package issuedelivery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

const (
	MinimumWatchInterval = 100 * time.Millisecond
	MaximumWatchInterval = 5 * time.Minute
	MinimumWatchTimeout  = time.Second
	MaximumWatchTimeout  = 24 * time.Hour
)

type WatchRequest struct {
	RepositoryPath string
	IssueNumber    int
	Interval       time.Duration
	Timeout        time.Duration
}

type WatchTerminalOutcome string

const (
	WatchTerminalTimeoutNoChange WatchTerminalOutcome = "timeout-no-change"
)

type WatchEvent struct {
	Sequence        int
	ObservedAt      time.Time
	Outcome         Outcome
	ErrorClass      StatusErrorClass
	TerminalOutcome WatchTerminalOutcome
}

type WatchEmitter func(WatchEvent) error

type WatchTimeoutError struct {
	Timeout time.Duration
}

func (e *WatchTimeoutError) Error() string {
	return fmt.Sprintf("watch timed out after %s", e.Timeout)
}

type systemWaiter struct{}

func (systemWaiter) Wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func ValidateWatchRequest(request WatchRequest) error {
	if request.IssueNumber <= 0 || strings.TrimSpace(request.RepositoryPath) == "" {
		return errors.New("Watch requires a repository path and positive issue number")
	}
	if request.Interval < MinimumWatchInterval || request.Interval > MaximumWatchInterval {
		return fmt.Errorf(
			"watch interval must be between %s and %s",
			MinimumWatchInterval,
			MaximumWatchInterval,
		)
	}
	if request.Timeout < MinimumWatchTimeout || request.Timeout > MaximumWatchTimeout {
		return fmt.Errorf(
			"watch timeout must be between %s and %s",
			MinimumWatchTimeout,
			MaximumWatchTimeout,
		)
	}
	if request.Timeout < request.Interval {
		return errors.New("watch timeout must be greater than or equal to watch interval")
	}
	return nil
}

// Watch observes a run until it reaches a non-pollable pause or a pollable
// observation changes. It never advances or rewrites the run.
func (m *Module) Watch(ctx context.Context, request WatchRequest, emit WatchEmitter) error {
	if ctx == nil {
		return errors.New("Watch requires a context")
	}
	if err := ValidateWatchRequest(request); err != nil {
		return err
	}
	if emit == nil {
		return errors.New("Watch requires an event emitter")
	}

	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var timedOut atomic.Bool
	timeoutDone := make(chan struct{})
	go func() {
		defer close(timeoutDone)
		if err := m.waiter.Wait(watchCtx, request.Timeout); err == nil {
			timedOut.Store(true)
			cancel()
		}
	}()

	var progress watchProgress
	err := m.watchLoop(watchCtx, request, emit, &progress)
	cancel()
	<-timeoutDone
	if timedOut.Load() &&
		(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		terminal := WatchEvent{
			ObservedAt:      m.clock.Now(),
			TerminalOutcome: WatchTerminalTimeoutNoChange,
		}
		if progress.lastSuccessful != nil {
			terminal.Outcome = *progress.lastSuccessful
		}
		if err := emitWatchEvent(&progress, emit, terminal); err != nil {
			return err
		}
		return &WatchTimeoutError{Timeout: request.Timeout}
	}
	return err
}

type watchProgress struct {
	sequence       int
	lastEmitted    *WatchEvent
	lastSuccessful *Outcome
}

func emitWatchEvent(progress *watchProgress, emit WatchEmitter, event WatchEvent) error {
	progress.sequence++
	event.Sequence = progress.sequence
	if err := emit(event); err != nil {
		return err
	}
	copy := event
	progress.lastEmitted = &copy
	return nil
}

func (m *Module) watchLoop(
	ctx context.Context,
	request WatchRequest,
	emit WatchEmitter,
	progress *watchProgress,
) error {
	statusRequest := StatusRequest{
		RepositoryPath: request.RepositoryPath,
		IssueNumber:    request.IssueNumber,
	}
	for {
		var (
			outcome    Outcome
			observeErr error
		)
		if progress.lastSuccessful != nil && progress.lastSuccessful.IssueLockContended {
			git, err := m.git.ObserveGit(ctx, request.RepositoryPath)
			if err != nil {
				observeErr = statusObserverError(ctx, StatusErrorGitRead, "observe Git", err)
			} else {
				available, err := m.store.issueLockAvailable(
					ctx,
					git.CommonDir,
					request.IssueNumber,
				)
				if err != nil {
					observeErr = statusObserverError(
						ctx,
						StatusErrorRunState,
						"probe issue delivery lock",
						err,
					)
					if class, _, typed := StatusErrorDetails(observeErr); typed {
						observeErr = NewStatusError(class, false, observeErr)
					}
				} else if available {
					outcome = *progress.lastSuccessful
					operation, err := m.store.loadOperation(git.CommonDir, request.IssueNumber)
					if err != nil {
						return statusObserverError(ctx, StatusErrorRunState, "load Advance operation", err)
					}
					outcome.Operation = operation
					outcome.IssueLockContended = false
					outcome.NextAction = ActionRetryAdvance
					outcome.StatusObservation = &StatusObservation{
						Persisted: StatusRelevantIdentity{
							Kind: StatusIdentityLock, Value: "contended",
						},
						Current: StatusRelevantIdentity{
							Kind: StatusIdentityLock, Value: "available",
						},
						Changed: true,
					}
				} else {
					outcome = *progress.lastSuccessful
					operation, err := m.store.loadOperation(git.CommonDir, request.IssueNumber)
					if err != nil {
						observeErr = statusObserverError(ctx, StatusErrorRunState, "load Advance operation", err)
					} else {
						outcome.Operation = operation
					}
				}
			}
		} else {
			outcome, observeErr = m.Status(ctx, statusRequest)
		}
		observedAt := m.clock.Now()
		if observeErr != nil {
			if errors.Is(observeErr, context.Canceled) ||
				errors.Is(observeErr, context.DeadlineExceeded) {
				return observeErr
			}
			class, transient, typed := StatusErrorDetails(observeErr)
			if !typed {
				class = StatusErrorRunState
			}
			eventOutcome := Outcome{}
			if progress.lastSuccessful != nil {
				eventOutcome = *progress.lastSuccessful
			}
			event := WatchEvent{
				ObservedAt: observedAt, Outcome: eventOutcome, ErrorClass: class,
			}
			if progress.lastEmitted == nil || !sameWatchEvent(*progress.lastEmitted, event) {
				if err := emitWatchEvent(progress, emit, event); err != nil {
					return err
				}
			}
			if !typed || !transient {
				return fmt.Errorf("watch observation failed (%s): %w", class, observeErr)
			}
			if err := m.waiter.Wait(ctx, request.Interval); err != nil {
				return err
			}
			continue
		}

		lockAvailable := progress.lastSuccessful != nil &&
			progress.lastSuccessful.IssueLockContended &&
			!outcome.IssueLockContended
		externalChanged := outcome.PauseCause == PauseExternalResult &&
			outcome.StatusObservation != nil &&
			outcome.StatusObservation.Changed
		if externalChanged {
			outcome.NextAction = ActionAdvance
		}
		if lockAvailable {
			outcome.NextAction = ActionRetryAdvance
		}
		event := WatchEvent{
			ObservedAt: observedAt, Outcome: outcome,
		}
		recovered := progress.lastEmitted != nil && progress.lastEmitted.ErrorClass != ""
		meaningfulChange := progress.lastEmitted == nil || !sameWatchEvent(*progress.lastEmitted, event)
		if meaningfulChange {
			if err := emitWatchEvent(progress, emit, event); err != nil {
				return err
			}
		}
		if lockAvailable || externalChanged {
			return nil
		}
		if !watchPollable(outcome) {
			return nil
		}
		if progress.lastSuccessful != nil && meaningfulChange && !recovered &&
			!progress.lastSuccessful.IssueLockContended {
			return nil
		}
		copy := outcome
		progress.lastSuccessful = &copy
		if err := m.waiter.Wait(ctx, request.Interval); err != nil {
			return err
		}
	}
}

func statusObserverError(
	ctx context.Context,
	class StatusErrorClass,
	operation string,
	err error,
) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if _, _, typed := StatusErrorDetails(err); typed {
		return err
	}
	return NewStatusError(class, true, fmt.Errorf("%s: %w", operation, err))
}

func watchPollable(outcome Outcome) bool {
	return outcome.PauseCause == PauseExternalResult ||
		outcome.PauseCause == PauseLockContention
}

func sameWatchEvent(left, right WatchEvent) bool {
	if left.ErrorClass != right.ErrorClass ||
		left.TerminalOutcome != right.TerminalOutcome ||
		left.Outcome.RunID != right.Outcome.RunID ||
		left.Outcome.State != right.Outcome.State ||
		left.Outcome.PauseCause != right.Outcome.PauseCause ||
		left.Outcome.NextAction != right.Outcome.NextAction {
		return false
	}
	if (left.Outcome.Operation == nil) != (right.Outcome.Operation == nil) {
		return false
	}
	if left.Outcome.Operation != nil && *left.Outcome.Operation != *right.Outcome.Operation {
		return false
	}
	leftStatus, rightStatus := left.Outcome.StatusObservation, right.Outcome.StatusObservation
	switch {
	case leftStatus == nil && rightStatus == nil:
		return true
	case leftStatus == nil || rightStatus == nil:
		return false
	default:
		return leftStatus.Current == rightStatus.Current
	}
}
