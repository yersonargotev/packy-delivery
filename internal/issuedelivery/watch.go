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

type WatchEvent struct {
	Sequence   int
	ObservedAt time.Time
	Outcome    Outcome
	ErrorClass StatusErrorClass
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

	err := m.watchLoop(watchCtx, request, emit)
	cancel()
	<-timeoutDone
	if timedOut.Load() {
		return &WatchTimeoutError{Timeout: request.Timeout}
	}
	return err
}

func (m *Module) watchLoop(ctx context.Context, request WatchRequest, emit WatchEmitter) error {
	statusRequest := StatusRequest{
		RepositoryPath: request.RepositoryPath,
		IssueNumber:    request.IssueNumber,
	}
	var (
		sequence       int
		lastEmitted    *WatchEvent
		lastSuccessful *Outcome
	)
	for {
		var (
			outcome    Outcome
			observeErr error
		)
		if lastSuccessful != nil && lastSuccessful.IssueLockContended {
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
					outcome = *lastSuccessful
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
					outcome = *lastSuccessful
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
			if lastSuccessful != nil {
				eventOutcome = *lastSuccessful
			}
			event := WatchEvent{
				Sequence: sequence + 1, ObservedAt: observedAt,
				Outcome: eventOutcome, ErrorClass: class,
			}
			if lastEmitted == nil || !sameWatchEvent(*lastEmitted, event) {
				sequence++
				event.Sequence = sequence
				if err := emit(event); err != nil {
					return err
				}
				copy := event
				lastEmitted = &copy
			}
			if !typed || !transient {
				return fmt.Errorf("watch observation failed (%s): %w", class, observeErr)
			}
			if err := m.waiter.Wait(ctx, request.Interval); err != nil {
				return err
			}
			continue
		}

		lockAvailable := lastSuccessful != nil &&
			lastSuccessful.IssueLockContended &&
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
			Sequence: sequence + 1, ObservedAt: observedAt, Outcome: outcome,
		}
		recovered := lastEmitted != nil && lastEmitted.ErrorClass != ""
		meaningfulChange := lastEmitted == nil || !sameWatchEvent(*lastEmitted, event)
		if meaningfulChange {
			sequence++
			event.Sequence = sequence
			if err := emit(event); err != nil {
				return err
			}
			copy := event
			lastEmitted = &copy
		}
		if lockAvailable || externalChanged {
			return nil
		}
		if !watchPollable(outcome) {
			return nil
		}
		if lastSuccessful != nil && meaningfulChange && !recovered &&
			!lastSuccessful.IssueLockContended {
			return nil
		}
		copy := outcome
		lastSuccessful = &copy
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
		left.Outcome.RunID != right.Outcome.RunID ||
		left.Outcome.State != right.Outcome.State ||
		left.Outcome.PauseCause != right.Outcome.PauseCause ||
		left.Outcome.NextAction != right.Outcome.NextAction {
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
