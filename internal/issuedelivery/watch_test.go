package issuedelivery

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type watchTestWaiter struct {
	timeout time.Duration
	poll    func()
}

func (w *watchTestWaiter) Wait(ctx context.Context, duration time.Duration) error {
	if duration == w.timeout {
		<-ctx.Done()
		return ctx.Err()
	}
	if w.poll != nil {
		w.poll()
	}
	return ctx.Err()
}

func TestWatchEmitsInitialAndExternalSemanticChange(t *testing.T) {
	module, git, _ := moduleFixture(t, 356)
	if _, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
	}); err != nil {
		t.Fatal(err)
	}
	err := module.store.withIssueLock(
		context.Background(),
		git.value.CommonDir,
		356,
		func(store lockedIssueStore) error {
			runID, data, found, err := store.loadActive()
			if err != nil || !found {
				return err
			}
			record, err := decodeRun(data)
			if err != nil {
				return err
			}
			record.State = StateWaiting
			record.Reason = "awaiting an external repository result"
			record.PendingQualificationCorrection = nil
			record.Timing[len(record.Timing)-1].To = StateWaiting
			updated, err := encodeRun(record)
			if err != nil {
				return err
			}
			_, err = store.storeRevisionAndActivate(runID, updated)
			return err
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	timeout := 10 * time.Second
	module.waiter = &watchTestWaiter{
		timeout: timeout,
		poll: func() {
			git.mu.Lock()
			git.value.HeadSHA = strings.Repeat("8", 40)
			git.value.TreeSHA = strings.Repeat("9", 40)
			git.value.WorkspaceClean = true
			git.mu.Unlock()
		},
	}
	var events []WatchEvent
	err = module.Watch(context.Background(), WatchRequest{
		RepositoryPath: "/repo", IssueNumber: 356,
		Interval: MinimumWatchInterval, Timeout: timeout,
	}, func(event WatchEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%#v", events)
	}
	if events[0].Sequence != 1 || events[1].Sequence != 2 ||
		events[0].Outcome.StatusObservation == nil ||
		events[0].Outcome.StatusObservation.Changed ||
		events[1].Outcome.StatusObservation == nil ||
		!events[1].Outcome.StatusObservation.Changed ||
		events[1].Outcome.NextAction != ActionAdvance {
		t.Fatalf("events=%#v", events)
	}
}

func TestWatchRejectsInvalidRequestBeforeObservation(t *testing.T) {
	module, git, _ := moduleFixture(t, 356)
	git.mu.Lock()
	git.calls = 0
	git.mu.Unlock()
	err := module.Watch(context.Background(), WatchRequest{
		RepositoryPath: "/repo", IssueNumber: 356,
		Interval: MinimumWatchInterval - time.Nanosecond,
		Timeout:  MinimumWatchTimeout,
	}, func(WatchEvent) error { return nil })
	if err == nil {
		t.Fatal("invalid interval was accepted")
	}
	git.mu.Lock()
	defer git.mu.Unlock()
	if git.calls != 0 {
		t.Fatalf("invalid watch made %d observations", git.calls)
	}
	if err := ValidateWatchRequest(WatchRequest{
		RepositoryPath: "/repo", IssueNumber: 356,
		Interval: 2 * time.Second, Timeout: time.Second,
	}); err == nil {
		t.Fatal("timeout shorter than interval was accepted")
	}
}

type blockingGitObserver struct {
	started chan struct{}
	once    sync.Once
}

func (o *blockingGitObserver) ObserveGit(ctx context.Context, _ string) (GitObservation, error) {
	o.once.Do(func() { close(o.started) })
	<-ctx.Done()
	return GitObservation{}, ctx.Err()
}

type immediateTimeoutWaiter struct{}

func (immediateTimeoutWaiter) Wait(ctx context.Context, duration time.Duration) error {
	if duration >= MinimumWatchTimeout {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestWatchTimeoutCancelsInflightStatus(t *testing.T) {
	git := &blockingGitObserver{started: make(chan struct{})}
	module, err := New(Config{
		Git: git, GitHub: &fakeGitHubObserver{},
		Waiter: immediateTimeoutWaiter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = module.Watch(context.Background(), WatchRequest{
		RepositoryPath: "/repo", IssueNumber: 356,
		Interval: MinimumWatchInterval, Timeout: MinimumWatchTimeout,
	}, func(WatchEvent) error { return nil })
	var timeoutErr *WatchTimeoutError
	if !errors.As(err, &timeoutErr) || timeoutErr.Timeout != MinimumWatchTimeout {
		t.Fatalf("error=%v", err)
	}
	select {
	case <-git.started:
	default:
		t.Fatal("Status was not started")
	}
}

func TestWatchLockRecoveryOnlyProbesGitAndLock(t *testing.T) {
	module, git, tracker := moduleFixture(t, 356)
	if _, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
	}); err != nil {
		t.Fatal(err)
	}
	before := snapshotRegularFiles(t, git.value.CommonDir)
	tracker.mu.Lock()
	tracker.calls = 0
	tracker.mu.Unlock()

	locked := make(chan struct{})
	release := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- module.store.withIssueLock(
			context.Background(),
			git.value.CommonDir,
			356,
			func(lockedIssueStore) error {
				close(locked)
				<-release
				return nil
			},
		)
	}()
	<-locked
	timeout := 10 * time.Second
	var releaseOnce sync.Once
	module.waiter = &watchTestWaiter{
		timeout: timeout,
		poll: func() {
			releaseOnce.Do(func() {
				close(release)
				if err := <-lockDone; err != nil {
					t.Errorf("release issue lock: %v", err)
				}
				tracker.mu.Lock()
				tracker.value.Issue.Number = 999
				tracker.mu.Unlock()
			})
		},
	}
	var events []WatchEvent
	err := module.Watch(context.Background(), WatchRequest{
		RepositoryPath: "/repo", IssueNumber: 356,
		Interval: MinimumWatchInterval, Timeout: timeout,
	}, func(event WatchEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || !events[0].Outcome.IssueLockContended ||
		events[1].Outcome.IssueLockContended ||
		events[1].Outcome.NextAction != ActionRetryAdvance {
		t.Fatalf("events=%#v", events)
	}
	tracker.mu.Lock()
	trackerCalls := tracker.calls
	tracker.mu.Unlock()
	if trackerCalls != 0 {
		t.Fatalf("lock recovery made %d tracker calls", trackerCalls)
	}
	after := snapshotRegularFiles(t, git.value.CommonDir)
	if !reflect.DeepEqual(after, before) {
		t.Fatal("lock recovery changed run store")
	}
}

func TestWatchReloadsMonotonicOperationProgressWhileContended(t *testing.T) {
	module, git, _ := moduleFixture(t, 356)
	if _, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
	}); err != nil {
		t.Fatal(err)
	}
	operation, err := newAdvanceOperation(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	advancePhase := make(chan struct{})
	phaseUpdated := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- module.store.withAdvanceOperationLock(
			context.Background(), git.value.CommonDir, 356, &operation,
			func(ctx context.Context, _ lockedIssueStore) error {
				close(locked)
				<-advancePhase
				if err := advanceOperationProgress(ctx, OperationPhaseValidationSession, strings.Repeat("a", 64)); err != nil {
					return err
				}
				close(phaseUpdated)
				<-release
				return nil
			},
		)
	}()
	<-locked
	polls := 0
	module.waiter = &watchTestWaiter{
		timeout: 10 * time.Second,
		poll: func() {
			polls++
			if polls == 1 {
				close(advancePhase)
				<-phaseUpdated
				return
			}
			close(release)
			if err := <-done; err != nil {
				t.Errorf("finish Advance operation: %v", err)
			}
		},
	}
	var events []WatchEvent
	err = module.Watch(context.Background(), WatchRequest{
		RepositoryPath: "/repo", IssueNumber: 356,
		Interval: MinimumWatchInterval, Timeout: 10 * time.Second,
	}, func(event WatchEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events=%#v", events)
	}
	for _, event := range events {
		if event.Outcome.Operation == nil || event.Outcome.Operation.ID != operation.ID {
			t.Fatalf("operation identity changed: %#v", events)
		}
	}
	if events[0].Outcome.Operation.Phase != OperationPhaseAdvance ||
		events[1].Outcome.Operation.Phase != OperationPhaseValidationSession ||
		events[1].Outcome.Operation.ValidationSessionID == "" ||
		events[2].Outcome.Operation.State != OperationCompleted ||
		events[2].Outcome.IssueLockContended {
		t.Fatalf("operation progress is not monotonic: %#v", events)
	}
}
