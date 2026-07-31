package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type scriptedStatusResult struct {
	outcome issuedelivery.Outcome
	err     error
}

type scriptedStatuser struct {
	results []scriptedStatusResult
	calls   int
}

func (s *scriptedStatuser) Status(
	_ context.Context,
	_ issuedelivery.StatusRequest,
) (issuedelivery.Outcome, error) {
	index := s.calls
	s.calls++
	if index >= len(s.results) {
		index = len(s.results) - 1
	}
	return s.results[index].outcome, s.results[index].err
}

type watchFakeClock struct {
	now     time.Time
	waits   []time.Duration
	waitErr error
}

func (clock *watchFakeClock) Now() time.Time { return clock.now }

func (clock *watchFakeClock) Wait(_ context.Context, duration time.Duration) error {
	clock.waits = append(clock.waits, duration)
	if clock.waitErr != nil {
		return clock.waitErr
	}
	clock.now = clock.now.Add(duration)
	return nil
}

func TestWatchJSONLEmitsInitialAndChangedExternalResultOnly(t *testing.T) {
	start := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	clock := &watchFakeClock{now: start}
	initial := watchOutcome(
		issuedelivery.PauseExternalResult,
		issuedelivery.ActionObserveExternalResult,
		"persisted",
		"persisted",
	)
	changed := watchOutcome(
		issuedelivery.PauseExternalResult,
		issuedelivery.ActionObserveExternalResult,
		"persisted",
		"changed",
	)
	statuser := &scriptedStatuser{results: []scriptedStatusResult{
		{outcome: initial},
		{outcome: initial},
		{outcome: changed},
	}}
	cmd := watchTestCommand(clock, statuser)
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), watchArgs(t, "jsonl", "5s"), &stdout); err != nil {
		t.Fatal(err)
	}
	events := decodeWatchEvents(t, stdout.String())
	if len(events) != 2 {
		t.Fatalf("events=%#v", events)
	}
	if events[0].Sequence != 1 ||
		events[0].NextAction != issuedelivery.ActionObserveExternalResult ||
		events[0].RelevantIdentity == nil ||
		events[0].RelevantIdentity.Value != "persisted" {
		t.Fatalf("initial event=%#v", events[0])
	}
	if events[1].Sequence != 2 ||
		events[1].NextAction != issuedelivery.ActionAdvance ||
		events[1].RelevantIdentity == nil ||
		events[1].RelevantIdentity.Value != "changed" {
		t.Fatalf("changed event=%#v", events[1])
	}
	if statuser.calls != 3 || !reflect.DeepEqual(
		clock.waits,
		[]time.Duration{100 * time.Millisecond, 100 * time.Millisecond},
	) {
		t.Fatalf("calls=%d waits=%v", statuser.calls, clock.waits)
	}
}

func TestWatchTextEmitsInitialAndChangedExternalResultOnly(t *testing.T) {
	clock := &watchFakeClock{now: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)}
	initial := watchOutcome(
		issuedelivery.PauseExternalResult,
		issuedelivery.ActionObserveExternalResult,
		"persisted",
		"persisted",
	)
	changed := watchOutcome(
		issuedelivery.PauseExternalResult,
		issuedelivery.ActionObserveExternalResult,
		"persisted",
		"changed",
	)
	statuser := &scriptedStatuser{results: []scriptedStatusResult{
		{outcome: initial},
		{outcome: initial},
		{outcome: changed},
	}}
	cmd := watchTestCommand(clock, statuser)
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), watchArgs(t, "text", "5s"), &stdout); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 ||
		!strings.Contains(lines[0], "next=observe-external-result") ||
		!strings.Contains(lines[1], "next=advance") ||
		!strings.Contains(lines[1], "identity=ci:changed") {
		t.Fatalf("output=%q", stdout.String())
	}
}

func TestWatchOpenWaitOnlyChangesAreSilentUntilDistinctTimeout(t *testing.T) {
	clock := &watchFakeClock{now: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)}
	outcome := watchOutcome(
		issuedelivery.PauseExternalResult,
		issuedelivery.ActionObserveExternalResult,
		"same",
		"same",
	)
	statuser := &scriptedStatuser{results: []scriptedStatusResult{{outcome: outcome}}}
	cmd := watchTestCommand(clock, statuser)
	var stdout bytes.Buffer
	err := cmd.run(context.Background(), watchArgs(t, "jsonl", "1s"), &stdout)
	var timeout *watchTimeoutError
	if !errors.As(err, &timeout) || commandExitCode(err) != 2 {
		t.Fatalf("timeout error=%T %v code=%d", err, err, commandExitCode(err))
	}
	events := decodeWatchEvents(t, stdout.String())
	if len(events) != 1 {
		t.Fatalf("unchanged watch emitted noise: %#v", events)
	}
	if statuser.calls != 10 {
		t.Fatalf("Status calls=%d want 10", statuser.calls)
	}
}

func TestWatchLockAvailabilityStopsWithRetryAdvance(t *testing.T) {
	clock := &watchFakeClock{now: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)}
	contended := watchOutcome(
		issuedelivery.PauseLockContention,
		issuedelivery.ActionRetryAdvance,
		"contended",
		"contended",
	)
	contended.IssueLockContended = true
	available := watchOutcome(
		issuedelivery.PauseExternalResult,
		issuedelivery.ActionObserveExternalResult,
		"persisted",
		"changed",
	)
	statuser := &scriptedStatuser{results: []scriptedStatusResult{
		{outcome: contended},
		{outcome: available},
	}}
	cmd := watchTestCommand(clock, statuser)
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), watchArgs(t, "jsonl", "5s"), &stdout); err != nil {
		t.Fatal(err)
	}
	events := decodeWatchEvents(t, stdout.String())
	if len(events) != 2 || events[1].NextAction != issuedelivery.ActionRetryAdvance {
		t.Fatalf("events=%#v", events)
	}
}

func TestWatchStopsImmediatelyForNonPollablePauses(t *testing.T) {
	tests := []struct {
		name   string
		pause  issuedelivery.PauseCause
		action issuedelivery.NextAction
	}{
		{"semantic input", issuedelivery.PauseSemanticInput, issuedelivery.ActionProvideDecision},
		{"independent review", issuedelivery.PauseIndependentReview, issuedelivery.ActionProvideCandidateReview},
		{"repair", issuedelivery.PauseCandidateRepair, issuedelivery.ActionRepairCandidate},
		{"authorization", issuedelivery.PauseNonLocalAuthorization, issuedelivery.ActionAuthorizeNonLocal},
		{"invariant", issuedelivery.PauseInvariantBlock, issuedelivery.ActionInspectBlockedTransition},
		{"legacy", issuedelivery.PauseLegacyWorkflow, issuedelivery.ActionResumeLegacyV1},
		{"completed", issuedelivery.PauseCompleted, issuedelivery.ActionNone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &watchFakeClock{now: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)}
			outcome := watchOutcome(test.pause, test.action, "identity", "identity")
			statuser := &scriptedStatuser{results: []scriptedStatusResult{{outcome: outcome}}}
			cmd := watchTestCommand(clock, statuser)
			var stdout bytes.Buffer
			if err := cmd.run(context.Background(), watchArgs(t, "text", "5s"), &stdout); err != nil {
				t.Fatal(err)
			}
			if statuser.calls != 1 || len(clock.waits) != 0 ||
				strings.Count(stdout.String(), "\n") != 1 {
				t.Fatalf("calls=%d waits=%v output=%q", statuser.calls, clock.waits, stdout.String())
			}
		})
	}
}

func TestWatchDeduplicatesTransientErrorsAndContinuesAfterRecovery(t *testing.T) {
	clock := &watchFakeClock{now: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)}
	initial := watchOutcome(
		issuedelivery.PauseExternalResult,
		issuedelivery.ActionObserveExternalResult,
		"same",
		"same",
	)
	changed := watchOutcome(
		issuedelivery.PauseExternalResult,
		issuedelivery.ActionObserveExternalResult,
		"same",
		"changed",
	)
	gitRead := issuedelivery.NewStatusError(
		issuedelivery.StatusErrorGitRead,
		true,
		errors.New("temporary Git read"),
	)
	githubRead := issuedelivery.NewStatusError(
		issuedelivery.StatusErrorGitHubRead,
		true,
		errors.New("temporary GitHub read"),
	)
	statuser := &scriptedStatuser{results: []scriptedStatusResult{
		{outcome: initial},
		{err: gitRead},
		{err: gitRead},
		{err: githubRead},
		{outcome: initial},
		{outcome: changed},
	}}
	cmd := watchTestCommand(clock, statuser)
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), watchArgs(t, "jsonl", "5s"), &stdout); err != nil {
		t.Fatal(err)
	}
	events := decodeWatchEvents(t, stdout.String())
	if len(events) != 5 {
		t.Fatalf("events=%#v", events)
	}
	wantErrors := []issuedelivery.StatusErrorClass{
		"",
		issuedelivery.StatusErrorGitRead,
		issuedelivery.StatusErrorGitHubRead,
		"",
		"",
	}
	for index, want := range wantErrors {
		if events[index].ErrorClass != want || events[index].Sequence != index+1 {
			t.Fatalf("event[%d]=%#v", index, events[index])
		}
	}
	if events[len(events)-1].NextAction != issuedelivery.ActionAdvance {
		t.Fatalf("final event=%#v", events[len(events)-1])
	}
}

func TestWatchPermanentObservationErrorEmitsClassAndFailsWithoutWaiting(t *testing.T) {
	clock := &watchFakeClock{now: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)}
	permanent := issuedelivery.NewStatusError(
		issuedelivery.StatusErrorIdentity,
		false,
		errors.New("identity mismatch"),
	)
	statuser := &scriptedStatuser{results: []scriptedStatusResult{{err: permanent}}}
	cmd := watchTestCommand(clock, statuser)
	var stdout bytes.Buffer
	err := cmd.run(context.Background(), watchArgs(t, "jsonl", "5s"), &stdout)
	if err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("error=%v", err)
	}
	events := decodeWatchEvents(t, stdout.String())
	if len(events) != 1 || events[0].ErrorClass != issuedelivery.StatusErrorIdentity ||
		len(clock.waits) != 0 {
		t.Fatalf("events=%#v waits=%v", events, clock.waits)
	}
}

func TestWatchHonorsContextCancellationWhileWaiting(t *testing.T) {
	clock := &watchFakeClock{
		now:     time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC),
		waitErr: context.Canceled,
	}
	outcome := watchOutcome(
		issuedelivery.PauseExternalResult,
		issuedelivery.ActionObserveExternalResult,
		"same",
		"same",
	)
	statuser := &scriptedStatuser{results: []scriptedStatusResult{{outcome: outcome}}}
	cmd := watchTestCommand(clock, statuser)
	err := cmd.run(context.Background(), watchArgs(t, "text", "5s"), &bytes.Buffer{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestWatchRejectsInvalidBoundsBeforeConstructingStatus(t *testing.T) {
	repository := t.TempDir()
	tests := [][]string{
		{"watch", "--repository", repository, "--issue", "29", "--timeout", "1s"},
		{"watch", "--repository", repository, "--issue", "29", "--interval", "100ms"},
		{"watch", "--repository", repository, "--issue", "29", "--interval", "99ms", "--timeout", "1s"},
		{"watch", "--repository", repository, "--issue", "29", "--interval", "100ms", "--timeout", "999ms"},
		{"watch", "--repository", repository, "--issue", "29", "--interval", "6m", "--timeout", "10m"},
		{"watch", "--repository", repository, "--issue", "29", "--interval", "1m", "--timeout", "25h"},
		{"watch", "--repository", repository, "--issue", "29", "--interval", "2s", "--timeout", "1s"},
		{"watch", "--repository", repository, "--issue", "29", "--interval", "100ms", "--timeout", "1s", "--output", "json"},
	}
	for _, args := range tests {
		called := false
		cmd := command{StatusFactory: func(statusOptions) (issueDeliveryStatuser, error) {
			called = true
			return nil, nil
		}}
		if err := cmd.run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("args %v succeeded", args)
		}
		if called {
			t.Fatalf("args %v constructed Status before validation", args)
		}
	}
}

func watchOutcome(
	pause issuedelivery.PauseCause,
	action issuedelivery.NextAction,
	persisted, current string,
) issuedelivery.Outcome {
	return issuedelivery.Outcome{
		RunID: "run-watch", State: issuedelivery.StateWaiting,
		PauseCause: pause, NextAction: action,
		StatusObservation: &issuedelivery.StatusObservation{
			Persisted: issuedelivery.StatusRelevantIdentity{
				Kind: issuedelivery.StatusIdentityCI, Value: persisted,
			},
			Current: issuedelivery.StatusRelevantIdentity{
				Kind: issuedelivery.StatusIdentityCI, Value: current,
			},
			Changed: persisted != current,
		},
	}
}

func watchTestCommand(clock *watchFakeClock, statuser issueDeliveryStatuser) command {
	return command{
		Now: clock.Now, Wait: clock.Wait,
		StatusFactory: func(statusOptions) (issueDeliveryStatuser, error) {
			return statuser, nil
		},
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
			panic("watch must not construct Advance")
		},
		LegacyPrefixRequired: true,
	}
}

func watchArgs(t *testing.T, output, timeout string) []string {
	t.Helper()
	repository, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return []string{
		"watch",
		"--repository", repository,
		"--issue", "29",
		"--interval", "100ms",
		"--timeout", timeout,
		"--output", output,
	}
}

func decodeWatchEvents(t *testing.T, output string) []watchEvent {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	events := make([]watchEvent, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var event watchEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}
