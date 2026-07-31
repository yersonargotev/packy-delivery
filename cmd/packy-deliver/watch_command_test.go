package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type scriptedWatcher struct {
	events  []issuedelivery.WatchEvent
	err     error
	calls   int
	request issuedelivery.WatchRequest
}

func (watcher *scriptedWatcher) Watch(
	_ context.Context,
	request issuedelivery.WatchRequest,
	emit issuedelivery.WatchEmitter,
) error {
	watcher.calls++
	watcher.request = request
	for _, event := range watcher.events {
		if err := emit(event); err != nil {
			return err
		}
	}
	return watcher.err
}

func TestWatchCommandRendersVersionedJSONLEvents(t *testing.T) {
	observedAt := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	watcher := &scriptedWatcher{events: []issuedelivery.WatchEvent{
		watchDomainEvent(1, observedAt, issuedelivery.ActionObserveExternalResult, "same", ""),
		watchDomainEvent(2, observedAt.Add(time.Second), issuedelivery.ActionAdvance, "changed", ""),
	}}
	command := watchTestCommand(watcher)
	var stdout bytes.Buffer
	if err := command.run(context.Background(), watchArgs(t, "jsonl", "5s"), &stdout); err != nil {
		t.Fatal(err)
	}
	events := decodeWatchEvents(t, stdout.String())
	if len(events) != 2 ||
		events[0].Schema != watchEventSchema ||
		events[0].Sequence != 1 ||
		events[1].Sequence != 2 ||
		events[1].NextAction != issuedelivery.ActionAdvance ||
		events[1].RelevantIdentity == nil ||
		events[1].RelevantIdentity.Value != "changed" {
		t.Fatalf("events=%#v", events)
	}
	if watcher.calls != 1 ||
		watcher.request.Interval != 100*time.Millisecond ||
		watcher.request.Timeout != 5*time.Second {
		t.Fatalf("calls=%d request=%#v", watcher.calls, watcher.request)
	}
}

func TestWatchCommandRendersTextWithoutInventingEvents(t *testing.T) {
	observedAt := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	watcher := &scriptedWatcher{events: []issuedelivery.WatchEvent{
		watchDomainEvent(1, observedAt, issuedelivery.ActionObserveExternalResult, "same", ""),
		watchDomainEvent(2, observedAt.Add(time.Second), issuedelivery.ActionAdvance, "changed", ""),
	}}
	var stdout bytes.Buffer
	if err := watchTestCommand(watcher).run(
		context.Background(),
		watchArgs(t, "text", "5s"),
		&stdout,
	); err != nil {
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

func TestWatchCommandRendersBoundedErrorClass(t *testing.T) {
	observedAt := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	watcher := &scriptedWatcher{events: []issuedelivery.WatchEvent{
		watchDomainEvent(1, observedAt, "", "", issuedelivery.StatusErrorGitHubRead),
	}}
	var stdout bytes.Buffer
	if err := watchTestCommand(watcher).run(
		context.Background(),
		watchArgs(t, "jsonl", "5s"),
		&stdout,
	); err != nil {
		t.Fatal(err)
	}
	events := decodeWatchEvents(t, stdout.String())
	if len(events) != 1 || events[0].ErrorClass != issuedelivery.StatusErrorGitHubRead {
		t.Fatalf("events=%#v", events)
	}
}

func TestWatchCommandMapsTimeoutToDistinctExitCode(t *testing.T) {
	watcher := &scriptedWatcher{err: &issuedelivery.WatchTimeoutError{Timeout: time.Second}}
	err := watchTestCommand(watcher).run(
		context.Background(),
		watchArgs(t, "jsonl", "1s"),
		&bytes.Buffer{},
	)
	var timeout *watchTimeoutError
	if !errors.As(err, &timeout) || commandExitCode(err) != 2 {
		t.Fatalf("error=%T %v code=%d", err, err, commandExitCode(err))
	}
}

func TestWatchCommandPropagatesCancellation(t *testing.T) {
	watcher := &scriptedWatcher{err: context.Canceled}
	err := watchTestCommand(watcher).run(
		context.Background(),
		watchArgs(t, "text", "5s"),
		&bytes.Buffer{},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestWatchRejectsInvalidBoundsBeforeConstructingWatcher(t *testing.T) {
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
		command := command{WatchFactory: func(statusOptions) (issueDeliveryWatcher, error) {
			called = true
			return nil, nil
		}}
		if err := command.run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("args %v succeeded", args)
		}
		if called {
			t.Fatalf("args %v constructed Watch before validation", args)
		}
	}
}

func watchDomainEvent(
	sequence int,
	observedAt time.Time,
	action issuedelivery.NextAction,
	identity string,
	errorClass issuedelivery.StatusErrorClass,
) issuedelivery.WatchEvent {
	outcome := issuedelivery.Outcome{
		RunID:      "run-watch",
		State:      issuedelivery.StateWaiting,
		PauseCause: issuedelivery.PauseExternalResult,
		NextAction: action,
	}
	if identity != "" {
		outcome.StatusObservation = &issuedelivery.StatusObservation{
			Current: issuedelivery.StatusRelevantIdentity{
				Kind: issuedelivery.StatusIdentityCI, Value: identity,
			},
		}
	}
	return issuedelivery.WatchEvent{
		Sequence: sequence, ObservedAt: observedAt,
		Outcome: outcome, ErrorClass: errorClass,
	}
}

func watchTestCommand(watcher issueDeliveryWatcher) command {
	return command{
		WatchFactory: func(statusOptions) (issueDeliveryWatcher, error) {
			return watcher, nil
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
