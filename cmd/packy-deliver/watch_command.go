package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

const (
	watchEventSchema = "packy.watch-event/v1"
	minWatchInterval = 100 * time.Millisecond
	maxWatchInterval = 5 * time.Minute
	minWatchTimeout  = time.Second
	maxWatchTimeout  = 24 * time.Hour
)

type watchOptions struct {
	RepositoryPath string
	IssueNumber    int
	Interval       time.Duration
	Timeout        time.Duration
	Output         string
}

type watchEvent struct {
	Schema           string                                `json:"schema"`
	Sequence         int                                   `json:"sequence"`
	ObservedAt       string                                `json:"observed_at"`
	RunID            string                                `json:"run_id,omitempty"`
	State            issuedelivery.State                   `json:"state,omitempty"`
	PauseCause       issuedelivery.PauseCause              `json:"pause_cause,omitempty"`
	NextAction       issuedelivery.NextAction              `json:"next_action,omitempty"`
	RelevantIdentity *issuedelivery.StatusRelevantIdentity `json:"relevant_identity,omitempty"`
	ErrorClass       issuedelivery.StatusErrorClass        `json:"error_class,omitempty"`
}

type watchTimeoutError struct {
	timeout time.Duration
}

func (e *watchTimeoutError) Error() string {
	return fmt.Sprintf("watch timed out after %s", e.timeout)
}

func (*watchTimeoutError) ExitCode() int { return 2 }

func (c command) watch(ctx context.Context, args []string, stdout io.Writer) error {
	if ctx == nil {
		return errors.New("watch requires a context")
	}
	options, err := parseWatchOptions(args)
	if err != nil {
		return err
	}
	if c.StatusFactory == nil {
		return errors.New("Status adapter is unavailable")
	}
	observer, err := c.StatusFactory(statusOptions{
		RepositoryPath: options.RepositoryPath,
		IssueNumber:    options.IssueNumber,
	})
	if err != nil {
		return fmt.Errorf("configure Status: %w", err)
	}
	started := c.now()
	deadline := started.Add(options.Timeout)
	request := issuedelivery.StatusRequest{
		RepositoryPath: options.RepositoryPath,
		IssueNumber:    options.IssueNumber,
	}
	var (
		sequence       int
		lastEmitted    *watchEvent
		lastSuccessful *issuedelivery.Outcome
	)
	for {
		if sequence > 0 && !c.now().Before(deadline) {
			return &watchTimeoutError{timeout: options.Timeout}
		}
		outcome, observeErr := observer.Status(ctx, request)
		observedAt := c.now()
		if observeErr != nil {
			if errors.Is(observeErr, context.Canceled) ||
				errors.Is(observeErr, context.DeadlineExceeded) {
				return observeErr
			}
			class, transient, typed := issuedelivery.StatusErrorDetails(observeErr)
			if !typed {
				class = issuedelivery.StatusErrorRunState
			}
			event := watchErrorEvent(sequence+1, observedAt, lastSuccessful, class)
			if lastEmitted == nil || !sameWatchEvent(*lastEmitted, event) {
				sequence++
				event.Sequence = sequence
				if err := emitWatchEvent(stdout, options.Output, event); err != nil {
					return err
				}
				copy := event
				lastEmitted = &copy
			}
			if !typed || !transient {
				return fmt.Errorf("watch observation failed (%s): %w", class, observeErr)
			}
			if err := c.waitForWatchPoll(ctx, options.Interval, deadline); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				return &watchTimeoutError{timeout: options.Timeout}
			}
			continue
		}

		event := watchOutcomeEvent(sequence+1, observedAt, outcome)
		lockAvailable := lastSuccessful != nil &&
			lastSuccessful.IssueLockContended &&
			!outcome.IssueLockContended
		externalChanged := outcome.PauseCause == issuedelivery.PauseExternalResult &&
			outcome.StatusObservation != nil &&
			outcome.StatusObservation.Changed
		if externalChanged {
			event.NextAction = issuedelivery.ActionAdvance
		}
		if lockAvailable {
			event.NextAction = issuedelivery.ActionRetryAdvance
		}
		recovered := lastEmitted != nil && lastEmitted.ErrorClass != ""
		meaningfulChange := lastEmitted == nil || !sameWatchEvent(*lastEmitted, event)
		if meaningfulChange {
			sequence++
			event.Sequence = sequence
			if err := emitWatchEvent(stdout, options.Output, event); err != nil {
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
		if err := c.waitForWatchPoll(ctx, options.Interval, deadline); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return &watchTimeoutError{timeout: options.Timeout}
		}
	}
}

func parseWatchOptions(args []string) (watchOptions, error) {
	f := flag.NewFlagSet("packy-deliver watch", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var options watchOptions
	f.StringVar(&options.RepositoryPath, "repository", "", "absolute repository containing the delivery run")
	f.IntVar(&options.IssueNumber, "issue", 0, "Packy issue number")
	f.DurationVar(&options.Interval, "interval", 0, "poll interval")
	f.DurationVar(&options.Timeout, "timeout", 0, "overall timeout")
	f.StringVar(&options.Output, "output", "text", "event format: text or jsonl")
	if err := f.Parse(args); err != nil {
		return watchOptions{}, err
	}
	if f.NArg() != 0 || options.IssueNumber <= 0 || strings.TrimSpace(options.RepositoryPath) == "" {
		return watchOptions{}, errors.New("issue and repository are required and positional arguments are forbidden")
	}
	if !filepath.IsAbs(options.RepositoryPath) {
		return watchOptions{}, errors.New("repository must be an absolute path")
	}
	if options.Interval < minWatchInterval || options.Interval > maxWatchInterval {
		return watchOptions{}, fmt.Errorf(
			"interval must be from %s through %s",
			minWatchInterval,
			maxWatchInterval,
		)
	}
	if options.Timeout < minWatchTimeout || options.Timeout > maxWatchTimeout {
		return watchOptions{}, fmt.Errorf(
			"timeout must be from %s through %s",
			minWatchTimeout,
			maxWatchTimeout,
		)
	}
	if options.Timeout < options.Interval {
		return watchOptions{}, errors.New("timeout must be at least the polling interval")
	}
	if options.Output != "text" && options.Output != "jsonl" {
		return watchOptions{}, fmt.Errorf("output %q is invalid; use text or jsonl", options.Output)
	}
	resolved, err := filepath.EvalSymlinks(options.RepositoryPath)
	if err != nil {
		return watchOptions{}, fmt.Errorf("resolve repository: %w", err)
	}
	options.RepositoryPath = filepath.Clean(resolved)
	return options, nil
}

func containsWatchHelpFlag(args []string) bool {
	return containsHelpFlag(args, func(arg string) bool {
		switch arg {
		case "-repository", "--repository", "-issue", "--issue",
			"-interval", "--interval", "-timeout", "--timeout", "-output", "--output":
			return true
		default:
			return false
		}
	})
}

func watchOutcomeEvent(
	sequence int,
	observedAt time.Time,
	outcome issuedelivery.Outcome,
) watchEvent {
	event := watchEvent{
		Schema: watchEventSchema, Sequence: sequence,
		ObservedAt: observedAt.UTC().Format(time.RFC3339Nano),
		RunID:      outcome.RunID, State: outcome.State,
		PauseCause: outcome.PauseCause, NextAction: outcome.NextAction,
	}
	if outcome.StatusObservation != nil {
		identity := outcome.StatusObservation.Current
		event.RelevantIdentity = &identity
	}
	return event
}

func watchErrorEvent(
	sequence int,
	observedAt time.Time,
	last *issuedelivery.Outcome,
	class issuedelivery.StatusErrorClass,
) watchEvent {
	if last == nil {
		return watchEvent{
			Schema: watchEventSchema, Sequence: sequence,
			ObservedAt: observedAt.UTC().Format(time.RFC3339Nano),
			ErrorClass: class,
		}
	}
	event := watchOutcomeEvent(sequence, observedAt, *last)
	event.ErrorClass = class
	return event
}

func watchPollable(outcome issuedelivery.Outcome) bool {
	return outcome.PauseCause == issuedelivery.PauseExternalResult ||
		outcome.PauseCause == issuedelivery.PauseLockContention
}

func sameWatchEvent(left, right watchEvent) bool {
	if left.RunID != right.RunID ||
		left.State != right.State ||
		left.PauseCause != right.PauseCause ||
		left.NextAction != right.NextAction ||
		left.ErrorClass != right.ErrorClass {
		return false
	}
	switch {
	case left.RelevantIdentity == nil && right.RelevantIdentity == nil:
		return true
	case left.RelevantIdentity == nil || right.RelevantIdentity == nil:
		return false
	default:
		return *left.RelevantIdentity == *right.RelevantIdentity
	}
}

func emitWatchEvent(stdout io.Writer, output string, event watchEvent) error {
	if output == "jsonl" {
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		raw = append(raw, '\n')
		_, err = stdout.Write(raw)
		return err
	}
	identity := ""
	if event.RelevantIdentity != nil {
		identity = fmt.Sprintf(
			" identity=%s:%s",
			event.RelevantIdentity.Kind,
			event.RelevantIdentity.Value,
		)
		if event.RelevantIdentity.Count != 0 {
			identity += fmt.Sprintf(" count=%d", event.RelevantIdentity.Count)
		}
	}
	errorClass := ""
	if event.ErrorClass != "" {
		errorClass = " error=" + string(event.ErrorClass)
	}
	_, err := fmt.Fprintf(
		stdout,
		"watch[%d] at=%s run=%s state=%s pause=%s next=%s%s%s\n",
		event.Sequence,
		event.ObservedAt,
		event.RunID,
		event.State,
		event.PauseCause,
		event.NextAction,
		identity,
		errorClass,
	)
	return err
}

func (c command) waitForWatchPoll(
	ctx context.Context,
	interval time.Duration,
	deadline time.Time,
) error {
	remaining := deadline.Sub(c.now())
	if remaining <= 0 {
		return &watchTimeoutError{timeout: 0}
	}
	if interval > remaining {
		interval = remaining
	}
	if err := c.wait(ctx, interval); err != nil {
		return err
	}
	if !c.now().Before(deadline) {
		return &watchTimeoutError{timeout: 0}
	}
	return nil
}
