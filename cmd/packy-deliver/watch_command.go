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

const watchEventSchema = "packy.watch-event/v1"

type watchOptions struct {
	RepositoryPath string
	IssueNumber    int
	Interval       time.Duration
	Timeout        time.Duration
	Output         string
}

type issueDeliveryWatcher interface {
	Watch(context.Context, issuedelivery.WatchRequest, issuedelivery.WatchEmitter) error
}

type watchFactory func(statusOptions) (issueDeliveryWatcher, error)

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
	Operation        *issuedelivery.Operation              `json:"operation,omitempty"`
}

type watchTimeoutError struct {
	err error
}

func (e *watchTimeoutError) Error() string { return e.err.Error() }
func (e *watchTimeoutError) Unwrap() error { return e.err }
func (*watchTimeoutError) ExitCode() int   { return 2 }

func (c command) watch(ctx context.Context, args []string, stdout io.Writer) error {
	if ctx == nil {
		return errors.New("watch requires a context")
	}
	options, err := parseWatchOptions(args)
	if err != nil {
		return err
	}
	if c.WatchFactory == nil {
		return errors.New("Watch adapter is unavailable")
	}
	watcher, err := c.WatchFactory(statusOptions{
		RepositoryPath: options.RepositoryPath,
		IssueNumber:    options.IssueNumber,
	})
	if err != nil {
		return fmt.Errorf("configure Watch: %w", err)
	}
	err = watcher.Watch(ctx, issuedelivery.WatchRequest{
		RepositoryPath: options.RepositoryPath,
		IssueNumber:    options.IssueNumber,
		Interval:       options.Interval,
		Timeout:        options.Timeout,
	}, func(event issuedelivery.WatchEvent) error {
		return emitWatchEvent(stdout, options.Output, watchEventFromDomain(event))
	})
	var timeout *issuedelivery.WatchTimeoutError
	if errors.As(err, &timeout) {
		return &watchTimeoutError{err: err}
	}
	return err
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
	request := issuedelivery.WatchRequest{
		RepositoryPath: options.RepositoryPath,
		IssueNumber:    options.IssueNumber,
		Interval:       options.Interval,
		Timeout:        options.Timeout,
	}
	if err := issuedelivery.ValidateWatchRequest(request); err != nil {
		return watchOptions{}, err
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

func watchEventFromDomain(observed issuedelivery.WatchEvent) watchEvent {
	outcome := observed.Outcome
	event := watchEvent{
		Schema: watchEventSchema, Sequence: observed.Sequence,
		ObservedAt: observed.ObservedAt.UTC().Format(time.RFC3339Nano),
		RunID:      outcome.RunID, State: outcome.State,
		PauseCause: outcome.PauseCause, NextAction: outcome.NextAction,
		ErrorClass: observed.ErrorClass,
		Operation:  outcome.Operation,
	}
	if outcome.StatusObservation != nil {
		identity := outcome.StatusObservation.Current
		event.RelevantIdentity = &identity
	}
	return event
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
	operation := ""
	if event.Operation != nil {
		operation = fmt.Sprintf(
			" operation=%s kind=%s phase=%s state=%s started=%s",
			event.Operation.ID,
			event.Operation.Kind,
			event.Operation.Phase,
			event.Operation.State,
			event.Operation.StartedAt,
		)
		if event.Operation.ValidationSessionID != "" {
			operation += " validation-session=" + event.Operation.ValidationSessionID
		}
	}
	_, err := fmt.Fprintf(
		stdout,
		"watch[%d] at=%s run=%s state=%s pause=%s next=%s%s%s%s\n",
		event.Sequence,
		event.ObservedAt,
		event.RunID,
		event.State,
		event.PauseCause,
		event.NextAction,
		identity,
		operation,
		errorClass,
	)
	return err
}
