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

	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type statusOptions struct {
	RepositoryPath string
	IssueNumber    int
	Output         string
}

type issueDeliveryStatuser interface {
	Status(context.Context, issuedelivery.StatusRequest) (issuedelivery.Outcome, error)
}

type statusFactory func(statusOptions) (issueDeliveryStatuser, error)

type productionStatusNonLocalObserver struct {
	gateway productionNonLocalGateway
}

func (observer productionStatusNonLocalObserver) ObserveNonLocal(
	ctx context.Context,
	request issuedelivery.NonLocalObserveRequest,
) (issuedelivery.NonLocalObservation, error) {
	observation, err := observer.gateway.observeNonLocal(ctx, request, false)
	if err != nil {
		var commandError *remoteCommandError
		if errors.As(err, &commandError) {
			return issuedelivery.NonLocalObservation{}, classifyStatusCommandError(
				issuedelivery.StatusErrorExternalRead,
				issuedelivery.StatusErrorIdentity,
				err,
			)
		}
		var decodeError *remoteDecodeError
		if errors.As(err, &decodeError) {
			return issuedelivery.NonLocalObservation{}, issuedelivery.NewStatusError(
				issuedelivery.StatusErrorCorruption,
				false,
				err,
			)
		}
		return issuedelivery.NonLocalObservation{}, issuedelivery.NewStatusError(
			issuedelivery.StatusErrorIdentity,
			false,
			err,
		)
	}
	return observation, nil
}

func classifyStatusCommandError(
	transientClass issuedelivery.StatusErrorClass,
	rejectedClass issuedelivery.StatusErrorClass,
	err error,
) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if _, _, typed := issuedelivery.StatusErrorDetails(err); typed {
		return err
	}
	var rejected *commandRejectedError
	if errors.As(err, &rejected) {
		return issuedelivery.NewStatusError(rejectedClass, false, err)
	}
	return issuedelivery.NewStatusError(transientClass, true, err)
}

func (c command) status(ctx context.Context, args []string, stdout io.Writer) error {
	f := flag.NewFlagSet("packy-deliver status", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var options statusOptions
	f.StringVar(&options.RepositoryPath, "repository", "", "absolute repository containing the delivery run")
	f.IntVar(&options.IssueNumber, "issue", 0, "Packy issue number")
	f.StringVar(&options.Output, "output", "json", "compact report format: json or text")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || options.IssueNumber <= 0 || strings.TrimSpace(options.RepositoryPath) == "" {
		return errors.New("issue and repository are required and positional arguments are forbidden")
	}
	if !filepath.IsAbs(options.RepositoryPath) {
		return errors.New("repository must be an absolute path")
	}
	if options.Output != "json" && options.Output != "text" {
		return fmt.Errorf("output %q is invalid; use json or text", options.Output)
	}
	var err error
	options.RepositoryPath, err = filepath.EvalSymlinks(options.RepositoryPath)
	if err != nil {
		return fmt.Errorf("resolve repository: %w", err)
	}
	options.RepositoryPath = filepath.Clean(options.RepositoryPath)
	if c.StatusFactory == nil {
		return errors.New("Status adapter is unavailable")
	}
	observer, err := c.StatusFactory(options)
	if err != nil {
		return fmt.Errorf("configure Status: %w", err)
	}
	outcome, err := observer.Status(ctx, issuedelivery.StatusRequest{
		RepositoryPath: options.RepositoryPath,
		IssueNumber:    options.IssueNumber,
	})
	if err != nil {
		return err
	}
	report, err := compactReportFromOutcome(outcome, c.now())
	if err != nil {
		return err
	}
	if options.Output == "text" {
		_, err = io.WriteString(stdout, renderCompactAdvanceReport(report))
		return err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	_, err = stdout.Write(raw)
	return err
}

func containsStatusHelpFlag(args []string) bool {
	return containsHelpFlag(args, func(arg string) bool {
		switch arg {
		case "-repository", "--repository", "-issue", "--issue", "-output", "--output", "-bundle", "--bundle":
			return true
		default:
			return false
		}
	})
}

func newProductionStatuser(options statusOptions) (issueDeliveryStatuser, error) {
	return newProductionObservationModule(options)
}

func newProductionWatcher(options statusOptions) (issueDeliveryWatcher, error) {
	return newProductionObservationModule(options)
}

func newProductionObservationModule(options statusOptions) (*issuedelivery.Module, error) {
	runner := execRunner{}
	return issuedelivery.New(issuedelivery.Config{
		Git:    productionGitObserver{runner: runner},
		GitHub: productionTrackerObserver{runner: runner},
		NonLocalObserver: productionStatusNonLocalObserver{
			gateway: productionNonLocalGateway{
				runner: runner, repository: options.RepositoryPath,
			},
		},
	})
}
