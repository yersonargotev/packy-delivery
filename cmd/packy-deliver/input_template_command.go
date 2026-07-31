package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type inputTemplateOptions struct {
	RepositoryPath string
	IssueNumber    int
	Kind           issuedelivery.InputTemplateKind
	OutputPath     string
	Force          bool
}

type issueDeliveryInputTemplateMaterializer interface {
	MaterializeInputTemplate(
		context.Context,
		issuedelivery.InputTemplateRequest,
	) (issuedelivery.InputTemplate, error)
}

type inputTemplateFactory func(string) (issueDeliveryInputTemplateMaterializer, error)

func (c command) inputTemplate(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("packy-deliver input-template", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var options inputTemplateOptions
	var kind string
	f.StringVar(&options.RepositoryPath, "repository", "", "absolute repository containing the delivery run")
	f.IntVar(&options.IssueNumber, "issue", 0, "Packy issue number")
	f.StringVar(&kind, "kind", "", "pending semantic-input kind")
	f.StringVar(&options.OutputPath, "output", "", "exact draft file to create")
	f.BoolVar(&options.Force, "force", false, "atomically replace an existing regular output file")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || options.IssueNumber <= 0 ||
		strings.TrimSpace(options.RepositoryPath) == "" ||
		strings.TrimSpace(kind) == "" ||
		strings.TrimSpace(options.OutputPath) == "" {
		return errors.New("issue, kind, output, and repository are required and positional arguments are forbidden")
	}
	if !filepath.IsAbs(options.RepositoryPath) {
		return errors.New("repository must be an absolute path")
	}
	options.Kind = issuedelivery.InputTemplateKind(kind)
	var err error
	options.RepositoryPath, err = filepath.EvalSymlinks(options.RepositoryPath)
	if err != nil {
		return fmt.Errorf("resolve repository: %w", err)
	}
	options.RepositoryPath = filepath.Clean(options.RepositoryPath)
	if c.InputTemplateFactory == nil {
		return errors.New("input-template adapter is unavailable")
	}
	materializer, err := c.InputTemplateFactory(options.RepositoryPath)
	if err != nil {
		return fmt.Errorf("configure input-template: %w", err)
	}
	template, err := materializer.MaterializeInputTemplate(ctx, issuedelivery.InputTemplateRequest{
		RepositoryPath: options.RepositoryPath,
		IssueNumber:    options.IssueNumber,
		Kind:           options.Kind,
	})
	if err != nil {
		return err
	}
	content, err := inputTemplateJSON(options.Kind, template)
	if err != nil {
		return err
	}
	return writeInputTemplate(options.OutputPath, content, options.Force)
}

func inputTemplateJSON(
	kind issuedelivery.InputTemplateKind,
	template issuedelivery.InputTemplate,
) ([]byte, error) {
	var value any
	switch kind {
	case issuedelivery.InputTemplateDecision:
		if template.Decision == nil {
			return nil, errors.New("materialized decision template is absent")
		}
		value = template.Decision
	case issuedelivery.InputTemplateQualificationReview:
		if template.QualificationReview == nil {
			return nil, errors.New("materialized qualification review template is absent")
		}
		value = advanceReviewContent{
			Reviews:             []issuedelivery.CandidateReview{},
			Specialists:         []issuedelivery.SpecialistReview{},
			Acceptance:          []issuedelivery.AcceptanceProof{},
			QualificationReview: template.QualificationReview,
		}
	case issuedelivery.InputTemplateQualificationCorrection:
		if template.QualificationCorrection == nil {
			return nil, errors.New("materialized qualification correction template is absent")
		}
		value = advanceReviewContent{
			Reviews:                 []issuedelivery.CandidateReview{},
			Specialists:             []issuedelivery.SpecialistReview{},
			Acceptance:              []issuedelivery.AcceptanceProof{},
			QualificationCorrection: template.QualificationCorrection,
		}
	case issuedelivery.InputTemplateRepair:
		if template.Repair == nil {
			return nil, errors.New("materialized repair template is absent")
		}
		value = template.Repair
	case issuedelivery.InputTemplateCIAttribution:
		if len(template.CIAttributions) == 0 {
			return nil, errors.New("materialized CI attribution template is absent")
		}
		value = template.CIAttributions
	default:
		return nil, fmt.Errorf("input template kind %q is invalid", kind)
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode input template: %w", err)
	}
	return append(raw, '\n'), nil
}

func writeInputTemplate(path string, content []byte, force bool) (returnErr error) {
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	switch {
	case err == nil && !force:
		return fmt.Errorf("output %q already exists; use --force to replace it", path)
	case err == nil && info.Mode().Type() != 0:
		return fmt.Errorf("output %q is not a regular file", path)
	case errors.Is(err, fs.ErrNotExist) && force:
		return fmt.Errorf("output %q does not exist; --force replaces only an existing regular file", path)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("inspect output %q: %w", path, err)
	}

	parent := filepath.Dir(path)
	temp, err := os.CreateTemp(parent, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary input template: %w", err)
	}
	tempPath := temp.Name()
	tempOpen := true
	defer func() {
		var closeErr error
		if tempOpen {
			closeErr = temp.Close()
		}
		removeErr := os.Remove(tempPath)
		if returnErr == nil && closeErr != nil {
			returnErr = fmt.Errorf("close temporary input template: %w", closeErr)
		}
		if returnErr == nil && removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			returnErr = fmt.Errorf("remove temporary input template: %w", removeErr)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("set input template permissions: %w", err)
	}
	if _, err := temp.Write(content); err != nil {
		return fmt.Errorf("write input template: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync input template: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close input template: %w", err)
	}
	tempOpen = false
	if force {
		if err := atomicExchangeInputTemplate(tempPath, path); err != nil {
			return fmt.Errorf("replace input template: %w", err)
		}
		replaced, err := os.Lstat(tempPath)
		if err != nil {
			return fmt.Errorf("inspect replaced input template: %w", err)
		}
		if replaced.Mode().Type() != 0 {
			if restoreErr := atomicExchangeInputTemplate(tempPath, path); restoreErr != nil {
				return fmt.Errorf(
					"restore non-regular input template target after replacement refusal: %w",
					restoreErr,
				)
			}
			return fmt.Errorf("output %q is not a regular file", path)
		}
		if err := os.Remove(tempPath); err != nil {
			return fmt.Errorf("remove replaced input template: %w", err)
		}
	} else if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("output %q already exists; use --force to replace it", path)
		}
		return fmt.Errorf("create input template: %w", err)
	} else if err := os.Remove(tempPath); err != nil {
		return fmt.Errorf("remove linked input template temporary file: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("sync input template directory: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func containsInputTemplateHelpFlag(args []string) bool {
	return containsHelpFlag(args, func(arg string) bool {
		switch arg {
		case "-repository", "--repository", "-issue", "--issue",
			"-kind", "--kind", "-output", "--output":
			return true
		default:
			return false
		}
	})
}

func newProductionInputTemplateMaterializer(
	repository string,
) (issueDeliveryInputTemplateMaterializer, error) {
	runner := execRunner{}
	return issuedelivery.New(issuedelivery.Config{
		Git:              productionGitObserver{runner: runner},
		GitHub:           productionTrackerObserver{runner: runner},
		NonLocalObserver: productionNonLocalGateway{runner: runner, repository: repository},
	})
}
