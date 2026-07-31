package issuedelivery

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Status observes one persisted schema-v2 run without advancing or rewriting it.
func (m *Module) Status(ctx context.Context, request StatusRequest) (Outcome, error) {
	if ctx == nil {
		return Outcome{}, errors.New("Status requires a context")
	}
	if request.IssueNumber <= 0 || strings.TrimSpace(request.RepositoryPath) == "" {
		return Outcome{}, errors.New("Status requires a repository path and positive issue number")
	}
	git, err := m.git.ObserveGit(ctx, request.RepositoryPath)
	if err != nil {
		return Outcome{}, fmt.Errorf("observe Git: %w", err)
	}

	var outcome Outcome
	err = m.store.observeIssue(ctx, git.CommonDir, request.IssueNumber, func(store lockedIssueStore) error {
		activeID, activeData, found, err := store.loadActive()
		if err != nil {
			return err
		}
		if !found {
			return errors.New("active issue delivery run does not exist")
		}
		active, err := decodeRun(activeData)
		if err != nil {
			return err
		}
		if active.ID != activeID {
			return errors.New("active issue delivery run identity does not match its selector")
		}
		if active.Schema != runSchema {
			return errors.New("schema v1 issue delivery status requires the explicit legacy-v1 workflow")
		}
		if active.Issue.Number != request.IssueNumber ||
			active.Repository.Owner != git.Owner || active.Repository.Name != git.Name {
			return errors.New("active issue delivery run identity does not match requested repository and issue")
		}

		tracker, err := m.github.ObserveIssue(ctx, git, request.IssueNumber)
		if err != nil {
			return fmt.Errorf("observe GitHub issue: %w", err)
		}
		if tracker.Issue.Number != request.IssueNumber {
			return fmt.Errorf(
				"GitHub observer returned issue #%d for requested issue #%d",
				tracker.Issue.Number,
				request.IssueNumber,
			)
		}
		if active.Repository != tracker.Repository || active.Issue != tracker.Issue {
			return errors.New("active issue delivery run identity does not match current repository and issue")
		}
		outcome = outcomeFromRecord(active)
		return nil
	})
	if errors.Is(err, errIssueRunActive) {
		return outcomeWithPause(Outcome{
			State: StateWaiting, Reason: "another Advance call is active for this issue",
			IssueLockContended: true,
		}), nil
	}
	if err != nil {
		return Outcome{}, err
	}
	return outcomeWithPause(outcome), nil
}
