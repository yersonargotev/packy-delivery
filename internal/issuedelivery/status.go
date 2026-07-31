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
		return Outcome{}, NewStatusError(
			StatusErrorGitRead,
			true,
			fmt.Errorf("observe Git: %w", err),
		)
	}

	var outcome Outcome
	err = m.store.observeIssue(ctx, git.CommonDir, request.IssueNumber, func(store lockedIssueStore) error {
		activeID, activeData, found, err := store.loadActive()
		if err != nil {
			return NewStatusError(StatusErrorRunState, false, err)
		}
		if !found {
			return NewStatusError(
				StatusErrorRunState,
				false,
				errors.New("active issue delivery run does not exist"),
			)
		}
		active, err := decodeRun(activeData)
		if err != nil {
			return NewStatusError(StatusErrorCorruption, false, err)
		}
		if active.ID != activeID {
			return NewStatusError(
				StatusErrorIdentity,
				false,
				errors.New("active issue delivery run identity does not match its selector"),
			)
		}
		if active.Schema != runSchema {
			return NewStatusError(
				StatusErrorLegacy,
				false,
				errors.New("schema v1 issue delivery status requires the explicit legacy-v1 workflow"),
			)
		}
		if active.Issue.Number != request.IssueNumber ||
			active.Repository.Owner != git.Owner || active.Repository.Name != git.Name {
			return NewStatusError(
				StatusErrorIdentity,
				false,
				errors.New("active issue delivery run identity does not match requested repository and issue"),
			)
		}

		tracker, err := m.github.ObserveIssue(ctx, git, request.IssueNumber)
		if err != nil {
			return NewStatusError(
				StatusErrorGitHubRead,
				true,
				fmt.Errorf("observe GitHub issue: %w", err),
			)
		}
		if tracker.Issue.Number != request.IssueNumber {
			return NewStatusError(
				StatusErrorAuthority,
				false,
				fmt.Errorf(
					"GitHub observer returned issue #%d for requested issue #%d",
					tracker.Issue.Number,
					request.IssueNumber,
				),
			)
		}
		if active.Repository != tracker.Repository || active.Issue != tracker.Issue {
			return NewStatusError(
				StatusErrorAuthority,
				false,
				errors.New("active issue delivery run identity does not match current repository and issue"),
			)
		}

		persisted := outcomeWithPause(outcomeFromRecord(active))
		var currentNonLocal *NonLocalObservation
		if persisted.PauseCause == PauseExternalResult &&
			active.NonLocal != nil &&
			m.nonlocalObserver != nil {
			candidate := latestCandidate(&active)
			if candidate == nil || active.LocalReadiness == nil {
				return NewStatusError(
					StatusErrorRunState,
					false,
					errors.New("non-local status lacks current candidate readiness"),
				)
			}
			observation, err := m.nonlocalObserver.ObserveNonLocal(
				ctx,
				nonLocalObserveRequest(active, *candidate),
			)
			if err != nil {
				if _, _, typed := StatusErrorDetails(err); typed {
					return err
				}
				return NewStatusError(StatusErrorExternalRead, true, err)
			}
			currentNonLocal = &observation
		}
		statusObservation, err := statusObservationFrom(active, git, currentNonLocal)
		if err != nil {
			return NewStatusError(StatusErrorIdentity, false, err)
		}
		persisted.StatusObservation = &statusObservation
		outcome = persisted
		return nil
	})
	if errors.Is(err, errIssueRunActive) {
		return outcomeWithPause(Outcome{
			State: StateWaiting, Reason: "another Advance call is active for this issue",
			IssueLockContended: true,
			StatusObservation: &StatusObservation{
				Persisted: StatusRelevantIdentity{Kind: StatusIdentityLock, Value: "contended"},
				Current:   StatusRelevantIdentity{Kind: StatusIdentityLock, Value: "contended"},
			},
		}), nil
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Outcome{}, err
		}
		if _, _, typed := StatusErrorDetails(err); typed {
			return Outcome{}, err
		}
		return Outcome{}, NewStatusError(StatusErrorRunState, false, err)
	}
	if outcome.StatusObservation == nil {
		return Outcome{}, NewStatusError(
			StatusErrorRunState,
			false,
			errors.New("status observation is unavailable"),
		)
	}
	if err := ctx.Err(); err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}
