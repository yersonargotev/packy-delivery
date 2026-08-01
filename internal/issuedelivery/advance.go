package issuedelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func (m *Module) Advance(ctx context.Context, request Request) (Outcome, error) {
	if ctx == nil {
		return Outcome{}, errors.New("Advance requires a context")
	}
	if request.IssueNumber <= 0 || strings.TrimSpace(request.RepositoryPath) == "" {
		return Outcome{}, errors.New("Advance requires a repository path and positive issue number")
	}
	git, err := m.git.ObserveGit(ctx, request.RepositoryPath)
	if err != nil {
		return Outcome{}, fmt.Errorf("observe Git: %w", err)
	}
	operation, err := newAdvanceOperation(time.Now())
	if err != nil {
		return Outcome{}, err
	}

	var outcome Outcome
	err = m.store.withAdvanceOperationLock(ctx, git.CommonDir, request.IssueNumber, &operation, func(ctx context.Context, store lockedIssueStore) error {
		tracker, err := m.github.ObserveIssue(ctx, git, request.IssueNumber)
		if err != nil {
			return fmt.Errorf("observe GitHub issue: %w", err)
		}
		if tracker.Issue.Number != request.IssueNumber {
			return fmt.Errorf("GitHub observer returned issue #%d for requested issue #%d", tracker.Issue.Number, request.IssueNumber)
		}
		activeID, activeData, found, err := store.loadActive()
		if err != nil {
			return err
		}
		var active runRecord
		if found {
			active, err = decodeRun(activeData)
			if err != nil {
				return err
			}
			if active.ID != activeID || active.Repository != tracker.Repository || active.Issue != tracker.Issue {
				return errors.New("active issue delivery run identity does not match current authority")
			}
			if active.Schema == legacyRunSchema && !m.allowLegacyV1 {
				return errors.New("schema v1 issue delivery requires the explicit legacy-v1 workflow")
			}
			if active.State == StateCompleted {
				outcome = outcomeFromRecord(active)
				return nil
			}
			if active.NonLocal != nil && active.NonLocal.PullRequest != nil && m.nonlocal == nil {
				outcome, err = m.persistAssuranceTransition(
					store, active, StateBlocked,
					"existing pull request requires a non-local observer to exclude or adopt merge; candidate flow remains disabled",
					"post-merge-observation",
				)
				return err
			}
			if active.NonLocal != nil && active.NonLocal.PullRequest != nil && m.nonlocal != nil {
				var handled bool
				outcome, handled, err = m.resumeMergedBeforeAuthority(
					ctx, store, active, git, tracker, request,
				)
				if err != nil || handled {
					return err
				}
			}
		}
		compiled, err := compileAuthority(git, tracker, active.Decisions, request.Decision, m.declaredProfile)
		if err != nil {
			return err
		}
		if found {
			if active.AuthoritySHA256 == compiled.hash {
				if request.Decision != nil {
					return errors.New("delivery decision is not expected after authority qualification")
				}
				var handled bool
				outcome, handled, err = m.advanceQualification(store, active, request)
				if handled && err == nil {
					outcome.Observations = observationsFrom(git, tracker, compiled.hash)
				}
				if err != nil || handled {
					return err
				}
				if m.review != nil {
					outcome, err = m.advanceAssurance(ctx, store, active, git, tracker, compiled, request)
					return err
				}
				if request.Repair != nil {
					return errors.New("repair decision requires configured review and validation executors")
				}
				outcome = outcomeFromRecord(active)
				outcome.Observations = observationsFrom(git, tracker, compiled.hash)
				return nil
			}
		}

		nowStarted := m.clock.Now().UTC()
		supersedes := ""
		if found {
			supersedes = active.ID
		}
		runID := runIdentity(tracker.Repository, tracker.Issue, compiled.hash, supersedes)
		orphanData, orphanFound, err := store.loadRun(runID)
		if err != nil {
			return err
		}
		if orphanFound {
			orphan, err := decodeRun(orphanData)
			if err != nil {
				return err
			}
			if !compatibleOrphan(orphan, tracker, compiled, supersedes) {
				return errors.New("orphaned issue delivery run does not match current qualification")
			}
			if err := store.activate(runID); err != nil {
				return err
			}
			outcome, _, err = m.advanceQualification(store, orphan, request)
			if err != nil {
				return err
			}
			if outcome.RunID == "" {
				outcome = outcomeFromRecord(orphan)
			}
			outcome.Observations = observationsFrom(git, tracker, compiled.hash)
			return nil
		}
		nowCompleted := m.clock.Now().UTC()
		record := runRecord{
			Schema: runSchema, ID: runID, Repository: tracker.Repository, Issue: tracker.Issue,
			AuthoritySHA256: compiled.hash, State: compiled.state, Reason: compiled.reason,
			Evidence: &compiled.evidence, PendingDecision: compiled.pending,
			PendingQualificationCorrection: compiled.qualification,
			Decisions:                      append([]Decision{}, compiled.decisions...),
			Observations:                   observationsFrom(git, tracker, compiled.hash),
			EffectiveProfile:               compiled.evidence.RiskProfile,
			Timing: []Timing{{
				Sequence: 1, Phase: "qualification", To: compiled.state,
				StartedAt: nowStarted.Format(timeFormat), CompletedAt: nowCompleted.Format(timeFormat),
			}},
			CreatedAt: nowStarted.Format(timeFormat), UpdatedAt: nowCompleted.Format(timeFormat),
		}
		if compiled.pending != nil {
			record.Evidence = nil
		}
		if found {
			record.SupersedesRunID = active.ID
		}
		if err := projectAutomaticAssurance(&record); err != nil {
			return err
		}
		data, err := encodeRun(record)
		if err != nil {
			return err
		}
		if err := store.storeAndActivate(runID, data); err != nil {
			return err
		}
		outcome = outcomeFromRecord(record)
		return nil
	})
	if errors.Is(err, errIssueRunActive) {
		operation.State = OperationCompleted
		outcome = Outcome{
			State: StateWaiting, Reason: "another Advance call is active for this issue",
			IssueLockContended: true,
		}
		err = nil
	}
	if err != nil {
		return Outcome{}, err
	}
	outcome.Operation = &operation
	return outcomeWithPause(outcome), nil
}

func compatibleOrphan(
	record runRecord,
	tracker TrackerObservation,
	compiled compiledAuthority,
	supersedes string,
) bool {
	common := record.Repository == tracker.Repository &&
		record.Issue == tracker.Issue &&
		record.AuthoritySHA256 == compiled.hash &&
		record.SupersedesRunID == supersedes &&
		equalQualificationEvidence(record.Evidence, evidencePointer(compiled)) &&
		reflect.DeepEqual(record.PendingDecision, compiled.pending) &&
		reflect.DeepEqual(record.Decisions, compiled.decisions)
	if !common {
		return false
	}
	if record.State == compiled.state && record.Reason == compiled.reason &&
		reflect.DeepEqual(record.PendingQualificationCorrection, compiled.qualification) {
		return true
	}
	return compatiblePreCompilerCorrectionOrphan(record, compiled)
}

func equalQualificationEvidence(left, right *deliveryevidence.Bundle) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftCopy, rightCopy := *left, *right
	leftCopy.CandidateReviewReceipts, rightCopy.CandidateReviewReceipts = nil, nil
	leftCopy.AssuranceAdjudications, rightCopy.AssuranceAdjudications = nil, nil
	leftCopy.AssurancePhases, rightCopy.AssurancePhases = nil, nil
	leftCopy.ExhaustiveAssurance, rightCopy.ExhaustiveAssurance = nil, nil
	return reflect.DeepEqual(leftCopy, rightCopy)
}

func compatiblePreCompilerCorrectionOrphan(
	record runRecord,
	compiled compiledAuthority,
) bool {
	return record.Schema == runSchema &&
		compiled.qualification != nil &&
		record.State == StateNeedsReview &&
		record.Reason == "qualification evidence is ready for independent review" &&
		record.PendingQualificationCorrection == nil &&
		!record.QualificationApproved &&
		len(record.QualificationReviews) == 0 &&
		len(record.QualificationCorrections) == 0 &&
		requiresQualificationCorrection(record.Evidence)
}

func evidencePointer(compiled compiledAuthority) *deliveryevidence.Bundle {
	if compiled.pending != nil {
		return nil
	}
	return &compiled.evidence
}

const timeFormat = "2006-01-02T15:04:05.000000000Z"

func runIdentity(
	repository deliveryevidence.RepositoryIdentity,
	issue deliveryevidence.IssueIdentity,
	authorityHash, supersedes string,
) string {
	sum := sha256.Sum256([]byte(
		repository.NodeID + "\x00" + issue.NodeID + "\x00" + authorityHash + "\x00" + supersedes,
	))
	return hex.EncodeToString(sum[:])
}

func outcomeFromRecord(record runRecord) Outcome {
	var candidate *Candidate
	if current := latestCandidate(&record); current != nil {
		value := *current
		candidate = &value
	}
	return Outcome{
		RunID: record.ID, State: record.State, Reason: record.Reason,
		RunSchema:       record.Schema,
		BlockerKind:     blockerKindFromRecord(record),
		SupersedesRunID: record.SupersedesRunID, Decision: record.PendingDecision,
		Evidence: record.Evidence, Observations: record.Observations,
		Candidate: candidate, ImpactConfirmation: impactConfirmationFromCandidate(candidate),
		Repair: record.PendingRepair, LocalReadiness: record.LocalReadiness,
		QualificationCorrection: record.PendingQualificationCorrection,
		QualificationApproved:   record.QualificationApproved,
		QualificationReviews:    append([]QualificationReview(nil), record.QualificationReviews...),
		QualificationCorrections: append(
			[]QualificationCorrection(nil), record.QualificationCorrections...,
		),
		ValidationSessions: append(
			[]ValidationSession(nil), record.ValidationSessions...,
		),
		ValidationInvalidations: append(
			[]ValidationInvalidation(nil), record.ValidationInvalidations...,
		),
		NonLocal:         record.NonLocal,
		Timing:           append([]Timing(nil), record.Timing...),
		EffectiveProfile: record.EffectiveProfile,
	}
}

func outcomeWithPause(outcome Outcome) Outcome {
	switch {
	case outcome.State == StateCompleted:
		outcome.PauseCause, outcome.NextAction = PauseCompleted, ActionNone
	case outcome.State == StateBlocked:
		outcome.PauseCause, outcome.NextAction = PauseInvariantBlock, blockerNextAction(outcome.BlockerKind)
	case outcome.QualificationCorrection != nil:
		outcome.PauseCause, outcome.NextAction = PauseSemanticInput, ActionProvideQualificationCorrection
	case outcome.Repair != nil:
		outcome.PauseCause, outcome.NextAction = PauseSemanticInput, ActionProvideRepairDecision
	case outcome.Decision != nil || outcome.State == StateNeedsDecision:
		outcome.PauseCause, outcome.NextAction = PauseSemanticInput, ActionProvideDecision
	case outcome.State == StateNeedsReview:
		outcome.PauseCause, outcome.NextAction = reviewPause(outcome)
	case outcome.State == StateWaiting && outcome.IssueLockContended:
		outcome.PauseCause, outcome.NextAction = PauseLockContention, ActionRetryAdvance
	case outcome.State == StateWaiting && outcome.LocalReadiness != nil && outcome.NonLocal == nil:
		if outcome.RunSchema == legacyRunSchema {
			outcome.PauseCause, outcome.NextAction = PauseLegacyWorkflow, ActionResumeLegacyV1
		} else {
			outcome.PauseCause, outcome.NextAction = PauseNonLocalAuthorization, ActionAuthorizeNonLocal
		}
	case deterministicWaitingTransition(outcome):
		outcome.PauseCause, outcome.NextAction = PauseDeterministicAdvance, ActionAdvance
	default:
		outcome.PauseCause, outcome.NextAction = PauseExternalResult, ActionObserveExternalResult
	}
	return outcome
}

func deterministicWaitingTransition(outcome Outcome) bool {
	switch outcome.Reason {
	case "exact non-local delivery authority is recorded",
		"exact remote issue branch is proved",
		"exact pull-request creation intent is recorded before mutation",
		"one exact-head pull request is proved",
		"required CI is green for the exact candidate HEAD; awaiting merge authority",
		"exact merge intent is recorded before mutation",
		"exact completed merge is adopted; only verification and cleanup may continue",
		"post-merge operator-state baseline is recorded before cleanup",
		"remote issue branch absence was requested by exact identity",
		"one exact workflow-owned worktree absence was requested",
		"local issue branch absence was requested after worktree cleanup",
		"local main fast-forward was requested by compare-and-swap":
		return true
	default:
		return false
	}
}

func reviewPause(outcome Outcome) (PauseCause, NextAction) {
	if outcome.Candidate == nil {
		if outcome.QualificationApproved {
			return PauseDeterministicAdvance, ActionAdvance
		}
		return PauseIndependentReview, ActionProvideQualificationReview
	}
	if outcome.ImpactConfirmation != nil {
		return PauseSemanticInput, ActionProvideImpactConfirmation
	}
	if hasAcceptedFindings(outcome.Candidate.RepairDecision) ||
		(outcome.NonLocal != nil && outcome.NonLocal.CandidateFailure != nil) {
		return PauseCandidateRepair, ActionRepairCandidate
	}
	if len(missingReviewAxes(outcome.Candidate)) > 0 ||
		len(missingSpecialistBoundaries(outcome.Candidate)) > 0 {
		return PauseIndependentReview, ActionProvideCandidateReview
	}
	return PauseDeterministicAdvance, ActionAdvance
}

func blockerKindFromRecord(record runRecord) BlockerKind {
	if record.State != StateBlocked || len(record.Timing) == 0 {
		return ""
	}
	phase, reason := record.Timing[len(record.Timing)-1].Phase, record.Reason
	switch phase {
	case "qualification", "qualification-review", "qualification-correction":
		return BlockerAuthority
	case "post-merge-observation":
		switch {
		case strings.Contains(reason, "requires a non-local observer"):
			return BlockerNonLocalObserver
		case strings.Contains(reason, "requires a local verification and cleanup adapter"):
			return BlockerLocalCompletionObserver
		case strings.Contains(reason, "confirmed merge is absent"):
			return BlockerMergeObservationAbsent
		case strings.Contains(reason, "issue closed without"):
			return BlockerIssueClosure
		default:
			return BlockerMergeIdentity
		}
	case "specialist-review":
		return BlockerSpecialistReview
	case "risk-observation":
		return BlockerRiskObservation
	case "focused-validation", "boundary-validation", "exhaustive-validation":
		if strings.Contains(reason, "traceability") {
			return BlockerAcceptanceTraceability
		}
		return BlockerValidationEnvironment
	case "local-readiness":
		return BlockerLocalReadiness
	case "non-local-freshness":
		return BlockerNonLocalFreshness
	case "non-local-observation":
		return BlockerNonLocalObservation
	case "branch-push":
		return BlockerRemoteBranch
	case "pull-request":
		return BlockerPullRequest
	case "ci-wait":
		if strings.Contains(reason, "attribution is unknown") {
			return BlockerCIAttribution
		}
		return BlockerCIObservation
	case "merge-readiness":
		return BlockerMergeReadiness
	case "merge-adoption":
		if strings.Contains(reason, "local/operator observation") {
			return BlockerLocalCleanup
		}
		return BlockerMergeIdentity
	case "merge":
		return BlockerMergeIdentity
	case "integration-verification":
		return BlockerIntegration
	case "remote-cleanup":
		if strings.Contains(reason, "remote issue branch identity") {
			return BlockerRemoteBranch
		}
		return BlockerRemoteCleanup
	case "worktree-cleanup":
		return BlockerWorktreeCleanup
	case "local-branch-cleanup":
		return BlockerLocalBranchCleanup
	case "main-synchronization":
		return BlockerMainSynchronization
	case "local-cleanup":
		return BlockerLocalCleanup
	default:
		return ""
	}
}

func blockerNextAction(kind BlockerKind) NextAction {
	switch kind {
	case BlockerAuthority:
		return ActionResolveAuthorityBlock
	case BlockerNonLocalObserver:
		return ActionConfigureNonLocalObserver
	case BlockerLocalCompletionObserver:
		return ActionConfigureLocalCompletionObserver
	case BlockerMergeObservationAbsent:
		return ActionInspectMergeObservation
	case BlockerIssueClosure:
		return ActionInspectIssueClosure
	case BlockerMergeIdentity:
		return ActionReconcileMerge
	case BlockerSpecialistReview:
		return ActionRestoreSpecialistReview
	case BlockerRiskObservation:
		return ActionRepairRiskObservation
	case BlockerValidationEnvironment:
		return ActionRepairValidationEnvironment
	case BlockerAcceptanceTraceability:
		return ActionRepairAcceptanceTraceability
	case BlockerLocalReadiness:
		return ActionRestoreLocalReadiness
	case BlockerNonLocalFreshness:
		return ActionRestoreNonLocalFreshness
	case BlockerNonLocalObservation:
		return ActionRestoreNonLocalObservation
	case BlockerRemoteBranch:
		return ActionReconcileRemoteBranch
	case BlockerPullRequest:
		return ActionReconcilePullRequest
	case BlockerCIAttribution:
		return ActionProvideCIAttribution
	case BlockerCIObservation:
		return ActionRestoreCIObservation
	case BlockerMergeReadiness:
		return ActionRestoreMergeReadiness
	case BlockerIntegration:
		return ActionReconcileIntegration
	case BlockerRemoteCleanup:
		return ActionReconcileRemoteCleanup
	case BlockerWorktreeCleanup:
		return ActionReconcileWorktreeCleanup
	case BlockerLocalBranchCleanup:
		return ActionReconcileLocalBranchCleanup
	case BlockerMainSynchronization:
		return ActionReconcileMainSynchronization
	case BlockerLocalCleanup:
		return ActionReconcileLocalCleanup
	default:
		return ActionInspectBlockedTransition
	}
}

func observationsFrom(git GitObservation, tracker TrackerObservation, authoritySHA256 string) Observations {
	return Observations{
		Repository: tracker.Repository, Issue: tracker.Issue, AuthoritySHA256: authoritySHA256,
		CommitSHA: git.HeadSHA, TreeSHA: git.TreeSHA, WorkspaceClean: git.WorkspaceClean,
	}
}
