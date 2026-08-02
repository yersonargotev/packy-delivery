package issuedelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func (m *Module) advanceAssurance(
	ctx context.Context,
	store lockedIssueStore,
	record runRecord,
	git GitObservation,
	tracker TrackerObservation,
	compiled compiledAuthority,
	request Request,
) (Outcome, error) {
	if request.Repair != nil {
		candidate := latestCandidate(&record)
		if record.Schema != legacyRunSchema &&
			(candidate == nil || candidate.CommitSHA != git.HeadSHA || candidate.TreeSHA != git.TreeSHA) {
			return Outcome{}, errors.New("repair decision does not match the current Git checkout")
		}
		return m.applyRepairDecision(store, record, *request.Repair)
	}
	if request.ImpactAssessment != nil && request.ImpactConfirmationResponse != nil {
		return Outcome{}, errors.New("one Advance call cannot supply an impact assessment and confirmation")
	}
	if record.PendingRepair != nil {
		return outcomeFromRecord(record), nil
	}
	if request.NonLocal != nil && m.nonlocal == nil {
		return Outcome{}, errors.New("non-local authorization requires a configured non-local gateway")
	}
	if request.NonLocal != nil && record.LocalReadiness == nil {
		return Outcome{}, errors.New("non-local authorization requires exact local readiness")
	}

	candidate := latestCandidate(&record)
	if (request.ImpactAssessment != nil || request.ImpactConfirmationResponse != nil) &&
		(candidate == nil || candidate.CommitSHA != git.HeadSHA || candidate.TreeSHA != git.TreeSHA) {
		return Outcome{}, errors.New("impact evidence requires the exact current derived candidate")
	}
	if len(request.CandidateReviews) != 0 && len(request.SpecialistReviews) != 0 {
		return Outcome{}, errors.New("one Advance call cannot supply candidate and specialist packet responses")
	}
	if len(request.CandidateReviews) != 0 || len(request.SpecialistReviews) != 0 {
		if candidate == nil || candidate.CommitSHA != git.HeadSHA || candidate.TreeSHA != git.TreeSHA {
			return Outcome{}, errors.New("review packet response does not match the exact current candidate")
		}
	}
	if (request.ImpactAssessment != nil || request.ImpactConfirmationResponse != nil) &&
		(len(request.CandidateReviews) != 0 || len(request.SpecialistReviews) != 0) {
		return Outcome{}, errors.New("one Advance call cannot supply impact evidence and review responses")
	}
	if record.Schema != legacyRunSchema && candidate == nil &&
		git.HeadSHA == record.Evidence.StartingBaseSHA {
		const reason = "qualification is approved; awaiting candidate development"
		if record.State == StateWaiting && record.Reason == reason {
			return outcomeFromRecord(record), nil
		}
		return m.persistAssuranceTransition(
			store,
			record,
			StateWaiting,
			reason,
			"candidate-development",
		)
	}
	candidateDevelopmentObserved := candidate != nil
	if !candidateDevelopmentObserved && record.Evidence != nil {
		candidateDevelopmentObserved = git.HeadSHA != record.Evidence.StartingBaseSHA
	}
	if candidateDevelopmentObserved && !deliveryBranch(git.Branch, tracker.Issue.Number) {
		return m.persistAssuranceTransition(
			store, record, StateBlocked,
			localReadinessBlockReason(tracker.Issue.Number),
			"local-readiness",
		)
	}
	if candidate == nil || candidate.CommitSHA != git.HeadSHA || candidate.TreeSHA != git.TreeSHA {
		if candidate != nil && hasAcceptedFindings(candidate.RepairDecision) {
			// The changed tree is the declared repair batch.
		} else if candidate != nil && unresolvedFindingIDs(candidate) != nil {
			return Outcome{}, errors.New("candidate changed before its review findings were adjudicated")
		}
		activityPhase := "implementation"
		if candidate != nil {
			activityPhase = "repair"
		}
		if err := m.appendElapsedTiming(&record, activityPhase, m.clock.Now().UTC()); err != nil {
			return Outcome{}, err
		}
		next := newCandidate(record, candidate, git)
		if record.Schema != legacyRunSchema {
			if _, err := m.observeCandidateRisk(ctx, &record, &next, candidate, request.RepositoryPath); err != nil {
				return m.persistAssuranceTransition(
					store, record, StateBlocked, "candidate risk observation is incomplete or invalid",
					"risk-observation",
				)
			}
		}
		if err := validateSandboxRoot(m.sandboxRoot); err != nil {
			return m.persistAssuranceTransition(
				store, record, StateBlocked, "configured validation sandbox is not physically isolated",
				"focused-validation",
			)
		}
		result, err := m.validation.Focused(ctx, m.validationRequest(record, next))
		if err != nil {
			return Outcome{}, fmt.Errorf("run focused validation: %w", err)
		}
		if err := m.validateValidationResult(result, next, false); err != nil {
			return m.persistAssuranceTransition(
				store, record, StateBlocked, "focused validation sandbox or exact candidate evidence is invalid",
				"focused-validation",
			)
		}
		next.Focused = &ValidationProof{
			Kind: "focused", Result: result, CompletedAt: m.clock.Now().UTC().Format(timeFormat),
		}
		record.Candidates = append(record.Candidates, next)
		record.LocalReadiness = nil
		record.NonLocal = nil
		invalidateAcceptance(record.Evidence, record.QualificationCorrections)
		return m.persistAssuranceTransition(
			store, record, StateNeedsReview, "focused candidate evidence is ready for review", "focused-validation",
		)
	}

	if record.NonLocal != nil && record.NonLocal.CandidateFailure != nil &&
		record.NonLocal.Authorization.CandidateID == candidate.ID {
		return outcomeWithReason(
			record, StateNeedsReview,
			"change-attributable CI failure requires a candidate-changing repair",
		), nil
	}

	if record.Schema != legacyRunSchema {
		riskChanged, err := m.observeCandidateRisk(ctx, &record, candidate, nil, request.RepositoryPath)
		if err != nil {
			return m.persistAssuranceTransition(
				store, record, StateBlocked, "candidate risk observation is incomplete or invalid",
				"risk-observation",
			)
		}
		if riskChanged {
			invalidateForProfileEscalation(&record, candidate)
			return m.persistAssuranceTransition(
				store, record, StateNeedsReview, "candidate assurance profile or sensitive boundaries escalated",
				"risk-observation",
			)
		}
	}
	if request.ImpactAssessment != nil {
		return m.admitImpactAssessment(store, record, candidate, *request.ImpactAssessment)
	}
	if request.ImpactConfirmationResponse != nil {
		return m.admitImpactConfirmation(store, record, candidate, *request.ImpactConfirmationResponse)
	}
	if candidate.Derivation != nil && candidate.Derivation.PendingConfirmation != nil {
		return outcomeFromRecord(record), nil
	}

	if len(request.CandidateReviews) != 0 {
		changed, err := reconcileCandidatePacketResponses(&record, candidate, request.CandidateReviews)
		if err != nil {
			return Outcome{}, err
		}
		if changed {
			if ids := unresolvedFindingIDs(candidate); len(ids) > 0 && len(missingReviewAxes(candidate)) == 0 {
				record.PendingRepair = repairDecisionRequest(record.Schema, candidate.ID, ids)
				return m.persistAssuranceTransition(store, record, StateNeedsDecision, "review findings require one batch adjudication", "review")
			}
			return m.persistAssuranceTransition(store, record, StateNeedsReview, "candidate packet responses were persisted", "review")
		}
		return outcomeFromRecord(record), nil
	}
	if len(request.SpecialistReviews) != 0 {
		if len(missingReviewAxes(candidate)) != 0 || len(unresolvedFindingIDs(candidate)) != 0 {
			return Outcome{}, errors.New("specialist packet responses require completed candidate axes without unresolved findings")
		}
		changed, err := reconcileSpecialistPacketResponses(&record, candidate, request.SpecialistReviews)
		if err != nil {
			return Outcome{}, err
		}
		if changed {
			if ids := unresolvedFindingIDs(candidate); len(ids) > 0 && len(missingSpecialistBoundaries(candidate)) == 0 {
				record.PendingRepair = repairDecisionRequest(record.Schema, candidate.ID, ids)
				return m.persistAssuranceTransition(store, record, StateNeedsDecision, "review findings require one batch adjudication", "specialist-review")
			}
			return m.persistAssuranceTransition(store, record, StateNeedsReview, "specialist packet responses were persisted", "specialist-review")
		}
		return outcomeFromRecord(record), nil
	}

	if record.LocalReadiness != nil &&
		record.LocalReadiness.CandidateID == candidate.ID &&
		record.LocalReadiness.CommitSHA == git.HeadSHA &&
		record.LocalReadiness.TreeSHA == git.TreeSHA {
		if record.LocalReadiness.Branch == git.Branch &&
			git.WorkspaceClean && deliveryBranch(git.Branch, tracker.Issue.Number) {
			if m.nonlocal != nil {
				return m.advanceNonLocal(ctx, store, record, git, tracker, compiled, request)
			}
			if record.State == StateWaiting {
				return outcomeFromRecord(record), nil
			}
			return m.persistAssuranceTransition(
				store, record, StateWaiting, "exact local readiness is proved; awaiting non-local delivery authority",
				"local-readiness",
			)
		}
		return m.persistAssuranceTransition(
			store, record, StateBlocked,
			"local readiness no longer matches the current branch or workspace; "+
				localReadinessBlockReason(tracker.Issue.Number),
			"local-readiness",
		)
	}

	missing := missingReviewAxes(candidate)
	if len(missing) > 0 {
		reviews, err := m.executeReviews(ctx, record, *candidate, missing)
		if err != nil {
			return Outcome{}, err
		}
		for _, review := range reviews {
			if review.Completed {
				candidate.Reviews = append(candidate.Reviews, review)
				if review.Axis == deliveryevidence.ReviewSpec {
					candidate.Acceptance = append([]AcceptanceProof(nil), review.Acceptance...)
				}
			}
		}
		sort.Slice(candidate.Reviews, func(i, j int) bool {
			if candidate.Reviews[i].Iteration != candidate.Reviews[j].Iteration {
				return candidate.Reviews[i].Iteration < candidate.Reviews[j].Iteration
			}
			return candidate.Reviews[i].Axis < candidate.Reviews[j].Axis
		})
		for _, review := range reviews {
			if !review.Completed {
				return m.persistAssuranceTransition(
					store, record, StateWaiting, "independent candidate review is still running", "review",
				)
			}
		}
		if ids := unresolvedFindingIDs(candidate); len(ids) > 0 {
			record.PendingRepair = repairDecisionRequest(record.Schema, candidate.ID, ids)
			return m.persistAssuranceTransition(
				store, record, StateNeedsDecision, "review findings require one batch adjudication", "review",
			)
		}
		return m.persistAssuranceTransition(
			store, record, StateNeedsReview, "required candidate reviews completed without findings", "review",
		)
	}

	if ids := unresolvedFindingIDs(candidate); len(ids) > 0 {
		record.PendingRepair = repairDecisionRequest(record.Schema, candidate.ID, ids)
		return m.persistAssuranceTransition(
			store, record, StateNeedsDecision, "review findings require one batch adjudication", "review",
		)
	}
	if missing := missingSpecialistBoundaries(candidate); len(missing) > 0 {
		reviews, err := m.executeSpecialistReviews(ctx, record, *candidate, missing)
		if err != nil {
			return m.persistAssuranceTransition(
				store, record, StateBlocked, "required high-risk specialist review is unavailable",
				"specialist-review",
			)
		}
		for _, review := range reviews {
			if review.Completed {
				candidate.SpecialistReviews = append(candidate.SpecialistReviews, review)
			}
		}
		sort.Slice(candidate.SpecialistReviews, func(i, j int) bool {
			return candidate.SpecialistReviews[i].Boundary < candidate.SpecialistReviews[j].Boundary
		})
		for _, review := range reviews {
			if !review.Completed {
				return m.persistAssuranceTransition(
					store, record, StateWaiting, "high-risk specialist review is still running",
					"specialist-review",
				)
			}
		}
		if ids := unresolvedFindingIDs(candidate); len(ids) > 0 {
			record.PendingRepair = repairDecisionRequest(record.Schema, candidate.ID, ids)
			return m.persistAssuranceTransition(
				store, record, StateNeedsDecision, "review findings require one batch adjudication",
				"specialist-review",
			)
		}
		return m.persistAssuranceTransition(
			store, record, StateNeedsReview, "required high-risk specialist reviews completed",
			"specialist-review",
		)
	}
	if hasAcceptedFindings(candidate.RepairDecision) {
		return outcomeWithReason(record, StateNeedsReview, "accepted findings must be repaired as one candidate batch"), nil
	}
	if candidate.Exhaustive == nil && !exactLocalReadiness(git, *candidate, tracker.Issue.Number) {
		return m.persistAssuranceTransition(
			store, record, StateBlocked,
			localReadinessBlockReason(tracker.Issue.Number),
			"local-readiness",
		)
	}
	var validationSession *ValidationSession
	validationReused := false
	if record.Schema != legacyRunSchema && m.validationSession != nil {
		var err error
		validationSession, validationReused, err = m.reusableDerivedValidationSession(ctx, &record, candidate, request)
		if err != nil {
			return Outcome{}, err
		}
		if !validationReused {
			session, outcome, handled, advanceErr := m.advanceValidationSession(
				ctx, store, record, *candidate, request,
			)
			if advanceErr != nil {
				return outcome, advanceErr
			}
			if handled {
				return outcome, nil
			}
			validationSession = session
		}
	}
	if missing := missingBoundaryProofs(candidate); len(missing) > 0 {
		var proofs []BoundaryProof
		if validationSession != nil {
			proofs = boundaryProofsFromValidationSession(
				*validationSession, *candidate, missing,
				m.clock.Now().UTC().Format(timeFormat),
			)
			if validationReused {
				for index := range proofs {
					proofs[index].ValidationDerivationReceiptID = validationDerivationReceiptID(
						candidate, deliveryevidence.ValidationObligationIdentity{
							Kind:     deliveryevidence.ValidationObligationBoundary,
							Boundary: deliveryevidence.SensitiveBoundary(proofs[index].Result.Boundary),
						},
					)
				}
			}
		} else {
			var err error
			proofs, err = m.executeBoundaryProofs(ctx, record, *candidate, missing)
			if err != nil {
				return m.persistAssuranceTransition(
					store, record, StateBlocked, "required sandboxed high-risk boundary proof is invalid",
					"boundary-validation",
				)
			}
		}
		candidate.BoundaryProofs = append(candidate.BoundaryProofs, proofs...)
		sort.Slice(candidate.BoundaryProofs, func(i, j int) bool {
			return candidate.BoundaryProofs[i].Result.Boundary < candidate.BoundaryProofs[j].Result.Boundary
		})
		return m.persistAssuranceTransition(
			store, record, StateNeedsReview, "required sandboxed high-risk boundary proofs completed",
			"boundary-validation",
		)
	}
	if candidate.Exhaustive == nil {
		var result ValidationResult
		if validationSession != nil {
			result = exhaustiveResultFromValidationSession(*validationSession)
		} else {
			if err := validateSandboxRoot(m.sandboxRoot); err != nil {
				return m.persistAssuranceTransition(
					store, record, StateBlocked, "configured validation sandbox is not physically isolated",
					"exhaustive-validation",
				)
			}
			var err error
			result, err = m.validation.Exhaustive(ctx, m.validationRequest(record, *candidate))
			if err != nil {
				return Outcome{}, fmt.Errorf("run exhaustive validation: %w", err)
			}
		}
		if err := m.validateValidationResult(result, *candidate, true); err != nil {
			return m.persistAssuranceTransition(
				store, record, StateBlocked, "exhaustive validation sandbox or exact candidate evidence is invalid",
				"exhaustive-validation",
			)
		}
		nextEvidence := *record.Evidence
		nextEvidence.AcceptanceMatrix = append(
			[]deliveryevidence.AcceptanceRow(nil), record.Evidence.AcceptanceMatrix...,
		)
		proofs := result.Acceptance
		if record.Schema != legacyRunSchema && phaseOwnedAcceptance(nextEvidence.AcceptanceMatrix) {
			if len(result.Acceptance) != 0 {
				return m.persistAssuranceTransition(
					store, record, StateBlocked,
					"exhaustive validator returned forbidden semantic acceptance prose",
					"exhaustive-validation",
				)
			}
			if err := validateValidationTraceability(
				result.Traceability, nextEvidence.AcceptanceMatrix, *candidate,
			); err != nil {
				return m.persistAssuranceTransition(
					store, record, StateBlocked, "exhaustive validation lacks exact acceptance traceability",
					"exhaustive-validation",
				)
			}
			proofs = candidate.Acceptance
		}
		var acceptanceErr error
		if len(proofs) == 0 && containsAxis(retainedReviewAxes(candidate), deliveryevidence.ReviewSpec) {
			acceptanceErr = admitDerivedAcceptance(&nextEvidence, record, candidate)
		} else {
			acceptanceErr = admitAcceptanceProofs(&nextEvidence, candidate, proofs)
		}
		if acceptanceErr != nil {
			return m.persistAssuranceTransition(
				store, record, StateBlocked, "exhaustive validation lacks exact acceptance traceability",
				"exhaustive-validation",
			)
		}
		completed := m.clock.Now().UTC()
		completedAt := completed.Format(time.RFC3339Nano)
		if !validationReused {
			var receiptErr error
			nextEvidence, receiptErr = deliveryevidence.RecordExhaustiveValidation(
				nextEvidence,
				deliveryevidence.ExhaustiveValidationResult{
					Observation: deliveryevidence.ValidationObservation{
						Repository: record.Repository, CheckoutSHA256: result.CheckoutSHA256,
						CommitSHA: result.CommitSHA, TreeSHA: result.TreeSHA, WorkspaceClean: result.WorkspaceClean,
						ValidatorIdentity: result.ValidatorIdentity, ValidatorSHA256: result.ValidatorSHA256,
						ValidatorIdentityExpiresAt: result.ValidatorIdentityExpiresAt,
						RequiredCommand:            result.Command,
						Sandbox: deliveryevidence.SandboxFacts{
							HomeRoot: result.HomeRoot, ConfigHomeRoot: result.ConfigRoot, Sandboxed: result.Sandboxed,
						},
					},
					CompletedAt: completedAt, Succeeded: result.Succeeded, Completed: result.Completed,
				},
			)
			if receiptErr != nil {
				return m.persistAssuranceTransition(
					store, record, StateBlocked,
					"canonical exhaustive validation receipt is invalid: "+receiptErr.Error(),
					"exhaustive-validation",
				)
			}
		}
		if record.Schema != legacyRunSchema {
			started, parseErr := time.Parse(timeFormat, record.UpdatedAt)
			if parseErr != nil || completed.Before(started) {
				return Outcome{}, errors.New("exhaustive validation lifecycle timing is invalid")
			}
			record.Timing = append(record.Timing, Timing{
				Sequence: len(record.Timing) + 1, Phase: exhaustiveValidationSucceededPhase,
				From: record.State, To: record.State,
				StartedAt: started.UTC().Format(time.RFC3339Nano), CompletedAt: completedAt,
			})
			record.UpdatedAt = completedAt
		}
		validationReference := &ValidationReceiptReference{
			Schema: deliveryevidence.ValidationReceiptV1, CandidateID: candidate.ID,
			CommitSHA: result.CommitSHA, TreeSHA: result.TreeSHA, CompletedAt: completedAt,
		}
		if validationReused {
			validationReference.Schema = deliveryevidence.ValidationReceiptSchema(deliveryevidence.ValidationDerivationReceiptSchema)
			validationReference.ReceiptID = validationDerivationReceiptID(candidate, deliveryevidence.ValidationObligationIdentity{Kind: deliveryevidence.ValidationObligationExhaustive})
		}
		for index := range candidate.Acceptance {
			candidate.Acceptance[index].ValidationReceipt = validationReference
		}
		candidate.Exhaustive = &ValidationProof{
			Kind: "exhaustive", Result: result, CompletedAt: completedAt,
		}
		if validationSession != nil {
			candidate.Exhaustive.ValidationCompletionSHA256 =
				validationSession.CompletionSHA256
		}
		if validationReused {
			candidate.Exhaustive.ValidationDerivationReceiptID = validationReference.ReceiptID
		}
		if record.Schema != legacyRunSchema {
			candidate.Exhaustive.TimingSequence = len(record.Timing)
		}
		if record.Schema == legacyRunSchema || !phaseOwnedAcceptance(nextEvidence.AcceptanceMatrix) {
			candidate.Acceptance = append([]AcceptanceProof(nil), result.Acceptance...)
		}
		record.Evidence = &nextEvidence
	}
	freshGit, err := m.git.ObserveGit(ctx, git.Worktree)
	if err != nil {
		return Outcome{}, fmt.Errorf("reobserve Git after exhaustive validation: %w", err)
	}
	freshTracker, err := m.github.ObserveIssue(ctx, freshGit, tracker.Issue.Number)
	if err != nil {
		return Outcome{}, fmt.Errorf("reobserve GitHub after exhaustive validation: %w", err)
	}
	freshAuthority, err := compileAuthority(
		freshGit, freshTracker, record.Decisions, nil,
		qualifiedRiskProfile(record, record.Evidence.RiskProfile),
		record.DeliveryProfile != nil,
	)
	if err != nil {
		return Outcome{}, err
	}
	if freshAuthority.hash != compiled.hash || freshGit.HeadSHA != candidate.CommitSHA ||
		freshGit.TreeSHA != candidate.TreeSHA || !freshGit.WorkspaceClean ||
		!deliveryBranch(freshGit.Branch, tracker.Issue.Number) {
		return m.persistAssuranceTransition(
			store, record, StateBlocked, "fresh authority or exact HEAD changed during exhaustive validation",
			"local-readiness",
		)
	}
	record.LocalReadiness = &LocalReadiness{
		CandidateID: candidate.ID, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		AuthorityHash: compiled.hash, Branch: freshGit.Branch, ReadyAt: m.clock.Now().UTC().Format(timeFormat),
	}
	return m.persistAssuranceTransition(
		store, record, StateWaiting, "exact local readiness is proved; awaiting non-local delivery authority",
		"local-readiness",
	)
}

func reconcileCandidatePacketResponses(record *runRecord, candidate *Candidate, supplied []CandidateReview) (bool, error) {
	seenAxes := map[deliveryevidence.ReviewAxis]bool{}
	var additions []CandidateReview
	for _, review := range supplied {
		if seenAxes[review.Axis] {
			return false, fmt.Errorf("duplicate candidate packet response for axis %q", review.Axis)
		}
		seenAxes[review.Axis] = true
		expectedIteration := currentReviewIteration(candidate)
		expected := candidatePacketID(*record, *candidate, review.Axis, expectedIteration)
		expectedSHA := candidatePacketSHA256(*record, *candidate, review.Axis, expectedIteration)
		if err := validateCandidateReview(review, *candidate, candidate.RequiredReviews, expectedIteration, expected, expectedSHA); err != nil {
			return false, err
		}
		if !review.Completed {
			continue
		}
		review = qualifyCandidateReviewFindings(review)
		matched := false
		for _, persisted := range candidate.Reviews {
			if persisted.Axis != review.Axis || persisted.Iteration != review.Iteration {
				continue
			}
			matched = true
			if !reflect.DeepEqual(persisted, review) {
				return false, errors.New("candidate packet response conflicts with the already persisted response")
			}
		}
		if !matched {
			additions = append(additions, review)
		}
	}
	if err := validateReviewBatch(*candidate, additions); err != nil {
		return false, err
	}
	for _, review := range additions {
		if review.Axis == deliveryevidence.ReviewSpec && phaseOwnedAcceptance(record.Evidence.AcceptanceMatrix) {
			evidence := *record.Evidence
			evidence.AcceptanceMatrix = append([]deliveryevidence.AcceptanceRow(nil), record.Evidence.AcceptanceMatrix...)
			reviewed := *candidate
			reviewed.Reviews = append(append([]CandidateReview(nil), candidate.Reviews...), review)
			if err := admitAcceptanceProofs(&evidence, &reviewed, review.Acceptance); err != nil {
				return false, fmt.Errorf("Spec review acceptance proof is invalid: %w", err)
			}
		}
		candidate.Reviews = append(candidate.Reviews, review)
		if review.Axis == deliveryevidence.ReviewSpec {
			candidate.Acceptance = append([]AcceptanceProof(nil), review.Acceptance...)
		}
	}
	sort.Slice(candidate.Reviews, func(i, j int) bool {
		if candidate.Reviews[i].Iteration != candidate.Reviews[j].Iteration {
			return candidate.Reviews[i].Iteration < candidate.Reviews[j].Iteration
		}
		return candidate.Reviews[i].Axis < candidate.Reviews[j].Axis
	})
	return len(additions) != 0, nil
}

func (m *Module) applyRepairDecision(
	store lockedIssueStore,
	record runRecord,
	decision RepairDecision,
) (Outcome, error) {
	candidate := latestCandidate(&record)
	if candidate == nil || decision.CandidateID != candidate.ID {
		return Outcome{}, errors.New("repair decision does not match the pending candidate")
	}
	if decision.Class != RepairBounded && decision.Class != RepairCandidateChanging &&
		decision.Class != RepairAdjudicationOnly {
		return Outcome{}, fmt.Errorf("invalid repair class %q", decision.Class)
	}
	if record.Schema == legacyRunSchema && decision.Class == RepairAdjudicationOnly {
		return Outcome{}, fmt.Errorf("invalid repair class %q", decision.Class)
	}
	decision.Findings = append([]FindingDecision(nil), decision.Findings...)
	sort.Slice(decision.Findings, func(i, j int) bool {
		return decision.Findings[i].FindingID < decision.Findings[j].FindingID
	})
	if record.PendingRepair == nil {
		if decision.Class == RepairAdjudicationOnly && matchingLastRepairBatch(candidate, decision) {
			return outcomeFromRecord(record), nil
		}
		return Outcome{}, errors.New("repair decision does not match the pending candidate")
	}
	if decision.CandidateID != record.PendingRepair.CandidateID {
		return Outcome{}, errors.New("repair decision does not match the pending candidate")
	}
	expected := unresolvedFindingIDs(candidate)
	if len(decision.Findings) != len(expected) {
		return Outcome{}, errors.New("repair decision must adjudicate every finding as one batch")
	}
	got := make(map[string]bool, len(decision.Findings))
	for _, item := range decision.Findings {
		if got[item.FindingID] || strings.TrimSpace(item.Evidence) == "" ||
			(item.Disposition != FindingAccepted && item.Disposition != FindingRejected) {
			return Outcome{}, errors.New("repair decision contains an invalid finding adjudication")
		}
		got[item.FindingID] = true
	}
	for _, id := range expected {
		if !got[id] {
			return Outcome{}, errors.New("repair decision must adjudicate every finding as one batch")
		}
	}
	if decision.Class == RepairBounded && !hasAcceptedFindings(&decision) {
		return Outcome{}, errors.New("bounded repair requires at least one accepted finding")
	}
	if record.Schema != legacyRunSchema &&
		decision.Class == RepairCandidateChanging && !hasAcceptedFindings(&decision) {
		return Outcome{}, errors.New("candidate-changing repair requires at least one accepted finding")
	}
	if decision.Class == RepairAdjudicationOnly && hasAcceptedFindings(&decision) {
		return Outcome{}, errors.New("adjudication-only requires every finding to be rejected with evidence")
	}
	priorDecision := candidate.RepairDecision
	merged := decision
	if priorDecision != nil {
		merged.Class = strongestRepairClass(priorDecision.Class, decision.Class)
		merged.Findings = append(
			append([]FindingDecision(nil), priorDecision.Findings...),
			decision.Findings...,
		)
		sort.Slice(merged.Findings, func(i, j int) bool {
			return merged.Findings[i].FindingID < merged.Findings[j].FindingID
		})
	}
	candidate.RepairDecision = &merged
	if record.Schema != legacyRunSchema {
		if len(candidate.RepairBatches) == 0 && candidate.LastRepairBatch == nil &&
			priorDecision != nil {
			prefixDecision := *priorDecision
			prefixDecision.Findings = append(
				[]FindingDecision(nil), priorDecision.Findings...,
			)
			prefixIDs := make([]string, 0, len(prefixDecision.Findings))
			for _, item := range prefixDecision.Findings {
				prefixIDs = append(prefixIDs, item.FindingID)
			}
			candidate.RepairBatches = append(candidate.RepairBatches, RepairBatchReceipt{
				RequestID:        repairDecisionRequest(record.Schema, candidate.ID, prefixIDs).ID,
				CompatiblePrefix: true,
				Decision:         prefixDecision,
			})
		}
		receipt := RepairBatchReceipt{
			RequestID: record.PendingRepair.ID,
			Decision:  decision,
		}
		candidate.RepairBatches = append(candidate.RepairBatches, receipt)
		candidate.LastRepairBatch = &receipt
	}
	record.PendingRepair = nil
	reason := "review findings were adjudicated without an accepted repair"
	if hasAcceptedFindings(&merged) {
		reason = "accepted findings must be repaired as one candidate batch"
	}
	return m.persistAssuranceTransition(store, record, StateNeedsReview, reason, "adjudication")
}

func matchingLastRepairBatch(candidate *Candidate, supplied RepairDecision) bool {
	if candidate.LastRepairBatch != nil {
		return matchingRepairDecision(&candidate.LastRepairBatch.Decision, supplied)
	}
	return matchingRepairDecision(candidate.RepairDecision, supplied)
}

func matchingRepairDecision(recorded *RepairDecision, supplied RepairDecision) bool {
	if recorded == nil || recorded.CandidateID != supplied.CandidateID ||
		recorded.Class != supplied.Class || len(recorded.Findings) != len(supplied.Findings) {
		return false
	}
	for index, item := range supplied.Findings {
		if recorded.Findings[index] != item {
			return false
		}
	}
	return true
}

func strongestRepairClass(left, right RepairClass) RepairClass {
	rank := func(class RepairClass) int {
		switch class {
		case RepairCandidateChanging:
			return 3
		case RepairBounded:
			return 2
		case RepairAdjudicationOnly:
			return 1
		default:
			return 0
		}
	}
	if rank(right) > rank(left) {
		return right
	}
	return left
}

func (m *Module) executeReviews(
	ctx context.Context,
	record runRecord,
	candidate Candidate,
	axes []deliveryevidence.ReviewAxis,
) ([]CandidateReview, error) {
	iteration := currentReviewIteration(&candidate)
	type result struct {
		review CandidateReview
		err    error
	}
	results := make(chan result, len(axes))
	var group sync.WaitGroup
	for _, axis := range axes {
		axis := axis
		group.Add(1)
		go func() {
			defer group.Done()
			review, err := m.review.Review(ctx, ReviewRequest{
				RunID: record.ID, CandidateID: candidate.ID, Repository: record.Repository, Issue: record.Issue,
				Axis: axis, BaseSHA: candidate.BaseSHA, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
				Iteration:      iteration,
				AcceptanceRows: append([]deliveryevidence.AcceptanceRow(nil), record.Evidence.AcceptanceMatrix...),
			})
			results <- result{review: review, err: err}
		}()
	}
	group.Wait()
	close(results)
	out := make([]CandidateReview, 0, len(axes))
	for result := range results {
		if result.err != nil {
			return nil, fmt.Errorf("execute candidate review: %w", result.err)
		}
		if err := validateCandidateReview(
			result.review, candidate, axes, iteration,
			expectedCandidatePacketID(record, candidate, result.review.Axis),
			candidatePacketSHA256(record, candidate, result.review.Axis, iteration),
		); err != nil {
			return nil, err
		}
		result.review = qualifyCandidateReviewFindings(result.review)
		if result.review.Axis == deliveryevidence.ReviewSpec && result.review.Completed &&
			phaseOwnedAcceptance(record.Evidence.AcceptanceMatrix) {
			evidence := *record.Evidence
			evidence.AcceptanceMatrix = append(
				[]deliveryevidence.AcceptanceRow(nil), record.Evidence.AcceptanceMatrix...,
			)
			reviewedCandidate := candidate
			reviewedCandidate.Reviews = append(
				append([]CandidateReview(nil), candidate.Reviews...), result.review,
			)
			if err := admitAcceptanceProofs(
				&evidence, &reviewedCandidate, result.review.Acceptance,
			); err != nil {
				return nil, fmt.Errorf("Spec review acceptance proof is invalid: %w", err)
			}
		}
		out = append(out, result.review)
	}
	if err := validateReviewBatch(candidate, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (m *Module) persistAssuranceTransition(
	store lockedIssueStore,
	record runRecord,
	state State,
	reason, phase string,
) (Outcome, error) {
	record.ObservationDiagnostic = nil
	return m.persistAssuranceTransitionRecord(store, record, state, reason, phase)
}

func (m *Module) persistAssuranceTransitionWithObservationDiagnostic(
	store lockedIssueStore,
	record runRecord,
	state State,
	reason, phase string,
	diagnostic ObservationDiagnostic,
) (Outcome, error) {
	record.ObservationDiagnostic = cloneObservationDiagnostic(&diagnostic)
	return m.persistAssuranceTransitionRecord(store, record, state, reason, phase)
}

func (m *Module) persistAssuranceTransitionRecord(
	store lockedIssueStore,
	record runRecord,
	state State,
	reason, phase string,
) (Outcome, error) {
	started, err := time.Parse(time.RFC3339Nano, record.UpdatedAt)
	if err != nil {
		return Outcome{}, fmt.Errorf("parse issue delivery transition start: %w", err)
	}
	previous := record.State
	record.State, record.Reason = state, reason
	completed := m.clock.Now().UTC()
	if completed.Before(started) {
		return Outcome{}, errors.New("issue delivery transition clock moved backwards")
	}
	record.Timing = append(record.Timing, Timing{
		Sequence: len(record.Timing) + 1, Phase: phase, From: previous, To: state,
		StartedAt: started.Format(timeFormat), CompletedAt: completed.Format(timeFormat),
	})
	record.UpdatedAt = completed.Format(timeFormat)
	adoptLegacyNullQualificationFindings(&record)
	if err := projectAutomaticAssurance(&record); err != nil {
		return Outcome{}, err
	}
	data, err := encodeRun(record)
	if err != nil {
		return Outcome{}, err
	}
	if _, err := store.storeRevisionAndActivate(record.ID, data); err != nil {
		return Outcome{}, err
	}
	return outcomeFromRecord(record), nil
}

func (m *Module) appendElapsedTiming(record *runRecord, phase string, completed time.Time) error {
	started, err := time.Parse(time.RFC3339Nano, record.UpdatedAt)
	if err != nil {
		return fmt.Errorf("parse issue delivery activity start: %w", err)
	}
	if completed.Before(started) {
		return errors.New("issue delivery activity clock moved backwards")
	}
	record.Timing = append(record.Timing, Timing{
		Sequence: len(record.Timing) + 1, Phase: phase, From: record.State, To: record.State,
		StartedAt: started.Format(timeFormat), CompletedAt: completed.Format(timeFormat),
	})
	record.UpdatedAt = completed.Format(timeFormat)
	return nil
}

func newCandidate(record runRecord, previous *Candidate, git GitObservation) Candidate {
	base, class := record.Evidence.StartingBaseSHA, RepairClass("")
	required := bothReviewAxes()
	if previous != nil {
		class = RepairCandidateChanging
		if hasAcceptedFindings(previous.RepairDecision) {
			class = previous.RepairDecision.Class
			if class == RepairBounded {
				required = bothReviewAxes()
			}
		}
	}
	next := Candidate{
		ID:      candidateIdentity(record.ID, base, git.HeadSHA, git.TreeSHA),
		BaseSHA: base, CommitSHA: git.HeadSHA, TreeSHA: git.TreeSHA, RepairClass: class,
		RequiredReviews: required, ReviewIteration: 1, Reviews: []CandidateReview{},
		Effects: []EffectObservation{}, Boundaries: []SensitiveBoundary{},
		RequiredSpecialists: []SensitiveBoundary{}, SpecialistReviews: []SpecialistReview{},
		BoundaryProofs: []BoundaryProof{},
	}
	return next
}

func candidateIdentity(runID, base, commit, tree string) string {
	sum := sha256.Sum256([]byte(runID + "\x00" + base + "\x00" + commit + "\x00" + tree))
	return hex.EncodeToString(sum[:])
}

func (m *Module) validationRequest(record runRecord, candidate Candidate) ValidationRequest {
	return ValidationRequest{
		RunID: record.ID, CandidateID: candidate.ID, Repository: record.Repository, Issue: record.Issue,
		CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		HomeRoot: filepath.Join(m.sandboxRoot, "home"), ConfigRoot: filepath.Join(m.sandboxRoot, "config"),
		AcceptanceRows: append([]deliveryevidence.AcceptanceRow(nil), record.Evidence.AcceptanceMatrix...),
		Profile:        candidate.Profile, Boundaries: append([]SensitiveBoundary(nil), candidate.Boundaries...),
	}
}

func (m *Module) validateValidationResult(result ValidationResult, candidate Candidate, exhaustive bool) error {
	if err := validateSandboxRoot(m.sandboxRoot); err != nil {
		return err
	}
	if result.CommitSHA != candidate.CommitSHA || result.TreeSHA != candidate.TreeSHA ||
		!result.Sandboxed || !result.Succeeded || !result.Completed ||
		strings.TrimSpace(result.Command) == "" {
		return errors.New("validation result does not prove the exact sandboxed candidate")
	}
	for _, root := range []string{result.HomeRoot, result.ConfigRoot} {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return errors.New("validation sandbox roots must be absolute and canonical")
		}
	}
	if result.HomeRoot == result.ConfigRoot {
		return errors.New("validation sandbox roots must be distinct")
	}
	if result.HomeRoot != filepath.Join(m.sandboxRoot, "home") ||
		result.ConfigRoot != filepath.Join(m.sandboxRoot, "config") {
		return errors.New("validation result does not use the configured sandbox")
	}
	if exhaustive {
		expires, err := time.Parse(time.RFC3339Nano, result.ValidatorIdentityExpiresAt)
		if result.Command != "./scripts/validate-packy.sh" ||
			result.ValidatorIdentity != "scripts/validate-packy.sh" ||
			!runIDPattern.MatchString(result.CheckoutSHA256) ||
			!runIDPattern.MatchString(result.ValidatorSHA256) ||
			err != nil || !m.clock.Now().UTC().Before(expires) || !result.WorkspaceClean {
			return errors.New("exhaustive result does not prove the repository validation authority")
		}
	}
	return nil
}

func validateCandidateReview(
	review CandidateReview,
	candidate Candidate,
	requested []deliveryevidence.ReviewAxis,
	expectedIteration int,
	expectedPacketID ...string,
) error {
	if review.CandidateID != candidate.ID || !containsAxis(requested, review.Axis) || review.Findings == nil ||
		review.Iteration != expectedIteration || review.CommitSHA != candidate.CommitSHA ||
		review.TreeSHA != candidate.TreeSHA {
		return errors.New("candidate review does not match its exact request")
	}
	if review.PacketID != "" && (len(expectedPacketID) < 1 || review.PacketID != expectedPacketID[0]) {
		return errors.New("candidate review does not match its exact current packet")
	}
	if err := validatePacketResponseDigest(review.PacketID, review.PacketSHA256, review.ResponseSHA256, review.Completed); err != nil {
		return fmt.Errorf("candidate review source: %w", err)
	}
	if review.PacketID != "" && (len(expectedPacketID) != 2 || review.PacketSHA256 != expectedPacketID[1]) {
		return errors.New("candidate review does not match its exact current packet SHA-256")
	}
	if !review.Completed && len(review.Findings) != 0 {
		return errors.New("incomplete candidate review cannot contain findings")
	}
	seenFindings := make(map[string]bool, len(review.Findings))
	for _, finding := range review.Findings {
		if finding.Axis != review.Axis || strings.TrimSpace(finding.ID) == "" || seenFindings[finding.ID] {
			return errors.New("candidate review contains an invalid finding")
		}
		seenFindings[finding.ID] = true
	}
	if review.Axis != deliveryevidence.ReviewSpec && len(review.Acceptance) != 0 {
		return errors.New("only the Spec review may author semantic acceptance proof")
	}
	for _, proof := range review.Acceptance {
		if proof.CandidateID != candidate.ID ||
			proof.Phase != deliveryevidence.AssuranceCandidateReview ||
			proof.ValidationReceipt != nil || proof.ReviewReceipt == nil ||
			proof.ReviewReceipt.CandidateID != review.CandidateID ||
			proof.ReviewReceipt.Axis != review.Axis ||
			proof.ReviewReceipt.Iteration != review.Iteration ||
			proof.ReviewReceipt.CommitSHA != review.CommitSHA ||
			proof.ReviewReceipt.TreeSHA != review.TreeSHA {
			return errors.New("candidate review contains stale or phase-invalid acceptance proof")
		}
		if !review.Completed && !generatedAcceptanceProofPlaceholder(proof) {
			return errors.New("incomplete candidate review cannot contain completed acceptance proof")
		}
	}
	return nil
}

func generatedAcceptanceProofPlaceholder(proof AcceptanceProof) bool {
	for _, field := range acceptanceEvidenceFields(proof) {
		if field.value != inputPlaceholder {
			return false
		}
	}
	return true
}

type acceptanceEvidenceField struct{ name, value string }

func acceptanceEvidenceFields(proof AcceptanceProof) []acceptanceEvidenceField {
	return []acceptanceEvidenceField{
		{"positive", proof.PositiveEvidence},
		{"negative", proof.NegativeEvidence},
		{"failure", proof.FailureEvidence},
		{"mutation", proof.MutationEvidence},
		{"compatibility", proof.CompatibilityEvidence},
		{"preservation", proof.PreservationEvidence},
		{"migration", proof.MigrationEvidence},
	}
}

func validateReviewBatch(candidate Candidate, reviews []CandidateReview) error {
	seen := make(map[string]bool)
	for _, review := range candidate.Reviews {
		for _, finding := range review.Findings {
			seen[packetFindingKey(review.PacketID, finding.ID)] = true
		}
	}
	for _, review := range reviews {
		for _, finding := range review.Findings {
			key := packetFindingKey(review.PacketID, finding.ID)
			if seen[key] {
				return fmt.Errorf("duplicate candidate review finding ID %q", finding.ID)
			}
			seen[key] = true
		}
	}
	return nil
}

func invalidateAcceptance(
	evidence *deliveryevidence.Bundle,
	corrections []QualificationCorrection,
) {
	if len(corrections) > 0 {
		evidence.AcceptanceMatrix = append(
			[]deliveryevidence.AcceptanceRow(nil),
			corrections[len(corrections)-1].AcceptanceMatrix...,
		)
	}
	for index := range evidence.AcceptanceMatrix {
		row := &evidence.AcceptanceMatrix[index]
		row.State = deliveryevidence.AcceptancePlanned
	}
	evidence.ValidationReceipts = []deliveryevidence.ValidationReceipt{}
}

func admitAcceptanceProofs(
	evidence *deliveryevidence.Bundle,
	candidate *Candidate,
	proofs []AcceptanceProof,
) error {
	if len(proofs) != len(evidence.AcceptanceMatrix) {
		return errors.New("every acceptance row requires one exact proof")
	}
	byID := make(map[string]AcceptanceProof, len(proofs))
	required := map[string]bool{"positive": true, "failure": true, "mutation": true}
	if candidate.Profile == "" {
		for _, name := range []string{
			"positive", "negative", "failure", "mutation", "compatibility", "preservation", "migration",
		} {
			required[name] = true
		}
	} else if candidate.Profile == deliveryevidence.RiskStandard || candidate.Profile == deliveryevidence.RiskHigh {
		required["negative"] = true
		required["compatibility"] = true
		required["preservation"] = true
	}
	if candidateRequiresMigrationEvidence(candidate) {
		required["migration"] = true
	}
	for _, proof := range proofs {
		if byID[proof.Identity].Identity != "" {
			return fmt.Errorf("duplicate acceptance proof %q", proof.Identity)
		}
		if proof.CandidateID != "" && proof.CandidateID != candidate.ID {
			return fmt.Errorf("acceptance proof %q belongs to a stale candidate", proof.Identity)
		}
		if proof.Phase != "" && proof.Phase != deliveryevidence.AssuranceCandidateReview {
			return fmt.Errorf("acceptance proof %q has stale phase ownership", proof.Identity)
		}
		if reference := proof.ReviewReceipt; reference != nil {
			matched := false
			for _, review := range candidate.Reviews {
				if review.CandidateID == reference.CandidateID && review.Axis == reference.Axis &&
					review.Iteration == reference.Iteration && review.CommitSHA == reference.CommitSHA &&
					review.TreeSHA == reference.TreeSHA && review.Completed {
					matched = true
				}
			}
			if reference.CandidateID != candidate.ID || reference.CommitSHA != candidate.CommitSHA ||
				reference.TreeSHA != candidate.TreeSHA || reference.Iteration < 1 || !matched {
				return fmt.Errorf("acceptance proof %q references a stale review receipt", proof.Identity)
			}
		}
		if reference := proof.ValidationReceipt; reference != nil &&
			(reference.Schema != deliveryevidence.ValidationReceiptV1 ||
				reference.CandidateID != candidate.ID || reference.CommitSHA != candidate.CommitSHA ||
				reference.TreeSHA != candidate.TreeSHA || strings.TrimSpace(reference.CompletedAt) == "") {
			return fmt.Errorf("acceptance proof %q references a stale validation receipt", proof.Identity)
		}
		for _, field := range acceptanceEvidenceFields(proof) {
			value := strings.TrimSpace(field.value)
			if value == inputPlaceholder {
				return fmt.Errorf(
					"acceptance %s evidence retains a generated judgment placeholder for %s",
					field.name, proof.Identity,
				)
			}
			if value == "" || (!required[field.name] && !strings.Contains(value, candidate.ID) &&
				!strings.HasPrefix(value, "not-applicable:") && proof.CandidateID == "") ||
				(required[field.name] && proof.CandidateID == "" && !strings.Contains(value, candidate.ID)) {
				return fmt.Errorf(
					"acceptance %s evidence is insufficient for %s candidate %s",
					field.name, candidate.Profile, candidate.ID,
				)
			}
		}
		byID[proof.Identity] = proof
	}
	next := append([]deliveryevidence.AcceptanceRow(nil), evidence.AcceptanceMatrix...)
	for index := range next {
		row := &next[index]
		proof, found := byID[row.Identity]
		if !found {
			return fmt.Errorf("acceptance row %q lacks proof", row.Identity)
		}
		row.PositiveEvidence = proof.PositiveEvidence
		row.NegativeEvidence = proof.NegativeEvidence
		row.FailureEvidence = proof.FailureEvidence
		row.MutationEvidence = proof.MutationEvidence
		row.CompatibilityEvidence = proof.CompatibilityEvidence
		row.PreservationEvidence = proof.PreservationEvidence
		row.MigrationEvidence = proof.MigrationEvidence
		row.State = deliveryevidence.AcceptanceProved
	}
	evidence.AcceptanceMatrix = next
	return nil
}

func admitDerivedAcceptance(
	evidence *deliveryevidence.Bundle,
	record runRecord,
	candidate *Candidate,
) error {
	if candidate.Derivation == nil || candidate.Derivation.Confirmation == nil {
		return errors.New("derived acceptance lacks confirmed derivation")
	}
	var specReceipt *deliveryevidence.ReviewDerivationReceipt
	for index := range candidate.Derivation.RetainedReviewReceipts {
		receipt := &candidate.Derivation.RetainedReviewReceipts[index]
		if receipt.Axis == deliveryevidence.ReviewSpec {
			specReceipt = receipt
		}
	}
	if specReceipt == nil {
		return errors.New("derived acceptance lacks a canonical Spec derivation receipt")
	}
	var parent *Candidate
	for index := range record.Candidates {
		if record.Candidates[index].ID == candidate.Derivation.ParentCandidateID {
			parent = &record.Candidates[index]
		}
	}
	if parent == nil || len(parent.Acceptance) != len(evidence.AcceptanceMatrix) {
		return errors.New("derived acceptance lacks exact parent semantic proof")
	}
	covered := make(map[deliveryevidence.EvidenceObligationIdentity]bool, len(specReceipt.Obligations))
	for _, obligation := range specReceipt.Obligations {
		covered[obligation] = true
	}
	for _, row := range evidence.AcceptanceMatrix {
		for _, obligation := range row.Obligations {
			if obligation.Phase != deliveryevidence.AssuranceCandidateReview {
				continue
			}
			identity := deliveryevidence.EvidenceObligationIdentity{
				CriterionID: row.Identity, Kind: obligation.Kind, Phase: obligation.Phase,
			}
			if !covered[identity] {
				return fmt.Errorf("derived acceptance omits retained obligation for %s", row.Identity)
			}
		}
	}
	parentEvidence := *evidence
	parentEvidence.AcceptanceMatrix = append([]deliveryevidence.AcceptanceRow(nil), evidence.AcceptanceMatrix...)
	if err := admitAcceptanceProofs(&parentEvidence, parent, parent.Acceptance); err != nil {
		return fmt.Errorf("validate parent semantic proof: %w", err)
	}
	evidence.AcceptanceMatrix = parentEvidence.AcceptanceMatrix
	return nil
}

func phaseOwnedAcceptance(rows []deliveryevidence.AcceptanceRow) bool {
	for _, row := range rows {
		if len(row.Obligations) > 0 {
			return true
		}
	}
	return false
}

func validateValidationTraceability(
	traces []ValidationTrace,
	rows []deliveryevidence.AcceptanceRow,
	candidate Candidate,
) error {
	if len(traces) != len(rows) {
		return errors.New("every acceptance row requires one exhaustive validation trace")
	}
	required := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.Identity == "" || required[row.Identity] {
			return errors.New("acceptance rows contain an invalid identity")
		}
		required[row.Identity] = true
	}
	seen := make(map[string]bool, len(traces))
	for _, trace := range traces {
		if !required[trace.Identity] || seen[trace.Identity] ||
			trace.CandidateID != candidate.ID ||
			trace.Phase != deliveryevidence.AssuranceExhaustiveValidation ||
			trace.CommitSHA != candidate.CommitSHA || trace.TreeSHA != candidate.TreeSHA {
			return errors.New("exhaustive validation trace is duplicate, foreign, or stale")
		}
		seen[trace.Identity] = true
	}
	return nil
}

func candidateRequiresMigrationEvidence(candidate *Candidate) bool {
	for _, observation := range candidate.Effects {
		if observation.Effect == EffectMigration || observation.Effect == EffectPersistentFormat {
			return true
		}
	}
	return false
}

func latestCandidate(record *runRecord) *Candidate {
	if len(record.Candidates) == 0 {
		return nil
	}
	return &record.Candidates[len(record.Candidates)-1]
}

func missingReviewAxes(candidate *Candidate) []deliveryevidence.ReviewAxis {
	have := map[deliveryevidence.ReviewAxis]bool{}
	for _, axis := range retainedReviewAxes(candidate) {
		have[axis] = true
	}
	iteration := currentReviewIteration(candidate)
	for _, review := range candidate.Reviews {
		if review.Completed && review.Iteration == iteration {
			have[review.Axis] = true
		}
	}
	var missing []deliveryevidence.ReviewAxis
	for _, axis := range candidate.RequiredReviews {
		if !have[axis] {
			missing = append(missing, axis)
		}
	}
	return missing
}

func currentReviewIteration(candidate *Candidate) int {
	if candidate.ReviewIteration > 0 {
		return candidate.ReviewIteration
	}
	if len(candidate.Reviews) > 0 {
		return candidate.Reviews[len(candidate.Reviews)-1].Iteration
	}
	return 1
}

func unresolvedFindingIDs(candidate *Candidate) []string {
	decided := map[string]bool{}
	if candidate.RepairDecision != nil {
		for _, item := range candidate.RepairDecision.Findings {
			decided[item.FindingID] = true
		}
	}
	var ids []string
	for _, review := range candidate.Reviews {
		for _, finding := range review.Findings {
			if !decided[finding.ID] {
				ids = append(ids, finding.ID)
			}
		}
	}
	for _, review := range candidate.SpecialistReviews {
		for _, finding := range review.Findings {
			if !decided[finding.ID] {
				ids = append(ids, finding.ID)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func repairDecisionRequest(schema, candidateID string, findingIDs []string) *RepairDecisionRequest {
	ids := append([]string(nil), findingIDs...)
	options := []RepairClass{RepairBounded, RepairCandidateChanging}
	if schema != legacyRunSchema {
		options = []RepairClass{RepairAdjudicationOnly, RepairBounded, RepairCandidateChanging}
	}
	return &RepairDecisionRequest{
		ID:          stableID("repair-decision", candidateID+"\x00"+strings.Join(ids, "\x00")),
		CandidateID: candidateID, FindingIDs: ids,
		Options: options,
	}
}

func hasAcceptedFindings(decision *RepairDecision) bool {
	if decision == nil {
		return false
	}
	for _, item := range decision.Findings {
		if item.Disposition == FindingAccepted {
			return true
		}
	}
	return false
}

func acceptedFindingAxes(candidate Candidate) []deliveryevidence.ReviewAxis {
	accepted := map[string]bool{}
	for _, decision := range candidate.RepairDecision.Findings {
		if decision.Disposition == FindingAccepted {
			accepted[decision.FindingID] = true
		}
	}
	axes := map[deliveryevidence.ReviewAxis]bool{}
	for _, review := range candidate.Reviews {
		for _, finding := range review.Findings {
			if accepted[finding.ID] {
				axes[review.Axis] = true
			}
		}
	}
	var out []deliveryevidence.ReviewAxis
	for _, axis := range bothReviewAxes() {
		if axes[axis] {
			out = append(out, axis)
		}
	}
	return out
}

func bothReviewAxes() []deliveryevidence.ReviewAxis {
	return []deliveryevidence.ReviewAxis{deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec}
}

func containsAxis(axes []deliveryevidence.ReviewAxis, target deliveryevidence.ReviewAxis) bool {
	for _, axis := range axes {
		if axis == target {
			return true
		}
	}
	return false
}

func deliveryBranch(branch string, issue int) bool {
	for _, prefix := range deliveryBranchPrefixes(issue) {
		if strings.HasPrefix(branch, prefix) {
			return true
		}
	}
	return false
}

func deliveryBranchPrefixes(issue int) []string {
	return []string{
		"chore/issue-" + fmt.Sprint(issue) + "-",
		"feat/issue-" + fmt.Sprint(issue) + "-",
		"fix/issue-" + fmt.Sprint(issue) + "-",
	}
}

func deliveryBranchForms(issue int) []string {
	prefixes := deliveryBranchPrefixes(issue)
	forms := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		forms[index] = prefix + "*"
	}
	return forms
}

func exactLocalReadiness(git GitObservation, candidate Candidate, issue int) bool {
	return git.WorkspaceClean && git.HeadSHA == candidate.CommitSHA &&
		git.TreeSHA == candidate.TreeSHA && deliveryBranch(git.Branch, issue)
}

func localReadinessBlockReason(issue int) string {
	return "local readiness requires a clean workspace, exact candidate HEAD/tree, and one of: " +
		strings.Join(deliveryBranchForms(issue), ", ")
}

func outcomeWithReason(record runRecord, state State, reason string) Outcome {
	outcome := outcomeFromRecord(record)
	outcome.State, outcome.Reason = state, reason
	return outcome
}
