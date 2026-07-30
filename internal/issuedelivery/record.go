package issuedelivery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

const runSchema = "packy.issue-delivery-run/v2"

type runWire struct {
	Schema                         string                               `json:"schema"`
	ID                             string                               `json:"id"`
	Repository                     deliveryevidence.RepositoryIdentity  `json:"repository"`
	Issue                          deliveryevidence.IssueIdentity       `json:"issue"`
	AuthoritySHA256                string                               `json:"authority_sha256"`
	State                          State                                `json:"state"`
	Reason                         string                               `json:"reason"`
	SupersedesRunID                string                               `json:"supersedes_run_id,omitempty"`
	Evidence                       json.RawMessage                      `json:"evidence,omitempty"`
	PendingDecision                *DecisionRequest                     `json:"pending_decision,omitempty"`
	Decisions                      []Decision                           `json:"decisions"`
	Observations                   Observations                         `json:"observations"`
	Candidates                     []Candidate                          `json:"candidates,omitempty"`
	PendingRepair                  *RepairDecisionRequest               `json:"pending_repair,omitempty"`
	PendingQualificationCorrection *QualificationCorrectionRequest      `json:"pending_qualification_correction,omitempty"`
	QualificationApproved          bool                                 `json:"qualification_approved,omitempty"`
	QualificationReviews           []QualificationReview                `json:"qualification_reviews,omitempty"`
	QualificationCorrections       []QualificationCorrection            `json:"qualification_corrections,omitempty"`
	LocalReadiness                 *LocalReadiness                      `json:"local_readiness,omitempty"`
	EffectiveProfile               deliveryevidence.DeliveryRiskProfile `json:"effective_profile,omitempty"`
	RequiredBoundaries             []SensitiveBoundary                  `json:"required_boundaries,omitempty"`
	ProfileHistory                 []ProfileTransition                  `json:"profile_history,omitempty"`
	NonLocal                       *NonLocalDelivery                    `json:"non_local,omitempty"`
	Timing                         []Timing                             `json:"timing"`
	CreatedAt                      string                               `json:"created_at"`
	UpdatedAt                      string                               `json:"updated_at"`
}

func encodeRun(record runRecord) ([]byte, error) {
	if record.Schema == legacyRunSchema {
		return encodeLegacyRun(record)
	}
	wire := runWire{
		Schema: record.Schema, ID: record.ID, Repository: record.Repository, Issue: record.Issue,
		AuthoritySHA256: record.AuthoritySHA256, State: record.State, Reason: record.Reason,
		SupersedesRunID: record.SupersedesRunID, PendingDecision: record.PendingDecision,
		Decisions: record.Decisions, Observations: record.Observations, Timing: record.Timing,
		Candidates: record.Candidates, PendingRepair: record.PendingRepair,
		PendingQualificationCorrection: record.PendingQualificationCorrection,
		QualificationApproved:          record.QualificationApproved,
		QualificationReviews:           record.QualificationReviews,
		QualificationCorrections:       record.QualificationCorrections,
		LocalReadiness:                 record.LocalReadiness,
		EffectiveProfile:               record.EffectiveProfile, RequiredBoundaries: record.RequiredBoundaries,
		ProfileHistory: record.ProfileHistory,
		NonLocal:       record.NonLocal,
		CreatedAt:      record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
	if record.Evidence != nil {
		evidence, err := deliveryevidence.CanonicalJSON(*record.Evidence)
		if err != nil {
			return nil, err
		}
		wire.Evidence = bytes.TrimSuffix(evidence, []byte{'\n'})
	}
	return json.Marshal(wire)
}

func decodeRun(data []byte) (runRecord, error) {
	var envelope struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return runRecord{}, fmt.Errorf("decode issue delivery run: %w", err)
	}
	if envelope.Schema == legacyRunSchema {
		return decodeLegacyRun(data)
	}
	var wire runWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return runRecord{}, fmt.Errorf("decode issue delivery run: %w", err)
	}
	canonical, err := json.Marshal(wire)
	if err != nil {
		return runRecord{}, err
	}
	if !bytes.Equal(data, canonical) || wire.Schema != runSchema || !validRunID(wire.ID) {
		return runRecord{}, fmt.Errorf("issue delivery run is not canonical")
	}
	record := runRecord{
		Schema: wire.Schema, ID: wire.ID, Repository: wire.Repository, Issue: wire.Issue,
		AuthoritySHA256: wire.AuthoritySHA256, State: wire.State, Reason: wire.Reason,
		SupersedesRunID: wire.SupersedesRunID, PendingDecision: wire.PendingDecision,
		Decisions: wire.Decisions, Observations: wire.Observations, Timing: wire.Timing,
		Candidates: wire.Candidates, PendingRepair: wire.PendingRepair,
		PendingQualificationCorrection: wire.PendingQualificationCorrection,
		QualificationApproved:          wire.QualificationApproved,
		QualificationReviews:           wire.QualificationReviews,
		QualificationCorrections:       wire.QualificationCorrections,
		LocalReadiness:                 wire.LocalReadiness,
		EffectiveProfile:               wire.EffectiveProfile, RequiredBoundaries: wire.RequiredBoundaries,
		ProfileHistory: wire.ProfileHistory,
		NonLocal:       wire.NonLocal,
		CreatedAt:      wire.CreatedAt, UpdatedAt: wire.UpdatedAt,
	}
	if len(wire.Evidence) > 0 {
		evidence, err := deliveryevidence.Decode(append(append([]byte(nil), wire.Evidence...), '\n'))
		if err != nil {
			return runRecord{}, err
		}
		record.Evidence = &evidence
	}
	adoptLegacyNullQualificationFindings(&record)
	if err := validateRun(record); err != nil {
		return runRecord{}, err
	}
	return record, nil
}

func validateRun(record runRecord) error {
	if (record.Schema != runSchema && record.Schema != legacyRunSchema) ||
		record.ID != runIdentity(record.Repository, record.Issue, record.AuthoritySHA256, record.SupersedesRunID) {
		return fmt.Errorf("issue delivery run identity is invalid")
	}
	if record.Repository.Owner == "" || record.Repository.Name == "" || record.Repository.NodeID == "" ||
		record.Issue.Number <= 0 || record.Issue.NodeID == "" ||
		len(record.AuthoritySHA256) != 64 || !runIDPattern.MatchString(record.AuthoritySHA256) {
		return fmt.Errorf("issue delivery run authority identity is incomplete")
	}
	if strings.TrimSpace(record.Reason) == "" || record.Decisions == nil || record.Timing == nil ||
		strings.TrimSpace(record.CreatedAt) == "" || strings.TrimSpace(record.UpdatedAt) == "" {
		return fmt.Errorf("issue delivery run state is incomplete")
	}
	switch record.State {
	case StateNeedsDecision:
		authorityDecision := record.PendingDecision != nil && record.PendingRepair == nil && record.Evidence == nil
		repairDecision := record.PendingDecision == nil && record.PendingRepair != nil && record.Evidence != nil
		qualificationCorrection := record.PendingDecision == nil && record.PendingRepair == nil &&
			record.PendingQualificationCorrection != nil && record.Evidence != nil
		if !authorityDecision && !repairDecision && !qualificationCorrection {
			return fmt.Errorf("needs-decision run requires exactly one authority or repair decision")
		}
	case StateNeedsReview, StateWaiting, StateBlocked, StateCompleted:
		if record.PendingDecision != nil || record.PendingRepair != nil ||
			record.PendingQualificationCorrection != nil || record.Evidence == nil {
			return fmt.Errorf("%s run requires admitted evidence and no pending decision", record.State)
		}
	default:
		return fmt.Errorf("persisted issue delivery run has invalid state %q", record.State)
	}
	if record.Evidence != nil {
		if record.Evidence.Repository != record.Repository || record.Evidence.Issue != record.Issue ||
			record.Evidence.Authority.IssueSHA256 != record.AuthoritySHA256 {
			return fmt.Errorf("issue delivery evidence does not match its run")
		}
	}
	if err := validateQualificationHistory(record); err != nil {
		return err
	}
	if record.Observations.Repository != record.Repository || record.Observations.Issue != record.Issue ||
		record.Observations.AuthoritySHA256 != record.AuthoritySHA256 ||
		!fullGitSHAPattern.MatchString(record.Observations.CommitSHA) ||
		!fullGitSHAPattern.MatchString(record.Observations.TreeSHA) {
		return fmt.Errorf("issue delivery run observations do not match its authority")
	}
	for i, timing := range record.Timing {
		started, startErr := time.Parse(timeFormat, timing.StartedAt)
		completed, completeErr := time.Parse(timeFormat, timing.CompletedAt)
		if timing.Sequence != i+1 || strings.TrimSpace(timing.Phase) == "" ||
			startErr != nil || completeErr != nil || completed.Before(started) {
			return fmt.Errorf("issue delivery run timing is invalid")
		}
	}
	if len(record.Timing) == 0 || record.Timing[len(record.Timing)-1].To != record.State {
		return fmt.Errorf("issue delivery run timing does not reach current state")
	}
	if _, err := time.Parse(timeFormat, record.CreatedAt); err != nil {
		return fmt.Errorf("issue delivery run creation time is invalid")
	}
	if _, err := time.Parse(timeFormat, record.UpdatedAt); err != nil {
		return fmt.Errorf("issue delivery run update time is invalid")
	}
	for _, decision := range record.Decisions {
		if strings.TrimSpace(decision.RequestID) == "" {
			return fmt.Errorf("issue delivery run contains an invalid decision")
		}
	}
	if err := validateCandidates(record); err != nil {
		return err
	}
	return nil
}

func validateCandidates(record runRecord) error {
	if record.Schema == legacyRunSchema {
		for _, candidate := range record.Candidates {
			if candidate.RepairDecision != nil &&
				candidate.RepairDecision.Class == RepairAdjudicationOnly {
				return fmt.Errorf("issue delivery candidate contains an invalid repair decision")
			}
		}
		return validateLegacyCandidates(record)
	}
	if len(record.Candidates) == 0 {
		if record.PendingRepair != nil || record.LocalReadiness != nil {
			return fmt.Errorf("issue delivery assurance state requires a candidate")
		}
		if record.EffectiveProfile != "" && record.Evidence != nil &&
			record.EffectiveProfile != record.Evidence.RiskProfile {
			return fmt.Errorf("issue delivery run profile does not match its evidence")
		}
		return nil
	}
	seen := make(map[string]bool, len(record.Candidates))
	candidateOrder := make(map[string]int, len(record.Candidates))
	for index, candidate := range record.Candidates {
		if candidate.ID != candidateIdentity(record.ID, candidate.BaseSHA, candidate.CommitSHA, candidate.TreeSHA) ||
			seen[candidate.ID] ||
			!fullGitSHAPattern.MatchString(candidate.BaseSHA) ||
			!fullGitSHAPattern.MatchString(candidate.CommitSHA) ||
			!fullGitSHAPattern.MatchString(candidate.TreeSHA) ||
			(len(candidate.RequiredReviews) == 0 &&
				(candidate.RepairClass != RepairBounded || len(candidate.RequiredSpecialists) == 0)) ||
			candidate.Reviews == nil ||
			candidate.Effects == nil || candidate.Boundaries == nil ||
			candidate.RequiredSpecialists == nil || candidate.SpecialistReviews == nil ||
			candidate.BoundaryProofs == nil ||
			(candidate.ObservedFloor != deliveryevidence.RiskLow &&
				candidate.ObservedFloor != deliveryevidence.RiskStandard &&
				candidate.ObservedFloor != deliveryevidence.RiskHigh) ||
			(candidate.Profile != deliveryevidence.RiskLow &&
				candidate.Profile != deliveryevidence.RiskStandard &&
				candidate.Profile != deliveryevidence.RiskHigh) {
			return fmt.Errorf("issue delivery candidate %d is invalid", index+1)
		}
		seen[candidate.ID] = true
		candidateOrder[candidate.ID] = index
		assessment := mechanicalProfileFloor(candidate.Effects)
		if !assessment.Complete ||
			assessment.Profile != candidate.ObservedFloor ||
			!equalEffectObservations(assessment.Effects, candidate.Effects) ||
			maxRiskProfile(candidate.ObservedFloor, candidate.Profile) != candidate.Profile ||
			!equalBoundaries(candidate.Boundaries, unionBoundaries(nil, candidate.Boundaries)) {
			return fmt.Errorf("issue delivery candidate risk assessment is invalid")
		}
		for _, boundary := range assessment.Boundaries {
			if !containsBoundary(candidate.Boundaries, boundary) {
				return fmt.Errorf("issue delivery candidate omits an observed sensitive boundary")
			}
		}
		if candidate.Profile == deliveryevidence.RiskHigh && len(candidate.Boundaries) == 0 {
			return fmt.Errorf("high-risk issue delivery candidate requires a sensitive boundary")
		}
		if candidate.Profile != deliveryevidence.RiskHigh && len(candidate.RequiredSpecialists) != 0 {
			return fmt.Errorf("non-high-risk issue delivery candidate requires no specialist")
		}
		if !equalBoundaries(candidate.RequiredSpecialists, unionBoundaries(nil, candidate.RequiredSpecialists)) {
			return fmt.Errorf("issue delivery candidate specialist boundaries are invalid")
		}
		for _, boundary := range candidate.RequiredSpecialists {
			if !containsBoundary(candidate.Boundaries, boundary) {
				return fmt.Errorf("issue delivery candidate specialist is outside its sensitive boundaries")
			}
		}
		if candidate.Profile == deliveryevidence.RiskHigh && candidate.RepairClass != RepairBounded &&
			!equalBoundaries(candidate.RequiredSpecialists, candidate.Boundaries) {
			return fmt.Errorf("high-risk issue delivery candidate omits a required specialist")
		}
		if index > 0 {
			previous := record.Candidates[index-1]
			if maxRiskProfile(previous.Profile, candidate.Profile) != candidate.Profile ||
				!equalBoundaries(candidate.Boundaries, unionBoundaries(previous.Boundaries, candidate.Boundaries)) {
				return fmt.Errorf("issue delivery candidate assurance is not monotonic")
			}
		}
		required := make(map[deliveryevidence.ReviewAxis]bool, len(candidate.RequiredReviews))
		for _, axis := range candidate.RequiredReviews {
			if (axis != deliveryevidence.ReviewStandards && axis != deliveryevidence.ReviewSpec) || required[axis] {
				return fmt.Errorf("issue delivery candidate has invalid required reviews")
			}
			required[axis] = true
		}
		findingIDs := make(map[string]bool)
		var reviewedAcceptance []AcceptanceProof
		specReviewCompleted := false
		completedReviews := make(map[deliveryevidence.ReviewAxis]int, len(candidate.RequiredReviews))
		currentIteration := currentReviewIteration(&candidate)
		if phaseOwnedAcceptance(record.Evidence.AcceptanceMatrix) {
			lastIteration := 0
			for reviewIndex, review := range candidate.Reviews {
				if review.Iteration != lastIteration {
					if review.Iteration != reviewIndex+1 {
						return fmt.Errorf("issue delivery candidate review iteration sequence is invalid")
					}
					lastIteration = review.Iteration
				}
			}
			if candidate.ReviewIteration > 0 &&
				candidate.ReviewIteration != lastIteration &&
				candidate.ReviewIteration != len(candidate.Reviews)+1 {
				return fmt.Errorf("issue delivery candidate current review iteration is invalid")
			}
		}
		batchAxes := make(map[int]map[deliveryevidence.ReviewAxis]bool)
		for _, review := range candidate.Reviews {
			if review.CandidateID != candidate.ID || !required[review.Axis] || review.Findings == nil {
				return fmt.Errorf("issue delivery candidate contains an invalid review")
			}
			if phaseOwnedAcceptance(record.Evidence.AcceptanceMatrix) &&
				(review.Iteration < 1 || review.CommitSHA != candidate.CommitSHA ||
					review.TreeSHA != candidate.TreeSHA) {
				return fmt.Errorf("issue delivery candidate contains a stale review receipt")
			}
			if phaseOwnedAcceptance(record.Evidence.AcceptanceMatrix) {
				if batchAxes[review.Iteration] == nil {
					batchAxes[review.Iteration] = make(map[deliveryevidence.ReviewAxis]bool)
				}
				if batchAxes[review.Iteration][review.Axis] {
					return fmt.Errorf("issue delivery candidate review iteration contains a duplicate axis")
				}
				batchAxes[review.Iteration][review.Axis] = true
			}
			if !review.Completed && len(review.Findings) != 0 {
				return fmt.Errorf("incomplete issue delivery candidate review contains findings")
			}
			if !review.Completed && len(review.Acceptance) != 0 {
				return fmt.Errorf("incomplete issue delivery candidate review contains acceptance proof")
			}
			for _, finding := range review.Findings {
				if findingIDs[finding.ID] || strings.TrimSpace(finding.ID) == "" || finding.Axis != review.Axis {
					return fmt.Errorf("issue delivery candidate contains an invalid finding")
				}
				findingIDs[finding.ID] = true
			}
			for _, proof := range review.Acceptance {
				if proof.CandidateID != candidate.ID ||
					proof.Phase != deliveryevidence.AssuranceCandidateReview ||
					proof.ReviewReceipt == nil ||
					proof.ReviewReceipt.CandidateID != review.CandidateID ||
					proof.ReviewReceipt.Axis != review.Axis ||
					proof.ReviewReceipt.Iteration != review.Iteration ||
					proof.ReviewReceipt.CommitSHA != review.CommitSHA ||
					proof.ReviewReceipt.TreeSHA != review.TreeSHA {
					return fmt.Errorf("issue delivery candidate contains a stale acceptance review reference")
				}
			}
			if review.Iteration == currentIteration &&
				review.Axis == deliveryevidence.ReviewSpec && review.Completed {
				reviewedAcceptance = review.Acceptance
				specReviewCompleted = true
			}
			if review.Iteration == currentIteration && review.Completed {
				completedReviews[review.Axis]++
			}
		}
		if phaseOwnedAcceptance(record.Evidence.AcceptanceMatrix) {
			if !specReviewCompleted {
				if len(candidate.Acceptance) != 0 {
					return fmt.Errorf("issue delivery candidate acceptance lacks a completed current Spec review")
				}
			} else {
				candidateSemantic := append([]AcceptanceProof(nil), candidate.Acceptance...)
				for proofIndex := range candidateSemantic {
					candidateSemantic[proofIndex].ValidationReceipt = nil
				}
				if !reflect.DeepEqual(candidateSemantic, reviewedAcceptance) {
					return fmt.Errorf("issue delivery candidate acceptance does not match its completed Spec review")
				}
			}
		}
		if candidate.Exhaustive != nil && phaseOwnedAcceptance(record.Evidence.AcceptanceMatrix) {
			for axis := range required {
				if completedReviews[axis] != 1 {
					return fmt.Errorf("issue delivery exhaustive candidate lacks exactly one completed required review")
				}
			}
			acceptanceEvidence := *record.Evidence
			acceptanceEvidence.AcceptanceMatrix = append(
				[]deliveryevidence.AcceptanceRow(nil), record.Evidence.AcceptanceMatrix...,
			)
			if err := admitAcceptanceProofs(
				&acceptanceEvidence, &candidate, candidate.Acceptance,
			); err != nil {
				return fmt.Errorf("issue delivery exhaustive candidate acceptance is incomplete: %w", err)
			}
		}
		for _, proof := range []*ValidationProof{candidate.Focused, candidate.Exhaustive} {
			if proof == nil {
				continue
			}
			if proof.Result.CommitSHA != candidate.CommitSHA || proof.Result.TreeSHA != candidate.TreeSHA ||
				strings.TrimSpace(proof.CompletedAt) == "" || !proof.Result.Sandboxed ||
				!proof.Result.Succeeded || !proof.Result.Completed ||
				!filepath.IsAbs(proof.Result.HomeRoot) || filepath.Clean(proof.Result.HomeRoot) != proof.Result.HomeRoot ||
				!filepath.IsAbs(proof.Result.ConfigRoot) || filepath.Clean(proof.Result.ConfigRoot) != proof.Result.ConfigRoot ||
				proof.Result.HomeRoot == proof.Result.ConfigRoot {
				return fmt.Errorf("issue delivery candidate contains an invalid validation proof")
			}
		}
		if candidate.Focused != nil && candidate.Focused.Kind != "focused" {
			return fmt.Errorf("issue delivery candidate contains an invalid focused proof")
		}
		if candidate.Exhaustive != nil &&
			(candidate.Exhaustive.Kind != "exhaustive" ||
				candidate.Exhaustive.Result.Command != "./scripts/validate-packy.sh" ||
				candidate.Exhaustive.Result.ValidatorIdentity != "scripts/validate-packy.sh" ||
				!runIDPattern.MatchString(candidate.Exhaustive.Result.CheckoutSHA256) ||
				!runIDPattern.MatchString(candidate.Exhaustive.Result.ValidatorSHA256) ||
				!candidate.Exhaustive.Result.WorkspaceClean) {
			return fmt.Errorf("issue delivery candidate contains an invalid exhaustive proof")
		}
		if candidate.Exhaustive != nil && phaseOwnedAcceptance(record.Evidence.AcceptanceMatrix) {
			if len(candidate.Exhaustive.Result.Acceptance) != 0 ||
				validateValidationTraceability(
					candidate.Exhaustive.Result.Traceability,
					record.Evidence.AcceptanceMatrix,
					candidate,
				) != nil {
				return fmt.Errorf("issue delivery candidate contains invalid exhaustive acceptance traceability")
			}
		}
		for _, proof := range candidate.Acceptance {
			if !phaseOwnedAcceptance(record.Evidence.AcceptanceMatrix) {
				break
			}
			if proof.CandidateID != candidate.ID ||
				proof.Phase != deliveryevidence.AssuranceCandidateReview {
				return fmt.Errorf("issue delivery candidate contains a stale acceptance proof")
			}
			if candidate.Exhaustive == nil && proof.ValidationReceipt != nil {
				return fmt.Errorf("issue delivery candidate contains a premature acceptance validation reference")
			}
			if candidate.Exhaustive != nil {
				reference := proof.ValidationReceipt
				if reference == nil ||
					reference.Schema != deliveryevidence.ValidationReceiptV1 ||
					reference.CandidateID != candidate.ID ||
					reference.CommitSHA != candidate.CommitSHA ||
					reference.CommitSHA != candidate.Exhaustive.Result.CommitSHA ||
					reference.TreeSHA != candidate.TreeSHA ||
					reference.TreeSHA != candidate.Exhaustive.Result.TreeSHA ||
					reference.CompletedAt != candidate.Exhaustive.CompletedAt {
					return fmt.Errorf("issue delivery candidate contains a stale acceptance validation reference")
				}
			}
			if candidate.Exhaustive != nil && index == len(record.Candidates)-1 {
				reference := proof.ValidationReceipt
				matched := false
				for _, receipt := range record.Evidence.ValidationReceipts {
					if receipt.Schema == reference.Schema &&
						receipt.CommitSHA == reference.CommitSHA &&
						receipt.TreeSHA == reference.TreeSHA &&
						receipt.CompletedAt == reference.CompletedAt {
						matched = true
					}
				}
				if !matched {
					return fmt.Errorf("issue delivery candidate contains a stale acceptance validation reference")
				}
			}
		}
		specialists := map[SensitiveBoundary]bool{}
		for _, review := range candidate.SpecialistReviews {
			if specialists[review.Boundary] || review.CandidateID != candidate.ID ||
				!containsBoundary(candidate.RequiredSpecialists, review.Boundary) ||
				review.Specialist != specialistForBoundary(review.Boundary) || review.Findings == nil {
				return fmt.Errorf("issue delivery candidate contains an invalid specialist review")
			}
			if !review.Completed && len(review.Findings) != 0 {
				return fmt.Errorf("incomplete issue delivery specialist review contains findings")
			}
			for _, finding := range review.Findings {
				if findingIDs[finding.ID] || strings.TrimSpace(finding.ID) == "" {
					return fmt.Errorf("issue delivery candidate contains an invalid specialist finding")
				}
				findingIDs[finding.ID] = true
			}
			specialists[review.Boundary] = true
		}
		if err := validatePersistedRepairDecision(record.Schema, candidate, findingIDs); err != nil {
			return err
		}
		proofs := map[SensitiveBoundary]bool{}
		for _, proof := range candidate.BoundaryProofs {
			result := proof.Result
			if proofs[result.Boundary] || result.CandidateID != candidate.ID ||
				!containsBoundary(candidate.Boundaries, result.Boundary) ||
				result.CommitSHA != candidate.CommitSHA || result.TreeSHA != candidate.TreeSHA ||
				!result.Sandboxed || !result.Succeeded || !result.Completed ||
				result.OperatorStateBeforeSHA256 != result.OperatorStateAfterSHA256 ||
				!runIDPattern.MatchString(result.OperatorStateBeforeSHA256) ||
				!runIDPattern.MatchString(result.ToolSHA256) ||
				!runIDPattern.MatchString(result.WriteManifestSHA256) {
				return fmt.Errorf("issue delivery candidate contains an invalid boundary proof")
			}
			proofs[result.Boundary] = true
		}
	}
	current := record.Candidates[len(record.Candidates)-1]
	if record.PendingRepair != nil &&
		(record.PendingRepair.CandidateID != current.ID || strings.TrimSpace(record.PendingRepair.ID) == "" ||
			len(record.PendingRepair.FindingIDs) == 0) {
		return fmt.Errorf("pending repair does not match the current candidate")
	}
	if record.LocalReadiness != nil &&
		(record.LocalReadiness.CandidateID != current.ID ||
			record.LocalReadiness.CommitSHA != current.CommitSHA ||
			record.LocalReadiness.TreeSHA != current.TreeSHA ||
			record.LocalReadiness.AuthorityHash != record.AuthoritySHA256 ||
			strings.TrimSpace(record.LocalReadiness.Branch) == "" ||
			strings.TrimSpace(record.LocalReadiness.ReadyAt) == "") {
		return fmt.Errorf("local readiness does not match the current candidate")
	}
	if record.LocalReadiness != nil {
		if current.Exhaustive == nil || len(current.Acceptance) != len(record.Evidence.AcceptanceMatrix) ||
			len(record.Evidence.ValidationReceipts) == 0 ||
			len(missingSpecialistBoundaries(&current)) != 0 ||
			len(missingBoundaryProofs(&current)) != 0 {
			return fmt.Errorf("local readiness lacks exact candidate assurance")
		}
		for _, row := range record.Evidence.AcceptanceMatrix {
			if row.State != deliveryevidence.AcceptanceProved {
				return fmt.Errorf("local readiness contains unproved acceptance")
			}
		}
	}
	if record.EffectiveProfile != current.Profile || record.Evidence.RiskProfile != record.EffectiveProfile ||
		!equalBoundaries(record.RequiredBoundaries, current.Boundaries) {
		return fmt.Errorf("issue delivery run profile does not match its current candidate")
	}
	previousProfile := deliveryevidence.RiskLow
	previousBoundaries := []SensitiveBoundary{}
	previousCandidateIndex := -1
	for index, transition := range record.ProfileHistory {
		candidateIndex, candidateFound := candidateOrder[transition.CandidateID]
		if transition.Sequence != index+1 || !candidateFound ||
			(candidateIndex != previousCandidateIndex && candidateIndex != previousCandidateIndex+1) ||
			(transition.ObservedFloor != deliveryevidence.RiskLow &&
				transition.ObservedFloor != deliveryevidence.RiskStandard &&
				transition.ObservedFloor != deliveryevidence.RiskHigh) ||
			maxRiskProfile(transition.ObservedFloor, transition.EffectiveProfile) != transition.EffectiveProfile ||
			maxRiskProfile(previousProfile, transition.EffectiveProfile) != transition.EffectiveProfile ||
			!equalBoundaries(transition.Boundaries, unionBoundaries(nil, transition.Boundaries)) ||
			!equalBoundaries(transition.Boundaries, unionBoundaries(previousBoundaries, transition.Boundaries)) ||
			strings.TrimSpace(transition.ObservedAt) == "" {
			return fmt.Errorf("issue delivery profile history is invalid")
		}
		candidate := record.Candidates[candidateIndex]
		if maxRiskProfile(transition.EffectiveProfile, candidate.Profile) != candidate.Profile ||
			!equalBoundaries(candidate.Boundaries, unionBoundaries(transition.Boundaries, candidate.Boundaries)) {
			return fmt.Errorf("issue delivery profile transition does not match its candidate")
		}
		if candidateIndex != previousCandidateIndex && previousCandidateIndex >= 0 {
			previousCandidate := record.Candidates[previousCandidateIndex]
			if previousProfile != previousCandidate.Profile ||
				!equalBoundaries(previousBoundaries, previousCandidate.Boundaries) {
				return fmt.Errorf("issue delivery profile history does not close its candidate")
			}
		}
		previousProfile = transition.EffectiveProfile
		previousBoundaries = transition.Boundaries
		previousCandidateIndex = candidateIndex
	}
	if len(record.ProfileHistory) == 0 ||
		previousCandidateIndex != len(record.Candidates)-1 ||
		record.ProfileHistory[len(record.ProfileHistory)-1].EffectiveProfile != record.EffectiveProfile ||
		!equalBoundaries(record.ProfileHistory[len(record.ProfileHistory)-1].Boundaries, record.RequiredBoundaries) {
		return fmt.Errorf("issue delivery profile history does not reach current profile")
	}
	if err := validateNonLocalRecord(record, current); err != nil {
		return err
	}
	return nil
}

func validatePersistedRepairDecision(
	schema string,
	candidate Candidate,
	findingIDs map[string]bool,
) error {
	decision := candidate.RepairDecision
	if decision == nil {
		return nil
	}
	if decision.CandidateID != candidate.ID ||
		(schema == legacyRunSchema && decision.Class == RepairAdjudicationOnly) ||
		(decision.Class != RepairBounded &&
			decision.Class != RepairCandidateChanging &&
			decision.Class != RepairAdjudicationOnly) ||
		len(decision.Findings) != len(findingIDs) {
		return fmt.Errorf("issue delivery candidate contains an invalid repair decision")
	}
	seen := make(map[string]bool, len(decision.Findings))
	accepted := false
	for _, item := range decision.Findings {
		if seen[item.FindingID] || !findingIDs[item.FindingID] ||
			strings.TrimSpace(item.Evidence) == "" ||
			(item.Disposition != FindingAccepted && item.Disposition != FindingRejected) {
			return fmt.Errorf("issue delivery candidate contains an invalid repair decision")
		}
		seen[item.FindingID] = true
		accepted = accepted || item.Disposition == FindingAccepted
	}
	if decision.Class == RepairAdjudicationOnly {
		if accepted {
			return fmt.Errorf("issue delivery candidate contains an invalid repair decision")
		}
	} else if decision.Class == RepairBounded && !accepted {
		return fmt.Errorf("issue delivery candidate contains an invalid repair decision")
	}
	return nil
}
