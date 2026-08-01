package issuedelivery

import (
	"fmt"
	"sort"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

type CompactTimingCategory string
type TimingObjectiveComparisonResult string
type ReusedValidationArtifactKind string

const (
	CompactTimingActiveWork     CompactTimingCategory = "active-work"
	CompactTimingReview         CompactTimingCategory = "review"
	CompactTimingValidation     CompactTimingCategory = "validation"
	CompactTimingExternalCIWait CompactTimingCategory = "external-ci-wait"
	CompactTimingMerge          CompactTimingCategory = "merge"
	CompactTimingCleanup        CompactTimingCategory = "cleanup"
)

const (
	TimingObjectivePending     TimingObjectiveComparisonResult = "pending"
	TimingObjectiveInProgress  TimingObjectiveComparisonResult = "in-progress"
	TimingObjectiveWithin      TimingObjectiveComparisonResult = "within-objective"
	TimingObjectiveOver        TimingObjectiveComparisonResult = "over-objective"
	TimingObjectiveUnderRange  TimingObjectiveComparisonResult = "under-objective-range"
	TimingObjectiveWithinRange TimingObjectiveComparisonResult = "within-objective-range"
	TimingObjectiveOverRange   TimingObjectiveComparisonResult = "over-objective-range"
)

const (
	ReusedValidationBoundary   ReusedValidationArtifactKind = "boundary"
	ReusedValidationExhaustive ReusedValidationArtifactKind = "exhaustive"
)

var compactTimingCategoryOrder = [...]CompactTimingCategory{
	CompactTimingActiveWork,
	CompactTimingReview,
	CompactTimingValidation,
	CompactTimingExternalCIWait,
	CompactTimingMerge,
	CompactTimingCleanup,
}

var validationInvalidationClassOrder = [...]ValidationInvalidationClass{
	ValidationInvalidationCandidate,
	ValidationInvalidationCommit,
	ValidationInvalidationTree,
	ValidationInvalidationCheckout,
	ValidationInvalidationValidator,
	ValidationInvalidationCommand,
	ValidationInvalidationSandbox,
	ValidationInvalidationInstrumentation,
	ValidationInvalidationBoundaryRequirement,
	ValidationInvalidationExpiry,
	ValidationInvalidationWorkspace,
	ValidationInvalidationFailedExecution,
}

type CompactRunProjection struct {
	Timing    CompactTimingProjection    `json:"timing"`
	Assurance CompactAssuranceProjection `json:"assurance"`
}

type CompactTimingProjection struct {
	Categories                  []CompactTimingCategoryDuration `json:"categories"`
	OpenExternalWaitNanoseconds *int64                          `json:"open_external_wait_nanoseconds,omitempty"`
	Objective                   TimingObjectiveComparison       `json:"objective"`
}

type CompactTimingCategoryDuration struct {
	Category            CompactTimingCategory `json:"category"`
	DurationNanoseconds int64                 `json:"duration_nanoseconds"`
}

type TimingObjectiveComparison struct {
	Profile     deliveryevidence.DeliveryRiskProfile `json:"profile,omitempty"`
	Applicable  bool                                 `json:"applicable"`
	PRReadiness *TimingThresholdComparison           `json:"pr_readiness,omitempty"`
	EndToEnd    *TimingRangeComparison               `json:"end_to_end,omitempty"`
}

type TimingThresholdComparison struct {
	ObservedNanoseconds *int64                          `json:"observed_nanoseconds,omitempty"`
	MaximumNanoseconds  int64                           `json:"maximum_nanoseconds"`
	Comparison          TimingObjectiveComparisonResult `json:"comparison"`
}

type TimingRangeComparison struct {
	ObservedNanoseconds int64                           `json:"observed_nanoseconds"`
	MinimumNanoseconds  int64                           `json:"minimum_nanoseconds"`
	MaximumNanoseconds  int64                           `json:"maximum_nanoseconds"`
	Comparison          TimingObjectiveComparisonResult `json:"comparison"`
}

type CompactAssuranceProjection struct {
	Progress                  *CompactAssuranceProgress  `json:"progress,omitempty"`
	RetainedReviewReceipts    []RetainedReviewReceipt    `json:"retained_review_receipts,omitempty"`
	ReusedValidationArtifacts []ReusedValidationArtifact `json:"reused_validation_artifacts,omitempty"`
	Invalidations             []ValidationInvalidation   `json:"invalidations,omitempty"`
}

type CompactAssuranceProgress struct {
	CandidateReviewAxes  CompactReviewProgress      `json:"candidate_review_axes"`
	SpecialistBoundaries *CompactSpecialistProgress `json:"specialist_boundaries,omitempty"`
}

type CompactReviewProgress struct {
	Retained       []deliveryevidence.ReviewAxis `json:"retained,omitempty"`
	CompletedDelta []deliveryevidence.ReviewAxis `json:"completed_delta,omitempty"`
	Completed      []deliveryevidence.ReviewAxis `json:"completed"`
	Pending        []deliveryevidence.ReviewAxis `json:"pending"`
}

type CompactSpecialistProgress struct {
	Retained       []CompactSpecialistBoundary `json:"retained,omitempty"`
	CompletedDelta []CompactSpecialistBoundary `json:"completed_delta,omitempty"`
	Completed      []CompactSpecialistBoundary `json:"completed"`
	Pending        []CompactSpecialistBoundary `json:"pending"`
}

type CompactSpecialistBoundary struct {
	Boundary   SensitiveBoundary `json:"boundary"`
	Specialist string            `json:"specialist"`
}

type RetainedReviewReceipt struct {
	Identity   string                      `json:"identity"`
	Iteration  int                         `json:"iteration"`
	Axis       deliveryevidence.ReviewAxis `json:"axis,omitempty"`
	Boundary   SensitiveBoundary           `json:"boundary,omitempty"`
	Specialist string                      `json:"specialist,omitempty"`
}

type ReusedValidationArtifact struct {
	Kind                       ReusedValidationArtifactKind `json:"kind"`
	Identity                   string                       `json:"identity"`
	Boundary                   SensitiveBoundary            `json:"boundary,omitempty"`
	SessionID                  string                       `json:"session_id"`
	ValidationCompletionSHA256 string                       `json:"validation_completion_sha256"`
}

// BuildCompactRunProjection exposes a bounded explanation of canonical run
// facts. It is observational only: none of its comparisons participate in
// delivery state, readiness, or exit-status decisions.
func BuildCompactRunProjection(outcome Outcome, now time.Time) (CompactRunProjection, error) {
	timing, err := compactTimingProjection(outcome, now)
	if err != nil {
		return CompactRunProjection{}, err
	}
	return CompactRunProjection{
		Timing:    timing,
		Assurance: compactAssuranceProjection(outcome),
	}, nil
}

func compactTimingProjection(outcome Outcome, now time.Time) (CompactTimingProjection, error) {
	snapshotNow := now.UTC()
	var openWait *int64
	if len(outcome.Timing) > 0 {
		last := outcome.Timing[len(outcome.Timing)-1]
		if last.To == StateWaiting && last.Phase == "ci-wait" {
			started, err := time.Parse(time.RFC3339Nano, last.CompletedAt)
			if err != nil {
				return CompactTimingProjection{}, fmt.Errorf("open external wait has invalid start: %w", err)
			}
			if snapshotNow.Before(started) {
				return CompactTimingProjection{}, fmt.Errorf("timing report time precedes open external wait")
			}
			duration := snapshotNow.Sub(started).Nanoseconds()
			openWait = &duration
			snapshotNow = started
		}
	}
	report, err := BuildTimingReport(outcome.Timing, snapshotNow)
	if err != nil {
		return CompactTimingProjection{}, err
	}
	totals := make(map[CompactTimingCategory]int64, len(compactTimingCategoryOrder))
	for _, category := range report.Categories {
		switch category.Category {
		case TimingQualification, TimingImplementation, TimingRepair:
			totals[CompactTimingActiveWork] += category.DurationNanoseconds
		case TimingReview:
			totals[CompactTimingReview] += category.DurationNanoseconds
		case TimingValidation:
			totals[CompactTimingValidation] += category.DurationNanoseconds
		case TimingCIWait:
			totals[CompactTimingExternalCIWait] += category.DurationNanoseconds
		case TimingMerge:
			totals[CompactTimingMerge] += category.DurationNanoseconds
		case TimingCleanup:
			totals[CompactTimingCleanup] += category.DurationNanoseconds
		}
	}
	categories := make([]CompactTimingCategoryDuration, 0, len(compactTimingCategoryOrder))
	for _, category := range compactTimingCategoryOrder {
		categories = append(categories, CompactTimingCategoryDuration{
			Category: category, DurationNanoseconds: totals[category],
		})
	}
	return CompactTimingProjection{
		Categories:                  categories,
		OpenExternalWaitNanoseconds: openWait,
		Objective:                   compactTimingObjective(outcome, report.LowRisk),
	}, nil
}

func compactTimingObjective(outcome Outcome, telemetry LowRiskTimingTelemetry) TimingObjectiveComparison {
	comparison := TimingObjectiveComparison{
		Profile:    outcome.EffectiveProfile,
		Applicable: outcome.EffectiveProfile == deliveryevidence.RiskLow,
	}
	if !comparison.Applicable {
		return comparison
	}
	prComparison := TimingObjectivePending
	if telemetry.QualificationToPRReadinessNanoseconds != nil {
		prComparison = TimingObjectiveWithin
		if *telemetry.QualificationToPRReadinessNanoseconds > telemetry.PRReadinessObjectiveNanoseconds {
			prComparison = TimingObjectiveOver
		}
	}
	endComparison := TimingObjectiveInProgress
	if outcome.State == StateCompleted {
		switch {
		case telemetry.EndToEndNanoseconds < telemetry.EndToEndObjectiveMinNanoseconds:
			endComparison = TimingObjectiveUnderRange
		case telemetry.EndToEndNanoseconds > telemetry.EndToEndObjectiveMaxNanoseconds:
			endComparison = TimingObjectiveOverRange
		default:
			endComparison = TimingObjectiveWithinRange
		}
	} else if telemetry.EndToEndNanoseconds > telemetry.EndToEndObjectiveMaxNanoseconds {
		endComparison = TimingObjectiveOverRange
	}
	comparison.PRReadiness = &TimingThresholdComparison{
		ObservedNanoseconds: telemetry.QualificationToPRReadinessNanoseconds,
		MaximumNanoseconds:  telemetry.PRReadinessObjectiveNanoseconds,
		Comparison:          prComparison,
	}
	comparison.EndToEnd = &TimingRangeComparison{
		ObservedNanoseconds: telemetry.EndToEndNanoseconds,
		MinimumNanoseconds:  telemetry.EndToEndObjectiveMinNanoseconds,
		MaximumNanoseconds:  telemetry.EndToEndObjectiveMaxNanoseconds,
		Comparison:          endComparison,
	}
	return comparison
}

func compactAssuranceProjection(outcome Outcome) CompactAssuranceProjection {
	candidate := outcome.Candidate
	if candidate == nil {
		return CompactAssuranceProjection{}
	}
	projection := CompactAssuranceProjection{
		Progress: compactAssuranceProgress(*candidate),
		Invalidations: boundedValidationInvalidations(
			outcome.ValidationInvalidations,
			candidate.ID,
		),
	}
	projection.RetainedReviewReceipts = retainedReviewReceipts(outcome.Evidence, *candidate)
	projection.ReusedValidationArtifacts = reusedValidationArtifacts(outcome, *candidate)
	return projection
}

func compactAssuranceProgress(candidate Candidate) *CompactAssuranceProgress {
	progress := &CompactAssuranceProgress{
		CandidateReviewAxes: CompactReviewProgress{
			Completed: []deliveryevidence.ReviewAxis{}, Pending: []deliveryevidence.ReviewAxis{},
		},
	}
	if candidate.Derivation != nil {
		progress.CandidateReviewAxes.Retained = []deliveryevidence.ReviewAxis{}
		progress.CandidateReviewAxes.CompletedDelta = []deliveryevidence.ReviewAxis{}
	}
	if len(candidate.RequiredSpecialists) != 0 {
		progress.SpecialistBoundaries = &CompactSpecialistProgress{
			Completed: []CompactSpecialistBoundary{},
			Pending:   []CompactSpecialistBoundary{},
		}
		if candidate.Derivation != nil {
			progress.SpecialistBoundaries.Retained = []CompactSpecialistBoundary{}
			progress.SpecialistBoundaries.CompletedDelta = []CompactSpecialistBoundary{}
		}
	}

	pendingAxes := missingReviewAxes(&candidate)
	requiredAxes := make(map[deliveryevidence.ReviewAxis]bool, len(candidate.RequiredReviews))
	for _, axis := range candidate.RequiredReviews {
		requiredAxes[axis] = true
	}
	var axes []deliveryevidence.ReviewAxis
	for _, axis := range bothReviewAxes() {
		if requiredAxes[axis] {
			axes = append(axes, axis)
		}
	}
	for _, axis := range axes {
		if containsAxis(pendingAxes, axis) {
			progress.CandidateReviewAxes.Pending = append(
				progress.CandidateReviewAxes.Pending, axis,
			)
		} else if containsAxis(retainedReviewAxes(&candidate), axis) {
			progress.CandidateReviewAxes.Retained = append(
				progress.CandidateReviewAxes.Retained, axis,
			)
		} else if candidate.Derivation != nil && containsAxis(candidate.Derivation.Decision.DeltaReviewAxes, axis) {
			progress.CandidateReviewAxes.CompletedDelta = append(
				progress.CandidateReviewAxes.CompletedDelta, axis,
			)
		} else {
			progress.CandidateReviewAxes.Completed = append(
				progress.CandidateReviewAxes.Completed, axis,
			)
		}
	}

	if progress.SpecialistBoundaries == nil {
		return progress
	}
	pendingBoundaries := missingSpecialistBoundaries(&candidate)
	boundaries := append([]SensitiveBoundary(nil), candidate.RequiredSpecialists...)
	sort.Slice(boundaries, func(i, j int) bool { return boundaries[i] < boundaries[j] })
	for _, boundary := range boundaries {
		entry := CompactSpecialistBoundary{
			Boundary: boundary, Specialist: specialistForBoundary(boundary),
		}
		if containsBoundary(pendingBoundaries, boundary) {
			progress.SpecialistBoundaries.Pending = append(
				progress.SpecialistBoundaries.Pending, entry,
			)
		} else if containsBoundary(retainedSpecialistBoundaries(&candidate), boundary) {
			progress.SpecialistBoundaries.Retained = append(
				progress.SpecialistBoundaries.Retained, entry,
			)
		} else if candidate.Derivation != nil &&
			!containsEvidenceBoundary(candidate.Derivation.Decision.FullSpecialistBoundaries, boundary) {
			progress.SpecialistBoundaries.CompletedDelta = append(
				progress.SpecialistBoundaries.CompletedDelta, entry,
			)
		} else {
			progress.SpecialistBoundaries.Completed = append(
				progress.SpecialistBoundaries.Completed, entry,
			)
		}
	}
	return progress
}

func containsEvidenceBoundary(values []deliveryevidence.SensitiveBoundary, want SensitiveBoundary) bool {
	for _, value := range values {
		if value == deliveryevidence.SensitiveBoundary(want) {
			return true
		}
	}
	return false
}

func retainedReviewReceipts(
	evidence *deliveryevidence.Bundle,
	candidate Candidate,
) []RetainedReviewReceipt {
	if candidate.Derivation != nil && len(candidate.Derivation.RetainedReviewReceipts) != 0 {
		result := make([]RetainedReviewReceipt, 0, len(candidate.Derivation.RetainedReviewReceipts))
		for _, receipt := range candidate.Derivation.RetainedReviewReceipts {
			boundary := SensitiveBoundary(receipt.Boundary)
			result = append(result, RetainedReviewReceipt{
				Identity: receipt.Identity, Axis: receipt.Axis, Boundary: boundary,
				Specialist: specialistForBoundary(boundary),
			})
		}
		return result
	}
	if evidence == nil {
		return nil
	}
	var retained *deliveryevidence.CandidateReviewReceipt
	for index := range evidence.CandidateReviewReceipts {
		receipt := &evidence.CandidateReviewReceipts[index]
		if receipt.CandidateID != candidate.ID ||
			receipt.CommitSHA != candidate.CommitSHA ||
			receipt.TreeSHA != candidate.TreeSHA {
			continue
		}
		if retained == nil || receipt.Iteration > retained.Iteration {
			retained = receipt
		}
	}
	if retained == nil {
		return nil
	}
	return []RetainedReviewReceipt{{
		Identity: retained.Identity, Iteration: retained.Iteration,
	}}
}

func reusedValidationArtifacts(outcome Outcome, candidate Candidate) []ReusedValidationArtifact {
	sessions := make(map[string]ValidationSession)
	for _, session := range outcome.ValidationSessions {
		if session.CompletionSHA256 == "" ||
			session.CandidateID != candidate.ID ||
			session.CommitSHA != candidate.CommitSHA ||
			session.TreeSHA != candidate.TreeSHA {
			continue
		}
		sessions[session.CompletionSHA256] = session
	}
	var artifacts []ReusedValidationArtifact
	for _, proof := range candidate.BoundaryProofs {
		session, ok := sessions[proof.ValidationCompletionSHA256]
		if !ok ||
			proof.Result.CandidateID != candidate.ID ||
			proof.Result.CommitSHA != candidate.CommitSHA ||
			proof.Result.TreeSHA != candidate.TreeSHA ||
			proof.Result.WriteManifestSHA256 == "" {
			continue
		}
		artifacts = append(artifacts, ReusedValidationArtifact{
			Kind: ReusedValidationBoundary, Identity: proof.Result.WriteManifestSHA256,
			Boundary:  proof.Result.Boundary,
			SessionID: session.ID, ValidationCompletionSHA256: session.CompletionSHA256,
		})
	}
	if proof := candidate.Exhaustive; proof != nil {
		if session, ok := sessions[proof.ValidationCompletionSHA256]; ok &&
			proof.Result.CommitSHA == candidate.CommitSHA &&
			proof.Result.TreeSHA == candidate.TreeSHA {
			identity := exhaustiveReceiptIdentity(outcome.Evidence, candidate, *proof)
			if identity != "" {
				artifacts = append(artifacts, ReusedValidationArtifact{
					Kind: ReusedValidationExhaustive, Identity: identity,
					SessionID: session.ID, ValidationCompletionSHA256: session.CompletionSHA256,
				})
			}
		}
	}
	sort.Slice(artifacts, func(i, j int) bool {
		if artifacts[i].Kind == artifacts[j].Kind {
			return artifacts[i].Boundary < artifacts[j].Boundary
		}
		return artifacts[i].Kind < artifacts[j].Kind
	})
	return artifacts
}

func exhaustiveReceiptIdentity(
	evidence *deliveryevidence.Bundle,
	candidate Candidate,
	proof ValidationProof,
) string {
	if evidence == nil {
		return ""
	}
	for _, receipt := range evidence.ExhaustiveAssurance {
		if receipt.CandidateID == candidate.ID &&
			receipt.CommitSHA == candidate.CommitSHA &&
			receipt.TreeSHA == candidate.TreeSHA &&
			receipt.CompletedAt == proof.CompletedAt {
			return receipt.Identity
		}
	}
	return ""
}

func boundedValidationInvalidations(
	values []ValidationInvalidation,
	candidateID string,
) []ValidationInvalidation {
	latest := make(map[ValidationInvalidationClass]ValidationInvalidation, len(validationInvalidationClassOrder))
	for _, value := range values {
		if value.CandidateID != candidateID {
			continue
		}
		latest[value.Class] = value
	}
	out := make([]ValidationInvalidation, 0, len(latest))
	for _, class := range validationInvalidationClassOrder {
		if value, ok := latest[class]; ok {
			out = append(out, value)
		}
	}
	return out
}
