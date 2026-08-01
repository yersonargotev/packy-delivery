package issuedelivery

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func TestCompactRunProjectionAggregatesCanonicalTimingAndReportsObjectiveOverrun(t *testing.T) {
	start := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	timings := compactProjectionTimings(start, []compactTimingFixture{
		{"qualification", StateNeedsReview, 5 * time.Minute},
		{"candidate-development", StateNeedsReview, 10 * time.Minute},
		{"review", StateNeedsReview, 5 * time.Minute},
		{"repair", StateNeedsReview, 5 * time.Minute},
		{"exhaustive-validation", StateWaiting, 5 * time.Minute},
		{"pull-request", StateWaiting, 1 * time.Minute},
		{"ci-success", StateWaiting, 2 * time.Minute},
		{"merge", StateWaiting, 1 * time.Minute},
		{"completion", StateCompleted, 2 * time.Minute},
	})
	projection, err := BuildCompactRunProjection(Outcome{
		State: StateCompleted, Timing: timings, EffectiveProfile: deliveryevidence.RiskLow,
	}, start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := []CompactTimingCategoryDuration{
		{CompactTimingActiveWork, int64(21 * time.Minute)},
		{CompactTimingReview, int64(5 * time.Minute)},
		{CompactTimingValidation, int64(5 * time.Minute)},
		{CompactTimingExternalCIWait, int64(2 * time.Minute)},
		{CompactTimingMerge, int64(time.Minute)},
		{CompactTimingCleanup, int64(2 * time.Minute)},
	}
	if !reflect.DeepEqual(projection.Timing.Categories, want) {
		t.Fatalf("categories=%#v want %#v", projection.Timing.Categories, want)
	}
	if projection.Timing.OpenExternalWaitNanoseconds != nil {
		t.Fatalf("completed run reported open wait: %#v", projection.Timing)
	}
	objective := projection.Timing.Objective
	if !objective.Applicable || objective.PRReadiness == nil || objective.EndToEnd == nil {
		t.Fatalf("low-risk objective missing: %#v", objective)
	}
	if objective.PRReadiness.Comparison != "over-objective" ||
		objective.EndToEnd.Comparison != "over-objective-range" {
		t.Fatalf("objective comparison=%#v", objective)
	}
}

func TestCompactRunProjectionIsStableApartFromDeclaredOpenWait(t *testing.T) {
	start := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	outcome := Outcome{
		State: StateWaiting, EffectiveProfile: deliveryevidence.RiskLow,
		Timing: compactProjectionTimings(start, []compactTimingFixture{
			{"qualification", StateNeedsReview, time.Minute},
			{"ci-wait", StateWaiting, time.Minute},
		}),
	}
	first, err := BuildCompactRunProjection(outcome, start.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCompactRunProjection(outcome, start.Add(8*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.Timing.OpenExternalWaitNanoseconds == nil ||
		second.Timing.OpenExternalWaitNanoseconds == nil ||
		*second.Timing.OpenExternalWaitNanoseconds-*first.Timing.OpenExternalWaitNanoseconds !=
			int64(3*time.Minute) {
		t.Fatalf("open waits first=%v second=%v",
			first.Timing.OpenExternalWaitNanoseconds, second.Timing.OpenExternalWaitNanoseconds)
	}
	first.Timing.OpenExternalWaitNanoseconds = nil
	second.Timing.OpenExternalWaitNanoseconds = nil
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("non-wait projection changed:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func TestCompactRunProjectionNamesRetainedAndReusedCurrentCandidateEvidence(t *testing.T) {
	candidateID := "candidate-current"
	commit := strings.Repeat("a", 40)
	tree := strings.Repeat("b", 40)
	completion := strings.Repeat("c", 64)
	completedAt := "2026-07-31T12:00:00Z"
	outcome := Outcome{
		Candidate: &Candidate{
			ID: candidateID, CommitSHA: commit, TreeSHA: tree,
			BoundaryProofs: []BoundaryProof{{
				Result: BoundaryValidationResult{
					CandidateID: candidateID, Boundary: BoundarySecurity,
					CommitSHA: commit, TreeSHA: tree,
					WriteManifestSHA256: strings.Repeat("d", 64),
				},
				ValidationCompletionSHA256: completion,
			}},
			Exhaustive: &ValidationProof{
				Result:                     ValidationResult{CommitSHA: commit, TreeSHA: tree},
				ValidationCompletionSHA256: completion,
				CompletedAt:                completedAt,
			},
		},
		ValidationSessions: []ValidationSession{{
			ID: "session-current", CandidateID: candidateID, CommitSHA: commit,
			TreeSHA: tree, CompletionSHA256: completion,
		}},
		Evidence: &deliveryevidence.Bundle{
			CandidateReviewReceipts: []deliveryevidence.CandidateReviewReceipt{
				{
					Identity: "receipt-old-iteration", CandidateID: candidateID,
					Iteration: 1, CommitSHA: commit, TreeSHA: tree,
				},
				{
					Identity: "receipt-current-iteration", CandidateID: candidateID,
					Iteration: 2, CommitSHA: commit, TreeSHA: tree,
				},
				{
					Identity: "receipt-replaced-candidate", CandidateID: "candidate-old",
					Iteration: 3, CommitSHA: commit, TreeSHA: tree,
				},
			},
			ExhaustiveAssurance: []deliveryevidence.ExhaustiveAssuranceReceipt{{
				Identity: "exhaustive-receipt", CandidateID: candidateID,
				CommitSHA: commit, TreeSHA: tree, CompletedAt: completedAt,
			}},
		},
	}
	projection, err := BuildCompactRunProjection(outcome, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if got := projection.Assurance.RetainedReviewReceipts; !reflect.DeepEqual(
		got,
		[]RetainedReviewReceipt{{Identity: "receipt-current-iteration", Iteration: 2}},
	) {
		t.Fatalf("retained reviews=%#v", got)
	}
	wantArtifacts := []ReusedValidationArtifact{
		{
			Kind: "boundary", Identity: strings.Repeat("d", 64),
			Boundary: BoundarySecurity, SessionID: "session-current",
			ValidationCompletionSHA256: completion,
		},
		{
			Kind: "exhaustive", Identity: "exhaustive-receipt",
			SessionID: "session-current", ValidationCompletionSHA256: completion,
		},
	}
	if !reflect.DeepEqual(projection.Assurance.ReusedValidationArtifacts, wantArtifacts) {
		t.Fatalf("reused artifacts=%#v want %#v",
			projection.Assurance.ReusedValidationArtifacts, wantArtifacts)
	}
}

func TestCompactRunProjectionBoundsEveryPersistedInvalidationClass(t *testing.T) {
	classes := validationInvalidationClassOrder[:]
	invalidations := make([]ValidationInvalidation, 0, len(classes)+1)
	for index, class := range classes {
		invalidations = append(invalidations, ValidationInvalidation{
			SessionID: "session", CandidateID: "candidate", Class: class,
			ObservedAt: time.Date(2026, 7, 31, 12, index, 0, 0, time.UTC).Format(time.RFC3339Nano),
		})
	}
	invalidations = append(invalidations, ValidationInvalidation{
		SessionID: "replacement-session", CandidateID: "candidate",
		Class: ValidationInvalidationCandidate, ObservedAt: "2026-07-31T13:00:00Z",
	})
	invalidations = append(invalidations, ValidationInvalidation{
		SessionID: "stale-session", CandidateID: "candidate-old",
		Class: ValidationInvalidationWorkspace, ObservedAt: "2026-07-31T14:00:00Z",
	})
	projection, err := BuildCompactRunProjection(Outcome{
		Candidate:               &Candidate{ID: "candidate"},
		ValidationInvalidations: invalidations,
	}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	got := projection.Assurance.Invalidations
	if len(got) != len(classes) {
		t.Fatalf("invalidations=%#v", got)
	}
	for index, class := range classes {
		if got[index].Class != class {
			t.Fatalf("class[%d]=%q want %q", index, got[index].Class, class)
		}
	}
	if got[0].SessionID != "replacement-session" ||
		got[0].CandidateID != "candidate" {
		t.Fatalf("candidate replacement was not the retained persisted fact: %#v", got[0])
	}
	for _, invalidation := range got {
		if invalidation.SessionID == "stale-session" {
			t.Fatalf("stale candidate invalidation leaked: %#v", got)
		}
	}
	empty, err := BuildCompactRunProjection(Outcome{
		Candidate: &Candidate{ID: "candidate-with-no-invalidations"},
	}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Assurance.Invalidations) != 0 {
		t.Fatalf("missing evidence inferred an invalidation: %#v", empty.Assurance.Invalidations)
	}
}

func TestCompactRunProjectionExposesCurrentCandidateAssuranceProgress(t *testing.T) {
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	candidate := Candidate{
		ID: "candidate-current", CommitSHA: commit, TreeSHA: tree,
		RequiredReviews: []deliveryevidence.ReviewAxis{
			deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
		},
		ReviewIteration: 2,
		Reviews: []CandidateReview{
			{
				CandidateID: "candidate-current", Axis: deliveryevidence.ReviewStandards,
				Iteration: 1, CommitSHA: commit, TreeSHA: tree,
				Findings: []deliveryevidence.ReviewFinding{}, Completed: true,
			},
			{
				CandidateID: "candidate-current", Axis: deliveryevidence.ReviewStandards,
				Iteration: 2, CommitSHA: commit, TreeSHA: tree,
				Findings: []deliveryevidence.ReviewFinding{}, Completed: true,
			},
		},
		RequiredSpecialists: []SensitiveBoundary{BoundaryPublication, BoundarySecurity},
		SpecialistReviews: []SpecialistReview{{
			CandidateID: "candidate-current", Boundary: BoundarySecurity,
			Specialist: "security-specialist", Findings: []SpecialistFinding{}, Completed: true,
		}},
	}

	projection, err := BuildCompactRunProjection(Outcome{Candidate: &candidate}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	want := &CompactAssuranceProgress{
		CandidateReviewAxes: CompactReviewProgress{
			Completed: []deliveryevidence.ReviewAxis{deliveryevidence.ReviewStandards},
			Pending:   []deliveryevidence.ReviewAxis{deliveryevidence.ReviewSpec},
		},
		SpecialistBoundaries: &CompactSpecialistProgress{
			Completed: []CompactSpecialistBoundary{{
				Boundary: BoundarySecurity, Specialist: "security-specialist",
			}},
			Pending: []CompactSpecialistBoundary{{
				Boundary: BoundaryPublication, Specialist: "publication-specialist",
			}},
		},
	}
	if !reflect.DeepEqual(projection.Assurance.Progress, want) {
		t.Fatalf("assurance progress=%#v want %#v", projection.Assurance.Progress, want)
	}
}

func TestCompactRunProjectionDoesNotInventAssuranceBeforeCandidateRisk(t *testing.T) {
	projection, err := BuildCompactRunProjection(Outcome{
		State: StateWaiting, Reason: "qualification is approved; awaiting candidate development",
	}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if projection.Assurance.Progress != nil {
		t.Fatalf("qualification-only outcome invented assurance progress: %#v", projection.Assurance.Progress)
	}
}

type partialSpecialistReviewExecutorForProjection struct {
	incomplete SensitiveBoundary
}

func (f partialSpecialistReviewExecutorForProjection) ReviewSpecialist(
	_ context.Context,
	request SpecialistReviewRequest,
) (SpecialistReview, error) {
	return SpecialistReview{
		CandidateID: request.CandidateID, Boundary: request.Boundary,
		Specialist: request.Specialist, Findings: []SpecialistFinding{},
		Completed: request.Boundary != f.incomplete,
	}, nil
}

func TestCompactRunProjectionReflectsPersistedPartialAssurance(t *testing.T) {
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	module, _, _, reviewer, _ := assuranceFixture(t)
	reviewer.responses[deliveryevidence.ReviewSpec] = []CandidateReview{{
		Completed: false, Acceptance: []AcceptanceProof{},
	}}
	mustAdvance(t, module, request)
	partialCandidate := mustAdvance(t, module, request)
	if partialCandidate.Candidate == nil || len(partialCandidate.Candidate.Reviews) != 1 {
		t.Fatalf("partial candidate was not persisted: %#v", partialCandidate)
	}
	status, err := module.Status(context.Background(), StatusRequest{
		RepositoryPath: request.RepositoryPath, IssueNumber: request.IssueNumber,
	})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := BuildCompactRunProjection(status, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if got := projection.Assurance.Progress.CandidateReviewAxes; !reflect.DeepEqual(
		got,
		CompactReviewProgress{
			Completed: []deliveryevidence.ReviewAxis{deliveryevidence.ReviewStandards},
			Pending:   []deliveryevidence.ReviewAxis{deliveryevidence.ReviewSpec},
		},
	) {
		t.Fatalf("persisted partial candidate progress=%#v", got)
	}

	module, _, _, _, _ = assuranceFixture(t)
	module.risk.(*fakeCandidateRiskObserver).effects = []EffectObservation{
		{Effect: EffectPublication, Evidence: "publishes an artifact", Complete: true},
		{Effect: EffectSecurity, Evidence: "changes credential handling", Complete: true},
	}
	module.specialist = partialSpecialistReviewExecutorForProjection{incomplete: BoundarySecurity}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	partialSpecialist := mustAdvance(t, module, request)
	if partialSpecialist.Candidate == nil || len(partialSpecialist.Candidate.SpecialistReviews) != 1 {
		t.Fatalf("partial specialist review was not persisted: %#v", partialSpecialist)
	}
	status, err = module.Status(context.Background(), StatusRequest{
		RepositoryPath: request.RepositoryPath, IssueNumber: request.IssueNumber,
	})
	if err != nil {
		t.Fatal(err)
	}
	projection, err = BuildCompactRunProjection(status, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if got := projection.Assurance.Progress.SpecialistBoundaries; got == nil || !reflect.DeepEqual(
		*got,
		CompactSpecialistProgress{
			Completed: []CompactSpecialistBoundary{{
				Boundary: BoundaryPublication, Specialist: "publication-specialist",
			}},
			Pending: []CompactSpecialistBoundary{{
				Boundary: BoundarySecurity, Specialist: "security-specialist",
			}},
		},
	) {
		t.Fatalf("persisted partial specialist progress=%#v", got)
	}
}

type compactTimingFixture struct {
	phase    string
	to       State
	duration time.Duration
}

func compactProjectionTimings(start time.Time, values []compactTimingFixture) []Timing {
	timings := make([]Timing, 0, len(values))
	cursor := start
	for index, value := range values {
		completed := cursor.Add(value.duration)
		timings = append(timings, Timing{
			Sequence: index + 1, Phase: value.phase, To: value.to,
			StartedAt: cursor.Format(time.RFC3339Nano), CompletedAt: completed.Format(time.RFC3339Nano),
		})
		cursor = completed
	}
	return timings
}
