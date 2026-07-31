package issuedelivery

import (
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
			Kind: "boundary", Boundary: BoundarySecurity, SessionID: "session-current",
			ValidationCompletionSHA256: completion,
		},
		{
			Kind: "exhaustive", SessionID: "session-current",
			ValidationCompletionSHA256: completion, ReceiptIdentity: "exhaustive-receipt",
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
		SessionID: "replacement-session", CandidateID: "replacement-candidate",
		Class: ValidationInvalidationCandidate, ObservedAt: "2026-07-31T13:00:00Z",
	})
	projection, err := BuildCompactRunProjection(Outcome{
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
		got[0].CandidateID != "replacement-candidate" {
		t.Fatalf("candidate replacement was not the retained persisted fact: %#v", got[0])
	}
	empty, err := BuildCompactRunProjection(Outcome{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Assurance.Invalidations) != 0 {
		t.Fatalf("missing evidence inferred an invalidation: %#v", empty.Assurance.Invalidations)
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
