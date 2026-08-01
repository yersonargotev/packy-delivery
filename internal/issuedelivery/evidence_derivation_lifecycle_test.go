package issuedelivery

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

type lifecycleImpactAuthority struct{}

func (lifecycleImpactAuthority) AuthenticatedImpactPrincipal() deliveryevidence.ImpactAuthor {
	return deliveryevidence.ImpactAuthor{
		Kind: deliveryevidence.ImpactAuthorAuthorizedHuman, Identity: "maintainer",
	}
}

func (lifecycleImpactAuthority) AuthorizedImpactAuthor(author deliveryevidence.ImpactAuthor) bool {
	return author.Kind == deliveryevidence.ImpactAuthorAuthorizedHuman &&
		(author.Identity == "maintainer" || author.Identity == "independent-reviewer")
}

func (lifecycleImpactAuthority) IndependentImpactConfirmer(author, confirmer deliveryevidence.ImpactAuthor) bool {
	return author.Identity == "maintainer" && confirmer.Identity == "independent-reviewer"
}

func TestAdvanceAdmitsImpactConfirmedDeltaReviewWithoutCopyingParentEvidence(t *testing.T) {
	module, git, _, reviewer, _ := assuranceFixture(t)
	module.impactAuthority = lifecycleImpactAuthority{}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}

	for range 4 {
		mustAdvance(t, module, request)
	}
	parent := *mustAdvance(t, module, request).Candidate
	parentReviewCalls := map[deliveryevidence.ReviewAxis]int{
		deliveryevidence.ReviewStandards: reviewer.calls[deliveryevidence.ReviewStandards],
		deliveryevidence.ReviewSpec:      reviewer.calls[deliveryevidence.ReviewSpec],
	}

	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
	derivedOutcome := mustAdvance(t, module, request)
	derived := *derivedOutcome.Candidate
	assessment := lifecycleImpactAssessment(t, derivedOutcome, parent, derived,
		[]deliveryevidence.EvidenceChange{{
			Class: deliveryevidence.ChangeNonBehavioral, Rationale: "format-only repair",
		}})

	pending := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357, ImpactAssessment: &assessment,
	})
	if pending.ImpactConfirmation == nil ||
		pending.ImpactConfirmation.AssessmentID != assessment.ID ||
		pending.ImpactConfirmation.ParentCandidateID != parent.ID ||
		pending.ImpactConfirmation.DerivedCandidateID != derived.ID {
		t.Fatalf("impact confirmation packet = %#v", pending.ImpactConfirmation)
	}
	confirmation, err := deliveryevidence.NewImpactConfirmation(deliveryevidence.ImpactConfirmationInput{
		AssessmentID: assessment.ID, ParentCandidateID: parent.ID, DerivedCandidateID: derived.ID,
		Confirmer: deliveryevidence.ImpactAuthor{
			Kind: deliveryevidence.ImpactAuthorAuthorizedHuman, Identity: "independent-reviewer",
		},
		Decision:  deliveryevidence.ImpactConfirmationAccepted,
		Rationale: "the exact non-behavioral impact is complete", Completed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357, ImpactConfirmationResponse: &confirmation,
	})
	if accepted.Candidate.Derivation == nil ||
		accepted.Candidate.Derivation.ParentCandidateID != parent.ID ||
		accepted.Candidate.Derivation.Assessment.ID != assessment.ID ||
		accepted.Candidate.Derivation.Confirmation.ID != confirmation.ID {
		t.Fatalf("candidate derivation = %#v", accepted.Candidate.Derivation)
	}
	if got := accepted.Candidate.Derivation.RetainedReviewReceipts; len(got) != 1 ||
		got[0].Axis != deliveryevidence.ReviewSpec || got[0].ParentReceiptIdentity == "" ||
		got[0].AssessmentID != assessment.ID || got[0].ConfirmationID != confirmation.ID {
		t.Fatalf("retained review receipts = %#v", got)
	}
	for _, obligation := range accepted.Candidate.Derivation.RetainedReviewReceipts[0].Obligations {
		if obligation.Phase != deliveryevidence.AssuranceCandidateReview {
			t.Fatalf("Spec derivation receipt claimed non-review obligation: %#v", obligation)
		}
	}
	if len(accepted.Candidate.Reviews) != 0 {
		t.Fatalf("parent review content was copied onto derived candidate: %#v", accepted.Candidate.Reviews)
	}
	packets, err := module.ReviewPackets(context.Background(), ReviewPacketRequest{
		RepositoryPath: "/repo", IssueNumber: 357, Kind: ReviewPacketCandidate,
		Axis: deliveryevidence.ReviewStandards,
	})
	if err != nil || len(packets.Packets) != 1 {
		t.Fatalf("delta review packets = %#v, %v", packets, err)
	}
	delta := packets.Packets[0].Derivation
	if delta == nil || delta.ParentCandidateID != parent.ID ||
		delta.AssessmentID != assessment.ID || delta.ConfirmationID != confirmation.ID ||
		len(delta.ParentEvidenceReceipts) != 1 || len(delta.RetainedObligations) == 0 ||
		len(delta.ChangedObligations) != 0 || !reflect.DeepEqual(delta.ExactDelta, assessment.Changes) {
		t.Fatalf("delta packet derivation = %#v", delta)
	}

	completedDelta := mustAdvance(t, module, request)
	if reviewer.calls[deliveryevidence.ReviewStandards] != parentReviewCalls[deliveryevidence.ReviewStandards]+1 ||
		reviewer.calls[deliveryevidence.ReviewSpec] != parentReviewCalls[deliveryevidence.ReviewSpec] {
		t.Fatalf("review calls after delta = %#v parent=%#v", reviewer.calls, parentReviewCalls)
	}
	foundDeltaReceipt := false
	for _, receipt := range completedDelta.Evidence.CandidateReviewReceipts {
		if receipt.CandidateID == derived.ID &&
			reflect.DeepEqual(receipt.Axes, []deliveryevidence.ReviewAxis{deliveryevidence.ReviewStandards}) {
			foundDeltaReceipt = true
		}
	}
	if !foundDeltaReceipt {
		t.Fatal("completed Standards delta lacks a canonical current-candidate receipt")
	}
	progress, err := BuildCompactRunProjection(completedDelta, module.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(progress.Assurance.Progress.CandidateReviewAxes.Retained,
		[]deliveryevidence.ReviewAxis{deliveryevidence.ReviewSpec}) ||
		!reflect.DeepEqual(progress.Assurance.Progress.CandidateReviewAxes.CompletedDelta,
			[]deliveryevidence.ReviewAxis{deliveryevidence.ReviewStandards}) ||
		len(progress.Assurance.Progress.CandidateReviewAxes.Pending) != 0 {
		t.Fatalf("derived assurance progress = %#v", progress.Assurance.Progress)
	}
	validated := mustAdvance(t, module, request)
	if validated.State == StateBlocked {
		t.Fatalf("confirmed retained Spec assurance did not reach fresh validation: %#v", validated)
	}
	ready := mustAdvance(t, module, request)
	if ready.State != StateWaiting || ready.LocalReadiness == nil {
		t.Fatalf("safe delta did not reach exact local readiness: %#v", ready)
	}
}

func TestAdvanceProtectedOrAmbiguousDerivationFallsBackToCompleteReviews(t *testing.T) {
	classes := []deliveryevidence.EvidenceChangeClass{
		deliveryevidence.ChangeBehavior,
		deliveryevidence.ChangeContract,
		deliveryevidence.ChangeScope,
		deliveryevidence.ChangeArchitecture,
		deliveryevidence.ChangeSecurity,
		deliveryevidence.ChangeRiskProfile,
		deliveryevidence.ChangeAmbiguous,
	}
	for _, class := range classes {
		t.Run(string(class), func(t *testing.T) {
			module, git, _, reviewer, _ := assuranceFixture(t)
			module.impactAuthority = lifecycleImpactAuthority{}
			request := Request{RepositoryPath: "/repo", IssueNumber: 357}
			for range 4 {
				mustAdvance(t, module, request)
			}
			parent := *mustAdvance(t, module, request).Candidate
			before := map[deliveryevidence.ReviewAxis]int{
				deliveryevidence.ReviewStandards: reviewer.calls[deliveryevidence.ReviewStandards],
				deliveryevidence.ReviewSpec:      reviewer.calls[deliveryevidence.ReviewSpec],
			}
			git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
			derivedOutcome := mustAdvance(t, module, request)
			assessment := lifecycleImpactAssessment(t, derivedOutcome, parent, *derivedOutcome.Candidate,
				[]deliveryevidence.EvidenceChange{{Class: class, Rationale: "protected change"}})
			admitted := mustAdvance(t, module, Request{
				RepositoryPath: "/repo", IssueNumber: 357, ImpactAssessment: &assessment,
			})
			if admitted.ImpactConfirmation != nil || admitted.Candidate.Derivation == nil ||
				!reflect.DeepEqual(admitted.Candidate.Derivation.Decision.FullReviewAxes,
					[]deliveryevidence.ReviewAxis{deliveryevidence.ReviewSpec, deliveryevidence.ReviewStandards}) {
				t.Fatalf("protected derivation decision = %#v", admitted.Candidate.Derivation)
			}
			mustAdvance(t, module, request)
			if reviewer.calls[deliveryevidence.ReviewStandards] != before[deliveryevidence.ReviewStandards]+1 ||
				reviewer.calls[deliveryevidence.ReviewSpec] != before[deliveryevidence.ReviewSpec]+1 {
				t.Fatalf("protected change %q review calls=%#v before=%#v", class, reviewer.calls, before)
			}
		})
	}
}

func TestAdvanceImpactConfirmationReplayIsIdempotentAndConflictFailsClosed(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	module.impactAuthority = lifecycleImpactAuthority{}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 4 {
		mustAdvance(t, module, request)
	}
	parent := *mustAdvance(t, module, request).Candidate
	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
	derived := mustAdvance(t, module, request)
	assessment := lifecycleImpactAssessment(t, derived, parent, *derived.Candidate,
		[]deliveryevidence.EvidenceChange{{Class: deliveryevidence.ChangeNonBehavioral, Rationale: "format-only"}})
	mustAdvance(t, module, Request{RepositoryPath: "/repo", IssueNumber: 357, ImpactAssessment: &assessment})
	confirmation, err := deliveryevidence.NewImpactConfirmation(deliveryevidence.ImpactConfirmationInput{
		AssessmentID: assessment.ID, ParentCandidateID: parent.ID, DerivedCandidateID: derived.Candidate.ID,
		Confirmer: deliveryevidence.ImpactAuthor{Kind: deliveryevidence.ImpactAuthorAuthorizedHuman, Identity: "independent-reviewer"},
		Decision:  deliveryevidence.ImpactConfirmationAccepted, Rationale: "confirmed", Completed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := mustAdvance(t, module, Request{RepositoryPath: "/repo", IssueNumber: 357, ImpactConfirmationResponse: &confirmation})
	replayed := mustAdvance(t, module, Request{RepositoryPath: "/repo", IssueNumber: 357, ImpactConfirmationResponse: &confirmation})
	if !reflect.DeepEqual(first.Candidate.Derivation.RetainedReviewReceipts, replayed.Candidate.Derivation.RetainedReviewReceipts) {
		t.Fatal("exact confirmation replay duplicated derivation receipts")
	}
	conflict := confirmation
	conflict.Rationale = "different bytes under the old identity"
	if _, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 357, ImpactConfirmationResponse: &conflict}); err == nil {
		t.Fatal("conflicting impact confirmation replay succeeded")
	}
}

func TestAdvanceChangedAcceptanceMeaningRequiresFreshSpecProof(t *testing.T) {
	module, git, _, reviewer, _ := assuranceFixture(t)
	module.impactAuthority = lifecycleImpactAuthority{}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 4 {
		mustAdvance(t, module, request)
	}
	parent := *mustAdvance(t, module, request).Candidate
	before := map[deliveryevidence.ReviewAxis]int{
		deliveryevidence.ReviewStandards: reviewer.calls[deliveryevidence.ReviewStandards],
		deliveryevidence.ReviewSpec:      reviewer.calls[deliveryevidence.ReviewSpec],
	}
	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
	derived := mustAdvance(t, module, request)
	assessment := lifecycleImpactAssessment(t, derived, parent, *derived.Candidate,
		[]deliveryevidence.EvidenceChange{{
			Class:     deliveryevidence.ChangeAcceptanceMeaning,
			Rationale: "criterion semantics changed",
		}})
	mustAdvance(t, module, Request{RepositoryPath: "/repo", IssueNumber: 357, ImpactAssessment: &assessment})
	confirmation, err := deliveryevidence.NewImpactConfirmation(deliveryevidence.ImpactConfirmationInput{
		AssessmentID: assessment.ID, ParentCandidateID: parent.ID, DerivedCandidateID: derived.Candidate.ID,
		Confirmer: deliveryevidence.ImpactAuthor{Kind: deliveryevidence.ImpactAuthorAuthorizedHuman, Identity: "independent-reviewer"},
		Decision:  deliveryevidence.ImpactConfirmationAccepted,
		Rationale: "confirmed changed acceptance meaning", Completed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	confirmed := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357, ImpactConfirmationResponse: &confirmation,
	})
	if len(confirmed.Candidate.Derivation.RetainedReviewReceipts) != 0 ||
		!containsAxis(confirmed.Candidate.Derivation.Decision.FullReviewAxes, deliveryevidence.ReviewSpec) {
		t.Fatalf("changed acceptance derivation = %#v", confirmed.Candidate.Derivation)
	}
	reviewed := mustAdvance(t, module, request)
	if reviewer.calls[deliveryevidence.ReviewStandards] != before[deliveryevidence.ReviewStandards]+1 ||
		reviewer.calls[deliveryevidence.ReviewSpec] != before[deliveryevidence.ReviewSpec]+1 ||
		len(reviewed.Candidate.Acceptance) != len(reviewed.Evidence.AcceptanceMatrix) {
		t.Fatalf("fresh acceptance review calls=%#v candidate=%#v", reviewer.calls, reviewed.Candidate)
	}
}

func TestAdvanceInvalidImpactAssessmentClassesTakeFreshReviewPath(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*deliveryevidence.EvidenceImpactAssessmentInput)
	}{
		{name: "incomplete", mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
			input.Complete = false
		}},
		{name: "authority mismatch", mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
			input.ParentAuthority.SHA256 = strings.Repeat("f", 64)
		}},
		{name: "caller spoofs another authorized principal", mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
			input.Author.Identity = "independent-reviewer"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			module, git, _, reviewer, _ := assuranceFixture(t)
			module.impactAuthority = lifecycleImpactAuthority{}
			request := Request{RepositoryPath: "/repo", IssueNumber: 357}
			for range 4 {
				mustAdvance(t, module, request)
			}
			parent := *mustAdvance(t, module, request).Candidate
			before := map[deliveryevidence.ReviewAxis]int{
				deliveryevidence.ReviewStandards: reviewer.calls[deliveryevidence.ReviewStandards],
				deliveryevidence.ReviewSpec:      reviewer.calls[deliveryevidence.ReviewSpec],
			}
			git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
			derived := mustAdvance(t, module, request)
			assessment := lifecycleImpactAssessment(t, derived, parent, *derived.Candidate,
				[]deliveryevidence.EvidenceChange{{Class: deliveryevidence.ChangeNonBehavioral, Rationale: "claimed safe delta"}})
			input := assessment.EvidenceImpactAssessmentInput
			test.mutate(&input)
			assessment, err := deliveryevidence.NewEvidenceImpactAssessment(input)
			if err != nil {
				t.Fatal(err)
			}
			admitted := mustAdvance(t, module, Request{
				RepositoryPath: "/repo", IssueNumber: 357, ImpactAssessment: &assessment,
			})
			if admitted.ImpactConfirmation != nil || len(retainedReviewAxes(admitted.Candidate)) != 0 {
				t.Fatalf("invalid assessment retained authority: %#v", admitted.Candidate.Derivation)
			}
			mustAdvance(t, module, request)
			if reviewer.calls[deliveryevidence.ReviewStandards] != before[deliveryevidence.ReviewStandards]+1 ||
				reviewer.calls[deliveryevidence.ReviewSpec] != before[deliveryevidence.ReviewSpec]+1 {
				t.Fatalf("invalid assessment did not take full review path: %#v", reviewer.calls)
			}
		})
	}
}

func TestAdvanceRejectedImpactConfirmationClearsPauseAndFallsBack(t *testing.T) {
	module, git, _, reviewer, _ := assuranceFixture(t)
	module.impactAuthority = lifecycleImpactAuthority{}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 4 {
		mustAdvance(t, module, request)
	}
	parent := *mustAdvance(t, module, request).Candidate
	before := map[deliveryevidence.ReviewAxis]int{
		deliveryevidence.ReviewStandards: reviewer.calls[deliveryevidence.ReviewStandards],
		deliveryevidence.ReviewSpec:      reviewer.calls[deliveryevidence.ReviewSpec],
	}
	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
	derived := mustAdvance(t, module, request)
	assessment := lifecycleImpactAssessment(t, derived, parent, *derived.Candidate,
		[]deliveryevidence.EvidenceChange{{Class: deliveryevidence.ChangeNonBehavioral, Rationale: "format-only"}})
	mustAdvance(t, module, Request{RepositoryPath: "/repo", IssueNumber: 357, ImpactAssessment: &assessment})
	rejected, err := deliveryevidence.NewImpactConfirmation(deliveryevidence.ImpactConfirmationInput{
		AssessmentID: assessment.ID, ParentCandidateID: parent.ID, DerivedCandidateID: derived.Candidate.ID,
		Confirmer: deliveryevidence.ImpactAuthor{Kind: deliveryevidence.ImpactAuthorAuthorizedHuman, Identity: "independent-reviewer"},
		Decision:  deliveryevidence.ImpactConfirmationRejected,
		Rationale: "impact is not safely bounded", Completed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	fallback := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357, ImpactConfirmationResponse: &rejected,
	})
	if fallback.ImpactConfirmation != nil || fallback.Candidate.Derivation.FallbackReason == "" ||
		len(fallback.Candidate.Derivation.RetainedReviewReceipts) != 0 {
		t.Fatalf("rejected confirmation did not fail closed: %#v", fallback.Candidate.Derivation)
	}
	mustAdvance(t, module, request)
	if reviewer.calls[deliveryevidence.ReviewStandards] != before[deliveryevidence.ReviewStandards]+1 ||
		reviewer.calls[deliveryevidence.ReviewSpec] != before[deliveryevidence.ReviewSpec]+1 {
		t.Fatalf("rejected confirmation did not take full reviews: %#v", reviewer.calls)
	}
}

func TestAdvanceSafeDeltaRetainsExactSpecialistButRefreshesBoundaryProof(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	module.impactAuthority = lifecycleImpactAuthority{}
	module.risk.(*fakeCandidateRiskObserver).effects = []EffectObservation{{
		Effect: EffectSecurity, Evidence: "security boundary remains unchanged", Complete: true,
	}}
	specialist := &fakeSpecialistReviewExecutor{}
	boundary := &fakeBoundaryValidationExecutor{}
	module.specialist, module.boundary = specialist, boundary
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 6 {
		mustAdvance(t, module, request)
	}
	parent := *mustAdvance(t, module, request).Candidate
	if len(specialist.calls) != 1 || len(boundary.calls) != 1 {
		t.Fatalf("parent specialist assurance calls=%v boundary=%v", specialist.calls, boundary.calls)
	}
	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
	derived := mustAdvance(t, module, request)
	assessment := lifecycleImpactAssessment(t, derived, parent, *derived.Candidate,
		[]deliveryevidence.EvidenceChange{{Class: deliveryevidence.ChangeNonBehavioral, Rationale: "format-only"}})
	mustAdvance(t, module, Request{RepositoryPath: "/repo", IssueNumber: 357, ImpactAssessment: &assessment})
	confirmation, err := deliveryevidence.NewImpactConfirmation(deliveryevidence.ImpactConfirmationInput{
		AssessmentID: assessment.ID, ParentCandidateID: parent.ID, DerivedCandidateID: derived.Candidate.ID,
		Confirmer: deliveryevidence.ImpactAuthor{Kind: deliveryevidence.ImpactAuthorAuthorizedHuman, Identity: "independent-reviewer"},
		Decision:  deliveryevidence.ImpactConfirmationAccepted, Rationale: "boundary is unaffected", Completed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	confirmed := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357, ImpactConfirmationResponse: &confirmation,
	})
	if !containsBoundary(retainedSpecialistBoundaries(confirmed.Candidate), BoundarySecurity) {
		t.Fatalf("specialist derivation receipts=%#v", confirmed.Candidate.Derivation.RetainedReviewReceipts)
	}
	for range 4 {
		mustAdvance(t, module, request)
	}
	if len(specialist.calls) != 1 || len(boundary.calls) != 2 {
		t.Fatalf("derived specialist assurance calls=%v boundary=%v", specialist.calls, boundary.calls)
	}
}

func lifecycleImpactAssessment(
	t *testing.T,
	outcome Outcome,
	parent Candidate,
	derived Candidate,
	changes []deliveryevidence.EvidenceChange,
) deliveryevidence.EvidenceImpactAssessment {
	t.Helper()
	obligations := make([]deliveryevidence.AcceptanceObligationImpact, 0)
	for _, row := range outcome.Evidence.AcceptanceMatrix {
		for _, obligation := range row.Obligations {
			identity := deliveryevidence.EvidenceObligationIdentity{
				CriterionID: row.Identity, Kind: obligation.Kind, Phase: obligation.Phase,
			}
			obligations = append(obligations, deliveryevidence.AcceptanceObligationImpact{
				Parent: identity, Derived: identity, Disposition: deliveryevidence.ImpactUnaffected,
				Rationale: "criterion meaning and evidence ownership are unchanged",
			})
		}
	}
	digest, err := acceptanceObligationSetDigest(outcome.Evidence.AcceptanceMatrix)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := deliveryevidence.NewEvidenceImpactAssessment(deliveryevidence.EvidenceImpactAssessmentInput{
		Author: deliveryevidence.ImpactAuthor{
			Kind: deliveryevidence.ImpactAuthorAuthorizedHuman, Identity: "maintainer",
		},
		ParentAuthority: deliveryevidence.EvidenceAuthorityIdentity{
			RunSchema: deliveryevidence.EvidenceDerivationRunSchemaV2,
			RunID:     outcome.RunID, SHA256: outcome.Observations.AuthoritySHA256,
		},
		DerivedAuthority: deliveryevidence.EvidenceAuthorityIdentity{
			RunSchema: deliveryevidence.EvidenceDerivationRunSchemaV2,
			RunID:     outcome.RunID, SHA256: outcome.Observations.AuthoritySHA256,
		},
		ParentCandidate:        lifecycleEvidenceCandidate(parent),
		DerivedCandidate:       lifecycleEvidenceCandidate(derived),
		ParentAcceptanceSHA256: digest, DerivedAcceptanceSHA256: digest,
		ParentObligationCount: len(obligations), DerivedObligationCount: len(obligations),
		Obligations: obligations, Changes: changes, Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return assessment
}

func lifecycleEvidenceCandidate(candidate Candidate) deliveryevidence.EvidenceCandidateIdentity {
	boundaries := make([]deliveryevidence.SensitiveBoundary, len(candidate.Boundaries))
	for index, boundary := range candidate.Boundaries {
		boundaries[index] = deliveryevidence.SensitiveBoundary(boundary)
	}
	return deliveryevidence.EvidenceCandidateIdentity{
		ID: candidate.ID, BaseSHA: candidate.BaseSHA, CommitSHA: candidate.CommitSHA,
		TreeSHA: candidate.TreeSHA, ReviewGeneration: currentReviewIteration(&candidate),
		RiskProfile:         candidate.Profile,
		RequiredReviewAxes:  append([]deliveryevidence.ReviewAxis(nil), candidate.RequiredReviews...),
		SensitiveBoundaries: boundaries,
	}
}
