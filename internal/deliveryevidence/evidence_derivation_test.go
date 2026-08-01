package deliveryevidence_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func TestEvidenceImpactAssessmentMakesSafeRetentionExplicit(t *testing.T) {
	assessment, err := deliveryevidence.NewEvidenceImpactAssessment(safeImpactInput())
	if err != nil {
		t.Fatalf("compile safe impact assessment: %v", err)
	}

	decision, err := deliveryevidence.EvaluateEvidenceImpactAssessment(testImpactAuthority{}, assessment)
	if err != nil {
		t.Fatalf("evaluate safe impact assessment: %v", err)
	}
	if _, err := deliveryevidence.EvaluateEvidenceImpactAssessment(
		testImpactAuthority{denyAll: true}, assessment,
	); err == nil {
		t.Fatal("untrusted impact author received a retention decision")
	}
	if len(assessment.ID) != 64 || decision.AssessmentID != assessment.ID {
		t.Fatalf("assessment identity is not canonical: assessment=%q decision=%q", assessment.ID, decision.AssessmentID)
	}
	if !decision.IndependentConfirmationRequired || decision.ExhaustiveValidationRequired {
		t.Fatalf("safe decision has wrong gates: %#v", decision)
	}
	if !reflect.DeepEqual(decision.RetainableReviewAxes, []deliveryevidence.ReviewAxis{
		deliveryevidence.ReviewSpec,
		deliveryevidence.ReviewStandards,
	}) {
		t.Fatalf("retainable review axes = %#v", decision.RetainableReviewAxes)
	}
	if !reflect.DeepEqual(decision.DeltaReviewAxes, []deliveryevidence.ReviewAxis{
		deliveryevidence.ReviewStandards,
	}) {
		t.Fatalf("delta review axes = %#v", decision.DeltaReviewAxes)
	}
	if !reflect.DeepEqual(decision.RetainableSpecialistBoundaries, []deliveryevidence.SensitiveBoundary{
		deliveryevidence.BoundaryInstallation,
	}) {
		t.Fatalf("retainable specialist boundaries = %#v", decision.RetainableSpecialistBoundaries)
	}
	if !reflect.DeepEqual(decision.RetainableBoundaryValidations, []deliveryevidence.SensitiveBoundary{
		deliveryevidence.BoundaryInstallation,
	}) {
		t.Fatalf("retainable boundary validations = %#v", decision.RetainableBoundaryValidations)
	}

	raw, err := json.Marshal(assessment)
	if err != nil {
		t.Fatalf("marshal impact assessment: %v", err)
	}
	var replayed deliveryevidence.EvidenceImpactAssessment
	if err := json.Unmarshal(raw, &replayed); err != nil {
		t.Fatalf("unmarshal impact assessment: %v", err)
	}
	replayedDecision, err := deliveryevidence.EvaluateEvidenceImpactAssessment(testImpactAuthority{}, replayed)
	if err != nil {
		t.Fatalf("replay impact assessment: %v", err)
	}
	if !reflect.DeepEqual(replayedDecision, decision) {
		t.Fatalf("replay decision changed:\n got %#v\nwant %#v", replayedDecision, decision)
	}
}

func TestNonBehavioralTreeDeltaRetainsReviewButRequiresFreshValidation(t *testing.T) {
	input := safeImpactInput()
	input.DerivedCandidate.TreeSHA = strings.Repeat("8", 40)
	input.Changes[0].Rationale = "explanatory documentation changed without changing authority or acceptance meaning"
	assessment, err := deliveryevidence.NewEvidenceImpactAssessment(input)
	if err != nil {
		t.Fatalf("compile non-behavioral tree delta: %v", err)
	}
	decision, err := deliveryevidence.EvaluateEvidenceImpactAssessment(testImpactAuthority{}, assessment)
	if err != nil {
		t.Fatalf("evaluate non-behavioral tree delta: %v", err)
	}
	if !decision.ExhaustiveValidationRequired ||
		len(decision.FullReviewAxes) != 0 ||
		len(decision.FullSpecialistBoundaries) != 0 ||
		!reflect.DeepEqual(decision.FullBoundaryValidations, []deliveryevidence.SensitiveBoundary{
			deliveryevidence.BoundaryInstallation,
		}) ||
		!hasEvidenceInvalidation(decision.Invalidations, deliveryevidence.ChangeTree) {
		t.Fatalf("non-behavioral tree delta decision = %#v", decision)
	}
}

func TestEvidenceImpactAssessmentForcesMandatoryInvalidation(t *testing.T) {
	allAxes := []deliveryevidence.ReviewAxis{
		deliveryevidence.ReviewSpec,
		deliveryevidence.ReviewStandards,
	}
	tests := []struct {
		name            string
		mutate          func(*deliveryevidence.EvidenceImpactAssessmentInput)
		fullAxes        []deliveryevidence.ReviewAxis
		fullSpecialists []deliveryevidence.SensitiveBoundary
		fullBoundaries  []deliveryevidence.SensitiveBoundary
		exhaustive      bool
	}{
		{
			name: "authority",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.DerivedAuthority.SHA256 = strings.Repeat("b", 64)
				input.Changes = protectedChange(deliveryevidence.ChangeAuthority)
			},
			fullAxes: allAxes, fullSpecialists: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, fullBoundaries: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, exhaustive: true,
		},
		{
			name: "behavior",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.DerivedCandidate.TreeSHA = strings.Repeat("4", 40)
				input.Changes = protectedChange(deliveryevidence.ChangeBehavior)
			},
			fullAxes: allAxes, fullSpecialists: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, fullBoundaries: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, exhaustive: true,
		},
		{
			name: "contract scope architecture or security",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.Changes = []deliveryevidence.EvidenceChange{
					{Class: deliveryevidence.ChangeContract, Rationale: "public contract changed"},
					{Class: deliveryevidence.ChangeScope, Rationale: "authority scope changed"},
					{Class: deliveryevidence.ChangeArchitecture, Rationale: "architectural seam changed"},
					{Class: deliveryevidence.ChangeSecurity, Rationale: "security posture changed"},
				}
			},
			fullAxes: allAxes, fullSpecialists: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, fullBoundaries: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, exhaustive: true,
		},
		{
			name: "acceptance meaning",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.DerivedAcceptanceSHA256 = strings.Repeat("d", 64)
				input.Obligations[0].Disposition = deliveryevidence.ImpactChanged
				input.Obligations[0].Rationale = "the positive obligation now has different meaning"
				input.Changes = protectedChange(deliveryevidence.ChangeAcceptanceMeaning)
			},
			fullAxes: []deliveryevidence.ReviewAxis{deliveryevidence.ReviewSpec}, fullSpecialists: []deliveryevidence.SensitiveBoundary{}, fullBoundaries: []deliveryevidence.SensitiveBoundary{}, exhaustive: true,
		},
		{
			name: "partial acceptance impact",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.DerivedObligationCount = 2
			},
			fullAxes: allAxes, fullSpecialists: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, fullBoundaries: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, exhaustive: true,
		},
		{
			name: "risk profile",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.DerivedCandidate.RiskProfile = deliveryevidence.RiskStandard
				input.Changes = protectedChange(deliveryevidence.ChangeRiskProfile)
			},
			fullAxes: allAxes, fullSpecialists: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, fullBoundaries: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, exhaustive: true,
		},
		{
			name: "sensitive boundary",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.DerivedCandidate.SensitiveBoundaries = append(
					input.DerivedCandidate.SensitiveBoundaries,
					deliveryevidence.BoundarySecurity,
				)
				input.Changes = []deliveryevidence.EvidenceChange{{
					Class: deliveryevidence.ChangeSensitiveBoundary, Rationale: "security boundary introduced",
					Boundaries: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundarySecurity},
				}}
			},
			fullAxes: []deliveryevidence.ReviewAxis{}, fullSpecialists: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundarySecurity}, fullBoundaries: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundarySecurity}, exhaustive: true,
		},
		{
			name: "validation conditions",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.Changes = []deliveryevidence.EvidenceChange{
					{Class: deliveryevidence.ChangeValidator, Rationale: "validator changed"},
					{Class: deliveryevidence.ChangeRequiredCommand, Rationale: "required command changed"},
					{Class: deliveryevidence.ChangeSandbox, Rationale: "sandbox roots changed"},
					{Class: deliveryevidence.ChangeInstrumentation, Rationale: "instrumentation changed"},
					{Class: deliveryevidence.ChangeExpiry, Rationale: "validator expiry changed"},
					{Class: deliveryevidence.ChangeWorkspaceState, Rationale: "workspace observation changed"},
				}
			},
			fullAxes: []deliveryevidence.ReviewAxis{}, fullSpecialists: []deliveryevidence.SensitiveBoundary{}, fullBoundaries: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, exhaustive: true,
		},
		{
			name: "ambiguity",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.Complete = false
				input.Changes = protectedChange(deliveryevidence.ChangeAmbiguous)
			},
			fullAxes: allAxes, fullSpecialists: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, fullBoundaries: []deliveryevidence.SensitiveBoundary{deliveryevidence.BoundaryInstallation}, exhaustive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := safeImpactInput()
			tt.mutate(&input)
			assessment, err := deliveryevidence.NewEvidenceImpactAssessment(input)
			if err != nil {
				t.Fatalf("compile protected impact assessment: %v", err)
			}
			decision, err := deliveryevidence.EvaluateEvidenceImpactAssessment(testImpactAuthority{}, assessment)
			if err != nil {
				t.Fatalf("evaluate protected impact assessment: %v", err)
			}
			if !reflect.DeepEqual(decision.FullReviewAxes, tt.fullAxes) ||
				!reflect.DeepEqual(decision.FullSpecialistBoundaries, tt.fullSpecialists) ||
				!reflect.DeepEqual(decision.FullBoundaryValidations, tt.fullBoundaries) ||
				decision.ExhaustiveValidationRequired != tt.exhaustive ||
				len(decision.Invalidations) == 0 {
				t.Fatalf("mandatory invalidation decision = %#v", decision)
			}
		})
	}
}

func TestImpactConfirmationMustBeIndependentAndExactlyBound(t *testing.T) {
	assessment, err := deliveryevidence.NewEvidenceImpactAssessment(safeImpactInput())
	if err != nil {
		t.Fatalf("compile impact assessment: %v", err)
	}
	confirmation, err := deliveryevidence.NewImpactConfirmation(
		deliveryevidence.ImpactConfirmationInput{
			AssessmentID:       assessment.ID,
			ParentCandidateID:  assessment.ParentCandidate.ID,
			DerivedCandidateID: assessment.DerivedCandidate.ID,
			Confirmer: deliveryevidence.ImpactAuthor{
				Kind:     deliveryevidence.ImpactAuthorAuthorizedHuman,
				Identity: "reviewer:bob",
			},
			Decision:  deliveryevidence.ImpactConfirmationAccepted,
			Rationale: "the declared delta and every unaffected obligation were independently checked",
			Completed: true,
		},
	)
	if err != nil {
		t.Fatalf("compile impact confirmation: %v", err)
	}
	authority := testImpactAuthority{}
	if err := deliveryevidence.AdmitImpactConfirmation(authority, assessment, confirmation); err != nil {
		t.Fatalf("admit independent impact confirmation: %v", err)
	}
	if err := deliveryevidence.AdmitImpactConfirmation(
		testImpactAuthority{denyAll: true}, assessment, confirmation,
	); err == nil {
		t.Fatal("untrusted impact identities were admitted")
	}
	if err := deliveryevidence.AdmitImpactConfirmation(authority, assessment, confirmation, confirmation); err == nil {
		t.Fatal("duplicate accepted confirmations were admitted")
	}

	policyInput := safeImpactInput()
	policyInput.Author = deliveryevidence.ImpactAuthor{
		Kind:               deliveryevidence.ImpactAuthorRegisteredPolicy,
		Identity:           "policy:primary-name",
		RegistrationSHA256: strings.Repeat("e", 64),
	}
	policyAssessment, err := deliveryevidence.NewEvidenceImpactAssessment(policyInput)
	if err != nil {
		t.Fatalf("compile policy-authored assessment: %v", err)
	}
	policyAlias, err := deliveryevidence.NewImpactConfirmation(
		deliveryevidence.ImpactConfirmationInput{
			AssessmentID:       policyAssessment.ID,
			ParentCandidateID:  policyAssessment.ParentCandidate.ID,
			DerivedCandidateID: policyAssessment.DerivedCandidate.ID,
			Confirmer: deliveryevidence.ImpactAuthor{
				Kind:               deliveryevidence.ImpactAuthorRegisteredPolicy,
				Identity:           "policy:alias-name",
				RegistrationSHA256: policyAssessment.Author.RegistrationSHA256,
			},
			Decision: deliveryevidence.ImpactConfirmationAccepted, Rationale: "same policy under an alias",
			Completed: true,
		},
	)
	if err != nil {
		t.Fatalf("compile aliased policy confirmation: %v", err)
	}
	if err := deliveryevidence.AdmitImpactConfirmation(authority, policyAssessment, policyAlias); err == nil {
		t.Fatal("the assessment author's policy registration self-confirmed under an alias")
	}
	if len(confirmation.ID) != 64 {
		t.Fatalf("confirmation identity = %q", confirmation.ID)
	}

	tests := []struct {
		name   string
		mutate func(*deliveryevidence.ImpactConfirmation)
	}{
		{
			name: "same author",
			mutate: func(value *deliveryevidence.ImpactConfirmation) {
				value.Confirmer = assessment.Author
			},
		},
		{
			name: "stale assessment",
			mutate: func(value *deliveryevidence.ImpactConfirmation) {
				value.AssessmentID = strings.Repeat("f", 64)
			},
		},
		{
			name: "stale candidate",
			mutate: func(value *deliveryevidence.ImpactConfirmation) {
				value.DerivedCandidateID = "candidate-stale"
			},
		},
		{
			name: "incomplete",
			mutate: func(value *deliveryevidence.ImpactConfirmation) {
				value.Completed = false
			},
		},
		{
			name: "rejected",
			mutate: func(value *deliveryevidence.ImpactConfirmation) {
				value.Decision = deliveryevidence.ImpactConfirmationRejected
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalid := confirmation
			tt.mutate(&invalid)
			if err := deliveryevidence.AdmitImpactConfirmation(authority, assessment, invalid); err == nil {
				t.Fatal("invalid impact confirmation was admitted")
			}
		})
	}
}

func TestValidationCompatibilityRequiresTheCompleteRegisteredTuple(t *testing.T) {
	impact, err := deliveryevidence.NewEvidenceImpactAssessment(safeImpactInput())
	if err != nil {
		t.Fatalf("compile impact assessment: %v", err)
	}
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	confirmation := acceptedImpactConfirmation(t, impact)
	compatible := compatibleValidationInput(impact, confirmation.ID, now.Add(time.Hour))
	assessment, err := deliveryevidence.NewValidationCompatibilityAssessment(compatible)
	if err != nil {
		t.Fatalf("compile validation compatibility assessment: %v", err)
	}
	authority := testImpactAuthority{}
	registry := testValidationRegistry{artifact: assessment.Source, found: true}
	decision, err := deliveryevidence.EvaluateValidationCompatibility(
		authority, registry, impact, []deliveryevidence.ImpactConfirmation{confirmation}, assessment, now,
	)
	if err != nil {
		t.Fatalf("evaluate validation compatibility: %v", err)
	}
	if !decision.Eligible || len(decision.Invalidations) != 0 || len(assessment.ID) != 64 {
		t.Fatalf("compatible registered validation was refused: %#v", decision)
	}
	unregistered, err := deliveryevidence.EvaluateValidationCompatibility(
		authority, testValidationRegistry{}, impact,
		[]deliveryevidence.ImpactConfirmation{confirmation}, assessment, now,
	)
	if err != nil {
		t.Fatalf("evaluate relabeled unregistered artifact: %v", err)
	}
	if unregistered.Eligible ||
		!hasValidationInvalidation(unregistered.Invalidations, deliveryevidence.ValidationInvalidationSource) {
		t.Fatalf("relabeled unregistered artifact decision = %#v", unregistered)
	}
	for name, confirmations := range map[string][]deliveryevidence.ImpactConfirmation{
		"missing confirmation":   {},
		"duplicate confirmation": {confirmation, confirmation},
	} {
		t.Run(name, func(t *testing.T) {
			unconfirmed, err := deliveryevidence.EvaluateValidationCompatibility(
				authority, registry, impact, confirmations, assessment, now,
			)
			if err != nil {
				t.Fatalf("evaluate unconfirmed compatibility: %v", err)
			}
			if unconfirmed.Eligible ||
				!hasValidationInvalidation(unconfirmed.Invalidations, deliveryevidence.ValidationInvalidationImpact) {
				t.Fatalf("unconfirmed compatibility decision = %#v", unconfirmed)
			}
		})
	}

	tests := []struct {
		name   string
		mutate func(*deliveryevidence.ValidationCompatibilityAssessmentInput)
		class  deliveryevidence.ValidationInvalidationClass
	}{
		{
			name: "stale confirmation identity",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.ImpactConfirmationID = strings.Repeat("9", 64)
			},
			class: deliveryevidence.ValidationInvalidationImpact,
		},
		{
			name: "unregistered session schema",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Source.SessionSchema = "packy.validation-session/v99"
			},
			class: deliveryevidence.ValidationInvalidationSource,
		},
		{
			name: "arbitrary log",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Source.Kind = deliveryevidence.ValidationArtifactArbitraryLog
			},
			class: deliveryevidence.ValidationInvalidationSource,
		},
		{
			name: "unregistered manual execution",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Source.Kind = deliveryevidence.ValidationArtifactManualExecution
			},
			class: deliveryevidence.ValidationInvalidationSource,
		},
		{
			name: "stale parent candidate",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Source.Candidate.CommitSHA = strings.Repeat("9", 40)
			},
			class: deliveryevidence.ValidationInvalidationCandidate,
		},
		{
			name: "tree mismatch",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Source.Candidate.TreeSHA = strings.Repeat("9", 40)
			},
			class: deliveryevidence.ValidationInvalidationTree,
		},
		{
			name: "checkout identity",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Required.CheckoutSHA256 = strings.Repeat("9", 64)
			},
			class: deliveryevidence.ValidationInvalidationCheckout,
		},
		{
			name: "validator identity or digest",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Required.Environment.ValidatorSHA256 = strings.Repeat("8", 64)
			},
			class: deliveryevidence.ValidationInvalidationValidator,
		},
		{
			name: "required command",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Required.Environment.RequiredCommand = "./scripts/a-different-validator.sh"
			},
			class: deliveryevidence.ValidationInvalidationCommand,
		},
		{
			name: "sandbox roots",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Required.Environment.HomeRoot = "/sandbox/other-home"
			},
			class: deliveryevidence.ValidationInvalidationSandbox,
		},
		{
			name: "instrumentation",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Required.Environment.Instrumentation = []deliveryevidence.ValidationInstrumentation{
					deliveryevidence.InstrumentationPackyValidator,
				}
			},
			class: deliveryevidence.ValidationInvalidationInstrumentation,
		},
		{
			name: "boundary mismatch",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Required.Environment.CoveredBoundaries = []deliveryevidence.SensitiveBoundary{
					deliveryevidence.BoundaryInstallation,
					deliveryevidence.BoundarySecurity,
				}
			},
			class: deliveryevidence.ValidationInvalidationBoundaryRequirement,
		},
		{
			name: "expired",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Source.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
			},
			class: deliveryevidence.ValidationInvalidationExpiry,
		},
		{
			name: "expiry requirement drift",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Required.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339Nano)
			},
			class: deliveryevidence.ValidationInvalidationExpiry,
		},
		{
			name: "dirty workspace",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Source.WorkspaceClean = false
			},
			class: deliveryevidence.ValidationInvalidationWorkspace,
		},
		{
			name: "failed execution",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Source.Succeeded = false
			},
			class: deliveryevidence.ValidationInvalidationFailedExecution,
		},
		{
			name: "ambiguous completion",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Source.CompletionCount = 2
			},
			class: deliveryevidence.ValidationInvalidationCompletion,
		},
		{
			name: "different obligation",
			mutate: func(input *deliveryevidence.ValidationCompatibilityAssessmentInput) {
				input.Required.Obligation = deliveryevidence.ValidationObligationIdentity{
					Kind:     deliveryevidence.ValidationObligationBoundary,
					Boundary: deliveryevidence.BoundaryInstallation,
				}
			},
			class: deliveryevidence.ValidationInvalidationObligation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := compatibleValidationInput(impact, confirmation.ID, now.Add(time.Hour))
			tt.mutate(&input)
			candidate, err := deliveryevidence.NewValidationCompatibilityAssessment(input)
			if err != nil {
				t.Fatalf("compile incompatible tuple: %v", err)
			}
			decision, err := deliveryevidence.EvaluateValidationCompatibility(
				authority, registry, impact, []deliveryevidence.ImpactConfirmation{confirmation}, candidate, now,
			)
			if err != nil {
				t.Fatalf("evaluate incompatible tuple: %v", err)
			}
			if decision.Eligible || !hasValidationInvalidation(decision.Invalidations, tt.class) {
				t.Fatalf("incompatible tuple decision = %#v", decision)
			}
		})
	}
}

func TestLegacyRunCannotGainSyntheticDerivationAuthority(t *testing.T) {
	input := safeImpactInput()
	input.ParentAuthority.RunSchema = deliveryevidence.EvidenceDerivationRunSchemaV1
	input.DerivedAuthority.RunSchema = deliveryevidence.EvidenceDerivationRunSchemaV1
	if _, err := deliveryevidence.NewEvidenceImpactAssessment(input); err == nil {
		t.Fatal("legacy run admitted an impact assessment")
	}

	input.ParentAuthority.RunSchema = "packy.issue-delivery-run/v99"
	input.DerivedAuthority.RunSchema = "packy.issue-delivery-run/v99"
	if _, err := deliveryevidence.NewEvidenceImpactAssessment(input); err == nil {
		t.Fatal("unknown run schema was admitted into an impact assessment")
	}
}

func TestEvidenceDerivationCanonicalContractRejectsDuplicatesAndStaleIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*deliveryevidence.EvidenceImpactAssessmentInput)
	}{
		{
			name: "missing core review axis",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.ParentCandidate.RequiredReviewAxes = []deliveryevidence.ReviewAxis{
					deliveryevidence.ReviewStandards,
				}
				input.DerivedCandidate.RequiredReviewAxes = []deliveryevidence.ReviewAxis{
					deliveryevidence.ReviewStandards,
				}
			},
		},
		{
			name: "duplicate review axis",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.DerivedCandidate.RequiredReviewAxes = append(
					input.DerivedCandidate.RequiredReviewAxes,
					deliveryevidence.ReviewSpec,
				)
			},
		},
		{
			name: "duplicate boundary",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.ParentCandidate.SensitiveBoundaries = append(
					input.ParentCandidate.SensitiveBoundaries,
					deliveryevidence.BoundaryInstallation,
				)
			},
		},
		{
			name: "duplicate obligation",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.Obligations = append(input.Obligations, input.Obligations[0])
			},
		},
		{
			name: "duplicate change class",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.Changes = append(input.Changes, input.Changes[0])
			},
		},
		{
			name: "duplicate affected boundary",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.Changes = []deliveryevidence.EvidenceChange{{
					Class: deliveryevidence.ChangeSensitiveBoundary, Rationale: "duplicated boundary",
					Boundaries: []deliveryevidence.SensitiveBoundary{
						deliveryevidence.BoundarySecurity,
						deliveryevidence.BoundarySecurity,
					},
				}}
			},
		},
		{
			name: "unknown obligation",
			mutate: func(input *deliveryevidence.EvidenceImpactAssessmentInput) {
				input.Obligations[0].Derived.Kind = "invented"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := safeImpactInput()
			tt.mutate(&input)
			if _, err := deliveryevidence.NewEvidenceImpactAssessment(input); err == nil {
				t.Fatal("non-canonical impact assessment was admitted")
			}
		})
	}

	assessment, err := deliveryevidence.NewEvidenceImpactAssessment(safeImpactInput())
	if err != nil {
		t.Fatalf("compile canonical assessment: %v", err)
	}
	assessment.DerivedCandidate.RequiredReviewAxes = []deliveryevidence.ReviewAxis{
		deliveryevidence.ReviewStandards,
		deliveryevidence.ReviewSpec,
	}
	if _, err := deliveryevidence.EvaluateEvidenceImpactAssessment(testImpactAuthority{}, assessment); err == nil {
		t.Fatal("non-canonical ordering with a stale identity was admitted")
	}
}

func TestValidationCompatibilityCanonicalContractRejectsDuplicateTupleMembers(t *testing.T) {
	impact, err := deliveryevidence.NewEvidenceImpactAssessment(safeImpactInput())
	if err != nil {
		t.Fatalf("compile impact assessment: %v", err)
	}
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	confirmation := acceptedImpactConfirmation(t, impact)
	duplicateInstrumentation := compatibleValidationInput(impact, confirmation.ID, now.Add(time.Hour))
	duplicateInstrumentation.Source.Environment.Instrumentation = append(
		duplicateInstrumentation.Source.Environment.Instrumentation,
		deliveryevidence.InstrumentationPackyValidator,
	)
	if _, err := deliveryevidence.NewValidationCompatibilityAssessment(duplicateInstrumentation); err == nil {
		t.Fatal("duplicate validation instrumentation was admitted")
	}

	duplicateBoundary := compatibleValidationInput(impact, confirmation.ID, now.Add(time.Hour))
	duplicateBoundary.Required.Environment.CoveredBoundaries = append(
		duplicateBoundary.Required.Environment.CoveredBoundaries,
		deliveryevidence.BoundaryInstallation,
	)
	if _, err := deliveryevidence.NewValidationCompatibilityAssessment(duplicateBoundary); err == nil {
		t.Fatal("duplicate covered boundary was admitted")
	}

	canonical, err := deliveryevidence.NewValidationCompatibilityAssessment(
		compatibleValidationInput(impact, confirmation.ID, now.Add(time.Hour)),
	)
	if err != nil {
		t.Fatalf("compile canonical compatibility assessment: %v", err)
	}
	canonical.Source.Environment.Instrumentation = []deliveryevidence.ValidationInstrumentation{
		deliveryevidence.InstrumentationWorkspaceClean,
		deliveryevidence.InstrumentationPackyValidator,
		deliveryevidence.InstrumentationAcceptanceTraceability,
	}
	if _, err := deliveryevidence.EvaluateValidationCompatibility(
		testImpactAuthority{}, testValidationRegistry{artifact: canonical.Source, found: true},
		impact, []deliveryevidence.ImpactConfirmation{confirmation}, canonical, now,
	); err == nil {
		t.Fatal("non-canonical validation tuple with stale identity was admitted")
	}
}

func safeImpactInput() deliveryevidence.EvidenceImpactAssessmentInput {
	return deliveryevidence.EvidenceImpactAssessmentInput{
		Author: deliveryevidence.ImpactAuthor{
			Kind:     deliveryevidence.ImpactAuthorAuthorizedHuman,
			Identity: "maintainer:alice",
		},
		ParentAuthority:         evidenceAuthority("run-current"),
		DerivedAuthority:        evidenceAuthority("run-current"),
		ParentCandidate:         evidenceCandidate("candidate-parent", "1", "2", 1),
		DerivedCandidate:        evidenceCandidate("candidate-derived", "3", "2", 2),
		ParentAcceptanceSHA256:  strings.Repeat("c", 64),
		DerivedAcceptanceSHA256: strings.Repeat("c", 64),
		ParentObligationCount:   1,
		DerivedObligationCount:  1,
		Obligations: []deliveryevidence.AcceptanceObligationImpact{
			{
				Parent:      evidenceObligation("criterion-1", deliveryevidence.EvidencePositive),
				Derived:     evidenceObligation("criterion-1", deliveryevidence.EvidencePositive),
				Disposition: deliveryevidence.ImpactUnaffected,
				Rationale:   "the commit-metadata-only delta does not change acceptance meaning",
			},
		},
		Changes: []deliveryevidence.EvidenceChange{
			{
				Class:     deliveryevidence.ChangeNonBehavioral,
				Rationale: "only commit metadata changed",
			},
		},
		Complete: true,
	}
}

func protectedChange(class deliveryevidence.EvidenceChangeClass) []deliveryevidence.EvidenceChange {
	return []deliveryevidence.EvidenceChange{{Class: class, Rationale: "protected change requires fresh evidence"}}
}

func compatibleValidationInput(
	impact deliveryevidence.EvidenceImpactAssessment,
	confirmationID string,
	expires time.Time,
) deliveryevidence.ValidationCompatibilityAssessmentInput {
	environment := deliveryevidence.ValidationEnvironmentIdentity{
		ValidatorIdentity: "packy-validator:v1",
		ValidatorSHA256:   strings.Repeat("6", 64),
		RequiredCommand:   "./scripts/validate-packy.sh",
		HomeRoot:          "/sandbox/home",
		ConfigRoot:        "/sandbox/config",
		Instrumentation: []deliveryevidence.ValidationInstrumentation{
			deliveryevidence.InstrumentationWorkspaceClean,
			deliveryevidence.InstrumentationPackyValidator,
			deliveryevidence.InstrumentationAcceptanceTraceability,
		},
		CoveredBoundaries: []deliveryevidence.SensitiveBoundary{
			deliveryevidence.BoundaryInstallation,
		},
	}
	obligation := deliveryevidence.ValidationObligationIdentity{
		Kind: deliveryevidence.ValidationObligationExhaustive,
	}
	return deliveryevidence.ValidationCompatibilityAssessmentInput{
		ImpactAssessmentID:   impact.ID,
		ImpactConfirmationID: confirmationID,
		Source: deliveryevidence.RegisteredValidationArtifact{
			SessionSchema:    "packy.validation-session/v1",
			Kind:             deliveryevidence.ValidationArtifactRegisteredSession,
			SessionID:        strings.Repeat("4", 64),
			CompletionSHA256: strings.Repeat("5", 64),
			CheckoutSHA256:   strings.Repeat("7", 64),
			Candidate:        impact.ParentCandidate,
			Environment:      environment,
			Obligation:       obligation,
			ExpiresAt:        expires.Format(time.RFC3339Nano),
			CompletedAt:      expires.Add(-2 * time.Hour).Format(time.RFC3339Nano),
			WorkspaceClean:   true,
			Succeeded:        true,
			Completed:        true,
			CompletionCount:  1,
		},
		Required: deliveryevidence.ValidationCompatibilityRequirement{
			Candidate:      impact.DerivedCandidate,
			CheckoutSHA256: strings.Repeat("7", 64),
			Environment:    environment,
			Obligation:     obligation,
			ExpiresAt:      expires.Format(time.RFC3339Nano),
			WorkspaceClean: true,
		},
	}
}

func acceptedImpactConfirmation(
	t *testing.T,
	impact deliveryevidence.EvidenceImpactAssessment,
) deliveryevidence.ImpactConfirmation {
	t.Helper()
	confirmation, err := deliveryevidence.NewImpactConfirmation(
		deliveryevidence.ImpactConfirmationInput{
			AssessmentID:       impact.ID,
			ParentCandidateID:  impact.ParentCandidate.ID,
			DerivedCandidateID: impact.DerivedCandidate.ID,
			Confirmer: deliveryevidence.ImpactAuthor{
				Kind:     deliveryevidence.ImpactAuthorAuthorizedHuman,
				Identity: "reviewer:validation-compatibility",
			},
			Decision:  deliveryevidence.ImpactConfirmationAccepted,
			Rationale: "the exact impact assessment was independently confirmed",
			Completed: true,
		},
	)
	if err != nil {
		t.Fatalf("compile accepted impact confirmation: %v", err)
	}
	return confirmation
}

func hasValidationInvalidation(
	invalidations []deliveryevidence.ValidationCompatibilityInvalidation,
	want deliveryevidence.ValidationInvalidationClass,
) bool {
	for _, invalidation := range invalidations {
		if invalidation.Class == want {
			return true
		}
	}
	return false
}

func hasEvidenceInvalidation(
	invalidations []deliveryevidence.EvidenceInvalidation,
	want deliveryevidence.EvidenceChangeClass,
) bool {
	for _, invalidation := range invalidations {
		if invalidation.Class == want {
			return true
		}
	}
	return false
}

func evidenceAuthority(runID string) deliveryevidence.EvidenceAuthorityIdentity {
	return deliveryevidence.EvidenceAuthorityIdentity{
		RunSchema: deliveryevidence.EvidenceDerivationRunSchemaV2,
		RunID:     runID,
		SHA256:    strings.Repeat("a", 64),
	}
}

func evidenceCandidate(id, commitDigit, treeDigit string, generation int) deliveryevidence.EvidenceCandidateIdentity {
	return deliveryevidence.EvidenceCandidateIdentity{
		ID:               id,
		BaseSHA:          strings.Repeat("0", 40),
		CommitSHA:        strings.Repeat(commitDigit, 40),
		TreeSHA:          strings.Repeat(treeDigit, 40),
		ReviewGeneration: generation,
		RiskProfile:      deliveryevidence.RiskHigh,
		RequiredReviewAxes: []deliveryevidence.ReviewAxis{
			deliveryevidence.ReviewStandards,
			deliveryevidence.ReviewSpec,
		},
		SensitiveBoundaries: []deliveryevidence.SensitiveBoundary{
			deliveryevidence.BoundaryInstallation,
		},
	}
}

func evidenceObligation(criterionID string, kind deliveryevidence.AcceptanceEvidenceKind) deliveryevidence.EvidenceObligationIdentity {
	return deliveryevidence.EvidenceObligationIdentity{
		CriterionID: criterionID,
		Kind:        kind,
		Phase:       deliveryevidence.AssuranceCandidateReview,
	}
}

type testImpactAuthority struct {
	denyAll bool
}

func (authority testImpactAuthority) AuthorizedImpactAuthor(author deliveryevidence.ImpactAuthor) bool {
	if authority.denyAll {
		return false
	}
	if author.Kind == deliveryevidence.ImpactAuthorRegisteredPolicy {
		return author.RegistrationSHA256 == strings.Repeat("e", 64)
	}
	switch author.Identity {
	case "maintainer:alice", "reviewer:bob", "reviewer:validation-compatibility":
		return true
	default:
		return false
	}
}

func (testImpactAuthority) IndependentImpactConfirmer(
	author deliveryevidence.ImpactAuthor,
	confirmer deliveryevidence.ImpactAuthor,
) bool {
	if author.Identity == confirmer.Identity {
		return false
	}
	return author.RegistrationSHA256 == "" ||
		confirmer.RegistrationSHA256 == "" ||
		author.RegistrationSHA256 != confirmer.RegistrationSHA256
}

type testValidationRegistry struct {
	artifact deliveryevidence.RegisteredValidationArtifact
	found    bool
}

func (registry testValidationRegistry) RegisteredValidationArtifact(
	sessionID string,
	completionSHA256 string,
) (deliveryevidence.RegisteredValidationArtifact, bool) {
	if !registry.found || registry.artifact.SessionID != sessionID ||
		registry.artifact.CompletionSHA256 != completionSHA256 {
		return deliveryevidence.RegisteredValidationArtifact{}, false
	}
	return registry.artifact, true
}
