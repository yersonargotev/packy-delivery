package deliveryevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	EvidenceImpactAssessmentSchema    = "packy.evidence-impact-assessment/v1"
	ImpactConfirmationSchema          = "packy.evidence-impact-confirmation/v1"
	ValidationCompatibilitySchema     = "packy.validation-compatibility-assessment/v1"
	EvidenceDerivationRunSchemaV1     = "packy.issue-delivery-run/v1"
	EvidenceDerivationRunSchemaV2     = "packy.issue-delivery-run/v2"
	RegisteredValidationSessionSchema = "packy.validation-session/v1"
)

var (
	gitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type SensitiveBoundary string

const (
	BoundaryInstallation      SensitiveBoundary = "installation"
	BoundaryRealConfiguration SensitiveBoundary = "real-configuration"
	BoundarySecurity          SensitiveBoundary = "security"
	BoundaryPublication       SensitiveBoundary = "publication"
	BoundaryMigration         SensitiveBoundary = "migration"
	BoundaryPersistentFormat  SensitiveBoundary = "persistent-format"
	BoundaryGovernance        SensitiveBoundary = "governance"
	BoundaryDestructive       SensitiveBoundary = "destructive-effect"
)

type ValidationInstrumentation string

const (
	InstrumentationPackyValidator         ValidationInstrumentation = "packy-validator"
	InstrumentationWorkspaceClean         ValidationInstrumentation = "workspace-clean"
	InstrumentationAcceptanceTraceability ValidationInstrumentation = "acceptance-traceability"
	InstrumentationOperatorState          ValidationInstrumentation = "operator-state"
	InstrumentationSandboxWriteManifest   ValidationInstrumentation = "sandbox-write-manifest"
)

type ValidationInvalidationClass string

const (
	ValidationInvalidationCandidate           ValidationInvalidationClass = "candidate"
	ValidationInvalidationCommit              ValidationInvalidationClass = "commit"
	ValidationInvalidationTree                ValidationInvalidationClass = "tree"
	ValidationInvalidationCheckout            ValidationInvalidationClass = "checkout"
	ValidationInvalidationValidator           ValidationInvalidationClass = "validator"
	ValidationInvalidationCommand             ValidationInvalidationClass = "command"
	ValidationInvalidationSandbox             ValidationInvalidationClass = "sandbox"
	ValidationInvalidationInstrumentation     ValidationInvalidationClass = "instrumentation"
	ValidationInvalidationBoundaryRequirement ValidationInvalidationClass = "boundary-requirement"
	ValidationInvalidationExpiry              ValidationInvalidationClass = "expiry"
	ValidationInvalidationWorkspace           ValidationInvalidationClass = "workspace"
	ValidationInvalidationFailedExecution     ValidationInvalidationClass = "failed-execution"
)

type ImpactAuthorKind string

const (
	ImpactAuthorAuthorizedHuman  ImpactAuthorKind = "authorized-human"
	ImpactAuthorRegisteredPolicy ImpactAuthorKind = "registered-policy"
)

type ImpactAuthor struct {
	Kind               ImpactAuthorKind `json:"kind"`
	Identity           string           `json:"identity"`
	RegistrationSHA256 string           `json:"registration_sha256,omitempty"`
}

// ImpactAuthority admits author and confirmer identities from the trusted
// delivery authority rather than from caller-authored strings alone.
type ImpactAuthority interface {
	AuthorizedImpactAuthor(ImpactAuthor) bool
	IndependentImpactConfirmer(author, confirmer ImpactAuthor) bool
}

type EvidenceAuthorityIdentity struct {
	RunSchema string `json:"run_schema"`
	RunID     string `json:"run_id"`
	SHA256    string `json:"sha256"`
}

type EvidenceCandidateIdentity struct {
	ID                  string              `json:"id"`
	BaseSHA             string              `json:"base_sha"`
	CommitSHA           string              `json:"commit_sha"`
	TreeSHA             string              `json:"tree_sha"`
	ReviewGeneration    int                 `json:"review_generation"`
	RiskProfile         DeliveryRiskProfile `json:"risk_profile"`
	RequiredReviewAxes  []ReviewAxis        `json:"required_review_axes"`
	SensitiveBoundaries []SensitiveBoundary `json:"sensitive_boundaries"`
}

type EvidenceObligationIdentity struct {
	CriterionID string                 `json:"criterion_id"`
	Kind        AcceptanceEvidenceKind `json:"kind"`
	Phase       AssurancePhase         `json:"phase"`
}

type ImpactDisposition string

const (
	ImpactUnaffected ImpactDisposition = "unaffected"
	ImpactChanged    ImpactDisposition = "changed"
	ImpactAmbiguous  ImpactDisposition = "ambiguous"
)

type AcceptanceObligationImpact struct {
	Parent      EvidenceObligationIdentity `json:"parent"`
	Derived     EvidenceObligationIdentity `json:"derived"`
	Disposition ImpactDisposition          `json:"disposition"`
	Rationale   string                     `json:"rationale"`
}

type EvidenceChangeClass string

const (
	ChangeNonBehavioral     EvidenceChangeClass = "non-behavioral"
	ChangeTree              EvidenceChangeClass = "tree"
	ChangeAuthority         EvidenceChangeClass = "authority"
	ChangeBehavior          EvidenceChangeClass = "behavior"
	ChangeContract          EvidenceChangeClass = "contract"
	ChangeScope             EvidenceChangeClass = "scope"
	ChangeArchitecture      EvidenceChangeClass = "architecture"
	ChangeSecurity          EvidenceChangeClass = "security"
	ChangeAcceptanceMeaning EvidenceChangeClass = "acceptance-meaning"
	ChangeRiskProfile       EvidenceChangeClass = "risk-profile"
	ChangeSensitiveBoundary EvidenceChangeClass = "sensitive-boundary"
	ChangeValidator         EvidenceChangeClass = "validator"
	ChangeRequiredCommand   EvidenceChangeClass = "required-command"
	ChangeSandbox           EvidenceChangeClass = "sandbox"
	ChangeInstrumentation   EvidenceChangeClass = "instrumentation"
	ChangeExpiry            EvidenceChangeClass = "expiry"
	ChangeWorkspaceState    EvidenceChangeClass = "workspace-state"
	ChangeMigration         EvidenceChangeClass = "migration"
	ChangeAmbiguous         EvidenceChangeClass = "ambiguous"
)

type EvidenceChange struct {
	Class      EvidenceChangeClass `json:"class"`
	Rationale  string              `json:"rationale"`
	Boundaries []SensitiveBoundary `json:"boundaries,omitempty"`
}

type EvidenceImpactAssessmentInput struct {
	Author                  ImpactAuthor                 `json:"author"`
	ParentAuthority         EvidenceAuthorityIdentity    `json:"parent_authority"`
	DerivedAuthority        EvidenceAuthorityIdentity    `json:"derived_authority"`
	ParentCandidate         EvidenceCandidateIdentity    `json:"parent_candidate"`
	DerivedCandidate        EvidenceCandidateIdentity    `json:"derived_candidate"`
	ParentAcceptanceSHA256  string                       `json:"parent_acceptance_sha256"`
	DerivedAcceptanceSHA256 string                       `json:"derived_acceptance_sha256"`
	ParentObligationCount   int                          `json:"parent_obligation_count"`
	DerivedObligationCount  int                          `json:"derived_obligation_count"`
	Obligations             []AcceptanceObligationImpact `json:"obligations"`
	Changes                 []EvidenceChange             `json:"changes"`
	Complete                bool                         `json:"complete"`
}

type EvidenceImpactAssessment struct {
	Schema string `json:"schema"`
	ID     string `json:"id"`
	EvidenceImpactAssessmentInput
}

type EvidenceDerivationDecision struct {
	AssessmentID                    string                 `json:"assessment_id"`
	IndependentConfirmationRequired bool                   `json:"independent_confirmation_required"`
	RetainableReviewAxes            []ReviewAxis           `json:"retainable_review_axes"`
	DeltaReviewAxes                 []ReviewAxis           `json:"delta_review_axes"`
	FullReviewAxes                  []ReviewAxis           `json:"full_review_axes"`
	RetainableSpecialistBoundaries  []SensitiveBoundary    `json:"retainable_specialist_boundaries"`
	FullSpecialistBoundaries        []SensitiveBoundary    `json:"full_specialist_boundaries"`
	RetainableBoundaryValidations   []SensitiveBoundary    `json:"retainable_boundary_validations"`
	FullBoundaryValidations         []SensitiveBoundary    `json:"full_boundary_validations"`
	ExhaustiveValidationRequired    bool                   `json:"exhaustive_validation_required"`
	Invalidations                   []EvidenceInvalidation `json:"invalidations"`
}

type EvidenceInvalidation struct {
	Class  EvidenceChangeClass `json:"class"`
	Reason string              `json:"reason"`
}

type ImpactConfirmationDecision string

const (
	ImpactConfirmationAccepted ImpactConfirmationDecision = "accepted"
	ImpactConfirmationRejected ImpactConfirmationDecision = "rejected"
)

type ImpactConfirmationInput struct {
	AssessmentID       string                     `json:"assessment_id"`
	ParentCandidateID  string                     `json:"parent_candidate_id"`
	DerivedCandidateID string                     `json:"derived_candidate_id"`
	Confirmer          ImpactAuthor               `json:"confirmer"`
	Decision           ImpactConfirmationDecision `json:"decision"`
	Rationale          string                     `json:"rationale"`
	Completed          bool                       `json:"completed"`
}

type ImpactConfirmation struct {
	Schema string `json:"schema"`
	ID     string `json:"id"`
	ImpactConfirmationInput
}

type ValidationArtifactKind string

const (
	ValidationArtifactRegisteredSession ValidationArtifactKind = "registered-validation-session"
	ValidationArtifactManualExecution   ValidationArtifactKind = "manual-execution"
	ValidationArtifactArbitraryLog      ValidationArtifactKind = "arbitrary-log"
)

type ValidationObligationKind string

const (
	ValidationObligationExhaustive ValidationObligationKind = "exhaustive"
	ValidationObligationBoundary   ValidationObligationKind = "boundary"
)

type ValidationObligationIdentity struct {
	Kind     ValidationObligationKind `json:"kind"`
	Boundary SensitiveBoundary        `json:"boundary,omitempty"`
}

type ValidationEnvironmentIdentity struct {
	ValidatorIdentity string                      `json:"validator_identity"`
	ValidatorSHA256   string                      `json:"validator_sha256"`
	RequiredCommand   string                      `json:"required_command"`
	HomeRoot          string                      `json:"home_root"`
	ConfigRoot        string                      `json:"config_root"`
	Instrumentation   []ValidationInstrumentation `json:"instrumentation"`
	CoveredBoundaries []SensitiveBoundary         `json:"covered_boundaries"`
}

type RegisteredValidationArtifact struct {
	SessionSchema    string                        `json:"session_schema"`
	Kind             ValidationArtifactKind        `json:"kind"`
	SessionID        string                        `json:"session_id"`
	CompletionSHA256 string                        `json:"completion_sha256"`
	CheckoutSHA256   string                        `json:"checkout_sha256"`
	Candidate        EvidenceCandidateIdentity     `json:"candidate"`
	Environment      ValidationEnvironmentIdentity `json:"environment"`
	Obligation       ValidationObligationIdentity  `json:"obligation"`
	ExpiresAt        string                        `json:"expires_at"`
	CompletedAt      string                        `json:"completed_at"`
	WorkspaceClean   bool                          `json:"workspace_clean"`
	Succeeded        bool                          `json:"succeeded"`
	Completed        bool                          `json:"completed"`
	CompletionCount  int                           `json:"completion_count"`
}

// ValidationArtifactRegistry resolves only artifacts registered by the
// canonical validation-session lifecycle.
type ValidationArtifactRegistry interface {
	RegisteredValidationArtifact(sessionID, completionSHA256 string) (RegisteredValidationArtifact, bool)
}

type ValidationCompatibilityRequirement struct {
	Candidate      EvidenceCandidateIdentity     `json:"candidate"`
	CheckoutSHA256 string                        `json:"checkout_sha256"`
	Environment    ValidationEnvironmentIdentity `json:"environment"`
	Obligation     ValidationObligationIdentity  `json:"obligation"`
	ExpiresAt      string                        `json:"expires_at"`
	WorkspaceClean bool                          `json:"workspace_clean"`
}

type ValidationCompatibilityAssessmentInput struct {
	ImpactAssessmentID   string                             `json:"impact_assessment_id"`
	ImpactConfirmationID string                             `json:"impact_confirmation_id"`
	Source               RegisteredValidationArtifact       `json:"source"`
	Required             ValidationCompatibilityRequirement `json:"required"`
}

type ValidationCompatibilityAssessment struct {
	Schema string `json:"schema"`
	ID     string `json:"id"`
	ValidationCompatibilityAssessmentInput
}

type ValidationCompatibilityInvalidation struct {
	Class  ValidationInvalidationClass `json:"class"`
	Reason string                      `json:"reason"`
}

type ValidationCompatibilityDecision struct {
	AssessmentID  string                                `json:"assessment_id"`
	Eligible      bool                                  `json:"eligible"`
	Invalidations []ValidationCompatibilityInvalidation `json:"invalidations"`
}

const (
	ValidationInvalidationSource     ValidationInvalidationClass = "source"
	ValidationInvalidationCompletion ValidationInvalidationClass = "completion"
	ValidationInvalidationObligation ValidationInvalidationClass = "obligation"
	ValidationInvalidationImpact     ValidationInvalidationClass = "impact-assessment"
)

func NewEvidenceImpactAssessment(input EvidenceImpactAssessmentInput) (EvidenceImpactAssessment, error) {
	input = cloneImpactAssessmentInput(input)
	canonicalizeImpactAssessmentInput(&input)
	assessment := EvidenceImpactAssessment{
		Schema:                        EvidenceImpactAssessmentSchema,
		EvidenceImpactAssessmentInput: input,
	}
	if err := validateEvidenceImpactAssessmentShape(assessment); err != nil {
		return EvidenceImpactAssessment{}, err
	}
	identity, err := evidenceImpactAssessmentIdentity(assessment)
	if err != nil {
		return EvidenceImpactAssessment{}, err
	}
	assessment.ID = identity
	return assessment, nil
}

func EvaluateEvidenceImpactAssessment(
	authority ImpactAuthority,
	assessment EvidenceImpactAssessment,
) (EvidenceDerivationDecision, error) {
	if err := ValidateEvidenceImpactAssessment(assessment); err != nil {
		return EvidenceDerivationDecision{}, err
	}
	if authority == nil || !authority.AuthorizedImpactAuthor(assessment.Author) {
		return EvidenceDerivationDecision{}, errors.New("impact author is not authorized")
	}
	decision := EvidenceDerivationDecision{
		AssessmentID:                   assessment.ID,
		RetainableReviewAxes:           append([]ReviewAxis(nil), assessment.DerivedCandidate.RequiredReviewAxes...),
		DeltaReviewAxes:                []ReviewAxis{},
		FullReviewAxes:                 []ReviewAxis{},
		RetainableSpecialistBoundaries: append([]SensitiveBoundary(nil), assessment.DerivedCandidate.SensitiveBoundaries...),
		FullSpecialistBoundaries:       []SensitiveBoundary{},
		RetainableBoundaryValidations:  append([]SensitiveBoundary(nil), assessment.DerivedCandidate.SensitiveBoundaries...),
		FullBoundaryValidations:        []SensitiveBoundary{},
		Invalidations:                  []EvidenceInvalidation{},
	}
	if containsReviewAxis(assessment.DerivedCandidate.RequiredReviewAxes, ReviewStandards) {
		decision.DeltaReviewAxes = append(decision.DeltaReviewAxes, ReviewStandards)
	}
	fullAll := func(class EvidenceChangeClass, reason string) {
		decision.FullReviewAxes = append([]ReviewAxis(nil), assessment.DerivedCandidate.RequiredReviewAxes...)
		decision.FullSpecialistBoundaries = append([]SensitiveBoundary(nil), assessment.DerivedCandidate.SensitiveBoundaries...)
		decision.FullBoundaryValidations = append([]SensitiveBoundary(nil), assessment.DerivedCandidate.SensitiveBoundaries...)
		decision.ExhaustiveValidationRequired = true
		appendEvidenceInvalidation(&decision, class, reason)
	}
	fullAxis := func(axis ReviewAxis, class EvidenceChangeClass, reason string) {
		if containsReviewAxis(assessment.DerivedCandidate.RequiredReviewAxes, axis) {
			decision.FullReviewAxes = appendUniqueReviewAxis(decision.FullReviewAxes, axis)
		}
		decision.ExhaustiveValidationRequired = true
		appendEvidenceInvalidation(&decision, class, reason)
	}

	if !assessment.Complete {
		fullAll(ChangeAmbiguous, "impact assessment is incomplete")
	}
	if assessment.ParentAuthority.RunSchema != EvidenceDerivationRunSchemaV2 ||
		assessment.DerivedAuthority.RunSchema != EvidenceDerivationRunSchemaV2 {
		fullAll(ChangeMigration, "legacy runs cannot gain synthetic derivation authority")
	}
	if assessment.ParentAuthority != assessment.DerivedAuthority {
		fullAll(ChangeAuthority, "delivery authority changed")
	}
	if assessment.ParentCandidate.TreeSHA != assessment.DerivedCandidate.TreeSHA {
		decision.FullBoundaryValidations = append(
			[]SensitiveBoundary(nil),
			assessment.DerivedCandidate.SensitiveBoundaries...,
		)
		decision.ExhaustiveValidationRequired = true
		appendEvidenceInvalidation(&decision, ChangeTree, "candidate tree changed")
	}
	if assessment.ParentCandidate.RiskProfile != assessment.DerivedCandidate.RiskProfile ||
		!equalJSON(assessment.ParentCandidate.RequiredReviewAxes, assessment.DerivedCandidate.RequiredReviewAxes) {
		fullAll(ChangeRiskProfile, "risk profile or required review set changed")
	}
	if assessment.ParentObligationCount != len(assessment.Obligations) ||
		assessment.DerivedObligationCount != len(assessment.Obligations) {
		fullAll(ChangeAmbiguous, "acceptance impact does not cover every bound obligation")
	}
	if assessment.ParentAcceptanceSHA256 != assessment.DerivedAcceptanceSHA256 {
		fullAxis(ReviewSpec, ChangeAcceptanceMeaning, "acceptance obligation set changed")
	}
	if changed := changedBoundaries(
		assessment.ParentCandidate.SensitiveBoundaries,
		assessment.DerivedCandidate.SensitiveBoundaries,
	); len(changed) > 0 {
		decision.FullSpecialistBoundaries = appendUniqueBoundaries(decision.FullSpecialistBoundaries, changed...)
		decision.FullBoundaryValidations = appendUniqueBoundaries(decision.FullBoundaryValidations, changed...)
		decision.ExhaustiveValidationRequired = true
		appendEvidenceInvalidation(&decision, ChangeSensitiveBoundary, "sensitive boundary set changed")
	}
	for _, obligation := range assessment.Obligations {
		if obligation.Parent != obligation.Derived || obligation.Disposition != ImpactUnaffected {
			fullAxis(ReviewSpec, ChangeAcceptanceMeaning, "acceptance obligation changed or is ambiguous")
		}
	}
	for _, change := range assessment.Changes {
		switch change.Class {
		case ChangeNonBehavioral:
		case ChangeTree:
			decision.FullBoundaryValidations = append(
				[]SensitiveBoundary(nil),
				assessment.DerivedCandidate.SensitiveBoundaries...,
			)
			decision.ExhaustiveValidationRequired = true
			appendEvidenceInvalidation(&decision, change.Class, change.Rationale)
		case ChangeAcceptanceMeaning:
			fullAxis(ReviewSpec, change.Class, change.Rationale)
		case ChangeSensitiveBoundary:
			decision.FullSpecialistBoundaries = appendUniqueBoundaries(decision.FullSpecialistBoundaries, change.Boundaries...)
			decision.FullBoundaryValidations = appendUniqueBoundaries(decision.FullBoundaryValidations, change.Boundaries...)
			decision.ExhaustiveValidationRequired = true
			appendEvidenceInvalidation(&decision, change.Class, change.Rationale)
		case ChangeValidator, ChangeRequiredCommand, ChangeSandbox, ChangeInstrumentation,
			ChangeExpiry, ChangeWorkspaceState:
			decision.FullBoundaryValidations = append(
				[]SensitiveBoundary(nil),
				assessment.DerivedCandidate.SensitiveBoundaries...,
			)
			decision.ExhaustiveValidationRequired = true
			appendEvidenceInvalidation(&decision, change.Class, change.Rationale)
		case ChangeAuthority, ChangeBehavior, ChangeContract, ChangeScope,
			ChangeArchitecture, ChangeSecurity, ChangeRiskProfile, ChangeMigration, ChangeAmbiguous:
			fullAll(change.Class, change.Rationale)
		}
	}

	sort.Slice(decision.FullReviewAxes, func(i, j int) bool {
		return decision.FullReviewAxes[i] < decision.FullReviewAxes[j]
	})
	sort.Slice(decision.FullSpecialistBoundaries, func(i, j int) bool {
		return decision.FullSpecialistBoundaries[i] < decision.FullSpecialistBoundaries[j]
	})
	sort.Slice(decision.FullBoundaryValidations, func(i, j int) bool {
		return decision.FullBoundaryValidations[i] < decision.FullBoundaryValidations[j]
	})
	decision.RetainableReviewAxes = subtractReviewAxes(decision.RetainableReviewAxes, decision.FullReviewAxes)
	decision.RetainableSpecialistBoundaries = subtractBoundaries(
		decision.RetainableSpecialistBoundaries,
		decision.FullSpecialistBoundaries,
	)
	decision.RetainableBoundaryValidations = subtractBoundaries(
		decision.RetainableBoundaryValidations,
		decision.FullBoundaryValidations,
	)
	if containsReviewAxis(decision.FullReviewAxes, ReviewStandards) {
		decision.DeltaReviewAxes = []ReviewAxis{}
	}
	decision.IndependentConfirmationRequired =
		len(decision.RetainableReviewAxes) > 0 ||
			len(decision.RetainableSpecialistBoundaries) > 0 ||
			len(decision.RetainableBoundaryValidations) > 0 ||
			!decision.ExhaustiveValidationRequired
	return decision, nil
}

func ValidateEvidenceImpactAssessment(assessment EvidenceImpactAssessment) error {
	if err := validateEvidenceImpactAssessmentShape(assessment); err != nil {
		return err
	}
	canonical := cloneImpactAssessmentInput(assessment.EvidenceImpactAssessmentInput)
	canonicalizeImpactAssessmentInput(&canonical)
	if !equalJSON(canonical, assessment.EvidenceImpactAssessmentInput) {
		return errors.New("impact assessment is not canonical")
	}
	want, err := evidenceImpactAssessmentIdentity(assessment)
	if err != nil {
		return err
	}
	if assessment.ID != want {
		return errors.New("impact assessment identity is stale")
	}
	return nil
}

func NewImpactConfirmation(input ImpactConfirmationInput) (ImpactConfirmation, error) {
	confirmation := ImpactConfirmation{
		Schema:                  ImpactConfirmationSchema,
		ImpactConfirmationInput: input,
	}
	if err := validateImpactConfirmationShape(confirmation); err != nil {
		return ImpactConfirmation{}, err
	}
	identity, err := impactConfirmationIdentity(confirmation)
	if err != nil {
		return ImpactConfirmation{}, err
	}
	confirmation.ID = identity
	return confirmation, nil
}

func AdmitImpactConfirmation(
	authority ImpactAuthority,
	assessment EvidenceImpactAssessment,
	confirmations ...ImpactConfirmation,
) error {
	if err := ValidateEvidenceImpactAssessment(assessment); err != nil {
		return fmt.Errorf("validate confirmed impact assessment: %w", err)
	}
	if len(confirmations) != 1 {
		return errors.New("exactly one impact confirmation is required")
	}
	confirmation := confirmations[0]
	if authority == nil || !authority.AuthorizedImpactAuthor(assessment.Author) ||
		!authority.AuthorizedImpactAuthor(confirmation.Confirmer) {
		return errors.New("impact author or confirmer is not authorized")
	}
	if err := validateImpactConfirmationShape(confirmation); err != nil {
		return err
	}
	want, err := impactConfirmationIdentity(confirmation)
	if err != nil {
		return err
	}
	if confirmation.ID != want {
		return errors.New("impact confirmation identity is stale")
	}
	if confirmation.AssessmentID != assessment.ID ||
		confirmation.ParentCandidateID != assessment.ParentCandidate.ID ||
		confirmation.DerivedCandidateID != assessment.DerivedCandidate.ID {
		return errors.New("impact confirmation does not match the exact assessment and candidates")
	}
	sameIdentity := confirmation.Confirmer.Identity == assessment.Author.Identity
	samePolicyRegistration := confirmation.Confirmer.Kind == ImpactAuthorRegisteredPolicy &&
		assessment.Author.Kind == ImpactAuthorRegisteredPolicy &&
		confirmation.Confirmer.RegistrationSHA256 == assessment.Author.RegistrationSHA256
	if sameIdentity || samePolicyRegistration ||
		!authority.IndependentImpactConfirmer(assessment.Author, confirmation.Confirmer) {
		return errors.New("impact confirmation is not independent from its author")
	}
	if !confirmation.Completed || confirmation.Decision != ImpactConfirmationAccepted {
		return errors.New("impact confirmation was not completed and accepted")
	}
	return nil
}

func NewValidationCompatibilityAssessment(
	input ValidationCompatibilityAssessmentInput,
) (ValidationCompatibilityAssessment, error) {
	input = cloneValidationCompatibilityInput(input)
	canonicalizeValidationCompatibilityInput(&input)
	assessment := ValidationCompatibilityAssessment{
		Schema:                                 ValidationCompatibilitySchema,
		ValidationCompatibilityAssessmentInput: input,
	}
	if err := validateValidationCompatibilityShape(assessment); err != nil {
		return ValidationCompatibilityAssessment{}, err
	}
	identity, err := validationCompatibilityIdentity(assessment)
	if err != nil {
		return ValidationCompatibilityAssessment{}, err
	}
	assessment.ID = identity
	return assessment, nil
}

func EvaluateValidationCompatibility(
	authority ImpactAuthority,
	registry ValidationArtifactRegistry,
	impact EvidenceImpactAssessment,
	confirmations []ImpactConfirmation,
	assessment ValidationCompatibilityAssessment,
	now time.Time,
) (ValidationCompatibilityDecision, error) {
	if err := ValidateEvidenceImpactAssessment(impact); err != nil {
		return ValidationCompatibilityDecision{}, fmt.Errorf("validate impact assessment: %w", err)
	}
	if err := validateValidationCompatibilityAssessment(assessment); err != nil {
		return ValidationCompatibilityDecision{}, err
	}
	decision := ValidationCompatibilityDecision{
		AssessmentID:  assessment.ID,
		Invalidations: []ValidationCompatibilityInvalidation{},
	}
	add := func(class ValidationInvalidationClass, reason string) {
		appendValidationCompatibilityInvalidation(&decision, class, reason)
	}
	if assessment.ImpactAssessmentID != impact.ID {
		add(ValidationInvalidationImpact, "compatibility assessment references a stale impact assessment")
	}
	if err := AdmitImpactConfirmation(authority, impact, confirmations...); err != nil {
		add(ValidationInvalidationImpact, "impact assessment lacks one exact admitted independent confirmation")
	}
	if len(confirmations) != 1 || assessment.ImpactConfirmationID != confirmations[0].ID {
		add(ValidationInvalidationImpact, "compatibility assessment references a stale impact confirmation")
	}
	impactDecision, err := EvaluateEvidenceImpactAssessment(authority, impact)
	if err != nil {
		return ValidationCompatibilityDecision{}, err
	}
	if impactDecision.ExhaustiveValidationRequired {
		add(ValidationInvalidationImpact, "impact assessment requires fresh exhaustive validation")
	}
	if assessment.Source.SessionSchema != RegisteredValidationSessionSchema {
		add(ValidationInvalidationSource, "validation artifact does not use the registered session schema")
	}
	if assessment.Source.Kind != ValidationArtifactRegisteredSession {
		add(ValidationInvalidationSource, "only a canonical registered validation session is admissible")
	}
	registeredSource, registered := RegisteredValidationArtifact{}, false
	if registry != nil {
		registeredSource, registered = registry.RegisteredValidationArtifact(
			assessment.Source.SessionID,
			assessment.Source.CompletionSHA256,
		)
	}
	if !registered || !equalJSON(registeredSource, assessment.Source) {
		add(ValidationInvalidationSource, "validation artifact is not present in the canonical session registry")
	}
	if assessment.Source.Candidate.ID != impact.ParentCandidate.ID ||
		assessment.Required.Candidate.ID != impact.DerivedCandidate.ID {
		add(ValidationInvalidationCandidate, "source or required candidate identity is stale")
	}
	if assessment.Source.Candidate.CommitSHA != impact.ParentCandidate.CommitSHA ||
		assessment.Required.Candidate.CommitSHA != impact.DerivedCandidate.CommitSHA {
		add(ValidationInvalidationCandidate, "source or required candidate commit is stale")
		add(ValidationInvalidationCommit, "source or required commit does not match its candidate")
	}
	if assessment.Source.Candidate.TreeSHA != impact.ParentCandidate.TreeSHA ||
		assessment.Required.Candidate.TreeSHA != impact.DerivedCandidate.TreeSHA ||
		assessment.Source.Candidate.TreeSHA != assessment.Required.Candidate.TreeSHA {
		add(ValidationInvalidationTree, "source and required trees are not the exact compatible tree")
	}
	if assessment.Source.CheckoutSHA256 != assessment.Required.CheckoutSHA256 {
		add(ValidationInvalidationCheckout, "checkout identity changed")
	}
	if !equalJSON(assessment.Source.Candidate, impact.ParentCandidate) ||
		!equalJSON(assessment.Required.Candidate, impact.DerivedCandidate) {
		add(ValidationInvalidationCandidate, "source or required candidate tuple is stale")
	}
	sourceEnvironment := assessment.Source.Environment
	requiredEnvironment := assessment.Required.Environment
	if sourceEnvironment.ValidatorIdentity != requiredEnvironment.ValidatorIdentity ||
		sourceEnvironment.ValidatorSHA256 != requiredEnvironment.ValidatorSHA256 {
		add(ValidationInvalidationValidator, "validator identity or digest changed")
	}
	if sourceEnvironment.RequiredCommand != requiredEnvironment.RequiredCommand {
		add(ValidationInvalidationCommand, "required validation command changed")
	}
	if sourceEnvironment.HomeRoot != requiredEnvironment.HomeRoot ||
		sourceEnvironment.ConfigRoot != requiredEnvironment.ConfigRoot {
		add(ValidationInvalidationSandbox, "sandbox roots changed")
	}
	if !equalJSON(sourceEnvironment.Instrumentation, requiredEnvironment.Instrumentation) {
		add(ValidationInvalidationInstrumentation, "required instrumentation changed")
	}
	if !equalJSON(sourceEnvironment.CoveredBoundaries, requiredEnvironment.CoveredBoundaries) {
		add(ValidationInvalidationBoundaryRequirement, "covered boundary set changed")
	}
	expires, expiryErr := time.Parse(time.RFC3339Nano, assessment.Source.ExpiresAt)
	if expiryErr != nil || !canonicalDerivationTimestamp(assessment.Source.ExpiresAt, expires) ||
		!expires.After(now.UTC()) {
		add(ValidationInvalidationExpiry, "registered validator identity is expired or malformed")
	}
	requiredExpires, requiredExpiryErr := time.Parse(time.RFC3339Nano, assessment.Required.ExpiresAt)
	if assessment.Source.ExpiresAt != assessment.Required.ExpiresAt || requiredExpiryErr != nil ||
		!canonicalDerivationTimestamp(assessment.Required.ExpiresAt, requiredExpires) ||
		!requiredExpires.After(now.UTC()) {
		add(ValidationInvalidationExpiry, "required validator expiry changed or is invalid")
	}
	completed, completionErr := time.Parse(time.RFC3339Nano, assessment.Source.CompletedAt)
	if completionErr != nil || !canonicalDerivationTimestamp(assessment.Source.CompletedAt, completed) ||
		completed.After(now.UTC()) || (!expires.IsZero() && completed.After(expires)) {
		add(ValidationInvalidationCompletion, "registered validation completion time is invalid")
	}
	if !assessment.Source.WorkspaceClean || !assessment.Required.WorkspaceClean {
		add(ValidationInvalidationWorkspace, "source or required workspace is not clean")
	}
	if !assessment.Source.Succeeded || !assessment.Source.Completed {
		add(ValidationInvalidationFailedExecution, "registered validation did not complete successfully")
	}
	if assessment.Source.CompletionCount != 1 {
		add(ValidationInvalidationCompletion, "registered validation completion is ambiguous")
	}
	if assessment.Source.Obligation != assessment.Required.Obligation {
		add(ValidationInvalidationObligation, "validation artifact proves a different obligation")
	}
	if assessment.Required.Obligation.Kind == ValidationObligationBoundary &&
		!containsBoundary(requiredEnvironment.CoveredBoundaries, assessment.Required.Obligation.Boundary) {
		add(ValidationInvalidationBoundaryRequirement, "required boundary is not covered by the artifact")
	}
	decision.Eligible = len(decision.Invalidations) == 0
	return decision, nil
}

func validateImpactConfirmationShape(confirmation ImpactConfirmation) error {
	if confirmation.Schema != ImpactConfirmationSchema {
		return fmt.Errorf("unsupported impact confirmation schema %q", confirmation.Schema)
	}
	if !validSHA256(confirmation.AssessmentID) ||
		strings.TrimSpace(confirmation.ParentCandidateID) == "" ||
		strings.TrimSpace(confirmation.DerivedCandidateID) == "" ||
		strings.TrimSpace(confirmation.Rationale) == "" {
		return errors.New("impact confirmation identity and rationale are incomplete")
	}
	if err := validateImpactAuthor(confirmation.Confirmer); err != nil {
		return fmt.Errorf("impact confirmer: %w", err)
	}
	switch confirmation.Decision {
	case ImpactConfirmationAccepted, ImpactConfirmationRejected:
	default:
		return fmt.Errorf("unsupported impact confirmation decision %q", confirmation.Decision)
	}
	return nil
}

func validateValidationCompatibilityAssessment(assessment ValidationCompatibilityAssessment) error {
	if err := validateValidationCompatibilityShape(assessment); err != nil {
		return err
	}
	canonical := cloneValidationCompatibilityInput(assessment.ValidationCompatibilityAssessmentInput)
	canonicalizeValidationCompatibilityInput(&canonical)
	if !equalJSON(canonical, assessment.ValidationCompatibilityAssessmentInput) {
		return errors.New("validation compatibility assessment is not canonical")
	}
	want, err := validationCompatibilityIdentity(assessment)
	if err != nil {
		return err
	}
	if assessment.ID != want {
		return errors.New("validation compatibility assessment identity is stale")
	}
	return nil
}

func validateValidationCompatibilityShape(assessment ValidationCompatibilityAssessment) error {
	if assessment.Schema != ValidationCompatibilitySchema {
		return fmt.Errorf("unsupported validation compatibility schema %q", assessment.Schema)
	}
	if !validSHA256(assessment.ImpactAssessmentID) || !validSHA256(assessment.ImpactConfirmationID) ||
		strings.TrimSpace(assessment.Source.SessionSchema) == "" ||
		!validSHA256(assessment.Source.SessionID) || !validSHA256(assessment.Source.CompletionSHA256) ||
		!validSHA256(assessment.Source.CheckoutSHA256) || !validSHA256(assessment.Required.CheckoutSHA256) {
		return errors.New("validation compatibility source identities are incomplete")
	}
	switch assessment.Source.Kind {
	case ValidationArtifactRegisteredSession, ValidationArtifactManualExecution, ValidationArtifactArbitraryLog:
	default:
		return fmt.Errorf("unsupported validation artifact kind %q", assessment.Source.Kind)
	}
	if err := validateEvidenceCandidateIdentity("source", assessment.Source.Candidate); err != nil {
		return err
	}
	if err := validateEvidenceCandidateIdentity("required", assessment.Required.Candidate); err != nil {
		return err
	}
	for role, environment := range map[string]ValidationEnvironmentIdentity{
		"source":   assessment.Source.Environment,
		"required": assessment.Required.Environment,
	} {
		if strings.TrimSpace(environment.ValidatorIdentity) == "" || !validSHA256(environment.ValidatorSHA256) ||
			strings.TrimSpace(environment.RequiredCommand) == "" || strings.TrimSpace(environment.HomeRoot) == "" ||
			strings.TrimSpace(environment.ConfigRoot) == "" || len(environment.Instrumentation) == 0 {
			return fmt.Errorf("%s validation environment identity is incomplete", role)
		}
		seenInstrumentation := map[ValidationInstrumentation]struct{}{}
		for _, instrumentation := range environment.Instrumentation {
			switch instrumentation {
			case InstrumentationPackyValidator, InstrumentationWorkspaceClean,
				InstrumentationAcceptanceTraceability, InstrumentationOperatorState,
				InstrumentationSandboxWriteManifest:
			default:
				return fmt.Errorf("%s validation instrumentation %q is invalid", role, instrumentation)
			}
			if _, duplicate := seenInstrumentation[instrumentation]; duplicate {
				return fmt.Errorf("%s validation instrumentation %q is duplicated", role, instrumentation)
			}
			seenInstrumentation[instrumentation] = struct{}{}
		}
		seenBoundaries := map[SensitiveBoundary]struct{}{}
		for _, boundary := range environment.CoveredBoundaries {
			if !validSensitiveBoundary(boundary) {
				return fmt.Errorf("%s validation boundary %q is invalid", role, boundary)
			}
			if _, duplicate := seenBoundaries[boundary]; duplicate {
				return fmt.Errorf("%s validation boundary %q is duplicated", role, boundary)
			}
			seenBoundaries[boundary] = struct{}{}
		}
	}
	for _, obligation := range []ValidationObligationIdentity{
		assessment.Source.Obligation,
		assessment.Required.Obligation,
	} {
		switch obligation.Kind {
		case ValidationObligationExhaustive:
			if obligation.Boundary != "" {
				return errors.New("exhaustive validation obligation cannot name a boundary")
			}
		case ValidationObligationBoundary:
			if obligation.Boundary == "" {
				return errors.New("boundary validation obligation must name its exact boundary")
			}
		default:
			return fmt.Errorf("unsupported validation obligation %q", obligation.Kind)
		}
	}
	if strings.TrimSpace(assessment.Source.ExpiresAt) == "" ||
		strings.TrimSpace(assessment.Required.ExpiresAt) == "" ||
		strings.TrimSpace(assessment.Source.CompletedAt) == "" ||
		assessment.Source.CompletionCount < 0 {
		return errors.New("validation completion and expiry facts are incomplete")
	}
	return nil
}

func validateEvidenceImpactAssessmentShape(assessment EvidenceImpactAssessment) error {
	if assessment.Schema != EvidenceImpactAssessmentSchema {
		return fmt.Errorf("unsupported impact assessment schema %q", assessment.Schema)
	}
	if err := validateImpactAuthor(assessment.Author); err != nil {
		return fmt.Errorf("impact author: %w", err)
	}
	if strings.TrimSpace(assessment.ParentAuthority.RunID) == "" ||
		strings.TrimSpace(assessment.DerivedAuthority.RunID) == "" ||
		!validSHA256(assessment.ParentAuthority.SHA256) ||
		!validSHA256(assessment.DerivedAuthority.SHA256) {
		return errors.New("impact assessment authority identity is incomplete")
	}
	if !validSHA256(assessment.ParentAcceptanceSHA256) || !validSHA256(assessment.DerivedAcceptanceSHA256) ||
		assessment.ParentObligationCount <= 0 || assessment.DerivedObligationCount <= 0 {
		return errors.New("impact assessment acceptance-set identity is incomplete")
	}
	for _, schema := range []string{
		assessment.ParentAuthority.RunSchema,
		assessment.DerivedAuthority.RunSchema,
	} {
		if schema != EvidenceDerivationRunSchemaV2 {
			return fmt.Errorf("unsupported derivation run schema %q", schema)
		}
	}
	if err := validateEvidenceCandidateIdentity("parent", assessment.ParentCandidate); err != nil {
		return err
	}
	if err := validateEvidenceCandidateIdentity("derived", assessment.DerivedCandidate); err != nil {
		return err
	}
	if assessment.ParentCandidate.ID == assessment.DerivedCandidate.ID ||
		assessment.ParentCandidate.CommitSHA == assessment.DerivedCandidate.CommitSHA {
		return errors.New("derived candidate identity does not name a distinct candidate and commit")
	}
	if len(assessment.Obligations) == 0 || len(assessment.Changes) == 0 {
		return errors.New("impact assessment must enumerate obligations and changes")
	}
	parentObligations := map[string]struct{}{}
	derivedObligations := map[string]struct{}{}
	for _, obligation := range assessment.Obligations {
		if strings.TrimSpace(obligation.Parent.CriterionID) == "" ||
			strings.TrimSpace(obligation.Derived.CriterionID) == "" ||
			strings.TrimSpace(obligation.Rationale) == "" {
			return errors.New("impact assessment contains an incomplete acceptance obligation")
		}
		if !validEvidenceObligation(obligation.Parent) || !validEvidenceObligation(obligation.Derived) {
			return errors.New("impact assessment contains an unknown acceptance obligation")
		}
		parentKey := evidenceObligationKey(obligation.Parent)
		derivedKey := evidenceObligationKey(obligation.Derived)
		if _, duplicate := parentObligations[parentKey]; duplicate {
			return errors.New("impact assessment contains a duplicate parent obligation")
		}
		if _, duplicate := derivedObligations[derivedKey]; duplicate {
			return errors.New("impact assessment contains a duplicate derived obligation")
		}
		parentObligations[parentKey] = struct{}{}
		derivedObligations[derivedKey] = struct{}{}
		switch obligation.Disposition {
		case ImpactUnaffected, ImpactChanged, ImpactAmbiguous:
		default:
			return fmt.Errorf("unsupported obligation impact disposition %q", obligation.Disposition)
		}
	}
	changeClasses := map[EvidenceChangeClass]struct{}{}
	for _, change := range assessment.Changes {
		if strings.TrimSpace(change.Rationale) == "" {
			return errors.New("impact assessment change rationale is required")
		}
		switch change.Class {
		case ChangeNonBehavioral, ChangeTree, ChangeAuthority, ChangeBehavior, ChangeContract,
			ChangeScope, ChangeArchitecture, ChangeSecurity, ChangeAcceptanceMeaning,
			ChangeRiskProfile, ChangeSensitiveBoundary, ChangeValidator, ChangeRequiredCommand,
			ChangeSandbox, ChangeInstrumentation, ChangeExpiry, ChangeWorkspaceState,
			ChangeMigration, ChangeAmbiguous:
		default:
			return fmt.Errorf("unsupported evidence change class %q", change.Class)
		}
		if change.Class == ChangeSensitiveBoundary && len(change.Boundaries) == 0 {
			return errors.New("sensitive-boundary impact must identify its boundaries")
		}
		if change.Class != ChangeSensitiveBoundary && len(change.Boundaries) != 0 {
			return errors.New("only sensitive-boundary impact may identify boundaries")
		}
		seenAffectedBoundaries := map[SensitiveBoundary]struct{}{}
		for _, boundary := range change.Boundaries {
			if !validSensitiveBoundary(boundary) {
				return fmt.Errorf("impact assessment boundary %q is invalid", boundary)
			}
			if _, duplicate := seenAffectedBoundaries[boundary]; duplicate {
				return fmt.Errorf("impact assessment repeats boundary %q", boundary)
			}
			seenAffectedBoundaries[boundary] = struct{}{}
		}
		if _, duplicate := changeClasses[change.Class]; duplicate {
			return fmt.Errorf("impact assessment repeats change class %q", change.Class)
		}
		changeClasses[change.Class] = struct{}{}
	}
	return nil
}

func validateImpactAuthor(author ImpactAuthor) error {
	if strings.TrimSpace(author.Identity) == "" {
		return errors.New("identity is required")
	}
	switch author.Kind {
	case ImpactAuthorAuthorizedHuman:
		if author.RegistrationSHA256 != "" {
			return errors.New("authorized human cannot carry a policy registration")
		}
	case ImpactAuthorRegisteredPolicy:
		if !validSHA256(author.RegistrationSHA256) {
			return errors.New("registered policy requires its registration digest")
		}
	default:
		return fmt.Errorf("unsupported kind %q", author.Kind)
	}
	return nil
}

func validateEvidenceCandidateIdentity(role string, candidate EvidenceCandidateIdentity) error {
	if strings.TrimSpace(candidate.ID) == "" || !gitSHAPattern.MatchString(candidate.BaseSHA) ||
		!gitSHAPattern.MatchString(candidate.CommitSHA) || !gitSHAPattern.MatchString(candidate.TreeSHA) ||
		candidate.ReviewGeneration <= 0 || len(candidate.RequiredReviewAxes) == 0 {
		return fmt.Errorf("%s candidate identity is incomplete", role)
	}
	switch candidate.RiskProfile {
	case RiskLow, RiskStandard, RiskHigh:
	default:
		return fmt.Errorf("%s candidate risk profile is invalid", role)
	}
	seenAxes := map[ReviewAxis]struct{}{}
	for _, axis := range candidate.RequiredReviewAxes {
		if axis != ReviewStandards && axis != ReviewSpec {
			return fmt.Errorf("%s candidate review axis %q is invalid", role, axis)
		}
		if _, duplicate := seenAxes[axis]; duplicate {
			return fmt.Errorf("%s candidate repeats review axis %q", role, axis)
		}
		seenAxes[axis] = struct{}{}
	}
	if _, standards := seenAxes[ReviewStandards]; !standards {
		return fmt.Errorf("%s candidate is missing the Standards review axis", role)
	}
	if _, spec := seenAxes[ReviewSpec]; !spec {
		return fmt.Errorf("%s candidate is missing the Spec review axis", role)
	}
	seenBoundaries := map[SensitiveBoundary]struct{}{}
	for _, boundary := range candidate.SensitiveBoundaries {
		if !validSensitiveBoundary(boundary) {
			return fmt.Errorf("%s candidate boundary %q is invalid", role, boundary)
		}
		if _, duplicate := seenBoundaries[boundary]; duplicate {
			return fmt.Errorf("%s candidate repeats boundary %q", role, boundary)
		}
		seenBoundaries[boundary] = struct{}{}
	}
	return nil
}

func validEvidenceObligation(obligation EvidenceObligationIdentity) bool {
	switch obligation.Kind {
	case EvidencePositive, EvidenceNegative,
		EvidenceFailure, EvidenceMutation,
		EvidenceCompatibility, EvidencePreservation,
		EvidenceMigration:
		return obligation.Phase == AssuranceCandidateReview
	case EvidenceValidation:
		return obligation.Phase == AssuranceExhaustiveValidation
	default:
		return false
	}
}

func evidenceObligationKey(obligation EvidenceObligationIdentity) string {
	return obligation.CriterionID + "\x00" + string(obligation.Kind) + "\x00" + string(obligation.Phase)
}

func validSensitiveBoundary(boundary SensitiveBoundary) bool {
	switch boundary {
	case BoundaryInstallation, BoundaryRealConfiguration, BoundarySecurity,
		BoundaryPublication, BoundaryMigration, BoundaryPersistentFormat,
		BoundaryGovernance, BoundaryDestructive:
		return true
	default:
		return false
	}
}

func canonicalizeImpactAssessmentInput(input *EvidenceImpactAssessmentInput) {
	canonicalizeEvidenceCandidate(&input.ParentCandidate)
	canonicalizeEvidenceCandidate(&input.DerivedCandidate)
	sort.Slice(input.Obligations, func(i, j int) bool {
		return obligationImpactKey(input.Obligations[i]) < obligationImpactKey(input.Obligations[j])
	})
	for index := range input.Changes {
		sort.Slice(input.Changes[index].Boundaries, func(i, j int) bool {
			return input.Changes[index].Boundaries[i] < input.Changes[index].Boundaries[j]
		})
	}
	sort.Slice(input.Changes, func(i, j int) bool {
		return input.Changes[i].Class < input.Changes[j].Class
	})
}

func cloneImpactAssessmentInput(input EvidenceImpactAssessmentInput) EvidenceImpactAssessmentInput {
	input.ParentCandidate = cloneEvidenceCandidate(input.ParentCandidate)
	input.DerivedCandidate = cloneEvidenceCandidate(input.DerivedCandidate)
	input.Obligations = append([]AcceptanceObligationImpact(nil), input.Obligations...)
	input.Changes = append([]EvidenceChange(nil), input.Changes...)
	for index := range input.Changes {
		input.Changes[index].Boundaries = append(
			[]SensitiveBoundary(nil),
			input.Changes[index].Boundaries...,
		)
	}
	return input
}

func cloneEvidenceCandidate(candidate EvidenceCandidateIdentity) EvidenceCandidateIdentity {
	candidate.RequiredReviewAxes = append(
		[]ReviewAxis(nil),
		candidate.RequiredReviewAxes...,
	)
	candidate.SensitiveBoundaries = append(
		[]SensitiveBoundary(nil),
		candidate.SensitiveBoundaries...,
	)
	return candidate
}

func canonicalizeEvidenceCandidate(candidate *EvidenceCandidateIdentity) {
	sort.Slice(candidate.RequiredReviewAxes, func(i, j int) bool {
		return candidate.RequiredReviewAxes[i] < candidate.RequiredReviewAxes[j]
	})
	sort.Slice(candidate.SensitiveBoundaries, func(i, j int) bool {
		return candidate.SensitiveBoundaries[i] < candidate.SensitiveBoundaries[j]
	})
}

func canonicalizeValidationCompatibilityInput(input *ValidationCompatibilityAssessmentInput) {
	canonicalizeEvidenceCandidate(&input.Source.Candidate)
	canonicalizeEvidenceCandidate(&input.Required.Candidate)
	canonicalizeValidationEnvironment(&input.Source.Environment)
	canonicalizeValidationEnvironment(&input.Required.Environment)
}

func cloneValidationCompatibilityInput(
	input ValidationCompatibilityAssessmentInput,
) ValidationCompatibilityAssessmentInput {
	input.Source.Candidate = cloneEvidenceCandidate(input.Source.Candidate)
	input.Required.Candidate = cloneEvidenceCandidate(input.Required.Candidate)
	input.Source.Environment = cloneValidationEnvironment(input.Source.Environment)
	input.Required.Environment = cloneValidationEnvironment(input.Required.Environment)
	return input
}

func cloneValidationEnvironment(environment ValidationEnvironmentIdentity) ValidationEnvironmentIdentity {
	environment.Instrumentation = append(
		[]ValidationInstrumentation(nil),
		environment.Instrumentation...,
	)
	environment.CoveredBoundaries = append(
		[]SensitiveBoundary(nil),
		environment.CoveredBoundaries...,
	)
	return environment
}

func canonicalizeValidationEnvironment(environment *ValidationEnvironmentIdentity) {
	sort.Slice(environment.Instrumentation, func(i, j int) bool {
		return environment.Instrumentation[i] < environment.Instrumentation[j]
	})
	sort.Slice(environment.CoveredBoundaries, func(i, j int) bool {
		return environment.CoveredBoundaries[i] < environment.CoveredBoundaries[j]
	})
}

func obligationImpactKey(impact AcceptanceObligationImpact) string {
	return impact.Parent.CriterionID + "\x00" + string(impact.Parent.Kind) + "\x00" + string(impact.Parent.Phase)
}

func evidenceImpactAssessmentIdentity(assessment EvidenceImpactAssessment) (string, error) {
	assessment.ID = ""
	return canonicalSHA256(assessment)
}

func impactConfirmationIdentity(confirmation ImpactConfirmation) (string, error) {
	confirmation.ID = ""
	return canonicalSHA256(confirmation)
}

func validationCompatibilityIdentity(assessment ValidationCompatibilityAssessment) (string, error) {
	assessment.ID = ""
	return canonicalSHA256(assessment)
}

func canonicalSHA256(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func appendEvidenceInvalidation(decision *EvidenceDerivationDecision, class EvidenceChangeClass, reason string) {
	for _, invalidation := range decision.Invalidations {
		if invalidation.Class == class && invalidation.Reason == reason {
			return
		}
	}
	decision.Invalidations = append(decision.Invalidations, EvidenceInvalidation{Class: class, Reason: reason})
	sort.Slice(decision.Invalidations, func(i, j int) bool {
		if decision.Invalidations[i].Class != decision.Invalidations[j].Class {
			return decision.Invalidations[i].Class < decision.Invalidations[j].Class
		}
		return decision.Invalidations[i].Reason < decision.Invalidations[j].Reason
	})
}

func appendValidationCompatibilityInvalidation(
	decision *ValidationCompatibilityDecision,
	class ValidationInvalidationClass,
	reason string,
) {
	for _, invalidation := range decision.Invalidations {
		if invalidation.Class == class && invalidation.Reason == reason {
			return
		}
	}
	decision.Invalidations = append(decision.Invalidations, ValidationCompatibilityInvalidation{
		Class: class, Reason: reason,
	})
	sort.Slice(decision.Invalidations, func(i, j int) bool {
		if decision.Invalidations[i].Class != decision.Invalidations[j].Class {
			return decision.Invalidations[i].Class < decision.Invalidations[j].Class
		}
		return decision.Invalidations[i].Reason < decision.Invalidations[j].Reason
	})
}

func appendUniqueReviewAxis(values []ReviewAxis, additions ...ReviewAxis) []ReviewAxis {
	for _, addition := range additions {
		if !containsReviewAxis(values, addition) {
			values = append(values, addition)
		}
	}
	return values
}

func appendUniqueBoundaries(values []SensitiveBoundary, additions ...SensitiveBoundary) []SensitiveBoundary {
	for _, addition := range additions {
		found := false
		for _, value := range values {
			if value == addition {
				found = true
				break
			}
		}
		if !found {
			values = append(values, addition)
		}
	}
	return values
}

func containsReviewAxis(values []ReviewAxis, want ReviewAxis) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func subtractReviewAxes(values, removed []ReviewAxis) []ReviewAxis {
	result := make([]ReviewAxis, 0, len(values))
	for _, value := range values {
		if !containsReviewAxis(removed, value) {
			result = append(result, value)
		}
	}
	return result
}

func subtractBoundaries(values, removed []SensitiveBoundary) []SensitiveBoundary {
	result := make([]SensitiveBoundary, 0, len(values))
	for _, value := range values {
		keep := true
		for _, remove := range removed {
			if value == remove {
				keep = false
				break
			}
		}
		if keep {
			result = append(result, value)
		}
	}
	return result
}

func containsBoundary(values []SensitiveBoundary, want SensitiveBoundary) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func changedBoundaries(parent, derived []SensitiveBoundary) []SensitiveBoundary {
	changed := []SensitiveBoundary{}
	for _, boundary := range parent {
		if len(subtractBoundaries([]SensitiveBoundary{boundary}, derived)) > 0 {
			changed = appendUniqueBoundaries(changed, boundary)
		}
	}
	for _, boundary := range derived {
		if len(subtractBoundaries([]SensitiveBoundary{boundary}, parent)) > 0 {
			changed = appendUniqueBoundaries(changed, boundary)
		}
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i] < changed[j] })
	return changed
}

func equalJSON(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func validSHA256(value string) bool {
	return sha256Pattern.MatchString(value)
}

func canonicalDerivationTimestamp(value string, parsed time.Time) bool {
	return !parsed.IsZero() && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
}
