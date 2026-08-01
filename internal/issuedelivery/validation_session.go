package issuedelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

const validationSessionSchema = "packy.validation-session/v1"

type ValidationSessionState string

const (
	ValidationSessionStarted   ValidationSessionState = "started"
	ValidationSessionCompleted ValidationSessionState = "completed"
	ValidationSessionFailed    ValidationSessionState = "failed"
)

type ValidationInstrumentation string

const (
	InstrumentationPackyValidator         ValidationInstrumentation = "packy-validator"
	InstrumentationWorkspaceClean         ValidationInstrumentation = "workspace-clean"
	InstrumentationAcceptanceTraceability ValidationInstrumentation = "acceptance-traceability"
	InstrumentationOperatorState          ValidationInstrumentation = "operator-state"
	InstrumentationSandboxWriteManifest   ValidationInstrumentation = "sandbox-write-manifest"
)

type ValidationInvalidationClass = deliveryevidence.ValidationInvalidationClass

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
	ValidationInvalidationSource              ValidationInvalidationClass = "source"
	ValidationInvalidationCompletion          ValidationInvalidationClass = "completion"
	ValidationInvalidationObligation          ValidationInvalidationClass = "obligation"
	ValidationInvalidationImpact              ValidationInvalidationClass = "impact-assessment"
)

type ValidationSessionObserveRequest struct {
	RunID                   string
	Repository              deliveryevidence.RepositoryIdentity
	Issue                   deliveryevidence.IssueIdentity
	RepositoryPath          string
	CandidateID             string
	CommitSHA               string
	TreeSHA                 string
	HomeRoot                string
	ConfigRoot              string
	RequiredInstrumentation []ValidationInstrumentation
	CoveredBoundaries       []SensitiveBoundary
}

type ValidationSessionObservation struct {
	CheckoutSHA256    string                      `json:"checkout_sha256"`
	CommitSHA         string                      `json:"commit_sha"`
	TreeSHA           string                      `json:"tree_sha"`
	WorkspaceClean    bool                        `json:"workspace_clean"`
	ValidatorIdentity string                      `json:"validator_identity"`
	ValidatorSHA256   string                      `json:"validator_sha256"`
	Command           string                      `json:"command"`
	HomeRoot          string                      `json:"home_root"`
	ConfigRoot        string                      `json:"config_root"`
	Instrumentation   []ValidationInstrumentation `json:"instrumentation"`
	CoveredBoundaries []SensitiveBoundary         `json:"covered_boundaries"`
}

type ValidationSessionExecuteRequest struct {
	Session        ValidationSession
	AcceptanceRows []deliveryevidence.AcceptanceRow
}

type ValidationSessionBoundaryEvidence struct {
	Boundary                  SensitiveBoundary `json:"boundary"`
	OperatorStateBeforeSHA256 string            `json:"operator_state_before_sha256"`
	OperatorStateAfterSHA256  string            `json:"operator_state_after_sha256"`
	SandboxBeforeSHA256       string            `json:"sandbox_before_sha256"`
	SandboxAfterSHA256        string            `json:"sandbox_after_sha256"`
	WriteManifestSHA256       string            `json:"write_manifest_sha256"`
}

type ValidationSessionResult struct {
	SessionID                 string                              `json:"session_id"`
	CommitSHA                 string                              `json:"commit_sha"`
	TreeSHA                   string                              `json:"tree_sha"`
	WorkspaceClean            bool                                `json:"workspace_clean"`
	OperatorStateBeforeSHA256 string                              `json:"operator_state_before_sha256,omitempty"`
	OperatorStateAfterSHA256  string                              `json:"operator_state_after_sha256,omitempty"`
	SandboxBeforeSHA256       string                              `json:"sandbox_before_sha256"`
	SandboxAfterSHA256        string                              `json:"sandbox_after_sha256"`
	Acceptance                []AcceptanceProof                   `json:"acceptance,omitempty"`
	Traceability              []ValidationTrace                   `json:"traceability,omitempty"`
	BoundaryEvidence          []ValidationSessionBoundaryEvidence `json:"boundary_evidence,omitempty"`
	Succeeded                 bool                                `json:"succeeded"`
	Completed                 bool                                `json:"completed"`
}

type ValidationSession struct {
	Schema                     string                              `json:"schema"`
	ID                         string                              `json:"id"`
	Attempt                    int                                 `json:"attempt"`
	State                      ValidationSessionState              `json:"state"`
	RunID                      string                              `json:"run_id"`
	Repository                 deliveryevidence.RepositoryIdentity `json:"repository"`
	Issue                      deliveryevidence.IssueIdentity      `json:"issue"`
	CandidateID                string                              `json:"candidate_id"`
	CommitSHA                  string                              `json:"commit_sha"`
	TreeSHA                    string                              `json:"tree_sha"`
	CheckoutSHA256             string                              `json:"checkout_sha256"`
	ValidatorIdentity          string                              `json:"validator_identity"`
	ValidatorSHA256            string                              `json:"validator_sha256"`
	ValidatorIdentityExpiresAt string                              `json:"validator_identity_expires_at"`
	Command                    string                              `json:"command"`
	HomeRoot                   string                              `json:"home_root"`
	ConfigRoot                 string                              `json:"config_root"`
	WorkspaceClean             bool                                `json:"workspace_clean"`
	Instrumentation            []ValidationInstrumentation         `json:"instrumentation"`
	CoveredBoundaries          []SensitiveBoundary                 `json:"covered_boundaries"`
	StartedAt                  string                              `json:"started_at"`
	CompletedAt                string                              `json:"completed_at,omitempty"`
	Result                     *ValidationSessionResult            `json:"result,omitempty"`
	ResultSHA256               string                              `json:"result_sha256,omitempty"`
	CompletionSHA256           string                              `json:"completion_sha256,omitempty"`
}

type ValidationInvalidation struct {
	SessionID   string                      `json:"session_id"`
	CandidateID string                      `json:"candidate_id"`
	Class       ValidationInvalidationClass `json:"class"`
	ObservedAt  string                      `json:"observed_at"`
	Reason      string                      `json:"reason,omitempty"`
}

type ValidationSessionExecutor interface {
	ObserveValidationSession(
		context.Context,
		ValidationSessionObserveRequest,
	) (ValidationSessionObservation, error)
	ExecuteValidationSession(
		context.Context,
		ValidationSessionExecuteRequest,
	) (ValidationSessionResult, error)
}

func requiredValidationInstrumentation(candidate Candidate) []ValidationInstrumentation {
	required := []ValidationInstrumentation{
		InstrumentationAcceptanceTraceability,
		InstrumentationPackyValidator,
		InstrumentationWorkspaceClean,
	}
	if len(candidate.Boundaries) > 0 {
		required = append(
			required,
			InstrumentationOperatorState,
			InstrumentationSandboxWriteManifest,
		)
	}
	sort.Slice(required, func(i, j int) bool { return required[i] < required[j] })
	return required
}

type validationArtifactRegistry struct {
	record     runRecord
	obligation deliveryevidence.ValidationObligationIdentity
}

func (r validationArtifactRegistry) RegisteredValidationArtifact(sessionID, completionSHA256 string) (deliveryevidence.RegisteredValidationArtifact, bool) {
	session, found := validationSessionByCompletion(r.record.ValidationSessions, completionSHA256)
	if !found || session.ID != sessionID {
		return deliveryevidence.RegisteredValidationArtifact{}, false
	}
	candidate := candidateByID(r.record.Candidates, session.CandidateID)
	if candidate == nil {
		return deliveryevidence.RegisteredValidationArtifact{}, false
	}
	return registeredValidationArtifact(r.record, session, *candidate, r.obligation)
}

func registeredValidationArtifact(
	record runRecord,
	session ValidationSession,
	candidate Candidate,
	obligation deliveryevidence.ValidationObligationIdentity,
) (deliveryevidence.RegisteredValidationArtifact, bool) {
	if session.State != ValidationSessionCompleted || session.Result == nil ||
		!session.Result.Succeeded || !session.Result.Completed {
		return deliveryevidence.RegisteredValidationArtifact{}, false
	}
	switch obligation.Kind {
	case deliveryevidence.ValidationObligationExhaustive:
		if obligation.Boundary != "" {
			return deliveryevidence.RegisteredValidationArtifact{}, false
		}
	case deliveryevidence.ValidationObligationBoundary:
		boundary := SensitiveBoundary(obligation.Boundary)
		if _, found := validationBoundaryEvidence(session.Result.BoundaryEvidence, boundary); !found ||
			!containsAllBoundaries(session.CoveredBoundaries, []SensitiveBoundary{boundary}) {
			return deliveryevidence.RegisteredValidationArtifact{}, false
		}
	default:
		return deliveryevidence.RegisteredValidationArtifact{}, false
	}
	return deliveryevidence.RegisteredValidationArtifact{
		SessionSchema: session.Schema, Kind: deliveryevidence.ValidationArtifactRegisteredSession,
		SessionID: session.ID, CompletionSHA256: session.CompletionSHA256,
		CheckoutSHA256: session.CheckoutSHA256, Candidate: evidenceCandidateIdentity(candidate),
		Environment: validationEnvironment(session), Obligation: obligation,
		ExpiresAt: session.ValidatorIdentityExpiresAt, CompletedAt: canonicalValidationTimestamp(session.CompletedAt),
		WorkspaceClean: session.WorkspaceClean, Succeeded: session.Result.Succeeded,
		Completed:       session.Result.Completed,
		CompletionCount: validationCompletionCount(record.ValidationSessions, session.CompletionSHA256),
	}, true
}

func validationEnvironment(session ValidationSession) deliveryevidence.ValidationEnvironmentIdentity {
	instrumentation := make([]deliveryevidence.ValidationInstrumentation, len(session.Instrumentation))
	for index, value := range session.Instrumentation {
		instrumentation[index] = deliveryevidence.ValidationInstrumentation(value)
	}
	var boundaries []deliveryevidence.SensitiveBoundary
	if len(session.CoveredBoundaries) != 0 {
		boundaries = make([]deliveryevidence.SensitiveBoundary, len(session.CoveredBoundaries))
	}
	for index, value := range session.CoveredBoundaries {
		boundaries[index] = deliveryevidence.SensitiveBoundary(value)
	}
	return deliveryevidence.ValidationEnvironmentIdentity{
		ValidatorIdentity: session.ValidatorIdentity, ValidatorSHA256: session.ValidatorSHA256,
		RequiredCommand: session.Command, HomeRoot: session.HomeRoot, ConfigRoot: session.ConfigRoot,
		Instrumentation: instrumentation, CoveredBoundaries: boundaries,
	}
}

func observedValidationEnvironment(observation ValidationSessionObservation) deliveryevidence.ValidationEnvironmentIdentity {
	session := ValidationSession{
		ValidatorIdentity: observation.ValidatorIdentity, ValidatorSHA256: observation.ValidatorSHA256,
		Command: observation.Command, HomeRoot: observation.HomeRoot, ConfigRoot: observation.ConfigRoot,
		Instrumentation: observation.Instrumentation, CoveredBoundaries: observation.CoveredBoundaries,
	}
	return validationEnvironment(session)
}

func (m *Module) reusableDerivedValidationSession(
	ctx context.Context,
	record *runRecord,
	candidate *Candidate,
	request Request,
) (*ValidationSession, bool, error) {
	derivation := candidate.Derivation
	if derivation == nil || derivation.Confirmation == nil || derivation.FallbackReason != "" ||
		derivation.Decision.ExhaustiveValidationRequired ||
		len(derivation.Decision.FullBoundaryValidations) != 0 {
		return nil, false, nil
	}
	parent := candidateByID(record.Candidates, derivation.ParentCandidateID)
	if parent == nil {
		return nil, false, errors.New("validation derivation parent candidate is unavailable")
	}
	var source *ValidationSession
	for index := range record.ValidationSessions {
		session := &record.ValidationSessions[index]
		if session.CandidateID == parent.ID && session.State == ValidationSessionCompleted &&
			session.Result != nil && session.CompletionSHA256 != "" {
			source = session
		}
	}
	if source == nil {
		for index := len(record.ValidationSessions) - 1; index >= 0; index-- {
			session := record.ValidationSessions[index]
			if session.CandidateID == parent.ID {
				appendValidationInvalidationReason(record, session.ID, candidate.ID,
					ValidationInvalidationFailedExecution,
					"parent validation session did not complete successfully and unambiguously",
					m.clock.Now().UTC())
				break
			}
		}
		return nil, false, nil
	}
	requiredInstrumentation := requiredValidationInstrumentation(*candidate)
	requiredBoundaries := append([]SensitiveBoundary(nil), candidate.Boundaries...)
	sort.Slice(requiredBoundaries, func(i, j int) bool { return requiredBoundaries[i] < requiredBoundaries[j] })
	observation, err := m.validationSession.ObserveValidationSession(ctx, ValidationSessionObserveRequest{
		RunID: record.ID, Repository: record.Repository, Issue: record.Issue,
		RepositoryPath: request.RepositoryPath, CandidateID: candidate.ID,
		CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		HomeRoot: filepath.Join(m.sandboxRoot, "home"), ConfigRoot: filepath.Join(m.sandboxRoot, "config"),
		RequiredInstrumentation: requiredInstrumentation, CoveredBoundaries: requiredBoundaries,
	})
	if err != nil {
		return nil, false, fmt.Errorf("observe derived candidate validation compatibility: %w", err)
	}
	obligations := []deliveryevidence.ValidationObligationIdentity{{Kind: deliveryevidence.ValidationObligationExhaustive}}
	for _, boundary := range requiredBoundaries {
		obligations = append(obligations, deliveryevidence.ValidationObligationIdentity{
			Kind:     deliveryevidence.ValidationObligationBoundary,
			Boundary: deliveryevidence.SensitiveBoundary(boundary),
		})
	}

	assessments := make([]deliveryevidence.ValidationCompatibilityAssessment, 0, len(obligations))
	receipts := make([]deliveryevidence.ValidationDerivationReceipt, 0, len(obligations))
	now := m.clock.Now().UTC()
	for _, obligation := range obligations {
		sourceArtifact, registered := registeredValidationArtifact(*record, *source, *parent, obligation)
		if !registered {
			appendValidationInvalidationReason(record, source.ID, candidate.ID,
				ValidationInvalidationObligation,
				"registered validation session does not prove the required exact obligation", now)
			clearValidationDerivation(candidate)
			return nil, false, nil
		}
		assessment, assessmentErr := deliveryevidence.NewValidationCompatibilityAssessment(deliveryevidence.ValidationCompatibilityAssessmentInput{
			ImpactAssessmentID: derivation.Assessment.ID, ImpactConfirmationID: derivation.Confirmation.ID,
			Source: sourceArtifact,
			Required: deliveryevidence.ValidationCompatibilityRequirement{
				Candidate: evidenceCandidateIdentity(*candidate), CheckoutSHA256: observation.CheckoutSHA256,
				Environment: observedValidationEnvironment(observation), Obligation: obligation,
				ExpiresAt: source.ValidatorIdentityExpiresAt, WorkspaceClean: observation.WorkspaceClean,
			},
		})
		if assessmentErr != nil {
			return nil, false, assessmentErr
		}
		decision, evaluationErr := deliveryevidence.EvaluateValidationCompatibility(
			persistedImpactAuthorAuthority{ImpactAuthority: m.impactAuthority, author: derivation.Assessment.Author},
			validationArtifactRegistry{record: *record, obligation: obligation}, derivation.Assessment,
			[]deliveryevidence.ImpactConfirmation{*derivation.Confirmation}, assessment, now,
		)
		if evaluationErr != nil {
			return nil, false, evaluationErr
		}
		if !decision.Eligible {
			for _, invalidation := range decision.Invalidations {
				appendValidationInvalidationReason(record, source.ID, candidate.ID, invalidation.Class, invalidation.Reason, now)
			}
			clearValidationDerivation(candidate)
			return nil, false, nil
		}
		receipt := deliveryevidence.ValidationDerivationReceipt{
			Schema:          deliveryevidence.ValidationDerivationReceiptSchema,
			SourceSessionID: source.ID, SourceCompletionSHA256: source.CompletionSHA256,
			CompatibilityAssessmentID: assessment.ID, ImpactAssessmentID: derivation.Assessment.ID,
			ConfirmationID: derivation.Confirmation.ID, ParentCandidateID: parent.ID,
			DerivedCandidateID: candidate.ID, Obligation: obligation,
		}
		receipt.Identity = deliveryevidence.ValidationDerivationReceiptIdentity(receipt)
		assessments = append(assessments, assessment)
		receipts = append(receipts, receipt)
	}
	derivation.ValidationCompatibilityAssessments = assessments
	derivation.ValidationDerivationReceipts = receipts
	return derivedValidationSession(*source, *candidate), true, nil
}

func clearValidationDerivation(candidate *Candidate) {
	if candidate == nil || candidate.Derivation == nil {
		return
	}
	candidate.Derivation.ValidationCompatibilityAssessments = nil
	candidate.Derivation.ValidationDerivationReceipts = nil
	keptBoundaries := candidate.BoundaryProofs[:0]
	for _, proof := range candidate.BoundaryProofs {
		if proof.ValidationDerivationReceiptID == "" {
			keptBoundaries = append(keptBoundaries, proof)
		}
	}
	candidate.BoundaryProofs = keptBoundaries
	if candidate.Exhaustive != nil && candidate.Exhaustive.ValidationDerivationReceiptID != "" {
		candidate.Exhaustive = nil
		for index := range candidate.Acceptance {
			reference := candidate.Acceptance[index].ValidationReceipt
			if reference != nil && reference.Schema == deliveryevidence.ValidationReceiptSchema(deliveryevidence.ValidationDerivationReceiptSchema) {
				candidate.Acceptance[index].ValidationReceipt = nil
			}
		}
	}
}

func canonicalValidationTimestamp(value string) string {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return parsed.UTC().Format(time.RFC3339Nano)
}

func candidateByID(candidates []Candidate, id string) *Candidate {
	for index := range candidates {
		if candidates[index].ID == id {
			return &candidates[index]
		}
	}
	return nil
}

func validationCompletionCount(sessions []ValidationSession, completionSHA256 string) int {
	count := 0
	for _, session := range sessions {
		if session.CompletionSHA256 == completionSHA256 {
			count++
		}
	}
	return count
}

func derivedValidationSession(source ValidationSession, candidate Candidate) *ValidationSession {
	derived := source
	derived.CandidateID, derived.CommitSHA, derived.TreeSHA = candidate.ID, candidate.CommitSHA, candidate.TreeSHA
	result := *source.Result
	result.Acceptance = append([]AcceptanceProof(nil), source.Result.Acceptance...)
	result.Traceability = append([]ValidationTrace(nil), source.Result.Traceability...)
	result.BoundaryEvidence = append([]ValidationSessionBoundaryEvidence(nil), source.Result.BoundaryEvidence...)
	result.CommitSHA, result.TreeSHA = candidate.CommitSHA, candidate.TreeSHA
	for index := range result.Traceability {
		result.Traceability[index].CandidateID = candidate.ID
		result.Traceability[index].CommitSHA = candidate.CommitSHA
		result.Traceability[index].TreeSHA = candidate.TreeSHA
	}
	derived.Result = &result
	return &derived
}

func (m *Module) advanceValidationSession(
	ctx context.Context,
	store lockedIssueStore,
	record runRecord,
	candidate Candidate,
	request Request,
) (*ValidationSession, Outcome, bool, error) {
	if m.validationSession == nil {
		return nil, Outcome{}, false, nil
	}
	required := requiredValidationInstrumentation(candidate)
	boundaries := append([]SensitiveBoundary(nil), candidate.Boundaries...)
	sort.Slice(boundaries, func(i, j int) bool { return boundaries[i] < boundaries[j] })
	observation, err := m.validationSession.ObserveValidationSession(
		ctx,
		ValidationSessionObserveRequest{
			RunID: record.ID, Repository: record.Repository, Issue: record.Issue,
			RepositoryPath: request.RepositoryPath, CandidateID: candidate.ID,
			CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
			HomeRoot:                filepath.Join(m.sandboxRoot, "home"),
			ConfigRoot:              filepath.Join(m.sandboxRoot, "config"),
			RequiredInstrumentation: required, CoveredBoundaries: boundaries,
		},
	)
	if err != nil {
		return nil, Outcome{}, false, fmt.Errorf("observe candidate validation session: %w", err)
	}
	now := m.clock.Now().UTC()
	if err := validateValidationSessionObservation(observation, candidate, m.sandboxRoot, required, boundaries); err != nil {
		if latest := latestValidationSession(record.ValidationSessions); latest != nil {
			appendValidationInvalidation(&record, latest.ID, candidate.ID, observationInvalidationClass(*latest, observation, required, boundaries, now), now)
		}
		outcome, persistErr := m.persistAssuranceTransition(
			store, record, StateBlocked,
			"candidate validation session observation is incompatible",
			"validation-session-observation",
		)
		return nil, outcome, true, persistErr
	}

	latest := latestValidationSession(record.ValidationSessions)
	if latest != nil {
		class := validationSessionMismatch(*latest, candidate, observation, required, boundaries, now)
		if class == "" && latest.State == ValidationSessionCompleted {
			return latest, Outcome{}, false, nil
		}
		if class == "" {
			class = ValidationInvalidationFailedExecution
		}
		if latest.State == ValidationSessionStarted {
			latest.State = ValidationSessionFailed
			latest.CompletedAt = now.Format(timeFormat)
		}
		appendValidationInvalidation(&record, latest.ID, candidate.ID, class, now)
	}

	session := newValidationSession(record, candidate, observation, now)
	record.ValidationSessions = append(record.ValidationSessions, session)
	if _, err := m.persistAssuranceTransition(
		store, record, StateNeedsReview,
		"candidate validation session started",
		"validation-session-started",
	); err != nil {
		return nil, Outcome{}, true, err
	}
	_, data, found, err := store.loadActive()
	if err != nil {
		return nil, Outcome{}, true, err
	}
	if !found {
		return nil, Outcome{}, true, errors.New("persisted validation session start is unavailable")
	}
	persisted, err := decodeRun(data)
	if err != nil {
		return nil, Outcome{}, true, err
	}
	started := latestValidationSession(persisted.ValidationSessions)
	if started == nil || started.ID != session.ID || started.State != ValidationSessionStarted {
		return nil, Outcome{}, true, errors.New("persisted validation session start does not match execution")
	}
	if err := advanceOperationProgress(ctx, OperationPhaseValidationSession, started.ID); err != nil {
		return nil, Outcome{}, true, err
	}
	return m.executeStartedValidationSession(
		ctx, store, persisted, candidate, boundaries, started,
	)
}

func (m *Module) executeStartedValidationSession(
	ctx context.Context,
	store lockedIssueStore,
	record runRecord,
	candidate Candidate,
	boundaries []SensitiveBoundary,
	session *ValidationSession,
) (*ValidationSession, Outcome, bool, error) {
	result, executeErr := m.validationSession.ExecuteValidationSession(
		ctx,
		ValidationSessionExecuteRequest{
			Session: *session,
			AcceptanceRows: append(
				[]deliveryevidence.AcceptanceRow(nil),
				record.Evidence.AcceptanceMatrix...,
			),
		},
	)
	if ctxErr := ctx.Err(); ctxErr != nil {
		executeErr = ctxErr
	}
	completed := m.clock.Now().UTC()
	if executeErr != nil {
		session.State = ValidationSessionFailed
		session.CompletedAt = completed.Format(timeFormat)
		appendValidationInvalidation(
			&record, session.ID, candidate.ID,
			ValidationInvalidationFailedExecution, completed,
		)
		outcome, persistErr := m.persistAssuranceTransition(
			store, record, StateBlocked,
			"candidate validation session execution failed",
			"validation-session-failed",
		)
		if persistErr != nil {
			return nil, Outcome{}, true, persistErr
		}
		return nil, outcome, true, fmt.Errorf(
			"execute candidate validation session: %w",
			executeErr,
		)
	}
	if err := validateValidationSessionResult(
		result, *session, candidate, boundaries,
		record.Evidence.AcceptanceMatrix,
	); err != nil {
		session.State = ValidationSessionFailed
		session.CompletedAt = completed.Format(timeFormat)
		appendValidationInvalidation(
			&record, session.ID, candidate.ID,
			ValidationInvalidationFailedExecution, completed,
		)
		outcome, persistErr := m.persistAssuranceTransition(
			store, record, StateBlocked,
			"candidate validation session result is invalid",
			"validation-session-failed",
		)
		return nil, outcome, true, persistErr
	}
	resultSHA, err := validationSessionResultDigest(result)
	if err != nil {
		return nil, Outcome{}, true, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		session.State = ValidationSessionFailed
		session.CompletedAt = completed.Format(timeFormat)
		appendValidationInvalidation(
			&record, session.ID, candidate.ID,
			ValidationInvalidationFailedExecution, completed,
		)
		outcome, persistErr := m.persistAssuranceTransition(
			store, record, StateBlocked,
			"candidate validation session execution failed",
			"validation-session-failed",
		)
		if persistErr != nil {
			return nil, Outcome{}, true, persistErr
		}
		return nil, outcome, true, fmt.Errorf("execute candidate validation session: %w", ctxErr)
	}
	session.State = ValidationSessionCompleted
	session.CompletedAt = completed.Format(timeFormat)
	session.Result = &result
	session.ResultSHA256 = resultSHA
	session.CompletionSHA256 = validationSessionCompletionIdentity(*session)
	outcome, persistErr := m.persistAssuranceTransition(
		store, record, StateNeedsReview,
		"candidate validation session completed",
		"validation-session-completed",
	)
	return nil, outcome, true, persistErr
}

func newValidationSession(
	record runRecord,
	candidate Candidate,
	observation ValidationSessionObservation,
	started time.Time,
) ValidationSession {
	session := ValidationSession{
		Schema: validationSessionSchema, Attempt: len(record.ValidationSessions) + 1,
		State: ValidationSessionStarted,
		RunID: record.ID, Repository: record.Repository, Issue: record.Issue,
		CandidateID: candidate.ID, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		CheckoutSHA256:    observation.CheckoutSHA256,
		ValidatorIdentity: observation.ValidatorIdentity, ValidatorSHA256: observation.ValidatorSHA256,
		ValidatorIdentityExpiresAt: started.Add(24 * time.Hour).Format(time.RFC3339Nano),
		Command:                    observation.Command, HomeRoot: observation.HomeRoot, ConfigRoot: observation.ConfigRoot,
		WorkspaceClean:    observation.WorkspaceClean,
		Instrumentation:   append([]ValidationInstrumentation(nil), observation.Instrumentation...),
		CoveredBoundaries: append([]SensitiveBoundary(nil), observation.CoveredBoundaries...),
		StartedAt:         started.Format(timeFormat),
	}
	session.ID = validationSessionIdentity(session)
	return session
}

func validationSessionIdentity(session ValidationSession) string {
	identity := struct {
		Schema, RunID, CandidateID, CommitSHA, TreeSHA, CheckoutSHA256 string
		Attempt                                                        int
		Repository                                                     deliveryevidence.RepositoryIdentity
		Issue                                                          deliveryevidence.IssueIdentity
		ValidatorIdentity, ValidatorSHA256, ValidatorIdentityExpiresAt string
		Command, HomeRoot, ConfigRoot, StartedAt                       string
		WorkspaceClean                                                 bool
		Instrumentation                                                []ValidationInstrumentation
		CoveredBoundaries                                              []SensitiveBoundary
	}{
		session.Schema, session.RunID, session.CandidateID, session.CommitSHA, session.TreeSHA,
		session.CheckoutSHA256, session.Attempt, session.Repository, session.Issue,
		session.ValidatorIdentity, session.ValidatorSHA256, session.ValidatorIdentityExpiresAt,
		session.Command, session.HomeRoot, session.ConfigRoot, session.StartedAt,
		session.WorkspaceClean, session.Instrumentation, session.CoveredBoundaries,
	}
	raw, _ := json.Marshal(identity)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validationSessionResultDigest(result ValidationSessionResult) (string, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func validationSessionCompletionIdentity(session ValidationSession) string {
	identity := struct {
		ExecutionID       string
		State             ValidationSessionState
		CompletedAt       string
		Expiry            string
		ResultSHA256      string
		Succeeded         bool
		Completed         bool
		WorkspaceClean    bool
		Instrumentation   []ValidationInstrumentation
		CoveredBoundaries []SensitiveBoundary
	}{
		ExecutionID: session.ID, State: session.State, CompletedAt: session.CompletedAt,
		Expiry: session.ValidatorIdentityExpiresAt, ResultSHA256: session.ResultSHA256,
		Succeeded:      session.Result != nil && session.Result.Succeeded,
		Completed:      session.Result != nil && session.Result.Completed,
		WorkspaceClean: session.Result != nil && session.Result.WorkspaceClean,
		Instrumentation: append(
			[]ValidationInstrumentation(nil),
			session.Instrumentation...,
		),
		CoveredBoundaries: append([]SensitiveBoundary(nil), session.CoveredBoundaries...),
	}
	raw, _ := json.Marshal(identity)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validateValidationSessionObservation(
	observation ValidationSessionObservation,
	candidate Candidate,
	sandboxRoot string,
	required []ValidationInstrumentation,
	boundaries []SensitiveBoundary,
) error {
	if observation.CommitSHA != candidate.CommitSHA || observation.TreeSHA != candidate.TreeSHA ||
		!observation.WorkspaceClean ||
		!runIDPattern.MatchString(observation.CheckoutSHA256) ||
		strings.TrimSpace(observation.ValidatorIdentity) == "" ||
		!runIDPattern.MatchString(observation.ValidatorSHA256) ||
		observation.Command != "./scripts/validate-packy.sh" ||
		observation.HomeRoot != filepath.Join(sandboxRoot, "home") ||
		observation.ConfigRoot != filepath.Join(sandboxRoot, "config") ||
		!canonicalInstrumentation(observation.Instrumentation) ||
		!containsAllInstrumentation(observation.Instrumentation, required) ||
		!canonicalBoundaries(observation.CoveredBoundaries) ||
		!containsAllBoundaries(observation.CoveredBoundaries, boundaries) {
		return errors.New("validation session observation does not cover the exact clean candidate")
	}
	return nil
}

func validateValidationSessionResult(
	result ValidationSessionResult,
	session ValidationSession,
	candidate Candidate,
	boundaries []SensitiveBoundary,
	acceptanceRows []deliveryevidence.AcceptanceRow,
) error {
	if result.SessionID != session.ID || result.CommitSHA != candidate.CommitSHA ||
		result.TreeSHA != candidate.TreeSHA || !result.WorkspaceClean ||
		!result.Succeeded || !result.Completed ||
		!runIDPattern.MatchString(result.SandboxBeforeSHA256) ||
		!runIDPattern.MatchString(result.SandboxAfterSHA256) {
		return errors.New("validation session result does not prove the exact clean candidate")
	}
	if len(boundaries) > 0 &&
		(!runIDPattern.MatchString(result.OperatorStateBeforeSHA256) ||
			result.OperatorStateBeforeSHA256 != result.OperatorStateAfterSHA256) {
		return errors.New("validation session result does not preserve protected operator state")
	}
	if len(result.BoundaryEvidence) != len(boundaries) {
		return errors.New("validation session result lacks boundary-keyed evidence")
	}
	for index, boundary := range boundaries {
		evidence := result.BoundaryEvidence[index]
		if evidence.Boundary != boundary ||
			evidence.OperatorStateBeforeSHA256 != result.OperatorStateBeforeSHA256 ||
			evidence.OperatorStateAfterSHA256 != result.OperatorStateAfterSHA256 ||
			evidence.SandboxBeforeSHA256 != result.SandboxBeforeSHA256 ||
			evidence.SandboxAfterSHA256 != result.SandboxAfterSHA256 ||
			evidence.WriteManifestSHA256 != ValidationBoundaryWriteManifest(
				session, boundary, evidence.SandboxBeforeSHA256, evidence.SandboxAfterSHA256,
			) {
			return errors.New("validation session boundary evidence is invalid")
		}
	}
	if phaseOwnedAcceptance(acceptanceRows) {
		if len(result.Acceptance) != 0 ||
			validateValidationTraceability(result.Traceability, acceptanceRows, candidate) != nil {
			return errors.New("validation session result lacks exact acceptance traceability")
		}
	}
	return nil
}

func ValidationBoundaryWriteManifest(
	session ValidationSession,
	boundary SensitiveBoundary,
	sandboxBefore, sandboxAfter string,
) string {
	manifest := sha256.Sum256([]byte(strings.Join([]string{
		session.ID, string(boundary), session.CandidateID,
		session.CommitSHA, session.TreeSHA,
		session.HomeRoot, sandboxBefore,
		session.ConfigRoot, sandboxAfter,
	}, "\x00")))
	return hex.EncodeToString(manifest[:])
}

func validationSessionMismatch(
	session ValidationSession,
	candidate Candidate,
	observation ValidationSessionObservation,
	required []ValidationInstrumentation,
	boundaries []SensitiveBoundary,
	now time.Time,
) ValidationInvalidationClass {
	switch {
	case session.CandidateID != candidate.ID:
		return ValidationInvalidationCandidate
	case session.CommitSHA != candidate.CommitSHA:
		return ValidationInvalidationCommit
	case session.TreeSHA != candidate.TreeSHA:
		return ValidationInvalidationTree
	case session.CheckoutSHA256 != observation.CheckoutSHA256:
		return ValidationInvalidationCheckout
	case session.ValidatorIdentity != observation.ValidatorIdentity ||
		session.ValidatorSHA256 != observation.ValidatorSHA256:
		return ValidationInvalidationValidator
	case session.Command != observation.Command:
		return ValidationInvalidationCommand
	case session.HomeRoot != observation.HomeRoot || session.ConfigRoot != observation.ConfigRoot:
		return ValidationInvalidationSandbox
	case !containsAllInstrumentation(session.Instrumentation, required) ||
		!containsAllInstrumentation(observation.Instrumentation, required):
		return ValidationInvalidationInstrumentation
	case !containsAllBoundaries(session.CoveredBoundaries, boundaries) ||
		!containsAllBoundaries(observation.CoveredBoundaries, boundaries):
		return ValidationInvalidationBoundaryRequirement
	case !session.WorkspaceClean || !observation.WorkspaceClean:
		return ValidationInvalidationWorkspace
	}
	expires, err := parseCanonicalValidationSessionExpiry(session.ValidatorIdentityExpiresAt)
	if err != nil || !now.Before(expires) {
		return ValidationInvalidationExpiry
	}
	if session.State == ValidationSessionFailed {
		return ValidationInvalidationFailedExecution
	}
	return ""
}

func observationInvalidationClass(
	session ValidationSession,
	observation ValidationSessionObservation,
	required []ValidationInstrumentation,
	boundaries []SensitiveBoundary,
	now time.Time,
) ValidationInvalidationClass {
	candidate := Candidate{
		ID: session.CandidateID, CommitSHA: observation.CommitSHA, TreeSHA: observation.TreeSHA,
	}
	class := validationSessionMismatch(session, candidate, observation, required, boundaries, now)
	if class == "" {
		return ValidationInvalidationWorkspace
	}
	return class
}

func latestValidationSession(sessions []ValidationSession) *ValidationSession {
	if len(sessions) == 0 {
		return nil
	}
	return &sessions[len(sessions)-1]
}

func appendValidationInvalidation(
	record *runRecord,
	sessionID, candidateID string,
	class ValidationInvalidationClass,
	observed time.Time,
) {
	appendValidationInvalidationReason(record, sessionID, candidateID, class, "", observed)
}

func appendValidationInvalidationReason(
	record *runRecord,
	sessionID, candidateID string,
	class ValidationInvalidationClass,
	reason string,
	observed time.Time,
) {
	if class == "" {
		return
	}
	for _, invalidation := range record.ValidationInvalidations {
		if invalidation.SessionID == sessionID &&
			invalidation.CandidateID == candidateID &&
			invalidation.Class == class {
			return
		}
	}
	record.ValidationInvalidations = append(record.ValidationInvalidations, ValidationInvalidation{
		SessionID: sessionID, CandidateID: candidateID, Class: class,
		ObservedAt: observed.Format(timeFormat), Reason: reason,
	})
}

func validationDerivationReceiptID(candidate *Candidate, obligation deliveryevidence.ValidationObligationIdentity) string {
	if candidate == nil || candidate.Derivation == nil {
		return ""
	}
	for _, receipt := range candidate.Derivation.ValidationDerivationReceipts {
		if receipt.Obligation == obligation {
			return receipt.Identity
		}
	}
	return ""
}

func canonicalInstrumentation(values []ValidationInstrumentation) bool {
	if len(values) == 0 {
		return false
	}
	for index, value := range values {
		if index > 0 && values[index-1] >= value {
			return false
		}
		switch value {
		case InstrumentationPackyValidator, InstrumentationWorkspaceClean,
			InstrumentationAcceptanceTraceability, InstrumentationOperatorState,
			InstrumentationSandboxWriteManifest:
		default:
			return false
		}
	}
	return true
}

func containsAllInstrumentation(have, required []ValidationInstrumentation) bool {
	set := make(map[ValidationInstrumentation]bool, len(have))
	for _, value := range have {
		set[value] = true
	}
	for _, value := range required {
		if !set[value] {
			return false
		}
	}
	return true
}

func canonicalBoundaries(values []SensitiveBoundary) bool {
	for index, value := range values {
		if index > 0 && values[index-1] >= value {
			return false
		}
		if specialistForBoundary(value) == "" {
			return false
		}
	}
	return true
}

func containsAllBoundaries(have, required []SensitiveBoundary) bool {
	set := make(map[SensitiveBoundary]bool, len(have))
	for _, value := range have {
		set[value] = true
	}
	for _, value := range required {
		if !set[value] {
			return false
		}
	}
	return true
}

func validateValidationSessions(record runRecord) error {
	if record.Schema == legacyRunSchema {
		if len(record.ValidationSessions) != 0 || len(record.ValidationInvalidations) != 0 {
			return errors.New("legacy issue delivery run cannot contain validation sessions")
		}
		return nil
	}
	candidates := make(map[string]Candidate, len(record.Candidates))
	for _, candidate := range record.Candidates {
		candidates[candidate.ID] = candidate
	}
	sessionIDs := make(map[string]bool, len(record.ValidationSessions))
	for sessionIndex, session := range record.ValidationSessions {
		candidate, found := candidates[session.CandidateID]
		started, startErr := time.Parse(timeFormat, session.StartedAt)
		expires, expiryErr := parseCanonicalValidationSessionExpiry(
			session.ValidatorIdentityExpiresAt,
		)
		if !found || session.Schema != validationSessionSchema ||
			session.Attempt != sessionIndex+1 || session.RunID != record.ID ||
			session.Repository != record.Repository || session.Issue != record.Issue ||
			session.CommitSHA != candidate.CommitSHA || session.TreeSHA != candidate.TreeSHA ||
			session.ID != validationSessionIdentity(session) || sessionIDs[session.ID] ||
			!runIDPattern.MatchString(session.CheckoutSHA256) ||
			strings.TrimSpace(session.ValidatorIdentity) == "" ||
			!runIDPattern.MatchString(session.ValidatorSHA256) ||
			session.Command != "./scripts/validate-packy.sh" ||
			!filepath.IsAbs(session.HomeRoot) || !filepath.IsAbs(session.ConfigRoot) ||
			filepath.Clean(session.HomeRoot) != session.HomeRoot ||
			filepath.Clean(session.ConfigRoot) != session.ConfigRoot ||
			session.HomeRoot == session.ConfigRoot || !session.WorkspaceClean ||
			!canonicalInstrumentation(session.Instrumentation) ||
			!canonicalBoundaries(session.CoveredBoundaries) ||
			startErr != nil || expiryErr != nil || !expires.After(started) {
			return errors.New("issue delivery validation session identity is invalid")
		}
		sessionIDs[session.ID] = true
		switch session.State {
		case ValidationSessionStarted:
			if session.CompletedAt != "" || session.Result != nil ||
				session.ResultSHA256 != "" || session.CompletionSHA256 != "" {
				return errors.New("started validation session contains completion evidence")
			}
		case ValidationSessionCompleted:
			completed, err := time.Parse(timeFormat, session.CompletedAt)
			if err != nil || completed.Before(started) || session.Result == nil {
				return errors.New("completed validation session timing is invalid")
			}
			if err := validateValidationSessionResult(
				*session.Result, session, candidate, session.CoveredBoundaries,
				record.Evidence.AcceptanceMatrix,
			); err != nil {
				return err
			}
			digest, err := validationSessionResultDigest(*session.Result)
			if err != nil || digest != session.ResultSHA256 {
				return errors.New("completed validation session result identity is invalid")
			}
			if session.CompletionSHA256 != validationSessionCompletionIdentity(session) {
				return errors.New("completed validation session identity is invalid")
			}
		case ValidationSessionFailed:
			if _, err := time.Parse(timeFormat, session.CompletedAt); err != nil ||
				session.Result != nil || session.ResultSHA256 != "" ||
				session.CompletionSHA256 != "" {
				return errors.New("failed validation session state is invalid")
			}
		default:
			return errors.New("issue delivery validation session state is invalid")
		}
	}
	seenInvalidations := map[string]bool{}
	for _, invalidation := range record.ValidationInvalidations {
		key := strings.Join([]string{
			invalidation.SessionID, invalidation.CandidateID, string(invalidation.Class),
		}, "\x00")
		if !sessionIDs[invalidation.SessionID] || candidates[invalidation.CandidateID].ID == "" ||
			seenInvalidations[key] {
			return errors.New("issue delivery validation invalidation identity is invalid")
		}
		seenInvalidations[key] = true
		if _, err := time.Parse(timeFormat, invalidation.ObservedAt); err != nil {
			return errors.New("issue delivery validation invalidation time is invalid")
		}
		if invalidation.Reason != "" && (strings.TrimSpace(invalidation.Reason) != invalidation.Reason || len(invalidation.Reason) > 240) {
			return errors.New("issue delivery validation invalidation reason is invalid")
		}
		switch invalidation.Class {
		case ValidationInvalidationCandidate, ValidationInvalidationCommit,
			ValidationInvalidationTree, ValidationInvalidationCheckout,
			ValidationInvalidationValidator, ValidationInvalidationCommand,
			ValidationInvalidationSandbox, ValidationInvalidationInstrumentation,
			ValidationInvalidationBoundaryRequirement, ValidationInvalidationExpiry,
			ValidationInvalidationWorkspace, ValidationInvalidationFailedExecution,
			ValidationInvalidationSource, ValidationInvalidationCompletion,
			ValidationInvalidationObligation, ValidationInvalidationImpact:
		default:
			return errors.New("issue delivery validation invalidation class is invalid")
		}
	}
	for _, candidate := range record.Candidates {
		for _, proof := range candidate.BoundaryProofs {
			if proof.ValidationCompletionSHA256 == "" {
				continue
			}
			session, found := validationSessionByCompletion(
				record.ValidationSessions,
				proof.ValidationCompletionSHA256,
			)
			if !found || session.State != ValidationSessionCompleted ||
				!validValidationProofOwner(candidate, session, proof.ValidationDerivationReceiptID,
					deliveryevidence.ValidationObligationIdentity{Kind: deliveryevidence.ValidationObligationBoundary, Boundary: deliveryevidence.SensitiveBoundary(proof.Result.Boundary)}) ||
				!containsAllBoundaries(session.CoveredBoundaries, []SensitiveBoundary{proof.Result.Boundary}) {
				return errors.New("boundary proof validation session reference is invalid")
			}
		}
		if candidate.Exhaustive == nil ||
			candidate.Exhaustive.ValidationCompletionSHA256 == "" {
			continue
		}
		session, found := validationSessionByCompletion(
			record.ValidationSessions,
			candidate.Exhaustive.ValidationCompletionSHA256,
		)
		if !found || session.State != ValidationSessionCompleted ||
			!validValidationProofOwner(candidate, session, candidate.Exhaustive.ValidationDerivationReceiptID,
				deliveryevidence.ValidationObligationIdentity{Kind: deliveryevidence.ValidationObligationExhaustive}) {
			return errors.New("exhaustive validation session reference is invalid")
		}
	}
	return nil
}

func validValidationProofOwner(candidate Candidate, session ValidationSession, receiptID string, obligation deliveryevidence.ValidationObligationIdentity) bool {
	if session.CandidateID == candidate.ID {
		return receiptID == ""
	}
	if candidate.Derivation == nil || receiptID == "" {
		return false
	}
	for _, receipt := range candidate.Derivation.ValidationDerivationReceipts {
		if receipt.Identity == receiptID && receipt.SourceSessionID == session.ID &&
			receipt.SourceCompletionSHA256 == session.CompletionSHA256 &&
			receipt.ParentCandidateID == session.CandidateID &&
			receipt.DerivedCandidateID == candidate.ID && receipt.Obligation == obligation {
			return true
		}
	}
	return false
}

func parseCanonicalValidationSessionExpiry(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC ||
		parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("validation session expiry is not canonical")
	}
	return parsed, nil
}

func validationSessionByCompletion(
	sessions []ValidationSession,
	completionSHA256 string,
) (ValidationSession, bool) {
	for _, session := range sessions {
		if session.CompletionSHA256 == completionSHA256 {
			return session, true
		}
	}
	return ValidationSession{}, false
}

func boundaryProofsFromValidationSession(
	session ValidationSession,
	candidate Candidate,
	boundaries []SensitiveBoundary,
	completedAt string,
) []BoundaryProof {
	proofs := make([]BoundaryProof, 0, len(boundaries))
	for _, boundary := range boundaries {
		evidence, found := validationBoundaryEvidence(
			session.Result.BoundaryEvidence,
			boundary,
		)
		if !found {
			continue
		}
		proofs = append(proofs, BoundaryProof{
			ValidationCompletionSHA256: session.CompletionSHA256,
			Result: BoundaryValidationResult{
				CandidateID: candidate.ID, Boundary: boundary,
				CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
				Command: session.Command, ToolIdentity: session.ValidatorIdentity,
				ToolSHA256: session.ValidatorSHA256, HomeRoot: session.HomeRoot,
				ConfigRoot:                session.ConfigRoot,
				OperatorStateBeforeSHA256: evidence.OperatorStateBeforeSHA256,
				OperatorStateAfterSHA256:  evidence.OperatorStateAfterSHA256,
				WriteManifestSHA256:       evidence.WriteManifestSHA256,
				Evidence:                  "boundary proof derived from immutable candidate validation session " + session.CompletionSHA256,
				Sandboxed:                 true, Succeeded: true, Completed: true,
			},
			CompletedAt: completedAt,
		})
	}
	return proofs
}

func validationBoundaryEvidence(
	values []ValidationSessionBoundaryEvidence,
	boundary SensitiveBoundary,
) (ValidationSessionBoundaryEvidence, bool) {
	for _, value := range values {
		if value.Boundary == boundary {
			return value, true
		}
	}
	return ValidationSessionBoundaryEvidence{}, false
}

func exhaustiveResultFromValidationSession(session ValidationSession) ValidationResult {
	return ValidationResult{
		CommitSHA: session.CommitSHA, TreeSHA: session.TreeSHA,
		Command: session.Command, HomeRoot: session.HomeRoot, ConfigRoot: session.ConfigRoot,
		CheckoutSHA256:    session.CheckoutSHA256,
		ValidatorIdentity: session.ValidatorIdentity, ValidatorSHA256: session.ValidatorSHA256,
		ValidatorIdentityExpiresAt: session.ValidatorIdentityExpiresAt,
		WorkspaceClean:             session.WorkspaceClean, Sandboxed: true,
		Succeeded: true, Completed: true,
		Acceptance:   append([]AcceptanceProof(nil), session.Result.Acceptance...),
		Traceability: append([]ValidationTrace(nil), session.Result.Traceability...),
	}
}
