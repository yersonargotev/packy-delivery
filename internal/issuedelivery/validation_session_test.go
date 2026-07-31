package issuedelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

type fakeValidationSessionExecutor struct {
	observeCalls int
	executeCalls int
	executeHook  func(ValidationSession)
	executeErr   error
}

func readActiveValidationSessionRecord(
	t *testing.T,
	commonDir string,
	issue int,
) ([]byte, runRecord) {
	t.Helper()
	issueRoot := filepath.Join(
		commonDir, "packy", "issue-delivery", "issue-"+fmt.Sprint(issue),
	)
	activeBytes, err := os.ReadFile(filepath.Join(issueRoot, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	var active activeRun
	if err := json.Unmarshal(activeBytes, &active); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(issueRoot, "runs", active.RunID+".json")
	if active.Revision != "" {
		path = filepath.Join(issueRoot, "revisions", active.RunID, active.Revision+".json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeRun(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, record
}

func (f *fakeValidationSessionExecutor) ObserveValidationSession(
	_ context.Context,
	request ValidationSessionObserveRequest,
) (ValidationSessionObservation, error) {
	f.observeCalls++
	return ValidationSessionObservation{
		CheckoutSHA256:    strings.Repeat("7", 64),
		CommitSHA:         request.CommitSHA,
		TreeSHA:           request.TreeSHA,
		WorkspaceClean:    true,
		ValidatorIdentity: "scripts/validate-packy.sh",
		ValidatorSHA256:   strings.Repeat("8", 64),
		Command:           "./scripts/validate-packy.sh",
		HomeRoot:          request.HomeRoot,
		ConfigRoot:        request.ConfigRoot,
		Instrumentation: append(
			[]ValidationInstrumentation(nil),
			request.RequiredInstrumentation...,
		),
		CoveredBoundaries: append(
			[]SensitiveBoundary(nil),
			request.CoveredBoundaries...,
		),
	}, nil
}

func (f *fakeValidationSessionExecutor) ExecuteValidationSession(
	_ context.Context,
	request ValidationSessionExecuteRequest,
) (ValidationSessionResult, error) {
	f.executeCalls++
	if f.executeHook != nil {
		f.executeHook(request.Session)
	}
	if f.executeErr != nil {
		return ValidationSessionResult{}, f.executeErr
	}
	result := ValidationSessionResult{
		SessionID:                 request.Session.ID,
		CommitSHA:                 request.Session.CommitSHA,
		TreeSHA:                   request.Session.TreeSHA,
		WorkspaceClean:            true,
		OperatorStateBeforeSHA256: strings.Repeat("9", 64),
		OperatorStateAfterSHA256:  strings.Repeat("9", 64),
		SandboxBeforeSHA256:       strings.Repeat("a", 64),
		SandboxAfterSHA256:        strings.Repeat("b", 64),
		Succeeded:                 true,
		Completed:                 true,
	}
	for _, row := range request.AcceptanceRows {
		if len(row.Obligations) == 0 {
			continue
		}
		result.Traceability = append(result.Traceability, ValidationTrace{
			Identity: row.Identity, CandidateID: request.Session.CandidateID,
			Phase:     deliveryevidence.AssuranceExhaustiveValidation,
			CommitSHA: request.Session.CommitSHA, TreeSHA: request.Session.TreeSHA,
		})
	}
	for _, boundary := range request.Session.CoveredBoundaries {
		result.BoundaryEvidence = append(
			result.BoundaryEvidence,
			ValidationSessionBoundaryEvidence{
				Boundary:                  boundary,
				OperatorStateBeforeSHA256: result.OperatorStateBeforeSHA256,
				OperatorStateAfterSHA256:  result.OperatorStateAfterSHA256,
				SandboxBeforeSHA256:       result.SandboxBeforeSHA256,
				SandboxAfterSHA256:        result.SandboxAfterSHA256,
				WriteManifestSHA256: ValidationBoundaryWriteManifest(
					request.Session,
					boundary,
					result.SandboxBeforeSHA256,
					result.SandboxAfterSHA256,
				),
			},
		)
	}
	return result, nil
}

func TestValidationSessionRunsCandidateValidatorOnceAndDerivesAllAssuranceArtifacts(t *testing.T) {
	module, git, _, _, validator := assuranceFixture(t)
	module.risk.(*fakeCandidateRiskObserver).effects = []EffectObservation{
		{Effect: EffectSecurity, Evidence: "changes credential handling", Complete: true},
		{Effect: EffectRealConfiguration, Evidence: "writes real configuration", Complete: true},
	}
	specialist := &fakeSpecialistReviewExecutor{}
	boundary := &fakeBoundaryValidationExecutor{}
	session := &fakeValidationSessionExecutor{}
	session.executeHook = func(ValidationSession) {
		_, persisted := readActiveValidationSessionRecord(t, git.value.CommonDir, 357)
		if len(persisted.ValidationSessions) != 1 ||
			persisted.ValidationSessions[0].State != ValidationSessionStarted {
			t.Fatalf("validation execution began before durable start: %#v", persisted.ValidationSessions)
		}
	}
	module.specialist = specialist
	module.boundary = boundary
	module.validationSession = session
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}

	var outcome Outcome
	for step := 0; step < 15; step++ {
		var err error
		outcome, err = module.Advance(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.LocalReadiness != nil {
			break
		}
	}
	if outcome.LocalReadiness == nil || outcome.Candidate == nil {
		t.Fatalf("candidate did not reach local readiness: %#v", outcome)
	}
	if session.executeCalls != 1 || validator.exhaustiveCalls != 0 || len(boundary.calls) != 0 {
		t.Fatalf(
			"session executions=%d legacy exhaustive=%d legacy boundaries=%v",
			session.executeCalls, validator.exhaustiveCalls, boundary.calls,
		)
	}
	if len(outcome.Candidate.BoundaryProofs) != 2 {
		t.Fatalf("boundary proofs=%#v", outcome.Candidate.BoundaryProofs)
	}
	completionSHA256 := outcome.Candidate.Exhaustive.ValidationCompletionSHA256
	if completionSHA256 == "" {
		t.Fatal("exhaustive proof does not reference its validation session")
	}
	for _, proof := range outcome.Candidate.BoundaryProofs {
		if proof.ValidationCompletionSHA256 != completionSHA256 {
			t.Fatalf(
				"boundary proof completion=%q exhaustive completion=%q",
				proof.ValidationCompletionSHA256,
				completionSHA256,
			)
		}
	}
	raw, record := readActiveValidationSessionRecord(t, git.value.CommonDir, 357)
	if len(record.ValidationSessions) != 1 ||
		record.ValidationSessions[0].CompletionSHA256 != completionSHA256 {
		t.Fatalf("persisted validation sessions=%#v", record.ValidationSessions)
	}
	reencoded, err := encodeRun(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, reencoded) {
		t.Fatal("completed validation session did not recover to identical canonical bytes")
	}

	if _, err := module.Advance(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if session.executeCalls != 1 {
		t.Fatalf("completed validation session reran: executions=%d", session.executeCalls)
	}
}

func TestFailedValidationSessionPersistsFailureWithoutAssuranceArtifacts(t *testing.T) {
	module, git, _, _, validator := assuranceFixture(t)
	session := &fakeValidationSessionExecutor{executeErr: errors.New("validator failed")}
	module.validationSession = session
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}

	var outcome Outcome
	var advanceErr error
	for step := 0; step < 10; step++ {
		outcome, advanceErr = module.Advance(context.Background(), request)
		if advanceErr != nil {
			break
		}
	}
	if advanceErr == nil || !strings.Contains(advanceErr.Error(), "validator failed") {
		t.Fatalf("failed session outcome=%#v error=%v", outcome, advanceErr)
	}
	_, record := readActiveValidationSessionRecord(t, git.value.CommonDir, 357)
	latest := latestValidationSession(record.ValidationSessions)
	candidate := latestCandidate(&record)
	if latest == nil || latest.State != ValidationSessionFailed ||
		candidate == nil || len(candidate.BoundaryProofs) != 0 || candidate.Exhaustive != nil {
		t.Fatalf("failed session produced assurance evidence: session=%#v candidate=%#v", latest, candidate)
	}
	if validator.exhaustiveCalls != 0 {
		t.Fatalf("failed session fell back to legacy exhaustive validation: %d", validator.exhaustiveCalls)
	}
}

func TestRestartInvalidatesAmbiguousStartedSessionBeforeFreshExecution(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	var outcome Outcome
	for step := 0; step < 5; step++ {
		var err error
		outcome, err = module.Advance(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(outcome.Reason, "candidate reviews completed") {
			break
		}
	}
	if outcome.Candidate == nil || !strings.Contains(outcome.Reason, "candidate reviews completed") {
		t.Fatalf("candidate did not reach the pre-validation pause: %#v", outcome)
	}
	err := module.store.withIssueLock(
		context.Background(),
		git.value.CommonDir,
		request.IssueNumber,
		func(store lockedIssueStore) error {
			_, data, found, loadErr := store.loadActive()
			if loadErr != nil {
				return loadErr
			}
			if !found {
				return errors.New("active run is unavailable")
			}
			record, decodeErr := decodeRun(data)
			if decodeErr != nil {
				return decodeErr
			}
			candidate := latestCandidate(&record)
			required := requiredValidationInstrumentation(*candidate)
			started := newValidationSession(
				record,
				*candidate,
				ValidationSessionObservation{
					CheckoutSHA256:    strings.Repeat("7", 64),
					CommitSHA:         candidate.CommitSHA,
					TreeSHA:           candidate.TreeSHA,
					WorkspaceClean:    true,
					ValidatorIdentity: "scripts/validate-packy.sh",
					ValidatorSHA256:   strings.Repeat("8", 64),
					Command:           "./scripts/validate-packy.sh",
					HomeRoot:          filepath.Join(module.sandboxRoot, "home"),
					ConfigRoot:        filepath.Join(module.sandboxRoot, "config"),
					Instrumentation:   required,
					CoveredBoundaries: []SensitiveBoundary{},
				},
				module.clock.Now().UTC(),
			)
			record.ValidationSessions = append(record.ValidationSessions, started)
			encoded, encodeErr := encodeRun(record)
			if encodeErr != nil {
				return encodeErr
			}
			_, storeErr := store.storeRevisionAndActivate(record.ID, encoded)
			return storeErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	session := &fakeValidationSessionExecutor{}
	module.validationSession = session
	if _, err := module.Advance(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	_, record := readActiveValidationSessionRecord(t, git.value.CommonDir, 357)
	if len(record.ValidationSessions) != 2 ||
		record.ValidationSessions[0].State != ValidationSessionFailed ||
		record.ValidationSessions[1].State != ValidationSessionCompleted ||
		record.ValidationSessions[0].ID == record.ValidationSessions[1].ID ||
		session.executeCalls != 1 {
		t.Fatalf(
			"restart sessions=%#v executions=%d",
			record.ValidationSessions,
			session.executeCalls,
		)
	}
	if len(record.ValidationInvalidations) != 1 ||
		record.ValidationInvalidations[0].Class != ValidationInvalidationFailedExecution {
		t.Fatalf("restart invalidations=%#v", record.ValidationInvalidations)
	}
}

func TestValidationSessionRequirementEscalationRecordsFiniteInvalidation(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	session := &fakeValidationSessionExecutor{}
	module.validationSession = session
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}

	var outcome Outcome
	for step := 0; step < 12; step++ {
		var err error
		outcome, err = module.Advance(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.LocalReadiness != nil {
			break
		}
	}
	if outcome.LocalReadiness == nil || session.executeCalls != 1 {
		t.Fatalf("initial validation session did not complete: %#v", outcome)
	}

	module.risk.(*fakeCandidateRiskObserver).effects = []EffectObservation{{
		Effect: EffectSecurity, Evidence: "new credential boundary discovered", Complete: true,
	}}
	module.specialist = &fakeSpecialistReviewExecutor{}
	if _, err := module.Advance(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 12; step++ {
		var err error
		outcome, err = module.Advance(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.LocalReadiness != nil &&
			len(outcome.ValidationSessions) == 2 {
			break
		}
	}
	_, record := readActiveValidationSessionRecord(t, git.value.CommonDir, 357)
	if len(record.ValidationSessions) != 2 ||
		record.ValidationSessions[1].State != ValidationSessionCompleted ||
		len(record.ValidationInvalidations) != 1 ||
		record.ValidationInvalidations[0].Class != ValidationInvalidationInstrumentation ||
		session.executeCalls != 2 {
		t.Fatalf(
			"escalated sessions=%#v invalidations=%#v executions=%d",
			record.ValidationSessions,
			record.ValidationInvalidations,
			session.executeCalls,
		)
	}
}

func TestValidationSessionCompatibilityUsesInstrumentationSetInclusion(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	required := []ValidationInstrumentation{
		InstrumentationAcceptanceTraceability,
		InstrumentationPackyValidator,
		InstrumentationWorkspaceClean,
	}
	session := ValidationSession{
		State:                      ValidationSessionCompleted,
		CandidateID:                "candidate",
		CommitSHA:                  strings.Repeat("1", 40),
		TreeSHA:                    strings.Repeat("2", 40),
		CheckoutSHA256:             strings.Repeat("3", 64),
		ValidatorIdentity:          "scripts/validate-packy.sh",
		ValidatorSHA256:            strings.Repeat("4", 64),
		ValidatorIdentityExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
		Command:                    "./scripts/validate-packy.sh",
		HomeRoot:                   "/sandbox/home",
		ConfigRoot:                 "/sandbox/config",
		WorkspaceClean:             true,
		Instrumentation: append(
			append([]ValidationInstrumentation(nil), required...),
			InstrumentationOperatorState,
		),
		CoveredBoundaries: []SensitiveBoundary{BoundarySecurity},
	}
	observation := ValidationSessionObservation{
		CheckoutSHA256:    session.CheckoutSHA256,
		CommitSHA:         session.CommitSHA,
		TreeSHA:           session.TreeSHA,
		WorkspaceClean:    true,
		ValidatorIdentity: session.ValidatorIdentity,
		ValidatorSHA256:   session.ValidatorSHA256,
		Command:           session.Command,
		HomeRoot:          session.HomeRoot,
		ConfigRoot:        session.ConfigRoot,
		Instrumentation: append(
			append([]ValidationInstrumentation(nil), required...),
			InstrumentationSandboxWriteManifest,
		),
		CoveredBoundaries: []SensitiveBoundary{BoundarySecurity, BoundaryPublication},
	}
	if class := validationSessionMismatch(
		session,
		Candidate{ID: session.CandidateID, CommitSHA: session.CommitSHA, TreeSHA: session.TreeSHA},
		observation,
		required,
		[]SensitiveBoundary{BoundarySecurity},
		now,
	); class != "" {
		t.Fatalf("compatible instrumentation superset invalidated as %q", class)
	}
}

func TestValidationSessionMismatchClassesAreFiniteAndObservable(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	required := []ValidationInstrumentation{
		InstrumentationAcceptanceTraceability,
		InstrumentationPackyValidator,
		InstrumentationWorkspaceClean,
	}
	candidate := Candidate{
		ID: "candidate", CommitSHA: strings.Repeat("1", 40), TreeSHA: strings.Repeat("2", 40),
	}
	session := ValidationSession{
		State: ValidationSessionCompleted, CandidateID: candidate.ID,
		CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		CheckoutSHA256: strings.Repeat("3", 64), ValidatorIdentity: "scripts/validate-packy.sh",
		ValidatorSHA256:            strings.Repeat("4", 64),
		ValidatorIdentityExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
		Command:                    "./scripts/validate-packy.sh",
		HomeRoot:                   "/sandbox/home",
		ConfigRoot:                 "/sandbox/config",
		WorkspaceClean:             true,
		Instrumentation:            append([]ValidationInstrumentation(nil), required...),
		CoveredBoundaries:          []SensitiveBoundary{BoundarySecurity},
	}
	observation := ValidationSessionObservation{
		CheckoutSHA256: session.CheckoutSHA256, CommitSHA: session.CommitSHA,
		TreeSHA: session.TreeSHA, WorkspaceClean: true,
		ValidatorIdentity: session.ValidatorIdentity, ValidatorSHA256: session.ValidatorSHA256,
		Command: session.Command, HomeRoot: session.HomeRoot, ConfigRoot: session.ConfigRoot,
		Instrumentation:   append([]ValidationInstrumentation(nil), required...),
		CoveredBoundaries: []SensitiveBoundary{BoundarySecurity},
	}
	type mismatchCase struct {
		name     string
		want     ValidationInvalidationClass
		mutate   func(*ValidationSession, *Candidate, *ValidationSessionObservation)
		required []ValidationInstrumentation
		bounds   []SensitiveBoundary
		at       time.Time
	}
	cases := []mismatchCase{
		{name: "candidate", want: ValidationInvalidationCandidate, mutate: func(s *ValidationSession, _ *Candidate, _ *ValidationSessionObservation) {
			s.CandidateID = "other"
		}},
		{name: "commit", want: ValidationInvalidationCommit, mutate: func(s *ValidationSession, _ *Candidate, _ *ValidationSessionObservation) {
			s.CommitSHA = strings.Repeat("5", 40)
		}},
		{name: "tree", want: ValidationInvalidationTree, mutate: func(s *ValidationSession, _ *Candidate, _ *ValidationSessionObservation) {
			s.TreeSHA = strings.Repeat("6", 40)
		}},
		{name: "checkout", want: ValidationInvalidationCheckout, mutate: func(_ *ValidationSession, _ *Candidate, o *ValidationSessionObservation) {
			o.CheckoutSHA256 = strings.Repeat("7", 64)
		}},
		{name: "validator", want: ValidationInvalidationValidator, mutate: func(_ *ValidationSession, _ *Candidate, o *ValidationSessionObservation) {
			o.ValidatorSHA256 = strings.Repeat("8", 64)
		}},
		{name: "command", want: ValidationInvalidationCommand, mutate: func(_ *ValidationSession, _ *Candidate, o *ValidationSessionObservation) {
			o.Command = "./scripts/other.sh"
		}},
		{name: "sandbox", want: ValidationInvalidationSandbox, mutate: func(_ *ValidationSession, _ *Candidate, o *ValidationSessionObservation) {
			o.HomeRoot = "/other/home"
		}},
		{
			name: "instrumentation", want: ValidationInvalidationInstrumentation,
			required: append(append([]ValidationInstrumentation(nil), required...), InstrumentationOperatorState),
		},
		{
			name: "boundary", want: ValidationInvalidationBoundaryRequirement,
			bounds: []SensitiveBoundary{BoundarySecurity, BoundaryPublication},
		},
		{name: "expiry", want: ValidationInvalidationExpiry, at: now.Add(2 * time.Hour)},
		{name: "workspace", want: ValidationInvalidationWorkspace, mutate: func(s *ValidationSession, _ *Candidate, _ *ValidationSessionObservation) {
			s.WorkspaceClean = false
		}},
		{name: "failed execution", want: ValidationInvalidationFailedExecution, mutate: func(s *ValidationSession, _ *Candidate, _ *ValidationSessionObservation) {
			s.State = ValidationSessionFailed
		}},
	}
	seen := map[ValidationInvalidationClass]bool{}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			currentSession, currentCandidate, currentObservation := session, candidate, observation
			currentSession.Instrumentation = append(
				[]ValidationInstrumentation(nil), session.Instrumentation...,
			)
			currentObservation.Instrumentation = append(
				[]ValidationInstrumentation(nil), observation.Instrumentation...,
			)
			if test.mutate != nil {
				test.mutate(&currentSession, &currentCandidate, &currentObservation)
			}
			currentRequired := required
			if test.required != nil {
				currentRequired = test.required
			}
			currentBoundaries := []SensitiveBoundary{BoundarySecurity}
			if test.bounds != nil {
				currentBoundaries = test.bounds
			}
			at := now
			if !test.at.IsZero() {
				at = test.at
			}
			got := validationSessionMismatch(
				currentSession, currentCandidate, currentObservation,
				currentRequired, currentBoundaries, at,
			)
			if got != test.want {
				t.Fatalf("mismatch class=%q, want %q", got, test.want)
			}
			seen[got] = true
		})
	}
	if len(seen) != 12 {
		t.Fatalf("observed mismatch classes=%v", seen)
	}
}
