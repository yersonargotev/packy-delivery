package issuedelivery

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

type fakeReviewExecutor struct {
	mu                      sync.Mutex
	responses               map[deliveryevidence.ReviewAxis][]CandidateReview
	calls                   map[deliveryevidence.ReviewAxis]int
	hook                    func(deliveryevidence.ReviewAxis)
	missingNegative         bool
	missingMigration        bool
	checkDeferredValidation bool
}

type fakeCandidateRiskObserver struct {
	mu      sync.Mutex
	effects []EffectObservation
	calls   int
}

func (f *fakeCandidateRiskObserver) ObserveCandidateRisk(
	_ context.Context,
	request CandidateRiskRequest,
) (CandidateRiskObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	effects := append([]EffectObservation(nil), f.effects...)
	if len(effects) == 0 {
		effects = []EffectObservation{{
			Effect: EffectPassive, Evidence: "test-only passive candidate", Complete: true,
		}}
	}
	return CandidateRiskObservation{
		CandidateID: request.CandidateID, CommitSHA: request.CommitSHA, TreeSHA: request.TreeSHA,
		Effects: effects, Completed: true,
	}, nil
}

func (f *fakeReviewExecutor) Review(_ context.Context, request ReviewRequest) (CandidateReview, error) {
	if f.hook != nil {
		f.hook(request.Axis)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[request.Axis]++
	response := CandidateReview{Completed: true}
	queue := f.responses[request.Axis]
	if len(queue) > 0 {
		response = queue[0]
		f.responses[request.Axis] = queue[1:]
	}
	response.Axis = request.Axis
	response.CandidateID = request.CandidateID
	if response.Iteration == 0 && response.CommitSHA == "" && response.TreeSHA == "" {
		response.Iteration, response.CommitSHA, response.TreeSHA =
			request.Iteration, request.CommitSHA, request.TreeSHA
	}
	if response.Findings == nil {
		response.Findings = []deliveryevidence.ReviewFinding{}
	}
	if request.Axis == deliveryevidence.ReviewSpec && response.Acceptance == nil {
		for _, row := range request.AcceptanceRows {
			response.Acceptance = append(response.Acceptance, AcceptanceProof{
				CandidateID: request.CandidateID, Phase: deliveryevidence.AssuranceCandidateReview,
				Identity: row.Identity, PositiveEvidence: "positive semantic reasoning",
				NegativeEvidence: "negative semantic reasoning", FailureEvidence: "failure semantic reasoning",
				MutationEvidence: "mutation semantic reasoning", CompatibilityEvidence: "compatibility semantic reasoning",
				PreservationEvidence: "preservation semantic reasoning", MigrationEvidence: "migration semantic reasoning",
				ReviewReceipt: &ReviewReceiptReference{
					CandidateID: request.CandidateID, Axis: request.Axis,
					Iteration: request.Iteration, CommitSHA: request.CommitSHA, TreeSHA: request.TreeSHA,
				},
			})
		}
	}
	if request.Axis == deliveryevidence.ReviewSpec && f.checkDeferredValidation {
		for _, row := range request.AcceptanceRows {
			deferred := false
			for _, obligation := range row.Obligations {
				if obligation.Kind == deliveryevidence.EvidenceValidation &&
					obligation.Phase == deliveryevidence.AssuranceExhaustiveValidation {
					deferred = true
				}
			}
			if !deferred {
				response.Findings = append(response.Findings, deliveryevidence.ReviewFinding{
					ID: "premature-missing-validator", Axis: deliveryevidence.ReviewSpec,
					Severity: deliveryevidence.SeverityP2, Authority: deliveryevidence.AuthoritySpecRequirement,
					Citation: row.Identity, Location: "exhaustive-validation",
					Evidence: "validator receipt is incorrectly required during candidate review",
				})
			}
		}
	}
	if request.Axis == deliveryevidence.ReviewSpec {
		for index := range response.Acceptance {
			if f.missingNegative {
				response.Acceptance[index].NegativeEvidence = ""
			}
			if f.missingMigration {
				response.Acceptance[index].MigrationEvidence = ""
			}
		}
	}
	return response, nil
}

type fakeValidationExecutor struct {
	mu                 sync.Mutex
	focusedCalls       int
	exhaustiveCalls    int
	invalidSandbox     bool
	invalidCommand     bool
	missingAcceptance  bool
	missingNegative    bool
	missingMigration   bool
	migrationNA        bool
	semanticAcceptance bool
	afterExhaustive    func()
}

func (f *fakeValidationExecutor) Focused(_ context.Context, request ValidationRequest) (ValidationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.focusedCalls++
	return f.result(request), nil
}

func (f *fakeValidationExecutor) Exhaustive(_ context.Context, request ValidationRequest) (ValidationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exhaustiveCalls++
	result := f.result(request)
	result.Command = "./scripts/validate-packy.sh"
	if f.invalidCommand {
		result.Command = "true"
	}
	result.CheckoutSHA256 = strings.Repeat("d", 64)
	result.ValidatorIdentity = "scripts/validate-packy.sh"
	result.ValidatorSHA256 = strings.Repeat("e", 64)
	result.ValidatorIdentityExpiresAt = "2030-01-01T00:00:00Z"
	result.WorkspaceClean = true
	phaseOwned := false
	for _, row := range request.AcceptanceRows {
		if len(row.Obligations) > 0 {
			phaseOwned = true
			result.Traceability = append(result.Traceability, ValidationTrace{
				Identity: row.Identity, CandidateID: request.CandidateID,
				Phase:     deliveryevidence.AssuranceExhaustiveValidation,
				CommitSHA: request.CommitSHA, TreeSHA: request.TreeSHA,
			})
			continue
		}
		binding := "candidate " + request.CandidateID
		proof := AcceptanceProof{
			Identity: row.Identity, PositiveEvidence: binding + " positive",
			NegativeEvidence: binding + " negative", FailureEvidence: binding + " failure",
			MutationEvidence: binding + " mutation", CompatibilityEvidence: binding + " compatibility",
			PreservationEvidence: binding + " preservation", MigrationEvidence: binding + " migration",
		}
		if f.missingNegative {
			proof.NegativeEvidence = ""
		}
		if f.missingMigration {
			proof.MigrationEvidence = ""
		}
		if f.migrationNA {
			proof.MigrationEvidence = "not-applicable: candidate has no migration effect"
		}
		result.Acceptance = append(result.Acceptance, proof)
	}
	if phaseOwned && f.semanticAcceptance && len(request.AcceptanceRows) > 0 {
		result.Acceptance = []AcceptanceProof{{
			Identity:         request.AcceptanceRows[0].Identity,
			PositiveEvidence: "validator-authored semantic prose",
		}}
	}
	if f.missingAcceptance {
		if phaseOwned && len(result.Traceability) > 0 {
			result.Traceability = result.Traceability[:len(result.Traceability)-1]
		} else if len(result.Acceptance) > 0 {
			result.Acceptance = result.Acceptance[:len(result.Acceptance)-1]
		}
	}
	if f.afterExhaustive != nil {
		f.afterExhaustive()
	}
	return result, nil
}

func (f *fakeValidationExecutor) result(request ValidationRequest) ValidationResult {
	home, config := request.HomeRoot, request.ConfigRoot
	if f.invalidSandbox {
		home = "relative/home"
	}
	return ValidationResult{
		CommitSHA: request.CommitSHA, TreeSHA: request.TreeSHA,
		Command: "test assurance", HomeRoot: home, ConfigRoot: config,
		Sandboxed: true, Succeeded: true, Completed: true,
	}
}

func assuranceFixture(t *testing.T) (*Module, *fakeGitObserver, *fakeGitHubObserver, *fakeReviewExecutor, *fakeValidationExecutor) {
	t.Helper()
	fixture := assuranceFixtureWithoutQualification(t)
	approveQualificationFixture(t, fixture.module, 357)
	return fixture.module, fixture.git, fixture.tracker, fixture.reviewer, fixture.validator
}

type assuranceTestFixture struct {
	module    *Module
	git       *fakeGitObserver
	tracker   *fakeGitHubObserver
	reviewer  *fakeReviewExecutor
	validator *fakeValidationExecutor
}

func assuranceFixtureWithoutQualification(t *testing.T) assuranceTestFixture {
	t.Helper()
	module, git, tracker := moduleFixture(t, 357)
	git.value.Branch = "chore/issue-357-prove-low-risk-candidate"
	reviewer := &fakeReviewExecutor{
		responses: map[deliveryevidence.ReviewAxis][]CandidateReview{},
		calls:     map[deliveryevidence.ReviewAxis]int{},
	}
	validator := &fakeValidationExecutor{}
	risk := &fakeCandidateRiskObserver{}
	sandbox, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"home", "config"} {
		if err := os.Mkdir(filepath.Join(sandbox, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	module.review, module.validation, module.risk, module.sandboxRoot = reviewer, validator, risk, sandbox
	return assuranceTestFixture{
		module: module, git: git, tracker: tracker, reviewer: reviewer, validator: validator,
	}
}

func approveQualificationFixture(t *testing.T, module *Module, issue int) {
	t.Helper()
	request := Request{RepositoryPath: "/repo", IssueNumber: issue}
	qualified := mustAdvance(t, module, request)
	pending := qualified.QualificationCorrection
	if pending == nil {
		t.Fatalf("fixture compiler did not request qualification correction: %#v", qualified)
	}
	rows := append([]deliveryevidence.AcceptanceRow(nil), qualified.Evidence.AcceptanceMatrix...)
	for index := range rows {
		rows[index].OwningSeam = "issuedelivery assurance fixture seam"
		rows[index].PositiveEvidence = "planned: focused positive evidence"
		rows[index].NegativeEvidence = "planned: focused negative evidence"
		rows[index].FailureEvidence = "planned: focused failure evidence"
		rows[index].MutationEvidence = "planned: focused mutation evidence"
		rows[index].CompatibilityEvidence = "planned: focused compatibility evidence"
		rows[index].PreservationEvidence = "planned: focused preservation evidence"
	}
	corrected := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: issue,
		QualificationCorrection: compilerQualificationCorrectionForTest(
			pending, rows,
			"mapped every assurance criterion through the typed correction envelope",
		),
	})
	correctedHash, err := acceptanceMatrixDigest(corrected.Evidence.AcceptanceMatrix)
	if err != nil {
		t.Fatal(err)
	}
	approved := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: issue,
		QualificationReview: &QualificationReview{
			AuthoritySHA256:        corrected.Observations.AuthoritySHA256,
			AcceptanceMatrixSHA256: correctedHash,
			Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
		},
	})
	if !approved.QualificationApproved {
		t.Fatalf("fixture qualification was not approved: %#v", approved)
	}
}

func compilerQualificationCorrectionForTest(
	pending *QualificationCorrectionRequest,
	rows []deliveryevidence.AcceptanceRow,
	evidence string,
) *QualificationCorrection {
	bound := append([]deliveryevidence.AcceptanceRow(nil), rows...)
	for index := range bound {
		identity := strings.ReplaceAll(bound[index].Identity, "-", "_")
		prefix := "[criterion:" + bound[index].Identity + "] "
		assertion := func(value string) string {
			if len(value) < 24 {
				return value + " contract assertion"
			}
			return value
		}
		bound[index].OwningSeam = prefix + "source=symbol:issuedelivery." +
			identity + ".owningSeam; assertion=" + assertion(bound[index].OwningSeam)
		bound[index].PositiveEvidence = prefix + "source=test:TestQualification_" +
			identity + "_Positive; assertion=" + assertion(bound[index].PositiveEvidence)
		bound[index].NegativeEvidence = prefix + "source=test:TestQualification_" +
			identity + "_Negative; assertion=" + assertion(bound[index].NegativeEvidence)
		bound[index].FailureEvidence = prefix + "source=test:TestQualification_" +
			identity + "_Failure; assertion=" + assertion(bound[index].FailureEvidence)
		bound[index].MutationEvidence = prefix + "source=test:TestQualification_" +
			identity + "_Mutation; assertion=" + assertion(bound[index].MutationEvidence)
		bound[index].CompatibilityEvidence = prefix + "source=test:TestQualification_" +
			identity + "_Compatibility; assertion=" + assertion(bound[index].CompatibilityEvidence)
		bound[index].PreservationEvidence = prefix + "source=test:TestQualification_" +
			identity + "_Preservation; assertion=" + assertion(bound[index].PreservationEvidence)
		bound[index].MigrationEvidence = prefix + "source=authority:" +
			bound[index].Identity + "/migration; assertion=" + assertion(bound[index].MigrationEvidence)
	}
	return &QualificationCorrection{
		RequestID:            pending.ID,
		AuthoritySHA256:      pending.AuthoritySHA256,
		ReviewedMatrixSHA256: pending.ReviewedMatrixSHA256,
		FindingIDs:           append([]string(nil), pending.FindingIDs...),
		AcceptanceMatrix:     bound,
		Evidence: "[request:" + pending.ID + "] findings=" +
			strings.Join(pending.FindingIDs, ",") + "; rationale=" + evidence,
	}
}

func TestAdvanceReviewsAccumulatedCandidateInParallelAndReachesExactLocalReadiness(t *testing.T) {
	module, _, _, reviewer, validator := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	focused, err := module.Advance(context.Background(), request)
	if err != nil || focused.State != StateNeedsReview || focused.Candidate == nil ||
		focused.Candidate.Focused == nil {
		t.Fatalf("focused outcome=%#v err=%v", focused, err)
	}

	entered := make(chan deliveryevidence.ReviewAxis, 2)
	release := make(chan struct{})
	reviewer.hook = func(axis deliveryevidence.ReviewAxis) {
		entered <- axis
		<-release
	}
	reviewed := make(chan Outcome, 1)
	reviewErr := make(chan error, 1)
	go func() {
		outcome, advanceErr := module.Advance(context.Background(), request)
		reviewErr <- advanceErr
		reviewed <- outcome
	}()
	seen := map[deliveryevidence.ReviewAxis]bool{}
	for len(seen) < 2 {
		select {
		case axis := <-entered:
			seen[axis] = true
		case err := <-reviewErr:
			t.Fatalf("advance returned before parallel reviews: %v", err)
		case outcome := <-reviewed:
			t.Fatalf("advance returned before parallel reviews: %#v", outcome)
		}
	}
	if !seen[deliveryevidence.ReviewStandards] || !seen[deliveryevidence.ReviewSpec] {
		t.Fatalf("reviews did not start independently: %v", seen)
	}
	close(release)
	if err := <-reviewErr; err != nil {
		t.Fatal(err)
	}
	reviewOutcome := <-reviewed
	if reviewOutcome.State != StateNeedsReview || len(reviewOutcome.Candidate.Reviews) != 2 {
		t.Fatalf("review outcome=%#v", reviewOutcome)
	}
	if reviewOutcome.PauseCause != PauseDeterministicAdvance || reviewOutcome.NextAction != ActionAdvance {
		t.Fatalf("post-review pause metadata = %q, %q", reviewOutcome.PauseCause, reviewOutcome.NextAction)
	}
	reviewer.hook = nil

	ready, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if ready.State != StateWaiting || ready.LocalReadiness == nil ||
		ready.LocalReadiness.CommitSHA != strings.Repeat("b", 40) ||
		ready.LocalReadiness.TreeSHA != strings.Repeat("c", 40) {
		t.Fatalf("local readiness=%#v", ready)
	}
	for _, row := range ready.Evidence.AcceptanceMatrix {
		if row.State != deliveryevidence.AcceptanceProved {
			t.Fatalf("acceptance row %q state=%q", row.Identity, row.State)
		}
	}
	if validator.focusedCalls != 1 || validator.exhaustiveCalls != 1 {
		t.Fatalf("validation calls focused=%d exhaustive=%d", validator.focusedCalls, validator.exhaustiveCalls)
	}
}

func TestAdvanceBoundedRepairUsesFocusedOriginatingAxisConfirmation(t *testing.T) {
	module, git, _, reviewer, validator := assuranceFixture(t)
	finding := deliveryevidence.ReviewFinding{
		ID: "S357-1", Axis: deliveryevidence.ReviewStandards, Severity: deliveryevidence.SeverityP2,
		Authority: deliveryevidence.AuthorityDocumentedStandard, Citation: "AGENTS.md",
		Location: "internal/issuedelivery/assurance.go", Evidence: "bounded repair required",
	}
	reviewer.responses[deliveryevidence.ReviewStandards] = []CandidateReview{
		{Completed: true, Findings: []deliveryevidence.ReviewFinding{finding}},
		{Completed: true, Findings: []deliveryevidence.ReviewFinding{}},
	}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	found := mustAdvance(t, module, request)
	if found.State != StateNeedsDecision || found.Repair == nil {
		t.Fatalf("finding outcome=%#v", found)
	}
	planned := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		Repair: &RepairDecision{
			CandidateID: found.Repair.CandidateID, Class: RepairBounded,
			Findings: []FindingDecision{{
				FindingID: "S357-1", Disposition: FindingAccepted, Evidence: "repair as one bounded batch",
			}},
		},
	})
	if planned.State != StateNeedsReview {
		t.Fatalf("repair plan outcome=%#v", planned)
	}
	if planned.PauseCause != PauseCandidateRepair || planned.NextAction != ActionRepairCandidate {
		t.Fatalf("repair plan pause metadata = %q, %q", planned.PauseCause, planned.NextAction)
	}
	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
	repaired := mustAdvance(t, module, request)
	if repaired.Candidate == nil || repaired.Candidate.RepairClass != RepairBounded ||
		repaired.Candidate.Focused == nil ||
		repaired.Candidate.BaseSHA != strings.Repeat("a", 40) {
		t.Fatalf("bounded candidate=%#v", repaired)
	}
	confirmed := mustAdvance(t, module, request)
	if confirmed.State != StateNeedsReview || len(confirmed.Candidate.Reviews) != 2 {
		t.Fatalf("bounded confirmation=%#v", confirmed)
	}
	ready := mustAdvance(t, module, request)
	if ready.State != StateWaiting || ready.LocalReadiness == nil {
		t.Fatalf("bounded readiness=%#v", ready)
	}
	if reviewer.calls[deliveryevidence.ReviewStandards] != 2 ||
		reviewer.calls[deliveryevidence.ReviewSpec] != 2 ||
		validator.focusedCalls != 2 || validator.exhaustiveCalls != 1 {
		t.Fatalf("calls reviews=%v focused=%d exhaustive=%d", reviewer.calls, validator.focusedCalls, validator.exhaustiveCalls)
	}
}

func TestAdvanceCandidateChangingRepairRepeatsBothReviewAxes(t *testing.T) {
	module, git, _, reviewer, _ := assuranceFixture(t)
	finding := deliveryevidence.ReviewFinding{
		ID: "S357-2", Axis: deliveryevidence.ReviewSpec, Severity: deliveryevidence.SeverityP2,
		Authority: deliveryevidence.AuthoritySpecRequirement, Citation: "issue#357",
		Location: "internal/issuedelivery/assurance.go", Evidence: "candidate behavior must change",
	}
	reviewer.responses[deliveryevidence.ReviewSpec] = []CandidateReview{
		{Completed: true, Findings: []deliveryevidence.ReviewFinding{finding}},
		{Completed: true, Findings: []deliveryevidence.ReviewFinding{}},
	}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	found := mustAdvance(t, module, request)
	planned := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		Repair: &RepairDecision{
			CandidateID: found.Repair.CandidateID, Class: RepairCandidateChanging,
			Findings: []FindingDecision{{
				FindingID: "S357-2", Disposition: FindingAccepted, Evidence: "repair as one candidate-changing batch",
			}},
		},
	})
	oldCandidateID := planned.Candidate.ID
	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
	changed := mustAdvance(t, module, request)
	if changed.Candidate == nil || changed.Candidate.ID == oldCandidateID ||
		changed.Candidate.RepairClass != RepairCandidateChanging {
		t.Fatalf("candidate-changing repair=%#v", changed)
	}
	reviewed := mustAdvance(t, module, request)
	if len(reviewed.Candidate.Reviews) != 2 ||
		reviewer.calls[deliveryevidence.ReviewStandards] != 2 ||
		reviewer.calls[deliveryevidence.ReviewSpec] != 2 {
		t.Fatalf("candidate-changing reviews=%#v calls=%v", reviewed.Candidate.Reviews, reviewer.calls)
	}
}

func TestAdvanceRejectsBoundedClassificationWithoutAcceptedFinding(t *testing.T) {
	module, _, _, reviewer, _ := assuranceFixture(t)
	finding := deliveryevidence.ReviewFinding{
		ID: "S357-3", Axis: deliveryevidence.ReviewStandards, Severity: deliveryevidence.SeverityP2,
		Authority: deliveryevidence.AuthorityDocumentedStandard, Citation: "AGENTS.md",
		Location: "internal/issuedelivery/assurance.go", Evidence: "finding may be rejected",
	}
	reviewer.responses[deliveryevidence.ReviewStandards] = []CandidateReview{{
		Completed: true, Findings: []deliveryevidence.ReviewFinding{finding},
	}}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	found := mustAdvance(t, module, request)
	_, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		Repair: &RepairDecision{
			CandidateID: found.Repair.CandidateID, Class: RepairBounded,
			Findings: []FindingDecision{{
				FindingID: "S357-3", Disposition: FindingRejected, Evidence: "review evidence disproves finding",
			}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "bounded repair requires") {
		t.Fatalf("bounded rejected-only adjudication error=%v", err)
	}
}

func TestAdvanceRejectsCandidateChangingClassificationWithoutAcceptedFinding(t *testing.T) {
	module, _, _, reviewer, _ := assuranceFixture(t)
	finding := deliveryevidence.ReviewFinding{
		ID: "S357-3b", Axis: deliveryevidence.ReviewSpec, Severity: deliveryevidence.SeverityP2,
		Authority: deliveryevidence.AuthoritySpecRequirement, Citation: "issue#357",
		Location: "internal/issuedelivery/assurance.go", Evidence: "finding may be rejected",
	}
	reviewer.responses[deliveryevidence.ReviewSpec] = []CandidateReview{{
		Completed: true, Findings: []deliveryevidence.ReviewFinding{finding},
	}}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	found := mustAdvance(t, module, request)
	_, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		Repair: &RepairDecision{
			CandidateID: found.Repair.CandidateID, Class: RepairCandidateChanging,
			Findings: []FindingDecision{{
				FindingID: "S357-3b", Disposition: FindingRejected, Evidence: "review evidence disproves finding",
			}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "candidate-changing repair requires") {
		t.Fatalf("candidate-changing rejected-only adjudication error=%v", err)
	}
}

func TestAdvanceRejectsRepairDecisionForStaleGitCheckout(t *testing.T) {
	module, git, _, reviewer, _ := assuranceFixture(t)
	finding := deliveryevidence.ReviewFinding{
		ID: "S357-stale", Axis: deliveryevidence.ReviewStandards, Severity: deliveryevidence.SeverityP2,
		Authority: deliveryevidence.AuthorityDocumentedStandard, Citation: "AGENTS.md",
		Location: "internal/issuedelivery/assurance.go", Evidence: "bounded repair required",
	}
	reviewer.responses[deliveryevidence.ReviewStandards] = []CandidateReview{{
		Completed: true, Findings: []deliveryevidence.ReviewFinding{finding},
	}}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	found := mustAdvance(t, module, request)
	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
	_, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		Repair: &RepairDecision{
			CandidateID: found.Repair.CandidateID, Class: RepairBounded,
			Findings: []FindingDecision{{
				FindingID: "S357-stale", Disposition: FindingAccepted, Evidence: "repair finding",
			}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "current Git checkout") {
		t.Fatalf("stale checkout repair decision error=%v", err)
	}
}

func TestAdvanceAdjudicationOnlyPreservesCandidateAssuranceAndAdoptsResume(t *testing.T) {
	module, _, _, reviewer, validator := assuranceFixture(t)
	standardsFinding := deliveryevidence.ReviewFinding{
		ID: "S357-4", Axis: deliveryevidence.ReviewStandards, Severity: deliveryevidence.SeverityP2,
		Authority: deliveryevidence.AuthorityDocumentedStandard, Citation: "AGENTS.md",
		Location: "internal/issuedelivery/assurance.go", Evidence: "standards finding may be rejected",
	}
	specFinding := deliveryevidence.ReviewFinding{
		ID: "S357-5", Axis: deliveryevidence.ReviewSpec, Severity: deliveryevidence.SeverityP2,
		Authority: deliveryevidence.AuthoritySpecRequirement, Citation: "issue#357",
		Location: "internal/issuedelivery/assurance.go", Evidence: "spec finding may be rejected",
	}
	reviewer.responses[deliveryevidence.ReviewStandards] = []CandidateReview{{
		Completed: true, Findings: []deliveryevidence.ReviewFinding{standardsFinding},
	}}
	reviewer.responses[deliveryevidence.ReviewSpec] = []CandidateReview{{
		Completed: true, Findings: []deliveryevidence.ReviewFinding{specFinding},
	}}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	found := mustAdvance(t, module, request)
	if found.Repair == nil || !reflect.DeepEqual(
		found.Repair.Options,
		[]RepairClass{RepairAdjudicationOnly, RepairBounded, RepairCandidateChanging},
	) {
		t.Fatalf("repair options=%#v", found.Repair)
	}
	before := *found.Candidate
	beforeEvidence := *found.Evidence
	decision := RepairDecision{
		CandidateID: found.Repair.CandidateID, Class: RepairAdjudicationOnly,
		Findings: []FindingDecision{
			{FindingID: "S357-5", Disposition: FindingRejected, Evidence: "spec evidence disproves finding"},
			{FindingID: "S357-4", Disposition: FindingRejected, Evidence: "standards evidence disproves finding"},
		},
	}
	adjudicated := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357, Repair: &decision,
	})
	if adjudicated.State != StateNeedsReview || adjudicated.Repair != nil ||
		adjudicated.Candidate.ID != before.ID ||
		adjudicated.Candidate.CommitSHA != before.CommitSHA ||
		adjudicated.Candidate.TreeSHA != before.TreeSHA ||
		adjudicated.Candidate.RepairDecision == nil ||
		adjudicated.Candidate.RepairDecision.Class != RepairAdjudicationOnly ||
		!reflect.DeepEqual(adjudicated.Candidate.Effects, before.Effects) ||
		!reflect.DeepEqual(adjudicated.Candidate.Boundaries, before.Boundaries) ||
		!reflect.DeepEqual(adjudicated.Candidate.Reviews, before.Reviews) ||
		!reflect.DeepEqual(adjudicated.Candidate.SpecialistReviews, before.SpecialistReviews) ||
		!reflect.DeepEqual(adjudicated.Evidence, &beforeEvidence) {
		t.Fatalf("adjudication-only outcome=%#v", adjudicated)
	}
	timingCount := len(adjudicated.Timing)
	resumed := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357, Repair: &decision,
	})
	if !reflect.DeepEqual(resumed.Candidate, adjudicated.Candidate) ||
		!reflect.DeepEqual(resumed.Evidence, adjudicated.Evidence) ||
		len(resumed.Timing) != timingCount {
		t.Fatalf("matching adjudication resume duplicated or changed evidence: %#v", resumed)
	}
	ready := mustAdvance(t, module, request)
	if ready.State != StateWaiting || ready.LocalReadiness == nil ||
		validator.focusedCalls != 1 || validator.exhaustiveCalls != 1 {
		t.Fatalf("adjudication-only readiness=%#v", ready)
	}
}

func TestAdvanceAdjudicationOnlyFailsClosed(t *testing.T) {
	module, _, _, reviewer, _ := assuranceFixture(t)
	for axis, finding := range map[deliveryevidence.ReviewAxis]deliveryevidence.ReviewFinding{
		deliveryevidence.ReviewStandards: {
			ID: "S357-6", Axis: deliveryevidence.ReviewStandards, Severity: deliveryevidence.SeverityP2,
			Authority: deliveryevidence.AuthorityDocumentedStandard, Citation: "AGENTS.md",
			Location: "internal/issuedelivery/assurance.go", Evidence: "standards finding",
		},
		deliveryevidence.ReviewSpec: {
			ID: "S357-7", Axis: deliveryevidence.ReviewSpec, Severity: deliveryevidence.SeverityP2,
			Authority: deliveryevidence.AuthoritySpecRequirement, Citation: "issue#357",
			Location: "internal/issuedelivery/assurance.go", Evidence: "spec finding",
		},
	} {
		reviewer.responses[axis] = []CandidateReview{{Completed: true, Findings: []deliveryevidence.ReviewFinding{finding}}}
	}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	found := mustAdvance(t, module, request)
	rejected := FindingDecision{
		FindingID: "S357-6", Disposition: FindingRejected, Evidence: "evidence disproves standards finding",
	}
	specRejected := FindingDecision{
		FindingID: "S357-7", Disposition: FindingRejected, Evidence: "evidence disproves spec finding",
	}
	tests := []struct {
		name     string
		decision RepairDecision
	}{
		{
			name: "mixed",
			decision: RepairDecision{
				CandidateID: found.Repair.CandidateID, Class: RepairAdjudicationOnly,
				Findings: []FindingDecision{
					{FindingID: "S357-6", Disposition: FindingAccepted, Evidence: "accept finding"},
					specRejected,
				},
			},
		},
		{
			name: "missing finding",
			decision: RepairDecision{
				CandidateID: found.Repair.CandidateID, Class: RepairAdjudicationOnly,
				Findings: []FindingDecision{rejected},
			},
		},
		{
			name: "missing evidence",
			decision: RepairDecision{
				CandidateID: found.Repair.CandidateID, Class: RepairAdjudicationOnly,
				Findings: []FindingDecision{
					{FindingID: "S357-6", Disposition: FindingRejected},
					specRejected,
				},
			},
		},
		{
			name: "stale candidate",
			decision: RepairDecision{
				CandidateID: "stale-candidate", Class: RepairAdjudicationOnly,
				Findings: []FindingDecision{rejected, specRejected},
			},
		},
		{
			name: "unsupported class",
			decision: RepairDecision{
				CandidateID: found.Repair.CandidateID, Class: RepairClass("unsupported"),
				Findings: []FindingDecision{rejected, specRejected},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := module.Advance(context.Background(), Request{
				RepositoryPath: "/repo", IssueNumber: 357, Repair: &test.decision,
			}); err == nil {
				t.Fatal("invalid adjudication-only decision succeeded")
			}
		})
	}
	status := mustAdvance(t, module, request)
	if status.State != StateNeedsDecision || status.Repair == nil ||
		status.Candidate.RepairDecision != nil {
		t.Fatalf("failed adjudication changed pending state=%#v", status)
	}
}

func TestAdvanceRejectsDuplicateFindingIDsAcrossReviewAxes(t *testing.T) {
	module, _, _, reviewer, _ := assuranceFixture(t)
	reviewer.responses[deliveryevidence.ReviewStandards] = []CandidateReview{{
		Completed: true, Findings: []deliveryevidence.ReviewFinding{{
			ID: "duplicate", Axis: deliveryevidence.ReviewStandards, Severity: deliveryevidence.SeverityP2,
			Authority: deliveryevidence.AuthorityDocumentedStandard, Citation: "AGENTS.md",
			Location: "internal/issuedelivery/assurance.go", Evidence: "standards evidence",
		}},
	}}
	reviewer.responses[deliveryevidence.ReviewSpec] = []CandidateReview{{
		Completed: true, Findings: []deliveryevidence.ReviewFinding{{
			ID: "duplicate", Axis: deliveryevidence.ReviewSpec, Severity: deliveryevidence.SeverityP2,
			Authority: deliveryevidence.AuthoritySpecRequirement, Citation: "issue#357",
			Location: "internal/issuedelivery/assurance.go", Evidence: "spec evidence",
		}},
	}}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	if _, err := module.Advance(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "duplicate candidate review finding") {
		t.Fatalf("duplicate review finding error=%v", err)
	}
}

func TestAdvanceReusesExactReceiptAndInvalidatesChangedCandidate(t *testing.T) {
	module, git, _, _, validator := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 4 {
		mustAdvance(t, module, request)
	}
	reused := mustAdvance(t, module, request)
	if reused.State != StateWaiting || reused.LocalReadiness == nil || validator.exhaustiveCalls != 1 {
		t.Fatalf("reused readiness=%#v exhaustive=%d", reused, validator.exhaustiveCalls)
	}
	git.value.Branch = "main"
	wrongBranch := mustAdvance(t, module, request)
	if wrongBranch.State != StateBlocked {
		t.Fatalf("wrong branch reused readiness=%#v", wrongBranch)
	}
	git.value.Branch = "chore/issue-357-prove-low-risk-candidate"
	restored := mustAdvance(t, module, request)
	if restored.State != StateWaiting || validator.exhaustiveCalls != 1 {
		t.Fatalf("restored readiness=%#v exhaustive=%d", restored, validator.exhaustiveCalls)
	}
	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
	invalidated := mustAdvance(t, module, request)
	if invalidated.State != StateNeedsReview || invalidated.LocalReadiness != nil ||
		invalidated.Candidate == nil || invalidated.Candidate.Focused == nil {
		t.Fatalf("invalidated candidate=%#v", invalidated)
	}
	for _, row := range invalidated.Evidence.AcceptanceMatrix {
		if row.State != deliveryevidence.AcceptancePlanned {
			t.Fatalf("changed candidate retained acceptance row %q state=%q", row.Identity, row.State)
		}
	}
}

func TestAdvanceBlocksUnsafeValidationSandbox(t *testing.T) {
	module, _, _, _, validator := assuranceFixture(t)
	validator.invalidSandbox = true
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	blocked := mustAdvance(t, module, request)
	if blocked.State != StateBlocked || !strings.Contains(blocked.Reason, "sandbox") {
		t.Fatalf("unsafe sandbox outcome=%#v", blocked)
	}
}

func TestAdvanceBlocksSymlinkedConfiguredSandbox(t *testing.T) {
	module, _, _, _, _ := assuranceFixture(t)
	home := filepath.Join(module.sandboxRoot, "home")
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), home); err != nil {
		t.Fatal(err)
	}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	blocked := mustAdvance(t, module, request)
	if blocked.State != StateBlocked || !strings.Contains(blocked.Reason, "physically isolated") {
		t.Fatalf("symlinked sandbox outcome=%#v", blocked)
	}
}

func TestAdvanceRetriesFreshGateWithoutRerunningExactExhaustiveReceipt(t *testing.T) {
	module, git, _, _, validator := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 2 {
		mustAdvance(t, module, request)
	}
	validator.afterExhaustive = func() {
		git.value.Branch = "main"
	}
	blocked := mustAdvance(t, module, request)
	if blocked.State != StateBlocked || validator.exhaustiveCalls != 1 {
		t.Fatalf("transient gate outcome=%#v exhaustive=%d", blocked, validator.exhaustiveCalls)
	}
	validator.afterExhaustive = nil
	git.value.Branch = "chore/issue-357-prove-low-risk-candidate"
	ready := mustAdvance(t, module, request)
	if ready.State != StateWaiting || ready.LocalReadiness == nil || validator.exhaustiveCalls != 1 {
		t.Fatalf("retried gate outcome=%#v exhaustive=%d", ready, validator.exhaustiveCalls)
	}
}

func TestAdvanceBlocksNonCanonicalExhaustiveAuthority(t *testing.T) {
	module, _, _, _, validator := assuranceFixture(t)
	validator.invalidCommand = true
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 3 {
		mustAdvance(t, module, request)
	}
	blocked := mustAdvance(t, module, request)
	if blocked.State != StateBlocked || !strings.Contains(blocked.Reason, "exhaustive") {
		t.Fatalf("non-canonical exhaustive outcome=%#v", blocked)
	}
}

func TestAdvanceBlocksIncompleteAcceptanceTraceability(t *testing.T) {
	module, _, _, _, validator := assuranceFixture(t)
	validator.missingAcceptance = true
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 3 {
		mustAdvance(t, module, request)
	}
	blocked := mustAdvance(t, module, request)
	if blocked.State != StateBlocked || !strings.Contains(blocked.Reason, "traceability") {
		t.Fatalf("incomplete acceptance outcome=%#v", blocked)
	}
}

func TestAdvanceRejectsValidatorAuthoredSemanticAcceptance(t *testing.T) {
	module, _, _, _, validator := assuranceFixture(t)
	validator.semanticAcceptance = true
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 3 {
		mustAdvance(t, module, request)
	}
	blocked := mustAdvance(t, module, request)
	if blocked.State != StateBlocked ||
		!strings.Contains(blocked.Reason, "forbidden semantic acceptance prose") {
		t.Fatalf("validator semantic acceptance outcome=%#v", blocked)
	}
}

func mustAdvance(t *testing.T, module *Module, request Request) Outcome {
	t.Helper()
	outcome, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

func TestSpecReviewSeesDeferredValidatorObligationWithoutPrematureFinding(t *testing.T) {
	module, _, _, reviewer, _ := assuranceFixture(t)
	reviewer.checkDeferredValidation = true
	var observed bool
	reviewer.hook = func(axis deliveryevidence.ReviewAxis) {
		if axis == deliveryevidence.ReviewSpec {
			observed = true
		}
	}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 3 {
		mustAdvance(t, module, request)
	}
	outcome := mustAdvance(t, module, request)
	if !observed || outcome.State == StateBlocked || outcome.State == StateNeedsDecision {
		t.Fatalf("pre-validation Spec review treated deferred validator evidence as missing: %#v", outcome)
	}
	for _, review := range outcome.Candidate.Reviews {
		for _, finding := range review.Findings {
			if finding.ID == "premature-missing-validator" {
				t.Fatalf("Spec review manufactured premature validator finding: %#v", review)
			}
		}
	}
}

func TestValidationTraceabilityRejectsDuplicateForeignAndStaleRows(t *testing.T) {
	candidate := Candidate{ID: "candidate", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40)}
	rows := []deliveryevidence.AcceptanceRow{{Identity: "AC-1"}, {Identity: "AC-2"}}
	valid := []ValidationTrace{
		{Identity: "AC-1", CandidateID: candidate.ID, Phase: deliveryevidence.AssuranceExhaustiveValidation, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA},
		{Identity: "AC-2", CandidateID: candidate.ID, Phase: deliveryevidence.AssuranceExhaustiveValidation, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA},
	}
	for _, test := range []struct {
		name   string
		mutate func([]ValidationTrace)
	}{
		{"duplicate", func(traces []ValidationTrace) { traces[1].Identity = "AC-1" }},
		{"foreign", func(traces []ValidationTrace) { traces[1].Identity = "AC-3" }},
		{"candidate", func(traces []ValidationTrace) { traces[1].CandidateID = "stale" }},
		{"phase", func(traces []ValidationTrace) { traces[1].Phase = deliveryevidence.AssuranceCandidateReview }},
		{"commit", func(traces []ValidationTrace) { traces[1].CommitSHA = strings.Repeat("c", 40) }},
		{"tree", func(traces []ValidationTrace) { traces[1].TreeSHA = strings.Repeat("d", 40) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			traces := append([]ValidationTrace(nil), valid...)
			test.mutate(traces)
			if err := validateValidationTraceability(traces, rows, candidate); err == nil {
				t.Fatal("invalid exhaustive traceability was admitted")
			}
		})
	}
}

func TestCandidateReviewRejectsStaleReturnedIdentityAndReceipt(t *testing.T) {
	candidate := Candidate{ID: "candidate", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40)}
	proof := AcceptanceProof{
		CandidateID: candidate.ID, Phase: deliveryevidence.AssuranceCandidateReview, Identity: "AC-1",
		PositiveEvidence: "positive", NegativeEvidence: "negative", FailureEvidence: "failure",
		MutationEvidence: "mutation", CompatibilityEvidence: "compatibility",
		PreservationEvidence: "preservation", MigrationEvidence: "migration",
		ReviewReceipt: &ReviewReceiptReference{
			CandidateID: candidate.ID, Axis: deliveryevidence.ReviewSpec, Iteration: 1,
			CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		},
	}
	valid := CandidateReview{
		CandidateID: candidate.ID, Axis: deliveryevidence.ReviewSpec, Iteration: 1,
		CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		Findings: []deliveryevidence.ReviewFinding{}, Acceptance: []AcceptanceProof{proof}, Completed: true,
	}
	for _, test := range []struct {
		name   string
		mutate func(*CandidateReview)
	}{
		{"iteration", func(review *CandidateReview) { review.Iteration = 2 }},
		{"commit", func(review *CandidateReview) { review.CommitSHA = strings.Repeat("c", 40) }},
		{"tree", func(review *CandidateReview) { review.TreeSHA = strings.Repeat("d", 40) }},
		{"missing receipt", func(review *CandidateReview) { review.Acceptance[0].ReviewReceipt = nil }},
		{"tampered receipt", func(review *CandidateReview) { review.Acceptance[0].ReviewReceipt.Iteration = 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			review := valid
			review.Acceptance = append([]AcceptanceProof(nil), valid.Acceptance...)
			receipt := *valid.Acceptance[0].ReviewReceipt
			review.Acceptance[0].ReviewReceipt = &receipt
			test.mutate(&review)
			if err := validateCandidateReview(
				review, candidate, []deliveryevidence.ReviewAxis{deliveryevidence.ReviewSpec}, 1,
			); err == nil {
				t.Fatal("stale returned review identity was admitted")
			}
		})
	}
}

func TestPersistedAcceptanceMustMatchRetainedSpecReview(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 4 {
		mustAdvance(t, module, request)
	}
	var record runRecord
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, 357,
		func(store lockedIssueStore) error {
			_, data, found, loadErr := store.loadActive()
			if loadErr != nil || !found {
				return loadErr
			}
			record, loadErr = decodeRun(data)
			return loadErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	current := &record.Candidates[len(record.Candidates)-1]
	if len(current.Acceptance) == 0 {
		t.Fatal("fixture lacks persisted acceptance proof")
	}
	current.Acceptance[0].PositiveEvidence = "tampered after Spec review"
	if err := validateRun(record); err == nil ||
		!strings.Contains(err.Error(), "does not match its completed Spec review") {
		t.Fatalf("tampered persisted acceptance validation error=%v", err)
	}
}

func TestSupersededCandidateRequiresExactValidationReceiptReference(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 4 {
		mustAdvance(t, module, request)
	}
	git.value.HeadSHA = strings.Repeat("d", 40)
	git.value.TreeSHA = strings.Repeat("e", 40)
	mustAdvance(t, module, request)

	var persisted []byte
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, 357,
		func(store lockedIssueStore) error {
			_, data, found, loadErr := store.loadActive()
			if loadErr != nil || !found {
				return loadErr
			}
			persisted = append([]byte(nil), data...)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := decodeRun(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Candidates) < 2 || baseline.Candidates[0].Exhaustive == nil ||
		len(baseline.Candidates[0].Acceptance) == 0 ||
		baseline.Candidates[0].Acceptance[0].ValidationReceipt == nil {
		t.Fatalf("fixture lacks superseded exhaustive candidate: %#v", baseline.Candidates)
	}

	for _, test := range []struct {
		name   string
		mutate func(*AcceptanceProof)
	}{
		{"removed", func(proof *AcceptanceProof) { proof.ValidationReceipt = nil }},
		{"schema", func(proof *AcceptanceProof) {
			proof.ValidationReceipt.Schema = "packy.exhaustive-validation/unknown"
		}},
		{"candidate", func(proof *AcceptanceProof) { proof.ValidationReceipt.CandidateID = "stale" }},
		{"commit", func(proof *AcceptanceProof) {
			proof.ValidationReceipt.CommitSHA = strings.Repeat("f", 40)
		}},
		{"tree", func(proof *AcceptanceProof) {
			proof.ValidationReceipt.TreeSHA = strings.Repeat("f", 40)
		}},
		{"completedAt", func(proof *AcceptanceProof) {
			proof.ValidationReceipt.CompletedAt = "2026-07-30T23:59:59Z"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, decodeErr := decodeRun(persisted)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			proof := &record.Candidates[0].Acceptance[0]
			if proof.ValidationReceipt != nil {
				reference := *proof.ValidationReceipt
				proof.ValidationReceipt = &reference
			}
			test.mutate(proof)
			if err := validateRun(record); err == nil ||
				!strings.Contains(err.Error(), "stale acceptance validation reference") {
				t.Fatalf("superseded %s reference validation error=%v", test.name, err)
			}
		})
	}
}

func TestAcceptanceProofRejectsStaleStructuralReceiptIdentity(t *testing.T) {
	candidate := Candidate{
		ID: "candidate", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
	}
	proof := AcceptanceProof{
		CandidateID: "candidate", Phase: deliveryevidence.AssuranceCandidateReview, Identity: "AC-1",
		PositiveEvidence: "positive", NegativeEvidence: "negative", FailureEvidence: "failure",
		MutationEvidence: "mutation", CompatibilityEvidence: "compatibility",
		PreservationEvidence: "preservation", MigrationEvidence: "migration",
		ReviewReceipt: &ReviewReceiptReference{
			CandidateID: "candidate", Axis: deliveryevidence.ReviewSpec, Iteration: 1,
			CommitSHA: candidate.CommitSHA, TreeSHA: strings.Repeat("c", 40),
		},
	}
	evidence := &deliveryevidence.Bundle{AcceptanceMatrix: []deliveryevidence.AcceptanceRow{{
		Identity: "AC-1", Obligations: deliveryevidence.PhaseOwnedAcceptanceObligations(),
	}}}
	if err := admitAcceptanceProofs(evidence, &candidate, []AcceptanceProof{proof}); err == nil ||
		!strings.Contains(err.Error(), "stale review receipt") {
		t.Fatalf("stale receipt admission error=%v", err)
	}
}
