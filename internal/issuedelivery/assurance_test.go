package issuedelivery

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestAdvanceWaitsForFirstCandidateAfterQualificationApproval(t *testing.T) {
	fixture := assuranceFixtureWithoutQualification(t)
	fixture.git.value.HeadSHA = fixture.git.value.StartingBaseSHA
	approveQualificationFixture(t, fixture.module, 357)

	var blockedRunID string
	var qualifiedEvidence deliveryevidence.Bundle
	var qualificationReviews []QualificationReview
	var qualificationCorrections []QualificationCorrection
	err := fixture.module.store.withIssueLock(
		context.Background(),
		fixture.git.value.CommonDir,
		357,
		func(store lockedIssueStore) error {
			_, data, found, loadErr := store.loadActive()
			if loadErr != nil || !found {
				return loadErr
			}
			record, loadErr := decodeRun(data)
			if loadErr != nil {
				return loadErr
			}
			snapshot, loadErr := decodeRun(data)
			if loadErr != nil {
				return loadErr
			}
			qualifiedEvidence = *snapshot.Evidence
			qualificationReviews = snapshot.QualificationReviews
			qualificationCorrections = snapshot.QualificationCorrections
			blocked, loadErr := fixture.module.persistAssuranceTransition(
				store,
				record,
				StateBlocked,
				"candidate risk observation is incomplete or invalid",
				"risk-observation",
			)
			blockedRunID = blocked.RunID
			return loadErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	waiting := mustAdvance(t, fixture.module, Request{
		RepositoryPath: "/repo",
		IssueNumber:    357,
	})
	if waiting.RunID != blockedRunID || !waiting.QualificationApproved ||
		waiting.State != StateWaiting || waiting.Candidate != nil ||
		waiting.PauseCause != PauseExternalResult ||
		waiting.NextAction != ActionObserveExternalResult {
		t.Fatalf("unchanged baseline outcome = %#v", waiting)
	}
	if got := fixture.module.risk.(*fakeCandidateRiskObserver).calls; got != 0 {
		t.Fatalf("unchanged baseline risk observations = %d, want 0", got)
	}
	if fixture.validator.focusedCalls != 0 {
		t.Fatalf("unchanged baseline focused validations = %d, want 0", fixture.validator.focusedCalls)
	}
	record, err := decodeRun(persistedAssuranceRun(t, fixture.module, fixture.git))
	if err != nil {
		t.Fatal(err)
	}
	if record.State != StateWaiting || len(record.Candidates) != 0 ||
		len(record.ProfileHistory) != 0 ||
		record.Timing[len(record.Timing)-2].Phase != "risk-observation" ||
		record.Timing[len(record.Timing)-1].Phase != "candidate-development" ||
		record.Evidence.Schema != qualifiedEvidence.Schema ||
		record.Evidence.Repository != qualifiedEvidence.Repository ||
		record.Evidence.Issue != qualifiedEvidence.Issue ||
		record.Evidence.Spec != qualifiedEvidence.Spec ||
		!reflect.DeepEqual(record.Evidence.Authority, qualifiedEvidence.Authority) ||
		record.Evidence.RiskProfile != qualifiedEvidence.RiskProfile ||
		record.Evidence.StartingBaseSHA != qualifiedEvidence.StartingBaseSHA ||
		!reflect.DeepEqual(record.Evidence.Scope, qualifiedEvidence.Scope) ||
		!reflect.DeepEqual(record.Evidence.AcceptanceMatrix, qualifiedEvidence.AcceptanceMatrix) ||
		!reflect.DeepEqual(record.Evidence.Iterations, qualifiedEvidence.Iterations) ||
		!reflect.DeepEqual(record.Evidence.ReviewReceipts, qualifiedEvidence.ReviewReceipts) ||
		!reflect.DeepEqual(record.Evidence.Adjudications, qualifiedEvidence.Adjudications) ||
		!reflect.DeepEqual(record.Evidence.ValidationReceipts, qualifiedEvidence.ValidationReceipts) ||
		!reflect.DeepEqual(record.Evidence.FocusedValidation, qualifiedEvidence.FocusedValidation) ||
		!reflect.DeepEqual(record.QualificationReviews, qualificationReviews) ||
		!reflect.DeepEqual(record.QualificationCorrections, qualificationCorrections) {
		t.Fatalf("unchanged baseline persisted assurance = %#v", record)
	}
	waitingRevision := persistedAssuranceRun(t, fixture.module, fixture.git)
	mustAdvance(t, fixture.module, Request{
		RepositoryPath: "/repo",
		IssueNumber:    357,
	})
	if resumed := persistedAssuranceRun(t, fixture.module, fixture.git); !reflect.DeepEqual(resumed, waitingRevision) {
		t.Fatal("repeated unchanged baseline duplicated persisted transition")
	}

	fixture.git.value.HeadSHA = strings.Repeat("b", 40)
	fixture.git.value.TreeSHA = strings.Repeat("c", 40)
	advanced := mustAdvance(t, fixture.module, Request{
		RepositoryPath: "/repo",
		IssueNumber:    357,
	})
	if advanced.State != StateNeedsReview || advanced.Candidate == nil ||
		advanced.Candidate.CommitSHA != fixture.git.value.HeadSHA ||
		advanced.Candidate.TreeSHA != fixture.git.value.TreeSHA {
		t.Fatalf("changed candidate outcome = %#v", advanced)
	}
	if got := fixture.module.risk.(*fakeCandidateRiskObserver).calls; got != 1 {
		t.Fatalf("changed candidate risk observations = %d, want 1", got)
	}
	record, err = decodeRun(persistedAssuranceRun(t, fixture.module, fixture.git))
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Candidates) != 1 || len(record.ProfileHistory) != 1 {
		t.Fatalf("changed candidate assurance = %#v", record)
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

func TestAutomaticReviewReceiptWaitsForCompleteRequiredAxisBatch(t *testing.T) {
	module, _, _, reviewer, _ := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	reviewer.responses[deliveryevidence.ReviewSpec] = []CandidateReview{
		{Completed: false, Acceptance: []AcceptanceProof{}},
		{Completed: true},
	}
	focused := mustAdvance(t, module, request)
	if focused.Candidate == nil || focused.Candidate.Focused == nil {
		t.Fatalf("candidate did not reach focused review: %#v", focused)
	}
	staged := mustAdvance(t, module, request)
	if staged.State != StateWaiting || len(staged.Candidate.Reviews) != 1 ||
		staged.Candidate.Reviews[0].Axis != deliveryevidence.ReviewStandards ||
		len(staged.Evidence.CandidateReviewReceipts) != 0 {
		t.Fatalf("partial review batch projected a canonical receipt: %#v", staged)
	}
	completed := mustAdvance(t, module, request)
	if len(completed.Candidate.Reviews) != 2 ||
		len(completed.Evidence.CandidateReviewReceipts) != 1 {
		t.Fatalf("completed required review batch was not projected exactly once: %#v", completed)
	}
	if got, want := completed.Evidence.CandidateReviewReceipts[0].CompletedAt,
		completed.Timing[len(completed.Timing)-1].CompletedAt; got != want {
		t.Fatalf("review receipt completion=%q, want final-axis phase completion %q", got, want)
	}
	receiptID := completed.Evidence.CandidateReviewReceipts[0].Identity
	resumed := mustAdvance(t, module, request)
	if len(resumed.Evidence.CandidateReviewReceipts) != 1 ||
		resumed.Evidence.CandidateReviewReceipts[0].Identity != receiptID {
		t.Fatalf("review batch resume duplicated its canonical receipt: %#v", resumed.Evidence)
	}
}

func TestLegacyReviewBatchMigrationUsesContiguousReviewTimingClosures(t *testing.T) {
	sha := func(value string) string { return strings.Repeat(value, 40) }
	timing := func(sequence int, phase, completed string) Timing {
		return Timing{
			Sequence: sequence, Phase: phase, To: StateNeedsReview,
			StartedAt: "2026-07-30T01:00:00.000000000Z", CompletedAt: completed,
		}
	}
	review := func(candidate string, iteration int, axis deliveryevidence.ReviewAxis) CandidateReview {
		return CandidateReview{
			CandidateID: candidate, Iteration: iteration, Axis: axis,
			CommitSHA: sha("b"), TreeSHA: sha("c"),
			Findings: []deliveryevidence.ReviewFinding{}, Completed: true,
		}
	}
	record := runRecord{
		Schema: runSchema,
		Repository: deliveryevidence.RepositoryIdentity{
			Owner: "yersonargotev", Name: "packy", NodeID: "R1",
		},
		Evidence: &deliveryevidence.Bundle{
			Schema: deliveryevidence.SchemaV2,
			Repository: deliveryevidence.RepositoryIdentity{
				Owner: "yersonargotev", Name: "packy", NodeID: "R1",
			},
		},
		Observations: Observations{CommitSHA: sha("a"), TreeSHA: sha("d")},
		Candidates: []Candidate{
			{
				ID: "candidate-1", CommitSHA: sha("b"), TreeSHA: sha("c"),
				RequiredReviews: []deliveryevidence.ReviewAxis{deliveryevidence.ReviewStandards},
				ReviewIteration: 2,
				Reviews: []CandidateReview{
					review("candidate-1", 1, deliveryevidence.ReviewStandards),
					review("candidate-1", 2, deliveryevidence.ReviewStandards),
				},
			},
			{
				ID: "candidate-2", CommitSHA: sha("b"), TreeSHA: sha("c"),
				RequiredReviews: []deliveryevidence.ReviewAxis{deliveryevidence.ReviewStandards},
				ReviewIteration: 1,
				Reviews: []CandidateReview{
					review("candidate-2", 1, deliveryevidence.ReviewStandards),
				},
			},
		},
		Timing: []Timing{
			timing(1, "implementation", "2026-07-30T01:00:01.000000000Z"),
			timing(2, "review", "2026-07-30T01:00:02.000000000Z"),
			timing(3, "review", "2026-07-30T01:00:03.000000000Z"),
			timing(4, "adjudication", "2026-07-30T01:00:04.000000000Z"),
			timing(5, "review", "2026-07-30T01:00:05.000000000Z"),
			timing(6, "repair", "2026-07-30T01:00:06.000000000Z"),
			timing(7, "review", "2026-07-30T01:00:07.000000000Z"),
		},
	}
	if err := projectAutomaticAssurance(&record); err != nil {
		t.Fatal(err)
	}
	if batches := record.Candidates[0].ReviewBatches; len(batches) != 2 ||
		batches[0].TimingSequence != 3 || batches[0].CompletedAt != record.Timing[2].CompletedAt ||
		batches[1].TimingSequence != 5 || batches[1].CompletedAt != record.Timing[4].CompletedAt {
		t.Fatalf("first candidate migrated review closures=%#v", batches)
	}
	if batches := record.Candidates[1].ReviewBatches; len(batches) != 1 ||
		batches[0].TimingSequence != 7 || batches[0].CompletedAt != record.Timing[6].CompletedAt {
		t.Fatalf("second candidate migrated review closures=%#v", batches)
	}
	rebound := record
	rebound.Candidates = append([]Candidate(nil), record.Candidates...)
	rebound.Candidates[1].ReviewBatches = append(
		[]CandidateReviewBatch(nil), record.Candidates[1].ReviewBatches...,
	)
	rebound.Candidates[1].ReviewBatches[0].TimingSequence =
		record.Candidates[0].ReviewBatches[0].TimingSequence
	rebound.Candidates[1].ReviewBatches[0].CompletedAt =
		record.Candidates[0].ReviewBatches[0].CompletedAt
	if err := projectAutomaticAssurance(&rebound); err == nil {
		t.Fatal("candidate review batch rebound to another candidate timing was admitted")
	}
	surplus := record
	surplus.Timing = append([]Timing(nil), record.Timing...)
	surplus.Timing = append(surplus.Timing, timing(
		len(surplus.Timing)+1, "review", "2026-07-30T01:00:08.000000000Z",
	))
	if err := projectAutomaticAssurance(&surplus); err == nil {
		t.Fatal("surplus candidate review timing closure was admitted")
	}

	partialThenComplete := record
	partialThenComplete.Evidence = &deliveryevidence.Bundle{
		Schema: deliveryevidence.SchemaV2, Repository: record.Repository,
	}
	partialThenComplete.Candidates = append([]Candidate(nil), record.Candidates...)
	partialThenComplete.Candidates[0].ReviewIteration = 1
	partialThenComplete.Candidates[0].RequiredReviews = []deliveryevidence.ReviewAxis{
		deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
	}
	partialThenComplete.Candidates[0].Reviews = []CandidateReview{{
		CandidateID: "candidate-1", Iteration: 1, Axis: deliveryevidence.ReviewStandards,
		CommitSHA: sha("b"), TreeSHA: sha("c"), Completed: true,
		Findings: []deliveryevidence.ReviewFinding{},
	}}
	partialThenComplete.Candidates[0].ReviewBatches = nil
	partialThenComplete.Candidates[1].ReviewBatches = nil
	partialThenComplete.Timing = []Timing{
		record.Timing[0], record.Timing[1], record.Timing[2],
		record.Timing[5], record.Timing[6],
	}
	for index := range partialThenComplete.Timing {
		partialThenComplete.Timing[index].Sequence = index + 1
	}
	if err := projectAutomaticAssurance(&partialThenComplete); err != nil {
		t.Fatalf("earlier incomplete candidate shifted later review closure: %v", err)
	}
	if receipts := partialThenComplete.Evidence.CandidateReviewReceipts; len(receipts) != 1 ||
		receipts[0].CandidateID != "candidate-2" ||
		receipts[0].CompletedAt != partialThenComplete.Timing[4].CompletedAt {
		t.Fatalf("earlier incomplete candidate misassigned later review receipt: %#v", receipts)
	}
}

func TestProfileEscalationDoesNotReceiptAbandonedPartialReviewIteration(t *testing.T) {
	sha := func(value string) string { return strings.Repeat(value, 40) }
	record := runRecord{
		Schema: runSchema,
		Repository: deliveryevidence.RepositoryIdentity{
			Owner: "yersonargotev", Name: "packy", NodeID: "R1",
		},
		Evidence: &deliveryevidence.Bundle{
			Schema: deliveryevidence.SchemaV2,
			Repository: deliveryevidence.RepositoryIdentity{
				Owner: "yersonargotev", Name: "packy", NodeID: "R1",
			},
		},
		Candidates: []Candidate{{
			ID: "candidate", CommitSHA: sha("b"), TreeSHA: sha("c"),
			ReviewIteration: 2,
			RequiredReviews: []deliveryevidence.ReviewAxis{
				deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
			},
			Reviews: []CandidateReview{
				{
					CandidateID: "candidate", Iteration: 1, Axis: deliveryevidence.ReviewStandards,
					CommitSHA: sha("b"), TreeSHA: sha("c"), Completed: true,
					Findings: []deliveryevidence.ReviewFinding{},
				},
				{
					CandidateID: "candidate", Iteration: 2, Axis: deliveryevidence.ReviewStandards,
					CommitSHA: sha("b"), TreeSHA: sha("c"), Completed: true,
					Findings: []deliveryevidence.ReviewFinding{},
				},
				{
					CandidateID: "candidate", Iteration: 2, Axis: deliveryevidence.ReviewSpec,
					CommitSHA: sha("b"), TreeSHA: sha("c"), Completed: true,
					Findings: []deliveryevidence.ReviewFinding{},
				},
			},
		}},
		Timing: []Timing{
			{
				Sequence: 1, Phase: "review", To: StateNeedsReview,
				StartedAt:   "2026-07-30T01:00:00.000000000Z",
				CompletedAt: "2026-07-30T01:00:01.000000000Z",
			},
			{
				Sequence: 2, Phase: "review", To: StateNeedsReview,
				StartedAt:   "2026-07-30T01:00:02.000000000Z",
				CompletedAt: "2026-07-30T01:00:03.000000000Z",
			},
		},
	}
	if err := projectAutomaticAssurance(&record); err == nil ||
		!strings.Contains(err.Error(), "historical review iteration lacks authoritative review batch") {
		t.Fatalf("profile escalation promoted an abandoned partial review iteration: %v", err)
	}
	if len(record.Evidence.CandidateReviewReceipts) != 0 {
		t.Fatalf("abandoned partial review iteration received a canonical receipt: %#v",
			record.Evidence.CandidateReviewReceipts)
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
	module, git, _, reviewer, validator := assuranceFixture(t)
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
		!reflect.DeepEqual(adjudicated.Candidate.SpecialistReviews, before.SpecialistReviews) ||
		len(adjudicated.Evidence.CandidateReviewReceipts) != 1 ||
		len(adjudicated.Evidence.AssuranceAdjudications) != 1 ||
		adjudicated.Evidence.AssuranceAdjudications[0].Class != string(RepairAdjudicationOnly) {
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
	if len(ready.Evidence.ExhaustiveAssurance) != 1 ||
		len(ready.Evidence.AssurancePhases) != len(ready.Timing) ||
		ready.Evidence.ExhaustiveAssurance[0].CandidateID != ready.Candidate.ID {
		t.Fatalf("canonical assurance receipts are incomplete: %#v", ready.Evidence)
	}
	for _, proof := range ready.Candidate.Acceptance {
		if proof.ReviewReceipt == nil || proof.ReviewReceipt.ReceiptID == "" ||
			proof.ValidationReceipt == nil || proof.ValidationReceipt.ReceiptID == "" {
			t.Fatalf("acceptance proof does not reference canonical receipts: %#v", proof)
		}
	}
	readyRecord, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	preAssurance, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	preAssurance.Evidence.CandidateReviewReceipts = nil
	preAssurance.Evidence.AssuranceAdjudications = nil
	preAssurance.Evidence.AssurancePhases = nil
	preAssurance.Evidence.ExhaustiveAssurance = nil
	for candidateIndex := range preAssurance.Candidates {
		candidate := &preAssurance.Candidates[candidateIndex]
		candidate.ReviewBatches = nil
		candidate.ExhaustiveHistory = nil
		if candidate.Exhaustive != nil {
			candidate.Exhaustive.TimingSequence = 0
		}
		for reviewIndex := range candidate.Reviews {
			for proofIndex := range candidate.Reviews[reviewIndex].Acceptance {
				if reference := candidate.Reviews[reviewIndex].Acceptance[proofIndex].ReviewReceipt; reference != nil {
					reference.ReceiptID = ""
				}
			}
		}
		for proofIndex := range candidate.Acceptance {
			if reference := candidate.Acceptance[proofIndex].ReviewReceipt; reference != nil {
				reference.ReceiptID = ""
			}
			if reference := candidate.Acceptance[proofIndex].ValidationReceipt; reference != nil {
				reference.ReceiptID = ""
			}
		}
	}
	filteredTiming := preAssurance.Timing[:0]
	for _, timing := range preAssurance.Timing {
		if timing.Phase != exhaustiveValidationSucceededPhase {
			filteredTiming = append(filteredTiming, timing)
		}
	}
	preAssurance.Timing = filteredTiming
	for index := range preAssurance.Timing {
		preAssurance.Timing[index].Sequence = index + 1
	}
	if err := projectAutomaticAssurance(&preAssurance); err != nil {
		t.Fatalf("receipt-less ready v2 exhaustive timing migration failed: %v", err)
	}
	current := &preAssurance.Candidates[len(preAssurance.Candidates)-1]
	if current.Exhaustive == nil || current.Exhaustive.TimingSequence < 1 ||
		preAssurance.Timing[current.Exhaustive.TimingSequence-1].Phase != exhaustiveValidationSucceededPhase ||
		len(preAssurance.Evidence.ExhaustiveAssurance) != 1 {
		t.Fatalf("receipt-less ready v2 did not bootstrap canonical exhaustive lifecycle: %#v", preAssurance)
	}
	preAssuranceTimingCount := len(preAssurance.Timing)
	if err := projectAutomaticAssurance(&preAssurance); err != nil ||
		len(preAssurance.Timing) != preAssuranceTimingCount ||
		len(preAssurance.Evidence.ExhaustiveAssurance) != 1 {
		t.Fatalf("receipt-less ready v2 bootstrap was not resumably idempotent: %v %#v", err, preAssurance)
	}
	if err := validateRun(preAssurance); err != nil {
		t.Fatalf("migrated receipt-less ready v2 run is invalid: %v", err)
	}
	reportNow := time.Date(2026, 7, 30, 2, 0, 0, 0, time.UTC)
	if _, err := BuildTimingReport(preAssurance.Timing, reportNow); err != nil {
		t.Fatalf("migrated receipt-less ready v2 timing report is invalid: %v", err)
	}
	historicalRequirements, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	historicalCandidate := &historicalRequirements.Candidates[len(historicalRequirements.Candidates)-1]
	historicalCandidate.ReviewBatches[0].RequiredAxes = []deliveryevidence.ReviewAxis{
		deliveryevidence.ReviewStandards,
	}
	historicalCandidate.ReviewIteration = len(historicalCandidate.Reviews) + 1
	historicalCandidate.RequiredReviews = []deliveryevidence.ReviewAxis{
		deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
	}
	if err := projectAutomaticAssurance(&historicalRequirements); err != nil {
		t.Fatalf("broadened current review requirements invalidated completed historical iteration: %v", err)
	}
	tamperedExhaustive := readyRecord
	exhaustiveReceipt := &tamperedExhaustive.Evidence.ExhaustiveAssurance[0]
	exhaustiveReceipt.ValidatorIdentity = "scripts/forged-validator.sh"
	exhaustiveReceipt.Identity = deliveryevidence.ExhaustiveAssuranceReceiptIdentity(*exhaustiveReceipt)
	if err := validateRun(tamperedExhaustive); err == nil {
		t.Fatal("self-consistent tampered exhaustive assurance receipt was admitted")
	}
	failedTimingAnchor, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	exhaustiveSequence := failedTimingAnchor.Candidates[0].Exhaustive.TimingSequence
	failedTimingAnchor.Timing[exhaustiveSequence-1].Phase = "exhaustive-validation"
	if err := validateRun(failedTimingAnchor); err == nil {
		t.Fatal("failed exhaustive-validation timing anchored successful assurance history")
	}
	noncanonicalLegacyTiming, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalLegacyTiming.Timing[0].StartedAt = "2026-07-29T20:00:00-05:00"
	if err := validateRun(noncanonicalLegacyTiming); err == nil {
		t.Fatal("offset spelling was admitted for a legacy lifecycle timestamp")
	}
	noncanonicalSuccessTiming, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalSuccessTiming.Timing[exhaustiveSequence-1].CompletedAt =
		"2026-07-30T01:00:11.000000000Z"
	if err := validateRun(noncanonicalSuccessTiming); err == nil {
		t.Fatal("noncanonical fractional spelling was admitted for successful exhaustive timing")
	}
	orphanReferences, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	orphanReferences.Evidence.CandidateReviewReceipts = nil
	orphanReferences.Evidence.AssuranceAdjudications = nil
	orphanReferences.Evidence.AssurancePhases = nil
	orphanReferences.Evidence.ExhaustiveAssurance = nil
	if err := validateRun(orphanReferences); err == nil {
		t.Fatal("receipt identity references without canonical receipt arrays were admitted")
	}
	for candidateIndex := range orphanReferences.Candidates {
		candidate := &orphanReferences.Candidates[candidateIndex]
		for reviewIndex := range candidate.Reviews {
			for proofIndex := range candidate.Reviews[reviewIndex].Acceptance {
				if reference := candidate.Reviews[reviewIndex].Acceptance[proofIndex].ReviewReceipt; reference != nil {
					reference.ReceiptID = ""
				}
			}
		}
		for proofIndex := range candidate.Acceptance {
			if reference := candidate.Acceptance[proofIndex].ReviewReceipt; reference != nil {
				reference.ReceiptID = ""
			}
			if reference := candidate.Acceptance[proofIndex].ValidationReceipt; reference != nil {
				reference.ReceiptID = ""
			}
		}
	}
	if err := validateRun(orphanReferences); err == nil {
		t.Fatal("canonical receipt arrays were deleted despite retained assurance history")
	}
	foreignReview, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	reviewReceipt := deliveryevidence.CandidateReviewReceipt{
		CandidateID: "foreign-candidate", Iteration: 1,
		Axes: []deliveryevidence.ReviewAxis{
			deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
		},
		FindingsSHA256: strings.Repeat("a", 64), CommitSHA: strings.Repeat("b", 40),
		TreeSHA:     strings.Repeat("c", 40),
		CompletedAt: ready.Timing[len(ready.Timing)-1].CompletedAt,
	}
	reviewReceipt.Identity = deliveryevidence.CandidateReviewReceiptIdentity(
		reviewReceipt.CandidateID, reviewReceipt.Iteration, reviewReceipt.Axes,
		reviewReceipt.FindingsSHA256, reviewReceipt.CommitSHA, reviewReceipt.TreeSHA,
	)
	foreignReview.Evidence.CandidateReviewReceipts = append(
		foreignReview.Evidence.CandidateReviewReceipts, reviewReceipt,
	)
	if err := validateRun(foreignReview); err == nil {
		t.Fatal("self-consistent foreign review assurance receipt was admitted")
	}
	foreignAdjudication, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	adjudicationReceipt := deliveryevidence.AssuranceAdjudicationReceipt{
		RequestID: "foreign-request", CandidateID: "foreign-candidate", Generation: 1,
		Class: string(RepairAdjudicationOnly),
		Findings: []deliveryevidence.AssuranceFindingDecision{{
			FindingID: "foreign-finding", Disposition: string(FindingRejected), Evidence: "forged evidence",
		}},
	}
	adjudicationReceipt.Identity = deliveryevidence.AssuranceAdjudicationReceiptIdentity(
		adjudicationReceipt.RequestID, adjudicationReceipt.CandidateID,
		adjudicationReceipt.Generation, adjudicationReceipt.Class,
		adjudicationReceipt.CompatiblePrefix, adjudicationReceipt.Findings,
	)
	foreignAdjudication.Evidence.AssuranceAdjudications = append(
		foreignAdjudication.Evidence.AssuranceAdjudications, adjudicationReceipt,
	)
	if err := validateRun(foreignAdjudication); err == nil {
		t.Fatal("self-consistent foreign adjudication assurance receipt was admitted")
	}
	for name, mutate := range map[string]func(*runRecord){
		"anchored partial review": func(record *runRecord) {
			record.Candidates[len(record.Candidates)-1].ReviewBatches = nil
			receipt := &record.Evidence.CandidateReviewReceipts[0]
			receipt.Axes = receipt.Axes[:1]
			receipt.Identity = deliveryevidence.CandidateReviewReceiptIdentity(
				receipt.CandidateID, receipt.Iteration, receipt.Axes, receipt.FindingsSHA256,
				receipt.CommitSHA, receipt.TreeSHA,
			)
		},
		"partial current review batch": func(record *runRecord) {
			candidate := &record.Candidates[len(record.Candidates)-1]
			candidate.ReviewBatches[0].RequiredAxes = candidate.ReviewBatches[0].RequiredAxes[:1]
			receipt := &record.Evidence.CandidateReviewReceipts[0]
			receipt.Axes = receipt.Axes[:1]
			receipt.Identity = deliveryevidence.CandidateReviewReceiptIdentity(
				receipt.CandidateID, receipt.Iteration, receipt.Axes, receipt.FindingsSHA256,
				receipt.CommitSHA, receipt.TreeSHA,
			)
		},
		"arbitrary review completion": func(record *runRecord) {
			candidate := &record.Candidates[len(record.Candidates)-1]
			candidate.ReviewBatches[0].CompletedAt = record.Timing[0].CompletedAt
			receipt := &record.Evidence.CandidateReviewReceipts[0]
			receipt.CompletedAt = candidate.ReviewBatches[0].CompletedAt
		},
		"stale review timing sequence": func(record *runRecord) {
			candidate := &record.Candidates[len(record.Candidates)-1]
			candidate.ReviewBatches[0].TimingSequence = record.Timing[0].Sequence
			candidate.ReviewBatches[0].CompletedAt = record.Timing[0].CompletedAt
			receipt := &record.Evidence.CandidateReviewReceipts[0]
			receipt.CompletedAt = candidate.ReviewBatches[0].CompletedAt
		},
		"duplicate review": func(record *runRecord) {
			record.Evidence.CandidateReviewReceipts = append(
				record.Evidence.CandidateReviewReceipts,
				record.Evidence.CandidateReviewReceipts[0],
			)
		},
		"duplicate adjudication": func(record *runRecord) {
			record.Evidence.AssuranceAdjudications = append(
				record.Evidence.AssuranceAdjudications,
				record.Evidence.AssuranceAdjudications[0],
			)
		},
		"duplicate exhaustive": func(record *runRecord) {
			record.Evidence.ExhaustiveAssurance = append(
				record.Evidence.ExhaustiveAssurance,
				record.Evidence.ExhaustiveAssurance[0],
			)
		},
		"unknown exhaustive": func(record *runRecord) {
			receipt := record.Evidence.ExhaustiveAssurance[0]
			receipt.CandidateID = "foreign-candidate"
			receipt.Identity = deliveryevidence.ExhaustiveAssuranceReceiptIdentity(receipt)
			record.Evidence.ExhaustiveAssurance = append(record.Evidence.ExhaustiveAssurance, receipt)
		},
		"injected exhaustive history": func(record *runRecord) {
			candidate := &record.Candidates[len(record.Candidates)-1]
			proof := *candidate.Exhaustive
			proof.TimingSequence = candidate.ReviewBatches[0].TimingSequence
			proof.CompletedAt = candidate.ReviewBatches[0].CompletedAt
			candidate.ExhaustiveHistory = append(candidate.ExhaustiveHistory, proof)
			receipt := record.Evidence.ExhaustiveAssurance[0]
			receipt.CompletedAt = proof.CompletedAt
			receipt.Identity = deliveryevidence.ExhaustiveAssuranceReceiptIdentity(receipt)
			record.Evidence.ExhaustiveAssurance = append(record.Evidence.ExhaustiveAssurance, receipt)
		},
	} {
		t.Run(name, func(t *testing.T) {
			record, decodeErr := decodeRun(persistedAssuranceRun(t, module, git))
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			mutate(&record)
			if err := validateRun(record); err == nil {
				t.Fatalf("%s assurance projection was admitted", name)
			}
		})
	}
	risk := module.risk.(*fakeCandidateRiskObserver)
	risk.effects = []EffectObservation{{
		Effect: EffectOrdinaryBehavior, Evidence: "standard behavior", Complete: true,
	}}
	reviewer.responses[deliveryevidence.ReviewStandards] = []CandidateReview{{
		Completed: true,
		Findings: []deliveryevidence.ReviewFinding{{
			ID: "S357-escalated", Axis: deliveryevidence.ReviewStandards,
			Severity:  deliveryevidence.SeverityP2,
			Authority: deliveryevidence.AuthorityDocumentedStandard,
			Citation:  "AGENTS.md", Location: "internal/issuedelivery/assurance.go",
			Evidence: "fresh escalated review finding",
		}},
	}}
	escalated := mustAdvance(t, module, request)
	if escalated.State != StateNeedsReview ||
		escalated.Candidate.ReviewIteration != len(before.Reviews)+1 ||
		!reflect.DeepEqual(escalated.Candidate.Reviews, before.Reviews) ||
		escalated.Candidate.RepairDecision == nil ||
		escalated.Candidate.RepairDecision.Class != RepairAdjudicationOnly ||
		len(escalated.Candidate.Acceptance) != 0 || escalated.Candidate.Exhaustive != nil ||
		len(escalated.Candidate.ExhaustiveHistory) != 1 ||
		len(escalated.Evidence.ExhaustiveAssurance) != 1 {
		t.Fatalf("adjudicated profile escalation lost review history: %#v", escalated)
	}
	rereviewed := mustAdvance(t, module, request)
	if len(rereviewed.Candidate.Reviews) != len(before.Reviews)+2 ||
		!reflect.DeepEqual(rereviewed.Candidate.Reviews[:len(before.Reviews)], before.Reviews) ||
		rereviewed.Candidate.RepairDecision == nil || rereviewed.Repair == nil ||
		!reflect.DeepEqual(rereviewed.Repair.FindingIDs, []string{"S357-escalated"}) {
		t.Fatalf("profile escalation re-review did not append history: %#v", rereviewed)
	}
	resumedFinding := mustAdvance(t, module, request)
	if !reflect.DeepEqual(resumedFinding.Repair, rereviewed.Repair) ||
		!reflect.DeepEqual(resumedFinding.Candidate.RepairDecision, rereviewed.Candidate.RepairDecision) {
		t.Fatalf("pending escalated finding did not resume: %#v", resumedFinding)
	}
	pendingBytes := persistedAssuranceRun(t, module, git)
	for _, test := range []struct {
		name   string
		mutate func(*Candidate)
	}{
		{"missing historical disposition", func(candidate *Candidate) {
			candidate.RepairDecision.Findings = candidate.RepairDecision.Findings[1:]
		}},
		{"historical disposition claims pending finding", func(candidate *Candidate) {
			candidate.RepairDecision.Findings[0].FindingID = "S357-escalated"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, err := decodeRun(pendingBytes)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&record.Candidates[len(record.Candidates)-1])
			if err := validateRun(record); err == nil {
				t.Fatal("tampered cumulative historical disposition was admitted")
			}
		})
	}
	escalatedDecision := RepairDecision{
		CandidateID: rereviewed.Candidate.ID, Class: RepairAdjudicationOnly,
		Findings: []FindingDecision{{
			FindingID: "S357-escalated", Disposition: FindingRejected,
			Evidence: "escalated evidence disproves finding",
		}},
	}
	readjudicated := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357, Repair: &escalatedDecision,
	})
	if readjudicated.Candidate.RepairDecision == nil ||
		len(readjudicated.Candidate.RepairDecision.Findings) != 3 ||
		unresolvedFindingIDs(readjudicated.Candidate) != nil {
		t.Fatalf("escalated adjudication was not cumulative: %#v", readjudicated)
	}
	replayed := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357, Repair: &escalatedDecision,
	})
	if !reflect.DeepEqual(replayed.Candidate.RepairDecision, readjudicated.Candidate.RepairDecision) ||
		len(replayed.Timing) != len(readjudicated.Timing) {
		t.Fatalf("escalated adjudication replay changed persisted history: %#v", replayed)
	}
	for _, invalid := range []RepairDecision{
		{
			CandidateID: escalatedDecision.CandidateID, Class: RepairAdjudicationOnly,
			Findings: append(append([]FindingDecision(nil), escalatedDecision.Findings...),
				escalatedDecision.Findings[0]),
		},
		{
			CandidateID: escalatedDecision.CandidateID, Class: RepairBounded,
			Findings: escalatedDecision.Findings,
		},
		{
			CandidateID: escalatedDecision.CandidateID, Class: RepairAdjudicationOnly,
			Findings: []FindingDecision{{
				FindingID: "S357-escalated", Disposition: FindingAccepted,
				Evidence: "accepted instead",
			}},
		},
	} {
		if _, err := module.Advance(context.Background(), Request{
			RepositoryPath: "/repo", IssueNumber: 357, Repair: &invalid,
		}); err == nil {
			t.Fatalf("invalid last-batch replay was admitted: %#v", invalid)
		}
	}
	lastBatchBytes := persistedAssuranceRun(t, module, git)
	for _, mutate := range []func(*RepairBatchReceipt){
		func(receipt *RepairBatchReceipt) { receipt.RequestID = "tampered" },
		func(receipt *RepairBatchReceipt) { receipt.Decision.Class = RepairBounded },
		func(receipt *RepairBatchReceipt) {
			receipt.Decision.Findings[0].Evidence = "tampered evidence"
		},
	} {
		record, err := decodeRun(lastBatchBytes)
		if err != nil {
			t.Fatal(err)
		}
		mutate(record.Candidates[len(record.Candidates)-1].LastRepairBatch)
		if err := validateRun(record); err == nil {
			t.Fatal("tampered last repair batch was admitted")
		}
	}
	orphaned, err := decodeRun(lastBatchBytes)
	if err != nil {
		t.Fatal(err)
	}
	orphaned.Candidates[len(orphaned.Candidates)-1].RepairDecision = nil
	if err := validateRun(orphaned); err == nil {
		t.Fatal("orphaned last repair batch was admitted")
	}
}

func TestProfileEscalationCannotDowngradeCandidateChangingRepairClass(t *testing.T) {
	module, git, _, reviewer, _ := assuranceFixture(t)
	reviewer.responses[deliveryevidence.ReviewStandards] = []CandidateReview{{
		Completed: true, Findings: []deliveryevidence.ReviewFinding{{
			ID: "accepted-first", Axis: deliveryevidence.ReviewStandards,
			Severity:  deliveryevidence.SeverityP2,
			Authority: deliveryevidence.AuthorityDocumentedStandard,
			Citation:  "AGENTS.md", Location: "internal/issuedelivery/assurance.go",
			Evidence: "candidate-changing repair needed",
		}},
	}}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	found := mustAdvance(t, module, request)
	accepted := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		Repair: &RepairDecision{
			CandidateID: found.Candidate.ID, Class: RepairCandidateChanging,
			Findings: []FindingDecision{{
				FindingID: "accepted-first", Disposition: FindingAccepted,
				Evidence: "repair as candidate-changing batch",
			}},
		},
	})
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, request.IssueNumber,
		func(store lockedIssueStore) error {
			_, data, found, loadErr := store.loadActive()
			if loadErr != nil || !found {
				return loadErr
			}
			record, decodeErr := decodeRun(data)
			if decodeErr != nil {
				return decodeErr
			}
			current := &record.Candidates[len(record.Candidates)-1]
			current.RepairBatches = nil
			current.LastRepairBatch = nil
			record.Evidence.AssuranceAdjudications = nil
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
	reviewer.responses[deliveryevidence.ReviewSpec] = []CandidateReview{{
		Completed: true, Findings: []deliveryevidence.ReviewFinding{{
			ID: "rejected-second", Axis: deliveryevidence.ReviewSpec,
			Severity:  deliveryevidence.SeverityP2,
			Authority: deliveryevidence.AuthoritySpecRequirement,
			Citation:  "issue#357", Location: "internal/issuedelivery/assurance.go",
			Evidence: "fresh escalation finding",
		}},
	}}
	module.risk.(*fakeCandidateRiskObserver).effects = []EffectObservation{{
		Effect: EffectOrdinaryBehavior, Evidence: "standard behavior", Complete: true,
	}}
	escalated := mustAdvance(t, module, request)
	if escalated.Candidate.ID != accepted.Candidate.ID {
		t.Fatalf("profile escalation changed candidate: %#v", escalated)
	}
	second := mustAdvance(t, module, request)
	merged := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		Repair: &RepairDecision{
			CandidateID: second.Candidate.ID, Class: RepairAdjudicationOnly,
			Findings: []FindingDecision{{
				FindingID: "rejected-second", Disposition: FindingRejected,
				Evidence: "evidence rejects fresh finding",
			}},
		},
	})
	if merged.Candidate.RepairDecision.Class != RepairCandidateChanging ||
		!strings.Contains(merged.Reason, "accepted findings") {
		t.Fatalf("later rejection downgraded accepted repair: %#v", merged)
	}
	persisted := persistedAssuranceRun(t, module, git)
	resumedRecord, err := decodeRun(persisted)
	if err != nil {
		t.Fatalf("cumulative accepted repair did not resume: %v", err)
	}
	resumedCandidate := &resumedRecord.Candidates[len(resumedRecord.Candidates)-1]
	if len(resumedCandidate.RepairBatches) != 2 ||
		!resumedCandidate.RepairBatches[0].CompatiblePrefix ||
		resumedCandidate.LastRepairBatch == nil ||
		resumedCandidate.LastRepairBatch.CompatiblePrefix {
		t.Fatalf("historyless v2 repair was not bootstrapped: %#v", resumedCandidate)
	}
	for _, mutate := range []func(*deliveryevidence.AssuranceAdjudicationReceipt){
		func(receipt *deliveryevidence.AssuranceAdjudicationReceipt) { receipt.Class = string(RepairBounded) },
		func(receipt *deliveryevidence.AssuranceAdjudicationReceipt) {
			receipt.Findings[0].Evidence = "self-consistent forged adjudication evidence"
		},
		func(receipt *deliveryevidence.AssuranceAdjudicationReceipt) { receipt.Generation++ },
	} {
		record, err := decodeRun(persisted)
		if err != nil {
			t.Fatal(err)
		}
		receipt := &record.Evidence.AssuranceAdjudications[0]
		mutate(receipt)
		receipt.Identity = deliveryevidence.AssuranceAdjudicationReceiptIdentity(
			receipt.RequestID, receipt.CandidateID, receipt.Generation, receipt.Class,
			receipt.CompatiblePrefix, receipt.Findings,
		)
		if err := validateRun(record); err == nil {
			t.Fatal("self-consistent tampered adjudication receipt was admitted")
		}
	}
	for _, mutate := range []func(*Candidate){
		func(candidate *Candidate) { candidate.RepairDecision.Class = RepairBounded },
		func(candidate *Candidate) {
			for index := range candidate.RepairDecision.Findings {
				candidate.RepairDecision.Findings[index].Disposition = FindingRejected
			}
		},
	} {
		record, err := decodeRun(persisted)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&record.Candidates[len(record.Candidates)-1])
		if err := validateRun(record); err == nil {
			t.Fatal("tampered cumulative repair history was admitted")
		}
	}
	compatible, err := decodeRun(persisted)
	if err != nil {
		t.Fatal(err)
	}
	compatibleCandidate := &compatible.Candidates[len(compatible.Candidates)-1]
	for index := range compatibleCandidate.RepairDecision.Findings {
		if compatibleCandidate.RepairDecision.Findings[index].FindingID == "accepted-first" {
			compatibleCandidate.RepairDecision.Findings[index].Disposition = FindingRejected
		}
	}
	compatibleCandidate.RepairBatches[0].Decision.Findings[0].Disposition = FindingRejected
	compatibleReceipt := &compatible.Evidence.AssuranceAdjudications[0]
	compatibleReceipt.Findings[0].Disposition = string(FindingRejected)
	compatibleReceipt.CompatiblePrefix = true
	compatibleReceipt.Identity = deliveryevidence.AssuranceAdjudicationReceiptIdentity(
		compatibleReceipt.RequestID, compatibleReceipt.CandidateID, compatibleReceipt.Generation,
		compatibleReceipt.Class, compatibleReceipt.CompatiblePrefix, compatibleReceipt.Findings,
	)
	if err := validateRun(compatible); err != nil {
		t.Fatalf("compatible candidate-changing rejected-only prefix failed validation: %v", err)
	}
	compatibleCandidate.RepairBatches[0].CompatiblePrefix = false
	if err := validateRun(compatible); err == nil {
		t.Fatal("tampered compatible repair prefix was admitted")
	}
	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)
	next := mustAdvance(t, module, request)
	if next.Candidate.RepairClass != RepairCandidateChanging {
		t.Fatalf("new candidate did not inherit strongest repair class: %#v", next.Candidate)
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

func TestAdvanceBlocksInvalidBranchBeforeLegacyExhaustiveValidation(t *testing.T) {
	module, git, _, _, validator := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)

	git.value.Branch = "main"
	blocked := mustAdvance(t, module, request)
	if blocked.State != StateBlocked || blocked.BlockerKind != BlockerLocalReadiness ||
		blocked.NextAction != ActionRestoreLocalReadiness {
		t.Fatalf("invalid branch outcome=%#v", blocked)
	}
	if validator.exhaustiveCalls != 0 {
		t.Fatalf("invalid branch invoked exhaustive validator %d times", validator.exhaustiveCalls)
	}
	for _, form := range []string{
		"chore/issue-357-*", "feat/issue-357-*", "fix/issue-357-*",
	} {
		if !strings.Contains(blocked.Reason, form) {
			t.Fatalf("local-readiness reason %q does not list %q", blocked.Reason, form)
		}
	}
}

func TestAdvanceAcceptsEveryDeliveryBranchFormBeforeExhaustiveValidation(t *testing.T) {
	for _, branch := range []string{
		"chore/issue-357-readiness", "feat/issue-357-readiness", "fix/issue-357-readiness",
	} {
		t.Run(branch, func(t *testing.T) {
			module, git, _, _, validator := assuranceFixture(t)
			request := Request{RepositoryPath: "/repo", IssueNumber: 357}
			mustAdvance(t, module, request)
			mustAdvance(t, module, request)
			git.value.Branch = branch

			ready := mustAdvance(t, module, request)
			if ready.State != StateWaiting || ready.LocalReadiness == nil ||
				validator.exhaustiveCalls != 1 {
				t.Fatalf("accepted branch outcome=%#v exhaustive=%d", ready, validator.exhaustiveCalls)
			}
		})
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

func TestPersistedAcceptanceRequiresCurrentSpecReview(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 4 {
		mustAdvance(t, module, request)
	}
	record, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	current := &record.Candidates[len(record.Candidates)-1]
	current.ReviewIteration = len(current.Reviews) + 1
	if err := validateRun(record); err == nil ||
		!strings.Contains(err.Error(), "lacks a completed current Spec review") {
		t.Fatalf("fabricated pre-review acceptance validation error=%v", err)
	}
}

func TestPersistedReviewIterationsMustFollowCanonicalBatchSequence(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 4 {
		mustAdvance(t, module, request)
	}
	record, err := decodeRun(persistedAssuranceRun(t, module, git))
	if err != nil {
		t.Fatal(err)
	}
	current := &record.Candidates[len(record.Candidates)-1]
	current.ReviewIteration++
	for reviewIndex := range current.Reviews {
		current.Reviews[reviewIndex].Iteration++
		for proofIndex := range current.Reviews[reviewIndex].Acceptance {
			current.Reviews[reviewIndex].Acceptance[proofIndex].ReviewReceipt.Iteration++
		}
	}
	for batchIndex := range current.ReviewBatches {
		current.ReviewBatches[batchIndex].Iteration++
	}
	for proofIndex := range current.Acceptance {
		current.Acceptance[proofIndex].ReviewReceipt.Iteration++
	}
	if err := validateRun(record); err == nil ||
		!strings.Contains(err.Error(), "review iteration sequence") {
		t.Fatalf("self-consistent stale review iteration validation error=%v", err)
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
			if err := validateRun(record); err == nil {
				t.Fatalf("superseded %s reference validation error=%v", test.name, err)
			}
		})
	}
}

func TestPhaseOwnedPersistedCandidateRequiresCompleteExhaustiveAssurance(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	for range 4 {
		mustAdvance(t, module, request)
	}
	currentBytes := persistedAssuranceRun(t, module, git)
	t.Run("current acceptance removed", func(t *testing.T) {
		record, err := decodeRun(currentBytes)
		if err != nil {
			t.Fatal(err)
		}
		record.Candidates[len(record.Candidates)-1].Acceptance = nil
		if err := validateRun(record); err == nil {
			t.Fatal("current exhaustive candidate admitted a removed acceptance slice")
		}
	})

	git.value.HeadSHA = strings.Repeat("d", 40)
	git.value.TreeSHA = strings.Repeat("e", 40)
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	supersededBytes := persistedAssuranceRun(t, module, git)

	for _, test := range []struct {
		name   string
		mutate func(*runRecord)
	}{
		{"superseded acceptance removed", func(record *runRecord) {
			record.Candidates[0].Acceptance = nil
		}},
		{"superseded Standards review removed", func(record *runRecord) {
			reviews := record.Candidates[0].Reviews[:0]
			for _, review := range record.Candidates[0].Reviews {
				if review.Axis != deliveryevidence.ReviewStandards {
					reviews = append(reviews, review)
				}
			}
			record.Candidates[0].Reviews = reviews
		}},
		{"superseded Spec review removed", func(record *runRecord) {
			reviews := record.Candidates[0].Reviews[:0]
			for _, review := range record.Candidates[0].Reviews {
				if review.Axis != deliveryevidence.ReviewSpec {
					reviews = append(reviews, review)
				}
			}
			record.Candidates[0].Reviews = reviews
		}},
		{"superseded proof missing", func(record *runRecord) {
			record.Candidates[0].Acceptance = record.Candidates[0].Acceptance[:1]
		}},
		{"superseded proof duplicate", func(record *runRecord) {
			record.Candidates[0].Acceptance[1].Identity =
				record.Candidates[0].Acceptance[0].Identity
		}},
		{"superseded proof foreign", func(record *runRecord) {
			record.Candidates[0].Acceptance[1].Identity = "criterion-foreign"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, err := decodeRun(supersededBytes)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&record)
			if err := validateRun(record); err == nil {
				t.Fatal("incomplete superseded exhaustive assurance was admitted")
			}
		})
	}

	t.Run("pre-exhaustive validation reference", func(t *testing.T) {
		record, err := decodeRun(supersededBytes)
		if err != nil {
			t.Fatal(err)
		}
		current := &record.Candidates[len(record.Candidates)-1]
		if current.Exhaustive != nil || len(current.Acceptance) == 0 {
			t.Fatalf("fixture is not a pre-exhaustive reviewed candidate: %#v", current)
		}
		current.Acceptance[0].ValidationReceipt = &ValidationReceiptReference{
			Schema: deliveryevidence.ValidationReceiptV1, CandidateID: current.ID,
			CommitSHA: current.CommitSHA, TreeSHA: current.TreeSHA,
			CompletedAt: "2026-07-30T23:59:59Z",
		}
		if err := validateRun(record); err == nil ||
			!strings.Contains(err.Error(), "premature acceptance validation reference") {
			t.Fatalf("forged pre-exhaustive reference validation error=%v", err)
		}
	})
}

func persistedAssuranceRun(
	t *testing.T,
	module *Module,
	git *fakeGitObserver,
) []byte {
	t.Helper()
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
	return persisted
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
