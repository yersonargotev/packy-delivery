package issuedelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

type fakeGitObserver struct {
	mu    sync.Mutex
	value GitObservation
	calls int
}

func (f *fakeGitObserver) ObserveGit(_ context.Context, _ string) (GitObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.value, nil
}

type fakeGitHubObserver struct {
	mu    sync.Mutex
	value TrackerObservation
	calls int
	hook  func(int)
}

func (f *fakeGitHubObserver) ObserveIssue(_ context.Context, _ GitObservation, issue int) (TrackerObservation, error) {
	f.mu.Lock()
	f.calls++
	hook := f.hook
	value := f.value
	f.mu.Unlock()
	if hook != nil {
		hook(issue)
	}
	value.Issue.Number = issue
	return value, nil
}

type fakeClock struct {
	mu   sync.Mutex
	next time.Time
	step time.Duration
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	got := f.next
	f.next = f.next.Add(f.step)
	return got
}

func moduleFixture(t *testing.T, issue int) (*Module, *fakeGitObserver, *fakeGitHubObserver) {
	t.Helper()
	common := filepath.Join(t.TempDir(), "common")
	if err := os.MkdirAll(common, 0700); err != nil {
		t.Fatal(err)
	}
	git := &fakeGitObserver{value: GitObservation{
		CommonDir: common, Worktree: filepath.Join(filepath.Dir(common), "worktree"),
		OriginURL: "git@github.com:yersonargotev/packy.git", Owner: "yersonargotev", Name: "packy",
		StartingBaseSHA: strings.Repeat("a", 40), HeadSHA: strings.Repeat("b", 40),
		TreeSHA: strings.Repeat("c", 40), WorkspaceClean: true, Branch: "chore/issue-356-test",
	}}
	tracker := &fakeGitHubObserver{value: TrackerObservation{
		Repository: deliveryevidence.RepositoryIdentity{Owner: "yersonargotev", Name: "packy", NodeID: "R1"},
		Issue:      deliveryevidence.IssueIdentity{Number: issue, NodeID: "I1"},
		Title:      "Qualify one low-risk run",
		Body:       "explicit authority",
		State:      "OPEN",
		Labels:     []string{"delivery:low-risk", "type:chore", "status:approved"},
		Criteria: []AuthorityItem{
			{Text: "Persist one self-contained low-risk run.", EvidenceLink: "issue#356:criterion-1"},
			{Text: "Resume without creating a duplicate run.", EvidenceLink: "issue#356:criterion-2"},
		},
		Exclusions:   []AuthorityItem{{Text: "Do not push a branch.", EvidenceLink: "issue#356:out-of-scope"}},
		Dependencies: []DependencyObservation{},
		References:   []ReferenceObservation{},
		Ambiguities:  []AuthorityItem{},
	}}
	clock := &fakeClock{next: time.Date(2026, 7, 30, 1, 0, 0, 0, time.UTC), step: time.Second}
	module, err := New(Config{
		Git: git, GitHub: tracker, Clock: clock, DeclaredProfile: deliveryevidence.RiskLow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return module, git, tracker
}

func TestAdvanceRejectsInvalidAuthorityDeliveryProfileBinding(t *testing.T) {
	tests := []struct {
		name    string
		labels  []string
		profile deliveryevidence.DeliveryRiskProfile
		want    string
	}{
		{name: "missing", labels: []string{"status:approved"}, profile: deliveryevidence.RiskLow, want: "exactly one delivery profile"},
		{name: "multiple", labels: []string{"delivery:low-risk", "delivery:standard", "status:approved"}, profile: deliveryevidence.RiskLow, want: "exactly one delivery profile"},
		{name: "mismatch", labels: []string{"delivery:standard", "status:approved"}, profile: deliveryevidence.RiskLow, want: "does not match declared risk profile"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			module, _, tracker := moduleFixture(t, 356)
			module.declaredProfile = test.profile
			tracker.value.Labels = test.labels
			_, err := module.Advance(context.Background(), Request{
				RepositoryPath: "/repo", IssueNumber: 356,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want %q", err, test.want)
			}
		})
	}
}

func TestAdvanceIssue344StyleSelfContainedLowRiskRunCreatesAndResumes(t *testing.T) {
	module, git, tracker := moduleFixture(t, 356)
	request := Request{RepositoryPath: "/ignored/by-fake", IssueNumber: 356}

	first, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunID == "" || first.State != StateNeedsDecision || first.Evidence == nil ||
		first.QualificationCorrection == nil {
		t.Fatalf("fresh outcome = %#v", first)
	}
	if first.Evidence.Schema != deliveryevidence.SchemaV2 ||
		first.Evidence.Authority.Kind != deliveryevidence.AuthoritySelfContainedIssue ||
		first.Evidence.RiskProfile != deliveryevidence.RiskLow ||
		first.Evidence.Spec != (deliveryevidence.SpecIdentity{}) {
		t.Fatalf("fresh evidence = %#v", first.Evidence)
	}
	if first.DeliveryProfile == nil ||
		first.DeliveryProfile.AuthorityLabel != "delivery:low-risk" ||
		first.DeliveryProfile.Profile != deliveryevidence.RiskLow {
		t.Fatalf("delivery profile binding = %#v", first.DeliveryProfile)
	}
	if len(first.Evidence.AcceptanceMatrix) != 2 || len(first.Evidence.Scope.OwnedNow) != 2 ||
		len(first.Evidence.Scope.Forbidden) != 1 || len(first.Timing) != 1 {
		t.Fatalf("compiled run = %#v", first)
	}
	if first.Observations.CommitSHA != strings.Repeat("b", 40) ||
		first.Observations.TreeSHA != strings.Repeat("c", 40) ||
		!first.Observations.WorkspaceClean {
		t.Fatalf("persisted observations = %#v", first.Observations)
	}

	git.value.HeadSHA = strings.Repeat("d", 40)
	git.value.TreeSHA = strings.Repeat("e", 40)
	second, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.RunID != first.RunID || second.State != StateNeedsDecision ||
		len(second.Timing) != len(first.Timing) {
		t.Fatalf("resume changed run: first=%#v second=%#v", first, second)
	}
	if second.Observations.CommitSHA != strings.Repeat("d", 40) ||
		second.Observations.TreeSHA != strings.Repeat("e", 40) {
		t.Fatalf("resume returned stale observations: %#v", second.Observations)
	}
	if git.calls != 2 || tracker.calls != 2 {
		t.Fatalf("observations were not reacquired: git=%d github=%d", git.calls, tracker.calls)
	}
}

func TestAdvanceResumesSchemaV2RunWithoutDeliveryProfileBinding(t *testing.T) {
	module, git, _ := moduleFixture(t, 356)
	request := Request{RepositoryPath: "/repo", IssueNumber: 356}
	first := mustAdvance(t, module, request)
	var historical []byte
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, request.IssueNumber,
		func(store lockedIssueStore) error {
			_, data, found, err := store.loadActive()
			if err != nil || !found {
				return err
			}
			record, err := decodeRun(data)
			if err != nil {
				return err
			}
			record.DeliveryProfile = nil
			historical, err = encodeRun(record)
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	historicalModule, historicalGit, _ := moduleFixture(t, 356)
	err = historicalModule.store.withIssueLock(
		context.Background(), historicalGit.value.CommonDir, request.IssueNumber,
		func(store lockedIssueStore) error {
			return store.storeAndActivate(first.RunID, historical)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	resumed := mustAdvance(t, historicalModule, request)
	if resumed.RunID != first.RunID || resumed.DeliveryProfile != nil {
		t.Fatalf("resumed pre-binding v2 run=%#v", resumed)
	}
}

func TestAdvanceIssueWithSpecificationBindsAndRequalifiesChangedSpecification(t *testing.T) {
	module, _, tracker := moduleFixture(t, 361)
	tracker.value.Specification = &SpecificationObservation{
		Identity: deliveryevidence.SpecIdentity{Number: 354, NodeID: "S354"},
		Title:    "Specify risk-adjusted issue delivery",
		Body:     "The accepted delivery orchestration specification.",
		State:    "OPEN",
		URL:      "https://github.com/yersonargotev/packy/issues/354",
		Labels:   []string{"type:spec", "status:approved"},
	}
	request := Request{RepositoryPath: "/repo", IssueNumber: 361}

	first, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Evidence == nil ||
		first.Evidence.Authority.Kind != deliveryevidence.AuthorityIssueWithSpecification ||
		first.Evidence.Spec != tracker.value.Specification.Identity ||
		first.Evidence.Authority.SpecSHA256 == "" {
		t.Fatalf("issue-with-specification evidence = %#v", first.Evidence)
	}

	tracker.mu.Lock()
	tracker.value.Specification.Body += " Revised."
	tracker.mu.Unlock()
	second, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.RunID == first.RunID || second.SupersedesRunID != first.RunID ||
		second.Evidence.Authority.SpecSHA256 == first.Evidence.Authority.SpecSHA256 {
		t.Fatalf("changed specification did not requalify: first=%#v second=%#v", first, second)
	}
}

func TestAdvanceRejectsUnapprovedIssueOrSpecificationAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeGitHubObserver)
	}{
		{
			name: "issue",
			mutate: func(tracker *fakeGitHubObserver) {
				tracker.value.Labels = []string{"type:chore"}
			},
		},
		{
			name: "specification",
			mutate: func(tracker *fakeGitHubObserver) {
				tracker.value.Specification = &SpecificationObservation{
					Identity: deliveryevidence.SpecIdentity{Number: 354, NodeID: "S354"},
					Title:    "Spec", Body: "Normative authority.", State: "OPEN",
					URL:    "https://github.com/yersonargotev/packy/issues/354",
					Labels: []string{"type:spec"},
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			module, _, tracker := moduleFixture(t, 361)
			test.mutate(tracker)
			if _, err := module.Advance(
				context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 361},
			); err == nil || !strings.Contains(err.Error(), "approved") {
				t.Fatalf("unapproved authority accepted: %v", err)
			}
		})
	}
}

func TestAdvanceSupersedesChangedAuthorityWithoutRewritingPriorRun(t *testing.T) {
	module, _, tracker := moduleFixture(t, 356)
	request := Request{RepositoryPath: "/repo", IssueNumber: 356}
	originalCriteria := append([]AuthorityItem(nil), tracker.value.Criteria...)
	first, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(
		module.storePathForTest(t, 356), "runs", first.RunID+".json",
	)
	oldBytes, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}

	tracker.mu.Lock()
	tracker.value.Criteria = append(tracker.value.Criteria, AuthorityItem{
		Text: "Record automatic phase timing.", EvidenceLink: "issue#356:criterion-3",
	})
	tracker.mu.Unlock()
	second, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.RunID == first.RunID || second.SupersedesRunID != first.RunID ||
		len(second.Evidence.AcceptanceMatrix) != 3 {
		t.Fatalf("requalified outcome = %#v", second)
	}
	gotOldBytes, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotOldBytes, oldBytes) {
		t.Fatal("superseding authority rewrote the prior run")
	}

	tracker.mu.Lock()
	tracker.value.Criteria = originalCriteria
	tracker.mu.Unlock()
	third, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if third.RunID == first.RunID || third.RunID == second.RunID ||
		third.SupersedesRunID != second.RunID {
		t.Fatalf("A-B-A requalification reused history: first=%s second=%s third=%#v", first.RunID, second.RunID, third)
	}
	gotOldBytes, err = os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotOldBytes, oldBytes) {
		t.Fatal("A-B-A requalification rewrote the original run")
	}
}

func TestAdvanceCompilesStableProfileIDsFromNormalizedAuthority(t *testing.T) {
	module, _, tracker := moduleFixture(t, 356)
	tracker.value.References = []ReferenceObservation{{
		Identity: "ADR 0020", URL: "docs/adr/0020-adopt-risk-adjusted-issue-delivery-orchestration.md",
	}}
	first, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 356})
	if err != nil {
		t.Fatal(err)
	}
	firstIDs := acceptanceIDs(first)

	tracker.mu.Lock()
	tracker.value.Criteria = []AuthorityItem{
		{Text: "  Resume without creating a duplicate run. ", EvidenceLink: "issue#356:criterion-2"},
		{Text: "Persist   one self-contained low-risk run.", EvidenceLink: "issue#356:criterion-1"},
	}
	tracker.mu.Unlock()
	second, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 356})
	if err != nil {
		t.Fatal(err)
	}
	if got := acceptanceIDs(second); strings.Join(got, ",") != strings.Join(firstIDs, ",") {
		t.Fatalf("stable IDs changed: first=%v second=%v", firstIDs, got)
	}
	if len(second.Evidence.Scope.Prerequisites) != 1 ||
		!strings.HasPrefix(second.Evidence.Scope.Prerequisites[0].Identity, "reference-") {
		t.Fatalf("authority references were not compiled: %#v", second.Evidence.Scope.Prerequisites)
	}
	for _, row := range second.Evidence.AcceptanceMatrix {
		if row.OwningSeam == "" || row.PositiveEvidence == "" || row.NegativeEvidence == "" ||
			row.FailureEvidence == "" || row.MutationEvidence == "" ||
			row.CompatibilityEvidence == "" || row.PreservationEvidence == "" ||
			row.MigrationEvidence == "" {
			t.Fatalf("profile-shaped row is incomplete: %#v", row)
		}
	}
}

func TestAdvancePausesForTypedDecisionAndResumesWithMatchingAnswer(t *testing.T) {
	module, _, tracker := moduleFixture(t, 356)
	tracker.value.Ambiguities = []AuthorityItem{{
		Text:         "Should compatibility with v1 be part of this issue?",
		EvidenceLink: "issue#356:question-1",
	}}
	request := Request{RepositoryPath: "/repo", IssueNumber: 356}
	pending, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if pending.State != StateNeedsDecision || pending.Decision == nil || pending.Evidence != nil {
		t.Fatalf("pending outcome = %#v", pending)
	}
	if pending.PauseCause != PauseSemanticInput || pending.NextAction != ActionProvideDecision {
		t.Fatalf("pending pause metadata = %q, %q", pending.PauseCause, pending.NextAction)
	}

	_, err = module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
		Decision: &Decision{RequestID: "wrong", Disposition: DecisionForbidden, Requirement: "No v1 changes.", EvidenceLink: "caller:decision"},
	})
	var mismatch *DecisionMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("mismatched decision error = %v", err)
	}

	resolved, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
		Decision: &Decision{
			RequestID: pending.Decision.ID, Disposition: DecisionForbidden,
			Requirement: "Do not change the v1 workflow.", EvidenceLink: "caller:decision-1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.State != StateNeedsDecision || resolved.Evidence == nil ||
		resolved.QualificationCorrection == nil ||
		resolved.SupersedesRunID != pending.RunID || len(resolved.Evidence.Scope.Forbidden) != 2 {
		t.Fatalf("resolved outcome = %#v", resolved)
	}
	resumed, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.RunID != resolved.RunID || resumed.State != StateNeedsDecision {
		t.Fatalf("resolved decision was not resumed: resolved=%#v resumed=%#v", resolved, resumed)
	}
	if resumed.PauseCause != resolved.PauseCause || resumed.NextAction != resolved.NextAction {
		t.Fatalf("resumed pause metadata changed: resolved=%#v resumed=%#v", resolved, resumed)
	}
}

func TestOutcomeWithPauseDerivesExactActionFromTypedFacts(t *testing.T) {
	candidate := &Candidate{
		ID: "candidate-1", RequiredReviews: []deliveryevidence.ReviewAxis{deliveryevidence.ReviewSpec},
	}
	reviewedCandidate := &Candidate{ID: "candidate-2"}
	repairCandidate := &Candidate{
		ID: "candidate-3",
		RepairDecision: &RepairDecision{Findings: []FindingDecision{{
			FindingID: "finding-1", Disposition: FindingAccepted,
		}}},
	}
	readiness := &LocalReadiness{CandidateID: candidate.ID}
	tests := []struct {
		name    string
		outcome Outcome
		cause   PauseCause
		action  NextAction
	}{
		{
			name: "semantic decision", outcome: Outcome{
				State: StateNeedsDecision, Decision: &DecisionRequest{},
			},
			cause: PauseSemanticInput, action: ActionProvideDecision,
		},
		{
			name: "qualification correction", outcome: Outcome{
				State: StateNeedsDecision, QualificationCorrection: &QualificationCorrectionRequest{},
			},
			cause: PauseSemanticInput, action: ActionProvideQualificationCorrection,
		},
		{
			name: "repair decision", outcome: Outcome{
				State: StateNeedsDecision, Repair: &RepairDecisionRequest{},
			},
			cause: PauseSemanticInput, action: ActionProvideRepairDecision,
		},
		{
			name: "qualification review", outcome: Outcome{State: StateNeedsReview},
			cause: PauseIndependentReview, action: ActionProvideQualificationReview,
		},
		{
			name: "candidate review", outcome: Outcome{
				State: StateNeedsReview, Candidate: candidate,
			},
			cause: PauseIndependentReview, action: ActionProvideCandidateReview,
		},
		{
			name: "post-qualification advance", outcome: Outcome{
				State: StateNeedsReview, QualificationApproved: true,
			},
			cause: PauseDeterministicAdvance, action: ActionAdvance,
		},
		{
			name: "post-review advance", outcome: Outcome{
				State: StateNeedsReview, Candidate: reviewedCandidate,
			},
			cause: PauseDeterministicAdvance, action: ActionAdvance,
		},
		{
			name: "repair candidate", outcome: Outcome{
				State: StateNeedsReview, Candidate: repairCandidate,
			},
			cause: PauseCandidateRepair, action: ActionRepairCandidate,
		},
		{
			name: "external result", outcome: Outcome{State: StateWaiting},
			cause: PauseExternalResult, action: ActionObserveExternalResult,
		},
		{
			name: "non-local authorization", outcome: Outcome{
				State: StateWaiting, RunSchema: runSchema,
				Evidence:  &deliveryevidence.Bundle{Schema: deliveryevidence.SchemaV2},
				Candidate: candidate, LocalReadiness: readiness,
			},
			cause: PauseNonLocalAuthorization, action: ActionAuthorizeNonLocal,
		},
		{
			name: "invariant block", outcome: Outcome{
				State: StateBlocked, BlockerKind: BlockerAuthority,
				Timing: []Timing{{Phase: "qualification"}},
			},
			cause: PauseInvariantBlock, action: ActionResolveAuthorityBlock,
		},
		{
			name: "legacy workflow", outcome: Outcome{
				State: StateWaiting, RunSchema: legacyRunSchema,
				Evidence:       &deliveryevidence.Bundle{Schema: deliveryevidence.SchemaV2},
				LocalReadiness: readiness,
			},
			cause: PauseLegacyWorkflow, action: ActionResumeLegacyV1,
		},
		{
			name: "completion", outcome: Outcome{State: StateCompleted},
			cause: PauseCompleted, action: ActionNone,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := outcomeWithPause(test.outcome)
			if got.PauseCause != test.cause || got.NextAction != test.action {
				t.Fatalf("pause metadata = %q, %q; want %q, %q", got.PauseCause, got.NextAction, test.cause, test.action)
			}
		})
	}
}

func TestOutcomeFromLegacyEnvelopeUsesRunSchemaForReadinessAction(t *testing.T) {
	outcome := outcomeWithPause(outcomeFromRecord(runRecord{
		Schema: legacyRunSchema, State: StateWaiting,
		Evidence:       &deliveryevidence.Bundle{Schema: deliveryevidence.SchemaV2},
		LocalReadiness: &LocalReadiness{CandidateID: "legacy-candidate"},
	}))
	if outcome.RunSchema != legacyRunSchema ||
		outcome.PauseCause != PauseLegacyWorkflow ||
		outcome.NextAction != ActionResumeLegacyV1 {
		t.Fatalf("legacy envelope pause metadata = %#v", outcome)
	}
}

func TestAdvanceIssueLockWaitIncludesStableExternalObservation(t *testing.T) {
	module, git, _ := moduleFixture(t, 356)
	var first Outcome
	err := module.store.withIssueLock(
		context.Background(),
		git.value.CommonDir,
		356,
		func(lockedIssueStore) error {
			var err error
			first, err = module.Advance(context.Background(), Request{
				RepositoryPath: "/repo", IssueNumber: 356,
			})
			return err
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != StateWaiting || first.PauseCause != PauseLockContention ||
		first.NextAction != ActionRetryAdvance {
		t.Fatalf("issue-lock outcome = %#v", first)
	}
	second := outcomeWithPause(Outcome{
		State: first.State, Reason: first.Reason, IssueLockContended: first.IssueLockContended,
	})
	if second.PauseCause != first.PauseCause || second.NextAction != first.NextAction {
		t.Fatalf("repeated issue-lock metadata changed: first=%#v second=%#v", first, second)
	}
}

func TestBlockedNextActionCoversProductionTransitionPhases(t *testing.T) {
	tests := map[string]NextAction{
		"qualification":            ActionResolveAuthorityBlock,
		"qualification-review":     ActionResolveAuthorityBlock,
		"qualification-correction": ActionResolveAuthorityBlock,
		"post-merge-observation":   ActionReconcileMerge,
		"specialist-review":        ActionRestoreSpecialistReview,
		"risk-observation":         ActionRepairRiskObservation,
		"focused-validation":       ActionRepairValidationEnvironment,
		"boundary-validation":      ActionRepairValidationEnvironment,
		"exhaustive-validation":    ActionRepairValidationEnvironment,
		"local-readiness":          ActionRestoreLocalReadiness,
		"non-local-freshness":      ActionRestoreNonLocalFreshness,
		"non-local-observation":    ActionRestoreNonLocalObservation,
		"branch-push":              ActionReconcileRemoteBranch,
		"pull-request":             ActionReconcilePullRequest,
		"ci-wait":                  ActionRestoreCIObservation,
		"merge-readiness":          ActionRestoreMergeReadiness,
		"merge-adoption":           ActionReconcileMerge,
		"merge":                    ActionReconcileMerge,
		"integration-verification": ActionReconcileIntegration,
		"remote-cleanup":           ActionReconcileRemoteCleanup,
		"worktree-cleanup":         ActionReconcileWorktreeCleanup,
		"local-branch-cleanup":     ActionReconcileLocalBranchCleanup,
		"main-synchronization":     ActionReconcileMainSynchronization,
		"local-cleanup":            ActionReconcileLocalCleanup,
	}
	for phase, want := range tests {
		t.Run(phase, func(t *testing.T) {
			record := runRecord{
				State: StateBlocked, Reason: "generic blocked condition",
				Timing: []Timing{{Phase: phase}},
			}
			if got := blockerNextAction(blockerKindFromRecord(record)); got != want {
				t.Fatalf("blocked action = %q, want %q", got, want)
			}
		})
	}
	specific := []struct {
		name, phase, reason string
		kind                BlockerKind
		action              NextAction
	}{
		{
			name: "missing observer", phase: "post-merge-observation",
			reason: "existing pull request requires a non-local observer to exclude or adopt merge; candidate flow remains disabled",
			kind:   BlockerNonLocalObserver, action: ActionConfigureNonLocalObserver,
		},
		{
			name: "missing local completion observer", phase: "post-merge-observation",
			reason: "confirmed merge requires a local verification and cleanup adapter; candidate flow remains disabled",
			kind:   BlockerLocalCompletionObserver, action: ActionConfigureLocalCompletionObserver,
		},
		{
			name: "merge absent", phase: "post-merge-observation",
			reason: "confirmed merge is absent from current observation; preserve external state for inspection",
			kind:   BlockerMergeObservationAbsent, action: ActionInspectMergeObservation,
		},
		{
			name: "closed without merge", phase: "post-merge-observation",
			reason: "issue closed without an exact matching merge; preserve external state for inspection",
			kind:   BlockerIssueClosure, action: ActionInspectIssueClosure,
		},
		{
			name: "ci attribution", phase: "ci-wait",
			reason: "CI failure attribution is unknown; classify the exact failed run before retrying or repairing",
			kind:   BlockerCIAttribution, action: ActionProvideCIAttribution,
		},
		{
			name: "acceptance traceability", phase: "exhaustive-validation",
			reason: "exhaustive validation lacks exact acceptance traceability",
			kind:   BlockerAcceptanceTraceability, action: ActionRepairAcceptanceTraceability,
		},
		{
			name: "merge adoption local observation", phase: "merge-adoption",
			reason: "pre-merge local/operator observation is incomplete or incompatible",
			kind:   BlockerLocalCleanup, action: ActionReconcileLocalCleanup,
		},
	}
	for _, test := range specific {
		t.Run(test.name, func(t *testing.T) {
			record := runRecord{
				State: StateBlocked, Reason: test.reason, Timing: []Timing{{Phase: test.phase}},
			}
			kind := blockerKindFromRecord(record)
			if kind != test.kind || blockerNextAction(kind) != test.action {
				t.Fatalf("blocker = %q, %q; want %q, %q", kind, blockerNextAction(kind), test.kind, test.action)
			}
		})
	}
	if got := blockerNextAction(blockerKindFromRecord(runRecord{
		State: StateBlocked, Reason: "unknown", Timing: []Timing{{Phase: "unknown"}},
	})); got != ActionInspectBlockedTransition {
		t.Fatalf("unknown blocker action = %q", got)
	}
}

func TestAdvanceResolvesEveryMaterialAmbiguityBeforeReview(t *testing.T) {
	module, _, tracker := moduleFixture(t, 356)
	tracker.value.Ambiguities = []AuthorityItem{
		{Text: "Include v1 compatibility?", EvidenceLink: "issue#356:question-1"},
		{Text: "Include CLI wiring?", EvidenceLink: "issue#356:question-2"},
	}
	request := Request{RepositoryPath: "/repo", IssueNumber: 356}
	outcome, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := 0; sequence < 2; sequence++ {
		if outcome.State != StateNeedsDecision || outcome.Decision == nil {
			t.Fatalf("ambiguity %d was skipped: %#v", sequence+1, outcome)
		}
		outcome, err = module.Advance(context.Background(), Request{
			RepositoryPath: "/repo", IssueNumber: 356,
			Decision: &Decision{
				RequestID: outcome.Decision.ID, Disposition: DecisionForbidden,
				Requirement: "Exclude " + outcome.Decision.Evidence, EvidenceLink: "caller:decision-" + strconv.Itoa(sequence+1),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if outcome.State != StateNeedsDecision || outcome.QualificationCorrection == nil ||
		len(outcome.Evidence.Scope.Forbidden) != 3 {
		t.Fatalf("all ambiguities resolved outcome = %#v", outcome)
	}
}

func TestAdvanceSupersedesChangedAmbiguityEvidence(t *testing.T) {
	module, _, tracker := moduleFixture(t, 356)
	tracker.value.Ambiguities = []AuthorityItem{{
		Text: "Include v1 compatibility?", EvidenceLink: "issue#356:question-1",
	}}
	first, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 356})
	if err != nil {
		t.Fatal(err)
	}
	tracker.value.Ambiguities[0].Text = "Include both v1 compatibility and migration?"
	second, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 356})
	if err != nil {
		t.Fatal(err)
	}
	if second.RunID == first.RunID || second.SupersedesRunID != first.RunID ||
		second.Decision.ID == first.Decision.ID {
		t.Fatalf("changed ambiguity resumed stale prompt: first=%#v second=%#v", first, second)
	}
}

func TestAdvanceAdvertisesOnlySupportedDecisionsAndRejectsUnsolicitedInput(t *testing.T) {
	module, _, tracker := moduleFixture(t, 356)
	tracker.value.Criteria = nil
	pending, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 356})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Decision.Kind != DecisionSupplyCriterion ||
		len(pending.Decision.Options) != 1 || pending.Decision.Options[0] != DecisionOwnedNow {
		t.Fatalf("criterion decision options = %#v", pending.Decision)
	}

	cleanModule, _, _ := moduleFixture(t, 357)
	_, err = cleanModule.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		Decision: &Decision{
			RequestID: "unsolicited", Disposition: DecisionOwnedNow,
			Requirement: "Invented criterion", EvidenceLink: "caller:unsolicited",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "not requested") {
		t.Fatalf("unsolicited decision error = %v", err)
	}
}

func TestAdvanceRejectsSemanticallyInvalidPersistedRun(t *testing.T) {
	module, _, _ := moduleFixture(t, 356)
	request := Request{RepositoryPath: "/repo", IssueNumber: 356}
	outcome, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	runPath := filepath.Join(module.storePathForTest(t, 356), "runs", outcome.RunID+".json")
	data, err := os.ReadFile(runPath)
	if err != nil {
		t.Fatal(err)
	}
	var wire runWire
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	wire.State = StateCompleted
	data, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := module.Advance(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "completed run requires admitted evidence") {
		t.Fatalf("invalid persisted run error = %v", err)
	}
}

func TestAdvanceRecoversRunPersistedWithoutActivePointer(t *testing.T) {
	module, _, _ := moduleFixture(t, 356)
	request := Request{RepositoryPath: "/repo", IssueNumber: 356}
	first, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(module.storePathForTest(t, 356), "active.json")
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}

	recovered, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.RunID != first.RunID || !reflect.DeepEqual(recovered.Timing, first.Timing) {
		t.Fatalf("orphaned run was regenerated: first=%#v recovered=%#v", first, recovered)
	}
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("active pointer was not recovered: %v", err)
	}
}

func TestAdvanceAdoptsPreCompilerCorrectionOrphanAndConverges(t *testing.T) {
	module, _, _ := moduleFixture(t, 356)
	request := Request{RepositoryPath: "/repo", IssueNumber: 356}
	created, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	runPath := filepath.Join(module.storePathForTest(t, 356), "runs", created.RunID+".json")
	data, err := os.ReadFile(runPath)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeRun(data)
	if err != nil {
		t.Fatal(err)
	}
	record.State = StateNeedsReview
	record.Reason = "qualification evidence is ready for independent review"
	record.PendingQualificationCorrection = nil
	record.Timing[len(record.Timing)-1].To = StateNeedsReview
	historical, err := encodeRun(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runPath, historical, 0o600); err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(module.storePathForTest(t, 356), "active.json")
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}

	adopted, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if adopted.RunID != created.RunID || adopted.State != StateNeedsDecision ||
		adopted.QualificationCorrection == nil ||
		len(adopted.QualificationReviews) != 0 {
		t.Fatalf("historical qualification orphan was not adopted and converged: %#v", adopted)
	}
	revisions, err := os.ReadDir(filepath.Join(
		module.storePathForTest(t, 356), "revisions", created.RunID,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(revisions) != 1 {
		t.Fatalf("historical orphan convergence revisions = %d, want 1", len(revisions))
	}
}

func TestAdvanceRejectsSymlinkedStateDirectory(t *testing.T) {
	module, git, _ := moduleFixture(t, 356)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(git.value.CommonDir, "packy")); err != nil {
		t.Fatal(err)
	}
	if _, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
	}); err == nil {
		t.Fatal("Advance accepted a symlinked state directory")
	}
}

func TestAdvanceUsesLockedDirectoryForEveryStateOperation(t *testing.T) {
	module, _, tracker := moduleFixture(t, 356)
	issueDir := module.storePathForTest(t, 356)
	movedDir := issueDir + "-moved"
	tracker.hook = func(issue int) {
		if issue != 356 {
			return
		}
		if err := os.Rename(issueDir, movedDir); err != nil {
			t.Error(err)
			return
		}
		if err := os.Mkdir(issueDir, 0700); err != nil {
			t.Error(err)
		}
	}
	outcome, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(movedDir, "runs", outcome.RunID+".json")); err != nil {
		t.Fatalf("run escaped the locked directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(movedDir, "active.json")); err != nil {
		t.Fatalf("active pointer escaped the locked directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(issueDir, "active.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory received state: %v", err)
	}
}

func TestAdvanceReportsBlockedDependency(t *testing.T) {
	module, _, tracker := moduleFixture(t, 356)
	tracker.value.Dependencies = []DependencyObservation{{
		Identity: "issue-355", Number: 355, Title: "Admit v2 evidence",
		State: "OPEN", URL: "https://github.com/yersonargotev/packy/issues/355",
	}}
	outcome, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 356})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.State != StateBlocked ||
		outcome.BlockerKind != BlockerAuthority ||
		outcome.NextAction != ActionResolveAuthorityBlock ||
		outcome.Evidence.Authority.DependencyDisposition[0].Disposition != deliveryevidence.DependencyBlocking {
		t.Fatalf("blocked outcome = %#v", outcome)
	}
	replayed, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
	})
	if err != nil {
		t.Fatal(err)
	}
	if replayed.BlockerKind != outcome.BlockerKind || replayed.NextAction != outcome.NextAction {
		t.Fatalf("replayed blocker changed: first=%#v replayed=%#v", outcome, replayed)
	}
}

func TestAdvanceSerializesOneIssueButAllowsDifferentIssues(t *testing.T) {
	module, _, tracker := moduleFixture(t, 356)
	entered := make(chan struct{})
	release := make(chan struct{})
	tracker.hook = func(issue int) {
		if issue == 356 {
			close(entered)
			<-release
		}
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 356})
		firstDone <- err
	}()
	<-entered

	waiting, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 356})
	if err != nil {
		t.Fatal(err)
	}
	if waiting.State != StateWaiting {
		t.Fatalf("same issue contention = %#v", waiting)
	}
	other, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 357})
	if err != nil {
		t.Fatal(err)
	}
	if other.State != StateNeedsDecision || other.QualificationCorrection == nil {
		t.Fatalf("different issue outcome = %#v", other)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestAdvanceRecordsAutomaticPhaseTiming(t *testing.T) {
	module, _, _ := moduleFixture(t, 356)
	outcome, err := module.Advance(context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 356})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Timing) != 1 {
		t.Fatalf("timing = %#v", outcome.Timing)
	}
	timing := outcome.Timing[0]
	if timing.Sequence != 1 || timing.Phase != "qualification" ||
		timing.StartedAt != "2026-07-30T01:00:00.000000000Z" ||
		timing.CompletedAt != "2026-07-30T01:00:01.000000000Z" {
		t.Fatalf("automatic timing = %#v", timing)
	}
}

func (m *Module) storePathForTest(t *testing.T, issue int) string {
	t.Helper()
	git := m.git.(*fakeGitObserver)
	return filepath.Join(git.value.CommonDir, "packy", "issue-delivery", "issue-"+strconv.Itoa(issue))
}

func acceptanceIDs(outcome Outcome) []string {
	ids := make([]string, 0, len(outcome.Evidence.AcceptanceMatrix))
	for _, row := range outcome.Evidence.AcceptanceMatrix {
		ids = append(ids, row.Identity)
	}
	return ids
}
