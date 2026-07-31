package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type fakeIssueDeliveryAdvancer struct {
	outcomes []issuedelivery.Outcome
	requests []issuedelivery.Request
}

type commandGitObserver struct {
	observation issuedelivery.GitObservation
}

func (o commandGitObserver) ObserveGit(context.Context, string) (issuedelivery.GitObservation, error) {
	return o.observation, nil
}

type commandTrackerObserver struct {
	observation issuedelivery.TrackerObservation
}

type commandMutableTrackerObserver struct {
	observation issuedelivery.TrackerObservation
}

type commandBlockingTrackerObserver struct {
	observation issuedelivery.TrackerObservation
	entered     chan struct{}
	release     chan struct{}
}

func (o commandTrackerObserver) ObserveIssue(
	_ context.Context,
	_ issuedelivery.GitObservation,
	_ int,
) (issuedelivery.TrackerObservation, error) {
	return o.observation, nil
}

func (o *commandMutableTrackerObserver) ObserveIssue(
	_ context.Context,
	_ issuedelivery.GitObservation,
	_ int,
) (issuedelivery.TrackerObservation, error) {
	return o.observation, nil
}

func (o *commandBlockingTrackerObserver) ObserveIssue(
	_ context.Context,
	_ issuedelivery.GitObservation,
	_ int,
) (issuedelivery.TrackerObservation, error) {
	close(o.entered)
	<-o.release
	return o.observation, nil
}

type commandClock struct {
	now time.Time
}

type commandWaitingNonLocalGateway struct{}

type commandFindingReviewExecutor struct{}

func (commandFindingReviewExecutor) Review(
	_ context.Context,
	request issuedelivery.ReviewRequest,
) (issuedelivery.CandidateReview, error) {
	findings := []deliveryevidence.ReviewFinding{}
	if request.Axis == deliveryevidence.ReviewStandards {
		findings = append(findings, deliveryevidence.ReviewFinding{
			ID: "command-bounded-repair", Axis: deliveryevidence.ReviewStandards,
			Severity:  deliveryevidence.SeverityP2,
			Authority: deliveryevidence.AuthorityDocumentedStandard,
			Citation:  "AGENTS.md", Location: "cmd/packy-deliver/advance_command_test.go",
			Evidence: "the production-shaped command fixture requires one bounded repair",
		})
	}
	review := issuedelivery.CandidateReview{
		CandidateID: request.CandidateID, Axis: request.Axis,
		Iteration: request.Iteration, CommitSHA: request.CommitSHA, TreeSHA: request.TreeSHA,
		Findings: findings, Completed: true,
	}
	if request.Axis == deliveryevidence.ReviewSpec {
		review.Acceptance = productionPathAcceptance(request)
	}
	return review, nil
}

func (commandWaitingNonLocalGateway) ObserveNonLocal(
	context.Context,
	issuedelivery.NonLocalObserveRequest,
) (issuedelivery.NonLocalObservation, error) {
	return issuedelivery.NonLocalObservation{}, errors.New("external observation is pending")
}

func (commandWaitingNonLocalGateway) PushIssueBranch(
	context.Context,
	issuedelivery.PushIssueBranchRequest,
) error {
	return nil
}

func (commandWaitingNonLocalGateway) EnsurePullRequest(
	context.Context,
	issuedelivery.EnsurePullRequestRequest,
) error {
	return nil
}

func (commandWaitingNonLocalGateway) RetryInfrastructureCheck(
	context.Context,
	issuedelivery.RetryInfrastructureCheckRequest,
) error {
	return nil
}

func (commandWaitingNonLocalGateway) EnsureMerge(
	context.Context,
	issuedelivery.EnsureMergeRequest,
) error {
	return nil
}

func (commandWaitingNonLocalGateway) EnsureRemoteIssueBranchAbsent(
	context.Context,
	issuedelivery.DeleteRemoteIssueBranchRequest,
) error {
	return nil
}

func (c *commandClock) Now() time.Time {
	c.now = c.now.Add(time.Second)
	return c.now
}

func newCommandQualificationModule(
	t *testing.T,
	repository, common string,
	tracker issuedelivery.TrackerObservation,
) *issuedelivery.Module {
	t.Helper()
	module, err := issuedelivery.New(issuedelivery.Config{
		Git: commandGitObserver{observation: issuedelivery.GitObservation{
			CommonDir: common, Worktree: repository,
			OriginURL: "git@github.com:yersonargotev/packy.git",
			Owner:     "yersonargotev", Name: "packy",
			StartingBaseSHA: strings.Repeat("a", 40), HeadSHA: strings.Repeat("b", 40),
			TreeSHA: strings.Repeat("c", 40), WorkspaceClean: true,
			Branch: "chore/issue-361-advance-cutover",
		}},
		GitHub:          commandTrackerObserver{observation: tracker},
		Clock:           &commandClock{now: time.Date(2026, 7, 30, 6, 0, 0, 0, time.UTC)},
		DeclaredProfile: deliveryevidence.RiskLow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return module
}

func (f *fakeIssueDeliveryAdvancer) Advance(_ context.Context, request issuedelivery.Request) (issuedelivery.Outcome, error) {
	f.requests = append(f.requests, request)
	outcome := f.outcomes[0]
	f.outcomes = f.outcomes[1:]
	return outcome, nil
}

func TestAdvanceCommandFullReportIncludesCandidateDevelopmentTiming(t *testing.T) {
	repository := t.TempDir()
	fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{{
		RunID: "run-1", State: issuedelivery.StateWaiting,
		Reason:     "qualification is approved; awaiting candidate development",
		PauseCause: issuedelivery.PauseExternalResult,
		NextAction: issuedelivery.ActionObserveExternalResult,
		Timing: []issuedelivery.Timing{
			{
				Sequence: 1, Phase: "qualification", To: issuedelivery.StateNeedsReview,
				StartedAt:   "2026-07-30T06:00:00.000000000Z",
				CompletedAt: "2026-07-30T06:00:01.000000000Z",
			},
			{
				Sequence: 2, Phase: "candidate-development",
				From: issuedelivery.StateNeedsReview, To: issuedelivery.StateWaiting,
				StartedAt:   "2026-07-30T06:00:01.000000000Z",
				CompletedAt: "2026-07-30T06:00:03.000000000Z",
			},
		},
	}}}
	cmd := command{
		Now: func() time.Time { return time.Date(2026, 7, 30, 6, 0, 4, 0, time.UTC) },
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
			return fake, nil
		},
	}
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361",
		"--risk-profile", "low-risk", "--full-report",
	}, &stdout); err != nil {
		t.Fatal(err)
	}
	var report advanceReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	for _, category := range report.TimingReport.Categories {
		if category.Category == issuedelivery.TimingImplementation {
			if category.DurationNanoseconds != int64(2*time.Second) {
				t.Fatalf("candidate development duration = %d", category.DurationNanoseconds)
			}
			return
		}
	}
	t.Fatal("full report omitted candidate development timing")
}

func TestAdvanceCommandCallsDeepModuleAndSynthesizesOnlyExactRemoteAuthorization(t *testing.T) {
	repository := t.TempDir()
	resolvedRepository, err := filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &issuedelivery.Candidate{
		ID: "candidate-1", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
	}
	readiness := &issuedelivery.LocalReadiness{
		CandidateID: candidate.ID, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		AuthorityHash: strings.Repeat("c", 64), Branch: "chore/issue-361-cutover",
		ReadyAt: "2026-07-30T06:00:00.000000000Z",
	}
	fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{
		{
			RunID: "run-1", State: issuedelivery.StateWaiting, Reason: "local ready",
			Candidate: candidate, LocalReadiness: readiness,
			PauseCause: issuedelivery.PauseNonLocalAuthorization,
			NextAction: issuedelivery.ActionAuthorizeNonLocal,
		},
		{
			RunID: "run-1", State: issuedelivery.StateWaiting,
			Reason: "exact non-local delivery authority is recorded",
		},
	}}
	var configured advanceOptions
	cmd := command{AdvanceFactory: func(options advanceOptions) (issueDeliveryAdvancer, error) {
		configured = options
		return fake, nil
	}}
	var stdout bytes.Buffer
	err = cmd.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361",
		"--spec", "354",
		"--risk-profile", "low-risk", "--authorize-non-local",
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if configured.RepositoryPath != resolvedRepository || configured.IssueNumber != 361 ||
		configured.SpecificationNumber != 354 ||
		configured.DeclaredProfile != deliveryevidence.RiskLow || !configured.AuthorizeRemote {
		t.Fatalf("configured options = %#v", configured)
	}
	if len(fake.requests) != 2 || fake.requests[0].NonLocal != nil {
		t.Fatalf("requests = %#v", fake.requests)
	}
	wantAuthorization := &issuedelivery.NonLocalAuthorization{
		RunID: "run-1", CandidateID: candidate.ID, CommitSHA: candidate.CommitSHA,
		TreeSHA: candidate.TreeSHA, Branch: readiness.Branch, LocalReadyAt: readiness.ReadyAt,
	}
	if got := fake.requests[1].NonLocal; got == nil || *got != *wantAuthorization {
		t.Fatalf("non-local authorization = %#v, want %#v", got, wantAuthorization)
	}
	var report advanceReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.RunID != "run-1" || report.State != issuedelivery.StateWaiting ||
		report.Reason != "exact non-local delivery authority is recorded" {
		t.Fatalf("report = %#v", report)
	}
}

func TestAdvanceCommandReportsEveryPauseCategory(t *testing.T) {
	tests := []struct {
		name    string
		outcome issuedelivery.Outcome
		cause   issuedelivery.PauseCause
		action  issuedelivery.NextAction
	}{
		{
			name: "semantic input", outcome: issuedelivery.Outcome{
				State:      issuedelivery.StateNeedsDecision,
				PauseCause: issuedelivery.PauseSemanticInput, NextAction: issuedelivery.ActionProvideDecision,
			},
			cause: issuedelivery.PauseSemanticInput, action: issuedelivery.ActionProvideDecision,
		},
		{
			name: "independent review", outcome: issuedelivery.Outcome{
				State:      issuedelivery.StateNeedsReview,
				PauseCause: issuedelivery.PauseIndependentReview, NextAction: issuedelivery.ActionProvideQualificationReview,
			},
			cause: issuedelivery.PauseIndependentReview, action: issuedelivery.ActionProvideQualificationReview,
		},
		{
			name: "external result", outcome: issuedelivery.Outcome{
				State:      issuedelivery.StateWaiting,
				PauseCause: issuedelivery.PauseExternalResult, NextAction: issuedelivery.ActionObserveExternalResult,
			},
			cause: issuedelivery.PauseExternalResult, action: issuedelivery.ActionObserveExternalResult,
		},
		{
			name: "non-local authorization", outcome: issuedelivery.Outcome{
				State:      issuedelivery.StateWaiting,
				PauseCause: issuedelivery.PauseNonLocalAuthorization, NextAction: issuedelivery.ActionAuthorizeNonLocal,
			},
			cause: issuedelivery.PauseNonLocalAuthorization, action: issuedelivery.ActionAuthorizeNonLocal,
		},
		{
			name: "invariant block", outcome: issuedelivery.Outcome{
				State:      issuedelivery.StateBlocked,
				PauseCause: issuedelivery.PauseInvariantBlock, NextAction: issuedelivery.ActionResolveAuthorityBlock,
			},
			cause: issuedelivery.PauseInvariantBlock, action: issuedelivery.ActionResolveAuthorityBlock,
		},
		{
			name: "completed", outcome: issuedelivery.Outcome{
				State:      issuedelivery.StateCompleted,
				PauseCause: issuedelivery.PauseCompleted, NextAction: issuedelivery.ActionNone,
			},
			cause: issuedelivery.PauseCompleted, action: issuedelivery.ActionNone,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := t.TempDir()
			fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{test.outcome}}
			cmd := command{AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
				return fake, nil
			}}
			var stdout bytes.Buffer
			if err := cmd.run(context.Background(), []string{
				"advance", "--repository", repository, "--issue", "4",
			}, &stdout); err != nil {
				t.Fatal(err)
			}
			var report advanceReport
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.PauseCause != test.cause || report.NextAction != test.action {
				t.Fatalf("pause metadata = %q, %q; want %q, %q", report.PauseCause, report.NextAction, test.cause, test.action)
			}
		})
	}
}

func TestAdvanceCommandHighestSeamCreatesV2RunThroughRealModule(t *testing.T) {
	repository := t.TempDir()
	resolvedRepository, err := filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	common := filepath.Join(repository, "common")
	if err = os.Mkdir(common, 0o700); err != nil {
		t.Fatal(err)
	}
	module := newCommandQualificationModule(t, resolvedRepository, common, issuedelivery.TrackerObservation{
		Repository: deliveryevidence.RepositoryIdentity{
			Owner: "yersonargotev", Name: "packy", NodeID: "R1",
		},
		Issue: deliveryevidence.IssueIdentity{Number: 361, NodeID: "I361"},
		Title: "Cut over issue delivery to Advance", Body: "self-contained authority",
		State: "OPEN", Labels: []string{"status:approved", "type:chore"},
		Criteria: []issuedelivery.AuthorityItem{{
			Text: "The private CLI invokes Advance.", EvidenceLink: "issue#361:criterion-1",
		}},
		Exclusions: []issuedelivery.AuthorityItem{{
			Text: "No public Packy command.", EvidenceLink: "issue#361:out-of-scope",
		}},
		Dependencies: []issuedelivery.DependencyObservation{},
		References:   []issuedelivery.ReferenceObservation{},
		Ambiguities:  []issuedelivery.AuthorityItem{},
	})
	cmd := command{
		Now: func() time.Time { return time.Date(2026, 7, 30, 6, 1, 0, 0, time.UTC) },
		AdvanceFactory: func(options advanceOptions) (issueDeliveryAdvancer, error) {
			return module, nil
		},
	}
	var stdout bytes.Buffer
	if err = cmd.run(context.Background(), []string{
		"advance", "--repository", resolvedRepository, "--issue", "361",
		"--risk-profile", "low-risk", "--full-report",
	}, &stdout); err != nil {
		t.Fatal(err)
	}
	var report advanceReport
	if err = json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.State != issuedelivery.StateNeedsDecision || report.RunID == "" ||
		report.PauseCause != issuedelivery.PauseSemanticInput ||
		report.NextAction != issuedelivery.ActionProvideQualificationCorrection ||
		report.QualificationCorrection == nil ||
		report.Evidence == nil || report.Evidence.Schema != deliveryevidence.SchemaV2 ||
		report.Evidence.RiskProfile != deliveryevidence.RiskLow ||
		report.TimingReport.LowRisk.PRReadinessObjectiveNanoseconds != int64(25*time.Minute) {
		t.Fatalf("highest-seam Advance report = %#v", report)
	}
}

func TestAdvanceCommandRealModuleReportsQualificationPauseCategories(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*issuedelivery.TrackerObservation)
		cause  issuedelivery.PauseCause
		action issuedelivery.NextAction
	}{
		{
			name: "semantic input",
			mutate: func(tracker *issuedelivery.TrackerObservation) {
				tracker.Ambiguities = []issuedelivery.AuthorityItem{{
					Text: "Does the issue include schema v1?", EvidenceLink: "issue#361:question-1",
				}}
			},
			cause: issuedelivery.PauseSemanticInput, action: issuedelivery.ActionProvideDecision,
		},
		{
			name: "invariant block",
			mutate: func(tracker *issuedelivery.TrackerObservation) {
				tracker.Dependencies = []issuedelivery.DependencyObservation{{
					Identity: "issue-360", Number: 360, Title: "Required dependency",
					State: "OPEN", URL: "https://github.com/yersonargotev/packy/issues/360",
				}}
			},
			cause: issuedelivery.PauseInvariantBlock, action: issuedelivery.ActionResolveAuthorityBlock,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := t.TempDir()
			resolvedRepository, err := filepath.EvalSymlinks(repository)
			if err != nil {
				t.Fatal(err)
			}
			common := filepath.Join(repository, "common")
			if err = os.Mkdir(common, 0o700); err != nil {
				t.Fatal(err)
			}
			tracker := issuedelivery.TrackerObservation{
				Repository: deliveryevidence.RepositoryIdentity{
					Owner: "yersonargotev", Name: "packy", NodeID: "R1",
				},
				Issue: deliveryevidence.IssueIdentity{Number: 361, NodeID: "I361"},
				Title: "Pause metadata", Body: "self-contained authority",
				State: "OPEN", Labels: []string{"status:approved", "type:chore"},
				Criteria: []issuedelivery.AuthorityItem{{
					Text: "Advance reports typed pause metadata.", EvidenceLink: "issue#361:criterion-1",
				}},
				Exclusions:   []issuedelivery.AuthorityItem{},
				Dependencies: []issuedelivery.DependencyObservation{},
				References:   []issuedelivery.ReferenceObservation{},
				Ambiguities:  []issuedelivery.AuthorityItem{},
			}
			test.mutate(&tracker)
			module := newCommandQualificationModule(t, resolvedRepository, common, tracker)
			cmd := command{
				Now: func() time.Time { return time.Date(2026, 7, 30, 6, 1, 0, 0, time.UTC) },
				AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
					return module, nil
				},
			}
			report := runAdvanceCommandReport(t, cmd, resolvedRepository)
			if report.PauseCause != test.cause || report.NextAction != test.action {
				t.Fatalf("real Module pause metadata = %q, %q; want %q, %q", report.PauseCause, report.NextAction, test.cause, test.action)
			}
		})
	}
}

func TestAdvanceCommandRealModuleReportsNonLocalAndExternalPauses(t *testing.T) {
	module, _, repository, _, _ := productionReadyModule(t, commandWaitingNonLocalGateway{}, nil, nil, "")
	cmd := command{
		Now: func() time.Time { return time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC) },
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
			return module, nil
		},
	}
	authorization := runAdvanceCommandReport(t, cmd, repository)
	if authorization.PauseCause != issuedelivery.PauseNonLocalAuthorization ||
		authorization.NextAction != issuedelivery.ActionAuthorizeNonLocal {
		t.Fatalf("non-local authorization pause = %#v", authorization)
	}
	external := runAdvanceCommandReport(t, cmd, repository, "--authorize-non-local")
	if external.PauseCause != issuedelivery.PauseExternalResult ||
		external.NextAction != issuedelivery.ActionObserveExternalResult {
		t.Fatalf("external result pause = %#v", external)
	}
}

func TestAdvanceCommandRealModuleReportsLockContention(t *testing.T) {
	repository := t.TempDir()
	resolvedRepository, err := filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	common := filepath.Join(repository, "common")
	if err = os.Mkdir(common, 0o700); err != nil {
		t.Fatal(err)
	}
	tracker := &commandBlockingTrackerObserver{
		observation: issuedelivery.TrackerObservation{
			Repository: deliveryevidence.RepositoryIdentity{
				Owner: "yersonargotev", Name: "packy", NodeID: "R1",
			},
			Issue: deliveryevidence.IssueIdentity{Number: 361, NodeID: "I361"},
			Title: "Lock contention", Body: "self-contained authority",
			State: "OPEN", Labels: []string{"status:approved", "type:chore"},
			Criteria: []issuedelivery.AuthorityItem{{
				Text: "Advance retries lock contention.", EvidenceLink: "issue#361:criterion-1",
			}},
			Exclusions: []issuedelivery.AuthorityItem{}, Dependencies: []issuedelivery.DependencyObservation{},
			References: []issuedelivery.ReferenceObservation{}, Ambiguities: []issuedelivery.AuthorityItem{},
		},
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	module, err := issuedelivery.New(issuedelivery.Config{
		Git: commandGitObserver{observation: issuedelivery.GitObservation{
			CommonDir: common, Worktree: resolvedRepository,
			OriginURL: "git@github.com:yersonargotev/packy.git",
			Owner:     "yersonargotev", Name: "packy",
			StartingBaseSHA: strings.Repeat("a", 40), HeadSHA: strings.Repeat("b", 40),
			TreeSHA: strings.Repeat("c", 40), WorkspaceClean: true,
			Branch: "chore/issue-361-lock-contention",
		}},
		GitHub: tracker, Clock: &commandClock{now: time.Date(2026, 7, 30, 6, 0, 0, 0, time.UTC)},
		DeclaredProfile: deliveryevidence.RiskLow,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, advanceErr := module.Advance(context.Background(), issuedelivery.Request{
			RepositoryPath: resolvedRepository, IssueNumber: 361,
		})
		firstDone <- advanceErr
	}()
	<-tracker.entered
	cmd := command{
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) { return module, nil },
	}
	var stdout bytes.Buffer
	if err = cmd.run(context.Background(), []string{
		"advance", "--repository", resolvedRepository, "--issue", "361", "--risk-profile", "low-risk",
	}, &stdout); err != nil {
		t.Fatal(err)
	}
	close(tracker.release)
	if err = <-firstDone; err != nil {
		t.Fatal(err)
	}
	var report advanceReport
	if err = json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.PauseCause != issuedelivery.PauseLockContention ||
		report.NextAction != issuedelivery.ActionRetryAdvance {
		t.Fatalf("lock contention report = %#v", report)
	}
}

func commandAcceptanceDigest(t *testing.T, rows []deliveryevidence.AcceptanceRow) string {
	t.Helper()
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func runAdvanceCommandReport(
	t *testing.T,
	cmd command,
	repository string,
	extra ...string,
) advanceReport {
	t.Helper()
	args := []string{
		"advance", "--repository", repository, "--issue", "361",
		"--risk-profile", "low-risk", "--full-report",
	}
	args = append(args, extra...)
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), args, &stdout); err != nil {
		t.Fatal(err)
	}
	var report advanceReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestAdvanceCommandRealModuleConvergesPastDeterministicAdvance(t *testing.T) {
	module, corrected, repository, _, _ := productionReadyModule(
		t, nil, nil, nil, "before-qualification-approval",
	)
	content := advanceReviewContent{QualificationReview: &issuedelivery.QualificationReview{
		AuthoritySHA256:        corrected.Observations.AuthoritySHA256,
		AcceptanceMatrixSHA256: commandAcceptanceDigest(t, corrected.Evidence.AcceptanceMatrix),
		Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
	}}
	path := filepath.Join(t.TempDir(), "review.json")
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := command{
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) { return module, nil },
	}
	report := runAdvanceCommandReport(t, cmd, repository, "--review-content", path)
	if report.PauseCause != issuedelivery.PauseIndependentReview ||
		report.NextAction != issuedelivery.ActionProvideCandidateReview ||
		report.Candidate == nil {
		t.Fatalf("converged advance report = %#v", report)
	}
}

func TestAdvanceCommandRealModuleReportsCandidateRepair(t *testing.T) {
	module, found, repository, _, _ := productionReadyModule(
		t, nil, nil, commandFindingReviewExecutor{}, "repair-decision",
	)
	if found.Repair == nil {
		t.Fatalf("production fixture did not request repair: %#v", found)
	}
	repair := issuedelivery.RepairDecision{
		CandidateID: found.Repair.CandidateID, Class: issuedelivery.RepairBounded,
		Findings: []issuedelivery.FindingDecision{{
			FindingID: "command-bounded-repair", Disposition: issuedelivery.FindingAccepted,
			Evidence: "repair the accepted command finding as one bounded batch",
		}},
	}
	path := filepath.Join(t.TempDir(), "repair.json")
	raw, err := json.Marshal(repair)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := command{
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) { return module, nil },
	}
	report := runAdvanceCommandReport(t, cmd, repository, "--repair", path)
	if report.PauseCause != issuedelivery.PauseCandidateRepair ||
		report.NextAction != issuedelivery.ActionRepairCandidate {
		t.Fatalf("candidate repair report = %#v", report)
	}
}

func TestAdvanceCommandFullReportProjectsCanonicalAssuranceOnce(t *testing.T) {
	module, found, repository, _, _ := productionReadyModule(
		t, nil, nil, commandFindingReviewExecutor{}, "repair-decision",
	)
	if found.Repair == nil {
		t.Fatalf("production fixture did not request adjudication: %#v", found)
	}
	repair := issuedelivery.RepairDecision{
		CandidateID: found.Repair.CandidateID, Class: issuedelivery.RepairAdjudicationOnly,
		Findings: []issuedelivery.FindingDecision{{
			FindingID: "command-bounded-repair", Disposition: issuedelivery.FindingRejected,
			Evidence: "the cited command fixture is test-only and requires no production repair",
		}},
	}
	path := filepath.Join(t.TempDir(), "adjudication.json")
	raw, err := json.Marshal(repair)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := command{
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) { return module, nil },
	}
	report := runAdvanceCommandReport(t, cmd, repository, "--repair", path)
	if report.State != issuedelivery.StateWaiting || report.LocalReadiness == nil ||
		report.Evidence == nil || report.Candidate == nil {
		t.Fatalf("full command report did not reach exact local readiness: %#v", report)
	}
	if len(report.Evidence.CandidateReviewReceipts) != 1 ||
		len(report.Evidence.AssuranceAdjudications) != 1 ||
		len(report.Evidence.ExhaustiveAssurance) != 1 ||
		len(report.Evidence.AssurancePhases) != len(report.Timing) {
		t.Fatalf("canonical assurance projection is incomplete: %#v", report.Evidence)
	}
	reviewID := report.Evidence.CandidateReviewReceipts[0].Identity
	validationID := report.Evidence.ExhaustiveAssurance[0].Identity
	for _, proof := range report.Candidate.Acceptance {
		if proof.ReviewReceipt == nil || proof.ReviewReceipt.ReceiptID != reviewID ||
			proof.ValidationReceipt == nil || proof.ValidationReceipt.ReceiptID != validationID {
			t.Fatalf("acceptance proof does not bind canonical receipts: %#v", proof)
		}
	}

	resumed := runAdvanceCommandReport(t, cmd, repository)
	if resumed.State != issuedelivery.StateWaiting ||
		len(resumed.Evidence.CandidateReviewReceipts) != 1 ||
		len(resumed.Evidence.AssuranceAdjudications) != 1 ||
		len(resumed.Evidence.ExhaustiveAssurance) != 1 ||
		resumed.Evidence.CandidateReviewReceipts[0].Identity != reviewID ||
		resumed.Evidence.ExhaustiveAssurance[0].Identity != validationID ||
		len(resumed.Evidence.AssurancePhases) != len(report.Evidence.AssurancePhases) {
		t.Fatalf("resumed command duplicated canonical assurance: %#v", resumed)
	}
}

type commandLegacyCandidate struct {
	ID              string                          `json:"id"`
	BaseSHA         string                          `json:"base_sha"`
	CommitSHA       string                          `json:"commit_sha"`
	TreeSHA         string                          `json:"tree_sha"`
	RepairClass     issuedelivery.RepairClass       `json:"repair_class,omitempty"`
	RequiredReviews []deliveryevidence.ReviewAxis   `json:"required_reviews"`
	Reviews         []issuedelivery.CandidateReview `json:"reviews"`
	Acceptance      []issuedelivery.AcceptanceProof `json:"acceptance,omitempty"`
	Focused         *issuedelivery.ValidationProof  `json:"focused,omitempty"`
	Exhaustive      *issuedelivery.ValidationProof  `json:"exhaustive,omitempty"`
	RepairDecision  *issuedelivery.RepairDecision   `json:"repair_decision,omitempty"`
}

type commandLegacyRun struct {
	Schema          string                               `json:"schema"`
	ID              string                               `json:"id"`
	Repository      deliveryevidence.RepositoryIdentity  `json:"repository"`
	Issue           deliveryevidence.IssueIdentity       `json:"issue"`
	AuthoritySHA256 string                               `json:"authority_sha256"`
	State           issuedelivery.State                  `json:"state"`
	Reason          string                               `json:"reason"`
	SupersedesRunID string                               `json:"supersedes_run_id,omitempty"`
	Evidence        json.RawMessage                      `json:"evidence,omitempty"`
	PendingDecision *issuedelivery.DecisionRequest       `json:"pending_decision,omitempty"`
	Decisions       []issuedelivery.Decision             `json:"decisions"`
	Observations    issuedelivery.Observations           `json:"observations"`
	Candidates      []commandLegacyCandidate             `json:"candidates,omitempty"`
	PendingRepair   *issuedelivery.RepairDecisionRequest `json:"pending_repair,omitempty"`
	LocalReadiness  *issuedelivery.LocalReadiness        `json:"local_readiness,omitempty"`
	Timing          []issuedelivery.Timing               `json:"timing"`
	CreatedAt       string                               `json:"created_at"`
	UpdatedAt       string                               `json:"updated_at"`
}

func convertActiveRunToLegacy(t *testing.T, repository string, issue int) {
	t.Helper()
	directory := filepath.Join(
		repository, ".git", "packy", "issue-delivery", fmt.Sprintf("issue-%d", issue),
	)
	activeRaw, err := os.ReadFile(filepath.Join(directory, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	var active struct {
		RunID    string `json:"run_id"`
		Revision string `json:"revision,omitempty"`
	}
	if err = json.Unmarshal(activeRaw, &active); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runs", active.RunID+".json")
	if active.Revision != "" {
		path = filepath.Join(directory, "revisions", active.RunID, active.Revision+".json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		ID              string
		Repository      deliveryevidence.RepositoryIdentity
		Issue           deliveryevidence.IssueIdentity
		AuthoritySHA256 string `json:"authority_sha256"`
		State           issuedelivery.State
		Reason          string
		SupersedesRunID string `json:"supersedes_run_id"`
		Evidence        json.RawMessage
		PendingDecision *issuedelivery.DecisionRequest `json:"pending_decision"`
		Decisions       []issuedelivery.Decision
		Observations    issuedelivery.Observations
		Candidates      []issuedelivery.Candidate
		PendingRepair   *issuedelivery.RepairDecisionRequest `json:"pending_repair"`
		LocalReadiness  *issuedelivery.LocalReadiness        `json:"local_readiness"`
		Timing          []issuedelivery.Timing
		CreatedAt       string `json:"created_at"`
		UpdatedAt       string `json:"updated_at"`
	}
	if err = json.Unmarshal(raw, &source); err != nil {
		t.Fatal(err)
	}
	candidates := make([]commandLegacyCandidate, 0, len(source.Candidates))
	for _, candidate := range source.Candidates {
		candidates = append(candidates, commandLegacyCandidate{
			ID: candidate.ID, BaseSHA: candidate.BaseSHA, CommitSHA: candidate.CommitSHA,
			TreeSHA: candidate.TreeSHA, RepairClass: candidate.RepairClass,
			RequiredReviews: candidate.RequiredReviews, Reviews: candidate.Reviews,
			Acceptance: candidate.Acceptance, Focused: candidate.Focused,
			Exhaustive: candidate.Exhaustive, RepairDecision: candidate.RepairDecision,
		})
	}
	legacy := commandLegacyRun{
		Schema: "packy.issue-delivery-run/v1", ID: source.ID,
		Repository: source.Repository, Issue: source.Issue,
		AuthoritySHA256: source.AuthoritySHA256, State: source.State, Reason: source.Reason,
		SupersedesRunID: source.SupersedesRunID, Evidence: source.Evidence,
		PendingDecision: source.PendingDecision, Decisions: source.Decisions,
		Observations: source.Observations, Candidates: candidates,
		PendingRepair: source.PendingRepair, LocalReadiness: source.LocalReadiness,
		Timing: source.Timing, CreatedAt: source.CreatedAt, UpdatedAt: source.UpdatedAt,
	}
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if active.Revision != "" {
		active.Revision = fmt.Sprintf("%x", sha256.Sum256(legacyRaw))
		path = filepath.Join(directory, "revisions", active.RunID, active.Revision+".json")
		updatedActive, marshalErr := json.Marshal(active)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if err = os.WriteFile(filepath.Join(directory, "active.json"), updatedActive, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(path, legacyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAdvanceCommandRealModuleReportsLegacyWorkflow(t *testing.T) {
	module, _, repository, _, _ := productionReadyModule(t, nil, nil, nil, "")
	convertActiveRunToLegacy(t, repository, 361)
	cmd := command{
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) { return module, nil },
	}
	report := runAdvanceCommandReport(t, cmd, repository)
	if report.PauseCause != issuedelivery.PauseLegacyWorkflow ||
		report.NextAction != issuedelivery.ActionResumeLegacyV1 ||
		report.Evidence == nil || report.Evidence.Schema != deliveryevidence.SchemaV2 {
		t.Fatalf("legacy workflow report = %#v", report)
	}
}

func TestAdvanceCommandAdmitsOnlyTypedSemanticContent(t *testing.T) {
	root := t.TempDir()
	repository := t.TempDir()
	write := func(name string, value any) string {
		t.Helper()
		path := filepath.Join(root, name+".json")
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	decision := issuedelivery.Decision{
		RequestID: "decision-1", Disposition: issuedelivery.DecisionOwnedNow,
		Requirement: "clarified behavior", EvidenceLink: "issue#361",
	}
	reviews := advanceReviewContent{Reviews: []issuedelivery.CandidateReview{{
		CandidateID: "candidate-1", Axis: deliveryevidence.ReviewStandards, Completed: true,
	}}, Acceptance: []issuedelivery.AcceptanceProof{{
		Identity: "criterion-1", PositiveEvidence: "candidate-1: reviewed positive proof",
	}}, QualificationReview: &issuedelivery.QualificationReview{
		AuthoritySHA256:        strings.Repeat("b", 64),
		AcceptanceMatrixSHA256: strings.Repeat("c", 64),
		Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
	}, QualificationCorrection: &issuedelivery.QualificationCorrection{
		AuthoritySHA256:      strings.Repeat("b", 64),
		ReviewedMatrixSHA256: strings.Repeat("c", 64),
		FindingIDs:           []string{"qualification-1"},
		AcceptanceMatrix: []deliveryevidence.AcceptanceRow{{
			Identity: "criterion-1", Criterion: "observable behavior",
			OwningSeam: "product seam", PositiveEvidence: "positive",
			NegativeEvidence: "negative", FailureEvidence: "failure",
			MutationEvidence: "mutation", CompatibilityEvidence: "compatibility",
			PreservationEvidence: "preservation", MigrationEvidence: "migration",
			State: deliveryevidence.AcceptancePlanned,
		}},
		Evidence: "corrected exact owning seam and planned evidence",
	}}
	ciAttributions := []advanceCIFailureAttribution{{
		CheckIdentity: "Validate Packy-owned code", RunID: 42,
		HeadSHA:     strings.Repeat("a", 40),
		DetailsURL:  "https://github.com/yersonargotev/packy/actions/runs/42",
		Attribution: issuedelivery.FailureInfrastructure,
	}}
	fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{{
		RunID: "run-1", State: issuedelivery.StateNeedsReview, Reason: "candidate review required",
	}}}
	var configured advanceOptions
	cmd := command{AdvanceFactory: func(options advanceOptions) (issueDeliveryAdvancer, error) {
		configured = options
		return fake, nil
	}}
	err := cmd.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361",
		"--decision", write("decision", decision),
		"--review-content", write("reviews", reviews),
		"--ci-attribution", write("ci-attribution", ciAttributions),
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if configured.Decision == nil || *configured.Decision != decision ||
		len(configured.Reviews) != 1 || configured.Reviews[0].Axis != deliveryevidence.ReviewStandards ||
		len(configured.Acceptance) != 1 || configured.Acceptance[0].Identity != "criterion-1" ||
		configured.QualificationReview == nil || !configured.QualificationReview.Completed ||
		configured.QualificationCorrection == nil ||
		configured.QualificationCorrection.FindingIDs[0] != "qualification-1" ||
		len(configured.CIFailureAttributions) != 1 ||
		configured.CIFailureAttributions[0].Attribution != issuedelivery.FailureInfrastructure {
		t.Fatalf("configured semantic content = %#v", configured)
	}
	if len(fake.requests) != 1 || fake.requests[0].Decision == nil ||
		*fake.requests[0].Decision != decision ||
		fake.requests[0].QualificationReview == nil ||
		fake.requests[0].QualificationCorrection == nil {
		t.Fatalf("Advance requests = %#v", fake.requests)
	}

	unknown := filepath.Join(root, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"request_id":"x","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = cmd.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361", "--decision", unknown,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown semantic field accepted: %v", err)
	}

	multiple := filepath.Join(root, "multiple.json")
	if err := os.WriteFile(multiple, []byte(`{"request_id":"x"} {"request_id":"y"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = cmd.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361", "--decision", multiple,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "exactly one JSON value") {
		t.Fatalf("multiple semantic JSON values accepted: %v", err)
	}
}

func TestAdvanceCommandMergesRepeatedReviewContentDeterministically(t *testing.T) {
	root := t.TempDir()
	repository := t.TempDir()
	write := func(name string, content advanceReviewContent) string {
		t.Helper()
		path := filepath.Join(root, name+".json")
		raw, err := json.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	standards := issuedelivery.CandidateReview{
		CandidateID: "candidate-1", Axis: deliveryevidence.ReviewStandards, Completed: true,
	}
	spec := issuedelivery.CandidateReview{
		CandidateID: "candidate-1", Axis: deliveryevidence.ReviewSpec, Completed: true,
	}
	qualification := issuedelivery.QualificationReview{
		AuthoritySHA256: strings.Repeat("a", 64), AcceptanceMatrixSHA256: strings.Repeat("b", 64),
		Findings: []deliveryevidence.ReviewFinding{}, Completed: true,
	}
	first := write("first", advanceReviewContent{
		Reviews: []issuedelivery.CandidateReview{standards}, QualificationReview: &qualification,
	})
	second := write("second", advanceReviewContent{
		Reviews: []issuedelivery.CandidateReview{spec}, QualificationReview: &qualification,
	})
	fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{{
		RunID: "run-1", State: issuedelivery.StateNeedsReview, Reason: "reviews remain pending",
	}}}
	var configured advanceOptions
	cmd := command{AdvanceFactory: func(options advanceOptions) (issueDeliveryAdvancer, error) {
		configured = options
		return fake, nil
	}}
	err := cmd.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361",
		"--review-content", first, "--review-content", second, "--review-content", first,
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(configured.Reviews) != 2 ||
		configured.Reviews[0].Axis != deliveryevidence.ReviewStandards ||
		configured.Reviews[1].Axis != deliveryevidence.ReviewSpec ||
		configured.QualificationReview == nil ||
		!reflect.DeepEqual(*configured.QualificationReview, qualification) {
		t.Fatalf("merged review content = %#v", configured)
	}

	conflict := standards
	conflict.Completed = false
	conflictingPath := write("conflict", advanceReviewContent{
		Reviews: []issuedelivery.CandidateReview{conflict},
	})
	factoryCalled := false
	cmd.AdvanceFactory = func(advanceOptions) (issueDeliveryAdvancer, error) {
		factoryCalled = true
		return fake, nil
	}
	err = cmd.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361",
		"--review-content", first, "--review-content", conflictingPath,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "conflicting candidate review") {
		t.Fatalf("conflicting repeated review content accepted: %v", err)
	}
	if factoryCalled {
		t.Fatal("conflicting review content reached the Advance factory")
	}
}

func TestConvergentAdvanceConsumesPacketResponsesOnce(t *testing.T) {
	fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{
		{
			RunID: "run-1", State: issuedelivery.StateNeedsReview,
			Reason:     "packet responses persisted",
			PauseCause: issuedelivery.PauseDeterministicAdvance,
			NextAction: issuedelivery.ActionAdvance,
		},
		{
			RunID: "run-1", State: issuedelivery.StateWaiting,
			Reason:     "remaining review response is pending",
			PauseCause: issuedelivery.PauseIndependentReview,
			NextAction: issuedelivery.ActionProvideCandidateReview,
		},
	}}
	request := issuedelivery.Request{
		RepositoryPath: "/repo", IssueNumber: 30,
		CandidateReviews: []issuedelivery.CandidateReview{{
			PacketID: strings.Repeat("a", 64), CandidateID: "candidate-1",
			Axis: deliveryevidence.ReviewStandards,
		}},
	}
	if _, err := convergeAdvance(context.Background(), fake, request, false); err != nil {
		t.Fatal(err)
	}
	if len(fake.requests) != 2 || len(fake.requests[0].CandidateReviews) != 1 ||
		len(fake.requests[1].CandidateReviews) != 0 {
		t.Fatalf("convergent packet requests = %#v", fake.requests)
	}
}

func TestAdvanceCommandRejectsCallerPhaseSequencingInputs(t *testing.T) {
	repository := t.TempDir()
	cmd := command{AdvanceFactory: func(options advanceOptions) (issueDeliveryAdvancer, error) {
		return &fakeIssueDeliveryAdvancer{}, nil
	}}
	for _, args := range [][]string{
		{"advance", "--repository", repository, "--issue", "361", "qualification"},
		{"advance", "--repository", repository, "--issue", "361", "--risk-profile", "routine"},
		{"advance", "--repository", repository, "--issue", "361", "--spec", "361"},
		{"advance", "--repository", repository, "--issue", "361", "--sandbox-root", t.TempDir()},
		{"advance", "--repository", repository},
	} {
		if err := cmd.run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid caller sequencing accepted: %v", args)
		}
	}
}

func TestProductionCommandExposesHistoricalSequencingOnlyBehindLegacyV1(t *testing.T) {
	cmd := command{LegacyPrefixRequired: true}
	err := cmd.run(context.Background(), []string{"initialize"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "only through legacy-v1") {
		t.Fatalf("direct legacy command accepted: %v", err)
	}
	err = cmd.run(context.Background(), []string{"legacy-v1", "initialize"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "qualified-bundle") {
		t.Fatalf("explicit legacy-v1 path did not dispatch historical command: %v", err)
	}
	qualificationPath := filepath.Join(t.TempDir(), "v2.json")
	if err = os.WriteFile(
		qualificationPath,
		[]byte(`{"schema":"packy.delivery-evidence/v2","issue_number":361}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	err = cmd.run(context.Background(), []string{
		"legacy-v1", "initialize", "--qualified-bundle", qualificationPath,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "only schema v1") {
		t.Fatalf("legacy-v1 accepted caller-assembled v2 evidence: %v", err)
	}
}

func TestProductionCommandReportsBuildVersion(t *testing.T) {
	original := version
	version = "1.2.3"
	t.Cleanup(func() { version = original })

	var output bytes.Buffer
	if err := (command{}).run(context.Background(), []string{"version"}, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "1.2.3\n" {
		t.Fatalf("version output = %q", output.String())
	}
	if err := (command{}).run(context.Background(), []string{"version", "extra"}, &bytes.Buffer{}); err == nil {
		t.Fatal("version accepted an argument")
	}
}
