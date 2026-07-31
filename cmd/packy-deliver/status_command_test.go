package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type fakeIssueDeliveryStatuser struct {
	outcome  issuedelivery.Outcome
	err      error
	requests []issuedelivery.StatusRequest
}

type statusCountingGitObserver struct {
	observation issuedelivery.GitObservation
	calls       int
}

func (o *statusCountingGitObserver) ObserveGit(
	context.Context,
	string,
) (issuedelivery.GitObservation, error) {
	o.calls++
	return o.observation, nil
}

type statusCountingTrackerObserver struct {
	observation issuedelivery.TrackerObservation
	calls       int
}

func (o *statusCountingTrackerObserver) ObserveIssue(
	context.Context,
	issuedelivery.GitObservation,
	int,
) (issuedelivery.TrackerObservation, error) {
	o.calls++
	return o.observation, nil
}

type statusEffectCounters struct {
	review, validation, risk, specialist, boundary int
	nonLocalRead, nonLocalWrite                    int
	localRead, localWrite                          int
}

func (c *statusEffectCounters) Review(
	context.Context,
	issuedelivery.ReviewRequest,
) (issuedelivery.CandidateReview, error) {
	c.review++
	return issuedelivery.CandidateReview{}, nil
}

func (c *statusEffectCounters) Focused(
	context.Context,
	issuedelivery.ValidationRequest,
) (issuedelivery.ValidationResult, error) {
	c.validation++
	return issuedelivery.ValidationResult{}, nil
}

func (c *statusEffectCounters) Exhaustive(
	context.Context,
	issuedelivery.ValidationRequest,
) (issuedelivery.ValidationResult, error) {
	c.validation++
	return issuedelivery.ValidationResult{}, nil
}

func (c *statusEffectCounters) ObserveCandidateRisk(
	context.Context,
	issuedelivery.CandidateRiskRequest,
) (issuedelivery.CandidateRiskObservation, error) {
	c.risk++
	return issuedelivery.CandidateRiskObservation{}, nil
}

func (c *statusEffectCounters) ReviewSpecialist(
	context.Context,
	issuedelivery.SpecialistReviewRequest,
) (issuedelivery.SpecialistReview, error) {
	c.specialist++
	return issuedelivery.SpecialistReview{}, nil
}

func (c *statusEffectCounters) ValidateBoundary(
	context.Context,
	issuedelivery.BoundaryValidationRequest,
) (issuedelivery.BoundaryValidationResult, error) {
	c.boundary++
	return issuedelivery.BoundaryValidationResult{}, nil
}

func (c *statusEffectCounters) ObserveNonLocal(
	context.Context,
	issuedelivery.NonLocalObserveRequest,
) (issuedelivery.NonLocalObservation, error) {
	c.nonLocalRead++
	return issuedelivery.NonLocalObservation{}, nil
}

func (c *statusEffectCounters) PushIssueBranch(
	context.Context,
	issuedelivery.PushIssueBranchRequest,
) error {
	c.nonLocalWrite++
	return nil
}

func (c *statusEffectCounters) EnsurePullRequest(
	context.Context,
	issuedelivery.EnsurePullRequestRequest,
) error {
	c.nonLocalWrite++
	return nil
}

func (c *statusEffectCounters) RetryInfrastructureCheck(
	context.Context,
	issuedelivery.RetryInfrastructureCheckRequest,
) error {
	c.nonLocalWrite++
	return nil
}

func (c *statusEffectCounters) EnsureMerge(
	context.Context,
	issuedelivery.EnsureMergeRequest,
) error {
	c.nonLocalWrite++
	return nil
}

func (c *statusEffectCounters) EnsureRemoteIssueBranchAbsent(
	context.Context,
	issuedelivery.DeleteRemoteIssueBranchRequest,
) error {
	c.nonLocalWrite++
	return nil
}

func (c *statusEffectCounters) ObserveLocalCompletion(
	context.Context,
	issuedelivery.LocalCompletionObserveRequest,
) (issuedelivery.LocalCompletionObservation, error) {
	c.localRead++
	return issuedelivery.LocalCompletionObservation{}, nil
}

func (c *statusEffectCounters) EnsureManagedWorktreeAbsent(
	context.Context,
	issuedelivery.RemoveManagedWorktreeRequest,
) error {
	c.localWrite++
	return nil
}

func (c *statusEffectCounters) EnsureLocalIssueBranchAbsent(
	context.Context,
	issuedelivery.DeleteLocalIssueBranchRequest,
) error {
	c.localWrite++
	return nil
}

func (c *statusEffectCounters) EnsureLocalMainFastForward(
	context.Context,
	issuedelivery.FastForwardLocalMainRequest,
) error {
	c.localWrite++
	return nil
}

func (f *fakeIssueDeliveryStatuser) Status(
	_ context.Context,
	request issuedelivery.StatusRequest,
) (issuedelivery.Outcome, error) {
	f.requests = append(f.requests, request)
	return f.outcome, f.err
}

func TestStatusCommandObservesExactlyOnceAndMatchesCompactAdvance(t *testing.T) {
	repository := t.TempDir()
	waitStarted := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	now := waitStarted.Add(3 * time.Minute)
	outcome := issuedelivery.Outcome{
		RunID: "run-25", State: issuedelivery.StateWaiting,
		Reason: "awaiting external result", PauseCause: issuedelivery.PauseExternalResult,
		NextAction: issuedelivery.ActionObserveExternalResult,
		Timing: []issuedelivery.Timing{{
			Sequence: 1, Phase: "ci-wait", To: issuedelivery.StateWaiting,
			StartedAt:   waitStarted.Add(-time.Minute).Format(time.RFC3339Nano),
			CompletedAt: waitStarted.Format(time.RFC3339Nano),
		}},
		Candidate: &issuedelivery.Candidate{
			ID: "candidate-25", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
		},
	}
	statuser := &fakeIssueDeliveryStatuser{outcome: outcome}
	advancer := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{outcome}}
	cmd := command{
		Now: func() time.Time { return now },
		StatusFactory: func(statusOptions) (issueDeliveryStatuser, error) {
			return statuser, nil
		},
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
			return advancer, nil
		},
	}
	var statusOutput, advanceOutput bytes.Buffer
	if err := cmd.run(context.Background(), []string{
		"status", "--repository", repository, "--issue", "25",
	}, &statusOutput); err != nil {
		t.Fatal(err)
	}
	if err := cmd.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "25",
	}, &advanceOutput); err != nil {
		t.Fatal(err)
	}
	if statusOutput.String() != advanceOutput.String() {
		t.Fatalf("compact output differs:\nstatus:\n%s\nadvance:\n%s", statusOutput.String(), advanceOutput.String())
	}
	if !strings.Contains(statusOutput.String(), `"open_external_wait_nanoseconds": 180000000000`) {
		t.Fatalf("compact output lacks current open external wait: %s", statusOutput.String())
	}
	if len(statuser.requests) != 1 {
		t.Fatalf("Status calls = %d, want 1", len(statuser.requests))
	}
	resolvedRepository, err := filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	want := issuedelivery.StatusRequest{
		RepositoryPath: filepath.Clean(resolvedRepository),
		IssueNumber:    25,
	}
	if !reflect.DeepEqual(statuser.requests[0], want) {
		t.Fatalf("Status request = %#v, want %#v", statuser.requests[0], want)
	}
}

func TestStatusCommandTextUsesCompactProjectionForEveryRunState(t *testing.T) {
	tests := []issuedelivery.Outcome{
		{RunID: "active", State: issuedelivery.StateNeedsDecision, PauseCause: issuedelivery.PauseSemanticInput, NextAction: issuedelivery.ActionProvideDecision},
		{RunID: "waiting", State: issuedelivery.StateWaiting, PauseCause: issuedelivery.PauseExternalResult, NextAction: issuedelivery.ActionObserveExternalResult},
		{RunID: "completed", State: issuedelivery.StateCompleted, PauseCause: issuedelivery.PauseCompleted, NextAction: issuedelivery.ActionNone},
		{RunID: "blocked", State: issuedelivery.StateBlocked, PauseCause: issuedelivery.PauseInvariantBlock, NextAction: issuedelivery.ActionInspectBlockedTransition},
		{State: issuedelivery.StateWaiting, PauseCause: issuedelivery.PauseLockContention, NextAction: issuedelivery.ActionRetryAdvance},
	}
	for _, outcome := range tests {
		t.Run(string(outcome.State)+"-"+outcome.RunID, func(t *testing.T) {
			fake := &fakeIssueDeliveryStatuser{outcome: outcome}
			cmd := command{StatusFactory: func(statusOptions) (issueDeliveryStatuser, error) {
				return fake, nil
			}}
			var output bytes.Buffer
			if err := cmd.run(context.Background(), []string{
				"status", "--repository", t.TempDir(), "--issue", "25", "--output", "text",
			}, &output); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"state: " + string(outcome.State),
				"pause cause: " + string(outcome.PauseCause),
				"next action: " + string(outcome.NextAction),
			} {
				if !strings.Contains(output.String(), want) {
					t.Errorf("text output missing %q:\n%s", want, output.String())
				}
			}
		})
	}
}

func TestStatusCommandRejectsInvalidInputAndObservationFailure(t *testing.T) {
	repository := t.TempDir()
	fake := &fakeIssueDeliveryStatuser{err: errors.New("corrupt persisted run")}
	cmd := command{StatusFactory: func(statusOptions) (issueDeliveryStatuser, error) {
		return fake, nil
	}}
	for _, args := range [][]string{
		{"status", "--issue", "25"},
		{"status", "--repository", repository},
		{"status", "--repository", "relative/repository", "--issue", "25"},
		{"status", "--repository", repository, "--issue", "25", "--output", "yaml"},
		{"status", "--repository", repository, "--issue", "25", "--decision", "input.json"},
		{"status", "--repository", repository, "--issue", "25", "phase"},
	} {
		if err := cmd.run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid status input accepted: %v", args)
		}
	}
	err := cmd.run(context.Background(), []string{
		"status", "--repository", repository, "--issue", "25",
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "corrupt persisted run") {
		t.Fatalf("observation failure = %v", err)
	}
	if len(fake.requests) != 1 {
		t.Fatalf("failed observation calls = %d, want 1", len(fake.requests))
	}
}

func TestStatusCommandHighestSeamUsesGitCommonDirectoryAndReadOnlyModule(t *testing.T) {
	repository := t.TempDir()
	resolvedRepository, err := filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	common := filepath.Join(repository, "common")
	if err := os.Mkdir(common, 0o700); err != nil {
		t.Fatal(err)
	}
	git := &statusCountingGitObserver{observation: issuedelivery.GitObservation{
		CommonDir: common, Worktree: resolvedRepository,
		OriginURL: "git@github.com:yersonargotev/packy.git",
		Owner:     "yersonargotev", Name: "packy",
		StartingBaseSHA: strings.Repeat("a", 40), HeadSHA: strings.Repeat("b", 40),
		TreeSHA: strings.Repeat("c", 40), WorkspaceClean: true,
		Branch: "feat/issue-25-run-aware-status",
	}}
	tracker := &statusCountingTrackerObserver{observation: issuedelivery.TrackerObservation{
		Repository: deliveryevidence.RepositoryIdentity{
			Owner: "yersonargotev", Name: "packy", NodeID: "R1",
		},
		Issue:  deliveryevidence.IssueIdentity{Number: 25, NodeID: "I25"},
		Title:  "Expose run-aware schema-v2 status",
		Body:   "self-contained authority",
		State:  "OPEN",
		Labels: []string{"status:approved", "type:chore"},
		Criteria: []issuedelivery.AuthorityItem{{
			Text: "Status performs one observation.", EvidenceLink: "issue#25:criterion-1",
		}},
		Exclusions:   []issuedelivery.AuthorityItem{},
		Dependencies: []issuedelivery.DependencyObservation{},
		References:   []issuedelivery.ReferenceObservation{},
		Ambiguities:  []issuedelivery.AuthorityItem{},
	}}
	effects := &statusEffectCounters{}
	sandboxRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"home", "config"} {
		if err := os.Mkdir(filepath.Join(sandboxRoot, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	module, err := issuedelivery.New(issuedelivery.Config{
		Git: git, GitHub: tracker,
		Review: effects, Validation: effects, Risk: effects,
		Specialist: effects, Boundary: effects, NonLocal: effects, LocalCompletion: effects,
		SandboxRoot: sandboxRoot, DeclaredProfile: deliveryevidence.RiskLow,
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := module.Advance(context.Background(), issuedelivery.Request{
		RepositoryPath: resolvedRepository, IssueNumber: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	git.calls, tracker.calls = 0, 0
	*effects = statusEffectCounters{}
	before := statusSnapshotRegularFiles(t, common)
	cmd := command{StatusFactory: func(statusOptions) (issueDeliveryStatuser, error) {
		return module, nil
	}}
	var output bytes.Buffer
	if err := cmd.run(context.Background(), []string{
		"status", "--repository", resolvedRepository, "--issue", "25",
	}, &output); err != nil {
		t.Fatal(err)
	}
	if git.calls != 1 || tracker.calls != 1 {
		t.Fatalf("status observations: Git=%d GitHub=%d, want one each", git.calls, tracker.calls)
	}
	if *effects != (statusEffectCounters{}) {
		t.Fatalf("status invoked forbidden effects: %#v", effects)
	}
	after := statusSnapshotRegularFiles(t, common)
	if !reflect.DeepEqual(after, before) {
		t.Fatal("status wrote the Git-common-directory run store")
	}
	if _, err := os.Stat(filepath.Join(
		common, "packy", "issue-delivery", "issue-25", "active.json",
	)); err != nil {
		t.Fatalf("Git-common-directory run selector missing: %v", err)
	}
	var report compactAdvanceReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.RunID != created.RunID || report.State != created.State ||
		report.PauseCause != created.PauseCause || report.NextAction != created.NextAction {
		t.Fatalf("highest-seam status = %#v, created = %#v", report, created)
	}
}

func statusSnapshotRegularFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[path] = bytes.Clone(raw)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return files
}
