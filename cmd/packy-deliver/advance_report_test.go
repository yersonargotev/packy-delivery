package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

func TestCompactAdvanceReportSnapshotsEveryPauseCause(t *testing.T) {
	tests := []struct {
		name   string
		state  issuedelivery.State
		cause  issuedelivery.PauseCause
		action issuedelivery.NextAction
	}{
		{"semantic input", issuedelivery.StateNeedsDecision, issuedelivery.PauseSemanticInput, issuedelivery.ActionProvideDecision},
		{"independent review", issuedelivery.StateNeedsReview, issuedelivery.PauseIndependentReview, issuedelivery.ActionProvideCandidateReview},
		{"external result", issuedelivery.StateWaiting, issuedelivery.PauseExternalResult, issuedelivery.ActionObserveExternalResult},
		{"non-local authorization", issuedelivery.StateWaiting, issuedelivery.PauseNonLocalAuthorization, issuedelivery.ActionAuthorizeNonLocal},
		{"invariant block", issuedelivery.StateBlocked, issuedelivery.PauseInvariantBlock, issuedelivery.ActionResolveAuthorityBlock},
		{"completed", issuedelivery.StateCompleted, issuedelivery.PauseCompleted, issuedelivery.ActionNone},
		{"candidate repair", issuedelivery.StateNeedsReview, issuedelivery.PauseCandidateRepair, issuedelivery.ActionRepairCandidate},
		{"lock contention", issuedelivery.StateWaiting, issuedelivery.PauseLockContention, issuedelivery.ActionRetryAdvance},
		{"legacy workflow", issuedelivery.StateWaiting, issuedelivery.PauseLegacyWorkflow, issuedelivery.ActionResumeLegacyV1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome := issuedelivery.Outcome{
				RunID: "run-snapshot", State: test.state, Reason: "pause",
				PauseCause: test.cause, NextAction: test.action,
			}
			jsonOutput := runAdvanceOutput(t, outcome)
			wantJSON := fmt.Sprintf(
				"{\n  \"run_id\": \"run-snapshot\",\n  \"state\": %q,\n  \"reason\": \"pause\",\n  \"pause_cause\": %q,\n  \"next_action\": %q\n}\n",
				test.state, test.cause, test.action,
			)
			if jsonOutput != wantJSON {
				t.Fatalf("compact JSON snapshot:\n got %s\nwant %s", jsonOutput, wantJSON)
			}
			textOutput := runAdvanceOutput(t, outcome, "--output", "text")
			wantText := fmt.Sprintf(
				"run: run-snapshot\nstate: %s\npause cause: %s\nnext action: %s\nreason: pause\n",
				test.state, test.cause, test.action,
			)
			if textOutput != wantText {
				t.Fatalf("compact text snapshot:\n got %s\nwant %s", textOutput, wantText)
			}
		})
	}
}

func TestFullAdvanceReportRoundTripsWithoutProjectionLoss(t *testing.T) {
	candidate := representativeCandidate()
	outcome := issuedelivery.Outcome{
		RunID: "run-roundtrip", State: issuedelivery.StateNeedsReview,
		Reason: "review the exact candidate", PauseCause: issuedelivery.PauseIndependentReview,
		NextAction: issuedelivery.ActionProvideCandidateReview, Candidate: candidate,
		QualificationReviews: []issuedelivery.QualificationReview{{
			AuthoritySHA256:        strings.Repeat("d", 64),
			AcceptanceMatrixSHA256: strings.Repeat("e", 64),
			Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
		}},
	}
	full := runAdvanceOutput(t, outcome, "--full-report")
	var decoded advanceReport
	if err := json.Unmarshal([]byte(full), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Candidate, candidate) ||
		len(decoded.QualificationReviews) != len(outcome.QualificationReviews) {
		t.Fatal("full canonical report lost outcome fields")
	}
}

func TestRepeatedCompactAdvanceReportsAreMateriallySmaller(t *testing.T) {
	candidate := representativeCandidate()
	readiness := &issuedelivery.LocalReadiness{
		CandidateID: candidate.ID, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		AuthorityHash: strings.Repeat("d", 64), Branch: "feat/issue-7",
		ReadyAt: "2026-07-30T12:00:00.000000000Z",
	}
	branch := &issuedelivery.RemoteBranchObservation{Name: readiness.Branch, HeadSHA: candidate.CommitSHA}
	pullRequest := &issuedelivery.RemotePullRequestObservation{
		Number: 7, URL: "https://github.com/yersonargotev/packy/pull/7",
		HeadSHA: candidate.CommitSHA,
	}
	check := representativeCheck()
	merge := &issuedelivery.MergeProof{
		PullRequest: 7, URL: pullRequest.URL, HeadSHA: candidate.CommitSHA,
		MergeCommitSHA: strings.Repeat("f", 40),
	}
	sequence := []issuedelivery.Outcome{
		{
			RunID: "run-sequence", State: issuedelivery.StateNeedsReview,
			Reason: "candidate review required", PauseCause: issuedelivery.PauseIndependentReview,
			NextAction: issuedelivery.ActionProvideCandidateReview, Candidate: candidate,
		},
		{
			RunID: "run-sequence", State: issuedelivery.StateWaiting,
			Reason: "local readiness proved", PauseCause: issuedelivery.PauseNonLocalAuthorization,
			NextAction: issuedelivery.ActionAuthorizeNonLocal, Candidate: candidate, LocalReadiness: readiness,
		},
		{
			RunID: "run-sequence", State: issuedelivery.StateWaiting,
			Reason: "pull request ready", PauseCause: issuedelivery.PauseExternalResult,
			NextAction: issuedelivery.ActionObserveExternalResult, Candidate: candidate, LocalReadiness: readiness,
			NonLocal: &issuedelivery.NonLocalDelivery{Branch: branch, PullRequest: pullRequest},
		},
		{
			RunID: "run-sequence", State: issuedelivery.StateWaiting,
			Reason: "CI running", PauseCause: issuedelivery.PauseExternalResult,
			NextAction: issuedelivery.ActionObserveExternalResult, Candidate: candidate, LocalReadiness: readiness,
			NonLocal: &issuedelivery.NonLocalDelivery{
				Branch: branch, PullRequest: pullRequest,
				Checks: []issuedelivery.CICheckObservation{check},
			},
		},
		{
			RunID: "run-sequence", State: issuedelivery.StateCompleted,
			Reason: "delivery completed", PauseCause: issuedelivery.PauseCompleted,
			NextAction: issuedelivery.ActionNone, Candidate: candidate, LocalReadiness: readiness,
			NonLocal: &issuedelivery.NonLocalDelivery{
				Branch: branch, PullRequest: pullRequest,
				Checks: []issuedelivery.CICheckObservation{check}, Merge: merge,
			},
		},
	}
	var compactBytes, fullBytes int
	for _, outcome := range sequence {
		compact := runAdvanceOutput(t, outcome)
		full := runAdvanceOutput(t, outcome, "--full-report")
		compactBytes += len(compact)
		fullBytes += len(full)
		for _, excluded := range []string{
			"qualification_reviews", "evidence", "reviews", "timing", "timing_report",
		} {
			if strings.Contains(compact, `"`+excluded+`"`) {
				t.Fatalf("compact report contains %q history: %s", excluded, compact)
			}
		}
	}
	t.Logf("representative repeated report bytes: compact=%d full=%d", compactBytes, fullBytes)
	if compactBytes*3 >= fullBytes {
		t.Fatalf("repeated compact reports are not materially smaller: compact=%d full=%d",
			compactBytes, fullBytes)
	}
}

func TestCompactAdvanceReportKeepsOnlyCurrentDeliveryIdentity(t *testing.T) {
	branch := &issuedelivery.RemoteBranchObservation{Name: "feat/issue-7", HeadSHA: strings.Repeat("a", 40)}
	pullRequest := &issuedelivery.RemotePullRequestObservation{
		Number: 7, URL: "https://github.com/yersonargotev/packy/pull/7",
		HeadSHA: strings.Repeat("a", 40),
	}
	check := representativeCheck()
	merge := &issuedelivery.MergeProof{
		PullRequest: 7, URL: pullRequest.URL, HeadSHA: pullRequest.HeadSHA,
		MergeCommitSHA: strings.Repeat("b", 40),
	}
	base := issuedelivery.Outcome{
		RunID: "run", State: issuedelivery.StateWaiting,
		PauseCause: issuedelivery.PauseExternalResult,
		NextAction: issuedelivery.ActionObserveExternalResult,
		Candidate: &issuedelivery.Candidate{
			ID: "candidate", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("c", 40),
		},
		LocalReadiness: &issuedelivery.LocalReadiness{
			CandidateID: "candidate", CommitSHA: strings.Repeat("a", 40),
			TreeSHA: strings.Repeat("c", 40), Branch: "feat/issue-7",
		},
	}
	for _, test := range []struct {
		name   string
		remote issuedelivery.NonLocalDelivery
		assert func(*testing.T, compactAdvanceReport)
	}{
		{"branch", issuedelivery.NonLocalDelivery{Branch: branch}, func(t *testing.T, report compactAdvanceReport) {
			if report.Branch == nil || report.PullRequest != nil || report.CI != nil || report.Merge != nil {
				t.Fatalf("branch projection=%#v", report)
			}
		}},
		{"pull request", issuedelivery.NonLocalDelivery{Branch: branch, PullRequest: pullRequest}, func(t *testing.T, report compactAdvanceReport) {
			if report.Branch != nil || report.PullRequest == nil || report.CI != nil || report.Merge != nil {
				t.Fatalf("pull request projection=%#v", report)
			}
		}},
		{"CI", issuedelivery.NonLocalDelivery{Branch: branch, PullRequest: pullRequest, Checks: []issuedelivery.CICheckObservation{check}}, func(t *testing.T, report compactAdvanceReport) {
			if report.Branch != nil || report.PullRequest != nil || len(report.CI) != 1 || report.Merge != nil {
				t.Fatalf("CI projection=%#v", report)
			}
		}},
		{"merge", issuedelivery.NonLocalDelivery{Branch: branch, PullRequest: pullRequest, Checks: []issuedelivery.CICheckObservation{check}, Merge: merge}, func(t *testing.T, report compactAdvanceReport) {
			if report.Branch != nil || report.PullRequest != nil || report.CI != nil || report.Merge == nil {
				t.Fatalf("merge projection=%#v", report)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			outcome := base
			outcome.NonLocal = &test.remote
			report := compactReportFromOutcome(outcome)
			if report.Candidate != nil {
				t.Fatalf("remote progress leaked candidate identity: %#v", report)
			}
			test.assert(t, report)
		})
	}
	authorized := base
	authorized.NonLocal = &issuedelivery.NonLocalDelivery{}
	authorizedReport := compactReportFromOutcome(authorized)
	if authorizedReport.Branch == nil || authorizedReport.Candidate != nil {
		t.Fatalf("post-authorization projection=%#v", authorizedReport)
	}
	blocked := base
	blocked.BlockerKind = issuedelivery.BlockerPullRequest
	if report := compactReportFromOutcome(blocked); report.BlockerKind != issuedelivery.BlockerPullRequest ||
		report.Candidate != nil || report.Branch != nil || report.PullRequest != nil ||
		report.CI != nil || report.Merge != nil {
		t.Fatalf("blocker identity=%#v", report)
	}
}

func representativeCandidate() *issuedelivery.Candidate {
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	return &issuedelivery.Candidate{
		ID: "candidate", CommitSHA: commit, TreeSHA: tree,
		RequiredReviews: []deliveryevidence.ReviewAxis{
			deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
		},
		ReviewIteration: 1,
		Reviews: []issuedelivery.CandidateReview{
			{
				CandidateID: "candidate", Axis: deliveryevidence.ReviewStandards,
				Iteration: 1, CommitSHA: commit, TreeSHA: tree,
				Findings: []deliveryevidence.ReviewFinding{}, Completed: true,
			},
			{
				CandidateID: "candidate", Axis: deliveryevidence.ReviewSpec,
				Iteration: 1, CommitSHA: commit, TreeSHA: tree,
				Findings: []deliveryevidence.ReviewFinding{}, Completed: true,
			},
		},
	}
}

func representativeCheck() issuedelivery.CICheckObservation {
	return issuedelivery.CICheckObservation{
		RequiredCheck: deliveryevidence.RequiredCheck{
			Identity: "Validate Packy", HeadSHA: strings.Repeat("a", 40),
			Conclusion: "success",
		},
		StatusKind: issuedelivery.CIKindCheckRun, RunID: 77,
		DetailsURL: "https://github.com/yersonargotev/packy/actions/runs/77",
	}
}

func runAdvanceOutput(
	t *testing.T,
	outcome issuedelivery.Outcome,
	extra ...string,
) string {
	t.Helper()
	repository := t.TempDir()
	fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{outcome}}
	cmd := command{AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
		return fake, nil
	}}
	args := []string{"advance", "--repository", repository, "--issue", "7"}
	args = append(args, extra...)
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), args, &stdout); err != nil {
		t.Fatal(err)
	}
	return stdout.String()
}
