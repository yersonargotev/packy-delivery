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
		{"deterministic advance", issuedelivery.StateNeedsReview, issuedelivery.PauseDeterministicAdvance, issuedelivery.ActionAdvance},
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

func TestCompactAdvanceReportIsMateriallySmallerAndFullReportRoundTrips(t *testing.T) {
	reviews := make([]issuedelivery.CandidateReview, 80)
	for index := range reviews {
		reviews[index] = issuedelivery.CandidateReview{
			CandidateID: "candidate", Axis: deliveryevidence.ReviewStandards,
			Iteration: index + 1, CommitSHA: strings.Repeat("a", 40),
			TreeSHA: strings.Repeat("b", 40), Findings: []deliveryevidence.ReviewFinding{},
			Completed: true,
		}
	}
	candidate := &issuedelivery.Candidate{
		ID: "candidate", CommitSHA: strings.Repeat("a", 40),
		TreeSHA: strings.Repeat("b", 40), Reviews: reviews,
	}
	outcome := issuedelivery.Outcome{
		RunID: "run-large", State: issuedelivery.StateNeedsReview,
		Reason: "review the exact candidate", PauseCause: issuedelivery.PauseIndependentReview,
		NextAction: issuedelivery.ActionProvideCandidateReview, Candidate: candidate,
		QualificationReviews: make([]issuedelivery.QualificationReview, 40),
	}
	compact := runAdvanceOutput(t, outcome)
	full := runAdvanceOutput(t, outcome, "--full-report")
	t.Logf("representative report bytes: compact=%d full=%d", len(compact), len(full))
	if len(compact)*4 >= len(full) {
		t.Fatalf("compact report is not materially smaller: compact=%d full=%d", len(compact), len(full))
	}
	for _, excluded := range []string{
		"qualification_reviews", "evidence", "reviews", "timing", "timing_report",
	} {
		if strings.Contains(compact, `"`+excluded+`"`) {
			t.Fatalf("compact report contains %q history: %s", excluded, compact)
		}
	}
	var decoded advanceReport
	if err := json.Unmarshal([]byte(full), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Candidate, candidate) ||
		len(decoded.QualificationReviews) != len(outcome.QualificationReviews) {
		t.Fatal("full canonical report lost outcome fields")
	}
}

func TestCompactAdvanceReportKeepsOnlyCurrentDeliveryIdentity(t *testing.T) {
	branch := &issuedelivery.RemoteBranchObservation{Name: "feat/issue-7", HeadSHA: strings.Repeat("a", 40)}
	pullRequest := &issuedelivery.RemotePullRequestObservation{
		Number: 7, URL: "https://github.com/yersonargotev/packy/pull/7",
		HeadSHA: strings.Repeat("a", 40),
	}
	check := issuedelivery.CICheckObservation{
		RequiredCheck: deliveryevidence.RequiredCheck{
			Identity: "Validate Packy", HeadSHA: strings.Repeat("a", 40),
			Conclusion: "success",
		},
		StatusKind: issuedelivery.CIKindCheckRun, RunID: 77,
		DetailsURL: "https://github.com/yersonargotev/packy/actions/runs/77",
	}
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
			if report.Branch != nil || report.PullRequest == nil || len(report.CI) != 1 || report.Merge != nil {
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
			if report.Candidate == nil {
				t.Fatal("current candidate identity was omitted")
			}
			test.assert(t, report)
		})
	}
	blocked := base
	blocked.BlockerKind = issuedelivery.BlockerPullRequest
	if report := compactReportFromOutcome(blocked); report.BlockerKind != issuedelivery.BlockerPullRequest {
		t.Fatalf("blocker identity=%#v", report)
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
