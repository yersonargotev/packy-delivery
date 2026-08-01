package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

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
				"{\n  \"run_id\": \"run-snapshot\",\n  \"state\": %q,\n  \"reason\": \"pause\",\n  \"pause_cause\": %q,\n  \"next_action\": %q,\n  \"timing_summary\": {\n    \"categories\": [\n      {\n        \"category\": \"active-work\",\n        \"duration_nanoseconds\": 0\n      },\n      {\n        \"category\": \"review\",\n        \"duration_nanoseconds\": 0\n      },\n      {\n        \"category\": \"validation\",\n        \"duration_nanoseconds\": 0\n      },\n      {\n        \"category\": \"external-ci-wait\",\n        \"duration_nanoseconds\": 0\n      },\n      {\n        \"category\": \"merge\",\n        \"duration_nanoseconds\": 0\n      },\n      {\n        \"category\": \"cleanup\",\n        \"duration_nanoseconds\": 0\n      }\n    ],\n    \"objective\": {\n      \"applicable\": false\n    }\n  },\n  \"assurance\": {}\n}\n",
				test.state, test.cause, test.action,
			)
			if jsonOutput != wantJSON {
				t.Fatalf("compact JSON snapshot:\n got %s\nwant %s", jsonOutput, wantJSON)
			}
			textOutput := runAdvanceOutput(t, outcome, "--output", "text")
			wantText := fmt.Sprintf(
				"run: run-snapshot\nstate: %s\npause cause: %s\nnext action: %s\nreason: pause\n"+
					"timing: active-work=0ns\n"+
					"timing: review=0ns\n"+
					"timing: validation=0ns\n"+
					"timing: external-ci-wait=0ns\n"+
					"timing: merge=0ns\n"+
					"timing: cleanup=0ns\n"+
					"timing objective: profile= applicable=false\n",
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
		Remediation: &issuedelivery.LocalReadinessRemediation{AcceptedBranchForms: []string{
			"chore/issue-7-*", "feat/issue-7-*", "fix/issue-7-*",
		}},
		QualificationReviews: []issuedelivery.QualificationReview{{
			AuthoritySHA256:        strings.Repeat("d", 64),
			AcceptanceMatrixSHA256: strings.Repeat("e", 64),
			Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
		}},
		ValidationSessions: []issuedelivery.ValidationSession{{
			ID: strings.Repeat("f", 64), Attempt: 1,
			State:    issuedelivery.ValidationSessionStarted,
			HomeRoot: "/Users/operator/private-home", ConfigRoot: "/Users/operator/private-config",
		}},
		ValidationInvalidations: []issuedelivery.ValidationInvalidation{{
			SessionID: strings.Repeat("f", 64), CandidateID: candidate.ID,
			Class:      issuedelivery.ValidationInvalidationWorkspace,
			ObservedAt: "2026-07-31T12:00:00.000000000Z",
		}},
	}
	full := runAdvanceOutput(t, outcome, "--full-report")
	var decoded advanceReport
	if err := json.Unmarshal([]byte(full), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Candidate, candidate) ||
		!reflect.DeepEqual(decoded.Remediation, outcome.Remediation) ||
		!reflect.DeepEqual(decoded.ValidationSessions, outcome.ValidationSessions) ||
		!reflect.DeepEqual(decoded.ValidationInvalidations, outcome.ValidationInvalidations) ||
		len(decoded.QualificationReviews) != len(outcome.QualificationReviews) {
		t.Fatal("full canonical report lost outcome fields")
	}
	compact := runAdvanceOutput(t, outcome)
	if strings.Contains(compact, "/Users/operator") ||
		strings.Contains(compact, `"validation_session"`) {
		t.Fatalf("compact projection leaked raw validation details: %s", compact)
	}
}

func TestAdvanceReportsStructuredObservationDiagnosticInEveryFormat(t *testing.T) {
	diagnostic := &issuedelivery.ObservationDiagnostic{
		Kind:           issuedelivery.ObservationDiagnosticWorkflowDefinition,
		CommandPurpose: "resolve exact workflow definition",
		Repository:     "yersonargotev/packy", Ref: strings.Repeat("a", 40),
		WorkflowPath:      ".github/workflows/governance.yml",
		ObservationSource: issuedelivery.ObservationSourceCommitStatus,
		RetryCount:        1, FinalFailureClass: issuedelivery.WorkflowDefinitionFailurePersistent,
		Detail: "exact workflow definition ref remained absent after one ref refresh",
	}
	outcome := issuedelivery.Outcome{
		RunID: "run-diagnostic", State: issuedelivery.StateWaiting,
		Reason: "post-merge observation failed", PauseCause: issuedelivery.PauseExternalResult,
		NextAction:            issuedelivery.ActionObserveExternalResult,
		ObservationDiagnostic: diagnostic,
	}

	for _, args := range [][]string{nil, {"--full-report"}} {
		output := runAdvanceOutput(t, outcome, args...)
		var public struct {
			ObservationDiagnostic *issuedelivery.ObservationDiagnostic `json:"observation_diagnostic"`
		}
		if err := json.Unmarshal([]byte(output), &public); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(public.ObservationDiagnostic, diagnostic) {
			t.Fatalf("structured diagnostic=%#v; want %#v; output=%s",
				public.ObservationDiagnostic, diagnostic, output)
		}
	}

	text := runAdvanceOutput(t, outcome, "--output", "text")
	for _, expected := range []string{
		"observation diagnostic: workflow-definition",
		"purpose=resolve exact workflow definition",
		"ref=" + strings.Repeat("a", 40),
		"workflow=.github/workflows/governance.yml",
		"source=commit-status", "retries=1", "failure=persistent-ref-absence",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("text diagnostic missing %q: %s", expected, text)
		}
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
			"qualification_reviews", "evidence", "reviews", "timing_report",
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
			report, err := compactReportFromOutcome(outcome, time.Unix(0, 0))
			if err != nil {
				t.Fatal(err)
			}
			if report.Candidate != nil {
				t.Fatalf("remote progress leaked candidate identity: %#v", report)
			}
			test.assert(t, report)
		})
	}
	authorized := base
	authorized.NonLocal = &issuedelivery.NonLocalDelivery{}
	authorizedReport, err := compactReportFromOutcome(authorized, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if authorizedReport.Branch == nil || authorizedReport.Candidate != nil {
		t.Fatalf("post-authorization projection=%#v", authorizedReport)
	}
	blocked := base
	blocked.BlockerKind = issuedelivery.BlockerPullRequest
	report, err := compactReportFromOutcome(blocked, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if report.BlockerKind != issuedelivery.BlockerPullRequest ||
		report.Candidate != nil || report.Branch != nil || report.PullRequest != nil ||
		report.CI != nil || report.Merge != nil {
		t.Fatalf("blocker identity=%#v", report)
	}
}

func TestCompactAdvanceReportExposesAssuranceProgressAtThePublicSeam(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	completedReview := func(axis deliveryevidence.ReviewAxis) issuedelivery.CandidateReview {
		return issuedelivery.CandidateReview{
			CandidateID: "candidate-progress", Axis: axis, Iteration: 1,
			CommitSHA: commit, TreeSHA: tree,
			Findings: []deliveryevidence.ReviewFinding{}, Completed: true,
		}
	}
	completedSpecialist := func(boundary issuedelivery.SensitiveBoundary) issuedelivery.SpecialistReview {
		identities := map[issuedelivery.SensitiveBoundary]string{
			issuedelivery.BoundaryPublication: "publication-specialist",
			issuedelivery.BoundarySecurity:    "security-specialist",
		}
		return issuedelivery.SpecialistReview{
			CandidateID: "candidate-progress", Boundary: boundary,
			Specialist: identities[boundary], Findings: []issuedelivery.SpecialistFinding{}, Completed: true,
		}
	}
	newCandidate := func(reviews []issuedelivery.CandidateReview, specialists []issuedelivery.SpecialistReview) *issuedelivery.Candidate {
		return &issuedelivery.Candidate{
			ID: "candidate-progress", CommitSHA: commit, TreeSHA: tree,
			RequiredReviews: []deliveryevidence.ReviewAxis{
				deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
			},
			ReviewIteration: 1, Reviews: reviews,
			RequiredSpecialists: []issuedelivery.SensitiveBoundary{
				issuedelivery.BoundaryPublication, issuedelivery.BoundarySecurity,
			},
			SpecialistReviews: specialists,
		}
	}
	tests := []struct {
		name                string
		candidate           *issuedelivery.Candidate
		completedAxes       []deliveryevidence.ReviewAxis
		pendingAxes         []deliveryevidence.ReviewAxis
		completedBoundaries []issuedelivery.CompactSpecialistBoundary
		pendingBoundaries   []issuedelivery.CompactSpecialistBoundary
	}{
		{
			name: "no candidate",
		},
		{
			name: "initial candidate", candidate: newCandidate(nil, nil),
			completedAxes: []deliveryevidence.ReviewAxis{},
			pendingAxes: []deliveryevidence.ReviewAxis{
				deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
			},
			completedBoundaries: []issuedelivery.CompactSpecialistBoundary{},
			pendingBoundaries: []issuedelivery.CompactSpecialistBoundary{
				{Boundary: issuedelivery.BoundaryPublication, Specialist: "publication-specialist"},
				{Boundary: issuedelivery.BoundarySecurity, Specialist: "security-specialist"},
			},
		},
		{
			name: "partial candidate reviews", candidate: newCandidate(
				[]issuedelivery.CandidateReview{completedReview(deliveryevidence.ReviewStandards)}, nil,
			),
			completedAxes:       []deliveryevidence.ReviewAxis{deliveryevidence.ReviewStandards},
			pendingAxes:         []deliveryevidence.ReviewAxis{deliveryevidence.ReviewSpec},
			completedBoundaries: []issuedelivery.CompactSpecialistBoundary{},
			pendingBoundaries: []issuedelivery.CompactSpecialistBoundary{
				{Boundary: issuedelivery.BoundaryPublication, Specialist: "publication-specialist"},
				{Boundary: issuedelivery.BoundarySecurity, Specialist: "security-specialist"},
			},
		},
		{
			name: "partial specialist reviews", candidate: newCandidate(
				[]issuedelivery.CandidateReview{
					completedReview(deliveryevidence.ReviewStandards),
					completedReview(deliveryevidence.ReviewSpec),
				},
				[]issuedelivery.SpecialistReview{completedSpecialist(issuedelivery.BoundarySecurity)},
			),
			completedAxes: []deliveryevidence.ReviewAxis{
				deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
			},
			pendingAxes: []deliveryevidence.ReviewAxis{},
			completedBoundaries: []issuedelivery.CompactSpecialistBoundary{
				{Boundary: issuedelivery.BoundarySecurity, Specialist: "security-specialist"},
			},
			pendingBoundaries: []issuedelivery.CompactSpecialistBoundary{
				{Boundary: issuedelivery.BoundaryPublication, Specialist: "publication-specialist"},
			},
		},
		{
			name: "completed assurance", candidate: newCandidate(
				[]issuedelivery.CandidateReview{
					completedReview(deliveryevidence.ReviewStandards),
					completedReview(deliveryevidence.ReviewSpec),
				},
				[]issuedelivery.SpecialistReview{
					completedSpecialist(issuedelivery.BoundaryPublication),
					completedSpecialist(issuedelivery.BoundarySecurity),
				},
			),
			completedAxes: []deliveryevidence.ReviewAxis{
				deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
			},
			pendingAxes: []deliveryevidence.ReviewAxis{},
			completedBoundaries: []issuedelivery.CompactSpecialistBoundary{
				{Boundary: issuedelivery.BoundaryPublication, Specialist: "publication-specialist"},
				{Boundary: issuedelivery.BoundarySecurity, Specialist: "security-specialist"},
			},
			pendingBoundaries: []issuedelivery.CompactSpecialistBoundary{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome := issuedelivery.Outcome{
				RunID: "run-progress", State: issuedelivery.StateNeedsReview,
				PauseCause: issuedelivery.PauseIndependentReview,
				NextAction: issuedelivery.ActionProvideCandidateReview,
				Candidate:  test.candidate,
			}
			jsonOutput := runAdvanceOutput(t, outcome)
			var report compactAdvanceReport
			if err := json.Unmarshal([]byte(jsonOutput), &report); err != nil {
				t.Fatal(err)
			}
			if test.candidate == nil {
				if report.Assurance.Progress != nil {
					t.Fatalf("no-candidate report invented progress: %#v", report.Assurance.Progress)
				}
				if statusOutput := runStatusOutput(t, outcome); statusOutput != jsonOutput {
					t.Fatalf("status and Advance compact JSON differ:\nstatus:\n%s\nadvance:\n%s", statusOutput, jsonOutput)
				}
				return
			}
			if report.Assurance.Progress == nil {
				t.Fatal("candidate report omitted assurance progress")
			}
			progress := report.Assurance.Progress
			if !reflect.DeepEqual(progress.CandidateReviewAxes.Completed, test.completedAxes) ||
				!reflect.DeepEqual(progress.CandidateReviewAxes.Pending, test.pendingAxes) ||
				!reflect.DeepEqual(progress.SpecialistBoundaries.Completed, test.completedBoundaries) ||
				!reflect.DeepEqual(progress.SpecialistBoundaries.Pending, test.pendingBoundaries) {
				t.Fatalf("progress=%#v", progress)
			}
			textOutput := runAdvanceOutput(t, outcome, "--output", "text")
			if statusOutput := runStatusOutput(t, outcome); statusOutput != jsonOutput {
				t.Fatalf("status and Advance compact JSON differ:\nstatus:\n%s\nadvance:\n%s", statusOutput, jsonOutput)
			}
			if statusOutput := runStatusOutput(t, outcome, "--output", "text"); statusOutput != textOutput {
				t.Fatalf("status and Advance compact text differ:\nstatus:\n%s\nadvance:\n%s", statusOutput, textOutput)
			}
			textEntries := append(
				compactProgressTextEntries(test.completedAxes, test.pendingAxes),
				compactSpecialistProgressTextEntries(test.completedBoundaries, test.pendingBoundaries)...,
			)
			for _, entry := range textEntries {
				if !strings.Contains(textOutput, entry) {
					t.Errorf("text output missing %q:\n%s", entry, textOutput)
				}
			}
		})
	}
}

func TestCompactAdvanceReportTextHandlesCandidateWithoutSpecialistWork(t *testing.T) {
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	outcome := issuedelivery.Outcome{
		RunID: "run-standard", State: issuedelivery.StateNeedsReview,
		PauseCause: issuedelivery.PauseIndependentReview,
		NextAction: issuedelivery.ActionProvideCandidateReview,
		Candidate: &issuedelivery.Candidate{
			ID: "candidate-standard", CommitSHA: commit, TreeSHA: tree,
			RequiredReviews: []deliveryevidence.ReviewAxis{
				deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
			},
			ReviewIteration: 1, Reviews: []issuedelivery.CandidateReview{},
		},
	}
	output := runAdvanceOutput(t, outcome, "--output", "text")
	if !strings.Contains(output, "candidate review pending: standards") ||
		!strings.Contains(output, "candidate review pending: spec") ||
		strings.Contains(output, "specialist review") {
		t.Fatalf("standard candidate text report=%s", output)
	}
}

func TestCompactAdvanceReportNamesEachReusedValidationObligation(t *testing.T) {
	completion := strings.Repeat("c", 64)
	sessionID := strings.Repeat("d", 64)
	candidate := &issuedelivery.Candidate{
		ID: "derived-candidate", RequiredReviews: []deliveryevidence.ReviewAxis{},
		RequiredSpecialists: []issuedelivery.SensitiveBoundary{},
		Derivation: &issuedelivery.CandidateDerivation{
			ValidationDerivationReceipts: []deliveryevidence.ValidationDerivationReceipt{
				{
					Identity: "derived-exhaustive", SourceSessionID: sessionID,
					SourceCompletionSHA256: completion,
					Obligation:             deliveryevidence.ValidationObligationIdentity{Kind: deliveryevidence.ValidationObligationExhaustive},
				},
				{
					Identity: "derived-security", SourceSessionID: sessionID,
					SourceCompletionSHA256: completion,
					Obligation: deliveryevidence.ValidationObligationIdentity{
						Kind: deliveryevidence.ValidationObligationBoundary, Boundary: deliveryevidence.BoundarySecurity,
					},
				},
			},
		},
	}
	outcome := issuedelivery.Outcome{
		RunID: "run-validation-reuse", State: issuedelivery.StateWaiting,
		PauseCause: issuedelivery.PauseExternalResult, NextAction: issuedelivery.ActionObserveExternalResult,
		Candidate: candidate,
	}
	jsonOutput := runAdvanceOutput(t, outcome)
	var report compactAdvanceReport
	if err := json.Unmarshal([]byte(jsonOutput), &report); err != nil {
		t.Fatal(err)
	}
	if got := report.Assurance.ReusedValidationArtifacts; len(got) != 2 ||
		got[0].Kind != issuedelivery.ReusedValidationBoundary || got[0].Boundary != issuedelivery.BoundarySecurity ||
		got[1].Kind != issuedelivery.ReusedValidationExhaustive {
		t.Fatalf("reused validation JSON=%#v", got)
	}
	textOutput := runAdvanceOutput(t, outcome, "--output", "text")
	for _, expected := range []string{
		"reused validation artifact: boundary identity=derived-security",
		"boundary=security",
		"reused validation artifact: exhaustive identity=derived-exhaustive",
	} {
		if !strings.Contains(textOutput, expected) {
			t.Fatalf("text report omitted %q:\n%s", expected, textOutput)
		}
	}
}

func compactProgressTextEntries(
	completed, pending []deliveryevidence.ReviewAxis,
) []string {
	entries := make([]string, 0, len(completed)+len(pending))
	for _, axis := range completed {
		entries = append(entries, "candidate review completed: "+string(axis))
	}
	for _, axis := range pending {
		entries = append(entries, "candidate review pending: "+string(axis))
	}
	return entries
}

func compactSpecialistProgressTextEntries(
	completed, pending []issuedelivery.CompactSpecialistBoundary,
) []string {
	entries := make([]string, 0, len(completed)+len(pending))
	for _, item := range completed {
		entries = append(entries, "specialist review completed: "+string(item.Boundary)+" specialist="+item.Specialist)
	}
	for _, item := range pending {
		entries = append(entries, "specialist review pending: "+string(item.Boundary)+" specialist="+item.Specialist)
	}
	return entries
}

func runStatusOutput(t *testing.T, outcome issuedelivery.Outcome, extra ...string) string {
	t.Helper()
	repository := t.TempDir()
	fake := &fakeIssueDeliveryStatuser{outcome: outcome}
	cmd := command{StatusFactory: func(statusOptions) (issueDeliveryStatuser, error) {
		return fake, nil
	}}
	args := []string{"status", "--repository", repository, "--issue", "7"}
	args = append(args, extra...)
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), args, &stdout); err != nil {
		t.Fatal(err)
	}
	return stdout.String()
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
