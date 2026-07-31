package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

func TestAdvanceCommandConvergesAndConsumesSemanticInputOnce(t *testing.T) {
	decision := &issuedelivery.Decision{RequestID: "decision-1"}
	fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{
		{
			RunID: "run", State: issuedelivery.StateNeedsReview, Reason: "qualification approved",
			PauseCause: issuedelivery.PauseDeterministicAdvance, NextAction: issuedelivery.ActionAdvance,
		},
		{
			RunID: "run", State: issuedelivery.StateNeedsReview, Reason: "candidate focused",
			PauseCause: issuedelivery.PauseDeterministicAdvance, NextAction: issuedelivery.ActionAdvance,
			Candidate: &issuedelivery.Candidate{ID: "candidate"},
		},
		{
			RunID: "run", State: issuedelivery.StateNeedsReview, Reason: "review required",
			PauseCause: issuedelivery.PauseIndependentReview,
			NextAction: issuedelivery.ActionProvideCandidateReview,
			Candidate:  &issuedelivery.Candidate{ID: "candidate"},
		},
	}}
	outcome, err := convergeAdvance(context.Background(), fake, issuedelivery.Request{
		RepositoryPath: "/repo", IssueNumber: 8, Decision: decision,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.PauseCause != issuedelivery.PauseIndependentReview || len(fake.requests) != 3 {
		t.Fatalf("converged outcome=%#v requests=%#v", outcome, fake.requests)
	}
	if fake.requests[0].Decision != decision ||
		fake.requests[1].Decision != nil || fake.requests[2].Decision != nil {
		t.Fatalf("one-shot decision was reused: %#v", fake.requests)
	}
}

func TestAdvanceCommandStopsAtEveryGenuineBoundary(t *testing.T) {
	for _, cause := range []issuedelivery.PauseCause{
		issuedelivery.PauseSemanticInput,
		issuedelivery.PauseIndependentReview,
		issuedelivery.PauseExternalResult,
		issuedelivery.PauseNonLocalAuthorization,
		issuedelivery.PauseInvariantBlock,
		issuedelivery.PauseCandidateRepair,
		issuedelivery.PauseLockContention,
		issuedelivery.PauseLegacyWorkflow,
		issuedelivery.PauseCompleted,
	} {
		t.Run(string(cause), func(t *testing.T) {
			expected := issuedelivery.Outcome{
				RunID: "run", State: issuedelivery.StateWaiting,
				PauseCause: cause, NextAction: issuedelivery.ActionObserveExternalResult,
			}
			fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{expected}}
			got, err := convergeAdvance(context.Background(), fake, issuedelivery.Request{}, false)
			if err != nil {
				t.Fatal(err)
			}
			if got.PauseCause != cause || len(fake.requests) != 1 {
				t.Fatalf("boundary %q crossed: outcome=%#v calls=%d", cause, got, len(fake.requests))
			}
		})
	}
}

func TestAdvanceCommandConsumesExplicitNonLocalAuthorizationOnce(t *testing.T) {
	candidate := &issuedelivery.Candidate{
		ID: "candidate", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
	}
	readiness := &issuedelivery.LocalReadiness{
		CandidateID: candidate.ID, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		Branch: "feat/issue-8", ReadyAt: "2026-07-30T12:00:00.000000000Z",
	}
	fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{
		{
			RunID: "run", State: issuedelivery.StateNeedsReview, Reason: "ready next",
			PauseCause: issuedelivery.PauseDeterministicAdvance, NextAction: issuedelivery.ActionAdvance,
		},
		{
			RunID: "run", State: issuedelivery.StateWaiting, Candidate: candidate,
			LocalReadiness: readiness, PauseCause: issuedelivery.PauseNonLocalAuthorization,
			NextAction: issuedelivery.ActionAuthorizeNonLocal,
		},
		{
			RunID: "run", State: issuedelivery.StateWaiting, Candidate: candidate,
			LocalReadiness: readiness, NonLocal: &issuedelivery.NonLocalDelivery{},
			PauseCause: issuedelivery.PauseExternalResult,
			NextAction: issuedelivery.ActionObserveExternalResult,
		},
	}}
	if _, err := convergeAdvance(context.Background(), fake, issuedelivery.Request{
		RepositoryPath: "/repo", IssueNumber: 8,
	}, true); err != nil {
		t.Fatal(err)
	}
	if len(fake.requests) != 3 || fake.requests[0].NonLocal != nil ||
		fake.requests[1].NonLocal != nil || fake.requests[2].NonLocal == nil {
		t.Fatalf("authorization calls=%#v", fake.requests)
	}
}

func TestAdvanceCommandAuthorizationDoesNotCrossAnotherBoundary(t *testing.T) {
	candidate := &issuedelivery.Candidate{
		ID: "candidate", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
	}
	blocked := issuedelivery.Outcome{
		RunID: "run", State: issuedelivery.StateBlocked, Candidate: candidate,
		LocalReadiness: &issuedelivery.LocalReadiness{
			CandidateID: candidate.ID, CommitSHA: candidate.CommitSHA,
			TreeSHA: candidate.TreeSHA, Branch: "feat/issue-8",
		},
		PauseCause: issuedelivery.PauseInvariantBlock,
		NextAction: issuedelivery.ActionInspectBlockedTransition,
	}
	fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{blocked}}
	got, err := convergeAdvance(
		context.Background(), fake, issuedelivery.Request{RepositoryPath: "/repo", IssueNumber: 8}, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.PauseCause != issuedelivery.PauseInvariantBlock ||
		len(fake.requests) != 1 || fake.requests[0].NonLocal != nil {
		t.Fatalf("authorization crossed invariant boundary: outcome=%#v requests=%#v", got, fake.requests)
	}
}

func TestAdvanceCommandConvergenceGuardsFailClosed(t *testing.T) {
	t.Run("repeated signature", func(t *testing.T) {
		repeated := issuedelivery.Outcome{
			RunID: "run", State: issuedelivery.StateNeedsReview, Reason: "same",
			PauseCause: issuedelivery.PauseDeterministicAdvance, NextAction: issuedelivery.ActionAdvance,
		}
		fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{repeated, repeated}}
		got, err := convergeAdvance(context.Background(), fake, issuedelivery.Request{}, false)
		if err != nil {
			t.Fatal(err)
		}
		assertConvergenceBlock(t, got)
		if len(fake.requests) != 2 {
			t.Fatalf("repeated guard calls=%d", len(fake.requests))
		}
	})
	t.Run("transition cap", func(t *testing.T) {
		outcomes := make([]issuedelivery.Outcome, maxConvergentAdvanceTransitions)
		for index := range outcomes {
			outcomes[index] = issuedelivery.Outcome{
				RunID: "run", State: issuedelivery.StateNeedsReview,
				Reason:     fmt.Sprintf("transition-%d", index),
				PauseCause: issuedelivery.PauseDeterministicAdvance,
				NextAction: issuedelivery.ActionAdvance,
			}
		}
		fake := &fakeIssueDeliveryAdvancer{outcomes: outcomes}
		got, err := convergeAdvance(context.Background(), fake, issuedelivery.Request{}, false)
		if err != nil {
			t.Fatal(err)
		}
		assertConvergenceBlock(t, got)
		if len(fake.requests) != maxConvergentAdvanceTransitions {
			t.Fatalf("cap calls=%d", len(fake.requests))
		}
	})
}

func TestAdvanceCommandRendersTypedConvergenceBlock(t *testing.T) {
	repeated := issuedelivery.Outcome{
		RunID: "run", State: issuedelivery.StateNeedsReview, Reason: "same",
		PauseCause: issuedelivery.PauseDeterministicAdvance, NextAction: issuedelivery.ActionAdvance,
	}
	fake := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{repeated, repeated}}
	cmd := command{AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
		return fake, nil
	}}
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), []string{
		"advance", "--repository", t.TempDir(), "--issue", "8",
	}, &stdout); err != nil {
		t.Fatal(err)
	}
	var report compactAdvanceReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	assertConvergenceBlock(t, issuedelivery.Outcome{
		State: report.State, PauseCause: report.PauseCause,
		NextAction: report.NextAction, BlockerKind: report.BlockerKind,
	})
}

func assertConvergenceBlock(t *testing.T, outcome issuedelivery.Outcome) {
	t.Helper()
	if outcome.State != issuedelivery.StateBlocked ||
		outcome.PauseCause != issuedelivery.PauseInvariantBlock ||
		outcome.NextAction != issuedelivery.ActionInspectBlockedTransition ||
		outcome.BlockerKind != issuedelivery.BlockerAdvanceConvergence {
		t.Fatalf("convergence block=%#v", outcome)
	}
}
