package issuedelivery

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

type inputTemplateNonLocalObserver struct {
	requests    []NonLocalObserveRequest
	observation NonLocalObservation
	err         error
}

func (o *inputTemplateNonLocalObserver) ObserveNonLocal(
	_ context.Context,
	request NonLocalObserveRequest,
) (NonLocalObservation, error) {
	o.requests = append(o.requests, request)
	return o.observation, o.err
}

func TestInputTemplateFromOutcomeCopiesMechanicalIdentityForEveryKind(t *testing.T) {
	authority := strings.Repeat("a", 64)
	matrix := []deliveryevidence.AcceptanceRow{{
		Identity: "criterion-1", Criterion: "exact criterion",
		Obligations: deliveryevidence.PhaseOwnedAcceptanceObligations(),
	}}
	matrixHash, err := acceptanceMatrixDigest(matrix)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		kind    InputTemplateKind
		outcome Outcome
		check   func(*testing.T, InputTemplate)
	}{
		{
			name: "decision", kind: InputTemplateDecision,
			outcome: Outcome{Decision: &DecisionRequest{ID: "decision-1"}},
			check: func(t *testing.T, draft InputTemplate) {
				if draft.Decision == nil || draft.Decision.RequestID != "decision-1" ||
					string(draft.Decision.Disposition) != inputPlaceholder {
					t.Fatalf("decision draft = %#v", draft.Decision)
				}
			},
		},
		{
			name: "qualification review", kind: InputTemplateQualificationReview,
			outcome: Outcome{
				Observations: Observations{AuthoritySHA256: authority},
				Evidence:     &deliveryevidence.Bundle{AcceptanceMatrix: matrix},
			},
			check: func(t *testing.T, draft InputTemplate) {
				got := draft.QualificationReview
				if got == nil || got.AuthoritySHA256 != authority ||
					got.AcceptanceMatrixSHA256 != matrixHash || got.Completed ||
					len(got.Findings) != 1 || got.Findings[0].ID != inputPlaceholder {
					t.Fatalf("qualification review draft = %#v", got)
				}
			},
		},
		{
			name: "qualification correction", kind: InputTemplateQualificationCorrection,
			outcome: Outcome{
				Evidence: &deliveryevidence.Bundle{AcceptanceMatrix: matrix},
				QualificationCorrection: &QualificationCorrectionRequest{
					ID: "correction-1", AuthoritySHA256: authority,
					ReviewedMatrixSHA256: matrixHash, FindingIDs: []string{"finding-1"},
				},
			},
			check: func(t *testing.T, draft InputTemplate) {
				got := draft.QualificationCorrection
				if got == nil || got.RequestID != "correction-1" ||
					got.AuthoritySHA256 != authority || got.ReviewedMatrixSHA256 != matrixHash ||
					!reflect.DeepEqual(got.FindingIDs, []string{"finding-1"}) ||
					len(got.AcceptanceMatrix) != 1 ||
					got.AcceptanceMatrix[0].Identity != matrix[0].Identity ||
					got.AcceptanceMatrix[0].Criterion != matrix[0].Criterion ||
					got.AcceptanceMatrix[0].OwningSeam != inputPlaceholder ||
					got.Evidence != inputPlaceholder {
					t.Fatalf("qualification correction draft = %#v", got)
				}
			},
		},
		{
			name: "repair", kind: InputTemplateRepair,
			outcome: Outcome{Repair: &RepairDecisionRequest{
				CandidateID: "candidate-1", FindingIDs: []string{"finding-b", "finding-a"},
			}},
			check: func(t *testing.T, draft InputTemplate) {
				got := draft.Repair
				if got == nil || got.CandidateID != "candidate-1" ||
					string(got.Class) != inputPlaceholder ||
					!reflect.DeepEqual(
						[]string{got.Findings[0].FindingID, got.Findings[1].FindingID},
						[]string{"finding-b", "finding-a"},
					) {
					t.Fatalf("repair draft = %#v", got)
				}
			},
		},
		{
			name: "CI attribution", kind: InputTemplateCIAttribution,
			outcome: Outcome{NonLocal: &NonLocalDelivery{Checks: []CICheckObservation{
				{
					RequiredCheck: deliveryevidence.RequiredCheck{
						Identity: "build", Conclusion: "failure", HeadSHA: strings.Repeat("b", 40),
					},
					RunID: 41, DetailsURL: "https://example.test/runs/41",
				},
				{
					RequiredCheck: deliveryevidence.RequiredCheck{
						Identity: "green", Conclusion: "success", HeadSHA: strings.Repeat("b", 40),
					},
					RunID: 42, DetailsURL: "https://example.test/runs/42",
				},
			}}},
			check: func(t *testing.T, draft InputTemplate) {
				if len(draft.CIAttributions) != 1 {
					t.Fatalf("CI attribution draft = %#v", draft.CIAttributions)
				}
				got := draft.CIAttributions[0]
				if got.CheckIdentity != "build" || got.RunID != 41 ||
					got.HeadSHA != strings.Repeat("b", 40) ||
					got.DetailsURL != "https://example.test/runs/41" ||
					string(got.Attribution) != inputPlaceholder {
					t.Fatalf("CI attribution = %#v", got)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft, err := inputTemplateFromOutcome(test.kind, test.outcome)
			if err != nil {
				t.Fatal(err)
			}
			test.check(t, draft)
		})
	}
}

func TestCurrentCIAttributionRequestRequiresExactFreshRemoteObservation(t *testing.T) {
	head := strings.Repeat("a", 40)
	repository := deliveryevidence.RepositoryIdentity{
		Owner: "yersonargotev", Name: "packy", NodeID: "repository-1",
	}
	issue := deliveryevidence.IssueIdentity{Number: 27, NodeID: "issue-27"}
	branch := RemoteBranchObservation{Name: "feat/issue-27-input-templates", HeadSHA: head}
	pullRequest := RemotePullRequestObservation{
		Number: 27, URL: "https://github.com/yersonargotev/packy/pull/27",
		State: "OPEN", BaseRef: "main", BaseSHA: strings.Repeat("b", 40),
		HeadBranch: branch.Name, HeadSHA: head,
		HeadRepositoryNodeID: repository.NodeID, ClosingIssue: issue.Number,
	}
	checks := []CICheckObservation{{
		RequiredCheck: deliveryevidence.RequiredCheck{
			Identity: "build", Conclusion: "failure", HeadSHA: head,
		},
		RunID: 41, DetailsURL: "https://github.com/yersonargotev/packy/actions/runs/41",
	}}
	active := runRecord{
		ID: "run-27", Repository: repository, Issue: issue,
		NonLocal: &NonLocalDelivery{
			Authorization: NonLocalAuthorization{
				RunID: "run-27", CandidateID: "candidate-27",
				CommitSHA: head, TreeSHA: strings.Repeat("c", 40),
				Branch: branch.Name,
			},
			BaseRef: "main", Branch: &branch, PullRequest: &pullRequest, Checks: checks,
		},
	}
	observer := &inputTemplateNonLocalObserver{observation: NonLocalObservation{
		Branch: &branch, PullRequests: []RemotePullRequestObservation{pullRequest}, Checks: checks,
	}}
	module := &Module{nonlocalObserver: observer}
	if err := module.validateCurrentCIAttributionRequest(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	wantRequest := NonLocalObserveRequest{
		RunID: active.ID, Repository: repository, Issue: issue,
		CandidateID: "candidate-27", Branch: branch.Name, BaseRef: "main", HeadSHA: head,
	}
	if !reflect.DeepEqual(observer.requests, []NonLocalObserveRequest{wantRequest}) {
		t.Fatalf("non-local requests = %#v, want %#v", observer.requests, wantRequest)
	}

	observer.observation.Checks = append([]CICheckObservation(nil), checks...)
	observer.observation.Checks[0].RunID = 42
	if err := module.validateCurrentCIAttributionRequest(
		context.Background(), active,
	); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("superseded CI run error = %v", err)
	}
}

func TestMaterializeInputTemplateRejectsWrongPauseAndStaleAuthorityWithoutWriting(t *testing.T) {
	module, git, tracker := moduleFixture(t, 356)
	tracker.mu.Lock()
	tracker.value.Ambiguities = []AuthorityItem{{
		Text: "Choose exact scope.", EvidenceLink: "issue#356:ambiguity",
	}}
	tracker.mu.Unlock()
	if _, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
	}); err != nil {
		t.Fatal(err)
	}
	before := snapshotRegularFiles(t, git.value.CommonDir)

	draft, err := module.MaterializeInputTemplate(context.Background(), InputTemplateRequest{
		RepositoryPath: "/repo", IssueNumber: 356, Kind: InputTemplateDecision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if draft.Decision == nil {
		t.Fatal("decision draft is absent")
	}
	if _, err := module.MaterializeInputTemplate(context.Background(), InputTemplateRequest{
		RepositoryPath: "/repo", IssueNumber: 356, Kind: InputTemplateRepair,
	}); err == nil || !strings.Contains(err.Error(), "does not match current pending action") {
		t.Fatalf("wrong-pause error = %v", err)
	}

	tracker.mu.Lock()
	tracker.value.Body += "\nchanged authority"
	tracker.mu.Unlock()
	if _, err := module.MaterializeInputTemplate(context.Background(), InputTemplateRequest{
		RepositoryPath: "/repo", IssueNumber: 356, Kind: InputTemplateDecision,
	}); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale-authority error = %v", err)
	}
	after := snapshotRegularFiles(t, git.value.CommonDir)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("input template observation changed the run store")
	}
}

func TestMaterializeInputTemplateRejectsCompletedAndBlockedRuns(t *testing.T) {
	for _, outcome := range []Outcome{
		{State: StateCompleted, NextAction: ActionNone},
		{State: StateBlocked, NextAction: ActionInspectBlockedTransition},
	} {
		if err := validateInputTemplateAction(
			InputTemplateDecision, ActionProvideDecision, outcome,
		); err == nil || !strings.Contains(err.Error(), "does not match current pending action") {
			t.Fatalf("%s run error = %v", outcome.State, err)
		}
	}
}
