package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type commandCompletionLocal struct {
	observation issuedelivery.LocalCompletionObservation
}

func (l *commandCompletionLocal) ObserveLocalCompletion(
	context.Context,
	issuedelivery.LocalCompletionObserveRequest,
) (issuedelivery.LocalCompletionObservation, error) {
	return l.observation, nil
}

func (*commandCompletionLocal) EnsureManagedWorktreeAbsent(
	context.Context,
	issuedelivery.RemoveManagedWorktreeRequest,
) error {
	return nil
}

func (l *commandCompletionLocal) EnsureLocalIssueBranchAbsent(
	context.Context,
	issuedelivery.DeleteLocalIssueBranchRequest,
) error {
	l.observation.LocalBranch = nil
	return nil
}

func (l *commandCompletionLocal) EnsureLocalMainFastForward(
	_ context.Context,
	request issuedelivery.FastForwardLocalMainRequest,
) error {
	l.observation.LocalMain.HeadSHA = request.OriginMainSHA
	l.observation.LocalMain.OriginHeadSHA = request.OriginMainSHA
	l.observation.LocalMain.Relation = issuedelivery.LocalMainSynced
	return nil
}

type commandCompletionRemote struct {
	observation issuedelivery.NonLocalObservation
	tracker     *commandMutableTrackerObserver
	local       *commandCompletionLocal
	clock       *commandClock
}

func (r *commandCompletionRemote) ObserveNonLocal(
	context.Context,
	issuedelivery.NonLocalObserveRequest,
) (issuedelivery.NonLocalObservation, error) {
	return r.observation, nil
}

func (r *commandCompletionRemote) PushIssueBranch(
	_ context.Context,
	request issuedelivery.PushIssueBranchRequest,
) error {
	r.observation.Branch = &issuedelivery.RemoteBranchObservation{
		Name: request.Branch, HeadSHA: request.HeadSHA,
	}
	return nil
}

func (r *commandCompletionRemote) EnsurePullRequest(
	_ context.Context,
	request issuedelivery.EnsurePullRequestRequest,
) error {
	r.observation.PullRequests = []issuedelivery.RemotePullRequestObservation{{
		Number: 1, URL: "https://github.com/yersonargotev/packy/pull/1",
		State: "OPEN", BaseRef: request.BaseRef, BaseSHA: strings.Repeat("a", 40),
		HeadBranch: request.HeadBranch, HeadSHA: request.HeadSHA,
		HeadRepositoryNodeID: request.Repository.NodeID, ClosingIssue: request.Issue.Number,
	}}
	r.observation.Checks = commandSuccessfulChecks(request.Repository, request.HeadSHA, strings.Repeat("a", 40))
	return nil
}

func (*commandCompletionRemote) RetryInfrastructureCheck(
	context.Context,
	issuedelivery.RetryInfrastructureCheckRequest,
) error {
	return nil
}

func (r *commandCompletionRemote) EnsureMerge(
	_ context.Context,
	request issuedelivery.EnsureMergeRequest,
) error {
	mergeCommit := strings.Repeat("f", 40)
	r.observation.Merge = &issuedelivery.MergeObservation{
		PullRequest: request.PullRequest, URL: r.observation.PullRequests[0].URL,
		BaseRef: "main", HeadSHA: request.HeadSHA, MergeCommitSHA: mergeCommit,
		MergedAt: r.clock.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
	}
	r.observation.OriginMain = &issuedelivery.OriginMainObservation{
		HeadSHA: mergeCommit, MergeCommitSHA: mergeCommit, CandidateHeadSHA: request.HeadSHA,
		ContainsMergeCommit: true, ContainsCandidateHead: true,
	}
	r.tracker.observation.State = "CLOSED"
	r.local.observation.Integration.Branch = "main"
	r.local.observation.LocalBranch = nil
	r.local.observation.LocalMain = issuedelivery.LocalMainObservation{
		Exists: true, HeadSHA: mergeCommit, OriginHeadSHA: mergeCommit,
		Relation: issuedelivery.LocalMainSynced, Clean: true,
	}
	return nil
}

func (r *commandCompletionRemote) EnsureRemoteIssueBranchAbsent(
	context.Context,
	issuedelivery.DeleteRemoteIssueBranchRequest,
) error {
	r.observation.Branch = nil
	return nil
}

func commandSuccessfulChecks(
	repository deliveryevidence.RepositoryIdentity,
	head, base string,
) []issuedelivery.CICheckObservation {
	identities := []string{
		"Claude 2.1.203 package smoke",
		"CodeQL",
		"Governance / Validate authorization",
		"Validate Packy-owned code",
	}
	checks := make([]issuedelivery.CICheckObservation, 0, len(identities))
	for index, identity := range identities {
		runID := int64(index + 1)
		check := issuedelivery.CICheckObservation{
			RequiredCheck: deliveryevidence.RequiredCheck{
				Identity: identity, Conclusion: "success", HeadSHA: head,
			},
			StatusKind: issuedelivery.CIKindCheckRun,
			Publisher: issuedelivery.TrustedPublisherEvidence{
				AppID: 15368, Slug: "github-actions",
			},
			Workflow: issuedelivery.CIWorkflowEvidence{
				Name: "CI", Path: ".github/workflows/ci.yml", RunID: runID,
				DefinitionRef: head, DefinitionSHA: strings.Repeat("e", 40),
			},
			RunID: runID,
			DetailsURL: "https://github.com/" + repository.Owner + "/" + repository.Name +
				"/actions/runs/" + string(rune('1'+index)),
		}
		if identity == "CodeQL" {
			check.Workflow.Name = "Security"
			check.Workflow.Path = ".github/workflows/security-pr.yml"
		}
		if identity == "Governance / Validate authorization" {
			check.StatusKind = issuedelivery.CIKindCommitStatus
			check.Publisher = issuedelivery.TrustedPublisherEvidence{
				Login: "github-actions[bot]", ID: 41898282, Type: "Bot",
				HTMLURL: "https://github.com/apps/github-actions",
			}
			check.Source = issuedelivery.TrustedPublisherEvidence{AppID: 15368, Slug: "github-actions"}
			check.Workflow.Name = "Governance"
			check.Workflow.Path = ".github/workflows/governance.yml"
			check.Workflow.DefinitionRef = base
		}
		checks = append(checks, check)
	}
	return checks
}

func TestAdvanceCommandRealModuleReportsCompletion(t *testing.T) {
	local := &commandCompletionLocal{}
	remote := &commandCompletionRemote{
		local: local,
		observation: issuedelivery.NonLocalObservation{
			PullRequests: []issuedelivery.RemotePullRequestObservation{},
			Checks:       []issuedelivery.CICheckObservation{},
		},
	}
	module, ready, repository, tracker, clock := productionReadyModule(t, remote, local, nil, "")
	remote.tracker = tracker
	remote.clock = clock
	local.observation = issuedelivery.LocalCompletionObservation{
		OperatorStateSHA256: strings.Repeat("9", 64),
		Integration: issuedelivery.IntegrationWorkspaceObservation{
			Path: repository, Branch: ready.LocalReadiness.Branch, Clean: true,
		},
		Worktrees: []issuedelivery.ManagedWorktreeObservation{},
		LocalBranch: &issuedelivery.LocalBranchObservation{
			Name: ready.LocalReadiness.Branch, HeadSHA: ready.Candidate.CommitSHA,
		},
		LocalMain: issuedelivery.LocalMainObservation{
			Exists: true, HeadSHA: strings.Repeat("a", 40), OriginHeadSHA: strings.Repeat("a", 40),
			Relation: issuedelivery.LocalMainSynced, Clean: true,
		},
	}
	authorization := issuedelivery.NonLocalAuthorization{
		RunID: ready.RunID, CandidateID: ready.Candidate.ID,
		CommitSHA: ready.Candidate.CommitSHA, TreeSHA: ready.Candidate.TreeSHA,
		Branch: ready.LocalReadiness.Branch, LocalReadyAt: ready.LocalReadiness.ReadyAt,
	}
	if _, err := module.Advance(context.Background(), issuedelivery.Request{
		RepositoryPath: repository, IssueNumber: 361, NonLocal: &authorization,
	}); err != nil {
		t.Fatal(err)
	}
	var merged issuedelivery.Outcome
	for attempts := 0; attempts < 16; attempts++ {
		var err error
		merged, err = module.Advance(context.Background(), issuedelivery.Request{
			RepositoryPath: repository, IssueNumber: 361,
		})
		if err != nil {
			t.Fatal(err)
		}
		if merged.NonLocal != nil && merged.NonLocal.Merge != nil {
			break
		}
	}
	if merged.NonLocal == nil || merged.NonLocal.Merge == nil {
		t.Fatalf("fixture did not reach an adopted merge: %#v", merged)
	}
	cmd := command{
		Now: func() time.Time { return time.Date(2026, 7, 30, 11, 0, 0, 0, time.UTC) },
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
			return module, nil
		},
	}
	report := runAdvanceCommandReport(t, cmd, repository)
	if report.State != issuedelivery.StateCompleted ||
		report.PauseCause != issuedelivery.PauseCompleted ||
		report.NextAction != issuedelivery.ActionNone {
		t.Fatalf("real Module completion report = %#v", report)
	}
	resumed := runAdvanceCommandReport(t, cmd, repository)
	if resumed.State != issuedelivery.StateCompleted ||
		resumed.RunID != report.RunID ||
		resumed.NonLocal == nil || resumed.NonLocal.Merge == nil {
		t.Fatalf("completed effects were not adopted on resume: %#v", resumed)
	}
}
