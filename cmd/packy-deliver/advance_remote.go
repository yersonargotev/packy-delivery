package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type productionNonLocalGateway struct {
	runner       Runner
	repository   string
	attributions []advanceCIFailureAttribution
}

type remoteCommandError struct {
	err error
}

func (e *remoteCommandError) Error() string { return e.err.Error() }
func (e *remoteCommandError) Unwrap() error { return e.err }

type remoteDecodeError struct {
	err error
}

func (e *remoteDecodeError) Error() string { return e.err.Error() }
func (e *remoteDecodeError) Unwrap() error { return e.err }

type workflowDefinitionDiagnostic struct {
	CommandPurpose    string
	Repository        string
	Ref               string
	WorkflowPath      string
	ObservationSource string
	RetryCount        int
	FinalFailureClass string
	Detail            string
	cause             error
}

func (e *workflowDefinitionDiagnostic) Error() string {
	return fmt.Sprintf(
		"workflow-definition observation failed: command purpose=%q repository=%q ref=%q workflow path=%q observation source=%q retry count=%d final failure class=%q detail=%q",
		sanitizeDiagnosticValue(e.CommandPurpose),
		sanitizeDiagnosticValue(e.Repository),
		sanitizeDiagnosticValue(e.Ref),
		sanitizeDiagnosticValue(e.WorkflowPath),
		sanitizeDiagnosticValue(e.ObservationSource),
		e.RetryCount,
		sanitizeDiagnosticValue(e.FinalFailureClass),
		sanitizeDiagnosticValue(e.Detail),
	)
}

func (e *workflowDefinitionDiagnostic) Unwrap() error { return e.cause }

func (e *workflowDefinitionDiagnostic) ObservationDiagnostic() string { return e.Error() }

const (
	workflowDefinitionSourceDirect         = "direct lookup"
	workflowDefinitionSourceCheckRun       = "check-run"
	workflowDefinitionSourceCommitStatus   = "commit-status"
	workflowDefinitionFailureMalformedRef  = "malformed-ref"
	workflowDefinitionFailureUntrustedPath = "untrusted-path"
	workflowDefinitionFailureIncompatible  = "incompatible-identity"
	workflowDefinitionFailureRefAbsent     = "ref-absent"
	workflowDefinitionFailurePathAbsent    = "workflow-path-absent"
	workflowDefinitionFailurePersistent    = "persistent-ref-absence"
	workflowDefinitionFailureMalformedBlob = "malformed-blob"
	workflowDefinitionFailureCancellation  = "cancellation"
	workflowDefinitionFailureAuthorization = "authorization"
	workflowDefinitionFailureCommand       = "command-failure"
)

type remoteRepository struct {
	ID            string `json:"id"`
	NameWithOwner string `json:"nameWithOwner"`
}

type remotePullRequest struct {
	Number         int    `json:"number"`
	URL            string `json:"url"`
	State          string `json:"state"`
	BaseRefName    string `json:"baseRefName"`
	BaseRefOID     string `json:"baseRefOid"`
	HeadRefName    string `json:"headRefName"`
	HeadRefOID     string `json:"headRefOid"`
	HeadRepository struct {
		ID string `json:"id"`
	} `json:"headRepository"`
	ClosingIssuesReferences []struct {
		Number int    `json:"number"`
		ID     string `json:"id"`
	} `json:"closingIssuesReferences"`
	MergedAt    string `json:"mergedAt"`
	MergeCommit *struct {
		OID string `json:"oid"`
	} `json:"mergeCommit"`
}

type checkRunsResponse struct {
	CheckRuns []struct {
		Name       string `json:"name"`
		HeadSHA    string `json:"head_sha"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		DetailsURL string `json:"details_url"`
		App        struct {
			ID   int64  `json:"id"`
			Slug string `json:"slug"`
		} `json:"app"`
	} `json:"check_runs"`
}

type commitStatus struct {
	ID        int64  `json:"id"`
	Context   string `json:"context"`
	State     string `json:"state"`
	TargetURL string `json:"target_url"`
	Creator   struct {
		Login   string `json:"login"`
		ID      int64  `json:"id"`
		Type    string `json:"type"`
		HTMLURL string `json:"html_url"`
	} `json:"creator"`
}

type workflowRun struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	HeadSHA string `json:"head_sha"`
	HTMLURL string `json:"html_url"`
	Actor   struct {
		Login   string `json:"login"`
		ID      int64  `json:"id"`
		Type    string `json:"type"`
		HTMLURL string `json:"html_url"`
	} `json:"actor"`
}

type remoteRefResponse struct {
	Ref    string `json:"ref"`
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

const (
	checkRunsProjection    = `{check_runs:[.check_runs[]|{name,head_sha,status,conclusion,details_url,app:{id:.app.id,slug:.app.slug}}]}`
	statusesProjection     = `[.[]|{id,context,state,target_url,creator:{login:.creator.login,id:.creator.id,type:.creator.type,html_url:.creator.html_url}}]`
	workflowRunProjection  = `{id,name,path,head_sha,html_url,actor:{login:.actor.login,id:.actor.id,type:.actor.type,html_url:.actor.html_url}}`
	pullRequestsProjection = `[.[]|{number,url,state,baseRefName,baseRefOid,headRefName,headRefOid,headRepository:{id:.headRepository.id},closingIssuesReferences:[.closingIssuesReferences[]|{number,id}],mergedAt,mergeCommit:(if .mergeCommit==null then null else {oid:.mergeCommit.oid} end)}]`
	pullRequestProjection  = `{number,state,baseRefOid,headRefOid,closingIssuesReferences:[.closingIssuesReferences[]|{number,id}],mergedAt}`
	remoteRefsProjection   = `[.[]|{ref,object:{type:.object.type,sha:.object.sha}}]`
)

func (gateway productionNonLocalGateway) ObserveNonLocal(ctx context.Context, request issuedelivery.NonLocalObserveRequest) (issuedelivery.NonLocalObservation, error) {
	return gateway.observeNonLocal(ctx, request, true)
}

func (gateway productionNonLocalGateway) observeNonLocal(
	ctx context.Context,
	request issuedelivery.NonLocalObserveRequest,
	refreshTracking bool,
) (issuedelivery.NonLocalObservation, error) {
	if err := gateway.validateObserveRequest(ctx, request); err != nil {
		return issuedelivery.NonLocalObservation{}, err
	}
	repo := repositoryName(request.Repository)
	if refreshTracking {
		if _, err := gateway.output(
			ctx, "git", "fetch", "--prune", "--no-tags", "origin",
			"refs/heads/"+request.BaseRef+":refs/remotes/origin/"+request.BaseRef,
		); err != nil {
			return issuedelivery.NonLocalObservation{}, fmt.Errorf("refresh exact origin/%s: %w", request.BaseRef, err)
		}
	}
	branchHead, err := gateway.observeRemoteRef(ctx, repo, request.Branch)
	if err != nil {
		return issuedelivery.NonLocalObservation{}, fmt.Errorf("observe remote issue branch: %w", err)
	}
	baseHead, err := gateway.observeRemoteRef(ctx, repo, request.BaseRef)
	if err != nil {
		return issuedelivery.NonLocalObservation{}, fmt.Errorf("observe remote base branch: %w", err)
	}
	if baseHead == "" {
		return issuedelivery.NonLocalObservation{}, errors.New("remote base branch is absent")
	}
	if refreshTracking {
		trackingRaw, err := gateway.output(
			ctx, "git", "rev-parse", "refs/remotes/origin/"+request.BaseRef+"^{commit}",
		)
		if err != nil || strings.TrimSpace(string(trackingRaw)) != baseHead {
			return issuedelivery.NonLocalObservation{}, errors.New("refreshed origin base does not match remote observation")
		}
	}
	observation := issuedelivery.NonLocalObservation{
		PullRequests: []issuedelivery.RemotePullRequestObservation{},
		Checks:       []issuedelivery.CICheckObservation{},
	}
	if branchHead != "" {
		observation.Branch = &issuedelivery.RemoteBranchObservation{
			Name: request.Branch, HeadSHA: branchHead,
		}
	}

	prRaw, err := gateway.output(ctx, "gh", "pr", "list", "--repo", repo, "--state", "all",
		"--head", request.Branch, "--json",
		"number,url,state,baseRefName,baseRefOid,headRefName,headRefOid,headRepository,closingIssuesReferences,mergedAt,mergeCommit",
		"--jq", pullRequestsProjection)
	if err != nil {
		return issuedelivery.NonLocalObservation{}, fmt.Errorf("observe pull requests: %w", err)
	}
	var prs []remotePullRequest
	if err := exactJSON(prRaw, &prs); err != nil {
		return issuedelivery.NonLocalObservation{}, fmt.Errorf("decode pull requests: %w", err)
	}
	for _, pr := range prs {
		converted, err := convertPullRequest(pr, request)
		if err != nil {
			return issuedelivery.NonLocalObservation{}, err
		}
		observation.PullRequests = append(observation.PullRequests, converted)
		if pr.MergedAt != "" && pr.MergeCommit != nil {
			mergedAt, err := normalizeRemoteTimestamp(pr.MergedAt)
			if err != nil {
				return issuedelivery.NonLocalObservation{}, err
			}
			if observation.Merge != nil {
				return issuedelivery.NonLocalObservation{}, errors.New("multiple merged pull requests match the delivery branch")
			}
			observation.Merge = &issuedelivery.MergeObservation{
				PullRequest: pr.Number, URL: pr.URL, BaseRef: pr.BaseRefName,
				HeadSHA: pr.HeadRefOID, MergeCommitSHA: pr.MergeCommit.OID, MergedAt: mergedAt,
			}
		}
	}
	sort.Slice(observation.PullRequests, func(i, j int) bool {
		return observation.PullRequests[i].Number < observation.PullRequests[j].Number
	})
	if len(observation.PullRequests) > 0 {
		checks, err := gateway.observeChecksWithRefresh(ctx, request, baseHead, refreshTracking)
		if err != nil {
			return issuedelivery.NonLocalObservation{}, err
		}
		observation.Checks = checks
	}
	if observation.Merge != nil && refreshTracking {
		mainHead := baseHead
		mergeContained, err := gateway.containsOriginMain(ctx, observation.Merge.MergeCommitSHA)
		if err != nil {
			return issuedelivery.NonLocalObservation{}, err
		}
		headContained, err := gateway.containsOriginMain(ctx, request.HeadSHA)
		if err != nil {
			return issuedelivery.NonLocalObservation{}, err
		}
		observation.OriginMain = &issuedelivery.OriginMainObservation{
			HeadSHA: mainHead, MergeCommitSHA: observation.Merge.MergeCommitSHA,
			CandidateHeadSHA: request.HeadSHA, ContainsMergeCommit: mergeContained,
			ContainsCandidateHead: headContained,
		}
	}
	return observation, nil
}

func normalizeRemoteTimestamp(value string) (string, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "", errors.New("remote timestamp is malformed")
	}
	return parsed.UTC().Format("2006-01-02T15:04:05.000000000Z"), nil
}

func (gateway productionNonLocalGateway) PushIssueBranch(ctx context.Context, request issuedelivery.PushIssueBranchRequest) error {
	if err := gateway.validateRepository(ctx, request.Repository); err != nil {
		return err
	}
	if err := validBranchAndHead(request.Branch, request.HeadSHA); err != nil {
		return err
	}
	raw, err := gateway.output(ctx, "git", "ls-remote", "--refs", "origin", "refs/heads/"+request.Branch)
	if err != nil {
		return fmt.Errorf("observe issue branch before push: %w", err)
	}
	refs, err := parseRemoteRefs(raw)
	if err != nil {
		return err
	}
	if current := refs["refs/heads/"+request.Branch]; current != "" && current != request.HeadSHA {
		_, err = gateway.output(ctx, "git", "merge-base", "--is-ancestor", current, request.HeadSHA)
		if err != nil {
			return errors.New("remote issue branch is not an ancestor of the authorized candidate")
		}
	}
	_, err = gateway.output(ctx, "git", "push", "origin",
		request.HeadSHA+":refs/heads/"+request.Branch)
	if err != nil {
		return fmt.Errorf("push exact issue branch: %w", err)
	}
	return nil
}

func (gateway productionNonLocalGateway) EnsurePullRequest(ctx context.Context, request issuedelivery.EnsurePullRequestRequest) error {
	observe := issuedelivery.NonLocalObserveRequest{
		RunID: request.RunID, Repository: request.Repository, Issue: request.Issue,
		CandidateID: request.CandidateID, Branch: request.HeadBranch,
		BaseRef: request.BaseRef, HeadSHA: request.HeadSHA,
	}
	state, err := gateway.ObserveNonLocal(ctx, observe)
	if err != nil {
		return err
	}
	for _, pr := range state.PullRequests {
		if pr.HeadBranch == request.HeadBranch && pr.HeadSHA == request.HeadSHA &&
			pr.BaseRef == request.BaseRef && pr.ClosingIssue == request.Issue.Number {
			return nil
		}
		return errors.New("an incompatible pull request already owns the delivery branch")
	}
	_, err = gateway.output(ctx, "gh", "pr", "create", "--repo", repositoryName(request.Repository),
		"--base", request.BaseRef, "--head", request.HeadBranch,
		"--title", request.Title, "--body", request.Body)
	if err != nil {
		return fmt.Errorf("create exact pull request: %w", err)
	}
	return nil
}

func (gateway productionNonLocalGateway) RetryInfrastructureCheck(ctx context.Context, request issuedelivery.RetryInfrastructureCheckRequest) error {
	if err := gateway.validateRepository(ctx, request.Repository); err != nil {
		return err
	}
	if request.FailedRunID <= 0 || !validSHA(request.HeadSHA) {
		return errors.New("retry requires an exact failed run and candidate head")
	}
	run, err := gateway.workflowRun(ctx, request.Repository, request.FailedRunID)
	if err != nil {
		return err
	}
	if run.HeadSHA != request.HeadSHA || !trustedCheckIdentity(request.CheckIdentity, run.Name, run.Path) {
		return errors.New("failed workflow run identity is incompatible with the authorized retry")
	}
	_, err = gateway.output(ctx, "gh", "run", "rerun", strconv.FormatInt(request.FailedRunID, 10),
		"--repo", repositoryName(request.Repository), "--failed")
	if err != nil {
		return fmt.Errorf("retry failed infrastructure jobs: %w", err)
	}
	return nil
}

func (gateway productionNonLocalGateway) EnsureMerge(ctx context.Context, request issuedelivery.EnsureMergeRequest) error {
	if err := gateway.validateRepository(ctx, request.Repository); err != nil {
		return err
	}
	if request.Method != "merge" || request.PullRequest <= 0 || !validSHA(request.HeadSHA) || !validSHA(request.BaseSHA) {
		return errors.New("merge request has an incompatible exact identity or method")
	}
	raw, err := gateway.output(ctx, "gh", "pr", "view", strconv.Itoa(request.PullRequest),
		"--repo", repositoryName(request.Repository), "--json",
		"number,state,baseRefOid,headRefOid,closingIssuesReferences,mergedAt",
		"--jq", pullRequestProjection)
	if err != nil {
		return fmt.Errorf("observe pull request before merge: %w", err)
	}
	var pr remotePullRequest
	if err := exactJSON(raw, &pr); err != nil {
		return err
	}
	if pr.Number != request.PullRequest || pr.State != "OPEN" || pr.HeadRefOID != request.HeadSHA ||
		pr.BaseRefOID != request.BaseSHA || closingIssue(pr.ClosingIssuesReferences, request.Issue) == 0 {
		return errors.New("pull request changed before merge")
	}
	_, err = gateway.output(ctx, "gh", "pr", "merge", strconv.Itoa(request.PullRequest),
		"--repo", repositoryName(request.Repository), "--merge",
		"--match-head-commit", request.HeadSHA)
	if err != nil {
		return fmt.Errorf("merge exact pull request: %w", err)
	}
	return nil
}

func (gateway productionNonLocalGateway) EnsureRemoteIssueBranchAbsent(ctx context.Context, request issuedelivery.DeleteRemoteIssueBranchRequest) error {
	if err := gateway.validateRepository(ctx, request.Repository); err != nil {
		return err
	}
	if err := validBranchAndHead(request.Branch, request.HeadSHA); err != nil {
		return err
	}
	raw, err := gateway.output(ctx, "git", "ls-remote", "--refs", "origin", "refs/heads/"+request.Branch)
	if err != nil {
		return fmt.Errorf("observe issue branch before deletion: %w", err)
	}
	refs, err := parseRemoteRefs(raw)
	if err != nil {
		return err
	}
	if current := refs["refs/heads/"+request.Branch]; current == "" {
		return nil
	} else if current != request.HeadSHA {
		return errors.New("remote issue branch head is incompatible with authorized cleanup")
	}
	lease := "--force-with-lease=refs/heads/" + request.Branch + ":" + request.HeadSHA
	_, err = gateway.output(
		ctx, "git", "push", lease, "origin", ":refs/heads/"+request.Branch,
	)
	if err != nil {
		return fmt.Errorf("delete exact remote issue branch: %w", err)
	}
	return nil
}

func (gateway productionNonLocalGateway) observeChecks(
	ctx context.Context,
	request issuedelivery.NonLocalObserveRequest,
	baseSHA string,
) ([]issuedelivery.CICheckObservation, error) {
	return gateway.observeChecksWithRefresh(ctx, request, baseSHA, true)
}

func (gateway productionNonLocalGateway) observeChecksWithRefresh(
	ctx context.Context,
	request issuedelivery.NonLocalObserveRequest,
	baseSHA string,
	allowDefinitionRefRefresh bool,
) ([]issuedelivery.CICheckObservation, error) {
	repo := repositoryName(request.Repository)
	raw, err := gateway.output(ctx, "gh", "api", "-H", "Accept: application/vnd.github+json",
		"repos/"+repo+"/commits/"+request.HeadSHA+"/check-runs?filter=latest",
		"--jq", checkRunsProjection)
	if err != nil {
		return nil, fmt.Errorf("observe check runs: %w", err)
	}
	var runs checkRunsResponse
	if err := exactJSON(raw, &runs); err != nil {
		return nil, err
	}
	statusRaw, err := gateway.output(ctx, "gh", "api", "-H", "Accept: application/vnd.github+json",
		"repos/"+repo+"/commits/"+request.HeadSHA+"/statuses",
		"--jq", statusesProjection)
	if err != nil {
		return nil, fmt.Errorf("observe commit statuses: %w", err)
	}
	var statuses []commitStatus
	if err := exactJSON(statusRaw, &statuses); err != nil {
		return nil, err
	}
	var checks []issuedelivery.CICheckObservation
	for _, run := range runs.CheckRuns {
		if !isRequiredCheck(run.Name) {
			continue
		}
		runID, err := githubRunID(run.DetailsURL, request.Repository)
		if err != nil {
			return nil, err
		}
		workflow, err := gateway.workflowRun(ctx, request.Repository, runID)
		if err != nil {
			return nil, err
		}
		if err := validateObservedWorkflow(
			request.Repository, request.HeadSHA, workflow, run.Name, run.HeadSHA,
			workflowDefinitionSourceCheckRun,
		); err != nil {
			return nil, err
		}
		definitionSHA, err := gateway.definitionSHAForObservation(
			ctx, repositoryName(request.Repository), request.HeadSHA, workflow.Path,
			workflowDefinitionSourceCheckRun, allowDefinitionRefRefresh,
		)
		if err != nil {
			return nil, err
		}
		checks = append(checks, issuedelivery.CICheckObservation{
			RequiredCheck: deliveryevidence.RequiredCheck{
				Identity: run.Name, Conclusion: checkConclusion(run.Status, run.Conclusion), HeadSHA: run.HeadSHA,
			},
			StatusKind: issuedelivery.CIKindCheckRun,
			Publisher:  issuedelivery.TrustedPublisherEvidence{AppID: run.App.ID, Slug: run.App.Slug},
			Workflow: issuedelivery.CIWorkflowEvidence{
				Name: workflow.Name, Path: workflow.Path, RunID: runID,
				DefinitionRef: request.HeadSHA, DefinitionSHA: definitionSHA,
			},
			RunID: runID, DetailsURL: run.DetailsURL,
		})
	}
	status, found, err := latestCommitStatus(statuses, "Governance / Validate authorization")
	if err != nil {
		return nil, err
	}
	if found {
		runID, err := githubRunID(status.TargetURL, request.Repository)
		if err != nil {
			return nil, err
		}
		workflow, err := gateway.workflowRun(ctx, request.Repository, runID)
		if err != nil {
			return nil, err
		}
		if err := validateObservedWorkflow(
			request.Repository, baseSHA, workflow, status.Context, workflow.HeadSHA,
			workflowDefinitionSourceCommitStatus,
		); err != nil {
			return nil, err
		}
		definitionSHA, err := gateway.definitionSHAForObservation(
			ctx, repositoryName(request.Repository), baseSHA, workflow.Path,
			workflowDefinitionSourceCommitStatus, allowDefinitionRefRefresh,
		)
		if err != nil {
			return nil, err
		}
		checks = append(checks, issuedelivery.CICheckObservation{
			RequiredCheck: deliveryevidence.RequiredCheck{
				Identity: status.Context, Conclusion: statusConclusion(status.State), HeadSHA: request.HeadSHA,
			},
			StatusKind: issuedelivery.CIKindCommitStatus,
			Publisher: issuedelivery.TrustedPublisherEvidence{
				Login: status.Creator.Login, ID: status.Creator.ID,
				Type: status.Creator.Type, HTMLURL: status.Creator.HTMLURL,
			},
			Source: issuedelivery.TrustedPublisherEvidence{AppID: 15368, Slug: "github-actions"},
			Workflow: issuedelivery.CIWorkflowEvidence{
				Name: workflow.Name, Path: workflow.Path, RunID: runID,
				DefinitionRef: baseSHA, DefinitionSHA: definitionSHA,
			},
			RunID: runID, DetailsURL: status.TargetURL,
		})
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].Identity < checks[j].Identity })
	return applyCIFailureAttributions(checks, gateway.attributions)
}

func latestCommitStatus(statuses []commitStatus, identity string) (commitStatus, bool, error) {
	var latest commitStatus
	found := false
	for _, status := range statuses {
		if status.Context != identity {
			continue
		}
		if status.ID <= 0 {
			return commitStatus{}, false, errors.New("commit status has no stable identity")
		}
		if !found || status.ID > latest.ID {
			latest = status
			found = true
		}
	}
	return latest, found, nil
}

func applyCIFailureAttributions(
	checks []issuedelivery.CICheckObservation,
	attributions []advanceCIFailureAttribution,
) ([]issuedelivery.CICheckObservation, error) {
	applied := make(map[int]bool, len(attributions))
	for index := range checks {
		check := &checks[index]
		for decisionIndex, decision := range attributions {
			if decision.CheckIdentity != check.Identity || decision.RunID != check.RunID ||
				decision.HeadSHA != check.HeadSHA || decision.DetailsURL != check.DetailsURL {
				continue
			}
			if applied[decisionIndex] {
				return nil, errors.New("CI failure attribution matches more than one observed check")
			}
			conclusion := strings.ToLower(strings.TrimSpace(check.Conclusion))
			if conclusion != "failure" && conclusion != "failed" && conclusion != "cancelled" {
				return nil, errors.New("CI attribution applies only to an exact failed check")
			}
			if decision.Attribution != issuedelivery.FailureInfrastructure &&
				decision.Attribution != issuedelivery.FailureCandidate {
				return nil, errors.New("CI failure attribution must be infrastructure or candidate")
			}
			check.FailureAttribution = decision.Attribution
			applied[decisionIndex] = true
		}
	}
	for index := range attributions {
		if !applied[index] {
			return nil, errors.New("CI failure attribution does not match an exact observed failed run")
		}
	}
	return checks, nil
}

func (gateway productionNonLocalGateway) validateObserveRequest(ctx context.Context, request issuedelivery.NonLocalObserveRequest) error {
	if err := gateway.validateRepository(ctx, request.Repository); err != nil {
		return err
	}
	if request.Issue.Number <= 0 || request.Issue.NodeID == "" || request.BaseRef != "main" ||
		!strings.Contains(request.Branch, "issue-"+strconv.Itoa(request.Issue.Number)+"-") {
		return errors.New("non-local observation identity is incompatible with Packy delivery")
	}
	return validBranchAndHead(request.Branch, request.HeadSHA)
}

func (gateway productionNonLocalGateway) validateRepository(ctx context.Context, repository deliveryevidence.RepositoryIdentity) error {
	if gateway.runner == nil {
		return errors.New("non-local runner is required")
	}
	if repository.Owner != "yersonargotev" || repository.Name != "packy" || repository.NodeID == "" {
		return errors.New("non-local repository identity is not Packy")
	}
	raw, err := gateway.output(ctx, "gh", "repo", "view", repositoryName(repository),
		"--json", "id,nameWithOwner")
	if err != nil {
		return fmt.Errorf("observe repository identity: %w", err)
	}
	var observed remoteRepository
	if err := exactJSON(raw, &observed); err != nil {
		return err
	}
	if observed.ID != repository.NodeID || observed.NameWithOwner != repositoryName(repository) {
		return errors.New("observed repository identity is incompatible with Packy")
	}
	return nil
}

func (gateway productionNonLocalGateway) workflowRun(ctx context.Context, repository deliveryevidence.RepositoryIdentity, runID int64) (workflowRun, error) {
	raw, err := gateway.output(ctx, "gh", "api", "-H", "Accept: application/vnd.github+json",
		"repos/"+repositoryName(repository)+"/actions/runs/"+strconv.FormatInt(runID, 10),
		"--jq", workflowRunProjection)
	if err != nil {
		return workflowRun{}, fmt.Errorf("observe workflow run: %w", err)
	}
	var run workflowRun
	if err := exactJSON(raw, &run); err != nil {
		return workflowRun{}, err
	}
	if run.ID != runID {
		return workflowRun{}, errors.New("workflow run identity changed")
	}
	return run, nil
}

func (gateway productionNonLocalGateway) definitionSHA(ctx context.Context, ref, path string) (string, error) {
	return gateway.definitionSHAForObservation(
		ctx, "unknown repository", ref, path, workflowDefinitionSourceDirect, true,
	)
}

func (gateway productionNonLocalGateway) definitionSHAForObservation(
	ctx context.Context,
	repository string,
	ref string,
	path string,
	source string,
	allowRefRefresh bool,
) (string, error) {
	if !validSHA(ref) {
		return "", newWorkflowDefinitionDiagnostic(
			repository, ref, path, source, 0,
			workflowDefinitionFailureMalformedRef,
			"exact workflow definition ref is not a lowercase SHA",
			nil,
		)
	}
	if !trustedWorkflowPath(path) {
		return "", newWorkflowDefinitionDiagnostic(
			repository, ref, path, source, 0,
			workflowDefinitionFailureUntrustedPath,
			"workflow path is outside the trusted Packy workflow set",
			nil,
		)
	}

	lookup := func() ([]byte, error) {
		return gateway.output(ctx, "git", "rev-parse", ref+":"+path)
	}
	raw, err := lookup()
	if err == nil {
		return validateWorkflowDefinitionBlob(repository, ref, path, source, 0, raw)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", newWorkflowDefinitionDiagnostic(
			repository, ref, path, source, 0,
			workflowDefinitionFailureCancellation,
			"exact workflow definition lookup was cancelled",
			ctxErr,
		)
	}
	if !workflowDefinitionLookupNeedsRefProbe(err) {
		return "", workflowDefinitionCommandFailure(repository, ref, path, source, 0, err)
	}
	refPresent, probeErr := gateway.workflowDefinitionRefPresent(ctx, ref)
	if probeErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", newWorkflowDefinitionDiagnostic(
				repository, ref, path, source, 0,
				workflowDefinitionFailureCancellation,
				"exact workflow definition ref probe was cancelled",
				ctxErr,
			)
		}
		if !workflowDefinitionRefAbsent(probeErr) {
			return "", workflowDefinitionCommandFailure(repository, ref, path, source, 0, probeErr)
		}
	}
	if refPresent {
		return "", newWorkflowDefinitionDiagnostic(
			repository, ref, path, source, 0,
			workflowDefinitionFailurePathAbsent,
			"exact workflow definition path is absent from the locally available ref",
			err,
		)
	}
	if !allowRefRefresh {
		return "", newWorkflowDefinitionDiagnostic(
			repository, ref, path, source, 0,
			workflowDefinitionFailureRefAbsent,
			"exact workflow definition ref is not locally available for observation-only status",
			err,
		)
	}

	if _, err := gateway.output(ctx, "git", "fetch", "--quiet", "--no-tags", "origin", ref); err != nil {
		return "", workflowDefinitionCommandFailure(repository, ref, path, source, 1, err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", newWorkflowDefinitionDiagnostic(
			repository, ref, path, source, 1,
			workflowDefinitionFailureCancellation,
			"workflow definition ref refresh was cancelled",
			ctxErr,
		)
	}

	raw, err = lookup()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", newWorkflowDefinitionDiagnostic(
				repository, ref, path, source, 1,
				workflowDefinitionFailureCancellation,
				"exact workflow definition retry was cancelled",
				ctxErr,
			)
		}
		if !workflowDefinitionLookupNeedsRefProbe(err) {
			return "", workflowDefinitionCommandFailure(repository, ref, path, source, 1, err)
		}
		refPresent, probeErr := gateway.workflowDefinitionRefPresent(ctx, ref)
		if probeErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return "", newWorkflowDefinitionDiagnostic(
					repository, ref, path, source, 1,
					workflowDefinitionFailureCancellation,
					"exact workflow definition ref probe after retry was cancelled",
					ctxErr,
				)
			}
			if !workflowDefinitionRefAbsent(probeErr) {
				return "", workflowDefinitionCommandFailure(repository, ref, path, source, 1, probeErr)
			}
		}
		if refPresent {
			return "", newWorkflowDefinitionDiagnostic(
				repository, ref, path, source, 1,
				workflowDefinitionFailurePathAbsent,
				"exact workflow definition path is absent after the ref refresh",
				err,
			)
		}
		return "", newWorkflowDefinitionDiagnostic(
			repository, ref, path, source, 1,
			workflowDefinitionFailurePersistent,
			"exact workflow definition ref remained absent after one ref refresh",
			err,
		)
	}
	return validateWorkflowDefinitionBlob(repository, ref, path, source, 1, raw)
}

func (gateway productionNonLocalGateway) workflowDefinitionRefPresent(
	ctx context.Context,
	ref string,
) (bool, error) {
	_, err := gateway.output(ctx, "git", "cat-file", "-e", ref+"^{commit}")
	return err == nil, err
}

func validateWorkflowDefinitionBlob(
	repository string,
	ref string,
	path string,
	source string,
	retryCount int,
	raw []byte,
) (string, error) {
	sha := strings.TrimSpace(string(raw))
	if !validSHA(sha) {
		return "", newWorkflowDefinitionDiagnostic(
			repository, ref, path, source, retryCount,
			workflowDefinitionFailureMalformedBlob,
			"workflow definition blob identity is malformed",
			nil,
		)
	}
	return sha, nil
}

func validateObservedWorkflow(
	repository deliveryevidence.RepositoryIdentity,
	ref string,
	workflow workflowRun,
	identity string,
	observedHead string,
	source string,
) error {
	if trustedCheckIdentity(identity, workflow.Name, workflow.Path) &&
		validSHA(observedHead) && observedHead == ref &&
		validSHA(workflow.HeadSHA) && workflow.HeadSHA == ref {
		return nil
	}
	return newWorkflowDefinitionDiagnostic(
		repositoryName(repository), ref, workflow.Path, source, 0,
		workflowDefinitionFailureIncompatible,
		"observed workflow or check-run identity is incompatible with the required check",
		nil,
	)
}

func workflowDefinitionCommandFailure(
	repository string,
	ref string,
	path string,
	source string,
	retryCount int,
	err error,
) error {
	failureClass := workflowDefinitionFailureCommand
	detail := "exact workflow definition command failed"
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		failureClass = workflowDefinitionFailureCancellation
		detail = "exact workflow definition command was cancelled"
	} else if workflowDefinitionAuthorizationFailure(err) {
		failureClass = workflowDefinitionFailureAuthorization
		detail = "exact workflow definition ref refresh was not authorized"
	}
	return newWorkflowDefinitionDiagnostic(
		repository, ref, path, source, retryCount, failureClass, detail, err,
	)
}

func newWorkflowDefinitionDiagnostic(
	repository string,
	ref string,
	path string,
	source string,
	retryCount int,
	failureClass string,
	detail string,
	cause error,
) error {
	return &workflowDefinitionDiagnostic{
		CommandPurpose:    "resolve exact workflow definition",
		Repository:        repository,
		Ref:               ref,
		WorkflowPath:      path,
		ObservationSource: source,
		RetryCount:        retryCount,
		FinalFailureClass: failureClass,
		Detail:            detail,
		cause:             cause,
	}
}

func workflowDefinitionRefAbsent(err error) bool {
	message := workflowDefinitionErrorText(err)
	for _, marker := range []string{
		"unknown revision",
		"invalid object name",
		"bad object",
		"not a valid object name",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func workflowDefinitionLookupNeedsRefProbe(err error) bool {
	if workflowDefinitionRefAbsent(err) {
		return true
	}
	message := workflowDefinitionErrorText(err)
	for _, marker := range []string{
		"does not exist in",
		"exists on disk, but not in",
		"ambiguous argument",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func workflowDefinitionAuthorizationFailure(err error) bool {
	message := workflowDefinitionErrorText(err)
	for _, marker := range []string{
		"authentication failed",
		"authorization failed",
		"not authorized",
		"unauthorized",
		"permission denied",
		"access denied",
		"could not read username",
		"http 401",
		"http 403",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func workflowDefinitionErrorText(err error) string {
	parts := []string{err.Error()}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		parts = append(parts, string(exitError.Stderr))
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func sanitizeDiagnosticValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 {
			return '_'
		}
		return r
	}, value)
	if len(value) > 200 {
		return value[:200] + "..."
	}
	return value
}

func (gateway productionNonLocalGateway) containsOriginMain(ctx context.Context, sha string) (bool, error) {
	raw, err := gateway.output(ctx, "git", "branch", "-r", "--contains", sha, "--format=%(refname:short)")
	if err != nil {
		return false, fmt.Errorf("observe origin/main containment: %w", err)
	}
	for _, ref := range strings.Fields(string(raw)) {
		if ref == "origin/main" {
			return true, nil
		}
	}
	return false, nil
}

func (gateway productionNonLocalGateway) output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "git" && gateway.repository != "" {
		args = append([]string{"-C", gateway.repository}, args...)
	}
	output, err := gateway.runner.Output(ctx, name, args...)
	if err != nil {
		return output, &remoteCommandError{err: err}
	}
	return output, nil
}

func (gateway productionNonLocalGateway) observeRemoteRef(
	ctx context.Context,
	repository string,
	branch string,
) (string, error) {
	raw, err := gateway.output(
		ctx,
		"gh",
		"api",
		"repos/"+repository+"/git/matching-refs/heads/"+branch,
		"--jq",
		remoteRefsProjection,
	)
	if err != nil {
		return "", err
	}
	var observed []remoteRefResponse
	if err := exactJSON(raw, &observed); err != nil {
		return "", fmt.Errorf("decode remote refs: %w", err)
	}
	exact := "refs/heads/" + branch
	head := ""
	for _, ref := range observed {
		if ref.Ref != exact {
			continue
		}
		if head != "" || ref.Object.Type != "commit" || !validSHA(ref.Object.SHA) {
			return "", errors.New("remote branch identity is ambiguous or invalid")
		}
		head = ref.Object.SHA
	}
	return head, nil
}

func exactJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return &remoteDecodeError{err: err}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("command output contains more than one JSON value")
		}
		return &remoteDecodeError{err: err}
	}
	return nil
}

func parseRemoteRefs(raw []byte) (map[string]string, error) {
	refs := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !validSHA(fields[0]) || !strings.HasPrefix(fields[1], "refs/heads/") {
			return nil, errors.New("remote ref observation is malformed")
		}
		if _, duplicate := refs[fields[1]]; duplicate {
			return nil, errors.New("remote ref observation is ambiguous")
		}
		refs[fields[1]] = fields[0]
	}
	return refs, nil
}

func convertPullRequest(pr remotePullRequest, request issuedelivery.NonLocalObserveRequest) (issuedelivery.RemotePullRequestObservation, error) {
	if pr.Number <= 0 || !safeGitHubURL(pr.URL, request.Repository, "pull", pr.Number) ||
		!validSHA(pr.BaseRefOID) || !validSHA(pr.HeadRefOID) || pr.HeadRepository.ID == "" {
		return issuedelivery.RemotePullRequestObservation{}, errors.New("pull-request observation has an unsafe identity")
	}
	return issuedelivery.RemotePullRequestObservation{
		Number: pr.Number, URL: pr.URL, State: pr.State, BaseRef: pr.BaseRefName,
		BaseSHA: pr.BaseRefOID, HeadBranch: pr.HeadRefName, HeadSHA: pr.HeadRefOID,
		HeadRepositoryNodeID: pr.HeadRepository.ID,
		ClosingIssue:         closingIssue(pr.ClosingIssuesReferences, request.Issue),
	}, nil
}

func closingIssue(values []struct {
	Number int    `json:"number"`
	ID     string `json:"id"`
}, issue deliveryevidence.IssueIdentity) int {
	for _, value := range values {
		if value.Number == issue.Number && value.ID == issue.NodeID {
			return value.Number
		}
	}
	return 0
}

func githubRunID(value string, repository deliveryevidence.RepositoryIdentity) (int64, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return 0, errors.New("workflow run URL is unsafe")
	}
	prefix := "/" + repositoryName(repository) + "/actions/runs/"
	tail := strings.TrimPrefix(parsed.Path, prefix)
	if tail == parsed.Path {
		return 0, errors.New("workflow run URL has a foreign repository")
	}
	idText := strings.Split(tail, "/")[0]
	runID, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || runID <= 0 {
		return 0, errors.New("workflow run URL has no exact run identity")
	}
	return runID, nil
}

func checkConclusion(status, conclusion string) string {
	if strings.EqualFold(status, "completed") {
		return strings.ToLower(conclusion)
	}
	return ""
}

func statusConclusion(state string) string {
	if strings.EqualFold(state, "pending") {
		return ""
	}
	if strings.EqualFold(state, "error") {
		return "failure"
	}
	return strings.ToLower(state)
}

func trustedCheckIdentity(identity, workflowName, workflowPath string) bool {
	switch identity {
	case "Validate Packy-owned code", "Claude 2.1.203 package smoke":
		return workflowName == "CI" && workflowPath == ".github/workflows/ci.yml"
	case "Governance / Validate authorization":
		return workflowName == "Governance" && workflowPath == ".github/workflows/governance.yml"
	case "CodeQL":
		return workflowName == "Security" && workflowPath == ".github/workflows/security-pr.yml"
	default:
		return false
	}
}

func isRequiredCheck(identity string) bool {
	return trustedCheckIdentity(identity, "CI", ".github/workflows/ci.yml") ||
		trustedCheckIdentity(identity, "Security", ".github/workflows/security-pr.yml")
}

func trustedWorkflowPath(path string) bool {
	return path == ".github/workflows/ci.yml" ||
		path == ".github/workflows/governance.yml" ||
		path == ".github/workflows/security-pr.yml"
}

func validBranchAndHead(branch, head string) error {
	if !validSHA(head) || strings.TrimSpace(branch) != branch || branch == "" ||
		strings.HasPrefix(branch, "-") || strings.ContainsAny(branch, " \t\r\n~^:?*[\\") ||
		strings.Contains(branch, "..") || strings.Contains(branch, "@{") {
		return errors.New("branch or candidate head identity is unsafe")
	}
	return nil
}

func validSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func safeGitHubURL(value string, repository deliveryevidence.RepositoryIdentity, kind string, number int) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host == "github.com" &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.Path == fmt.Sprintf("/%s/%s/%d", repositoryName(repository), kind, number)
}

func repositoryName(repository deliveryevidence.RepositoryIdentity) string {
	return repository.Owner + "/" + repository.Name
}
