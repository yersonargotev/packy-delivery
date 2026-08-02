package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

const governanceProcessHelperEnvironment = "PACKY_GOVERNANCE_PROCESS_HELPER"

type governanceProcessRemote struct {
	*commandCompletionRemote
	runner *fakeRemoteRunner
}

func (remote *governanceProcessRemote) EnsurePullRequest(
	ctx context.Context,
	request issuedelivery.EnsurePullRequestRequest,
) error {
	if request.PullRequest > 0 {
		for index := range remote.observation.PullRequests {
			if remote.observation.PullRequests[index].Number == request.PullRequest {
				remote.observation.PullRequests[index].DeliveryProfiles = []string{request.DeliveryProfile}
				return nil
			}
		}
		return errors.New("pull request is not observable")
	}
	observation, err := (productionNonLocalGateway{runner: remote.runner}).ObserveNonLocal(
		ctx,
		issuedelivery.NonLocalObserveRequest{
			RunID: request.RunID, Repository: request.Repository, Issue: request.Issue,
			CandidateID: request.CandidateID, Branch: request.HeadBranch,
			BaseRef: request.BaseRef, HeadSHA: request.HeadSHA,
		},
	)
	if err != nil {
		return err
	}
	remote.observation = observation
	return nil
}

type governanceProcessResult struct {
	Report         advanceReport `json:"report"`
	ObservationOps []string      `json:"observation_ops"`
}

func TestAdvanceProcessReachesMergeWithCandidateHeadedPullRequestTargetGovernance(t *testing.T) {
	if os.Getenv(governanceProcessHelperEnvironment) != "" {
		runGovernanceProcessHelper(t)
		return
	}

	sandbox := t.TempDir()
	home := filepath.Join(sandbox, "home")
	config := filepath.Join(sandbox, "config")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(config, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestAdvanceProcessReachesMergeWithCandidateHeadedPullRequestTargetGovernance$")
	command.Env = replacedEnvironment(os.Environ(), map[string]string{
		governanceProcessHelperEnvironment: "1",
		"HOME":                             home,
		"XDG_CONFIG_HOME":                  config,
	})
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Governance process helper: %v\n%s", err, output)
	}
	var result governanceProcessResult
	if err := json.NewDecoder(bytes.NewReader(output)).Decode(&result); err != nil {
		t.Fatalf("decode Governance process result: %v\n%s", err, output)
	}
	if result.Report.NonLocal == nil || result.Report.NonLocal.Merge == nil {
		t.Fatalf("ordinary Packy CI did not reach an adopted merge: %#v", result.Report)
	}
	for _, operation := range result.ObservationOps {
		for _, forbidden := range []string{"issue comment", "issue edit", "--add-label", " status create"} {
			if strings.Contains(operation, forbidden) {
				t.Fatalf("Governance observation required operator side effect %q", operation)
			}
		}
	}
}

func runGovernanceProcessHelper(t *testing.T) {
	local := &commandCompletionLocal{}
	baseRemote := &commandCompletionRemote{
		local: local,
		observation: issuedelivery.NonLocalObservation{
			PullRequests: []issuedelivery.RemotePullRequestObservation{},
			Checks:       []issuedelivery.CICheckObservation{},
		},
	}
	remote := &governanceProcessRemote{commandCompletionRemote: baseRemote}
	module, ready, repository, tracker, clock := productionReadyModule(t, remote, local, nil, "")
	baseRemote.tracker = tracker
	baseRemote.clock = clock
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
	remote.runner = successfulPackyCIRunner(
		ready.Candidate.CommitSHA, strings.Repeat("a", 40), ready.LocalReadiness.Branch,
	)
	cmd := command{
		Now: clock.Now,
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
			return module, nil
		},
	}
	report := runAdvanceCommandReport(t, cmd, repository, "--authorize-non-local")
	for attempts := 0; attempts < 8 && (report.NonLocal == nil || report.NonLocal.Merge == nil); attempts++ {
		report = runAdvanceCommandReport(t, cmd, repository)
	}
	operations := make([]string, 0, len(remote.runner.calls))
	for _, call := range remote.runner.calls {
		operations = append(operations, call.name+" "+strings.Join(call.args, " "))
	}
	if err := json.NewEncoder(os.Stdout).Encode(governanceProcessResult{
		Report: report, ObservationOps: operations,
	}); err != nil {
		t.Fatal(err)
	}
}

func successfulPackyCIRunner(head, base, branch string) *fakeRemoteRunner {
	definition := strings.Repeat("e", 40)
	workflow := func(id int, name, path string) []byte {
		return []byte(`{"id":` + string(rune('0'+id)) + `,"name":"` + name + `","path":"` + path + `","head_sha":"` + head + `","html_url":"https://github.com/yersonargotev/packy/actions/runs/` + string(rune('0'+id)) + `","actor":{"login":"maintainer","id":1,"type":"User","html_url":"https://github.com/maintainer"}}`)
	}
	governance := []byte(candidateHeadedGovernanceWorkflow(4, head, base))
	return &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"id":"R1","nameWithOwner":"yersonargotev/packy"}`),
		nil,
		remoteRefFixture(branch, head),
		remoteRefFixture("main", base),
		[]byte(base + "\n"),
		[]byte(`[{"number":17,"url":"https://github.com/yersonargotev/packy/pull/17","state":"OPEN","baseRefName":"main","baseRefOid":"` + base + `","headRefName":"` + branch + `","headRefOid":"` + head + `","headRepository":{"id":"R1"},"closingIssuesReferences":[{"number":361,"id":"I361"}],"mergedAt":"","mergeCommit":null}]`),
		[]byte(`{"check_runs":[{"name":"Validate Packy-owned code","head_sha":"` + head + `","status":"completed","conclusion":"success","details_url":"https://github.com/yersonargotev/packy/actions/runs/1","app":{"id":15368,"slug":"github-actions"}},{"name":"Claude 2.1.203 package smoke","head_sha":"` + head + `","status":"completed","conclusion":"success","details_url":"https://github.com/yersonargotev/packy/actions/runs/2","app":{"id":15368,"slug":"github-actions"}},{"name":"CodeQL","head_sha":"` + head + `","status":"completed","conclusion":"success","details_url":"https://github.com/yersonargotev/packy/actions/runs/3","app":{"id":15368,"slug":"github-actions"}}]}`),
		[]byte(`[{"id":7,"context":"Governance / Validate authorization","state":"success","target_url":"https://github.com/yersonargotev/packy/actions/runs/4","creator":{"login":"github-actions[bot]","id":41898282,"type":"Bot","html_url":"https://github.com/apps/github-actions"}}]`),
		workflow(1, "CI", ".github/workflows/ci.yml"), []byte(definition + "\n"),
		workflow(2, "CI", ".github/workflows/ci.yml"), []byte(definition + "\n"),
		workflow(3, "Security", ".github/workflows/security-pr.yml"), []byte(definition + "\n"),
		governance, []byte(definition + "\n"),
	}}
}
