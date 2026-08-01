package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type remoteRunnerCall struct {
	name string
	args []string
}

type fakeRemoteRunner struct {
	outputs [][]byte
	errs    []error
	calls   []remoteRunnerCall
}

func (runner *fakeRemoteRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	runner.calls = append(runner.calls, remoteRunnerCall{name: name, args: append([]string(nil), args...)})
	index := len(runner.calls) - 1
	if index >= len(runner.outputs) {
		return nil, errors.New("unexpected command")
	}
	var err error
	if index < len(runner.errs) {
		err = runner.errs[index]
	}
	return runner.outputs[index], err
}

func TestProductionNonLocalPushObservesThenUsesExactRefspec(t *testing.T) {
	head := strings.Repeat("b", 40)
	runner := &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"id":"R1","nameWithOwner":"yersonargotev/packy"}`),
		nil,
		nil,
	}}
	gateway := productionNonLocalGateway{runner: runner}
	err := gateway.PushIssueBranch(context.Background(), issuedelivery.PushIssueBranchRequest{
		Repository: packyRemoteRepository(), Branch: "chore/issue-361-remote-adapter", HeadSHA: head,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []remoteRunnerCall{
		{name: "gh", args: []string{"repo", "view", "yersonargotev/packy", "--json", "id,nameWithOwner"}},
		{name: "git", args: []string{"ls-remote", "--refs", "origin", "refs/heads/chore/issue-361-remote-adapter"}},
		{name: "git", args: []string{"push", "origin", head + ":refs/heads/chore/issue-361-remote-adapter"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("commands differ\n got: %#v\nwant: %#v", runner.calls, want)
	}
}

func TestProductionNonLocalObservationRefreshesAndBindsOriginMain(t *testing.T) {
	head, main := strings.Repeat("b", 40), strings.Repeat("a", 40)
	runner := &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"id":"R1","nameWithOwner":"yersonargotev/packy"}`),
		nil,
		remoteRefFixture("chore/issue-361-remote-adapter", head),
		remoteRefFixture("main", main),
		[]byte(main + "\n"),
		[]byte(`[]`),
	}}
	gateway := productionNonLocalGateway{runner: runner}
	observation, err := gateway.ObserveNonLocal(
		context.Background(),
		issuedelivery.NonLocalObserveRequest{
			Repository: packyRemoteRepository(),
			Issue:      deliveryevidence.IssueIdentity{Number: 361, NodeID: "I361"},
			Branch:     "chore/issue-361-remote-adapter", BaseRef: "main", HeadSHA: head,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Branch == nil || observation.Branch.HeadSHA != head {
		t.Fatalf("remote observation = %#v", observation)
	}
	if got := runner.calls[1]; got.name != "git" || !reflect.DeepEqual(got.args, []string{
		"fetch", "--prune", "--no-tags", "origin",
		"refs/heads/main:refs/remotes/origin/main",
	}) {
		t.Fatalf("origin/main refresh = %#v", got)
	}
	if got := runner.calls[5]; got.name != "gh" || !reflect.DeepEqual(got.args, []string{
		"pr", "list", "--repo", "yersonargotev/packy", "--state", "all",
		"--head", "chore/issue-361-remote-adapter", "--json",
		"number,url,state,baseRefName,baseRefOid,headRefName,headRefOid,headRepository,closingIssuesReferences,mergedAt,mergeCommit",
		"--jq", pullRequestsProjection,
	}) {
		t.Fatalf("pull-request observation command = %#v", got)
	}
}

func TestProductionStatusNonLocalObservationUsesOnlyReadCommands(t *testing.T) {
	head, main := strings.Repeat("b", 40), strings.Repeat("a", 40)
	runner := &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"id":"R1","nameWithOwner":"yersonargotev/packy"}`),
		remoteRefFixture("chore/issue-361-remote-adapter", head),
		remoteRefFixture("main", main),
		[]byte(`[]`),
	}}
	observer := productionStatusNonLocalObserver{
		gateway: productionNonLocalGateway{runner: runner, repository: "/packy"},
	}
	observation, err := observer.ObserveNonLocal(
		context.Background(),
		issuedelivery.NonLocalObserveRequest{
			Repository: packyRemoteRepository(),
			Issue:      deliveryevidence.IssueIdentity{Number: 361, NodeID: "I361"},
			Branch:     "chore/issue-361-remote-adapter", BaseRef: "main", HeadSHA: head,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Branch == nil || observation.Branch.HeadSHA != head ||
		observation.PullRequests == nil || observation.Checks == nil {
		t.Fatalf("observation=%#v", observation)
	}
	for _, call := range runner.calls {
		command := call.name + " " + strings.Join(call.args, " ")
		for _, forbidden := range []string{
			"git fetch", "git push", "gh pr create", "gh pr merge", "gh run rerun",
		} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("status observation used mutation command %q", command)
			}
		}
	}
}

func TestProductionStatusNonLocalObservationClassifiesCommandFailureAsTransient(t *testing.T) {
	runner := &fakeRemoteRunner{
		outputs: [][]byte{nil},
		errs:    []error{errors.New("temporary transport failure")},
	}
	observer := productionStatusNonLocalObserver{
		gateway: productionNonLocalGateway{runner: runner},
	}
	_, err := observer.ObserveNonLocal(
		context.Background(),
		issuedelivery.NonLocalObserveRequest{
			Repository: packyRemoteRepository(),
			Issue:      deliveryevidence.IssueIdentity{Number: 361, NodeID: "I361"},
			Branch:     "chore/issue-361-remote-adapter",
			BaseRef:    "main",
			HeadSHA:    strings.Repeat("b", 40),
		},
	)
	class, transient, ok := issuedelivery.StatusErrorDetails(err)
	if !ok || class != issuedelivery.StatusErrorExternalRead || !transient {
		t.Fatalf("error=%T %v class=%q transient=%t", err, err, class, transient)
	}
}

func TestProductionStatusNonLocalObservationClassifiesRejectedIdentityReadAsPermanent(t *testing.T) {
	runner := &fakeRemoteRunner{
		outputs: [][]byte{nil},
		errs: []error{&commandRejectedError{
			err: errors.New("GitHub rejected the command"),
		}},
	}
	observer := productionStatusNonLocalObserver{
		gateway: productionNonLocalGateway{runner: runner},
	}
	_, err := observer.ObserveNonLocal(
		context.Background(),
		issuedelivery.NonLocalObserveRequest{
			Repository: packyRemoteRepository(),
			Issue:      deliveryevidence.IssueIdentity{Number: 361, NodeID: "I361"},
			Branch:     "chore/issue-361-remote-adapter",
			BaseRef:    "main",
			HeadSHA:    strings.Repeat("b", 40),
		},
	)
	class, transient, ok := issuedelivery.StatusErrorDetails(err)
	if !ok || class != issuedelivery.StatusErrorIdentity || transient {
		t.Fatalf("error=%T %v class=%q transient=%t", err, err, class, transient)
	}
}

func TestProductionStatusNonLocalObservationClassifiesInvalidIdentityAsPermanent(t *testing.T) {
	runner := &fakeRemoteRunner{
		outputs: [][]byte{[]byte(`{"id":"unexpected","nameWithOwner":"another/repository"}`)},
	}
	observer := productionStatusNonLocalObserver{
		gateway: productionNonLocalGateway{runner: runner},
	}
	_, err := observer.ObserveNonLocal(
		context.Background(),
		issuedelivery.NonLocalObserveRequest{
			Repository: packyRemoteRepository(),
			Issue:      deliveryevidence.IssueIdentity{Number: 361, NodeID: "I361"},
			Branch:     "chore/issue-361-remote-adapter",
			BaseRef:    "main",
			HeadSHA:    strings.Repeat("b", 40),
		},
	)
	class, transient, ok := issuedelivery.StatusErrorDetails(err)
	if !ok || class != issuedelivery.StatusErrorIdentity || transient {
		t.Fatalf("error=%T %v class=%q transient=%t", err, err, class, transient)
	}
}

func TestProductionStatusNonLocalObservationClassifiesMalformedJSONAsCorruption(t *testing.T) {
	head, main := strings.Repeat("b", 40), strings.Repeat("a", 40)
	runner := &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"id":"R1","nameWithOwner":"yersonargotev/packy"}`),
		remoteRefFixture("chore/issue-361-remote-adapter", head),
		remoteRefFixture("main", main),
		[]byte(`[{"number":`),
	}}
	observer := productionStatusNonLocalObserver{
		gateway: productionNonLocalGateway{runner: runner},
	}
	_, err := observer.ObserveNonLocal(
		context.Background(),
		issuedelivery.NonLocalObserveRequest{
			Repository: packyRemoteRepository(),
			Issue:      deliveryevidence.IssueIdentity{Number: 361, NodeID: "I361"},
			Branch:     "chore/issue-361-remote-adapter",
			BaseRef:    "main",
			HeadSHA:    head,
		},
	)
	class, transient, ok := issuedelivery.StatusErrorDetails(err)
	if !ok || class != issuedelivery.StatusErrorCorruption || transient {
		t.Fatalf("error=%T %v class=%q transient=%t", err, err, class, transient)
	}
}

func remoteRefFixture(branch string, sha string) []byte {
	return []byte(
		`[{"ref":"refs/heads/` + branch +
			`","object":{"type":"commit","sha":"` + sha + `"}}]`,
	)
}

func TestProductionNonLocalChecksProjectGitHubResponsesBeforeStrictDecode(t *testing.T) {
	head, base := strings.Repeat("b", 40), strings.Repeat("a", 40)
	runner := &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"check_runs":[{"name":"Validate Packy-owned code","head_sha":"` + head + `","status":"completed","conclusion":"success","details_url":"https://github.com/yersonargotev/packy/actions/runs/42/job/7","app":{"id":15368,"slug":"github-actions"}}]}`),
		[]byte(`[]`),
		[]byte(`{"id":42,"name":"CI","path":".github/workflows/ci.yml","head_sha":"` + head + `","html_url":"https://github.com/yersonargotev/packy/actions/runs/42","actor":{"login":"maintainer","id":1,"type":"User","html_url":"https://github.com/maintainer"}}`),
		[]byte(head),
	}}
	gateway := productionNonLocalGateway{runner: runner}
	checks, err := gateway.observeChecks(context.Background(), issuedelivery.NonLocalObserveRequest{
		Repository: packyRemoteRepository(), HeadSHA: head,
	}, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || checks[0].Identity != "Validate Packy-owned code" {
		t.Fatalf("checks = %#v", checks)
	}
	if got := runner.calls[0]; got.name != "gh" || !reflect.DeepEqual(got.args, []string{
		"api", "-H", "Accept: application/vnd.github+json",
		"repos/yersonargotev/packy/commits/" + head + "/check-runs?filter=latest",
		"--jq", checkRunsProjection,
	}) {
		t.Fatalf("check-runs command = %#v", got)
	}
	if got := runner.calls[1]; got.name != "gh" || !reflect.DeepEqual(got.args, []string{
		"api", "-H", "Accept: application/vnd.github+json",
		"repos/yersonargotev/packy/commits/" + head + "/statuses",
		"--jq", statusesProjection,
	}) {
		t.Fatalf("statuses command = %#v", got)
	}
	if got := runner.calls[2]; got.name != "gh" || !reflect.DeepEqual(got.args, []string{
		"api", "-H", "Accept: application/vnd.github+json",
		"repos/yersonargotev/packy/actions/runs/42",
		"--jq", workflowRunProjection,
	}) {
		t.Fatalf("workflow command = %#v", got)
	}
}

func TestWorkflowDefinitionSHARefreshesExactRefOnce(t *testing.T) {
	ref, blob := strings.Repeat("a", 40), strings.Repeat("b", 40)
	path := ".github/workflows/ci.yml"
	runner := &fakeRemoteRunner{
		outputs: [][]byte{nil, nil, nil, []byte(blob + "\n")},
		errs: []error{
			errors.New("fatal: invalid object name '" + ref + "'."),
			errors.New("fatal: Not a valid object name " + ref + "^{commit}"),
		},
	}
	gateway := productionNonLocalGateway{runner: runner}

	got, err := gateway.definitionSHAForObservation(
		context.Background(), "yersonargotev/packy", ref, path,
		workflowDefinitionSourceCheckRun, true,
	)
	if err != nil || got != blob {
		t.Fatalf("definition SHA = %q, err=%v; want %q", got, err, blob)
	}
	want := []remoteRunnerCall{
		{name: "git", args: []string{"rev-parse", ref + ":" + path}},
		{name: "git", args: []string{"cat-file", "-e", ref + "^{commit}"}},
		{name: "git", args: []string{"fetch", "--quiet", "--no-tags", "origin", ref}},
		{name: "git", args: []string{"rev-parse", ref + ":" + path}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("workflow-definition recovery commands differ\n got: %#v\nwant: %#v", runner.calls, want)
	}
}

func TestWorkflowDefinitionSHAReportsPersistentAbsenceWithoutSecondRefresh(t *testing.T) {
	ref := strings.Repeat("a", 40)
	path := ".github/workflows/governance.yml"
	missing := errors.New("fatal: invalid object name '" + ref + "'.")
	missingProbe := errors.New("fatal: Not a valid object name " + ref + "^{commit}")
	runner := &fakeRemoteRunner{
		outputs: [][]byte{nil, nil, nil, nil, nil},
		errs:    []error{missing, missingProbe, nil, missing, missingProbe},
	}
	gateway := productionNonLocalGateway{runner: runner}

	_, err := gateway.definitionSHAForObservation(
		context.Background(), "yersonargotev/packy", ref, path,
		workflowDefinitionSourceCommitStatus, true,
	)
	var diagnostic *workflowDefinitionDiagnostic
	if !errors.As(err, &diagnostic) || diagnostic.RetryCount != 1 ||
		diagnostic.FinalFailureClass != workflowDefinitionFailurePersistent {
		t.Fatalf("diagnostic = %#v, err=%v", diagnostic, err)
	}
	structured := diagnostic.ObservationDiagnostic()
	if structured.Kind != issuedelivery.ObservationDiagnosticWorkflowDefinition ||
		structured.CommandPurpose != "resolve exact workflow definition" ||
		structured.Repository != "yersonargotev/packy" || structured.Ref != ref ||
		structured.WorkflowPath != path ||
		structured.ObservationSource != issuedelivery.ObservationSourceCommitStatus ||
		structured.RetryCount != 1 ||
		structured.FinalFailureClass != issuedelivery.WorkflowDefinitionFailurePersistent {
		t.Fatalf("structured diagnostic = %#v", structured)
	}
	for _, expected := range []string{
		`command purpose="resolve exact workflow definition"`,
		`repository="yersonargotev/packy"`,
		`ref="` + ref + `"`,
		`workflow path="` + path + `"`,
		`observation source="commit-status"`,
		`retry count=1`,
		`final failure class="persistent-ref-absence"`,
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("diagnostic %q missing from %v", expected, err)
		}
	}
	if len(runner.calls) != 5 || runner.calls[2].name != "git" ||
		!reflect.DeepEqual(runner.calls[2].args, []string{"fetch", "--quiet", "--no-tags", "origin", ref}) {
		t.Fatalf("unexpected bounded recovery commands: %#v", runner.calls)
	}
	if !reflect.DeepEqual(runner.calls[0], runner.calls[3]) {
		t.Fatalf("retry changed the exact lookup: %#v", runner.calls)
	}
}

func TestStatusWorkflowDefinitionObservationDoesNotRefreshAbsentRef(t *testing.T) {
	ref := strings.Repeat("a", 40)
	runner := &fakeRemoteRunner{
		outputs: [][]byte{nil, nil},
		errs: []error{
			errors.New("fatal: invalid object name '" + ref + "'."),
			errors.New("fatal: Not a valid object name " + ref + "^{commit}"),
		},
	}
	gateway := productionNonLocalGateway{runner: runner}

	_, err := gateway.definitionSHAForObservation(
		context.Background(), "yersonargotev/packy", ref, ".github/workflows/ci.yml",
		workflowDefinitionSourceCheckRun, false,
	)
	var diagnostic *workflowDefinitionDiagnostic
	if !errors.As(err, &diagnostic) || diagnostic.FinalFailureClass != workflowDefinitionFailureRefAbsent ||
		diagnostic.RetryCount != 0 || len(runner.calls) != 2 {
		t.Fatalf("status ref observation refreshed or misclassified absence: diagnostic=%#v err=%v calls=%#v", diagnostic, err, runner.calls)
	}
}

func TestWorkflowDefinitionSHARejectsInvalidIdentityWithoutRefresh(t *testing.T) {
	validRef := strings.Repeat("a", 40)
	tests := []struct {
		name string
		ref  string
		path string
		want issuedelivery.WorkflowDefinitionFailureClass
	}{
		{name: "malformed SHA", ref: "not-a-sha", path: ".github/workflows/ci.yml", want: workflowDefinitionFailureMalformedRef},
		{name: "untrusted workflow path", ref: validRef, path: ".github/workflows/foreign.yml", want: workflowDefinitionFailureUntrustedPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &fakeRemoteRunner{}
			gateway := productionNonLocalGateway{runner: runner}
			_, err := gateway.definitionSHAForObservation(
				context.Background(), "yersonargotev/packy", tt.ref, tt.path,
				workflowDefinitionSourceCheckRun, true,
			)
			var diagnostic *workflowDefinitionDiagnostic
			if !errors.As(err, &diagnostic) || diagnostic.FinalFailureClass != tt.want {
				t.Fatalf("diagnostic = %#v, err=%v", diagnostic, err)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("invalid identity triggered commands: %#v", runner.calls)
			}
		})
	}
}

func TestWorkflowDefinitionSHADoesNotRefreshForMissingWorkflowPath(t *testing.T) {
	ref := strings.Repeat("a", 40)
	runner := &fakeRemoteRunner{
		outputs: [][]byte{nil, nil},
		errs:    []error{errors.New("fatal: path '.github/workflows/ci.yml' does not exist in '" + ref + "'")},
	}
	gateway := productionNonLocalGateway{runner: runner}

	_, err := gateway.definitionSHAForObservation(
		context.Background(), "yersonargotev/packy", ref, ".github/workflows/ci.yml",
		workflowDefinitionSourceCheckRun, true,
	)
	var diagnostic *workflowDefinitionDiagnostic
	if !errors.As(err, &diagnostic) || diagnostic.FinalFailureClass != workflowDefinitionFailurePathAbsent ||
		diagnostic.RetryCount != 0 || len(runner.calls) != 2 {
		t.Fatalf("missing workflow path was treated as ref skew: diagnostic=%#v err=%v calls=%#v", diagnostic, err, runner.calls)
	}
}

func TestWorkflowDefinitionSHARejectsIncompatibleObservedWorkflowWithoutRefresh(t *testing.T) {
	head := strings.Repeat("b", 40)
	runner := &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"check_runs":[{"name":"Validate Packy-owned code","head_sha":"` + head + `","status":"completed","conclusion":"success","details_url":"https://github.com/yersonargotev/packy/actions/runs/42/job/7","app":{"id":15368,"slug":"github-actions"}}]}`),
		[]byte(`[]`),
		[]byte(`{"id":42,"name":"Security","path":".github/workflows/security-pr.yml","head_sha":"` + head + `","html_url":"https://github.com/yersonargotev/packy/actions/runs/42","actor":{"login":"maintainer","id":1,"type":"User","html_url":"https://github.com/maintainer"}}`),
	}}
	gateway := productionNonLocalGateway{runner: runner}
	_, err := gateway.observeChecks(context.Background(), issuedelivery.NonLocalObserveRequest{
		Repository: packyRemoteRepository(), HeadSHA: head,
	}, strings.Repeat("a", 40))
	var diagnostic *workflowDefinitionDiagnostic
	if !errors.As(err, &diagnostic) || diagnostic.FinalFailureClass != workflowDefinitionFailureIncompatible {
		t.Fatalf("diagnostic = %#v, err=%v", diagnostic, err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("incompatible workflow triggered resolution or refresh: %#v", runner.calls)
	}
}

func TestWorkflowDefinitionSHARejectsMismatchedWorkflowHeadWithoutRefresh(t *testing.T) {
	head, workflowHead := strings.Repeat("b", 40), strings.Repeat("c", 40)
	runner := &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"check_runs":[{"name":"Validate Packy-owned code","head_sha":"` + workflowHead + `","status":"completed","conclusion":"success","details_url":"https://github.com/yersonargotev/packy/actions/runs/42/job/7","app":{"id":15368,"slug":"github-actions"}}]}`),
		[]byte(`[]`),
		[]byte(`{"id":42,"name":"CI","path":".github/workflows/ci.yml","head_sha":"` + workflowHead + `","html_url":"https://github.com/yersonargotev/packy/actions/runs/42","actor":{"login":"maintainer","id":1,"type":"User","html_url":"https://github.com/maintainer"}}`),
	}}
	gateway := productionNonLocalGateway{runner: runner}
	_, err := gateway.observeChecks(context.Background(), issuedelivery.NonLocalObserveRequest{
		Repository: packyRemoteRepository(), HeadSHA: head,
	}, strings.Repeat("a", 40))
	var diagnostic *workflowDefinitionDiagnostic
	if !errors.As(err, &diagnostic) || diagnostic.FinalFailureClass != workflowDefinitionFailureIncompatible {
		t.Fatalf("diagnostic = %#v, err=%v", diagnostic, err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("mismatched workflow HEAD triggered resolution or refresh: %#v", runner.calls)
	}
}

func TestWorkflowDefinitionSHADoesNotRefreshAfterCancellation(t *testing.T) {
	ref := strings.Repeat("a", 40)
	runner := &fakeRemoteRunner{
		outputs: [][]byte{nil},
		errs:    []error{context.Canceled},
	}
	gateway := productionNonLocalGateway{runner: runner}

	_, err := gateway.definitionSHAForObservation(
		context.Background(), "yersonargotev/packy", ref, ".github/workflows/ci.yml",
		workflowDefinitionSourceCheckRun, true,
	)
	var diagnostic *workflowDefinitionDiagnostic
	if !errors.As(err, &diagnostic) || diagnostic.FinalFailureClass != workflowDefinitionFailureCancellation ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("diagnostic = %#v, err=%v", diagnostic, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("cancellation triggered ref refresh: %#v", runner.calls)
	}
}

func TestWorkflowDefinitionSHADoesNotTreatAuthorizationFailureAsRefSkew(t *testing.T) {
	ref := strings.Repeat("a", 40)
	runner := &fakeRemoteRunner{
		outputs: [][]byte{nil, nil, nil},
		errs: []error{
			errors.New("fatal: invalid object name '" + ref + "'."),
			errors.New("fatal: Not a valid object name " + ref + "^{commit}"),
			errors.New("remote: permission denied for token=secret-value"),
		},
	}
	gateway := productionNonLocalGateway{runner: runner}

	_, err := gateway.definitionSHAForObservation(
		context.Background(), "yersonargotev/packy", ref, ".github/workflows/ci.yml",
		workflowDefinitionSourceCheckRun, true,
	)
	var diagnostic *workflowDefinitionDiagnostic
	if !errors.As(err, &diagnostic) || diagnostic.FinalFailureClass != workflowDefinitionFailureAuthorization ||
		diagnostic.RetryCount != 1 {
		t.Fatalf("diagnostic = %#v, err=%v", diagnostic, err)
	}
	if strings.Contains(err.Error(), "secret-value") || len(runner.calls) != 3 {
		t.Fatalf("authorization failure leaked or retried unexpectedly: err=%v calls=%#v", err, runner.calls)
	}
}

func TestWorkflowDefinitionSHARecoversGovernanceBaseObservedAfterMerge(t *testing.T) {
	base, blob := strings.Repeat("a", 40), strings.Repeat("b", 40)
	runner := &fakeRemoteRunner{
		outputs: [][]byte{
			[]byte(`{"check_runs":[]}`),
			[]byte(`[{"id":7,"context":"Governance / Validate authorization","state":"success","target_url":"https://github.com/yersonargotev/packy/actions/runs/42","creator":{"login":"github-actions[bot]","id":41898282,"type":"Bot","html_url":"https://github.com/apps/github-actions"}}]`),
			[]byte(`{"id":42,"name":"Governance","path":".github/workflows/governance.yml","head_sha":"` + base + `","html_url":"https://github.com/yersonargotev/packy/actions/runs/42","actor":{"login":"maintainer","id":1,"type":"User","html_url":"https://github.com/maintainer"}}`),
			nil,
			nil,
			nil,
			[]byte(blob + "\n"),
		},
		errs: []error{
			nil, nil, nil,
			errors.New("fatal: invalid object name '" + base + "'."),
			errors.New("fatal: Not a valid object name " + base + "^{commit}"),
		},
	}
	gateway := productionNonLocalGateway{runner: runner}
	checks, err := gateway.observeChecks(context.Background(), issuedelivery.NonLocalObserveRequest{
		Repository: packyRemoteRepository(), HeadSHA: strings.Repeat("c", 40),
	}, base)
	if err != nil || len(checks) != 1 {
		t.Fatalf("checks = %#v, err=%v", checks, err)
	}
	if checks[0].Identity != "Governance / Validate authorization" ||
		checks[0].Workflow.DefinitionRef != base || checks[0].Workflow.DefinitionSHA != blob {
		t.Fatalf("governance workflow evidence = %#v", checks[0].Workflow)
	}
	if len(runner.calls) != 7 || !reflect.DeepEqual(runner.calls[3], runner.calls[6]) ||
		!reflect.DeepEqual(runner.calls[5].args, []string{"fetch", "--quiet", "--no-tags", "origin", base}) {
		t.Fatalf("governance recovery commands = %#v", runner.calls)
	}
}

func TestProductionNonLocalMergeUsesMatchHeadCommit(t *testing.T) {
	head, base := strings.Repeat("b", 40), strings.Repeat("a", 40)
	runner := &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"id":"R1","nameWithOwner":"yersonargotev/packy"}`),
		[]byte(`{"number":17,"state":"OPEN","baseRefOid":"` + base + `","headRefOid":"` + head + `","closingIssuesReferences":[{"number":361,"id":"I1"}],"mergedAt":""}`),
		nil,
	}}
	gateway := productionNonLocalGateway{runner: runner}
	err := gateway.EnsureMerge(context.Background(), issuedelivery.EnsureMergeRequest{
		Repository: packyRemoteRepository(), Issue: deliveryevidence.IssueIdentity{Number: 361, NodeID: "I1"},
		PullRequest: 17, HeadSHA: head, BaseSHA: base, Method: "merge",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := runner.calls[1]; got.name != "gh" || !reflect.DeepEqual(got.args, []string{
		"pr", "view", "17", "--repo", "yersonargotev/packy", "--json",
		"number,state,baseRefOid,headRefOid,closingIssuesReferences,mergedAt",
		"--jq", pullRequestProjection,
	}) {
		t.Fatalf("pull-request merge observation command = %#v", got)
	}
	got := runner.calls[2]
	want := remoteRunnerCall{name: "gh", args: []string{
		"pr", "merge", "17", "--repo", "yersonargotev/packy", "--merge",
		"--match-head-commit", head,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merge command = %#v, want %#v", got, want)
	}
}

func TestProductionNonLocalCleanupRejectsMovedBranchWithoutDeletion(t *testing.T) {
	head, moved := strings.Repeat("b", 40), strings.Repeat("c", 40)
	runner := &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"id":"R1","nameWithOwner":"yersonargotev/packy"}`),
		[]byte(moved + "\trefs/heads/fix/issue-361-adapter\n"),
	}}
	gateway := productionNonLocalGateway{runner: runner}
	err := gateway.EnsureRemoteIssueBranchAbsent(context.Background(), issuedelivery.DeleteRemoteIssueBranchRequest{
		Repository: packyRemoteRepository(), Branch: "fix/issue-361-adapter", HeadSHA: head,
	})
	if err == nil || !strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("error = %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("unexpected mutation after incompatible observation: %#v", runner.calls)
	}
}

func TestProductionNonLocalCleanupUsesExactLease(t *testing.T) {
	head := strings.Repeat("b", 40)
	runner := &fakeRemoteRunner{outputs: [][]byte{
		[]byte(`{"id":"R1","nameWithOwner":"yersonargotev/packy"}`),
		[]byte(head + "\trefs/heads/fix/issue-361-adapter\n"),
		nil,
	}}
	gateway := productionNonLocalGateway{runner: runner}
	err := gateway.EnsureRemoteIssueBranchAbsent(
		context.Background(),
		issuedelivery.DeleteRemoteIssueBranchRequest{
			Repository: packyRemoteRepository(),
			Branch:     "fix/issue-361-adapter", HeadSHA: head,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	got := runner.calls[2]
	wantLease := "--force-with-lease=refs/heads/fix/issue-361-adapter:" + head
	if got.name != "git" || !reflect.DeepEqual(got.args, []string{
		"push", wantLease, "origin", ":refs/heads/fix/issue-361-adapter",
	}) {
		t.Fatalf("leased cleanup command = %#v", got)
	}
}

func TestProductionNonLocalCleanupRejectsConcurrentBranchMoveAtLease(t *testing.T) {
	head := strings.Repeat("b", 40)
	runner := &fakeRemoteRunner{
		outputs: [][]byte{
			[]byte(`{"id":"R1","nameWithOwner":"yersonargotev/packy"}`),
			[]byte(head + "\trefs/heads/fix/issue-361-adapter\n"),
			nil,
		},
		errs: []error{nil, nil, errors.New("stale info")},
	}
	err := (productionNonLocalGateway{runner: runner}).EnsureRemoteIssueBranchAbsent(
		context.Background(),
		issuedelivery.DeleteRemoteIssueBranchRequest{
			Repository: packyRemoteRepository(),
			Branch:     "fix/issue-361-adapter", HeadSHA: head,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "delete exact remote") {
		t.Fatalf("concurrent remote branch movement was not rejected: %v", err)
	}
}

func TestProductionNonLocalRejectsForeignRepositoryBeforeMutation(t *testing.T) {
	runner := &fakeRemoteRunner{}
	gateway := productionNonLocalGateway{runner: runner}
	err := gateway.PushIssueBranch(context.Background(), issuedelivery.PushIssueBranchRequest{
		Repository: deliveryevidence.RepositoryIdentity{Owner: "other", Name: "packy", NodeID: "R1"},
		Branch:     "chore/issue-361-adapter", HeadSHA: strings.Repeat("b", 40),
	})
	if err == nil || len(runner.calls) != 0 {
		t.Fatalf("foreign identity was not rejected before commands: err=%v calls=%#v", err, runner.calls)
	}
}

func TestTrustedCheckIdentityRejectsIncompatibleWorkflow(t *testing.T) {
	if trustedCheckIdentity("CodeQL", "CI", ".github/workflows/ci.yml") {
		t.Fatal("CodeQL must not accept CI workflow provenance")
	}
	if trustedCheckIdentity("foreign", "Security", ".github/workflows/security-pr.yml") {
		t.Fatal("foreign required check accepted")
	}
}

func TestApplyCIFailureAttributionRequiresExactFailedRun(t *testing.T) {
	head := strings.Repeat("b", 40)
	checks := []issuedelivery.CICheckObservation{{
		RequiredCheck: deliveryevidence.RequiredCheck{
			Identity: "Validate Packy-owned code", Conclusion: "failure", HeadSHA: head,
		},
		RunID: 42, DetailsURL: "https://github.com/yersonargotev/packy/actions/runs/42",
	}}
	decision := advanceCIFailureAttribution{
		CheckIdentity: checks[0].Identity, RunID: checks[0].RunID,
		HeadSHA: head, DetailsURL: checks[0].DetailsURL,
		Attribution: issuedelivery.FailureCandidate,
	}
	got, err := applyCIFailureAttributions(checks, []advanceCIFailureAttribution{decision})
	if err != nil || got[0].FailureAttribution != issuedelivery.FailureCandidate {
		t.Fatalf("exact attribution = %#v, err=%v", got, err)
	}
	decision.RunID++
	if _, err = applyCIFailureAttributions(checks, []advanceCIFailureAttribution{decision}); err == nil {
		t.Fatal("foreign failed run attribution was accepted")
	}
}

func TestLatestCommitStatusSelectsNewestIdentity(t *testing.T) {
	statuses := []commitStatus{
		{ID: 41, Context: "Governance / Validate authorization", State: "pending"},
		{ID: 42, Context: "Governance / Validate authorization", State: "success"},
		{ID: 43, Context: "other", State: "failure"},
	}
	got, found, err := latestCommitStatus(statuses, "Governance / Validate authorization")
	if err != nil {
		t.Fatal(err)
	}
	if !found || got.ID != 42 || got.State != "success" {
		t.Fatalf("latest status = %#v, found=%v", got, found)
	}
}

func TestLatestCommitStatusRejectsMalformedMatchingIdentity(t *testing.T) {
	_, _, err := latestCommitStatus([]commitStatus{{
		Context: "Governance / Validate authorization", State: "success",
	}}, "Governance / Validate authorization")
	if err == nil {
		t.Fatal("matching status without a stable identity was accepted")
	}
}

func TestNormalizeRemoteTimestampUsesCanonicalDeliveryFormat(t *testing.T) {
	got, err := normalizeRemoteTimestamp("2026-07-30T15:10:37Z")
	if err != nil {
		t.Fatal(err)
	}
	if got != "2026-07-30T15:10:37.000000000Z" {
		t.Fatalf("normalized timestamp = %q", got)
	}
	if _, err = normalizeRemoteTimestamp("not-a-timestamp"); err == nil {
		t.Fatal("malformed remote timestamp was accepted")
	}
}

func packyRemoteRepository() deliveryevidence.RepositoryIdentity {
	return deliveryevidence.RepositoryIdentity{Owner: "yersonargotev", Name: "packy", NodeID: "R1"}
}
