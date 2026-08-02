package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type operatorWorkflowNonLocalGateway struct {
	observation issuedelivery.NonLocalObservation
	retryCalls  int
}

func (gateway *operatorWorkflowNonLocalGateway) ObserveNonLocal(
	context.Context,
	issuedelivery.NonLocalObserveRequest,
) (issuedelivery.NonLocalObservation, error) {
	return gateway.observation, nil
}

func (gateway *operatorWorkflowNonLocalGateway) PushIssueBranch(
	_ context.Context,
	request issuedelivery.PushIssueBranchRequest,
) error {
	gateway.observation.Branch = &issuedelivery.RemoteBranchObservation{
		Name: request.Branch, HeadSHA: request.HeadSHA,
	}
	return nil
}

func (gateway *operatorWorkflowNonLocalGateway) EnsurePullRequest(
	_ context.Context,
	request issuedelivery.EnsurePullRequestRequest,
) error {
	if request.PullRequest > 0 {
		for index := range gateway.observation.PullRequests {
			if gateway.observation.PullRequests[index].Number == request.PullRequest {
				gateway.observation.PullRequests[index].DeliveryProfiles = []string{request.DeliveryProfile}
				return nil
			}
		}
	}
	gateway.observation.PullRequests = []issuedelivery.RemotePullRequestObservation{{
		Number: 31, URL: "https://github.com/yersonargotev/packy/pull/31", State: "OPEN",
		BaseRef: "main", BaseSHA: strings.Repeat("a", 40),
		HeadBranch: request.HeadBranch, HeadSHA: request.HeadSHA,
		HeadRepositoryNodeID: request.Repository.NodeID,
		ClosingIssue:         request.Issue.Number,
		DeliveryProfiles:     []string{request.DeliveryProfile},
	}}
	return nil
}

func (gateway *operatorWorkflowNonLocalGateway) RetryInfrastructureCheck(
	context.Context,
	issuedelivery.RetryInfrastructureCheckRequest,
) error {
	gateway.retryCalls++
	return nil
}

func (*operatorWorkflowNonLocalGateway) EnsureMerge(
	context.Context,
	issuedelivery.EnsureMergeRequest,
) error {
	return nil
}

func (gateway *operatorWorkflowNonLocalGateway) EnsureRemoteIssueBranchAbsent(
	context.Context,
	issuedelivery.DeleteRemoteIssueBranchRequest,
) error {
	gateway.observation.Branch = nil
	return nil
}

func TestOperatorWorkflowRoundTripsGeneratedInputsThroughRealModule(t *testing.T) {
	home, config, state := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("XDG_STATE_HOME", state)

	nonLocal := &operatorWorkflowNonLocalGateway{observation: issuedelivery.NonLocalObservation{
		PullRequests: []issuedelivery.RemotePullRequestObservation{},
		Checks:       []issuedelivery.CICheckObservation{},
	}}
	module, initial, repository, _, clock := productionReadyModule(
		t,
		nonLocal,
		nil,
		suppliedReviewExecutor{},
		"qualification-correction",
		issuedelivery.AuthorityItem{
			Text: "Reach exact local readiness.", EvidenceLink: "issue#361:acceptance-1",
		},
		issuedelivery.AuthorityItem{
			Text: "Preserve the public delivery contract.", EvidenceLink: "issue#361:acceptance-2",
		},
	)
	cmd := command{
		Now: clock.Now,
		StatusFactory: func(statusOptions) (issueDeliveryStatuser, error) {
			return module, nil
		},
		InputTemplateFactory: func(string) (issueDeliveryInputTemplateMaterializer, error) {
			return module, nil
		},
		ReviewPacketFactory: func(string) (issueDeliveryReviewPacketMaterializer, error) {
			return module, nil
		},
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
			return module, nil
		},
		WatchFactory: func(statusOptions) (issueDeliveryWatcher, error) {
			return module, nil
		},
	}
	run := func(args ...string) []byte {
		t.Helper()
		var stdout bytes.Buffer
		if err := cmd.run(context.Background(), args, &stdout); err != nil {
			t.Fatalf("run %q: %v", args, err)
		}
		return stdout.Bytes()
	}

	statusRaw := run("status", "--repository", repository, "--issue", "361")
	var status compactAdvanceReport
	if err := json.Unmarshal(statusRaw, &status); err != nil {
		t.Fatal(err)
	}
	if status.RunID != initial.RunID ||
		status.NextAction != issuedelivery.ActionProvideQualificationCorrection {
		t.Fatalf("initial compact status = %#v", status)
	}

	correctionPath := filepath.Join(t.TempDir(), "qualification-correction.json")
	run(
		"input-template", "--repository", repository, "--issue", "361",
		"--kind", string(issuedelivery.InputTemplateQualificationCorrection),
		"--output", correctionPath,
	)
	var correctionContent advanceReviewContent
	if err := decodeSemanticJSONFile("--review-content", correctionPath, &correctionContent); err != nil {
		t.Fatal(err)
	}
	fillOperatorQualificationCorrection(t, correctionContent.QualificationCorrection)
	writeOperatorJSON(t, correctionPath, correctionContent)

	afterCorrection := runOperatorAdvanceReport(
		t, cmd, repository, "--review-content", correctionPath,
	)
	if afterCorrection.RunID != initial.RunID ||
		afterCorrection.NextAction != issuedelivery.ActionProvideQualificationReview {
		t.Fatalf("generated correction did not reach real qualification review: %#v", afterCorrection)
	}

	qualificationDirectory := filepath.Join(t.TempDir(), "qualification-review")
	run(
		"review-packets", "--repository", repository, "--issue", "361",
		"--kind", string(issuedelivery.ReviewPacketQualification),
		"--output", qualificationDirectory,
	)
	fillOperatorReviewResponses(t, qualificationDirectory)
	afterQualification := runOperatorAdvanceReport(
		t, cmd, repository, "--review-content", qualificationDirectory,
	)
	if afterQualification.Candidate == nil ||
		afterQualification.NextAction != issuedelivery.ActionProvideCandidateReview {
		t.Fatalf("qualification response did not reach real candidate review: %#v", afterQualification)
	}

	candidateDirectory := filepath.Join(t.TempDir(), "candidate-reviews")
	run(
		"review-packets", "--repository", repository, "--issue", "361",
		"--kind", string(issuedelivery.ReviewPacketCandidate),
		"--output", candidateDirectory,
	)
	completeOperatorReviewResponses(t, candidateDirectory, false)
	var rejected bytes.Buffer
	err := cmd.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361",
		"--risk-profile", "low-risk", "--full-report",
		"--review-content", candidateDirectory,
	}, &rejected)
	if err == nil || !strings.Contains(err.Error(), "generated judgment placeholder") {
		t.Fatalf("untouched generated Spec placeholders were admitted: %v", err)
	}
	completeOperatorReviewResponses(t, candidateDirectory, true)
	afterReviews := runOperatorAdvanceReport(
		t,
		cmd,
		repository,
		"--review-content", candidateDirectory,
		"--authorize-non-local",
	)
	if afterReviews.Candidate == nil || len(afterReviews.Candidate.Reviews) != 2 ||
		afterReviews.PauseCause != issuedelivery.PauseExternalResult {
		t.Fatalf("parallel responses did not reach real external wait: %#v", afterReviews)
	}
	for _, review := range afterReviews.Candidate.Reviews {
		if !review.Completed || review.PacketID == "" || review.PacketSHA256 == "" ||
			review.ResponseSHA256 == "" {
			t.Fatalf("real module did not admit exact completed packet response: %#v", review)
		}
	}

	nonLocal.observation.Checks = []issuedelivery.CICheckObservation{{
		RequiredCheck: deliveryevidence.RequiredCheck{
			Identity: "build", Conclusion: "success",
			HeadSHA: afterReviews.Candidate.CommitSHA,
		},
		RunID: 31, DetailsURL: "https://example.test/actions/31",
	}}
	watchRaw := run(
		"watch", "--repository", repository, "--issue", "361",
		"--interval", "100ms", "--timeout", "1s", "--output", "jsonl",
	)
	if !bytes.Contains(watchRaw, []byte(`"next_action":"advance"`)) {
		t.Fatalf("watch did not report the changed external result:\n%s", watchRaw)
	}

	final := runOperatorAdvanceReport(t, cmd, repository)
	if final.RunID != initial.RunID || final.NonLocal == nil ||
		len(final.NonLocal.Checks) != 1 ||
		final.NonLocal.Checks[0].RunID != 31 {
		t.Fatalf("final Advance did not adopt the watched external result: %#v", final)
	}
}

func TestOperatorCommandsResumePersistedInfrastructureRetryJournal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	nonLocal := &operatorWorkflowNonLocalGateway{observation: issuedelivery.NonLocalObservation{
		PullRequests: []issuedelivery.RemotePullRequestObservation{},
		Checks:       []issuedelivery.CICheckObservation{},
	}}
	local := &commandCompletionLocal{}
	module, ready, repository, _, clock := productionReadyModule(t, nonLocal, local, nil, "")
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
	cmd := command{
		Now: clock.Now,
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
			return module, nil
		},
		StatusFactory: func(statusOptions) (issueDeliveryStatuser, error) {
			return module, nil
		},
	}

	waiting := runOperatorAdvanceReport(t, cmd, repository, "--authorize-non-local")
	if waiting.NonLocal == nil || waiting.NonLocal.PullRequest == nil {
		waiting = runOperatorAdvanceReport(t, cmd, repository)
	}
	if waiting.NonLocal == nil || waiting.NonLocal.PullRequest == nil {
		t.Fatalf("authorized command did not reach exact CI wait: %#v", waiting)
	}
	checks := commandSuccessfulChecks(
		deliveryevidence.RepositoryIdentity{Owner: "yersonargotev", Name: "packy", NodeID: "R1"},
		ready.Candidate.CommitSHA,
		strings.Repeat("a", 40),
	)
	checks[0].Conclusion = "failure"
	checks[0].FailureAttribution = issuedelivery.FailureInfrastructure
	nonLocal.observation.Checks = checks
	retrying := runOperatorAdvanceReport(t, cmd, repository)
	if nonLocal.retryCalls != 1 || retrying.NonLocal == nil ||
		len(retrying.NonLocal.Retries) != 1 {
		t.Fatalf("retrying report=%#v retry calls=%d", retrying, nonLocal.retryCalls)
	}

	checks[0].Conclusion = ""
	checks[0].FailureAttribution = ""
	nonLocal.observation.Checks = checks
	pending := runOperatorAdvanceReport(t, cmd, repository)
	if nonLocal.retryCalls != 1 || pending.PauseCause != issuedelivery.PauseExternalResult ||
		pending.NextAction != issuedelivery.ActionObserveExternalResult ||
		pending.NonLocal == nil || pending.NonLocal.CIStatus != string(issuedelivery.CIPending) {
		t.Fatalf("pending report=%#v retry calls=%d", pending, nonLocal.retryCalls)
	}

	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), []string{
		"status", "--repository", repository, "--issue", "361",
	}, &stdout); err != nil {
		t.Fatal(err)
	}
	var status compactAdvanceReport
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.RunID != ready.RunID || status.PauseCause != issuedelivery.PauseExternalResult ||
		status.NextAction != issuedelivery.ActionObserveExternalResult {
		t.Fatalf("status did not decode persisted v0.6.2 retry journal: %#v", status)
	}

	checks[0].Conclusion = "success"
	nonLocal.observation.Checks = checks
	green := runOperatorAdvanceReport(t, cmd, repository)
	if nonLocal.retryCalls != 1 || green.NonLocal == nil ||
		green.NonLocal.CIStatus != string(issuedelivery.CISuccess) ||
		len(green.NonLocal.Retries) != 1 || green.Candidate == nil ||
		green.Candidate.ID != ready.Candidate.ID ||
		green.Candidate.CommitSHA != ready.Candidate.CommitSHA ||
		!strings.Contains(green.Reason, "merge was dispatched") {
		t.Fatalf("green retry did not resume to merge readiness: %#v", green)
	}
}

func TestOperatorWorkflowReportsQualificationBindingFieldAndLocatorRule(t *testing.T) {
	home, config, state := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("XDG_STATE_HOME", state)

	module, _, repository, _, clock := productionReadyModule(
		t,
		&operatorWorkflowNonLocalGateway{},
		nil,
		suppliedReviewExecutor{},
		"qualification-correction",
		issuedelivery.AuthorityItem{
			Text: "Reach exact local readiness.", EvidenceLink: "issue#361:acceptance-1",
		},
		issuedelivery.AuthorityItem{
			Text: "Preserve the public delivery contract.", EvidenceLink: "issue#361:acceptance-2",
		},
	)
	cmd := command{
		Now: clock.Now,
		InputTemplateFactory: func(string) (issueDeliveryInputTemplateMaterializer, error) {
			return module, nil
		},
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
			return module, nil
		},
	}
	correctionPath := filepath.Join(t.TempDir(), "qualification-correction.json")
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), []string{
		"input-template", "--repository", repository, "--issue", "361",
		"--kind", string(issuedelivery.InputTemplateQualificationCorrection),
		"--output", correctionPath,
	}, &stdout); err != nil {
		t.Fatal(err)
	}
	var valid advanceReviewContent
	readOperatorJSON(t, correctionPath, &valid)
	fillOperatorQualificationCorrection(t, valid.QualificationCorrection)
	if len(valid.QualificationCorrection.AcceptanceMatrix) < 2 {
		t.Fatalf("qualification fixture has fewer than two rows: %#v", valid.QualificationCorrection)
	}

	assertion := "; assertion=this assertion remains long enough to satisfy the binding grammar"
	tests := []struct {
		name        string
		row         int
		field       string
		kind        string
		locator     string
		expectation string
		set         func(*deliveryevidence.AcceptanceRow, string)
	}{
		{"owning seam file", 0, "owning_seam", "file", "", "<path>/<name>", func(row *deliveryevidence.AcceptanceRow, value string) { row.OwningSeam = value }},
		{"positive symbol", 1, "positive_evidence", "symbol", "Unqualified", "1-2 '.' or ':' characters", func(row *deliveryevidence.AcceptanceRow, value string) { row.PositiveEvidence = value }},
		{"negative test", 0, "negative_evidence", "test", "TestShort", "Test<name>", func(row *deliveryevidence.AcceptanceRow, value string) { row.NegativeEvidence = value }},
		{"failure command", 1, "failure_evidence", "command", "scripts/check.sh", "./<path>/<name>", func(row *deliveryevidence.AcceptanceRow, value string) { row.FailureEvidence = value }},
		{"mutation fixture", 0, "mutation_evidence", "fixture", "fixture/group", "fixture/<group>/<name>", func(row *deliveryevidence.AcceptanceRow, value string) { row.MutationEvidence = value }},
		{"compatibility review", 1, "compatibility_evidence", "review", "review/not-a-receipt", "review/<16-lowercase-hex>", func(row *deliveryevidence.AcceptanceRow, value string) { row.CompatibilityEvidence = value }},
		{"preservation authority", 0, "preservation_evidence", "authority", "criterion-invalid", "criterion-<16-lowercase-hex>[/<name>] or issue#<number>[/<name>]", func(row *deliveryevidence.AcceptanceRow, value string) { row.PreservationEvidence = value }},
		{"migration not applicable", 1, "migration_evidence", "not-applicable", "reason/single", "reason/<word>-<word>[-<word>...]", func(row *deliveryevidence.AcceptanceRow, value string) { row.MigrationEvidence = value }},
		{"parseable source with invalid prefix", 0, "owning_seam", "fixture", "fixture/group/name", "must start with", func(row *deliveryevidence.AcceptanceRow, _ string) {
			row.OwningSeam = "[criterion:source=wrong] source=fixture:fixture/group/name" + assertion
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(valid)
			if err != nil {
				t.Fatal(err)
			}
			var content advanceReviewContent
			if err = json.Unmarshal(raw, &content); err != nil {
				t.Fatal(err)
			}
			row := &content.QualificationCorrection.AcceptanceMatrix[test.row]
			test.set(row, "[criterion:"+row.Identity+"] source="+test.kind+":"+test.locator+assertion)
			writeOperatorJSON(t, correctionPath, content)

			stdout.Reset()
			err = cmd.run(context.Background(), []string{
				"advance", "--repository", repository, "--issue", "361",
				"--risk-profile", "low-risk", "--review-content", correctionPath,
			}, &stdout)
			if err == nil {
				t.Fatal("invalid qualification correction was accepted")
			}
			for _, expected := range []string{
				row.Identity,
				"acceptance_matrix[" + strconv.Itoa(test.row) + "]." + test.field,
				"source kind " + strconv.Quote(test.kind),
				test.expectation,
			} {
				if !strings.Contains(err.Error(), expected) {
					t.Fatalf("binding error %q does not contain %q", err, expected)
				}
			}
		})
	}

	t.Run("stable criterion identity", func(t *testing.T) {
		raw, err := json.Marshal(valid)
		if err != nil {
			t.Fatal(err)
		}
		var content advanceReviewContent
		if err = json.Unmarshal(raw, &content); err != nil {
			t.Fatal(err)
		}
		row := &content.QualificationCorrection.AcceptanceMatrix[0]
		stableIdentity := row.Identity
		row.Identity = "criterion-ffffffffffffffff"
		writeOperatorJSON(t, correctionPath, content)

		stdout.Reset()
		err = cmd.run(context.Background(), []string{
			"advance", "--repository", repository, "--issue", "361",
			"--risk-profile", "low-risk", "--review-content", correctionPath,
		}, &stdout)
		if err == nil || !strings.Contains(err.Error(), stableIdentity) ||
			!strings.Contains(err.Error(), "acceptance_matrix[0].identity") {
			t.Fatalf("altered criterion identity error = %v", err)
		}
	})
}

func fillOperatorQualificationCorrection(
	t *testing.T,
	correction *issuedelivery.QualificationCorrection,
) {
	t.Helper()
	if correction == nil {
		t.Fatal("generated correction template is absent")
	}
	for index := range correction.AcceptanceMatrix {
		row := &correction.AcceptanceMatrix[index]
		prefix := "[criterion:" + row.Identity + "] "
		identity := strings.ReplaceAll(row.Identity, "-", "_")
		row.OwningSeam = prefix + "source=symbol:packydeliver." + identity +
			".operatorJourney; assertion=the command runner owns the integrated operator seam"
		row.PositiveEvidence = prefix + "source=test:TestOperatorWorkflow_" + identity +
			"_Positive; assertion=the generated artifact is accepted unchanged"
		row.NegativeEvidence = prefix + "source=test:TestOperatorWorkflow_" + identity +
			"_Negative; assertion=a stale artifact is rejected"
		row.FailureEvidence = prefix + "source=test:TestOperatorWorkflow_" + identity +
			"_Failure; assertion=an invalid artifact fails closed"
		row.MutationEvidence = prefix + "source=test:TestOperatorWorkflow_" + identity +
			"_Mutation; assertion=Advance alone persists the transition"
		row.CompatibilityEvidence = prefix + "source=test:TestOperatorWorkflow_" + identity +
			"_Compatibility; assertion=the public JSON contract remains compatible"
		row.PreservationEvidence = prefix + "source=test:TestOperatorWorkflow_" + identity +
			"_Preservation; assertion=sandboxed operator configuration is preserved"
		row.MigrationEvidence = prefix + "source=authority:" + row.Identity +
			"/migration; assertion=no evidence migration is required"
		row.State = deliveryevidence.AcceptancePlanned
	}
	correction.Evidence = "[request:" + correction.RequestID + "] findings=" +
		strings.Join(correction.FindingIDs, ",") +
		"; rationale=filled the generated correction without translating its JSON shape"
}

func fillOperatorReviewResponses(t *testing.T, directory string) {
	completeOperatorReviewResponses(t, directory, true)
}

func completeOperatorReviewResponses(t *testing.T, directory string, fillAcceptance bool) {
	t.Helper()
	var manifest reviewPacketDirectoryManifest
	readOperatorJSON(t, filepath.Join(directory, "manifest.json"), &manifest)
	for _, entry := range manifest.Entries {
		var packet issuedelivery.ReviewPacket
		readOperatorJSON(t, filepath.Join(directory, entry.PacketFile), &packet)
		var response issuedelivery.ReviewPacketResponseTemplate
		responsePath := filepath.Join(directory, entry.ResponseFile)
		readOperatorJSON(t, responsePath, &response)
		switch {
		case response.Qualification != nil:
			response.Qualification.Completed = true
		case response.Candidate != nil:
			response.Candidate.Completed = true
			if response.Candidate.Axis == deliveryevidence.ReviewSpec {
				if len(response.Candidate.Acceptance) != len(packet.AcceptanceRows) {
					t.Fatalf("generated Spec proof count = %d, rows = %d", len(response.Candidate.Acceptance), len(packet.AcceptanceRows))
				}
				for index := range response.Candidate.Acceptance {
					proof := &response.Candidate.Acceptance[index]
					if proof.Identity != packet.AcceptanceRows[index].Identity {
						t.Fatalf("generated Spec proof order = %#v", response.Candidate.Acceptance)
					}
					if !fillAcceptance {
						continue
					}
					completed := productionPathAcceptance(issuedelivery.ReviewRequest{
						CandidateID: response.Candidate.CandidateID,
						Axis:        response.Candidate.Axis, Iteration: response.Candidate.Iteration,
						CommitSHA: response.Candidate.CommitSHA, TreeSHA: response.Candidate.TreeSHA,
						AcceptanceRows: []deliveryevidence.AcceptanceRow{packet.AcceptanceRows[index]},
					})[0]
					proof.PositiveEvidence = completed.PositiveEvidence
					proof.NegativeEvidence = completed.NegativeEvidence
					proof.FailureEvidence = completed.FailureEvidence
					proof.MutationEvidence = completed.MutationEvidence
					proof.CompatibilityEvidence = completed.CompatibilityEvidence
					proof.PreservationEvidence = completed.PreservationEvidence
					proof.MigrationEvidence = completed.MigrationEvidence
				}
			}
		default:
			t.Fatalf("unexpected response template in %s: %#v", responsePath, response)
		}
		writeOperatorJSON(t, responsePath, response)
	}
}

func readOperatorJSON(t *testing.T, path string, target any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}

func writeOperatorJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func runOperatorAdvanceReport(
	t *testing.T,
	cmd command,
	repository string,
	extra ...string,
) advanceReport {
	t.Helper()
	args := []string{
		"advance", "--repository", repository, "--issue", "361",
		"--risk-profile", "low-risk", "--full-report",
	}
	args = append(args, extra...)
	var stdout bytes.Buffer
	if err := cmd.run(context.Background(), args, &stdout); err != nil {
		t.Fatal(err)
	}
	var report advanceReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	return report
}
