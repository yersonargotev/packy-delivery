package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type operatorWorkflowNonLocalGateway struct {
	observation issuedelivery.NonLocalObservation
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
	gateway.observation.PullRequests = []issuedelivery.RemotePullRequestObservation{{
		Number: 31, URL: "https://github.com/yersonargotev/packy/pull/31", State: "OPEN",
		BaseRef: "main", BaseSHA: strings.Repeat("a", 40),
		HeadBranch: request.HeadBranch, HeadSHA: request.HeadSHA,
		HeadRepositoryNodeID: request.Repository.NodeID,
		ClosingIssue:         request.Issue.Number,
	}}
	return nil
}

func (*operatorWorkflowNonLocalGateway) RetryInfrastructureCheck(
	context.Context,
	issuedelivery.RetryInfrastructureCheckRequest,
) error {
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
	fillOperatorReviewResponses(t, candidateDirectory)
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
				response.Candidate.Acceptance = productionPathAcceptance(
					issuedelivery.ReviewRequest{
						CandidateID:    response.Candidate.CandidateID,
						Axis:           response.Candidate.Axis,
						Iteration:      response.Candidate.Iteration,
						CommitSHA:      response.Candidate.CommitSHA,
						TreeSHA:        response.Candidate.TreeSHA,
						AcceptanceRows: packet.AcceptanceRows,
					},
				)
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
