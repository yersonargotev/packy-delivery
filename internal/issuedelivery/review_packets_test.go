package issuedelivery

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func TestReviewPacketsObservesCurrentRunWithoutWriting(t *testing.T) {
	module, git, _ := moduleFixture(t, 390)
	outcome, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 390,
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.QualificationCorrection == nil {
		t.Fatalf("qualification correction fixture = %#v", outcome)
	}
	rows := append([]deliveryevidence.AcceptanceRow(nil), outcome.Evidence.AcceptanceMatrix...)
	for index := range rows {
		rows[index].OwningSeam = "issuedelivery review packet fixture seam"
		rows[index].PositiveEvidence = "planned: packet positive evidence"
		rows[index].NegativeEvidence = "planned: packet negative evidence"
		rows[index].FailureEvidence = "planned: packet failure evidence"
		rows[index].MutationEvidence = "planned: packet mutation evidence"
		rows[index].CompatibilityEvidence = "planned: packet compatibility evidence"
		rows[index].PreservationEvidence = "planned: packet preservation evidence"
	}
	outcome, err = module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 390,
		QualificationCorrection: compilerQualificationCorrectionForTest(
			outcome.QualificationCorrection,
			rows,
			"bind review packet qualification evidence",
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.State != StateNeedsReview || outcome.QualificationApproved {
		t.Fatalf("qualification fixture = %#v", outcome)
	}
	before := snapshotRegularFiles(t, git.value.CommonDir)
	set, err := module.ReviewPackets(context.Background(), ReviewPacketRequest{
		RepositoryPath: "/repo", IssueNumber: 390, Kind: ReviewPacketQualification,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Packets) != 1 || set.Packets[0].Kind != ReviewPacketQualification {
		t.Fatalf("qualification packet set = %#v", set)
	}
	after := snapshotRegularFiles(t, git.value.CommonDir)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("review packet observation changed the run store")
	}
}

func TestReviewPacketsFromRecordAreDeterministicAndScoped(t *testing.T) {
	record, git := reviewPacketTestRecord()

	qualificationRecord := record
	qualificationRecord.QualificationApproved = false
	qualificationRecord.Candidates = nil
	qualification, err := reviewPacketsFromRecord(qualificationRecord, git, ReviewPacketRequest{Kind: ReviewPacketQualification})
	if err != nil || len(qualification) != 1 || qualification[0].Response.Qualification == nil {
		t.Fatalf("qualification packets = %#v, %v", qualification, err)
	}
	repeated, err := reviewPacketsFromRecord(qualificationRecord, git, ReviewPacketRequest{Kind: ReviewPacketQualification})
	if err != nil || !reflect.DeepEqual(qualification, repeated) {
		t.Fatalf("repeated qualification packets changed: %#v, %v", repeated, err)
	}

	candidates, err := reviewPacketsFromRecord(record, git, ReviewPacketRequest{Kind: ReviewPacketCandidate})
	if err != nil || len(candidates) != 2 {
		t.Fatalf("candidate packets = %#v, %v", candidates, err)
	}
	if candidates[0].PacketID == candidates[1].PacketID || candidates[0].Axis == candidates[1].Axis {
		t.Fatalf("candidate axes were not independently bound: %#v", candidates)
	}

	specialistRecord := record
	specialistRecord.Candidates = append([]Candidate(nil), record.Candidates...)
	specialistRecord.Candidates[0].Reviews = []CandidateReview{
		{CandidateID: record.Candidates[0].ID, Axis: deliveryevidence.ReviewStandards, Iteration: 1, CommitSHA: git.HeadSHA, TreeSHA: git.TreeSHA, Findings: []deliveryevidence.ReviewFinding{}, Completed: true},
		{CandidateID: record.Candidates[0].ID, Axis: deliveryevidence.ReviewSpec, Iteration: 1, CommitSHA: git.HeadSHA, TreeSHA: git.TreeSHA, Findings: []deliveryevidence.ReviewFinding{}, Completed: true},
	}
	specialists, err := reviewPacketsFromRecord(specialistRecord, git, ReviewPacketRequest{Kind: ReviewPacketSpecialist})
	if err != nil || len(specialists) != 2 {
		t.Fatalf("specialist packets = %#v, %v", specialists, err)
	}
	for _, packet := range specialists {
		if packet.Specialist == "" || packet.Response.Specialist == nil ||
			packet.Response.Specialist.PacketID != packet.PacketID || packet.RequiredBoundaryProof == nil ||
			packet.RequiredBoundaryProof.Boundary != packet.Boundary || !packet.RequiredBoundaryProof.Sandboxed ||
			!packet.RequiredBoundaryProof.IsolatedHome || !packet.RequiredBoundaryProof.IsolatedConfig ||
			!packet.RequiredBoundaryProof.NoOperatorMutation {
			t.Fatalf("specialist packet is not response-bound: %#v", packet)
		}
	}
}

func TestCandidatePacketResponseRestartReplayAndConflict(t *testing.T) {
	record, git := reviewPacketTestRecord()
	packets, err := reviewPacketsFromRecord(record, git, ReviewPacketRequest{Kind: ReviewPacketCandidate})
	if err != nil {
		t.Fatal(err)
	}
	var response, pending CandidateReview
	for _, packet := range packets {
		if packet.Axis == deliveryevidence.ReviewStandards {
			response = *packet.Response.Candidate
		} else {
			pending = *packet.Response.Candidate
		}
	}
	response.Completed = true
	response.ResponseSHA256 = strings.Repeat("2", 64)
	changed, err := reconcileCandidatePacketResponses(&record, &record.Candidates[0], []CandidateReview{response, pending})
	if err != nil || !changed || len(record.Candidates[0].Reviews) != 1 {
		t.Fatalf("partial persistence = %v, %v, %#v", changed, err, record.Candidates[0].Reviews)
	}

	restarted := record
	changed, err = reconcileCandidatePacketResponses(&restarted, &restarted.Candidates[0], []CandidateReview{response})
	if err != nil || changed {
		t.Fatalf("exact restart replay = %v, %v", changed, err)
	}
	differentBytes := response
	differentBytes.ResponseSHA256 = strings.Repeat("3", 64)
	if _, err := reconcileCandidatePacketResponses(&restarted, &restarted.Candidates[0], []CandidateReview{differentBytes}); err == nil {
		t.Fatal("semantically equal candidate response with different source digest was accepted")
	}
	conflict := response
	conflict.Findings = []deliveryevidence.ReviewFinding{{ID: "conflict", Axis: conflict.Axis}}
	if _, err := reconcileCandidatePacketResponses(&restarted, &restarted.Candidates[0], []CandidateReview{conflict}); err == nil {
		t.Fatal("conflicting persisted candidate packet response was accepted")
	}
}

func TestPacketFindingIDsAreScopedAcrossAxesAndBoundaries(t *testing.T) {
	record, git := reviewPacketTestRecord()
	record.Evidence.AcceptanceMatrix[0].Obligations = nil
	packets, err := reviewPacketsFromRecord(record, git, ReviewPacketRequest{Kind: ReviewPacketCandidate})
	if err != nil {
		t.Fatal(err)
	}
	responses := make([]CandidateReview, 0, 2)
	for i, packet := range packets {
		response := *packet.Response.Candidate
		response.Completed, response.ResponseSHA256 = true, strings.Repeat(string(rune('4'+i)), 64)
		response.Findings = []deliveryevidence.ReviewFinding{{ID: "same-local-id", Axis: response.Axis}}
		responses = append(responses, response)
	}
	if changed, err := reconcileCandidatePacketResponses(&record, &record.Candidates[0], responses); err != nil || !changed {
		t.Fatalf("cross-axis local finding IDs = %v, %v", changed, err)
	}
	if record.Candidates[0].Reviews[0].Findings[0].ID == record.Candidates[0].Reviews[1].Findings[0].ID {
		t.Fatal("cross-axis findings were not packet-qualified")
	}

	specialistRecord, specialistGit := reviewPacketTestRecord()
	candidate := &specialistRecord.Candidates[0]
	candidate.Reviews = []CandidateReview{
		{CandidateID: candidate.ID, Axis: deliveryevidence.ReviewStandards, Iteration: 1, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA, Findings: []deliveryevidence.ReviewFinding{}, Completed: true},
		{CandidateID: candidate.ID, Axis: deliveryevidence.ReviewSpec, Iteration: 1, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA, Findings: []deliveryevidence.ReviewFinding{}, Completed: true},
	}
	specialists, err := reviewPacketsFromRecord(specialistRecord, specialistGit, ReviewPacketRequest{Kind: ReviewPacketSpecialist})
	if err != nil {
		t.Fatal(err)
	}
	responsesSpecialist := make([]SpecialistReview, 0, 2)
	for i, packet := range specialists {
		response := *packet.Response.Specialist
		response.Completed, response.ResponseSHA256 = true, strings.Repeat(string(rune('6'+i)), 64)
		response.Findings = []SpecialistFinding{{ID: "same-local-id", Citation: "c", Location: "l", Evidence: "e"}}
		responsesSpecialist = append(responsesSpecialist, response)
	}
	if changed, err := reconcileSpecialistPacketResponses(&specialistRecord, candidate, responsesSpecialist); err != nil || !changed {
		t.Fatalf("cross-boundary local finding IDs = %v, %v", changed, err)
	}
	if candidate.SpecialistReviews[0].Findings[0].ID == candidate.SpecialistReviews[1].Findings[0].ID {
		t.Fatal("cross-boundary findings were not packet-qualified")
	}
}

func TestSpecialistPacketResponseRestartReplayAndConflict(t *testing.T) {
	record, _ := reviewPacketTestRecord()
	candidate := &record.Candidates[0]
	candidate.Reviews = []CandidateReview{
		{Axis: deliveryevidence.ReviewStandards, Completed: true}, {Axis: deliveryevidence.ReviewSpec, Completed: true},
	}
	response := SpecialistReview{PacketID: specialistPacketID(record, *candidate, BoundaryGovernance), ResponseSHA256: strings.Repeat("2", 64), CandidateID: candidate.ID, Boundary: BoundaryGovernance, Specialist: specialistForBoundary(BoundaryGovernance), Findings: []SpecialistFinding{}, Completed: true}
	changed, err := reconcileSpecialistPacketResponses(&record, candidate, []SpecialistReview{response})
	if err != nil || !changed {
		t.Fatalf("partial specialist persistence = %v, %v", changed, err)
	}
	restarted := record
	changed, err = reconcileSpecialistPacketResponses(&restarted, &restarted.Candidates[0], []SpecialistReview{response})
	if err != nil || changed {
		t.Fatalf("exact specialist replay = %v, %v", changed, err)
	}
	conflict := response
	conflict.Findings = []SpecialistFinding{{ID: "conflict", Citation: "c", Location: "l", Evidence: "e"}}
	if _, err := reconcileSpecialistPacketResponses(&restarted, &restarted.Candidates[0], []SpecialistReview{conflict}); err == nil {
		t.Fatal("conflicting persisted specialist response was accepted")
	}
}

func TestPacketBoundCandidateReviewRejectsMismatchAndDuplicateFinding(t *testing.T) {
	record, git := reviewPacketTestRecord()
	packet, err := reviewPacketsFromRecord(record, git, ReviewPacketRequest{
		Kind: ReviewPacketCandidate, Axis: deliveryevidence.ReviewStandards,
	})
	if err != nil || len(packet) != 1 {
		t.Fatalf("packet = %#v, %v", packet, err)
	}
	candidate := record.Candidates[0]
	review := *packet[0].Response.Candidate
	review.Completed = true
	review.Findings = []deliveryevidence.ReviewFinding{{
		ID: "duplicate", Axis: review.Axis,
	}, {ID: "duplicate", Axis: review.Axis}}
	if err := validateCandidateReview(review, candidate, candidate.RequiredReviews, 1, packet[0].PacketID); err == nil {
		t.Fatal("duplicate finding IDs were accepted")
	}
	review.Findings = []deliveryevidence.ReviewFinding{}
	review.PacketID = strings.Repeat("f", 64)
	if err := validateCandidateReview(review, candidate, candidate.RequiredReviews, 1, packet[0].PacketID); err == nil {
		t.Fatal("mismatched packet ID was accepted")
	}
	review.PacketID = ""
	if err := validateCandidateReview(review, candidate, candidate.RequiredReviews, 1, packet[0].PacketID); err != nil {
		t.Fatalf("legacy empty packet ID was rejected: %v", err)
	}
}

func reviewPacketTestRecord() (runRecord, GitObservation) {
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	record := runRecord{
		Schema: runSchema, ID: strings.Repeat("c", 64), AuthoritySHA256: strings.Repeat("d", 64),
		State: StateNeedsReview, QualificationApproved: true,
		Repository: deliveryevidence.RepositoryIdentity{Owner: "owner", Name: "repo", NodeID: "R_1"},
		Issue:      deliveryevidence.IssueIdentity{Number: 30, NodeID: "I_30"},
		Evidence: &deliveryevidence.Bundle{
			Authority:        deliveryevidence.Authority{IssueSHA256: strings.Repeat("e", 64), Labels: []string{}, DependencyDisposition: []deliveryevidence.DependencyDisposition{}, AcceptanceCriteria: []string{"AC-1"}},
			AcceptanceMatrix: []deliveryevidence.AcceptanceRow{{Identity: "AC-1", Criterion: "packet contract", Obligations: deliveryevidence.PhaseOwnedAcceptanceObligations()}},
		},
		Candidates: []Candidate{{
			ID: strings.Repeat("1", 64), BaseSHA: strings.Repeat("9", 40), CommitSHA: commit, TreeSHA: tree,
			RequiredReviews: bothReviewAxes(), ReviewIteration: 1, Reviews: []CandidateReview{},
			RequiredSpecialists: []SensitiveBoundary{BoundaryGovernance, BoundarySecurity}, SpecialistReviews: []SpecialistReview{},
		}},
	}
	return record, GitObservation{HeadSHA: commit, TreeSHA: tree}
}
