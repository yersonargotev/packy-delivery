package issuedelivery

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func TestDecodeV2RejectsInvalidPersistedRepairDecision(t *testing.T) {
	module, git, _, reviewer, _ := assuranceFixture(t)
	reviewer.responses[deliveryevidence.ReviewStandards] = []CandidateReview{{
		Completed: true,
		Findings: []deliveryevidence.ReviewFinding{{
			ID: "persisted-standards", Axis: deliveryevidence.ReviewStandards,
			Severity: deliveryevidence.SeverityP2, Authority: deliveryevidence.AuthorityDocumentedStandard,
			Citation: "AGENTS.md", Location: "internal/issuedelivery/record.go", Evidence: "standards finding",
		}},
	}}
	reviewer.responses[deliveryevidence.ReviewSpec] = []CandidateReview{{
		Completed: true,
		Findings: []deliveryevidence.ReviewFinding{{
			ID: "persisted-spec", Axis: deliveryevidence.ReviewSpec,
			Severity: deliveryevidence.SeverityP2, Authority: deliveryevidence.AuthoritySpecRequirement,
			Citation: "issue#357", Location: "internal/issuedelivery/record.go", Evidence: "spec finding",
		}},
	}}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	found := mustAdvance(t, module, request)
	mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		Repair: &RepairDecision{
			CandidateID: found.Repair.CandidateID, Class: RepairAdjudicationOnly,
			Findings: []FindingDecision{
				{FindingID: "persisted-standards", Disposition: FindingRejected, Evidence: "standards rebuttal"},
				{FindingID: "persisted-spec", Disposition: FindingRejected, Evidence: "spec rebuttal"},
			},
		},
	})

	var valid []byte
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, request.IssueNumber,
		func(store lockedIssueStore) error {
			_, data, _, loadErr := store.loadActive()
			valid = append([]byte(nil), data...)
			return loadErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRun(valid); err != nil {
		t.Fatalf("valid persisted adjudication failed decode: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*runWire)
	}{
		{
			name: "unsupported class",
			mutate: func(wire *runWire) {
				wire.Candidates[0].RepairDecision.Class = RepairClass("unsupported")
			},
		},
		{
			name: "missing finding",
			mutate: func(wire *runWire) {
				wire.Candidates[0].RepairDecision.Findings =
					wire.Candidates[0].RepairDecision.Findings[:1]
			},
		},
		{
			name: "duplicate finding",
			mutate: func(wire *runWire) {
				wire.Candidates[0].RepairDecision.Findings[1].FindingID =
					wire.Candidates[0].RepairDecision.Findings[0].FindingID
			},
		},
		{
			name: "unsupported disposition",
			mutate: func(wire *runWire) {
				wire.Candidates[0].RepairDecision.Findings[0].Disposition =
					FindingDisposition("unsupported")
			},
		},
		{
			name: "blank evidence",
			mutate: func(wire *runWire) {
				wire.Candidates[0].RepairDecision.Findings[0].Evidence = " "
			},
		},
		{
			name: "candidate identity",
			mutate: func(wire *runWire) {
				wire.Candidates[0].RepairDecision.CandidateID = "different-candidate"
			},
		},
		{
			name: "adjudication-only accepted finding",
			mutate: func(wire *runWire) {
				wire.Candidates[0].RepairDecision.Findings[0].Disposition = FindingAccepted
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var wire runWire
			if err := json.Unmarshal(valid, &wire); err != nil {
				t.Fatal(err)
			}
			test.mutate(&wire)
			corrupt, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeRun(corrupt); err == nil ||
				!strings.Contains(err.Error(), "invalid repair decision") {
				t.Fatalf("corrupt repair decision decode error=%v", err)
			}
		})
	}

	var historical runWire
	if err := json.Unmarshal(valid, &historical); err != nil {
		t.Fatal(err)
	}
	historical.Candidates[0].RepairDecision.Class = RepairCandidateChanging
	historical.Candidates[0].RepairBatches = nil
	historical.Candidates[0].LastRepairBatch = nil
	evidence, err := deliveryevidence.Decode(append(append([]byte(nil), historical.Evidence...), '\n'))
	if err != nil {
		t.Fatal(err)
	}
	evidence.AssuranceAdjudications = nil
	canonicalEvidence, err := deliveryevidence.CanonicalJSON(evidence)
	if err != nil {
		t.Fatal(err)
	}
	historical.Evidence = append(json.RawMessage(nil), canonicalEvidence[:len(canonicalEvidence)-1]...)
	historicalBytes, err := json.Marshal(historical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRun(historicalBytes); err != nil {
		t.Fatalf("historical candidate-changing all-rejected record failed decode: %v", err)
	}
}
