package issuedelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func TestDecodeLegacyRunPreservesCanonicalV1SemanticsAndEncoding(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)

	var current runRecord
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, request.IssueNumber,
		func(store lockedIssueStore) error {
			_, data, found, loadErr := store.loadActive()
			if loadErr != nil {
				return loadErr
			}
			if !found {
				t.Fatal("active run not found")
			}
			current, loadErr = decodeRun(data)
			return loadErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := deliveryevidence.CanonicalJSON(*current.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	legacyCandidates := make([]legacyCandidate, 0, len(current.Candidates))
	for _, candidate := range current.Candidates {
		legacyCandidates = append(legacyCandidates, legacyCandidate{
			ID: candidate.ID, BaseSHA: candidate.BaseSHA, CommitSHA: candidate.CommitSHA,
			TreeSHA: candidate.TreeSHA, RepairClass: candidate.RepairClass,
			RequiredReviews: candidate.RequiredReviews, Reviews: candidate.Reviews,
			Acceptance: candidate.Acceptance, Focused: candidate.Focused,
			Exhaustive: candidate.Exhaustive, RepairDecision: candidate.RepairDecision,
		})
	}
	legacyBytes, err := json.Marshal(legacyRunWire{
		Schema: legacyRunSchema, ID: current.ID,
		Repository: current.Repository, Issue: current.Issue,
		AuthoritySHA256: current.AuthoritySHA256, State: current.State, Reason: current.Reason,
		SupersedesRunID: current.SupersedesRunID,
		Evidence:        bytes.TrimSuffix(evidence, []byte{'\n'}),
		PendingDecision: current.PendingDecision, Decisions: current.Decisions,
		Observations: current.Observations, Candidates: legacyCandidates,
		PendingRepair: current.PendingRepair, LocalReadiness: current.LocalReadiness,
		Timing: current.Timing, CreatedAt: current.CreatedAt, UpdatedAt: current.UpdatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := decodeRun(legacyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != legacyRunSchema ||
		decoded.EffectiveProfile != "" ||
		len(decoded.Candidates) != 1 ||
		decoded.Candidates[0].Profile != "" ||
		decoded.Candidates[0].Effects != nil ||
		decoded.ProfileHistory != nil {
		t.Fatalf("decoded legacy run=%#v", decoded)
	}
	encoded, err := encodeRun(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, legacyBytes) {
		t.Fatalf("v1 encoding changed:\n got %s\nwant %s", encoded, legacyBytes)
	}

	var invalid legacyRunWire
	if err := json.Unmarshal(legacyBytes, &invalid); err != nil {
		t.Fatal(err)
	}
	invalid.Candidates[0].RepairDecision = &RepairDecision{
		CandidateID: invalid.Candidates[0].ID,
		Class:       RepairAdjudicationOnly,
		Findings:    []FindingDecision{},
	}
	invalidBytes, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRun(invalidBytes); err == nil ||
		!strings.Contains(err.Error(), "invalid repair decision") {
		t.Fatalf("legacy adjudication-only record decode error=%v", err)
	}
}

func TestLegacyRunContinuesUnderV1AssuranceWithoutRiskReclassification(t *testing.T) {
	module, git, tracker, _, validator := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	risk := module.risk.(*fakeCandidateRiskObserver)
	initialRiskCalls := risk.calls

	var outcome Outcome
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, request.IssueNumber,
		func(store lockedIssueStore) error {
			_, data, _, loadErr := store.loadActive()
			if loadErr != nil {
				return loadErr
			}
			record, loadErr := decodeRun(data)
			if loadErr != nil {
				return loadErr
			}
			record.Schema = legacyRunSchema
			record.Evidence.CandidateReviewReceipts = nil
			record.Evidence.AssuranceAdjudications = nil
			record.Evidence.AssurancePhases = nil
			record.Evidence.ExhaustiveAssurance = nil
			record.EffectiveProfile = ""
			record.RequiredBoundaries = nil
			record.ProfileHistory = nil
			for index := range record.Evidence.AcceptanceMatrix {
				record.Evidence.AcceptanceMatrix[index].Obligations = nil
			}
			for index := range record.Candidates {
				record.Candidates[index].ObservedFloor = ""
				record.Candidates[index].Profile = ""
				record.Candidates[index].Effects = nil
				record.Candidates[index].Boundaries = nil
				record.Candidates[index].RequiredSpecialists = nil
				record.Candidates[index].SpecialistReviews = nil
				record.Candidates[index].BoundaryProofs = nil
			}
			compiled, compileErr := compileAuthority(
				git.value, tracker.value, record.Decisions, nil, deliveryevidence.RiskStandard,
			)
			if compileErr != nil {
				return compileErr
			}
			outcome, loadErr = module.advanceAssurance(
				context.Background(), store, record, git.value, tracker.value, compiled, request,
			)
			return loadErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.State != StateNeedsReview || outcome.Candidate == nil ||
		len(outcome.Candidate.Reviews) != 2 || risk.calls != initialRiskCalls {
		t.Fatalf("legacy continuation outcome=%#v risk calls=%d", outcome, risk.calls)
	}
	err = module.store.withIssueLock(
		context.Background(), git.value.CommonDir, request.IssueNumber,
		func(store lockedIssueStore) error {
			_, data, _, loadErr := store.loadActive()
			if loadErr != nil {
				return loadErr
			}
			var envelope struct {
				Schema string `json:"schema"`
			}
			if loadErr = json.Unmarshal(data, &envelope); loadErr != nil {
				return loadErr
			}
			if envelope.Schema != legacyRunSchema {
				t.Fatalf("continued legacy schema=%q", envelope.Schema)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	validator.missingNegative = true
	if _, err = module.Advance(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "explicit legacy-v1") {
		t.Fatalf("normal Advance admitted legacy v1 run: %v", err)
	}
	module.allowLegacyV1 = true
	blocked := mustAdvance(t, module, request)
	if blocked.State != StateBlocked ||
		!strings.Contains(blocked.Reason, "acceptance traceability") ||
		risk.calls != initialRiskCalls {
		t.Fatalf("weakened legacy acceptance outcome=%#v risk calls=%d", blocked, risk.calls)
	}
	timingBeforeSuccessfulExhaustive := len(blocked.Timing)
	validator.missingNegative = false
	validator.afterExhaustive = func() {
		git.value.Branch = "main"
	}
	completed := mustAdvance(t, module, request)
	if completed.State != StateBlocked || completed.Candidate == nil || completed.Candidate.Exhaustive == nil {
		t.Fatalf("legacy exhaustive continuation outcome=%#v", completed)
	}
	if len(completed.Timing) != timingBeforeSuccessfulExhaustive+1 ||
		completed.Timing[len(completed.Timing)-1].Phase != "local-readiness" {
		t.Fatalf("legacy exhaustive changed the v1 transition timing shape: before=%d after=%#v",
			timingBeforeSuccessfulExhaustive, completed.Timing)
	}
	for _, timing := range completed.Timing {
		if timing.Phase == exhaustiveValidationSucceededPhase {
			t.Fatalf("legacy v1 run emitted v2 successful exhaustive timing: %#v", timing)
		}
	}
}

func TestLegacyRunAtStartingHeadStillCreatesHistoricalCandidate(t *testing.T) {
	module, git, tracker, _, validator := assuranceFixture(t)
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	git.value.HeadSHA = git.value.StartingBaseSHA
	risk := module.risk.(*fakeCandidateRiskObserver)
	initialRiskCalls := risk.calls

	var outcome Outcome
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, request.IssueNumber,
		func(store lockedIssueStore) error {
			_, data, _, loadErr := store.loadActive()
			if loadErr != nil {
				return loadErr
			}
			record, loadErr := decodeRun(data)
			if loadErr != nil {
				return loadErr
			}
			record.Schema = legacyRunSchema
			record.Evidence.CandidateReviewReceipts = nil
			record.Evidence.AssuranceAdjudications = nil
			record.Evidence.AssurancePhases = nil
			record.Evidence.ExhaustiveAssurance = nil
			record.EffectiveProfile = ""
			record.RequiredBoundaries = nil
			record.ProfileHistory = nil
			for index := range record.Evidence.AcceptanceMatrix {
				record.Evidence.AcceptanceMatrix[index].Obligations = nil
			}
			compiled, compileErr := compileAuthority(
				git.value, tracker.value, record.Decisions, nil, deliveryevidence.RiskStandard,
			)
			if compileErr != nil {
				return compileErr
			}
			outcome, loadErr = module.advanceAssurance(
				context.Background(), store, record, git.value, tracker.value, compiled, request,
			)
			return loadErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.State != StateNeedsReview || outcome.Candidate == nil ||
		outcome.Candidate.CommitSHA != git.value.StartingBaseSHA ||
		validator.focusedCalls != 1 || risk.calls != initialRiskCalls {
		t.Fatalf("same-head legacy outcome=%#v risk calls=%d", outcome, risk.calls)
	}
}

func TestLegacyRepairDecisionOptionsAndAcceptanceRemainV1(t *testing.T) {
	request := repairDecisionRequest(legacyRunSchema, "candidate", []string{"finding"})
	if !reflect.DeepEqual(request.Options, []RepairClass{RepairBounded, RepairCandidateChanging}) {
		t.Fatalf("legacy repair options=%v", request.Options)
	}
	module := &Module{}
	record := runRecord{
		Schema: legacyRunSchema,
		Candidates: []Candidate{{
			ID: "candidate",
		}},
		PendingRepair: request,
	}
	_, err := module.applyRepairDecision(lockedIssueStore{}, record, RepairDecision{
		CandidateID: "candidate", Class: RepairAdjudicationOnly,
		Findings: []FindingDecision{{
			FindingID: "finding", Disposition: FindingRejected, Evidence: "evidence",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid repair class") {
		t.Fatalf("legacy adjudication-only acceptance error=%v", err)
	}
}

func TestLegacyCandidateChangingRejectedOnlyDecisionRetainsRuntimeSemantics(t *testing.T) {
	module, git, tracker, reviewer, _ := assuranceFixture(t)
	reviewer.responses[deliveryevidence.ReviewSpec] = []CandidateReview{{
		Completed: true,
		Findings: []deliveryevidence.ReviewFinding{{
			ID: "legacy-rejected", Axis: deliveryevidence.ReviewSpec,
			Severity: deliveryevidence.SeverityP2, Authority: deliveryevidence.AuthoritySpecRequirement,
			Citation: "issue#357", Location: "internal/issuedelivery/record_v1_test.go",
			Evidence: "legacy candidate-changing finding",
		}},
	}}
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	mustAdvance(t, module, request)
	mustAdvance(t, module, request)
	found := mustAdvance(t, module, request)
	git.value.HeadSHA, git.value.TreeSHA = strings.Repeat("d", 40), strings.Repeat("e", 40)

	var outcome Outcome
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, request.IssueNumber,
		func(store lockedIssueStore) error {
			_, data, _, loadErr := store.loadActive()
			if loadErr != nil {
				return loadErr
			}
			record, loadErr := decodeRun(data)
			if loadErr != nil {
				return loadErr
			}
			record.Schema = legacyRunSchema
			record.EffectiveProfile = ""
			record.RequiredBoundaries = nil
			record.ProfileHistory = nil
			for index := range record.Candidates {
				record.Candidates[index].ObservedFloor = ""
				record.Candidates[index].Profile = ""
				record.Candidates[index].Effects = nil
				record.Candidates[index].Boundaries = nil
				record.Candidates[index].RequiredSpecialists = nil
				record.Candidates[index].SpecialistReviews = nil
				record.Candidates[index].BoundaryProofs = nil
			}
			compiled, compileErr := compileAuthority(
				git.value, tracker.value, record.Decisions, nil, deliveryevidence.RiskStandard,
			)
			if compileErr != nil {
				return compileErr
			}
			legacyRequest := request
			legacyRequest.Repair = &RepairDecision{
				CandidateID: found.Repair.CandidateID, Class: RepairCandidateChanging,
				Findings: []FindingDecision{{
					FindingID: "legacy-rejected", Disposition: FindingRejected,
					Evidence: "legacy evidence rejects finding",
				}},
			}
			outcome, loadErr = module.advanceAssurance(
				context.Background(), store, record, git.value, tracker.value, compiled, legacyRequest,
			)
			return loadErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.State != StateNeedsReview || outcome.Candidate == nil ||
		outcome.Candidate.RepairDecision == nil ||
		outcome.Candidate.RepairDecision.Class != RepairCandidateChanging ||
		len(outcome.Candidate.RepairBatches) != 0 ||
		outcome.Candidate.LastRepairBatch != nil {
		t.Fatalf("legacy candidate-changing rejected-only outcome=%#v", outcome)
	}
	err = module.store.withIssueLock(
		context.Background(), git.value.CommonDir, request.IssueNumber,
		func(store lockedIssueStore) error {
			_, data, found, loadErr := store.loadActive()
			if loadErr != nil || !found {
				return loadErr
			}
			resumed, decodeErr := decodeRun(data)
			if decodeErr != nil {
				return decodeErr
			}
			if len(resumed.Candidates[len(resumed.Candidates)-1].RepairBatches) != 0 ||
				resumed.Candidates[len(resumed.Candidates)-1].LastRepairBatch != nil {
				return errors.New("legacy persisted candidate contains a last repair batch")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}
