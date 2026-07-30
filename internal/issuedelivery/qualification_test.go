package issuedelivery

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func TestAdvancePersistsRejectedQualificationCorrectionAndIndependentRereview(t *testing.T) {
	module, _, _ := moduleFixture(t, 370)
	request := Request{RepositoryPath: "/repo", IssueNumber: 370}

	qualified, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	originalPath := filepath.Join(module.storePathForTest(t, 370), "runs", qualified.RunID+".json")
	originalBytes, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	matrixHash, err := acceptanceMatrixDigest(qualified.Evidence.AcceptanceMatrix)
	if err != nil {
		t.Fatal(err)
	}
	_, err = module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 370,
		QualificationReview: &QualificationReview{
			AuthoritySHA256:        qualified.Observations.AuthoritySHA256,
			AcceptanceMatrixSHA256: matrixHash,
			Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "correction is required") {
		t.Fatalf("unresolved qualification approval error = %v", err)
	}
	rejected := qualified
	pending := rejected.QualificationCorrection
	if rejected.State != StateNeedsDecision || pending == nil ||
		len(pending.FindingIDs) != len(rejected.Evidence.AcceptanceMatrix) {
		t.Fatalf("compiled qualification correction = %#v", rejected)
	}
	resumed, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.State != StateNeedsDecision || resumed.QualificationCorrection == nil ||
		resumed.QualificationCorrection.ReviewedMatrixSHA256 != matrixHash {
		t.Fatalf("resumed rejected qualification = %#v", resumed)
	}
	revisions, err := os.ReadDir(filepath.Join(
		module.storePathForTest(t, 370), "revisions", qualified.RunID,
	))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(revisions) != 0 {
		t.Fatalf("new compiler correction request revisions = %d, want 0", len(revisions))
	}
	gotOriginal, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotOriginal, originalBytes) {
		t.Fatal("qualification rejection rewrote the original run bytes")
	}
	for _, test := range []struct {
		name string
		ids  []string
	}{
		{
			name: "duplicate",
			ids:  []string{pending.FindingIDs[0], pending.FindingIDs[0]},
		},
		{
			name: "foreign equal length",
			ids:  []string{pending.FindingIDs[0], "qualification-compiler-finding-ffffffffffffffff"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows := append(
				[]deliveryevidence.AcceptanceRow(nil), rejected.Evidence.AcceptanceMatrix...,
			)
			for index := range rows {
				rows[index].OwningSeam = "issuedelivery qualification correction boundary"
				rows[index].PositiveEvidence = "renderer positive behavior assertion"
				rows[index].NegativeEvidence = "renderer negative behavior assertion"
				rows[index].FailureEvidence = "renderer failure behavior assertion"
				rows[index].MutationEvidence = "renderer mutation boundary assertion"
				rows[index].CompatibilityEvidence = "renderer compatibility contract assertion"
				rows[index].PreservationEvidence = "renderer preservation contract assertion"
			}
			correction := compilerQualificationCorrectionForTest(
				pending, rows, "mapped renderer authority to observable contract assertions",
			)
			correction.FindingIDs = canonicalFindingIDs(test.ids)
			correction.Evidence = "[request:" + pending.ID + "] findings=" +
				strings.Join(correction.FindingIDs, ",") +
				"; rationale=mapped renderer authority to observable contract assertions"
			if _, advanceErr := module.Advance(context.Background(), Request{
				RepositoryPath: "/repo", IssueNumber: 370,
				QualificationCorrection: correction,
			}); advanceErr == nil ||
				!strings.Contains(advanceErr.Error(), "every finding") {
				t.Fatalf("invalid finding set error = %v", advanceErr)
			}
			current, readErr := os.ReadFile(originalPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(current, originalBytes) {
				t.Fatal("invalid finding set mutated active run bytes")
			}
			revisions, readErr := os.ReadDir(filepath.Join(
				module.storePathForTest(t, 370), "revisions", qualified.RunID,
			))
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if len(revisions) != 0 {
				t.Fatalf("invalid finding set revisions = %d, want 0", len(revisions))
			}
			resumed := mustAdvance(t, module, request)
			if resumed.State != StateNeedsDecision ||
				!reflect.DeepEqual(resumed.QualificationCorrection, pending) {
				t.Fatalf("invalid finding set damaged resume: %#v", resumed)
			}
		})
	}
	_, err = module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 370,
		QualificationCorrection: &QualificationCorrection{
			RequestID:            pending.ID,
			AuthoritySHA256:      rejected.Observations.AuthoritySHA256,
			ReviewedMatrixSHA256: matrixHash,
			FindingIDs:           pending.FindingIDs,
			AcceptanceMatrix:     rejected.Evidence.AcceptanceMatrix,
			Evidence:             "unresolved correction must fail closed",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unresolved qualification correction error = %v", err)
	}
	spacedSentinel := append(
		[]deliveryevidence.AcceptanceRow(nil), rejected.Evidence.AcceptanceMatrix...,
	)
	spacedSentinel[0].OwningSeam = "  QUALIFICATION CORRECTION REQUIRED  "
	_, err = module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 370,
		QualificationCorrection: &QualificationCorrection{
			RequestID:            pending.ID,
			AuthoritySHA256:      rejected.Observations.AuthoritySHA256,
			ReviewedMatrixSHA256: matrixHash,
			FindingIDs:           pending.FindingIDs,
			AcceptanceMatrix:     spacedSentinel,
			Evidence:             "normalized unresolved correction must fail closed",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("normalized unresolved qualification correction error = %v", err)
	}

	correctedRows := append([]deliveryevidence.AcceptanceRow(nil), rejected.Evidence.AcceptanceMatrix...)
	for index := range correctedRows {
		correctedRows[index].OwningSeam = "issuedelivery qualification test seam"
		correctedRows[index].PositiveEvidence = "planned: focused positive evidence"
		correctedRows[index].NegativeEvidence = "planned: focused negative evidence"
		correctedRows[index].FailureEvidence = "planned: focused failure evidence"
		correctedRows[index].MutationEvidence = "planned: focused mutation evidence"
		correctedRows[index].CompatibilityEvidence = "planned: focused compatibility evidence"
		correctedRows[index].PreservationEvidence = "planned: focused preservation evidence"
	}
	correctedRows[0].OwningSeam = "internal/cli pack-show renderer"
	correctedRows[0].PositiveEvidence = "planned: pack-show human renderer ordering test"
	_, err = module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 370,
		QualificationCorrection: &QualificationCorrection{
			RequestID:            pending.ID,
			AuthoritySHA256:      rejected.Observations.AuthoritySHA256,
			ReviewedMatrixSHA256: strings.Repeat("0", 64),
			FindingIDs:           pending.FindingIDs,
			AcceptanceMatrix:     correctedRows,
			Evidence:             "mismatched correction must fail closed",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched qualification correction error = %v", err)
	}
	reorderedIDs := append([]string(nil), pending.FindingIDs...)
	for left, right := 0, len(reorderedIDs)-1; left < right; left, right = left+1, right-1 {
		reorderedIDs[left], reorderedIDs[right] = reorderedIDs[right], reorderedIDs[left]
	}
	correction := compilerQualificationCorrectionForTest(
		pending, correctedRows,
		"mapped the criterion to its observable renderer and compatibility tests",
	)
	correction.FindingIDs = reorderedIDs
	corrected, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 370, QualificationCorrection: correction,
	})
	if err != nil {
		t.Fatal(err)
	}
	if corrected.State != StateNeedsReview || corrected.QualificationCorrection != nil ||
		corrected.Evidence.AcceptanceMatrix[0].OwningSeam !=
			correction.AcceptanceMatrix[0].OwningSeam {
		t.Fatalf("corrected qualification = %#v", corrected)
	}
	if !reflect.DeepEqual(
		corrected.QualificationCorrections[0].FindingIDs, pending.FindingIDs,
	) {
		t.Fatalf("stored compiler finding IDs are not canonical: %#v", corrected)
	}
	replayedCorrection, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 370, QualificationCorrection: correction,
	})
	if err != nil {
		t.Fatal(err)
	}
	if replayedCorrection.State != StateNeedsReview {
		t.Fatalf("replayed qualification correction = %#v", replayedCorrection)
	}
	assertQualificationRevisionCount(t, module, qualified.RunID, 1)
	correctedHash, err := acceptanceMatrixDigest(corrected.Evidence.AcceptanceMatrix)
	if err != nil {
		t.Fatal(err)
	}
	approval := &QualificationReview{
		AuthoritySHA256:        corrected.Observations.AuthoritySHA256,
		AcceptanceMatrixSHA256: correctedHash,
		Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
	}
	approved, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 370, QualificationReview: approval,
	})
	if err != nil {
		t.Fatal(err)
	}
	if approved.State != StateNeedsReview || !approved.QualificationApproved ||
		len(approved.QualificationReviews) != 1 || len(approved.QualificationCorrections) != 1 {
		t.Fatalf("approved qualification = %#v", approved)
	}
	if approved.PauseCause != PauseDeterministicAdvance || approved.NextAction != ActionAdvance {
		t.Fatalf("approved qualification pause metadata = %q, %q", approved.PauseCause, approved.NextAction)
	}
	replayedApproval, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 370, QualificationReview: approval,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !replayedApproval.QualificationApproved {
		t.Fatalf("replayed qualification approval = %#v", replayedApproval)
	}
	if replayedApproval.PauseCause != approved.PauseCause || replayedApproval.NextAction != approved.NextAction {
		t.Fatalf("replayed qualification pause metadata changed: approved=%#v replayed=%#v", approved, replayedApproval)
	}
	assertQualificationRevisionCount(t, module, qualified.RunID, 2)
	reloaded, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.QualificationApproved || len(reloaded.QualificationReviews) != 1 {
		t.Fatalf("reloaded approved qualification = %#v", reloaded)
	}
}

func TestAdvanceCompilesIssue347ProductSpecificQualificationEvidence(t *testing.T) {
	module, _, tracker := moduleFixture(t, 347)
	tracker.value.Title = "Make pack inspection and dry-run output easier to scan"
	tracker.value.Criteria = []AuthorityItem{
		{Text: "`packy pack show` presents a compact decision-oriented summary before detailed resource and surface contracts.", EvidenceLink: "issue#347:acceptance-1"},
		{Text: "Classic `--dry-run` output groups or summarizes repetitive actions before the complete action detail.", EvidenceLink: "issue#347:acceptance-2"},
		{Text: "Users can still obtain every planned action needed for safety and auditability.", EvidenceLink: "issue#347:acceptance-3"},
		{Text: "Existing versioned JSON schemas and redaction guarantees remain compatible.", EvidenceLink: "issue#347:acceptance-4"},
		{Text: "Human-output tests cover the new ordering and guidance.", EvidenceLink: "issue#347:acceptance-5"},
		{Text: "`./scripts/validate-packy.sh` passes.", EvidenceLink: "issue#347:acceptance-6"},
	}

	outcome, err := module.Advance(
		context.Background(), Request{RepositoryPath: "/repo", IssueNumber: 347},
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Candidate != nil || outcome.QualificationApproved {
		t.Fatalf("unqualified product criteria advanced: %#v", outcome)
	}
	pending := outcome.QualificationCorrection
	if pending == nil {
		t.Fatalf("compiler did not request product-specific qualification: %#v", outcome)
	}
	for _, row := range outcome.Evidence.AcceptanceMatrix {
		if row.OwningSeam != qualificationPlanRequired {
			t.Fatalf("unqualified criterion inferred a product seam: %#v", row)
		}
	}
	correctedRows := append(
		[]deliveryevidence.AcceptanceRow(nil), outcome.Evidence.AcceptanceMatrix...,
	)
	plans := []*deliveryevidence.AcceptanceRow{
		{
			OwningSeam:            "internal/cli pack-show human renderer",
			PositiveEvidence:      "planned: pack show summary ordering test",
			NegativeEvidence:      "planned: ordering regression test",
			FailureEvidence:       "planned: pack show actionable failure output",
			MutationEvidence:      "not applicable: pack show is read-only",
			CompatibilityEvidence: "planned: structured pack-show JSON compatibility",
			PreservationEvidence:  "planned: detailed resource contracts remain available",
		},
		{
			OwningSeam:            "internal/cli classic dry-run human renderer",
			PositiveEvidence:      "planned: dry-run groups actions before complete action detail",
			NegativeEvidence:      "planned: repetitive detail ordering regression test",
			FailureEvidence:       "planned: blocked-action guidance",
			MutationEvidence:      "planned: dry-run proves no lifecycle mutation",
			CompatibilityEvidence: "planned: structured dry-run JSON compatibility",
			PreservationEvidence:  "planned: complete action detail remains available",
		},
		{
			OwningSeam:            "internal/cli classic dry-run audit renderer",
			PositiveEvidence:      "planned: every action remains available for audit",
			NegativeEvidence:      "planned: omitted action fails preservation test",
			FailureEvidence:       "planned: incomplete audit detail blocks acceptance",
			MutationEvidence:      "planned: audit rendering is non-mutating",
			CompatibilityEvidence: "planned: action identity compatibility",
			PreservationEvidence:  "planned: complete action set is preserved",
		},
		{
			OwningSeam:            "versioned JSON and redaction contracts",
			PositiveEvidence:      "planned: JSON schema and redaction tests",
			NegativeEvidence:      "planned: sensitive value exposure fails tests",
			FailureEvidence:       "planned: incompatible JSON blocks acceptance",
			MutationEvidence:      "not applicable: serialization tests are observational",
			CompatibilityEvidence: "planned: versioned JSON remains compatible",
			PreservationEvidence:  "planned: redaction guarantees remain intact",
		},
		{
			OwningSeam:            "internal/cli human-output contract tests",
			PositiveEvidence:      "planned: human ordering and guidance tests",
			NegativeEvidence:      "planned: missing guidance fails tests",
			FailureEvidence:       "planned: blocked output remains actionable",
			MutationEvidence:      "not applicable: renderer tests do not mutate state",
			CompatibilityEvidence: "planned: JSON remains independent",
			PreservationEvidence:  "planned: detailed audit output remains available",
		},
		{
			OwningSeam:            "scripts/validate-packy.sh",
			PositiveEvidence:      "planned: exact validate-packy.sh success",
			NegativeEvidence:      "planned: candidate mismatch is rejected",
			FailureEvidence:       "planned: validator failure blocks readiness",
			MutationEvidence:      "not applicable: validation is read-only",
			CompatibilityEvidence: "planned: validator authority remains canonical",
			PreservationEvidence:  "planned: sandbox preserves operator configuration",
		},
	}
	plansByCriterion := make(map[string]*deliveryevidence.AcceptanceRow, len(plans))
	for index, plan := range plans {
		plansByCriterion[tracker.value.Criteria[index].Text] = plan
	}
	for index := range correctedRows {
		plan := plansByCriterion[correctedRows[index].Criterion]
		correctedRows[index].OwningSeam = plan.OwningSeam
		correctedRows[index].PositiveEvidence = plan.PositiveEvidence
		correctedRows[index].NegativeEvidence = plan.NegativeEvidence
		correctedRows[index].FailureEvidence = plan.FailureEvidence
		correctedRows[index].MutationEvidence = plan.MutationEvidence
		correctedRows[index].CompatibilityEvidence = plan.CompatibilityEvidence
		correctedRows[index].PreservationEvidence = plan.PreservationEvidence
	}
	corrected := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 347,
		QualificationCorrection: compilerQualificationCorrectionForTest(
			pending, correctedRows,
			"mapped every criterion to its explicit product evidence seam",
		),
	})
	rows := make(map[string]deliveryevidence.AcceptanceRow)
	for _, row := range corrected.Evidence.AcceptanceMatrix {
		rows[row.Criterion] = row
	}
	assertQualificationRowContains(t, rows[tracker.value.Criteria[0].Text], "pack show", "ordering")
	assertQualificationRowContains(t, rows[tracker.value.Criteria[1].Text], "dry-run", "complete action")
	assertQualificationRowContains(t, rows[tracker.value.Criteria[2].Text], "dry-run", "audit")
	assertQualificationRowContains(t, rows[tracker.value.Criteria[3].Text], "JSON", "redaction")
	assertQualificationRowContains(t, rows[tracker.value.Criteria[4].Text], "human", "guidance")
	assertQualificationRowContains(t, rows[tracker.value.Criteria[5].Text], "validate-packy.sh", "exact")
}

func TestCandidateInvalidationPreservesCorrectedQualificationEvidencePlan(t *testing.T) {
	fixture := assuranceFixtureWithoutQualification(t)
	module := fixture.module
	request := Request{RepositoryPath: "/repo", IssueNumber: 357}
	qualified := mustAdvance(t, module, request)
	pending := qualified.QualificationCorrection
	rows := append([]deliveryevidence.AcceptanceRow(nil), qualified.Evidence.AcceptanceMatrix...)
	for index := range rows {
		rows[index].OwningSeam = "specific supporting seam"
		rows[index].PositiveEvidence = "planned: supporting positive evidence"
		rows[index].NegativeEvidence = "planned: supporting negative evidence"
		rows[index].FailureEvidence = "planned: supporting failure evidence"
		rows[index].MutationEvidence = "planned: supporting mutation evidence"
		rows[index].CompatibilityEvidence = "planned: supporting compatibility evidence"
		rows[index].PreservationEvidence = "planned: supporting preservation evidence"
	}
	rows[0].OwningSeam = "specific product seam"
	rows[0].PositiveEvidence = "planned: specific positive evidence"
	rows[0].NegativeEvidence = "planned: specific negative evidence"
	rows[0].FailureEvidence = "planned: specific failure evidence"
	rows[0].MutationEvidence = "planned: specific mutation evidence"
	rows[0].CompatibilityEvidence = "planned: specific compatibility evidence"
	rows[0].PreservationEvidence = "planned: specific preservation evidence"
	corrected := mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		QualificationCorrection: compilerQualificationCorrectionForTest(
			pending, rows, "mapped the criterion to its specific product evidence",
		),
	})
	correctedHash, err := acceptanceMatrixDigest(corrected.Evidence.AcceptanceMatrix)
	if err != nil {
		t.Fatal(err)
	}
	mustAdvance(t, module, Request{
		RepositoryPath: "/repo", IssueNumber: 357,
		QualificationReview: &QualificationReview{
			AuthoritySHA256:        corrected.Observations.AuthoritySHA256,
			AcceptanceMatrixSHA256: correctedHash,
			Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
		},
	})
	candidate := mustAdvance(t, module, request)
	if candidate.Candidate == nil ||
		candidate.Evidence.AcceptanceMatrix[0].PositiveEvidence !=
			corrected.Evidence.AcceptanceMatrix[0].PositiveEvidence {
		t.Fatalf("candidate invalidated corrected qualification plan: %#v", candidate)
	}
}

func TestAdvanceResumesPreCorrectionV2MarkerRunWithDirectCompilerRequest(t *testing.T) {
	module, _, _ := moduleFixture(t, 371)
	request := Request{RepositoryPath: "/repo", IssueNumber: 371}
	created := mustAdvance(t, module, request)
	runPath := filepath.Join(module.storePathForTest(t, 371), "runs", created.RunID+".json")
	data, err := os.ReadFile(runPath)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeRun(data)
	if err != nil {
		t.Fatal(err)
	}
	record.PendingQualificationCorrection = nil
	record.State = StateNeedsReview
	record.Reason = "qualification evidence is ready for independent review"
	record.Timing[len(record.Timing)-1].To = StateNeedsReview
	historical, err := encodeRun(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runPath, historical, 0o600); err != nil {
		t.Fatal(err)
	}

	resumed := mustAdvance(t, module, request)
	if resumed.State != StateNeedsDecision || resumed.QualificationCorrection == nil ||
		len(resumed.QualificationReviews) != 0 {
		t.Fatalf("historical marker run did not converge to direct correction: %#v", resumed)
	}
	revisions, err := os.ReadDir(filepath.Join(
		module.storePathForTest(t, 371), "revisions", created.RunID,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(revisions) != 1 {
		t.Fatalf("historical marker convergence revisions = %d, want 1", len(revisions))
	}
}

func assertQualificationRevisionCount(t *testing.T, module *Module, runID string, want int) {
	t.Helper()
	revisions, err := os.ReadDir(filepath.Join(
		module.storePathForTest(t, 370), "revisions", runID,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(revisions) != want {
		t.Fatalf("qualification revisions = %d, want %d", len(revisions), want)
	}
}

func TestQualificationSeamValidationAllowsProofsButRejectsUnreviewedOwnership(t *testing.T) {
	corrected := []deliveryevidence.AcceptanceRow{{
		Identity: "criterion-1", Criterion: "Exact behavior.", OwningSeam: "reviewed seam",
		PositiveEvidence: "planned positive", State: deliveryevidence.AcceptancePlanned,
	}}
	proved := append([]deliveryevidence.AcceptanceRow(nil), corrected...)
	proved[0].PositiveEvidence = "candidate-specific positive proof"
	proved[0].State = deliveryevidence.AcceptanceProved
	if !qualificationSeamsMatchCorrection(proved, corrected) {
		t.Fatal("candidate proof invalidated the reviewed qualification seam")
	}
	proved[0].OwningSeam = "unreviewed seam"
	if qualificationSeamsMatchCorrection(proved, corrected) {
		t.Fatal("unreviewed qualification seam was accepted")
	}
}

func TestSpecificQualificationTextRejectsGenericAndMarkerVariants(t *testing.T) {
	for _, value := range []string{
		"implementation",
		"evidence",
		"planned evidence",
		"qualification correction required here",
		"planned implementation evidence",
		"updated qualification proof",
	} {
		t.Run(strings.ReplaceAll(value, " ", "_"), func(t *testing.T) {
			if specificQualificationText(value) {
				t.Fatalf("generic qualification text accepted: %q", value)
			}
		})
	}
	for _, value := range []string{
		"internal/cli pack-show renderer ordering contract",
		"candidate mismatch is rejected by the pack-show snapshot assertion",
	} {
		if !specificQualificationText(value) {
			t.Fatalf("substantive qualification text rejected: %q", value)
		}
	}
}

func TestQualificationMatrixRejectsGenericContentInEveryCorrectedCell(t *testing.T) {
	evidence := &deliveryevidence.Bundle{Scope: deliveryevidence.ScopeLedger{
		OwnedNow: []deliveryevidence.LedgerEntry{{
			Identity: "criterion-1", Requirement: "Render the compact pack summary.",
		}},
	}}
	base := deliveryevidence.AcceptanceRow{
		Identity: "criterion-1", Criterion: "Render the compact pack summary.",
		OwningSeam:            "internal/cli compact pack summary renderer",
		PositiveEvidence:      "pack summary ordering assertion covers the compact renderer",
		NegativeEvidence:      "expanded resource output rejects compact-only omissions",
		FailureEvidence:       "renderer failure reports the unavailable pack summary",
		MutationEvidence:      "read-only renderer leaves lifecycle resources unchanged",
		CompatibilityEvidence: "versioned pack JSON remains byte-compatible",
		PreservationEvidence:  "complete resource details remain available below the summary",
		MigrationEvidence:     "self-contained delivery has no persisted format migration",
		State:                 deliveryevidence.AcceptancePlanned,
	}
	fields := []struct {
		name string
		set  func(*deliveryevidence.AcceptanceRow, string)
	}{
		{"owning seam", func(row *deliveryevidence.AcceptanceRow, value string) { row.OwningSeam = value }},
		{"positive", func(row *deliveryevidence.AcceptanceRow, value string) { row.PositiveEvidence = value }},
		{"negative", func(row *deliveryevidence.AcceptanceRow, value string) { row.NegativeEvidence = value }},
		{"failure", func(row *deliveryevidence.AcceptanceRow, value string) { row.FailureEvidence = value }},
		{"mutation", func(row *deliveryevidence.AcceptanceRow, value string) { row.MutationEvidence = value }},
		{"compatibility", func(row *deliveryevidence.AcceptanceRow, value string) { row.CompatibilityEvidence = value }},
		{"preservation", func(row *deliveryevidence.AcceptanceRow, value string) { row.PreservationEvidence = value }},
		{"migration", func(row *deliveryevidence.AcceptanceRow, value string) { row.MigrationEvidence = value }},
	}
	for _, field := range fields {
		for _, generic := range []string{
			"implementation", "evidence", "planned evidence",
			"qualification correction required here",
		} {
			t.Run(field.name+"/"+strings.ReplaceAll(generic, " ", "_"), func(t *testing.T) {
				row := base
				field.set(&row, generic)
				if err := validateQualificationMatrix(
					evidence, []deliveryevidence.AcceptanceRow{row},
				); err == nil {
					t.Fatalf("%s accepted generic value %q", field.name, generic)
				}
			})
		}
	}
}

func TestCompilerQualificationBindingsRejectGenericAndForeignContent(t *testing.T) {
	pending := &QualificationCorrectionRequest{
		ID:         "qualification-compiler-request-binding",
		FindingIDs: []string{"finding-alpha", "finding-beta"},
	}
	rows := []deliveryevidence.AcceptanceRow{
		{
			Identity:              "criterion-aaaaaaaaaaaaaaaa",
			OwningSeam:            "pack summary renderer boundary",
			PositiveEvidence:      "summary ordering assertion",
			NegativeEvidence:      "omission regression assertion",
			FailureEvidence:       "renderer failure guidance",
			MutationEvidence:      "read-only lifecycle assertion",
			CompatibilityEvidence: "versioned JSON snapshot",
			PreservationEvidence:  "resource detail availability",
			MigrationEvidence:     "self-contained format disposition",
		},
		{
			Identity:              "criterion-bbbbbbbbbbbbbbbb",
			OwningSeam:            "dry-run audit renderer",
			PositiveEvidence:      "complete action assertion",
			NegativeEvidence:      "missing action regression",
			FailureEvidence:       "blocked action guidance",
			MutationEvidence:      "non-mutating execution assertion",
			CompatibilityEvidence: "action identity snapshot",
			PreservationEvidence:  "audit detail availability",
			MigrationEvidence:     "unchanged format disposition",
		},
	}
	valid := compilerQualificationCorrectionForTest(
		pending, rows, "mapped renderer authority to observable contract assertions",
	)
	if err := validateCompilerQualificationBindings(*valid); err != nil {
		t.Fatalf("valid distinct criterion bindings rejected: %v", err)
	}

	for _, value := range []string{
		"[request:" + pending.ID + "] findings=finding-alpha,finding-beta",
		"[request:" + pending.ID + "] findings=finding-alpha; rationale=" +
			"mapped renderer authority to observable contract assertions",
		"[request:wrong-request] findings=finding-alpha,finding-beta; rationale=" +
			"mapped renderer authority to observable contract assertions",
		"[request:" + pending.ID + "] findings=finding-alpha,finding-beta; rationale=",
		"[request:" + pending.ID + "] findings=finding-alpha,finding-beta; rationale=" +
			"mapped renderer authority; extra=field",
	} {
		correction := *valid
		correction.Evidence = value
		if err := validateCompilerQualificationBindings(correction); err == nil {
			t.Fatalf("compiler explanation binding accepted %q", value)
		}
	}

	fields := []struct {
		name string
		set  func(*deliveryevidence.AcceptanceRow, string)
	}{
		{"owning seam", func(row *deliveryevidence.AcceptanceRow, value string) { row.OwningSeam = value }},
		{"positive", func(row *deliveryevidence.AcceptanceRow, value string) { row.PositiveEvidence = value }},
		{"negative", func(row *deliveryevidence.AcceptanceRow, value string) { row.NegativeEvidence = value }},
		{"failure", func(row *deliveryevidence.AcceptanceRow, value string) { row.FailureEvidence = value }},
		{"mutation", func(row *deliveryevidence.AcceptanceRow, value string) { row.MutationEvidence = value }},
		{"compatibility", func(row *deliveryevidence.AcceptanceRow, value string) { row.CompatibilityEvidence = value }},
		{"preservation", func(row *deliveryevidence.AcceptanceRow, value string) { row.PreservationEvidence = value }},
		{"migration", func(row *deliveryevidence.AcceptanceRow, value string) { row.MigrationEvidence = value }},
	}
	for _, field := range fields {
		for _, value := range []string{
			"[criterion:criterion-aaaaaaaaaaaaaaaa] source=review:review status approved; assertion=" +
				"renderer contract assertion covers observable behavior",
			"[criterion:criterion-aaaaaaaaaaaaaaaa] source=review:validation status passed; assertion=" +
				"renderer contract assertion covers observable behavior",
			"[criterion:criterion-aaaaaaaaaaaaaaaa] source=review:review result accepted; assertion=" +
				"renderer contract assertion covers observable behavior",
			"[criterion:criterion-aaaaaaaaaaaaaaaa] source=status:review/status-approved; assertion=" +
				"renderer contract assertion covers observable behavior",
			"[criterion:criterion-aaaaaaaaaaaaaaaa] source=test:TestRendererContract",
			"[criterion:criterion-bbbbbbbbbbbbbbbb] source=test:TestRendererContract; assertion=" +
				"renderer contract assertion covers observable behavior",
			"[criterion:criterion-aaaaaaaaaaaaaaaa] source=test:TestRendererContract; assertion=",
			"[criterion:criterion-aaaaaaaaaaaaaaaa] source=test:TestRendererContract; assertion=" +
				"renderer contract assertion; extra=field",
		} {
			correction := *valid
			correction.AcceptanceMatrix = append(
				[]deliveryevidence.AcceptanceRow(nil), valid.AcceptanceMatrix...,
			)
			field.set(&correction.AcceptanceMatrix[0], value)
			if err := validateCompilerQualificationBindings(correction); err == nil {
				t.Fatalf("%s binding accepted %q", field.name, value)
			}
		}
	}
}

func TestQualificationHistoryRejectsSelfConsistentForgedCompilerRequest(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	var persisted []byte
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, 357,
		func(store lockedIssueStore) error {
			_, data, found, loadErr := store.loadActive()
			if loadErr != nil || !found {
				return loadErr
			}
			persisted = append([]byte(nil), data...)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*QualificationCorrection)
	}{
		{
			name: "matrix hash",
			mutate: func(correction *QualificationCorrection) {
				correction.ReviewedMatrixSHA256 = strings.Repeat("0", 64)
			},
		},
		{
			name: "finding set",
			mutate: func(correction *QualificationCorrection) {
				correction.FindingIDs = []string{"forged-compiler-finding"}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, decodeErr := decodeRun(persisted)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			correction := &record.QualificationCorrections[0]
			test.mutate(correction)
			correction.FindingIDs = canonicalFindingIDs(correction.FindingIDs)
			correction.RequestID = stableID(
				"qualification-compiler-request",
				correction.AuthoritySHA256+"\x00"+correction.ReviewedMatrixSHA256+
					"\x00"+strings.Join(correction.FindingIDs, "\x00"),
			)
			if err := validateQualificationHistory(record); err == nil ||
				!strings.Contains(err.Error(), "invalid compiler correction") {
				t.Fatalf("forged compiler correction validation error = %v", err)
			}
		})
	}
}

func TestDecodeV2PreservesHistoricalReviewerCorrectionWithPlannedEvidence(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	var record runRecord
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, 357,
		func(store lockedIssueStore) error {
			_, data, found, loadErr := store.loadActive()
			if loadErr != nil || !found {
				return loadErr
			}
			record, loadErr = decodeRun(data)
			return loadErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	rows := append(
		[]deliveryevidence.AcceptanceRow(nil), record.Evidence.AcceptanceMatrix...,
	)
	for index := range rows {
		rows[index].OwningSeam = "planned"
		rows[index].PositiveEvidence = "planned"
		rows[index].NegativeEvidence = "planned"
		rows[index].FailureEvidence = "planned"
		rows[index].MutationEvidence = "planned"
		rows[index].CompatibilityEvidence = "planned"
		rows[index].PreservationEvidence = "planned"
		rows[index].MigrationEvidence = "planned"
	}
	matrixHash, err := acceptanceMatrixDigest(rows)
	if err != nil {
		t.Fatal(err)
	}
	scope := record.Evidence.Scope.OwnedNow[0]
	finding := deliveryevidence.ReviewFinding{
		ID: "historical-reviewer-finding", Axis: deliveryevidence.ReviewSpec,
		Severity:  deliveryevidence.SeverityP1,
		Authority: deliveryevidence.AuthoritySpecRequirement,
		Citation:  scope.EvidenceLink, Location: scope.Identity,
		Evidence: "historical reviewer requested a planned evidence correction",
	}
	rejected := QualificationReview{
		AuthoritySHA256:        record.AuthoritySHA256,
		AcceptanceMatrixSHA256: record.QualificationReviews[0].AcceptanceMatrixSHA256,
		Findings:               []deliveryevidence.ReviewFinding{finding}, Completed: true,
	}
	approved := QualificationReview{
		AuthoritySHA256:        record.AuthoritySHA256,
		AcceptanceMatrixSHA256: matrixHash,
		Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
	}
	reviewerCorrection := QualificationCorrection{
		AuthoritySHA256:      record.AuthoritySHA256,
		ReviewedMatrixSHA256: rejected.AcceptanceMatrixSHA256,
		FindingIDs:           []string{finding.ID}, AcceptanceMatrix: rows,
		Evidence: "planned",
	}
	record.Evidence.AcceptanceMatrix = rows
	record.QualificationReviews = []QualificationReview{rejected, approved}
	record.QualificationCorrections = append(
		record.QualificationCorrections[:1], reviewerCorrection,
	)
	historical, err := encodeRun(record)
	if err != nil {
		t.Fatalf("encode canonical historical reviewer correction: %v", err)
	}
	decoded, err := decodeRun(historical)
	if err != nil {
		t.Fatalf("decode canonical historical reviewer correction: %v", err)
	}
	got := decoded.QualificationCorrections[1]
	if got.RequestID != "" || got.Evidence != "planned" ||
		got.AcceptanceMatrix[0].PositiveEvidence != "planned" {
		t.Fatalf("historical reviewer correction changed during decode: %#v", got)
	}
}

func TestQualificationHistoryRejectsNullFindingsAndInvalidCorrectionMatrices(t *testing.T) {
	module, git, _, _, _ := assuranceFixture(t)
	var record runRecord
	var persisted []byte
	err := module.store.withIssueLock(
		context.Background(), git.value.CommonDir, 357,
		func(store lockedIssueStore) error {
			_, data, found, loadErr := store.loadActive()
			if loadErr != nil || !found {
				return loadErr
			}
			persisted = append([]byte(nil), data...)
			record, loadErr = decodeRun(data)
			return loadErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	last := len(record.QualificationReviews) - 1
	record.QualificationReviews[last].Findings = nil
	if err := validateQualificationHistory(record); err == nil ||
		!strings.Contains(err.Error(), "invalid review") {
		t.Fatalf("null qualification findings validation error = %v", err)
	}
	record.QualificationReviews[last].Findings = []deliveryevidence.ReviewFinding{}
	record.QualificationCorrections[0].AcceptanceMatrix[0].OwningSeam =
		qualificationPlanRequired
	if err := validateQualificationHistory(record); err == nil ||
		!strings.Contains(err.Error(), "invalid compiler correction") {
		t.Fatalf("invalid correction matrix validation error = %v", err)
	}

	legacyNull := bytes.Replace(
		persisted,
		[]byte(`"findings":[],"completed":true`),
		[]byte(`"findings":null,"completed":true`),
		1,
	)
	if bytes.Equal(legacyNull, persisted) {
		t.Fatal("fixture did not contain an empty qualification findings array")
	}
	adopted, err := decodeRun(legacyNull)
	if err != nil {
		t.Fatalf("decode historical null qualification findings: %v", err)
	}
	if adopted.QualificationReviews[len(adopted.QualificationReviews)-1].Findings == nil {
		t.Fatal("historical null qualification findings were not adopted as an explicit array")
	}
	if !bytes.Equal(
		persisted,
		bytes.Replace(
			legacyNull,
			[]byte(`"findings":null,"completed":true`),
			[]byte(`"findings":[],"completed":true`),
			1,
		),
	) {
		t.Fatal("historical qualification bytes were not preserved during adoption")
	}

	pending := adopted
	pending.QualificationApproved = false
	pending.QualificationReviews = pending.QualificationReviews[:1]
	pending.Evidence.AcceptanceMatrix[0].OwningSeam = "different complete seam"
	if err := validateQualificationHistory(pending); err == nil ||
		!strings.Contains(err.Error(), "not ready for independent rereview") {
		t.Fatalf("unbound pending rereview matrix validation error = %v", err)
	}
}

func assertQualificationRowContains(
	t *testing.T,
	row deliveryevidence.AcceptanceRow,
	values ...string,
) {
	t.Helper()
	compiled := strings.ToLower(strings.Join([]string{
		row.OwningSeam, row.PositiveEvidence, row.NegativeEvidence, row.FailureEvidence,
		row.MutationEvidence, row.CompatibilityEvidence, row.PreservationEvidence,
	}, " "))
	for _, value := range values {
		if !strings.Contains(compiled, strings.ToLower(value)) {
			t.Fatalf("qualification row %q does not contain %q: %#v", row.Criterion, value, row)
		}
	}
}
