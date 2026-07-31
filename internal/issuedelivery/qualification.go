package issuedelivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

type QualificationReview struct {
	PacketID               string                           `json:"packet_id,omitempty"`
	PacketSHA256           string                           `json:"packet_sha256,omitempty"`
	ResponseSHA256         string                           `json:"response_sha256,omitempty"`
	AuthoritySHA256        string                           `json:"authority_sha256"`
	AcceptanceMatrixSHA256 string                           `json:"acceptance_matrix_sha256"`
	Findings               []deliveryevidence.ReviewFinding `json:"findings"`
	Completed              bool                             `json:"completed"`
}

type QualificationCorrectionRequest struct {
	ID                   string                 `json:"id,omitempty"`
	AuthoritySHA256      string                 `json:"authority_sha256"`
	ReviewedMatrixSHA256 string                 `json:"reviewed_matrix_sha256"`
	FindingIDs           []string               `json:"finding_ids"`
	Findings             []QualificationFinding `json:"findings,omitempty"`
}

type QualificationFinding struct {
	ID          string `json:"id"`
	CriterionID string `json:"criterion_id"`
	Criterion   string `json:"criterion"`
	Evidence    string `json:"evidence"`
}

type QualificationCorrection struct {
	RequestID            string                           `json:"request_id,omitempty"`
	AuthoritySHA256      string                           `json:"authority_sha256"`
	ReviewedMatrixSHA256 string                           `json:"reviewed_matrix_sha256"`
	FindingIDs           []string                         `json:"finding_ids"`
	AcceptanceMatrix     []deliveryevidence.AcceptanceRow `json:"acceptance_matrix"`
	Evidence             string                           `json:"evidence"`
}

func (m *Module) advanceQualification(
	store lockedIssueStore,
	record runRecord,
	request Request,
) (Outcome, bool, error) {
	review, correction := request.QualificationReview, request.QualificationCorrection
	if review != nil && correction != nil {
		return Outcome{}, true, errors.New("one Advance call cannot review and correct qualification")
	}
	if review != nil && len(record.QualificationReviews) > 0 &&
		reflect.DeepEqual(*review, record.QualificationReviews[len(record.QualificationReviews)-1]) {
		return outcomeFromRecord(record), true, nil
	}
	if correction != nil {
		canonical := canonicalQualificationCorrection(*correction)
		correction = &canonical
		if len(record.QualificationCorrections) > 0 &&
			reflect.DeepEqual(canonical, record.QualificationCorrections[len(record.QualificationCorrections)-1]) {
			return outcomeFromRecord(record), true, nil
		}
	}
	if record.PendingQualificationCorrection != nil {
		if correction == nil {
			if review != nil {
				return Outcome{}, true, errors.New("qualification correction is required before independent rereview")
			}
			return outcomeFromRecord(record), true, nil
		}
		if err := validateQualificationCorrection(record, *correction); err != nil {
			return Outcome{}, true, err
		}
		nextEvidence := *record.Evidence
		nextEvidence.AcceptanceMatrix = append(
			[]deliveryevidence.AcceptanceRow(nil), correction.AcceptanceMatrix...,
		)
		if requiresQualificationCorrection(&nextEvidence) {
			return Outcome{}, true, errors.New("qualification correction must resolve every acceptance row")
		}
		if err := deliveryevidence.Validate(nextEvidence); err != nil {
			return Outcome{}, true, fmt.Errorf("corrected qualification evidence is invalid: %w", err)
		}
		stored := *correction
		stored.FindingIDs = canonicalFindingIDs(correction.FindingIDs)
		stored.AcceptanceMatrix = append(
			[]deliveryevidence.AcceptanceRow(nil), correction.AcceptanceMatrix...,
		)
		record.Evidence = &nextEvidence
		record.QualificationCorrections = append(record.QualificationCorrections, stored)
		record.PendingQualificationCorrection = nil
		record.QualificationApproved = false
		outcome, err := m.persistAssuranceTransition(
			store, record, StateNeedsReview,
			"corrected qualification evidence is ready for independent rereview",
			"qualification-correction",
		)
		return outcome, true, err
	}
	if correction != nil {
		return Outcome{}, true, errors.New("qualification correction was not requested")
	}
	if record.State != StateBlocked && !record.QualificationApproved &&
		requiresQualificationCorrection(record.Evidence) {
		pending, err := compilerQualificationCorrectionRequest(record.AuthoritySHA256, record.Evidence)
		if err != nil {
			return Outcome{}, true, err
		}
		record.PendingQualificationCorrection = pending
		outcome, err := m.persistAssuranceTransition(
			store, record, StateNeedsDecision,
			"compiler qualification findings require one persisted correction",
			"qualification-compiler",
		)
		return outcome, true, err
	}
	if review == nil {
		return Outcome{}, false, nil
	}
	if record.QualificationApproved {
		return Outcome{}, true, errors.New("qualification is already independently approved")
	}
	if err := validateQualificationReview(record, *review); err != nil {
		return Outcome{}, true, err
	}
	if len(review.Findings) == 0 && requiresQualificationCorrection(record.Evidence) {
		return Outcome{}, true, errors.New("qualification approval requires every acceptance row to be resolved")
	}
	stored := *review
	stored.Findings = append([]deliveryevidence.ReviewFinding{}, review.Findings...)
	record.QualificationReviews = append(record.QualificationReviews, stored)
	if len(stored.Findings) == 0 {
		record.QualificationApproved = true
		outcome, err := m.persistAssuranceTransition(
			store, record, StateNeedsReview,
			"qualification evidence passed independent review",
			"qualification-review",
		)
		return outcome, true, err
	}
	findingIDs := make([]string, 0, len(stored.Findings))
	for _, finding := range stored.Findings {
		findingIDs = append(findingIDs, finding.ID)
	}
	sort.Strings(findingIDs)
	record.PendingQualificationCorrection = &QualificationCorrectionRequest{
		AuthoritySHA256:      record.AuthoritySHA256,
		ReviewedMatrixSHA256: stored.AcceptanceMatrixSHA256,
		FindingIDs:           findingIDs,
	}
	record.QualificationApproved = false
	outcome, err := m.persistAssuranceTransition(
		store, record, StateNeedsDecision,
		"qualification review findings require one persisted correction",
		"qualification-review",
	)
	return outcome, true, err
}

func validateQualificationReview(record runRecord, review QualificationReview) error {
	if record.Evidence == nil || !review.Completed || review.Findings == nil ||
		review.AuthoritySHA256 != record.AuthoritySHA256 {
		return errors.New("qualification review does not match the completed authority")
	}
	digest, err := acceptanceMatrixDigest(record.Evidence.AcceptanceMatrix)
	if err != nil {
		return err
	}
	if review.AcceptanceMatrixSHA256 != digest {
		return errors.New("qualification review does not match the current acceptance matrix")
	}
	if err := validatePacketResponseDigest(review.PacketID, review.PacketSHA256, review.ResponseSHA256, review.Completed); err != nil {
		return fmt.Errorf("qualification review source: %w", err)
	}
	if review.PacketID != "" {
		packets, packetErr := reviewPacketsFromRecord(
			record, GitObservation{}, ReviewPacketRequest{Kind: ReviewPacketQualification},
		)
		if packetErr != nil || len(packets) != 1 || review.PacketID != packets[0].PacketID {
			return errors.New("qualification review does not match its exact current packet")
		}
		if review.PacketSHA256 != packets[0].SHA256 {
			return errors.New("qualification review does not match its exact current packet SHA-256")
		}
	}
	links := make(map[string]string, len(record.Evidence.Scope.OwnedNow))
	for _, entry := range record.Evidence.Scope.OwnedNow {
		links[entry.Identity] = entry.EvidenceLink
	}
	seen := make(map[string]bool, len(review.Findings))
	for _, finding := range review.Findings {
		if !validQualificationFinding(finding) || seen[finding.ID] ||
			links[finding.Location] == "" || finding.Citation != links[finding.Location] ||
			strings.TrimSpace(finding.Evidence) == "" {
			return errors.New("qualification review contains an invalid or untraceable finding")
		}
		seen[finding.ID] = true
	}
	return nil
}

func validateQualificationHistory(record runRecord) error {
	if len(record.QualificationReviews) == 0 {
		if record.QualificationApproved || len(record.QualificationCorrections) > 1 ||
			(len(record.QualificationCorrections) == 1 &&
				!isCompilerQualificationCorrection(record.QualificationCorrections[0])) {
			return errors.New("qualification state requires a persisted independent review")
		}
		if record.PendingQualificationCorrection != nil {
			if err := validateCompilerQualificationRequest(record, *record.PendingQualificationCorrection); err != nil {
				return err
			}
		}
		if len(record.QualificationCorrections) == 1 {
			if err := validateCompilerQualificationCorrection(record, record.QualificationCorrections[0]); err != nil {
				return err
			}
		}
		return nil
	}
	compilerOffset := compilerQualificationCorrectionCount(record)
	if compilerOffset == 1 {
		if err := validateCompilerQualificationCorrection(record, record.QualificationCorrections[0]); err != nil {
			return err
		}
	}
	if record.Evidence == nil ||
		len(record.QualificationCorrections)-compilerOffset > len(record.QualificationReviews) {
		return errors.New("qualification history is incomplete")
	}
	links := make(map[string]string, len(record.Evidence.Scope.OwnedNow))
	for _, entry := range record.Evidence.Scope.OwnedNow {
		links[entry.Identity] = entry.EvidenceLink
	}
	for _, review := range record.QualificationReviews {
		if review.AuthoritySHA256 != record.AuthoritySHA256 ||
			!runIDPattern.MatchString(review.AcceptanceMatrixSHA256) ||
			review.Findings == nil || !review.Completed {
			return errors.New("qualification history contains an invalid review")
		}
		if err := validatePacketResponseDigest(review.PacketID, review.PacketSHA256, review.ResponseSHA256, review.Completed); err != nil {
			return fmt.Errorf("qualification history contains an invalid review source: %w", err)
		}
		seen := make(map[string]bool, len(review.Findings))
		for _, finding := range review.Findings {
			if !validQualificationFinding(finding) || seen[finding.ID] ||
				links[finding.Location] == "" || finding.Citation != links[finding.Location] {
				return errors.New("qualification history contains an invalid finding")
			}
			seen[finding.ID] = true
		}
	}
	for index, correction := range record.QualificationCorrections[compilerOffset:] {
		review := record.QualificationReviews[index]
		if correction.AuthoritySHA256 != record.AuthoritySHA256 ||
			correction.ReviewedMatrixSHA256 != review.AcceptanceMatrixSHA256 ||
			len(review.Findings) == 0 || strings.TrimSpace(correction.Evidence) == "" ||
			len(correction.FindingIDs) != len(review.Findings) {
			return errors.New("qualification history contains an invalid correction")
		}
		want := make([]string, 0, len(review.Findings))
		for _, finding := range review.Findings {
			want = append(want, finding.ID)
		}
		got := append([]string(nil), correction.FindingIDs...)
		sort.Strings(want)
		sort.Strings(got)
		for item := range want {
			if got[item] != want[item] {
				return errors.New("qualification correction does not cover its review findings")
			}
		}
		if err := validateHistoricalReviewerQualificationMatrix(
			record.Evidence, correction.AcceptanceMatrix,
		); err != nil {
			return errors.New("qualification history contains an invalid correction matrix")
		}
		if index+1 < len(record.QualificationReviews) {
			digest, err := acceptanceMatrixDigest(correction.AcceptanceMatrix)
			if err != nil ||
				record.QualificationReviews[index+1].AcceptanceMatrixSHA256 != digest {
				return errors.New("qualification correction is not bound to its independent rereview")
			}
		}
	}
	currentDigest, err := acceptanceMatrixDigest(record.Evidence.AcceptanceMatrix)
	if err != nil {
		return err
	}
	lastReview := record.QualificationReviews[len(record.QualificationReviews)-1]
	if record.PendingQualificationCorrection != nil {
		pending := record.PendingQualificationCorrection
		if isCompilerQualificationRequest(*pending) {
			return errors.New("compiler qualification correction cannot remain pending after independent review")
		}
		if len(lastReview.Findings) == 0 ||
			len(record.QualificationReviews) !=
				len(record.QualificationCorrections)-compilerOffset+1 ||
			pending.AuthoritySHA256 != record.AuthoritySHA256 ||
			pending.ReviewedMatrixSHA256 != currentDigest ||
			pending.ReviewedMatrixSHA256 != lastReview.AcceptanceMatrixSHA256 {
			return errors.New("pending qualification correction does not match its rejected review")
		}
	}
	if record.QualificationApproved {
		if len(lastReview.Findings) != 0 ||
			len(record.QualificationReviews) != len(record.QualificationCorrections)-compilerOffset+1 {
			return errors.New("qualification approval does not match the current matrix")
		}
		corrected := record.QualificationCorrections[len(record.QualificationCorrections)-1].AcceptanceMatrix
		correctedDigest, err := acceptanceMatrixDigest(corrected)
		if err != nil || lastReview.AcceptanceMatrixSHA256 != correctedDigest ||
			(len(record.Candidates) == 0 && currentDigest != correctedDigest) ||
			(len(record.Candidates) > 0 &&
				!qualificationSeamsMatchCorrection(record.Evidence.AcceptanceMatrix, corrected)) {
			return errors.New("qualification approval does not match the current matrix")
		}
	} else if record.PendingQualificationCorrection == nil &&
		len(record.QualificationReviews) != len(record.QualificationCorrections)-compilerOffset {
		return errors.New("qualification history is not ready for independent rereview")
	} else if !record.QualificationApproved && record.PendingQualificationCorrection == nil &&
		len(record.QualificationCorrections) > 0 {
		corrected := record.QualificationCorrections[len(record.QualificationCorrections)-1].AcceptanceMatrix
		correctedDigest, err := acceptanceMatrixDigest(corrected)
		if err != nil || currentDigest != correctedDigest {
			return errors.New("active qualification matrix does not match the pending independent rereview")
		}
	}
	return nil
}

func compilerQualificationCorrectionRequest(
	authority string,
	evidence *deliveryevidence.Bundle,
) (*QualificationCorrectionRequest, error) {
	if !requiresQualificationCorrection(evidence) {
		return nil, nil
	}
	matrixHash, err := acceptanceMatrixDigest(evidence.AcceptanceMatrix)
	if err != nil {
		return nil, err
	}
	findings := make([]QualificationFinding, 0, len(evidence.AcceptanceMatrix))
	for _, row := range evidence.AcceptanceMatrix {
		if !strings.EqualFold(cleanText(row.OwningSeam), qualificationPlanRequired) {
			continue
		}
		id := stableID("qualification-compiler-finding",
			authority+"\x00"+matrixHash+"\x00"+row.Identity+"\x00"+row.Criterion)
		findings = append(findings, QualificationFinding{
			ID: id, CriterionID: row.Identity, Criterion: row.Criterion,
			Evidence: "compiler-known qualification marker requires a complete evidence plan",
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	ids := make([]string, len(findings))
	for index := range findings {
		ids[index] = findings[index].ID
	}
	return &QualificationCorrectionRequest{
		ID: stableID("qualification-compiler-request",
			authority+"\x00"+matrixHash+"\x00"+strings.Join(ids, "\x00")),
		AuthoritySHA256: authority, ReviewedMatrixSHA256: matrixHash,
		FindingIDs: ids, Findings: findings,
	}, nil
}

func originalCompilerQualificationEvidence(
	evidence *deliveryevidence.Bundle,
	phaseOwned bool,
) (*deliveryevidence.Bundle, error) {
	if evidence == nil {
		return nil, errors.New("compiler qualification evidence is unavailable")
	}
	migrationEvidence := ""
	switch evidence.Authority.Kind {
	case deliveryevidence.AuthoritySelfContainedIssue:
		migrationEvidence = "not applicable: new self-contained run"
	case deliveryevidence.AuthorityIssueWithSpecification:
		migrationEvidence = "not applicable: new issue-with-specification run"
	default:
		return nil, errors.New("compiler qualification authority kind is invalid")
	}
	original := *evidence
	original.AcceptanceMatrix = make([]deliveryevidence.AcceptanceRow, len(evidence.Scope.OwnedNow))
	for index, scope := range evidence.Scope.OwnedNow {
		compile := compileLegacyAcceptanceRow
		if phaseOwned {
			compile = compileAcceptanceRow
		}
		original.AcceptanceMatrix[index] = compile(scope.Identity, scope.Requirement, migrationEvidence)
	}
	return &original, nil
}

func validateCompilerQualificationRequest(
	record runRecord,
	pending QualificationCorrectionRequest,
) error {
	expected, err := compilerQualificationCorrectionRequest(record.AuthoritySHA256, record.Evidence)
	if err != nil || expected == nil || !reflect.DeepEqual(pending, *expected) {
		return errors.New("compiler qualification correction request does not match the current authority and matrix")
	}
	return nil
}

func validateCompilerQualificationCorrection(record runRecord, correction QualificationCorrection) error {
	phaseOwnedOriginal, err := originalCompilerQualificationEvidence(record.Evidence, true)
	if err != nil {
		return err
	}
	legacyOriginal, err := originalCompilerQualificationEvidence(record.Evidence, false)
	if err != nil {
		return err
	}
	phaseOwnedExpected, phaseErr := compilerQualificationCorrectionRequest(
		record.AuthoritySHA256, phaseOwnedOriginal,
	)
	legacyExpected, legacyErr := compilerQualificationCorrectionRequest(
		record.AuthoritySHA256, legacyOriginal,
	)
	if phaseErr != nil || legacyErr != nil || phaseOwnedExpected == nil || legacyExpected == nil {
		return errors.New("qualification history contains an invalid compiler correction")
	}
	expected := phaseOwnedExpected
	phaseOwned := correction.ReviewedMatrixSHA256 == phaseOwnedExpected.ReviewedMatrixSHA256
	if correction.ReviewedMatrixSHA256 == legacyExpected.ReviewedMatrixSHA256 {
		expected = legacyExpected
	} else if !phaseOwned {
		return errors.New("qualification history contains an invalid compiler correction")
	}
	if correction.RequestID != expected.ID ||
		correction.AuthoritySHA256 != expected.AuthoritySHA256 ||
		correction.ReviewedMatrixSHA256 != expected.ReviewedMatrixSHA256 ||
		!reflect.DeepEqual(correction.FindingIDs, expected.FindingIDs) ||
		validateCompilerQualificationBindings(correction) != nil {
		return errors.New("qualification history contains an invalid compiler correction")
	}
	if validateQualificationMatrixShape(record.Evidence, correction.AcceptanceMatrix) != nil {
		return errors.New("qualification history contains an invalid compiler correction")
	}
	for _, row := range correction.AcceptanceMatrix {
		if phaseOwned && !reflect.DeepEqual(row.Obligations, deliveryevidence.PhaseOwnedAcceptanceObligations()) {
			return errors.New("qualification history contains erased or changed phase ownership")
		}
		if !phaseOwned && len(row.Obligations) != 0 {
			return errors.New("historical qualification correction changed legacy phase ownership")
		}
	}
	return nil
}

func isCompilerQualificationRequest(request QualificationCorrectionRequest) bool {
	return request.ID != ""
}

func isCompilerQualificationCorrection(correction QualificationCorrection) bool {
	return correction.RequestID != ""
}

func compilerQualificationCorrectionCount(record runRecord) int {
	if len(record.QualificationCorrections) > 0 &&
		isCompilerQualificationCorrection(record.QualificationCorrections[0]) {
		return 1
	}
	return 0
}

func canonicalFindingIDs(ids []string) []string {
	canonical := append([]string(nil), ids...)
	sort.Strings(canonical)
	return canonical
}

func canonicalQualificationCorrection(correction QualificationCorrection) QualificationCorrection {
	correction.FindingIDs = canonicalFindingIDs(correction.FindingIDs)
	return correction
}

func adoptLegacyNullQualificationFindings(record *runRecord) {
	for index := range record.QualificationReviews {
		if record.QualificationReviews[index].Findings == nil {
			record.QualificationReviews[index].Findings = []deliveryevidence.ReviewFinding{}
		}
	}
}

func qualificationSeamsMatchCorrection(
	current, corrected []deliveryevidence.AcceptanceRow,
) bool {
	if len(current) != len(corrected) {
		return false
	}
	for index := range corrected {
		if current[index].Identity != corrected[index].Identity ||
			current[index].Criterion != corrected[index].Criterion ||
			current[index].OwningSeam != corrected[index].OwningSeam ||
			!reflect.DeepEqual(current[index].Obligations, corrected[index].Obligations) {
			return false
		}
	}
	return true
}

func requiresQualificationCorrection(evidence *deliveryevidence.Bundle) bool {
	if evidence == nil {
		return false
	}
	rows := evidence.AcceptanceMatrix
	for _, row := range rows {
		if strings.EqualFold(cleanText(row.OwningSeam), qualificationPlanRequired) {
			return true
		}
	}
	return false
}

func validQualificationFinding(finding deliveryevidence.ReviewFinding) bool {
	return strings.TrimSpace(finding.ID) != "" &&
		finding.Axis == deliveryevidence.ReviewSpec &&
		finding.Authority == deliveryevidence.AuthoritySpecRequirement &&
		(finding.Severity == deliveryevidence.SeverityP0 ||
			finding.Severity == deliveryevidence.SeverityP1 ||
			finding.Severity == deliveryevidence.SeverityP2 ||
			finding.Severity == deliveryevidence.SeverityP3) &&
		strings.TrimSpace(finding.Evidence) != ""
}

func validateQualificationCorrection(record runRecord, correction QualificationCorrection) error {
	pending := record.PendingQualificationCorrection
	if pending == nil || correction.AuthoritySHA256 != pending.AuthoritySHA256 ||
		correction.RequestID != pending.ID ||
		correction.ReviewedMatrixSHA256 != pending.ReviewedMatrixSHA256 ||
		len(correction.FindingIDs) != len(pending.FindingIDs) {
		return errors.New("qualification correction does not match the pending review findings")
	}
	if !exactCanonicalFindingIDs(correction.FindingIDs, pending.FindingIDs) {
		return errors.New("qualification correction must address every finding as one batch")
	}
	if isCompilerQualificationRequest(*pending) {
		if err := validateCompilerQualificationBindings(correction); err != nil {
			return err
		}
		return validateQualificationMatrixShape(record.Evidence, correction.AcceptanceMatrix)
	}
	if !specificQualificationText(correction.Evidence) {
		return errors.New("qualification correction does not match the pending review findings")
	}
	if err := validateQualificationMatrix(record.Evidence, correction.AcceptanceMatrix); err != nil {
		return err
	}
	return nil
}

func exactCanonicalFindingIDs(got, want []string) bool {
	canonical := canonicalFindingIDs(got)
	if len(canonical) != len(want) || !reflect.DeepEqual(canonical, want) {
		return false
	}
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return false
		}
	}
	return true
}

func validateQualificationMatrix(
	evidence *deliveryevidence.Bundle,
	rows []deliveryevidence.AcceptanceRow,
) error {
	if err := validateQualificationMatrixShape(evidence, rows); err != nil {
		return err
	}
	for _, row := range rows {
		if !specificQualificationText(row.OwningSeam) ||
			!specificQualificationText(row.PositiveEvidence) ||
			!specificQualificationText(row.NegativeEvidence) ||
			!specificQualificationText(row.FailureEvidence) ||
			!specificQualificationText(row.MutationEvidence) ||
			!specificQualificationText(row.CompatibilityEvidence) ||
			!specificQualificationText(row.PreservationEvidence) ||
			!specificQualificationText(row.MigrationEvidence) ||
			strings.EqualFold(cleanText(row.OwningSeam), qualificationPlanRequired) {
			return errors.New("qualification correction must preserve traceability and complete every evidence row")
		}
	}
	return nil
}

func validateQualificationMatrixShape(
	evidence *deliveryevidence.Bundle,
	rows []deliveryevidence.AcceptanceRow,
) error {
	if evidence == nil || len(rows) != len(evidence.Scope.OwnedNow) ||
		len(evidence.AcceptanceMatrix) != len(rows) {
		return errors.New("qualification correction must preserve every acceptance criterion")
	}
	for index, row := range rows {
		scope := evidence.Scope.OwnedNow[index]
		if row.Identity != scope.Identity || row.Criterion != scope.Requirement ||
			row.State != deliveryevidence.AcceptancePlanned ||
			!reflect.DeepEqual(row.Obligations, evidence.AcceptanceMatrix[index].Obligations) {
			return errors.New("qualification correction must preserve traceability and complete every evidence row")
		}
	}
	return nil
}

func validateHistoricalReviewerQualificationMatrix(
	evidence *deliveryevidence.Bundle,
	rows []deliveryevidence.AcceptanceRow,
) error {
	if err := validateQualificationMatrixShape(evidence, rows); err != nil {
		return err
	}
	for _, row := range rows {
		if strings.TrimSpace(row.OwningSeam) == "" ||
			strings.TrimSpace(row.PositiveEvidence) == "" ||
			strings.TrimSpace(row.NegativeEvidence) == "" ||
			strings.TrimSpace(row.FailureEvidence) == "" ||
			strings.TrimSpace(row.MutationEvidence) == "" ||
			strings.TrimSpace(row.CompatibilityEvidence) == "" ||
			strings.TrimSpace(row.PreservationEvidence) == "" ||
			strings.TrimSpace(row.MigrationEvidence) == "" ||
			strings.EqualFold(cleanText(row.OwningSeam), qualificationPlanRequired) {
			return errors.New("historical qualification correction matrix is incomplete")
		}
	}
	return nil
}

func specificQualificationText(value string) bool {
	normalized := strings.ToLower(cleanText(value))
	if len(normalized) < 12 || strings.HasPrefix(normalized, "required:") ||
		strings.Contains(normalized, qualificationPlanRequired) {
		return false
	}
	generic := map[string]bool{
		"addressed": true, "complete": true, "correction": true, "evidence": true,
		"fixed": true, "here": true, "implementation": true, "implemented": true,
		"plan": true, "planned": true, "proof": true, "qualification": true,
		"required": true, "test": true, "tests": true, "updated": true,
	}
	for _, token := range strings.FieldsFunc(normalized, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		if len(token) >= 4 && !generic[token] {
			return true
		}
	}
	return false
}

func validateCompilerQualificationBindings(correction QualificationCorrection) error {
	if !validCompilerQualificationEvidence(correction) {
		return errors.New("compiler qualification correction evidence is not bound to its request")
	}
	for _, row := range correction.AcceptanceMatrix {
		for _, value := range []string{
			row.OwningSeam, row.PositiveEvidence, row.NegativeEvidence,
			row.FailureEvidence, row.MutationEvidence, row.CompatibilityEvidence,
			row.PreservationEvidence, row.MigrationEvidence,
		} {
			if !validCompilerQualificationCell(value, row.Identity) {
				return errors.New("compiler qualification correction row is not bound to its criterion")
			}
		}
	}
	return nil
}

func validCompilerQualificationEvidence(correction QualificationCorrection) bool {
	prefix := "[request:" + correction.RequestID + "] findings="
	if !strings.HasPrefix(correction.Evidence, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(correction.Evidence, prefix), "; rationale=")
	if len(parts) != 2 ||
		parts[0] != strings.Join(correction.FindingIDs, ",") {
		return false
	}
	return validCompilerQualificationStatement(parts[1])
}

func validCompilerQualificationCell(value, criterionID string) bool {
	prefix := "[criterion:" + criterionID + "] source="
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, prefix), "; assertion=")
	if len(parts) != 2 {
		return false
	}
	source := strings.SplitN(parts[0], ":", 2)
	return len(source) == 2 && validCompilerQualificationLocator(source[0], source[1]) &&
		validCompilerQualificationStatement(parts[1])
}

var (
	compilerFileLocatorPattern      = regexp.MustCompile(`^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$`)
	compilerSymbolLocatorPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:[.:]{1,2}[A-Za-z_][A-Za-z0-9_-]*)+$`)
	compilerTestLocatorPattern      = regexp.MustCompile(`^Test[A-Za-z0-9_]{8,}$`)
	compilerFixtureLocatorPattern   = regexp.MustCompile(`^fixture/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	compilerReviewLocatorPattern    = regexp.MustCompile(`^review/[a-f0-9]{16}$`)
	compilerReasonLocatorPattern    = regexp.MustCompile(`^reason/[a-z0-9]+(?:-[a-z0-9]+){1,}$`)
	compilerAuthorityLocatorPattern = regexp.MustCompile(`^(?:criterion-[a-f0-9]{16}|issue#[1-9][0-9]*)(?:/[A-Za-z0-9_.-]+)?$`)
)

func validCompilerQualificationLocator(kind, locator string) bool {
	switch kind {
	case "file":
		return compilerFileLocatorPattern.MatchString(locator)
	case "symbol":
		return compilerSymbolLocatorPattern.MatchString(locator)
	case "test":
		return compilerTestLocatorPattern.MatchString(locator)
	case "command":
		return strings.HasPrefix(locator, "./") &&
			compilerFileLocatorPattern.MatchString(strings.TrimPrefix(locator, "./"))
	case "fixture":
		return compilerFixtureLocatorPattern.MatchString(locator)
	case "review":
		return compilerReviewLocatorPattern.MatchString(locator)
	case "authority":
		return compilerAuthorityLocatorPattern.MatchString(locator)
	case "not-applicable":
		return compilerReasonLocatorPattern.MatchString(locator)
	default:
		return false
	}
}

func validCompilerQualificationStatement(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == value && len(value) >= 24 && len(value) <= 512 &&
		!strings.Contains(value, ";") &&
		!strings.Contains(strings.ToLower(cleanText(value)), qualificationPlanRequired)
}

func acceptanceMatrixDigest(rows []deliveryevidence.AcceptanceRow) (string, error) {
	raw, err := json.Marshal(rows)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
