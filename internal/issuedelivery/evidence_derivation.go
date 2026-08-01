package issuedelivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func impactConfirmationFromCandidate(candidate *Candidate) *ImpactConfirmationPacket {
	if candidate == nil || candidate.Derivation == nil {
		return nil
	}
	return candidate.Derivation.PendingConfirmation
}

func acceptanceObligationSetDigest(rows []deliveryevidence.AcceptanceRow) (string, error) {
	identities := make([]deliveryevidence.EvidenceObligationIdentity, 0)
	for _, row := range rows {
		for _, obligation := range row.Obligations {
			identities = append(identities, deliveryevidence.EvidenceObligationIdentity{
				CriterionID: row.Identity, Kind: obligation.Kind, Phase: obligation.Phase,
			})
		}
	}
	sort.Slice(identities, func(i, j int) bool {
		left, right := identities[i], identities[j]
		if left.CriterionID != right.CriterionID {
			return left.CriterionID < right.CriterionID
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.Phase < right.Phase
	})
	raw, err := json.Marshal(identities)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func evidenceCandidateIdentity(candidate Candidate) deliveryevidence.EvidenceCandidateIdentity {
	var boundaries []deliveryevidence.SensitiveBoundary
	if len(candidate.Boundaries) != 0 {
		boundaries = make([]deliveryevidence.SensitiveBoundary, len(candidate.Boundaries))
	}
	for index, boundary := range candidate.Boundaries {
		boundaries[index] = deliveryevidence.SensitiveBoundary(boundary)
	}
	sort.Slice(boundaries, func(i, j int) bool { return boundaries[i] < boundaries[j] })
	axes := append([]deliveryevidence.ReviewAxis(nil), candidate.RequiredReviews...)
	sort.Slice(axes, func(i, j int) bool { return axes[i] < axes[j] })
	return deliveryevidence.EvidenceCandidateIdentity{
		ID: candidate.ID, BaseSHA: candidate.BaseSHA, CommitSHA: candidate.CommitSHA,
		TreeSHA: candidate.TreeSHA, ReviewGeneration: currentReviewIteration(&candidate),
		RiskProfile:         candidate.Profile,
		RequiredReviewAxes:  axes,
		SensitiveBoundaries: boundaries,
	}
}

func impactObligations(rows []deliveryevidence.AcceptanceRow) []deliveryevidence.AcceptanceObligationImpact {
	result := make([]deliveryevidence.AcceptanceObligationImpact, 0)
	for _, row := range rows {
		for _, obligation := range row.Obligations {
			identity := deliveryevidence.EvidenceObligationIdentity{
				CriterionID: row.Identity, Kind: obligation.Kind, Phase: obligation.Phase,
			}
			result = append(result, deliveryevidence.AcceptanceObligationImpact{
				Parent: identity, Derived: identity, Disposition: deliveryevidence.ImpactUnaffected,
			})
		}
	}
	return result
}

func (m *Module) admitImpactAssessment(
	store lockedIssueStore,
	record runRecord,
	candidate *Candidate,
	assessment deliveryevidence.EvidenceImpactAssessment,
) (Outcome, error) {
	if record.Schema == legacyRunSchema {
		return m.persistImpactFallback(store, record, candidate, "schema v1 cannot admit evidence derivation")
	}
	if len(record.Candidates) < 2 || candidate != &record.Candidates[len(record.Candidates)-1] {
		return m.persistImpactFallback(store, record, candidate, "impact assessment lacks an exact derived candidate")
	}
	if candidate.Derivation != nil {
		if reflect.DeepEqual(candidate.Derivation.Assessment, assessment) {
			return outcomeFromRecord(record), nil
		}
		return Outcome{}, errors.New("derived candidate already has a different impact assessment")
	}
	parent := record.Candidates[len(record.Candidates)-2]
	digest, err := acceptanceObligationSetDigest(record.Evidence.AcceptanceMatrix)
	if err != nil {
		return Outcome{}, err
	}
	authority := deliveryevidence.EvidenceAuthorityIdentity{
		RunSchema: deliveryevidence.EvidenceDerivationRunSchemaV2,
		RunID:     record.ID, SHA256: record.AuthoritySHA256,
	}
	if assessment.ParentAuthority != authority || assessment.DerivedAuthority != authority {
		return m.persistImpactFallback(store, record, candidate, "impact assessment authority is stale or mismatched")
	}
	if !reflect.DeepEqual(assessment.ParentCandidate, evidenceCandidateIdentity(parent)) {
		return m.persistImpactFallback(store, record, candidate, "impact assessment parent candidate is stale")
	}
	if !reflect.DeepEqual(assessment.DerivedCandidate, evidenceCandidateIdentity(*candidate)) {
		return m.persistImpactFallback(store, record, candidate, "impact assessment derived candidate is stale")
	}
	if assessment.ParentAcceptanceSHA256 != digest || assessment.DerivedAcceptanceSHA256 != digest {
		return m.persistImpactFallback(store, record, candidate, "impact assessment acceptance identity is stale")
	}
	expectedObligations := impactObligations(record.Evidence.AcceptanceMatrix)
	if assessment.ParentObligationCount != len(expectedObligations) ||
		assessment.DerivedObligationCount != len(expectedObligations) ||
		len(assessment.Obligations) != len(expectedObligations) {
		return m.persistImpactFallback(store, record, candidate, "impact assessment obligation coverage is incomplete")
	}
	for index, obligation := range assessment.Obligations {
		if obligation.Parent != expectedObligations[index].Parent ||
			obligation.Derived != expectedObligations[index].Derived {
			return m.persistImpactFallback(store, record, candidate, "impact assessment acceptance obligations are stale")
		}
	}
	authenticated, ok := m.impactAuthority.(AuthenticatedImpactAuthority)
	if !ok || authenticated.AuthenticatedImpactPrincipal() != assessment.Author {
		return m.persistImpactFallback(store, record, candidate, "impact assessment author is not the authenticated principal")
	}
	decision, err := deliveryevidence.EvaluateEvidenceImpactAssessment(m.impactAuthority, assessment)
	if err != nil {
		return m.persistImpactFallback(store, record, candidate, "impact assessment is invalid or unauthorized")
	}
	derivation := &CandidateDerivation{
		ParentCandidateID: parent.ID, Assessment: assessment, Decision: decision,
		RetainedReviewReceipts: []deliveryevidence.ReviewDerivationReceipt{},
	}
	if decision.IndependentConfirmationRequired {
		packet := &ImpactConfirmationPacket{
			Schema:       impactConfirmationPacketSchema,
			AssessmentID: assessment.ID, ParentCandidateID: parent.ID, DerivedCandidateID: candidate.ID,
		}
		packet.PacketID = stableID("impact-confirmation", packet.AssessmentID+"\x00"+packet.ParentCandidateID+"\x00"+packet.DerivedCandidateID)
		derivation.PendingConfirmation = packet
	}
	candidate.Derivation = derivation
	reason := "impact assessment requires complete fresh review evidence"
	if derivation.PendingConfirmation != nil {
		reason = "impact assessment awaits independent confirmation"
	}
	return m.persistAssuranceTransition(store, record, StateNeedsReview, reason, "impact-assessment")
}

func (m *Module) admitImpactConfirmation(
	store lockedIssueStore,
	record runRecord,
	candidate *Candidate,
	confirmation deliveryevidence.ImpactConfirmation,
) (Outcome, error) {
	if candidate == nil || candidate.Derivation == nil {
		return Outcome{}, errors.New("impact confirmation has no pending assessment")
	}
	derivation := candidate.Derivation
	if derivation.Confirmation != nil {
		if reflect.DeepEqual(*derivation.Confirmation, confirmation) {
			return outcomeFromRecord(record), nil
		}
		return Outcome{}, errors.New("derived candidate already has a different impact confirmation")
	}
	if derivation.PendingConfirmation == nil {
		return Outcome{}, errors.New("impact confirmation is not required for the accepted assessment")
	}
	if err := deliveryevidence.AdmitImpactConfirmation(
		persistedImpactAuthorAuthority{ImpactAuthority: m.impactAuthority, author: derivation.Assessment.Author},
		derivation.Assessment, confirmation,
	); err != nil {
		return m.persistImpactFallback(store, record, candidate, "impact confirmation is rejected, incomplete, stale, mismatched, or not independent")
	}
	parent := record.Candidates[len(record.Candidates)-2]
	receipts, err := reviewDerivationReceipts(record, parent, *candidate, *derivation, confirmation)
	if err != nil {
		return Outcome{}, err
	}
	derivation.Confirmation = &confirmation
	derivation.PendingConfirmation = nil
	derivation.RetainedReviewReceipts = receipts
	return m.persistAssuranceTransition(
		store, record, StateNeedsReview, "independent impact confirmation admitted; delta review is pending", "impact-confirmation",
	)
}

type persistedImpactAuthorAuthority struct {
	deliveryevidence.ImpactAuthority
	author deliveryevidence.ImpactAuthor
}

func (a persistedImpactAuthorAuthority) AuthorizedImpactAuthor(author deliveryevidence.ImpactAuthor) bool {
	return author == a.author || a.ImpactAuthority.AuthorizedImpactAuthor(author)
}

func (m *Module) persistImpactFallback(
	store lockedIssueStore,
	record runRecord,
	candidate *Candidate,
	reason string,
) (Outcome, error) {
	if candidate != nil && candidate.Derivation != nil {
		candidate.Derivation.PendingConfirmation = nil
		candidate.Derivation.Confirmation = nil
		candidate.Derivation.RetainedReviewReceipts = []deliveryevidence.ReviewDerivationReceipt{}
		candidate.Derivation.FallbackReason = reason
	}
	return m.persistAssuranceTransition(
		store, record, StateNeedsReview,
		"impact evidence failed closed; complete fresh review evidence is required",
		"impact-confirmation",
	)
}

func reviewDerivationReceipts(
	record runRecord,
	parent Candidate,
	derived Candidate,
	derivation CandidateDerivation,
	confirmation deliveryevidence.ImpactConfirmation,
) ([]deliveryevidence.ReviewDerivationReceipt, error) {
	delta := make(map[deliveryevidence.ReviewAxis]bool, len(derivation.Decision.DeltaReviewAxes))
	for _, axis := range derivation.Decision.DeltaReviewAxes {
		delta[axis] = true
	}
	obligations := make([]deliveryevidence.EvidenceObligationIdentity, 0)
	for _, impact := range derivation.Assessment.Obligations {
		if impact.Disposition == deliveryevidence.ImpactUnaffected &&
			impact.Derived.Phase == deliveryevidence.AssuranceCandidateReview {
			obligations = append(obligations, impact.Derived)
		}
	}
	receipts := make([]deliveryevidence.ReviewDerivationReceipt, 0)
	for _, axis := range derivation.Decision.RetainableReviewAxes {
		if delta[axis] {
			continue
		}
		parentReceipt := ""
		for _, receipt := range record.Evidence.CandidateReviewReceipts {
			if receipt.CandidateID != parent.ID {
				continue
			}
			for _, receiptAxis := range receipt.Axes {
				if receiptAxis == axis {
					parentReceipt = receipt.Identity
				}
			}
		}
		if parentReceipt == "" {
			return nil, fmt.Errorf("retainable %s review lacks a canonical parent receipt", axis)
		}
		receipt := deliveryevidence.ReviewDerivationReceipt{
			Schema:                deliveryevidence.ReviewDerivationReceiptSchema,
			ParentReceiptIdentity: parentReceipt,
			AssessmentID:          derivation.Assessment.ID, ConfirmationID: confirmation.ID,
			ParentCandidateID: parent.ID, DerivedCandidateID: derived.ID, Axis: axis,
			Obligations: []deliveryevidence.EvidenceObligationIdentity{},
		}
		if axis == deliveryevidence.ReviewSpec {
			receipt.Obligations = append(receipt.Obligations, obligations...)
		}
		receipt.Identity = deliveryevidence.ReviewDerivationReceiptIdentity(receipt)
		receipts = append(receipts, receipt)
	}
	sort.Slice(receipts, func(i, j int) bool { return receipts[i].Axis < receipts[j].Axis })
	fullSpecialists := map[deliveryevidence.SensitiveBoundary]bool{}
	for _, boundary := range derivation.Decision.FullSpecialistBoundaries {
		fullSpecialists[boundary] = true
	}
	for _, boundary := range derivation.Decision.RetainableSpecialistBoundaries {
		if fullSpecialists[boundary] {
			continue
		}
		var parentReview *SpecialistReview
		for index := range parent.SpecialistReviews {
			if deliveryevidence.SensitiveBoundary(parent.SpecialistReviews[index].Boundary) == boundary &&
				parent.SpecialistReviews[index].Completed {
				parentReview = &parent.SpecialistReviews[index]
			}
		}
		if parentReview == nil {
			return nil, fmt.Errorf("retainable %s specialist review lacks canonical parent evidence", boundary)
		}
		raw, err := json.Marshal(parentReview)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		receipt := deliveryevidence.ReviewDerivationReceipt{
			Schema:                deliveryevidence.ReviewDerivationReceiptSchema,
			ParentReceiptIdentity: hex.EncodeToString(sum[:]),
			AssessmentID:          derivation.Assessment.ID, ConfirmationID: confirmation.ID,
			ParentCandidateID: parent.ID, DerivedCandidateID: derived.ID,
			Boundary: boundary, Obligations: []deliveryevidence.EvidenceObligationIdentity{},
		}
		receipt.Identity = deliveryevidence.ReviewDerivationReceiptIdentity(receipt)
		receipts = append(receipts, receipt)
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].Axis != receipts[j].Axis {
			return receipts[i].Axis < receipts[j].Axis
		}
		return receipts[i].Boundary < receipts[j].Boundary
	})
	return receipts, nil
}

func retainedReviewAxes(candidate *Candidate) []deliveryevidence.ReviewAxis {
	if candidate == nil || candidate.Derivation == nil || candidate.Derivation.Confirmation == nil {
		return nil
	}
	result := make([]deliveryevidence.ReviewAxis, 0, len(candidate.Derivation.RetainedReviewReceipts))
	for _, receipt := range candidate.Derivation.RetainedReviewReceipts {
		if receipt.Axis != "" {
			result = append(result, receipt.Axis)
		}
	}
	return result
}

func freshReviewAxes(candidate *Candidate) []deliveryevidence.ReviewAxis {
	if candidate == nil {
		return nil
	}
	if candidate.Derivation == nil || candidate.Derivation.FallbackReason != "" {
		return append([]deliveryevidence.ReviewAxis(nil), candidate.RequiredReviews...)
	}
	result := append([]deliveryevidence.ReviewAxis(nil), candidate.Derivation.Decision.FullReviewAxes...)
	for _, axis := range candidate.Derivation.Decision.DeltaReviewAxes {
		if !containsAxis(result, axis) {
			result = append(result, axis)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func retainedSpecialistBoundaries(candidate *Candidate) []SensitiveBoundary {
	if candidate == nil || candidate.Derivation == nil || candidate.Derivation.Confirmation == nil {
		return nil
	}
	result := make([]SensitiveBoundary, 0)
	for _, receipt := range candidate.Derivation.RetainedReviewReceipts {
		if receipt.Boundary != "" {
			result = append(result, SensitiveBoundary(receipt.Boundary))
		}
	}
	return result
}

func hasCandidateSemanticAssurance(candidate *Candidate, rowCount int) bool {
	return len(candidate.Acceptance) == rowCount ||
		(len(candidate.Acceptance) == 0 && containsAxis(retainedReviewAxes(candidate), deliveryevidence.ReviewSpec))
}

func reviewPacketDerivation(
	record runRecord,
	candidate Candidate,
	axis deliveryevidence.ReviewAxis,
) *ReviewPacketDerivation {
	if candidate.Derivation == nil {
		return nil
	}
	derivation := candidate.Derivation
	packet := &ReviewPacketDerivation{
		ParentCandidateID:      derivation.ParentCandidateID,
		AssessmentID:           derivation.Assessment.ID,
		ParentEvidenceReceipts: []string{},
		RetainedObligations:    []deliveryevidence.EvidenceObligationIdentity{},
		ChangedObligations:     []deliveryevidence.AcceptanceObligationImpact{},
		ExactDelta:             append([]deliveryevidence.EvidenceChange(nil), derivation.Assessment.Changes...),
	}
	if derivation.Confirmation != nil {
		packet.ConfirmationID = derivation.Confirmation.ID
	}
	seenReceipts := map[string]bool{}
	for _, receipt := range record.Evidence.CandidateReviewReceipts {
		if receipt.CandidateID != derivation.ParentCandidateID {
			continue
		}
		for _, receiptAxis := range receipt.Axes {
			if receiptAxis == axis && !seenReceipts[receipt.Identity] {
				packet.ParentEvidenceReceipts = append(packet.ParentEvidenceReceipts, receipt.Identity)
				seenReceipts[receipt.Identity] = true
			}
		}
	}
	for _, receipt := range derivation.RetainedReviewReceipts {
		if !seenReceipts[receipt.ParentReceiptIdentity] {
			packet.ParentEvidenceReceipts = append(packet.ParentEvidenceReceipts, receipt.ParentReceiptIdentity)
			seenReceipts[receipt.ParentReceiptIdentity] = true
		}
	}
	for _, obligation := range derivation.Assessment.Obligations {
		if obligation.Derived.Phase != deliveryevidence.AssuranceCandidateReview {
			continue
		}
		if obligation.Disposition == deliveryevidence.ImpactUnaffected {
			packet.RetainedObligations = append(packet.RetainedObligations, obligation.Derived)
		} else {
			packet.ChangedObligations = append(packet.ChangedObligations, obligation)
		}
	}
	sort.Strings(packet.ParentEvidenceReceipts)
	return packet
}

type structuralImpactAuthority struct{}

func (structuralImpactAuthority) AuthorizedImpactAuthor(deliveryevidence.ImpactAuthor) bool {
	return true
}

func (structuralImpactAuthority) IndependentImpactConfirmer(author, confirmer deliveryevidence.ImpactAuthor) bool {
	return author.Identity != confirmer.Identity
}

func validateCandidateDerivation(record runRecord, candidateIndex int) error {
	candidate := record.Candidates[candidateIndex]
	if candidate.Derivation == nil {
		return nil
	}
	if candidateIndex == 0 || record.Schema == legacyRunSchema {
		return errors.New("issue delivery candidate has synthetic derivation authority")
	}
	derivation := candidate.Derivation
	parent := record.Candidates[candidateIndex-1]
	if derivation.ParentCandidateID != parent.ID {
		return errors.New("issue delivery candidate derivation parent is stale")
	}
	if err := deliveryevidence.ValidateEvidenceImpactAssessment(derivation.Assessment); err != nil {
		return fmt.Errorf("issue delivery candidate impact assessment is invalid: %w", err)
	}
	authority := deliveryevidence.EvidenceAuthorityIdentity{
		RunSchema: deliveryevidence.EvidenceDerivationRunSchemaV2,
		RunID:     record.ID, SHA256: record.AuthoritySHA256,
	}
	if derivation.Assessment.ParentAuthority != authority || derivation.Assessment.DerivedAuthority != authority ||
		!reflect.DeepEqual(derivation.Assessment.ParentCandidate, evidenceCandidateIdentity(parent)) ||
		!reflect.DeepEqual(derivation.Assessment.DerivedCandidate, evidenceCandidateIdentity(candidate)) {
		return errors.New("issue delivery candidate derivation identities are stale")
	}
	digest, err := acceptanceObligationSetDigest(record.Evidence.AcceptanceMatrix)
	if err != nil {
		return err
	}
	if derivation.Assessment.ParentAcceptanceSHA256 != digest ||
		derivation.Assessment.DerivedAcceptanceSHA256 != digest {
		return errors.New("issue delivery candidate derivation acceptance identity is stale")
	}
	decision, err := deliveryevidence.EvaluateEvidenceImpactAssessment(
		structuralImpactAuthority{}, derivation.Assessment,
	)
	if err != nil || !reflect.DeepEqual(decision, derivation.Decision) {
		return errors.New("issue delivery candidate derivation decision is not canonical")
	}
	if derivation.PendingConfirmation != nil {
		packet := derivation.PendingConfirmation
		wantID := stableID("impact-confirmation", packet.AssessmentID+"\x00"+packet.ParentCandidateID+"\x00"+packet.DerivedCandidateID)
		if derivation.Confirmation != nil || !decision.IndependentConfirmationRequired ||
			packet.Schema != impactConfirmationPacketSchema || packet.PacketID != wantID ||
			packet.AssessmentID != derivation.Assessment.ID || packet.ParentCandidateID != parent.ID ||
			packet.DerivedCandidateID != candidate.ID || len(derivation.RetainedReviewReceipts) != 0 ||
			len(derivation.ValidationCompatibilityAssessments) != 0 || len(derivation.ValidationDerivationReceipts) != 0 {
			return errors.New("issue delivery candidate impact confirmation packet is invalid")
		}
		return nil
	}
	if derivation.FallbackReason != "" {
		if derivation.PendingConfirmation != nil || derivation.Confirmation != nil ||
			len(derivation.RetainedReviewReceipts) != 0 || len(derivation.ValidationCompatibilityAssessments) != 0 ||
			len(derivation.ValidationDerivationReceipts) != 0 {
			return errors.New("issue delivery candidate impact fallback retained derivation authority")
		}
		return nil
	}
	if decision.IndependentConfirmationRequired && derivation.Confirmation == nil {
		return errors.New("issue delivery candidate derivation lacks required impact confirmation")
	}
	if derivation.Confirmation != nil {
		if err := deliveryevidence.AdmitImpactConfirmation(
			structuralImpactAuthority{}, derivation.Assessment, *derivation.Confirmation,
		); err != nil {
			return fmt.Errorf("issue delivery candidate impact confirmation is invalid: %w", err)
		}
	}
	expectedReceipts := []deliveryevidence.ReviewDerivationReceipt{}
	if derivation.Confirmation != nil {
		expectedReceipts, err = reviewDerivationReceipts(
			record, parent, candidate, *derivation, *derivation.Confirmation,
		)
		if err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(expectedReceipts, derivation.RetainedReviewReceipts) {
		return errors.New("issue delivery candidate review derivation receipts are incomplete or conflicting")
	}
	if err := validateValidationDerivationReceipts(record, parent, candidate, derivation); err != nil {
		return err
	}
	return nil
}

func validateValidationDerivationReceipts(record runRecord, parent, candidate Candidate, derivation *CandidateDerivation) error {
	if len(derivation.ValidationCompatibilityAssessments) != len(derivation.ValidationDerivationReceipts) {
		return errors.New("issue delivery candidate validation derivation is incomplete")
	}
	if len(derivation.ValidationDerivationReceipts) != 0 &&
		(derivation.Decision.ExhaustiveValidationRequired || len(derivation.Decision.FullBoundaryValidations) != 0) {
		return errors.New("issue delivery candidate validation derivation retained an obligation that requires fresh evidence")
	}
	seen := map[deliveryevidence.ValidationObligationIdentity]bool{}
	for index, receipt := range derivation.ValidationDerivationReceipts {
		assessment := derivation.ValidationCompatibilityAssessments[index]
		canonical, err := deliveryevidence.NewValidationCompatibilityAssessment(assessment.ValidationCompatibilityAssessmentInput)
		if err != nil || !reflect.DeepEqual(canonical, assessment) {
			return errors.New("issue delivery candidate validation compatibility assessment is not canonical")
		}
		if receipt.Schema != deliveryevidence.ValidationDerivationReceiptSchema ||
			receipt.Identity != deliveryevidence.ValidationDerivationReceiptIdentity(receipt) ||
			receipt.CompatibilityAssessmentID != assessment.ID ||
			receipt.ImpactAssessmentID != derivation.Assessment.ID || derivation.Confirmation == nil ||
			receipt.ConfirmationID != derivation.Confirmation.ID || receipt.ParentCandidateID != parent.ID ||
			receipt.DerivedCandidateID != candidate.ID || receipt.Obligation != assessment.Required.Obligation ||
			receipt.SourceSessionID != assessment.Source.SessionID ||
			receipt.SourceCompletionSHA256 != assessment.Source.CompletionSHA256 || seen[receipt.Obligation] {
			return errors.New("issue delivery candidate validation derivation receipt is invalid")
		}
		seen[receipt.Obligation] = true
		source, found := validationSessionByCompletion(record.ValidationSessions, receipt.SourceCompletionSHA256)
		if !found || source.ID != receipt.SourceSessionID || source.CandidateID != parent.ID ||
			source.State != ValidationSessionCompleted || source.Result == nil {
			return errors.New("issue delivery candidate validation derivation source is invalid")
		}
		expectedSource, registered := registeredValidationArtifact(record, source, parent, receipt.Obligation)
		if !registered {
			return errors.New("issue delivery candidate validation derivation obligation is not registered")
		}
		expectedRequired := deliveryevidence.ValidationCompatibilityRequirement{
			Candidate: evidenceCandidateIdentity(candidate), CheckoutSHA256: source.CheckoutSHA256,
			Environment: validationEnvironment(source), Obligation: receipt.Obligation,
			ExpiresAt: source.ValidatorIdentityExpiresAt, WorkspaceClean: true,
		}
		if assessment.ImpactAssessmentID != derivation.Assessment.ID ||
			assessment.ImpactConfirmationID != derivation.Confirmation.ID {
			return errors.New("issue delivery candidate validation compatibility authority is stale")
		}
		if !reflect.DeepEqual(assessment.Source, expectedSource) {
			return errors.New("issue delivery candidate validation compatibility source tuple is stale")
		}
		if !reflect.DeepEqual(assessment.Required, expectedRequired) {
			return errors.New("issue delivery candidate validation compatibility tuple is stale")
		}
	}
	if len(derivation.ValidationDerivationReceipts) != 0 {
		expected := map[deliveryevidence.ValidationObligationIdentity]bool{
			{Kind: deliveryevidence.ValidationObligationExhaustive}: true,
		}
		for _, boundary := range candidate.Boundaries {
			expected[deliveryevidence.ValidationObligationIdentity{
				Kind:     deliveryevidence.ValidationObligationBoundary,
				Boundary: deliveryevidence.SensitiveBoundary(boundary),
			}] = true
		}
		if !reflect.DeepEqual(seen, expected) {
			return errors.New("issue delivery candidate validation derivation obligations are incomplete")
		}
	}
	return nil
}
