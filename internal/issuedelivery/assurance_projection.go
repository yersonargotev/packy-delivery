package issuedelivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func projectAutomaticAssurance(record *runRecord) error {
	if record.Schema == legacyRunSchema || record.Evidence == nil {
		return nil
	}
	var expectedReviews []deliveryevidence.CandidateReviewReceipt
	var expectedAdjudications []deliveryevidence.AssuranceAdjudicationReceipt
	var expectedExhaustive []deliveryevidence.ExhaustiveAssuranceReceipt
	reviewIDs := make(map[string]string)
	reviewTimingGroups := contiguousReviewTimingGroups(record.Timing)
	reviewTimingGroupIndex := 0
	for candidateIndex := range record.Candidates {
		candidate := &record.Candidates[candidateIndex]
		byIteration := make(map[int][]CandidateReview)
		for _, review := range candidate.Reviews {
			if review.Completed {
				byIteration[review.Iteration] = append(byIteration[review.Iteration], review)
			}
		}
		iterations := make([]int, 0, len(byIteration))
		for iteration := range byIteration {
			iterations = append(iterations, iteration)
		}
		sort.Ints(iterations)
		for _, iteration := range iterations {
			reviews := byIteration[iteration]
			sort.Slice(reviews, func(i, j int) bool { return reviews[i].Axis < reviews[j].Axis })
			var batch *CandidateReviewBatch
			for batchIndex := range candidate.ReviewBatches {
				if candidate.ReviewBatches[batchIndex].Iteration == iteration {
					batch = &candidate.ReviewBatches[batchIndex]
					break
				}
			}
			requiredAxes := candidate.RequiredReviews
			if batch != nil {
				requiredAxes = batch.RequiredAxes
			} else if iteration < currentReviewIteration(candidate) {
				requiredAxes = make([]deliveryevidence.ReviewAxis, 0, len(reviews))
				for _, review := range reviews {
					requiredAxes = append(requiredAxes, review.Axis)
				}
			}
			completed := make(map[deliveryevidence.ReviewAxis]bool, len(reviews))
			for _, review := range reviews {
				completed[review.Axis] = true
			}
			fullBatch := true
			for _, required := range requiredAxes {
				if !completed[required] {
					fullBatch = false
					break
				}
			}
			if !fullBatch {
				continue
			}
			var closingTiming Timing
			if reviewTimingGroupIndex < len(reviewTimingGroups) {
				closingTiming = reviewTimingGroups[reviewTimingGroupIndex]
			}
			reviewTimingGroupIndex++
			if batch == nil {
				if closingTiming.Sequence == 0 {
					return fmt.Errorf("completed review batch lacks authoritative review timing")
				}
				candidate.ReviewBatches = append(candidate.ReviewBatches, CandidateReviewBatch{
					Iteration: iteration, RequiredAxes: append([]deliveryevidence.ReviewAxis(nil), requiredAxes...),
					TimingSequence: closingTiming.Sequence, CompletedAt: closingTiming.CompletedAt,
				})
				batch = &candidate.ReviewBatches[len(candidate.ReviewBatches)-1]
			}
			axes := make([]deliveryevidence.ReviewAxis, 0, len(reviews))
			for _, review := range reviews {
				axes = append(axes, review.Axis)
			}
			digestReviews := append([]CandidateReview(nil), reviews...)
			for reviewIndex := range digestReviews {
				digestReviews[reviewIndex].Acceptance = append(
					[]AcceptanceProof(nil), digestReviews[reviewIndex].Acceptance...,
				)
				for proofIndex := range digestReviews[reviewIndex].Acceptance {
					if reference := digestReviews[reviewIndex].Acceptance[proofIndex].ReviewReceipt; reference != nil {
						copy := *reference
						copy.ReceiptID = ""
						digestReviews[reviewIndex].Acceptance[proofIndex].ReviewReceipt = &copy
					}
				}
			}
			raw, err := json.Marshal(digestReviews)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(raw)
			findingsDigest := hex.EncodeToString(sum[:])
			receipt := deliveryevidence.CandidateReviewReceipt{
				CandidateID: candidate.ID, Iteration: iteration, Axes: axes,
				FindingsSHA256: findingsDigest, CommitSHA: candidate.CommitSHA,
				TreeSHA: candidate.TreeSHA, CompletedAt: batch.CompletedAt,
			}
			receipt.Identity = deliveryevidence.CandidateReviewReceiptIdentity(
				receipt.CandidateID, receipt.Iteration, receipt.Axes, receipt.FindingsSHA256,
				receipt.CommitSHA, receipt.TreeSHA,
			)
			expectedReviews = append(expectedReviews, receipt)
			for _, axis := range axes {
				reviewIDs[reviewReferenceKey(candidate.ID, iteration, axis)] = receipt.Identity
			}
		}
		repairBatches := append([]RepairBatchReceipt(nil), candidate.RepairBatches...)
		if candidate.LastRepairBatch != nil {
			found := false
			for _, batch := range repairBatches {
				if batch.RequestID == candidate.LastRepairBatch.RequestID {
					found = true
				}
			}
			if !found {
				repairBatches = append(repairBatches, *candidate.LastRepairBatch)
			}
		}
		for batchIndex, batch := range repairBatches {
			findings := make([]deliveryevidence.AssuranceFindingDecision, len(batch.Decision.Findings))
			for index, finding := range batch.Decision.Findings {
				findings[index] = deliveryevidence.AssuranceFindingDecision{
					FindingID: finding.FindingID, Disposition: string(finding.Disposition), Evidence: finding.Evidence,
				}
			}
			sort.Slice(findings, func(i, j int) bool { return findings[i].FindingID < findings[j].FindingID })
			generation := batchIndex + 1
			receipt := deliveryevidence.AssuranceAdjudicationReceipt{
				RequestID: batch.RequestID, CandidateID: batch.Decision.CandidateID, Generation: generation,
				Class: string(batch.Decision.Class), CompatiblePrefix: batch.CompatiblePrefix, Findings: findings,
			}
			receipt.Identity = deliveryevidence.AssuranceAdjudicationReceiptIdentity(
				receipt.RequestID, receipt.CandidateID, receipt.Generation, receipt.Class,
				receipt.CompatiblePrefix, receipt.Findings,
			)
			expectedAdjudications = append(expectedAdjudications, receipt)
		}
		exhaustiveProofs := append([]ValidationProof(nil), candidate.ExhaustiveHistory...)
		if candidate.Exhaustive != nil {
			if candidate.Exhaustive.TimingSequence == 0 {
				timing, ok := latestPhaseTiming(record.Timing, "exhaustive-validation")
				if !ok || timing.CompletedAt != candidate.Exhaustive.CompletedAt {
					return fmt.Errorf("current exhaustive proof lacks authoritative lifecycle timing")
				}
				candidate.Exhaustive.TimingSequence = timing.Sequence
			}
			exhaustiveProofs = append(exhaustiveProofs, *candidate.Exhaustive)
		}
		for proofIndex := range exhaustiveProofs {
			proof := exhaustiveProofs[proofIndex]
			result := proof.Result
			receipt := deliveryevidence.ExhaustiveAssuranceReceipt{
				Repository: record.Repository, CandidateID: candidate.ID,
				CommitSHA: result.CommitSHA, TreeSHA: result.TreeSHA,
				CheckoutSHA256: result.CheckoutSHA256, ValidatorIdentity: result.ValidatorIdentity,
				ValidatorSHA256:            result.ValidatorSHA256,
				ValidatorIdentityExpiresAt: result.ValidatorIdentityExpiresAt,
				Command:                    result.Command, HomeRoot: result.HomeRoot, ConfigRoot: result.ConfigRoot,
				Sandboxed: result.Sandboxed, CompletedAt: proof.CompletedAt,
			}
			receipt.Identity = deliveryevidence.ExhaustiveAssuranceReceiptIdentity(receipt)
			expectedExhaustive = append(expectedExhaustive, receipt)
			if candidate.Exhaustive == nil || proofIndex != len(exhaustiveProofs)-1 {
				continue
			}
			for acceptanceIndex := range candidate.Acceptance {
				reference := candidate.Acceptance[acceptanceIndex].ValidationReceipt
				if reference != nil {
					if reference.ReceiptID != "" && reference.ReceiptID != receipt.Identity {
						return fmt.Errorf("acceptance validation receipt identity conflicts with canonical assurance")
					}
					reference.ReceiptID = receipt.Identity
				}
			}
		}
		for reviewIndex := range candidate.Reviews {
			review := &candidate.Reviews[reviewIndex]
			for proofIndex := range review.Acceptance {
				reference := review.Acceptance[proofIndex].ReviewReceipt
				if reference == nil {
					continue
				}
				id := reviewIDs[reviewReferenceKey(reference.CandidateID, reference.Iteration, reference.Axis)]
				if id == "" || (reference.ReceiptID != "" && reference.ReceiptID != id) {
					return fmt.Errorf("acceptance review receipt identity conflicts with canonical assurance")
				}
				reference.ReceiptID = id
			}
		}
		for proofIndex := range candidate.Acceptance {
			reference := candidate.Acceptance[proofIndex].ReviewReceipt
			if reference == nil {
				continue
			}
			id := reviewIDs[reviewReferenceKey(reference.CandidateID, reference.Iteration, reference.Axis)]
			if id == "" || (reference.ReceiptID != "" && reference.ReceiptID != id) {
				return fmt.Errorf("acceptance review receipt identity conflicts with canonical assurance")
			}
			reference.ReceiptID = id
		}
	}

	expectedPhases := projectAssurancePhases(*record)
	mergedReviews, err := reconcileReceipts(record.Evidence.CandidateReviewReceipts, expectedReviews,
		func(value deliveryevidence.CandidateReviewReceipt) string {
			return fmt.Sprintf("%s\x00%d", value.CandidateID, value.Iteration)
		}, "candidate review")
	if err != nil {
		return err
	}
	mergedAdjudications, err := reconcileReceipts(
		record.Evidence.AssuranceAdjudications, expectedAdjudications,
		func(value deliveryevidence.AssuranceAdjudicationReceipt) string {
			return value.CandidateID + "\x00" + value.RequestID
		}, "adjudication",
	)
	if err != nil {
		return err
	}
	if err := requireReceiptPrefix(record.Evidence.AssurancePhases, expectedPhases, "phase"); err != nil {
		return err
	}
	mergedExhaustive, err := reconcileReceipts(record.Evidence.ExhaustiveAssurance, expectedExhaustive,
		func(value deliveryevidence.ExhaustiveAssuranceReceipt) string {
			return value.CandidateID + "\x00" + value.CompletedAt
		},
		"exhaustive")
	if err != nil {
		return err
	}
	record.Evidence.CandidateReviewReceipts = mergedReviews
	record.Evidence.AssuranceAdjudications = mergedAdjudications
	record.Evidence.AssurancePhases = expectedPhases
	record.Evidence.ExhaustiveAssurance = mergedExhaustive
	return nil
}

func validatePersistedAutomaticAssurance(record runRecord) error {
	if record.Schema == legacyRunSchema || record.Evidence == nil {
		return nil
	}
	if len(record.Evidence.CandidateReviewReceipts) == 0 &&
		len(record.Evidence.AssuranceAdjudications) == 0 &&
		len(record.Evidence.AssurancePhases) == 0 &&
		len(record.Evidence.ExhaustiveAssurance) == 0 {
		if hasAnyReceiptReferences(record.Candidates) || hasAutomaticAssuranceHistory(record.Candidates) {
			return fmt.Errorf("persisted automatic assurance history or references lack canonical receipts")
		}
		return nil
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	var projected runRecord
	if err := json.Unmarshal(raw, &projected); err != nil {
		return err
	}
	if err := projectAutomaticAssurance(&projected); err != nil {
		return err
	}
	if !reflect.DeepEqual(record.Evidence.CandidateReviewReceipts, projected.Evidence.CandidateReviewReceipts) {
		return fmt.Errorf("persisted automatic candidate review assurance projection is incomplete")
	}
	if !reflect.DeepEqual(record.Evidence.AssuranceAdjudications, projected.Evidence.AssuranceAdjudications) {
		return fmt.Errorf("persisted automatic adjudication assurance projection is incomplete")
	}
	if !reflect.DeepEqual(record.Evidence.AssurancePhases, projected.Evidence.AssurancePhases) {
		return fmt.Errorf("persisted automatic phase assurance projection is incomplete")
	}
	if !reflect.DeepEqual(record.Evidence.ExhaustiveAssurance, projected.Evidence.ExhaustiveAssurance) ||
		hasIncompleteReceiptReferences(record.Candidates) {
		return fmt.Errorf("persisted automatic assurance projection is incomplete")
	}
	return nil
}

func hasAutomaticAssuranceHistory(candidates []Candidate) bool {
	for _, candidate := range candidates {
		if len(candidate.ReviewBatches) != 0 ||
			len(candidate.ExhaustiveHistory) != 0 {
			return true
		}
	}
	return false
}

func hasAnyReceiptReferences(candidates []Candidate) bool {
	for _, candidate := range candidates {
		for _, review := range candidate.Reviews {
			for _, proof := range review.Acceptance {
				if proof.ReviewReceipt != nil && proof.ReviewReceipt.ReceiptID != "" {
					return true
				}
			}
		}
		for _, proof := range candidate.Acceptance {
			if (proof.ReviewReceipt != nil && proof.ReviewReceipt.ReceiptID != "") ||
				(proof.ValidationReceipt != nil && proof.ValidationReceipt.ReceiptID != "") {
				return true
			}
		}
	}
	return false
}

func hasIncompleteReceiptReferences(candidates []Candidate) bool {
	for _, candidate := range candidates {
		for _, review := range candidate.Reviews {
			for _, proof := range review.Acceptance {
				if proof.ReviewReceipt != nil && proof.ReviewReceipt.ReceiptID == "" {
					return true
				}
			}
		}
		for _, proof := range candidate.Acceptance {
			if proof.ReviewReceipt != nil && proof.ReviewReceipt.ReceiptID == "" {
				return true
			}
			if candidate.Exhaustive != nil && proof.ValidationReceipt != nil &&
				proof.ValidationReceipt.ReceiptID == "" {
				return true
			}
		}
	}
	return false
}

func projectAssurancePhases(record runRecord) []deliveryevidence.AssurancePhaseReceipt {
	out := make([]deliveryevidence.AssurancePhaseReceipt, 0, len(record.Timing))
	candidateIndex := -1
	for _, timing := range record.Timing {
		if (timing.Phase == "implementation" || timing.Phase == "repair") &&
			candidateIndex+1 < len(record.Candidates) {
			candidateIndex++
		}
		base, commit, tree := record.Observations.CommitSHA, record.Observations.CommitSHA, record.Observations.TreeSHA
		candidateID := ""
		if candidateIndex >= 0 {
			candidate := record.Candidates[candidateIndex]
			candidateID, base, commit, tree = candidate.ID, candidate.BaseSHA, candidate.CommitSHA, candidate.TreeSHA
		}
		receipt := deliveryevidence.AssurancePhaseReceipt{
			Sequence: timing.Sequence, Repository: record.Repository, Phase: timing.Phase,
			CandidateID: candidateID, BaseSHA: base, CommitSHA: commit, TreeSHA: tree,
			StartedAt: timing.StartedAt, CompletedAt: timing.CompletedAt,
		}
		receipt.Identity = deliveryevidence.AssurancePhaseReceiptIdentity(
			receipt.Sequence, receipt.Repository, receipt.Phase, receipt.CandidateID,
			receipt.BaseSHA, receipt.CommitSHA, receipt.TreeSHA, receipt.StartedAt, receipt.CompletedAt,
		)
		out = append(out, receipt)
	}
	return out
}

func requireReceiptPrefix[T any](persisted, expected []T, kind string) error {
	if len(persisted) == 0 {
		return nil
	}
	if len(persisted) > len(expected) || !reflect.DeepEqual(persisted, expected[:len(persisted)]) {
		return fmt.Errorf("persisted %s assurance projection conflicts with authoritative run (%d persisted, %d expected)", kind, len(persisted), len(expected))
	}
	return nil
}

func reconcileReceipts[T any](persisted, expected []T, key func(T) string, kind string) ([]T, error) {
	if len(persisted) == 0 && len(expected) == 0 {
		return nil, nil
	}
	expectedByKey := make(map[string]T, len(expected))
	for _, receipt := range expected {
		semanticKey := key(receipt)
		if _, duplicate := expectedByKey[semanticKey]; duplicate {
			return nil, fmt.Errorf("authoritative %s assurance facts contain a duplicate semantic key", kind)
		}
		expectedByKey[semanticKey] = receipt
	}
	seen := make(map[string]bool, len(persisted))
	out := make([]T, 0, len(expected))
	for _, receipt := range persisted {
		semanticKey := key(receipt)
		expectedReceipt, known := expectedByKey[semanticKey]
		if seen[semanticKey] || !known {
			return nil, fmt.Errorf("persisted %s assurance projection conflicts with authoritative run", kind)
		}
		seen[semanticKey] = true
		out = append(out, expectedReceipt)
	}
	for _, receipt := range expected {
		if !seen[key(receipt)] {
			out = append(out, receipt)
		}
	}
	return out, nil
}

func latestPhaseTiming(timings []Timing, phase string) (Timing, bool) {
	for index := len(timings) - 1; index >= 0; index-- {
		if timings[index].Phase == phase {
			return timings[index], true
		}
	}
	return Timing{}, false
}

func contiguousReviewTimingGroups(timings []Timing) []Timing {
	var groups []Timing
	for index, timing := range timings {
		if timing.Phase != "review" {
			continue
		}
		if index+1 == len(timings) || timings[index+1].Phase != "review" {
			groups = append(groups, timing)
		}
	}
	return groups
}

func reviewReferenceKey(candidateID string, iteration int, axis deliveryevidence.ReviewAxis) string {
	return fmt.Sprintf("%s\x00%d\x00%s", candidateID, iteration, axis)
}
