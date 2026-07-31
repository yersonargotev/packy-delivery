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
	reviewTimes := phaseCompletionTimes(record.Timing, "review")
	reviewTime := 0
	reviewIDs := make(map[string]string)
	adjudicationGenerations := make(map[string]int)
	adjudicationRequests := make(map[string]deliveryevidence.AssuranceAdjudicationReceipt)
	for _, receipt := range record.Evidence.AssuranceAdjudications {
		if receipt.Generation > adjudicationGenerations[receipt.CandidateID] {
			adjudicationGenerations[receipt.CandidateID] = receipt.Generation
		}
		adjudicationRequests[receipt.CandidateID+"\x00"+receipt.RequestID] = receipt
	}

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
			completedAt := record.UpdatedAt
			if reviewTime < len(reviewTimes) {
				completedAt = reviewTimes[reviewTime]
			}
			reviewTime++
			receipt := deliveryevidence.CandidateReviewReceipt{
				CandidateID: candidate.ID, Iteration: iteration, Axes: axes,
				FindingsSHA256: findingsDigest, CommitSHA: candidate.CommitSHA,
				TreeSHA: candidate.TreeSHA, CompletedAt: completedAt,
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
		generationOffset := 0
		if len(candidate.RepairBatches) > 0 {
			firstKey := candidate.ID + "\x00" + candidate.RepairBatches[0].RequestID
			if _, retained := adjudicationRequests[firstKey]; !retained {
				generationOffset = adjudicationGenerations[candidate.ID]
			}
		}
		for batchIndex, batch := range candidate.RepairBatches {
			findings := make([]deliveryevidence.AssuranceFindingDecision, len(batch.Decision.Findings))
			for index, finding := range batch.Decision.Findings {
				findings[index] = deliveryevidence.AssuranceFindingDecision{
					FindingID: finding.FindingID, Disposition: string(finding.Disposition), Evidence: finding.Evidence,
				}
			}
			sort.Slice(findings, func(i, j int) bool { return findings[i].FindingID < findings[j].FindingID })
			generation := generationOffset + batchIndex + 1
			receipt := deliveryevidence.AssuranceAdjudicationReceipt{
				RequestID: batch.RequestID, CandidateID: candidate.ID, Generation: generation,
				Class: string(batch.Decision.Class), CompatiblePrefix: batch.CompatiblePrefix, Findings: findings,
			}
			receipt.Identity = deliveryevidence.AssuranceAdjudicationReceiptIdentity(
				receipt.RequestID, receipt.CandidateID, receipt.Generation, receipt.Class,
				receipt.CompatiblePrefix, receipt.Findings,
			)
			expectedAdjudications = append(expectedAdjudications, receipt)
		}
		if candidate.Exhaustive != nil {
			result := candidate.Exhaustive.Result
			receipt := deliveryevidence.ExhaustiveAssuranceReceipt{
				Repository: record.Repository, CandidateID: candidate.ID,
				CommitSHA: result.CommitSHA, TreeSHA: result.TreeSHA,
				CheckoutSHA256: result.CheckoutSHA256, ValidatorIdentity: result.ValidatorIdentity,
				ValidatorSHA256:            result.ValidatorSHA256,
				ValidatorIdentityExpiresAt: result.ValidatorIdentityExpiresAt,
				Command:                    result.Command, HomeRoot: result.HomeRoot, ConfigRoot: result.ConfigRoot,
				Sandboxed: result.Sandboxed, CompletedAt: candidate.Exhaustive.CompletedAt,
			}
			receipt.Identity = deliveryevidence.ExhaustiveAssuranceReceiptIdentity(receipt)
			expectedExhaustive = append(expectedExhaustive, receipt)
			for proofIndex := range candidate.Acceptance {
				reference := candidate.Acceptance[proofIndex].ValidationReceipt
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
	mergedReviews, err := mergeReceipts(record.Evidence.CandidateReviewReceipts, expectedReviews,
		func(value deliveryevidence.CandidateReviewReceipt) string {
			return fmt.Sprintf("%s\x00%d", value.CandidateID, value.Iteration)
		}, "candidate review")
	if err != nil {
		return err
	}
	mergedAdjudications, err := mergeAdjudicationReceipts(
		record.Evidence.AssuranceAdjudications, expectedAdjudications,
	)
	if err != nil {
		return err
	}
	if err := requireReceiptPrefix(record.Evidence.AssurancePhases, expectedPhases, "phase"); err != nil {
		return err
	}
	mergedExhaustive, err := mergeReceipts(record.Evidence.ExhaustiveAssurance, expectedExhaustive,
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
		if hasAnyReceiptReferences(record.Candidates) {
			return fmt.Errorf("persisted automatic assurance references lack canonical receipts")
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

func mergeReceipts[T any](persisted, expected []T, key func(T) string, kind string) ([]T, error) {
	out := append([]T(nil), persisted...)
	positions := make(map[string]int, len(persisted))
	for index, receipt := range persisted {
		positions[key(receipt)] = index
	}
	for _, receipt := range expected {
		if index, ok := positions[key(receipt)]; ok {
			if !reflect.DeepEqual(out[index], receipt) {
				return nil, fmt.Errorf("persisted %s assurance projection conflicts with authoritative run", kind)
			}
			continue
		}
		positions[key(receipt)] = len(out)
		out = append(out, receipt)
	}
	return out, nil
}

func mergeAdjudicationReceipts(
	persisted, expected []deliveryevidence.AssuranceAdjudicationReceipt,
) ([]deliveryevidence.AssuranceAdjudicationReceipt, error) {
	out := append([]deliveryevidence.AssuranceAdjudicationReceipt(nil), persisted...)
	positions := make(map[string]int, len(out))
	for index, receipt := range out {
		positions[receipt.CandidateID+"\x00"+receipt.RequestID] = index
	}
	for _, receipt := range expected {
		key := receipt.CandidateID + "\x00" + receipt.RequestID
		index, ok := positions[key]
		if !ok {
			positions[key] = len(out)
			out = append(out, receipt)
			continue
		}
		if reflect.DeepEqual(out[index], receipt) {
			continue
		}
		prior := out[index]
		prior.CompatiblePrefix = true
		prior.Identity = deliveryevidence.AssuranceAdjudicationReceiptIdentity(
			prior.RequestID, prior.CandidateID, prior.Generation, prior.Class,
			prior.CompatiblePrefix, prior.Findings,
		)
		if !out[index].CompatiblePrefix && receipt.CompatiblePrefix && reflect.DeepEqual(prior, receipt) {
			out[index] = receipt
			continue
		}
		return nil, fmt.Errorf("persisted adjudication assurance projection conflicts with authoritative run")
	}
	return out, nil
}

func phaseCompletionTimes(timings []Timing, phase string) []string {
	var out []string
	for _, timing := range timings {
		if timing.Phase == phase {
			out = append(out, timing.CompletedAt)
		}
	}
	return out
}

func reviewReferenceKey(candidateID string, iteration int, axis deliveryevidence.ReviewAxis) string {
	return fmt.Sprintf("%s\x00%d\x00%s", candidateID, iteration, axis)
}
