package deliveryevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type CandidateReviewReceipt struct {
	Identity       string       `json:"identity"`
	CandidateID    string       `json:"candidate_id"`
	Iteration      int          `json:"iteration"`
	Axes           []ReviewAxis `json:"axes"`
	FindingsSHA256 string       `json:"findings_sha256"`
	CommitSHA      string       `json:"commit_sha"`
	TreeSHA        string       `json:"tree_sha"`
	CompletedAt    string       `json:"completed_at"`
}

type AssuranceFindingDecision struct {
	FindingID   string `json:"finding_id"`
	Disposition string `json:"disposition"`
	Evidence    string `json:"evidence"`
}

type AssuranceAdjudicationReceipt struct {
	Identity         string                     `json:"identity"`
	RequestID        string                     `json:"request_id"`
	CandidateID      string                     `json:"candidate_id"`
	Generation       int                        `json:"generation"`
	Class            string                     `json:"class"`
	CompatiblePrefix bool                       `json:"compatible_prefix,omitempty"`
	Findings         []AssuranceFindingDecision `json:"findings"`
}

type AssurancePhaseReceipt struct {
	Identity    string             `json:"identity"`
	Sequence    int                `json:"sequence"`
	Repository  RepositoryIdentity `json:"repository"`
	Phase       string             `json:"phase"`
	CandidateID string             `json:"candidate_id,omitempty"`
	BaseSHA     string             `json:"base_sha"`
	CommitSHA   string             `json:"commit_sha,omitempty"`
	TreeSHA     string             `json:"tree_sha,omitempty"`
	StartedAt   string             `json:"started_at"`
	CompletedAt string             `json:"completed_at"`
}

type ExhaustiveAssuranceReceipt struct {
	Identity                   string             `json:"identity"`
	Repository                 RepositoryIdentity `json:"repository"`
	CandidateID                string             `json:"candidate_id"`
	CommitSHA                  string             `json:"commit_sha"`
	TreeSHA                    string             `json:"tree_sha"`
	CheckoutSHA256             string             `json:"checkout_sha256"`
	ValidatorIdentity          string             `json:"validator_identity"`
	ValidatorSHA256            string             `json:"validator_sha256"`
	ValidatorIdentityExpiresAt string             `json:"validator_identity_expires_at"`
	Command                    string             `json:"command"`
	HomeRoot                   string             `json:"home_root"`
	ConfigRoot                 string             `json:"config_root"`
	Sandboxed                  bool               `json:"sandboxed"`
	CompletedAt                string             `json:"completed_at"`
}

func CandidateReviewReceiptIdentity(
	candidateID string,
	iteration int,
	axes []ReviewAxis,
	findingsSHA256, commitSHA, treeSHA string,
) string {
	parts := []string{candidateID, strconv.Itoa(iteration), findingsSHA256, commitSHA, treeSHA}
	for _, axis := range axes {
		parts = append(parts, string(axis))
	}
	return assuranceIdentity("candidate-review", parts...)
}

func AssuranceAdjudicationReceiptIdentity(
	requestID, candidateID string,
	generation int,
	class string,
	compatiblePrefix bool,
	findings []AssuranceFindingDecision,
) string {
	parts := []string{requestID, candidateID, strconv.Itoa(generation), class, strconv.FormatBool(compatiblePrefix)}
	for _, finding := range findings {
		parts = append(parts, finding.FindingID, finding.Disposition, finding.Evidence)
	}
	return assuranceIdentity("adjudication", parts...)
}

func AssurancePhaseReceiptIdentity(
	sequence int,
	repository RepositoryIdentity,
	phase, candidateID, baseSHA, commitSHA, treeSHA, startedAt, completedAt string,
) string {
	return assuranceIdentity(
		"phase", strconv.Itoa(sequence), repository.Owner, repository.Name, repository.NodeID,
		phase, candidateID, baseSHA, commitSHA, treeSHA, startedAt, completedAt,
	)
}

func ExhaustiveAssuranceReceiptIdentity(receipt ExhaustiveAssuranceReceipt) string {
	return assuranceIdentity(
		"exhaustive", receipt.Repository.Owner, receipt.Repository.Name, receipt.Repository.NodeID,
		receipt.CandidateID, receipt.CommitSHA, receipt.TreeSHA, receipt.CheckoutSHA256,
		receipt.ValidatorIdentity, receipt.ValidatorSHA256, receipt.ValidatorIdentityExpiresAt,
		receipt.Command, receipt.HomeRoot, receipt.ConfigRoot, strconv.FormatBool(receipt.Sandboxed),
		receipt.CompletedAt,
	)
}

func assuranceIdentity(kind string, parts ...string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + strings.Join(parts, "\x00")))
	return kind + "-" + hex.EncodeToString(sum[:])
}

func validateAutomaticAssurance(b Bundle) error {
	if b.Schema == SchemaV1 {
		if len(b.CandidateReviewReceipts) != 0 || len(b.AssuranceAdjudications) != 0 ||
			len(b.AssurancePhases) != 0 || len(b.ExhaustiveAssurance) != 0 {
			return errors.New("schema v1 cannot contain automatic assurance receipts")
		}
		return nil
	}
	reviewIDs := map[string]bool{}
	for _, receipt := range b.CandidateReviewReceipts {
		if receipt.Iteration < 1 || !gitSHA(receipt.CommitSHA) || !gitSHA(receipt.TreeSHA) ||
			blank(receipt.CandidateID) || !digest(receipt.FindingsSHA256) || len(receipt.Axes) == 0 {
			return errors.New("candidate review assurance receipt is incomplete")
		}
		if _, err := time.Parse(time.RFC3339Nano, receipt.CompletedAt); err != nil {
			return errors.New("candidate review completion is invalid")
		}
		axes := append([]ReviewAxis(nil), receipt.Axes...)
		sort.Slice(axes, func(i, j int) bool { return axes[i] < axes[j] })
		for index, axis := range axes {
			if (axis != ReviewStandards && axis != ReviewSpec) ||
				(index > 0 && axes[index-1] == axis) {
				return errors.New("candidate review assurance axes are invalid")
			}
		}
		if receipt.Identity != CandidateReviewReceiptIdentity(
			receipt.CandidateID, receipt.Iteration, axes, receipt.FindingsSHA256, receipt.CommitSHA, receipt.TreeSHA,
		) || reviewIDs[receipt.Identity] {
			return errors.New("candidate review assurance identity is invalid")
		}
		reviewIDs[receipt.Identity] = true
	}
	adjudicationIDs := map[string]bool{}
	for _, receipt := range b.AssuranceAdjudications {
		if blank(receipt.RequestID) || blank(receipt.CandidateID) || receipt.Generation < 1 ||
			(receipt.Class != "adjudication-only" && receipt.Class != "bounded" &&
				receipt.Class != "candidate-changing") || len(receipt.Findings) == 0 {
			return errors.New("assurance adjudication receipt is incomplete")
		}
		for index, finding := range receipt.Findings {
			if blank(finding.FindingID) ||
				(finding.Disposition != "accepted" && finding.Disposition != "rejected-with-evidence") ||
				blank(finding.Evidence) ||
				(index > 0 && receipt.Findings[index-1].FindingID >= finding.FindingID) {
				return errors.New("assurance adjudication finding batch is invalid")
			}
		}
		if receipt.Identity != AssuranceAdjudicationReceiptIdentity(
			receipt.RequestID, receipt.CandidateID, receipt.Generation, receipt.Class,
			receipt.CompatiblePrefix, receipt.Findings,
		) || adjudicationIDs[receipt.Identity] {
			return errors.New("assurance adjudication identity is invalid")
		}
		adjudicationIDs[receipt.Identity] = true
	}
	for index, receipt := range b.AssurancePhases {
		if receipt.Sequence != index+1 || receipt.Repository != b.Repository || blank(receipt.Phase) ||
			!gitSHA(receipt.BaseSHA) || !gitSHA(receipt.CommitSHA) || !gitSHA(receipt.TreeSHA) {
			return errors.New("assurance phase receipt is incomplete")
		}
		started, err := time.Parse(time.RFC3339Nano, receipt.StartedAt)
		if err != nil {
			return errors.New("assurance phase start is invalid")
		}
		completed, err := time.Parse(time.RFC3339Nano, receipt.CompletedAt)
		if err != nil || completed.Before(started) {
			return errors.New("assurance phase completion is invalid")
		}
		if receipt.Identity != AssurancePhaseReceiptIdentity(
			receipt.Sequence, receipt.Repository, receipt.Phase, receipt.CandidateID,
			receipt.BaseSHA, receipt.CommitSHA, receipt.TreeSHA, receipt.StartedAt, receipt.CompletedAt,
		) {
			return errors.New("assurance phase receipt identity is invalid")
		}
	}
	exhaustiveIDs := map[string]bool{}
	for _, receipt := range b.ExhaustiveAssurance {
		if receipt.Repository != b.Repository || blank(receipt.CandidateID) ||
			!gitSHA(receipt.CommitSHA) || !gitSHA(receipt.TreeSHA) ||
			!digest(receipt.CheckoutSHA256) || blank(receipt.ValidatorIdentity) ||
			!digest(receipt.ValidatorSHA256) || blank(receipt.Command) ||
			!receipt.Sandboxed || blank(receipt.HomeRoot) || blank(receipt.ConfigRoot) {
			return errors.New("exhaustive assurance receipt is incomplete")
		}
		if _, err := time.Parse(time.RFC3339Nano, receipt.CompletedAt); err != nil {
			return errors.New("exhaustive assurance completion is invalid")
		}
		if _, err := time.Parse(time.RFC3339Nano, receipt.ValidatorIdentityExpiresAt); err != nil {
			return errors.New("exhaustive assurance validator identity expiry is invalid")
		}
		if receipt.Identity != ExhaustiveAssuranceReceiptIdentity(receipt) ||
			exhaustiveIDs[receipt.Identity] {
			return fmt.Errorf("exhaustive assurance identity is invalid")
		}
		exhaustiveIDs[receipt.Identity] = true
	}
	return nil
}
