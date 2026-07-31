package issuedelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

const reviewPacketSchema = "packy.issue-delivery/review-packets/v1"

type ReviewPacketKind string

const (
	ReviewPacketQualification ReviewPacketKind = "qualification"
	ReviewPacketCandidate     ReviewPacketKind = "candidate"
	ReviewPacketSpecialist    ReviewPacketKind = "specialist"
)

type ReviewPacketRequest struct {
	RepositoryPath string
	IssueNumber    int
	Kind           ReviewPacketKind
	Axis           deliveryevidence.ReviewAxis
	Boundary       SensitiveBoundary
}

type ReviewPacketSet struct {
	Schema   string               `json:"schema"`
	RunID    string               `json:"run_id"`
	Packets  []ReviewPacket       `json:"packets"`
	Manifest ReviewPacketManifest `json:"manifest"`
}

type ReviewPacketManifest struct {
	Entries []ReviewPacketManifestEntry `json:"entries"`
	SHA256  string                      `json:"sha256"`
}

type ReviewPacketManifestEntry struct {
	PacketID string           `json:"packet_id"`
	SHA256   string           `json:"sha256"`
	Kind     ReviewPacketKind `json:"kind"`
}

type ReviewPacket struct {
	Schema                      string                                          `json:"schema"`
	PacketID                    string                                          `json:"packet_id"`
	SHA256                      string                                          `json:"sha256"`
	Kind                        ReviewPacketKind                                `json:"kind"`
	Axis                        deliveryevidence.ReviewAxis                     `json:"axis,omitempty"`
	Boundary                    SensitiveBoundary                               `json:"boundary,omitempty"`
	Specialist                  string                                          `json:"specialist,omitempty"`
	Generation                  int                                             `json:"generation"`
	Iteration                   int                                             `json:"iteration,omitempty"`
	RunID                       string                                          `json:"run_id"`
	Repository                  deliveryevidence.RepositoryIdentity             `json:"repository"`
	Issue                       deliveryevidence.IssueIdentity                  `json:"issue"`
	AuthoritySHA256             string                                          `json:"authority_sha256"`
	Authority                   deliveryevidence.Authority                      `json:"authority"`
	CandidateID                 string                                          `json:"candidate_id,omitempty"`
	BaseSHA                     string                                          `json:"base_sha,omitempty"`
	CommitSHA                   string                                          `json:"commit_sha,omitempty"`
	TreeSHA                     string                                          `json:"tree_sha,omitempty"`
	AcceptanceRows              []deliveryevidence.AcceptanceRow                `json:"acceptance_rows"`
	AcceptanceRowsSHA256        string                                          `json:"acceptance_rows_sha256"`
	RequiredObligations         []deliveryevidence.AcceptanceObligation         `json:"required_obligations"`
	PriorFindings               []deliveryevidence.ReviewFinding                `json:"prior_findings"`
	PriorSpecialistFindings     []SpecialistFinding                             `json:"prior_specialist_findings"`
	PriorAdjudications          []deliveryevidence.Adjudication                 `json:"prior_adjudications"`
	PriorAssuranceAdjudications []deliveryevidence.AssuranceAdjudicationReceipt `json:"prior_assurance_adjudications"`
	RequiredBoundaryProof       *ReviewPacketBoundaryProofObligation            `json:"required_boundary_proof,omitempty"`
	Response                    ReviewPacketResponseTemplate                    `json:"response"`
}

type ReviewPacketBoundaryProofObligation struct {
	RunID              string                              `json:"run_id"`
	CandidateID        string                              `json:"candidate_id"`
	Repository         deliveryevidence.RepositoryIdentity `json:"repository"`
	Issue              deliveryevidence.IssueIdentity      `json:"issue"`
	Boundary           SensitiveBoundary                   `json:"boundary"`
	CommitSHA          string                              `json:"commit_sha"`
	TreeSHA            string                              `json:"tree_sha"`
	Sandboxed          bool                                `json:"sandboxed"`
	IsolatedHome       bool                                `json:"isolated_home"`
	IsolatedConfig     bool                                `json:"isolated_config"`
	NoOperatorMutation bool                                `json:"no_operator_mutation"`
}

type ReviewPacketResponseTemplate struct {
	PacketID      string               `json:"packet_id"`
	Qualification *QualificationReview `json:"qualification,omitempty"`
	Candidate     *CandidateReview     `json:"candidate,omitempty"`
	Specialist    *SpecialistReview    `json:"specialist,omitempty"`
}

// ReviewPackets observes contract-shaped review work for the exact current run.
// It takes the shared issue lock and never advances or rewrites delivery state.
func (m *Module) ReviewPackets(ctx context.Context, request ReviewPacketRequest) (ReviewPacketSet, error) {
	if ctx == nil {
		return ReviewPacketSet{}, errors.New("ReviewPackets requires a context")
	}
	if strings.TrimSpace(request.RepositoryPath) == "" || request.IssueNumber <= 0 {
		return ReviewPacketSet{}, errors.New("ReviewPackets requires a repository path and positive issue number")
	}
	if request.Kind != ReviewPacketQualification && request.Kind != ReviewPacketCandidate && request.Kind != ReviewPacketSpecialist {
		return ReviewPacketSet{}, fmt.Errorf("review packet kind %q is invalid", request.Kind)
	}
	git, err := m.git.ObserveGit(ctx, request.RepositoryPath)
	if err != nil {
		return ReviewPacketSet{}, fmt.Errorf("observe Git: %w", err)
	}
	var result ReviewPacketSet
	err = m.store.observeIssue(ctx, git.CommonDir, request.IssueNumber, func(store lockedIssueStore) error {
		id, data, found, err := store.loadActive()
		if err != nil {
			return err
		}
		if !found {
			return errors.New("active issue delivery run does not exist")
		}
		record, err := decodeRun(data)
		if err != nil {
			return err
		}
		if record.ID != id || record.Schema != runSchema {
			return errors.New("review packets require the exact active schema-v2 run")
		}
		if record.Repository.Owner != git.Owner || record.Repository.Name != git.Name || record.Issue.Number != request.IssueNumber {
			return errors.New("active issue delivery run identity does not match requested repository and issue")
		}
		tracker, err := m.github.ObserveIssue(ctx, git, request.IssueNumber)
		if err != nil {
			return fmt.Errorf("observe GitHub issue: %w", err)
		}
		if tracker.Repository != record.Repository || tracker.Issue != record.Issue {
			return errors.New("active issue delivery run identity does not match current repository and issue")
		}
		compiled, err := compileAuthority(git, tracker, record.Decisions, nil, m.declaredProfile)
		if err != nil || compiled.hash != record.AuthoritySHA256 {
			return errors.New("review packet request is stale because current authority changed")
		}
		packets, err := reviewPacketsFromRecord(record, git, request)
		if err != nil {
			return err
		}
		result = ReviewPacketSet{Schema: reviewPacketSchema, RunID: record.ID, Packets: packets}
		for _, packet := range packets {
			result.Manifest.Entries = append(result.Manifest.Entries, ReviewPacketManifestEntry{PacketID: packet.PacketID, SHA256: packet.SHA256, Kind: packet.Kind})
		}
		result.Manifest.SHA256, err = canonicalReviewPacketDigest(result.Manifest.Entries)
		return err
	})
	if errors.Is(err, errIssueRunActive) {
		return ReviewPacketSet{}, errors.New("another Advance call is active for this issue")
	}
	return result, err
}

func reviewPacketsFromRecord(record runRecord, git GitObservation, request ReviewPacketRequest) ([]ReviewPacket, error) {
	if record.Evidence == nil {
		return nil, errors.New("review packet request lacks current evidence")
	}
	if record.State != StateNeedsReview && record.State != StateWaiting {
		return nil, errors.New("review packet kind is not currently pending")
	}
	if record.PendingDecision != nil || record.PendingQualificationCorrection != nil ||
		record.PendingRepair != nil {
		return nil, errors.New("review packet kind is not currently pending")
	}
	rows := append([]deliveryevidence.AcceptanceRow(nil), record.Evidence.AcceptanceMatrix...)
	rowsDigest, err := acceptanceMatrixDigest(rows)
	if err != nil {
		return nil, err
	}
	base := ReviewPacket{Schema: reviewPacketSchema, Kind: request.Kind, RunID: record.ID, Repository: record.Repository, Issue: record.Issue, AuthoritySHA256: record.AuthoritySHA256, Authority: record.Evidence.Authority, AcceptanceRows: rows, AcceptanceRowsSHA256: rowsDigest, RequiredObligations: packetObligations(rows), PriorFindings: []deliveryevidence.ReviewFinding{}, PriorSpecialistFindings: []SpecialistFinding{}, PriorAdjudications: []deliveryevidence.Adjudication{}, PriorAssuranceAdjudications: []deliveryevidence.AssuranceAdjudicationReceipt{}}
	var packets []ReviewPacket
	switch request.Kind {
	case ReviewPacketQualification:
		if request.Axis != "" || request.Boundary != "" || record.QualificationApproved ||
			len(record.Candidates) != 0 {
			return nil, errors.New("qualification review packet is not currently required")
		}
		base.Generation = len(record.QualificationReviews) + 1
		for _, review := range record.QualificationReviews {
			base.PriorFindings = append(base.PriorFindings, review.Findings...)
		}
		packets = append(packets, base)
	case ReviewPacketCandidate:
		if !record.QualificationApproved {
			return nil, errors.New("candidate review packet is not currently required")
		}
		candidate, generation, err := currentPacketCandidate(record, git)
		if err != nil {
			return nil, err
		}
		axes := missingReviewAxes(candidate)
		if request.Axis != "" {
			if !containsAxis(axes, request.Axis) {
				return nil, errors.New("requested candidate review axis is not currently required")
			}
			axes = []deliveryevidence.ReviewAxis{request.Axis}
		}
		if request.Boundary != "" {
			return nil, errors.New("candidate review packet does not accept a boundary")
		}
		for _, axis := range axes {
			packet := base
			packet.Axis, packet.Generation, packet.Iteration = axis, generation, currentReviewIteration(candidate)
			bindPacketCandidate(&packet, *candidate)
			for _, review := range candidate.Reviews {
				if review.Axis == axis {
					packet.PriorFindings = append(packet.PriorFindings, review.Findings...)
				}
			}
			packets = append(packets, packet)
		}
	case ReviewPacketSpecialist:
		candidate, generation, err := currentPacketCandidate(record, git)
		if err != nil {
			return nil, err
		}
		if len(missingReviewAxes(candidate)) != 0 || len(unresolvedFindingIDs(candidate)) != 0 {
			return nil, errors.New("specialist review packets require completed candidate axes without unresolved findings")
		}
		boundaries := missingSpecialistBoundaries(candidate)
		if request.Boundary != "" {
			if !containsBoundary(boundaries, request.Boundary) {
				return nil, errors.New("requested specialist boundary is not currently required")
			}
			boundaries = []SensitiveBoundary{request.Boundary}
		}
		if request.Axis != "" {
			return nil, errors.New("specialist review packet does not accept an axis")
		}
		for _, boundary := range boundaries {
			packet := base
			packet.Boundary, packet.Specialist, packet.Generation = boundary, specialistForBoundary(boundary), generation
			bindPacketCandidate(&packet, *candidate)
			packet.RequiredBoundaryProof = boundaryProofObligation(record, *candidate, boundary)
			for _, review := range candidate.SpecialistReviews {
				if review.Boundary == boundary {
					packet.PriorSpecialistFindings = append(packet.PriorSpecialistFindings, review.Findings...)
				}
			}
			packets = append(packets, packet)
		}
	}
	if len(packets) == 0 {
		return nil, errors.New("no review packets are currently required")
	}
	for i := range packets {
		addRelevantAdjudications(&packets[i], record.Evidence.Adjudications)
		addRelevantAssuranceAdjudications(&packets[i], record.Evidence.AssuranceAdjudications)
		if err := finalizeReviewPacket(&packets[i]); err != nil {
			return nil, err
		}
	}
	sort.Slice(packets, func(i, j int) bool { return packets[i].PacketID < packets[j].PacketID })
	return packets, nil
}

func currentPacketCandidate(record runRecord, git GitObservation) (*Candidate, int, error) {
	if len(record.Candidates) == 0 {
		return nil, 0, errors.New("candidate review packet is not currently required")
	}
	c := &record.Candidates[len(record.Candidates)-1]
	if c.CommitSHA != git.HeadSHA || c.TreeSHA != git.TreeSHA {
		return nil, 0, errors.New("review packet request is stale because current Git checkout changed")
	}
	return c, len(record.Candidates), nil
}

func bindPacketCandidate(packet *ReviewPacket, c Candidate) {
	packet.CandidateID, packet.BaseSHA, packet.CommitSHA, packet.TreeSHA = c.ID, c.BaseSHA, c.CommitSHA, c.TreeSHA
}

func packetObligations(rows []deliveryevidence.AcceptanceRow) []deliveryevidence.AcceptanceObligation {
	seen := map[deliveryevidence.AcceptanceObligation]bool{}
	var out []deliveryevidence.AcceptanceObligation
	for _, row := range rows {
		for _, obligation := range row.Obligations {
			if !seen[obligation] {
				seen[obligation] = true
				out = append(out, obligation)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Phase == out[j].Phase {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Phase < out[j].Phase
	})
	return out
}

func addRelevantAdjudications(packet *ReviewPacket, all []deliveryevidence.Adjudication) {
	ids := map[string]bool{}
	for _, f := range packet.PriorFindings {
		ids[f.ID] = true
	}
	for _, f := range packet.PriorSpecialistFindings {
		ids[f.ID] = true
	}
	for _, a := range all {
		if ids[a.FindingID] {
			packet.PriorAdjudications = append(packet.PriorAdjudications, a)
		}
	}
}

func addRelevantAssuranceAdjudications(packet *ReviewPacket, all []deliveryevidence.AssuranceAdjudicationReceipt) {
	ids := map[string]bool{}
	for _, finding := range packet.PriorFindings {
		ids[finding.ID] = true
	}
	for _, finding := range packet.PriorSpecialistFindings {
		ids[finding.ID] = true
	}
	for _, adjudication := range all {
		if adjudication.CandidateID != packet.CandidateID {
			continue
		}
		copy := adjudication
		copy.Findings = nil
		for _, finding := range adjudication.Findings {
			if ids[finding.FindingID] {
				copy.Findings = append(copy.Findings, finding)
			}
		}
		if len(copy.Findings) != 0 {
			packet.PriorAssuranceAdjudications = append(packet.PriorAssuranceAdjudications, copy)
		}
	}
}

func finalizeReviewPacket(packet *ReviewPacket) error {
	idProjection := struct {
		Schema                                   string           `json:"schema"`
		Kind                                     ReviewPacketKind `json:"kind"`
		RunID, AuthoritySHA256, CandidateID      string
		Axis                                     deliveryevidence.ReviewAxis `json:"axis,omitempty"`
		Boundary                                 SensitiveBoundary           `json:"boundary,omitempty"`
		Generation, Iteration                    int
		AcceptanceRowsSHA256, CommitSHA, TreeSHA string
		RequiredBoundaryProof                    *ReviewPacketBoundaryProofObligation `json:"required_boundary_proof,omitempty"`
	}{reviewPacketSchema, packet.Kind, packet.RunID, packet.AuthoritySHA256, packet.CandidateID, packet.Axis, packet.Boundary, packet.Generation, packet.Iteration, packet.AcceptanceRowsSHA256, packet.CommitSHA, packet.TreeSHA, packet.RequiredBoundaryProof}
	id, err := canonicalReviewPacketDigest(idProjection)
	if err != nil {
		return err
	}
	packet.PacketID = id
	switch packet.Kind {
	case ReviewPacketQualification:
		packet.Response = ReviewPacketResponseTemplate{PacketID: id, Qualification: &QualificationReview{PacketID: id, AuthoritySHA256: packet.AuthoritySHA256, AcceptanceMatrixSHA256: packet.AcceptanceRowsSHA256, Findings: []deliveryevidence.ReviewFinding{}}}
	case ReviewPacketCandidate:
		packet.Response = ReviewPacketResponseTemplate{PacketID: id, Candidate: &CandidateReview{PacketID: id, CandidateID: packet.CandidateID, Axis: packet.Axis, Iteration: packet.Iteration, CommitSHA: packet.CommitSHA, TreeSHA: packet.TreeSHA, Findings: []deliveryevidence.ReviewFinding{}}}
	case ReviewPacketSpecialist:
		packet.Response = ReviewPacketResponseTemplate{PacketID: id, Specialist: &SpecialistReview{PacketID: id, CandidateID: packet.CandidateID, Boundary: packet.Boundary, Specialist: packet.Specialist, Findings: []SpecialistFinding{}}}
	}
	digestProjection := *packet
	digestProjection.SHA256 = ""
	packet.SHA256, err = canonicalReviewPacketDigest(digestProjection)
	return err
}

func expectedCandidatePacketID(record runRecord, candidate Candidate, axis deliveryevidence.ReviewAxis) string {
	return candidatePacketID(record, candidate, axis, currentReviewIteration(&candidate))
}

func expectedSpecialistPacketID(record runRecord, candidate Candidate, boundary SensitiveBoundary) string {
	return specialistPacketID(record, candidate, boundary)
}

func candidatePacketID(record runRecord, candidate Candidate, axis deliveryevidence.ReviewAxis, iteration int) string {
	packet := packetIdentityBase(record, ReviewPacketCandidate)
	packet.Axis, packet.Generation, packet.Iteration = axis, len(record.Candidates), iteration
	bindPacketCandidate(&packet, candidate)
	if err := finalizeReviewPacket(&packet); err != nil {
		return ""
	}
	return packet.PacketID
}

func specialistPacketID(record runRecord, candidate Candidate, boundary SensitiveBoundary) string {
	packet := packetIdentityBase(record, ReviewPacketSpecialist)
	packet.Boundary, packet.Specialist, packet.Generation = boundary, specialistForBoundary(boundary), len(record.Candidates)
	bindPacketCandidate(&packet, candidate)
	packet.RequiredBoundaryProof = boundaryProofObligation(record, candidate, boundary)
	if err := finalizeReviewPacket(&packet); err != nil {
		return ""
	}
	return packet.PacketID
}

func boundaryProofObligation(record runRecord, candidate Candidate, boundary SensitiveBoundary) *ReviewPacketBoundaryProofObligation {
	return &ReviewPacketBoundaryProofObligation{RunID: record.ID, CandidateID: candidate.ID, Repository: record.Repository, Issue: record.Issue, Boundary: boundary, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA, Sandboxed: true, IsolatedHome: true, IsolatedConfig: true, NoOperatorMutation: true}
}

func packetIdentityBase(record runRecord, kind ReviewPacketKind) ReviewPacket {
	packet := ReviewPacket{Schema: reviewPacketSchema, Kind: kind, RunID: record.ID, Repository: record.Repository, Issue: record.Issue, AuthoritySHA256: record.AuthoritySHA256}
	if record.Evidence != nil {
		packet.AcceptanceRowsSHA256, _ = acceptanceMatrixDigest(record.Evidence.AcceptanceMatrix)
	}
	return packet
}

func canonicalReviewPacketDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func validatePacketResponseDigest(packetID, digest string, completed bool) error {
	if packetID == "" {
		if digest != "" {
			return errors.New("legacy response without packet ID cannot bind a response digest")
		}
		return nil
	}
	if digest == "" && !completed {
		return nil
	}
	if !runIDPattern.MatchString(digest) {
		return errors.New("completed packet response requires an exact source SHA-256")
	}
	return nil
}

func packetFindingKey(packetID, findingID string) string {
	if packetID == "" {
		return findingID
	}
	return packetID + "\x00" + findingID
}

func qualifyPacketFindingID(packetID, findingID string) string {
	if packetID == "" || strings.HasPrefix(findingID, packetID+":") {
		return findingID
	}
	return packetID + ":" + findingID
}

func qualifyCandidateReviewFindings(review CandidateReview) CandidateReview {
	review.Findings = append([]deliveryevidence.ReviewFinding{}, review.Findings...)
	for i := range review.Findings {
		review.Findings[i].ID = qualifyPacketFindingID(review.PacketID, review.Findings[i].ID)
	}
	return review
}

func qualifySpecialistReviewFindings(review SpecialistReview) SpecialistReview {
	review.Findings = append([]SpecialistFinding{}, review.Findings...)
	for i := range review.Findings {
		review.Findings[i].ID = qualifyPacketFindingID(review.PacketID, review.Findings[i].ID)
	}
	return review
}
