package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type fakeReviewPacketMaterializer struct {
	requests []issuedelivery.ReviewPacketRequest
	set      issuedelivery.ReviewPacketSet
	err      error
}

func (f *fakeReviewPacketMaterializer) ReviewPackets(
	_ context.Context,
	request issuedelivery.ReviewPacketRequest,
) (issuedelivery.ReviewPacketSet, error) {
	f.requests = append(f.requests, request)
	return f.set, f.err
}

func testReviewPacketSet() issuedelivery.ReviewPacketSet {
	standardsID := strings.Repeat("1", 64)
	specID := strings.Repeat("2", 64)
	standards := issuedelivery.ReviewPacket{
		Schema: "packy.issue-delivery/review-packets/v1", PacketID: standardsID,
		SHA256: strings.Repeat("a", 64), Kind: issuedelivery.ReviewPacketCandidate,
		Axis: deliveryevidence.ReviewStandards,
		Response: issuedelivery.ReviewPacketResponseTemplate{
			PacketID: standardsID,
			Candidate: &issuedelivery.CandidateReview{
				PacketID: standardsID, CandidateID: "candidate-1",
				Axis: deliveryevidence.ReviewStandards,
			},
		},
	}
	spec := issuedelivery.ReviewPacket{
		Schema: "packy.issue-delivery/review-packets/v1", PacketID: specID,
		SHA256: strings.Repeat("b", 64), Kind: issuedelivery.ReviewPacketCandidate,
		Axis: deliveryevidence.ReviewSpec,
		Response: issuedelivery.ReviewPacketResponseTemplate{
			PacketID: specID,
			Candidate: &issuedelivery.CandidateReview{
				PacketID: specID, CandidateID: "candidate-1",
				Axis: deliveryevidence.ReviewSpec,
			},
		},
	}
	packetDigest := func(packet issuedelivery.ReviewPacket) string {
		raw, err := json.Marshal(reviewPacketDigestProjection(packet))
		if err != nil {
			panic(err)
		}
		return fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	standards.SHA256 = packetDigest(standards)
	spec.SHA256 = packetDigest(spec)
	standards.Response.PacketSHA256 = standards.SHA256
	standards.Response.Candidate.PacketSHA256 = standards.SHA256
	spec.Response.PacketSHA256 = spec.SHA256
	spec.Response.Candidate.PacketSHA256 = spec.SHA256
	manifestEntries := []issuedelivery.ReviewPacketManifestEntry{
		{PacketID: standardsID, SHA256: standards.SHA256, Kind: standards.Kind},
		{PacketID: specID, SHA256: spec.SHA256, Kind: spec.Kind},
	}
	manifestRaw, err := json.Marshal(manifestEntries)
	if err != nil {
		panic(err)
	}
	return issuedelivery.ReviewPacketSet{
		Schema: "packy.issue-delivery/review-packets/v1", RunID: "run-1",
		Packets: []issuedelivery.ReviewPacket{standards, spec},
		Manifest: issuedelivery.ReviewPacketManifest{
			Entries: manifestEntries,
			SHA256:  fmt.Sprintf("%x", sha256.Sum256(manifestRaw)),
		},
	}
}

func TestReviewPacketsCommandExportsDeterministicPrivateDirectory(t *testing.T) {
	repository := t.TempDir()
	output := filepath.Join(t.TempDir(), "packets")
	fake := &fakeReviewPacketMaterializer{set: testReviewPacketSet()}
	cmd := command{ReviewPacketFactory: func(string) (issueDeliveryReviewPacketMaterializer, error) {
		return fake, nil
	}}
	if err := cmd.run(context.Background(), []string{
		"review-packets", "--repository", repository, "--issue", "30",
		"--kind", "candidate", "--output", output,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	resolvedRepository, err := filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.requests) != 1 ||
		fake.requests[0].RepositoryPath != resolvedRepository ||
		fake.requests[0].IssueNumber != 30 ||
		fake.requests[0].Kind != issuedelivery.ReviewPacketCandidate {
		t.Fatalf("review packet requests = %#v", fake.requests)
	}
	directoryInfo, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("packet directory mode = %o", directoryInfo.Mode().Perm())
	}
	entries, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("packet directory entries = %d", len(entries))
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("packet file %q mode = %v", entry.Name(), info.Mode())
		}
	}
	var manifest reviewPacketDirectoryManifest
	raw, err := os.ReadFile(filepath.Join(output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != reviewPacketDirectorySchema ||
		len(manifest.Entries) != 2 ||
		manifest.Entries[0].PacketID >= manifest.Entries[1].PacketID {
		t.Fatalf("packet manifest = %#v", manifest)
	}

	contents, err := loadAdvanceReviewContents(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != 2 || len(contents[0].Reviews) != 1 || len(contents[1].Reviews) != 1 ||
		contents[0].Reviews[0].Axis != deliveryevidence.ReviewStandards ||
		contents[1].Reviews[0].Axis != deliveryevidence.ReviewSpec {
		t.Fatalf("loaded packet responses = %#v", contents)
	}

	advancer := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{{
		RunID: "run-1", State: issuedelivery.StateWaiting, Reason: "reviews remain pending",
	}}}
	var configured advanceOptions
	advanceCommand := command{AdvanceFactory: func(options advanceOptions) (issueDeliveryAdvancer, error) {
		configured = options
		return advancer, nil
	}}
	if err := advanceCommand.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "30",
		"--review-content", output,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(configured.Reviews) != 2 || len(advancer.requests) != 1 ||
		len(advancer.requests[0].CandidateReviews) != 2 {
		t.Fatalf("packet directory was not admitted through Advance: options=%#v requests=%#v", configured, advancer.requests)
	}
}

func TestReviewPacketDirectoryRefusesExistingAndNonRegularTargets(t *testing.T) {
	set := testReviewPacketSet()
	root := t.TempDir()
	existing := filepath.Join(root, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeReviewPacketDirectory(existing, set); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output accepted: %v", err)
	}
	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(existing, symlink); err != nil {
		t.Fatal(err)
	}
	if err := writeReviewPacketDirectory(symlink, set); err == nil ||
		!strings.Contains(err.Error(), "not a regular directory path") {
		t.Fatalf("symlink output accepted: %v", err)
	}
}

func TestAtomicReviewPacketDirectoryPublicationDoesNotReplaceRaceWinner(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	target := filepath.Join(root, "target")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "manifest.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "race-winner")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicPublishReviewPacketDirectory(staging, target); err == nil {
		t.Fatal("atomic directory publication replaced an existing race winner")
	}
	if raw, err := os.ReadFile(sentinel); err != nil || string(raw) != "preserve" {
		t.Fatalf("race winner was changed: %q, %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(staging, "manifest.json")); err != nil {
		t.Fatalf("failed publication consumed staging directory: %v", err)
	}
}

func TestAdvanceReviewContentDirectoryRejectsMismatchedAndSymlinkedResponses(t *testing.T) {
	output := filepath.Join(t.TempDir(), "packets")
	if err := writeReviewPacketDirectory(output, testReviewPacketSet()); err != nil {
		t.Fatal(err)
	}
	var manifest reviewPacketDirectoryManifest
	manifestRaw, err := os.ReadFile(filepath.Join(output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	responsePath := filepath.Join(output, manifest.Entries[0].ResponseFile)
	responseRaw, err := os.ReadFile(responsePath)
	if err != nil {
		t.Fatal(err)
	}
	var response issuedelivery.ReviewPacketResponseTemplate
	if err = json.Unmarshal(responseRaw, &response); err != nil {
		t.Fatal(err)
	}
	response.PacketID = strings.Repeat("f", 64)
	bad, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(responsePath, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadAdvanceReviewContents(output); err == nil ||
		!strings.Contains(err.Error(), "packet identity") {
		t.Fatalf("mismatched response accepted: %v", err)
	}

	if err = os.Remove(responsePath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "response.json")
	if err = os.WriteFile(target, responseRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, responsePath); err != nil {
		t.Fatal(err)
	}
	if _, err = loadAdvanceReviewContents(output); err == nil ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlinked response accepted: %v", err)
	}
}

func TestAdvanceReviewContentDirectoryRejectsNonRegularManifest(t *testing.T) {
	for _, test := range []struct {
		name    string
		replace func(*testing.T, string, []byte)
	}{
		{
			name: "symlink",
			replace: func(t *testing.T, path string, original []byte) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "manifest.json")
				if err := os.WriteFile(target, original, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			replace: func(t *testing.T, path string, _ []byte) {
				t.Helper()
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "packets")
			if err := writeReviewPacketDirectory(output, testReviewPacketSet()); err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(output, "manifest.json")
			original, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(manifestPath); err != nil {
				t.Fatal(err)
			}
			test.replace(t, manifestPath, original)
			if _, err = loadAdvanceReviewContents(output); err == nil ||
				!strings.Contains(err.Error(), "manifest is not a regular file") {
				t.Fatalf("non-regular manifest accepted: %v", err)
			}
		})
	}
}

func TestAdvanceReviewContentDirectoryRejectsMalformedManifest(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*reviewPacketDirectoryManifest)
	}{
		{
			name: "unordered",
			mutate: func(manifest *reviewPacketDirectoryManifest) {
				manifest.Entries[0], manifest.Entries[1] = manifest.Entries[1], manifest.Entries[0]
			},
		},
		{
			name: "unsafe response filename",
			mutate: func(manifest *reviewPacketDirectoryManifest) {
				manifest.Entries[0].ResponseFile = "../response.json"
			},
		},
		{
			name: "duplicate packet",
			mutate: func(manifest *reviewPacketDirectoryManifest) {
				manifest.Entries[1] = manifest.Entries[0]
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "packets")
			if err := writeReviewPacketDirectory(output, testReviewPacketSet()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(output, "manifest.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var manifest reviewPacketDirectoryManifest
			if err = json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
			test.mutate(&manifest)
			raw, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err = loadAdvanceReviewContents(output); err == nil {
				t.Fatal("malformed review packet manifest was accepted")
			}
		})
	}
}

func TestReviewPacketDirectoryPartiallyAdmitsReplaysAndRejectsConflict(t *testing.T) {
	module, qualified, repository, _, _ := productionReadyModule(
		t, nil, nil, nil, "before-qualification-approval",
	)
	qualification := advanceReviewContent{QualificationReview: &issuedelivery.QualificationReview{
		AuthoritySHA256:        qualified.Observations.AuthoritySHA256,
		AcceptanceMatrixSHA256: commandAcceptanceDigest(t, qualified.Evidence.AcceptanceMatrix),
		Findings:               []deliveryevidence.ReviewFinding{},
		Completed:              true,
	}}
	qualificationRaw, err := json.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	qualificationPath := filepath.Join(t.TempDir(), "qualification.json")
	if err = os.WriteFile(qualificationPath, qualificationRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	advanceCommand := command{
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) { return module, nil },
	}
	pending := runAdvanceCommandReport(
		t, advanceCommand, repository, "--review-content", qualificationPath,
	)
	if pending.Candidate == nil || len(pending.Candidate.Reviews) != 0 {
		t.Fatalf("candidate review fixture = %#v", pending)
	}

	output := filepath.Join(t.TempDir(), "packets")
	exportCommand := command{ReviewPacketFactory: func(string) (issueDeliveryReviewPacketMaterializer, error) {
		return module, nil
	}}
	if err = exportCommand.run(context.Background(), []string{
		"review-packets", "--repository", repository, "--issue", "361",
		"--kind", "candidate", "--output", output,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var manifest reviewPacketDirectoryManifest
	manifestRaw, err := os.ReadFile(filepath.Join(output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	var responsePath string
	var responseRaw []byte
	var response issuedelivery.ReviewPacketResponseTemplate
	selectedEntry := -1
	for index, entry := range manifest.Entries {
		candidatePath := filepath.Join(output, entry.ResponseFile)
		candidateRaw, readErr := os.ReadFile(candidatePath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var candidateResponse issuedelivery.ReviewPacketResponseTemplate
		if err = json.Unmarshal(candidateRaw, &candidateResponse); err != nil {
			t.Fatal(err)
		}
		if candidateResponse.Candidate != nil &&
			candidateResponse.Candidate.Axis == deliveryevidence.ReviewStandards {
			responsePath, responseRaw, response = candidatePath, candidateRaw, candidateResponse
			selectedEntry = index
			break
		}
	}
	if responsePath == "" || response.Candidate == nil || selectedEntry < 0 {
		t.Fatalf("candidate response template = %#v", response)
	}
	packetPath := filepath.Join(output, manifest.Entries[selectedEntry].PacketFile)
	packetRaw, err := os.ReadFile(packetPath)
	if err != nil {
		t.Fatal(err)
	}
	var packet issuedelivery.ReviewPacket
	if err = json.Unmarshal(packetRaw, &packet); err != nil {
		t.Fatal(err)
	}
	packet.PriorFindings = append(packet.PriorFindings, deliveryevidence.ReviewFinding{
		ID: "fabricated-packet-context", Axis: packet.Axis,
	})
	packetDigestRaw, err := json.Marshal(reviewPacketDigestProjection(packet))
	if err != nil {
		t.Fatal(err)
	}
	packet.SHA256 = fmt.Sprintf("%x", sha256.Sum256(packetDigestRaw))
	packet.Response.PacketSHA256 = packet.SHA256
	packet.Response.Candidate.PacketSHA256 = packet.SHA256
	tamperedPacketRaw, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(packetPath, append(tamperedPacketRaw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	response.PacketSHA256 = packet.SHA256
	response.Candidate.PacketSHA256 = packet.SHA256
	response.Candidate.Completed = true
	tamperedResponseRaw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(responsePath, tamperedResponseRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest.Entries[selectedEntry].SHA256 = packet.SHA256
	domainEntries := make([]issuedelivery.ReviewPacketManifestEntry, 0, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		domainEntries = append(domainEntries, issuedelivery.ReviewPacketManifestEntry{
			PacketID: entry.PacketID, SHA256: entry.SHA256, Kind: entry.Kind,
		})
	}
	domainEntriesRaw, err := json.Marshal(domainEntries)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestSHA256 = fmt.Sprintf("%x", sha256.Sum256(domainEntriesRaw))
	tamperedManifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(output, "manifest.json"), tamperedManifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = advanceCommand.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361",
		"--risk-profile", "low-risk", "--full-report", "--review-content", output,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "exact current packet SHA-256") {
		t.Fatalf("self-rehashed modified packet context was accepted: %v", err)
	}
	if err = os.WriteFile(packetPath, packetRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(responsePath, responseRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(output, "manifest.json"), manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	response = issuedelivery.ReviewPacketResponseTemplate{}
	if err = json.Unmarshal(responseRaw, &response); err != nil {
		t.Fatal(err)
	}
	response.Candidate.Completed = true
	responseRaw, err = json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(responsePath, responseRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	partiallyAdmitted := runAdvanceCommandReport(
		t, advanceCommand, repository, "--review-content", output,
	)
	if partiallyAdmitted.Candidate == nil || len(partiallyAdmitted.Candidate.Reviews) != 1 ||
		partiallyAdmitted.NextAction != issuedelivery.ActionProvideCandidateReview {
		t.Fatalf("partially admitted packet directory = %#v", partiallyAdmitted)
	}
	replayed := runAdvanceCommandReport(
		t, advanceCommand, repository, "--review-content", output,
	)
	if replayed.Candidate == nil || len(replayed.Candidate.Reviews) != 1 {
		t.Fatalf("replayed packet directory duplicated response = %#v", replayed)
	}

	alternateBytes, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(responsePath, alternateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	err = advanceCommand.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361",
		"--risk-profile", "low-risk", "--full-report", "--review-content", output,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "conflicts with the already persisted response") {
		t.Fatalf("byte-different semantic replay accepted: %v", err)
	}

	response.Candidate.Findings = []deliveryevidence.ReviewFinding{{
		ID: "conflicting-replay", Axis: response.Candidate.Axis,
	}}
	responseRaw, err = json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(responsePath, responseRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = advanceCommand.run(context.Background(), []string{
		"advance", "--repository", repository, "--issue", "361",
		"--risk-profile", "low-risk", "--full-report", "--review-content", output,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "conflicts with the already persisted response") {
		t.Fatalf("conflicting packet replay accepted: %v", err)
	}
}
