package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

const reviewPacketDirectorySchema = "packy.review-packet-directory/v1"

type reviewPacketOptions struct {
	RepositoryPath string
	IssueNumber    int
	Kind           issuedelivery.ReviewPacketKind
	Axis           deliveryevidence.ReviewAxis
	Boundary       issuedelivery.SensitiveBoundary
	OutputPath     string
}

type issueDeliveryReviewPacketMaterializer interface {
	ReviewPackets(context.Context, issuedelivery.ReviewPacketRequest) (issuedelivery.ReviewPacketSet, error)
}

type reviewPacketFactory func(string) (issueDeliveryReviewPacketMaterializer, error)

type reviewPacketDirectoryManifest struct {
	Schema         string                       `json:"schema"`
	RunID          string                       `json:"run_id"`
	Entries        []reviewPacketDirectoryEntry `json:"entries"`
	ManifestSHA256 string                       `json:"manifest_sha256"`
}

type reviewPacketDirectoryEntry struct {
	PacketID     string                         `json:"packet_id"`
	SHA256       string                         `json:"sha256"`
	Kind         issuedelivery.ReviewPacketKind `json:"kind"`
	PacketFile   string                         `json:"packet_file"`
	ResponseFile string                         `json:"response_file"`
}

func (c command) reviewPackets(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("packy-deliver review-packets", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var options reviewPacketOptions
	var kind, axis, boundary string
	f.StringVar(&options.RepositoryPath, "repository", "", "absolute repository containing the delivery run")
	f.IntVar(&options.IssueNumber, "issue", 0, "Packy issue number")
	f.StringVar(&kind, "kind", "", "review packet kind")
	f.StringVar(&axis, "axis", "", "candidate review axis")
	f.StringVar(&boundary, "boundary", "", "specialist review boundary")
	f.StringVar(&options.OutputPath, "output", "", "new packet directory to create")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || options.IssueNumber <= 0 ||
		strings.TrimSpace(options.RepositoryPath) == "" ||
		strings.TrimSpace(kind) == "" ||
		strings.TrimSpace(options.OutputPath) == "" {
		return errors.New("issue, kind, output, and repository are required and positional arguments are forbidden")
	}
	if !filepath.IsAbs(options.RepositoryPath) {
		return errors.New("repository must be an absolute path")
	}
	resolved, err := filepath.EvalSymlinks(options.RepositoryPath)
	if err != nil {
		return fmt.Errorf("resolve repository: %w", err)
	}
	options.RepositoryPath = filepath.Clean(resolved)
	options.Kind = issuedelivery.ReviewPacketKind(kind)
	options.Axis = deliveryevidence.ReviewAxis(axis)
	options.Boundary = issuedelivery.SensitiveBoundary(boundary)
	if c.ReviewPacketFactory == nil {
		return errors.New("review-packets adapter is unavailable")
	}
	materializer, err := c.ReviewPacketFactory(options.RepositoryPath)
	if err != nil {
		return fmt.Errorf("configure review-packets: %w", err)
	}
	set, err := materializer.ReviewPackets(ctx, issuedelivery.ReviewPacketRequest{
		RepositoryPath: options.RepositoryPath,
		IssueNumber:    options.IssueNumber,
		Kind:           options.Kind,
		Axis:           options.Axis,
		Boundary:       options.Boundary,
	})
	if err != nil {
		return err
	}
	return writeReviewPacketDirectory(options.OutputPath, set)
}

func writeReviewPacketDirectory(path string, set issuedelivery.ReviewPacketSet) (returnErr error) {
	path = filepath.Clean(path)
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("output %q is not a regular directory path", path)
		}
		return fmt.Errorf("output %q already exists", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect output %q: %w", path, err)
	}
	if len(set.Packets) == 0 || len(set.Packets) != len(set.Manifest.Entries) {
		return errors.New("review packet set has an invalid manifest")
	}

	parent := filepath.Dir(path)
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create packet staging directory: %w", err)
	}
	if err = os.Chmod(staging, 0o700); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("set packet staging permissions: %w", err)
	}
	defer func() {
		removeErr := os.RemoveAll(staging)
		if returnErr == nil && removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			returnErr = fmt.Errorf("remove packet staging directory: %w", removeErr)
		}
	}()

	manifest := reviewPacketDirectoryManifest{
		Schema: reviewPacketDirectorySchema, RunID: set.RunID,
		ManifestSHA256: set.Manifest.SHA256,
	}
	for index, packet := range set.Packets {
		entry := set.Manifest.Entries[index]
		if packet.PacketID != entry.PacketID || packet.SHA256 != entry.SHA256 ||
			packet.Kind != entry.Kind || !validReviewPacketID(packet.PacketID) {
			return errors.New("review packet set has an inconsistent manifest")
		}
		packetName := packet.PacketID + ".packet.json"
		responseName := packet.PacketID + ".response.json"
		if err := writeStagedReviewPacketFile(staging, packetName, packet); err != nil {
			return err
		}
		if err := writeStagedReviewPacketFile(staging, responseName, packet.Response); err != nil {
			return err
		}
		manifest.Entries = append(manifest.Entries, reviewPacketDirectoryEntry{
			PacketID: packet.PacketID, SHA256: packet.SHA256, Kind: packet.Kind,
			PacketFile: packetName, ResponseFile: responseName,
		})
	}
	if err := writeStagedReviewPacketFile(staging, "manifest.json", manifest); err != nil {
		return err
	}
	if err := syncDirectory(staging); err != nil {
		return fmt.Errorf("sync packet staging directory: %w", err)
	}
	if err := atomicPublishReviewPacketDirectory(staging, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("output %q already exists", path)
		}
		return fmt.Errorf("publish review packet directory: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("sync review packet parent directory: %w", err)
	}
	return nil
}

func writeStagedReviewPacketFile(directory, name string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode review packet file %q: %w", name, err)
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create review packet file %q: %w", name, err)
	}
	open := true
	defer func() {
		if open {
			_ = file.Close()
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		return fmt.Errorf("set review packet file %q permissions: %w", name, err)
	}
	if _, err = file.Write(raw); err != nil {
		return fmt.Errorf("write review packet file %q: %w", name, err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync review packet file %q: %w", name, err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close review packet file %q: %w", name, err)
	}
	open = false
	return nil
}

func loadAdvanceReviewContents(path string) ([]advanceReviewContent, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("--review-content expected a JSON file path or packet directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("--review-content refuses symbolic links")
	}
	if info.IsDir() {
		return loadReviewPacketDirectory(path)
	}
	if info.Mode().Type() != 0 {
		return nil, errors.New("--review-content requires a regular file or directory")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--review-content expected a JSON file path: %w", err)
	}
	content, err := decodeReviewResponse(raw)
	if err != nil {
		return nil, err
	}
	return []advanceReviewContent{content}, nil
}

func loadReviewPacketDirectory(path string) ([]advanceReviewContent, error) {
	manifestPath := filepath.Join(path, "manifest.json")
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("inspect review packet manifest: %w", err)
	}
	if manifestInfo.Mode().Type() != 0 {
		return nil, errors.New("review packet manifest is not a regular file")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read review packet manifest: %w", err)
	}
	var manifest reviewPacketDirectoryManifest
	if err := decodeSemanticJSON(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode review packet manifest: %w", err)
	}
	if manifest.Schema != reviewPacketDirectorySchema || manifest.RunID == "" ||
		manifest.ManifestSHA256 == "" || len(manifest.Entries) == 0 {
		return nil, errors.New("review packet manifest is incomplete or has an unsupported schema")
	}
	if !sort.SliceIsSorted(manifest.Entries, func(i, j int) bool {
		return manifest.Entries[i].PacketID < manifest.Entries[j].PacketID
	}) {
		return nil, errors.New("review packet manifest entries are not in deterministic packet order")
	}
	seen := map[string]bool{}
	contents := make([]advanceReviewContent, 0, len(manifest.Entries))
	domainEntries := make([]issuedelivery.ReviewPacketManifestEntry, 0, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		if !validReviewPacketID(entry.PacketID) || seen[entry.PacketID] ||
			entry.ResponseFile != entry.PacketID+".response.json" ||
			entry.PacketFile != entry.PacketID+".packet.json" {
			return nil, errors.New("review packet manifest contains an invalid or duplicate entry")
		}
		seen[entry.PacketID] = true
		packetPath := filepath.Join(path, entry.PacketFile)
		packetInfo, err := os.Lstat(packetPath)
		if err != nil {
			return nil, fmt.Errorf("inspect review packet %q: %w", entry.PacketFile, err)
		}
		if packetInfo.Mode().Type() != 0 {
			return nil, fmt.Errorf("review packet %q is not a regular file", entry.PacketFile)
		}
		packetRaw, err := os.ReadFile(packetPath)
		if err != nil {
			return nil, fmt.Errorf("read review packet %q: %w", entry.PacketFile, err)
		}
		var packet issuedelivery.ReviewPacket
		if err := decodeSemanticJSON(packetRaw, &packet); err != nil {
			return nil, fmt.Errorf("decode review packet %q: %w", entry.PacketFile, err)
		}
		if packet.PacketID != entry.PacketID || packet.SHA256 != entry.SHA256 ||
			packet.Kind != entry.Kind {
			return nil, fmt.Errorf("review packet %q does not match its manifest entry", entry.PacketFile)
		}
		digestProjection := reviewPacketDigestProjection(packet)
		digestRaw, err := json.Marshal(digestProjection)
		if err != nil {
			return nil, fmt.Errorf("encode review packet digest projection: %w", err)
		}
		digest := sha256.Sum256(digestRaw)
		if hex.EncodeToString(digest[:]) != packet.SHA256 {
			return nil, fmt.Errorf("review packet %q digest is invalid", entry.PacketFile)
		}
		domainEntries = append(domainEntries, issuedelivery.ReviewPacketManifestEntry{
			PacketID: entry.PacketID, SHA256: entry.SHA256, Kind: entry.Kind,
		})
		responsePath := filepath.Join(path, entry.ResponseFile)
		info, err := os.Lstat(responsePath)
		if err != nil {
			return nil, fmt.Errorf("inspect review response %q: %w", entry.ResponseFile, err)
		}
		if info.Mode().Type() != 0 {
			return nil, fmt.Errorf("review response %q is not a regular file", entry.ResponseFile)
		}
		responseRaw, err := os.ReadFile(responsePath)
		if err != nil {
			return nil, fmt.Errorf("read review response %q: %w", entry.ResponseFile, err)
		}
		content, err := decodePacketResponse(responseRaw, entry.PacketID, entry.SHA256)
		if err != nil {
			return nil, fmt.Errorf("decode review response %q: %w", entry.ResponseFile, err)
		}
		contents = append(contents, content)
	}
	manifestRaw, err := json.Marshal(domainEntries)
	if err != nil {
		return nil, fmt.Errorf("encode review packet manifest digest projection: %w", err)
	}
	manifestDigest := sha256.Sum256(manifestRaw)
	if hex.EncodeToString(manifestDigest[:]) != manifest.ManifestSHA256 {
		return nil, errors.New("review packet manifest digest is invalid")
	}
	return contents, nil
}

func decodeReviewResponse(raw []byte) (advanceReviewContent, error) {
	var shape struct {
		PacketID     string `json:"packet_id"`
		PacketSHA256 string `json:"packet_sha256"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return advanceReviewContent{}, err
	}
	if shape.PacketID != "" {
		return decodePacketResponse(raw, shape.PacketID, shape.PacketSHA256)
	}
	var content advanceReviewContent
	if err := decodeSemanticJSON(raw, &content); err != nil {
		return advanceReviewContent{}, err
	}
	if err := bindReviewResponseSHA256(raw, &content); err != nil {
		return advanceReviewContent{}, err
	}
	return content, nil
}

func decodePacketResponse(raw []byte, expectedPacketID, expectedPacketSHA256 string) (advanceReviewContent, error) {
	var response issuedelivery.ReviewPacketResponseTemplate
	if err := decodeSemanticJSON(raw, &response); err != nil {
		return advanceReviewContent{}, err
	}
	if response.PacketID != expectedPacketID || !validReviewPacketID(response.PacketID) {
		return advanceReviewContent{}, errors.New("review response packet identity is absent or mismatched")
	}
	if response.PacketSHA256 != expectedPacketSHA256 || !validReviewPacketID(response.PacketSHA256) {
		return advanceReviewContent{}, errors.New("review response packet digest is absent or mismatched")
	}
	populated := 0
	content := advanceReviewContent{}
	if response.Qualification != nil {
		populated++
		if response.Qualification.PacketID != response.PacketID ||
			response.Qualification.PacketSHA256 != response.PacketSHA256 {
			return advanceReviewContent{}, errors.New("qualification response packet identity is mismatched")
		}
		content.QualificationReview = response.Qualification
	}
	if response.Candidate != nil {
		populated++
		if response.Candidate.PacketID != response.PacketID ||
			response.Candidate.PacketSHA256 != response.PacketSHA256 {
			return advanceReviewContent{}, errors.New("candidate response packet identity is mismatched")
		}
		content.Reviews = []issuedelivery.CandidateReview{*response.Candidate}
	}
	if response.Specialist != nil {
		populated++
		if response.Specialist.PacketID != response.PacketID ||
			response.Specialist.PacketSHA256 != response.PacketSHA256 {
			return advanceReviewContent{}, errors.New("specialist response packet identity is mismatched")
		}
		content.Specialists = []issuedelivery.SpecialistReview{*response.Specialist}
	}
	if populated != 1 {
		return advanceReviewContent{}, errors.New("review response must populate exactly one typed response")
	}
	if err := bindReviewResponseSHA256(raw, &content); err != nil {
		return advanceReviewContent{}, err
	}
	return content, nil
}

func reviewPacketDigestProjection(packet issuedelivery.ReviewPacket) issuedelivery.ReviewPacket {
	projection := packet
	projection.SHA256 = ""
	projection.Response.PacketSHA256 = ""
	if packet.Response.Qualification != nil {
		review := *packet.Response.Qualification
		review.PacketSHA256 = ""
		projection.Response.Qualification = &review
	}
	if packet.Response.Candidate != nil {
		review := *packet.Response.Candidate
		review.PacketSHA256 = ""
		projection.Response.Candidate = &review
	}
	if packet.Response.Specialist != nil {
		review := *packet.Response.Specialist
		review.PacketSHA256 = ""
		projection.Response.Specialist = &review
	}
	return projection
}

func bindReviewResponseSHA256(raw []byte, content *advanceReviewContent) error {
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	for index := range content.Reviews {
		review := &content.Reviews[index]
		if review.ResponseSHA256 != "" {
			return errors.New("candidate response source digest is reserved for admission")
		}
		if review.PacketID != "" {
			review.ResponseSHA256 = digest
		}
	}
	for index := range content.Specialists {
		review := &content.Specialists[index]
		if review.ResponseSHA256 != "" {
			return errors.New("specialist response source digest is reserved for admission")
		}
		if review.PacketID != "" {
			review.ResponseSHA256 = digest
		}
	}
	if review := content.QualificationReview; review != nil {
		if review.ResponseSHA256 != "" {
			return errors.New("qualification response source digest is reserved for admission")
		}
		if review.PacketID != "" {
			review.ResponseSHA256 = digest
		}
	}
	return nil
}

func decodeSemanticJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("input must contain exactly one JSON value")
	}
	return nil
}

func validReviewPacketID(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func containsReviewPacketsHelpFlag(args []string) bool {
	return containsHelpFlag(args, func(arg string) bool {
		switch arg {
		case "-repository", "--repository", "-issue", "--issue", "-kind", "--kind",
			"-axis", "--axis", "-boundary", "--boundary", "-output", "--output":
			return true
		default:
			return false
		}
	})
}

func newProductionReviewPacketMaterializer(
	repository string,
) (issueDeliveryReviewPacketMaterializer, error) {
	runner := execRunner{}
	return issuedelivery.New(issuedelivery.Config{
		Git:              productionGitObserver{runner: runner},
		GitHub:           productionTrackerObserver{runner: runner},
		NonLocalObserver: productionNonLocalGateway{runner: runner, repository: repository},
	})
}
