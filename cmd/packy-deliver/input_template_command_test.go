package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type fakeInputTemplateMaterializer struct {
	requests []issuedelivery.InputTemplateRequest
	template issuedelivery.InputTemplate
	err      error
}

func (f *fakeInputTemplateMaterializer) MaterializeInputTemplate(
	_ context.Context,
	request issuedelivery.InputTemplateRequest,
) (issuedelivery.InputTemplate, error) {
	f.requests = append(f.requests, request)
	return f.template, f.err
}

func TestInputTemplateCommandMaterializesDeterministicContractForEveryKind(t *testing.T) {
	authority := strings.Repeat("a", 64)
	matrix := []deliveryevidence.AcceptanceRow{{
		Identity: "criterion-1", Criterion: "criterion",
		Obligations: deliveryevidence.PhaseOwnedAcceptanceObligations(),
	}}
	tests := []struct {
		kind     issuedelivery.InputTemplateKind
		template issuedelivery.InputTemplate
		decode   func(*testing.T, string)
	}{
		{
			kind: issuedelivery.InputTemplateDecision,
			template: issuedelivery.InputTemplate{Decision: &issuedelivery.Decision{
				RequestID: "decision-1", Disposition: "REQUIRED", Requirement: "REQUIRED",
				EvidenceLink: "REQUIRED",
			}},
			decode: func(t *testing.T, path string) {
				var value *issuedelivery.Decision
				if err := decodeOptionalExactJSON("--decision", path, &value); err != nil {
					t.Fatal(err)
				}
				if value == nil || value.RequestID != "decision-1" {
					t.Fatalf("decision = %#v", value)
				}
			},
		},
		{
			kind: issuedelivery.InputTemplateQualificationReview,
			template: issuedelivery.InputTemplate{QualificationReview: &issuedelivery.QualificationReview{
				AuthoritySHA256: authority, AcceptanceMatrixSHA256: strings.Repeat("b", 64),
				Findings: []deliveryevidence.ReviewFinding{}, Completed: false,
			}},
			decode: func(t *testing.T, path string) {
				var value advanceReviewContent
				if err := decodeSemanticJSONFile("--review-content", path, &value); err != nil {
					t.Fatal(err)
				}
				if value.QualificationReview == nil ||
					value.QualificationReview.AuthoritySHA256 != authority ||
					value.Reviews == nil || value.Specialists == nil || value.Acceptance == nil {
					t.Fatalf("qualification review content = %#v", value)
				}
			},
		},
		{
			kind: issuedelivery.InputTemplateQualificationCorrection,
			template: issuedelivery.InputTemplate{
				QualificationCorrection: &issuedelivery.QualificationCorrection{
					RequestID: "correction-1", AuthoritySHA256: authority,
					ReviewedMatrixSHA256: strings.Repeat("b", 64),
					FindingIDs:           []string{"finding-1"},
					AcceptanceMatrix:     matrix,
					Evidence:             "REQUIRED",
				},
			},
			decode: func(t *testing.T, path string) {
				var value advanceReviewContent
				if err := decodeSemanticJSONFile("--review-content", path, &value); err != nil {
					t.Fatal(err)
				}
				if value.QualificationCorrection == nil ||
					value.QualificationCorrection.RequestID != "correction-1" ||
					value.Reviews == nil || value.Specialists == nil || value.Acceptance == nil {
					t.Fatalf("qualification correction content = %#v", value)
				}
			},
		},
		{
			kind: issuedelivery.InputTemplateRepair,
			template: issuedelivery.InputTemplate{Repair: &issuedelivery.RepairDecision{
				CandidateID: "candidate-1", Class: "REQUIRED",
				Findings: []issuedelivery.FindingDecision{{
					FindingID: "finding-1", Disposition: "REQUIRED", Evidence: "REQUIRED",
				}},
			}},
			decode: func(t *testing.T, path string) {
				var value *issuedelivery.RepairDecision
				if err := decodeOptionalExactJSON("--repair", path, &value); err != nil {
					t.Fatal(err)
				}
				if value == nil || value.CandidateID != "candidate-1" {
					t.Fatalf("repair = %#v", value)
				}
			},
		},
		{
			kind: issuedelivery.InputTemplateCIAttribution,
			template: issuedelivery.InputTemplate{
				CIAttributions: []issuedelivery.CIFailureAttributionInput{{
					CheckIdentity: "build", RunID: 41, HeadSHA: strings.Repeat("c", 40),
					DetailsURL: "https://example.test/runs/41", Attribution: "REQUIRED",
				}},
			},
			decode: func(t *testing.T, path string) {
				var value []advanceCIFailureAttribution
				if err := decodeSemanticJSONFile("--ci-attribution", path, &value); err != nil {
					t.Fatal(err)
				}
				if len(value) != 1 || value[0].CheckIdentity != "build" ||
					value[0].RunID != 41 || value[0].DetailsURL != "https://example.test/runs/41" {
					t.Fatalf("CI attributions = %#v", value)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(string(test.kind), func(t *testing.T) {
			repository := t.TempDir()
			resolvedRepository, err := filepath.EvalSymlinks(repository)
			if err != nil {
				t.Fatal(err)
			}
			first, second := filepath.Join(t.TempDir(), "first.json"), filepath.Join(t.TempDir(), "second.json")
			fake := &fakeInputTemplateMaterializer{template: test.template}
			var configuredRepositories []string
			cmd := command{InputTemplateFactory: func(repository string) (issueDeliveryInputTemplateMaterializer, error) {
				configuredRepositories = append(configuredRepositories, repository)
				return fake, nil
			}}
			for _, output := range []string{first, second} {
				if err := cmd.run(context.Background(), []string{
					"input-template", "--repository", repository, "--issue", "27",
					"--kind", string(test.kind), "--output", output,
				}, &bytes.Buffer{}); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(output)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Fatalf("output mode = %o, want 600", info.Mode().Perm())
				}
				test.decode(t, output)
			}
			firstRaw, err := os.ReadFile(first)
			if err != nil {
				t.Fatal(err)
			}
			secondRaw, err := os.ReadFile(second)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(firstRaw, secondRaw) {
				t.Fatalf("nondeterministic templates:\n%s\n%s", firstRaw, secondRaw)
			}
			if len(fake.requests) != 2 ||
				fake.requests[0].Kind != test.kind ||
				fake.requests[0].IssueNumber != 27 {
				t.Fatalf("materializer requests = %#v", fake.requests)
			}
			if !reflect.DeepEqual(configuredRepositories, []string{resolvedRepository, resolvedRepository}) {
				t.Fatalf("configured repositories = %v, want %q twice", configuredRepositories, resolvedRepository)
			}
		})
	}
}

func TestInputTemplateCommandSafeCreationAndForceReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "draft.json")
	missing := filepath.Join(root, "missing.json")
	if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	content := issuedelivery.InputTemplate{Decision: &issuedelivery.Decision{RequestID: "decision-1"}}
	fake := &fakeInputTemplateMaterializer{template: content}
	cmd := command{InputTemplateFactory: func(string) (issueDeliveryInputTemplateMaterializer, error) {
		return fake, nil
	}}
	args := []string{
		"input-template", "--repository", root, "--issue", "27",
		"--kind", "decision", "--output", path,
	}
	if err := cmd.run(context.Background(), []string{
		"input-template", "--repository", root, "--issue", "27",
		"--kind", "decision", "--output", missing, "--force",
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("force-missing error = %v", err)
	}
	if err := cmd.run(context.Background(), args, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("exclusive-create error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "original" {
		t.Fatalf("exclusive create changed existing output to %q", raw)
	}
	if err := cmd.run(
		context.Background(), append(args, "--force"), &bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("forced output mode = %o, want 600", info.Mode().Perm())
	}
	var decision issuedelivery.Decision
	replaced, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(replaced, &decision); err != nil || decision.RequestID != "decision-1" {
		t.Fatalf("forced output = %s, decode error = %v", replaced, err)
	}
}

func TestInputTemplateCommandRefusesSymlinksNonRegularTargetsAndMissingParents(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("protected"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "draft-link")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "draft-directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	missingParent := filepath.Join(root, "absent", "draft.json")
	fake := &fakeInputTemplateMaterializer{template: issuedelivery.InputTemplate{
		Decision: &issuedelivery.Decision{RequestID: "decision-1"},
	}}
	cmd := command{InputTemplateFactory: func(string) (issueDeliveryInputTemplateMaterializer, error) {
		return fake, nil
	}}
	for _, output := range []string{symlink, directory, missingParent} {
		err := cmd.run(context.Background(), []string{
			"input-template", "--repository", root, "--issue", "27",
			"--kind", "decision", "--output", output, "--force",
		}, &bytes.Buffer{})
		if err == nil {
			t.Fatalf("unsafe output accepted: %s", output)
		}
	}
	protected, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(protected) != "protected" {
		t.Fatalf("symlink target changed to %q", protected)
	}
	if _, err := os.Stat(filepath.Dir(missingParent)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing parent was created: %v", err)
	}
}

func TestInputTemplateCommandRejectsInvalidInputAndMalformedProjectionBeforeWriting(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "draft.json")
	fake := &fakeInputTemplateMaterializer{template: issuedelivery.InputTemplate{}}
	cmd := command{InputTemplateFactory: func(string) (issueDeliveryInputTemplateMaterializer, error) {
		return fake, nil
	}}
	for _, args := range [][]string{
		{"input-template", "--issue", "27", "--kind", "decision", "--output", output},
		{"input-template", "--repository", "relative", "--issue", "27", "--kind", "decision", "--output", output},
		{"input-template", "--repository", root, "--kind", "decision", "--output", output},
		{"input-template", "--repository", root, "--issue", "27", "--output", output},
		{"input-template", "--repository", root, "--issue", "27", "--kind", "decision"},
		{"input-template", "--repository", root, "--issue", "27", "--kind", "unknown", "--output", output},
		{"input-template", "--repository", root, "--issue", "27", "--kind", "decision", "--output", output, "extra"},
		{"input-template", "--repository", root, "--issue", "27", "--kind", "decision", "--output", output},
	} {
		if err := cmd.run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid input accepted: %v", args)
		}
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid input created output: %v", err)
	}
}

func TestInputTemplateHelpIsSpecificAndValueAware(t *testing.T) {
	for _, args := range [][]string{
		{"help", "input-template"},
		{"input-template", "--help"},
		{"input-template", "--output", "draft.json", "--help"},
	} {
		var output bytes.Buffer
		if err := (command{}).run(context.Background(), args, &output); err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{"visible invalid placeholders", "not accepted input", "--force"} {
			if !strings.Contains(output.String(), text) {
				t.Fatalf("help for %v missing %q:\n%s", args, text, output.String())
			}
		}
	}
	var output bytes.Buffer
	err := (command{}).run(context.Background(), []string{
		"input-template", "--output", "--help", "--issue", "27",
		"--repository", t.TempDir(), "--kind", "decision",
	}, &output)
	if err == nil || output.Len() != 0 {
		t.Fatalf("--help used as output value was treated as help: err=%v output=%q", err, output.String())
	}
}

func TestInputTemplateProjectionShapeUsesNoUnrelatedFields(t *testing.T) {
	template := issuedelivery.InputTemplate{
		QualificationReview: &issuedelivery.QualificationReview{
			AuthoritySHA256:        strings.Repeat("a", 64),
			AcceptanceMatrixSHA256: strings.Repeat("b", 64),
			Findings:               []deliveryevidence.ReviewFinding{},
		},
	}
	raw, err := inputTemplateJSON(issuedelivery.InputTemplateQualificationReview, template)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	want := []string{"acceptance_proofs", "qualification_review", "reviews", "specialist_reviews"}
	got := make([]string, 0, len(object))
	for key := range object {
		got = append(got, key)
	}
	if len(got) != len(want) {
		t.Fatalf("review wrapper keys = %v, want %v", got, want)
	}
	for _, key := range want {
		if _, ok := object[key]; !ok {
			t.Fatalf("review wrapper missing %q: %s", key, raw)
		}
	}
	if reflect.DeepEqual(object["qualification_review"], json.RawMessage("null")) {
		t.Fatalf("qualification review is null: %s", raw)
	}
}

func TestFilledInputTemplateFileRoundTripsThroughMatchingAdvanceOption(t *testing.T) {
	repository := t.TempDir()
	tests := []struct {
		name        string
		kind        issuedelivery.InputTemplateKind
		draft       issuedelivery.InputTemplate
		filled      any
		advanceFlag string
		check       func(*testing.T, advanceOptions)
	}{
		{
			name: "decision", kind: issuedelivery.InputTemplateDecision,
			draft: issuedelivery.InputTemplate{Decision: &issuedelivery.Decision{RequestID: "decision-1"}},
			filled: issuedelivery.Decision{
				RequestID: "decision-1", Disposition: issuedelivery.DecisionOwnedNow,
				Requirement: "Implement the exact criterion.", EvidenceLink: "issue#27",
			},
			advanceFlag: "--decision",
			check: func(t *testing.T, options advanceOptions) {
				if options.Decision == nil || options.Decision.RequestID != "decision-1" {
					t.Fatalf("Advance decision = %#v", options.Decision)
				}
			},
		},
		{
			name: "qualification review", kind: issuedelivery.InputTemplateQualificationReview,
			draft: issuedelivery.InputTemplate{QualificationReview: &issuedelivery.QualificationReview{}},
			filled: advanceReviewContent{
				Reviews:     []issuedelivery.CandidateReview{},
				Specialists: []issuedelivery.SpecialistReview{},
				Acceptance:  []issuedelivery.AcceptanceProof{},
				QualificationReview: &issuedelivery.QualificationReview{
					AuthoritySHA256:        strings.Repeat("a", 64),
					AcceptanceMatrixSHA256: strings.Repeat("b", 64),
					Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
				},
			},
			advanceFlag: "--review-content",
			check: func(t *testing.T, options advanceOptions) {
				if options.QualificationReview == nil || !options.QualificationReview.Completed {
					t.Fatalf("Advance qualification review = %#v", options.QualificationReview)
				}
			},
		},
		{
			name: "qualification correction", kind: issuedelivery.InputTemplateQualificationCorrection,
			draft: issuedelivery.InputTemplate{
				QualificationCorrection: &issuedelivery.QualificationCorrection{},
			},
			filled: advanceReviewContent{
				Reviews:     []issuedelivery.CandidateReview{},
				Specialists: []issuedelivery.SpecialistReview{},
				Acceptance:  []issuedelivery.AcceptanceProof{},
				QualificationCorrection: &issuedelivery.QualificationCorrection{
					RequestID: "correction-1", AuthoritySHA256: strings.Repeat("a", 64),
					ReviewedMatrixSHA256: strings.Repeat("b", 64),
					FindingIDs:           []string{"finding-1"},
					AcceptanceMatrix:     []deliveryevidence.AcceptanceRow{},
					Evidence:             "Reviewed and corrected every compiler finding.",
				},
			},
			advanceFlag: "--review-content",
			check: func(t *testing.T, options advanceOptions) {
				if options.QualificationCorrection == nil ||
					options.QualificationCorrection.RequestID != "correction-1" {
					t.Fatalf("Advance qualification correction = %#v", options.QualificationCorrection)
				}
			},
		},
		{
			name: "repair", kind: issuedelivery.InputTemplateRepair,
			draft: issuedelivery.InputTemplate{Repair: &issuedelivery.RepairDecision{CandidateID: "candidate-1"}},
			filled: issuedelivery.RepairDecision{
				CandidateID: "candidate-1", Class: issuedelivery.RepairAdjudicationOnly,
				Findings: []issuedelivery.FindingDecision{{
					FindingID: "finding-1", Disposition: issuedelivery.FindingRejected,
					Evidence: "The cited line proves the finding does not apply.",
				}},
			},
			advanceFlag: "--repair",
			check: func(t *testing.T, options advanceOptions) {
				if options.Repair == nil || options.Repair.CandidateID != "candidate-1" {
					t.Fatalf("Advance repair = %#v", options.Repair)
				}
			},
		},
		{
			name: "CI attribution", kind: issuedelivery.InputTemplateCIAttribution,
			draft: issuedelivery.InputTemplate{CIAttributions: []issuedelivery.CIFailureAttributionInput{{
				CheckIdentity: "build", RunID: 41, HeadSHA: strings.Repeat("c", 40),
				DetailsURL: "https://example.test/runs/41",
			}}},
			filled: []advanceCIFailureAttribution{{
				CheckIdentity: "build", RunID: 41, HeadSHA: strings.Repeat("c", 40),
				DetailsURL:  "https://example.test/runs/41",
				Attribution: issuedelivery.FailureCandidate,
			}},
			advanceFlag: "--ci-attribution",
			check: func(t *testing.T, options advanceOptions) {
				if len(options.CIFailureAttributions) != 1 ||
					options.CIFailureAttributions[0].Attribution != issuedelivery.FailureCandidate {
					t.Fatalf("Advance CI attributions = %#v", options.CIFailureAttributions)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			materializer := &fakeInputTemplateMaterializer{template: test.draft}
			generator := command{
				InputTemplateFactory: func(string) (issueDeliveryInputTemplateMaterializer, error) {
					return materializer, nil
				},
			}
			if err := generator.run(context.Background(), []string{
				"input-template", "--repository", repository, "--issue", "27",
				"--kind", string(test.kind), "--output", path,
			}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			filled, err := json.MarshalIndent(test.filled, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(filled, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			var configured advanceOptions
			advancer := &fakeIssueDeliveryAdvancer{outcomes: []issuedelivery.Outcome{{
				State: issuedelivery.StateCompleted, PauseCause: issuedelivery.PauseCompleted,
				NextAction: issuedelivery.ActionNone,
			}}}
			advance := command{AdvanceFactory: func(options advanceOptions) (issueDeliveryAdvancer, error) {
				configured = options
				return advancer, nil
			}}
			if err := advance.run(context.Background(), []string{
				"advance", "--repository", repository, "--issue", "27", test.advanceFlag, path,
			}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			test.check(t, configured)
		})
	}
}
