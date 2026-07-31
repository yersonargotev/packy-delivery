package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type productionPathReviewExecutor struct{}

type runtimeRunnerFunc func(context.Context, string, ...string) ([]byte, error)

func (run runtimeRunnerFunc) Output(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	return run(ctx, name, args...)
}

func (productionPathReviewExecutor) Review(
	_ context.Context,
	request issuedelivery.ReviewRequest,
) (issuedelivery.CandidateReview, error) {
	review := issuedelivery.CandidateReview{
		CandidateID: request.CandidateID, Axis: request.Axis,
		Iteration: request.Iteration, CommitSHA: request.CommitSHA, TreeSHA: request.TreeSHA,
		Findings: []deliveryevidence.ReviewFinding{}, Completed: true,
	}
	if request.Axis == deliveryevidence.ReviewSpec {
		review.Acceptance = productionPathAcceptance(request)
	}
	return review, nil
}

func productionPathAcceptance(request issuedelivery.ReviewRequest) []issuedelivery.AcceptanceProof {
	proofs := make([]issuedelivery.AcceptanceProof, 0, len(request.AcceptanceRows))
	for _, row := range request.AcceptanceRows {
		proofs = append(proofs, issuedelivery.AcceptanceProof{
			CandidateID: request.CandidateID, Phase: deliveryevidence.AssuranceCandidateReview,
			Identity: row.Identity, PositiveEvidence: row.PositiveEvidence,
			NegativeEvidence: row.NegativeEvidence, FailureEvidence: row.FailureEvidence,
			MutationEvidence: row.MutationEvidence, CompatibilityEvidence: row.CompatibilityEvidence,
			PreservationEvidence: row.PreservationEvidence, MigrationEvidence: row.MigrationEvidence,
			ReviewReceipt: &issuedelivery.ReviewReceiptReference{
				CandidateID: request.CandidateID, Axis: request.Axis, Iteration: request.Iteration,
				CommitSHA: request.CommitSHA, TreeSHA: request.TreeSHA,
			},
		})
	}
	return proofs
}

type productionPathRiskObserver struct{}

func (productionPathRiskObserver) ObserveCandidateRisk(
	_ context.Context,
	request issuedelivery.CandidateRiskRequest,
) (issuedelivery.CandidateRiskObservation, error) {
	return issuedelivery.CandidateRiskObservation{
		CandidateID: request.CandidateID, CommitSHA: request.CommitSHA, TreeSHA: request.TreeSHA,
		Effects: []issuedelivery.EffectObservation{{
			Effect: issuedelivery.EffectPassive, Evidence: "production-path test", Complete: true,
		}},
		Completed: true,
	}, nil
}

type productionPathHighRiskObserver struct{}

func (productionPathHighRiskObserver) ObserveCandidateRisk(
	_ context.Context,
	request issuedelivery.CandidateRiskRequest,
) (issuedelivery.CandidateRiskObservation, error) {
	return issuedelivery.CandidateRiskObservation{
		CandidateID: request.CandidateID, CommitSHA: request.CommitSHA, TreeSHA: request.TreeSHA,
		Effects: []issuedelivery.EffectObservation{
			{
				Effect:   issuedelivery.EffectSecurity,
				Evidence: "production-path security boundary",
				Complete: true,
			},
			{
				Effect:   issuedelivery.EffectRealConfiguration,
				Evidence: "production-path configuration boundary",
				Complete: true,
			},
		},
		Completed: true,
	}, nil
}

type productionPathSpecialistExecutor struct{}

func (productionPathSpecialistExecutor) ReviewSpecialist(
	_ context.Context,
	request issuedelivery.SpecialistReviewRequest,
) (issuedelivery.SpecialistReview, error) {
	return issuedelivery.SpecialistReview{
		CandidateID: request.CandidateID,
		Boundary:    request.Boundary,
		Specialist:  request.Specialist,
		Findings:    []issuedelivery.SpecialistFinding{},
		Completed:   true,
	}, nil
}

type productionValidationObservationRunner struct {
	commit     string
	tree       string
	repository string
	common     string
}

type mutatingValidationRunner struct {
	mutate func() error
}

func (runner mutatingValidationRunner) Run(
	_ context.Context,
	_ string,
	_ deliveryevidence.SandboxFacts,
) error {
	return runner.mutate()
}

func (runner productionValidationObservationRunner) Output(
	_ context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	if name != "git" {
		return nil, errors.New("unexpected validation observation command")
	}
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "rev-parse HEAD^{commit}"):
		return []byte(runner.commit + "\n"), nil
	case strings.Contains(joined, "rev-parse HEAD^{tree}"):
		return []byte(runner.tree + "\n"), nil
	case strings.Contains(joined, "status --porcelain"):
		return nil, nil
	case strings.Contains(joined, "worktree list --porcelain"):
		return []byte("worktree " + runner.repository + "\n"), nil
	case strings.Contains(joined, "--git-common-dir"):
		return []byte(runner.common + "\n"), nil
	default:
		return nil, errors.New("unexpected validation observation")
	}
}

func TestSandboxSnapshotDigestBindsActualDeclaredWrites(t *testing.T) {
	home, config := filepath.Join(t.TempDir(), "home"), filepath.Join(t.TempDir(), "config")
	for _, root := range []string{home, config} {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	before, err := sandboxSnapshotDigest(home, config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(home, "cache"), []byte("written"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := sandboxSnapshotDigest(home, config)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("sandbox write was absent from the content-addressed manifest")
	}
}

func TestProductionBoundaryValidationRejectsProtectedRepositoryWrite(t *testing.T) {
	for _, relative := range []string{
		".git/config", ".git/hooks/pre-commit", ".git/refs/heads/main", "ignored.cache",
	} {
		t.Run(strings.ReplaceAll(relative, "/", "_"), func(t *testing.T) {
			repository, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, directory := range []string{
				filepath.Join(repository, "scripts"), filepath.Join(repository, ".git", "objects"),
				filepath.Join(repository, ".git", "hooks"), filepath.Join(repository, ".git", "refs", "heads"),
			} {
				if err = os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err = os.WriteFile(
				filepath.Join(repository, "scripts", "validate-packy.sh"),
				[]byte("#!/bin/sh\n"), 0o700,
			); err != nil {
				t.Fatal(err)
			}
			home, config := filepath.Join(repository, "home"), filepath.Join(repository, "config")
			for _, root := range []string{home, config} {
				if err = os.MkdirAll(root, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			runner := &fakeRunner{outputs: [][]byte{
				nil, []byte("worktree /repo\n"), []byte(filepath.Join(repository, ".git") + "\n"),
				nil, []byte("worktree /repo\n"), []byte(filepath.Join(repository, ".git") + "\n"),
			}}
			executor := productionBoundaryExecutor{
				repository: repository, runner: runner,
				validation: mutatingValidationRunner{mutate: func() error {
					target := filepath.Join(repository, relative)
					if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
						return err
					}
					return os.WriteFile(target, []byte("changed"), 0o600)
				}},
				mu: &sync.Mutex{},
			}
			_, err = executor.ValidateBoundary(context.Background(), issuedelivery.BoundaryValidationRequest{
				CandidateID: "candidate", Boundary: issuedelivery.BoundarySecurity,
				CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
				HomeRoot: home, ConfigRoot: config,
			})
			if err == nil || !strings.Contains(err.Error(), "protected repository state changed") {
				t.Fatalf("protected write %q was accepted: %v", relative, err)
			}
		})
	}
}

func productionReadyModule(
	t *testing.T,
	nonLocal issuedelivery.NonLocalGateway,
	localCompletion issuedelivery.LocalCompletionGateway,
	review issuedelivery.ReviewExecutor,
	stop string,
) (*issuedelivery.Module, issuedelivery.Outcome, string, *commandMutableTrackerObserver, *commandClock) {
	t.Helper()
	repository := t.TempDir()
	var err error
	repository, err = filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repository, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repository, "scripts", "validate-packy.sh"),
		[]byte("#!/bin/sh\nexit 0\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	common, sandbox := filepath.Join(repository, ".git"), filepath.Join(repository, "sandbox")
	for _, path := range []string{
		common, sandbox, filepath.Join(sandbox, "home"), filepath.Join(sandbox, "config"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	commit, tree := strings.Repeat("b", 40), strings.Repeat("c", 40)
	git := commandGitObserver{observation: issuedelivery.GitObservation{
		CommonDir: common, Worktree: repository,
		OriginURL: "git@github.com:yersonargotev/packy.git",
		Owner:     "yersonargotev", Name: "packy", StartingBaseSHA: strings.Repeat("a", 40),
		HeadSHA: commit, TreeSHA: tree, WorkspaceClean: true,
		Branch: "chore/issue-361-production-validation",
	}}
	tracker := &commandMutableTrackerObserver{observation: issuedelivery.TrackerObservation{
		Repository: deliveryevidence.RepositoryIdentity{
			Owner: "yersonargotev", Name: "packy", NodeID: "R1",
		},
		Issue: deliveryevidence.IssueIdentity{Number: 361, NodeID: "I361"},
		Title: "Cut over", Body: "Approved authority.", State: "OPEN",
		Labels: []string{"status:approved", "type:chore"},
		Criteria: []issuedelivery.AuthorityItem{{
			Text: "Reach exact local readiness.", EvidenceLink: "issue#361:acceptance-1",
		}},
		Exclusions: []issuedelivery.AuthorityItem{}, Dependencies: []issuedelivery.DependencyObservation{},
		References: []issuedelivery.ReferenceObservation{}, Ambiguities: []issuedelivery.AuthorityItem{},
	}}
	clock := &commandClock{now: time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)}
	focusedRunner, exhaustiveRunner := &fakeValidationRunner{}, &fakeValidationRunner{}
	observationRunner := productionValidationObservationRunner{
		commit: commit, tree: tree, repository: repository, common: common,
	}
	validationAdapter := &productionValidationExecutor{
		repository: repository,
		runner:     observationRunner,
		focused:    focusedRunner, exhaustive: exhaustiveRunner, now: clock.Now,
	}
	boundary := productionBoundaryExecutor{
		repository: repository, runner: observationRunner,
		validation: exhaustiveRunner, mu: &sync.Mutex{},
	}
	if review == nil {
		review = productionPathReviewExecutor{}
	}
	var risk issuedelivery.CandidateRiskObserver = productionPathRiskObserver{}
	if stop == "high-risk-validation" {
		risk = productionPathHighRiskObserver{}
	}
	module, err := issuedelivery.New(issuedelivery.Config{
		Git: git, GitHub: tracker, Review: review,
		Validation: validationAdapter,
		Risk:       risk,
		Specialist: productionPathSpecialistExecutor{},
		Boundary:   boundary,
		ValidationSession: productionValidationSessionExecutor{
			repository: repository, runner: observationRunner,
			validation: exhaustiveRunner, boundary: boundary,
		},
		Clock: clock, SandboxRoot: sandbox,
		NonLocal: nonLocal, LocalCompletion: localCompletion,
		DeclaredProfile: deliveryevidence.RiskLow, AllowLegacyV1: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := issuedelivery.Request{RepositoryPath: repository, IssueNumber: 361}
	qualified, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	matrixDigest := func(rows []deliveryevidence.AcceptanceRow) string {
		t.Helper()
		raw, marshalErr := json.Marshal(rows)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	pending := qualified.QualificationCorrection
	if pending == nil {
		t.Fatalf("compiler did not request qualification correction: %#v", qualified)
	}
	if stop == "qualification-correction" {
		return module, qualified, repository, tracker, clock
	}
	rows := append([]deliveryevidence.AcceptanceRow(nil), qualified.Evidence.AcceptanceMatrix...)
	rows[0].OwningSeam = "production validation adapter"
	rows[0].PositiveEvidence = "planned: exact candidate validation succeeds"
	rows[0].NegativeEvidence = "planned: mismatched candidate is rejected"
	rows[0].FailureEvidence = "planned: validation failure blocks readiness"
	rows[0].MutationEvidence = "planned: readiness receipt is persisted"
	rows[0].CompatibilityEvidence = "planned: validation contract remains compatible"
	rows[0].PreservationEvidence = "planned: sandbox preserves operator configuration"
	for index := range rows {
		identity := strings.ReplaceAll(rows[index].Identity, "-", "_")
		prefix := "[criterion:" + rows[index].Identity + "] "
		rows[index].OwningSeam = prefix + "source=symbol:packydeliver." +
			identity + ".validationAdapter; assertion=" + rows[index].OwningSeam +
			" owns the production validation boundary"
		rows[index].PositiveEvidence = prefix + "source=test:TestProduction_" +
			identity + "_Positive; assertion=" + rows[index].PositiveEvidence
		rows[index].NegativeEvidence = prefix + "source=test:TestProduction_" +
			identity + "_Negative; assertion=" + rows[index].NegativeEvidence
		rows[index].FailureEvidence = prefix + "source=test:TestProduction_" +
			identity + "_Failure; assertion=" + rows[index].FailureEvidence
		rows[index].MutationEvidence = prefix + "source=test:TestProduction_" +
			identity + "_Mutation; assertion=" + rows[index].MutationEvidence
		rows[index].CompatibilityEvidence = prefix + "source=test:TestProduction_" +
			identity + "_Compatibility; assertion=" + rows[index].CompatibilityEvidence
		rows[index].PreservationEvidence = prefix + "source=test:TestProduction_" +
			identity + "_Preservation; assertion=" + rows[index].PreservationEvidence
		rows[index].MigrationEvidence = prefix + "source=authority:" +
			rows[index].Identity + "/migration; assertion=" + rows[index].MigrationEvidence
	}
	corrected, err := module.Advance(context.Background(), issuedelivery.Request{
		RepositoryPath: repository, IssueNumber: 361,
		QualificationCorrection: &issuedelivery.QualificationCorrection{
			RequestID:            pending.ID,
			AuthoritySHA256:      pending.AuthoritySHA256,
			ReviewedMatrixSHA256: pending.ReviewedMatrixSHA256,
			FindingIDs:           pending.FindingIDs,
			AcceptanceMatrix:     rows,
			Evidence: "[request:" + pending.ID + "] findings=" +
				strings.Join(pending.FindingIDs, ",") +
				"; rationale=mapped validation authority through the typed correction envelope",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stop == "before-qualification-approval" {
		return module, corrected, repository, tracker, clock
	}
	_, err = module.Advance(context.Background(), issuedelivery.Request{
		RepositoryPath: repository, IssueNumber: 361,
		QualificationReview: &issuedelivery.QualificationReview{
			AuthoritySHA256:        corrected.Observations.AuthoritySHA256,
			AcceptanceMatrixSHA256: matrixDigest(corrected.Evidence.AcceptanceMatrix),
			Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var outcome issuedelivery.Outcome
	for attempts := 0; attempts < 8; attempts++ {
		outcome, err = module.Advance(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.LocalReadiness != nil {
			break
		}
		if stop == "repair-decision" && outcome.Repair != nil {
			return module, outcome, repository, tracker, clock
		}
	}
	if outcome.LocalReadiness == nil || outcome.State != issuedelivery.StateWaiting ||
		outcome.Evidence == nil ||
		outcome.Evidence.AcceptanceMatrix[0].State != deliveryevidence.AcceptanceProved ||
		len(focusedRunner.calls) != 1 || len(exhaustiveRunner.calls) != 1 ||
		outcome.Candidate == nil ||
		outcome.Candidate.Exhaustive == nil ||
		outcome.Candidate.Exhaustive.ValidationCompletionSHA256 == "" ||
		len(outcome.ValidationSessions) != 1 ||
		outcome.ValidationSessions[0].Result == nil {
		t.Fatalf("production-shaped path did not reach local readiness: %#v", outcome)
	}
	if stop != "high-risk-validation" {
		return module, outcome, repository, tracker, clock
	}
	if len(outcome.Candidate.BoundaryProofs) != 2 ||
		len(outcome.ValidationSessions[0].Result.BoundaryEvidence) != 2 {
		t.Fatalf("production high-risk path lacks boundary evidence: %#v", outcome)
	}
	completion := outcome.Candidate.Exhaustive.ValidationCompletionSHA256
	first, second := outcome.Candidate.BoundaryProofs[0], outcome.Candidate.BoundaryProofs[1]
	if first.ValidationCompletionSHA256 != completion ||
		second.ValidationCompletionSHA256 != completion ||
		first.Result.WriteManifestSHA256 == second.Result.WriteManifestSHA256 {
		t.Fatalf(
			"production boundary proofs do not retain one completion with distinct manifests: %#v",
			outcome.Candidate.BoundaryProofs,
		)
	}
	return module, outcome, repository, tracker, clock
}

func TestProductionValidationSessionRunsOnceForTwoBoundariesAndExhaustiveAssurance(t *testing.T) {
	_, _, _, _, _ = productionReadyModule(t, nil, nil, nil, "high-risk-validation")
}

func TestProductionTrackerObserverBindsSelectedSpecification(t *testing.T) {
	repository, _ := json.Marshal(map[string]any{
		"nameWithOwner": "yersonargotev/packy", "id": "R1",
	})
	issue, _ := json.Marshal(map[string]any{
		"number": 361, "id": "I361", "title": "Cut over", "body": "## Acceptance criteria\n- [ ] Use Advance.",
		"state": "OPEN", "url": "https://github.com/yersonargotev/packy/issues/361",
		"labels":    []map[string]string{{"name": "status:approved"}},
		"blockedBy": map[string]any{"nodes": []any{}, "totalCount": 0},
	})
	specification, _ := json.Marshal(map[string]any{
		"number": 354, "id": "I354", "title": "Delivery specification", "body": "Accepted orchestration.",
		"state": "OPEN", "url": "https://github.com/yersonargotev/packy/issues/354",
		"labels": []map[string]string{{"name": "type:spec"}, {"name": "status:approved"}},
	})
	runner := &fakeRunner{outputs: [][]byte{repository, issue, specification}}
	observer := productionTrackerObserver{runner: runner, specificationNumber: 354}

	observation, err := observer.ObserveIssue(context.Background(), issuedelivery.GitObservation{
		Owner: "yersonargotev", Name: "packy",
	}, 361)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Specification == nil ||
		observation.Specification.Identity != (deliveryevidence.SpecIdentity{Number: 354, NodeID: "I354"}) ||
		observation.Specification.URL != "https://github.com/yersonargotev/packy/issues/354" {
		t.Fatalf("specification observation = %#v", observation.Specification)
	}
	if len(runner.calls) != 3 || !strings.Contains(runner.calls[2], "issue view 354") {
		t.Fatalf("tracker calls = %v", runner.calls)
	}
}

func TestProductionTrackerObserverClassifiesReadFailures(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		class     issuedelivery.StatusErrorClass
		transient bool
	}{
		{
			name: "transport", err: errors.New("temporary connection reset"),
			class: issuedelivery.StatusErrorGitHubRead, transient: true,
		},
		{
			name: "transient command rejection", err: &commandRejectedError{
				err: errors.New("GitHub service unavailable"), transient: true,
			},
			class: issuedelivery.StatusErrorGitHubRead, transient: true,
		},
		{
			name: "authority", err: &commandRejectedError{
				err: errors.New("GitHub rejected the command"),
			},
			class: issuedelivery.StatusErrorAuthority,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := productionTrackerObserver{runner: runtimeRunnerFunc(
				func(context.Context, string, ...string) ([]byte, error) {
					return nil, test.err
				},
			)}
			_, err := observer.ObserveIssue(
				context.Background(),
				issuedelivery.GitObservation{Owner: "yersonargotev", Name: "packy"},
				361,
			)
			class, transient, ok := issuedelivery.StatusErrorDetails(err)
			if !ok || class != test.class || transient != test.transient {
				t.Fatalf("error=%T %v class=%q transient=%t", err, err, class, transient)
			}
		})
	}
}

func TestProductionTrackerObserverClassifiesMalformedAuthorityAsCorruption(t *testing.T) {
	observer := productionTrackerObserver{runner: &fakeRunner{
		outputs: [][]byte{[]byte(`{"nameWithOwner":`)},
	}}
	_, err := observer.ObserveIssue(
		context.Background(),
		issuedelivery.GitObservation{Owner: "yersonargotev", Name: "packy"},
		361,
	)
	class, transient, ok := issuedelivery.StatusErrorDetails(err)
	if !ok || class != issuedelivery.StatusErrorCorruption || transient {
		t.Fatalf("error=%T %v class=%q transient=%t", err, err, class, transient)
	}
}

func TestParseIssueAuthorityExtractsStableCriteriaExclusionsAmbiguitiesAndReferences(t *testing.T) {
	body := `## Parent

- #354

## Acceptance criteria

- [ ] Complete issue delivery invokes Advance.
- [ ] Choose one of two materially different outputs?

## Out of scope

- A public packy deliver command.
`
	criteria, exclusions, ambiguities, references := parseIssueAuthority(
		body,
		"https://github.com/yersonargotev/packy/issues/361",
		"yersonargotev/packy",
	)
	if len(criteria) != 1 || criteria[0].Text != "Complete issue delivery invokes Advance." ||
		criteria[0].EvidenceLink != "https://github.com/yersonargotev/packy/issues/361#acceptance-1" {
		t.Fatalf("criteria = %#v", criteria)
	}
	if len(ambiguities) != 1 || !strings.HasSuffix(ambiguities[0].Text, "?") {
		t.Fatalf("ambiguities = %#v", ambiguities)
	}
	if len(exclusions) != 1 || exclusions[0].Text != "A public packy deliver command." {
		t.Fatalf("exclusions = %#v", exclusions)
	}
	if len(references) != 1 || references[0].URL != "https://github.com/yersonargotev/packy/issues/354" {
		t.Fatalf("references = %#v", references)
	}
}

func TestSuppliedReviewExecutorsWaitUntilExactCandidateContentExists(t *testing.T) {
	reviewExecutor := suppliedReviewExecutor{reviews: []issuedelivery.CandidateReview{{
		CandidateID: "candidate-1", Axis: deliveryevidence.ReviewStandards, Completed: true,
	}}}
	waiting, err := reviewExecutor.Review(context.Background(), issuedelivery.ReviewRequest{
		CandidateID: "candidate-2", Axis: deliveryevidence.ReviewStandards,
	})
	if err != nil || waiting.Completed || waiting.Findings == nil ||
		waiting.CandidateID != "candidate-2" {
		t.Fatalf("waiting review = %#v, err=%v", waiting, err)
	}
	exact, err := reviewExecutor.Review(context.Background(), issuedelivery.ReviewRequest{
		CandidateID: "candidate-1", Axis: deliveryevidence.ReviewStandards, Iteration: 2,
		CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
	})
	if err != nil || !exact.Completed || exact.Findings == nil ||
		exact.Iteration != 2 || exact.CommitSHA != strings.Repeat("a", 40) ||
		exact.TreeSHA != strings.Repeat("b", 40) {
		t.Fatalf("exact review = %#v, err=%v", exact, err)
	}

	conflicting := suppliedReviewExecutor{reviews: []issuedelivery.CandidateReview{{
		CandidateID: "candidate-1", Axis: deliveryevidence.ReviewStandards,
		Iteration: 3, CommitSHA: strings.Repeat("c", 40), TreeSHA: strings.Repeat("d", 40),
		Findings: []deliveryevidence.ReviewFinding{}, Completed: true,
	}}}
	stale, err := conflicting.Review(context.Background(), issuedelivery.ReviewRequest{
		CandidateID: "candidate-1", Axis: deliveryevidence.ReviewStandards, Iteration: 2,
		CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
	})
	if err != nil || stale.Iteration != 3 || stale.CommitSHA != strings.Repeat("c", 40) {
		t.Fatalf("adapter overwrote conflicting returned review identity: %#v, err=%v", stale, err)
	}

	specialistExecutor := suppliedSpecialistExecutor{}
	specialist, err := specialistExecutor.ReviewSpecialist(
		context.Background(),
		issuedelivery.SpecialistReviewRequest{
			CandidateID: "candidate-1", Boundary: issuedelivery.BoundarySecurity,
			Specialist: "security-specialist",
		},
	)
	if err != nil || specialist.Completed || specialist.Findings == nil ||
		specialist.Boundary != issuedelivery.BoundarySecurity {
		t.Fatalf("waiting specialist = %#v, err=%v", specialist, err)
	}
}
