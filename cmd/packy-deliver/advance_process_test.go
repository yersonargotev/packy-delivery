package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
	"golang.org/x/sys/unix"
)

const (
	advanceProcessHelperEnvironment = "PACKY_ADVANCE_PROCESS_HELPER"
	advanceProcessRepositoryEnv     = "PACKY_ADVANCE_PROCESS_REPOSITORY"
	advanceProcessSignalsEnv        = "PACKY_ADVANCE_PROCESS_SIGNALS"
	advanceProcessContenderEnv      = "PACKY_ADVANCE_PROCESS_CONTENDER"
	advanceProcessAssuranceEnv      = "PACKY_ADVANCE_PROCESS_ASSURANCE"
	advanceProcessBranchEnv         = "PACKY_ADVANCE_PROCESS_BRANCH_REMEDIATION"
)

func TestAdvanceProcessLifecycle(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	t.Run("caller stops waiting while Advance remains alive", func(t *testing.T) {
		fixture := newAdvanceProcessFixture(t, binary)
		process := fixture.startAdvance()
		process.waitForSignal(filepath.Join(fixture.signals, "started"))

		callerWindow, stopWaiting := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer stopWaiting()
		select {
		case <-process.done:
			t.Fatal("Advance exited before the caller's wait window expired")
		case <-callerWindow.Done():
			if !errors.Is(callerWindow.Err(), context.DeadlineExceeded) {
				t.Fatalf("caller wait window = %v", callerWindow.Err())
			}
		}
		fixture.assertProcessAlive(process.command.Process.Pid)
		fixture.assertValidatorAlive()
		operation := fixture.assertStatusContention()
		fixture.assertConcurrentAdvanceHasDistinctOperation(operation)
		fixture.assertSameStatusOperation(operation)

		watch := fixture.startWatch()
		watch.waitForContention(operation.ID)
		fixture.releaseValidator()
		watch.waitForAvailability()
		process.wait()
		watch.waitForOperationState("completed")
		fixture.assertSignals("started", "released", "exited", "lock-released")
		fixture.assertNoSignal("cancelled")
		fixture.assertValidatorExited()
		fixture.assertValidatorDescendantExited()
	})

	t.Run("actual Advance context cancellation", func(t *testing.T) {
		fixture := newAdvanceProcessFixture(t, binary)
		process := fixture.startAdvance()
		process.waitForSignal(filepath.Join(fixture.signals, "started"))
		operation := fixture.assertStatusContention()

		watch := fixture.startWatch()
		watch.waitForContention(operation.ID)
		if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("cancel Advance context: %v", err)
		}
		watch.waitForAvailability()
		process.wait()
		watch.waitForOperationState("cancelled")
		fixture.assertSignals("started", "cancelled", "exited", "lock-released")
		fixture.assertNoSignal("released")
		fixture.assertValidatorExited()
		fixture.assertValidatorDescendantExited()
	})

	t.Run("normal completion", func(t *testing.T) {
		fixture := newAdvanceProcessFixture(t, binary)
		process := fixture.startAdvance()
		process.waitForSignal(filepath.Join(fixture.signals, "started"))
		operation := fixture.assertStatusContention()

		watch := fixture.startWatch()
		watch.waitForContention(operation.ID)
		fixture.releaseValidator()
		watch.waitForAvailability()
		process.wait()
		watch.waitForOperationState("completed")
		fixture.assertSignals("started", "released", "exited", "lock-released")
		fixture.assertNoSignal("cancelled")
		fixture.assertValidatorExited()
		fixture.assertValidatorDescendantExited()
	})

	t.Run("validator failure", func(t *testing.T) {
		fixture := newAdvanceProcessFixture(t, binary)
		fixture.failValidator()
		process := fixture.startAdvance()
		process.waitForSignal(filepath.Join(fixture.signals, "started"))
		operation := fixture.assertStatusContention()

		watch := fixture.startWatch()
		watch.waitForContention(operation.ID)
		fixture.releaseValidator()
		watch.waitForAvailability()
		process.waitForFailure()
		watch.waitForOperationState("failed")
		fixture.assertSignals("started", "released", "exited", "lock-released")
		fixture.assertValidatorExited()
		fixture.assertValidatorDescendantExited()
	})
}

func TestAdvanceProcessAssuranceProgress(t *testing.T) {
	fixture := newAdvanceProcessFixture(t, "")
	command := exec.Command(os.Args[0], "-test.run=^TestAdvanceProcessHelper$")
	command.Env = replacedEnvironment(fixture.environment, map[string]string{
		advanceProcessHelperEnvironment: "1",
		advanceProcessAssuranceEnv:      "1",
		advanceProcessRepositoryEnv:     fixture.repository,
		advanceProcessSignalsEnv:        fixture.signals,
	})
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("assurance progress subprocess: %v\n%s", err, output)
	}
	var snapshots []processAssuranceSnapshot
	if err := json.NewDecoder(bytes.NewReader(output)).Decode(&snapshots); err != nil {
		t.Fatalf("decode assurance progress subprocess output: %v\n%s", err, output)
	}
	expected := []struct {
		name                string
		completedAxes       []deliveryevidence.ReviewAxis
		pendingAxes         []deliveryevidence.ReviewAxis
		completedBoundaries []issuedelivery.CompactSpecialistBoundary
		pendingBoundaries   []issuedelivery.CompactSpecialistBoundary
	}{
		{name: "no candidate"},
		{
			name:          "initial candidate",
			completedAxes: []deliveryevidence.ReviewAxis{},
			pendingAxes: []deliveryevidence.ReviewAxis{
				deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
			},
			completedBoundaries: []issuedelivery.CompactSpecialistBoundary{},
			pendingBoundaries: []issuedelivery.CompactSpecialistBoundary{
				{Boundary: issuedelivery.BoundaryRealConfiguration, Specialist: "configuration-specialist"},
				{Boundary: issuedelivery.BoundarySecurity, Specialist: "security-specialist"},
			},
		},
		{
			name:                "partial candidate reviews",
			completedAxes:       []deliveryevidence.ReviewAxis{deliveryevidence.ReviewStandards},
			pendingAxes:         []deliveryevidence.ReviewAxis{deliveryevidence.ReviewSpec},
			completedBoundaries: []issuedelivery.CompactSpecialistBoundary{},
			pendingBoundaries: []issuedelivery.CompactSpecialistBoundary{
				{Boundary: issuedelivery.BoundaryRealConfiguration, Specialist: "configuration-specialist"},
				{Boundary: issuedelivery.BoundarySecurity, Specialist: "security-specialist"},
			},
		},
		{
			name: "partial specialist reviews",
			completedAxes: []deliveryevidence.ReviewAxis{
				deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
			},
			pendingAxes: []deliveryevidence.ReviewAxis{},
			completedBoundaries: []issuedelivery.CompactSpecialistBoundary{
				{Boundary: issuedelivery.BoundarySecurity, Specialist: "security-specialist"},
			},
			pendingBoundaries: []issuedelivery.CompactSpecialistBoundary{
				{Boundary: issuedelivery.BoundaryRealConfiguration, Specialist: "configuration-specialist"},
			},
		},
		{
			name: "completed assurance",
			completedAxes: []deliveryevidence.ReviewAxis{
				deliveryevidence.ReviewStandards, deliveryevidence.ReviewSpec,
			},
			pendingAxes: []deliveryevidence.ReviewAxis{},
			completedBoundaries: []issuedelivery.CompactSpecialistBoundary{
				{Boundary: issuedelivery.BoundaryRealConfiguration, Specialist: "configuration-specialist"},
				{Boundary: issuedelivery.BoundarySecurity, Specialist: "security-specialist"},
			},
			pendingBoundaries: []issuedelivery.CompactSpecialistBoundary{},
		},
	}
	if len(snapshots) != len(expected) {
		t.Fatalf("assurance progress snapshots = %d, want %d\n%s", len(snapshots), len(expected), output)
	}
	for index, want := range expected {
		snapshot := snapshots[index]
		if snapshot.Name != want.name {
			t.Fatalf("snapshot %d name = %q, want %q", index, snapshot.Name, want.name)
		}
		var report compactAdvanceReport
		if err := json.Unmarshal(snapshot.JSON, &report); err != nil {
			t.Fatalf("decode %s compact JSON: %v", want.name, err)
		}
		if want.name == "no candidate" {
			if report.Assurance.Progress != nil ||
				strings.Contains(snapshot.Text, "candidate review") ||
				strings.Contains(snapshot.Text, "specialist review") {
				t.Fatalf("no-candidate process report invented assurance progress:\nJSON=%s\ntext=%s", snapshot.JSON, snapshot.Text)
			}
			continue
		}
		progress := report.Assurance.Progress
		if progress == nil ||
			!reflect.DeepEqual(progress.CandidateReviewAxes.Completed, want.completedAxes) ||
			!reflect.DeepEqual(progress.CandidateReviewAxes.Pending, want.pendingAxes) ||
			progress.SpecialistBoundaries == nil ||
			!reflect.DeepEqual(progress.SpecialistBoundaries.Completed, want.completedBoundaries) ||
			!reflect.DeepEqual(progress.SpecialistBoundaries.Pending, want.pendingBoundaries) {
			t.Fatalf("%s process progress = %#v", want.name, progress)
		}
		entries := append(
			compactProgressTextEntries(want.completedAxes, want.pendingAxes),
			compactSpecialistProgressTextEntries(want.completedBoundaries, want.pendingBoundaries)...,
		)
		for _, entry := range entries {
			if !strings.Contains(snapshot.Text, entry) {
				t.Errorf("%s text output missing %q:\n%s", want.name, entry, snapshot.Text)
			}
		}
	}
}

func TestAdvanceProcessReportsStructuredBranchRemediation(t *testing.T) {
	fixture := newAdvanceProcessFixture(t, "")
	runFixtureGit(t, fixture.repository, fixture.environment, "branch", "-m", "main")
	command := exec.Command(os.Args[0], "-test.run=^TestAdvanceProcessHelper$")
	command.Env = replacedEnvironment(fixture.environment, map[string]string{
		advanceProcessHelperEnvironment: "1",
		advanceProcessBranchEnv:         "1",
		advanceProcessRepositoryEnv:     fixture.repository,
		advanceProcessSignalsEnv:        fixture.signals,
	})
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("branch remediation subprocess: %v\n%s", err, output)
	}
	var snapshot processBranchRemediationSnapshot
	if err := json.NewDecoder(bytes.NewReader(output)).Decode(&snapshot); err != nil {
		t.Fatalf("decode branch remediation subprocess output: %v\n%s", err, output)
	}
	var report compactAdvanceReport
	if err := json.Unmarshal(snapshot.JSON, &report); err != nil {
		t.Fatalf("decode branch remediation JSON: %v\n%s", err, snapshot.JSON)
	}
	want := []string{
		"chore/issue-44-*", "feat/issue-44-*", "fix/issue-44-*",
	}
	if report.BlockerKind != issuedelivery.BlockerLocalReadiness ||
		report.Remediation == nil ||
		!reflect.DeepEqual(report.Remediation.AcceptedBranchForms, want) {
		t.Fatalf("process branch remediation=%#v; want %#v", report.Remediation, want)
	}
	if !strings.Contains(snapshot.Text,
		"accepted branch forms: chore/issue-44-*, feat/issue-44-*, fix/issue-44-*\n") {
		t.Fatalf("process text remediation=%q", snapshot.Text)
	}
}

// TestAdvanceProcessHelper is a test-only process host. It exercises the public
// command parser with a cancellable context while the harness below reproduces
// Advance's real issue flock and production validator adapter.
func TestAdvanceProcessHelper(t *testing.T) {
	if os.Getenv(advanceProcessHelperEnvironment) == "" {
		t.Skip("process helper")
	}
	repository := os.Getenv(advanceProcessRepositoryEnv)
	signals := os.Getenv(advanceProcessSignalsEnv)
	if os.Getenv(advanceProcessAssuranceEnv) != "" {
		runProcessAssuranceProgressHelper(t, repository, signals)
		return
	}
	if os.Getenv(advanceProcessBranchEnv) != "" {
		runProcessBranchRemediationHelper(t, repository, signals)
		return
	}
	ctx, cancel := commandContext([]string{"advance"})
	defer cancel()
	contender := os.Getenv(advanceProcessContenderEnv) != ""
	var module *issuedelivery.Module
	if contender {
		module = newProcessContentionModule(t)
	} else {
		module = newProcessLifecycleModule(t, repository, signals)
	}
	cmd := command{AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) {
		return module, nil
	}}
	var output bytes.Buffer
	err := cmd.run(ctx, []string{
		"advance", "--repository", repository, "--issue", "44",
		"--risk-profile", "low-risk",
	}, &output)
	if contender {
		_, _ = os.Stdout.Write(output.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	assertProcessIssueLockAvailable(t, repository)
	writeProcessSignal(signals, "lock-released")
	if ctx.Err() != nil {
		if err == nil {
			t.Fatal("cancelled Advance returned without an error")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
}

type processAssuranceSnapshot struct {
	Name string          `json:"name"`
	JSON json.RawMessage `json:"json"`
	Text string          `json:"text"`
}

type processBranchRemediationSnapshot struct {
	JSON json.RawMessage `json:"json"`
	Text string          `json:"text"`
}

func runProcessBranchRemediationHelper(t *testing.T, repository, signals string) {
	t.Helper()
	module := newProcessLifecycleModuleWithExecutors(
		t, repository, signals, productionPathReviewExecutor{}, productionPathRiskObserver{},
		productionPathSpecialistExecutor{}, false,
	)
	qualifyProcessLifecycleModule(t, module, repository)
	cmd := command{
		AdvanceFactory: func(advanceOptions) (issueDeliveryAdvancer, error) { return module, nil },
		StatusFactory:  func(statusOptions) (issueDeliveryStatuser, error) { return module, nil },
	}
	run := func(args ...string) string {
		t.Helper()
		var output bytes.Buffer
		if err := cmd.run(context.Background(), args, &output); err != nil {
			t.Fatal(err)
		}
		return output.String()
	}
	snapshot := processBranchRemediationSnapshot{
		JSON: json.RawMessage(run(
			"advance", "--repository", repository, "--issue", "44", "--risk-profile", "low-risk",
		)),
		Text: run("status", "--repository", repository, "--issue", "44", "--output", "text"),
	}
	if err := json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
		t.Fatal(err)
	}
}

type processStagedReviewExecutor struct {
	completeSpec atomic.Bool
}

func (executor *processStagedReviewExecutor) Review(
	ctx context.Context,
	request issuedelivery.ReviewRequest,
) (issuedelivery.CandidateReview, error) {
	review, err := (productionPathReviewExecutor{}).Review(ctx, request)
	if request.Axis == deliveryevidence.ReviewSpec && !executor.completeSpec.Load() {
		review.Acceptance = nil
		review.Completed = false
	}
	return review, err
}

type processStagedSpecialistExecutor struct {
	completeConfiguration atomic.Bool
}

func (executor *processStagedSpecialistExecutor) ReviewSpecialist(
	ctx context.Context,
	request issuedelivery.SpecialistReviewRequest,
) (issuedelivery.SpecialistReview, error) {
	review, err := (productionPathSpecialistExecutor{}).ReviewSpecialist(ctx, request)
	if request.Boundary == issuedelivery.BoundaryRealConfiguration &&
		!executor.completeConfiguration.Load() {
		review.Completed = false
	}
	return review, err
}

func runProcessAssuranceProgressHelper(t *testing.T, repository, signals string) {
	t.Helper()
	reviews := &processStagedReviewExecutor{}
	specialists := &processStagedSpecialistExecutor{}
	module := newProcessLifecycleModuleWithExecutors(
		t,
		repository,
		signals,
		reviews,
		productionPathHighRiskObserver{},
		specialists,
		false,
	)
	qualifyProcessLifecycleModule(t, module, repository)
	snapshots := []processAssuranceSnapshot{
		captureProcessAssuranceSnapshot(t, "no candidate", module, repository),
	}
	request := issuedelivery.Request{RepositoryPath: repository, IssueNumber: 44}
	advance := func() {
		t.Helper()
		if _, err := module.Advance(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	advance()
	snapshots = append(snapshots, captureProcessAssuranceSnapshot(t, "initial candidate", module, repository))
	advance()
	snapshots = append(snapshots, captureProcessAssuranceSnapshot(t, "partial candidate reviews", module, repository))
	reviews.completeSpec.Store(true)
	advance()
	advance()
	snapshots = append(snapshots, captureProcessAssuranceSnapshot(t, "partial specialist reviews", module, repository))
	specialists.completeConfiguration.Store(true)
	advance()
	snapshots = append(snapshots, captureProcessAssuranceSnapshot(t, "completed assurance", module, repository))
	if err := json.NewEncoder(os.Stdout).Encode(snapshots); err != nil {
		t.Fatal(err)
	}
}

func captureProcessAssuranceSnapshot(
	t *testing.T,
	name string,
	module *issuedelivery.Module,
	repository string,
) processAssuranceSnapshot {
	t.Helper()
	cmd := command{StatusFactory: func(statusOptions) (issueDeliveryStatuser, error) {
		return module, nil
	}}
	run := func(extra ...string) string {
		t.Helper()
		args := []string{"status", "--repository", repository, "--issue", "44"}
		args = append(args, extra...)
		var output bytes.Buffer
		if err := cmd.run(context.Background(), args, &output); err != nil {
			t.Fatal(err)
		}
		return output.String()
	}
	return processAssuranceSnapshot{
		Name: name,
		JSON: json.RawMessage(run()),
		Text: run("--output", "text"),
	}
}

func newProcessContentionModule(t *testing.T) *issuedelivery.Module {
	t.Helper()
	module, err := issuedelivery.New(issuedelivery.Config{
		Git:    productionGitObserver{runner: execRunner{}},
		GitHub: &commandMutableTrackerObserver{},
		Clock:  &commandClock{now: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return module
}

type processValidationRunner struct {
	signals string
	mu      sync.Mutex
	armed   bool
}

var errProcessValidationBoundary = errors.New("process validation boundary reached")

func (r *processValidationRunner) Run(
	ctx context.Context,
	repository string,
	sandbox deliveryevidence.SandboxFacts,
) error {
	r.mu.Lock()
	armed := r.armed
	r.mu.Unlock()
	if !armed {
		return errProcessValidationBoundary
	}
	runErr := (execValidationRunner{}).Run(ctx, repository, sandbox)
	if ctx.Err() != nil {
		writeProcessSignal(r.signals, "cancelled")
	}
	writeProcessSignal(r.signals, "exited")
	return runErr
}

func (r *processValidationRunner) arm() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.armed = true
}

func newProcessLifecycleModule(t *testing.T, repository, signals string) *issuedelivery.Module {
	return newProcessLifecycleModuleWithExecutors(
		t,
		repository,
		signals,
		productionPathReviewExecutor{},
		productionPathRiskObserver{},
		productionPathSpecialistExecutor{},
		true,
	)
}

func newProcessLifecycleModuleWithExecutors(
	t *testing.T,
	repository string,
	signals string,
	review issuedelivery.ReviewExecutor,
	risk issuedelivery.CandidateRiskObserver,
	specialist issuedelivery.SpecialistReviewExecutor,
	advanceToValidation bool,
) *issuedelivery.Module {
	t.Helper()
	gitOutput := func(args ...string) string {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", repository}, args...)...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
		}
		return strings.TrimSpace(string(output))
	}
	base := gitOutput("rev-parse", "origin/main^{commit}")
	commit := gitOutput("rev-parse", "HEAD^{commit}")
	tree := gitOutput("rev-parse", "HEAD^{tree}")
	common := filepath.Join(repository, ".git")
	sandbox := filepath.Join(signals, "sandbox")
	git := commandGitObserver{observation: issuedelivery.GitObservation{
		CommonDir: common, Worktree: repository,
		OriginURL: "git@github.com:yersonargotev/packy.git",
		Owner:     "yersonargotev", Name: "packy", StartingBaseSHA: base,
		HeadSHA: commit, TreeSHA: tree, WorkspaceClean: true,
		Branch: gitOutput("branch", "--show-current"),
	}}
	tracker := &commandMutableTrackerObserver{observation: issuedelivery.TrackerObservation{
		Repository: deliveryevidence.RepositoryIdentity{
			Owner: "yersonargotev", Name: "packy", NodeID: "R1",
		},
		Issue: deliveryevidence.IssueIdentity{Number: 44, NodeID: "I44"},
		Title: "Reproduce Advance process cancellation", Body: "Approved authority.", State: "OPEN",
		Labels: []string{"status:approved", "type:chore"},
		Criteria: []issuedelivery.AuthorityItem{{
			Text: "Characterize a long-running Advance process.", EvidenceLink: "issue#44:acceptance-1",
		}},
		Exclusions: []issuedelivery.AuthorityItem{}, Dependencies: []issuedelivery.DependencyObservation{},
		References: []issuedelivery.ReferenceObservation{}, Ambiguities: []issuedelivery.AuthorityItem{},
	}}
	clock := &commandClock{now: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)}
	focused := &fakeValidationRunner{}
	longRunning := &processValidationRunner{signals: signals}
	observation := productionValidationObservationRunner{
		commit: commit, tree: tree, repository: repository, common: common,
	}
	validation := &productionValidationExecutor{
		repository: repository, runner: observation,
		focused: focused, exhaustive: longRunning, now: clock.Now,
	}
	boundary := productionBoundaryExecutor{
		repository: repository, runner: observation, validation: longRunning, mu: &sync.Mutex{},
	}
	module, err := issuedelivery.New(issuedelivery.Config{
		Git: git, GitHub: tracker, Review: review,
		Validation: validation, Risk: risk,
		Specialist: specialist, Boundary: boundary,
		ValidationSession: productionValidationSessionExecutor{
			repository: repository, runner: observation, validation: longRunning, boundary: boundary,
		},
		Clock: clock, SandboxRoot: sandbox, DeclaredProfile: deliveryevidence.RiskLow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if advanceToValidation {
		qualifyProcessLifecycleModule(t, module, repository)
		advanceProcessLifecycleModuleToValidation(t, module, repository, longRunning)
	}
	return module
}

func advanceProcessLifecycleModuleToValidation(
	t *testing.T,
	module *issuedelivery.Module,
	repository string,
	validation *processValidationRunner,
) {
	t.Helper()
	request := issuedelivery.Request{RepositoryPath: repository, IssueNumber: 44}
	for attempts := 0; attempts < 8; attempts++ {
		_, err := module.Advance(context.Background(), request)
		if errors.Is(err, errProcessValidationBoundary) {
			validation.arm()
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("Advance did not reach the process validation boundary")
}

func qualifyProcessLifecycleModule(t *testing.T, module *issuedelivery.Module, repository string) {
	t.Helper()
	request := issuedelivery.Request{RepositoryPath: repository, IssueNumber: 44}
	qualified, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	pending := qualified.QualificationCorrection
	if pending == nil {
		t.Fatalf("qualification correction is absent: %#v", qualified)
	}
	rows := append([]deliveryevidence.AcceptanceRow(nil), qualified.Evidence.AcceptanceMatrix...)
	for index := range rows {
		identity := strings.ReplaceAll(rows[index].Identity, "-", "_")
		prefix := "[criterion:" + rows[index].Identity + "] "
		rows[index].OwningSeam = prefix + "source=symbol:packydeliver." + identity +
			".processLifecycle; assertion=public process lifecycle owns the reproduction"
		rows[index].PositiveEvidence = prefix + "source=test:TestAdvanceProcessLifecycle_Positive; assertion=normal completion is observed"
		rows[index].NegativeEvidence = prefix + "source=test:TestAdvanceProcessLifecycle_Negative; assertion=detached waiting does not cancel"
		rows[index].FailureEvidence = prefix + "source=test:TestAdvanceProcessLifecycle_Failure; assertion=context cancellation terminates validation"
		rows[index].MutationEvidence = prefix + "source=test:TestAdvanceProcessLifecycle_Mutation; assertion=lock availability changes after exit"
		rows[index].CompatibilityEvidence = prefix + "source=test:TestAdvanceProcessLifecycle_Compatibility; assertion=public contention output remains compatible"
		rows[index].PreservationEvidence = prefix + "source=test:TestAdvanceProcessLifecycle_Preservation; assertion=sandboxed roots and local repository are preserved"
		rows[index].MigrationEvidence = prefix + "source=authority:" + rows[index].Identity + "/migration; assertion=no schema migration is required for this process fixture"
	}
	corrected, err := module.Advance(context.Background(), issuedelivery.Request{
		RepositoryPath: repository, IssueNumber: 44,
		QualificationCorrection: &issuedelivery.QualificationCorrection{
			RequestID: pending.ID, AuthoritySHA256: pending.AuthoritySHA256,
			ReviewedMatrixSHA256: pending.ReviewedMatrixSHA256, FindingIDs: pending.FindingIDs,
			AcceptanceMatrix: rows,
			Evidence: "[request:" + pending.ID + "] findings=" + strings.Join(pending.FindingIDs, ",") +
				"; rationale=bound the process lifecycle fixture through typed qualification",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(corrected.Evidence.AcceptanceMatrix)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	approved, err := module.Advance(context.Background(), issuedelivery.Request{
		RepositoryPath: repository, IssueNumber: 44,
		QualificationReview: &issuedelivery.QualificationReview{
			AuthoritySHA256:        corrected.Observations.AuthoritySHA256,
			AcceptanceMatrixSHA256: hex.EncodeToString(digest[:]),
			Findings:               []deliveryevidence.ReviewFinding{}, Completed: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !approved.QualificationApproved {
		t.Fatalf("qualification was not approved: %#v", approved)
	}
}

func assertProcessIssueLockAvailable(t *testing.T, repository string) {
	t.Helper()
	lock, err := os.OpenFile(
		filepath.Join(repository, ".git", "packy", "issue-delivery", "issue-44", "advance.lock"),
		os.O_RDWR,
		0o600,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("issue lock remains held after Advance returned: %v", err)
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

type advanceProcessFixture struct {
	t           *testing.T
	binary      string
	repository  string
	signals     string
	environment []string
}

func newAdvanceProcessFixture(t *testing.T, binary string) *advanceProcessFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(root, "repository")
	signals := filepath.Join(root, "signals")
	tools := filepath.Join(root, "tools")
	for _, directory := range []string{
		repository,
		signals,
		tools,
		filepath.Join(repository, "scripts"),
		filepath.Join(signals, "sandbox", "home"),
		filepath.Join(signals, "sandbox", "config"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mkfifo(filepath.Join(signals, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	validator := []byte(`#!/bin/sh
set -eu
printf '%s\n' "$$" > "$PACKY_ADVANCE_PROCESS_SIGNALS/validator-pid"
sleep 100000 &
descendant=$!
printf '%s\n' "$descendant" > "$PACKY_ADVANCE_PROCESS_SIGNALS/validator-descendant-pid"
cleanup() {
  kill "$descendant" 2>/dev/null || true
  wait "$descendant" 2>/dev/null || true
}
trap cleanup EXIT
: > "$PACKY_ADVANCE_PROCESS_SIGNALS/started"
IFS= read -r _ < "$PACKY_ADVANCE_PROCESS_SIGNALS/release"
: > "$PACKY_ADVANCE_PROCESS_SIGNALS/released"
if [ -f "$PACKY_ADVANCE_PROCESS_SIGNALS/fail" ]; then
  exit 17
fi
`)
	if err := os.WriteFile(filepath.Join(repository, "scripts", "validate-packy.sh"), validator, 0o700); err != nil {
		t.Fatal(err)
	}
	githubGuard := []byte(`#!/bin/sh
: > "$PACKY_ADVANCE_PROCESS_SIGNALS/github-called"
exit 99
`)
	if err := os.WriteFile(filepath.Join(tools, "gh"), githubGuard, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	config := filepath.Join(root, "config")
	for _, directory := range []string{home, config} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	environment := replacedEnvironment(os.Environ(), map[string]string{
		"HOME": home, "XDG_CONFIG_HOME": config,
		"PATH":                   tools + string(os.PathListSeparator) + os.Getenv("PATH"),
		advanceProcessSignalsEnv: signals,
		"GIT_CONFIG_GLOBAL":      filepath.Join(root, "empty-gitconfig"),
		"GIT_CONFIG_NOSYSTEM":    "1",
	})
	runFixtureGit(t, repository, environment, "init", "-b", "chore/issue-44-process-lifecycle")
	runFixtureGit(t, repository, environment, "config", "user.name", "Packy Process Test")
	runFixtureGit(t, repository, environment, "config", "user.email", "packy-process@example.test")
	runFixtureGit(t, repository, environment, "remote", "add", "origin", "git@github.com:yersonargotev/packy.git")
	runFixtureGit(t, repository, environment, "add", "scripts/validate-packy.sh")
	runFixtureGit(t, repository, environment, "commit", "-m", "process fixture base")
	runFixtureGit(t, repository, environment, "update-ref", "refs/remotes/origin/main", "HEAD")
	if err := os.WriteFile(filepath.Join(repository, "candidate.txt"), []byte("candidate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, repository, environment, "add", "candidate.txt")
	runFixtureGit(t, repository, environment, "commit", "-m", "candidate")
	fixture := &advanceProcessFixture{
		t: t, binary: binary, repository: repository, signals: signals, environment: environment,
	}
	t.Cleanup(func() { fixture.assertNoSignal("github-called") })
	return fixture
}

type managedProcess struct {
	t       *testing.T
	command *exec.Cmd
	done    chan struct{}
	mu      sync.Mutex
	err     error
	stdout  *safeBuffer
	stderr  *safeBuffer
}

func startManagedProcess(t *testing.T, command *exec.Cmd, cleanupSignal os.Signal) *managedProcess {
	t.Helper()
	process := &managedProcess{
		t: t, command: command, done: make(chan struct{}),
		stdout: &safeBuffer{}, stderr: &safeBuffer{},
	}
	command.Stdout, command.Stderr = process.stdout, process.stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		process.mu.Lock()
		process.err = command.Wait()
		process.mu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() {
		select {
		case <-process.done:
			return
		default:
		}
		_ = process.command.Process.Signal(cleanupSignal)
		select {
		case <-process.done:
		case <-time.After(2 * time.Second):
			_ = process.command.Process.Kill()
			<-process.done
		}
	})
	return process
}

func (f *advanceProcessFixture) startAdvance() *managedProcess {
	f.t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestAdvanceProcessHelper$")
	command.Env = replacedEnvironment(f.environment, map[string]string{
		advanceProcessHelperEnvironment: "1",
		advanceProcessRepositoryEnv:     f.repository,
		advanceProcessSignalsEnv:        f.signals,
	})
	return startManagedProcess(f.t, command, syscall.SIGTERM)
}

func (f *advanceProcessFixture) startWatch() *runningWatch {
	f.t.Helper()
	command := exec.Command(
		f.binary, "watch", "--repository", f.repository, "--issue", "44",
		"--interval", "100ms", "--timeout", "10s", "--output", "jsonl",
	)
	command.Env = f.environment
	return &runningWatch{managedProcess: startManagedProcess(f.t, command, os.Kill)}
}

type processOperation struct {
	ID                  string `json:"id"`
	Kind                string `json:"kind"`
	Phase               string `json:"phase"`
	State               string `json:"state"`
	StartedAt           string `json:"started_at"`
	ValidationSessionID string `json:"validation_session_id"`
}

func (f *advanceProcessFixture) assertStatusContention() processOperation {
	f.t.Helper()
	command := exec.Command(
		f.binary, "status", "--repository", f.repository, "--issue", "44", "--output", "json",
	)
	command.Env = f.environment
	output, err := command.CombinedOutput()
	if err != nil {
		f.t.Fatalf("status contention probe: %v\n%s", err, output)
	}
	for _, expected := range []string{`"pause_cause": "lock-contention"`, `"next_action": "retry-advance"`} {
		if !bytes.Contains(output, []byte(expected)) {
			f.t.Fatalf("status did not report %s: %s", expected, output)
		}
	}
	var report struct {
		Operation *processOperation `json:"operation"`
	}
	if err := json.NewDecoder(bytes.NewReader(output)).Decode(&report); err != nil {
		f.t.Fatal(err)
	}
	if report.Operation == nil || len(report.Operation.ID) != 32 ||
		report.Operation.Kind != "advance" || report.Operation.Phase != "validation-session" || report.Operation.State != "active" ||
		report.Operation.StartedAt == "" || report.Operation.ValidationSessionID == "" {
		f.t.Fatalf("status operation metadata is incomplete: %#v\n%s", report.Operation, output)
	}
	if report.Operation.ID == report.Operation.ValidationSessionID {
		f.t.Fatalf("operation identity must be distinct from validation session identity: %#v", report.Operation)
	}
	return *report.Operation
}

func (f *advanceProcessFixture) assertSameStatusOperation(want processOperation) {
	f.t.Helper()
	if got := f.assertStatusContention(); got != want {
		f.t.Fatalf("live operation identity changed: got %#v want %#v", got, want)
	}
}

func (f *advanceProcessFixture) assertConcurrentAdvanceHasDistinctOperation(owner processOperation) {
	f.t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestAdvanceProcessHelper$")
	command.Env = replacedEnvironment(f.environment, map[string]string{
		advanceProcessHelperEnvironment: "1",
		advanceProcessContenderEnv:      "1",
		advanceProcessRepositoryEnv:     f.repository,
		advanceProcessSignalsEnv:        f.signals,
	})
	output, err := command.CombinedOutput()
	if err != nil {
		f.t.Fatalf("concurrent Advance: %v\n%s", err, output)
	}
	var report struct {
		PauseCause string            `json:"pause_cause"`
		Operation  *processOperation `json:"operation"`
	}
	if err := json.NewDecoder(bytes.NewReader(output)).Decode(&report); err != nil {
		f.t.Fatal(err)
	}
	if report.PauseCause != "lock-contention" || report.Operation == nil ||
		report.Operation.ID == owner.ID || report.Operation.State != "completed" {
		f.t.Fatalf("concurrent Advance operation = %#v, owner = %#v\n%s", report.Operation, owner, output)
	}
}

func (f *advanceProcessFixture) releaseValidator() {
	f.t.Helper()
	release, err := os.OpenFile(filepath.Join(f.signals, "release"), os.O_WRONLY, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err = release.WriteString("release\n"); err != nil {
		release.Close()
		f.t.Fatal(err)
	}
	if err = release.Close(); err != nil {
		f.t.Fatal(err)
	}
}

func (f *advanceProcessFixture) failValidator() {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.signals, "fail"), []byte("\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *advanceProcessFixture) waitForSignal(name string) {
	f.t.Helper()
	waitForPath(f.t, filepath.Join(f.signals, name), "signal "+name)
}

func (f *advanceProcessFixture) assertSignals(names ...string) {
	f.t.Helper()
	for _, name := range names {
		f.waitForSignal(name)
	}
}

func (f *advanceProcessFixture) assertNoSignal(name string) {
	f.t.Helper()
	if _, err := os.Stat(filepath.Join(f.signals, name)); !errors.Is(err, os.ErrNotExist) {
		f.t.Fatalf("unexpected %s signal: %v", name, err)
	}
}

func (f *advanceProcessFixture) assertProcessAlive(pid int) {
	f.t.Helper()
	if err := unix.Kill(pid, 0); err != nil {
		f.t.Fatalf("Advance process %d is not alive: %v", pid, err)
	}
}

func (f *advanceProcessFixture) assertValidatorAlive() {
	f.t.Helper()
	pid := f.validatorPID()
	if err := unix.Kill(pid, 0); err != nil {
		f.t.Fatalf("validator process %d is not alive: %v", pid, err)
	}
}

func (f *advanceProcessFixture) assertValidatorExited() {
	f.t.Helper()
	pid := f.validatorPID()
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		f.t.Fatalf("validator process %d survived unexpectedly: %v", pid, err)
	}
}

func (f *advanceProcessFixture) assertValidatorDescendantExited() {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.signals, "validator-descendant-pid"))
	if err != nil {
		f.t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		f.t.Fatal(err)
	}
	exited, _, err := pollUntil(10*time.Second, nil, func() (bool, error) {
		return errors.Is(unix.Kill(pid, 0), unix.ESRCH), nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if !exited {
		f.t.Fatalf("validator descendant process %d survived unexpectedly", pid)
	}
}

func (f *advanceProcessFixture) validatorPID() int {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.signals, "validator-pid"))
	if err != nil {
		f.t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		f.t.Fatal(err)
	}
	return pid
}

func (p *managedProcess) wait() {
	p.t.Helper()
	select {
	case <-p.done:
		p.mu.Lock()
		err := p.err
		p.mu.Unlock()
		if err != nil {
			p.t.Fatalf("Advance helper: %v\nstdout=%s\nstderr=%s", err, p.stdout.String(), p.stderr.String())
		}
	case <-time.After(10 * time.Second):
		p.t.Fatalf("Advance helper did not exit\nstdout=%s\nstderr=%s", p.stdout.String(), p.stderr.String())
	}
}

func (p *managedProcess) waitForFailure() {
	p.t.Helper()
	select {
	case <-p.done:
		p.mu.Lock()
		err := p.err
		p.mu.Unlock()
		if err == nil {
			p.t.Fatalf("Advance helper succeeded unexpectedly\nstdout=%s\nstderr=%s", p.stdout.String(), p.stderr.String())
		}
	case <-time.After(10 * time.Second):
		p.t.Fatalf("Advance helper did not exit\nstdout=%s\nstderr=%s", p.stdout.String(), p.stderr.String())
	}
}

func (p *managedProcess) waitForSignal(path string) {
	p.t.Helper()
	ready, stopped, err := pollUntil(10*time.Second, p.done, func() (bool, error) {
		if _, err := os.Stat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		return false, nil
	})
	if err != nil {
		p.t.Fatal(err)
	}
	if stopped {
		p.mu.Lock()
		processErr := p.err
		p.mu.Unlock()
		p.t.Fatalf("Advance helper exited before %s: %v\nstdout=%s\nstderr=%s", filepath.Base(path), processErr, p.stdout.String(), p.stderr.String())
	}
	if !ready {
		p.t.Fatalf("timed out waiting for %s\nstdout=%s\nstderr=%s", filepath.Base(path), p.stdout.String(), p.stderr.String())
	}
}

type runningWatch struct {
	*managedProcess
}

func (w *runningWatch) waitForContention(operationID string) {
	w.t.Helper()
	w.waitForOutput(`"pause_cause":"lock-contention"`)
	w.waitForOutput(`"id":"` + operationID + `"`)
	w.waitForOutput(`"phase":"validation-session"`)
}

func (w *runningWatch) waitForAvailability() {
	w.t.Helper()
	select {
	case <-w.done:
		w.mu.Lock()
		err := w.err
		w.mu.Unlock()
		if err != nil {
			w.t.Fatalf("watch: %v\nstdout=%s\nstderr=%s", err, w.stdout.String(), w.stderr.String())
		}
	case <-time.After(10 * time.Second):
		w.t.Fatalf("watch did not observe lock release\nstdout=%s\nstderr=%s", w.stdout.String(), w.stderr.String())
	}
	for _, expected := range []string{`"kind":"lock","value":"available"`, `"next_action":"retry-advance"`} {
		if !strings.Contains(w.stdout.String(), expected) {
			w.t.Fatalf("watch did not report %s: %s", expected, w.stdout.String())
		}
	}
}

func (w *runningWatch) waitForOperationState(state string) {
	w.t.Helper()
	if !strings.Contains(w.stdout.String(), `"operation":`) ||
		!strings.Contains(w.stdout.String(), `"state":"`+state+`"`) {
		w.t.Fatalf("watch did not report terminal operation state %q: %s", state, w.stdout.String())
	}
}

func (w *runningWatch) waitForOutput(expected string) {
	w.t.Helper()
	ready, stopped, err := pollUntil(10*time.Second, w.done, func() (bool, error) {
		return strings.Contains(w.stdout.String(), expected), nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
	if stopped {
		w.mu.Lock()
		processErr := w.err
		w.mu.Unlock()
		w.t.Fatalf("watch exited before %s: %v\nstdout=%s\nstderr=%s", expected, processErr, w.stdout.String(), w.stderr.String())
	}
	if !ready {
		w.t.Fatalf("watch did not emit %s\nstdout=%s\nstderr=%s", expected, w.stdout.String(), w.stderr.String())
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *safeBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(data)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func waitForPath(t *testing.T, path, description string) {
	t.Helper()
	ready, _, err := pollUntil(10*time.Second, nil, func() (bool, error) {
		if _, err := os.Stat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		return false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ready {
		t.Fatalf("timed out waiting for %s", description)
	}
}

func pollUntil(
	timeout time.Duration,
	stopped <-chan struct{},
	ready func() (bool, error),
) (matched bool, processStopped bool, err error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		matched, err = ready()
		if matched || err != nil {
			return matched, false, err
		}
		select {
		case <-stopped:
			return false, true, nil
		case <-timer.C:
			return false, false, nil
		case <-ticker.C:
		}
	}
}

func writeProcessSignal(directory, name string) {
	_ = os.WriteFile(filepath.Join(directory, name), []byte("\n"), 0o600)
}

func runFixtureGit(t *testing.T, repository string, environment []string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", repository}, args...)...)
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}
