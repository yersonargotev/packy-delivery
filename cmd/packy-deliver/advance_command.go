package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
	"github.com/yersonargotev/packy-delivery/internal/issuedelivery"
)

type advanceOptions struct {
	RepositoryPath          string
	IssueNumber             int
	SpecificationNumber     int
	SandboxRoot             string
	DeclaredProfile         deliveryevidence.DeliveryRiskProfile
	Decision                *issuedelivery.Decision
	Repair                  *issuedelivery.RepairDecision
	Reviews                 []issuedelivery.CandidateReview
	Specialists             []issuedelivery.SpecialistReview
	Acceptance              []issuedelivery.AcceptanceProof
	QualificationReview     *issuedelivery.QualificationReview
	QualificationCorrection *issuedelivery.QualificationCorrection
	CIFailureAttributions   []advanceCIFailureAttribution
	AuthorizeRemote         bool
	FullReport              bool
	Output                  string
}

type advanceFactory func(advanceOptions) (issueDeliveryAdvancer, error)

type advanceReviewContent struct {
	Reviews                 []issuedelivery.CandidateReview        `json:"reviews"`
	Specialists             []issuedelivery.SpecialistReview       `json:"specialist_reviews"`
	Acceptance              []issuedelivery.AcceptanceProof        `json:"acceptance_proofs"`
	QualificationReview     *issuedelivery.QualificationReview     `json:"qualification_review,omitempty"`
	QualificationCorrection *issuedelivery.QualificationCorrection `json:"qualification_correction,omitempty"`
}

type advanceCIFailureAttribution struct {
	CheckIdentity string                             `json:"check_identity"`
	RunID         int64                              `json:"run_id"`
	HeadSHA       string                             `json:"head_sha"`
	DetailsURL    string                             `json:"details_url"`
	Attribution   issuedelivery.CIFailureAttribution `json:"attribution"`
}

type advanceReport struct {
	RunID                    string                                        `json:"run_id"`
	State                    issuedelivery.State                           `json:"state"`
	Reason                   string                                        `json:"reason"`
	PauseCause               issuedelivery.PauseCause                      `json:"pause_cause"`
	NextAction               issuedelivery.NextAction                      `json:"next_action"`
	SupersedesRunID          string                                        `json:"supersedes_run_id,omitempty"`
	Decision                 *issuedelivery.DecisionRequest                `json:"decision,omitempty"`
	Repair                   *issuedelivery.RepairDecisionRequest          `json:"repair,omitempty"`
	QualificationCorrection  *issuedelivery.QualificationCorrectionRequest `json:"qualification_correction,omitempty"`
	QualificationApproved    bool                                          `json:"qualification_approved,omitempty"`
	QualificationReviews     []issuedelivery.QualificationReview           `json:"qualification_reviews,omitempty"`
	QualificationCorrections []issuedelivery.QualificationCorrection       `json:"qualification_corrections,omitempty"`
	Evidence                 *deliveryevidence.Bundle                      `json:"evidence,omitempty"`
	Observations             issuedelivery.Observations                    `json:"observations"`
	Candidate                *issuedelivery.Candidate                      `json:"candidate,omitempty"`
	LocalReadiness           *issuedelivery.LocalReadiness                 `json:"local_readiness,omitempty"`
	NonLocal                 *issuedelivery.NonLocalDelivery               `json:"non_local,omitempty"`
	Timing                   []issuedelivery.Timing                        `json:"timing"`
	TimingReport             issuedelivery.TimingReport                    `json:"timing_report"`
}

type compactAdvanceReport struct {
	RunID                   string                                        `json:"run_id"`
	State                   issuedelivery.State                           `json:"state"`
	Reason                  string                                        `json:"reason"`
	PauseCause              issuedelivery.PauseCause                      `json:"pause_cause"`
	NextAction              issuedelivery.NextAction                      `json:"next_action"`
	BlockerKind             issuedelivery.BlockerKind                     `json:"blocker_kind,omitempty"`
	SupersedesRunID         string                                        `json:"supersedes_run_id,omitempty"`
	Decision                *issuedelivery.DecisionRequest                `json:"decision,omitempty"`
	Repair                  *issuedelivery.RepairDecisionRequest          `json:"repair,omitempty"`
	QualificationCorrection *issuedelivery.QualificationCorrectionRequest `json:"qualification_correction,omitempty"`
	Candidate               *compactCandidateIdentity                     `json:"candidate,omitempty"`
	Branch                  *issuedelivery.RemoteBranchObservation        `json:"branch,omitempty"`
	PullRequest             *compactPullRequestIdentity                   `json:"pull_request,omitempty"`
	CI                      []compactCIIdentity                           `json:"ci,omitempty"`
	Merge                   *issuedelivery.MergeProof                     `json:"merge,omitempty"`
}

type compactCandidateIdentity struct {
	ID        string `json:"id"`
	CommitSHA string `json:"commit_sha"`
	TreeSHA   string `json:"tree_sha"`
}

type compactPullRequestIdentity struct {
	Number  int    `json:"number"`
	URL     string `json:"url"`
	HeadSHA string `json:"head_sha"`
}

type compactCIIdentity struct {
	Identity   string                     `json:"identity"`
	RunID      int64                      `json:"run_id"`
	Status     issuedelivery.CIStatusKind `json:"status"`
	Conclusion string                     `json:"conclusion,omitempty"`
	HeadSHA    string                     `json:"head_sha"`
	DetailsURL string                     `json:"details_url"`
}

const maxConvergentAdvanceTransitions = 32

func (c command) advance(ctx context.Context, args []string, stdout io.Writer) error {
	f := flag.NewFlagSet("deliveryevidence advance", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var options advanceOptions
	var profile, decisionPath, repairPath, reviewPath, ciAttributionPath string
	f.StringVar(&options.RepositoryPath, "repository", ".", "repository to observe")
	f.IntVar(&options.IssueNumber, "issue", 0, "approved Packy issue number")
	f.IntVar(&options.SpecificationNumber, "spec", 0, "approved governing specification issue number")
	f.StringVar(&profile, "risk-profile", string(deliveryevidence.RiskStandard), "declared low-risk, standard, or high-risk profile")
	f.StringVar(&decisionPath, "decision", "", "typed semantic qualification decision")
	f.StringVar(&repairPath, "repair", "", "typed finding adjudication and repair classification")
	f.StringVar(&reviewPath, "review-content", "", "candidate and specialist review content")
	f.StringVar(&ciAttributionPath, "ci-attribution", "", "typed attribution of exact failed CI runs")
	f.BoolVar(&options.AuthorizeRemote, "authorize-non-local", false, "authorize deterministic delivery effects after exact local readiness")
	f.BoolVar(&options.FullReport, "full-report", false, "emit the complete canonical JSON report")
	f.StringVar(&options.Output, "output", "json", "compact report format: json or text")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || options.IssueNumber <= 0 || strings.TrimSpace(options.RepositoryPath) == "" {
		return errors.New("issue and repository are required and positional arguments are forbidden")
	}
	if options.SpecificationNumber < 0 || options.SpecificationNumber == options.IssueNumber {
		return errors.New("specification must be a distinct positive issue number when supplied")
	}
	repositoryPath, err := filepath.Abs(options.RepositoryPath)
	if err != nil {
		return fmt.Errorf("resolve repository: %w", err)
	}
	options.RepositoryPath, err = filepath.EvalSymlinks(repositoryPath)
	if err != nil {
		return fmt.Errorf("resolve repository: %w", err)
	}
	options.RepositoryPath = filepath.Clean(options.RepositoryPath)
	options.DeclaredProfile = deliveryevidence.DeliveryRiskProfile(profile)
	if options.DeclaredProfile != deliveryevidence.RiskLow &&
		options.DeclaredProfile != deliveryevidence.RiskStandard &&
		options.DeclaredProfile != deliveryevidence.RiskHigh {
		return fmt.Errorf("risk profile %q is invalid", profile)
	}
	if err := decodeOptionalExactJSON(decisionPath, &options.Decision); err != nil {
		return fmt.Errorf("decode decision: %w", err)
	}
	if err := decodeOptionalExactJSON(repairPath, &options.Repair); err != nil {
		return fmt.Errorf("decode repair: %w", err)
	}
	if reviewPath != "" {
		var content advanceReviewContent
		if err := decodeExactJSONFile(reviewPath, &content); err != nil {
			return fmt.Errorf("decode review content: %w", err)
		}
		options.Reviews = content.Reviews
		options.Specialists = content.Specialists
		options.Acceptance = content.Acceptance
		options.QualificationReview = content.QualificationReview
		options.QualificationCorrection = content.QualificationCorrection
	}
	if ciAttributionPath != "" {
		if err := decodeExactJSONFile(ciAttributionPath, &options.CIFailureAttributions); err != nil {
			return fmt.Errorf("decode CI attribution: %w", err)
		}
		if options.CIFailureAttributions == nil {
			return errors.New("CI attribution requires an explicit array")
		}
	}
	if options.Decision != nil && options.Repair != nil {
		return errors.New("one Advance call cannot submit both a qualification decision and repair adjudication")
	}
	if options.Output != "json" && options.Output != "text" {
		return fmt.Errorf("output %q is invalid; use json or text", options.Output)
	}
	if options.FullReport && options.Output != "json" {
		return errors.New("full report is canonical JSON and cannot use text output")
	}
	if c.AdvanceFactory == nil {
		return errors.New("Advance adapter is unavailable")
	}
	advancer, err := c.AdvanceFactory(options)
	if err != nil {
		return fmt.Errorf("configure Advance: %w", err)
	}
	request := issuedelivery.Request{
		RepositoryPath:          options.RepositoryPath,
		IssueNumber:             options.IssueNumber,
		Decision:                options.Decision,
		Repair:                  options.Repair,
		QualificationReview:     options.QualificationReview,
		QualificationCorrection: options.QualificationCorrection,
	}
	outcome, err := convergeAdvance(ctx, advancer, request, options.AuthorizeRemote)
	if err != nil {
		return err
	}
	var report any
	if options.FullReport {
		report, err = reportFromOutcome(outcome, c.now())
	} else {
		report = compactReportFromOutcome(outcome)
	}
	if err != nil {
		return err
	}
	if options.Output == "text" {
		_, err = io.WriteString(stdout, renderCompactAdvanceReport(report.(compactAdvanceReport)))
		return err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	_, err = stdout.Write(raw)
	return err
}

func convergeAdvance(
	ctx context.Context,
	advancer issueDeliveryAdvancer,
	request issuedelivery.Request,
	authorizeRemote bool,
) (issuedelivery.Outcome, error) {
	authorizationAvailable := authorizeRemote
	seen := map[string]bool{}
	var last issuedelivery.Outcome
	for transition := 0; transition < maxConvergentAdvanceTransitions; transition++ {
		outcome, err := advancer.Advance(ctx, request)
		if err != nil {
			return issuedelivery.Outcome{}, err
		}
		last = outcome
		request.Decision, request.Repair = nil, nil
		request.QualificationReview, request.QualificationCorrection = nil, nil
		request.NonLocal = nil

		if authorizationAvailable &&
			outcome.PauseCause == issuedelivery.PauseNonLocalAuthorization &&
			outcome.NextAction == issuedelivery.ActionAuthorizeNonLocal &&
			outcome.LocalReadiness != nil && outcome.NonLocal == nil {
			request.NonLocal = nonLocalAuthorization(outcome)
			authorizationAvailable = false
			continue
		}
		if outcome.PauseCause != issuedelivery.PauseDeterministicAdvance {
			return outcome, nil
		}
		signature := advanceOutcomeSignature(outcome)
		if seen[signature] {
			return convergenceBlockedOutcome(outcome, "deterministic Advance repeated the same state signature"), nil
		}
		seen[signature] = true
	}
	return convergenceBlockedOutcome(
		last,
		fmt.Sprintf("deterministic Advance exceeded %d transitions", maxConvergentAdvanceTransitions),
	), nil
}

func advanceOutcomeSignature(outcome issuedelivery.Outcome) string {
	candidateID := ""
	if outcome.Candidate != nil {
		candidateID = outcome.Candidate.ID
	}
	remoteStage := ""
	if outcome.NonLocal != nil {
		switch {
		case outcome.NonLocal.Merge != nil:
			remoteStage = "merge:" + outcome.NonLocal.Merge.MergeCommitSHA
		case len(outcome.NonLocal.Checks) > 0:
			remoteStage = fmt.Sprintf("ci:%d", len(outcome.NonLocal.Checks))
		case outcome.NonLocal.PullRequest != nil:
			remoteStage = fmt.Sprintf("pr:%d", outcome.NonLocal.PullRequest.Number)
		case outcome.NonLocal.Branch != nil:
			remoteStage = "branch:" + outcome.NonLocal.Branch.HeadSHA
		default:
			remoteStage = "authorized"
		}
	}
	return strings.Join([]string{
		outcome.RunID, string(outcome.State), outcome.Reason, string(outcome.PauseCause),
		string(outcome.NextAction), candidateID, remoteStage,
	}, "\x00")
}

func convergenceBlockedOutcome(outcome issuedelivery.Outcome, reason string) issuedelivery.Outcome {
	outcome.State = issuedelivery.StateBlocked
	outcome.Reason = reason
	outcome.PauseCause = issuedelivery.PauseInvariantBlock
	outcome.NextAction = issuedelivery.ActionInspectBlockedTransition
	outcome.BlockerKind = issuedelivery.BlockerAdvanceConvergence
	return outcome
}

func compactReportFromOutcome(outcome issuedelivery.Outcome) compactAdvanceReport {
	report := compactAdvanceReport{
		RunID: outcome.RunID, State: outcome.State, Reason: outcome.Reason,
		PauseCause: outcome.PauseCause, NextAction: outcome.NextAction,
		BlockerKind: outcome.BlockerKind, SupersedesRunID: outcome.SupersedesRunID,
		Decision: outcome.Decision, Repair: outcome.Repair,
		QualificationCorrection: outcome.QualificationCorrection,
	}
	if outcome.BlockerKind != "" {
		return report
	}
	if remote := outcome.NonLocal; remote != nil {
		switch {
		case remote.Merge != nil:
			report.Merge = remote.Merge
		case len(remote.Checks) > 0:
			for _, check := range remote.Checks {
				report.CI = append(report.CI, compactCIIdentity{
					Identity: check.Identity, RunID: check.RunID, Status: check.StatusKind,
					Conclusion: check.Conclusion, HeadSHA: check.HeadSHA, DetailsURL: check.DetailsURL,
				})
			}
		case remote.PullRequest != nil:
			report.PullRequest = &compactPullRequestIdentity{
				Number: remote.PullRequest.Number, URL: remote.PullRequest.URL,
				HeadSHA: remote.PullRequest.HeadSHA,
			}
		default:
			if remote.Branch != nil {
				report.Branch = remote.Branch
			} else if outcome.LocalReadiness != nil {
				report.Branch = &issuedelivery.RemoteBranchObservation{
					Name:    outcome.LocalReadiness.Branch,
					HeadSHA: outcome.LocalReadiness.CommitSHA,
				}
			}
		}
		return report
	}
	if outcome.LocalReadiness != nil {
		report.Branch = &issuedelivery.RemoteBranchObservation{
			Name: outcome.LocalReadiness.Branch, HeadSHA: outcome.LocalReadiness.CommitSHA,
		}
		return report
	}
	if outcome.Candidate != nil {
		report.Candidate = &compactCandidateIdentity{
			ID: outcome.Candidate.ID, CommitSHA: outcome.Candidate.CommitSHA,
			TreeSHA: outcome.Candidate.TreeSHA,
		}
	}
	return report
}

func renderCompactAdvanceReport(report compactAdvanceReport) string {
	var out strings.Builder
	fmt.Fprintf(&out, "run: %s\nstate: %s\npause cause: %s\nnext action: %s\n",
		report.RunID, report.State, report.PauseCause, report.NextAction)
	if report.Reason != "" {
		fmt.Fprintf(&out, "reason: %s\n", report.Reason)
	}
	if report.BlockerKind != "" {
		fmt.Fprintf(&out, "blocker: %s\n", report.BlockerKind)
	}
	if report.Candidate != nil {
		fmt.Fprintf(&out, "candidate: %s commit=%s tree=%s\n",
			report.Candidate.ID, report.Candidate.CommitSHA, report.Candidate.TreeSHA)
	}
	if report.Branch != nil {
		fmt.Fprintf(&out, "branch: %s head=%s\n", report.Branch.Name, report.Branch.HeadSHA)
	}
	if report.PullRequest != nil {
		fmt.Fprintf(&out, "pull request: #%d %s head=%s\n",
			report.PullRequest.Number, report.PullRequest.URL, report.PullRequest.HeadSHA)
	}
	for _, check := range report.CI {
		fmt.Fprintf(&out, "ci: %s run=%d status=%s conclusion=%s head=%s %s\n",
			check.Identity, check.RunID, check.Status, check.Conclusion, check.HeadSHA, check.DetailsURL)
	}
	if report.Merge != nil {
		fmt.Fprintf(&out, "merge: pr=#%d commit=%s %s\n",
			report.Merge.PullRequest, report.Merge.MergeCommitSHA, report.Merge.URL)
	}
	return out.String()
}

func nonLocalAuthorization(outcome issuedelivery.Outcome) *issuedelivery.NonLocalAuthorization {
	readiness := outcome.LocalReadiness
	if readiness == nil || outcome.Candidate == nil {
		return nil
	}
	return &issuedelivery.NonLocalAuthorization{
		RunID: outcome.RunID, CandidateID: readiness.CandidateID,
		CommitSHA: readiness.CommitSHA, TreeSHA: readiness.TreeSHA,
		Branch: readiness.Branch, LocalReadyAt: readiness.ReadyAt,
	}
}

func reportFromOutcome(outcome issuedelivery.Outcome, now time.Time) (advanceReport, error) {
	timingReport, err := issuedelivery.BuildTimingReport(outcome.Timing, now)
	if err != nil {
		return advanceReport{}, fmt.Errorf("build timing report: %w", err)
	}
	return advanceReport{
		RunID: outcome.RunID, State: outcome.State, Reason: outcome.Reason,
		PauseCause: outcome.PauseCause, NextAction: outcome.NextAction,
		SupersedesRunID: outcome.SupersedesRunID, Decision: outcome.Decision,
		Repair: outcome.Repair, Evidence: outcome.Evidence, Observations: outcome.Observations,
		QualificationCorrection:  outcome.QualificationCorrection,
		QualificationApproved:    outcome.QualificationApproved,
		QualificationReviews:     outcome.QualificationReviews,
		QualificationCorrections: outcome.QualificationCorrections,
		Candidate:                outcome.Candidate, LocalReadiness: outcome.LocalReadiness,
		NonLocal: outcome.NonLocal, Timing: outcome.Timing, TimingReport: timingReport,
	}, nil
}

func decodeOptionalExactJSON[T any](path string, target **T) error {
	if path == "" {
		return nil
	}
	var value T
	if err := decodeExactJSONFile(path, &value); err != nil {
		return err
	}
	*target = &value
	return nil
}

func decodeExactJSONFile(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return errors.New("input must contain exactly one JSON value")
	}
	return nil
}
