package issuedelivery

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

const inputPlaceholder = "REQUIRED: replace this placeholder"

// MaterializeInputTemplate returns one draft for the exact current semantic-input
// request without advancing or rewriting the run.
func (m *Module) MaterializeInputTemplate(
	ctx context.Context,
	request InputTemplateRequest,
) (InputTemplate, error) {
	if ctx == nil {
		return InputTemplate{}, errors.New("MaterializeInputTemplate requires a context")
	}
	if request.IssueNumber <= 0 || strings.TrimSpace(request.RepositoryPath) == "" {
		return InputTemplate{}, errors.New(
			"MaterializeInputTemplate requires a repository path and positive issue number",
		)
	}
	expectedAction, ok := inputTemplateAction(request.Kind)
	if !ok {
		return InputTemplate{}, fmt.Errorf("input template kind %q is invalid", request.Kind)
	}
	git, err := m.git.ObserveGit(ctx, request.RepositoryPath)
	if err != nil {
		return InputTemplate{}, fmt.Errorf("observe Git: %w", err)
	}

	var template InputTemplate
	err = m.store.observeIssue(ctx, git.CommonDir, request.IssueNumber, func(store lockedIssueStore) error {
		activeID, activeData, found, err := store.loadActive()
		if err != nil {
			return err
		}
		if !found {
			return errors.New("active issue delivery run does not exist")
		}
		active, err := decodeRun(activeData)
		if err != nil {
			return err
		}
		if active.ID != activeID {
			return errors.New("active issue delivery run identity does not match its selector")
		}
		if active.Schema != runSchema {
			return errors.New("schema v1 issue delivery input requires the explicit legacy-v1 workflow")
		}
		if active.Issue.Number != request.IssueNumber ||
			active.Repository.Owner != git.Owner || active.Repository.Name != git.Name {
			return errors.New("active issue delivery run identity does not match requested repository and issue")
		}

		tracker, err := m.github.ObserveIssue(ctx, git, request.IssueNumber)
		if err != nil {
			return fmt.Errorf("observe GitHub issue: %w", err)
		}
		if tracker.Issue.Number != request.IssueNumber {
			return fmt.Errorf(
				"GitHub observer returned issue #%d for requested issue #%d",
				tracker.Issue.Number,
				request.IssueNumber,
			)
		}
		if active.Repository != tracker.Repository || active.Issue != tracker.Issue {
			return errors.New("active issue delivery run identity does not match current repository and issue")
		}
		compiled, err := compileAuthority(
			git, tracker, active.Decisions, nil, m.declaredProfile, active.DeliveryProfile != nil,
		)
		if err != nil {
			return fmt.Errorf("active semantic-input request is stale: %w", err)
		}
		if active.AuthoritySHA256 != compiled.hash {
			return errors.New("active semantic-input request is stale because current authority changed")
		}

		outcome := outcomeWithPause(outcomeFromRecord(active))
		if err := validateInputTemplateAction(request.Kind, expectedAction, outcome); err != nil {
			return err
		}
		if (request.Kind == InputTemplateRepair || request.Kind == InputTemplateCIAttribution) &&
			(outcome.Candidate == nil ||
				outcome.Candidate.CommitSHA != git.HeadSHA ||
				outcome.Candidate.TreeSHA != git.TreeSHA) {
			return errors.New("active semantic-input request is stale because the current Git checkout changed")
		}
		if request.Kind == InputTemplateCIAttribution {
			if err := m.validateCurrentCIAttributionRequest(ctx, active); err != nil {
				return err
			}
		}
		template, err = inputTemplateFromOutcome(request.Kind, outcome)
		return err
	})
	if errors.Is(err, errIssueRunActive) {
		return InputTemplate{}, errors.New("another Advance call is active for this issue")
	}
	if err != nil {
		return InputTemplate{}, err
	}
	return template, nil
}

func (m *Module) validateCurrentCIAttributionRequest(ctx context.Context, active runRecord) error {
	if m.nonlocalObserver == nil {
		return errors.New("current CI attribution requires a configured non-local observer")
	}
	if active.NonLocal == nil || active.NonLocal.PullRequest == nil {
		return errors.New("current CI attribution request lacks exact non-local identity")
	}
	authorization := active.NonLocal.Authorization
	fresh, err := m.nonlocalObserver.ObserveNonLocal(ctx, NonLocalObserveRequest{
		RunID: active.ID, Repository: active.Repository, Issue: active.Issue,
		CandidateID: authorization.CandidateID, Branch: authorization.Branch,
		BaseRef: active.NonLocal.BaseRef, HeadSHA: authorization.CommitSHA,
	})
	if err != nil {
		return fmt.Errorf("reobserve current CI attribution request: %w", err)
	}
	selected, err := selectExactPullRequest(
		fresh.PullRequests,
		active.Repository,
		active.Issue.Number,
		authorization.Branch,
		authorization.CommitSHA,
	)
	if err != nil || selected == nil ||
		fresh.Branch == nil || active.NonLocal.Branch == nil ||
		*fresh.Branch != *active.NonLocal.Branch ||
		!equalRemotePullRequest(*selected, *active.NonLocal.PullRequest) ||
		fresh.Merge != nil ||
		!equalCICheckObservations(
			currentInputTemplateChecks(fresh.Checks),
			currentInputTemplateChecks(active.NonLocal.Checks),
		) {
		return errors.New("active CI attribution request is stale because current remote observations changed")
	}
	return nil
}

func currentInputTemplateChecks(checks []CICheckObservation) []CICheckObservation {
	current := canonicalCICheckObservations(checks)
	for index := range current {
		if current[index].FailureAttribution == FailureUnknown {
			current[index].FailureAttribution = ""
		}
	}
	return current
}

func validateInputTemplateAction(
	kind InputTemplateKind,
	expectedAction NextAction,
	outcome Outcome,
) error {
	if outcome.NextAction != expectedAction {
		return fmt.Errorf(
			"input template kind %q does not match current pending action %q",
			kind,
			outcome.NextAction,
		)
	}
	return nil
}

func inputTemplateAction(kind InputTemplateKind) (NextAction, bool) {
	action, ok := inputTemplateActions[kind]
	return action, ok
}

var inputTemplateActions = map[InputTemplateKind]NextAction{
	InputTemplateDecision:                ActionProvideDecision,
	InputTemplateQualificationReview:     ActionProvideQualificationReview,
	InputTemplateQualificationCorrection: ActionProvideQualificationCorrection,
	InputTemplateRepair:                  ActionProvideRepairDecision,
	InputTemplateCIAttribution:           ActionProvideCIAttribution,
}

func inputTemplateFromOutcome(kind InputTemplateKind, outcome Outcome) (InputTemplate, error) {
	switch kind {
	case InputTemplateDecision:
		if outcome.Decision == nil {
			return InputTemplate{}, errors.New("current decision request is absent")
		}
		return InputTemplate{Decision: &Decision{
			RequestID:    outcome.Decision.ID,
			Disposition:  DecisionDisposition(inputPlaceholder),
			Requirement:  inputPlaceholder,
			EvidenceLink: inputPlaceholder,
		}}, nil
	case InputTemplateQualificationReview:
		if outcome.Evidence == nil {
			return InputTemplate{}, errors.New("current qualification evidence is absent")
		}
		matrixHash, err := acceptanceMatrixDigest(outcome.Evidence.AcceptanceMatrix)
		if err != nil {
			return InputTemplate{}, fmt.Errorf("digest current acceptance matrix: %w", err)
		}
		return InputTemplate{QualificationReview: &QualificationReview{
			AuthoritySHA256:        outcome.Observations.AuthoritySHA256,
			AcceptanceMatrixSHA256: matrixHash,
			Findings: []deliveryevidence.ReviewFinding{{
				ID:        inputPlaceholder,
				Axis:      deliveryevidence.ReviewAxis(inputPlaceholder),
				Severity:  deliveryevidence.FindingSeverity(inputPlaceholder),
				Authority: deliveryevidence.FindingAuthority(inputPlaceholder),
				Citation:  inputPlaceholder,
				Location:  inputPlaceholder,
				Evidence:  inputPlaceholder,
			}},
			Completed: false,
		}}, nil
	case InputTemplateQualificationCorrection:
		pending := outcome.QualificationCorrection
		if pending == nil || outcome.Evidence == nil {
			return InputTemplate{}, errors.New("current qualification correction request is absent")
		}
		rows := append([]deliveryevidence.AcceptanceRow(nil), outcome.Evidence.AcceptanceMatrix...)
		for index := range rows {
			rows[index].OwningSeam = inputPlaceholder
			rows[index].PositiveEvidence = inputPlaceholder
			rows[index].NegativeEvidence = inputPlaceholder
			rows[index].FailureEvidence = inputPlaceholder
			rows[index].MutationEvidence = inputPlaceholder
			rows[index].CompatibilityEvidence = inputPlaceholder
			rows[index].PreservationEvidence = inputPlaceholder
			rows[index].MigrationEvidence = inputPlaceholder
			rows[index].State = deliveryevidence.AcceptanceState(inputPlaceholder)
		}
		return InputTemplate{QualificationCorrection: &QualificationCorrection{
			RequestID:            pending.ID,
			AuthoritySHA256:      pending.AuthoritySHA256,
			ReviewedMatrixSHA256: pending.ReviewedMatrixSHA256,
			FindingIDs:           append([]string(nil), pending.FindingIDs...),
			AcceptanceMatrix:     rows,
			Evidence:             inputPlaceholder,
		}}, nil
	case InputTemplateRepair:
		pending := outcome.Repair
		if pending == nil {
			return InputTemplate{}, errors.New("current repair decision request is absent")
		}
		findings := make([]FindingDecision, 0, len(pending.FindingIDs))
		for _, id := range pending.FindingIDs {
			findings = append(findings, FindingDecision{
				FindingID: id, Disposition: FindingDisposition(inputPlaceholder), Evidence: inputPlaceholder,
			})
		}
		return InputTemplate{Repair: &RepairDecision{
			CandidateID: pending.CandidateID,
			Class:       RepairClass(inputPlaceholder),
			Findings:    findings,
		}}, nil
	case InputTemplateCIAttribution:
		if outcome.NonLocal == nil {
			return InputTemplate{}, errors.New("current CI failure observations are absent")
		}
		attributions := make([]CIFailureAttributionInput, 0)
		for _, check := range outcome.NonLocal.Checks {
			conclusion := strings.ToLower(strings.TrimSpace(check.Conclusion))
			if (check.FailureAttribution == "" || check.FailureAttribution == FailureUnknown) &&
				(conclusion == "failure" || conclusion == "failed" || conclusion == "cancelled") {
				attributions = append(attributions, CIFailureAttributionInput{
					CheckIdentity: check.Identity,
					RunID:         check.RunID,
					HeadSHA:       check.HeadSHA,
					DetailsURL:    check.DetailsURL,
					Attribution:   CIFailureAttribution(inputPlaceholder),
				})
			}
		}
		if len(attributions) == 0 {
			return InputTemplate{}, errors.New("current CI attribution request has no failed checks")
		}
		return InputTemplate{CIAttributions: attributions}, nil
	default:
		return InputTemplate{}, fmt.Errorf("input template kind %q is invalid", kind)
	}
}
