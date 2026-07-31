package issuedelivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

type StatusIdentityKind string

const (
	StatusIdentityWorktree    StatusIdentityKind = "worktree"
	StatusIdentityBranch      StatusIdentityKind = "branch"
	StatusIdentityPullRequest StatusIdentityKind = "pull-request"
	StatusIdentityCI          StatusIdentityKind = "ci"
	StatusIdentityMerge       StatusIdentityKind = "merge"
	StatusIdentityLock        StatusIdentityKind = "lock"
)

type StatusRelevantIdentity struct {
	Kind  StatusIdentityKind `json:"kind"`
	Value string             `json:"value"`
	Count int                `json:"count,omitempty"`
}

type StatusObservation struct {
	Persisted StatusRelevantIdentity `json:"persisted"`
	Current   StatusRelevantIdentity `json:"current"`
	Changed   bool                   `json:"changed"`
}

type StatusErrorClass string

const (
	StatusErrorGitRead      StatusErrorClass = "git-read"
	StatusErrorGitHubRead   StatusErrorClass = "github-read"
	StatusErrorExternalRead StatusErrorClass = "external-read"
	StatusErrorIdentity     StatusErrorClass = "identity"
	StatusErrorAuthority    StatusErrorClass = "authority"
	StatusErrorCorruption   StatusErrorClass = "corruption"
	StatusErrorRunState     StatusErrorClass = "run-state"
	StatusErrorLegacy       StatusErrorClass = "legacy"
)

type StatusError struct {
	Class     StatusErrorClass
	Transient bool
	err       error
}

func (e *StatusError) Error() string { return e.err.Error() }
func (e *StatusError) Unwrap() error { return e.err }

func NewStatusError(class StatusErrorClass, transient bool, err error) error {
	if err == nil {
		return nil
	}
	return &StatusError{Class: class, Transient: transient, err: err}
}

func StatusErrorDetails(err error) (class StatusErrorClass, transient, ok bool) {
	var statusError *StatusError
	if !errors.As(err, &statusError) {
		return "", false, false
	}
	return statusError.Class, statusError.Transient, true
}

func statusObservationFrom(
	record runRecord,
	git GitObservation,
	currentNonLocal *NonLocalObservation,
) (StatusObservation, error) {
	if record.NonLocal == nil {
		persisted := worktreeStatusIdentity(
			record.Observations.CommitSHA,
			record.Observations.TreeSHA,
			record.Observations.WorkspaceClean,
		)
		current := worktreeStatusIdentity(git.HeadSHA, git.TreeSHA, git.WorkspaceClean)
		return StatusObservation{Persisted: persisted, Current: current, Changed: current != persisted}, nil
	}
	candidate := latestCandidate(&record)
	if candidate == nil || record.LocalReadiness == nil {
		return StatusObservation{}, errors.New("non-local status lacks current candidate readiness")
	}
	fallback := worktreeStatusIdentity(candidate.CommitSHA, candidate.TreeSHA, true)
	persisted := persistedNonLocalStatusIdentity(*record.NonLocal, fallback)
	if currentNonLocal == nil {
		return StatusObservation{Persisted: persisted, Current: persisted}, nil
	}
	current, err := currentNonLocalStatusIdentity(record, *candidate, *currentNonLocal, fallback)
	if err != nil {
		return StatusObservation{}, err
	}
	return StatusObservation{Persisted: persisted, Current: current, Changed: current != persisted}, nil
}

func worktreeStatusIdentity(commit, tree string, clean bool) StatusRelevantIdentity {
	return StatusRelevantIdentity{
		Kind:  StatusIdentityWorktree,
		Value: fmt.Sprintf("commit=%s;tree=%s;clean=%t", commit, tree, clean),
	}
}

func persistedNonLocalStatusIdentity(
	nonLocal NonLocalDelivery,
	fallback StatusRelevantIdentity,
) StatusRelevantIdentity {
	switch {
	case nonLocal.Merge != nil:
		return mergeStatusIdentity(
			nonLocal.Merge.PullRequest,
			nonLocal.Merge.HeadSHA,
			nonLocal.Merge.MergeCommitSHA,
		)
	case len(nonLocal.Checks) > 0:
		return checksStatusIdentity(nonLocal.Checks)
	case nonLocal.PullRequest != nil:
		return pullRequestStatusIdentity(*nonLocal.PullRequest)
	case nonLocal.Branch != nil:
		return branchStatusIdentity(*nonLocal.Branch)
	default:
		return fallback
	}
}

func currentNonLocalStatusIdentity(
	record runRecord,
	candidate Candidate,
	observation NonLocalObservation,
	fallback StatusRelevantIdentity,
) (StatusRelevantIdentity, error) {
	if observation.PullRequests == nil || observation.Checks == nil {
		return StatusRelevantIdentity{}, errors.New("non-local status observation is incomplete")
	}
	pullRequest, err := selectExactPullRequest(
		observation.PullRequests,
		record.Repository,
		record.Issue.Number,
		record.LocalReadiness.Branch,
		candidate.CommitSHA,
	)
	if err != nil {
		return StatusRelevantIdentity{}, err
	}
	if observation.Merge != nil {
		if pullRequest == nil ||
			observation.Merge.PullRequest != pullRequest.Number ||
			observation.Merge.HeadSHA != pullRequest.HeadSHA {
			return StatusRelevantIdentity{}, errors.New(
				"merged pull-request identity is incompatible with current delivery",
			)
		}
		return mergeStatusIdentity(
			observation.Merge.PullRequest,
			observation.Merge.HeadSHA,
			observation.Merge.MergeCommitSHA,
		), nil
	}
	if len(observation.Checks) > 0 {
		if pullRequest == nil {
			return StatusRelevantIdentity{}, errors.New(
				"CI observation lacks the exact current pull request",
			)
		}
		return checksStatusIdentity(observation.Checks), nil
	}
	if pullRequest != nil {
		return pullRequestStatusIdentity(*pullRequest), nil
	}
	if observation.Branch != nil {
		return branchStatusIdentity(*observation.Branch), nil
	}
	return fallback, nil
}

func branchStatusIdentity(branch RemoteBranchObservation) StatusRelevantIdentity {
	return StatusRelevantIdentity{
		Kind: StatusIdentityBranch, Value: branch.Name + "@" + branch.HeadSHA,
	}
}

func pullRequestStatusIdentity(pullRequest RemotePullRequestObservation) StatusRelevantIdentity {
	return StatusRelevantIdentity{
		Kind: StatusIdentityPullRequest,
		Value: fmt.Sprintf(
			"number=%d;state=%s;base=%s;head=%s",
			pullRequest.Number,
			pullRequest.State,
			pullRequest.BaseSHA,
			pullRequest.HeadSHA,
		),
	}
}

func mergeStatusIdentity(
	pullRequest int,
	headSHA, mergeCommitSHA string,
) StatusRelevantIdentity {
	return StatusRelevantIdentity{
		Kind: StatusIdentityMerge,
		Value: fmt.Sprintf(
			"number=%d;head=%s;merge=%s",
			pullRequest,
			headSHA,
			mergeCommitSHA,
		),
	}
}

func checksStatusIdentity(checks []CICheckObservation) StatusRelevantIdentity {
	type identity struct {
		Name       string       `json:"name"`
		RunID      int64        `json:"run_id"`
		Status     CIStatusKind `json:"status"`
		Conclusion string       `json:"conclusion"`
		HeadSHA    string       `json:"head_sha"`
	}
	values := make([]identity, len(checks))
	for index, check := range checks {
		values[index] = identity{
			Name: check.Identity, RunID: check.RunID, Status: check.StatusKind,
			Conclusion: check.Conclusion, HeadSHA: check.HeadSHA,
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Name == values[j].Name {
			return values[i].RunID < values[j].RunID
		}
		return values[i].Name < values[j].Name
	})
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(raw)
	return StatusRelevantIdentity{
		Kind: StatusIdentityCI, Value: hex.EncodeToString(sum[:]), Count: len(values),
	}
}
