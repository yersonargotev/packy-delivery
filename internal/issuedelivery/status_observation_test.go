package issuedelivery

import (
	"errors"
	"strings"
	"testing"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

func TestStatusObservationDetectsCurrentWorktreeWithoutChangingPersistedFacts(t *testing.T) {
	record := runRecord{
		Observations: Observations{
			CommitSHA: strings.Repeat("a", 40),
			TreeSHA:   strings.Repeat("b", 40),
		},
	}
	current := GitObservation{
		HeadSHA: strings.Repeat("c", 40),
		TreeSHA: strings.Repeat("d", 40),
	}
	observation, err := statusObservationFrom(record, current, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Changed ||
		observation.Persisted.Kind != StatusIdentityWorktree ||
		observation.Current.Kind != StatusIdentityWorktree ||
		!strings.Contains(observation.Persisted.Value, strings.Repeat("a", 40)) ||
		!strings.Contains(observation.Current.Value, strings.Repeat("c", 40)) {
		t.Fatalf("observation=%#v", observation)
	}
	if record.Observations.CommitSHA != strings.Repeat("a", 40) {
		t.Fatalf("persisted record changed: %#v", record.Observations)
	}
}

func TestStatusObservationUsesStableOrderIndependentCIDigest(t *testing.T) {
	left := []CICheckObservation{
		{
			RequiredCheck: deliveryCheck("second", "success", strings.Repeat("a", 40)),
			StatusKind:    CIKindCheckRun,
			RunID:         2,
		},
		{
			RequiredCheck: deliveryCheck("first", "", strings.Repeat("a", 40)),
			StatusKind:    CIKindCheckRun,
			RunID:         1,
		},
	}
	right := []CICheckObservation{left[1], left[0]}
	leftIdentity := checksStatusIdentity(left)
	rightIdentity := checksStatusIdentity(right)
	if leftIdentity != rightIdentity || leftIdentity.Kind != StatusIdentityCI ||
		leftIdentity.Count != 2 {
		t.Fatalf("left=%#v right=%#v", leftIdentity, rightIdentity)
	}
	right[1].Conclusion = "failure"
	if checksStatusIdentity(right) == leftIdentity {
		t.Fatal("changed CI conclusion retained the same identity")
	}
}

func TestStatusObservationRejectsIncompleteNonLocalFacts(t *testing.T) {
	candidate := Candidate{
		ID: "candidate", CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
	}
	record := runRecord{
		Candidates: []Candidate{candidate},
		LocalReadiness: &LocalReadiness{
			Branch: "feat/issue-29-watch", CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
		},
		NonLocal: &NonLocalDelivery{
			Authorization: NonLocalAuthorization{Branch: "feat/issue-29-watch"},
			Checks:        []CICheckObservation{},
		},
	}
	_, err := statusObservationFrom(
		record,
		GitObservation{},
		&NonLocalObservation{PullRequests: nil, Checks: []CICheckObservation{}},
	)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("error=%v", err)
	}
}

func TestStatusErrorDetailsPreservesBoundedRetryPolicy(t *testing.T) {
	cause := errors.New("temporary")
	err := NewStatusError(StatusErrorGitHubRead, true, cause)
	class, transient, ok := StatusErrorDetails(err)
	if !ok || !transient || class != StatusErrorGitHubRead || !errors.Is(err, cause) {
		t.Fatalf("class=%q transient=%t ok=%t err=%v", class, transient, ok, err)
	}
	if _, _, ok := StatusErrorDetails(errors.New("untyped")); ok {
		t.Fatal("untyped error acquired retry policy")
	}
}

func deliveryCheck(name, conclusion, head string) deliveryevidence.RequiredCheck {
	return deliveryevidence.RequiredCheck{
		Identity: name, Conclusion: conclusion, HeadSHA: head,
	}
}
