package issuedelivery

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStatusObservesPersistedRunOnceWithoutWritingStore(t *testing.T) {
	module, git, tracker := moduleFixture(t, 356)
	request := Request{RepositoryPath: "/repo", IssueNumber: 356}
	created, err := module.Advance(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotRegularFiles(t, git.value.CommonDir)
	git.mu.Lock()
	git.calls = 0
	git.mu.Unlock()
	tracker.mu.Lock()
	tracker.calls = 0
	tracker.mu.Unlock()

	status, err := module.Status(context.Background(), StatusRequest{
		RepositoryPath: request.RepositoryPath,
		IssueNumber:    request.IssueNumber,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.RunID != created.RunID || status.State != created.State ||
		status.PauseCause != created.PauseCause || status.NextAction != created.NextAction {
		t.Fatalf("status = %#v, created = %#v", status, created)
	}
	if status.StatusObservation == nil || status.StatusObservation.Changed {
		t.Fatalf("current status observation = %#v", status.StatusObservation)
	}
	git.mu.Lock()
	gitCalls := git.calls
	git.mu.Unlock()
	tracker.mu.Lock()
	trackerCalls := tracker.calls
	tracker.mu.Unlock()
	if gitCalls != 1 || trackerCalls != 1 {
		t.Fatalf("observation calls: Git=%d GitHub=%d, want one each", gitCalls, trackerCalls)
	}
	after := snapshotRegularFiles(t, git.value.CommonDir)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("Status changed run store:\nbefore=%v\nafter=%v", before, after)
	}
}

func TestStatusProjectsFreshWorktreeIdentityWithoutAdoptingIt(t *testing.T) {
	module, git, _ := moduleFixture(t, 356)
	created, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
	})
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotRegularFiles(t, git.value.CommonDir)
	git.mu.Lock()
	git.value.HeadSHA = strings.Repeat("8", 40)
	git.value.TreeSHA = strings.Repeat("9", 40)
	git.value.WorkspaceClean = true
	git.mu.Unlock()

	status, err := module.Status(context.Background(), StatusRequest{
		RepositoryPath: "/repo", IssueNumber: 356,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.RunID != created.RunID || status.StatusObservation == nil ||
		!status.StatusObservation.Changed ||
		!strings.Contains(status.StatusObservation.Current.Value, strings.Repeat("8", 40)) ||
		status.Observations.CommitSHA == strings.Repeat("8", 40) {
		t.Fatalf("status=%#v", status)
	}
	after := snapshotRegularFiles(t, git.value.CommonDir)
	if !reflect.DeepEqual(after, before) {
		t.Fatal("fresh worktree projection changed persisted run bytes")
	}
}

func TestStatusReportsLockContentionWithoutObservingAuthorityOrWriting(t *testing.T) {
	module, git, tracker := moduleFixture(t, 356)
	if _, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
	}); err != nil {
		t.Fatal(err)
	}
	before := snapshotRegularFiles(t, git.value.CommonDir)
	tracker.mu.Lock()
	tracker.calls = 0
	tracker.mu.Unlock()

	err := module.store.withIssueLock(
		context.Background(),
		git.value.CommonDir,
		356,
		func(lockedIssueStore) error {
			status, statusErr := module.Status(context.Background(), StatusRequest{
				RepositoryPath: "/repo",
				IssueNumber:    356,
			})
			if statusErr != nil {
				return statusErr
			}
			if status.State != StateWaiting || status.PauseCause != PauseLockContention ||
				status.NextAction != ActionRetryAdvance ||
				status.StatusObservation == nil ||
				status.StatusObservation.Current.Kind != StatusIdentityLock {
				t.Fatalf("lock-contended status = %#v", status)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	tracker.mu.Lock()
	trackerCalls := tracker.calls
	tracker.mu.Unlock()
	if trackerCalls != 0 {
		t.Fatalf("lock-contended Status made %d GitHub observations, want 0", trackerCalls)
	}
	after := snapshotRegularFiles(t, git.value.CommonDir)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("lock-contended Status changed run store")
	}
}

func TestStatusFailsForMissingCorruptAndMismatchedRuns(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		module, _, _ := moduleFixture(t, 356)
		if _, err := module.Status(context.Background(), StatusRequest{
			RepositoryPath: "/repo", IssueNumber: 356,
		}); err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("missing run error = %v", err)
		} else if class, transient, ok := StatusErrorDetails(err); !ok ||
			transient || class != StatusErrorRunState {
			t.Fatalf("missing run classification = %q transient=%t ok=%t", class, transient, ok)
		}
	})

	t.Run("mismatched identity", func(t *testing.T) {
		module, _, tracker := moduleFixture(t, 356)
		if _, err := module.Advance(context.Background(), Request{
			RepositoryPath: "/repo", IssueNumber: 356,
		}); err != nil {
			t.Fatal(err)
		}
		tracker.mu.Lock()
		tracker.value.Repository.NodeID = "replacement-repository"
		tracker.mu.Unlock()
		if _, err := module.Status(context.Background(), StatusRequest{
			RepositoryPath: "/repo", IssueNumber: 356,
		}); err == nil || !strings.Contains(err.Error(), "identity does not match") {
			t.Fatalf("mismatched run error = %v", err)
		} else if class, transient, ok := StatusErrorDetails(err); !ok ||
			transient || class != StatusErrorAuthority {
			t.Fatalf("mismatch classification = %q transient=%t ok=%t", class, transient, ok)
		}
	})

	t.Run("corrupt", func(t *testing.T) {
		module, git, _ := moduleFixture(t, 356)
		created, err := module.Advance(context.Background(), Request{
			RepositoryPath: "/repo", IssueNumber: 356,
		})
		if err != nil {
			t.Fatal(err)
		}
		runPath := filepath.Join(
			git.value.CommonDir, "packy", "issue-delivery", "issue-356", "runs", created.RunID+".json",
		)
		if err := os.WriteFile(runPath, []byte(`{"schema":"corrupt"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := module.Status(context.Background(), StatusRequest{
			RepositoryPath: "/repo", IssueNumber: 356,
		}); err == nil {
			t.Fatal("corrupt run was observed successfully")
		}
	})
}

func TestStatusRefusesLegacyRunWithoutImplicitMigration(t *testing.T) {
	module, git, tracker := moduleFixture(t, 356)
	tracker.mu.Lock()
	tracker.value.Ambiguities = []AuthorityItem{{
		Text: "Choose one explicit scope.", EvidenceLink: "issue#356:ambiguity-1",
	}}
	tracker.mu.Unlock()
	if _, err := module.Advance(context.Background(), Request{
		RepositoryPath: "/repo", IssueNumber: 356,
	}); err != nil {
		t.Fatal(err)
	}
	err := module.store.withIssueLock(
		context.Background(),
		git.value.CommonDir,
		356,
		func(store lockedIssueStore) error {
			runID, data, found, err := store.loadActive()
			if err != nil || !found {
				return err
			}
			record, err := decodeRun(data)
			if err != nil {
				return err
			}
			record.Schema = legacyRunSchema
			record.EffectiveProfile = ""
			legacy, err := encodeRun(record)
			if err != nil {
				return err
			}
			_, err = store.storeRevisionAndActivate(runID, legacy)
			return err
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := module.Status(context.Background(), StatusRequest{
		RepositoryPath: "/repo", IssueNumber: 356,
	}); err == nil || !strings.Contains(err.Error(), "explicit legacy-v1") {
		t.Fatalf("legacy run status error = %v", err)
	}
}

func snapshotRegularFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[path] = bytes.Clone(raw)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
