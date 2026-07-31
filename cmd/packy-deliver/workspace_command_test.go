package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspacePrepareCreatesCleanIsolatedRepositoryWithoutChangingSource(t *testing.T) {
	root := t.TempDir()
	sandboxWorkspaceEnvironment(t)

	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	runWorkspaceGit(t, source, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(source, "tracked.txt"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runWorkspaceGit(t, source, "add", "tracked.txt")
	runWorkspaceGit(t, source, "-c", "user.name=Packy Test", "-c", "user.email=packy@example.test", "commit", "-m", "base")
	runWorkspaceGit(t, source, "remote", "add", "origin", "git@github.com:yersonargotev/packy.git")
	runWorkspaceGit(t, source, "update-ref", "refs/remotes/origin/main", "HEAD")
	base := workspaceGitOutput(t, source, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(source, "tracked.txt"), []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "staged.txt"), []byte("staged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runWorkspaceGit(t, source, "add", "staged.txt")
	if err := os.WriteFile(filepath.Join(source, "untracked.txt"), []byte("untracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := observeWorkspaceSource(t, source)

	destination := filepath.Join(root, "integration")
	var stdout bytes.Buffer
	runner := &recordingRunner{delegate: execRunner{}}
	err := (command{Git: runner}).run(context.Background(), []string{
		"workspace", "prepare",
		"--source", source,
		"--issue", "43",
		"--branch-kind", "feat",
		"--destination", destination,
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	if after := observeWorkspaceSource(t, source); after != before {
		t.Fatalf("source changed\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if got := workspaceGitOutput(t, destination, "symbolic-ref", "--short", "HEAD"); got != "feat/issue-43-workspace" {
		t.Fatalf("branch=%q", got)
	}
	if got := workspaceGitOutput(t, destination, "rev-parse", "HEAD"); got != base {
		t.Fatalf("HEAD=%q want %q", got, base)
	}
	for _, ref := range []string{"refs/heads/main", "refs/remotes/origin/main"} {
		if got := workspaceGitOutput(t, destination, "rev-parse", ref); got != base {
			t.Errorf("%s=%q want %q", ref, got, base)
		}
	}
	if sameFilesystemPath(
		workspaceGitOutput(t, source, "rev-parse", "--path-format=absolute", "--git-common-dir"),
		workspaceGitOutput(t, destination, "rev-parse", "--path-format=absolute", "--git-common-dir"),
	) {
		t.Fatal("prepared repository shares the source Git common directory")
	}
	if got := workspaceGitOutput(t, destination, "status", "--porcelain=v1", "--untracked-files=all"); got != "" {
		t.Fatalf("prepared workspace is dirty: %q", got)
	}
	for key, want := range map[string]string{
		"packy.delivery-prepared":          "true",
		"packy.delivery-source-common-dir": workspaceGitOutput(t, source, "rev-parse", "--path-format=absolute", "--git-common-dir"),
		"packy.delivery-issue":             "43",
		"packy.delivery-branch":            "feat/issue-43-workspace",
	} {
		if got := workspaceGitOutput(t, destination, "config", "--local", "--get", key); got != want {
			t.Errorf("%s=%q want %q", key, got, want)
		}
	}
	if got := workspaceGitOutput(t, destination, "remote", "get-url", "origin"); got != "git@github.com:yersonargotev/packy.git" {
		t.Fatalf("origin=%q", got)
	}
	if !strings.Contains(stdout.String(), destination) || !strings.Contains(stdout.String(), "feat/issue-43-workspace") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	for _, call := range runner.calls {
		if strings.Contains(" "+call+" ", " push ") || strings.Contains(call, "git fetch origin") {
			t.Fatalf("non-local Git effect: %s", call)
		}
	}
	if !slicesContainSubstring(runner.calls, " fetch --quiet --no-tags "+source+" ") {
		t.Fatalf("workspace was not seeded from the local source: %v", runner.calls)
	}
}

func TestWorkspacePrepareRejectsUnsafeDestinationsBeforeMutation(t *testing.T) {
	sandboxWorkspaceEnvironment(t)
	root := t.TempDir()
	source := prepareWorkspaceSource(t, filepath.Join(root, "source"), "git@github.com:yersonargotev/packy.git")

	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	nonempty := filepath.Join(root, "nonempty")
	if err := os.Mkdir(nonempty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonempty, "sentinel"), []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(filepath.Join(root, "missing-target"), symlink); err != nil {
		t.Fatal(err)
	}
	otherWorktree := filepath.Join(root, "other-worktree")
	runWorkspaceGit(t, source, "worktree", "add", "-b", "other", otherWorktree, "HEAD")

	tests := []struct {
		name        string
		destination string
		want        string
	}{
		{"existing empty", empty, "already exists"},
		{"existing nonempty", nonempty, "already exists"},
		{"symlink", symlink, "already exists"},
		{"inside source", filepath.Join(source, "integration"), "outside the source repository"},
		{"inside existing source worktree", filepath.Join(otherWorktree, "integration"), "outside every existing source worktree"},
		{"relative", "integration", "absolute path"},
		{"root", string(filepath.Separator), "unsafe"},
		{"missing parent", filepath.Join(root, "missing", "integration"), "parent must be an existing directory"},
	}
	before := observeCleanWorkspaceSource(t, source)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := (command{Git: execRunner{}}).run(context.Background(), []string{
				"workspace", "prepare", "--source", source, "--issue", "43",
				"--branch-kind", "fix", "--destination", test.destination,
			}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want containing %q", err, test.want)
			}
			if after := observeCleanWorkspaceSource(t, source); after != before {
				t.Fatalf("source changed\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
	if raw, err := os.ReadFile(filepath.Join(nonempty, "sentinel")); err != nil || string(raw) != "keep\n" {
		t.Fatalf("existing destination changed: %q %v", raw, err)
	}
	if target, err := os.Readlink(symlink); err != nil || target != filepath.Join(root, "missing-target") {
		t.Fatalf("symlink changed: %q %v", target, err)
	}
}

func TestWorkspacePrepareRejectsDetachedOrForeignSourceBeforeMutation(t *testing.T) {
	sandboxWorkspaceEnvironment(t)
	root := t.TempDir()
	tests := []struct {
		name   string
		origin string
		detach bool
		want   string
	}{
		{"detached", "git@github.com:yersonargotev/packy.git", true, "detached HEAD"},
		{"foreign", "git@github.com:someone/else.git", false, "not the Packy repository"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := prepareWorkspaceSource(t, filepath.Join(root, test.name+"-source"), test.origin)
			if test.detach {
				runWorkspaceGit(t, source, "switch", "--detach", "HEAD")
			}
			destination := filepath.Join(root, test.name+"-destination")
			before := observeCleanWorkspaceSource(t, source)
			err := (command{Git: execRunner{}}).run(context.Background(), []string{
				"workspace", "prepare", "--source", source, "--issue", "43",
				"--branch-kind", "chore", "--destination", destination,
			}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want containing %q", err, test.want)
			}
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("destination was mutated: %v", err)
			}
			if after := observeCleanWorkspaceSource(t, source); after != before {
				t.Fatalf("source changed\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

func TestWorkspacePrepareNeverReusesPreparedDestination(t *testing.T) {
	sandboxWorkspaceEnvironment(t)
	root := t.TempDir()
	source := prepareWorkspaceSource(t, filepath.Join(root, "source"), "https://github.com/yersonargotev/packy.git")
	destination := filepath.Join(root, "integration")
	args := []string{
		"workspace", "prepare", "--source", source, "--issue", "43",
		"--branch-kind", "feat", "--destination", destination,
	}
	if err := (command{Git: execRunner{}}).run(context.Background(), args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	before := observeCleanWorkspaceSource(t, destination)
	err := (command{Git: execRunner{}}).run(context.Background(), args, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "never reuses") {
		t.Fatalf("error=%v", err)
	}
	if after := observeCleanWorkspaceSource(t, destination); after != before {
		t.Fatalf("prepared destination changed\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestWorkspacePrepareValidatesIssueAndBranchKind(t *testing.T) {
	sandboxWorkspaceEnvironment(t)
	root := t.TempDir()
	source := prepareWorkspaceSource(t, filepath.Join(root, "source"), "git@github.com:yersonargotev/packy.git")
	for _, test := range []struct {
		name  string
		issue string
		kind  string
		want  string
	}{
		{"zero issue", "0", "feat", "issue must be positive"},
		{"negative issue", "-1", "feat", "issue must be positive"},
		{"invalid kind", "43", "feature", "branch-kind must be chore, feat, or fix"},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := filepath.Join(root, strings.ReplaceAll(test.name, " ", "-"))
			err := (command{Git: execRunner{}}).run(context.Background(), []string{
				"workspace", "prepare", "--source", source, "--issue", test.issue,
				"--branch-kind", test.kind, "--destination", destination,
			}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want containing %q", err, test.want)
			}
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("destination was mutated: %v", err)
			}
		})
	}
}

func observeWorkspaceSource(t *testing.T, repository string) string {
	t.Helper()
	parts := []string{
		workspaceGitOutput(t, repository, "symbolic-ref", "--short", "HEAD"),
		workspaceGitOutput(t, repository, "rev-parse", "HEAD"),
		workspaceGitRaw(t, repository, "ls-files", "--stage", "-z"),
		workspaceGitRaw(t, repository, "status", "--porcelain=v1", "-z", "--untracked-files=all"),
		workspaceGitRaw(t, repository, "worktree", "list", "--porcelain", "-z"),
		workspaceGitRaw(t, repository, "config", "--local", "--null", "--list"),
	}
	for _, name := range []string{"tracked.txt", "staged.txt", "untracked.txt"} {
		raw, err := os.ReadFile(filepath.Join(repository, name))
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, string(raw))
	}
	return strings.Join(parts, "\n---\n")
}

func observeCleanWorkspaceSource(t *testing.T, repository string) string {
	t.Helper()
	return strings.Join([]string{
		workspaceGitRaw(t, repository, "rev-parse", "--abbrev-ref", "HEAD"),
		workspaceGitRaw(t, repository, "rev-parse", "HEAD"),
		workspaceGitRaw(t, repository, "status", "--porcelain=v1", "-z", "--untracked-files=all"),
		workspaceGitRaw(t, repository, "worktree", "list", "--porcelain", "-z"),
		workspaceGitRaw(t, repository, "config", "--local", "--null", "--list"),
	}, "\n---\n")
}

func prepareWorkspaceSource(t *testing.T, repository, origin string) string {
	t.Helper()
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	runWorkspaceGit(t, repository, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(repository, "README.md"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runWorkspaceGit(t, repository, "add", "README.md")
	runWorkspaceGit(t, repository, "-c", "user.name=Packy Test", "-c", "user.email=packy@example.test", "commit", "-m", "fixture")
	runWorkspaceGit(t, repository, "remote", "add", "origin", origin)
	runWorkspaceGit(t, repository, "update-ref", "refs/remotes/origin/main", "HEAD")
	return repository
}

func sandboxWorkspaceEnvironment(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configHome := filepath.Join(root, "config")
	for _, path := range []string{home, configHome} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
}

func slicesContainSubstring(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

func runWorkspaceGit(t *testing.T, repository string, args ...string) {
	t.Helper()
	_ = workspaceGitRaw(t, repository, args...)
}

func workspaceGitOutput(t *testing.T, repository string, args ...string) string {
	t.Helper()
	return strings.TrimSpace(workspaceGitRaw(t, repository, args...))
}

func workspaceGitRaw(t *testing.T, repository string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", repository}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return string(output)
}
