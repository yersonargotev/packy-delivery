package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const workspaceUsage = `Usage: packy-deliver workspace prepare [options]

Create a new isolated Packy integration workspace without changing or adopting
the source checkout. Preparation is local-only: it performs no GitHub mutation
and grants no non-local delivery authorization.

Options:
  --source PATH       Absolute path to the attached Packy source repository
  --issue N           Positive Packy issue number
  --branch-kind KIND  Issue branch kind: chore, feat, or fix
  --destination PATH  Absolute path to a new destination
`

type workspacePrepareOptions struct {
	SourcePath      string
	IssueNumber     int
	BranchKind      string
	DestinationPath string
}

func (c command) workspace(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("workspace requires the prepare subcommand")
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		_, err := io.WriteString(stdout, workspaceUsage)
		return err
	}
	if args[0] != "prepare" {
		return fmt.Errorf("unknown workspace subcommand %q; use prepare", args[0])
	}
	if containsWorkspaceHelpFlag(args[1:]) {
		_, err := io.WriteString(stdout, workspaceUsage)
		return err
	}
	return c.workspacePrepare(ctx, args[1:], stdout)
}

func (c command) workspacePrepare(ctx context.Context, args []string, stdout io.Writer) (resultErr error) {
	f := flag.NewFlagSet("packy-deliver workspace prepare", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var options workspacePrepareOptions
	f.StringVar(&options.SourcePath, "source", "", "absolute Packy source repository")
	f.IntVar(&options.IssueNumber, "issue", 0, "Packy issue number")
	f.StringVar(&options.BranchKind, "branch-kind", "", "issue branch kind")
	f.StringVar(&options.DestinationPath, "destination", "", "new integration workspace")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("workspace prepare forbids positional arguments")
	}
	if c.Git == nil {
		return errors.New("Git adapter is unavailable")
	}
	if !filepath.IsAbs(options.SourcePath) {
		return errors.New("source must be an absolute path")
	}
	if options.IssueNumber <= 0 {
		return errors.New("issue must be positive")
	}
	if options.BranchKind != "chore" && options.BranchKind != "feat" && options.BranchKind != "fix" {
		return errors.New("branch-kind must be chore, feat, or fix")
	}
	if !filepath.IsAbs(options.DestinationPath) {
		return errors.New("destination must be an absolute path")
	}

	source := filepath.Clean(options.SourcePath)
	destination := filepath.Clean(options.DestinationPath)
	if destination == string(filepath.Separator) {
		return errors.New("destination is unsafe")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("destination already exists; workspace prepare never reuses a destination")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination: %w", err)
	}
	parentInfo, err := os.Stat(filepath.Dir(destination))
	if err != nil || !parentInfo.IsDir() {
		return errors.New("destination parent must be an existing directory")
	}

	top, err := gitOutput(ctx, c.Git, source, "rev-parse", "--path-format=absolute", "--show-toplevel")
	if err != nil || !sameFilesystemPath(top, source) {
		return errors.New("source must name the root of a Git repository")
	}
	common, err := gitOutput(ctx, c.Git, source, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return fmt.Errorf("observe source Git common directory: %w", err)
	}
	if _, err := gitOutput(ctx, c.Git, source, "symbolic-ref", "--quiet", "--short", "HEAD"); err != nil {
		return errors.New("source repository has detached HEAD; attach a branch before preparing a workspace")
	}
	origin, err := gitOutput(ctx, c.Git, source, "remote", "get-url", "origin")
	if err != nil {
		return errors.New("source repository has no origin remote")
	}
	slug, slugErr := githubSlug(origin)
	if slugErr != nil || slug != packyRepositorySlug {
		return errors.New("source origin is not the Packy repository")
	}
	base, err := gitOutput(ctx, c.Git, source, "rev-parse", "origin/main^{commit}")
	if err != nil {
		return errors.New("source repository has no local origin/main commit")
	}
	insideSource, sourcePathErr := pathWithin(destination, top)
	insideCommon, commonPathErr := pathWithin(destination, common)
	if sourcePathErr != nil || commonPathErr != nil {
		return errors.New("destination safety could not be established")
	}
	if insideSource || insideCommon {
		return errors.New("destination must be outside the source repository and Git common directory")
	}
	worktreeBytes, err := gitRaw(ctx, c.Git, source, "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return fmt.Errorf("observe source worktrees: %w", err)
	}
	worktrees, complete := parseWorktrees(worktreeBytes)
	if !complete {
		return errors.New("source worktree observation is incomplete")
	}
	for _, worktree := range worktrees {
		if sameFilesystemPath(worktree.path, top) {
			continue
		}
		inside, pathErr := pathWithin(destination, worktree.path)
		if pathErr != nil {
			return errors.New("destination safety against existing source worktrees could not be established")
		}
		if inside {
			return errors.New("destination must be outside every existing source worktree")
		}
	}
	branch := options.BranchKind + "/issue-" + strconv.Itoa(options.IssueNumber) + "-workspace"
	if _, err := c.Git.Output(ctx, "git", "check-ref-format", "--branch", branch); err != nil {
		return fmt.Errorf("constructed issue branch is invalid: %w", err)
	}

	if err := os.Mkdir(destination, 0o700); err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	created := true
	defer func() {
		if resultErr != nil && created {
			_ = os.RemoveAll(destination)
		}
	}()
	commands := [][]string{
		{"init", "--quiet"},
		{"remote", "add", "origin", origin},
		{"fetch", "--quiet", "--no-tags", source, "refs/remotes/origin/main:refs/remotes/origin/main"},
		{"update-ref", "refs/heads/main", base},
		{"switch", "--quiet", "--create", branch, "--no-track", base},
		{"config", "--local", "packy.delivery-prepared", "true"},
		{"config", "--local", "packy.delivery-source-common-dir", filepath.Clean(common)},
		{"config", "--local", "packy.delivery-issue", strconv.Itoa(options.IssueNumber)},
		{"config", "--local", "packy.delivery-branch", branch},
	}
	for _, command := range commands {
		if _, err := gitRaw(ctx, c.Git, destination, command...); err != nil {
			return fmt.Errorf("prepare workspace with git %s: %w", strings.Join(command, " "), err)
		}
	}
	preparedTop, topErr := gitOutput(ctx, c.Git, destination, "rev-parse", "--path-format=absolute", "--show-toplevel")
	preparedBranch, branchErr := gitOutput(ctx, c.Git, destination, "symbolic-ref", "--quiet", "--short", "HEAD")
	preparedHead, headErr := gitOutput(ctx, c.Git, destination, "rev-parse", "HEAD^{commit}")
	status, statusErr := gitRaw(ctx, c.Git, destination, "status", "--porcelain=v1", "--untracked-files=all")
	if topErr != nil || branchErr != nil || headErr != nil || statusErr != nil ||
		!sameFilesystemPath(preparedTop, destination) || preparedBranch != branch || preparedHead != base || len(status) != 0 {
		return errors.New("prepared workspace failed final identity or cleanliness verification")
	}
	created = false
	_, err = fmt.Fprintf(stdout, "prepared %s on %s at %s\n", destination, branch, base)
	return err
}

func containsWorkspaceHelpFlag(args []string) bool {
	return containsHelpFlag(args, func(arg string) bool {
		switch arg {
		case "-source", "--source", "-issue", "--issue", "-branch-kind", "--branch-kind", "-destination", "--destination":
			return true
		default:
			return false
		}
	})
}

func sameFilesystemPath(left, right string) bool {
	resolvedLeft, leftErr := filepath.EvalSymlinks(left)
	resolvedRight, rightErr := filepath.EvalSymlinks(right)
	return leftErr == nil && rightErr == nil && filepath.Clean(resolvedLeft) == filepath.Clean(resolvedRight)
}
