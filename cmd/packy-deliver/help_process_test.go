package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHelpCommandsAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	for _, args := range [][]string{
		{"--help"},
		{"-h"},
		{"help"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			stdout, stderr, exitCode := runPackyDeliverForHelpTest(t, binary, args...)
			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr)
			}
			for _, command := range []string{
				"advance", "input-template", "review-packets", "status", "watch",
				"workspace", "version", "legacy-v1",
			} {
				if !strings.Contains(stdout, command) {
					t.Errorf("stdout does not list %q:\n%s", command, stdout)
				}
			}
			for _, guidance := range []string{
				"status -> input-template -> advance -> review-packets -> advance -> watch -> advance",
				"Advance alone adopts results",
				"--full-report only for judgment or audit",
			} {
				if !strings.Contains(stdout, guidance) {
					t.Errorf("stdout does not contain operator guidance %q:\n%s", guidance, stdout)
				}
			}
			if stderr != "" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestWorkspaceHelpCommandsAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	for _, args := range [][]string{
		{"workspace", "--help"},
		{"workspace", "-h"},
		{"workspace", "prepare", "--help"},
		{"workspace", "prepare", "--issue", "43", "--help"},
		{"help", "workspace"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			stdout, stderr, exitCode := runPackyDeliverForHelpTest(t, binary, args...)
			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr)
			}
			for _, value := range []string{
				"workspace prepare", "--source", "--issue", "--branch-kind", "--destination",
				"no GitHub mutation", "no non-local delivery authorization",
			} {
				if !strings.Contains(stdout, value) {
					t.Errorf("stdout does not contain %q:\n%s", value, stdout)
				}
			}
			if stderr != "" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestWatchHelpCommandsAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	for _, args := range [][]string{
		{"watch", "--help"},
		{"watch", "-h"},
		{"watch", "--issue", "361", "--help"},
		{"help", "watch"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			stdout, stderr, exitCode := runPackyDeliverForHelpTest(t, binary, args...)
			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr)
			}
			for _, value := range []string{
				"--repository", "--issue", "--interval", "--timeout", "--output",
				"100ms", "24h", "terminal_outcome", "timeout-no-change", "code 2",
			} {
				if !strings.Contains(stdout, value) {
					t.Errorf("stdout does not contain %q:\n%s", value, stdout)
				}
			}
			if stderr != "" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestWatchTimeoutAndInterruptionAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	t.Run("timeout has distinct exit", func(t *testing.T) {
		repository, unlock := prepareLockContendedWatchRepository(t)
		defer unlock()
		stdout, stderr, exitCode := runPackyDeliverForHelpTest(
			t,
			binary,
			"watch",
			"--repository", repository,
			"--issue", "29",
			"--interval", "100ms",
			"--timeout", "1s",
			"--output", "jsonl",
		)
		if exitCode != 2 || !strings.Contains(stderr, "watch timed out after 1s") {
			t.Fatalf("exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
		if strings.Count(strings.TrimSpace(stdout), "\n") != 1 ||
			!strings.Contains(stdout, `"pause_cause":"lock-contention"`) ||
			!strings.Contains(stdout, `"terminal_outcome":"timeout-no-change"`) {
			t.Fatalf("timeout output=%q", stdout)
		}
	})

	t.Run("observer failure keeps operational exit", func(t *testing.T) {
		repository, unlock := prepareLockContendedWatchRepository(t)
		unlock()
		stdout, stderr, exitCode := runPackyDeliverForHelpTest(
			t,
			binary,
			"watch",
			"--repository", repository,
			"--issue", "29",
			"--interval", "100ms",
			"--timeout", "1s",
			"--output", "jsonl",
		)
		if exitCode != 1 ||
			!strings.Contains(stdout, `"error_class":"run-state"`) ||
			strings.Contains(stdout, `"terminal_outcome":`) ||
			!strings.Contains(stderr, "watch observation failed") {
			t.Fatalf("exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
	})

	t.Run("interrupt uses signal exit", func(t *testing.T) {
		repository, unlock := prepareLockContendedWatchRepository(t)
		defer unlock()
		command := exec.Command(
			binary,
			"watch",
			"--repository", repository,
			"--issue", "29",
			"--interval", "100ms",
			"--timeout", "10s",
			"--output", "jsonl",
		)
		command.Env = helpTestEnvironment(t)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(250 * time.Millisecond)
		if err := command.Process.Signal(os.Interrupt); err != nil {
			t.Fatal(err)
		}
		err := command.Wait()
		exitError, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("interrupt error=%T %v stdout=%q stderr=%q", err, err, stdout.String(), stderr.String())
		}
		status, ok := exitError.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGINT {
			t.Fatalf("wait status=%v stdout=%q stderr=%q", status, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), `"terminal_outcome":"timeout-no-change"`) {
			t.Fatalf("signal interruption was reported as timeout: %q", stdout.String())
		}
	})
}

func TestAdvanceHelpCommandsAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	for _, args := range [][]string{
		{"advance", "--help"},
		{"advance", "-h"},
		{"advance", "--help", "ignored"},
		{"advance", "-h", "ignored"},
		{"advance", "--issue", "361", "--help"},
		{"advance", "--repository", ".", "-h"},
		{"help", "advance"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			stdout, stderr, exitCode := runPackyDeliverForHelpTest(t, binary, args...)
			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr)
			}
			for _, option := range []string{
				"--repository", "--issue", "--risk-profile", "--authorize-non-local",
				"--output", "only lifecycle operation", "without translating their",
				"telemetry, never correctness",
			} {
				if !strings.Contains(stdout, option) {
					t.Errorf("stdout does not list %q:\n%s", option, stdout)
				}
			}
			if strings.Contains(stderr, "flag: help requested") {
				t.Errorf("stderr contains flag parser help error: %q", stderr)
			}
			if stderr != "" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestStatusHelpCommandsAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	for _, args := range [][]string{
		{"status", "--help"},
		{"status", "-h"},
		{"status", "--issue", "361", "--help"},
		{"help", "status"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			stdout, stderr, exitCode := runPackyDeliverForHelpTest(t, binary, args...)
			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr)
			}
			for _, option := range []string{"--repository", "--issue", "--output", "observation-only"} {
				if !strings.Contains(stdout, option) {
					t.Errorf("stdout does not contain %q:\n%s", option, stdout)
				}
			}
			if stderr != "" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestLegacyStatusHelpCommandsAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	for _, args := range [][]string{
		{"legacy-v1", "status", "--help"},
		{"legacy-v1", "status", "-h"},
		{"help", "legacy-v1"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			stdout, stderr, exitCode := runPackyDeliverForHelpTest(t, binary, args...)
			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr)
			}
			commands := []string{"status", "--bundle"}
			if args[0] == "help" {
				commands = append(commands,
					"initialize", "record-iteration", "record-review",
					"record-adjudication", "review-status", "record-focused-validation",
					"record-exhaustive-validation", "validation-status", "local-gate",
					"non-local-readiness", "final-outcome",
				)
			}
			for _, command := range commands {
				if !strings.Contains(stdout, command) {
					t.Errorf("stdout does not document legacy command %q:\n%s", command, stdout)
				}
			}
			if stderr != "" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestUnknownAndLegacyCommandsAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	stdout, stderr, exitCode := runPackyDeliverForHelpTest(t, binary, "typo")
	if exitCode == 0 {
		t.Fatal("unknown command exited successfully")
	}
	if stdout != "" {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, `packy-deliver help`) {
		t.Errorf("stderr does not guide to root help: %q", stderr)
	}
	if strings.Contains(stderr, "historical evidence sequencing") {
		t.Errorf("unknown command received historical sequencing guidance: %q", stderr)
	}

	stdout, stderr, exitCode = runPackyDeliverForHelpTest(t, binary, "advance", "help")
	if exitCode == 0 {
		t.Fatal("undocumented advance help form exited successfully")
	}
	if stdout != "" {
		t.Errorf("undocumented advance help stdout = %q", stdout)
	}
	if strings.Contains(stderr, "flag: help requested") {
		t.Errorf("undocumented advance help leaked flag parser help: %q", stderr)
	}

	stdout, stderr, exitCode = runPackyDeliverForHelpTest(t, binary, "initialize")
	if exitCode == 0 {
		t.Fatal("unprefixed legacy command exited successfully")
	}
	if stdout != "" {
		t.Errorf("unprefixed legacy stdout = %q", stdout)
	}
	for _, want := range []string{"legacy-v1", "packy-deliver help"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("unprefixed legacy stderr does not contain %q: %q", want, stderr)
		}
	}

	stdout, stderr, exitCode = runPackyDeliverForHelpTest(t, binary, "legacy-v1", "unknown")
	if exitCode == 0 {
		t.Fatal("unknown legacy-v1 command exited successfully")
	}
	if stdout != "" {
		t.Errorf("legacy stdout = %q", stdout)
	}
	if !strings.Contains(stderr, `unknown legacy v1 command "unknown"`) {
		t.Errorf("legacy stderr = %q", stderr)
	}
	if strings.Contains(stderr, "packy-deliver help") {
		t.Errorf("explicit legacy-v1 command lost legacy semantics: %q", stderr)
	}
}

func buildPackyDeliverForHelpTest(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "packy-deliver")
	environment := helpTestEnvironment(t)
	goEnvironment := exec.Command("go", "env", "GOMODCACHE")
	goEnvironment.Env = environment
	moduleCache, err := goEnvironment.Output()
	if err != nil {
		t.Fatalf("resolve Go module cache: %v", err)
	}
	goFlags := strings.TrimSpace(os.Getenv("GOFLAGS"))
	if !strings.Contains(" "+goFlags+" ", " -modcacherw ") {
		goFlags = strings.TrimSpace(goFlags + " -modcacherw")
	}
	environment = replacedEnvironment(environment, map[string]string{
		"GOMODCACHE": strings.TrimSpace(string(moduleCache)),
		"GOFLAGS":    goFlags,
	})

	command := exec.Command("go", "build", "-o", binary, ".")
	command.Dir = "."
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build packy-deliver: %v\n%s", err, output)
	}
	return binary
}

func runPackyDeliverForHelpTest(t *testing.T, binary string, args ...string) (string, string, int) {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Env = helpTestEnvironment(t)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	exitError, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v", args, err)
	}
	return stdout.String(), stderr.String(), exitError.ExitCode()
}

func helpTestEnvironment(t *testing.T) []string {
	t.Helper()
	home := t.TempDir()
	config := filepath.Join(home, "config")
	if err := os.Mkdir(config, 0o700); err != nil {
		t.Fatal(err)
	}
	return replacedEnvironment(os.Environ(), map[string]string{
		"HOME":            home,
		"XDG_CONFIG_HOME": config,
	})
}

func prepareLockContendedWatchRepository(t *testing.T) (string, func()) {
	t.Helper()
	repository := t.TempDir()
	environment := helpTestEnvironment(t)
	runGit := func(args ...string) {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", repository}, args...)...)
		command.Env = environment
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	runGit("init", "-b", "main")
	if err := os.WriteFile(filepath.Join(repository, "README.md"), []byte("watch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "README.md")
	runGit("-c", "user.name=Packy Test", "-c", "user.email=packy@example.test", "commit", "-m", "fixture")
	runGit("remote", "add", "origin", "git@github.com:yersonargotev/packy.git")
	runGit("update-ref", "refs/remotes/origin/main", "HEAD")

	issueDirectory := filepath.Join(
		repository,
		".git",
		"packy",
		"issue-delivery",
		"issue-29",
	)
	if err := os.MkdirAll(issueDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(
		filepath.Join(issueDirectory, "advance.lock"),
		os.O_CREATE|os.O_RDWR,
		0o600,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		t.Fatal(err)
	}
	return repository, func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
	}
}
