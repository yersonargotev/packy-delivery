package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
			for _, command := range []string{"advance", "status", "version", "legacy-v1"} {
				if !strings.Contains(stdout, command) {
					t.Errorf("stdout does not list %q:\n%s", command, stdout)
				}
			}
			if stderr != "" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestAdvanceHelpCommandsAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	for _, args := range [][]string{
		{"advance", "--help"},
		{"advance", "-h"},
		{"advance", "--help", "ignored"},
		{"advance", "-h", "ignored"},
		{"help", "advance"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			stdout, stderr, exitCode := runPackyDeliverForHelpTest(t, binary, args...)
			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr)
			}
			for _, option := range []string{"--repository", "--issue", "--risk-profile", "--authorize-non-local", "--output"} {
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
	environment = append(environment, "GOMODCACHE="+strings.TrimSpace(string(moduleCache)))

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
