package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAdvanceSemanticInputHelpNamesExactTypedJSONFilesAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)

	stdout, stderr, exitCode := runPackyDeliverForHelpTest(t, binary, "help", "advance")
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr)
	}
	for _, want := range []string{
		"--decision PATH            PATH to a file containing exactly one Decision JSON value",
		"--repair PATH              PATH to a file containing exactly one RepairDecision JSON value",
		"--review-content PATH      PATH to a file containing exactly one review-content JSON object",
		"--ci-attribution PATH      PATH to a file containing exactly one JSON array of CI failure attributions",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not describe %q:\n%s", want, stdout)
		}
	}
}

func TestAdvanceSemanticInputReadErrorsNameOptionAndPreserveCauseAsProcess(t *testing.T) {
	binary := buildPackyDeliverForHelpTest(t)
	repository := t.TempDir()

	for _, option := range []string{"--decision", "--repair", "--review-content", "--ci-attribution"} {
		t.Run(strings.TrimPrefix(option, "--"), func(t *testing.T) {
			missing := filepath.Join(t.TempDir(), "missing.json")
			stdout, stderr, exitCode := runPackyDeliverForHelpTest(
				t, binary,
				"advance", "--repository", repository, "--issue", "361", option, missing,
			)
			if exitCode == 0 {
				t.Fatal("missing semantic input file exited successfully")
			}
			if stdout != "" {
				t.Errorf("stdout = %q", stdout)
			}
			for _, want := range []string{option, "expected a JSON file path", "no such file or directory"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr does not preserve %q: %q", want, stderr)
				}
			}
		})
	}

	longProse := strings.Repeat("this is prose and not a JSON file path ", 12)
	_, stderr, exitCode := runPackyDeliverForHelpTest(
		t, binary,
		"advance", "--repository", repository, "--issue", "361", "--decision", longProse,
	)
	if exitCode == 0 {
		t.Fatal("long prose semantic input exited successfully")
	}
	for _, want := range []string{"--decision", "expected a JSON file path", "file name too long"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("long-prose stderr does not preserve %q: %q", want, stderr)
		}
	}
}
