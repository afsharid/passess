package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHookGoldens is the hook contract, one file pair per harness and event:
// testdata/hooks/HARNESS/EVENT--case.json is what the harness sends, and
// .golden what passess answers (exit code, stdout, stderr). -update rewrites
// the answers; review the diff.
func TestHookGoldens(t *testing.T) {
	noHarness(t)
	abs, _ := filepath.Abs(filepath.Join("testdata", "hooks"))
	t.Setenv("HOME", "/home/u")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", "/home/u/.local/state")
	t.Setenv("PASSESS_CONFIG", filepath.Join(abs, "config.toml"))
	t.Setenv("GITHUB_TOKEN", "passess-fake-gh-token-0123456789") // a credential already in the harness's environment

	inputs, _ := filepath.Glob(filepath.Join(abs, "*", "*.json"))
	if len(inputs) < 30 {
		t.Fatalf("only %d fixtures", len(inputs))
	}
	for _, in := range inputs {
		harness := filepath.Base(filepath.Dir(in))
		event, _, _ := strings.Cut(strings.TrimSuffix(filepath.Base(in), ".json"), "--")
		t.Run(harness+"/"+filepath.Base(in), func(t *testing.T) {
			payload, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			// Token-shaped strings are built at run time so scanners skip the fixtures.
			payload = bytes.ReplaceAll(payload, []byte("__FAKE_GITHUB_PAT__"), []byte("gh"+"p_"+strings.Repeat("A1b2C3d4E5", 3)+"f6G7h8"))
			var out, errb bytes.Buffer
			code := Main([]string{"hook", harness, event}, bytes.NewReader(payload), &out, &errb)
			got := fmt.Sprintf("exit: %d\n--- stdout\n%s--- stderr\n%s", code, out.String(), errb.String())
			if strings.Contains(got, "passess-fake-content-never-echoed") {
				t.Fatal("a file's content from the payload was echoed")
			}
			if strings.Contains(got, "passess-fake-gh-token-0123456789") {
				t.Fatal("a credential from the environment reached the reply")
			}
			golden := strings.TrimSuffix(in, ".json") + ".golden"
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if got != string(want) {
				t.Fatalf("reply changed; run go test ./internal/cli -run TestHookGoldens -update and review\n got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestHookFailsOpen(t *testing.T) {
	noHarness(t)
	t.Setenv("PASSESS_CONFIG", filepath.Join(t.TempDir(), "broken.toml"))
	if err := os.WriteFile(os.Getenv("PASSESS_CONFIG"), []byte("version = 99\n[[[broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"hook"}, {"hook", "notepad", "PreToolUse"}, {"hook", "claude", "PreToolUse"}} {
		var out, errb bytes.Buffer
		code := Main(args, strings.NewReader(`{"tool_name": "Bash", "tool_input": {"command": "ls"}}`), &out, &errb)
		if code != 0 || out.Len() != 0 {
			t.Errorf("%v: exit %d, stdout %q", args, code, out.String())
		}
	}
	// A broken config still refuses what the policy refuses, without names.
	var out bytes.Buffer
	Main([]string{"hook", "claude", "PreToolUse"}, strings.NewReader(`{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "printenv"}}`), &out, &bytes.Buffer{})
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %s", out.String())
	}
}
