package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/harness"
)

// fakeHarnesses gives the test its own HOME with Claude Code and Codex
// configs, plus claude and codex executables that only record their argv.
func fakeHarnesses(t *testing.T) (home, calls string) {
	t.Helper()
	noHarness(t) // uninstall --apply refuses under an agent
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	bin := filepath.Join(home, "bin")
	calls = filepath.Join(home, "calls.log")
	for _, name := range []string{"claude", "codex"} {
		script := "#!/bin/sh\necho \"" + name + " $*\" >> " + calls + "\n"
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Only the fake harness CLIs and the system: a real agy or gemini on PATH
	// would count as an installed harness and get written to.
	t.Setenv("PATH", strings.Join([]string{bin, "/usr/bin", "/bin", "/usr/sbin", "/sbin"}, string(os.PathListSeparator)))
	t.Setenv("XDG_CONFIG_HOME", "")

	writeFile := func(path, body string) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(filepath.Join(home, ".claude.json"), `{"mcpServers": {
  "legacy": {"command": "npx", "args": ["-y", "server"], "env": {"API_TOKEN": "passess-fake-legacy-0123456789abcdef"}}
}}`)
	writeFile(filepath.Join(home, ".claude", "CLAUDE.md"), "# My rules\n\nBe brief.\n")
	writeFile(filepath.Join(home, ".codex", "config.toml"), "model = \"gpt-6\"\n")

	cfg := filepath.Join(home, ".config", "passess", "config.toml")
	writeFile(cfg, `version = 1
[secrets.GITHUB_TOKEN]
ref = "env://PASSESS_TEST_GH"
[mcp.github]
command = ["github-mcp-server", "stdio"]
env = { GITHUB_PERSONAL_ACCESS_TOKEN = "GITHUB_TOKEN" }
`)
	t.Setenv("PASSESS_CONFIG", cfg)
	t.Chdir(home)
	return home, calls
}

func readCalls(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

func TestInstallDryRunChangesNothing(t *testing.T) {
	home, calls := fakeHarnesses(t)
	out, errOut, code := run(t, "install")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"Claude Code", "Codex", "github", "missing", "would add github", "credentials in clear: env.API_TOKEN", "Dry run"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if readCalls(t, calls) != "" {
		t.Fatal("a dry run must not call the harness CLIs")
	}
	doc, _ := os.ReadFile(filepath.Join(home, ".claude", "CLAUDE.md"))
	if strings.Contains(string(doc), harness.BlockStart) {
		t.Fatal("a dry run must not touch instructions")
	}
}

func TestInstallApplyAndUninstall(t *testing.T) {
	home, calls := fakeHarnesses(t)
	out, errOut, code := run(t, "install", "--apply", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	var got harnessOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Applied || len(got.Harnesses) != 2 || got.Harnesses[0].Backup == "" {
		t.Fatalf("report = %+v", got)
	}
	log := readCalls(t, calls)
	exe := passessPath()
	for _, want := range []string{
		"claude mcp add --scope user github -- " + exe + " mcp-exec github",
		"codex mcp add github -- " + exe + " mcp-exec github",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("calls lack %q:\n%s", want, log)
		}
	}
	for _, f := range []string{filepath.Join(home, ".claude", "CLAUDE.md"), filepath.Join(home, ".codex", "AGENTS.md")} {
		doc, err := os.ReadFile(f)
		if err != nil || harness.BlockState(string(doc)) != harness.BlockOK {
			t.Fatalf("%s lacks the instructions block: %v", f, err)
		}
	}
	claudeDoc, _ := os.ReadFile(filepath.Join(home, ".claude", "CLAUDE.md"))
	if !strings.HasPrefix(string(claudeDoc), "# My rules\n\nBe brief.\n") {
		t.Fatalf("existing instructions changed: %q", claudeDoc)
	}
	if strings.Contains(out, "passess-fake-legacy") {
		t.Fatal("the report carried a value")
	}

	// Pretend the harnesses now run passess, then uninstall.
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {"github": {"command": "`+exe+`", "args": ["mcp-exec", "github"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	for _, want := range []string{passessPath() + " hook claude PreToolUse", passessPath() + " hook claude UserPromptSubmit", `"matcher": "Bash|Read`} {
		if !strings.Contains(string(settings), want) {
			t.Fatalf("Claude settings lack %q:\n%s", want, settings)
		}
	}
	if hooks, _ := os.ReadFile(filepath.Join(home, ".codex", "hooks.json")); !strings.Contains(string(hooks), passessPath()+" hook codex PreToolUse") {
		t.Fatalf("Codex hooks.json:\n%s", hooks)
	}
	if out, _, _ := run(t, "status"); !strings.Contains(out, "hooks          ok") {
		t.Fatalf("status does not report the hooks:\n%s", out)
	}
	if out, errOut, code := run(t, "uninstall", "--apply"); code != 0 {
		t.Fatalf("uninstall: exit %d: %s %s", code, out, errOut)
	}
	if log := readCalls(t, calls); !strings.Contains(log, "claude mcp remove --scope user github") {
		t.Fatalf("uninstall did not remove the entry:\n%s", log)
	}
	claudeDoc, _ = os.ReadFile(filepath.Join(home, ".claude", "CLAUDE.md"))
	if string(claudeDoc) != "# My rules\n\nBe brief.\n" {
		t.Fatalf("uninstall did not restore the instructions: %q", claudeDoc)
	}
	// passess created both hook files; nothing of theirs is left, so they go.
	for _, f := range []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".codex", "hooks.json")} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			data, _ := os.ReadFile(f)
			t.Fatalf("%s is still there:\n%s", f, data)
		}
	}
}

func TestStatusExitCodeAndUnknownHarness(t *testing.T) {
	fakeHarnesses(t)
	if _, _, code := run(t, "status"); code != 1 {
		t.Fatalf("status with missing entries: exit %d, want 1", code)
	}
	if _, errOut, code := run(t, "install", "notepad"); code != ExitUsage || !strings.Contains(errOut, "unknown harness") {
		t.Fatalf("unknown harness: exit %d: %s", code, errOut)
	}
}

// TestLiveInstall runs install --apply and uninstall --apply end to end with
// the real claude and codex CLIs against a throwaway HOME. Opt in with
// PASSESS_LIVE_HARNESS=1.
func TestLiveInstall(t *testing.T) {
	if os.Getenv("PASSESS_LIVE_HARNESS") != "1" {
		t.Skip("set PASSESS_LIVE_HARNESS=1 to run against installed harness CLIs")
	}
	realPath := os.Getenv("PATH")
	home, _ := fakeHarnesses(t)
	t.Setenv("PATH", realPath) // the real CLIs, not the recorders
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	for _, cli := range []string{"claude", "codex"} {
		if _, err := exec.LookPath(cli); err != nil {
			t.Skipf("%s not installed", cli)
		}
	}
	if out, errOut, code := run(t, "install", "--apply"); code != 0 {
		t.Fatalf("install: exit %d:\n%s\n%s", code, out, errOut)
	}
	out, _, _ := run(t, "status", "--json")
	var got harnessOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, h := range got.Harnesses {
		ids[h.ID] = true
		if len(h.Servers) != 1 || h.Servers[0].State != harness.StateOK || h.InstructionsState != harness.BlockOK {
			t.Fatalf("%s after install: %+v", h.ID, h)
		}
	}
	if _, err := exec.LookPath("agy"); err == nil && !ids["antigravity"] {
		t.Fatalf("agy is installed but Antigravity was not covered: %v", ids)
	}
	t.Logf("covered: %v", ids)
	if out, errOut, code := run(t, "uninstall", "--apply"); code != 0 {
		t.Fatalf("uninstall: exit %d:\n%s\n%s", code, out, errOut)
	}
	out, _, _ = run(t, "status", "--json")
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	for _, h := range got.Harnesses {
		if h.Servers[0].State != harness.StateMissing || h.InstructionsState != harness.BlockMissing {
			t.Fatalf("%s after uninstall: %+v", h.ID, h)
		}
	}
}
