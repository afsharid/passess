package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/afsharid/passess/internal/agent"
	"github.com/afsharid/passess/internal/harness"
)

var update = flag.Bool("update", false, "rewrite the menu bar app's JSON fixtures")

// fixtureDir is where the macOS menu bar app's headless checks read from. It
// is made absolute before any test changes directory.
var fixtureDir = func() string {
	abs, err := filepath.Abs(filepath.Join("..", "..", "macos", "PassessBar", "Fixtures"))
	if err != nil {
		panic(err)
	}
	return abs
}()

var versionField = regexp.MustCompile(`"version": "[^"]*"`)

// golden compares a report with its fixture, or rewrites it with -update. Paths
// and the version are normalized so the files do not depend on the machine.
func golden(t *testing.T, name, got, configDir string) {
	t.Helper()
	got = strings.ReplaceAll(got, configDir, "/Users/you/.config/passess")
	got = versionField.ReplaceAllString(got, `"version": "v0.0.0-test"`)
	path := filepath.Join(fixtureDir, name)
	if *update {
		if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(want, []byte(got)) {
		t.Fatalf("%s is out of date; run go test ./internal/cli -run TestMenuBarFixtures -update\n got: %s\nwant: %s", name, got, want)
	}
}

// noHarness makes the test a person at a terminal: no harness markers in its
// environment, and no coding agent among its ancestors, though it may run
// inside one.
func noHarness(t *testing.T) {
	underChain(t)
	for _, v := range []string{"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_PROJECT_DIR", "CODEX_THREAD_ID", "CODEX_SANDBOX",
		"CODEX_CI", "CURSOR_TRACE_ID", "CURSOR_AGENT", "CURSOR_CLI", "GEMINI_CLI", "GEMINI_PROJECT_DIR", "OPENCODE",
		"OPENCODE_PID", "OPENCODE_CLIENT", "OPENCODE_TERMINAL", "ANTIGRAVITY_CLI_ALIAS", "ZED_SESSION_ID",
		// backend settings that would change what doctor reports
		"VAULT_ADDR", "BAO_ADDR", "VAULT_TOKEN", "BAO_TOKEN", "BW_SESSION", "BWS_ACCESS_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN"} {
		t.Setenv(v, "")
	}
}

// TestMenuBarAgentFixtures pins the agent's JSON the macOS app reads: `agent
// status --json`, running and not, and a question as an approver receives it.
// The times carry nanoseconds, as Go writes them.
func TestMenuBarAgentFixtures(t *testing.T) {
	at := time.Date(2026, 9, 26, 19, 30, 0, 123456789, time.UTC)
	info := &agent.Info{PID: 4242, Build: "v0.0.0-test", Protocol: agent.Version, Started: at,
		Socket: "/Users/you/.local/state/passess/agent.sock", Config: "/Users/you/.config/passess/config.toml",
		CacheTTL: "10m0s", Cached: []string{"GITHUB_TOKEN"}, Expires: at.Add(10 * time.Minute), Served: 3, Approvers: 1,
		Approvals: []agent.Approval{{Secret: "GITHUB_TOKEN", Program: "gh", Anchor: agent.Proc{PID: 4141, Name: "claude"},
			Until: at.Add(8 * time.Hour)}}}
	const home = "/Users/you/.config/passess"
	golden(t, "agent-status.json", string(statusJSON(true, info, false))+"\n", home)
	golden(t, "agent-status-outdated.json", string(statusJSON(true, info, true))+"\n", home)
	golden(t, "agent-status-stopped.json", string(statusJSON(false, nil, false))+"\n", home)
	ask, err := json.MarshalIndent(agent.Frame{Ask: &agent.AskFor{ID: "7", Secrets: []string{"GITHUB_TOKEN"}, Program: "gh",
		Path: "/opt/homebrew/bin/gh", Argv: []string{"gh", "api", "user"}, Dir: "/Users/you/project", Harness: "claude-code",
		Anchor: &agent.Proc{PID: 4242, Name: "claude"}, Until: at.Add(8 * time.Hour)}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "agent-ask.json", string(ask)+"\n", home)

	// passess status --json, as the panel's coding agents read it: one guarded,
	// one that needs `passess install`, one with nothing to set up.
	status, err := json.MarshalIndent(harnessOutput{Harnesses: []harnessReport{
		{ID: "claude", Label: "Claude Code", Config: "/Users/you/.claude.json", Servers: []harness.ServerStatus{},
			Unmanaged: []harness.Entry{}, Instructions: "/Users/you/.claude/CLAUDE.md", InstructionsState: harness.BlockOK,
			Hooks: harness.StateOK, Actions: []harness.Action{}, Errors: []string{}},
		{ID: "codex", Label: "Codex", Config: "/Users/you/.codex/config.toml",
			Servers:   []harness.ServerStatus{{Name: "landingfolio", State: harness.StateOK}},
			Unmanaged: []harness.Entry{}, Instructions: "/Users/you/.codex/AGENTS.md", InstructionsState: harness.BlockOK,
			Hooks: harness.StateMissing, Actions: []harness.Action{{Kind: "add", Server: "github"}}, Errors: []string{}},
		{ID: "claude-desktop", Label: "Claude Desktop", Config: "/Users/you/Library/Application Support/Claude/claude_desktop_config.json",
			Servers: []harness.ServerStatus{}, Unmanaged: []harness.Entry{}, InstructionsState: harness.BlockNone,
			Hooks: "none", Actions: []harness.Action{}, Errors: []string{}},
	}, Apps: []appReport{
		// an app set up and loaded, one key that reaches it, one that does not
		{ID: "dsh", Label: "DeepSeek Harness", Config: "/Users/you/.dsh/profiles/desktop/cordis.patch.yml",
			Plugin: "ok", Active: "2026-10-09T20:00:00.000Z",
			Keys:    []appKey{{Name: "EVREN_LLM_API_KEY", State: keyEveryAgent}, {Name: "OTHER_KEY", State: keyConnected}},
			Changes: []string{}, Errors: []string{}},
	}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "status.json", string(status)+"\n", home)
}

// TestMenuBarFixtures pins the JSON contract between the CLI and the macOS app.
func TestMenuBarFixtures(t *testing.T) {
	noHarness(t)

	dir := writeConfig(t, "version = 1\n[secrets.A]\nref = \"env://PASSESS_TEST_A\"\n")
	out, _, _ := run(t, "doctor", "--json")
	golden(t, "doctor-ok.json", out, dir)

	dir = writeConfig(t, "version = 1\n[secrets.B]\nref = \"vault://secret/app#token\"\n")
	out, _, _ = run(t, "doctor", "--json")
	golden(t, "doctor-problems.json", out, dir)

	dir = t.TempDir()
	t.Setenv("PASSESS_CONFIG", filepath.Join(dir, "config.toml"))
	out, _, _ = run(t, "doctor", "--json")
	golden(t, "doctor-no-config.json", out, dir)

	dir = writeConfig(t, "version = 1\n[secrets.PRESENT]\nref = \"env://PASSESS_TEST_PRESENT_TOKEN\"\n[secrets.ABSENT]\nref = \"env://PASSESS_TEST_ABSENT\"\n")
	t.Setenv("PASSESS_TEST_PRESENT_TOKEN", execValue)
	out, _, _ = run(t, "check", "--json")
	if strings.Contains(out, execValue) {
		t.Fatal("check printed a value")
	}
	golden(t, "check.json", out, dir)
}

// TestMenuBarSecretFixtures pins what the Secrets screen reads: `list --json`
// with every kind of clients list, and `discover --json`.
func TestMenuBarSecretFixtures(t *testing.T) {
	noHarness(t)
	dir := writeConfig(t, `version = 1
[secrets.OPENROUTER_API_KEY]
ref     = "bws://`+discProject+`/OPENROUTER_API_KEY"
clients = ["claude-code", "opencode"]
hosts   = ["openrouter.ai"]
[secrets.HASS_TOKEN]
ref     = "bws://`+discProject+`/HASS_TOKEN"
clients = ["claude-code"]
approve = true
[secrets.SUDO_PASSWORD]
ref     = "bws://`+discProject+`/SUDO_PASSWORD"
clients = []
[secrets.GITHUB_TOKEN]
ref   = "keychain://passess/github"
allow = ["gh", "git"]
note  = "repo:read"
[profiles.web]
secrets = ["OPENROUTER_API_KEY"]
allow   = ["node"]
`)
	out, _, _ := run(t, "list", "--json")
	golden(t, "list.json", out, dir)

	saved := discoverRunner
	t.Cleanup(func() { discoverRunner = saved })
	discoverRunner = discoverFake{t}
	t.Setenv("BWS_ACCESS_TOKEN", "passess-fake-bws-machine-token-0123456789")
	out, _, _ = run(t, "discover", "--json")
	if strings.Contains(out, discValue) {
		t.Fatal("discover printed a value")
	}
	golden(t, "discover.json", out, dir)
}
