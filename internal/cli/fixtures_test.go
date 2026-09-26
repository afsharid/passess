package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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

func noHarness(t *testing.T) {
	for _, v := range []string{"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_PROJECT_DIR", "CODEX_THREAD_ID", "CODEX_SANDBOX",
		"CODEX_CI", "CURSOR_TRACE_ID", "CURSOR_AGENT", "CURSOR_CLI", "GEMINI_CLI", "GEMINI_PROJECT_DIR", "OPENCODE",
		"OPENCODE_PID", "OPENCODE_CLIENT", "OPENCODE_TERMINAL", "ANTIGRAVITY_CLI_ALIAS", "ZED_SESSION_ID"} {
		t.Setenv(v, "")
	}
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
