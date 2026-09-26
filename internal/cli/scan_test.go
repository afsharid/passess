package cli

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseAnywhere(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "")
	pos, err := parseAnywhere(fs, []string{"claude", "--apply", "codex", "--", "--apply", "-x"})
	if err != nil || !*apply || !slices.Equal(pos, []string{"claude", "codex", "--apply", "-x"}) {
		t.Fatalf("pos = %q, apply = %v, err = %v", pos, *apply, err)
	}
	if _, err := parseAnywhere(fs, []string{"claude", "--nope"}); err == nil {
		t.Fatal("unknown flag after a positional accepted")
	}
}

// scan --scrub replaces a configured value in the transcripts that hold it:
// a dry run first, then --apply with a backup of the originals.
func TestScanScrubsTranscripts(t *testing.T) {
	noHarness(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	value := "passess-fake-scrub-" + "Kd83Lp2Qx9Vm4Ns7"
	t.Setenv("PASSESS_TEST_SCRUB", value)
	cfg := filepath.Join(home, ".config", "passess", "config.toml")
	t.Setenv("PASSESS_CONFIG", cfg)
	session := filepath.Join(home, ".claude", "projects", "-home-u-app", "s1.jsonl")
	for path, body := range map[string]string{
		cfg:     "version = 1\n[secrets.DEMO]\nref = \"env://PASSESS_TEST_SCRUB\"\n",
		session: `{"type":"user","message":"use ` + value + `"}` + "\n" + `{"type":"assistant","message":"ok"}` + "\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(session, old, old); err != nil {
		t.Fatal(err)
	}

	out, errOut, _ := run(t, "scan", "--scrub")
	if !strings.Contains(out, "Would scrub") || !strings.Contains(out, "DEMO ×1") {
		t.Fatalf("dry run:\n%s%s", out, errOut)
	}
	if b, _ := os.ReadFile(session); !strings.Contains(string(b), value) {
		t.Fatal("the dry run changed the transcript")
	}

	out, errOut, _ = run(t, "scan", "--scrub", "--apply", "--json")
	var res scanOutput
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("%v\n%s%s", err, out, errOut)
	}
	if len(res.Scrubbed) != 1 || !res.Scrubbed[0].Written || res.Backup == "" || strings.Contains(out, value) {
		t.Fatalf("apply: %+v", res)
	}
	if b, _ := os.ReadFile(session); strings.Contains(string(b), value) || !strings.Contains(string(b), "[REDACTED:DEMO]") {
		t.Fatalf("scrubbed transcript: %s", b)
	}
	copies, _ := filepath.Glob(filepath.Join(res.Backup, "*s1.jsonl"))
	if len(copies) != 1 {
		t.Fatalf("backup %s holds %v", res.Backup, copies)
	}
	if b, _ := os.ReadFile(copies[0]); !strings.Contains(string(b), value) {
		t.Fatal("the backup is not the original")
	}

	if _, _, code := run(t, "scan", "--apply"); code != ExitUsage {
		t.Fatalf("--apply alone: exit %d", code)
	}
}

func TestScan(t *testing.T) {
	noHarness(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	// Token-shaped strings are built at run time so scanners skip this file.
	pat := "gh" + "p_" + strings.Repeat("A1b2C3d4E5", 3) + "f6G7h8"
	known := "passess-fake-known-" + "Zq8Xw2Lm9Pv4Rt7Y"
	t.Setenv("PASSESS_TEST_SCAN", known)
	cfg := filepath.Join(home, ".config", "passess", "config.toml")
	t.Setenv("PASSESS_CONFIG", cfg)
	for path, body := range map[string]string{
		cfg: "version = 1\n[secrets.DEMO]\nref = \"env://PASSESS_TEST_SCAN\"\n[secrets.GONE]\nref = \"env://PASSESS_TEST_SCAN_UNSET\"\n",
		filepath.Join(home, ".codex", "config.toml"): "[mcp_servers.gh]\ncommand = \"gh-mcp\"\n[mcp_servers.gh.env]\nGITHUB_TOKEN = \"" + pat + "\"\n",
		filepath.Join(home, ".zshrc"):                "export PATH=$HOME/bin:$PATH\nexport DEMO=" + known + "\n",
		filepath.Join(home, "proj", ".env"):          "DEBUG=true\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(filepath.Join(home, "proj"))

	out, errOut, code := run(t, "scan", "--json")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s%s", code, out, errOut)
	}
	if strings.Contains(out, pat) || strings.Contains(out, known) {
		t.Fatal("scan printed a value")
	}
	var got scanOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	var rule, knownHit bool
	for _, f := range got.Findings {
		switch {
		case f.Category == "config" && f.Kind == "rule" && f.Rule == "github-pat" && f.Line == 4:
			rule = true
		case f.Category == "dotfile" && f.Kind == "known" && f.Secret == "DEMO" && f.Line == 2:
			knownHit = true
		}
	}
	if !rule || !knownHit || got.Known != 1 || !slices.Equal(got.Unresolved, []string{"GONE"}) {
		t.Fatalf("scan = %+v", got)
	}

	human, _, _ := run(t, "scan")
	for _, want := range []string{"~/.codex/config.toml:4  rule github-pat", "~/.zshrc:2  known DEMO", "rotate", "Not searched (could not be resolved): GONE"} {
		if !strings.Contains(strings.ToLower(human), strings.ToLower(want)) {
			t.Fatalf("output lacks %q:\n%s", want, human)
		}
	}

	// Explicit paths, flags after them; the clean file finds nothing.
	if out, errOut, code := run(t, "scan", ".env", "--no-known"); code != 0 {
		t.Fatalf("clean file: exit %d\n%s%s", code, out, errOut)
	}
}
