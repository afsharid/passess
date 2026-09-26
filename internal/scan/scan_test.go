package scan

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/redact"
	"github.com/afsharid/passess/internal/secret"
)

// Token-shaped strings are built at run time so secret scanners do not flag
// this source file.
var (
	githubPAT = "gh" + "p_" + strings.Repeat("A1b2C3d4E5", 3) + "f6G7h8"
	knownVal  = "passess-fake-known-" + "Zq8Xw2Lm9Pv4Rt7Y"
)

func rules(t *testing.T) *Rules {
	t.Helper()
	rs, err := DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestDefaultRulesLoad(t *testing.T) {
	if n := rules(t).Len(); n < 200 {
		t.Fatalf("only %d rules loaded", n)
	}
}

// TestVendoredRulesArePinned makes a rules update visible in review (ADR 5):
// refresh from upstream on purpose, then update RulesVersion and these values.
func TestVendoredRulesArePinned(t *testing.T) {
	sum := sha256.Sum256(gitleaksRules)
	if got := hex.EncodeToString(sum[:]); got != "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf" {
		t.Fatalf("rules/gitleaks.toml changed (sha256 %s); update RulesVersion and this pin", got)
	}
	if n := strings.Count(string(gitleaksRules), "\n[[rules]]\n"); n != 222 {
		t.Fatalf("rules/gitleaks.toml has %d rules, pinned 222", n)
	}
}

func TestRuleFindsTokenAndIgnoresProse(t *testing.T) {
	rs := rules(t)
	got := rs.Line("notes.txt", "token: "+githubPAT+"\n")
	if len(got) != 1 || got[0].Rule != "github-pat" || got[0].Secret != githubPAT {
		t.Fatalf("matches = %+v", got)
	}
	if got := rs.Line("notes.txt", "The quick brown fox jumps over the lazy dog, twice.\n"); len(got) != 0 {
		t.Fatalf("prose matched: %+v", got)
	}
	if got := rs.Line("app/node_modules/pkg/index.js", "token: "+githubPAT); len(got) != 0 {
		t.Fatalf("globally allowed path matched: %+v", got)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileFindsKnownAndRuleSecretsByLine(t *testing.T) {
	rd, _, err := redact.New([]redact.Secret{{Name: "MY_TOKEN", Value: secret.FromString(knownVal)}}, redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := &Scanner{Known: rd, Rules: rules(t)}
	s.KnownFP = map[string]string{"MY_TOKEN": s.Fingerprint([]byte(knownVal))}
	path := filepath.Join(t.TempDir(), "session.jsonl")
	writeFile(t, path, strings.Join([]string{
		`{"role":"user","text":"hello"}`,
		`{"role":"tool","text":"export MY_TOKEN=` + knownVal + `"}`,
		`{"role":"tool","text":"b64 ` + base64.StdEncoding.EncodeToString([]byte(knownVal)) + `"}`,
		`{"role":"assistant","text":"use ` + githubPAT + `"}`,
	}, "\n")+"\n")
	got, err := s.File(Target{Path: path, Category: "transcript"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("findings = %+v", got)
	}
	if got[0].Line != 2 || got[0].Kind != "known" || got[0].Secret != "MY_TOKEN" || got[0].Fingerprint != s.Fingerprint([]byte(knownVal)) || got[0].Length != 0 {
		t.Fatalf("known finding = %+v", got[0])
	}
	if got[1].Line != 3 || got[1].Kind != "known" {
		t.Fatalf("base64 variant = %+v", got[1])
	}
	if got[2].Line != 4 || got[2].Kind != "rule" || got[2].Rule != "github-pat" || got[2].Length != len(githubPAT) {
		t.Fatalf("rule finding = %+v", got[2])
	}
	for _, f := range got {
		if strings.Contains(f.Fingerprint, knownVal) || strings.Contains(f.Fingerprint, githubPAT) {
			t.Fatal("a finding carries a value")
		}
	}
}

func TestFingerprintsAreKeyedPerScanner(t *testing.T) {
	a, b := &Scanner{}, &Scanner{}
	v := []byte("passess-fake-short-pw")
	if first := a.Fingerprint(v); first != a.Fingerprint(append([]byte{}, v...)) {
		t.Fatal("one scanner must give one value one fingerprint")
	}
	if a.Fingerprint(v) == b.Fingerprint(v) {
		t.Fatal("two scanners gave the same fingerprint: it is not keyed")
	}
	sum := sha256.Sum256(v)
	if a.Fingerprint(v) == hex.EncodeToString(sum[:6]) {
		t.Fatal("the fingerprint is a plain hash of the value")
	}
}

func TestBinaryFilesAreSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob.bin")
	writeFile(t, path, "\x00\x01\x02 token: "+githubPAT)
	got, err := (&Scanner{Rules: rules(t)}).File(Target{Path: path})
	if err != nil || len(got) != 0 {
		t.Fatalf("binary file: %+v %v", got, err)
	}
}

func TestDiscover(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	for _, p := range []string{".claude.json", ".codex/config.toml", ".zshrc", ".kiro/agents/crew.json",
		".claude/projects/p/1.jsonl", ".codex/sessions/2026/09/26/r.jsonl", ".codex/history.jsonl",
		".claude.json.backup", ".claude/backups/.claude.json.backup.1790420106981", ".codex/config.toml.backup-20260801-210842",
		"state/backups/20260926-120000.000/00-Users_x_.env", "state/backups/20260926-120000.000/manifest.json"} {
		writeFile(t, filepath.Join(home, p), "x\n")
	}
	for _, p := range []string{".env", ".env.local", ".env.example", "api/.env.production", "node_modules/pkg/.env", "a/b/c/d/e/.env"} {
		writeFile(t, filepath.Join(project, p), "x\n")
	}
	count := func(ts []Target, category string) (n int, paths []string) {
		for _, t := range ts {
			if t.Category == category {
				n++
				paths = append(paths, t.Path)
			}
		}
		return n, paths
	}
	ts := Discover(Where{Home: home, Dir: project, Backups: filepath.Join(home, "state", "backups")})
	if n, _ := count(ts, "config"); n != 3 {
		t.Fatalf("configs = %d", n)
	}
	if n, _ := count(ts, "dotfile"); n != 1 {
		t.Fatalf("dotfiles = %d", n)
	}
	if n, paths := count(ts, "env"); n != 3 {
		t.Fatalf("env files = %v", paths)
	}
	if n, paths := count(ts, "backup"); n != 4 {
		t.Fatalf("backups = %v", paths)
	}
	if n, _ := count(ts, "transcript"); n != 0 {
		t.Fatal("transcripts only when asked")
	}
	if n, paths := count(Discover(Where{Home: home, Dir: project, Transcripts: true}), "transcript"); n != 3 {
		t.Fatalf("transcripts = %v", paths)
	}
}
