package cli

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
