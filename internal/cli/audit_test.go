package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditCommand(t *testing.T) {
	noHarness(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("PASSESS_CONFIG", filepath.Join(home, ".config", "passess", "config.toml"))
	t.Setenv("PATH", t.TempDir()+string(os.PathListSeparator)+"/usr/bin:/bin")
	key := "sk-" + "proj-passessfake" + strings.Repeat("Ab3", 8) // built at run time for scanners
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export OPENAI_API_KEY="+key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(home)

	out, errOut, code := run(t, "audit")
	if code != 1 || !strings.Contains(out, "~/.zshrc:1: OPENAI_API_KEY is set in clear") || !strings.Contains(out, "fix: passess add OPENAI_API_KEY --keychain") {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	if strings.Contains(out, key) {
		t.Fatal("audit printed a value")
	}
	out, _, _ = run(t, "audit", "--json")
	var got auditOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil || len(got.Findings) == 0 || got.Findings[0].Check != "dotfile-credential" {
		t.Fatalf("json = %s (%v)", out, err)
	}
	if _, _, code := run(t, "audit", "extra"); code != ExitUsage {
		t.Fatalf("extra argument: exit %d", code)
	}
}
