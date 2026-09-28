package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A project's own .claude/settings.json decides the env key names audit
// prints. A key carrying a newline, a terminal escape or a shell character
// must not reach the report as structure: no control character is printed,
// no line starts with the key's tail, and no fix line carries it into a
// command.
func TestAuditQuotesNamesFromProjectFiles(t *testing.T) {
	noHarness(t)
	home, project := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("PASSESS_CONFIG", filepath.Join(home, ".config", "passess", "config.toml"))
	t.Setenv("PATH", t.TempDir()+string(os.PathListSeparator)+"/usr/bin:/bin")
	value := "sk-" + "passessfake" + strings.Repeat("Ab3", 6) // built at run time for scanners
	key := "REAL_NAME\nFORGED_passess_fake_LINE \x1b]0;title\x07$(id)_TOKEN"
	doc, _ := json.Marshal(map[string]any{"env": map[string]string{key: value}})
	if err := os.MkdirAll(filepath.Join(project, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".claude", "settings.json"), doc, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)

	out, errOut, _ := run(t, "audit")
	if !strings.Contains(out, "claude-settings") && !strings.Contains(out, "env.") {
		t.Fatalf("the finding is missing:\n%s%s", out, errOut)
	}
	for _, r := range out {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f {
			t.Fatalf("control character %q in the report:\n%q", r, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "FORGED") {
			t.Fatalf("a line of the key's own making:\n%s", out)
		}
		if strings.Contains(line, "passess exec -s") && strings.Contains(line, "FORGED") {
			t.Fatalf("the key reached a fix command:\n%s", out)
		}
	}
	if strings.Contains(out, value) {
		t.Fatal("audit printed a value")
	}
}
