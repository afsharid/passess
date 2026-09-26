package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverFollowsXDGAndLinks(t *testing.T) {
	home, xdg := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(xdg, "zed", "settings.json"), "x\n")
	writeFile(t, filepath.Join(home, ".config", "zed", "settings.json"), "x\n") // not read: XDG_CONFIG_HOME wins
	writeFile(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "x\n")
	if err := os.MkdirAll(filepath.Join(xdg, "devin"), 0o700); err != nil {
		t.Fatal(err)
	}
	// One file reachable by two known paths is scanned once.
	if err := os.Symlink(filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), filepath.Join(xdg, "devin", "mcp_config.json")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, ".gemini", "antigravity-cli", "history.jsonl"), "x\n")
	writeFile(t, filepath.Join(home, ".gemini", "antigravity-cli", "brain", "notes.jsonl"), "x\n")

	got := map[string]string{}
	for _, tg := range Discover(Where{Home: home, ConfigHome: xdg, Transcripts: true}) {
		got[tg.Path] = tg.Category
	}
	for path, want := range map[string]string{
		filepath.Join(xdg, "zed", "settings.json"):                         "config",
		filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"):     "config",
		filepath.Join(home, ".gemini", "antigravity-cli", "history.jsonl"): "transcript",
	} {
		if got[path] != want {
			t.Errorf("%s: %q, want %q", path, got[path], want)
		}
	}
	for _, path := range []string{
		filepath.Join(home, ".config", "zed", "settings.json"),
		filepath.Join(xdg, "devin", "mcp_config.json"),
		filepath.Join(home, ".gemini", "antigravity-cli", "brain", "notes.jsonl"),
	} {
		if c, ok := got[path]; ok {
			t.Errorf("%s should not be scanned (got %s)", path, c)
		}
	}
}
