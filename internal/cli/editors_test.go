package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestInstallEditsJSONHarnesses covers a harness passess edits itself, with
// its config kept in a dotfiles repo and linked into place.
func TestInstallEditsJSONHarnesses(t *testing.T) {
	home, calls := fakeHarnesses(t)
	real := filepath.Join(home, "dotfiles", "cursor-mcp.json")
	original := "{\n  \"mcpServers\": {\n    \"theirs\": {\"command\": \"npx\", \"args\": [\"-y\", \"thing\"]}\n  }\n}\n"
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	out, errOut, code := run(t, "install", "cursor")
	if code != 0 || !strings.Contains(out, "would add github: set it to `"+passessPath()+" mcp-exec github` in ") || !strings.Contains(out, "Dry run") {
		t.Fatalf("dry run: exit %d\n%s%s", code, out, errOut)
	}
	if got, _ := os.ReadFile(real); string(got) != original {
		t.Fatal("the dry run changed the file")
	}

	if out, errOut, code := run(t, "install", "cursor", "--apply"); code != 0 {
		t.Fatalf("install: exit %d\n%s%s", code, out, errOut)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced by a file")
	}
	got, _ := os.ReadFile(real)
	if !strings.Contains(string(got), `"github": {`) || !strings.Contains(string(got), `"command": "`+passessPath()+`"`) || !strings.Contains(string(got), `"theirs"`) {
		t.Fatalf("after install:\n%s", got)
	}
	if out, _, code := run(t, "status", "cursor"); code != 0 || !strings.Contains(out, "github         ok") {
		t.Fatalf("status: exit %d\n%s", code, out)
	}

	if out, errOut, code := run(t, "uninstall", "cursor", "--apply"); code != 0 {
		t.Fatalf("uninstall: exit %d\n%s%s", code, out, errOut)
	}
	if got, _ := os.ReadFile(real); string(got) != original {
		t.Fatalf("uninstall is not byte-identical:\n%s", got)
	}
	if readCalls(t, calls) != "" {
		t.Fatal("no harness CLI should have run for Cursor")
	}
}

func TestOwnInstructionsFileGoesOnUninstall(t *testing.T) {
	home, _ := fakeHarnesses(t)
	if err := os.MkdirAll(filepath.Join(home, ".kiro", "settings"), 0o700); err != nil {
		t.Fatal(err)
	}
	steering := filepath.Join(home, ".kiro", "steering", "passess.md")
	if out, errOut, code := run(t, "install", "kiro", "--apply"); code != 0 {
		t.Fatalf("install: exit %d\n%s%s", code, out, errOut)
	}
	if doc, err := os.ReadFile(steering); err != nil || !strings.Contains(string(doc), "passess exec") {
		t.Fatalf("steering file: %v\n%s", err, doc)
	}
	if out, errOut, code := run(t, "uninstall", "kiro", "--apply"); code != 0 {
		t.Fatalf("uninstall: exit %d\n%s%s", code, out, errOut)
	}
	if _, err := os.Stat(steering); !os.IsNotExist(err) {
		t.Fatalf("the emptied steering file stayed: %v", err)
	}
	// A shared file keeps whatever else it holds.
	claudeMD, _ := os.ReadFile(filepath.Join(home, ".claude", "CLAUDE.md"))
	if !strings.Contains(string(claudeMD), "Be brief.") {
		t.Fatal("CLAUDE.md lost the user's text")
	}
}

func TestHarnessWithoutAConfigHereIsRefused(t *testing.T) {
	fakeHarnesses(t)
	if runtime.GOOS != "linux" {
		t.Skip("Claude Desktop has a config location on this system")
	}
	if _, errOut, code := run(t, "install", "claude-desktop"); code != ExitUsage || !strings.Contains(errOut, "no config location") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}
