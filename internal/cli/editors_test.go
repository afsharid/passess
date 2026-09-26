package cli

import (
	"os"
	"path/filepath"
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
