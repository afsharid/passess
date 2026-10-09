package cli

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/agent"
)

// Under a harness, passess add and passess uninstall --apply are the user's
// to run; and nobody may add a second name for a reference another secret
// already has, since the alias would bring an allow list and approval
// setting of its own.
func TestAddUnderAHarness(t *testing.T) {
	noHarness(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	t.Setenv("PASSESS_CONFIG", cfg)
	body := "version = 1\n[secrets.PROD]\nref = \"keychain://passess/PROD\"\nallow = [\"deploy\"]\napprove = true\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// An alias of PROD's reference is refused for anyone.
	if _, errOut, code := run(t, "add", "EVIL", "--ref", "keychain://passess/PROD", "--allow", "curl"); code != ExitConfig ||
		!strings.Contains(errOut, "secrets.PROD") {
		t.Fatalf("alias: exit %d, %q", code, errOut)
	}
	// A new reference is fine for a person.
	if _, errOut, code := run(t, "add", "OTHER", "--ref", "env://PASSESS_TEST_OTHER"); code != 0 {
		t.Fatalf("add: exit %d, %q", code, errOut)
	}

	t.Setenv("CLAUDECODE", "1")
	if _, errOut, code := run(t, "add", "THIRD", "--ref", "env://PASSESS_TEST_THIRD"); code != ExitNoPerm ||
		!strings.Contains(errOut, "yourself") {
		t.Fatalf("add under a harness: exit %d, %q", code, errOut)
	}
	if _, errOut, code := run(t, "uninstall", "--apply"); code != ExitNoPerm || !strings.Contains(errOut, "yourself") {
		t.Fatalf("uninstall --apply under a harness: exit %d, %q", code, errOut)
	}
	data, _ := os.ReadFile(cfg)
	if strings.Contains(string(data), "EVIL") || strings.Contains(string(data), "THIRD") {
		t.Fatalf("a refused add changed the config:\n%s", data)
	}
}

// The commands that move values or take the hooks away see an agent the way
// the commands that hand secrets out do: Kiro sets no marker, and a command
// cleared of markers still has its ancestors.
func TestSetupCommandsRefuseAnAgentAmongAncestors(t *testing.T) {
	home, calls := fakeHarnesses(t)
	stored := fakeKeychain(t)
	if err := os.MkdirAll(filepath.Join(home, "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "app", ".env"), []byte("API_KEY=passess-fake-apikey-0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := readTree(t, home)
	underChain(t, agent.Proc{Name: "passess"}, agent.Proc{Name: "zsh"}, agent.Proc{Name: "kiro-cli-chat"})
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"migrate", "env", "app/.env", "--apply", "--yes"}, "not from kiro"},
		{[]string{"migrate", "mcp", "claude", "legacy", "--apply", "--yes"}, "not from kiro"},
		{[]string{"uninstall", "--apply"}, "guard kiro sessions"},
		{[]string{"install", "--apply", "--no-hooks"}, "guard kiro sessions"},
		{[]string{"install", "--apply", "--force"}, "not from kiro"},
		{[]string{"agent", "approve"}, "inside kiro"},
	} {
		if _, errOut, code := run(t, c.args...); code != ExitNoPerm || !strings.Contains(errOut, c.want) {
			t.Fatalf("%q from Kiro: exit %d, %q", c.args, code, errOut)
		}
	}
	if after := readTree(t, home); !maps.Equal(after, before) {
		t.Fatalf("Kiro changed files:\nbefore %v\nafter  %v", slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
	}
	if log := readCalls(t, calls); log != "" || len(stored) != 0 {
		t.Fatalf("Kiro ran a harness CLI or stored a value: %q, %v", log, slices.Sorted(maps.Keys(stored)))
	}
}

// readTree returns the contents of every file under dir, by path.
func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		files[path] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
