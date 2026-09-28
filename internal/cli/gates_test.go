package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
