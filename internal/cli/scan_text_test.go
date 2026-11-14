package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanFixture is a home with a secret whose value sits in a .env file under
// a directory of the given name; it returns that file.
func scanFixture(t *testing.T, dirName string) (env string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	t.Setenv("PASSESS_TEST_SCAN_VALUE", "passess-fake-scan-"+"Kd83Lp2Qx9Vm4Ns7")
	cfg := filepath.Join(home, ".config", "passess", "config.toml")
	t.Setenv("PASSESS_CONFIG", cfg)
	env = filepath.Join(home, "clone", dirName, ".env")
	for path, body := range map[string]string{
		cfg: "version = 1\n[secrets.DEMO]\nref = \"env://PASSESS_TEST_SCAN_VALUE\"\nclients = [\"codex\"]\napprove = true\n",
		env: "A=1\nTOKEN=passess-fake-scan-Kd83Lp2Qx9Vm4Ns7\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Skipf("this file system refuses the name: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return env
}

// A clone names its directories and files; `scan` shows those names without
// the characters a terminal acts on, in the findings and in the errors.
func TestScanPrintsRepositoryNamesWithoutControls(t *testing.T) {
	noHarness(t)
	hostile := "pkg\x1b]0;owned\x07\n  1 finding(s) in 1 file(s) scanned; rules: none; 0 configured value(s) searched for.\x1b[8m"
	env := scanFixture(t, hostile)
	clone := filepath.Dir(filepath.Dir(env))
	out, errOut, code := run(t, "scan", "--dir", clone)
	if code != 1 {
		t.Fatalf("exit %d:\n%s%s", code, out, errOut)
	}
	noTerminalControls(t, "scan", out)
	if !strings.Contains(out, "known DEMO") || !strings.Contains(out, "  1 finding(s) in 1 file(s) scanned; rules: none; 0 configured value(s) searched for.") {
		t.Fatalf("the finding is gone:\n%s", out)
	}
	if got := strings.Count(out, "1 finding(s) in 1 file(s) scanned"); got != 2 { // the forged text stays on the path's line
		t.Fatalf("%d summary rows:\n%s", got, out)
	}
	if err := os.Chmod(env, 0); err == nil {
		out, _, _ := run(t, "scan", "--no-known", "--dir", clone)
		noTerminalControls(t, "the errors", out)
		if err := os.Chmod(env, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// JSON keeps the names as they are; it escapes them.
	jsonOut, _, _ := run(t, "scan", "--json", "--dir", clone)
	if !strings.Contains(jsonOut, `\u001b]0;owned`) {
		t.Fatalf("json:\n%s", jsonOut)
	}
}
