package cli

import (
	"os"
	"strings"
	"testing"
)

// A server limited with harnesses = [...] is registered there and nowhere else.
func TestServerLimitedToOneHarness(t *testing.T) {
	_, calls := fakeHarnesses(t)
	if err := os.WriteFile(os.Getenv("PASSESS_CONFIG"), []byte(`version = 1
[secrets.GITHUB_TOKEN]
ref = "env://PASSESS_TEST_GH"
[mcp.github]
command   = ["github-mcp-server", "stdio"]
env       = { GITHUB_PERSONAL_ACCESS_TOKEN = "GITHUB_TOKEN" }
harnesses = ["codex"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, errOut, code := run(t, "install", "--apply", "--no-hooks"); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	log := readCalls(t, calls)
	if !strings.Contains(log, "codex mcp add github") || strings.Contains(log, "claude mcp add") {
		t.Fatalf("calls:\n%s", log)
	}
	if out, _, _ := run(t, "inventory"); !strings.Contains(out, "(codex only)") {
		t.Fatalf("inventory does not say where the server goes:\n%s", out)
	}

	if err := os.WriteFile(os.Getenv("PASSESS_CONFIG"), []byte("version = 1\n[mcp.x]\ncommand = [\"a\"]\nharnesses = [\"notepad\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(t, "install"); code != ExitConfig || !strings.Contains(errOut, `harnesses names "notepad"`) {
		t.Fatalf("unknown harness: exit %d: %s", code, errOut)
	}
}
