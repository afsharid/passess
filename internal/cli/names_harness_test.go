package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/agent"
)

// A harness file names its entries and env variables; status, the migrate
// preview and the inventory show them without control or bidi characters.
func TestHarnessEntryNamesPrintWithoutControls(t *testing.T) {
	noHarness(t)
	fakeKeychain(t)
	home, _ := fakeHarnesses(t)
	body := `{"mcpServers": {"srv\u001b[2Jx\u202e": {"command": "npx", "env": {"K\u001b[2K_TOKEN\u202e": "passess-fake-legacy-0123456789abcdef", "API_TOKEN": "passess-fake-legacy-abcdef0123456789"}}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"status", "claude"}, {"inventory"}, {"migrate", "mcp", "claude", "srv\x1b[2Jx\u202e"}} {
		out, errOut, _ := run(t, args...)
		if !strings.Contains(out, "API_TOKEN") {
			t.Fatalf("%v: the entry is not shown:\n%s%s", args, out, errOut)
		}
		noTerminalControls(t, strings.Join(args, " "), out+errOut)
	}
}

// Under an agent, `scan` says in one sentence what to do instead.
func TestScanRefusalSaysWhatToDoOnce(t *testing.T) {
	noHarness(t)
	underChain(t, agent.Proc{Name: "passess"}, agent.Proc{Name: "zsh"}, agent.Proc{Name: "claude"})
	_, errOut, code := run(t, "scan")
	if code != ExitNoPerm || !strings.Contains(errOut, "--no-known") || strings.Count(errOut, "yourself") > 1 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}
