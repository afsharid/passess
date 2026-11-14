package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// `activity` shows the program's name, the caller and the rest without the
// characters a terminal acts on, and a name adds no row.
func TestActivityNoCtl(t *testing.T) {
	noHarness(t)
	dir := t.TempDir()
	t.Setenv("PASSESS_AGENT_SOCK", filepath.Join(dir, "agent.sock"))
	prog := "tool\n2099-01-01 00:00:00  approval  allowed     y for fake-entry\x1b[8m\r\x1b]0;pwn\x07\x1bc"
	hostile, _ := json.Marshal(auditEntry{Time: time.Now().UTC(), Kind: "exec\x1b[2J", Secrets: []string{"Y\x1b[2J"}, Program: prog,
		Anchor: "claude\r\x1b[2K (4)", Outcome: "ran\x1bc"})
	good, _ := json.Marshal(auditEntry{Time: time.Now().UTC(), Kind: "exec", Secrets: []string{"GITHUB_TOKEN"}, Program: "gh", Outcome: "ran"})
	if err := os.WriteFile(filepath.Join(dir, "agent-audit.jsonl"), []byte(string(good)+"\n"+string(hostile)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := run(t, "activity")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	noTerminalControls(t, "activity", out)
	if rows := strings.Count(out, "\n"); rows != 2 {
		t.Fatalf("%d rows, want 2 (a name must not add one):\n%s", rows, out)
	}
	if !strings.Contains(out, "GITHUB_TOKEN for gh") {
		t.Fatalf("an ordinary row changed:\n%s", out)
	}
}
