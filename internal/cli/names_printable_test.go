package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const bidiName = "x\x1b[2Jy\u202e\u2028z\u200b"

// printable drops the characters visible() spells out: control, bidi,
// zero-width and line-separator runes, and keeps a tab.
func TestPrintableDropsWhatVisibleSpellsOut(t *testing.T) {
	if got := printable("gh" + bidiName + "\tok"); got != "ghx[2Jyz\tok" {
		t.Fatalf("printable = %q", got)
	}
	noTerminalControls(t, "printable", printable(bidiName+"\u2029\u061c\u2060"))
	if printable("é ünï-名") != "é ünï-名" {
		t.Fatal("printable changed an ordinary name")
	}
}

// The activity view drops bidi, zero-width and line-separator runes too.
func TestActivityBidi(t *testing.T) {
	noHarness(t)
	dir := t.TempDir()
	t.Setenv("PASSESS_AGENT_SOCK", filepath.Join(dir, "agent.sock"))
	line := `{"time":"` + time.Now().UTC().Format(time.RFC3339) + `","kind":"exec","secrets":["A\u202eB"],"program":"gh\u202e\u2028x\u200b","outcome":"ran"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "agent-audit.jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := run(t, "activity")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	noTerminalControls(t, "activity", out)
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("a separator added a row:\n%q", out)
	}
}
