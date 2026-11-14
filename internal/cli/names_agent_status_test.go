package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/afsharid/passess/internal/agent"
)

// The text view of `agent status` spells out an approved program's, a
// secret's and a caller's name.
func TestPrintInfoSpellsOutApprovedNames(t *testing.T) {
	var b bytes.Buffer
	printInfo(&b, &agent.Info{Started: time.Now(), CacheTTL: "0s", Approvals: []agent.Approval{
		{Secret: "S" + bidiName, Program: bidiName, Anchor: agent.Proc{PID: 3, Name: "claude" + bidiName}, Until: time.Now().Add(time.Hour)},
		{Secret: "GITHUB_TOKEN", Program: "gh", Anchor: agent.Proc{PID: 4, Name: "claude"}, Until: time.Now().Add(time.Hour)},
	}})
	noTerminalControls(t, "agent status", b.String())
	if !strings.Contains(b.String(), "GITHUB_TOKEN for gh, asked by claude (pid 4)") {
		t.Fatalf("an ordinary Allow changed:\n%s", b.String())
	}
}
