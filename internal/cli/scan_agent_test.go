package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/agent"
)

// Matching the configured values resolves secrets the agent may not use and
// names the line of a guess that is right: a coding agent gets only the scan
// that does not.
func TestScanKnownValuesAreNotForAnAgent(t *testing.T) {
	noHarness(t)
	env := scanFixture(t, "pkg")
	dir := filepath.Dir(filepath.Dir(env))
	for name, chain := range map[string][]agent.Proc{
		"ancestor": {{Name: "passess"}, {Name: "zsh"}, {Name: "claude"}},
		"marker":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			underChain(t, chain...)
			if name == "marker" {
				t.Setenv("CLAUDECODE", "1")
			}
			for _, args := range [][]string{
				{"scan", "--json", env},
				{"scan", "--dir", dir},
				{"scan", "--scrub"},
				{"scan", "--transcripts"},
			} {
				out, errOut, code := run(t, args...)
				if code != ExitNoPerm || strings.Contains(out+errOut, "DEMO") || strings.Contains(out, "known") {
					t.Fatalf("%v: exit %d\n%s%s", args, code, out, errOut)
				}
			}
			// Without the values nothing is resolved, and the rules still run.
			out, errOut, code := run(t, "scan", "--no-known", "--json", env)
			var got scanOutput
			if json.Unmarshal([]byte(out), &got) != nil || code != 0 || got.Known != 0 || len(got.Unresolved) != 0 {
				t.Fatalf("--no-known: exit %d\n%s%s", code, out, errOut)
			}
		})
	}
	// Control: the user, at a terminal, still finds the value.
	underChain(t)
	out, errOut, code := run(t, "scan", "--json", env)
	var got scanOutput
	if json.Unmarshal([]byte(out), &got) != nil || code != 1 || got.Known != 1 || len(got.Findings) != 1 || got.Findings[0].Secret != "DEMO" {
		t.Fatalf("at a terminal: exit %d\n%s%s", code, out, errOut)
	}
}
