package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/agent"
)

// A credential can sit in an MCP entry's arguments or URL, which the
// classifier does not look at. A coding agent that previews the move, or
// reads the status, does not get them; the user does.
func TestHarnessEntryArgsAndURLAreWithheldFromAnAgent(t *testing.T) {
	noHarness(t)
	fakeKeychain(t)
	home, _ := fakeHarnesses(t)
	dsn := "postgresql://app:passess-fake-dsnpw-77@db.internal/prod"
	key := "--api-key=passess-fake-argkey-0011223344556677"
	urlWithToken := "https://mcp.example.com/sse?token=passess-fake-urltoken-99887766"
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {
  "srv": {"command": "npx", "args": ["-y", "pkg", "--dsn", "`+dsn+`", "`+key+`"], "env": {"API_TOKEN": "passess-fake-legacy-0123456789abcdef"}},
  "other": {"args": ["--api-key=passess-fake-statuskey-0011223344556677"], "url": "`+urlWithToken+`"}
}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets := []string{"passess-fake-dsnpw-77", "passess-fake-argkey", "passess-fake-urltoken", "passess-fake-statuskey", "passess-fake-legacy"}
	leaks := func(text string) string {
		for _, s := range secrets {
			if strings.Contains(text, s) {
				return s
			}
		}
		return ""
	}

	// The user at a terminal sees the whole entry.
	out, _, code := run(t, "migrate", "mcp", "claude", "srv")
	if code != 0 || !strings.Contains(out, dsn) || !strings.Contains(out, key) || strings.Contains(out, "withheld") {
		t.Fatalf("the user's preview: exit %d\n%s", code, out)
	}
	statusOut, _, _ := run(t, "status", "--json", "claude")
	if !strings.Contains(statusOut, key) || !strings.Contains(statusOut, "passess-fake-urltoken") {
		t.Fatalf("the user's status:\n%s", statusOut)
	}

	for name, chain := range map[string][]agent.Proc{
		"ancestor": {{Name: "passess"}, {Name: "zsh"}, {Name: "claude"}},
		"marker":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			underChain(t, chain...)
			if name == "marker" {
				t.Setenv("CLAUDECODE", "1")
			}
			out, errOut, code := run(t, "migrate", "mcp", "claude", "srv")
			if code != 0 || leaks(out+errOut) != "" || !strings.Contains(out, "env.API_TOKEN -> API_TOKEN") || !strings.Contains(out, "withheld") || !strings.Contains(out, `"npx"`) {
				t.Fatalf("preview: exit %d, leaks %q\n%s%s", code, leaks(out+errOut), out, errOut)
			}
			for _, args := range [][]string{{"status", "--json", "claude"}, {"status", "claude"}, {"status", "--json"}} {
				out, errOut, _ := run(t, args...)
				if leaks(out+errOut) != "" || strings.Contains(out, "--api-key") {
					t.Fatalf("%v leaks %q:\n%s%s", args, leaks(out+errOut), out, errOut)
				}
			}
			out, _, _ = run(t, "status", "--json", "claude")
			if !strings.Contains(out, `"name": "other"`) {
				t.Fatalf("the unmanaged entries are gone from the status:\n%s", out)
			}
		})
	}
}
