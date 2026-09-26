package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInventory(t *testing.T) {
	noHarness(t)
	home, calls := fakeHarnesses(t)
	t.Setenv("PASSESS_TEST_GH", "passess-fake-inventory-0123456789")
	if err := os.WriteFile(os.Getenv("PASSESS_CONFIG"), []byte(`version = 1
[backends.bws]
access_token = "keychain://passess/bws"

[secrets.GITHUB_TOKEN]
ref   = "env://PASSESS_TEST_GH"
allow = ["gh", "git"]
note  = "repo:read | rotate yearly"
[secrets.NVIDIA_API_KEY]
ref = ["bws://ai-stack/NVIDIA_API_KEY", "keychain://passess/nvidia"]
[secrets.REMOTE_TOKEN]
ref = "keychain://passess/mcp.remote.REMOTE_TOKEN"

[mcp.github]
command = ["github-mcp-server", "stdio"]
env     = { GITHUB_PERSONAL_ACCESS_TOKEN = "GITHUB_TOKEN" }
[mcp.remote]
url     = "https://mcp.example.com/mcp"
headers = { Authorization = "Bearer {{REMOTE_TOKEN}}", X-Client = "passess" }

[profiles.hermes]
secrets  = ["NVIDIA_API_KEY"]
required = ["NVIDIA_API_KEY"]
allow    = ["hermes"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "passess.toml"), []byte("version = 1\n[needs.GITHUB_TOKEN]\n[needs.STRIPE_KEY]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "auth.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, errOut, code := run(t, "inventory")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if strings.Contains(out, "passess-fake") {
		t.Fatal("inventory printed a value")
	}
	for _, want := range []string{
		"# Secret inventory",
		"| `GITHUB_TOKEN` | environment `env://PASSESS_TEST_GH` | mcp github, this project | gh, git | repo:read \\| rotate yearly |",
		"| `NVIDIA_API_KEY` | Bitwarden Secrets Manager `bws://ai-stack/NVIDIA_API_KEY`, else OS keychain `keychain://passess/nvidia` | profile hermes | any but shells and interpreters | — |",
		"This project (`~/passess.toml`) also needs: STRIPE_KEY.",
		"| Server | Runs | Credentials | Claude Code | Codex |",
		"| `github` | `github-mcp-server stdio` | GITHUB_PERSONAL_ACCESS_TOKEN ← GITHUB_TOKEN | missing | missing |",
		"| `remote` | `https://mcp.example.com/mcp` (bridged) | Authorization ← REMOTE_TOKEN | missing | missing |",
		"Claude Code still holds credentials in clear in `~/.claude.json`: `legacy` (env.API_TOKEN)",
		"| `hermes` | NVIDIA_API_KEY | NVIDIA_API_KEY | hermes |",
		"| Bitwarden Secrets Manager | machine-account access token | `keychain://passess/bws` |",
		"| `passess` | `bws` | Bitwarden Secrets Manager machine-account access token |",
		"| `passess` | `mcp.remote.REMOTE_TOKEN` | REMOTE_TOKEN |",
		"| `~/.codex/auth.json` | 0600 | Codex sign-in or OpenAI API key |",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("inventory lacks %q:\n%s", want, out)
		}
	}
	if readCalls(t, calls) != "" {
		t.Fatal("inventory must not call the harness CLIs")
	}
}
