package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

// The false positives the first run on a real machine turned up.
func TestRealRunFalsePositives(t *testing.T) {
	home := t.TempDir()
	digests := "3f2a" + strings.Repeat("9c1e7b5d", 7) + "a1," + "7d04" + strings.Repeat("e6b2c8f0", 7) + "c3"
	write(t, filepath.Join(home, ".codex", "config.toml"),
		"[shell_environment_policy]\nignore_default_excludes = false\nexclude = [\"*PASSWORD*\", \"*PASSWD*\"]\n"+
			"[shell_environment_policy.set]\nNODE_REPL_TRUSTED_BROWSER_CLIENT_SHA256S = \""+digests+"\"\n", 0o600)
	write(t, filepath.Join(home, ".zshrc"), "export GOOGLE_CLOUD_PROJECT=gen-lang-client-0816463281\n", 0o600)
	write(t, filepath.Join(home, ".kiro", "agents", "kirocrew.json"), `{"name": "kirocrew", "includeMcpJson": true, "mcpServers": {"fs": {"command": "npx"}}}`, 0o644)
	write(t, filepath.Join(home, ".kiro", "agents", "leaky.json"), `{"name": "leaky", "includeMcpJson": true,
  "mcpServers": {"gh": {"command": "gh-mcp", "env": {"GITHUB_TOKEN": "passess-fake-kiro-0123456789abcdef"}}}}`, 0o644)
	t.Setenv("PATH", t.TempDir())

	fs, errs := Run(Input{
		Home: home, Dir: home, Harness: "claude-code",
		Environ:  []string{"CLAUDE_CODE_MESSAGING_TOKEN=passess-fake-harness-own-0123", "OPENAI_API_KEY=passess-fake-user-0123456789"},
		Adapters: nil,
	})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	got := byCheck(fs)
	if f := got["codex-shell-env-set"]; len(f) != 0 {
		t.Errorf("a list of SHA-256 sums was taken for a credential: %+v", f)
	}
	if f := got["dotfile-credential"]; len(f) != 0 {
		t.Errorf("a project ID was taken for a credential: %+v", f)
	}
	env := got["environment"]
	if len(env) != 1 || strings.Contains(env[0].Detail, "CLAUDE_CODE_MESSAGING_TOKEN") || !strings.Contains(env[0].Detail, "OPENAI_API_KEY") ||
		!strings.Contains(env[0].Detail, "leaving out 1 it sets for itself") {
		t.Errorf("environment = %+v", env)
	}
	modes := map[string]bool{}
	for _, f := range got["permissions"] {
		modes[filepath.Base(f.Path)] = true
	}
	if modes["kirocrew.json"] || !modes["leaky.json"] {
		t.Errorf("Kiro profile modes: %v (only a profile holding a credential should be reported)", modes)
	}
}
