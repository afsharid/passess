package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/harness"
)

// Token-shaped strings are built at run time so secret scanners skip this file.
var (
	openaiKey = "sk-" + "proj-passessfake" + strings.Repeat("Ab3", 8)
	hfToken   = "hf_" + "passessfake" + strings.Repeat("Zx9", 8)
)

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // umask
		t.Fatal(err)
	}
}

func byCheck(fs []Finding) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range fs {
		out[f.Check] = append(out[f.Check], f)
	}
	return out
}

func noValues(t *testing.T, fs []Finding) {
	t.Helper()
	for _, f := range fs {
		for _, v := range []string{openaiKey, hfToken, "passess-fake"} {
			if strings.Contains(f.Detail+f.Fix, v) {
				t.Fatalf("finding shows a value: %+v", f)
			}
		}
	}
}

func TestAudit(t *testing.T) {
	home := t.TempDir()
	codexHome := filepath.Join(home, ".codex")
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"env": {"ANTHROPIC_API_KEY": "passess-fake-anthropic", "DEBUG": "1", "GH_TOKEN": "${GH_TOKEN}"}}`, 0o644)
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {
  "leaky": {"command": "npx", "env": {"API_TOKEN": "passess-fake-inline-0123456789abcdef"}},
  "fine": {"command": "passess", "args": ["mcp-exec", "fine"]}}}`, 0o600)
	write(t, filepath.Join(codexHome, "config.toml"), "model = \"o3\"\n", 0o600)
	write(t, filepath.Join(codexHome, "auth.json"), "{}", 0o600)
	write(t, filepath.Join(home, ".zshrc"), "export PATH=$HOME/bin:$PATH\nexport OPENAI_API_KEY="+openaiKey+"\nexport GITHUB_TOKEN=$(gh auth token)\nexport NPM_TOKEN=${NPM_TOKEN_FROM_VAULT}\n", 0o644)
	write(t, filepath.Join(home, ".config", "fish", "config.fish"), "set -gx EDITOR vim\nset -gx HF_TOKEN "+hfToken+"\n", 0o600)
	write(t, filepath.Join(home, ".config", "opencode", "opencode.jsonc"), "{}", 0o644)
	cfg := filepath.Join(home, ".config", "passess", "config.toml")
	write(t, cfg, "version = 1\n", 0o600)
	t.Setenv("PATH", t.TempDir()) // no harness binaries: installed means "has a config"

	in := Input{
		Home: home, Dir: home, Config: cfg,
		Environ:  []string{"HOME=" + home, "OPENAI_API_KEY=passess-fake-env", "EMPTY_TOKEN=", "EDITOR=vim"},
		Adapters: []harness.Adapter{harness.Claude{Home: home}, harness.Codex{Home: home, CodexHome: codexHome}},
	}
	fs, errs := Run(in)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	noValues(t, fs)
	got := byCheck(fs)

	if f := got["claude-settings-env"]; len(f) != 1 || !strings.Contains(f[0].Detail, "env.ANTHROPIC_API_KEY") {
		t.Fatalf("claude settings = %+v", f)
	}
	if f := got["mcp-inline"]; len(f) != 1 || f[0].Fix != "passess migrate mcp claude leaky" {
		t.Fatalf("mcp inline = %+v", f)
	}
	if f := got["codex-shell-env"]; len(f) != 1 || !strings.Contains(f[0].Fix, "ignore_default_excludes = false") {
		t.Fatalf("codex = %+v", f)
	}
	dot := got["dotfile-credential"]
	if len(dot) != 2 || dot[0].Line != 2 || !strings.Contains(dot[0].Detail, "OPENAI_API_KEY") || !strings.Contains(dot[1].Detail, "HF_TOKEN") {
		t.Fatalf("dotfiles = %+v", dot)
	}
	if f := got["environment"]; len(f) != 1 || !strings.Contains(f[0].Detail, ": OPENAI_API_KEY.") {
		t.Fatalf("environment = %+v", f)
	}
	perms := map[string]bool{}
	for _, f := range got["permissions"] {
		perms[strings.TrimPrefix(f.Path, home+"/")] = true
	}
	if len(perms) != 2 || !perms[".claude/settings.json"] || !perms[".config/opencode/opencode.jsonc"] { // dotfiles are 0644 by custom
		t.Fatalf("permissions = %v", perms)
	}
}

func TestCodexPolicies(t *testing.T) {
	for name, c := range map[string]struct {
		body  string
		check string // "" means no finding
	}{
		"no policy":         {"", "codex-shell-env"},
		"excludes ignored":  {"[shell_environment_policy]\ninherit = \"all\"\n", "codex-shell-env"},
		"no password rule":  {"[shell_environment_policy]\nignore_default_excludes = false\n", "codex-shell-env-password"},
		"fixed":             {"[shell_environment_policy]\nignore_default_excludes = false\nexclude = [\"*password*\", \"*PASSWD*\"]\n", ""},
		"core only":         {"[shell_environment_policy]\ninherit = \"core\"\n", ""},
		"credential in set": {"[shell_environment_policy]\ninherit = \"none\"\nset = { API_TOKEN = \"passess-fake-set\", MODE = \"ci\" }\n", "codex-shell-env-set"},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			write(t, filepath.Join(home, ".codex", "config.toml"), c.body, 0o600)
			fs, err := codexShellEnv(Input{Home: home, Adapters: []harness.Adapter{harness.Codex{Home: home}}})
			if err != nil {
				t.Fatal(err)
			}
			noValues(t, fs)
			switch {
			case c.check == "" && len(fs) != 0:
				t.Fatalf("unexpected findings: %+v", fs)
			case c.check != "" && (len(fs) != 1 || fs[0].Check != c.check):
				t.Fatalf("findings = %+v, want one %s", fs, c.check)
			}
		})
	}
	// Not installed and no config: nothing to say.
	t.Setenv("PATH", t.TempDir())
	if fs, _ := codexShellEnv(Input{Home: t.TempDir(), Adapters: []harness.Adapter{harness.Codex{Home: t.TempDir()}}}); len(fs) != 0 {
		t.Fatalf("findings without Codex: %+v", fs)
	}
}
