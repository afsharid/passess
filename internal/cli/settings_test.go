package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// settingsEnv is a config with one secret, and a run helper for it.
func settingsEnv(t *testing.T) (cfg string, run func(args ...string) (string, string, int)) {
	t.Helper()
	noHarness(t)
	cfg = filepath.Join(t.TempDir(), "passess", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("version = 1\n\n[secrets.GITHUB_TOKEN]\nref = \"env://GH\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PASSESS_CONFIG", cfg)
	return cfg, func(args ...string) (string, string, int) {
		t.Helper()
		var out, errb strings.Builder
		code := Main(args, strings.NewReader(""), &out, &errb)
		return out.String(), errb.String(), code
	}
}

func TestMCPCommands(t *testing.T) {
	cfg, run := settingsEnv(t)
	must := func(args ...string) {
		t.Helper()
		if out, errOut, code := run(args...); code != 0 {
			t.Fatalf("%v: exit %d, %q %q", args, code, out, errOut)
		}
	}
	must("mcp", "add", "github", "--command", "npx", "--command", "-y", "--command", "@x/github-mcp,with-comma",
		"--env", "GITHUB_PERSONAL_ACCESS_TOKEN=GITHUB_TOKEN", "--var", "LOG_LEVEL=info", "--harnesses", "claude,codex")
	data, _ := os.ReadFile(cfg)
	want := "[mcp.github]\ncommand = [\"npx\", \"-y\", \"@x/github-mcp,with-comma\"]\nenv = { GITHUB_PERSONAL_ACCESS_TOKEN = \"GITHUB_TOKEN\" }\nvars = { LOG_LEVEL = \"info\" }\nharnesses = [\"claude\", \"codex\"]\n"
	if !strings.Contains(string(data), want) {
		t.Fatalf("config:\n%s", data)
	}
	if _, errOut, code := run("mcp", "add", "github", "--url", "https://x.example.com/mcp"); code != ExitConfig || !strings.Contains(errOut, "already defined") {
		t.Fatalf("add twice: exit %d, %q", code, errOut)
	}
	// Switching to a remote server takes out what only a local one has.
	must("mcp", "set", "github", "--url", "https://api.githubcopilot.com/mcp/", "--header", "Authorization=Bearer {{GITHUB_TOKEN}}")
	out, _, _ := run("mcp", "list", "--json")
	var list []mcpView
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list) != 1 {
		t.Fatalf("list: %v %s", err, out)
	}
	if m := list[0]; m.URL == "" || len(m.Command) != 0 || len(m.Env) != 0 || m.Headers["Authorization"] != "Bearer {{GITHUB_TOKEN}}" ||
		len(m.Secrets) != 1 || m.Secrets[0] != "GITHUB_TOKEN" || !m.Redact {
		t.Fatalf("after set: %+v", m)
	}
	// A secret the config does not define is refused by validation.
	if _, errOut, code := run("mcp", "add", "other", "--command", "srv", "--env", "X=NOPE"); code != ExitConfig || !strings.Contains(errOut, "NOPE") {
		t.Fatalf("undefined secret: exit %d, %q", code, errOut)
	}
	// A plain value that is a credential never reaches the file.
	pat := "gh" + "p_" + strings.Repeat("A1b2C3d4E5", 3) + "f6G7h8"
	if _, errOut, code := run("mcp", "add", "leak", "--command", "srv", "--var", "TOKEN="+pat); code != ExitUsage || !strings.Contains(errOut, "credential") {
		t.Fatalf("a credential in vars: exit %d, %q", code, errOut)
	}
	if _, errOut, code := run("mcp", "set", "github", "--header", "Authorization=Bearer "+pat); code != ExitUsage || !strings.Contains(errOut, "credential") {
		t.Fatalf("a credential in a header: exit %d, %q", code, errOut)
	}
	if data, _ := os.ReadFile(cfg); strings.Contains(string(data), pat) {
		t.Fatal("the credential reached the config")
	}
	// An empty value empties a list or table, as the app sends for a cleared field.
	must("mcp", "add", "local", "--command", "srv", "--env", "T=GITHUB_TOKEN", "--inherit", "HOME")
	must("mcp", "set", "local", "--env", "", "--var", "", "--inherit", "")
	if data, _ := os.ReadFile(cfg); strings.Contains(string(data), "GITHUB_TOKEN\" }") || strings.Contains(string(data), "inherit") {
		t.Fatalf("lists not emptied:\n%s", data)
	}
	must("mcp", "remove", "local")
	must("mcp", "remove", "github")
	if data, _ := os.ReadFile(cfg); strings.Contains(string(data), "mcp") {
		t.Fatalf("after remove:\n%s", data)
	}
	t.Setenv("CLAUDECODE", "1")
	if _, _, code := run("mcp", "add", "x", "--command", "srv"); code != ExitNoPerm {
		t.Fatalf("under an agent: exit %d", code)
	}
	if _, _, code := run("mcp", "list", "--json"); code != 0 {
		t.Fatalf("list under an agent: exit %d", code)
	}
}

func TestProfileCommands(t *testing.T) {
	cfg, run := settingsEnv(t)
	if out, errOut, code := run("profile", "add", "web", "--secrets", "GITHUB_TOKEN", "--allow", "node,npm", "--env", "NODE_ENV=development"); code != 0 {
		t.Fatalf("add: exit %d, %q %q", code, out, errOut)
	}
	data, _ := os.ReadFile(cfg)
	if !strings.Contains(string(data), "[profiles.web]\nsecrets = [\"GITHUB_TOKEN\"]\nallow = [\"node\", \"npm\"]\nenv = { NODE_ENV = \"development\" }\n") {
		t.Fatalf("config:\n%s", data)
	}
	// The config's own validation still applies: a profile names its programs.
	if _, errOut, code := run("profile", "set", "web", "--allow", ""); code != ExitConfig || !strings.Contains(errOut, "programs") {
		t.Fatalf("no programs: exit %d, %q", code, errOut)
	}
	if _, errOut, code := run("profile", "set", "web", "--tty", "--allow", "node"); code != 0 {
		t.Fatalf("set: exit %d, %q", code, errOut)
	}
	out, _, _ := run("profile", "list", "--json")
	var list []profileView
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list) != 1 || !list[0].TTY || len(list[0].Allow) != 1 || list[0].Run != "passess run web -- COMMAND" {
		t.Fatalf("list: %v %s", err, out)
	}
	if _, errOut, code := run("profile", "add", "api", "--secrets", "MISSING"); code != ExitConfig || !strings.Contains(errOut, "MISSING") {
		t.Fatalf("undefined secret: exit %d, %q", code, errOut)
	}
	if _, _, code := run("profile", "add", "none"); code != ExitUsage {
		t.Fatalf("no secrets: exit %d", code)
	}
	if _, _, code := run("profile", "remove", "web"); code != 0 {
		t.Fatalf("remove: exit %d", code)
	}
}

func TestAgentConfig(t *testing.T) {
	cfg, run := settingsEnv(t)
	out, _, code := run("agent", "config", "--json")
	var v agentConfigView
	if code != 0 || json.Unmarshal([]byte(out), &v) != nil || v.ApprovalTTL != "8h0m0s" {
		t.Fatalf("defaults: exit %d, %s", code, out)
	}
	if _, errOut, code := run("agent", "config", "--cache-ttl", "5m", "--approval-ttl", "0"); code != 0 {
		t.Fatalf("set: exit %d, %q", code, errOut)
	}
	data, _ := os.ReadFile(cfg)
	if !strings.Contains(string(data), "[agent]\napproval_ttl = \"0\"\ncache_ttl = \"5m\"\n") {
		t.Fatalf("config:\n%s", data)
	}
	if _, _, code := run("agent", "config", "--cache-ttl", "soon"); code != ExitUsage {
		t.Fatalf("a bad duration: exit %d", code)
	}
	if _, _, code := run("agent", "config", "--cache-ttl", ""); code != 0 {
		t.Fatalf("back to the default: exit %d", code)
	}
	if data, _ := os.ReadFile(cfg); strings.Contains(string(data), "cache_ttl") {
		t.Fatalf("cache_ttl stayed:\n%s", data)
	}
	t.Setenv("CLAUDECODE", "1")
	if _, _, code := run("agent", "config", "--approval-ttl", "999h"); code != ExitNoPerm {
		t.Fatalf("under an agent: exit %d", code)
	}
}
