package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/secret"
)

// fakeKeychain replaces the OS keychain for the test.
func fakeKeychain(t *testing.T) map[string]string {
	t.Helper()
	var mu sync.Mutex
	stored := map[string]string{}
	old := keychainStore
	keychainStore = func(*Streams) func(context.Context, string, string, secret.Value) error {
		return func(_ context.Context, service, account string, v secret.Value) error {
			mu.Lock()
			defer mu.Unlock()
			stored[service+"/"+account] = string(v.Bytes())
			return nil
		}
	}
	t.Cleanup(func() { keychainStore = old })
	return stored
}

func TestMigrateEnv(t *testing.T) {
	noHarness(t)
	stored := fakeKeychain(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	t.Setenv("PASSESS_CONFIG", filepath.Join(home, ".config", "passess", "config.toml"))
	project := filepath.Join(home, "My App")
	envPath := filepath.Join(project, ".env")
	body := "# app settings\nAPI_KEY=passess-fake-apikey-0123456789abcdef\nDEBUG=true\nDATABASE_URL=postgres://app:passess-fake-dbpw@db/app\nEMPTY_SECRET=\nSESSION_SECRET=${API_KEY}\n"
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)

	out, errOut, code := run(t, "migrate", "env", ".env")
	if code != 0 || !strings.Contains(out, "API_KEY (line 2) -> keychain://passess/my-app.API_KEY") || !strings.Contains(out, "DATABASE_URL (line 4)") ||
		!strings.Contains(out, "skip SESSION_SECRET (line 6): refers to another variable") || !strings.Contains(out, "Dry run") {
		t.Fatalf("dry run: exit %d\n%s%s", code, out, errOut)
	}
	if strings.Contains(out, "DEBUG") || len(stored) != 0 {
		t.Fatalf("dry run moved something or listed a non-secret:\n%s", out)
	}
	if got, _ := os.ReadFile(envPath); string(got) != body {
		t.Fatal("dry run changed the file")
	}

	t.Setenv("CLAUDECODE", "1")
	if _, errOut, code := run(t, "migrate", "env", ".env", "--apply", "--yes"); code != ExitNoPerm || !strings.Contains(errOut, "yourself") {
		t.Fatalf("under a harness: exit %d: %s", code, errOut)
	}
	t.Setenv("CLAUDECODE", "")

	out, errOut, code = run(t, "migrate", "env", ".env", "--apply", "--yes")
	if code != 0 {
		t.Fatalf("apply: exit %d\n%s%s", code, out, errOut)
	}
	if stored["passess/my-app.API_KEY"] != "passess-fake-apikey-0123456789abcdef" || stored["passess/my-app.DATABASE_URL"] != "postgres://app:passess-fake-dbpw@db/app" {
		t.Fatalf("stored = %v", stored)
	}
	if strings.Contains(out, "passess-fake-apikey") || strings.Contains(out, "passess-fake-dbpw") {
		t.Fatal("migrate printed a value")
	}
	for _, want := range []string{"The backup still holds the old values in clear", "rm -r ", shellLine(keychainPrompt("my-app.API_KEY")), "passess scan"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	got, _ := os.ReadFile(envPath)
	if string(got) != "# app settings\nDEBUG=true\nEMPTY_SECRET=\nSESSION_SECRET=${API_KEY}\n" {
		t.Fatalf(".env after migrate: %q", got)
	}
	u, err := config.LoadUser(filepath.Join(home, ".config", "passess", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if r := u.Secrets["API_KEY"].Refs; len(r) != 1 || r[0].String() != "keychain://passess/my-app.API_KEY" {
		t.Fatalf("API_KEY refs = %v", r)
	}
	proj, err := config.LoadProject(filepath.Join(project, config.ProjectFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := proj.NeedsName("DATABASE_URL"); !ok {
		t.Fatalf("project needs = %+v", proj.Needs)
	}
	if entries, _ := os.ReadDir(filepath.Join(home, "state", "passess", "backups")); len(entries) != 1 {
		t.Fatal("no backup taken")
	}
}

func TestMigrateMCP(t *testing.T) {
	noHarness(t)
	stored := fakeKeychain(t)
	home, calls := fakeHarnesses(t)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers": {
  "legacy": {"command": "npx", "args": ["-y", "server"], "env": {"API_TOKEN": "passess-fake-legacy-0123456789abcdef", "LOG_LEVEL": "debug"}},
  "inherits": {"command": "npx", "args": ["other"], "env": {"API_TOKEN": "${API_TOKEN}"}}
}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(t, "migrate", "mcp", "claude", "inherits", "--apply", "--yes"); code != ExitConfig || !strings.Contains(errOut, "env.API_TOKEN") || len(stored) != 0 {
		t.Fatalf("a reference was treated as a value: exit %d: %s", code, errOut)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(`
[mcp_servers.remote]
url = "https://mcp.example.com/mcp"
[mcp_servers.remote.http_headers]
Authorization = "Bearer passess-fake-remote-0123456789abcdef"
X-Client = "passess-test"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	out, errOut, code := run(t, "migrate", "mcp", "claude", "legacy")
	if code != 0 || !strings.Contains(out, "env.API_TOKEN -> API_TOKEN at keychain://passess/mcp.legacy.API_TOKEN") || !strings.Contains(out, "Dry run") {
		t.Fatalf("dry run: exit %d\n%s%s", code, out, errOut)
	}
	if len(stored) != 0 || readCalls(t, calls) != "" || strings.Contains(out, "passess-fake-legacy") {
		t.Fatal("the dry run changed something or printed a value")
	}
	out, errOut, code = run(t, "migrate", "mcp", "claude", "legacy", "--apply", "--yes")
	if code != 0 || !strings.Contains(out, "where agents could read it") {
		t.Fatalf("claude: exit %d\n%s%s", code, out, errOut)
	}
	if stored["passess/mcp.legacy.API_TOKEN"] != "passess-fake-legacy-0123456789abcdef" {
		t.Fatalf("stored = %v", stored)
	}
	out, errOut, code = run(t, "migrate", "mcp", "codex", "remote", "--apply", "--yes")
	if code != 0 {
		t.Fatalf("codex: exit %d\n%s%s", code, out, errOut)
	}
	if stored["passess/mcp.remote.REMOTE_TOKEN"] != "passess-fake-remote-0123456789abcdef" {
		t.Fatalf("the auth scheme must not be stored with the token: %v", stored)
	}

	u, err := config.LoadUser(os.Getenv("PASSESS_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	legacy, remote := u.MCP["legacy"], u.MCP["remote"]
	if strings.Join(legacy.Command, " ") != "npx -y server" || legacy.Env["API_TOKEN"] != "API_TOKEN" || legacy.Vars["LOG_LEVEL"] != "debug" {
		t.Fatalf("legacy = %+v", legacy)
	}
	if remote.URL != "https://mcp.example.com/mcp" || remote.Headers["Authorization"] != "Bearer {{REMOTE_TOKEN}}" || remote.Headers["X-Client"] != "passess-test" {
		t.Fatalf("remote = %+v", remote)
	}
	log := readCalls(t, calls)
	for _, want := range []string{"claude mcp remove --scope user legacy", "claude mcp add --scope user legacy -- " + passessPath() + " mcp-exec legacy",
		"codex mcp remove remote", "codex mcp add remote -- " + passessPath() + " mcp-exec remote"} {
		if !strings.Contains(log, want) {
			t.Fatalf("calls lack %q:\n%s", want, log)
		}
	}
	cfg, _ := os.ReadFile(os.Getenv("PASSESS_CONFIG"))
	if strings.Contains(string(cfg), "passess-fake-legacy") || strings.Contains(string(cfg), "passess-fake-remote") {
		t.Fatal("a value reached the passess config")
	}
}
