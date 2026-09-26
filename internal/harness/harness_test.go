package harness

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const passessBin = "/usr/local/bin/passess"

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClaudeEntries(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude.json"), `{
  "numStartups": 12,
  "mcpServers": {
    "github": {"type": "stdio", "command": "`+passessBin+`", "args": ["mcp-exec", "github"], "env": {}},
    "legacy": {"command": "npx", "args": ["-y", "server"], "env": {"API_TOKEN": "passess-fake-legacy-0123456789abcdef", "CONFIG": "/Users/x/config.json", "REF": "${OTHER}"}},
    "remote": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer passess-fake-header-0123456789abcdef"}}
  }
}`)
	entries, err := Claude{Home: home}.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %+v", entries)
	}
	gh, legacy, remote := entries[0], entries[1], entries[2]
	if !gh.ManagedBy("") || legacy.ManagedBy("") || remote.ManagedBy("") {
		t.Fatalf("managed flags wrong: %+v", entries)
	}
	if !slices.Equal(legacy.Leaks, []string{"env.API_TOKEN"}) || !slices.Equal(legacy.EnvKeys, []string{"API_TOKEN", "CONFIG", "REF"}) {
		t.Fatalf("legacy = %+v", legacy)
	}
	if !slices.Equal(remote.Leaks, []string{"headers.Authorization"}) || remote.URL == "" {
		t.Fatalf("remote = %+v", remote)
	}
	data, _ := json.Marshal(entries)
	if strings.Contains(string(data), "passess-fake-legacy") || strings.Contains(string(data), "passess-fake-header") {
		t.Fatal("entries must not carry values")
	}
}

func TestCodexEntries(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), `
model = "gpt-6"

# my servers
[mcp_servers.github]
command = "`+passessBin+`"
args = ["mcp-exec", "github"]

[mcp_servers.legacy]
command = "npx"
args = ["-y", "server"]
[mcp_servers.legacy.env]
API_TOKEN = "passess-fake-legacy-0123456789abcdef"

[mcp_servers.remote]
url = "https://mcp.example.com/mcp"
[mcp_servers.remote.http_headers]
Authorization = "Bearer passess-fake-header-0123456789abcdef"
`)
	c := Codex{Home: home}
	entries, err := c.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || !entries[0].ManagedBy("") || !slices.Equal(entries[1].Leaks, []string{"env.API_TOKEN"}) ||
		!slices.Equal(entries[2].Leaks, []string{"http_headers.Authorization"}) {
		t.Fatalf("entries = %+v", entries)
	}
	if got := (Codex{Home: home, CodexHome: "/elsewhere"}).ConfigPath(); got != "/elsewhere/config.toml" {
		t.Fatal(got)
	}
}

func TestPlan(t *testing.T) {
	a := Claude{}
	want := func(name string) Desired { return Desired{Name: name, Argv: []string{passessBin, "mcp-exec", name}} }
	entries := []Entry{
		{Name: "ok", Command: passessBin, Args: []string{"mcp-exec", "ok"}},
		{Name: "moved", Command: "/old/place/passess", Args: []string{"mcp-exec", "moved"}},
		{Name: "theirs", Command: "npx", Args: []string{"server"}, Leaks: []string{"env.TOKEN"}},
		{Name: "stale", Command: passessBin, Args: []string{"mcp-exec", "stale"}},
	}
	statuses, actions := Plan(a, []Desired{want("ok"), want("new"), want("moved"), want("theirs")}, entries, false)
	states := map[string]string{}
	for _, s := range statuses {
		states[s.Name] = s.State
	}
	if states["ok"] != StateOK || states["new"] != StateMissing || states["moved"] != StateDrift || states["theirs"] != StateUnmanaged {
		t.Fatalf("states = %v", states)
	}
	if len(actions) != 2 || actions[0].Kind != "add" || actions[1].Kind != "replace" || len(actions[1].Commands) != 2 {
		t.Fatalf("actions = %+v", actions)
	}
	if !strings.Contains(statuses[3].Detail, "env.TOKEN") {
		t.Fatalf("unmanaged detail should name the leak: %q", statuses[3].Detail)
	}
	if _, forced := Plan(a, []Desired{want("theirs")}, entries, true); len(forced) != 1 || forced[0].Kind != "replace" {
		t.Fatalf("force: %+v", forced)
	}
	removals := PlanRemoval(a, entries, passessBin)
	if len(removals) != 3 {
		t.Fatalf("removal should cover the three passess entries: %+v", removals)
	}
	if got := a.AddCommand("x", []string{passessBin, "mcp-exec", "x"}); !slices.Equal(got, []string{"claude", "mcp", "add", "--scope", "user", "x", "--", passessBin, "mcp-exec", "x"}) {
		t.Fatal(got)
	}
}

func TestInstructionsBlock(t *testing.T) {
	for _, doc := range []string{"", "# Mine\n\nKeep this.\n", "# Mine\n\n" + BlockStart + "\nold text\n" + BlockEnd + "\n\n## After\n"} {
		once := Splice(doc)
		if BlockState(once) != BlockOK || Splice(once) != once {
			t.Fatalf("splice not idempotent for %q", doc)
		}
		if strings.Count(once, BlockStart) != 1 {
			t.Fatalf("duplicate block in %q", once)
		}
		for _, keep := range []string{"Keep this.", "## After"} {
			if strings.Contains(doc, keep) && !strings.Contains(once, keep) {
				t.Fatalf("splice lost %q", keep)
			}
		}
	}
	doc := "# Mine\n\nKeep this.\n"
	if got := Unsplice(Splice(doc)); got != doc {
		t.Fatalf("unsplice did not restore:\n%q\n%q", got, doc)
	}
	if BlockState(doc) != BlockMissing || BlockState(doc+"\n"+BlockStart+"\nold\n"+BlockEnd) != BlockDrift {
		t.Fatal("block states")
	}
}

func TestBackup(t *testing.T) {
	src := t.TempDir()
	a, b := filepath.Join(src, "a.json"), filepath.Join(src, "missing.toml")
	writeFile(t, a, `{"x":1}`)
	dir, err := Backup(filepath.Join(t.TempDir(), "backups"), []string{a, b}, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("backup dir mode %v %v", st.Mode(), err)
	}
	var manifest []struct{ Original, Copy string }
	data, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err := json.Unmarshal(data, &manifest); err != nil || len(manifest) != 1 || manifest[0].Original != a {
		t.Fatalf("manifest = %s", data)
	}
	copied, _ := os.ReadFile(filepath.Join(dir, manifest[0].Copy))
	if string(copied) != `{"x":1}` {
		t.Fatal("copy differs")
	}
}

// TestLiveHarnessCLIs drives the real claude and codex CLIs against a
// throwaway HOME, so the argv passess builds is checked by the harnesses
// themselves. Opt in with PASSESS_LIVE_HARNESS=1.
func TestLiveHarnessCLIs(t *testing.T) {
	if os.Getenv("PASSESS_LIVE_HARNESS") != "1" {
		t.Skip("set PASSESS_LIVE_HARNESS=1 to run against installed harness CLIs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	argv := []string{passessBin, "mcp-exec", "demo"}
	for _, a := range []Adapter{Claude{Home: home}, Codex{Home: home, CodexHome: filepath.Join(home, ".codex")}} {
		if _, err := exec.LookPath(a.ID()); err != nil {
			t.Logf("%s not installed, skipped", a.ID())
			continue
		}
		run := func(cmd []string) {
			out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", strings.Join(cmd, " "), err, out)
			}
		}
		run(a.AddCommand("demo", argv))
		entries, err := a.Entries()
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || !entries[0].ManagedBy("") || entries[0].Command != passessBin {
			t.Fatalf("%s after add: %+v", a.ID(), entries)
		}
		run(a.RemoveCommand("demo"))
		if entries, _ := a.Entries(); len(entries) != 0 {
			t.Fatalf("%s after remove: %+v", a.ID(), entries)
		}
	}
}
