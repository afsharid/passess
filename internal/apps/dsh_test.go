package apps

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func testDSH(t *testing.T) DSH {
	t.Helper()
	home := t.TempDir()
	env := map[string]string{"HOME": home}
	d := NewDSH(func(k string) string { return env[k] }, filepath.Join(home, "data"), filepath.Join(home, "state"))
	d.App = filepath.Join(home, "none.app")
	return d
}

const userPatch = `# the user's own rows
- id: agent-default-model
  name: "@deepseek-ai/dsh-agent-default-model"
  config:
    provider: evren
- id: llm-pi-ai
  config:
    providers:
      evren:
        apiKeyEnv: EVREN_LLM_API_KEY
      other:
        apiKeyEnv: "OTHER_KEY"   # quoted, with a comment
      again:
        apiKeyEnv: EVREN_LLM_API_KEY
`

func TestInstallSplicesIntoTheUsersPatch(t *testing.T) {
	d := testDSH(t)
	if d.Installed() {
		t.Fatal("no app and no profile: not installed")
	}
	if err := os.MkdirAll(d.Profile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.Patch, []byte(userPatch), 0o600); err != nil {
		t.Fatal(err)
	}
	if !d.Installed() || d.PluginState() != StateMissing || d.RowState() != StateMissing {
		t.Fatalf("before: installed %v, plugin %s, row %s", d.Installed(), d.PluginState(), d.RowState())
	}
	if err := d.Install(); err != nil {
		t.Fatal(err)
	}
	if d.PluginState() != StateOK || d.RowState() != StateOK {
		t.Fatalf("after: plugin %s, row %s", d.PluginState(), d.RowState())
	}
	got, _ := os.ReadFile(d.Patch)
	if want := userPatch + block(d.Plugin); string(got) != want {
		t.Fatalf("the user's rows must stay as they were, passess's block after them:\n%s", got)
	}

	// A second install changes nothing; a moved plugin path is rewritten in place.
	if err := d.Install(); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(d.Patch); string(again) != string(got) {
		t.Fatalf("a second install changed the patch:\n%s", again)
	}
	moved := d
	moved.Plugin = filepath.Join(filepath.Dir(d.Plugin), "elsewhere", "index.mjs")
	if moved.RowState() != StateDrift {
		t.Fatalf("a block naming another path: %s", moved.RowState())
	}
	if err := moved.Install(); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(d.Patch); string(after) != userPatch+block(moved.Plugin) {
		t.Fatalf("the block was not replaced in place:\n%s", after)
	}

	// An edited plugin file is drift, and install puts it back.
	if err := os.WriteFile(moved.Plugin, []byte("// edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if moved.PluginState() != StateDrift {
		t.Fatalf("an edited plugin: %s", moved.PluginState())
	}

	if err := moved.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(d.Patch); string(after) != userPatch {
		t.Fatalf("uninstall must leave the user's rows only:\n%s", after)
	}
	if moved.PluginState() != StateMissing {
		t.Fatal("uninstall leaves the plugin file")
	}
}

func TestInstallCreatesAPatchAndUninstallLeavesOneDSHStarts(t *testing.T) {
	d := testDSH(t)
	if err := d.Install(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(d.Patch)
	if string(got) != block(d.Plugin) {
		t.Fatalf("a new patch holds the block only:\n%s", got)
	}
	if err := d.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(d.Patch); string(got) != "[]\n" {
		t.Fatalf("DSH refuses an empty patch; got %q", got)
	}
}

// The plugin path comes from XDG_DATA_HOME or HOME, which whoever runs
// passess sets: it must not add rows of its own to the user's patch.
func TestInstallRefusesAPathThatWouldAddRows(t *testing.T) {
	d := testDSH(t)
	if err := os.MkdirAll(d.Profile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.Patch, []byte(userPatch), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"/tmp/evil\n    - id: pwn\n      name: /tmp/evil/plugin.mjs\n    #/dsh/index.mjs",
		"relative/dsh/index.mjs",
		"/tmp/bell\a/dsh/index.mjs",
	} {
		evil := d
		evil.Plugin = bad
		if err := evil.Install(); err == nil {
			t.Fatalf("installed with plugin path %q", bad)
		}
		if got, _ := os.ReadFile(d.Patch); string(got) != userPatch {
			t.Fatalf("plugin path %q changed the patch:\n%s", bad, got)
		}
	}
	// A path with YAML's own characters stays one quoted scalar.
	odd := d
	odd.Plugin = filepath.Join(filepath.Dir(d.Plugin), `a "b": #c`, "index.mjs")
	if err := odd.Install(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(d.Patch)
	if want := `name: "` + strings.ReplaceAll(odd.Plugin, `"`, `\"`) + `"`; !strings.Contains(string(got), want) || strings.Count(string(got), "- id:") != strings.Count(userPatch, "- id:")+1 {
		t.Fatalf("the path did not stay one quoted value (want %s):\n%s", want, got)
	}
}

func TestKeys(t *testing.T) {
	d := testDSH(t)
	if d.Keys() != nil {
		t.Fatal("no patch, no keys")
	}
	if err := os.MkdirAll(d.Profile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.Patch, []byte(userPatch), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := d.Keys(); !slices.Equal(got, []string{"EVREN_LLM_API_KEY", "OTHER_KEY"}) {
		t.Fatalf("got %v", got)
	}
}

func TestActive(t *testing.T) {
	d := testDSH(t)
	if d.Active() != "" {
		t.Fatal("no status file: not active")
	}
	if err := os.MkdirAll(filepath.Dir(d.Status), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(pid int) {
		t.Helper()
		body := fmt.Sprintf(`{"pid": %d, "since": "2026-10-09T20:00:00.000Z"}`, pid)
		if err := os.WriteFile(d.Status, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(os.Getpid())
	if got := d.Active(); !strings.HasPrefix(got, "2026-10-09") {
		t.Fatalf("a fresh heartbeat: %q", got)
	}
	old := time.Now().Add(-2 * beatFresh)
	if err := os.Chtimes(d.Status, old, old); err != nil {
		t.Fatal(err)
	}
	if d.Active() != "" {
		t.Fatal("a stale heartbeat: not active")
	}
}

// The plugin passess writes is the one its tests run against.
func TestEmbeddedPluginIsTheSource(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("dsh", "index.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(src) != string(dshPlugin) {
		t.Fatal("the embedded plugin differs from dsh/index.mjs")
	}
}
