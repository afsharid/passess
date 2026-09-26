package harness

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// theirs is a server the user configured, in the shape each harness uses.
func theirs(spec JSONSpec) string {
	if spec.ID == "opencode" {
		return `{"type": "local", "command": ["npx", "-y", "tracker"], "environment": {"TRACKER_TOKEN": "` + fakeToken + `"}}`
	}
	return `{"command": "npx", "args": ["-y", "tracker"], "env": {"TRACKER_TOKEN": "` + fakeToken + `"}}`
}

// fakeToken looks like a credential to the leak check; built at run time.
var fakeToken = "passess-fake-" + strings.Repeat("Zq8Xw2Lm9P", 3)

// config is a realistic file: the harness's own settings, the user's server,
// comments where the format allows them.
func config(spec JSONSpec) string {
	comment := ""
	if spec.ID == "opencode" || spec.ID == "zed" {
		comment = "  // my settings\n"
	}
	servers := `"` + spec.Servers[0] + `": {` + "\n" + `    "tracker": ` + theirs(spec) + "\n  }"
	return "{\n" + comment + `  "theme": "dark",` + "\n  " + servers + "\n}\n"
}

func writeAt(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestJSONAdaptersRoundTrip(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		for _, spec := range JSONSpecs(goos) {
			if spec.Entry == nil || len(spec.Paths) == 0 {
				continue // written by its own CLI, or absent on this OS
			}
			t.Run(goos+"/"+spec.ID, func(t *testing.T) {
				home := t.TempDir()
				j := JSONFile{Spec: spec, Home: home}
				path := j.abs(spec.Paths[0])
				before := config(spec)
				writeAt(t, path, before)
				if resolved, _ := filepath.EvalSymlinks(path); !j.Installed() || j.ConfigPath() != resolved {
					t.Fatalf("installed %v, config %s", j.Installed(), j.ConfigPath())
				}

				entries, err := j.Entries()
				if err != nil || len(entries) != 1 || entries[0].Command != "npx" || !slices.Equal(entries[0].Leaks, []string{"env.TRACKER_TOKEN"}) {
					t.Fatalf("entries = %+v, %v", entries, err)
				}
				argv := []string{"/opt/bin/passess", "mcp-exec", "github"}
				desired := []Desired{{Name: "github", Argv: argv}}
				statuses, actions := Plan(j, desired, entries, false)
				if statuses[0].State != StateMissing || len(actions) != 1 || len(actions[0].Commands) != 0 {
					t.Fatalf("plan = %+v %+v", statuses, actions)
				}
				after, err := j.Edit([]byte(before), actions)
				if err != nil {
					t.Fatal(err)
				}
				writeAt(t, path, string(after))
				entries, _ = j.Entries()
				if len(entries) != 2 || !entries[0].ManagedBy(argv[0]) || !slices.Equal(entries[0].Args, argv[1:]) {
					t.Fatalf("after install: %+v\n%s", entries, after)
				}
				if strings.Contains(before, "// my settings") && !strings.Contains(string(after), "// my settings") {
					t.Fatalf("comment lost:\n%s", after)
				}
				if statuses, actions := Plan(j, desired, entries, false); statuses[0].State != StateOK || len(actions) != 0 {
					t.Fatalf("second install would change something: %+v %+v", statuses, actions)
				}
				back, err := j.Edit(after, PlanRemoval(j, entries, argv[0]))
				if err != nil {
					t.Fatal(err)
				}
				if string(back) != before {
					t.Fatalf("uninstall is not byte-identical:\n%s\n---\n%s", before, back)
				}
			})
		}
	}
}

func TestJSONAdapterDetails(t *testing.T) {
	specs := map[string]JSONSpec{}
	for _, s := range JSONSpecs("darwin") {
		specs[s.ID] = s
	}
	home := t.TempDir()

	// OpenCode: one command array holds program and arguments.
	oc := JSONFile{Spec: specs["opencode"], Home: home}
	writeAt(t, oc.abs("$XDG/opencode/opencode.jsonc"), config(specs["opencode"]))
	raw, ok, err := oc.Raw("tracker")
	if err != nil || !ok || raw.Command != "npx" || !slices.Equal(raw.Args, []string{"-y", "tracker"}) || raw.Env["TRACKER_TOKEN"] != fakeToken {
		t.Fatalf("raw = %+v %v %v", raw, ok, err)
	}
	out, _ := oc.Edit(nil, []Action{{Kind: "add", Server: "gh", Argv: []string{"/p", "mcp-exec", "gh"}}})
	if !strings.Contains(string(out), `"command": [`) || !strings.Contains(string(out), `"enabled": true`) {
		t.Fatalf("opencode entry:\n%s", out)
	}
	// Both OpenCode files present: passess will not guess which one counts.
	writeAt(t, oc.abs("$XDG/opencode/opencode.json"), "{}")
	if _, err := oc.Entries(); err == nil || !strings.Contains(err.Error(), "merge them") {
		t.Fatalf("two configs: %v", err)
	}

	// XDG_CONFIG_HOME moves the $XDG paths.
	xdg := JSONFile{Spec: specs["zed"], Home: home, ConfigHome: "/elsewhere"}
	if xdg.ConfigPath() != "/elsewhere/zed/settings.json" || xdg.InstructionsPath() != "/elsewhere/zed/AGENTS.md" {
		t.Fatalf("xdg paths: %s %s", xdg.ConfigPath(), xdg.InstructionsPath())
	}

	// A symlinked config is edited where it points.
	real := filepath.Join(home, "dotfiles", "cursor-mcp.json")
	writeAt(t, real, "{}\n")
	cur := JSONFile{Spec: specs["cursor"], Home: home}
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(home, ".cursor", "mcp.json")); err != nil {
		t.Fatal(err)
	}
	realResolved, _ := filepath.EvalSymlinks(real)
	if cur.ConfigPath() != realResolved {
		t.Fatalf("config path %s, want the link target %s", cur.ConfigPath(), realResolved)
	}

	// Never create a harness's directory; create a file only where allowed.
	empty := t.TempDir()
	for id, want := range map[string]bool{"cursor": false, "zed": false, "claude-desktop": false} {
		if got := (JSONFile{Spec: specs[id], Home: empty}).Installed(); got != want {
			t.Errorf("%s installed in an empty home: %v", id, got)
		}
	}
	if err := os.MkdirAll(filepath.Join(empty, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !(JSONFile{Spec: specs["cursor"], Home: empty}).Installed() {
		t.Error("cursor with ~/.cursor present should be installable")
	}
	if err := os.MkdirAll(filepath.Join(empty, ".config", "zed"), 0o700); err != nil {
		t.Fatal(err)
	}
	if (JSONFile{Spec: specs["zed"], Home: empty}).Installed() {
		t.Error("zed without settings.json must not count: passess only edits it")
	}
	t.Setenv("PATH", t.TempDir())
	if err := os.MkdirAll(filepath.Join(empty, ".gemini"), 0o700); err != nil {
		t.Fatal(err)
	}
	if (JSONFile{Spec: specs["gemini"], Home: empty}).Installed() {
		t.Error("gemini needs its CLI before passess creates settings.json (~/.gemini also belongs to Antigravity)")
	}
	if (JSONFile{Spec: specs["antigravity"], Home: empty}).Installed() {
		t.Error("antigravity without agy or a config")
	}
}

func TestInstructionPathsAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, goos := range []string{"darwin", "linux"} {
		for _, s := range JSONSpecs(goos) {
			if s.Instructions == "" {
				continue
			}
			if other, dup := seen[s.Instructions]; dup && other != s.ID {
				t.Fatalf("%s and %s share %s: uninstalling one would strip the other's block", s.ID, other, s.Instructions)
			}
			seen[s.Instructions] = s.ID
		}
	}
	for _, p := range []string{".claude/CLAUDE.md", ".codex/AGENTS.md"} {
		if id, dup := seen[p]; dup {
			t.Fatalf("%s shares %s with Claude Code or Codex", id, p)
		}
	}
}
