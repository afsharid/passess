package hook

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func parseEvent(t *testing.T, harness, event, payload string) Event {
	t.Helper()
	ev, err := Adapters[harness].Parse(event, []byte(payload), nil)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// Every Claude Code tool that runs a shell command reaches the shell checks:
// the verdict for a Monitor command is the verdict for the same Bash command.
func TestClaudeShellTools(t *testing.T) {
	env := testEnv(t)
	for _, tool := range []string{"Bash", "Monitor"} {
		for _, cmd := range []string{"cat .env", "passess agent stop"} {
			payload := `{"hook_event_name":"PreToolUse","tool_name":"` + tool + `","tool_input":{"command":"` + cmd + `"},"cwd":"/home/u/proj"}`
			ev := parseEvent(t, "claude", "PreToolUse", payload)
			if ev.Kind != Shell || ev.Command != cmd {
				t.Fatalf("%s %q parsed as %+v", tool, cmd, ev)
			}
			if v := Decide(ev, env); !v.Deny {
				t.Errorf("%s %q allowed", tool, cmd)
			}
		}
		payload := `{"hook_event_name":"PreToolUse","tool_name":"` + tool + `","tool_input":{"command":"ls"},"cwd":"/home/u/proj"}`
		if v := Decide(parseEvent(t, "claude", "PreToolUse", payload), env); v.Deny {
			t.Errorf("%s ls denied: %s", tool, v.Reason)
		}
	}
}

// The destination of a Codex apply_patch rename is a file the patch writes.
func TestApplyPatchMoveTo(t *testing.T) {
	env := testEnv(t)
	const cfg = "/home/u/.config/passess/config.toml"
	patch := func(body string) string {
		b := strings.NewReplacer("\n", `\n`).Replace("*** Begin Patch\n" + body + "\n@@\n-a\n+b\n*** End Patch")
		return `{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"` + b + `"},"cwd":"/home/u/proj"}`
	}
	for name, body := range map[string]string{
		"add":      "*** Add File: " + cfg,
		"update":   "*** Update File: " + cfg,
		"move to":  "*** Update File: /tmp/evil.toml\n*** Move to: " + cfg,
		"relative": "*** Update File: /tmp/evil.toml\n*** Move to: ../.config/passess/config.toml",
	} {
		for _, h := range []string{"claude", "codex"} {
			if v := Decide(parseEvent(t, h, "PreToolUse", patch(body)), env); !v.Deny {
				t.Errorf("%s %s: allowed", h, name)
			}
		}
	}
	ok := parseEvent(t, "codex", "PreToolUse", patch("*** Update File: src/a.go\n*** Move to: src/b.go"))
	if len(ok.Paths) != 2 || Decide(ok, env).Deny {
		t.Errorf("ordinary rename: %+v", ok)
	}
}

// OpenCode's multiedit, and patch or apply_patch given as patchText, write
// files like write and edit do.
func TestOpenCodeWriteTools(t *testing.T) {
	env := testEnv(t)
	const cfg = "/home/u/.config/passess/config.toml"
	for name, payload := range map[string]string{
		"write":       `{"tool":"write","args":{"filePath":"` + cfg + `"},"cwd":"/p"}`,
		"edit":        `{"tool":"edit","args":{"filePath":"` + cfg + `"},"cwd":"/p"}`,
		"multiedit":   `{"tool":"multiedit","args":{"filePath":"` + cfg + `"},"cwd":"/p"}`,
		"patch":       `{"tool":"patch","args":{"filePath":"` + cfg + `"},"cwd":"/p"}`,
		"patchText":   `{"tool":"patch","args":{"patchText":"*** Begin Patch\n*** Update File: ` + cfg + `\n@@\n-a\n+b\n*** End Patch"},"cwd":"/p"}`,
		"apply_patch": `{"tool":"apply_patch","args":{"patchText":"*** Begin Patch\n*** Update File: /tmp/x\n*** Move to: ` + cfg + `\n@@\n-a\n+b\n*** End Patch"},"cwd":"/p"}`,
		"relative":    `{"tool":"multiedit","args":{"filePath":"../.config/passess/config.toml"},"cwd":"/home/u/proj"}`,
	} {
		ev := parseEvent(t, "opencode", "tool.execute.before", payload)
		if ev.Kind != Write || !Decide(ev, env).Deny {
			t.Errorf("%s: %+v", name, ev)
		}
	}
	for _, payload := range []string{
		`{"tool":"multiedit","args":{"filePath":"src/a.go"},"cwd":"/home/u/proj"}`,
		`{"tool":"patch","args":{"patchText":"*** Begin Patch\n*** Update File: src/a.go\n@@\n-a\n+b\n*** End Patch"},"cwd":"/home/u/proj"}`,
	} {
		if v := Decide(parseEvent(t, "opencode", "tool.execute.before", payload), env); v.Deny {
			t.Errorf("ordinary write denied: %s", payload)
		}
	}
}

// An apply_patch envelope given to a shell command, by heredoc or through a
// pipe, writes the files it names, and a header may be indented.
func TestApplyPatchInShell(t *testing.T) {
	env := testEnv(t)
	const cfg = "/home/u/.config/passess/config.toml"
	envelope := func(body string) string { return "*** Begin Patch\n" + body + "\n@@\n-a\n+b\n*** End Patch" }
	jsonText := strings.NewReplacer("\n", `\n`, "\r", `\r`, "\t", `\t`).Replace
	for name, body := range map[string]string{
		"add": "*** Add File: " + cfg, "update": "*** Update File: " + cfg, "move to": "*** Update File: /tmp/x\n*** Move to: " + cfg,
		"relative": "*** Update File: /tmp/x\n*** Move to: ../.config/passess/config.toml", "tilde": "*** Add File: ~/.config/passess/config.toml",
		"indented": "  *** Add File: " + cfg, "indented move": "*** Update File: /tmp/x\n\t*** Move to: " + cfg, "crlf": "*** Add File: " + cfg + "\r",
	} {
		heredoc := "apply_patch <<'EOF'\n" + envelope(body) + "\nEOF"
		for _, cmd := range []string{heredoc, "cat <<'EOF' | apply_patch\n" + envelope(body) + "\nEOF", "applypatch <<'EOF'\n" + envelope(body) + "\nEOF"} {
			if v := Decide(Event{Kind: Shell, Command: cmd, CWD: "/home/u/proj"}, env); !v.Deny {
				t.Errorf("shell %s: allowed: %q", name, cmd)
			}
		}
		// the same envelope through the harnesses' shell tools
		bash := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` + jsonText(heredoc) + `"},"cwd":"/home/u/proj"}`
		if v := Decide(parseEvent(t, "claude", "PreToolUse", bash), env); !v.Deny {
			t.Errorf("claude Bash %s: allowed", name)
		}
		argv := `{"tool_name":"shell","tool_input":{"command":["bash","-lc","` + jsonText(heredoc) + `"]},"cwd":"/home/u/proj"}`
		if v := Decide(parseEvent(t, "codex", "PreToolUse", argv), env); !v.Deny {
			t.Errorf("codex shell %s: allowed", name)
		}
	}
	for _, body := range []string{"*** Add File: src/a.go", "*** Update File: a.go\n*** Move to: b.go", "  *** Add File: docs/x.md"} {
		cmd := "apply_patch <<'EOF'\n" + envelope(body) + "\nEOF"
		if v := Decide(Event{Kind: Shell, Command: cmd, CWD: "/home/u/proj"}, env); v.Deny {
			t.Errorf("ordinary patch denied: %s: %s", body, v.Reason)
		}
	}
	// a patch text in a command that is not apply_patch is only text
	if v := Decide(Event{Kind: Shell, Command: "echo '*** Add File: " + cfg + "'", CWD: "/home/u/proj"}, env); v.Deny {
		t.Errorf("echo of a header denied: %s", v.Reason)
	}
	// the tool payload with an indented header
	tool := `{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"` + jsonText("*** Begin Patch\n*** Update File: /tmp/x\n  *** Move to: "+cfg+"\n*** End Patch") + `"},"cwd":"/home/u/proj"}`
	if v := Decide(parseEvent(t, "codex", "PreToolUse", tool), env); !v.Deny {
		t.Error("indented Move to allowed")
	}
}

// searchEvent is the event a harness's search tool gives for a glob, in the
// working directory /home/u/proj, with a directory path when path is set.
func searchEvents(t *testing.T, glob, path string) map[string]Event {
	t.Helper()
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	claudeInput := `"pattern":"passess-fake","glob":` + q(glob)
	opencodeInput := `"pattern":"passess-fake","include":` + q(glob)
	geminiInclude := `"include":[` + q(glob) + `]`
	antigravityArgs := `"Query":"passess-fake","Includes":[` + q(glob) + `]`
	if path != "" {
		claudeInput += `,"path":` + q(path)
		opencodeInput += `,"path":` + q(path)
		geminiInclude += `,"dir_path":` + q(path)
		antigravityArgs += `,"SearchPath":` + q(path)
	}
	return map[string]Event{
		"claude Grep": parseEvent(t, "claude", "PreToolUse",
			`{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{`+claudeInput+`},"cwd":"/home/u/proj"}`),
		"codex Grep": parseEvent(t, "codex", "PreToolUse",
			`{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{`+claudeInput+`},"cwd":"/home/u/proj"}`),
		"gemini read_many_files": parseEvent(t, "gemini", "BeforeTool",
			`{"hook_event_name":"BeforeTool","tool_name":"read_many_files","tool_input":{"paths":["."],`+geminiInclude+`},"cwd":"/home/u/proj"}`),
		"gemini search_file_content": parseEvent(t, "gemini", "BeforeTool",
			`{"hook_event_name":"BeforeTool","tool_name":"search_file_content","tool_input":{"pattern":"passess-fake",`+geminiInclude+`},"cwd":"/home/u/proj"}`),
		"opencode grep": parseEvent(t, "opencode", "tool.execute.before",
			`{"tool":"grep","args":{`+opencodeInput+`},"cwd":"/home/u/proj"}`),
		"antigravity grep_search": parseEvent(t, "antigravity", "PreToolUse",
			`{"toolCall":{"name":"grep_search","args":{`+antigravityArgs+`}},"workspacePaths":["/home/u/proj"]}`),
	}
}

// A search whose glob or include pattern names a file the Read refusal covers
// is refused with the Read refusal's text, with no path, with a directory path,
// and by every harness whose search tool takes such a pattern.
func TestSearchGlobNamingGuardedFile(t *testing.T) {
	env := testEnv(t)
	for _, glob := range []string{
		".env", ".env*", "**/.env", "**/.env*", ".env.*", ".env.local", "src/.env.production", ".envrc", "*.env", "{.env,.envrc}",
		".env{,.local}", "*.pem", "**/*.key", "*.{go,pem}", "id_rsa", "**/id_ed25519*", ".ENV", ".env?", "{a,{b,.env}}.x",
	} {
		for _, path := range []string{"", "/home/u/proj", "."} {
			for name, ev := range searchEvents(t, glob, path) {
				if ev.Kind != Read {
					t.Errorf("%s glob %q path %q: kind %s", name, glob, path, ev.Kind)
					continue
				}
				v := Decide(ev, env)
				if !v.Deny {
					t.Errorf("%s glob %q path %q: allowed", name, glob, path)
				} else if !strings.HasPrefix(v.Reason, "passess: "+glob+" ") || !strings.Contains(v.Reason, "; reading it puts them into this conversation. "+useInstead) {
					t.Errorf("%s glob %q: reason %q is not the Read refusal's", name, glob, v.Reason)
				}
			}
		}
	}
	// The same words as reading the file itself.
	read := Decide(Event{Kind: Read, Paths: []string{".env"}, CWD: "/home/u/proj"}, env)
	grep := Decide(searchEvents(t, ".env", "")["claude Grep"], env)
	if !read.Deny || read.Reason != grep.Reason {
		t.Errorf("Read: %q, Grep: %q", read.Reason, grep.Reason)
	}
}

// Ordinary searches stay allowed: testdata/ordinary-globs.txt holds the globs.
func TestSearchGlobOrdinary(t *testing.T) {
	b, err := os.ReadFile("testdata/ordinary-globs.txt")
	if err != nil {
		t.Fatal(err)
	}
	globs := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(globs) < 10 {
		t.Fatalf("the table holds %d globs", len(globs))
	}
	env := testEnv(t)
	for _, glob := range globs {
		for _, path := range []string{"", "/home/u/proj", "."} {
			for name, ev := range searchEvents(t, glob, path) {
				if v := Decide(ev, env); v.Deny {
					t.Errorf("%s glob %q path %q: refused: %s", name, glob, path, v.Reason)
				}
			}
		}
	}
	// A search with neither path nor glob, and the Glob tool, name no file.
	for _, payload := range []string{
		`{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{"pattern":"passess-fake"},"cwd":"/home/u/proj"}`,
		`{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{"pattern":"passess-fake","path":"/home/u/proj","output_mode":"content"},"cwd":"/home/u/proj"}`,
		`{"hook_event_name":"PreToolUse","tool_name":"Glob","tool_input":{"pattern":".env*"},"cwd":"/home/u/proj"}`,
	} {
		if v := Decide(parseEvent(t, "claude", "PreToolUse", payload), env); v.Deny {
			t.Errorf("%s: refused: %s", payload, v.Reason)
		}
	}
}

// The refusals that already held: the file named as the path.
func TestSearchPathNamingGuardedFile(t *testing.T) {
	env := testEnv(t)
	for _, payload := range []string{
		`{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{"pattern":"x","path":".env"},"cwd":"/home/u/proj"}`,
		`{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{"pattern":"x","path":"/home/u/proj/.env","glob":"*.go"},"cwd":"/home/u/proj"}`,
	} {
		if v := Decide(parseEvent(t, "claude", "PreToolUse", payload), env); !v.Deny {
			t.Errorf("%s: allowed", payload)
		}
	}
	gem := `{"hook_event_name":"BeforeTool","tool_name":"read_many_files","tool_input":{"paths":%s},"cwd":"/home/u/proj"}`
	for paths, deny := range map[string]bool{`[".env*"]`: true, `["**/.env.*"]`: true, `["src","docs/*.md"]`: false, `["."]`: false} {
		if v := Decide(parseEvent(t, "gemini", "BeforeTool", strings.Replace(gem, "%s", paths, 1)), env); v.Deny != deny {
			t.Errorf("read_many_files paths %s: refused=%v, want %v", paths, v.Deny, deny)
		}
	}
}
