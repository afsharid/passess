package hook

import (
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
