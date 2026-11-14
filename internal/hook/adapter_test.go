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
