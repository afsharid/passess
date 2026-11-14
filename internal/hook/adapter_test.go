package hook

import "testing"

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
