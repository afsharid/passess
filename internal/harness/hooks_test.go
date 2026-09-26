package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/jsonedit"
)

const self = "/opt/homebrew/bin/passess"

// existing is a hook config the user already has, per style.
func existing(style string) string {
	switch style {
	case HookGroups:
		return `{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit",
        "hooks": [{"type": "command", "command": "my-formatter"}]
      }
    ]
  }
}
`
	case HookCursor:
		return "{\n  \"version\": 1,\n  \"hooks\": {\n    \"afterFileEdit\": [{\"command\": \"./format.sh\"}]\n  }\n}\n"
	case HookNamed:
		return "{\n  \"my-linter\": {\n    \"PostToolUse\": [{\"matcher\": \"run_command\", \"hooks\": [{\"type\": \"command\", \"command\": \"./lint.sh\"}]}]\n  }\n}\n"
	}
	return ""
}

func TestHooksRoundTrip(t *testing.T) {
	for _, spec := range HookSpecs() {
		t.Run(spec.ID, func(t *testing.T) {
			home := t.TempDir()
			h := Hooks{Spec: spec, Home: home}
			before := existing(spec.Style)
			if err := os.MkdirAll(filepath.Dir(h.Path()), 0o700); err != nil {
				t.Fatal(err)
			}
			if before != "" {
				if err := os.WriteFile(h.Path(), []byte(before), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if st, err := h.State(self); err != nil || st != StateMissing {
				t.Fatalf("state before = %s, %v", st, err)
			}
			if !h.Installable() {
				t.Fatal("not installable")
			}
			out, err := h.Edit([]byte(before), self, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.Path(), out, 0o600); err != nil {
				t.Fatal(err)
			}
			if st, _ := h.State(self); st != StateOK {
				t.Fatalf("state after install = %s:\n%s", st, out)
			}
			if st, _ := h.State("/elsewhere/passess"); st != StateDrift {
				t.Fatalf("another binary should read as drift, got %s", st)
			}
			if spec.Style != HookPlugin {
				for _, e := range spec.Events {
					if !strings.Contains(string(out), self+" hook "+spec.Harness+" "+e.Name) {
						t.Fatalf("no handler for %s:\n%s", e.Name, out)
					}
				}
				var doc any
				if err := jsonedit.Decode(out, &doc); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(before, "my-formatter") && !strings.Contains(string(out), "my-formatter") {
					t.Fatal("the user's hook was lost")
				}
			} else if !strings.Contains(string(out), `const PASSESS = "`+self+`"`) {
				t.Fatalf("plugin does not name the binary:\n%s", out)
			}
			// Installing again changes nothing.
			if again, _ := h.Edit(out, self, true); string(again) != string(out) {
				t.Fatalf("install is not idempotent:\n%s\n---\n%s", out, again)
			}
			back, err := h.Edit(out, self, false)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case spec.Style == HookPlugin:
				if back != nil {
					t.Fatal("uninstall should remove the plugin file")
				}
			case before != "":
				if string(back) != before {
					t.Fatalf("uninstall is not byte-identical:\n%s\n---\n%s", before, back)
				}
			}
		})
	}
}

func TestIsPassessCommand(t *testing.T) {
	for cmd, want := range map[string]bool{
		"passess hook claude PreToolUse": true, "/opt/homebrew/bin/passess hook codex X": true,
		"'/Users/a b/bin/passess' hook claude X": true, "passess exec -s X -- y": false, "my-linter": false, "passessx hook a b": false,
	} {
		if IsPassessCommand(cmd, "") != want {
			t.Errorf("IsPassessCommand(%q) != %v", cmd, want)
		}
	}
	if !IsPassessCommand("/tmp/go-build/cli.test hook claude X", "/tmp/go-build/cli.test") {
		t.Error("the running binary is passess too")
	}
}
