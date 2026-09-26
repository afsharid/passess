package jsonedit

import (
	"reflect"
	"strings"
	"testing"
)

type hookGroup struct {
	Matcher string `json:"matcher"`
	Hooks   []struct {
		Type    string `json:"type"`
		Command string `json:"command"`
	} `json:"hooks"`
}

func passessGroup() hookGroup {
	g := hookGroup{Matcher: "Bash"}
	g.Hooks = append(g.Hooks, struct {
		Type    string `json:"type"`
		Command string `json:"command"`
	}{"command", "passess hook claude PreToolUse"})
	return g
}

// isPassess finds the elements passess added.
func isPassess(v any) bool {
	g, _ := v.(map[string]any)
	hooks, _ := g["hooks"].([]any)
	for _, h := range hooks {
		if m, _ := h.(map[string]any); m != nil {
			if c, _ := m["command"].(string); strings.HasPrefix(c, "passess hook ") {
				return true
			}
		}
	}
	return false
}

var hookDocs = map[string]string{
	"settings with a hook": `{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit",
        "hooks": [{"type": "command", "command": "my-linter"}]
      }
    ]
  }
}
`,
	"jsonc, trailing commas": `{
  // user hooks
  "hooks": {
    "PreToolUse": [
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "fmt"}]}, // formatting
    ],
  },
}
`,
	"empty array":      "{\n  \"hooks\": {\n    \"PreToolUse\": []\n  }\n}\n",
	"one-line array":   `{"hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": []}]}}`,
	"no hooks yet":     "{\n  \"model\": \"opus\"\n}\n",
	"array of strings": "{\n  \"hooks\": {\n    \"PreToolUse\": [\n      \"a\",\n      \"b\"\n    ]\n  }\n}\n",
}

var hookPath = []string{"hooks", "PreToolUse"}

func TestAppendAndRemoveWhere(t *testing.T) {
	for name, src := range hookDocs {
		t.Run(name, func(t *testing.T) {
			before := decode(t, []byte(src))
			out, err := Append([]byte(src), hookPath, passessGroup())
			if err != nil {
				t.Fatal(err)
			}
			after := decode(t, out)
			hooks, _ := after["hooks"].(map[string]any)
			list, _ := hooks["PreToolUse"].([]any)
			if len(list) == 0 || !isPassess(list[len(list)-1]) {
				t.Fatalf("not appended last:\n%s", out)
			}
			if strings.Contains(src, "// formatting") && !strings.Contains(string(out), "// formatting") {
				t.Fatalf("comment lost:\n%s", out)
			}
			// A second passess element, then both go in one call.
			out, _ = Append(out, hookPath, passessGroup())
			back, err := RemoveWhere(out, hookPath, isPassess)
			if err != nil {
				t.Fatal(err)
			}
			if name == "no hooks yet" {
				restored := decode(t, back)
				delete(restored, "hooks")
				if !reflect.DeepEqual(before, restored) {
					t.Fatalf("content changed:\n%s", back)
				}
				return
			}
			if string(back) != src {
				t.Fatalf("append then remove is not byte-identical:\n--- before\n%s\n--- after\n%s", src, back)
			}
		})
	}
	if _, err := Append([]byte(`{"hooks": {"PreToolUse": {}}}`), hookPath, 1); err == nil {
		t.Fatal("appending to an object was accepted")
	}
	if got, _ := RemoveWhere([]byte(`{"x": 1}`), hookPath, isPassess); string(got) != `{"x": 1}` {
		t.Fatalf("missing path: %s", got)
	}
}

func FuzzAppendRemove(f *testing.F) {
	for _, d := range hookDocs {
		f.Add(d)
	}
	f.Fuzz(func(t *testing.T, src string) {
		var before map[string]any
		if Decode([]byte(src), &before) != nil || before == nil {
			return
		}
		if h, ok := before["hooks"]; ok {
			hm, isObj := h.(map[string]any)
			if !isObj {
				return
			}
			if p, ok := hm["PreToolUse"]; ok {
				list, isArr := p.([]any)
				if !isArr {
					return
				}
				for _, e := range list {
					if isPassess(e) {
						return // the document already holds a passess element
					}
				}
			}
		}
		out, err := Append([]byte(src), hookPath, passessGroup())
		if err != nil {
			t.Fatalf("Append: %v\n%q", err, src)
		}
		back, err := RemoveWhere(out, hookPath, isPassess)
		if err != nil {
			t.Fatalf("RemoveWhere: %v\n%q", err, out)
		}
		var restored map[string]any
		if err := Decode(back, &restored); err != nil {
			t.Fatalf("broke the document: %v\n%q\n%q", err, out, back)
		}
		if _, had := before["hooks"]; !had {
			delete(restored, "hooks")
		} else if hm := before["hooks"].(map[string]any); hm["PreToolUse"] == nil {
			delete(restored["hooks"].(map[string]any), "PreToolUse")
		}
		if !reflect.DeepEqual(before, restored) {
			t.Fatalf("content changed:\n%q\n%q", src, back)
		}
	})
}
