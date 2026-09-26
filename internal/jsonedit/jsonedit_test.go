package jsonedit

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type server struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

var entry = server{Command: "/opt/bin/passess", Args: []string{"mcp-exec", "github"}}

// docs are the shapes real harness configs come in.
var docs = map[string]string{
	"two spaces": `{
  "theme": "dark",
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "server-fs"]
    }
  }
}
`,
	"four spaces, no trailing newline": "{\n    \"mcpServers\": {\n        \"fs\": {\"command\": \"npx\"}\n    }\n}",
	"tabs":                             "{\n\t\"mcpServers\": {\n\t\t\"fs\": {\n\t\t\t\"command\": \"npx\"\n\t\t}\n\t}\n}\n",
	"jsonc with comments and trailing commas": `{
  // the harness's own settings
  "$schema": "https://opencode.ai/config.json",
  "mcpServers": {
    /* local tools */
    "fs": {
      "command": "npx", // pinned
    },
  },
  "theme": "dark",
}
`,
	"comment after the last member": "{\n  \"mcpServers\": {\n    \"fs\": {\"command\": \"npx\"} // the only one\n  }\n}\n",
	"empty servers":                 "{\n  \"mcpServers\": {}\n}\n",
	"no servers yet":                "{\n  \"theme\": \"dark\"\n}\n",
	"one line":                      `{"mcpServers": {"fs": {"command": "npx"}}}`,
	"empty document":                "",
}

func decode(t *testing.T, src []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := Decode(src, &m); err != nil {
		t.Fatalf("result does not parse: %v\n%s", err, src)
	}
	return m
}

func servers(m map[string]any) map[string]any {
	s, _ := m["mcpServers"].(map[string]any)
	return s
}

func TestSetAddsAndDeleteRestores(t *testing.T) {
	for name, src := range docs {
		t.Run(name, func(t *testing.T) {
			before := map[string]any{}
			if strings.TrimSpace(src) != "" {
				before = decode(t, []byte(src))
			}
			out, err := Set([]byte(src), []string{"mcpServers"}, "github", entry)
			if err != nil {
				t.Fatal(err)
			}
			after := decode(t, out)
			var want any
			raw, _ := json.Marshal(entry)
			_ = json.Unmarshal(raw, &want)
			if got := servers(after)["github"]; !reflect.DeepEqual(got, want) {
				t.Fatalf("github = %v, want %v\n%s", got, want, out)
			}
			// Everything else is untouched.
			delete(servers(after), "github")
			if len(servers(after)) == 0 && servers(before) == nil {
				delete(after, "mcpServers")
			}
			if bothEmpty := len(before) == 0 && len(after) == 0; !bothEmpty && !reflect.DeepEqual(before, after) {
				t.Fatalf("other content changed:\nbefore %v\nafter  %v\n%s", before, after, out)
			}
			if json.Valid([]byte(src)) && !json.Valid(out) {
				t.Fatalf("strict JSON became JSONC:\n%s", out)
			}
			for _, c := range []string{"// the harness's own settings", "/* local tools */", "// pinned", "// the only one"} {
				if strings.Contains(src, c) && !strings.Contains(string(out), c) {
					t.Fatalf("comment %q lost:\n%s", c, out)
				}
			}
			back, err := Delete(out, []string{"mcpServers"}, "github")
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "no servers yet", "empty document":
				// The servers object passess created stays, empty.
				if s := servers(decode(t, back)); len(s) != 0 {
					t.Fatalf("after delete: %s", back)
				}
			default:
				if string(back) != src {
					t.Fatalf("add then delete is not byte-identical:\n--- before\n%s\n--- after\n%s", src, back)
				}
			}
		})
	}
}

func TestSetReplacesInPlace(t *testing.T) {
	src := docs["jsonc with comments and trailing commas"]
	out, err := Set([]byte(src), []string{"mcpServers"}, "fs", entry)
	if err != nil {
		t.Fatal(err)
	}
	if got := servers(decode(t, out))["fs"].(map[string]any)["command"]; got != entry.Command {
		t.Fatalf("fs.command = %v\n%s", got, out)
	}
	for _, keep := range []string{"/* local tools */", "\"theme\": \"dark\",", "// the harness's own settings"} {
		if !strings.Contains(string(out), keep) {
			t.Fatalf("lost %q:\n%s", keep, out)
		}
	}
	// A second identical Set is a no-op.
	again, _ := Set(out, []string{"mcpServers"}, "fs", entry)
	if string(again) != string(out) {
		t.Fatalf("Set is not idempotent:\n%s\n%s", out, again)
	}
}

func TestDelete(t *testing.T) {
	src := `{
  "mcpServers": {
    "a": {"command": "a"},
    // about b
    "b": {"command": "b"}, // same line
    "c": {"command": "c"}
  }
}
`
	for name, want := range map[string]string{
		"a": "{\n  \"mcpServers\": {\n    // about b\n    \"b\": {\"command\": \"b\"}, // same line\n    \"c\": {\"command\": \"c\"}\n  }\n}\n",
		"b": "{\n  \"mcpServers\": {\n    \"a\": {\"command\": \"a\"},\n    // about b\n    \"c\": {\"command\": \"c\"}\n  }\n}\n",
		"c": "{\n  \"mcpServers\": {\n    \"a\": {\"command\": \"a\"},\n    // about b\n    \"b\": {\"command\": \"b\"} // same line\n  }\n}\n",
		"z": src,
	} {
		got, err := Delete([]byte(src), []string{"mcpServers"}, name)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("delete %s:\n%s\nwant\n%s", name, got, want)
		}
		decode(t, got)
	}
	if got, _ := Delete([]byte(`{"x": 1}`), []string{"mcpServers"}, "a"); string(got) != `{"x": 1}` {
		t.Fatalf("missing path: %s", got)
	}
}

func TestNestedPathAndErrors(t *testing.T) {
	out, err := Set([]byte("{\n  \"mcp\": {\n    \"servers\": {}\n  }\n}\n"), []string{"mcp", "servers"}, "github", entry)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		MCP struct {
			Servers map[string]server `json:"servers"`
		} `json:"mcp"`
	}
	if err := Decode(out, &m); err != nil || m.MCP.Servers["github"].Command != entry.Command {
		t.Fatalf("nested = %+v %v\n%s", m, err, out)
	}
	if _, err := Set([]byte(`{"mcpServers": []}`), []string{"mcpServers"}, "x", entry); err == nil {
		t.Fatal("a non-object path was accepted")
	}
	if _, err := Set([]byte(`{"mcpServers": {`), []string{"mcpServers"}, "x", entry); err == nil {
		t.Fatal("broken JSON was accepted")
	}
}
