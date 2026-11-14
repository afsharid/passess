package jsonedit

import (
	"encoding/json"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
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

// A hostile config that nests a million levels must come back as an error:
// hujson.Parse recurses per level and a stack overflow is fatal.
func TestDeepNestingIsRefused(t *testing.T) {
	const n = 1_000_000
	deep := strings.Repeat("[", n) + strings.Repeat("]", n)
	deepObj := strings.Repeat(`{"passess-fake":`, n) + "1" + strings.Repeat("}", n)
	for name, doc := range map[string]string{"arrays": deep, "objects": deepObj} {
		t.Run(name, func(t *testing.T) {
			src := []byte(doc)
			var out any
			if err := Decode(src, &out); err == nil {
				t.Error("Decode accepted deep nesting")
			}
			if _, err := Set(src, nil, "k", 1); err == nil {
				t.Error("Set accepted deep nesting")
			}
			if _, err := Append(src, nil, 1); err == nil {
				t.Error("Append accepted deep nesting")
			}
			if _, err := RemoveWhere(src, nil, func(any) bool { return true }); err == nil {
				t.Error("RemoveWhere accepted deep nesting")
			}
			if _, err := Delete(src, nil, "k"); err == nil {
				t.Error("Delete accepted deep nesting")
			}
		})
	}
}

// Brackets inside strings and comments do not count as nesting, and nesting
// up to the limit still parses.
func TestDepthCountSkipsStringsAndComments(t *testing.T) {
	filler := strings.Repeat("[", maxDepth+10)
	doc := `{"a": "` + filler + `\"` + filler + `", // ` + filler + "\n" + `/* ` + filler + ` */ "b": 1}`
	var out map[string]any
	if err := Decode([]byte(doc), &out); err != nil {
		t.Fatalf("brackets in strings and comments rejected: %v", err)
	}
	ok := strings.Repeat("[", maxDepth) + strings.Repeat("]", maxDepth)
	if err := Decode([]byte(ok), new(any)); err != nil {
		t.Errorf("nesting at the limit rejected: %v", err)
	}
	over := strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1)
	if err := Decode([]byte(over), new(any)); err == nil {
		t.Error("nesting over the limit accepted")
	}
}

// Inputs that stress the counter's string and comment skipping. Every one is
// valid for hujson or refused by it; none may pass the counter at less depth
// than hujson builds, and the ones holding brackets only in strings or
// comments must still decode.
func TestDepthCountEdgeCases(t *testing.T) {
	n := maxDepth + 88
	open := strings.Repeat("[", n)
	mixed := func(pairs int) string {
		return strings.Repeat(`{"a":[`, pairs) + strings.Repeat(`]}`, pairs)
	}
	for name, tc := range map[string]struct {
		doc string
		ok  bool
	}{
		"escaped backslash before closing quote": {`["` + open + `\\", ` + `[1]]`, true},
		"escaped quote keeps string open":        {`["` + open + `\"` + open + `"]`, true},
		"closed line comment":                    {"[1, // " + open + "\n2]", true},
		"closed block comment":                   {"[1, /* " + open + " */ 2]", true},
		"slash star slash is not a close":        {"[/*/ " + open + " */ 1]", true},
		"unterminated string":                    {`["` + open, false},
		"unterminated line comment":              {"[1, // " + open, false},
		"unterminated block comment":             {"[1, /* " + open, false},
		"mixed 256 pairs":                        {mixed(maxDepth / 2), true},
		"mixed 257 pairs":                        {mixed(maxDepth/2 + 1), false},
		"array at the limit":                     {strings.Repeat("[", maxDepth) + strings.Repeat("]", maxDepth), true},
		"array over the limit":                   {strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1), false},
	} {
		t.Run(name, func(t *testing.T) {
			err := Decode([]byte(tc.doc), new(any))
			if tc.ok && err != nil {
				t.Errorf("rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("accepted")
			}
			if _, perr := Set([]byte(tc.doc), nil, "k", 1); tc.ok && strings.HasPrefix(tc.doc, "{") && perr != nil {
				t.Errorf("Set rejected: %v", perr)
			}
		})
	}
}

// A closing bracket never takes the count below zero, so stray closers
// cannot hide the nesting that follows them.
func TestDepthCountIsClamped(t *testing.T) {
	strays := strings.Repeat("]", 600) + strings.Repeat("[", maxDepth+1)
	if got := maxNesting([]byte(strays)); got != maxDepth+1 {
		t.Errorf("maxNesting after stray closers = %d, want %d", got, maxDepth+1)
	}
	if err := Decode([]byte(strays), new(any)); err == nil {
		t.Error("stray closers followed by deep nesting accepted")
	}
}

// treeDepth is how deep hujson nests the parsed value.
func treeDepth(v hujson.ValueTrimmed) int {
	deepest := 0
	switch x := v.(type) {
	case *hujson.Object:
		for _, m := range x.Members {
			deepest = max(deepest, treeDepth(m.Value.Value))
		}
		return deepest + 1
	case *hujson.Array:
		for _, e := range x.Elements {
			deepest = max(deepest, treeDepth(e.Value))
		}
		return deepest + 1
	}
	return 0
}

// For documents hujson accepts, the counter reports at least the nesting
// hujson builds, so it can never pass a document the recursive parser would
// overflow on. The inputs are random strings over the characters the counter
// treats specially, and tricky seeds.
func TestDepthCountAgreesWithHujson(t *testing.T) {
	seeds := []string{
		`{"a":[1,{"b":[]}]}`, `["\\"]`, `["\""]`, "[/*/ [[[ */ 1]", "[// [[\n1]",
		`[1, /* ] */ 2]`, `{"k": "[[{{", "j": [[[]]]}`, "[]", "{}", `"x"`, "1",
	}
	alphabet := []string{"[", "]", "{", "}", `"`, `\`, "/", "*", "\n", ",", ":", "1", "a", " ", " ", "\r", `"a":`}
	rng := rand.New(rand.NewPCG(1, 2))
	valid := 0
	check := func(doc string) {
		v, err := hujson.Parse([]byte(doc))
		if err != nil {
			return
		}
		valid++
		if got, want := maxNesting([]byte(doc)), treeDepth(v.Value); got < want {
			t.Fatalf("maxNesting(%q) = %d, hujson nests %d", doc, got, want)
		}
	}
	for _, s := range seeds {
		check(s)
	}
	for range 200000 {
		var b strings.Builder
		for range 1 + rng.IntN(14) {
			b.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		check(b.String())
	}
	if valid < 100 {
		t.Fatalf("only %d random documents were valid; the differential check proves little", valid)
	}
}

// A document over MaxSize is refused by every entry point before hujson sees
// it; one at MaxSize still parses.
func TestSizeCap(t *testing.T) {
	pad := func(n int) []byte { return []byte("{}" + strings.Repeat(" ", n-2)) }
	if err := Decode(pad(MaxSize), new(any)); err != nil {
		t.Errorf("document at the cap rejected: %v", err)
	}
	huge := pad(MaxSize + 1)
	if err := Decode(huge, new(any)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("Decode over the cap: %v", err)
	}
	if _, err := Set(huge, nil, "k", 1); err == nil {
		t.Error("Set accepted a document over the cap")
	}
	if _, err := Append(huge, nil, 1); err == nil {
		t.Error("Append accepted a document over the cap")
	}
	if _, err := RemoveWhere(huge, nil, func(any) bool { return true }); err == nil {
		t.Error("RemoveWhere accepted a document over the cap")
	}
	if _, err := Delete(huge, nil, "k"); err == nil {
		t.Error("Delete accepted a document over the cap")
	}
	flat := []byte("[" + strings.Repeat("1,", MaxSize/2) + "1]")
	if err := Decode(flat, new(any)); err == nil {
		t.Error("a flat array over the cap was parsed")
	}
}
