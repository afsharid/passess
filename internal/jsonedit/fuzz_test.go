package jsonedit

import (
	"reflect"
	"testing"
)

// FuzzSetDelete: whatever parses must still parse after a Set, hold the new
// member, keep the rest, and come back to the same content after a Delete.
func FuzzSetDelete(f *testing.F) {
	for _, d := range docs {
		f.Add(d)
	}
	f.Fuzz(func(t *testing.T, src string) {
		var before map[string]any
		if Decode([]byte(src), &before) != nil || before == nil {
			return
		}
		if v, ok := before["mcpServers"]; ok {
			if _, obj := v.(map[string]any); !obj {
				return
			}
		}
		out, err := Set([]byte(src), []string{"mcpServers"}, "passess-fuzz", entry)
		if err != nil {
			t.Fatalf("Set: %v\n%q", err, src)
		}
		var after map[string]any
		if err := Decode(out, &after); err != nil {
			t.Fatalf("Set broke the document: %v\n%q\n%q", err, src, out)
		}
		if _, ok := servers(after)["passess-fuzz"]; !ok {
			t.Fatalf("member missing:\n%q", out)
		}
		back, err := Delete(out, []string{"mcpServers"}, "passess-fuzz")
		if err != nil {
			t.Fatalf("Delete: %v", err)
		}
		var restored map[string]any
		if err := Decode(back, &restored); err != nil {
			t.Fatalf("Delete broke the document: %v\n%q\n%q", err, out, back)
		}
		if _, had := before["mcpServers"]; !had {
			delete(restored, "mcpServers")
		}
		if !reflect.DeepEqual(before, restored) {
			t.Fatalf("content changed:\n%q\n%q", src, back)
		}
	})
}
