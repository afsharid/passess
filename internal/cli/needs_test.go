package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// needs adds and removes [needs.NAME] in a project's passess.toml, starts
// one when there is none, finds the nearest one from a subdirectory, says
// which names the user config defines, and leaves nothing else behind.
func TestNeeds(t *testing.T) {
	noHarness(t)
	writeConfig(t, "version = 1\n[secrets.GITHUB_TOKEN]\nref = \"env://GH\"\n")
	proj := t.TempDir()
	sub := filepath.Join(proj, "web", "src")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(args ...string) string {
		t.Helper()
		out, errOut, code := run(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d, %q %q", args, code, out, errOut)
		}
		return out
	}
	list := func(dir string) needsOutput {
		t.Helper()
		var got needsOutput
		if err := json.Unmarshal([]byte(must("needs", "list", "--json", "--dir", dir)), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := list(proj); got.Path != "" || len(got.Needs) != 0 {
		t.Fatalf("no file yet: %+v", got)
	}
	must("needs", "add", "GITHUB_TOKEN", "--dir", proj, "--note", "release notes", "--allow", "gh")
	must("needs", "add", "OPENAI_API_KEY", "--dir", proj)
	file := filepath.Join(proj, "passess.toml")
	data, _ := os.ReadFile(file)
	want := "version = 1\n\n[needs.GITHUB_TOKEN]\nnote = \"release notes\"\nallow = [\"gh\"]\n\n[needs.OPENAI_API_KEY]\n"
	if string(data) != want {
		t.Fatalf("file:\n%s\nwant:\n%s", data, want)
	}
	got := list(sub) // found from below
	if got.Path != file || len(got.Needs) != 2 || !got.Needs[0].Defined || got.Needs[1].Defined || got.Needs[0].Allow[0] != "gh" {
		t.Fatalf("list: %+v", got)
	}
	must("needs", "remove", "OPENAI_API_KEY", "--dir", sub)
	if got := list(proj); len(got.Needs) != 1 {
		t.Fatalf("after remove: %+v", got)
	}
	entries, _ := os.ReadDir(proj)
	for _, e := range entries {
		if e.Name() != "passess.toml" && e.Name() != "web" {
			t.Fatalf("left %s in the project", e.Name())
		}
	}
	if _, errOut, code := run(t, "needs", "add", "not-a-name", "--dir", proj); code != ExitUsage || !strings.Contains(errOut, "not a secret name") {
		t.Fatalf("bad name: exit %d, %q", code, errOut)
	}
	if _, _, code := run(t, "needs", "remove", "X", "--dir", t.TempDir()); code != ExitConfig {
		t.Fatalf("remove with no file: exit %d", code)
	}
}
