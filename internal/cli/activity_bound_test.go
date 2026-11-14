package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// One long line, as a client could make the agent write, does not stop
// `activity` from showing the others.
func TestActivityLongLine(t *testing.T) {
	noHarness(t)
	dir := t.TempDir()
	t.Setenv("PASSESS_AGENT_SOCK", filepath.Join(dir, "agent.sock"))
	log := filepath.Join(dir, "agent-audit.jsonl")
	now := time.Now().UTC()
	line := func(program string, argv []string) string {
		b, _ := json.Marshal(auditEntry{Time: now, Kind: "exec", Secrets: []string{"Y"}, Program: program, Argv: argv, Outcome: "ran"})
		return string(b) + "\n"
	}
	huge := make([]string, 8)
	for i := range huge {
		huge[i] = strings.Repeat("\x01", 100000)
	}
	// An overlong line in the middle, and one at the end with no newline.
	body := line("before", nil) + line("big", huge) + line("after", nil) + strings.TrimSuffix(line("big", huge), "\n")
	for _, p := range []string{log + ".1", log} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, errOut, code := run(t, "activity", "--json")
	var got []auditEntry
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("exit %d: %s%s", code, out[:min(len(out), 200)], errOut)
	}
	var names []string
	for _, e := range got {
		names = append(names, e.Program)
	}
	if strings.Join(names, ",") != "after,before,after,before" {
		t.Fatalf("entries %v", names)
	}
}

// The agent keeps every entry short whatever a client sent.
func TestAuditLogBoundsWhatAClientSent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-audit.jsonl")
	l := &auditLog{path: path}
	words := make([]string, 500)
	for i := range words {
		words[i] = strings.Repeat("\x01", 100000)
	}
	l.write(auditEntry{Kind: "exec", Secrets: words, Program: strings.Repeat("p", 5000), Argv: words, Dir: strings.Repeat("é", 5000),
		Anchor: strings.Repeat("a", 5000), Harness: strings.Repeat("h", 5000), Outcome: "ran"})
	l.write(auditEntry{Kind: "exec", Secrets: []string{"GITHUB_TOKEN"}, Program: "gh", Argv: []string{"gh", "api", "user"}, Dir: "/srv/repo", Outcome: "ran"})
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	if len(lines) != 2 || len(lines[0]) > 200<<10 {
		t.Fatalf("%d lines, the first %d bytes", len(lines), len(lines[0]))
	}
	var first, second auditEntry
	if json.Unmarshal(lines[0], &first) != nil || json.Unmarshal(lines[1], &second) != nil {
		t.Fatal("a line does not parse")
	}
	if len(first.Argv) != auditWords+1 || first.Argv[auditWords] != "…" || len(first.Secrets) != auditSecrets+1 {
		t.Fatalf("argv %d words, secrets %d", len(first.Argv), len(first.Secrets))
	}
	if !strings.HasSuffix(first.Dir, "…") || len(first.Dir) > auditDir+len("…") || !strings.HasSuffix(first.Program, "…") {
		t.Fatalf("dir %d bytes, program %q", len(first.Dir), first.Program)
	}
	if strings.Join(second.Argv, " ") != "gh api user" || second.Dir != "/srv/repo" || second.Program != "gh" || second.Secrets[0] != "GITHUB_TOKEN" {
		t.Fatalf("an ordinary entry changed: %+v", second)
	}
}
