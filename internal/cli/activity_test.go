package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// activity reads the agent's audit log, the rotated one too, newest first,
// skips a line cut short, and filters by secret and age.
func TestActivity(t *testing.T) {
	noHarness(t)
	dir := t.TempDir()
	t.Setenv("PASSESS_AGENT_SOCK", filepath.Join(dir, "agent.sock"))
	log := filepath.Join(dir, "agent-audit.jsonl")
	line := func(at time.Time, kind, secret, outcome string) string {
		b, _ := json.Marshal(auditEntry{Time: at, Kind: kind, Secrets: []string{secret}, Program: "gh", Outcome: outcome})
		return string(b) + "\n"
	}
	old := time.Now().Add(-48 * time.Hour).UTC()
	recent := time.Now().Add(-time.Hour).UTC()
	if err := os.WriteFile(log+".1", []byte(line(old, "exec", "GITHUB_TOKEN", "ran")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, []byte(line(recent, "approval", "GITHUB_TOKEN", "allowed")+line(recent, "exec", "HASS_TOKEN", "ran")+`{"time": "cut`), 0o600); err != nil {
		t.Fatal(err)
	}
	read := func(args ...string) []auditEntry {
		t.Helper()
		out, errOut, code := run(t, append([]string{"activity", "--json"}, args...)...)
		var got []auditEntry
		if code != 0 || json.Unmarshal([]byte(out), &got) != nil {
			t.Fatalf("%v: exit %d, %s %s", args, code, out, errOut)
		}
		return got
	}
	if got := read(); len(got) != 3 || got[0].Secrets[0] != "HASS_TOKEN" || got[2].Outcome != "ran" || got[2].Time.After(got[0].Time) {
		t.Fatalf("all: %+v", got)
	}
	if got := read("--secret", "GITHUB_TOKEN"); len(got) != 2 {
		t.Fatalf("by secret: %+v", got)
	}
	if got := read("--since", "24h"); len(got) != 2 {
		t.Fatalf("by age: %+v", got)
	}
	if got := read("--limit", "1"); len(got) != 1 {
		t.Fatalf("limit: %+v", got)
	}
	out, _, _ := run(t, "activity")
	if !strings.Contains(out, "GITHUB_TOKEN for gh") {
		t.Fatalf("text:\n%s", out)
	}
	if err := os.Remove(log); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(log + ".1"); err != nil {
		t.Fatal(err)
	}
	if got := read(); len(got) != 0 {
		t.Fatalf("no log: %+v", got)
	}
}

// A log past auditMax is kept as .1 and a new one is started.
func TestAuditLogRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent-audit.jsonl")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", auditMax)), 0o600); err != nil {
		t.Fatal(err)
	}
	l := &auditLog{path: path}
	l.write(auditEntry{Kind: "exec", Secrets: []string{"A"}, Outcome: "ran"})
	if fi, err := os.Stat(path + ".1"); err != nil || fi.Size() != auditMax {
		t.Fatalf("rotated: %v", err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), `"outcome":"ran"`) || len(b) > 1024 {
		t.Fatalf("new log: %q", b)
	}
}
