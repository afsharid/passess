package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/afsharid/passess/internal/agent"
)

func init() {
	commands["activity"] = command{"what the agent ran and what was approved, newest first: secret names and programs, never values", runActivity}
}

// auditMax is the size at which the agent starts a new audit log; the
// previous one is kept as agent-audit.jsonl.1, so the log never holds more
// than twice this.
const auditMax = 2 << 20

// auditPath is the agent's audit log, next to its socket.
func auditPath(getenv func(string) string) (string, error) {
	sock, err := agent.SocketPath(getenv)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(sock), "agent-audit.jsonl"), nil
}

func runActivity(st *Streams, args []string) int {
	fs := flag.NewFlagSet("activity", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	limit := fs.Int("limit", 200, "at most this many entries")
	secret := fs.String("secret", "", "only entries for this secret")
	since := fs.Duration("since", 0, "only entries this recent, such as 24h; 0 for all")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 || *limit < 1 {
		fmt.Fprintln(st.Stderr, "Usage: passess activity [--json] [--limit N] [--secret NAME] [--since 24h]")
		return ExitUsage
	}
	path, err := auditPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	var cutoff time.Time
	if *since > 0 {
		cutoff = time.Now().Add(-*since)
	}
	var entries []auditEntry
	for _, p := range []string{path + ".1", path} { // oldest first
		got, err := readAudit(p, func(e auditEntry) bool {
			return (*secret == "" || slices.Contains(e.Secrets, *secret)) && !e.Time.Before(cutoff)
		})
		if err != nil {
			return failf(st, ExitSoftware, "reading %s: %v", p, err)
		}
		entries = append(entries, got...)
	}
	slices.Reverse(entries)
	if len(entries) > *limit {
		entries = entries[:*limit]
	}
	if *asJSON {
		if entries == nil {
			entries = []auditEntry{}
		}
		return writeJSON(st, entries)
	}
	if len(entries) == 0 {
		fmt.Fprintln(st.Stdout, "no activity yet: the agent records what it runs and what you approve")
		return ExitOK
	}
	for _, e := range entries {
		who := e.Program
		if e.Anchor != "" {
			who += ", asked by " + e.Anchor
		}
		fmt.Fprintf(st.Stdout, "%s  %-8s %-11s %s for %s\n", e.Time.Local().Format("2006-01-02 15:04:05"), e.Kind, e.Outcome,
			strings.Join(e.Secrets, ", "), who)
	}
	return ExitOK
}

// readAudit returns the entries in one log file that keep says to. A line
// that does not parse, such as one cut short by a crash, is skipped; a
// missing file has none.
func readAudit(path string, keep func(auditEntry) bool) ([]auditEntry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []auditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var e auditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil && keep(e) {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}
