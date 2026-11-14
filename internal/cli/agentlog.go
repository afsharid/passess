package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/afsharid/passess/internal/agent"
)

// auditLog is the agent's record of what it ran and what was approved, one
// JSON object per line. It names secrets and programs, never values; argv
// words that look like credentials are replaced.
type auditLog struct {
	mu     sync.Mutex
	path   string // "" writes nothing
	stderr io.Writer
	warned bool
}

type auditEntry struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`              // exec, ask, approval
	PID     int       `json:"pid,omitempty"`     // the client
	Anchor  string    `json:"anchor,omitempty"`  // the caller an approval belongs to: name (pid)
	Harness string    `json:"harness,omitempty"` // from the client's environment, unverified
	Secrets []string  `json:"secrets"`
	Program string    `json:"program,omitempty"`
	Argv    []string  `json:"argv,omitempty"`
	Dir     string    `json:"dir,omitempty"`
	Outcome string    `json:"outcome"` // ran, refused, failed, allowed, denied, timeout, no-approver, cancelled
	Status  *int      `json:"status,omitempty"`
}

// What one entry may hold. The agent writes what a client sent, and a client
// is not trusted to keep a line short: with these the longest line stays
// under 200 KB even when every byte is escaped, far below what
// readAudit reads.
const (
	auditField   = 256 // bytes of one word, name or path
	auditDir     = 1024
	auditWords   = 32 // argv words kept
	auditSecrets = 64
)

// bounded returns e with every field the client chose cut to its limit; a
// cut field ends in "…".
func (e auditEntry) bounded() auditEntry {
	e.Anchor = clip(e.Anchor, auditField)
	e.Harness = clip(e.Harness, auditField)
	e.Program = clip(e.Program, auditField)
	e.Dir = clip(e.Dir, auditDir)
	e.Secrets = clipAll(e.Secrets, auditSecrets)
	e.Argv = clipAll(e.Argv, auditWords)
	return e
}

// clipAll keeps the first n words, each cut to auditField, and ends with a
// "…" word when it dropped any.
func clipAll(words []string, n int) []string {
	if words == nil {
		return nil
	}
	out := make([]string, 0, min(len(words), n+1))
	for i, w := range words {
		if i == n {
			out = append(out, "…")
			break
		}
		out = append(out, clip(w, auditField))
	}
	return out
}

// clip cuts s to at most n bytes, on a character boundary, and marks the cut.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func (l *auditLog) write(e auditEntry) {
	if l == nil || l.path == "" {
		return
	}
	e.Time = time.Now().UTC()
	e = e.bounded()
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if fi, err := os.Stat(l.path); err == nil && fi.Size() >= auditMax {
		_ = os.Rename(l.path, l.path+".1") // the previous log; the one before it goes
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err == nil {
		_, err = f.Write(append(b, '\n'))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil && !l.warned && l.stderr != nil {
		l.warned = true
		fmt.Fprintf(l.stderr, "passess agent: cannot write the audit log: %v\n", err)
	}
}

func (l *auditLog) approval(secrets []string, program, dir string, anchor agent.Proc, anchored bool, outcome string) {
	e := auditEntry{Kind: "approval", Secrets: secrets, Program: program, Dir: dir, Outcome: outcome}
	if anchored {
		e.Anchor = fmt.Sprintf("%s (%d)", anchor.Name, anchor.PID)
	}
	l.write(e)
}

// outcomeOf names how an exec or ask request ended.
func outcomeOf(code int, ran bool) string {
	switch {
	case ran:
		return "ran"
	case code == ExitNoPerm:
		return "refused"
	case code == 0:
		return "allowed"
	default:
		return "failed"
	}
}
