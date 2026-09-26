package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

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

func (l *auditLog) write(e auditEntry) {
	if l == nil || l.path == "" {
		return
	}
	e.Time = time.Now().UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
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
