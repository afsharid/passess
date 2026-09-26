// Package agent is the transport between passess clients and `passess agent`:
// a Unix socket that only the user's own processes may use. A client hands
// over its standard streams and a request and gets back an exit status. No
// secret value crosses the socket in either direction; the agent runs the
// child itself (ADR 8).
package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// Version is the protocol version. A status or stop request, and the field
// that carries this number, keep their shape across versions so that any
// passess can stop any agent.
const Version = 1

// Kind is what a request asks for.
type Kind string

const (
	Exec     Kind = "exec"     // run a command with secrets; the client's stdio is attached
	Ask      Kind = "ask"      // may these secrets go to this command? No value either way
	Approver Kind = "approver" // answer asks for as long as the connection lasts
	Status   Kind = "status"   // describe the agent
	Lock     Kind = "lock"     // forget every cached value and approval
	Stop     Kind = "stop"     // stop accepting, forget, exit once running commands end
)

// Secret is one -s flag: the variable to set and the secret it gets.
type Secret struct {
	Env  string `json:"env"`
	Name string `json:"name"`
}

// Request is what a client asks for. It carries the client's whole
// environment, which may hold credentials of its own, so nothing may format
// or log it; Environ prints as a count.
type Request struct {
	V       int      `json:"v"`
	Build   string   `json:"build,omitempty"` // the client's passess version
	Kind    Kind     `json:"kind"`
	Argv    []string `json:"argv,omitempty"`
	Dir     string   `json:"dir,omitempty"`
	Env     Environ  `json:"env,omitempty"`
	Secrets []Secret `json:"secrets,omitempty"`
	Config  string   `json:"config,omitempty"` // the user config path the client would read
}

// Environ is an environment in KEY=value form. Every fmt verb prints only how
// many variables it holds; JSON carries it whole.
type Environ []string

func (e Environ) String() string             { return fmt.Sprintf("[%d variables]", len(e)) }
func (e Environ) GoString() string           { return e.String() }
func (e Environ) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, e.String()) }

// Lookup returns the value of key, as os.LookupEnv would; the last entry wins.
func (e Environ) Lookup(key string) (string, bool) {
	for i := len(e) - 1; i >= 0; i-- {
		if len(e[i]) > len(key) && e[i][len(key)] == '=' && e[i][:len(key)] == key {
			return e[i][len(key)+1:], true
		}
	}
	return "", false
}

// Frame is one message after the request: signals from the client, then one
// reply from the agent.
type Frame struct {
	Signal int     `json:"signal,omitempty"` // client → agent: deliver this signal to the child
	Status *int    `json:"status,omitempty"` // agent → client: the exit status; the last frame
	Error  string  `json:"error,omitempty"`  // agent → client: why a request failed, as the client would say it
	Info   *Info   `json:"info,omitempty"`   // agent → client: the answer to Status
	Ask    *AskFor `json:"ask,omitempty"`    // agent → approver: a question
	Cancel string  `json:"cancel,omitempty"` // agent → approver: the question with this ID is settled
	Answer *Answer `json:"answer,omitempty"` // approver → agent
}

// AskFor is a question for an approver: may these secrets go to this
// command? It carries names and the command, never a value.
type AskFor struct {
	ID      string    `json:"id"`
	Secrets []string  `json:"secrets"`
	Program string    `json:"program"` // the program family the secrets would go to
	Path    string    `json:"path"`    // the executable, resolved
	Argv    []string  `json:"argv"`    // with words that look like credentials replaced
	Dir     string    `json:"dir"`
	Harness string    `json:"harness,omitempty"` // from the caller's environment: a label, unverified
	Anchor  *Proc     `json:"anchor,omitempty"`  // the process an Allow is remembered for; nil: it is not
	Until   time.Time `json:"until,omitzero"`    // how long an Allow lasts
}

// Answer is an approver's reply.
type Answer struct {
	ID    string `json:"id"`
	Allow bool   `json:"allow"`
}

// Approval is an Allow the agent remembers.
type Approval struct {
	Secret  string    `json:"secret"`
	Program string    `json:"program"`
	Anchor  Proc      `json:"anchor"`
	Until   time.Time `json:"until"`
}

// Info describes a running agent. It names secrets, never values.
type Info struct {
	PID      int       `json:"pid"`
	Build    string    `json:"build"`
	Protocol int       `json:"protocol"`
	Started  time.Time `json:"started"`
	Socket   string    `json:"socket"`
	Config   string    `json:"config"`
	CacheTTL string    `json:"cache_ttl"`
	Cached   []string  `json:"cached"`           // secrets whose values the agent holds
	Expires  time.Time `json:"expires,omitzero"` // when it forgets them
	Busy     bool      `json:"busy,omitempty"`   // a vault was being asked; Cached may lag
	Jobs     int       `json:"jobs"`             // commands running
	Served   int       `json:"served"`           // exec requests since it started
	Stopping bool      `json:"stopping,omitempty"`

	Approvers int        `json:"approvers"` // connected
	Approvals []Approval `json:"approvals"`
	Pending   int        `json:"pending"` // questions no one has answered yet
}

// ErrNotRunning means no agent listens on the socket.
var ErrNotRunning = errors.New("the passess agent is not running")

// ErrRunning means another agent already serves the socket.
var ErrRunning = errors.New("a passess agent is already running")

// maxPath is the longest socket path every supported system accepts
// (sun_path is 104 bytes on macOS, including the terminating NUL).
const maxPath = 103

// SocketPath returns where the agent listens: $PASSESS_AGENT_SOCK, else
// $XDG_RUNTIME_DIR/passess/agent.sock, else ~/.local/state/passess/agent.sock.
// It deliberately ignores XDG_STATE_HOME: an agent started from the GUI and a
// client started from a shell must agree without sharing shell settings.
func SocketPath(getenv func(string) string) (string, error) {
	p := getenv("PASSESS_AGENT_SOCK")
	switch {
	case p != "":
	case getenv("XDG_RUNTIME_DIR") != "":
		p = filepath.Join(getenv("XDG_RUNTIME_DIR"), "passess", "agent.sock")
	case getenv("HOME") != "":
		p = filepath.Join(getenv("HOME"), ".local", "state", "passess", "agent.sock")
	default:
		return "", errors.New("cannot locate the agent socket: HOME is not set")
	}
	if len(p) > maxPath {
		return "", fmt.Errorf("the agent socket path %s is longer than %d bytes; set PASSESS_AGENT_SOCK to a shorter one", p, maxPath)
	}
	return p, nil
}
