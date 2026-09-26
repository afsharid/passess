package agent

import "github.com/afsharid/passess/internal/detect"

// Proc is one process as the kernel describes it.
type Proc struct {
	PID  int    `json:"pid"`
	PPID int    `json:"-"`
	Name string `json:"name"` // the executable's name as the kernel keeps it: 16 bytes on macOS, 15 on Linux
	// Start is when the process started, in a unit only equality needs; with
	// PID it names the process across pid reuse.
	Start int64 `json:"-"`
}

// Same reports whether p and q are the same process, not merely the same pid.
func (p Proc) Same(q Proc) bool { return p.PID == q.PID && p.Start == q.Start }

// Alive reports whether p is still running: its pid is taken by the process
// that started when p did.
func (p Proc) Alive() bool {
	q, err := procInfo(p.PID)
	return err == nil && p.Same(q)
}

// Ancestry returns the process pid and its ancestors, nearest first, up to
// but not including pid 1.
func Ancestry(pid int) ([]Proc, error) {
	var chain []Proc
	for pid > 1 && len(chain) < 64 {
		p, err := procInfo(pid)
		if err != nil {
			if len(chain) == 0 {
				return nil, err
			}
			break // an ancestor exited meanwhile; the chain ends there
		}
		chain = append(chain, p)
		pid = p.PPID
	}
	return chain, nil
}

// shells are the programs an anchor search looks through: a harness runs
// each command in one, and a shell says nothing about who asked.
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true,
	"fish": true, "tcsh": true, "csh": true, "nu": true, "xonsh": true}

// Anchor is the process an approval belongs to: the nearest ancestor of the
// caller, chain[0], that is neither passess nor a shell. Claude Code, for one,
// starts every command in a new session, so neither the session nor the
// shell names it; its own process does, and a process cannot choose its
// ancestors. ok is false when the chain ends without such a process (an
// orphaned shell): then nothing is remembered.
func Anchor(chain []Proc) (Proc, bool) {
	for _, p := range chain[min(1, len(chain)):] {
		if p.Name == "passess" || shells[p.Name] || shells[trimLogin(p.Name)] {
			continue
		}
		return p, true
	}
	return Proc{}, false
}

// trimLogin turns a login shell's "-zsh" into "zsh".
func trimLogin(name string) string {
	if len(name) > 1 && name[0] == '-' {
		return name[1:]
	}
	return name
}

// HarnessOf returns the harness a process's name belongs to, or "".
func HarnessOf(p Proc) string { return detect.Program(p.Name) }
