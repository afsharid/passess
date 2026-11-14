package hook

import (
	"strings"
	"testing"
	"time"
)

// Long command lines cost time in proportion to their length: a hook that runs
// past the harness timeout fails open. Each shape is timed at two sizes; a
// quadratic step makes the larger run about four times the smaller one's cost
// per doubling, a linear one twice. Only the growth is checked: the absolute
// time depends on the machine and on the race detector.
func TestLongCommandLinesAreLinear(t *testing.T) {
	env := testEnv(t)
	shapes := map[string]func(n int) string{
		"wrapper chain then passess": func(n int) string {
			return strings.Repeat("sudo ", n) + strings.Repeat("passess ", n)
		},
		"cd chain":   func(n int) string { return strings.Repeat("cd a && ", n) + "ls" },
		"eval chain": func(n int) string { return strings.Repeat("eval ", n) + "ls" },
		"function re-walks": func(n int) string {
			return "f() { ls; }; " + strings.Repeat("f; ", n)
		},
		"watch chain":      func(n int) string { return strings.Repeat("watch ", n) + "ls" },
		"su chain":         func(n int) string { return strings.Repeat("su ", n) + "ls" },
		"apply_patch list": func(n int) string { return strings.Repeat("apply_patch; ", n) },
		"nested wrappers with options": func(n int) string {
			return strings.Repeat("sudo -u root ", n) + "ls"
		},
	}
	decide := func(cmd string) time.Duration {
		best := time.Hour
		for i := 0; i < 3; i++ {
			start := time.Now()
			Decide(Event{Kind: Shell, Command: cmd, CWD: "/home/u/proj"}, env)
			best = min(best, time.Since(start))
		}
		return best
	}
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			small, large := decide(shape(1000)), decide(shape(4000))
			t.Logf("1000: %v, 4000: %v", small, large)
			// 4x the input: linear costs about 4x, quadratic about 16x.
			if large > 8*small+5*time.Millisecond {
				t.Errorf("cost grows faster than the input: %v at 1000, %v at 4000", small, large)
			}
		})
	}
}

// Command lines inside command lines are parsed again at each level, so the
// depth is bounded: a chain of eval or watch is refused past it, and below it
// a refusal still reaches the innermost command.
func TestNestedShellsAreBounded(t *testing.T) {
	env := testEnv(t)
	for _, c := range []struct {
		cmd  string
		deny bool
	}{
		{"eval eval eval ls", false},
		{"eval eval eval eval eval cat .env", true},
		{"watch watch watch ls", false},
		{`watch watch "cat .env"`, true},
		{"su su -c 'cat .env'", true},
		{"sudo sudo sudo sudo sudo sudo sudo -u root sudo passess agent stop", true},
		{"sudo -u a sudo -u b su -c 'passess agent stop'", true},
		{strings.Repeat("eval ", maxShellDepth+8) + "ls", true},
		{strings.Repeat("watch ", maxShellDepth+8) + "ls", true},
	} {
		v := Decide(Event{Kind: Shell, Command: c.cmd, CWD: "/home/u/proj"}, env)
		if v.Deny != c.deny {
			t.Errorf("refused=%v, want %v: %.60s: %s", v.Deny, c.deny, c.cmd, v.Reason)
		}
	}
	if v := Decide(Event{Kind: Shell, Command: strings.Repeat("eval ", maxShellDepth+8) + "ls", CWD: "/home/u/proj"}, env); v.Reason != nestedReason {
		t.Errorf("reason for a deep chain: %s", v.Reason)
	}
}

// A cd chain so long that its path passes the system's limit leaves the
// directory unknown, and an unknown directory that last was a protected one
// still refuses the config's name.
func TestLongCdChainKeepsProtectedDirectory(t *testing.T) {
	env := testEnv(t)
	cmd := "cd ~/.config/passess && " + strings.Repeat("cd a && ", 3000) + "echo x >> config.toml"
	if v := Decide(Event{Kind: Shell, Command: cmd, CWD: "/home/u/proj"}, env); !v.Deny {
		t.Error("a write to config.toml after a long cd chain from the config directory was allowed")
	}
	cmd = "cd a && " + strings.Repeat("cd a && ", 3000) + "echo x >> config.toml"
	if v := Decide(Event{Kind: Shell, Command: cmd, CWD: "/home/u/proj"}, env); v.Deny {
		t.Errorf("a long cd chain inside the project was refused: %s", v.Reason)
	}
}
