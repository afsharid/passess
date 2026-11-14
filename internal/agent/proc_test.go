package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func TestAncestryOfThisProcess(t *testing.T) {
	chain, err := Ancestry(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) < 2 || chain[0].PID != os.Getpid() || chain[1].PID != os.Getppid() {
		t.Fatalf("chain %+v", chain)
	}
	for _, p := range chain {
		if p.Name == "" || p.Start == 0 || !p.Alive() {
			t.Errorf("%+v: missing name or start, or not alive", p)
		}
	}
}

func TestAProcessThatExitedIsNotAlive(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p, err := procInfo(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if p.Alive() {
		t.Fatal("a reaped process is alive")
	}
	if _, err := Ancestry(cmd.Process.Pid); err == nil {
		t.Fatal("the ancestry of a reaped process")
	}
}

func TestTruncated(t *testing.T) {
	for _, c := range []struct {
		chain []Proc
		want  bool
	}{
		{nil, false},
		{[]Proc{{PID: 5, PPID: 1}}, false},
		{[]Proc{{PID: 5, PPID: 4}, {PID: 4, PPID: 1}}, false},
		{[]Proc{{PID: 5, PPID: 4}, {PID: 4, PPID: 3}}, true},
	} {
		if got := Truncated(c.chain); got != c.want {
			t.Errorf("%+v: %v", c.chain, got)
		}
	}
}

// TestMain makes this binary the measurement TestDeepChainIsTruncated runs at
// the bottom of its chain: it reports its own ancestry.
func TestMain(m *testing.M) {
	if os.Getenv("PASSESS_TEST_MEASURE") != "" {
		chain, err := Ancestry(os.Getpid())
		fmt.Printf("%d %v %v\n", len(chain), Truncated(chain), err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// chainScript starts the next level of the chain and waits, so each level is
// a cheap shell; the last level runs the command it was given.
const chainScript = `n=$1; shift
if [ "$n" -gt 0 ]; then
	sh "$0" $((n-1)) "$@"
	status=$?
	exit $status
fi
"$@"
`

// A process cannot choose its ancestors, but it can put enough processes of
// its own below the harness to push it past the cap. Such a chain is
// Truncated, and a short one is not. Only the innermost process is a copy of
// the test binary; the levels above it are shells.
func TestDeepChainIsTruncated(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "chain.sh")
	if err := os.WriteFile(script, []byte(chainScript), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		depth     int
		truncated bool
	}{{3, false}, {70, true}} {
		cmd := exec.Command("/bin/sh", script, strconv.Itoa(c.depth), self)
		cmd.Env = append(os.Environ(), "PASSESS_TEST_MEASURE=1")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("depth %d: %v", c.depth, err)
		}
		var n int
		var trunc bool
		var rest string
		if _, err := fmt.Sscanf(string(out), "%d %t %s", &n, &trunc, &rest); err != nil || trunc != c.truncated || rest != "<nil>" {
			t.Fatalf("depth %d: %q, %v", c.depth, out, err)
		}
		if c.truncated && n != maxAncestry {
			t.Errorf("depth %d: chain of %d, want the cap %d", c.depth, n, maxAncestry)
		}
	}
}

func TestAnchor(t *testing.T) {
	p := func(name string, pid int) Proc { return Proc{PID: pid, Name: name, Start: int64(pid)} }
	for _, c := range []struct {
		chain []Proc
		want  string // "" for no anchor
	}{
		// passess ← zsh (a new one per command) ← claude
		{[]Proc{p("passess", 10), p("zsh", 9), p("claude", 8), p("Claude", 7)}, "claude"},
		// passess ← bash ← -zsh (login) ← codex
		{[]Proc{p("passess", 10), p("bash", 9), p("-zsh", 8), p("codex", 7)}, "codex"},
		// a harness that runs passess directly
		{[]Proc{p("passess", 10), p("opencode.exe", 9)}, "opencode.exe"},
		// a wrapper that forks is an anchor of its own: more prompts, never fewer
		{[]Proc{p("passess", 10), p("time", 9), p("zsh", 8), p("claude", 7)}, "time"},
		// an in-process client counts from its parent
		{[]Proc{p("cli.test", 10), p("go", 9)}, "go"},
		// an orphaned shell anchors nothing
		{[]Proc{p("passess", 10), p("sh", 9)}, ""},
		{[]Proc{p("passess", 10)}, ""},
		{nil, ""},
	} {
		a, ok := Anchor(c.chain)
		if ok != (c.want != "") || a.Name != c.want {
			t.Errorf("Anchor(%v) = %+v, %v; want %q", c.chain, a, ok, c.want)
		}
	}
}
