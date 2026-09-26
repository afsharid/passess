package agent

import (
	"os"
	"os/exec"
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
