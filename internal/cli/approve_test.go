package cli

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/afsharid/passess/internal/agent"
	"github.com/afsharid/passess/internal/buildinfo"
	"github.com/afsharid/passess/internal/policy"
)

// setupApprovals is setup with X needing approval; agent adds lines to the
// [agent] table.
func setupApprovals(t *testing.T, agentLines ...string) {
	t.Helper()
	dir := setupDir(t)
	body := `version = 1
[secrets.X]
ref     = "env://PASSESS_TEST_X_TOKEN"
allow   = ["sh"]
approve = true
[secrets.Y]
ref   = "env://PASSESS_TEST_Y_TOKEN"
allow = ["sh"]
[profiles.svc]
secrets = ["X"]
allow   = ["sh"]
[agent]
` + strings.Join(agentLines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeApprover answers the agent's questions the way decide says; with a nil
// decide it only collects them.
type fakeApprover struct {
	c      *agent.Conn
	mu     sync.Mutex
	asks   []agent.AskFor
	notify chan agent.AskFor
}

func connectApprover(t *testing.T, decide func(agent.AskFor) bool) *fakeApprover {
	t.Helper()
	c := dialApprover(t)
	if err := c.Send(agent.Request{V: agent.Version, Build: buildinfo.String(), Kind: agent.Approver}, nil); err != nil {
		t.Fatal(err)
	}
	if f, err := c.ReadFrame(); err != nil || f.Status == nil {
		t.Fatalf("the agent did not take the approver: %+v, %v", f, err)
	}
	a := &fakeApprover{c: c, notify: make(chan agent.AskFor, 16)}
	go func() {
		for {
			f, err := c.ReadFrame()
			if err != nil {
				return
			}
			if f.Ask == nil {
				continue
			}
			a.mu.Lock()
			a.asks = append(a.asks, *f.Ask)
			a.mu.Unlock()
			a.notify <- *f.Ask
			if decide != nil {
				_ = c.Write(agent.Frame{Answer: &agent.Answer{ID: f.Ask.ID, Allow: decide(*f.Ask)}})
			}
		}
	}()
	return a
}

func (a *fakeApprover) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.asks)
}

func allowAll(agent.AskFor) bool { return true }

// dialApprover connects to the agent the way Passess.app does, from a
// process whose parent is launchd: a relay, this test binary started by a
// shell that exits at once. A connection of the test's own has the test's
// ancestors, and when they include a coding agent (the tests run from one),
// the agent refuses it as an approver.
func dialApprover(t *testing.T) *agent.Conn {
	t.Helper()
	sock := os.Getenv("PASSESS_AGENT_SOCK")
	dir, err := os.MkdirTemp(filepath.Dir(sock), "r") // beside the agent's: a socket path must stay short
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	listen := filepath.Join(dir, "s")
	sh := exec.Command("/bin/sh", "-c", `"$0" &`, self)
	sh.Env = append(os.Environ(), "PASSESS_TEST_RELAY="+listen, "PASSESS_TEST_RELAY_TO="+sock)
	if err := sh.Run(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		c, err := agent.Dial(listen)
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay never listened: %v", err)
		}
	}
}

// relay is the process dialApprover starts. It connects to the agent at to
// only once the test has connected on listen, which the test does after the
// shell is gone: by then launchd (init on Linux) is the relay's parent. It
// copies bytes both ways until either side closes.
func relay(listen, to string) int {
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: listen, Net: "unix"})
	if err != nil {
		return 1
	}
	_ = l.SetDeadline(time.Now().Add(time.Minute)) // a test that never connects leaves no relay behind
	down, err := l.Accept()
	_ = l.Close()
	if err != nil {
		return 1
	}
	up, err := net.Dial("unix", to)
	if err != nil {
		return 1
	}
	go func() { _, _ = io.Copy(up, down); _ = up.Close() }()
	_, _ = io.Copy(down, up)
	return 0
}

func TestApprovalWithNoApproverIsNo(t *testing.T) {
	setupApprovals(t)
	startAgent(t)
	out, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "echo ran")
	if code != ExitNoPerm || out != "" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	for _, want := range []string{"X needs the user's approval to go to sh", "asked for by go (pid", "no approver is running", "Passess.app"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	// A secret without approve needs no one.
	if out, errOut, code := run(t, "exec", "-s", "Y", "--", "sh", "-c", "echo ran"); code != 0 || out != "ran\n" {
		t.Fatalf("Y: exit %d, %q, %q", code, out, errOut)
	}
}

func TestApprovalIsRememberedForTheCaller(t *testing.T) {
	setupApprovals(t)
	startAgent(t)
	a := connectApprover(t, allowAll)
	for i := range 2 {
		out, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", `echo "$X"`)
		if code != 0 || out != "[REDACTED:X]\n" {
			t.Fatalf("run %d: exit %d, %q, %q", i, code, out, errOut)
		}
	}
	if a.count() != 1 {
		t.Fatalf("%d questions for one caller, want 1", a.count())
	}
	q := a.asks[0]
	if q.Program != "sh" || strings.Join(q.Secrets, ",") != "X" || q.Anchor == nil || q.Anchor.Name != "go" || q.Until.IsZero() ||
		!strings.HasPrefix(strings.Join(q.Argv, " "), "sh -c") {
		t.Fatalf("question %+v", q)
	}
	out, _, _ := run(t, "agent", "status")
	if !strings.Contains(out, "X for sh, asked by go") || !strings.Contains(out, "1 approver(s) connected") {
		t.Fatalf("status:\n%s", out)
	}

	// Another caller is asked again: the binary started by this test, and the
	// same through /usr/bin/time, which forks and so is an anchor of its own.
	for _, argv := range [][]string{
		{binary, "exec", "-s", "X", "--", "sh", "-c", "echo ran"},
		{"/usr/bin/time", binary, "exec", "-s", "X", "--", "sh", "-c", "echo ran"},
	} {
		if out, err := exec.Command(argv[0], argv[1:]...).Output(); err != nil || string(out) != "ran\n" {
			t.Fatalf("%v: %q, %v", argv, out, err)
		}
	}
	if a.count() != 3 {
		t.Fatalf("%d questions, want 3: one per caller", a.count())
	}
	if a.asks[1].Anchor.Name != "cli.test" || a.asks[2].Anchor.Name != "time" {
		t.Fatalf("anchors %q and %q", a.asks[1].Anchor.Name, a.asks[2].Anchor.Name)
	}
}

func TestApprovalDeniedAndTimedOut(t *testing.T) {
	setupApprovals(t, `approval_timeout = "300ms"`)
	startAgent(t)
	deny := connectApprover(t, func(agent.AskFor) bool { return false })
	_, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "echo ran")
	if code != ExitNoPerm || !strings.Contains(errOut, "the user denied it") {
		t.Fatalf("denied: exit %d, %q", code, errOut)
	}
	_ = deny.c.Close()
	connectApprover(t, nil) // connected, never answers
	start := time.Now()
	_, errOut, code = run(t, "exec", "-s", "X", "--", "sh", "-c", "echo ran")
	if code != ExitNoPerm || !strings.Contains(errOut, "no answer within 300ms") || time.Since(start) > 5*time.Second {
		t.Fatalf("silent approver: exit %d after %s, %q", code, time.Since(start), errOut)
	}
}

func TestApprovalEndsWithLockAndWithoutTTL(t *testing.T) {
	setupApprovals(t)
	startAgent(t)
	a := connectApprover(t, allowAll)
	exec1 := func() {
		t.Helper()
		if _, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "true"); code != 0 {
			t.Fatalf("exit %d, %q", code, errOut)
		}
	}
	exec1()
	exec1()
	if _, _, code := run(t, "agent", "lock"); code != 0 {
		t.Fatal("lock failed")
	}
	exec1()
	if a.count() != 2 {
		t.Fatalf("%d questions, want 2: lock forgets the Allow", a.count())
	}
}

func TestApprovalTTLZeroAsksEachTime(t *testing.T) {
	setupApprovals(t, `approval_ttl = "0"`)
	startAgent(t)
	a := connectApprover(t, allowAll)
	for range 2 {
		if _, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "true"); code != 0 {
			t.Fatalf("exit %d, %q", code, errOut)
		}
	}
	if a.count() != 2 || !a.asks[0].Until.IsZero() {
		t.Fatalf("%d questions (want 2), until %v", a.count(), a.asks[0].Until)
	}
}

// A harness gives up on a command after its own timeout; an Allow that
// arrives after that still counts, so the retry runs without a second question.
func TestApprovalThatArrivesLateCounts(t *testing.T) {
	setupApprovals(t, `approval_timeout = "20s"`)
	agentPID := startAgent(t)
	a := connectApprover(t, nil)
	cmd := exec.Command(binary, "exec", "-s", "X", "--", "sh", "-c", "echo ran")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var q agent.AskFor
	select {
	case q = <-a.notify:
	case <-time.After(5 * time.Second):
		t.Fatal("no question")
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	if err := a.c.Write(agent.Frame{Answer: &agent.Answer{ID: q.ID, Allow: true}}); err != nil {
		t.Fatal(err)
	}
	var out []byte
	var err error
	for range 50 { // the Allow is settled by the agent's approver loop
		if out, err = exec.Command(binary, "exec", "-s", "X", "--", "sh", "-c", "echo ran").Output(); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || string(out) != "ran\n" || a.count() != 1 {
		t.Fatalf("retry: %q, %v, %d questions (agent %d)", out, err, a.count(), agentPID)
	}
}

func TestApprovalForInProcessRun(t *testing.T) {
	setupApprovals(t)
	// No agent: no one to ask, so no.
	if _, errOut, code := run(t, "run", "svc", "--", "sh", "-c", "echo ran"); code != ExitNoPerm || !strings.Contains(errOut, "no agent is running") {
		t.Fatalf("no agent: exit %d, %q", code, errOut)
	}
	startAgent(t)
	a := connectApprover(t, allowAll)
	out, errOut, code := run(t, "run", "svc", "--", "sh", "-c", `echo "$X"`)
	if code != 0 || out != "[REDACTED:X]\n" || a.count() != 1 {
		t.Fatalf("with an approver: exit %d, %q, %q, %d questions", code, out, errOut, a.count())
	}
}

func TestApproveRefusesInsideAHarnessAndWithoutATerminal(t *testing.T) {
	setup(t)
	noHarness(t)
	if _, errOut, code := run(t, "agent", "approve"); code != ExitUsage || !strings.Contains(errOut, "on a terminal") {
		t.Fatalf("no terminal: exit %d, %q", code, errOut)
	}
	t.Setenv("CODEX_THREAD_ID", "1")
	if _, errOut, code := run(t, "agent", "approve"); code != ExitNoPerm || !strings.Contains(errOut, "inside codex") {
		t.Fatalf("under a harness: exit %d, %q", code, errOut)
	}
}

func TestApproverGate(t *testing.T) {
	p := func(name string, pid int) agent.Proc { return agent.Proc{PID: pid, Name: name} }
	if err := approverGate([]agent.Proc{p("passess", 3), p("zsh", 2), p("claude", 1)}); err == nil {
		t.Error("an approver started by Claude Code was let in")
	}
	// script forks, so it is the anchor; the harness above it still counts.
	if err := approverGate([]agent.Proc{p("python3", 4), p("script", 3), p("zsh", 2), p("claude", 1)}); err == nil ||
		!strings.Contains(err.Error(), "started by claude (pid 1)") {
		t.Errorf("an approver behind script in Claude Code: %v", err)
	}
	if err := approverGate([]agent.Proc{p("passess", 3), p("-zsh", 2), p("login", 1)}); err != nil {
		t.Errorf("a terminal's approver: %v", err)
	}
	if err := approverGate([]agent.Proc{p("PassessBar", 3)}); err != nil {
		t.Errorf("the menu bar app: %v", err)
	}
}

// The terminal approver's loop, fed through pipes instead of a terminal.
func TestApproveLoop(t *testing.T) {
	setupApprovals(t)
	startAgent(t)
	c := dialApprover(t)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() { _ = approveLoop(&Streams{Stderr: io.Discard}, c, inR, outW) }()
	prompts := make(chan string, 4)
	go func() {
		r := bufio.NewReader(outR)
		var line strings.Builder
		for {
			b, err := r.ReadByte()
			if err != nil {
				return
			}
			line.WriteByte(b)
			if strings.HasSuffix(line.String(), "[y/N] ") {
				prompts <- line.String()
				line.Reset()
			}
		}
	}()
	// Wait until the approver is registered: the loop prints once it is.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if f, err := ask(os.Getenv("PASSESS_AGENT_SOCK"), agent.Status); err == nil && f.Info.Approvers == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the approver never registered")
		}
	}
	type result struct {
		out  string
		code int
	}
	done := make(chan result, 1)
	go func() {
		out, _, code := run(t, "exec", "-s", "X", "--", "sh", "-c", `echo "$X"`)
		done <- result{out, code}
	}()
	select {
	case p := <-prompts:
		if !strings.Contains(p, "go (pid") || !strings.Contains(p, "wants X for sh") || !strings.Contains(p, "$ sh -c") {
			t.Fatalf("prompt %q", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no prompt")
	}
	if _, err := io.WriteString(inW, "y\n"); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.code != 0 || r.out != "[REDACTED:X]\n" {
		t.Fatalf("exec after y: %+v", r)
	}
}

// A request refused before the policy runs (here: an unreadable project
// file) is audited too.
func TestAgentAuditsEarlyRefusals(t *testing.T) {
	dir := setupDir(t)
	startAgent(t)
	if err := os.WriteFile(filepath.Join(dir, "passess.toml"), []byte("version = [broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "true"); code != ExitConfig {
		t.Fatalf("exit %d, want %d", code, ExitConfig)
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(os.Getenv("PASSESS_AGENT_SOCK")), "agent-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var e auditEntry
	if err := json.Unmarshal(b, &e); err != nil || e.Kind != "exec" || e.Outcome != "failed" || e.Status == nil ||
		*e.Status != ExitConfig || strings.Join(e.Secrets, ",") != "X" {
		t.Fatalf("audit %s (%v)", b, err)
	}
}

func TestAgentAuditLog(t *testing.T) {
	setupApprovals(t)
	startAgent(t)
	connectApprover(t, func(q agent.AskFor) bool { return q.Program == "sh" })
	looks := "ghp_" + strings.Repeat("a1B2c3D4e5F6", 3) // built here, so no scanner sees a literal
	if !policy.LooksLikeSecret(looks) {
		t.Fatal("the fixture does not look like a credential")
	}
	if _, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", `echo "$X"`, "arg0", looks); code != 0 {
		t.Fatalf("exit %d, %q", code, errOut)
	}
	_, _, _ = run(t, "exec", "-s", "Y", "--", "no-such-command-passess")
	b, err := os.ReadFile(filepath.Join(filepath.Dir(os.Getenv("PASSESS_AGENT_SOCK")), "agent-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), execValue) || strings.Contains(string(b), looks) {
		t.Fatalf("the audit log holds a value:\n%s", b)
	}
	var kinds []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e auditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		kinds = append(kinds, e.Kind+":"+e.Outcome)
		if e.Kind == "exec" && e.Outcome == "ran" && !strings.Contains(strings.Join(e.Argv, " "), "[REDACTED]") {
			t.Errorf("argv kept a credential-shaped word: %v", e.Argv)
		}
	}
	if got := strings.Join(kinds, " "); got != "approval:allowed exec:ran exec:failed" {
		t.Fatalf("entries %s", got)
	}
	fi, err := os.Stat(filepath.Join(filepath.Dir(os.Getenv("PASSESS_AGENT_SOCK")), "agent-audit.jsonl"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode().Perm(), err)
	}
}
