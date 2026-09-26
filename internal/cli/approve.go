package cli

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/afsharid/passess/internal/agent"
	"github.com/afsharid/passess/internal/buildinfo"
	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/detect"
	"github.com/afsharid/passess/internal/policy"
	"github.com/afsharid/passess/internal/redact"
)

// Approvals (ADR 9). A secret with approve = true goes to a program only
// after the user allowed that secret for that program family and that
// caller. The caller is the anchor of its ancestry, a process identified by
// pid and start time. An Allow lasts agent.approval_ttl, or until lock or
// stop. With no one to ask, the answer is no.

// approvalKey is what an Allow is remembered under.
type approvalKey struct {
	secret, program string
	pid             int
	start           int64
}

type approval struct {
	anchor agent.Proc
	until  time.Time
}

// pendingAsk is a question no approver has answered yet. Callers that need
// the same Allow wait on the same question.
type pendingAsk struct {
	ask   agent.AskFor
	keys  []approvalKey // nil: the answer is for this caller only
	ttl   time.Duration
	timer *time.Timer
	done  chan struct{} // closed once settled
	allow bool
	why   string
}

// approval decides whether the secrets among names that need approval may go
// to prog for the caller anchored at anchor, asking the approvers when no
// remembered Allow covers them. It returns 0, or an exit code after
// explaining the refusal on st.Stderr. A signal from the caller, or the
// caller leaving, ends its wait; the question stays open, so an Allow that
// comes late still counts for the next try.
func (s *agentServer) approval(st *Streams, u *config.User, names []string, prog policy.Program, req agent.Request,
	anchor agent.Proc, anchored bool, frames <-chan agent.Frame) int {
	var need []string
	for _, n := range names {
		if u.Secrets[n].Approve {
			need = append(need, n)
		}
	}
	if len(need) == 0 {
		return 0
	}
	slices.Sort(need)
	family := policy.Family(prog.Name)
	remember := anchored && u.Agent.ApprovalTTL > 0
	now := time.Now()

	s.mu.Lock()
	var missing []string
	var keys []approvalKey
	for _, n := range need {
		k := approvalKey{n, family, anchor.PID, anchor.Start}
		if a, ok := s.approved[k]; remember && ok && now.Before(a.until) {
			continue
		}
		missing, keys = append(missing, n), append(keys, k)
	}
	if len(missing) == 0 {
		s.mu.Unlock()
		return 0
	}
	if len(s.approvers) == 0 {
		s.mu.Unlock()
		s.log.approval(missing, family, req.Dir, anchor, anchored, "no-approver")
		return refuseApproval(st, missing, family, anchor, anchored, "no approver is running")
	}
	if !remember {
		keys = nil
	}
	ask := agent.AskFor{Secrets: missing, Program: family, Path: prog.Path, Argv: redactArgv(req.Argv, nil), Dir: req.Dir,
		Harness: detect.Harness(func(k string) string { v, _ := req.Env.Lookup(k); return v })}
	if anchored {
		ask.Anchor = &anchor
	}
	if remember {
		ask.Until = now.Add(u.Agent.ApprovalTTL)
	}
	p, fresh := s.pendingFor(keys, ask, u.Agent.ApprovalTTL, u.Agent.ApprovalTimeout)
	var approvers []*agent.Conn
	if fresh {
		approvers = s.approverList()
	}
	s.mu.Unlock()
	for _, c := range approvers {
		_ = c.Write(agent.Frame{Ask: &p.ask})
	}

	for {
		select {
		case <-p.done:
			if p.allow {
				return 0
			}
			return refuseApproval(st, missing, family, anchor, anchored, p.why)
		case f, ok := <-frames:
			if !ok {
				if p.keys == nil {
					s.settle(p, false, "the caller went away", "cancelled")
				}
				return ExitSoftware // no one is left to read it
			}
			if f.Signal > 0 {
				if p.keys == nil {
					s.settle(p, false, "the caller was interrupted", "cancelled")
				}
				return 128 + f.Signal
			}
		}
	}
}

// pendingFor returns the open question for keys, or opens one. fresh says
// whether the approvers have yet to see it. The caller holds s.mu.
func (s *agentServer) pendingFor(keys []approvalKey, ask agent.AskFor, ttl, timeout time.Duration) (p *pendingAsk, fresh bool) {
	if keys != nil {
		for _, p := range s.pending {
			if slices.Equal(p.keys, keys) {
				return p, false
			}
		}
	}
	s.asks++
	ask.ID = strconv.FormatUint(s.asks, 10)
	p = &pendingAsk{ask: ask, keys: keys, ttl: ttl, done: make(chan struct{})}
	p.timer = time.AfterFunc(timeout, func() { s.settle(p, false, "no answer within "+timeout.String(), "timeout") })
	s.pending[ask.ID] = p
	return p, true
}

// settle answers p once: remembers an Allow, wakes whoever waits, tells the
// approvers the question is gone, and writes the outcome to the audit log.
func (s *agentServer) settle(p *pendingAsk, allow bool, why, outcome string) {
	s.mu.Lock()
	if s.pending[p.ask.ID] != p {
		s.mu.Unlock()
		return
	}
	delete(s.pending, p.ask.ID)
	p.timer.Stop()
	p.allow, p.why = allow, why
	if allow && p.keys != nil {
		until := time.Now().Add(p.ttl)
		for _, k := range p.keys {
			s.approved[k] = approval{anchor: *p.ask.Anchor, until: until}
		}
	}
	approvers := s.approverList()
	s.mu.Unlock()
	close(p.done)
	for _, c := range approvers {
		_ = c.Write(agent.Frame{Cancel: p.ask.ID})
	}
	var anchor agent.Proc
	if p.ask.Anchor != nil {
		anchor = *p.ask.Anchor
	}
	s.log.approval(p.ask.Secrets, p.ask.Program, p.ask.Dir, anchor, p.ask.Anchor != nil, outcome)
}

// approverList is every connected approver. The caller holds s.mu.
func (s *agentServer) approverList() []*agent.Conn {
	out := make([]*agent.Conn, 0, len(s.approvers))
	for c := range s.approvers {
		out = append(out, c)
	}
	return out
}

// dropApprovals forgets every Allow and refuses every open question.
func (s *agentServer) dropApprovals(why string) {
	s.mu.Lock()
	s.approved = map[approvalKey]approval{}
	open := make([]*pendingAsk, 0, len(s.pending))
	for _, p := range s.pending {
		open = append(open, p)
	}
	s.mu.Unlock()
	for _, p := range open {
		s.settle(p, false, why, "cancelled")
	}
}

// approvals lists the live Allows, dropping the ones that expired or whose
// caller is gone.
func (s *agentServer) approvals() []agent.Approval {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []agent.Approval{}
	for k, a := range s.approved {
		if now.After(a.until) || !a.anchor.Alive() {
			delete(s.approved, k)
			continue
		}
		out = append(out, agent.Approval{Secret: k.secret, Program: k.program, Anchor: a.anchor, Until: a.until})
	}
	slices.SortFunc(out, func(a, b agent.Approval) int {
		return cmp.Or(cmp.Compare(a.Secret, b.Secret), cmp.Compare(a.Program, b.Program), cmp.Compare(a.Anchor.PID, b.Anchor.PID))
	})
	return out
}

// serveApprover sends questions to an approver and settles them with its
// answers, for as long as it stays connected.
func (s *agentServer) serveApprover(c *agent.Conn) {
	chain, _ := agent.Ancestry(c.Peer.PID)
	if err := approverGate(chain); err != nil {
		_ = c.Write(agent.Frame{Error: err.Error()})
		return
	}
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		_ = c.Write(agent.Frame{Error: "the agent is stopping"})
		return
	}
	s.approvers[c] = true
	open := make([]agent.AskFor, 0, len(s.pending))
	for _, p := range s.pending {
		open = append(open, p.ask)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.approvers, c)
		s.mu.Unlock()
	}()
	if c.Write(agent.Frame{Status: new(0)}) != nil {
		return
	}
	slices.SortFunc(open, func(a, b agent.AskFor) int { // IDs are counters: oldest first
		return cmp.Or(cmp.Compare(len(a.ID), len(b.ID)), cmp.Compare(a.ID, b.ID))
	})
	for i := range open {
		_ = c.Write(agent.Frame{Ask: &open[i]})
	}
	for {
		f, err := c.ReadFrame()
		if err != nil {
			return
		}
		if f.Answer == nil {
			continue
		}
		s.mu.Lock()
		p := s.pending[f.Answer.ID]
		s.mu.Unlock()
		if p == nil {
			continue
		}
		if f.Answer.Allow {
			s.settle(p, true, "allowed", "allowed")
		} else {
			s.settle(p, false, "the user denied it", "denied")
		}
	}
}

// approverGate refuses an approver whose anchor is a harness: an agent must
// not approve its own requests. One that detaches from the harness first
// gets through (T6).
func approverGate(chain []agent.Proc) error {
	if a, ok := agent.Anchor(chain); ok {
		if h := agent.HarnessOf(a); h != "" {
			return fmt.Errorf("refusing an approver started by %s (pid %d): an agent must not approve its own requests; the user approves in Passess.app or with `passess agent approve` in a terminal of their own", a.Name, a.PID)
		}
	}
	return nil
}

// refuseApproval explains a missing Allow.
func refuseApproval(st *Streams, names []string, program string, anchor agent.Proc, anchored bool, why string) int {
	who := "a caller passess cannot identify, so the answer holds for this command only"
	if anchored {
		who = fmt.Sprintf("%s (pid %d)", anchor.Name, anchor.PID)
	}
	verb := "needs"
	if len(names) > 1 {
		verb = "need"
	}
	fmt.Fprintf(st.Stderr, "passess: %s %s the user's approval to go to %s, asked for by %s, and did not get it: %s.\n",
		strings.Join(names, ", "), verb, program, who, why)
	fmt.Fprintln(st.Stderr, "  Ask the user to approve it in Passess.app, or with `passess agent approve` in a terminal of their own, then run the command again.")
	return ExitNoPerm
}

// redactArgv replaces the words of argv that look like credentials, and with
// rd the values it knows.
func redactArgv(argv []string, rd *redact.Redactor) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		switch {
		case policy.LooksLikeSecret(a):
			out[i] = "[REDACTED]"
		case rd != nil:
			out[i] = string(rd.Redact([]byte(a)))
		default:
			out[i] = a
		}
	}
	return out
}

// askApproval is the in-process paths' way to an Allow (exec at a terminal,
// run, mcp-exec): a yes or no from the agent, with no value in either
// direction. Without an agent the answer is no.
func askApproval(st *Streams, u *config.User, names, argv []string) int {
	var need []string
	for _, n := range names {
		if u.Secrets[n].Approve {
			need = append(need, n)
		}
	}
	if len(need) == 0 {
		return 0
	}
	fail := func(why string) int {
		fmt.Fprintf(st.Stderr, "passess: %s needs the user's approval, and %s.\n", strings.Join(need, ", "), why)
		fmt.Fprintln(st.Stderr, "  Ask the user to start it (`passess agent start`) and to approve in Passess.app or with `passess agent approve`.")
		return ExitNoPerm
	}
	path, err := agent.SocketPath(st.Getenv)
	if err != nil {
		return fail("there is no agent to ask")
	}
	c, err := agent.Dial(path)
	if errors.Is(err, agent.ErrNotRunning) {
		return fail("no agent is running to ask for it")
	}
	if err != nil {
		return fail("the agent cannot be reached to ask for it (" + err.Error() + ")")
	}
	defer c.Close()
	cfg, err := config.UserPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	req := agent.Request{V: agent.Version, Build: buildinfo.String(), Kind: agent.Ask, Argv: argv, Dir: wd, Env: os.Environ(), Config: cfg}
	for _, n := range names {
		req.Secrets = append(req.Secrets, agent.Secret{Env: n, Name: n})
	}
	if err := c.Send(req, nil); err != nil {
		return fail("the agent cannot be reached to ask for it (" + err.Error() + ")")
	}
	f, err := c.ReadFrame()
	if err != nil || f.Status == nil {
		return failf(st, ExitSoftware, "lost the agent while waiting for approval: %v", err)
	}
	fmt.Fprint(st.Stderr, f.Error)
	return *f.Status
}

// clientFrames reads what a client sends until it goes away or quit closes,
// so a signal or a departure is seen at any stage of its request.
func clientFrames(c *agent.Conn, quit <-chan struct{}) <-chan agent.Frame {
	ch := make(chan agent.Frame, 8)
	go func() {
		defer close(ch)
		for {
			f, err := c.ReadFrame()
			if err != nil {
				return
			}
			select {
			case ch <- f:
			case <-quit:
				return
			}
		}
	}()
	return ch
}

// agentApprove answers the agent's questions on this terminal.
func agentApprove(st *Streams) int {
	if h := detect.Harness(st.Getenv); h != "" {
		return failf(st, ExitNoPerm, "refusing to approve from inside %s: an agent must not approve its own requests", h)
	}
	if !isTerminal(st.Stdin) || !isTerminal(st.Stdout) {
		return failf(st, ExitUsage, "passess agent approve answers on a terminal; run it in one of your own")
	}
	path, err := agent.SocketPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	c, err := agent.Dial(path)
	if err != nil {
		return failf(st, ExitUnavailable, "%v; start it with `passess agent start`", err)
	}
	defer c.Close()
	return approveLoop(st, c, st.Stdin, st.Stdout)
}

// approveLoop registers as an approver and asks the user about each question
// in turn, reading y or n from in.
func approveLoop(st *Streams, c *agent.Conn, in io.Reader, out io.Writer) int {
	if err := c.Send(agent.Request{V: agent.Version, Build: buildinfo.String(), Kind: agent.Approver}, nil); err != nil {
		return failf(st, ExitUnavailable, "%v", err)
	}
	f, err := c.ReadFrame()
	if err != nil {
		return failf(st, ExitUnavailable, "%v", err)
	}
	if f.Error != "" {
		return failf(st, ExitNoPerm, "%s", f.Error)
	}
	fmt.Fprintln(out, "passess agent approve: waiting for questions; Ctrl-C to stop")

	frames := make(chan agent.Frame)
	go func() {
		defer close(frames)
		for {
			f, err := c.ReadFrame()
			if err != nil {
				return
			}
			frames <- f
		}
	}()
	lines := make(chan string)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()

	var queue []agent.AskFor
	settled := map[string]bool{}
	var current *agent.AskFor
	for {
		for current == nil && len(queue) > 0 {
			a := queue[0]
			queue = queue[1:]
			if !settled[a.ID] {
				current = &a
				printAsk(out, a)
			}
		}
		select {
		case f, ok := <-frames:
			if !ok {
				fmt.Fprintln(out, "passess agent approve: the agent went away")
				return ExitOK
			}
			switch {
			case f.Ask != nil:
				queue = append(queue, *f.Ask)
			case f.Cancel != "":
				settled[f.Cancel] = true
				if current != nil && current.ID == f.Cancel {
					fmt.Fprintln(out, "\n  (settled elsewhere)")
					current = nil
				}
			}
		case line, ok := <-lines:
			if !ok {
				return ExitOK
			}
			if current == nil {
				continue
			}
			allow := strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
			if err := c.Write(agent.Frame{Answer: &agent.Answer{ID: current.ID, Allow: allow}}); err != nil {
				return failf(st, ExitUnavailable, "%v", err)
			}
			if allow {
				fmt.Fprintln(out, "  allowed")
			} else {
				fmt.Fprintln(out, "  denied")
			}
			settled[current.ID] = true
			current = nil
		}
	}
}

func printAsk(w io.Writer, a agent.AskFor) {
	who := "a caller passess cannot identify"
	if a.Anchor != nil {
		who = fmt.Sprintf("%s (pid %d)", a.Anchor.Name, a.Anchor.PID)
	}
	if a.Harness != "" {
		who += ", which says it is " + a.Harness
	}
	fmt.Fprintf(w, "\n%s wants %s for %s\n  in %s\n  $ %s\n", who, strings.Join(a.Secrets, ", "), a.Program, a.Dir, shellLine(a.Argv))
	if a.Until.IsZero() {
		fmt.Fprint(w, "Allow for this command? [y/N] ")
	} else {
		fmt.Fprintf(w, "Allow until %s? [y/N] ", a.Until.Local().Format("Mon 15:04"))
	}
}
