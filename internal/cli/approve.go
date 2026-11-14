package cli

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

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
	sum    string // the secret's Fingerprint when the user allowed it
}

// pendingAsk is a question no approver has answered yet. Callers that need
// the same Allow wait on the same question.
type pendingAsk struct {
	ask   agent.AskFor
	keys  []approvalKey // nil: the answer is for this caller only
	sums  map[approvalKey]string
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
	need = slices.Compact(need)
	family := policy.Family(prog.Name)
	remember := anchored && u.Agent.ApprovalTTL > 0
	now := time.Now()

	s.mu.Lock()
	var missing []string
	var keys []approvalKey
	sums := map[approvalKey]string{}
	for _, n := range need {
		k := approvalKey{n, family, anchor.PID, anchor.Start}
		sum := u.Secrets[n].Fingerprint()
		a, ok := s.approved[k]
		if remember && ok && now.Before(a.until) && a.sum == sum {
			continue
		}
		if ok && a.sum != sum {
			// The secret changed since the user allowed it: that Allow was
			// for something else, and is gone.
			delete(s.approved, k)
		}
		missing, keys, sums[k] = append(missing, n), append(keys, k), sum
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
	// The requester chose the argv, the directory and the program's name;
	// the question shows them with control characters made visible, so no
	// approver, terminal or app, acts on bytes the requester picked. Bounded
	// then cuts it to a size every approver can read.
	ask := agent.AskFor{Secrets: missing, Program: visible(family), Path: visible(prog.Path), Argv: visibleAll(redactArgv(req.Argv, nil)), Dir: visible(req.Dir),
		Harness: visible(detect.Harness(func(k string) string { v, _ := req.Env.Lookup(k); return v }))}.Bounded()
	if anchored {
		shown := anchor
		shown.Name = visible(shown.Name)
		ask.Anchor = &shown
	}
	if remember {
		ask.Until = now.Add(u.Agent.ApprovalTTL)
	}
	p, fresh := s.pendingFor(keys, sums, ask, u.Agent.ApprovalTTL, u.Agent.ApprovalTimeout)
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
func (s *agentServer) pendingFor(keys []approvalKey, sums map[approvalKey]string, ask agent.AskFor, ttl, timeout time.Duration) (p *pendingAsk, fresh bool) {
	if keys != nil {
		for _, p := range s.pending {
			if slices.Equal(p.keys, keys) && maps.Equal(p.sums, sums) {
				return p, false
			}
		}
	}
	s.asks++
	ask.ID = s.epoch + "-" + strconv.FormatUint(s.asks, 10)
	p = &pendingAsk{ask: ask, keys: keys, sums: sums, ttl: ttl, done: make(chan struct{})}
	p.timer = time.AfterFunc(timeout, func() { s.settle(p, false, "no answer within "+timeout.String(), "timeout") })
	s.pending[ask.ID] = p
	return p, true
}

// settle answers p once: remembers an Allow, wakes whoever waits, tells the
// approvers the question is gone, and writes the outcome to the audit log.
func (s *agentServer) settle(p *pendingAsk, allow bool, why, outcome string) {
	s.mu.Lock()
	ok := s.claim(p, allow, why)
	approvers := s.approverList()
	s.mu.Unlock()
	if ok {
		s.finish(p, allow, outcome, approvers)
	}
}

// claim takes p out of the open questions and records the answer, remembering
// an Allow. It reports false when p was settled already. The caller holds
// s.mu, so an answer and a lock cannot interleave.
func (s *agentServer) claim(p *pendingAsk, allow bool, why string) bool {
	if s.pending[p.ask.ID] != p {
		return false
	}
	delete(s.pending, p.ask.ID)
	p.timer.Stop()
	p.allow, p.why = allow, why
	if allow && p.keys != nil {
		until := time.Now().Add(p.ttl)
		for _, k := range p.keys {
			s.approved[k] = approval{anchor: *p.ask.Anchor, until: until, sum: p.sums[k]}
		}
	}
	return true
}

// finish wakes whoever waits on a claimed p, tells the approvers the question
// is gone, and writes the outcome to the audit log. It runs without s.mu.
func (s *agentServer) finish(p *pendingAsk, allow bool, outcome string, approvers []*agent.Conn) {
	close(p.done)
	if allow {
		s.prune()
	}
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

// dropApprovals forgets every Allow and refuses every open question. Both
// happen under one hold of s.mu: an approver's Allow that arrives meanwhile
// finds its question gone and is not remembered past the lock.
func (s *agentServer) dropApprovals(why string) {
	s.mu.Lock()
	open := make([]*pendingAsk, 0, len(s.pending))
	for _, p := range s.pending {
		open = append(open, p)
	}
	for _, p := range open {
		s.claim(p, false, why)
	}
	s.approved = map[approvalKey]approval{}
	approvers := s.approverList()
	s.mu.Unlock()
	for _, p := range open {
		s.finish(p, false, "cancelled", approvers)
	}
}

// revoke forgets the Allows r matches and says how many there were. Taking
// an Allow back only narrows access, so it needs no approval of its own.
func (s *agentServer) revoke(r agent.RevokeFor) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k := range s.approved {
		if k.secret == r.Secret && (r.Program == "" || k.program == r.Program) && (r.PID == 0 || k.pid == r.PID) {
			delete(s.approved, k)
			n++
		}
	}
	if n > 0 {
		s.log.write(auditEntry{Kind: "approval", Secrets: []string{r.Secret}, Program: r.Program, Outcome: "revoked"})
	}
	return n
}

// prune drops the Allows that expired or whose caller is gone. Whether a
// caller lives is a kernel call per entry, made without holding s.mu.
func (s *agentServer) prune() {
	now := time.Now()
	s.mu.Lock()
	var anchors []approvalKey
	for k, a := range s.approved {
		if now.After(a.until) {
			delete(s.approved, k)
			continue
		}
		anchors = append(anchors, k)
	}
	s.mu.Unlock()
	var gone []approvalKey
	for _, k := range anchors {
		if !(agent.Proc{PID: k.pid, Start: k.start}).Alive() {
			gone = append(gone, k)
		}
	}
	if len(gone) == 0 {
		return
	}
	s.mu.Lock()
	for _, k := range gone { // the key names the dead process, so no new Allow can share it
		delete(s.approved, k)
	}
	s.mu.Unlock()
}

// approvals lists the live Allows. With u, an Allow for a secret that has
// changed or gone since is dropped: it would not be honored.
func (s *agentServer) approvals(u *config.User) []agent.Approval {
	s.prune()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []agent.Approval{}
	for k, a := range s.approved {
		if u != nil {
			if sec, ok := u.Secrets[k.secret]; !ok || sec.Fingerprint() != a.sum {
				delete(s.approved, k)
				continue
			}
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
	if err := approverGate(peerChain(c.Peer.PID)); err != nil {
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

// peerChain is the process chain of the peer with pid, as the agent sees it. A
// peer passess cannot identify (pid 0 or 1, a process that has gone, an empty
// chain) gets agent.Unreadable, which counts as an unidentified caller: the
// kernel gave no pid, or the peer left before the walk, and either may hide a
// harness, as a detached child does.
func peerChain(pid int) []agent.Proc {
	if pid <= 1 {
		return agent.Unreadable(pid)
	}
	chain, err := agent.Ancestry(pid)
	if err != nil || len(chain) == 0 {
		return agent.Unreadable(pid)
	}
	return chain
}

// approverGate refuses an approver with a harness among its ancestors: an
// agent must not approve its own requests. The whole chain counts, not only
// the anchor, since any program the agent starts in between (script,
// timeout, an interpreter) is an anchor of its own. One that detaches from
// the harness first, a daemonized child whose parent is now launchd, gets
// through (T6). A chain cut short or empty, which may hide the harness, is refused.
func approverGate(chain []agent.Proc) error {
	if len(chain) == 0 || agent.Truncated(chain) {
		return errors.New("refusing an approver whose process chain passess cannot read to the end: an agent must not approve its own requests; the user approves in Passess.app or with `passess agent approve` in a terminal of their own")
	}
	for _, p := range chain {
		if agent.HarnessOf(p) != "" {
			return fmt.Errorf("refusing an approver started by %s (pid %d): an agent must not approve its own requests; the user approves in Passess.app or with `passess agent approve` in a terminal of their own", p.Name, p.PID)
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
	if agents := callerAgents(st.Getenv, selfChain()); len(agents) > 0 {
		return failf(st, ExitNoPerm, "refusing to approve from inside %s: an agent must not approve its own requests", agents[0])
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
	// Each line carries when it was read, so an answer typed for a question
	// that was settled elsewhere is not taken as the answer to the next one.
	type typed struct {
		text string
		at   time.Time
	}
	lines := make(chan typed)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- typed{sc.Text(), time.Now()}
		}
	}()

	var queue []agent.AskFor
	settled := map[string]bool{}
	var current *agent.AskFor
	var shown time.Time // when current was printed
	for {
		for current == nil && len(queue) > 0 {
			a := queue[0]
			queue = queue[1:]
			if !settled[a.ID] {
				current = &a
				shown = time.Now() // before printing: a reply to the prompt always counts
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
			if line.at.Before(shown) {
				fmt.Fprintln(out, "  (that answer came before this question; answer it again)")
				continue
			}
			answer := strings.TrimSpace(line.text)
			allow := strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
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
		who = fmt.Sprintf("%s (pid %d)", visible(a.Anchor.Name), a.Anchor.PID)
	}
	if a.Harness != "" {
		who += ", which says it is " + visible(a.Harness)
	}
	fmt.Fprintf(w, "\n%s wants %s for %s\n  in %s\n  $ %s\n", who, visible(strings.Join(a.Secrets, ", ")), visible(a.Program), visible(a.Dir), visible(shellLine(a.Argv)))
	if a.Until.IsZero() {
		fmt.Fprint(w, "Allow for this command? [y/N] ")
	} else {
		fmt.Fprintf(w, "Allow until %s? [y/N] ", a.Until.Local().Format("Mon 15:04"))
	}
}

// visible spells out the control, format and line-separator characters in
// text a requester chose, as \n, \x1b or \u202e, so a prompt shows them
// instead of acting on them: an escape sequence can redraw the lines above
// it, and a bidi mark can reorder the line. It never drops a character, so
// the shown text maps back to the real name. Text that holds none comes back
// unchanged.
func visible(s string) string { return spell(s, false) }

// spell is the one helper behind visible and printable. It spells out what
// hiddenAt names, as \n, \x1b, \u202e or \U000e0067, and keeps a tab when
// keepTab is set.
func spell(s string, keepTab bool) string {
	rs := []rune(s)
	var b strings.Builder
	spelled := false
	for i, r := range rs {
		if !hiddenAt(rs, i) || (keepTab && r == '\t') {
			b.WriteRune(r)
			continue
		}
		spelled = true
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	if !spelled {
		return s
	}
	return b.String()
}

func visibleAll(words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = visible(w)
	}
	return out
}

// hidden reports a rune that is hidden wherever it stands: controls (C0, DEL
// and C1), the bidi embeddings, overrides and isolates, the line and
// paragraph separators, and the format characters that show nothing (zero
// width space, word joiner, soft hyphen, BOM and the like). Ordinary text
// keeps the left and right marks, the variation selectors and, in context,
// the joiners and the flag tags that hiddenAt decides.
func hidden(r rune) bool {
	switch {
	case r == '\u200c', r == '\u200d', r == '\u200e', r == '\u200f', isTag(r):
		return false
	}
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

// hiddenAt is hidden for the rune at rs[i], where its neighbours count: a
// zero width joiner or non-joiner stays between letters, marks, digits or
// emoji, as in Persian and in an emoji family; a tag character stays in a
// flag sequence, a black flag, tags for letters and digits, then the cancel
// tag.
func hiddenAt(rs []rune, i int) bool {
	r := rs[i]
	switch {
	case r == '\u200c', r == '\u200d':
		return i == 0 || i == len(rs)-1 || !joins(rs[i-1]) || !joins(rs[i+1])
	case isTag(r):
		return !inFlag(rs, i)
	}
	return hidden(r)
}

func joins(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsDigit(r) || unicode.Is(unicode.So, r) || unicode.Is(unicode.Sk, r)
}

func isTag(r rune) bool { return r >= 0xe0020 && r <= 0xe007f }

// inFlag reports whether the tag character at rs[i] belongs to a complete
// flag sequence: U+1F3F4, tags for letters and digits, the cancel tag.
func inFlag(rs []rune, i int) bool {
	j := i
	for j > 0 && isTag(rs[j-1]) {
		j--
	}
	if j == 0 || rs[j-1] != 0x1f3f4 {
		return false
	}
	k := j
	for k < len(rs) && isTag(rs[k]) {
		r := rs[k]
		if r == 0xe007f {
			return k == len(rs)-1 || !isTag(rs[k+1])
		}
		if r < 0xe0030 || (r > 0xe0039 && r < 0xe0061) || r > 0xe007a {
			return false
		}
		k++
	}
	return false
}
