package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/afsharid/passess/internal/agent"
	"github.com/afsharid/passess/internal/buildinfo"
	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/launch"
	"github.com/afsharid/passess/internal/provider"
	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/resolve"
	"github.com/afsharid/passess/internal/secret"
)

func init() {
	commands["agent"] = command{"keep resolved values in memory and run exec for agents: start, stop, status, lock", runAgent}
}

// ExitAgentStopped is what `passess agent status` returns when no agent runs
// (LSB's "program is not running").
const ExitAgentStopped = 3

// killGrace is how long a command whose client went away gets between SIGTERM
// and SIGKILL.
const killGrace = 5 * time.Second

func runAgent(st *Streams, args []string) int {
	usage := func() int {
		fmt.Fprintln(st.Stderr, "Usage: passess agent start | stop | status [--json] | lock | serve")
		return ExitUsage
	}
	if len(args) == 0 {
		return usage()
	}
	switch sub, rest := args[0], args[1:]; {
	case sub == "status" && (len(rest) == 0 || len(rest) == 1 && rest[0] == "--json"):
		return agentStatus(st, len(rest) == 1)
	case len(rest) != 0:
		return usage()
	case sub == "start":
		return agentStart(st)
	case sub == "serve":
		return agentServe(st)
	case sub == "stop", sub == "lock":
		return agentControl(st, agent.Kind(sub))
	default:
		return usage()
	}
}

// ask sends a control request to the agent at path and returns its reply.
func ask(path string, kind agent.Kind) (agent.Frame, error) {
	c, err := agent.Dial(path)
	if err != nil {
		return agent.Frame{}, err
	}
	defer c.Close()
	if err := c.Send(agent.Request{V: agent.Version, Build: buildinfo.String(), Kind: kind}, nil); err != nil {
		return agent.Frame{}, err
	}
	f, err := c.ReadFrame()
	if err == nil && f.Error != "" {
		err = errors.New(f.Error)
	}
	return f, err
}

func agentStatus(st *Streams, asJSON bool) int {
	path, err := agent.SocketPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	f, err := ask(path, agent.Status)
	running := err == nil && f.Info != nil
	if err != nil && !errors.Is(err, agent.ErrNotRunning) {
		return failf(st, ExitUnavailable, "cannot reach the agent at %s: %v", path, err)
	}
	if asJSON {
		out := struct {
			Running bool `json:"running"`
			*agent.Info
		}{running, f.Info}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Fprintln(st.Stdout, string(b))
	} else if running {
		printInfo(st.Stdout, f.Info)
	} else {
		fmt.Fprintf(st.Stdout, "passess agent: not running (socket %s)\n", path)
	}
	if !running {
		return ExitAgentStopped
	}
	return ExitOK
}

func printInfo(w io.Writer, in *agent.Info) {
	state := "running"
	if in.Stopping {
		state = "stopping"
	}
	fmt.Fprintf(w, "passess agent: %s, pid %d, passess %s, up %s\n", state, in.PID, in.Build, time.Since(in.Started).Round(time.Second))
	fmt.Fprintf(w, "  socket   %s\n", in.Socket)
	fmt.Fprintf(w, "  config   %s\n", in.Config)
	switch {
	case in.CacheTTL == "0s":
		fmt.Fprintln(w, "  cache    off: every command asks the vault")
	case len(in.Cached) == 0:
		fmt.Fprintf(w, "  cache    %s, holds nothing\n", in.CacheTTL)
	default:
		fmt.Fprintf(w, "  cache    %s, holds %s until %s\n", in.CacheTTL, strings.Join(in.Cached, ", "), in.Expires.Local().Format("15:04:05"))
	}
	if in.Busy {
		fmt.Fprintln(w, "           (a vault is being asked right now)")
	}
	fmt.Fprintf(w, "  running  %d command(s); %d since it started\n", in.Jobs, in.Served)
}

func agentControl(st *Streams, kind agent.Kind) int {
	path, err := agent.SocketPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	_, err = ask(path, kind)
	switch {
	case errors.Is(err, agent.ErrNotRunning):
		fmt.Fprintln(st.Stdout, "passess agent: not running")
		return ExitOK
	case err != nil:
		return failf(st, ExitUnavailable, "agent %s: %v", kind, err)
	case kind == agent.Stop:
		fmt.Fprintln(st.Stdout, "passess agent: stopped; commands it was running finish first")
	default:
		fmt.Fprintln(st.Stdout, "passess agent: forgot every cached value")
	}
	return ExitOK
}

// agentStart starts `passess agent serve` in a session of its own and waits
// until it answers.
func agentStart(st *Streams) int {
	path, err := agent.SocketPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	if f, err := ask(path, agent.Status); err == nil && f.Info != nil {
		fmt.Fprintf(st.Stdout, "passess agent: already running, pid %d\n", f.Info.PID)
		return ExitOK
	}
	self, err := os.Executable()
	if err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	logPath := filepath.Join(filepath.Dir(path), "agent.log")
	logf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	defer logf.Close()
	cfg, err := config.UserPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	cmd := exec.Command(self, "agent", "serve")
	cmd.Stdout, cmd.Stderr = logf, logf
	// The agent runs from / so it pins no directory; relative paths in its
	// environment would then point elsewhere, so it gets them absolute.
	cmd.Dir = "/"
	cmd.Env = append(os.Environ(), "PASSESS_CONFIG="+absolute(cfg), "PASSESS_AGENT_SOCK="+absolute(path))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if f, err := ask(path, agent.Status); err == nil && f.Info != nil {
			fmt.Fprintf(st.Stdout, "passess agent: started, pid %d; cached values last %s\n", f.Info.PID, f.Info.CacheTTL)
			return ExitOK
		}
		select {
		case err := <-exited:
			return failf(st, ExitSoftware, "the agent exited at once (%v); %s says why", err, logPath)
		case <-time.After(50 * time.Millisecond):
		}
	}
	return failf(st, ExitSoftware, "the agent did not answer within 5 s; see %s", logPath)
}

func agentServe(st *Streams) int {
	path, err := agent.SocketPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	cfg, err := config.UserPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	if err := agent.Harden(); err != nil {
		fmt.Fprintf(st.Stderr, "passess agent: warning: %v\n", err)
	}
	l, err := agent.Listen(path)
	if err != nil {
		return failf(st, ExitUnavailable, "%v", err)
	}
	s := &agentServer{l: l, configPath: canonical(cfg), started: time.Now(), live: map[*generation]bool{},
		resolvers: func(u *config.User) (*resolve.Resolver, func()) { return newResolver(st, u) }}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigs)
	go func() {
		<-sigs
		s.stop()
		<-sigs // a second one while commands drain: leave them to it
		os.Exit(128 + int(syscall.SIGINT))
	}()
	fmt.Fprintf(st.Stderr, "passess agent: pid %d serving %s on %s\n", os.Getpid(), s.configPath, path)
	s.serve()
	fmt.Fprintln(st.Stderr, "passess agent: stopped")
	return ExitOK
}

// agentServer runs exec requests for its clients. It keeps what vaults
// return for the config's cache_ttl and hands no value to anyone: the child
// gets it in its environment, the client gets the child's redacted output
// and exit status.
type agentServer struct {
	l          *agent.Listener
	configPath string // the user config it serves, canonical
	started    time.Time
	// resolvers builds a generation's providers, in the agent's own
	// environment: backend credentials come from there.
	resolvers func(*config.User) (*resolve.Resolver, func())
	handlers  sync.WaitGroup
	running   atomic.Int32 // commands running
	served    atomic.Int32 // exec requests received
	stopOnce  sync.Once

	mu       sync.Mutex
	gen      *generation          // the shared cache, nil when empty
	live     map[*generation]bool // every generation not yet forgotten
	stopping bool
}

func (s *agentServer) serve() {
	for {
		c, err := s.l.Accept()
		if err != nil {
			if s.isStopping() {
				break
			}
			time.Sleep(10 * time.Millisecond) // EMFILE and the like
			continue
		}
		s.handlers.Add(1)
		go func() {
			defer s.handlers.Done()
			s.handle(c)
		}()
	}
	s.handlers.Wait()
}

func (s *agentServer) isStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

func (s *agentServer) handle(c *agent.Conn) {
	defer c.Close()
	req, files, err := c.Receive(10 * time.Second)
	if err != nil {
		return
	}
	if req.Kind != agent.Exec {
		for _, f := range files {
			_ = f.Close()
		}
	}
	switch req.Kind {
	case agent.Exec:
		status := s.exec(c, req, files)
		_ = c.Write(agent.Frame{Status: &status})
	case agent.Status:
		_ = c.Write(agent.Frame{Info: s.info()})
	case agent.Lock:
		s.forget()
		_ = c.Write(agent.Frame{Status: new(0)})
	case agent.Stop:
		s.stop() // before the reply: once stop returns, the socket is gone
		_ = c.Write(agent.Frame{Status: new(0)})
	default:
		_ = c.Write(agent.Frame{Error: fmt.Sprintf("unknown request %q", req.Kind)})
	}
}

// stop closes the socket, forgets every value and lets serve return once
// running commands end. A new agent may start meanwhile.
func (s *agentServer) stop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopping = true
		s.mu.Unlock()
		_ = s.l.Close()
		s.forget()
	})
}

func (s *agentServer) info() *agent.Info {
	in := &agent.Info{PID: os.Getpid(), Build: buildinfo.String(), Protocol: agent.Version, Started: s.started,
		Socket: s.l.Path(), Config: s.configPath, Jobs: int(s.running.Load()), Served: int(s.served.Load())}
	if u, err := config.LoadUser(s.configPath); err == nil {
		in.CacheTTL = u.Agent.CacheTTL.String()
	}
	s.mu.Lock()
	in.Stopping = s.stopping
	s.mu.Unlock()
	in.Cached, in.Expires, in.Busy = s.cacheState()
	return in
}

// cacheState names the secrets the shared cache holds and says when it
// forgets them. busy means a vault call holds the cache: the answer does not
// wait for a Touch ID prompt.
func (s *agentServer) cacheState() (names []string, expires time.Time, busy bool) {
	names = []string{}
	s.mu.Lock()
	g := s.gen
	s.mu.Unlock()
	if g == nil {
		return names, time.Time{}, false
	}
	if !g.mu.TryLock() {
		return names, g.expires, true
	}
	defer g.mu.Unlock()
	if g.closed {
		return names, time.Time{}, false
	}
	for name, sec := range g.user.Secrets {
		for _, r := range sec.Refs {
			if g.res.Cached(r) {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	return names, g.expires, false
}

// exec runs one request's command with the client's stdin, stdout and stderr.
func (s *agentServer) exec(c *agent.Conn, req agent.Request, files []*os.File) int {
	s.served.Add(1)
	if len(files) != 3 {
		for _, f := range files {
			_ = f.Close()
		}
		return ExitUsage
	}
	stdin, stdout, stderr := files[0], files[1], files[2]
	defer stdout.Close()
	defer stderr.Close()
	closeStdin := sync.OnceFunc(func() { _ = stdin.Close() })
	defer closeStdin()
	st := &Streams{Stdin: stdin, Stdout: stdout, Stderr: stderr, Getenv: func(k string) string {
		v, _ := req.Env.Lookup(k)
		return v
	}}

	if req.V != agent.Version || req.Build != buildinfo.String() {
		return failf(st, ExitUnavailable, "the running agent is passess %s and this is passess %s; restart it: passess agent stop && passess agent start",
			buildinfo.String(), req.Build)
	}
	if len(req.Argv) == 0 || len(req.Secrets) == 0 || !filepath.IsAbs(req.Dir) {
		return failf(st, ExitUsage, "an exec request needs a command, secrets and an absolute working directory")
	}
	var wanted secretFlags
	for _, w := range req.Secrets {
		if !envNameRe.MatchString(w.Env) || !envNameRe.MatchString(w.Name) {
			return failf(st, ExitUsage, "%q=%q is not ENV=NAME", w.Env, w.Name)
		}
		wanted = append(wanted, struct{ env, name string }{w.Env, w.Name})
	}
	// req.Config is the client's spelling of its config path; messages use it,
	// as they would in the client.
	cfg := req.Config
	if !filepath.IsAbs(cfg) {
		cfg = filepath.Join(req.Dir, cfg)
	}
	if canonical(cfg) != s.configPath {
		return failf(st, ExitConfig, "the agent serves %s, but this command would read %s; set PASSESS_CONFIG and XDG_CONFIG_HOME as the agent has them, or restart the agent from here: passess agent stop && passess agent start",
			s.configPath, req.Config)
	}
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	u, err := config.ParseUser(req.Config, data)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	proj, err := loadProject(req.Dir)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}

	g, code := s.acquire(st, u, sha256.Sum256(data))
	if code != 0 {
		return code
	}
	res := requestResolver(g, req.Env)
	spec, code := prepareExec(st, u, proj, req.Env, req.Argv, wanted, res, lookPathIn(req.Env, req.Dir))
	res.Zero()
	s.release(g)
	if code != 0 {
		return code
	}
	defer spec.Redactor.Zero()
	spec.Dir, spec.Stdin, spec.Stdout, spec.Stderr = req.Dir, stdin, stdout, stderr
	spec.NewGroup = true // signals for the agent's own group are not the child's
	child, code, err := launch.Start(spec)
	closeStdin() // the child has its own copy
	if err != nil {
		return failf(st, code, "%s: %v", req.Argv[0], err)
	}
	s.running.Add(1)
	defer s.running.Add(-1)
	done := make(chan struct{})
	go relaySignals(c, child, done)
	status, err := child.Wait()
	close(done)
	return execStatus(st, req.Argv[0], status, err)
}

// relaySignals delivers the signals the client forwards. A client that goes
// away takes its command with it: SIGTERM, then SIGKILL after killGrace.
// Signals go to the child alone, never to a process group: once the child is
// reaped, os.Process refuses to signal a reused pid, a group id offers no
// such guard.
func relaySignals(c *agent.Conn, child *launch.Child, done <-chan struct{}) {
	for {
		f, err := c.ReadFrame()
		select {
		case <-done:
			return
		default:
		}
		if err != nil {
			_ = child.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(killGrace):
				_ = child.Signal(syscall.SIGKILL)
			}
			return
		}
		if f.Signal > 0 {
			_ = child.Signal(syscall.Signal(f.Signal))
		}
	}
}

// generation is one lifetime of the agent's cache: the providers, the values
// they returned, and when all of it is forgotten.
type generation struct {
	mu     sync.Mutex // serializes vault calls; guards res and closed
	res    *resolve.Resolver
	zero   func()
	closed bool

	// guarded by agentServer.mu
	user    *config.User
	sum     [sha256.Size]byte // the config it was built from
	expires time.Time         // zero for a generation of one command
	refs    int
	retired bool // no new command may use it
	timer   *time.Timer
}

// close forgets every value the generation holds.
func (g *generation) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		g.closed = true
		g.zero()
	}
}

// acquire returns the generation a command resolves through: the shared one
// if it was built from the same config, a new one otherwise, or one of its
// own when cache_ttl is 0.
func (s *agentServer) acquire(st *Streams, u *config.User, sum [sha256.Size]byte) (*generation, int) {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil, failf(st, ExitUnavailable, "the agent is stopping; run the command again")
	}
	var old *generation
	g := s.gen
	if g == nil || g.sum != sum || u.Agent.CacheTTL == 0 {
		if g != nil {
			old, g.retired, s.gen = g, true, nil
		}
		res, zero := s.resolvers(u)
		g = &generation{res: res, zero: zero, user: u, sum: sum}
		s.live[g] = true
		if ttl := u.Agent.CacheTTL; ttl > 0 {
			g.expires = time.Now().Add(ttl)
			g.timer = time.AfterFunc(ttl, func() { s.retire(g) })
			s.gen = g
		} else {
			g.retired = true
		}
	}
	g.refs++
	idle := old != nil && old.refs == 0
	s.mu.Unlock()
	if idle {
		s.drop(old)
	}
	return g, 0
}

// release ends a command's use of g.
func (s *agentServer) release(g *generation) {
	s.mu.Lock()
	g.refs--
	idle := g.refs == 0 && g.retired
	s.mu.Unlock()
	if idle {
		s.drop(g)
	}
}

// retire ends g's lifetime: no new command gets it, and it forgets its values
// as soon as the commands being prepared with it are done.
func (s *agentServer) retire(g *generation) {
	s.mu.Lock()
	if s.gen == g {
		s.gen = nil
	}
	g.retired = true
	idle := g.refs == 0
	s.mu.Unlock()
	if idle {
		s.drop(g)
	}
}

// forget closes every generation now, even one a command is being prepared
// with; that command fails and says so.
func (s *agentServer) forget() {
	s.mu.Lock()
	var all []*generation
	for g := range s.live {
		all = append(all, g)
		g.retired = true
	}
	s.gen = nil
	s.mu.Unlock()
	for _, g := range all {
		s.drop(g)
	}
}

func (s *agentServer) drop(g *generation) {
	s.mu.Lock()
	delete(s.live, g)
	if g.timer != nil {
		g.timer.Stop()
	}
	s.mu.Unlock()
	g.close()
}

// errForgotten is why a command fails when the agent forgets its values
// while the command is being prepared.
var errForgotten = errors.New("the agent forgot its values while this command was being prepared; run it again")

// requestResolver resolves one request's secrets: env:// from the client's
// environment, never cached, everything else through g.
func requestResolver(g *generation, env agent.Environ) *resolve.Resolver {
	ps := []provider.Provider{provider.Env{Lookup: env.Lookup}}
	for _, scheme := range []string{ref.Keychain, ref.BWS, ref.OnePassword, ref.Vault, ref.Bitwarden} {
		ps = append(ps, cachedScheme{g, scheme})
	}
	return resolve.New(ps...)
}

// cachedScheme hands a request one scheme's values from a generation: from
// its cache, or from the vault. The request gets a copy, so forgetting the
// cache never pulls a value out from under a command being prepared.
type cachedScheme struct {
	g      *generation
	scheme string
}

func (p cachedScheme) Scheme() string { return p.scheme }

func (p cachedScheme) Available(ctx context.Context) error {
	p.g.mu.Lock()
	defer p.g.mu.Unlock()
	if p.g.closed {
		return errForgotten
	}
	return p.g.res.Available(ctx, p.scheme)
}

func (p cachedScheme) Resolve(ctx context.Context, r ref.Ref) (secret.Value, error) {
	p.g.mu.Lock()
	defer p.g.mu.Unlock()
	if p.g.closed {
		return secret.Value{}, &provider.Error{Ref: r, Err: errForgotten}
	}
	v, err := p.g.res.Ref(ctx, r)
	if err != nil {
		return secret.Value{}, err
	}
	return secret.New(v.Bytes()), nil
}

// lookPathIn finds a program the way exec.LookPath would in the client: in
// its PATH, relative to its working directory. A bare name never resolves
// through an empty or relative PATH entry (exec.ErrDot); a name with a slash
// resolves against dir. The result is absolute.
func lookPathIn(env agent.Environ, dir string) func(string) (string, error) {
	return func(file string) (string, error) {
		if strings.Contains(file, "/") {
			p := file
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			if err := executable(p); err != nil {
				return "", &exec.Error{Name: file, Err: err}
			}
			return p, nil
		}
		path, _ := env.Lookup("PATH")
		for _, d := range filepath.SplitList(path) {
			if !filepath.IsAbs(d) {
				continue
			}
			if p := filepath.Join(d, file); executable(p) == nil {
				return p, nil
			}
		}
		return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
	}
}

func executable(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if m := fi.Mode(); m.IsDir() || m&0o111 == 0 {
		return fs.ErrPermission
	}
	return nil
}

// absolute is p made absolute against the working directory, or p itself.
func absolute(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// canonical is p absolute with symlinks resolved, as far as it exists, so
// two spellings of one config file compare equal.
func canonical(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		return filepath.Join(r, filepath.Base(p))
	}
	return filepath.Clean(p)
}

// agentFor returns a connection to the running agent when this exec goes
// through it: an agent listens, and neither stdin nor stdout is a terminal,
// which a child in the agent's session could not use as its own. With no
// agent the command runs in this process; with an agent it cannot reach, it
// does not run at all (a non-zero code).
func agentFor(st *Streams) (*agent.Conn, int) {
	if isTerminal(st.Stdin) || isTerminal(st.Stdout) {
		return nil, 0
	}
	path, err := agent.SocketPath(st.Getenv)
	if err != nil {
		return nil, 0 // no agent can listen where no socket path exists
	}
	c, err := agent.Dial(path)
	switch {
	case errors.Is(err, agent.ErrNotRunning):
		return nil, 0
	case err != nil:
		return nil, failf(st, ExitUnavailable, "an agent socket is at %s but cannot be used: %v; stop that agent or set PASSESS_AGENT_SOCK", path, err)
	}
	return c, 0
}

// execThroughAgent hands the command, this process's streams and its
// environment to the agent, forwards signals, and exits as the child did.
func execThroughAgent(st *Streams, c *agent.Conn, argv []string, wanted secretFlags) int {
	defer c.Close()
	cfg, err := config.UserPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	req := agent.Request{V: agent.Version, Build: buildinfo.String(), Kind: agent.Exec, Argv: argv, Dir: wd,
		Env: os.Environ(), Config: cfg}
	for _, w := range wanted {
		req.Secrets = append(req.Secrets, agent.Secret{Env: w.env, Name: w.name})
	}

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)

	a, err := attach(st)
	if err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	err = c.Send(req, a.files)
	a.sent()
	if err != nil {
		return failf(st, ExitUnavailable, "cannot reach the agent: %v", err)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-sigs:
				if n, ok := sig.(syscall.Signal); ok {
					_ = c.Write(agent.Frame{Signal: int(n)})
				}
			case <-done:
				return
			}
		}
	}()
	f, err := c.ReadFrame()
	a.wait()
	if err != nil || f.Status == nil {
		if err == nil {
			err = errors.New(f.Error)
		}
		return failf(st, ExitSoftware, "lost the agent before the command finished: %v", err)
	}
	return *f.Status
}

// attached are the streams an exec hands to the agent: this process's own
// files as they are, anything else (a test's buffers) through pipes.
type attached struct {
	files []*os.File
	ours  []*os.File // pipe ends whose other end the agent gets
	pumps sync.WaitGroup
}

func attach(st *Streams) (*attached, error) {
	a := &attached{}
	in, ok := st.Stdin.(*os.File)
	if !ok {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		src := st.Stdin
		if src == nil {
			src = strings.NewReader("")
		}
		go func() {
			_, _ = io.Copy(w, src)
			_ = w.Close()
		}()
		in = r
		a.ours = append(a.ours, r)
	}
	a.files = append(a.files, in)
	for _, dst := range []io.Writer{st.Stdout, st.Stderr} {
		out, ok := dst.(*os.File)
		if !ok {
			r, w, err := os.Pipe()
			if err != nil {
				a.sent()
				return nil, err
			}
			a.pumps.Add(1)
			go func() {
				defer a.pumps.Done()
				_, _ = io.Copy(dst, r)
				_ = r.Close()
			}()
			out = w
			a.ours = append(a.ours, w)
		}
		a.files = append(a.files, out)
	}
	return a, nil
}

// sent closes this process's copies of what the agent now holds, so the
// output pipes end when the agent closes its copies.
func (a *attached) sent() {
	for _, f := range a.ours {
		_ = f.Close()
	}
	a.ours = nil
}

// wait waits until everything the agent wrote has been copied out.
func (a *attached) wait() { a.pumps.Wait() }

// loadProject reads the project file for dir, if there is one.
func loadProject(dir string) (*config.Project, error) {
	pf := config.FindProject(dir)
	if pf == "" {
		return nil, nil
	}
	return config.LoadProject(pf)
}
