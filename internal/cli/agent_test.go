package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/afsharid/passess/internal/agent"
	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/resolve"
	"github.com/afsharid/passess/internal/secret"
)

// agentSocket points this process's clients at a socket in a directory of
// its own, short enough for sun_path, and returns its path.
func agentSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	t.Setenv("PASSESS_AGENT_SOCK", sock)
	return sock
}

// startAgent runs `passess agent serve` for the rest of the test, in the
// environment the test has set up, points clients at it and returns its pid.
func startAgent(t *testing.T) int {
	t.Helper()
	sock := agentSocket(t)
	logPath := filepath.Join(filepath.Dir(sock), "serve.log")
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logf.Close()
	cmd := exec.Command(binary, "agent", "serve")
	cmd.Env = os.Environ()
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Dir = "/" // where `agent start` puts it: nothing may depend on the agent's cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	})
	for range 250 {
		if f, err := ask(sock, agent.Status); err == nil && f.Info != nil {
			return cmd.Process.Pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	b, _ := os.ReadFile(logPath)
	t.Fatalf("the agent never answered: %s", b)
	return 0
}

// The agent is only another place for exec to run: what a caller sees must
// not change, refusals and failures included.
func TestExecIsTheSameThroughTheAgent(t *testing.T) {
	setup(t)
	cases := [][]string{
		{"exec", "-s", "X", "--", "sh", "-c", `echo "out $X"; echo "err $X" >&2; exit 3`},
		{"exec", "-s", "X", "-s", "ALIAS=X", "--", "sh", "-c", "env | grep -v '^PASSESS_AGENT_SOCK=' | sort"},
		{"exec", "-s", "Y", "--", "sh", "-c", "echo $Y"},
		{"exec", "-s", "NOPE", "--", "ls"},
		{"exec", "-s", "X", "--", "no-such-command-passess"},
		{"exec", "-s", "X", "--", "./config.toml"},
		{"exec", "-s", "X", "--", "sh", "-c", "pwd; /bin/pwd -P"},
	}
	type result struct {
		out, err string
		code     int
	}
	var want []result
	for _, c := range cases {
		out, errOut, code := run(t, c...)
		want = append(want, result{out, errOut, code})
	}
	startAgent(t)
	for i, c := range cases {
		out, errOut, code := run(t, c...)
		if got := (result{out, errOut, code}); got != want[i] {
			t.Errorf("passess %s\n in this process: %+v\n through the agent: %+v", strings.Join(c, " "), want[i], got)
		}
	}
}

// Codex runs commands under a seatbelt profile that denies connecting to Unix
// sockets. There exec must run in-process, not fail.
func TestExecInASandboxThatForbidsTheSocket(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("needs macOS sandbox-exec")
	}
	setup(t)
	startAgent(t)
	cmd := exec.Command("/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network-outbound (remote unix-socket))",
		binary, "exec", "-s", "X", "--", "sh", "-c", `echo "$X"`)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || string(out) != "[REDACTED:X]\n" || !strings.Contains(stderr.String(), "out of this sandbox's reach") {
		t.Fatalf("exec in the sandbox: %v, stdout %q, stderr %q", err, out, stderr.String())
	}
	if f, err := ask(os.Getenv("PASSESS_AGENT_SOCK"), agent.Status); err != nil || f.Info.Served != 0 {
		t.Fatalf("the agent was reached from the sandbox: %v %+v", err, f.Info)
	}
}

func TestAgentEndsTheCommandOfAClientThatDies(t *testing.T) {
	setup(t)
	agentPID := startAgent(t)
	cmd, child := startPassess(t, agentPID, "exec", "-s", "Y", "--", "sleep", "30")
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	for deadline := time.Now().Add(killGrace + 2*time.Second); alive(child); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the command outlived its client")
		}
	}
}

func TestAgentServesOnlyItsOwnConfig(t *testing.T) {
	dir := setupDir(t)
	startAgent(t)

	// Another spelling of the same file is the same config.
	link := filepath.Join(t.TempDir(), "link.toml")
	if err := os.Symlink(filepath.Join(dir, "config.toml"), link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PASSESS_CONFIG", link)
	if _, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "true"); code != 0 {
		t.Fatalf("a symlink to the agent's config: exit %d, %q", code, errOut)
	}

	other := filepath.Join(t.TempDir(), "other.toml")
	if err := os.WriteFile(other, []byte("version = 1\n[secrets.X]\nref = \"env://PASSESS_TEST_X_TOKEN\"\nallow = [\"sh\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PASSESS_CONFIG", other)
	out, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "echo ran")
	if code != ExitConfig || out != "" || !strings.Contains(errOut, "the agent serves") || !strings.Contains(errOut, other) {
		t.Fatalf("another config: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestAgentStatusLockStop(t *testing.T) {
	setup(t)
	pid := startAgent(t)
	sock := os.Getenv("PASSESS_AGENT_SOCK")

	out, errOut, code := run(t, "agent", "status")
	if code != 0 || !strings.Contains(out, "pid "+strconv.Itoa(pid)) || !strings.Contains(out, "holds nothing") {
		t.Fatalf("status: exit %d, %q, %q", code, out, errOut)
	}
	out, _, code = run(t, "agent", "status", "--json")
	var st struct {
		Running bool `json:"running"`
		PID     int  `json:"pid"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || code != 0 || !st.Running || st.PID != pid {
		t.Fatalf("status --json: exit %d, %q (%v)", code, out, err)
	}
	if out, _, code := run(t, "agent", "lock"); code != 0 || !strings.Contains(out, "forgot") {
		t.Fatalf("lock: exit %d, %q", code, out)
	}
	if out, _, code := run(t, "agent", "stop"); code != 0 || !strings.Contains(out, "stopped") {
		t.Fatalf("stop: exit %d, %q", code, out)
	}
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the socket outlived stop: %v", err)
	}
	if out, _, code := run(t, "agent", "status"); code != ExitAgentStopped || !strings.Contains(out, "not running") {
		t.Fatalf("status after stop: exit %d, %q", code, out)
	}
	if out, _, code := run(t, "agent", "stop"); code != 0 || !strings.Contains(out, "not running") {
		t.Fatalf("stop when stopped: exit %d, %q", code, out)
	}
	// Without an agent, exec runs in this process again.
	if out, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", `echo "$X"`); code != 0 || out != "[REDACTED:X]\n" {
		t.Fatalf("exec after stop: exit %d, %q, %q", code, out, errOut)
	}
}

func TestAgentStartRunsOne(t *testing.T) {
	setup(t)
	agentSocket(t)
	passess := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("passess %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	// A relative config path must survive the agent's move to /.
	t.Setenv("PASSESS_CONFIG", "config.toml")
	if out := passess("agent", "start"); !strings.Contains(out, "started, pid") {
		t.Fatalf("start: %q", out)
	}
	t.Cleanup(func() { _, _ = exec.Command(binary, "agent", "stop").CombinedOutput() })
	if out := passess("agent", "start"); !strings.Contains(out, "already running") {
		t.Fatalf("second start: %q", out)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if out := passess("exec", "-s", "X", "--", "sh", "-c", `/bin/pwd -P; echo "$X"`); out != canonical(wd)+"\n[REDACTED:X]\n" {
		t.Fatalf("exec through the started agent: %q", out)
	}
	if out, _, _ := run(t, "agent", "status"); !strings.Contains(out, "1 since it started") {
		t.Fatalf("the exec did not go through the agent: %q", out)
	}
	if out := passess("agent", "stop"); !strings.Contains(out, "stopped") {
		t.Fatalf("stop: %q", out)
	}
}

func TestAgentUsage(t *testing.T) {
	for _, args := range [][]string{{"agent"}, {"agent", "nope"}, {"agent", "stop", "now"}, {"agent", "status", "--yaml"}} {
		if _, _, code := run(t, args...); code != ExitUsage {
			t.Errorf("passess %s: exit %d, want %d", strings.Join(args, " "), code, ExitUsage)
		}
	}
}

// countingProvider stands in for a vault and counts how often it is asked.
type countingProvider struct {
	calls *atomic.Int32
}

func (countingProvider) Scheme() string                  { return ref.Keychain }
func (countingProvider) Available(context.Context) error { return nil }

func (p countingProvider) Resolve(_ context.Context, r ref.Ref) (secret.Value, error) {
	p.calls.Add(1)
	return secret.FromString("passess-fake-cached-" + r.Path[1]), nil
}

func cacheServer(calls *atomic.Int32) *agentServer {
	return newAgentServer(nil, "", func(*config.User) (*resolve.Resolver, func()) {
		r := resolve.New(countingProvider{calls})
		return r, r.Zero
	})
}

func cacheConfig(t *testing.T, ttl string) (*config.User, [sha256.Size]byte) {
	t.Helper()
	body := "version = 1\n[secrets.K]\nref = \"keychain://svc/k-account\"\n[secrets.E]\nref = \"env://PASSESS_TEST_E\"\n[agent]\ncache_ttl = \"" + ttl + "\"\n"
	u, err := config.ParseUser("/test/config.toml", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return u, sha256.Sum256([]byte(body))
}

// resolveVia resolves one secret the way an exec request does.
func resolveVia(t *testing.T, s *agentServer, u *config.User, sum [sha256.Size]byte, env agent.Environ, name string) (string, error) {
	t.Helper()
	g, code := s.acquire(&Streams{Stderr: io.Discard}, u, sum)
	if code != 0 {
		t.Fatalf("acquire: exit %d", code)
	}
	defer s.release(g)
	res := requestResolver(g, env)
	defer res.Zero()
	v, err := res.Secret(context.Background(), u.Secrets[name])
	if err != nil {
		return "", err
	}
	return string(v.Bytes()), nil
}

func TestAgentCacheLifetime(t *testing.T) {
	var calls atomic.Int32
	s := cacheServer(&calls)
	u, sum := cacheConfig(t, "1h")
	want := "passess-fake-cached-k-account"
	expect := func(what string, n int32) {
		t.Helper()
		v, err := resolveVia(t, s, u, sum, nil, "K")
		if err != nil || v != want {
			t.Fatalf("%s: %q, %v", what, v, err)
		}
		if got := calls.Load(); got != n {
			t.Fatalf("%s: the vault was asked %d times, want %d", what, got, n)
		}
	}
	expect("first command", 1)
	// The first command zeroed its copy; the cache kept its own.
	expect("second command", 1)
	if names, _, _ := s.cacheState(); strings.Join(names, ",") != "K" {
		t.Fatalf("cached names %v", names)
	}

	s.forget()
	if names, _, _ := s.cacheState(); len(names) != 0 {
		t.Fatalf("lock left %v", names)
	}
	expect("after lock", 2)

	u, sum = cacheConfig(t, "2h") // the config changed
	expect("after a config change", 3)
	if len(s.live) != 1 {
		t.Fatalf("%d generations alive, want 1", len(s.live))
	}

	u, sum = cacheConfig(t, "0")
	expect("cache off", 4)
	expect("cache off again", 5)
	if len(s.live) != 0 || s.gen != nil {
		t.Fatal("a cache-off command left a generation behind")
	}

	u, sum = cacheConfig(t, "50ms")
	expect("short lifetime", 6)
	time.Sleep(300 * time.Millisecond)
	if names, _, _ := s.cacheState(); len(names) != 0 {
		t.Fatalf("expiry left %v", names)
	}
	expect("after expiry", 7)
}

func TestAgentForgetsUnderACommandBeingPrepared(t *testing.T) {
	var calls atomic.Int32
	s := cacheServer(&calls)
	u, sum := cacheConfig(t, "1h")
	g, _ := s.acquire(&Streams{Stderr: io.Discard}, u, sum)
	res := requestResolver(g, nil)
	s.forget()
	if _, err := res.Secret(context.Background(), u.Secrets["K"]); !errors.Is(err, errForgotten) {
		t.Fatalf("resolving after lock: %v", err)
	}
	s.release(g)
	if len(s.live) != 0 || calls.Load() != 0 {
		t.Fatalf("%d generations alive, %d vault calls", len(s.live), calls.Load())
	}
}

func TestAgentTakesEnvFromTheRequest(t *testing.T) {
	var calls atomic.Int32
	s := cacheServer(&calls)
	u, sum := cacheConfig(t, "1h")
	for _, v := range []string{"passess-fake-first-0123456789", "passess-fake-second-0123456789"} {
		got, err := resolveVia(t, s, u, sum, agent.Environ{"PASSESS_TEST_E=" + v}, "E")
		if err != nil || got != v {
			t.Fatalf("env:// gave %q, %v; want %q", got, err, v)
		}
	}
	if _, err := resolveVia(t, s, u, sum, nil, "E"); err == nil {
		t.Fatal("env:// resolved from somewhere other than the request")
	}
	if names, _, _ := s.cacheState(); len(names) != 0 {
		t.Fatalf("env:// values were cached: %v", names)
	}
}

func TestAgentRefusesAnotherBuild(t *testing.T) {
	var files []*os.File
	var stderr *os.File
	for i := range 3 {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		if i == 0 {
			_ = w.Close()
			files = append(files, r)
			continue
		}
		files = append(files, w)
		if i == 2 {
			stderr = r
		}
	}
	s := cacheServer(new(atomic.Int32))
	code := s.exec(&agent.Conn{}, agent.Request{V: agent.Version, Build: "0.0.0-another", Kind: agent.Exec}, files)
	msg, _ := io.ReadAll(stderr)
	if code != ExitUnavailable || !strings.Contains(string(msg), "passess agent stop && passess agent start") {
		t.Fatalf("exit %d, stderr %q", code, msg)
	}
}

func TestSameBuild(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"0.5.0", "v0.5.0", true},
		{"v0.5.0-alpha", "v0.5.0-alpha", true},
		{"0.5.0", "0.5.1", false},
		{"dev", "dev-abc123", false},
	} {
		if got := sameBuild(c.a, c.b); got != c.same {
			t.Errorf("sameBuild(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestLookPathIn(t *testing.T) {
	dir := t.TempDir()
	mk := func(rel string, mode os.FileMode) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/true\n"), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tool := mk("bin/tool", 0o755)
	mk("bin/plain", 0o644)
	sneaky := mk("rel/sneaky", 0o755)
	look := lookPathIn(agent.Environ{"PATH=rel::" + filepath.Join(dir, "bin")}, dir)

	if p, err := look("tool"); err != nil || p != tool {
		t.Errorf("tool: %q, %v", p, err)
	}
	if _, err := look("plain"); err == nil {
		t.Error("a file without an execute bit was found")
	}
	if _, err := look("sneaky"); !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("a relative PATH entry was searched: %v", err)
	}
	if p, err := look("./rel/sneaky"); err != nil || p != sneaky {
		t.Errorf("./rel/sneaky: %q, %v", p, err)
	}
	if p, err := look(tool); err != nil || p != tool {
		t.Errorf("absolute: %q, %v", p, err)
	}
	if _, err := look("missing"); !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}
