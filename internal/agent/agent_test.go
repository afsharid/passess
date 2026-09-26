package agent

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shortDir returns a directory whose socket paths fit in sun_path;
// t.TempDir() names grow with the test's name.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func listen(t *testing.T) *Listener {
	t.Helper()
	l, err := Listen(filepath.Join(shortDir(t), "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestRequestAndFilesCrossTheSocket(t *testing.T) {
	l := listen(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	type got struct {
		req   Request
		files []*os.File
		peer  Peer
		err   error
	}
	done := make(chan got, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- got{err: err}
			return
		}
		req, files, err := c.Receive(5 * time.Second)
		done <- got{req, files, c.Peer, err}
		_ = c.Write(Frame{Status: new(7)})
	}()

	c, err := Dial(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	env := Environ{"PATH=/bin", "LONG=" + strings.Repeat("x", 200<<10)} // wider than any socket buffer
	req := Request{V: Version, Kind: Exec, Argv: []string{"gh", "api"}, Dir: "/tmp", Env: env,
		Secrets: []Secret{{Env: "GH_TOKEN", Name: "GITHUB_TOKEN"}}}
	if err := c.Send(req, []*os.File{os.Stdin, w, w}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	g := <-done
	if g.err != nil {
		t.Fatal(g.err)
	}
	if g.peer.UID != os.Getuid() || g.peer.PID != os.Getpid() {
		t.Errorf("peer = %+v, want uid %d pid %d", g.peer, os.Getuid(), os.Getpid())
	}
	if len(g.req.Env) != 2 || g.req.Argv[1] != "api" || g.req.Secrets[0].Name != "GITHUB_TOKEN" {
		t.Errorf("request arrived as %+v", g.req)
	}
	if len(g.files) != 3 {
		t.Fatalf("%d files arrived, want 3", len(g.files))
	}
	if _, err := io.WriteString(g.files[1], "through the passed descriptor"); err != nil {
		t.Fatal(err)
	}
	for _, f := range g.files {
		_ = f.Close()
	}
	out, err := io.ReadAll(r)
	if err != nil || string(out) != "through the passed descriptor" {
		t.Fatalf("read %q, %v", out, err)
	}
	f, err := c.ReadFrame()
	if err != nil || f.Status == nil || *f.Status != 7 {
		t.Fatalf("frame %+v, %v", f, err)
	}
}

func TestEnvironNeverFormats(t *testing.T) {
	req := Request{Env: Environ{"GITHUB_TOKEN=passess-fake-environ-0123456789"}}
	for _, s := range []string{fmt.Sprint(req), fmt.Sprintf("%+v", req), fmt.Sprintf("%#v", req), fmt.Sprintf("%s %q %x", req.Env, req.Env, req.Env)} {
		if strings.Contains(s, "passess-fake") {
			t.Fatalf("formatted a value: %s", s)
		}
	}
	if v, ok := req.Env.Lookup("GITHUB_TOKEN"); !ok || v != "passess-fake-environ-0123456789" {
		t.Fatal("Lookup lost the value")
	}
	if _, ok := (Environ{"GITHUB_TOKENX=1", "GITHUB_TOKEN"}).Lookup("GITHUB_TOKEN"); ok {
		t.Fatal("Lookup matched a longer name or a bare word")
	}
}

func TestOneAgentPerSocket(t *testing.T) {
	l := listen(t)
	if _, err := Listen(l.Path()); !errors.Is(err, ErrRunning) {
		t.Fatalf("second Listen: %v, want ErrRunning", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(l.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Close left the socket: %v", err)
	}
	if _, err := Dial(l.Path()); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Dial after Close: %v, want ErrNotRunning", err)
	}
	again, err := Listen(l.Path())
	if err != nil {
		t.Fatalf("Listen after Close: %v", err)
	}
	_ = again.Close()
}

func TestStaleSocketIsReplacedAndOtherFilesAreNot(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "agent.sock")
	// A socket nobody listens on, as a killed agent leaves it.
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ul.SetUnlinkOnClose(false)
	_ = ul.Close()
	if _, err := Dial(path); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Dial to a stale socket: %v, want ErrNotRunning", err)
	}
	l, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	_ = l.Close()

	regular := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(regular, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(regular); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("Listen on a regular file: %v", err)
	}
	if b, _ := os.ReadFile(regular); string(b) != "keep me" {
		t.Fatal("Listen touched a regular file")
	}
}

func TestSocketIsPrivate(t *testing.T) {
	l := listen(t)
	fi, err := os.Stat(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestReceiveRejectsMiscountedDescriptors(t *testing.T) {
	l := listen(t)
	errs := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			errs <- err
			return
		}
		_, _, err = c.Receive(5 * time.Second)
		errs <- err
	}()
	c, err := Dial(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Announce three descriptors, send none.
	if _, err := c.c.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	if err := c.Write(Request{V: Version, Kind: Status}); err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err == nil || !strings.Contains(err.Error(), "announced 3") {
		t.Fatalf("Receive: %v", err)
	}
}

func TestReceiveTimesOut(t *testing.T) {
	l := listen(t)
	errs := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			errs <- err
			return
		}
		_, _, err = c.Receive(50 * time.Millisecond)
		errs <- err
	}()
	c, err := Dial(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := <-errs; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a silent client: %v, want a deadline error", err)
	}
}

func TestSocketPath(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	for _, c := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"PASSESS_AGENT_SOCK": "/s/a.sock", "HOME": "/h"}, "/s/a.sock"},
		{map[string]string{"XDG_RUNTIME_DIR": "/run/user/1", "HOME": "/h"}, "/run/user/1/passess/agent.sock"},
		{map[string]string{"HOME": "/h", "XDG_STATE_HOME": "/elsewhere"}, "/h/.local/state/passess/agent.sock"},
	} {
		got, err := SocketPath(env(c.env))
		if err != nil || got != c.want {
			t.Errorf("SocketPath(%v) = %q, %v; want %q", c.env, got, err, c.want)
		}
	}
	if _, err := SocketPath(env(map[string]string{"PASSESS_AGENT_SOCK": "/" + strings.Repeat("d", 120)})); err == nil {
		t.Error("an overlong path was accepted")
	}
	if _, err := SocketPath(env(nil)); err == nil {
		t.Error("no HOME was accepted")
	}
}
