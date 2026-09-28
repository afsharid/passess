package cli

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/afsharid/passess/internal/agent"
)

// Connections past the agent's limit are turned away at once rather than
// held until the agent runs out of file descriptors, and the agent keeps
// answering once they are gone.
func TestAgentTurnsAwayConnectionsPastItsLimit(t *testing.T) {
	setup(t)
	sock := agentSocket(t)
	logf, err := os.Create(filepath.Join(filepath.Dir(sock), "serve.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logf.Close()
	// 64 descriptors: at most 16 connections, 4 of them long-lived.
	cmd := exec.Command("/bin/sh", "-c", `ulimit -n 64 && exec "$0" agent serve`, binary)
	cmd.Env = os.Environ()
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	})
	for i := 0; ; i++ {
		if f, err := ask(sock, agent.Status); err == nil && f.Info != nil {
			break
		}
		if i == 250 {
			t.Fatal("the agent never answered")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Hold 60 connections that never send a request.
	var held []net.Conn
	for range 60 {
		c, err := net.Dial("unix", sock)
		if err != nil {
			continue // the kernel's backlog may refuse some outright; that is fine too
		}
		held = append(held, c)
	}
	turnedAway := 0
	for _, c := range held {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err != nil && !isTimeout(err) {
			turnedAway++ // closed by the agent, not merely left waiting
		}
	}
	if turnedAway < 30 {
		t.Fatalf("only %d of %d connections past the limit were turned away at once", turnedAway, len(held))
	}
	for _, c := range held {
		_ = c.Close()
	}
	if f, err := ask(sock, agent.Status); err != nil || f.Info == nil {
		t.Fatalf("status after the flood: %v", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
