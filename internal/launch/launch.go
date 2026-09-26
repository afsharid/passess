// Package launch runs a child process whose output passes through a redactor.
package launch

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/afsharid/passess/internal/redact"
)

// Spec describes the child.
type Spec struct {
	Path     string   // resolved executable
	Argv     []string // argv[0] as the caller typed it, then the arguments
	Env      []string // complete environment
	Dir      string   // working directory; "" means the caller's
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	Redactor *redact.Redactor

	// ForwardInterrupt also forwards SIGINT and SIGQUIT. Leave it off when
	// attached to a terminal: the terminal already delivers them to the whole
	// foreground process group, child included.
	ForwardInterrupt bool
}

// Status codes for failures to start, matching the shell's.
const (
	NotExecutable = 126
	NotFound      = 127
)

// Child is a running child process.
type Child struct {
	cmd            *exec.Cmd
	stdout, stderr *redact.Writer
}

// Start starts the child with its output passing through the redactor. On
// failure it returns the shell's status for it: 126 or 127.
func Start(s Spec) (*Child, int, error) {
	cmd := exec.Command(s.Path, s.Argv[1:]...)
	cmd.Args[0] = s.Argv[0]
	cmd.Env = s.Env
	cmd.Dir = s.Dir
	cmd.Stdin = s.Stdin
	c := &Child{cmd: cmd, stdout: s.Redactor.NewWriter(s.Stdout), stderr: s.Redactor.NewWriter(s.Stderr)}
	cmd.Stdout, cmd.Stderr = c.stdout, c.stderr
	if err := cmd.Start(); err != nil {
		_ = c.stdout.Close()
		_ = c.stderr.Close()
		if errors.Is(err, os.ErrPermission) {
			return nil, NotExecutable, err
		}
		return nil, NotFound, err
	}
	return c, 0, nil
}

// Signal delivers sig to the child.
func (c *Child) Signal(sig os.Signal) error { return c.cmd.Process.Signal(sig) }

// Wait waits for the child and its output, and returns its status the way a
// shell reports it: the exit code, or 128 plus the signal that killed it.
func (c *Child) Wait() (int, error) {
	err := c.cmd.Wait()
	outErr, errErr := c.stdout.Close(), c.stderr.Close()
	status := 0
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			status = 128 + int(ws.Signal())
		} else {
			status = exit.ExitCode()
		}
	default:
		return 1, err
	}
	return status, errors.Join(outErr, errErr)
}

// Run starts the child, forwards this process's termination signals to it,
// waits for it and its output, and returns its status.
func Run(s Spec) (int, error) {
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)

	c, code, err := Start(s)
	if err != nil {
		return code, err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigs:
				if !s.ForwardInterrupt && (sig == syscall.SIGINT || sig == syscall.SIGQUIT) {
					continue
				}
				_ = c.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	status, err := c.Wait()
	close(done)
	return status, err
}
