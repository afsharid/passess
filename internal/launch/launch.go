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

// Run starts the child, forwards termination signals to it, waits for it and
// its output, and returns its status the way a shell reports it: the exit
// code, or 128 plus the signal that killed it.
func Run(s Spec) (int, error) {
	cmd := exec.Command(s.Path, s.Argv[1:]...)
	cmd.Args[0] = s.Argv[0]
	cmd.Env = s.Env
	cmd.Stdin = s.Stdin

	stdout := s.Redactor.NewWriter(s.Stdout)
	stderr := s.Redactor.NewWriter(s.Stderr)
	cmd.Stdout, cmd.Stderr = stdout, stderr

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		if errors.Is(err, os.ErrPermission) {
			return NotExecutable, err
		}
		return NotFound, err
	}

	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigs:
				if !s.ForwardInterrupt && (sig == syscall.SIGINT || sig == syscall.SIGQUIT) {
					continue
				}
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()

	err := cmd.Wait()
	close(done)
	outErr, errErr := stdout.Close(), stderr.Close()

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
