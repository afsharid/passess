// Package provider resolves secret references against password-manager
// backends. Providers reach backends through their own CLIs so that users keep
// the authentication they already have (for example 1Password's desktop
// biometric unlock).
package provider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

// Provider resolves references of one scheme.
type Provider interface {
	Scheme() string
	// Available reports whether the backend can be used now; the error says
	// how to make it usable.
	Available(ctx context.Context) error
	// Resolve returns the value the reference points to.
	Resolve(ctx context.Context, r ref.Ref) (secret.Value, error)
}

var (
	// ErrNotFound means the backend answered and the reference points to nothing.
	ErrNotFound = errors.New("not found")
	// ErrUnavailable means the backend cannot be asked: CLI missing, locked, no credentials.
	ErrUnavailable = errors.New("backend unavailable")
)

// Error ties a failure to the reference it concerns. It never carries a value.
type Error struct {
	Ref ref.Ref
	Err error
}

func (e *Error) Error() string { return e.Ref.String() + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Runner runs a backend CLI. The real one is ExecRunner; tests substitute fakes.
type Runner interface {
	Run(ctx context.Context, c Cmd) (Result, error)
}

// Cmd is one CLI invocation. Secrets such as access tokens travel in Env or
// Stdin, never in Args.
type Cmd struct {
	Name  string
	Args  []string
	Env   []string // complete environment of the child
	Stdin []byte
}

// Result is what a CLI invocation produced.
type Result struct {
	Stdout []byte
	Stderr []byte
	Exit   int
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

// Run executes c. A non-zero exit is reported in Result.Exit, not as an error;
// the error is for failures to start the command at all.
func (ExecRunner) Run(ctx context.Context, c Cmd) (Result, error) {
	path, err := exec.LookPath(c.Name)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s is not installed or not on PATH", ErrUnavailable, c.Name)
	}
	cmd := exec.CommandContext(ctx, path, c.Args...)
	cmd.Env = c.Env
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		res.Exit = exit.ExitCode()
	default:
		return res, err
	}
	return res, nil
}

// BaseEnv is the environment backend CLIs run with: enough to find their
// config and locale, nothing that could carry another secret.
func BaseEnv(getenv func(string) string) []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR"} {
		if v := getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

var tokenish = regexp.MustCompile(`[A-Za-z0-9+/=_\-.:]{20,}`)

// CLIMessage turns a CLI's stderr into something safe to show: the first
// non-empty line, with long token-like runs masked in case the CLI echoed a
// credential.
func CLIMessage(stderr []byte) string {
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = tokenish.ReplaceAllString(line, "…")
		if len(line) > 200 {
			line = line[:200] + "…"
		}
		return line
	}
	return "no error message"
}

// trimNewline removes one trailing newline that CLIs append to a value.
func trimNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

// valueFrom wraps b in a secret.Value and zeroes b.
func valueFrom(b []byte) secret.Value {
	v := secret.New(b)
	clear(b)
	return v
}

// OSGetenv is the default environment lookup.
var OSGetenv = os.Getenv
