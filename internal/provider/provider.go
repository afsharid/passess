// Package provider resolves secret references against password-manager
// backends. Providers reach backends through their own CLIs so that users keep
// the authentication they already have (for example 1Password's desktop
// biometric unlock).
package provider

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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

// ExecRunner runs commands with os/exec. Look finds the program; nil means
// LookTrusted, which never consults PATH.
type ExecRunner struct {
	Look func(name string) (string, error)
}

// Run executes c. A non-zero exit is reported in Result.Exit, not as an error;
// the error is for failures to start the command at all.
func (r ExecRunner) Run(ctx context.Context, c Cmd) (Result, error) {
	look := r.Look
	if look == nil {
		look = LookTrusted
	}
	path, err := look(c.Name)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s is not installed in a standard location", ErrUnavailable, c.Name)
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

// trustedDirs are the only places a backend CLI is taken from. The caller's
// PATH is not one of them: passess runs in its caller's environment, so a
// directory an agent put first on PATH would be handed a vault's master
// token. These are install locations; planting a binary in one of them is an
// attack on the installation itself, not a choice made per command. The home
// directory comes from the account database, not from $HOME, which the caller
// sets too.
func trustedDirs() []string {
	dirs := []string{"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
		"/home/linuxbrew/.linuxbrew/bin", "/snap/bin"}
	if home := accountHome(); home != "" {
		for _, d := range []string{".local/bin", ".cargo/bin", "go/bin", ".npm-global/bin"} {
			dirs = append(dirs, filepath.Join(home, d))
		}
	}
	return dirs
}

// accountHome is the home directory in the account database, "" when the
// lookup fails. On macOS os/user asks the system (getpwuid_r) even without
// cgo. Elsewhere, without cgo, user.Current and user.LookupId fall back to
// $HOME and $USER when the uid has no /etc/passwd entry (LDAP and SSSD
// accounts, containers run as an arbitrary uid), and those are the caller's
// to set; so /etc/passwd is read here and nothing else. A variable so that
// tests can point it at a directory of their own.
var accountHome = func() string {
	if runtime.GOOS == "darwin" {
		if u, err := user.Current(); err == nil {
			return u.HomeDir
		}
		return ""
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer f.Close()
	return passwdHome(f, strconv.Itoa(os.Getuid()))
}

// passwdHome is the home directory of uid in an /etc/passwd-style file, ""
// when no line names it.
func passwdHome(r io.Reader, uid string) string {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) >= 7 && f[2] == uid && filepath.IsAbs(f[5]) {
			return f[5]
		}
	}
	return ""
}

// LookTrusted finds a backend CLI by name in trustedDirs only.
func LookTrusted(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, filepath.Separator) {
		return "", fmt.Errorf("%q is not a program name", name)
	}
	for _, d := range trustedDirs() {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}

// TrustedPath is the PATH a backend CLI runs with, so that what it starts in
// turn (node for bw, say) comes from the same places.
func TrustedPath() string {
	return strings.Join(trustedDirs(), string(filepath.ListSeparator))
}

// BaseEnv is the environment backend CLIs run with: enough to find their
// config and locale, nothing that could carry another secret. PATH is
// TrustedPath, never the caller's, and HOME is the account's or absent: it
// decides where the CLI reads its own config, a server URL among it.
func BaseEnv(getenv func(string) string) []string {
	env := []string{"PATH=" + TrustedPath()}
	// Without an account home there is no HOME the caller did not choose, so
	// the CLI gets none rather than one that points it at another config.
	if home := accountHome(); home != "" {
		env = append(env, "HOME="+home)
	}
	for _, k := range []string{"USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "XDG_RUNTIME_DIR"} {
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

// lookPath finds a backend CLI; tests replace it.
var lookPath = exec.LookPath
