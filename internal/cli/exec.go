package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/launch"
	"github.com/afsharid/passess/internal/policy"
	"github.com/afsharid/passess/internal/redact"
	"github.com/afsharid/passess/internal/secret"
)

func init() {
	commands["exec"] = command{"run a command with secrets in its environment, output redacted", runExec}
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// secretFlags collects -s NAME, -s NAME,NAME and -s ENV=NAME.
type secretFlags []struct{ env, name string }

func (s *secretFlags) String() string { return "" }

func (s *secretFlags) Set(v string) error {
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		env, name, alias := strings.Cut(item, "=")
		if !alias {
			name = env
		}
		if !envNameRe.MatchString(env) || !envNameRe.MatchString(name) {
			return fmt.Errorf("%q is not NAME or ENV=NAME", item)
		}
		*s = append(*s, struct{ env, name string }{env, name})
	}
	return nil
}

func runExec(st *Streams, args []string) int {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	var wanted secretFlags
	fs.Var(&wanted, "s", "secret to inject: NAME, NAME,NAME or ENV=NAME (repeatable)")
	fs.Var(&wanted, "secret", "same as -s")
	fs.Usage = func() {
		fmt.Fprintln(st.Stderr, "Usage: passess exec -s NAME[,NAME] [-s ENV=NAME] -- command [args...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	argv := fs.Args()
	if len(argv) == 0 || len(wanted) == 0 {
		fs.Usage()
		return ExitUsage
	}

	if c, code := agentFor(st); code != 0 {
		return code
	} else if c != nil {
		return execThroughAgent(st, c, argv, wanted)
	}

	u, proj, code := loadConfig(st)
	if code != 0 {
		return code
	}
	res, zero := newResolver(st, u)
	defer zero()
	spec, code := prepareExec(st, u, proj, os.Environ(), argv, wanted, res, exec.LookPath)
	if code != 0 {
		return code
	}
	defer spec.Redactor.Zero()
	spec.Stdin, spec.Stdout, spec.Stderr = st.Stdin, st.Stdout, st.Stderr
	spec.ForwardInterrupt = !isTerminal(st.Stdin)
	status, err := launch.Run(spec)
	return execStatus(st, argv[0], status, err)
}

// secretSource resolves configured secrets.
type secretSource interface {
	Secret(ctx context.Context, s config.Secret) (secret.Value, error)
}

// prepareExec checks the policy for argv and every wanted secret, resolves
// them and returns the child's spec without its streams. Refusals and
// warnings go to st.Stderr; a non-zero code means nothing may run. The spec's
// environment and redactor hold copies: res may forget its values at once.
func prepareExec(st *Streams, u *config.User, proj *config.Project, environ, argv []string, wanted secretFlags,
	res secretSource, lookPath func(string) (string, error)) (launch.Spec, int) {
	prog, err := policy.Inspect(argv[0], lookPath)
	if err != nil {
		return launch.Spec{}, failf(st, ExitNotFound, "%v", err)
	}
	for _, w := range wanted {
		s, ok := u.Secrets[w.name]
		if !ok {
			return launch.Spec{}, failf(st, ExitConfig, "%s is not defined; ask the user to run `passess add %s --ref <reference>` (or add a [secrets.%s] table to %s)", w.name, w.name, w.name, u.Path)
		}
		d := policy.Check(w.name, prog, policy.Effective(s.Allow, proj.ProjectAllow(w.name)))
		if !d.Allowed {
			return launch.Spec{}, refuse(st, u, w.name, d)
		}
	}

	inject := map[string]secret.Value{}
	var named []redact.Secret
	for _, w := range wanted {
		v, err := res.Secret(context.Background(), u.Secrets[w.name])
		if err != nil {
			return launch.Spec{}, failf(st, resolveExitCode(err), "%v", err)
		}
		inject[w.env] = v
		named = append(named, redact.Secret{Name: w.name, Value: v})
	}
	rd, warnings, err := redact.New(named, redact.Options{})
	if err != nil {
		return launch.Spec{}, failf(st, ExitConfig, "%v", err)
	}
	for _, w := range warnings {
		fmt.Fprintf(st.Stderr, "passess: warning: %s\n", w)
	}
	return launch.Spec{Path: prog.Path, Argv: argv, Env: childEnv(environ, u, inject), Redactor: rd}, 0
}

// execStatus reports a child that did not start or whose output was lost,
// and passes its status on.
func execStatus(st *Streams, argv0 string, status int, err error) int {
	if err != nil && status >= launch.NotExecutable {
		return failf(st, status, "%s: %v", argv0, err)
	}
	if err != nil && !errors.Is(err, syscall.EPIPE) {
		fmt.Fprintf(st.Stderr, "passess: %v\n", err)
	}
	return status
}

// refuse explains a policy refusal and how to proceed.
func refuse(st *Streams, u *config.User, name string, d policy.Decision) int {
	fmt.Fprintf(st.Stderr, "passess: refusing to give %s to this command: %s.\n", name, d.Reason)
	fmt.Fprintf(st.Stderr, "  Run a program that reads %s from its environment instead, for example:\n", name)
	fmt.Fprintf(st.Stderr, "    passess exec -s %s -- gh api user\n", name)
	fmt.Fprintf(st.Stderr, "  For HTTP, curl can read it without a shell:\n")
	fmt.Fprintf(st.Stderr, "    passess exec -s %[1]s -- curl --variable %%%[1]s --expand-header 'Authorization: Bearer {{%[1]s}}' https://…\n", name)
	if policy.Denied(d.Family) {
		fmt.Fprintf(st.Stderr, "  To allow %s anyway, add %q to secrets.%s.allow in %s.\n", d.Family, d.Family, name, u.Path)
	} else {
		fmt.Fprintf(st.Stderr, "  To allow it, add %q to secrets.%s.allow in %s.\n", d.Family, name, u.Path)
	}
	return ExitNoPerm
}

// isTerminal reports whether a stream is a terminal (not merely a character
// device: /dev/null is one too).
func isTerminal(stream any) bool {
	f, ok := stream.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
