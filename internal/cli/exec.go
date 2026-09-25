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

	u, proj, code := loadConfig(st)
	if code != 0 {
		return code
	}
	prog, err := policy.Inspect(argv[0], exec.LookPath)
	if err != nil {
		return failf(st, ExitNotFound, "%v", err)
	}
	for _, w := range wanted {
		s, ok := u.Secrets[w.name]
		if !ok {
			return failf(st, ExitConfig, "%s is not defined; add a [secrets.%s] table with ref = \"<reference>\" to %s", w.name, w.name, u.Path)
		}
		d := policy.Check(w.name, prog, policy.Effective(s.Allow, proj.ProjectAllow(w.name)))
		if !d.Allowed {
			return refuse(st, u, w.name, d)
		}
	}

	res, zero := newResolver(st, u)
	defer zero()
	inject := map[string]secret.Value{}
	var named []redact.Secret
	for _, w := range wanted {
		v, err := res.Secret(context.Background(), u.Secrets[w.name])
		if err != nil {
			return failf(st, resolveExitCode(err), "%v", err)
		}
		inject[w.env] = v
		named = append(named, redact.Secret{Name: w.name, Value: v})
	}
	rd, warnings, err := redact.New(named, redact.Options{})
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	defer rd.Zero()
	for _, w := range warnings {
		fmt.Fprintf(st.Stderr, "passess: warning: %s\n", w)
	}

	status, err := launch.Run(launch.Spec{
		Path:             prog.Path,
		Argv:             argv,
		Env:              childEnv(os.Environ(), u, inject),
		Stdin:            st.Stdin,
		Stdout:           st.Stdout,
		Stderr:           st.Stderr,
		Redactor:         rd,
		ForwardInterrupt: !isTerminal(st.Stdin),
	})
	if err != nil && status >= launch.NotExecutable {
		return failf(st, status, "%s: %v", argv[0], err)
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
