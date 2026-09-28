package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/detect"
	"github.com/afsharid/passess/internal/launch"
	"github.com/afsharid/passess/internal/policy"
	"github.com/afsharid/passess/internal/redact"
	"github.com/afsharid/passess/internal/secret"
)

func init() {
	commands["run"] = command{"run a service with a profile's secrets in a clean environment", runRun}
}

// safeEnv is what a profile's child inherits from the caller unless the
// profile asks for more.
var safeEnv = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "TERM", "TMPDIR", "TZ", "SSH_AUTH_SOCK",
	"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
}

func runRun(st *Streams, args []string) int {
	if len(args) >= 2 && args[1] == "--" {
		args = append(args[:1:1], args[2:]...)
	}
	if len(args) < 2 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(st.Stderr, "Usage: passess run <profile> -- command [args...]")
		return ExitUsage
	}
	name, argv := args[0], args[1:]

	u, proj, code := loadConfig(st)
	if code != 0 {
		return code
	}
	prof, ok := u.Profiles[name]
	if !ok {
		return failf(st, ExitConfig, "no profile %q in %s", name, u.Path)
	}
	prog, err := policy.Inspect(argv[0], exec.LookPath)
	if err != nil {
		return failf(st, ExitNotFound, "%v", err)
	}
	if d := policy.Check("profile "+name, prog, prof.Allow); !d.Allowed {
		return failf(st, ExitNoPerm, "refusing to run this command with profile %s: %s. Add it to profiles.%s.allow in %s if it belongs there.",
			name, d.Reason, name, u.Path)
	}
	for _, s := range prof.Secrets {
		allow := policy.Effective(policy.Effective(u.Secrets[s].Allow, prof.Allow), proj.ProjectAllow(s))
		if d := policy.Check(s, prog, allow); !d.Allowed {
			return refuse(st, u, s, d)
		}
	}
	if code := askApproval(st, u, prof.Secrets, argv); code != 0 {
		return code
	}

	res, zero := newResolver(st, u)
	defer zero()
	inject := map[string]secret.Value{}
	var named []redact.Secret
	for _, s := range prof.Secrets {
		v, err := res.Secret(context.Background(), u.Secrets[s])
		if err != nil {
			if contains(prof.Required, s) {
				return failf(st, resolveExitCode(err), "%v", err)
			}
			continue // optional: the service runs without it
		}
		inject[s] = v
		named = append(named, redact.Secret{Name: s, Value: v})
	}
	env := profileEnv(st.Getenv, prof, inject)

	// A human at a terminal gets the program itself: TUIs keep working. Anything
	// else — an agent, a log file, launchd — gets redacted output.
	if isTerminal(st.Stdout) && detect.Harness(st.Getenv) == "" {
		argv0 := argv[0]
		if err := prog.Unchanged(); err != nil {
			return failf(st, ExitNotExec, "%v", err)
		}
		err := syscall.Exec(prog.Path, append([]string{argv0}, argv[1:]...), env)
		return failf(st, ExitNotExec, "%s: %v", argv0, err)
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
		Path: prog.Path, Argv: argv, Env: env,
		Stdin: st.Stdin, Stdout: st.Stdout, Stderr: st.Stderr,
		Redactor: rd, ForwardInterrupt: !isTerminal(st.Stdin), Verify: prog.Unchanged,
	})
	if err != nil && status >= launch.NotExecutable {
		return failf(st, status, "%s: %v", argv[0], err)
	}
	if err != nil && !errors.Is(err, syscall.EPIPE) {
		fmt.Fprintf(st.Stderr, "passess: %v\n", err)
	}
	return status
}

// profileEnv builds a profile's environment from nothing: the safe caller
// variables, the ones the profile inherits, its plain values, its secrets.
func profileEnv(getenv func(string) string, p config.Profile, inject map[string]secret.Value) []string {
	vars := map[string]string{}
	pass := func(k string) {
		if v := getenv(k); v != "" {
			vars[k] = v
		}
	}
	for _, k := range safeEnv {
		pass(k)
	}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "LC_") {
			pass(k)
		}
	}
	for _, k := range p.Inherit {
		pass(k)
	}
	home := vars["HOME"]
	for k, v := range p.Env {
		if home != "" && strings.HasPrefix(v, "~/") {
			v = home + v[1:]
		}
		vars[k] = v
	}
	if vars["PATH"] == "" {
		vars["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	}
	env := make([]string, 0, len(vars)+len(inject))
	for k, v := range vars {
		if _, isSecret := inject[k]; !isSecret {
			env = append(env, k+"="+v)
		}
	}
	sort.Strings(env)
	names := make([]string, 0, len(inject))
	for k := range inject {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		env = append(env, k+"="+string(inject[k].Bytes()))
	}
	return env
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
