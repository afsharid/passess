package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/hook"
	"github.com/afsharid/passess/internal/redact"
	"github.com/afsharid/passess/internal/scan"
)

func init() {
	commands["hook"] = command{"answer a harness hook event on stdin (what harness hook configs call)", runHook}
}

// maxHookPayload bounds what a hook reads: tool results can be large, but a
// hook that waits on an endless stream would stall the agent.
const maxHookPayload = 16 << 20

// runHook fails open. A hook is a second line of defense, so a broken config,
// an unknown event or a bug must not stop the agent: anything but an explicit
// refusal exits 0 with nothing on stdout. Nothing from the payload is echoed:
// some harnesses send a file's content with the event.
func runHook(st *Streams, args []string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(st.Stderr, "passess hook: internal error; the action is allowed")
			code = 0
		}
	}()
	if len(args) != 2 {
		names := make([]string, 0, len(hook.Adapters))
		for n := range hook.Adapters {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Fprintf(st.Stderr, "Usage: passess hook HARNESS EVENT < event.json   (harnesses: %s)\n", strings.Join(names, ", "))
		return ExitOK
	}
	adapter, ok := hook.Adapters[args[0]]
	if !ok {
		fmt.Fprintf(st.Stderr, "passess hook: unknown harness %q; the action is allowed\n", args[0])
		return ExitOK
	}
	payload, err := io.ReadAll(io.LimitReader(st.Stdin, maxHookPayload))
	if err != nil {
		return ExitOK
	}
	ev, err := adapter.Parse(args[1], payload, st.Getenv)
	clear(payload)
	if err != nil {
		fmt.Fprintln(st.Stderr, "passess hook: the event could not be read; the action is allowed")
		return ExitOK
	}
	reply := adapter.Render(ev, hook.Decide(ev, hookEnv(st)))
	_, _ = st.Stdout.Write(reply.Stdout)
	_, _ = st.Stderr.Write(reply.Stderr)
	return reply.Exit
}

// hookEnv is what the policy may know: secret names from the config (never
// values), where passess keeps its config and state, and, loaded on first use,
// the rules and the credential values already in the harness's environment.
func hookEnv(st *Streams) hook.Env {
	home := st.Getenv("HOME")
	env := hook.Env{Home: home, Getenv: st.Getenv, Environ: os.Environ(), StateDir: stateDir(st.Getenv)}
	xdg := st.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	env.ConfigDirs = []string{filepath.Join(xdg, "passess")}
	if path, err := config.UserPath(st.Getenv); err == nil {
		env.ConfigDirs = append(env.ConfigDirs, filepath.Dir(path))
		if u, err := config.LoadUser(path); err == nil {
			env.Secrets = u.SortedNames()
		}
	}
	var rulesOnce, knownOnce sync.Once
	var rules *scan.Rules
	var known *redact.Redactor
	env.Rules = func() *scan.Rules {
		rulesOnce.Do(func() { rules, _ = scan.DefaultRules() })
		return rules
	}
	env.Known = func() *redact.Redactor {
		knownOnce.Do(func() { known = hook.KnownFromEnviron(env.Environ, env.Secrets) })
		return known
	}
	return env
}
