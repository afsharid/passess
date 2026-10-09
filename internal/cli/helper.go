package cli

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/afsharid/passess/internal/agent"
	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/detect"
	"github.com/afsharid/passess/internal/policy"
)

func init() {
	commands["helper"] = command{"print one secret for a harness's key helper setting (apiKeyHelper), never on a terminal", runHelper}
}

// HelperFamily is the name a secret's allow list must hold before passess
// helper prints it.
const HelperFamily = policy.ReservedFamily

// runHelper prints one secret's value, for a harness that runs a command to
// get its own API key (Claude Code's apiKeyHelper). The value leaves passess
// on purpose, so each secret opts in, the hooks refuse the command in agent
// shells, and a terminal never gets it. What this protects is the key's
// place on disk, not the key from the harness's own agent (ADR 8). A desktop
// app passess knows (detect.IsApp) opts in another way: the user connects the
// secret to it by name (ADR 11).
func runHelper(st *Streams, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(st.Stderr, "Usage: passess helper NAME   (for a harness setting such as Claude Code's apiKeyHelper)")
		return ExitUsage
	}
	name := args[0]
	if isTerminal(st.Stdout) {
		return failf(st, ExitUsage, "passess helper prints a secret for a harness to read; it does not print one on a terminal. Put `passess helper %s` in the harness's key helper setting.", name)
	}
	u, _, code := loadConfig(st)
	if code != 0 {
		return code
	}
	s, ok := u.Secrets[name]
	if !ok {
		return failf(st, ExitConfig, "%s is not defined in %s", name, u.Path)
	}
	if !slices.Contains(s.Allow, HelperFamily) {
		app := askingApp(selfChain())
		if app == "" {
			return failf(st, ExitNoPerm, "%s may not go to passess helper, which prints it for whatever runs it. If a harness needs it as its own API key, add %q to secrets.%s.allow in %s.",
				name, HelperFamily, name, u.Path)
		}
		if !namesApp(s, app) {
			return failf(st, ExitNoPerm, "%s is not connected to %s by name. The user connects it in Passess.app, or runs `passess set %s --clients …` with %s in the list; a secret with no list is not one the user chose for an app.",
				name, detect.Label(app), name, app)
		}
		// The app is known by its process name, which any program can take.
		// A secret any program may receive (no allow list) loses nothing to
		// that: `passess exec` hands it to such a program anyway. One the user
		// narrowed to some programs must opt in to passess helper itself.
		if len(s.Allow) > 0 {
			return failf(st, ExitNoPerm, "%s goes only to %s, and %s is known by a process name any program can take. To let it read the key anyway, add %q to secrets.%s.allow in %s.",
				name, strings.Join(s.Allow, ", "), detect.Label(app), HelperFamily, name, u.Path)
		}
	}
	self, err := os.Executable()
	if err != nil {
		self = "passess"
	}
	if code := admit(st, u, []string{name}, []string{self, "helper", name}); code != 0 {
		return code
	}
	res, zero := newResolver(st, u)
	defer zero()
	v, err := res.Secret(context.Background(), s)
	if err != nil {
		return failf(st, resolveExitCode(err), "%v", err)
	}
	if _, err := st.Stdout.Write(append(v.Bytes(), '\n')); err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	return ExitOK
}

// askingApp returns the desktop app that started this process itself, or "".
// Only the app's own process counts: with a shell between them it is the
// app's agent running a command, not the app reading its key.
func askingApp(chain []agent.Proc) string {
	if len(chain) < 2 {
		return ""
	}
	if id := detect.Program(chain[1].Name); detect.IsApp(id) {
		return id
	}
	return ""
}

// namesApp reports whether the secret's clients list names the app. No list
// means every agent may ask, which is not the user choosing this app: unlike
// config.Secret.ConnectedTo, which counts no list as every agent, on purpose.
func namesApp(s config.Secret, app string) bool {
	return s.Clients != nil && slices.Contains(s.Clients, app)
}
