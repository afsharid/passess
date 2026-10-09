package cli

import (
	"context"
	"fmt"
	"os"
	"slices"

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
// place on disk, not the key from the harness's own agent (ADR 8).
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
		return failf(st, ExitNoPerm, "%s may not go to passess helper, which prints it for whatever runs it. If a harness needs it as its own API key, add %q to secrets.%s.allow in %s.",
			name, HelperFamily, name, u.Path)
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
