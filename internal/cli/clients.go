package cli

import (
	"os"
	"slices"

	"github.com/afsharid/passess/internal/agent"
	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/detect"
)

// selfChain is this process and its ancestors, nearest first. Tests that act
// as a person at a terminal replace it: run from inside a coding agent, the
// real chain names that agent.
var selfChain = func() []agent.Proc {
	chain, _ := agent.Ancestry(os.Getpid())
	return chain
}

// callerAgents names the coding agents a call comes from: those its
// environment names and those whose programs are in its process chain. A
// command can clear a marker from its environment but cannot choose its
// ancestors; either one seen counts.
func callerAgents(getenv func(string) string, chain []agent.Proc) []string {
	out := detect.Harnesses(getenv)
	for _, p := range chain {
		if h := detect.Program(p.Name); h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// checkClients refuses when a secret is not connected to every coding agent
// the call comes from: an agent started inside another acts for both. A call
// no agent is seen in keeps the secret's other rules, since detection only
// ever adds protection (package detect).
func checkClients(st *Streams, u *config.User, names, agents []string) int {
	for _, n := range names {
		s, ok := u.Secrets[n]
		if !ok {
			continue // the caller reports an undefined name itself
		}
		for _, a := range agents {
			if !s.ConnectedTo(a) {
				return failf(st, ExitNoPerm, "%s is not connected to %s. The user connects it in Passess.app, or runs `passess set %s --clients …` in a terminal of their own.",
					n, detect.Label(a), n)
			}
		}
	}
	return 0
}

// admit is the in-process paths' last check before they resolve secrets:
// each must be connected to the coding agents the call comes from, and those
// marked approve need the user's Allow.
func admit(st *Streams, u *config.User, names, argv []string) int {
	if code := checkClients(st, u, names, callerAgents(st.Getenv, selfChain())); code != 0 {
		return code
	}
	return askApproval(st, u, names, argv)
}

// refuseUnderAgent keeps a command the user's when a coding agent is seen in
// the call, the same two ways checkClients sees one: what decides who may use
// which secret must not be weaker than what it decides. what says what the
// command does, for the refusal.
func refuseUnderAgent(st *Streams, command, what string) int {
	if agents := callerAgents(st.Getenv, selfChain()); len(agents) > 0 {
		return failf(st, ExitNoPerm, "passess %s %s; run it yourself in a terminal or use Passess.app, not from %s. Tell the user what you need.",
			command, what, detect.Label(agents[0]))
	}
	return 0
}
