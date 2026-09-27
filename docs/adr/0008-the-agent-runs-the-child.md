# 8. The agent runs the child; no value crosses its socket

Status: accepted, 2026-09-26

## Context

`passess exec` resolves every reference through a vault CLI, measured at 0.4–0.5 s
for `bws` on the maintainer's machine, and applies the policy (allow lists, no shells
by default) to the program it is about to start. Slice 6 adds `passess agent`: a
per-user process that keeps resolved values in memory for a while and, next, asks the
user to approve secrets marked for it.

The obvious agent answers "give me GITHUB_TOKEN for gh". Any process running as the
user can ask that — a script the agent wrote, `nc -U` on the socket — and hand the
value to any program. The allow list would become a suggestion, and the cache would
be worse than no cache: a vault that prompts (1Password with Touch ID) would stop
prompting. Checking the caller's executable does not close this well: on macOS the path
needs `proc_pidpath` (cgo, which ADR 1 rules out), the PID can be reused between the
check and the reply, and the passess binary itself lives in a user-writable directory.

## Decision

The agent never returns a value. It is ssh-agent's shape turned into an exec service.

- `passess exec` with an agent listening and no terminal on stdin or stdout sends its
  argv, working directory and environment, and passes its stdin, stdout and stderr as
  descriptors (`SCM_RIGHTS`).
- The agent checks the peer's UID and applies the policy to the program *it* will run,
  found in the client's `PATH` by the rules of `exec.LookPath`. It resolves the values
  through its cache, starts the child in its own process group and redacts the child's
  output into the passed descriptors. It relays the signals the client forwards and
  sends back the exit status. A client that goes away takes its command along:
  `SIGTERM`, then `SIGKILL` after 5 s.
- `env://` references resolve from the client's environment and are never cached.
  Backend credentials (`backends.*`) resolve in the agent's own environment.
- The cache lives in generations: one per config, forgotten after `agent.cache_ttl`
  (default 10 minutes, gpg-agent's) or when the config changes, and at once on
  `passess agent lock` or `stop`. Requests get copies, so forgetting never races a
  command being prepared.
- The agent serves one config, its own. A request from a client that would read
  another, or that was built from another passess version, is refused with the fix
  (`passess agent stop && passess agent start`). It is never run in-process instead:
  a fallback would be the way around the approvals that come next.
- Without an agent, and whenever stdin or stdout is a terminal, `exec` runs in-process
  as before. A child in the agent's session cannot use the caller's terminal as its
  own: no job control, no `/dev/tty` for a password prompt.
- `run` stays in-process. Its children are services and dev servers that must outlive
  an agent restart. Approvals reach it later as a yes/no question to the agent, with
  no value in the answer. `mcp-exec` stays in-process too.
- Control requests (`status`, `lock`, `stop`) keep their shape across protocol
  versions, so any passess can stop any agent.

## Consequences

- Allow lists keep their meaning. The cache and the coming approvals cost one socket
  round trip instead of a vault call per reference: 0.45 s became 0.01 s for a cached
  `bws` secret.
- Stdout, stderr and exit codes must be the same on both paths. The exec tests run
  both ways, and one test holds the two to byte-identical results, refusals included.
- Values live longer in memory. The agent disables core dumps and refuses debuggers
  that attach later (`PT_DENY_ATTACH` on macOS, `PR_SET_DUMPABLE` on Linux). A
  same-user process that reads memory some other way remains T6.
- The agent is not a boundary against a same-user process: `passess exec` from a
  terminal, or after `passess agent stop`, resolves in-process. With approvals (next
  PR) the hooks will refuse `passess agent stop` and `PASSESS_CONFIG=` or
  `PASSESS_AGENT_SOCK=` prefixes in agent commands. Otherwise an approval is one
  environment variable away from being skipped.
- After an upgrade, a running agent refuses the new client until it is restarted. That
  is the price of never running a request under another version's policy.
- Later, once the hooks refused `passess agent stop`, `passess agent start` came to
  replace an agent of another build, so an agent command can restart it after an
  upgrade. It does so only when the new agent would serve the config the old one
  served: a start cannot bring another config in.
- The agent's log (`agent.log`, next to its socket) holds passess's own messages only.
