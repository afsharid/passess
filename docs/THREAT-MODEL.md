# Threat model

passess sits between a password manager the user already trusts and AI coding agents
the user does not fully control. This document says what it defends against, how, and
where the protection stops. Read the last section before relying on it.

## Assets

- Secret values held in the user's password manager (API keys, tokens, passwords, DSNs).
- The bootstrap credential passess itself uses to reach a backend (for example a
  Bitwarden Secrets Manager machine token kept in the OS keychain).

## Threats

| # | Threat | Goal | Mechanism |
|---|---|---|---|
| T1 | A value reaches the model's context by accident: the agent reads `.env`, dumps the environment, prints a header while debugging, a tool echoes a DSN in an error | Primary: near zero | Values never enter the agent's environment or files; `exec`, `run` and `mcp-exec` redact child output; hooks refuse known-bad commands early |
| T2 | Plaintext at rest: harness configs and their backups, dotfiles, `.env`, transcripts | Primary: find, move, eliminate | `scan`, `audit`, `migrate`; MCP configs reference `passess mcp-exec <name>` instead of holding tokens |
| T3 | The agent writes a key into code or a commit | Catch | Scanning and hooks; the agent never learns the value in the first place |
| T4 | Over-broad access: every process inherits every secret | Least privilege | Secrets are declared per consumer (command, MCP server, profile) and connected to the coding agents that may ask for them (`clients`, ADR 10) |
| T5 | Prompt-injection exfiltration: the agent *uses* a secret it cannot see and sends it elsewhere | Make harder | Per-secret command allow lists; shells, interpreters and encoders refused by default; later approvals and a host-bound egress proxy |
| T6 | A deliberately malicious agent with an unsandboxed shell running as the same OS user | Out of scope | Such a process can read anything the user can, including the keychain. A hard boundary needs the harness sandbox with passess outside it |
| T7 | A malicious repository: a cloned project's passess file asks for the user's secrets | Prevent | Project files may only name the secrets they need; references and policy widening live in user config alone |

## Limits, stated plainly

- **Redaction is best effort.** It matches the raw value and its common encodings (URL,
  JSON-escaped, base64). A value that is split, reversed, hashed or otherwise transformed
  is not caught. The real protection is that the value is never handed to the agent and
  that shells and interpreters cannot receive it by default.
- **Harness hooks are not a security boundary.** Several ingestion paths never fire a
  hook: file-change notifications (see anthropics/claude-code#94082, where a changed
  credential file reached the transcript despite a PreToolUse hook), pasted text,
  `@`-mentions, subagent results, compaction. Hooks stop the obvious mistakes early and
  suggest the right command; they are not what keeps a value out of the context.
- **Allowing `curl` means allowing every host.** A secret whose allow list contains
  `curl` can be sent through `exec` to any URL the agent chooses. `passess http` closes
  that for secrets that name their `hosts`: passess sends the request itself, only to
  those hosts, over https, and follows redirects only among them, and no child process
  holds the value. It binds the host, not what the request does there: an agent can
  still use a token for anything the API allows it. Programs other than curl (gh, a
  cloud CLI) reach their hosts through `exec` as before; a transparent proxy for them
  is future work.
- **Keychain ACLs do not stop the same user.** Any same-user process that shells out to
  `security` can read an item that `security` is trusted for. Binding the bootstrap
  credential to a signed passess binary is planned, and even then T6 stays out of scope.
- **The agent can edit passess's own config.** It runs as the same user, so it could
  add an allow list entry or an `[mcp.*]` server that hands a secret to a program of
  its choosing. The hooks refuse agent writes to `~/.config/passess`, through file
  tools and through shell redirects, `tee`, `sed -i`, `cp` and `mv`. A write the parser
  cannot see (a script it runs, an interpreter one-liner) still gets through, so this
  stays part of T5. `passess status` and `doctor` are where a changed config shows up.
- **Parallel hooks can clobber each other.** In Claude Code, hooks run on the original
  tool output and the last rewrite wins; another plugin that rewrites output can undo a
  redaction. `audit` does not check for this yet.
- **Another hook can keep what passess redacts.** Hooks run side by side on the same
  tool output. One that records it (context-mode indexes tool output, for example)
  stores the unredacted text before passess's replacement reaches the model.
- **Hooks fail open.** A broken config, an unknown event or a bug lets the action
  through. That is deliberate, because a hook that blocks everything gets removed. It
  is also why the hooks are not the boundary.
- **Backups keep what they copied.** `migrate` and `install` back up every file before
  changing it (0600, in a 0700 directory under `~/.local/state/passess/backups`). After a
  migrate, that backup is the one place passess leaves a value on disk: the original file,
  as it was. Harnesses keep their own copies too (`~/.claude/backups`). `scan` reports
  both and `migrate` prints the removal command; deleting them is the user's call,
  because a backup is also how a bad change is undone.
- **The agent holds values in memory.** `passess agent` keeps what it resolved for
  `agent.cache_ttl`. It disables core dumps and refuses debuggers that attach later,
  and zeroes values on expiry, `lock` and `stop`. It returns no value over its socket:
  it runs the command itself (ADR 8). A same-user process that reads its memory some
  other way is T6.
- **The agent is not a boundary.** A same-user process can skip it: a command at a
  terminal, or one run after `passess agent stop`, resolves in-process. The hooks refuse
  the plain ways around it in agent commands: `passess agent stop`, `serve` and
  `approve`, `PASSESS_CONFIG` or `PASSESS_AGENT_SOCK` set in a command, and programs
  other than passess naming the agent's socket. `passess agent start` replaces an agent
  of another build only with one serving the same config; an older passess can replace
  a newer agent that way, which forgets the cache and the approvals, as `agent lock`
  does. That is part of T5, not a hard line: what the hooks cannot parse (a script, an
  interpreter one-liner that builds the path) still gets through.
- **A clients list holds the agents passess recognizes.** An agent is seen by a marker
  in its commands' environment or by its executable among their ancestors. A command
  that clears the markers and detaches from the agent (a daemonized child whose parent
  is now launchd) is seen as no agent and keeps only the secret's allow list. So is an
  agent passess does not know. Like the allow lists, `clients` narrows an agent that
  uses passess; one that attacks it is T6.
- **The agent answers whether a text holds one of its values.** Hooks send tool output
  to it for masking, and so could any same-user process, with a guess. For a short,
  guessable value, a password, that is an oracle. Reaching the socket at all is T6.
- **`passess helper` prints a value by design.** It is for a harness's own API key
  (Claude Code's `apiKeyHelper`). Each secret opts in, a terminal never gets it, and the
  hooks refuse it in agent shells. But the harness's agent can run what the harness
  runs, so this keeps the key off disk, not away from the agent.
- **Approvals stop an agent that uses passess, not one that attacks it.** Any process
  running as the user can connect to the agent as an approver, and so could approve its
  own requests. The agent refuses approvers anchored at a harness executable, and
  `passess agent approve` refuses when it sees a harness, by a marker or among its
  ancestors. A process that detaches from its harness first gets through, which makes
  it T6. An Allow follows the anchor process (ADR 9): in an editor's integrated
  terminal, the user's commands and the editor's agent share it.
- **Moving a value does not unleak it.** A token that sat in a file an agent could read,
  or in a transcript, may already have reached a model provider. `migrate` says to
  rotate; `scan --transcripts` shows where a known value went; `scan --scrub` takes it
  out of the transcripts on disk, and the provider's copy stays where it is.

## Consequences for the design

1. The primary mechanism is to never place a value where the agent can reach it: no
   plaintext `.env` in the workspace, no secrets in the harness environment, no secrets
   in config files.
2. Redaction happens at the subprocess boundary (`exec`, `run`, `mcp-exec`), not in the
   harness.
3. Secret values are held in a type whose every formatting path prints `[REDACTED]`, are
   never passed in argv, never logged, and never written to disk by passess, except in
   the backup of a file that already held them.
