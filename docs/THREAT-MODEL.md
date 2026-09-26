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
| T4 | Over-broad access: every process inherits every secret | Least privilege | Secrets are declared per consumer (command, MCP server, profile) |
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
- **Allowing `curl` means allowing every host.** Until the egress proxy exists, a secret
  whose allow list contains `curl` can be sent to any URL the agent chooses. The curl
  form passess teaches agents is also the exfiltration form.
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
- **Hooks fail open.** A broken config, an unknown event or a bug lets the action
  through. That is deliberate, because a hook that blocks everything gets removed. It
  is also why the hooks are not the boundary.
- **Backups keep what they copied.** `migrate` and `install` back up every file before
  changing it (0600, in a 0700 directory under `~/.local/state/passess/backups`). After a
  migrate, that backup is the one place passess leaves a value on disk: the original file,
  as it was. Harnesses keep their own copies too (`~/.claude/backups`). `scan` reports
  both and `migrate` prints the removal command; deleting them is the user's call,
  because a backup is also how a bad change is undone.
- **Moving a value does not unleak it.** A token that sat in a file an agent could read,
  or in a transcript, may already have reached a model provider. `migrate` says to
  rotate; `scan --transcripts` shows where a known value went.

## Consequences for the design

1. The primary mechanism is to never place a value where the agent can reach it: no
   plaintext `.env` in the workspace, no secrets in the harness environment, no secrets
   in config files.
2. Redaction happens at the subprocess boundary (`exec`, `run`, `mcp-exec`), not in the
   harness.
3. Secret values are held in a type whose every formatting path prints `[REDACTED]`, are
   never passed in argv, never logged, and never written to disk by passess, except in
   the backup of a file that already held them.
