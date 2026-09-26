# 4. Shells, interpreters and encoders get no secrets by default

Status: accepted, 2026-09-25

## Context

`passess exec` and `passess run` put a secret in a child's environment and redact the
child's output. Redaction matches the value and its common encodings; a program that
transforms the value (reverses it, splits it, re-encodes it) defeats it. Shells and
interpreters make such transformations a one-liner, and a prompt-injected agent can ask
for exactly that.

## Decision

Unless a secret's `allow` list names them explicitly, these programs cannot receive a
secret: sh, bash, zsh, fish, dash, ksh, python, python3, node, deno, bun, perl, ruby, php,
osascript, env, printenv, base64, xxd, od, hexdump, rev, tr. The check applies to the
program passess would actually execute, not to the name the caller typed: symlinks are
resolved, a script is judged by the interpreter on its `#!` line (including
`/usr/bin/env <name>`), and a binary byte-identical to a denied interpreter found on
`PATH` is treated as that interpreter, so `cp /bin/sh ./gh` does not get through. The
same policy code serves `exec`, `run` profiles and `mcp-exec`. `mcp-exec` takes its
command from user config only, never from its caller's argv.

An MCP server's command is different: the user wrote it into their own config and
`mcp-exec` takes no command from its caller, so no agent chose it. The default refusal
does not apply there (`npx` and `uvx` are how most servers start), but a secret's
explicit allow list still does.

Names fold into families before comparison: every shell is `sh` (Debian's `/bin/sh` is
dash, Fedora's is bash, Alpine's is busybox, and allowing a shell should not depend on
which one), `python3.14` is `python`, `nodejs` is `node`. For a multi-call binary such as
busybox the applet named by argv[0] decides, so `ls` on Alpine stays an ordinary program
while `sh` and `busybox` itself stay denied.

## Consequences

- Common tools that read credentials from the environment (`gh`, `git`, `aws`, `psql`,
  `curl --variable %NAME --expand-header …`) work without configuration.
- Commands that need the value inside an argument must either use such a tool-native
  mechanism or have `sh` added to that secret's allow list, a visible, deliberate choice.
- This raises the bar for T5; it does not close it. Allowing `curl` still allows any host,
  and a deliberately modified copy of an interpreter is not recognized (that is T6).
