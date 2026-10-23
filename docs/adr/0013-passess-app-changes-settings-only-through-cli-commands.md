# 13. Passess.app changes settings only through CLI commands

Status: accepted, 2026-10-23

## Context

Slice 8 is "secrets without a terminal". Until now only a Bitwarden Secrets Manager
secret could be added from Passess.app. A 1Password field, a keychain value, a Vault or
`bw` reference, the agent at login and the CLI on the PATH all needed a terminal or a
hand edit of `config.toml`.

The app could write `config.toml` itself. It does not, for three reasons:

- ADR 7 edits configs by splicing bytes, with the result checked by parsing both
  versions. That code is in Go, under test, and behind the config lock. A second writer
  in Swift would be a second implementation of the same checks.
- The CLI refuses changes under a coding agent (`refuseUnderAgent`). A file the app
  writes would bypass that gate for any process that can drive the app's code.
- A setting changed in the app and the same setting changed in a terminal must give
  the same file. One writer guarantees it.

## Decision

- Passess.app never writes `config.toml`. Every setting the app changes has a CLI
  command, and the app runs that command through `Runner.swift`.
- Secret values never go in argv. A command that takes a value reads it from stdin:
  `passess backend bws`, and now `passess add NAME --keychain --value-stdin`. The app
  sends such a value only to the CLI inside its own bundle (`Passess.bundled()`), never
  to one found on the search path.
- What the app shows from a backend comes from a command that returns names only.
  `passess browse op --json` lists vaults, items and fields. `op item get` sends every
  value of an item, so passess decodes into types that have no value field and clears
  op's answer; a test walks the JSON for a `value` key. `passess browse keychain --json`
  runs `security dump-keychain` without `-d`.
- New commands for this slice: `browse op`, `browse keychain`, `add --keychain
  --value-stdin`, and `set --ref`, `set --allow`. `list` and `browse` read a config not
  written yet as an empty one, so first-run setup can list agents before any secret.
- What is not a passess setting stays in the app: the `~/.local/bin/passess` link to the
  bundled CLI, and the LaunchAgent that runs `passess agent serve` at login
  (`SMAppService.agent`, plist inside the app).
- `passess install --apply` refuses when the only path to itself is inside an app
  bundle. Harness configs would otherwise name a binary that moves with the app.

## Consequences

- The CLI grows a command per setting. The rest followed the same rule: `backend op |
  vault | bw | bws`, `mcp add | set | remove | list`, `profile add | set | remove | list`
  and `agent config` write `[backends.NAME]`, `[mcp.NAME]`, `[profiles.NAME]` and
  `[agent]` with the same checked splice (`config.SetTableFields`, which can create a
  table the file does not have yet). The Vault token and the `bw` session go to the
  keychain on stdin, as the bws token does. A plain value that looks like a credential
  (an MCP server's vars, a header's text, a profile's env) is refused. The app shows
  these in a Settings window, and `doctor --json` names an action per problem so the
  app offers a button instead of a command to copy. No setting needs a hand edit.
- The app needs the CLI to change anything; a dev build from `swift run` has no bundled
  CLI and cannot store a keychain value or register the login agent.
- The login agent is the bundled build. When the CLI on the PATH is a different build,
  the panel's existing update path replaces the agent with that build, so at each login
  the agent may be restarted once.
- `browse op` cannot ask op for names alone; the values reach passess's memory briefly.
  This is the same exposure as `passess discover` with bws.
