# 10. Secrets name the coding agents they are connected to, chosen in the app

Status: accepted, 2026-10-09

## Context

A secret added to the vault did nothing until someone ran `passess add` in a terminal
with the right reference, and the menu bar app could only show status. People who keep
their secrets in Bitwarden expected a new one to show up in the app, and wanted to say
in a few clicks which coding agent may use it, without a terminal or a text file.

Who may receive a secret was a list of programs (`allow`). Every coding agent could ask
for every secret; nothing said "Codex, but not OpenCode".

## Decision

- `[secrets.NAME]` takes `clients`: the coding agents it is connected to, named by the
  IDs `internal/detect` reports (`claude-code`, `codex`, `opencode`, `kiro`,
  `antigravity`, `cursor`, `gemini-cli`, `zed`). Without the key every agent may ask, as
  before; `clients = []` connects it to none. An unknown ID is a config error.
- exec (in-process and through the agent), `run`, `http`, `mcp-exec` and `helper`
  refuse a secret when a coding agent the call comes from is not in its list. An agent
  is seen two ways: a marker in the caller's environment, or a harness executable among
  the caller's ancestors (`detect.Program`, as for anchors in ADR 9). Every agent seen
  must be connected, so an agent started inside another acts for both.
- A call in which no agent is seen keeps the secret's other rules. Detection only ever
  adds a refusal (the rule of `internal/detect`); the user's own terminal and services
  started by launchd still get what their allow lists and profiles say.
- `passess discover` lists the bws secrets no reference points at, with a name and a
  reference to add each by. `bws secret list` prints values beside the names; passess
  parses the names and clears that output at once. Other backends come later.
- `passess set` changes a secret's clients, approval and note; `passess remove` forgets
  one, but never one a profile or MCP server uses. Both edit the one `[secrets.NAME]`
  table byte for byte, after a backup, and keep the result only if parsing both versions
  shows exactly that change. `add` takes `--clients` and `--approve`. `add`, `set` and
  `remove` hold a lock file next to the config while they read and write it, so a change
  from the app and one from a terminal queue up instead of one overwriting the other.
- `add`, `set`, `remove` and `discover` refuse when a coding agent is seen in the call,
  by a marker or among the caller's ancestors, as the commands that hand out secrets
  see one: what decides who may use a secret must not be easier to reach than what it
  decides (an agent without a marker, Kiro, is seen by its process). The hooks refuse
  them in agent shells too. Who may use which secret, and what the vault holds, are the
  user's.
- The menu bar app lists the secrets and the vault's unconnected ones. Connecting or
  changing one opens a window with a checkbox per agent and "ask me first"; Save asks for
  Touch ID or the password, then runs the CLI. The app never receives a value.

## Consequences

- The app can do what needed a terminal, and an agent driving the screen can press the
  buttons but not the sensor.
- `clients` narrows who may ask; `allow` still narrows what may receive. A secret the
  user restricts to Codex no longer reaches an MCP server Claude Code starts, and the
  app says which profiles and MCP servers use each secret.
- A coding agent passess does not recognize counts as no agent. The list is the one
  `detect` knows; adding a harness there adds it here.
- A config with `clients` does not load in a passess older than this one, which rejects
  unknown keys: the CLI, the agent and the app have to be updated together.
- Discovery fetches every value the machine account can read, as resolving a project
  does, so the app runs it on start, when it opens and at most every half hour.
