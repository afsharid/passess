# 11. A desktop app reads the keys connected to it by name

Status: accepted, 2026-10-09

## Context

DeepSeek Harness (DSH) is a desktop app with its own model providers. A provider names
the variable that holds its key (`apiKeyEnv: EVREN_LLM_API_KEY`) and DSH looks for it
in its launch environment, then in a plain-text file under `~/.dsh`, then in `.env`
files. It has no key helper command and no keychain store.

A launcher that runs DSH under `passess exec -s EVREN_LLM_API_KEY` keeps the key off
disk, but only when DSH is started through it. Opened from the Dock, from Spotlight, or
by its own restart after an update, DSH has no key. The user's expectation is the
other one: connecting a secret to DSH in Passess.app should be enough, however DSH is
opened.

`passess helper` already prints one secret for a harness to read (ADR 8), but each
secret opts in with `passess-helper` in its allow list, which the app cannot set and a
tick in the Connect window does not mean.

## Decision

- `detect` marks some agents as apps (`IsApp`): desktop apps that ask `passess helper`
  for their own keys. DSH is the first; it is seen by its process name, as in ADR 10.
- `passess helper NAME` prints a secret without `passess-helper` in its allow list when
  the process that started passess itself is such an app, and the secret's `clients`
  names that app. No list (every agent) does not count: the user has to choose the app.
- Only the app's own process counts. With a shell between them it is the app's agent
  running a command, and the rule of ADR 8 applies unchanged.
- Everything else `helper` does stays: no value on a terminal, `clients` checked for
  every agent seen in the call, approval asked for a secret marked `approve`.
- The app side ships here, as the Claude Code plugin does: `plugins/dsh` wraps DSH's
  credentials service. A key DSH does not find in its own sources, and that `passess
  list` shows connected to `dsh`, it asks of `passess helper` without a shell; it keeps
  the value in memory for a few minutes and never logs or writes it.

## Consequences

- Ticking DSH for a secret in Passess.app is what lets DSH read it, from the Dock too.
- The key is off disk, as with the launcher. It is not kept from DSH's own agent:
  its tools run as the same user, and `exec passess helper NAME` from its shell
  replaces the shell, so passess sees DSH as the parent. The launcher already put the
  key in DSH's environment, which the agent's tools inherit; this is no weaker.
- Another app joins by its process name in `detect`, `IsApp`, and a plugin or helper
  setting on its side.
- This is not the roadmap's launch-profile design, where connecting a secret adds it
  to a profile passess starts the app with. That still needs the app to be started by
  passess; this works however the app is started.
