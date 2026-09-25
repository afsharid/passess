# 3. Project files name secrets; only user config maps them

Status: accepted, 2026-09-25

## Context

A project-level `passess.toml` is convenient: it tells a new contributor which secrets
the project needs. But a cloned repository is untrusted input. If a project file could
declare `ref = "keychain://…"` together with `allow = ["curl"]`, cloning a malicious repo
and letting an agent follow its instructions would turn passess into the exfiltration
tool.

## Decision

In v1 a project file may only list the secret names it needs, with optional notes and
optional narrowing of the allowed commands. References, backends and any widening of
policy exist only in the user's own config (`~/.config/passess/config.toml`). A project
can narrow what the user allows, never widen it.

## Consequences

- `passess check` reports names a project needs that the user has not mapped, with the
  command to map them.
- Teams that want to share references (for example 1Password shared vaults) will get an
  explicit `passess trust` step later, recorded by content hash in user config.
