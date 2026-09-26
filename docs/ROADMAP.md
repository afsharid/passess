# Roadmap

passess grows in thin vertical slices; each one is usable on its own. Release gates
follow the slices.

| Release | Slices | What it brings |
|---|---|---|
| — | 0, 1 | Skeleton, threat model, `exec` and `run` with `env://`, `keychain://` and `bws://` |
| v0.1.0-alpha | 2 | `mcp-exec` (local stdio proxy and remote HTTP bridge), `install` / `uninstall` / `status` for Claude Code and Codex |
| v0.2.0-alpha | 3 | `scan`, `audit`, `inventory`, `migrate`; 1Password, Vault/OpenBao and Bitwarden Password Manager providers |
| v0.3.0-alpha | 4 | Config-level support for OpenCode, Kiro, Antigravity, Cursor, Gemini CLI, VS Code / Copilot, Windsurf, Zed, Claude Desktop |
| v0.4.0-alpha | 5 | Guard hooks for Claude Code, Codex, OpenCode, Kiro, Antigravity, Cursor and Gemini CLI, registered by `install`; the Claude Code plugin |
| **v0.4.0** | — | The first complete release: slice 5 once the canary matrix is green and the maintainer's own machine runs on passess (both need the maintainer) |
| v0.5 | 6 | `passess agent`: in-memory cache, approvals (Touch ID in the macOS menu bar app), audit log, session-wide redaction |
| v0.6+ | 7 | Host-bound egress proxy, transcript clean-up, `fnox://`, `passess trust`, Linux and Windows polish, signed releases |

## Slice details

**Slice 1 (done).** References and a value type that cannot be printed, the redactor,
providers for `env`, `keychain` and `bws`, the policy that keeps shells and
interpreters away from secrets, `exec`, `run` with profiles, `list`, `check`, `add`
and `doctor`, each with `--json`.

**Slice 2 (done).** `passess mcp-exec <name>` becomes the MCP `command` in every
harness: the server's command and secrets live in passess config, not in the harness
file. Remote servers get a stdio-to-streamable-HTTP bridge built on the official MCP
Go SDK that adds the auth header itself (ADR 6). Installers for Claude Code and Codex
go through the harnesses' own CLIs (`claude mcp`, `codex mcp`), which own their file
formats; dry run by default, backups before any change, `uninstall` as the undo.

**Slice 3 (done).** Providers for 1Password (`op`), Vault / OpenBao (HTTP, KV v1 and
v2) and the Bitwarden Password Manager (`bw`). `scan` looks at harness configs and the
backups kept next to them, dotfiles, `.env` files and, on request, transcripts, with the
vendored gitleaks rules plus the exact values of configured secrets (ADR 5); it never
prints a value. `audit` reports harness defaults and files that hand credentials to
agents, each with its fix. `migrate` moves `.env` lines and inline MCP credentials into
the OS keychain and rewires the harness; `inventory` writes a value-free Markdown map.
Flags may follow arguments (`passess install claude --apply`).

**Slice 4 (done).** `install`, `status`, `uninstall` and `migrate mcp` reach nine more
harnesses. Antigravity goes through `agy mcp`; the other eight have no command that works
unattended, so passess edits their JSON or JSONC config with a byte-level splicer that
keeps comments and formatting and makes uninstall exact (ADR 7). Each harness is a small
spec: config paths (XDG-aware, symlinks resolved, never creating a harness's directory),
the path to its servers, the entry shape and its instructions file. `audit` reports Kiro
agent profiles that ignore the global MCP config. Writing into those profiles, and the
`tools` lists that gate them, is left for when the hooks for Kiro land.

**Slice 5 (done).** One handler, `passess hook <harness> <event>`, normalizes each
harness's hook payload and applies a deny-only policy. Shell commands are parsed
(mvdan.cc/sh), not pattern-matched. It refuses environment dumps, reads of `.env` and
credential files, vault reads that print a value, `$TOKEN` in a command line, pasted
credentials in prompts, and agent writes to the passess config. It redacts tool output
where the harness allows, and adds a session note. It fails open, and one golden per
harness and event is the contract. `install` registers it with six harnesses; Kiro
is by hand. The measured cost is p50 4.0 ms for a shell check and 5.0 ms for a prompt
check (ADR 5). Hooks are defense in depth; see the threat model for why they are not
the boundary.

**Slice 6 (in progress).** `passess agent` runs agent commands itself and keeps what
vaults returned in memory for `agent.cache_ttl`; no value crosses its socket (ADR 8).
Done: the socket (the user's own processes only, stdio passed as descriptors), the
cache with `status`, `lock` and `stop`, and `exec` through the agent with the in-process
path unchanged. Next: approvals keyed on secret, program and harness, answered with
Touch ID in the menu bar app and failing closed; an audit log of names; then hook
redaction with the agent's values, `passess helper` for `apiKeyHelper`, and hooks that
refuse ways around the agent.

**Before v0.4.0.** The canary matrix: each harness, run for real with a canary secret,
must never show it in its output, transcripts or files. And the maintainer's machine
must run on passess: its MCP servers through `mcp-exec`, its secrets moved, `audit`
clean. Both use the maintainer's accounts, so they wait for them.

**macOS menu bar app (first version done).** A thin AppKit client, `macos/PassessBar`,
that shows `passess doctor --json`, runs `check` on request and bundles the CLI. From
slice 6 it asks for Touch ID approval when the daemon needs it. It never receives a
secret value; the JSON it reads is pinned by fixtures that the Go tests write and the
app's headless checks decode.
