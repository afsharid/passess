# Roadmap

passess grows in thin vertical slices; each one is usable on its own. Release gates
follow the slices.

| Release | Slices | What it brings |
|---|---|---|
| — | 0, 1 | Skeleton, threat model, `exec` and `run` with `env://`, `keychain://` and `bws://` |
| v0.1.0-alpha | 2 | `mcp-exec` (local stdio proxy and remote HTTP bridge), `install` / `uninstall` / `status` for Claude Code and Codex |
| v0.2 | 3 | `scan`, `audit`, `inventory`, `migrate`; 1Password, Vault/OpenBao and Bitwarden Password Manager providers |
| v0.3 | 4 | Config-level support for OpenCode, Kiro, Antigravity, Cursor, Gemini CLI, VS Code / Copilot, Windsurf, Zed, Claude Desktop |
| **v0.4** | 5 | Guard hooks and native plugin packages for Claude Code, Codex, OpenCode, Kiro, Antigravity, Cursor and Gemini CLI — the first complete release |
| v0.5 | 6 | `passess agent`: in-memory cache, approvals (Touch ID in the macOS menu bar app), audit log, session-wide redaction |
| v0.6+ | 7 | Host-bound egress proxy, transcript clean-up, `fnox://`, `passess trust`, Linux and Windows polish, signed releases |

## Slice details

**Slice 1 (done).** References and a value type that cannot be printed, the redactor,
providers for `env`, `keychain` and `bws`, the policy that keeps shells and
interpreters away from secrets, `exec`, `run` with profiles. Still to do in this
slice: `list`, `check`, `add`, `doctor` (with `--json` for the menu bar app).

**Slice 2.** `passess mcp-exec <name>` becomes the MCP `command` in every harness:
the server's command and secrets live in passess config, not in the harness file.
Remote servers get a stdio-to-streamable-HTTP bridge built on the official MCP Go SDK
that adds the auth header itself. Installers for Claude Code (through `claude mcp`)
and Codex (in-place TOML edits) with dry run, backups and rollback.

**Slice 3.** Scanning harness configs, dotfiles, `.env` files and transcripts with
known-value matching plus vendored gitleaks rules (ADR 5); auditing harness defaults;
migrating inline secrets into the user's vault.

**Slice 5.** One hook handler, `passess hook <harness> <event>`, normalizes each
harness's hook JSON and applies a deny-only policy: no reading `.env` or credential
files, no environment dumps, a paste guard for prompts, context at session start.
Hooks are defense in depth; see the threat model for why they are not the boundary.

**macOS menu bar app.** A thin SwiftUI client that shows `passess doctor --json` and,
from slice 6, asks for Touch ID approval when the daemon needs it. It never receives a
secret value.
