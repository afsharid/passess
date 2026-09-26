# passess

**The last mile between your password manager and your AI coding agents.**

> Status: pre-alpha. Nothing here is ready to trust with a real secret yet.
> Works today: `exec`, `run`, `list`, `check`, `add`, `doctor`, `mcp-exec`, and
> `install` / `status` / `uninstall` for Claude Code and Codex, with `env://`,
> `keychain://` and `bws://` references; plus the macOS menu bar app. Next: scanning
> and migrating plaintext secrets, then 1Password, Vault and `bw`.

AI coding agents need API keys and passwords to do real work, and today those secrets
end up everywhere: plaintext tokens in MCP config files, `.env` files the agent reads,
`env` and `curl -v` output that lands in the model's context, keys pasted into chat,
secrets committed by the agent. Once a value reaches the context it also reaches the
provider's logs, session transcripts and memory stores.

passess is not a new vault. You keep your secrets where they already are — Bitwarden
(Password Manager or Secrets Manager), 1Password, HashiCorp Vault / OpenBao or the macOS
Keychain. passess stores only *references* (`op://…`, `bws://…`, `vault://…`), resolves
them at the last moment into the one subprocess that needs them, and scrubs the values
from whatever comes back. By default the agent never sees a value.

## How it works

```sh
# The agent runs a command that needs a secret. The value goes into the child's
# environment only; anything the child prints is redacted.
passess exec -s GITHUB_TOKEN -- gh api user

# MCP servers are registered in every harness as `passess mcp-exec <name>`, so no
# harness config file holds a token.
passess mcp-exec github

# Services and dev servers get a named profile with a clean environment.
passess run web -- npm run dev
```

The same references and policy work across Claude Code, Codex, OpenCode, Kiro,
Antigravity, Cursor and Gemini CLI, with config-level support for VS Code / Copilot,
Windsurf, Zed and Claude Desktop. See [docs/ROADMAP.md](docs/ROADMAP.md) for what
lands when.

## Install

```sh
go install github.com/afsharid/passess/cmd/passess@latest
```

Requires Go 1.27.1 or newer. Or download a release: macOS and Linux binaries for
arm64 and amd64, `checksums.txt`, and the menu bar app for Apple silicon. Each file
carries a build provenance attestation:

```sh
gh attestation verify passess_0.1.0-alpha_darwin_arm64.tar.gz --repo afsharid/passess
```

## Quick start

Put a secret in the macOS Keychain (the value is prompted for, never typed on the
command line), then describe it in `~/.config/passess/config.toml`:

```sh
security add-generic-password -U -s passess -a github -w
```

```toml
version = 1

[secrets.GITHUB_TOKEN]
ref   = "keychain://passess/github"
allow = ["gh", "git"]
```

```sh
passess exec -s GITHUB_TOKEN -- gh api user   # the value reaches gh only
passess exec -s GITHUB_TOKEN -- sh -c 'echo $GITHUB_TOKEN'
# refused: shells get no secrets unless the allow list names them
```

A reference can also point at Bitwarden Secrets Manager (`bws://<project>/<KEY>`,
with the machine token itself kept in the keychain via `backends.bws.access_token`)
or at an environment variable (`env://NAME`). 1Password, Vault / OpenBao and the
Bitwarden Password Manager follow.

Other commands: `passess list` (names, backends, who may receive them), `passess
check` (which secrets resolve, never their values), `passess add NAME --ref …` or
`passess add NAME --keychain` (you type the value into the keychain yourself), and
`passess doctor` (what is wrong and the command that fixes it). Each takes `--json`.

## MCP servers without tokens in harness configs

Define each server once, in passess config:

```toml
[mcp.github]                                  # a local stdio server
command = ["github-mcp-server", "stdio"]
env     = { GITHUB_PERSONAL_ACCESS_TOKEN = "GITHUB_TOKEN" }

[mcp.tracker]                                 # a remote streamable-HTTP server
url     = "https://mcp.example.com/mcp"
headers = { Authorization = "Bearer {{TRACKER_TOKEN}}" }
```

Then let passess register them with your harnesses:

```sh
passess install            # dry run: shows what would change in Claude Code and Codex
passess install --apply    # registers each server as `passess mcp-exec NAME`
passess status             # what each harness runs, and any credentials still in clear
```

The harness config ends up holding only `passess mcp-exec github`. The local server
gets its secret in its environment; for a remote server passess runs a stdio bridge
that adds the header itself, so even harnesses started from the Dock work. Output
from either comes back redacted. Changes go through `claude mcp` and `codex mcp`,
files are backed up under `~/.local/state/passess/backups` first, and
`passess uninstall --apply` takes everything out again.

## macOS menu bar app

`Passess.app` sits in the menu bar and shows `passess doctor`: whether the config
loads, whether each backend is usable, and every problem with its fix one click
away on the clipboard. "Check secrets now" reports which secrets resolve — names and
sources only; the app never receives a value. It bundles its own copy of the CLI.

```sh
make macos-app            # needs only the Xcode Command Line Tools
open bin/Passess.app
```

The build is ad-hoc signed, so the first launch of a copy downloaded from elsewhere
needs right-click → Open. Touch ID approvals for the upcoming `passess agent` will
live here too.

## What it protects against — and what it does not

- **Accidental exposure** (the common case): an agent reading `.env`, dumping the
  environment, printing a header while debugging. This is the primary target.
- **Plaintext at rest**: tokens in harness configs, dotfiles, `.env` files and transcripts.
- **Over-broad access**: every process inheriting every secret.
- **Prompt-injection exfiltration** is made harder (per-secret command allow lists, no
  shells or interpreters by default), not impossible.
- **A deliberately malicious agent with an unsandboxed shell running as your user** is
  out of scope: it can read anything you can. A hard boundary needs the harness sandbox
  with passess outside it.

Redaction is best effort, not a sandbox. Harness hooks are defense in depth, not the
mechanism: several ingestion paths (file watchers, pasted text, compaction) never fire a
hook. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## License

Apache-2.0
