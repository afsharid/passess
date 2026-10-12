# 12. passess names the key a DSH provider asks for

Status: accepted, 2026-10-12

## Context

ADR 11 has DSH's plugin answer for the keys DSH asks its credentials service for. A
user connected `CLAUDE_API_KEY` to `dsh` in Passess.app, and DSH's Claude models still
had no key. `passess status dsh` did not list the key at all.

Read in DSH 0.2.0-rc.2 (`dsh-llm-pi-ai`):

- A provider's key comes from `credentials.resolve(profile.apiKeyEnv)`. When the
  profile has no `apiKeyEnv`, that function returns at once and asks nothing.
- pi-ai then looks in the launch environment only (`ANTHROPIC_API_KEY` for
  `anthropic`). A DSH opened from the Dock has none.

So for a provider that names no key, the plugin is never asked, whatever name the
secret has. The user's `anthropic` provider listed models and nothing else.

Before this was read, the plan was a per-secret alias (`as = { dsh = "ANTHROPIC_API_KEY" }`)
that the plugin would map. Clef chose it at 0.99 over a plugin config in the patch
block and a new per-app table. The alias cannot work: it only renames a question DSH
never asks. It was dropped.

## Decision

- `passess status dsh` lists every provider under a `providers:` mapping that has no
  `apiKeyEnv` as an `unnamed` key, with the provider's name.
- `passess install dsh --key PROVIDER=NAME --apply` writes `apiKeyEnv: NAME` under that
  provider in the user's `cordis.patch.yml`. It replaces an existing line in place, and
  otherwise inserts one line after the provider's own line, at its keys' indentation.
  Every other byte stays as it was. It reads the file back and restores it when the
  provider does not show the new name (ADR 7). A backup is taken first, as for install.
- The name is the passess secret's own name. No alias: DSH then asks for exactly the
  name passess has, and ADR 11's by-name rule applies unchanged.
- `--key --apply` is refused under a coding agent. Which secret a provider sends to its
  endpoint is the user's call, like connecting it.
- Passess.app shows the provider in DSH's row. Its Connect lists the secrets passess
  has. Picking one runs the command above, then opens that secret with DSH ticked when
  it is not connected to DSH by name yet.

## Consequences

- The line goes outside passess's marked block, into the user's own rows.
  `uninstall` does not take it out: it names a secret, and works the same with the
  key typed into DSH's Models page under that name.
- The scan follows indentation, not YAML. A provider under a quoted key or written inline
  (`anthropic: { ... }`) is not listed, and `--key` refuses it.
- A provider DSH uses but the patch does not list (only `provider: anthropic` in the
  default model) is not covered. The Models page adds it to the patch.
- Out of scope: `ANTHROPIC_AUTH_TOKEN`, and providers that authenticate without a key
  (Bedrock, Vertex).
- Whether DSH rereads the patch while running was not measured; the CLI says to
  restart it after naming a key.
