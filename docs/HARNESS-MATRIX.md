# Harness matrix

What each AI coding harness lets passess do, and how each claim was established.
The deciding column is whether a hook can change the output the model sees: most
harnesses can block a call, few can correct what comes back, which is why passess
redacts at the subprocess boundary.

Verification key: **bin** = read from the installed binary's own schema strings;
**run** = observed by running the installed binary; **src** = read from the harness's
source code; **doc** = vendor documentation;
**cfg** = observed in real config files on the maintainer's machine; **?** = not
verified yet.

| Harness | Block a call | Rewrite input | Rewrite model-visible output | MCP env syntax | Instructions file |
|---|---|---|---|---|---|
| Claude Code 2.1.281 | yes, `permissionDecision` (bin) | yes, `updatedInput` (bin) | yes, PostToolUse `updatedToolOutput`, which must keep the tool's output shape (bin) | `${VAR}`, `${VAR:-default}` (doc) | `CLAUDE.md` |
| Codex 0.155 | yes, same fields as Claude Code (bin, doc) | yes, `updatedInput` (bin) | no documented field; no `updatedToolOutput` in the binary (bin) | TOML; `bearer_token_env_var`, `env_http_headers` (doc) | `AGENTS.md` |
| Gemini CLI | yes, BeforeTool `decision: deny` (doc) | yes, `tool_input` (doc) | yes: AfterTool exit 2 replaces the result with stderr (doc) | `$VAR`, `${VAR}` (doc) | `GEMINI.md` |
| Cursor | yes, `permission: deny`, exit 2 (doc) | yes, `updated_input` (doc) | MCP only, `updated_mcp_tool_output`; not shell (doc) | `${env:NAME}`, `envFile` (doc) | `AGENTS.md`, rules |
| OpenCode 1.18 | yes, `tool.execute.before` throws (doc, bin) | yes, argument mutation (doc) | yes, `tool.execute.after` mutates `output.output` (doc) | `{env:NAME}`, `{file:path}` (doc, bin) | `AGENTS.md` |
| Kiro CLI 2.21 | yes, preToolUse exit 2 (doc; events in the binary) | ? | no (doc) | JSON `env` (cfg) | steering files |
| Antigravity (agy 1.2.11) | yes, PreToolUse `decision: deny` (doc); no prompt or session event | ? | no (doc) | JSON `env` (cfg) | `~/.gemini/config/rules/` (bin) |
| VS Code / Copilot | config-level only for now | | | `${input:id}` with `password: true`, `${env:VAR}` (doc) | `copilot-instructions.md` |
| Windsurf | pre-hooks only (doc) | no (doc) | no (doc) | JSON | |
| Zed, Claude Desktop | config-level only for now | | | JSON `env` | |

## How passess installs itself

| Harness | Reads | Writes | Instructions | Verified |
|---|---|---|---|---|
| Claude Code | `~/.claude.json` → `mcpServers` (user scope) | `claude mcp add --scope user NAME -- passess mcp-exec NAME`, `claude mcp remove --scope user NAME` | `~/.claude/CLAUDE.md` | live, against the installed CLI in a throwaway `HOME` |
| Codex | `$CODEX_HOME/config.toml` → `[mcp_servers.*]` | `codex mcp add NAME -- passess mcp-exec NAME`, `codex mcp remove NAME` | `$CODEX_HOME/AGENTS.md` | live, same way |
| Antigravity | `~/.gemini/config/mcp_config.json` → `mcpServers` (resolved: `~/.gemini/antigravity/mcp_config.json` links to it) | `agy mcp add NAME passess mcp-exec NAME`, `agy mcp remove NAME` | `~/.gemini/config/rules/passess.md` | live (agy 1.2.11) |
| OpenCode | `$XDG/opencode/opencode.json` or `.jsonc` → `mcp` (`type: local`, one `command` array, `environment`) | file edit; refuses when both files exist | `$XDG/opencode/AGENTS.md` | golden |
| Kiro | `~/.kiro/settings/mcp.json` → `mcpServers` | file edit | `~/.kiro/steering/passess.md` | golden |
| Gemini CLI | `~/.gemini/settings.json` → `mcpServers` (strict JSON) | file edit, only with `gemini` on PATH | `~/.gemini/GEMINI.md` | golden |
| Cursor | `~/.cursor/mcp.json` → `mcpServers` (`type: stdio`) | file edit | — | golden, symlink case |
| VS Code | `Code/User/mcp.json` → `servers` (`type: stdio`) | edits an existing file only: the path is inferred | — | golden |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` or `$XDG/devin/mcp_config.json` | edits an existing file only | — | golden |
| Zed | `$XDG/zed/settings.json` → `context_servers`, an untagged enum whose stdio form is `{command, args, env?}` (src, zed@933d8d9) | edits an existing file only | `$XDG/zed/AGENTS.md` | golden |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS only) | file edit | — | golden |

`$XDG` is `XDG_CONFIG_HOME`, else `~/.config`. "golden" means an adapter test on a real
config shape: install adds the entry, a second install changes nothing, and uninstall
gives back the original bytes. Edited files keep their mode; `audit` reports modes
separately.

The harness CLIs own their file formats, so passess never rewrites `~/.claude.json`
(which Claude Code updates constantly) or the TOML that holds a user's other Codex
settings. The entries carry no secret, so passing them as arguments exposes nothing.
Where no CLI works unattended, passess edits the file itself (ADR 7).

What the harnesses did, rather than what their docs say:

- `agy` 1.2.11 has `mcp add` and `mcp remove`. They work without sign-in and write
  `~/.gemini/config/mcp_config.json` (run, in a throwaway `HOME`). Antigravity's docs do
  not list them. Its global customization root is `~/.gemini/config/`, with `rules/`
  beside `skills/` and `workflows/` (bin).
- `kiro-cli` 2.21.4 refuses `mcp add` without a signed-in account, even for the local
  file (run). Its help lists `--args` and `--agent`, which the docs do not.
- Kiro agent profiles load `~/.kiro/settings/mcp.json` only with `includeMcpJson: true`,
  and the default is false (doc). 6 of 7 profiles on the maintainer's machine leave it
  off (cfg). `passess audit` lists such profiles.

## How passess registers its hook handler

`passess install` adds one handler per event, running `/absolute/path/to/passess hook
HARNESS EVENT`; entries whose command runs `passess hook` are passess's, and `uninstall`
removes exactly those (and any event list or file only they filled). The exchanges
themselves, one per harness and event, are pinned in `internal/cli/testdata/hooks/`.

| Harness | File | Events | Payload, as read |
|---|---|---|---|
| Claude Code | `~/.claude/settings.json` → `hooks` | PreToolUse (Bash, Read, Grep, Write, Edit, MultiEdit, Notebook*), PostToolUse, UserPromptSubmit, SessionStart | `tool_name`, `tool_input`, `tool_response`, `prompt` (doc, bin) |
| Codex | `~/.codex/hooks.json` → `hooks` | PreToolUse, UserPromptSubmit, SessionStart | as Claude Code; the shell command may be an argv array; `apply_patch` names its files in the patch; the prompt may come as `user_prompt` (doc) |
| Gemini CLI | `~/.gemini/settings.json` → `hooks` | BeforeTool, AfterTool, BeforeAgent, SessionStart | `tool_name`, `tool_input`, `tool_response.llmContent`, `prompt` (doc) |
| Cursor | `~/.cursor/hooks.json` (`version: 1`) | beforeShellExecution, beforeReadFile, beforeSubmitPrompt, sessionStart | `command`, `file_path` (the file's `content` also arrives and is ignored), `prompt` (doc) |
| OpenCode | `$XDG/opencode/plugins/passess.js` | tool.execute.before/after, chat.message | passess's own JSON, from its plugin |
| Antigravity | `~/.gemini/config/hooks.json` → `passess` | PreToolUse | `toolCall.name`, `toolCall.args` (`CommandLine`, `Cwd`; file tools by any `*Path`/`*File` argument) (doc, bin) |
| Kiro | an agent profile's `hooks`, by hand | agentSpawn, userPromptSubmit, preToolUse | tool names `execute_bash`, `fs_read`, `fs_write` (bin); the stdin fields are not documented, so passess reads the Claude-style ones and `USER_PROMPT` (doc) |

Codex runs hooks it has not seen before only once they are trusted in `/hooks` (doc).

## Insecure defaults

`passess audit` checks the first two today; the rest arrive with their adapters.

- Codex 0.155.0-alpha.16.4 (run): with no `shell_environment_policy`, variables named
  `*KEY*`, `*SECRET*` and `*TOKEN*` reach the commands the agent runs.
  `ignore_default_excludes = false` drops those three; `*PASSWORD*` and `*PASSWD*` still
  pass unless listed in `exclude`, and `exclude = ["*PASSWORD*", "*PASSWD*"]` works.
  Method: `codex sandbox -- /usr/bin/env` with an empty `CODEX_HOME` and fake variables,
  varying `-c shell_environment_policy.…`. That is the seatbelt runner, not the agent's
  own shell tool; alpha defaults move, so audit re-reads the config rather than trusting
  a version number. Profiles are `$CODEX_HOME/NAME.config.toml` files layered over
  `config.toml` by `--profile NAME`, and their policy applies to those runs (run); 0.155
  refuses to start with the legacy `profile = "…"` key. audit reads `config.toml`, the
  layer every run gets.
- Claude Code: credentials in `settings.json` `env` reach every session, command and MCP
  server. It also keeps copies of `~/.claude.json` in `~/.claude.json.backup` and
  `~/.claude/backups/` (cfg), which still hold whatever the file held; `passess scan`
  reads them.
- Claude Code: MCP `env` values passed on the command line are visible in `ps`
  (anthropics/claude-code#80045). passess entries carry no value, so nothing shows.
- Kiro: agent profiles with `includeMcpJson: false` do not receive the global MCP config
  (cfg: 6 of 7 profiles on the maintainer's machine).
- Antigravity: several config paths, one of them a symlink; resolve, never glob (cfg).
- Windsurf: `post_cascade_response_with_transcript` writes the full transcript to JSONL (doc).
- Goose and Copilot CLI: fall back to plaintext token storage when no keychain is available (doc).

## Harness detection

Used only to label audit records and to *add* protection, never to grant anything:
`CLAUDE_PROJECT_DIR`, `CODEX_THREAD_ID`, `CURSOR_TRACE_ID`, `GEMINI_CLI`, `OPENCODE*`,
`ANTIGRAVITY_CLI_ALIAS`, `ZED_SESSION_ID`, `VSCODE_PID`. Kiro sets no marker.

Entries marked **?** are verified before the hook adapters for that harness are written,
and the end-to-end canary results will be recorded here per harness.
