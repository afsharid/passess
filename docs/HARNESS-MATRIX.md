# Harness matrix

What each AI coding harness lets passess do, and how each claim was established.
The deciding column is whether a hook can change the output the model sees: most
harnesses can block a call, few can correct what comes back, which is why passess
redacts at the subprocess boundary.

Verification key: **bin** = read from the installed binary's own schema strings;
**doc** = vendor documentation; **cfg** = observed in real config files on the
maintainer's machine; **?** = not verified yet.

| Harness | Block a call | Rewrite input | Rewrite model-visible output | MCP env syntax | Instructions file |
|---|---|---|---|---|---|
| Claude Code 2.1.281 | yes, `permissionDecision` (bin) | yes, `updatedInput` (bin) | yes, PostToolUse `updatedToolOutput`, all tools, synchronous hooks only (bin) | `${VAR}`, `${VAR:-default}` (doc) | `CLAUDE.md` |
| Codex 0.155 | yes (bin, doc) | yes, `updatedInput` (bin) | yes, PostToolUse `decision: block` (doc) | TOML; `bearer_token_env_var`, `env_http_headers` (doc) | `AGENTS.md` |
| Gemini CLI | yes, BeforeTool (doc) | yes, `tool_input` (doc) | yes, AfterTool (doc) | `$VAR`, `${VAR}` (doc) | `GEMINI.md` |
| Cursor | yes, `failClosed` available (doc) | yes, `updated_input` (doc) | MCP only, `updated_mcp_tool_output`; not shell (doc) | `${env:NAME}`, `envFile` (doc) | `AGENTS.md`, rules |
| OpenCode 1.18 | yes, `tool.execute.before` throws (doc, bin) | yes, argument mutation (doc) | ? | `{env:NAME}`, `{file:path}` (doc, bin) | `AGENTS.md` |
| Kiro CLI 2.21 | yes, preToolUse (doc, cfg) | ? | ? | JSON `env` (cfg) | steering files |
| Antigravity | CLI hooks exist (?) | ? | ? | JSON `env` (cfg) | `GEMINI.md` |
| VS Code / Copilot | config-level only for now | | | `${input:id}` with `password: true`, `${env:VAR}` (doc) | `copilot-instructions.md` |
| Windsurf | pre-hooks only (doc) | no (doc) | no (doc) | JSON | |
| Zed, Claude Desktop | config-level only for now | | | JSON `env` | |

## Insecure defaults passess will audit

- Claude Code: MCP `env` values passed on the command line are visible in `ps`
  (anthropics/claude-code#80045).
- Codex: `shell_environment_policy.ignore_default_excludes` — documented as passing
  variables named like `*KEY*`, `*SECRET*`, `*TOKEN*` into agent shells by default; to be
  confirmed against the installed version.
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
