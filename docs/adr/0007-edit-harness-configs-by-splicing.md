# 7. Edit harness configs by splicing bytes, never by re-encoding

Status: accepted, 2026-09-26

## Context

Slice 2 left file formats to the harnesses: passess registers servers through
`claude mcp` and `codex mcp`. Most harnesses offer nothing that works unattended.
OpenCode's `mcp add` is an interactive wizard with no `remove`. `kiro-cli mcp add`
refuses to run without a signed-in account, even for a local file (measured on 2.21.4).
Cursor, Windsurf, Zed, VS Code (for removal) and Claude Desktop have no such command. So
passess has to write their JSON or JSONC files itself, and those files are the user's:
hand-edited, commented, often kept in a dotfiles repository and linked into place.

Measured with `github.com/tailscale/hujson`:

- Re-encoding through `encoding/json` drops every comment and reorders keys.
- hujson's `Patch` inserts compact JSON glued to the previous member's line.
- `Format` keeps comments but re-indents the whole file with tabs and aligns every
  value. That makes a diff the size of the file.

## Decision

- `internal/jsonedit` parses with hujson only to learn byte offsets, then splices text.
  - A new member goes on its own line, indented like its siblings.
  - Commas follow the file's own style: trailing commas stay trailing, strict JSON stays
    strict.
  - A replaced member keeps its place.
  - A deleted member takes its line and comma with it, but not the comments around it.
- Adding a member and then deleting it gives back the original bytes. `uninstall`
  relies on this, and every adapter test asserts it.
- A symlinked config is edited where it points (`EvalSymlinks`), so the link survives.
- passess never creates a harness's directory. It creates a missing config only at a
  path the harness documents, and edits only an existing file where the path is
  inferred.
- After writing, the adapter reads the file back. If the harness would not see the
  change, the old bytes are restored.
- Where a harness CLI works unattended (Claude Code, Codex, Antigravity's `agy mcp`),
  passess still uses it.

## Consequences

- One small editor serves every JSON harness; adding one is a spec: where the file is,
  the path to its servers, the entry shape.
- The editor is fuzzed: any document that parses must survive Set then Delete with its
  content intact.
- One case is not byte-identical: when passess had to create the servers object, it
  leaves an empty one behind after uninstall.
