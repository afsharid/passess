# 6. The official MCP Go SDK carries the remote bridge

Status: accepted, 2026-09-26

## Context

`passess mcp-exec NAME` for a remote server must look like a stdio MCP server to the
harness while speaking streamable HTTP to the real one: session ids, the protocol
version header, server-sent events for both replies and server-initiated messages,
reconnects. Hand-rolling that client is where subtle bugs live. The official SDK
(`github.com/modelcontextprotocol/go-sdk`, v1.8.0) has both halves: `IOTransport` for
newline-delimited JSON over stdio and `StreamableClientTransport` for the remote end,
each exposing a `Connection` that reads and writes JSON-RPC messages.

Linking it has a cost, measured the same way as ADR 5 (Mac mini, macOS 27, Go 1.27.1,
`CGO_ENABLED=0 -s -w`, hyperfine, both binaries in one run to share system load):

| Binary | Size | `version` p50 | p95 |
|---|---|---|---|
| without the SDK | 3.6 MB | 4.3 ms | 8.6 ms |
| with the SDK | 8.8 MB | 6.5 ms | 11.1 ms |

## Decision

Use the SDK for the bridge: relay messages between an `IOTransport` connection (the
harness) and a `StreamableClientTransport` connection whose HTTP client adds the
configured headers, with the harness side writing through the redactor. passess does
not interpret MCP; the upstream server handles initialization and everything else.

## Consequences

- Every command pays about 2 ms more at startup. That is inside the 10 ms hook budget
  but halves the headroom; slice 5 measures the hook path again, and if it no longer
  fits, the bridge moves into a separate binary that `mcp-exec` executes.
- Remote servers get correct session handling and server-initiated messages without
  passess code for them.
