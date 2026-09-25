# 1. Go, one static binary

Status: accepted, 2026-09-25

## Context

passess runs as a hook on every tool call in several harnesses, wraps every MCP server,
and has to install cleanly for individual developers on macOS and Linux. Startup time is
paid on each hook invocation; a runtime dependency is paid on each install.

## Decision

Write passess in Go and ship a single binary built with `CGO_ENABLED=0`. Backends are
reached through their own CLIs (`op`, `bws`, `bw`, `security`) or plain HTTP (Vault /
OpenBao) so users keep their existing authentication, including 1Password's desktop
biometric unlock.

## Consequences

- Hook startup stays in the low milliseconds; the budget is < 10 ms p50 and is measured,
  not assumed.
- Every package linked into the binary runs its `init` on every invocation, so heavy
  dependencies must be justified against that budget.
- Features that need Apple frameworks (Keychain ACLs bound to the passess binary, Touch
  ID approvals) will need cgo on darwin later; that is a separate decision.
