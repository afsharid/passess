# 5. Do not link gitleaks into the passess binary

Status: accepted, 2026-09-25

## Context

Hooks run on every tool call, so the hook path has a budget of < 10 ms p50 (ADR 1).
Secret-shaped detection (paste guard, scanning) wants gitleaks' rule set. Measured on an
M-series Mac mini, macOS 27, Go 1.27.1, `CGO_ENABLED=0`, hyperfine 300 runs, 30 warm-up:

| Binary | Size | p50 | p95 |
|---|---|---|---|
| passess skeleton, `version` | 1.6 MB | 2.8 ms | 4.3 ms |
| same with `gitleaks/v8/detect` linked, not used | 8.9 MB | 6.2 ms | 8.3 ms |
| same, `NewDetectorDefaultConfig()` + one `DetectString` | 8.9 MB | 19.8 ms | 32.9 ms |

Linking alone costs every command 3.4 ms of package initialization and 7.3 MB of
binary, and pulls in viper, cobra, archive readers and a WebAssembly regex engine — a
large supply-chain surface for a tool that handles secrets. Building the default
detector per call is twice the hook budget.

## Decision

- The passess binary does not import gitleaks.
- Detection rules come from gitleaks' default rule set (MIT), vendored as data with its
  license notice, compiled with Go's `regexp` behind a keyword prefilter: one
  alternation of every rule's keywords, run on the lowercased line. A rule's own
  regular expression is compiled only when one of its keywords appears in the input,
  so the hook path pays for the rules it actually needs.
- Known-value matching — the redactor with the user's actual secret values — stays the
  primary detector. Rules are the net for values passess does not know.

## Consequences

- Measured with slice 5 on the same machine (`-s -w`, hyperfine, 300 runs, the payloads
  in `internal/cli/testdata/hooks`): `passess hook claude PreToolUse` on a shell command
  is p50 4.0 ms, p95 4.7 ms. `UserPromptSubmit`, which loads the rules and checks the
  prompt, is p50 5.0 ms, p95 5.5 ms. Both are inside the 10 ms budget, so the bridge of
  ADR 6 stays in the one binary.
- Vendored rules must be refreshed from upstream deliberately; a test pins the rule count
  and file hash so updates are visible in review.
