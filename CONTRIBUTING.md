# Contributing

Thanks for helping. A few rules keep a secrets tool trustworthy.

## Setup

```sh
make hooks   # gitleaks pre-commit hook; it refuses commits when gitleaks is missing
make check   # go vet, race tests, golangci-lint
```

## Rules

- **No real secret, anywhere.** Test values carry the marker `passess-fake`
  (for example `passess-fake-token-0123456789`); `.gitleaks.toml` exempts only lines
  with that marker. If a test needs a token-shaped string without the marker, build
  it by concatenation so scanners do not see it in the source.
- **A value never reaches argv, a log, an error or a file.** Hold values in
  `secret.Value`; its formatting methods print `[REDACTED]`. Errors name the
  reference, never the value.
- **Measure what runs in hooks.** Hook commands run on every tool call in a
  harness; keep them under 10 ms p50 and show the numbers when that changes.
- Small commits with messages that say why. Architecture decisions go in
  `docs/adr/`.
