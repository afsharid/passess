# 2. References, not a vault

Status: accepted, 2026-09-25

## Context

Developers already keep secrets in a password manager. Tools that introduce their own
encrypted store ask users to copy secrets into yet another place, which multiplies
copies and rotation work.

## Decision

passess never stores a secret value. Configuration holds references — `op://vault/item/field`,
`bws://<uuid>` or `bws://<project>/<KEY>`, `bw://<item>/<field>`,
`vault://<mount>/<path>#<key>`, `keychain://<service>/<account>`, `env://NAME` — and a
secret may list several candidates, the first one that resolves wins. Values are resolved
at the moment a consumer starts, held in memory only, and handed to that consumer alone.

## Consequences

- Rotation happens in the user's password manager; nothing in passess goes stale.
- Resolution depends on the backend being reachable and unlocked; failures name the
  reference, never a value.
- The only credential passess must hold is the bootstrap credential for a backend, and
  that lives in the OS keychain, itself addressed by a reference.
