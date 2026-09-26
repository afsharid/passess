# Security policy

passess handles other people's secrets, so security reports get priority over
everything else in this project.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on
this repository (private vulnerability reporting). Do not open a public issue for
anything that could expose a secret or let one be exfiltrated.

Include what you ran, what you expected, what happened, and the passess version
(`passess version`). Never include a real secret in a report; the test suites use
values carrying the marker `passess-fake`, and so can you.

You will get an acknowledgement within a few days. Fixes for confirmed issues are
released as soon as they are ready, with credit unless you ask otherwise.

## Scope

In scope: anything that makes a secret value reach a place passess promises to keep
it out of — the output of `exec`, `run` or `mcp-exec`, error messages, logs, argv,
files written by passess — or that lets a policy be bypassed (a shell or interpreter
receiving a secret it was not allowed, a project file widening user policy).

Out of scope, by design (see [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)): a
deliberately malicious process running as the same OS user without a sandbox, and
values transformed in ways redaction cannot recognize (split, reversed, hashed).
Reports that show these limits matter more than we claim are still welcome.

## Supported versions

passess is pre-alpha. Only the latest commit on `main` receives fixes.
