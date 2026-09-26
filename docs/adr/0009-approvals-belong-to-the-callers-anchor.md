# 9. Approvals belong to the caller's anchor process

Status: accepted, 2026-09-26

## Context

ADR 8 keys an approval on (secret, program family, harness). The harness is known only
from markers in the caller's environment (`CLAUDECODE=1`), and any process can set
those. An Allow given to Claude Code would then be one `CLAUDECODE=1` away for anything
else. `internal/detect` already has a rule: a marker may add protection or label a
record, never grant anything.

Other identities fall short too:

- Session ids: Claude Code starts every command in a new session (measured on
  2.1.281: the command's shell is its own session leader), so a session-keyed Allow
  would ask again on every command.
- Terminals: a harness's commands have no terminal.
- The client's executable: it is passess itself.

## Decision

An approval is keyed on (secret, program family, **anchor**).

- The anchor is the nearest ancestor of the caller that is neither passess nor a shell,
  identified by pid **and start time**, so a reused pid does not inherit it.
  - It is read from the kernel: `sysctl kern.proc.pid` on macOS, `/proc/PID/stat` on
    Linux.
  - A process cannot choose its ancestors. Detaching from the harness, or putting a
    forking wrapper in between (`/usr/bin/time`, a Python script), gives a new anchor:
    more questions, never fewer.
- A chain that ends without such a process (an orphaned shell) has no anchor. Its
  answer counts for that command only.
- The program family is the agent's own finding, from the caller's `PATH`, as for exec.
  It is never the caller's word, including for the `ask` requests of the in-process
  paths.
- An Allow lasts `agent.approval_ttl` (8 h) while the anchor lives. `lock` and `stop`
  forget every Allow.
- No approver connected, a denial, or no answer within `agent.approval_timeout` (60 s)
  is a refusal that names the anchor.
- Callers that need the same Allow share one question.
- An Allow that arrives after its caller gave up still counts, for the retry: harnesses
  time commands out, and a question should not be asked twice.
- The in-process paths (exec at a terminal, `run`, `mcp-exec`) ask the agent a yes/no
  question with no value either way. Without an agent, the answer is no.
- Approvers:
  - Passess.app, next.
  - `passess agent approve` on the user's own terminal. It refuses inside a harness and
    without a terminal.
  - Any other process that connects as one. The agent refuses approvers whose own
    anchor is a harness executable (`detect.Program`).

Anchors measured on the maintainer's Mac, 2026-09-26, with a dev agent and no approver,
reading the name from the refusal:

| Harness | Anchor |
|---|---|
| Claude Code | `claude` |
| Kiro CLI | `kiro-cli-chat` |
| Antigravity CLI | `agy` |

None puts a per-command process between itself and the shell, so one Allow covers a
session. Codex and OpenCode are unmeasured: in that run neither CLI reached a model.

## Consequences

- An Allow means "this program family may have this secret while this harness process
  lives", which is what the question on screen says.
- An editor's integrated terminal anchors at the editor, and so does an agent that runs
  commands in it. There, the user and the agent share Allows.
- Approvals stop an agent that uses passess as it was taught. They do not stop one
  that attacks passess (T6):
  - it can connect to the socket as an approver after detaching from the harness;
  - it can run a command in-process after `passess agent stop`.
  PR 3's hooks refuse `passess agent approve` and `stop`, direct use of the socket, and
  `PASSESS_CONFIG=` or `PASSESS_AGENT_SOCK=` in agent commands.
- The agent appends every question's outcome to `agent-audit.jsonl`: names, programs,
  anchors and outcomes, never a value.
