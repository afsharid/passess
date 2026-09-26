// passess plugin for OpenCode, written by `passess install` and removed by
// `passess uninstall`. It asks `passess hook opencode EVENT` before a tool
// runs, after it returns and before a message is sent. It fails open: when
// passess is missing or errs, OpenCode carries on.
import { spawnSync } from "node:child_process"

const PASSESS = "__PASSESS__"

function ask(event, payload) {
  try {
    const r = spawnSync(PASSESS, ["hook", "opencode", event], {
      input: JSON.stringify(payload),
      encoding: "utf8",
      timeout: 10000,
    })
    if (r.status !== 0 || !r.stdout) return {}
    return JSON.parse(r.stdout)
  } catch {
    return {}
  }
}

export const Passess = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    const r = ask("tool.execute.before", { tool: input.tool, args: output.args, cwd: directory })
    if (r.block) throw new Error(r.block)
  },
  "tool.execute.after": async (input, output) => {
    if (typeof output.output !== "string") return
    const r = ask("tool.execute.after", { tool: input.tool, output: output.output, cwd: directory })
    if (typeof r.output === "string") output.output = r.output
  },
  "chat.message": async (_input, output) => {
    const parts = (output.parts || []).filter((p) => p.type === "text")
    const text = parts.map((p) => p.text).join("\n")
    if (!text) return
    const r = ask("chat.message", { text, cwd: directory })
    if (r.block) for (const p of parts) p.text = "[withheld by passess] " + r.block
  },
})
