// DeepSeek Harness plugin: the keys connected to DSH in passess, however DSH
// is opened (ADR 11).
//
// It wraps the credentials service DSH already runs. A reference the service
// resolves (the launch environment, ~/.dsh/.credentials.yaml, .env files)
// keeps its value; one it does not, and that passess connects to "dsh" by
// name, is asked of `passess helper NAME`, run without a shell so passess sees
// DSH itself as its parent. Values stay in memory for ttlSeconds and are never
// logged or written.

import { execFile } from 'node:child_process'
import { access, constants } from 'node:fs/promises'

export const name = 'passess-credentials'
export const inject = ['credentials']

const AGENT_ID = 'dsh'
// Opened from the Dock, DSH has a minimal PATH; look where passess installs.
const SEARCH = ['/opt/homebrew/bin', '/usr/local/bin', `${process.env.HOME}/.local/bin`, `${process.env.HOME}/go/bin`]

export function apply(ctx, config = {}) {
  const ttl = (config.ttlSeconds ?? 300) * 1000
  const listTtl = (config.listSeconds ?? 30) * 1000
  const creds = ctx.credentials
  const { resolve, describe } = creds
  const values = new Map() // ref → { value, until } | { failed: true, until }
  const pending = new Map() // ref → Promise
  let connected = { names: new Set(), until: 0 }
  let binary

  const run = async (args, timeout) => {
    binary ??= config.passess ?? (await find())
    return new Promise((done, fail) => {
      execFile(binary, args, { timeout, maxBuffer: 1 << 20, windowsHide: true }, (error, stdout, stderr) => {
        if (error) {
          const why = String(stderr).trim().split('\n')[0] || error.message
          fail(new Error(`passess ${args[0]} ${args[1] ?? ''}: ${why}`))
        } else done(String(stdout))
      })
    })
  }

  // The names passess connects to DSH by name; a secret with no clients list
  // is every agent's, which passess helper does not count for an app.
  const connectedNames = async () => {
    if (Date.now() < connected.until) return connected.names
    try {
      const list = JSON.parse(await run(['list', '--json'], 15_000))
      const names = new Set(
        (list.secrets ?? []).filter(s => Array.isArray(s.clients) && s.clients.includes(AGENT_ID)).map(s => s.name),
      )
      connected = { names, until: Date.now() + listTtl }
    } catch (error) {
      ctx.logger.warn('passess-credentials: %s', error.message)
      connected = { names: new Set(), until: Date.now() + listTtl }
    }
    return connected.names
  }

  const fromPassess = async ref => {
    const hit = values.get(ref)
    if (hit && Date.now() < hit.until) return hit.failed ? undefined : hit.value
    if (!(await connectedNames()).has(ref)) return undefined
    if (!pending.has(ref)) {
      pending.set(ref, (async () => {
        try {
          // A secret marked approve waits for the user's Touch ID.
          const value = (await run(['helper', ref], 120_000)).replace(/\n$/, '')
          values.set(ref, value ? { value, until: Date.now() + ttl } : { failed: true, until: Date.now() + listTtl })
        } catch (error) {
          ctx.logger.warn('passess-credentials: %s', error.message)
          values.set(ref, { failed: true, until: Date.now() + listTtl })
        } finally {
          pending.delete(ref)
        }
      })())
    }
    await pending.get(ref)
    const got = values.get(ref)
    return got && !got.failed ? got.value : undefined
  }

  creds.resolve = async function (ref) {
    const own = await resolve.call(this, ref)
    if (own !== undefined) return own
    const value = await fromPassess(ref)
    return value === undefined ? undefined : { value, source: 'env' }
  }

  // Configured without fetching the value: settings pages call this often.
  creds.describe = async function (ref) {
    const own = await describe.call(this, ref)
    if (own.configured) return own
    return (await connectedNames()).has(ref) ? { configured: true, source: 'env', writable: false } : own
  }

  ctx.effect(() => () => {
    creds.resolve = resolve
    creds.describe = describe
    values.clear()
  })
}

async function find() {
  for (const dir of SEARCH) {
    const candidate = `${dir}/passess`
    try {
      await access(candidate, constants.X_OK)
      return candidate
    } catch {}
  }
  return 'passess'
}
