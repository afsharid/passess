// Run: node internal/apps/dsh/test/plugin.test.mjs (make dsh-check)
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const plugin = await import('../index.mjs')
const state = mkdtempSync(join(tmpdir(), 'passess-dsh-'))
process.env.XDG_STATE_HOME = state
const statusFile = join(state, 'passess', 'dsh-plugin.json')
const log = join(here, 'calls.log') // fake-passess appends here
rmSync(log, { force: true })

const warnings = []
const effects = []
const service = {
  local: { LOCAL: 'local-value' },
  async resolve(ref) { return this.local[ref] ? { value: this.local[ref], source: 'file' } : undefined },
  async describe(ref) { return this.local[ref] ? { configured: true, source: 'file', writable: true } : { configured: false, writable: true } },
}
const originalResolve = service.resolve
const ctx = {
  credentials: service,
  logger: { warn: (...a) => warnings.push(a.join(' ')) },
  effect: f => effects.push(f()),
}
plugin.apply(ctx, { passess: join(here, 'fake-passess') })

assert.deepEqual(await service.resolve('LOCAL'), { value: 'local-value', source: 'file' })
assert.deepEqual(await service.resolve('CONNECTED'), { value: 'fake-value-123', source: 'env' })
assert.equal(await service.resolve('EVERY'), undefined, 'no clients list is not connected by name')
assert.equal(await service.resolve('BROKEN'), undefined, 'a refusal reads as absent')
assert.equal(await service.resolve('UNKNOWN'), undefined)
assert.deepEqual(await service.describe('CONNECTED'), { configured: true, source: 'env', writable: false })
assert.deepEqual(await service.describe('EVERY'), { configured: false, writable: true })

// Cached: a second round asks passess nothing.
const before = readFileSync(log, 'utf8')
await Promise.all([service.resolve('CONNECTED'), service.resolve('CONNECTED'), service.resolve('BROKEN')])
assert.equal(readFileSync(log, 'utf8'), before)
assert.deepEqual(before.trim().split('\n'), ['list --json', 'helper CONNECTED', 'helper BROKEN'])

assert.ok(warnings.some(w => w.includes('not connected')), 'the refusal is logged')
assert.ok(!warnings.some(w => w.includes('fake-value-123')), 'a value is never logged')

const reported = JSON.parse(readFileSync(statusFile, 'utf8'))
assert.equal(reported.pid, process.pid, 'the status file names the running process')

await Promise.all(effects.map(dispose => dispose()))
assert.equal(service.resolve, originalResolve, 'dispose restores the service')
assert.ok(!existsSync(statusFile), 'dispose removes the status file')

// A reloaded plugin writes its own file first: the old one's dispose keeps it.
const second = { ...ctx, credentials: { ...service }, effect: f => effects2.push(f()) }
const effects2 = []
plugin.apply(second, { passess: join(here, 'fake-passess') })
await new Promise(r => setTimeout(r, 50))
writeFileSync(statusFile, '{"pid": 1, "since": "another instance"}\n')
await Promise.all(effects2.map(dispose => dispose()))
assert.ok(existsSync(statusFile), "dispose keeps another instance's status file")

// The heartbeat: while loaded the plugin rewrites its file, so it stays fresh.
rmSync(statusFile, { force: true })
const effects3 = []
plugin.apply({ ...ctx, credentials: { ...service }, effect: f => effects3.push(f()) }, { passess: join(here, 'fake-passess'), beatSeconds: 0.05 })
await new Promise(r => setTimeout(r, 30))
const first = statSync(statusFile).mtimeMs
await new Promise(r => setTimeout(r, 200))
assert.ok(statSync(statusFile).mtimeMs > first, 'the heartbeat rewrites the status file')
await Promise.all(effects3.map(dispose => dispose()))
assert.ok(!existsSync(statusFile), 'dispose stops the heartbeat and removes its file')
rmSync(log, { force: true })
rmSync(state, { recursive: true, force: true })
console.log('plugin: all checks passed')
