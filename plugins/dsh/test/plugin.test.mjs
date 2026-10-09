// Run: node plugins/dsh/test/plugin.test.mjs
import assert from 'node:assert/strict'
import { readFileSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const plugin = await import('../index.js')
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

effects.forEach(dispose => dispose())
assert.equal(service.resolve, originalResolve, 'dispose restores the service')
rmSync(log, { force: true })
console.log('plugin: all checks passed')
