import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const checkout = process.env.DSH_CHECKOUT
if (!checkout) throw new Error('DSH_CHECKOUT must point to a built DeepSeek Harness checkout.')
const pluginEntry = process.env.PLUGIN_ENTRY
const plugin = pluginEntry ? await import(pathToFileURL(resolve(pluginEntry)).href) : await import('../index.js')
const importBuilt = async (relativePath) => import(pathToFileURL(resolve(checkout, relativePath)).href)
const { Context } = await importBuilt('vendor/cordis/lib/index.js')
const { default: SystemPrompt } = await importBuilt('packages/core/system-prompt/lib/index.js')
const { default: ToolRuntime } = await importBuilt('packages/core/tools/lib/index.js')
const sha = (value) => createHash('sha256').update(value).digest('hex')

const root = await mkdtemp(join(tmpdir(), 'dsh-policy-drift-runtime-')); await mkdir(join(root, 'snapshots'))
const controls = { approval: { mode: 'always' }, tools: { allow: ['read'] } }
const baseline = `${JSON.stringify({ schemaVersion: 1, policyId: 'runtime-policy', revision: 'baseline-1', controls }, null, 2)}\n`
const observed = `${JSON.stringify({ schemaVersion: 1, policyId: 'runtime-policy', revision: 'observed-1', controls }, null, 2)}\n`
await writeFile(join(root, 'snapshots/baseline.json'), baseline); await writeFile(join(root, 'snapshots/observed.json'), observed)
await writeFile(join(root, 'manifest.json'), `${JSON.stringify({ schemaVersion: 1, policyId: 'runtime-policy', baseline: { path: 'snapshots/baseline.json', sha256: sha(baseline), revision: 'baseline-1' }, observed: { path: 'snapshots/observed.json', sha256: sha(observed), revision: 'observed-1' }, coverageRoots: ['/controls'], rules: [{ id: 'approval-not-weaker', path: '/controls/approval/mode', kind: 'ordered-not-weaker', severity: 'critical', order: ['always', 'on-request', 'never'] }, { id: 'tools-no-additions', path: '/controls/tools/allow', kind: 'set-no-additions', severity: 'high' }] }, null, 2)}\n`)

const ctx = new Context()
try {
  await ctx.plugin(SystemPrompt); await ctx.plugin(ToolRuntime); await ctx.plugin(plugin, { workspaceRoot: root })
  const tools = ctx.get('tools'); const schemas = tools.schemas(); const names = schemas.filter(({ name }) => name.startsWith('dsh_policy_drift_')).map(({ name }) => name)
  assert.deepEqual(names, ['dsh_policy_drift_inspect', 'dsh_policy_drift_verify'])
  const result = await tools.execute({ signal: new AbortController().signal, callId: 'policy-drift-verify-smoke', name: 'dsh_policy_drift_verify', arguments: { manifestPath: 'manifest.json', artifactDir: 'artifacts' } })
  assert.equal(result.isError, false); assert.equal(result.value.status, 'verified'); assert.equal(result.value.returnsPolicyValues, false)
  process.stdout.write(`${JSON.stringify({ ok: true, dshTools: names, status: result.value.status, reportSha256: result.value.artifact.sha256 })}\n`)
} finally { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }) }
