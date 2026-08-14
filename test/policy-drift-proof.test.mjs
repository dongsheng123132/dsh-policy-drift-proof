import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { inspectPolicyDrift, verifyPolicyDrift } from '../lib/policy-drift-proof.mjs'

const sha = (value) => createHash('sha256').update(value).digest('hex')
const baseControls = { approval: { mode: 'always' }, sandbox: { mode: 'read-only' }, tools: { allow: ['read', 'search'] }, plugins: { core: 'a'.repeat(64) } }
const rules = [
  { id: 'approval-not-weaker', path: '/controls/approval/mode', kind: 'ordered-not-weaker', severity: 'critical', order: ['always', 'on-request', 'never'] },
  { id: 'sandbox-not-weaker', path: '/controls/sandbox/mode', kind: 'ordered-not-weaker', severity: 'critical', order: ['read-only', 'workspace-write', 'unrestricted'] },
  { id: 'tool-allow-no-additions', path: '/controls/tools/allow', kind: 'set-no-additions', severity: 'high' },
  { id: 'plugin-pin-exact', path: '/controls/plugins', kind: 'exact', severity: 'high' }
]

async function fixture({ baselineControls = baseControls, observedControls = structuredClone(baseControls), customRules = rules, coverageRoots = ['/controls'], observedHash, omitObserved = false } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'dsh-policy-drift-proof-')); await mkdir(path.join(root, 'snapshots'))
  const baseline = `${JSON.stringify({ schemaVersion: 1, policyId: 'prod-policy', revision: 'baseline-1', controls: baselineControls }, null, 2)}\n`
  const observed = `${JSON.stringify({ schemaVersion: 1, policyId: 'prod-policy', revision: 'observed-1', controls: observedControls }, null, 2)}\n`
  await writeFile(path.join(root, 'snapshots/baseline.json'), baseline); if (!omitObserved) await writeFile(path.join(root, 'snapshots/observed.json'), observed)
  const manifest = { schemaVersion: 1, policyId: 'prod-policy', baseline: { path: 'snapshots/baseline.json', sha256: sha(baseline), revision: 'baseline-1' }, observed: { path: 'snapshots/observed.json', sha256: observedHash ?? sha(observed), revision: 'observed-1' }, coverageRoots, rules: customRules }
  await writeFile(path.join(root, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)
  return root
}

test('inspect exposes pins and rules but no policy values', async (t) => {
  const root = await fixture(); t.after(() => rm(root, { recursive: true, force: true }))
  const result = await inspectPolicyDrift({ workspaceRoot: root, manifestPath: 'manifest.json' }); const rendered = JSON.stringify(result)
  assert.equal(result.returnsPolicyValues, false); assert.equal(result.rules.length, 4); assert.ok(!rendered.includes('read-only')); assert.ok(!rendered.includes('always'))
})

test('unchanged pinned snapshots produce a content-addressed verified report', async (t) => {
  const root = await fixture(); t.after(() => rm(root, { recursive: true, force: true }))
  const result = await verifyPolicyDrift({ workspaceRoot: root, manifestPath: 'manifest.json', artifactDir: 'artifacts' })
  assert.equal(result.status, 'verified'); assert.equal(result.comparison.driftStatus, 'unchanged'); assert.ok(result.artifact.path.includes(result.artifact.sha256))
  assert.equal(sha(await readFile(path.join(root, result.artifact.path))), result.artifact.sha256)
})

test('ordered permission weakening fails without returning values', async (t) => {
  const observed = structuredClone(baseControls); observed.approval.mode = 'never'; const root = await fixture({ observedControls: observed }); t.after(() => rm(root, { recursive: true, force: true }))
  const result = await verifyPolicyDrift({ workspaceRoot: root, manifestPath: 'manifest.json', artifactDir: 'artifacts' }); const rendered = JSON.stringify(result)
  assert.equal(result.status, 'failed'); assert.equal(result.comparison.ruleResults.find(({ ruleId }) => ruleId === 'approval-not-weaker').outcome, 'weakened'); assert.ok(!rendered.includes('"never"')); assert.ok(!rendered.includes('"always"'))
})

test('allowlist additions fail and expose only item digests', async (t) => {
  const observed = structuredClone(baseControls); observed.tools.allow.push('shell'); const root = await fixture({ observedControls: observed }); t.after(() => rm(root, { recursive: true, force: true }))
  const result = await verifyPolicyDrift({ workspaceRoot: root, manifestPath: 'manifest.json', artifactDir: 'artifacts' }); const rule = result.comparison.ruleResults.find(({ ruleId }) => ruleId === 'tool-allow-no-additions')
  assert.equal(rule.outcome, 'weakened'); assert.equal(rule.addedDigests.length, 1); assert.ok(!JSON.stringify(result).includes('shell'))
})

test('tightening is observable drift but passes', async (t) => {
  const observed = structuredClone(baseControls); observed.tools.allow = ['read']; const root = await fixture({ observedControls: observed }); t.after(() => rm(root, { recursive: true, force: true }))
  const result = await verifyPolicyDrift({ workspaceRoot: root, manifestPath: 'manifest.json', artifactDir: 'artifacts' })
  assert.equal(result.status, 'verified'); assert.equal(result.comparison.driftStatus, 'changed'); assert.equal(result.comparison.ruleResults.find(({ ruleId }) => ruleId === 'tool-allow-no-additions').outcome, 'tightened')
})

test('unclassified covered drift fails closed', async (t) => {
  const observed = structuredClone(baseControls); observed.network = { mode: 'open' }; const root = await fixture({ observedControls: observed }); t.after(() => rm(root, { recursive: true, force: true }))
  const result = await verifyPolicyDrift({ workspaceRoot: root, manifestPath: 'manifest.json', artifactDir: 'artifacts' })
  assert.equal(result.status, 'failed'); assert.ok(result.comparison.unclassifiedPaths.includes('/controls/network/mode'))
})

test('stale and missing observed snapshots are disclosed', async (t) => {
  const staleRoot = await fixture({ observedHash: 'f'.repeat(64) }); t.after(() => rm(staleRoot, { recursive: true, force: true }))
  const stale = await verifyPolicyDrift({ workspaceRoot: staleRoot, manifestPath: 'manifest.json', artifactDir: 'artifacts' }); assert.deepEqual(stale.disclosure.staleInputs, ['observed']); assert.equal(stale.status, 'failed')
  const missingRoot = await fixture({ omitObserved: true }); t.after(() => rm(missingRoot, { recursive: true, force: true }))
  const missing = await verifyPolicyDrift({ workspaceRoot: missingRoot, manifestPath: 'manifest.json', artifactDir: 'artifacts' }); assert.deepEqual(missing.disclosure.missingInputs, ['observed']); assert.equal(missing.status, 'failed')
})

test('secret-shaped fields and path traversal are rejected', async (t) => {
  const secret = structuredClone(baseControls); secret.network = { apiKey: 'do-not-read' }; const root = await fixture({ observedControls: secret }); t.after(() => rm(root, { recursive: true, force: true }))
  await assert.rejects(() => verifyPolicyDrift({ workspaceRoot: root, manifestPath: 'manifest.json', artifactDir: 'artifacts' }), { code: 'FORBIDDEN_FIELD' })
  await assert.rejects(() => inspectPolicyDrift({ workspaceRoot: root, manifestPath: '../manifest.json' }), { code: 'UNSAFE_PATH' })
})

test('symlink snapshot is rejected when the platform permits creating it', async (t) => {
  const root = await fixture(); t.after(() => rm(root, { recursive: true, force: true })); await rm(path.join(root, 'snapshots/observed.json'))
  try { await symlink(path.join(root, 'snapshots/baseline.json'), path.join(root, 'snapshots/observed.json'), 'file') } catch (error) { if (['EPERM', 'EACCES'].includes(error.code)) return t.skip('symlink creation unavailable'); throw error }
  await assert.rejects(() => verifyPolicyDrift({ workspaceRoot: root, manifestPath: 'manifest.json', artifactDir: 'artifacts' }), { code: 'UNSAFE_PATH' })
})
