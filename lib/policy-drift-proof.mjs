import { createHash, randomUUID } from 'node:crypto'
import { link, lstat, mkdir, readFile, realpath, unlink, writeFile } from 'node:fs/promises'
import path from 'node:path'

const MAX_BYTES = 4_194_304
const MAX_NODES = 20_000
const FORBIDDEN_KEYS = /(authorization|api.?key|secret|token|password|credential|cookie|private.?key|raw.?value|stdout|stderr|prompt|message|content)/i
const ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/
const HASH = /^[a-f0-9]{64}$/
const RULE_KINDS = new Set(['exact', 'ordered-not-weaker', 'set-no-additions'])
const sha = (value) => createHash('sha256').update(value).digest('hex')
const stable = (value) => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value
const stableJson = (value) => `${JSON.stringify(stable(value), null, 2)}\n`
const digestValue = (value) => sha(JSON.stringify(stable(value)) ?? '"__undefined__"')

export class PolicyDriftError extends Error {
  constructor(code, message) { super(message); this.name = 'PolicyDriftError'; this.code = code }
}

function requireObject(value, label) { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PolicyDriftError('INVALID_SCHEMA', `${label} must be an object`) }
function validateSafeTree(value, at = '$', counter = { count: 0 }) {
  counter.count += 1
  if (counter.count > MAX_NODES) throw new PolicyDriftError('INPUT_TOO_COMPLEX', `policy tree exceeds ${MAX_NODES} nodes`)
  if (typeof value === 'string' && value.length > 512) throw new PolicyDriftError('VALUE_TOO_LARGE', `string at ${at} exceeds 512 characters`)
  if (Array.isArray(value)) {
    if (value.length > 1000) throw new PolicyDriftError('VALUE_TOO_LARGE', `array at ${at} exceeds 1000 items`)
    value.forEach((child, i) => validateSafeTree(child, `${at}[${i}]`, counter)); return
  }
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.test(key)) throw new PolicyDriftError('FORBIDDEN_FIELD', `secret or raw-output shaped field at ${at}.${key}`)
    validateSafeTree(child, `${at}.${key}`, counter)
  }
}

async function rootDirectory(rootValue) {
  const root = await realpath(rootValue); const info = await lstat(root)
  if (!info.isDirectory() || info.isSymbolicLink()) throw new PolicyDriftError('UNSAFE_PATH', 'workspaceRoot must be a real directory')
  return root
}

async function safeFile(rootValue, relativePath, label, { optional = false } = {}) {
  if (typeof relativePath !== 'string' || !relativePath || path.isAbsolute(relativePath)) throw new PolicyDriftError('UNSAFE_PATH', `${label} must be workspace-relative`)
  const root = await rootDirectory(rootValue); const target = path.resolve(root, relativePath); const rel = path.relative(root, target)
  if (rel.startsWith('..') || path.isAbsolute(rel)) throw new PolicyDriftError('UNSAFE_PATH', `${label} escapes workspaceRoot`)
  let info
  try { info = await lstat(target) } catch (error) { if (optional && error.code === 'ENOENT') return { root, target, missing: true }; throw error }
  if (!info.isFile() || info.isSymbolicLink()) throw new PolicyDriftError('UNSAFE_PATH', `${label} must be a regular non-symlink file`)
  if (info.size > MAX_BYTES) throw new PolicyDriftError('INPUT_TOO_LARGE', `${label} exceeds ${MAX_BYTES} bytes`)
  const resolved = await realpath(target); const resolvedRel = path.relative(root, resolved)
  if (resolvedRel.startsWith('..') || path.isAbsolute(resolvedRel)) throw new PolicyDriftError('UNSAFE_PATH', `${label} resolves outside workspaceRoot`)
  return { root, target: resolved, missing: false }
}

async function artifactDirectory(rootValue, relativePath) {
  if (typeof relativePath !== 'string' || !relativePath || path.isAbsolute(relativePath)) throw new PolicyDriftError('UNSAFE_PATH', 'artifactDir must be workspace-relative')
  const root = await rootDirectory(rootValue); const target = path.resolve(root, relativePath); const rel = path.relative(root, target)
  if (rel.startsWith('..') || path.isAbsolute(rel)) throw new PolicyDriftError('UNSAFE_PATH', 'artifactDir escapes workspaceRoot')
  await mkdir(target, { recursive: true }); const info = await lstat(target)
  if (!info.isDirectory() || info.isSymbolicLink()) throw new PolicyDriftError('UNSAFE_PATH', 'artifactDir must be a real directory')
  const resolved = await realpath(target); const resolvedRel = path.relative(root, resolved)
  if (resolvedRel.startsWith('..') || path.isAbsolute(resolvedRel)) throw new PolicyDriftError('UNSAFE_PATH', 'artifactDir resolves outside workspaceRoot')
  return { root, target: resolved }
}

function validatePointer(pointer, label) {
  if (typeof pointer !== 'string' || !pointer.startsWith('/') || pointer.includes('//') || pointer.endsWith('/')) throw new PolicyDriftError('INVALID_SCHEMA', `${label} must be an RFC 6901-style absolute pointer`)
}
function decodePointer(pointer) { return pointer.slice(1).split('/').map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~')) }
function atPointer(value, pointer) { return decodePointer(pointer).reduce((current, key) => current === undefined ? undefined : current?.[key], value) }
function under(pointer, root) { return pointer === root || pointer.startsWith(`${root}/`) }

function validateManifest(manifest) {
  requireObject(manifest, 'manifest'); validateSafeTree(manifest)
  if (manifest.schemaVersion !== 1 || !ID.test(manifest.policyId)) throw new PolicyDriftError('INVALID_SCHEMA', 'schemaVersion must be 1 and policyId must be a stable id')
  for (const label of ['baseline', 'observed']) {
    const ref = manifest[label]; requireObject(ref, label)
    if (typeof ref.path !== 'string' || !HASH.test(ref.sha256) || typeof ref.revision !== 'string' || !ref.revision) throw new PolicyDriftError('INVALID_SCHEMA', `${label} needs path, sha256 and revision`)
  }
  if (!Array.isArray(manifest.coverageRoots) || !manifest.coverageRoots.length) throw new PolicyDriftError('INVALID_SCHEMA', 'coverageRoots must be non-empty')
  const roots = new Set(); for (const [i, root] of manifest.coverageRoots.entries()) { validatePointer(root, `coverageRoots[${i}]`); if (roots.has(root)) throw new PolicyDriftError('INVALID_SCHEMA', 'coverageRoots must be unique'); roots.add(root) }
  if (!Array.isArray(manifest.rules) || !manifest.rules.length) throw new PolicyDriftError('INVALID_SCHEMA', 'rules must be non-empty')
  const ids = new Set(); const paths = new Set()
  for (const [i, rule] of manifest.rules.entries()) {
    requireObject(rule, `rules[${i}]`); validatePointer(rule.path, `rules[${i}].path`)
    if (!ID.test(rule.id) || ids.has(rule.id) || paths.has(rule.path) || !RULE_KINDS.has(rule.kind) || !['low', 'medium', 'high', 'critical'].includes(rule.severity) || ![...roots].some((root) => under(rule.path, root))) throw new PolicyDriftError('INVALID_SCHEMA', `rules[${i}] is invalid, duplicate or outside coverage`)
    if (rule.kind === 'ordered-not-weaker' && (!Array.isArray(rule.order) || rule.order.length < 2 || new Set(rule.order).size !== rule.order.length || rule.order.some((item) => typeof item !== 'string'))) throw new PolicyDriftError('INVALID_SCHEMA', `${rule.id}.order must list unique strings from restrictive to permissive`)
    ids.add(rule.id); paths.add(rule.path)
  }
  return manifest
}

async function loadManifest(root, manifestPath) {
  const { target } = await safeFile(root, manifestPath, 'manifestPath'); const bytes = await readFile(target)
  let value; try { value = JSON.parse(bytes.toString('utf8')) } catch { throw new PolicyDriftError('INVALID_JSON', 'manifestPath is not valid JSON') }
  return { manifest: validateManifest(value), manifestSha256: sha(bytes) }
}

function parseManifestJson(manifestJson) {
  if (typeof manifestJson !== 'string' || !manifestJson || Buffer.byteLength(manifestJson) > MAX_BYTES) throw new PolicyDriftError('INPUT_TOO_LARGE', `manifestJson must be a non-empty string of at most ${MAX_BYTES} bytes`)
  let value; try { value = JSON.parse(manifestJson) } catch { throw new PolicyDriftError('INVALID_JSON', 'manifestJson is not valid JSON') }
  return { manifest: validateManifest(value), manifestSha256: sha(manifestJson) }
}

async function loadSnapshot(root, reference, label, policyId) {
  const located = await safeFile(root, reference.path, `${label}.path`, { optional: true })
  if (located.missing) return { label, status: 'missing', expectedSha256: reference.sha256, actualSha256: null, revision: reference.revision, value: null }
  const bytes = await readFile(located.target); const actualSha256 = sha(bytes)
  let value; try { value = JSON.parse(bytes.toString('utf8')) } catch { throw new PolicyDriftError('INVALID_JSON', `${label}.path is not valid JSON`) }
  requireObject(value, label); validateSafeTree(value)
  if (value.schemaVersion !== 1 || value.policyId !== policyId || value.revision !== reference.revision) throw new PolicyDriftError('SNAPSHOT_IDENTITY_MISMATCH', `${label} identity or revision does not match manifest`)
  requireObject(value.controls, `${label}.controls`)
  return { label, status: actualSha256 === reference.sha256 ? 'current' : 'stale', expectedSha256: reference.sha256, actualSha256, revision: reference.revision, value }
}

function parseSnapshotJson(snapshotJson, reference, label, policyId) {
  if (typeof snapshotJson !== 'string' || !snapshotJson || Buffer.byteLength(snapshotJson) > MAX_BYTES) throw new PolicyDriftError('INPUT_TOO_LARGE', `${label}SnapshotJson must be a non-empty string of at most ${MAX_BYTES} bytes`)
  const actualSha256 = sha(snapshotJson); let value
  try { value = JSON.parse(snapshotJson) } catch { throw new PolicyDriftError('INVALID_JSON', `${label}SnapshotJson is not valid JSON`) }
  requireObject(value, label); validateSafeTree(value)
  if (value.schemaVersion !== 1 || value.policyId !== policyId || value.revision !== reference.revision) throw new PolicyDriftError('SNAPSHOT_IDENTITY_MISMATCH', `${label} identity or revision does not match manifest`)
  requireObject(value.controls, `${label}.controls`)
  return { label, status: actualSha256 === reference.sha256 ? 'current' : 'stale', expectedSha256: reference.sha256, actualSha256, revision: reference.revision, value }
}

function leafPaths(value, pointer = '') {
  if (!value || typeof value !== 'object') return [pointer || '/']
  if (Array.isArray(value)) return [pointer || '/']
  const keys = Object.keys(value)
  if (!keys.length) return [pointer || '/']
  return keys.flatMap((key) => leafPaths(value[key], `${pointer}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`))
}

function changedLeaves(baseline, observed, roots) {
  const paths = new Set([...leafPaths(baseline), ...leafPaths(observed)])
  return [...paths].filter((pointer) => roots.some((root) => under(pointer, root)) && digestValue(atPointer(baseline, pointer)) !== digestValue(atPointer(observed, pointer))).sort()
}

function evaluateRule(rule, baseline, observed) {
  const before = atPointer(baseline, rule.path); const after = atPointer(observed, rule.path)
  const base = { ruleId: rule.id, path: rule.path, kind: rule.kind, severity: rule.severity, baselineDigest: digestValue(before), observedDigest: digestValue(after) }
  if (base.baselineDigest === base.observedDigest) return { ...base, outcome: 'unchanged', violates: false }
  if (rule.kind === 'exact') return { ...base, outcome: 'changed', violates: true }
  if (rule.kind === 'ordered-not-weaker') {
    const beforeIndex = rule.order.indexOf(before); const afterIndex = rule.order.indexOf(after)
    if (beforeIndex < 0 || afterIndex < 0) return { ...base, outcome: 'unknown-enum', violates: true }
    return { ...base, outcome: afterIndex > beforeIndex ? 'weakened' : 'tightened', violates: afterIndex > beforeIndex }
  }
  if (!Array.isArray(before) || !Array.isArray(after) || before.some((item) => typeof item !== 'string') || after.some((item) => typeof item !== 'string')) return { ...base, outcome: 'invalid-set', violates: true }
  const beforeSet = new Set(before); const afterSet = new Set(after)
  const addedDigests = [...afterSet].filter((item) => !beforeSet.has(item)).map(digestValue).sort()
  const removedDigests = [...beforeSet].filter((item) => !afterSet.has(item)).map(digestValue).sort()
  return { ...base, outcome: addedDigests.length ? 'weakened' : 'tightened', violates: addedDigests.length > 0, addedDigests, removedDigests }
}

function compare(manifest, baseline, observed) {
  const ruleResults = manifest.rules.map((rule) => evaluateRule(rule, baseline, observed))
  const changes = changedLeaves(baseline, observed, manifest.coverageRoots)
  const unclassifiedPaths = changes.filter((pointer) => !manifest.rules.some((rule) => under(pointer, rule.path)))
  const findings = [
    ...ruleResults.filter(({ violates }) => violates).map(({ ruleId, path, outcome, severity }) => ({ code: 'POLICY_DRIFT_VIOLATION', ruleId, path, outcome, severity })),
    ...unclassifiedPaths.map((pointer) => ({ code: 'UNCLASSIFIED_DRIFT', path: pointer, severity: 'high' }))
  ]
  return { driftStatus: changes.length ? 'changed' : 'unchanged', changedLeafCount: changes.length, unclassifiedPaths, ruleResults, findings }
}

async function writeReport(rootValue, artifactDir, report) {
  const { root, target: directory } = await artifactDirectory(rootValue, artifactDir); const body = stableJson(report); const reportSha256 = sha(body)
  const filename = `policy-drift-proof-${reportSha256}.json`; const target = path.join(directory, filename); const temporary = path.join(directory, `.${filename}.${randomUUID()}.tmp`)
  try {
    await writeFile(temporary, body, { encoding: 'utf8', flag: 'wx' })
    try { await link(temporary, target) } catch (error) { if (error.code !== 'EEXIST') throw error }
    const reread = await readFile(target, 'utf8')
    if (reread !== body || sha(reread) !== reportSha256) throw new PolicyDriftError('WRITE_VERIFY_FAILED', 'report read-back verification failed')
    return { path: path.relative(root, target).replaceAll(path.sep, '/'), sha256: reportSha256, bytes: Buffer.byteLength(body), verifiedByReadBack: true }
  } finally { try { await unlink(temporary) } catch {} }
}

export async function inspectPolicyDrift({ workspaceRoot: root = process.cwd(), manifestPath }) {
  const { manifest, manifestSha256 } = await loadManifest(root, manifestPath)
  return { schemaVersion: 1, operation: 'inspect', returnsPolicyValues: false, policyId: manifest.policyId, manifestSha256, snapshots: { baseline: { revision: manifest.baseline.revision, expectedSha256: manifest.baseline.sha256 }, observed: { revision: manifest.observed.revision, expectedSha256: manifest.observed.sha256 } }, coverageRoots: manifest.coverageRoots, rules: manifest.rules.map(({ id, path, kind, severity }) => ({ id, path, kind, severity })) }
}

export async function verifyPolicyDrift({ workspaceRoot: root = process.cwd(), manifestPath, artifactDir }) {
  const { manifest, manifestSha256 } = await loadManifest(root, manifestPath)
  const baseline = await loadSnapshot(root, manifest.baseline, 'baseline', manifest.policyId); const observed = await loadSnapshot(root, manifest.observed, 'observed', manifest.policyId)
  const inputsCurrent = baseline.status === 'current' && observed.status === 'current'
  const comparison = baseline.value && observed.value ? compare(manifest, baseline.value, observed.value) : { driftStatus: 'unknown', changedLeafCount: 0, unclassifiedPaths: [], ruleResults: [], findings: [{ code: 'MISSING_SNAPSHOT', severity: 'critical' }] }
  const report = { schemaVersion: 1, operation: 'verify', returnsPolicyValues: false, policyId: manifest.policyId, inputs: { manifestSha256, baseline: { status: baseline.status, revision: baseline.revision, expectedSha256: baseline.expectedSha256, actualSha256: baseline.actualSha256 }, observed: { status: observed.status, revision: observed.revision, expectedSha256: observed.expectedSha256, actualSha256: observed.actualSha256 } }, status: inputsCurrent && comparison.findings.length === 0 ? 'verified' : 'failed', verdict: inputsCurrent && comparison.findings.length === 0 ? 'pass' : 'fail', disclosure: { staleInputs: [baseline, observed].filter(({ status }) => status === 'stale').map(({ label }) => label), missingInputs: [baseline, observed].filter(({ status }) => status === 'missing').map(({ label }) => label) }, comparison }
  const artifact = await writeReport(root, artifactDir, report)
  return { ...report, artifact }
}

export function inspectPolicyDriftManifestJson(manifestJson) {
  const { manifest, manifestSha256 } = parseManifestJson(manifestJson)
  return { schemaVersion: 1, operation: 'inspect-inline-manifest', proofOnly: true, filesystemAccess: false, executesActions: false, returnsPolicyValues: false, policyId: manifest.policyId, manifestSha256, snapshots: { baseline: { revision: manifest.baseline.revision, expectedSha256: manifest.baseline.sha256 }, observed: { revision: manifest.observed.revision, expectedSha256: manifest.observed.sha256 } }, coverageRoots: manifest.coverageRoots, rules: manifest.rules.map(({ id, path, kind, severity }) => ({ id, path, kind, severity })) }
}

export function verifyPolicyDriftSnapshotsJson(manifestJson, baselineSnapshotJson, observedSnapshotJson) {
  const { manifest, manifestSha256 } = parseManifestJson(manifestJson)
  const baseline = parseSnapshotJson(baselineSnapshotJson, manifest.baseline, 'baseline', manifest.policyId)
  const observed = parseSnapshotJson(observedSnapshotJson, manifest.observed, 'observed', manifest.policyId)
  const comparison = compare(manifest, baseline.value, observed.value)
  const inputsCurrent = baseline.status === 'current' && observed.status === 'current'
  return { schemaVersion: 1, operation: 'verify-inline-snapshots', proofOnly: true, filesystemAccess: false, executesActions: false, returnsPolicyValues: false, policyId: manifest.policyId, inputs: { manifestSha256, baseline: { status: baseline.status, revision: baseline.revision, expectedSha256: baseline.expectedSha256, actualSha256: baseline.actualSha256 }, observed: { status: observed.status, revision: observed.revision, expectedSha256: observed.expectedSha256, actualSha256: observed.actualSha256 } }, status: inputsCurrent && comparison.findings.length === 0 ? 'verified' : 'failed', verdict: inputsCurrent && comparison.findings.length === 0 ? 'pass' : 'fail', disclosure: { staleInputs: [baseline, observed].filter(({ status }) => status === 'stale').map(({ label }) => label), missingInputs: [] }, comparison }
}
