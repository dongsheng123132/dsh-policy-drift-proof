import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { readFile } from 'node:fs/promises'

const manifestJson = await readFile(new URL('../examples/basic/policy-drift.manifest.json', import.meta.url), 'utf8')
const baselineSnapshotJson = await readFile(new URL('../examples/basic/snapshots/baseline.json', import.meta.url), 'utf8')
const observedSnapshotJson = await readFile(new URL('../examples/basic/snapshots/observed.json', import.meta.url), 'utf8')
const child = spawn(process.execPath, ['mcp-server.mjs'], { cwd: new URL('../', import.meta.url), shell: false, stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot } })
let buffer = ''; const responses = []
child.stdout.setEncoding('utf8'); child.stdout.on('data', (chunk) => { buffer += chunk; let index; while ((index = buffer.indexOf('\n')) >= 0) { const line = buffer.slice(0, index); buffer = buffer.slice(index + 1); if (line) responses.push(JSON.parse(line)) } })
const send = (id, method, params = {}) => child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
send(1, 'initialize', { protocolVersion: '2025-06-18' }); send(2, 'tools/list'); send(3, 'tools/call', { name: 'policy_drift_inspect', arguments: { manifestJson } }); send(4, 'tools/call', { name: 'policy_drift_verify', arguments: { manifestJson, baselineSnapshotJson, observedSnapshotJson } })
const secret = JSON.parse(observedSnapshotJson); secret.controls.apiToken = 'must-not-echo'; send(5, 'tools/call', { name: 'policy_drift_verify', arguments: { manifestJson, baselineSnapshotJson, observedSnapshotJson: JSON.stringify(secret) } })
const deadline = Date.now() + 5000; while (responses.length < 5 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20)); child.stdin.end(); if (!child.killed) child.kill()
assert.equal(responses.length, 5); assert.equal(responses[0].result.serverInfo.version, '0.2.0'); assert.deepEqual(responses[1].result.tools.map(({ name }) => name), ['policy_drift_inspect', 'policy_drift_verify']); assert.equal(responses[2].result.structuredContent.filesystemAccess, false); assert.equal(responses[3].result.structuredContent.returnsPolicyValues, false); assert.equal(responses[4].error.data.code, 'FORBIDDEN_FIELD'); assert.ok(!JSON.stringify(responses[4]).includes('must-not-echo'))
process.stdout.write(`${JSON.stringify({ ok: true, protocol: '2025-06-18', tools: 2, proofOnly: true, secretFieldRejected: true })}\n`)
