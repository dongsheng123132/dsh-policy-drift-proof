import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import path from 'node:path'

const child = spawn(process.execPath, ['mcp-server.mjs'], { cwd: new URL('../', import.meta.url), shell: false, stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot } })
let buffer = ''; const responses = []
child.stdout.setEncoding('utf8'); child.stdout.on('data', (chunk) => { buffer += chunk; let index; while ((index = buffer.indexOf('\n')) >= 0) { const line = buffer.slice(0, index); buffer = buffer.slice(index + 1); if (line) responses.push(JSON.parse(line)) } })
child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } })}\n`)
child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })}\n`)
child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'policy_drift_inspect', arguments: { workspaceRoot: path.resolve('examples/basic'), manifestPath: 'policy-drift.manifest.json' } } })}\n`)
const deadline = Date.now() + 5000; while (responses.length < 3 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20))
child.stdin.end(); if (!child.killed) child.kill()
assert.equal(responses.length, 3); assert.equal(responses[0].result.serverInfo.name, 'dsh-policy-drift-proof'); assert.deepEqual(responses[1].result.tools.map(({ name }) => name), ['policy_drift_inspect', 'policy_drift_verify']); assert.equal(responses[2].result.structuredContent.returnsPolicyValues, false)
process.stdout.write(`${JSON.stringify({ ok: true, protocol: '2025-06-18', tools: 2, call: 'inspect' })}\n`)
