#!/usr/bin/env node
import readline from 'node:readline'
import { inspectPolicyDrift, verifyPolicyDrift } from './lib/policy-drift-proof.mjs'

const tools = [
  { name: 'policy_drift_inspect', description: 'Inspect pinned policy snapshot evidence without policy values.', inputSchema: { type: 'object', required: ['workspaceRoot', 'manifestPath'], properties: { workspaceRoot: { type: 'string' }, manifestPath: { type: 'string' } }, additionalProperties: false } },
  { name: 'policy_drift_verify', description: 'Verify value-redacted DSH policy drift and write a content-addressed report.', inputSchema: { type: 'object', required: ['workspaceRoot', 'manifestPath', 'artifactDir'], properties: { workspaceRoot: { type: 'string' }, manifestPath: { type: 'string' }, artifactDir: { type: 'string' } }, additionalProperties: false } }
]
async function call(name, args) { if (name === 'policy_drift_inspect') return inspectPolicyDrift(args); if (name === 'policy_drift_verify') return verifyPolicyDrift(args); throw Object.assign(new Error(`Unknown tool: ${name}`), { code: 'METHOD_NOT_FOUND' }) }
const send = (value) => process.stdout.write(`${JSON.stringify(value)}\n`)
const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
for await (const line of lines) {
  if (!line.trim()) continue; let request; try { request = JSON.parse(line) } catch { continue }; if (request.id === undefined) continue
  try {
    if (request.method === 'initialize') send({ jsonrpc: '2.0', id: request.id, result: { protocolVersion: request.params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'dsh-policy-drift-proof', version: '0.1.0' } } })
    else if (request.method === 'tools/list') send({ jsonrpc: '2.0', id: request.id, result: { tools } })
    else if (request.method === 'tools/call') { const result = await call(request.params?.name, request.params?.arguments ?? {}); send({ jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result } }) }
    else send({ jsonrpc: '2.0', id: request.id, error: { code: -32601, message: 'Method not found' } })
  } catch (error) { send({ jsonrpc: '2.0', id: request.id, error: { code: -32000, message: error.message, data: { code: error.code ?? 'ERROR' } } }) }
}
