#!/usr/bin/env node
import readline from 'node:readline'
import { inspectPolicyDriftManifestJson, verifyPolicyDriftSnapshotsJson } from './lib/policy-drift-proof.mjs'

const MAX_LINE_BYTES = 14 * 1024 * 1024
const tools = [
  { name: 'policy_drift_inspect', description: 'Proof-only inspection of an inline policy drift manifest without filesystem access or policy values in output.', inputSchema: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string' } }, additionalProperties: false } },
  { name: 'policy_drift_verify', description: 'Proof-only comparison of pinned inline baseline and observed snapshots. Secret- and raw-output-shaped fields are rejected; values are never returned.', inputSchema: { type: 'object', required: ['manifestJson', 'baselineSnapshotJson', 'observedSnapshotJson'], properties: { manifestJson: { type: 'string' }, baselineSnapshotJson: { type: 'string' }, observedSnapshotJson: { type: 'string' } }, additionalProperties: false } }
]
function call(name, args) { if (name === 'policy_drift_inspect') return inspectPolicyDriftManifestJson(args.manifestJson); if (name === 'policy_drift_verify') return verifyPolicyDriftSnapshotsJson(args.manifestJson, args.baselineSnapshotJson, args.observedSnapshotJson); throw Object.assign(new Error(`Unknown tool: ${name}`), { code: 'METHOD_NOT_FOUND' }) }
const send = (value) => process.stdout.write(`${JSON.stringify(value)}\n`)
const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
for await (const line of lines) {
  if (!line.trim()) continue; if (Buffer.byteLength(line) > MAX_LINE_BYTES) continue
  let request; try { request = JSON.parse(line) } catch { continue }; if (request.id === undefined) continue
  try {
    if (request.method === 'initialize') send({ jsonrpc: '2.0', id: request.id, result: { protocolVersion: request.params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'dsh-policy-drift-proof', version: '0.2.0' } } })
    else if (request.method === 'tools/list') send({ jsonrpc: '2.0', id: request.id, result: { tools } })
    else if (request.method === 'tools/call') { const result = call(request.params?.name, request.params?.arguments ?? {}); send({ jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result } }) }
    else send({ jsonrpc: '2.0', id: request.id, error: { code: -32601, message: 'Method not found' } })
  } catch (error) { send({ jsonrpc: '2.0', id: request.id, error: { code: -32000, message: error.message, data: { code: error.code ?? 'ERROR' } } }) }
}
