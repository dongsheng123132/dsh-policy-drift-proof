import assert from 'node:assert/strict'
import { createDefinitions } from '../index.js'
const tools = createDefinitions({}, {}).map(({ name }) => name)
assert.deepEqual(tools, ['dsh_policy_drift_inspect', 'dsh_policy_drift_verify'])
process.stdout.write(`${JSON.stringify({ ok: true, tools })}\n`)
