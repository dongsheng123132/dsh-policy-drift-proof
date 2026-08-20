import assert from 'node:assert/strict'
import * as plugin from '../index.js'
assert.equal('default' in plugin, false); assert.equal(plugin.name, 'dsh-policy-drift-proof'); assert.deepEqual(plugin.inject, ['tools'])
const tools = plugin.createDefinitions({}, {}).map(({ name }) => name)
assert.deepEqual(tools, ['dsh_policy_drift_inspect', 'dsh_policy_drift_verify'])
process.stdout.write(`${JSON.stringify({ ok: true, namespaceLoaderSafe: true, tools })}\n`)
