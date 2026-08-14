#!/usr/bin/env node
import { inspectPolicyDrift, verifyPolicyDrift } from '../lib/policy-drift-proof.mjs'

const [command, ...rest] = process.argv.slice(2); const args = Object.fromEntries(rest.reduce((pairs, item, index) => item.startsWith('--') ? [...pairs, [item.slice(2), rest[index + 1]]] : pairs, []))
try {
  const common = { workspaceRoot: args.workspace ?? process.cwd(), manifestPath: args.manifest }
  const result = command === 'inspect' ? await inspectPolicyDrift(common) : command === 'verify' ? await verifyPolicyDrift({ ...common, artifactDir: args.artifactDir }) : null
  if (!result) throw Object.assign(new Error('usage: dsh-policy-drift-proof <inspect|verify> --manifest <relative.json> [--workspace <dir>] [--artifactDir <relative-dir>]'), { code: 'USAGE' })
  process.stdout.write(`${JSON.stringify(result)}\n`); if (result.status === 'failed') process.exitCode = 2
} catch (error) { process.stderr.write(`${JSON.stringify({ ok: false, code: error.code ?? 'ERROR', message: error.message })}\n`); process.exitCode = error.code === 'USAGE' ? 1 : 2 }
