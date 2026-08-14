import { defineTool } from '@deepseek-ai/dsh-tools'
import { inspectPolicyDrift, verifyPolicyDrift } from './lib/policy-drift-proof.mjs'

export const name = 'dsh-policy-drift-proof'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const base = (config, args) => ({ workspaceRoot: config.workspaceRoot ?? process.cwd(), manifestPath: args.manifestPath, artifactDir: args.artifactDir })

export function createDefinitions(_ctx, config = {}) {
  return [
    defineTool({
      name: 'dsh_policy_drift_inspect',
      description: 'Inspect policy snapshot pins, coverage roots and rule semantics without returning policy values.',
      parameters: { manifestPath: { type: 'string', required: true } },
      output: { schema: { type: 'json' }, render: renderJson },
      execute(args) { return inspectPolicyDrift(base(config, args)) }
    }),
    defineTool({
      name: 'dsh_policy_drift_verify',
      description: 'Verify pinned DSH policy snapshots and emit a content-addressed, value-redacted drift verdict.',
      parameters: { manifestPath: { type: 'string', required: true }, artifactDir: { type: 'string', required: true } },
      output: { schema: { type: 'json' }, render: renderJson },
      execute(args) { return verifyPolicyDrift(base(config, args)) }
    })
  ]
}

export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
export default apply
