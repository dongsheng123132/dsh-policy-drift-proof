import { access, readFile } from 'node:fs/promises'
const required = ['.codex-plugin/plugin.json', '.mcp.json', 'mcp-server.mjs', 'bin/dsh-policy-drift-proof.mjs', 'cordis.patch.yml', 'index.js', 'lib/policy-drift-proof.mjs', 'README.md', 'README.zh-CN.md', 'SECURITY.md']
await Promise.all(required.map((file) => access(file)))
const pkg = JSON.parse(await readFile('package.json', 'utf8')); const plugin = JSON.parse(await readFile('.codex-plugin/plugin.json', 'utf8')); const mcp = JSON.parse(await readFile('.mcp.json', 'utf8'))
if (pkg.name !== plugin.name || pkg.version !== plugin.version || plugin.mcpServers !== './.mcp.json') throw new Error('package/plugin identity or MCP path mismatch')
if (!mcp.mcpServers?.['dsh-policy-drift-proof']) throw new Error('MCP server declaration missing')
if (pkg.scripts?.preinstall || pkg.scripts?.install || pkg.scripts?.postinstall) throw new Error('lifecycle scripts are forbidden')
process.stdout.write(`${JSON.stringify({ ok: true, requiredFiles: required.length, lifecycleScripts: false, mcp: true })}\n`)
