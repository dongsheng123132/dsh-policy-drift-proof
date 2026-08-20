import { access, readFile } from 'node:fs/promises'
const required = ['.codex-plugin/plugin.json', '.mcp.json', 'mcp-server.mjs', 'bin/dsh-policy-drift-proof.mjs', 'cordis.patch.yml', 'index.js', 'lib/policy-drift-proof.mjs', 'README.md', 'README.zh-CN.md', 'SECURITY.md', 'test/stock-web-loader-smoke.mjs']
await Promise.all(required.map((file) => access(file)))
const pkg = JSON.parse(await readFile('package.json', 'utf8')); const plugin = JSON.parse(await readFile('.codex-plugin/plugin.json', 'utf8')); const mcp = JSON.parse(await readFile('.mcp.json', 'utf8'))
if (pkg.name !== plugin.name || pkg.version !== plugin.version || plugin.mcpServers !== './.mcp.json') throw new Error('package/plugin identity or MCP path mismatch')
if (!mcp.mcpServers?.['dsh-policy-drift-proof']) throw new Error('MCP server declaration missing')
if (pkg.scripts?.preinstall || pkg.scripts?.install || pkg.scripts?.postinstall || pkg.scripts?.prepare) throw new Error('lifecycle scripts are forbidden')
const index = await readFile('index.js', 'utf8'); const core = await readFile('lib/policy-drift-proof.mjs', 'utf8'); const server = await readFile('mcp-server.mjs', 'utf8')
if (/export\s+default\b/.test(index)) throw new Error('default export is forbidden: stock DSH Loader must receive namespace inject metadata')
if (index.includes('@deepseek-ai/dsh-tools')) throw new Error('plugin entry must not bundle a second DSH runtime')
for (const guard of ['verifiedByReadBack', 'returnsPolicyValues', 'FORBIDDEN_FIELD', 'escapes workspaceRoot', 'regular non-symlink file']) if (!core.includes(guard)) throw new Error(`guard missing: ${guard}`)
for (const shared of ['inspectPolicyDriftManifestJson', 'verifyPolicyDriftSnapshotsJson']) if (!server.includes(shared)) throw new Error(`MCP must use shared core ${shared}`)
process.stdout.write(`${JSON.stringify({ ok: true, requiredFiles: required.length, lifecycleScripts: false, mcp: true, namespaceLoaderSafe: true, hostNeutralTools: true, proofOnlyMcp: true })}\n`)
