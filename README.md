# dsh-policy-drift-proof

Read-only, content-addressed policy/configuration drift evidence for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

This plugin does **not** enforce tool calls, approve actions, scan repositories, or repair configuration. `dsh-tool-policy` already provides pre-execution policy routing, while SecurStack provides security scans and policy gates. This plugin covers the missing evidence question: did the policy snapshot actually observed by an operator differ from the pinned baseline, and was the difference weakening, tightening, exact, or unclassified?

## Evidence model

The explicit manifest pins a baseline and observed `policy-snapshot/v1` by SHA-256 and revision. Rules cover declared JSON Pointer roots:

- `ordered-not-weaker`: enum order is restrictive to permissive; moving right fails.
- `set-no-additions`: additions fail, removals are recorded as tightening.
- `exact`: any change fails.
- any changed covered leaf without a rule fails closed as `UNCLASSIFIED_DRIFT`.

Reports include paths, classifications and SHA-256 digests only. They never include policy values. Secret-shaped fields, raw output fields, absolute/escaping paths, symlinks, oversized inputs and excessive structure are rejected. The verifier performs no network calls or child processes and writes only one content-addressed JSON report beneath the explicit `artifactDir`, then reads it back and verifies its digest.

`verified` means both snapshot hashes and revisions matched and no weakening, exact or unclassified violation was found. Tightening remains observable through `driftStatus: "changed"`. This is evidence about supplied snapshots, not a security certification.

## CLI

```sh
node bin/dsh-policy-drift-proof.mjs inspect \
  --workspace examples/basic \
  --manifest policy-drift.manifest.json

node bin/dsh-policy-drift-proof.mjs verify \
  --workspace examples/basic \
  --manifest policy-drift.manifest.json \
  --artifactDir artifacts
```

The CLI prints one JSON object to stdout. A drift violation exits `2`; invalid usage exits `1`.

## DeepSeek Harness bundle

```sh
dsh plugin --profile policy-proof add github:dongsheng123132/dsh-policy-drift-proof#<commit>
dsh profile --profile policy-proof compose
```

The bundle registers:

- `dsh_policy_drift_inspect`
- `dsh_policy_drift_verify`

The companion stdio MCP server exposes `policy_drift_inspect` and `policy_drift_verify` through `.mcp.json`.

## Verification

```sh
npm test
npm run check
npm run smoke:mcp
python C:/Users/ZhuanZ/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

CI runs tests, structural checks and MCP smoke on Ubuntu and Windows. Node.js 22 or newer is required.

## License

MIT
