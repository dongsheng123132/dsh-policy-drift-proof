# dsh-policy-drift-proof

[![CI](https://github.com/dongsheng123132/dsh-policy-drift-proof/actions/workflows/check.yml/badge.svg)](https://github.com/dongsheng123132/dsh-policy-drift-proof/actions/workflows/check.yml)
[![MIT 许可证](https://img.shields.io/github/license/dongsheng123132/dsh-policy-drift-proof)](LICENSE)
[![Node.js 22+](https://img.shields.io/badge/Node.js-%E2%89%A522-339933?logo=nodedotjs&logoColor=white)](package.json)
[![Awesome DSH Plugins](https://img.shields.io/badge/Awesome_DSH-%E5%B7%B2%E9%AA%8C%E8%AF%81%E5%AE%9E%E9%AA%8C-0969da)](https://github.com/dongsheng123132/awesome-dsh-plugins/blob/main/README.zh-CN.md#2origin-%E6%8F%92%E4%BB%B6%E5%AE%9E%E9%AA%8C%E5%AE%A4)

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的只读、内容寻址策略/配置漂移证据插件。

0.2 版补齐宿主中立的 DSH ToolDefinition、只处理内联证据的 Codex MCP、真实 ToolRuntime 调用与 stock Web Loader 回归。包入口只导出 namespace，不捆绑第二套 DSH 运行时。

它不执行策略、不审批工具调用、不扫描仓库，也不修复配置。`dsh-tool-policy` 已经负责调用前策略路由，SecurStack 已经负责安全扫描和策略门；本插件只回答缺失的证据问题：显式观测到的策略快照是否偏离固定基线，以及变化属于权限放宽、收紧、精确漂移还是未分类漂移。

## 证据模型

Manifest 用 SHA-256 和 revision 固定 baseline/observed 两份 `policy-snapshot/v1`，并用 JSON Pointer 规则覆盖控制面：

- `ordered-not-weaker`：枚举从严格到宽松排列，向右移动即失败；
- `set-no-additions`：新增权限失败，删除权限记为收紧；
- `exact`：任何改变都失败；
- 覆盖范围内没有规则解释的改变，按 `UNCLASSIFIED_DRIFT` 失败闭合。

报告只含路径、分类和摘要，不含任何策略原值。秘密形字段、原始输出字段、绝对路径、目录逃逸、symlink、超大输入和过度复杂结构都会被拒绝。工具不联网、不启动子进程，只向显式 `artifactDir` 写一个内容寻址 JSON，并回读核验。

`verified` 只表示两份快照的哈希和 revision 与 manifest 一致，且没有放宽、精确或未分类违规。权限收紧仍以 `driftStatus: "changed"` 可观察。它是输入证据的判决，不是安全认证。

## 使用

```sh
node bin/dsh-policy-drift-proof.mjs verify \
  --workspace examples/basic \
  --manifest policy-drift.manifest.json \
  --artifactDir artifacts
```

DSH bundle 注册两个工具：`dsh_policy_drift_inspect`、`dsh_policy_drift_verify`；MCP 伴随服务器注册对应的 inspect/verify 工具，但只接受内联 manifest 和固定的内联 snapshot，不读写文件、不联网、不启动子进程、不执行或修复策略，拒绝秘密/原始输出形字段且从不返回策略原值。工作区文件核验与内容寻址报告发布仍走 DSH 或 CLI。

## 验证

```sh
npm test
npm run check
npm run smoke:plugin
npm run smoke:mcp
DSH_CHECKOUT=/path/to/built/deepseek-harness npm run smoke:dsh
DSH_CHECKOUT=/path/to/built/deepseek-harness DSH_HOME=/path/to/isolated-home npm run smoke:web-loader
python C:/Users/ZhuanZ/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

GitHub Actions 在 Ubuntu 和 Windows 上运行。许可证：MIT。
