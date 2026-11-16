# 安全策略

## 支持版本

安全修复只针对 `main` 分支的最新 release tag。该项目处于 0.x 阶段，不维护长期分支。

## 报告漏洞

**请不要在公开 issue 中报告安全漏洞。**

私下报告渠道：

1. GitHub Security Advisories（首选）：仓库页 → Security → Report a vulnerability。
2. 备用：通过 GitHub 联系维护者 @tuxbuddy。

请在报告中包含：受影响版本/commit、复现步骤或 PoC、影响评估、可行的修复建议。

## 响应时限

| 阶段 | 目标 |
| --- | --- |
| 确认收到 | 3 天内 |
| 初步评估与分级 | 7 天内 |
| 修复发布 | 高危 14 天内，其余 30 天内 |

修复发布后会在 release notes 致谢报告者（可要求匿名）。

## 安全设计边界（供报告参考）

- MCP 服务默认只读；写操作需显式策略（`--mcp-policy`），L3 动作需一次性审批凭证。
- 所有 SSH 目标经 `SshTarget` 白名单校验；ssh 调用不经 shell、`--` 终止选项解析。
- 远端命令有总超时与输出上限；凭据只依赖系统 ssh（agent/keychain），本工具不读取、不落盘、不输出私钥内容。
- 特权探针能力隔离在 `probe-helper`（独立 root 服务，socket 按 uid 校验）；主程序不提权。
- 配置/主机清单/审计文件 0600；审计记录位于 `~/.local/share/system-monitor/mcp-audit.jsonl`。

已知不设防的场景（报告前请确认不在其列）：

- 用户主动使用 `trusted` 策略模式后的 AI 写操作（该模式即声明信任调用方）。
- 用户 `HOME` 目录被本机攻击者直接读写（同权限下无隔离可言）。
