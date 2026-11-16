---
name: system-monitor
description: 通过 system-monitor 的 MCP 服务监控、诊断与调度 Linux 本机或 SSH 远端主机。覆盖主机切换、CPU/内存/温度/功耗/GPU/PSI 压力、进程列表与详情、结束/信号/nice、cgroup CPU 与 pids 限额、网络连接、文件系统、ftrace 探针、eBPF 能力、以及「证据→方案→审批→执行→验证」的诊断会话。用户说“看看机器负载/温度/功耗”“远端主机现在怎么样”“哪个进程占满 CPU”“把某个进程结束掉”“限制某个分组 CPU”“内存是不是不够了”“探针看看函数调用”“做一次主机体检”时使用。
---

# system-monitor MCP

`system-monitor` 是本机资源监控与调度工具（Rust 单二进制）。以 MCP stdio 服务运行时暴露工具与预置工作流。

```bash
system-monitor mcp          # stdio，换行分隔 JSON-RPC 2.0
system-monitor mcp --mcp-policy=confirm    # 允许 L2；L3 需审批凭证
system-monitor mcp --mcp-policy=trusted    # 全放行（仅限受控环境）
```

在 Qoder 的 MCP 设置中注册（自定义 stdio 服务）：

```json
{
  "type": "stdio",
  "command": "<repo>/target/release/system-monitor",
  "args": ["mcp"]
}
```

## 使用原则

- **默认只读**：未显式提升策略时，L2/L3 写操作会被结构化拒绝（`error=policy_denied`）。
- **主机参数**：所有工具接受 `host`（`local` 或 `user@host`）；省略时使用 `host_use` 设定的默认主机。跨主机操作请显式传 `host`，避免隐式切换。
- **新鲜度**：概览/负载/进程/网络/文件系统返回 `freshness`（`sampled_age_secs`、`stale`、`last_error`）。远端采集失败但存在旧样本时会返回 `stale=true` 的旧数据，不要把它当成实时值。
- **先观测后动手**：结束进程前先用 `process_list` / `process_details` 确认 PID、命令名与用户；改变系统状态优先走诊断会话。
- **探针默认本机**；远端需要在目标机安装同一 root probe-helper 服务（`scripts/install-probe-helper.sh`），MCP/GUI 通过 SSH 代理调用，不开放额外端口。

## 工具

### 主机与总览（L0）

| 工具 | 作用 | 关键参数 |
| --- | --- | --- |
| `hosts_list` | 本地与 hosts.conf 中的主机、当前主机 | — |
| `host_use` | 切换默认主机 | `host`: `local` 或 `user@host` |
| `system_overview` | CPU/每核、内存/Swap、温度、频率、功耗、GPU、负载、运行时长、磁盘/网络速率、OOM 计数 | `host?` |
| `system_load` | 1/5/15 分钟负载、运行时长、进程数、CPU 占用 | `host?` |
| `host_capabilities` | cgroup/PSI/BTF/tracefs/thermal/cpufreq/RAPL 等真实能力 | `host?` |
| `psi_status` | cpu/memory/io 压力（some/full avg10/60/300），不支持时明确标记 | — |
| `ebpf_doctor` | eBPF 能力矩阵与实验定义 | — |

### 进程（读 L0，写 L2/L3）

| 工具 | 作用 | 关键参数 |
| --- | --- | --- |
| `process_list` | 进程列表，按 CPU/内存/RSS/PID 排序并过滤 | `sort`、`limit`、`filter`、`host?` |
| `process_details` | 单进程 uid/gid、线程、内存、I/O、FD、OOM 评分（仅本机） | `pid` |
| `process_signal` | TERM/KILL/STOP/CONT/HUP/INT/USR1/USR2，可作用于进程树 | `pid`、`signal`、`tree?`、`host?` |
| `process_nice` | 调整 nice（-20..19） | `pid`、`nice`、`host?` |

### cgroup 调度（枚举 L1，写 L2/L3）

| 工具 | 作用 | 关键参数 |
| --- | --- | --- |
| `scheduler_groups` | 只读列出分组、CPU 上限/权重、pids 上限、节流比 | `host?` |
| `scheduler_status` | 本机 cgroup v2 / 委派 / 控制器 / 可写性体检 | — |
| `scheduler_set_limit` | 设置 `cpu_max_pct` / `cpu_weight` / `pids_max` | `group`、三者至少一项、`host?` |
| `scheduler_group_action` | 创建/删除分组（delete 为 L3） | `action`、`name`、`host?` |

### 网络与磁盘（L0）

| 工具 | 作用 | 关键参数 |
| --- | --- | --- |
| `network_connections` | TCP/TCP6/UDP/UDP6 连接与监听 | `proto?`、`state?`、`limit?`、`host?` |
| `filesystems` | 文件系统用量 | `host?` |

### 探针（本机 / 远端）

| 工具 | 作用 | 关键参数 |
| --- | --- | --- |
| `probe_status` | 内核版本、kallsyms 数量、可探测目标、权限、helper 就绪 | `host?` |
| `probe_search` | 搜索函数 / 系统调用 | `query`、`kind?`、`limit?`、`host?` |
| `probe_attach` | 挂载 kprobe / syscall / uprobe | `symbol`、`kind?`、`target?`、`stack?`、`pid?`、`args?`、`host?` |
| `probe_poll` | 读取命中计数与最近调用 | `host?`（省略沿用活动探针主机） |
| `probe_detach` | 卸载探针 | `host?`（省略沿用活动探针主机） |

### 诊断会话（L1 簿记，执行由命令风险决定）

| 工具 | 作用 | 关键参数 |
| --- | --- | --- |
| `diag_start` | 新建会话，返回 `session` 与 `next_action` | — |
| `diag_add_evidence` | 追加证据（事实/推断/置信度） | `session`、`fact`、`source?`、`hypothesis?`、`confidence?` |
| `diag_submit_plan` | 提交方案（**需先有证据**），返回 `plan_hash` 与 `warnings` | `session`、`description`、`command`、`rollback?`、`verify_metric?` |
| `diag_approve` | 审批方案；L3 需 `approval_token` | `session`、`plan_hash`、`approval_token?` |
| `diag_execute` | 经统一 dispatcher 执行已审批方案 | `session`、`plan_hash` |
| `diag_verify` | 复采验证并归档，返回报告与 `report_path` | `session`、`note?` |
| `diag_status` | 查看会话；省略 `session` 时列出最近会话摘要 | `session?`、`limit?` |
| `diag_abort` | 中止会话 | `session` |

### 策略

| 工具 | 作用 |
| --- | --- |
| `policy_status` | 当前模式、完整风险目录、参数敏感升级规则、审批与审计位置 |

工具返回同时包含 `text` 与 `structuredContent`；错误为结构化 JSON（`error` / `tool` / `message` / `hint` 等字段），客户端应读 `structuredContent` 或解析 `text`。

## 预置工作流（MCP prompts）

- `diagnose_high_cpu`：高 CPU 定位与可回滚处置
- `diagnose_memory_pressure`：内存压力排查
- `host_health_check`：主机只读体检

## 典型流程

### 1. 只读体检

`host_capabilities` → `system_overview` → `system_load` → `psi_status` → `filesystems` → `network_connections {"state":"LISTEN"}` → `scheduler_status` →（本机）`probe_status`。

### 2. 进程处置

`process_list {"sort":"cpu","limit":10}` 确认 PID/命令名/用户 → 需要时 `process_details` → 优先 `process_nice` 或 cgroup 限流 → 再考虑 `process_signal {"signal":"TERM"}` → 顽固进程才 KILL，且需 L3 审批。

### 3. 限流

`scheduler_group_action {"action":"create","name":"build"}` → `scheduler_set_limit {"group":"build","cpu_max_pct":50}`。远端要求目标机存在可写的用户 cgroup 委派根。

### 4. 诊断会话（改变系统状态时优先）

1. `diag_start` 建会话；
2. `diag_add_evidence` 写入读数（事实与推断分开，标注置信度）；
3. `diag_submit_plan` 提交方案，命令 JSON 形如 `{"kind":"cg_set","group":"media","pct":50}` / `{"kind":"nice","pid":123,"nice":10}` / `{"kind":"signal","pid":123,"sig":15}`，写清 `rollback` 与 `verify_metric`；
4. `diag_approve` → `diag_execute`；
5. 复采后 `diag_verify` 归档。每个响应都带 `next_action`，按它推进即可。

会话持久化在 `~/.local/share/system-monitor/diag/`，MCP 重启后可继续未完成会话。

## 策略与审批

| 等级 | 含义 | readonly | confirm | trusted |
| --- | --- | --- | --- | --- |
| L0 | 纯读取 | ✅ | ✅ | ✅ |
| L1 | 诊断/会话簿记 | ✅ | ✅ | ✅ |
| L2 | 可恢复控制（nice、限额、挂探针） | ❌ | ✅ | ✅ |
| L3 | 破坏性（KILL、进程树、删除分组） | ❌ | `approval_token` | ✅ |

L3 凭证由人本机签发（一次性、绑定工具与参数、限时）：

```bash
system-monitor mcp-approve --tool process_signal --args '{"pid":123,"signal":"KILL"}' --ttl 60
```

把输出的 token 作为 `approval_token` 传入，不要跨 PID/分组复用。所有写操作（含被拒绝的）记录于 `~/.local/share/system-monitor/mcp-audit.jsonl`。

## 注意

- 结束进程前必须确认 PID 与命令名；不要凭进程名猜测 PID。
- 远端操作权限等同该 SSH 用户；失败时优先检查免密登录、目标 cgroup 委派与目标机工具是否存在。
- 远端暂不支持探针；`process_details` 目前仅本机。
- 温度/功耗在树莓派上来自 vcgencmd；其他主机温度取 hwmon，功耗取 Intel RAPL。