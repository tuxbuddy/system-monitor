---
name: system-monitor
description: 通过 system-monitor 的 MCP 服务监控与调度 Linux 本机或 SSH 远端主机。覆盖主机切换、CPU/内存/温度/功耗/GPU、机器负载、进程列表与结束/信号/nice、cgroup CPU 与 pids 限额、网络连接、文件系统、ftrace 探针。用户说“看看机器负载/温度/功耗”“远端主机现在怎么样”“把某个进程结束掉”“限制某个分组 CPU”“探针看看函数调用”时使用。
---

# system-monitor MCP

`system-monitor` 是本机资源监控与调度工具（Rust 单二进制）。以 MCP stdio 服务方式运行时暴露下列能力：

```bash
system-monitor mcp          # stdio，换行分隔 JSON-RPC 2.0
```

在 Qoder 的 MCP 设置中注册（自定义 stdio 服务）：

```json
{
  "type": "stdio",
  "command": "<repo>/target/release/system-monitor",
  "args": ["mcp"]
}
```

远端能力依赖本机到目标的 SSH 免密登录；目标在 `~/.config/system-monitor/hosts.conf` 中维护（每行 `user@host`）。探针依赖已安装的 root probe-helper 服务（`scripts/install-probe-helper.sh`），仅本机可用。

## 工具

| 工具 | 作用 | 关键参数 |
| --- | --- | --- |
| `hosts_list` | 列出本地与已配置主机、当前主机 | — |
| `host_use` | 切换默认主机 | `host`: `local` 或 `user@host` |
| `system_overview` | CPU/每核、内存与 Swap、温度、频率、功耗、GPU、负载、运行时长、磁盘/网络速率 | `host?` |
| `system_load` | 1/5/15 分钟负载、运行时长、进程数 | `host?` |
| `process_list` | 进程列表 | `sort`(cpu/mem/rss/pid)、`limit`、`filter`、`host?` |
| `process_signal` | 发送 TERM/KILL/STOP/CONT/HUP/INT/USR1/USR2 | `pid`、`signal`、`tree?`、`host?` |
| `process_nice` | 调整 nice（-20..19） | `pid`、`nice`、`host?` |
| `scheduler_groups` | 列出 cgroup 分组与限额 | `host?` |
| `scheduler_set_limit` | 设置 `cpu_max_pct` / `cpu_weight` / `pids_max` | `group`、三者至少一项、`host?` |
| `scheduler_group_action` | 创建 / 删除分组 | `action`、`name`、`host?` |
| `network_connections` | TCP/TCP6/UDP/UDP6 连接与监听 | `proto?`、`state?`、`limit?`、`host?` |
| `filesystems` | 文件系统用量 | `host?` |
| `probe_status` | 内核版本、kallsyms 数量、可探测目标、tracefs/BPF 权限 | — |
| `probe_search` | 搜索函数 / 系统调用 | `query`、`kind?`、`limit?` |
| `probe_attach` | 挂载 kprobe / syscall / uprobe | `symbol`、`kind?`、`target?`、`stack?`、`pid?`、`args?` |
| `probe_poll` | 读取探针命中与最近调用 | — |
| `probe_detach` | 卸载探针 | — |

`host` 参数省略时使用 `host_use` 选定的主机；传入时只对本次调用生效。

## 典型用法

1. 先 `hosts_list` 确认目标，再 `system_overview` 看整体；要看负载细节用 `system_load`。
2. 发现异常进程：`process_list {"sort":"cpu","limit":10}` → 确认 PID 后 `process_signal {"pid":123,"signal":"TERM"}`；顽固进程用 `"signal":"KILL"`，整棵子树加 `"tree":true`（仅 TERM/KILL）。
3. 限流：`scheduler_group_action {"action":"create","name":"build"}` → `scheduler_set_limit {"group":"build","cpu_max_pct":50}`；远端主机要求目标机存在可写的用户 cgroup 委派根。
4. 网络与磁盘：`network_connections {"state":"LISTEN"}`、`filesystems`。
5. 探针：`probe_status` 看能力 → `probe_search {"query":"do_sys_open"}` → `probe_attach {"kind":"syscall","symbol":"openat"}` → `probe_poll` → `probe_detach`。

## 注意

- `process_signal`、`process_nice`、`scheduler_*` 会改变系统状态；结束进程前先通过 `process_list` 确认 PID 与命令名。
- 远端操作的权限等同该 SSH 用户（通常 root），返回错误时优先检查 SSH 免密、目标 cgroup 委派与目标机工具是否存在。
- 探针只作用于运行 `system-monitor mcp` 的本机，远端主机暂不支持探针。
- 温度/功耗在树莓派上来自 vcgencmd；其他主机温度取 hwmon，功耗取 Intel RAPL（需要 root 读能量计）。