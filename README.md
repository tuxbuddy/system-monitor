# 系统监视器（system-monitor）

面向 Linux 桌面的资源监控与调度工具，Rust + egui（eframe）原生 GUI，另带终端界面（TUI），单二进制运行，贴近 Raspberry Pi 等 ARM 桌面使用。

## 功能

- **总览**：CPU / 内存 / 温度 / 告警聚合，本地与远程主机切换。
- **监控**：整机与每核 CPU、内存 / Swap、进程表（平铺 / 树形 / 按应用分组），支持排序、终止 / 杀死、nice 调整、CPU 与 pids cgroup 限额。核心数较多时以热力条汇总，逐核明细按需展开。
- **调度**：按 CPU 占用、温度、降频状态自动调节目标 cgroup 的 CPU 配额，带滞回与冷却时间，默认关闭。
- **性能**：分组卡片式趋势大盘（处理器 / 内存显卡 / 网络 / 磁盘 / 文件系统），可调告警阈值。
- **网络**：上下行吞吐趋势、连接统计与可过滤的连接列表。
- **探针**：基于 tracefs 的函数 / syscall kprobe / uprobe 挂载计数；特权操作由 root helper 经 unix socket 代执行，GUI 本身不提权。
- **TUI**：`--tui` 终端界面，无桌面也能用；CPU / 每核 / 内存 / Swap / 温度 / 功耗 / GPU / 进程表，`H` 切换本地与 SSH 主机，支持结束进程、信号与暂停恢复。
- **MCP 服务**：`system-monitor mcp` 以 stdio MCP 暴露 17 个工具（概览、负载、进程、调度、网络、文件系统、探针、主机切换），供 AI 客户端直接调用。
- **远程**：SSH 采集其它主机（远端零安装，需已配置免密登录），支持多主机汇总；监控、性能、网络、调度与结束进程均作用于所选主机。
- **平台档案**：内置 raspberry-pi / debian / ubuntu / kylin / uos / deepin / openEuler 等档案，可用 `~/.config/system-monitor/platform.conf` 覆盖。

默认只读采集，任何会改变进程或系统状态的操作都需要在界面中确认。

## 构建与运行

需要 Rust 1.85+（edition 2024）。图形版另需 Linux 桌面（X11 或 Wayland）。

```bash
# 桌面版（默认包含 GUI + TUI）
cargo build --release
./target/release/system-monitor          # 有桌面会话时打开图形界面
./target/release/system-monitor --tui    # 强制使用终端界面
```

无 `DISPLAY` / `WAYLAND_DISPLAY` 时自动进入 TUI，也可直接构建不含 egui 的纯 TUI 版本（服务器 / 树莓派无桌面场景，体积更小）：

```bash
cargo build --release --no-default-features
./target/release/system-monitor --tui
```

TUI 按键：`H` 切换主机、`Tab` 排序、`↑↓` 选择、`t`/`T` 结束/强制结束、`x` 结束进程树、`p` 暂停恢复、`空格` 暂停刷新、`?` 帮助、`q` 退出。

桌面界面：顶部为「监控 / 调度 / 性能 / 网络 / 总览 / 探针」导航；监控页的 KPI 大盘可一键收起，其它页面保留一行实时指标条。快捷键：`Ctrl+1–6` 切换页面、`F5` 刷新、`空格` 暂停、`Ctrl+F` 搜索进程、`↑/↓` 选择进程、`Del` 结束进程、`Esc` 取消/清除。

桌面入口见 `system-monitor.desktop`，其中 `Exec` 指向构建产物，按实际路径修改后复制到 `~/.local/share/applications/`。

## MCP 服务

```bash
system-monitor mcp          # stdio，换行分隔 JSON-RPC 2.0
```

在 MCP 客户端中注册为自定义 stdio 服务：

```json
{
  "type": "stdio",
  "command": "<repo>/target/release/system-monitor",
  "args": ["mcp"]
}
```

工具：`hosts_list`、`host_use`、`system_overview`、`system_load`、`process_list`、
`process_signal`、`process_nice`、`scheduler_groups`、`scheduler_set_limit`、
`scheduler_group_action`、`network_connections`、`filesystems`、`probe_status`、
`probe_search`、`probe_attach`、`probe_poll`、`probe_detach`。

- 所有读取类工具都接受可选 `host`（`user@host`），省略时用 `host_use` 选定的主机
- 探针工具只作用于运行 MCP 的本机，需要先安装 root probe-helper 服务
- 远端调度要求目标机存在可写的用户 cgroup 委派根
- Qoder skill 见 `skills/system-monitor/SKILL.md`（安装到 `~/.qoder-cn/skills/` 后可直接触发）

## CI 产物（GitHub Actions）

`.github/workflows/build.yml` 在 push / PR / 手动触发时跑 clippy 与测试，并产出三份构建：

| 产物 | 内容 |
| --- | --- |
| `system-monitor-linux-x86_64-gui` | 桌面版（含 TUI，`--tui` 切换） |
| `system-monitor-linux-x86_64-tui` | 纯 TUI，不链接图形库 |
| `system-monitor-linux-aarch64-tui` | 树莓派 / ARM64 服务器用的纯 TUI（交叉编译） |

打 `v*` 标签时自动创建 GitHub Release 并附上三份压缩包与 sha256。

## 可选：特权探针 helper

探针需要读写 tracefs，由独立的 root systemd 服务承担：

```bash
cargo build --release --bin probe-helper
sudo scripts/install-probe-helper.sh     # 安装并启动 system-monitor-probe.service
sudo scripts/uninstall-probe-helper.sh   # 卸载
```

## 配置

| 文件 | 内容 |
| --- | --- |
| `~/.config/system-monitor/config.conf` | 排序、刷新间隔、表格视图、告警阈值、大盘展开状态 |
| `~/.config/system-monitor/platform.conf` | 平台采集档案覆盖 |
| `~/.config/system-monitor/hosts.conf` | 远程主机列表（每行一个 SSH 目标） |

## 测试

```bash
cargo test                                    # 桌面版（含 GUI 模块）
cargo test --no-default-features --bin system-monitor   # 纯 TUI 版
```

## 设计文档

`docs/superpowers/specs/` 按版本记录了设计与演进：

- `2026-11-10-cpu-manager-design.md` — v1 基础监控与调控
- `2026-11-11-cpu-manager-v2-design.md` — 内存监控与历史曲线
- `2026-11-11-cpu-manager-v3-design.md` — 能效 / 供电与平台档案
- `2026-11-12-scheduler-center-design.md` — v4 调度中心、探针与远程主机