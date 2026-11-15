# 系统监视器（system-monitor）

面向 Linux 桌面的资源监控与调度工具，Rust + egui（eframe）原生 GUI，单二进制运行，贴近 Raspberry Pi 等 ARM 桌面使用。

## 功能

- **总览**：CPU / 内存 / 温度 / 告警聚合，本地与远程主机切换。
- **监控**：整机与每核 CPU、内存 / Swap、进程表（平铺 / 树形 / 按应用分组），支持排序、终止 / 杀死、nice 调整、CPU 与 pids cgroup 限额。
- **调度**：按 CPU 占用、温度、降频状态自动调节目标 cgroup 的 CPU 配额，带滞回与冷却时间，默认关闭。
- **性能**：CPU / 内存历史曲线、磁盘与文件系统用量。
- **网络**：连接列表与网卡收发速率。
- **探针**：基于 tracefs 的函数 / syscall kprobe / uprobe 挂载计数；特权操作由 root helper 经 unix socket 代执行，GUI 本身不提权。
- **远程**：SSH 只读采集其它主机（远端零安装，需已配置免密登录），支持多主机汇总。
- **平台档案**：内置 raspberry-pi / debian / ubuntu / kylin / uos / deepin / openEuler 等档案，可用 `~/.config/system-monitor/platform.conf` 覆盖。

默认只读采集，任何会改变进程或系统状态的操作都需要在界面中确认。

## 构建与运行

需要 Linux（X11 或 Wayland）与 Rust 1.85+（edition 2024）。

```bash
cargo build --release
./target/release/system-monitor
```

桌面入口见 `system-monitor.desktop`，其中 `Exec` 指向构建产物，按实际路径修改后复制到 `~/.local/share/applications/`。

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
| `~/.config/system-monitor/config.conf` | 排序、刷新间隔、视图、告警阈值 |
| `~/.config/system-monitor/platform.conf` | 平台采集档案覆盖 |
| `~/.config/system-monitor/hosts.conf` | 远程主机列表（每行一个 SSH 目标） |

## 测试

```bash
cargo test
```

## 设计文档

`docs/superpowers/specs/` 按版本记录了设计与演进：

- `2026-11-10-cpu-manager-design.md` — v1 基础监控与调控
- `2026-11-11-cpu-manager-v2-design.md` — 内存监控与历史曲线
- `2026-11-11-cpu-manager-v3-design.md` — 能效 / 供电与平台档案
- `2026-11-12-scheduler-center-design.md` — v4 调度中心、探针与远程主机