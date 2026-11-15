# CPU 管理器（cpu-manager）设计文档

日期：2026-11-10
环境：Raspberry Pi 500 / Debian 13 arm64 / Wayland 桌面
状态：已与用户确认（GUI 窗口、三类调控操作、Rust + egui）

## 1. 目标

一个桌面 GUI 程序：实时显示系统 CPU 占用，列出各进程 CPU 占用，并对选中进程进行调控（结束、调优先级、暂停/恢复）。

## 2. 功能需求

- 顶部：总 CPU 占用百分比（0–100%）大数字 + 进度条；4 个核心各一个小进度条。
- 进程表格：PID、名称、用户、CPU%、nice、状态；默认按 CPU% 降序；点表头切换排序列与方向；过滤框按名称/PID 子串过滤。
- 刷新：每秒采样一次。
- 调控（对选中进程）：
  - 结束进程：SIGTERM；强制结束：SIGKILL。两者均弹确认框（显示 PID + 名称）。
  - 调优先级：对话框内滑杆选 nice（-19..19），确认后 setpriority。
  - 暂停/恢复：SIGSTOP / SIGCONT，按进程状态显示对应按钮。
- 状态栏：显示最近一次操作结果或错误。
- 自身进程（本程序 PID）禁用全部调控按钮。

## 3. 非目标（YAGNI）

内存/磁盘/网络监控、历史曲线、远程访问、自动调控策略、多语言（界面仅中文）。

## 4. 技术选型

- Rust（本机 1.99.1）+ eframe/egui（glow 渲染后端，纯 Rust 无系统 GUI 依赖）+ egui_extras（TableBuilder 表格）。
- nix crate：kill / setpriority / 用户名解析（features: signal, resource, user）。
- 数据层只用 std 读 /proc，不依赖第三方采集库，保证可单测。

## 5. 架构与数据流

```
src/main.rs      入口，eframe::run_native
src/procstats.rs 数据层（std only）：/proc 解析 + 两次采样差值
src/actions.rs   调控层：nix 封装 kill/setpriority，错误类型化
src/app.rs       egui App：布局、表格、对话框、状态栏
```

- `procstats::Sampler` 持有上次快照；每秒读 `/proc/stat`（总与各核 jiffies）与 `/proc/<pid>/stat`（utime+stime、nice、state）、`/proc/<pid>/status`（Uid→用户名）。
- CPU% 口径同 top（Irix 模式）：进程 CPU% = Δ进程jiffies / Δ总jiffies × 核数 × 100，可超 100%；总 CPU% = Δbusy / Δtotal × 100（0–100）。
- 首次采样无差值，显示 0，下一秒起正常。
- 采样在 UI 线程内完成（约几百进程读取为毫秒级），不引线程；用 `request_repaint_after` 驱动每秒刷新。
- 进程在两次读取间消失：跳过该进程，不算错误。

## 6. 错误处理与安全

- 操作时进程已退出（ESRCH）→ 状态栏"进程已退出"，立即刷新列表。
- 权限不足（EPERM：调低 nice、动其他用户/root 进程）→ 状态栏提示"权限不足，可用 sudo 运行本程序"。降低 nice 无 root 必失败，属预期提示。
- 结束/强制结束必须经确认对话框（egui::Modal），显示 PID 与名称，防误点。
- 对 PID 1 与自身 PID 禁用按钮。
- /proc 单个文件读取失败只跳过该进程，不让整帧崩溃。

## 7. 测试

- `procstats` 单元测试（cargo test）：合成 /proc 文本 fixture 测 stat 行解析（含名称含空格/括号的 comm）、jiffies 差值→百分比换算、消失进程跳过。
- `actions` 集成测试：spawn 自有 `sleep` 子进程，验证 SIGSTOP→状态 T、SIGCONT→恢复、SIGTERM→退出、renice +5 生效；只操作自己的子进程，安全。
- GUI：`cargo build` 通过 + 真机启动冒烟（能开窗、有数据、按钮可点）+ 用户手动验收。
- `cargo clippy` 无警告。

## 8. 构建与运行

- 开发：`cargo run`；日常：`cargo build --release` 后运行 `target/release/cpu-manager`。
- 附 `cpu-manager.desktop` 桌面启动器（用户级安装到 ~/.local/share/applications，双击打开）。
- 首次编译数分钟（Pi 4 核），后续增量编译快。