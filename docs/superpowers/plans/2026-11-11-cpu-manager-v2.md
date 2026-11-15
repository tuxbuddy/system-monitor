# CPU 管理器 v2（监控完善）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 v1 基础上增加内存监控、系统负载/运行时长、CPU 历史曲线、进程命令行可见与刷新控制。

**Architecture:** 沿用 v1 三层：procstats.rs 数据层（std only，纯函数可单测）→ actions.rs 调控层（本轮不动）→ app.rs egui 展示。新数据全部来自 /proc 既有文件，无新依赖、无线程。

**Tech Stack:** Rust 1.99.1 / eframe+egui 0.37.0（glow）/ egui_extras 0.37.0 / nix 0.31.3 / libc 0.2.191。

**Spec:** docs/superpowers/specs/2026-11-11-cpu-manager-v2-design.md（v1 基线：2026-11-10-cpu-manager-design.md）

## Global Constraints

- 禁止任何 git 提交（本机无提交身份且禁止改 git config）；不写 git add/commit 步骤。
- 无新依赖；Cargo.toml 与 Cargo.lock 不动（eframe/egui/egui_extras 0.37.0、nix 0.31.3、libc 0.2.191）。
- 无多线程；采样在 UI 线程，1 秒一次。
- 界面文案仅中文，与本计划给出的字符串逐字一致。
- CPU% 口径不变（Irix：进程可超 100%；总/核 0–100）；首采零值；消失进程跳过；saturating_sub。
- 调控安全语义不变：确认框、自身/PID 1 禁用、ESRCH 立即刷新、EPERM 提示「权限不足，可用 sudo 运行本程序」。
- egui 0.37 API 以 ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ 源码为准：App::ui（非 update）、Panel::top/bottom、show(ui,…)、Id::unique、ui.selectable_label、egui::Modal。已核实：Painter::line_segment([Pos2;2], impl Into<Stroke>)（painter.rs:318）、Painter::rect_filled(Rect, impl Into<CornerRadius>, impl Into<Color32>)（painter.rs:397，f32→CornerRadius 见 corner_radius.rs:41）、Stroke::new(f32, impl Into<Color32>)（stroke.rs:26）、Ui::allocate_exact_size(Vec2, Sense)->(Rect, Response)（ui.rs:1276）。
- 每个任务结束必须：cargo build 零警告、cargo clippy --all-targets -- -D warnings 干净、cargo test 全绿。
- 测试只操作自有子进程（actions 既有约定）；新增测试均为纯函数 fixture，不碰真实系统进程。
- T1 期间 procstats.rs 顶部临时 `#![allow(dead_code)]`（新函数尚未被 app 接线，bin target 会报 dead_code），T3 接线完成后移除（T3 验收项）。

---

### Task 1: procstats 数据层扩展（TDD）

**Files:**
- Modify: `src/procstats.rs`（现 332 行）

**Interfaces:**
- Consumes: v1 既有 `CpuTimes/ProcSnapshot/SystemSnapshot/ProcUsage/Usage/compute/Sampler`。
- Produces（T2/T3 依赖，签名逐字）：
  - `pub struct MemInfo { pub total_kb: u64, pub available_kb: u64 }`，`impl MemInfo { pub fn used_kb(self) -> u64 }`
  - `pub struct LoadAvg { pub one: f32, pub five: f32, pub fifteen: f32 }`
  - `pub struct StatusFields { pub uid: Option<u32>, pub rss_kb: u64 }`
  - `pub fn parse_meminfo(text: &str) -> Option<MemInfo>`
  - `pub fn parse_loadavg(text: &str) -> Option<LoadAvg>`
  - `pub fn parse_uptime(text: &str) -> Option<u64>`
  - `pub fn format_uptime(secs: u64) -> String`
  - `pub fn parse_status(text: &str) -> StatusFields`
  - `pub fn read_status(pid: i32) -> StatusFields`
  - `pub fn format_cmdline(bytes: &[u8]) -> String`
  - `pub fn read_cmdline(pid: i32) -> String`
  - `ProcSnapshot` 增 `pub rss_kb: u64`；`SystemSnapshot` 增 `pub mem: Option<MemInfo>, pub load: Option<LoadAvg>, pub uptime_secs: Option<u64>`；`ProcUsage` 增 `pub rss_kb: u64`；`Usage` 增同样三个 Option 字段（compute 从 curr 透传）。

- [ ] **Step 1: 加类型、函数桩与结构字段（让测试可编译）**

在 `src/procstats.rs` **文件第一行**（所有 `use` 之前——inner attribute 必须在模块最顶部，放 use 之后会编译错误）加：

```rust
#![allow(dead_code)] // 临时：T3 接线完成后移除（全局约束）
```

在 `ProcSnapshot` 定义后加新类型与桩（函数体全部 `todo!()`，Step 4 实现）：

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemInfo {
    pub total_kb: u64,
    pub available_kb: u64,
}

impl MemInfo {
    pub fn used_kb(self) -> u64 {
        todo!()
    }
}

pub fn parse_meminfo(_text: &str) -> Option<MemInfo> {
    todo!()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LoadAvg {
    pub one: f32,
    pub five: f32,
    pub fifteen: f32,
}

pub fn parse_loadavg(_text: &str) -> Option<LoadAvg> {
    todo!()
}

pub fn parse_uptime(_text: &str) -> Option<u64> {
    todo!()
}

pub fn format_uptime(_secs: u64) -> String {
    todo!()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StatusFields {
    pub uid: Option<u32>,
    pub rss_kb: u64,
}

pub fn parse_status(_text: &str) -> StatusFields {
    todo!()
}

pub fn read_status(_pid: i32) -> StatusFields {
    todo!()
}

pub fn format_cmdline(_bytes: &[u8]) -> String {
    todo!()
}

pub fn read_cmdline(_pid: i32) -> String {
    todo!()
}
```

结构字段扩展（既有字段与顺序不动，末尾追加）：
- `ProcSnapshot` 加 `pub rss_kb: u64,`；`parse_proc_stat` 的构造加 `rss_kb: 0,`。
- `SystemSnapshot` 加 `pub mem: Option<MemInfo>, pub load: Option<LoadAvg>, pub uptime_secs: Option<u64>,`。
- `ProcUsage` 加 `pub rss_kb: u64,`。
- `Usage` 加 `pub mem: Option<MemInfo>, pub load: Option<LoadAvg>, pub uptime_secs: Option<u64>,`。

编译接线（桩阶段机械改动，非实现）：
- `compute` 里 `ProcUsage { … }` 构造加 `rss_kb: 0,`；`Usage { total_percent, core_percent, procs }` 改为 `Usage { total_percent, core_percent, procs, mem: None, load: None, uptime_secs: None }`。
- 测试 helper `proc()` 构造加 `rss_kb: 0,`；`snap()` 改为 `SystemSnapshot { cores, procs, ..Default::default() }`。
- `read_uid` 与 `read_snapshot` 本步不动（Step 4 接线）。

- [ ] **Step 2: 写 8 个新测试**

追加到 `mod tests` 末尾：

```rust
    #[test]
    fn parse_meminfo_ok_and_missing() {
        let text = "MemTotal:       8000000 kB\nMemFree:  1000000 kB\nMemAvailable:   3000000 kB\nBuffers:  200000 kB\n";
        let m = parse_meminfo(text).unwrap();
        assert_eq!(m.total_kb, 8000000);
        assert_eq!(m.available_kb, 3000000);
        assert_eq!(m.used_kb(), 5000000);
        assert!(parse_meminfo("MemTotal: 8000000 kB\n").is_none());
        assert!(parse_meminfo("garbage").is_none());
    }

    #[test]
    fn parse_loadavg_ok_and_garbage() {
        let l = parse_loadavg("0.52 0.48 0.45 1/234 5678\n").unwrap();
        assert!((l.one - 0.52).abs() < 1e-6);
        assert!((l.five - 0.48).abs() < 1e-6);
        assert!((l.fifteen - 0.45).abs() < 1e-6);
        assert!(parse_loadavg("0.5 0.4").is_none());
        assert!(parse_loadavg("garbage").is_none());
    }

    #[test]
    fn parse_uptime_ok_and_garbage() {
        assert_eq!(parse_uptime("12345.67 23456.78\n"), Some(12345));
        assert_eq!(parse_uptime("garbage"), None);
    }

    #[test]
    fn format_uptime_buckets() {
        assert_eq!(format_uptime(90061), "1天1小时");
        assert_eq!(format_uptime(3661), "1小时1分");
        assert_eq!(format_uptime(61), "1分1秒");
        assert_eq!(format_uptime(45), "45秒");
        assert_eq!(format_uptime(0), "0秒");
    }

    #[test]
    fn parse_status_uid_rss() {
        let text = "Name:\tsleep\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t  2048 kB\n";
        let f = parse_status(text);
        assert_eq!(f.uid, Some(1000));
        assert_eq!(f.rss_kb, 2048);
        let no_rss = parse_status("Uid:\t0\t0\t0\t0\n");
        assert_eq!(no_rss.uid, Some(0));
        assert_eq!(no_rss.rss_kb, 0);
        let g = parse_status("garbage");
        assert_eq!(g.uid, None);
        assert_eq!(g.rss_kb, 0);
    }

    #[test]
    fn format_cmdline_cases() {
        assert_eq!(format_cmdline(b"sleep\030\0"), "sleep 30");
        assert_eq!(format_cmdline(b""), "");
        assert_eq!(format_cmdline(b"\0\0"), "");
        assert_eq!(format_cmdline(b"/usr/bin/app\0--flag\0"), "/usr/bin/app --flag");
    }

    #[test]
    fn compute_irix_over_100_percent() {
        // 既有行为表征测试（终审遗留建议）：2 核各 total 1000→2000（Δ总 2000），
        // 进程 Δ2000 → 2000/2000×2×100 = 200%。预期直接通过，非 RED。
        let prev = snap(
            vec![
                CpuTimes { user: 500, idle: 500, ..Default::default() },
                CpuTimes { user: 500, idle: 500, ..Default::default() },
            ],
            vec![proc(1, 0, 0)],
        );
        let curr = snap(
            vec![
                CpuTimes { user: 1500, idle: 500, ..Default::default() },
                CpuTimes { user: 1500, idle: 500, ..Default::default() },
            ],
            vec![proc(1, 1200, 800)],
        );
        let u = compute(&prev, &curr, &HashMap::new());
        assert!((u.procs[0].cpu_percent - 200.0).abs() < 0.01);
    }

    #[test]
    fn compute_passthrough_mem_load_uptime_rss() {
        let mut prev = snap(vec![CpuTimes { user: 100, idle: 900, ..Default::default() }], vec![proc(1, 0, 0)]);
        let mut curr = snap(vec![CpuTimes { user: 200, idle: 1800, ..Default::default() }], vec![proc(1, 10, 0)]);
        curr.procs[0].rss_kb = 4096;
        curr.mem = Some(MemInfo { total_kb: 8000000, available_kb: 3000000 });
        curr.load = Some(LoadAvg { one: 0.5, five: 0.4, fifteen: 0.3 });
        curr.uptime_secs = Some(12345);
        prev.mem = Some(MemInfo { total_kb: 8000000, available_kb: 4000000 });
        let u = compute(&prev, &curr, &HashMap::new());
        assert_eq!(u.procs[0].rss_kb, 4096);
        assert_eq!(u.mem.unwrap().used_kb(), 5000000); // 取 curr 而非 prev
        assert!((u.load.unwrap().one - 0.5).abs() < 1e-6);
        assert_eq!(u.uptime_secs, Some(12345));
    }
```

- [ ] **Step 3: 跑测试确认 RED**

Run: `cargo test 2>&1 | tail -25`
Expected: 7 FAIL（6 个 `todo!()` panic：parse_meminfo/parse_loadavg/parse_uptime/format_uptime/parse_status/format_cmdline；1 个 `u.mem.unwrap()` panic：compute_passthrough_mem_load_uptime_rss 因 mem 尚为 None），9 PASS（既有 8 + compute_irix_over_100_percent 表征测试）。失败原因必须是 todo!/unwrap panic，不是编译错误。

- [ ] **Step 4: 实现全部函数与接线**

替换各桩为：

```rust
impl MemInfo {
    pub fn used_kb(self) -> u64 {
        self.total_kb.saturating_sub(self.available_kb)
    }
}

/// 解析 /proc/meminfo；缺 MemTotal 或 MemAvailable → None。
pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut total = None;
    let mut available = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:")
            && let Some(v) = rest.split_whitespace().next().and_then(|s| s.parse().ok())
        {
            total = Some(v);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:")
            && let Some(v) = rest.split_whitespace().next().and_then(|s| s.parse().ok())
        {
            available = Some(v);
        }
    }
    Some(MemInfo { total_kb: total?, available_kb: available? })
}

pub fn parse_loadavg(text: &str) -> Option<LoadAvg> {
    let mut it = text.split_whitespace();
    let one = it.next()?.parse().ok()?;
    let five = it.next()?.parse().ok()?;
    let fifteen = it.next()?.parse().ok()?;
    Some(LoadAvg { one, five, fifteen })
}

pub fn parse_uptime(text: &str) -> Option<u64> {
    let secs: f64 = text.split_whitespace().next()?.parse().ok()?;
    Some(secs.floor() as u64)
}

pub fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if days > 0 {
        format!("{days}天{hours}小时")
    } else if hours > 0 {
        format!("{hours}小时{mins}分")
    } else if mins > 0 {
        format!("{mins}分{s}秒")
    } else {
        format!("{s}秒")
    }
}

pub fn parse_status(text: &str) -> StatusFields {
    let mut f = StatusFields::default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            f.uid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            f.rss_kb = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }
    f
}

pub fn read_status(pid: i32) -> StatusFields {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .map(|s| parse_status(&s))
        .unwrap_or_default()
}

pub fn format_cmdline(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace('\0', " ").trim().to_string()
}

pub fn read_cmdline(pid: i32) -> String {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| format_cmdline(&b))
        .unwrap_or_default()
}
```

`read_snapshot` 接线：删除 `read_uid` 函数；进程循环里 `p.uid = read_uid(pid).unwrap_or(u32::MAX);` 替换为：

```rust
            let st = read_status(pid);
            p.uid = st.uid.unwrap_or(u32::MAX);
            p.rss_kb = st.rss_kb;
```

`read_snapshot` 末尾（`snap.procs` 循环结束后、`snap` 返回前）加：

```rust
    snap.mem = fs::read_to_string("/proc/meminfo").ok().and_then(|s| parse_meminfo(&s));
    snap.load = fs::read_to_string("/proc/loadavg").ok().and_then(|s| parse_loadavg(&s));
    snap.uptime_secs = fs::read_to_string("/proc/uptime").ok().and_then(|s| parse_uptime(&s));
```

`compute` 透传：`ProcUsage` 构造的 `rss_kb: 0,` 改 `rss_kb: p.rss_kb,`；`Usage` 构造的 `mem: None, load: None, uptime_secs: None` 改 `mem: curr.mem, load: curr.load, uptime_secs: curr.uptime_secs`。

- [ ] **Step 5: 跑测试与 clippy 确认 GREEN**

Run: `cargo test 2>&1 | tail -5` → Expected: 16 passed; 0 failed。
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -3` → Expected: Finished，零警告（allow(dead_code) 在位）。
Run: `cargo build 2>&1 | tail -3` → Expected: Finished，零警告。

- [ ] **Step 6: 无提交（全局约束），自查后写报告**

---

### Task 2: 顶部展示增强（内存条/系统信息行/CPU 历史曲线）

**Files:**
- Modify: `src/app.rs`（现 338 行）
- Modify: `src/main.rs`（窗口高度）

**Interfaces:**
- Consumes: T1 的 `Usage.mem/load/uptime_secs`、`MemInfo.used_kb()`、`format_uptime`。
- Produces: `CpuManagerApp.history: VecDeque<f32>`（上限 60）、`fn resample(&mut self)`（采样+计时重置+历史推入+失效选中清理，T3 的立即刷新/暂停复用）、`fn sparkline(&self, ui: &mut egui::Ui)`。

- [ ] **Step 1: history 字段 + resample() 抽取与接线**

`src/app.rs` 导入改：

```rust
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, Pos2, RichText, Stroke, Vec2};
use egui_extras::{Column, TableBuilder};

use crate::actions::{self, ActionError};
use crate::procstats::{ProcUsage, Sampler, Usage, format_uptime};
```

`CpuManagerApp` 加字段 `history: VecDeque<f32>,`；`new()` 初始化加 `history: VecDeque::new(),`；`new()` 末尾 `app.usage = app.sampler.sample();` 改为 `app.resample();`。

新增方法（放在 `report` 前）：

```rust
    fn resample(&mut self) {
        self.usage = self.sampler.sample();
        self.last_sample = Instant::now();
        self.history.push_back(self.usage.total_percent);
        if self.history.len() > 60 {
            self.history.pop_front();
        }
        if let Some(pid) = self.selected
            && !self.usage.procs.iter().any(|p| p.pid == pid)
        {
            self.selected = None;
        }
    }
```

`report()` 的 Gone 分支整体（`self.usage = …` 到 selected 清理的 `}`）替换为单行 `self.resample();`。
`ui()` 的 tick 块替换为：

```rust
        if self.last_sample.elapsed() >= Duration::from_secs(1) {
            self.resample();
        }
```

- [ ] **Step 2: top_panel 重写 + sparkline**

`top_panel` 整体替换为：

```rust
    fn top_panel(&self, ui: &mut egui::Ui) {
        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("CPU 管理器");
                ui.separator();
                ui.label(RichText::new(format!("{:.1}%", self.usage.total_percent)).size(28.0).strong());
                ui.add(egui::ProgressBar::new(self.usage.total_percent / 100.0).desired_width(200.0));
                self.sparkline(ui);
            });
            ui.horizontal(|ui| {
                for (i, p) in self.usage.core_percent.iter().enumerate() {
                    ui.label(format!("核{i}"));
                    ui.add(egui::ProgressBar::new(p / 100.0).desired_width(90.0).text(format!("{p:.0}%")));
                }
            });
            if let Some(mem) = self.usage.mem {
                ui.horizontal(|ui| {
                    ui.label("内存");
                    let frac = if mem.total_kb == 0 { 0.0 } else { mem.used_kb() as f32 / mem.total_kb as f32 };
                    ui.add(egui::ProgressBar::new(frac).desired_width(200.0));
                    ui.label(format!("{:.1} / {:.1} GB", mem.used_kb() as f64 / 1048576.0, mem.total_kb as f64 / 1048576.0));
                });
            }
            ui.horizontal(|ui| {
                let mut parts: Vec<String> = Vec::new();
                if let Some(l) = self.usage.load {
                    parts.push(format!("负载 {:.2} {:.2} {:.2}", l.one, l.five, l.fifteen));
                }
                if let Some(up) = self.usage.uptime_secs {
                    parts.push(format!("已运行 {}", format_uptime(up)));
                }
                parts.push(format!("共 {} 个进程", self.usage.procs.len()));
                ui.label(RichText::new(parts.join(" · ")).small());
            });
            ui.add_space(4.0);
        });
    }

    fn sparkline(&self, ui: &mut egui::Ui) {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(200.0, 36.0), egui::Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, Color32::from_gray(24));
        let y50 = rect.top() + rect.height() * 0.5;
        painter.line_segment(
            [Pos2::new(rect.left(), y50), Pos2::new(rect.right(), y50)],
            Stroke::new(1.0, Color32::from_gray(60)),
        );
        let n = self.history.len();
        if n >= 2 {
            let pts: Vec<Pos2> = self
                .history
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let x = rect.left() + rect.width() * (i as f32 / (n - 1) as f32);
                    let y = rect.bottom() - rect.height() * (v.clamp(0.0, 100.0) / 100.0);
                    Pos2::new(x, y)
                })
                .collect();
            for pair in pts.windows(2) {
                painter.line_segment([pair[0], pair[1]], Stroke::new(1.5, Color32::from_rgb(90, 170, 250)));
            }
        }
    }
```

- [ ] **Step 3: 过滤行计数挪走 + 窗口高度**

`central()` 过滤行删除 `ui.label(format!("共 {} 个进程", self.usage.procs.len()));`（已挪到顶部信息行）。
`src/main.rs` 的 `with_inner_size([920.0, 620.0])` 改 `with_inner_size([920.0, 700.0])`。

- [ ] **Step 4: 验证**

Run: `cargo build 2>&1 | tail -3` → 零警告。
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -3` → 干净。
Run: `cargo test 2>&1 | tail -3` → 16 passed。
（GUI 层无单测为既定约定，真机冒烟在 Task 4。）

- [ ] **Step 5: 无提交，自查后写报告**

---

### Task 3: 交互与表格增强（内存列/cmdline/刷新控制/Delete 键）

**Files:**
- Modify: `src/app.rs`
- Modify: `src/procstats.rs`（仅移除临时 allow(dead_code)）

**Interfaces:**
- Consumes: T1 的 `ProcUsage.rss_kb`、`read_cmdline`；T2 的 `resample()`。
- Produces: `SortCol::Mem`；`Confirm.cmdline: String`；`fn ask_confirm(&mut self, kind: ConfirmKind, pid: i32, comm: &str)`；`fn truncate_chars(s: &str, max: usize) -> String`（模块级私有）；`paused: bool`、`cmdline_cache: Option<(i32, String)>` 字段。

- [ ] **Step 1: 内存列与排序**

`SortCol` 枚举加 `Mem,`（放 `Cpu,` 后）。
`visible_rows()` 的 match 加臂：`SortCol::Mem => a.rss_kb.cmp(&b.rss_kb),`。
表头切换默认方向：`self.sort_desc = col == SortCol::Cpu;` 改 `self.sort_desc = col == SortCol::Cpu || col == SortCol::Mem;`。
`TableBuilder` 列定义：在 CPU% 的 `.column(Column::exact(80.0))` 之后加 `.column(Column::exact(80.0))`（内存列）。
表头数组在 `(SortCol::Cpu, "CPU%"),` 后加 `(SortCol::Mem, "内存MB"),`。
表体在 CPU% 单元格 `row.col(|ui| { ui.label(format!("{:.1}", p.cpu_percent)); });` 后加：

```rust
                        row.col(|ui| { ui.label(format!("{:.1}", p.rss_kb as f32 / 1024.0)); });
```

- [ ] **Step 2: 刷新控制 + Delete 键**

`CpuManagerApp` 加字段 `paused: bool,`，`new()` 初始化 `paused: false,`。
`ui()` tick 条件改：`if !self.paused && self.last_sample.elapsed() >= Duration::from_secs(1) {`。
`central()` 过滤行（计数已删）改为：

```rust
            ui.horizontal(|ui| {
                ui.label("过滤:");
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("名称或 PID").desired_width(200.0));
                if ui.button("立即刷新").clicked() {
                    self.resample();
                }
                let pause_label = if self.paused { "继续刷新" } else { "暂停刷新" };
                if ui.button(pause_label).clicked() {
                    self.paused = !self.paused;
                }
            });
```

`ui()` 开头（tick 之前）加 Delete 键处理：

```rust
        if self.confirm.is_none()
            && self.nice_dialog.is_none()
            && ui.input(|i| i.key_pressed(egui::Key::Delete))
            && let Some(pid) = self.selected
            && pid != self.own_pid
            && pid != 1
        {
            let comm = self.usage.procs.iter().find(|p| p.pid == pid).map(|p| p.comm.clone());
            if let Some(comm) = comm {
                self.ask_confirm(ConfirmKind::Terminate, pid, &comm);
            }
        }
```

- [ ] **Step 3: cmdline 缓存、显示与确认框**

导入加 `read_cmdline`：`use crate::procstats::{ProcUsage, Sampler, Usage, format_uptime, read_cmdline};`。
`CpuManagerApp` 加字段 `cmdline_cache: Option<(i32, String)>,`，`new()` 初始化 `cmdline_cache: None,`。
`ui()` 里 tick 之后、面板调用之前加：

```rust
        match self.selected {
            Some(pid) => {
                if self.cmdline_cache.as_ref().is_none_or(|(p, _)| *p != pid) {
                    let mut cmd = read_cmdline(pid);
                    if cmd.is_empty() {
                        cmd = self
                            .usage
                            .procs
                            .iter()
                            .find(|p| p.pid == pid)
                            .map(|p| format!("[{}]", p.comm))
                            .unwrap_or_default();
                    }
                    self.cmdline_cache = Some((pid, cmd));
                }
            }
            None => self.cmdline_cache = None,
        }
```

`central()` 过滤行之后、`let rows = self.visible_rows();` 之前加：

```rust
            if let Some((_, cmd)) = &self.cmdline_cache {
                ui.label(RichText::new(format!("命令行: {}", truncate_chars(cmd, 160))).small());
            }
```

`Confirm` 结构加 `cmdline: String,`。新增方法（放 `report` 后）：

```rust
    fn ask_confirm(&mut self, kind: ConfirmKind, pid: i32, comm: &str) {
        let mut cmdline = read_cmdline(pid);
        if cmdline.is_empty() {
            cmdline = format!("[{comm}]");
        }
        self.confirm = Some(Confirm { kind, pid, comm: comm.to_string(), cmdline });
    }
```

`bottom_panel` 两处确认框构造替换：
- Terminate 按钮分支的 `self.confirm = Some(Confirm { kind: ConfirmKind::Terminate, pid: *pid, comm: comm.clone() });` → `self.ask_confirm(ConfirmKind::Terminate, *pid, comm);`
- Kill 按钮分支同理 → `self.ask_confirm(ConfirmKind::Kill, *pid, comm);`

`dialogs()` 确认框：拷贝元组改 `let confirm = self.confirm.as_ref().map(|c| (c.kind, c.pid, c.comm.clone(), c.cmdline.clone()));`，解构改 `if let Some((kind, pid, comm, cmdline)) = confirm {`；问题 label 之后加：

```rust
                ui.label(RichText::new(format!("命令行: {}", truncate_chars(&cmdline, 160))).small());
```

模块级（`load_cjk_font` 前）加：

```rust
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}
```

- [ ] **Step 4: 移除 procstats.rs 顶部临时 `#![allow(dead_code)]`**

此时全部新函数已被 app 接线（read_cmdline/format_uptime），dead_code 应自然干净。

- [ ] **Step 5: 验证**

Run: `cargo build 2>&1 | tail -3` → 零警告。
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -3` → 干净（若 read_cmdline 等仍报 dead_code，说明接线遗漏，修到干净为止，不得恢复 allow）。
Run: `cargo test 2>&1 | tail -3` → 16 passed。

- [ ] **Step 6: 无提交，自查后写报告**

---

### Task 4: Release 构建 + 真机冒烟 + 交付准备

**Files:**
- Modify: 无源码改动（仅构建与运行验证；如发现 bug 回对应任务修）

**Interfaces:**
- Consumes: T1–T3 全部成果。
- Produces: `target/release/cpu-manager` 新二进制；运行中的 GUI 实例；验证记录。

- [ ] **Step 1: Release 构建**

Run: `cargo build --release 2>&1 | tail -3`（增量约 1–2 分钟；必要时后台跑）
Expected: Finished，零警告。

- [ ] **Step 2: 全量验证**

Run: `cargo test 2>&1 | tail -3` → 16 passed; 0 failed。
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -3` → 干净。

- [ ] **Step 3: 重拉 GUI 冒烟**

当前旧实例 PID 42514（controller 自起进程，可 kill）。Run:

```bash
kill 42514; sleep 1
setsid nohup ./target/release/cpu-manager >/tmp/cpu-manager-gui.log 2>&1 </dev/null &
sleep 3; pgrep -x cpu-manager; wc -c /tmp/cpu-manager-gui.log
```

Expected: 新 PID 存在；日志 0 字节。若旧 PID 已不在，跳过 kill 直接启动。
（窗口内容目视验收由用户完成：内存行/信息行/曲线/内存列/命令行/刷新按钮。）

- [ ] **Step 4: 无提交，写报告（含新 PID、验证输出）**