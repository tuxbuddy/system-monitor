# CPU 管理器 v3 Implementation Plan（内存扩展 + 能效/供电监控）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 v2 基础上做全内存监控（细分/Swap/每进程内存%）并新增 Pi 500 能效与供电监控（温度/频率/核心功耗/供电电压/节流状态）。

**Architecture:** procstats.rs 扩展 /proc 内存数据（纯函数+单测）；新增 pi.rs 隔离硬件传感器（sysfs 温度/频率纯文件读 + vcgencmd 功耗/节流子进程，纯解析器与 IO 分离）；app.rs 集成能效/供电行、内存 Swap+详情、供电详情、内存% 列。

**Tech Stack:** Rust 1.99 / eframe+egui 0.37 / egui_extras 0.37 / nix 0.31 / libc 0.2；std::fs（sysfs/proc）+ std::process::Command（vcgencmd）；无新增 crate。

**Spec:** docs/superpowers/specs/2026-11-11-cpu-manager-v3-design.md

## Global Constraints

- 无 git 提交（本机无提交身份，禁止改 git config）；评审用工作区快照 `diff -u`。
- 无新增 crate 依赖；vcgencmd 经 `std::process::Command`，sysfs/proc 经 `std::fs`。
- 界面中文文案逐字照抄本计划，不改写、不增删。
- 采样每秒一次；`pi::read_pi_stats()` 在 `resample()` 内调用，与采样同节奏。
- 安全语义不变：调控按钮/确认框/Delete 守卫（含 `!text_edit_focused()`）/ESRCH 即时刷新/EPERM 提示/自身与 PID1 保护。
- egui 0.37 已核验 API：`CollapsingHeader::new(impl Into<WidgetText>).default_open(bool).show(&mut Ui, impl FnOnce(&mut Ui)->R)`（collapsing_header.rs:392/451/649）；`Panel::top/bottom(...).show(ui,…)`、`ProgressBar::new(f32).desired_width(f32)`、`RichText::new(...).color(Color32).small()`、`Color32::from_rgb/u8`、`ui.separator()` 沿用 v2。
- 门禁：`cargo build` 零警告 + `cargo clippy --all-targets -- -D warnings` 干净 + `cargo test` 全量通过。
- T1 必须修正既有 `compute_passthrough_mem_load_uptime_rss` 测试的 `MemInfo` 构造为 `..Default::default()`（新增字段否则编译失败）。
- 子代理不得再派生子代理（无助手、无评审）；评审对 checkout 只读。
- 功耗口径：只报核心功耗（VDD_CORE_V×A）+ 各 rail 明细，不报整板总功耗。频率 headline = 各核平均。

---

### Task 1: procstats 内存扩展

**Files:**
- Modify: `src/procstats.rs`（MemInfo 结构/parse_meminfo/swap_used_kb、ProcUsage.mem_percent、compute、测试）

**Interfaces:**
- Consumes: 既有 `SystemSnapshot{mem:Option<MemInfo>,…}`、`ProcSnapshot{rss_kb,…}`、`compute(prev,curr,users)->Usage`。
- Produces: `MemInfo{total_kb,available_kb,free_kb,buffers_kb,cached_kb,swap_total_kb,swap_free_kb}` + `used_kb()/swap_used_kb()`；`ProcUsage.mem_percent:f32`；`parse_meminfo(&str)->Option<MemInfo>`（要求 MemTotal+MemAvailable）。T3 消费这些字段。

- [ ] **Step 1: 扩展结构 + 桩 + 写失败测试**

在 `src/procstats.rs` 把 `MemInfo` 结构改为：

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemInfo {
    pub total_kb: u64,
    pub available_kb: u64,
    pub free_kb: u64,
    pub buffers_kb: u64,
    pub cached_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

impl MemInfo {
    pub fn used_kb(self) -> u64 {
        self.total_kb.saturating_sub(self.available_kb)
    }
    pub fn swap_used_kb(self) -> u64 {
        todo!()
    }
}
```

把 `parse_meminfo` 的返回行临时改为（保留旧解析逻辑，新字段暂为 0）：

```rust
    Some(MemInfo { total_kb: total?, available_kb: available?, ..Default::default() })
```

在 `ProcUsage` 结构末尾加字段 `pub mem_percent: f32,`；在 `compute` 的 `ProcUsage { … rss_kb: p.rss_kb, }` 构造里临时加 `mem_percent: 0.0,`。

把既有测试 `compute_passthrough_mem_load_uptime_rss` 里两处 `MemInfo { total_kb: …, available_kb: … }` 改为带 `..Default::default()`：

```rust
        curr.mem = Some(MemInfo { total_kb: 8000000, available_kb: 3000000, ..Default::default() });
        prev.mem = Some(MemInfo { total_kb: 8000000, available_kb: 4000000, ..Default::default() });
```

在 `mod tests` 末尾加两个测试：

```rust
    #[test]
    fn parse_meminfo_full_fields() {
        let text = "MemTotal:       8000000 kB\nMemFree:  1000000 kB\nMemAvailable:   3000000 kB\nBuffers:  200000 kB\nCached:   1500000 kB\nSwapCached: 0 kB\nSwapTotal: 2000000 kB\nSwapFree: 1500000 kB\n";
        let m = parse_meminfo(text).unwrap();
        assert_eq!(m.free_kb, 1000000);
        assert_eq!(m.buffers_kb, 200000);
        assert_eq!(m.cached_kb, 1500000);
        assert_eq!(m.swap_total_kb, 2000000);
        assert_eq!(m.swap_free_kb, 1500000);
        assert_eq!(m.swap_used_kb(), 500000);
    }

    #[test]
    fn compute_mem_percent() {
        let mut curr = snap(vec![CpuTimes { user: 100, idle: 900, ..Default::default() }], vec![proc(1, 0, 0)]);
        curr.procs[0].rss_kb = 800000;
        curr.mem = Some(MemInfo { total_kb: 8000000, available_kb: 3000000, ..Default::default() });
        let prev = curr.clone();
        let u = compute(&prev, &curr, &HashMap::new());
        assert!((u.procs[0].mem_percent - 10.0).abs() < 0.01);

        let mut curr0 = snap(vec![CpuTimes { user: 100, idle: 900, ..Default::default() }], vec![proc(1, 0, 0)]);
        curr0.procs[0].rss_kb = 800000;
        curr0.mem = Some(MemInfo::default());
        let u0 = compute(&curr0.clone(), &curr0, &HashMap::new());
        assert_eq!(u0.procs[0].mem_percent, 0.0);
    }
```

- [ ] **Step 2: 运行确认 RED**

Run: `cargo test --bin cpu-manager procstats 2>&1 | tail -30`
Expected: `parse_meminfo_full_fields` FAIL（free_kb 0≠1000000，且 swap_used_kb `todo!()` panic）；`compute_mem_percent` FAIL（0≠10）；既有测试 PASS。

- [ ] **Step 3: 实现 parse_meminfo / swap_used_kb / compute mem_percent**

把 `parse_meminfo` 整体替换为：

```rust
/// 解析 /proc/meminfo；缺 MemTotal 或 MemAvailable → None，其余字段缺省 0。
pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut m = MemInfo::default();
    let mut have_total = false;
    let mut have_avail = false;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let key = it.next().unwrap_or("");
        let Some(v) = it.next().and_then(|s| s.parse::<u64>().ok()) else { continue };
        match key {
            "MemTotal:" => { m.total_kb = v; have_total = true; }
            "MemAvailable:" => { m.available_kb = v; have_avail = true; }
            "MemFree:" => m.free_kb = v,
            "Buffers:" => m.buffers_kb = v,
            "Cached:" => m.cached_kb = v,
            "SwapTotal:" => m.swap_total_kb = v,
            "SwapFree:" => m.swap_free_kb = v,
            _ => {}
        }
    }
    if have_total && have_avail { Some(m) } else { None }
}
```

把 `swap_used_kb` 桩替换为：

```rust
    pub fn swap_used_kb(self) -> u64 {
        self.swap_total_kb.saturating_sub(self.swap_free_kb)
    }
```

在 `compute` 里 `let prev_map …` 之前加一行：

```rust
    let mem_total_kb = curr.mem.map(|m| m.total_kb).unwrap_or(0);
```

把 procs 闭包里的 `mem_percent: 0.0,` 替换为真实计算——在闭包内 `let cpu = …;` 之后加：

```rust
            let mem_percent = if mem_total_kb == 0 {
                0.0
            } else {
                p.rss_kb as f32 / mem_total_kb as f32 * 100.0
            };
```

并把构造里的 `mem_percent: 0.0,` 改为 `mem_percent,`。

- [ ] **Step 4: 运行确认 GREEN**

Run: `cargo test --bin cpu-manager procstats 2>&1 | tail -25`
Expected: 全部 procstats 测试 PASS（含两个新测试与修正后的 compute_passthrough）。

- [ ] **Step 5: clippy + 快照（无提交）**

Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -5`
Expected: 干净（Finished，无警告）。
快照：`cp src/procstats.rs .superpowers/sdd/2026-11-11-cpu-manager-v3/procstats.rs.pre-t1`（先建目录）。

---

### Task 2: pi.rs 硬件传感器模块

**Files:**
- Create: `src/pi.rs`
- Modify: `src/main.rs`（加 `mod pi;`）

**Interfaces:**
- Consumes: 无（独立模块，std::fs + std::process::Command）。
- Produces: `Rail{name:String,volts:f32,amps:f32}+watts()`；`Power{core_v,core_a,core_w,ext5v_v}`；`Throttle{undervoltage,freq_capped,throttled,soft_temp_limit,occurred}+any_current()/warning()`；`PiStats{temp_c:Option<f32>,freq_ghz:Option<f32>,power:Option<Power>,throttle:Option<Throttle>,rails:Vec<Rail>}`；`read_pi_stats()->PiStats`；纯解析器 `parse_temp_millideg/parse_freq_khz/parse_pmic/power_summary/parse_throttled`。T3 消费 `PiStats` 与 `read_pi_stats`。

- [ ] **Step 1: 创建 pi.rs（结构 + 桩 + 测试）+ main.rs 加 mod**

创建 `src/pi.rs`：

```rust
use std::fs;
use std::process::Command;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Rail {
    pub name: String,
    pub volts: f32,
    pub amps: f32,
}

impl Rail {
    pub fn watts(&self) -> f32 {
        self.volts * self.amps
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Power {
    pub core_v: f32,
    pub core_a: f32,
    pub core_w: f32,
    pub ext5v_v: f32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Throttle {
    pub undervoltage: bool,
    pub freq_capped: bool,
    pub throttled: bool,
    pub soft_temp_limit: bool,
    pub occurred: bool,
}

impl Throttle {
    pub fn any_current(self) -> bool {
        todo!()
    }
    pub fn warning(self) -> String {
        todo!()
    }
}

#[derive(Clone, Debug, Default)]
pub struct PiStats {
    pub temp_c: Option<f32>,
    pub freq_ghz: Option<f32>,
    pub power: Option<Power>,
    pub throttle: Option<Throttle>,
    pub rails: Vec<Rail>,
}

pub fn parse_temp_millideg(_text: &str) -> Option<f32> {
    todo!()
}

pub fn parse_freq_khz(_text: &str) -> Option<u64> {
    todo!()
}

pub fn parse_pmic(_text: &str) -> Vec<Rail> {
    todo!()
}

pub fn power_summary(_rails: &[Rail]) -> Power {
    todo!()
}

pub fn parse_throttled(_text: &str) -> Option<Throttle> {
    todo!()
}

fn run_vcgencmd(_args: &[&str]) -> Option<String> {
    todo!()
}

pub fn read_pi_stats() -> PiStats {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_millideg() {
        assert!((parse_temp_millideg("50700\n").unwrap() - 50.7).abs() < 0.01);
        assert_eq!(parse_temp_millideg("garbage"), None);
    }

    #[test]
    fn freq_khz() {
        assert_eq!(parse_freq_khz("2400000\n"), Some(2400000));
        assert_eq!(parse_freq_khz("x"), None);
    }

    const PMIC: &str = " VDD_CORE_A current(7)=2.73258000A\n VDD_CORE_V volt(15)=0.86495640V\n EXT5V_V volt(24)=5.10138000V\n 3V3_SYS_A current(1)=0.14150990A\n 3V3_SYS_V volt(9)=3.29982600V\n";

    #[test]
    fn pmic_pairs_rails() {
        let rails = parse_pmic(PMIC);
        let core = rails.iter().find(|r| r.name == "VDD_CORE").unwrap();
        assert!((core.volts - 0.86495640).abs() < 1e-4);
        assert!((core.amps - 2.73258000).abs() < 1e-4);
        let ext = rails.iter().find(|r| r.name == "EXT5V").unwrap();
        assert!((ext.volts - 5.10138).abs() < 1e-4);
        assert_eq!(ext.amps, 0.0);
        assert_eq!(rails.len(), 3);
    }

    #[test]
    fn power_summary_core_watts() {
        let p = power_summary(&parse_pmic(PMIC));
        assert!((p.core_w - 0.86495640 * 2.73258000).abs() < 1e-3);
        assert!((p.ext5v_v - 5.10138).abs() < 1e-4);
    }

    #[test]
    fn throttled_decode() {
        let t0 = parse_throttled("throttled=0x0\n").unwrap();
        assert!(!t0.any_current());
        assert!(!t0.occurred);
        let t1 = parse_throttled("throttled=0x50005\n").unwrap();
        assert!(t1.undervoltage);
        assert!(t1.throttled);
        assert!(!t1.freq_capped);
        assert!(t1.occurred);
        assert!(t1.any_current());
        assert_eq!(parse_throttled("garbage"), None);
    }

    #[test]
    fn throttle_warning_text() {
        let t = Throttle { undervoltage: true, throttled: true, occurred: true, ..Default::default() };
        let w = t.warning();
        assert!(w.contains("欠压"));
        assert!(w.contains("节流"));
        assert!(w.contains("历史"));
        assert_eq!(Throttle::default().warning(), "");
    }

    #[test]
    fn read_pi_stats_smoke() {
        // Pi 500 真机冒烟：温度/频率/功耗/节流均应可得（与 actions 集成测试同属环境相关）
        let s = read_pi_stats();
        assert!(s.temp_c.is_some());
        assert!(s.freq_ghz.is_some());
        assert!(s.power.is_some());
        assert!(s.throttle.is_some());
        assert!(!s.rails.is_empty());
    }
}
```

在 `src/main.rs` 顶部 mod 声明加一行（保持字母序）：

```rust
mod actions;
mod app;
mod pi;
mod procstats;
```

- [ ] **Step 2: 运行确认 RED**

Run: `cargo test --bin cpu-manager pi:: 2>&1 | tail -30`
Expected: pi::tests 全部 FAIL（`todo!()` panic）；编译通过（桩用 `_text`/`_args` 避免未用警告）。

- [ ] **Step 3: 实现解析器与 IO**

把 `Throttle::any_current`/`warning` 桩替换为：

```rust
    pub fn any_current(self) -> bool {
        self.undervoltage || self.freq_capped || self.throttled || self.soft_temp_limit
    }

    pub fn warning(self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.undervoltage { parts.push("欠压"); }
        if self.freq_capped { parts.push("降频"); }
        if self.throttled { parts.push("节流"); }
        if self.soft_temp_limit { parts.push("温度限制"); }
        let mut s = parts.join("/");
        if self.occurred {
            if s.is_empty() { s = "曾发生节流".to_string(); } else { s.push_str("（含历史）"); }
        }
        s
    }
```

把五个解析器桩替换为：

```rust
pub fn parse_temp_millideg(text: &str) -> Option<f32> {
    let v: i64 = text.split_whitespace().next()?.parse().ok()?;
    Some(v as f32 / 1000.0)
}

pub fn parse_freq_khz(text: &str) -> Option<u64> {
    text.split_whitespace().next()?.parse().ok()
}

/// 解析 vcgencmd pmic_read_adc：按 _V/_A 去后缀配对 base name，保持首见顺序。
pub fn parse_pmic(text: &str) -> Vec<Rail> {
    use std::collections::HashMap;
    let mut map: HashMap<String, (f32, f32)> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some(label) = line.split_whitespace().next() else { continue };
        let Some(rest) = line.split('=').nth(1) else { continue };
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
        let Ok(val) = num.parse::<f32>() else { continue };
        let (base, is_volt) = if let Some(b) = label.strip_suffix("_V") {
            (b, true)
        } else if let Some(b) = label.strip_suffix("_A") {
            (b, false)
        } else {
            continue;
        };
        if !order.iter().any(|n| n.as_str() == base) {
            order.push(base.to_string());
        }
        let entry = map.entry(base.to_string()).or_insert((0.0, 0.0));
        if is_volt { entry.0 = val; } else { entry.1 = val; }
    }
    order
        .into_iter()
        .map(|name| {
            let (volts, amps) = map.get(&name).copied().unwrap_or((0.0, 0.0));
            Rail { name, volts, amps }
        })
        .collect()
}

pub fn power_summary(rails: &[Rail]) -> Power {
    let mut p = Power::default();
    for r in rails {
        match r.name.as_str() {
            "VDD_CORE" => { p.core_v = r.volts; p.core_a = r.amps; p.core_w = r.watts(); }
            "EXT5V" => p.ext5v_v = r.volts,
            _ => {}
        }
    }
    p
}

pub fn parse_throttled(text: &str) -> Option<Throttle> {
    let hex = text.split("throttled=0x").nth(1)?.split_whitespace().next()?;
    let bits = u32::from_str_radix(hex, 16).ok()?;
    Some(Throttle {
        undervoltage: bits & 1 != 0,
        freq_capped: bits & (1 << 1) != 0,
        throttled: bits & (1 << 2) != 0,
        soft_temp_limit: bits & (1 << 3) != 0,
        occurred: (bits >> 16) & 0xF != 0,
    })
}
```

把 `run_vcgencmd`/`read_pi_stats` 桩替换为：

```rust
fn run_vcgencmd(args: &[&str]) -> Option<String> {
    let out = Command::new("vcgencmd").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

pub fn read_pi_stats() -> PiStats {
    let temp_c = fs::read_to_string("/sys/class/thermal/thermal_zone0/temp")
        .ok()
        .and_then(|s| parse_temp_millideg(&s));

    let mut freqs: Vec<f32> = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") {
        for e in entries.flatten() {
            let name = e.file_name();
            let n = name.to_str().unwrap_or("");
            let suffix = n.strip_prefix("cpu").unwrap_or("");
            if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(s) = fs::read_to_string(e.path().join("cpufreq/scaling_cur_freq"))
                && let Some(khz) = parse_freq_khz(&s)
            {
                freqs.push(khz as f32 / 1_000_000.0);
            }
        }
    }
    let freq_ghz = if freqs.is_empty() {
        None
    } else {
        Some(freqs.iter().sum::<f32>() / freqs.len() as f32)
    };

    let rails = run_vcgencmd(&["pmic_read_adc"]).map(|s| parse_pmic(&s)).unwrap_or_default();
    let power = if rails.is_empty() { None } else { Some(power_summary(&rails)) };
    let throttle = run_vcgencmd(&["get_throttled"]).and_then(|s| parse_throttled(&s));

    PiStats { temp_c, freq_ghz, power, throttle, rails }
}
```

- [ ] **Step 4: 运行确认 GREEN**

Run: `cargo test --bin cpu-manager pi:: 2>&1 | tail -25`
Expected: pi::tests 7 个全 PASS（含真机 read_pi_stats_smoke）。

- [ ] **Step 5: clippy + 快照（无提交）**

Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -5`
Expected: 干净。
快照：`cp src/pi.rs .superpowers/sdd/2026-11-11-cpu-manager-v3/pi.rs.pre-t3`。

---

### Task 3: app.rs UI 集成

**Files:**
- Modify: `src/app.rs`（import、pi 字段、resample、SortCol::MemPct、visible_rows、top_panel、central 表格）
- Modify: `src/main.rs`（窗口高度 700→760）

**Interfaces:**
- Consumes: T1 `MemInfo{free_kb,buffers_kb,cached_kb,swap_total_kb,swap_free_kb,swap_used_kb()}`、`ProcUsage.mem_percent`；T2 `pi::{PiStats,read_pi_stats}`、`Throttle::{any_current,warning}`、`Rail::{name,volts,amps,watts}`、`Power::{core_w,ext5v_v}`。
- Produces: 完整 v3 GUI（无下游任务）。

- [ ] **Step 1: import + pi 字段 + resample + 排序**

`src/app.rs` 把 use 行改为：

```rust
use crate::actions::{self, ActionError};
use crate::pi::{self, PiStats};
use crate::procstats::{ProcUsage, Sampler, Usage, format_uptime, read_cmdline};
```

`SortCol` 枚举加变体（放在 Mem 之后）：

```rust
enum SortCol {
    Cpu,
    Mem,
    MemPct,
    Pid,
    Name,
    User,
    Nice,
    State,
}
```

`CpuManagerApp` 结构加字段 `pi: PiStats,`（放在 `cmdline_cache` 之后）；`new()` 初始化列表加 `pi: PiStats::default(),`（放在 `cmdline_cache: None,` 之后）。

`resample()` 在 `self.usage = self.sampler.sample();` 之后加一行：

```rust
        self.pi = pi::read_pi_stats();
```

`visible_rows` 的 match 加臂（放在 `SortCol::Mem` 之后）：

```rust
                SortCol::MemPct => a.mem_percent.partial_cmp(&b.mem_percent).unwrap_or(std::cmp::Ordering::Equal),
```

- [ ] **Step 2: top_panel 内存 Swap + 能效/供电行 + 折叠详情**

把 `top_panel` 里既有内存块（`if let Some(mem) = self.usage.mem { … }`）整体替换为：

```rust
            if let Some(mem) = self.usage.mem {
                ui.horizontal(|ui| {
                    ui.label("内存");
                    let frac = if mem.total_kb == 0 { 0.0 } else { mem.used_kb() as f32 / mem.total_kb as f32 };
                    ui.add(egui::ProgressBar::new(frac).desired_width(160.0));
                    ui.label(format!("{:.1}/{:.1} GB", mem.used_kb() as f64 / 1048576.0, mem.total_kb as f64 / 1048576.0));
                    ui.separator();
                    ui.label("Swap");
                    let sfrac = if mem.swap_total_kb == 0 { 0.0 } else { mem.swap_used_kb() as f32 / mem.swap_total_kb as f32 };
                    ui.add(egui::ProgressBar::new(sfrac).desired_width(100.0));
                    ui.label(format!("{:.0}/{:.0} MB", mem.swap_used_kb() as f64 / 1024.0, mem.swap_total_kb as f64 / 1024.0));
                });
            }
            ui.horizontal(|ui| {
                let temp = self.pi.temp_c.map(|t| format!("{t:.1}°C")).unwrap_or_else(|| "—".to_string());
                let freq = self.pi.freq_ghz.map(|f| format!("{f:.2} GHz")).unwrap_or_else(|| "—".to_string());
                let (pw, sv) = match self.pi.power {
                    Some(p) => (format!("{:.2} W", p.core_w), format!("{:.2} V", p.ext5v_v)),
                    None => ("—".to_string(), "—".to_string()),
                };
                ui.label(format!("温度 {temp} · 频率 {freq} · 核心功耗 {pw} · 供电 {sv}"));
                if let Some(th) = self.pi.throttle {
                    if th.any_current() {
                        ui.label(RichText::new(th.warning()).color(Color32::from_rgb(255, 120, 120)));
                    } else if th.occurred {
                        ui.label(RichText::new(th.warning()).color(Color32::YELLOW).small());
                    } else {
                        ui.label(RichText::new("供电正常").color(Color32::from_rgb(120, 200, 120)).small());
                    }
                }
            });
            egui::CollapsingHeader::new("内存详情").default_open(false).show(ui, |ui| {
                if let Some(m) = self.usage.mem {
                    ui.label(format!("空闲 {:.0} MB · 缓冲 {:.0} MB · 缓存 {:.0} MB", m.free_kb as f64 / 1024.0, m.buffers_kb as f64 / 1024.0, m.cached_kb as f64 / 1024.0));
                    ui.label(format!("Swap 已用 {:.0} / {:.0} MB", m.swap_used_kb() as f64 / 1024.0, m.swap_total_kb as f64 / 1024.0));
                } else {
                    ui.label("—");
                }
            });
            egui::CollapsingHeader::new("供电详情").default_open(false).show(ui, |ui| {
                if self.pi.rails.is_empty() {
                    ui.label("—（vcgencmd 不可用）");
                } else {
                    for r in &self.pi.rails {
                        ui.label(format!("{}: {:.3} V × {:.3} A = {:.3} W", r.name, r.volts, r.amps, r.watts()));
                    }
                }
            });
```

- [ ] **Step 3: central 表格加内存% 列**

在 `TableBuilder` 列定义里，第二个 `Column::exact(80.0)`（内存MB）之后插入一列：

```rust
                .column(Column::exact(60.0))
```

header 元组数组里 `(SortCol::Mem, "内存MB"),` 之后加：

```rust
                        (SortCol::MemPct, "内存%"),
```

header 默认排序判断改为：

```rust
                                    self.sort_desc = col == SortCol::Cpu || col == SortCol::Mem || col == SortCol::MemPct;
```

body 里内存MB 单元格（`row.col(|ui| { ui.label(format!("{:.1}", p.rss_kb as f32 / 1024.0)); });`）之后加：

```rust
                        row.col(|ui| { ui.label(format!("{:.1}", p.mem_percent)); });
```

- [ ] **Step 4: main.rs 窗口高度 + 构建验证**

`src/main.rs` 把 `.with_inner_size([920.0, 700.0])` 改为 `.with_inner_size([920.0, 760.0])`。

Run: `cargo build 2>&1 | tail -8`
Expected: 零警告编译通过。
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -5`
Expected: 干净。
Run: `cargo test 2>&1 | tail -8`
Expected: 全量 PASS（procstats + actions + pi）。

- [ ] **Step 5: 快照（无提交）**

快照：`cp src/app.rs .superpowers/sdd/2026-11-11-cpu-manager-v3/app.rs.pre-t3`、`cp src/main.rs .superpowers/sdd/2026-11-11-cpu-manager-v3/main.rs.pre-t3`。

---

### Task 4: 构建冒烟 + 终审 + 交付

**Files:**
- 无源码改动（验证任务）；产物 `target/release/cpu-manager`。

**Interfaces:**
- Consumes: T1–T3 全部成果。
- Produces: 运行中的 v3 GUI + 终审结论 + 交付。

- [ ] **Step 1: Release 构建（零警告）**

Run: `cargo build --release 2>&1 | tail -8`
Expected: Finished，零警告。

- [ ] **Step 2: 全量验证**

Run: `cargo test --release 2>&1 | tail -12`
Expected: 全量 PASS（procstats 15 + actions 3 + pi 8，按实际计数）。
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -5`
Expected: 干净。

- [ ] **Step 3: 重拉 GUI 冒烟（保持运行）**

先停旧实例：`pkill -f target/release/cpu-manager`（仅杀本程序）。
 detached 启动：`setsid nohup ./target/release/cpu-manager >/tmp/cpu-manager-gui.log 2>&1 </dev/null &`
Run: `sleep 2; ps -eo pid,ppid,sid,comm | grep cpu-manager | grep -v grep; wc -c /tmp/cpu-manager-gui.log`
Expected: 进程存活、PPID=1、日志 0 字节（无 panic）。GUI 留运行供用户验收。

- [ ] **Step 4: 终审 + 交付（无提交）**

由 controller 派终审子代理对全量快照 diff 做整支评审（spec 符合 + 质量）；发现 Critical/Important 走唯一修复轮 + 限定复审。交付话术含：新功能清单、运行中 GUI、已知限制、我做的裁定。