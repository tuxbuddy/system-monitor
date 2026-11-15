# CPU 管理器（cpu-manager）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 Raspberry Pi 500（Debian 13 arm64, Wayland）上构建一个 Rust + egui 桌面 GUI：实时显示系统与每核 CPU 占用、按占用列出进程，并支持结束/强制结束/调优先级/暂停恢复。

**Architecture:** 三层分离——`procstats`（纯 std 读 /proc，两次快照差值算占用，纯函数可单测）、`actions`（nix 信号 + libc setpriority，错误类型化）、`app`（eframe/egui 界面，UI 线程内每秒采样，无线程）。

**Tech Stack:** Rust 1.99.1（edition 2024）、eframe 0.37（glow 后端）、egui_extras 0.37（表格）、nix 0.31（signal/user）、libc 0.2（setpriority）。

**Spec:** `docs/superpowers/specs/2026-11-10-cpu-manager-design.md`

## Global Constraints

- 工作目录：`/home/zhangyi/project/cpu-manager`，所有 cargo/git 命令都在此目录执行。
- 依赖精确版本：`eframe =0.37`（`--no-default-features --features glow,default_fonts,wayland,x11`）、`egui_extras =0.37`、`nix =0.31`（features `signal,user`）、`libc =0.2`。
- **nix 0.31 已移除 setpriority**，调优先级必须用 `libc::setpriority`（已核实源码）。
- **egui 0.37 无 `SelectableLabel` 结构体**，用 `ui.selectable_label(checked, text)` 方法（已核实源码）。
- `FontDefinitions.font_data` 值类型是 `Arc<FontData>`（用 `.into()` 转换）；CJK 字体从 `/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc` 加载（已确认存在），`FontData` 默认 index 0 即可显示中文。
- 界面文案一律中文。
- CPU% 口径同 top（Irix 模式）：进程 CPU% = Δ进程jiffies / Δ总jiffies × 核数 × 100，可超 100%；总/每核 CPU% 为 0–100。busy = total − idle − iowait。
- 安全：结束/强制结束必须经 `egui::Modal` 二次确认（显示 PID+名称）；自身 PID 与 PID 1 禁用全部调控按钮；EPERM/EACCES → 状态栏提示"权限不足，可用 sudo 运行本程序"；ESRCH → "进程已退出"。
- 不引入线程；采样在 UI 线程，周期 1 秒。
- **跳过所有 git 提交步骤**：本机未配置 git 提交身份，且禁止修改 git config。用 `cargo test`/`cargo build` 结果作为每个任务的完成证据。
- 长编译（eframe 首次全量编译在 Pi 上可能 5–10 分钟）：Bash 超时给足 600000ms，必要时 run_in_background。
- 验证 API 用的 crate 源码在 /tmp（egui-0.37.0、epaint-0.37.0、egui_extras-0.37.0、eframe-0.37.0、nix-0.31.3），可能被清理；需要时按 `https://crates.io/api/v1/crates/<name>/<version>/download` 重新下载。

---

### Task 1: 脚手架 + procstats 数据层（TDD）

**Files:**
- Create: `Cargo.toml`（cargo init 生成后加依赖）、`src/procstats.rs`
- Modify: `src/main.rs`（cargo init 生成的 hello world 改为模块声明）

**Interfaces:**
- Produces（后续任务依赖的精确签名）：
  - `pub struct CpuTimes { pub user/nice/system/idle/iowait/irq/softirq/steal: u64 }`，`pub fn total(self) -> u64`、`pub fn busy(self) -> u64`、`pub fn parse(line: &str) -> Option<Self>`
  - `pub struct ProcSnapshot { pub pid: i32, pub comm: String, pub utime: u64, pub stime: u64, pub nice: i64, pub state: char, pub uid: u32 }`
  - `pub fn parse_proc_stat(line: &str) -> Option<ProcSnapshot>`（uid 置 0，由 read_snapshot 填）
  - `pub struct SystemSnapshot { pub cores: Vec<CpuTimes>, pub procs: Vec<ProcSnapshot> }`（Clone + Default）
  - `pub fn read_snapshot() -> SystemSnapshot`
  - `pub struct ProcUsage { pub pid: i32, pub comm: String, pub user: String, pub cpu_percent: f32, pub nice: i64, pub state: char }`
  - `pub struct Usage { pub total_percent: f32, pub core_percent: Vec<f32>, pub procs: Vec<ProcUsage> }`（Default；procs 按 cpu_percent 降序）
  - `pub fn compute(prev: &SystemSnapshot, curr: &SystemSnapshot, users: &HashMap<u32, String>) -> Usage`
  - `pub fn username(uid: u32) -> String`
  - `pub struct Sampler`，`pub fn new() -> Self`、`pub fn sample(&mut self) -> Usage`

- [ ] **Step 1: 初始化项目与依赖**

```bash
cd /home/zhangyi/project/cpu-manager
cargo init --name cpu-manager
cargo add nix@0.31 --features signal,user
cargo add libc@0.2
```

`src/main.rs` 改为：

```rust
mod procstats;

fn main() {
    println!("cpu-manager");
}
```

- [ ] **Step 2: 写 procstats.rs（类型 + todo!() 桩 + 全部测试）**

创建 `src/procstats.rs`，完整内容：

```rust
use std::collections::HashMap;
use std::fs;

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    pub fn total(self) -> u64 {
        self.user + self.nice + self.system + self.idle + self.iowait + self.irq + self.softirq + self.steal
    }

    pub fn busy(self) -> u64 {
        self.total() - self.idle - self.iowait
    }

    /// 解析 /proc/stat 的 cpu/cpuN 行；guest 字段已含在 user 中，忽略。
    pub fn parse(line: &str) -> Option<Self> {
        let _ = line;
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct ProcSnapshot {
    pub pid: i32,
    pub comm: String,
    pub utime: u64,
    pub stime: u64,
    pub nice: i64,
    pub state: char,
    pub uid: u32,
}

/// 解析 /proc/<pid>/stat 行。comm 可含空格/括号，用首个 '(' 与最后一个 ')' 定位。
pub fn parse_proc_stat(line: &str) -> Option<ProcSnapshot> {
    let _ = line;
    todo!()
}

#[derive(Clone, Debug, Default)]
pub struct SystemSnapshot {
    pub cores: Vec<CpuTimes>,
    pub procs: Vec<ProcSnapshot>,
}

pub fn read_snapshot() -> SystemSnapshot {
    todo!()
}

#[derive(Clone, Debug)]
pub struct ProcUsage {
    pub pid: i32,
    pub comm: String,
    pub user: String,
    pub cpu_percent: f32,
    pub nice: i64,
    pub state: char,
}

#[derive(Clone, Debug, Default)]
pub struct Usage {
    pub total_percent: f32,
    pub core_percent: Vec<f32>,
    pub procs: Vec<ProcUsage>,
}

/// 纯函数：两次快照差值 → 占用率。users 缺省时回退为 uid 字符串。
pub fn compute(
    prev: &SystemSnapshot,
    curr: &SystemSnapshot,
    users: &HashMap<u32, String>,
) -> Usage {
    let _ = (prev, curr, users);
    todo!()
}

pub fn username(uid: u32) -> String {
    let _ = uid;
    todo!()
}

pub struct Sampler {
    prev: Option<SystemSnapshot>,
}

impl Sampler {
    pub fn new() -> Self {
        Self { prev: None }
    }

    pub fn sample(&mut self) -> Usage {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_line() {
        let t = CpuTimes::parse("cpu0 100 20 30 400 50 6 7 8 0 0").unwrap();
        assert_eq!(t.total(), 621);
        assert_eq!(t.busy(), 171);
        assert!(CpuTimes::parse("intr 123 456").is_none());
        assert!(CpuTimes::parse("cpu0 1 2 3").is_none());
    }

    fn stat_line(pid: i32, comm: &str, state: &str, utime: u64, stime: u64, nice: i64) -> String {
        let mut rest: Vec<String> = (0..24).map(|_| "0".to_string()).collect();
        rest[0] = state.to_string();
        rest[11] = utime.to_string();
        rest[12] = stime.to_string();
        rest[16] = nice.to_string();
        format!("{pid} ({comm}) {}", rest.join(" "))
    }

    #[test]
    fn parse_proc_stat_tricky_comm() {
        let line = stat_line(123, "my (proc) name", "S", 500, 250, 5);
        let p = parse_proc_stat(&line).unwrap();
        assert_eq!(p.pid, 123);
        assert_eq!(p.comm, "my (proc) name");
        assert_eq!(p.state, 'S');
        assert_eq!(p.utime, 500);
        assert_eq!(p.stime, 250);
        assert_eq!(p.nice, 5);
        assert!(parse_proc_stat("garbage").is_none());
    }

    fn snap(cores: Vec<CpuTimes>, procs: Vec<ProcSnapshot>) -> SystemSnapshot {
        SystemSnapshot { cores, procs }
    }

    fn proc(pid: i32, utime: u64, stime: u64) -> ProcSnapshot {
        ProcSnapshot { pid, comm: format!("p{pid}"), utime, stime, nice: 0, state: 'S', uid: 1000 }
    }

    #[test]
    fn compute_percentages() {
        let prev = snap(
            vec![CpuTimes { user: 100, system: 100, idle: 800, ..Default::default() }],
            vec![proc(1, 60, 40)],
        );
        let curr = snap(
            vec![CpuTimes { user: 200, system: 200, idle: 1600, ..Default::default() }],
            vec![proc(1, 180, 120)],
        );
        // total 1000→2000，busy 200→400 → 20%；进程 Δ300-100=200 /1000 ×1核 ×100 = 20%
        let u = compute(&prev, &curr, &HashMap::new());
        assert!((u.total_percent - 20.0).abs() < 0.01);
        assert!((u.core_percent[0] - 20.0).abs() < 0.01);
        assert_eq!(u.procs.len(), 1);
        assert!((u.procs[0].cpu_percent - 20.0).abs() < 0.01);
        assert_eq!(u.procs[0].user, "1000");
    }

    #[test]
    fn compute_multicore_new_and_gone_procs() {
        let prev = snap(
            vec![
                CpuTimes { user: 100, idle: 900, ..Default::default() },
                CpuTimes { user: 100, idle: 900, ..Default::default() },
            ],
            vec![proc(1, 100, 0), proc(2, 0, 0)],
        );
        let curr = snap(
            vec![
                CpuTimes { user: 200, idle: 1800, ..Default::default() },
                CpuTimes { user: 100, idle: 1900, ..Default::default() },
            ],
            vec![proc(1, 300, 0), proc(3, 50, 0)],
        );
        // 总 2000→4000，busy 200→300 → 5%；进程1 Δ200/2000×2×100=20%；新进程3=0；进程2消失
        let u = compute(&prev, &curr, &HashMap::new());
        assert!((u.total_percent - 5.0).abs() < 0.01);
        assert!((u.core_percent[0] - 10.0).abs() < 0.01);
        assert_eq!(u.core_percent[1], 0.0);
        assert_eq!(u.procs.len(), 2);
        assert_eq!(u.procs[0].pid, 1);
        assert!((u.procs[0].cpu_percent - 20.0).abs() < 0.01);
        assert_eq!(u.procs[1].pid, 3);
        assert_eq!(u.procs[1].cpu_percent, 0.0);
    }

    #[test]
    fn compute_zero_delta() {
        let s = snap(
            vec![CpuTimes { user: 100, idle: 900, ..Default::default() }],
            vec![proc(1, 10, 5)],
        );
        let u = compute(&s, &s, &HashMap::new());
        assert_eq!(u.total_percent, 0.0);
        assert_eq!(u.procs[0].cpu_percent, 0.0);
    }
}
```

- [ ] **Step 3: 跑测试确认失败**

```bash
cargo test
```

预期：编译通过，5 个测试全部 FAIL（`todo!()` panic）。

- [ ] **Step 4: 实现全部函数**

把 `src/procstats.rs` 中 6 个 `todo!()` 函数体替换为以下实现（其余内容不变）：

```rust
// CpuTimes::parse
let mut it = line.split_whitespace();
let label = it.next()?;
if !label.starts_with("cpu") {
    return None;
}
let v: Vec<u64> = it.filter_map(|s| s.parse().ok()).take(8).collect();
if v.len() < 8 {
    return None;
}
Some(Self {
    user: v[0], nice: v[1], system: v[2], idle: v[3],
    iowait: v[4], irq: v[5], softirq: v[6], steal: v[7],
})
```

```rust
// parse_proc_stat
let open = line.find('(')?;
let close = line.rfind(')')?;
if close < open {
    return None;
}
let pid: i32 = line[..open].trim().parse().ok()?;
let comm = line[open + 1..close].to_string();
let rest: Vec<&str> = line[close + 1..].split_whitespace().collect();
// rest[0]=state(第3列) rest[11]=utime(14) rest[12]=stime(15) rest[16]=nice(19)
if rest.len() < 17 {
    return None;
}
Some(ProcSnapshot {
    pid,
    comm,
    state: rest[0].chars().next()?,
    utime: rest[11].parse().ok()?,
    stime: rest[12].parse().ok()?,
    nice: rest[16].parse().ok()?,
    uid: 0,
})
```

```rust
// read_snapshot（含私有 read_uid 辅助函数，加在 read_snapshot 前面）
fn read_uid(pid: i32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

pub fn read_snapshot() -> SystemSnapshot {
    let mut snap = SystemSnapshot::default();
    if let Ok(stat) = fs::read_to_string("/proc/stat") {
        for line in stat.lines() {
            // 只要 cpu0..cpuN 行，跳过聚合 "cpu " 行
            if line.starts_with("cpu") && !line.starts_with("cpu ") {
                if let Some(t) = CpuTimes::parse(line) {
                    snap.cores.push(t);
                }
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some(mut p) = parse_proc_stat(&stat) else {
                continue;
            };
            p.uid = read_uid(pid).unwrap_or(u32::MAX);
            snap.procs.push(p);
        }
    }
    snap
}
```

```rust
// compute
fn pct(busy_delta: u64, total_delta: u64) -> f32 {
    if total_delta == 0 {
        0.0
    } else {
        busy_delta as f32 / total_delta as f32 * 100.0
    }
}

pub fn compute(
    prev: &SystemSnapshot,
    curr: &SystemSnapshot,
    users: &HashMap<u32, String>,
) -> Usage {
    let n = curr.cores.len().max(1);
    let prev_total: u64 = prev.cores.iter().map(|c| c.total()).sum();
    let curr_total: u64 = curr.cores.iter().map(|c| c.total()).sum();
    let prev_busy: u64 = prev.cores.iter().map(|c| c.busy()).sum();
    let curr_busy: u64 = curr.cores.iter().map(|c| c.busy()).sum();
    let total_delta = curr_total.saturating_sub(prev_total);
    let total_percent = pct(curr_busy.saturating_sub(prev_busy), total_delta);
    let core_percent = curr
        .cores
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let p = prev.cores.get(i).copied().unwrap_or_default();
            pct(c.busy().saturating_sub(p.busy()), c.total().saturating_sub(p.total()))
        })
        .collect();
    let prev_map: HashMap<i32, &ProcSnapshot> = prev.procs.iter().map(|p| (p.pid, p)).collect();
    let mut procs: Vec<ProcUsage> = curr
        .procs
        .iter()
        .map(|p| {
            let cpu = match prev_map.get(&p.pid) {
                Some(old) => {
                    let d = (p.utime + p.stime).saturating_sub(old.utime + old.stime);
                    if total_delta == 0 {
                        0.0
                    } else {
                        d as f32 / total_delta as f32 * n as f32 * 100.0
                    }
                }
                None => 0.0,
            };
            ProcUsage {
                pid: p.pid,
                comm: p.comm.clone(),
                user: users.get(&p.uid).cloned().unwrap_or_else(|| p.uid.to_string()),
                cpu_percent: cpu,
                nice: p.nice,
                state: p.state,
            }
        })
        .collect();
    procs.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
    Usage { total_percent, core_percent, procs }
}
```

```rust
// username
nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
    .ok()
    .flatten()
    .map(|u| u.name)
    .unwrap_or_else(|| uid.to_string())
```

```rust
// Sampler::sample —— 首次采样 prev=curr 克隆，差值全 0，自然显示 0%
let curr = read_snapshot();
let prev = self.prev.replace(curr.clone()).unwrap_or_else(|| curr.clone());
let mut users: HashMap<u32, String> = HashMap::new();
for p in &curr.procs {
    users.entry(p.uid).or_insert_with(|| username(p.uid));
}
compute(&prev, &curr, &users)
```

注意：`pct` 是自由函数，放在 `compute` 前面；`read_uid` 放在 `read_snapshot` 前面。

- [ ] **Step 5: 跑测试确认通过 + clippy**

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

预期：5 个测试 PASS；clippy 无警告（如有警告，修复后重跑）。

---

### Task 2: actions 调控层（TDD，只操作自有子进程）

**Files:**
- Create: `src/actions.rs`
- Modify: `src/main.rs`（加 `mod actions;`）

**Interfaces:**
- Consumes: `crate::procstats::parse_proc_stat`（测试里读子进程状态/nice 用）
- Produces：
  - `pub enum ActionError { Gone, Permission, Other(String) }`（实现 `fmt::Display`，文案见 Global Constraints）
  - `pub fn terminate(pid: i32) -> Result<(), ActionError>`（SIGTERM）
  - `pub fn kill_force(pid: i32) -> Result<(), ActionError>`（SIGKILL）
  - `pub fn stop(pid: i32) -> Result<(), ActionError>`（SIGSTOP）
  - `pub fn resume(pid: i32) -> Result<(), ActionError>`（SIGCONT）
  - `pub fn set_nice(pid: i32, nice: i32) -> Result<(), ActionError>`（libc::setpriority）

- [ ] **Step 1: 写 actions.rs（桩 + 全部测试）**

`src/main.rs` 加一行 `mod actions;`。创建 `src/actions.rs`：

```rust
use std::fmt;

#[derive(Debug)]
pub enum ActionError {
    Gone,
    Permission,
    Other(String),
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gone => write!(f, "进程已退出"),
            Self::Permission => write!(f, "权限不足，可用 sudo 运行本程序"),
            Self::Other(e) => write!(f, "操作失败：{e}"),
        }
    }
}

pub fn terminate(pid: i32) -> Result<(), ActionError> {
    let _ = pid;
    todo!()
}

pub fn kill_force(pid: i32) -> Result<(), ActionError> {
    let _ = pid;
    todo!()
}

pub fn stop(pid: i32) -> Result<(), ActionError> {
    let _ = pid;
    todo!()
}

pub fn resume(pid: i32) -> Result<(), ActionError> {
    let _ = pid;
    todo!()
}

pub fn set_nice(pid: i32, nice: i32) -> Result<(), ActionError> {
    let _ = (pid, nice);
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};
    use std::thread;
    use std::time::Duration;

    fn spawn_sleeper() -> Child {
        Command::new("sleep").arg("30").spawn().expect("spawn sleep")
    }

    fn snapshot_of(pid: i32) -> crate::procstats::ProcSnapshot {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        crate::procstats::parse_proc_stat(&stat).unwrap()
    }

    #[test]
    fn stop_resume_terminate_lifecycle() {
        let mut child = spawn_sleeper();
        let pid = child.id() as i32;
        stop(pid).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(snapshot_of(pid).state, 'T');
        resume(pid).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert!(matches!(snapshot_of(pid).state, 'S' | 'R'));
        terminate(pid).unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
    }

    #[test]
    fn renice_own_child() {
        let mut child = spawn_sleeper();
        let pid = child.id() as i32;
        set_nice(pid, 5).unwrap();
        assert_eq!(snapshot_of(pid).nice, 5);
        kill_force(pid).unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn gone_process_reports_gone() {
        let mut child = spawn_sleeper();
        let pid = child.id() as i32;
        kill_force(pid).unwrap();
        child.wait().unwrap();
        assert!(matches!(terminate(pid), Err(ActionError::Gone)));
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
cargo test actions
```

预期：3 个测试 FAIL（todo!() panic）。

- [ ] **Step 3: 实现**

把 5 个 `todo!()` 函数体替换为（并在文件顶部 `use std::fmt;` 之后加 `use nix::sys::signal::{kill, Signal}; use nix::unistd::Pid;`）：

```rust
fn map_nix(e: nix::errno::Errno) -> ActionError {
    match e {
        nix::errno::Errno::ESRCH => ActionError::Gone,
        nix::errno::Errno::EPERM | nix::errno::Errno::EACCES => ActionError::Permission,
        other => ActionError::Other(other.to_string()),
    }
}

fn send(pid: i32, sig: Signal) -> Result<(), ActionError> {
    kill(Pid::from_raw(pid), sig).map_err(map_nix)
}

pub fn terminate(pid: i32) -> Result<(), ActionError> {
    send(pid, Signal::SIGTERM)
}

pub fn kill_force(pid: i32) -> Result<(), ActionError> {
    send(pid, Signal::SIGKILL)
}

pub fn stop(pid: i32) -> Result<(), ActionError> {
    send(pid, Signal::SIGSTOP)
}

pub fn resume(pid: i32) -> Result<(), ActionError> {
    send(pid, Signal::SIGCONT)
}

/// nix 0.31 已移除 setpriority，直接用 libc。
pub fn set_nice(pid: i32, nice: i32) -> Result<(), ActionError> {
    let ret = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice) };
    if ret == -1 {
        let e = std::io::Error::last_os_error();
        Err(match e.raw_os_error() {
            Some(libc::ESRCH) => ActionError::Gone,
            Some(libc::EPERM) | Some(libc::EACCES) => ActionError::Permission,
            _ => ActionError::Other(e.to_string()),
        })
    } else {
        Ok(())
    }
}
```

- [ ] **Step 4: 跑全部测试确认通过 + clippy**

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

预期：8 个测试全部 PASS；clippy 无警告。

---

### Task 3: egui GUI（app.rs + main.rs + 中文字体）

**Files:**
- Create: `src/app.rs`
- Modify: `src/main.rs`（整体替换）、`Cargo.toml`（cargo add）

**Interfaces:**
- Consumes: Task 1 的 `Sampler/Usage/ProcUsage`（字段名见 Task 1 Interfaces）；Task 2 的 `actions::{terminate, kill_force, stop, resume, set_nice, ActionError}`
- Produces: `pub struct CpuManagerApp`，`pub fn new(cc: &eframe::CreationContext<'_>) -> Self`，实现 `eframe::App`

- [ ] **Step 1: 加 GUI 依赖**

```bash
cargo add eframe@0.37 --no-default-features --features glow,default_fonts,wayland,x11
cargo add egui_extras@0.37
```

- [ ] **Step 2: 写 src/app.rs（完整内容）**

```rust
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};

use crate::actions::{self, ActionError};
use crate::procstats::{ProcUsage, Sampler, Usage};

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortCol {
    Cpu,
    Pid,
    Name,
    User,
    Nice,
    State,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfirmKind {
    Terminate,
    Kill,
}

struct Confirm {
    kind: ConfirmKind,
    pid: i32,
    comm: String,
}

struct NiceDialog {
    pid: i32,
    comm: String,
    value: i32,
}

pub struct CpuManagerApp {
    sampler: Sampler,
    usage: Usage,
    last_sample: Instant,
    filter: String,
    sort_col: SortCol,
    sort_desc: bool,
    selected: Option<i32>,
    confirm: Option<Confirm>,
    nice_dialog: Option<NiceDialog>,
    status: String,
    own_pid: i32,
}

impl CpuManagerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        load_cjk_font(&cc.egui_ctx);
        let mut app = Self {
            sampler: Sampler::new(),
            usage: Usage::default(),
            last_sample: Instant::now(),
            filter: String::new(),
            sort_col: SortCol::Cpu,
            sort_desc: true,
            selected: None,
            confirm: None,
            nice_dialog: None,
            status: "就绪".to_string(),
            own_pid: std::process::id() as i32,
        };
        app.usage = app.sampler.sample();
        app
    }

    fn report(&mut self, result: Result<(), ActionError>, ok_msg: String) {
        self.status = match result {
            Ok(()) => ok_msg,
            Err(e) => e.to_string(),
        };
    }

    fn visible_rows(&self) -> Vec<ProcUsage> {
        let f = self.filter.trim();
        let mut rows: Vec<ProcUsage> = self
            .usage
            .procs
            .iter()
            .filter(|p| f.is_empty() || p.comm.contains(f) || p.pid.to_string().contains(f))
            .cloned()
            .collect();
        let desc = self.sort_desc;
        rows.sort_by(|a, b| {
            let ord = match self.sort_col {
                SortCol::Cpu => a.cpu_percent.partial_cmp(&b.cpu_percent).unwrap_or(std::cmp::Ordering::Equal),
                SortCol::Pid => a.pid.cmp(&b.pid),
                SortCol::Name => a.comm.cmp(&b.comm),
                SortCol::User => a.user.cmp(&b.user),
                SortCol::Nice => a.nice.cmp(&b.nice),
                SortCol::State => a.state.cmp(&b.state),
            };
            if desc { ord.reverse() } else { ord }
        });
        rows
    }

    fn top_panel(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("CPU 管理器");
                ui.separator();
                ui.label(RichText::new(format!("{:.1}%", self.usage.total_percent)).size(28.0).strong());
                ui.add(egui::ProgressBar::new(self.usage.total_percent / 100.0).desired_width(200.0));
            });
            ui.horizontal(|ui| {
                for (i, p) in self.usage.core_percent.iter().enumerate() {
                    ui.label(format!("核{i}"));
                    ui.add(egui::ProgressBar::new(p / 100.0).desired_width(90.0).text(format!("{p:.0}%")));
                }
            });
            ui.add_space(4.0);
        });
    }

    fn central(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("过滤:");
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("名称或 PID").desired_width(200.0));
                ui.label(format!("共 {} 个进程", self.usage.procs.len()));
            });
            let rows = self.visible_rows();
            TableBuilder::new(ui)
                .striped(true)
                .column(Column::exact(70.0))
                .column(Column::remainder())
                .column(Column::exact(90.0))
                .column(Column::exact(80.0))
                .column(Column::exact(50.0))
                .column(Column::exact(50.0))
                .header(22.0, |mut header| {
                    for (col, title) in [
                        (SortCol::Pid, "PID"),
                        (SortCol::Name, "名称"),
                        (SortCol::User, "用户"),
                        (SortCol::Cpu, "CPU%"),
                        (SortCol::Nice, "nice"),
                        (SortCol::State, "状态"),
                    ] {
                        header.col(|ui| {
                            let arrow = if self.sort_col == col {
                                if self.sort_desc { " ▼" } else { " ▲" }
                            } else {
                                ""
                            };
                            if ui.add(egui::Button::new(format!("{title}{arrow}")).frame(false)).clicked() {
                                if self.sort_col == col {
                                    self.sort_desc = !self.sort_desc;
                                } else {
                                    self.sort_col = col;
                                    self.sort_desc = col == SortCol::Cpu;
                                }
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(20.0, rows.len(), |mut row| {
                        let p = &rows[row.index()];
                        let is_sel = self.selected == Some(p.pid);
                        row.col(|ui| {
                            if ui.selectable_label(is_sel, p.pid.to_string()).clicked() {
                                self.selected = Some(p.pid);
                            }
                        });
                        row.col(|ui| {
                            if ui.selectable_label(is_sel, p.comm.as_str()).clicked() {
                                self.selected = Some(p.pid);
                            }
                        });
                        row.col(|ui| { ui.label(p.user.as_str()); });
                        row.col(|ui| { ui.label(format!("{:.1}", p.cpu_percent)); });
                        row.col(|ui| { ui.label(p.nice.to_string()); });
                        row.col(|ui| { ui.label(p.state.to_string()); });
                    });
                });
        });
    }

    fn bottom_panel(&mut self, ctx: &egui::Context) {
        // 先取出选中信息（owned），避免闭包内 &mut self 与 &self.usage 借用冲突
        let sel: Option<(i32, String, char, i64)> = self
            .selected
            .and_then(|pid| self.usage.procs.iter().find(|p| p.pid == pid))
            .map(|p| (p.pid, p.comm.clone(), p.state, p.nice));
        let actionable = sel.as_ref().is_some_and(|(pid, ..)| *pid != self.own_pid && *pid != 1);
        let stopped = sel.as_ref().is_some_and(|(_, _, state, _)| *state == 'T');
        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(actionable, egui::Button::new("结束进程")).clicked() {
                    if let Some((pid, comm, _, _)) = &sel {
                        self.confirm = Some(Confirm { kind: ConfirmKind::Terminate, pid: *pid, comm: comm.clone() });
                    }
                }
                if ui.add_enabled(actionable, egui::Button::new("强制结束")).clicked() {
                    if let Some((pid, comm, _, _)) = &sel {
                        self.confirm = Some(Confirm { kind: ConfirmKind::Kill, pid: *pid, comm: comm.clone() });
                    }
                }
                if ui.add_enabled(actionable, egui::Button::new("调优先级")).clicked() {
                    if let Some((pid, comm, _, nice)) = &sel {
                        self.nice_dialog = Some(NiceDialog { pid: *pid, comm: comm.clone(), value: (*nice).clamp(-19, 19) as i32 });
                    }
                }
                let pause_label = if stopped { "恢复进程" } else { "暂停进程" };
                if ui.add_enabled(actionable, egui::Button::new(pause_label)).clicked() {
                    if let Some((pid, comm, _, _)) = &sel {
                        let (pid, comm) = (*pid, comm.clone());
                        let r = if stopped {
                            actions::resume(pid)
                        } else {
                            actions::stop(pid)
                        };
                        let verb = if stopped { "恢复" } else { "暂停" };
                        self.report(r, format!("已{verb}进程 {pid}（{comm}）"));
                    }
                }
            });
            ui.label(self.status.as_str());
            ui.add_space(4.0);
        });
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        // 先拷贝数据，避免 Modal 闭包内 &mut self 与借用冲突
        let confirm = self.confirm.as_ref().map(|c| (c.kind, c.pid, c.comm.clone()));
        if let Some((kind, pid, comm)) = confirm {
            let mut done = false;
            egui::Modal::new(egui::Id::new("confirm")).show(ctx, |ui| {
                ui.set_width(320.0);
                let verb = if kind == ConfirmKind::Kill { "强制结束" } else { "结束" };
                ui.label(format!("确定要{verb}进程 {pid}（{comm}）吗？"));
                if kind == ConfirmKind::Kill {
                    ui.label(RichText::new("强制结束可能丢失未保存数据。").color(Color32::YELLOW));
                }
                ui.horizontal(|ui| {
                    if ui.button("确定").clicked() {
                        let r = if kind == ConfirmKind::Kill {
                            actions::kill_force(pid)
                        } else {
                            actions::terminate(pid)
                        };
                        self.report(r, format!("已{verb}进程 {pid}（{comm}）"));
                        done = true;
                    }
                    if ui.button("取消").clicked() {
                        done = true;
                    }
                });
            });
            if done {
                self.confirm = None;
            }
        }

        let nice = self.nice_dialog.as_ref().map(|d| (d.pid, d.comm.clone(), d.value));
        if let Some((pid, comm, mut value)) = nice {
            let mut apply = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::new("nice")).show(ctx, |ui| {
                ui.set_width(320.0);
                ui.label(format!("调整进程 {pid}（{comm}）的优先级"));
                ui.add(egui::Slider::new(&mut value, -19..=19).text("nice"));
                ui.label("数值越大优先级越低；调低数值（更高优先级）需要 sudo。");
                ui.horizontal(|ui| {
                    if ui.button("应用").clicked() {
                        apply = true;
                    }
                    if ui.button("取消").clicked() {
                        cancel = true;
                    }
                });
            });
            if apply {
                let r = actions::set_nice(pid, value);
                self.report(r, format!("已将进程 {pid} 的 nice 调整为 {value}"));
                self.nice_dialog = None;
            } else if cancel {
                self.nice_dialog = None;
            } else if let Some(d) = &mut self.nice_dialog {
                d.value = value;
            }
        }
    }
}

impl eframe::App for CpuManagerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_sample.elapsed() >= Duration::from_secs(1) {
            self.usage = self.sampler.sample();
            self.last_sample = Instant::now();
            if let Some(pid) = self.selected {
                if !self.usage.procs.iter().any(|p| p.pid == pid) {
                    self.selected = None;
                }
            }
        }
        self.top_panel(ctx);
        self.bottom_panel(ctx);
        self.central(ctx);
        self.dialogs(ctx);
        ctx.request_repaint_after(Duration::from_secs(1));
    }
}

fn load_cjk_font(ctx: &egui::Context) {
    const CANDIDATES: &[&str] = &[
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
    ];
    let Some(bytes) = CANDIDATES.iter().find_map(|p| std::fs::read(p).ok()) else {
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert("cjk".to_owned(), egui::FontData::from_owned(bytes).into());
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts.families.entry(family).or_default().insert(0, "cjk".to_owned());
    }
    ctx.set_fonts(fonts);
}
```

- [ ] **Step 3: 整体替换 src/main.rs**

```rust
mod actions;
mod app;
mod procstats;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([920.0, 620.0])
            .with_title("CPU 管理器"),
        ..Default::default()
    };
    eframe::run_native(
        "cpu-manager",
        options,
        Box::new(|cc| Ok(Box::new(app::CpuManagerApp::new(cc)))),
    )
}
```

- [ ] **Step 4: 编译（首次全量编译慢，超时给 600000ms，必要时 run_in_background）**

```bash
cargo build 2>&1 | tail -20
```

预期：`Finished` 无 error。如有编译错误，对照 /tmp 下 crate 源码修正（重点：eframe 0.37 的 AppCreator 返回 `Ok(Box::new(...))`；`ui.selectable_label` 而非 SelectableLabel；font_data 值为 Arc 用 `.into()`）。

- [ ] **Step 5: 测试与 clippy 回归**

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

预期：8 个测试 PASS，clippy 无警告。

---

### Task 4: 桌面启动器 + Release 构建 + 真机冒烟

**Files:**
- Create: `cpu-manager.desktop`（项目根目录）
- 安装到: `~/.local/share/applications/cpu-manager.desktop`

**Interfaces:**
- Consumes: Task 3 产出的可运行 GUI 程序

- [ ] **Step 1: 写桌面启动器**

创建 `cpu-manager.desktop`：

```ini
[Desktop Entry]
Type=Application
Name=CPU 管理器
Comment=显示 CPU 占用并调控进程
Exec=/home/zhangyi/project/cpu-manager/target/release/cpu-manager
Icon=utilities-system-monitor
Terminal=false
Categories=System;Monitor;
```

- [ ] **Step 2: Release 构建**

```bash
cargo build --release 2>&1 | tail -5
```

预期：`Finished` `release` profile。超时 600000ms，必要时 run_in_background。

- [ ] **Step 3: 安装启动器并真机冒烟**

```bash
cp cpu-manager.desktop ~/.local/share/applications/cpu-manager.desktop
```

用 run_in_background 启动 `./target/release/cpu-manager`（会话环境已有 WAYLAND_DISPLAY=wayland-0 / DISPLAY=:0）。等约 5 秒后检查后台输出：无 panic、无 error 即冒烟通过；窗口应已出现在桌面上，请用户目视确认（总占用、进程列表、中文显示正常）。**保持进程运行**留给用户试用，不要主动杀掉。

若启动失败（如 Wayland 连接错误），把 stderr 原样记录并尝试 `WINIT_UNIX_BACKEND=x11 ./target/release/cpu-manager` 走 XWayland 兜底。

- [ ] **Step 4: 最终验证与交付**

```bash
cargo test 2>&1 | tail -5
cargo clippy --all-targets -- -D warnings 2>&1 | tail -3
```

预期：8 测试 PASS、clippy 干净。向用户交付：功能清单、运行方式（桌面图标"CPU 管理器"或 `cargo run --release`）、已知限制（调低 nice/动其他用户进程需 sudo；git 未提交因身份未配置）。