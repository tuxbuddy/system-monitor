# 资源管理器 v4「调度中心」实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 cpu-manager 之上加「调度」视图，用用户态 cgroup 对自有进程施加可逆的 CPU 上限，并由温度/供电驱动可选自动节流。

**Architecture:** 三层：`cgroup.rs`（cgroup v2 文件系统控制，纯换算+薄 I/O）、`scheduler.rs`（纯策略状态机）、`app.rs`（视图切换 + 编排执行）。策略层不依赖控制层。

**Tech Stack:** Rust 2024、eframe/egui 0.37、egui_extras 0.37、nix 0.31、libc。cgroup v2（/sys/fs/cgroup，user@<uid>.service 委派子树，仅 cpu+pids）。

**Spec:** `docs/superpowers/specs/2026-11-12-scheduler-center-design.md`

## Global Constraints

- **禁止新增依赖**（Cargo.toml 不动，仅用现有 crate）。
- **不做 git 提交**（无提交身份）；每个任务以「Self-review + 写报告」代替 commit。
- **测试只操作本进程 spawn 的 `sleep` 子进程**，绝不迁移/限制用户真实进程或系统进程。
- **不做内存预算**（内核 `cgroup_disable=memory`）；**不用 sudo**；只管理 uid=1000 自有进程。
- 二进制 crate：测试命令一律 `cargo test --bin cpu-manager`。
- egui 0.37 API 以已核验为准：`Frame::NONE`、`egui::style::*`（非 root）、`ui.selectable_value`、`ui.selectable_label`、`ui.add_enabled`、`Label::new(...).truncate()`、`ui.with_layout`。
- 窗口内一切动作可逆；自动模式默认关；写失败不 panic，落状态栏。
- 交付门禁：`cargo build --release` 零警告 + `cargo clippy --release --all-targets -- -D warnings` 干净 + 全量测试全绿。

---

## 文件结构

- Create `src/cgroup.rs` — cgroup 控制层 + 纯函数 + 守卫式真机冒烟测试
- Create `src/scheduler.rs` — 纯策略引擎 + 单测
- Modify `src/main.rs` — 加 `mod cgroup;` `mod scheduler;`
- Modify `src/app.rs` — `View` 枚举、调度字段、`视图切换`、`monitor_view`（抽取现有中央体）、`scheduler_view`、编排方法
- Modify `docs/superpowers/specs/...` — 无需改

---

## Task 1: cgroup.rs（控制层）

**Files:**
- Create: `src/cgroup.rs`
- Modify: `src/main.rs`（新增 `mod cgroup;`）

**Interfaces:**
- Produces: `CgroupManager::detect() -> Result<CgroupManager, CgError>`；`list_groups/create_group/delete_group/set_cpu_max/set_cpu_weight/set_pids_max/move_in/release/group_of`；`GroupState{name,cpu_max_pct,cpu_weight,pids_max,procs}`；`CgError{NotDelegated,Permission,Gone,Io(String),Invalid(String)}` 及 `impl Display`；纯函数 `parse_self_cgroup/pct_to_cpu_max/parse_cpu_max/valid_group_name`。

- [ ] **Step 1: 在 `src/main.rs` 加 `mod cgroup;`，写 `src/cgroup.rs` 的桩 + 失败测试**

在 main.rs 的 `mod actions;` 一行后加 `mod cgroup;`。

在 `src/cgroup.rs` 先写纯函数桩与测试：

```rust
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum CgError {
    NotDelegated,
    Permission,
    Gone,
    Io(String),
    Invalid(String),
}

impl std::fmt::Display for CgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDelegated => write!(f, "调度不可用：当前不在可委派的 cgroup 子树内"),
            Self::Permission => write!(f, "权限不足：需在用户会话内运行"),
            Self::Gone => write!(f, "进程或 cgroup 已不存在"),
            Self::Io(e) => write!(f, "cgroup 操作失败：{e}"),
            Self::Invalid(e) => write!(f, "{e}"),
        }
    }
}

pub fn parse_self_cgroup(_text: &str, _uid: u32) -> Option<PathBuf> {
    None
}
pub fn pct_to_cpu_max(_pct: u32) -> String {
    String::new()
}
pub fn parse_cpu_max(_text: &str) -> Option<u32> {
    None
}
pub fn valid_group_name(_name: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_delegated_root() {
        let text = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-x.scope\n";
        assert_eq!(
            parse_self_cgroup(text, 1000),
            Some(PathBuf::from("/user.slice/user-1000.slice/user@1000.service"))
        );
    }

    #[test]
    fn rejects_wrong_uid() {
        let text = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-x.scope\n";
        assert_eq!(parse_self_cgroup(text, 1001), None);
    }

    #[test]
    fn rejects_missing_unified_line() {
        assert_eq!(parse_self_cgroup("2::/foo\n", 1000), None);
    }

    #[test]
    fn pct_roundtrip() {
        assert_eq!(pct_to_cpu_max(50), "50000 100000");
        assert_eq!(parse_cpu_max("50000 100000"), Some(50));
        assert_eq!(pct_to_cpu_max(200), "200000 100000");
        assert_eq!(parse_cpu_max("200000 100000"), Some(200));
        assert_eq!(parse_cpu_max("max 100000"), None);
    }

    #[test]
    fn group_name_rules() {
        assert!(valid_group_name("ffmpeg"));
        assert!(valid_group_name("build_2.x"));
        assert!(!valid_group_name(""));
        assert!(!valid_group_name("../x"));
        assert!(!valid_group_name("a/b"));
        assert!(!valid_group_name(&"x".repeat(65)));
    }
}
```

- [ ] **Step 2: 跑测试确认 RED**

Run: `cargo test --bin cpu-manager cgroup::tests`
Expected: FAIL（桩返回 None/空，断言不符）

- [ ] **Step 3: 实现纯函数**

```rust
pub fn parse_self_cgroup(text: &str, uid: u32) -> Option<PathBuf> {
    let line = text.lines().find(|l| l.starts_with("0::"))?;
    let path = line.strip_prefix("0::")?;
    let marker = format!("user@{uid}.service");
    let mut acc: Vec<&str> = Vec::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        acc.push(seg);
        if seg == marker {
            return Some(PathBuf::from("/").join(acc.join("/")));
        }
    }
    None
}

pub fn pct_to_cpu_max(pct: u32) -> String {
    format!("{} 100000", pct.saturating_mul(1000))
}

pub fn parse_cpu_max(text: &str) -> Option<u32> {
    let mut it = text.trim().split_whitespace();
    let quota = it.next()?;
    let _period = it.next()?;
    if quota == "max" {
        return None;
    }
    Some((quota.parse::<u64>().ok()? / 1000) as u32)
}

pub fn valid_group_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}
```

- [ ] **Step 4: 跑测试确认 GREEN**

Run: `cargo test --bin cpu-manager cgroup::tests`
Expected: PASS（5 个）

- [ ] **Step 5: 加控制层 struct 与真机操作 + 守卫式冒烟测试**

在 cgroup.rs 追加（`CgroupManager` 及其方法，实现见下方完整代码）：

```rust
pub struct GroupState {
    pub name: String,
    pub cpu_max_pct: Option<u32>,
    pub cpu_weight: u32,
    pub pids_max: Option<u32>,
    pub procs: usize,
}

pub struct CgroupManager {
    root: PathBuf,
    container: PathBuf,
}

fn map_io(e: std::io::Error) -> CgError {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => CgError::Permission,
        std::io::ErrorKind::NotFound => CgError::Gone,
        _ => CgError::Io(e.to_string()),
    }
}

fn is_writable(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// 读 /proc/<pid>/cgroup 的统一层级路径，返回其 /sys/fs/cgroup 下的绝对目录。
fn proc_cgroup_dir(pid: i32) -> Option<PathBuf> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

fn check_own_process(pid: i32) -> Result<(), CgError> {
    let me = std::process::id() as i32;
    if pid <= 1 || pid == me {
        return Err(CgError::Invalid("拒绝操作 init/自身进程".into()));
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(map_io)?;
    let uid_line = status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .ok_or_else(|| CgError::Invalid("无法读取进程 Uid".into()))?;
    let real_uid: u32 = uid_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| CgError::Invalid("无法解析进程 Uid".into()))?;
    let my_uid = unsafe { libc::getuid() };
    if real_uid != my_uid {
        return Err(CgError::Permission);
    }
    Ok(())
}

impl CgroupManager {
    pub fn detect() -> Result<Self, CgError> {
        let text = std::fs::read_to_string("/proc/self/cgroup").map_err(map_io)?;
        let uid = unsafe { libc::getuid() };
        let rel = parse_self_cgroup(&text, uid).ok_or(CgError::NotDelegated)?;
        let root = PathBuf::from("/sys/fs/cgroup").join(rel.to_string_lossy().trim_start_matches('/'));
        let ctrls = std::fs::read_to_string(root.join("cgroup.controllers")).unwrap_or_default();
        if !ctrls.split_whitespace().any(|c| c == "cpu") {
            return Err(CgError::NotDelegated);
        }
        if !is_writable(&root) {
            return Err(CgError::Permission);
        }
        let container = root.join("cm-sched");
        std::fs::create_dir_all(&container).map_err(map_io)?;
        // 容器只放子组、不放进程，才允许为子组启用控制器
        let _ = std::fs::write(container.join("cgroup.subtree_control"), "+cpu +pids");
        Ok(Self { root, container })
    }

    fn group_path(&self, name: &str) -> PathBuf {
        self.container.join(name)
    }

    pub fn create_group(&self, name: &str) -> Result<(), CgError> {
        if !valid_group_name(name) {
            return Err(CgError::Invalid("非法分组名".into()));
        }
        match std::fs::create_dir(self.group_path(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(CgError::Invalid("分组已存在".into()))
            }
            Err(e) => Err(map_io(e)),
        }
    }

    pub fn delete_group(&self, name: &str) -> Result<(), CgError> {
        if !valid_group_name(name) {
            return Err(CgError::Invalid("非法分组名".into()));
        }
        std::fs::remove_dir(self.group_path(name)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => CgError::Gone,
            _ => CgError::Invalid(format!("删除失败（组内可能仍有进程）：{e}")),
        })
    }

    pub fn set_cpu_max(&self, name: &str, pct: Option<u32>) -> Result<(), CgError> {
        if !valid_group_name(name) {
            return Err(CgError::Invalid("非法分组名".into()));
        }
        let val = match pct {
            Some(p) if p == 0 => "max 100000".to_string(),
            Some(p) => pct_to_cpu_max(p),
            None => "max 100000".to_string(),
        };
        std::fs::write(self.group_path(name).join("cpu.max"), val).map_err(map_io)
    }

    pub fn set_cpu_weight(&self, name: &str, weight: u32) -> Result<(), CgError> {
        if !valid_group_name(name) {
            return Err(CgError::Invalid("非法分组名".into()));
        }
        let w = weight.clamp(1, 10000);
        std::fs::write(self.group_path(name).join("cpu.weight"), w.to_string()).map_err(map_io)
    }

    pub fn set_pids_max(&self, name: &str, max: Option<u32>) -> Result<(), CgError> {
        if !valid_group_name(name) {
            return Err(CgError::Invalid("非法分组名".into()));
        }
        let val = max.map(|m| m.max(1).to_string()).unwrap_or_else(|| "max".to_string());
        std::fs::write(self.group_path(name).join("pids.max"), val).map_err(map_io)
    }

    pub fn move_in(&self, name: &str, pid: i32) -> Result<PathBuf, CgError> {
        if !valid_group_name(name) {
            return Err(CgError::Invalid("非法分组名".into()));
        }
        check_own_process(pid)?;
        let original = proc_cgroup_dir(pid).ok_or(CgError::Gone)?;
        std::fs::write(self.group_path(name).join("cgroup.procs"), pid.to_string()).map_err(map_io)?;
        Ok(original)
    }

    pub fn release(&self, pid: i32, original: &Path) -> Result<(), CgError> {
        let target = if original.is_dir() {
            original.to_path_buf()
        } else {
            let d = self.container.join("default");
            if !d.is_dir() {
                let _ = std::fs::create_dir(&d);
                let _ = std::fs::write(d.join("cpu.max"), "max 100000");
            }
            d
        };
        std::fs::write(target.join("cgroup.procs"), pid.to_string()).map_err(map_io)
    }

    pub fn group_of(&self, pid: i32) -> Option<String> {
        let dir = proc_cgroup_dir(pid)?;
        let base = self.container.to_string_lossy().into_owned();
        let s = dir.to_string_lossy().into_owned();
        let rest = s.strip_prefix(&base)?.trim_start_matches('/');
        if rest.is_empty() {
            return None;
        }
        Some(rest.split('/').next().unwrap_or(rest).to_string())
    }

    pub fn list_groups(&self) -> Result<Vec<GroupState>, CgError> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.container).map_err(map_io)?.flatten() {
            let path = e.path();
            if !path.is_dir() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            if name == "default" {
                continue;
            }
            let cpu_max_pct = std::fs::read_to_string(path.join("cpu.max"))
                .ok()
                .and_then(|t| parse_cpu_max(&t));
            let cpu_weight = std::fs::read_to_string(path.join("cpu.weight"))
                .ok()
                .and_then(|t| t.trim().parse().ok())
                .unwrap_or(100);
            let pids_max = std::fs::read_to_string(path.join("pids.max"))
                .ok()
                .and_then(|t| {
                    let t = t.trim();
                    if t == "max" {
                        None
                    } else {
                        t.parse().ok()
                    }
                });
            let procs = std::fs::read_to_string(path.join("cgroup.procs"))
                .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0);
            out.push(GroupState { name, cpu_max_pct, cpu_weight, pids_max, procs });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}
```

在 tests 模块追加守卫式真机冒烟：

```rust
    #[test]
    fn smoke_create_limit_move_release() {
        let mgr = match CgroupManager::detect() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("skip cgroup smoke: {e}");
                return;
            }
        };
        let name = format!("cm-sched-test-{}", std::process::id());
        let _ = mgr.delete_group(&name);
        mgr.create_group(&name).expect("create");
        mgr.set_cpu_max(&name, Some(50)).expect("cpu.max");
        let g = mgr.list_groups().expect("list");
        let st = g.iter().find(|x| x.name == name).expect("present");
        assert_eq!(st.cpu_max_pct, Some(50));

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        let original = mgr.move_in(&name, pid).expect("move in");
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(mgr.group_of(pid), Some(name.clone()));

        mgr.release(pid, &original).expect("release");
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_ne!(mgr.group_of(pid), Some(name.clone()));

        let _ = child.kill();
        let _ = child.wait();
        mgr.delete_group(&name).expect("delete");
    }
```

- [ ] **Step 6: 跑测试确认 GREEN**

Run: `cargo test --bin cpu-manager cgroup::tests`
Expected: PASS（6 个；真机冒烟若委派不可用会 eprintln 跳过，本机应实际执行并通过）

- [ ] **Step 7: Self-review + 写报告（无提交）**

检查：路径全部拼接在容器下（无穿越）；`check_own_process` 拦截 init/自身/他人；测试只碰 spawn 的 sleep。
将要点写入 `.superpowers/sdd/` 下对应报告（如无目录则跳过内部报告，最终交付统一汇报）。

---

## Task 2: scheduler.rs（纯策略）

**Files:**
- Create: `src/scheduler.rs`
- Modify: `src/main.rs`（新增 `mod scheduler;`）

**Interfaces:**
- Produces: `Config{enabled,temp_high,temp_low,throttle_pct,target_group:Option<String>,cooldown_secs}`（`Default`：false/80/70/50/None/20）；`Snapshot{temp_c:Option<f32>,throttled,undervoltage}`；`Action{Engage{group,pct},Restore{group}}`；`State{engaged,last_change:Option<Instant>}`；`evaluate(&Config,&Snapshot,&mut State,Instant)->Vec<Action>`。
- Consumes: 无。

- [ ] **Step 1: 在 `src/main.rs` 加 `mod scheduler;`，写桩 + 失败测试**

```rust
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Config {
    pub enabled: bool,
    pub temp_high: f32,
    pub temp_low: f32,
    pub throttle_pct: u32,
    pub target_group: Option<String>,
    pub cooldown_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            temp_high: 80.0,
            temp_low: 70.0,
            throttle_pct: 50,
            target_group: None,
            cooldown_secs: 20,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Snapshot {
    pub temp_c: Option<f32>,
    pub throttled: bool,
    pub undervoltage: bool,
}

#[derive(Clone, PartialEq, Debug)]
pub enum Action {
    Engage { group: String, pct: u32 },
    Restore { group: String },
}

#[derive(Default)]
pub struct State {
    pub engaged: bool,
    pub last_change: Option<Instant>,
}

pub fn evaluate(_cfg: &Config, _snap: &Snapshot, _st: &mut State, _now: Instant) -> Vec<Action> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_on() -> Config {
        Config { enabled: true, target_group: Some("g".into()), ..Config::default() }
    }

    #[test]
    fn disabled_does_nothing() {
        let mut st = State::default();
        let c = Config { enabled: false, target_group: Some("g".into()), ..Config::default() };
        let s = Snapshot { temp_c: Some(99.0), throttled: true, undervoltage: true };
        assert!(evaluate(&c, &s, &mut st, Instant::now()).is_empty());
        assert!(!st.engaged);
    }

    #[test]
    fn no_target_group_does_nothing() {
        let mut st = State::default();
        let c = Config { enabled: true, target_group: None, ..Config::default() };
        let s = Snapshot { temp_c: Some(99.0), throttled: false, undervoltage: false };
        assert!(evaluate(&c, &s, &mut st, Instant::now()).is_empty());
    }

    #[test]
    fn engages_on_high_temp() {
        let mut st = State::default();
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(85.0), throttled: false, undervoltage: false };
        let a = evaluate(&c, &s, &mut st, Instant::now());
        assert_eq!(a, vec![Action::Engage { group: "g".into(), pct: 50 }]);
        assert!(st.engaged);
    }

    #[test]
    fn engages_on_throttle_even_if_cool() {
        let mut st = State::default();
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(50.0), throttled: true, undervoltage: false };
        let a = evaluate(&c, &s, &mut st, Instant::now());
        assert_eq!(a, vec![Action::Engage { group: "g".into(), pct: 50 }]);
    }

    #[test]
    fn stays_engaged_in_hysteresis_band() {
        let mut st = State { engaged: true, last_change: None };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(75.0), throttled: false, undervoltage: false };
        assert!(evaluate(&c, &s, &mut st, Instant::now()).is_empty());
        assert!(st.engaged);
    }

    #[test]
    fn releases_when_cool() {
        let base = Instant::now();
        let mut st = State { engaged: true, last_change: Some(base) };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(68.0), throttled: false, undervoltage: false };
        let a = evaluate(&c, &s, &mut st, base + Duration::from_secs(21));
        assert_eq!(a, vec![Action::Restore { group: "g".into() }]);
        assert!(!st.engaged);
    }

    #[test]
    fn cooldown_blocks_release() {
        let base = Instant::now();
        let mut st = State { engaged: true, last_change: Some(base) };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(60.0), throttled: false, undervoltage: false };
        assert!(evaluate(&c, &s, &mut st, base + Duration::from_secs(5)).is_empty());
        assert!(st.engaged);
    }

    #[test]
    fn cooldown_blocks_re_engage() {
        let base = Instant::now();
        let mut st = State { engaged: false, last_change: Some(base) };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(90.0), throttled: false, undervoltage: false };
        assert!(evaluate(&c, &s, &mut st, base + Duration::from_secs(3)).is_empty());
        assert!(!st.engaged);
    }

    #[test]
    fn none_temp_does_not_release() {
        let mut st = State { engaged: true, last_change: None };
        let c = cfg_on();
        let s = Snapshot { temp_c: None, throttled: false, undervoltage: false };
        assert!(evaluate(&c, &s, &mut st, Instant::now()).is_empty());
        assert!(st.engaged);
    }
}
```

- [ ] **Step 2: 跑测试确认 RED**

Run: `cargo test --bin cpu-manager scheduler::tests`
Expected: FAIL（桩返回空，engage/release 断言不符）

- [ ] **Step 3: 实现 evaluate**

```rust
pub fn evaluate(cfg: &Config, snap: &Snapshot, st: &mut State, now: Instant) -> Vec<Action> {
    if !cfg.enabled {
        return vec![];
    }
    let Some(group) = cfg.target_group.clone() else {
        return vec![];
    };
    let cooled = st
        .last_change
        .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(cfg.cooldown_secs));
    let hot = snap.temp_c.is_some_and(|t| t >= cfg.temp_high) || snap.throttled || snap.undervoltage;
    let cool = snap.temp_c.is_some_and(|t| t <= cfg.temp_low) && !snap.throttled && !snap.undervoltage;

    if !st.engaged && hot && cooled {
        st.engaged = true;
        st.last_change = Some(now);
        vec![Action::Engage { group, pct: cfg.throttle_pct }]
    } else if st.engaged && cool && cooled {
        st.engaged = false;
        st.last_change = Some(now);
        vec![Action::Restore { group }]
    } else {
        vec![]
    }
}
```

- [ ] **Step 4: 跑测试确认 GREEN**

Run: `cargo test --bin cpu-manager scheduler::tests`
Expected: PASS（9 个）

- [ ] **Step 5: Self-review + 报告（无提交）**

确认纯逻辑、无 I/O、`now` 注入便于冷却测试；`is_none_or` 已在本 crate 使用过（Rust 1.99 支持）。

---

## Task 3: app.rs 调度 UI + 编排

**Files:**
- Modify: `src/app.rs`

**Interfaces:**
- Consumes: `crate::cgroup::{CgroupManager, GroupState, CgError}`、`crate::scheduler::{self, Config as SchedConfig, State as SchedState, Snapshot, Action}`。
- Produces: `View` 枚举、`monitor_view`、`scheduler_view` 与编排方法。

- [ ] **Step 1: 加导入、`View` 枚举、字段与初始化**

顶部 import 加：
```rust
use std::path::PathBuf;
use crate::cgroup::{self, CgroupManager, GroupState};
use crate::scheduler::{self, Action as SchedAction, Config as SchedConfig, Snapshot as SchedSnapshot, State as SchedState};
```

加枚举（放在 `SortCol` 附近）：
```rust
#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Monitor,
    Scheduler,
}
```

`CpuManagerApp` 结构体新增字段（在 `pi` 之后）：
```rust
    view: View,
    mgr: Option<CgroupManager>,
    cg_error: Option<String>,
    groups: Vec<GroupState>,
    new_group: String,
    sel_group: Option<String>,
    sched: SchedConfig,
    sched_state: SchedState,
    original_of: std::collections::HashMap<i32, PathBuf>,
```

`new()` 初始化中，把 `..` 前的字段补齐（注意 `let mut app` 后再 refresh）：
```rust
            view: View::Monitor,
            mgr: None,
            cg_error: None,
            groups: Vec::new(),
            new_group: String::new(),
            sel_group: None,
            sched: SchedConfig::default(),
            sched_state: SchedState::default(),
            original_of: std::collections::HashMap::new(),
```
并把 `let mut app = Self { ... }` 之前插入：
```rust
        let (mgr, cg_error) = match CgroupManager::detect() {
            Ok(m) => (Some(m), None),
            Err(e) => (None, Some(e.to_string())),
        };
```
`app.resample();` 之前插入 `app.refresh_groups();`。

- [ ] **Step 2: 加编排方法（放在 `report` 方法后）**

```rust
    fn refresh_groups(&mut self) {
        if let Some(m) = &self.mgr {
            self.groups = m.list_groups().unwrap_or_default();
        } else {
            self.groups.clear();
        }
    }

    fn finish_cg(&mut self, res: Option<Result<(), cgroup::CgError>>, ok_msg: String) {
        match res {
            Some(Ok(())) => {
                self.status_error = false;
                self.status = ok_msg;
                self.refresh_groups();
            }
            Some(Err(e)) => {
                self.status_error = true;
                self.status = e.to_string();
            }
            None => {}
        }
    }

    fn do_set_cpu_max(&mut self, group: &str, pct: Option<u32>) {
        let res = self.mgr.as_ref().map(|m| m.set_cpu_max(group, pct));
        let cap = pct.map(|p| format!("{p}%")).unwrap_or_else(|| "不限".into());
        self.finish_cg(res, format!("分组 {group} CPU 上限 → {cap}"));
    }

    fn do_join_group(&mut self, group: &str, pid: i32) {
        let res = self.mgr.as_ref().map(|m| m.move_in(group, pid));
        match res {
            Some(Ok(orig)) => {
                self.original_of.insert(pid, orig);
                self.status_error = false;
                self.status = format!("进程 {pid} 已加入分组 {group}");
                self.refresh_groups();
            }
            Some(Err(e)) => {
                self.status_error = true;
                self.status = e.to_string();
            }
            None => {}
        }
    }

    fn do_leave_group(&mut self, pid: i32) {
        let Some(orig) = self.original_of.remove(&pid) else {
            return;
        };
        let res = self.mgr.as_ref().map(|m| m.release(pid, &orig));
        self.finish_cg(res, format!("进程 {pid} 已移出分组"));
    }

    fn do_delete_group(&mut self, group: &str) {
        let res = self.mgr.as_ref().map(|m| m.delete_group(group));
        if self.sel_group.as_deref() == Some(group) {
            self.sel_group = None;
        }
        self.finish_cg(res, format!("已删除分组 {group}"));
    }

    fn dissolve_all_limits(&mut self) {
        let names: Vec<String> = self.groups.iter().map(|g| g.name.clone()).collect();
        if let Some(m) = &self.mgr {
            for n in &names {
                let _ = m.set_cpu_max(n, None);
            }
        }
        let originals: Vec<(i32, PathBuf)> = self.original_of.drain().collect();
        if let Some(m) = &self.mgr {
            for (pid, orig) in &originals {
                let _ = m.release(*pid, orig);
            }
        }
        self.status_error = false;
        self.status = "已解除全部限速".to_string();
        self.refresh_groups();
    }

    fn apply_sched_action(&mut self, act: SchedAction) {
        let (group, pct, verb) = match act {
            SchedAction::Engage { group, pct } => (group, Some(pct), "自动节流"),
            SchedAction::Restore { group } => (group, None, "自动恢复"),
        };
        let res = self.mgr.as_ref().map(|m| m.set_cpu_max(&group, pct));
        let cap = pct.map(|p| format!(" → {p}%")).unwrap_or_default();
        self.finish_cg(res, format!("{verb}：分组 {group}{cap}"));
    }

    fn run_scheduler(&mut self) {
        if !self.sched.enabled || self.mgr.is_none() {
            return;
        }
        let snap = SchedSnapshot {
            temp_c: self.pi.temp_c,
            throttled: self.pi.throttle.is_some_and(|t| t.any_current()),
            undervoltage: self.pi.throttle.is_some_and(|t| t.undervoltage),
        };
        let actions = scheduler::evaluate(&self.sched, &snap, &mut self.sched_state, Instant::now());
        for a in actions {
            self.apply_sched_action(a);
        }
    }
```

- [ ] **Step 3: resample() 末尾刷新分组与运行调度**

在 `resample()` 的 `self.last_sample = Instant::now();` 之后、`self.history.push_back(...)` 之前插入：
```rust
        self.refresh_groups();
        self.run_scheduler();
```

- [ ] **Step 4: 重构 `central` 为视图切换 + 抽取 `monitor_view`**

把现有 `fn central(&mut self, ui)` 的整个 `CentralPanel...show` 体抽出为 `fn monitor_view(&mut self, ui: &mut egui::Ui)`（原样搬运：工具栏、命令行栏、表格、空状态；去掉外层 `CentralPanel`）。

新 `central`：
```rust
    fn central(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.view, View::Monitor, RichText::new("监控").size(13.0));
                ui.selectable_value(&mut self.view, View::Scheduler, RichText::new("调度").size(13.0));
            });
            ui.add_space(6.0);
            match self.view {
                View::Monitor => self.monitor_view(ui),
                View::Scheduler => self.scheduler_view(ui),
            }
        });
    }
```

- [ ] **Step 5: 实现 `scheduler_view`**

```rust
    fn scheduler_view(&mut self, ui: &mut egui::Ui) {
        let available = self.mgr.is_some();
        let (banner, color) = if available {
            ("可调度：用户 cgroup（cpu / pids）".to_string(), theme::SUCCESS)
        } else {
            (
                format!("调度不可用：{}", self.cg_error.clone().unwrap_or_else(|| "未知原因".into())),
                theme::DANGER,
            )
        };
        egui::Frame::NONE
            .fill(theme::tint(color, 0.12))
            .corner_radius(6)
            .inner_margin(Margin::symmetric(10, 7))
            .show(ui, |ui| {
                ui.label(RichText::new(banner).size(12.5).color(color));
            });
        ui.add_space(10.0);

        // 新建分组
        ui.horizontal(|ui| {
            ui.label(RichText::new("新建分组").size(12.5).color(theme::TEXT_SEC));
            ui.add(
                egui::TextEdit::singleline(&mut self.new_group)
                    .hint_text("名称：字母数字 . _ -")
                    .desired_width(180.0),
            );
            let can = available && !self.new_group.trim().is_empty();
            if action_btn(ui, "创建", theme::SUCCESS, can, false) {
                let name = self.new_group.trim().to_string();
                let res = self.mgr.as_ref().map(|m| m.create_group(&name));
                self.finish_cg(res, format!("已创建分组 {name}"));
                if self.status_error == false {
                    self.new_group.clear();
                }
            }
        });
        ui.add_space(8.0);

        // 分组列表
        if self.groups.is_empty() {
            ui.label(RichText::new("还没有分组。").size(12.0).color(theme::TEXT_MUTED));
        }
        let groups = self.groups.clone();
        for g in &groups {
            ui.horizontal(|ui| {
                let sel = self.sel_group.as_deref() == Some(g.name.as_str());
                if ui
                    .selectable_label(sel, RichText::new(&g.name).size(12.5).strong())
                    .clicked()
                {
                    self.sel_group = Some(g.name.clone());
                }
                let cap = g.cpu_max_pct.map(|p| format!("{p}%")).unwrap_or_else(|| "不限".into());
                ui.label(
                    RichText::new(format!("CPU {cap} · {} 进程", g.procs))
                        .size(11.5)
                        .color(theme::TEXT_MUTED),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if action_btn(ui, "删除", theme::DANGER, available, false) {
                        self.do_delete_group(&g.name);
                    }
                });
            });
        }
        ui.add_space(8.0);

        // 选中分组的上限操作
        if let Some(grp) = self.sel_group.clone() {
            ui.horizontal(|ui| {
                ui.label(RichText::new("CPU 上限").size(12.5).color(theme::TEXT_SEC));
                for (label, pct) in [
                    ("25%", Some(25u32)),
                    ("50%", Some(50u32)),
                    ("100%", Some(100u32)),
                    ("200%", Some(200u32)),
                    ("不限", None),
                ] {
                    if action_btn(ui, label, theme::INFO, available, false) {
                        self.do_set_cpu_max(&grp, pct);
                    }
                }
            });
            if let Some(pid) = self.selected {
                let managed = self.mgr.as_ref().and_then(|m| m.group_of(pid)).is_some();
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("当前选中进程 PID {pid}")).size(12.0).color(theme::TEXT_SEC),
                    );
                    if !managed {
                        if action_btn(ui, "加入此分组", theme::SUCCESS, available, false) {
                            self.do_join_group(&grp, pid);
                        }
                    } else if action_btn(ui, "移出分组", theme::WARNING, available, false) {
                        self.do_leave_group(pid);
                    }
                });
            }
        }
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(8.0);

        // 自动节流规则
        ui.label(RichText::new("自动节流").size(12.5).strong().color(theme::TEXT_SEC));
        let mut enabled = self.sched.enabled;
        ui.horizontal(|ui| {
            ui.checkbox(&mut enabled, RichText::new("启用自动模式").size(12.5));
            ui.label(
                RichText::new("仅做可逆的 CPU 上限收紧/放宽，不会杀进程")
                    .size(11.0)
                    .color(theme::TEXT_MUTED),
            );
        });
        self.sched.enabled = enabled;
        ui.horizontal(|ui| {
            ui.label(RichText::new("触发温度").size(12.0).color(theme::TEXT_SEC));
            ui.add(egui::Slider::new(&mut self.sched.temp_high, 60.0..=90.0).suffix("°C"));
            ui.label(RichText::new("回落温度").size(12.0).color(theme::TEXT_SEC));
            ui.add(egui::Slider::new(&mut self.sched.temp_low, 40.0..=80.0).suffix("°C"));
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("节流到").size(12.0).color(theme::TEXT_SEC));
            ui.add(egui::Slider::new(&mut self.sched.throttle_pct, 10..=200).suffix("%"));
            ui.label(RichText::new("目标分组").size(12.0).color(theme::TEXT_SEC));
            let current = self
                .sched
                .target_group
                .clone()
                .unwrap_or_else(|| "（未选择）".into());
            egui::ComboBox::from_id_salt("sched_target")
                .selected_text(current)
                .width(140.0)
                .show_ui(ui, |ui| {
                    for g in &groups {
                        ui.selectable_value(&mut self.sched.target_group, Some(g.name.clone()), &g.name);
                    }
                });
        });
        ui.add_space(8.0);
        if action_btn(ui, "解除全部限速", theme::WARNING, available, false) {
            self.dissolve_all_limits();
        }
    }
```

- [ ] **Step 6: 构建 + clippy + 全量测试**

Run: `cargo build --release`
Expected: 编译通过、零警告。
Run: `cargo clippy --release --all-targets -- -D warnings`
Expected: 干净。
Run: `cargo test --bin cpu-manager`
Expected: 全绿（cgroup 6 + scheduler 9 + 既有 35）。

若报借用错误：`do_*`/`finish_cg` 已用 `self.mgr.as_ref().map(...)` 取 owned `Result` 后再改 `self.status`，避免冲突；如仍冲突，把 `g.name` 先 clone 到局部再调用。

- [ ] **Step 7: Self-review + 报告（无提交）**

核对：视图切换不破坏监控视图；调度不可用时控件禁用 + 横幅；自动模式默认关；`解除全部限速` 复位 cpu.max 并还原进程。

---

## Task 4: 终验 + 冒烟 + 交付

**Files:** 无新增；仅验证与交付。

- [ ] **Step 1: 视觉验证调度面板（临时默认视图翻转）**

临时把 `new()` 里 `view: View::Monitor` 改为 `View::Scheduler`，`cargo build --release`，重拉 GUI 截图核对调度面板布局，**随后改回 `View::Monitor` 并重新构建**。

```bash
pkill -x cpu-manager; sleep 1
export WAYLAND_DISPLAY=wayland-0 XDG_RUNTIME_DIR=/run/user/1000 DISPLAY=:0
setsid nohup ./target/release/cpu-manager >/tmp/cpu-manager-gui.log 2>&1 </dev/null &
sleep 3
grim /tmp/shot-sched.png
```
Expected: 截图可见「可调度」横幅、分组区、上限按钮、自动节流规则。

- [ ] **Step 2: 还原默认视图 + 最终构建**

把 `view` 改回 `View::Monitor`，重跑 `cargo build --release` + clippy + test（同 T3 Step 6），确认全绿零警告。

- [ ] **Step 3: 真机冒烟（测试只碰 sleep）**

Run: `cargo test --bin cpu-manager cgroup::tests -- --nocapture`
Expected: 真机冒烟实际执行并通过（委派可用时），无残留 `cm-sched-test-*` 组。

- [ ] **Step 4: 重拉 GUI（默认监控视图）并保持运行**

```bash
pkill -x cpu-manager; sleep 1
export WAYLAND_DISPLAY=wayland-0 XDG_RUNTIME_DIR=/run/user/1000 DISPLAY=:0
setsid nohup ./target/release/cpu-manager >/tmp/cpu-manager-gui.log 2>&1 </dev/null &
sleep 3
pgrep -ax cpu-manager
```
Expected: 进程在跑、日志无错误。

- [ ] **Step 5: 交付汇报**

汇总：新增能力、实机限制（无内存）、安全护栏、测试与验证结果、交互路径未做注入式点击测试的诚实说明。

---

## Self-Review（计划作者自查）

- **Spec 覆盖**：§5 cgroup→T1；§6 scheduler→T2；§7 UI→T3；§11 测试→T1/T2 单测 + T4 冒烟；§9 安全→T1 `check_own_process` + T3 自动默认关；§3 实机→detect 校验。齐。
- **占位扫描**：无 TBD/TODO；代码块均为可落地实现。
- **类型一致**：`GroupState` 字段、`CgError` 变体、`Action` 变体、`evaluate` 签名在 T1/T2/T3 间一致；app 用 `SchedConfig/SchedState/SchedSnapshot/SchedAction` 别名避免与既有 `Config` 冲突。
- **一处提醒**：T3 的 `monitor_view` 是从现有 `central` 原样抽取，抽取时保留原有工具栏/表格/空状态代码不变。