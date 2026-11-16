use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum CgError {
    NotDelegated,
    /// cgroup.controllers 有控制器，但 subtree_control 写入后读回未生效
    /// （典型原因：systemd 未委派该控制器、cgroup v1、挂载只读）。
    ControllerNotEnabled { missing: Vec<String> },
    Permission,
    Gone,
    Io(String),
    Invalid(String),
}

impl std::fmt::Display for CgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDelegated => write!(f, "调度不可用：当前不在可委派的 cgroup 子树内"),
            Self::ControllerNotEnabled { missing } => write!(
                f,
                "控制器未启用：{} 不在 cgroup.subtree_control 中（检查 systemd Delegate= 或 cgroup 版本）",
                missing.join(", ")
            ),
            Self::Permission => write!(f, "权限不足：需在用户会话内运行"),
            Self::Gone => write!(f, "进程或 cgroup 已不存在"),
            Self::Io(e) => write!(f, "cgroup 操作失败：{e}"),
            Self::Invalid(e) => write!(f, "{e}"),
        }
    }
}

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
    let mut it = text.split_whitespace();
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

#[derive(Clone)]
pub struct GroupState {
    pub name: String,
    pub cpu_max_pct: Option<u32>,
    pub cpu_weight: u32,
    pub pids_max: Option<u32>,
    pub procs: usize,
    /// cpu.stat 节流统计 (nr_periods, nr_throttled, throttled_usec)；文件缺失 None。
    pub throttle: Option<(u64, u64, u64)>,
}

pub struct CgroupManager {
    container: PathBuf,
}

fn map_io(e: std::io::Error) -> CgError {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => CgError::Permission,
        std::io::ErrorKind::NotFound => CgError::Gone,
        _ => CgError::Io(e.to_string()),
    }
}

/// 清理本次检测新建的容器：只删空目录，不误删既有内容；失败忽略（幂等）。
fn cleanup_created(container: &Path, created_now: bool) {
    if created_now {
        let _ = std::fs::remove_dir(container);
    }
}

/// 分组内核统计（#20）。
#[derive(Clone, Copy, Debug, Default)]
pub struct CgStats {
    pub cpu: CpuStat,
    pub memory: Option<EventsCounters>,
    pub pids: Option<EventsCounters>,
    pub memory_current_bytes: Option<u64>,
    pub pids_current: Option<u64>,
}

impl CgStats {
    /// 节流时间占比：throttled_usec / 周期×period? 无 period 信息，改以
    /// 被限流次数占周期次数比例表示（0..=1；除零安全）。
    pub fn throttle_ratio(&self) -> f64 {
        if self.cpu.nr_periods == 0 {
            0.0
        } else {
            self.cpu.nr_throttled as f64 / self.cpu.nr_periods as f64
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "cpu_stat": {
                "nr_periods": self.cpu.nr_periods,
                "nr_throttled": self.cpu.nr_throttled,
                "throttled_usec": self.cpu.throttled_usec,
                "throttled_ratio": round_ratio(self.throttle_ratio()),
            },
            "memory_events": self.memory.as_ref().map(events_json),
            "pids_events": self.pids.as_ref().map(events_json),
            "memory_current_bytes": self.memory_current_bytes,
            "pids_current": self.pids_current,
        })
    }
}

fn round_ratio(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// cpu.stat 计数器（#20）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuStat {
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
}

/// 解析 cpu.stat：三键齐备才算有效（异常行忽略，缺键 None）。
pub fn parse_cpu_stat(text: &str) -> CpuStat {
    let mut out = CpuStat::default();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        match (it.next(), it.next().and_then(|v| v.parse::<u64>().ok())) {
            (Some("nr_periods"), Some(v)) => out.nr_periods = v,
            (Some("nr_throttled"), Some(v)) => out.nr_throttled = v,
            (Some("throttled_usec"), Some(v)) => out.throttled_usec = v,
            _ => {}
        }
    }
    out
}

/// memory.events / pids.events 计数器。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventsCounters {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
}

/// 解析 events 文件；已知的五键取值，未知键忽略，全部缺省为 0（不 panic）。
pub fn parse_events_file(text: &str) -> EventsCounters {
    let mut out = EventsCounters::default();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        match (it.next(), it.next().and_then(|v| v.parse::<u64>().ok())) {
            (Some("low"), Some(v)) => out.low = v,
            (Some("high"), Some(v)) => out.high = v,
            (Some("max"), Some(v)) => out.max = v,
            (Some("oom"), Some(v)) => out.oom = v,
            (Some("oom_kill"), Some(v)) => out.oom_kill = v,
            _ => {}
        }
    }
    out
}

fn events_json(e: &EventsCounters) -> serde_json::Value {
    serde_json::json!({"low": e.low, "high": e.high, "max": e.max, "oom": e.oom, "oom_kill": e.oom_kill})
}

/// 单项体检结果：名字、是否通过、人可读详情（GUI 状态栏与 MCP scheduler_status 复用）。
#[derive(Clone, Debug)]
pub struct CgCheck {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// cgroup 调度可用性体检：逐步检查并在失败处给出原因与修复建议。
pub fn doctor() -> Vec<CgCheck> {
    let mut out = Vec::new();
    let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    out.push(CgCheck {
        name: "cgroup_v2",
        ok: cgroup_v2,
        detail: if cgroup_v2 {
            "统一层级已挂载".to_string()
        } else {
            "未检测到 cgroup v2（统一层级）；v1 不支持本工具的调度".to_string()
        },
    });
    let text = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let uid = unsafe { libc::getuid() };
    let Some(rel) = parse_self_cgroup(&text, uid) else {
        out.push(CgCheck { name: "delegation", ok: false, detail: "当前会话不在 user@<uid>.service 委派子树内（尝试从用户会话启动）".to_string() });
        return out;
    };
    out.push(CgCheck { name: "delegation", ok: true, detail: format!("委派根：{}", rel.display()) });
    let root = PathBuf::from("/sys/fs/cgroup").join(rel.to_string_lossy().trim_start_matches('/'));
    let ctrls = std::fs::read_to_string(root.join("cgroup.controllers")).unwrap_or_default();
    let has_cpu = ctrls.split_whitespace().any(|c| c == "cpu");
    let has_pids = ctrls.split_whitespace().any(|c| c == "pids");
    out.push(CgCheck {
        name: "controllers",
        ok: has_cpu && has_pids,
        detail: format!(
            "可用控制器{}：{}",
            if has_cpu && has_pids { "" } else { "（缺失）" },
            ctrls.split_whitespace().collect::<Vec<_>>().join(" ")
        ),
    });
    if !(has_cpu && has_pids) {
        out.push(CgCheck { name: "subtree_control", ok: false, detail: "上游未委派 cpu/pids，无法继续".to_string() });
        return out;
    }
    let container = root.join("cm-sched");
    match CgroupManager::detect() {
        Ok(_) => out.push(CgCheck { name: "subtree_control", ok: true, detail: "cm-sched 就绪：cpu/pids 已启用，cpu.max / pids.max 可写".to_string() }),
        Err(e) => {
            out.push(CgCheck { name: "subtree_control", ok: false, detail: format!("检测失败：{e}") });
            let _ = container;
        }
    }
    out
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
    /// 能力检测以「读回验证」为准：控制器确认启用、目标文件存在且可写才报告可用；
    /// 本次新建的容器在检测失败时清理，不留半初始化目录。
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
        let created_now = !container.exists();
        std::fs::create_dir_all(&container).map_err(map_io)?;
        // 容器只放子组、不放进程，才允许为子组启用控制器。
        // 写入结果必须读回验证：subtree_control 写入被内核静默拒绝（控制器未委派）
        // 时不会报错，但不读回就是假阳性。
        let write_res = std::fs::write(container.join("cgroup.subtree_control"), "+cpu +pids");
        let readback = std::fs::read_to_string(container.join("cgroup.subtree_control")).unwrap_or_default();
        let mut missing = Vec::new();
        for want in ["cpu", "pids"] {
            if !readback.split_whitespace().any(|c| c == want) {
                missing.push(want.to_string());
            }
        }
        if !missing.is_empty() || write_res.is_err() {
            cleanup_created(&container, created_now);
            return Err(CgError::ControllerNotEnabled { missing });
        }
        // 目标文件必须存在且可写，否则调度运行期必然失败
        for f in ["cpu.max", "pids.max"] {
            let p = container.join(f);
            if !p.exists() {
                cleanup_created(&container, created_now);
                return Err(CgError::Io(format!("缺少 {f}（cgroup v1 或控制器未挂载？）")));
            }
            if !is_writable(&p) {
                cleanup_created(&container, created_now);
                return Err(CgError::Permission);
            }
        }
        Ok(Self { container })
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
            Some(p) if p > 0 => pct_to_cpu_max(p),
            _ => "max 100000".to_string(),
        };
        self.set_cpu_max_raw(name, &val)
    }

    /// 写原始 `cpu.max` 值（恢复限流前状态用，值来自对账记录）。
    pub fn set_cpu_max_raw(&self, name: &str, val: &str) -> Result<(), CgError> {
        if !valid_group_name(name) {
            return Err(CgError::Invalid("非法分组名".into()));
        }
        std::fs::write(self.group_path(name).join("cpu.max"), val).map_err(map_io)
    }

    /// 读当前 `cpu.max` 原文（对账基准；分组不存在返回 None）。
    pub fn read_cpu_max(&self, name: &str) -> Option<String> {
        if !valid_group_name(name) {
            return None;
        }
        std::fs::read_to_string(self.group_path(name).join("cpu.max")).ok()
    }

    /// 分组内核统计（#20）：cpu.stat 节流、memory/pids events。
    /// 文件缺失返回 None（控制器未启用），解析失败按 0 兜底不 panic。
    pub fn read_group_stats(&self, name: &str) -> Option<CgStats> {
        if !valid_group_name(name) {
            return None;
        }
        let g = self.group_path(name);
        let cpu_stat = std::fs::read_to_string(g.join("cpu.stat")).ok()?;
        let mem_events = std::fs::read_to_string(g.join("memory.events")).ok();
        let pids_events = std::fs::read_to_string(g.join("pids.events")).ok();
        let mem_current = std::fs::read_to_string(g.join("memory.current"))
            .ok()
            .and_then(|t| t.trim().parse().ok());
        let pids_current = std::fs::read_to_string(g.join("pids.current"))
            .ok()
            .and_then(|t| t.trim().parse().ok());
        Some(CgStats {
            cpu: parse_cpu_stat(&cpu_stat),
            memory: mem_events.as_deref().map(parse_events_file),
            pids: pids_events.as_deref().map(parse_events_file),
            memory_current_bytes: mem_current,
            pids_current,
        })
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
            let pids_max = std::fs::read_to_string(path.join("pids.max")).ok().and_then(|t| {
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
            let throttle = std::fs::read_to_string(path.join("cpu.stat")).ok().map(|t| {
                let c = parse_cpu_stat(&t);
                (c.nr_periods, c.nr_throttled, c.throttled_usec)
            });
            out.push(GroupState { name, cpu_max_pct, cpu_weight, pids_max, procs, throttle });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
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
    fn parse_cpu_stat_keys() {
        let t = "nr_periods 100\nnr_throttled 7\nthrottled_usec 250000\n";
        let c = parse_cpu_stat(t);
        assert_eq!(c, CpuStat { nr_periods: 100, nr_throttled: 7, throttled_usec: 250_000 });
        // 异常行忽略、缺键 0(不 panic)
        let g = parse_cpu_stat("garbage line\nnr_periods 5\nbroken\n");
        assert_eq!(g.nr_periods, 5);
        assert_eq!(g.nr_throttled, 0);
    }

    #[test]
    fn parse_events_and_throttle_ratio() {
        let e = parse_events_file("low 1\nhigh 2\nmax 3\noom 4\noom_kill 5\nkill_unknown 9\n");
        assert_eq!(e, EventsCounters { low: 1, high: 2, max: 3, oom: 4, oom_kill: 5 });
        let st = CgStats { cpu: CpuStat { nr_periods: 4, nr_throttled: 1, throttled_usec: 10 }, ..Default::default() };
        assert!((st.throttle_ratio() - 0.25).abs() < 1e-9);
        // 除零安全
        let zero = CgStats::default();
        assert_eq!(zero.throttle_ratio(), 0.0);
    }

    #[test]
    fn controller_not_enabled_is_distinct_error() {
        // 错误分类必须可区分：控制器未启用 ≠ 未委派 ≠ 权限
        let e = CgError::ControllerNotEnabled { missing: vec!["cpu".into()] };
        assert!(e.to_string().contains("控制器未启用"));
        assert!(e.to_string().contains("cpu"));
        assert_ne!(format!("{}", CgError::NotDelegated), e.to_string());
    }

    #[test]
    fn doctor_reports_stepwise_results() {
        let checks = doctor();
        assert!(!checks.is_empty());
        assert!(checks.iter().any(|c| c.name == "cgroup_v2"));
        // 在无 cgroup v2 的环境（macOS/容器）应明确报不可用而不是空结果
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            assert!(!checks[0].ok);
        }
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
}