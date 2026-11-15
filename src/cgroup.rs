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
            out.push(GroupState { name, cpu_max_pct, cpu_weight, pids_max, procs });
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