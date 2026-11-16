use std::fmt;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

#[derive(Debug)]
pub enum ActionError {
    /// 目标进程已退出。
    Gone,
    /// PID 存在但身份不匹配：原观察目标已退出、PID 被复用（拒绝执行）。
    IdentityChanged,
    Permission,
    /// 内核/环境不支持 pidfd 且回退路径也不可用。
    Unsupported(String),
    Other(String),
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gone => write!(f, "进程已退出"),
            Self::IdentityChanged => write!(f, "进程身份已变化（PID 复用或目标已退出），拒绝操作"),
            Self::Permission => write!(f, "权限不足，可用 sudo 运行本程序"),
            Self::Unsupported(e) => write!(f, "当前内核不支持 pidfd：{e}"),
            Self::Other(e) => write!(f, "操作失败：{e}"),
        }
    }
}

fn map_nix(e: nix::errno::Errno) -> ActionError {
    match e {
        nix::errno::Errno::ESRCH => ActionError::Gone,
        nix::errno::Errno::EPERM | nix::errno::Errno::EACCES => ActionError::Permission,
        other => ActionError::Other(other.to_string()),
    }
}

// ---- 进程实例身份：pidfd 优先，starttime 校验兜底 ----

/// Linux 5.3+ 的 pidfd_open / pidfd_send_signal 系统调用号
///（x86_64 与 aarch64 相同；其它架构走 starttime 回退路径）。
#[cfg(target_os = "linux")]
const SYS_PIDFD_OPEN: libc::c_long = 434;
#[cfg(target_os = "linux")]
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;

#[cfg(target_os = "linux")]
fn pidfd_supported() -> bool {
    // 可靠判定：对 init(1) 完整走一遍 pidfd_open + pidfd_send_signal(sig=0 探测)
    // ——init 恒存在；open 返回 fd 但 send 报 ENOSYS/EINVAL（某些容器/seccomp 环境
    // 只放行 open）同样视为不支持，走 starttime 回退路径。
    let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, 1, 0u32) };
    if fd < 0 {
        return false;
    }
    let fd = fd as libc::c_int;
    let r = unsafe { libc::syscall(SYS_PIDFD_SEND_SIGNAL, fd, 0, 0u64) };
    unsafe { libc::close(fd) };
    r == 0
}

#[cfg(not(target_os = "linux"))]
fn pidfd_supported() -> bool {
    false
}

/// 经 pidfd 向进程实例发信号（内核保证 fd 绑定的进程退出后不复用）。
#[cfg(target_os = "linux")]
fn pidfd_send(pid: i32, sig: i32) -> Result<(), ActionError> {
    let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0u32) };
    if fd < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(match e {
            libc::ESRCH => ActionError::Gone,
            _ => ActionError::Unsupported(format!("pidfd_open 失败（errno {e}）")),
        });
    }
    let fd = fd as libc::c_int;
    // 信号 0：仅探测目标仍是 fd 绑定的实例
    let r = unsafe { libc::syscall(SYS_PIDFD_SEND_SIGNAL, fd, sig, 0u64) };
    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    unsafe { libc::close(fd) };
    if r == 0 {
        Ok(())
    } else {
        Err(match err {
            libc::ESRCH => ActionError::Gone,
            libc::EPERM | libc::EACCES => ActionError::Permission,
            // ENOSYS/EINVAL：环境不支持（seccomp/兼容层），调用方回退 starttime 路径
            libc::ENOSYS | libc::EINVAL => ActionError::Unsupported(format!("pidfd_send_signal errno {err}")),
            _ => ActionError::Other(format!("pidfd_send_signal errno {err}")),
        })
    }
}

#[cfg(not(target_os = "linux"))]
fn pidfd_send(_pid: i32, _sig: i32) -> Result<(), ActionError> {
    Err(ActionError::Unsupported("非 Linux 平台".to_string()))
}

/// 读 /proc/<pid>/stat 的 starttime（第 22 字段）。
pub fn read_starttime(pid: i32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm 可能含任意字符（含括号/空格），以最后一个 ')' 为界
    let close = text.rfind(')')?;
    let rest: Vec<&str> = text[close + 1..].split_whitespace().collect();
    // rest[0]=state(第3列)，starttime 是第22列 → rest[19]
    rest.get(19)?.parse().ok()
}

/// 带身份校验的信号发送：
/// 1. pidfd 可用 → pidfd_open 绑定实例后发信号（杜绝 PID 复用）；
/// 2. pidfd 不可用 → 对比发送前后的 starttime，变化即拒绝。
///
/// `expected_starttime` 非零时先比对（进程树操作传入采集时的值）。
pub fn send_signal_verified(pid: i32, sig: Signal, expected_starttime: Option<u64>) -> Result<(), ActionError> {
    if pid <= 1 {
        return Err(ActionError::Other("拒绝操作 init".to_string()));
    }
    // 非 Linux 平台（无 /proc，如 macOS 开发机）：没有 starttime 来源，保持
    // 传统 kill 行为（pidfd/starttime 防线是 Linux 特性）
    if !std::path::Path::new("/proc").exists() {
        return kill(Pid::from_raw(pid), sig).map_err(map_nix);
    }
    if let Some(expect) = expected_starttime.filter(|t| *t > 0) {
        let now = read_starttime(pid).ok_or(ActionError::Gone)?;
        if now != expect {
            return Err(ActionError::IdentityChanged);
        }
    }
    if pidfd_supported() {
        match pidfd_send(pid, sig as i32) {
            // Gone/Permission/成功都是确定结论；环境不支持才回退
            Err(ActionError::Unsupported(e)) => {
                // 落到下方 starttime 回退路径
                let _ = e;
            }
            other => return other,
        }
    }
    // 回退：发送前后 starttime 必须一致（窗口缩窄但不为零）
    let before = read_starttime(pid).ok_or(ActionError::Gone)?;
    let r = kill(Pid::from_raw(pid), sig).map_err(map_nix);
    if r.is_ok()
        && let Some(after) = read_starttime(pid)
        && after != before
    {
        return Err(ActionError::IdentityChanged);
    }
    r
}

fn send(pid: i32, sig: Signal) -> Result<(), ActionError> {
    send_signal_verified(pid, sig, None)
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

pub fn send_signal(pid: i32, sig: Signal) -> Result<(), ActionError> {
    send(pid, sig)
}

/// 进程树信号：先对树内每个 PID 采样 (pid, starttime)，再逐个校验身份后发送。
/// 单个成员 Gone 静默跳过；IdentityChanged 计入失败但继续处理其余成员；
/// 全部失败时返回最后一个错误。
pub fn tree_signal(root: i32, sig: Signal) -> Result<usize, ActionError> {
    let pairs = crate::procstats::read_pid_pairs();
    let mut victims = crate::procstats::descendants(root, &pairs);
    victims.push(root);
    // 快照身份窗口：所有 victims 的 starttime 一次性采齐
    let snapshot: Vec<(i32, Option<u64>)> = victims
        .iter()
        .map(|p| (*p, read_starttime(*p)))
        .collect();
    let mut count = 0usize;
    let mut identity_err: Option<ActionError> = None;
    let mut last_err: Option<ActionError> = None;
    for (pid, starttime) in snapshot {
        match send_signal_verified(pid, sig, starttime) {
            Ok(()) => count += 1,
            Err(ActionError::Gone) => {}
            Err(e @ ActionError::IdentityChanged) => identity_err = Some(e),
            Err(e) => last_err = Some(e),
        }
    }
    if count == 0
        && let Some(e) = identity_err.or(last_err)
    {
        return Err(e);
    }
    Ok(count)
}

pub fn terminate_tree(root: i32) -> Result<usize, ActionError> {
    tree_signal(root, Signal::SIGTERM)
}

pub fn kill_tree(root: i32) -> Result<usize, ActionError> {
    tree_signal(root, Signal::SIGKILL)
}

/// nix 0.31 已移除 setpriority，直接用 libc。
/// 先校验 starttime（nice 作用于具体实例），防止调错对象。
pub fn set_nice(pid: i32, nice: i32) -> Result<(), ActionError> {
    let before = read_starttime(pid).ok_or(ActionError::Gone)?;
    let ret = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice) };
    if ret == -1 {
        let e = std::io::Error::last_os_error();
        Err(match e.raw_os_error() {
            Some(libc::ESRCH) => ActionError::Gone,
            Some(libc::EPERM) | Some(libc::EACCES) => ActionError::Permission,
            _ => ActionError::Other(e.to_string()),
        })
    } else {
        // 成功后再核对一次身份；不一致则报 IdentityChanged（nice 可能落在了复用者上）
        if let Some(after) = read_starttime(pid)
            && after != before
        {
            return Err(ActionError::IdentityChanged);
        }
        Ok(())
    }
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

    #[test]
    fn terminate_tree_signals_own_child() {
        let mut child = spawn_sleeper();
        let pid = child.id() as i32;
        let n = terminate_tree(pid).unwrap();
        assert!(n >= 1);
        let status = child.wait().unwrap();
        assert!(!status.success());
    }

    #[test]
    fn starttime_mismatch_is_identity_changed() {
        // 身份校验依赖 /proc；非 Linux 开发机没有该防线，直接传统 kill
        if !std::path::Path::new("/proc").exists() {
            return;
        }
        // 期望 starttime 与现实不符 → 必须拒绝（PID 复用防线）
        let mut child = spawn_sleeper();
        let pid = child.id() as i32;
        let r = send_signal_verified(pid, Signal::SIGSTOP, Some(12345));
        match r {
            Err(ActionError::IdentityChanged) => {}
            other => panic!("错误 starttime 应拒绝，实际 {other:?}"),
        }
        // 正确 starttime 放行
        let st = read_starttime(pid).unwrap();
        send_signal_verified(pid, Signal::SIGCONT, Some(st)).unwrap();
        kill_force(pid).unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn refused_to_signal_init() {
        assert!(matches!(send_signal_verified(1, Signal::SIGTERM, None), Err(ActionError::Other(_))));
    }

    #[test]
    fn starttime_readable_for_self() {
        let me = std::process::id() as i32;
        let st = read_starttime(me);
        // macOS 无 /proc → None;Linux 上必须可读且随进程稳定
        if std::path::Path::new("/proc/self").exists() {
            let st = st.expect("Linux 下应能读到自身 starttime");
            assert_eq!(read_starttime(me), Some(st));
        }
    }
}
