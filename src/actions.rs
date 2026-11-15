use std::fmt;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

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

pub fn send_signal(pid: i32, sig: Signal) -> Result<(), ActionError> {
    send(pid, sig)
}

pub fn terminate_tree(root: i32) -> Result<usize, ActionError> {
    tree_signal(root, Signal::SIGTERM)
}

pub fn kill_tree(root: i32) -> Result<usize, ActionError> {
    tree_signal(root, Signal::SIGKILL)
}

fn tree_signal(root: i32, sig: Signal) -> Result<usize, ActionError> {
    let pairs = crate::procstats::read_pid_pairs();
    let mut victims = crate::procstats::descendants(root, &pairs);
    victims.push(root);
    let mut count = 0usize;
    let mut last_err = None;
    for pid in victims {
        match send(pid, sig) {
            Ok(()) => count += 1,
            Err(ActionError::Gone) => {}
            Err(e) => last_err = Some(e),
        }
    }
    if count == 0
        && let Some(e) = last_err
    {
        return Err(e);
    }
    Ok(count)
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
}
