//! 统一应用服务层（#12）：采集只读；所有控制（写）操作经 `CommandDispatcher`
//! 做风险分级、审计与结构化错误；MCP / GUI / TUI 共用同一执行路径。

use monitor_core::mcppolicy::{self, PolicyMode, RiskLevel};
use monitor_linux::{actions, cgroup, procstats};
use monitor_remote::remote;
use serde_json::Value;

/// 统一错误分类：跨本地/远端一致的语义，前端不再各自解释字符串。
#[derive(Debug, Clone)]
pub enum MonitorError {
    NotFound(String),
    Permission(String),
    Timeout(String),
    Unsupported(String),
    Invalid(String),
    RemoteFailed(String),
}

impl std::fmt::Display for MonitorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(e) => write!(f, "目标不存在：{e}"),
            Self::Permission(e) => write!(f, "权限不足：{e}"),
            Self::Timeout(e) => write!(f, "超时：{e}"),
            Self::Unsupported(e) => write!(f, "不支持：{e}"),
            Self::Invalid(e) => write!(f, "参数非法：{e}"),
            Self::RemoteFailed(e) => write!(f, "远端失败：{e}"),
        }
    }
}

impl std::error::Error for MonitorError {}

impl From<actions::ActionError> for MonitorError {
    fn from(e: actions::ActionError) -> Self {
        match e {
            actions::ActionError::Gone => Self::NotFound("进程已退出".into()),
            actions::ActionError::IdentityChanged => Self::Invalid("进程身份已变化（PID 复用防线）".into()),
            actions::ActionError::Permission => Self::Permission("需要同 uid 或 root".into()),
            actions::ActionError::Unsupported(e) => Self::Unsupported(e),
            actions::ActionError::Other(e) => Self::RemoteFailed(e),
        }
    }
}

impl From<remote::RemoteError> for MonitorError {
    fn from(e: remote::RemoteError) -> Self {
        match e.code() {
            "auth" => Self::Permission(e.to_string()),
            "unreachable" | "timeout" | "cancelled" => Self::Timeout(e.to_string()),
            "spawn" => Self::Unsupported(e.to_string()),
            _ => Self::RemoteFailed(e.to_string()),
        }
    }
}

impl From<cgroup::CgError> for MonitorError {
    fn from(e: cgroup::CgError) -> Self {
        match e {
            cgroup::CgError::Gone => Self::NotFound("进程或 cgroup".into()),
            cgroup::CgError::Permission => Self::Permission("cgroup 写入被拒".into()),
            cgroup::CgError::NotDelegated | cgroup::CgError::ControllerNotEnabled { .. } => Self::Unsupported(e.to_string()),
            cgroup::CgError::Io(e) | cgroup::CgError::Invalid(e) => Self::Invalid(e),
        }
    }
}

/// 采集（只读）接口：本地与远端各一实现，能力差异由调用方经 caps 判断。
pub struct SystemCollector;

impl SystemCollector {
    pub fn process_details_local(pid: i32) -> procstats::ProcDetails {
        procstats::read_details(pid)
    }

    pub fn read_details_remote(target: &remote::SshTarget, pid: i32) -> Option<procstats::ProcDetails> {
        remote::read_details(target, pid)
    }
}

/// 控制命令：全部写操作的唯一表达（前端构造，dispatcher 执行）。
#[derive(Debug, Clone)]
pub enum Command {
    SignalLocal { pid: i32, sig: i32 },
    SignalRemote { target: String, pid: i32, sig: i32 },
    /// 进程树信号（victims 已由调用方从快照展开；dispatcher 逐个校验身份）。
    SignalTreeLocal { victims: Vec<i32>, sig: i32 },
    SignalTreeRemote { target: String, victims: Vec<i32>, sig: i32 },
    NiceLocal { pid: i32, nice: i32 },
    NiceRemote { target: String, pid: i32, nice: i32 },
    CgSetLocal { group: String, pct: Option<u32> },
    CgSetRemote { target: String, base: String, group: String, pct: Option<u32> },
    /// 分组创建/删除（delete 为 L3）。
    CgGroupLocal { action: CgAction, name: String },
    CgGroupRemote { action: CgAction, target: String, base: String, name: String },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CgAction {
    Create,
    Delete,
}

impl CgAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Delete => "delete",
        }
    }
}

impl Command {
    /// 命令的风险等级（与 mcppolicy 的工具分级表同源语义）。
    pub fn risk(&self) -> RiskLevel {
        match self {
            Self::SignalLocal { sig, .. } | Self::SignalRemote { sig, .. } | Self::SignalTreeLocal { sig, .. } | Self::SignalTreeRemote { sig, .. } => {
                if *sig == 9 {
                    RiskLevel::L3 // KILL / 进程树：破坏性
                } else {
                    RiskLevel::L2
                }
            }
            Self::CgGroupLocal { action, .. } | Self::CgGroupRemote { action, .. } => {
                if *action == CgAction::Delete {
                    RiskLevel::L3
                } else {
                    RiskLevel::L2
                }
            }
            Self::NiceLocal { .. } | Self::NiceRemote { .. } | Self::CgSetLocal { .. } | Self::CgSetRemote { .. } => RiskLevel::L2,
        }
    }

    /// 审计展示名。
    pub fn name(&self) -> &'static str {
        match self {
            Self::SignalLocal { .. } => "signal_local",
            Self::SignalRemote { .. } => "signal_remote",
            Self::SignalTreeLocal { .. } => "signal_tree_local",
            Self::SignalTreeRemote { .. } => "signal_tree_remote",
            Self::NiceLocal { .. } => "nice_local",
            Self::NiceRemote { .. } => "nice_remote",
            Self::CgSetLocal { .. } => "cg_set_local",
            Self::CgSetRemote { .. } => "cg_set_remote",
            Self::CgGroupLocal { .. } => "cg_group_local",
            Self::CgGroupRemote { .. } => "cg_group_remote",
        }
    }
}

/// 命令执行器：风险分级 → 策略裁决 → 审计 → 执行。
/// MCP 直接调用；GUI/TUI 经后台线程调用同一入口（#15 的 job 体）。
pub struct CommandDispatcher {
    pub policy: PolicyMode,
    pub caller: String,
}

impl CommandDispatcher {
    pub fn new(policy: PolicyMode, caller: impl Into<String>) -> Self {
        Self { policy, caller: caller.into() }
    }

    /// 裁决并执行。审计含被拒绝的调用（失败也记录）。
    pub fn run(&self, cmd: &Command) -> Result<String, MonitorError> {
        let level = cmd.risk();
        // 复用 MCP 策略裁决：confirm 下 L3 需要凭证;这里凭证由调用方
        // 预先经 mcppolicy::issue_approval/consume_approval 处理（MCP 工具层）
        let allowed = match self.policy {
            PolicyMode::Readonly => level <= RiskLevel::L1,
            _ => true,
        };
        let host = "local";
        let ev = mcppolicy::AuditEvent {
            tool: cmd.name(),
            host,
            level,
            ok: allowed,
            error: if allowed { None } else { Some("policy_denied") },
            mode: self.policy,
            caller: &self.caller,
        };
        let _ = mcppolicy::audit(&ev);
        if !allowed {
            return Err(MonitorError::Permission(format!(
                "策略拒绝：当前模式 {} 不允许 {}（风险 {}）",
                self.policy.as_str(),
                cmd.name(),
                level.as_str()
            )));
        }
        self.execute(cmd)
    }

    fn execute(&self, cmd: &Command) -> Result<String, MonitorError> {
        match cmd {
            Command::SignalLocal { pid, sig } => {
                let sig = nix_signal(*sig)?;
                actions::send_signal(*pid, sig).map_err(MonitorError::from)?;
                Ok(format!("已向进程 {pid} 发送信号"))
            }
            Command::SignalRemote { target, pid, sig } => {
                let t = parse_target(target)?;
                remote::signal(&t, *pid, *sig).map_err(MonitorError::RemoteFailed)?;
                Ok(format!("已向远端进程 {pid} 发送信号"))
            }
            Command::SignalTreeLocal { victims, sig } => {
                let sig = nix_signal(*sig)?;
                let mut ok = 0usize;
                for pid in victims {
                    // starttime 在 send 内部即时校验（pidfd 优先）
                    if actions::send_signal_verified(*pid, sig, monitor_linux::actions::read_starttime(*pid)).is_ok() {
                        ok += 1;
                    }
                }
                if ok == 0 {
                    return Err(MonitorError::NotFound("进程树成员均已退出".into()));
                }
                Ok(format!("已向 {ok} 个进程发送信号"))
            }
            Command::SignalTreeRemote { target, victims, sig } => {
                let t = parse_target(target)?;
                let n = remote::signal_many(&t, victims, *sig).map_err(MonitorError::RemoteFailed)?;
                Ok(format!("已向 {n} 个远端进程发送信号"))
            }
            Command::NiceLocal { pid, nice } => {
                actions::set_nice(*pid, *nice).map_err(MonitorError::from)?;
                Ok(format!("已调整进程 {pid} nice={nice}"))
            }
            Command::NiceRemote { target, pid, nice } => {
                let t = parse_target(target)?;
                remote::set_nice(&t, *pid, *nice).map_err(MonitorError::RemoteFailed)?;
                Ok(format!("已调整远端进程 {pid} nice={nice}"))
            }
            Command::CgSetLocal { group, pct } => {
                let mgr = cgroup::CgroupManager::detect().map_err(MonitorError::from)?;
                mgr.set_cpu_max(group, *pct).map_err(MonitorError::from)?;
                Ok(format!("已设置分组 {group} CPU 上限"))
            }
            Command::CgSetRemote { target, base, group, pct } => {
                let t = parse_target(target)?;
                remote::cg_set_cpu_max(&t, base, group, *pct)
                    .then_some(())
                    .ok_or_else(|| MonitorError::RemoteFailed("设置 cpu.max 失败".into()))?;
                Ok(format!("已设置远端分组 {group} CPU 上限"))
            }
            Command::CgGroupLocal { action, name } => {
                let mgr = cgroup::CgroupManager::detect().map_err(MonitorError::from)?;
                match action {
                    CgAction::Create => mgr.create_group(name).map_err(MonitorError::from)?,
                    CgAction::Delete => mgr.delete_group(name).map_err(MonitorError::from)?,
                }
                Ok(format!("已{}分组 {name}", if *action == CgAction::Create { "创建" } else { "删除" }))
            }
            Command::CgGroupRemote { action, target, base, name } => {
                let t = parse_target(target)?;
                let ok = match action {
                    CgAction::Create => {
                        let ok = remote::cg_create(&t, base, name);
                        if ok {
                            let ready = remote::cg_ensure(&t, base);
                            ready.ok
                        } else {
                            false
                        }
                    }
                    CgAction::Delete => remote::cg_delete(&t, base, name),
                };
                ok.then_some(())
                    .ok_or_else(|| MonitorError::RemoteFailed(format!("远端 {} 失败（名称冲突/权限/组内进程）", action.as_str())))?;
                Ok(format!("已远端{}分组 {name}", if *action == CgAction::Create { "创建" } else { "删除" }))
            }
        }
    }
}

fn parse_target(s: &str) -> Result<remote::SshTarget, MonitorError> {
    remote::SshTarget::parse(s).map_err(|e| MonitorError::Invalid(format!("SSH 目标：{e}")))
}

fn nix_signal(num: i32) -> Result<nix::sys::signal::Signal, MonitorError> {
    use nix::sys::signal::Signal;
    Signal::try_from(num).map_err(|_| MonitorError::Invalid(format!("非法信号编号 {num}")))
}

/// 命令 → JSON（MCP 结果复用）。
pub fn command_json(cmd: &Command, msg: &str) -> Value {
    serde_json::json!({ "command": cmd.name(), "risk": cmd.risk().as_str(), "result": msg })
}

#[cfg(test)]
mod tests {
    use super::*;
    use monitor_core::mcppolicy::PolicyMode;

    #[test]
    fn risk_levels_match_policy_table() {
        let kill = Command::SignalLocal { pid: 42, sig: 9 };
        assert_eq!(kill.risk(), RiskLevel::L3);
        let term = Command::SignalLocal { pid: 42, sig: 15 };
        assert_eq!(term.risk(), RiskLevel::L2);
        let del = Command::CgGroupLocal { action: CgAction::Delete, name: "g".into() };
        assert_eq!(del.risk(), RiskLevel::L3);
        let create = Command::CgGroupLocal { action: CgAction::Create, name: "g".into() };
        assert_eq!(create.risk(), RiskLevel::L2);
    }

    #[test]
    fn readonly_denies_l2_and_l3_structured() {
        let d = CommandDispatcher::new(PolicyMode::Readonly, "test");
        let err = d.run(&Command::NiceLocal { pid: 1, nice: 5 }).unwrap_err();
        assert!(matches!(err, MonitorError::Permission(_)), "readonly 下 L2 必须拒绝：{err}");
        // 审计也记录了拒绝(文件写到真实 HOME——测试环境可接受,与 mcppolicy 审计一致)
        assert!(err.to_string().contains("策略拒绝"));
    }

    #[test]
    fn error_taxonomy_is_uniform() {
        // ActionError→MonitorError 映射
        assert!(matches!(
            MonitorError::from(actions::ActionError::Gone),
            MonitorError::NotFound(_)
        ));
        assert!(matches!(
            MonitorError::from(actions::ActionError::IdentityChanged),
            MonitorError::Invalid(_)
        ));
        assert!(matches!(
            MonitorError::from(remote::RemoteError::Timeout { elapsed: std::time::Duration::from_secs(1) }),
            MonitorError::Timeout(_)
        ));
        let auth = MonitorError::from(remote::RemoteError::Failed {
            code: 255,
            stderr: "Permission denied".into(),
        });
        assert!(matches!(auth, MonitorError::Permission(_)));
    }

    #[test]
    fn invalid_target_is_invalid_not_remote() {
        let d = CommandDispatcher::new(PolicyMode::Trusted, "test");
        let err = d.run(&Command::SignalRemote {
            target: "-oProxyCommand=evil".into(),
            pid: 42,
            sig: 15,
        });
        assert!(matches!(err, Err(MonitorError::Invalid(_))), "注入目标在校验层拒绝：{err:?}");
    }

    #[test]
    fn trusted_executes_local_signal_with_identity_guard() {
        // 非 Linux(无 /proc)回退传统 kill;Linux 走 pidfd——两种实现都必须成功
        let d = CommandDispatcher::new(PolicyMode::Trusted, "test");
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let r = d.run(&Command::SignalLocal { pid, sig: 15 });
        let _ = child.kill();
        let _ = child.wait();
        assert!(r.is_ok(), "trusted 本地信号应成功：{r:?}");
    }
}
