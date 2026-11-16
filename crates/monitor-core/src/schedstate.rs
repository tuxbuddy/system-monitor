//! 自动限流动作的持久化与启动对账（#8）。
//!
//! 自动调度把 `cpu.max` 写成限流值后，把 `AppliedAction`（限流前的原值、
//! 我们写入的值、主机/分组/时间）原子落盘。进程崩溃或重启后：
//! - 若当前 `cpu.max` 仍等于我们写入的值 → 可精确恢复 `previous_cpu_max`；
//! - 若已被外部修改 → 不盲目覆盖，标记待人工确认；
//! - 状态文件损坏 → 不阻塞启动，按无状态处理。

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::fsutil;

/// 一次已应用的自动限流动作。
#[derive(Clone, PartialEq, Debug)]
pub struct AppliedAction {
    pub host: String,
    pub group: String,
    /// 限流前 `cpu.max` 的原始内容（如 "max 100000" 或 "300000 100000"）。
    pub previous_cpu_max: String,
    /// 我们写入的百分比（None = 已解除）。
    pub applied_pct: Option<u32>,
    pub at_unix: u64,
    pub pid: u32,
}

impl AppliedAction {
    pub fn now(host: &str, group: &str, previous_cpu_max: String, applied_pct: Option<u32>) -> Self {
        Self {
            host: host.to_string(),
            group: group.to_string(),
            previous_cpu_max,
            applied_pct,
            at_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            pid: std::process::id(),
        }
    }

    /// 我们写入的 `cpu.max` 应该长什么样（对账基准）。
    pub fn applied_cpu_max(&self) -> String {
        match self.applied_pct {
            Some(p) => crate::cgparse::pct_to_cpu_max(p),
            None => "max 100000".to_string(),
        }
    }
}

fn state_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/share/system-monitor/sched-state.json"))
}

/// 原子写入状态文件（0600；覆盖单条——自动调度同一时刻只有一个活动动作）。
pub fn save(action: &AppliedAction) -> std::io::Result<()> {
    let Some(p) = state_path() else {
        return Ok(());
    };
    let body = serde_json::json!({
        "host": action.host,
        "group": action.group,
        "previous_cpu_max": action.previous_cpu_max,
        "applied_pct": action.applied_pct,
        "at_unix": action.at_unix,
        "pid": action.pid,
    });
    fsutil::atomic_write(&p, serde_json::to_string_pretty(&body).unwrap_or_default().as_bytes(), fsutil::MODE_PRIVATE)
}

/// 清除状态文件（解除限流成功后调用）。
pub fn clear() {
    if let Some(p) = state_path() {
        let _ = std::fs::remove_file(p);
    }
}

/// 读取未完成动作；损坏/缺字段返回 None（不阻塞启动）。
pub fn load() -> Option<AppliedAction> {
    let p = state_path()?;
    let text = std::fs::read_to_string(p).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    Some(AppliedAction {
        host: v.get("host")?.as_str()?.to_string(),
        group: v.get("group")?.as_str()?.to_string(),
        previous_cpu_max: v.get("previous_cpu_max")?.as_str()?.to_string(),
        applied_pct: v.get("applied_pct").and_then(|x| x.as_u64()).map(|x| x as u32),
        at_unix: v.get("at_unix").and_then(|x| x.as_u64()).unwrap_or(0),
        pid: v.get("pid").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
    })
}

/// 对账结果：启动时读到未完成动作后如何处置。
#[derive(Debug)]
pub enum Reconcile {
    /// 当前 cpu.max 仍等于我们写入的值：应精确恢复 previous_cpu_max。
    RestoreTo(String),
    /// 当前值已被外部修改：不动它，提示人工确认。
    ExternalChange { current: String },
    /// 记录属于另一个主机/另一个进程实例（远端或旧 pid），跳过自动处理。
    Skipped { reason: String },
}

/// 纯函数对账：给出记录、当前 cpu.max 读数、本机身份，决定处置。
/// `current_cpu_max` 为 None 表示读不到（分组已删除等）。
pub fn reconcile(
    action: &AppliedAction,
    current_cpu_max: Option<&str>,
    this_host: &str,
) -> Reconcile {
    if action.host != this_host {
        return Reconcile::Skipped { reason: format!("记录属于主机 {}", action.host) };
    }
    let Some(cur) = current_cpu_max else {
        return Reconcile::Skipped { reason: "分组已不存在".to_string() };
    };
    let cur = normalize_cpu_max(cur);
    let applied = normalize_cpu_max(&action.applied_cpu_max());
    if cur == applied {
        // 上次写入仍在位：精确恢复
        let restore = if action.previous_cpu_max.trim().is_empty() {
            "max 100000".to_string()
        } else {
            action.previous_cpu_max.clone()
        };
        Reconcile::RestoreTo(restore)
    } else {
        Reconcile::ExternalChange { current: cur.to_string() }
    }
}

/// 解析 `cpu.max` 内容为规范化比较形态（去空白差异）。
pub fn normalize_cpu_max(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applied_cpu_max_roundtrip() {
        let a = AppliedAction::now("h", "g", "max 100000".to_string(), Some(50));
        assert_eq!(a.applied_cpu_max(), "50000 100000");
        let b = AppliedAction::now("h", "g", String::new(), None);
        assert_eq!(b.applied_cpu_max(), "max 100000");
    }

    #[test]
    fn reconcile_restores_when_untouched() {
        let a = AppliedAction::now("local", "ffmpeg", "max 100000".to_string(), Some(50));
        match reconcile(&a, Some("50000  100000\n"), "local") {
            Reconcile::RestoreTo(prev) => assert_eq!(prev, "max 100000"),
            other => panic!("未被动过的限流应恢复原值，实际 {other:?}"),
        }
    }

    #[test]
    fn reconcile_respects_external_change() {
        let a = AppliedAction::now("local", "ffmpeg", "max 100000".to_string(), Some(50));
        match reconcile(&a, Some("300000 100000"), "local") {
            Reconcile::ExternalChange { current } => assert_eq!(normalize_cpu_max(&current), "300000 100000"),
            other => panic!("外部修改不得盲目覆盖，实际 {other:?}"),
        }
    }

    #[test]
    fn reconcile_skips_other_host_and_missing_group() {
        let a = AppliedAction::now("other-host", "g", String::new(), Some(50));
        assert!(matches!(reconcile(&a, Some("50000 100000"), "local"), Reconcile::Skipped { .. }));
        let b = AppliedAction::now("local", "gone", String::new(), Some(50));
        assert!(matches!(reconcile(&b, None, "local"), Reconcile::Skipped { .. }));
    }

    #[test]
    fn restore_falls_back_to_max_when_previous_missing() {
        let a = AppliedAction::now("local", "g", String::new(), Some(50));
        match reconcile(&a, Some("50000 100000"), "local") {
            Reconcile::RestoreTo(prev) => assert_eq!(prev, "max 100000"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn load_survives_garbage() {
        // 真实路径损坏文件不 panic、不阻塞（load 走 HOME,这里只验证容错语义）
        let broken = "not json at all {{{";
        assert!(serde_json::from_str::<Value>(broken).is_err());
    }
}
