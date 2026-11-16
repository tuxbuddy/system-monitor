//! AgentCore：单主机 Agent 的本地执行核。
//!
//! 职责（#29 验收逐条）：
//! - 只执行类型化任务（无任意 shell;collect/read 只读,control 经本地策略门）;
//! - 本地策略优先：超出本地策略的动作**拒绝**（控制端无法越权）;
//! - 心跳（注册时间/最近活跃）;控制端离线时任务进本地队列,恢复后补跑;
//! - 每个任务执行前查吊销注册表,吊销即时生效。

use crate::registry::Registry;
use crate::types::{ConstrainedKind, Task, TaskResult};

/// 本地策略：Agent 所在主机的主人设定的边界。
#[derive(Clone, Debug)]
pub struct LocalPolicy {
    /// 允许的 nice 上调上限（如 19 = 最低优先级）。超出即拒绝。
    pub max_nice: i32,
    /// 是否允许任何受限控制（false = 纯只读 Agent）。
    pub allow_control: bool,
}

impl Default for LocalPolicy {
    fn default() -> Self {
        Self { max_nice: 19, allow_control: true }
    }
}

/// 本地执行器：把类型化任务落到本机（真实实现经 monitor-linux;PoC 用注入执行器）。
pub trait LocalExecutor {
    fn collect_overview(&self) -> Result<serde_json::Value, String>;
    fn read_process(&self, pid: i32) -> Result<serde_json::Value, String>;
    fn nice_lower(&self, pid: i32, value: i32) -> Result<serde_json::Value, String>;
}

/// Agent 状态：本地队列 + 心跳。
pub struct AgentCore {
    pub fingerprint: String,
    pub policy: LocalPolicy,
    pub last_heartbeat: u64,
    pub executed: u64,
    offline_queue: Vec<(u64, Task)>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl AgentCore {
    pub fn new(fingerprint: &str, policy: LocalPolicy) -> Self {
        Self { fingerprint: fingerprint.to_string(), policy, last_heartbeat: unix_now(), executed: 0, offline_queue: Vec::new() }
    }

    /// 心跳：返回 (fingerprint, 时间戳)。
    pub fn heartbeat(&mut self) -> (String, u64) {
        self.last_heartbeat = unix_now();
        (self.fingerprint.clone(), self.last_heartbeat)
    }

    /// 任务执行入口：吊销检查 → 本地策略门 → 执行器 → 回执。
    /// `registry` 由控制端与 Agent 共享（真实部署中吊销列表经心跳下发）。
    pub fn handle(
        &mut self,
        registry: &Registry,
        task_id: u64,
        task: &Task,
        exec: &dyn LocalExecutor,
        control_offline: bool,
    ) -> Option<TaskResult> {
        // 吊销即时生效：任何任务前先查
        if registry.is_revoked(&self.fingerprint) {
            return Some(TaskResult {
                task_id,
                ok: false,
                payload: serde_json::json!({"error": "agent_revoked"}),
            });
        }
        if control_offline {
            // 控制端离线：入本地队列,继续本地工作
            self.offline_queue.push((task_id, task.clone()));
            return None;
        }
        Some(self.execute(task_id, task, exec))
    }

    fn execute(&mut self, task_id: u64, task: &Task, exec: &dyn LocalExecutor) -> TaskResult {
        self.executed += 1;
        self.last_heartbeat = unix_now();
        let r = match task {
            Task::CollectOverview => exec.collect_overview(),
            Task::ReadProcess { pid } => exec.read_process(*pid),
            Task::ConstrainedControl { kind, pid } => self.policy_gate(*kind, *pid).and_then(|_| exec.nice_lower(*pid, match kind {
                ConstrainedKind::NiceLowerPriority { value } => *value,
            })),
        };
        match r {
            Ok(payload) => TaskResult { task_id, ok: true, payload },
            Err(e) => TaskResult { task_id, ok: false, payload: serde_json::json!({"error": e}) },
        }
    }

    /// 本地策略门：控制端请求超出本地策略 → 拒绝（这是"Agent 无法越权"的根）。
    fn policy_gate(&self, kind: ConstrainedKind, pid: i32) -> Result<(), String> {
        if pid <= 1 {
            return Err("本地策略:拒绝操作 init".to_string());
        }
        match kind {
            ConstrainedKind::NiceLowerPriority { value } => {
                if !self.policy.allow_control {
                    return Err("本地策略:此主机为只读 Agent".to_string());
                }
                if value < 0 || value > self.policy.max_nice {
                    return Err(format!("本地策略:nice {} 超出允许范围 (0..={})", value, self.policy.max_nice));
                }
                Ok(())
            }
        }
    }

    /// 控制端恢复后补跑离线队列。
    pub fn drain_offline_queue(&mut self, exec: &dyn LocalExecutor) -> Vec<TaskResult> {
        let q = std::mem::take(&mut self.offline_queue);
        q.into_iter().map(|(id, t)| self.execute(id, &t, exec)).collect()
    }

    pub fn offline_pending(&self) -> usize {
        self.offline_queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;
    use serde_json::json;

    struct FakeExec;
    impl LocalExecutor for FakeExec {
        fn collect_overview(&self) -> Result<serde_json::Value, String> {
            Ok(json!({"cpu": 12.5, "mem": 40.0}))
        }
        fn read_process(&self, pid: i32) -> Result<serde_json::Value, String> {
            Ok(json!({"pid": pid, "comm": "ffmpeg"}))
        }
        fn nice_lower(&self, pid: i32, value: i32) -> Result<serde_json::Value, String> {
            Ok(json!({"pid": pid, "nice": value}))
        }
    }

    #[test]
    fn policy_gate_rejects_out_of_range_nice() {
        let mut a = AgentCore::new("fp", LocalPolicy { max_nice: 10, allow_control: true });
        let r = a.execute(1, &Task::ConstrainedControl { kind: ConstrainedKind::NiceLowerPriority { value: 15 }, pid: 42 }, &FakeExec);
        assert!(!r.ok);
        assert!(r.payload["error"].as_str().unwrap().contains("超出"), "{}", r.payload);
        // 负 nice（提权方向）一律拒绝
        let r = a.execute(2, &Task::ConstrainedControl { kind: ConstrainedKind::NiceLowerPriority { value: -5 }, pid: 42 }, &FakeExec);
        assert!(!r.ok);
    }

    #[test]
    fn readonly_agent_refuses_control() {
        let mut a = AgentCore::new("fp", LocalPolicy { max_nice: 19, allow_control: false });
        let r = a.execute(1, &Task::ConstrainedControl { kind: ConstrainedKind::NiceLowerPriority { value: 5 }, pid: 42 }, &FakeExec);
        assert!(r.payload["error"].as_str().unwrap().contains("只读"));
    }

    #[test]
    fn offline_queues_and_drains_on_recovery() {
        let mut a = AgentCore::new("fp", LocalPolicy::default());
        let reg = Registry::default();
        let r = a.handle(&reg, 1, &Task::CollectOverview, &FakeExec, true);
        assert!(r.is_none(), "控制端离线:任务入队");
        assert_eq!(a.offline_pending(), 1);
        let results = a.drain_offline_queue(&FakeExec);
        assert_eq!(results.len(), 1);
        assert!(results[0].ok);
        assert_eq!(a.offline_pending(), 0);
    }

    #[test]
    fn revoked_agent_rejects_any_task() {
        let mut a = AgentCore::new("fp", LocalPolicy::default());
        let mut reg = Registry::default();
        reg.register("fp", &[]);
        reg.revoke("fp");
        let r = a.handle(&reg, 1, &Task::CollectOverview, &FakeExec, false);
        let r = r.unwrap();
        assert!(!r.ok);
        assert_eq!(r.payload["error"], "agent_revoked");
    }
}
