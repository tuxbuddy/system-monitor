//! 类型化任务与回执：Agent 只接受枚举列出的任务,不接受任意 shell。

use serde_json::{json, Value};

/// 任务类型（封闭集合;新增须走评审——这是"Agent 无法执行任意 shell"的根）。
#[derive(Clone, Debug, PartialEq)]
pub enum Task {
    /// 采集一次系统概览（只读）。
    CollectOverview,
    /// 读取指定进程详情（只读）。
    ReadProcess { pid: i32 },
    /// 本地受限控制（经本地策略门:只允许 nice 上调等可恢复动作）。
    ConstrainedControl { kind: ConstrainedKind, pid: i32 },
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConstrainedKind {
    /// nice 上调（降低优先级,可逆）。
    NiceLowerPriority { value: i32 },
}

/// 任务回执。
#[derive(Clone, Debug, PartialEq)]
pub struct TaskResult {
    pub task_id: u64,
    pub ok: bool,
    pub payload: Value,
}

impl Task {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::CollectOverview => "collect_overview",
            Self::ReadProcess { .. } => "read_process",
            Self::ConstrainedControl { .. } => "constrained_control",
        }
    }

    /// 审计要素（控制端可核对的摘要,不含任意字符串命令）。
    pub fn audit_json(&self, id: u64) -> Value {
        match self {
            Self::CollectOverview => json!({"task": "collect_overview", "id": id}),
            Self::ReadProcess { pid } => json!({"task": "read_process", "id": id, "pid": pid}),
            Self::ConstrainedControl { kind, pid } => json!({
                "task": "constrained_control", "id": id, "pid": pid,
                "kind": match kind {
                    ConstrainedKind::NiceLowerPriority { value } => json!({"nice": value}),
                },
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_kind_and_audit_shape() {
        let t = Task::ConstrainedControl { kind: ConstrainedKind::NiceLowerPriority { value: 5 }, pid: 42 };
        assert_eq!(t.kind(), "constrained_control");
        let a = t.audit_json(7);
        assert_eq!(a["kind"]["nice"], 5);
        assert!(a.get("shell").is_none(), "审计面不出现 shell 字段");
    }
}
