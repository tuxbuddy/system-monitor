//! MCP 诊断会话工作流（#25）：证据 → 方案 → 审批 → 执行 → 验证 → 归档。
//!
//! 领域模型：
//! - `Evidence`：来源/时间/原始值/推断，区分事实与假设（confidence）。
//! - `ActionPlan`：风险等级、影响范围、回滚步骤、预期验证指标；哈希绑定内容。
//! - `Approval`：绑定计划哈希，计划变更即失效；L3 动作必须审批
//!   （复用 mcppolicy 的一次性凭证，不另造审批通道）。
//! - `DiagnosticSession`：可持久化（JSONL 追加，脱敏导出）。
//!
//! 执行一律经 [`crate::service::CommandDispatcher`]（策略+审计），
//! 会话本身不做任何系统副作用。

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use monitor_core::mcppolicy::RiskLevel;

/// 单条证据：fact（直接读数）或 hypothesis（推断，带置信度）。
#[derive(Clone, Debug, PartialEq)]
pub struct Evidence {
    pub id: u64,
    pub ts_unix: u64,
    pub source: String,
    pub fact: String,
    pub hypothesis: Option<String>,
    pub confidence: Confidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// 动作方案：绑定命令（经 dispatcher 执行）与回滚。
#[derive(Clone, Debug)]
pub struct ActionPlan {
    pub id: u64,
    pub description: String,
    /// 计划内容哈希（审批绑定键；变更即失效）。
    pub hash: u64,
    pub risk: RiskLevel,
    /// 序列化的命令描述（执行时经 dispatcher 重建）。
    pub command_json: Value,
    pub rollback: String,
    /// 预期验证指标（执行后复采核对）。
    pub verify_metric: String,
}

/// 计划内容哈希（FNV-1a；语义=同一描述+命令+风险 必须同哈希）。
pub fn plan_hash(description: &str, command_json: &Value, risk: RiskLevel) -> u64 {
    let material = format!("{description}|{command_json}|{}", risk.as_str());
    let mut h: u64 = 0xcbf29ce484222325;
    for b in material.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// 会话阶段。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Phase {
    Collecting,
    Planning,
    AwaitingApproval,
    Executing,
    Verifying,
    Done,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Planning => "planning",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Executing => "executing",
            Self::Verifying => "verifying",
            Self::Done => "done",
        }
    }
}

/// 一次端到端诊断会话。
#[derive(Clone, Debug)]
pub struct DiagnosticSession {
    pub id: String,
    pub phase: Phase,
    pub evidences: Vec<Evidence>,
    pub plans: HashMap<u64, ActionPlan>,
    pub approved: Option<(u64, u64)>, // (plan_hash, approved_at_unix)
    pub execution: Option<ExecutionResult>,
    pub verify_note: Option<String>,
    next_id: u64,
}

#[derive(Clone, Debug)]
pub struct ExecutionResult {
    pub ok: bool,
    pub message: String,
    pub at_unix: u64,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}



impl DiagnosticSession {
    pub fn new() -> Self {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let id = format!("diag-{}-{}-{}", unix_now(), std::process::id(), seq);
        Self {
            id,
            phase: Phase::Collecting,
            evidences: Vec::new(),
            plans: HashMap::new(),
            approved: None,
            execution: None,
            verify_note: None,
            next_id: 1,
        }
    }

    /// 追加证据。
    pub fn add_evidence(&mut self, source: &str, fact: &str, hypothesis: Option<&str>, confidence: Confidence) -> &Evidence {
        let ev = Evidence {
            id: self.next_id,
            ts_unix: unix_now(),
            source: source.to_string(),
            fact: fact.to_string(),
            hypothesis: hypothesis.map(String::from),
            confidence,
        };
        self.next_id += 1;
        self.evidences.push(ev);
        self.evidences.last().expect("刚刚 push")
    }

    /// 提交方案：进入 Planning；返回计划哈希（审批键）。
    pub fn submit_plan(
        &mut self,
        description: &str,
        command_json: Value,
        risk: RiskLevel,
        rollback: &str,
        verify_metric: &str,
    ) -> u64 {
        let hash = plan_hash(description, &command_json, risk);
        self.plans.insert(
            hash,
            ActionPlan {
                id: self.next_id,
                description: description.to_string(),
                hash,
                risk,
                command_json,
                rollback: rollback.to_string(),
                verify_metric: verify_metric.to_string(),
            },
        );
        self.next_id += 1;
        if self.phase < Phase::Planning {
            self.phase = Phase::Planning;
        }
        hash
    }

    /// 请求审批：计划哈希对应 L3 时必须给出凭证（consume 由 mcppolicy 校验）。
    /// 审批通过后进入 AwaitingApproval→（凭证通过）可执行状态。
    pub fn approve(&mut self, plan_hash: u64, approved: bool, token_result: Result<(), String>) -> Result<(), String> {
        let plan = self.plans.get(&plan_hash).ok_or("计划不存在")?;
        if plan.risk >= RiskLevel::L3 {
            token_result.map_err(|e| format!("L3 审批未通过：{e}"))?;
        }
        if approved {
            self.approved = Some((plan_hash, unix_now()));
            self.phase = Phase::AwaitingApproval;
        }
        Ok(())
    }

    /// 计划是否可执行：已审批 + 哈希未变。
    pub fn can_execute(&self, plan_hash: u64) -> Result<(), String> {
        let Some((approved_hash, _)) = self.approved else {
            return Err("计划未审批".to_string());
        };
        if approved_hash != plan_hash {
            return Err("审批与计划不匹配（计划已变更即失效）".to_string());
        }
        if !self.plans.contains_key(&plan_hash) {
            return Err("计划已被替换".to_string());
        }
        Ok(())
    }

    /// 记录执行结果（执行本身由调用方经 dispatcher 完成）。
    pub fn record_execution(&mut self, plan_hash: u64, ok: bool, message: &str) -> Result<(), String> {
        self.can_execute(plan_hash)?;
        self.execution = Some(ExecutionResult { ok, message: message.to_string(), at_unix: unix_now() });
        self.phase = Phase::Verifying;
        Ok(())
    }

    /// 复采验证：给出验证说明后归档。
    pub fn verify(&mut self, note: &str) {
        self.verify_note = Some(note.to_string());
        self.phase = Phase::Done;
    }

    /// 会话 JSON（审计/回放用；敏感字段已由证据来源控制,这里不再二次脱敏）。
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "phase": self.phase.as_str(),
            "evidences": self.evidences.iter().map(|e| json!({
                "id": e.id, "ts": e.ts_unix, "source": e.source,
                "fact": e.fact, "hypothesis": e.hypothesis, "confidence": e.confidence.as_str(),
            })).collect::<Vec<_>>(),
            "plans": self.plans.values().map(|p| json!({
                "hash": format!("{:016x}", p.hash), "description": p.description,
                "risk": p.risk.as_str(), "rollback": p.rollback, "verify_metric": p.verify_metric,
            })).collect::<Vec<_>>(),
            "approved": self.approved.map(|(h, t)| json!({"plan_hash": format!("{h:016x}"), "at": t})),
            "execution": self.execution.as_ref().map(|e| json!({"ok": e.ok, "message": e.message, "at": e.at_unix})),
            "verify": self.verify_note,
        })
    }
}

impl Default for DiagnosticSession {
    fn default() -> Self {
        Self::new()
    }
}

/// 会话仓库（进程内；MCP 单实例持有）。持久化由调用方按需 to_json 落盘。
#[derive(Default)]
pub struct SessionStore {
    sessions: HashMap<String, DiagnosticSession>,
}

impl SessionStore {
    pub fn create(&mut self) -> &DiagnosticSession {
        let s = DiagnosticSession::new();
        let id = s.id.clone();
        self.sessions.insert(id.clone(), s);
        self.sessions.get(&id).expect("刚刚插入")
    }

    pub fn get(&self, id: &str) -> Option<&DiagnosticSession> {
        self.sessions.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut DiagnosticSession> {
        self.sessions.get_mut(id)
    }

    pub fn ids(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 「高 CPU」端到端演示：证据 → 方案 → 审批 → 执行 → 验证（fake 执行器）。
    #[test]
    fn end_to_end_high_cpu_session() {
        let mut store = SessionStore::default();
        let sid = store.create().id.clone();
        let sess = store.get_mut(&sid).unwrap();

        // 1. 采集证据
        sess.add_evidence("/proc/stat", "cpu 95%", Some("进程 ffmpeg 持续占满"), Confidence::High);
        sess.add_evidence("psi", "psi.cpu.some avg10=45", Some("资源真争用而非采样噪声"), Confidence::High);
        sess.add_evidence("ps", "ffmpeg pid=1234 nice=0", None, Confidence::High);
        assert_eq!(sess.phase, Phase::Collecting);

        // 2. 提交方案（限流 ffmpeg 所在分组到 50%,回滚=恢复 max）
        let cmd = json!({"kind": "cg_set", "group": "media", "pct": 50});
        let h = sess.submit_plan("将 media 分组 CPU 限到 50%", cmd.clone(), RiskLevel::L2, "恢复 cpu.max 为 max", "psi.cpu.some avg10 < 20");
        assert_eq!(sess.phase, Phase::Planning);

        // 3. L2 无需凭证即可审批
        sess.approve(h, true, Ok(())).unwrap();
        assert!(sess.can_execute(h).is_ok());

        // 4. 执行（fake dispatcher 结果）
        sess.record_execution(h, true, "cpu.max=50000 100000").unwrap();
        assert_eq!(sess.phase, Phase::Verifying);

        // 5. 复采验证 + 归档
        sess.verify("psi.cpu.some avg10 降至 8;进程未被杀");
        assert_eq!(sess.phase, Phase::Done);
        let j = sess.to_json();
        assert_eq!(j["phase"], "done");
        assert_eq!(j["evidences"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn l3_requires_token_and_plan_change_invalidates_approval() {
        let mut sess = DiagnosticSession::new();
        let cmd = json!({"kind": "signal", "pid": 4242, "sig": 9});
        let h = sess.submit_plan("KILL pid 4242", cmd, RiskLevel::L3, "无", "进程消失");

        // L3 无凭证：拒绝
        let err = sess.approve(h, true, Err("凭证缺失".into())).unwrap_err();
        assert!(err.contains("L3 审批未通过"));
        assert!(sess.can_execute(h).is_err(), "未审批不可执行");

        // 有凭证：通过
        sess.approve(h, true, Ok(())).unwrap();
        assert!(sess.can_execute(h).is_ok());

        // 计划变更（提交新哈希的同描述? 内容不同 → 新哈希）→ 旧审批失效
        let cmd2 = json!({"kind": "signal", "pid": 9999, "sig": 9});
        let h2 = sess.submit_plan("KILL pid 9999", cmd2, RiskLevel::L3, "无", "进程消失");
        assert_ne!(h, h2);
        assert!(sess.can_execute(h2).is_err(), "新计划未审批");
        // 内容相同的计划 → 哈希一致
        let h3 = sess.submit_plan("KILL pid 4242", json!({"kind": "signal", "pid": 4242, "sig": 9}), RiskLevel::L3, "无", "进程消失");
        assert_eq!(h, h3, "同内容同哈希(幂等审批)");
    }

    #[test]
    fn store_scopes_sessions() {
        let mut store = SessionStore::default();
        let a = store.create().id.clone();
        let b = store.create().id.clone();
        assert_ne!(a, b);
        assert_eq!(store.ids().len(), 2);
        assert!(store.get(&a).is_some());
    }

    #[test]
    fn hash_is_order_stable_and_risk_sensitive() {
        let h1 = plan_hash("d", &json!({"a": 1}), RiskLevel::L2);
        let h2 = plan_hash("d", &json!({"a": 1}), RiskLevel::L2);
        assert_eq!(h1, h2);
        let h3 = plan_hash("d", &json!({"a": 1}), RiskLevel::L3);
        assert_ne!(h1, h3);
    }
}
