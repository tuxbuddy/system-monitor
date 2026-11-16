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

    pub fn parse(s: &str) -> Self {
        match s {
            "low" => Self::Low,
            "medium" => Self::Medium,
            _ => Self::High,
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
    Aborted,
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
            Self::Aborted => "aborted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "collecting" => Some(Self::Collecting),
            "planning" => Some(Self::Planning),
            "awaiting_approval" => Some(Self::AwaitingApproval),
            "executing" => Some(Self::Executing),
            "verifying" => Some(Self::Verifying),
            "done" => Some(Self::Done),
            "aborted" => Some(Self::Aborted),
            _ => None,
        }
    }

    /// 当前阶段唯一推荐的下一步工具，直接放进每个响应，省得 AI 猜状态机。
    pub fn next_action(self) -> &'static str {
        match self {
            Self::Collecting => "diag_add_evidence",
            Self::Planning => "diag_approve",
            Self::AwaitingApproval | Self::Executing => "diag_execute",
            Self::Verifying => "diag_verify",
            Self::Done | Self::Aborted => "none",
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
    created_at: u64,
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
            created_at: unix_now(),
            next_id: 1,
        }
    }

    /// 会话级推荐下一步：收集阶段一旦有证据，就应该进入方案而不是继续堆证据。
    pub fn next_action(&self) -> &'static str {
        if self.phase == Phase::Collecting && !self.evidences.is_empty() {
            "diag_submit_plan"
        } else {
            self.phase.next_action()
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
    /// 没有证据的方案直接拒绝——避免 AI 在未观测的情况下直接动手。
    pub fn submit_plan(
        &mut self,
        description: &str,
        command_json: Value,
        risk: RiskLevel,
        rollback: &str,
        verify_metric: &str,
    ) -> Result<u64, String> {
        if self.evidences.is_empty() {
            return Err("提交方案前至少需要一条证据（先调用 diag_add_evidence）".to_string());
        }
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
        Ok(hash)
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

    /// 中止会话：不再推进状态机。
    pub fn abort(&mut self) -> Result<(), String> {
        if matches!(self.phase, Phase::Done | Phase::Aborted) {
            return Err(format!("会话已是 {}，不能中止", self.phase.as_str()));
        }
        self.phase = Phase::Aborted;
        Ok(())
    }

    /// 会话 JSON（审计/回放/持久化；含恢复所需字段与推荐下一步）。
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "phase": self.phase.as_str(),
            "next_action": self.next_action(),
            "created_at": self.created_at,
            "evidences": self.evidences.iter().map(|e| json!({
                "id": e.id, "ts": e.ts_unix, "source": e.source,
                "fact": e.fact, "hypothesis": e.hypothesis, "confidence": e.confidence.as_str(),
            })).collect::<Vec<_>>(),
            "plans": self.plans.values().map(|p| json!({
                "id": p.id, "hash": format!("{:016x}", p.hash), "description": p.description,
                "risk": p.risk.as_str(), "command": p.command_json,
                "rollback": p.rollback, "verify_metric": p.verify_metric,
            })).collect::<Vec<_>>(),
            "approved": self.approved.map(|(h, t)| json!({"plan_hash": format!("{h:016x}"), "at": t})),
            "execution": self.execution.as_ref().map(|e| json!({"ok": e.ok, "message": e.message, "at": e.at_unix})),
            "verify": self.verify_note,
            "next_id": self.next_id,
        })
    }

    /// 从持久化 JSON 恢复（字段缺失时安全降级，不 panic）。
    pub fn from_json(v: &Value) -> Option<Self> {
        let id = v.get("id")?.as_str()?.to_string();
        let phase = Phase::parse(v.get("phase")?.as_str()?)?;
        let created_at = v.get("created_at").and_then(|x| x.as_u64()).unwrap_or(0);

        let mut evidences = Vec::new();
        for e in v.get("evidences").and_then(|x| x.as_array()).into_iter().flatten() {
            evidences.push(Evidence {
                id: e.get("id").and_then(|x| x.as_u64()).unwrap_or(0),
                ts_unix: e.get("ts").and_then(|x| x.as_u64()).unwrap_or(0),
                source: e.get("source").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                fact: e.get("fact").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                hypothesis: e.get("hypothesis").and_then(|x| x.as_str()).map(String::from),
                confidence: Confidence::parse(e.get("confidence").and_then(|x| x.as_str()).unwrap_or("high")),
            });
        }

        let mut plans = HashMap::new();
        for p in v.get("plans").and_then(|x| x.as_array()).into_iter().flatten() {
            let Some(hash) = p.get("hash").and_then(|x| x.as_str()).and_then(parse_hash) else { continue };
            let Some(risk) = p.get("risk").and_then(|x| x.as_str()).and_then(RiskLevel::parse) else { continue };
            plans.insert(
                hash,
                ActionPlan {
                    id: p.get("id").and_then(|x| x.as_u64()).unwrap_or(0),
                    description: p.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    hash,
                    risk,
                    command_json: p.get("command").cloned().unwrap_or(Value::Null),
                    rollback: p.get("rollback").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    verify_metric: p.get("verify_metric").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                },
            );
        }

        let approved = v.get("approved").and_then(|a| {
            let hash = a.get("plan_hash").and_then(|x| x.as_str()).and_then(parse_hash)?;
            let at = a.get("at").and_then(|x| x.as_u64()).unwrap_or(0);
            Some((hash, at))
        });
        let execution = v.get("execution").and_then(|e| {
            Some(ExecutionResult {
                ok: e.get("ok")?.as_bool()?,
                message: e.get("message").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                at_unix: e.get("at").and_then(|x| x.as_u64()).unwrap_or(0),
            })
        });
        let next_id = v
            .get("next_id")
            .and_then(|x| x.as_u64())
            .unwrap_or_else(|| evidences.len().max(plans.len()) as u64 + 1);

        Some(Self {
            id,
            phase,
            evidences,
            plans,
            approved,
            execution,
            verify_note: v.get("verify").and_then(|x| x.as_str()).map(String::from),
            created_at,
            next_id,
        })
    }
}

fn parse_hash(s: &str) -> Option<u64> {
    u64::from_str_radix(s, 16).ok()
}

/// 会话 id 形如 `diag-<unix>-<pid>-<seq>`：只允许字母数字与 `-`。
fn is_valid_session_id(id: &str) -> bool {
    id.starts_with("diag-") && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

impl Default for DiagnosticSession {
    fn default() -> Self {
        Self::new()
    }
}

/// 会话仓库（MCP 单实例持有）。默认不落盘（单测隔离）；
/// `load_or_default` 在真实服务里启用持久化，MCP 重启后可继续未完成会话。
#[derive(Default)]
pub struct SessionStore {
    sessions: HashMap<String, DiagnosticSession>,
    dir: Option<std::path::PathBuf>,
}

/// 内存中最多保留的会话数；超出时优先淘汰已结束、再淘汰最旧的。
pub const MAX_SESSIONS: usize = 64;
/// 磁盘上最多保留的会话报告数（防止长期运行无限增长）。
pub const MAX_SESSION_FILES: usize = 256;

impl SessionStore {
    /// 从数据目录恢复近期会话（最多 32 个文件），并启用后续持久化。
    pub fn load_or_default() -> Self {
        let Some(dir) = monitor_core::mcppolicy::data_dir().map(|d| d.join("diag")) else {
            return Self::default();
        };
        Self::load_from(dir)
    }

    /// 从指定目录恢复（可测试入口，不读环境变量）。
    pub fn load_from(dir: std::path::PathBuf) -> Self {
        let mut store = Self { sessions: HashMap::new(), dir: Some(dir.clone()) };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return store;
        };
        let mut files: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        let start = files.len().saturating_sub(32);
        for path in &files[start..] {
            let Some(sess) = std::fs::read_to_string(path)
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                .and_then(|v| DiagnosticSession::from_json(&v))
            else {
                continue;
            };
            // 文件名来自会话 id：只接受本程序生成的格式，防止异常 id 造成路径穿越
            if !is_valid_session_id(&sess.id) {
                continue;
            }
            store.sessions.insert(sess.id.clone(), sess);
        }
        while store.sessions.len() > MAX_SESSIONS {
            store.evict_one();
        }
        store
    }

    pub fn create(&mut self) -> &DiagnosticSession {
        while self.sessions.len() >= MAX_SESSIONS {
            self.evict_one();
        }
        let s = DiagnosticSession::new();
        let id = s.id.clone();
        self.sessions.insert(id.clone(), s);
        let _ = self.persist(&id);
        self.prune_files(MAX_SESSION_FILES);
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

    /// 最近会话摘要：AI 重启后不用先记住 session id 也能挑到要续的会话。
    pub fn summaries(&self, limit: usize) -> Vec<Value> {
        let mut list: Vec<&DiagnosticSession> = self.sessions.values().collect();
        list.sort_by_key(|s| std::cmp::Reverse(s.created_at));
        list.into_iter()
            .take(limit)
            .map(|s| {
                json!({
                    "session": s.id,
                    "phase": s.phase.as_str(),
                    "next_action": s.next_action(),
                    "created_at": s.created_at,
                    "evidences": s.evidences.len(),
                    "plans": s.plans.len(),
                    "approved": s.approved.map(|(h, _)| format!("{h:016x}")),
                    "executed": s.execution.as_ref().map(|e| e.ok),
                })
            })
            .collect()
    }

    /// 持久化单个会话，返回落盘路径（未启用持久化时为 None）。
    pub fn persist(&self, id: &str) -> Option<std::path::PathBuf> {
        if !is_valid_session_id(id) {
            return None;
        }
        let dir = self.dir.as_ref()?;
        let body = self.sessions.get(id)?.to_json().to_string();
        let path = dir.join(format!("{id}.json"));
        match monitor_core::fsutil::atomic_write(&path, body.as_bytes(), monitor_core::fsutil::MODE_PRIVATE) {
            Ok(()) => Some(path),
            Err(e) => {
                eprintln!("system-monitor mcp: 诊断会话写入失败：{e}");
                None
            }
        }
    }

    /// 淘汰一个会话：优先已结束（done/aborted），其次最旧。只移除内存，保留审计文件。
    fn evict_one(&mut self) {
        let victim = self
            .sessions
            .values()
            .filter(|s| matches!(s.phase, Phase::Done | Phase::Aborted))
            .min_by_key(|s| s.created_at)
            .or_else(|| self.sessions.values().min_by_key(|s| s.created_at))
            .map(|s| s.id.clone());
        if let Some(id) = victim {
            self.sessions.remove(&id);
        }
    }

    /// 仅保留最近 `keep` 份报告文件；删除失败不阻塞主流程。
    fn prune_files(&self, keep: usize) {
        let Some(dir) = &self.dir else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut files: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        if files.len() <= keep {
            return;
        }
        files.sort();
        for path in files.iter().take(files.len() - keep) {
            let _ = std::fs::remove_file(path);
        }
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
        let h = sess
            .submit_plan("将 media 分组 CPU 限到 50%", cmd.clone(), RiskLevel::L2, "恢复 cpu.max 为 max", "psi.cpu.some avg10 < 20")
            .unwrap();
        assert_eq!(sess.phase, Phase::Planning);
        assert_eq!(sess.phase.next_action(), "diag_approve");

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
        sess.add_evidence("ps", "pid 4242 占用 180% CPU", None, Confidence::High);
        let cmd = json!({"kind": "signal", "pid": 4242, "sig": 9});
        let h = sess
            .submit_plan("KILL pid 4242", cmd, RiskLevel::L3, "无", "进程消失")
            .unwrap();

        // L3 无凭证：拒绝
        let err = sess.approve(h, true, Err("凭证缺失".into())).unwrap_err();
        assert!(err.contains("L3 审批未通过"));
        assert!(sess.can_execute(h).is_err(), "未审批不可执行");

        // 有凭证：通过
        sess.approve(h, true, Ok(())).unwrap();
        assert!(sess.can_execute(h).is_ok());

        // 计划变更（提交新哈希的同描述? 内容不同 → 新哈希）→ 旧审批失效
        let cmd2 = json!({"kind": "signal", "pid": 9999, "sig": 9});
        let h2 = sess
            .submit_plan("KILL pid 9999", cmd2, RiskLevel::L3, "无", "进程消失")
            .unwrap();
        assert_ne!(h, h2);
        assert!(sess.can_execute(h2).is_err(), "新计划未审批");
        // 内容相同的计划 → 哈希一致
        let h3 = sess
            .submit_plan("KILL pid 4242", json!({"kind": "signal", "pid": 4242, "sig": 9}), RiskLevel::L3, "无", "进程消失")
            .unwrap();
        assert_eq!(h, h3, "同内容同哈希(幂等审批)");
    }

    #[test]
    fn plan_requires_evidence_first() {
        let mut sess = DiagnosticSession::new();
        let err = sess
            .submit_plan("blind", json!({"kind": "nice", "pid": 1, "nice": 5}), RiskLevel::L2, "restore", "metric")
            .unwrap_err();
        assert!(err.contains("至少需要一条证据"), "{err}");
        sess.add_evidence("proc", "cpu 90%", None, Confidence::High);
        assert!(sess
            .submit_plan("now grounded", json!({"kind": "nice", "pid": 1, "nice": 5}), RiskLevel::L2, "restore", "metric")
            .is_ok());
    }

    #[test]
    fn session_json_roundtrip_and_abort() {
        let mut sess = DiagnosticSession::new();
        sess.add_evidence("psi", "memory.some avg10=60", Some("真实压力"), Confidence::Medium);
        let h = sess
            .submit_plan("nice", json!({"kind": "nice", "pid": 7, "nice": 10}), RiskLevel::L2, "nice=0", "psi<20")
            .unwrap();
        sess.approve(h, true, Ok(())).unwrap();
        sess.record_execution(h, true, "ok").unwrap();

        let restored = DiagnosticSession::from_json(&sess.to_json()).expect("可恢复");
        assert_eq!(restored.id, sess.id);
        assert_eq!(restored.phase, Phase::Verifying);
        assert_eq!(restored.evidences.len(), 1);
        assert!(restored.plans.contains_key(&h));
        assert_eq!(restored.plans[&h].command_json["pid"], 7);
        assert_eq!(restored.phase.next_action(), "diag_verify");

        // 恢复后仍可完成验证
        let mut restored = restored;
        restored.verify("ps 回落");
        assert_eq!(restored.phase, Phase::Done);
        assert!(restored.abort().is_err(), "已归档不能中止");
    }

    #[test]
    fn store_caps_sessions_and_prefers_evicting_finished() {
        let mut store = SessionStore::default();
        for _ in 0..MAX_SESSIONS {
            let id = store.create().id.clone();
            store.get_mut(&id).unwrap().verify("done");
        }
        assert_eq!(store.ids().len(), MAX_SESSIONS);
        store.create();
        assert_eq!(store.ids().len(), MAX_SESSIONS, "超出上限必须淘汰");
    }

    #[test]
    fn persistence_writes_and_loads_session() {
        let tmp = std::env::temp_dir().join(format!("sm-diag-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut store = SessionStore { sessions: HashMap::new(), dir: Some(tmp.clone()) };
        let id = store.create().id.clone();
        {
            let sess = store.get_mut(&id).unwrap();
            sess.add_evidence("proc", "cpu 80%", None, Confidence::High);
        }
        let path = store.persist(&id).expect("写入");
        assert!(path.exists());
        assert!(store.persist("../evil").is_none(), "异常 id 不得落到目录外");
        let text = std::fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        let loaded = DiagnosticSession::from_json(&v).expect("可加载");
        assert_eq!(loaded.evidences.len(), 1);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn summaries_expose_resumable_state() {
        let mut store = SessionStore::default();
        let with_evidence = store.create().id.clone();
        let _empty = store.create().id.clone();
        {
            let sess = store.get_mut(&with_evidence).unwrap();
            sess.add_evidence("proc", "cpu 10%", None, Confidence::High);
        }
        let list = store.summaries(10);
        assert_eq!(list.len(), 2);
        let row = list.iter().find(|v| v["session"] == with_evidence).unwrap();
        assert_eq!(row["phase"], "collecting");
        assert_eq!(row["next_action"], "diag_submit_plan");
        assert_eq!(row["evidences"], 1);
    }

    #[test]
    fn load_from_restores_persisted_sessions() {
        let tmp = std::env::temp_dir().join(format!("sm-diag-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut store = SessionStore::load_from(tmp.clone());
        let id = store.create().id.clone();
        {
            let sess = store.get_mut(&id).unwrap();
            sess.add_evidence("proc", "cpu 40%", None, Confidence::High);
        }
        assert!(store.persist(&id).is_some());
        drop(store);

        let loaded = SessionStore::load_from(tmp.clone());
        assert!(loaded.get(&id).is_some(), "重启后应恢复会话");
        assert_eq!(loaded.summaries(5)[0]["session"], id);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn prune_files_keeps_newest_reports() {
        let tmp = std::env::temp_dir().join(format!("sm-diag-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        for i in 1..=5 {
            std::fs::write(tmp.join(format!("diag-{i}.json")), "{}").unwrap();
        }
        let store = SessionStore { sessions: HashMap::new(), dir: Some(tmp.clone()) };
        store.prune_files(2);
        let mut left: Vec<String> = std::fs::read_dir(&tmp)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, vec!["diag-4.json", "diag-5.json"]);
        let _ = std::fs::remove_dir_all(&tmp);
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
