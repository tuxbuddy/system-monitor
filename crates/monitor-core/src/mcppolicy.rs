//! MCP 工具风险分级、授权策略与审计（#1）。
//!
//! 默认只读：未经显式授权，MCP 服务不得执行任何改变系统状态的工具。
//! - 风险分级 L0-L3 由固定分类表 + 参数敏愽数据共同决定（服务端强制，
//!   客户端注解只是提示）；
//! - 启动策略：`readonly`（默认，放行 L0/L1 只读与诊断）→ `confirm`
//!   （放行 L2 可恢复控制，L3 需一次性审批凭证）→ `trusted`（全放行）；
//! - L3 审批凭证由带外 CLI `system-monitor mcp-approve` 签发，绑定工具与
//!   具体参数、限时限次，不能复用到其它 PID/分组；
//! - 所有写操作（含被拒绝的）写审计日志。

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::fsutil;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum RiskLevel {
    /// 纯读取，无副作用。
    L0,
    /// 诊断：读取/连接可能触发采集，但不改变系统状态。
    L1,
    /// 可恢复控制：改变进程/分组状态但可撤销（nice、限额、探针挂载）。
    L2,
    /// 破坏性控制：不可撤销或影响面大（KILL、进程树、删除分组）。
    L3,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PolicyMode {
    Readonly,
    Confirm,
    Trusted,
}

impl PolicyMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "readonly" | "" => Some(Self::Readonly),
            "confirm" => Some(Self::Confirm),
            "trusted" => Some(Self::Trusted),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Readonly => "readonly",
            Self::Confirm => "confirm",
            Self::Trusted => "trusted",
        }
    }

    /// 当前模式下该风险等级是否需要审批凭证（只有 confirm 下的 L3 需要）。
    fn allowed(self, level: RiskLevel) -> Allowance {
        match self {
            Self::Readonly => {
                if level <= RiskLevel::L1 {
                    Allowance::Pass
                } else {
                    Allowance::Denied { required: self, level }
                }
            }
            Self::Confirm => {
                if level <= RiskLevel::L2 {
                    Allowance::Pass
                } else {
                    Allowance::Ticket
                }
            }
            Self::Trusted => Allowance::Pass,
        }
    }
}

enum Allowance {
    Pass,
    Ticket,
    /// `level` 进入 Deny 决策供调用方结构化展示
    Denied { required: PolicyMode, level: RiskLevel },
}

/// 工具基础分级表（参数敏感的升降级在 [`risk_of`] 中处理）。
fn base_risk(tool: &str) -> RiskLevel {
    match tool {
        // L0 纯读取
        "hosts_list" | "system_overview" | "system_load" | "process_list" | "network_connections"
        | "filesystems" | "process_details" => RiskLevel::L0,
        // L1 诊断（只读连接 / 探针元数据）
        "host_use" | "probe_status" | "probe_search" | "probe_poll" | "scheduler_status" | "psi_status" => RiskLevel::L1,
        // L2 可恢复控制
        "process_nice" | "scheduler_set_limit" | "probe_attach" | "probe_detach" => RiskLevel::L2,
        // L3 / 参数敏感
        "process_signal" | "scheduler_group_action" => RiskLevel::L2, // 具体看 risk_of
        // 元工具
        "policy_status" => RiskLevel::L0,
        other => {
            // 未知工具不允许任何放行猜测
            let _ = other;
            RiskLevel::L3
        }
    }
}

/// 结合参数计算实际风险：KILL / 进程树 / 删除分组升级为 L3。
pub fn risk_of(tool: &str, args: &Value) -> RiskLevel {
    match tool {
        "process_signal" => {
            let sig = args.get("signal").and_then(|v| v.as_str()).unwrap_or("TERM").to_uppercase();
            let tree = args.get("tree").and_then(|v| v.as_bool()).unwrap_or(false);
            if sig == "KILL" || tree {
                RiskLevel::L3
            } else {
                RiskLevel::L2
            }
        }
        "scheduler_group_action" => {
            match args.get("action").and_then(|v| v.as_str()).unwrap_or("") {
                "delete" => RiskLevel::L3,
                "create" => RiskLevel::L2,
                _ => RiskLevel::L3, // 未知动作按最高风险
            }
        }
        other => base_risk(other),
    }
}

/// 参数规范化摘要（审批凭证绑定用）：键排序、紧凑序列化。
fn canonical_params(args: &Value) -> String {
    fn norm(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), norm(&m[k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&norm(args)).unwrap_or_else(|_| "{}".to_string())
}

fn data_dir() -> Option<PathBuf> {
    // SM_HOME 仅供测试隔离：把状态文件指到临时目录，不碰真实用户数据
    let home = match std::env::var_os("SM_HOME") {
        Some(h) => h,
        None => std::env::var_os("HOME")?,
    };
    Some(PathBuf::from(home).join(".local/share/system-monitor"))
}

fn audit_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join("mcp-audit.jsonl"))
}

fn approvals_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join("mcp-approvals.json"))
}

fn secret_path() -> Option<PathBuf> {
    let home = match std::env::var_os("SM_HOME") {
        Some(h) => h,
        None => std::env::var_os("HOME")?,
    };
    Some(PathBuf::from(home).join(".config/system-monitor/mcp-secret"))
}

/// 审计事件：时间、主机、工具、参数摘要、结果、错误、调用方标识。
pub struct AuditEvent<'a> {
    pub tool: &'a str,
    pub host: &'a str,
    pub level: RiskLevel,
    pub ok: bool,
    pub error: Option<&'a str>,
    pub mode: PolicyMode,
    pub caller: &'a str,
}

/// 构造单条审计 JSON 行（纯函数，便于测试）。
pub fn audit_line(ev: &AuditEvent, ts: u64) -> String {
    let digest = {
        // 简单稳定摘要（无需密码学强度，仅去识别化）
        let mut h: u64 = 0xcbf29ce484222325;
        for b in ev.tool.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        format!("{h:016x}")
    };
    serde_json::json!({
        "ts": ts,
        "mode": ev.mode.as_str(),
        "tool": ev.tool,
        "host": ev.host,
        "level": ev.level.as_str(),
        "tool_digest": digest,
        "ok": ev.ok,
        "error": ev.error,
        "caller": ev.caller,
    })
    .to_string()
}

/// 追加一条审计记录（append + 大小轮转）。失败返回 Err 由调用方报告，不阻塞主流程。
pub fn audit(ev: &AuditEvent) -> std::io::Result<()> {
    let Some(p) = audit_path() else {
        return Ok(());
    };
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    fsutil::append_line_capped(&p, &audit_line(ev, ts), 2 * 1024 * 1024, 3, 8192)
}

/// 一次性审批凭证（token 绑定 工具+参数+过期时间；消费后作废）。
pub struct Approval {
    pub token: String,
    pub expires_at: u64,
    /// 签发时绑定的工具名（CLI 回显用；服务端校验走 token 本身）
    #[allow(dead_code)]
    pub tool: String,
    /// 签发时绑定的规范化参数（CLI 回显用）
    #[allow(dead_code)]
    pub params: String,
}

fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// 读取（或首次生成）本机签发密钥：0600，64 字节随机。
fn load_or_create_secret() -> Result<Vec<u8>, String> {
    use std::io::Read;
    let Some(p) = secret_path() else {
        return Err("无 HOME，无法管理审批密钥".to_string());
    };
    if let Ok(mut f) = std::fs::File::open(&p) {
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        if buf.len() >= 32 {
            return Ok(buf);
        }
    }
    // 生成新密钥：/dev/urandom 定长 64 字节（不能 read_to_end——urandom 永不 EOF 会挂死），
    // 回退时间+pid 混合
    let secret: Vec<u8> = {
        let mut buf = vec![0u8; 64];
        let ok = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| {
                use std::io::Read;
                f.read_exact(&mut buf)
            })
            .is_ok();
        if ok { buf } else { fallback_secret() }
    };
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    fsutil::atomic_write(&p, &secret, fsutil::MODE_PRIVATE).map_err(|e| e.to_string())?;
    Ok(secret)
}

fn fallback_secret() -> Vec<u8> {
    let mut seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
        ^ (std::process::id() as u64) << 32;
    (0..64)
        .map(|_| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        })
        .collect()
}

fn token_for(secret: &[u8], tool: &str, params: &str, expires_at: u64) -> String {
    let mut material = Vec::with_capacity(secret.len() + tool.len() + params.len() + 8);
    material.extend_from_slice(secret);
    material.extend_from_slice(tool.as_bytes());
    material.push(0);
    material.extend_from_slice(params.as_bytes());
    material.push(0);
    material.extend_from_slice(&expires_at.to_le_bytes());
    format!("v1.{:016x}.{}", fnv64(&material), expires_at)
}

fn used_tokens() -> Vec<String> {
    approvals_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.get("used").and_then(|u| u.as_array()).cloned())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn mark_used(token: &str) {
    let Some(p) = approvals_path() else { return };
    let mut used = used_tokens();
    used.push(token.to_string());
    // 只保留最近 256 条消费记录，防无限增长
    let drain = used.len().saturating_sub(256);
    used.drain(..drain);
    let body = serde_json::json!({ "used": used });
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = fsutil::atomic_write(&p, body.to_string().as_bytes(), fsutil::MODE_PRIVATE);
}

/// 签发审批凭证（CLI `mcp-approve` 调用）。打印给用户，由人转交给 AI 会话。
pub fn issue_approval(tool: &str, args: &Value, ttl_secs: u64) -> Result<Approval, String> {
    let risk = risk_of(tool, args);
    if risk < RiskLevel::L3 {
        return Err(format!("{tool} 风险等级为 {}，不需要审批凭证", risk.as_str()));
    }
    let secret = load_or_create_secret()?;
    let params = canonical_params(args);
    let expires_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() + ttl_secs.max(1);
    Ok(Approval { token: token_for(&secret, tool, &params, expires_at), expires_at, tool: tool.to_string(), params })
}

/// 校验并消费审批凭证：签名匹配 + 未过期 + 未使用过 + 参数一致。
/// 通过即消费（写入 used 列表），不可复用。
pub fn consume_approval(tool: &str, args: &Value, token: &str) -> Result<(), String> {
    let secret = load_or_create_secret()?;
    let params = canonical_params(args);
    // token 形如 v1.<hash>.<expires>
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != "v1" {
        return Err("审批凭证格式无效".to_string());
    }
    let Ok(expires_at) = parts[2].parse::<u64>() else {
        return Err("审批凭证格式无效".to_string());
    };
    let expect = token_for(&secret, tool, &params, expires_at);
    // 常量时间比较（防时序侧信道意义有限，但至少语义明确）
    if !constant_time_eq(expect.as_bytes(), token.as_bytes()) {
        return Err("审批凭证不匹配（工具或参数与签发时不一致，凭证不可跨参数复用）".to_string());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if now > expires_at {
        return Err("审批凭证已过期".to_string());
    }
    if used_tokens().iter().any(|t| t == token) {
        return Err("审批凭证已使用过（一次性）".to_string());
    }
    mark_used(token);
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 策略裁决结果。
#[derive(Debug)]
pub enum Decision {
    Allow,
    /// 需要审批凭证（附人可读指引）。
    NeedTicket { hint: String },
    /// 策略拒绝（附结构化错误信息）。
    Deny { error: String, required_level: RiskLevel },
}

/// 服务端强制校验入口：MCP 每个工具调用先经过这里。
pub fn check(mode: PolicyMode, tool: &str, args: &Value, token: Option<&str>) -> Decision {
    let level = risk_of(tool, args);
    match mode.allowed(level) {
        Allowance::Pass => Decision::Allow,
        Allowance::Ticket => match token {
            Some(t) => match consume_approval(tool, args, t) {
                Ok(()) => Decision::Allow,
                Err(e) => Decision::Deny { error: format!("审批失败：{e}"), required_level: level },
            },
            None => Decision::NeedTicket {
                hint: format!(
                    "工具 {tool} 风险等级 {}（破坏性控制），confirm 模式下需要一次性审批凭证。\
                     请让用户在服务所在主机运行：system-monitor mcp-approve --tool {tool} --args '{}' --ttl 60，\
                     然后把输出的 token 作为 approval_token 参数重新调用。",
                    level.as_str(),
                    canonical_params(args)
                ),
            },
        },
        Allowance::Denied { required, level: denied_level } => Decision::Deny {
            error: format!(
                "策略拒绝：当前模式 {} 不允许执行 {}（风险 {}）。启动时使用 --mcp-policy=confirm 或 trusted 可提升权限。",
                required.as_str(),
                tool,
                level.as_str()
            ),
            required_level: denied_level,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    /// 串行化所有触碰密钥/审批文件的测试（env var 与文件系统都是进程级共享）。
    fn state_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 在独立临时 HOME 里执行（测试互不污染，也不写真实用户目录）。
    fn isolated<F: FnOnce()>(f: F) {
        let _g = state_lock();
        let tmp = std::env::temp_dir().join(format!("sm-mcpolicy-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // SAFETY: 所有触碰 SM_HOME 的测试都在 state_lock 内串行执行
        unsafe { std::env::set_var("SM_HOME", &tmp) };
        f();
        unsafe { std::env::remove_var("SM_HOME") };
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn args(pid: i32, sig: &str, tree: bool) -> Value {
        json!({"pid": pid, "signal": sig, "tree": tree})
    }

    #[test]
    fn risk_classification() {
        assert_eq!(risk_of("system_overview", &json!({})), RiskLevel::L0);
        assert_eq!(risk_of("probe_search", &json!({})), RiskLevel::L1);
        assert_eq!(risk_of("process_nice", &json!({"pid": 1, "nice": 5})), RiskLevel::L2);
        assert_eq!(risk_of("process_signal", &args(42, "TERM", false)), RiskLevel::L2);
        assert_eq!(risk_of("process_signal", &args(42, "KILL", false)), RiskLevel::L3);
        assert_eq!(risk_of("process_signal", &args(42, "TERM", true)), RiskLevel::L3);
        assert_eq!(risk_of("scheduler_group_action", &json!({"action": "create", "name": "g"})), RiskLevel::L2);
        assert_eq!(risk_of("scheduler_group_action", &json!({"action": "delete", "name": "g"})), RiskLevel::L3);
        assert_eq!(risk_of("unknown_tool", &json!({})), RiskLevel::L3);
    }

    #[test]
    fn readonly_denies_all_writes() {
        let d = check(PolicyMode::Readonly, "process_nice", &json!({"pid": 42, "nice": 5}), None);
        assert!(matches!(d, Decision::Deny { .. }), "readonly 必须拒绝 L2");
        let d = check(PolicyMode::Readonly, "process_signal", &args(42, "KILL", false), None);
        assert!(matches!(d, Decision::Deny { .. }));
        // 只读与诊断放行
        assert!(matches!(check(PolicyMode::Readonly, "system_overview", &json!({}), None), Decision::Allow));
        assert!(matches!(check(PolicyMode::Readonly, "host_use", &json!({"host": "x"}), None), Decision::Allow));
    }

    #[test]
    fn confirm_allows_l2_but_l3_needs_ticket() {
        assert!(matches!(check(PolicyMode::Confirm, "process_nice", &json!({"pid": 42, "nice": 5}), None), Decision::Allow));
        let a = args(42, "KILL", false);
        assert!(matches!(check(PolicyMode::Confirm, "process_signal", &a, None), Decision::NeedTicket { .. }));
        // 假 token 拒绝
        match check(PolicyMode::Confirm, "process_signal", &a, Some("v1.0000.1")) {
            Decision::Deny { error, .. } => assert!(error.contains("审批失败")),
            other => panic!("假 token 应拒绝，实际 {other:?}"),
        }
    }

    #[test]
    fn trusted_allows_everything() {
        assert!(matches!(check(PolicyMode::Trusted, "process_signal", &args(42, "KILL", true), None), Decision::Allow));
    }

    #[test]
    fn approval_ticket_binds_params_and_is_single_use() {
        isolated(|| {
        let a = args(4242, "KILL", false);
        let ap = issue_approval("process_signal", &a, 60).expect("签发");
        // 匹配参数:允许;并立即消费
        assert!(consume_approval("process_signal", &a, &ap.token).is_ok(), "正确凭证应通过");
        // 复用拒绝
        let err = consume_approval("process_signal", &a, &ap.token).unwrap_err();
        assert!(err.contains("已使用"), "{err}");
        // 不同参数拒绝（凭证不可跨 PID 复用）
        let other = args(9999, "KILL", false);
        let ap2 = issue_approval("process_signal", &other, 60).unwrap();
        let err = consume_approval("process_signal", &a, &ap2.token).unwrap_err();
        assert!(err.contains("不匹配"), "{err}");
        // 过期拒绝
        let expired = Approval {
            token: {
                let secret = load_or_create_secret().unwrap();
                token_for(&secret, "process_signal", &canonical_params(&a), 1)
            },
            expires_at: 1,
            tool: "process_signal".to_string(),
            params: canonical_params(&a),
        };
        std::thread::sleep(Duration::from_millis(10));
        let err = consume_approval("process_signal", &a, &expired.token).unwrap_err();
        assert!(err.contains("过期"), "{err}");
        });
    }

    #[test]
    fn canonical_params_is_order_insensitive() {
        let a = json!({"pid": 42, "signal": "KILL"});
        let b = json!({"signal": "KILL", "pid": 42});
        assert_eq!(canonical_params(&a), canonical_params(&b));
        assert_ne!(canonical_params(&a), canonical_params(&json!({"pid": 43, "signal": "KILL"})));
    }

    #[test]
    fn policy_mode_parsing() {
        assert_eq!(PolicyMode::parse(""), Some(PolicyMode::Readonly));
        assert_eq!(PolicyMode::parse("READONLY"), Some(PolicyMode::Readonly));
        assert_eq!(PolicyMode::parse("confirm"), Some(PolicyMode::Confirm));
        assert_eq!(PolicyMode::parse("trusted"), Some(PolicyMode::Trusted));
        assert_eq!(PolicyMode::parse("yolo"), None);
    }

    #[test]
    fn audit_line_is_valid_json() {
        let ev = AuditEvent { tool: "process_signal", host: "local", level: RiskLevel::L3, ok: false, error: Some("策略拒绝"), mode: PolicyMode::Readonly, caller: "test" };
        let line = audit_line(&ev, 1_738_000_000);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["tool"], "process_signal");
        assert_eq!(v["level"], "L3");
        assert_eq!(v["ok"], false);
        assert_eq!(v["ts"], 1_738_000_000);
        assert_eq!(v["mode"], "readonly");
        assert!(v["tool_digest"].as_str().unwrap().len() == 16);
    }
}
