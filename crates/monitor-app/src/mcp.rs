//! MCP 服务（stdio，换行分隔的 JSON-RPC 2.0）。
//! 启动：`system-monitor mcp`
//!
//! 暴露能力：主机切换、概览/负载、进程列表与信号、cgroup 调度、
//! 网络连接、文件系统、探针（本机 tracefs/uprobe）。
//! 远端主机经 SSH 采集与操作，与 GUI/TUI 使用同一套数据层。

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use monitor_core::mcppolicy::{self, PolicyMode, RiskLevel};
use crate::service::{CgAction, Command, CommandDispatcher};
use monitor_linux::pi::PiStats;
use monitor_linux::procstats::{self, FsUsage, NetConn, Sampler, Usage};
use monitor_remote::remote;

struct View {
    usage: Usage,
    pi: PiStats,
    filesystems: Vec<FsUsage>,
    conns: Vec<NetConn>,
    label: String,
    /// 采样距今秒数（本地近似 0）。
    age_secs: u64,
    /// 采集失败后返回旧数据时为 true。
    stale: bool,
    /// 最近一次采集失败原因。
    last_error: Option<String>,
}

/// 本地「附加」采样：只有概览、文件系统、网络工具需要。
#[derive(Clone)]
struct LocalAux {
    filesystems: Vec<FsUsage>,
    conns: Vec<NetConn>,
}

#[derive(Clone)]
struct Cached<T> {
    value: T,
    at: Instant,
}

impl<T> Cached<T> {
    fn fresh(&self, ttl: Duration) -> bool {
        self.at.elapsed() < ttl
    }
}

/// 每主机新鲜度元数据：失败时保留上次成功时间，才能真正给出 stale 数据。
#[derive(Default)]
struct RemoteFresh {
    last_ok: Option<Instant>,
    last_error: Option<String>,
}

/// 缓存窗口：连续工具调用（AI 常见行为）不再重复扫 /proc、跑 vcgencmd。
const LOCAL_USAGE_TTL: Duration = Duration::from_secs(2);
const LOCAL_PI_TTL: Duration = Duration::from_secs(5);
const LOCAL_AUX_TTL: Duration = Duration::from_secs(3);
const REMOTE_TTL: Duration = Duration::from_secs(2);

pub struct Server {
    current: Option<remote::SshTarget>,
    hosts: Vec<remote::SshTarget>,
    /// 每主机最近一次成功采样时刻与失败原因（新鲜度元数据）。
    remote_fresh: HashMap<String, RemoteFresh>,
    /// 服务端强制策略：默认 readonly，禁止隐式升级。
    policy: PolicyMode,
    caller: String,
    /// 统一命令执行器（#12）：写操作全部经它（策略+审计+错误归一）。
    dispatcher: CommandDispatcher,
    /// 诊断会话仓库（#25）。
    diag_store: std::sync::Arc<std::sync::Mutex<crate::diagnose::SessionStore>>,
    sampler: Sampler,
    local_usage: Option<Cached<Usage>>,
    local_pi: Option<Cached<PiStats>>,
    local_aux: Option<Cached<LocalAux>>,
    remote_cache: HashMap<String, Cached<remote::RemoteSample>>,
    remote_prev: HashMap<String, Option<remote::Counters>>,
    probe_cache: HashMap<String, (monitor_linux::probe::Snapshot, Instant)>,
    /// 当前活动探针所在主机：None=无，Some(None)=本机，Some(Some(host))=远端。
    probe_active: Option<Option<remote::SshTarget>>,
}

impl Server {
    fn new() -> Self {
        let mut s = Self {
            current: None,
            hosts: remote::load_hosts().0,
            policy: PolicyMode::Readonly,
            caller: std::env::var("SM_MCP_CALLER").unwrap_or_else(|_| "stdio".to_string()),
            dispatcher: CommandDispatcher::new(PolicyMode::Readonly, "mcp"),
            diag_store: std::sync::Arc::new(std::sync::Mutex::new(crate::diagnose::SessionStore::load_or_default())),
            remote_fresh: HashMap::new(),
            sampler: Sampler::new(),
            local_usage: None,
            local_pi: None,
            local_aux: None,
            remote_cache: HashMap::new(),
            remote_prev: HashMap::new(),
            probe_cache: HashMap::new(),
            probe_active: None,
        };
        // 预热：两次 150ms 间隔的采样，让首个工具调用就返回真实 CPU 百分比
        let _ = s.sampler.sample();
        std::thread::sleep(Duration::from_millis(150));
        let usage = s.sampler.sample();
        s.local_usage = Some(Cached { value: usage, at: Instant::now() });
        s.local_pi = Some(Cached { value: monitor_linux::pi::read_pi_stats(), at: Instant::now() });
        s
    }

    /// 解析工具参数里的目标主机：非法目标直接报错，绝不进入 ssh 命令行。
    fn target(&self, args: &Value) -> Result<Option<remote::SshTarget>, String> {
        match args.get("host").and_then(|v| v.as_str()) {
            Some(h) if !h.is_empty() && h != "local" => {
                remote::SshTarget::parse(h).map(Some).map_err(|e| format!("host 参数非法：{e}"))
            }
            Some(_) => Ok(None),
            None => Ok(self.current.clone()),
        }
    }

    /// 本地 CPU/进程采样：2 秒窗口内复用，长时间无调用时补一次短间隔采样。
    fn local_usage(&mut self) -> Usage {
        if let Some(c) = &self.local_usage
            && c.fresh(LOCAL_USAGE_TTL)
        {
            return c.value.clone();
        }
        let gap = self.local_usage.as_ref().map(|c| c.at.elapsed()).unwrap_or(Duration::MAX);
        let mut usage = self.sampler.sample();
        if gap > Duration::from_secs(3) {
            // 间隔太久时补一次短间隔采样，返回「瞬时」而不是长时间平均
            std::thread::sleep(Duration::from_millis(150));
            usage = self.sampler.sample();
        }
        self.local_usage = Some(Cached { value: usage.clone(), at: Instant::now() });
        usage
    }

    /// 本地传感器采样：vcgencmd 是子进程，单独 5 秒缓存，只有概览需要。
    fn local_pi(&mut self) -> PiStats {
        if let Some(c) = &self.local_pi
            && c.fresh(LOCAL_PI_TTL)
        {
            return c.value.clone();
        }
        let value = monitor_linux::pi::read_pi_stats();
        self.local_pi = Some(Cached { value: value.clone(), at: Instant::now() });
        value
    }

    /// 本地附加采样：文件系统与连接表，3 秒窗口内复用。
    fn local_aux(&mut self) -> LocalAux {
        if let Some(c) = &self.local_aux
            && c.fresh(LOCAL_AUX_TTL)
        {
            return c.value.clone();
        }
        let value = LocalAux {
            filesystems: procstats::read_filesystems(),
            conns: procstats::read_net_conns(),
        };
        self.local_aux = Some(Cached { value: value.clone(), at: Instant::now() });
        value
    }

    /// 采集视图。`aux` 控制是否读文件系统/连接表，`pi` 控制是否跑 vcgencmd；
    /// 进程、负载、网络、磁盘类工具不为此付无谓成本。
    fn view(&mut self, host: &Option<remote::SshTarget>, aux: bool, pi: bool) -> Result<View, String> {
        match host {
            None => {
                let usage = self.local_usage();
                let pi = if pi { self.local_pi() } else { PiStats::default() };
                let (filesystems, conns) = if aux {
                    let a = self.local_aux();
                    (a.filesystems, a.conns)
                } else {
                    (Vec::new(), Vec::new())
                };
                Ok(View {
                    usage,
                    pi,
                    filesystems,
                    conns,
                    label: "本地".to_string(),
                    age_secs: 0,
                    stale: false,
                    last_error: None,
                })
            }
            Some(h) => self.remote_view(h),
        }
    }

    fn remote_view(&mut self, h: &remote::SshTarget) -> Result<View, String> {
        let key = h.as_str().to_string();
        if let Some(c) = self.remote_cache.get(&key)
            && c.fresh(REMOTE_TTL)
        {
            let age = c.at.elapsed().as_secs();
            let last_error = self.remote_fresh.get(&key).and_then(|f| f.last_error.clone());
            return Ok(view_from_sample(c.value.clone(), key, age, last_error.is_some(), last_error));
        }
        let mut prev = self.remote_prev.remove(&key).flatten();
        let first = prev.is_none();
        let mut sample = remote::collect_result(h, &mut prev);
        if first && sample.is_err() {
            std::thread::sleep(Duration::from_millis(120));
            sample = remote::collect_result(h, &mut prev);
        }
        self.remote_prev.insert(key.clone(), prev);
        match sample {
            Ok(s) => {
                let at = Instant::now();
                self.remote_cache.insert(key.clone(), Cached { value: s.clone(), at });
                let fresh = self.remote_fresh.entry(key.clone()).or_default();
                fresh.last_ok = Some(at);
                fresh.last_error = None;
                Ok(view_from_sample(s, key, 0, false, None))
            }
            Err(e) => {
                let fresh = self.remote_fresh.entry(key.clone()).or_default();
                fresh.last_error = Some(e.clone());
                // 有历史成功样本：降级返回 stale 数据而不是整体报错，调用方仍可继续分析
                if let Some(c) = self.remote_cache.get(&key) {
                    let age = fresh
                        .last_ok
                        .map(|t| t.elapsed().as_secs())
                        .unwrap_or_else(|| c.at.elapsed().as_secs());
                    return Ok(view_from_sample(c.value.clone(), key, age, true, Some(e)));
                }
                Err(json!({
                    "error": "collect_failed",
                    "host": key,
                    "message": e,
                    "stale": false,
                })
                .to_string())
            }
        }
    }

    fn probe_snapshot(&mut self, host: &Option<remote::SshTarget>) -> Result<monitor_linux::probe::Snapshot, String> {
        let key = host
            .as_ref()
            .map(|t| t.as_str().to_string())
            .unwrap_or_else(|| "local".to_string());
        if let Some((snap, at)) = self.probe_cache.get(&key)
            && at.elapsed() < Duration::from_secs(60)
        {
            return Ok(snap.clone());
        }
        let snap = crate::probe_source::snapshot(host.as_ref())?;
        self.probe_cache.insert(key, (snap.clone(), Instant::now()));
        Ok(snap)
    }

    /// poll/detach 的 host 解析：显式 host 优先，否则用活动探针 host；都没有则本机。
    fn probe_host_arg(&self, args: &Value) -> Result<Option<remote::SshTarget>, String> {
        match args.get("host").and_then(|v| v.as_str()) {
            Some(h) if !h.is_empty() && h != "local" => {
                remote::SshTarget::parse(h).map(Some).map_err(|e| format!("host 参数非法：{e}"))
            }
            Some(_) => Ok(None),
            None => Ok(self.probe_active.clone().unwrap_or(None)),
        }
    }

    fn audit(&self, tool: &str, level: RiskLevel, ok: bool, error: Option<&str>) {
        let host = self.current.as_ref().map(|t| t.as_str()).unwrap_or("local");
        let ev = mcppolicy::AuditEvent {
            tool,
            host,
            level,
            ok,
            error,
            mode: self.policy,
            caller: &self.caller,
        };
        if let Err(e) = mcppolicy::audit(&ev) {
            eprintln!("system-monitor mcp: 审计写入失败：{e}");
        }
    }

    /// 工具调用统一入口：先做服务端策略裁决（拒绝也审计），再分派执行；
    /// L2/L3 写操作的执行结果同样审计。
    fn call(&mut self, name: &str, args: &Value) -> Result<Value, String> {
        let token = args.get("approval_token").and_then(|v| v.as_str());
        let level = mcppolicy::risk_of(name, args);
        match mcppolicy::check(self.policy, name, args, token) {
            mcppolicy::Decision::Allow => {}
            mcppolicy::Decision::NeedTicket { hint } => {
                self.audit(name, level, false, Some("needs_approval"));
                return Err(json!({
                    "error": "needs_approval",
                    "tool": name,
                    "level": level.as_str(),
                    "hint": hint,
                }).to_string());
            }
            mcppolicy::Decision::Deny { error, required_level } => {
                self.audit(name, level, false, Some("policy_denied"));
                return Err(json!({
                    "error": "policy_denied",
                    "tool": name,
                    "required_level": required_level.as_str(),
                    "current_mode": self.policy.as_str(),
                    "message": error,
                }).to_string());
            }
        }
        let result = self.call_inner(name, args);
        if level >= RiskLevel::L2 {
            match &result {
                Ok(_) => self.audit(name, level, true, None),
                Err(e) => self.audit(name, level, false, Some(e)),
            }
        }
        result
    }

    fn call_inner(&mut self, name: &str, args: &Value) -> Result<Value, String> {
        match name {
            "policy_status" => {
                let mut levels: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
                for (name, level) in mcppolicy::catalog() {
                    levels.entry(level.as_str()).or_default().push(name);
                }
                Ok(json!({
                    "mode": self.policy.as_str(),
                    "caller": self.caller,
                    "current_host": self.current.as_ref().map(|t| t.as_str()).unwrap_or("local"),
                    "levels": levels,
                    "parameter_sensitive": {
                        "process_signal": "signal=KILL 或 tree=true → L3",
                        "scheduler_group_action": "action=delete → L3",
                        "diag_execute": "实际风险由 plan 内命令决定，执行时经 dispatcher 复核",
                    },
                    "approval": "confirm 模式下 L3 需 approval_token（system-monitor mcp-approve 签发，一次性、绑定参数）",
                    "audit": "~/.local/share/system-monitor/mcp-audit.jsonl",
                }))
            }
            "hosts_list" => {
                let (saved, errs) = remote::load_hosts();
                Ok(json!({
                    "current": self.current.as_ref().map(|t| t.as_str()).unwrap_or("local"),
                    "hosts": saved.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
                    "invalid_lines": errs.iter().map(|e| json!({"line": e.line_no, "target": e.target, "error": e.error.to_string()})).collect::<Vec<_>>(),
                }))
            }
            "host_use" => {
                let h = args.get("host").and_then(|v| v.as_str()).unwrap_or("local").trim().to_string();
                if h.is_empty() || h == "local" {
                    self.current = None;
                    return Ok(json!({"current": "local", "os": local_os()}));
                }
                let target = remote::SshTarget::parse(&h).map_err(|e| format!("host 参数非法：{e}"))?;
                let mut prev = None;
                let sample = remote::collect_result(&target, &mut prev).map_err(|e| format!("无法连接主机：{h}（{e}）"))?;
                let at = Instant::now();
                self.remote_cache.insert(h.clone(), Cached { value: sample.clone(), at });
                self.remote_prev.insert(h.clone(), prev);
                let fresh = self.remote_fresh.entry(h.clone()).or_default();
                fresh.last_ok = Some(at);
                fresh.last_error = None;
                self.current = Some(target.clone());
                if !self.hosts.iter().any(|x| x == &target) {
                    self.hosts.push(target.clone());
                }
                Ok(json!({
                    "current": h,
                    "os": sample.pi.remote.as_ref().map(|r| r.os.clone()).unwrap_or_default(),
                    "uid": sample.pi.remote.as_ref().map(|r| r.uid).unwrap_or(0),
                }))
            }
            "system_overview" => {
                let host = self.target(args)?;
                let v = self.view(&host, true, true)?;
                Ok(overview_json(&v))
            }
            "system_load" => {
                let host = self.target(args)?;
                let v = self.view(&host, false, false)?;
                Ok(json!({
                    "host": v.label,
                    "load": v.usage.load.map(|l| json!({"1m": round2(l.one), "5m": round2(l.five), "15m": round2(l.fifteen)})),
                    "uptime_secs": v.usage.uptime_secs,
                    "process_count": v.usage.procs.len(),
                    "cpu_percent": round1(v.usage.total_percent),
                    "freshness": freshness_json(&v),
                }))
            }
            "process_list" => {
                let host = self.target(args)?;
                let v = self.view(&host, false, false)?;
                let sort = args.get("sort").and_then(|x| x.as_str()).unwrap_or("cpu");
                let limit = args.get("limit").and_then(|x| x.as_u64()).unwrap_or(25).clamp(1, 500) as usize;
                let filter = args.get("filter").and_then(|x| x.as_str()).unwrap_or("").to_lowercase();
                let mut procs: Vec<&procstats::ProcUsage> = v
                    .usage
                    .procs
                    .iter()
                    .filter(|p| {
                        filter.is_empty()
                            || p.comm.to_lowercase().contains(&filter)
                            || p.user.to_lowercase().contains(&filter)
                            || p.pid.to_string() == filter
                    })
                    .collect();
                match sort {
                    "mem" => procs.sort_by(|a, b| b.mem_percent.partial_cmp(&a.mem_percent).unwrap_or(std::cmp::Ordering::Equal)),
                    "rss" => procs.sort_by_key(|p| std::cmp::Reverse(p.rss_kb)),
                    "pid" => procs.sort_by_key(|p| p.pid),
                    _ => procs.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal)),
                }
                let total = procs.len();
                let rows: Vec<Value> = procs
                    .into_iter()
                    .take(limit)
                    .map(|p| {
                        json!({
                            "pid": p.pid, "ppid": p.ppid, "comm": p.comm, "user": p.user, "uid": p.uid,
                            "state": p.state.to_string(), "cpu_percent": round1(p.cpu_percent),
                            "mem_percent": round1(p.mem_percent), "rss_kb": p.rss_kb, "nice": p.nice,
                        })
                    })
                    .collect();
                Ok(json!({"host": v.label, "total": total, "sort": sort, "processes": rows, "freshness": freshness_json(&v)}))
            }
            "process_signal" => {
                let pid = args.get("pid").and_then(|v| v.as_i64()).ok_or("缺少 pid")? as i32;
                if pid <= 1 {
                    return Err("拒绝操作 PID ≤ 1".to_string());
                }
                let sig = args.get("signal").and_then(|v| v.as_str()).unwrap_or("TERM").to_uppercase();
                let tree = args.get("tree").and_then(|v| v.as_bool()).unwrap_or(false);
                let host = self.target(args)?;
                let num = signal_number(&sig)?;
                if tree && num != 9 && num != 15 {
                    return Err("tree=true 仅支持 TERM / KILL".to_string());
                }
                let (ok, n) = match &host {
                    None => {
                        if tree {
                            let r = if num == 9 { monitor_linux::actions::kill_tree(pid) } else { monitor_linux::actions::terminate_tree(pid) };
                            (r.map(|n| n as u64).map_err(|e| e.to_string())?, 0)
                        } else {
                            let signal = local_signal(&sig)?;
                            monitor_linux::actions::send_signal(pid, signal).map_err(|e| e.to_string())?;
                            (1, 0)
                        }
                    }
                    Some(h) => {
                        if tree {
                            let v = self.view(&host, false, false)?;
                            let pairs: Vec<(i32, i32)> = v.usage.procs.iter().map(|p| (p.pid, p.ppid)).collect();
                            let mut pids = procstats::descendants(pid, &pairs);
                            pids.push(pid);
                            (remote::signal_many(h, &pids, num)? as u64, 0)
                        } else {
                            remote::signal(h, pid, num)?;
                            (1, 0)
                        }
                    }
                };
                let count = if n > 0 { n } else { ok };
                Ok(json!({
                    "host": host.as_ref().map(|t| t.as_str()).unwrap_or("local"),
                    "pid": pid, "signal": sig, "tree": tree, "signalled": count,
                }))
            }
            "process_nice" => {
                let pid = args.get("pid").and_then(|v| v.as_i64()).ok_or("缺少 pid")? as i32;
                if pid <= 1 {
                    return Err("拒绝操作 PID ≤ 1".to_string());
                }
                let nice = args.get("nice").and_then(|v| v.as_i64()).ok_or("缺少 nice")?.clamp(-20, 19) as i32;
                let host = self.target(args)?;
                match &host {
                    None => monitor_linux::actions::set_nice(pid, nice).map_err(|e| e.to_string())?,
                    Some(h) => remote::set_nice(h, pid, nice)?,
                }
                Ok(json!({"host": host.as_ref().map(|t| t.as_str()).unwrap_or("local"), "pid": pid, "nice": nice}))
            }
            "host_capabilities" => {
                let host = args.get("host").and_then(|v| v.as_str());
                match host {
                    None | Some("local") | Some("") => {
                        let caps = monitor_linux::caps::detect_local();
                        let mut v = caps.to_json();
                        v["host"] = json!("local");
                        Ok(v)
                    }
                    Some(h) => {
                        let target = remote::SshTarget::parse(h).map_err(|e| format!("host 参数非法：{e}"))?;
                        let script = monitor_linux::caps::capabilities_script();
                        let out = remote::ssh_exec(&target, &script, &remote::ExecLimits::default(), None)
                            .map_err(|e| format!("远端能力采集失败：{e}"))?;
                        let mut v = monitor_linux::caps::parse_report(&out.stdout).to_json();
                        v["host"] = json!(h);
                        Ok(v)
                    }
                }
            }
            "process_details" => {
                let pid = args.get("pid").and_then(|v| v.as_i64()).ok_or("缺少 pid")? as i32;
                if pid <= 1 {
                    return Err("拒绝查询 PID ≤ 1".to_string());
                }
                if self.target(args)?.is_some() {
                    return Err("process_details 目前仅支持本地主机（远端用 process_list + host 上直接查询）".to_string());
                }
                let d = procstats::read_details(pid);
                Ok(json!({
                    "host": "local",
                    "pid": pid,
                    "uid": d.uid, "gid": d.gid, "threads": d.threads,
                    "vsize_kb": d.vsize_kb, "rss_kb": d.rss_kb,
                    "cmdline": d.cmdline, "exe": d.exe, "cwd": d.cwd,
                    "io_read_bytes": d.io_read_bytes, "io_write_bytes": d.io_write_bytes,
                    "io_rchar_wchar": d.io_rchar_wchar,
                    "fd_count": d.fd_count, "fd_limit": d.fd_limit,
                    "oom_score": d.oom_score, "oom_score_adj": d.oom_score_adj,
                }))
            }
            "ebpf_doctor" => {
                // eBPF 实验能力矩阵（#27）:不支持时明确列出原因
                let cap = monitor_linux::ebpf::detect();
                let mut v = cap.to_json();
                v["limits"] = monitor_linux::ebpf::ResourceLimits::from_env().to_json();
                v["experiments"] = monitor_linux::ebpf::experiments_json();
                Ok(v)
            }
            // ---- 诊断会话（#25）----
            "diag_start" => {
                let mut store = self.diag_store.lock().map_err(|e| e.to_string())?;
                let (id, phase, next) = {
                    let sess = store.create();
                    (sess.id.clone(), sess.phase.as_str(), sess.next_action())
                };
                let path = store.persist(&id);
                Ok(json!({
                    "session": id, "phase": phase, "next_action": next,
                    "persisted": path.is_some(),
                }))
            }
            "diag_add_evidence" => {
                let id = args.get("session").and_then(|v| v.as_str()).ok_or("缺少 session")?;
                let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("manual");
                let fact = args.get("fact").and_then(|v| v.as_str()).ok_or("缺少 fact")?;
                let hypothesis = args.get("hypothesis").and_then(|v| v.as_str());
                let conf = match args.get("confidence").and_then(|v| v.as_str()).unwrap_or("high") {
                    "low" => crate::diagnose::Confidence::Low,
                    "medium" => crate::diagnose::Confidence::Medium,
                    _ => crate::diagnose::Confidence::High,
                };
                let mut store = self.diag_store.lock().map_err(|e| e.to_string())?;
                let (evidence_id, phase, next) = {
                    let sess = store.get_mut(id).ok_or_else(|| format!("会话 {id} 不存在"))?;
                    let ev = sess.add_evidence(source, fact, hypothesis, conf);
                    (ev.id, sess.phase.as_str(), sess.next_action())
                };
                let _ = store.persist(id);
                Ok(json!({
                    "session": id, "evidence_id": evidence_id,
                    "phase": phase, "next_action": next,
                }))
            }
            "diag_submit_plan" => {
                let id = args.get("session").and_then(|v| v.as_str()).ok_or("缺少 session")?;
                let description = args.get("description").and_then(|v| v.as_str()).ok_or("缺少 description")?;
                let command = args.get("command").cloned().ok_or("缺少 command(经 dispatcher 执行的命令 JSON)")?;
                let rollback = args.get("rollback").and_then(|v| v.as_str()).unwrap_or("");
                let verify = args.get("verify_metric").and_then(|v| v.as_str()).unwrap_or("");
                let risk = derive_risk(&command)?;
                let mut store = self.diag_store.lock().map_err(|e| e.to_string())?;
                let (h, phase, next) = {
                    let sess = store.get_mut(id).ok_or_else(|| format!("会话 {id} 不存在"))?;
                    let h = sess.submit_plan(description, command, risk, rollback, verify)?;
                    (h, sess.phase.as_str(), sess.next_action())
                };
                let _ = store.persist(id);
                let mut warnings: Vec<&str> = Vec::new();
                if rollback.trim().is_empty() || rollback.trim() == "无" {
                    warnings.push("未提供回滚步骤：可恢复动作也应能还原");
                }
                if verify.trim().is_empty() {
                    warnings.push("未提供验证指标：执行后无法判断是否生效");
                }
                Ok(json!({
                    "session": id, "plan_hash": format!("{h:016x}"), "risk": risk.as_str(),
                    "phase": phase, "next_action": next, "warnings": warnings,
                }))
            }
            "diag_approve" => {
                let id = args.get("session").and_then(|v| v.as_str()).ok_or("缺少 session")?;
                let hash_raw = args.get("plan_hash").and_then(|v| v.as_str()).ok_or("缺少 plan_hash")?;
                let h = u64::from_str_radix(hash_raw, 16).map_err(|_| "plan_hash 需为 16 进制")?;
                let token = args.get("approval_token").and_then(|v| v.as_str()).map(String::from);
                let mut store = self.diag_store.lock().map_err(|e| e.to_string())?;
                let (phase, next) = {
                    let sess = store.get_mut(id).ok_or_else(|| format!("会话 {id} 不存在"))?;
                    let token_result = sess
                        .plans
                        .get(&h)
                        .map(|plan| {
                            if plan.risk >= monitor_core::mcppolicy::RiskLevel::L3 {
                                match &token {
                                    Some(t) => monitor_core::mcppolicy::consume_approval(
                                        "diag_execute",
                                        &json!({"session": id, "plan": plan.command_json}),
                                        t,
                                    )
                                    .map(|_| ()),
                                    None => Err("L3 需要 approval_token(mcp-approve --tool diag_execute)".to_string()),
                                }
                            } else {
                                Ok(())
                            }
                        })
                        .unwrap_or_else(|| Err("计划不存在".to_string()));
                    sess.approve(h, true, token_result).map_err(|e| e.to_string())?;
                    (sess.phase.as_str(), sess.next_action())
                };
                let _ = store.persist(id);
                Ok(json!({
                    "session": id, "plan_hash": hash_raw, "approved": true,
                    "phase": phase, "next_action": next,
                }))
            }
            "diag_execute" => {
                let id = args.get("session").and_then(|v| v.as_str()).ok_or("缺少 session")?;
                let hash_raw = args.get("plan_hash").and_then(|v| v.as_str()).ok_or("缺少 plan_hash")?;
                let h = u64::from_str_radix(hash_raw, 16).map_err(|_| "plan_hash 需为 16 进制")?;
                let mut store = self.diag_store.lock().map_err(|e| e.to_string())?;
                let (ok, msg, phase) = {
                    let sess = store.get_mut(id).ok_or_else(|| format!("会话 {id} 不存在"))?;
                    sess.can_execute(h).map_err(|e| e.to_string())?;
                    let cmd = sess.plans.get(&h).ok_or("计划不存在")?.command_json.clone();
                    let command = command_from_json(&cmd)?;
                    let (ok, msg) = match self.dispatcher.run(&command) {
                        Ok(m) => (true, m),
                        Err(e) => (false, e.to_string()),
                    };
                    sess.record_execution(h, ok, &msg).map_err(|e| e.to_string())?;
                    (ok, msg, sess.phase)
                };
                let _ = store.persist(id);
                Ok(json!({
                    "session": id, "ok": ok, "message": msg,
                    "phase": phase.as_str(), "next_action": phase.next_action(),
                }))
            }
            "diag_verify" => {
                let id = args.get("session").and_then(|v| v.as_str()).ok_or("缺少 session")?;
                let note = args.get("note").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let mut store = self.diag_store.lock().map_err(|e| e.to_string())?;
                let phase = {
                    let sess = store.get_mut(id).ok_or_else(|| format!("会话 {id} 不存在"))?;
                    sess.verify(&note);
                    sess.phase
                };
                let path = store.persist(id);
                let report = store.get(id).map(|s| s.to_json()).unwrap_or(Value::Null);
                Ok(json!({
                    "session": id, "phase": phase.as_str(), "next_action": phase.next_action(),
                    "report": report, "report_path": path.map(|p| p.display().to_string()),
                }))
            }
            "diag_status" => {
                let store = self.diag_store.lock().map_err(|e| e.to_string())?;
                match args.get("session").and_then(|v| v.as_str()) {
                    Some(id) => {
                        let sess = store.get(id).ok_or_else(|| format!("会话 {id} 不存在"))?;
                        Ok(sess.to_json())
                    }
                    None => {
                        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20).clamp(1, 64) as usize;
                        Ok(json!({
                            "sessions": store.summaries(limit),
                            "next_action": "diag_status",
                            "hint": "传入 session 查看完整报告；按 next_action 继续未完成会话",
                        }))
                    }
                }
            }
            "diag_abort" => {
                let id = args.get("session").and_then(|v| v.as_str()).ok_or("缺少 session")?;
                let mut store = self.diag_store.lock().map_err(|e| e.to_string())?;
                let phase = {
                    let sess = store.get_mut(id).ok_or_else(|| format!("会话 {id} 不存在"))?;
                    sess.abort()?;
                    sess.phase
                };
                let _ = store.persist(id);
                Ok(json!({"session": id, "phase": phase.as_str(), "next_action": "none"}))
            }
            "psi_status" => {
                let snap = monitor_core::psi::read_local();
                // cgroup v2 委派根下的 *.pressure 作为补充源(本地 /proc/pressure 缺失时尤其有用)
                let cg = std::env::var_os("HOME")
                    .and_then(|_| {
                        let uid = unsafe { libc::getuid() };
                        let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
                        monitor_linux::cgroup::parse_self_cgroup(&text, uid)
                    })
                    .and_then(|rel| std::fs::read_to_string("/sys/fs/cgroup").ok().map(|_| rel));
                let cgroup_pressure = cg.map(|rel| {
                    let dir = std::path::PathBuf::from("/sys/fs/cgroup").join(rel.to_string_lossy().trim_start_matches('/'));
                    monitor_core::psi::read_cgroup(&dir)
                });
                Ok(json!({
                    "host": "local",
                    "pressure": snap.to_json(),
                    "cgroup_pressure": cgroup_pressure.map(|p| p.to_json()),
                }))
            }
            "scheduler_status" => {
                // cgroup 调度体检：逐步报告委派/控制器/可写性，失败给修复建议
                let checks = monitor_linux::cgroup::doctor();
                Ok(json!({
                    "host": "local",
                    "ok": checks.iter().all(|c| c.ok),
                    "checks": checks.iter().map(|c| json!({"name": c.name, "ok": c.ok, "detail": c.detail})).collect::<Vec<_>>(),
                }))
            }
            "scheduler_groups" => {
                let host = self.target(args)?;
                match &host {
                    None => {
                        let groups = monitor_linux::cgroup::list_groups_readonly().map_err(|e| e.to_string())?;
                        Ok(json!({"host": "local", "groups": groups_json(&groups)}))
                    }
                    Some(h) => {
                        let base = remote::cg_base_readonly(h).ok_or_else(|| "该主机没有用户 cgroup 委派根".to_string())?;
                        let groups = remote::cg_list(h, &base);
                        Ok(json!({"host": h.as_str(), "base": base, "groups": groups_json(&groups)}))
                    }
                }
            }
            "scheduler_set_limit" => {
                let host = self.target(args)?;
                let group = args.get("group").and_then(|v| v.as_str()).ok_or("缺少 group")?.to_string();
                if !monitor_linux::cgroup::valid_group_name(&group) {
                    return Err("group 名称非法".to_string());
                }
                let pct = args.get("cpu_max_pct").and_then(|v| v.as_u64()).map(|v| v as u32);
                let weight = args.get("cpu_weight").and_then(|v| v.as_u64()).map(|v| v as u32);
                let pids = match args.get("pids_max") {
                    Some(Value::Null) => Some(None),
                    Some(v) => Some(Some(v.as_u64().ok_or("pids_max 需为数字")? as u32)),
                    None => None,
                };
                if pct.is_none() && weight.is_none() && pids.is_none() {
                    return Err("至少提供 cpu_max_pct / cpu_weight / pids_max 之一".to_string());
                }
                match &host {
                    None => {
                        let mgr = monitor_linux::cgroup::CgroupManager::detect().map_err(|e| e.to_string())?;
                        if let Some(p) = pct {
                            mgr.set_cpu_max(&group, Some(p)).map_err(|e| e.to_string())?;
                        }
                        if let Some(w) = weight {
                            mgr.set_cpu_weight(&group, w).map_err(|e| e.to_string())?;
                        }
                        if let Some(m) = pids {
                            mgr.set_pids_max(&group, m).map_err(|e| e.to_string())?;
                        }
                    }
                    Some(h) => {
                        let base = remote::cg_base(h).ok_or_else(|| "该主机没有可写的用户 cgroup 委派根".to_string())?;
                        if let Some(p) = pct {
                            self.dispatcher
                                .run(&Command::CgSetRemote {
                                    target: h.as_str().to_string(),
                                    base: base.clone(),
                                    group: group.clone(),
                                    pct: Some(p),
                                })
                                .map_err(|e| e.to_string())?;
                        }
                        if let Some(w) = weight
                            && !remote::cg_set_weight(h, &base, &group, w)
                        {
                            return Err("设置 cpu.weight 失败".to_string());
                        }
                        if let Some(m) = pids
                            && !remote::cg_set_pids(h, &base, &group, m)
                        {
                            return Err("设置 pids.max 失败".to_string());
                        }
                    }
                }
                Ok(json!({
                    "host": host.as_ref().map(|t| t.as_str()).unwrap_or("local"),
                    "group": group, "cpu_max_pct": pct, "cpu_weight": weight,
                    "pids_max": pids.flatten(),
                }))
            }
            "scheduler_group_action" => {
                let host = self.target(args)?;
                let action = args.get("action").and_then(|v| v.as_str()).ok_or("缺少 action（create/delete）")?;
                let name = args.get("name").and_then(|v| v.as_str()).ok_or("缺少 name")?.to_string();
                if !monitor_linux::cgroup::valid_group_name(&name) {
                    return Err("分组名非法".to_string());
                }
                let cg_action = match action {
                    "create" => CgAction::Create,
                    "delete" => CgAction::Delete,
                    other => return Err(format!("未知 action：{other}")),
                };
                match &host {
                    None => {
                        self.dispatcher
                            .run(&Command::CgGroupLocal { action: cg_action, name: name.clone() })
                            .map_err(|e| e.to_string())?;
                    }
                    Some(h) => {
                        let base = remote::cg_base(h).ok_or_else(|| "该主机没有可写的用户 cgroup 委派根".to_string())?;
                        self.dispatcher
                            .run(&Command::CgGroupRemote {
                                action: cg_action,
                                target: h.as_str().to_string(),
                                base,
                                name: name.clone(),
                            })
                            .map_err(|e| e.to_string())?;
                    }
                }
                Ok(json!({"host": host.as_ref().map(|t| t.as_str()).unwrap_or("local"), "action": action, "name": name}))
            }
            "network_connections" => {
                let host = self.target(args)?;
                let v = self.view(&host, true, false)?;
                let proto = args.get("proto").and_then(|x| x.as_str()).map(|s| s.to_uppercase());
                let state = args.get("state").and_then(|x| x.as_str()).map(|s| s.to_uppercase());
                let limit = args.get("limit").and_then(|x| x.as_u64()).unwrap_or(50).clamp(1, 1000) as usize;
                let mut rows: Vec<&NetConn> = v
                    .conns
                    .iter()
                    .filter(|c| proto.as_deref().is_none_or(|p| c.proto == p))
                    .filter(|c| state.as_deref().is_none_or(|s| c.state == s))
                    .collect();
                let total = rows.len();
                let listen = v.conns.iter().filter(|c| c.state == "LISTEN").count();
                let estab = v.conns.iter().filter(|c| c.state == "ESTABLISHED").count();
                rows.truncate(limit);
                Ok(json!({
                    "host": v.label, "total": total, "listening": listen, "established": estab,
                    "connections": rows.iter().map(|c| json!({
                        "proto": c.proto, "local": c.local, "remote": c.remote, "state": c.state, "uid": c.uid,
                    })).collect::<Vec<_>>(),
                    "freshness": freshness_json(&v),
                }))
            }
            "filesystems" => {
                let host = self.target(args)?;
                let v = self.view(&host, true, false)?;
                Ok(json!({
                    "host": v.label,
                    "filesystems": v.filesystems.iter().map(|f| json!({
                        "source": f.source, "mount": f.mount, "total_kb": f.total_kb, "avail_kb": f.avail_kb,
                        "used_kb": f.used_kb(), "used_percent": round1(f.used_frac() * 100.0),
                    })).collect::<Vec<_>>(),
                    "freshness": freshness_json(&v),
                }))
            }
            "probe_status" => {
                let host = self.target(args)?;
                let snap = self.probe_snapshot(&host)?;
                let scope = if host.is_some() { "远端" } else { "本机" };
                Ok(json!({
                    "scope": scope,
                    "host": host.as_ref().map(|h| h.as_str()).unwrap_or("local"),
                    "helper_ready": snap.helper_ready,
                    "kernel_release": snap.kernel_release,
                    "functions": snap.functions.len(),
                    "syscalls": snap.syscalls.len(),
                    "uprobe_targets": snap.uprobes.len(),
                    "sample_uprobes": snap.uprobes.iter().take(10).map(|u| json!({
                        "path": u.path.display().to_string(), "procs": u.procs, "sample_pid": u.sample_pid,
                    })).collect::<Vec<_>>(),
                    "caps": {
                        "euid": snap.caps.euid,
                        "bpf_syscall": snap.caps.bpf_syscall,
                        "bpf_jit": snap.caps.bpf_jit,
                        "kprobe_events": snap.caps.kprobe_events,
                        "uprobe_events": snap.caps.uprobe_events,
                        "btf_file": snap.caps.btf_file,
                        "unprivileged_bpf_disabled": snap.caps.unprivileged_bpf_disabled,
                        "cap_bpf": snap.caps.cap_bpf,
                        "cap_perfmon": snap.caps.cap_perfmon,
                        "tracefs_readable": snap.caps.tracefs_readable,
                        "kprobe_events_writable": snap.caps.kprobe_events_writable,
                        "done": snap.caps.tools.iter().map(|(n, ok)| json!({"tool": n, "available": ok})).collect::<Vec<_>>(),
                    },
                    "errors": snap.errors,
                    "sweep_ms": snap.sweep_ms,
                }))
            }
            "probe_search" => {
                let host = self.target(args)?;
                let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("both");
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).clamp(1, 500) as usize;
                let snap = self.probe_snapshot(&host)?;
                let mut out: Vec<Value> = Vec::new();
                if kind != "syscall" {
                    for s in snap.functions.iter().filter(|s| s.name.to_lowercase().contains(&q)) {
                        out.push(json!({"kind": "function", "name": s.name}));
                        if out.len() >= limit {
                            break;
                        }
                    }
                }
                if out.len() < limit && kind != "function" {
                    for s in snap.syscalls.iter().filter(|s| s.name.to_lowercase().contains(&q)) {
                        out.push(json!({"kind": "syscall", "name": s.name}));
                        if out.len() >= limit {
                            break;
                        }
                    }
                }
                Ok(json!({
                    "host": host.as_ref().map(|h| h.as_str()).unwrap_or("local"),
                    "query": q, "count": out.len(), "results": out,
                }))
            }
            "probe_attach" => {
                let host = self.target(args)?;
                let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("kprobe");
                let symbol = args.get("symbol").and_then(|v| v.as_str()).ok_or("缺少 symbol")?;
                let target = args.get("target").and_then(|v| v.as_str()).map(std::path::PathBuf::from);
                let stack = args.get("stack").and_then(|v| v.as_bool()).unwrap_or(false);
                let pid = args.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);
                let extra = args.get("args").and_then(|v| v.as_str()).unwrap_or("");
                let attach = monitor_linux::probeclient::Attach {
                    kind,
                    target: target.as_deref(),
                    symbol,
                    stack,
                    pid,
                    args: extra,
                };
                if let Some(prev) = self.probe_active.clone()
                    && prev != host
                {
                    let mut prev_send = |cmd: &str| crate::probe_source::exchange(prev.as_ref(), cmd);
                    let _ = monitor_linux::probeclient::detach_via(&mut prev_send);
                }
                self.probe_active = None;
                let mut send = |cmd: &str| crate::probe_source::exchange(host.as_ref(), cmd);
                monitor_linux::probeclient::attach_via(&mut send, &attach)?;
                self.probe_active = Some(host.clone());
                Ok(json!({
                    "attached": true, "kind": kind, "symbol": symbol, "stack": stack, "pid": pid,
                    "host": host.as_ref().map(|h| h.as_str()).unwrap_or("local"),
                }))
            }
            "probe_poll" => {
                let host = self.probe_host_arg(args)?;
                let mut send = |cmd: &str| crate::probe_source::exchange(host.as_ref(), cmd);
                let stats = monitor_linux::probeclient::poll_via(&mut send)?;
                Ok(json!({
                    "host": host.as_ref().map(|h| h.as_str()).unwrap_or("local"),
                    "total": stats.total,
                    "calls": stats.calls.iter().map(|c| json!({
                        "comm": c.comm, "pid": c.pid, "entry": c.entry, "ret": c.ret, "stack": c.stack,
                    })).collect::<Vec<_>>(),
                }))
            }
            "probe_detach" => {
                let host = self.probe_host_arg(args)?;
                let mut send = |cmd: &str| crate::probe_source::exchange(host.as_ref(), cmd);
                monitor_linux::probeclient::detach_via(&mut send)?;
                self.probe_active = None;
                Ok(json!({
                    "detached": true,
                    "host": host.as_ref().map(|h| h.as_str()).unwrap_or("local"),
                }))
            }
            other => Err(format!("未知工具：{other}")),
        }
    }
}

/// 方案命令 JSON → Command（dispatcher 执行）。
fn command_from_json(v: &Value) -> Result<crate::service::Command, String> {
    use crate::service::Command as C;
    let kind = v.get("kind").and_then(|k| k.as_str()).ok_or("command 缺少 kind")?;
    match kind {
        "cg_set" => {
            let group = v.get("group").and_then(|g| g.as_str()).ok_or("cg_set 缺少 group")?;
            let pct = v.get("pct").and_then(|p| p.as_u64()).map(|p| p as u32);
            Ok(C::CgSetLocal { group: group.to_string(), pct })
        }
        "signal" => {
            let pid = v.get("pid").and_then(|p| p.as_i64()).ok_or("signal 缺少 pid")? as i32;
            let sig = v.get("sig").and_then(|s| s.as_i64()).ok_or("signal 缺少 sig")? as i32;
            Ok(C::SignalLocal { pid, sig })
        }
        "nice" => {
            let pid = v.get("pid").and_then(|p| p.as_i64()).ok_or("nice 缺少 pid")? as i32;
            let nice = v.get("nice").and_then(|n| n.as_i64()).ok_or("nice 缺少 nice")? as i32;
            Ok(C::NiceLocal { pid, nice })
        }
        other => Err(format!("未知命令 kind：{other}")),
    }
}

/// 由命令内容推导风险(与 dispatcher/分级表同源)。
fn derive_risk(v: &Value) -> Result<monitor_core::mcppolicy::RiskLevel, String> {
    Ok(command_from_json(v)?.risk())
}

fn local_os() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_string())
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

fn round1(v: f32) -> f64 {
    (f64::from(v) * 10.0).round() / 10.0
}

fn round2(v: f32) -> f64 {
    (f64::from(v) * 100.0).round() / 100.0
}

fn view_from_sample(s: remote::RemoteSample, label: String, age_secs: u64, stale: bool, last_error: Option<String>) -> View {
    View {
        usage: s.usage,
        pi: s.pi,
        filesystems: s.filesystems,
        conns: s.conns,
        label,
        age_secs,
        stale,
        last_error,
    }
}

fn freshness_json(v: &View) -> Value {
    json!({
        "sampled_age_secs": v.age_secs,
        "stale": v.stale,
        "last_error": v.last_error,
    })
}

fn system_oom_kill() -> Option<u64> {
    std::fs::read_to_string("/proc/vmstat").ok().and_then(|t| procstats::parse_vmstat_oom_kill(&t))
}

fn overview_json(v: &View) -> Value {
    let mem = v.usage.mem.map(|m| {
        json!({
            "total_kb": m.total_kb, "available_kb": m.available_kb, "used_kb": m.used_kb(),
            "used_percent": round1(if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 }),
            "swap_total_kb": m.swap_total_kb, "swap_used_kb": m.swap_used_kb(),
        })
    });
    let cores: Vec<f64> = v.usage.core_percent.iter().map(|c| round1(*c)).collect();
    json!({
        "host": v.label,
        "os": v.pi.remote.as_ref().map(|r| r.os.clone()).unwrap_or_else(local_os),
        "cpu": {
            "total_percent": round1(v.usage.total_percent),
            "cores": cores,
            "count": cores.len(),
        },
        "memory": mem,
        "temperature_c": v.pi.temp_c.map(round1),
        "cpu_freq_ghz": v.pi.freq_ghz.map(round2),
        "power_w": v.pi.power.map(|p| round2(p.core_w)),
        "gpu": {
            "model": v.pi.gpu.model,
            "temp_c": v.pi.gpu.temp_c.map(round1),
            "v3d_ghz": v.pi.gpu.v3d_ghz.map(round2),
        },
        "throttle": v.pi.throttle.map(|t| json!({
            "undervoltage": t.undervoltage, "freq_capped": t.freq_capped,
            "throttled": t.throttled, "soft_temp_limit": t.soft_temp_limit, "occurred": t.occurred,
        })),
        "load": v.usage.load.map(|l| json!({"1m": round2(l.one), "5m": round2(l.five), "15m": round2(l.fifteen)})),
        "uptime_secs": v.usage.uptime_secs,
        "disk_read_bps": v.usage.disk_read_bps.round(),
        "disk_write_bps": v.usage.disk_write_bps.round(),
        "net_rx_bps": v.usage.net_rx_bps.round(),
        "net_tx_bps": v.usage.net_tx_bps.round(),
        "process_count": v.usage.procs.len(),
        "filesystems": v.filesystems.len(),
        "connections": v.conns.len(),
        "freshness": freshness_json(v),
        "oom_kill_total": system_oom_kill(),
    })
}

fn groups_json(groups: &[monitor_linux::cgroup::GroupState]) -> Vec<Value> {
    groups
        .iter()
        .map(|g| {
            let throttle = g.throttle.map(|(periods, throttled, usec)| {
                let ratio = if periods == 0 { 0.0 } else { throttled as f64 / periods as f64 };
                json!({"nr_periods": periods, "nr_throttled": throttled, "throttled_usec": usec, "throttled_ratio": (ratio * 1000.0).round() / 1000.0})
            });
            json!({
                "name": g.name, "cpu_max_percent": g.cpu_max_pct, "cpu_weight": g.cpu_weight,
                "pids_max": g.pids_max, "process_count": g.procs,
                "cpu_throttle": throttle,
            })
        })
        .collect()
}

fn signal_number(name: &str) -> Result<i32, String> {
    Ok(match name {
        "HUP" => 1,
        "INT" => 2,
        "TERM" => 15,
        "KILL" => 9,
        "STOP" => 19,
        "CONT" => 18,
        "USR1" => 10,
        "USR2" => 12,
        other => return Err(format!("不支持的信号：{other}")),
    })
}

fn local_signal(name: &str) -> Result<nix::sys::signal::Signal, String> {
    use nix::sys::signal::Signal;
    Ok(match name {
        "HUP" => Signal::SIGHUP,
        "INT" => Signal::SIGINT,
        "TERM" => Signal::SIGTERM,
        "KILL" => Signal::SIGKILL,
        "STOP" => Signal::SIGSTOP,
        "CONT" => Signal::SIGCONT,
        "USR1" => Signal::SIGUSR1,
        "USR2" => Signal::SIGUSR2,
        other => return Err(format!("不支持的信号：{other}")),
    })
}

fn tools() -> Vec<Value> {
    vec![
        tool(
            "policy_status",
            "查看 MCP 策略：当前模式（readonly/confirm/trusted）、工具风险分级表、审批与审计说明。",
            json!({}),
            &[],
        ),
        tool(
            "hosts_list",
            "列出本地视角与 hosts.conf 中配置的 SSH 主机，以及当前选中的主机。",
            json!({}),
            &[],
        ),
        tool(
            "host_use",
            "切换后续工具调用的默认主机：\"local\" 或 \"user@host\"（需已配置 SSH 免密登录）。返回远端系统名与登录 uid。",
            json!({"host": {"type": "string", "description": "\"local\" 或 user@host"}}),
            &["host"],
        ),
        tool(
            "system_overview",
            "当前主机概览：CPU 总占用与每核、内存/Swap、温度、CPU 频率、功耗、GPU 型号与温度、负载、运行时长、磁盘/网络速率。",
            json!({"host": {"type": "string", "description": "临时指定主机（可选，默认当前主机）"}}),
            &[],
        ),
        tool(
            "system_load",
            "机器负载：1/5/15 分钟平均负载、运行时长、进程数、CPU 占用。",
            json!({"host": {"type": "string"}}),
            &[],
        ),
        tool(
            "process_list",
            "进程列表，可按 CPU / 内存 / RSS / PID 排序并过滤。",
            json!({
                "host": {"type": "string"},
                "sort": {"type": "string", "enum": ["cpu", "mem", "rss", "pid"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "filter": {"type": "string", "description": "匹配进程名 / 用户 / PID"},
            }),
            &[],
        ),
        tool(
            "process_signal",
            "向进程发送信号（TERM/KILL/STOP/CONT/HUP/INT/USR1/USR2），可选结束整棵进程树。远端主机经 SSH 执行。KILL 或 tree=true 为 L3：confirm 模式需 approval_token。",
            json!({
                "pid": {"type": "integer"},
                "signal": {"type": "string"},
                "tree": {"type": "boolean", "description": "true 时对进程树执行（仅 TERM/KILL 有意义）"},
                "host": {"type": "string"},
                "approval_token": {"type": "string", "description": "L3 一次性审批凭证（system-monitor mcp-approve 签发）"},
            }),
            &["pid"],
        ),
        tool(
            "process_nice",
            "调整进程 nice 值（-20..19；降低数值通常需要 root）。",
            json!({
                "pid": {"type": "integer"},
                "nice": {"type": "integer", "minimum": -20, "maximum": 19},
                "host": {"type": "string"},
            }),
            &["pid", "nice"],
        ),
        tool(
            "scheduler_groups",
            "只读列出 cgroup 调度分组（CPU 上限/权重、pids 上限、进程数），不会创建调度容器。远端主机要求存在用户委派 cgroup。",
            json!({"host": {"type": "string"}}),
            &[],
        ),
        tool(
            "scheduler_status",
            "本机 cgroup 调度体检：cgroup v2 / 委派 / 控制器 / 可写性逐项报告，失败附原因与修复建议。",
            json!({}),
            &[],
        ),
        tool(
            "process_details",
            "本地进程详情：uid/gid/线程数/内存、I/O 字节(read/write 与 rchar/wchar)、FD 数量与上限、OOM 评分。",
            json!({"pid": {"type": "integer"}}),
            &["pid"],
        ),
        tool(
            "ebpf_doctor",
            "eBPF 实验能力矩阵:内核版本/BTF/bpf(2)/perf/tracefs 逐项检查,不满足时列出原因;附三个首批场景的实验定义与资源上限。",
            json!({}),
            &[],
        ),
        tool(
            "diag_start",
            "开始一次诊断会话:后续证据/方案/审批/执行/验证都引用返回的 session id。会话持久化到 ~/.local/share/system-monitor/diag，重启后可继续。",
            json!({}),
            &[],
        ),
        tool(
            "diag_add_evidence",
            "向会话追加证据(事实/推断/置信度)。",
            json!({
                "session": {"type": "string"},
                "source": {"type": "string"},
                "fact": {"type": "string"},
                "hypothesis": {"type": "string"},
                "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            }),
            &["session", "fact"],
        ),
        tool(
            "diag_submit_plan",
            "提交动作方案(需先有至少一条证据):命令 JSON(kind=cg_set|signal|nice,经统一 dispatcher 执行)、回滚步骤、预期验证指标。返回 plan_hash 与 warnings。",
            json!({
                "session": {"type": "string"},
                "description": {"type": "string"},
                "command": {"type": "object"},
                "rollback": {"type": "string"},
                "verify_metric": {"type": "string"},
            }),
            &["session", "description", "command"],
        ),
        tool(
            "diag_approve",
            "审批方案;L3(KILL/树/删除)需 approval_token(mcp-approve --tool diag_execute)。计划变更后旧审批失效。",
            json!({
                "session": {"type": "string"},
                "plan_hash": {"type": "string"},
                "approval_token": {"type": "string"},
            }),
            &["session", "plan_hash"],
        ),
        tool(
            "diag_execute",
            "执行已审批的方案(经统一 dispatcher:策略+审计)。执行后进入 verifying。",
            json!({"session": {"type": "string"}, "plan_hash": {"type": "string"}}),
            &["session", "plan_hash"],
        ),
        tool(
            "diag_verify",
            "复采验证并归档会话(返回完整报告与 report_path，可回放/导出)。",
            json!({"session": {"type": "string"}, "note": {"type": "string"}}),
            &["session"],
        ),
        tool(
            "diag_status",
            "查看会话状态/报告(含证据链与审计要素)，返回 next_action 指示下一步工具；省略 session 时列出最近会话摘要（limit 默认 20，最大 64）。",
            json!({"session": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 64}}),
            &[],
        ),
        tool(
            "diag_abort",
            "中止诊断会话（不再推进状态机）；已归档会话不可中止。",
            json!({"session": {"type": "string"}}),
            &["session"],
        ),
        tool(
            "psi_status",
            "本机 PSI 压力失速指标：cpu/memory/io 的 some/full(avg10/60/300 与 total)。内核未启用 PSI 时标记 unsupported,不伪造 0。",
            json!({}),
            &[],
        ),
        tool(
            "host_capabilities",
            "主机真实能力报告：cgroup v2/委派/控制器、PSI、BTF、tracefs、systemd、thermal、cpufreq、RAPL、探针工具。host 可选（默认本机，远端经 SSH 一次性采集）。",
            json!({"host": {"type": "string"}}),
            &[],
        ),
        tool(
            "scheduler_set_limit",
            "设置 cgroup 分组限额：cpu_max_pct（每核百分比，如 50）、cpu_weight（1-10000）、pids_max（null 表示不限）。",
            json!({
                "group": {"type": "string"},
                "cpu_max_pct": {"type": "integer", "minimum": 1, "maximum": 10000},
                "cpu_weight": {"type": "integer", "minimum": 1, "maximum": 10000},
                "pids_max": {"type": ["integer", "null"]},
                "host": {"type": "string"},
            }),
            &["group"],
        ),
        tool(
            "scheduler_group_action",
            "创建或删除 cgroup 调度分组。delete 为 L3：confirm 模式需 approval_token。",
            json!({
                "action": {"type": "string", "enum": ["create", "delete"]},
                "name": {"type": "string"},
                "host": {"type": "string"},
                "approval_token": {"type": "string", "description": "L3 一次性审批凭证（system-monitor mcp-approve 签发）"},
            }),
            &["action", "name"],
        ),
        tool(
            "network_connections",
            "网络连接列表（TCP/TCP6/UDP/UDP6），可按协议、状态过滤，附带监听/已连接计数。",
            json!({
                "proto": {"type": "string", "enum": ["TCP", "TCP6", "UDP", "UDP6"]},
                "state": {"type": "string", "description": "如 LISTEN / ESTABLISHED"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                "host": {"type": "string"},
            }),
            &[],
        ),
        tool(
            "filesystems",
            "文件系统用量（来源、挂载点、总量/可用/已用、使用率）。",
            json!({"host": {"type": "string"}}),
            &[],
        ),
        tool(
            "probe_status",
            "探针能力（本机或 host 指定的远端）：内核版本、kallsyms 函数/系统调用数量、可探测用户态目标、tracefs/BPF 权限、helper 就绪状态。",
            json!({"host": {"type": "string"}}),
            &[],
        ),
        tool(
            "probe_search",
            "在 kallsyms 中搜索函数或系统调用名（支持远端 host）。",
            json!({
                "query": {"type": "string"},
                "kind": {"type": "string", "enum": ["function", "syscall", "both"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "host": {"type": "string"},
            }),
            &["query"],
        ),
        tool(
            "probe_attach",
            "挂载 kprobe / syscall / uprobe（本机或 host 指定的远端，需目标机已安装 root probe-helper 服务）。可指定 stack、pid、args 过滤。",
            json!({
                "kind": {"type": "string", "enum": ["kprobe", "syscall", "uprobe"]},
                "symbol": {"type": "string"},
                "target": {"type": "string", "description": "uprobe 的可执行文件路径"},
                "stack": {"type": "boolean"},
                "pid": {"type": "integer"},
                "args": {"type": "string", "description": "tracefs fetchargs（arm64: arg0=%x0；x86_64: arg0=%di）"},
                "host": {"type": "string"},
            }),
            &["symbol"],
        ),
        tool("probe_poll", "读取探针累计命中与最近调用记录（默认沿用活动探针主机）。", json!({"host": {"type": "string"}}), &[]),
        tool("probe_detach", "卸载当前探针（默认沿用活动探针主机）。", json!({"host": {"type": "string"}}), &[]),
    ]
}

/// 工具声明：注解（readOnlyHint/destructiveHint）由服务端分级表派生，
/// 与 mcppolicy::risk_of 保持同源，不会出现注解放行、服务端拒绝的劈叉。
fn tool(name: &str, desc: &str, props: Value, required: &[&str]) -> Value {
    // 注解只是给客户端的提示，服务端策略仍以 mcppolicy 为准。
    const READ_ONLY_TOOLS: &[&str] = &[
        "hosts_list", "system_overview", "system_load", "process_list", "process_details",
        "host_capabilities", "network_connections", "filesystems", "scheduler_groups",
        "scheduler_status", "psi_status", "ebpf_doctor", "probe_status", "probe_search",
        "probe_poll", "policy_status",
    ];
    let read_only = READ_ONLY_TOOLS.contains(&name);
    // 这两个工具是否破坏性取决于参数（KILL/tree/delete），按保守方向提示
    let destructive = matches!(name, "process_signal" | "scheduler_group_action");
    json!({
        "name": name,
        "description": desc,
        "inputSchema": {
            "type": "object",
            "properties": props,
            "required": required,
        },
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": read_only,
            "openWorldHint": false,
        },
    })
}

/// 预置工作流（MCP prompts）：把「该怎么用这些工具」直接交给 AI 客户端。
fn prompts() -> Vec<Value> {
    vec![
        json!({
            "name": "diagnose_high_cpu",
            "title": "高 CPU 定位与可回滚处置",
            "description": "证据 → 方案 → 审批 → 执行 → 验证的闭环，默认不 KILL。",
            "arguments": [{"name": "host", "description": "目标主机（local 或 user@host）", "required": false}],
        }),
        json!({
            "name": "diagnose_memory_pressure",
            "title": "内存压力排查",
            "description": "结合 PSI、进程 RSS 与 OOM 计数判断内存压力来源，避免直接杀进程。",
            "arguments": [{"name": "host", "description": "目标主机（local 或 user@host）", "required": false}],
        }),
        json!({
            "name": "host_health_check",
            "title": "主机只读体检",
            "description": "按固定顺序采集能力、负载、压力、磁盘、网络与调度状态，输出异常与建议。",
            "arguments": [{"name": "host", "description": "目标主机（local 或 user@host）", "required": false}],
        }),
    ]
}

fn prompt_messages(name: &str, args: &Value) -> Option<Value> {
    let host = args
        .get("host")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("当前主机");
    let (description, text) = match name {
        "diagnose_high_cpu" => (
            "高 CPU 定位与可回滚处置",
            format!(
                "在 {host} 上做一次高 CPU 诊断，严格按步骤：\n\
                 1. system_overview 与 system_load 记录总 CPU、每核、负载；psi_status 看 CPU 压力。\n\
                 2. process_list {{\"sort\":\"cpu\",\"limit\":10}} 找出持续占用最高的进程，确认 PID、命令名、用户；必要时 process_details 看线程与 FD。\n\
                 3. diag_start 开会话，用 diag_add_evidence 把读数写成证据（事实与推断分开，标注置信度）。\n\
                 4. 优先可回滚方案：scheduler_set_limit 限流分组或 process_nice；用 diag_submit_plan 提交，写清回滚步骤与验证指标。\n\
                 5. diag_approve → diag_execute → 复采后 diag_verify 归档。\n\
                 不要直接 KILL 或结束进程树；L3 必须由人在本机用 system-monitor mcp-approve 签发 approval_token。"
            ),
        ),
        "diagnose_memory_pressure" => (
            "内存压力排查",
            format!(
                "在 {host} 上排查内存压力：\n\
                 1. system_overview 看内存/Swap 与 OOM 计数；psi_status 看 memory some/full。\n\
                 2. process_list {{\"sort\":\"mem\",\"limit\":15}} 与 sort=rss 找大户；对重点进程用 process_details 看 RSS、线程与 FD。\n\
                 3. filesystems 排除磁盘写满造成的假象；host_capabilities 确认 mem cgroup 是否可用，不可用时不要提案内存限额。\n\
                 4. 把证据写入 diag_start 会话；处置优先 process_nice 或调度分组限流，提交方案时写明回滚与验证指标。\n\
                 不要直接杀进程；需要时才走 L3 并由人签发审批凭证。"
            ),
        ),
        "host_health_check" => (
            "主机只读体检",
            format!(
                "对 {host} 做一次只读体检，不做任何写操作：\n\
                 1. host_capabilities 确认采集能力边界。\n\
                 2. system_overview → system_load → psi_status 看资源与压力。\n\
                 3. filesystems → network_connections {{\"state\":\"LISTEN\"}} 看磁盘与监听端口。\n\
                 4. scheduler_status 看 cgroup 委派与可写性；本机再看 probe_status。\n\
                 汇总异常项、可能原因与下一步建议；需要处置时再走诊断会话。"
            ),
        ),
        _ => return None,
    };
    Some(json!({
        "description": description,
        "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
    }))
}

fn handle(server: &mut Server, msg: &Value) -> Option<Value> {
    let method = msg.get("method")?.as_str()?;
    let id = msg.get("id").cloned();
    // 通知（无 id）不回包，例如 notifications/initialized
    id.as_ref()?;
    let response = match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}, "prompts": {}},
            "serverInfo": {"name": "system-monitor", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "系统监视器 MCP（本地 / SSH 远端），默认只读。\
看现状：system_overview → system_load / psi_status → process_list（高占用）→ process_details（单进程细节）。\
所有工具接受 host=local|user@host，省略时用 host_use 的默认主机；跨主机操作请显式传 host。\
要改系统状态：diag_start → diag_add_evidence → diag_submit_plan（写 rollback 与 verify_metric）→ diag_approve → diag_execute → diag_verify。\
readonly 模式拒绝 L2+；confirm 下 L3 需 approval_token；写操作全部审计。\
probe_* 仅本机且需 root probe-helper。返回同时包含 text 与 structuredContent，错误为结构化 JSON。",
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "prompts/list" => Ok(json!({"prompts": prompts()})),
        "prompts/get" => {
            let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match prompt_messages(name, &args) {
                Some(v) => Ok(v),
                None => Err((-32602, format!("未知 prompt：{name}"))),
            }
        }
        "tools/call" => {
            let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match server.call(name, &args) {
                Ok(v) => {
                    let text = serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string());
                    Ok(json!({
                        "content": [{"type": "text", "text": text}],
                        "structuredContent": v,
                        "isError": false,
                    }))
                }
                Err(e) => {
                    // 统一错误 envelope：已是 JSON 的（策略拒绝/采集失败）原样透传，其余包装
                    let payload = serde_json::from_str::<Value>(&e)
                        .ok()
                        .filter(|v| v.is_object())
                        .unwrap_or_else(|| json!({"error": "tool_error", "tool": name, "message": e}));
                    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
                    Ok(json!({
                        "content": [{"type": "text", "text": text}],
                        "structuredContent": payload,
                        "isError": true,
                    }))
                }
            }
        }
        other => Err((-32601, format!("未知方法：{other}"))),
    };
    Some(match response {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
    })
}

pub fn run() -> std::io::Result<()> {
    let mut server = Server::new();
    let argv: Vec<String> = std::env::args().collect();
    let raw = argv
        .iter()
        .find_map(|a| a.strip_prefix("--mcp-policy=").map(String::from))
        .or_else(|| std::env::var("SM_MCP_POLICY").ok());
    if let Some(raw) = raw {
        match PolicyMode::parse(&raw) {
            Some(m) => {
                server.policy = m;
                server.dispatcher = CommandDispatcher::new(m, "mcp");
            }
            None => {
                eprintln!("system-monitor mcp: 非法策略值 \"{raw}\"（可选 readonly / confirm / trusted），拒绝启动");
                std::process::exit(2);
            }
        }
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({"jsonrpc": "2.0", "id": Value::Null, "error": {"code": -32700, "message": format!("JSON 解析失败：{e}")}});
                let _ = serde_json::to_writer(&mut out, &resp);
                let _ = out.write_all(b"\n");
                let _ = out.flush();
                continue;
            }
        };
        if let Some(resp) = handle(&mut server, &msg) {
            let _ = serde_json::to_writer(&mut out, &resp);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(server: &mut Server, line: &str) -> Value {
        let msg: Value = serde_json::from_str(line).unwrap();
        handle(server, &msg).unwrap()
    }

    #[test]
    fn initialize_and_list_tools() {
        let mut s = Server::new();
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);
        assert_eq!(r["result"]["serverInfo"]["name"], "system-monitor");
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let tools = r["result"]["tools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t["name"] == "system_overview"));
        assert!(tools.iter().any(|t| t["name"] == "process_signal"));
        assert!(tools.iter().any(|t| t["name"] == "probe_attach"));
        assert!(tools.iter().any(|t| t["name"] == "host_use"));
    }

    #[test]
    fn notifications_and_unknown_methods() {
        let mut s = Server::new();
        let msg: Value = serde_json::from_str(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap();
        assert!(handle(&mut s, &msg).is_none());
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":3,"method":"nope"}"#);
        assert_eq!(r["error"]["code"], -32601);
    }

    #[test]
    fn tool_errors_are_reported() {
        let mut s = Server::new();
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"process_signal","arguments":{"pid":1,"signal":"KILL"}}}"#,
        );
        assert_eq!(r["result"]["isError"], true);
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}"#,
        );
        assert_eq!(r["result"]["isError"], true);
    }

    #[test]
    fn signal_number_mapping() {
        assert_eq!(signal_number("TERM").unwrap(), 15);
        assert_eq!(signal_number("kill").unwrap_err(), "不支持的信号：kill");
        assert_eq!(signal_number("KILL").unwrap(), 9);
    }

    #[test]
    fn default_policy_is_readonly_and_blocks_writes() {
        // 默认启动的 MCP 无法执行任何写操作：结构化拒绝 + 不触碰系统
        let mut s = Server::new();
        assert_eq!(s.policy, PolicyMode::Readonly, "默认必须是只读策略");
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"process_signal","arguments":{"pid":999999,"signal":"TERM"}}}"#,
        );
        assert_eq!(r["result"]["isError"], true);
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).expect("拒绝信息应为结构化 JSON");
        assert_eq!(v["error"], "policy_denied");
        assert_eq!(v["required_level"], "L2");
        assert_eq!(v["current_mode"], "readonly");
        // L3 同样拒绝;且 KILL 连审批提示都给出（若 confirm 模式）
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"process_signal","arguments":{"pid":999999,"signal":"KILL"}}}"#,
        );
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["error"], "policy_denied");
        assert_eq!(v["required_level"], "L3");
        // 只读工具不受影响
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"system_load","arguments":{}}}"#,
        );
        assert_eq!(r["result"]["isError"], false);
    }

    #[test]
    fn trusted_mode_allows_and_unknown_policy_fails_closed() {
        let mut s = Server::new();
        s.policy = PolicyMode::Trusted;
        // trusted 下对不存在 PID 发信号：策略放行，执行层报 gone（而非 policy_denied）
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"process_signal","arguments":{"pid":999999,"signal":"TERM"}}}"#,
        );
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("policy_denied"), "trusted 应放行（执行层错误是另一回事）：{text}");
        // 未知工具按 L3 处理（fail closed）
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"rm_rf_everything","arguments":{}}}"#,
        );
        assert_eq!(r["result"]["isError"], true);
    }

    #[test]
    fn tools_carry_policy_annotations() {
        let mut s = Server::new();
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":15,"method":"tools/list"}"#);
        let tools = r["result"]["tools"].as_array().unwrap();
        let find = |n: &str| tools.iter().find(|t| t["name"] == n).unwrap().clone();
        assert_eq!(find("system_overview")["annotations"]["readOnlyHint"], true);
        assert_eq!(find("system_overview")["annotations"]["idempotentHint"], true);
        assert_eq!(find("process_nice")["annotations"]["readOnlyHint"], false);
        assert_eq!(find("process_signal")["annotations"]["destructiveHint"], true);
        assert_eq!(find("scheduler_group_action")["annotations"]["destructiveHint"], true);
        assert_eq!(find("scheduler_groups")["annotations"]["readOnlyHint"], true);
        assert!(find("policy_status")["name"] == "policy_status");
    }

    #[test]
    fn catalog_covers_every_advertised_tool() {
        let listed = tools();
        let mut advertised: Vec<&str> = listed.iter().map(|t| t["name"].as_str().unwrap()).collect();
        advertised.sort_unstable();
        let mut catalog: Vec<&str> = mcppolicy::catalog().iter().map(|(n, _)| *n).collect();
        catalog.sort_unstable();
        assert_eq!(advertised, catalog, "policy_status 目录必须覆盖 tools/list，反之亦然");
    }

    #[test]
    fn docs_list_every_advertised_tool() {
        let readme = include_str!("../../../README.md");
        let skill = include_str!("../../../skills/system-monitor/SKILL.md");
        for (name, _) in mcppolicy::catalog() {
            assert!(readme.contains(name), "README.md 缺少工具 {name}");
            assert!(skill.contains(name), "SKILL.md 缺少工具 {name}");
        }
    }

    #[test]
    fn tools_call_returns_structured_content_and_error_envelope() {
        let mut s = Server::new();
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"system_load","arguments":{}}}"#,
        );
        assert_eq!(r["result"]["isError"], false);
        assert_eq!(r["result"]["structuredContent"]["host"], "本地");
        // 参数错误也要有结构化 envelope，而不是裸字符串
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"process_details","arguments":{}}}"#,
        );
        assert_eq!(r["result"]["isError"], true);
        let v = &r["result"]["structuredContent"];
        assert_eq!(v["error"], "tool_error");
        assert_eq!(v["tool"], "process_details");
        assert!(v["message"].as_str().unwrap().contains("pid"));
    }

    #[test]
    fn prompts_expose_workflows() {
        let mut s = Server::new();
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":22,"method":"prompts/list"}"#);
        let list = r["result"]["prompts"].as_array().unwrap();
        assert!(list.iter().any(|p| p["name"] == "diagnose_high_cpu"));
        assert!(list.iter().any(|p| p["name"] == "host_health_check"));

        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":23,"method":"prompts/get","params":{"name":"diagnose_high_cpu","arguments":{"host":"user@box"}}}"#,
        );
        let text = r["result"]["messages"][0]["content"]["text"].as_str().unwrap();
        assert!(text.contains("user@box"));
        assert!(text.contains("diag_start"));
        assert!(text.contains("不要直接 KILL"));

        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":24,"method":"prompts/get","params":{"name":"nope"}}"#,
        );
        assert_eq!(r["error"]["code"], -32602);
    }

    #[test]
    fn diag_session_end_to_end_demo() {
        // 「高 CPU」端到端:证据→方案→审批→执行→验证(MVP 演示,无真实执行)
        let mut s = Server::new();
        s.policy = PolicyMode::Trusted; // 演示放行执行;readonly 下 diag_execute 会被策略拦
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"diag_start","arguments":{}}}"#);
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        let sid = v["session"].as_str().unwrap().to_string();
        assert_eq!(v["next_action"], "diag_add_evidence");

        for (fact, hyp) in [("cpu 95%", "ffmpeg 占满"), ("psi.cpu.some avg10=45", "真实争用")] {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"diag_add_evidence","arguments":{{"session":"{sid}","source":"proc","fact":"{fact}","hypothesis":"{hyp}"}}}}}}"#
            );
            let r = call(&mut s, &line);
            assert_eq!(r["result"]["isError"], false);
        }
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"diag_submit_plan","arguments":{{"session":"{sid}","description":"限流 media 分组","command":{{"kind":"cg_set","group":"media","pct":50}},"rollback":"恢复 max","verify_metric":"psi<20"}}}}}}"#
        );
        let r = call(&mut s, &line);
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        let hash = v["plan_hash"].as_str().unwrap().to_string();
        assert_eq!(v["next_action"], "diag_approve");
        assert_eq!(v["warnings"].as_array().unwrap().len(), 0);

        let line = format!(
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"diag_approve","arguments":{{"session":"{sid}","plan_hash":"{hash}"}}}}}}"#
        );
        let r = call(&mut s, &line);
        assert_eq!(r["result"]["isError"], false);

        let line = format!(
            r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"diag_execute","arguments":{{"session":"{sid}","plan_hash":"{hash}"}}}}}}"#
        );
        let r = call(&mut s, &line);
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        // cg_set 本机无 cgroup 环境会执行失败,但流程状态机必须推进到 verifying
        assert_eq!(v["phase"], "verifying", "{v}");
        assert_eq!(v["next_action"], "diag_verify");

        let line = format!(
            r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"diag_verify","arguments":{{"session":"{sid}","note":"psi 回落"}}}}}}"#
        );
        let r = call(&mut s, &line);
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["phase"], "done");
        assert_eq!(v["next_action"], "none");
        assert!(v["report"]["next_action"] == "none");
        assert!(v["report_path"].as_str().is_some(), "启用持久化的服务应给出报告路径");
        assert!(v["report"]["evidences"].as_array().unwrap().len() >= 2, "证据链可回放");
    }

    #[test]
    fn diag_execute_denied_in_readonly() {
        let mut s = Server::new(); // readonly
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"diag_start","arguments":{}}}"#);
        let sid: String = {
            let text = r["result"]["content"][0]["text"].as_str().unwrap();
            let v: Value = serde_json::from_str(text).unwrap();
            v["session"].as_str().unwrap().to_string()
        };
        // 方案必须建立在证据之上
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"diag_add_evidence","arguments":{{"session":"{sid}","source":"proc","fact":"pid 4242 cpu 30%"}}}}}}"#
        );
        let r = call(&mut s, &line);
        assert_eq!(r["result"]["isError"], false);
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"diag_submit_plan","arguments":{{"session":"{sid}","description":"x","command":{{"kind":"signal","pid":4242,"sig":15}}}}}}}}"#
        );
        let r = call(&mut s, &line);
        let hash: String = {
            let text = r["result"]["content"][0]["text"].as_str().unwrap();
            let v: Value = serde_json::from_str(text).unwrap();
            v["plan_hash"].as_str().unwrap().to_string()
        };
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"diag_approve","arguments":{{"session":"{sid}","plan_hash":"{hash}"}}}}}}"#
        );
        let r = call(&mut s, &line);
        assert_eq!(r["result"]["isError"], false);
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"diag_execute","arguments":{{"session":"{sid}","plan_hash":"{hash}"}}}}}}"#
        );
        let r = call(&mut s, &line);
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("策略拒绝"), "readonly 下 diag_execute 必须被策略拦截：{text}");
    }

    #[test]
    fn policy_status_reports_levels() {
        let mut s = Server::new();
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"policy_status","arguments":{}}}"#,
        );
        assert_eq!(r["result"]["isError"], false);
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["mode"], "readonly");
        assert!(v["levels"]["L0"].as_array().unwrap().iter().any(|x| x == "system_overview"));
        assert!(v["levels"]["L0"].as_array().unwrap().iter().any(|x| x == "host_capabilities"));
        assert!(v["levels"]["L1"].as_array().unwrap().iter().any(|x| x == "diag_abort"));
        assert!(v["levels"]["L3"].is_null(), "L3 由参数动态升级，不在基础目录里");
    }

    #[test]
    fn local_overview_smoke() {
        let mut s = Server::new();
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"system_overview","arguments":{}}}"#,
        );
        assert_eq!(r["result"]["isError"], false);
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["host"], "本地");
        assert!(v["cpu"]["count"].as_u64().unwrap() > 0);
    }
}
