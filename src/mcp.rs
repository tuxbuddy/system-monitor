//! MCP 服务（stdio，换行分隔的 JSON-RPC 2.0）。
//! 启动：`system-monitor mcp`
//!
//! 暴露能力：主机切换、概览/负载、进程列表与信号、cgroup 调度、
//! 网络连接、文件系统、探针（本机 tracefs/uprobe）。
//! 远端主机经 SSH 采集与操作，与 GUI/TUI 使用同一套数据层。

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::mcppolicy::{self, PolicyMode, RiskLevel};
use crate::pi::PiStats;
use crate::procstats::{self, FsUsage, NetConn, Sampler, Usage};
use crate::remote;

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

pub struct Server {
    current: Option<remote::SshTarget>,
    hosts: Vec<remote::SshTarget>,
    /// 每主机最近一次成功采样时刻与失败原因（新鲜度元数据）。
    remote_fresh: HashMap<String, (Option<Instant>, Option<String>)>,
    /// 服务端强制策略：默认 readonly，禁止隐式升级。
    policy: PolicyMode,
    caller: String,
    sampler: Sampler,
    last_local: Instant,
    remote_prev: HashMap<String, Option<remote::Counters>>,
    probe: Option<(crate::probe::Snapshot, Instant)>,
}

impl Server {
    fn new() -> Self {
        let mut s = Self {
            current: None,
            hosts: remote::load_hosts().0,
            policy: PolicyMode::Readonly,
            caller: std::env::var("SM_MCP_CALLER").unwrap_or_else(|_| "stdio".to_string()),
            remote_fresh: HashMap::new(),
            sampler: Sampler::new(),
            last_local: Instant::now() - Duration::from_secs(10),
            remote_prev: HashMap::new(),
            probe: None,
        };
        // 预热采样，让首次调用就能算出 CPU 百分比
        let _ = s.sampler.sample();
        s.last_local = Instant::now() - Duration::from_secs(10);
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

    fn view(&mut self, host: &Option<remote::SshTarget>) -> Result<View, String> {
        match host {
            None => {
                let mut usage = self.sampler.sample();
                if self.last_local.elapsed() > Duration::from_secs(3) {
                    // 间隔太久时补一次短间隔采样，返回「瞬时」而不是长时间平均
                    std::thread::sleep(Duration::from_millis(150));
                    usage = self.sampler.sample();
                }
                self.last_local = Instant::now();
                Ok(View {
                    usage,
                    pi: crate::pi::read_pi_stats(),
                    filesystems: procstats::read_filesystems(),
                    conns: procstats::read_net_conns(),
                    label: "本地".to_string(),
                    age_secs: 0,
                    stale: false,
                    last_error: None,
                })
            }
            Some(h) => {
                let key = h.as_str().to_string();
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
                        self.remote_fresh.insert(key.clone(), (Some(Instant::now()), None));
                        Ok(View {
                            usage: s.usage,
                            pi: s.pi,
                            filesystems: s.filesystems,
                            conns: s.conns,
                            label: h.as_str().to_string(),
                            age_secs: 0,
                            stale: false,
                            last_error: None,
                        })
                    }
                    Err(e) => {
                        // 失败：记录错误；若此前有成功样本，带 stale 标记返回旧数据
                        self.remote_fresh.insert(key.clone(), (None, Some(e.clone())));
                        let (last_at, _) = self.remote_fresh.get(&key).cloned().unwrap_or((None, None));
                        let age = last_at.map(|t| t.elapsed().as_secs()).unwrap_or(0);
                        // 无历史数据时向上报错;有历史时调用方可继续用 overview_json 的 stale 标记
                        Err(format!(
                            "{{\"error\":\"collect_failed\",\"host\":\"{key}\",\"message\":\"{e}\",\"stale\":true,\"last_ok_age_secs\":{age}}}"
                        ))
                    }
                }
            }
        }
    }

    fn probe_snapshot(&mut self) -> &crate::probe::Snapshot {
        let stale = self.probe.as_ref().is_none_or(|(_, at)| at.elapsed() > Duration::from_secs(60));
        if stale {
            self.probe = Some((crate::probe::Snapshot::load(), Instant::now()));
        }
        &self.probe.as_ref().expect("刚刚写入").0
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
            "policy_status" => Ok(json!({
                "mode": self.policy.as_str(),
                "caller": self.caller,
                "levels": {
                    "L0_read": ["hosts_list", "system_overview", "system_load", "process_list", "network_connections", "filesystems"],
                    "L1_diagnose": ["host_use", "probe_status", "probe_search", "probe_poll"],
                    "L2_recoverable": ["process_nice", "process_signal(非KILL且非tree)", "scheduler_set_limit", "scheduler_group_action(create)", "probe_attach", "probe_detach"],
                    "L3_destructive": ["process_signal(KILL或tree)", "scheduler_group_action(delete)"],
                },
                "approval": "L3 在 confirm 模式下需 approval_token（由 system-monitor mcp-approve 签发，一次性、绑定参数）",
                "audit": "~/.local/share/system-monitor/mcp-audit.jsonl",
            })),
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
                let sample = remote::collect(&target, &mut prev).ok_or_else(|| format!("无法连接主机：{h}"))?;
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
                let v = self.view(&host)?;
                Ok(overview_json(&v))
            }
            "system_load" => {
                let host = self.target(args)?;
                let v = self.view(&host)?;
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
                let v = self.view(&host)?;
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
                Ok(json!({"host": v.label, "total": total, "sort": sort, "processes": rows}))
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
                            let r = if num == 9 { crate::actions::kill_tree(pid) } else { crate::actions::terminate_tree(pid) };
                            (r.map(|n| n as u64).map_err(|e| e.to_string())?, 0)
                        } else {
                            let signal = local_signal(&sig)?;
                            crate::actions::send_signal(pid, signal).map_err(|e| e.to_string())?;
                            (1, 0)
                        }
                    }
                    Some(h) => {
                        if tree {
                            let v = self.view(&host)?;
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
                    None => crate::actions::set_nice(pid, nice).map_err(|e| e.to_string())?,
                    Some(h) => remote::set_nice(h, pid, nice)?,
                }
                Ok(json!({"host": host.as_ref().map(|t| t.as_str()).unwrap_or("local"), "pid": pid, "nice": nice}))
            }
            "host_capabilities" => {
                let host = args.get("host").and_then(|v| v.as_str());
                match host {
                    None | Some("local") | Some("") => {
                        let caps = crate::caps::detect_local();
                        let mut v = caps.to_json();
                        v["host"] = json!("local");
                        Ok(v)
                    }
                    Some(h) => {
                        let target = remote::SshTarget::parse(h).map_err(|e| format!("host 参数非法：{e}"))?;
                        let script = crate::caps::capabilities_script();
                        let out = remote::ssh_exec(&target, &script, &remote::ExecLimits::default(), None)
                            .map_err(|e| format!("远端能力采集失败：{e}"))?;
                        let mut v = crate::caps::parse_report(&out.stdout).to_json();
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
            "psi_status" => {
                let snap = crate::psi::read_local();
                // cgroup v2 委派根下的 *.pressure 作为补充源(本地 /proc/pressure 缺失时尤其有用)
                let cg = std::env::var_os("HOME")
                    .and_then(|_| {
                        let uid = unsafe { libc::getuid() };
                        let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
                        crate::cgroup::parse_self_cgroup(&text, uid)
                    })
                    .and_then(|rel| std::fs::read_to_string("/sys/fs/cgroup").ok().map(|_| rel));
                let cgroup_pressure = cg.map(|rel| {
                    let dir = std::path::PathBuf::from("/sys/fs/cgroup").join(rel.to_string_lossy().trim_start_matches('/'));
                    crate::psi::read_cgroup(&dir)
                });
                Ok(json!({
                    "host": "local",
                    "pressure": snap.to_json(),
                    "cgroup_pressure": cgroup_pressure.map(|p| p.to_json()),
                }))
            }
            "scheduler_status" => {
                // cgroup 调度体检：逐步报告委派/控制器/可写性，失败给修复建议
                let checks = crate::cgroup::doctor();
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
                        let mgr = crate::cgroup::CgroupManager::detect().map_err(|e| e.to_string())?;
                        let groups = mgr.list_groups().map_err(|e| e.to_string())?;
                        Ok(json!({"host": "local", "groups": groups_json(&groups)}))
                    }
                    Some(h) => {
                        let base = remote::cg_base(h).ok_or_else(|| "该主机没有可写的用户 cgroup 委派根".to_string())?;
                        let groups = remote::cg_list(h, &base);
                        Ok(json!({"host": h.as_str(), "base": base, "groups": groups_json(&groups)}))
                    }
                }
            }
            "scheduler_set_limit" => {
                let host = self.target(args)?;
                let group = args.get("group").and_then(|v| v.as_str()).ok_or("缺少 group")?.to_string();
                if !crate::cgroup::valid_group_name(&group) {
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
                        let mgr = crate::cgroup::CgroupManager::detect().map_err(|e| e.to_string())?;
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
                        if let Some(p) = pct
                            && !remote::cg_set_cpu_max(h, &base, &group, Some(p))
                        {
                            return Err("设置 cpu.max 失败（分组不存在或权限不足）".to_string());
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
                if !crate::cgroup::valid_group_name(&name) {
                    return Err("分组名非法".to_string());
                }
                match &host {
                    None => {
                        let mgr = crate::cgroup::CgroupManager::detect().map_err(|e| e.to_string())?;
                        match action {
                            "create" => mgr.create_group(&name).map_err(|e| e.to_string())?,
                            "delete" => mgr.delete_group(&name).map_err(|e| e.to_string())?,
                            other => return Err(format!("未知 action：{other}")),
                        }
                    }
                    Some(h) => {
                        let base = remote::cg_base(h).ok_or_else(|| "该主机没有可写的用户 cgroup 委派根".to_string())?;
                        match action {
                            "create" => {
                                if !remote::cg_create(h, &base, &name) {
                                    return Err("远端创建失败（名称冲突或权限不足）".to_string());
                                }
                                let ready = remote::cg_ensure(h, &base);
                                if !ready.ok {
                                    return Err(format!(
                                        "远端调度容器未就绪（码 {:?}）：{}",
                                        ready.error_code.unwrap_or(99),
                                        ready.detail
                                    ));
                                }
                            }
                            "delete" => {
                                if !remote::cg_delete(h, &base, &name) {
                                    return Err("远端删除失败（组内仍有进程或权限不足）".to_string());
                                }
                            }
                            other => return Err(format!("未知 action：{other}")),
                        }
                    }
                }
                Ok(json!({"host": host.as_ref().map(|t| t.as_str()).unwrap_or("local"), "action": action, "name": name}))
            }
            "network_connections" => {
                let host = self.target(args)?;
                let v = self.view(&host)?;
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
                }))
            }
            "filesystems" => {
                let host = self.target(args)?;
                let v = self.view(&host)?;
                Ok(json!({
                    "host": v.label,
                    "filesystems": v.filesystems.iter().map(|f| json!({
                        "source": f.source, "mount": f.mount, "total_kb": f.total_kb, "avail_kb": f.avail_kb,
                        "used_kb": f.used_kb(), "used_percent": round1(f.used_frac() * 100.0),
                    })).collect::<Vec<_>>(),
                }))
            }
            "probe_status" => {
                let snap = self.probe_snapshot();
                Ok(json!({
                    "scope": "本机",
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
                let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("both");
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).clamp(1, 500) as usize;
                let snap = self.probe_snapshot();
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
                Ok(json!({"query": q, "count": out.len(), "results": out}))
            }
            "probe_attach" => {
                let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("kprobe");
                let symbol = args.get("symbol").and_then(|v| v.as_str()).ok_or("缺少 symbol")?;
                let target = args.get("target").and_then(|v| v.as_str()).map(std::path::PathBuf::from);
                let stack = args.get("stack").and_then(|v| v.as_bool()).unwrap_or(false);
                let pid = args.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);
                let extra = args.get("args").and_then(|v| v.as_str()).unwrap_or("");
                let attach = crate::probeclient::Attach {
                    kind,
                    target: target.as_deref(),
                    symbol,
                    stack,
                    pid,
                    args: extra,
                };
                crate::probeclient::attach(&attach)?;
                Ok(json!({"attached": true, "kind": kind, "symbol": symbol, "stack": stack, "pid": pid}))
            }
            "probe_poll" => {
                let stats = crate::probeclient::poll()?;
                Ok(json!({
                    "total": stats.total,
                    "calls": stats.calls.iter().map(|c| json!({
                        "comm": c.comm, "pid": c.pid, "entry": c.entry, "ret": c.ret, "stack": c.stack,
                    })).collect::<Vec<_>>(),
                }))
            }
            "probe_detach" => {
                crate::probeclient::detach()?;
                Ok(json!({"detached": true}))
            }
            other => Err(format!("未知工具：{other}")),
        }
    }
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

fn groups_json(groups: &[crate::cgroup::GroupState]) -> Vec<Value> {
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
            "列出 cgroup 调度分组（CPU 上限/权重、pids 上限、进程数）。远端主机要求存在可写的用户委派 cgroup。",
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
            "本机探针能力：内核版本、kallsyms 函数/系统调用数量、可探测用户态目标、tracefs/BPF 权限与所需工具。",
            json!({}),
            &[],
        ),
        tool(
            "probe_search",
            "在 kallsyms 中搜索函数或系统调用名。",
            json!({
                "query": {"type": "string"},
                "kind": {"type": "string", "enum": ["function", "syscall", "both"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            }),
            &["query"],
        ),
        tool(
            "probe_attach",
            "挂载 kprobe / syscall / uprobe（需先安装 root probe-helper 服务）。可指定 stack、pid、args 过滤。",
            json!({
                "kind": {"type": "string", "enum": ["kprobe", "syscall", "uprobe"]},
                "symbol": {"type": "string"},
                "target": {"type": "string", "description": "uprobe 的可执行文件路径"},
                "stack": {"type": "boolean"},
                "pid": {"type": "integer"},
                "args": {"type": "string", "description": "附加过滤表达式，如 comm==bash"},
            }),
            &["symbol"],
        ),
        tool("probe_poll", "读取探针累计命中与最近调用记录。", json!({}), &[]),
        tool("probe_detach", "卸载当前探针。", json!({}), &[]),
    ]
}

/// 工具声明：注解（readOnlyHint/destructiveHint）由服务端分级表派生，
/// 与 mcppolicy::risk_of 保持同源，不会出现注解放行、服务端拒绝的劈叉。
fn tool(name: &str, desc: &str, props: Value, required: &[&str]) -> Value {
    // 静态注解按工具名的基础分级；参数敏感（KILL/tree/delete）在服务端运行时升级
    const READ_ONLY_TOOLS: &[&str] = &[
        "hosts_list", "host_use", "system_overview", "system_load", "process_list",
        "network_connections", "filesystems", "probe_status", "probe_search", "probe_poll",
        "policy_status",
    ];
    let (read_only, destructive) = match name {
        // 运行时按参数定级（KILL/tree/delete 会升级 L3），注解不给只读提示
        "process_signal" | "scheduler_group_action" => (false, false),
        n if READ_ONLY_TOOLS.contains(&n) => (true, false),
        _ => (false, false),
    };
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
        },
    })
}

fn handle(server: &mut Server, msg: &Value) -> Option<Value> {
    let method = msg.get("method")?.as_str()?;
    let id = msg.get("id").cloned();
    // 通知（无 id）不回包，例如 notifications/initialized
    id.as_ref()?;
    let response = match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "system-monitor", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "系统监视器 MCP：hosts_list / host_use 切换主机；system_overview / system_load 看负载；process_list / process_signal / process_nice 管进程；scheduler_* 管 cgroup；network_connections / filesystems；probe_* 为本机探针。",
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => {
            let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match server.call(name, &args) {
                Ok(v) => Ok(json!({
                    "content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string())}],
                    "isError": false,
                })),
                Err(e) => Ok(json!({
                    "content": [{"type": "text", "text": e}],
                    "isError": true,
                })),
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
            Some(m) => server.policy = m,
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
        assert_eq!(find("process_nice")["annotations"]["readOnlyHint"], false);
        assert!(find("policy_status")["name"] == "policy_status");
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
        assert!(v["levels"]["L3_destructive"].is_array());
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