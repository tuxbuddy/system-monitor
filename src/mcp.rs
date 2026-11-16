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

use crate::pi::PiStats;
use crate::procstats::{self, FsUsage, NetConn, Sampler, Usage};
use crate::remote;

struct View {
    usage: Usage,
    pi: PiStats,
    filesystems: Vec<FsUsage>,
    conns: Vec<NetConn>,
    label: String,
}

pub struct Server {
    current: Option<remote::SshTarget>,
    hosts: Vec<remote::SshTarget>,
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
                })
            }
            Some(h) => {
                let key = h.as_str().to_string();
                let mut prev = self.remote_prev.remove(&key).flatten();
                let first = prev.is_none();
                let mut sample = remote::collect(h, &mut prev).ok_or_else(|| format!("无法连接远端主机：{key}"))?;
                if first {
                    std::thread::sleep(Duration::from_millis(120));
                    if let Some(again) = remote::collect(h, &mut prev) {
                        sample = again;
                    }
                }
                self.remote_prev.insert(key, prev);
                Ok(View {
                    usage: sample.usage,
                    pi: sample.pi,
                    filesystems: sample.filesystems,
                    conns: sample.conns,
                    label: h.as_str().to_string(),
                })
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

    fn call(&mut self, name: &str, args: &Value) -> Result<Value, String> {
        match name {
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
                        let ok = match action {
                            "create" => remote::cg_create(h, &base, &name) && remote::cg_ensure(h, &base),
                            "delete" => remote::cg_delete(h, &base, &name),
                            other => return Err(format!("未知 action：{other}")),
                        };
                        if !ok {
                            return Err(format!("远端 {action} 失败（名称冲突或权限不足）"));
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
    })
}

fn groups_json(groups: &[crate::cgroup::GroupState]) -> Vec<Value> {
    groups
        .iter()
        .map(|g| {
            json!({
                "name": g.name, "cpu_max_percent": g.cpu_max_pct, "cpu_weight": g.cpu_weight,
                "pids_max": g.pids_max, "process_count": g.procs,
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
            "向进程发送信号（TERM/KILL/STOP/CONT/HUP/INT/USR1/USR2），可选结束整棵进程树。远端主机经 SSH 执行。",
            json!({
                "pid": {"type": "integer"},
                "signal": {"type": "string"},
                "tree": {"type": "boolean", "description": "true 时对进程树执行（仅 TERM/KILL 有意义）"},
                "host": {"type": "string"},
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
            "创建或删除 cgroup 调度分组。",
            json!({
                "action": {"type": "string", "enum": ["create", "delete"]},
                "name": {"type": "string"},
                "host": {"type": "string"},
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

fn tool(name: &str, desc: &str, props: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": desc,
        "inputSchema": {
            "type": "object",
            "properties": props,
            "required": required,
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