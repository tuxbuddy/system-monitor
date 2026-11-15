//! SSH 远程主机采集（只读、远端零安装）。
//! 本地周期性执行一条只读脚本（cat /proc/*、可选 vcgencmd、ps），按节解析成
//! 与本地一致的 Usage / PiStats，从而整套界面可直接展示远端。
//!
//! 前提：本机到目标已配置免密登录（SSH key / agent）；命令一律只读。

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use crate::pi::{self, GpuStats, PiStats};
use crate::procstats::{self, CpuTimes, ProcUsage, Usage};

/// 远端只读采集脚本（单次 SSH 一次拿全）。
pub const SCRIPT: &str = r#"LANG=C
echo '##stat'; cat /proc/stat
echo '##mem'; cat /proc/meminfo
echo '##load'; cat /proc/loadavg
echo '##up'; cat /proc/uptime
echo '##disk'; cat /proc/diskstats
echo '##net'; cat /proc/net/dev
echo '##temp'; for f in /sys/class/thermal/thermal_zone0/temp /sys/class/hwmon/hwmon0/temp1_input; do cat "$f" 2>/dev/null && break; done
echo '##v3d'; command -v vcgencmd >/dev/null 2>&1 && vcgencmd measure_clock v3d 2>/dev/null
echo '##thr'; command -v vcgencmd >/dev/null 2>&1 && vcgencmd get_throttled 2>/dev/null
echo '##ps'; ps -eo pid=,ppid=,comm=,user=,stat=,pcpu=,pmem=,rss=,ni= 2>/dev/null
echo '##end'
"#;

/// 跨采样累计量（用于算 CPU%/磁盘/网络速率）。
pub struct Counters {
    pub cpu: Vec<CpuTimes>,
    pub disk: Option<(u64, u64)>,
    pub net: Option<(u64, u64)>,
    pub at: Instant,
}

pub fn hosts_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/system-monitor/hosts.conf"))
}

pub fn parse_hosts(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|s| s.to_string())
        .collect()
}

pub fn load_hosts() -> Vec<String> {
    hosts_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| parse_hosts(&t))
        .unwrap_or_default()
}

pub fn save_hosts(hosts: &[String]) {
    if let Some(p) = hosts_path() {
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(p, hosts.join("\n") + "\n");
    }
}

fn sections(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut cur = String::new();
    let mut buf = String::new();
    for line in text.lines() {
        if let Some(k) = line.strip_prefix("##") {
            if !cur.is_empty() {
                map.insert(cur.clone(), std::mem::take(&mut buf));
            }
            cur = k.trim().to_string();
        } else {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    if !cur.is_empty() {
        map.insert(cur, buf);
    }
    map
}

fn pct(busy: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        busy as f32 / total as f32 * 100.0
    }
}

fn rate(p: Option<(u64, u64)>, c: Option<(u64, u64)>, secs: f32) -> (f32, f32) {
    match (p, c) {
        (Some(p), Some(c)) if secs > 0.0 => (
            if c.0 >= p.0 { (c.0 - p.0) as f32 / secs } else { 0.0 },
            if c.1 >= p.1 { (c.1 - p.1) as f32 / secs } else { 0.0 },
        ),
        _ => (0.0, 0.0),
    }
}

fn parse_ps(text: &str) -> Vec<ProcUsage> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 9 {
            continue;
        }
        let Ok(pid) = f[0].parse::<i32>() else {
            continue;
        };
        out.push(ProcUsage {
            pid,
            ppid: f[1].parse().unwrap_or(0),
            uid: 0,
            comm: f[2].to_string(),
            user: f[3].to_string(),
            cpu_percent: f[5].parse().unwrap_or(0.0),
            nice: f[8].parse().unwrap_or(0),
            state: f[4].chars().next().unwrap_or('?'),
            rss_kb: f[7].parse().unwrap_or(0),
            mem_percent: f[6].parse().unwrap_or(0.0),
        });
    }
    out.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// 解析一次脚本输出；用 prev 累计量算 CPU/磁盘/网络增量。
pub fn parse_output(text: &str, prev: &mut Option<Counters>) -> Option<(Usage, PiStats)> {
    let sec = sections(text);
    let now = Instant::now();
    let cores: Vec<CpuTimes> = sec
        .get("stat")
        .map(|s| {
            s.lines()
                .filter(|l| l.starts_with("cpu") && !l.starts_with("cpu "))
                .filter_map(CpuTimes::parse)
                .collect()
        })
        .unwrap_or_default();
    let (prev_cores, elapsed) = match prev.as_ref() {
        Some(p) => (p.cpu.clone(), now.duration_since(p.at).as_secs_f32().max(0.001)),
        None => (Vec::new(), 0.0),
    };
    let total_percent = if prev_cores.is_empty() {
        0.0
    } else {
        let pt: u64 = prev_cores.iter().map(|c| c.total()).sum();
        let ct: u64 = cores.iter().map(|c| c.total()).sum();
        let pb: u64 = prev_cores.iter().map(|c| c.busy()).sum();
        let cb: u64 = cores.iter().map(|c| c.busy()).sum();
        pct(cb.saturating_sub(pb), ct.saturating_sub(pt))
    };
    let core_percent: Vec<f32> = cores
        .iter()
        .enumerate()
        .map(|(i, c)| match prev_cores.get(i) {
            Some(p) => pct(c.busy().saturating_sub(p.busy()), c.total().saturating_sub(p.total())),
            None => 0.0,
        })
        .collect();
    let disk = sec.get("disk").and_then(|s| procstats::parse_diskstats(s));
    let net = sec.get("net").and_then(|s| procstats::parse_netdev(s));
    let (disk_r, disk_w) = rate(prev.as_ref().and_then(|p| p.disk), disk, elapsed);
    let (net_rx, net_tx) = rate(prev.as_ref().and_then(|p| p.net), net, elapsed);
    let mem = sec.get("mem").and_then(|s| procstats::parse_meminfo(s));
    let load = sec.get("load").and_then(|s| procstats::parse_loadavg(s));
    let uptime_secs = sec.get("up").and_then(|s| procstats::parse_uptime(s));
    let temp_c = sec.get("temp").and_then(|s| pi::parse_temp_millideg(s));
    let v3d = sec.get("v3d").and_then(|s| pi::parse_clock_hz(s));
    let throttle = sec.get("thr").and_then(|s| pi::parse_throttled(s));
    let procs = sec.get("ps").map(|s| parse_ps(s)).unwrap_or_default();
    *prev = Some(Counters { cpu: cores, disk, net, at: now });
    let usage = Usage {
        total_percent,
        core_percent,
        procs,
        mem,
        load,
        uptime_secs,
        disk_read_bps: disk_r,
        disk_write_bps: disk_w,
        net_rx_bps: net_rx,
        net_tx_bps: net_tx,
    };
    let pi = PiStats {
        temp_c,
        freq_ghz: None,
        gpu: GpuStats { v3d_ghz: v3d, ..Default::default() },
        power: None,
        throttle,
        rails: Vec::new(),
    };
    Some((usage, pi))
}

/// 通过 SSH 拉取一次（只读）。target 形如 user@host 或 ~/.ssh/config 里的别名。
pub fn collect(target: &str, prev: &mut Option<Counters>) -> Option<(Usage, PiStats)> {
    let out = Command::new("ssh")
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=6"])
        .arg(target)
        .arg(SCRIPT)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_output(&text, prev)
}

/// 单主机摘要（供总览页并排展示）。
#[derive(Clone, Copy)]
pub struct FleetSummary {
    pub ok: bool,
    pub cpu: f32,
    pub mem: f32,
    pub temp: f32,
    pub gpu: f32,
    pub load1: f32,
    pub procs: usize,
}

pub fn summary(target: &str, prev: &mut Option<Counters>) -> FleetSummary {
    match collect(target, prev) {
        Some((u, pi)) => FleetSummary {
            ok: true,
            cpu: u.total_percent,
            mem: u.mem.map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 }).unwrap_or(0.0),
            temp: pi.temp_c.unwrap_or(0.0),
            gpu: pi.gpu.v3d_ghz.unwrap_or(0.0),
            load1: u.load.map(|l| l.one).unwrap_or(0.0),
            procs: u.procs.len(),
        },
        None => FleetSummary {
            ok: false,
            cpu: 0.0,
            mem: 0.0,
            temp: 0.0,
            gpu: 0.0,
            load1: 0.0,
            procs: 0,
        },
    }
}

// ---- 远端 cgroup（写操作，仅在用户显式允许时调用）----
// 只作用于该主机上「当前用户」的分组；所有名字经白名单校验，路径来自远端 /proc，均做基本转义校验。

use crate::cgroup::{self, GroupState};

fn ssh_sh(target: &str, script: &str) -> Option<String> {
    let out = Command::new("ssh")
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=6"])
        .arg(target)
        .arg(script)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// 用户 systemd 管理器（委派根）目录：user-<uid>.slice/user@<uid>.service。
pub fn user_service_path(uid: u32) -> String {
    format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service")
}

/// 远端可写的委派根。注意：SSH 会话本身在 `session-*.scope`，并不在 `user@uid.service`
/// 内，所以必须按 SSH 用户的 uid 推算 user@uid.service 并校验存在且可写。
pub fn cg_base(target: &str) -> Option<String> {
    let uid: u32 = ssh_sh(target, "id -u")?.trim().parse().ok()?;
    let base = user_service_path(uid);
    let ok = ssh_sh(target, &format!("[ -d '{base}' ] && [ -w '{base}' ] && echo OK"))
        .map(|s| s.contains("OK"))
        .unwrap_or(false);
    ok.then_some(base)
}

/// 建并准备容器 cm-sched（+cpu +pids）。
pub fn cg_ensure(target: &str, base: &str) -> bool {
    let c = format!("{base}/cm-sched");
    ssh_sh(
        target,
        &format!("mkdir -p '{c}' && printf '+cpu +pids' > '{c}/cgroup.subtree_control' 2>/dev/null; echo READY"),
    )
    .map(|s| s.contains("READY"))
    .unwrap_or(false)
}

fn parse_group_lines(text: &str) -> Vec<GroupState> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('|').collect();
        if f.len() != 5 {
            continue;
        }
        let pids_max = {
            let t = f[3].trim();
            if t.is_empty() || t == "max" { None } else { t.parse().ok() }
        };
        out.push(GroupState {
            name: f[0].to_string(),
            cpu_max_pct: cgroup::parse_cpu_max(f[1]),
            cpu_weight: f[2].trim().parse().unwrap_or(100),
            pids_max,
            procs: f[4].trim().parse().unwrap_or(0),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn cg_list(target: &str, base: &str) -> Vec<GroupState> {
    let c = format!("{base}/cm-sched");
    let script = format!(
        "cd '{c}' 2>/dev/null || exit 0; for d in */; do n=${{d%/}}; [ \"$n\" = default ] && continue; \
printf '%s|%s|%s|%s|%s\\n' \"$n\" \"$(cat \"$d/cpu.max\" 2>/dev/null)\" \"$(cat \"$d/cpu.weight\" 2>/dev/null)\" \"$(cat \"$d/pids.max\" 2>/dev/null)\" \"$(grep -c . \"$d/cgroup.procs\" 2>/dev/null)\"; done"
    );
    parse_group_lines(&ssh_sh(target, &script).unwrap_or_default())
}

fn safe_name(name: &str) -> bool {
    cgroup::valid_group_name(name)
}

pub fn cg_create(target: &str, base: &str, name: &str) -> bool {
    safe_name(name) && ssh_sh(target, &format!("mkdir '{base}/cm-sched/{name}'")).is_some()
}

pub fn cg_delete(target: &str, base: &str, name: &str) -> bool {
    safe_name(name) && ssh_sh(target, &format!("rmdir '{base}/cm-sched/{name}'")).is_some()
}

pub fn cg_set_cpu_max(target: &str, base: &str, name: &str, pct: Option<u32>) -> bool {
    if !safe_name(name) {
        return false;
    }
    let val = match pct {
        Some(p) if p > 0 => format!("{} 100000", p.saturating_mul(1000)),
        _ => "max 100000".to_string(),
    };
    ssh_sh(target, &format!("printf '{val}' > '{base}/cm-sched/{name}/cpu.max'")).is_some()
}

pub fn cg_set_weight(target: &str, base: &str, name: &str, w: u32) -> bool {
    safe_name(name) && ssh_sh(target, &format!("printf '{}' > '{base}/cm-sched/{name}/cpu.weight'", w.clamp(1, 10000))).is_some()
}

pub fn cg_set_pids(target: &str, base: &str, name: &str, max: Option<u32>) -> bool {
    if !safe_name(name) {
        return false;
    }
    let val = max.map(|m| m.max(1).to_string()).unwrap_or_else(|| "max".to_string());
    ssh_sh(target, &format!("printf '{val}' > '{base}/cm-sched/{name}/pids.max'")).is_some()
}

/// 迁入并返回原 cgroup 路径（形如 /user.slice/...），供还原。
pub fn cg_move_in(target: &str, base: &str, name: &str, pid: i32) -> Option<String> {
    if !safe_name(name) {
        return None;
    }
    let c = format!("{base}/cm-sched/{name}");
    let script = format!(
        "o=$(sed -n 's|^0::||p' /proc/{pid}/cgroup); printf '{pid}' > '{c}/cgroup.procs' && printf '%s' \"$o\""
    );
    ssh_sh(target, &script).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub fn cg_release(target: &str, original: &str, pid: i32) -> bool {
    if original.is_empty() || original.contains('\'') || original.contains(';') {
        return false;
    }
    ssh_sh(target, &format!("printf '{pid}' > '/sys/fs/cgroup{original}/cgroup.procs'")).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_parse() {
        let v = parse_hosts("# 注释\n pi@192.168.1.5 \n\nroot@kylin\n");
        assert_eq!(v, vec!["pi@192.168.1.5".to_string(), "root@kylin".to_string()]);
    }

    fn blob(cpu_user: u64, cpu_idle: u64) -> String {
        format!(
            "##stat\ncpu0 {cpu_user} 0 0 {cpu_idle} 0 0 0 0\n##mem\nMemTotal: 8000 kB\nMemAvailable: 4000 kB\n##load\n0.5 0.4 0.3 1/100 1\n##up\n1000.0 0\n##ps\n1 0 init root S 0.0 0.1 100 0\n42 1 busy user R 12.5 2.0 2048 5\n##end\n"
        )
    }

    #[test]
    fn parses_and_computes_delta() {
        let mut prev = None;
        let (u1, _) = parse_output(&blob(100, 900), &mut prev).unwrap();
        assert_eq!(u1.total_percent, 0.0); // 无前值
        assert_eq!(u1.procs.len(), 2);
        assert_eq!(u1.procs[0].comm, "busy"); // 按 CPU 排序
        let (u2, _) = parse_output(&blob(200, 1800), &mut prev).unwrap();
        // 两次差值：busy 100 / total 1000 = 10%
        assert!((u2.total_percent - 10.0).abs() < 0.01);
        assert_eq!(u2.mem.unwrap().total_kb, 8000);
    }

    #[test]
    fn script_runs_locally() {
        let Ok(out) = Command::new("sh").arg("-c").arg(SCRIPT).output() else {
            return;
        };
        if !out.status.success() {
            return;
        }
        let mut prev = None;
        let r = parse_output(&String::from_utf8_lossy(&out.stdout), &mut prev);
        assert!(r.is_some(), "本机脚本输出应可解析");
        let (u, _) = r.unwrap();
        assert!(!u.procs.is_empty(), "应解析到进程列表");
    }

    #[test]
    fn user_service_path_shape() {
        assert_eq!(
            user_service_path(0),
            "/sys/fs/cgroup/user.slice/user-0.slice/user@0.service"
        );
        assert_eq!(
            user_service_path(1000),
            "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"
        );
    }

    #[test]
    fn group_lines_parse() {
        let t = "build|50000 100000|200|64|3\nbg|max 100000|100|max|0\n";
        let g = parse_group_lines(t);
        assert_eq!(g.len(), 2);
        let b = g.iter().find(|x| x.name == "build").unwrap();
        assert_eq!(b.cpu_max_pct, Some(50));
        assert_eq!(b.cpu_weight, 200);
        assert_eq!(b.pids_max, Some(64));
        assert_eq!(b.procs, 3);
        let bg = g.iter().find(|x| x.name == "bg").unwrap();
        assert_eq!(bg.cpu_max_pct, None);
        assert_eq!(bg.pids_max, None);
    }
}