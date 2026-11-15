//! SSH 远程主机采集（只读、远端零安装）。
//! 本地周期性执行一条只读脚本（cat /proc/*、可选 vcgencmd、ps），按节解析成
//! 与本地一致的 Usage / PiStats，从而整套界面可直接展示远端。
//!
//! 前提：本机到目标已配置免密登录（SSH key / agent）；命令一律只读。

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::fsutil;
use crate::pi::{self, GpuStats, PiStats, Power, RemoteInfo};
use crate::procstats::{self, CpuTimes, FsUsage, NetConn, ProcDetails, ProcUsage, Usage};
pub use crate::sshtarget::{HostsLineError, SshTarget, parse_hosts_checked};

// ---- SSH 执行层：统一 deadline / 输出上限 / 取消 ----

/// 单次远端命令的限制。默认总超时 10s、输出 2 MiB。
#[derive(Clone, Copy)]
pub struct ExecLimits {
    pub timeout: Duration,
    pub max_output: usize,
}

impl Default for ExecLimits {
    fn default() -> Self {
        Self { timeout: Duration::from_secs(10), max_output: 2 * 1024 * 1024 }
    }
}

/// 协作式取消标志：主机切换、退出、fleet 刷新时置位，在途命令尽快返回。
#[derive(Default)]
pub struct Cancel {
    flag: AtomicBool,
}

impl Cancel {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
    fn cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

/// 远端失败的结构化错误：区分阶段，带耗时，不再以裸字符串兜底。
#[derive(Debug, Clone)]
pub enum RemoteError {
    /// ssh 无法启动（本机没有 ssh、资源不足等）。
    Spawn(String),
    /// 超过总超时，子进程已被 kill 并回收。
    Timeout { elapsed: Duration },
    /// 调用方主动取消，子进程已被 kill 并回收。
    Cancelled { elapsed: Duration },
    /// ssh 退出码非 0（认证失败、网络不可达、远端命令失败）。
    Failed { code: i32, stderr: String },
}

impl RemoteError {
    /// 机器可读的错误码，供 UI/MCP 展示与分类。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Spawn(_) => "spawn",
            Self::Timeout { .. } => "timeout",
            Self::Cancelled { .. } => "cancelled",
            Self::Failed { code, stderr } => {
                if stderr.contains("Permission denied") || stderr.contains("Authentication failed") {
                    "auth"
                } else if *code == 255 {
                    "unreachable"
                } else {
                    "command"
                }
            }
        }
    }
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "无法启动 ssh：{e}"),
            Self::Timeout { elapsed } => write!(f, "远端命令超时（{:.1}s），已终止", elapsed.as_secs_f32()),
            Self::Cancelled { elapsed } => write!(f, "远端命令已取消（{:.1}s）", elapsed.as_secs_f32()),
            Self::Failed { code, stderr } => {
                let msg = stderr.trim();
                if msg.is_empty() {
                    write!(f, "远端命令失败（退出码 {code}）")
                } else {
                    write!(f, "远端命令失败：{}", truncate_tail(msg, 300))
                }
            }
        }
    }
}

fn truncate_tail(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

#[derive(Debug)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    /// 输出超过上限被截断（数据不完整，调用方需感知）。
    pub truncated: bool,
}

/// 统一的 SSH 执行入口：所有远端命令都必须经过这里。
///
/// 保证：在 `timeout + 1s` 内返回；超时/取消后 kill 并回收 ssh，不留孤儿进程；
/// stdout/stderr 各自最多读 `max_output` 字节，超限置 `truncated` 并终止命令。
pub fn ssh_exec(
    target: &SshTarget,
    script: &str,
    limits: &ExecLimits,
    cancel: Option<&Cancel>,
) -> Result<ExecOutput, RemoteError> {
    let started = Instant::now();
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=6",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "--", // 终止选项解析：目标串即使形如选项也不会被 ssh 误读
    ])
    .arg(target.as_str())
    .arg(script)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child: Child = cmd.spawn().map_err(|e| RemoteError::Spawn(e.to_string()))?;

    // 读线程：各限 max_output 字节；读满即标记截断，主循环会终止命令。
    let truncated = Arc::new(AtomicBool::new(false));
    let out_handle = spawn_reader(child.stdout.take(), limits.max_output, truncated.clone());
    let err_handle = spawn_reader(child.stderr.take(), limits.max_output, truncated.clone());

    let outcome = loop {
        if let Some(c) = cancel
            && c.cancelled()
        {
            break Err(RemoteError::Cancelled { elapsed: started.elapsed() });
        }
        if truncated.load(Ordering::Relaxed) {
            break Err(RemoteError::Failed { code: -1, stderr: format!("输出超过 {} 字节上限，命令已终止", limits.max_output) });
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(e) => break Err(RemoteError::Spawn(e.to_string())),
        }
        if started.elapsed() >= limits.timeout {
            break Err(RemoteError::Timeout { elapsed: started.elapsed() });
        }
        std::thread::sleep(Duration::from_millis(25));
    };

    if outcome.is_err() {
        // 超时 / 取消 / 截断：kill 进程并同步回收，读线程随管道 EOF 退出
        let _ = child.kill();
        let _ = child.wait();
    }
    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();
    let truncated = truncated.load(Ordering::Relaxed);

    match outcome {
        Err(e) => Err(e),
        Ok(status) => {
            if status.success() {
                Ok(ExecOutput {
                    stdout: String::from_utf8_lossy(&stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&stderr).into_owned(),
                    truncated,
                })
            } else {
                Err(RemoteError::Failed { code: status.code().unwrap_or(-1), stderr: String::from_utf8_lossy(&stderr).into_owned() })
            }
        }
    }
}

fn spawn_reader<R: Read + Send + 'static>(
    pipe: Option<R>,
    cap: usize,
    truncated: Arc<AtomicBool>,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let Some(mut pipe) = pipe else {
            return Vec::new();
        };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > cap {
                        let room = cap.saturating_sub(buf.len());
                        buf.extend_from_slice(&chunk[..room]);
                        truncated.store(true, Ordering::Relaxed);
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(_) => break,
            }
        }
        buf
    })
}

/// 远端只读采集脚本（单次 SSH 一次拿全）。
/// 跨发行版：传感器优先 hwmon（coretemp/k10temp 等），功耗优先 RAPL 能量差分，
/// 显卡型号取 lspci、温度取显卡驱动 hwmon；树莓派仍走 vcgencmd。
pub const SCRIPT: &str = r#"LANG=C
echo '##os'; (. /etc/os-release 2>/dev/null; printf '%s|%s|%s\n' "$PRETTY_NAME" "$ID" "$(id -u)")
echo '##stat'; cat /proc/stat
echo '##mem'; cat /proc/meminfo
echo '##load'; cat /proc/loadavg
echo '##up'; cat /proc/uptime
echo '##disk'; cat /proc/diskstats
echo '##net'; cat /proc/net/dev
echo '##temp'; for n in coretemp k10temp zenpower cpu_thermal soc_thermal; do for d in /sys/class/hwmon/hwmon*/; do if [ "$(cat "$d/name" 2>/dev/null)" = "$n" ]; then cat "$d/temp1_input" 2>/dev/null && break 2; fi; done; done || cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null
echo '##freq'; cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null
echo '##rapl'; cat /sys/class/powercap/intel-rapl:0/energy_uj 2>/dev/null || cat /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj 2>/dev/null
echo '##gpu'; lspci 2>/dev/null | grep -iE 'vga compatible|3d controller|display controller' | head -n 1; for n in nouveau amdgpu i915 radeon; do for d in /sys/class/hwmon/hwmon*/; do if [ "$(cat "$d/name" 2>/dev/null)" = "$n" ]; then cat "$d/temp1_input" 2>/dev/null && break 2; fi; done; done
echo '##v3d'; command -v vcgencmd >/dev/null 2>&1 && vcgencmd measure_clock v3d 2>/dev/null
echo '##thr'; command -v vcgencmd >/dev/null 2>&1 && vcgencmd get_throttled 2>/dev/null
echo '##df'; df -P -k 2>/dev/null
echo '##tcp'; cat /proc/net/tcp 2>/dev/null
echo '##tcp6'; cat /proc/net/tcp6 2>/dev/null
echo '##udp'; cat /proc/net/udp 2>/dev/null
echo '##udp6'; cat /proc/net/udp6 2>/dev/null
echo '##ps'; ps -eo pid=,ppid=,comm=,user=,uid=,stat=,pcpu=,pmem=,rss=,ni= 2>/dev/null
echo '##end'
"#;

/// 跨采样累计量（用于算 CPU%/磁盘/网络速率/功耗）。
pub struct Counters {
    pub cpu: Vec<CpuTimes>,
    pub disk: Option<(u64, u64)>,
    pub net: Option<(u64, u64)>,
    pub rapl_uj: Option<u64>,
    pub at: Instant,
}

pub fn hosts_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/system-monitor/hosts.conf"))
}

/// 读取 hosts.conf：合法目标 + 带行号的非法行报告（不静默跳过）。
pub fn load_hosts() -> (Vec<SshTarget>, Vec<HostsLineError>) {
    hosts_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| parse_hosts_checked(&t))
        .unwrap_or_default()
}

/// 原子写入主机清单（0600）。所有条目先经校验；返回首个非法项的错误。
pub fn save_hosts(hosts: &[SshTarget]) -> Result<(), String> {
    let Some(p) = hosts_path() else {
        return Ok(());
    };
    let mut text = String::new();
    for h in hosts {
        text.push_str(h.as_str());
        text.push('\n');
    }
    fsutil::atomic_write(&p, text.as_bytes(), fsutil::MODE_PRIVATE).map_err(|e| format!("hosts.conf 写入失败：{e}"))
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
        if f.len() < 10 {
            continue;
        }
        let Ok(pid) = f[0].parse::<i32>() else {
            continue;
        };
        out.push(ProcUsage {
            pid,
            ppid: f[1].parse().unwrap_or(0),
            uid: f[4].parse().unwrap_or(0),
            comm: f[2].to_string(),
            user: f[3].to_string(),
            cpu_percent: f[6].parse().unwrap_or(0.0),
            nice: f[9].parse().unwrap_or(0),
            state: f[5].chars().next().unwrap_or('?'),
            rss_kb: f[8].parse().unwrap_or(0),
            mem_percent: f[7].parse().unwrap_or(0.0),
        });
    }
    out.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// 解析 `##os`："Ubuntu 26.04 LTS|ubuntu|1000" → 系统名 + 登录 uid。
fn parse_remote(text: &str) -> Option<RemoteInfo> {
    let line = text.lines().next()?.trim();
    let mut f = line.split('|');
    let os = f.next()?.trim();
    if os.is_empty() {
        return None;
    }
    let uid = f.nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    Some(RemoteInfo { os: os.to_string(), uid })
}

fn parse_rapl(text: &str) -> Option<u64> {
    text.split_whitespace().next()?.parse().ok()
}

/// "01:00.0 VGA compatible controller: NVIDIA Corporation GK208B [GeForce GT 730] (rev a1)"
/// → "GeForce GT 730"（优先取最后一对方括号里的市场名，否则去厂商前缀）。
fn parse_gpu_model(line: &str) -> Option<String> {
    let l = line.trim();
    if l.is_empty() {
        return None;
    }
    let tail = l.split_once(": ").map(|(_, r)| r).unwrap_or(l);
    let tail = tail.split(" (rev ").next().unwrap_or(tail).trim();
    if let Some(a) = tail.rfind('[')
        && let Some(b) = tail[a + 1..].find(']')
        && b > 0
    {
        return Some(tail[a + 1..a + 1 + b].trim().to_string());
    }
    let mut name = tail.to_string();
    for v in ["NVIDIA Corporation ", "Advanced Micro Devices, Inc. ", "Intel Corporation "] {
        if let Some(r) = name.strip_prefix(v) {
            name = r.to_string();
            break;
        }
    }
    (!name.is_empty()).then_some(name)
}

/// 解析 `##gpu`：型号行（lspci）+ 温度行（hwmon 毫度）。
fn parse_gpu(text: &str) -> (Option<String>, Option<f32>) {
    let (mut model, mut temp) = (None, None);
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Ok(m) = line.parse::<i64>() {
            if temp.is_none() {
                temp = Some(m as f32 / 1000.0);
            }
        } else if model.is_none() {
            model = parse_gpu_model(line);
        }
    }
    (model, temp)
}

/// 一次远端采样的完整结果（界面各页共用）。
#[derive(Clone)]
pub struct RemoteSample {
    pub usage: Usage,
    pub pi: PiStats,
    pub filesystems: Vec<FsUsage>,
    pub conns: Vec<NetConn>,
}

/// 解析一次脚本输出；用 prev 累计量算 CPU/磁盘/网络增量与 RAPL 功耗。
pub fn parse_output(text: &str, prev: &mut Option<Counters>) -> Option<RemoteSample> {
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
    let freq_ghz = sec.get("freq").and_then(|s| pi::parse_freq_khz(s)).map(|k| k as f32 / 1_000_000.0);
    let rapl = sec.get("rapl").and_then(|s| parse_rapl(s));
    let power_w = match (prev.as_ref().and_then(|p| p.rapl_uj), rapl) {
        (Some(p), Some(c)) if c >= p && elapsed > 0.0 => Some((c - p) as f64 / 1e6 / elapsed as f64),
        _ => None,
    };
    let (gpu_model, gpu_temp) = sec.get("gpu").map(|s| parse_gpu(s)).unwrap_or((None, None));
    let v3d = sec.get("v3d").and_then(|s| pi::parse_clock_hz(s));
    let throttle = sec.get("thr").and_then(|s| pi::parse_throttled(s));
    let os = sec.get("os").and_then(|s| parse_remote(s));
    let procs = sec.get("ps").map(|s| parse_ps(s)).unwrap_or_default();
    let filesystems = sec.get("df").map(|s| procstats::parse_df(s)).unwrap_or_default();
    let mut conns = Vec::new();
    for (key, proto) in [("tcp", "TCP"), ("tcp6", "TCP6"), ("udp", "UDP"), ("udp6", "UDP6")] {
        if let Some(text) = sec.get(key) {
            conns.extend(procstats::parse_proc_net(text, proto));
        }
    }
    *prev = Some(Counters { cpu: cores, disk, net, rapl_uj: rapl, at: now });
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
        freq_ghz,
        gpu: GpuStats { v3d_ghz: v3d, model: gpu_model, temp_c: gpu_temp, ..Default::default() },
        power: power_w.map(|w| Power { core_v: 0.0, core_a: 0.0, core_w: w as f32, ext5v_v: 0.0 }),
        throttle,
        rails: Vec::new(),
        remote: os,
    };
    Some(RemoteSample { usage, pi, filesystems, conns })
}

/// 通过 SSH 拉取一次（只读）。target 必须是已校验的 `SshTarget`。
pub fn collect(target: &SshTarget, prev: &mut Option<Counters>) -> Option<RemoteSample> {
    let out = ssh_exec(target, SCRIPT, &ExecLimits::default(), None).ok()?;
    if out.truncated {
        return None; // 输出不完整，宁可不更新也不能拿半截数据冒充采样
    }
    parse_output(&out.stdout, prev)
}

/// 单主机摘要（供总览页并排展示）。
#[derive(Clone)]
pub struct FleetSummary {
    pub ok: bool,
    pub os: String,
    pub cpu: f32,
    pub mem: f32,
    pub temp: f32,
    pub gpu: f32,
    pub load1: f32,
    pub procs: usize,
}

pub fn summary(target: &SshTarget, prev: &mut Option<Counters>) -> FleetSummary {
    match collect(target, prev) {
        Some(s) => FleetSummary {
            ok: true,
            os: s.pi.remote.as_ref().map(|r| r.os.clone()).unwrap_or_default(),
            cpu: s.usage.total_percent,
            mem: s
                .usage
                .mem
                .map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 })
                .unwrap_or(0.0),
            temp: s.pi.temp_c.unwrap_or(0.0),
            gpu: s.pi.gpu.v3d_ghz.or(s.pi.gpu.temp_c).unwrap_or(0.0),
            load1: s.usage.load.map(|l| l.one).unwrap_or(0.0),
            procs: s.usage.procs.len(),
        },
        None => FleetSummary {
            ok: false,
            os: String::new(),
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

fn ssh_sh(target: &SshTarget, script: &str) -> Option<String> {
    let out = ssh_exec(target, script, &ExecLimits::default(), None).ok()?;
    if out.truncated {
        return None;
    }
    Some(out.stdout)
}

// ---- 远端进程操作（对应本地 actions.rs；只接受数字 PID 与固定命令模板）----

fn ssh_run(target: &SshTarget, cmd: &str) -> Result<String, String> {
    let out = ssh_exec(target, cmd, &ExecLimits::default(), None).map_err(|e| e.to_string())?;
    if out.truncated {
        return Err("远端输出超过上限（可能异常）".to_string());
    }
    Ok(out.stdout)
}

fn valid_pid(pid: i32) -> bool {
    pid > 1
}

/// 向远端单个进程发信号（sig 为信号编号，如 15/9/18/19）。
pub fn signal(target: &SshTarget, pid: i32, sig: i32) -> Result<(), String> {
    if !valid_pid(pid) {
        return Err("PID 无效".to_string());
    }
    ssh_run(target, &format!("kill -{sig} {pid}")).map(|_| ())
}

/// 向远端一组进程发信号，返回成功个数（用于结束进程树）。
pub fn signal_many(target: &SshTarget, pids: &[i32], sig: i32) -> Result<usize, String> {
    let list: Vec<String> = pids.iter().copied().filter(|p| valid_pid(*p)).map(|p| p.to_string()).collect();
    if list.is_empty() {
        return Err("PID 无效".to_string());
    }
    let script = format!("n=0; for p in {}; do kill -{sig} \"$p\" 2>/dev/null && n=$((n+1)); done; echo $n", list.join(" "));
    ssh_run(target, &script)?.trim().parse::<usize>().map_err(|_| "远端返回异常".to_string())
}

pub fn set_nice(target: &SshTarget, pid: i32, nice: i32) -> Result<(), String> {
    if !valid_pid(pid) {
        return Err("PID 无效".to_string());
    }
    ssh_run(target, &format!("renice -n {} -p {pid}", nice.clamp(-20, 19))).map(|_| ())
}

pub fn read_cmdline(target: &SshTarget, pid: i32) -> Option<String> {
    if !valid_pid(pid) {
        return None;
    }
    let out = ssh_run(target, &format!("cat /proc/{pid}/cmdline 2>/dev/null")).ok()?;
    Some(procstats::format_cmdline(out.as_bytes()))
}

/// 远端进程详情（status / cmdline / exe / cwd / io 一次拉取）。
pub fn read_details(target: &SshTarget, pid: i32) -> Option<ProcDetails> {
    if !valid_pid(pid) {
        return None;
    }
    let script = format!(
        "echo '##st'; cat /proc/{pid}/status 2>/dev/null; echo '##cmd'; cat /proc/{pid}/cmdline 2>/dev/null; echo '##exe'; readlink /proc/{pid}/exe 2>/dev/null; echo '##cwd'; readlink /proc/{pid}/cwd 2>/dev/null; echo '##io'; cat /proc/{pid}/io 2>/dev/null"
    );
    let sec = sections(&ssh_run(target, &script).ok()?);
    let st = sec.get("st").map(|s| procstats::parse_status_detail(s)).unwrap_or_default();
    let cmdline = sec.get("cmd").map(|s| procstats::format_cmdline(s.as_bytes())).unwrap_or_default();
    let path_of = |key: &str| {
        sec.get(key)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "—".to_string())
    };
    let (io_r, io_w) = sec.get("io").map(|s| procstats::parse_proc_io(s)).unwrap_or((0, 0));
    Some(ProcDetails {
        uid: st.uid,
        gid: st.gid,
        threads: st.threads,
        vsize_kb: st.vsize_kb,
        rss_kb: st.rss_kb,
        cmdline,
        exe: path_of("exe"),
        cwd: path_of("cwd"),
        io_read_bytes: io_r,
        io_write_bytes: io_w,
    })
}

/// 用户 systemd 管理器（委派根）目录：user-<uid>.slice/user@<uid>.service。
pub fn user_service_path(uid: u32) -> String {
    format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service")
}

/// 远端可写的委派根。注意：SSH 会话本身在 `session-*.scope`，并不在 `user@uid.service`
/// 内，所以必须按 SSH 用户的 uid 推算 user@uid.service 并校验存在且可写。
pub fn cg_base(target: &SshTarget) -> Option<String> {
    let uid: u32 = ssh_sh(target, "id -u")?.trim().parse().ok()?;
    let base = user_service_path(uid);
    let ok = ssh_sh(target, &format!("[ -d '{base}' ] && [ -w '{base}' ] && echo OK"))
        .map(|s| s.contains("OK"))
        .unwrap_or(false);
    ok.then_some(base)
}

/// 建并准备容器 cm-sched（+cpu +pids）。
pub fn cg_ensure(target: &SshTarget, base: &str) -> bool {
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

pub fn cg_list(target: &SshTarget, base: &str) -> Vec<GroupState> {
    let c = format!("{base}/cm-sched");
    let script = format!(
        "cd '{c}' 2>/dev/null || exit 0; for d in */; do [ -d \"$d\" ] || continue; n=${{d%/}}; [ \"$n\" = default ] && continue; \
printf '%s|%s|%s|%s|%s\\n' \"$n\" \"$(cat \"$d/cpu.max\" 2>/dev/null)\" \"$(cat \"$d/cpu.weight\" 2>/dev/null)\" \"$(cat \"$d/pids.max\" 2>/dev/null)\" \"$(grep -c . \"$d/cgroup.procs\" 2>/dev/null)\"; done"
    );
    parse_group_lines(&ssh_sh(target, &script).unwrap_or_default())
}

fn safe_name(name: &str) -> bool {
    cgroup::valid_group_name(name)
}

pub fn cg_create(target: &SshTarget, base: &str, name: &str) -> bool {
    safe_name(name) && ssh_sh(target, &format!("mkdir '{base}/cm-sched/{name}'")).is_some()
}

pub fn cg_delete(target: &SshTarget, base: &str, name: &str) -> bool {
    safe_name(name) && ssh_sh(target, &format!("rmdir '{base}/cm-sched/{name}'")).is_some()
}

pub fn cg_set_cpu_max(target: &SshTarget, base: &str, name: &str, pct: Option<u32>) -> bool {
    if !safe_name(name) {
        return false;
    }
    let val = match pct {
        Some(p) if p > 0 => format!("{} 100000", p.saturating_mul(1000)),
        _ => "max 100000".to_string(),
    };
    ssh_sh(target, &format!("printf '{val}' > '{base}/cm-sched/{name}/cpu.max'")).is_some()
}

pub fn cg_set_weight(target: &SshTarget, base: &str, name: &str, w: u32) -> bool {
    safe_name(name) && ssh_sh(target, &format!("printf '{}' > '{base}/cm-sched/{name}/cpu.weight'", w.clamp(1, 10000))).is_some()
}

pub fn cg_set_pids(target: &SshTarget, base: &str, name: &str, max: Option<u32>) -> bool {
    if !safe_name(name) {
        return false;
    }
    let val = max.map(|m| m.max(1).to_string()).unwrap_or_else(|| "max".to_string());
    ssh_sh(target, &format!("printf '{val}' > '{base}/cm-sched/{name}/pids.max'")).is_some()
}

/// 迁入并返回原 cgroup 路径（形如 /user.slice/...），供还原。
pub fn cg_move_in(target: &SshTarget, base: &str, name: &str, pid: i32) -> Option<String> {
    if !safe_name(name) {
        return None;
    }
    let c = format!("{base}/cm-sched/{name}");
    let script = format!(
        "o=$(sed -n 's|^0::||p' /proc/{pid}/cgroup); printf '{pid}' > '{c}/cgroup.procs' && printf '%s' \"$o\""
    );
    ssh_sh(target, &script).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub fn cg_release(target: &SshTarget, original: &str, pid: i32) -> bool {
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
        let (v, errs) = parse_hosts_checked("# 注释\n pi@192.168.1.5 \n\nroot@kylin\n");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].as_str(), "pi@192.168.1.5");
        assert_eq!(v[1].as_str(), "root@kylin");
        assert!(errs.is_empty(), "合法清单不应有错误：{errs:?}");
        // 非法行必须报行号而不是被吞掉
        let (_, errs) = parse_hosts_checked("ok-host\n-Injected\n");
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].line_no, 2);
    }

    fn any_host() -> SshTarget {
        SshTarget::parse("no-such-host.invalid").unwrap()
    }

    #[test]
    fn remote_calls_have_deadline() {
        // 不可达主机 + 短超时：必须在 deadline 附近返回结构化错误
        let t = any_host();
        let limits = ExecLimits { timeout: Duration::from_millis(700), max_output: 64 * 1024 };
        let started = Instant::now();
        let r = ssh_exec(&t, "echo hi", &limits, None);
        let elapsed = started.elapsed();
        match r {
            Err(RemoteError::Timeout { .. }) | Err(RemoteError::Failed { .. }) => {}
            other => panic!("应超时/失败，实际 {other:?}"),
        }
        assert!(elapsed < Duration::from_secs(3), "超时应在 deadline+缓冲内返回，实际 {elapsed:?}");
    }

    #[test]
    fn ssh_exec_supports_cancel() {
        // 用不可路由地址保证命令在连接阶段悬挂，100ms 后取消必然生效
        let t = SshTarget::parse("user@10.255.255.1").unwrap();
        let cancel = Cancel::new();
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let started = Instant::now();
        let r = ssh_exec(&t, "echo hi", &ExecLimits { timeout: Duration::from_secs(30), max_output: 1024 }, Some(&cancel));
        assert!(matches!(r, Err(RemoteError::Cancelled { .. })), "应可取消，实际 {r:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "取消应及时返回");
    }

    #[test]
    fn ssh_exec_output_is_capped() {
        // 直接验证 reader 上限：读到 cap 即停并标记截断
        let truncated = Arc::new(AtomicBool::new(false));
        let h = spawn_reader(Some(std::io::Cursor::new(vec![b'y'; 1024])), 16, truncated.clone());
        let buf = h.join().unwrap();
        assert_eq!(buf.len(), 16);
        assert!(truncated.load(Ordering::Relaxed));
        // 小于上限的输入完整读取、不标记
        let truncated = Arc::new(AtomicBool::new(false));
        let h = spawn_reader(Some(std::io::Cursor::new(vec![b'y'; 8])), 16, truncated.clone());
        assert_eq!(h.join().unwrap().len(), 8);
        assert!(!truncated.load(Ordering::Relaxed));
    }

    #[test]
    fn remote_error_codes_are_classified() {
        assert_eq!(RemoteError::Failed { code: 255, stderr: "ssh: connect to host x port 22: Connection timed out".into() }.code(), "unreachable");
        assert_eq!(RemoteError::Failed { code: 255, stderr: "user@x: Permission denied (publickey).".into() }.code(), "auth");
        assert_eq!(RemoteError::Failed { code: 1, stderr: String::new() }.code(), "command");
        assert_eq!(RemoteError::Timeout { elapsed: Duration::from_secs(10) }.code(), "timeout");
        assert_eq!(RemoteError::Cancelled { elapsed: Duration::from_secs(1) }.code(), "cancelled");
    }

    fn blob(cpu_user: u64, cpu_idle: u64) -> String {
        format!(
            "##os\nUbuntu 26.04 LTS|ubuntu|1000\n##stat\ncpu0 {cpu_user} 0 0 {cpu_idle} 0 0 0 0\n##mem\nMemTotal: 8000 kB\nMemAvailable: 4000 kB\n##load\n0.5 0.4 0.3 1/100 1\n##up\n1000.0 0\n##df\nFilesystem 1024-blocks Used Available Capacity Mounted on\n/dev/nvme0n1p2 491240 300000 170000 64% /\n/dev/nvme0n1p1 1000 100 900 10% /boot/efi\ntmpfs 1000 1 999 1% /run\n##tcp\n  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1\n##ps\n1 0 init root 0 S 0.0 0.1 100 0\n42 1 busy user 1000 R 12.5 2.0 2048 5\n##end\n"
        )
    }

    #[test]
    fn parses_and_computes_delta() {
        let mut prev = None;
        let s1 = parse_output(&blob(100, 900), &mut prev).unwrap();
        assert_eq!(s1.usage.total_percent, 0.0); // 无前值
        assert_eq!(s1.usage.procs.len(), 2);
        assert_eq!(s1.usage.procs[0].comm, "busy"); // 按 CPU 排序
        assert_eq!(s1.usage.procs[0].uid, 1000);
        let s2 = parse_output(&blob(200, 1800), &mut prev).unwrap();
        // 两次差值：busy 100 / total 1000 = 10%
        assert!((s2.usage.total_percent - 10.0).abs() < 0.01);
        assert_eq!(s2.usage.mem.unwrap().total_kb, 8000);
        // 文件系统与连接：tmpfs 被过滤
        assert_eq!(s2.filesystems.len(), 2);
        assert_eq!(s2.filesystems[0].mount, "/");
        assert_eq!(s2.filesystems[0].avail_kb, 170000);
        assert_eq!(s2.conns.len(), 1);
        assert_eq!(s2.conns[0].state, "LISTEN");
        let r = s2.pi.remote.as_ref().unwrap();
        assert_eq!(r.os, "Ubuntu 26.04 LTS");
        assert_eq!(r.uid, 1000);
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
        let s = r.unwrap();
        assert!(!s.usage.procs.is_empty(), "应解析到进程列表");
        assert!(s.pi.remote.is_some(), "本机也应能读出 os-release");
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
    fn os_and_gpu_parse() {
        let r = parse_remote("Ubuntu 26.04 LTS|ubuntu|1000\n").unwrap();
        assert_eq!(r.os, "Ubuntu 26.04 LTS");
        assert_eq!(r.uid, 1000);
        let r = parse_remote("Debian GNU/Linux 13 (trixie)|debian\n").unwrap();
        assert_eq!(r.uid, 0);
        assert_eq!(parse_remote(""), None);

        let lspci = "01:00.0 VGA compatible controller: NVIDIA Corporation GK208B [GeForce GT 730] (rev a1)";
        assert_eq!(parse_gpu_model(lspci), Some("GeForce GT 730".to_string()));
        let amd = "03:00.0 VGA compatible controller: Advanced Micro Devices, Inc. [AMD/ATI] Navi 22 [Radeon RX 6700 XT] (rev c1)";
        assert_eq!(parse_gpu_model(amd), Some("Radeon RX 6700 XT".to_string()));
        let virt = "00:02.0 VGA compatible controller: Device 1234:1111";
        assert_eq!(parse_gpu_model(virt), Some("Device 1234:1111".to_string()));

        assert_eq!(parse_gpu(&format!("{lspci}\n47000\n")), (Some("GeForce GT 730".to_string()), Some(47.0)));
        assert_eq!(parse_gpu("47000\n"), (None, Some(47.0)));
        assert_eq!(parse_gpu(""), (None, None));
    }

    #[test]
    fn rapl_delta_to_watts() {
        let blob = |uj: u64| {
            format!(
                "##os\nUbuntu 26.04 LTS|ubuntu|0\n##stat\ncpu0 100 0 0 900 0 0 0 0\n##temp\n40000\n##freq\n3995661\n##rapl\n{uj}\n##gpu\n01:00.0 VGA compatible controller: NVIDIA Corporation GK208B [GeForce GT 730] (rev a1)\n47000\n##ps\n1 0 init root 0 S 0.0 0.1 100 0\n##end\n"
            )
        };
        let mut prev = None;
        let s1 = parse_output(&blob(1_000_000_000), &mut prev).unwrap();
        assert_eq!(s1.pi.power, None); // 首帧无差分
        assert_eq!(s1.pi.remote.as_ref().unwrap().os, "Ubuntu 26.04 LTS");
        assert_eq!(s1.pi.temp_c, Some(40.0));
        assert_eq!(s1.pi.gpu.model.as_deref(), Some("GeForce GT 730"));
        assert_eq!(s1.pi.gpu.temp_c, Some(47.0));
        assert!((s1.pi.freq_ghz.unwrap() - 3.995661).abs() < 0.001);

        // 让累计量与时间戳都落在上一帧前 2 秒：20 J / 2 s ≈ 10 W
        if let Some(c) = prev.as_mut() {
            c.rapl_uj = Some(1_000_000_000);
            c.at = Instant::now() - std::time::Duration::from_secs(2);
        }
        let s2 = parse_output(&blob(1_020_000_000), &mut prev).unwrap();
        let w = s2.pi.power.unwrap().core_w;
        assert!((w - 10.0).abs() < 1.0, "RAPL 差分应约 10W，实际 {w}");
        assert_eq!(s2.pi.power.unwrap().ext5v_v, 0.0);
    }

    #[test]
    fn remote_actions_reject_bad_pid() {
        // 非法 PID 在发 SSH 前即拒绝，不触碰网络
        let h = any_host();
        assert!(signal(&h, 1, 15).is_err());
        assert!(signal(&h, 0, 9).is_err());
        assert!(signal_many(&h, &[0, 1], 15).is_err());
        assert!(set_nice(&h, 1, 5).is_err());
        assert_eq!(read_cmdline(&h, 1), None);
        assert!(read_details(&h, 0).is_none());
    }

    #[test]
    fn live_host_smoke() {
        // 需显式指定在线主机才会执行：SM_LIVE_HOST=root@10.44.129.215 cargo test
        let Ok(host) = std::env::var("SM_LIVE_HOST") else {
            return;
        };
        let Ok(host) = SshTarget::parse(host.trim()) else {
            panic!("SM_LIVE_HOST 不是合法 SSH 目标");
        };
        let mut prev = None;
        let s = collect(&host, &mut prev).expect("远端采样应成功");
        assert!(s.pi.remote.is_some(), "应读到远端 os-release");
        assert!(!s.usage.procs.is_empty(), "应读到远端进程");
        assert!(!s.filesystems.is_empty(), "应读到远端文件系统");

        let out = ssh_run(&host, "setsid nohup sleep 30 >/dev/null 2>&1 & echo $!").unwrap();
        let pid: i32 = out.trim().parse().unwrap();
        let d = read_details(&host, pid).expect("远端详情应可读");
        assert!(d.cmdline.contains("sleep"), "cmdline 应为 sleep：{}", d.cmdline);
        set_nice(&host, pid, 5).expect("renice 应成功");
        signal(&host, pid, 15).expect("TERM 应送达");
        std::thread::sleep(std::time::Duration::from_millis(400));
        let alive = ssh_run(&host, &format!("test -d /proc/{pid} && echo alive || echo gone")).unwrap();
        assert!(alive.contains("gone"), "进程应已被结束");
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