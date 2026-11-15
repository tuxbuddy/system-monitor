use std::collections::HashMap;
use std::fs;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    pub fn total(self) -> u64 {
        self.user + self.nice + self.system + self.idle + self.iowait + self.irq + self.softirq + self.steal
    }

    pub fn busy(self) -> u64 {
        self.total() - self.idle - self.iowait
    }

    /// 解析 /proc/stat 的 cpu/cpuN 行；guest 字段已含在 user 中，忽略。
    pub fn parse(line: &str) -> Option<Self> {
        let mut it = line.split_whitespace();
        let label = it.next()?;
        if !label.starts_with("cpu") {
            return None;
        }
        let v: Vec<u64> = it.filter_map(|s| s.parse().ok()).take(8).collect();
        if v.len() < 8 {
            return None;
        }
        Some(Self {
            user: v[0], nice: v[1], system: v[2], idle: v[3],
            iowait: v[4], irq: v[5], softirq: v[6], steal: v[7],
        })
    }
}

#[derive(Clone, Debug)]
pub struct ProcSnapshot {
    pub pid: i32,
    pub comm: String,
    pub utime: u64,
    pub stime: u64,
    pub nice: i64,
    pub state: char,
    pub uid: u32,
    pub rss_kb: u64,
    pub ppid: i32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemInfo {
    pub total_kb: u64,
    pub available_kb: u64,
    pub free_kb: u64,
    pub buffers_kb: u64,
    pub cached_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

impl MemInfo {
    pub fn used_kb(self) -> u64 {
        self.total_kb.saturating_sub(self.available_kb)
    }
    pub fn swap_used_kb(self) -> u64 {
        self.swap_total_kb.saturating_sub(self.swap_free_kb)
    }
}

/// 解析 /proc/meminfo；缺 MemTotal 或 MemAvailable → None，其余字段缺省 0。
pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut m = MemInfo::default();
    let mut have_total = false;
    let mut have_avail = false;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let key = it.next().unwrap_or("");
        let Some(v) = it.next().and_then(|s| s.parse::<u64>().ok()) else { continue };
        match key {
            "MemTotal:" => { m.total_kb = v; have_total = true; }
            "MemAvailable:" => { m.available_kb = v; have_avail = true; }
            "MemFree:" => m.free_kb = v,
            "Buffers:" => m.buffers_kb = v,
            "Cached:" => m.cached_kb = v,
            "SwapTotal:" => m.swap_total_kb = v,
            "SwapFree:" => m.swap_free_kb = v,
            _ => {}
        }
    }
    if have_total && have_avail { Some(m) } else { None }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LoadAvg {
    pub one: f32,
    pub five: f32,
    pub fifteen: f32,
}

pub fn parse_loadavg(text: &str) -> Option<LoadAvg> {
    let mut it = text.split_whitespace();
    let one = it.next()?.parse().ok()?;
    let five = it.next()?.parse().ok()?;
    let fifteen = it.next()?.parse().ok()?;
    Some(LoadAvg { one, five, fifteen })
}

pub fn parse_uptime(text: &str) -> Option<u64> {
    let secs: f64 = text.split_whitespace().next()?.parse().ok()?;
    Some(secs.floor() as u64)
}

pub fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if days > 0 {
        format!("{days}天{hours}小时")
    } else if hours > 0 {
        format!("{hours}小时{mins}分")
    } else if mins > 0 {
        format!("{mins}分{s}秒")
    } else {
        format!("{s}秒")
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StatusFields {
    pub uid: Option<u32>,
    pub rss_kb: u64,
}

pub fn parse_status(text: &str) -> StatusFields {
    let mut f = StatusFields::default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            f.uid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            f.rss_kb = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }
    f
}

pub fn read_status(pid: i32) -> StatusFields {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .map(|s| parse_status(&s))
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StatusDetail {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub threads: u64,
    pub vsize_kb: u64,
    pub rss_kb: u64,
}

pub fn parse_status_detail(text: &str) -> StatusDetail {
    let mut d = StatusDetail::default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            d.uid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            d.gid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
        } else if let Some(rest) = line.strip_prefix("Threads:") {
            d.threads = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmSize:") {
            d.vsize_kb = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            d.rss_kb = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }
    d
}

#[derive(Clone, Debug, Default)]
pub struct ProcDetails {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub threads: u64,
    pub vsize_kb: u64,
    pub rss_kb: u64,
    pub cmdline: String,
    pub exe: String,
    pub cwd: String,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
}

/// 按需读取某个进程的详细信息（供详情弹窗用）。
pub fn read_details(pid: i32) -> ProcDetails {
    let d = fs::read_to_string(format!("/proc/{pid}/status"))
        .map(|s| parse_status_detail(&s))
        .unwrap_or_default();
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "—".to_string());
    let cwd = fs::read_link(format!("/proc/{pid}/cwd"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "—".to_string());
    let (io_read_bytes, io_write_bytes) = fs::read_to_string(format!("/proc/{pid}/io"))
        .map(|s| parse_proc_io(&s))
        .unwrap_or((0, 0));
    ProcDetails {
        uid: d.uid,
        gid: d.gid,
        threads: d.threads,
        vsize_kb: d.vsize_kb,
        rss_kb: d.rss_kb,
        cmdline: read_cmdline(pid),
        exe,
        cwd,
        io_read_bytes,
        io_write_bytes,
    }
}

#[derive(Clone, Debug)]
pub struct NetConn {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub uid: u32,
}

fn decode_addr(hex: &str) -> String {
    let Some((ip, port)) = hex.split_once(':') else {
        return hex.to_string();
    };
    let port = u16::from_str_radix(port, 16).unwrap_or(0);
    if ip.len() == 8 {
        let v = u32::from_str_radix(ip, 16).unwrap_or(0);
        format!("{}.{}.{}.{}:{}", v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff, port)
    } else if ip.len() == 32 {
        format!("[v6]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn tcp_state(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "?",
    }
}

pub fn parse_proc_net(text: &str, proto: &str) -> Vec<NetConn> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        out.push(NetConn {
            proto: proto.to_string(),
            local: decode_addr(f[1]),
            remote: decode_addr(f[2]),
            state: tcp_state(f[3]).to_string(),
            uid: f[7].parse().unwrap_or(0),
        });
    }
    out
}

pub fn read_net_conns() -> Vec<NetConn> {
    let mut out = Vec::new();
    for (path, proto) in [
        ("/proc/net/tcp", "TCP"),
        ("/proc/net/tcp6", "TCP6"),
        ("/proc/net/udp", "UDP"),
        ("/proc/net/udp6", "UDP6"),
    ] {
        if let Ok(text) = fs::read_to_string(path) {
            out.extend(parse_proc_net(&text, proto));
        }
    }
    out
}

pub fn format_cmdline(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace('\0', " ").trim().to_string()
}

pub fn read_cmdline(pid: i32) -> String {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| format_cmdline(&b))
        .unwrap_or_default()
}

fn is_whole_disk(name: &str) -> bool {
    if name.starts_with("nvme") {
        return !name.contains('p');
    }
    if name.starts_with("mmcblk") {
        return !name.contains('p');
    }
    if let Some(rest) = name.strip_prefix("sd") {
        return rest.len() == 1;
    }
    if let Some(rest) = name.strip_prefix("vd") {
        return rest.len() == 1;
    }
    if let Some(rest) = name.strip_prefix("hd") {
        return rest.len() == 1;
    }
    false
}

/// 汇总 /proc/diskstats 整盘累计读写字节（扇区×512）。跳过分区与 loop/ram。
pub fn parse_diskstats(text: &str) -> Option<(u64, u64)> {
    let mut read_bytes = 0u64;
    let mut write_bytes = 0u64;
    let mut any = false;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        if !is_whole_disk(f[2]) {
            continue;
        }
        let Some(sectors_read) = f[5].parse::<u64>().ok() else {
            continue;
        };
        let Some(sectors_written) = f[9].parse::<u64>().ok() else {
            continue;
        };
        read_bytes += sectors_read.saturating_mul(512);
        write_bytes += sectors_written.saturating_mul(512);
        any = true;
    }
    any.then_some((read_bytes, write_bytes))
}

/// 汇总 /proc/net/dev 各物理接口累计收发字节（排除 lo）。
pub fn parse_netdev(text: &str) -> Option<(u64, u64)> {
    let mut rx = 0u64;
    let mut tx = 0u64;
    let mut any = false;
    for line in text.lines() {
        let Some((iface, rest)) = line.split_once(':') else {
            continue;
        };
        let name = iface.trim();
        if name.is_empty() || name == "lo" {
            continue;
        }
        let nums: Vec<u64> = rest.split_whitespace().filter_map(|s| s.parse().ok()).collect();
        if nums.len() < 9 {
            continue;
        }
        rx += nums[0];
        tx += nums[8];
        any = true;
    }
    any.then_some((rx, tx))
}

/// 解析 /proc/<pid>/io 的累计读写字节。
pub fn parse_proc_io(text: &str) -> (u64, u64) {
    let mut read_bytes = 0u64;
    let mut write_bytes = 0u64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("read_bytes:") {
            read_bytes = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("write_bytes:") {
            write_bytes = rest.trim().parse().unwrap_or(0);
        }
    }
    (read_bytes, write_bytes)
}

#[derive(Clone, Debug)]
pub struct FsUsage {
    pub source: String,
    pub mount: String,
    pub total_kb: u64,
    pub avail_kb: u64,
}

impl FsUsage {
    pub fn used_kb(&self) -> u64 {
        self.total_kb.saturating_sub(self.avail_kb)
    }
    pub fn used_frac(&self) -> f32 {
        if self.total_kb == 0 {
            0.0
        } else {
            (self.used_kb() as f32 / self.total_kb as f32).clamp(0.0, 1.0)
        }
    }
}

/// 从 /proc/mounts 提取真实块设备挂载（只保留常见文件系统类型）。
pub fn parse_mounts(text: &str) -> Vec<(String, String, String)> {
    const KEEP: &[&str] = &[
        "ext2", "ext3", "ext4", "btrfs", "vfat", "exfat", "ntfs", "ntfs3", "f2fs", "xfs", "overlay",
        "squashfs",
    ];
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(src), Some(mnt), Some(fst)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if KEEP.contains(&fst) {
            out.push((src.to_string(), mnt.to_string(), fst.to_string()));
        }
    }
    out
}

fn statvfs_kb(mount: &str) -> Option<(u64, u64)> {
    let c = std::ffi::CString::new(mount.as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let fr = st.f_frsize as u64;
    let total = (st.f_blocks as u64).saturating_mul(fr) / 1024;
    let avail = (st.f_bavail as u64).saturating_mul(fr) / 1024;
    Some((total, avail))
}

pub fn read_filesystems() -> Vec<FsUsage> {
    let Ok(text) = fs::read_to_string("/proc/mounts") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (source, mount, _fst) in parse_mounts(&text) {
        if let Some((total_kb, avail_kb)) = statvfs_kb(&mount)
            && total_kb > 0
        {
            out.push(FsUsage { source, mount, total_kb, avail_kb });
        }
    }
    out
}

/// 解析 /proc/<pid>/stat 行。comm 可含空格/括号，用首个 '(' 与最后一个 ')' 定位。
pub fn parse_proc_stat(line: &str) -> Option<ProcSnapshot> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close < open {
        return None;
    }
    let pid: i32 = line[..open].trim().parse().ok()?;
    let comm = line[open + 1..close].to_string();
    let rest: Vec<&str> = line[close + 1..].split_whitespace().collect();
    // rest[0]=state(第3列) rest[11]=utime(14) rest[12]=stime(15) rest[16]=nice(19)
    if rest.len() < 17 {
        return None;
    }
    Some(ProcSnapshot {
        pid,
        comm,
        state: rest[0].chars().next()?,
        utime: rest[11].parse().ok()?,
        stime: rest[12].parse().ok()?,
        nice: rest[16].parse().ok()?,
        uid: 0,
        rss_kb: 0,
        ppid: rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(0),
    })
}

#[derive(Clone, Debug, Default)]
pub struct SystemSnapshot {
    pub cores: Vec<CpuTimes>,
    pub procs: Vec<ProcSnapshot>,
    pub mem: Option<MemInfo>,
    pub load: Option<LoadAvg>,
    pub uptime_secs: Option<u64>,
    pub disk: Option<(u64, u64)>,
    pub net: Option<(u64, u64)>,
}

pub fn read_snapshot() -> SystemSnapshot {
    let mut snap = SystemSnapshot::default();
    if let Ok(stat) = fs::read_to_string("/proc/stat") {
        for line in stat.lines() {
            // 只要 cpu0..cpuN 行，跳过聚合 "cpu " 行
            if line.starts_with("cpu") && !line.starts_with("cpu ")
                && let Some(t) = CpuTimes::parse(line)
            {
                snap.cores.push(t);
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some(mut p) = parse_proc_stat(&stat) else {
                continue;
            };
            let st = read_status(pid);
            p.uid = st.uid.unwrap_or(u32::MAX);
            p.rss_kb = st.rss_kb;
            snap.procs.push(p);
        }
    }
    snap.mem = fs::read_to_string("/proc/meminfo").ok().and_then(|s| parse_meminfo(&s));
    snap.load = fs::read_to_string("/proc/loadavg").ok().and_then(|s| parse_loadavg(&s));
    snap.uptime_secs = fs::read_to_string("/proc/uptime").ok().and_then(|s| parse_uptime(&s));
    snap.disk = fs::read_to_string("/proc/diskstats").ok().and_then(|s| parse_diskstats(&s));
    snap.net = fs::read_to_string("/proc/net/dev").ok().and_then(|s| parse_netdev(&s));
    snap
}

#[derive(Clone, Debug)]
pub struct ProcUsage {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub comm: String,
    pub user: String,
    pub cpu_percent: f32,
    pub nice: i64,
    pub state: char,
    pub rss_kb: u64,
    pub mem_percent: f32,
}

#[derive(Clone, Debug, Default)]
pub struct Usage {
    pub total_percent: f32,
    pub core_percent: Vec<f32>,
    pub procs: Vec<ProcUsage>,
    pub mem: Option<MemInfo>,
    pub load: Option<LoadAvg>,
    pub uptime_secs: Option<u64>,
    pub disk_read_bps: f32,
    pub disk_write_bps: f32,
    pub net_rx_bps: f32,
    pub net_tx_bps: f32,
}

fn pct(busy_delta: u64, total_delta: u64) -> f32 {
    if total_delta == 0 {
        0.0
    } else {
        busy_delta as f32 / total_delta as f32 * 100.0
    }
}

/// 纯函数：两次快照差值 → 占用率。users 缺省时回退为 uid 字符串。
pub fn compute(
    prev: &SystemSnapshot,
    curr: &SystemSnapshot,
    users: &HashMap<u32, String>,
) -> Usage {
    let n = curr.cores.len().max(1);
    let prev_total: u64 = prev.cores.iter().map(|c| c.total()).sum();
    let curr_total: u64 = curr.cores.iter().map(|c| c.total()).sum();
    let prev_busy: u64 = prev.cores.iter().map(|c| c.busy()).sum();
    let curr_busy: u64 = curr.cores.iter().map(|c| c.busy()).sum();
    let total_delta = curr_total.saturating_sub(prev_total);
    let total_percent = pct(curr_busy.saturating_sub(prev_busy), total_delta);
    let core_percent = curr
        .cores
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let p = prev.cores.get(i).copied().unwrap_or_default();
            pct(c.busy().saturating_sub(p.busy()), c.total().saturating_sub(p.total()))
        })
        .collect();
    let mem_total_kb = curr.mem.map(|m| m.total_kb).unwrap_or(0);
    let prev_map: HashMap<i32, &ProcSnapshot> = prev.procs.iter().map(|p| (p.pid, p)).collect();
    let mut procs: Vec<ProcUsage> = curr
        .procs
        .iter()
        .map(|p| {
            let cpu = match prev_map.get(&p.pid) {
                Some(old) => {
                    let d = (p.utime + p.stime).saturating_sub(old.utime + old.stime);
                    if total_delta == 0 {
                        0.0
                    } else {
                        d as f32 / total_delta as f32 * n as f32 * 100.0
                    }
                }
                None => 0.0,
            };
            let mem_percent = if mem_total_kb == 0 {
                0.0
            } else {
                p.rss_kb as f32 / mem_total_kb as f32 * 100.0
            };
            ProcUsage {
                pid: p.pid,
                ppid: p.ppid,
                uid: p.uid,
                comm: p.comm.clone(),
                user: users.get(&p.uid).cloned().unwrap_or_else(|| p.uid.to_string()),
                cpu_percent: cpu,
                nice: p.nice,
                state: p.state,
                rss_kb: p.rss_kb,
                mem_percent,
            }
        })
        .collect();
    procs.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
    Usage {
        total_percent,
        core_percent,
        procs,
        mem: curr.mem,
        load: curr.load,
        uptime_secs: curr.uptime_secs,
        disk_read_bps: 0.0,
        disk_write_bps: 0.0,
        net_rx_bps: 0.0,
        net_tx_bps: 0.0,
    }
}

/// 纯函数：按 (pid, ppid) 序列构建 DFS 树序，返回 (原索引, 深度)。
/// 输入序列的顺序即同级顺序；父 pid 不在集合内的视为根；自指/环有 visited 保护。
pub fn tree_order(items: &[(i32, i32)]) -> Vec<(usize, u16)> {
    let n = items.len();
    let index_of: HashMap<i32, usize> = items.iter().enumerate().map(|(i, (pid, _))| (*pid, i)).collect();
    let mut children: HashMap<i32, Vec<usize>> = HashMap::new();
    let mut roots: Vec<usize> = Vec::new();
    for (i, (pid, ppid)) in items.iter().enumerate() {
        if *ppid != *pid && index_of.contains_key(ppid) {
            children.entry(*ppid).or_default().push(i);
        } else {
            roots.push(i);
        }
    }
    fn dfs(
        i: usize,
        depth: u16,
        items: &[(i32, i32)],
        children: &HashMap<i32, Vec<usize>>,
        visited: &mut [bool],
        out: &mut Vec<(usize, u16)>,
    ) {
        if visited[i] {
            return;
        }
        visited[i] = true;
        out.push((i, depth));
        if let Some(kids) = children.get(&items[i].0) {
            for &k in kids {
                dfs(k, depth + 1, items, children, visited, out);
            }
        }
    }
    let mut out = Vec::with_capacity(n);
    let mut visited = vec![false; n];
    for &r in &roots {
        dfs(r, 0, items, &children, &mut visited, &mut out);
    }
    for i in 0..n {
        if !visited[i] {
            dfs(i, 0, items, &children, &mut visited, &mut out);
        }
    }
    out
}

/// 扫描 /proc 得到 (pid, ppid) 列表（仅供结束进程树等动作按需调用）。
pub fn read_pid_pairs() -> Vec<(i32, i32)> {
    let mut pairs = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for e in entries.flatten() {
            if e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()).is_none() {
                continue;
            }
            if let Ok(stat) = fs::read_to_string(e.path().join("stat"))
                && let Some(p) = parse_proc_stat(&stat)
            {
                pairs.push((p.pid, p.ppid));
            }
        }
    }
    pairs
}

/// 纯函数：返回 root 的所有后代 pid（不含 root），带 visited 防环。
pub fn descendants(root: i32, pairs: &[(i32, i32)]) -> Vec<i32> {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for &(pid, ppid) in pairs {
        children.entry(ppid).or_default().push(pid);
    }
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<i32> = std::collections::HashSet::new();
    let mut st = vec![root];
    while let Some(pid) = st.pop() {
        if let Some(kids) = children.get(&pid) {
            for &k in kids {
                if seen.insert(k) {
                    out.push(k);
                    st.push(k);
                }
            }
        }
    }
    out
}

/// 纯函数：把进程树按「应用（根+全部后代）」聚合，CPU/内存求和，进程数并入名称。
pub fn app_groups(procs: &[ProcUsage]) -> Vec<ProcUsage> {
    let index_of: HashMap<i32, usize> = procs.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
    let mut children: HashMap<i32, Vec<usize>> = HashMap::new();
    let mut roots: Vec<usize> = Vec::new();
    for (i, p) in procs.iter().enumerate() {
        if p.ppid != p.pid && index_of.contains_key(&p.ppid) {
            children.entry(p.ppid).or_default().push(i);
        } else {
            roots.push(i);
        }
    }
    let mut out = Vec::new();
    for &r in &roots {
        let mut visited = vec![false; procs.len()];
        let mut st = vec![r];
        let mut cpu = 0.0f32;
        let mut rss = 0u64;
        let mut mem = 0.0f32;
        let mut n = 0usize;
        while let Some(i) = st.pop() {
            if visited[i] {
                continue;
            }
            visited[i] = true;
            let p = &procs[i];
            cpu += p.cpu_percent;
            rss += p.rss_kb;
            mem += p.mem_percent;
            n += 1;
            if let Some(kids) = children.get(&p.pid) {
                for &k in kids {
                    st.push(k);
                }
            }
        }
        let root = &procs[r];
        let comm = if n > 1 {
            format!("{}（{} 进程）", root.comm, n)
        } else {
            root.comm.clone()
        };
        out.push(ProcUsage {
            pid: root.pid,
            ppid: root.ppid,
            uid: root.uid,
            comm,
            user: root.user.clone(),
            cpu_percent: cpu,
            nice: root.nice,
            state: root.state,
            rss_kb: rss,
            mem_percent: mem,
        });
    }
    out.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
    out
}

pub fn username(uid: u32) -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}

pub struct Sampler {
    prev: Option<SystemSnapshot>,
    prev_at: Instant,
}

impl Sampler {
    pub fn new() -> Self {
        Self { prev: None, prev_at: Instant::now() }
    }

    pub fn sample(&mut self) -> Usage {
        // 首次采样 prev=curr 克隆，差值全 0，自然显示 0%
        let curr = read_snapshot();
        let prev = self.prev.replace(curr.clone()).unwrap_or_else(|| curr.clone());
        let elapsed = self.prev_at.elapsed().as_secs_f64();
        self.prev_at = Instant::now();
        let mut users: HashMap<u32, String> = HashMap::new();
        for p in &curr.procs {
            users.entry(p.uid).or_insert_with(|| username(p.uid));
        }
        let mut usage = compute(&prev, &curr, &users);
        let secs = if elapsed > 0.05 { elapsed as f32 } else { 0.0 };
        let rate = |p: Option<(u64, u64)>, c: Option<(u64, u64)>, idx: usize| -> f32 {
            match (p, c) {
                (Some(p), Some(c)) if secs > 0.0 => {
                    let a = [p.0, p.1][idx];
                    let b = [c.0, c.1][idx];
                    if b >= a {
                        (b - a) as f32 / secs
                    } else {
                        0.0
                    }
                }
                _ => 0.0,
            }
        };
        usage.disk_read_bps = rate(prev.disk, curr.disk, 0);
        usage.disk_write_bps = rate(prev.disk, curr.disk, 1);
        usage.net_rx_bps = rate(prev.net, curr.net, 0);
        usage.net_tx_bps = rate(prev.net, curr.net, 1);
        usage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_line() {
        let t = CpuTimes::parse("cpu0 100 20 30 400 50 6 7 8 0 0").unwrap();
        assert_eq!(t.total(), 621);
        assert_eq!(t.busy(), 171);
        assert!(CpuTimes::parse("intr 123 456").is_none());
        assert!(CpuTimes::parse("cpu0 1 2 3").is_none());
    }

    fn stat_line(pid: i32, comm: &str, state: &str, utime: u64, stime: u64, nice: i64) -> String {
        let mut rest: Vec<String> = (0..24).map(|_| "0".to_string()).collect();
        rest[0] = state.to_string();
        rest[11] = utime.to_string();
        rest[12] = stime.to_string();
        rest[16] = nice.to_string();
        format!("{pid} ({comm}) {}", rest.join(" "))
    }

    #[test]
    fn parse_proc_stat_tricky_comm() {
        let line = stat_line(123, "my (proc) name", "S", 500, 250, 5);
        let p = parse_proc_stat(&line).unwrap();
        assert_eq!(p.pid, 123);
        assert_eq!(p.comm, "my (proc) name");
        assert_eq!(p.state, 'S');
        assert_eq!(p.utime, 500);
        assert_eq!(p.stime, 250);
        assert_eq!(p.nice, 5);
        assert!(parse_proc_stat("garbage").is_none());
    }

    fn snap(cores: Vec<CpuTimes>, procs: Vec<ProcSnapshot>) -> SystemSnapshot {
        SystemSnapshot { cores, procs, ..Default::default() }
    }

    fn proc(pid: i32, utime: u64, stime: u64) -> ProcSnapshot {
        ProcSnapshot { pid, comm: format!("p{pid}"), utime, stime, nice: 0, state: 'S', uid: 1000, rss_kb: 0, ppid: 0 }
    }

    #[test]
    fn compute_percentages() {
        let prev = snap(
            vec![CpuTimes { user: 100, system: 100, idle: 800, ..Default::default() }],
            vec![proc(1, 60, 40)],
        );
        let curr = snap(
            vec![CpuTimes { user: 200, system: 200, idle: 1600, ..Default::default() }],
            vec![proc(1, 180, 120)],
        );
        // total 1000→2000，busy 200→400 → 20%；进程 Δ300-100=200 /1000 ×1核 ×100 = 20%
        let u = compute(&prev, &curr, &HashMap::new());
        assert!((u.total_percent - 20.0).abs() < 0.01);
        assert!((u.core_percent[0] - 20.0).abs() < 0.01);
        assert_eq!(u.procs.len(), 1);
        assert!((u.procs[0].cpu_percent - 20.0).abs() < 0.01);
        assert_eq!(u.procs[0].user, "1000");
    }

    #[test]
    fn compute_multicore_new_and_gone_procs() {
        let prev = snap(
            vec![
                CpuTimes { user: 100, idle: 900, ..Default::default() },
                CpuTimes { user: 100, idle: 900, ..Default::default() },
            ],
            vec![proc(1, 100, 0), proc(2, 0, 0)],
        );
        let curr = snap(
            vec![
                CpuTimes { user: 200, idle: 1800, ..Default::default() },
                CpuTimes { user: 100, idle: 1900, ..Default::default() },
            ],
            vec![proc(1, 300, 0), proc(3, 50, 0)],
        );
        // 总 2000→4000，busy 200→300 → 5%；进程1 Δ200/2000×2×100=20%；新进程3=0；进程2消失
        let u = compute(&prev, &curr, &HashMap::new());
        assert!((u.total_percent - 5.0).abs() < 0.01);
        assert!((u.core_percent[0] - 10.0).abs() < 0.01);
        assert_eq!(u.core_percent[1], 0.0);
        assert_eq!(u.procs.len(), 2);
        assert_eq!(u.procs[0].pid, 1);
        assert!((u.procs[0].cpu_percent - 20.0).abs() < 0.01);
        assert_eq!(u.procs[1].pid, 3);
        assert_eq!(u.procs[1].cpu_percent, 0.0);
    }

    #[test]
    fn compute_zero_delta() {
        let s = snap(
            vec![CpuTimes { user: 100, idle: 900, ..Default::default() }],
            vec![proc(1, 10, 5)],
        );
        let u = compute(&s, &s, &HashMap::new());
        assert_eq!(u.total_percent, 0.0);
        assert_eq!(u.procs[0].cpu_percent, 0.0);
    }

    #[test]
    fn parse_meminfo_ok_and_missing() {
        let text = "MemTotal:       8000000 kB\nMemFree:  1000000 kB\nMemAvailable:   3000000 kB\nBuffers:  200000 kB\n";
        let m = parse_meminfo(text).unwrap();
        assert_eq!(m.total_kb, 8000000);
        assert_eq!(m.available_kb, 3000000);
        assert_eq!(m.used_kb(), 5000000);
        assert!(parse_meminfo("MemTotal: 8000000 kB\n").is_none());
        assert!(parse_meminfo("garbage").is_none());
    }

    #[test]
    fn parse_loadavg_ok_and_garbage() {
        let l = parse_loadavg("0.52 0.48 0.45 1/234 5678\n").unwrap();
        assert!((l.one - 0.52).abs() < 1e-6);
        assert!((l.five - 0.48).abs() < 1e-6);
        assert!((l.fifteen - 0.45).abs() < 1e-6);
        assert!(parse_loadavg("0.5 0.4").is_none());
        assert!(parse_loadavg("garbage").is_none());
    }

    #[test]
    fn parse_uptime_ok_and_garbage() {
        assert_eq!(parse_uptime("12345.67 23456.78\n"), Some(12345));
        assert_eq!(parse_uptime("garbage"), None);
    }

    #[test]
    fn format_uptime_buckets() {
        assert_eq!(format_uptime(90061), "1天1小时");
        assert_eq!(format_uptime(3661), "1小时1分");
        assert_eq!(format_uptime(61), "1分1秒");
        assert_eq!(format_uptime(45), "45秒");
        assert_eq!(format_uptime(0), "0秒");
    }

    #[test]
    fn parse_status_uid_rss() {
        let text = "Name:\tsleep\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t  2048 kB\n";
        let f = parse_status(text);
        assert_eq!(f.uid, Some(1000));
        assert_eq!(f.rss_kb, 2048);
        let no_rss = parse_status("Uid:\t0\t0\t0\t0\n");
        assert_eq!(no_rss.uid, Some(0));
        assert_eq!(no_rss.rss_kb, 0);
        let g = parse_status("garbage");
        assert_eq!(g.uid, None);
        assert_eq!(g.rss_kb, 0);
    }

    #[test]
    fn format_cmdline_cases() {
        assert_eq!(format_cmdline(b"sleep\x0030\0"), "sleep 30");
        assert_eq!(format_cmdline(b""), "");
        assert_eq!(format_cmdline(b"\0\0"), "");
        assert_eq!(format_cmdline(b"/usr/bin/app\0--flag\0"), "/usr/bin/app --flag");
    }

    #[test]
    fn compute_irix_over_100_percent() {
        // 既有行为表征测试（终审遗留建议）：2 核各 total 1000→2000（Δ总 2000），
        // 进程 Δ2000 → 2000/2000×2×100 = 200%。预期直接通过，非 RED。
        let prev = snap(
            vec![
                CpuTimes { user: 500, idle: 500, ..Default::default() },
                CpuTimes { user: 500, idle: 500, ..Default::default() },
            ],
            vec![proc(1, 0, 0)],
        );
        let curr = snap(
            vec![
                CpuTimes { user: 1500, idle: 500, ..Default::default() },
                CpuTimes { user: 1500, idle: 500, ..Default::default() },
            ],
            vec![proc(1, 1200, 800)],
        );
        let u = compute(&prev, &curr, &HashMap::new());
        assert!((u.procs[0].cpu_percent - 200.0).abs() < 0.01);
    }

    #[test]
    fn compute_passthrough_mem_load_uptime_rss() {
        let mut prev = snap(vec![CpuTimes { user: 100, idle: 900, ..Default::default() }], vec![proc(1, 0, 0)]);
        let mut curr = snap(vec![CpuTimes { user: 200, idle: 1800, ..Default::default() }], vec![proc(1, 10, 0)]);
        curr.procs[0].rss_kb = 4096;
        curr.mem = Some(MemInfo { total_kb: 8000000, available_kb: 3000000, ..Default::default() });
        curr.load = Some(LoadAvg { one: 0.5, five: 0.4, fifteen: 0.3 });
        curr.uptime_secs = Some(12345);
        prev.mem = Some(MemInfo { total_kb: 8000000, available_kb: 4000000, ..Default::default() });
        let u = compute(&prev, &curr, &HashMap::new());
        assert_eq!(u.procs[0].rss_kb, 4096);
        assert_eq!(u.mem.unwrap().used_kb(), 5000000); // 取 curr 而非 prev
        assert!((u.load.unwrap().one - 0.5).abs() < 1e-6);
        assert_eq!(u.uptime_secs, Some(12345));
    }

    #[test]
    fn parse_meminfo_full_fields() {
        let text = "MemTotal:       8000000 kB\nMemFree:  1000000 kB\nMemAvailable:   3000000 kB\nBuffers:  200000 kB\nCached:   1500000 kB\nSwapCached: 0 kB\nSwapTotal: 2000000 kB\nSwapFree: 1500000 kB\n";
        let m = parse_meminfo(text).unwrap();
        assert_eq!(m.free_kb, 1000000);
        assert_eq!(m.buffers_kb, 200000);
        assert_eq!(m.cached_kb, 1500000);
        assert_eq!(m.swap_total_kb, 2000000);
        assert_eq!(m.swap_free_kb, 1500000);
        assert_eq!(m.swap_used_kb(), 500000);
    }

    #[test]
    fn compute_mem_percent() {
        let mut curr = snap(vec![CpuTimes { user: 100, idle: 900, ..Default::default() }], vec![proc(1, 0, 0)]);
        curr.procs[0].rss_kb = 800000;
        curr.mem = Some(MemInfo { total_kb: 8000000, available_kb: 3000000, ..Default::default() });
        let prev = curr.clone();
        let u = compute(&prev, &curr, &HashMap::new());
        assert!((u.procs[0].mem_percent - 10.0).abs() < 0.01);

        let mut curr0 = snap(vec![CpuTimes { user: 100, idle: 900, ..Default::default() }], vec![proc(1, 0, 0)]);
        curr0.procs[0].rss_kb = 800000;
        curr0.mem = Some(MemInfo::default());
        let u0 = compute(&curr0.clone(), &curr0, &HashMap::new());
        assert_eq!(u0.procs[0].mem_percent, 0.0);
    }

    #[test]
    fn parse_status_detail_fields() {
        let text = "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nThreads:\t5\nVmSize:\t  204800 kB\nVmRSS:\t  4096 kB\n";
        let d = parse_status_detail(text);
        assert_eq!(d.uid, Some(1000));
        assert_eq!(d.gid, Some(1000));
        assert_eq!(d.threads, 5);
        assert_eq!(d.vsize_kb, 204800);
        assert_eq!(d.rss_kb, 4096);
    }

    #[test]
    fn tree_order_nests_children() {
        // 1 -> 2 -> 4, 3；索引: 0=1,1=2,2=3,3=4
        let items = [(1, 0), (2, 1), (3, 1), (4, 2)];
        assert_eq!(tree_order(&items), vec![(0, 0), (1, 1), (3, 2), (2, 1)]);
    }

    #[test]
    fn tree_order_orphans_and_roots() {
        assert_eq!(tree_order(&[(10, 999)]), vec![(0, 0)]);
        assert_eq!(tree_order(&[(1, 0), (2, 0)]), vec![(0, 0), (1, 0)]);
        assert!(tree_order(&[]).is_empty());
    }

    #[test]
    fn tree_order_self_parent_is_root() {
        assert_eq!(tree_order(&[(7, 7)]), vec![(0, 0)]);
    }

    #[test]
    fn proc_stat_parses_ppid() {
        let mut rest: Vec<String> = (0..24).map(|_| "0".to_string()).collect();
        rest[0] = "S".into();
        rest[1] = "42".into(); // ppid
        rest[11] = "1".into();
        rest[12] = "2".into();
        rest[16] = "0".into();
        let line = format!("100 (x) {}", rest.join(" "));
        let p = parse_proc_stat(&line).unwrap();
        assert_eq!(p.ppid, 42);
    }

    #[test]
    fn parse_diskstats_whole_disks_only() {
        let text = "\
 179       0 mmcblk0 100 0 2000 0 50 0 1000 0 0 0 0
 179       1 mmcblk0p1 90 0 1800 0 40 0 900 0 0 0 0
   7       0 loop0 5 0 500 0 0 0 0 0 0 0 0
";
        let (r, w) = parse_diskstats(text).unwrap();
        assert_eq!(r, 2000 * 512);
        assert_eq!(w, 1000 * 512);
        assert!(parse_diskstats("garbage").is_none());
    }

    #[test]
    fn parse_netdev_excludes_loopback() {
        let text = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n  eth0: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0\n";
        let (rx, tx) = parse_netdev(text).unwrap();
        assert_eq!(rx, 5000);
        assert_eq!(tx, 7000);
    }

    #[test]
    fn parse_proc_io_bytes() {
        let text = "rchar: 100\nwchar: 200\nread_bytes: 4096\nwrite_bytes: 8192\n";
        assert_eq!(parse_proc_io(text), (4096, 8192));
        assert_eq!(parse_proc_io("garbage"), (0, 0));
    }

    #[test]
    fn parse_mounts_keeps_real_fs() {
        let text = "/dev/mmcblk0p2 / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\n/dev/mmcblk0p1 /boot vfat rw 0 0\ntmpfs /run tmpfs rw 0 0\n";
        let m = parse_mounts(text);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].1, "/");
        assert_eq!(m[0].2, "ext4");
        assert_eq!(m[1].1, "/boot");
        assert_eq!(m[1].2, "vfat");
    }

    fn pu(pid: i32, ppid: i32, cpu: f32, rss: u64) -> ProcUsage {
        ProcUsage {
            pid,
            ppid,
            uid: 1000,
            comm: format!("p{pid}"),
            user: "u".into(),
            cpu_percent: cpu,
            nice: 0,
            state: 'S',
            rss_kb: rss,
            mem_percent: 0.0,
        }
    }

    #[test]
    fn descendants_collects_subtree() {
        let pairs = [(1, 0), (2, 1), (3, 1), (4, 2)];
        let mut d = descendants(1, &pairs);
        d.sort();
        assert_eq!(d, vec![2, 3, 4]);
        assert_eq!(descendants(2, &pairs), vec![4]);
        assert!(descendants(4, &pairs).is_empty());
    }

    #[test]
    fn app_groups_aggregates_children() {
        let procs = vec![pu(1, 0, 1.0, 100), pu(2, 1, 2.0, 200), pu(3, 1, 3.0, 300), pu(4, 2, 4.0, 400)];
        let apps = app_groups(&procs);
        assert_eq!(apps.len(), 1);
        let a = &apps[0];
        assert_eq!(a.pid, 1);
        assert!((a.cpu_percent - 10.0).abs() < 0.01);
        assert_eq!(a.rss_kb, 1000);
        assert!(a.comm.contains("4 进程"));
    }

    #[test]
    fn parse_proc_net_conns() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1\n   1: 0100007F:A1B2 0100007F:0016 01 00000000:00000000 00:00000000 00000000  1000        0 6789 1\n";
        let c = parse_proc_net(text, "TCP");
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].local, "127.0.0.1:22");
        assert_eq!(c[0].remote, "0.0.0.0:0");
        assert_eq!(c[0].state, "LISTEN");
        assert_eq!(c[0].uid, 1000);
        assert_eq!(c[1].state, "ESTABLISHED");
    }
}
