use std::fs;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::platform;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Rail {
    pub name: String,
    pub volts: f32,
    pub amps: f32,
}

impl Rail {
    pub fn watts(&self) -> f32 {
        self.volts * self.amps
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Power {
    pub core_v: f32,
    pub core_a: f32,
    pub core_w: f32,
    pub ext5v_v: f32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Throttle {
    pub undervoltage: bool,
    pub freq_capped: bool,
    pub throttled: bool,
    pub soft_temp_limit: bool,
    pub occurred: bool,
}

impl Throttle {
    pub fn any_current(self) -> bool {
        self.undervoltage || self.freq_capped || self.throttled || self.soft_temp_limit
    }

    pub fn warning(self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.undervoltage { parts.push("欠压"); }
        if self.freq_capped { parts.push("降频"); }
        if self.throttled { parts.push("节流"); }
        if self.soft_temp_limit { parts.push("温度限制"); }
        let mut s = parts.join("/");
        if self.occurred {
            if s.is_empty() { s = "曾发生节流".to_string(); } else { s.push_str("（含历史）"); }
        }
        s
    }
}

#[derive(Clone, Debug, Default)]
pub struct GpuStats {
    pub v3d_ghz: Option<f32>,
    pub core_ghz: Option<f32>,
    pub isp_ghz: Option<f32>,
    pub hevc_ghz: Option<f32>,
    pub hdmi_ghz: Option<f32>,
    pub gpu_mem_mb: Option<u64>,
    pub malloc_mb: Option<u64>,
    pub bo_count: Option<u64>,
    pub bo_size_mb: Option<u64>,
    pub clients: Option<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct PiStats {
    pub temp_c: Option<f32>,
    pub freq_ghz: Option<f32>,
    pub gpu: GpuStats,
    pub power: Option<Power>,
    pub throttle: Option<Throttle>,
    pub rails: Vec<Rail>,
}

pub fn parse_temp_millideg(text: &str) -> Option<f32> {
    let v: i64 = text.split_whitespace().next()?.parse().ok()?;
    Some(v as f32 / 1000.0)
}

pub fn parse_freq_khz(text: &str) -> Option<u64> {
    text.split_whitespace().next()?.parse().ok()
}

/// 解析 vcgencmd measure_clock 输出 "frequency(0)=500000000" → GHz。
pub fn parse_clock_hz(text: &str) -> Option<f32> {
    let after = text.split('=').nth(1)?.trim();
    let hz: f64 = after.parse().ok()?;
    Some((hz / 1_000_000_000.0) as f32)
}

/// 解析 debugfs measure_clock："cycles: NNN (1165.2 Mhz)" → GHz（免 fork）。
pub fn parse_debugfs_clock(text: &str) -> Option<f32> {
    let mhz: f32 = text.split('(').nth(1)?.split_whitespace().next()?.parse().ok()?;
    Some(mhz / 1000.0)
}

/// 解析 vcgencmd get_mem "gpu=8M" → 8（MB）。
pub fn parse_mem_mb(text: &str) -> Option<u64> {
    let v = text.split('=').nth(1)?.trim();
    let num: String = v.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

/// 解析 debugfs bo_stats："allocated bos: N" / "allocated bo size (kb): M"。
pub fn parse_bo_stats(text: &str) -> (Option<u64>, Option<u64>) {
    let mut count = None;
    let mut size_kb = None;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("allocated bos") {
            count = line.split(':').nth(1).and_then(|s| s.trim().parse().ok());
        } else if lower.contains("allocated bo size") {
            size_kb = line.split(':').nth(1).and_then(|s| s.trim().parse::<u64>().ok());
        }
    }
    (count, size_kb)
}

/// 解析 debugfs clients：统计使用 GPU 的进程数（按 tgid 去重，跳过表头）。
pub fn parse_gpu_clients(text: &str) -> usize {
    let mut tgids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 || line.trim().is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let _cmd = it.next();
        if let Some(tgid) = it.next() {
            tgids.insert(tgid.to_string());
        }
    }
    tgids.len()
}

fn read_first(paths: &[String]) -> Option<String> {
    paths.iter().find_map(|p| fs::read_to_string(p).ok())
}

/// GPU 慢变字段（媒体时钟/显存/BO/客户端）——刷新成本高，做 5s 缓存。
#[derive(Clone, Default)]
struct GpuSlow {
    core_ghz: Option<f32>,
    isp_ghz: Option<f32>,
    hevc_ghz: Option<f32>,
    hdmi_ghz: Option<f32>,
    gpu_mem_mb: Option<u64>,
    malloc_mb: Option<u64>,
    bo_count: Option<u64>,
    bo_size_mb: Option<u64>,
    clients: Option<usize>,
}

fn gpu_slow() -> GpuSlow {
    static CACHE: OnceLock<Mutex<(Option<Instant>, GpuSlow)>> = OnceLock::new();
    let cell = CACHE.get_or_init(|| Mutex::new((None, GpuSlow::default())));
    let Ok(mut guard) = cell.lock() else {
        return GpuSlow::default();
    };
    let fresh = guard.0.is_some_and(|t| t.elapsed() < Duration::from_secs(5));
    if !fresh {
        let pf = platform::platform();
        let has = |e: &str| pf.gpu_engines.iter().any(|x| x == e);
        let clock = |name: &str| run_vcgencmd(&["measure_clock", name]).and_then(|s| parse_clock_hz(&s));
        let (bo_count, bo_size_kb) = read_first(&pf.gpu_bo_stats)
            .map(|s| parse_bo_stats(&s))
            .unwrap_or((None, None));
        let mem = |k: &str| {
            if pf.has_vcgencmd {
                run_vcgencmd(&["get_mem", k]).and_then(|s| parse_mem_mb(&s))
            } else {
                None
            }
        };
        guard.1 = GpuSlow {
            core_ghz: if has("core") { clock("core") } else { None },
            isp_ghz: if has("isp") { clock("isp") } else { None },
            hevc_ghz: if has("hevc") { clock("hevc") } else { None },
            hdmi_ghz: if has("hdmi") { clock("hdmi") } else { None },
            gpu_mem_mb: mem("gpu"),
            malloc_mb: mem("malloc"),
            bo_count,
            bo_size_mb: bo_size_kb.map(|kb| kb / 1024),
            clients: read_first(&pf.gpu_clients).map(|s| parse_gpu_clients(&s)),
        };
        guard.0 = Some(Instant::now());
    }
    guard.1.clone()
}

/// 采集 GPU 信息：V3D 时钟走 debugfs（免 fork），慢变字段走 5s 缓存；失败即 None。
pub fn read_gpu() -> GpuStats {
    let pf = platform::platform();
    if !pf.gpu_enabled {
        return GpuStats::default();
    }
    let v3d_ghz = read_first(&pf.gpu_clock_debugfs)
        .and_then(|s| parse_debugfs_clock(&s))
        .or_else(|| run_vcgencmd(&["measure_clock", "v3d"]).and_then(|s| parse_clock_hz(&s)));
    let slow = gpu_slow();
    GpuStats {
        v3d_ghz,
        core_ghz: slow.core_ghz,
        isp_ghz: slow.isp_ghz,
        hevc_ghz: slow.hevc_ghz,
        hdmi_ghz: slow.hdmi_ghz,
        gpu_mem_mb: slow.gpu_mem_mb,
        malloc_mb: slow.malloc_mb,
        bo_count: slow.bo_count,
        bo_size_mb: slow.bo_size_mb,
        clients: slow.clients,
    }
}

/// 解析 vcgencmd pmic_read_adc：按 _V/_A 去后缀配对 base name，保持首见顺序。
pub fn parse_pmic(text: &str) -> Vec<Rail> {
    use std::collections::HashMap;
    let mut map: HashMap<String, (f32, f32)> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some(label) = line.split_whitespace().next() else { continue };
        let Some(rest) = line.split('=').nth(1) else { continue };
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
        let Ok(val) = num.parse::<f32>() else { continue };
        let (base, is_volt) = if let Some(b) = label.strip_suffix("_V") {
            (b, true)
        } else if let Some(b) = label.strip_suffix("_A") {
            (b, false)
        } else {
            continue;
        };
        if !order.iter().any(|n| n.as_str() == base) {
            order.push(base.to_string());
        }
        let entry = map.entry(base.to_string()).or_insert((0.0, 0.0));
        if is_volt { entry.0 = val; } else { entry.1 = val; }
    }
    order
        .into_iter()
        .map(|name| {
            let (volts, amps) = map.get(&name).copied().unwrap_or((0.0, 0.0));
            Rail { name, volts, amps }
        })
        .collect()
}

pub fn power_summary(rails: &[Rail]) -> Power {
    let mut p = Power::default();
    for r in rails {
        match r.name.as_str() {
            "VDD_CORE" => { p.core_v = r.volts; p.core_a = r.amps; p.core_w = r.watts(); }
            "EXT5V" => p.ext5v_v = r.volts,
            _ => {}
        }
    }
    p
}

pub fn parse_throttled(text: &str) -> Option<Throttle> {
    let hex = text.split("throttled=0x").nth(1)?.split_whitespace().next()?;
    let bits = u32::from_str_radix(hex, 16).ok()?;
    Some(Throttle {
        undervoltage: bits & 1 != 0,
        freq_capped: bits & (1 << 1) != 0,
        throttled: bits & (1 << 2) != 0,
        soft_temp_limit: bits & (1 << 3) != 0,
        occurred: (bits >> 16) & 0xF != 0,
    })
}

fn run_vcgencmd(args: &[&str]) -> Option<String> {
    let pf = platform::platform();
    if !pf.has_vcgencmd {
        return None;
    }
    let out = Command::new(&pf.vcgencmd_bin).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

pub fn read_pi_stats() -> PiStats {
    let pf = platform::platform();
    let temp_c = pf
        .thermal_paths
        .iter()
        .find_map(|p| fs::read_to_string(p).ok().and_then(|s| parse_temp_millideg(&s)));

    let mut freqs: Vec<f32> = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") {
        for e in entries.flatten() {
            let name = e.file_name();
            let n = name.to_str().unwrap_or("");
            let suffix = n.strip_prefix("cpu").unwrap_or("");
            if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(s) = fs::read_to_string(pf.cpu_freq_path.replace("{}", suffix))
                && let Some(khz) = parse_freq_khz(&s)
            {
                freqs.push(khz as f32 / 1_000_000.0);
            }
        }
    }
    let freq_ghz = if freqs.is_empty() {
        None
    } else {
        Some(freqs.iter().sum::<f32>() / freqs.len() as f32)
    };

    let rails = run_vcgencmd(&["pmic_read_adc"]).map(|s| parse_pmic(&s)).unwrap_or_default();
    let power = if rails.is_empty() { None } else { Some(power_summary(&rails)) };
    let throttle = run_vcgencmd(&["get_throttled"]).and_then(|s| parse_throttled(&s));
    let gpu = read_gpu();

    PiStats { temp_c, freq_ghz, gpu, power, throttle, rails }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_millideg() {
        assert!((parse_temp_millideg("50700\n").unwrap() - 50.7).abs() < 0.01);
        assert_eq!(parse_temp_millideg("garbage"), None);
    }

    #[test]
    fn freq_khz() {
        assert_eq!(parse_freq_khz("2400000\n"), Some(2400000));
        assert_eq!(parse_freq_khz("x"), None);
    }

    #[test]
    fn clock_hz_to_ghz() {
        assert!((parse_clock_hz("frequency(0)=500000000\n").unwrap() - 0.5).abs() < 1e-6);
        assert_eq!(parse_clock_hz("garbage"), None);
        assert!((parse_debugfs_clock("cycles: 1165230921 (1165.2 Mhz)\n").unwrap() - 1.1652).abs() < 1e-4);
        assert_eq!(parse_debugfs_clock("garbage"), None);
    }

    #[test]
    fn gpu_mem_and_bo_stats() {
        assert_eq!(parse_mem_mb("gpu=8M\n"), Some(8));
        assert_eq!(parse_mem_mb("malloc=1M\n"), Some(1));
        assert_eq!(parse_mem_mb("garbage"), None);
        let (n, sz) = parse_bo_stats("allocated bos:          1191\nallocated bo size (kb): 318192\n");
        assert_eq!(n, Some(1191));
        assert_eq!(sz, Some(318192));
        assert_eq!(parse_bo_stats("nope"), (None, None));
    }

    #[test]
    fn gpu_clients_distinct() {
        let text = "             command  tgid dev master a\n               labwc  1417 128   n    n\n               labwc  1417 128   n    n\n            Xwayland  1798 128   n    n\n";
        assert_eq!(parse_gpu_clients(text), 2);
        assert_eq!(parse_gpu_clients("command tgid\n"), 0);
    }

    const PMIC: &str = " VDD_CORE_A current(7)=2.73258000A\n VDD_CORE_V volt(15)=0.86495640V\n EXT5V_V volt(24)=5.10138000V\n 3V3_SYS_A current(1)=0.14150990A\n 3V3_SYS_V volt(9)=3.29982600V\n";

    #[test]
    fn pmic_pairs_rails() {
        let rails = parse_pmic(PMIC);
        let core = rails.iter().find(|r| r.name == "VDD_CORE").unwrap();
        assert!((core.volts - 0.8649564).abs() < 1e-4);
        assert!((core.amps - 2.73258).abs() < 1e-4);
        let ext = rails.iter().find(|r| r.name == "EXT5V").unwrap();
        assert!((ext.volts - 5.10138).abs() < 1e-4);
        assert_eq!(ext.amps, 0.0);
        assert_eq!(rails.len(), 3);
        assert_eq!(rails[0].name, "VDD_CORE");
        assert_eq!(rails[1].name, "EXT5V");
        assert_eq!(rails[2].name, "3V3_SYS");
    }

    #[test]
    fn power_summary_core_watts() {
        let p = power_summary(&parse_pmic(PMIC));
        assert!((p.core_w - 0.8649564 * 2.73258).abs() < 1e-3);
        assert!((p.ext5v_v - 5.10138).abs() < 1e-4);
    }

    #[test]
    fn throttled_decode() {
        let t0 = parse_throttled("throttled=0x0\n").unwrap();
        assert!(!t0.any_current());
        assert!(!t0.occurred);
        let t1 = parse_throttled("throttled=0x50005\n").unwrap();
        assert!(t1.undervoltage);
        assert!(t1.throttled);
        assert!(!t1.freq_capped);
        assert!(t1.occurred);
        assert!(t1.any_current());
        assert_eq!(parse_throttled("garbage"), None);
    }

    #[test]
    fn throttled_decode_capped_and_soft_limit() {
        let t = parse_throttled("throttled=0xA\n").unwrap();
        assert!(t.freq_capped);
        assert!(t.soft_temp_limit);
        assert!(!t.undervoltage);
        assert!(!t.throttled);
        assert!(!t.occurred);
        assert!(t.any_current());
        let cap_only = parse_throttled("throttled=0x2\n").unwrap();
        assert!(cap_only.freq_capped);
        assert!(!cap_only.soft_temp_limit);
        let soft_only = parse_throttled("throttled=0x8\n").unwrap();
        assert!(soft_only.soft_temp_limit);
        assert!(!soft_only.freq_capped);
    }

    #[test]
    fn throttle_warning_text() {
        let t = Throttle { undervoltage: true, throttled: true, occurred: true, ..Default::default() };
        let w = t.warning();
        assert!(w.contains("欠压"));
        assert!(w.contains("节流"));
        assert!(w.ends_with("（含历史）"));
        assert_eq!(Throttle::default().warning(), "");
        let occurred_only = Throttle { occurred: true, ..Default::default() };
        assert_eq!(occurred_only.warning(), "曾发生节流");
    }

    #[test]
    fn read_pi_stats_smoke() {
        // Pi 500 真机冒烟：温度/频率/功耗/节流均应可得（与 actions 集成测试同属环境相关）
        let s = read_pi_stats();
        assert!(s.temp_c.is_some());
        assert!(s.freq_ghz.is_some());
        assert!(s.power.is_some());
        assert!(s.throttle.is_some());
        assert!(!s.rails.is_empty());
    }
}
