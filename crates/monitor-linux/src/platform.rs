//! 平台采集档案：把「从哪读」解耦成按操作系统区分的配置。
//! 检测 OS → 选内置档案（raspberry-pi / ubuntu / kylin / debian / generic）→
//! 允许 ~/.config/system-monitor/platform.conf 覆盖。全部零依赖。
//!
//! 说明：/proc 各项（CPU/内存/进程/磁盘/网络/连接）是 Linux 通用的，不在差异范围；
//! 差异集中在：vcgencmd 是否可用、温度传感器路径、GPU 时钟/缓冲的 debugfs 挂点、CPU 频率路径。

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// 支持的 OS 档案（下拉自动列自此处；新增一个名字即可出现在选择器里）。
/// 除 raspberry-pi 外均走通用档案（无 vcgencmd、无 Pi GPU、通用 thermal/cpufreq）。
pub const KNOWN_OS: &[&str] = &[
    "raspberry-pi",
    "ubuntu",
    "debian",
    "kylin",
    "uos",
    "deepin",
    "openEuler",
    "anolis",
    "centos",
    "rocky",
    "almalinux",
    "fedora",
    "generic",
];

#[derive(Clone, Debug)]
pub struct Platform {
    pub os: String,
    pub has_vcgencmd: bool,
    pub vcgencmd_bin: String,
    pub thermal_paths: Vec<String>,
    /// 含 `{}` 占位，替换为 CPU 序号（0,1,2...）。
    pub cpu_freq_path: String,
    pub gpu_enabled: bool,
    pub gpu_clock_debugfs: Vec<String>,
    pub gpu_bo_stats: Vec<String>,
    pub gpu_clients: Vec<String>,
    /// 通过 `vcgencmd measure_clock <engine>` 读取的引擎名。
    pub gpu_engines: Vec<String>,
}

impl Default for Platform {
    fn default() -> Self {
        Self {
            os: "generic".to_string(),
            has_vcgencmd: false,
            vcgencmd_bin: "vcgencmd".to_string(),
            thermal_paths: vec![
                "/sys/class/thermal/thermal_zone0/temp".to_string(),
                "/sys/class/thermal/thermal_zone1/temp".to_string(),
                "/sys/class/hwmon/hwmon0/temp1_input".to_string(),
                "/sys/class/hwmon/hwmon1/temp1_input".to_string(),
            ],
            cpu_freq_path: "/sys/devices/system/cpu/cpu{}/cpufreq/scaling_cur_freq".to_string(),
            gpu_enabled: false,
            gpu_clock_debugfs: Vec::new(),
            gpu_bo_stats: Vec::new(),
            gpu_clients: Vec::new(),
            gpu_engines: Vec::new(),
        }
    }
}

/// 内置档案。
pub fn builtin(os: &str) -> Platform {
    match os {
        "raspberry-pi" => Platform {
            os: "raspberry-pi".to_string(),
            has_vcgencmd: true,
            thermal_paths: vec!["/sys/class/thermal/thermal_zone0/temp".to_string()],
            gpu_enabled: true,
            gpu_clock_debugfs: vec!["/sys/kernel/debug/dri/128/measure_clock".to_string()],
            gpu_bo_stats: vec![
                "/sys/kernel/debug/dri/128/bo_stats".to_string(),
                "/sys/kernel/debug/dri/1002000000.v3d/bo_stats".to_string(),
            ],
            gpu_clients: vec![
                "/sys/kernel/debug/dri/0/clients".to_string(),
                "/sys/kernel/debug/dri/128/clients".to_string(),
            ],
            gpu_engines: vec![
                "v3d".to_string(),
                "core".to_string(),
                "isp".to_string(),
                "hevc".to_string(),
                "hdmi".to_string(),
            ],
            ..Platform::default()
        },
        // Ubuntu / 麒麟 / Debian 服务器：无 vcgencmd、无 Pi 的 V3D；温度走通用 thermal/hwmon，
        // CPU 频率走通用 cpufreq（default 已覆盖）。
        _ => Platform {
            os: os.to_string(),
            ..Platform::default()
        },
    }
}

fn parse_bool(v: &str) -> bool {
    matches!(v, "1" | "true" | "yes" | "on")
}

fn split_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// 解析覆盖文本（key=value，忽略空行与 # 注释）并应用到档案。
pub fn apply(p: &mut Platform, text: &str) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "os" => p.os = v.to_string(),
            "has_vcgencmd" => p.has_vcgencmd = parse_bool(v),
            "vcgencmd_bin" => p.vcgencmd_bin = v.to_string(),
            "thermal_paths" => p.thermal_paths = split_list(v),
            "cpu_freq_path" => p.cpu_freq_path = v.to_string(),
            "gpu_enabled" => p.gpu_enabled = parse_bool(v),
            "gpu_clock_debugfs" => p.gpu_clock_debugfs = split_list(v),
            "gpu_bo_stats" => p.gpu_bo_stats = split_list(v),
            "gpu_clients" => p.gpu_clients = split_list(v),
            "gpu_engines" => p.gpu_engines = split_list(v),
            _ => {}
        }
    }
}

pub fn to_text(p: &Platform) -> String {
    format!(
        "# 系统监视器 · 平台采集档案（按 OS 生成，可编辑覆盖）\n\
# 列表用英文逗号分隔；改后重启生效\n\
os={}\nhas_vcgencmd={}\nvcgencmd_bin={}\nthermal_paths={}\ncpu_freq_path={}\ngpu_enabled={}\ngpu_clock_debugfs={}\ngpu_bo_stats={}\ngpu_clients={}\ngpu_engines={}\n",
        p.os,
        p.has_vcgencmd,
        p.vcgencmd_bin,
        p.thermal_paths.join(","),
        p.cpu_freq_path,
        p.gpu_enabled,
        p.gpu_clock_debugfs.join(","),
        p.gpu_bo_stats.join(","),
        p.gpu_clients.join(","),
        p.gpu_engines.join(",")
    )
}

pub fn path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/system-monitor/platform.conf"))
}

/// 读取磁盘上的实际配置文件内容（供 UI 展示）；不存在时给出提示。
pub fn config_text() -> String {
    match path().and_then(|p| std::fs::read_to_string(p).ok()) {
        Some(t) => t,
        None => "（未找到 platform.conf —— 首次运行会自动生成）".to_string(),
    }
}

/// 从配置文本里取 `os=` 值（用于显式选择操作系统档案）。
pub fn text_os(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("os=") {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn detect_os() -> String {
    let is_pi = std::fs::read_to_string("/proc/device-tree/model")
        .map(|m| m.contains("Raspberry Pi"))
        .unwrap_or(false)
        || Path::new("/usr/bin/vcgencmd").exists()
        || Path::new("/opt/vc/bin/vcgencmd").exists();
    if is_pi {
        return "raspberry-pi".to_string();
    }
    if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
        let mut id = None;
        let mut like = None;
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("ID=") {
                id = Some(v.trim().trim_matches('"').to_string());
            } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
                like = Some(v.trim().trim_matches('"').to_string());
            }
        }
        let like_has = |k: &str| {
            like.as_deref()
                .is_some_and(|l| l.split_whitespace().any(|w| w == k))
        };
        for k in ["ubuntu", "kylin", "debian"] {
            if id.as_deref() == Some(k) || like_has(k) {
                return k.to_string();
            }
        }
        if let Some(id) = id {
            return id;
        }
    }
    "generic".to_string()
}

pub fn load() -> Platform {
    let over = path().and_then(|fp| std::fs::read_to_string(&fp).ok());
    // 配置里显式写了 os= → 以该系统档案为基础；否则自动检测。
    let base_os = over
        .as_deref()
        .and_then(text_os)
        .unwrap_or_else(detect_os);
    let mut p = builtin(&base_os);
    match over {
        Some(text) => apply(&mut p, &text),
        None => {
            if let Some(fp) = path() {
                if let Some(dir) = fp.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let _ = std::fs::write(&fp, to_text(&p));
            }
        }
    }
    p
}

static PLATFORM: OnceLock<Mutex<Platform>> = OnceLock::new();

/// 进程级单例：首次调用时检测并加载（含写默认配置文件）。返回克隆，便于热重载后立即读取新值。
pub fn platform() -> Platform {
    let m = PLATFORM.get_or_init(|| Mutex::new(load()));
    m.lock().map(|g| g.clone()).unwrap_or_default()
}

/// 重新从磁盘加载并更新缓存（保存配置后调用即可“即时生效”）。
pub fn reload() {
    let fresh = load();
    let m = PLATFORM.get_or_init(|| Mutex::new(fresh.clone()));
    if let Ok(mut g) = m.lock() {
        *g = fresh;
    }
}

/// 把编辑后的文本写入 platform.conf。
pub fn save_text(text: &str) -> std::io::Result<()> {
    let p = path().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "无 HOME"))?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(p, text)
}

/// 当前 OS 的内置默认档案文本（用于“重新生成默认”）。
pub fn regenerate_text() -> String {
    to_text(&builtin(&detect_os()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raspberry_profile_has_vcgencmd_and_gpu() {
        let p = builtin("raspberry-pi");
        assert!(p.has_vcgencmd);
        assert!(p.gpu_enabled);
        assert!(p.gpu_engines.iter().any(|e| e == "v3d"));
        assert!(p.thermal_paths[0].contains("thermal_zone0"));
    }

    #[test]
    fn ubuntu_profile_no_vcgencmd_no_pi_gpu() {
        let p = builtin("ubuntu");
        assert!(!p.has_vcgencmd);
        assert!(!p.gpu_enabled);
        assert!(p.cpu_freq_path.contains("{}"));
    }

    #[test]
    fn apply_overrides_lists_and_bools() {
        let mut p = Platform::default();
        apply(
            &mut p,
            "os=custom\nhas_vcgencmd=1\nthermal_paths=/a/temp, /b/temp\ngpu_enabled=yes\n",
        );
        assert_eq!(p.os, "custom");
        assert!(p.has_vcgencmd);
        assert_eq!(p.thermal_paths, vec!["/a/temp".to_string(), "/b/temp".to_string()]);
        assert!(p.gpu_enabled);
    }

    #[test]
    fn roundtrip_text() {
        let p = builtin("raspberry-pi");
        let mut q = Platform::default();
        apply(&mut q, &to_text(&p));
        assert_eq!(q.os, p.os);
        assert_eq!(q.has_vcgencmd, p.has_vcgencmd);
        assert_eq!(q.gpu_bo_stats, p.gpu_bo_stats);
        assert_eq!(q.gpu_engines, p.gpu_engines);
    }

    #[test]
    fn text_os_and_known_list() {
        assert_eq!(text_os("# c\nos=kylin\nhas_vcgencmd=false\n"), Some("kylin".to_string()));
        assert_eq!(text_os("has_vcgencmd=true\n"), None);
        assert!(KNOWN_OS.contains(&"kylin"));
        assert!(KNOWN_OS.contains(&"ubuntu"));
        assert!(KNOWN_OS.contains(&"openEuler"));
        assert!(KNOWN_OS.contains(&"uos"));
        assert!(KNOWN_OS.len() >= 10);
    }
}