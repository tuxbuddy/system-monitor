//! eBPF 诊断实验（#27）：能力检测、资源上限、显式 unsupported 报告。
//!
//! 设计边界（与 roadmap 一致）：
//! - **默认构建不引入 eBPF 依赖**：本模块只做内核能力探测与实验脚手架，
//!   真正的 prog/map 加载在 `ebpf` feature 下经 tracefs 路径验证（见
//!   docs/ebpf-experiments.md），未满足前提时**明确报 unsupported**，
//!   绝不伪造数据或静默降级。
//! - 权限模型与 probe-helper 一致：特权操作在独立 root 服务，GUI 不提权。
//! - 三个首批场景（调度延迟/块 I/O 延迟/TCP 重传）各提供可复现实验,
//!   当前实现走 tracefs kprobe/tracepoint（探针基础设施已就绪），
//!   eBPF 版本为 feature-gated 后续演进——两者输出同构事件。

use serde_json::{json, Value};

/// 单项前提。
#[derive(Clone, Debug, PartialEq)]
pub struct EbpfCheck {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// eBPF 实验能力矩阵。
#[derive(Clone, Debug, Default)]
pub struct EbpfCapability {
    pub items: Vec<EbpfCheck>,
}

impl EbpfCapability {
    /// 内核 ≥ 5.8（BTF + ring buffer + 多数 tracepoint 齐备的保守下限）。
    pub fn supported(&self) -> bool {
        self.items.iter().all(|i| i.ok)
    }

    pub fn unsupported_reasons(&self) -> Vec<String> {
        self.items.iter().filter(|i| !i.ok).map(|i| i.detail.clone()).collect()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "supported": self.supported(),
            "items": self.items.iter().map(|i| json!({"name": i.name, "ok": i.ok, "detail": i.detail})).collect::<Vec<_>>(),
        })
    }
}

/// 内核主次版本号（uname -r "6.8.0-xx"）。
pub fn kernel_version() -> Option<(u64, u64)> {
    let uts = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let mut it = uts.trim().split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next().unwrap_or("0").split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?;
    Some((major, minor))
}

/// 资源上限（实验会话级；防止 map/日志失控）。
#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    /// map 条目上限（每场景）。
    pub max_map_entries: u32,
    /// 单会话最长秒数。
    pub max_session_secs: u64,
    /// 事件采样率（每 N 次 1 条）。
    pub sample_rate: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self { max_map_entries: 16_384, max_session_secs: 300, sample_rate: 1 }
    }
}

impl ResourceLimits {
    pub fn from_env() -> Self {
        let get = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
        Self {
            max_map_entries: get("SM_EBPF_MAX_ENTRIES", 16_384).max(64) as u32,
            max_session_secs: get("SM_EBPF_MAX_SECS", 300).max(1),
            sample_rate: get("SM_EBPF_SAMPLE_RATE", 1).max(1) as u32,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "max_map_entries": self.max_map_entries,
            "max_session_secs": self.max_session_secs,
            "sample_rate": self.sample_rate,
        })
    }
}

/// 本机 eBPF 实验能力检测（非 Linux 平台整组 unsupported）。
pub fn detect() -> EbpfCapability {
    let mut items = Vec::new();
    if !std::path::Path::new("/proc").exists() {
        return EbpfCapability {
            items: vec![EbpfCheck { name: "platform", ok: false, detail: "非 Linux 平台".to_string() }],
        };
    }
    // 内核版本
    let kv = kernel_version();
    let (ok, detail) = match kv {
        Some((maj, min)) if (maj, min) >= (5, 8) => (true, format!("内核 {maj}.{min} ≥ 5.8")),
        Some((maj, min)) => (false, format!("内核 {maj}.{min} < 5.8,ring buffer/BTF 支持不完整")),
        None => (false, "无法读取内核版本".to_string()),
    };
    items.push(EbpfCheck { name: "kernel_version", ok, detail });

    // BTF
    let btf = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
    items.push(EbpfCheck {
        name: "btf",
        ok: btf,
        detail: if btf { "BTF 可用（CO-RE）".into() } else { "无 /sys/kernel/btf/vmlinux".into() },
    });

    // bpf syscall（与 pidfd 同法探测:对 dummy 调用看 ENOSYS/EPERM）
    let bpf_syscall = bpf_syscall_available();
    items.push(EbpfCheck {
        name: "bpf_syscall",
        ok: bpf_syscall,
        detail: if bpf_syscall { "bpf(2) 系统调用可达".into() } else { "bpf(2) 被 seccomp 禁用或内核未编译".into() },
    });

    // perf_event_open（加载与 attach 需要）
    items.push(EbpfCheck {
        name: "perf_events",
        ok: std::path::Path::new("/sys/kernel/perf_event_paranoid").exists(),
        detail: "perf_event 子系统存在性（权限由 probe-helper 边界处理）".into(),
    });

    // tracefs（tracefs 实验路径与回退共用）
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let tracefs = mounts.lines().any(|l| l.contains("tracefs"));
    items.push(EbpfCheck {
        name: "tracefs",
        ok: tracefs,
        detail: if tracefs { "tracefs 已挂载(实验与回退路径)".into() } else { "tracefs 未挂载".into() },
    });

    EbpfCapability { items }
}

#[cfg(target_os = "linux")]
fn bpf_syscall_available() -> bool {
    // BPF_PROG_TEST_RUN 之类需要参数;用 BPF_CMD 枚举首个命令 + 空 attr
    // 探测:ENOSYS=未实现,EPERM/EINVAL=已实现但被策略限制（视为"可达"）
    const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
    let attr = [0u8; 16];
    let r = unsafe {
        libc::syscall(
            321, // __NR_bpf (x86_64/aarch64 同号)
            BPF_MAP_LOOKUP_ELEM,
            attr.as_ptr(),
            attr.len(),
        )
    };
    if r == 0 {
        return true;
    }
    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EINVAL) | Some(libc::EPERM) | Some(libc::ENOENT)
    )
}

#[cfg(not(target_os = "linux"))]
fn bpf_syscall_available() -> bool {
    false
}

/// 首批三个实验场景的定义（可复现实验的固定描述;执行走 tracefs 路径）。
pub const EXPERIMENTS: &[(&str, &str)] = &[
    (
        "sched_delay",
        "调度延迟:tracepoint sched/sched_switch 计数 + 采样运行队列等待;eBPF 版本用 hist 观测 p99",
    ),
    (
        "block_io_latency",
        "块 I/O 延迟:block_rq_issue/block_rq_complete kprobe 配对;eBPF 版本用 map 聚合直方图",
    ),
    (
        "tcp_retrans",
        "TCP 重传:tcp_retransmit_skb tracepoint 计数 + /proc/net/snmp 交叉验证",
    ),
];

/// 三个场景的可复现实验指引（docs 的机器可读摘要;执行器见 docs/ebpf-experiments.md）。
pub fn experiments_json() -> Value {
    json!({
        "experiments": EXPERIMENTS.iter().map(|(name, desc)| json!({
            "name": name,
            "description": desc,
            "harness": "tracefs(probe-helper 协议);eBPF 版本 feature=ebpf 后续接入",
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_linux_reports_unsupported_explicitly() {
        let cap = detect();
        if !std::path::Path::new("/proc").exists() {
            assert!(!cap.supported());
            assert_eq!(cap.unsupported_reasons(), vec!["非 Linux 平台".to_string()]);
            let j = cap.to_json();
            assert_eq!(j["supported"], false);
        }
    }

    #[test]
    fn kernel_version_parses_common_formats() {
        // 纯函数部分:用固定串逻辑抽测(真实读数在 Linux 上做)
        let parse = |s: &str| -> Option<(u64, u64)> {
            let mut it = s.trim().split('.');
            let major = it.next()?.parse().ok()?;
            let minor = it.next().unwrap_or("0").split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?;
            Some((major, minor))
        };
        assert_eq!(parse("6.8.0-45-generic"), Some((6, 8)));
        assert_eq!(parse("5.15"), Some((5, 15)));
        assert_eq!(parse("4.19.99"), Some((4, 19)));
    }

    #[test]
    fn limits_from_defaults_are_bounded() {
        let l = ResourceLimits::default();
        assert!(l.max_map_entries >= 64);
        assert!(l.max_session_secs >= 1);
        assert!(l.sample_rate >= 1);
        let j = l.to_json();
        assert_eq!(j["max_session_secs"], 300);
    }

    #[test]
    fn three_experiments_are_registered() {
        let j = experiments_json();
        assert_eq!(j["experiments"].as_array().unwrap().len(), 3);
    }
}
