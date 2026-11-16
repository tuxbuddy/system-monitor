//! 主机真实能力探测（#16）。
//!
//! 按内核版本、cgroup v2、BTF、tracefs、systemd、PSI、thermal/cpufreq、
//! RAPL、探针工具逐项探测，形成 `HostCapabilities` 报告；UI 与 MCP 据此
//! 启用/禁用/解释功能，而不是按发行版名称猜。平台档案只提供默认参数，
//! 能力判断一律以这里为准。
//!
//! 远端主机经一次性脚本批量采集同构数据（见 [`capabilities_script`]），
//! 解析共用 [`HostCapabilities::parse_report`]。

use serde_json::{json, Value};

/// 单项能力：是否可用 + 人可读原因（不可用时给修复建议）。
#[derive(Clone, Debug, PartialEq)]
pub struct CapItem {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// 主机能力报告。`items` 的键集合固定，序列化稳定。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostCapabilities {
    pub items: Vec<CapItem>,
}

impl HostCapabilities {
    /// 查询单项能力（测试与后续 UI 接线使用）。
    #[allow(dead_code)]
    pub fn get(&self, name: &str) -> Option<&CapItem> {
        self.items.iter().find(|i| i.name == name)
    }

    /// 判断功能是否可用（测试与后续 UI 接线使用）。
    #[allow(dead_code)]
    pub fn supports(&self, name: &str) -> bool {
        self.get(name).is_some_and(|i| i.ok)
    }

    /// JSON 报告（MCP host_capabilities 工具）。
    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.items.iter().all(|i| i.ok) || !self.items.is_empty(),
            "items": self.items.iter().map(|i| json!({
                "name": i.name, "ok": i.ok, "detail": i.detail,
            })).collect::<Vec<_>>(),
            "unavailable": self.items.iter().filter(|i| !i.ok).map(|i| i.name).collect::<Vec<_>>(),
        })
    }
}

/// 探测项清单（本地与远端同构；远端由 [`capabilities_script`] 输出同格式 KEY=VALUE）。
pub const CAP_NAMES: &[&str] = &[
    "cgroup_v2",
    "cgroup_delegated",
    "cgroup_controllers",
    "psi",
    "btf",
    "tracefs",
    "kprobe_events_writable",
    "systemd",
    "thermal",
    "cpufreq",
    "rapl",
    "probe_tools",
];

/// 本地探测。只在 Linux 上有完整结果；非 Linux 平台全部报告不可用（附原因）。
pub fn detect_local() -> HostCapabilities {
    let mut items = Vec::new();
    if !std::path::Path::new("/proc").exists() {
        // 非 Linux 开发机：明确整组不可用，而不是逐项误报
        let names: Vec<&str> = CAP_NAMES.to_vec();
        for n in names {
            items.push(CapItem { name: n, ok: false, detail: "非 Linux 平台（无 /proc、/sys）".to_string() });
        }
        return HostCapabilities { items };
    }

    // cgroup v2 统一层级
    let v2 = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    items.push(CapItem {
        name: "cgroup_v2",
        ok: v2,
        detail: if v2 { "统一层级已挂载".into() } else { "未检测到 cgroup v2（v1 不支持调度）".into() },
    });

    // 用户委派子树
    let delegated = crate::cgroup::parse_self_cgroup(
        &std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default(),
        unsafe { libc::getuid() },
    )
    .is_some();
    items.push(CapItem {
        name: "cgroup_delegated",
        ok: delegated,
        detail: if delegated {
            "当前会话位于 user@<uid>.service 委派子树".into()
        } else {
            "未在委派子树内（从用户会话启动，或检查 systemd Delegate=）".into()
        },
    });

    // 控制器读回验证（复用 detect 的读回语义）
    let controllers = crate::cgroup::doctor()
        .into_iter()
        .find(|c| c.name == "subtree_control")
        .map(|c| (c.ok, c.detail))
        .unwrap_or((false, "未完成体检".into()));
    items.push(CapItem { name: "cgroup_controllers", ok: controllers.0, detail: controllers.1 });

    // PSI
    let psi = std::path::Path::new("/proc/pressure/cpu").exists();
    items.push(CapItem {
        name: "psi",
        ok: psi,
        detail: if psi { "/proc/pressure 可读".into() } else { "内核未启用 PSI（CONFIG_PSI）".into() },
    });

    // BTF
    let btf = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
    items.push(CapItem {
        name: "btf",
        ok: btf,
        detail: if btf { "BTF 可用（CO-RE eBPF 前提）".into() } else { "无 /sys/kernel/btf/vmlinux".into() },
    });

    // tracefs
    let trace = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let tracefs = trace.lines().any(|l| l.contains("tracefs"));
    items.push(CapItem {
        name: "tracefs",
        ok: tracefs,
        detail: if tracefs { "tracefs 已挂载".into() } else { "tracefs 未挂载（mount -t tracefs）".into() },
    });

    // kprobe_events 可写
    let kp_w = {
        let p = std::path::Path::new("/sys/kernel/tracing/kprobe_events")
            .exists()
            .then(|| unsafe {
                // access(W_OK) 需要真实权限判断；以 CString 调用
                let c = std::ffi::CString::new("/sys/kernel/tracing/kprobe_events").unwrap();
                libc::access(c.as_ptr(), libc::W_OK) == 0
            })
            .unwrap_or(false);
        p
    };
    items.push(CapItem {
        name: "kprobe_events_writable",
        ok: kp_w,
        detail: if kp_w { "kprobe_events 可写（或 helper 可用）".into() } else { "kprobe_events 不可写（probe-helper 未安装？）".into() },
    });

    // systemd
    let systemd = std::path::Path::new("/run/systemd/system").exists();
    items.push(CapItem {
        name: "systemd",
        ok: systemd,
        detail: if systemd { "systemd 在运行（scope/slice 语义可用）".into() } else { "未检测到 systemd".into() },
    });

    // thermal / cpufreq / RAPL
    let thermal = std::fs::read_dir("/sys/class/thermal").map(|d| d.count() > 0).unwrap_or(false)
        || std::fs::read_dir("/sys/class/hwmon").map(|d| d.count() > 0).unwrap_or(false);
    items.push(CapItem {
        name: "thermal",
        ok: thermal,
        detail: if thermal { "thermal/hwmon 节点存在".into() } else { "无 thermal/hwmon 传感器节点".into() },
    });
    let cpufreq = std::path::Path::new("/sys/devices/system/cpu/cpu0/cpufreq").exists();
    items.push(CapItem {
        name: "cpufreq",
        ok: cpufreq,
        detail: if cpufreq { "cpufreq 可读（频率/调频器）".into() } else { "无 cpufreq 节点（虚拟化或固定频率）".into() },
    });
    let rapl = std::path::Path::new("/sys/class/powercap/intel-rapl:0").exists()
        || std::path::Path::new("/sys/class/powercap/intel-rapl").exists();
    items.push(CapItem {
        name: "rapl",
        ok: rapl,
        detail: if rapl { "RAPL 能量计数可用（功耗估算）".into() } else { "无 RAPL（非 Intel 或内核未启用）".into() },
    });

    // 探针工具（bcc/bpftrace/libbpf 等，从 probe::Snapshot 的 tools 表复用）
    let tools = crate::probe::Snapshot::load();
    let tools_ok = tools.caps.tools.iter().filter(|(_, ok)| *ok).count();
    items.push(CapItem {
        name: "probe_tools",
        ok: tools_ok > 0,
        detail: format!("{tools_ok} 个探针辅助工具可用"),
    });

    HostCapabilities { items }
}

/// 远端能力一次性采集脚本：输出 KEY=VALUE 行，与 [`parse_report`] 对齐。
pub fn capabilities_script() -> String {
    r#"
echo "cgroup_v2=$([ -e /sys/fs/cgroup/cgroup.controllers ] && echo 1 || echo 0)"
echo "cgroup_delegated=$(grep -q "0::.*user@$(id -u).service" /proc/self/cgroup && echo 1 || echo 0)"
ctrls=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo)
echo "cgroup_controllers=$(echo "$ctrls" | tr ' ' '\n' | grep -cx 'cpu' | awk '{print ($1>=1)?1:0}')"
echo "psi=$([ -e /proc/pressure/cpu ] && echo 1 || echo 0)"
echo "btf=$([ -e /sys/kernel/btf/vmlinux ] && echo 1 || echo 0)"
echo "tracefs=$(grep -c tracefs /proc/mounts 2>/dev/null | awk '{print ($1>=1)?1:0}')"
echo "kprobe_events_writable=$([ -w /sys/kernel/tracing/kprobe_events ] && echo 1 || echo 0)"
echo "systemd=$([ -d /run/systemd/system ] && echo 1 || echo 0)"
echo "thermal=$(ls /sys/class/thermal 2>/dev/null | head -1 | wc -l | awk '{print ($1>=1)?1:0}')"
echo "cpufreq=$([ -d /sys/devices/system/cpu/cpu0/cpufreq ] && echo 1 || echo 0)"
echo "rapl=$([ -d /sys/class/powercap/intel-rapl:0 ] && echo 1 || echo 0)"
echo "probe_tools=$(command -v bpftool >/dev/null 2>&1; echo $?)"
"#
    .to_string()
}

/// 解析脚本输出为 `HostCapabilities`（本地远端共用）。
pub fn parse_report(text: &str) -> HostCapabilities {
    let mut items = Vec::new();
    for name in CAP_NAMES {
        let want = format!("{name}=");
        let mut found = None;
        for line in text.lines() {
            if let Some(v) = line.trim().strip_prefix(&want) {
                found = Some(v.trim().to_string());
                break;
            }
        }
        let Some(v) = found else {
            items.push(CapItem { name, ok: false, detail: "远端未报告该项".into() });
            continue;
        };
        // probe_tools 特例：脚本 echo 的是 command -v 的退出码（0=找到 bpftool）
        let (ok, detail) = if *name == "probe_tools" {
            let ok = v.trim().starts_with('0');
            (ok, if ok { "bpftool 可用".into() } else { "未找到 bpftool".into() })
        } else {
            let ok = v.trim().starts_with('1');
            (ok, if ok { format!("{name}: 可用") } else { format!("{name}: 不可用") })
        };
        items.push(CapItem { name, ok, detail });
    }
    HostCapabilities { items }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_report_handles_all_keys_and_missing() {
        let report = "cgroup_v2=1\ncgroup_delegated=1\ncgroup_controllers=1\npsi=0\nbtf=1\ntracefs=1\nkprobe_events_writable=0\nsystemd=1\nthermal=1\ncpufreq=0\nrapl=0\nprobe_tools=0\n";
        let caps = parse_report(report);
        assert!(caps.supports("cgroup_v2"));
        assert!(caps.supports("btf"));
        assert!(!caps.supports("psi"));
        assert!(!caps.supports("kprobe_events_writable"));
        // bpftool 探测:exit 0 = 找到
        let with_tool = parse_report(&report.replace("probe_tools=0", "probe_tools=0\n"));
        assert!(with_tool.supports("probe_tools"));
        // 缺失键报不可用
        let missing = parse_report("cgroup_v2=1\n");
        assert!(!missing.supports("psi"));
        assert_eq!(missing.get("psi").unwrap().detail, "远端未报告该项");
    }

    #[test]
    fn supports_and_unavailable() {
        let caps = HostCapabilities {
            items: vec![
                CapItem { name: "psi", ok: true, detail: "x".into() },
                CapItem { name: "btf", ok: false, detail: "无 BTF".into() },
            ],
        };
        assert!(caps.supports("psi"));
        assert!(!caps.supports("btf"));
        let j = caps.to_json();
        assert_eq!(j["unavailable"], json!(["btf"]));
        assert_eq!(j["items"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn detect_local_never_panics_and_names_are_fixed() {
        let caps = detect_local();
        // 键集合固定且全覆盖（无论平台）
        for n in CAP_NAMES {
            assert!(caps.get(n).is_some(), "缺少探测项 {n}");
        }
        // macOS 上应整组明确不可用并给出原因
        if !std::path::Path::new("/proc").exists() {
            assert!(!caps.supports("cgroup_v2"));
            assert!(caps.get("cgroup_v2").unwrap().detail.contains("非 Linux"));
        }
    }

    #[test]
    fn script_output_shape_matches_parser() {
        // 脚本内每个 echo 的 KEY 都必须在 CAP_NAMES 中；KEY 与 parse_report 对齐
        let mut found = 0;
        for line in capabilities_script().lines() {
            let l = line.trim();
            // 只解析输出行：echo "key=..."（赋值行如 ctrls=... 不算）
            let Some(inner) = l.strip_prefix("echo \"") else {
                continue;
            };
            if let Some(eq) = inner.find('=') {
                let key = inner[..eq].trim();
                assert!(CAP_NAMES.contains(&key), "脚本输出未知键 {key}");
                found += 1;
            }
        }
        assert!(found >= CAP_NAMES.len(), "脚本应覆盖全部 {}/{} 个键", found, CAP_NAMES.len());
    }
}
