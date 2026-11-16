//! 探针数据源：本机直接扫描 /proc；远端经 SSH 扫描后组装同一份 Snapshot。

use monitor_linux::probe::{self, Snapshot};
use monitor_linux::probeclient;
use monitor_remote as remote;

pub fn local_snapshot() -> Snapshot {
    let mut snap = Snapshot::load();
    snap.helper_ready = probeclient::ping().is_ok();
    snap
}

pub fn remote_snapshot(target: &remote::SshTarget) -> Result<Snapshot, String> {
    let scan = remote::probe_scan(target)?;
    let caps = probe::caps_from_scan(
        &scan.config,
        scan.uid,
        scan.cap_eff,
        scan.tracefs_readable,
        scan.kprobe_events_writable,
        scan.debugfs_readable,
        scan.btf_file,
        scan.unprivileged_bpf_disabled,
        &scan.tools,
    );
    let uprobes = probe::uprobes_from_list(&scan.exes);
    let mut errors = Vec::new();
    if scan.kallsyms.is_empty() {
        errors.push("远端 kallsyms 为空（权限或内核限制）".to_string());
    }
    Ok(Snapshot::from_parts(
        scan.kernel_release,
        &scan.kallsyms,
        uprobes,
        caps,
        errors,
        scan.helper_ready,
        scan.sweep_ms,
    ))
}

pub fn snapshot(target: Option<&remote::SshTarget>) -> Result<Snapshot, String> {
    match target {
        Some(t) => remote_snapshot(t),
        None => Ok(local_snapshot()),
    }
}

/// 探针命令传输：本地 UnixSocket / 远端 SSH `probe-helper --one-shot`。
pub fn exchange(target: Option<&remote::SshTarget>, cmd: &str) -> Result<String, String> {
    match target {
        Some(t) => remote::probe_exchange(t, cmd),
        None => probeclient::local_transport(cmd),
    }
}