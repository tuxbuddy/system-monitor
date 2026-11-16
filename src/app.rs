use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, Margin, Pos2, RichText, Stroke, Vec2};
use egui_extras::{Column, TableBuilder};
use nix::sys::signal::Signal;

use crate::actions::{self, ActionError};
use crate::cgroup::{self, CgroupManager, GroupState};
use crate::config::{self, AppConfig};
use crate::pi::{self, PiStats};
use crate::platform;
use crate::remote;
use crate::probe;
use crate::probeclient;
use crate::procstats::{self, FsUsage, NetConn, ProcDetails, ProcUsage, Sampler, Usage, app_groups, format_uptime, read_cmdline, read_details, read_filesystems, read_net_conns, tree_order};
use crate::scheduler::{self, Action as SchedAction, Config as SchedConfig, Snapshot as SchedSnapshot, State as SchedState};
use crate::theme;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortCol {
    Cpu,
    Mem,
    MemPct,
    Pid,
    Ppid,
    Name,
    User,
    Nice,
    State,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Monitor,
    Scheduler,
    Performance,
    Network,
    Probe,
    Overview,
}

/// 主视图顺序：日常监控优先，调试类（总览/探针）靠后。
const NAV_ITEMS: [(View, &str, &str); 6] = [
    (View::Monitor, "监控", "进程列表与实时资源占用"),
    (View::Scheduler, "调度", "cgroup 限额、自动分组与温度/功耗自动节流"),
    (View::Performance, "性能", "最近两分钟的趋势大盘"),
    (View::Network, "网络", "连接明细与上下行吞吐"),
    (View::Overview, "总览", "本地 + SSH 主机的资源概览"),
    (View::Probe, "探针", "内核 / 用户态挂载点与参数追踪（调试工具）"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum TableMode {
    Flat,
    Tree,
    Apps,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfirmKind {
    Terminate,
    Kill,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeMode {
    Functions,
    Syscalls,
    Uprobe,
}

#[derive(Clone, PartialEq)]
enum ProbeSel {
    Kprobe(String),
    Uprobe { exe: PathBuf, sym: String },
}

struct Confirm {
    kind: ConfirmKind,
    pid: i32,
    comm: String,
    cmdline: String,
    tree: bool,
}

struct NiceDialog {
    pid: i32,
    comm: String,
    value: i32,
}

#[derive(Clone)]
struct AutoRule {
    pattern: String,
    group: String,
    pct: Option<u32>,
}

#[derive(Clone, Default)]
struct SharedMetrics {
    cpu: f32,
    mem: f32,
    temp: f32,
    power: f32,
    gpu: f32,
    disk_r: f32,
    disk_w: f32,
    net_rx: f32,
    net_tx: f32,
    procs: usize,
}

const HIST_CAP: usize = 120;

#[derive(Default)]
struct PerfHistory {
    cpu: VecDeque<f32>,
    mem: VecDeque<f32>,
    temp: VecDeque<f32>,
    power: VecDeque<f32>,
    disk_r: VecDeque<f32>,
    disk_w: VecDeque<f32>,
    net_rx: VecDeque<f32>,
    net_tx: VecDeque<f32>,
    gpu: VecDeque<f32>,
}

impl PerfHistory {
    fn push(dq: &mut VecDeque<f32>, v: f32) {
        dq.push_back(v);
        if dq.len() > HIST_CAP {
            dq.pop_front();
        }
    }

    fn record(&mut self, u: &Usage, pi: &PiStats) {
        let mem = u
            .mem
            .map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 })
            .unwrap_or(0.0);
        self.push_sample([
            u.total_percent,
            mem,
            pi.temp_c.unwrap_or(0.0),
            pi.power.map(|p| p.core_w).unwrap_or(0.0),
            pi.gpu.v3d_ghz.or(pi.gpu.temp_c).unwrap_or(0.0),
            u.disk_read_bps / 1024.0,
            u.disk_write_bps / 1024.0,
            u.net_rx_bps / 1024.0,
            u.net_tx_bps / 1024.0,
        ]);
    }

    fn push_sample(&mut self, v: [f32; 9]) {
        Self::push(&mut self.cpu, v[0]);
        Self::push(&mut self.mem, v[1]);
        Self::push(&mut self.temp, v[2]);
        Self::push(&mut self.power, v[3]);
        Self::push(&mut self.gpu, v[4]);
        Self::push(&mut self.disk_r, v[5]);
        Self::push(&mut self.disk_w, v[6]);
        Self::push(&mut self.net_rx, v[7]);
        Self::push(&mut self.net_tx, v[8]);
    }
}

pub struct CpuManagerApp {
    sampler: Sampler,
    usage: Usage,
    last_sample: Instant,
    filter: String,
    sort_col: SortCol,
    sort_desc: bool,
    selected: Option<i32>,
    confirm: Option<Confirm>,
    nice_dialog: Option<NiceDialog>,
    status: String,
    status_error: bool,
    own_pid: i32,
    paused: bool,
    interval: f32,
    cmdline_cache: Option<(i32, String)>,
    pi: PiStats,
    view: View,
    mgr: Option<CgroupManager>,
    cg_error: Option<String>,
    groups: Vec<GroupState>,
    new_group: String,
    sel_group: Option<String>,
    sched: SchedConfig,
    sched_state: SchedState,
    original_of: std::collections::HashMap<i32, PathBuf>,
    table_mode: TableMode,
    own_only: bool,
    own_uid: u32,
    details: Option<(ProcUsage, ProcDetails)>,
    perf: PerfHistory,
    filesystems: Vec<FsUsage>,
    net_conns: Vec<NetConn>,
    net_filter: String,
    auto_enabled: bool,
    auto_rules: Vec<AutoRule>,
    auto_skip: std::collections::HashSet<i32>,
    new_auto_pattern: String,
    new_auto_group: String,
    new_auto_pct: Option<u32>,
    last_hist: Instant,
    shared: Arc<Mutex<SharedMetrics>>,
    mini: bool,
    platform_edit: Option<String>,
    hosts: Vec<remote::SshTarget>,
    host_sel: Option<remote::SshTarget>,
    add_host: Option<String>,
    remote_shared: Arc<Mutex<remote::RemoteSlot>>,
    remote_prev: Arc<Mutex<Option<remote::Counters>>>,
    remote_inflight: Arc<Mutex<bool>>,
    last_remote_kick: Instant,
    fleet: Arc<Mutex<HashMap<String, remote::FleetSummary>>>,
    fleet_hosts: Arc<Mutex<Vec<remote::SshTarget>>>,
    local_view: Option<(Usage, PiStats)>,
    remote_write: bool,
    remote_cg_base: Option<(String, String)>,
    alert_cpu: f32,
    alert_mem: f32,
    alert_temp: f32,
    dash_open: bool,
    saved_cfg: AppConfig,
    probe: Option<probe::Snapshot>,
    probe_rx: Option<std::sync::mpsc::Receiver<probe::Snapshot>>,
    probe_query: String,
    probe_mode: ProbeMode,
    probe_sel: Option<ProbeSel>,
    probe_sel_exe: Option<PathBuf>,
    probe_elf: std::collections::HashMap<PathBuf, Result<probe::ElfSymbols, String>>,
    probe_armed: Option<ProbeSel>,
    probe_armed_stack: bool,
    probe_stack: bool,
    probe_hits: u64,
    probe_recent: Vec<probeclient::Call>,
    probe_agent_err: Option<String>,
    probe_poll_at: Instant,
    probe_uprobe_ok: Option<bool>,
    probe_args: String,
    probe_pid: String,
    probe_test_cmd: String,
    probe_test_child: Option<std::process::Child>,
    probe_armed_pid: Option<u32>,
    /// 历史写入失败的一次性报告（同错误不重复提示）。
    hist_err: Option<String>,
    /// 调度熔断告警只提示一次，重新启用后复位。
    sched_halt_warned: bool,
}

impl CpuManagerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_fonts(&cc.egui_ctx);
        theme::apply(&cc.egui_ctx);
        let cfg = config::load();
        let (mgr, cg_error) = match CgroupManager::detect() {
            Ok(m) => (Some(m), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let shared = Arc::new(Mutex::new(SharedMetrics::default()));
        start_metrics_server(shared.clone());
        let (hosts, hosts_errors) = remote::load_hosts();
        let hosts_warn = if hosts_errors.is_empty() {
            None
        } else {
            Some(format!(
                "hosts.conf 有 {} 行非法目标（已忽略）：{}",
                hosts_errors.len(),
                hosts_errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("；")
            ))
        };
        let fleet: Arc<Mutex<HashMap<String, remote::FleetSummary>>> = Arc::new(Mutex::new(HashMap::new()));
        let fleet_hosts = Arc::new(Mutex::new(hosts.clone()));
        start_fleet_poller(fleet.clone(), fleet_hosts.clone());
        let mut app = Self {
            sampler: Sampler::new(),
            usage: Usage::default(),
            last_sample: Instant::now(),
            filter: String::new(),
            sort_col: sort_col_from(&cfg.sort_col),
            sort_desc: cfg.sort_desc,
            selected: None,
            confirm: None,
            nice_dialog: None,
            status: "就绪".to_string(),
            status_error: false,
            own_pid: std::process::id() as i32,
            paused: false,
            interval: cfg.interval,
            cmdline_cache: None,
            pi: PiStats::default(),
            view: View::Monitor,
            mgr,
            cg_error,
            groups: Vec::new(),
            new_group: String::new(),
            sel_group: None,
            sched: SchedConfig::default(),
            sched_state: SchedState::default(),
            original_of: std::collections::HashMap::new(),
            table_mode: table_mode_from(&cfg.table_mode),
            own_only: cfg.own_only,
            own_uid: unsafe { libc::getuid() },
            details: None,
            perf: PerfHistory::default(),
            filesystems: Vec::new(),
            net_conns: Vec::new(),
            net_filter: String::new(),
            auto_enabled: false,
            auto_rules: Vec::new(),
            auto_skip: std::collections::HashSet::new(),
            new_auto_pattern: String::new(),
            new_auto_group: String::new(),
            new_auto_pct: Some(50),
            last_hist: Instant::now(),
            shared,
            mini: false,
            platform_edit: None,
            hosts: hosts.clone(),
            host_sel: None,
            add_host: None,
            remote_shared: Arc::new(Mutex::new(remote::RemoteSlot::new())),
            remote_prev: Arc::new(Mutex::new(None)),
            remote_inflight: Arc::new(Mutex::new(false)),
            last_remote_kick: Instant::now(),
            fleet,
            fleet_hosts,
            local_view: None,
            remote_write: false,
            remote_cg_base: None,
            alert_cpu: cfg.alert_cpu,
            alert_mem: cfg.alert_mem,
            alert_temp: cfg.alert_temp,
            dash_open: cfg.dash_open,
            saved_cfg: cfg,
            probe: None,
            probe_rx: None,
            probe_query: String::new(),
            probe_mode: ProbeMode::Functions,
            probe_sel: None,
            probe_sel_exe: None,
            probe_elf: std::collections::HashMap::new(),
            probe_armed: None,
            probe_armed_stack: false,
            probe_stack: false,
            probe_hits: 0,
            probe_recent: Vec::new(),
            probe_agent_err: None,
            probe_poll_at: Instant::now(),
            probe_uprobe_ok: None,
            probe_args: String::new(),
            probe_pid: String::new(),
            probe_test_cmd: String::new(),
            probe_test_child: None,
            probe_armed_pid: None,
            hist_err: None,
            sched_halt_warned: false,
        };
        app.saved_cfg = app.current_config();
        if let Some(w) = hosts_warn {
            app.status_error = true;
            app.status = w;
        }
        load_history_into(&mut app.perf);
        app.resample();
        app
    }

    fn resample(&mut self) {
        if let Some(target) = self.host_sel.clone() {
            self.resample_remote(&target);
            return;
        }
        self.usage = self.sampler.sample();
        self.pi = pi::read_pi_stats();
        self.local_view = Some((self.usage.clone(), self.pi.clone()));
        self.perf.record(&self.usage, &self.pi);
        if self.last_hist.elapsed() >= Duration::from_secs(30) {
            self.last_hist = Instant::now();
            self.append_history();
        }
        let mem_pct_now = self
            .usage
            .mem
            .map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 })
            .unwrap_or(0.0);
        if let Ok(mut m) = self.shared.lock() {
            *m = SharedMetrics {
                cpu: self.usage.total_percent,
                mem: mem_pct_now,
                temp: self.pi.temp_c.unwrap_or(0.0),
                power: self.pi.power.map(|p| p.core_w).unwrap_or(0.0),
                gpu: self.pi.gpu.v3d_ghz.unwrap_or(0.0),
                disk_r: self.usage.disk_read_bps / 1024.0,
                disk_w: self.usage.disk_write_bps / 1024.0,
                net_rx: self.usage.net_rx_bps / 1024.0,
                net_tx: self.usage.net_tx_bps / 1024.0,
                procs: self.usage.procs.len(),
            };
        }
        self.filesystems = read_filesystems();
        self.net_conns = read_net_conns();
        self.refresh_groups();
        self.run_scheduler();
        self.last_sample = Instant::now();
        if let Some(pid) = self.selected
            && !self.usage.procs.iter().any(|p| p.pid == pid)
        {
            self.selected = None;
        }
        let live: std::collections::HashSet<i32> = self.usage.procs.iter().map(|p| p.pid).collect();
        self.original_of.retain(|pid, _| live.contains(pid));
        self.auto_skip.retain(|pid| live.contains(pid));
        self.apply_auto_groups();
    }

    fn apply_auto_groups(&mut self) {
        if !self.auto_enabled || self.mgr.is_none() || self.auto_rules.is_empty() || self.host_sel.is_some() {
            return;
        }
        let mut plan: Vec<(i32, String, Option<u32>)> = Vec::new();
        for p in &self.usage.procs {
            if p.uid != self.own_uid || p.pid == self.own_pid || p.pid == 1 {
                continue;
            }
            if self.original_of.contains_key(&p.pid) || self.auto_skip.contains(&p.pid) {
                continue;
            }
            if let Some(rule) = self.auto_rules.iter().find(|r| !r.pattern.is_empty() && p.comm.contains(&r.pattern)) {
                plan.push((p.pid, rule.group.clone(), rule.pct));
            }
        }
        if plan.is_empty() {
            return;
        }
        let mut moved: Vec<(i32, PathBuf)> = Vec::new();
        if let Some(mgr) = &self.mgr {
            for (pid, group, pct) in plan {
                if mgr.group_of(pid).is_some() {
                    continue;
                }
                if !self.groups.iter().any(|g| g.name == group) {
                    let _ = mgr.create_group(&group);
                    let _ = mgr.set_cpu_max(&group, pct);
                }
                if let Ok(orig) = mgr.move_in(&group, pid) {
                    moved.push((pid, orig));
                }
            }
        }
        if !moved.is_empty() {
            for (pid, orig) in moved {
                self.original_of.insert(pid, orig);
            }
            self.refresh_groups();
        }
    }

    fn resample_remote(&mut self, target: &remote::SshTarget) {
        // 代次化采样：槽绑定 host+generation，过期线程的回写被丢弃；
        // 旧主机任务在途不阻塞新主机启动采样。
        let key = target.as_str().to_string();
        let mut ticket;
        let mut need_kick = false;
        if let Ok(mut slot) = self.remote_shared.lock() {
            if slot.host != key {
                ticket = slot.reset_for(&key);
                need_kick = true; // 主机切换：立即启动采样，不等节流窗口
            } else {
                ticket = slot.generation;
                let inflight = self.remote_inflight.lock().map(|g| *g).unwrap_or(false);
                if self.last_remote_kick.elapsed() >= Duration::from_secs(2) && !inflight {
                    need_kick = true;
                }
            }
            if need_kick {
                ticket = slot.reset_for(&key); // 递增代次作为本次回写凭证
            }
        } else {
            ticket = 0;
        }
        if need_kick {
            self.last_remote_kick = Instant::now();
            if let Ok(mut f) = self.remote_inflight.lock() {
                *f = true;
            }
            let shared = self.remote_shared.clone();
            let prev = self.remote_prev.clone();
            let inflight = self.remote_inflight.clone();
            let t = target.clone();
            let kick_key = key.clone();
            std::thread::spawn(move || {
                let mut p = prev.lock().ok().and_then(|mut g| g.take());
                let res = remote::collect(&t, &mut p);
                if let Ok(mut g) = prev.lock() {
                    *g = p;
                }
                // 校验 host+generation 后写入；主机已切换则丢弃
                if let Some(sample) = res
                    && let Ok(mut s) = shared.lock()
                {
                    s.accept(&kick_key, ticket, sample);
                }
                if let Ok(mut f) = inflight.lock() {
                    *f = false;
                }
            });
        }
        let sample = self
            .remote_shared
            .lock()
            .ok()
            .and_then(|s| s.current(&key).cloned());
        if let Some(s) = sample {
            self.usage = s.usage;
            self.pi = s.pi;
            self.filesystems = s.filesystems;
            self.net_conns = s.conns;
            self.perf.record(&self.usage, &self.pi);
        } else {
            self.filesystems.clear();
            self.net_conns.clear();
        }
        self.last_sample = Instant::now();
        if let Some(pid) = self.selected
            && !self.usage.procs.iter().any(|p| p.pid == pid)
        {
            self.selected = None;
        }
        let mem_pct_now = self
            .usage
            .mem
            .map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 })
            .unwrap_or(0.0);
        if let Ok(mut m) = self.shared.lock() {
            *m = SharedMetrics {
                cpu: self.usage.total_percent,
                mem: mem_pct_now,
                temp: self.pi.temp_c.unwrap_or(0.0),
                power: self.pi.power.map(|p| p.core_w).unwrap_or(0.0),
                gpu: self.pi.gpu.v3d_ghz.unwrap_or(0.0),
                disk_r: self.usage.disk_read_bps / 1024.0,
                disk_w: self.usage.disk_write_bps / 1024.0,
                net_rx: self.usage.net_rx_bps / 1024.0,
                net_tx: self.usage.net_tx_bps / 1024.0,
                procs: self.usage.procs.len(),
            };
        }
    }

    fn report(&mut self, result: Result<(), ActionError>, ok_msg: String) {
        self.status_error = result.is_err();
        self.status = match &result {
            Ok(()) => ok_msg,
            Err(e) => e.to_string(),
        };
        if matches!(result, Err(ActionError::Gone)) {
            self.resample();
        }
    }

    /// 当前视角下的「我自己」：本机为登录 uid，远端为 SSH 登录 uid。
    fn active_uid(&self) -> u32 {
        self.pi.remote.as_ref().map(|r| r.uid).unwrap_or(self.own_uid)
    }

    fn remote_err(e: String) -> ActionError {
        if e.contains("No such process") {
            ActionError::Gone
        } else if e.contains("Operation not permitted") || e.contains("Permission denied") {
            ActionError::Permission
        } else {
            ActionError::Other(e)
        }
    }

    /// 暂停 / 恢复：远端主机走 SSH kill，本机走 nix。
    fn act_pause(&mut self, pid: i32, stopped: bool, comm: &str) {
        let r = match self.host_sel.clone() {
            Some(h) => remote::signal(&h, pid, if stopped { libc::SIGCONT } else { libc::SIGSTOP }).map_err(Self::remote_err),
            None => {
                if stopped {
                    actions::resume(pid)
                } else {
                    actions::stop(pid)
                }
            }
        };
        let verb = if stopped { "恢复" } else { "暂停" };
        let where_ = if self.host_sel.is_some() { "（远端）" } else { "" };
        self.report(r, format!("已{verb}进程 {pid}（{comm}）{where_}"));
    }

    fn act_signal(&mut self, pid: i32, sig: Signal, label: &str) {
        let r = match self.host_sel.clone() {
            Some(h) => remote::signal(&h, pid, sig as i32).map_err(Self::remote_err),
            None => actions::send_signal(pid, sig),
        };
        let where_ = if self.host_sel.is_some() { "（远端）" } else { "" };
        self.report(r, format!("已向进程 {pid} 发送 {label}{where_}"));
    }

    /// 结束 / 强制结束 / 结束进程树；返回 (结果, 成功个数)。
    fn act_finish(&mut self, kind: ConfirmKind, pid: i32, tree: bool) -> (Result<(), ActionError>, usize) {
        let sig = if kind == ConfirmKind::Kill { libc::SIGKILL } else { libc::SIGTERM };
        if let Some(h) = self.host_sel.clone() {
            if tree {
                let pairs: Vec<(i32, i32)> = self.usage.procs.iter().map(|p| (p.pid, p.ppid)).collect();
                let mut pids = procstats::descendants(pid, &pairs);
                pids.push(pid);
                return match remote::signal_many(&h, &pids, sig) {
                    Ok(n) => (Ok(()), n),
                    Err(e) => (Err(Self::remote_err(e)), 0),
                };
            }
            return match remote::signal(&h, pid, sig) {
                Ok(()) => (Ok(()), 1),
                Err(e) => (Err(Self::remote_err(e)), 0),
            };
        }
        let r = if kind == ConfirmKind::Kill {
            if tree { actions::kill_tree(pid).map(|_| ()) } else { actions::kill_force(pid) }
        } else if tree {
            actions::terminate_tree(pid).map(|_| ())
        } else {
            actions::terminate(pid)
        };
        (r, 1)
    }

    fn act_set_nice(&mut self, pid: i32, value: i32, comm: &str) {
        let r = match self.host_sel.clone() {
            Some(h) => remote::set_nice(&h, pid, value).map_err(Self::remote_err),
            None => actions::set_nice(pid, value),
        };
        let where_ = if self.host_sel.is_some() { "（远端）" } else { "" };
        self.report(r, format!("已将进程 {pid}（{comm}）的 nice 调整为 {value}{where_}"));
    }

    fn copy_cmdline(&mut self, pid: i32, comm: &str) -> String {
        let mut c = match self.host_sel.clone() {
            Some(h) => remote::read_cmdline(&h, pid).unwrap_or_default(),
            None => read_cmdline(pid),
        };
        if c.is_empty() {
            c = format!("[{comm}]");
        }
        c
    }

    fn open_details(&mut self, p: &ProcUsage) {
        let d = match self.host_sel.clone() {
            Some(h) => remote::read_details(&h, p.pid).unwrap_or_default(),
            None => read_details(p.pid),
        };
        self.details = Some((p.clone(), d));
    }

    fn refresh_groups(&mut self) {
        if let Some(h) = self.host_sel.clone() {
            if !self.remote_write {
                self.groups.clear();
                return;
            }
            let base = self.remote_cg_base_for(&h);
            self.groups = match base {
                Some(b) => remote::cg_list(&h, &b),
                None => Vec::new(),
            };
            return;
        }
        if let Some(m) = &self.mgr {
            self.groups = m.list_groups().unwrap_or_default();
        } else {
            self.groups.clear();
        }
    }

    fn remote_cg_base_for(&mut self, host: &remote::SshTarget) -> Option<String> {
        if let Some((h, b)) = &self.remote_cg_base
            && h == host.as_str()
        {
            return Some(b.clone());
        }
        let base = remote::cg_base(host)?;
        remote::cg_ensure(host, &base);
        self.remote_cg_base = Some((host.as_str().to_string(), base.clone()));
        Some(base)
    }

    /// 远端写调度就绪时返回 (host, base)。
    fn cg_remote(&mut self) -> Option<(remote::SshTarget, String)> {
        if !self.remote_write {
            return None;
        }
        let h = self.host_sel.clone()?;
        let b = self.remote_cg_base_for(&h)?;
        Some((h, b))
    }

    fn remote_write_host(&self) -> Option<remote::SshTarget> {
        if self.remote_write { self.host_sel.clone() } else { None }
    }

    fn finish_remote(&mut self, ok: bool, ok_msg: String) {
        if ok {
            self.status_error = false;
            self.status = ok_msg;
            self.refresh_groups();
        } else {
            self.status_error = true;
            self.status = "远程操作失败（主机/权限/委派 cgroup）".to_string();
        }
    }

    fn finish_cg(&mut self, res: Option<Result<(), cgroup::CgError>>, ok_msg: String) {
        match res {
            Some(Ok(())) => {
                self.status_error = false;
                self.status = ok_msg;
                self.refresh_groups();
            }
            Some(Err(e)) => {
                self.status_error = true;
                self.status = e.to_string();
            }
            None => {}
        }
    }

    fn do_create_group(&mut self, name: &str) {
        if let Some((h, base)) = self.cg_remote() {
            let ok = remote::cg_create(&h, &base, name);
            if ok {
                self.sel_group = Some(name.to_string());
                self.new_group.clear();
            }
            self.finish_remote(ok, format!("已创建分组 {name}（远程）"));
            return;
        }
        let res = self.mgr.as_ref().map(|m| m.create_group(name));
        self.finish_cg(res, format!("已创建分组 {name}"));
        if !self.status_error {
            self.sel_group = Some(name.to_string());
            self.new_group.clear();
        }
    }

    fn do_set_cpu_max(&mut self, group: &str, pct: Option<u32>) {
        if let Some((h, base)) = self.cg_remote() {
            let ok = remote::cg_set_cpu_max(&h, &base, group, pct);
            let cap = pct.map(|p| format!("{p}%")).unwrap_or_else(|| "不限".into());
            self.finish_remote(ok, format!("分组 {group} CPU 上限 → {cap}（远程）"));
            return;
        }
        let res = self.mgr.as_ref().map(|m| m.set_cpu_max(group, pct));
        let cap = pct.map(|p| format!("{p}%")).unwrap_or_else(|| "不限".into());
        self.finish_cg(res, format!("分组 {group} CPU 上限 → {cap}"));
    }

    fn do_set_cpu_weight(&mut self, group: &str, weight: u32) {
        if let Some((h, base)) = self.cg_remote() {
            let ok = remote::cg_set_weight(&h, &base, group, weight);
            self.finish_remote(ok, format!("分组 {group} 权重 → {weight}（远程）"));
            return;
        }
        let res = self.mgr.as_ref().map(|m| m.set_cpu_weight(group, weight));
        self.finish_cg(res, format!("分组 {group} 权重 → {weight}"));
    }

    fn do_set_pids_max(&mut self, group: &str, max: Option<u32>) {
        if let Some((h, base)) = self.cg_remote() {
            let ok = remote::cg_set_pids(&h, &base, group, max);
            let cap = max.map(|m| m.to_string()).unwrap_or_else(|| "不限".into());
            self.finish_remote(ok, format!("分组 {group} 进程数上限 → {cap}（远程）"));
            return;
        }
        let res = self.mgr.as_ref().map(|m| m.set_pids_max(group, max));
        let cap = max.map(|m| m.to_string()).unwrap_or_else(|| "不限".into());
        self.finish_cg(res, format!("分组 {group} 进程数上限 → {cap}"));
    }

    fn do_join_group(&mut self, group: &str, pid: i32) {
        if let Some((h, base)) = self.cg_remote() {
            match remote::cg_move_in(&h, &base, group, pid) {
                Some(orig) => {
                    self.original_of.insert(pid, PathBuf::from(orig));
                    self.status_error = false;
                    self.status = format!("进程 {pid} 已加入分组 {group}（远程）");
                    self.refresh_groups();
                }
                None => {
                    self.status_error = true;
                    self.status = "远程迁入失败（主机/权限/委派）".to_string();
                }
            }
            return;
        }
        let res = self.mgr.as_ref().map(|m| m.move_in(group, pid));
        match res {
            Some(Ok(orig)) => {
                self.original_of.insert(pid, orig);
                self.status_error = false;
                self.status = format!("进程 {pid} 已加入分组 {group}");
                self.refresh_groups();
            }
            Some(Err(e)) => {
                self.status_error = true;
                self.status = e.to_string();
            }
            None => {}
        }
    }

    fn do_leave_group(&mut self, pid: i32) {
        if let Some(h) = self.remote_write_host() {
            self.auto_skip.insert(pid);
            if let Some(orig) = self.original_of.remove(&pid) {
                let ok = remote::cg_release(&h, &orig.to_string_lossy(), pid);
                self.finish_remote(ok, format!("进程 {pid} 已移出分组（远程）"));
            }
            return;
        }
        self.auto_skip.insert(pid);
        let Some(orig) = self.original_of.remove(&pid) else {
            return;
        };
        let res = self.mgr.as_ref().map(|m| m.release(pid, &orig));
        self.finish_cg(res, format!("进程 {pid} 已移出分组"));
    }

    fn do_delete_group(&mut self, group: &str) {
        if let Some((h, base)) = self.cg_remote() {
            let ok = remote::cg_delete(&h, &base, group);
            if self.sel_group.as_deref() == Some(group) {
                self.sel_group = None;
            }
            self.finish_remote(ok, format!("已删除分组 {group}（远程）"));
            return;
        }
        let res = self.mgr.as_ref().map(|m| m.delete_group(group));
        if self.sel_group.as_deref() == Some(group) {
            self.sel_group = None;
        }
        self.finish_cg(res, format!("已删除分组 {group}"));
    }

    fn dissolve_all_limits(&mut self) {
        if let Some((h, base)) = self.cg_remote() {
            let names: Vec<String> = self.groups.iter().map(|g| g.name.clone()).collect();
            for n in &names {
                remote::cg_set_cpu_max(&h, &base, n, None);
            }
            let origs: Vec<(i32, PathBuf)> = self.original_of.drain().collect();
            for (pid, orig) in &origs {
                remote::cg_release(&h, &orig.to_string_lossy(), *pid);
            }
            self.status_error = false;
            self.status = "已解除全部限速（远程）".to_string();
            self.refresh_groups();
            return;
        }
        let names: Vec<String> = self.groups.iter().map(|g| g.name.clone()).collect();
        if let Some(m) = &self.mgr {
            for n in &names {
                let _ = m.set_cpu_max(n, None);
            }
        }
        let originals: Vec<(i32, PathBuf)> = self.original_of.drain().collect();
        if let Some(m) = &self.mgr {
            for (pid, orig) in &originals {
                let _ = m.release(*pid, orig);
            }
        }
        self.status_error = false;
        self.status = "已解除全部限速".to_string();
        self.refresh_groups();
    }

    fn append_history(&mut self) {
        let Some(p) = history_path() else {
            return;
        };
        let mem = self
            .usage
            .mem
            .map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 })
            .unwrap_or(0.0);
        let line = format!(
            "{:.1},{:.1},{:.1},{:.2},{:.2},{:.1},{:.1},{:.1},{:.1}",
            self.usage.total_percent,
            mem,
            self.pi.temp_c.unwrap_or(0.0),
            self.pi.power.map(|p| p.core_w).unwrap_or(0.0),
            self.pi.gpu.v3d_ghz.unwrap_or(0.0),
            self.usage.disk_read_bps / 1024.0,
            self.usage.disk_write_bps / 1024.0,
            self.usage.net_rx_bps / 1024.0,
            self.usage.net_tx_bps / 1024.0,
        );
        // 原子目录 + 单行上限 + 大小轮转（5 MB × 3 份），失败只报告一次不刷屏
        if let Err(e) = crate::fsutil::append_line_capped(&p, &line, 5 * 1024 * 1024, 3, 4096)
            && self.hist_err.as_ref().is_none_or(|prev| prev != &e.to_string())
        {
            self.hist_err = Some(e.to_string());
        }
    }

    fn select_host(&mut self, sel: Option<String>) {
        // UI 传来的字符串在此边界一次性校验；非法目标不进入任何远端调用
        let parsed = sel.map(|s| remote::SshTarget::parse(&s)).transpose();
        self.host_sel = match parsed {
            Ok(t) => t,
            Err(e) => {
                self.status_error = true;
                self.status = format!("主机目标非法：{e}");
                return;
            }
        };
        self.remote_cg_base = None;
        self.pi = PiStats::default();
        self.usage = Usage::default();
        self.filesystems.clear();
        self.net_conns.clear();
        self.cmdline_cache = None;
        if let Ok(mut s) = self.remote_shared.lock() {
            s.sample = None; // 代次清零：任何在途回写都因 host 不匹配被丢弃
        }
        if let Ok(mut p) = self.remote_prev.lock() {
            *p = None;
        }
        self.last_remote_kick = Instant::now() - Duration::from_secs(5);
        self.status_error = false;
        self.status = match &self.host_sel {
            Some(h) => format!("远程监视：{h}（监视只读；结束进程/信号/优先级等操作按远端执行）"),
            None => "已切回本地".to_string(),
        };
        self.view = View::Monitor;
    }

    fn switch_os(&mut self, os: &str) {
        let text = platform::to_text(&platform::builtin(os));
        match platform::save_text(&text) {
            Ok(()) => {
                platform::reload();
                self.status_error = false;
                self.status = format!("已切换到系统档案：{os}");
            }
            Err(e) => {
                self.status_error = true;
                self.status = format!("切换失败：{e}");
            }
        }
    }

    fn export_snapshot(&mut self) {
        let Some(home) = std::env::var_os("HOME") else {
            self.status_error = true;
            self.status = "导出失败：无 HOME".into();
            return;
        };
        let dir = PathBuf::from(home).join(".local/share/system-monitor");
        let _ = std::fs::create_dir_all(&dir);
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = dir.join(format!("snapshot-{secs}.csv"));
        let mut out = String::from("pid,ppid,comm,user,state,cpu_percent,rss_kb,mem_percent,nice\n");
        for p in &self.usage.procs {
            out.push_str(&format!(
                "{},{},\"{}\",{},{},{:.1},{},{:.1},{}\n",
                p.pid,
                p.ppid,
                p.comm.replace('"', "'"),
                p.user,
                p.state,
                p.cpu_percent,
                p.rss_kb,
                p.mem_percent,
                p.nice
            ));
        }
        match std::fs::write(&path, out) {
            Ok(()) => {
                self.status_error = false;
                self.status = format!("已导出快照：{}", path.display());
            }
            Err(e) => {
                self.status_error = true;
                self.status = format!("导出失败：{e}");
            }
        }
    }

    /// 执行调度动作并返回写入是否成功（供调度状态机 commit）。
    fn apply_sched_action(&mut self, act: SchedAction) -> bool {
        let (group, pct, verb) = match act {
            SchedAction::Engage { group, pct } => (group, Some(pct), "自动节流"),
            SchedAction::Restore { group } => (group, None, "自动恢复"),
        };
        let res = self.mgr.as_ref().map(|m| m.set_cpu_max(&group, pct));
        let cap = pct.map(|p| format!(" → {p}%")).unwrap_or_default();
        let ok = matches!(res, Some(Ok(())));
        self.finish_cg(res, format!("{verb}：分组 {group}{cap}"));
        ok
    }

    fn current_config(&self) -> AppConfig {
        AppConfig {
            sort_col: sort_col_key(self.sort_col).to_string(),
            sort_desc: self.sort_desc,
            interval: self.interval,
            table_mode: table_mode_key(self.table_mode).to_string(),
            own_only: self.own_only,
            alert_cpu: self.alert_cpu,
            alert_mem: self.alert_mem,
            alert_temp: self.alert_temp,
            dash_open: self.dash_open,
        }
    }

    fn persist_if_changed(&mut self) {
        let cfg = self.current_config();
        if cfg != self.saved_cfg {
            if let Err(e) = config::save(&cfg) {
                self.status_error = true;
                self.status = format!("配置保存失败：{e}");
            }
            self.saved_cfg = cfg;
        }
    }

    fn run_scheduler(&mut self) {
        if !self.sched.enabled || self.mgr.is_none() || self.host_sel.is_some() {
            return;
        }
        // 熔断告警：提示一次并保持停机，直到用户重新启用
        if self.sched_state.halted {
            if !self.sched_halt_warned {
                self.sched_halt_warned = true;
                self.status_error = true;
                self.status = "自动调度已熔断：连续写入失败，已停止自动动作（可重新启用自动调度以重试）".to_string();
            }
            return;
        }
        let snap = SchedSnapshot {
            temp_c: self.pi.temp_c,
            cpu_percent: self.usage.total_percent,
            throttled: self.pi.throttle.is_some_and(|t| t.any_current()),
            undervoltage: self.pi.throttle.is_some_and(|t| t.undervoltage),
        };
        let now = Instant::now();
        // evaluate 为纯函数；状态只在执行器确认写入成功后 commit
        let actions = scheduler::evaluate(&self.sched, &snap, &self.sched_state, now);
        for a in actions {
            let note = match &a {
                SchedAction::Engage { group, pct } => format!("触发自动节流：分组 {group} → {pct}%"),
                SchedAction::Restore { group } => format!("自动恢复：分组 {group} 解除限速"),
            };
            let committed = a.clone();
            let ok = self.apply_sched_action(a);
            self.sched_state.commit(&committed, ok, Instant::now());
            if ok {
                notify("系统监视器 · 自动节流", &note);
            }
        }
    }

    fn ask_confirm(&mut self, kind: ConfirmKind, pid: i32, comm: &str) {
        self.open_confirm(kind, pid, comm, false);
    }

    fn ask_confirm_tree(&mut self, kind: ConfirmKind, pid: i32, comm: &str) {
        self.open_confirm(kind, pid, comm, true);
    }

    fn open_confirm(&mut self, kind: ConfirmKind, pid: i32, comm: &str, tree: bool) {
        let cmdline = self.copy_cmdline(pid, comm);
        self.confirm = Some(Confirm { kind, pid, comm: comm.to_string(), cmdline, tree });
    }

    fn visible_rows(&self) -> Vec<(ProcUsage, u16)> {
        let f = self.filter.trim();
        let mut rows: Vec<ProcUsage> = self
            .usage
            .procs
            .iter()
            .filter(|p| f.is_empty() || p.comm.contains(f) || p.pid.to_string().contains(f))
            .filter(|p| !self.own_only || p.uid == self.active_uid())
            .cloned()
            .collect();
        match self.table_mode {
            TableMode::Flat => {
                sort_procs(&mut rows, self.sort_col, self.sort_desc);
                rows.into_iter().map(|p| (p, 0)).collect()
            }
            TableMode::Tree => {
                sort_procs(&mut rows, self.sort_col, self.sort_desc);
                let pairs: Vec<(i32, i32)> = rows.iter().map(|p| (p.pid, p.ppid)).collect();
                let mut taken: Vec<Option<ProcUsage>> = rows.into_iter().map(Some).collect();
                let mut out = Vec::with_capacity(pairs.len());
                for (idx, depth) in tree_order(&pairs) {
                    if let Some(p) = taken[idx].take() {
                        out.push((p, depth));
                    }
                }
                out
            }
            TableMode::Apps => {
                let mut apps = app_groups(&rows);
                sort_procs(&mut apps, self.sort_col, self.sort_desc);
                apps.into_iter().map(|p| (p, 0)).collect()
            }
        }
    }

    fn active_alerts(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.usage.total_percent >= self.alert_cpu {
            v.push(format!("CPU {:.0}%", self.usage.total_percent));
        }
        let mem_pct = self
            .usage
            .mem
            .map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 })
            .unwrap_or(0.0);
        if mem_pct >= self.alert_mem {
            v.push(format!("内存 {mem_pct:.0}%"));
        }
        if let Some(t) = self.pi.temp_c
            && t >= self.alert_temp
        {
            v.push(format!("温度 {t:.0}°C"));
        }
        v
    }

    fn handle_keys(&mut self, ui: &mut egui::Ui) {
        let modal_open = self.confirm.is_some() || self.nice_dialog.is_some() || self.details.is_some() || self.platform_edit.is_some() || self.add_host.is_some();
        let typing = ui.ctx().text_edit_focused();
        // Esc：先关弹窗，再清搜索，最后清选中
        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            if modal_open {
                self.confirm = None;
                self.nice_dialog = None;
                self.details = None;
                self.platform_edit = None;
                self.add_host = None;
            } else if !self.filter.is_empty() {
                self.filter.clear();
            } else {
                self.selected = None;
            }
        }
        // Ctrl/Cmd+F：聚焦搜索框
        if ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::F)) {
            ui.ctx().memory_mut(|m| m.request_focus(egui::Id::unique("proc_search")));
        }
        if modal_open {
            return;
        }
        // Ctrl/Cmd+1..6：切换主视图（与导航顺序一致）
        if ui.input(|i| i.modifiers.command) {
            for (n, (view, ..)) in NAV_ITEMS.iter().enumerate() {
                let key = match n {
                    0 => egui::Key::Num1,
                    1 => egui::Key::Num2,
                    2 => egui::Key::Num3,
                    3 => egui::Key::Num4,
                    4 => egui::Key::Num5,
                    _ => egui::Key::Num6,
                };
                if ui.input(|i| i.key_pressed(key)) {
                    self.view = *view;
                }
            }
        }
        if ui.input(|i| i.key_pressed(egui::Key::F5)) {
            self.resample();
        }
        if !typing && ui.input(|i| i.key_pressed(egui::Key::Space)) {
            self.paused = !self.paused;
        }
        if !typing
            && ui.input(|i| i.key_pressed(egui::Key::Delete))
            && let Some(pid) = self.selected
            && (self.host_sel.is_some() || pid != self.own_pid)
            && pid != 1
            && let Some(comm) = self.usage.procs.iter().find(|p| p.pid == pid).map(|p| p.comm.clone())
        {
            self.ask_confirm(ConfirmKind::Terminate, pid, &comm);
        }
        if !typing {
            let down = ui.input(|i| i.key_pressed(egui::Key::ArrowDown));
            let up = ui.input(|i| i.key_pressed(egui::Key::ArrowUp));
            if down || up {
                let pids: Vec<i32> = self.visible_rows().iter().map(|(p, _)| p.pid).collect();
                self.selected = step_pid(&pids, self.selected, down);
            }
        }
    }

    fn set_mini(&mut self, ctx: &egui::Context, on: bool) {
        self.mini = on;
        if on {
            ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(Vec2::new(320.0, 150.0)));
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(Vec2::new(380.0, 184.0)));
            ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(egui::WindowLevel::AlwaysOnTop));
        } else {
            ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(egui::WindowLevel::Normal));
            ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(Vec2::new(1000.0, 640.0)));
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(Vec2::new(1280.0, 880.0)));
        }
    }

    fn mini_hud(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let (d, _) = ui.allocate_exact_size(Vec2::new(10.0, 10.0), egui::Sense::hover());
                ui.painter().circle_filled(d.center(), 4.0, if self.paused { theme::WARNING } else { theme::SUCCESS });
                ui.label(RichText::new("系统监视器").size(12.5).strong().color(theme::TEXT));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if action_btn(ui, "还原", theme::TEXT_SEC, true, false) {
                        self.set_mini(ui.ctx(), false);
                    }
                });
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                self.mini_stat(ui, "CPU", &format!("{:.0}%", self.usage.total_percent), theme::heat_color(self.usage.total_percent / 100.0));
                ui.add_space(12.0);
                let t = self.pi.temp_c.unwrap_or(0.0);
                self.mini_stat(ui, "温度", &format!("{t:.0}°C"), theme::temp_color(t));
                ui.add_space(12.0);
                self.mini_stat(ui, "GPU", &format!("{:.2}", self.pi.gpu.v3d_ghz.unwrap_or(0.0)), theme::GPU);
                ui.add_space(12.0);
                self.mini_stat(ui, "功耗", &format!("{:.1}W", self.pi.power.map(|p| p.core_w).unwrap_or(0.0)), theme::POWER);
            });
        });
    }

    fn mini_stat(&self, ui: &mut egui::Ui, label: &str, val: &str, color: Color32) {
        ui.vertical(|ui| {
            ui.label(RichText::new(label).size(10.0).color(theme::TEXT_MUTED));
            ui.label(RichText::new(val).size(18.0).monospace().strong().color(color));
        });
    }

    /// 细长实时指标条：非监控页（或大盘收起时）保留一眼可见的关键数值。
    fn vitals_strip(&self, ui: &mut egui::Ui) {
        let cpu = self.usage.total_percent;
        let mem_pct = self
            .usage
            .mem
            .map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 });
        let gpu = self
            .pi
            .gpu
            .v3d_ghz
            .map(|g| format!("{g:.2} GHz"))
            .or_else(|| self.pi.gpu.temp_c.map(|t| format!("{t:.0}°C")))
            .unwrap_or_else(|| "—".to_string());
        let rx = self.usage.net_rx_bps / 1024.0;
        let tx = self.usage.net_tx_bps / 1024.0;
        let dr = self.usage.disk_read_bps / 1024.0;
        let dw = self.usage.disk_write_bps / 1024.0;

        egui::Frame::NONE
            .fill(theme::EXTREME)
            .stroke(Stroke::new(1.0, theme::BORDER))
            .corner_radius(8)
            .inner_margin(Margin::symmetric(12, 5))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    vital(ui, "CPU", &format!("{cpu:.1}%"), theme::heat_color(cpu / 100.0));
                    ui.separator();
                    vital(
                        ui,
                        "内存",
                        &mem_pct.map(|p| format!("{p:.0}%")).unwrap_or_else(|| "—".to_string()),
                        theme::MEM,
                    );
                    ui.separator();
                    vital(
                        ui,
                        "温度",
                        &self.pi.temp_c.map(|t| format!("{t:.1}°C")).unwrap_or_else(|| "—".to_string()),
                        self.pi.temp_c.map(theme::temp_color).unwrap_or(theme::TEXT_MUTED),
                    );
                    ui.separator();
                    vital(
                        ui,
                        "功耗",
                        &self.pi.power.map(|p| format!("{:.1} W", p.core_w)).unwrap_or_else(|| "—".to_string()),
                        theme::POWER,
                    );
                    ui.separator();
                    vital(ui, "GPU", &gpu, theme::GPU);
                    ui.separator();
                    vital(ui, "网络", &format!("↓{rx:.0} ↑{tx:.0} KB/s"), theme::SUCCESS);
                    ui.separator();
                    vital(ui, "磁盘", &format!("读{dr:.0} 写{dw:.0} KB/s"), theme::INFO);
                });
            });
    }

    fn top_panel(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let (dot, _) = ui.allocate_exact_size(Vec2::new(10.0, 10.0), egui::Sense::hover());
                let dot_color = if self.paused { theme::WARNING } else { theme::SUCCESS };
                ui.painter().circle_filled(dot.center(), 4.0, dot_color);
                ui.add_space(2.0);
                ui.label(RichText::new("系统监视器").size(20.0).strong().color(theme::TEXT));
                ui.add_space(6.0);
                let (btext, bcolor) = if self.paused { ("已暂停", theme::WARNING) } else { ("实时", theme::SUCCESS) };
                badge(ui, btext, bcolor);
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);
                ui.label(RichText::new("主机").size(11.5).color(theme::TEXT_MUTED));
                let mut hs = self.host_sel.as_ref().map(|t| t.as_str().to_string());
                let hbefore = hs.clone();
                let hcur = hs.clone().unwrap_or_else(|| "本地".to_string());
                egui::ComboBox::from_id_salt("top_host")
                    .selected_text(hcur)
                    .width(150.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut hs, None, "本地");
                        for h in &self.hosts {
                            ui.selectable_value(&mut hs, Some(h.as_str().to_string()), h.as_str());
                        }
                    });
                if hs != hbefore {
                    self.select_host(hs);
                }
                if action_btn(ui, "＋", theme::TEXT_SEC, true, false) {
                    self.add_host = Some(String::new());
                }
                ui.add_space(6.0);
                ui.label(RichText::new("系统").size(11.5).color(theme::TEXT_MUTED));
                if self.host_sel.is_some() {
                    // 远端平台由 /etc/os-release 自动探测，无需也不必手动选档案
                    let os = self.pi.remote.as_ref().map(|r| r.os.clone()).unwrap_or_else(|| "探测中…".to_string());
                    ui.label(RichText::new(os).size(12.5).color(theme::TEXT_SEC)).on_hover_text(
                        "远端操作系统由该主机 /etc/os-release 自动探测；远端采集按能力探测传感器，与本地系统档案无关。",
                    );
                } else {
                    let mut pick = platform::platform().os;
                    let before = pick.clone();
                    egui::ComboBox::from_id_salt("top_os")
                        .selected_text(&pick)
                        .width(128.0)
                        .show_ui(ui, |ui| {
                            for os in platform::KNOWN_OS {
                                ui.selectable_value(&mut pick, (*os).to_string(), *os);
                            }
                        });
                    if pick != before {
                        self.switch_os(&pick);
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if action_btn(ui, "迷你", theme::TEXT_SEC, true, false) {
                        self.set_mini(ui.ctx(), true);
                    }
                    ui.add_space(10.0);
                    let mut parts: Vec<String> = Vec::new();
                    if let Some(l) = self.usage.load {
                        parts.push(format!("负载 {:.2} {:.2} {:.2}", l.one, l.five, l.fifteen));
                    }
                    if let Some(up) = self.usage.uptime_secs {
                        parts.push(format!("运行 {}", format_uptime(up)));
                    }
                    parts.push(format!("{} 进程", self.usage.procs.len()));
                    ui.label(RichText::new(parts.join("  ·  ")).size(12.0).color(theme::TEXT_SEC)).on_hover_text(
                        "系统平均负载（1 / 5 / 15 分钟）。约等于可运行 + 不可中断的进程数；除以核心数可判断是否饱和。",
                    );
                });
            });
            ui.add_space(10.0);
            self.nav_bar(ui);
            let alerts = self.active_alerts();
            if !alerts.is_empty() {
                ui.add_space(9.0);
                egui::Frame::NONE
                    .fill(theme::tint(theme::DANGER, 0.14))
                    .stroke(Stroke::new(1.0, theme::tint(theme::DANGER, 0.45)))
                    .corner_radius(8)
                    .inner_margin(Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.label(RichText::new(format!("告警：{}", alerts.join(" · "))).size(12.5).color(theme::DANGER));
                    });
            }
            let show_cards = self.view == View::Monitor && self.dash_open;
            if show_cards {
                ui.add_space(10.0);
                let gap = 12.0;
                let total = ui.available_width();
                let cw = ((total - 3.0 * gap) / 4.0 - 30.0).max(168.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    self.cpu_card(ui, cw);
                    ui.add_space(gap);
                    self.mem_card(ui, cw);
                    ui.add_space(gap);
                    self.energy_card(ui, cw);
                    ui.add_space(gap);
                    self.gpu_card(ui, cw);
                });
            } else {
                ui.add_space(9.0);
                self.vitals_strip(ui);
            }
            ui.add_space(8.0);
        });
    }

    /// 主视图导航：监控 / 调度 / 性能 / 网络 为主，总览与探针靠后；右侧放全局刷新控制。
    fn nav_bar(&mut self, ui: &mut egui::Ui) {
        let mut next = None;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            for (view, label, tip) in NAV_ITEMS {
                if nav_tab(ui, self.view == view, label).on_hover_text(tip).clicked() {
                    next = Some(view);
                }
                if view == View::Network {
                    ui.add_space(4.0);
                    ui.add(egui::Separator::default().vertical().spacing(14.0));
                    ui.add_space(4.0);
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                egui::ComboBox::from_id_salt("refresh_interval")
                    .selected_text(format!("{:.1} 秒", self.interval))
                    .width(78.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.interval, 0.5, "0.5 秒");
                        ui.selectable_value(&mut self.interval, 1.0, "1 秒");
                        ui.selectable_value(&mut self.interval, 2.0, "2 秒");
                        ui.selectable_value(&mut self.interval, 5.0, "5 秒");
                    });
                ui.label(RichText::new("间隔").size(11.5).color(theme::TEXT_MUTED));
                let (pause_label, pause_color) = if self.paused { ("继续", theme::SUCCESS) } else { ("暂停", theme::WARNING) };
                if action_btn(ui, pause_label, pause_color, true, false) {
                    self.paused = !self.paused;
                }
                if action_btn(ui, "刷新", theme::INFO, true, false) {
                    self.resample();
                }
                ui.add_space(4.0);
                if self.view == View::Monitor {
                    let (dash_label, dash_color) = if self.dash_open { ("收起大盘", theme::TEXT_SEC) } else { ("展开大盘", theme::CPU) };
                    if action_btn(ui, dash_label, dash_color, true, false) {
                        self.dash_open = !self.dash_open;
                    }
                }
            });
        });
        if let Some(v) = next {
            self.view = v;
        }
    }

    fn cpu_card(&self, ui: &mut egui::Ui, w: f32) {
        card(ui, w, 176.0, |ui| {
            let n = self.usage.core_percent.len();
            card_title(ui, theme::CPU, "处理器", &format!("{n} 核"));
            let frac = (self.usage.total_percent / 100.0).clamp(0.0, 1.0);
            let heat = theme::heat_color(frac);
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{:.1}", self.usage.total_percent)).size(32.0).monospace().strong().color(heat))
                    .on_hover_text("整机 CPU 使用率（各核心平均）。颜色随负载升高由灰→青→黄→红。");
                ui.label(RichText::new("%").size(14.0).color(theme::TEXT_SEC));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if n > 0 {
                        let peak = self.usage.core_percent.iter().copied().fold(0.0_f32, f32::max);
                        let avg = self.usage.core_percent.iter().sum::<f32>() / n as f32;
                        ui.label(RichText::new(format!("峰值 {peak:.0}% · 均值 {avg:.0}%")).size(10.5).monospace().color(theme::TEXT_MUTED));
                    }
                });
            });
            ui.add(egui::ProgressBar::new(frac).desired_width(w).desired_height(6.0).fill(heat).corner_radius(3).animate(true));
            self.sparkline(ui, w, 30.0);
            if n > 0 && n <= 8 {
                self.core_detail(ui, w, 13.0);
            } else if n > 8 {
                self.core_strip(ui, w, 26.0);
                egui::CollapsingHeader::new(RichText::new(format!("逐核明细（{n} 核）")).size(11.5).color(theme::TEXT_MUTED))
                    .default_open(false)
                    .show(ui, |ui| self.core_detail(ui, w, 12.0));
            }
        });
    }

    /// 逐核进度条（核心数少时直接展示）。
    fn core_detail(&self, ui: &mut egui::Ui, w: f32, row_h: f32) {
        let n = self.usage.core_percent.len();
        let core_w = (w - 8.0) / 2.0;
        for r in 0..n.div_ceil(2) {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 5.0;
                for c in 0..2 {
                    let i = r * 2 + c;
                    if i >= n {
                        continue;
                    }
                    let p = self.usage.core_percent[i];
                    let pf = (p / 100.0).clamp(0.0, 1.0);
                    let color = theme::heat_color(pf);
                    ui.allocate_ui_with_layout(Vec2::new(core_w, row_h), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.label(RichText::new(format!("核{i}")).size(10.0).color(theme::TEXT_MUTED));
                        ui.add(
                            egui::ProgressBar::new(pf)
                                .desired_width((core_w - 62.0).max(18.0))
                                .desired_height(8.0)
                                .fill(color)
                                .corner_radius(4),
                        );
                        ui.label(RichText::new(format!("{p:.0}%")).size(9.5).monospace().color(color));
                    });
                }
            });
        }
    }

    /// 逐核热力条：无论多少核心都只占一行，悬停可看单核数值。
    fn core_strip(&self, ui: &mut egui::Ui, w: f32, h: f32) {
        let n = self.usage.core_percent.len();
        if n == 0 {
            return;
        }
        let (rect, _) = ui.allocate_exact_size(Vec2::new(w, h), egui::Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, 4.0, theme::EXTREME);
        let gap = if n > 24 { 1.0 } else { 2.0 };
        let bw = ((rect.width() - gap * (n as f32 - 1.0)) / n as f32).max(1.0);
        for (i, &v) in self.usage.core_percent.iter().enumerate() {
            let f = (v / 100.0).clamp(0.0, 1.0);
            let bh = (rect.height() * f).max(2.0);
            let x = rect.left() + i as f32 * (bw + gap);
            let bar = egui::Rect::from_min_max(Pos2::new(x, rect.bottom() - bh), Pos2::new(x + bw, rect.bottom()));
            painter.rect_filled(bar, 1.0, if f < 0.02 { theme::BORDER } else { theme::heat_color(f) });
            ui.interact(
                egui::Rect::from_min_max(Pos2::new(x, rect.top()), Pos2::new(x + bw, rect.bottom())),
                egui::Id::unique(("core_strip", i)),
                egui::Sense::hover(),
            )
            .on_hover_text(format!("核 {i} · {v:.0}%"));
        }
    }

    fn mem_card(&self, ui: &mut egui::Ui, w: f32) {
        card(ui, w, 176.0, |ui| {
            if let Some(m) = self.usage.mem {
                let used_gb = m.used_kb() as f64 / 1048576.0;
                let total_gb = m.total_kb as f64 / 1048576.0;
                let frac = if m.total_kb == 0 { 0.0 } else { (m.used_kb() as f32 / m.total_kb as f32).clamp(0.0, 1.0) };
                card_title(ui, theme::MEM, "内存", &format!("{:.0}%", frac * 100.0));
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{used_gb:.1}")).size(32.0).monospace().strong().color(theme::MEM))
                        .on_hover_text("已用内存 ≈ 总量 − 空闲 − 缓冲 − 缓存。");
                    ui.label(RichText::new(format!("/ {total_gb:.1} GB")).size(14.0).color(theme::TEXT_SEC));
                });
                ui.add(egui::ProgressBar::new(frac).desired_width(w).desired_height(6.0).fill(theme::MEM).corner_radius(3).animate(true));
                let sfrac = if m.swap_total_kb == 0 { 0.0 } else { (m.swap_used_kb() as f32 / m.swap_total_kb as f32).clamp(0.0, 1.0) };
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Swap").size(11.0).color(theme::TEXT_MUTED));
                    ui.add(egui::ProgressBar::new(sfrac).desired_width((w - 142.0).max(36.0)).desired_height(6.0).fill(theme::POWER).corner_radius(3));
                    ui.label(RichText::new(format!("{:.0}/{:.0} MB", m.swap_used_kb() as f64 / 1024.0, m.swap_total_kb as f64 / 1024.0)).size(10.0).monospace().color(theme::TEXT_MUTED));
                });
                ui.label(RichText::new(format!("空闲 {:.0} MB · 缓冲 {:.0} MB · 缓存 {:.0} MB", m.free_kb as f64 / 1024.0, m.buffers_kb as f64 / 1024.0, m.cached_kb as f64 / 1024.0)).size(10.5).color(theme::TEXT_MUTED));
                sparkline_of(ui, w, 24.0, &self.perf.mem, theme::MEM, 100.0, HIST_CAP);
            } else {
                card_title(ui, theme::MEM, "内存", "");
                ui.label(RichText::new("—").color(theme::TEXT_MUTED));
            }
        });
    }

    fn energy_card(&self, ui: &mut egui::Ui, w: f32) {
        card(ui, w, 176.0, |ui| {
            card_title(ui, theme::POWER, "温度 / 功耗", "");
            let remote = self.host_sel.is_some();
            let tcolor = self.pi.temp_c.map(theme::temp_color).unwrap_or(theme::TEXT_MUTED);
            ui.horizontal(|ui| {
                ui.label(RichText::new(self.pi.temp_c.map(|t| format!("{t:.1}")).unwrap_or_else(|| "—".to_string())).size(32.0).monospace().strong().color(tcolor))
                    .on_hover_text(if remote {
                        "主机 CPU 温度（优先 coretemp / k10temp 等 hwmon 传感器）。"
                    } else {
                        "SoC 温度。温度升高由绿转琥珀再转红；树莓派约 85°C 触发降频保护。"
                    });
                ui.label(RichText::new("°C").size(15.0).color(theme::TEXT_SEC));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.vertical(|ui| {
                        if let Some(f) = self.pi.freq_ghz {
                            ui.label(RichText::new(format!("{f:.2} GHz")).size(12.0).monospace().color(theme::CPU));
                        }
                        if let Some(p) = self.pi.power {
                            ui.label(RichText::new(format!("{:.2} W", p.core_w)).size(12.0).monospace().color(theme::POWER))
                                .on_hover_text(if remote {
                                    "整包功耗：Intel RAPL 能量计差分（CPU + 核显）。"
                                } else {
                                    "核心功耗：PMIC 供电轨读数之和。"
                                });
                        }
                        if let Some(g) = self.pi.gpu.v3d_ghz {
                            ui.label(RichText::new(format!("GPU {g:.2} GHz")).size(11.0).monospace().color(theme::TEXT_SEC));
                        } else if let Some(m) = &self.pi.gpu.model {
                            ui.label(RichText::new(m.as_str()).size(11.0).color(theme::TEXT_SEC));
                        }
                    });
                });
            });
            ui.horizontal(|ui| {
                if remote {
                    ui.label(RichText::new("功耗来源").size(12.0).color(theme::TEXT_SEC));
                    let src = if self.pi.power.is_some() { "RAPL 整包能量计" } else { "—（无 RAPL 权限）" };
                    ui.label(RichText::new(src).size(13.0).monospace().color(theme::TEXT));
                } else {
                    ui.label(RichText::new("供电电压").size(12.0).color(theme::TEXT_SEC));
                    let sv = self.pi.power.map(|p| format!("{:.2} V", p.ext5v_v)).unwrap_or_else(|| "—".to_string());
                    ui.label(RichText::new(sv).size(13.0).monospace().color(theme::TEXT));
                }
            });
            if let Some(th) = self.pi.throttle {
                let (text, color) = if th.any_current() {
                    (th.warning(), theme::DANGER)
                } else if th.occurred {
                    (th.warning(), theme::WARNING)
                } else {
                    ("供电正常".to_string(), theme::SUCCESS)
                };
                egui::Frame::NONE.fill(theme::tint(color, 0.15)).corner_radius(6).inner_margin(Margin::symmetric(9, 6)).show(ui, |ui| {
                    ui.set_width((w - 18.0).max(60.0));
                    ui.add(egui::Label::new(RichText::new(text).size(11.5).color(color)).wrap())
                        .on_hover_text("读取 vcgencmd get_throttled 状态位：欠压 / 频率受限 / 降频 / 温度软限制。");
                });
            }
            if self.pi.temp_c.is_some() {
                sparkline_of(ui, w, 24.0, &self.perf.temp, tcolor, 100.0, HIST_CAP);
            }
            egui::CollapsingHeader::new(RichText::new("供电详情").size(12.0).color(theme::TEXT_SEC)).default_open(false).show(ui, |ui| {
                if self.pi.rails.is_empty() {
                    let tip = if remote { "—（该主机无 PMIC 分路；功耗取自 RAPL 能量计）" } else { "—（vcgencmd 不可用）" };
                    ui.label(RichText::new(tip).size(11.5).color(theme::TEXT_MUTED));
                } else {
                    for r in &self.pi.rails {
                        ui.label(RichText::new(format!("{}: {:.3} V × {:.3} A = {:.3} W", r.name, r.volts, r.amps, r.watts())).size(11.0).monospace().color(theme::TEXT_SEC));
                    }
                }
            });
        });
    }

    fn gpu_card(&self, ui: &mut egui::Ui, w: f32) {
        card(ui, w, 176.0, |ui| {
            let g = &self.pi.gpu;
            let clients = g.clients.map(|c| format!("{c} 进程")).unwrap_or_default();
            card_title(ui, theme::GPU, "显卡", &clients);
            let ghz = |v: Option<f32>| v.map(|x| format!("{x:.2}")).unwrap_or_else(|| "—".to_string());
            ui.horizontal(|ui| {
                if let Some(v) = g.v3d_ghz {
                    ui.label(RichText::new(ghz(Some(v))).size(32.0).monospace().strong().color(theme::GPU))
                        .on_hover_text("V3D 3D 引擎频率（树莓派）。");
                    ui.label(RichText::new("GHz").size(15.0).color(theme::TEXT_SEC));
                } else if let Some(t) = g.temp_c {
                    ui.label(RichText::new(format!("{t:.1}")).size(30.0).monospace().strong().color(theme::temp_color(t)))
                        .on_hover_text("显卡温度，来自显卡驱动（nouveau / amdgpu / i915 / radeon）的 hwmon 传感器。");
                    ui.label(RichText::new("°C").size(15.0).color(theme::TEXT_SEC));
                } else {
                    ui.label(RichText::new("—").size(30.0).monospace().strong().color(theme::TEXT_MUTED));
                }
            });
            if let Some(m) = &g.model {
                ui.label(RichText::new(m.as_str()).size(12.5).color(theme::TEXT_SEC)).on_hover_text("显卡型号来自 lspci，无需安装额外驱动。");
            }
            let has_engines = g.core_ghz.is_some() || g.isp_ghz.is_some() || g.hevc_ghz.is_some() || g.hdmi_ghz.is_some();
            if has_engines {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("核心").size(12.0).color(theme::TEXT_SEC));
                    ui.label(RichText::new(ghz(g.core_ghz)).size(12.0).monospace().color(theme::TEXT));
                    ui.add_space(8.0);
                    ui.label(RichText::new("ISP").size(12.0).color(theme::TEXT_SEC));
                    ui.label(RichText::new(ghz(g.isp_ghz)).size(12.0).monospace().color(theme::TEXT));
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new("HEVC").size(12.0).color(theme::TEXT_SEC));
                    ui.label(RichText::new(ghz(g.hevc_ghz)).size(12.0).monospace().color(theme::TEXT));
                    ui.add_space(8.0);
                    ui.label(RichText::new("HDMI").size(12.0).color(theme::TEXT_SEC));
                    ui.label(RichText::new(ghz(g.hdmi_ghz)).size(12.0).monospace().color(theme::TEXT));
                });
            }
            if g.gpu_mem_mb.is_some() || g.malloc_mb.is_some() || g.bo_count.is_some() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("显存").size(12.0).color(theme::TEXT_SEC));
                    let mem = match (g.gpu_mem_mb, g.malloc_mb) {
                        (Some(a), Some(b)) => format!("{a} MB / malloc {b}"),
                        (Some(a), None) => format!("{a} MB"),
                        _ => "—".to_string(),
                    };
                    ui.label(RichText::new(mem).size(12.0).monospace().color(theme::TEXT));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let bo = match (g.bo_count, g.bo_size_mb) {
                            (Some(n), Some(m)) => format!("BO {n}个 · {m}MB"),
                            (_, Some(m)) => format!("BO {m}MB"),
                            _ => "BO —".to_string(),
                        };
                        ui.label(RichText::new(bo).size(11.0).color(theme::TEXT_MUTED));
                    });
                });
            }
            let tip = if g.model.is_some() {
                "型号来自 lspci，温度来自显卡驱动 hwmon"
            } else {
                "V3D 无占用百分比，用频率/BO/客户端反映"
            };
            ui.label(RichText::new(tip).size(10.0).color(theme::TEXT_MUTED));
        });
    }

    fn sparkline(&self, ui: &mut egui::Ui, width: f32, height: f32) {
        let line = theme::heat_color(self.usage.total_percent / 100.0);
        sparkline_of(ui, width, height, &self.perf.cpu, line, 100.0, HIST_CAP);
    }

    fn central(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(4.0);
            match self.view {
                View::Monitor => self.monitor_body(ui),
                View::Scheduler => self.scheduler_view(ui),
                View::Performance => self.performance_view(ui),
                View::Network => self.network_view(ui),
                View::Probe => self.probe_view(ui),
                View::Overview => self.overview_view(ui),
            }
        });
    }

    fn monitor_body(&mut self, ui: &mut egui::Ui) {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("搜索").size(12.5).color(theme::TEXT_SEC));
                ui.add(egui::TextEdit::singleline(&mut self.filter).id(egui::Id::unique("proc_search")).hint_text("进程名称或 PID").desired_width(200.0));
                if action_btn(ui, "导出快照", theme::TEXT_SEC, true, false) {
                    self.export_snapshot();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(format!("{} 个进程", self.usage.procs.len())).size(12.0).color(theme::TEXT_MUTED));
                    ui.add_space(10.0);
                    ui.label(RichText::new("快捷键").size(12.0).color(theme::TEXT_MUTED)).on_hover_text(
                        "F5 刷新 · 空格 暂停/继续 · ↑/↓ 选择进程 · Del 结束进程 · Ctrl+F 搜索 · Ctrl+1–6 切换视图 · Esc 取消/清除 · 双击查看详情 · 右键更多操作",
                    );
                    ui.add_space(12.0);
                    ui.checkbox(&mut self.own_only, RichText::new("仅本用户").size(12.5));
                    ui.add_space(2.0);
                    ui.selectable_value(&mut self.table_mode, TableMode::Apps, RichText::new("应用").size(12.5));
                    ui.selectable_value(&mut self.table_mode, TableMode::Tree, RichText::new("树形").size(12.5));
                    ui.selectable_value(&mut self.table_mode, TableMode::Flat, RichText::new("平铺").size(12.5));
                });
            });
            ui.add_space(8.0);
            let (cmd_text, cmd_color, full) = match &self.cmdline_cache {
                Some((_, cmd)) => (truncate_chars(cmd, 200), theme::TEXT_SEC, cmd.clone()),
                None => ("选中一个进程以查看完整命令行".to_string(), theme::TEXT_MUTED, String::new()),
            };
            egui::Frame::NONE.fill(theme::EXTREME).corner_radius(6).inner_margin(Margin::symmetric(10, 7)).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("命令行").size(11.0).color(theme::TEXT_MUTED));
                    if full.is_empty() {
                        ui.add(egui::Label::new(RichText::new(cmd_text).size(11.5).monospace().color(cmd_color)).truncate());
                    } else {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if action_btn(ui, "复制", theme::INFO, true, false) {
                                ui.ctx().copy_text(full.clone());
                            }
                            ui.add_space(8.0);
                            ui.add(egui::Label::new(RichText::new(cmd_text).size(11.5).monospace().color(cmd_color)).truncate())
                                .on_hover_text(full.clone());
                        });
                    }
                });
            });
            ui.add_space(8.0);
            let rows = self.visible_rows();
            TableBuilder::new(ui)
                .striped(true)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::exact(72.0))
                .column(Column::exact(56.0))
                .column(Column::remainder())
                .column(Column::exact(96.0))
                .column(Column::exact(84.0))
                .column(Column::exact(96.0))
                .column(Column::exact(76.0))
                .column(Column::exact(60.0))
                .column(Column::exact(80.0))
                .header(28.0, |mut header| {
                    for (col, title, numeric) in [
                        (SortCol::Pid, "PID", false),
                        (SortCol::Ppid, "PPID", true),
                        (SortCol::Name, "名称", false),
                        (SortCol::User, "用户", false),
                        (SortCol::Cpu, "CPU%", true),
                        (SortCol::Mem, "内存MB", true),
                        (SortCol::MemPct, "内存%", true),
                        (SortCol::Nice, "nice", true),
                        (SortCol::State, "状态", false),
                    ] {
                        header.col(|ui| {
                            ui.painter().rect_filled(ui.max_rect(), 0.0, theme::SURFACE);
                            let active = self.sort_col == col;
                            let arrow = if active { if self.sort_desc { " ▼" } else { " ▲" } } else { "" };
                            let color = if active { theme::CPU } else { theme::TEXT_SEC };
                            let btn = egui::Button::new(RichText::new(format!("{title}{arrow}")).size(12.0).strong().color(color)).frame(false);
                            let clicked = if numeric {
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| ui.add(btn).clicked()).inner
                            } else {
                                ui.add(btn).clicked()
                            };
                            if clicked {
                                if active {
                                    self.sort_desc = !self.sort_desc;
                                } else {
                                    self.sort_col = col;
                                    self.sort_desc = matches!(col, SortCol::Cpu | SortCol::Mem | SortCol::MemPct);
                                }
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(26.0, rows.len(), |mut row| {
                        let (p, depth) = &rows[row.index()];
                        let is_sel = self.selected == Some(p.pid);
                        row.set_selected(is_sel);
                        row.col(|ui| {
                            if is_sel {
                                let r = ui.max_rect();
                                ui.painter().rect_filled(egui::Rect::from_min_max(r.min, Pos2::new(r.min.x + 3.0, r.max.y)), 0.0, theme::CPU);
                            }
                            ui.add_space(4.0);
                            ui.label(RichText::new(p.pid.to_string()).size(12.5).monospace().color(if is_sel { theme::TEXT } else { theme::TEXT_SEC }));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(p.ppid.to_string()).size(12.0).monospace().color(theme::TEXT_MUTED));
                        });
                        row.col(|ui| {
                            let indent = if *depth == 0 {
                                String::new()
                            } else {
                                format!("{}└ ", "  ".repeat(*depth as usize - 1))
                            };
                            ui.label(RichText::new(format!("{indent}{}", p.comm)).size(12.5).strong().color(theme::TEXT));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(p.user.as_str()).size(12.0).color(theme::TEXT_SEC));
                        });
                        row.col(|ui| {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(RichText::new(format!("{:.1}", p.cpu_percent)).size(12.5).monospace().color(theme::heat_color(p.cpu_percent / 100.0)));
                            });
                        });
                        row.col(|ui| {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(RichText::new(format!("{:.1}", p.rss_kb as f32 / 1024.0)).size(12.5).monospace().color(theme::TEXT_SEC));
                            });
                        });
                        row.col(|ui| {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(RichText::new(format!("{:.1}", p.mem_percent)).size(12.5).monospace().color(theme::heat_color(p.mem_percent / 100.0)));
                            });
                        });
                        row.col(|ui| {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(RichText::new(p.nice.to_string()).size(12.5).monospace().color(theme::TEXT_MUTED));
                            });
                        });
                        row.col(|ui| {
                            let (label, color) = theme::state_badge(p.state);
                            badge(ui, label, color).on_hover_text(format!("原始状态码: {}", p.state));
                        });
                        let resp = row.response();
                        if resp.clicked() {
                            self.selected = Some(p.pid);
                        }
                        if resp.double_clicked() {
                            self.open_details(p);
                        }
                        let pid = p.pid;
                        let comm = p.comm.clone();
                        let state = p.state;
                        let nice = p.nice;
                        let actionable = pid != 1 && (self.host_sel.is_some() || pid != self.own_pid);
                        resp.context_menu(|ui| {
                            self.selected = Some(pid);
                            ui.set_min_width(168.0);
                            if ui.button("复制 PID").clicked() {
                                ui.ctx().copy_text(pid.to_string());
                                ui.close();
                            }
                            if ui.button("复制命令行").clicked() {
                                let c = self.copy_cmdline(pid, &comm);
                                ui.ctx().copy_text(c);
                                ui.close();
                            }
                            ui.separator();
                            if ui.add_enabled(actionable, egui::Button::new("调优先级")).clicked() {
                                self.nice_dialog = Some(NiceDialog { pid, comm: comm.clone(), value: nice.clamp(-19, 19) as i32 });
                                ui.close();
                            }
                            let stopped = state == 'T';
                            let pause_label = if stopped { "恢复进程" } else { "暂停进程" };
                            if ui.add_enabled(actionable, egui::Button::new(pause_label)).clicked() {
                                self.act_pause(pid, stopped, &comm);
                                ui.close();
                            }
                            ui.separator();
                            if ui.add_enabled(actionable, egui::Button::new("结束进程")).clicked() {
                                self.ask_confirm(ConfirmKind::Terminate, pid, &comm);
                                ui.close();
                            }
                            if ui.add_enabled(actionable, egui::Button::new(RichText::new("强制结束").color(theme::DANGER))).clicked() {
                                self.ask_confirm(ConfirmKind::Kill, pid, &comm);
                                ui.close();
                            }
                            if ui.add_enabled(actionable, egui::Button::new("结束进程树")).clicked() {
                                self.ask_confirm_tree(ConfirmKind::Terminate, pid, &comm);
                                ui.close();
                            }
                            ui.separator();
                            ui.menu_button("发送信号", |ui| {
                                for (label, sig) in [
                                    ("HUP", Signal::SIGHUP),
                                    ("INT", Signal::SIGINT),
                                    ("TERM", Signal::SIGTERM),
                                    ("STOP", Signal::SIGSTOP),
                                    ("CONT", Signal::SIGCONT),
                                    ("USR1", Signal::SIGUSR1),
                                    ("USR2", Signal::SIGUSR2),
                                    ("KILL", Signal::SIGKILL),
                                ] {
                                    if ui.add_enabled(actionable, egui::Button::new(label)).clicked() {
                                        self.act_signal(pid, sig, label);
                                        ui.close();
                                    }
                                }
                            });
                        });
                    });
                });
            if rows.is_empty() && !self.filter.trim().is_empty() {
                ui.add_space(24.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new(format!("没有匹配「{}」的进程", self.filter.trim())).size(13.0).color(theme::TEXT_MUTED));
                });
            }
    }

    fn scheduler_view(&mut self, ui: &mut egui::Ui) {
        let remote = self.host_sel.is_some();
        let remote_write = remote && self.remote_write;
        let available = (self.mgr.is_some() && !remote) || remote_write;
        egui::ScrollArea::vertical().show(ui, |ui| {
        let (banner, color) = if remote && !remote_write {
            ("远程主机：只读（勾选『允许调度远端』可管理）".to_string(), theme::WARNING)
        } else if remote_write {
            (format!("远程调度：{}（写，仅本机用户进程）", self.host_sel.as_ref().map(|t| t.as_str()).unwrap_or("-")), theme::WARNING)
        } else if available {
            ("可调度：用户 cgroup（cpu / pids）".to_string(), theme::SUCCESS)
        } else {
            (
                format!("调度不可用：{}", self.cg_error.clone().unwrap_or_else(|| "未知原因".into())),
                theme::DANGER,
            )
        };
        egui::Frame::NONE
            .fill(theme::tint(color, 0.12))
            .corner_radius(6)
            .inner_margin(Margin::symmetric(10, 7))
            .show(ui, |ui| {
                ui.label(RichText::new(banner).size(12.5).color(color));
            });
        if remote {
            ui.add_space(6.0);
            let mut rw = self.remote_write;
            ui.horizontal(|ui| {
                ui.checkbox(&mut rw, RichText::new("允许调度远端（写操作）").size(12.0));
                ui.label(RichText::new("仅作用于该主机上你自己的进程，改动可逆").size(11.0).color(theme::TEXT_MUTED));
            });
            if rw != self.remote_write {
                self.remote_write = rw;
                self.remote_cg_base = None;
                if rw {
                    self.refresh_groups();
                } else {
                    self.groups.clear();
                    self.original_of.clear();
                }
            }
        }
        ui.add_space(10.0);

        section_card(ui, "分组", |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_group)
                        .hint_text("新建分组名（字母数字 . _ -）")
                        .desired_width(220.0),
                );
                let name = self.new_group.trim().to_string();
                let valid = crate::cgroup::valid_group_name(&name);
                if action_btn(ui, "创建", theme::SUCCESS, available && valid, false) {
                    self.do_create_group(&name);
                }
                if !name.is_empty() && !valid {
                    ui.label(RichText::new("名称含非法字符").size(11.0).color(theme::DANGER));
                }
            });

            if self.groups.is_empty() {
                ui.label(RichText::new("还没有分组。新建一个，再把进程加进去设上限。").size(12.0).color(theme::TEXT_MUTED));
                return;
            }
            let groups = self.groups.clone();
            for g in &groups {
                ui.horizontal(|ui| {
                    let sel = self.sel_group.as_deref() == Some(g.name.as_str());
                    if ui.selectable_label(sel, RichText::new(&g.name).size(12.5).strong()).clicked() {
                        self.sel_group = Some(g.name.clone());
                    }
                    let cap = g.cpu_max_pct.map(|p| format!("{p}%")).unwrap_or_else(|| "不限".into());
                    let cap_color = if g.cpu_max_pct.is_some() { theme::INFO } else { theme::TEXT_MUTED };
                    badge(ui, &format!("CPU {cap}"), cap_color);
                    let pids = g.pids_max.map(|m| format!(" · ≤{m} 进程")).unwrap_or_default();
                    ui.label(RichText::new(format!("权重 {} · {} 个进程{pids}", g.cpu_weight, g.procs)).size(11.0).color(theme::TEXT_MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if action_btn(ui, "删除", theme::DANGER, available, false) {
                            self.do_delete_group(&g.name);
                        }
                    });
                });
            }
        });

        section_card(ui, "自动分组", |ui| {
            ui.checkbox(&mut self.auto_enabled, RichText::new("启用（按进程名自动纳入分组，迁入可还原）").size(12.5));
            let rules = self.auto_rules.clone();
            if rules.is_empty() {
                ui.label(RichText::new("示例：进程名包含 ffmpeg → 分组 build，CPU 150%").size(11.0).color(theme::TEXT_MUTED));
            }
            for (i, r) in rules.iter().enumerate() {
                ui.horizontal(|ui| {
                    let cap = r.pct.map(|p| format!("{p}%")).unwrap_or_else(|| "不限".into());
                    ui.label(RichText::new(format!("{} → {} · CPU {cap}", r.pattern, r.group)).size(12.0).color(theme::TEXT));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if action_btn(ui, "删除", theme::DANGER, true, false) {
                            self.auto_rules.remove(i);
                        }
                    });
                });
            }
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.new_auto_pattern).hint_text("进程名包含").desired_width(110.0));
                ui.label(RichText::new("→").size(12.0).color(theme::TEXT_MUTED));
                ui.add(egui::TextEdit::singleline(&mut self.new_auto_group).hint_text("分组名").desired_width(100.0));
                ui.label(RichText::new("CPU").size(12.0).color(theme::TEXT_SEC));
                egui::ComboBox::from_id_salt("auto_pct")
                    .selected_text(self.new_auto_pct.map(|p| format!("{p}%")).unwrap_or_else(|| "不限".into()))
                    .width(70.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.new_auto_pct, Some(25), "25%");
                        ui.selectable_value(&mut self.new_auto_pct, Some(50), "50%");
                        ui.selectable_value(&mut self.new_auto_pct, Some(100), "100%");
                        ui.selectable_value(&mut self.new_auto_pct, Some(200), "200%");
                        ui.selectable_value(&mut self.new_auto_pct, None, "不限");
                    });
                let can = !self.new_auto_pattern.trim().is_empty() && crate::cgroup::valid_group_name(self.new_auto_group.trim());
                if action_btn(ui, "添加", theme::SUCCESS, can, false) {
                    self.auto_rules.push(AutoRule {
                        pattern: self.new_auto_pattern.trim().to_string(),
                        group: self.new_auto_group.trim().to_string(),
                        pct: self.new_auto_pct,
                    });
                    self.new_auto_pattern.clear();
                    self.new_auto_group.clear();
                }
            });
        });

        if let Some(grp) = self.sel_group.clone() {
            section_card(ui, "选中分组", |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&grp).size(13.0).strong().color(theme::CPU));
                    ui.label(RichText::new("CPU 上限").size(12.0).color(theme::TEXT_SEC));
                    for (label, pct) in [("25%", Some(25u32)), ("50%", Some(50u32)), ("100%", Some(100u32)), ("200%", Some(200u32)), ("不限", None)] {
                        if action_btn(ui, label, theme::INFO, available, false) {
                            self.do_set_cpu_max(&grp, pct);
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new("权重").size(12.0).color(theme::TEXT_SEC));
                    for w in [50u32, 100, 200] {
                        if action_btn(ui, &w.to_string(), theme::TEXT_SEC, available, false) {
                            self.do_set_cpu_weight(&grp, w);
                        }
                    }
                    ui.add_space(10.0);
                    ui.label(RichText::new("进程数上限").size(12.0).color(theme::TEXT_SEC));
                    for m in [None, Some(64u32), Some(128), Some(256)] {
                        let label = m.map(|x| x.to_string()).unwrap_or_else(|| "不限".into());
                        if action_btn(ui, &label, theme::TEXT_SEC, available, false) {
                            self.do_set_pids_max(&grp, m);
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new("成员").size(12.0).color(theme::TEXT_SEC));
                    if let Some(pid) = self.selected {
                        let managed = if remote {
                            self.original_of.contains_key(&pid)
                        } else {
                            self.mgr.as_ref().and_then(|m| m.group_of(pid)).is_some()
                        };
                        if !managed {
                            if action_btn(ui, "加入当前选中进程", theme::SUCCESS, available, false) {
                                self.do_join_group(&grp, pid);
                            }
                        } else if action_btn(ui, "移出当前选中进程", theme::WARNING, available, false) {
                            self.do_leave_group(pid);
                        }
                    } else {
                        ui.label(RichText::new("（在监控页选中一个进程后可加入）").size(11.0).color(theme::TEXT_MUTED));
                    }
                });
                let members: Vec<(i32, String)> = self
                    .original_of
                    .keys()
                    .copied()
                    .filter_map(|pid| self.usage.procs.iter().find(|p| p.pid == pid).map(|p| (pid, p.comm.clone())))
                    .collect();
                if members.is_empty() {
                    ui.label(RichText::new("（该分组暂无由本程序迁入的进程）").size(11.0).color(theme::TEXT_MUTED));
                } else {
                    for (pid, comm) in &members {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(comm.as_str()).size(12.0).color(theme::TEXT));
                            ui.label(RichText::new(format!("PID {pid}")).size(11.0).monospace().color(theme::TEXT_MUTED));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if action_btn(ui, "移出", theme::WARNING, available, false) {
                                    self.do_leave_group(*pid);
                                }
                            });
                        });
                    }
                }
            });
        }
        section_card(ui, "自动节流", |ui| {
            let mut enabled = self.sched.enabled;
            ui.horizontal(|ui| {
                ui.checkbox(&mut enabled, RichText::new("启用自动模式").size(12.5));
                ui.label(RichText::new("仅做可逆的 CPU 上限收紧/放宽，不会杀进程").size(11.0).color(theme::TEXT_MUTED));
            });
            if enabled != self.sched.enabled {
                // 重新启用 = 人工解除熔断，状态机清零重试
                self.sched.enabled = enabled;
                if enabled {
                    self.sched_state.reset();
                    self.sched_halt_warned = false;
                }
            }
            let (st_text, st_color, reason) = if !self.sched.enabled {
                ("未启用".to_string(), theme::TEXT_MUTED, None)
            } else if self.sched_state.halted {
                ("已熔断（连续写入失败）".to_string(), theme::DANGER, Some("关闭再开启自动模式可重试"))
            } else if self.sched.target_group.is_none() {
                ("已启用，未选目标分组".to_string(), theme::DANGER, Some("请选择目标分组"))
            } else if self.sched_state.engaged {
                ("自动节流中".to_string(), theme::WARNING, None)
            } else {
                ("监控中（未触发）".to_string(), theme::SUCCESS, None)
            };
            ui.horizontal(|ui| {
                ui.label(RichText::new("状态").size(12.0).color(theme::TEXT_SEC));
                ui.label(RichText::new(st_text).size(12.0).color(st_color));
                if let Some(r) = reason {
                    ui.label(RichText::new(r).size(11.0).color(theme::TEXT_MUTED));
                }
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new("触发温度").size(12.0).color(theme::TEXT_SEC));
                ui.add(egui::Slider::new(&mut self.sched.temp_high, 60.0..=90.0).suffix("°C"));
                ui.label(RichText::new("回落温度").size(12.0).color(theme::TEXT_SEC));
                ui.add(egui::Slider::new(&mut self.sched.temp_low, 40.0..=80.0).suffix("°C"));
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new("CPU 触发").size(12.0).color(theme::TEXT_SEC));
                ui.add(egui::Slider::new(&mut self.sched.cpu_high, 50.0..=100.0).suffix("%"));
                ui.label(RichText::new("（温度或 CPU 任一超阈即触发，带回落与冷却）").size(11.0).color(theme::TEXT_MUTED));
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new("节流到").size(12.0).color(theme::TEXT_SEC));
                ui.add(egui::Slider::new(&mut self.sched.throttle_pct, 10..=200).suffix("%"));
                ui.label(RichText::new("目标分组").size(12.0).color(theme::TEXT_SEC));
                let current = self.sched.target_group.clone().unwrap_or_else(|| "（未选择）".into());
                let groups = self.groups.clone();
                egui::ComboBox::from_id_salt("sched_target")
                    .selected_text(current)
                    .width(140.0)
                    .show_ui(ui, |ui| {
                        for g in &groups {
                            ui.selectable_value(&mut self.sched.target_group, Some(g.name.clone()), g.name.as_str());
                        }
                    });
            });
            ui.add_space(4.0);
            if action_btn(ui, "解除全部限速", theme::WARNING, available, false) {
                self.dissolve_all_limits();
            }
        });
        });
    }

    fn network_view(&mut self, ui: &mut egui::Ui) {
        let all = self.net_conns.clone();
        let listens = all.iter().filter(|c| c.state == "LISTEN").count();
        let estab = all.iter().filter(|c| c.state == "ESTABLISHED").count();
        let rx = self.usage.net_rx_bps / 1024.0;
        let tx = self.usage.net_tx_bps / 1024.0;
        let rx_value = format!("{rx:.0} KB/s");
        let tx_value = format!("{tx:.0} KB/s");

        ui.horizontal(|ui| {
            stat_tile(ui, "下行", &rx_value, theme::SUCCESS);
            ui.add_space(8.0);
            stat_tile(ui, "上行", &tx_value, theme::CPU);
            ui.add_space(8.0);
            stat_tile(ui, "已连接", &estab.to_string(), theme::CPU);
            ui.add_space(8.0);
            stat_tile(ui, "监听", &listens.to_string(), theme::WARNING);
            ui.add_space(8.0);
            stat_tile(ui, "连接总数", &all.len().to_string(), theme::TEXT_SEC);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.net_filter)
                        .id(egui::Id::unique("net_search"))
                        .hint_text("地址 / 协议 / 状态")
                        .desired_width(190.0),
                );
                ui.label(RichText::new("过滤").size(11.5).color(theme::TEXT_MUTED));
            });
        });
        if self.host_sel.is_some() {
            ui.add_space(4.0);
            ui.label(RichText::new("连接明细与吞吐均来自当前主机（远端经 SSH 读取 /proc/net）。").size(10.5).color(theme::TEXT_MUTED));
        }
        ui.add_space(8.0);

        let chart_card = |ui: &mut egui::Ui, title: &str, value: &str, color: Color32, data: &VecDeque<f32>| {
            let width = ui.available_width();
            theme::card_frame().show(ui, |ui| {
                ui.set_width((width - 26.0).max(160.0));
                metric_graph(ui, title, value, color, None, data, 56.0);
            });
        };
        ui.columns(2, |cols| {
            chart_card(&mut cols[0], "下行吞吐 ↓", &rx_value, theme::SUCCESS, &self.perf.net_rx);
            chart_card(&mut cols[1], "上行吞吐 ↑", &tx_value, theme::CPU, &self.perf.net_tx);
        });
        ui.add_space(10.0);

        let query = self.net_filter.trim().to_string();
        let conns: Vec<&NetConn> = all
            .iter()
            .filter(|c| {
                query.is_empty()
                    || icontains(&c.proto, &query)
                    || icontains(&c.local, &query)
                    || icontains(&c.remote, &query)
                    || icontains(&c.state, &query)
                    || c.uid.to_string().contains(&query)
            })
            .collect();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("显示 {} / {} 条 · 监听 {} · 已连接 {}", conns.len(), all.len(), listens, estab))
                    .size(11.5)
                    .color(theme::TEXT_MUTED),
            );
        });
        ui.add_space(4.0);
        TableBuilder::new(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(60.0))
            .column(Column::exact(190.0))
            .column(Column::remainder())
            .column(Column::exact(130.0))
            .column(Column::exact(80.0))
            .header(26.0, |mut h| {
                for t in ["协议", "本地地址", "远端地址", "状态", "UID"] {
                    h.col(|ui| {
                        ui.painter().rect_filled(ui.max_rect(), 0.0, theme::SURFACE);
                        ui.label(RichText::new(t).size(12.0).strong().color(theme::TEXT_SEC));
                    });
                }
            })
            .body(|body| {
                body.rows(24.0, conns.len(), |mut row| {
                    let c = conns[row.index()];
                    row.col(|ui| {
                        ui.label(RichText::new(&c.proto).size(11.5).monospace().color(theme::CPU));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(&c.local).size(11.5).monospace().color(theme::TEXT));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(&c.remote).size(11.5).monospace().color(theme::TEXT_SEC));
                    });
                    row.col(|ui| {
                        let color = if c.state == "LISTEN" {
                            theme::SUCCESS
                        } else if c.state == "ESTABLISHED" {
                            theme::CPU
                        } else {
                            theme::TEXT_MUTED
                        };
                        ui.label(RichText::new(&c.state).size(11.5).color(color));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(c.uid.to_string()).size(11.5).monospace().color(theme::TEXT_MUTED));
                    });
                });
            });
        if conns.is_empty() && !query.is_empty() {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(format!("没有匹配「{query}」的连接")).size(12.5).color(theme::TEXT_MUTED));
            });
        }
    }

    fn overview_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("主机总览 · 本地 + SSH 主机（远端每 5s 刷新）").size(12.5).strong().color(theme::TEXT_SEC));
            if action_btn(ui, "＋ 添加主机", theme::TEXT_SEC, true, false) {
                self.add_host = Some(String::new());
            }
        });
        ui.add_space(8.0);

        let mut rows = Vec::new();
        {
            let (ok, cpu, mem, temp, gpu, load, procs) = match &self.local_view {
                Some((u, pi)) => (
                    true,
                    u.total_percent,
                    u.mem.map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 }).unwrap_or(0.0),
                    pi.temp_c.unwrap_or(0.0),
                    pi.gpu.v3d_ghz.unwrap_or(0.0),
                    u.load.map(|l| l.one).unwrap_or(0.0),
                    u.procs.len(),
                ),
                None => (false, 0.0, 0.0, 0.0, 0.0, 0.0, 0),
            };
            rows.push((None, "本地".to_string(), String::new(), ok, cpu, mem, temp, gpu, load, procs));
        }
        let fleet = self.fleet.lock().ok().map(|f| f.clone()).unwrap_or_default();
        for h in &self.hosts {
            let key = h.as_str();
            let (ok, os, cpu, mem, temp, gpu, load, procs) = match fleet.get(key) {
                Some(s) => (s.ok, s.os.clone(), s.cpu, s.mem, s.temp, s.gpu, s.load1, s.procs),
                None => (false, String::new(), 0.0, 0.0, 0.0, 0.0, 0.0, 0),
            };
            rows.push((Some(key.to_string()), key.to_string(), os, ok, cpu, mem, temp, gpu, load, procs));
        }

        let selected = self.host_sel.as_ref().map(|t| t.as_str().to_string());
        for (sel, label, os, ok, cpu, mem, temp, gpu, load, procs) in rows {
            let is_cur = sel == selected;
            egui::Frame::NONE
                .fill(if is_cur { theme::tint(theme::CPU, 0.10) } else { theme::SURFACE })
                .stroke(Stroke::new(1.0, if is_cur { theme::CPU } else { theme::BORDER }))
                .corner_radius(8)
                .inner_margin(Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (dot, _) = ui.allocate_exact_size(Vec2::new(9.0, 9.0), egui::Sense::hover());
                        ui.painter().circle_filled(dot.center(), 4.0, if ok { theme::SUCCESS } else { theme::DANGER });
                        ui.label(RichText::new(&label).size(12.5).strong().color(theme::TEXT));
                        if !os.is_empty() {
                            ui.label(RichText::new(&os).size(10.5).color(theme::TEXT_MUTED));
                        }
                        if ok {
                            ui.label(RichText::new(format!("CPU {:.0}%", cpu)).size(11.5).monospace().color(theme::heat_color(cpu / 100.0)));
                            ui.label(RichText::new(format!("内存 {mem:.0}%")).size(11.5).monospace().color(theme::MEM));
                            if temp > 0.0 {
                                ui.label(RichText::new(format!("{temp:.0}°C")).size(11.5).monospace().color(theme::temp_color(temp)));
                            }
                            if gpu > 0.0 {
                                ui.label(RichText::new(format!("GPU {gpu:.2}")).size(11.5).monospace().color(theme::GPU));
                            }
                            ui.label(RichText::new(format!("负载 {load:.2} · {procs} 进程")).size(11.5).color(theme::TEXT_MUTED));
                        } else {
                            ui.label(RichText::new("离线 / 超时").size(11.5).color(theme::DANGER));
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if action_btn(ui, "查看", theme::INFO, true, false) {
                                self.select_host(sel.clone());
                            }
                        });
                    });
                });
            ui.add_space(6.0);
        }
    }

    fn performance_view(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            let width = ui.available_width();
            theme::card_frame().show(ui, |ui| {
                ui.set_width((width - 26.0).max(240.0));
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    ui.spacing_mut().item_spacing = Vec2::new(10.0, 8.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("告警阈值").size(12.5).strong().color(theme::TEXT_SEC));
                        ui.add_space(6.0);
                        ui.label(RichText::new("CPU").size(11.5).color(theme::TEXT_MUTED));
                        ui.add(egui::Slider::new(&mut self.alert_cpu, 50.0..=100.0).suffix("%"));
                        ui.add_space(4.0);
                        ui.label(RichText::new("内存").size(11.5).color(theme::TEXT_MUTED));
                        ui.add(egui::Slider::new(&mut self.alert_mem, 50.0..=100.0).suffix("%"));
                        ui.add_space(4.0);
                        ui.label(RichText::new("温度").size(11.5).color(theme::TEXT_MUTED));
                        ui.add(egui::Slider::new(&mut self.alert_temp, 60.0..=95.0).suffix("°C"));
                    });
                    let pf = platform::platform();
                    ui.horizontal(|ui| {
                        let mut line = format!(
                            "平台 {} · vcgencmd {} · GPU {} · 指标端点 127.0.0.1:9876",
                            pf.os,
                            if pf.has_vcgencmd { "可用" } else { "无" },
                            if pf.gpu_enabled { "开" } else { "关" }
                        );
                        if let Some(os) = self.pi.remote.as_ref().map(|r| r.os.as_str()) {
                            line.push_str(&format!(" · 远端 {os}（自动探测）"));
                        }
                        ui.label(RichText::new(line).size(10.5).color(theme::TEXT_MUTED));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if action_btn(ui, "配置 platform.conf", theme::TEXT_SEC, true, false) {
                                self.platform_edit = Some(platform::config_text());
                            }
                        });
                    });
                });
            });
            ui.add_space(10.0);

            let mem_pct = self
                .usage
                .mem
                .map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 })
                .unwrap_or(0.0);
            let temp = self.pi.temp_c.unwrap_or(0.0);
            let power = self.pi.power.map(|p| p.core_w).unwrap_or(0.0);
            let gpu_ghz = self.pi.gpu.v3d_ghz.unwrap_or(0.0);
            let gpu_t = self.pi.gpu.temp_c.unwrap_or(0.0);
            let (gpu_title, gpu_value, gpu_max) = if self.pi.gpu.v3d_ghz.is_some() {
                ("GPU 频率 (V3D)", format!("{gpu_ghz:.2} GHz"), Some(1.5))
            } else if self.pi.gpu.temp_c.is_some() {
                ("GPU 温度", format!("{gpu_t:.1}°C"), Some(100.0))
            } else {
                ("GPU 频率 (V3D)", format!("{gpu_ghz:.2} GHz"), Some(1.5))
            };
            let power_title = if self.host_sel.is_some() { "整机功耗 (RAPL)" } else { "核心功耗" };
            let disk_r = self.usage.disk_read_bps / 1024.0;
            let disk_w = self.usage.disk_write_bps / 1024.0;
            let net_rx = self.usage.net_rx_bps / 1024.0;
            let net_tx = self.usage.net_tx_bps / 1024.0;
            let cpu_value = format!("{:.1}%", self.usage.total_percent);
            let mem_value = format!("{mem_pct:.0}%");
            let temp_value = format!("{temp:.1}°C");
            let power_value = format!("{power:.2} W");
            let disk_r_value = format!("{disk_r:.0} KB/s");
            let disk_w_value = format!("{disk_w:.0} KB/s");
            let net_rx_value = format!("{net_rx:.0} KB/s");
            let net_tx_value = format!("{net_tx:.0} KB/s");
            let temp_heat = theme::temp_color(temp);
            let h = 74.0;

            // 大盘：左侧处理器 + 网络，右侧内存显卡 + 磁盘；窄窗口退化为单列。
            let left = |ui: &mut egui::Ui| {
                dash_card(ui, "处理器", theme::CPU, |ui| {
                    metric_graph(ui, "CPU 使用率", &cpu_value, theme::CPU, Some(100.0), &self.perf.cpu, h);
                    metric_graph(ui, "温度", &temp_value, temp_heat, Some(100.0), &self.perf.temp, h);
                    metric_graph(ui, power_title, &power_value, theme::POWER, None, &self.perf.power, h);
                });
                dash_card(ui, "网络吞吐", theme::SUCCESS, |ui| {
                    metric_graph(ui, "下行 ↓", &net_rx_value, theme::SUCCESS, None, &self.perf.net_rx, h);
                    metric_graph(ui, "上行 ↑", &net_tx_value, theme::CPU, None, &self.perf.net_tx, h);
                });
            };
            let right = |ui: &mut egui::Ui| {
                dash_card(ui, "内存与显卡", theme::MEM, |ui| {
                    metric_graph(ui, "内存使用率", &mem_value, theme::MEM, Some(100.0), &self.perf.mem, h);
                    metric_graph(ui, gpu_title, &gpu_value, theme::GPU, gpu_max, &self.perf.gpu, h);
                });
                dash_card(ui, "磁盘 I/O", theme::INFO, |ui| {
                    metric_graph(ui, "读取", &disk_r_value, theme::INFO, None, &self.perf.disk_r, h);
                    metric_graph(ui, "写入", &disk_w_value, theme::WARNING, None, &self.perf.disk_w, h);
                });
            };
            if ui.available_width() >= 760.0 {
                ui.columns(2, |cols| {
                    left(&mut cols[0]);
                    right(&mut cols[1]);
                });
            } else {
                left(ui);
                right(ui);
            }

            let fss = self.filesystems.clone();
            dash_card(ui, "文件系统", theme::INFO, |ui| {
                if fss.is_empty() {
                    ui.label(RichText::new("—（无块设备挂载）").size(12.0).color(theme::TEXT_MUTED));
                }
                for fs in &fss {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{} · {}", fs.mount, fs.source)).size(11.5).monospace().color(theme::TEXT_SEC));
                        let w = (ui.available_width() - 140.0).max(80.0);
                        ui.add(
                            egui::ProgressBar::new(fs.used_frac())
                                .desired_width(w)
                                .desired_height(6.0)
                                .fill(theme::heat_color(fs.used_frac()))
                                .corner_radius(3),
                        );
                        ui.label(
                            RichText::new(format!("{:.1}/{:.1} GB", fs.used_kb() as f64 / 1048576.0, fs.total_kb as f64 / 1048576.0))
                                .size(10.5)
                                .monospace()
                                .color(theme::TEXT_MUTED),
                        );
                    });
                }
            });
        });
    }

    fn probe_view(&mut self, ui: &mut egui::Ui) {
        if let Some(h) = self.host_sel.clone() {
            if self.probe_armed.is_some() {
                self.probe_stop();
            }
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("探针目前只在本机运行").size(15.0).strong().color(theme::TEXT));
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("当前查看的是远端主机 {h}，该主机上尚未部署探针代理（ftrace/uprobe 需本机内核挂点与本地可执行文件）。"))
                        .size(12.0)
                        .color(theme::TEXT_SEC),
                );
                ui.label(RichText::new("监控 / 性能 / 调度 / 总览 均已支持远端；切回本地即可使用探针。").size(11.5).color(theme::TEXT_MUTED));
                ui.add_space(10.0);
                if action_btn(ui, "切回本地查看探针", theme::INFO, true, false) {
                    self.select_host(None);
                }
            });
            return;
        }
        self.probe_agent_tick();
        if self.probe_armed.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(700));
        }
        if let Some(rx) = &self.probe_rx {
            match rx.try_recv() {
                Ok(snap) => {
                    self.probe_uprobe_ok = snap.caps.uprobe_events;
                    self.probe = Some(snap);
                    self.probe_rx = None;
                    self.probe_sel = None;
                    self.probe_sel_exe = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.probe_rx = None,
            }
        }
        if self.probe.is_none() {
            if self.probe_rx.is_none() {
                self.start_probe_load();
            }
            ui.add_space(28.0);
            ui.vertical_centered(|ui| {
                ui.spinner();
                ui.add_space(6.0);
                ui.label(RichText::new("正在扫描内核符号与用户态可执行文件…").size(12.5).color(theme::TEXT_SEC));
                ui.label(RichText::new("读取 /proc/kallsyms 约需 0.1–0.3 秒").size(11.0).color(theme::TEXT_MUTED));
            });
            ui.ctx().request_repaint_after(Duration::from_millis(150));
            return;
        }
        let snap = self.probe.take().expect("probe snapshot");
        let uprobe_blocked =
            matches!(&self.probe_sel, Some(ProbeSel::Uprobe { .. })) && self.probe_uprobe_ok == Some(false);
        let extra = 40.0
            + if self.probe_armed.is_some() { 22.0 } else { 0.0 }
            + if self.probe_agent_err.is_some() { 18.0 } else { 0.0 }
            + if uprobe_blocked { 18.0 } else { 0.0 }
            + if self.probe_sel.is_some() && self.probe_armed.is_none() { 34.0 } else { 0.0 };
        let table_h = (ui.available_height() - 235.0 - extra).clamp(110.0, 520.0);
        let refresh = egui::ScrollArea::vertical().show(ui, |ui| self.probe_body(ui, &snap, table_h)).inner;
        if refresh {
            self.probe = None;
            self.probe_elf.clear();
            self.probe_sel = None;
            self.probe_sel_exe = None;
            self.start_probe_load();
            self.status = "正在重新扫描挂载点…".to_string();
            self.status_error = false;
        } else {
            self.probe = Some(snap);
        }
    }

    fn start_probe_load(&mut self) {
        let (tx, rx) = std::sync::mpsc::channel();
        self.probe_rx = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(probe::Snapshot::load());
        });
    }

    fn probe_body(&mut self, ui: &mut egui::Ui, snap: &probe::Snapshot, table_h: f32) -> bool {
        let mut refresh = false;
        self.probe_status(ui, snap);
        for e in &snap.errors {
            ui.label(RichText::new(e).size(11.5).color(theme::DANGER));
        }
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.probe_mode, ProbeMode::Functions, RichText::new(format!("内核函数 {}", thousands(snap.functions.len()))).size(12.5));
            ui.selectable_value(&mut self.probe_mode, ProbeMode::Syscalls, RichText::new(format!("系统调用 {}", thousands(snap.syscalls.len()))).size(12.5));
            ui.selectable_value(&mut self.probe_mode, ProbeMode::Uprobe, RichText::new(format!("用户态 {}", thousands(snap.uprobes.len()))).size(12.5));
            ui.add_space(10.0);
            ui.label(RichText::new("搜索").size(12.5).color(theme::TEXT_SEC))
                .on_hover_text("按符号名挂载；地址被内核隐藏，不影响使用。");
            ui.add(
                egui::TextEdit::singleline(&mut self.probe_query)
                    .id(egui::Id::unique("probe_search"))
                    .hint_text("符号名（不区分大小写）")
                    .desired_width(220.0),
            );
            if self.probe_mode == ProbeMode::Uprobe {
                ui.add_space(6.0);
                ui.label(RichText::new("目标").size(12.5).color(theme::TEXT_SEC));
                let current = self
                    .probe_sel_exe
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "选择可执行文件".to_string());
                egui::ComboBox::from_id_salt("probe_target")
                    .selected_text(truncate_chars(&current, 42))
                    .width(310.0)
                    .show_ui(ui, |ui| {
                        for t in &snap.uprobes {
                            let text = format!("{}  ·  {} 进程 · PID {}", t.path.display(), t.procs, t.sample_pid);
                            if ui.selectable_label(self.probe_sel_exe.as_deref() == Some(t.path.as_path()), text).clicked() {
                                self.probe_sel_exe = Some(t.path.clone());
                            }
                        }
                    });
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if action_btn(ui, "重新扫描", theme::INFO, true, false) {
                    refresh = true;
                }
            });
        });
        ui.add_space(6.0);
        self.probe_actions(ui);
        ui.add_space(6.0);

        match self.probe_mode {
            ProbeMode::Uprobe => self.probe_uprobe_table(ui, table_h),
            _ => self.probe_kernel_table(ui, snap, table_h),
        }
        refresh
    }

    fn probe_status(&self, ui: &mut egui::Ui, snap: &probe::Snapshot) {
        let c = &snap.caps;
        egui::Frame::NONE
            .fill(theme::tint(theme::INFO, 0.10))
            .corner_radius(6)
            .inner_margin(Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let tools = c.tools.iter().map(|(n, ok)| format!("{n}{}", if *ok { "✓" } else { "✗" })).collect::<Vec<_>>().join(" · ");
                    badge(ui, "探针", theme::INFO).on_hover_text(format!(
                        "浏览挂载点不需要 root；挂载与命中读取由 root helper 通过 tracefs 完成。\n外部工具链：{tools}"
                    ));
                    cap_badge(ui, "系统调用", c.bpf_syscall).on_hover_text("内核配置 CONFIG_BPF_SYSCALL。");
                    cap_badge(ui, "JIT", c.bpf_jit).on_hover_text("内核配置 CONFIG_BPF_JIT。");
                    cap_badge(ui, "kprobe", c.kprobe_events).on_hover_text("内核配置 CONFIG_KPROBE_EVENTS。");
                    cap_badge(ui, "uprobe", c.uprobe_events)
                        .on_hover_text("内核配置 CONFIG_UPROBE_EVENTS；关闭时只能浏览符号，无法挂载。");
                    cap_badge(ui, "BTF", Some(c.btf_file))
                        .on_hover_text("缺少 /sys/kernel/btf/vmlinux：CO-RE 不可用，但不影响按符号名挂载。");
                    ui.label(RichText::new("·").size(11.0).color(theme::TEXT_MUTED));
                    let who = if c.euid == 0 { "root".to_string() } else { format!("uid {}", c.euid) };
                    badge(ui, &who, if c.euid == 0 { theme::SUCCESS } else { theme::TEXT_SEC });
                    cap_badge(ui, "CAP_BPF/PERFMON", Some(c.cap_bpf && c.cap_perfmon));
                    let (label, color) = match c.unprivileged_bpf_disabled {
                        Some(0) => ("非特权 BPF 允许", theme::WARNING),
                        Some(1) => ("非特权 BPF 关闭", theme::TEXT_SEC),
                        Some(2) => ("非特权 BPF 禁止", theme::WARNING),
                        _ => ("非特权 BPF 未知", theme::TEXT_MUTED),
                    };
                    badge(ui, label, color)
                        .on_hover_text("kernel.unprivileged_bpf_disabled；2 表示完全禁止非特权 BPF。");
                    ui.label(RichText::new("·").size(11.0).color(theme::TEXT_MUTED));
                    badge(ui, if c.tracefs_readable { "tracefs 可读" } else { "tracefs 仅 root" }, if c.tracefs_readable { theme::SUCCESS } else { theme::TEXT_MUTED });
                    badge(ui, if c.kprobe_events_writable { "kprobe_events 可写" } else { "kprobe_events 只读" }, if c.kprobe_events_writable { theme::SUCCESS } else { theme::TEXT_MUTED })
                        .on_hover_text(format!(
                            "挂载或移除探针会写入 tracefs 的 kprobe_events，需要提权。\ndebugfs：{}",
                            if c.debugfs_readable { "可读" } else { "不可读" }
                        ));
                    ui.label(
                        RichText::new(format!(
                            "扫描 {} ms · {} 秒前 · {}",
                            snap.sweep_ms,
                            snap.loaded_at.elapsed().as_secs(),
                            snap.kernel_release
                        ))
                        .size(10.5)
                        .color(theme::TEXT_MUTED),
                    );
                });
            });
    }

    fn probe_kernel_table(&mut self, ui: &mut egui::Ui, snap: &probe::Snapshot, table_h: f32) {
        let (rows, kind, color) = match self.probe_mode {
            ProbeMode::Syscalls => (&snap.syscalls, "syscall", theme::MEM),
            _ => (&snap.functions, "kprobe", theme::CPU),
        };
        let q = self.probe_query.trim();
        let indices: Vec<u32> = if q.is_empty() {
            (0..rows.len() as u32).collect()
        } else {
            rows.iter()
                .enumerate()
                .filter(|(_, s)| icontains(&s.name, q))
                .map(|(i, _)| i as u32)
                .collect()
        };
        let short = self.probe_mode == ProbeMode::Syscalls;
        let mut clicked: Option<String> = None;
        theme::card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                section_label(ui, if short { "系统调用挂载点" } else { "内核函数挂载点" });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(format!("{} / {}", thousands(indices.len()), thousands(rows.len()))).size(11.0).color(theme::TEXT_MUTED));
                    ui.add_space(10.0);
                    ui.label(RichText::new("点击符号选择挂载点").size(10.5).color(theme::TEXT_MUTED));
                });
            });
            ui.add_space(2.0);
            TableBuilder::new(ui)
                .striped(true)
                .sense(egui::Sense::click())
                .max_scroll_height(table_h)
                .auto_shrink([false, true])
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::exact(76.0))
                .column(Column::remainder())
                .column(Column::exact(150.0))
                .header(24.0, |mut header| {
                    header.col(|ui| {
                        section_label(ui, "类型");
                    });
                    header.col(|ui| {
                        section_label(ui, "符号");
                    });
                    header.col(|ui| {
                        section_label(ui, "模块");
                    });
                })
                .body(|body| {
                    body.rows(24.0, indices.len(), |mut row| {
                        let s = &rows[indices[row.index()] as usize];
                        let selected = matches!(&self.probe_sel, Some(ProbeSel::Kprobe(n)) if n == &s.name);
                        row.set_selected(selected);
                        row.col(|ui| {
                            badge(ui, kind, color);
                        });
                        row.col(|ui| {
                            let shown = if short { probe::syscall_short(&s.name) } else { s.name.as_str() };
                            ui.label(RichText::new(shown).size(12.0).monospace().color(theme::TEXT))
                                .on_hover_text(format!("{}（按此符号名挂载）", s.name));
                        });
                        row.col(|ui| {
                            if let Some(m) = &s.module {
                                badge(ui, m, theme::GPU);
                            } else {
                                ui.label(RichText::new("内核").size(11.0).color(theme::TEXT_MUTED));
                            }
                        });
                        if row.response().clicked() {
                            clicked = Some(s.name.clone());
                        }
                    });
                });
        });
        if let Some(name) = clicked {
            if self.probe_armed.is_some() {
                self.probe_stop();
            }
            self.probe_sel = Some(ProbeSel::Kprobe(name.clone()));
            self.status = format!("挂载点：kprobe:{name}");
            self.status_error = false;
        }
    }

    fn probe_uprobe_table(&mut self, ui: &mut egui::Ui, table_h: f32) {
        let Some(path) = self.probe_sel_exe.clone() else {
            theme::card_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("选择一个正在运行的可执行文件，解析其 ELF 函数符号作为 uprobe 挂载点。").size(12.0).color(theme::TEXT_SEC));
                ui.label(RichText::new("目标来自 /proc/<pid>/exe；已剥离的二进制只能看到动态导出符号。").size(11.0).color(theme::TEXT_MUTED));
            });
            return;
        };
        let parsed = self.probe_elf.remove(&path).unwrap_or_else(|| probe::elf_symbols(&path));
        let mut clicked: Option<String> = None;
        match &parsed {
            Ok(elf) => {
                let q = self.probe_query.trim();
                let indices: Vec<u32> = if q.is_empty() {
                    (0..elf.symbols.len() as u32).collect()
                } else {
                    elf.symbols
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| icontains(&s.name, q))
                        .map(|(i, _)| i as u32)
                        .collect()
                };
                theme::card_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        section_label(ui, "用户态 uprobe 挂载点");
                        ui.label(RichText::new(truncate_chars(&path.display().to_string(), 44)).size(11.0).monospace().color(theme::TEXT_SEC))
                            .on_hover_text(path.display().to_string());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let note = if elf.stripped {
                                format!("{} 个函数 · {} · 已剥离", thousands(elf.symbols.len()), elf.source)
                            } else {
                                format!("{} 个函数 · {}", thousands(elf.symbols.len()), elf.source)
                            };
                            ui.label(RichText::new(note).size(11.0).color(theme::TEXT_MUTED));
                        });
                    });
                    ui.add_space(2.0);
                    TableBuilder::new(ui)
                        .striped(true)
                        .sense(egui::Sense::click())
                        .max_scroll_height(table_h)
                        .auto_shrink([false, true])
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::remainder())
                        .column(Column::exact(96.0))
                        .column(Column::exact(64.0))
                        .column(Column::exact(56.0))
                        .header(24.0, |mut header| {
                            header.col(|ui| {
                                section_label(ui, "符号");
                            });
                            header.col(|ui| {
                                section_label(ui, "文件偏移");
                            });
                            header.col(|ui| {
                                section_label(ui, "大小");
                            });
                            header.col(|ui| {
                                section_label(ui, "绑定");
                            });
                        })
                        .body(|body| {
                            body.rows(24.0, indices.len(), |mut row| {
                                let s = &elf.symbols[indices[row.index()] as usize];
                                let selected = matches!(&self.probe_sel, Some(ProbeSel::Uprobe { exe, sym }) if exe == &path && sym == &s.name);
                                row.set_selected(selected);
                                row.col(|ui| {
                                    ui.label(RichText::new(&s.name).size(12.0).monospace().color(theme::TEXT));
                                });
                                row.col(|ui| {
                                    let (text, color, tip) = match s.off {
                                        Some(off) => (format!("0x{off:x}"), theme::TEXT_SEC, format!("文件偏移；vaddr 0x{:x}", s.addr)),
                                        None => ("—".to_string(), theme::TEXT_MUTED, format!("无文件数据（vaddr 0x{:x}）", s.addr)),
                                    };
                                    ui.label(RichText::new(text).size(11.5).monospace().color(color)).on_hover_text(tip);
                                });
                                row.col(|ui| {
                                    ui.label(RichText::new(s.size.to_string()).size(11.5).monospace().color(theme::TEXT_MUTED));
                                });
                                row.col(|ui| {
                                    ui.label(RichText::new(if s.global { "全局" } else { "局部" }).size(11.0).color(if s.global { theme::SUCCESS } else { theme::TEXT_MUTED }));
                                });
                                if row.response().clicked() {
                                    clicked = Some(s.name.clone());
                                }
                            });
                        });
                });
            }
            Err(e) => {
                theme::card_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    section_label(ui, "用户态 uprobe 挂载点");
                    ui.label(RichText::new(format!("无法解析 {}：{e}", path.display())).size(12.0).color(theme::DANGER));
                });
            }
        }
        if let Some(name) = clicked {
            if self.probe_armed.is_some() {
                self.probe_stop();
            }
            self.probe_sel = Some(ProbeSel::Uprobe { exe: path.clone(), sym: name.clone() });
            self.status = format!("挂载点：{}:{name}", path.display());
            self.status_error = false;
        }
        self.probe_elf.insert(path, parsed);
    }

    fn probe_agent_tick(&mut self) {
        if self.probe_armed.is_none() || self.probe_poll_at.elapsed() < Duration::from_millis(700) {
            return;
        }
        self.probe_poll_at = Instant::now();
        match probeclient::poll() {
            Ok(stats) => {
                self.probe_hits = stats.total;
                self.probe_recent = stats.calls;
                self.probe_agent_err = None;
            }
            Err(e) => {
                self.probe_armed = None;
                self.probe_agent_err = Some(e.clone());
                self.probe_recent.clear();
                self.status = format!("读取命中失败：{e}");
                self.status_error = true;
            }
        }
    }

    fn probe_start(&mut self) {
        let Some(sel) = self.probe_sel.clone() else {
            return;
        };
        let stack = self.probe_stack;
        let pid = if self.probe_pid.trim().is_empty() {
            None
        } else {
            match self.probe_pid.trim().parse::<u32>() {
                Ok(p) if p > 0 => Some(p),
                _ => {
                    self.probe_agent_err = Some("PID 过滤必须是正整数".to_string());
                    self.status = "PID 过滤必须是正整数".to_string();
                    self.status_error = true;
                    return;
                }
            }
        };
        let (kind, target, symbol) = match &sel {
            ProbeSel::Kprobe(n) if probe::is_syscall(n) => ("syscall", None, probe::syscall_short(n)),
            ProbeSel::Kprobe(n) => ("kprobe", None, n.as_str()),
            ProbeSel::Uprobe { exe, sym } => ("uprobe", Some(exe.as_path()), sym.as_str()),
        };
        let args = if kind == "syscall" { "" } else { self.probe_args.trim() };
        let result = probeclient::attach(&probeclient::Attach { kind, target, symbol, stack, pid, args });
        match result {
            Ok(()) => {
                self.probe_armed = Some(sel);
                self.probe_armed_stack = stack;
                self.probe_armed_pid = pid;
                self.probe_hits = 0;
                self.probe_recent.clear();
                self.probe_agent_err = None;
                self.probe_poll_at = Instant::now();
                self.status = "探针已挂载，等待命中…".to_string();
                self.status_error = false;
            }
            Err(e) => {
                self.probe_agent_err = Some(e.clone());
                self.status = format!("挂载失败：{e}");
                self.status_error = true;
            }
        }
    }

    fn probe_stop(&mut self) {
        if let Some(mut child) = self.probe_test_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if self.probe_armed.take().is_none() {
            return;
        }
        self.probe_recent.clear();
        self.probe_hits = 0;
        self.probe_armed_pid = None;
        match probeclient::detach() {
            Ok(()) => {
                self.status = "探针已停止".to_string();
                self.status_error = false;
            }
            Err(e) => {
                self.probe_agent_err = Some(e.clone());
                self.status = format!("停止探针失败：{e}");
                self.status_error = true;
            }
        }
    }

    fn probe_actions(&mut self, ui: &mut egui::Ui) {
        let is_syscall = matches!(&self.probe_sel, Some(ProbeSel::Kprobe(n)) if probe::is_syscall(n));
        let attach = match &self.probe_sel {
            Some(ProbeSel::Kprobe(n)) if probe::is_syscall(n) => Some((format!("syscall:{}", probe::syscall_short(n)), "系统调用")),
            Some(ProbeSel::Kprobe(n)) => Some((format!("kprobe:{n}"), "内核函数")),
            Some(ProbeSel::Uprobe { exe, sym }) => Some((format!("{}:{sym}", exe.display()), "用户态 uprobe")),
            None => None,
        };
        let armed = self.probe_armed.is_some();
        let uprobe_blocked = matches!(&self.probe_sel, Some(ProbeSel::Uprobe { .. })) && self.probe_uprobe_ok == Some(false);
        let mut copy_attach = false;
        let mut copy_hint = false;
        let mut start = false;
        let mut stop = false;
        let mut run_test = false;
        egui::Frame::NONE
            .fill(theme::EXTREME)
            .corner_radius(6)
            .inner_margin(Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("挂载点").size(11.0).color(theme::TEXT_MUTED));
                    match &attach {
                        Some((text, kind)) => {
                            ui.label(RichText::new(*kind).size(11.0).color(theme::INFO));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if armed {
                                    if action_btn(ui, "停止", theme::DANGER, true, false) {
                                        stop = true;
                                    }
                                    if let Some(pid) = self.probe_armed_pid {
                                        badge(ui, &format!("PID {pid}"), theme::INFO);
                                    }
                                    if self.probe_armed_stack {
                                        badge(ui, "抓栈", theme::WARNING);
                                    }
                                } else {
                                    if action_btn(ui, "挂载计数", theme::SUCCESS, !uprobe_blocked, false) {
                                        start = true;
                                    }
                                    ui.checkbox(&mut self.probe_stack, RichText::new("抓栈").size(11.5));
                                    if action_btn(ui, "复制", theme::INFO, true, false) {
                                        copy_attach = true;
                                    }
                                }
                                ui.add_space(8.0);
                                ui.add(egui::Label::new(RichText::new(text.as_str()).size(11.0).monospace().color(theme::TEXT)).truncate());
                            });
                        }
                        None => {
                            ui.label(RichText::new("点击表格中的符号，选择要挂载的 kprobe / syscall / uprobe").size(11.0).color(theme::TEXT_MUTED));
                        }
                    }
                });
                if !armed && attach.is_some() {
                        ui.horizontal_wrapped(|ui| {
                            if !is_syscall {
                                ui.label(RichText::new("参数").size(11.0).color(theme::TEXT_MUTED)).on_hover_text(
                                    "tracefs fetchargs，留空默认抓 x0–x7。示例：arg0=%x0 arg1=+0(%x1):string",
                                );
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.probe_args)
                                        .id(egui::Id::unique("probe_args"))
                                        .hint_text("arg0=%x0 arg1=+0(%x1):string")
                                        .desired_width(250.0),
                                );
                            }
                            ui.label(RichText::new("PID").size(11.0).color(theme::TEXT_MUTED))
                                .on_hover_text("只抓该进程/线程；留空抓全部。");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.probe_pid)
                                    .id(egui::Id::unique("probe_pid"))
                                    .hint_text("过滤")
                                    .desired_width(72.0),
                            );
                            ui.label(RichText::new("测试").size(11.0).color(theme::TEXT_MUTED))
                                .on_hover_text("以当前用户运行简单命令（0.5 秒后 exec），并按该 PID 过滤。");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.probe_test_cmd)
                                    .id(egui::Id::unique("probe_test"))
                                    .hint_text("命令")
                                    .desired_width(190.0),
                            );
                            let can_test = !self.probe_test_cmd.trim().is_empty() && !uprobe_blocked;
                            if action_btn(ui, "挂载并测试", theme::INFO, can_test, false) {
                                run_test = true;
                            }
                        });
                }
                if armed {
                    ui.horizontal(|ui| {
                        badge(ui, "已挂载", theme::SUCCESS);
                        ui.label(RichText::new(format!("命中 {}", thousands(self.probe_hits as usize))).size(12.0).monospace().color(theme::CPU));
                        if let Some(call) = self.probe_recent.last() {
                            ui.label(RichText::new(format!("{}（{}）", call.comm, call.pid)).size(11.0).color(theme::TEXT_SEC));
                            let entry = probe_payload(&call.entry);
                            let ret = probe_payload(&call.ret);
                            let ret = ret.strip_prefix("arg1=").map(|v| format!("ret={v}")).unwrap_or(ret);
                            let hover = format!(
                                "入参：{}\n回参：{}\n栈：{}",
                                call.entry,
                                if call.ret.is_empty() { "（未返回）" } else { call.ret.as_str() },
                                if call.stack.is_empty() { "—" } else { call.stack.as_str() }
                            );
                            let ret_text = if ret.is_empty() { "…".to_string() } else { truncate_chars(&ret, 30) };
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!("入: {}  回: {}", truncate_chars(&entry, 46), ret_text))
                                        .size(10.5)
                                        .monospace()
                                        .color(theme::TEXT_MUTED),
                                )
                                .truncate(),
                            )
                            .on_hover_text(hover);
                        } else {
                            ui.label(RichText::new("等待首次命中…").size(11.0).color(theme::TEXT_MUTED));
                        }
                    });
                } else if let Some(err) = &self.probe_agent_err {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(format!("⚠ {err}")).size(11.0).color(theme::WARNING));
                        if err.contains("helper") {
                            if action_btn(ui, "复制安装命令", theme::INFO, true, false) {
                                copy_hint = true;
                            }
                            ui.label(RichText::new(helper_install_hint()).size(10.5).monospace().color(theme::TEXT_MUTED));
                        }
                    });
                } else if uprobe_blocked {
                    ui.label(
                        RichText::new("此内核未启用 uprobes（CONFIG_UPROBE_EVENTS），只能浏览符号")
                            .size(11.0)
                            .color(theme::WARNING),
                    );
                }
            });
        if copy_attach
            && let Some((text, _)) = &attach
        {
            ui.ctx().copy_text(text.clone());
            self.status = "已复制挂载点".to_string();
            self.status_error = false;
        }
        if copy_hint {
            ui.ctx().copy_text(helper_install_hint());
            self.status = "已复制安装命令".to_string();
            self.status_error = false;
        }
        if start {
            self.probe_start();
        }
        if stop {
            self.probe_stop();
        }
        if run_test {
            self.probe_run_test();
        }
    }

    fn probe_run_test(&mut self) {
        let cmd = self.probe_test_cmd.trim().to_string();
        if cmd.is_empty() || self.probe_sel.is_none() {
            return;
        }
        if let Some(mut child) = self.probe_test_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.probe_stop();
        let child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("sleep 0.5; exec {cmd}"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let child = match child {
            Ok(c) => c,
            Err(e) => {
                self.probe_agent_err = Some(format!("启动测试命令失败：{e}"));
                self.status = format!("启动测试命令失败：{e}");
                self.status_error = true;
                return;
            }
        };
        let pid = child.id();
        self.probe_pid = pid.to_string();
        self.probe_test_child = Some(child);
        self.probe_start();
        if self.probe_armed.is_some() {
            self.status = format!("测试命令已启动（PID {pid}），等待命中…");
            self.status_error = false;
        } else if let Some(mut child) = self.probe_test_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn bottom_panel(&mut self, ui: &mut egui::Ui) {
        // 先取出选中信息（owned），避免闭包内 &mut self 与 &self.usage 借用冲突
        let sel: Option<(i32, String, char, i64)> = self
            .selected
            .and_then(|pid| self.usage.procs.iter().find(|p| p.pid == pid))
            .map(|p| (p.pid, p.comm.clone(), p.state, p.nice));
        let actionable = sel.as_ref().is_some_and(|(pid, ..)| *pid != 1 && (self.host_sel.is_some() || *pid != self.own_pid));
        let stopped = sel.as_ref().is_some_and(|(_, _, state, _)| *state == 'T');
        egui::Panel::bottom("bottom").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if let Some((pid, comm, _, _)) = &sel {
                    ui.label(RichText::new(format!("已选 {comm}")).size(12.5).strong().color(theme::TEXT));
                    ui.label(RichText::new(format!("PID {pid}")).size(11.5).monospace().color(theme::TEXT_MUTED));
                } else {
                    ui.label(RichText::new("未选中进程").size(12.5).color(theme::TEXT_MUTED));
                }
                ui.separator();
                if action_btn(ui, "结束进程", theme::DANGER, actionable, false)
                    && let Some((pid, comm, _, _)) = &sel
                {
                    self.ask_confirm(ConfirmKind::Terminate, *pid, comm);
                }
                if action_btn(ui, "强制结束", theme::DANGER, actionable, true)
                    && let Some((pid, comm, _, _)) = &sel
                {
                    self.ask_confirm(ConfirmKind::Kill, *pid, comm);
                }
                if action_btn(ui, "结束进程树", theme::DANGER, actionable, false)
                    && let Some((pid, comm, _, _)) = &sel
                {
                    self.ask_confirm_tree(ConfirmKind::Terminate, *pid, comm);
                }
                if action_btn(ui, "调优先级", theme::INFO, actionable, false)
                    && let Some((pid, comm, _, nice)) = &sel
                {
                    self.nice_dialog = Some(NiceDialog { pid: *pid, comm: comm.clone(), value: (*nice).clamp(-19, 19) as i32 });
                }
                let pause_label = if stopped { "恢复进程" } else { "暂停进程" };
                if action_btn(ui, pause_label, theme::WARNING, actionable, false)
                    && let Some((pid, comm, _, _)) = &sel
                {
                    let (pid, comm) = (*pid, comm.clone());
                    self.act_pause(pid, stopped, &comm);
                }
            });
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                let color = if self.status_error {
                    theme::DANGER
                } else if self.status == "就绪" {
                    theme::TEXT_MUTED
                } else {
                    theme::SUCCESS
                };
                let (dot, _) = ui.allocate_exact_size(Vec2::new(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(dot.center(), 3.0, color);
                ui.label(RichText::new(self.status.as_str()).size(12.0).color(color));
            });
            ui.add_space(6.0);
        });
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        // 先拷贝数据，避免 Modal 闭包内 &mut self 与借用冲突
        let confirm = self.confirm.as_ref().map(|c| (c.kind, c.pid, c.comm.clone(), c.cmdline.clone(), c.tree));
        if let Some((kind, pid, comm, cmdline, tree)) = confirm {
            let mut done = false;
            egui::Modal::new(egui::Id::unique("confirm")).show(ctx, |ui| {
                ui.set_width(400.0);
                ui.spacing_mut().item_spacing = Vec2::new(10.0, 10.0);
                let kill = kind == ConfirmKind::Kill;
                let action_name = if kill { "强制结束" } else { "结束" };
                let noun = if tree { "进程树" } else { "进程" };
                let accent = if kill { theme::DANGER } else { theme::WARNING };
                ui.horizontal(|ui| {
                    let (dot, _) = ui.allocate_exact_size(Vec2::new(12.0, 12.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot.center(), 5.0, accent);
                    ui.label(RichText::new(format!("{action_name}{noun}")).size(17.0).strong().color(theme::TEXT));
                });
                ui.label(RichText::new(format!("确定要{action_name}{noun} {pid}（{comm}）吗？")).size(13.0).color(theme::TEXT_SEC));
                egui::Frame::NONE.fill(theme::EXTREME).corner_radius(6).inner_margin(Margin::symmetric(10, 8)).show(ui, |ui| {
                    ui.set_width(378.0);
                    ui.add(egui::Label::new(RichText::new(truncate_chars(&cmdline, 220)).size(11.5).monospace().color(theme::TEXT_SEC)).wrap());
                });
                if tree {
                    ui.label(RichText::new("将同时结束该进程及其全部子进程。").size(12.0).color(theme::WARNING));
                }
                if kill {
                    ui.label(RichText::new("注意：强制结束可能丢失未保存数据。").size(12.0).color(theme::WARNING));
                }
                ui.add_space(2.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if action_btn(ui, "确定", accent, true, kill) {
                        let (r, n) = self.act_finish(kind, pid, tree);
                        let suffix = if n > 1 { format!("（{n} 个进程）") } else { String::new() };
                        let where_ = if self.host_sel.is_some() { "（远端）" } else { "" };
                        self.report(r, format!("已{action_name}{noun} {pid}（{comm}）{suffix}{where_}"));
                        done = true;
                    }
                    ui.add_space(8.0);
                    if action_btn(ui, "取消", theme::TEXT_SEC, true, false) {
                        done = true;
                    }
                });
            });
            if done {
                self.confirm = None;
            }
        }

        let nice = self.nice_dialog.as_ref().map(|d| (d.pid, d.comm.clone(), d.value));
        if let Some((pid, comm, mut value)) = nice {
            let mut apply = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::unique("nice")).show(ctx, |ui| {
                ui.set_width(400.0);
                ui.spacing_mut().item_spacing = Vec2::new(10.0, 10.0);
                ui.horizontal(|ui| {
                    let (dot, _) = ui.allocate_exact_size(Vec2::new(12.0, 12.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot.center(), 5.0, theme::INFO);
                    ui.label(RichText::new("调整优先级").size(17.0).strong().color(theme::TEXT));
                });
                ui.label(RichText::new(format!("进程 {pid}（{comm}）")).size(13.0).color(theme::TEXT_SEC));
                ui.add(egui::Slider::new(&mut value, -19..=19).text("nice"));
                ui.label(RichText::new("数值越大优先级越低；调低数值（更高优先级）需要 sudo。").size(11.5).color(theme::TEXT_MUTED));
                ui.add_space(2.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if action_btn(ui, "应用", theme::INFO, true, false) {
                        apply = true;
                    }
                    ui.add_space(8.0);
                    if action_btn(ui, "取消", theme::TEXT_SEC, true, false) {
                        cancel = true;
                    }
                });
            });
            if apply {
                self.act_set_nice(pid, value, &comm);
                self.nice_dialog = None;
            } else if cancel {
                self.nice_dialog = None;
            } else if let Some(d) = &mut self.nice_dialog {
                d.value = value;
            }
        }

        // 添加 SSH 主机
        if let Some(mut text) = self.add_host.clone() {
            let mut add = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::unique("add_host")).show(ctx, |ui| {
                ui.set_width(420.0);
                ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
                ui.horizontal(|ui| {
                    let (dot, _) = ui.allocate_exact_size(Vec2::new(12.0, 12.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot.center(), 5.0, theme::INFO);
                    ui.label(RichText::new("添加 SSH 主机").size(17.0).strong().color(theme::TEXT));
                });
                ui.label(RichText::new("格式 user@host 或 ~/.ssh/config 别名；需本机免密登录（只读采集）").size(11.0).color(theme::TEXT_MUTED));
                ui.add(egui::TextEdit::singleline(&mut text).hint_text("pi@192.168.1.10").desired_width(400.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if action_btn(ui, "添加", theme::SUCCESS, !text.trim().is_empty(), false) {
                        add = true;
                    }
                    ui.add_space(8.0);
                    if action_btn(ui, "取消", theme::TEXT_SEC, true, false) {
                        cancel = true;
                    }
                });
            });
            if add {
                let raw = text.trim().to_string();
                match remote::SshTarget::parse(&raw) {
                    Ok(t) => {
                        if !self.hosts.contains(&t) {
                            self.hosts.push(t.clone());
                            if let Err(e) = remote::save_hosts(&self.hosts) {
                                self.status_error = true;
                                self.status = e;
                            } else {
                                self.status_error = false;
                                self.status = format!("已添加主机 {t}");
                            }
                            if let Ok(mut fh) = self.fleet_hosts.lock() {
                                fh.push(t);
                            }
                        }
                        self.add_host = None;
                    }
                    // 非法目标留在输入框里让用户修正，不落盘
                    Err(e) => {
                        self.status_error = true;
                        self.status = format!("主机目标非法：{e}");
                        self.add_host = Some(text);
                    }
                }
            } else if cancel {
                self.add_host = None;
            } else {
                self.add_host = Some(text);
            }
        }

        // 平台配置编辑弹窗（可编辑、保存后即时重载）
        if let Some(mut text) = self.platform_edit.clone() {
            let mut save = false;
            let mut cancel = false;
            let mut regen = false;
            egui::Modal::new(egui::Id::unique("platform_conf")).show(ctx, |ui| {
                ui.set_width(620.0);
                ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
                ui.horizontal(|ui| {
                    let (dot, _) = ui.allocate_exact_size(Vec2::new(12.0, 12.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot.center(), 5.0, theme::INFO);
                    ui.label(RichText::new("配置 · platform.conf").size(17.0).strong().color(theme::TEXT));
                });
                ui.label(RichText::new("~/.config/system-monitor/platform.conf —— 保存后即时生效").size(11.0).color(theme::TEXT_MUTED));
                ui.horizontal(|ui| {
                    ui.label(RichText::new("操作系统档案").size(12.0).color(theme::TEXT_SEC));
                    let mut pick = platform::text_os(&text).unwrap_or_default();
                    let before = pick.clone();
                    egui::ComboBox::from_id_salt("pconf_os")
                        .selected_text(if pick.is_empty() { "自定义".to_string() } else { pick.clone() })
                        .width(150.0)
                        .show_ui(ui, |ui| {
                            for os in platform::KNOWN_OS {
                                ui.selectable_value(&mut pick, (*os).to_string(), *os);
                            }
                            // 若当前 os 不在预置列表里（自定义），也列出来方便回选
                            let cur = pick.clone();
                            if !cur.is_empty() && !platform::KNOWN_OS.contains(&cur.as_str()) {
                                ui.selectable_value(&mut pick, cur.clone(), cur);
                            }
                        });
                    if pick != before {
                        text = platform::to_text(&platform::builtin(&pick));
                    }
                    ui.label(RichText::new("选择会载入该系统默认采集路径，可再微调").size(11.0).color(theme::TEXT_MUTED));
                });
                egui::Frame::NONE.fill(theme::EXTREME).corner_radius(6).inner_margin(Margin::same(8)).show(ui, |ui| {
                    ui.set_width(600.0);
                    ui.add(
                        egui::TextEdit::multiline(&mut text)
                            .code_editor()
                            .desired_width(600.0)
                            .desired_rows(16)
                            .text_color(theme::TEXT),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if action_btn(ui, "保存并应用", theme::SUCCESS, true, false) {
                        save = true;
                    }
                    ui.add_space(8.0);
                    if action_btn(ui, "取消", theme::TEXT_SEC, true, false) {
                        cancel = true;
                    }
                    ui.add_space(8.0);
                    if action_btn(ui, "重新生成默认", theme::WARNING, true, false) {
                        regen = true;
                    }
                });
            });
            if save {
                match platform::save_text(&text) {
                    Ok(()) => {
                        platform::reload();
                        self.status_error = false;
                        self.status = "已保存并应用平台配置".to_string();
                        self.platform_edit = None;
                    }
                    Err(e) => {
                        self.status_error = true;
                        self.status = format!("保存失败：{e}");
                        self.platform_edit = Some(text);
                    }
                }
            } else if regen {
                self.platform_edit = Some(platform::regenerate_text());
            } else if cancel {
                self.platform_edit = None;
            } else {
                self.platform_edit = Some(text);
            }
        }

        // 进程详情弹窗（双击进程行打开）
        let det = self.details.clone();
        if let Some((p, d)) = det {
            let mut close = false;
            let (slabel, scolor) = theme::state_badge(p.state);
            egui::Modal::new(egui::Id::unique("process_details")).show(ctx, |ui| {
                ui.set_width(460.0);
                ui.spacing_mut().item_spacing = Vec2::new(10.0, 10.0);
                ui.horizontal(|ui| {
                    let (dot, _) = ui.allocate_exact_size(Vec2::new(12.0, 12.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot.center(), 5.0, theme::INFO);
                    ui.label(RichText::new("进程详情").size(17.0).strong().color(theme::TEXT));
                });
                ui.label(RichText::new(format!("{}（PID {}）", p.comm, p.pid)).size(13.0).color(theme::TEXT_SEC));
                egui::Grid::new("detail_grid").num_columns(2).spacing(Vec2::new(16.0, 6.0)).show(ui, |ui| {
                    ui.label(RichText::new("父进程 PPID").size(12.0).color(theme::TEXT_MUTED));
                    ui.label(RichText::new(p.ppid.to_string()).size(12.0).monospace().color(theme::TEXT));
                    ui.end_row();
                    ui.label(RichText::new("用户 UID").size(12.0).color(theme::TEXT_MUTED));
                    ui.label(RichText::new(d.uid.map(|u| u.to_string()).unwrap_or_else(|| "—".into())).size(12.0).monospace().color(theme::TEXT));
                    ui.end_row();
                    ui.label(RichText::new("组 GID").size(12.0).color(theme::TEXT_MUTED));
                    ui.label(RichText::new(d.gid.map(|g| g.to_string()).unwrap_or_else(|| "—".into())).size(12.0).monospace().color(theme::TEXT));
                    ui.end_row();
                    ui.label(RichText::new("状态").size(12.0).color(theme::TEXT_MUTED));
                    ui.label(RichText::new(format!("{slabel}（{}）", p.state)).size(12.0).color(scolor));
                    ui.end_row();
                    ui.label(RichText::new("nice").size(12.0).color(theme::TEXT_MUTED));
                    ui.label(RichText::new(p.nice.to_string()).size(12.0).monospace().color(theme::TEXT));
                    ui.end_row();
                    ui.label(RichText::new("线程数").size(12.0).color(theme::TEXT_MUTED));
                    ui.label(RichText::new(d.threads.to_string()).size(12.0).monospace().color(theme::TEXT));
                    ui.end_row();
                    ui.label(RichText::new("虚拟内存").size(12.0).color(theme::TEXT_MUTED));
                    ui.label(RichText::new(format!("{:.1} MB", d.vsize_kb as f64 / 1024.0)).size(12.0).monospace().color(theme::TEXT));
                    ui.end_row();
                    ui.label(RichText::new("常驻内存").size(12.0).color(theme::TEXT_MUTED));
                    ui.label(RichText::new(format!("{:.1} MB", d.rss_kb as f64 / 1024.0)).size(12.0).monospace().color(theme::TEXT));
                    ui.end_row();
                    ui.label(RichText::new("磁盘读").size(12.0).color(theme::TEXT_MUTED));
                    ui.label(RichText::new(format!("{:.1} MB", d.io_read_bytes as f64 / 1048576.0)).size(12.0).monospace().color(theme::TEXT));
                    ui.end_row();
                    ui.label(RichText::new("磁盘写").size(12.0).color(theme::TEXT_MUTED));
                    ui.label(RichText::new(format!("{:.1} MB", d.io_write_bytes as f64 / 1048576.0)).size(12.0).monospace().color(theme::TEXT));
                    ui.end_row();
                });
                for (label, val) in [
                    ("可执行", d.exe.clone()),
                    ("工作目录", d.cwd.clone()),
                    ("命令行", d.cmdline.clone()),
                ] {
                    ui.label(RichText::new(label).size(11.0).color(theme::TEXT_MUTED));
                    let shown = if val.is_empty() { "—".to_string() } else { val };
                    egui::Frame::NONE.fill(theme::EXTREME).corner_radius(6).inner_margin(Margin::symmetric(9, 6)).show(ui, |ui| {
                        ui.set_width(430.0);
                        ui.add(egui::Label::new(RichText::new(shown).size(11.5).monospace().color(theme::TEXT_SEC)).wrap());
                    });
                }
                ui.add_space(2.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if action_btn(ui, "关闭", theme::TEXT_SEC, true, false) {
                        close = true;
                    }
                });
            });
            if close {
                self.details = None;
            }
        }
    }
}

impl eframe::App for CpuManagerApp {
    // eframe 0.37 将 App::update 改为 App::ui（传入根 Ui）；面板 API 相应改为 show(ui, …)。
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if (self.mini || self.view != View::Probe) && self.probe_armed.is_some() {
            self.probe_stop();
        }
        self.handle_keys(ui);
        let finished = self.probe_test_child.as_mut().and_then(|c| c.try_wait().ok().flatten());
        if let Some(status) = finished {
            self.probe_test_child = None;
            self.status = format!("测试命令已结束（{status}）");
            self.status_error = !status.success();
        }
        if !self.paused && self.last_sample.elapsed() >= Duration::from_secs_f32(self.interval) {
            self.resample();
        }
        match self.selected {
            Some(pid) => {
                if self.cmdline_cache.as_ref().is_none_or(|(p, _)| *p != pid) {
                    let mut cmd = match self.host_sel.clone() {
                        Some(h) => remote::read_cmdline(&h, pid).unwrap_or_default(),
                        None => read_cmdline(pid),
                    };
                    if cmd.is_empty() {
                        cmd = self
                            .usage
                            .procs
                            .iter()
                            .find(|p| p.pid == pid)
                            .map(|p| format!("[{}]", p.comm))
                            .unwrap_or_default();
                    }
                    self.cmdline_cache = Some((pid, cmd));
                }
            }
            None => self.cmdline_cache = None,
        }
        if self.mini {
            self.mini_hud(ui);
        } else {
            self.top_panel(ui);
            self.bottom_panel(ui);
            self.central(ui);
        }
        self.dialogs(ui.ctx());
        self.persist_if_changed();
        ui.ctx().request_repaint_after(Duration::from_secs_f32(self.interval));
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

fn section_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(11.5).strong().color(theme::TEXT_SEC));
}

/// 导航标签：选中态用强调色描边 + 淡色底 + 底部短横，未选中悬停提亮。
fn nav_tab(ui: &mut egui::Ui, active: bool, label: &str) -> egui::Response {
    let color = if active { theme::CPU } else { theme::TEXT_SEC };
    let galley = ui.painter().layout_no_wrap(label.to_owned(), egui::FontId::proportional(13.5), color);
    let size = Vec2::new(galley.size().x + 26.0, 32.0);
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if active {
            painter.rect_filled(rect, 8.0, theme::tint(theme::CPU, 0.16));
            painter.rect_stroke(rect, 8.0, Stroke::new(1.0, theme::tint(theme::CPU, 0.55)), egui::StrokeKind::Inside);
            painter.rect_filled(
                egui::Rect::from_min_max(Pos2::new(rect.left() + 10.0, rect.bottom() - 3.0), Pos2::new(rect.right() - 10.0, rect.bottom() - 1.0)),
                1.0,
                theme::CPU,
            );
        } else if resp.hovered() {
            painter.rect_filled(rect, 8.0, theme::ELEVATED);
        }
        painter.galley(rect.center() - galley.size() * 0.5, galley, color);
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// 细指标条里的一对「标签 + 数值」。
fn vital(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    ui.label(RichText::new(label).size(10.5).color(theme::TEXT_MUTED));
    ui.label(RichText::new(value).size(12.0).monospace().strong().color(color));
}

/// 指标摘要块：淡色底 + 小标签 + 大数值，用于网络页等页头。
fn stat_tile(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    egui::Frame::NONE
        .fill(theme::tint(color, 0.10))
        .stroke(Stroke::new(1.0, theme::tint(color, 0.30)))
        .corner_radius(8)
        .inner_margin(Margin::symmetric(12, 5))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.label(RichText::new(label).size(10.0).color(theme::TEXT_MUTED));
                ui.label(RichText::new(value).size(15.0).monospace().strong().color(color));
            });
        });
}

/// 大盘卡片：整宽卡片 + 标题行，内部通常放 1~3 张趋势图。
fn dash_card(ui: &mut egui::Ui, title: &str, color: Color32, add: impl FnOnce(&mut egui::Ui)) {
    let width = ui.available_width();
    theme::card_frame().show(ui, |ui| {
        ui.set_width((width - 26.0).max(160.0));
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.spacing_mut().item_spacing = Vec2::new(8.0, 10.0);
            card_title(ui, color, title, "");
            add(ui);
        });
    });
    ui.add_space(10.0);
}

/// 卡片标题行：彩色圆点 + 标题 + 右侧补充信息。
fn card_title(ui: &mut egui::Ui, color: Color32, title: &str, right: &str) {
    ui.horizontal(|ui| {
        let (dot, _) = ui.allocate_exact_size(Vec2::splat(8.0), egui::Sense::hover());
        ui.painter().circle_filled(dot.center(), 3.0, color);
        ui.label(RichText::new(title).size(11.5).strong().color(theme::TEXT_SEC));
        if !right.is_empty() {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(right).size(11.0).color(theme::TEXT_MUTED));
            });
        }
    });
}

fn thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn icontains(hay: &str, needle: &str) -> bool {
    let n = needle.as_bytes();
    if n.is_empty() {
        return true;
    }
    hay.as_bytes().windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

fn cap_badge(ui: &mut egui::Ui, label: &str, ok: Option<bool>) -> egui::Response {
    let (mark, color) = match ok {
        Some(true) => ("✓", theme::SUCCESS),
        Some(false) => ("✗", theme::WARNING),
        None => ("?", theme::TEXT_MUTED),
    };
    badge(ui, &format!("{label} {mark}"), color)
}

fn probe_payload(line: &str) -> String {
    if let Some(pos) = line.find(": (") {
        let rest = &line[pos + 3..];
        if let Some(end) = rest.find(')') {
            let tail = rest[end + 1..].trim();
            if !tail.is_empty() {
                return tail.to_string();
            }
        }
    }
    if let Some(pos) = line.find(" -> ") {
        return line[pos + 4..].trim().to_string();
    }
    if let Some(pos) = line.find("sys_")
        && let Some(paren) = line[pos..].find('(')
    {
        let args = line[pos + paren..].trim();
        return if args == "()" { "（无参数）".to_string() } else { args.to_string() };
    }
    line.trim().to_string()
}

fn helper_install_hint() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.ancestors().nth(3).map(|root| root.join("scripts/install-probe-helper.sh")))
        .filter(|p| p.is_file())
        .map(|p| format!("sudo {}", p.display()))
        .unwrap_or_else(|| "sudo scripts/install-probe-helper.sh".to_string())
}

fn start_fleet_poller(
    fleet: Arc<Mutex<HashMap<String, remote::FleetSummary>>>,
    hosts: Arc<Mutex<Vec<remote::SshTarget>>>,
) {
    std::thread::spawn(move || {
        let mut prev: HashMap<String, Option<remote::Counters>> = HashMap::new();
        loop {
            let round_start = Instant::now();
            let list = hosts.lock().map(|h| h.clone()).unwrap_or_default();
            for target in list {
                let key = target.as_str().to_string();
                let mut p = prev.remove(&key).flatten();
                // 每台主机独立 10s deadline：一台挂住不会拖住整轮
                let s = remote::summary(&target, &mut p);
                prev.insert(key.clone(), p);
                if let Ok(mut f) = fleet.lock() {
                    f.insert(key, s);
                }
            }
            // 下一轮 = 本轮开始 + 5s，避免串行 SSH 耗时造成刷新周期漂移
            let spent = round_start.elapsed();
            if spent < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_secs(5) - spent);
            }
        }
    });
}

fn start_metrics_server(shared: Arc<Mutex<SharedMetrics>>) {
    std::thread::spawn(move || {
        let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:9876") else {
            return;
        };
        for stream in listener.incoming() {
            let Ok(mut s) = stream else {
                continue;
            };
            let m = shared.lock().map(|m| m.clone()).unwrap_or_default();
            let json = format!(
                "{{\"cpu\":{:.1},\"mem\":{:.1},\"temp\":{:.1},\"power\":{:.2},\"gpu_ghz\":{:.2},\"disk_read_kbps\":{:.1},\"disk_write_kbps\":{:.1},\"net_rx_kbps\":{:.1},\"net_tx_kbps\":{:.1},\"procs\":{}}}",
                m.cpu, m.mem, m.temp, m.power, m.gpu, m.disk_r, m.disk_w, m.net_rx, m.net_tx, m.procs
            );
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json.len(),
                json
            );
            use std::io::Write;
            let _ = s.write_all(resp.as_bytes());
        }
    });
}

fn history_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share/system-monitor/history.csv"))
}

fn parse_hist_line(s: &str) -> Option<[f32; 9]> {
    let v: Vec<f32> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    if v.len() == 9 {
        Some([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]])
    } else {
        None
    }
}

fn load_history_into(perf: &mut PerfHistory) {
    let Some(p) = history_path() else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(p) else {
        return;
    };
    let lines: Vec<&str> = text.lines().collect();
    for line in lines.iter().rev().take(HIST_CAP).rev() {
        if let Some(a) = parse_hist_line(line) {
            perf.push_sample(a);
        }
    }
}

fn notify(title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .arg("-a")
        .arg("系统监视器")
        .arg(title)
        .arg(body)
        .spawn();
}

fn section_card(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    let width = ui.available_width();
    theme::card_frame().show(ui, |ui| {
        ui.set_width((width - 26.0).max(200.0));
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
            card_title(ui, theme::INFO, title, "");
            add(ui);
        });
    });
    ui.add_space(10.0);
}

fn card(ui: &mut egui::Ui, width: f32, min_h: f32, add: impl FnOnce(&mut egui::Ui)) {
    theme::card_frame().show(ui, |ui| {
        // 父级是 horizontal，卡片内容必须显式改回纵向堆叠
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.set_width(width);
            ui.set_min_height(min_h);
            ui.spacing_mut().item_spacing = Vec2::new(8.0, 6.0);
            add(ui);
        });
    });
}

fn badge(ui: &mut egui::Ui, text: &str, fg: Color32) -> egui::Response {
    let font = egui::FontId::proportional(11.0);
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, fg);
    let size = galley.size() + Vec2::new(14.0, 6.0);
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter().rect_filled(rect, 6.0, theme::tint(fg, 0.18));
    ui.painter().galley(rect.min + Vec2::new(7.0, 3.0), galley, fg);
    resp
}

fn action_btn(ui: &mut egui::Ui, label: &str, color: Color32, enabled: bool, filled: bool) -> bool {
    let (fill, stroke, text_color) = if filled {
        (theme::DANGER_FILL, theme::DANGER_FILL, Color32::from_rgb(255, 246, 246))
    } else {
        (theme::tint(color, 0.12), theme::tint(color, 0.5), color)
    };
    let btn = egui::Button::new(RichText::new(label).size(13.0).strong().color(text_color))
        .fill(fill)
        .stroke(Stroke::new(1.0, stroke))
        .corner_radius(7)
        .min_size(Vec2::new(0.0, 30.0));
    let resp = ui.add_enabled(enabled, btn);
    if enabled && resp.hovered() {
        ui.painter().rect_filled(resp.rect, 7.0, Color32::from_white_alpha(12));
    }
    resp.clicked()
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    const CJK: &[&str] = &[
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
    ];
    if let Some(bytes) = CJK.iter().find_map(|p| std::fs::read(p).ok()) {
        fonts.font_data.insert("cjk".to_owned(), egui::FontData::from_owned(bytes).into());
        fonts.families.entry(egui::FontFamily::Proportional).or_default().insert(0, "cjk".to_owned());
        fonts.families.entry(egui::FontFamily::Monospace).or_default().push("cjk".to_owned());
    }
    const MONO: &[&str] = &[
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    ];
    if let Some(bytes) = MONO.iter().find_map(|p| std::fs::read(p).ok()) {
        fonts.font_data.insert("mono".to_owned(), egui::FontData::from_owned(bytes).into());
        fonts.families.entry(egui::FontFamily::Monospace).or_default().insert(0, "mono".to_owned());
    }
    ctx.set_fonts(fonts);
}

fn sparkline_of(
    ui: &mut egui::Ui,
    width: f32,
    height: f32,
    data: &VecDeque<f32>,
    line: Color32,
    max: f32,
    span: usize,
) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 6.0, theme::EXTREME);
    for f in [0.25, 0.5, 0.75] {
        let y = rect.bottom() - 3.0 - (height - 6.0) * f;
        painter.line_segment([Pos2::new(rect.left() + 4.0, y), Pos2::new(rect.right() - 4.0, y)], Stroke::new(1.0, theme::BORDER));
    }
    let n = data.len();
    if n < 2 {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "采集中…",
            egui::FontId::proportional(10.0),
            theme::TEXT_MUTED,
        );
        return;
    }
    // 采样点从右往左按固定间距排列：历史不足时不会拉成一条横跨整卡的斜线。
    let step = ((width - 8.0) / (span.max(2) - 1) as f32).max(0.5);
    let pts: Vec<Pos2> = data
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = rect.right() - 4.0 - (n as f32 - 1.0 - i as f32) * step;
            let y = rect.bottom() - 3.0 - (height - 6.0) * (v / max).clamp(0.0, 1.0);
            Pos2::new(x, y)
        })
        .collect();
    let fill = theme::lerp_color(theme::EXTREME, line, 0.20);
    for p in &pts {
        painter.line_segment([Pos2::new(p.x, rect.bottom() - 3.0), *p], Stroke::new(step.max(1.0), fill));
    }
    for pair in pts.windows(2) {
        painter.line_segment([pair[0], pair[1]], Stroke::new(1.6, line));
    }
    if let Some(last) = pts.last() {
        painter.circle_filled(*last, 2.4, line);
    }
}

fn metric_graph(
    ui: &mut egui::Ui,
    title: &str,
    value: &str,
    color: Color32,
    fixed_max: Option<f32>,
    data: &VecDeque<f32>,
    height: f32,
) {
    let width = ui.available_width().max(120.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 8.0, theme::EXTREME);
    let max = fixed_max.unwrap_or_else(|| data.iter().cloned().fold(1.0_f32, f32::max).max(1.0));
    for f in [0.25_f32, 0.5, 0.75] {
        let y = rect.bottom() - 6.0 - (height - 24.0) * f;
        painter.line_segment(
            [Pos2::new(rect.left() + 6.0, y), Pos2::new(rect.right() - 6.0, y)],
            Stroke::new(1.0, theme::BORDER),
        );
    }
    let n = data.len();
    if n >= 2 {
        let plot_top = rect.top() + 20.0;
        let plot_bottom = rect.bottom() - 6.0;
        let pts: Vec<Pos2> = data
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let x = rect.left() + 6.0 + (width - 12.0) * (i as f32 / (n - 1) as f32);
                let frac = (v / max).clamp(0.0, 1.0);
                let y = plot_bottom - (plot_bottom - plot_top) * frac;
                Pos2::new(x, y)
            })
            .collect();
        let fill = theme::lerp_color(theme::EXTREME, color, 0.20);
        let dx = ((width - 12.0) / (n - 1) as f32).max(1.0);
        for p in &pts {
            painter.line_segment([Pos2::new(p.x, plot_bottom), *p], Stroke::new(dx, fill));
        }
        for pair in pts.windows(2) {
            painter.line_segment([pair[0], pair[1]], Stroke::new(1.6, color));
        }
    }
    painter.text(rect.left_top() + egui::vec2(8.0, 5.0), egui::Align2::LEFT_TOP, title, egui::FontId::proportional(12.0), theme::TEXT_SEC);
    painter.text(rect.right_top() + egui::vec2(-8.0, 5.0), egui::Align2::RIGHT_TOP, value, egui::FontId::monospace(13.0), color);
}

fn sort_col_key(c: SortCol) -> &'static str {
    match c {
        SortCol::Cpu => "cpu",
        SortCol::Mem => "mem",
        SortCol::MemPct => "mempct",
        SortCol::Pid => "pid",
        SortCol::Ppid => "ppid",
        SortCol::Name => "name",
        SortCol::User => "user",
        SortCol::Nice => "nice",
        SortCol::State => "state",
    }
}

fn sort_col_from(key: &str) -> SortCol {
    match key {
        "mem" => SortCol::Mem,
        "mempct" => SortCol::MemPct,
        "pid" => SortCol::Pid,
        "ppid" => SortCol::Ppid,
        "name" => SortCol::Name,
        "user" => SortCol::User,
        "nice" => SortCol::Nice,
        "state" => SortCol::State,
        _ => SortCol::Cpu,
    }
}

fn table_mode_key(m: TableMode) -> &'static str {
    match m {
        TableMode::Flat => "flat",
        TableMode::Tree => "tree",
        TableMode::Apps => "apps",
    }
}

fn table_mode_from(key: &str) -> TableMode {
    match key {
        "tree" => TableMode::Tree,
        "apps" => TableMode::Apps,
        _ => TableMode::Flat,
    }
}

fn sort_procs(rows: &mut [ProcUsage], col: SortCol, desc: bool) {
    rows.sort_by(|a, b| {
        let ord = match col {
            SortCol::Cpu => a.cpu_percent.partial_cmp(&b.cpu_percent).unwrap_or(std::cmp::Ordering::Equal),
            SortCol::Mem => a.rss_kb.cmp(&b.rss_kb),
            SortCol::MemPct => a.mem_percent.partial_cmp(&b.mem_percent).unwrap_or(std::cmp::Ordering::Equal),
            SortCol::Pid => a.pid.cmp(&b.pid),
            SortCol::Ppid => a.ppid.cmp(&b.ppid),
            SortCol::Name => a.comm.cmp(&b.comm),
            SortCol::User => a.user.cmp(&b.user),
            SortCol::Nice => a.nice.cmp(&b.nice),
            SortCol::State => a.state.cmp(&b.state),
        };
        if desc { ord.reverse() } else { ord }
    });
}

/// 在可见 PID 序列中按方向移动选择：无选中时 down→首个、up→末个；边界处夹住；选中项已消失则视为无选中。
fn step_pid(pids: &[i32], current: Option<i32>, down: bool) -> Option<i32> {
    if pids.is_empty() {
        return None;
    }
    let idx = current.and_then(|pid| pids.iter().position(|&p| p == pid));
    let next = match idx {
        Some(i) => {
            if down {
                (i + 1).min(pids.len() - 1)
            } else {
                i.saturating_sub(1)
            }
        }
        None => {
            if down {
                0
            } else {
                pids.len() - 1
            }
        }
    };
    Some(pids[next])
}

#[cfg(test)]
mod tests {
    use super::{icontains, step_pid, thousands};

    #[test]
    fn thousands_grouping() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(66752), "66,752");
    }

    #[test]
    fn case_insensitive_search() {
        assert!(icontains("vfs_read", "READ"));
        assert!(icontains("__arm64_sys_openat", "SYS_OPEN"));
        assert!(!icontains("vfs_read", "socket"));
        assert!(icontains("anything", ""));
    }

    #[test]
    fn empty_list_returns_none() {
        assert_eq!(step_pid(&[], None, true), None);
        assert_eq!(step_pid(&[], Some(5), false), None);
    }

    #[test]
    fn none_selected_down_picks_first() {
        assert_eq!(step_pid(&[10, 20, 30], None, true), Some(10));
    }

    #[test]
    fn none_selected_up_picks_last() {
        assert_eq!(step_pid(&[10, 20, 30], None, false), Some(30));
    }

    #[test]
    fn down_moves_to_next() {
        assert_eq!(step_pid(&[10, 20, 30], Some(20), true), Some(30));
    }

    #[test]
    fn up_moves_to_prev() {
        assert_eq!(step_pid(&[10, 20, 30], Some(20), false), Some(10));
    }

    #[test]
    fn down_at_last_clamps() {
        assert_eq!(step_pid(&[10, 20, 30], Some(30), true), Some(30));
    }

    #[test]
    fn up_at_first_clamps() {
        assert_eq!(step_pid(&[10, 20, 30], Some(10), false), Some(10));
    }

    #[test]
    fn stale_pid_down_picks_first() {
        assert_eq!(step_pid(&[10, 20, 30], Some(99), true), Some(10));
    }

    #[test]
    fn hist_line_roundtrip() {
        assert_eq!(super::parse_hist_line("1.0,2.0,3.0,4.0,5.0,6.0,7.0,8.0,9.0").unwrap()[8], 9.0);
        assert!(super::parse_hist_line("1,2,3").is_none());
    }

    #[test]
    fn single_element_stays() {
        assert_eq!(step_pid(&[42], Some(42), true), Some(42));
        assert_eq!(step_pid(&[42], None, false), Some(42));
    }
}
