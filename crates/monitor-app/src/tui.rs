//! 终端界面：`system-monitor --tui`（无图形环境时自动启用）。
//! 本地零依赖读取 /proc；远端经 SSH 拉取，可切换 hosts.conf 中的主机，
//! 支持对当前主机结束进程 / 发信号 / 暂停恢复。

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState};
use ratatui::Terminal;

use monitor_linux::pi::PiStats;
use monitor_linux::procstats::{Sampler, Usage, format_uptime};
use monitor_remote::remote;

const HIST: usize = 60;

#[derive(Clone, Copy, PartialEq)]
enum SortBy {
    Cpu,
    Mem,
    Pid,
}

impl SortBy {
    fn label(self) -> &'static str {
        match self {
            Self::Cpu => "CPU",
            Self::Mem => "内存",
            Self::Pid => "PID",
        }
    }
    fn next(self) -> Self {
        match self {
            Self::Cpu => Self::Mem,
            Self::Mem => Self::Pid,
            Self::Pid => Self::Cpu,
        }
    }
}

struct Pending {
    pid: i32,
    comm: String,
    sig: i32,
    tree: bool,
}

pub struct App {
    sampler: Sampler,
    usage: Usage,
    pi: PiStats,
    last: Instant,
    interval: Duration,
    history: VecDeque<f32>,
    hosts: Vec<remote::SshTarget>,
    host_idx: Option<usize>,
    shared: Arc<Mutex<remote::RemoteSlot>>,
    prev: Arc<Mutex<Option<remote::Counters>>>,
    busy: Arc<AtomicBool>,
    last_kick: Instant,
    sort: SortBy,
    table: TableState,
    paused: bool,
    status: String,
    status_err: bool,
    pending: Option<Pending>,
    help: bool,
    quit: bool,
}

impl App {
    fn new() -> Self {
        let interval = config_interval();
        Self {
            sampler: Sampler::new(),
            usage: Usage::default(),
            pi: PiStats::default(),
            last: Instant::now() - Duration::from_secs(10),
            interval,
            history: VecDeque::new(),
            hosts: remote::load_hosts().0,
            host_idx: None,
            shared: Arc::new(Mutex::new(remote::RemoteSlot::new())),
            prev: Arc::new(Mutex::new(None)),
            busy: Arc::new(AtomicBool::new(false)),
            last_kick: Instant::now(),
            sort: SortBy::Cpu,
            table: TableState::default(),
            paused: false,
            status: "就绪".to_string(),
            status_err: false,
            pending: None,
            help: false,
            quit: false,
        }
    }

    fn host(&self) -> Option<remote::SshTarget> {
        self.host_idx.and_then(|i| self.hosts.get(i).cloned())
    }

    fn host_label(&self) -> String {
        self.host().map(|t| t.as_str().to_string()).unwrap_or_else(|| "本地".to_string())
    }

    fn resample(&mut self) {
        if let Some(target) = self.host() {
            self.resample_remote(&target);
            return;
        }
        self.usage = self.sampler.sample();
        self.pi = monitor_linux::pi::read_pi_stats();
        self.last = Instant::now();
        self.push_hist();
    }

    fn push_hist(&mut self) {
        self.history.push_back(self.usage.total_percent);
        if self.history.len() > HIST {
            self.history.pop_front();
        }
    }

    fn resample_remote(&mut self, target: &remote::SshTarget) {
        // 与 GUI 相同的代次化采样：过期代次回写被丢弃，切主机不显示旧数据
        let key = target.as_str().to_string();
        let ticket = {
            let Ok(mut slot) = self.shared.lock() else {
                return;
            };
            let switched = slot.host != key;
            if switched {
                slot.reset_for(&key)
            } else {
                slot.generation
            }
        };
        let inflight = self.busy.load(Ordering::Relaxed);
        let kick = self.last_kick.elapsed() >= self.interval && !inflight;
        if kick && !self.paused {
            let mut ticket = ticket;
            self.busy.store(true, Ordering::Relaxed);
            self.last_kick = Instant::now();
            let shared = self.shared.clone();
            let prev = self.prev.clone();
            let busy = self.busy.clone();
            let t = target.clone();
            let kick_key = key.clone();
            if let Ok(mut slot) = self.shared.lock() {
                ticket = slot.reset_for(&key); // 本轮回写凭证
            }
            std::thread::spawn(move || {
                let mut p = prev.lock().ok().and_then(|mut g| g.take());
                let res = remote::collect_result(&t, &mut p);
                if let Ok(mut g) = prev.lock() {
                    *g = p;
                }
                if let Ok(mut s) = shared.lock() {
                    match res {
                        Ok(sample) => {
                            s.accept(&kick_key, ticket, sample);
                        }
                        Err(e) => {
                            s.record_failure(&kick_key, e);
                        }
                    }
                }
                busy.store(false, Ordering::Relaxed);
            });
        }
        if let Some(f) = self.shared.lock().ok().and_then(|g| g.current_fresh(&key, self.interval.as_secs_f32() * 3.0)) {
            self.usage = f.sample.usage;
            self.pi = f.sample.pi;
            self.last = Instant::now();
            self.push_hist();
            if let Some(err) = &f.last_error {
                self.err(format!("采集失败（显示 {} 前数据）：{}", f.age_secs as u32, err));
            } else if f.stale {
                self.err(format!("数据已过期（{} 秒前采样）", f.age_secs as u32));
            }
        }
    }

    fn cycle_host(&mut self) {
        self.host_idx = match self.host_idx {
            None if self.hosts.is_empty() => None,
            None => Some(0),
            Some(i) if i + 1 < self.hosts.len() => Some(i + 1),
            Some(_) => None,
        };
        if let Ok(mut s) = self.shared.lock() {
            s.sample = None; // 主机切换：清空槽，旧线程回写因 host 不匹配被丢弃
        }
        if let Ok(mut p) = self.prev.lock() {
            *p = None;
        }
        self.usage = Usage::default();
        self.pi = PiStats::default();
        self.last_kick = Instant::now() - Duration::from_secs(10);
        self.table.select(Some(0));
        let label = self.host_label();
        self.ok(format!("视角：{label}"));
    }

    fn procs(&self) -> Vec<&monitor_linux::procstats::ProcUsage> {
        let mut v: Vec<&monitor_linux::procstats::ProcUsage> = self.usage.procs.iter().collect();
        match self.sort {
            SortBy::Cpu => v.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal)),
            SortBy::Mem => v.sort_by(|a, b| b.mem_percent.partial_cmp(&a.mem_percent).unwrap_or(std::cmp::Ordering::Equal)),
            SortBy::Pid => v.sort_by_key(|p| p.pid),
        }
        v
    }

    fn selected_pid(&self) -> Option<(i32, String)> {
        let rows = self.procs();
        self.table
            .selected()
            .and_then(|i| rows.get(i))
            .map(|p| (p.pid, p.comm.clone()))
    }

    fn ok(&mut self, msg: String) {
        self.status_err = false;
        self.status = msg;
    }

    fn err(&mut self, msg: String) {
        self.status_err = true;
        self.status = msg;
    }

    fn run_action(&mut self, pid: i32, sig: i32, tree: bool) -> (Result<(), String>, usize) {
        if let Some(h) = self.host() {
            if tree {
                let pairs: Vec<(i32, i32)> = self.usage.procs.iter().map(|p| (p.pid, p.ppid)).collect();
                let mut pids = monitor_linux::procstats::descendants(pid, &pairs);
                pids.push(pid);
                return match remote::signal_many(&h, &pids, sig) {
                    Ok(n) => (Ok(()), n),
                    Err(e) => (Err(e), 0),
                };
            }
            return match remote::signal(&h, pid, sig) {
                Ok(()) => (Ok(()), 1),
                Err(e) => (Err(e), 0),
            };
        }
        if tree {
            let n = 1 + monitor_linux::procstats::descendants(pid, &self.pid_pairs()).len();
            let r = if sig == 9 {
                monitor_linux::actions::kill_tree(pid).map(|_| ())
            } else {
                monitor_linux::actions::terminate_tree(pid).map(|_| ())
            };
            (r.map_err(|e| e.to_string()), n)
        } else {
            let r = match sig {
                9 => monitor_linux::actions::kill_force(pid),
                18 => monitor_linux::actions::stop(pid),
                19 => monitor_linux::actions::resume(pid),
                _ => monitor_linux::actions::terminate(pid),
            };
            (r.map_err(|e| e.to_string()), 1)
        }
    }

    fn pid_pairs(&self) -> Vec<(i32, i32)> {
        self.usage.procs.iter().map(|p| (p.pid, p.ppid)).collect()
    }

    fn handle_key(&mut self, code: KeyCode) {
        if self.help {
            if matches!(code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?')) {
                self.help = false;
            }
            return;
        }
        if let Some(p) = self.pending.take() {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let (r, n) = self.run_action(p.pid, p.sig, p.tree);
                    let verb = match p.sig {
                        9 => "强制结束",
                        15 => "结束",
                        18 => "暂停",
                        _ => "恢复",
                    };
                    let suffix = if n > 1 { format!("（{n} 个进程）") } else { String::new() };
                    let where_ = if self.host().is_some() { "（远端）" } else { "" };
                    match r {
                        Ok(()) => self.ok(format!("已{verb} {}（{}）{suffix}{where_}", p.pid, p.comm)),
                        Err(e) => self.err(e),
                    }
                }
                _ => self.ok("已取消".to_string()),
            }
            return;
        }
        let rows = self.procs().len();
        let cur = self.table.selected().unwrap_or(0);
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('H') => self.cycle_host(),
            KeyCode::Tab => {
                self.sort = self.sort.next();
                self.table.select(Some(0));
                self.ok(format!("排序：{}", self.sort.label()));
            }
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                let s = if self.paused { "已暂停刷新" } else { "继续刷新" };
                self.ok(s.to_string());
            }
            KeyCode::Char('r') => {
                self.last = Instant::now() - Duration::from_secs(10);
                self.last_kick = Instant::now() - Duration::from_secs(10);
                self.ok("已刷新".to_string());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if rows > 0 {
                    self.table.select(Some((cur + 1).min(rows - 1)));
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.table.select(Some(cur.saturating_sub(1)));
            }
            KeyCode::PageDown => {
                if rows > 0 {
                    self.table.select(Some((cur + 10).min(rows - 1)));
                }
            }
            KeyCode::PageUp => self.table.select(Some(cur.saturating_sub(10))),
            KeyCode::Home => self.table.select(Some(0)),
            KeyCode::End => {
                if rows > 0 {
                    self.table.select(Some(rows - 1));
                }
            }
            KeyCode::Char('t') | KeyCode::Char('T') | KeyCode::Char('x') => {
                if let Some((pid, comm)) = self.selected_pid() {
                    if pid <= 1 {
                        self.err("不能操作 PID 1".to_string());
                        return;
                    }
                    let (sig, tree) = match code {
                        KeyCode::Char('T') => (9, false),
                        KeyCode::Char('x') => (15, true),
                        _ => (15, false),
                    };
                    self.pending = Some(Pending { pid, comm, sig, tree });
                }
            }
            KeyCode::Char('p') => {
                if let Some((pid, comm)) = self.selected_pid() {
                    if pid <= 1 {
                        self.err("不能操作 PID 1".to_string());
                        return;
                    }
                    let stopped = self.usage.procs.iter().any(|p| p.pid == pid && p.state == 'T');
                    let sig = if stopped { 19 } else { 18 };
                    let (r, _) = self.run_action(pid, sig, false);
                    let verb = if stopped { "恢复" } else { "暂停" };
                    match r {
                        Ok(()) => self.ok(format!("已{verb}进程 {pid}（{comm}）")),
                        Err(e) => self.err(e),
                    }
                }
            }
            _ => {}
        }
    }
}

fn config_interval() -> Duration {
    let secs = monitor_core::config::load().interval;
    Duration::from_secs_f32(secs.clamp(0.5, 10.0))
}

pub fn run() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let res = event_loop(&mut terminal);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

fn event_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    let mut app = App::new();
    while !app.quit {
        if !app.paused && app.last.elapsed() >= app.interval {
            app.resample();
        }
        // 远端首次拉取较慢，稍等后再绘制可避免空屏
        terminal.draw(|f| draw(f, &mut app))?;
        if event::poll(Duration::from_millis(120))?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
        {
            app.handle_key(k.code);
        }
    }
    Ok(())
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let rows_cores = cores_height(app.usage.core_percent.len(), area.width);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(rows_cores),
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);

    header(f, chunks[0], app);
    kpi(f, chunks[1], app);
    cores(f, chunks[2], app);
    mem(f, chunks[3], app);
    proc_table(f, chunks[4], app);
    footer(f, chunks[5], app);
    if app.help {
        help(f, area);
    }
}

fn header(f: &mut Frame, area: Rect, app: &App) {
    let os = app
        .pi
        .remote
        .as_ref()
        .map(|r| r.os.clone())
        .unwrap_or_else(|| monitor_linux::platform::platform().os);
    let up = app.usage.uptime_secs.map(format_uptime).unwrap_or_else(|| "—".into());
    let load = app
        .usage
        .load
        .map(|l| format!("{:.2} {:.2} {:.2}", l.one, l.five, l.fifteen))
        .unwrap_or_else(|| "—".into());
    let title = Line::from(vec![
        Span::styled(" 系统监视器 ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled("主机 ", Style::default().fg(Color::DarkGray)),
        Span::styled(app.host_label(), Style::default().fg(if app.host().is_some() { Color::Yellow } else { Color::Green }).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled("系统 ", Style::default().fg(Color::DarkGray)),
        Span::styled(os, Style::default().fg(Color::White)),
        Span::raw("  "),
        Span::styled(format!("运行 {up}"), Style::default().fg(Color::Gray)),
        Span::raw("  "),
        Span::styled(format!("负载 {load}"), Style::default().fg(Color::Gray)),
        Span::raw("  "),
        Span::styled(format!("{} 进程", app.usage.procs.len()), Style::default().fg(Color::Gray)),
        Span::raw("  "),
        Span::styled(if app.paused { "已暂停" } else { "实时" }, Style::default().fg(if app.paused { Color::Yellow } else { Color::Green })),
    ]);
    let hints = Line::from(Span::styled(
        " H 切换主机  Tab 排序  t 结束  T 强制  x 结束树  p 暂停/恢复  ↑↓ 选择  ? 帮助  q 退出",
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(vec![title, hints]), area);
}

fn kpi(f: &mut Frame, area: Rect, app: &App) {
    let mem = app.usage.mem;
    let temp = app.pi.temp_c;
    let power = app.pi.power.map(|p| p.core_w);
    let gpu = if let Some(g) = app.pi.gpu.v3d_ghz {
        format!("{g:.2} GHz")
    } else if let Some(g) = app.pi.gpu.temp_c {
        format!("{g:.1}°C")
    } else {
        "—".to_string()
    };
    let gauge = |v: f32| {
        let filled = ((v / 100.0) * 18.0).round() as usize;
        let filled = filled.min(18);
        format!("{}{}", "█".repeat(filled), "░".repeat(18 - filled))
    };
    let line = Line::from(vec![
        Span::styled(format!(" CPU {:>5.1}% ", app.usage.total_percent), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{} ", gauge(app.usage.total_percent)), Style::default().fg(Color::Cyan)),
        Span::raw("│ "),
        Span::styled(
            format!(
                "内存 {:>5.1}% ",
                mem.map(|m| if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 }).unwrap_or(0.0)
            ),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
        Span::raw("│ "),
        Span::styled(format!("温度 {:>5.1}°C ", temp.unwrap_or(0.0)), Style::default().fg(temp_color(temp.unwrap_or(0.0)))),
        Span::raw("│ "),
        Span::styled(format!("功耗 {:>5.2} W ", power.unwrap_or(0.0)), Style::default().fg(Color::Magenta)),
        Span::raw("│ "),
        Span::styled(format!("GPU {gpu} "), Style::default().fg(Color::Blue)),
        Span::raw("│ "),
        Span::styled(
            format!("磁盘 R/W {:.0}/{:.0} KB/s  网络 ↓/↑ {:.0}/{:.0} KB/s", app.usage.disk_read_bps / 1024.0, app.usage.disk_write_bps / 1024.0, app.usage.net_rx_bps / 1024.0, app.usage.net_tx_bps / 1024.0),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn cores_height(n: usize, width: u16) -> u16 {
    let per_row = if width >= 110 { 4 } else if width >= 60 { 2 } else { 1 };
    let rows = n.div_ceil(per_row).max(1);
    (rows as u16).min(8)
}

fn cores(f: &mut Frame, area: Rect, app: &App) {
    let cores = &app.usage.core_percent;
    if cores.is_empty() {
        f.render_widget(Paragraph::new(Span::styled(" 无核心数据", Style::default().fg(Color::DarkGray))), area);
        return;
    }
    let per_row = (area.width as usize / 26).clamp(1, 4);
    let mut lines: Vec<Line> = Vec::new();
    for (row, chunk) in cores.chunks(per_row).enumerate() {
        let mut spans: Vec<Span> = vec![Span::raw(" ")];
        for (i, v) in chunk.iter().enumerate() {
            let idx = row * per_row + i;
            let color = heat(v / 100.0);
            spans.push(Span::styled(format!("核{idx:<2} "), Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(bar(*v / 100.0, 10), Style::default().fg(color)));
            spans.push(Span::styled(format!(" {v:>3.0}%  "), Style::default().fg(color)));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn mem(f: &mut Frame, area: Rect, app: &App) {
    let Some(m) = app.usage.mem else {
        f.render_widget(Paragraph::new(Span::styled(" 无内存数据", Style::default().fg(Color::DarkGray))), area);
        return;
    };
    let used_pct = if m.total_kb == 0 { 0.0 } else { m.used_kb() as f32 / m.total_kb as f32 * 100.0 };
    let swap_pct = if m.swap_total_kb == 0 { 0.0 } else { m.swap_used_kb() as f32 / m.swap_total_kb as f32 * 100.0 };
    let lines = vec![
        Line::from(vec![
            Span::styled(" 内存 ", Style::default().fg(Color::DarkGray)),
            Span::styled(bar(used_pct / 100.0, 20), Style::default().fg(heat(used_pct / 100.0))),
            Span::styled(
                format!(
                    " {used_pct:>3.0}%  {:.1} / {:.1} GB  缓存 {:.1} GB",
                    m.used_kb() as f64 / 1048576.0,
                    m.total_kb as f64 / 1048576.0,
                    m.cached_kb as f64 / 1048576.0,
                ),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Swap ", Style::default().fg(Color::DarkGray)),
            Span::styled(bar(swap_pct / 100.0, 20), Style::default().fg(Color::Yellow)),
            Span::styled(
                format!(
                    " {swap_pct:>3.0}%  {:.1} / {:.1} GB",
                    m.swap_used_kb() as f64 / 1048576.0,
                    m.swap_total_kb as f64 / 1048576.0
                ),
                Style::default().fg(Color::Gray),
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

fn bar(frac: f32, width: usize) -> String {
    let filled = ((frac.clamp(0.0, 1.0) * width as f32).round() as usize).min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn proc_table(f: &mut Frame, area: Rect, app: &mut App) {
    let procs: Vec<monitor_linux::procstats::ProcUsage> = app.procs().into_iter().cloned().collect();
    if !procs.is_empty() {
        match app.table.selected() {
            None => app.table.select(Some(0)),
            Some(sel) if sel >= procs.len() => app.table.select(Some(procs.len() - 1)),
            _ => {}
        }
    }
    let header = Row::new(vec!["PID", "CPU%", "内存%", "RSS MB", "PPID", "用户", "状态", "名称"])
        .style(Style::default().fg(Color::Black).bg(Color::Gray).add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = procs
        .iter()
        .map(|p| {
            let state_color = match p.state {
                'R' => Color::Green,
                'T' => Color::Yellow,
                'Z' => Color::Red,
                _ => Color::Gray,
            };
            Row::new(vec![
                Cell::from(p.pid.to_string()),
                Cell::from(format!("{:.1}", p.cpu_percent)).style(Style::default().fg(heat(p.cpu_percent / 100.0))),
                Cell::from(format!("{:.1}", p.mem_percent)),
                Cell::from(format!("{:.1}", p.rss_kb as f64 / 1024.0)),
                Cell::from(p.ppid.to_string()),
                Cell::from(p.user.clone()),
                Cell::from(p.state.to_string()).style(Style::default().fg(state_color)),
                Cell::from(p.comm.clone()),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Length(12),
        Constraint::Length(4),
        Constraint::Min(16),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::TOP).title(Span::styled(
            format!(" 进程（按 {} 降序）", app.sort.label()),
            Style::default().fg(Color::DarkGray),
        )))
        .row_highlight_style(Style::default().bg(Color::Rgb(0, 70, 90)).add_modifier(Modifier::BOLD))
        .highlight_symbol("› ");
    f.render_stateful_widget(table, area, &mut app.table);
}

fn footer(f: &mut Frame, area: Rect, app: &App) {
    let line = if let Some(p) = &app.pending {
        let action = match p.sig {
            9 => "强制结束",
            15 if p.tree => "结束进程树",
            15 => "结束进程",
            _ => "操作",
        };
        Line::from(vec![
            Span::styled(format!(" 确认{action} {}（{}）？", p.pid, p.comm), Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled("y 确认  n/其它 取消", Style::default().fg(Color::Yellow)),
        ])
    } else {
        let color = if app.status_err { Color::Red } else { Color::Green };
        let sel = app.selected_pid().map(|(pid, comm)| format!("已选 {pid} {comm}")).unwrap_or_else(|| "未选中".to_string());
        Line::from(vec![
            Span::styled(" ● ", Style::default().fg(color)),
            Span::styled(app.status.clone(), Style::default().fg(color)),
            Span::raw("   "),
            Span::styled(sel, Style::default().fg(Color::Gray)),
            Span::raw("   "),
            Span::styled(
                match app.host() {
                    Some(_) => "远端操作经 SSH 执行；危险操作需确认",
                    None => "本机操作",
                },
                Style::default().fg(Color::DarkGray),
            ),
        ])
    };
    f.render_widget(Paragraph::new(line), area);
}

fn help(f: &mut Frame, area: Rect) {
    let w = area.width.min(64);
    let h = 10.min(area.height);
    let rect = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let text = vec![
        Line::from(Span::styled(" 键盘操作", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(" H          切换主机（本地 ↔ hosts.conf 中的 SSH 主机）"),
        Line::from(" Tab        排序：CPU / 内存 / PID"),
        Line::from(" ↑ ↓ j k     选择进程    PgUp/PgDn 翻页"),
        Line::from(" t / T      结束 / 强制结束（需 y 确认）"),
        Line::from(" x          结束进程树（需 y 确认）"),
        Line::from(" p          暂停 / 恢复进程"),
        Line::from(" r 空格      立即刷新 / 暂停刷新"),
        Line::from(" ? / Esc    关闭帮助    q 退出"),
    ];
    f.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" 帮助 ")),
        rect,
    );
}

fn temp_color(t: f32) -> Color {
    if t >= 80.0 {
        Color::Red
    } else if t >= 65.0 {
        Color::Yellow
    } else {
        Color::Green
    }
}

fn heat(frac: f32) -> Color {
    let f = frac.clamp(0.0, 1.0);
    if f >= 0.85 {
        Color::Red
    } else if f >= 0.6 {
        Color::Yellow
    } else if f >= 0.3 {
        Color::Cyan
    } else {
        Color::Green
    }
}