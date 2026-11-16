//! 特权探针 helper：通过 tracefs 挂载 kprobe/uprobe/syscall tracepoint，
//! 向系统监视器提供入参、回参、命中计数与最近调用。只由 systemd 以 root 启动。
//!
//! 协议（每条命令一行，选项用制表符分隔；值内可含空格）：
//!   attach kprobe <符号> [\tstack=1][\tpid=N][\targs=<fetchargs>]
//!   attach syscall <名字> [\tstack=1][\tpid=N]
//!   attach uprobe <绝对路径> <符号> [\tstack=1][\tpid=N][\targs=<fetchargs>]
//!   detach | poll | ping
//! 回复：OK\t<说明> | ERR\t<说明> | STAT\t<调用数> + CALL... + END

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[allow(dead_code)]
#[path = "../../../../crates/monitor-linux/src/probe.rs"]
mod probe;

const SOCKET_DEFAULT: &str = "/run/system-monitor-probe/probe.sock";
const MAX_RECENT: usize = 200;
const REPLY_RECENT: usize = 5;
const MAX_PENDING: usize = 32;
const MAX_SESSION: Duration = Duration::from_secs(15 * 60);
const IDLE_LIMIT: Duration = Duration::from_secs(60);

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

fn main() {
    if let Err(e) = run() {
        eprintln!("probe-helper: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("需要 root 运行（请通过 systemd 服务启动）".to_string());
    }
    let trace = Trace::detect()?;
    let socket_path = std::env::var("SM_PROBE_SOCKET").unwrap_or_else(|_| SOCKET_DEFAULT.to_string());
    let allowed_uid = std::env::var("SM_PROBE_UID").ok().and_then(|v| v.parse::<u32>().ok());
    if let Some(parent) = Path::new(&socket_path).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建 socket 目录失败：{e}"))?;
    }
    if Path::new(&socket_path).exists() {
        if UnixStream::connect(&socket_path).is_ok() {
            return Err("已有 helper 在运行".to_string());
        }
        let _ = fs::remove_file(&socket_path);
    }
    let listener = UnixListener::bind(&socket_path).map_err(|e| format!("绑定 {socket_path} 失败：{e}"))?;
    fs::set_permissions(&socket_path, Permissions::from_mode(0o660)).map_err(|e| format!("设置 socket 权限失败：{e}"))?;
    listener.set_nonblocking(true).map_err(|e| format!("设置非阻塞失败：{e}"))?;
    unsafe {
        libc::signal(libc::SIGTERM, on_term as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_term as *const () as libc::sighandler_t);
    }
    cleanup_stale(&trace);
    eprintln!("probe-helper: ready at {socket_path}");

    let state = Arc::new(Mutex::new(State::default()));
    let mut last_client = Instant::now();
    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                last_client = Instant::now();
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                if !peer_allowed(&stream, allowed_uid) {
                    let _ = (&stream).write_all(b"ERR\tforbidden\n");
                    continue;
                }
                handle_client(stream, &state, &trace);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => {
                eprintln!("probe-helper: accept: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        if let Ok(mut st) = state.lock() {
            let stale = st.active.as_ref().is_some_and(|a| {
                last_client.elapsed() > IDLE_LIMIT || a.started.elapsed() > MAX_SESSION
            });
            if stale {
                st.detach();
            }
        }
    }
    if let Ok(mut st) = state.lock() {
        st.detach();
    }
    let _ = fs::remove_file(&socket_path);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Kprobe,
    Uprobe,
    Syscall,
}

impl Kind {
    fn group(self) -> &'static str {
        match self {
            Kind::Kprobe => "kprobes",
            Kind::Uprobe => "uprobes",
            Kind::Syscall => "syscalls",
        }
    }
}

struct Trace {
    base: PathBuf,
}

impl Trace {
    fn detect() -> Result<Self, String> {
        for base in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
            if Path::new(base).join("kprobe_events").exists() {
                return Ok(Self { base: PathBuf::from(base) });
            }
        }
        Err("未找到 tracefs（/sys/kernel/tracing 或 /sys/kernel/debug/tracing）".to_string())
    }

    fn events_file(&self, kind: Kind) -> PathBuf {
        self.base.join(match kind {
            Kind::Kprobe => "kprobe_events",
            Kind::Uprobe => "uprobe_events",
            Kind::Syscall => "syscalls/events",
        })
    }

    fn event_dir(&self, kind: Kind, name: &str) -> PathBuf {
        self.base.join("events").join(kind.group()).join(name)
    }
}

#[derive(Clone)]
struct AttachOpts {
    kind: Kind,
    target: String,
    symbol: String,
    stack: bool,
    pid: Option<u32>,
    args: String,
}

struct EventPaths {
    enable: PathBuf,
    filter: PathBuf,
    trigger: PathBuf,
    delete: Option<(PathBuf, String)>,
}

struct Capture {
    total: u64,
    recent: VecDeque<Call>,
    pending: HashMap<String, VecDeque<u64>>,
    next_id: u64,
}

impl Default for Capture {
    fn default() -> Self {
        Self {
            total: 0,
            recent: VecDeque::with_capacity(MAX_RECENT),
            pending: HashMap::new(),
            next_id: 0,
        }
    }
}

#[derive(Clone)]
struct Call {
    id: u64,
    comm: String,
    pid: String,
    entry: String,
    ret: String,
    stack: Vec<String>,
}

struct Active {
    label: String,
    events: Vec<EventPaths>,
    capture: Arc<Mutex<Capture>>,
    stop: Arc<AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
    started: Instant,
    stack: bool,
    filtered: bool,
}

#[derive(Default)]
struct State {
    active: Option<Active>,
    seq: u64,
}

impl State {
    fn detach(&mut self) {
        let Some(mut active) = self.active.take() else {
            return;
        };
        active.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = active.reader.take() {
            let _ = handle.join();
        }
        cleanup_events(&active.events, active.stack, active.filtered);
        eprintln!("probe-helper: detached {}", active.label);
    }

    fn attach(&mut self, trace: &Trace, opts: AttachOpts) -> Result<String, String> {
        self.detach();
        match opts.kind {
            Kind::Syscall => self.attach_syscall(trace, opts),
            _ => self.attach_dynamic(trace, opts),
        }
    }

    fn attach_dynamic(&mut self, trace: &Trace, opts: AttachOpts) -> Result<String, String> {
        if opts.kind == Kind::Uprobe && !trace.events_file(Kind::Uprobe).exists() {
            return Err("此内核未启用 uprobes（缺少 uprobe_events）".to_string());
        }
        self.seq += 1;
        let name = format!("sm{}_{}", std::process::id(), self.seq);
        let ret_name = format!("{name}ret");
        let arg = if opts.kind == Kind::Uprobe {
            format!("0x{:x}", probe::elf_symbol_offset(Path::new(&opts.target), &opts.symbol)?)
        } else {
            opts.symbol.clone()
        };
        let target = if opts.kind == Kind::Uprobe {
            format!("{}:{arg}", opts.target)
        } else {
            arg
        };
        let fetch = if opts.args.trim().is_empty() {
            default_args()
        } else {
            opts.args.trim().to_string()
        };
        let entry_line = format!("p:{name} {target} {fetch}\n");
        let ret_line = format!("r:{ret_name} {target} $retval\n");
        let events_file = trace.events_file(opts.kind);
        write_str(&events_file, &entry_line).map_err(|e| format!("写 tracefs 失败：{e}"))?;
        if let Err(e) = write_str(&events_file, &ret_line) {
            let _ = write_str(&events_file, &format!("-:{}/{name}\n", opts.kind.group()));
            return Err(format!("创建返回探针失败：{e}"));
        }
        let entry_dir = trace.event_dir(opts.kind, &name);
        let exit_dir = trace.event_dir(opts.kind, &ret_name);
        let events = vec![
            EventPaths {
                enable: entry_dir.join("enable"),
                filter: entry_dir.join("filter"),
                trigger: entry_dir.join("trigger"),
                delete: Some((events_file.clone(), format!("-:{}/{name}\n", opts.kind.group()))),
            },
            EventPaths {
                enable: exit_dir.join("enable"),
                filter: exit_dir.join("filter"),
                trigger: exit_dir.join("trigger"),
                delete: Some((events_file.clone(), format!("-:{}/{ret_name}\n", opts.kind.group()))),
            },
        ];
        if let Err(e) = setup_events(&events, opts.stack, opts.pid) {
            cleanup_events(&events, opts.stack, opts.pid.is_some());
            return Err(e);
        }
        let pipe = match open_pipe(&trace.base.join("trace_pipe")) {
            Ok(p) => p,
            Err(e) => {
                cleanup_events(&events, opts.stack, opts.pid.is_some());
                return Err(format!("打开 trace_pipe 失败：{e}"));
            }
        };
        let capture = Arc::new(Mutex::new(Capture::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let reader = spawn_reader(pipe, format!(" {name}:"), format!(" {ret_name}:"), stop.clone(), capture.clone());
        self.active = Some(Active {
            label: format!("{}:{}", if opts.kind == Kind::Uprobe { "uprobe" } else { "kprobe" }, opts.symbol),
            events,
            capture,
            stop,
            reader: Some(reader),
            started: Instant::now(),
            stack: opts.stack,
            filtered: opts.pid.is_some(),
        });
        eprintln!("probe-helper: attached {name} -> {entry_line}");
        Ok(name)
    }

    fn attach_syscall(&mut self, trace: &Trace, opts: AttachOpts) -> Result<String, String> {
        let base = trace.base.join("events").join("syscalls");
        let entry_name = format!("sys_enter_{}", opts.symbol);
        let exit_name = format!("sys_exit_{}", opts.symbol);
        let entry_dir = base.join(&entry_name);
        let exit_dir = base.join(&exit_name);
        if !entry_dir.exists() || !exit_dir.exists() {
            return Err(format!("此内核没有 syscall tracepoint {}", opts.symbol));
        }
        let events = vec![
            EventPaths {
                enable: entry_dir.join("enable"),
                filter: entry_dir.join("filter"),
                trigger: entry_dir.join("trigger"),
                delete: None,
            },
            EventPaths {
                enable: exit_dir.join("enable"),
                filter: exit_dir.join("filter"),
                trigger: exit_dir.join("trigger"),
                delete: None,
            },
        ];
        if let Err(e) = setup_events(&events, opts.stack, opts.pid) {
            cleanup_events(&events, opts.stack, opts.pid.is_some());
            return Err(e);
        }
        let pipe = match open_pipe(&trace.base.join("trace_pipe")) {
            Ok(p) => p,
            Err(e) => {
                cleanup_events(&events, opts.stack, opts.pid.is_some());
                return Err(format!("打开 trace_pipe 失败：{e}"));
            }
        };
        let capture = Arc::new(Mutex::new(Capture::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let reader = spawn_reader(
            pipe,
            format!(" sys_{}(", opts.symbol),
            format!(" sys_{} ->", opts.symbol),
            stop.clone(),
            capture.clone(),
        );
        self.active = Some(Active {
            label: format!("syscall:{}", opts.symbol),
            events,
            capture,
            stop,
            reader: Some(reader),
            started: Instant::now(),
            stack: opts.stack,
            filtered: opts.pid.is_some(),
        });
        eprintln!("probe-helper: attached syscall {} tracepoints", opts.symbol);
        Ok(opts.symbol)
    }
}

fn default_args() -> String {
    (0..8).map(|i| format!("arg{i}=%x{i}")).collect::<Vec<_>>().join(" ")
}

fn setup_events(events: &[EventPaths], stack: bool, pid: Option<u32>) -> Result<(), String> {
    if stack {
        write_str(&events[0].trigger, "stacktrace\n").map_err(|e| format!("启用抓栈失败：{e}"))?;
    }
    if let Some(pid) = pid {
        for ev in events {
            write_str(&ev.filter, &format!("common_pid == {pid}")).map_err(|e| format!("设置 PID 过滤失败：{e}"))?;
        }
    }
    for ev in events {
        write_str(&ev.enable, "1").map_err(|e| format!("启用事件失败：{e}"))?;
    }
    Ok(())
}

fn cleanup_events(events: &[EventPaths], stack: bool, filtered: bool) {
    for (i, ev) in events.iter().enumerate() {
        let _ = write_str(&ev.enable, "0");
        if filtered {
            let _ = write_str(&ev.filter, "");
        }
        if stack && i == 0 {
            let _ = write_str(&ev.trigger, "!stacktrace\n");
        }
        if let Some((file, del)) = &ev.delete {
            let _ = write_str(file, del);
        }
    }
}

fn valid_symbol(s: &str) -> bool {
    !s.is_empty() && s.len() <= 512 && !s.chars().any(|c| c.is_whitespace() || c == ':' || c.is_control())
}

fn valid_syscall(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('_')
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn valid_target(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 4096
        && !path.chars().any(|c| c.is_whitespace() || c == ':' || c.is_control())
        && Path::new(path).is_file()
}

fn valid_fetchargs(s: &str) -> bool {
    s.len() <= 512 && !s.chars().any(|c| c.is_control())
}

fn write_str(path: &Path, data: &str) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;
    f.write_all(data.as_bytes())
}

fn open_pipe(path: &Path) -> std::io::Result<File> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 { Some(cred.uid) } else { None }
}

fn peer_allowed(stream: &UnixStream, allowed: Option<u32>) -> bool {
    let Some(uid) = peer_uid(stream) else {
        return false;
    };
    match allowed {
        Some(allowed) => uid == allowed,
        None => uid == 0,
    }
}

fn spawn_reader(
    pipe: File,
    entry_marker: String,
    exit_marker: String,
    stop: Arc<AtomicBool>,
    capture: Arc<Mutex<Capture>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut pipe = pipe;
        let mut buf = [0u8; 8192];
        let mut partial: Vec<u8> = Vec::new();
        while !stop.load(Ordering::Relaxed) {
            match pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    partial.extend_from_slice(&buf[..n]);
                    while let Some(pos) = partial.iter().position(|&b| b == b'\n') {
                        let raw: Vec<u8> = partial.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&raw[..raw.len().saturating_sub(1)]).to_string();
                        ingest(&line, &entry_marker, &exit_marker, &capture);
                    }
                    if partial.len() > 1_000_000 {
                        partial.clear();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(20)),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    })
}

fn ingest(line: &str, entry_marker: &str, exit_marker: &str, capture: &Mutex<Capture>) {
    let t = line.trim_end();
    if t.is_empty() {
        return;
    }
    let Ok(mut c) = capture.lock() else {
        return;
    };
    let trimmed = t.trim_start();
    if let Some(frame) = trimmed.strip_prefix("=>") {
        if let Some(call) = c.recent.back_mut() {
            let frame = frame.trim();
            if !frame.is_empty() {
                call.stack.push(frame.to_string());
            }
        }
        return;
    }
    let enter = t.contains(entry_marker);
    let exit = t.contains(exit_marker);
    if !enter && !exit {
        return;
    }
    let (comm, pid) = split_head(t);
    if enter {
        c.total += 1;
        c.next_id += 1;
        let id = c.next_id;
        let call = Call { id, comm, pid: pid.clone(), entry: t.to_string(), ret: String::new(), stack: Vec::new() };
        if c.recent.len() >= MAX_RECENT {
            c.recent.pop_front();
        }
        c.recent.push_back(call);
        let queue = c.pending.entry(pid).or_default();
        queue.push_back(id);
        if queue.len() > MAX_PENDING {
            queue.pop_front();
        }
    } else {
        let id = c.pending.get_mut(&pid).and_then(|q| q.pop_back());
        if let Some(id) = id
            && let Some(call) = c.recent.iter_mut().rev().find(|c| c.id == id)
        {
            call.ret = t.to_string();
        }
    }
}

fn split_head(line: &str) -> (String, String) {
    let head = line.split_whitespace().next().unwrap_or("");
    match head.rsplit_once('-') {
        Some((comm, pid)) if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) => (comm.to_string(), pid.to_string()),
        _ => (head.to_string(), String::new()),
    }
}

fn esc(s: &str) -> String {
    s.replace(['\t', '\r'], " ").replace('\n', "\\n")
}

fn capture_reply(c: &Capture) -> String {
    let mut out = format!("STAT\t{}\n", c.total);
    for call in c.recent.iter().rev().take(REPLY_RECENT).rev() {
        out.push_str(&format!(
            "CALL\t{}\t{}\t{}\t{}\t{}\n",
            esc(&call.comm),
            esc(&call.pid),
            esc(&call.entry),
            esc(&call.ret),
            esc(&call.stack.join(" ← "))
        ));
    }
    out.push_str("END\n");
    out
}

fn stats_reply(state: &Mutex<State>) -> String {
    let Ok(st) = state.lock() else {
        return "ERR\tstate\n".to_string();
    };
    match &st.active {
        Some(active) => match active.capture.lock() {
            Ok(c) => capture_reply(&c),
            Err(_) => "ERR\tcapture\n".to_string(),
        },
        None => "ERR\t探针已自动停止（空闲或超时）\n".to_string(),
    }
}

fn handle_command(cmd: &str, state: &Arc<Mutex<State>>, trace: &Trace) -> String {
    let mut parts = cmd.split_whitespace();
    match parts.next() {
        Some("ping") => "OK\tready\n".to_string(),
        Some("poll") => stats_reply(state),
        Some("dump") => match fs::read_to_string(trace.base.join("trace")) {
            Ok(mut text) => {
                if text.len() > 64 * 1024 {
                    text.truncate(64 * 1024);
                }
                format!("DUMP\n{text}END\n")
            }
            Err(e) => format!("ERR\tdump: {e}\n"),
        },
        Some("detach") => {
            if let Ok(mut st) = state.lock() {
                st.detach();
            }
            "OK\tstopped\n".to_string()
        }
        Some("attach") => match parse_attach(cmd).and_then(|opts| {
            let mut st = state.lock().map_err(|_| "状态锁失败".to_string())?;
            st.attach(trace, opts)
        }) {
            Ok(msg) => format!("OK\t{msg}\n"),
            Err(e) => format!("ERR\t{}\n", esc(&e)),
        },
        _ => "ERR\tunknown command\n".to_string(),
    }
}

fn parse_attach(line: &str) -> Result<AttachOpts, String> {
    let mut fields = line.split('\t');
    let head = fields.next().unwrap_or("");
    let mut toks: Vec<&str> = head.split_whitespace().collect();
    if toks.first() != Some(&"attach") {
        return Err("未知命令".to_string());
    }
    if toks.len() < 3 {
        return Err("用法：attach kprobe <符号> | attach syscall <名字> | attach uprobe <路径> <符号>".to_string());
    }
    let kind = match toks[1] {
        "kprobe" => Kind::Kprobe,
        "uprobe" => Kind::Uprobe,
        "syscall" => Kind::Syscall,
        _ => return Err("未知探针类型".to_string()),
    };
    toks.drain(..2);
    let mut stack = false;
    if toks.last() == Some(&"stack") {
        stack = true;
        toks.pop();
    }
    let (target, symbol) = match kind {
        Kind::Uprobe => {
            if toks.len() != 2 {
                return Err("uprobe 需要 <绝对路径> <符号>".to_string());
            }
            (toks[0].to_string(), toks[1].to_string())
        }
        _ => {
            if toks.len() != 1 {
                return Err("参数数量不正确".to_string());
            }
            (String::new(), toks[0].to_string())
        }
    };
    let mut pid = None;
    let mut args = String::new();
    for field in fields {
        if field.is_empty() {
            continue;
        }
        let Some((key, value)) = field.split_once('=') else {
            return Err(format!("未知选项 {field}"));
        };
        match key {
            "stack" => match value {
                "1" | "true" => stack = true,
                "0" | "false" => stack = false,
                _ => return Err("stack 只接受 0/1".to_string()),
            },
            "pid" => {
                let p: u32 = value.parse().map_err(|_| "PID 必须是正整数".to_string())?;
                if p == 0 {
                    return Err("PID 必须是正整数".to_string());
                }
                pid = Some(p);
            }
            "args" => args = value.to_string(),
            _ => return Err(format!("未知选项 {key}")),
        }
    }
    match kind {
        Kind::Syscall => {
            if !valid_syscall(&symbol) {
                return Err("系统调用名只能包含小写字母、数字和下划线".to_string());
            }
            if !args.trim().is_empty() {
                return Err("系统调用由 tracepoint 自带具名参数，不支持自定义参数表达式".to_string());
            }
        }
        Kind::Kprobe => {
            if !valid_symbol(&symbol) {
                return Err("符号名包含非法字符或过长".to_string());
            }
        }
        Kind::Uprobe => {
            if !valid_symbol(&symbol) {
                return Err("符号名包含非法字符或过长".to_string());
            }
            if !valid_target(&target) {
                return Err("路径必须是存在、绝对且不含空白/冒号的普通文件".to_string());
            }
        }
    }
    if !valid_fetchargs(&args) {
        return Err("参数表达式过长或包含控制字符".to_string());
    }
    Ok(AttachOpts { kind, target, symbol, stack, pid, args })
}

fn handle_client(mut stream: UnixStream, state: &Arc<Mutex<State>>, trace: &Trace) {
    let Ok(read_stream) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let cmd = line.trim();
        if cmd.is_empty() {
            continue;
        }
        let quit = cmd == "quit";
        let reply = if quit {
            if let Ok(mut st) = state.lock() {
                st.detach();
            }
            "OK\tbye\n".to_string()
        } else {
            handle_command(cmd, state, trace)
        };
        if stream.write_all(reply.as_bytes()).is_err() {
            break;
        }
        if quit {
            std::process::exit(0);
        }
    }
}

/// 判定事件是否属于本工具：`sm<pid>_<seq>`（入口）与 `sm<pid>_<seq>ret`（返回）。
/// 命名前缀归属校验保证只清理自己（历史会话）的事件，不误删其它工具的探针。
fn is_our_event(name: &str) -> bool {
    // 返回探针名以 ret 结尾，剥掉后按同一规则校验
    let name = name.strip_suffix("ret").unwrap_or(name);
    let Some(rest) = name.strip_prefix("sm") else {
        return false;
    };
    let Some((pid, seq)) = rest.split_once('_') else {
        return false;
    };
    !pid.is_empty()
        && !seq.is_empty()
        && pid.chars().all(|c| c.is_ascii_digit())
        && seq.chars().all(|c| c.is_ascii_digit())
}

/// 启动时清理本工具的历史残留（崩溃/超时遗留）：入口 `p:` 与返回 `r:`
/// 成对处理。清理幂等；失败仅记录不阻塞服务启动。
fn cleanup_stale(trace: &Trace) {
    for kind in [Kind::Kprobe, Kind::Uprobe] {
        let path = trace.events_file(kind);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            // 同时匹配入口 p: 与返回 r:；其余行（他人的、tracepoint）不动
            let Some(rest) = line.strip_prefix("p:").or_else(|| line.strip_prefix("r:")) else {
                continue;
            };
            let Some(token) = rest.split_whitespace().next() else {
                continue;
            };
            let name = token.rsplit('/').next().unwrap_or(token);
            if is_our_event(name) {
                let _ = write_str(&path, &format!("-:{}/{name}\n", kind.group()));
                eprintln!("probe-helper: cleaned stale {name}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_injection() {
        assert!(valid_symbol("vfs_read"));
        assert!(valid_symbol("_ZN4core3fmt5write17h1234567890abcdefE"));
        assert!(!valid_symbol("bad symbol"));
        assert!(!valid_symbol("x\np:evil"));
        assert!(!valid_symbol("a:b"));
        assert!(!valid_symbol(""));
        assert!(valid_syscall("openat"));
        assert!(!valid_syscall("__arm64_sys_openat"));
        assert!(!valid_syscall("open at"));
        assert!(valid_target("/bin/sh"));
        assert!(!valid_target("relative/path"));
        assert!(!valid_target("/tmp/no such file"));
        assert!(valid_fetchargs("arg0=%x0 arg1=+0(%x1):string"));
        assert!(!valid_fetchargs("bad\nnewline"));
    }

    #[test]
    fn parses_attach_arguments() {
        let o = parse_attach("attach kprobe vfs_read\tstack=1\tpid=42\targs=arg0=%x0 arg1=%x1").unwrap();
        assert_eq!(o.kind, Kind::Kprobe);
        assert_eq!((o.symbol.as_str(), o.stack, o.pid), ("vfs_read", true, Some(42)));
        assert_eq!(o.args, "arg0=%x0 arg1=%x1");
        let o = parse_attach("attach kprobe vfs_read stack").unwrap();
        assert!(o.stack);
        let o = parse_attach("attach syscall openat\tpid=7").unwrap();
        assert_eq!(o.kind, Kind::Syscall);
        assert_eq!(o.symbol, "openat");
        assert_eq!(o.pid, Some(7));
        assert!(parse_attach("attach syscall openat\targs=arg0=%x0").is_err());
        assert!(parse_attach("attach kprobe bad symbol").is_err());
        assert!(parse_attach("attach kprobe a:b").is_err());
        assert!(parse_attach("attach uprobe relative main").is_err());
        assert!(parse_attach("attach kprobe vfs_read\tpid=0").is_err());
        assert!(parse_attach("attach kprobe vfs_read\tbogus=1").is_err());
    }

    #[test]
    fn default_register_args() {
        let a = default_args();
        assert!(a.starts_with("arg0=%x0 "));
        assert!(a.ends_with("arg7=%x7"));
    }

    #[test]
    fn pairs_entry_and_return() {
        let cap = Mutex::new(Capture::default());
        ingest(
            "bash-1234 [002] d... 1.0: sm1_1: (vfs_read+0x0/0x20) arg0=0x1 arg1=0x2",
            " sm1_1:",
            " sm1_1ret:",
            &cap,
        );
        ingest(" => vfs_read", " sm1_1:", " sm1_1ret:", &cap);
        ingest(
            "bash-1234 [002] d... 1.1: sm1_1ret: (vfs_read+0x0/0x20) ret=0x5",
            " sm1_1:",
            " sm1_1ret:",
            &cap,
        );
        let c = cap.lock().unwrap();
        assert_eq!(c.total, 1);
        let call = c.recent.front().expect("call");
        assert!(call.entry.contains("arg0=0x1"));
        assert!(call.ret.contains("ret=0x5"));
        assert_eq!(call.stack, vec!["vfs_read"]);
    }

    #[test]
    fn pairs_syscall_entry_exit() {
        let cap = Mutex::new(Capture::default());
        ingest(
            "ls-99 [001] d... 2.0: sys_openat(dfd: 0xffffff9c, filename: 0x7f00, flags: 0x0)",
            " sys_openat(",
            " sys_openat ->",
            &cap,
        );
        ingest(
            "ls-99 [001] d... 2.1: sys_openat -> 0x3",
            " sys_openat(",
            " sys_openat ->",
            &cap,
        );
        let c = cap.lock().unwrap();
        assert_eq!(c.total, 1);
        let call = c.recent.front().expect("call");
        assert!(call.entry.contains("filename: 0x7f00"));
        assert!(call.ret.contains("0x3"));
    }

    #[test]
    fn reply_escapes_fields() {
        let cap = Mutex::new(Capture::default());
        ingest("weird\tname-42 [000] .... 1.0: sm1_1: (x)", " sm1_1:", " sm1_1ret:", &cap);
        let c = cap.lock().unwrap();
        let out = capture_reply(&c);
        assert!(out.starts_with("STAT\t1\nCALL\t"));
        assert!(out.ends_with("END\n"));
        assert!(!out.contains("weird\tname"));
        assert!(out.contains("weird name"));
    }

    #[test]
    fn event_name_detection() {
        assert!(is_our_event("sm1234_7"));
        assert!(!is_our_event("sm1234_x"));
        assert!(!is_our_event("myprobe"));
        // 返回探针（ret 后缀）必须识别，否则清理漏掉 r: 残留
        assert!(is_our_event("sm1234_7ret"));
        assert!(is_our_event("sm999_12ret"));
        // 他人/伪装事件不认
        assert!(!is_our_event("sm1234_7retx"));
        assert!(!is_our_event("xsm1234_7"));
        assert!(!is_our_event("sm1234ret"));
        assert!(!is_our_event("sm1234_ret"));
    }

    #[test]
    fn cleanup_stale_is_prefix_scoped() {
        // 通过 CgReady 同款 from_output 风格验证:清理只作用于本工具前缀。
        // is_our_event 覆盖已足够;这里额外验证 r:/p: 双前缀的行解析逻辑
        let lines = [
            "p:sm111_1 vfs_read",      // 本工具入口
            "r:sm111_1ret vfs_read",   // 本工具返回
            "p:other_probe vfs_write", // 他人探针
            "p:sm222_2 do_sys_open",   // 另一会话入口
            "r:sm222_2ret do_sys_open", // 另一会话返回
        ];
        let ours: Vec<&str> = lines
            .iter()
            .filter_map(|l| {
                let rest = l.strip_prefix("p:").or_else(|| l.strip_prefix("r:"))?;
                let token = rest.split_whitespace().next()?;
                is_our_event(token).then_some(token)
            })
            .collect();
        assert_eq!(ours, vec!["sm111_1", "sm111_1ret", "sm222_2", "sm222_2ret"]);
    }
}