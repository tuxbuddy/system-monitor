//! 与 root probe-helper 的轻量客户端：每条命令新建一次 Unix socket 连接，
//! 避免在 GUI 线程里维护长连接与后台线程。

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::probe;

pub const SOCKET: &str = "/run/system-monitor-probe/probe.sock";
const TIMEOUT: Duration = Duration::from_millis(1500);

pub struct Attach<'a> {
    pub kind: &'a str,
    pub target: Option<&'a Path>,
    pub symbol: &'a str,
    pub stack: bool,
    pub pid: Option<u32>,
    pub args: &'a str,
}

#[derive(Clone, Debug, Default)]
pub struct Call {
    pub comm: String,
    pub pid: String,
    pub entry: String,
    pub ret: String,
    pub stack: String,
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub total: u64,
    pub calls: Vec<Call>,
}

pub fn attach(opts: &Attach<'_>) -> Result<(), String> {
    attach_via(&mut |cmd| exchange(cmd), opts)
}

/// 传给任意传输层（本地 UnixSocket / 远端 SSH）的挂载命令。
pub fn attach_command(opts: &Attach<'_>) -> String {
    let mut cmd = match (opts.kind, opts.target) {
        ("uprobe", Some(path)) => format!("attach uprobe {} {}", path.display(), opts.symbol),
        ("syscall", _) => format!("attach syscall {}", opts.symbol),
        _ => format!("attach kprobe {}", opts.symbol),
    };
    if opts.stack {
        cmd.push_str("\tstack=1");
    }
    if let Some(pid) = opts.pid {
        cmd.push_str(&format!("\tpid={pid}"));
    }
    let args = opts.args.trim();
    if !args.is_empty() {
        cmd.push_str("\targs=");
        cmd.push_str(args);
    }
    cmd
}

pub fn attach_via<F>(send: &mut F, opts: &Attach<'_>) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    first_ok(&send(&attach_command(opts))?)
}

pub fn detach() -> Result<(), String> {
    detach_via(&mut |cmd| exchange(cmd))
}

pub fn detach_via<F>(send: &mut F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    first_ok(&send("detach")?)
}

pub fn poll() -> Result<Stats, String> {
    poll_via(&mut |cmd| exchange(cmd))
}

pub fn poll_via<F>(send: &mut F) -> Result<Stats, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let reply = send("poll")?;
    if reply.starts_with("ERR") {
        return Err(reply.lines().next().unwrap_or("").trim_start_matches("ERR\t").to_string());
    }
    Ok(parse_reply(&reply))
}

/// 远端 uprobe 符号表：helper 的 `elf <path>` 回复。
pub fn elf_via<F>(send: &mut F, path: &str) -> Result<probe::ElfSymbols, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let reply = send(&format!("elf {path}"))?;
    if reply.starts_with("ERR") {
        return Err(reply.lines().next().unwrap_or("").trim_start_matches("ERR\t").to_string());
    }
    probe::parse_elf_reply(&reply)
}

/// 本地 helper 是否就绪（ping）。
pub fn ping() -> Result<(), String> {
    first_ok(&exchange("ping")?)
}

/// 本地 UnixSocket 传输，供 via 接口复用。
pub fn local_transport(cmd: &str) -> Result<String, String> {
    exchange(cmd)
}

fn first_ok(reply: &str) -> Result<(), String> {
    let line = reply.lines().next().unwrap_or("");
    if line.starts_with("OK") {
        Ok(())
    } else {
        Err(line.strip_prefix("ERR\t").unwrap_or(line).to_string())
    }
}

fn exchange(cmd: &str) -> Result<String, String> {
    let mut stream = UnixStream::connect(SOCKET).map_err(connect_error)?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(|e| format!("设置超时失败：{e}"))?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(|e| format!("设置超时失败：{e}"))?;
    stream
        .write_all(cmd.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| format!("发送命令失败：{e}"))?;
    let mut reader = BufReader::new(stream);
    let mut out = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let done = line.starts_with("OK") || line.starts_with("ERR") || line == "END\n";
                out.push_str(&line);
                if done {
                    break;
                }
            }
            Err(e) => return Err(format!("读取 helper 回复失败：{e}")),
        }
    }
    if out.is_empty() {
        Err("helper 没有返回内容".to_string())
    } else {
        Ok(out)
    }
}

fn connect_error(e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => "helper 未运行".to_string(),
        std::io::ErrorKind::PermissionDenied => "无权连接 helper（socket 权限）".to_string(),
        _ => format!("连接 helper 失败：{e}"),
    }
}

pub fn parse_reply(text: &str) -> Stats {
    let mut stats = Stats::default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("STAT\t") {
            stats.total = v.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("CALL\t") {
            let f: Vec<&str> = rest.splitn(5, '\t').collect();
            if f.len() == 5 {
                stats.calls.push(Call {
                    comm: f[0].to_string(),
                    pid: f[1].to_string(),
                    entry: f[2].to_string(),
                    ret: f[3].to_string(),
                    stack: f[4].to_string(),
                });
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_calls() {
        let text = "STAT\t12\nCALL\tbash\t1234\tbash-1234 [000] .... 1.0: sm1_1: (vfs_read) arg0=0x1\tbash-1234 [000] .... 1.1: sm1_1ret: ret=0x5\tvfs_read ← ksys_read\nEND\n";
        let s = parse_reply(text);
        assert_eq!(s.total, 12);
        assert_eq!(s.calls.len(), 1);
        assert_eq!(s.calls[0].comm, "bash");
        assert!(s.calls[0].entry.contains("arg0=0x1"));
        assert!(s.calls[0].ret.contains("ret=0x5"));
        assert_eq!(s.calls[0].stack, "vfs_read ← ksys_read");
    }

    #[test]
    fn parses_empty() {
        let s = parse_reply("STAT\t0\nEND\n");
        assert_eq!(s.total, 0);
        assert!(s.calls.is_empty());
    }

    #[test]
    fn via_transport_commands() {
        let seen = std::cell::RefCell::new(String::new());
        let mut send = |cmd: &str| {
            *seen.borrow_mut() = cmd.to_string();
            if cmd.starts_with("attach") {
                Ok("OK\tattached\n".to_string())
            } else if cmd == "poll" {
                Ok("STAT\t2\nEND\n".to_string())
            } else {
                Ok("OK\tstopped\n".to_string())
            }
        };
        let opts = Attach {
            kind: "kprobe",
            target: None,
            symbol: "vfs_read",
            stack: true,
            pid: Some(42),
            args: "arg0=%x0",
        };
        attach_via(&mut send, &opts).unwrap();
        assert!(seen.borrow().contains("attach kprobe vfs_read"));
        assert!(seen.borrow().contains("pid=42"));
        assert_eq!(poll_via(&mut send).unwrap().total, 2);
        detach_via(&mut send).unwrap();
    }

    #[test]
    fn elf_via_parses_helper_reply() {
        let mut send = |cmd: &str| {
            assert!(cmd.starts_with("elf /usr/bin/ls"));
            Ok("ELF\tdynsym\t1\t1\nSYM\tmain\t0x10\t4\t0x10\t1\nEND\n".to_string())
        };
        let elf = elf_via(&mut send, "/usr/bin/ls").unwrap();
        assert_eq!(elf.symbols.len(), 1);
        assert_eq!(elf.symbols[0].off, Some(0x10));
    }

    #[test]
    fn detects_errors() {
        assert!(first_ok("OK\tattached sm1_1\n").is_ok());
        assert_eq!(first_ok("ERR\t符号名包含非法字符\n").unwrap_err(), "符号名包含非法字符");
    }
}