//! 只读挂载点发现：kprobe（/proc/kallsyms）、uprobe（/proc/*/exe 与 ELF 符号表）
//! 以及本机采点能力。不加载任何 BPF 程序、不写 tracefs，因此不需要 root。

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

const MAX_SECTION_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SYMBOLS: usize = 500_000;
const TOOLS: [&str; 4] = ["bpftrace", "bpftool", "perf", "clang"];

#[derive(Clone, Debug, PartialEq)]
pub struct Symbol {
    pub name: String,
    pub module: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UprobeTarget {
    pub path: PathBuf,
    pub procs: usize,
    pub sample_pid: i32,
}

#[derive(Clone, Debug)]
pub struct ElfSym {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub global: bool,
    /// 文件偏移（uprobe_events 使用）；BSS 等无文件数据的符号为 None。
    pub off: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ElfSymbols {
    pub symbols: Vec<ElfSym>,
    pub source: &'static str,
    pub stripped: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Caps {
    pub euid: u32,
    pub bpf_syscall: Option<bool>,
    pub bpf_jit: Option<bool>,
    pub kprobe_events: Option<bool>,
    pub uprobe_events: Option<bool>,
    pub btf_file: bool,
    pub unprivileged_bpf_disabled: Option<u32>,
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
    pub tracefs_readable: bool,
    pub kprobe_events_writable: bool,
    pub debugfs_readable: bool,
    pub tools: Vec<(&'static str, bool)>,
}

pub struct Snapshot {
    pub kernel_release: String,
    pub functions: Vec<Symbol>,
    pub syscalls: Vec<Symbol>,
    pub uprobes: Vec<UprobeTarget>,
    pub caps: Caps,
    pub errors: Vec<String>,
    pub loaded_at: Instant,
    pub sweep_ms: u128,
}

impl Snapshot {
    pub fn load() -> Self {
        let start = Instant::now();
        let mut errors = Vec::new();

        let kernel_release = match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                errors.push(format!("读取内核版本失败：{e}"));
                "未知".to_string()
            }
        };

        let (functions, syscalls) = match std::fs::read_to_string("/proc/kallsyms") {
            Ok(text) => split_kallsyms(&text),
            Err(e) => {
                errors.push(format!("读取 /proc/kallsyms 失败：{e}"));
                (Vec::new(), Vec::new())
            }
        };

        let uprobes = collect_uprobes();
        let caps = read_caps(&kernel_release);

        Self {
            kernel_release,
            functions,
            syscalls,
            uprobes,
            caps,
            errors,
            loaded_at: Instant::now(),
            sweep_ms: start.elapsed().as_millis(),
        }
    }
}

pub fn is_syscall(name: &str) -> bool {
    name.starts_with("__arm64_sys_") || name.starts_with("__x64_sys_") || name.starts_with("__riscv_sys_")
}

pub fn syscall_short(name: &str) -> &str {
    name.rsplit_once("sys_").map(|(_, s)| s).unwrap_or(name)
}

/// 只保留可 kprobe 的代码符号（T/t/W/w），拆成系统调用与普通内核函数两组。
pub fn split_kallsyms(text: &str) -> (Vec<Symbol>, Vec<Symbol>) {
    let mut functions = Vec::new();
    let mut syscalls = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(_addr) = it.next() else { continue };
        let Some(kind) = it.next() else { continue };
        if !matches!(kind, "T" | "t" | "W" | "w") {
            continue;
        }
        let Some(name) = it.next() else { continue };
        if name.starts_with('$') {
            continue;
        }
        let module = it
            .next()
            .map(|m| m.trim_start_matches('[').trim_end_matches(']').to_string())
            .filter(|m| !m.is_empty());
        let sym = Symbol {
            name: name.to_string(),
            module,
        };
        if is_syscall(name) {
            syscalls.push(sym);
        } else {
            functions.push(sym);
        }
    }
    (tidy(functions), tidy(syscalls))
}

fn tidy(mut v: Vec<Symbol>) -> Vec<Symbol> {
    v.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.module.cmp(&b.module)));
    v.dedup_by(|a, b| a.name == b.name && a.module == b.module);
    v
}

pub fn collect_uprobes() -> Vec<UprobeTarget> {
    let mut map: HashMap<PathBuf, (usize, i32)> = HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in rd.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(path) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
            continue;
        };
        if path.to_string_lossy().ends_with(" (deleted)") {
            continue;
        }
        map.entry(path).and_modify(|e| e.0 += 1).or_insert((1, pid));
    }
    let mut out: Vec<UprobeTarget> = map
        .into_iter()
        .map(|(path, (procs, sample_pid))| UprobeTarget { path, procs, sample_pid })
        .collect();
    out.sort_by(|a, b| b.procs.cmp(&a.procs).then_with(|| a.path.cmp(&b.path)));
    out
}

pub fn elf_symbols(path: &Path) -> Result<ElfSymbols, String> {
    let file = File::open(path).map_err(|e| format!("无法打开：{e}"))?;
    let meta = file.metadata().map_err(|e| format!("无法读取元数据：{e}"))?;
    if !meta.is_file() {
        return Err("不是普通文件".to_string());
    }
    let mut src = FileSource(file);
    parse_elf_with(&mut src)
}

trait ByteSource {
    fn chunk(&mut self, off: u64, len: usize) -> Result<Vec<u8>, String>;
}

#[cfg(test)]
struct SliceSource<'a>(&'a [u8]);

#[cfg(test)]
impl ByteSource for SliceSource<'_> {
    fn chunk(&mut self, off: u64, len: usize) -> Result<Vec<u8>, String> {
        let start = usize::try_from(off).map_err(|_| "偏移越界".to_string())?;
        let end = start.checked_add(len).ok_or("读取范围溢出")?;
        self.0.get(start..end).map(|s| s.to_vec()).ok_or_else(|| "读取越界".to_string())
    }
}

struct FileSource(File);

impl ByteSource for FileSource {
    fn chunk(&mut self, off: u64, len: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        self.0.seek(SeekFrom::Start(off)).map_err(|e| format!("定位失败：{e}"))?;
        self.0.read_exact(&mut buf).map_err(|e| format!("读取失败：{e}"))?;
        Ok(buf)
    }
}

#[derive(Clone, Copy)]
struct Section {
    ty: u32,
    addr: u64,
    off: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

/// 把符号名解析成 uprobe_events 需要的文件偏移（GUI 侧由 helper 使用）。
#[allow(dead_code)]
pub fn elf_symbol_offset(path: &Path, symbol: &str) -> Result<u64, String> {
    let elf = elf_symbols(path)?;
    let sym = elf
        .symbols
        .iter()
        .find(|s| s.name == symbol)
        .ok_or_else(|| format!("符号 {symbol} 不在 {} 的符号表中", path.display()))?;
    sym.off
        .ok_or_else(|| format!("符号 {symbol} 没有可用的文件偏移（可能位于 BSS）"))
}

#[cfg(test)]
pub fn parse_elf(b: &[u8]) -> Result<ElfSymbols, String> {
    let mut src = SliceSource(b);
    parse_elf_with(&mut src)
}

/// 按段读取 64 位小端 ELF 的 .symtab / .dynsym，避免整文件载入大二进制。
fn parse_elf_with(src: &mut dyn ByteSource) -> Result<ElfSymbols, String> {
    let eh = src.chunk(0, 64)?;
    if &eh[0..4] != b"\x7fELF" {
        return Err("不是 ELF 文件".to_string());
    }
    if eh[4] != 2 {
        return Err("仅支持 64 位 ELF".to_string());
    }
    if eh[5] != 1 {
        return Err("仅支持小端 ELF".to_string());
    }
    let shoff = rd_u64(&eh, 40).ok_or("ELF 头不完整")?;
    let shentsize = rd_u16(&eh, 58).ok_or("ELF 头不完整")? as usize;
    let shnum = rd_u16(&eh, 60).ok_or("ELF 头不完整")? as usize;
    if shentsize < 64 {
        return Err("段表项过小".to_string());
    }
    let table_len = shnum.checked_mul(shentsize).ok_or("段表过大")?;
    if table_len > 16 * 1024 * 1024 {
        return Err("段表异常".to_string());
    }
    let table = src.chunk(shoff, table_len)?;

    let mut sections = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let o = i * shentsize;
        sections.push(Section {
            ty: rd_u32(&table, o + 4).ok_or("段表损坏")?,
            addr: rd_u64(&table, o + 16).ok_or("段表损坏")?,
            off: rd_u64(&table, o + 24).ok_or("段表损坏")?,
            size: rd_u64(&table, o + 32).ok_or("段表损坏")?,
            link: rd_u32(&table, o + 40).ok_or("段表损坏")?,
            entsize: rd_u64(&table, o + 56).ok_or("段表损坏")?,
        });
    }

    let mut syms: HashMap<String, ElfSym> = HashMap::new();
    let mut has_symtab = false;
    let mut has_dynsym = false;
    for s in &sections {
        if s.ty != 2 && s.ty != 11 {
            continue;
        }
        if s.ty == 2 {
            has_symtab = true;
        } else {
            has_dynsym = true;
        }
        let Some(strtab) = sections.get(s.link as usize) else { continue };
        if strtab.ty != 3 || s.size == 0 || s.size > MAX_SECTION_BYTES || strtab.size > MAX_SECTION_BYTES {
            continue;
        }
        let entsize = if s.entsize == 0 { 24 } else { usize::try_from(s.entsize).unwrap_or(0) };
        if entsize < 24 {
            continue;
        }
        let Ok(sym_bytes) = src.chunk(s.off, s.size as usize) else { continue };
        let Ok(str_bytes) = src.chunk(strtab.off, strtab.size as usize) else { continue };
        let count = (sym_bytes.len() / entsize).min(MAX_SYMBOLS);
        for i in 0..count {
            let o = i * entsize;
            let (Some(name_off), Some(info), Some(shndx), Some(value), Some(size)) = (
                rd_u32(&sym_bytes, o),
                rd_u8(&sym_bytes, o + 4),
                rd_u16(&sym_bytes, o + 6),
                rd_u64(&sym_bytes, o + 8),
                rd_u64(&sym_bytes, o + 16),
            ) else {
                break;
            };
            // STT_FUNC；跳过未定义符号（无地址，不能挂 uprobe）
            if info & 0xf != 2 || shndx == 0 || value == 0 {
                continue;
            }
            let Some(name) = read_str(&str_bytes, 0, str_bytes.len(), name_off as usize) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let global = info >> 4 != 0;
            let off = sections.get(shndx as usize).and_then(|sec| {
                if sec.ty == 8 {
                    return None;
                }
                value.checked_sub(sec.addr).and_then(|delta| sec.off.checked_add(delta))
            });
            let cand = ElfSym {
                name: name.to_string(),
                addr: value,
                size,
                global,
                off,
            };
            match syms.get_mut(&cand.name) {
                Some(old) => {
                    if (cand.global && !old.global) || (cand.global == old.global && cand.size > old.size) {
                        *old = cand;
                    }
                }
                None => {
                    syms.insert(cand.name.clone(), cand);
                }
            }
        }
    }

    let mut symbols: Vec<ElfSym> = syms.into_values().collect();
    symbols.sort_by(|a, b| a.name.cmp(&b.name));
    let source = match (has_symtab, has_dynsym) {
        (true, true) => "symtab + dynsym",
        (true, false) => "symtab",
        (false, true) => "dynsym",
        _ => "无",
    };
    Ok(ElfSymbols {
        symbols,
        source,
        stripped: !has_symtab,
    })
}

fn rd_u8(b: &[u8], off: usize) -> Option<u8> {
    b.get(off).copied()
}

fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn read_str(b: &[u8], off: usize, size: usize, rel: usize) -> Option<&str> {
    if rel >= size {
        return None;
    }
    let start = off.checked_add(rel)?;
    let end = off.checked_add(size)?.min(b.len());
    if start >= end {
        return None;
    }
    let s = &b[start..end];
    let nul = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    std::str::from_utf8(&s[..nul]).ok()
}

fn read_caps(release: &str) -> Caps {
    let cfg_text = std::fs::read_to_string(format!("/boot/config-{release}")).unwrap_or_default();
    let cap_eff = cap_eff();
    Caps {
        euid: unsafe { libc::geteuid() },
        bpf_syscall: cfg_flag(&cfg_text, "CONFIG_BPF_SYSCALL"),
        bpf_jit: cfg_flag(&cfg_text, "CONFIG_BPF_JIT"),
        kprobe_events: cfg_flag(&cfg_text, "CONFIG_KPROBE_EVENTS"),
        uprobe_events: cfg_flag(&cfg_text, "CONFIG_UPROBE_EVENTS"),
        btf_file: Path::new("/sys/kernel/btf/vmlinux").exists(),
        unprivileged_bpf_disabled: std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
            .ok()
            .and_then(|s| s.trim().parse().ok()),
        cap_bpf: cap_eff & (1 << 39) != 0,
        cap_perfmon: cap_eff & (1 << 38) != 0,
        tracefs_readable: std::fs::read_dir("/sys/kernel/tracing/events").is_ok(),
        kprobe_events_writable: writable("/sys/kernel/tracing/kprobe_events"),
        debugfs_readable: std::fs::read_dir("/sys/kernel/debug").is_ok(),
        tools: TOOLS.iter().map(|t| (*t, which(t))).collect(),
    }
}

fn cfg_flag(text: &str, key: &str) -> Option<bool> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(key)
            && let Some(v) = rest.strip_prefix('=')
        {
            return Some(v.trim() == "y" || v.trim() == "m");
        }
        if line.starts_with("# ") && line.contains(key) && line.ends_with(" is not set") {
            return Some(false);
        }
    }
    None
}

fn cap_eff() -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("CapEff:") {
            return u64::from_str_radix(v.trim(), 16).unwrap_or(0);
        }
    }
    0
}

fn writable(path: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(path) else {
        return false;
    };
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

fn which(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| std::env::split_paths(&paths).any(|d| d.join(name).is_file()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
0000000000000000 T _text
0000000000000000 t local_helper
0000000000000000 T __arm64_sys_openat
0000000000000000 T vfs_read
0000000000000000 t vfs_read
0000000000000000 T v3d_irq\t[v3d]
0000000000000000 D data_symbol
";

    #[test]
    fn kallsyms_split_and_dedupe() {
        let (funcs, syscalls) = split_kallsyms(SAMPLE);
        assert_eq!(syscalls.len(), 1);
        assert_eq!(syscalls[0].name, "__arm64_sys_openat");
        assert_eq!(syscall_short(&syscalls[0].name), "openat");
        assert_eq!(funcs.iter().filter(|s| s.name == "vfs_read").count(), 1);
        assert!(funcs.iter().any(|s| s.name == "v3d_irq" && s.module.as_deref() == Some("v3d")));
        assert!(!funcs.iter().any(|s| s.name == "data_symbol"));
    }

    fn tiny_elf() -> Vec<u8> {
        // 64 位小端 ELF：3 个段头（空 / .symtab / .strtab），一个 hello 函数符号
        let mut b = vec![0u8; 0x127];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[18..20].copy_from_slice(&0xB7u16.to_le_bytes()); // EM_AARCH64
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
        b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        b[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
        b[62..64].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx

        let symtab = 64 + 64;
        b[symtab + 4..symtab + 8].copy_from_slice(&2u32.to_le_bytes()); // SHT_SYMTAB
        b[symtab + 24..symtab + 32].copy_from_slice(&0x100u64.to_le_bytes());
        b[symtab + 32..symtab + 40].copy_from_slice(&24u64.to_le_bytes());
        b[symtab + 40..symtab + 44].copy_from_slice(&2u32.to_le_bytes()); // sh_link -> strtab
        b[symtab + 56..symtab + 64].copy_from_slice(&24u64.to_le_bytes());

        let strtab = 64 + 128;
        b[strtab + 4..strtab + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        b[strtab + 24..strtab + 32].copy_from_slice(&0x120u64.to_le_bytes());
        b[strtab + 32..strtab + 40].copy_from_slice(&7u64.to_le_bytes());

        b[0x100..0x104].copy_from_slice(&1u32.to_le_bytes()); // st_name
        b[0x104] = 0x12; // GLOBAL | FUNC
        b[0x106..0x108].copy_from_slice(&1u16.to_le_bytes());
        b[0x108..0x110].copy_from_slice(&0x1234u64.to_le_bytes());
        b[0x110..0x118].copy_from_slice(&16u64.to_le_bytes());
        b[0x120..0x127].copy_from_slice(b"\0hello\0");
        b
    }

    #[test]
    fn elf_function_symbols() {
        let elf = parse_elf(&tiny_elf()).expect("parse");
        assert_eq!(elf.symbols.len(), 1);
        assert_eq!(elf.symbols[0].name, "hello");
        assert_eq!(elf.symbols[0].addr, 0x1234);
        assert!(elf.symbols[0].global);
        assert_eq!(elf.source, "symtab");
        assert!(!elf.stripped);
    }

    #[test]
    fn elf_from_running_binary() {
        let exe = std::env::current_exe().expect("current_exe");
        let parsed = elf_symbols(&exe).expect("parse test binary");
        assert!(!parsed.symbols.is_empty());
        assert!(parsed.symbols.iter().any(|s| s.off.is_some()));
        let len = std::fs::metadata(&exe).unwrap().len();
        for s in &parsed.symbols {
            if let Some(off) = s.off {
                assert!(off < len, "offset {off:#x} out of file");
            }
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_elf(b"not an elf").is_err());
        let mut elf = tiny_elf();
        elf[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_elf(&elf).is_err());
    }

    #[test]
    fn config_flags() {
        let text = "CONFIG_BPF_SYSCALL=y\n# CONFIG_DEBUG_INFO_BTF is not set\nCONFIG_BPF_JIT=m\n";
        assert_eq!(cfg_flag(text, "CONFIG_BPF_SYSCALL"), Some(true));
        assert_eq!(cfg_flag(text, "CONFIG_DEBUG_INFO_BTF"), Some(false));
        assert_eq!(cfg_flag(text, "CONFIG_BPF_JIT"), Some(true));
        assert_eq!(cfg_flag(text, "CONFIG_MISSING"), None);
    }
}