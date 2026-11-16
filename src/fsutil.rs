//! 配置类文件的原子写入与历史轮转。
//!
//! 写入中断（崩溃、断电、磁盘满）不能留下半截文件：先写同目录临时文件、
//! fsync、chmod 最小权限，再 rename 原子替换。历史/日志类文件按大小轮转，
//! 保留固定份数，防止无限增长。

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// 权限：属主读写。配置与主机清单可能含内网拓扑，不该给其他用户读权限。
pub const MODE_PRIVATE: u32 = 0o600;

/// 原子写入：tmp(同目录) → write_all → fsync → chmod → rename → 目录 fsync。
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = tmp_path(path);
    let ret = write_tmp(&tmp, bytes, mode).and_then(|()| std::fs::rename(&tmp, path));
    if ret.is_err() {
        // 清理残留临时文件，失败不掩盖原始错误
        let _ = std::fs::remove_file(&tmp);
    }
    ret.and_then(|()| sync_dir(dir))
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "file".to_string());
    name.push_str(&format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

fn write_tmp(tmp: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = File::create(tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir).and_then(|d| d.sync_all())
}

/// 若文件超过 `max_bytes` 则轮转：`log` → `log.1` → … → `log.(keep)`，
/// 最老的一份被删除。返回是否发生了轮转。文件不存在时返回 Ok(false)。
pub fn rotate_if_large(path: &Path, max_bytes: u64, keep: usize) -> io::Result<bool> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(false);
    };
    if meta.len() <= max_bytes {
        return Ok(false);
    }
    for i in (1..keep).rev() {
        let from = numbered(path, i);
        let to = numbered(path, i + 1);
        if from.exists() {
            if to.exists() {
                std::fs::remove_file(&to)?;
            }
            std::fs::rename(&from, &to)?;
        }
    }
    std::fs::rename(path, numbered(path, 1))?;
    Ok(true)
}

fn numbered(path: &Path, n: usize) -> PathBuf {
    let mut name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "file".to_string());
    name.push_str(&format!(".{n}"));
    path.with_file_name(name)
}

/// 追加一行并保证单行不超过 `line_cap`（截断中间），随后按大小轮转。
/// 返回写入是否成功；调用方负责把失败展示给用户而不是静默丢弃。
pub fn append_line_capped(path: &Path, line: &str, max_bytes: u64, keep: usize, line_cap: usize) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let capped: String = if line.len() <= line_cap {
        line.to_string()
    } else {
        // 保留头尾，中间以省略号标记，保证单行不失控
        let head = line_cap / 2;
        let tail = line_cap / 4;
        format!("{}…{}", &line[..head], &line[line.len() - tail..])
    };
    rotate_if_large(path, max_bytes, keep)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new().append(true).create(true).mode(MODE_PRIVATE).open(path)?;
        writeln!(f, "{capped}")?;
    }
    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new().append(true).create(true).open(path)?;
        writeln!(f, "{capped}")?;
    }
    Ok(())
}

/// 读取文件前 `max_bytes` 字节（文本文件兜底，防止把异常大文件整个读入内存）。
#[allow(dead_code)] // 基础件：GUI/TUI 迁移大文件读取时复用
pub fn read_capped(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    let mut limited = (&mut f).take(max_bytes);
    limited.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sm-fsutil-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn atomic_write_replaces_content_and_sets_mode() {
        let d = tmpdir("atomic");
        let p = d.join("config.conf");
        atomic_write(&p, b"a=1\n", MODE_PRIVATE).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"a=1\n");
        atomic_write(&p, b"a=2\n", MODE_PRIVATE).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"a=2\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "配置文件权限应为 0600");
        }
        // 不留临时文件
        let leftovers: Vec<_> = std::fs::read_dir(&d).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(leftovers.len(), 1, "目录内只应有目标文件：{leftovers:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn atomic_write_failure_leaves_original_intact() {
        let d = tmpdir("fail");
        let p = d.join("x.conf");
        atomic_write(&p, b"good\n", MODE_PRIVATE).unwrap();
        // 让目标路径变成目录，rename 必然失败
        let blocking = d.join("x.conf.tmp-block");
        std::fs::create_dir(&blocking).unwrap();
        // 用一个无法 rename 覆盖的场景：目标为目录
        let target_as_dir = d.join("as-dir");
        std::fs::create_dir(&target_as_dir).unwrap();
        assert!(atomic_write(&target_as_dir, b"nope\n", MODE_PRIVATE).is_err());
        // 原文件内容未受影响
        assert_eq!(std::fs::read(&p).unwrap(), b"good\n");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rotate_keeps_bound() {
        let d = tmpdir("rotate");
        let p = d.join("history.log");
        let big = "x".repeat(300);
        for i in 0..4 {
            std::fs::write(&p, &big).unwrap();
            assert!(rotate_if_large(&p, 100, 3).unwrap());
            std::fs::write(numbered(&p, 1), format!("gen{i}")).unwrap_or(());
        }
        // 轮转语义：当前文件被 rename 走（.1 是最新一轮，旧轮次依次后移）
        assert!(!p.exists(), "轮转后主文件应被移走");
        assert!(numbered(&p, 1).exists());
        assert!(numbered(&p, 2).exists());
        assert!(numbered(&p, 3).exists(), "应保留 3 份历史");
        assert!(!numbered(&p, 4).exists(), "最老一份应被挤掉");
        // 不轮转的小文件
        std::fs::write(&p, "small").unwrap();
        assert!(!rotate_if_large(&p, 100, 3).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn append_capped_line_and_rotation() {
        let d = tmpdir("append");
        let p = d.join("h.log");
        let long_line = "y".repeat(10_000);
        append_line_capped(&p, &long_line, 4 * 1024 * 1024, 3, 1000).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.lines().count() == 1);
        assert!(text.trim().len() <= 1100, "超长行应被截断：{}", text.len());
        // 正常行
        append_line_capped(&p, "ok-line", 4 * 1024 * 1024, 3, 1000).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.ends_with("ok-line\n"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn read_capped_limits_input() {
        let d = tmpdir("readcap");
        let p = d.join("big.log");
        std::fs::write(&p, vec![b'z'; 1000]).unwrap();
        assert_eq!(read_capped(&p, 100).unwrap().len(), 100);
        let _ = std::fs::remove_dir_all(&d);
    }
}
