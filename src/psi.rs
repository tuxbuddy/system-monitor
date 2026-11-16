//! PSI 压力失速指标（#18）：/proc/pressure/{cpu,memory,io} 与 cgroup v2
//! `*.pressure` 的解析与展示数据。
//!
//! some = 有任务因资源等待而变慢；full = 所有任务同时停摆（cpu 无 full 行）。
//! 内核未启用 PSI 时文件不存在，调用方拿到 `None`，必须显式标记 unsupported，
//! 不能伪造 0。

use serde_json::{json, Value};

/// 单类资源的压力读数（avg 为百分比，total 为微秒累计）。
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct PsiLine {
    pub avg10: f32,
    pub avg60: f32,
    pub avg300: f32,
    pub total_us: u64,
}

/// 一类资源的 PSI：some 恒有，full 可缺（cpu 无 full）。
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct PsiResource {
    pub some: PsiLine,
    pub full: Option<PsiLine>,
}

/// 三类资源压力；`None` 表示该类不可用（文件缺失/内核未启用）。
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct PsiSnapshot {
    pub cpu: Option<PsiResource>,
    pub memory: Option<PsiResource>,
    pub io: Option<PsiResource>,
}

impl PsiSnapshot {
    pub fn any_supported(&self) -> bool {
        self.cpu.is_some() || self.memory.is_some() || self.io.is_some()
    }

    /// JSON（MCP/导出共用）；unsupported 类输出 null 而不是 0。
    pub fn to_json(&self) -> Value {
        let res = |r: &Option<PsiResource>| match r {
            None => Value::Null,
            Some(r) => json!({
                "some": line_json(&r.some),
                "full": r.full.as_ref().map(line_json),
            }),
        };
        json!({
            "supported": self.any_supported(),
            "cpu": res(&self.cpu),
            "memory": res(&self.memory),
            "io": res(&self.io),
        })
    }
}

fn line_json(l: &PsiLine) -> Value {
    json!({
        "avg10": round2(l.avg10), "avg60": round2(l.avg60), "avg300": round2(l.avg300),
        "total_us": l.total_us,
    })
}

fn round2(v: f32) -> f64 {
    (f64::from(v) * 100.0).round() / 100.0
}

/// 解析单行 `some avg10=0.00 avg60=0.00 avg300=0.00 total=0`。
/// 行内键序固定，但解析按前缀匹配以容忍内核格式微调；数值异常返回 None。
pub fn parse_psi_line(line: &str) -> Option<PsiLine> {
    let mut out = PsiLine::default();
    let mut seen = 0;
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("avg10=") {
            out.avg10 = v.parse().ok()?;
            seen += 1;
        } else if let Some(v) = tok.strip_prefix("avg60=") {
            out.avg60 = v.parse().ok()?;
            seen += 1;
        } else if let Some(v) = tok.strip_prefix("avg300=") {
            out.avg300 = v.parse().ok()?;
            seen += 1;
        } else if let Some(v) = tok.strip_prefix("total=") {
            out.total_us = v.parse().ok()?;
            seen += 1;
        }
    }
    (seen == 4).then_some(out)
}

/// 解析一类资源的文本（some 行 + 可选 full 行；异常行忽略但 some 缺失即 None）。
pub fn parse_psi_resource(text: &str) -> Option<PsiResource> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("some") {
            some = parse_psi_line(rest);
        } else if let Some(rest) = l.strip_prefix("full") {
            full = parse_psi_line(rest);
        }
    }
    Some(PsiResource { some: some?, full })
}

/// 读取本地 PSI 快照：/proc/pressure/{cpu,memory,io}。
/// 文件缺失（内核未启用 PSI）→ 对应类为 None；读失败同样 None。
pub fn read_local() -> PsiSnapshot {
    let read = |name: &str| -> Option<PsiResource> {
        let text = std::fs::read_to_string(format!("/proc/pressure/{name}")).ok()?;
        parse_psi_resource(&text)
    };
    PsiSnapshot { cpu: read("cpu"), memory: read("memory"), io: read("io") }
}

/// cgroup v2 的 `cpu.pressure` / `memory.pressure` / `io.pressure`（同格式）。
pub fn read_cgroup(dir: &std::path::Path) -> PsiSnapshot {
    let read = |name: &str| -> Option<PsiResource> {
        let text = std::fs::read_to_string(dir.join(format!("{name}.pressure"))).ok()?;
        parse_psi_resource(&text)
    };
    PsiSnapshot { cpu: read("cpu"), memory: read("memory"), io: read("io") }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "some avg10=1.23 avg60=4.56 avg300=7.89 total=123456789\nfull avg10=0.10 avg60=0.20 avg300=0.30 total=999\n";

    #[test]
    fn parses_some_and_full() {
        let r = parse_psi_resource(SAMPLE).unwrap();
        assert!((r.some.avg10 - 1.23).abs() < 1e-4);
        assert_eq!(r.some.total_us, 123_456_789);
        let full = r.full.unwrap();
        assert!((full.avg300 - 0.30).abs() < 1e-4);
        // cpu 无 full 行
        let cpu = parse_psi_resource("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
        assert!(cpu.full.is_none());
    }

    #[test]
    fn malformed_lines_are_not_fatal_but_some_is_required() {
        // garbage some 行解析失败 → None
        assert!(parse_psi_resource("some avg10=xx\nfull avg10=1 avg60=1 avg300=1 total=1\n").is_none());
        // some 缺失只有 full → None
        assert!(parse_psi_resource("full avg10=1 avg60=1 avg300=1 total=1\n").is_none());
        // 多余空行/空白容忍
        assert!(parse_psi_resource("\nsome avg10=1 avg60=2 avg300=3 total=4\n\n").is_some());
    }

    #[test]
    fn unsupported_is_null_not_zero() {
        let snap = PsiSnapshot { cpu: Some(parse_psi_resource(SAMPLE).unwrap()), memory: None, io: None };
        let j = snap.to_json();
        assert_eq!(j["supported"], true);
        assert_eq!(j["memory"], Value::Null, "unsupported 必须是 null,不能伪造 0");
        assert!(j["cpu"]["some"]["avg10"].as_f64().unwrap() > 0.0);
        assert_eq!(j["cpu"]["full"]["total_us"], 999);
        let none = PsiSnapshot::default();
        assert_eq!(none.to_json()["supported"], false);
    }

    #[test]
    fn local_read_tolerates_missing_files() {
        // 在无 PSI 的环境（macOS/容器）不 panic 且标记不支持
        let snap = read_local();
        if !std::path::Path::new("/proc/pressure/cpu").exists() {
            assert!(!snap.any_supported());
        }
    }
}
