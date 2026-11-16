//! cgroup v2 纯解析：cpu.max 编解码、分组名校验（core 层供 schedstate/remote/linux 共用）。

/// 百分比 → cpu.max 内容（如 50 → "50000 100000"）。
pub fn pct_to_cpu_max(pct: u32) -> String {
    format!("{} 100000", pct.saturating_mul(1000))
}

/// cpu.max 内容 → 百分比（"max 100000" → None）。
pub fn parse_cpu_max(text: &str) -> Option<u32> {
    let mut it = text.split_whitespace();
    let quota = it.next()?;
    let _period = it.next()?;
    if quota == "max" {
        return None;
    }
    Some((quota.parse::<u64>().ok()? / 1000) as u32)
}

/// 分组名白名单：非空、≤64、仅字母数字与 . _ -。
pub fn valid_group_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pct_roundtrip() {
        assert_eq!(pct_to_cpu_max(50), "50000 100000");
        assert_eq!(parse_cpu_max("50000 100000"), Some(50));
        assert_eq!(parse_cpu_max("max 100000"), None);
        assert!(valid_group_name("build_2.x"));
        assert!(!valid_group_name("../x"));
    }
}
