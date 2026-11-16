//! SSH 目标校验新类型：所有进入 `ssh` 命令行的主机都必须先通过这里。
//!
//! 目标串来自 `hosts.conf`、GUI 输入或 MCP 工具参数，属于不可信输入；
//! 未经校验的字符串可能以 `-` 开头被 ssh 当作选项，或携带空白/控制字符
//! 触发意外解析路径。校验规则：
//! - 可选 `user@` 前缀（只允许出现一次 `@`）；
//! - 主机部分允许：hostname / IPv4 / `[IPv6]` / ssh config 别名；
//! - 长度上限：整体 ≤ 320（user ≤ 64 + `@` + host ≤ 253 + 括号），主机部分 ≤ 255；
//! - 拒绝：首字符 `-`、空白/控制字符、shell 元字符、空主机。

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshTarget {
    /// 原样保留的合法目标串（user@host 或 host）。
    raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshTargetError {
    Empty,
    /// 以 `-` 开头，会被 ssh 当作选项解析。
    LeadingDash,
    /// 含空白或控制字符。
    BadChar(char),
    /// 含 shell 元字符。
    MetaChar(char),
    /// 出现多个 `@`。
    MultipleAt,
    /// user 部分为空（`@host`）。
    EmptyUser,
    /// 主机部分为空。
    EmptyHost,
    /// 超过长度上限。
    TooLong { len: usize, max: usize },
    /// IPv6 括号不闭合。
    BadIpv6,
}

impl fmt::Display for SshTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "SSH 目标为空"),
            Self::LeadingDash => write!(f, "SSH 目标不能以 - 开头（会被当作 ssh 选项）"),
            Self::BadChar(c) => write!(f, "SSH 目标含空白/控制字符：{c:?}"),
            Self::MetaChar(c) => write!(f, "SSH 目标含 shell 元字符：{c:?}"),
            Self::MultipleAt => write!(f, "SSH 目标包含多个 @"),
            Self::EmptyUser => write!(f, "user@ 前缀缺少用户名"),
            Self::EmptyHost => write!(f, "SSH 目标缺少主机名"),
            Self::TooLong { len, max } => write!(f, "SSH 目标过长：{len} > {max}"),
            Self::BadIpv6 => write!(f, "IPv6 目标括号不匹配"),
        }
    }
}

pub const MAX_TOTAL: usize = 320;
pub const MAX_HOST: usize = 255;
pub const MAX_USER: usize = 64;

/// 可能被 shell 或 ssh 特殊解释的元字符；主机名/别名/地址都不需要它们。
const META_CHARS: &[char] = &['`', '$', ';', '&', '|', '<', '>', '\\', '"', '\'', '!', '(', ')', '{', '}', '*', '?', '~', '#', '%', '\0'];

fn valid_user_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

impl SshTarget {
    /// 校验并构造目标。合法输入示例：`host`、`user@host`、`root@10.0.0.1`、
    /// `[fe80::1%25eth0]`、`my-alias`。
    pub fn parse(s: &str) -> Result<Self, SshTargetError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(SshTargetError::Empty);
        }
        if s.len() > MAX_TOTAL {
            return Err(SshTargetError::TooLong { len: s.len(), max: MAX_TOTAL });
        }
        if let Some(c) = s.chars().next()
            && c == '-'
        {
            return Err(SshTargetError::LeadingDash);
        }
        for c in s.chars() {
            if c.is_whitespace() || c.is_control() {
                return Err(SshTargetError::BadChar(c));
            }
            if META_CHARS.contains(&c) {
                return Err(SshTargetError::MetaChar(c));
            }
        }
        let (user, host) = match s.split_once('@') {
            None => (None, s),
            Some((u, rest)) => {
                if rest.contains('@') {
                    return Err(SshTargetError::MultipleAt);
                }
                if u.is_empty() {
                    return Err(SshTargetError::EmptyUser);
                }
                (Some(u), rest)
            }
        };
        if host.is_empty() {
            return Err(SshTargetError::EmptyHost);
        }
        if let Some(u) = user
            && (u.len() > MAX_USER || !u.chars().all(valid_user_char))
        {
            return Err(SshTargetError::MetaChar(u.chars().next().unwrap_or('?')));
        }
        if host.starts_with('-') {
            return Err(SshTargetError::LeadingDash);
        }
        if host.len() > MAX_HOST {
            return Err(SshTargetError::TooLong { len: host.len(), max: MAX_HOST });
        }
        // IPv6 字面量必须带方括号；`[`/`]` 已在元字符黑名单外单独放行校验。
        let inner = host.strip_prefix('[');
        if let Some(body) = inner {
            let Some(body) = body.strip_suffix(']') else {
                return Err(SshTargetError::BadIpv6);
            };
            if body.is_empty() || !body.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '%')) {
                return Err(SshTargetError::BadIpv6);
            }
        } else if host.contains(':') {
            // 不带括号的冒号会被 ssh 解析为 host:port，本项目不支持该形式。
            return Err(SshTargetError::BadChar(':'));
        } else if !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
            return Err(SshTargetError::BadChar(host.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))).unwrap_or('?')));
        }
        Ok(Self { raw: s.to_string() })
    }

    /// 已知合法路径（内部常量/测试构造用）。
    #[allow(dead_code)]
    pub fn new_unchecked(s: &str) -> Self {
        Self { raw: s.to_string() }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for SshTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl AsRef<str> for SshTarget {
    fn as_ref(&self) -> &str {
        &self.raw
    }
}

/// 校验失败带行号（`hosts.conf` 可定位报告）。
#[derive(Debug, Clone, PartialEq)]
pub struct HostsLineError {
    pub line_no: usize,
    pub target: String,
    pub error: SshTargetError,
}

impl fmt::Display for HostsLineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "第 {} 行「{}」：{}", self.line_no, self.target, self.error)
    }
}

/// 解析 hosts.conf 文本：返回合法目标与带行号的错误列表（非法行不静默跳过）。
pub fn parse_hosts_checked(text: &str) -> (Vec<SshTarget>, Vec<HostsLineError>) {
    let mut ok = Vec::new();
    let mut errs = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        match SshTarget::parse(l) {
            Ok(t) => ok.push(t),
            Err(e) => errs.push(HostsLineError { line_no: i + 1, target: l.to_string(), error: e }),
        }
    }
    (ok, errs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_legal_forms() {
        for s in ["pi@192.168.1.5", "root@kylin", "my-host.example.org", "[fe80::1]", "user@[2001:db8::1]", "alias_1", "a.b-c.d"] {
            assert!(SshTarget::parse(s).is_ok(), "应接受 {s}");
        }
    }

    #[test]
    fn rejects_option_injection() {
        assert_eq!(SshTarget::parse("-oProxyCommand=evil"), Err(SshTargetError::LeadingDash));
        assert_eq!(SshTarget::parse("--"), Err(SshTargetError::LeadingDash));
        assert_eq!(SshTarget::parse("-"), Err(SshTargetError::LeadingDash));
    }

    #[test]
    fn rejects_whitespace_and_control() {
        assert!(matches!(SshTarget::parse("a b"), Err(SshTargetError::BadChar(' '))));
        assert!(matches!(SshTarget::parse("a\nb"), Err(SshTargetError::BadChar('\n'))));
        assert!(matches!(SshTarget::parse("a\tb"), Err(SshTargetError::BadChar('\t'))));
        assert!(matches!(SshTarget::parse("a\u{0}b"), Err(SshTargetError::BadChar('\0'))));
    }

    #[test]
    fn rejects_meta_chars() {
        for s in ["host;rm", "host`x`", "$(x)", "host|x", "host&x", "host>x", "host<x", "host'x'", "host\"x\"", "host\\x", "a{b}", "a*b", "a?b", "a~b", "a#b", "a%b", "a!b", "a(b)", "a$b"] {
            let e = SshTarget::parse(s);
            assert!(matches!(e, Err(SshTargetError::MetaChar(_))), "{s} 应被拒绝（shell 元字符），实际 {e:?}");
        }
    }

    #[test]
    fn rejects_bare_brackets() {
        // 只有成对的 [IPv6] 合法；裸括号主机按字符集拒绝
        assert!(matches!(SshTarget::parse("a[b]"), Err(SshTargetError::BadChar('['))));
        assert!(matches!(SshTarget::parse("[fe80::1]x"), Err(SshTargetError::BadIpv6)));
        // 成对且 body 合法的 IPv6 字面量必须通过
        assert!(SshTarget::parse("[fe80::1]").is_ok());
        assert!(SshTarget::parse("user@[2001:db8::1]").is_ok());
        // host 部分以 - 开头同样视为选项注入
        assert_eq!(SshTarget::parse("root@-x"), Err(SshTargetError::LeadingDash));
        assert_eq!(SshTarget::parse("-x"), Err(SshTargetError::LeadingDash));
    }

    #[test]
    fn rejects_structural_errors() {
        assert_eq!(SshTarget::parse(""), Err(SshTargetError::Empty));
        assert_eq!(SshTarget::parse("   "), Err(SshTargetError::Empty));
        assert_eq!(SshTarget::parse("a@b@c"), Err(SshTargetError::MultipleAt));
        assert_eq!(SshTarget::parse("@host"), Err(SshTargetError::EmptyUser));
        assert_eq!(SshTarget::parse("user@"), Err(SshTargetError::EmptyHost));
        assert_eq!(SshTarget::parse("[fe80::1"), Err(SshTargetError::BadIpv6));
        assert_eq!(SshTarget::parse("[zz]"), Err(SshTargetError::BadIpv6));
        assert_eq!(SshTarget::parse("host:22"), Err(SshTargetError::BadChar(':')));
        assert!(matches!(SshTarget::parse(&"x".repeat(400)), Err(SshTargetError::TooLong { .. })));
        assert!(matches!(SshTarget::parse(&format!("{}.example.org", "x".repeat(300))), Err(SshTargetError::TooLong { .. })));
    }

    #[test]
    fn rejects_bad_user_chars() {
        assert!(matches!(SshTarget::parse("us er@host"), Err(SshTargetError::BadChar(' '))));
        assert!(matches!(SshTarget::parse("u!ser@host"), Err(SshTargetError::MetaChar('!'))));
    }

    #[test]
    fn hosts_checked_reports_line_numbers() {
        let (ok, errs) = parse_hosts_checked("# 注释\n pi@192.168.1.5 \n\n-bad\nuser@ok\nroot@-x\n");
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].as_str(), "pi@192.168.1.5");
        assert_eq!(errs.len(), 2);
        assert_eq!(errs[0].line_no, 4);
        assert_eq!(errs[0].error, SshTargetError::LeadingDash);
        assert_eq!(errs[1].line_no, 6);
        assert!(errs[0].to_string().contains("第 4 行"), "错误应带行号：{}", errs[0]);
    }
}
