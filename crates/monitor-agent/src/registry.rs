//! 主机注册表与吊销：按证书指纹身份；吊销即时生效（下一任务前必查）。

use serde_json::{json, Value};

/// 主机身份：指纹即身份（mTLS 传输下=客户端证书 SHA256;进程内传输=注册时分配）。
#[derive(Clone, Debug, PartialEq)]
pub struct HostIdentity {
    pub fingerprint: String,
    pub labels: Vec<String>,
    pub registered_at_unix: u64,
}

/// 注册表 + 吊销名单。
#[derive(Default, Clone)]
pub struct Registry {
    hosts: std::collections::HashMap<String, HostIdentity>,
    revoked: std::collections::HashSet<String>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl Registry {
    pub fn register(&mut self, fingerprint: &str, labels: &[&str]) -> HostIdentity {
        let id = HostIdentity {
            fingerprint: fingerprint.to_string(),
            labels: labels.iter().map(|s| s.to_string()).collect(),
            registered_at_unix: unix_now(),
        };
        self.hosts.insert(fingerprint.to_string(), id.clone());
        id
    }

    /// 吊销：即时生效——authenticate 在同调用内即拒绝。
    pub fn revoke(&mut self, fingerprint: &str) {
        self.revoked.insert(fingerprint.to_string());
    }

    /// 任务前鉴权：已注册且未被吊销。
    pub fn authenticate(&self, fingerprint: &str) -> Result<&HostIdentity, String> {
        if self.revoked.contains(fingerprint) {
            return Err("证书已吊销".to_string());
        }
        self.hosts.get(fingerprint).ok_or_else(|| "未注册的主机".to_string())
    }

    pub fn hosts(&self) -> Vec<&HostIdentity> {
        let mut v: Vec<&HostIdentity> = self.hosts.values().collect();
        v.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        v
    }

    pub fn is_revoked(&self, fingerprint: &str) -> bool {
        self.revoked.contains(fingerprint)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "hosts": self.hosts().iter().map(|h| json!({
                "fingerprint": h.fingerprint, "labels": h.labels, "registered_at": h.registered_at_unix,
                "revoked": self.is_revoked(&h.fingerprint),
            })).collect::<Vec<_>>(),
            "revoked_count": self.revoked.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_takes_effect_immediately() {
        let mut r = Registry::default();
        r.register("fp-aaa", &["lab", "gpu"]);
        assert!(r.authenticate("fp-aaa").is_ok());
        r.revoke("fp-aaa");
        let err = r.authenticate("fp-aaa").unwrap_err();
        assert!(err.contains("吊销"), "吊销后立即拒绝：{err}");
        assert!(r.is_revoked("fp-aaa"));
        // 未注册主机同样拒绝
        assert!(r.authenticate("fp-unknown").is_err());
    }

    #[test]
    fn registry_json_shape() {
        let mut r = Registry::default();
        r.register("fp-1", &["edge"]);
        let j = r.to_json();
        assert_eq!(j["hosts"].as_array().unwrap().len(), 1);
        assert_eq!(j["hosts"][0]["revoked"], false);
    }
}
