//! 传输抽象：进程内实现（仿真测试/PoC）；mTLS 网络传输为后续接入点。

use crate::types::Task;
use monitor_core::sshtarget::SshTarget;

/// 传输层：控制端 → Agent 的任务下发与回执。
/// mTLS 接入点：实现方在 `recv` 前完成双向 TLS 与指纹认证（Registry 把关）。
pub trait Transport {
    /// 控制端向目标主机下发任务;返回任务 id。
    fn send(&mut self, target: &str, task: Task) -> Result<u64, String>;
    /// Agent 侧拉取待处理任务（离线时返回空;本地队列仍在）。
    fn recv(&mut self, fingerprint: &str) -> Vec<(u64, Task)>;
}

/// 进程内传输（PoC/测试）：HashMap 信箱。
#[derive(Default)]
pub struct InProcessTransport {
    inboxes: std::collections::HashMap<String, Vec<(u64, Task)>>,
    next_id: u64,
}

impl InProcessTransport {
    /// 主机键规范统一走 SshTarget 校验（复用同一安全面）。
    pub fn canonical_target(host: &str) -> Result<String, String> {
        SshTarget::parse(host).map(|t| t.as_str().to_string()).map_err(|e| format!("主机目标非法：{e}"))
    }
}

impl Transport for InProcessTransport {
    fn send(&mut self, target: &str, task: Task) -> Result<u64, String> {
        let key = Self::canonical_target(target)?;
        self.next_id += 1;
        let id = self.next_id;
        self.inboxes.entry(key).or_default().push((id, task));
        Ok(id)
    }

    fn recv(&mut self, fingerprint: &str) -> Vec<(u64, Task)> {
        self.inboxes.remove(fingerprint).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbox_per_host_and_invalid_target_rejected() {
        let mut t = InProcessTransport::default();
        let id = t.send("root@host-a", Task::CollectOverview).unwrap();
        assert_eq!(id, 1);
        // 注入目标在传输层被拒
        assert!(t.send("-oProxyCommand=evil", Task::CollectOverview).is_err());
        assert_eq!(t.recv("root@host-a").len(), 1);
        assert!(t.recv("root@host-a").is_empty());
    }
}
