//! #29 PoC 仿真：20 台模拟主机注册→心跳→任务下发→回执→吊销→离线恢复。
//! 进程内传输,无网络依赖;真实部署的 mTLS 传输为 trait 接入点。

use monitor_agent::agent::{AgentCore, LocalExecutor, LocalPolicy};
use monitor_agent::registry::Registry;
use monitor_agent::transport::{InProcessTransport, Transport};
use monitor_agent::types::{ConstrainedKind, Task};
use serde_json::json;
use std::collections::HashMap;

struct SimExec;
impl LocalExecutor for SimExec {
    fn collect_overview(&self) -> Result<serde_json::Value, String> {
        Ok(json!({"cpu": 10.0 + (rand() % 30) as f64, "mem": 40.0, "procs": 180}))
    }
    fn read_process(&self, pid: i32) -> Result<serde_json::Value, String> {
        Ok(json!({"pid": pid, "comm": "sleep"}))
    }
    fn nice_lower(&self, pid: i32, value: i32) -> Result<serde_json::Value, String> {
        Ok(json!({"pid": pid, "nice": value}))
    }
}

// 伪随机（无外部依赖）
fn rand() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static S: AtomicU64 = AtomicU64::new(88172645463325252);
    let mut x = S.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    S.store(x, Ordering::Relaxed);
    x % 100
}

#[test]
fn twenty_host_simulation() {
    let mut registry = Registry::default();
    let mut transport = InProcessTransport::default();
    let mut agents: HashMap<String, AgentCore> = HashMap::new();
    let exec = SimExec;

    // 1. 注册 20 台（指纹=规范化主机串;真实部署为客户端证书 SHA256,
    //    InProcessTransport 的信箱键即规范化主机串,二者一致）
    for i in 0..20 {
        let host = format!("user@host-{i:02}");
        let fp = InProcessTransport::canonical_target(&host).unwrap();
        let labels: Vec<&str> = if i % 2 == 0 { vec!["edge", "x86"] } else { vec!["edge", "arm"] };
        registry.register(&fp, &labels);
        agents.insert(fp.clone(), AgentCore::new(&fp, LocalPolicy::default()));
    }
    assert_eq!(registry.hosts().len(), 20);

    // 2. 心跳全部有效
    for a in agents.values_mut() {
        let (fp, _ts) = a.heartbeat();
        assert!(registry.authenticate(&fp).is_ok());
    }

    // 3. 下发采集任务到全部 20 台,逐台执行并回执
    let mut receipts = 0;
    for i in 0..20 {
        let host = format!("user@host-{i:02}");
        transport.send(&host, Task::CollectOverview).unwrap();
    }
    for i in 0..20 {
        let fp = format!("user@host-{i:02}");
        let inbox = transport.recv(&fp);
        assert_eq!(inbox.len(), 1, "每台恰好一个任务");
        let a = agents.get_mut(&fp).unwrap();
        for (id, task) in inbox {
            let r = a.handle(&registry, id, &task, &exec, false).unwrap();
            assert!(r.ok);
            receipts += 1;
        }
    }
    assert_eq!(receipts, 20);

    // 4. 受限控制:nice 5 全部成功;nice 99 超出本地策略全部拒绝
    for i in 0..20 {
        let host = format!("user@host-{i:02}");
        transport.send(&host, Task::ConstrainedControl { kind: ConstrainedKind::NiceLowerPriority { value: 5 }, pid: 4242 }).unwrap();
    }
    for i in 0..20 {
        let fp = format!("user@host-{i:02}");
        for (id, task) in transport.recv(&fp) {
            let a = agents.get_mut(&fp).unwrap();
            let r = a.handle(&registry, id, &task, &exec, false).unwrap();
            assert!(r.ok, "nice 5 应在本地策略内：{}", r.payload);
        }
    }
    transport.send("user@host-00", Task::ConstrainedControl { kind: ConstrainedKind::NiceLowerPriority { value: 99 }, pid: 4242 }).unwrap();
    for (id, task) in transport.recv("user@host-00") {
        let a = agents.get_mut("user@host-00").unwrap();
        let r = a.handle(&registry, id, &task, &exec, false).unwrap();
        assert!(!r.ok, "nice 99 超出策略必须拒绝");
    }

    // 5. 控制端离线：任务入本地队列而非丢失
    transport.send("user@host-03", Task::CollectOverview).unwrap();
    for (id, task) in transport.recv("user@host-03") {
        let a = agents.get_mut("user@host-03").unwrap();
        let r = a.handle(&registry, id, &task, &exec, true);
        assert!(r.is_none(), "离线时任务排队");
    }
    assert_eq!(agents.get("user@host-03").unwrap().offline_pending(), 1);
    let drained = agents.get_mut("user@host-03").unwrap().drain_offline_queue(&exec);
    assert_eq!(drained.len(), 1);
    assert!(drained[0].ok);

    // 6. 吊销一台:立即拒绝任何任务(其它 19 台不受影响)
    registry.revoke("user@host-07");
    transport.send("user@host-07", Task::CollectOverview).unwrap();
    for (id, task) in transport.recv("user@host-07") {
        let a = agents.get_mut("user@host-07").unwrap();
        let r = a.handle(&registry, id, &task, &exec, false).unwrap();
        assert_eq!(r.payload["error"], "agent_revoked", "吊销即时生效");
    }
    transport.send("user@host-08", Task::CollectOverview).unwrap();
    for (id, task) in transport.recv("user@host-08") {
        let a = agents.get_mut("user@host-08").unwrap();
        let r = a.handle(&registry, id, &task, &exec, false).unwrap();
        assert!(r.ok, "未吊销主机正常");
    }

    // 7. 类型封闭:无 shell 变体(编译期保证);审计面无 shell 字段
    let audit = Task::CollectOverview.audit_json(1);
    assert!(audit.get("shell").is_none());
}
