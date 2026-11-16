# 受管 Agent PoC 报告（#29）

## 范围与诚实边界

本 PR 交付 Agent **核心**（类型化任务、本地策略门、吊销、离线队列）+ 20 台
模拟主机的**进程内仿真**。真实网络传输（mTLS 双向认证/证书轮换）为
`Transport` trait 的接入点——身份模型已按证书指纹设计（吊销表按指纹即时
拒绝），rustls/openssl 传输是下一步,不在本 PoC 内。

## 验收对账

| 验收项 | 状态 | 实现 |
| --- | --- | --- |
| 10–20 台模拟主机注册/采集/任务下发 | ✅ | `tests/poc_simulation.rs`:20 台注册→心跳→下发→回执 |
| Agent 无法执行任意 shell | ✅ | `Task` 为封闭枚举（编译期保证）；审计面无 shell 字段 |
| 证书吊销后立即失效 | ✅ | `Registry::revoke` + 每任务前 `authenticate`；仿真验证吊销主机拒收、其它正常 |
| 控制端离线继续本地工作并排队 | ✅ | `handle(..., control_offline=true)` 入队；恢复后 `drain_offline_queue` 补跑 |
| 本地策略优先 | ✅ | `LocalPolicy`：只读 Agent / nice 上限；越权拒绝在 Agent 侧，控制端无法越过 |
| 单机模式零依赖 | ✅ | 依赖方向：单机主程序不经 monitor-agent（workspace 强制） |

## mTLS 接入点（下一步）

```rust
impl Transport for TlsTransport { /* rustls 双向认证;recv 前 Registry::authenticate(指纹) */ }
```
证书轮换 = 新指纹重新注册 + 旧指纹 revoke（已实现,即时生效）。

## 资源与吞吐观察

仿真内 20 台×3 轮任务在亚毫秒级完成（进程内调用）；真实网络的吞吐/延迟
基线待 mTLS 传输接入后以同仿真脚本回放测量。
