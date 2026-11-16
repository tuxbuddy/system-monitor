//! 受管 Agent PoC（#29）：**类型化任务**（采集/诊断/受限控制——无任意 shell）、
//! 身份与吊销注册表、心跳与离线队列、本地策略门。
//!
//! 传输层为 trait（[`transport::Transport`]）：进程内实现供仿真测试；
//! mTLS 网络传输为后续接入点（身份模型已按证书指纹设计,吊销即时生效）。
//! 单机模式（system-monitor 主程序）完全不依赖本 crate。

pub mod agent;
pub mod registry;
pub mod transport;
pub mod types;

pub use agent::AgentCore;
pub use registry::Registry;
pub use types::{Task, TaskResult};
