//! system-monitor 共享数据层（库目标）：采集、cgroup、远端、策略、能力。
//! 二进制（GUI/TUI/MCP）与基准测试共同引用本库；
//! 依赖方向单向：bin → lib,lib 内模块只允许 crate:: 内部引用。

#![cfg_attr(not(feature = "gui"), allow(dead_code))]

pub mod actions;
pub mod caps;
pub mod cgroup;
pub mod config;
pub mod fsutil;
pub mod mcp;
pub mod mcppolicy;
pub mod pi;
pub mod platform;
pub mod probe;
pub mod probeclient;
pub mod procstats;
pub mod psi;
pub mod remote;
pub mod schedstate;
pub mod sshtarget;
pub mod tui;
#[cfg(feature = "gui")]
pub mod app;
#[cfg(feature = "gui")]
pub mod scheduler;
#[cfg(feature = "gui")]
pub mod theme;
