//! monitor-app：应用服务层与前端（MCP / TUI / GUI 共用）。

pub mod diagnose;
pub mod mcp;
pub mod metrics;
pub mod probe_source;
pub mod scheduler;
pub mod service;
pub mod tui;
#[cfg(feature = "gui")]
pub mod app;
#[cfg(feature = "gui")]
pub mod theme;
