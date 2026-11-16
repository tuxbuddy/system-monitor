//! monitor-core：领域类型与纯解析层。
//! 不依赖 Linux 系统调用面（仅 fs 读取与 libc 少量常量），跨平台可测。

pub mod cgparse;
pub mod config;
pub mod fsutil;
pub mod mcppolicy;
pub mod psi;
pub mod schedstate;
pub mod sshtarget;
