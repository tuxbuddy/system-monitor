//! monitor-remote：SSH 远端采集与控制。

pub mod remote;
pub use remote::{ExecLimits, ExecOutput, ssh_exec};
pub use remote::ProbeScan;
pub use remote::RemoteError;
pub use remote::SshTarget;
pub use remote::{probe_exchange, probe_scan};
