//! Linux cgroup v2 helpers for applying sandbox resource limits.
//!
//! The implementation lives in `capsule-core` so both host-agent and
//! sandboxd share one cgroup management path.

pub use capsule_core::cgroups::*;
