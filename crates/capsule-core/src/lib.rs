//! Shared contracts and data types used by the API, host agent, and runtimes.

pub mod admission;
pub mod audit;
pub mod availability;
pub mod backend_selection;
pub mod capacity;
pub mod cell_scheduler;
pub mod cgroups;
pub mod cost_model;
pub mod cpu_isolation;
pub mod crypto;
pub mod error;
pub mod event_bus;
pub mod fs_retry;
pub mod host_quarantine;
pub mod identity;
pub mod image_cache;
pub mod lease_token;
pub mod leases;
pub mod metadata;
pub mod metrics;
pub mod mount;
pub mod placement_engine;
pub mod policy;
pub mod quota;
pub mod restore_capacity;
pub mod runtime;
pub mod sandbox_facade;
pub mod scheduler;
pub mod secrets;
pub mod snapshot;
pub mod tenant;
pub mod types;
pub mod workspace;

pub use admission::*;
pub use audit::*;
pub use availability::*;
pub use backend_selection::*;
pub use capacity::*;
pub use cell_scheduler::*;
pub use cost_model::*;
pub use error::{Result, SandboxError};
pub use event_bus::*;
pub use fs_retry::{
    TRANSIENT_FS_BASE_DELAY, TRANSIENT_FS_MAX_ATTEMPTS, TRANSIENT_FS_MAX_DELAY,
    TransientFsRetryPolicy, is_transient_fs_error, retry_transient_fs_op,
    retry_transient_fs_op_with,
};
pub use host_quarantine::*;
pub use identity::*;
pub use image_cache::*;
pub use lease_token::*;
pub use leases::*;
pub use metadata::*;
pub use metrics::CORE_METRICS;
pub use placement_engine::{PlacementBackpressure, PlacementOutcome, place};
pub use policy::*;
pub use quota::*;
pub use restore_capacity::*;
pub use runtime::*;
pub use sandbox_facade::*;
pub use scheduler::*;
pub use snapshot::*;
pub use tenant::*;
pub use types::*;

#[cfg(any(test, feature = "mock-backend"))]
pub mod mock;
