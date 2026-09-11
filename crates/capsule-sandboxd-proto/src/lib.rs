//! Generated protobuf and gRPC bindings for host-agent to sandboxd control.
//!
//! # Schema
//!
//! - [`v1`] (`capsule.sandboxd.v1`) — sole `Sandboxd` service (Interface 1)
//!
//! # Status mapping
//!
//! [`status`] maps outcome wire strings and supervisor error classes to
//! [`tonic::Code`] without depending on the `capsule-sandboxd` crate.

#![expect(
    clippy::large_enum_variant,
    reason = "protobuf-generated enums are intentionally sized for the wire format"
)]

pub mod status;

/// Generated types and `Sandboxd` client/server for `capsule.sandboxd.v1`.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/capsule.sandboxd.v1.rs"));
}

pub use status::{
    METADATA_TOKEN_KEY, SupervisorErrorClass, operation_kind, outcome_reason, outcome_status,
    outcome_status_to_code, outcome_to_code, status_from_outcome_fields,
};
