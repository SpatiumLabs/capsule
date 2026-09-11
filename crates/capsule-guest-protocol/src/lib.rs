//! Generated protobuf and gRPC bindings for the Capsule host-guest
//! control protocol.
//!
//! # Schema packages
//!
//! - [`capsule::guest::bootstrap::v1`] — pre-negotiation handshake
//!   and mutual authentication.
//! - [`capsule::guest::v1`] — operational RPCs (exec, file transfer,
//!   mount, stats, health, quiesce, resume, shutdown).

#![expect(
    clippy::large_enum_variant,
    reason = "protobuf-generated enums are intentionally sized for the wire format"
)]

pub mod exec;
pub mod framed;
pub mod handshake;
pub mod session;

pub mod capsule {
    pub mod guest {
        pub mod bootstrap {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/capsule.guest.bootstrap.v1.rs"));
            }
        }
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/capsule.guest.v1.rs"));
        }
    }
}

/// Convenience re-export for bootstrap types (capsule::guest::bootstrap::v1).
pub use capsule::guest::bootstrap::v1 as bootstrap_v1;

/// Convenience re-export for operational types (capsule::guest::v1).
pub use capsule::guest::v1 as operational_v1;

// Primary API surface. Consumers import these from the crate root; do not
// reach into `session::` / `handshake::` / `framed::` module paths from
// other crates.
pub use framed::{FramedConnection, TransportStream};
pub use handshake::{
    HandshakeConfig, HandshakeError, HandshakeOutcome, compute_guest_proof,
    perform_handshake_exchange,
};
pub use session::{ExecResult, GetFileResult, GuestSession, InjectSecretsResult, SessionError};
