//! Typed snapshot errors.
//!
//! Per ADR-0007, compatibility failures must be typed and identify the
//! mismatched dimension without exposing secret metadata.

use thiserror::Error;

/// Errors related to snapshot operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SnapshotError {
    /// The snapshot is not in `Ready` state and cannot be restored.
    #[error("snapshot not ready: {id}")]
    SnapshotNotReady { id: String },

    /// The snapshot has been revoked and is permanently unavailable.
    #[error("snapshot revoked: {id}")]
    SnapshotRevoked { id: String },

    /// Tenant mismatch between snapshot owner and restore request.
    #[error(
        "tenant mismatch: snapshot {snapshot_id} owned by {snapshot_tenant}, request by {request_tenant}"
    )]
    TenantMismatch {
        snapshot_id: String,
        snapshot_tenant: String,
        request_tenant: String,
    },

    /// Integrity check failed: digest mismatch.
    #[error("integrity failed: expected {expected}, got {actual}")]
    IntegrityFailed { expected: String, actual: String },

    /// Encryption key is unavailable for this snapshot.
    #[error("key unavailable for snapshot {id}")]
    KeyUnavailable { id: String },

    /// Backend family mismatch (e.g., Firecracker snapshot on QEMU host).
    #[error("backend incompatible: snapshot uses {snapshot_backend}, host provides {host_backend}")]
    BackendIncompatible {
        snapshot_backend: String,
        host_backend: String,
    },

    /// Backend version mismatch.
    #[error("runtime version incompatible: snapshot {snapshot_version}, host {host_version}")]
    RuntimeVersionIncompatible {
        snapshot_version: String,
        host_version: String,
    },

    /// CPU architecture or feature mismatch.
    #[error("cpu incompatible: snapshot requires {required}, host provides {available}")]
    CpuIncompatible { required: String, available: String },

    /// Device model mismatch (e.g., different virtio version).
    #[error("device model incompatible: snapshot {snapshot_model}, host {host_model}")]
    DeviceModelIncompatible {
        snapshot_model: String,
        host_model: String,
    },

    /// Image digest mismatch.
    #[error("image incompatible: snapshot expects {expected}, host has {actual}")]
    ImageIncompatible { expected: String, actual: String },

    /// Guest protocol incompatibility.
    #[error("protocol incompatible: snapshot requires {required}, host supports {available}")]
    ProtocolIncompatible { required: String, available: String },

    /// Resource shape mismatch (vCPU, memory, workspace size).
    #[error(
        "resource shape incompatible: {dimension} snapshot={snapshot_value}, host={host_value}"
    )]
    ResourceShapeIncompatible {
        dimension: String,
        snapshot_value: String,
        host_value: String,
    },

    /// Policy incompatibility: the current policy does not allow this restore.
    #[error("policy incompatible: {reason}")]
    PolicyIncompatible { reason: String },

    /// Excluded state validation failed: prohibited state is still present.
    #[error("excluded state invalid: {reason}")]
    ExcludedStateInvalid { reason: String },

    /// Lineage is invalid (e.g., cycle detected, missing parent).
    #[error("lineage invalid: {reason}")]
    LineageInvalid { reason: String },

    /// Schema version is unsupported.
    #[error("unsupported schema version: {version}")]
    UnsupportedSchemaVersion { version: u32 },

    /// Snapshot not found.
    #[error("snapshot not found: {id}")]
    SnapshotNotFound { id: String },

    /// Snapshot already exists (idempotent creation conflict).
    #[error("snapshot already exists: {id}")]
    SnapshotAlreadyExists { id: String },

    /// Operation conflict: another operation is in progress.
    ///
    /// Also used pragmatically for I/O and other errors in filesystem
    /// paths where the failure prevents the operation from completing.
    /// In these cases the original `io::Error` is embedded in `reason`
    /// as a formatted string. This is a deliberate trade-off: it avoids
    /// propagating `io::Error` into the public error type (which would
    /// couple callers to OS-level error kinds) at the cost of losing
    /// structured programmatic access to the root cause. If richer
    /// error diagnostics become necessary, add an `#[source]` field or
    /// more specific variants (e.g., `FilesystemError { path: String,
    /// detail: String }`).
    #[error("snapshot operation conflict: {reason}")]
    OperationConflict { reason: String },

    /// Restore failed due to incomplete or missing blob data.
    #[error("blob missing for restore: {blob_ref}")]
    BlobMissing { blob_ref: String },

    /// Blob integrity verification failed during restore.
    #[error("blob integrity mismatch: {blob_ref} expected {expected} got {actual}")]
    BlobIntegrityMismatch {
        blob_ref: String,
        expected: String,
        actual: String,
    },

    /// Guest-agent resume notification failed or was rejected.
    #[error("resume notification failed: snapshot {snapshot_id}, reason: {reason}")]
    ResumeNotifyFailed { snapshot_id: String, reason: String },

    /// Guest-agent reconnect failed after restore.
    #[error("guest-agent reconnect failed after restore: {reason}")]
    GuestReconnectFailed { reason: String },

    /// Post-restore validation failed.
    #[error("post-restore validation failed: {reason}")]
    PostRestoreValidationFailed { reason: String },

    /// Partial restore cleanup completed (non-fatal, but restore did not succeed).
    #[error("partial restore cleanup: blobs staged but not fully committed, reason: {reason}")]
    PartialRestoreCleanup { reason: String },

    /// Blob store is unavailable.
    #[error("blob store unavailable: {reason}")]
    BlobStoreUnavailable { reason: String },

    /// Credential material was detected in a snapshot artifact.
    #[error("credential material detected in snapshot: {reason}")]
    CredentialMaterialDetected { reason: String },

    /// Credential refresh after restore failed.
    #[error("credential refresh failed: snapshot {snapshot_id}, reason: {reason}")]
    CredentialRefreshFailed { snapshot_id: String, reason: String },

    /// Credential fork inheritance was denied by policy.
    #[error("credential fork inheritance denied: {reason}")]
    CredentialForkDenied { reason: String },

    /// Credential exclusion validation failed.
    #[error("credential exclusion invalid: {reason}")]
    CredentialExclusionInvalid { reason: String },

    /// The snapshot was created under a different policy epoch than the current one.
    ///
    /// Restoring a snapshot from a permissive policy epoch into a restrictive one
    /// would bypass policy enforcement. This error prevents cross-epoch restore.
    #[error(
        "policy epoch incompatible: snapshot epoch {snapshot_epoch}, current epoch {current_epoch}"
    )]
    PolicyEpochIncompatible {
        snapshot_epoch: u64,
        current_epoch: u64,
    },

    /// Fork depth exceeds the configured maximum.
    ///
    /// Unlimited fork depth enables genealogical analysis that could reveal
    /// workload patterns across a tenant's sandbox fleet.
    ///
    /// # Security note
    ///
    /// The `Display` message omits `max_depth` to avoid leaking the exact
    /// security control threshold to untrusted callers. Internal log/metric
    /// paths can access `max_depth` programmatically.
    #[error("fork depth exceeded: maximum depth exceeded (actual: {actual_depth})")]
    ForkDepthExceeded {
        /// The maximum allowed fork depth. Not included in Display to avoid
        /// leaking the security control threshold to untrusted callers.
        max_depth: u32,
        /// The actual depth that was attempted.
        actual_depth: u32,
    },

    /// Integrity verification is required for this snapshot but was not satisfied.
    ///
    /// Covers two cases:
    /// 1. Schema version >= 2 requires a `SnapshotIntegrity` block with
    ///    `integrity_required: true` (schema downgrade attack prevention).
    /// 2. Production mode rejects `integrity_required: false` even if the
    ///    metadata claims it is optional (integrity_required is not a security boundary).
    #[error("integrity required for snapshot {snapshot_id}: {reason}")]
    IntegrityRequired { snapshot_id: String, reason: String },
}

/// Result alias for snapshot operations.
pub type SnapshotResult<T> = std::result::Result<T, SnapshotError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_not_ready_display() {
        let err = SnapshotError::SnapshotNotReady {
            id: "snp_01ABC".into(),
        };
        assert!(err.to_string().contains("not ready"));
        assert!(err.to_string().contains("snp_01ABC"));
    }

    #[test]
    fn integrity_failed_display() {
        let err = SnapshotError::IntegrityFailed {
            expected: "abc123".into(),
            actual: "def456".into(),
        };
        assert!(err.to_string().contains("integrity failed"));
        assert!(err.to_string().contains("abc123"));
        assert!(err.to_string().contains("def456"));
    }

    #[test]
    fn backend_incompatible_display() {
        let err = SnapshotError::BackendIncompatible {
            snapshot_backend: "firecracker".into(),
            host_backend: "qemu".into(),
        };
        assert!(err.to_string().contains("backend incompatible"));
        assert!(err.to_string().contains("firecracker"));
        assert!(err.to_string().contains("qemu"));
    }

    #[test]
    fn snapshot_error_partial_eq() {
        let a = SnapshotError::SnapshotNotReady { id: "snp_1".into() };
        let b = SnapshotError::SnapshotNotReady { id: "snp_1".into() };
        assert_eq!(a, b);

        let c = SnapshotError::SnapshotNotReady { id: "snp_2".into() };
        assert_ne!(a, c);
    }

    #[test]
    fn all_error_variants_display_meaningful() {
        let errors = [
            SnapshotError::SnapshotRevoked { id: "snp_x".into() },
            SnapshotError::TenantMismatch {
                snapshot_id: "snp_x".into(),
                snapshot_tenant: "tnt_a".into(),
                request_tenant: "tnt_b".into(),
            },
            SnapshotError::KeyUnavailable { id: "snp_x".into() },
            SnapshotError::CpuIncompatible {
                required: "x86_64-v3".into(),
                available: "x86_64-v2".into(),
            },
            SnapshotError::DeviceModelIncompatible {
                snapshot_model: "virtio-1.2".into(),
                host_model: "virtio-1.1".into(),
            },
            SnapshotError::ImageIncompatible {
                expected: "sha256:abc".into(),
                actual: "sha256:def".into(),
            },
            SnapshotError::ProtocolIncompatible {
                required: ">=2.0".into(),
                available: "1.5".into(),
            },
            SnapshotError::ResourceShapeIncompatible {
                dimension: "memory_mb".into(),
                snapshot_value: "2048".into(),
                host_value: "1024".into(),
            },
            SnapshotError::PolicyIncompatible {
                reason: "weakened isolation floor".into(),
            },
            SnapshotError::ExcludedStateInvalid {
                reason: "secret mount still attached".into(),
            },
            SnapshotError::LineageInvalid {
                reason: "cycle detected".into(),
            },
            SnapshotError::UnsupportedSchemaVersion { version: 99 },
            SnapshotError::SnapshotNotFound { id: "snp_x".into() },
            SnapshotError::SnapshotAlreadyExists { id: "snp_x".into() },
            SnapshotError::OperationConflict {
                reason: "another snapshot in progress".into(),
            },
            SnapshotError::BlobMissing {
                blob_ref: "blob-1".into(),
            },
            SnapshotError::BlobIntegrityMismatch {
                blob_ref: "blob-1".into(),
                expected: "abc".into(),
                actual: "def".into(),
            },
            SnapshotError::ResumeNotifyFailed {
                snapshot_id: "snp_x".into(),
                reason: "session mismatch".into(),
            },
            SnapshotError::GuestReconnectFailed {
                reason: "vsock timeout".into(),
            },
            SnapshotError::PostRestoreValidationFailed {
                reason: "health check failed".into(),
            },
            SnapshotError::PartialRestoreCleanup {
                reason: "blob staging incomplete".into(),
            },
            SnapshotError::BlobStoreUnavailable {
                reason: "connection refused".into(),
            },
            SnapshotError::CredentialMaterialDetected {
                reason: "credential file found in workspace layer".into(),
            },
            SnapshotError::CredentialRefreshFailed {
                snapshot_id: "snp_x".into(),
                reason: "broker unreachable".into(),
            },
            SnapshotError::CredentialForkDenied {
                reason: "fork policy does not permit credential inheritance".into(),
            },
            SnapshotError::CredentialExclusionInvalid {
                reason: "secret mount class not excluded".into(),
            },
            SnapshotError::PolicyEpochIncompatible {
                snapshot_epoch: 1,
                current_epoch: 2,
            },
            SnapshotError::IntegrityRequired {
                snapshot_id: "snp_x".into(),
                reason: "schema version 2 requires integrity block".into(),
            },
            SnapshotError::ForkDepthExceeded {
                max_depth: 10,
                actual_depth: 15,
            },
        ];
        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "error variant should have a message");
        }
    }

    #[test]
    fn fork_depth_exceeded_redacts_max_depth_from_display() {
        let err = SnapshotError::ForkDepthExceeded {
            max_depth: 10,
            actual_depth: 15,
        };
        let display = err.to_string();
        // Display should mention actual depth but NOT the max threshold.
        assert!(
            display.contains("15"),
            "Display should include actual_depth"
        );
        assert!(
            !display.contains("10"),
            "Display should NOT include max_depth (security control threshold)"
        );
        assert!(
            display.contains("depth exceeded"),
            "Display should mention depth exceeded"
        );
        // Fields are still accessible programmatically.
        match err {
            SnapshotError::ForkDepthExceeded {
                max_depth,
                actual_depth,
            } => {
                assert_eq!(max_depth, 10);
                assert_eq!(actual_depth, 15);
            }
            _ => panic!("expected ForkDepthExceeded"),
        }
    }
}
