//! Snapshot restore integration for the host agent.
//!
//! Wires together the restore orchestrator, executor, COW engine,
//! guest-agent communication, and lifecycle telemetry to provide
//! a complete snapshot restore flow.

use std::sync::Arc;
use std::time::Instant;

use capsule_core::{
    OperationId, RuntimeType, SandboxError, SandboxId, SnapshotId,
    snapshot::{
        BlobLocator, RestoreExecutor, RestoreOrchestrator, RestoreOutcome, RestorePhase,
        SnapshotRepository,
        cow::CowWorkspaceManager,
        error::SnapshotError,
        shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape},
    },
};
use capsule_guest_protocol::operational_v1::resume_notify_response;
use capsule_guest_protocol::{GuestSession, HandshakeConfig};

/// Host capability parameters needed to validate snapshot compatibility.
///
/// Populated from the host-agent's actual runtime state (adapter metadata,
/// host capacity, detected CPU architecture). These values are compared
/// against the snapshot's recorded capabilities during restore validation.
#[derive(Debug, Clone)]
pub struct RestoreHostParams {
    /// The backend expected to run the restored sandbox.
    pub backend: BackendRecord,
    /// Host CPU architecture and features.
    pub cpu: CpuShape,
    /// Host memory available for the restored sandbox.
    pub memory: MemoryShape,
    /// Host device model.
    pub device: DeviceModel,
    /// Runtime type selected for the sandbox.
    pub runtime: RuntimeType,
}

impl RestoreHostParams {
    /// Builds params for a Firecracker host with the given memory, vCPU,
    /// backend metadata, and CPU architecture.
    ///
    /// The machine type defaults to `"q35"` (Intel Q35 chipset), which is
    /// the standard for Firecracker and QEMU x86_64 guests. Set
    /// `machine_type` to `"virt"` for aarch64 or `"microvm"` for the
    /// Firecracker-specific machine profile if the guest image declares it.
    ///
    /// CPU architecture is detected from [`std::env::consts::ARCH`].
    pub fn for_firecracker(
        memory_mb: u64,
        vcpus: u32,
        backend_version: &str,
        protocol_version: &str,
        guest_agent_version: &str,
    ) -> Self {
        let arch = Self::detect_host_arch();
        // Firecracker x86_64 uses q35; aarch64 uses virt.
        let machine_type = match arch {
            "aarch64" => "virt",
            _ => "q35",
        };
        Self {
            backend: BackendRecord {
                backend_type: "firecracker".into(),
                backend_version: backend_version.into(),
                protocol_version: protocol_version.into(),
                guest_agent_version: Some(guest_agent_version.into()),
            },
            cpu: CpuShape::new(arch),
            memory: MemoryShape { memory_mb, vcpus },
            device: DeviceModel::new(machine_type),
            runtime: RuntimeType::Firecracker,
        }
    }

    /// Detects the host CPU architecture as a string suitable for
    /// [`CpuShape`] compatibility checks.
    fn detect_host_arch() -> &'static str {
        // `std::env::consts::ARCH` gives the Rust target triple's
        // architecture (e.g. "x86_64", "aarch64"). This is the
        // compatibility dimension that snapshot metadata records.
        std::env::consts::ARCH
    }
}

/// Executes a complete sandbox restore from a snapshot.
///
/// ## Flow
///
/// 1. Validate metadata compatibility against host capabilities
/// 2. Resolve blob references
/// 3. Verify blob integrity
/// 4. Create COW workspace from resolved blobs
/// 5. Reconnect to guest agent
/// 6. Send ResumeNotify
/// 7. Return outcome with diagnostics
///
/// ## Memory restore
///
/// This function delegates filesystem-only restore (base snapshots).
/// Memory profile restores are handled by the caller
/// ([`super::HostAgent::restore_from_snapshot`]) which:
/// 1. Calls [`RestoreOrchestrator::prepare_restore`] with `requires_memory: false`
///    to load metadata and resolve all blobs (including memory segments).
/// 2. Detects the memory profile via [`SnapshotProfile::preserves_memory`].
/// 3. Calls [`RestoreExecutor::execute_memory_restore`] directly via the
///    backend adapter (not through this function).
/// 4. Enforces stricter ResumeNotify acceptance (memory restore fails if the
///    guest rejects).
///
/// This split exists because memory restore couples to the runtime backend
/// lifecycle (pre-boot VM state, device model attachment) which the base
/// filesystem restore path does not own.
///
/// ## Error handling
///
/// Each phase failure produces a typed [`RestoreOutcome`] identifying
/// which phase failed and why. The caller decides whether to retry,
/// surface an error, or initiate partial cleanup.
#[expect(
    clippy::too_many_arguments,
    reason = "restore orchestrates many subsystems; use RestoreHostParams for host caps"
)]
pub async fn restore_sandbox_from_snapshot(
    snapshot_id: SnapshotId,
    sandbox_id: SandboxId,
    operation_id: OperationId,
    host_params: &RestoreHostParams,
    repository: Arc<dyn SnapshotRepository>,
    blob_locator: Arc<dyn BlobLocator>,
    cow_engine: Arc<dyn CowWorkspaceManager>,
    guest_addr: std::net::SocketAddr,
    policy_epoch: u64,
    snapshot_taken_at: &str,
    _agent_name: &str,
) -> RestoreOutcome {
    let started = Instant::now();

    let ctx = capsule_core::snapshot::RestoreContext {
        snapshot_id: snapshot_id.clone(),
        sandbox_id: sandbox_id.clone(),
        operation_id: operation_id.clone(),
        host_backend: host_params.backend.clone(),
        host_cpu: host_params.cpu.clone(),
        host_memory: host_params.memory,
        host_device: host_params.device.clone(),
        host_runtime: host_params.runtime,
        requires_memory: false,
        current_policy_epoch: policy_epoch,
        production_mode: true,
    };

    let orchestrator = RestoreOrchestrator::new(repository, blob_locator);

    // Phase 1–3: Validate, resolve, verify integrity.
    let (metadata, blob_set) = match orchestrator.prepare_restore(&ctx).await {
        Ok(result) => result,
        Err(e) => {
            return RestoreExecutor::phase_failure_outcome(
                RestorePhase::Validation,
                &e.to_string(),
                None,
                started,
            );
        }
    };

    // Phase 4: Execute filesystem restore.
    let fs_outcome = match RestoreExecutor::execute_filesystem_restore(
        &metadata,
        &blob_set,
        &*cow_engine,
        &sandbox_id,
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            return RestoreExecutor::phase_failure_outcome(
                RestorePhase::FilesystemRestore,
                &e.to_string(),
                Some(&blob_set),
                started,
            );
        }
    };

    // Phase 5: Reconnect to the guest agent with a bounded retry. A cold
    // restore (especially after host migration) may leave the guest agent
    // not-yet-listening; transient transport failures warrant short
    // re-attempts while terminal handshake violations fail immediately.
    const CONNECT_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    const CONNECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
    const CONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

    let handshake_config = HandshakeConfig {
        sandbox_id: sandbox_id.to_string(),
        image_id: String::new(),
        image_digest: String::new(),
        host_agent_version: env!("CARGO_PKG_VERSION").into(),
        host_capabilities: vec![
            "exec".into(),
            "file".into(),
            "mount".into(),
            "stats".into(),
            "health".into(),
            "shutdown".into(),
        ],
        transport_addr: guest_addr,
        timeout: CONNECT_ATTEMPT_TIMEOUT,
        policy_epoch,
    };

    let connect_deadline = Instant::now() + CONNECT_BUDGET;
    let session = loop {
        match GuestSession::connect_tcp(&handshake_config).await {
            Ok(session) => break Some(session),
            Err(e) => {
                let handshake_retryable = matches!(
                    &e,
                    capsule_guest_protocol::SessionError::Handshake(h) if h.is_retryable()
                );
                if !handshake_retryable || Instant::now() >= connect_deadline {
                    tracing::warn!(
                        sandbox_id = %sandbox_id,
                        snapshot_id = %snapshot_id,
                        error_kind = e.kind(),
                        error = %e,
                        "failed to establish guest session for resume notify"
                    );
                    break None;
                }
                tokio::time::sleep(CONNECT_BACKOFF).await;
            }
        }
    };

    let snapshot_ts = parse_snapshot_time(snapshot_taken_at);

    // Phase 6: The bootstrap handshake doubles as the readiness proof; send
    // ResumeNotify on the established session.
    let guest_notified = match session {
        Some(mut session) => {
            match session
                .resume_notify(
                    sandbox_id.as_str(),
                    policy_epoch,
                    snapshot_id.as_str(),
                    snapshot_ts,
                    operation_id.as_str(),
                )
                .await
            {
                Ok(response) => match response.result {
                    Some(resume_notify_response::Result::Accepted(true)) => {
                        tracing::info!(
                            sandbox_id = %sandbox_id,
                            snapshot_id = %snapshot_id,
                            "guest accepted resume notification"
                        );
                        true
                    }
                    Some(resume_notify_response::Result::Error(outcome)) => {
                        let detail = outcome
                            .status
                            .map(|s| format!("{s:?}"))
                            .unwrap_or_else(|| "unknown outcome".into());
                        tracing::warn!(
                            sandbox_id = %sandbox_id,
                            snapshot_id = %snapshot_id,
                            error = %detail,
                            "guest rejected resume notification"
                        );
                        return RestoreExecutor::phase_failure_outcome(
                            RestorePhase::ResumeNotify,
                            &format!("guest rejected resume: {detail}"),
                            Some(&blob_set),
                            started,
                        );
                    }
                    Some(resume_notify_response::Result::Accepted(false)) => {
                        tracing::warn!(
                            sandbox_id = %sandbox_id,
                            snapshot_id = %snapshot_id,
                            "guest declined resume notification"
                        );
                        false
                    }
                    None => {
                        tracing::warn!(
                            sandbox_id = %sandbox_id,
                            snapshot_id = %snapshot_id,
                            "resume notify response missing result"
                        );
                        false
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        sandbox_id = %sandbox_id,
                        snapshot_id = %snapshot_id,
                        error_kind = e.kind(),
                        error = %e,
                        "failed to send resume notify - guest may not be reachable yet"
                    );
                    false
                }
            }
        }
        None => false,
    };

    let latency_ms = started.elapsed().as_millis() as u64;
    tracing::info!(
        sandbox_id = %sandbox_id,
        snapshot_id = %snapshot_id,
        workspace_id = %fs_outcome.workspace_id,
        layers_restored = %fs_outcome.layers_restored,
        guest_notified = %guest_notified,
        latency_ms = %latency_ms,
        "snapshot restore completed"
    );

    RestoreOutcome {
        success: true,
        reason: "restore completed successfully".into(),
        latency_ms,
        blobs_resolved: !blob_set.is_empty(),
        guest_notified,
        blob_set: Some(blob_set),
        memory_restored: false,
    }
}

/// Parses an ISO-8601 / RFC-3339 timestamp string into a [`std::time::SystemTime`].
///
/// Returns `None` when the string is empty or unparseable so the guest
/// receives no snapshot timestamp rather than a bogus one.
fn parse_snapshot_time(s: &str) -> Option<std::time::SystemTime> {
    if s.trim().is_empty() {
        return None;
    }
    let odt =
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    let secs = odt.unix_timestamp();
    let nanos = odt.nanosecond();
    if secs >= 0 {
        Some(std::time::UNIX_EPOCH + std::time::Duration::new(secs as u64, nanos))
    } else {
        std::time::UNIX_EPOCH.checked_sub(std::time::Duration::new((-secs) as u64, nanos))
    }
}

/// Converts a [`SnapshotError`] to a host-agent [`SandboxError`].
///
/// Maps snapshot-specific errors to their closest host-agent equivalents
/// so the caller can use a unified error type.
pub fn snapshot_to_sandbox_error(err: &SnapshotError) -> SandboxError {
    match err {
        SnapshotError::SnapshotNotFound { id } => {
            SandboxError::SandboxNotFound(format!("snapshot not found: {id}"))
        }
        SnapshotError::SnapshotNotReady { id } => {
            SandboxError::NotReady(format!("snapshot not ready: {id}"))
        }
        SnapshotError::BlobMissing { blob_ref } => {
            SandboxError::SandboxNotFound(format!("blob missing: {blob_ref}"))
        }
        SnapshotError::BlobIntegrityMismatch {
            blob_ref,
            expected,
            actual,
        } => SandboxError::Other(format!(
            "blob integrity mismatch for {blob_ref}: expected {expected}, got {actual}"
        )),
        SnapshotError::BackendIncompatible { .. }
        | SnapshotError::CpuIncompatible { .. }
        | SnapshotError::ResourceShapeIncompatible { .. } => {
            SandboxError::NotReady(err.to_string())
        }
        SnapshotError::PartialRestoreCleanup { reason } => {
            SandboxError::Conflict(format!("partial restore cleanup required: {reason}"))
        }
        _ => SandboxError::Other(err.to_string()),
    }
}
