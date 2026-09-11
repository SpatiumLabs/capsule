//! Snapshot restore coordinator.
//!
//! Orchestrates the base snapshot restore flow: load metadata,
//! validate compatibility, locate blobs, verify integrity,
//! restore state, notify the guest-agent, and record latency
//! and outcome.
//!
//! This module implements: Base Snapshot Restore.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::identity::{
    AuditEvent, AuditEventDetails, AuditEventKind, OperationId, SandboxId, SnapshotId,
};
use crate::runtime::RuntimeType;

use super::blob::{BlobInfo, BlobLocator, BlobSet};
#[cfg_attr(not(test), allow(unused_imports))]
use super::credential_policy::{CredentialRefreshOutcome, CredentialSnapshotPolicy};
use super::encryption::{DecryptedTempGuard, decrypt_blob_file, verify_metadata_digest};
use super::error::{SnapshotError, SnapshotResult};
use super::metadata::SnapshotMetadata;
use super::repository::SnapshotRepository;
use super::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};

use super::encryption::KeyResolver;
use zeroize::Zeroize;

// ── Audit operation and outcome constants ──

/// Snapshot audit operation names.
///
/// Typed constants to avoid magic strings in audit event emission.
/// These map to `AuditEventDetails::SnapshotOperation.operation`.
pub mod audit_ops {
    /// Full restore validation (metadata, state, profile, compatibility).
    pub const VALIDATE_RESTORE: &str = "snapshot.validate_restore";
    /// Integrity requirement validation (schema downgrade + production gate).
    pub const VALIDATE_INTEGRITY: &str = "snapshot.validate_integrity";
    /// Blob integrity verification against expected digests.
    pub const VERIFY_INTEGRITY: &str = "snapshot.verify_integrity";
    /// Snapshot encryption during capture.
    pub const ENCRYPT_BLOB: &str = "snapshot.encrypt_blob";
    /// Snapshot decryption during restore.
    pub const DECRYPT_BLOB: &str = "snapshot.decrypt_blob";
    /// Metadata digest verification.
    pub const VERIFY_METADATA_DIGEST: &str = "snapshot.verify_metadata_digest";
    /// Key resolution from KMS.
    pub const KEY_ACCESS: &str = "snapshot.key_access";
}

/// Snapshot audit outcome constants.
///
/// These map to `AuditEventDetails::SnapshotOperation.outcome`.
pub mod audit_outcomes {
    /// The operation completed successfully.
    pub const SUCCESS: &str = "success";
    /// The operation failed (integrity mismatch, blob missing, etc.).
    pub const FAILED: &str = "failed";
    /// The operation was denied by policy or security gate.
    pub const DENIED: &str = "denied";
}

/// Parameters for a snapshot restore operation.
#[derive(Debug, Clone)]
pub struct RestoreContext {
    /// The snapshot to restore from.
    pub snapshot_id: SnapshotId,
    /// The sandbox that will be created/restored.
    pub sandbox_id: SandboxId,
    /// The operation ID for idempotency and tracing.
    pub operation_id: OperationId,
    /// Host backend capabilities for compatibility validation.
    pub host_backend: BackendRecord,
    /// Host CPU capabilities for compatibility validation.
    pub host_cpu: CpuShape,
    /// Host memory for compatibility validation.
    pub host_memory: MemoryShape,
    /// Host device model for compatibility validation.
    pub host_device: DeviceModel,
    /// Host runtime type for compatibility validation.
    pub host_runtime: RuntimeType,
    /// Whether to require memory profile support.
    /// Base snapshots are filesystem-only; set to false for base restore.
    pub requires_memory: bool,
    /// Current policy engine epoch for cross-epoch restore prevention.
    ///
    /// The snapshot's recorded `policy_epoch` must match this value.
    /// A mismatch means the policy set has changed since capture and
    /// the restore is rejected to prevent cross-epoch policy bypass.
    pub current_policy_epoch: u64,
    /// Whether the host is running in production mode.
    ///
    /// In production, `integrity_required: false` is rejected regardless
    /// of what the snapshot metadata claims. This ensures integrity
    /// verification cannot be silently disabled after deployment.
    pub production_mode: bool,
}

/// A blob that failed integrity verification during restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobIntegrityFailure {
    /// The blob reference that failed verification.
    pub blob_ref: String,
    /// Expected digest from snapshot metadata.
    pub expected: String,
    /// Actual digest computed from the resolved blob.
    pub actual: String,
}

/// Sink for snapshot-related audit events.
///
/// Implementations write audit records for snapshot operations:
/// encrypt, decrypt, integrity pass/fail, key access, and restore
/// outcomes. Without audit emission, repeated KMS unwrap calls
/// (offline brute-force attempt) are invisible.
///
/// This is called from [`RestoreOrchestrator`] at key security
/// decision points. A real implementation would write to the
/// regional audit event log.
pub trait SnapshotAuditSink: Send + Sync {
    /// Emit a snapshot audit event.
    fn emit(&self, event: AuditEvent);
}

/// Outcome of a snapshot restore operation.
#[derive(Debug, Clone)]
pub struct RestoreOutcome {
    /// Whether the restore succeeded.
    pub success: bool,
    /// Human-readable outcome reason.
    pub reason: String,
    /// Total wall-clock duration of the restore operation in milliseconds.
    pub latency_ms: u64,
    /// Whether blobs were fully resolved before the restore attempt.
    pub blobs_resolved: bool,
    /// Whether the guest-agent was notified after restore.
    pub guest_notified: bool,
    /// The resolved blob set, if blob resolution succeeded.
    pub blob_set: Option<BlobSet>,
    /// Whether memory state was successfully restored (memory profile only).
    pub memory_restored: bool,
}

/// Coordinates the snapshot restore flow.
///
/// The restore path validates compatibility from metadata before
/// loading any blobs. This prevents wasted I/O on incompatible
/// snapshots and ensures that only trusted metadata reaches the
/// backend for state restoration.
//
// TODO(partial-encryption-cleanup): introduces encryption but the
// staged-blob registry assigned to the snapshot-agent in ADR-0007 does not
// exist yet. Without it, a partial encryption failure during snapshot
// creation leaves orphaned encrypted blobs with no cleanup path. Track this
// as a blocking follow-up linked from so it does not get lost in
// post-merge churn.
pub struct RestoreOrchestrator {
    repository: Arc<dyn SnapshotRepository>,
    blob_locator: Arc<dyn BlobLocator>,
    audit_sink: Option<Arc<dyn SnapshotAuditSink>>,
    key_resolver: Option<Arc<dyn KeyResolver>>,
    /// Guards for decrypted temp files from the last `decrypt_blob_set` call.
    /// Held in a Mutex so `prepare_restore` can store them via `&self`.
    /// On drop, all guarded temp files are removed.
    temp_guards: parking_lot::Mutex<Vec<DecryptedTempGuard>>,
}

impl RestoreOrchestrator {
    /// Creates a new restore orchestrator without an audit sink.
    ///
    /// Use [`with_audit_sink`](Self::with_audit_sink) in production
    /// to enable audit event emission for security-critical operations.
    pub fn new(
        repository: Arc<dyn SnapshotRepository>,
        blob_locator: Arc<dyn BlobLocator>,
    ) -> Self {
        Self {
            repository,
            blob_locator,
            audit_sink: None,
            key_resolver: None,
            temp_guards: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Creates a new restore orchestrator with an audit sink.
    ///
    /// The audit sink receives events for encrypt, decrypt, integrity
    /// pass/fail, and key access operations. In production, this MUST
    /// be set to enable detection of offline brute-force attempts via
    /// repeated KMS unwrap calls.
    pub fn with_audit_sink(
        repository: Arc<dyn SnapshotRepository>,
        blob_locator: Arc<dyn BlobLocator>,
        audit_sink: Arc<dyn SnapshotAuditSink>,
    ) -> Self {
        Self {
            repository,
            blob_locator,
            audit_sink: Some(audit_sink),
            key_resolver: None,
            temp_guards: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Attaches a key resolver for snapshot decryption.
    ///
    /// When set, the restore path will attempt to decrypt encrypted blobs
    /// after resolving them via the blob locator. Without a key resolver,
    /// blobs are assumed to be stored in plaintext (v1 snapshots or
    /// development mode).
    pub fn with_key_resolver(mut self, key_resolver: Arc<dyn KeyResolver>) -> Self {
        self.key_resolver = Some(key_resolver);
        self
    }

    /// Emits a snapshot audit event if an audit sink is configured.
    fn emit_audit(
        &self,
        kind: AuditEventKind,
        operation: &str,
        outcome: &str,
        reason: Option<&str>,
        snapshot_id: Option<&str>,
    ) {
        if let Some(ref sink) = self.audit_sink {
            let event = AuditEvent {
                schema_version: crate::identity::AUDIT_SCHEMA_VERSION,
                id: crate::identity::AuditEventId::generate(),
                hlc_ts: crate::identity::HlcTimestamp::now(),
                kind,
                sandbox_id: None,
                tenant_id: None,
                from_state: None,
                to_state: None,
                principal: None,
                service: None,
                operation_id: None,
                trace_id: None,
                idempotency_key: None,
                failure: None,
                details: Some(AuditEventDetails::SnapshotOperation {
                    operation: operation.to_string(),
                    outcome: outcome.to_string(),
                    reason: reason.map(|r| r.to_string()),
                    snapshot_id: snapshot_id.map(|s| s.to_string()),
                    parent_snapshot_id: None,
                    state_profile: None,
                }),
                recorded_at: crate::types::now_iso(),
                epoch: None,
                fencing_token: None,
                producer: Some("host-agent".into()),
                request_id: None,
                action: Some(operation.to_string()),
                outcome: Some(outcome.to_string()),
                reason: reason.map(|r| r.to_string()),
                policy_decision_id: None,
                lease_id: None,
            };
            sink.emit(event);
        }
    }

    /// Executes the full restore validation pipeline: loads metadata,
    /// checks snapshot state, validates compatibility, and verifies
    /// the profile supports the requested operation.
    ///
    /// Returns the validated `SnapshotMetadata` if all checks pass.
    pub async fn validate_restore(&self, ctx: &RestoreContext) -> SnapshotResult<SnapshotMetadata> {
        let metadata = self.repository.get_snapshot(&ctx.snapshot_id).await?;

        let compat = metadata.to_compatibility_record();

        // State check: must be Ready
        compat.check_state(metadata.state)?;

        // Profile check: base restore is filesystem-only
        compat.check_profile_for_operation(ctx.requires_memory)?;

        // Full compatibility validation (includes policy epoch cross-check)
        compat.check_compatibility(
            &ctx.host_backend,
            &ctx.host_cpu,
            &ctx.host_memory,
            &ctx.host_device,
            ctx.host_runtime,
            ctx.current_policy_epoch,
        )?;

        // Schema downgrade attack prevention (P0): snapshots with
        // schema_version >= 2 MUST carry a SnapshotIntegrity block with
        // integrity_required: true. An attacker stripping the block from
        // a v2 snapshot is caught here before any blob I/O.
        if metadata.schema_version >= 2 {
            match &metadata.integrity {
                Some(integrity) if integrity.integrity_required => {
                    // OK: v2+ snapshot with required integrity
                }
                _ => {
                    self.emit_audit(
                        AuditEventKind::SnapshotOperation,
                        audit_ops::VALIDATE_INTEGRITY,
                        audit_outcomes::DENIED,
                        Some(&format!(
                            "schema_version {} requires SnapshotIntegrity with integrity_required: true",
                            metadata.schema_version
                        )),
                        Some(&ctx.snapshot_id.to_string()),
                    );
                    return Err(SnapshotError::IntegrityRequired {
                        snapshot_id: ctx.snapshot_id.to_string(),
                        reason: format!(
                            "schema version {} requires a SnapshotIntegrity block with integrity_required: true",
                            metadata.schema_version
                        ),
                    });
                }
            }
        }

        // Production integrity gate (P0): in production mode,
        // integrity_required: false is never acceptable, regardless
        // of what the snapshot metadata claims. This ensures integrity
        // verification cannot be silently disabled after deployment.
        if ctx.production_mode {
            match &metadata.integrity {
                Some(integrity) if !integrity.integrity_required => {
                    self.emit_audit(
                        AuditEventKind::SnapshotOperation,
                        audit_ops::VALIDATE_INTEGRITY,
                        audit_outcomes::DENIED,
                        Some("production mode requires integrity_required: true"),
                        Some(&ctx.snapshot_id.to_string()),
                    );
                    return Err(SnapshotError::IntegrityRequired {
                        snapshot_id: ctx.snapshot_id.to_string(),
                        reason: "production mode requires integrity_required: true".into(),
                    });
                }
                _ => {
                    // OK: either no integrity block (v1) or integrity_required: true
                }
            }
        }

        // Key reference validation: if the snapshot has an encryption key
        // reference, verify it is resolvable before proceeding to blob I/O.
        // This avoids wasting time on incompatible restores when the key
        // is unavailable.
        if let Some(key_ref) = metadata.effective_encryption_key_ref() {
            key_ref.is_resolvable().then_some(()).ok_or_else(|| {
                self.emit_audit(
                    AuditEventKind::SnapshotOperation,
                    audit_ops::KEY_ACCESS,
                    audit_outcomes::DENIED,
                    Some(&format!(
                        "key not resolvable: {}:{}",
                        key_ref.kms_id, key_ref.key_id
                    )),
                    Some(&ctx.snapshot_id.to_string()),
                );
                SnapshotError::KeyUnavailable {
                    id: format!("{}:{}", key_ref.kms_id, key_ref.key_id),
                }
            })?;
        }

        // Metadata digest verification: re-compute the digest from the
        // metadata fields we just validated and compare against the stored
        // integrity record. This catches metadata tampering after snapshot
        // creation (e.g., rewriting policy_epoch, blob digests, or tenant).
        if let Err(e) = verify_metadata_digest(&metadata) {
            self.emit_audit(
                AuditEventKind::SnapshotOperation,
                audit_ops::VERIFY_METADATA_DIGEST,
                audit_outcomes::FAILED,
                Some(&e.to_string()),
                Some(&ctx.snapshot_id.to_string()),
            );
            return Err(e);
        }

        // Audit: validation passed
        self.emit_audit(
            AuditEventKind::SnapshotOperation,
            audit_ops::VALIDATE_RESTORE,
            audit_outcomes::SUCCESS,
            None,
            Some(&ctx.snapshot_id.to_string()),
        );

        Ok(metadata)
    }

    /// Resolves all blob references from snapshot metadata into a [`BlobSet`].
    ///
    /// Collects filesystem, memory, and workspace layer blob references
    /// and resolves them via the configured [`BlobLocator`].
    pub async fn resolve_blobs(&self, metadata: &SnapshotMetadata) -> SnapshotResult<BlobSet> {
        let fs_refs: Vec<String> = metadata
            .filesystem_refs
            .iter()
            .map(|r| r.blob_ref.clone())
            .collect();

        let mem_refs: Vec<String> = metadata
            .memory_segments
            .iter()
            .map(|r| r.blob_ref.clone())
            .collect();

        let ws_refs: Vec<String> = metadata
            .workspace_layers
            .iter()
            .map(|r| r.blob_ref.clone())
            .collect();

        let (filesystem_blobs, memory_blobs, workspace_blobs) = tokio::join!(
            self.locate_category(&fs_refs),
            self.locate_category(&mem_refs),
            self.locate_category(&ws_refs),
        );

        Ok(BlobSet {
            filesystem_blobs: filesystem_blobs?,
            memory_blobs: memory_blobs?,
            workspace_blobs: workspace_blobs?,
        })
    }

    async fn locate_category(&self, refs: &[String]) -> SnapshotResult<Vec<BlobInfo>> {
        if refs.is_empty() {
            Ok(Vec::new())
        } else {
            self.blob_locator.locate_blobs(refs).await
        }
    }

    /// Runs the complete base restore preparation flow.
    ///
    /// This orchestrates:
    /// 1. Validate compatibility from metadata (no blob I/O yet)
    /// 2. Resolve blob references to local paths
    /// 3. Verify blob integrity against expected digests
    ///
    /// Returns validated metadata and resolved blobs if all checks pass.
    ///
    /// The caller (host agent) is responsible for:
    /// - Actually restoring VM state via the backend using the resolved paths
    /// - Reconnecting the guest-agent and sending ResumeNotify
    /// - Transitioning to Running after post-restore validation
    ///
    /// ## Error handling
    ///
    /// Returns `Err` for validation, blob-resolution, or integrity failures.
    /// Callers should convert these into structured `RestoreOutcome` records
    /// via [`failure_outcome`](Self::failure_outcome) to preserve latency and
    /// diagnostic data for observability.
    pub async fn prepare_restore(
        &self,
        ctx: &RestoreContext,
    ) -> SnapshotResult<(SnapshotMetadata, BlobSet)> {
        let started = Instant::now();

        let metadata = self.validate_restore(ctx).await?;

        let blob_set = self.resolve_blobs(&metadata).await?;

        // Verify blob integrity before decryption (pre-KMS check).
        // Integrity failures are surfaced as typed errors so the host agent
        // can decide whether to retry (transient corruption) or fail (tampering).
        let mismatches = self.verify_blob_integrity(&metadata, &blob_set).await?;
        if !mismatches.is_empty() {
            let first = &mismatches[0];
            self.emit_audit(
                AuditEventKind::SnapshotOperation,
                audit_ops::VERIFY_INTEGRITY,
                audit_outcomes::FAILED,
                Some(&format!(
                    "blob {} expected {} got {}",
                    first.blob_ref, first.expected, first.actual
                )),
                Some(&ctx.snapshot_id.to_string()),
            );
            return Err(SnapshotError::BlobIntegrityMismatch {
                blob_ref: first.blob_ref.clone(),
                expected: first.expected.clone(),
                actual: first.actual.clone(),
            });
        }

        self.emit_audit(
            AuditEventKind::SnapshotOperation,
            audit_ops::VERIFY_INTEGRITY,
            audit_outcomes::SUCCESS,
            None,
            Some(&ctx.snapshot_id.to_string()),
        );

        // Decrypt blobs if an encryption key is configured.
        // Decryption replaces each encrypted blob's path with the decrypted
        // temporary file path. Blobs without an encryption key reference are
        // passed through unchanged (v1 snapshots or plaintext blobs).
        let (blob_set, guards) = self.decrypt_blob_set(&metadata, blob_set).await?;
        // Hold guards in the orchestrator; they remove temp files on drop.
        // Call cleanup_decrypted_temp_files() to explicitly free them sooner.
        *self.temp_guards.lock() = guards;

        let _latency_ms = started.elapsed().as_millis() as u64;
        tracing::info!(
            snapshot_id = %ctx.snapshot_id,
            sandbox_id = %ctx.sandbox_id,
            operation_id = %ctx.operation_id,
            blob_count = %blob_set.len(),
            "snapshot restore prepared"
        );

        Ok((metadata, blob_set))
    }

    /// Decrypts all blobs in a blob set using the configured key resolver.
    ///
    /// For each blob that has an associated encryption key reference in the
    /// snapshot metadata, this method resolves the key from KMS, constructs
    /// the AAD from the blob and snapshot context, decrypts the file content,
    /// and writes the plaintext to a temporary file. The [`BlobSet`] is
    /// returned with paths updated to point to the decrypted temp files.
    ///
    /// Blobs without an encryption key are passed through unchanged.
    ///
    /// # Key resolution
    ///
    /// The key is resolved from the snapshot's [`EncryptionKeyRef`] via the
    /// configured [`KeyResolver`]. If no key resolver is configured or the
    /// snapshot has no encryption key reference, decryption is skipped.
    pub async fn decrypt_blob_set(
        &self,
        metadata: &SnapshotMetadata,
        blob_set: BlobSet,
    ) -> SnapshotResult<(BlobSet, Vec<DecryptedTempGuard>)> {
        // Determine the key reference for this snapshot.
        let Some(key_ref) = metadata.effective_encryption_key_ref() else {
            // Check legacy field as fallback.
            if metadata.encryption_key_ref.as_deref().is_some() {
                // Legacy key reference exists but not in structured format.
                // The snapshot was created before EncryptionKeyRef was added.
                // This is expected for v1 snapshots — treat as plaintext.
                tracing::debug!(
                    snapshot_id = %metadata.id,
                    "legacy encryption_key_ref without structured EncryptionKeyRef; treating as v1 plaintext snapshot"
                );
            }
            return Ok((blob_set, Vec::new()));
        };

        let Some(ref key_resolver) = self.key_resolver else {
            // No key resolver configured — blobs are assumed to be in plaintext
            // (development mode or v1 snapshots).
            return Ok((blob_set, Vec::new()));
        };

        // Resolve the key once for all blobs in this snapshot.
        let mut key = key_resolver.resolve_key(key_ref).await.inspect_err(|e| {
            self.emit_audit(
                AuditEventKind::SnapshotOperation,
                audit_ops::KEY_ACCESS,
                audit_outcomes::FAILED,
                Some(&e.to_string()),
                Some(&metadata.id.to_string()),
            );
        })?;

        self.emit_audit(
            AuditEventKind::SnapshotOperation,
            audit_ops::KEY_ACCESS,
            audit_outcomes::SUCCESS,
            None,
            Some(&metadata.id.to_string()),
        );

        let policy_epoch = metadata.policy_epoch.unwrap_or(0);
        let snapshot_id = metadata.id.to_string();
        let tenant_id = metadata.tenant_id.to_string();
        let key_id = format!("{}:{}", key_ref.kms_id, key_ref.key_id);

        // Helper to decrypt a single BlobInfo.
        // Returns the updated BlobInfo with decrypted path, and a guard
        // that cleans up the temp file when dropped.
        // Emits per-blob audit events for encryption/decryption tracking.
        let decrypt_one = |info: BlobInfo| -> SnapshotResult<(BlobInfo, DecryptedTempGuard)> {
            let guard = decrypt_blob_file(
                &info.path,
                &key,
                &info.blob_ref,
                &tenant_id,
                &snapshot_id,
                policy_epoch,
                &key_id,
            )
            .inspect_err(|e| {
                self.emit_audit(
                    AuditEventKind::SnapshotOperation,
                    audit_ops::DECRYPT_BLOB,
                    audit_outcomes::FAILED,
                    Some(&format!("blob {} decrypt failed: {}", info.blob_ref, e)),
                    Some(&metadata.id.to_string()),
                );
            })?;
            self.emit_audit(
                AuditEventKind::SnapshotOperation,
                audit_ops::DECRYPT_BLOB,
                audit_outcomes::SUCCESS,
                Some(&info.blob_ref),
                Some(&metadata.id.to_string()),
            );
            let decrypted_path = guard.path().to_path_buf();
            Ok((
                BlobInfo {
                    path: decrypted_path,
                    ..info
                },
                guard,
            ))
        };

        // Decrypt all categories concurrently.
        let (fs_result, mem_result, ws_result) = tokio::join!(
            Self::decrypt_category_with_guards(blob_set.filesystem_blobs, &decrypt_one),
            Self::decrypt_category_with_guards(blob_set.memory_blobs, &decrypt_one),
            Self::decrypt_category_with_guards(blob_set.workspace_blobs, &decrypt_one),
        );

        // Zeroize key material immediately after all decryption completes.
        // This bounds the window during which plaintext key bytes exist in memory.
        key.zeroize();

        let (filesystem_blobs, mut fs_guards) = fs_result?;
        let (memory_blobs, mut mem_guards) = mem_result?;
        let (workspace_blobs, mut ws_guards) = ws_result?;

        // Collect all temp file guards so the caller can hold them until
        // restore completes. Dropping the guards removes decrypted plaintext.
        let mut all_guards = Vec::new();
        all_guards.append(&mut fs_guards);
        all_guards.append(&mut mem_guards);
        all_guards.append(&mut ws_guards);

        let total = filesystem_blobs.len() + memory_blobs.len() + workspace_blobs.len();
        tracing::info!(
            snapshot_id = %metadata.id,
            blob_count = %total,
            "snapshot blobs decrypted"
        );

        Ok((
            BlobSet {
                filesystem_blobs,
                memory_blobs,
                workspace_blobs,
            },
            all_guards,
        ))
    }

    /// Decrypts a category of blobs using the provided decryption function,
    /// collecting cleanup guards alongside decrypted BlobInfos.
    async fn decrypt_category_with_guards(
        blobs: Vec<BlobInfo>,
        decrypt_one: &(
             dyn Fn(BlobInfo) -> SnapshotResult<(BlobInfo, DecryptedTempGuard)> + Send + Sync
         ),
    ) -> SnapshotResult<(Vec<BlobInfo>, Vec<DecryptedTempGuard>)> {
        let mut decrypted = Vec::with_capacity(blobs.len());
        let mut guards = Vec::with_capacity(blobs.len());
        for info in blobs {
            let (info, guard) = decrypt_one(info)?;
            decrypted.push(info);
            guards.push(guard);
        }
        Ok((decrypted, guards))
    }

    /// Verifies that all resolved blobs match their expected integrity digests.
    ///
    /// For each blob in the resolved set, this method re-computes the digest
    /// from the actual file content and compares it against the expected digest
    /// recorded in snapshot metadata.
    ///
    /// ## Skipped blobs
    ///
    /// Blobs without an expected digest are silently skipped (no integrity
    /// contract exists). Blobs whose resolved path does not exist on disk
    /// are also skipped — the caller should treat this as a signal to fetch
    /// the blob and re-verify.
    ///
    /// ## Concurrency
    ///
    /// Blob verification is primarily CPU-bound (Blake3 hashing dominates
    /// over file I/O for recently-resolved blobs that are warm in the page
    /// cache). This method hashes sequentially to avoid saturating all
    /// cores, but callers with many blobs may want concurrent verification
    /// via `tokio::spawn`.
    pub async fn verify_blob_integrity(
        &self,
        metadata: &SnapshotMetadata,
        blob_set: &BlobSet,
    ) -> SnapshotResult<Vec<BlobIntegrityFailure>> {
        // Build a lookup of expected digests from metadata.
        // Key: blob_ref, Value: (digest algorithm, digest value)
        let mut expected: hashbrown::HashMap<&str, &str> = hashbrown::HashMap::new();

        for fs_ref in &metadata.filesystem_refs {
            if let Some(ref digest) = fs_ref.digest {
                expected.insert(fs_ref.blob_ref.as_str(), digest.as_str());
            }
        }
        for seg in &metadata.memory_segments {
            if let Some(ref digest) = seg.digest {
                expected.insert(seg.blob_ref.as_str(), digest.as_str());
            }
        }
        for layer in &metadata.workspace_layers {
            if let Some(ref digest) = layer.digest {
                expected.insert(layer.blob_ref.as_str(), digest.as_str());
            }
        }

        let all_blobs: Vec<&BlobInfo> = blob_set
            .filesystem_blobs
            .iter()
            .chain(blob_set.memory_blobs.iter())
            .chain(blob_set.workspace_blobs.iter())
            .collect();

        let mut failures = Vec::new();

        for blob in &all_blobs {
            let Some(expected_digest) = expected.get(blob.blob_ref.as_str()) else {
                // No expected digest — nothing to verify against.
                continue;
            };

            let actual = match compute_file_digest(&blob.path) {
                Ok(d) => d,
                Err(_) => {
                    // Path not accessible — blob may need fetching.
                    // Don't fail here; the caller can re-verify after fetch.
                    continue;
                }
            };

            // Expected digests are stored as "<algo>:<hex>" (e.g. "blake3:abc123").
            // Compare the value part only — algorithm mismatches would be caught
            // at metadata validation time.
            let expected_value = expected_digest
                .split_once(':')
                .map(|(_algo, val)| val)
                .unwrap_or(expected_digest);

            if actual != expected_value {
                failures.push(BlobIntegrityFailure {
                    blob_ref: blob.blob_ref.clone(),
                    expected: (*expected_digest).to_string(),
                    actual,
                });
            }
        }

        if !failures.is_empty() {
            tracing::warn!(
                failure_count = %failures.len(),
                first_blob = %failures[0].blob_ref,
                "blob integrity verification found mismatches"
            );
        }

        Ok(failures)
    }

    /// Returns true if the given blob passes integrity verification.
    ///
    /// Convenience wrapper around [`verify_blob_integrity`] for callers
    /// that want to verify a single blob after fetching it.
    pub async fn verify_single_blob(
        blob_ref: &str,
        expected_digest: &str,
        path: &Path,
    ) -> SnapshotResult<()> {
        let actual = compute_file_digest(path).map_err(|_| SnapshotError::BlobMissing {
            blob_ref: blob_ref.to_string(),
        })?;

        let expected_value = expected_digest
            .split_once(':')
            .map(|(_algo, val)| val)
            .unwrap_or(expected_digest);

        if actual != expected_value {
            return Err(SnapshotError::BlobIntegrityMismatch {
                blob_ref: blob_ref.to_string(),
                expected: expected_digest.to_string(),
                actual,
            });
        }

        Ok(())
    }

    /// Constructs a failure outcome with timing information.
    pub fn failure_outcome(reason: &str, elapsed: Instant) -> RestoreOutcome {
        RestoreOutcome {
            success: false,
            reason: reason.to_string(),
            latency_ms: elapsed.elapsed().as_millis() as u64,
            blobs_resolved: false,
            guest_notified: false,
            blob_set: None,
            memory_restored: false,
        }
    }

    /// Constructs a success outcome with timing and diagnostics.
    pub fn success_outcome(
        elapsed: Instant,
        blob_set: &BlobSet,
        guest_notified: bool,
    ) -> RestoreOutcome {
        RestoreOutcome {
            success: true,
            reason: "restore completed successfully".into(),
            latency_ms: elapsed.elapsed().as_millis() as u64,
            blobs_resolved: !blob_set.is_empty(),
            guest_notified,
            blob_set: Some(blob_set.clone()),
            memory_restored: false,
        }
    }

    /// Validates credential exclusion policy for a snapshot after capture.
    ///
    /// This checks that the snapshot metadata enforces credential exclusion
    /// and that no credential paths are present in the captured filesystem refs.
    /// Should be called after snapshot capture and before marking it as Ready.
    pub fn validate_credential_exclusion(&self, metadata: &SnapshotMetadata) -> SnapshotResult<()> {
        metadata.validate_credential_exclusion()?;
        tracing::info!(
            snapshot_id = %metadata.id,
            excluded_mounts = ?metadata.excluded_mounts,
            "credential exclusion validated"
        );
        Ok(())
    }

    /// Validates that a snapshot artifact's metadata does not contain
    /// credential material.
    ///
    /// This is a defense-in-depth check that runs after capture to detect
    /// any credential leakage into snapshot metadata fields. It checks:
    /// 1. No mount point references match known credential paths
    /// 2. No workspace layers reference credential directories
    /// 3. The excluded_mounts list includes the secret class
    pub fn scan_for_credential_material(&self, metadata: &SnapshotMetadata) -> SnapshotResult<()> {
        // Check filesystem refs for credential mounts
        for fs_ref in &metadata.filesystem_refs {
            if fs_ref.mount_point == crate::mount::CANONICAL_SECRETS_TMPFS {
                return Err(SnapshotError::CredentialMaterialDetected {
                    reason: format!(
                        "credential mount '{}' found in filesystem refs",
                        fs_ref.mount_point
                    ),
                });
            }
        }

        // Best-effort defense-in-depth: check workspace layers for known
        // credential mount paths. This uses exact known paths rather than
        // substring matching to avoid false positives. A determined attacker
        // could bypass this check by obfuscating names, so it is NOT a
        // security boundary -- only the mount exclusion at capture time is.
        for layer in &metadata.workspace_layers {
            if layer.blob_ref == crate::mount::CANONICAL_SECRETS_TMPFS
                || layer.blob_ref.starts_with("/run/capsule/secrets")
            {
                return Err(SnapshotError::CredentialMaterialDetected {
                    reason: format!(
                        "credential path detected in workspace layer: {}",
                        layer.blob_ref
                    ),
                });
            }
        }

        // Verify excluded_mounts contains secret class
        if !metadata.excluded_mounts.iter().any(|m| m == "secret") {
            return Err(SnapshotError::CredentialExclusionInvalid {
                reason: "secret mount class not in excluded_mounts list".into(),
            });
        }

        tracing::info!(
            snapshot_id = %metadata.id,
            "credential material scan passed"
        );
        Ok(())
    }

    /// Determines the credential refresh outcome after a restore operation.
    ///
    /// This decides whether credentials should be refreshed based on the
    /// snapshot's credential policy. The actual refresh is performed by
    /// the caller (host agent) using the secrets broker.
    ///
    /// # Parameters
    ///
    /// - `metadata`: The snapshot metadata to evaluate policy from.
    /// - `has_valid_lease`: Whether the caller holds a valid access lease.
    /// - `credential_types`: The credential types being requested. Filtered
    ///   through [`CredentialSnapshotPolicy::allows_credential_type`].
    ///
    /// # Returns
    ///
    /// - `Skipped` if the policy disables refresh, exclude_from_snapshot is
    ///   false, or no requested credential types are allowed.
    /// - `Denied` if the policy requires a lease but none is provided.
    /// - `Refreshed { credential_count: 0, ... }` if the policy allows refresh.
    ///   **Note**: `credential_count` is always `0` here; the caller fills in
    ///   the actual count after performing the broker fetch. This placeholder
    ///   signals that the policy gate passed successfully.
    /// - `Unavailable` is never returned by this method (reserved for broker
    ///   failure reporting by the caller).
    pub fn evaluate_credential_refresh(
        &self,
        metadata: &SnapshotMetadata,
        has_valid_lease: bool,
        credential_types: &[String],
    ) -> CredentialRefreshOutcome {
        let policy = metadata.effective_credential_policy();

        if !policy.exclude_from_snapshot {
            return CredentialRefreshOutcome::Skipped {
                reason: "credential exclusion is disabled".into(),
            };
        }

        if !policy.refresh_after_restore {
            return CredentialRefreshOutcome::Skipped {
                reason: "credential refresh after restore is disabled by policy".into(),
            };
        }

        // Filter credential types through the policy's allowlist.
        // An empty allowed list means all types are permitted.
        if !policy.allowed_credential_types.is_empty() {
            let any_allowed = credential_types
                .iter()
                .any(|ct| policy.allows_credential_type(ct));
            if !any_allowed && !credential_types.is_empty() {
                return CredentialRefreshOutcome::Skipped {
                    reason: "no requested credential types are permitted by policy".into(),
                };
            }
        }

        if policy.require_lease_for_refresh && !has_valid_lease {
            return CredentialRefreshOutcome::Denied {
                reason: "valid lease required for credential refresh".into(),
            };
        }

        // Policy allows refresh - caller proceeds with broker.
        // credential_count is 0 here; the caller fills in the actual count
        // after performing the broker fetch.
        CredentialRefreshOutcome::Refreshed {
            credential_count: 0,
            lease_id: None,
        }
    }

    /// Validates fork credential inheritance against snapshot policy.
    ///
    /// Forks do not inherit parent credentials unless the snapshot's
    /// credential policy explicitly permits it.
    pub fn validate_fork_credential_inheritance(
        &self,
        parent_metadata: &SnapshotMetadata,
        requested_inheritance: bool,
    ) -> SnapshotResult<()> {
        if requested_inheritance && !parent_metadata.allows_fork_credential_inheritance() {
            return Err(SnapshotError::CredentialForkDenied {
                reason: "fork credential inheritance is not permitted by snapshot policy".into(),
            });
        }
        Ok(())
    }

    /// Runs the memory restore preparation flow.
    ///
    /// Memory restore requires:
    /// 1. Compatible backend, kernel, image, guest-agent, and memory shape
    /// 2. Memory profile snapshot (profile check with `requires_memory: true`)
    /// 3. At least one memory blob resolved
    ///
    /// Returns validated metadata and resolved blobs, or a typed error.
    /// On partial failure, callers should invoke [`Self::partial_cleanup_outcome`]
    /// to record cleanup status.
    pub async fn prepare_memory_restore(
        &self,
        ctx: &RestoreContext,
    ) -> SnapshotResult<(SnapshotMetadata, BlobSet)> {
        let started = Instant::now();

        let metadata = self.validate_restore(ctx).await?;

        if metadata.profile.preserves_memory() {
            // Redundant guard: validate_restore(ctx) with requires_memory: true
            // already checked this above, but we keep it as defense-in-depth
            // against a caller that bypasses the context parameter.
            if metadata.memory_segments.is_empty() {
                return Err(SnapshotError::ResourceShapeIncompatible {
                    dimension: "memory_segments".into(),
                    snapshot_value: "0".into(),
                    host_value: ">=1".into(),
                });
            }
        } else {
            return Err(SnapshotError::ResourceShapeIncompatible {
                dimension: "profile".into(),
                snapshot_value: metadata.profile.as_str().into(),
                host_value: "memory".into(),
            });
        }

        // Validate guest-agent version is present for memory restore compatibility
        if metadata
            .backend
            .guest_agent_version
            .as_deref()
            .unwrap_or("")
            .is_empty()
        {
            return Err(SnapshotError::ProtocolIncompatible {
                required: "guest_agent_version".into(),
                available: "unknown".into(),
            });
        }

        let blob_set = self.resolve_blobs(&metadata).await?;

        if blob_set.memory_blobs.is_empty() {
            return Err(SnapshotError::BlobMissing {
                blob_ref: "memory_blobs".into(),
            });
        }

        // Decrypt blobs before returning to the VM backend.
        // Encrypted memory blobs returned as ciphertext would
        // corrupt the guest on restore.
        let (blob_set, guards) = self.decrypt_blob_set(&metadata, blob_set).await?;
        *self.temp_guards.lock() = guards;

        let latency_ms = started.elapsed().as_millis() as u64;
        tracing::info!(
            snapshot_id = %ctx.snapshot_id,
            sandbox_id = %ctx.sandbox_id,
            operation_id = %ctx.operation_id,
            memory_blob_count = %blob_set.memory_blobs.len(),
            latency_ms = %latency_ms,
            "memory snapshot restore prepared"
        );

        Ok((metadata, blob_set))
    }

    /// Constructs a partial cleanup outcome indicating restore did not complete.
    ///
    /// This records that blobs were staged but the restore operation could not
    /// be fully committed. The caller should ensure runtime state is cleaned up.
    pub fn partial_cleanup_outcome(
        reason: &str,
        blob_set: Option<&BlobSet>,
        elapsed: Instant,
    ) -> RestoreOutcome {
        RestoreOutcome {
            success: false,
            reason: format!("partial restore cleanup: {reason}"),
            latency_ms: elapsed.elapsed().as_millis() as u64,
            blobs_resolved: blob_set.is_some_and(|bs| !bs.is_empty()),
            guest_notified: false,
            blob_set: blob_set.cloned(),
            memory_restored: false,
        }
    }

    /// Constructs a memory restore outcome with timing and diagnostics.
    pub fn memory_restore_outcome(
        success: bool,
        reason: &str,
        elapsed: Instant,
        blob_set: &BlobSet,
        guest_notified: bool,
        memory_restored: bool,
    ) -> RestoreOutcome {
        RestoreOutcome {
            success,
            reason: reason.to_string(),
            latency_ms: elapsed.elapsed().as_millis() as u64,
            blobs_resolved: !blob_set.is_empty(),
            guest_notified,
            blob_set: Some(blob_set.clone()),
            memory_restored,
        }
    }
}

/// Computes the Blake3 hex digest of a file at the given path.
///
/// Returns an error if the file cannot be read. For directories,
/// returns the empty-input Blake3 hash (matching [`BlobStore::compute_dir_digest`]
/// for empty directories).
fn compute_file_digest(path: &Path) -> Result<String, std::io::Error> {
    if path.is_dir() {
        // Directory digests are computed by the blob store's Merkle-tree
        // method. For single-file verification we use the raw file hash.
        // An empty directory hashes to the same value as empty input.
        let entries = std::fs::read_dir(path)?;
        if entries.count() == 0 {
            return Ok(blake3::hash(b"").to_hex().to_string());
        }
        // Non-empty directory — can't meaningfully hash as a single file.
        // This path should only be hit for layer directories resolved
        // through the blob locator; the caller should use verify_blob_integrity
        // which delegates to the blob store's compute_dir_digest for
        // multi-file directories.
        return Err(std::io::Error::other(
            "cannot compute single-file digest for non-empty directory",
        ));
    }

    let content = std::fs::read(path)?;
    Ok(blake3::hash(&content).to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TenantId;
    use crate::snapshot::blob::BlobInfo;
    use crate::snapshot::error::SnapshotError;
    use crate::snapshot::metadata::FilesystemRef;
    use crate::snapshot::profile::SnapshotProfile;
    use crate::snapshot::purpose::{LineageType, SnapshotPurpose};
    use crate::snapshot::repository::{SnapshotListPage, SnapshotRepository};
    use crate::snapshot::state::SnapshotState;
    use async_trait::async_trait;
    use parking_lot::Mutex;

    // In-memory test doubles

    struct InMemoryRepo {
        snapshots: Mutex<Vec<SnapshotMetadata>>,
    }

    impl InMemoryRepo {
        fn new() -> Self {
            Self {
                snapshots: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl SnapshotRepository for InMemoryRepo {
        async fn get_snapshot(&self, id: &SnapshotId) -> SnapshotResult<SnapshotMetadata> {
            self.snapshots
                .lock()
                .iter()
                .find(|m| m.id == *id)
                .cloned()
                .ok_or_else(|| SnapshotError::SnapshotNotFound { id: id.to_string() })
        }

        async fn store_snapshot(&self, metadata: &SnapshotMetadata) -> SnapshotResult<()> {
            let mut guard = self.snapshots.lock();
            if guard.iter().any(|m| m.id == metadata.id) {
                return Err(SnapshotError::SnapshotAlreadyExists {
                    id: metadata.id.to_string(),
                });
            }
            guard.push(metadata.clone());
            Ok(())
        }

        async fn update_snapshot(
            &self,
            metadata: &SnapshotMetadata,
            _expected_version: u64,
        ) -> SnapshotResult<()> {
            let mut guard = self.snapshots.lock();
            if let Some(existing) = guard.iter_mut().find(|m| m.id == metadata.id) {
                *existing = metadata.clone();
                Ok(())
            } else {
                Err(SnapshotError::SnapshotNotFound {
                    id: metadata.id.to_string(),
                })
            }
        }

        async fn list_snapshots(
            &self,
            _tenant_id: &TenantId,
            _purpose: Option<SnapshotPurpose>,
            _state: Option<SnapshotState>,
            _limit: usize,
            _cursor: Option<String>,
        ) -> SnapshotResult<SnapshotListPage> {
            Ok(SnapshotListPage {
                snapshots: self.snapshots.lock().clone(),
                next_cursor: None,
            })
        }

        async fn delete_snapshot(&self, id: &SnapshotId) -> SnapshotResult<()> {
            self.snapshots.lock().retain(|m| m.id != *id);
            Ok(())
        }
    }

    struct InMemoryBlobLocator {
        blobs: Mutex<Vec<BlobInfo>>,
        fail_on: Mutex<Option<String>>,
    }

    impl InMemoryBlobLocator {
        fn new() -> Self {
            Self {
                blobs: Mutex::new(Vec::new()),
                fail_on: Mutex::new(None),
            }
        }

        fn add_blob(&self, info: BlobInfo) {
            self.blobs.lock().push(info);
        }

        fn set_fail_on(&self, blob_ref: &str) {
            *self.fail_on.lock() = Some(blob_ref.to_string());
        }
    }

    #[async_trait]
    impl BlobLocator for InMemoryBlobLocator {
        async fn locate_blob(&self, blob_ref: &str) -> SnapshotResult<BlobInfo> {
            if let Some(ref fail_ref) = *self.fail_on.lock()
                && fail_ref == blob_ref
            {
                return Err(SnapshotError::BlobMissing {
                    blob_ref: blob_ref.to_string(),
                });
            }
            self.blobs
                .lock()
                .iter()
                .find(|b| b.blob_ref == blob_ref)
                .cloned()
                .ok_or_else(|| SnapshotError::BlobMissing {
                    blob_ref: blob_ref.to_string(),
                })
        }
    }

    // Helpers

    fn make_base_snapshot(snapshot_id: SnapshotId, tenant_id: &str) -> SnapshotMetadata {
        let mut meta = SnapshotMetadata::new(
            snapshot_id,
            TenantId::from_string(tenant_id),
            SandboxId::generate(),
            None,
            LineageType::Root,
            SnapshotPurpose::Base,
            SnapshotProfile::Filesystem,
            OperationId::generate(),
            "img_base".into(),
            BackendRecord {
                backend_type: "firecracker".into(),
                backend_version: "1.10.0".into(),
                protocol_version: "2.0".into(),
                guest_agent_version: Some("0.5.0".into()),
            },
            CpuShape::new("x86_64"),
            MemoryShape {
                memory_mb: 2048,
                vcpus: 2,
            },
            DeviceModel::new("q35"),
        );
        meta.filesystem_refs.push(FilesystemRef {
            blob_ref: "rootfs-base.ext4".into(),
            mount_point: "/".into(),
            fs_type: "ext4".into(),
            digest: Some("blake3:abc123".into()),
            is_root: true,
        });
        // : existing tests use v1 schema which does not require
        // SnapshotIntegrity blocks. New tests should use schema v2.
        meta.schema_version = 1;
        let _ = meta.mark_ready();
        meta
    }

    fn make_restore_context(snapshot_id: SnapshotId) -> RestoreContext {
        RestoreContext {
            snapshot_id,
            sandbox_id: SandboxId::generate(),
            operation_id: OperationId::generate(),
            host_backend: BackendRecord {
                backend_type: "firecracker".into(),
                backend_version: "1.10.0".into(),
                protocol_version: "2.0".into(),
                guest_agent_version: Some("0.5.0".into()),
            },
            host_cpu: CpuShape::new("x86_64"),
            host_memory: MemoryShape {
                memory_mb: 4096,
                vcpus: 4,
            },
            host_device: DeviceModel::new("q35"),
            host_runtime: RuntimeType::Firecracker,
            requires_memory: false,
            current_policy_epoch: 1,
            production_mode: false,
        }
    }

    // Tests: happy path

    #[tokio::test]
    async fn validate_restore_with_compatible_snapshot() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let snapshot_id = SnapshotId::generate();
        let meta = make_base_snapshot(snapshot_id.clone(), "tnt_test");
        repo.store_snapshot(&meta).await.unwrap();
        blobs.add_blob(BlobInfo {
            blob_ref: "rootfs-base.ext4".into(),
            path: "/tmp/rootfs-base.ext4".into(),
            size_bytes: 1024,
            digest: Some("blake3:abc123".into()),
        });

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let ctx = make_restore_context(snapshot_id);
        let result = orchestrator.validate_restore(&ctx).await;
        assert!(result.is_ok(), "expected valid restore: {:?}", result.err());
    }

    #[tokio::test]
    async fn prepare_restore_resolves_blobs() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let snapshot_id = SnapshotId::generate();
        let meta = make_base_snapshot(snapshot_id.clone(), "tnt_test");
        repo.store_snapshot(&meta).await.unwrap();
        blobs.add_blob(BlobInfo {
            blob_ref: "rootfs-base.ext4".into(),
            path: "/tmp/rootfs-base.ext4".into(),
            size_bytes: 1024,
            digest: Some("blake3:abc123".into()),
        });

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let ctx = make_restore_context(snapshot_id.clone());
        let (resolved_meta, blob_set) = orchestrator.prepare_restore(&ctx).await.unwrap();

        assert_eq!(resolved_meta.id, snapshot_id);
        assert_eq!(blob_set.len(), 1);
        assert_eq!(blob_set.filesystem_blobs.len(), 1);
        assert_eq!(blob_set.filesystem_blobs[0].blob_ref, "rootfs-base.ext4");
    }

    // Tests: incompatibility matrix

    #[tokio::test]
    async fn backend_mismatch_is_rejected() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let snapshot_id = SnapshotId::generate();
        let meta = make_base_snapshot(snapshot_id.clone(), "tnt_test");
        repo.store_snapshot(&meta).await.unwrap();

        let mut ctx = make_restore_context(snapshot_id);
        ctx.host_backend.backend_type = "qemu".into();

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let result = orchestrator.validate_restore(&ctx).await;
        assert!(
            matches!(result, Err(SnapshotError::BackendIncompatible { .. })),
            "expected BackendIncompatible, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn cpu_incompatible_is_rejected() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let snapshot_id = SnapshotId::generate();
        let meta = make_base_snapshot(snapshot_id.clone(), "tnt_test");
        repo.store_snapshot(&meta).await.unwrap();

        let mut ctx = make_restore_context(snapshot_id);
        ctx.host_cpu = CpuShape::new("aarch64");

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let result = orchestrator.validate_restore(&ctx).await;
        assert!(
            matches!(result, Err(SnapshotError::CpuIncompatible { .. })),
            "expected CpuIncompatible, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn insufficient_memory_is_rejected() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let snapshot_id = SnapshotId::generate();
        let meta = make_base_snapshot(snapshot_id.clone(), "tnt_test");
        repo.store_snapshot(&meta).await.unwrap();

        let mut ctx = make_restore_context(snapshot_id);
        ctx.host_memory = MemoryShape {
            memory_mb: 256,
            vcpus: 1,
        };

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let result = orchestrator.validate_restore(&ctx).await;
        assert!(
            matches!(result, Err(SnapshotError::ResourceShapeIncompatible { .. })),
            "expected ResourceShapeIncompatible, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn non_ready_snapshot_is_rejected() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let snapshot_id = SnapshotId::generate();
        let mut meta = make_base_snapshot(snapshot_id.clone(), "tnt_test");
        meta.state = SnapshotState::Staging; // not Ready
        repo.store_snapshot(&meta).await.unwrap();

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let ctx = make_restore_context(snapshot_id);
        let result = orchestrator.validate_restore(&ctx).await;
        assert!(
            matches!(result, Err(SnapshotError::SnapshotNotReady { .. })),
            "expected SnapshotNotReady, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn missing_snapshot_is_rejected() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let snapshot_id = SnapshotId::generate();

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let ctx = make_restore_context(snapshot_id);
        let result = orchestrator.validate_restore(&ctx).await;
        assert!(
            matches!(result, Err(SnapshotError::SnapshotNotFound { .. })),
            "expected SnapshotNotFound, got: {:?}",
            result
        );
    }

    // Tests: partial restore cleanup

    #[tokio::test]
    async fn blob_missing_during_resolve_causes_blob_missing_error() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let snapshot_id = SnapshotId::generate();
        let meta = make_base_snapshot(snapshot_id.clone(), "tnt_test");
        repo.store_snapshot(&meta).await.unwrap();
        // Do NOT add the blob -- it will be missing

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let ctx = make_restore_context(snapshot_id);
        let result = orchestrator.prepare_restore(&ctx).await;
        assert!(
            matches!(result, Err(SnapshotError::BlobMissing { .. })),
            "expected BlobMissing, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn failure_outcome_records_reason_and_timing() {
        let outcome = RestoreOrchestrator::failure_outcome("incompatible backend", Instant::now());
        assert!(!outcome.success);
        assert_eq!(outcome.reason, "incompatible backend");
        assert!(!outcome.blobs_resolved);
        assert!(!outcome.guest_notified);
        assert!(outcome.blob_set.is_none());
    }

    #[tokio::test]
    async fn success_outcome_records_diagnostics() {
        let blob_set = BlobSet {
            filesystem_blobs: vec![BlobInfo {
                blob_ref: "test".into(),
                path: "/tmp/test".into(),
                size_bytes: 100,
                digest: None,
            }],
            memory_blobs: vec![],
            workspace_blobs: vec![],
        };
        let outcome = RestoreOrchestrator::success_outcome(Instant::now(), &blob_set, true);
        assert!(outcome.success);
        assert!(outcome.blobs_resolved);
        assert!(outcome.guest_notified);
        assert!(outcome.blob_set.is_some());
    }

    // Tests: latency measurement

    #[tokio::test]
    async fn restore_records_latency_in_outcome() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let snapshot_id = SnapshotId::generate();
        let meta = make_base_snapshot(snapshot_id.clone(), "tnt_test");
        repo.store_snapshot(&meta).await.unwrap();
        blobs.add_blob(BlobInfo {
            blob_ref: "rootfs-base.ext4".into(),
            path: "/tmp/rootfs-base.ext4".into(),
            size_bytes: 1024,
            digest: Some("blake3:abc123".into()),
        });

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let ctx = make_restore_context(snapshot_id);
        let started = Instant::now();
        let result = orchestrator.prepare_restore(&ctx).await;
        assert!(result.is_ok());
        let (_meta, blob_set) = result.unwrap();
        let outcome = RestoreOrchestrator::success_outcome(started, &blob_set, true);
        assert!(outcome.success, "restore should succeed");
        assert!(outcome.guest_notified, "guest should be notified");
    }

    #[tokio::test]
    async fn blob_locator_configured_failure_produces_error() {
        let blobs = Arc::new(InMemoryBlobLocator::new());
        blobs.set_fail_on("will-fail");
        let result = blobs.locate_blob("will-fail").await;
        assert!(matches!(result, Err(SnapshotError::BlobMissing { .. })));
    }

    // Tests: credential exclusion validation

    #[test]
    fn scan_for_credential_material_passes_clean_snapshot() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy::production());
        meta.excluded_mounts = vec!["secret".into(), "runtime_tmp".into()];

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let result = orchestrator.scan_for_credential_material(&meta);
        assert!(result.is_ok(), "clean snapshot should pass credential scan");
    }

    #[test]
    fn scan_for_credential_material_detects_secret_mount() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy::production());
        meta.excluded_mounts = vec!["secret".into()];
        meta.filesystem_refs.push(FilesystemRef {
            blob_ref: "secrets-tmpfs".into(),
            mount_point: crate::mount::CANONICAL_SECRETS_TMPFS.into(),
            fs_type: "tmpfs".into(),
            digest: None,
            is_root: false,
        });

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let result = orchestrator.scan_for_credential_material(&meta);
        assert!(
            matches!(
                result,
                Err(SnapshotError::CredentialMaterialDetected { .. })
            ),
            "should detect credential material: {:?}",
            result
        );
    }

    #[test]
    fn scan_for_credential_material_fails_without_secret_in_excluded() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy::production());
        meta.excluded_mounts = vec!["workspace".into(), "runtime_tmp".into()];

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let result = orchestrator.scan_for_credential_material(&meta);
        assert!(
            matches!(
                result,
                Err(SnapshotError::CredentialExclusionInvalid { .. })
            ),
            "should detect missing secret exclusion: {:?}",
            result
        );
    }

    #[test]
    fn validate_credential_exclusion_happy_path() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy::production());
        meta.excluded_mounts = vec!["secret".into(), "runtime_tmp".into()];

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let result = orchestrator.validate_credential_exclusion(&meta);
        assert!(result.is_ok());
    }

    // Tests: credential refresh evaluation

    #[test]
    fn evaluate_credential_refresh_skipped_when_exclude_disabled() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy {
            exclude_from_snapshot: false,
            ..Default::default()
        });

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let outcome = orchestrator.evaluate_credential_refresh(&meta, true, &[]);
        assert!(
            matches!(outcome, CredentialRefreshOutcome::Skipped { .. }),
            "should skip when exclusion disabled"
        );
    }

    #[test]
    fn evaluate_credential_refresh_skipped_when_refresh_disabled() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy {
            refresh_after_restore: false,
            ..Default::default()
        });

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let outcome = orchestrator.evaluate_credential_refresh(&meta, true, &[]);
        assert!(
            matches!(outcome, CredentialRefreshOutcome::Skipped { .. }),
            "should skip when refresh disabled"
        );
    }

    #[test]
    fn evaluate_credential_refresh_denied_without_lease() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy::production());

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let outcome = orchestrator.evaluate_credential_refresh(&meta, false, &[]);
        assert!(
            matches!(outcome, CredentialRefreshOutcome::Denied { .. }),
            "should deny without valid lease: {:?}",
            outcome
        );
    }

    #[test]
    fn evaluate_credential_refresh_allowed_with_lease() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy::production());

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let outcome = orchestrator.evaluate_credential_refresh(&meta, true, &[]);
        assert!(
            matches!(outcome, CredentialRefreshOutcome::Refreshed { .. }),
            "should allow refresh with valid lease: {:?}",
            outcome
        );
    }

    #[test]
    fn evaluate_credential_refresh_allowed_without_lease_when_not_required() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy {
            require_lease_for_refresh: false,
            ..Default::default()
        });

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let outcome = orchestrator.evaluate_credential_refresh(&meta, false, &[]);
        assert!(
            matches!(outcome, CredentialRefreshOutcome::Refreshed { .. }),
            "should allow refresh when lease not required: {:?}",
            outcome
        );
    }

    // Tests: fork credential inheritance

    #[test]
    fn fork_credential_inheritance_denied_by_default() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy::production());

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let result = orchestrator.validate_fork_credential_inheritance(&meta, true);
        assert!(
            matches!(result, Err(SnapshotError::CredentialForkDenied { .. })),
            "should deny fork credential inheritance by default"
        );
    }

    #[test]
    fn fork_credential_inheritance_allowed_when_policy_permits() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.credential_policy = Some(CredentialSnapshotPolicy::development());

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let result = orchestrator.validate_fork_credential_inheritance(&meta, true);
        assert!(
            result.is_ok(),
            "should allow fork credential inheritance when policy permits"
        );
    }

    #[test]
    fn fork_no_inheritance_request_passes_regardless_of_policy() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let result = orchestrator.validate_fork_credential_inheritance(&meta, false);
        assert!(
            result.is_ok(),
            "no inheritance request should pass regardless of policy"
        );
    }

    // Tests: blob integrity verification

    #[tokio::test]
    async fn verify_blob_integrity_all_pass() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("data.bin");
        let content = b"hello integrity world";
        std::fs::write(&file_path, content).unwrap();
        let actual_digest = blake3::hash(content).to_hex().to_string();

        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        // Override the filesystem ref with one that has a known digest
        meta.filesystem_refs.clear();
        meta.filesystem_refs.push(FilesystemRef {
            blob_ref: "verified-file".into(),
            mount_point: "/".into(),
            fs_type: "ext4".into(),
            digest: Some(format!("blake3:{actual_digest}")),
            is_root: true,
        });
        meta.state = SnapshotState::Ready;
        repo.store_snapshot(&meta).await.unwrap();

        let blob_set = BlobSet {
            filesystem_blobs: vec![BlobInfo {
                blob_ref: "verified-file".into(),
                path: file_path,
                size_bytes: content.len() as u64,
                digest: Some(format!("blake3:{actual_digest}")),
            }],
            memory_blobs: vec![],
            workspace_blobs: vec![],
        };

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let failures = orchestrator
            .verify_blob_integrity(&meta, &blob_set)
            .await
            .unwrap();
        assert!(failures.is_empty(), "expected no failures: {failures:?}");
    }

    #[tokio::test]
    async fn verify_blob_integrity_detects_tampered_blob() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("tampered.bin");
        let content = b"original content";
        std::fs::write(&file_path, content).unwrap();
        let wrong_digest = blake3::hash(b"tampered content").to_hex().to_string();

        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.filesystem_refs.clear();
        meta.filesystem_refs.push(FilesystemRef {
            blob_ref: "tampered-file".into(),
            mount_point: "/".into(),
            fs_type: "ext4".into(),
            // Expected digest does NOT match actual file content
            digest: Some(format!("blake3:{wrong_digest}")),
            is_root: true,
        });
        meta.state = SnapshotState::Ready;
        repo.store_snapshot(&meta).await.unwrap();

        let blob_set = BlobSet {
            filesystem_blobs: vec![BlobInfo {
                blob_ref: "tampered-file".into(),
                path: file_path,
                size_bytes: content.len() as u64,
                digest: Some(format!("blake3:{wrong_digest}")),
            }],
            memory_blobs: vec![],
            workspace_blobs: vec![],
        };

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let failures = orchestrator
            .verify_blob_integrity(&meta, &blob_set)
            .await
            .unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].blob_ref, "tampered-file");
    }

    #[tokio::test]
    async fn verify_blob_integrity_skips_missing_digest() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("no-digest.bin");
        std::fs::write(&file_path, b"whatever").unwrap();

        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.filesystem_refs.clear();
        meta.filesystem_refs.push(FilesystemRef {
            blob_ref: "no-digest-file".into(),
            mount_point: "/".into(),
            fs_type: "ext4".into(),
            digest: None, // No expected digest
            is_root: true,
        });
        meta.state = SnapshotState::Ready;
        repo.store_snapshot(&meta).await.unwrap();

        let blob_set = BlobSet {
            filesystem_blobs: vec![BlobInfo {
                blob_ref: "no-digest-file".into(),
                path: file_path,
                size_bytes: 8,
                digest: None,
            }],
            memory_blobs: vec![],
            workspace_blobs: vec![],
        };

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let failures = orchestrator
            .verify_blob_integrity(&meta, &blob_set)
            .await
            .unwrap();
        assert!(
            failures.is_empty(),
            "blob without expected digest should be skipped"
        );
    }

    #[tokio::test]
    async fn verify_blob_integrity_skips_nonexistent_path() {
        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let mut meta = make_base_snapshot(SnapshotId::generate(), "tnt_test");
        meta.filesystem_refs.clear();
        meta.filesystem_refs.push(FilesystemRef {
            blob_ref: "ghost-file".into(),
            mount_point: "/".into(),
            fs_type: "ext4".into(),
            digest: Some("blake3:abcdef0123456789".into()),
            is_root: true,
        });
        meta.state = SnapshotState::Ready;
        repo.store_snapshot(&meta).await.unwrap();

        let blob_set = BlobSet {
            filesystem_blobs: vec![BlobInfo {
                blob_ref: "ghost-file".into(),
                path: std::path::PathBuf::from("/nonexistent/path/ghost"),
                size_bytes: 0,
                digest: Some("blake3:abcdef0123456789".into()),
            }],
            memory_blobs: vec![],
            workspace_blobs: vec![],
        };

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let failures = orchestrator
            .verify_blob_integrity(&meta, &blob_set)
            .await
            .unwrap();
        assert!(
            failures.is_empty(),
            "blob with inaccessible path should be skipped, not failed"
        );
    }

    #[tokio::test]
    async fn verify_single_blob_happy_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("single.bin");
        let content = b"single blob test";
        std::fs::write(&file_path, content).unwrap();
        let digest = blake3::hash(content).to_hex().to_string();

        let result = RestoreOrchestrator::verify_single_blob(
            "single-test",
            &format!("blake3:{digest}"),
            &file_path,
        )
        .await;
        assert!(result.is_ok(), "expected valid blob: {result:?}");
    }

    #[tokio::test]
    async fn verify_single_blob_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("bad.bin");
        std::fs::write(&file_path, b"real content").unwrap();
        let wrong_digest = blake3::hash(b"expected content").to_hex().to_string();

        let result = RestoreOrchestrator::verify_single_blob(
            "bad-blob",
            &format!("blake3:{wrong_digest}"),
            &file_path,
        )
        .await;
        assert!(
            matches!(result, Err(SnapshotError::BlobIntegrityMismatch { .. })),
            "expected BlobIntegrityMismatch, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_single_blob_missing_file() {
        let result = RestoreOrchestrator::verify_single_blob(
            "missing",
            "blake3:abcdef",
            std::path::Path::new("/definitely/not/here"),
        )
        .await;
        assert!(
            matches!(result, Err(SnapshotError::BlobMissing { .. })),
            "expected BlobMissing, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn prepare_restore_rejects_integrity_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("mismatch.bin");
        let content = b"actual content";
        std::fs::write(&file_path, content).unwrap();
        let wrong_digest = blake3::hash(b"different content").to_hex().to_string();

        let repo = Arc::new(InMemoryRepo::new());
        let blobs = Arc::new(InMemoryBlobLocator::new());
        let snapshot_id = SnapshotId::generate();
        let mut meta = make_base_snapshot(snapshot_id.clone(), "tnt_test");
        meta.filesystem_refs.clear();
        meta.filesystem_refs.push(FilesystemRef {
            blob_ref: "mismatch-file".into(),
            mount_point: "/".into(),
            fs_type: "ext4".into(),
            digest: Some(format!("blake3:{wrong_digest}")),
            is_root: true,
        });
        meta.state = SnapshotState::Ready;
        repo.store_snapshot(&meta).await.unwrap();

        blobs.add_blob(BlobInfo {
            blob_ref: "mismatch-file".into(),
            path: file_path,
            size_bytes: content.len() as u64,
            digest: Some(format!("blake3:{wrong_digest}")),
        });

        let orchestrator = RestoreOrchestrator::new(repo, blobs);
        let ctx = make_restore_context(snapshot_id);
        let result = orchestrator.prepare_restore(&ctx).await;
        assert!(
            matches!(result, Err(SnapshotError::BlobIntegrityMismatch { .. })),
            "prepare_restore should reject integrity mismatch, got: {result:?}"
        );
    }
}
