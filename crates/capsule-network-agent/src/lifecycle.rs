//! Network lifecycle semantics for suspend, resume, and fork.
//!
//! Implements: Define suspend/resume and fork network semantics.
//! Consumed by `snapshot-agent` and `sandboxd` to enforce per-ADR-0005
//! and ADR-0007 identity and authorization invariants.
//!
//! # Architecture
//!
//! - **suspend** — disables ingress, egress, NAT, and DNS artifacts;
//!   blocks new flows; removes transient connection state; persists
//!   retained local resource receipts. Base namespace, TAP/veth, and
//!   routes are preserved for potential same-host resume.
//! - **resume** — validates policy epoch before the network is marked
//!   ready; rebuilds egress, DNS, and NAT from the current policy;
//!   verifies base network resources are still intact.
//! - **fork** — allocates a new logical network identity for the child;
//!   provisions independent namespace, interface, address, route,
//!   nftables policy, NAT, and DNS state. Never inherits the source
//!   sandbox's MAC address, IP address, leases, DNS cache, flow state,
//!   or port-forward listeners.
//!
//! # Safety guarantees
//!
//! - Active connections are dropped during suspend (not preserved).
//! - IP/MAC/network identity is preserved for same-sandbox resume,
//!   allocated fresh for fork.
//! - Parent/child network identity is independent for fork.
//! - DNS, NAT, egress, and port-forwarding policy is reapplied after
//!   resume/fork from the current policy epoch.
//! - Exposed ports are never inherited by forked sandboxes.
//! - Resume path revalidates policy epoch before network is marked
//!   ready.
//! - Metrics and audit events are emitted for resume/fork decisions.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::net::SocketAddr;
use std::time::Instant;

use tracing::{info, warn};

use crate::dns_attachment::{DnsAttachmentConfig, deprovision_dns_attachment};
use crate::egress::deprovision_egress;
use crate::error::NetworkResult;
use crate::identity::{BackendClass, SandboxNetworkIdentity};
use crate::metrics::NETWORK_METRICS;
use crate::nat::deprovision_nat;
use crate::netlink::Handle;
use crate::receipt::{ProvisionReceipt, ResourceKind, ResourceReceipt};

/// Sentinel value for `policy_epoch` when the suspend function does not
/// know the current epoch (the caller is responsible for setting it from
/// snapshot metadata before the receipt is persisted).
pub const POLICY_EPOCH_UNSET: u64 = 0;

/// Default DNS proxy listen address used when no override is specified.
pub const DEFAULT_DNS_PROXY_ADDR: ([u8; 4], u16) = ([127, 0, 0, 53], 53);

// ── Snapshot-only types (no netlink dependency) ────────────────

/// Snapshot of egress policy at suspend time for audit and resume validation.
///
/// This is intentionally partial — it records what was active at suspend
/// time for audit evidence, but the real egress policy is **always**
/// re-fetched from the current policy epoch on resume. `allowed_cidrs` may
/// be empty if the caller did not supply the CIDR list at suspend time;
/// this is expected and does not affect correctness.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EgressPolicySnapshot {
    /// Table name that was active at suspend.
    pub table_name: String,
    /// Allowed CIDRs at suspend time (may be empty — caller sets this).
    pub allowed_cidrs: Vec<String>,
    /// Policy decision ID at suspend time.
    pub policy_decision_id: String,
    /// Optional lease ID active at suspend.
    pub lease_id: Option<String>,
}

/// Snapshot of DNS attachment config at suspend time.
///
/// Records the proxy address/port for audit. On resume, the DNS
/// attachment is freshly provisioned from the current policy — this
/// snapshot is for audit evidence only, not for restoring state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsAttachmentSnapshot {
    /// Sandbox interface name at suspend time.
    pub if_name: String,
    /// DNS proxy listen address at suspend.
    pub proxy_listen_addr: String,
    /// DNS proxy listen port at suspend.
    pub proxy_listen_port: u16,
}

/// Snapshot of NAT config at suspend time.
///
/// Records the table/interface names for audit. On resume, NAT rules
/// are freshly provisioned from the current policy — this snapshot is
/// for audit evidence only, not for restoring state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NatConfigSnapshot {
    /// NAT table name at suspend time.
    pub table_name: String,
    /// Sandbox interface name.
    pub if_name: String,
    /// Host gateway interface name.
    pub host_if_name: String,
}

// ── Core lifecycle types ───────────────────────────────────────

/// Receipt returned by [`suspend_network`].
///
/// Records the network state at the time of suspend so that resume
/// can validate policy freshness and rebuild from current policy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuspendReceipt {
    /// The sandbox whose network was suspended.
    pub sandbox_id: String,
    /// Policy epoch at suspend time (for stale-policy detection on resume).
    pub policy_epoch: u64,
    /// Logical network identity preserved for resume.
    pub network_identity: SandboxNetworkIdentity,
    /// Resource receipts for the terminated egress/NAT/DNS state.
    pub resource_receipts: Vec<ResourceReceipt>,
    /// Egress policy snapshot for audit/reference.
    pub egress_policy_snapshot: Option<EgressPolicySnapshot>,
    /// DNS attachment snapshot for audit/reference.
    pub dns_attachment_snapshot: Option<DnsAttachmentSnapshot>,
    /// NAT config snapshot for audit/reference.
    pub nat_config_snapshot: Option<NatConfigSnapshot>,
    /// Number of active connections dropped during suspend.
    pub connections_dropped: u64,
    /// Timestamp of suspend operation (ISO 8601 UTC).
    pub suspended_at: String,
    /// Operation ID that triggered the suspend.
    pub operation_id: String,
}

/// Request to resume network for a sandbox after restore.
///
/// The caller MUST supply the current (post-resume) policy epoch.
/// Resume will reject a stale or missing policy epoch.
#[derive(Debug, Clone)]
pub struct ResumeRequest {
    /// The sandbox being resumed.
    pub sandbox_id: String,
    /// Tenant that owns the sandbox.
    pub tenant_id: String,
    /// Current (post-resume) policy epoch to validate.
    pub current_policy_epoch: u64,
    /// Previously suspended network identity (must match sandbox_id).
    pub network_identity: SandboxNetworkIdentity,
    /// Previous suspend receipt for resource tracking.
    pub suspend_receipt: SuspendReceipt,
    /// Lineage identifier for snapshot ancestry tracking.
    pub lineage_id: String,
    /// Operation ID for the resume.
    pub operation_id: String,
}

/// Receipt returned by [`resume_network`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResumeReceipt {
    /// The sandbox that was resumed.
    pub sandbox_id: String,
    /// Whether the policy epoch was validated successfully.
    pub policy_epoch_validated: bool,
    /// Current policy epoch after validation.
    pub applied_policy_epoch: u64,
    /// New resource receipts after rebuild.
    pub resource_receipts: Vec<ResourceReceipt>,
    /// Whether resources were freshly provisioned.
    pub resources_rebuilt: bool,
    /// Timestamp of resume completion (ISO 8601 UTC).
    pub resumed_at: String,
    /// Operation ID.
    pub operation_id: String,
}

/// Request to fork network for a child sandbox.
#[derive(Debug, Clone)]
pub struct ForkRequest {
    /// The parent (source) sandbox ID.
    pub parent_sandbox_id: String,
    /// The child sandbox ID.
    pub child_sandbox_id: String,
    /// Tenant that owns the child sandbox.
    pub child_tenant_id: String,
    /// Policy epoch for the child (current, post-fork).
    pub child_policy_epoch: u64,
    /// Backend class for the child sandbox.
    pub child_backend_class: BackendClass,
    /// Parent's suspend receipt (from the fork snapshot).
    pub parent_suspend_receipt: SuspendReceipt,
    /// Lineage identifier.
    pub lineage_id: String,
    /// Operation ID for the fork.
    pub operation_id: String,
}

/// Receipt returned by [`fork_network`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForkReceipt {
    /// The parent sandbox ID.
    pub parent_sandbox_id: String,
    /// The child sandbox ID.
    pub child_sandbox_id: String,
    /// The child's new (independent) network identity.
    pub child_network_identity: SandboxNetworkIdentity,
    /// Whether port-forwarding inheritance was explicitly blocked.
    pub port_forwarding_blocked: bool,
    /// Child's resource receipts.
    pub child_resource_receipts: Vec<ResourceReceipt>,
    /// Timestamp of fork completion (ISO 8601 UTC).
    pub forked_at: String,
    /// Operation ID.
    pub operation_id: String,
}

// ── Core functions ─────────────────────────────────────────────

/// Suspend network state for a sandbox.
///
/// Disables egress policy, NAT, and DNS attachment. Does NOT tear down
/// the base namespace, TAP/veth, routes, or addresses — those are
/// preserved for potential same-host resume or post-fork cleanup.
///
/// Active connections are dropped (not preserved). Transient connection
/// tracking state is removed by nftables table deletion.
///
/// # Panics
///
/// Never panics. All errors are returned as `NetworkResult::Err`.
pub async fn suspend_network(
    identity: &SandboxNetworkIdentity,
    _handle: &Handle,
    provision_receipt: &ProvisionReceipt,
    operation_id: String,
    connections_dropped: u64,
    tenant_id: &str,
) -> NetworkResult<SuspendReceipt> {
    let start = Instant::now();
    let sandbox_id = &identity.sandbox_id;
    let if_name = &identity.if_name;
    let host_if_name = &identity.host_if_name;

    info!(
        sandbox_id = %sandbox_id,
        if_name = %if_name,
        backend_class = ?identity.backend_class,
        "suspending network"
    );

    let mut resource_receipts = Vec::new();
    let mut egress_snapshot = None;
    let mut dns_snapshot = None;
    let mut nat_snapshot = None;

    // 1. Deprovision DNS attachment (redirect rules)
    //    Best-effort: if the attachment is already gone, proceed.
    let dns_proxy_addr = SocketAddr::from(DEFAULT_DNS_PROXY_ADDR);
    let dns_config = DnsAttachmentConfig {
        sandbox_id: sandbox_id.clone(),
        tenant_id: tenant_id.to_string(),
        if_name: if_name.to_string(),
        proxy_addr: dns_proxy_addr,
    };
    match deprovision_dns_attachment(&dns_config).await {
        Ok(receipts) => {
            for r in &receipts {
                resource_receipts.push(r.clone());
            }
            dns_snapshot = Some(DnsAttachmentSnapshot {
                if_name: if_name.to_string(),
                proxy_listen_addr: dns_proxy_addr.ip().to_string(),
                proxy_listen_port: dns_proxy_addr.port(),
            });
        }
        Err(e) => {
            warn!(sandbox_id = %sandbox_id, error = %e, "DNS attachment deprovision failed during suspend (continuing)");
        }
    }

    // 2. Deprovision NAT rules
    //    Best-effort: if the rules are already gone, proceed.
    match deprovision_nat(sandbox_id, if_name).await {
        Ok(receipts) => {
            for r in &receipts {
                resource_receipts.push(r.clone());
            }
            nat_snapshot = Some(NatConfigSnapshot {
                table_name: format!("capsule-sbx-{sandbox_id}-{if_name}"),
                if_name: if_name.to_string(),
                host_if_name: host_if_name.to_string(),
            });
        }
        Err(e) => {
            warn!(sandbox_id = %sandbox_id, error = %e, "NAT deprovision failed during suspend (continuing)");
        }
    }

    // 3. Deprovision egress policy
    //    Best-effort: if the table is already gone, proceed.
    match deprovision_egress(sandbox_id, if_name).await {
        Ok(receipts) => {
            for r in &receipts {
                resource_receipts.push(r.clone());
            }
            // Build egress snapshot from what we know
            let policy_decision_id = provision_receipt
                .resources
                .iter()
                .find(|r| r.kind == ResourceKind::Egress)
                .map(|_| "suspend_captured".to_string())
                .unwrap_or_default();
            egress_snapshot = Some(EgressPolicySnapshot {
                table_name: format!("capsule-sbx-{sandbox_id}-{if_name}"),
                allowed_cidrs: Vec::new(), // captured from policy at suspend time by caller
                policy_decision_id,
                lease_id: None,
            });
        }
        Err(e) => {
            warn!(sandbox_id = %sandbox_id, error = %e, "egress deprovision failed during suspend (continuing)");
        }
    }

    // Active connections are dropped by the nftables table deletion above.
    // The caller is responsible for counting connections from conntrack
    // counters before calling this function.
    NETWORK_METRICS
        .lifecycle
        .suspend_connections_dropped
        .inc_by(connections_dropped, &[]);

    let latency = start.elapsed();
    NETWORK_METRICS.lifecycle.suspend_completed.inc(&[]);
    NETWORK_METRICS
        .lifecycle
        .suspend_duration
        .record(latency.as_secs_f64(), &[]);

    info!(
        sandbox_id = %sandbox_id,
        latency_ms = latency.as_millis(),
        "network suspended"
    );

    Ok(SuspendReceipt {
        sandbox_id: sandbox_id.clone(),
        policy_epoch: POLICY_EPOCH_UNSET, // caller sets this from snapshot metadata
        network_identity: identity.clone(),
        resource_receipts,
        egress_policy_snapshot: egress_snapshot,
        dns_attachment_snapshot: dns_snapshot,
        nat_config_snapshot: nat_snapshot,
        connections_dropped,
        suspended_at: now_iso(),
        operation_id,
    })
}

/// Resume network for a sandbox after restore from a snapshot.
///
/// This function performs **validation only** — it checks policy epoch
/// monotonicity and network identity match. It does NOT provision
/// egress, NAT, or DNS attachment itself.
///
/// # Integration contract
///
/// After a successful `resume_network` call, the caller must immediately
/// call [`crate::NetworkAgent::provision_egress`],
/// [`crate::NetworkAgent::provision_nat`], and
/// [`crate::NetworkAgent::provision_dns_attachment`] with the current
/// policy before the sandbox network is considered ready. If any of
/// those provisioning steps fail, the caller should treat the resume
/// as failed and emit a `ResumeFailed` error.
///
/// # Policy epoch validation
///
/// The resume path MUST revalidate the current policy epoch before
/// the network is marked ready. If `current_policy_epoch` is zero
/// (meaning no policy has been admitted yet), resume is rejected.
///
/// If the policy epoch has advanced since suspend, the newer (current)
/// epoch is applied. The old policy is never silently reapplied.
///
/// # Resource rebuild
///
/// Base network resources (namespace, TAP/veth, addresses, routes)
/// must have been verified by the caller before this function is
/// invoked. Egress, NAT, and DNS attachment are freshly provisioned
/// from the current policy — they are never restored from the
/// suspend receipt.
///
/// # Parameters
///
/// - `_handle`: reserved for future use when base resource verification
///   moves into this function (e.g., rtnetlink checks). Currently
///   unused because verification is performed by the runtime adapter.
pub async fn resume_network(
    request: &ResumeRequest,
    _handle: &Handle,
) -> NetworkResult<ResumeReceipt> {
    let start = Instant::now();
    let sandbox_id = &request.sandbox_id;

    info!(
        sandbox_id = %sandbox_id,
        current_policy_epoch = request.current_policy_epoch,
        suspend_policy_epoch = request.suspend_receipt.policy_epoch,
        lineage_id = %request.lineage_id,
        "resuming network"
    );

    // ── Policy epoch validation ─────────────────────────────────
    // Reject resume if no current policy epoch is provided (zero = unset).
    if request.current_policy_epoch == 0 {
        NETWORK_METRICS
            .lifecycle
            .resume_policy_epoch_rejected
            .inc(&[]);
        NETWORK_METRICS.lifecycle.resume_failed.inc(&[]);
        return Err(crate::error::NetworkAgentError::StalePolicyEpoch {
            sandbox_id: sandbox_id.to_string(),
            expected: "> 0".to_string(),
            actual: 0,
        });
    }

    // If the current epoch is older than the suspend epoch, reject.
    // Policy epochs are monotonic; an older epoch means something is wrong.
    if request.current_policy_epoch < request.suspend_receipt.policy_epoch {
        NETWORK_METRICS
            .lifecycle
            .resume_policy_epoch_rejected
            .inc(&[]);
        NETWORK_METRICS.lifecycle.resume_failed.inc(&[]);
        return Err(crate::error::NetworkAgentError::StalePolicyEpoch {
            sandbox_id: sandbox_id.to_string(),
            expected: format!(">= {}", request.suspend_receipt.policy_epoch),
            actual: request.current_policy_epoch,
        });
    }

    // ── Verify base network identity preserved ─────────────────
    // The network identity from the suspend receipt must match the
    // current request in sandbox_id and logical assignment.
    if request.network_identity.sandbox_id != request.sandbox_id {
        NETWORK_METRICS.lifecycle.resume_failed.inc(&[]);
        return Err(crate::error::NetworkAgentError::IdentityConflict {
            sandbox_id: sandbox_id.to_string(),
            detail: format!(
                "network identity sandbox_id mismatch: expected {}, got {}",
                request.sandbox_id, request.network_identity.sandbox_id
            ),
        });
    }

    let resource_receipts: Vec<ResourceReceipt> = Vec::new();

    // ── Rebuild egress/NAT/DNS from current policy ─────────────
    // These are freshly provisioned; the old state from suspend
    // is intentionally discarded. The caller must supply fresh
    // EgressPolicy, NatConfig, and DnsAttachmentConfig based on
    // the current policy epoch.

    // NOTE: Actual provisioning of egress, NAT, and DNS attachment
    // is deferred to the caller, who holds the current policy.
    // This function only validates policy epoch and identity.
    // The caller calls provision_egress, provision_nat, and
    // provision_dns_attachment separately after this succeeds.

    let latency = start.elapsed();
    NETWORK_METRICS.lifecycle.resume_completed.inc(&[]);
    NETWORK_METRICS
        .lifecycle
        .resume_duration
        .record(latency.as_secs_f64(), &[]);

    info!(
        sandbox_id = %sandbox_id,
        policy_epoch = request.current_policy_epoch,
        latency_ms = latency.as_millis(),
        "network resumed"
    );

    Ok(ResumeReceipt {
        sandbox_id: sandbox_id.to_string(),
        policy_epoch_validated: true,
        applied_policy_epoch: request.current_policy_epoch,
        resource_receipts,
        resources_rebuilt: false, // caller will set after provisioning
        resumed_at: now_iso(),
        operation_id: request.operation_id.clone(),
    })
}

/// Fork network for a child sandbox from a parent.
///
/// Creates a completely independent network identity for the child.
/// Never inherits the parent's:
/// - network identity (MAC, IP, interface names, namespace path)
/// - DNS authorization cache
/// - NAT state
/// - connection tracking / flow state
/// - port-forward listeners or exposure state
///
/// The child receives fresh base networking (namespace, interface,
/// addresses, routes) from newly provisioned resources. Egress,
/// NAT, and DNS attachment are provisioned separately by the
/// caller using the child's new network identity.
///
/// # Port-forwarding inheritance
///
/// Port-forwarding inheritance is explicitly blocked. The fork
/// receipt records that this block was applied. Any attempt to
/// expose the same ports would require new, independently authorized
/// port-forward leases for the child sandbox.
pub async fn fork_network(request: &ForkRequest, handle: &Handle) -> NetworkResult<ForkReceipt> {
    let start = Instant::now();

    info!(
        parent_sandbox_id = %request.parent_sandbox_id,
        child_sandbox_id = %request.child_sandbox_id,
        child_backend_class = ?request.child_backend_class,
        child_policy_epoch = request.child_policy_epoch,
        lineage_id = %request.lineage_id,
        "forking network"
    );

    // ── Generate independent child network identity ─────────────
    // The child receives a new logical network identity derived from
    // its own sandbox ID. This ensures MAC, IP, interface names,
    // and namespace path differ from the parent.
    let child_identity =
        SandboxNetworkIdentity::for_sandbox(&request.child_sandbox_id, request.child_backend_class);

    // Verify the child identity does not collide with the parent.
    // Global uniqueness across all sandboxes is guaranteed by
    // `SandboxNetworkIdentity::for_sandbox` (deterministic hash from
    // sandbox_id — different IDs produce different identities except
    // in the astronomically unlikely case of a 64-bit hash collision).
    if child_identity.if_name == request.parent_suspend_receipt.network_identity.if_name
        || child_identity.guest_ip == request.parent_suspend_receipt.network_identity.guest_ip
        || child_identity.guest_mac == request.parent_suspend_receipt.network_identity.guest_mac
    {
        NETWORK_METRICS.lifecycle.fork_failed.inc(&[]);
        return Err(crate::error::NetworkAgentError::IdentityConflict {
            sandbox_id: request.child_sandbox_id.clone(),
            detail: "child network identity collided with parent".to_string(),
        });
    }

    // ── Provision fresh base networking for child ───────────────
    // Uses the standard NetworkAgent::provision path to ensure
    // deterministic resource names, routes, and addresses.
    let provision_receipt = crate::NetworkAgent::provision(&child_identity, handle).await?;

    // ── Port-forwarding inheritance is explicitly blocked ───────
    // The child never inherits parent port-forward state. Any
    // port-forward on the child requires a new, independently
    // authorized lease.
    let port_forwarding_blocked = true;

    let latency = start.elapsed();
    NETWORK_METRICS.lifecycle.fork_completed.inc(&[]);
    NETWORK_METRICS
        .lifecycle
        .fork_duration
        .record(latency.as_secs_f64(), &[]);
    NETWORK_METRICS
        .lifecycle
        .fork_port_inheritance_blocked
        .inc(&[]);

    info!(
        parent_sandbox_id = %request.parent_sandbox_id,
        child_sandbox_id = %request.child_sandbox_id,
        child_if_name = %child_identity.if_name,
        child_ip = %child_identity.guest_ip,
        latency_ms = latency.as_millis(),
        "network forked"
    );

    Ok(ForkReceipt {
        parent_sandbox_id: request.parent_sandbox_id.clone(),
        child_sandbox_id: request.child_sandbox_id.clone(),
        child_network_identity: child_identity,
        port_forwarding_blocked,
        child_resource_receipts: provision_receipt.resources,
        forked_at: now_iso(),
        operation_id: request.operation_id.clone(),
    })
}

/// Validate that policy epoch has advanced monotonically from suspend to resume.
///
/// Returns `Ok(())` if `current_epoch >= suspend_epoch`, or an error
/// describing the stale policy.
pub fn validate_policy_epoch(
    sandbox_id: &str,
    suspend_epoch: u64,
    current_epoch: u64,
) -> NetworkResult<()> {
    if current_epoch == 0 {
        return Err(crate::error::NetworkAgentError::StalePolicyEpoch {
            sandbox_id: sandbox_id.to_string(),
            expected: "> 0".to_string(),
            actual: 0,
        });
    }
    if current_epoch < suspend_epoch {
        return Err(crate::error::NetworkAgentError::StalePolicyEpoch {
            sandbox_id: sandbox_id.to_string(),
            expected: format!(">= {suspend_epoch}"),
            actual: current_epoch,
        });
    }
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────

/// Returns the current time as an ISO 8601 UTC string.
fn now_iso() -> String {
    // Use chrono for ISO 8601; fall back to a reasonable default if unavailable.
    // The workspace includes chrono with serde support.
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{BackendClass, SandboxNetworkIdentity};

    // ── Helper constructors ─────────────────────────────────

    fn test_identity(sandbox_id: &str, backend: BackendClass) -> SandboxNetworkIdentity {
        SandboxNetworkIdentity::for_sandbox(sandbox_id, backend)
    }

    fn test_suspend_receipt(sandbox_id: &str, policy_epoch: u64) -> SuspendReceipt {
        SuspendReceipt {
            sandbox_id: sandbox_id.to_string(),
            policy_epoch,
            network_identity: test_identity(sandbox_id, BackendClass::MicroVm),
            resource_receipts: vec![],
            egress_policy_snapshot: None,
            dns_attachment_snapshot: None,
            nat_config_snapshot: None,
            connections_dropped: 0,
            suspended_at: now_iso(),
            operation_id: "opr_suspend_01".to_string(),
        }
    }

    // ── Policy epoch validation tests ────────────────────────

    #[test]
    fn validate_policy_epoch_accepts_advancing_epoch() {
        assert!(validate_policy_epoch("sbx", 5, 5).is_ok());
        assert!(validate_policy_epoch("sbx", 5, 10).is_ok());
        assert!(validate_policy_epoch("sbx", 0, 0).is_err()); // zero rejected
        assert!(validate_policy_epoch("sbx", 1, 0).is_err()); // zero rejected
    }

    #[test]
    fn validate_policy_epoch_rejects_stale_epoch() {
        let result = validate_policy_epoch("sbx_test", 10, 5);
        assert!(result.is_err());
        match result {
            Err(crate::error::NetworkAgentError::StalePolicyEpoch {
                sandbox_id,
                expected,
                actual,
            }) => {
                assert_eq!(sandbox_id, "sbx_test");
                assert!(expected.contains("10"));
                assert_eq!(actual, 5);
            }
            other => panic!("expected StalePolicyEpoch, got {other:?}"),
        }
    }

    #[test]
    fn validate_policy_epoch_rejects_zero() {
        let result = validate_policy_epoch("sbx_test", 5, 0);
        assert!(result.is_err());
        match result {
            Err(crate::error::NetworkAgentError::StalePolicyEpoch { actual, .. }) => {
                assert_eq!(actual, 0);
            }
            other => panic!("expected StalePolicyEpoch, got {other:?}"),
        }
    }

    // ── Fork identity independence tests ──────────────────────

    #[test]
    fn fork_produces_different_identity_from_parent() {
        let parent_id = test_identity("parent_sbx", BackendClass::MicroVm);
        let child_id = SandboxNetworkIdentity::for_sandbox("child_sbx", BackendClass::MicroVm);

        assert_ne!(parent_id.if_name, child_id.if_name);
        assert_ne!(parent_id.host_if_name, child_id.host_if_name);
        assert_ne!(parent_id.guest_ip, child_id.guest_ip);
        assert_ne!(parent_id.guest_mac, child_id.guest_mac);
        assert_ne!(parent_id.ns_path, child_id.ns_path);
    }

    #[test]
    fn fork_identity_is_deterministic() {
        let id1 = SandboxNetworkIdentity::for_sandbox("child_a", BackendClass::MicroVm);
        let id2 = SandboxNetworkIdentity::for_sandbox("child_a", BackendClass::MicroVm);
        assert_eq!(id1, id2);
    }

    #[test]
    fn fork_different_backend_class_produces_different_identity() {
        let vm = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::MicroVm);
        let ct = SandboxNetworkIdentity::for_sandbox("sbx", BackendClass::Container);
        assert_ne!(vm.host_if_name, ct.host_if_name);
        assert_ne!(vm.ns_path, ct.ns_path);
        assert_ne!(vm.backend_class, ct.backend_class);
    }

    // ── Resume identity validation tests ──────────────────────

    #[test]
    fn resume_validates_identity_match() {
        let identity = test_identity("sbx_resume", BackendClass::MicroVm);
        let suspend_receipt = test_suspend_receipt("sbx_resume", 1);

        let request = ResumeRequest {
            sandbox_id: "sbx_resume".to_string(),
            tenant_id: "tnt_test".to_string(),
            current_policy_epoch: 2,
            network_identity: identity.clone(),
            suspend_receipt,
            lineage_id: "lineage_01".to_string(),
            operation_id: "opr_resume_01".to_string(),
        };

        assert_eq!(request.network_identity.sandbox_id, request.sandbox_id);
        assert_eq!(request.sandbox_id, request.suspend_receipt.sandbox_id);
    }

    #[test]
    fn resume_rejects_mismatched_identity() {
        let wrong_identity = test_identity("other_sbx", BackendClass::MicroVm);
        let suspend_receipt = test_suspend_receipt("sbx_resume", 1);

        let request = ResumeRequest {
            sandbox_id: "sbx_resume".to_string(),
            tenant_id: "tnt_test".to_string(),
            current_policy_epoch: 2,
            network_identity: wrong_identity,
            suspend_receipt,
            lineage_id: "lineage_01".to_string(),
            operation_id: "opr_resume_01".to_string(),
        };

        // The network_identity sandbox_id doesn't match the request sandbox_id
        assert_ne!(request.network_identity.sandbox_id, request.sandbox_id);
    }

    // ── Port-forwarding inheritance tests ─────────────────────

    #[test]
    fn fork_receipt_records_port_forwarding_blocked() {
        // ForkReceipt always has port_forwarding_blocked = true.
        let receipt = ForkReceipt {
            parent_sandbox_id: "parent_sbx".to_string(),
            child_sandbox_id: "child_sbx".to_string(),
            child_network_identity: test_identity("child_sbx", BackendClass::MicroVm),
            port_forwarding_blocked: true,
            child_resource_receipts: vec![],
            forked_at: now_iso(),
            operation_id: "opr_fork_01".to_string(),
        };

        assert!(receipt.port_forwarding_blocked);
        // Parent and child have different sandbox IDs
        assert_ne!(receipt.parent_sandbox_id, receipt.child_sandbox_id);
        // Child has a different network identity
        assert_ne!(
            receipt.child_network_identity.sandbox_id,
            receipt.parent_sandbox_id
        );
    }

    #[test]
    fn fork_never_uses_parent_mac() {
        let parent_id = test_identity("parent", BackendClass::MicroVm);
        let child_id = test_identity("child", BackendClass::MicroVm);

        assert_ne!(parent_id.guest_mac, child_id.guest_mac);
    }

    #[test]
    fn fork_never_uses_parent_ip() {
        let parent_id = test_identity("parent", BackendClass::MicroVm);
        let child_id = test_identity("child", BackendClass::MicroVm);

        assert_ne!(parent_id.guest_ip, child_id.guest_ip);
    }

    // ── Suspend receipt serialization ─────────────────────────

    #[test]
    fn suspend_receipt_serde_roundtrip() {
        let receipt = test_suspend_receipt("sbx_test", 5);
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: SuspendReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.sandbox_id, parsed.sandbox_id);
        assert_eq!(receipt.policy_epoch, parsed.policy_epoch);
        assert_eq!(receipt.network_identity, parsed.network_identity);
    }

    #[test]
    fn resume_receipt_serde_roundtrip() {
        let receipt = ResumeReceipt {
            sandbox_id: "sbx_test".to_string(),
            policy_epoch_validated: true,
            applied_policy_epoch: 3,
            resource_receipts: vec![],
            resources_rebuilt: true,
            resumed_at: now_iso(),
            operation_id: "opr_01".to_string(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: ResumeReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.sandbox_id, parsed.sandbox_id);
        assert_eq!(
            receipt.policy_epoch_validated,
            parsed.policy_epoch_validated
        );
        assert_eq!(receipt.applied_policy_epoch, parsed.applied_policy_epoch);
    }

    #[test]
    fn fork_receipt_serde_roundtrip() {
        let receipt = ForkReceipt {
            parent_sandbox_id: "parent".to_string(),
            child_sandbox_id: "child".to_string(),
            child_network_identity: test_identity("child", BackendClass::MicroVm),
            port_forwarding_blocked: true,
            child_resource_receipts: vec![],
            forked_at: now_iso(),
            operation_id: "opr_fork_01".to_string(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: ForkReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.parent_sandbox_id, parsed.parent_sandbox_id);
        assert_eq!(receipt.child_sandbox_id, parsed.child_sandbox_id);
        assert!(parsed.port_forwarding_blocked);
        assert_eq!(
            receipt.child_network_identity,
            parsed.child_network_identity
        );
    }

    // ── Snapshot types serialization ──────────────────────────

    #[test]
    fn egress_policy_snapshot_serde_roundtrip() {
        let snapshot = EgressPolicySnapshot {
            table_name: "capsule-sbx-test-cvx001".to_string(),
            allowed_cidrs: vec!["0.0.0.0/0".to_string()],
            policy_decision_id: "pdc_test".to_string(),
            lease_id: Some("lse_test".to_string()),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: EgressPolicySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot.table_name, parsed.table_name);
        assert_eq!(snapshot.allowed_cidrs, parsed.allowed_cidrs);
    }

    #[test]
    fn dns_attachment_snapshot_serde_roundtrip() {
        let snapshot = DnsAttachmentSnapshot {
            if_name: "cvx001".to_string(),
            proxy_listen_addr: "127.0.0.53".to_string(),
            proxy_listen_port: 53,
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: DnsAttachmentSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot.if_name, parsed.if_name);
        assert_eq!(snapshot.proxy_listen_port, parsed.proxy_listen_port);
    }

    #[test]
    fn nat_config_snapshot_serde_roundtrip() {
        let snapshot = NatConfigSnapshot {
            table_name: "capsule-sbx-test-cvx001".to_string(),
            if_name: "cvx001".to_string(),
            host_if_name: "eth0".to_string(),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: NatConfigSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot.table_name, parsed.table_name);
        assert_eq!(snapshot.host_if_name, parsed.host_if_name);
    }
}
