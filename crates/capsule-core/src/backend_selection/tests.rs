use super::*;
use crate::identity::TenantId;
use crate::runtime::BackendCapabilities;
use crate::tenant::{Tenant, TenantStatus};

fn make_tenant(allowed_runtimes: Vec<RuntimeType>, allowed_classes: Vec<WorkloadClass>) -> Tenant {
    Tenant {
        id: TenantId::generate(),
        name: "test-tenant".into(),
        status: TenantStatus::Active,
        allowed_runtimes,
        allowed_workload_classes: allowed_classes,
        policy_epoch: Some(1),
    }
}

fn make_capabilities(
    runtimes: &[(RuntimeType, Vec<crate::runtime::BackendCapability>)],
) -> HashMap<RuntimeType, BackendCapabilities> {
    runtimes
        .iter()
        .map(|(rt, caps)| (*rt, BackendCapabilities::new(caps.iter().copied())))
        .collect()
}

fn default_required_capabilities() -> BackendCapabilities {
    use crate::runtime::BackendCapability;
    BackendCapabilities::from([
        BackendCapability::Boot,
        BackendCapability::GuestTransport,
        BackendCapability::Exec,
        BackendCapability::Health,
    ])
}

fn ready_health(runtimes: &[RuntimeType]) -> HashMap<RuntimeType, BackendHealth> {
    runtimes
        .iter()
        .copied()
        .map(|runtime| (runtime, BackendHealth::ready()))
        .collect()
}

fn passing_conformance(runtimes: &[RuntimeType]) -> HashMap<RuntimeType, ConformanceStatus> {
    runtimes
        .iter()
        .copied()
        .map(|runtime| {
            (
                runtime,
                ConformanceStatus {
                    passing: true,
                    profile: None,
                },
            )
        })
        .collect()
}

fn default_health() -> &'static HashMap<RuntimeType, BackendHealth> {
    static HEALTH: std::sync::LazyLock<HashMap<RuntimeType, BackendHealth>> =
        std::sync::LazyLock::new(|| {
            ready_health(&[
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
                RuntimeType::GVisor,
            ])
        });
    &HEALTH
}

fn default_conformance() -> &'static HashMap<RuntimeType, ConformanceStatus> {
    static CONFORMANCE: std::sync::LazyLock<HashMap<RuntimeType, ConformanceStatus>> =
        std::sync::LazyLock::new(|| {
            passing_conformance(&[
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
                RuntimeType::GVisor,
            ])
        });
    &CONFORMANCE
}

// ================================================================
// WorkloadClass -> Backend mappings
// ================================================================

#[test]
fn public_untrusted_prefers_firecracker_then_qemu() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[
        (
            RuntimeType::Firecracker,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
        (
            RuntimeType::Qemu,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
    ]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker, RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Firecracker));
    assert_eq!(result.fallback_rank, 0);
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::PreferredBackendPassed
    );
    assert!(result.rejected_candidates.is_empty());
}

#[test]
fn public_untrusted_falls_back_to_qemu_when_firecracker_unavailable() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Qemu,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Qemu));
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::FallbackBackendSelected
    );
    assert_eq!(result.fallback_rank, 1);
    assert_eq!(result.rejected_candidates.len(), 1);
    assert_eq!(
        result.rejected_candidates[0].runtime,
        RuntimeType::Firecracker
    );
}

#[test]
fn public_untrusted_rejects_gvisor_output() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::GVisor],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::GVisor,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::GVisor],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            // For PublicUntrusted, ordered candidates are [Firecracker, Qemu].
            // Neither is in tenant's allowed_runtimes (only gVisor), so both
            // fail TenantPolicy. gVisor is never a candidate for this class.
            assert!(!rejected.is_empty());
            assert!(
                rejected
                    .iter()
                    .all(|r| r.gate == BackendSelectionGate::TenantPolicy)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn trusted_fast_path_prefers_gvisor_then_firecracker_then_qemu() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![
            RuntimeType::GVisor,
            RuntimeType::Firecracker,
            RuntimeType::Qemu,
        ],
        vec![WorkloadClass::TrustedFastPath],
    );
    let caps = make_capabilities(&[
        (
            RuntimeType::GVisor,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
        (
            RuntimeType::Firecracker,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
        (
            RuntimeType::Qemu,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
    ]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::TrustedFastPath,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[
                RuntimeType::GVisor,
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
            ],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::GVisor));
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::PreferredBackendPassed
    );
}

#[test]
fn trusted_fast_path_falls_back_to_firecracker_when_gvisor_not_available() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::GVisor, RuntimeType::Firecracker],
        vec![WorkloadClass::TrustedFastPath],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::TrustedFastPath,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Firecracker));
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::FallbackBackendSelected
    );
}

#[test]
fn compatibility_vm_selects_qemu_only() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Qemu],
        vec![WorkloadClass::CompatibilityVm],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Qemu,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::CompatibilityVm,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Qemu));
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::PreferredBackendPassed
    );
}

#[test]
fn compatibility_vm_rejects_without_qemu() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::CompatibilityVm],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::CompatibilityVm,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::TenantPolicy)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

// ================================================================
// Tenant policy enforcement
// ================================================================

#[test]
fn tenant_policy_rejects_backend_not_in_allowed_runtimes() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Qemu,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(!rejected.is_empty());
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::TenantPolicy
                        && r.runtime == RuntimeType::Qemu)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn tenant_unauthorized_for_workload_class() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::GVisor],
        vec![], // no classes authorized
    );
    let caps = make_capabilities(&[]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::TrustedFastPath,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    assert!(matches!(
        err,
        BackendSelectionError::UnauthorizedClass { .. }
    ));
}

// ================================================================
// Capability rejection
// ================================================================

#[test]
fn missing_capability_rejects_backend() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[
        (
            RuntimeType::Firecracker,
            vec![crate::runtime::BackendCapability::Boot],
        ),
        (
            RuntimeType::Qemu,
            vec![crate::runtime::BackendCapability::Boot],
        ),
    ]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker, RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert_eq!(rejected.len(), 2);
            for r in &rejected {
                assert_eq!(r.gate, BackendSelectionGate::Capabilities);
            }
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

// ================================================================
// Isolation floor enforcement
// ================================================================

#[test]
fn isolation_floor_from_workload_class() {
    assert_eq!(
        IsolationFloor::from(WorkloadClass::PublicUntrusted),
        IsolationFloor::MicroVm
    );
    assert_eq!(
        IsolationFloor::from(WorkloadClass::TrustedFastPath),
        IsolationFloor::Container
    );
    assert_eq!(
        IsolationFloor::from(WorkloadClass::CompatibilityVm),
        IsolationFloor::MicroVm
    );
}

#[test]
fn runtime_isolation_floor_values() {
    assert_eq!(
        RuntimeType::Firecracker.isolation_floor(),
        IsolationFloor::MicroVm
    );
    assert_eq!(RuntimeType::Qemu.isolation_floor(), IsolationFloor::Vm);
    assert_eq!(
        RuntimeType::GVisor.isolation_floor(),
        IsolationFloor::Container
    );
}

#[test]
fn isolation_floor_ordering() {
    assert!(IsolationFloor::MicroVm > IsolationFloor::Container);
    assert!(IsolationFloor::Vm > IsolationFloor::MicroVm);
    assert!(IsolationFloor::Vm > IsolationFloor::Container);
}

// ================================================================
// Health gate
// ================================================================

#[test]
fn health_gate_rejects_unhealthy_backend() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let mut health: HashMap<RuntimeType, BackendHealth> = HashMap::new();
    health.insert(
        RuntimeType::Firecracker,
        BackendHealth {
            status: crate::runtime::BackendHealthStatus::Unavailable,
            checked_at: crate::types::now_iso(),
            message: Some("firecracker process crashed".into()),
        },
    );

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(&health),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(!rejected.is_empty());
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::HealthCapacity)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

// ================================================================
// Conformance status gate
// ================================================================

#[test]
fn conformance_gate_rejects_non_passing_backend() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let mut conformance: HashMap<RuntimeType, ConformanceStatus> = HashMap::new();
    conformance.insert(
        RuntimeType::Firecracker,
        ConformanceStatus {
            passing: false,
            profile: Some(WorkloadClass::PublicUntrusted),
        },
    );

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(&conformance),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(!rejected.is_empty());
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::ConformanceStatus)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

// ================================================================
// Selection result metadata
// ================================================================

#[test]
fn selection_records_metadata_on_success() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.workload_class, WorkloadClass::PublicUntrusted);
    assert_eq!(result.isolation_floor, IsolationFloor::MicroVm);
    assert!(result.tenant_id.is_some());
    assert_eq!(result.policy_epoch, Some(1));
    assert!(!result.decided_at.is_empty());
    assert!(result.required_capabilities.supports_all(&required));
}

// ================================================================
// Evaluation-only backends
// ================================================================

#[test]
fn production_eligibility() {
    assert!(RuntimeType::Firecracker.is_production_eligible());
    assert!(RuntimeType::Qemu.is_production_eligible());
    assert!(RuntimeType::GVisor.is_production_eligible());
    assert!(!RuntimeType::RemoteFirecracker.is_production_eligible());
}

#[test]
fn vm_boundary_classification() {
    assert!(RuntimeType::Firecracker.is_vm_boundary());
    assert!(RuntimeType::Qemu.is_vm_boundary());
    assert!(!RuntimeType::GVisor.is_vm_boundary());
}

#[test]
fn stranded_tenant_with_no_allowed_runtimes() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(vec![], vec![WorkloadClass::PublicUntrusted]);
    let caps = make_capabilities(&[]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    assert!(matches!(
        err,
        BackendSelectionError::NoBackendAvailable { .. }
    ));
}

// ================================================================
// Fail-closed gates
// ================================================================

#[test]
fn omitted_health_map_fails_closed() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: None,
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::HealthCapacity)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn omitted_conformance_map_fails_closed() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: None,
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::ConformanceStatus)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

#[test]
fn available_backends_rejects_missing_host_support() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[
        (
            RuntimeType::Firecracker,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
        (
            RuntimeType::Qemu,
            vec![
                crate::runtime::BackendCapability::Boot,
                crate::runtime::BackendCapability::GuestTransport,
                crate::runtime::BackendCapability::Exec,
                crate::runtime::BackendCapability::Health,
            ],
        ),
    ]);
    let required = default_required_capabilities();

    let result = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Qemu],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: false,
        })
        .unwrap();

    assert_eq!(result.selected, Some(RuntimeType::Qemu));
    assert_eq!(
        result.reason_code,
        SelectionReasonCode::FallbackBackendSelected
    );
    assert_eq!(
        result.rejected_candidates[0].runtime,
        RuntimeType::Firecracker
    );
    assert_eq!(
        result.rejected_candidates[0].gate,
        BackendSelectionGate::HostSupport
    );
}

#[test]
fn cross_tenant_without_cpu_policy_fails_closed() {
    let policy = BackendSelectionPolicy::new();
    let tenant = make_tenant(
        vec![RuntimeType::Firecracker],
        vec![WorkloadClass::PublicUntrusted],
    );
    let caps = make_capabilities(&[(
        RuntimeType::Firecracker,
        vec![
            crate::runtime::BackendCapability::Boot,
            crate::runtime::BackendCapability::GuestTransport,
            crate::runtime::BackendCapability::Exec,
            crate::runtime::BackendCapability::Health,
        ],
    )]);
    let required = default_required_capabilities();

    let err = policy
        .evaluate(&SelectionInputs {
            workload_class: WorkloadClass::PublicUntrusted,
            tenant: &tenant,
            required_capabilities: &required,
            available_backends: &[RuntimeType::Firecracker],
            backend_capabilities: &caps,
            conformance: Some(default_conformance()),
            host_health: Some(default_health()),
            cpu_isolation_policy: None,
            cross_tenant_host: true,
        })
        .unwrap_err();

    match err {
        BackendSelectionError::NoBackendAvailable { rejected, .. } => {
            assert!(
                rejected
                    .iter()
                    .any(|r| r.gate == BackendSelectionGate::CpuIsolation)
            );
        }
        other => panic!("expected NoBackendAvailable, got {other:?}"),
    }
}

// ================================================================
// WorkloadClass serde
// ================================================================

#[test]
fn workload_class_serde_kebab_case() {
    assert_eq!(
        serde_json::to_string(&WorkloadClass::PublicUntrusted).unwrap(),
        r#""public-untrusted""#
    );
    assert_eq!(
        serde_json::to_string(&WorkloadClass::TrustedFastPath).unwrap(),
        r#""trusted-fast-path""#
    );
    assert_eq!(
        serde_json::to_string(&WorkloadClass::CompatibilityVm).unwrap(),
        r#""compatibility-vm""#
    );

    let deser: WorkloadClass = serde_json::from_str(r#""public-untrusted""#).unwrap();
    assert_eq!(deser, WorkloadClass::PublicUntrusted);
}

#[test]
fn runtime_type_serde_kebab_case() {
    assert_eq!(
        serde_json::to_string(&RuntimeType::GVisor).unwrap(),
        r#""gvisor""#
    );
}
