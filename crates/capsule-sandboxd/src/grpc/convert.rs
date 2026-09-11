//! Conversions between wire protos and supervisor types.

use std::str::FromStr;

use capsule_core::{
    FencingToken, OperationId, RuntimeType, SandboxConfig, SandboxId, SandboxState, now_iso,
};
use capsule_sandboxd_proto::v1::{
    self, CommandMeta, HealthResponse, Outcome, PortTarget, SandboxObservation, port_target,
};
use capsule_sandboxd_proto::{
    SupervisorErrorClass, operation_kind, outcome_reason, outcome_status,
};
use tonic::Status;

use crate::{
    CommandContext, HostResourceSpec, ObservationWatchEvent, OperationKind, OperationOutcome,
    OutcomeReason, OutcomeStatus, PortTargetObservation, ResolvedPortTarget,
    SandboxObservationSnapshot, SecretsCoordinationError, SupervisorError, SupervisorHealth,
};

/// Maximum length for identifier strings (must match `ID_CAPACITY` in `ids.rs`).
const ID_MAX_LEN: usize = 128;

/// Parses [`CommandMeta`] into a supervisor [`CommandContext`].
pub(crate) fn command_context(meta: CommandMeta) -> Result<CommandContext, Status> {
    if meta.sandbox_id.is_empty() {
        return Err(Status::invalid_argument(
            "command meta sandbox_id is required",
        ));
    }
    if meta.sandbox_id.len() > ID_MAX_LEN {
        return Err(Status::invalid_argument(
            "sandbox_id exceeds maximum length",
        ));
    }
    if meta.operation_id.is_empty() {
        return Err(Status::invalid_argument(
            "command meta operation_id is required",
        ));
    }
    if meta.operation_id.len() > ID_MAX_LEN {
        return Err(Status::invalid_argument(
            "operation_id exceeds maximum length",
        ));
    }
    let assignment_fencing_token =
        FencingToken::from_str(&meta.assignment_fencing_token).map_err(Status::invalid_argument)?;
    Ok(CommandContext {
        sandbox_id: SandboxId::from_string(meta.sandbox_id),
        operation_id: OperationId::from_string(meta.operation_id),
        assignment_fencing_token,
        policy_epoch: meta.policy_epoch,
        deadline_unix_ms: meta.deadline_unix_ms,
    })
}

/// Maps proto prepare config into core [`SandboxConfig`].
pub(crate) fn sandbox_config(config: v1::SandboxConfig) -> Result<SandboxConfig, Status> {
    if config.id.is_empty() {
        return Err(Status::invalid_argument("sandbox config id is required"));
    }
    let ssh_port = match config.ssh_port {
        Some(port) => Some(
            u16::try_from(port)
                .map_err(|_| Status::invalid_argument("ssh_port out of u16 range"))?,
        ),
        None => None,
    };
    let cpu_set = if config.cpu_set.is_empty() {
        None
    } else {
        Some(config.cpu_set)
    };
    Ok(SandboxConfig {
        id: config.id,
        memory_limit_bytes: config.memory_limit_bytes,
        cpu_shares: config.cpu_shares,
        memory_soft_limit_bytes: config.memory_soft_limit_bytes,
        max_pids: config.max_pids,
        network_isolated: config.network_isolated,
        ssh_port,
        cpu_set,
        ..SandboxConfig::default()
    })
}

/// Parses a wire runtime type string.
pub(crate) fn runtime_type(value: &str) -> Result<RuntimeType, Status> {
    RuntimeType::from_str(value).map_err(|_| {
        Status::invalid_argument(format!(
            "unknown runtime_type {value:?}; expected firecracker|qemu|gvisor|remote-firecracker"
        ))
    })
}

/// Maps the optional wire host resource spec into supervisor inputs.
///
/// A missing spec yields defaults so resource-constrained values are derived
/// from the runtime config instead.
pub(crate) fn host_resource_spec(
    spec: Option<v1::HostResourceSpec>,
) -> Result<HostResourceSpec, Status> {
    let Some(spec) = spec else {
        return Ok(HostResourceSpec::default());
    };
    if spec
        .tenant_id
        .as_deref()
        .is_some_and(|tenant| tenant.len() > ID_MAX_LEN)
    {
        return Err(Status::invalid_argument("tenant_id exceeds maximum length"));
    }
    let mut requested_ports = Vec::with_capacity(spec.requested_ports.len());
    for port in spec.requested_ports {
        let port = u16::try_from(port).map_err(|_| {
            Status::invalid_argument(format!("requested_ports value {port} out of u16 range"))
        })?;
        if port != 0 {
            requested_ports.push(port);
        }
    }
    Ok(HostResourceSpec {
        vcpus: spec.vcpus,
        memory_mb: u64::from(spec.memory_mb),
        requested_ports,
        tenant_id: spec.tenant_id.filter(|tenant| !tenant.is_empty()),
        cross_tenant_host: spec.cross_tenant_host,
    })
}

/// Maps a supervisor outcome plus optional observed state onto the wire.
pub(crate) fn outcome_to_proto(
    outcome: OperationOutcome,
    observed_state: Option<SandboxState>,
) -> Outcome {
    Outcome {
        operation_id: outcome.operation_id.to_string(),
        sandbox_id: outcome.sandbox_id.to_string(),
        kind: operation_kind_wire(outcome.kind).into(),
        status: outcome_status_wire(outcome.status).into(),
        reason_code: outcome_reason_wire(outcome.reason).into(),
        non_ready_reason: outcome.non_ready_reason.map(|reason| reason.to_string()),
        message: outcome.message,
        resources: Vec::new(),
        observed_state: observed_state
            .map(SandboxState::as_str)
            .unwrap_or_default()
            .into(),
        completed_at: outcome.completed_at,
    }
}

/// Maps an enriched supervisor observation onto the wire snapshot.
pub(crate) fn snapshot_to_observation(snapshot: SandboxObservationSnapshot) -> SandboxObservation {
    let SandboxObservationSnapshot {
        status,
        generation,
        guest_boot_id,
        ports,
    } = snapshot;
    SandboxObservation {
        sandbox_id: status.sandbox_id.to_string(),
        observed_state: status.observed_state.as_str().into(),
        generation,
        host_boot_id: status.host_boot_id,
        guest_boot_id,
        backend: status.runtime.to_string(),
        ports: ports.into_iter().map(port_target_to_proto).collect(),
        ssh: None,
        policy_epoch: status.policy_epoch,
        assignment_fencing_token: status.assignment_fencing_token.to_string(),
        updated_at: status.updated_at,
    }
}

/// Maps one resolved port target onto the wire `PortTarget`.
pub(crate) fn port_target_to_proto(port: PortTargetObservation) -> PortTarget {
    let target = match port.target {
        ResolvedPortTarget::Tcp(addr) => port_target::Target::TcpAddr(addr.to_string()),
        ResolvedPortTarget::BackendManaged => port_target::Target::BackendManaged(true),
        ResolvedPortTarget::Unsupported => port_target::Target::Unsupported(true),
    };
    PortTarget {
        guest_port: u32::from(port.guest_port),
        target: Some(target),
    }
}

/// Maps an internal watch event onto the wire `WatchEvent`.
pub(crate) fn watch_event_to_proto(
    event: ObservationWatchEvent,
) -> capsule_sandboxd_proto::v1::WatchEvent {
    use capsule_sandboxd_proto::v1::{ReconcileStatus, WatchEvent, watch_event};
    match event {
        ObservationWatchEvent::Upsert(snapshot) => WatchEvent {
            body: Some(watch_event::Body::Upsert(snapshot_to_observation(snapshot))),
        },
        ObservationWatchEvent::Removed(sandbox_id) => WatchEvent {
            body: Some(watch_event::Body::RemovedSandboxId(sandbox_id.to_string())),
        },
        ObservationWatchEvent::Reconcile {
            complete,
            review_findings,
            host_boot_id,
        } => WatchEvent {
            body: Some(watch_event::Body::Reconcile(ReconcileStatus {
                complete,
                review_findings,
                host_boot_id,
            })),
        },
    }
}

/// Maps supervisor health into the Health RPC response.
///
/// `supported_runtimes` is the sandboxd registry's actual set of registered
/// backend families, so the host advertises exactly what placement can run.
pub(crate) fn health_to_proto(
    health: SupervisorHealth,
    host_boot_id: &str,
    supported_runtimes: &[RuntimeType],
) -> HealthResponse {
    HealthResponse {
        ready_for_work: health.ready,
        reconcile_complete: health.ready,
        review_findings: health.review_required,
        host_boot_id: host_boot_id.to_string(),
        supported_runtimes: supported_runtimes.iter().map(|r| r.to_string()).collect(),
    }
}

/// Builds a cancel Outcome. Only called when the supervisor actually canceled; the
/// "no active operation" case returns `NotFound` at the service layer.
pub(crate) fn cancel_outcome(operation_id: &str, sandbox_id: &str) -> Outcome {
    Outcome {
        operation_id: operation_id.to_string(),
        sandbox_id: sandbox_id.to_string(),
        kind: String::new(),
        status: outcome_status::CANCELED.into(),
        reason_code: outcome_reason::CANCELED_BY_HOST.into(),
        non_ready_reason: None,
        message: Some("operation cancel requested".into()),
        resources: Vec::new(),
        observed_state: String::new(),
        completed_at: now_iso(),
    }
}

/// Maps supervisor errors to gRPC statuses (not Outcome bodies).
pub(crate) fn supervisor_error_to_status(error: SupervisorError) -> Status {
    let class = match &error {
        SupervisorError::Ledger(_) => SupervisorErrorClass::Ledger,
        SupervisorError::Io(_) => SupervisorErrorClass::Io,
        SupervisorError::InvalidLedgerValue(_) => SupervisorErrorClass::InvalidLedgerValue,
        SupervisorError::StaleFencingToken { .. } => SupervisorErrorClass::StaleFencingToken,
        SupervisorError::OperationInProgress(_) => SupervisorErrorClass::OperationInProgress,
        SupervisorError::OperationIdentityConflict(_) => {
            SupervisorErrorClass::OperationIdentityConflict
        }
        SupervisorError::StalePolicyEpoch { .. } => SupervisorErrorClass::StalePolicyEpoch,
        SupervisorError::RuntimeNotAttached(_) => SupervisorErrorClass::RuntimeNotAttached,
        SupervisorError::SandboxMismatch { .. } => SupervisorErrorClass::SandboxMismatch,
        SupervisorError::InvalidProcessRequest(_) => SupervisorErrorClass::InvalidProcessRequest,
        SupervisorError::GuestSession(msg) if msg.contains("exceeds max_bytes") => {
            return Status::resource_exhausted(error.to_string());
        }
        // Only the missing-session message means the sandbox is not ready for
        // exec yet (e.g. the guest handshake has not completed), which is a
        // transient UNAVAILABLE. Other GuestSession failures are definitive
        // application errors and must not be retried as if the service were
        // briefly down.
        SupervisorError::GuestSession(msg) if msg.contains("has no guest session") => {
            return Status::unavailable(error.to_string());
        }
        SupervisorError::GuestSession(msg) if msg.contains("exec stream canceled") => {
            return Status::aborted(error.to_string());
        }
        SupervisorError::GuestSession(msg) if msg.contains("exec stream timed out") => {
            return Status::deadline_exceeded(error.to_string());
        }
        SupervisorError::GuestSession(_) => SupervisorErrorClass::Internal,
        SupervisorError::Secrets(err) => match err {
            SecretsCoordinationError::LeaseValidation(_) => {
                return Status::permission_denied(error.to_string());
            }
            SecretsCoordinationError::InvalidRequest(_) => {
                return Status::invalid_argument(error.to_string());
            }
            SecretsCoordinationError::Broker(_) | SecretsCoordinationError::GuestInjection(_) => {
                SupervisorErrorClass::Internal
            }
        },
    };
    class.status(error.to_string())
}

fn operation_kind_wire(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::Prepare => operation_kind::PREPARE,
        OperationKind::Boot => operation_kind::BOOT,
        OperationKind::Exec => operation_kind::EXEC,
        OperationKind::Suspend => operation_kind::SUSPEND,
        OperationKind::Resume => operation_kind::RESUME,
        OperationKind::Destroy => operation_kind::DESTROY,
        OperationKind::Process => operation_kind::PROCESS,
    }
}

fn outcome_status_wire(status: OutcomeStatus) -> &'static str {
    match status {
        OutcomeStatus::Running => outcome_status::RUNNING,
        OutcomeStatus::Succeeded => outcome_status::SUCCEEDED,
        OutcomeStatus::Failed => outcome_status::FAILED,
        OutcomeStatus::Canceled => outcome_status::CANCELED,
        OutcomeStatus::TimedOut => outcome_status::TIMED_OUT,
        OutcomeStatus::RequiresReview => outcome_status::REQUIRES_REVIEW,
    }
}

fn outcome_reason_wire(reason: OutcomeReason) -> &'static str {
    match reason {
        OutcomeReason::InProgress => outcome_reason::IN_PROGRESS,
        OutcomeReason::Completed => outcome_reason::COMPLETED,
        OutcomeReason::BackendFailure => outcome_reason::BACKEND_FAILURE,
        OutcomeReason::CanceledByHost => outcome_reason::CANCELED_BY_HOST,
        OutcomeReason::DeadlineExceeded => outcome_reason::DEADLINE_EXCEEDED,
        OutcomeReason::PartialCleanup => outcome_reason::PARTIAL_CLEANUP,
        OutcomeReason::SupervisorRestarted => outcome_reason::SUPERVISOR_RESTARTED,
        OutcomeReason::ProcessExited => outcome_reason::PROCESS_EXITED,
        OutcomeReason::ProcessSignaled => outcome_reason::PROCESS_SIGNALED,
        OutcomeReason::ProcessFailure => outcome_reason::PROCESS_FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use capsule_core::{FencingToken, RuntimeType, SandboxId, SandboxState};
    use capsule_sandboxd_proto::v1::{port_target, watch_event};

    use crate::SandboxStatus;

    #[test]
    fn parses_fencing_token_meta() {
        let meta = CommandMeta {
            sandbox_id: "sbx_1".into(),
            operation_id: "op_1".into(),
            assignment_fencing_token: "7.3".into(),
            policy_epoch: 1,
            deadline_unix_ms: 1,
        };
        let ctx = command_context(meta).unwrap();
        assert_eq!(
            ctx.assignment_fencing_token,
            FencingToken {
                epoch: 7,
                sequence: 3
            }
        );
    }

    #[test]
    fn rejects_oversized_sandbox_id() {
        let mut meta = CommandMeta {
            sandbox_id: "sbx_1".into(),
            operation_id: "opr_1".into(),
            assignment_fencing_token: "7.3".into(),
            policy_epoch: 1,
            deadline_unix_ms: 1,
        };
        meta.sandbox_id = format!("sbx_{:0>200}", "");
        let err = command_context(meta).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn rejects_oversized_operation_id() {
        let mut meta = CommandMeta {
            sandbox_id: "sbx_1".into(),
            operation_id: "opr_1".into(),
            assignment_fencing_token: "7.3".into(),
            policy_epoch: 1,
            deadline_unix_ms: 1,
        };
        meta.operation_id = format!("opr_{:0>200}", "");
        let err = command_context(meta).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn rejects_bad_fencing_token() {
        let meta = CommandMeta {
            sandbox_id: "sbx_1".into(),
            operation_id: "op_1".into(),
            assignment_fencing_token: "not-a-token".into(),
            policy_epoch: 1,
            deadline_unix_ms: 1,
        };
        let err = command_context(meta).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn host_resource_spec_parses_requested_ports_and_skips_zero() {
        let spec = host_resource_spec(Some(v1::HostResourceSpec {
            vcpus: 2,
            memory_mb: 512,
            requested_ports: vec![0, 22, 8080],
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(spec.requested_ports, vec![22, 8080]);
        assert_eq!(spec.vcpus, 2);
        assert_eq!(spec.memory_mb, 512);
    }

    #[test]
    fn host_resource_spec_rejects_port_outside_u16() {
        let err = host_resource_spec(Some(v1::HostResourceSpec {
            vcpus: 1,
            memory_mb: 128,
            requested_ports: vec![u32::from(u16::MAX) + 1],
            ..Default::default()
        }))
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("out of u16 range"));
    }

    #[test]
    fn host_resource_spec_none_is_default() {
        let spec = host_resource_spec(None).unwrap();
        assert!(spec.requested_ports.is_empty());
    }

    #[test]
    fn port_target_to_proto_maps_all_variants() {
        let tcp = port_target_to_proto(PortTargetObservation {
            guest_port: 8080,
            target: ResolvedPortTarget::Tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))),
        });
        assert_eq!(tcp.guest_port, 8080);
        assert!(matches!(
            tcp.target,
            Some(port_target::Target::TcpAddr(addr)) if addr == "127.0.0.1:8080"
        ));

        let managed = port_target_to_proto(PortTargetObservation {
            guest_port: 22,
            target: ResolvedPortTarget::BackendManaged,
        });
        assert!(matches!(
            managed.target,
            Some(port_target::Target::BackendManaged(true))
        ));

        let unsupported = port_target_to_proto(PortTargetObservation {
            guest_port: 9,
            target: ResolvedPortTarget::Unsupported,
        });
        assert!(matches!(
            unsupported.target,
            Some(port_target::Target::Unsupported(true))
        ));
    }

    fn sample_snapshot() -> SandboxObservationSnapshot {
        SandboxObservationSnapshot {
            status: SandboxStatus {
                sandbox_id: SandboxId::from_string("sbx_obs"),
                assignment_fencing_token: FencingToken {
                    epoch: 1,
                    sequence: 2,
                },
                policy_epoch: 3,
                runtime: RuntimeType::Firecracker,
                backend_version: "mock".into(),
                observed_state: SandboxState::Running,
                host_boot_id: "host-boot".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
            },
            generation: 7,
            guest_boot_id: "guest-boot".into(),
            ports: vec![PortTargetObservation {
                guest_port: 80,
                target: ResolvedPortTarget::Tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 80))),
            }],
        }
    }

    #[test]
    fn snapshot_to_observation_copies_generation_ports_and_ids() {
        let obs = snapshot_to_observation(sample_snapshot());
        assert_eq!(obs.sandbox_id, "sbx_obs");
        assert_eq!(obs.generation, 7);
        assert_eq!(obs.guest_boot_id, "guest-boot");
        assert_eq!(obs.host_boot_id, "host-boot");
        assert_eq!(obs.observed_state, SandboxState::Running.as_str());
        assert_eq!(obs.policy_epoch, 3);
        assert_eq!(obs.assignment_fencing_token, "1.2");
        assert_eq!(obs.ports.len(), 1);
        assert_eq!(obs.ports[0].guest_port, 80);
    }

    #[test]
    fn watch_event_to_proto_maps_upsert_removed_and_reconcile() {
        let upsert = watch_event_to_proto(ObservationWatchEvent::Upsert(sample_snapshot()));
        assert!(matches!(
            upsert.body,
            Some(watch_event::Body::Upsert(obs)) if obs.sandbox_id == "sbx_obs" && obs.generation == 7
        ));

        let removed = watch_event_to_proto(ObservationWatchEvent::Removed(SandboxId::from_string(
            "sbx_gone",
        )));
        assert!(matches!(
            removed.body,
            Some(watch_event::Body::RemovedSandboxId(id)) if id == "sbx_gone"
        ));

        let reconcile = watch_event_to_proto(ObservationWatchEvent::Reconcile {
            complete: true,
            review_findings: 2,
            host_boot_id: "boot".into(),
        });
        match reconcile.body {
            Some(watch_event::Body::Reconcile(status)) => {
                assert!(status.complete);
                assert_eq!(status.review_findings, 2);
                assert_eq!(status.host_boot_id, "boot");
            }
            other => panic!("expected reconcile, got {other:?}"),
        }
    }
}
