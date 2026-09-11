//! Wire round-trip tests for host-agent <-> sandboxd proto messages.

use capsule_sandboxd_proto::status::{
    SupervisorErrorClass, operation_kind, outcome_reason, outcome_status,
};
use capsule_sandboxd_proto::v1::{
    CommandMeta, Outcome, PortTarget, ResourceReceipt, SandboxObservation, port_target,
};
use prost::Message;
use tonic::Code;

fn sample_meta() -> CommandMeta {
    CommandMeta {
        sandbox_id: "sbx_01hxyz".into(),
        operation_id: "op_01hxyz".into(),
        assignment_fencing_token: "fence-7".into(),
        policy_epoch: 3,
        deadline_unix_ms: 1_700_000_000_000,
    }
}

#[test]
fn command_meta_round_trip() {
    let original = sample_meta();
    let bytes = original.encode_to_vec();
    let decoded = CommandMeta::decode(bytes.as_slice()).expect("decode CommandMeta");
    assert_eq!(decoded, original);
}

#[test]
fn outcome_round_trip() {
    let original = Outcome {
        operation_id: "op_1".into(),
        sandbox_id: "sbx_1".into(),
        kind: operation_kind::PREPARE.into(),
        status: outcome_status::SUCCEEDED.into(),
        reason_code: outcome_reason::COMPLETED.into(),
        non_ready_reason: None,
        message: Some("ok".into()),
        resources: vec![ResourceReceipt {
            class: "vm".into(),
            name: "fc-sbx_1".into(),
            external_id: Some("pid:123".into()),
            owner: "runtime".into(),
        }],
        observed_state: "Pending".into(),
        completed_at: "2026-07-23T00:00:00Z".into(),
    };
    let bytes = original.encode_to_vec();
    let decoded = Outcome::decode(bytes.as_slice()).expect("decode Outcome");
    assert_eq!(decoded, original);
    assert_eq!(decoded.resources.len(), 1);
    assert_eq!(decoded.resources[0].class, "vm");
}

#[test]
fn port_target_tcp_round_trip() {
    let original = PortTarget {
        guest_port: 8080,
        target: Some(port_target::Target::TcpAddr("10.0.0.2:8080".into())),
    };
    let bytes = original.encode_to_vec();
    let decoded = PortTarget::decode(bytes.as_slice()).expect("decode PortTarget");
    assert_eq!(decoded.guest_port, 8080);
    match decoded.target {
        Some(port_target::Target::TcpAddr(addr)) => assert_eq!(addr, "10.0.0.2:8080"),
        other => panic!("expected TcpAddr, got {other:?}"),
    }
}

#[test]
fn port_target_unsupported_round_trip() {
    let original = PortTarget {
        guest_port: 22,
        target: Some(port_target::Target::Unsupported(true)),
    };
    let bytes = original.encode_to_vec();
    let decoded = PortTarget::decode(bytes.as_slice()).expect("decode PortTarget");
    assert!(matches!(
        decoded.target,
        Some(port_target::Target::Unsupported(true))
    ));
}

#[test]
fn sandbox_observation_with_ports_round_trip() {
    let original = SandboxObservation {
        sandbox_id: "sbx_obs".into(),
        observed_state: "Running".into(),
        generation: 9,
        host_boot_id: "boot-a".into(),
        guest_boot_id: "gboot-b".into(),
        backend: "firecracker".into(),
        ports: vec![PortTarget {
            guest_port: 80,
            target: Some(port_target::Target::BackendManaged(true)),
        }],
        ssh: None,
        policy_epoch: 2,
        assignment_fencing_token: "fence-1".into(),
        updated_at: "2026-07-23T12:00:00Z".into(),
    };
    let bytes = original.encode_to_vec();
    let decoded = SandboxObservation::decode(bytes.as_slice()).expect("decode observation");
    assert_eq!(decoded.generation, 9);
    assert_eq!(decoded.ports.len(), 1);
    assert_eq!(decoded.observed_state, "Running");
}

#[test]
fn supervisor_error_class_codes_are_stable() {
    assert_eq!(
        SupervisorErrorClass::StaleFencingToken.tonic_code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        SupervisorErrorClass::RuntimeNotAttached.tonic_code(),
        Code::NotFound
    );
    assert_eq!(
        SupervisorErrorClass::Unauthenticated.tonic_code(),
        Code::Unauthenticated
    );
}
