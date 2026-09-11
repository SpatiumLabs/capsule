use capsule_core::{
    BackendCapabilities, BackendCapability, BackendOperation, ExecRequest, RuntimeBackend,
    SandboxConfig,
};
use capsule_runtime::conformance::{
    ConformanceProfile, run_backend_conformance, run_lifecycle_suite,
};
use capsule_runtime::mock::{MockBackend, MockBackendConfig, MockFailure};

fn profile() -> ConformanceProfile {
    ConformanceProfile {
        sandbox: SandboxConfig {
            id: "sbx_conformance_test".into(),
            memory_limit_bytes: 512 * 1024 * 1024,
            network_isolated: true,
            ..Default::default()
        },
        exec: ExecRequest {
            command: "true".into(),
            args: Vec::new(),
            env: None,
            working_dir: None,
            timeout_secs: Some(1),
        },
        fork_child: Some(SandboxConfig {
            id: "sbx_conformance_test-child".into(),
            memory_limit_bytes: 512 * 1024 * 1024,
            network_isolated: true,
            ..Default::default()
        }),
    }
}

#[tokio::test]
async fn full_suite_passes_with_mock_default() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(
        report.passed,
        "conformance suite did not pass. Failures:\n{:#?}",
        report.failures()
    );
    assert!(
        report.missing_capabilities.is_empty(),
        "missing capabilities: {:?}",
        report.missing_capabilities
    );
}

#[tokio::test]
async fn suite_reports_missing_capabilities() {
    let backend = MockBackend::new(MockBackendConfig {
        capabilities: BackendCapabilities::from([BackendCapability::Boot]),
        ..Default::default()
    });

    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(!report.passed);
    assert!(!report.missing_capabilities.is_empty());
    assert!(
        report
            .missing_capabilities
            .contains(&BackendCapability::GuestTransport)
    );
}

#[tokio::test]
async fn suite_reports_unsupported_capabilities() {
    let backend = MockBackend::new(MockBackendConfig {
        capabilities: BackendCapabilities::from([
            BackendCapability::Boot,
            BackendCapability::GuestTransport,
            BackendCapability::GuestReadiness,
            BackendCapability::Exec,
            BackendCapability::Stats,
            BackendCapability::Health,
            BackendCapability::Diagnostics,
        ]),
        ..Default::default()
    });

    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(
        report
            .unsupported_capabilities
            .contains(&BackendCapability::Suspend)
    );
    assert!(
        report
            .unsupported_capabilities
            .contains(&BackendCapability::Resume)
    );
    assert!(
        report
            .unsupported_capabilities
            .contains(&BackendCapability::Fork)
    );
    assert!(
        report
            .unsupported_capabilities
            .contains(&BackendCapability::BackendManagedPortForwarding)
    );
}

#[tokio::test]
async fn suite_records_checks_with_latency() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(!report.checks.is_empty());
    for check in &report.checks {
        assert!(!check.name.is_empty());
    }
}

#[tokio::test]
async fn suite_reports_failures_as_struct() {
    let backend = MockBackend::new(MockBackendConfig {
        failure: Some(MockFailure::Timeout {
            operation: BackendOperation::Boot,
        }),
        ..Default::default()
    });

    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(!report.passed);
    let failures = report.failures();
    assert!(!failures.is_empty(), "expected failures, got: {report:#?}");
}

#[tokio::test]
async fn backward_compat_runner_still_works() {
    let backend = MockBackend::default();
    let profile = profile();

    let ops = run_backend_conformance(&backend, &profile).await.unwrap();

    assert_eq!(ops.first(), Some(&BackendOperation::Prepare));
    assert_eq!(ops.last(), Some(&BackendOperation::Cleanup));
}

#[tokio::test]
async fn destroy_idempotency_succeeds_with_mock() {
    let backend = MockBackend::default();
    let _ = backend.prepare(&profile().sandbox).await;
    let _ = backend.boot().await;
    assert!(backend.destroy().await.is_ok());
    assert!(backend.destroy().await.is_ok());
}

#[tokio::test]
async fn cleanup_idempotency_succeeds_with_mock() {
    let backend = MockBackend::default();
    let _ = backend.prepare(&profile().sandbox).await;
    let _ = backend.boot().await;
    let _ = backend.destroy().await;
    assert!(backend.cleanup().await.is_ok());
    assert!(backend.cleanup().await.is_ok());
}

#[tokio::test]
async fn resource_accounting_tracks_prepare_resources() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    assert!(!report.resource_accounting.resource_classes.is_empty());
    assert!(report.resource_accounting.total_receipts > 0);
}

#[tokio::test]
async fn observability_latency_bounds_pass_for_mock() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let latency_check = report
        .checks
        .iter()
        .find(|c| c.name == "observability/latency-bounds")
        .expect("latency-bounds check should exist");
    assert!(latency_check.passed);
}

#[tokio::test]
async fn observability_resource_classes_present() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let resource_check = report
        .checks
        .iter()
        .find(|c| c.name == "observability/resource-classes-present")
        .expect("resource-classes-present check should exist");
    assert!(resource_check.passed);
}

#[tokio::test]
async fn observability_stats_memory_nonzero() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let memory_check = report
        .checks
        .iter()
        .find(|c| c.name == "observability/stats-memory-nonzero")
        .expect("stats-memory-nonzero check should exist");
    assert!(memory_check.passed);
}

#[tokio::test]
async fn observability_diagnostics_has_summary() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let diag_check = report
        .checks
        .iter()
        .find(|c| c.name == "observability/diagnostics-has-summary")
        .expect("diagnostics-has-summary check should exist");
    assert!(diag_check.passed);
}

#[tokio::test]
async fn render_json_produces_valid_output() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let json = report.to_json();
    assert!(json.is_object());
    assert_eq!(json["passed"], true);
    assert!(json["checks"].is_array());
    assert!(!json["checks"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn display_format_includes_status_and_checks() {
    let backend = MockBackend::default();
    let report = run_lifecycle_suite(&backend, &profile()).await.unwrap();

    let text = report.to_string();
    assert!(text.contains("PASS"));
    assert!(text.contains("lifecycle/prepare"));
    assert!(text.contains("Total latency"));
}
