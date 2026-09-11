//! sandboxd privileged OS process: sole RuntimeBackend owner over gRPC/UDS.

use anyhow::{Context, Result};
use capsule_sandboxd::config::{LogFormat, SandboxdConfig};
use capsule_sandboxd::grpc::server;
use capsule_sandboxd::init_seccomp;
use capsule_sandboxd::registry::AdapterRegistry;
use tokio::signal;
use tracing::info;

/// Builds the adapter registry for this process.
///
/// Production builds always return the real adapter set. With the
/// `mock-backend` feature (binary-level acceptance tests) and
/// `CAPSULE_SANDBOXD_MOCK_GUEST_ADDR` set, the Firecracker slot is replaced
/// by a `MockBackend` whose guest transport points at the given TCP address
/// (a real `capsule-guest-agent` process in those tests). The feature is
/// never enabled in release packaging. As an additional safety, the mock
/// path requires `CAPSULE_SANDBOXD_ALLOW_MOCK=1` so a release artifact built
/// with the feature cannot be switched to mock mode by a single env var.
fn build_registry() -> AdapterRegistry {
    #[cfg(feature = "mock-backend")]
    if let Ok(addr) = std::env::var("CAPSULE_SANDBOXD_MOCK_GUEST_ADDR")
        && std::env::var("CAPSULE_SANDBOXD_ALLOW_MOCK").as_deref() == Ok("1")
    {
        return mock_registry(&addr);
    }
    AdapterRegistry::default()
}

#[cfg(feature = "mock-backend")]
fn mock_registry(addr: &str) -> AdapterRegistry {
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;

    use capsule_core::{BackendOperation, RuntimeType};
    use capsule_runtime::mock::{MockBackend, MockBackendConfig, MockFailure};

    let guest_addr: std::net::SocketAddr = addr
        .parse()
        .expect("CAPSULE_SANDBOXD_MOCK_GUEST_ADDR must be a socket address");
    // Each backend instantiation appends one line so binary-level tests can
    // prove a daemon restart never silently re-creates a runtime.
    let count_file = std::env::var("CAPSULE_SANDBOXD_MOCK_BACKEND_COUNT_FILE").ok();
    let destroy_delay = std::env::var("CAPSULE_SANDBOXD_MOCK_DESTROY_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|ms| MockFailure::Delay {
            operation: BackendOperation::Destroy,
            duration: Duration::from_millis(ms),
        });

    let mut registry = AdapterRegistry::new();
    registry.register(RuntimeType::Firecracker, move || {
        if let Some(path) = count_file.as_deref()
            && let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            let _ = writeln!(file, "backend-created");
        }
        Arc::new(MockBackend::new(MockBackendConfig {
            guest_transport_addr: guest_addr,
            failure: destroy_delay.clone(),
            ..MockBackendConfig::default()
        })) as Arc<dyn capsule_core::RuntimeBackend>
    });
    info!(
        guest_addr = %guest_addr,
        "mock-backend feature active: Firecracker slot serves MockBackend"
    );
    registry
}

#[tokio::main]
async fn main() -> Result<()> {
    let config =
        SandboxdConfig::from_file_or_env().context("failed to load sandboxd configuration")?;

    let telemetry_config = capsule_telemetry::TelemetryConfig {
        settings: &capsule_telemetry::TelemetrySettings {
            log: capsule_telemetry::LogSettings {
                format: match config.log_format {
                    LogFormat::Pretty => capsule_telemetry::LogFormat::Pretty,
                    LogFormat::Json => capsule_telemetry::LogFormat::Json,
                },
                filter: "info,capsule_sandboxd=debug".to_string(),
                ..Default::default()
            },
            metrics: capsule_telemetry::MetricsSettings {
                service_name: "capsule-sandboxd".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
    };

    let driver = capsule_telemetry::init(telemetry_config)
        .map_err(|err| anyhow::anyhow!("failed to initialize telemetry: {err}"))?;
    tokio::spawn(driver);

    init_seccomp();

    info!(
        socket = %config.socket_path.display(),
        ledger = %config.ledger_path.display(),
        "sandboxd starting"
    );

    let registry = build_registry();
    server::run(config, registry, shutdown_signal()).await?;
    info!("sandboxd shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("shutdown signal received");
}
