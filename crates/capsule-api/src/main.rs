//! Starts the Capsule HTTP API and selects the configured sandbox runtime.

use std::backtrace::Backtrace;
use std::panic::PanicHookInfo;
use std::sync::Arc;

use anyhow::{Context, Result};
use capsule_api::build_router;
use capsule_api::{AppConfig, PolicyEnforcingAgent, RuntimeBackend};
use capsule_core::{
    Admission, LeaseAuthority, PolicyEngine, PrincipalId, QuotaEngine, SandboxFacade, TenantId,
};
use capsule_host_agent::{HostAgent, stub::StubAgent};
use tokio::signal;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::from_env()?;
    let log_format = match config.run_env {
        capsule_api::RunEnv::Development => capsule_telemetry::LogFormat::Pretty,
        capsule_api::RunEnv::Production => capsule_telemetry::LogFormat::Json,
    };

    let log_filter = match config.run_env {
        capsule_api::RunEnv::Development => "info,capsule_api=debug,tower_http=debug",
        capsule_api::RunEnv::Production => "warn,capsule_api=info,tower_http=info",
    };

    let telemetry_config = capsule_telemetry::TelemetryConfig {
        settings: &capsule_telemetry::TelemetrySettings {
            log: capsule_telemetry::LogSettings {
                format: log_format,
                filter: log_filter.to_string(),
                ..Default::default()
            },
            metrics: capsule_telemetry::MetricsSettings {
                service_name: "capsule-api".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
    };

    let driver = capsule_telemetry::init(telemetry_config)
        .map_err(|e| anyhow::anyhow!("failed to initialize telemetry: {e}"))?;

    tokio::spawn(driver);
    install_panic_hook();

    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .with_context(|| format!("failed to bind TCP listener at {}", config.bind_addr))?;
    let state = build_state(&config).await?;
    let app = build_router(state, config.token.clone());

    print_app_info(&config);
    info!(addr = %config.bind_addr, "Capsule API is listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    info!("shutdown complete");
    Ok(())
}

async fn build_state(config: &AppConfig) -> Result<Arc<dyn SandboxFacade>> {
    let authority = match config.lease_signing_key.as_deref() {
        Some(encoded) => LeaseAuthority::from_signing_key_base64(encoded)
            .map_err(|e| anyhow::anyhow!("CAPSULE_LEASE_SIGNING_KEY: {e}"))?,
        None => LeaseAuthority::generate(),
    };
    info!(
        verifying_key = %authority.verifying_key_base64(),
        "lease authority ready"
    );

    let policy = Arc::new(PolicyEngine::new());
    policy
        .load_policies(&config.policy_text)
        .map_err(|e| anyhow::anyhow!("failed to load admission policy: {e}"))?;
    let admission = Arc::new(Admission::new(
        policy,
        Arc::new(QuotaEngine::new()),
        authority.clone(),
    ));

    let inner: Arc<dyn SandboxFacade> = match config.runtime {
        RuntimeBackend::Stub => Arc::new(
            StubAgent::new(config.workspace_root.clone())
                .context("failed to initialize stub agent")?,
        ),
        RuntimeBackend::Host(runtime) => {
            let host = HostAgent::with_public_host(
                config.workspace_root.clone(),
                config.idle_timeout_secs,
                runtime,
                config.public_host.clone(),
            )
            .await
            .context("failed to initialize host agent")?;
            Arc::new(host.with_lease_authority(authority))
        }
    };

    Ok(Arc::new(PolicyEnforcingAgent::with_admission(
        inner,
        admission,
        TenantId::from_string(&config.tenant_id),
        PrincipalId::new(config.principal_id.clone()),
    )))
}

/// Waits for process termination signals so the API can shut down cleanly.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = signal::ctrl_c().await {
            error!(error = %err, "failed to install Ctrl+C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => signal.recv().await,
            Err(err) => {
                error!(error = %err, "failed to install SIGTERM handler");
                None
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}

fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info: &PanicHookInfo<'_>| {
        let location = panic_info
            .location()
            .map(|location| format!("{}:{}", location.file(), location.line()))
            .unwrap_or_else(|| "<unknown location>".to_string());

        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .map(|msg| (*msg).to_string())
            .or_else(|| panic_info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic payload".to_string());

        error!("CAPSULE_API_BOOT: panic at {location}: {payload}");
        error!(
            "CAPSULE_API_BOOT: backtrace:\n{}",
            Backtrace::force_capture()
        );

        default_hook(panic_info);
    }));
}

fn print_app_info(config: &AppConfig) {
    println!(
        "\n\tApplication: {}\n\tVersion: {}\n\tEnvironment: {}\n\tListening on: {}\n\tBackend: {:?}\n",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        config.run_env.as_str(),
        config.bind_addr,
        config.runtime
    );
}
