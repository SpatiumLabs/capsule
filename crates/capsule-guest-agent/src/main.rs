//! Runs the in-guest command execution service used by Capsule runtimes.
//!
//! Single wire format: every connection is a framed-protobuf bootstrap
//! handshake followed by the operational protocol on the same stream.
//! The legacy JSON-RPC 2.0 path has been removed.

mod exec;
mod file;
mod handshake;
mod health;
mod mount;
mod secrets;
mod shutdown;
mod stats;

use std::time::Duration;

use tokio::net::TcpListener;

use capsule_guest_protocol::FramedConnection;

const OPERATIONAL_TIMEOUT_SECS: u64 = 300;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing::info!("Guest Agent starting...");

    capsule_guest_agent_init_seccomp();

    let identity = load_identity().unwrap_or_default();
    let sandbox_id = read_sandbox_id().unwrap_or_else(|| "unknown-sandbox".into());
    let shared_secret = capsule_core::crypto::derive_handshake_shared_secret(&sandbox_id);
    let listen_port = read_listen_port();

    tracing::info!(
        image_id = %identity.image_id,
        boot_id = %identity.boot_id,
        sandbox_id = %sandbox_id,
        agent_version = %identity.agent_version,
        "guest agent initialized"
    );

    let listener = TcpListener::bind(("0.0.0.0", listen_port)).await?;
    tracing::info!("Listening for host connections on port {listen_port}");

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let identity = identity.clone();
        let shared_secret = shared_secret.clone();
        let sandbox_id = sandbox_id.clone();

        tokio::spawn(async move {
            tracing::debug!(peer = %peer_addr, "new connection");
            handle_handshake_connection(socket, &identity, &shared_secret, &sandbox_id).await;
        });
    }
}

async fn handle_handshake_connection(
    mut socket: tokio::net::TcpStream,
    identity: &handshake::GuestIdentity,
    shared_secret: &heapless::Vec<u8, 32>,
    sandbox_id: &str,
) {
    match handshake::serve_handshake(&mut socket, identity, shared_secret.clone()).await {
        Ok(Some(outcome)) => {
            tracing::info!(
                boot_id = %identity.boot_id,
                sandbox_id = %sandbox_id,
                "handshake completed, entering operational mode"
            );

            let session = exec::OperationalSession::new(&outcome, sandbox_id.to_string());
            let conn = FramedConnection::new(socket, Duration::from_secs(OPERATIONAL_TIMEOUT_SECS));
            exec::serve_operational(conn, session).await;
        }
        Ok(None) => {
            tracing::warn!("handshake rejected by guest");
        }
        Err(err) => {
            tracing::error!(error = %err, "handshake failed");
        }
    }
}

fn load_identity() -> Option<handshake::GuestIdentity> {
    let manifest_paths = [
        "/etc/capsule/manifest.json",
        "/opt/capsule/manifest.json",
        "/capsule/manifest.json",
    ];

    for path in &manifest_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            tracing::info!(path = %path, "loaded image manifest");
            return handshake::parse_manifest_json(&content);
        }
    }

    tracing::warn!("no image manifest found, using default identity");
    None
}

fn read_sandbox_id() -> Option<String> {
    // Kernel cmdline is the boot-time authority supplied by the hypervisor;
    // environment is only a test escape hatch for host-process testing. Checking
    // cmdline first prevents a compromised guest environment from overriding the
    // hypervisor-provided identity.
    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline")
        && let Some(id) = handshake::parse_sandbox_id_from_cmdline(&cmdline)
    {
        tracing::info!(sandbox_id = %id, "read sandbox_id from kernel cmdline");
        return Some(id);
    }

    if let Ok(id) = std::env::var("CAPSULE_SANDBOX_ID")
        && !id.trim().is_empty()
    {
        tracing::info!(sandbox_id = %id, "read sandbox_id from CAPSULE_SANDBOX_ID");
        return Some(id.trim().to_string());
    }

    tracing::warn!("no sandbox_id found in /proc/cmdline or CAPSULE_SANDBOX_ID");
    None
}

fn read_listen_port() -> u16 {
    std::env::var("CAPSULE_GUEST_AGENT_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(9999)
}

fn capsule_guest_agent_init_seccomp() {
    use capsule_seccomp::{CapabilitySet, ComponentProfile};
    use tracing::info;

    info!("initializing seccomp and capability minimization for guest-agent");

    let _ = capsule_seccomp::init_profile_for_component_with_strictness(
        ComponentProfile::GuestAgent,
        &CapabilitySet::guest_agent(),
        true,
        false,
    );
}
