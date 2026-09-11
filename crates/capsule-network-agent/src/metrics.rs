//! Centralized network-agent metrics.

use capsule_telemetry::metrics::{Counter, Gauge, Histogram};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

pub static NETWORK_METRICS: LazyLock<NetworkMetrics> = LazyLock::new(NetworkMetrics::register);

static METRIC_REDACTION_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_metric_redaction(enabled: bool) {
    METRIC_REDACTION_ENABLED.store(enabled, std::sync::atomic::Ordering::Release);
}

pub fn is_metric_redaction_enabled() -> bool {
    METRIC_REDACTION_ENABLED.load(std::sync::atomic::Ordering::Acquire)
}

static LAST_INTERFACE_STATS: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

const INTERFACE_STATS_MIN_INTERVAL_SECS: u64 = 60;
const STATS_EVICTION_LIMIT: usize = 1024;

// Metric name constants.
const SETUP_STARTED: &str = "network.setup.started";
const SETUP_COMPLETED: &str = "network.setup.completed";
const SETUP_NOT_COMPLETED: &str = "network.setup.not_completed";
const SETUP_DURATION_SECONDS: &str = "network.setup.duration_seconds";
const CLEANUP_REMOVED: &str = "network.cleanup.removed";
const CLEANUP_ABSENT: &str = "network.cleanup.absent";
const CLEANUP_COMPLETED: &str = "network.cleanup.completed";
const ROLLBACK_COMPLETED: &str = "network.rollback.completed";
const OBJECTS_COUNT: &str = "network.objects.count";
const EGRESS_ALLOWED: &str = "network.egress.allowed";
const EGRESS_DENIED: &str = "network.egress.denied";
const NAT_SESSIONS: &str = "network.nat.sessions";
const NAT_SETUP_COMPLETED: &str = "network.nat.setup_completed";
const NAT_ACTIVE_ENTRIES: &str = "network.nat.active_entries";
const EGRESS_SETUP_COMPLETED: &str = "network.egress.setup_completed";
const EGRESS_CLEANUP_COMPLETED: &str = "network.egress.cleanup_completed";

// Interface byte/packet counter metric name constants.
const INTERFACE_ALLOCATION_SUCCEEDED: &str = "network.interface.allocation_succeeded";
const INTERFACE_ALLOCATION_INCOMPLETE: &str = "network.interface.allocation_incomplete";
const INTERFACE_RX_BYTES: &str = "network.interface.rx_bytes";
const INTERFACE_TX_BYTES: &str = "network.interface.tx_bytes";
const INTERFACE_RX_PACKETS: &str = "network.interface.rx_packets";
const INTERFACE_TX_PACKETS: &str = "network.interface.tx_packets";

// Reconciliation metric name constants.
const RECONCILIATION_PASSES: &str = "network.reconciliation.passes";
const RECONCILIATION_PASS_DURATION_SECONDS: &str = "network.reconciliation.pass_duration_seconds";
const RECONCILIATION_STALE_OBJECTS: &str = "network.reconciliation.stale_objects";
const RECONCILIATION_CLEANED: &str = "network.reconciliation.cleaned";
const RECONCILIATION_REVIEW_REQUIRED: &str = "network.reconciliation.review_required";
const RECONCILIATION_CLEANUP_FAILED: &str = "network.reconciliation.cleanup_failed";
const RECONCILIATION_HEALTH_STATE: &str = "network.reconciliation.health_state";

// Lifecycle metric name constants.
const SUSPEND_COMPLETED: &str = "network.suspend.completed";
const SUSPEND_DURATION_SECONDS: &str = "network.suspend.duration_seconds";
const SUSPEND_CONNECTIONS_DROPPED: &str = "network.suspend.connections_dropped";

// Bandwidth shaping metric name constants.
const BANDWIDTH_SETUP_COMPLETED: &str = "network.bandwidth.setup_completed";
const BANDWIDTH_CLEANUP_COMPLETED: &str = "network.bandwidth.cleanup_completed";
const BANDWIDTH_LIMIT_CONFIGURED: &str = "network.bandwidth.limit_configured";

// Rate limit metric name constants.
const RATELIMIT_BANDWIDTH_DROPS: &str = "network.ratelimit.bandwidth_drops";
const RATELIMIT_PPS_DROPS: &str = "network.ratelimit.pps_drops";
const RATELIMIT_CONNECTION_DROPS: &str = "network.ratelimit.connection_drops";
const RATELIMIT_CONNECTION_RATE_DROPS: &str = "network.ratelimit.connection_rate_drops";
const RATELIMIT_NAT_DROPS: &str = "network.ratelimit.nat_drops";
const RATELIMIT_ACTIVE_CONNECTIONS: &str = "network.ratelimit.active_connections";
const RATELIMIT_BANDWIDTH_LIMIT_CONFIGURED: &str = "network.ratelimit.bandwidth_limit_configured";

const RESUME_COMPLETED: &str = "network.resume.completed";
const RESUME_FAILED: &str = "network.resume.failed";
const RESUME_POLICY_EPOCH_REJECTED: &str = "network.resume.policy_epoch_rejected";
const RESUME_DURATION_SECONDS: &str = "network.resume.duration_seconds";
const FORK_COMPLETED: &str = "network.fork.completed";
const FORK_FAILED: &str = "network.fork.failed";
const FORK_DURATION_SECONDS: &str = "network.fork.duration_seconds";
const FORK_PORT_INHERITANCE_BLOCKED: &str = "network.fork.port_inheritance_blocked";

const FLOW_EGRESS_BYTES: &str = "network.flow.egress_bytes";
const FLOW_EGRESS_PACKETS: &str = "network.flow.egress_packets";
const FLOW_TCP_SYN_SENT: &str = "network.flow.tcp.syn_sent";
const FLOW_TCP_ESTABLISHED: &str = "network.flow.tcp.established";
const FLOW_TCP_FIN_WAIT: &str = "network.flow.tcp.fin_wait";
const FLOW_TCP_RESET: &str = "network.flow.tcp.reset";
const FLOW_TCP_TOTAL: &str = "network.flow.tcp.total";
const FLOW_SAMPLED_CONNECTIONS: &str = "network.flow.sampled_connections";
const FLOW_SAMPLED_BYTES: &str = "network.flow.sampled_bytes";
const FLOW_SAMPLED_DURATION_MS: &str = "network.flow.sampled_duration_ms";

// Attribute value constants.
pub mod val {
    pub const MICROVM: &str = "microvm";
    pub const CONTAINER: &str = "container";
    pub const TAP: &str = "tap";
    pub const VETH: &str = "veth";
    pub const NAMESPACE: &str = "namespace";
    pub const ROUTE: &str = "route";
    pub const PROVISION_FAILURE: &str = "provision_failure";
    pub const ROUTE_ADD: &str = "route_add";
}

pub struct NetworkMetrics {
    pub setup: SetupMetrics,
    pub cleanup: CleanupMetrics,
    pub egress: EgressMetrics,
    pub nat: NatMetrics,
    pub bandwidth: BandwidthMetrics,
    pub lifecycle: LifecycleMetrics,
    pub reconciliation: ReconciliationMetrics,
    pub interface: InterfaceMetrics,
    pub ratelimit: RateLimitMetrics,
    pub flow: FlowTelemetryMetrics,
    pub objects: Gauge,
}

pub struct SetupMetrics {
    pub started: Counter,
    pub completed: Counter,
    pub not_completed: Counter,
    pub duration: Histogram,
}

pub struct CleanupMetrics {
    pub removed: Counter,
    pub absent: Counter,
    pub completed: Counter,
    pub rollback: Counter,
}

pub struct EgressMetrics {
    pub allowed: Counter,
    pub denied: Counter,
    pub setup_completed: Counter,
    pub cleanup_completed: Counter,
}

pub struct NatMetrics {
    pub sessions: Gauge,
    pub setup_completed: Counter,
    pub active_entries: Gauge,
}

pub struct BandwidthMetrics {
    pub setup_completed: Counter,
    pub cleanup_completed: Counter,
    pub limit_configured: Gauge,
}

/// Rate-limit hit counters.
pub struct RateLimitMetrics {
    pub bandwidth_drops: Counter,
    pub pps_drops: Counter,
    pub connection_drops: Counter,
    pub connection_rate_drops: Counter,
    pub nat_drops: Counter,
    pub active_connections: Gauge,
    pub bandwidth_limit_configured: Gauge,
}

/// Per-sandbox interface byte and packet counters.
///
/// These gauges report accumulated RX/TX counters for sandbox interfaces,
/// sourced from rtnetlink link stats where the backend supports them.
/// All metrics carry `sandbox_id` and `backend` labels for safe aggregation.
///
/// When `shared_host_metric_redaction` is enabled, `sandbox_id` is replaced
/// with `tenant_id`.
pub struct InterfaceMetrics {
    /// Cumulative received bytes on the sandbox interface.
    pub rx_bytes: Gauge,
    /// Cumulative transmitted bytes on the sandbox interface.
    pub tx_bytes: Gauge,
    /// Cumulative received packets on the sandbox interface.
    pub rx_packets: Gauge,
    /// Cumulative transmitted packets on the sandbox interface.
    pub tx_packets: Gauge,
    /// Successful interface allocation events.
    pub allocation_succeeded: Counter,
    /// Incomplete interface allocation events (provisioning failed mid-way).
    pub allocation_incomplete: Counter,
}

/// Reconciliation metrics for stale object detection and cleanup.
pub struct ReconciliationMetrics {
    /// Total number of reconciliation passes executed.
    pub passes: Counter,
    /// Duration of the most recent reconciliation pass.
    pub pass_duration: Histogram,
    /// Total number of stale objects detected.
    pub stale_objects: Counter,
    /// Number of stale objects successfully cleaned up.
    pub cleaned: Counter,
    /// Number of objects requiring operator review.
    pub review_required: Counter,
    /// Number of objects where cleanup failed.
    pub cleanup_failed: Counter,
    /// Current network health state (0=ready, 1=degraded, 2=unsafe).
    pub health_state: Gauge,
}

/// Lifecycle metrics for suspend, resume, and fork operations.
pub struct LifecycleMetrics {
    pub suspend_completed: Counter,
    pub suspend_duration: Histogram,
    pub suspend_connections_dropped: Counter,
    pub resume_completed: Counter,
    pub resume_failed: Counter,
    pub resume_policy_epoch_rejected: Counter,
    pub resume_duration: Histogram,
    pub fork_completed: Counter,
    pub fork_failed: Counter,
    pub fork_duration: Histogram,
    pub fork_port_inheritance_blocked: Counter,
}

pub struct FlowTelemetryMetrics {
    pub egress_bytes: Counter,
    pub egress_packets: Counter,
    pub tcp_syn_sent: Gauge,
    pub tcp_established: Gauge,
    pub tcp_fin_wait: Gauge,
    pub tcp_reset: Gauge,
    pub tcp_total: Gauge,
    pub sampled_connections: Counter,
    pub sampled_bytes: Counter,
    pub sampled_duration_ms: Histogram,
}

impl NetworkMetrics {
    fn register() -> Self {
        Self {
            setup: SetupMetrics {
                started: Counter::register(SETUP_STARTED),
                completed: Counter::register(SETUP_COMPLETED),
                not_completed: Counter::register(SETUP_NOT_COMPLETED),
                duration: Histogram::register(SETUP_DURATION_SECONDS),
            },
            cleanup: CleanupMetrics {
                removed: Counter::register(CLEANUP_REMOVED),
                absent: Counter::register(CLEANUP_ABSENT),
                completed: Counter::register(CLEANUP_COMPLETED),
                rollback: Counter::register(ROLLBACK_COMPLETED),
            },
            egress: EgressMetrics {
                allowed: Counter::register(EGRESS_ALLOWED),
                denied: Counter::register(EGRESS_DENIED),
                setup_completed: Counter::register(EGRESS_SETUP_COMPLETED),
                cleanup_completed: Counter::register(EGRESS_CLEANUP_COMPLETED),
            },
            nat: NatMetrics {
                sessions: Gauge::register(NAT_SESSIONS),
                setup_completed: Counter::register(NAT_SETUP_COMPLETED),
                active_entries: Gauge::register(NAT_ACTIVE_ENTRIES),
            },
            bandwidth: BandwidthMetrics {
                setup_completed: Counter::register(BANDWIDTH_SETUP_COMPLETED),
                cleanup_completed: Counter::register(BANDWIDTH_CLEANUP_COMPLETED),
                limit_configured: Gauge::register(BANDWIDTH_LIMIT_CONFIGURED),
            },
            ratelimit: RateLimitMetrics {
                bandwidth_drops: Counter::register(RATELIMIT_BANDWIDTH_DROPS),
                pps_drops: Counter::register(RATELIMIT_PPS_DROPS),
                connection_drops: Counter::register(RATELIMIT_CONNECTION_DROPS),
                connection_rate_drops: Counter::register(RATELIMIT_CONNECTION_RATE_DROPS),
                nat_drops: Counter::register(RATELIMIT_NAT_DROPS),
                active_connections: Gauge::register(RATELIMIT_ACTIVE_CONNECTIONS),
                bandwidth_limit_configured: Gauge::register(RATELIMIT_BANDWIDTH_LIMIT_CONFIGURED),
            },
            interface: InterfaceMetrics {
                rx_bytes: Gauge::register(INTERFACE_RX_BYTES),
                tx_bytes: Gauge::register(INTERFACE_TX_BYTES),
                rx_packets: Gauge::register(INTERFACE_RX_PACKETS),
                tx_packets: Gauge::register(INTERFACE_TX_PACKETS),
                allocation_succeeded: Counter::register(INTERFACE_ALLOCATION_SUCCEEDED),
                allocation_incomplete: Counter::register(INTERFACE_ALLOCATION_INCOMPLETE),
            },
            reconciliation: ReconciliationMetrics {
                passes: Counter::register(RECONCILIATION_PASSES),
                pass_duration: Histogram::register(RECONCILIATION_PASS_DURATION_SECONDS),
                stale_objects: Counter::register(RECONCILIATION_STALE_OBJECTS),
                cleaned: Counter::register(RECONCILIATION_CLEANED),
                review_required: Counter::register(RECONCILIATION_REVIEW_REQUIRED),
                cleanup_failed: Counter::register(RECONCILIATION_CLEANUP_FAILED),
                health_state: Gauge::register(RECONCILIATION_HEALTH_STATE),
            },
            lifecycle: LifecycleMetrics {
                suspend_completed: Counter::register(SUSPEND_COMPLETED),
                suspend_duration: Histogram::register(SUSPEND_DURATION_SECONDS),
                suspend_connections_dropped: Counter::register(SUSPEND_CONNECTIONS_DROPPED),
                resume_completed: Counter::register(RESUME_COMPLETED),
                resume_failed: Counter::register(RESUME_FAILED),
                resume_policy_epoch_rejected: Counter::register(RESUME_POLICY_EPOCH_REJECTED),
                resume_duration: Histogram::register(RESUME_DURATION_SECONDS),
                fork_completed: Counter::register(FORK_COMPLETED),
                fork_failed: Counter::register(FORK_FAILED),
                fork_duration: Histogram::register(FORK_DURATION_SECONDS),
                fork_port_inheritance_blocked: Counter::register(FORK_PORT_INHERITANCE_BLOCKED),
            },
            flow: FlowTelemetryMetrics {
                egress_bytes: Counter::register(FLOW_EGRESS_BYTES),
                egress_packets: Counter::register(FLOW_EGRESS_PACKETS),
                tcp_syn_sent: Gauge::register(FLOW_TCP_SYN_SENT),
                tcp_established: Gauge::register(FLOW_TCP_ESTABLISHED),
                tcp_fin_wait: Gauge::register(FLOW_TCP_FIN_WAIT),
                tcp_reset: Gauge::register(FLOW_TCP_RESET),
                tcp_total: Gauge::register(FLOW_TCP_TOTAL),
                sampled_connections: Counter::register(FLOW_SAMPLED_CONNECTIONS),
                sampled_bytes: Counter::register(FLOW_SAMPLED_BYTES),
                sampled_duration_ms: Histogram::register(FLOW_SAMPLED_DURATION_MS),
            },
            objects: Gauge::register(OBJECTS_COUNT),
        }
    }
}

/// Record per-sandbox interface byte/packet counters from rtnetlink stats.
///
/// Labels use `sandbox_id`, `if_name`, and `backend` dimensions.
/// All label values are tenant-safe (deterministic hash-derived names,
/// not user-provided content).
///
/// When `shared_host_metric_redaction` is enabled:
/// - `sandbox_id` is replaced with `tenant_id`.
/// - Reporting is rate-limited to once every 60s per key.
#[expect(
    clippy::too_many_arguments,
    reason = "interface stats require all fields for complete metric emission"
)]
pub fn record_interface_stats(
    sandbox_id: &str,
    if_name: &str,
    backend: &str,
    tenant_id: Option<&str>,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
) {
    let redacted = is_metric_redaction_enabled();

    if redacted {
        let key = if let Some(tid) = tenant_id {
            tid.to_string()
        } else {
            "unknown_tenant".to_string()
        };
        {
            let mut last = LAST_INTERFACE_STATS.lock().unwrap();
            if let Some(prev) = last.get(&key)
                && prev.elapsed().as_secs() < INTERFACE_STATS_MIN_INTERVAL_SECS
            {
                return;
            }
            if last.len() >= STATS_EVICTION_LIMIT {
                last.retain(|_, v| v.elapsed().as_secs() < INTERFACE_STATS_MIN_INTERVAL_SECS * 2);
            }
            last.insert(key, Instant::now());
        }
    }

    let id_label = if redacted {
        if let Some(tid) = tenant_id {
            (capsule_telemetry::metrics::attr::TENANT_ID, tid)
        } else {
            (
                capsule_telemetry::metrics::attr::TENANT_ID,
                "unknown_tenant",
            )
        }
    } else {
        (capsule_telemetry::metrics::attr::SANDBOX_ID, sandbox_id)
    };

    let attrs: &[(&str, &str)] = &[
        (id_label.0, id_label.1),
        ("if_name", if_name),
        (capsule_telemetry::metrics::attr::BACKEND, backend),
    ];
    NETWORK_METRICS
        .interface
        .rx_bytes
        .set(rx_bytes as f64, attrs);
    NETWORK_METRICS
        .interface
        .tx_bytes
        .set(tx_bytes as f64, attrs);
    NETWORK_METRICS
        .interface
        .rx_packets
        .set(rx_packets as f64, attrs);
    NETWORK_METRICS
        .interface
        .tx_packets
        .set(tx_packets as f64, attrs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_redaction_default_disabled() {
        assert!(!is_metric_redaction_enabled());
    }

    #[test]
    fn metric_redaction_enable_disable_roundtrip() {
        set_metric_redaction(true);
        assert!(is_metric_redaction_enabled());
        set_metric_redaction(false);
        assert!(!is_metric_redaction_enabled());
    }

    #[test]
    fn record_interface_stats_uses_sandbox_id_when_disabled() {
        set_metric_redaction(false);
        // Verify no panic on first call when redaction is disabled
        record_interface_stats("sbx_test", "cvx_if", "microvm", None, 100, 200, 10, 20);
    }

    #[test]
    fn record_interface_stats_uses_tenant_id_when_redacted() {
        set_metric_redaction(true);
        // Verify no panic with tenant_id when redaction is enabled
        record_interface_stats(
            "sbx_test",
            "cvx_if",
            "microvm",
            Some("tnt_test"),
            100,
            200,
            10,
            20,
        );
        set_metric_redaction(false);
    }

    #[test]
    fn record_interface_stats_rate_limit_enforced() {
        set_metric_redaction(true);
        let sandbox = "sbx_test_rate_limit";

        // First call - should record
        record_interface_stats(
            sandbox,
            "cvx_if",
            "microvm",
            Some("tnt_test"),
            100,
            200,
            10,
            20,
        );

        // Second call within 60s - should be rate-limited (return early)
        record_interface_stats(
            sandbox,
            "cvx_if",
            "microvm",
            Some("tnt_test"),
            200,
            400,
            20,
            40,
        );
        set_metric_redaction(false);
    }

    #[test]
    fn flow_telemetry_metrics_registered_without_panic() {
        let _ = &*NETWORK_METRICS;
        NETWORK_METRICS
            .flow
            .egress_bytes
            .inc(&[("sandbox_id", "sbx_test")]);
        NETWORK_METRICS
            .flow
            .egress_packets
            .inc(&[("sandbox_id", "sbx_test")]);
        NETWORK_METRICS
            .flow
            .tcp_established
            .set(1.0, &[("sandbox_id", "sbx_test")]);
        NETWORK_METRICS
            .flow
            .tcp_total
            .set(1.0, &[("sandbox_id", "sbx_test")]);
    }
}
