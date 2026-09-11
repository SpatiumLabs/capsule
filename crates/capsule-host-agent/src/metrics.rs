//! Centralized host-agent metrics.

use capsule_telemetry::metrics::{Counter, Gauge, Histogram};
use std::sync::LazyLock;
use std::sync::atomic::AtomicBool;

pub static HOST_METRICS: LazyLock<HostMetrics> = LazyLock::new(HostMetrics::register);

static METRIC_REDACTION_ENABLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_metric_redaction(enabled: bool) {
    METRIC_REDACTION_ENABLED.store(enabled, std::sync::atomic::Ordering::Release);
}

pub(crate) fn is_metric_redaction_enabled() -> bool {
    METRIC_REDACTION_ENABLED.load(std::sync::atomic::Ordering::Acquire)
}

/// Build metric attributes with optional `tenant_id` when redaction is enabled.
pub(crate) fn latency_attrs<'a>(
    status: &'a str,
    tenant_id: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut attrs = vec![(capsule_telemetry::metrics::attr::STATUS, status)];
    if is_metric_redaction_enabled()
        && let Some(tid) = tenant_id
    {
        attrs.push((capsule_telemetry::metrics::attr::TENANT_ID, tid));
    }
    attrs
}

/// Build event counter attributes with optional `tenant_id` when redaction is enabled.
pub(crate) fn event_attrs<'a>(
    event: &'a str,
    tenant_id: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut attrs = vec![(capsule_telemetry::metrics::attr::EVENT, event)];
    if is_metric_redaction_enabled()
        && let Some(tid) = tenant_id
    {
        attrs.push((capsule_telemetry::metrics::attr::TENANT_ID, tid));
    }
    attrs
}

/// Build event + reason counter attributes with optional `tenant_id` when redaction is enabled.
pub(crate) fn event_reason_attrs<'a>(
    event: &'a str,
    reason: &'a str,
    tenant_id: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut attrs = vec![
        (capsule_telemetry::metrics::attr::EVENT, event),
        (capsule_telemetry::metrics::attr::REASON, reason),
    ];
    if is_metric_redaction_enabled()
        && let Some(tid) = tenant_id
    {
        attrs.push((capsule_telemetry::metrics::attr::TENANT_ID, tid));
    }
    attrs
}

/// Returns the label for tracing diagnostics.
/// When redaction is enabled, replaces sandbox_id with tenant_id prefix.
pub(crate) fn tracing_identity_label<'a>(
    sandbox_id: &'a str,
    tenant_id: Option<&'a str>,
) -> std::borrow::Cow<'a, str> {
    if is_metric_redaction_enabled() {
        if let Some(tid) = tenant_id {
            std::borrow::Cow::Owned(format!("tenant:{tid}"))
        } else {
            std::borrow::Cow::Borrowed("redacted")
        }
    } else {
        std::borrow::Cow::Borrowed(sandbox_id)
    }
}

const BOOT_EVENTS_TOTAL: &str = "capsule_boot_events_total";
const BOOT_LATENCY_SECONDS: &str = "capsule_boot_latency_seconds";
const CREATE_EVENTS_TOTAL: &str = "capsule_create_events_total";
const CREATE_LATENCY_SECONDS: &str = "capsule_create_latency_seconds";
const PREPARE_EVENTS_TOTAL: &str = "capsule_prepare_events_total";
const PREPARE_LATENCY_SECONDS: &str = "capsule_prepare_latency_seconds";
const DESTROY_EVENTS_TOTAL: &str = "capsule_destroy_events_total";
const DESTROY_LATENCY_SECONDS: &str = "capsule_destroy_latency_seconds";
const FORK_EVENTS_TOTAL: &str = "capsule_fork_events_total";
const FORK_LATENCY_SECONDS: &str = "capsule_fork_latency_seconds";
const EXEC_EVENTS_TOTAL: &str = "capsule_exec_events_total";
const EXEC_DURATION_SECONDS: &str = "capsule_exec_duration_seconds";
const EXEC_OUTPUT_BYTES: &str = "capsule_exec_output_bytes";
const QUIESCE_EVENTS_TOTAL: &str = "capsule_quiesce_events_total";
const QUIESCE_DURATION_SECONDS: &str = "capsule_quiesce_duration_seconds";
const RESUME_NOTIFY_EVENTS_TOTAL: &str = "capsule_resume_notify_events_total";
const RESUME_NOTIFY_DURATION_SECONDS: &str = "capsule_resume_notify_duration_seconds";
const SUSPEND_EVENTS_TOTAL: &str = "capsule_suspend_events_total";
const SUSPEND_LATENCY_SECONDS: &str = "capsule_suspend_latency_seconds";
const RESUME_EVENTS_TOTAL: &str = "capsule_resume_events_total";
const RESUME_LATENCY_SECONDS: &str = "capsule_resume_latency_seconds";
const RESTORE_EVENTS_TOTAL: &str = "capsule_restore_events_total";
const RESTORE_LATENCY_SECONDS: &str = "capsule_restore_latency_seconds";
const CGROUP_SETUP_ERRORS_TOTAL: &str = "capsule_cgroup_setup_errors_total";
const CGROUP_OOM_EVENTS_TOTAL: &str = "capsule_cgroup_oom_events_total";
const CGROUP_MEMORY_HIGH_EVENTS_TOTAL: &str = "capsule_cgroup_memory_high_events_total";
const CGROUP_CPU_THROTTLED_TOTAL: &str = "capsule_cgroup_cpu_throttled_total";
const CGROUP_MEMORY_PRESSURE: &str = "capsule_cgroup_memory_pressure";
const CGROUP_MEMORY_PRESSURE_READ_ERRORS_TOTAL: &str =
    "capsule_cgroup_memory_pressure_read_errors_total";
const HOST_SANDBOX_COUNT: &str = "capsule_host_sandbox_count";
const HOST_DRAINING: &str = "capsule_host_draining";
const CREDENTIAL_ISSUED_TOTAL: &str = "capsule_credential_issued_total";
const CREDENTIAL_DENIED_TOTAL: &str = "capsule_credential_denied_total";
const CREDENTIAL_REFRESHED_TOTAL: &str = "capsule_credential_refreshed_total";
const CREDENTIAL_REVOKED_TOTAL: &str = "capsule_credential_revoked_total";

// Port-forwarding metric name constants.
const PORT_FORWARD_ENDPOINTS_ACTIVE: &str = "network.port_forward.endpoints_active";
const PORT_FORWARD_CONNECTIONS_ACTIVE: &str = "network.port_forward.connections_active";
const PORT_FORWARD_EXPOSE_TOTAL: &str = "network.port_forward.expose_total";
const PORT_FORWARD_REVOKE_TOTAL: &str = "network.port_forward.revoke_total";
const PORT_FORWARD_EXPIRED_TOTAL: &str = "network.port_forward.expired_total";
const PORT_FORWARD_DENIED_TOTAL: &str = "network.port_forward.denied_total";
const NETWORK_HEALTH_STATE: &str = "capsule_network_health_state";

// Attribute value constants.
pub mod val {
    pub const READY: &str = "ready";
    pub const NOT_READY: &str = "not_ready";

    pub const CREATE_STARTED: &str = "create_started";
    pub const CREATE_COMPLETED: &str = "create_completed";
    pub const CREATE_FAILED: &str = "create_failed";

    pub const PREPARE_STARTED: &str = "prepare_started";
    pub const PREPARE_COMPLETED: &str = "prepare_completed";
    pub const PREPARE_FAILED: &str = "prepare_failed";

    pub const DESTROY_STARTED: &str = "destroy_started";
    pub const DESTROY_COMPLETED: &str = "destroy_completed";
    pub const DESTROY_FAILED: &str = "destroy_failed";

    pub const FORK_STARTED: &str = "fork_started";
    pub const FORK_COMPLETED: &str = "fork_completed";
    pub const FORK_FAILED: &str = "fork_failed";

    pub const BOOT_START: &str = "boot_start";
    pub const BOOT_READY: &str = "boot_ready";
    pub const BOOT_NOT_READY: &str = "boot_not_ready";
    pub const BOOT_CLEANUP: &str = "boot_cleanup";

    pub const EXEC_STARTED: &str = "exec_started";
    pub const EXEC_SUCCEEDED: &str = "succeeded";
    pub const EXEC_FAILED: &str = "failed";
    pub const EXEC_CANCELED: &str = "canceled";
    pub const EXEC_TIMED_OUT: &str = "timed_out";
    pub const EXEC_NOT_COMPLETED: &str = "not_completed";

    pub const QUIESCE_STARTED: &str = "quiesce_started";
    pub const QUIESCE_READY: &str = "quiesce_ready";
    pub const QUIESCE_TIMED_OUT: &str = "quiesce_timed_out";
    pub const QUIESCE_FAILED: &str = "quiesce_failed";
    pub const QUIESCE_BUSY: &str = "quiesce_busy";
    pub const QUIESCE_UNSUPPORTED: &str = "quiesce_unsupported";

    pub const RESUME_NOTIFY_STARTED: &str = "resume_notify_started";
    pub const RESUME_NOTIFY_ACCEPTED: &str = "resume_notify_accepted";
    pub const RESUME_NOTIFY_STALE_EPOCH: &str = "resume_notify_stale_epoch";
    pub const RESUME_NOTIFY_SESSION_MISMATCH: &str = "resume_notify_session_mismatch";
    pub const RESUME_NOTIFY_RESOURCES_UNAVAILABLE: &str = "resume_notify_resources_unavailable";
    pub const RESUME_NOTIFY_FAILED: &str = "resume_notify_failed";

    pub const SUSPEND_STARTED: &str = "suspend_started";
    pub const SUSPEND_COMPLETED: &str = "suspend_completed";
    pub const SUSPEND_FAILED: &str = "suspend_failed";
    pub const SUSPEND_TIMED_OUT: &str = "suspend_timed_out";

    pub const RESUME_STARTED: &str = "resume_started";
    pub const RESUME_COMPLETED: &str = "resume_completed";
    pub const RESUME_FAILED: &str = "resume_failed";
    pub const RESUME_TIMED_OUT: &str = "resume_timed_out";

    pub const RESTORE_STARTED: &str = "restore_started";
    pub const RESTORE_COMPLETED: &str = "restore_completed";
    pub const RESTORE_FAILED: &str = "restore_failed";
    pub const RESTORE_MEMORY_RESTORED: &str = "restore_memory_restored";
    pub const RESTORE_PARTIAL_CLEANUP: &str = "restore_partial_cleanup";
}

pub struct HostMetrics {
    pub create_events: Counter,
    pub create_latency: Histogram,
    pub prepare_events: Counter,
    pub prepare_latency: Histogram,
    pub boot_events: Counter,
    pub boot_latency: Histogram,
    pub destroy_events: Counter,
    pub destroy_latency: Histogram,
    pub exec_events: Counter,
    pub exec_duration: Histogram,
    pub exec_output_bytes: Histogram,
    pub quiesce_events: Counter,
    pub quiesce_duration: Histogram,
    pub resume_notify_events: Counter,
    pub resume_notify_duration: Histogram,
    pub suspend_events: Counter,
    pub suspend_latency: Histogram,
    pub resume_events: Counter,
    pub resume_latency: Histogram,
    pub fork_events: Counter,
    pub fork_latency: Histogram,
    pub restore_events: Counter,
    pub restore_latency: Histogram,
    pub sandbox_count: Gauge,
    pub draining: Gauge,
    pub credential_issued: Counter,
    pub credential_denied: Counter,
    pub credential_refreshed: Counter,
    pub credential_revoked: Counter,
    // Pre-registered for follow-up cgroup event polling loop.
    // These counters will be incremented when periodic reads of
    // memory.events / cpu.stat are wired in a subsequent PR.
    pub cgroup_setup_errors: Counter,
    pub cgroup_oom_events: Counter,
    pub cgroup_memory_high_events: Counter,
    pub cgroup_cpu_throttled: Counter,
    /// Host-level aggregate gauge of cgroup v2 memory pressure.
    /// Tracks the maximum `memory.pressure` `some avg10` value across
    /// all active sandbox cgroups. 0.0 = no pressure, 100.0 = full stall.
    pub cgroup_memory_pressure: Gauge,
    /// Counter for memory pressure read/parse failures.
    /// Provides operator visibility into cgroup misconfiguration or kernel issues
    /// without changing the security properties of the gauge itself.
    pub cgroup_memory_pressure_read_errors: Counter,
    // Port-forwarding metrics.
    pub port_forward_endpoints_active: Gauge,
    pub port_forward_connections_active: Gauge,
    pub port_forward_expose_total: Counter,
    pub port_forward_revoke_total: Counter,
    pub port_forward_expired_total: Counter,
    pub port_forward_denied_total: Counter,
    /// Host-agent's observed view of network-agent health.
    /// Mirrors `network.reconciliation.health_state` as observed
    /// by the host-agent health check loop.
    pub network_health_state: Gauge,
}

impl HostMetrics {
    fn register() -> Self {
        Self {
            create_events: Counter::register(CREATE_EVENTS_TOTAL),
            create_latency: Histogram::register(CREATE_LATENCY_SECONDS),
            prepare_events: Counter::register(PREPARE_EVENTS_TOTAL),
            prepare_latency: Histogram::register(PREPARE_LATENCY_SECONDS),
            boot_events: Counter::register(BOOT_EVENTS_TOTAL),
            boot_latency: Histogram::register(BOOT_LATENCY_SECONDS),
            destroy_events: Counter::register(DESTROY_EVENTS_TOTAL),
            destroy_latency: Histogram::register(DESTROY_LATENCY_SECONDS),
            exec_events: Counter::register(EXEC_EVENTS_TOTAL),
            exec_duration: Histogram::register(EXEC_DURATION_SECONDS),
            exec_output_bytes: Histogram::register(EXEC_OUTPUT_BYTES),
            quiesce_events: Counter::register(QUIESCE_EVENTS_TOTAL),
            quiesce_duration: Histogram::register(QUIESCE_DURATION_SECONDS),
            resume_notify_events: Counter::register(RESUME_NOTIFY_EVENTS_TOTAL),
            resume_notify_duration: Histogram::register(RESUME_NOTIFY_DURATION_SECONDS),
            suspend_events: Counter::register(SUSPEND_EVENTS_TOTAL),
            suspend_latency: Histogram::register(SUSPEND_LATENCY_SECONDS),
            resume_events: Counter::register(RESUME_EVENTS_TOTAL),
            resume_latency: Histogram::register(RESUME_LATENCY_SECONDS),
            fork_events: Counter::register(FORK_EVENTS_TOTAL),
            fork_latency: Histogram::register(FORK_LATENCY_SECONDS),
            restore_events: Counter::register(RESTORE_EVENTS_TOTAL),
            restore_latency: Histogram::register(RESTORE_LATENCY_SECONDS),
            sandbox_count: Gauge::register(HOST_SANDBOX_COUNT),
            draining: Gauge::register(HOST_DRAINING),
            cgroup_setup_errors: Counter::register(CGROUP_SETUP_ERRORS_TOTAL),
            cgroup_oom_events: Counter::register(CGROUP_OOM_EVENTS_TOTAL),
            cgroup_memory_high_events: Counter::register(CGROUP_MEMORY_HIGH_EVENTS_TOTAL),
            cgroup_cpu_throttled: Counter::register(CGROUP_CPU_THROTTLED_TOTAL),
            cgroup_memory_pressure: Gauge::register(CGROUP_MEMORY_PRESSURE),
            cgroup_memory_pressure_read_errors: Counter::register(
                CGROUP_MEMORY_PRESSURE_READ_ERRORS_TOTAL,
            ),
            credential_issued: Counter::register(CREDENTIAL_ISSUED_TOTAL),
            credential_denied: Counter::register(CREDENTIAL_DENIED_TOTAL),
            credential_refreshed: Counter::register(CREDENTIAL_REFRESHED_TOTAL),
            credential_revoked: Counter::register(CREDENTIAL_REVOKED_TOTAL),
            port_forward_endpoints_active: Gauge::register(PORT_FORWARD_ENDPOINTS_ACTIVE),
            port_forward_connections_active: Gauge::register(PORT_FORWARD_CONNECTIONS_ACTIVE),
            port_forward_expose_total: Counter::register(PORT_FORWARD_EXPOSE_TOTAL),
            port_forward_revoke_total: Counter::register(PORT_FORWARD_REVOKE_TOTAL),
            port_forward_expired_total: Counter::register(PORT_FORWARD_EXPIRED_TOTAL),
            port_forward_denied_total: Counter::register(PORT_FORWARD_DENIED_TOTAL),
            network_health_state: Gauge::register(NETWORK_HEALTH_STATE),
        }
    }
}

pub fn record_credential_issued(count: u64) {
    HOST_METRICS.credential_issued.inc_by(count, &[]);
}

pub fn record_credential_denied(count: u64) {
    HOST_METRICS.credential_denied.inc_by(count, &[]);
}

pub fn record_credential_refreshed(count: u64) {
    HOST_METRICS.credential_refreshed.inc_by(count, &[]);
}

pub fn record_credential_revoked(count: u64) {
    HOST_METRICS.credential_revoked.inc_by(count, &[]);
}

/// Record the current count of active port-forward endpoints.
pub fn record_port_forward_endpoints_active(count: u64) {
    HOST_METRICS
        .port_forward_endpoints_active
        .set(count as f64, &[]);
}

/// Record the current count of active port-forward connections.
pub fn record_port_forward_connections_active(count: u64) {
    HOST_METRICS
        .port_forward_connections_active
        .set(count as f64, &[]);
}

/// Record a successful port-forward expose operation.
pub fn record_port_forward_expose() {
    HOST_METRICS.port_forward_expose_total.inc(&[]);
}

/// Record a port-forward revoke operation.
pub fn record_port_forward_revoke() {
    HOST_METRICS.port_forward_revoke_total.inc(&[]);
}

/// Record a port-forward endpoint that expired.
pub fn record_port_forward_expired() {
    HOST_METRICS.port_forward_expired_total.inc(&[]);
}

/// Record a denied port-forward expose attempt.
pub fn record_port_forward_denied() {
    HOST_METRICS.port_forward_denied_total.inc(&[]);
}

/// Record the network-agent's observed health state as reported
/// by the host-agent health check loop.
///
/// 0 = ready, 1 = degraded, 2 = unsafe.
pub fn record_network_health_state(value: f64) {
    HOST_METRICS.network_health_state.set(value, &[]);
}

/// Record a cgroup OOM event for a sandbox.
/// Excluded when shared_host_metric_redaction is enabled.
pub fn record_cgroup_oom_event(_tenant_id: Option<&str>) {
    if is_metric_redaction_enabled() {
        return;
    }
    HOST_METRICS.cgroup_oom_events.inc(&[]);
}

/// Record a cgroup memory high event for a sandbox.
/// Excluded when shared_host_metric_redaction is enabled.
pub fn record_cgroup_memory_high_event(_tenant_id: Option<&str>) {
    if is_metric_redaction_enabled() {
        return;
    }
    HOST_METRICS.cgroup_memory_high_events.inc(&[]);
}

/// Record a cgroup CPU throttled event for a sandbox.
/// Excluded when shared_host_metric_redaction is enabled.
pub fn record_cgroup_cpu_throttled(_tenant_id: Option<&str>) {
    if is_metric_redaction_enabled() {
        return;
    }
    HOST_METRICS.cgroup_cpu_throttled.inc(&[]);
}

/// Record a cgroup setup error for a sandbox.
/// Excluded when shared_host_metric_redaction is enabled.
pub fn record_cgroup_setup_error(_tenant_id: Option<&str>) {
    if is_metric_redaction_enabled() {
        return;
    }
    HOST_METRICS.cgroup_setup_errors.inc(&[]);
}

/// Record the host-level aggregate cgroup v2 memory pressure gauge.
///
/// This metric is always host-level aggregate (maximum `memory.pressure`
/// `some avg10` across all sandboxes), so it does not expose per-sandbox
/// data and is safe to emit even when `shared_host_metric_redaction` is
/// enabled.
pub fn record_cgroup_memory_pressure(value: f64) {
    HOST_METRICS.cgroup_memory_pressure.set(value, &[]);
}

/// Record memory pressure read/parse failures.
///
/// This counter provides operator visibility into cgroup misconfiguration
/// or kernel issues. It is always emitted (host-level aggregate) and does
/// not expose per-sandbox data.
pub fn record_cgroup_memory_pressure_read_error(count: u64) {
    HOST_METRICS
        .cgroup_memory_pressure_read_errors
        .inc_by(count, &[]);
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
    fn latency_attrs_no_tenant_id_when_disabled() {
        set_metric_redaction(false);
        let attrs = latency_attrs("completed", None);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0, capsule_telemetry::metrics::attr::STATUS);
        assert_eq!(attrs[0].1, "completed");
    }

    #[test]
    fn latency_attrs_no_tenant_id_when_redacted_without_tenant() {
        set_metric_redaction(true);
        let attrs = latency_attrs("completed", None);
        assert_eq!(attrs.len(), 1);
        set_metric_redaction(false);
    }

    #[test]
    fn latency_attrs_has_tenant_id_when_redacted() {
        set_metric_redaction(true);
        let attrs = latency_attrs("completed", Some("tnt_test"));
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[1].0, capsule_telemetry::metrics::attr::TENANT_ID);
        assert_eq!(attrs[1].1, "tnt_test");
        set_metric_redaction(false);
    }

    #[test]
    fn event_attrs_has_tenant_id_when_redacted() {
        set_metric_redaction(true);
        let attrs = event_attrs("create_started", Some("tnt_test"));
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[1].0, capsule_telemetry::metrics::attr::TENANT_ID);
        assert_eq!(attrs[1].1, "tnt_test");
        set_metric_redaction(false);
    }

    #[test]
    fn event_reason_attrs_has_tenant_id_when_redacted() {
        set_metric_redaction(true);
        let attrs = event_reason_attrs("create_failed", "oom", Some("tnt_test"));
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[2].0, capsule_telemetry::metrics::attr::TENANT_ID);
        assert_eq!(attrs[2].1, "tnt_test");
        set_metric_redaction(false);
    }

    #[test]
    fn cgroup_oom_excluded_when_redaction_enabled() {
        set_metric_redaction(true);
        let before = tracing_identity_label("sbx_test", Some("tnt_test"));
        assert!(before.starts_with("tenant:"));
        set_metric_redaction(false);
    }

    #[test]
    fn tracing_identity_label_uses_sandbox_when_disabled() {
        set_metric_redaction(false);
        let label = tracing_identity_label("sbx_test", Some("tnt_test"));
        assert_eq!(label, "sbx_test");
    }

    #[test]
    fn tracing_identity_label_falls_back_to_redacted() {
        set_metric_redaction(true);
        let label = tracing_identity_label("sbx_test", None);
        assert_eq!(label, "redacted");
        set_metric_redaction(false);
    }

    #[test]
    fn cgroup_metrics_excluded_when_redacted() {
        let before_oom = tracing_identity_label("sbx_oom", Some("tnt_oom"));
        assert_eq!(before_oom, "sbx_oom");

        set_metric_redaction(true);
        let redacted_oom = tracing_identity_label("sbx_oom", Some("tnt_oom"));
        assert_eq!(redacted_oom, "tenant:tnt_oom");
        set_metric_redaction(false);
    }
}
