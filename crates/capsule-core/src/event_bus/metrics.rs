//! Audit pipeline health metrics.
//!
//! Per ADR-0009, audit pipeline metrics provide visibility into delivery
//! health, backlog, and end-to-end lag.

use std::sync::LazyLock;

use capsule_telemetry::metrics::{Counter, Gauge, Histogram};

/// Audit pipeline metrics registered at startup.
pub static AUDIT_PIPELINE_METRICS: LazyLock<AuditPipelineMetrics> =
    LazyLock::new(AuditPipelineMetrics::register);

const DELIVERY_COUNT: &str = "capsule.audit.delivery.count";
const DELIVERY_LAG: &str = "capsule.audit.delivery.lag";
const OUTBOX_PENDING: &str = "capsule.audit.outbox.pending";

pub struct AuditPipelineMetrics {
    pub delivery_count: Counter,
    pub delivery_lag: Histogram,
    pub outbox_pending: Gauge,
}

impl AuditPipelineMetrics {
    fn register() -> Self {
        Self {
            delivery_count: Counter::register(DELIVERY_COUNT),
            delivery_lag: Histogram::register(DELIVERY_LAG),
            outbox_pending: Gauge::register(OUTBOX_PENDING),
        }
    }
}

/// Record delivery of audit events.
///
/// `outcome` should be a bounded value such as `delivered`, `retry`,
/// `dead_letter`, or `dropped`.
pub fn record_audit_delivery(batch_size: usize, outcome: &str, reason: Option<&str>) {
    let mut attrs: Vec<(&str, &str)> = vec![("outcome", outcome)];
    if let Some(reason) = reason {
        attrs.push(("reason", reason));
    }
    AUDIT_PIPELINE_METRICS
        .delivery_count
        .inc_by(batch_size as u64, &attrs);
}

/// Record a delivery lag in seconds (wall-clock time from event generation
/// to persistence confirmation).
pub fn record_audit_delivery_lag(lag_seconds: f64) {
    AUDIT_PIPELINE_METRICS.delivery_lag.record(lag_seconds, &[]);
}

/// Record the current outbox pending count.
///
/// Note: this reflects the most recently observed batch size rather than
/// the full channel depth because `tokio::sync::mpsc` does not expose a
/// channel length. For true backlog monitoring, emit this from the producer
/// side where the backlog is known.
pub fn record_audit_outbox_pending(count: u64) {
    AUDIT_PIPELINE_METRICS.outbox_pending.set(count as f64, &[]);
}
