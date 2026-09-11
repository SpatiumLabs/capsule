//! Core observability metrics.
//!
//! ## Snapshot cache metrics and shared-host redaction (SC-IMPL-04)
//!
//! Snapshot cache metrics (`capsule_snapshot_cache_hits`, `capsule_snapshot_cache_misses`,
//! `capsule_snapshot_eviction_*`) are rate-limited on shared multi-tenant hosts to
//! prevent cross-tenant cache activity inference via high-frequency metric sampling.
//!
//! ### Rate-limiting strategy
//!
//! When `shared_host_metric_redaction` is enabled:
//! 1. Metrics are throttled to one emission per 60-second window per key.
//! 2. Key space uses a `{metric_type}:{tenant_id}` scheme. The current cache layer
//!    (`TieredCacheManager` / `CacheTierStore`) lacks tenant context, so all call sites
//!    pass `None` for `tenant_id`, collapsing to a single host-level key per metric type.
//!    This means the rate limiter applies per-host, not per-tenant.
//! 3. No `tenant_id` label is attached to the emitted OTel data points.
//!
//! This is a known limitation: if per-tenant (still rate-limited) visibility is needed,
//! `tenant_id` must be threaded through the cache tiering layer. For now, host-level
//! aggregation is the safer default---it prevents cross-tenant inference without leaking
//! tenancy boundaries through metric labels.
//!
//! On dedicated-tenancy hosts (redaction disabled), all metrics pass through without
//! rate-limiting, maintaining full per-host granularity.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use capsule_telemetry::metrics::{Counter, Gauge, Histogram};
use hashbrown::HashMap;
use parking_lot::Mutex;

pub static CORE_METRICS: LazyLock<CoreMetrics> = LazyLock::new(CoreMetrics::register);

static METRIC_REDACTION_ENABLED: AtomicBool = AtomicBool::new(false);

/// Last-emission timestamps for snapshot cache metrics on shared hosts.
///
/// Key format: `{metric_type}:{tenant_id}` where `tenant_id` is currently always
/// `"host"` since the cache tiering layer does not propagate tenant context.
///
/// Uses `parking_lot::Mutex` (no poisoning) to keep the fast path simple.
static LAST_SNAPSHOT_CACHE_METRICS: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Minimum interval (seconds) between emissions of the same snapshot cache metric key.
/// Applied only when `shared_host_metric_redaction` is enabled.
const SNAPSHOT_CACHE_MIN_INTERVAL_SECS: u64 = 60;

/// Maximum number of tracked rate-limit keys before GC is triggered.
/// Bounds memory usage and prevents unbounded growth from key injection.
const SNAPSHOT_CACHE_EVICTION_LIMIT: usize = 1024;

pub fn set_metric_redaction(enabled: bool) {
    METRIC_REDACTION_ENABLED.store(enabled, Ordering::Release);
}

pub fn is_metric_redaction_enabled() -> bool {
    METRIC_REDACTION_ENABLED.load(Ordering::Acquire)
}

/// Check whether a snapshot cache metric should be emitted on a shared host.
///
/// Rate-limits to one emission per `SNAPSHOT_CACHE_MIN_INTERVAL_SECS` per
/// `"{prefix}:{tenant_id}"` key. Callers should first check
/// `is_metric_redaction_enabled()`; this function assumes it is `true`.
///
/// Stale entries are evicted when the map exceeds `SNAPSHOT_CACHE_EVICTION_LIMIT`.
fn should_emit_snapshot_cache_metric(prefix: &str, tenant_id: Option<&str>) -> bool {
    let key = if let Some(tid) = tenant_id {
        [prefix, ":", tid].concat()
    } else {
        [prefix, ":", "host"].concat()
    };
    let mut last = LAST_SNAPSHOT_CACHE_METRICS.lock();
    if let Some(prev) = last.get(&key)
        && prev.elapsed().as_secs() < SNAPSHOT_CACHE_MIN_INTERVAL_SECS
    {
        return false;
    }
    if last.len() >= SNAPSHOT_CACHE_EVICTION_LIMIT {
        last.retain(|_, v| v.elapsed().as_secs() < SNAPSHOT_CACHE_MIN_INTERVAL_SECS * 2);
    }
    last.insert(key, Instant::now());
    true
}

/// Record a snapshot cache hit. Rate-limited on shared hosts.
///
/// `tenant_id` is optional. When `None` (current default from the cache tiering layer),
/// the rate-limiter key collapses to `"hit:host"` and no `tenant_id` label is attached.
pub fn record_snapshot_cache_hit(tenant_id: Option<&str>) {
    if is_metric_redaction_enabled() && !should_emit_snapshot_cache_metric("hit", tenant_id) {
        return;
    }
    let attrs = snapshot_cache_attrs(tenant_id);
    CORE_METRICS.snapshot_cache_hits.inc(&attrs);
}

/// Record a snapshot cache miss. Rate-limited on shared hosts.
///
/// See `record_snapshot_cache_hit` for tenant context caveats.
pub fn record_snapshot_cache_miss(tenant_id: Option<&str>) {
    if is_metric_redaction_enabled() && !should_emit_snapshot_cache_metric("miss", tenant_id) {
        return;
    }
    let attrs = snapshot_cache_attrs(tenant_id);
    CORE_METRICS.snapshot_cache_misses.inc(&attrs);
}

/// Record a snapshot eviction. Rate-limited on shared hosts.
///
/// See `record_snapshot_cache_hit` for tenant context caveats.
pub fn record_snapshot_eviction(tenant_id: Option<&str>, freed_bytes: u64) {
    if is_metric_redaction_enabled() && !should_emit_snapshot_cache_metric("evict", tenant_id) {
        return;
    }
    let attrs = snapshot_cache_attrs(tenant_id);
    CORE_METRICS.snapshot_eviction_count.inc(&attrs);
    CORE_METRICS
        .snapshot_eviction_bytes
        .inc_by(freed_bytes, &attrs);
}

fn snapshot_cache_attrs(tenant_id: Option<&str>) -> Vec<(&'static str, &str)> {
    if is_metric_redaction_enabled()
        && let Some(tid) = tenant_id
    {
        vec![(capsule_telemetry::metrics::attr::TENANT_ID, tid)]
    } else {
        vec![]
    }
}

const PLACEMENT_LATENCY_SECONDS: &str = "capsule_placement_latency_seconds";
const PLACEMENT_HOSTS_EVALUATED: &str = "capsule_placement_hosts_evaluated";
const PLACEMENT_HOSTS_PASSED_CONSTRAINTS: &str = "capsule_placement_hosts_passed_constraints";

const GC_PASS_DURATION_SECONDS: &str = "capsule_gc_pass_duration_seconds";
const GC_ORPHANS_DETECTED: &str = "capsule_gc_orphans_detected";
const GC_RESOURCES_REMOVED: &str = "capsule_gc_resources_removed";
const GC_REVIEW_REQUIRED: &str = "capsule_gc_review_required";
const GC_CLEANUP_FAILED: &str = "capsule_gc_cleanup_failed";

const CPU_RECEIPTS_RESTORED: &str = "capsule_cpu_receipts_restored";
const CPU_RECEIPTS_SKIPPED: &str = "capsule_cpu_receipts_skipped";

const SNAPSHOT_CACHE_HITS: &str = "capsule_snapshot_cache_hits";
const SNAPSHOT_CACHE_MISSES: &str = "capsule_snapshot_cache_misses";
const SNAPSHOT_EVICTION_COUNT: &str = "capsule_snapshot_eviction_count";
const SNAPSHOT_EVICTION_BYTES: &str = "capsule_snapshot_eviction_bytes";
const SNAPSHOT_REF_REGISTERED: &str = "capsule_snapshot_ref_registered";
const SNAPSHOT_REF_DEREGISTERED: &str = "capsule_snapshot_ref_deregistered";
const SNAPSHOT_GC_PASSES: &str = "capsule_snapshot_gc_passes";
const SNAPSHOT_GC_DELETED: &str = "capsule_snapshot_gc_deleted";
const SNAPSHOT_GC_BYTES_FREED: &str = "capsule_snapshot_gc_bytes_freed";
const SNAPSHOT_GC_SKIPPED_REF: &str = "capsule_snapshot_gc_skipped_ref";
const SNAPSHOT_GC_SKIPPED_RETENTION: &str = "capsule_snapshot_gc_skipped_retention";
const SNAPSHOT_GC_CANDIDATES: &str = "capsule_snapshot_gc_candidates";

pub struct CoreMetrics {
    pub placement_latency: Histogram,
    pub hosts_evaluated: Histogram,
    pub hosts_passed: Histogram,
    pub gc_pass_duration: Histogram,
    pub gc_orphans_detected: Counter,
    pub gc_resources_removed: Counter,
    pub gc_review_required: Counter,
    pub gc_cleanup_failed: Counter,
    pub cpu_receipts_restored: Counter,
    pub cpu_receipts_skipped: Counter,
    pub snapshot_cache_hits: Counter,
    pub snapshot_cache_misses: Counter,
    pub snapshot_eviction_count: Counter,
    pub snapshot_eviction_bytes: Counter,
    pub snapshot_ref_registered: Counter,
    pub snapshot_ref_deregistered: Counter,
    pub snapshot_gc_passes: Counter,
    pub snapshot_gc_deleted: Counter,
    pub snapshot_gc_bytes_freed: Counter,
    pub snapshot_gc_skipped_ref: Counter,
    pub snapshot_gc_skipped_retention: Counter,
    pub snapshot_gc_candidates: Gauge,
}

impl CoreMetrics {
    fn register() -> Self {
        Self {
            placement_latency: Histogram::register(PLACEMENT_LATENCY_SECONDS),
            hosts_evaluated: Histogram::register(PLACEMENT_HOSTS_EVALUATED),
            hosts_passed: Histogram::register(PLACEMENT_HOSTS_PASSED_CONSTRAINTS),
            gc_pass_duration: Histogram::register(GC_PASS_DURATION_SECONDS),
            gc_orphans_detected: Counter::register(GC_ORPHANS_DETECTED),
            gc_resources_removed: Counter::register(GC_RESOURCES_REMOVED),
            gc_review_required: Counter::register(GC_REVIEW_REQUIRED),
            gc_cleanup_failed: Counter::register(GC_CLEANUP_FAILED),
            cpu_receipts_restored: Counter::register(CPU_RECEIPTS_RESTORED),
            cpu_receipts_skipped: Counter::register(CPU_RECEIPTS_SKIPPED),
            snapshot_cache_hits: Counter::register(SNAPSHOT_CACHE_HITS),
            snapshot_cache_misses: Counter::register(SNAPSHOT_CACHE_MISSES),
            snapshot_eviction_count: Counter::register(SNAPSHOT_EVICTION_COUNT),
            snapshot_eviction_bytes: Counter::register(SNAPSHOT_EVICTION_BYTES),
            snapshot_ref_registered: Counter::register(SNAPSHOT_REF_REGISTERED),
            snapshot_ref_deregistered: Counter::register(SNAPSHOT_REF_DEREGISTERED),
            snapshot_gc_passes: Counter::register(SNAPSHOT_GC_PASSES),
            snapshot_gc_deleted: Counter::register(SNAPSHOT_GC_DELETED),
            snapshot_gc_bytes_freed: Counter::register(SNAPSHOT_GC_BYTES_FREED),
            snapshot_gc_skipped_ref: Counter::register(SNAPSHOT_GC_SKIPPED_REF),
            snapshot_gc_skipped_retention: Counter::register(SNAPSHOT_GC_SKIPPED_RETENTION),
            snapshot_gc_candidates: Gauge::register(SNAPSHOT_GC_CANDIDATES),
        }
    }
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
    fn should_emit_first_call_returns_true() {
        set_metric_redaction(true);
        assert!(should_emit_snapshot_cache_metric(
            "hit",
            Some("test_tenant")
        ));
        set_metric_redaction(false);
    }

    #[test]
    fn should_emit_second_call_within_interval_returns_false() {
        set_metric_redaction(true);
        assert!(should_emit_snapshot_cache_metric("hit", Some("rl_test")));
        assert!(!should_emit_snapshot_cache_metric("hit", Some("rl_test")));
        set_metric_redaction(false);
    }

    #[test]
    fn should_emit_different_keys_are_independent() {
        set_metric_redaction(true);
        assert!(should_emit_snapshot_cache_metric("hit", Some("tenant_a")));
        assert!(should_emit_snapshot_cache_metric("miss", Some("tenant_a")));
        assert!(should_emit_snapshot_cache_metric("hit", Some("tenant_b")));
        assert!(!should_emit_snapshot_cache_metric("hit", Some("tenant_a")));
        assert!(should_emit_snapshot_cache_metric("evict", Some("tenant_b")));
        set_metric_redaction(false);
    }

    #[test]
    fn record_snapshot_cache_hit_does_not_panic() {
        set_metric_redaction(false);
        record_snapshot_cache_hit(None);
        record_snapshot_cache_hit(Some("tnt_test"));
        set_metric_redaction(true);
        record_snapshot_cache_hit(None);
        record_snapshot_cache_hit(Some("tnt_test"));
        set_metric_redaction(false);
    }

    #[test]
    fn record_snapshot_cache_miss_does_not_panic() {
        set_metric_redaction(false);
        record_snapshot_cache_miss(None);
        record_snapshot_cache_miss(Some("tnt_test"));
        set_metric_redaction(true);
        record_snapshot_cache_miss(None);
        record_snapshot_cache_miss(Some("tnt_test"));
        set_metric_redaction(false);
    }

    #[test]
    fn record_snapshot_eviction_does_not_panic() {
        set_metric_redaction(false);
        record_snapshot_eviction(None, 1024);
        record_snapshot_eviction(Some("tnt_test"), 2048);
        set_metric_redaction(true);
        record_snapshot_eviction(None, 1024);
        record_snapshot_eviction(Some("tnt_test"), 2048);
        set_metric_redaction(false);
    }

    #[test]
    fn snapshot_cache_attrs_empty_when_redaction_disabled() {
        set_metric_redaction(false);
        let attrs = snapshot_cache_attrs(Some("tnt_test"));
        assert!(attrs.is_empty());
    }

    #[test]
    fn snapshot_cache_attrs_has_tenant_id_when_redacted() {
        set_metric_redaction(true);
        let attrs = snapshot_cache_attrs(Some("tnt_test"));
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0, capsule_telemetry::metrics::attr::TENANT_ID);
        assert_eq!(attrs[0].1, "tnt_test");
        set_metric_redaction(false);
    }

    #[test]
    fn snapshot_cache_attrs_empty_when_redacted_but_no_tenant() {
        set_metric_redaction(true);
        let attrs = snapshot_cache_attrs(None);
        assert!(attrs.is_empty());
        set_metric_redaction(false);
    }
}
