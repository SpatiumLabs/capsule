//! DNS-specific metrics counters and histogram.
//!
//! All metrics are prefixed with `network.dns.`.

use capsule_telemetry::metrics::{Counter, Gauge, Histogram};
use std::sync::LazyLock;

pub(super) static DNS_METRICS: LazyLock<DnsMetrics> = LazyLock::new(DnsMetrics::register);

const DNS_QUERIES_TOTAL: &str = "network.dns.queries_total";
const DNS_ALLOWED: &str = "network.dns.allowed";
const DNS_DENIED: &str = "network.dns.denied";
const DNS_FAILED: &str = "network.dns.failed";
const DNS_CACHE_HITS: &str = "network.dns.cache_hits";
const DNS_CACHE_MISSES: &str = "network.dns.cache_misses";
const DNS_RESOLUTION_DURATION: &str = "network.dns.resolution_duration_seconds";
const DNS_POLICY_ACTIONS: &str = "network.dns.policy_actions";
const DNS_REGISTERED_SANDBOXES: &str = "network.dns.registered_sandboxes";
const DNS_QUERY_DOMAIN: &str = "network.dns.query_domain";
const DNS_RESPONSE_CODE: &str = "network.dns.response_code";

/// DNS policy action attribute values.
pub(super) mod dns_action {
    pub(crate) const ALLOW_RULE: &str = "allow_rule";
    pub(crate) const DENY_RULE: &str = "deny_rule";
    pub(crate) const DEFAULT_ALLOW: &str = "default_allow";
    pub(crate) const DEFAULT_DENY: &str = "default_deny";
    pub(crate) const PLATFORM_INTERNAL: &str = "platform_internal";
    pub(crate) const UNSUPPORTED_QTYPE: &str = "unsupported_qtype";
    pub(crate) const NO_POLICY: &str = "no_policy";
    pub(crate) const IPV6_UNSUPPORTED: &str = "ipv6_unsupported";
}

pub(super) struct DnsMetrics {
    pub queries_total: Counter,
    pub allowed: Counter,
    pub denied: Counter,
    pub failed: Counter,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub resolution_duration: Histogram,
    pub policy_actions: Counter,
    pub registered_sandboxes: Gauge,
    pub query_domain: Counter,
    pub response_code: Counter,
}

impl DnsMetrics {
    fn register() -> Self {
        Self {
            queries_total: Counter::register(DNS_QUERIES_TOTAL),
            allowed: Counter::register(DNS_ALLOWED),
            denied: Counter::register(DNS_DENIED),
            failed: Counter::register(DNS_FAILED),
            cache_hits: Counter::register(DNS_CACHE_HITS),
            cache_misses: Counter::register(DNS_CACHE_MISSES),
            resolution_duration: Histogram::register(DNS_RESOLUTION_DURATION),
            policy_actions: Counter::register(DNS_POLICY_ACTIONS),
            registered_sandboxes: Gauge::register(DNS_REGISTERED_SANDBOXES),
            query_domain: Counter::register(DNS_QUERY_DOMAIN),
            response_code: Counter::register(DNS_RESPONSE_CODE),
        }
    }
}
