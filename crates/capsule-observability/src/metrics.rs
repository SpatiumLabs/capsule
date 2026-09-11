//! Convenience functions for recording observability metrics.
//!
//! These functions provide typed interfaces to the global
//! [`OBSERVABILITY_METRICS`](crate::OBSERVABILITY_METRICS) static,
//! allowing callers to record data without accessing the struct fields directly.

/// Record the number of CPU profiling samples collected.
pub fn record_cpu_sample_collected(count: u64) {
    crate::OBSERVABILITY_METRICS
        .cpu_samples_total
        .inc_by(count, &[]);
}

/// Record memory usage for a sandbox.
pub fn record_memory_usage(sandbox_id: &str, bytes: u64) {
    crate::OBSERVABILITY_METRICS
        .memory_usage_bytes
        .set(bytes as f64, &[("sandbox_id", sandbox_id)]);
}

/// Record memory pressure for a sandbox.
pub fn record_memory_pressure(sandbox_id: &str, pressure: f64) {
    crate::OBSERVABILITY_METRICS
        .memory_pressure_avg10
        .set(pressure, &[("sandbox_id", sandbox_id)]);
}

/// Record an I/O read latency sample.
pub fn record_io_latency_read(latency_secs: f64) {
    crate::OBSERVABILITY_METRICS
        .io_read_latency_seconds
        .record(latency_secs, &[]);
}

/// Record an I/O write latency sample.
pub fn record_io_latency_write(latency_secs: f64) {
    crate::OBSERVABILITY_METRICS
        .io_write_latency_seconds
        .record(latency_secs, &[]);
}

/// Set whether the eBPF observability backend is active.
pub fn record_ebpf_enabled(enabled: bool) {
    crate::OBSERVABILITY_METRICS
        .ebpf_observability_enabled
        .set(if enabled { 1.0 } else { 0.0 }, &[]);
}
