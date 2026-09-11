//! Metrics wrappers and OTLP gRPC exporter.

use core::time::Duration;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use parking_lot::Mutex;
use std::sync::LazyLock;

use crate::BoxError;
use crate::settings::MetricsSettings;

/// Shared metric attribute key constants.
pub mod attr {
    /// Network or device type (tap, veth, route, namespace).
    pub const KIND: &str = "kind";
    /// Backend runtime class (microvm, container).
    pub const BACKEND: &str = "backend";
    /// Failure or skip reason.
    pub const REASON: &str = "reason";
    /// Boot lifecycle event name.
    pub const EVENT: &str = "event";
    /// Boot outcome status (ready, not_ready).
    pub const STATUS: &str = "status";
    /// Lifecycle operation name (create, boot, exec, destroy, etc.).
    pub const OPERATION: &str = "operation";
    /// Lifecycle outcome (success, timeout, cancelled, runtime_failed, etc.).
    pub const OUTCOME: &str = "outcome";
    /// Tenant identifier for shared-host metric redaction mode.
    pub const TENANT_ID: &str = "tenant_id";
    /// Sandbox identifier (excluded in shared-host metric redaction mode).
    pub const SANDBOX_ID: &str = "sandbox_id";
}

static METER_PROVIDER: LazyLock<Mutex<Option<SdkMeterProvider>>> =
    LazyLock::new(|| Mutex::new(None));

pub(crate) fn init_exporter(
    settings: &MetricsSettings,
) -> Result<Option<SdkMeterProvider>, BoxError> {
    if settings.otlp_endpoint.is_empty() {
        return Ok(None);
    }

    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&settings.otlp_endpoint)
        .build()
        .map_err(|e| Box::new(e) as BoxError)?;

    let mut resource_attrs: Vec<KeyValue> =
        vec![KeyValue::new("service.name", settings.service_name.clone())];
    resource_attrs.extend(
        settings
            .resource_attributes
            .iter()
            .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
    );

    let resource = opentelemetry_sdk::Resource::builder()
        .with_attributes(resource_attrs)
        .build();

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(settings.export_interval_secs))
        .build();

    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    opentelemetry::global::set_meter_provider(provider.clone());

    let mut guard = METER_PROVIDER.lock();
    *guard = Some(provider.clone());

    Ok(Some(provider))
}

pub(crate) fn shutdown_metrics() {
    if let Some(provider) = METER_PROVIDER.lock().take() {
        let _ = provider.shutdown();
    }
}

/// Counter metric.
pub struct Counter {
    inner: opentelemetry::metrics::Counter<u64>,
}

impl Counter {
    pub fn register(name: &'static str) -> Self {
        let meter = opentelemetry::global::meter("capsule");
        let inner = meter.u64_counter(name).build();
        Self { inner }
    }

    pub fn inc(&self, attrs: &[(&str, &str)]) {
        self.add(1, attrs);
    }

    /// Increments the counter by an explicit amount.
    pub fn inc_by(&self, value: u64, attrs: &[(&str, &str)]) {
        self.add(value, attrs);
    }

    fn add(&self, value: u64, attrs: &[(&str, &str)]) {
        let kvs: Vec<KeyValue> = attrs
            .iter()
            .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
            .collect();
        self.inner.add(value, &kvs);
    }
}

/// Histogram metric.
pub struct Histogram {
    inner: opentelemetry::metrics::Histogram<f64>,
}

impl Histogram {
    pub fn register(name: &'static str) -> Self {
        let meter = opentelemetry::global::meter("capsule");
        let inner = meter.f64_histogram(name).build();
        Self { inner }
    }

    pub fn record(&self, value: f64, attrs: &[(&str, &str)]) {
        let kvs: Vec<KeyValue> = attrs
            .iter()
            .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
            .collect();
        self.inner.record(value, &kvs);
    }
}

/// Gauge metric.
pub struct Gauge {
    inner: opentelemetry::metrics::Gauge<f64>,
}

impl Gauge {
    pub fn register(name: &'static str) -> Self {
        let meter = opentelemetry::global::meter("capsule");
        let inner = meter.f64_gauge(name).build();
        Self { inner }
    }

    pub fn set(&self, value: f64, attrs: &[(&str, &str)]) {
        let kvs: Vec<KeyValue> = attrs
            .iter()
            .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
            .collect();
        self.inner.record(value, &kvs);
    }
}

/// Test helper: initialize an in-memory exporter for assertions.
#[cfg(test)]
pub fn init_test() {
    // no-op in test mode - metrics are recorded via global but not exported
    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder().build();
    opentelemetry::global::set_meter_provider(provider);
}
