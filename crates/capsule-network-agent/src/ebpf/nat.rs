use std::net::Ipv4Addr;
use std::time::Instant;

use tracing::{debug, info, warn};

use super::loader::EbpfLoader;
use crate::error::{NetworkAgentError, NetworkResult};
use crate::metrics::NETWORK_METRICS;
use crate::receipt::{ResourceKind, ResourceReceipt};

pub struct EbpfNatManager {
    loader: EbpfLoader,
}

impl EbpfNatManager {
    pub fn new(loader: EbpfLoader) -> Self {
        Self { loader }
    }

    pub fn loader(&self) -> &EbpfLoader {
        &self.loader
    }

    pub fn provision_nat(
        &self,
        sandbox_id: &str,
        if_name: &str,
        host_ip: Ipv4Addr,
        ifindex: u32,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        let start = Instant::now();
        let mut receipts = Vec::new();

        debug!(
            sandbox_id = %sandbox_id,
            if_name = %if_name,
            host_ip = %host_ip,
            "provisioning eBPF NAT via TC"
        );

        let host_ip_be = u32::from_be_bytes(host_ip.octets());

        self.loader
            .update_host_ip(ifindex, host_ip_be)
            .map_err(|e| NetworkAgentError::NatSetupFailed {
                sandbox_id: sandbox_id.to_string(),
                detail: format!("failed to set host IP in BPF map: {e}"),
            })?;

        self.loader
            .attach_tc_nat(if_name)
            .map_err(|e| NetworkAgentError::NatSetupFailed {
                sandbox_id: sandbox_id.to_string(),
                detail: format!("failed to attach TC NAT program: {e}"),
            })?;

        let latency = start.elapsed();

        receipts.push(ResourceReceipt {
            sandbox_id: sandbox_id.to_string(),
            resource_name: format!("ebpf-tc-nat-{if_name}"),
            kind: ResourceKind::Nat,
            created: true,
            provision_latency: latency,
        });

        NETWORK_METRICS.nat.setup_completed.inc(&[]);
        info!(
            sandbox_id = %sandbox_id,
            if_name = %if_name,
            host_ip = %host_ip,
            latency_ms = latency.as_millis(),
            "eBPF NAT (TC) provisioned"
        );

        Ok(receipts)
    }

    pub fn deprovision_nat(
        &self,
        sandbox_id: &str,
        if_name: &str,
        ifindex: u32,
    ) -> NetworkResult<Vec<ResourceReceipt>> {
        let start = Instant::now();
        let mut receipts = Vec::new();

        debug!(
            sandbox_id = %sandbox_id,
            if_name = %if_name,
            "deprovisioning eBPF NAT"
        );

        match self.loader.detach_tc_nat(if_name) {
            Ok(()) => {}
            Err(e) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    if_name = %if_name,
                    error = %e,
                    "TC NAT detach failed (may already be detached)"
                );
            }
        }

        let _ = self.loader.gc_nat_entries(ifindex);

        NETWORK_METRICS
            .nat
            .sessions
            .set(0f64, &[("sandbox_id", sandbox_id)]);

        let latency = start.elapsed();

        receipts.push(ResourceReceipt {
            sandbox_id: sandbox_id.to_string(),
            resource_name: format!("ebpf-tc-nat-{if_name}"),
            kind: ResourceKind::Nat,
            created: false,
            provision_latency: latency,
        });

        info!(
            sandbox_id = %sandbox_id,
            if_name = %if_name,
            latency_ms = latency.as_millis(),
            "eBPF NAT deprovisioned"
        );

        Ok(receipts)
    }
}
