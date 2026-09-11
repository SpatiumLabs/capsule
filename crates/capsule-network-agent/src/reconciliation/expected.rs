//! Pre-computed expected resource names for known sandboxes.
//!
//! Calls into [`crate::identity`] for deterministic hashing and guest-IP
//! derivation, avoiding duplicate logic.  Naming conventions are local to
//! this module because they are reconciliation-specific knowledge, not
//! part of the identity module's public contract.

use std::collections::BTreeSet;

use crate::identity::{fnv1a64, sandbox_guest_ip};

use super::KnownSandboxIds;

// Naming prefix constants
pub(super) const PREFIX_SANDBOX_IF: &str = "cvx";
pub(super) const PREFIX_HOST_PEER_VM: &str = "hp-";
pub(super) const PREFIX_HOST_PEER_CT: &str = "hpc";
pub(super) const PREFIX_NS_CT: &str = "cnt-";
pub(super) const PREFIX_NFT_TABLE: &str = "capsule-sbx-";

/// Returns true if the link name matches Capsule naming conventions.
pub(super) fn is_capsule_link(name: &str) -> bool {
    name.starts_with(PREFIX_SANDBOX_IF)
        || name.starts_with(PREFIX_HOST_PEER_VM)
        || name.starts_with(PREFIX_HOST_PEER_CT)
}

/// Returns true if the network namespace name matches Capsule conventions.
pub(super) fn is_capsule_ns(name: &str) -> bool {
    name.starts_with(PREFIX_SANDBOX_IF) || name.starts_with(PREFIX_NS_CT)
}

/// Returns the resource class for a link name.
pub(super) fn link_kind_to_class(name: &str) -> super::ResourceClass {
    if name.starts_with(PREFIX_SANDBOX_IF) {
        super::ResourceClass::TapOrVeth
    } else if name.starts_with(PREFIX_HOST_PEER_VM) || name.starts_with(PREFIX_HOST_PEER_CT) {
        super::ResourceClass::HostPeer
    } else {
        super::ResourceClass::Unknown
    }
}

/// Pre-computed set of expected network resource names.
#[derive(Debug, Clone)]
pub(super) struct ExpectedResources {
    /// Interface names expected for known sandboxes.
    pub link_names: BTreeSet<String>,
    /// Namespace base names expected (without `/var/run/netns/` prefix).
    pub ns_names: BTreeSet<String>,
    /// Guest IPs expected for known sandboxes (for DNS/route matching).
    pub guest_ips: BTreeSet<String>,
}

impl ExpectedResources {
    /// Build expected resource names for every known sandbox.
    ///
    /// For each sandbox ID, computes the fnv1a64 hash and generates
    /// the possible link and namespace names for both MicroVM and
    /// Container backends. This is intentionally over-inclusive.
    pub(super) fn from_known_sandbox_ids(known_ids: &KnownSandboxIds) -> Self {
        let mut link_names = BTreeSet::new();
        let mut ns_names = BTreeSet::new();
        let mut guest_ips = BTreeSet::new();

        for sandbox_id in known_ids {
            let hash = fnv1a64(sandbox_id.as_bytes());
            let hex = format!("{:010x}", hash & 0xffffffffff);

            // Guest IP from the identity module's deterministic formula
            let ip = sandbox_guest_ip(sandbox_id);
            guest_ips.insert(ip.to_string());

            // Sandbox-side interface name (same for both backends)
            let sandbox_if = format!("{PREFIX_SANDBOX_IF}{hex}");
            link_names.insert(sandbox_if.clone());

            // Host-side peer for MicroVM: hp-cvx{hex}
            link_names.insert(format!("{PREFIX_HOST_PEER_VM}{PREFIX_SANDBOX_IF}{hex}"));

            // Host-side peer for Container: hpc{hex}
            link_names.insert(format!("{PREFIX_HOST_PEER_CT}{hex}"));

            // Namespace names
            ns_names.insert(sandbox_if.clone()); // MicroVM ns
            ns_names.insert(format!("{PREFIX_NS_CT}{PREFIX_SANDBOX_IF}{hex}")); // Container ns
        }

        Self {
            link_names,
            ns_names,
            guest_ips,
        }
    }

    /// Returns true if the given link name matches any expected sandbox.
    pub(super) fn owns_link(&self, name: &str) -> bool {
        self.link_names.contains(name)
    }

    /// Returns true if the given namespace base name matches any expected sandbox.
    pub(super) fn owns_ns(&self, name: &str) -> bool {
        self.ns_names.contains(name)
    }

    /// Returns true if the given guest IP matches any expected sandbox.
    pub(super) fn owns_guest_ip(&self, ip: &str) -> bool {
        self.guest_ips.contains(ip)
    }
}
