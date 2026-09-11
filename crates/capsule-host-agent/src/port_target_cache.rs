//! Host-side cache of sandboxd port targets keyed by generation.
//!
//! The port proxy resolves upstream addresses only through this cache (fed by
//! Watch/List observations and GetPortTarget). Missing or generation-mismatched
//! entries fail closed. Invalidation writes a tombstone so a stale List or
//! GetPortTarget cannot repopulate dropped routes.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use capsule_sandboxd_proto::v1::{PortTarget, SandboxObservation, port_target};
use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;

/// Resolved upstream for one guest port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachedPortTarget {
    /// Host-reachable TCP address for proxying.
    Tcp(SocketAddr),
    /// Backend owns exposure; host proxy must not bind a route.
    BackendManaged,
    /// Port cannot be exposed.
    Unsupported,
}

#[derive(Debug, Clone)]
struct PortEntry {
    generation: u64,
    target: CachedPortTarget,
}

#[derive(Debug, Clone)]
struct SandboxEpoch {
    generation: u64,
    host_boot_id: String,
}

#[derive(Debug, Default)]
struct CacheInner {
    /// Last sandboxd process boot observed on Watch Reconcile / List.
    host_boot_id: String,
    /// Per-sandbox generation from the latest accepted observation.
    generations: HashMap<String, SandboxEpoch>,
    /// Port targets keyed by `(sandbox_id, guest_port)`.
    ports: HashMap<(String, u16), PortEntry>,
    /// Invalidation floor: reject applies at or below this generation
    /// for the same host boot.
    tombstones: HashMap<String, SandboxEpoch>,
}

/// Shared observation-backed port target cache.
#[derive(Clone, Default)]
pub struct PortTargetCache {
    inner: Arc<RwLock<CacheInner>>,
}

impl PortTargetCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cached generation for a sandbox, if any.
    #[must_use]
    pub fn generation(&self, sandbox_id: &str) -> Option<u64> {
        self.inner
            .read()
            .generations
            .get(sandbox_id)
            .map(|epoch| epoch.generation)
    }

    /// Looks up a TCP upstream when the cached generation still matches.
    ///
    /// Returns `None` for missing entries, generation mismatch, or non-TCP
    /// targets so the proxy fails closed.
    #[must_use]
    pub fn resolve_tcp(&self, sandbox_id: &str, guest_port: u16) -> Option<SocketAddr> {
        let guard = self.inner.read();
        let generation = guard.generations.get(sandbox_id)?.generation;
        let entry = guard.ports.get(&(sandbox_id.to_string(), guest_port))?;
        if entry.generation != generation {
            return None;
        }
        match entry.target {
            CachedPortTarget::Tcp(addr) => Some(addr),
            CachedPortTarget::BackendManaged | CachedPortTarget::Unsupported => None,
        }
    }

    /// Drops cached routes and tombstones when sandboxd's process boot changes.
    pub fn note_host_boot_id(&self, host_boot_id: &str) {
        if host_boot_id.is_empty() {
            return;
        }
        let mut guard = self.inner.write();
        if guard.host_boot_id.is_empty() {
            guard.host_boot_id = host_boot_id.to_string();
            return;
        }
        if guard.host_boot_id == host_boot_id {
            return;
        }
        guard.host_boot_id = host_boot_id.to_string();
        guard.generations.clear();
        guard.ports.clear();
        guard.tombstones.clear();
    }

    /// Applies a full observation snapshot (Watch upsert or List reconcile).
    ///
    /// Older generations on the same host boot are ignored. A different
    /// `host_boot_id` is treated as a sandboxd restart and accepted.
    pub fn apply_observation(&self, observation: &SandboxObservation) {
        self.note_host_boot_id(&observation.host_boot_id);
        let mut guard = self.inner.write();
        if !accept_epoch(
            &guard,
            &observation.sandbox_id,
            observation.generation,
            &observation.host_boot_id,
        ) {
            return;
        }
        install_observation(&mut guard, observation);
    }

    /// Records a GetPortTarget response when its generation is not stale.
    pub fn apply_get_port_target(
        &self,
        sandbox_id: &str,
        guest_port: u16,
        target: &PortTarget,
        generation: u64,
    ) {
        let mut guard = self.inner.write();
        let boot = guard
            .generations
            .get(sandbox_id)
            .map(|epoch| epoch.host_boot_id.as_str())
            .or_else(|| {
                guard
                    .tombstones
                    .get(sandbox_id)
                    .map(|epoch| epoch.host_boot_id.as_str())
            })
            .unwrap_or("")
            .to_string();
        if !accept_epoch(&guard, sandbox_id, generation, &boot) {
            return;
        }
        let Some(decoded) = decode_port_target(target) else {
            return;
        };
        guard.tombstones.remove(sandbox_id);
        guard.generations.insert(
            sandbox_id.to_string(),
            SandboxEpoch {
                generation,
                host_boot_id: boot,
            },
        );
        guard.ports.insert(
            (sandbox_id.to_string(), guest_port),
            PortEntry {
                generation,
                target: decoded,
            },
        );
    }

    /// Invalidates every cached route for one sandbox (resume/destroy/Watch remove).
    ///
    /// Writes a tombstone so a late List/GetPortTarget at or below the last
    /// accepted generation cannot restore the dropped routes.
    pub fn invalidate_sandbox(&self, sandbox_id: &str) {
        let mut guard = self.inner.write();
        invalidate_locked(&mut guard, sandbox_id);
    }

    /// Applies a ListSandboxes snapshot without wiping newer Watch state.
    ///
    /// Listed snapshots go through the monotonic/tombstone guard. Ids present
    /// in the cache but absent from the list are dropped only when they were
    /// not updated after this reconcile started.
    pub fn reconcile_from_list(&self, observations: &[SandboxObservation]) {
        if let Some(boot) = observations
            .iter()
            .map(|observation| observation.host_boot_id.as_str())
            .find(|boot| !boot.is_empty())
        {
            self.note_host_boot_id(boot);
        }

        let listed: HashSet<String> = observations
            .iter()
            .map(|observation| observation.sandbox_id.clone())
            .collect();
        let snapshot: HashMap<String, u64> = self
            .inner
            .read()
            .generations
            .iter()
            .map(|(id, epoch)| (id.clone(), epoch.generation))
            .collect();

        for observation in observations {
            self.apply_observation(observation);
        }

        let mut guard = self.inner.write();
        let stale: Vec<String> = guard
            .generations
            .iter()
            .filter(|(id, _)| !listed.contains(*id))
            .filter(|(id, epoch)| snapshot.get(*id).copied() == Some(epoch.generation))
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            invalidate_locked(&mut guard, &id);
        }
    }
}

fn same_host_boot(incoming: &str, cached: &str) -> bool {
    if incoming.is_empty() || cached.is_empty() {
        return true;
    }
    incoming == cached
}

fn accept_epoch(guard: &CacheInner, sandbox_id: &str, generation: u64, host_boot_id: &str) -> bool {
    if let Some(tomb) = guard.tombstones.get(sandbox_id)
        && same_host_boot(host_boot_id, &tomb.host_boot_id)
        && generation <= tomb.generation
    {
        return false;
    }
    if let Some(current) = guard.generations.get(sandbox_id)
        && same_host_boot(host_boot_id, &current.host_boot_id)
        && generation < current.generation
    {
        return false;
    }
    true
}

fn install_observation(guard: &mut CacheInner, observation: &SandboxObservation) {
    let sandbox_id = observation.sandbox_id.as_str();
    guard.tombstones.remove(sandbox_id);
    guard.ports.retain(|(sid, _), _| sid != sandbox_id);
    guard.generations.insert(
        sandbox_id.to_string(),
        SandboxEpoch {
            generation: observation.generation,
            host_boot_id: observation.host_boot_id.clone(),
        },
    );

    for port in &observation.ports {
        let Ok(guest_port) = u16::try_from(port.guest_port) else {
            continue;
        };
        if guest_port == 0 {
            continue;
        }
        if let Some(target) = decode_port_target(port) {
            guard.ports.insert(
                (sandbox_id.to_string(), guest_port),
                PortEntry {
                    generation: observation.generation,
                    target,
                },
            );
        }
    }
}

fn invalidate_locked(guard: &mut CacheInner, sandbox_id: &str) {
    let tomb = match guard.generations.remove(sandbox_id) {
        Some(epoch) => epoch,
        None => SandboxEpoch {
            generation: u64::MAX,
            host_boot_id: guard.host_boot_id.clone(),
        },
    };
    guard.ports.retain(|(sid, _), _| sid != sandbox_id);
    guard.tombstones.insert(sandbox_id.to_string(), tomb);
}

fn decode_port_target(port: &PortTarget) -> Option<CachedPortTarget> {
    match port.target.as_ref()? {
        port_target::Target::TcpAddr(addr) => {
            let addr = SocketAddr::from_str(addr).ok()?;
            Some(CachedPortTarget::Tcp(addr))
        }
        port_target::Target::BackendManaged(true) => Some(CachedPortTarget::BackendManaged),
        port_target::Target::Unsupported(true) => Some(CachedPortTarget::Unsupported),
        port_target::Target::BackendManaged(false) | port_target::Target::Unsupported(false) => {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsule_sandboxd_proto::v1::SandboxObservation;

    fn observation(
        id: &str,
        generation: u64,
        ports: Vec<PortTarget>,
        host_boot_id: &str,
    ) -> SandboxObservation {
        SandboxObservation {
            sandbox_id: id.into(),
            observed_state: "running".into(),
            generation,
            host_boot_id: host_boot_id.into(),
            guest_boot_id: String::new(),
            backend: "mock".into(),
            ports,
            ssh: None,
            policy_epoch: 1,
            assignment_fencing_token: "1.1".into(),
            updated_at: "t".into(),
        }
    }

    fn tcp_port(guest: u16, addr: &str) -> PortTarget {
        PortTarget {
            guest_port: u32::from(guest),
            target: Some(port_target::Target::TcpAddr(addr.into())),
        }
    }

    #[test]
    fn resolve_tcp_requires_matching_generation() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            3,
            vec![tcp_port(8080, "127.0.0.1:18080")],
            "boot",
        ));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("127.0.0.1:18080".parse().unwrap())
        );

        {
            let mut guard = cache.inner.write();
            if let Some(epoch) = guard.generations.get_mut("sbx_a") {
                epoch.generation = 4;
            }
        }
        assert_eq!(cache.resolve_tcp("sbx_a", 8080), None);
    }

    #[test]
    fn newer_observation_drops_stale_routes() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            1,
            vec![
                tcp_port(8080, "127.0.0.1:18080"),
                tcp_port(22, "127.0.0.1:22"),
            ],
            "boot",
        ));
        cache.apply_observation(&observation(
            "sbx_a",
            2,
            vec![tcp_port(8080, "10.0.0.2:8080")],
            "boot",
        ));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("10.0.0.2:8080".parse().unwrap())
        );
        assert_eq!(cache.resolve_tcp("sbx_a", 22), None);
    }

    #[test]
    fn invalidate_sandbox_clears_routes() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            1,
            vec![tcp_port(8080, "127.0.0.1:18080")],
            "boot",
        ));
        cache.invalidate_sandbox("sbx_a");
        assert_eq!(cache.resolve_tcp("sbx_a", 8080), None);
        assert_eq!(cache.generation("sbx_a"), None);
    }

    #[test]
    fn stale_observation_is_ignored() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            5,
            vec![tcp_port(8080, "127.0.0.1:5")],
            "boot",
        ));
        cache.apply_observation(&observation(
            "sbx_a",
            2,
            vec![tcp_port(8080, "127.0.0.1:2")],
            "boot",
        ));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("127.0.0.1:5".parse().unwrap())
        );
    }

    #[test]
    fn tombstone_rejects_stale_list_and_get_after_invalidate() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            4,
            vec![tcp_port(8080, "127.0.0.1:4")],
            "boot",
        ));
        cache.invalidate_sandbox("sbx_a");
        cache.apply_observation(&observation(
            "sbx_a",
            4,
            vec![tcp_port(8080, "127.0.0.1:4")],
            "boot",
        ));
        assert_eq!(cache.resolve_tcp("sbx_a", 8080), None);

        cache.apply_get_port_target("sbx_a", 8080, &tcp_port(8080, "127.0.0.1:4"), 4);
        assert_eq!(cache.resolve_tcp("sbx_a", 8080), None);

        cache.apply_observation(&observation(
            "sbx_a",
            5,
            vec![tcp_port(8080, "10.0.0.2:8080")],
            "boot",
        ));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("10.0.0.2:8080".parse().unwrap())
        );
    }

    #[test]
    fn reconcile_from_list_does_not_wipe_newer_watch_state() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_keep",
            3,
            vec![tcp_port(80, "127.0.0.1:80")],
            "boot",
        ));
        cache.apply_observation(&observation(
            "sbx_gone",
            1,
            vec![tcp_port(22, "127.0.0.1:22")],
            "boot",
        ));
        cache.invalidate_sandbox("sbx_gone");

        cache.reconcile_from_list(&[
            observation("sbx_keep", 2, vec![tcp_port(80, "10.0.0.1:80")], "boot"),
            observation("sbx_gone", 1, vec![tcp_port(22, "127.0.0.1:22")], "boot"),
        ]);

        assert_eq!(
            cache.resolve_tcp("sbx_keep", 80),
            Some("127.0.0.1:80".parse().unwrap())
        );
        assert_eq!(cache.resolve_tcp("sbx_gone", 22), None);
    }

    #[test]
    fn reconcile_from_list_drops_absent_ids_not_updated_during_reconcile() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_live",
            1,
            vec![tcp_port(80, "127.0.0.1:80")],
            "boot",
        ));
        cache.apply_observation(&observation(
            "sbx_stale",
            1,
            vec![tcp_port(22, "127.0.0.1:22")],
            "boot",
        ));

        cache.reconcile_from_list(&[observation(
            "sbx_live",
            1,
            vec![tcp_port(80, "127.0.0.1:80")],
            "boot",
        )]);

        assert!(cache.resolve_tcp("sbx_live", 80).is_some());
        assert_eq!(cache.resolve_tcp("sbx_stale", 22), None);
        assert_eq!(cache.generation("sbx_stale"), None);
    }

    #[test]
    fn host_boot_id_change_resets_generation_floor() {
        let cache = PortTargetCache::new();
        cache.apply_observation(&observation(
            "sbx_a",
            9,
            vec![tcp_port(8080, "127.0.0.1:9")],
            "boot-old",
        ));
        cache.apply_observation(&observation(
            "sbx_a",
            1,
            vec![tcp_port(8080, "127.0.0.1:1")],
            "boot-new",
        ));
        assert_eq!(
            cache.resolve_tcp("sbx_a", 8080),
            Some("127.0.0.1:1".parse().unwrap())
        );
        assert_eq!(cache.generation("sbx_a"), Some(1));
    }
}
