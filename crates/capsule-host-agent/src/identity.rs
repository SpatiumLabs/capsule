//! Host-level identity used for inventory reporting and structured logging.

use capsule_core::RuntimeType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostIdentity {
    pub host_id: String,
    pub cell_id: String,
    pub region: String,
}

impl HostIdentity {
    pub fn new(host_id: String, cell_id: String, region: String) -> Self {
        Self {
            host_id,
            cell_id,
            region,
        }
    }

    pub fn from_env(default_region: &str) -> Self {
        let host_id = std::env::var("CAPSULE_HOST_ID").unwrap_or_else(|_| default_host_id());
        let cell_id = std::env::var("CAPSULE_CELL_ID").unwrap_or_else(|_| "default-cell".into());
        let region = std::env::var("CAPSULE_REGION").unwrap_or_else(|_| default_region.into());
        Self {
            host_id,
            cell_id,
            region,
        }
    }

    pub(crate) fn default_host_id() -> String {
        default_host_id()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostCapacity {
    pub cpu_count: u32,
    pub memory_mb_total: u64,
    pub memory_mb_available: u64,
    pub disk_mb_total: u64,
    pub disk_mb_available: u64,
}

impl HostCapacity {
    pub fn detect() -> Self {
        let cpu_count = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1);

        let (mem_total_kb, mem_avail_kb) = detect_memory_kb();

        let (disk_total_mb, disk_avail_mb) = detect_disk_mb();

        Self {
            cpu_count,
            memory_mb_total: mem_total_kb / 1024,
            memory_mb_available: mem_avail_kb / 1024,
            disk_mb_total: disk_total_mb,
            disk_mb_available: disk_avail_mb,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostInventory {
    pub identity: HostIdentity,
    pub capacity: HostCapacity,
    pub supported_backends: Vec<RuntimeType>,
    pub agent_version: String,
}

fn default_host_id() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown-host".into())
}

fn detect_memory_kb() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let info = sys_info::mem_info();
        match info {
            Ok(info) => (info.total, info.avail),
            Err(_) => (0, 0),
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let total = Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|b| b / 1024)
            .unwrap_or(0);

        let page_size = Command::new("sysctl")
            .args(["-n", "vm.pagesize"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(4096);

        let free_pages = Command::new("sysctl")
            .args(["-n", "vm.page_free_count"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);

        (total, page_size * free_pages / 1024)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        (0, 0)
    }
}

fn detect_disk_mb() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let info = sys_info::disk_info();
        match info {
            Ok(info) => linux_disk_kb_to_mb(info.total, info.free),
            Err(_) => (0, 0),
        }
    }

    #[cfg(target_os = "macos")]
    {
        parse_df_output()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        (0, 0)
    }
}

#[cfg(target_os = "macos")]
fn parse_df_output() -> (u64, u64) {
    use std::process::Command;
    Command::new("df")
        .args(["-m", "/"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines().nth(1).and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    Some((parts[1].parse::<u64>().ok()?, parts[3].parse::<u64>().ok()?))
                } else {
                    None
                }
            })
        })
        .unwrap_or((10240, 10240))
}

#[cfg(target_os = "linux")]
fn linux_disk_kb_to_mb(total_kb: u64, free_kb: u64) -> (u64, u64) {
    (total_kb / 1024, free_kb / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // These tests mutate process-global env vars, so they must not run
    // concurrently within the same test binary.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn host_identity_uses_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("CAPSULE_HOST_ID", "test-host");
            std::env::set_var("CAPSULE_CELL_ID", "test-cell");
            std::env::set_var("CAPSULE_REGION", "test-region");
        }

        let identity = HostIdentity::from_env("default-region");
        assert_eq!(identity.host_id, "test-host");
        assert_eq!(identity.cell_id, "test-cell");
        assert_eq!(identity.region, "test-region");

        unsafe {
            std::env::remove_var("CAPSULE_HOST_ID");
            std::env::remove_var("CAPSULE_CELL_ID");
            std::env::remove_var("CAPSULE_REGION");
        }
    }

    #[test]
    fn host_identity_falls_back() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("CAPSULE_HOST_ID");
            std::env::remove_var("CAPSULE_CELL_ID");
            std::env::remove_var("CAPSULE_REGION");
        }
        let identity = HostIdentity::from_env("fallback-region");
        assert!(!identity.host_id.is_empty());
        assert_eq!(identity.cell_id, "default-cell");
        assert_eq!(identity.region, "fallback-region");
    }

    #[test]
    fn host_capacity_detects_cpu_count() {
        let capacity = HostCapacity::detect();
        assert!(capacity.cpu_count >= 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_units_convert_from_kb_to_mb() {
        assert_eq!(linux_disk_kb_to_mb(4 * 1024, 2 * 1024), (4, 2));
    }
}
