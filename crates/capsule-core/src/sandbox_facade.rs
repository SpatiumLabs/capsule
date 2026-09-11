//! Public sandbox management surface consumed by the platform API.
//!
//! `SandboxFacade` is the seam between API-style consumers (the `capsule-api`
//! HTTP layer today, a remote control-plane client tomorrow) and whatever
//! serves sandboxes behind it (an in-process host agent, a stub, a test
//! mock). Host-only control operations (prepare, fenced boot, drain, host
//! inventory) are deliberately not part of this surface; they live behind
//! the host's own control interface.

use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::{
    AccessLease, ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest,
    LeaseAction, LeaseScope, PortForwardEndpoint, PortForwardRequest, PortForwardResponse, Result,
    SandboxError, SandboxInfo, SandboxSpec, SshInfo, TaskEvent, TaskInfo, TaskRequest,
};

/// The sandbox operations surface exposed to API consumers.
///
/// Every backend that can serve sandbox traffic behind the HTTP API
/// (in-process host agent, stub, test mock) implements this trait.
/// Capability-optional operations (leases, port forwarding) default to
/// [`SandboxError::NotImplemented`] so lean backends only implement what
/// they actually support.
#[async_trait]
pub trait SandboxFacade: Send + Sync {
    /// Creates a new sandbox from the given spec.
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxInfo>;

    /// Returns a page of sandboxes sorted by id, plus the next cursor.
    async fn list(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)>;

    /// Returns the current info for one sandbox.
    async fn get(&self, id: &str) -> Result<SandboxInfo>;

    /// Destroys a sandbox and releases its host resources.
    async fn destroy(&self, id: &str) -> Result<()>;

    /// Purges a stopped sandbox's remaining state.
    async fn purge(&self, id: &str) -> Result<()>;

    /// Stops a running sandbox without purging its host-side record.
    async fn stop(&self, id: &str) -> Result<()>;

    /// Bumps the idle timeout so the sandbox is not reaped.
    async fn keepalive(&self, id: &str) -> Result<()>;

    /// Runs a command inside an existing sandbox.
    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResponse>;

    /// Reads a file from the sandbox filesystem.
    async fn file_read(&self, id: &str, path: &str) -> Result<FileReadResponse>;

    /// Writes a file to the sandbox filesystem.
    async fn file_write(&self, id: &str, req: FileWriteRequest) -> Result<FileInfo>;

    /// Lists files under a directory in the sandbox.
    async fn file_list(&self, id: &str, dir: &str, recursive: bool) -> Result<Vec<FileInfo>>;

    /// Starts a background task in the sandbox.
    async fn task_start(&self, id: &str, req: TaskRequest) -> Result<TaskInfo>;

    /// Returns the current state of a task.
    async fn task_get(&self, id: &str, task_id: &str) -> Result<TaskInfo>;

    /// Cancels a running task.
    async fn task_cancel(&self, id: &str, task_id: &str) -> Result<()>;

    /// Subscribes to the event stream of a task.
    fn task_subscribe(&self, id: &str, task_id: &str) -> Result<broadcast::Receiver<TaskEvent>>;

    /// Returns SSH connection info for the sandbox.
    async fn ssh_info(&self, id: &str) -> Result<SshInfo>;

    /// Issues a signed access lease for a sandbox action.
    async fn issue_access_lease(
        &self,
        _sandbox_id: &str,
        _action: LeaseAction,
        _scope: LeaseScope,
    ) -> Result<AccessLease> {
        Err(SandboxError::NotImplemented(
            "access lease issuance is not implemented by this facade",
        ))
    }

    /// Exposes a guest port on the host and returns the bound endpoint.
    async fn expose_port(
        &self,
        _id: &str,
        _req: PortForwardRequest,
    ) -> Result<PortForwardEndpoint> {
        Err(SandboxError::NotImplemented(
            "port forwarding is not implemented by this facade",
        ))
    }

    /// Revokes a previously exposed port endpoint.
    async fn revoke_port(&self, _id: &str, _endpoint_id: &str) -> Result<PortForwardResponse> {
        Err(SandboxError::NotImplemented(
            "port forwarding is not implemented by this facade",
        ))
    }

    /// Lists the currently exposed port endpoints of a sandbox.
    async fn list_ports(&self, _id: &str) -> Result<Vec<PortForwardEndpoint>> {
        Err(SandboxError::NotImplemented(
            "port forwarding is not implemented by this facade",
        ))
    }

    /// Suspends a running sandbox. The default only verifies existence.
    async fn suspend(&self, id: &str) -> Result<()> {
        let _ = self.get(id).await?;
        Ok(())
    }

    /// Resumes a suspended sandbox. The default only verifies existence.
    async fn resume(&self, id: &str) -> Result<()> {
        let _ = self.get(id).await?;
        Ok(())
    }
}
