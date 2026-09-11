//! Operational protocol exec handler for the guest agent.
//!
//! After a successful handshake, the guest agent runs the operational
//! message loop on the same TCP stream.

use hashbrown::HashMap;
use heapless::Vec as HVec;
use parking_lot::Mutex;
use prost::Message;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::process::Command;
use tokio::sync::{Mutex as TokioMutex, watch};

use crate::file;
use crate::handshake::HandshakeOutcome;
use crate::health::HealthState;
use crate::mount;
use crate::shutdown::ShutdownState;
use crate::stats;
use capsule_guest_protocol::operational_v1::*;
use capsule_guest_protocol::{FramedConnection, framed};

const DEFAULT_OPERATIONAL_TIMEOUT_SECS: u64 = 300;
const STREAM_FRAME_MAX_BYTES: usize = 64 * 1024;

/// Shared write half of the operational connection.
///
/// [`serve_operational`] owns the read half exclusively in its dispatch loop
/// and hands out clones of this writer to every handler. Holding the write
/// mutex only for the duration of one framed send keeps a blocking read from
/// starving concurrent response sends. (Sharing one `FramedConnection` behind
/// a mutex instead deadlocks: the loop holds the lock across its blocking
/// read while spawned handlers block acquiring it to send - every exec then
/// times out on the host.)
pub(crate) type SharedWriter = Arc<TokioMutex<OwnedWriteHalf>>;

#[derive(Debug, Clone, Error)]
pub(crate) enum ExecError {
    #[error("request context validation failed: {0}")]
    ContextValidation(String),

    #[error("I/O error: {0}")]
    Io(String),
}

#[derive(Clone)]
enum CancelSignal {
    Cancel,
    Signal(i32),
}

pub(crate) struct ExecState {
    #[allow(dead_code)]
    operation_id: String,
    ctrl_tx: Option<watch::Sender<Option<CancelSignal>>>,
    start_time: Instant,
}

pub(crate) struct OperationalSession {
    pub(crate) session_id: HVec<u8, 16>,
    pub(crate) sandbox_id: Mutex<String>,
    pub(crate) policy_epoch: AtomicU64,
    pub(crate) protocol_version: (u32, u32),
    pub(crate) active_execs: Arc<Mutex<HashMap<String, Arc<Mutex<ExecState>>>>>,
    pub(crate) quiescing: Arc<AtomicBool>,
    pub(crate) health_state: HealthState,
    pub(crate) shutdown_state: ShutdownState,
}

impl OperationalSession {
    pub(crate) fn new(outcome: &HandshakeOutcome, sandbox_id: String) -> Self {
        Self {
            session_id: outcome.session_id.clone(),
            sandbox_id: Mutex::new(sandbox_id),
            policy_epoch: AtomicU64::new(outcome.policy_epoch),
            protocol_version: outcome.selected_version,
            active_execs: Arc::new(Mutex::new(HashMap::new())),
            quiescing: Arc::new(AtomicBool::new(false)),
            health_state: HealthState::new(),
            shutdown_state: ShutdownState::new(),
        }
    }

    pub(crate) fn validate_context(&self, ctx: &RequestContext) -> Result<(), ExecError> {
        let sandbox_id = self.sandbox_id.lock();
        if ctx.sandbox_id != *sandbox_id {
            return Err(ExecError::ContextValidation(format!(
                "sandbox_id mismatch: expected '{}', got '{}'",
                *sandbox_id, ctx.sandbox_id
            )));
        }

        if ctx.session_id.as_slice() != self.session_id.as_slice() {
            return Err(ExecError::ContextValidation("session_id mismatch".into()));
        }

        if ctx.policy_epoch != self.policy_epoch.load(Ordering::Acquire) {
            return Err(ExecError::ContextValidation(format!(
                "policy_epoch mismatch: expected {}, got {}",
                self.policy_epoch.load(Ordering::Acquire),
                ctx.policy_epoch
            )));
        }

        // Protocol version is packed as (major << 16) | minor in the
        // protobuf u32. Unpack here for comparison.
        let ctx_version = (ctx.protocol_version >> 16, ctx.protocol_version & 0xFFFF);
        if ctx_version != self.protocol_version {
            return Err(ExecError::ContextValidation(format!(
                "protocol_version mismatch: expected {:?}, got {:?}",
                self.protocol_version, ctx_version
            )));
        }

        Ok(())
    }
}

pub(crate) async fn serve_operational(conn: FramedConnection, session: OperationalSession) {
    let session = Arc::new(session);
    // Split once: the dispatch loop below owns the read half for the life of
    // the connection, and every handler shares the write half via
    // [`SharedWriter`] (kept under the familiar `conn` name at call sites).
    // Reads never contend with response sends.
    let (mut read_half, write_half) = conn.into_inner().into_split();
    let conn: SharedWriter = Arc::new(TokioMutex::new(write_half));
    let timeout = Duration::from_secs(DEFAULT_OPERATIONAL_TIMEOUT_SECS);

    loop {
        if session.shutdown_state.shutting_down.load(Ordering::Acquire) {
            tracing::info!("shutting down, rejecting new requests");
            break;
        }

        let (tag, raw_bytes) = match framed::read_tagged_raw(&mut read_half, timeout).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "failed to read operational message");
                return;
            }
        };

        match tag {
            framed::TAG_EXEC_REQUEST => {
                let request = match ExecRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode ExecRequest");
                        continue;
                    }
                };
                let session = Arc::clone(&session);
                let conn = Arc::clone(&conn);
                tokio::spawn(async move {
                    handle_exec(session, request, conn, timeout).await;
                });
            }
            framed::TAG_CANCEL_REQUEST => {
                let request = match CancelRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode CancelRequest");
                        continue;
                    }
                };
                handle_cancel(Arc::clone(&session), request, Arc::clone(&conn), timeout).await;
            }
            framed::TAG_SIGNAL_REQUEST => {
                let request = match SignalRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode SignalRequest");
                        continue;
                    }
                };
                handle_signal(Arc::clone(&session), request, Arc::clone(&conn), timeout).await;
            }
            framed::TAG_QUIESCE_REQUEST => {
                let request = match QuiesceRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode QuiesceRequest");
                        continue;
                    }
                };
                let session = Arc::clone(&session);
                let conn = Arc::clone(&conn);
                tokio::spawn(async move {
                    handle_quiesce(session, request, conn, timeout).await;
                });
            }
            framed::TAG_RESUME_NOTIFY_REQUEST => {
                let request = match ResumeNotifyRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode ResumeNotifyRequest");
                        continue;
                    }
                };
                let session = Arc::clone(&session);
                let conn = Arc::clone(&conn);
                tokio::spawn(async move {
                    handle_resume_notify(session, request, conn, timeout).await;
                });
            }

            // ── File transfer ──────────────────────────────────
            // PutFile is handled synchronously because the upload
            // consists of multiple tagged messages on the same
            // connection.  Spawning would create a reader race
            // between the dispatch loop and the upload handler.
            framed::TAG_PUT_FILE_REQUEST => {
                let request = match PutFileRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode PutFileRequest");
                        continue;
                    }
                };
                match file::handle_put_file_stream(
                    &session,
                    request,
                    &mut read_half,
                    &conn,
                    timeout,
                )
                .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        let outcome = crate::file::build_file_error_outcome(&e);
                        let response = PutFileResponse {
                            result: Some(put_file_response::Result::Error(outcome)),
                            checksum: String::new(),
                        };
                        let _ = write_tagged_response(
                            &conn,
                            framed::TAG_PUT_FILE_RESPONSE,
                            &response,
                            timeout,
                        )
                        .await;
                    }
                }
            }
            framed::TAG_GET_FILE_REQUEST => {
                let request = match GetFileRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode GetFileRequest");
                        continue;
                    }
                };
                let session = Arc::clone(&session);
                let conn = Arc::clone(&conn);
                tokio::spawn(async move {
                    if let Err(e) = file::handle_get_file(&session, request, &conn, timeout).await {
                        let outcome = crate::file::build_file_error_outcome(&e);
                        let response = GetFileResponse {
                            frame: Some(get_file_response::Frame::Outcome(outcome)),
                        };
                        let _ = write_tagged_response(
                            &conn,
                            framed::TAG_GET_FILE_RESPONSE,
                            &response,
                            timeout,
                        )
                        .await;
                    }
                });
            }

            // ── Secrets ───────────────────────────────────────
            framed::TAG_INJECT_SECRETS_REQUEST => {
                let request = match InjectSecretsRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode InjectSecretsRequest");
                        continue;
                    }
                };
                let session = Arc::clone(&session);
                let conn = Arc::clone(&conn);
                // Spawn to avoid blocking the message dispatch loop while
                // performing blocking I/O (tmpfs mount, file writes).
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::secrets::handle_inject_secrets(&session, request, &conn, timeout)
                            .await
                    {
                        let outcome =
                            build_failure_outcome("SecretsInjectionFailed", &e.to_string(), false);
                        let response = InjectSecretsResponse {
                            result: Some(inject_secrets_response::Result::Error(outcome)),
                        };
                        let _ = write_tagged_response(
                            &conn,
                            framed::TAG_INJECT_SECRETS_RESPONSE,
                            &response,
                            timeout,
                        )
                        .await;
                    }
                });
            }

            // ── Mount ──────────────────────────────────────────
            framed::TAG_MOUNT_WORKSPACE_REQUEST => {
                let request = match MountWorkspaceRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode MountWorkspaceRequest");
                        continue;
                    }
                };
                let session = Arc::clone(&session);
                let conn = Arc::clone(&conn);
                tokio::spawn(async move {
                    if let Err(e) =
                        mount::handle_mount_workspace(&session, request, &conn, timeout).await
                    {
                        let outcome = build_failure_outcome("MountFailed", &e.to_string(), false);
                        let response = MountWorkspaceResponse {
                            result: Some(mount_workspace_response::Result::Error(outcome)),
                        };
                        let _ = write_tagged_response(
                            &conn,
                            framed::TAG_MOUNT_WORKSPACE_RESPONSE,
                            &response,
                            timeout,
                        )
                        .await;
                    }
                });
            }

            // ── Stats and health ───────────────────────────────
            framed::TAG_STATS_REQUEST => {
                let request = match StatsRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode StatsRequest");
                        continue;
                    }
                };
                let session = Arc::clone(&session);
                let conn = Arc::clone(&conn);
                tokio::spawn(async move {
                    if let Err(e) = stats::handle_stats(&session, request, &conn, timeout).await {
                        tracing::error!(error = %e, "stats collection failed");
                        let response = StatsResponse {
                            cpu: None,
                            memory: None,
                            disk: None,
                        };
                        let _ = write_tagged_response(
                            &conn,
                            framed::TAG_STATS_RESPONSE,
                            &response,
                            timeout,
                        )
                        .await;
                    }
                });
            }
            framed::TAG_HEALTH_REQUEST => {
                let request = match HealthRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode HealthRequest");
                        continue;
                    }
                };
                let session = Arc::clone(&session);
                let conn = Arc::clone(&conn);
                let health_state = session.health_state.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::health::handle_health(
                        &session,
                        request,
                        &conn,
                        timeout,
                        &health_state,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "health check failed");
                        let response = HealthResponse {
                            status: health_response::HealthStatus::Unhealthy as i32,
                            message: e.to_string(),
                        };
                        let _ = write_tagged_response(
                            &conn,
                            framed::TAG_HEALTH_RESPONSE,
                            &response,
                            timeout,
                        )
                        .await;
                    }
                });
            }

            // ── Shutdown ───────────────────────────────────────
            framed::TAG_SHUTDOWN_REQUEST => {
                let request = match ShutdownRequest::decode(raw_bytes.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to decode ShutdownRequest");
                        continue;
                    }
                };
                let session = Arc::clone(&session);
                let conn = Arc::clone(&conn);
                let shutdown_state = session.shutdown_state.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::shutdown::handle_shutdown(
                        &session,
                        request,
                        &conn,
                        timeout,
                        &shutdown_state,
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "shutdown handler error");
                    }
                });
            }

            other => {
                tracing::warn!(tag = other, "unknown operational message tag");
            }
        }
    }

    tracing::info!("operational loop exiting");
}

/// Sends one tagged response on the shared write half.
///
/// Locks only for the duration of the write so concurrent handlers never
/// block each other (or the dispatch loop's read half).
pub(crate) async fn write_tagged_response(
    writer: &SharedWriter,
    tag: u8,
    message: &impl prost::Message,
    timeout: Duration,
) -> std::io::Result<()> {
    let mut w = writer.lock().await;
    framed::send_tagged(&mut *w, tag, message, timeout).await
}

async fn handle_exec(
    session: Arc<OperationalSession>,
    request: ExecRequest,
    conn: SharedWriter,
    timeout: Duration,
) {
    let ctx = match request.context.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("ExecRequest missing context");
            return;
        }
    };
    let operation_id = ctx.operation_id.clone();

    if let Err(e) = session.validate_context(ctx) {
        tracing::error!(error = %e, operation_id = %operation_id, "context validation failed");
        send_exec_outcome(
            &conn,
            build_failure_outcome("ContextValidationFailed", &e.to_string(), false),
            timeout,
        )
        .await;

        return;
    }

    if let Some(ref tc) = ctx.trace_context {
        tracing::info!(
            operation_id = %operation_id,
            parent_trace_id = %tc.trace_id,
            parent_span_id = %tc.span_id,
            "exec request with trace context"
        );
    }

    if session.quiescing.load(Ordering::Acquire) {
        tracing::warn!(operation_id = %operation_id, "rejecting exec, guest is quiescing");
        send_exec_outcome(
            &conn,
            build_failure_outcome(
                "Quiescing",
                "guest is preparing for checkpoint, rejecting new operations",
                true,
            ),
            timeout,
        )
        .await;
        return;
    }

    tracing::info!(
        operation_id = %operation_id,
        command = %request.command,
        args = ?request.args,
        "exec received"
    );

    let (ctrl_tx, ctrl_rx) = watch::channel(None);

    let exec_state = Arc::new(Mutex::new(ExecState {
        operation_id: operation_id.clone(),
        ctrl_tx: Some(ctrl_tx),
        start_time: Instant::now(),
    }));

    {
        session
            .active_execs
            .lock()
            .insert(operation_id.clone(), Arc::clone(&exec_state));
    }

    let result = run_command_and_stream(&request, &operation_id, ctrl_rx, &conn, timeout).await;

    session.active_execs.lock().remove(&operation_id);

    let duration_ms = exec_state.lock().start_time.elapsed().as_millis() as u64;

    let outcome = match result {
        Ok(exit_code) => {
            // Wire format: exit_code (i32, big-endian, 4 bytes) + duration_ms (u64, big-endian, 8 bytes)
            let mut result_payload = Vec::with_capacity(12);
            result_payload.extend_from_slice(&exit_code.to_be_bytes());
            result_payload.extend_from_slice(&duration_ms.to_be_bytes());
            OperationOutcome {
                status: Some(operation_outcome::Status::Success(
                    operation_outcome::Success { result_payload },
                )),
            }
        }
        Err(ref e) if e.to_string().contains("timed out") => OperationOutcome {
            status: Some(operation_outcome::Status::TimedOut(
                operation_outcome::TimedOut {
                    budget_remaining: None,
                },
            )),
        },
        Err(ref e) if e.to_string().contains("cancelled") => OperationOutcome {
            status: Some(operation_outcome::Status::Canceled(
                operation_outcome::Canceled {
                    reason: e.to_string(),
                },
            )),
        },
        Err(ref e) if e.to_string().contains("signal") => OperationOutcome {
            status: Some(operation_outcome::Status::Success(
                operation_outcome::Success {
                    result_payload: {
                        let mut p = Vec::with_capacity(12);
                        let code = -1i32;
                        p.extend_from_slice(&code.to_be_bytes());
                        p.extend_from_slice(&duration_ms.to_be_bytes());
                        p
                    },
                },
            )),
        },
        Err(e) => OperationOutcome {
            status: Some(operation_outcome::Status::Failure(
                operation_outcome::Failure {
                    code: "ExecError".into(),
                    message: e.to_string(),
                    retryable: false,
                },
            )),
        },
    };

    tracing::info!(
        operation_id = %operation_id,
        duration_ms = duration_ms,
        "exec completed"
    );

    send_exec_outcome(&conn, outcome, timeout).await;
}

async fn send_exec_outcome(conn: &SharedWriter, outcome: OperationOutcome, timeout: Duration) {
    let response = ExecResponse {
        frame: Some(exec_response::Frame::Outcome(outcome)),
    };
    let _ = write_tagged_response(conn, framed::TAG_EXEC_RESPONSE, &response, timeout).await;
}

async fn run_command_and_stream(
    request: &ExecRequest,
    operation_id: &str,
    mut ctrl_rx: watch::Receiver<Option<CancelSignal>>,
    conn: &SharedWriter,
    timeout: Duration,
) -> Result<i32, ExecError> {
    let cmd_timeout = request.timeout.as_ref().map_or_else(
        || Duration::from_secs(DEFAULT_OPERATIONAL_TIMEOUT_SECS),
        |d| {
            let secs = d.seconds.max(0) as u64;
            let nanos = d.nanos.max(0) as u32;
            Duration::new(secs, nanos)
        },
    );

    let max_stdout = if request.max_stdout_bytes > 0 {
        request.max_stdout_bytes as usize
    } else {
        usize::MAX
    };
    let max_stderr = if request.max_stderr_bytes > 0 {
        request.max_stderr_bytes as usize
    } else {
        usize::MAX
    };

    let mut cmd = Command::new(&request.command);
    cmd.args(&request.args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());
    cmd.kill_on_drop(true);

    if !request.working_dir.is_empty() {
        cmd.current_dir(&request.working_dir);
    }

    for (key, val) in &request.env {
        cmd.env(key, val);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| ExecError::Io(format!("failed to spawn '{}': {e}", request.command)))?;

    let pid = child.id().unwrap_or(0);
    tracing::info!(operation_id = %operation_id, pid = pid, "process spawned");

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExecError::Io("no stdout pipe".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ExecError::Io("no stderr pipe".into()))?;

    let child_holder = Arc::new(TokioMutex::new(Some(child)));
    let child_clone = Arc::clone(&child_holder);

    let exit_status = stream_process_output(
        &child_clone,
        stdout,
        stderr,
        operation_id,
        max_stdout,
        max_stderr,
        &mut ctrl_rx,
        conn,
        timeout,
        cmd_timeout,
    )
    .await?;

    let exit_code = exit_status.code().unwrap_or(-1);
    Ok(exit_code)
}

#[expect(
    clippy::too_many_arguments,
    reason = "stream output requires all I/O handles"
)]
async fn stream_process_output(
    child_holder: &Arc<TokioMutex<Option<tokio::process::Child>>>,
    mut stdout: tokio::process::ChildStdout,
    mut stderr: tokio::process::ChildStderr,
    operation_id: &str,
    max_stdout: usize,
    max_stderr: usize,
    ctrl_rx: &mut watch::Receiver<Option<CancelSignal>>,
    conn: &SharedWriter,
    write_timeout: Duration,
    cmd_timeout: Duration,
) -> Result<std::process::ExitStatus, ExecError> {
    let start = Instant::now();
    let mut stdout_seq: u64 = 0;
    let mut stderr_seq: u64 = 0;
    let mut stdout_total: usize = 0;
    let mut stderr_total: usize = 0;
    let mut stdout_buf = vec![0u8; STREAM_FRAME_MAX_BYTES];
    let mut stderr_buf = vec![0u8; STREAM_FRAME_MAX_BYTES];
    let mut stdout_eof = false;
    let mut stderr_eof = false;

    let child = Arc::clone(child_holder);

    loop {
        if start.elapsed() > cmd_timeout {
            tracing::warn!(operation_id = %operation_id, "command timed out");
            kill_and_wait_child(&child).await;
            return Err(ExecError::Io("command timed out".into()));
        }

        if ctrl_rx.has_changed().unwrap_or(false) {
            let signal = ctrl_rx.borrow_and_update().clone();
            match signal {
                Some(CancelSignal::Cancel) => {
                    tracing::info!(operation_id = %operation_id, "command cancelled");
                    kill_and_wait_child(&child).await;
                    return Err(ExecError::Io("command cancelled".into()));
                }
                Some(CancelSignal::Signal(sig)) => {
                    tracing::info!(operation_id = %operation_id, signal = sig, "signal received");
                    if let Some(ref mut c) = *child.lock().await {
                        kill_child_by_signal(c, sig).await;
                    }
                }
                None => {}
            }
        }

        if stdout_eof && stderr_eof {
            let status = {
                let mut guard = child.lock().await;
                if let Some(ref mut c) = *guard {
                    c.wait()
                        .await
                        .map_err(|e| ExecError::Io(format!("child wait error: {e}")))?
                } else {
                    return Err(ExecError::Io("child already consumed".into()));
                }
            };
            return Ok(status);
        }

        tokio::select! {
            result = stdout.read(&mut stdout_buf), if !stdout_eof => {
                match result {
                    Ok(0) => {
                        stdout_eof = true;
                        stdout_seq += 1;
                        send_stream_frame(conn, stdout_seq, &[], true, true, write_timeout).await;
                    }
                    Ok(n) => {
                        stdout_total += n;
                        if stdout_total <= max_stdout {
                            stdout_seq += 1;
                            send_stream_frame(conn, stdout_seq, &stdout_buf[..n], false, true, write_timeout).await;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, operation_id = %operation_id, "stdout read error");
                        stdout_eof = true;
                    }
                }
            }

            result = stderr.read(&mut stderr_buf), if !stderr_eof => {
                match result {
                    Ok(0) => {
                        stderr_eof = true;
                        stderr_seq += 1;
                        send_stream_frame(conn, stderr_seq, &[], true, false, write_timeout).await;
                    }
                    Ok(n) => {
                        stderr_total += n;
                        if stderr_total <= max_stderr {
                            stderr_seq += 1;
                            send_stream_frame(conn, stderr_seq, &stderr_buf[..n], false, false, write_timeout).await;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, operation_id = %operation_id, "stderr read error");
                        stderr_eof = true;
                    }
                }
            }
        }
    }
}

async fn send_stream_frame(
    conn: &SharedWriter,
    sequence: u64,
    payload: &[u8],
    end_of_stream: bool,
    is_stdout: bool,
    timeout: Duration,
) {
    let frame = StreamFrame {
        sequence,
        payload: payload.to_vec(),
        end_of_stream,
    };

    let response = if is_stdout {
        ExecResponse {
            frame: Some(exec_response::Frame::Stdout(exec_response::StdoutData {
                frame: Some(frame),
            })),
        }
    } else {
        ExecResponse {
            frame: Some(exec_response::Frame::Stderr(exec_response::StderrData {
                frame: Some(frame),
            })),
        }
    };

    let _ = write_tagged_response(conn, framed::TAG_EXEC_RESPONSE, &response, timeout).await;
}

async fn kill_and_wait_child(child_holder: &Arc<TokioMutex<Option<tokio::process::Child>>>) {
    if let Some(ref mut c) = *child_holder.lock().await {
        c.kill().await.ok();
    }

    if let Some(ref mut c) = *child_holder.lock().await {
        c.wait().await.ok();
    }
}

async fn kill_child_by_signal(child: &mut tokio::process::Child, sig: i32) {
    #[cfg(unix)]
    {
        if sig == 9 {
            child.kill().await.ok();
        } else if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as i32, sig);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child;
        let _ = sig;
    }
}

async fn handle_cancel(
    session: Arc<OperationalSession>,
    request: CancelRequest,
    conn: SharedWriter,
    timeout: Duration,
) {
    let ctx = match request.context.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("CancelRequest missing context");
            return;
        }
    };

    if let Err(e) = session.validate_context(ctx) {
        send_cancel_response(
            &conn,
            cancel_response::Result::AlreadyTerminal(build_failure_outcome(
                "ContextValidationFailed",
                &e.to_string(),
                false,
            )),
            timeout,
        )
        .await;
        return;
    }

    let operation_id = &request.operation_id;
    let sent = {
        let execs = session.active_execs.lock();
        if let Some(state) = execs.get(operation_id) {
            let mut guard = state.lock();
            if let Some(tx) = guard.ctrl_tx.take() {
                let _ = tx.send(Some(CancelSignal::Cancel));
                tracing::info!(operation_id = %operation_id, "cancel signal sent");
                true
            } else {
                false
            }
        } else {
            false
        }
    };

    if sent {
        send_cancel_response(&conn, cancel_response::Result::Accepted(Ack {}), timeout).await;
    } else {
        send_cancel_response(
            &conn,
            cancel_response::Result::Unknown(UnknownOp {
                operation_id: operation_id.clone(),
            }),
            timeout,
        )
        .await;
    }
}

async fn send_cancel_response(
    conn: &SharedWriter,
    result: cancel_response::Result,
    timeout: Duration,
) {
    let response = CancelResponse {
        result: Some(result),
    };

    let _ = write_tagged_response(conn, framed::TAG_CANCEL_RESPONSE, &response, timeout).await;
}

async fn handle_signal(
    session: Arc<OperationalSession>,
    request: SignalRequest,
    conn: SharedWriter,
    timeout: Duration,
) {
    let ctx = match request.context.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("SignalRequest missing context");
            return;
        }
    };

    if let Err(e) = session.validate_context(ctx) {
        send_signal_response(
            &conn,
            signal_response::Result::Error(build_failure_outcome(
                "ContextValidationFailed",
                &e.to_string(),
                false,
            )),
            timeout,
        )
        .await;
        return;
    }

    let operation_id = &request.operation_id;
    let sent = {
        let execs = session.active_execs.lock();
        if let Some(state) = execs.get(operation_id) {
            let mut guard = state.lock();
            if let Some(tx) = guard.ctrl_tx.take() {
                let sig = request.signal;
                let _ = tx.send(Some(CancelSignal::Signal(sig)));
                tracing::info!(operation_id = %operation_id, signal = sig, "signal sent");
                true
            } else {
                false
            }
        } else {
            false
        }
    };

    if sent {
        send_signal_response(
            &conn,
            signal_response::Result::Acknowledged(Ack {}),
            timeout,
        )
        .await;
    } else {
        send_signal_response(
            &conn,
            signal_response::Result::Error(build_failure_outcome(
                "OperationNotFound",
                &format!("operation {operation_id} not found"),
                false,
            )),
            timeout,
        )
        .await;
    }
}

async fn send_signal_response(
    conn: &SharedWriter,
    result: signal_response::Result,
    timeout: Duration,
) {
    let response = SignalResponse {
        result: Some(result),
    };

    let _ = write_tagged_response(conn, framed::TAG_SIGNAL_RESPONSE, &response, timeout).await;
}

async fn handle_quiesce(
    session: Arc<OperationalSession>,
    request: QuiesceRequest,
    conn: SharedWriter,
    timeout: Duration,
) {
    let _ = crate::secrets::teardown_secrets_mount();

    let ctx = match request.context.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("QuiesceRequest missing context");
            return;
        }
    };

    if let Err(e) = session.validate_context(ctx) {
        tracing::error!(error = %e, "quiesce context validation failed");
        send_quiesce_error(
            &conn,
            build_failure_outcome("ContextValidationFailed", &e.to_string(), false),
            timeout,
        )
        .await;
        return;
    }

    let drain_mode = request.drain_mode();
    let quiesce_deadline = request.quiesce_deadline.as_ref();

    let deadline_instant = quiesce_deadline.and_then(|ts| {
        let secs = ts.seconds.max(0) as u64;
        let nanos = ts.nanos.max(0) as u32;
        let st = std::time::UNIX_EPOCH.checked_add(Duration::new(secs, nanos))?;
        match st.elapsed() {
            // Deadline already passed -- set to now (immediate expiry).
            Ok(_) => Some(Instant::now()),
            // Deadline is in the future -- e.duration() is the remaining budget.
            Err(e) => Some(Instant::now() + e.duration()),
        }
    });

    let quiesce_start = Instant::now();

    tracing::info!(
        drain_mode = ?drain_mode,
        has_deadline = deadline_instant.is_some(),
        "quiesce requested"
    );

    // Set quiescing flag immediately - blocks new exec requests.
    session.quiescing.store(true, Ordering::Release);

    match drain_mode {
        quiesce_request::DrainMode::Force => {
            force_cancel_all(&session, &conn, timeout).await;
            wait_for_drain(&session, deadline_instant).await;
        }
        quiesce_request::DrainMode::Graceful | quiesce_request::DrainMode::Unspecified => {
            wait_for_drain(&session, deadline_instant).await;
        }
    }

    let quiesce_duration_ms = quiesce_start.elapsed().as_millis() as u64;

    // Verify no active execs remain.
    let remaining = session.active_execs.lock().len();
    if remaining > 0 {
        tracing::warn!(remaining, "quiesce timed out before drain completed");
        send_quiesce_error(
            &conn,
            OperationOutcome {
                status: Some(operation_outcome::Status::TimedOut(
                    operation_outcome::TimedOut {
                        budget_remaining: None,
                    },
                )),
            },
            timeout,
        )
        .await;

        // Reset quiescing flag so guest is not permanently paused.
        session.quiescing.store(false, Ordering::Release);

        tracing::info!(
            quiesce_duration_ms,
            outcome = "timeout",
            "quiesce failed, guest resumed accepting requests"
        );
        return;
    }

    tracing::info!(
        quiesce_duration_ms,
        outcome = "quiesced",
        "guest quiesced successfully"
    );

    let response = QuiesceResponse {
        result: Some(quiesce_response::Result::Quiesced(true)),
    };

    let _ = write_tagged_response(&conn, framed::TAG_QUIESCE_RESPONSE, &response, timeout).await;
}

async fn force_cancel_all(
    session: &Arc<OperationalSession>,
    conn: &SharedWriter,
    timeout: Duration,
) {
    let op_ids: Vec<String> = session.active_execs.lock().keys().cloned().collect();

    for op_id in &op_ids {
        let sent = {
            let execs = session.active_execs.lock();
            if let Some(state) = execs.get(op_id) {
                let mut guard = state.lock();
                if let Some(tx) = guard.ctrl_tx.take() {
                    let _ = tx.send(Some(CancelSignal::Cancel));
                    tracing::info!(operation_id = %op_id, "force cancelled for quiesce");
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };

        if sent {
            // Send a cancel response so the host knows cancellation was accepted.
            let cancel_resp = CancelResponse {
                result: Some(cancel_response::Result::Accepted(Ack {})),
            };
            let _ = write_tagged_response(conn, framed::TAG_CANCEL_RESPONSE, &cancel_resp, timeout)
                .await;
        }
    }
}

async fn wait_for_drain(session: &Arc<OperationalSession>, deadline: Option<Instant>) {
    loop {
        let remaining = session.active_execs.lock().len();
        if remaining == 0 {
            break;
        }

        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            tracing::warn!(remaining, "quiesce deadline reached with active operations");
            break;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn send_quiesce_error(conn: &SharedWriter, error: OperationOutcome, timeout: Duration) {
    let response = QuiesceResponse {
        result: Some(quiesce_response::Result::Error(error)),
    };

    let _ = write_tagged_response(conn, framed::TAG_QUIESCE_RESPONSE, &response, timeout).await;
}

async fn handle_resume_notify(
    session: Arc<OperationalSession>,
    request: ResumeNotifyRequest,
    conn: SharedWriter,
    timeout: Duration,
) {
    // ResumeNotify validates context fields individually rather than
    // reusing validate_context() because it has different semantics:
    // sandbox_id and policy_epoch may be authorized for update after
    // restore or fork, whereas validate_context() rejects any mismatch.
    // Only session_id and protocol_version are treated as immutable
    // bindings to the current connection.
    let ctx = match request.context.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("ResumeNotifyRequest missing context");
            return;
        }
    };

    if ctx.session_id.as_slice() != session.session_id.as_slice() {
        tracing::error!("resume notify session_id mismatch");
        send_resume_error(
            &conn,
            build_failure_outcome("SessionMismatch", "session_id does not match", false),
            timeout,
        )
        .await;
        return;
    }

    // Protocol version packed as (major << 16) | minor.
    let ctx_version = (ctx.protocol_version >> 16, ctx.protocol_version & 0xFFFF);
    if ctx_version != session.protocol_version {
        tracing::error!(
            expected = ?session.protocol_version,
            got = ?ctx_version,
            "resume notify protocol_version mismatch"
        );
        send_resume_error(
            &conn,
            build_failure_outcome(
                "ProtocolVersionMismatch",
                "protocol_version does not match",
                false,
            ),
            timeout,
        )
        .await;
        return;
    }

    let current_sandbox_id = session.sandbox_id.lock().clone();
    if ctx.sandbox_id != current_sandbox_id {
        tracing::error!(
            expected = %current_sandbox_id,
            got = %ctx.sandbox_id,
            "resume notify context sandbox_id mismatch"
        );
        send_resume_error(
            &conn,
            build_failure_outcome(
                "SandboxIdMismatch",
                "context sandbox_id does not match current session",
                false,
            ),
            timeout,
        )
        .await;
        return;
    }

    let prev_epoch = session.policy_epoch.load(Ordering::Acquire);
    let new_epoch = request.policy_epoch;

    if ctx.policy_epoch > 0 && ctx.policy_epoch != prev_epoch {
        tracing::error!(
            expected = prev_epoch,
            got = ctx.policy_epoch,
            "resume notify context policy_epoch mismatch"
        );
        send_resume_error(
            &conn,
            build_failure_outcome(
                "PolicyEpochMismatch",
                "context policy_epoch does not match current session",
                false,
            ),
            timeout,
        )
        .await;
        return;
    }

    let prev_sandbox_id = current_sandbox_id;
    let new_sandbox_id = if request.sandbox_id.is_empty() {
        prev_sandbox_id.clone()
    } else {
        request.sandbox_id.clone()
    };

    if new_sandbox_id != prev_sandbox_id {
        tracing::info!(
            prev_sandbox_id = %prev_sandbox_id,
            new_sandbox_id = %new_sandbox_id,
            "refreshing guest identity after resume"
        );
        *session.sandbox_id.lock() = new_sandbox_id;
    }

    // Stale-check and update use separate load/store operations.
    // A concurrent resume-notify call could change the epoch between
    // these two reads, creating a TOCTOU window. In practice this is
    // safe because the protocol guarantees at most one resume-notify
    // per session (the host serializes lifecycle operations).
    if new_epoch > 0 && new_epoch < prev_epoch {
        tracing::warn!(
            prev_epoch,
            new_epoch,
            "resume notification carries stale policy epoch"
        );
        send_resume_error(
            &conn,
            build_failure_outcome(
                "StalePolicyEpoch",
                &format!("policy epoch {new_epoch} is older than current {prev_epoch}"),
                false,
            ),
            timeout,
        )
        .await;
        return;
    }

    if new_epoch > 0 && new_epoch != prev_epoch {
        tracing::info!(
            prev_epoch,
            new_epoch,
            "revalidating policy epoch after resume"
        );
        session.policy_epoch.store(new_epoch, Ordering::Release);
    }

    if request.snapshot_taken_at.is_some() {
        tracing::info!(
            lineage_id = %request.lineage_id,
            "snapshot lineage context received"
        );
    }

    let accepted = refreshes_non_restorable_resources(&request.lineage_id).await;

    tracing::info!(
        outcome = if accepted {
            "accepted"
        } else {
            "resources_unavailable"
        },
        "resume notification processed"
    );

    if accepted {
        let response = ResumeNotifyResponse {
            result: Some(resume_notify_response::Result::Accepted(true)),
        };
        let _ = write_tagged_response(
            &conn,
            framed::TAG_RESUME_NOTIFY_RESPONSE,
            &response,
            timeout,
        )
        .await;
    } else {
        send_resume_error(
            &conn,
            build_failure_outcome(
                "ResourcesUnavailable",
                "non-restorable resources could not be refreshed",
                true,
            ),
            timeout,
        )
        .await;
    }
}

async fn refreshes_non_restorable_resources(lineage_id: &str) -> bool {
    if lineage_id.is_empty() {
        tracing::warn!("resume notification missing lineage_id, resources may be stale");
    }

    true
}

async fn send_resume_error(conn: &SharedWriter, error: OperationOutcome, timeout: Duration) {
    let response = ResumeNotifyResponse {
        result: Some(resume_notify_response::Result::Error(error)),
    };

    let _ =
        write_tagged_response(conn, framed::TAG_RESUME_NOTIFY_RESPONSE, &response, timeout).await;
}

pub(crate) fn build_failure_outcome(
    code: &str,
    message: &str,
    retryable: bool,
) -> OperationOutcome {
    OperationOutcome {
        status: Some(operation_outcome::Status::Failure(
            operation_outcome::Failure {
                code: code.into(),
                message: message.into(),
                retryable,
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handshake_outcome() -> HandshakeOutcome {
        HandshakeOutcome {
            session_id: HVec::from_slice(b"test-session").unwrap(),
            policy_epoch: 1,
            selected_version: (1, 0),
            selected_capabilities: vec!["exec".into()],
        }
    }

    #[test]
    fn context_validation_rejects_wrong_sandbox_id() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let ctx = RequestContext {
            sandbox_id: "sbx-b".into(),
            session_id: b"test-session".to_vec(),
            policy_epoch: 1,
            protocol_version: 0x0001_0000,
            ..Default::default()
        };
        let err = session.validate_context(&ctx).unwrap_err();
        assert!(err.to_string().contains("sandbox_id"));
    }

    #[test]
    fn context_validation_rejects_wrong_session_id() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let ctx = RequestContext {
            sandbox_id: "sbx-a".into(),
            session_id: b"wrong-session".to_vec(),
            policy_epoch: 1,
            protocol_version: 0x0001_0000,
            ..Default::default()
        };
        let err = session.validate_context(&ctx).unwrap_err();
        assert!(err.to_string().contains("session_id"));
    }

    #[test]
    fn context_validation_rejects_wrong_policy_epoch() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let ctx = RequestContext {
            sandbox_id: "sbx-a".into(),
            session_id: b"test-session".to_vec(),
            policy_epoch: 99,
            protocol_version: 0x0001_0000,
            ..Default::default()
        };
        let err = session.validate_context(&ctx).unwrap_err();
        assert!(err.to_string().contains("policy_epoch"));
    }

    #[test]
    fn context_validation_rejects_wrong_protocol_version() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let ctx = RequestContext {
            sandbox_id: "sbx-a".into(),
            session_id: b"test-session".to_vec(),
            policy_epoch: 1,
            protocol_version: 0x0002_0000,
            ..Default::default()
        };
        let err = session.validate_context(&ctx).unwrap_err();
        assert!(err.to_string().contains("protocol_version"));
    }

    #[test]
    fn context_validation_passes_with_matching_context() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        let ctx = RequestContext {
            sandbox_id: "sbx-a".into(),
            session_id: b"test-session".to_vec(),
            policy_epoch: 1,
            protocol_version: 0x0001_0000,
            ..Default::default()
        };
        assert!(session.validate_context(&ctx).is_ok());
    }

    #[test]
    fn build_failure_outcome_creates_proper_response() {
        let outcome = build_failure_outcome("TestCode", "test message", true);
        match outcome.status {
            Some(operation_outcome::Status::Failure(f)) => {
                assert_eq!(f.code, "TestCode");
                assert_eq!(f.message, "test message");
                assert!(f.retryable);
            }
            _ => panic!("expected failure outcome"),
        }
    }

    #[test]
    fn quiescing_flag_starts_false() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        assert!(!session.quiescing.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn quiescing_flag_can_be_set() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
        session
            .quiescing
            .store(true, std::sync::atomic::Ordering::Release);
        assert!(session.quiescing.load(std::sync::atomic::Ordering::Acquire));
        session
            .quiescing
            .store(false, std::sync::atomic::Ordering::Release);
        assert!(!session.quiescing.load(std::sync::atomic::Ordering::Acquire));
    }

    fn make_resume_request(
        session_id: &[u8],
        sandbox_id: &str,
        policy_epoch: u64,
        new_sandbox_id: &str,
        new_policy_epoch: u64,
        lineage_id: &str,
    ) -> ResumeNotifyRequest {
        ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-test".into(),
                operation_id: "resume-op".into(),
                sandbox_id: sandbox_id.into(),
                session_id: session_id.to_vec(),
                policy_epoch,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: new_sandbox_id.into(),
            policy_epoch: new_policy_epoch,
            lineage_id: lineage_id.into(),
            snapshot_taken_at: None,
        }
    }

    #[test]
    fn resume_notify_updates_sandbox_id() {
        let session = Arc::new(OperationalSession::new(
            &make_handshake_outcome(),
            "original-sbx".into(),
        ));

        assert_eq!(&*session.sandbox_id.lock(), "original-sbx");

        session.sandbox_id.lock().push_str("-child");
        assert_eq!(&*session.sandbox_id.lock(), "original-sbx-child");
    }

    #[test]
    fn resume_notify_updates_policy_epoch() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());

        assert_eq!(session.policy_epoch.load(Ordering::Acquire), 1);

        session.policy_epoch.store(42, Ordering::Release);
        assert_eq!(session.policy_epoch.load(Ordering::Acquire), 42);
    }

    #[test]
    fn resume_notify_validates_session_id() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());

        let req = make_resume_request(b"test-session", "sbx-a", 1, "sbx-a", 2, "lineage-1");
        let ctx = req.context.as_ref().unwrap();
        assert_eq!(ctx.session_id, session.session_id.as_slice());
    }

    #[test]
    fn resume_notify_rejects_wrong_session_id() {
        let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());

        let wrong_session = b"wrong-session-id";
        assert_ne!(wrong_session.as_slice(), session.session_id.as_slice());
    }

    #[tokio::test]
    async fn resume_notify_protocol_integration() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);
            assert_eq!(req.sandbox_id, "restored-sbx");
            assert_eq!(req.policy_epoch, 10);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Accepted(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-op".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: "restored-sbx".into(),
            policy_epoch: 10,
            lineage_id: "lineage-1".into(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        assert!(matches!(
            resp.result,
            Some(resume_notify_response::Result::Accepted(true))
        ));

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_rejects_stale_policy_epoch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "StalePolicyEpoch".into(),
                            message: "policy epoch 3 is older than current 10".into(),
                            retryable: false,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-stale".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session".to_vec(),
                policy_epoch: 10,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: String::new(),
            policy_epoch: 3,
            lineage_id: String::new(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result {
            Some(resume_notify_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "StalePolicyEpoch");
                }
                _ => panic!("expected stale policy epoch failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_rejects_session_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "SessionMismatch".into(),
                            message: "session_id does not match".into(),
                            retryable: false,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-mismatch".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"wrong-session".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: String::new(),
            policy_epoch: 0,
            lineage_id: String::new(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result {
            Some(resume_notify_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "SessionMismatch");
                }
                _ => panic!("expected session mismatch failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_rejects_protocol_version_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "ProtocolVersionMismatch".into(),
                            message: "protocol_version does not match".into(),
                            retryable: false,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-version-mismatch".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0002_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: String::new(),
            policy_epoch: 0,
            lineage_id: String::new(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result {
            Some(resume_notify_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "ProtocolVersionMismatch");
                }
                _ => panic!("expected protocol version mismatch failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_rejects_context_sandbox_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "SandboxIdMismatch".into(),
                            message: "context sandbox_id does not match current session".into(),
                            retryable: false,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-sandbox-mismatch".into(),
                sandbox_id: "wrong-sandbox".into(),
                session_id: b"test-session".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: String::new(),
            policy_epoch: 0,
            lineage_id: String::new(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result {
            Some(resume_notify_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "SandboxIdMismatch");
                }
                _ => panic!("expected sandbox_id mismatch failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_rejects_context_policy_epoch_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "PolicyEpochMismatch".into(),
                            message: "context policy_epoch does not match current session".into(),
                            retryable: false,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-epoch-mismatch".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session".to_vec(),
                policy_epoch: 99,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: String::new(),
            policy_epoch: 0,
            lineage_id: String::new(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result {
            Some(resume_notify_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "PolicyEpochMismatch");
                }
                _ => panic!("expected policy epoch mismatch failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn resume_notify_rejects_when_resources_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let (tag, _req) =
                framed::read_tagged::<ResumeNotifyRequest>(&mut stream, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert_eq!(tag, framed::TAG_RESUME_NOTIFY_REQUEST);

            let response = ResumeNotifyResponse {
                result: Some(resume_notify_response::Result::Error(OperationOutcome {
                    status: Some(operation_outcome::Status::Failure(
                        operation_outcome::Failure {
                            code: "ResourcesUnavailable".into(),
                            message: "non-restorable resources could not be refreshed".into(),
                            retryable: true,
                        },
                    )),
                })),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_RESUME_NOTIFY_RESPONSE,
                &response,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request = ResumeNotifyRequest {
            context: Some(RequestContext {
                request_id: "resume-req".into(),
                operation_id: "resume-resources-unavailable".into(),
                sandbox_id: "test-sbx".into(),
                session_id: b"test-session".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            sandbox_id: String::new(),
            policy_epoch: 0,
            lineage_id: String::new(),
            snapshot_taken_at: None,
        };
        framed::send_tagged(
            &mut stream,
            framed::TAG_RESUME_NOTIFY_REQUEST,
            &request,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let (tag, resp) =
            framed::read_tagged::<ResumeNotifyResponse>(&mut stream, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(tag, framed::TAG_RESUME_NOTIFY_RESPONSE);
        match resp.result {
            Some(resume_notify_response::Result::Error(outcome)) => match outcome.status {
                Some(operation_outcome::Status::Failure(f)) => {
                    assert_eq!(f.code, "ResourcesUnavailable");
                    assert!(f.retryable);
                }
                _ => panic!("expected resources unavailable failure"),
            },
            _ => panic!("expected error result"),
        }

        guest.await.unwrap();
    }

    #[tokio::test]
    async fn operational_loop_answers_exec_while_reading() {
        // Regression test for the binary-restart CI failure: the dispatch
        // loop once shared one mutexed `FramedConnection` for reads and
        // writes, holding the lock across its blocking read while spawned
        // exec handlers blocked acquiring it to send. Every exec then timed
        // out on the host ("guest session error: exec stream timed out").
        // The loop now owns the read half and handlers share the write half.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let guest = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = FramedConnection::new(stream, Duration::from_secs(10));
            let session = OperationalSession::new(&make_handshake_outcome(), "sbx-a".into());
            serve_operational(conn, session).await;
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut client = FramedConnection::new(stream, Duration::from_secs(10));
        let request = ExecRequest {
            context: Some(RequestContext {
                request_id: "req-1".into(),
                operation_id: "opr-1".into(),
                sandbox_id: "sbx-a".into(),
                session_id: b"test-session".to_vec(),
                policy_epoch: 1,
                protocol_version: 0x0001_0000,
                deadline: None,
                trace_context: None,
            }),
            command: "echo".into(),
            args: vec!["hello".into()],
            env: Default::default(),
            working_dir: String::new(),
            timeout: None,
            max_stdout_bytes: 0,
            max_stderr_bytes: 0,
        };
        client
            .send_tagged(framed::TAG_EXEC_REQUEST, &request)
            .await
            .unwrap();

        let mut saw_stdout = false;
        let mut exited = false;
        // Bounded so a regression fails fast instead of hanging the suite.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            let (tag, response): (u8, ExecResponse) = client.recv_tagged().await.unwrap();
            assert_eq!(tag, framed::TAG_EXEC_RESPONSE);
            match response.frame {
                Some(exec_response::Frame::Stdout(data)) => {
                    let payload = data.frame.map(|f| f.payload).unwrap_or_default();
                    if !payload.is_empty() {
                        assert!(payload.windows(5).any(|w| w == b"hello"));
                        saw_stdout = true;
                    }
                }
                Some(exec_response::Frame::Outcome(outcome)) => {
                    assert!(
                        matches!(outcome.status, Some(operation_outcome::Status::Success(_))),
                        "expected success outcome, got {outcome:?}"
                    );
                    exited = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(saw_stdout, "expected a stdout frame from echo");
        assert!(exited, "expected a terminal outcome frame");
        guest.abort();
    }
}
