//! Map sandboxd operation outcomes and error classes to tonic status codes.
//!
//! This module is intentionally free of a dependency on `capsule-sandboxd` so
//! host-agent and sandboxd can share the same mapping without a crate cycle.
//! Wire `status`/`reason_code` strings match the proto `Outcome` fields.

use tonic::{Code, Status};

/// gRPC metadata key for the shared host-agent <-> sandboxd token.
pub const METADATA_TOKEN_KEY: &str = "x-capsule-sandboxd-token";

/// Wire values for [`crate::v1::Outcome::status`].
pub mod outcome_status {
    pub const RUNNING: &str = "running";
    pub const SUCCEEDED: &str = "succeeded";
    pub const FAILED: &str = "failed";
    pub const CANCELED: &str = "canceled";
    pub const TIMED_OUT: &str = "timed_out";
    pub const REQUIRES_REVIEW: &str = "requires_review";
}

/// Wire values for [`crate::v1::Outcome::kind`].
pub mod operation_kind {
    pub const PREPARE: &str = "prepare";
    pub const BOOT: &str = "boot";
    pub const EXEC: &str = "exec";
    pub const SUSPEND: &str = "suspend";
    pub const RESUME: &str = "resume";
    pub const DESTROY: &str = "destroy";
    pub const PROCESS: &str = "process";
}

/// Wire values for [`crate::v1::Outcome::reason_code`].
///
/// Names match `OutcomeReason` serde `snake_case` in `capsule-sandboxd`.
pub mod outcome_reason {
    pub const IN_PROGRESS: &str = "in_progress";
    pub const COMPLETED: &str = "completed";
    pub const BACKEND_FAILURE: &str = "backend_failure";
    pub const CANCELED_BY_HOST: &str = "canceled_by_host";
    pub const DEADLINE_EXCEEDED: &str = "deadline_exceeded";
    pub const PARTIAL_CLEANUP: &str = "partial_cleanup";
    pub const SUPERVISOR_RESTARTED: &str = "supervisor_restarted";
    pub const PROCESS_EXITED: &str = "process_exited";
    pub const PROCESS_SIGNALED: &str = "process_signaled";
    pub const PROCESS_FAILURE: &str = "process_failure";

    /// Every known wire reason code (for exhaustiveness tests).
    pub const ALL: &[&str] = &[
        IN_PROGRESS,
        COMPLETED,
        BACKEND_FAILURE,
        CANCELED_BY_HOST,
        DEADLINE_EXCEEDED,
        PARTIAL_CLEANUP,
        SUPERVISOR_RESTARTED,
        PROCESS_EXITED,
        PROCESS_SIGNALED,
        PROCESS_FAILURE,
    ];
}

/// Stable error class for mapping host/sandboxd failures to gRPC codes.
///
/// Mirrors `SupervisorError` variants without importing that type, and extends
/// them with RPC-layer classes (`Unauthenticated`, `PermissionDenied`,
/// `NotFound`, `Internal`) that have no ledger equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorErrorClass {
    /// Ledger/SQL failure.
    Ledger,
    /// Local I/O failure.
    Io,
    /// Corrupt ledger payload.
    InvalidLedgerValue,
    /// Assignment fencing token is stale.
    StaleFencingToken,
    /// Operation already active.
    OperationInProgress,
    /// Operation id reused with different identity.
    OperationIdentityConflict,
    /// Policy epoch is stale.
    StalePolicyEpoch,
    /// No runtime handle attached.
    RuntimeNotAttached,
    /// Command sandbox id does not match config.
    SandboxMismatch,
    /// Invalid process request.
    InvalidProcessRequest,
    /// Auth token or peer credentials rejected.
    Unauthenticated,
    /// Caller not permitted for this socket/sandbox.
    PermissionDenied,
    /// Sandbox not found in ledger.
    NotFound,
    /// Catch-all internal failure.
    Internal,
}

impl SupervisorErrorClass {
    /// Returns the tonic code used when this class is raised as an RPC error
    /// (as opposed to a successful RPC carrying a failed [`Outcome`]).
    #[must_use]
    pub fn tonic_code(self) -> Code {
        match self {
            Self::Ledger | Self::Io | Self::InvalidLedgerValue | Self::Internal => Code::Internal,
            Self::StaleFencingToken | Self::StalePolicyEpoch | Self::OperationIdentityConflict => {
                Code::FailedPrecondition
            }
            Self::OperationInProgress => Code::AlreadyExists,
            Self::RuntimeNotAttached | Self::NotFound => Code::NotFound,
            Self::SandboxMismatch | Self::InvalidProcessRequest => Code::InvalidArgument,
            Self::Unauthenticated => Code::Unauthenticated,
            Self::PermissionDenied => Code::PermissionDenied,
        }
    }

    /// Builds a tonic [`Status`] with a redacted message.
    #[must_use]
    pub fn status(self, message: impl Into<String>) -> Status {
        Status::new(self.tonic_code(), message)
    }
}

/// Map a terminal or active outcome `status` wire string to a tonic code when
/// the server chooses to surface the outcome as a gRPC error.
///
/// Successful RPCs normally return `Outcome` in the response body even when
/// `status == failed`. Use this when a call cannot produce a body (auth, parse)
/// or when a streaming call aborts before `ExecFailed`.
#[must_use]
pub fn outcome_status_to_code(status: &str) -> Code {
    match status {
        outcome_status::SUCCEEDED | outcome_status::RUNNING => Code::Ok,
        outcome_status::CANCELED => Code::Cancelled,
        outcome_status::TIMED_OUT => Code::DeadlineExceeded,
        outcome_status::REQUIRES_REVIEW => Code::FailedPrecondition,
        outcome_status::FAILED => Code::Internal,
        _ => Code::Unknown,
    }
}

/// Map a wire `reason_code` to a tonic code for finer failure classification.
#[must_use]
pub fn outcome_reason_to_code(reason_code: &str) -> Code {
    match reason_code {
        outcome_reason::COMPLETED
        | outcome_reason::IN_PROGRESS
        | outcome_reason::PROCESS_EXITED => Code::Ok,
        outcome_reason::CANCELED_BY_HOST => Code::Cancelled,
        outcome_reason::DEADLINE_EXCEEDED => Code::DeadlineExceeded,
        outcome_reason::PARTIAL_CLEANUP
        | outcome_reason::SUPERVISOR_RESTARTED
        | outcome_reason::BACKEND_FAILURE => Code::FailedPrecondition,
        outcome_reason::PROCESS_SIGNALED | outcome_reason::PROCESS_FAILURE => Code::Internal,
        _ => Code::Unknown,
    }
}

/// Prefer reason-specific codes when present; fall back to outcome status.
#[must_use]
pub fn outcome_to_code(status: &str, reason_code: &str) -> Code {
    let from_reason = outcome_reason_to_code(reason_code);
    if from_reason != Code::Unknown && from_reason != Code::Ok {
        return from_reason;
    }
    if status == outcome_status::SUCCEEDED || status == outcome_status::RUNNING {
        return Code::Ok;
    }
    let from_status = outcome_status_to_code(status);
    if from_status != Code::Unknown {
        return from_status;
    }
    from_reason
}

/// Build a status from outcome wire fields (for stream abort/no-body paths).
#[must_use]
pub fn status_from_outcome_fields(
    status: &str,
    reason_code: &str,
    message: Option<&str>,
) -> Status {
    let code = outcome_to_code(status, reason_code);
    let msg = message.unwrap_or(status).to_string();
    Status::new(code, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_fencing_is_failed_precondition() {
        assert_eq!(
            SupervisorErrorClass::StaleFencingToken.tonic_code(),
            Code::FailedPrecondition
        );
    }

    #[test]
    fn operation_in_progress_is_already_exists() {
        assert_eq!(
            SupervisorErrorClass::OperationInProgress.tonic_code(),
            Code::AlreadyExists
        );
    }

    #[test]
    fn timed_out_outcome_maps_to_deadline_exceeded() {
        assert_eq!(
            outcome_to_code(outcome_status::TIMED_OUT, outcome_reason::DEADLINE_EXCEEDED),
            Code::DeadlineExceeded
        );
    }

    #[test]
    fn canceled_outcome_maps_to_cancelled() {
        assert_eq!(
            outcome_to_code(outcome_status::CANCELED, outcome_reason::CANCELED_BY_HOST),
            Code::Cancelled
        );
    }

    #[test]
    fn succeeded_is_ok() {
        assert_eq!(
            outcome_to_code(outcome_status::SUCCEEDED, outcome_reason::COMPLETED),
            Code::Ok
        );
    }

    #[test]
    fn metadata_token_key_matches_adr() {
        assert_eq!(METADATA_TOKEN_KEY, "x-capsule-sandboxd-token");
    }

    #[test]
    fn process_failure_reasons_map_to_internal() {
        assert_eq!(
            outcome_reason_to_code(outcome_reason::PROCESS_SIGNALED),
            Code::Internal
        );
        assert_eq!(
            outcome_reason_to_code(outcome_reason::PROCESS_FAILURE),
            Code::Internal
        );
    }

    #[test]
    fn outcome_reason_all_is_exhaustive_and_mapped() {
        assert_eq!(outcome_reason::ALL.len(), 10);
        for reason in outcome_reason::ALL {
            assert_ne!(
                outcome_reason_to_code(reason),
                Code::Unknown,
                "unmapped reason_code {reason}"
            );
        }
    }
}
