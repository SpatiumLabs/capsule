//! HTTP-facing error mapping from domain failures into API responses.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use capsule_core::SandboxError;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
    #[error("malformed request: {0}")]
    BadRequest(String),
    #[error("missing or invalid Authorization header")]
    Unauthorized,
}

impl AppError {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            AppError::Sandbox(s) => match s {
                SandboxError::SandboxNotFound(_)
                | SandboxError::TaskNotFound(_)
                | SandboxError::WorkspaceNotFound(_) => (StatusCode::NOT_FOUND, "NotFound"),
                SandboxError::BadRequest(_) | SandboxError::PathEscape(_) => {
                    (StatusCode::BAD_REQUEST, "BadRequest")
                }
                SandboxError::Conflict(_)
                | SandboxError::InvalidStateTransition(_)
                | SandboxError::VersionConflict(_)
                | SandboxError::OperationStale(_) => (StatusCode::CONFLICT, "Conflict"),
                SandboxError::PortInUse(_) => (StatusCode::CONFLICT, "PortInUse"),
                SandboxError::Unprocessable(_) => {
                    (StatusCode::UNPROCESSABLE_ENTITY, "Unprocessable")
                }
                SandboxError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
                SandboxError::NotImplemented(_) => (StatusCode::NOT_IMPLEMENTED, "NotImplemented"),
                SandboxError::NotReady(_) => {
                    (StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable")
                }
                SandboxError::Io(_)
                | SandboxError::Other(_)
                | SandboxError::CgroupSetupFailed { .. }
                | SandboxError::CgroupCleanupFailed { .. } => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal")
                }
                SandboxError::QuotaExceeded { .. } => {
                    (StatusCode::TOO_MANY_REQUESTS, "QuotaExceeded")
                }
                SandboxError::PolicyDenied { .. } => (StatusCode::FORBIDDEN, "PolicyDenied"),
                SandboxError::BackendSelectionRejected { .. } => {
                    (StatusCode::UNPROCESSABLE_ENTITY, "BackendSelectionRejected")
                }
            },
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "BadRequest"),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        let message = self.to_string();
        if status.is_server_error() {
            tracing::error!(error = %message, "server error");
        }
        (
            status,
            Json(json!({"error": code, "message": message, "status": status.as_u16()})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_maps_to_404() {
        let e: AppError = SandboxError::SandboxNotFound("x".into()).into();
        assert_eq!(e.parts().0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn bad_request_maps_to_400() {
        let e: AppError = SandboxError::BadRequest("nope".into()).into();
        assert_eq!(e.parts().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn port_in_use_maps_to_409_with_specific_code() {
        let e: AppError = SandboxError::PortInUse(3000).into();
        assert_eq!(e.parts(), (StatusCode::CONFLICT, "PortInUse"));
    }

    #[test]
    fn not_implemented_maps_to_501() {
        let e: AppError = SandboxError::NotImplemented("file_read").into();
        assert_eq!(e.parts().0, StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn io_maps_to_500() {
        let io = std::io::Error::other("boom");
        let e: AppError = SandboxError::Io(io).into();
        assert_eq!(e.parts().0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn quota_exceeded_maps_to_429() {
        let e: AppError = SandboxError::QuotaExceeded {
            resource: "vcpus".into(),
            limit: 32,
            current: 32,
        }
        .into();
        assert_eq!(e.parts().0, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn policy_denied_maps_to_403() {
        let e: AppError = SandboxError::PolicyDenied {
            reason: "untrusted".into(),
        }
        .into();
        assert_eq!(e.parts().0, StatusCode::FORBIDDEN);
    }
}
