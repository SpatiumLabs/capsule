//! Host-side secrets broker coordination.
//!
//! The [`SecretsCoordinator`] validates access leases, calls the secrets
//! broker, sends credentials to the guest agent via the operational
//! protocol, and emits audit events for every credential operation.

use std::sync::Arc;

use capsule_core::event_bus::{AuditEventBuilder, AuditEventSink};
use capsule_core::leases::{LeaseAction, LeaseManager, LeaseScope, LeaseValidationError};
use capsule_core::secrets::{
    CredentialBundle, CredentialRequest, SecretsBroker, SecretsBrokerError,
};
use capsule_core::{
    AuditEventDetails, AuditEventKind, AuditOutcome, AuditProducer, Hlc, LeaseId, PolicyDecisionId,
    SandboxId, TenantId,
};

use crate::client::GuestConnection;
use crate::metrics;

/// Errors that can occur during secrets coordination.
#[derive(Debug, thiserror::Error)]
pub enum SecretsCoordinationError {
    /// Lease validation failed.
    #[error("lease validation failed: {0}")]
    LeaseValidation(LeaseValidationError),
    /// Secrets broker returned an error.
    #[error("broker error: {0}")]
    Broker(#[from] SecretsBrokerError),
    /// Guest injection RPC failed.
    #[error("guest injection failed: {0}")]
    GuestInjection(String),
    /// Lease revocation failed.
    #[error("lease revocation failed: {0}")]
    Revocation(String),
    /// Audit event emission failed.
    #[error("audit error: {0}")]
    Audit(String),
}

impl From<LeaseValidationError> for SecretsCoordinationError {
    fn from(err: LeaseValidationError) -> Self {
        Self::LeaseValidation(err)
    }
}

impl From<SecretsCoordinationError> for capsule_core::SandboxError {
    fn from(err: SecretsCoordinationError) -> Self {
        capsule_core::SandboxError::Other(format!("secrets coordination failed: {err}"))
    }
}

/// Coordinates the full credential lifecycle: validate, fetch, inject, audit.
pub struct SecretsCoordinator {
    broker: Arc<dyn SecretsBroker>,
    lease_manager: Arc<LeaseManager>,
    audit_sink: Arc<dyn AuditEventSink>,
    hlc: Arc<Hlc>,
}

impl SecretsCoordinator {
    /// Create a new coordinator.
    pub fn new(
        broker: Arc<dyn SecretsBroker>,
        lease_manager: Arc<LeaseManager>,
        audit_sink: Arc<dyn AuditEventSink>,
        hlc: Arc<Hlc>,
    ) -> Self {
        Self {
            broker,
            lease_manager,
            audit_sink,
            hlc,
        }
    }

    /// Validate the access lease, fetch credentials from the broker, and
    /// inject them into the guest via an operational protocol RPC.
    ///
    /// Emits a `CredentialIssuance` audit event on success and a
    /// `CredentialDenied` event on denial or failure.
    #[expect(
        clippy::too_many_arguments,
        reason = "each parameter is independently required for lease validation and RPC context"
    )]
    pub async fn inject(
        &self,
        tenant_id: &TenantId,
        sandbox_id: &SandboxId,
        operation_id: &str,
        lease_id: &LeaseId,
        policy_decision_id: Option<&PolicyDecisionId>,
        credential_types: &[String],
        guest_conn: &mut GuestConnection,
    ) -> Result<CredentialBundle, SecretsCoordinationError> {
        let requested_scope = LeaseScope {
            ports: vec![],
            paths: vec![],
            egress_cidrs: vec![],
            credential_types: credential_types.to_vec(),
        };

        let _lease = self
            .lease_manager
            .validate_with_scope(
                lease_id,
                sandbox_id,
                tenant_id,
                LeaseAction::CredentialAccess,
                &requested_scope,
                guest_conn.policy_epoch(),
            )
            .map_err(|e| {
                self.emit_credential_issuance(
                    tenant_id,
                    sandbox_id,
                    Some(lease_id.as_str()),
                    policy_decision_id.map(|id| id.as_str()),
                    AuditOutcome::Denied,
                    Some(e.to_string()),
                    credential_types,
                );
                metrics::record_credential_denied(1);
                SecretsCoordinationError::LeaseValidation(e)
            })?;

        let request = CredentialRequest {
            tenant_id: tenant_id.clone(),
            sandbox_id: sandbox_id.clone(),
            operation_id: operation_id.into(),
            policy_decision_id: policy_decision_id.cloned(),
            lease_id: Some(lease_id.clone()),
            credential_types: credential_types.to_vec(),
        };

        let bundle = self
            .broker
            .fetch_credentials(&request)
            .await
            .inspect_err(|e| {
                self.emit_credential_issuance(
                    tenant_id,
                    sandbox_id,
                    Some(lease_id.as_str()),
                    policy_decision_id.map(|id| id.as_str()),
                    AuditOutcome::Denied,
                    Some(e.to_string()),
                    credential_types,
                );
                metrics::record_credential_denied(1);
            })?;

        let credentials: Vec<capsule_guest_protocol::operational_v1::SecretCredential> = bundle
            .credentials
            .iter()
            .map(
                |c| capsule_guest_protocol::operational_v1::SecretCredential {
                    name: c.name.clone(),
                    content: c.value.clone(),
                    mode: 0o400,
                },
            )
            .collect();

        guest_conn
            .inject_secrets(
                lease_id.as_str(),
                policy_decision_id.map(|id| id.as_str()).unwrap_or(""),
                &credentials,
                operation_id,
            )
            .await
            .map_err(|e| SecretsCoordinationError::GuestInjection(e.to_string()))?;

        self.emit_credential_issuance(
            tenant_id,
            sandbox_id,
            Some(lease_id.as_str()),
            policy_decision_id.map(|id| id.as_str()),
            AuditOutcome::Success,
            None,
            credential_types,
        );

        metrics::record_credential_issued(1);

        Ok(bundle)
    }

    /// Refresh credentials after a sandbox resume.
    ///
    /// Delegates to [`inject`] and emits an additional audit event with a
    /// "refreshed on resume" reason.
    #[expect(
        clippy::too_many_arguments,
        reason = "delegates to inject which requires the same parameter set"
    )]
    pub async fn refresh(
        &self,
        tenant_id: &TenantId,
        sandbox_id: &SandboxId,
        operation_id: &str,
        lease_id: &LeaseId,
        policy_decision_id: Option<&PolicyDecisionId>,
        credential_types: &[String],
        guest_conn: &mut GuestConnection,
    ) -> Result<CredentialBundle, SecretsCoordinationError> {
        let bundle = self
            .inject(
                tenant_id,
                sandbox_id,
                operation_id,
                lease_id,
                policy_decision_id,
                credential_types,
                guest_conn,
            )
            .await?;

        self.emit_credential_issuance(
            tenant_id,
            sandbox_id,
            Some(lease_id.as_str()),
            policy_decision_id.map(|id| id.as_str()),
            AuditOutcome::Success,
            Some("refreshed on resume".into()),
            credential_types,
        );

        metrics::record_credential_refreshed(1);

        Ok(bundle)
    }

    /// Revoke the credential access lease and emit a revocation audit event.
    pub async fn revoke(
        &self,
        tenant_id: &TenantId,
        sandbox_id: &SandboxId,
        lease_id: Option<&LeaseId>,
        reason: capsule_core::leases::RevocationReason,
    ) -> Result<(), SecretsCoordinationError> {
        if let Some(id) = lease_id {
            self.lease_manager
                .revoke(id, reason)
                .map_err(|e| SecretsCoordinationError::Revocation(e.to_string()))?;
        }

        self.emit_credential_issuance(
            tenant_id,
            sandbox_id,
            lease_id.map(|id| id.as_str()),
            None,
            AuditOutcome::Revoked,
            Some(format!("{reason:?}")),
            &[],
        );

        metrics::record_credential_revoked(1);

        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "all fields are independently required by the audit event schema"
    )]
    fn emit_credential_issuance(
        &self,
        tenant_id: &TenantId,
        sandbox_id: &SandboxId,
        lease_id: Option<&str>,
        policy_decision_id: Option<&str>,
        outcome: AuditOutcome,
        reason: Option<String>,
        credential_types: &[String],
    ) {
        let kind = match outcome {
            AuditOutcome::Revoked => AuditEventKind::CredentialRevoked,
            AuditOutcome::Deny | AuditOutcome::Denied => AuditEventKind::CredentialDenied,
            _ => AuditEventKind::CredentialIssuance,
        };
        let _ = self.audit_sink.emit(
            AuditEventBuilder::new(self.hlc.clone(), kind)
                .sandbox_id(sandbox_id.clone())
                .tenant_id(tenant_id.clone())
                .lease_id(lease_id.unwrap_or(""))
                .policy_decision_id(policy_decision_id.unwrap_or(""))
                .outcome(outcome)
                .producer(AuditProducer::HostAgent)
                .details(AuditEventDetails::CredentialIssuance {
                    action: "credential_access".into(),
                    outcome: outcome.to_string(),
                    reason,
                    credential_type: credential_types.join(","),
                    lease_id: lease_id.map(|s| s.to_string()),
                })
                .build(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use capsule_core::event_bus::InMemoryAuditSink;
    use capsule_core::leases::LeaseScope;
    use capsule_core::leases::RevocationReason;
    use capsule_core::policy::{PolicyAction, PolicyEngine};
    use capsule_core::secrets::mock::MockSecretsBroker;
    use capsule_core::{PrincipalId, SandboxId, TenantId};

    const DEFAULT_LEASE_TTL_SECS: u64 = 3600;

    fn test_hlc() -> Arc<Hlc> {
        Arc::new(Hlc::new())
    }

    fn test_coordinator(
        broker: Arc<MockSecretsBroker>,
        lease_mgr: Arc<LeaseManager>,
        sink: Arc<InMemoryAuditSink>,
    ) -> SecretsCoordinator {
        SecretsCoordinator::new(
            broker as Arc<dyn SecretsBroker>,
            lease_mgr,
            sink,
            test_hlc(),
        )
    }

    fn test_policy_engine() -> PolicyEngine {
        let engine = PolicyEngine::new();
        engine
            .load_policies(
                r#"
permit(principal, action, resource);
"#,
            )
            .unwrap();
        engine
    }

    #[tokio::test]
    async fn revoke_emits_audit_event() {
        let sink = Arc::new(InMemoryAuditSink::new());
        let broker = Arc::new(MockSecretsBroker::new());
        let lease_mgr = Arc::new(LeaseManager::new());
        let engine = test_policy_engine();

        let tenant_id = TenantId::generate();
        let sandbox_id = SandboxId::generate();
        let principal = PrincipalId::new("user:revoker");
        let decision = engine.evaluate(&principal, &tenant_id, PolicyAction::Exec);

        let lease = lease_mgr.issue(
            tenant_id.clone(),
            principal,
            sandbox_id.clone(),
            LeaseAction::CredentialAccess,
            LeaseScope::unbounded(),
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let coordinator = test_coordinator(broker, lease_mgr, sink.clone());

        coordinator
            .revoke(
                &tenant_id,
                &sandbox_id,
                Some(&lease.lease_id),
                capsule_core::leases::RevocationReason::AdminAction,
            )
            .await
            .unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, AuditEventKind::CredentialRevoked);
        assert_eq!(events[0].outcome.as_deref(), Some("revoked"));
    }

    #[tokio::test]
    async fn revoke_without_lease_still_emits() {
        let sink = Arc::new(InMemoryAuditSink::new());
        let broker = Arc::new(MockSecretsBroker::new());
        let lease_mgr = Arc::new(LeaseManager::new());
        let coordinator = test_coordinator(broker, lease_mgr, sink.clone());

        coordinator
            .revoke(
                &TenantId::generate(),
                &SandboxId::generate(),
                None,
                capsule_core::leases::RevocationReason::ResourceRemoved,
            )
            .await
            .unwrap();

        assert_eq!(sink.events().len(), 1);
    }

    #[tokio::test]
    async fn broker_returns_credentials_for_valid_tenant() {
        let broker = Arc::new(MockSecretsBroker::new());
        broker.seed(
            "tnt_test",
            vec![capsule_core::secrets::mock::MockCredential {
                credential_type: "aws".into(),
                name: "AWS_ACCESS_KEY_ID".into(),
                value: b"AKIAIOSFODNN7EXAMPLE".to_vec(),
            }],
        );

        let coordinator = SecretsCoordinator::new(
            broker as Arc<dyn SecretsBroker>,
            Arc::new(LeaseManager::new()),
            Arc::new(capsule_core::event_bus::NoopAuditSink),
            test_hlc(),
        );

        let request = CredentialRequest {
            tenant_id: TenantId::from_string("tnt_test"),
            sandbox_id: SandboxId::generate(),
            operation_id: "op_test".into(),
            policy_decision_id: None,
            lease_id: None,
            credential_types: vec!["aws".into()],
        };

        let bundle = coordinator
            .broker
            .fetch_credentials(&request)
            .await
            .unwrap();
        assert_eq!(bundle.credentials.len(), 1);
        assert_eq!(bundle.credentials[0].name, "AWS_ACCESS_KEY_ID");
        assert_eq!(bundle.credentials[0].value, b"AKIAIOSFODNN7EXAMPLE");
    }

    #[tokio::test]
    async fn broker_denies_unknown_credential_type() {
        let broker = Arc::new(MockSecretsBroker::new());
        let coordinator = SecretsCoordinator::new(
            broker as Arc<dyn SecretsBroker>,
            Arc::new(LeaseManager::new()),
            Arc::new(capsule_core::event_bus::NoopAuditSink),
            test_hlc(),
        );

        let request = CredentialRequest {
            tenant_id: TenantId::generate(),
            sandbox_id: SandboxId::generate(),
            operation_id: "op_test".into(),
            policy_decision_id: None,
            lease_id: None,
            credential_types: vec!["gcp".into()],
        };

        let result = coordinator.broker.fetch_credentials(&request).await;
        assert!(matches!(
            result,
            Err(SecretsBrokerError::UnknownCredentialType(_))
        ));
    }

    #[tokio::test]
    async fn lease_validation_rejects_revoked_lease() {
        let lease_mgr = Arc::new(LeaseManager::new());
        let engine = test_policy_engine();

        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();
        let principal = PrincipalId::new("user:alice");
        let decision = engine.evaluate(&principal, &tenant, PolicyAction::Exec);

        let lease = lease_mgr.issue(
            tenant.clone(),
            principal,
            sandbox.clone(),
            LeaseAction::CredentialAccess,
            LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["aws".into()],
            },
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        lease_mgr
            .revoke(&lease.lease_id, RevocationReason::AdminAction)
            .unwrap();

        let result = lease_mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::CredentialAccess,
            &LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["aws".into()],
            },
            decision.policy_epoch,
        );

        assert!(matches!(result, Err(LeaseValidationError::Revoked { .. })));
    }

    #[tokio::test]
    async fn lease_validation_rejects_wrong_sandbox() {
        let lease_mgr = Arc::new(LeaseManager::new());
        let engine = test_policy_engine();

        let tenant = TenantId::generate();
        let sandbox_a = SandboxId::generate();
        let sandbox_b = SandboxId::generate();
        let principal = PrincipalId::new("user:alice");
        let decision = engine.evaluate(&principal, &tenant, PolicyAction::Exec);

        let lease = lease_mgr.issue(
            tenant.clone(),
            principal,
            sandbox_a.clone(),
            LeaseAction::CredentialAccess,
            LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["aws".into()],
            },
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let result = lease_mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox_b,
            &tenant,
            LeaseAction::CredentialAccess,
            &LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["aws".into()],
            },
            decision.policy_epoch,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::WrongSandbox { .. })
        ));
    }

    #[tokio::test]
    async fn lease_validation_rejects_stale_policy_epoch() {
        let lease_mgr = Arc::new(LeaseManager::new());
        let engine = test_policy_engine();

        let tenant = TenantId::generate();
        let sandbox = SandboxId::generate();
        let principal = PrincipalId::new("user:alice");
        let decision = engine.evaluate(&principal, &tenant, PolicyAction::Exec);

        let lease = lease_mgr.issue(
            tenant.clone(),
            principal,
            sandbox.clone(),
            LeaseAction::CredentialAccess,
            LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["aws".into()],
            },
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let newer_epoch = decision.policy_epoch + 1;
        let result = lease_mgr.validate_with_scope(
            &lease.lease_id,
            &sandbox,
            &tenant,
            LeaseAction::CredentialAccess,
            &LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["aws".into()],
            },
            newer_epoch,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::StalePolicyEpoch { .. })
        ));
    }

    #[tokio::test]
    async fn audit_credential_issuance_details_are_correct() {
        let sink = Arc::new(InMemoryAuditSink::new());
        let broker = Arc::new(MockSecretsBroker::new());
        let lease_mgr = Arc::new(LeaseManager::new());
        let coordinator = test_coordinator(broker, lease_mgr, sink.clone());

        let tenant_id = TenantId::from_string("tnt_audit_test");
        let sandbox_id = SandboxId::from_string("sbx_audit_test");

        coordinator.emit_credential_issuance(
            &tenant_id,
            &sandbox_id,
            Some("lse_audit_test"),
            Some("pdc_123"),
            AuditOutcome::Success,
            None,
            &["aws".into(), "gcp".into()],
        );

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, AuditEventKind::CredentialIssuance);
        assert_eq!(
            events[0].sandbox_id.as_ref().map(|s| s.as_str()),
            Some("sbx_audit_test")
        );
        assert_eq!(
            events[0].tenant_id.as_ref().map(|t| t.as_str()),
            Some("tnt_audit_test")
        );
        assert_eq!(events[0].outcome.as_deref(), Some("success"));
        assert_eq!(events[0].lease_id.as_deref(), Some("lse_audit_test"));
        assert_eq!(events[0].policy_decision_id.as_deref(), Some("pdc_123"));

        match &events[0].details {
            Some(AuditEventDetails::CredentialIssuance {
                action,
                outcome,
                reason,
                credential_type,
                lease_id: detail_lease_id,
            }) => {
                assert_eq!(action, "credential_access");
                assert_eq!(outcome, "success");
                assert!(reason.is_none());
                assert_eq!(credential_type, "aws,gcp");
                assert_eq!(detail_lease_id.as_deref(), Some("lse_audit_test"));
            }
            other => panic!("unexpected details: {other:?}"),
        }
    }

    // ──── Inject: full integration with mock TCP guest server ────

    #[tokio::test]
    async fn inject_succeeds_with_valid_lease_and_mock_broker() {
        use capsule_guest_protocol::framed;
        use capsule_guest_protocol::operational_v1::{
            InjectSecretsResponse, inject_secrets_response,
        };
        use tokio::net::TcpListener;

        // Set up a mock TCP server that responds to inject_secrets
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read the tagged request (any tagged message is fine)
            let _ = framed::read_tagged::<InjectSecretsResponse>(
                &mut stream,
                std::time::Duration::from_secs(2),
            )
            .await;
            // Send back a success response
            let resp = InjectSecretsResponse {
                result: Some(inject_secrets_response::Result::Injected(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_INJECT_SECRETS_RESPONSE,
                &resp,
                std::time::Duration::from_secs(2),
            )
            .await
            .unwrap();
        });

        // Set up the real components
        let sink = Arc::new(InMemoryAuditSink::new());
        let lease_mgr = Arc::new(LeaseManager::new());
        let broker = Arc::new(MockSecretsBroker::new());
        broker.seed(
            "tnt_inject_test",
            vec![capsule_core::secrets::mock::MockCredential {
                credential_type: "aws".into(),
                name: "AWS_KEY".into(),
                value: b"AKIAIOSFODNN7EXAMPLE".to_vec(),
            }],
        );

        let engine = test_policy_engine();
        let tenant = TenantId::from_string("tnt_inject_test");
        let sandbox = SandboxId::from_string("sbx_inject_test");
        let principal = PrincipalId::new("user:injector");
        let decision = engine.evaluate(&principal, &tenant, PolicyAction::Exec);

        let lease = lease_mgr.issue(
            tenant.clone(),
            principal,
            sandbox.clone(),
            LeaseAction::CredentialAccess,
            LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["aws".into()],
            },
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let coordinator = SecretsCoordinator::new(
            broker as Arc<dyn SecretsBroker>,
            lease_mgr.clone(),
            sink.clone() as Arc<dyn capsule_core::event_bus::AuditEventSink>,
            test_hlc(),
        );

        // Connect to the mock server and create a GuestConnection
        let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let framed_conn = framed::FramedConnection::new(stream, std::time::Duration::from_secs(5));
        let mut guest_conn = GuestConnection::from_framed(
            framed_conn,
            b"1234567890123456".to_vec(),
            "sbx_inject_test".to_string(),
            decision.policy_epoch,
            (0, 1),
        );

        // Call inject
        let result = coordinator
            .inject(
                &tenant,
                &sandbox,
                "op_inject",
                &lease.lease_id,
                Some(&decision.decision_id),
                &["aws".to_string()],
                &mut guest_conn,
            )
            .await;

        assert!(result.is_ok(), "inject should succeed: {result:?}");

        let bundle = result.unwrap();
        assert_eq!(bundle.credentials.len(), 1);
        assert_eq!(bundle.credentials[0].name, "AWS_KEY");

        // Verify audit events
        let issuance_events = sink.events_by_kind(AuditEventKind::CredentialIssuance);
        assert!(
            !issuance_events.is_empty(),
            "should emit CredentialIssuance on success"
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn inject_rejects_invalid_lease_with_denial_audit() {
        use capsule_guest_protocol::framed;
        use capsule_guest_protocol::operational_v1::{
            InjectSecretsResponse, inject_secrets_response,
        };
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = framed::read_tagged::<InjectSecretsResponse>(
                &mut stream,
                std::time::Duration::from_secs(2),
            )
            .await;
            let resp = InjectSecretsResponse {
                result: Some(inject_secrets_response::Result::Injected(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_INJECT_SECRETS_RESPONSE,
                &resp,
                std::time::Duration::from_secs(2),
            )
            .await
            .unwrap();
        });

        let sink = Arc::new(InMemoryAuditSink::new());
        let lease_mgr = Arc::new(LeaseManager::new());
        let broker = Arc::new(MockSecretsBroker::new());
        broker.seed(
            "tnt_deny_test",
            vec![capsule_core::secrets::mock::MockCredential {
                credential_type: "aws".into(),
                name: "AWS_KEY".into(),
                value: b"test".to_vec(),
            }],
        );

        let engine = test_policy_engine();
        let tenant = TenantId::from_string("tnt_deny_test");
        let sandbox = SandboxId::from_string("sbx_deny_test");
        let principal = PrincipalId::new("user:denied");
        let decision = engine.evaluate(&principal, &tenant, PolicyAction::Exec);

        // Issue a lease for a DIFFERENT sandbox to trigger denial
        let other_sandbox = SandboxId::from_string("sbx_other");
        let lease = lease_mgr.issue(
            tenant.clone(),
            principal,
            other_sandbox,
            LeaseAction::CredentialAccess,
            LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["aws".into()],
            },
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        let coordinator = SecretsCoordinator::new(
            broker as Arc<dyn SecretsBroker>,
            lease_mgr.clone(),
            sink.clone() as Arc<dyn capsule_core::event_bus::AuditEventSink>,
            test_hlc(),
        );

        let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let framed_conn = framed::FramedConnection::new(stream, std::time::Duration::from_secs(5));
        let mut guest_conn = GuestConnection::from_framed(
            framed_conn,
            b"1234567890123456".to_vec(),
            "sbx_deny_test".to_string(),
            decision.policy_epoch,
            (0, 1),
        );

        let result = coordinator
            .inject(
                &tenant,
                &sandbox,
                "op_deny",
                &lease.lease_id,
                Some(&decision.decision_id),
                &["aws".to_string()],
                &mut guest_conn,
            )
            .await;

        assert!(result.is_err(), "inject with wrong sandbox should fail");

        // Verify denial audit
        let denied_events = sink.events_by_kind(AuditEventKind::CredentialDenied);
        assert!(
            !denied_events.is_empty(),
            "should emit CredentialDenied on lease validation failure"
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn inject_rejects_revoked_lease_with_denial_audit() {
        use capsule_guest_protocol::framed;
        use capsule_guest_protocol::operational_v1::{
            InjectSecretsResponse, inject_secrets_response,
        };
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = framed::read_tagged::<InjectSecretsResponse>(
                &mut stream,
                std::time::Duration::from_secs(2),
            )
            .await;
            let resp = InjectSecretsResponse {
                result: Some(inject_secrets_response::Result::Injected(true)),
            };
            framed::send_tagged(
                &mut stream,
                framed::TAG_INJECT_SECRETS_RESPONSE,
                &resp,
                std::time::Duration::from_secs(2),
            )
            .await
            .unwrap();
        });

        let sink = Arc::new(InMemoryAuditSink::new());
        let lease_mgr = Arc::new(LeaseManager::new());
        let broker = Arc::new(MockSecretsBroker::new());
        broker.seed(
            "tnt_rev_inject",
            vec![capsule_core::secrets::mock::MockCredential {
                credential_type: "aws".into(),
                name: "AWS_KEY".into(),
                value: b"test".to_vec(),
            }],
        );

        let engine = test_policy_engine();
        let tenant = TenantId::from_string("tnt_rev_inject");
        let sandbox = SandboxId::from_string("sbx_rev_inject");
        let principal = PrincipalId::new("user:revoked");
        let decision = engine.evaluate(&principal, &tenant, PolicyAction::Exec);

        let lease = lease_mgr.issue(
            tenant.clone(),
            principal,
            sandbox.clone(),
            LeaseAction::CredentialAccess,
            LeaseScope {
                ports: vec![],
                paths: vec![],
                egress_cidrs: vec![],
                credential_types: vec!["aws".into()],
            },
            &decision,
            DEFAULT_LEASE_TTL_SECS,
        );

        // Revoke the lease
        lease_mgr
            .revoke(&lease.lease_id, RevocationReason::AdminAction)
            .unwrap();

        let coordinator = SecretsCoordinator::new(
            broker as Arc<dyn SecretsBroker>,
            lease_mgr.clone(),
            sink.clone() as Arc<dyn capsule_core::event_bus::AuditEventSink>,
            test_hlc(),
        );

        let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let framed_conn = framed::FramedConnection::new(stream, std::time::Duration::from_secs(5));
        let mut guest_conn = GuestConnection::from_framed(
            framed_conn,
            b"1234567890123456".to_vec(),
            "sbx_rev_inject".to_string(),
            decision.policy_epoch,
            (0, 1),
        );

        let result = coordinator
            .inject(
                &tenant,
                &sandbox,
                "op_revoked",
                &lease.lease_id,
                Some(&decision.decision_id),
                &["aws".to_string()],
                &mut guest_conn,
            )
            .await;

        assert!(result.is_err(), "revoked lease should cause inject to fail");
        assert!(
            matches!(
                result.unwrap_err(),
                crate::secrets::SecretsCoordinationError::LeaseValidation(
                    LeaseValidationError::Revoked { .. }
                )
            ),
            "should fail with Revoked error"
        );

        let denied_events = sink.events_by_kind(AuditEventKind::CredentialDenied);
        assert!(
            !denied_events.is_empty(),
            "should emit CredentialDenied on revoked lease"
        );

        server.await.unwrap();
    }
}
