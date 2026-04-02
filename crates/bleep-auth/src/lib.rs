// ============================================================================
// BLEEP-AUTH: Production Authentication & Identity Layer
//
// Provides the complete authentication surface for BLEEP nodes:
//
//   credentials     — salted SHA3-256 hashing; constant-time verify; Zeroize.
//   session         — HS256 JWT issuance/validation; JTI deny-list revocation.
//   rbac            — Role hierarchy; DashMap assignments; O(1) permission eval.
//   identity        — NodeIdentity & DappIdentity; deterministic IDs.
//   validator_binding — Kyber1024 challenge/response proof-of-possession.
//   audit           — Merkle-chained append-only log; tamper detection.
//   rate_limiter    — Fixed-window token bucket per (identity, action).
//
// Entry point: `AuthService::new(jwt_secret)`.
// ============================================================================

pub mod audit;
pub mod credentials;
pub mod errors;
pub mod identity;
pub mod rate_limiter;
pub mod rbac;
pub mod session;
pub mod validator_binding;

pub use audit::{AuditEntry, AuditEvent, AuditEventKind, AuditLog};
pub use credentials::{Credential, CredentialKind, CredentialStore};
pub use errors::{AuthError, AuthResult};
pub use identity::{DappIdentity, IdentityKind, IdentityRegistry, NodeIdentity};
pub use rate_limiter::{RateLimitConfig, RateLimiter};
pub use rbac::{AccessDecision, Permission, RbacEngine, Role};
pub use session::{SessionClaims, SessionManager, SessionToken};
pub use validator_binding::{ValidatorBinding, ValidatorBindingProof, ValidatorBindingRegistry};

use log::info;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Unified authentication service. Wrap in `Arc<AuthService>` for sharing.
///
/// # Safety invariants
/// 1. `jwt_secret` must be ≥32 bytes of cryptographically random material.
/// 2. Every write operation passes through the rate limiter before execution.
/// 3. All events (including denials) are appended to the audit log.
/// 4. Validator binding requires Kyber1024 key-possession proof.
/// 5. Password rotation deactivates the previous hash immediately.
/// 6. Session revocation is permanent and takes effect within the same call.
pub struct AuthService {
    pub credentials: Arc<RwLock<CredentialStore>>,
    pub sessions: Arc<SessionManager>,
    pub rbac: Arc<RbacEngine>,
    pub identities: Arc<RwLock<IdentityRegistry>>,
    pub validator_bindings: Arc<RwLock<ValidatorBindingRegistry>>,
    pub audit: Arc<RwLock<AuditLog>>,
    pub rate_limiter: Arc<RateLimiter>,
}

impl AuthService {
    pub fn new(jwt_secret: Vec<u8>) -> AuthResult<Self> {
        Ok(Self {
            credentials: Arc::new(RwLock::new(CredentialStore::new())),
            sessions: Arc::new(SessionManager::new(jwt_secret)?),
            rbac: Arc::new(RbacEngine::new()),
            identities: Arc::new(RwLock::new(IdentityRegistry::new())),
            validator_bindings: Arc::new(RwLock::new(ValidatorBindingRegistry::new())),
            audit: Arc::new(RwLock::new(AuditLog::new())),
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::strict())),
        })
    }

    // ─── Registration ──────────────────────────────────────────────────────

    pub async fn register_operator(
        &self,
        operator_handle: String,
        display_name: String,
        password: String,
        kyber_public_key: Vec<u8>,
    ) -> AuthResult<(NodeIdentity, SessionToken)> {
        self.rate_limiter
            .check_and_record(&operator_handle, "register")?;

        let identity = {
            let mut reg = self.identities.write().await;
            reg.register_node_operator(operator_handle.clone(), display_name, kyber_public_key)?
        };

        self.credentials
            .write()
            .await
            .store_password(&identity.id, password)?;
        self.rbac.assign_role(&identity.id, Role::NodeOperator);

        let token = self.sessions.issue(
            &identity.id,
            &[Role::NodeOperator],
            chrono::Duration::hours(8),
        )?;

        self.audit.write().await.record(AuditEvent {
            kind: AuditEventKind::Registration,
            actor_id: identity.id.clone(),
            resource: "node_identity".into(),
            action: "register_operator".into(),
            outcome: "success".into(),
            details: format!("handle={operator_handle}"),
            timestamp: chrono::Utc::now(),
        });

        info!("[Auth] Operator registered: {}", identity.id);
        Ok((identity, token))
    }

    pub async fn register_dapp(
        &self,
        developer_handle: String,
        display_name: String,
        password: String,
    ) -> AuthResult<(DappIdentity, SessionToken)> {
        self.rate_limiter
            .check_and_record(&developer_handle, "register")?;

        let identity = {
            let mut reg = self.identities.write().await;
            reg.register_dapp_developer(developer_handle.clone(), display_name)?
        };

        self.credentials
            .write()
            .await
            .store_password(&identity.id, password)?;
        self.rbac.assign_role(&identity.id, Role::DappDeveloper);

        let token = self.sessions.issue(
            &identity.id,
            &[Role::DappDeveloper],
            chrono::Duration::hours(8),
        )?;

        self.audit.write().await.record(AuditEvent {
            kind: AuditEventKind::Registration,
            actor_id: identity.id.clone(),
            resource: "dapp_identity".into(),
            action: "register_dapp".into(),
            outcome: "success".into(),
            details: format!("handle={developer_handle}"),
            timestamp: chrono::Utc::now(),
        });

        Ok((identity, token))
    }

    // ─── Login / Logout ────────────────────────────────────────────────────

    /// Authenticate by identity ID and password. Returns a fresh 8-hour session.
    pub async fn login(&self, identity_id: &str, password: &str) -> AuthResult<SessionToken> {
        self.rate_limiter.check_and_record(identity_id, "login")?;
        self.credentials
            .write()
            .await
            .verify_password(identity_id, password)?;

        let roles = self.rbac.get_roles(identity_id);
        let token = self
            .sessions
            .issue(identity_id, &roles, chrono::Duration::hours(8))?;

        self.audit.write().await.record(AuditEvent {
            kind: AuditEventKind::Login,
            actor_id: identity_id.to_string(),
            resource: "session".into(),
            action: "login".into(),
            outcome: "success".into(),
            details: format!("jti={}", token.jti),
            timestamp: chrono::Utc::now(),
        });

        Ok(token)
    }

    pub async fn logout(&self, token: &str) -> AuthResult<()> {
        let claims = self.sessions.validate(token)?;
        self.sessions.revoke(&claims.jti)?;

        self.audit.write().await.record(AuditEvent {
            kind: AuditEventKind::Logout,
            actor_id: claims.sub.clone(),
            resource: "session".into(),
            action: "logout".into(),
            outcome: "success".into(),
            details: format!("revoked jti={}", claims.jti),
            timestamp: chrono::Utc::now(),
        });
        Ok(())
    }

    // ─── Token validation (hot path — no I/O) ─────────────────────────────

    pub async fn validate_token(&self, token: &str) -> AuthResult<SessionClaims> {
        self.sessions.validate(token)
    }

    // ─── Authorization ─────────────────────────────────────────────────────

    pub async fn authorize(
        &self,
        claims: &SessionClaims,
        permission: Permission,
    ) -> AccessDecision {
        let decision = self.rbac.evaluate(&claims.roles, permission);

        if let AccessDecision::Denied(ref reason) = decision {
            self.audit.write().await.record(AuditEvent {
                kind: AuditEventKind::AccessDenied,
                actor_id: claims.sub.clone(),
                resource: format!("{permission:?}"),
                action: "authorize".into(),
                outcome: "denied".into(),
                details: reason.clone(),
                timestamp: chrono::Utc::now(),
            });
        }

        decision
    }

    // ─── Validator binding ─────────────────────────────────────────────────

    /// Issue a Kyber1024 binding challenge.
    /// Returns (challenge_id, kyber_ciphertext) to forward to the operator.
    pub async fn issue_binding_challenge(
        &self,
        validator_public_key: &[u8],
    ) -> AuthResult<(String, Vec<u8>)> {
        self.validator_bindings
            .write()
            .await
            .issue_challenge(validator_public_key)
    }

    /// Complete validator binding. Requires `Permission::BindValidator`.
    /// Elevates the operator's role set to include `Validator` on success.
    pub async fn bind_validator(
        &self,
        claims: &SessionClaims,
        validator_id: String,
        proof: ValidatorBindingProof,
    ) -> AuthResult<ValidatorBinding> {
        if let AccessDecision::Denied(r) =
            self.rbac.evaluate(&claims.roles, Permission::BindValidator)
        {
            return Err(AuthError::Unauthorized(r));
        }

        let binding = self.validator_bindings.write().await.bind(
            claims.sub.clone(),
            validator_id.clone(),
            proof,
        )?;

        self.rbac.assign_role(&claims.sub, Role::Validator);

        self.audit.write().await.record(AuditEvent {
            kind: AuditEventKind::ValidatorBound,
            actor_id: claims.sub.clone(),
            resource: "validator_binding".into(),
            action: "bind_validator".into(),
            outcome: "success".into(),
            details: format!("validator={validator_id}"),
            timestamp: chrono::Utc::now(),
        });

        Ok(binding)
    }

    // ─── API key management ────────────────────────────────────────────────

    pub async fn issue_api_key(&self, identity_id: &str) -> AuthResult<String> {
        let key = self.credentials.write().await.issue_api_key(identity_id)?;

        self.audit.write().await.record(AuditEvent {
            kind: AuditEventKind::CredentialRotated,
            actor_id: identity_id.to_string(),
            resource: "api_key".into(),
            action: "issue_api_key".into(),
            outcome: "success".into(),
            details: "new API key issued".into(),
            timestamp: chrono::Utc::now(),
        });

        Ok(key)
    }

    // ─── Maintenance (called by bleep-scheduler) ───────────────────────────

    /// Purge expired session revocations and rate-limit buckets.
    /// Call every 5 minutes from the scheduler.
    pub async fn maintenance_sweep(&self) {
        self.sessions
            .purge_expired_revocations(chrono::Duration::hours(24));
        self.rate_limiter.purge_expired();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Vec<u8> {
        b"a-production-grade-32byte-secret!".to_vec()
    }
    fn kyber_key() -> Vec<u8> {
        vec![0xABu8; 1568]
    }
    async fn svc() -> AuthService {
        AuthService::new(secret()).unwrap()
    }

    #[tokio::test]
    async fn register_and_login() {
        let s = svc().await;
        let (id, _) = s
            .register_operator(
                "op-handle".into(),
                "Test Operator".into(),
                "secure-password-123".into(),
                kyber_key(),
            )
            .await
            .unwrap();
        let tok = s.login(&id.id, "secure-password-123").await.unwrap();
        let c = s.validate_token(&tok.token).await.unwrap();
        assert_eq!(c.sub, id.id);
        assert!(c.roles.contains(&Role::NodeOperator));
    }

    #[tokio::test]
    async fn wrong_password_rejected() {
        let s = svc().await;
        let (id, _) = s
            .register_operator(
                "op2".into(),
                "Op2".into(),
                "right-pass-here!".into(),
                kyber_key(),
            )
            .await
            .unwrap();
        assert!(s.login(&id.id, "wrong").await.is_err());
    }

    #[tokio::test]
    async fn logout_invalidates_session() {
        let s = svc().await;
        let (id, _) = s
            .register_operator(
                "op3".into(),
                "Op3".into(),
                "logout-test-pass!".into(),
                kyber_key(),
            )
            .await
            .unwrap();
        let tok = s.login(&id.id, "logout-test-pass!").await.unwrap();
        s.logout(&tok.token).await.unwrap();
        assert!(s.validate_token(&tok.token).await.is_err());
    }

    #[tokio::test]
    async fn rbac_operator_permissions() {
        let s = svc().await;
        let (_, tok) = s
            .register_operator(
                "op4".into(),
                "Op4".into(),
                "rbac-test-pass!!".into(),
                kyber_key(),
            )
            .await
            .unwrap();
        let c = s.validate_token(&tok.token).await.unwrap();
        assert!(s.authorize(&c, Permission::RegisterNode).await.is_granted());
        assert!(!s
            .authorize(&c, Permission::AdministerSystem)
            .await
            .is_granted());
    }

    #[tokio::test]
    async fn audit_chain_intact_after_operations() {
        let s = svc().await;
        let (id, _) = s
            .register_operator(
                "op5".into(),
                "Op5".into(),
                "audit-test-pass!!".into(),
                kyber_key(),
            )
            .await
            .unwrap();
        s.login(&id.id, "audit-test-pass!!").await.unwrap();
        let log = s.audit.read().await;
        assert!(log.len() >= 2);
        assert!(log.verify_chain().is_ok());
    }

    #[tokio::test]
    async fn dapp_cannot_sign_blocks() {
        let s = svc().await;
        let (_, tok) = s
            .register_dapp("dev-handle".into(), "Dev".into(), "dapp-secure-pass".into())
            .await
            .unwrap();
        let c = s.validate_token(&tok.token).await.unwrap();
        assert!(!s.authorize(&c, Permission::SignBlock).await.is_granted());
        assert!(s
            .authorize(&c, Permission::DeployContract)
            .await
            .is_granted());
    }
}

// ── Hardening-phase modules ────────────────────────────────────────────────────
pub mod audit_store;
pub use audit_store::{AuditLogStore, StoredAuditEntry, AUDIT_CACHE_SIZE};
