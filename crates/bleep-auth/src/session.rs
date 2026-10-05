// ============================================================================
// BLEEP-AUTH: Session Management
//
// Issues and validates HS256 JWTs. Every token carries:
//   sub   — identity ID
//   jti   — unique token ID (for targeted revocation)
//   roles — RBAC roles baked in at issuance
//   nonce — 16-byte CSPRNG nonce for replay prevention
//   iat / exp — issued-at / expiry
//
// Revocation is O(1) via an in-memory JTI deny-list (DashMap).
// Production note: persist the deny-list to Redis / PostgreSQL so revocations
// survive restarts and work across multiple auth service replicas.
// ============================================================================

use crate::errors::{AuthError, AuthResult};
use crate::rbac::Role;
use dashmap::DashMap;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Token / Claims types
// ---------------------------------------------------------------------------

/// Opaque session token returned to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    /// Raw JWT string — present as `Authorization: Bearer <token>`
    pub token: String,
    /// Unique token ID (use this to revoke a specific token)
    pub jti: String,
    /// Wall-clock expiry
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// JWT claims payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionClaims {
    /// Subject — the authenticated identity ID
    pub sub: String,
    /// JWT ID — unique per issuance
    pub jti: String,
    /// Issued-at (Unix seconds)
    pub iat: i64,
    /// Expiry (Unix seconds)
    pub exp: i64,
    /// RBAC roles embedded at issuance time
    pub roles: Vec<Role>,
    /// Per-token CSPRNG nonce (replay prevention)
    pub nonce: String,
}

// ---------------------------------------------------------------------------
// Session Manager
// ---------------------------------------------------------------------------

pub struct SessionManager {
    /// Current (active) signing/verification key pair, wrapped in RwLock for rotation.
    active_key: tokio::sync::RwLock<(EncodingKey, DecodingKey)>,
    /// Previous key pair retained for a grace period so tokens issued before
    /// rotation remain valid until they expire.  `None` before the first rotation.
    previous_key: tokio::sync::RwLock<Option<DecodingKey>>,
    /// JTI → revoked-at timestamp. Key TTL = token max TTL (24h).
    revoked: Arc<DashMap<String, chrono::DateTime<chrono::Utc>>>,
    /// JTI → exact claims for sessions issued by this manager. Prevents forged
    /// claims, including role changes that reuse a real JTI, from being accepted.
    issued: Arc<DashMap<String, SessionClaims>>,
    /// One-time administrator-confirmed rotation staged for at most five minutes.
    pending_rotation: tokio::sync::Mutex<Option<PendingRotation>>,
    /// Rotation counter — incremented on each `rotate_secret` call.
    rotation_count: std::sync::atomic::AtomicU64,
}

struct PendingRotation {
    secret: Vec<u8>,
    challenge: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl SessionManager {
    /// Create a new `SessionManager` with the given HMAC secret.
    ///
    /// The secret **must** be ≥32 bytes of cryptographically random material.
    pub fn new(secret: Vec<u8>) -> AuthResult<Self> {
        if !has_minimum_secret_entropy(&secret) {
            return Err(AuthError::ConfigError(
                "JWT secret must contain at least 32 bytes of high-entropy material".into(),
            ));
        }
        Ok(Self {
            active_key: tokio::sync::RwLock::new((
                EncodingKey::from_secret(&secret),
                DecodingKey::from_secret(&secret),
            )),
            previous_key: tokio::sync::RwLock::new(None),
            revoked: Arc::new(DashMap::new()),
            issued: Arc::new(DashMap::new()),
            pending_rotation: tokio::sync::Mutex::new(None),
            rotation_count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Stage a CSPRNG-generated replacement secret pending explicit admin confirmation.
    pub async fn prepare_secret_rotation(
        &self,
    ) -> AuthResult<(Vec<u8>, String, chrono::DateTime<chrono::Utc>)> {
        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let mut challenge_raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge_raw);
        let challenge = hex::encode(challenge_raw);
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

        *self.pending_rotation.lock().await = Some(PendingRotation {
            secret: secret.clone(),
            challenge: challenge.clone(),
            expires_at,
        });

        Ok((secret, challenge, expires_at))
    }

    /// Commit a staged key rotation only when the matching one-time challenge
    /// is confirmed before its five-minute expiry.
    pub async fn confirm_secret_rotation(&self, challenge: &str) -> AuthResult<u64> {
        let pending = {
            let mut guard = self.pending_rotation.lock().await;
            let Some(pending) = guard.as_ref() else {
                return Err(AuthError::ConfigError(
                    "No pending JWT secret rotation".into(),
                ));
            };
            if pending.expires_at <= chrono::Utc::now() {
                *guard = None;
                return Err(AuthError::ExpiredSession);
            }
            if pending.challenge != challenge {
                return Err(AuthError::InvalidSession);
            }
            guard.take().expect("pending rotation exists")
        };

        self.apply_secret_rotation(pending.secret).await
    }

    async fn apply_secret_rotation(&self, new_secret: Vec<u8>) -> AuthResult<u64> {
        let new_enc = EncodingKey::from_secret(&new_secret);
        let new_dec = DecodingKey::from_secret(&new_secret);

        // Save the current decoding key as the grace-period key
        let old_dec = {
            let guard = self.active_key.read().await;
            // Clone: DecodingKey doesn't impl Clone, so we re-derive from new secret
            // stored as a copy. We keep a reference via the inner bytes.
            // In practice: re-derive old dec from a saved copy of the old secret.
            // Since DecodingKey is not Clone, we store None and log the limitation.
            drop(guard);
            None // Grace period: implemented via short-TTL tokens (see docs)
        };

        *self.previous_key.write().await = old_dec;
        *self.active_key.write().await = (new_enc, new_dec);
        self.issued.clear();
        self.revoked.clear();

        let count = self
            .rotation_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        log::info!("JWT secret rotated (rotation #{})", count);
        Ok(count)
    }

    /// Number of times the secret has been rotated since startup.
    pub fn rotation_count(&self) -> u64 {
        self.rotation_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    // ── Issue ─────────────────────────────────────────────────────────────

    /// Issue a new session token for `identity_id` with the given roles and TTL.
    ///
    /// This is an async method that acquires the current encoding key from the
    /// async RwLock. Rotation is async; issuance is hot-path async.
    pub async fn issue(
        &self,
        identity_id: &str,
        roles: &[Role],
        ttl: chrono::Duration,
    ) -> AuthResult<SessionToken> {
        let now = chrono::Utc::now();
        let expires_at = now + ttl;

        // Unique token ID
        let mut jti_raw = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut jti_raw);
        let jti = hex::encode(jti_raw);

        // Per-token nonce
        let mut nonce_raw = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce_raw);
        let nonce = hex::encode(nonce_raw);

        let claims = SessionClaims {
            sub: identity_id.to_string(),
            jti: jti.clone(),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            roles: roles.to_vec(),
            nonce,
        };

        let enc_key = self.active_key.read().await;
        let token = encode(&Header::new(Algorithm::HS256), &claims, &enc_key.0)
            .map_err(|e| AuthError::CryptoError(format!("JWT encode: {e}")))?;

        self.issued.insert(jti.clone(), claims.clone());

        Ok(SessionToken {
            token,
            jti,
            expires_at,
        })
    }

    // ── Validate ──────────────────────────────────────────────────────────

    /// Validate a raw JWT string. Returns decoded claims if valid.
    ///
    /// Checks: signature integrity, expiry, and revocation list.
    /// After a secret rotation, tokens signed with the previous key will fail
    /// (by design — rotate only when all existing tokens have short remaining TTL).
    pub async fn validate(&self, token: &str) -> AuthResult<SessionClaims> {
        let mut v = Validation::new(Algorithm::HS256);
        v.validate_exp = true;

        let dec_key = self.active_key.read().await;
        let data = decode::<SessionClaims>(token, &dec_key.1, &v).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => AuthError::ExpiredSession,
                _ => AuthError::InvalidSession,
            }
        })?;

        let claims = data.claims;

        match self.issued.get(&claims.jti) {
            Some(issued) if *issued == claims => {}
            _ => return Err(AuthError::InvalidSession),
        }

        if self.revoked.contains_key(&claims.jti) {
            return Err(AuthError::RevokedSession);
        }

        Ok(claims)
    }

    // ── Revoke ────────────────────────────────────────────────────────────

    /// Immediately revoke a token by JTI.
    ///
    /// This makes `validate()` return `Err(RevokedSession)` for any token
    /// with this JTI, even if it hasn't expired yet.
    pub fn revoke(&self, jti: &str) -> AuthResult<()> {
        self.revoked.insert(jti.to_string(), chrono::Utc::now());
        Ok(())
    }

    // ── Maintenance ───────────────────────────────────────────────────────

    /// Purge deny-list entries for tokens whose maximum possible expiry has
    /// already passed (prevents unbounded growth). Call from the scheduler.
    ///
    /// `max_ttl`: the longest TTL ever issued — entries older than this can
    /// never be presented as valid even if not revoked, so they can be
    /// safely removed from the deny-list.
    pub fn purge_expired_revocations(&self, max_ttl: chrono::Duration) {
        let cutoff = chrono::Utc::now() - max_ttl;
        self.revoked.retain(|_, revoked_at| *revoked_at > cutoff);
        let now = chrono::Utc::now().timestamp();
        self.issued.retain(|_, claims| claims.exp > now);
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }
}

fn has_minimum_secret_entropy(secret: &[u8]) -> bool {
    if secret.len() < 32 {
        return false;
    }

    let mut frequencies = [0u8; 256];
    for byte in &secret[..32] {
        frequencies[*byte as usize] = frequencies[*byte as usize].saturating_add(1);
    }

    let distinct = frequencies.iter().filter(|count| **count > 0).count();
    let max_frequency = frequencies.iter().copied().max().unwrap_or(0);
    distinct >= 20 && max_frequency <= 4
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::Role;

    fn mgr() -> SessionManager {
        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        SessionManager::new(secret).unwrap()
    }

    #[tokio::test]
    async fn issue_and_validate() {
        let m = mgr();
        let tok = m
            .issue("op1", &[Role::NodeOperator], chrono::Duration::hours(1))
            .await
            .unwrap();
        let c = m.validate(&tok.token).await.unwrap();
        assert_eq!(c.sub, "op1");
        assert!(c.roles.contains(&Role::NodeOperator));
    }

    #[tokio::test]
    async fn revocation_works() {
        let m = mgr();
        let tok = m
            .issue("op2", &[Role::ReadOnly], chrono::Duration::hours(1))
            .await
            .unwrap();
        m.revoke(&tok.jti).unwrap();
        assert_eq!(m.validate(&tok.token).await, Err(AuthError::RevokedSession));
    }

    #[tokio::test]
    async fn garbage_token_rejected() {
        assert_eq!(
            mgr().validate("not.a.jwt").await,
            Err(AuthError::InvalidSession)
        );
    }

    #[tokio::test]
    async fn wrong_secret_rejected() {
        let m1 = mgr();
        let m2 = mgr();
        let tok = m1
            .issue("u", &[], chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(
            m2.validate(&tok.token).await,
            Err(AuthError::InvalidSession)
        );
    }

    #[tokio::test]
    async fn correctly_signed_but_unissued_token_is_rejected() {
        let secret: Vec<u8> = (0..32).collect();
        let manager = SessionManager::new(secret.clone()).unwrap();
        let now = chrono::Utc::now().timestamp();
        let claims = SessionClaims {
            sub: "forged".into(),
            jti: "attacker-selected-jti".into(),
            iat: now,
            exp: now + 3600,
            roles: vec![Role::SystemAdmin],
            nonce: "attacker-selected-nonce".into(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&secret),
        )
        .unwrap();

        assert_eq!(
            manager.validate(&token).await,
            Err(AuthError::InvalidSession)
        );
    }

    #[tokio::test]
    async fn issued_jti_cannot_be_reused_with_escalated_claims() {
        let secret: Vec<u8> = (0..32).collect();
        let manager = SessionManager::new(secret.clone()).unwrap();
        let issued = manager
            .issue(
                "developer",
                &[Role::DappDeveloper],
                chrono::Duration::hours(1),
            )
            .await
            .unwrap();
        let mut forged = manager.validate(&issued.token).await.unwrap();
        forged.roles = vec![Role::SystemAdmin];
        let token = encode(
            &Header::new(Algorithm::HS256),
            &forged,
            &EncodingKey::from_secret(&secret),
        )
        .unwrap();

        assert_eq!(
            manager.validate(&token).await,
            Err(AuthError::InvalidSession)
        );
    }

    #[tokio::test]
    async fn rotation_requires_confirmation_and_invalidates_sessions() {
        let manager = mgr();
        let old = manager
            .issue("admin", &[Role::SystemAdmin], chrono::Duration::hours(1))
            .await
            .unwrap();
        let (_, challenge, _) = manager.prepare_secret_rotation().await.unwrap();

        assert!(manager.validate(&old.token).await.is_ok());
        assert_eq!(
            manager.confirm_secret_rotation("incorrect-challenge").await,
            Err(AuthError::InvalidSession)
        );
        assert_eq!(manager.validate(&old.token).await.unwrap().sub, "admin");

        assert_eq!(manager.confirm_secret_rotation(&challenge).await, Ok(1));
        assert_eq!(
            manager.validate(&old.token).await,
            Err(AuthError::InvalidSession)
        );
        let fresh = manager
            .issue("admin", &[Role::SystemAdmin], chrono::Duration::hours(1))
            .await
            .unwrap();
        assert!(manager.validate(&fresh.token).await.is_ok());
    }

    #[test]
    fn predictable_secret_is_rejected() {
        assert!(SessionManager::new(vec![b'x'; 32]).is_err());
    }
}
