use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq)]
pub enum AuthError {
    // ── Credential errors ────────────────────────────────────────────────
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Password too weak: must be ≥12 characters")]
    PasswordTooWeak,

    // ── Identity errors ──────────────────────────────────────────────────
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    #[error("Identity already exists: {0}")]
    IdentityAlreadyExists(String),

    #[error("Identity is deactivated: {0}")]
    IdentityDeactivated(String),

    // ── Session errors ───────────────────────────────────────────────────
    #[error("Session token is invalid or malformed")]
    InvalidSession,

    #[error("Session token has expired")]
    ExpiredSession,

    #[error("Session has been explicitly revoked")]
    RevokedSession,

    // ── Access control errors ────────────────────────────────────────────
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("System administrator has already been bootstrapped")]
    AlreadyBootstrapped,

    // ── Rate limiting ────────────────────────────────────────────────────
    #[error("Rate limit exceeded for identity '{identity}' on action '{action}' — retry after {retry_after_secs}s")]
    RateLimitExceeded {
        identity: String,
        action: String,
        retry_after_secs: i64,
    },

    // ── Validator binding ────────────────────────────────────────────────
    #[error("Validator binding error: {0}")]
    ValidatorBindingError(String),

    #[error("Binding challenge not found or already consumed: {0}")]
    ChallengeNotFound(String),

    #[error("Binding challenge has expired")]
    ChallengeExpired,

    // ── Key material ─────────────────────────────────────────────────────
    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),

    // ── Crypto / encoding ────────────────────────────────────────────────
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    // ── Infrastructure ───────────────────────────────────────────────────
    #[error("Audit log error: {0}")]
    AuditError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type AuthResult<T> = Result<T, AuthError>;
