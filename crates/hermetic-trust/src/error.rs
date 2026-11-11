#![forbid(unsafe_code)]

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),
    #[error("PKCS#8 error: {0}")]
    Pkcs8(#[from] rsa::pkcs8::Error),
    #[error("PKCS#1 error: {0}")]
    Pkcs1(#[from] rsa::pkcs1::Error),
    #[error("HKDF error: {0}")]
    Hkdf(String),
    #[error("Time error: {0}")]
    Time(String),
    #[error("Seed file must be exactly 32 bytes (got {0})")]
    InvalidSeedFileLength(usize),
    #[error("Seed file permissions {0:#o} are insecure: group or world readable")]
    InsecureSeedFilePermissions(u32),
    #[error("JKS error: {0}")]
    Jks(String),
    #[error("Rootfs symlink error: {0}")]
    Symlink(String),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Certificate error: {0}")]
    Cert(String),
    #[error("alias collision with private key")]
    AliasCollisionWithPrivateKey,
    #[error("unknown keystore password")]
    UnknownKeystorePassword,
}
