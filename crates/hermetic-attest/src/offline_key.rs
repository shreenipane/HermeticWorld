//! Offline-key signing for DSSE envelopes (architecture §12: "signed with Sigstore
//! keyless or with an offline key"). The offline key is Ed25519.
//!
//! The private key is a PKCS#8 v1/v2 document handed in by path (read with
//! [`crate::safe_read_file`], so symlinks, FIFOs and devices are refused) or by an
//! already-open file descriptor (any [`Read`]). Nothing here knows a default key
//! location. The key id is `sha256:<hex of SHA-256 of the 32-byte public key>`.

use std::fmt;
use std::io::Read;
use std::path::Path;

use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest as _, Sha256};

use crate::dsse::{SignatureError, Signer, Verifier};
use crate::fs::safe_read_file;
use crate::hex::hex_encode;

/// Largest accepted PKCS#8 private key document.
pub const MAX_PRIVATE_KEY_BYTES: usize = 1024;
/// Ed25519 public key length.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIGNATURE_BYTES: usize = 64;
/// Largest number of trusted keys one verifier holds.
pub const MAX_TRUSTED_KEYS: usize = 64;

#[derive(Clone, PartialEq, Eq)]
pub enum KeyError {
    Read(String),
    TooLarge { limit: usize },
    InvalidPrivateKey,
    InvalidPublicKey,
    NoTrustedKeys,
    TooManyTrustedKeys { limit: usize },
    DuplicateTrustedKey,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(e) => write!(f, "cannot read key: {e}"),
            Self::TooLarge { limit } => write!(f, "key exceeds {limit} bytes"),
            Self::InvalidPrivateKey => write!(f, "invalid Ed25519 PKCS#8 private key"),
            Self::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            Self::NoTrustedKeys => write!(f, "no trusted keys"),
            Self::TooManyTrustedKeys { limit } => write!(f, "more than {limit} trusted keys"),
            Self::DuplicateTrustedKey => write!(f, "duplicate trusted key"),
        }
    }
}

impl std::error::Error for KeyError {}
redacted_debug!(KeyError);

/// Key id of an Ed25519 public key.
pub fn ed25519_key_id(public_key: &[u8]) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(public_key)))
}

/// Ed25519 signer over a PKCS#8 private key.
pub struct Ed25519Signer {
    pair: Ed25519KeyPair,
    key_id: String,
}

impl Ed25519Signer {
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, KeyError> {
        if der.len() > MAX_PRIVATE_KEY_BYTES {
            return Err(KeyError::TooLarge {
                limit: MAX_PRIVATE_KEY_BYTES,
            });
        }
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map_err(|_| KeyError::InvalidPrivateKey)?;
        let key_id = ed25519_key_id(pair.public_key().as_ref());
        Ok(Self { pair, key_id })
    }

    /// Load from a path; refuses symlinks and non-regular files.
    pub fn from_pkcs8_path(path: &Path) -> Result<Self, KeyError> {
        let bytes = safe_read_file(path, MAX_PRIVATE_KEY_BYTES)
            .map_err(|e| KeyError::Read(e.to_string()))?;
        Self::from_pkcs8(&bytes)
    }

    /// Load from an open descriptor (bounded read).
    pub fn from_pkcs8_reader(reader: impl Read) -> Result<Self, KeyError> {
        let mut bytes = Vec::new();
        reader
            .take(MAX_PRIVATE_KEY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| KeyError::InvalidPrivateKey)?;
        Self::from_pkcs8(&bytes)
    }

    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_KEY_BYTES] {
        let mut out = [0u8; ED25519_PUBLIC_KEY_BYTES];
        out.copy_from_slice(self.pair.public_key().as_ref());
        out
    }
}

impl Signer for Ed25519Signer {
    fn key_id(&self) -> Option<String> {
        Some(self.key_id.clone())
    }

    fn sign(&self, pae_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        Ok(self.pair.sign(pae_bytes).as_ref().to_vec())
    }
}

/// Verifier over a fixed set of trusted Ed25519 public keys.
///
/// Every signature must carry a key id naming a trusted key; a missing or
/// unknown key id fails closed.
pub struct Ed25519Verifier {
    keys: Vec<(String, [u8; ED25519_PUBLIC_KEY_BYTES])>,
}

impl Ed25519Verifier {
    pub fn new(public_keys: &[&[u8]]) -> Result<Self, KeyError> {
        if public_keys.is_empty() {
            return Err(KeyError::NoTrustedKeys);
        }
        if public_keys.len() > MAX_TRUSTED_KEYS {
            return Err(KeyError::TooManyTrustedKeys {
                limit: MAX_TRUSTED_KEYS,
            });
        }
        let mut keys: Vec<(String, [u8; ED25519_PUBLIC_KEY_BYTES])> = Vec::new();
        for raw in public_keys {
            let key: [u8; ED25519_PUBLIC_KEY_BYTES] =
                (*raw).try_into().map_err(|_| KeyError::InvalidPublicKey)?;
            let id = ed25519_key_id(&key);
            if keys.iter().any(|(k, _)| *k == id) {
                return Err(KeyError::DuplicateTrustedKey);
            }
            keys.push((id, key));
        }
        Ok(Self { keys })
    }

    /// Load one raw 32-byte public key from a path (no symlinks).
    pub fn from_public_key_path(path: &Path) -> Result<Self, KeyError> {
        let bytes = safe_read_file(path, ED25519_PUBLIC_KEY_BYTES)
            .map_err(|e| KeyError::Read(e.to_string()))?;
        Self::new(&[&bytes])
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(
        &self,
        key_id: Option<&str>,
        pae_bytes: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), SignatureError> {
        let id =
            key_id.ok_or_else(|| SignatureError::VerificationFailed("missing key id".into()))?;
        let (_, key) = self
            .keys
            .iter()
            .find(|(k, _)| k == id)
            .ok_or_else(|| SignatureError::VerificationFailed("untrusted key id".into()))?;
        if sig_bytes.len() != ED25519_SIGNATURE_BYTES {
            return Err(SignatureError::VerificationFailed(
                "bad signature length".into(),
            ));
        }
        UnparsedPublicKey::new(&ED25519, key)
            .verify(pae_bytes, sig_bytes)
            .map_err(|_| SignatureError::VerificationFailed("bad signature".into()))
    }
}
