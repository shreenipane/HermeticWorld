use sha2::{Digest, Sha256};

/// Compute the lowercase hexadecimal SHA-256 hash of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("Hash chain head mismatch: expected {expected}, actual {actual}")]
    HeadMismatch { expected: String, actual: String },
}

/// A cryptographic hash chain where head(0) = 64 zeros, and
/// head(n) = sha256(head(n-1) || sha256(record)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashChain {
    head: [u8; 32],
}

impl Default for HashChain {
    fn default() -> Self {
        Self::new()
    }
}

impl HashChain {
    /// Create a new hash chain initialized with head(0) = 64 zeros.
    pub fn new() -> Self {
        Self { head: [0u8; 32] }
    }

    /// Return the raw 32-byte head.
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// Return the current head as a 64-character lowercase hexadecimal string.
    pub fn head_hex(&self) -> String {
        hex::encode(self.head)
    }

    /// Append a record to the chain and return the new head as a hex string.
    ///
    /// head(n) = sha256(head(n-1) || sha256(record))
    pub fn append(&mut self, record_bytes: &[u8]) -> String {
        let mut record_hasher = Sha256::new();
        record_hasher.update(record_bytes);
        let record_digest = record_hasher.finalize();

        let mut chain_hasher = Sha256::new();
        chain_hasher.update(self.head);
        chain_hasher.update(record_digest);
        self.head = chain_hasher.finalize().into();
        self.head_hex()
    }

    /// Verify that replaying `records` starting from head(0) produces `self.head`.
    pub fn verify<'a, I>(&self, records: I) -> Result<String, ChainError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut chain = HashChain::new();
        for r in records {
            chain.append(r);
        }
        if chain.head == self.head {
            Ok(chain.head_hex())
        } else {
            Err(ChainError::HeadMismatch {
                expected: self.head_hex(),
                actual: chain.head_hex(),
            })
        }
    }

    /// Verify that replaying `records` produces `expected_head`.
    pub fn verify_records<'a, I>(records: I, expected_head: &str) -> Result<String, ChainError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut chain = HashChain::new();
        for r in records {
            chain.append(r);
        }
        let computed = chain.head_hex();
        if computed.eq_ignore_ascii_case(expected_head) {
            Ok(computed)
        } else {
            Err(ChainError::HeadMismatch {
                expected: expected_head.to_string(),
                actual: computed,
            })
        }
    }
}
