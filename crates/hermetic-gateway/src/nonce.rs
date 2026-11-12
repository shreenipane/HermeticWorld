#![forbid(unsafe_code)]

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunNonce {
    hex: String,
}

impl RunNonce {
    /// Generate a fresh 128-bit random nonce using system entropy (getrandom).
    /// Never derived from time.
    pub fn generate() -> Result<Self, String> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|e| format!("Failed to generate random nonce: {e}"))?;
        let hex = hex::encode(bytes);
        Ok(Self { hex })
    }

    /// Create from a known hex string (useful for testing).
    pub fn from_hex(hex: String) -> Self {
        Self { hex }
    }

    /// Lowercase 32-character hexadecimal representation.
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// The prefix text to prepend to the system prompt: `"[run-nonce <hex>]\n"`.
    pub fn system_prefix(&self) -> String {
        format!("[run-nonce {}]\n", self.hex)
    }
}

impl fmt::Display for RunNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex)
    }
}
