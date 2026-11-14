//! Verify patched executables through the same descriptors used for execution.
use crate::{remaining, Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::time::Instant;

pub const MAX_BUILD_LOCK_BYTES: u64 = 16_384;
pub const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const HASH_CHUNK_BYTES: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPin {
    schema: String,
    version: String,
    source_sha256: String,
    patch_sha256: String,
    builder_image: String,
    target: String,
    rust: String,
    firecracker_sha256: String,
    jailer_sha256: String,
}
fn hash_text(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl BuildPin {
    pub fn read(reader: impl Read) -> Result<Self> {
        let mut bytes = Vec::new();
        reader
            .take(MAX_BUILD_LOCK_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BUILD_LOCK_BYTES {
            return Err(Error::Validation("Firecracker build lock cap"));
        }
        let pin: Self = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Validation("Firecracker build lock schema"))?;
        let patch = format!(
            "{:x}",
            Sha256::digest(include_bytes!(
                "../../../vmm/firecracker-patches/0001-host-pv-clock-filter.patch"
            ))
        );
        if pin.schema != "hermetic-firecracker-build/v1"
            || pin.version != "1.18.0"
            || pin.source_sha256
                != "89f02fe6867edcf0a0154305d5533a611e48eaa99ba11d24aa2f076492bef615"
            || pin.patch_sha256 != patch
            || pin.target != "x86_64-unknown-linux-musl"
            || pin.rust != "1.97.0"
            || !pin
                .builder_image
                .strip_prefix("sha256:")
                .is_some_and(hash_text)
            || !hash_text(&pin.firecracker_sha256)
            || !hash_text(&pin.jailer_sha256)
        {
            return Err(Error::Validation("Firecracker build provenance"));
        }
        Ok(pin)
    }
    pub fn configured() -> Result<Self> {
        let path = std::env::var("HERMETIC_FIRECRACKER_LOCK")
            .map_err(|_| Error::Validation("HERMETIC_FIRECRACKER_LOCK required for patched VMM"))?;
        Self::read(crate::fs::open_image(&path)?)
    }
    pub fn verify(&self, binary: &File, jailer: bool, end: Instant) -> Result<()> {
        let expected = if jailer {
            &self.jailer_sha256
        } else {
            &self.firecracker_sha256
        };
        let mut hash = Sha256::new();
        let mut offset = 0u64;
        let mut buffer = [0u8; HASH_CHUNK_BYTES];
        loop {
            remaining(end, "verify executable")?;
            let n = binary.read_at(&mut buffer, offset)?;
            if n == 0 {
                break;
            }
            offset = offset.checked_add(n as u64).ok_or(Error::Io)?;
            if offset > MAX_EXECUTABLE_BYTES {
                return Err(Error::Validation("executable size cap"));
            }
            hash.update(buffer.get(..n).ok_or(Error::Io)?);
        }
        if offset == 0 || format!("{:x}", hash.finalize()) != *expected {
            return Err(Error::Validation("patched executable hash mismatch"));
        }
        Ok(())
    }
}
