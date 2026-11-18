//! dm-verity v1 table parsing, tree layout, and verification.
use crate::{Error, Result};
use sha2::{Digest, Sha256};

pub const BLOCK_BYTES: usize = 4096;
pub const DIGEST_BYTES: usize = 32;
pub const DIGESTS_PER_BLOCK: usize = BLOCK_BYTES / DIGEST_BYTES; // 128
pub const SALT_HEX_LEN: usize = 64;
pub const ROOT_HASH_HEX_LEN: usize = 64;
pub const MAX_VERITY_DATA_BLOCKS: u64 = 16 * 1024 * 1024; // 64 GiB max image
pub const MAX_VERITY_TABLE_BYTES: usize = 1024;
pub const MAX_LEVELS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerityTable {
    pub device_name: String,
    pub num_sectors: u64,
    pub data_device: String,
    pub hash_device: String,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub num_data_blocks: u64,
    pub hash_start_block: u64,
    pub algorithm: String,
    pub root_hash: String,
    pub salt: String,
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = match bytes[i] {
            b'0'..=b'9' => bytes[i] - b'0',
            b'a'..=b'f' => bytes[i] - b'a' + 10,
            _ => return None,
        };
        let lo = match bytes[i + 1] {
            b'0'..=b'9' => bytes[i + 1] - b'0',
            b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
            _ => return None,
        };
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

pub fn is_valid_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Computes the number of hash blocks and per-level block counts.
/// Matches Linux dm-verity v1 hash tree layout.
pub fn calculate_tree_layout(num_data_blocks: u64) -> Result<(u64, Vec<u64>)> {
    if num_data_blocks == 0 || num_data_blocks > MAX_VERITY_DATA_BLOCKS {
        return Err(Error::Validation("invalid verity data block count"));
    }
    if num_data_blocks == 1 {
        return Ok((0, Vec::new()));
    }
    let mut levels = Vec::new();
    let mut current = num_data_blocks.div_ceil(DIGESTS_PER_BLOCK as u64);
    levels.push(current);
    while current > 1 {
        if levels.len() >= MAX_LEVELS {
            return Err(Error::Validation("verity tree exceeds maximum levels"));
        }
        current = current.div_ceil(DIGESTS_PER_BLOCK as u64);
        levels.push(current);
    }
    let mut total: u64 = 0;
    for &lvl in &levels {
        total = total
            .checked_add(lvl)
            .ok_or(Error::Validation("verity hash blocks overflow"))?;
    }
    Ok((total, levels))
}

/// Parses a `dm-mod.create="..."` parameter or the enclosed table string.
pub fn parse_dm_create(arg: &str) -> Result<VerityTable> {
    if arg.len() > MAX_VERITY_TABLE_BYTES || arg.is_empty() {
        return Err(Error::Validation("verity dm-mod.create size cap"));
    }
    let s = if arg.starts_with("dm-mod.create=") {
        let remainder = arg
            .strip_prefix("dm-mod.create=")
            .ok_or(Error::Validation("dm-mod.create prefix"))?;
        if !remainder.starts_with('"') || !remainder.ends_with('"') || remainder.len() < 2 {
            return Err(Error::Validation("dm-mod.create quoted string required"));
        }
        &remainder[1..remainder.len() - 1]
    } else if arg.starts_with('"') && arg.ends_with('"') && arg.len() >= 2 {
        &arg[1..arg.len() - 1]
    } else {
        arg
    };

    let parts: Vec<&str> = s.splitn(5, ',').collect();
    if parts.len() != 5 {
        return Err(Error::Validation("invalid dm-mod.create header format"));
    }
    let device_name = parts[0];
    let minor = parts[2];
    let flags = parts[3];
    let table_str = parts[4];

    if device_name != "netvm" {
        return Err(Error::Validation("verity device name must be netvm"));
    }
    if !minor.is_empty() && minor != "0" {
        return Err(Error::Validation("verity device minor must be 0 or empty"));
    }
    if flags != "ro" {
        return Err(Error::Validation("verity device must be read-only (ro)"));
    }

    let tokens: Vec<&str> = table_str.split_ascii_whitespace().collect();
    if tokens.len() != 15 && tokens.len() != 13 {
        return Err(Error::Validation("invalid verity table token count"));
    }

    let start_sector = tokens[0]
        .parse::<u64>()
        .map_err(|_| Error::Validation("invalid start sector"))?;
    if start_sector != 0 {
        return Err(Error::Validation("verity start sector must be 0"));
    }

    let num_sectors = tokens[1]
        .parse::<u64>()
        .map_err(|_| Error::Validation("invalid num sectors"))?;

    let target_type = tokens[2];
    if target_type != "verity" {
        return Err(Error::Validation("target type must be verity"));
    }

    let version = tokens[3]
        .parse::<u32>()
        .map_err(|_| Error::Validation("invalid verity version"))?;
    if version != 1 {
        return Err(Error::Validation("verity version must be 1"));
    }

    let data_device = tokens[4];
    if data_device != "/dev/vda" {
        return Err(Error::Validation("verity data device must be /dev/vda"));
    }

    let hash_device = tokens[5];
    if hash_device != "/dev/vdb" {
        return Err(Error::Validation("verity hash device must be /dev/vdb"));
    }

    let data_block_size = tokens[6]
        .parse::<u32>()
        .map_err(|_| Error::Validation("invalid data block size"))?;
    if data_block_size != BLOCK_BYTES as u32 {
        return Err(Error::Validation("verity data block size must be 4096"));
    }

    let hash_block_size = tokens[7]
        .parse::<u32>()
        .map_err(|_| Error::Validation("invalid hash block size"))?;
    if hash_block_size != BLOCK_BYTES as u32 {
        return Err(Error::Validation("verity hash block size must be 4096"));
    }

    let num_data_blocks = tokens[8]
        .parse::<u64>()
        .map_err(|_| Error::Validation("invalid num data blocks"))?;
    if num_data_blocks == 0 || num_data_blocks > MAX_VERITY_DATA_BLOCKS {
        return Err(Error::Validation("verity num data blocks out of range"));
    }

    let expected_sectors = num_data_blocks
        .checked_mul(8)
        .ok_or(Error::Validation("sectors overflow"))?;
    if num_sectors != expected_sectors {
        return Err(Error::Validation("sectors must equal num_data_blocks * 8"));
    }

    let hash_start_block = tokens[9]
        .parse::<u64>()
        .map_err(|_| Error::Validation("invalid hash start block"))?;
    if hash_start_block != 0 {
        return Err(Error::Validation("verity hash start block must be 0"));
    }

    let algorithm = tokens[10];
    if algorithm != "sha256" {
        return Err(Error::Validation("verity algorithm must be sha256"));
    }

    let root_hash = tokens[11];
    if !is_valid_hex(root_hash, ROOT_HASH_HEX_LEN) {
        return Err(Error::Validation(
            "verity root hash must be 64 lowercase hex digits",
        ));
    }

    let salt = tokens[12];
    if !is_valid_hex(salt, SALT_HEX_LEN) {
        return Err(Error::Validation(
            "verity salt must be 64 lowercase hex digits",
        ));
    }

    if tokens.len() == 15 {
        if tokens[13] != "1" || tokens[14] != "restart_on_corruption" {
            return Err(Error::Validation(
                "verity optional parameter must be 1 restart_on_corruption",
            ));
        }
    } else if tokens.len() == 13 {
        // No optional parameters
    } else {
        return Err(Error::Validation("invalid verity table token count"));
    }

    Ok(VerityTable {
        device_name: device_name.to_string(),
        num_sectors,
        data_device: data_device.to_string(),
        hash_device: hash_device.to_string(),
        data_block_size,
        hash_block_size,
        num_data_blocks,
        hash_start_block,
        algorithm: algorithm.to_string(),
        root_hash: root_hash.to_string(),
        salt: salt.to_string(),
    })
}

/// Formats the `dm-mod.create="..."` parameter.
pub fn format_dm_create(
    device_name: &str,
    num_data_blocks: u64,
    root_hash: &str,
    salt: &str,
) -> Result<String> {
    if device_name != "netvm" {
        return Err(Error::Validation("device name must be netvm"));
    }
    if num_data_blocks == 0 || num_data_blocks > MAX_VERITY_DATA_BLOCKS {
        return Err(Error::Validation("num_data_blocks out of range"));
    }
    if !is_valid_hex(root_hash, ROOT_HASH_HEX_LEN) {
        return Err(Error::Validation("invalid root hash hex"));
    }
    if !is_valid_hex(salt, SALT_HEX_LEN) {
        return Err(Error::Validation("invalid salt hex"));
    }
    let sectors = num_data_blocks
        .checked_mul(8)
        .ok_or(Error::Validation("sectors overflow"))?;
    Ok(format!(
        "dm-mod.create=\"{device_name},,,ro,0 {sectors} verity 1 /dev/vda /dev/vdb 4096 4096 {num_data_blocks} 0 sha256 {root_hash} {salt} 1 restart_on_corruption\""
    ))
}

/// Validates that the root block matches the expected root hash when hashed with salt.
pub fn verify_root_block(
    root_block: &[u8],
    salt_hex: &str,
    expected_root_hash: &str,
) -> Result<()> {
    if root_block.len() != BLOCK_BYTES {
        return Err(Error::Validation("root block must be 4096 bytes"));
    }
    let salt = hex_decode(salt_hex).ok_or(Error::Validation("invalid salt hex"))?;
    let mut hasher = Sha256::new();
    hasher.update(&salt);
    hasher.update(root_block);
    let digest = hasher.finalize();
    let calculated_hash = hex_encode(&digest);
    if calculated_hash != expected_root_hash {
        return Err(Error::Validation("verity root hash mismatch"));
    }
    Ok(())
}

/// Pure Rust helper for computing dm-verity v1 Merkle tree (for offline testing).
pub fn compute_verity_tree(data: &[u8], salt_hex: &str) -> Result<(String, Vec<u8>)> {
    if data.is_empty() || !data.len().is_multiple_of(BLOCK_BYTES) {
        return Err(Error::Validation(
            "data must be non-empty multiple of 4096 bytes",
        ));
    }
    let num_data_blocks = (data.len() / BLOCK_BYTES) as u64;
    let salt = hex_decode(salt_hex).ok_or(Error::Validation("invalid salt hex"))?;
    if salt.len() != 32 {
        return Err(Error::Validation("salt must be 32 bytes"));
    }

    if num_data_blocks == 1 {
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        hasher.update(data);
        let digest = hasher.finalize();
        return Ok((hex_encode(&digest), Vec::new()));
    }

    let (total_blocks, levels) = calculate_tree_layout(num_data_blocks)?;
    let num_levels = levels.len();

    // Compute hashes level by level
    let mut tree_levels: Vec<Vec<u8>> = Vec::with_capacity(num_levels);

    // Level 0: hash of each data block
    let mut level0 = Vec::with_capacity(levels[0] as usize * BLOCK_BYTES);
    for chunk in data.as_chunks::<BLOCK_BYTES>().0 {
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        hasher.update(chunk);
        level0.extend_from_slice(&hasher.finalize());
    }
    // Zero-pad level0 to block boundary
    let rem0 = level0.len() % BLOCK_BYTES;
    if rem0 != 0 {
        level0.resize(level0.len() + (BLOCK_BYTES - rem0), 0);
    }
    tree_levels.push(level0);

    // Intermediate levels
    for lvl in 1..num_levels {
        let prev = &tree_levels[lvl - 1];
        let mut curr = Vec::with_capacity(levels[lvl] as usize * BLOCK_BYTES);
        for chunk in prev.as_chunks::<BLOCK_BYTES>().0 {
            let mut hasher = Sha256::new();
            hasher.update(&salt);
            hasher.update(chunk);
            curr.extend_from_slice(&hasher.finalize());
        }
        let rem = curr.len() % BLOCK_BYTES;
        if rem != 0 {
            curr.resize(curr.len() + (BLOCK_BYTES - rem), 0);
        }
        tree_levels.push(curr);
    }

    // Root block is the single block at tree_levels[num_levels - 1]
    let root_block = &tree_levels[num_levels - 1];
    let mut hasher = Sha256::new();
    hasher.update(&salt);
    hasher.update(root_block);
    let root_hash = hex_encode(&hasher.finalize());

    // In dm-verity v1 disk layout: root block is at block 0, down to level 0.
    let mut hash_image = Vec::with_capacity(total_blocks as usize * BLOCK_BYTES);
    for lvl in (0..num_levels).rev() {
        hash_image.extend_from_slice(&tree_levels[lvl]);
    }

    Ok((root_hash, hash_image))
}
