#![forbid(unsafe_code)]

//! Sealed repository reader and reachability verifier.
//!
//! Provides bounded, no-follow access to bare Git repositories on disk (loose and pack v2),
//! enforcing that only objects reachable from the sealed base commit and its ancestors can
//! ever be served.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;

use super::types::{compute_sha1, is_hex_oid, GitError, GitObject, ObjectType};

/// Hard bound on the number of reachable commits traversed from base commit.
pub const MAX_REACHABLE_COMMITS: usize = 100_000;

/// Maximum delta recursion depth to prevent circular or pathological delta chains.
pub const MAX_DELTA_DEPTH: usize = 32;

/// Maximum size in bytes of a single decompressed Git object (64 MiB).
pub const MAX_OBJECT_SIZE: usize = 64 * 1024 * 1024;

/// Maximum number of refs loaded from a repository.
pub const MAX_REFS: usize = 10_000;

/// Maximum number of pack indexes opened per repository.
pub const MAX_PACK_INDEXES: usize = 64;

/// In-memory view of a Git pack index v2.
#[derive(Debug, Clone)]
pub struct PackIndex {
    pub pack_path: PathBuf,
    pub fanout: [u32; 256],
    pub oids: Vec<[u8; 20]>,
    pub offsets: Vec<u64>,
}

impl PackIndex {
    pub fn open(idx_path: &Path) -> Result<Self, GitError> {
        let mut f = File::open(idx_path)?;
        let mut magic = [0u8; 4];
        f.read_exact(&mut magic)?;
        if &magic != b"\xfftOc" {
            return Err(GitError::Unsupported("pack idx v1 unsupported".into()));
        }

        let mut ver_buf = [0u8; 4];
        f.read_exact(&mut ver_buf)?;
        let version = u32::from_be_bytes(ver_buf);
        if version != 2 {
            return Err(GitError::Unsupported(format!("pack idx v{version} unsupported")));
        }

        let mut fanout = [0u32; 256];
        let mut buf4 = [0u8; 4];
        let mut prev = 0u32;
        for (i, entry) in fanout.iter_mut().enumerate() {
            f.read_exact(&mut buf4)?;
            let count = u32::from_be_bytes(buf4);
            if i > 0 && count < prev {
                return Err(GitError::Corrupt("idx fanout not monotonic".into()));
            }
            prev = count;
            *entry = count;
        }

        let total_objects = fanout[255] as usize;
        let mut oids = Vec::with_capacity(total_objects);
        let mut oid_buf = [0u8; 20];
        for _ in 0..total_objects {
            f.read_exact(&mut oid_buf)?;
            oids.push(oid_buf);
        }

        // Skip CRC32 table (total_objects * 4 bytes)
        f.seek(SeekFrom::Current((total_objects as i64) * 4))?;

        // 32-bit offsets
        let mut raw_offsets = Vec::with_capacity(total_objects);
        for _ in 0..total_objects {
            f.read_exact(&mut buf4)?;
            raw_offsets.push(u32::from_be_bytes(buf4));
        }

        // 64-bit large offsets table if any
        let mut large_indices = Vec::new();
        for (i, &off) in raw_offsets.iter().enumerate() {
            if off & 0x8000_0000 != 0 {
                let idx = (off & 0x7fff_ffff) as usize;
                large_indices.push((i, idx));
            }
        }

        let mut large_offsets = Vec::new();
        if !large_indices.is_empty() {
            let max_idx = large_indices.iter().map(|(_, idx)| *idx).max().unwrap_or(0);
            let mut buf8 = [0u8; 8];
            for _ in 0..=max_idx {
                f.read_exact(&mut buf8)?;
                large_offsets.push(u64::from_be_bytes(buf8));
            }
        }

        let mut offsets = Vec::with_capacity(total_objects);
        for off in raw_offsets {
            if off & 0x8000_0000 == 0 {
                offsets.push(off as u64);
            } else {
                let idx = (off & 0x7fff_ffff) as usize;
                let large_off = large_offsets
                    .get(idx)
                    .copied()
                    .ok_or_else(|| GitError::Corrupt("large offset index out of range".into()))?;
                offsets.push(large_off);
            }
        }

        let pack_path = idx_path.with_extension("pack");
        if !pack_path.exists() {
            return Err(GitError::NotFound(format!(
                "missing pack file for idx {}",
                idx_path.display()
            )));
        }

        Ok(Self {
            pack_path,
            fanout,
            oids,
            offsets,
        })
    }

    pub fn find_object(&self, oid_bytes: &[u8; 20]) -> Option<u64> {
        let first_byte = oid_bytes[0] as usize;
        let low = if first_byte == 0 {
            0
        } else {
            self.fanout[first_byte - 1] as usize
        };
        let high = self.fanout[first_byte] as usize;

        if low >= high || high > self.oids.len() {
            return None;
        }

        match self.oids[low..high].binary_search(oid_bytes) {
            Ok(idx) => Some(self.offsets[low + idx]),
            Err(_) => None,
        }
    }
}

/// A sealed repository binding holding verified reachable objects.
pub struct SealedRepoBinding {
    pub authority: String,
    pub path: String,
    pub base_commit: String,
    pub repo_dir: PathBuf,
    pub refs: BTreeMap<String, String>,
    pub head_symref: Option<String>,
    pub reachable_commits: BTreeSet<String>,
    packs: Vec<PackIndex>,
}

impl SealedRepoBinding {
    /// Opens and validates a bare Git repository against `base_commit`.
    pub fn open(
        authority: &str,
        path: &str,
        repo_dir: &Path,
        base_commit: Option<&str>,
    ) -> Result<Self, GitError> {
        let normalized_path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };

        if !repo_dir.is_dir() {
            return Err(GitError::NotFound(format!(
                "repository directory not found: {}",
                repo_dir.display()
            )));
        }

        // 1. Read pack indexes
        let pack_dir = repo_dir.join("objects").join("pack");
        let mut packs = Vec::new();
        if pack_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&pack_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() && p.extension().is_some_and(|e| e == "idx") {
                        if packs.len() >= MAX_PACK_INDEXES {
                            return Err(GitError::LimitExceeded("too many pack indexes".into()));
                        }
                        packs.push(PackIndex::open(&p)?);
                    }
                }
            }
        }

        // 2. Read refs (HEAD, packed-refs, loose refs)
        let mut refs = BTreeMap::new();
        let mut head_symref = None;

        let head_path = repo_dir.join("HEAD");
        if head_path.is_file() {
            let mut head_content = String::new();
            File::open(&head_path)?.take(512).read_to_string(&mut head_content)?;
            let trimmed = head_content.trim();
            if let Some(target) = trimmed.strip_prefix("ref: ") {
                head_symref = Some(target.trim().to_string());
            } else if is_hex_oid(trimmed) {
                refs.insert("HEAD".to_string(), trimmed.to_string());
            }
        }

        let packed_refs_path = repo_dir.join("packed-refs");
        if packed_refs_path.is_file() {
            let mut content = String::new();
            File::open(&packed_refs_path)?
                .take(16 * 1024 * 1024)
                .read_to_string(&mut content)?;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('^') {
                    continue;
                }
                if let Some((oid, refname)) = trimmed.split_once(' ') {
                    if is_hex_oid(oid) && refs.len() < MAX_REFS {
                        refs.insert(refname.to_string(), oid.to_string());
                    }
                }
            }
        }

        // Read loose refs in refs/heads and refs/tags
        load_loose_refs(&repo_dir.join("refs"), "refs", &mut refs)?;

        // If HEAD was a symref, resolve it
        if let Some(ref target) = head_symref {
            if let Some(oid) = refs.get(target) {
                refs.insert("HEAD".to_string(), oid.clone());
            }
        }

        // 3. Determine base commit
        let base_sha = match base_commit {
            Some(b) => {
                if !is_hex_oid(b) {
                    return Err(GitError::Corrupt(format!("invalid base commit format: {b}")));
                }
                b.to_string()
            }
            None => {
                // Default to HEAD commit
                refs.get("HEAD")
                    .cloned()
                    .ok_or_else(|| GitError::NotFound("no HEAD ref found to derive base commit".into()))?
            }
        };

        let mut binding = Self {
            authority: authority.to_ascii_lowercase(),
            path: normalized_path,
            base_commit: base_sha.clone(),
            repo_dir: repo_dir.to_path_buf(),
            refs,
            head_symref,
            reachable_commits: BTreeSet::new(),
            packs,
        };

        // 4. Compute reachability from base_commit
        binding.compute_reachability(&base_sha)?;

        // 5. Filter refs to only those pointing at ancestors of base_commit (TR-SEAL-2)
        binding.refs.retain(|_, oid| binding.reachable_commits.contains(oid));

        Ok(binding)
    }

    /// BFS from `start_commit` through parents to compute the exact reachable commit set.
    fn compute_reachability(&mut self, start_commit: &str) -> Result<(), GitError> {
        let mut queue = VecDeque::new();
        queue.push_back(start_commit.to_string());
        self.reachable_commits.insert(start_commit.to_string());

        while let Some(current_sha) = queue.pop_front() {
            let obj = self.read_object_internal(&current_sha, 0)?;
            if obj.obj_type != ObjectType::Commit {
                return Err(GitError::Corrupt(format!(
                    "object {current_sha} is {}, expected commit",
                    obj.obj_type.as_str()
                )));
            }

            let parents = parse_commit_parents(&obj.data);
            for parent in parents {
                if self.reachable_commits.insert(parent.clone()) {
                    if self.reachable_commits.len() > MAX_REACHABLE_COMMITS {
                        return Err(GitError::LimitExceeded(
                            "reachable commit count exceeds maximum allowed".into(),
                        ));
                    }
                    queue.push_back(parent);
                }
            }
        }

        Ok(())
    }

    /// Verifies if a given commit OID is reachable from the sealed base commit.
    pub fn is_reachable_commit(&self, oid: &str) -> bool {
        self.reachable_commits.contains(oid)
    }

    /// Reads a Git object from the repository by 40-hex OID.
    pub fn read_object(&self, oid: &str) -> Result<GitObject, GitError> {
        self.read_object_internal(oid, 0)
    }

    fn read_object_internal(&self, oid: &str, depth: usize) -> Result<GitObject, GitError> {
        if depth > MAX_DELTA_DEPTH {
            return Err(GitError::LimitExceeded("delta recursion depth exceeded".into()));
        }
        if !is_hex_oid(oid) {
            return Err(GitError::NotFound(format!("invalid hex oid: {oid}")));
        }

        // Check loose object
        let (dir_part, file_part) = oid.split_at(2);
        let loose_path = self.repo_dir.join("objects").join(dir_part).join(file_part);
        if loose_path.is_file() {
            let mut f = File::open(&loose_path)?;
            let mut decoder = ZlibDecoder::new(f);
            let mut decompressed = Vec::new();
            decoder
                .take(MAX_OBJECT_SIZE as u64 + 1)
                .read_to_end(&mut decompressed)?;
            if decompressed.len() > MAX_OBJECT_SIZE {
                return Err(GitError::LimitExceeded("loose object exceeds size limit".into()));
            }

            let nul_pos = decompressed
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| GitError::Corrupt("missing null separator in loose object".into()))?;
            let header_str = std::str::from_utf8(&decompressed[..nul_pos])
                .map_err(|_| GitError::Corrupt("non-utf8 object header".into()))?;
            let (type_str, _size_str) = header_str
                .split_once(' ')
                .ok_or_else(|| GitError::Corrupt("malformed loose object header".into()))?;

            let obj_type = match type_str {
                "commit" => ObjectType::Commit,
                "tree" => ObjectType::Tree,
                "blob" => ObjectType::Blob,
                "tag" => ObjectType::Tag,
                other => return Err(GitError::Corrupt(format!("unknown object type {other}"))),
            };

            let data = decompressed[nul_pos + 1..].to_vec();
            let computed = compute_sha1(obj_type, &data);
            if !computed.eq_ignore_ascii_case(oid) {
                return Err(GitError::Corrupt(format!(
                    "sha1 mismatch for loose object: expected {oid}, got {computed}"
                )));
            }

            return Ok(GitObject { obj_type, data });
        }

        // Check pack files
        let mut oid_bytes = [0u8; 20];
        hex::decode_to_slice(oid, &mut oid_bytes)
            .map_err(|_| GitError::NotFound("invalid hex".into()))?;

        for pack in &self.packs {
            if let Some(offset) = pack.find_object(&oid_bytes) {
                return self.read_pack_object(&pack.pack_path, offset, depth);
            }
        }

        Err(GitError::NotFound(format!("object {oid} not found")))
    }

    fn read_pack_object(
        &self,
        pack_path: &Path,
        offset: u64,
        depth: usize,
    ) -> Result<GitObject, GitError> {
        let mut f = File::open(pack_path)?;
        f.seek(SeekFrom::Start(offset))?;

        // Read varint header
        let mut byte = [0u8; 1];
        f.read_exact(&mut byte)?;
        let mut b = byte[0];
        let raw_type = (b >> 4) & 0x07;
        let mut size = (b & 0x0f) as usize;
        let mut shift = 4;

        while (b & 0x80) != 0 {
            f.read_exact(&mut byte)?;
            b = byte[0];
            size |= ((b & 0x7f) as usize) << shift;
            shift += 7;
            if shift > 64 {
                return Err(GitError::Corrupt("pack varint size overflow".into()));
            }
        }

        if size > MAX_OBJECT_SIZE {
            return Err(GitError::LimitExceeded("packed object exceeds size limit".into()));
        }

        match raw_type {
            1 | 2 | 3 | 4 => {
                let obj_type = ObjectType::from_u8(raw_type)
                    .ok_or_else(|| GitError::Corrupt("invalid object type".into()))?;
                let mut decoder = ZlibDecoder::new(f);
                let mut data = Vec::with_capacity(size);
                decoder
                    .take(size as u64 + 1)
                    .read_to_end(&mut data)?;
                if data.len() != size {
                    return Err(GitError::Corrupt("decompressed size mismatch".into()));
                }
                Ok(GitObject { obj_type, data })
            }
            6 => {
                // OBJ_OFS_DELTA
                f.read_exact(&mut byte)?;
                let mut b = byte[0];
                let mut delta_offset = (b & 0x7f) as u64;
                while (b & 0x80) != 0 {
                    f.read_exact(&mut byte)?;
                    b = byte[0];
                    delta_offset = (delta_offset + 1)
                        .checked_shl(7)
                        .ok_or_else(|| GitError::Corrupt("delta offset overflow".into()))?
                        | ((b & 0x7f) as u64);
                }
                let base_offset = offset
                    .checked_sub(delta_offset)
                    .ok_or_else(|| GitError::Corrupt("underflow in base offset".into()))?;

                let base_obj = self.read_pack_object(pack_path, base_offset, depth + 1)?;

                let mut decoder = ZlibDecoder::new(f);
                let mut delta_data = Vec::new();
                decoder
                    .take(MAX_OBJECT_SIZE as u64 + 1)
                    .read_to_end(&mut delta_data)?;
                let resolved = apply_delta(&base_obj.data, &delta_data)?;
                Ok(GitObject {
                    obj_type: base_obj.obj_type,
                    data: resolved,
                })
            }
            7 => {
                // OBJ_REF_DELTA
                let mut base_oid_bytes = [0u8; 20];
                f.read_exact(&mut base_oid_bytes)?;
                let base_oid = hex::encode(base_oid_bytes);

                let base_obj = self.read_object_internal(&base_oid, depth + 1)?;

                let mut decoder = ZlibDecoder::new(f);
                let mut delta_data = Vec::new();
                decoder
                    .take(MAX_OBJECT_SIZE as u64 + 1)
                    .read_to_end(&mut delta_data)?;
                let resolved = apply_delta(&base_obj.data, &delta_data)?;
                Ok(GitObject {
                    obj_type: base_obj.obj_type,
                    data: resolved,
                })
            }
            other => Err(GitError::Corrupt(format!("unsupported pack object type {other}"))),
        }
    }
}

/// Recursively loads loose refs from a refs directory.
fn load_loose_refs(dir: &Path, prefix: &str, out: &mut BTreeMap<String, String>) -> Result<(), GitError> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let refname = format!("{prefix}/{name}");
        if p.is_dir() {
            load_loose_refs(&p, &refname, out)?;
        } else if p.is_file() {
            let mut content = String::new();
            if File::open(&p)?
                .take(128)
                .read_to_string(&mut content)
                .is_ok()
            {
                let trimmed = content.trim();
                if is_hex_oid(trimmed) && out.len() < MAX_REFS {
                    out.insert(refname, trimmed.to_string());
                }
            }
        }
    }
    Ok(())
}

/// Extracts all parent OIDs from raw commit object data.
pub fn parse_commit_parents(data: &[u8]) -> Vec<String> {
    let mut parents = Vec::new();
    let text = String::from_utf8_lossy(data);
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(parent) = line.strip_prefix("parent ") {
            let p = parent.trim();
            if is_hex_oid(p) {
                parents.push(p.to_string());
            }
        }
    }
    parents
}

/// Extracts the root tree OID from raw commit object data.
pub fn parse_commit_tree(data: &[u8]) -> Result<String, GitError> {
    let text = String::from_utf8_lossy(data);
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(tree) = line.strip_prefix("tree ") {
            let t = tree.trim();
            if is_hex_oid(t) {
                return Ok(t.to_string());
            }
        }
    }
    Err(GitError::Corrupt("missing tree line in commit".into()))
}

/// A parsed entry from a Git tree object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: u32,
    pub name: String,
    pub oid: String,
    pub is_tree: bool,
}

/// Parses all entries from a raw Git tree object.
pub fn parse_tree_entries(data: &[u8]) -> Result<Vec<TreeEntry>, GitError> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    while pos < data.len() {
        let space_pos = data[pos..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| GitError::Corrupt("malformed tree entry: missing space".into()))?;
        let mode_str = std::str::from_utf8(&data[pos..pos + space_pos])
            .map_err(|_| GitError::Corrupt("non-ascii tree entry mode".into()))?;
        let mode = u32::from_str_radix(mode_str, 8)
            .map_err(|_| GitError::Corrupt("invalid octal mode in tree entry".into()))?;
        pos += space_pos + 1;

        let nul_pos = data[pos..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| GitError::Corrupt("malformed tree entry: missing null".into()))?;
        let name = std::str::from_utf8(&data[pos..pos + nul_pos])
            .map_err(|_| GitError::Corrupt("non-utf8 tree entry name".into()))?
            .to_string();
        pos += nul_pos + 1;

        if pos + 20 > data.len() {
            return Err(GitError::Corrupt("truncated tree entry oid".into()));
        }
        let oid = hex::encode(&data[pos..pos + 20]);
        pos += 20;

        let is_tree = (mode & 0o170000) == 0o040000;
        entries.push(TreeEntry {
            mode,
            name,
            oid,
            is_tree,
        });
    }

    Ok(entries)
}

/// Applies a Git delta stream to a base object payload.
fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, GitError> {
    let mut pos = 0usize;

    // Read base size
    let mut base_size = 0usize;
    let mut shift = 0;
    loop {
        if pos >= delta.len() {
            return Err(GitError::Corrupt("truncated delta header".into()));
        }
        let b = delta[pos];
        pos += 1;
        base_size |= ((b & 0x7f) as usize) << shift;
        shift += 7;
        if (b & 0x80) == 0 {
            break;
        }
    }
    if base_size != base.len() {
        return Err(GitError::Corrupt("delta base size mismatch".into()));
    }

    // Read target size
    let mut target_size = 0usize;
    shift = 0;
    loop {
        if pos >= delta.len() {
            return Err(GitError::Corrupt("truncated delta target size".into()));
        }
        let b = delta[pos];
        pos += 1;
        target_size |= ((b & 0x7f) as usize) << shift;
        shift += 7;
        if (b & 0x80) == 0 {
            break;
        }
    }

    if target_size > MAX_OBJECT_SIZE {
        return Err(GitError::LimitExceeded("delta target size exceeds limit".into()));
    }

    let mut out = Vec::with_capacity(target_size);

    while pos < delta.len() {
        let op = delta[pos];
        pos += 1;

        if (op & 0x80) != 0 {
            // Copy from base
            let mut cp_off = 0usize;
            let mut cp_len = 0usize;

            if (op & 0x01) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated delta copy offset".into()));
                }
                cp_off |= delta[pos] as usize;
                pos += 1;
            }
            if (op & 0x02) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated delta copy offset".into()));
                }
                cp_off |= (delta[pos] as usize) << 8;
                pos += 1;
            }
            if (op & 0x04) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated delta copy offset".into()));
                }
                cp_off |= (delta[pos] as usize) << 16;
                pos += 1;
            }
            if (op & 0x08) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated delta copy offset".into()));
                }
                cp_off |= (delta[pos] as usize) << 24;
                pos += 1;
            }

            if (op & 0x10) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated delta copy len".into()));
                }
                cp_len |= delta[pos] as usize;
                pos += 1;
            }
            if (op & 0x20) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated delta copy len".into()));
                }
                cp_len |= (delta[pos] as usize) << 8;
                pos += 1;
            }
            if (op & 0x40) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated delta copy len".into()));
                }
                cp_len |= (delta[pos] as usize) << 16;
                pos += 1;
            }

            if cp_len == 0 {
                cp_len = 0x10000;
            }

            let cp_end = cp_off
                .checked_add(cp_len)
                .ok_or_else(|| GitError::Corrupt("delta copy range overflow".into()))?;
            if cp_end > base.len() {
                return Err(GitError::Corrupt("delta copy range beyond base size".into()));
            }

            out.extend_from_slice(&base[cp_off..cp_end]);
        } else if op != 0 {
            // Insert from delta
            let ins_len = op as usize;
            if pos + ins_len > delta.len() {
                return Err(GitError::Corrupt("truncated delta insert data".into()));
            }
            out.extend_from_slice(&delta[pos..pos + ins_len]);
            pos += ins_len;
        } else {
            return Err(GitError::Corrupt("invalid zero opcode in delta".into()));
        }
    }

    if out.len() != target_size {
        return Err(GitError::Corrupt("applied delta output size mismatch".into()));
    }

    Ok(out)
}
