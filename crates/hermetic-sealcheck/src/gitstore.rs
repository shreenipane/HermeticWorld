use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};

use crate::containers::CountingReader;
use crate::scan::ScanOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectType::Commit => "commit",
            ObjectType::Tree => "tree",
            ObjectType::Blob => "blob",
            ObjectType::Tag => "tag",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitObject {
    pub obj_type: ObjectType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub tree: String,
    pub parents: Vec<String>,
    pub committer_time: Option<i64>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: u32,
    pub name: String,
    pub oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub target_oid: String,
    pub target_type: ObjectType,
    pub tag_name: String,
    pub tagger_time: Option<i64>,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Corrupt git store: {0}")]
    Corrupt(String),
    #[error("Unsupported git feature: {0}")]
    Unsupported(String),
    #[error("Object not found: {0}")]
    NotFound(String),
    #[error("Limit exceeded: {0}")]
    LimitExceeded(String),
}

/// Ids come from parsed object text, so check them before slicing by byte index.
pub fn is_hex_oid(oid: &str) -> bool {
    oid.len() == 40 && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn compute_git_sha1(obj_type: ObjectType, data: &[u8]) -> String {
    let header = format!("{} {}\0", obj_type.as_str(), data.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub struct PackIndex {
    pub idx_path: PathBuf,
    pub pack_path: PathBuf,
    pub fanout: [u32; 256],
    pub oids: Vec<[u8; 20]>,
    pub offsets: Vec<u64>,
}

/// Blobs decoded (offset, bytes), whether a delta base was missing, and the error that
/// stopped decoding, if any. Blobs decoded before an error are still returned for scanning.
pub type StrayPackResult = (Vec<(u64, Vec<u8>)>, bool, Option<GitError>);

impl PackIndex {
    pub fn open(idx_path: &Path) -> Result<Self, GitError> {
        let mut f = File::open(idx_path)?;
        let mut magic = [0u8; 4];
        if f.read_exact(&mut magic).is_err() {
            return Err(GitError::Corrupt("truncated pack idx".into()));
        }
        if &magic != b"\xfftOc" {
            return Err(GitError::Unsupported("pack idx v1".into()));
        }

        let mut ver_buf = [0u8; 4];
        if f.read_exact(&mut ver_buf).is_err() {
            return Err(GitError::Corrupt("truncated pack idx version".into()));
        }
        let version = u32::from_be_bytes(ver_buf);
        if version != 2 {
            return Err(GitError::Unsupported(format!(
                "unsupported pack idx version {}",
                version
            )));
        }

        let mut fanout = [0u32; 256];
        let mut buf4 = [0u8; 4];
        let mut prev = 0u32;
        for (i, entry) in fanout.iter_mut().enumerate() {
            if f.read_exact(&mut buf4).is_err() {
                return Err(GitError::Corrupt("truncated pack idx fanout".into()));
            }
            let count = u32::from_be_bytes(buf4);
            if i > 0 && count < prev {
                return Err(GitError::Corrupt("idx fanout not monotonic".into()));
            }
            prev = count;
            *entry = count;
        }

        // The count comes from the file: check it against the file's size before allocating.
        let total_objects = fanout[255] as usize;
        let min_len = 8 + 256 * 4 + (total_objects as u64) * (20 + 4 + 4) + 40;
        if f.metadata()?.len() < min_len {
            return Err(GitError::Corrupt(
                "pack idx shorter than its object count".into(),
            ));
        }
        let mut oids = Vec::with_capacity(total_objects);
        let mut oid_buf = [0u8; 20];
        for _ in 0..total_objects {
            if f.read_exact(&mut oid_buf).is_err() {
                return Err(GitError::Corrupt("truncated pack idx oids".into()));
            }
            oids.push(oid_buf);
        }

        // Skip CRC32 table (total_objects * 4 bytes)
        f.seek(SeekFrom::Current((total_objects as i64) * 4))?;

        // 32-bit offsets table
        let mut raw_offsets = Vec::with_capacity(total_objects);
        for _ in 0..total_objects {
            if f.read_exact(&mut buf4).is_err() {
                return Err(GitError::Corrupt("truncated pack idx offsets".into()));
            }
            raw_offsets.push(u32::from_be_bytes(buf4));
        }

        // Read 8-byte offsets table if needed
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
                if f.read_exact(&mut buf8).is_err() {
                    return Err(GitError::Corrupt("truncated pack idx large offsets".into()));
                }
                large_offsets.push(u64::from_be_bytes(buf8));
            }
        }

        let mut offsets = Vec::with_capacity(total_objects);
        for off in raw_offsets {
            if off & 0x8000_0000 == 0 {
                offsets.push(off as u64);
            } else {
                let idx = (off & 0x7fff_ffff) as usize;
                if idx >= large_offsets.len() {
                    return Err(GitError::Corrupt(
                        "invalid large offset index in idx".into(),
                    ));
                }
                offsets.push(large_offsets[idx]);
            }
        }

        let pack_path = idx_path.with_extension("pack");
        if !pack_path.exists() {
            return Err(GitError::Corrupt(format!(
                "missing pack file for {}",
                idx_path.display()
            )));
        }

        let pack_len = pack_path.metadata()?.len();
        if pack_len < 32 {
            return Err(GitError::Corrupt("truncated pack".into()));
        }

        let mut pack_f = File::open(&pack_path)?;
        let mut pack_magic = [0u8; 4];
        if pack_f.read_exact(&mut pack_magic).is_err() || &pack_magic != b"PACK" {
            return Err(GitError::Corrupt(
                "truncated pack or invalid pack magic".into(),
            ));
        }
        let mut ver_bytes = [0u8; 4];
        if pack_f.read_exact(&mut ver_bytes).is_err() {
            return Err(GitError::Corrupt("truncated pack".into()));
        }
        let pack_ver = u32::from_be_bytes(ver_bytes);
        if pack_ver != 2 && pack_ver != 3 {
            return Err(GitError::Unsupported(format!(
                "unsupported pack version {}",
                pack_ver
            )));
        }

        let mut count_bytes = [0u8; 4];
        if pack_f.read_exact(&mut count_bytes).is_err() {
            return Err(GitError::Corrupt("truncated pack".into()));
        }
        if u32::from_be_bytes(count_bytes) != fanout[255] {
            return Err(GitError::Corrupt(
                "pack object count differs from its idx".into(),
            ));
        }

        for &offset in &offsets {
            if offset >= pack_len {
                return Err(GitError::Corrupt("idx offset beyond the pack".into()));
            }
        }

        Ok(Self {
            idx_path: idx_path.to_path_buf(),
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

pub struct DeltaBaseCache {
    max_bytes: usize,
    current_bytes: usize,
    entries: HashMap<String, (ObjectType, Vec<u8>)>,
    lru: VecDeque<String>,
}

impl DeltaBaseCache {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            current_bytes: 0,
            entries: HashMap::new(),
            lru: VecDeque::new(),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<(ObjectType, Vec<u8>)> {
        self.entries.get(key).cloned()
    }

    pub fn insert(&mut self, key: String, obj_type: ObjectType, data: Vec<u8>) {
        let data_len = data.len();
        if data_len > self.max_bytes || self.entries.contains_key(&key) {
            return;
        }

        while self.current_bytes + data_len > self.max_bytes && !self.lru.is_empty() {
            if let Some(evict_key) = self.lru.pop_front() {
                if let Some((_, evicted)) = self.entries.remove(&evict_key) {
                    self.current_bytes = self.current_bytes.saturating_sub(evicted.len());
                }
            }
        }

        self.current_bytes += data_len;
        self.entries.insert(key.clone(), (obj_type, data));
        self.lru.push_back(key);
    }
}

pub struct GitStore {
    git_dir: PathBuf,
    objects_dir: PathBuf,
    packs: Vec<PackIndex>,
    cache: DeltaBaseCache,
    max_member_bytes: u64,
    max_depth: usize,
}

impl GitStore {
    pub fn open(git_dir: &Path, opts: &ScanOptions) -> Result<Self, GitError> {
        let objects_dir = git_dir.join("objects");
        let pack_dir = objects_dir.join("pack");
        let mut packs = Vec::new();

        if pack_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&pack_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && path.extension().is_some_and(|ext| ext == "idx") {
                        packs.push(PackIndex::open(&path)?);
                    }
                }
            }
        }

        Ok(Self {
            git_dir: git_dir.to_path_buf(),
            objects_dir,
            packs,
            cache: DeltaBaseCache::new(64 * 1024 * 1024), // 64 MiB
            max_member_bytes: opts.max_member_bytes,
            max_depth: opts.max_delta_depth,
        })
    }

    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    pub fn enumerate_object_ids(&self) -> Result<HashSet<String>, GitError> {
        let mut ids = HashSet::new();

        // 1. Loose objects: objects/[0-9a-f]{2}/[0-9a-f]{38}
        if self.objects_dir.is_dir() {
            for entry in std::fs::read_dir(&self.objects_dir)?.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let dir_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                    if dir_name.len() == 2 && dir_name.chars().all(|c| c.is_ascii_hexdigit()) {
                        for sub_entry in std::fs::read_dir(&path)?.flatten() {
                            let sub_path = sub_entry.path();
                            if sub_path.is_file() {
                                let file_name =
                                    sub_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                                if file_name.len() == 38
                                    && file_name.chars().all(|c| c.is_ascii_hexdigit())
                                {
                                    ids.insert(format!("{}{}", dir_name, file_name).to_lowercase());
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Packed objects
        for pack in &self.packs {
            for oid_bytes in &pack.oids {
                ids.insert(hex::encode(oid_bytes));
            }
        }

        Ok(ids)
    }

    pub fn read_object(&mut self, oid: &str) -> Result<GitObject, GitError> {
        if !is_hex_oid(oid) {
            return Err(GitError::Corrupt(format!("invalid oid: {}", oid)));
        }

        if let Some((obj_type, data)) = self.cache.get(oid) {
            return Ok(GitObject { obj_type, data });
        }

        // 1. Try loose object
        let (dir_part, file_part) = oid.split_at(2);
        let loose_path = self.objects_dir.join(dir_part).join(file_part);
        if loose_path.is_file() {
            let obj = self.read_loose_object(&loose_path)?;
            self.cache
                .insert(oid.to_string(), obj.obj_type, obj.data.clone());
            return Ok(obj);
        }

        // 2. Try packs
        let oid_bytes = hex::decode(oid)
            .map_err(|_| GitError::Corrupt(format!("hex decode error for oid {}", oid)))?;
        let mut oid_arr = [0u8; 20];
        oid_arr.copy_from_slice(&oid_bytes);

        for pack_idx in 0..self.packs.len() {
            if let Some(offset) = self.packs[pack_idx].find_object(&oid_arr) {
                let mut visited_offsets = HashSet::new();
                let mut visited_oids = HashSet::new();
                visited_oids.insert(oid.to_string());
                let obj = self.read_packed_object(
                    pack_idx,
                    offset,
                    0,
                    &mut visited_offsets,
                    &mut visited_oids,
                )?;
                self.cache
                    .insert(oid.to_string(), obj.obj_type, obj.data.clone());
                return Ok(obj);
            }
        }

        Err(GitError::NotFound(format!("object {} not found", oid)))
    }

    fn read_loose_object(&self, path: &Path) -> Result<GitObject, GitError> {
        let f = File::open(path)?;
        let mut total_expanded = 0u64;
        let opts = ScanOptions {
            max_member_bytes: self.max_member_bytes,
            ..Default::default()
        };

        let compressed_bytes = path.metadata()?.len();
        let decoder = ZlibDecoder::new(f);
        let mut counting =
            CountingReader::new(decoder, &mut total_expanded, compressed_bytes, &opts);

        let mut decompressed = Vec::new();
        counting.read_to_end(&mut decompressed).map_err(|e| {
            let msg = e.to_string();
            if msg.starts_with("bomb limit exceeded") {
                GitError::LimitExceeded(msg)
            } else {
                GitError::Corrupt(format!("loose object decompress error: {e}"))
            }
        })?;

        let null_pos = decompressed
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| GitError::Corrupt("missing null byte in loose object header".into()))?;

        let header_str = std::str::from_utf8(&decompressed[..null_pos])
            .map_err(|_| GitError::Corrupt("non-utf8 loose object header".into()))?;

        let mut parts = header_str.split(' ');
        let type_str = parts
            .next()
            .ok_or_else(|| GitError::Corrupt("missing type in loose object header".into()))?;
        let size_str = parts
            .next()
            .ok_or_else(|| GitError::Corrupt("missing size in loose object header".into()))?;

        let declared_size: usize = size_str
            .parse()
            .map_err(|_| GitError::Corrupt("invalid size in loose object header".into()))?;

        if declared_size as u64 > self.max_member_bytes {
            return Err(GitError::LimitExceeded(
                "declared object size over limit".into(),
            ));
        }

        let obj_type = match type_str {
            "commit" => ObjectType::Commit,
            "tree" => ObjectType::Tree,
            "blob" => ObjectType::Blob,
            "tag" => ObjectType::Tag,
            other => {
                return Err(GitError::Corrupt(format!(
                    "unknown object type '{}'",
                    other
                )))
            }
        };

        let data = decompressed[null_pos + 1..].to_vec();
        if data.len() != declared_size {
            return Err(GitError::Corrupt("loose object size mismatch".into()));
        }

        Ok(GitObject { obj_type, data })
    }

    /// Inflate a pack entry under the member limit. Consumes the file, so a delta
    /// chain doesn't hold one descriptor per level while it recurses.
    fn inflate(&self, f: File, size: u64, what: &str) -> Result<Vec<u8>, GitError> {
        let mut total_expanded = 0u64;
        let opts = ScanOptions {
            max_member_bytes: self.max_member_bytes,
            ..Default::default()
        };
        let decoder = ZlibDecoder::new(f);
        let mut counting = CountingReader::new(decoder, &mut total_expanded, 0, &opts);
        let mut data = Vec::with_capacity(size as usize);
        counting.read_to_end(&mut data).map_err(|e| {
            let msg = e.to_string();
            if msg.starts_with("bomb limit exceeded") {
                GitError::LimitExceeded(msg)
            } else {
                GitError::Corrupt(format!("pack {what} decompression error: {e}"))
            }
        })?;
        Ok(data)
    }

    /// Read a delta's base at an offset, through the resolved-base cache.
    fn read_ofs_base(
        &mut self,
        pack_idx: usize,
        base_offset: u64,
        depth: usize,
        visited_offsets: &mut HashSet<(usize, u64)>,
        visited_oids: &mut HashSet<String>,
    ) -> Result<GitObject, GitError> {
        let key = format!("{pack_idx}@{base_offset}");
        if let Some((obj_type, data)) = self.cache.get(&key) {
            return Ok(GitObject { obj_type, data });
        }
        let obj =
            self.read_packed_object(pack_idx, base_offset, depth, visited_offsets, visited_oids)?;
        self.cache.insert(key, obj.obj_type, obj.data.clone());
        Ok(obj)
    }

    fn read_packed_object(
        &mut self,
        pack_idx: usize,
        offset: u64,
        depth: usize,
        visited_offsets: &mut HashSet<(usize, u64)>,
        visited_oids: &mut HashSet<String>,
    ) -> Result<GitObject, GitError> {
        if depth > self.max_depth {
            return Err(GitError::LimitExceeded(
                "delta chain depth limit exceeded".into(),
            ));
        }

        if !visited_offsets.insert((pack_idx, offset)) {
            return Err(GitError::Corrupt("delta cycle detected (offset)".into()));
        }

        let pack_path = self.packs[pack_idx].pack_path.clone();
        let mut f = File::open(&pack_path)?;
        f.seek(SeekFrom::Start(offset))?;

        // Read object header
        let mut b = [0u8; 1];
        f.read_exact(&mut b)
            .map_err(|e| GitError::Corrupt(format!("truncated pack object header: {e}")))?;
        let first_byte = b[0];
        let type_num = (first_byte >> 4) & 0x07;
        let mut size = (first_byte & 0x0f) as u64;
        let mut shift = 4;
        let mut more = (first_byte & 0x80) != 0;

        while more {
            f.read_exact(&mut b)
                .map_err(|e| GitError::Corrupt(format!("truncated pack object header: {e}")))?;
            let byte = b[0];
            size |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            if shift > 64 {
                return Err(GitError::Corrupt("object size overflow in pack".into()));
            }
            more = (byte & 0x80) != 0;
        }

        if size > self.max_member_bytes {
            return Err(GitError::LimitExceeded(
                "a declared object size over the limit".into(),
            ));
        }

        match type_num {
            1..=4 => {
                let obj_type = match type_num {
                    1 => ObjectType::Commit,
                    2 => ObjectType::Tree,
                    3 => ObjectType::Blob,
                    4 => ObjectType::Tag,
                    _ => unreachable!(),
                };

                let data = self.inflate(f, size, "object")?;

                if data.len() as u64 != size {
                    return Err(GitError::Corrupt("inflated size mismatch in pack".into()));
                }

                Ok(GitObject { obj_type, data })
            }
            6 => {
                // OFS_DELTA
                let mut c = [0u8; 1];
                f.read_exact(&mut c)
                    .map_err(|e| GitError::Corrupt(format!("truncated ofs delta: {e}")))?;
                let mut byte = c[0];
                let mut base_offset_delta = (byte & 0x7f) as u64;

                while (byte & 0x80) != 0 {
                    f.read_exact(&mut c)
                        .map_err(|e| GitError::Corrupt(format!("truncated ofs delta: {e}")))?;
                    byte = c[0];
                    base_offset_delta = base_offset_delta
                        .checked_add(1)
                        .and_then(|d| d.checked_mul(128))
                        .and_then(|d| d.checked_add((byte & 0x7f) as u64))
                        .ok_or_else(|| GitError::Corrupt("base offset delta overflow".into()))?;
                }

                let base_offset = offset
                    .checked_sub(base_offset_delta)
                    .ok_or_else(|| GitError::Corrupt("base offset underflow".into()))?;

                let delta_data = self.inflate(f, size, "delta")?;

                let base_obj = self.read_ofs_base(
                    pack_idx,
                    base_offset,
                    depth + 1,
                    visited_offsets,
                    visited_oids,
                )?;

                let result_data = apply_delta(&base_obj.data, &delta_data, self.max_member_bytes)?;
                Ok(GitObject {
                    obj_type: base_obj.obj_type,
                    data: result_data,
                })
            }
            7 => {
                // REF_DELTA
                let mut base_oid_bytes = [0u8; 20];
                f.read_exact(&mut base_oid_bytes)
                    .map_err(|e| GitError::Corrupt(format!("truncated ref delta oid: {e}")))?;
                let base_oid = hex::encode(base_oid_bytes);

                if !visited_oids.insert(base_oid.clone()) {
                    return Err(GitError::Corrupt("delta cycle detected (ref)".into()));
                }

                let delta_data = self.inflate(f, size, "delta")?;

                // Base object could be loose or in any pack
                let base_obj =
                    self.read_object_internal(&base_oid, depth + 1, visited_offsets, visited_oids)?;

                let result_data = apply_delta(&base_obj.data, &delta_data, self.max_member_bytes)?;
                Ok(GitObject {
                    obj_type: base_obj.obj_type,
                    data: result_data,
                })
            }
            other => Err(GitError::Corrupt(format!(
                "invalid pack object type {}",
                other
            ))),
        }
    }

    fn read_object_internal(
        &mut self,
        oid: &str,
        depth: usize,
        visited_offsets: &mut HashSet<(usize, u64)>,
        visited_oids: &mut HashSet<String>,
    ) -> Result<GitObject, GitError> {
        if depth > self.max_depth {
            return Err(GitError::LimitExceeded(
                "delta chain depth limit exceeded".into(),
            ));
        }

        if !is_hex_oid(oid) {
            return Err(GitError::Corrupt(format!("invalid oid: {}", oid)));
        }

        if let Some((obj_type, data)) = self.cache.get(oid) {
            return Ok(GitObject { obj_type, data });
        }

        let (dir_part, file_part) = oid.split_at(2);
        let loose_path = self.objects_dir.join(dir_part).join(file_part);
        if loose_path.is_file() {
            let obj = self.read_loose_object(&loose_path)?;
            self.cache
                .insert(oid.to_string(), obj.obj_type, obj.data.clone());
            return Ok(obj);
        }

        let oid_bytes = hex::decode(oid)
            .map_err(|_| GitError::Corrupt(format!("hex decode error for oid {}", oid)))?;
        let mut oid_arr = [0u8; 20];
        oid_arr.copy_from_slice(&oid_bytes);

        for pack_idx in 0..self.packs.len() {
            if let Some(offset) = self.packs[pack_idx].find_object(&oid_arr) {
                let obj = self.read_packed_object(
                    pack_idx,
                    offset,
                    depth,
                    visited_offsets,
                    visited_oids,
                )?;
                self.cache
                    .insert(oid.to_string(), obj.obj_type, obj.data.clone());
                return Ok(obj);
            }
        }

        Err(GitError::NotFound(format!("object {} not found", oid)))
    }

    pub fn parse_commit(&self, data: &[u8]) -> Result<Commit, GitError> {
        // Old commits can be Latin-1; the header fields needed here are ASCII.
        let lossy = String::from_utf8_lossy(data);
        let text: &str = &lossy;

        let (header, message) = match text.find("\n\n") {
            Some(pos) => (&text[..pos], text[pos + 2..].to_string()),
            None => (text, String::new()),
        };

        let mut tree = String::new();
        let mut parents = Vec::new();
        let mut committer_time = None;

        for line in header.lines() {
            if let Some(stripped) = line.strip_prefix("tree ") {
                tree = stripped.trim().to_string();
            } else if let Some(stripped) = line.strip_prefix("parent ") {
                parents.push(stripped.trim().to_string());
            } else if let Some(stripped) = line.strip_prefix("committer ") {
                if let Some(idx) = stripped.rfind('>') {
                    let date_part = stripped[idx + 1..].trim();
                    if let Some(ts_str) = date_part.split_whitespace().next() {
                        committer_time = ts_str.parse::<i64>().ok();
                    }
                }
            }
        }

        if tree.is_empty() {
            return Err(GitError::Corrupt("commit missing tree header".into()));
        }

        Ok(Commit {
            tree,
            parents,
            committer_time,
            message,
        })
    }

    pub fn parse_tree(&self, data: &[u8]) -> Result<Tree, GitError> {
        let mut entries = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let space_pos = data[pos..]
                .iter()
                .position(|&b| b == b' ')
                .map(|p| pos + p)
                .ok_or_else(|| GitError::Corrupt("malformed tree entry: missing space".into()))?;

            let mode_str = std::str::from_utf8(&data[pos..space_pos])
                .map_err(|_| GitError::Corrupt("non-utf8 tree mode".into()))?;
            let mode = u32::from_str_radix(mode_str, 8)
                .map_err(|_| GitError::Corrupt("invalid tree mode octal".into()))?;

            let null_pos = data[space_pos + 1..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| space_pos + 1 + p)
                .ok_or_else(|| GitError::Corrupt("malformed tree entry: missing null".into()))?;

            let name = String::from_utf8_lossy(&data[space_pos + 1..null_pos]).into_owned();

            let oid_start = null_pos + 1;
            let oid_end = oid_start + 20;
            if oid_end > data.len() {
                return Err(GitError::Corrupt("truncated tree entry oid".into()));
            }

            let oid = hex::encode(&data[oid_start..oid_end]);
            entries.push(TreeEntry { mode, name, oid });
            pos = oid_end;
        }

        Ok(Tree { entries })
    }

    pub fn parse_tag(&self, data: &[u8]) -> Result<Tag, GitError> {
        let lossy = String::from_utf8_lossy(data);
        let text: &str = &lossy;

        let (header, message) = match text.find("\n\n") {
            Some(pos) => (&text[..pos], text[pos + 2..].to_string()),
            None => (text, String::new()),
        };

        let mut target_oid = String::new();
        let mut target_type = ObjectType::Commit;
        let mut tag_name = String::new();
        let mut tagger_time = None;

        for line in header.lines() {
            if let Some(stripped) = line.strip_prefix("object ") {
                target_oid = stripped.trim().to_string();
            } else if let Some(stripped) = line.strip_prefix("type ") {
                target_type = match stripped.trim() {
                    "commit" => ObjectType::Commit,
                    "tree" => ObjectType::Tree,
                    "blob" => ObjectType::Blob,
                    "tag" => ObjectType::Tag,
                    other => {
                        return Err(GitError::Corrupt(format!(
                            "unknown target type in tag: {}",
                            other
                        )))
                    }
                };
            } else if let Some(stripped) = line.strip_prefix("tag ") {
                tag_name = stripped.trim().to_string();
            } else if let Some(stripped) = line.strip_prefix("tagger ") {
                if let Some(idx) = stripped.rfind('>') {
                    let date_part = stripped[idx + 1..].trim();
                    if let Some(ts_str) = date_part.split_whitespace().next() {
                        tagger_time = ts_str.parse::<i64>().ok();
                    }
                }
            }
        }

        if target_oid.is_empty() {
            return Err(GitError::Corrupt("tag missing object header".into()));
        }

        Ok(Tag {
            target_oid,
            target_type,
            tag_name,
            tagger_time,
            message,
        })
    }
}

pub fn apply_delta(base: &[u8], delta: &[u8], max_member_bytes: u64) -> Result<Vec<u8>, GitError> {
    let mut pos = 0;

    // 1. Base size
    let mut base_size = 0u64;
    let mut shift = 0;
    let mut terminated = false;
    while pos < delta.len() {
        let b = delta[pos];
        pos += 1;
        base_size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if (b & 0x80) == 0 {
            terminated = true;
            break;
        }
        if shift > 64 {
            return Err(GitError::Corrupt("delta base size overflow".into()));
        }
    }
    if !terminated {
        return Err(GitError::Corrupt("truncated delta base size".into()));
    }

    if base_size != base.len() as u64 {
        return Err(GitError::Corrupt("delta base size mismatch".into()));
    }

    // 2. Result size
    let mut result_size = 0u64;
    let mut shift = 0;
    let mut terminated = false;
    while pos < delta.len() {
        let b = delta[pos];
        pos += 1;
        result_size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if (b & 0x80) == 0 {
            terminated = true;
            break;
        }
        if shift > 64 {
            return Err(GitError::Corrupt("delta result size overflow".into()));
        }
    }
    if !terminated {
        return Err(GitError::Corrupt("truncated delta result size".into()));
    }

    if result_size > max_member_bytes {
        return Err(GitError::LimitExceeded(
            "a declared object size over the limit".into(),
        ));
    }

    let mut result = Vec::with_capacity(result_size as usize);

    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;

        if cmd & 0x80 != 0 {
            // Copy instruction
            let mut offset = 0u64;
            let mut size = 0u64;

            if (cmd & 0x01) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated copy offset".into()));
                }
                offset |= delta[pos] as u64;
                pos += 1;
            }
            if (cmd & 0x02) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated copy offset".into()));
                }
                offset |= (delta[pos] as u64) << 8;
                pos += 1;
            }
            if (cmd & 0x04) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated copy offset".into()));
                }
                offset |= (delta[pos] as u64) << 16;
                pos += 1;
            }
            if (cmd & 0x08) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated copy offset".into()));
                }
                offset |= (delta[pos] as u64) << 24;
                pos += 1;
            }

            if (cmd & 0x10) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated copy size".into()));
                }
                size |= delta[pos] as u64;
                pos += 1;
            }
            if (cmd & 0x20) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated copy size".into()));
                }
                size |= (delta[pos] as u64) << 8;
                pos += 1;
            }
            if (cmd & 0x40) != 0 {
                if pos >= delta.len() {
                    return Err(GitError::Corrupt("truncated copy size".into()));
                }
                size |= (delta[pos] as u64) << 16;
                pos += 1;
            }

            if size == 0 {
                size = 0x10000;
            }

            let end = offset
                .checked_add(size)
                .ok_or_else(|| GitError::Corrupt("delta copy overflow".into()))?;
            if end > base.len() as u64 {
                return Err(GitError::Corrupt("delta copy beyond the base".into()));
            }
            if result.len() as u64 + size > result_size {
                return Err(GitError::Corrupt("delta result size mismatch".into()));
            }

            result.extend_from_slice(&base[offset as usize..end as usize]);
        } else if cmd > 0 {
            // Insert instruction
            let insert_len = cmd as usize;
            if pos + insert_len > delta.len() {
                return Err(GitError::Corrupt("truncated insert instruction".into()));
            }
            if result.len() as u64 + insert_len as u64 > result_size {
                return Err(GitError::Corrupt("delta result size mismatch".into()));
            }
            result.extend_from_slice(&delta[pos..pos + insert_len]);
            pos += insert_len;
        } else {
            return Err(GitError::Corrupt("invalid zero delta instruction".into()));
        }
    }

    if result.len() as u64 != result_size {
        return Err(GitError::Corrupt("delta result size mismatch".into()));
    }

    Ok(result)
}

/// Inflate one stray-pack entry under the member and total limits, returning it and its
/// compressed length.
fn inflate_stray(
    input: &[u8],
    size: u64,
    opts: &ScanOptions,
    total_expanded: &mut u64,
) -> Result<(Vec<u8>, usize), GitError> {
    let mut decoder = ZlibDecoder::new(input);
    let mut data = Vec::with_capacity(size.min(opts.max_member_bytes) as usize);
    CountingReader::new(&mut decoder, total_expanded, 0, opts)
        .read_to_end(&mut data)
        .map_err(|e| {
            let msg = e.to_string();
            if msg.starts_with("bomb limit exceeded") {
                GitError::LimitExceeded(msg)
            } else {
                GitError::Corrupt(format!("stray pack decompress error: {e}"))
            }
        })?;
    Ok((data, decoder.total_in() as usize))
}

/// Parse a stray pack sequentially from a memory slice. `total_expanded` is the enclosing
/// container's running total, so a pack can't exceed the container's budget.
pub fn scan_stray_pack_slice(
    bytes: &[u8],
    opts: &ScanOptions,
    total_expanded: &mut u64,
) -> StrayPackResult {
    let mut objects = Vec::new();
    let mut has_unresolved = false;
    let error = decode_stray_objects(
        bytes,
        opts,
        total_expanded,
        &mut objects,
        &mut has_unresolved,
    )
    .err();
    let blobs = objects
        .into_iter()
        .filter(|(_, obj_type, _)| *obj_type == ObjectType::Blob)
        .map(|(offset, _, data)| (offset, data))
        .collect();
    (blobs, has_unresolved, error)
}

fn decode_stray_objects(
    bytes: &[u8],
    opts: &ScanOptions,
    total_expanded: &mut u64,
    objects: &mut Vec<(u64, ObjectType, Vec<u8>)>,
    has_unresolved: &mut bool,
) -> Result<(), GitError> {
    if bytes.len() < 12 || &bytes[0..4] != b"PACK" {
        return Err(GitError::Corrupt("invalid pack magic".into()));
    }

    let ver = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if ver != 2 && ver != 3 {
        return Err(GitError::Unsupported(format!(
            "unsupported pack version {}",
            ver
        )));
    }

    let num_objects = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    let mut by_offset: HashMap<u64, usize> = HashMap::new();
    let mut by_oid: HashMap<String, usize> = HashMap::new();
    let mut cursor = 12;
    let end = bytes.len().saturating_sub(20);

    for _ in 0..num_objects {
        if cursor >= end {
            return Err(GitError::Corrupt("pack ends before its last object".into()));
        }
        let obj_offset = cursor as u64;
        let first_byte = bytes[cursor];
        cursor += 1;
        let type_num = (first_byte >> 4) & 0x07;
        let mut size = (first_byte & 0x0f) as u64;
        let mut shift = 4;
        let mut more = (first_byte & 0x80) != 0;

        while more {
            let b = *bytes
                .get(cursor)
                .ok_or_else(|| GitError::Corrupt("truncated pack object header".into()))?;
            cursor += 1;
            if shift > 57 {
                return Err(GitError::Corrupt("object size overflow in pack".into()));
            }
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
            more = (b & 0x80) != 0;
        }
        if size > opts.max_member_bytes {
            return Err(GitError::LimitExceeded(format!(
                "bomb limit exceeded: declared object size {size} bytes"
            )));
        }

        // (type, data) of the resolved object, or None when its delta base is unavailable.
        let resolved = match type_num {
            1..=4 => {
                let obj_type = match type_num {
                    1 => ObjectType::Commit,
                    2 => ObjectType::Tree,
                    3 => ObjectType::Blob,
                    _ => ObjectType::Tag,
                };
                let (data, used) = inflate_stray(&bytes[cursor..], size, opts, total_expanded)?;
                cursor += used;
                Some((obj_type, data))
            }
            6 | 7 => {
                let base_idx = if type_num == 6 {
                    let mut byte = *bytes
                        .get(cursor)
                        .ok_or_else(|| GitError::Corrupt("truncated ofs delta".into()))?;
                    cursor += 1;
                    let mut delta = (byte & 0x7f) as u64;
                    while (byte & 0x80) != 0 {
                        byte = *bytes
                            .get(cursor)
                            .ok_or_else(|| GitError::Corrupt("truncated ofs delta".into()))?;
                        cursor += 1;
                        delta = delta
                            .checked_add(1)
                            .and_then(|d| d.checked_mul(128))
                            .and_then(|d| d.checked_add((byte & 0x7f) as u64))
                            .ok_or_else(|| GitError::Corrupt("base offset overflow".into()))?;
                    }
                    let base_offset = obj_offset
                        .checked_sub(delta)
                        .ok_or_else(|| GitError::Corrupt("base offset underflow".into()))?;
                    by_offset.get(&base_offset).copied()
                } else {
                    let oid = bytes
                        .get(cursor..cursor + 20)
                        .ok_or_else(|| GitError::Corrupt("truncated ref delta oid".into()))?;
                    cursor += 20;
                    by_oid.get(&hex::encode(oid)).copied()
                };

                let (delta_data, used) =
                    inflate_stray(&bytes[cursor..], size, opts, total_expanded)?;
                cursor += used;

                match base_idx {
                    Some(idx) => {
                        let (_, base_type, base_data) = &objects[idx];
                        let base_type = *base_type;
                        let result = apply_delta(base_data, &delta_data, opts.max_member_bytes)?;
                        *total_expanded += result.len() as u64;
                        if *total_expanded > opts.max_total_expanded_bytes {
                            return Err(GitError::LimitExceeded(format!(
                                "bomb limit exceeded: total expanded size {} bytes",
                                *total_expanded
                            )));
                        }
                        Some((base_type, result))
                    }
                    None => None,
                }
            }
            other => {
                return Err(GitError::Corrupt(format!(
                    "invalid pack object type {other}"
                )))
            }
        };

        match resolved {
            Some((obj_type, data)) => {
                let idx = objects.len();
                by_offset.insert(obj_offset, idx);
                by_oid.insert(compute_git_sha1(obj_type, &data), idx);
                objects.push((obj_offset, obj_type, data));
            }
            None => *has_unresolved = true,
        }
    }

    Ok(())
}
