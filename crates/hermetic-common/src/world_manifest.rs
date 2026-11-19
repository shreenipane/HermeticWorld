use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, UtcOffset};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub struct ValidationErrors {
    pub errors: Vec<String>,
}

impl std::fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Validation failed with {} error(s):", self.errors.len())?;
        for err in &self.errors {
            writeln!(f, "  - {}", err)?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorldManifestError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Validation(#[from] ValidationErrors),
    #[error("Field not found: {0}")]
    FieldNotFound(String),
    #[error("Special file encountered at '{0}'")]
    SpecialFile(String),
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    #[error("Invalid digest format: {0}")]
    InvalidDigest(String),
    #[error("Non-UTF-8 path encountered: '{0}'")]
    NonUtf8Path(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    Dated,
    Undated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealLevel {
    Strict,
    RepoOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateAtT {
    Full,
    Partial,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispositionKind {
    Repaired,
    Excluded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestCutoffs {
    pub t_world: String,
    pub t_clock: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_commit: Option<String>,
    pub pkg_cutoff: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagesRecord {
    pub closure_root: String,
    pub baseline_month: String,
    pub baseline_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebRecord {
    pub index_month: String,
    pub capture_index_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateEntry {
    pub name: String,
    pub version: String,
    pub digest: String,
    pub date: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateExemption {
    pub package: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_mib: u64,
    pub wall_time_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSpec {
    pub env: BTreeMap<String, String>,
    pub workdir: String,
    pub user: String,
    pub entrypoint: Vec<String>,
    pub resources: Resources,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disposition {
    pub kind: DispositionKind,
    pub detector: String,
    pub detail: String,
}

/// Built-in, versioned test services; never arbitrary executables or URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestService {
    #[serde(rename = "httpbin-v1")]
    HttpbinV1,
}

/// One reviewed built-in service is currently supported per task.
pub const MAX_TEST_SERVICES: usize = 1;

/// Canonical World Manifest describing a sealed world (§13.1, TR-SEAL-11, TR-SEAL-12).
///
/// Hashing and leaf canonicalization rules:
/// - Each leaf is `(path, value)` where `path` is the JSON-pointer-like field path
///   (e.g., `/cutoffs/t_clock`, `/substrate/2/digest`, `/run_spec/env/PATH`) and `value`
///   is the canonical JSON encoding of the scalar (strings as JSON strings, numbers as integers).
/// - **Optional fields that are absent produce no leaf.**
/// - **An empty list produces no leaf.**
/// - Leaves are sorted by path in byte order.
/// - Leaf hash: `BLAKE3("hw-leaf\0" || len(path) u32 LE || path || len(value) u32 LE || value)`.
/// - Tree: binary Merkle tree over leaf hashes in sorted order; internal node `BLAKE3("hw-node\0" || left || right)`.
///   An odd node at a level is promoted unchanged. The empty tree is `BLAKE3("hw-empty\0")`.
/// - World root: `"blake3:" + hex(root)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldManifest {
    // Identity
    pub spec_version: String,
    pub task_id: String,
    pub task_class: TaskClass,
    pub seal_level: SealLevel,

    // Cutoffs
    pub cutoffs: ManifestCutoffs,

    // Content
    /// Repository tree digest.
    ///
    /// Under the chosen scheme, `repo_tree_digest` represents the Git object ID of
    /// the tree at `base_commit` in the sealed Git store (e.g. `sha1:<40 hex>`,
    /// `git:<40 or 64 hex>`, or `sha256:<64 hex>`), or a `blake3:<64 hex>` Merkle tree.
    pub repo_tree_digest: String,
    pub rootfs_digest: String,
    pub packages: PackagesRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<WebRecord>,

    // Substrate
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub substrate: Vec<SubstrateEntry>,
    pub substrate_at_t: SubstrateAtT,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exemptions: Vec<SubstrateExemption>,

    // Network
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_table: Vec<String>,
    pub world_ca_cert_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_store_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub test_services: Vec<TestService>,

    // Run spec
    pub run_spec: RunSpec,

    // Evidence
    pub sealcheck_report_digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dispositions: Vec<Disposition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofDirection {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofStep {
    pub direction: ProofDirection,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProof {
    pub path: String,
    pub value: String,
    pub proof: Vec<ProofStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub path: String,
    pub value: String,
}

fn escape_json_pointer(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

fn collect_leaves_from_value(
    path: &str,
    val: &serde_json::Value,
    leaves: &mut Vec<Leaf>,
) -> Result<(), WorldManifestError> {
    match val {
        serde_json::Value::Null => {
            // Optional fields that are absent produce no leaf.
        }
        serde_json::Value::Bool(b) => {
            leaves.push(Leaf {
                path: path.to_string(),
                value: b.to_string(),
            });
        }
        serde_json::Value::Number(n) => {
            if !n.is_i64() && !n.is_u64() {
                return Err(WorldManifestError::InvalidDigest(format!(
                    "Floating point number not permitted in manifest: {}",
                    n
                )));
            }
            leaves.push(Leaf {
                path: path.to_string(),
                value: n.to_string(),
            });
        }
        serde_json::Value::String(s) => {
            let encoded = serde_json::to_string(s)?;
            leaves.push(Leaf {
                path: path.to_string(),
                value: encoded,
            });
        }
        serde_json::Value::Array(arr) => {
            // An empty list produces no leaf
            if !arr.is_empty() {
                for (idx, item) in arr.iter().enumerate() {
                    let subpath = format!("{}/{}", path, idx);
                    collect_leaves_from_value(&subpath, item, leaves)?;
                }
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if !v.is_null() {
                    let subpath = format!("{}/{}", path, escape_json_pointer(k));
                    collect_leaves_from_value(&subpath, v, leaves)?;
                }
            }
        }
    }
    Ok(())
}

pub fn compute_leaf_hash_raw(domain_tag: &[u8], path: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain_tag);
    hasher.update(&(path.len() as u32).to_le_bytes());
    hasher.update(path);
    hasher.update(&(value.len() as u32).to_le_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

pub fn compute_leaf_hash(domain_tag: &[u8], path: &str, value: &str) -> [u8; 32] {
    compute_leaf_hash_raw(domain_tag, path.as_bytes(), value.as_bytes())
}

pub fn compute_merkle_root(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    if leaf_hashes.is_empty() {
        return *blake3::hash(b"hw-empty\0").as_bytes();
    }
    let mut current = leaf_hashes.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                let mut h = Hasher::new();
                h.update(b"hw-node\0");
                h.update(&current[i]);
                h.update(&current[i + 1]);
                next.push(h.finalize().into());
                i += 2;
            } else {
                next.push(current[i]);
                i += 1;
            }
        }
        current = next;
    }
    current[0]
}

fn parse_digest_64(hex_str: &str) -> Result<[u8; 32], WorldManifestError> {
    if hex_str.len() != 64 {
        return Err(WorldManifestError::InvalidDigest(format!(
            "Digest hex must be 64 characters, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)
        .map_err(|e| WorldManifestError::InvalidDigest(format!("Invalid hex in digest: {}", e)))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_root_hash(root: &str) -> Result<[u8; 32], WorldManifestError> {
    let hex_part = if let Some(stripped) = root.strip_prefix("blake3:") {
        stripped
    } else {
        return Err(WorldManifestError::InvalidProof(format!(
            "Root must have 'blake3:' prefix, got '{}'",
            root
        )));
    };
    parse_digest_64(hex_part)
}

fn parse_hash_32(hash: &str) -> Result<[u8; 32], WorldManifestError> {
    let hex_part = if let Some(stripped) = hash.strip_prefix("blake3:") {
        stripped
    } else if let Some(stripped) = hash.strip_prefix("sha256:") {
        stripped
    } else {
        hash
    };
    parse_digest_64(hex_part)
}

fn validate_repo_tree_digest(name: &str, s: &str, errors: &mut Vec<String>) {
    let (algo, hex_part) = if let Some(stripped) = s.strip_prefix("blake3:") {
        ("blake3", stripped)
    } else if let Some(stripped) = s.strip_prefix("sha256:") {
        ("sha256", stripped)
    } else if let Some(stripped) = s.strip_prefix("git:") {
        ("git", stripped)
    } else if let Some(stripped) = s.strip_prefix("sha1:") {
        ("sha1", stripped)
    } else {
        errors.push(format!(
            "Digest '{name}' must start with 'blake3:', 'sha256:', 'git:', or 'sha1:', got '{s}'"
        ));
        return;
    };

    let expected_len = match algo {
        "blake3" | "sha256" => hex_part.len() == 64,
        "sha1" => hex_part.len() == 40,
        "git" => hex_part.len() == 40 || hex_part.len() == 64,
        _ => false,
    };

    if !expected_len {
        errors.push(format!(
            "Digest '{name}' hex portion has invalid length for algorithm '{algo}', got {}",
            hex_part.len()
        ));
    } else if !hex_part
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        errors.push(format!(
            "Digest '{name}' hex portion must be lowercase hex characters, got '{hex_part}'"
        ));
    }
}

fn validate_digest(name: &str, s: &str, errors: &mut Vec<String>) {
    let hex_part = if let Some(stripped) = s.strip_prefix("blake3:") {
        stripped
    } else if let Some(stripped) = s.strip_prefix("sha256:") {
        stripped
    } else {
        errors.push(format!(
            "Digest '{name}' must start with 'blake3:' or 'sha256:', got '{s}'"
        ));
        return;
    };

    if hex_part.len() != 64 {
        errors.push(format!(
            "Digest '{name}' hex portion must be 64 characters, got {}",
            hex_part.len()
        ));
    } else if !hex_part
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        errors.push(format!(
            "Digest '{name}' hex portion must be lowercase hex characters, got '{hex_part}'"
        ));
    }
}

fn validate_month(name: &str, s: &str, errors: &mut Vec<String>) {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 || parts[0].len() != 4 || parts[1].len() != 2 {
        errors.push(format!(
            "Month field '{name}' must have format 'YYYY-MM', got '{s}'"
        ));
        return;
    }
    let year_ok = parts[0].chars().all(|c| c.is_ascii_digit());
    let month_val = parts[1].parse::<u32>().ok();
    match month_val {
        Some(m) if year_ok && (1..=12).contains(&m) => {}
        _ => {
            errors.push(format!(
                "Month field '{name}' has invalid year or month value: '{s}'"
            ));
        }
    }
}

fn parse_ymd_date(s: &str) -> Option<Date> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return None;
    }
    if !parts[0].chars().all(|c| c.is_ascii_digit())
        || !parts[1].chars().all(|c| c.is_ascii_digit())
        || !parts[2].chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let year = parts[0].parse::<i32>().ok()?;
    let month_u8 = parts[1].parse::<u8>().ok()?;
    let day = parts[2].parse::<u8>().ok()?;
    let month = Month::try_from(month_u8).ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

fn parse_rfc3339_utc(name: &str, s: &str, errors: &mut Vec<String>) -> Option<OffsetDateTime> {
    match OffsetDateTime::parse(s, &Rfc3339) {
        Ok(dt) => {
            if dt.offset() != UtcOffset::UTC {
                errors.push(format!(
                    "Timestamp '{name}' must be in UTC timezone (Z or +00:00), got offset '{}'",
                    dt.offset()
                ));
                None
            } else {
                Some(dt)
            }
        }
        Err(e) => {
            errors.push(format!(
                "Timestamp '{name}' is not valid RFC 3339 UTC ('{s}'): {e}"
            ));
            None
        }
    }
}

impl WorldManifest {
    pub fn from_json_str(s: &str) -> Result<Self, WorldManifestError> {
        let manifest: Self = serde_json::from_str(s)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn load(path: &Path) -> Result<Self, WorldManifestError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_json_str(&content)
    }

    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();

        // 1. Identity
        if self.spec_version != "hermetic-world/v1" {
            errors.push(format!(
                "spec_version must be 'hermetic-world/v1', got '{}'",
                self.spec_version
            ));
        }
        if self.task_id.trim().is_empty() {
            errors.push("task_id cannot be empty".to_string());
        }

        // 2. Cutoffs
        let t_world = parse_rfc3339_utc("t_world", &self.cutoffs.t_world, &mut errors);
        let t_clock = parse_rfc3339_utc("t_clock", &self.cutoffs.t_clock, &mut errors);
        let _pkg_cutoff = parse_rfc3339_utc("pkg_cutoff", &self.cutoffs.pkg_cutoff, &mut errors);

        if let (Some(w), Some(c)) = (t_world, t_clock) {
            if c < w {
                errors.push(format!(
                    "t_clock ({}) cannot be earlier than t_world ({})",
                    self.cutoffs.t_clock, self.cutoffs.t_world
                ));
            }
        }

        match (self.task_class, &self.cutoffs.base_commit) {
            (TaskClass::Dated, None) => {
                errors.push("base_commit is required for dated task_class".to_string());
            }
            (_, Some(commit)) => {
                if commit.len() != 40
                    || !commit
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                {
                    errors.push(format!(
                        "base_commit must be 40 lowercase hexadecimal characters, got '{commit}'"
                    ));
                }
            }
            (TaskClass::Undated, None) => {}
        }

        // 3. Content
        validate_repo_tree_digest("repo_tree_digest", &self.repo_tree_digest, &mut errors);
        validate_digest("rootfs_digest", &self.rootfs_digest, &mut errors);
        validate_digest("closure_root", &self.packages.closure_root, &mut errors);
        validate_digest("baseline_root", &self.packages.baseline_root, &mut errors);
        validate_month("baseline_month", &self.packages.baseline_month, &mut errors);

        if let Some(ref web) = self.web {
            validate_month("index_month", &web.index_month, &mut errors);
            validate_digest("capture_index_root", &web.capture_index_root, &mut errors);
        }

        // 4. Substrate
        for (i, entry) in self.substrate.iter().enumerate() {
            validate_digest(
                &format!("substrate[{i}].digest"),
                &entry.digest,
                &mut errors,
            );
            // Verify date format: RFC3339 or YYYY-MM-DD (valid calendar date)
            let is_rfc3339 = OffsetDateTime::parse(&entry.date, &Rfc3339).is_ok();
            let is_ymd = parse_ymd_date(&entry.date).is_some();
            if !is_rfc3339 && !is_ymd {
                errors.push(format!(
                    "Field 'substrate[{i}].date' must be a valid RFC 3339 timestamp or YYYY-MM-DD calendar date, got '{}'",
                    entry.date
                ));
            }
        }

        // 5. Network
        if self.test_services.len() > MAX_TEST_SERVICES {
            errors.push("test_services exceeds supported service count".to_string());
        }
        for i in 1..self.dns_table.len() {
            if self.dns_table[i - 1].as_bytes() >= self.dns_table[i].as_bytes() {
                errors.push(
                    "dns_table must be strictly sorted (sorted and unique) in byte order"
                        .to_string(),
                );
                break;
            }
        }
        validate_digest(
            "world_ca_cert_sha256",
            &self.world_ca_cert_sha256,
            &mut errors,
        );
        for i in 1..self.trust_store_paths.len() {
            if self.trust_store_paths[i - 1].as_bytes() >= self.trust_store_paths[i].as_bytes() {
                errors.push(
                    "trust_store_paths must be strictly sorted (sorted and unique) in byte order"
                        .to_string(),
                );
                break;
            }
        }

        // 6. Run spec
        if self.run_spec.resources.vcpus == 0 {
            errors.push("resources.vcpus must be greater than 0".to_string());
        }
        if self.run_spec.resources.memory_mib == 0 {
            errors.push("resources.memory_mib must be greater than 0".to_string());
        }
        if self.run_spec.resources.disk_mib == 0 {
            errors.push("resources.disk_mib must be greater than 0".to_string());
        }
        if self.run_spec.resources.wall_time_s == 0 {
            errors.push("resources.wall_time_s must be greater than 0".to_string());
        }

        // 7. Evidence
        validate_digest(
            "sealcheck_report_digest",
            &self.sealcheck_report_digest,
            &mut errors,
        );

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors { errors })
        }
    }

    /// Collect all canonical leaves for this manifest sorted by path (byte order).
    ///
    /// Optional fields that are absent produce no leaf, and empty lists produce no leaf.
    pub fn leaves(&self) -> Result<Vec<Leaf>, WorldManifestError> {
        let val = serde_json::to_value(self)?;
        let mut leaves = Vec::new();
        collect_leaves_from_value("", &val, &mut leaves)?;
        leaves.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        Ok(leaves)
    }

    /// Compute the Merkle `world_root` over all canonical leaves of the manifest.
    pub fn world_root(&self) -> Result<String, WorldManifestError> {
        let leaves = self.leaves()?;
        let leaf_hashes: Vec<[u8; 32]> = leaves
            .iter()
            .map(|l| compute_leaf_hash(b"hw-leaf\0", &l.path, &l.value))
            .collect();
        let root = compute_merkle_root(&leaf_hashes);
        Ok(format!("blake3:{}", hex::encode(root)))
    }

    /// Generate a Merkle inclusion proof for a single field path (e.g. `/cutoffs/t_clock`).
    ///
    /// Returns `(leaf_value, proof_steps)`.
    pub fn inclusion_proof(
        &self,
        target_path: &str,
    ) -> Result<(String, Vec<ProofStep>), WorldManifestError> {
        let leaves = self.leaves()?;
        let target_idx = leaves
            .iter()
            .position(|l| l.path == target_path)
            .ok_or_else(|| WorldManifestError::FieldNotFound(target_path.to_string()))?;
        let target_value = leaves[target_idx].value.clone();

        if leaves.len() <= 1 {
            return Ok((target_value, Vec::new()));
        }

        let mut current: Vec<[u8; 32]> = leaves
            .iter()
            .map(|l| compute_leaf_hash(b"hw-leaf\0", &l.path, &l.value))
            .collect();

        let mut proof = Vec::new();
        let mut idx = target_idx;

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    let mut h = Hasher::new();
                    h.update(b"hw-node\0");
                    h.update(&current[i]);
                    h.update(&current[i + 1]);
                    next.push(h.finalize().into());

                    if i == idx {
                        proof.push(ProofStep {
                            direction: ProofDirection::Right,
                            hash: hex::encode(current[i + 1]),
                        });
                    } else if i + 1 == idx {
                        proof.push(ProofStep {
                            direction: ProofDirection::Left,
                            hash: hex::encode(current[i]),
                        });
                    }
                    i += 2;
                } else {
                    next.push(current[i]);
                    i += 1;
                }
            }
            idx /= 2;
            current = next;
        }

        Ok((target_value, proof))
    }

    /// Add a disposition to this manifest (§5.5, TR-SEAL-11).
    pub fn add_disposition(
        &mut self,
        kind: DispositionKind,
        detector: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.dispositions.push(Disposition {
            kind,
            detector: detector.into(),
            detail: detail.into(),
        });
    }
}

/// Verify a Merkle inclusion proof for a path and value against an expected root.
pub fn verify_inclusion(
    expected_root: &str,
    path: &str,
    value: &str,
    proof: &[ProofStep],
) -> Result<bool, WorldManifestError> {
    let expected_bytes = parse_root_hash(expected_root)?;
    let leaf_hash = compute_leaf_hash(b"hw-leaf\0", path, value);
    let mut current = leaf_hash;

    for step in proof {
        let sibling_bytes = parse_hash_32(&step.hash)?;
        let mut h = Hasher::new();
        h.update(b"hw-node\0");
        match step.direction {
            ProofDirection::Right => {
                h.update(&current);
                h.update(&sibling_bytes);
            }
            ProofDirection::Left => {
                h.update(&sibling_bytes);
                h.update(&current);
            }
        }
        current = h.finalize().into();
    }

    Ok(current == expected_bytes)
}

#[derive(Serialize)]
struct TreeEntryValue<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<&'a str>,
    executable: bool,
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
}

struct TreeEntry {
    rel_path: Vec<u8>,
    value: Vec<u8>,
}

#[cfg(unix)]
fn is_owner_executable(meta: &std::fs::Metadata) -> bool {
    (meta.permissions().mode() & 0o100) != 0
}

#[cfg(not(unix))]
fn is_owner_executable(_meta: &std::fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn is_special_file(ft: &std::fs::FileType) -> bool {
    ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device()
}

#[cfg(not(unix))]
fn is_special_file(_ft: &std::fs::FileType) -> bool {
    false
}

#[cfg(unix)]
fn path_to_rel_bytes(base_dir: &Path, path: &Path) -> Result<Vec<u8>, WorldManifestError> {
    let rel = path
        .strip_prefix(base_dir)
        .map_err(|e| WorldManifestError::Io(std::io::Error::other(e)))?;
    let mut parts: Vec<&[u8]> = Vec::new();
    for comp in rel.components() {
        parts.push(comp.as_os_str().as_bytes());
    }
    Ok(parts.join(&b'/'))
}

#[cfg(not(unix))]
fn path_to_rel_bytes(base_dir: &Path, path: &Path) -> Result<Vec<u8>, WorldManifestError> {
    let rel = path
        .strip_prefix(base_dir)
        .map_err(|e| WorldManifestError::Io(std::io::Error::other(e)))?;
    let mut parts: Vec<&[u8]> = Vec::new();
    for comp in rel.components() {
        let s = comp.as_os_str().to_str().ok_or_else(|| {
            WorldManifestError::NonUtf8Path(comp.as_os_str().to_string_lossy().to_string())
        })?;
        parts.push(s.as_bytes());
    }
    Ok(parts.join(&b'/'))
}

#[cfg(unix)]
fn read_symlink_target_bytes(path: &Path) -> Result<Vec<u8>, WorldManifestError> {
    let target = std::fs::read_link(path)?;
    Ok(target.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn read_symlink_target_bytes(path: &Path) -> Result<Vec<u8>, WorldManifestError> {
    let target = std::fs::read_link(path)?;
    let s = target
        .as_os_str()
        .to_str()
        .ok_or_else(|| WorldManifestError::NonUtf8Path(target.to_string_lossy().to_string()))?;
    Ok(s.as_bytes().to_vec())
}

fn serialize_json_byte_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.push(b'"');
    for &b in bytes {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            c if c < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c).as_bytes());
            }
            c => out.push(c),
        }
    }
    out.push(b'"');
    out
}

/// Compute the `blake3:` digest of a file's contents, streamed in chunks.
pub fn digest_file(path: &Path) -> Result<String, WorldManifestError> {
    let mut file = File::open(path)?;
    let mut hasher = Hasher::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!(
        "blake3:{}",
        hex::encode(hasher.finalize().as_bytes())
    ))
}

fn walk_dir_entries(
    base_dir: &Path,
    current_dir: &Path,
    entries: &mut Vec<TreeEntry>,
) -> Result<(), WorldManifestError> {
    let read_dir = std::fs::read_dir(current_dir)?;
    let mut dir_items = Vec::new();
    for item in read_dir {
        let entry = item?;
        dir_items.push(entry.path());
    }
    dir_items.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });

    for path in dir_items {
        let symlink_meta = std::fs::symlink_metadata(&path)?;
        let ft = symlink_meta.file_type();

        if is_special_file(&ft) {
            return Err(WorldManifestError::SpecialFile(path.display().to_string()));
        }

        let rel_path_bytes = path_to_rel_bytes(base_dir, &path)?;

        if ft.is_symlink() {
            let target_bytes = read_symlink_target_bytes(&path)?;
            let val = if let Ok(target_str) = std::str::from_utf8(&target_bytes) {
                serde_json::to_vec(&TreeEntryValue {
                    executable: false,
                    kind: "symlink",
                    digest: None,
                    target: Some(target_str),
                })?
            } else {
                let mut v = Vec::new();
                v.extend_from_slice(b"{\"executable\":false,\"kind\":\"symlink\",\"target\":");
                v.extend_from_slice(&serialize_json_byte_string(&target_bytes));
                v.extend_from_slice(b"}");
                v
            };
            entries.push(TreeEntry {
                rel_path: rel_path_bytes,
                value: val,
            });
        } else if ft.is_dir() {
            let is_exec = is_owner_executable(&symlink_meta);
            let val = serde_json::to_vec(&TreeEntryValue {
                executable: is_exec,
                kind: "dir",
                digest: None,
                target: None,
            })?;
            entries.push(TreeEntry {
                rel_path: rel_path_bytes,
                value: val,
            });
            walk_dir_entries(base_dir, &path, entries)?;
        } else if ft.is_file() {
            let is_exec = is_owner_executable(&symlink_meta);
            let file_digest = digest_file(&path)?;
            let val = serde_json::to_vec(&TreeEntryValue {
                executable: is_exec,
                kind: "file",
                digest: Some(&file_digest),
                target: None,
            })?;
            entries.push(TreeEntry {
                rel_path: rel_path_bytes,
                value: val,
            });
        }
    }
    Ok(())
}

/// Compute the Merkle tree digest of a directory tree with domain tag `"hw-tree\0"`.
///
/// Walks the directory sorted by byte path, never follows symlinks (a symlink contributes its
/// target bytes), includes each entry's relative path, kind (file, dir, symlink), executable bit
/// (only the owner-executable bit 0o100 is recorded, for files and directories alike),
/// and file content digests (streamed). Special files (FIFOs, sockets, devices) return an error naming the path.
pub fn digest_tree(dir: &Path) -> Result<String, WorldManifestError> {
    let mut entries = Vec::new();
    walk_dir_entries(dir, dir, &mut entries)?;
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let leaf_hashes: Vec<[u8; 32]> = entries
        .iter()
        .map(|e| compute_leaf_hash_raw(b"hw-tree\0", &e.rel_path, &e.value))
        .collect();
    let root = compute_merkle_root(&leaf_hashes);
    Ok(format!("blake3:{}", hex::encode(root)))
}
