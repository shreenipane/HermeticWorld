use std::io::{self, Cursor, Read};
use std::path::Path;

use rusqlite::Connection;

use crate::benchmark::{check_d9_content, check_d9_path_with_display, BenchmarkSignatures};
use crate::bytecode::{pyc_header_len, pyc_magic};
use crate::fingerprint::FingerprintSet;
use crate::scan::{match_unit, Finding, ScanOptions, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerType {
    Zip,
    Tar,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Sqlite,
    Pyc,
    GitPack,
}

pub fn detect_container_type(bytes: &[u8], path: &str) -> Option<ContainerType> {
    if bytes.len() >= 8 && bytes.starts_with(b"PACK") {
        let ver = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if ver == 2 || ver == 3 {
            return Some(ContainerType::GitPack);
        }
    }
    if bytes.starts_with(b"SQLite format 3\0") {
        return Some(ContainerType::Sqlite);
    }
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        return Some(ContainerType::Zip);
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some(ContainerType::Gzip);
    }
    if bytes.starts_with(b"BZh") {
        return Some(ContainerType::Bzip2);
    }
    if bytes.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        return Some(ContainerType::Xz);
    }
    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(ContainerType::Zstd);
    }
    if pyc_magic(bytes).is_some() || path.ends_with(".pyc") {
        return Some(ContainerType::Pyc);
    }
    if is_tar(bytes) {
        return Some(ContainerType::Tar);
    }
    None
}

pub fn is_tar(bytes: &[u8]) -> bool {
    if bytes.len() < 512 {
        return false;
    }
    if bytes.len() >= 262 && &bytes[257..262] == b"ustar" {
        return true;
    }
    tar_header_checksum_valid(&bytes[..512])
}

fn tar_header_checksum_valid(header: &[u8]) -> bool {
    if header.len() < 512 {
        return false;
    }
    let cksum_slice = &header[148..156];
    let mut start = 0;
    while start < cksum_slice.len() && (cksum_slice[start] == 0 || cksum_slice[start] == b' ') {
        start += 1;
    }
    let mut end = cksum_slice.len();
    while end > start && (cksum_slice[end - 1] == 0 || cksum_slice[end - 1] == b' ') {
        end -= 1;
    }
    if start == end {
        return false;
    }
    let digits = &cksum_slice[start..end];
    if digits.iter().any(|&b| !b.is_ascii_digit() || b > b'7') {
        return false;
    }
    let Ok(octal_str) = std::str::from_utf8(digits) else {
        return false;
    };
    let Ok(stored_val) = u32::from_str_radix(octal_str, 8) else {
        return false;
    };
    let mut sum: u32 = 0;
    for (i, &b) in header[..512].iter().enumerate() {
        if (148..156).contains(&i) {
            sum += b' ' as u32;
        } else {
            sum += b as u32;
        }
    }
    stored_val == sum
}

/// Counting read wrapper enforcing member size, total expanded size, and expansion ratio limits.
pub struct CountingReader<'a, R> {
    inner: R,
    member_bytes_read: u64,
    total_expanded_bytes: &'a mut u64,
    compressed_bytes: u64,
    max_member_bytes: u64,
    max_total_expanded_bytes: u64,
    max_ratio: f64,
}

impl<'a, R: Read> CountingReader<'a, R> {
    pub fn new(
        inner: R,
        total_expanded_bytes: &'a mut u64,
        compressed_bytes: u64,
        opts: &ScanOptions,
    ) -> Self {
        Self {
            inner,
            member_bytes_read: 0,
            total_expanded_bytes,
            compressed_bytes,
            max_member_bytes: opts.max_member_bytes,
            max_total_expanded_bytes: opts.max_total_expanded_bytes,
            max_ratio: opts.max_ratio,
        }
    }
}

impl<'a, R: Read> Read for CountingReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            return Ok(0);
        }
        self.member_bytes_read += n as u64;
        *self.total_expanded_bytes += n as u64;

        if self.member_bytes_read > self.max_member_bytes {
            return Err(io::Error::other(format!(
                "bomb limit exceeded: member size {} bytes > max {} bytes",
                self.member_bytes_read, self.max_member_bytes
            )));
        }

        if *self.total_expanded_bytes > self.max_total_expanded_bytes {
            return Err(io::Error::other(format!(
                "bomb limit exceeded: total expanded size {} bytes > max {} bytes",
                *self.total_expanded_bytes, self.max_total_expanded_bytes
            )));
        }

        if self.compressed_bytes > 0 && self.member_bytes_read > 1024 * 1024 {
            let ratio = self.member_bytes_read as f64 / self.compressed_bytes as f64;
            if ratio > self.max_ratio {
                return Err(io::Error::other(format!(
                    "bomb limit exceeded: expansion ratio {:.1} > max {}",
                    ratio, self.max_ratio
                )));
            }
        }

        Ok(n)
    }
}

pub fn extract_pyc_constants(bytes: &[u8]) -> String {
    let header_len = match pyc_magic(bytes) {
        Some(magic) => pyc_header_len(magic),
        None => 0,
    };
    if bytes.len() <= header_len {
        return String::new();
    }
    let body = &bytes[header_len..];
    let mut runs = Vec::new();
    let mut current_run = Vec::new();

    let mut i = 0;
    while i < body.len() {
        let b = body[i];
        if (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r' {
            current_run.push(b);
            i += 1;
        } else {
            if let Ok(s) = std::str::from_utf8(&body[i..]) {
                if let Some(c) = s.chars().next() {
                    if !c.is_control() {
                        current_run.extend_from_slice(&body[i..i + c.len_utf8()]);
                        i += c.len_utf8();
                        continue;
                    }
                }
            }
            if current_run.len() >= 6 {
                if let Ok(s) = std::str::from_utf8(&current_run) {
                    runs.push(s.to_string());
                }
            }
            current_run.clear();
            i += 1;
        }
    }
    if current_run.len() >= 6 {
        if let Ok(s) = std::str::from_utf8(&current_run) {
            runs.push(s.to_string());
        }
    }

    runs.join("\n")
}

fn strip_compression_suffix(name: &str) -> String {
    if let Some(s) = name.strip_suffix(".tar.gz") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".tgz") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".tar.bz2") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".tbz2") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".tar.xz") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".txz") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".tar.zst") {
        format!("{}.tar", s)
    } else if let Some(s) = name.strip_suffix(".gz") {
        s.to_string()
    } else if let Some(s) = name.strip_suffix(".bz2") {
        s.to_string()
    } else if let Some(s) = name.strip_suffix(".xz") {
        s.to_string()
    } else if let Some(s) = name.strip_suffix(".zst") {
        s.to_string()
    } else {
        name.to_string()
    }
}

pub struct ContainerScanner<'a> {
    pub fp: &'a FingerprintSet,
    pub signatures: &'a BenchmarkSignatures,
    pub opts: &'a ScanOptions,
    pub total_expanded: u64,
    pub findings: Vec<Finding>,
    pub root_prefix_len: usize,
}

impl<'a> ContainerScanner<'a> {
    pub fn new(
        fp: &'a FingerprintSet,
        signatures: &'a BenchmarkSignatures,
        opts: &'a ScanOptions,
    ) -> Self {
        Self::new_with_root_prefix(fp, signatures, opts, 0)
    }

    pub fn new_with_root_prefix(
        fp: &'a FingerprintSet,
        signatures: &'a BenchmarkSignatures,
        opts: &'a ScanOptions,
        root_prefix_len: usize,
    ) -> Self {
        Self {
            fp,
            signatures,
            opts,
            total_expanded: 0,
            findings: Vec::new(),
            root_prefix_len,
        }
    }

    pub fn scan(&mut self, path: &str, bytes: &[u8], depth: usize) {
        // 1. Path check for D9 on every path (relative to scan root)
        let match_path = match path.get(self.root_prefix_len..) {
            Some(rel) if !rel.is_empty() => rel.trim_start_matches(['/', '\\']),
            _ => path,
        };
        self.findings.extend(check_d9_path_with_display(
            match_path,
            path,
            self.signatures,
            self.opts.visibility,
        ));

        // 2. Check container type
        let container_type = detect_container_type(bytes, path);

        if let Some(ctype) = container_type {
            if depth > self.opts.max_depth {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_depth".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!(
                        "container depth {} exceeds limit {}",
                        depth, self.opts.max_depth
                    )],
                });
                return;
            }

            match ctype {
                ContainerType::GitPack => {
                    self.scan_stray_pack(path, bytes, depth);
                }
                ContainerType::Pyc => {
                    let constants_text = extract_pyc_constants(bytes);
                    if !constants_text.is_empty() {
                        self.scan_text(path, &constants_text);
                    }
                }
                ContainerType::Sqlite => {
                    self.scan_sqlite(path, bytes);
                }
                ContainerType::Zip => {
                    self.scan_zip(path, bytes, depth);
                }
                ContainerType::Tar => {
                    self.scan_tar(path, bytes, depth);
                }
                ContainerType::Gzip => {
                    self.decompress_and_scan(path, bytes, ContainerType::Gzip, depth);
                }
                ContainerType::Bzip2 => {
                    self.decompress_and_scan(path, bytes, ContainerType::Bzip2, depth);
                }
                ContainerType::Xz => {
                    self.decompress_and_scan(path, bytes, ContainerType::Xz, depth);
                }
                ContainerType::Zstd => {
                    self.decompress_and_scan(path, bytes, ContainerType::Zstd, depth);
                }
            }
        } else {
            // Plain file unit
            // Check binary (NUL byte in first 8 KiB)
            let check_len = bytes.len().min(8192);
            if bytes[..check_len].contains(&0) {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "file".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec!["skipped binary file (contains NUL byte)".into()],
                });
                return;
            }

            let text = String::from_utf8_lossy(bytes);
            self.scan_text(path, &text);
        }
    }

    pub fn scan_text(&mut self, path: &str, text: &str) {
        self.findings.extend(check_d9_content(
            path,
            text,
            self.signatures,
            self.opts.visibility,
        ));
        self.findings
            .extend(match_unit(text, self.fp, self.opts, "D2", "file", path));
    }

    fn scan_stray_pack(&mut self, path: &str, bytes: &[u8], depth: usize) {
        match crate::gitstore::scan_stray_pack_slice(bytes, self.opts, &mut self.total_expanded) {
            Ok((blobs, has_unresolved_ref_delta)) => {
                for (offset, blob_bytes) in blobs {
                    let blob_path = format!("{}#{}", path, offset);
                    self.scan(&blob_path, &blob_bytes, depth + 1);
                }
                if has_unresolved_ref_delta {
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_skipped".into(),
                        path: path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec!["unresolved REF_DELTA in stray pack".into()],
                    });
                }
            }
            Err(crate::gitstore::GitError::LimitExceeded(msg)) => {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_bomb".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Review,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![msg],
                });
            }
            Err(e) => {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("failed to parse stray git pack: {e}")],
                });
            }
        }
    }

    fn scan_sqlite(&mut self, path: &str, bytes: &[u8]) {
        let temp_file = match tempfile::NamedTempFile::new() {
            Ok(t) => t,
            Err(e) => {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("failed to create temp file for sqlite: {e}")],
                });
                return;
            }
        };

        if let Err(e) = std::fs::write(temp_file.path(), bytes) {
            self.findings.push(Finding {
                detector: "D2".into(),
                channel: "container_error".into(),
                path: path.to_string(),
                visibility: self.opts.visibility,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec![format!("failed to write temp sqlite file: {e}")],
            });
            return;
        }

        let conn = match Connection::open_with_flags(
            temp_file.path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) {
            Ok(c) => c,
            Err(e) => {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("sqlite open error: {e}")],
                });
                return;
            }
        };

        let mut stmt = match conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
        ) {
            Ok(s) => s,
            Err(e) => {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("sqlite tables query error: {e}")],
                });
                return;
            }
        };

        let table_names: Vec<String> = match stmt.query_map([], |row| row.get(0)) {
            Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("sqlite table names map error: {e}")],
                });
                return;
            }
        };

        for table in table_names {
            let escaped_table = table.replace('"', "\"\"");
            let query = format!("SELECT rowid, * FROM \"{}\"", escaped_table);
            let has_rowid = conn.prepare(&query).is_ok();

            let (sql, has_explicit_rowid) = if has_rowid {
                (query, true)
            } else {
                (format!("SELECT * FROM \"{}\"", escaped_table), false)
            };

            let mut row_stmt = match conn.prepare(&sql) {
                Ok(s) => s,
                Err(e) => {
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: format!("{}::{}", path, table),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!(
                            "failed to prepare statement for table '{}': {e}",
                            table
                        )],
                    });
                    continue;
                }
            };

            let col_count = row_stmt.column_count();
            let mut rows = match row_stmt.query([]) {
                Ok(r) => r,
                Err(e) => {
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: format!("{}::{}", path, table),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("failed to query rows for table '{}': {e}", table)],
                    });
                    continue;
                }
            };

            let mut row_idx: i64 = 0;
            loop {
                let row = match rows.next() {
                    Ok(Some(r)) => r,
                    Ok(None) => break,
                    Err(e) => {
                        self.findings.push(Finding {
                            detector: "D2".into(),
                            channel: "container_error".into(),
                            path: format!("{}::{}", path, table),
                            visibility: self.opts.visibility,
                            severity: Severity::Info,
                            confidence: 0.0,
                            hunk: None,
                            evidence: vec![format!(
                                "failed to fetch row for table '{}': {e}",
                                table
                            )],
                        });
                        break;
                    }
                };
                row_idx += 1;
                let rowid_str = if has_explicit_rowid {
                    let id: i64 = row.get(0).unwrap_or(row_idx);
                    id.to_string()
                } else {
                    row_idx.to_string()
                };

                let start_col = if has_explicit_rowid { 1 } else { 0 };
                let mut row_text_parts = Vec::new();

                for c in start_col..col_count {
                    if let Ok(val) = row.get_ref(c) {
                        match val {
                            rusqlite::types::ValueRef::Text(s) => {
                                if let Ok(s_str) = std::str::from_utf8(s) {
                                    row_text_parts.push(s_str.to_string());
                                }
                            }
                            rusqlite::types::ValueRef::Blob(b) => {
                                if let Ok(s_str) = std::str::from_utf8(b) {
                                    row_text_parts.push(s_str.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }

                if !row_text_parts.is_empty() {
                    let row_text = row_text_parts.join("\n");
                    let row_path = format!("{}::{}#{}", path, table, rowid_str);
                    self.scan_text(&row_path, &row_text);
                }
            }
        }
    }

    fn scan_zip(&mut self, path: &str, bytes: &[u8], depth: usize) {
        let reader = Cursor::new(bytes);
        let mut archive = match zip::ZipArchive::new(reader) {
            Ok(a) => a,
            Err(e) => {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("failed to open zip archive: {e}")],
                });
                return;
            }
        };

        for i in 0..archive.len() {
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("failed to read zip member index {i}: {e}")],
                    });
                    continue;
                }
            };

            if file.is_dir() {
                continue;
            }

            let member_name = file.name().to_string();
            let member_path = format!("{}!/{}", path, member_name);
            let compressed_size = file.compressed_size();

            let mut member_bytes = Vec::new();
            let mut counting = CountingReader::new(
                &mut file,
                &mut self.total_expanded,
                compressed_size,
                self.opts,
            );

            if let Err(e) = counting.read_to_end(&mut member_bytes) {
                let msg = e.to_string();
                if msg.starts_with("bomb limit exceeded") {
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_bomb".into(),
                        path: path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Review,
                        confidence: 1.0,
                        hunk: None,
                        evidence: vec![msg],
                    });
                    return;
                } else {
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: member_path,
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("error reading zip entry: {msg}")],
                    });
                    continue;
                }
            }

            self.scan(&member_path, &member_bytes, depth + 1);
        }
    }

    fn scan_tar(&mut self, path: &str, bytes: &[u8], depth: usize) {
        let cursor = Cursor::new(bytes);
        let mut archive = tar::Archive::new(cursor);

        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("failed to read tar entries: {e}")],
                });
                return;
            }
        };

        for entry_res in entries {
            let mut entry = match entry_res {
                Ok(e) => e,
                Err(e) => {
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("tar entry read error: {e}")],
                    });
                    continue;
                }
            };

            let entry_type = entry.header().entry_type();
            match entry_type {
                tar::EntryType::Regular
                | tar::EntryType::GNUSparse
                | tar::EntryType::Continuous => {}
                tar::EntryType::Directory | tar::EntryType::Symlink | tar::EntryType::Link => {
                    continue
                }
                _ => {
                    let entry_path = entry
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "unknown".into());
                    let member_path = format!("{}!/{}", path, entry_path);
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_skipped".into(),
                        path: member_path,
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("tar member type '{:?}' skipped", entry_type)],
                    });
                    continue;
                }
            }

            let entry_path = match entry.path() {
                Ok(p) => p.display().to_string(),
                Err(e) => {
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("invalid tar entry path: {e}")],
                    });
                    continue;
                }
            };

            let member_path = format!("{}!/{}", path, entry_path);
            let size = entry.header().size().unwrap_or(0);

            let mut member_bytes = Vec::new();
            let mut counting =
                CountingReader::new(&mut entry, &mut self.total_expanded, size, self.opts);

            if let Err(e) = counting.read_to_end(&mut member_bytes) {
                let msg = e.to_string();
                if msg.starts_with("bomb limit exceeded") {
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_bomb".into(),
                        path: path.to_string(),
                        visibility: self.opts.visibility,
                        severity: Severity::Review,
                        confidence: 1.0,
                        hunk: None,
                        evidence: vec![msg],
                    });
                    return;
                } else {
                    self.findings.push(Finding {
                        detector: "D2".into(),
                        channel: "container_error".into(),
                        path: member_path,
                        visibility: self.opts.visibility,
                        severity: Severity::Info,
                        confidence: 0.0,
                        hunk: None,
                        evidence: vec![format!("error reading tar entry: {msg}")],
                    });
                    continue;
                }
            }

            self.scan(&member_path, &member_bytes, depth + 1);
        }
    }

    fn decompress_and_scan(
        &mut self,
        path: &str,
        compressed_bytes: &[u8],
        kind: ContainerType,
        depth: usize,
    ) {
        let mut decompressed_bytes = Vec::new();
        let comp_len = compressed_bytes.len() as u64;

        let res = match kind {
            ContainerType::Gzip => {
                let decoder = flate2::read::GzDecoder::new(Cursor::new(compressed_bytes));
                let mut counting =
                    CountingReader::new(decoder, &mut self.total_expanded, comp_len, self.opts);
                counting.read_to_end(&mut decompressed_bytes)
            }
            ContainerType::Bzip2 => {
                let decoder = bzip2::read::BzDecoder::new(Cursor::new(compressed_bytes));
                let mut counting =
                    CountingReader::new(decoder, &mut self.total_expanded, comp_len, self.opts);
                counting.read_to_end(&mut decompressed_bytes)
            }
            ContainerType::Xz => {
                let decoder = xz2::read::XzDecoder::new(Cursor::new(compressed_bytes));
                let mut counting =
                    CountingReader::new(decoder, &mut self.total_expanded, comp_len, self.opts);
                counting.read_to_end(&mut decompressed_bytes)
            }
            ContainerType::Zstd => {
                match zstd::stream::read::Decoder::new(Cursor::new(compressed_bytes)) {
                    Ok(decoder) => {
                        let mut counting = CountingReader::new(
                            decoder,
                            &mut self.total_expanded,
                            comp_len,
                            self.opts,
                        );
                        counting.read_to_end(&mut decompressed_bytes)
                    }
                    Err(e) => Err(e),
                }
            }
            _ => return,
        };

        if let Err(e) = res {
            let msg = e.to_string();
            if msg.starts_with("bomb limit exceeded") {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_bomb".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Review,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![msg],
                });
                return;
            } else {
                self.findings.push(Finding {
                    detector: "D2".into(),
                    channel: "container_error".into(),
                    path: path.to_string(),
                    visibility: self.opts.visibility,
                    severity: Severity::Info,
                    confidence: 0.0,
                    hunk: None,
                    evidence: vec![format!("decompression error: {msg}")],
                });
                return;
            }
        }

        let is_tar_content = is_tar(&decompressed_bytes);
        if is_tar_content {
            self.scan_tar(path, &decompressed_bytes, depth);
        } else {
            let inner_name = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .map(strip_compression_suffix)
                .unwrap_or_else(|| "uncompressed".into());

            let member_path = format!("{}!/{}", path, inner_name);
            self.scan(&member_path, &decompressed_bytes, depth + 1);
        }
    }
}

pub fn scan_container_or_unit(
    path: &str,
    bytes: &[u8],
    fp: &FingerprintSet,
    signatures: &BenchmarkSignatures,
    opts: &ScanOptions,
) -> Vec<Finding> {
    scan_container_or_unit_with_root_prefix(path, bytes, fp, signatures, opts, 0)
}

pub fn scan_container_or_unit_with_root_prefix(
    path: &str,
    bytes: &[u8],
    fp: &FingerprintSet,
    signatures: &BenchmarkSignatures,
    opts: &ScanOptions,
    root_prefix_len: usize,
) -> Vec<Finding> {
    let mut scanner = ContainerScanner::new_with_root_prefix(fp, signatures, opts, root_prefix_len);
    scanner.scan(path, bytes, 0);
    scanner.findings
}
