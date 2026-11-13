#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::config::{ExtractConfig, TaskClass};
use crate::error::{ExtractError, FormatError, PathError, QuotaError, TaskClassError};
use crate::format::{
    format_hex, PayloadStreamer, RecordHeader, RecordType, RECORD_HEADER_SIZE, STREAM_MAGIC,
    STREAM_VERSION,
};
use crate::report::{
    generate_tree_manifest_fd, AcceptedPath, DroppedPath, ExtractReport, ReportFlag, ReportTotals,
    RestoredPath,
};
use crate::restore::{
    is_section_restored_file, is_whole_path_test_infra, restore_file_sections, RestoreOutcome,
};
use crate::safe_fs::{
    copy_base_tree, create_directory, create_file_exclusive, create_staging_dir, delete_entry,
    open_dir_path, prepare_output_dir, publish_atomically, read_base_file, resolve_existing_parent,
    resolve_or_create_parent_dir, restore_base_entry, CleanupGuard,
};
use crate::shadowing::check_shadowing;

pub const MAX_STREAM_RECORDS: u64 = 20_000;
pub const MAX_SECTION_BYTES: u64 = 1024 * 1024;

/// Validates a stream from `reader` and extracts it into `out_dir` according to `class` and `config`.
pub fn validate_stream<R: Read>(
    reader: &mut R,
    base_dir: &Path,
    out_dir: &Path,
    class: TaskClass,
    config: &ExtractConfig,
) -> Result<ExtractReport, ExtractError> {
    config.validate()?;
    // 3. Read and validate stream header (8 bytes: magic [u8; 4], version u32 LE)
    let mut stream_header = [0u8; 8];
    reader
        .read_exact(&mut stream_header)
        .map_err(|_e| FormatError::Truncated("cannot read 8-byte stream header"))?;

    let magic = [
        stream_header[0],
        stream_header[1],
        stream_header[2],
        stream_header[3],
    ];
    if magic != STREAM_MAGIC {
        return Err(ExtractError::Format(FormatError::BadMagic(magic)));
    }

    let version = u32::from_le_bytes([
        stream_header[4],
        stream_header[5],
        stream_header[6],
        stream_header[7],
    ]);
    if version != STREAM_VERSION {
        return Err(ExtractError::Format(FormatError::UnsupportedVersion(
            version,
        )));
    }

    let base_fd = open_dir_path(base_dir)?;
    let (parent_fd, out_fd, out_name, tmp_name) = prepare_output_dir(out_dir)?;
    let staging_fd = create_staging_dir(&parent_fd, &tmp_name)?;
    let mut cleanup_guard = CleanupGuard::new(&parent_fd, &staging_fd, tmp_name.clone());
    let base_index = copy_base_tree(&base_fd, (class == TaskClass::Patch).then_some(&staging_fd))?;
    let mut protected_ancestors = HashSet::new();
    for path in base_index.keys().chain(config.test_paths.iter()) {
        if is_whole_path_test_infra(path, &config.test_paths).is_some()
            || is_section_restored_file(path)
        {
            let mut prefix = String::new();
            for component in path.split('/') {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(component);
                protected_ancestors.insert(prefix.clone());
            }
        }
    }

    // 4. Processing loop
    let mut records_received = 0u64;
    let mut files_accepted = 0u64;
    let mut directories_accepted = 0u64;
    let mut deletions_accepted = 0u64;
    let mut total_bytes_accepted = 0u64;
    let mut total_stream_file_bytes = 0u64;
    let mut paths_dropped = 0u64;
    let mut paths_restored = 0u64;
    let mut files_received = 0u64;
    let mut directories_received = HashSet::new();

    let mut declared_files: HashSet<String> = HashSet::new();
    let mut declared_directories: HashSet<String> = HashSet::new();
    let mut all_seen_paths: HashSet<String> = HashSet::new();

    let mut report_accepted = Vec::new();
    let mut report_dropped = Vec::new();
    let mut report_restored = Vec::new();
    let mut report_flags = Vec::new();
    let mut new_files: Vec<String> = Vec::new();

    loop {
        let mut header_buf = [0u8; RECORD_HEADER_SIZE];
        match reader.read_exact(&mut header_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(ExtractError::Format(FormatError::Truncated(
                    "unexpected EOF while reading record header",
                )));
            }
            Err(e) => return Err(ExtractError::Io(e)),
        }

        let header = RecordHeader::parse(&header_buf).map_err(ExtractError::Format)?;
        records_received += 1;

        if header.record_type == RecordType::EndOfStream {
            // End of stream record
            let expected_records = records_received - 1;
            if header.record_count != expected_records {
                return Err(ExtractError::Format(FormatError::CountMismatch {
                    declared: header.record_count,
                    actual: expected_records,
                }));
            }

            if header.size != total_stream_file_bytes {
                return Err(ExtractError::Format(FormatError::TotalBytesMismatch {
                    declared: header.size,
                    actual: total_stream_file_bytes,
                }));
            }

            // Check for trailing garbage
            let mut trailing_byte = [0u8; 1];
            match reader.read(&mut trailing_byte) {
                Ok(0) => {}
                Ok(_) => return Err(ExtractError::Format(FormatError::TrailingGarbage)),
                Err(e) => return Err(ExtractError::Io(e)),
            }

            break;
        }

        if records_received > MAX_STREAM_RECORDS {
            return Err(QuotaError::ResourceLimit("MAX_STREAM_RECORDS").into());
        }

        // Non-EOS records in State task class are forbidden
        if class == TaskClass::State {
            return Err(ExtractError::TaskClass(
                TaskClassError::StateTaskNonEmptyStream {
                    path: format!("type: {:?}", header.record_type),
                },
            ));
        }

        // Validate path_len
        let path_len = header.path_len as usize;
        let path_cap = config
            .max_path_bytes
            .min(crate::safe_fs::MAX_TREE_PATH_BYTES);
        if path_len > path_cap {
            return Err(ExtractError::Format(FormatError::OversizedField {
                field: "path_len",
                size: path_len,
                cap: path_cap,
            }));
        }

        let mut path_buf = vec![0u8; path_len];
        match reader.read_exact(&mut path_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(ExtractError::Format(FormatError::Truncated(
                    "unexpected EOF while reading path bytes",
                )));
            }
            Err(e) => return Err(ExtractError::Io(e)),
        }

        let path_str = std::str::from_utf8(&path_buf)
            .map_err(|_| ExtractError::Format(FormatError::InvalidUtf8Path))?;

        // -------------------------------------------------------------------
        // Path validation checks
        // -------------------------------------------------------------------
        if path_str.is_empty() {
            return Err(ExtractError::PathValidation(PathError::Empty));
        }
        if path_str.starts_with('/') {
            return Err(ExtractError::PathValidation(PathError::Absolute(
                path_str.to_string(),
            )));
        }
        if path_str.len() >= 2
            && path_str.as_bytes()[1] == b':'
            && path_str.as_bytes()[0].is_ascii_alphabetic()
        {
            return Err(ExtractError::PathValidation(PathError::DrivePrefix(
                path_str.to_string(),
            )));
        }
        if path_str.contains('\\') {
            return Err(ExtractError::PathValidation(PathError::Backslash(
                path_str.to_string(),
            )));
        }
        if path_str.contains('\0') {
            return Err(ExtractError::PathValidation(PathError::NulByte(
                path_str.to_string(),
            )));
        }

        let components: Vec<&str> = path_str.split('/').collect();
        if components.len() > config.max_path_depth.min(crate::safe_fs::MAX_TREE_DEPTH) {
            return Err(ExtractError::PathValidation(PathError::DepthExceeded {
                path: path_str.to_string(),
                depth: components.len(),
                cap: config.max_path_depth,
            }));
        }

        for comp in &components {
            if comp.is_empty() {
                return Err(ExtractError::PathValidation(PathError::EmptyComponent(
                    path_str.to_string(),
                )));
            }
            if *comp == "." || *comp == ".." {
                return Err(ExtractError::PathValidation(PathError::DotOrDotDot(
                    path_str.to_string(),
                )));
            }
        }

        // Check path traversal through regular file
        for i in 1..components.len() {
            let prefix = components[..i].join("/");
            if declared_files.contains(&prefix) {
                return Err(ExtractError::PathValidation(
                    PathError::TraversesRegularFile {
                        path: path_str.to_string(),
                        file_component: prefix,
                    },
                ));
            }
        }

        // Check if regular file replaces a directory with declared children
        if header.record_type == RecordType::RegularFile {
            if declared_directories.contains(path_str) {
                return Err(ExtractError::PathValidation(
                    PathError::FileReplacesDirectoryWithChildren {
                        path: path_str.to_string(),
                    },
                ));
            }
            let child_prefix = format!("{path_str}/");
            if declared_files.iter().any(|f| f.starts_with(&child_prefix))
                || declared_directories
                    .iter()
                    .any(|d| d.starts_with(&child_prefix))
            {
                return Err(ExtractError::PathValidation(
                    PathError::FileReplacesDirectoryWithChildren {
                        path: path_str.to_string(),
                    },
                ));
            }
        }

        // Duplicate path check
        if all_seen_paths.contains(path_str) {
            return Err(ExtractError::PathValidation(PathError::DuplicatePath(
                path_str.to_string(),
            )));
        }
        all_seen_paths.insert(path_str.to_string());

        // Task class boundary checks
        match class {
            TaskClass::Patch => {
                if let Some(ref repo_dir) = config.repo_dir {
                    if !repo_dir.is_empty() {
                        let prefix = if repo_dir.ends_with('/') {
                            repo_dir.clone()
                        } else {
                            format!("{repo_dir}/")
                        };
                        if path_str != repo_dir && !path_str.starts_with(&prefix) {
                            return Err(ExtractError::TaskClass(TaskClassError::OutsideRepoDir {
                                path: path_str.to_string(),
                                repo_dir: repo_dir.clone(),
                            }));
                        }
                    }
                }
            }
            TaskClass::Artifact => {
                if !config.artifact_paths.iter().any(|a| a == path_str) {
                    return Err(ExtractError::TaskClass(
                        TaskClassError::UndeclaredArtifactPath {
                            path: path_str.to_string(),
                        },
                    ));
                }
            }
            TaskClass::State => unreachable!(),
        }

        // Quota checks
        if header.size > config.max_file_bytes {
            return Err(ExtractError::Quota(QuotaError::FileBytesExceeded {
                path: path_str.to_string(),
                size: header.size,
                cap: config.max_file_bytes,
            }));
        }

        if header.record_type == RecordType::RegularFile {
            total_stream_file_bytes = total_stream_file_bytes
                .checked_add(header.size)
                .ok_or(QuotaError::ResourceLimit("stream total bytes overflow"))?;
            if total_stream_file_bytes > config.max_total_bytes {
                return Err(ExtractError::Quota(QuotaError::TotalBytesExceeded {
                    total: total_stream_file_bytes,
                    cap: config.max_total_bytes,
                }));
            }
        }

        if header.record_type == RecordType::RegularFile {
            files_received += 1;
            if files_received > config.max_file_count {
                return Err(ExtractError::Quota(QuotaError::FileCountExceeded {
                    count: files_received,
                    cap: config.max_file_count,
                }));
            }
        }
        if header.record_type != RecordType::Deletion {
            for i in 1..components.len() {
                directories_received.insert(components[..i].join("/"));
                if directories_received.len() > crate::safe_fs::MAX_TREE_ENTRIES {
                    return Err(
                        QuotaError::ResourceLimit("MAX_TREE_ENTRIES stream directories").into(),
                    );
                }
            }
        }
        if header.record_type == RecordType::Directory {
            directories_received.insert(path_str.to_string());
        }
        if directories_received.len() as u64 > config.max_dir_count {
            return Err(ExtractError::Quota(QuotaError::DirCountExceeded {
                count: directories_received.len() as u64,
                cap: config.max_dir_count,
            }));
        }

        // Declarations constrain later paths even when policy drops the record.
        match header.record_type {
            RecordType::RegularFile => {
                declared_files.insert(path_str.to_owned());
            }
            RecordType::Directory => {
                declared_directories.insert(path_str.to_owned());
            }
            _ => {}
        }

        // -------------------------------------------------------------------
        // Test infrastructure checks (whole path drop and restore)
        // -------------------------------------------------------------------
        let protected_reason = is_whole_path_test_infra(path_str, &config.test_paths)
            .or_else(|| {
                (protected_ancestors.contains(path_str)
                    && (header.record_type != RecordType::Directory)
                    && !(header.record_type == RecordType::RegularFile
                        && is_section_restored_file(path_str)))
                .then_some("protected_descendant")
            })
            .or_else(|| {
                (is_section_restored_file(path_str)
                    && header.record_type != RecordType::RegularFile)
                    .then_some("protected_configuration_type")
            });
        if let Some(reason) = protected_reason {
            paths_dropped += 1;
            report_dropped.push(DroppedPath {
                path: path_str.to_string(),
                reason: reason.to_string(),
            });

            // Stream and discard payload, verifying SHA-256 and size
            if header.record_type == RecordType::RegularFile {
                PayloadStreamer::discard_and_hash(reader, header.size, header.sha256, path_str)?;
            }

            // If it exists in base, record it as restored
            if base_index.contains_key(path_str) {
                if class != TaskClass::Patch {
                    restore_base_entry(&base_fd, &base_index, &staging_fd, path_str)?;
                }
                paths_restored += 1;
                report_restored.push(RestoredPath {
                    path: path_str.to_string(),
                    reason: "restored_from_base".to_string(),
                });
            }

            continue;
        }

        // -------------------------------------------------------------------
        // Section restoration checks (setup.cfg, pyproject.toml)
        // -------------------------------------------------------------------
        if is_section_restored_file(path_str) && header.record_type == RecordType::RegularFile {
            if header.size > MAX_SECTION_BYTES {
                return Err(QuotaError::ResourceLimit("MAX_SECTION_BYTES").into());
            }
            let mut payload = Vec::new();
            PayloadStreamer::stream_to_writer(
                reader,
                header.size,
                header.sha256,
                &mut payload,
                path_str,
            )?;

            let agent_text = std::str::from_utf8(&payload).ok();
            let base_payload = if base_index.contains_key(path_str) {
                Some(read_base_file(&base_fd, path_str, MAX_SECTION_BYTES)?)
            } else {
                None
            };
            let base_text = base_payload
                .as_deref()
                .and_then(|v| std::str::from_utf8(v).ok());

            match agent_text {
                Some(agent_str) => {
                    match if base_payload.is_some() && base_text.is_none() {
                        RestoreOutcome::FallbackWholeBaseRestored
                    } else {
                        restore_file_sections(path_str, base_text, agent_str)
                    } {
                        RestoreOutcome::SectionsRestored(merged) => {
                            let (p_fd, leaf) = resolve_or_create_parent_dir(&staging_fd, path_str)?;
                            let mut f = create_file_exclusive(&p_fd, &leaf, 0o644)?;
                            use std::io::Write;
                            f.write_all(merged.as_bytes()).map_err(ExtractError::Io)?;

                            let mut m_hasher = Sha256::new();
                            m_hasher.update(merged.as_bytes());
                            let m_hash: [u8; 32] = m_hasher.finalize().into();

                            paths_restored += 1;
                            report_restored.push(RestoredPath {
                                path: path_str.to_string(),
                                reason: "test_runner_sections_restored".to_string(),
                            });

                            files_accepted += 1;
                            total_bytes_accepted += header.size;
                            declared_files.insert(path_str.to_string());
                            report_accepted.push(AcceptedPath {
                                path: path_str.to_string(),
                                kind: "file".to_string(),
                                mode: "0644".to_string(),
                                size: merged.len() as u64,
                                sha256: format_hex(&m_hash),
                            });
                        }
                        RestoreOutcome::FallbackWholeBaseRestored => {
                            if base_index.contains_key(path_str) {
                                if class != TaskClass::Patch {
                                    restore_base_entry(
                                        &base_fd,
                                        &base_index,
                                        &staging_fd,
                                        path_str,
                                    )?;
                                }
                                paths_restored += 1;
                                report_restored.push(RestoredPath {
                                    path: path_str.to_string(),
                                    reason: "safe_fallback_unparseable_restored_whole_from_base"
                                        .to_string(),
                                });
                            } else {
                                paths_dropped += 1;
                                report_dropped.push(DroppedPath {
                                    path: path_str.to_string(),
                                    reason: "safe_fallback_unparseable_no_base".to_string(),
                                });
                            }
                        }
                        RestoreOutcome::Unmodified => {
                            let (p_fd, leaf) = resolve_or_create_parent_dir(&staging_fd, path_str)?;
                            let mut f = create_file_exclusive(&p_fd, &leaf, 0o644)?;
                            use std::io::Write;
                            f.write_all(&payload).map_err(ExtractError::Io)?;

                            files_accepted += 1;
                            total_bytes_accepted += header.size;
                            declared_files.insert(path_str.to_string());
                            report_accepted.push(AcceptedPath {
                                path: path_str.to_string(),
                                kind: "file".to_string(),
                                mode: "0644".to_string(),
                                size: header.size,
                                sha256: format_hex(&header.sha256),
                            });
                            if !base_index.contains_key(path_str) {
                                new_files.push(path_str.to_string());
                            }
                        }
                    }
                }
                None => {
                    // Non-UTF-8: conservative rule restores whole file from base
                    if base_index.contains_key(path_str) {
                        if class != TaskClass::Patch {
                            restore_base_entry(&base_fd, &base_index, &staging_fd, path_str)?;
                        }
                        paths_restored += 1;
                        report_restored.push(RestoredPath {
                            path: path_str.to_string(),
                            reason: "safe_fallback_unparseable_restored_whole_from_base"
                                .to_string(),
                        });
                    } else {
                        paths_dropped += 1;
                        report_dropped.push(DroppedPath {
                            path: path_str.to_string(),
                            reason: "safe_fallback_unparseable_no_base".to_string(),
                        });
                    }
                }
            }

            continue;
        }

        // -------------------------------------------------------------------
        // Standard record operations
        // -------------------------------------------------------------------
        match header.record_type {
            RecordType::Directory => {
                let (p_fd, leaf) = resolve_or_create_parent_dir(&staging_fd, path_str)?;
                create_directory(&p_fd, &leaf, 0o755)?;
                declared_directories.insert(path_str.to_string());
                directories_accepted += 1;

                report_accepted.push(AcceptedPath {
                    path: path_str.to_string(),
                    kind: "directory".to_string(),
                    mode: "0755".to_string(),
                    size: 0,
                    sha256: format_hex(&[0u8; 32]),
                });
            }
            RecordType::Deletion => {
                if let Some((p_fd, leaf)) = resolve_existing_parent(&staging_fd, path_str)? {
                    delete_entry(&p_fd, &leaf)?;
                }
                deletions_accepted += 1;

                report_accepted.push(AcceptedPath {
                    path: path_str.to_string(),
                    kind: "deletion".to_string(),
                    mode: "0000".to_string(),
                    size: 0,
                    sha256: format_hex(&[0u8; 32]),
                });
            }
            RecordType::RegularFile => {
                let exec_bit = (header.mode & 0o111) != 0;
                let target_mode = if exec_bit { 0o755 } else { 0o644 };

                let (p_fd, leaf) = resolve_or_create_parent_dir(&staging_fd, path_str)?;
                let mut out_file = create_file_exclusive(&p_fd, &leaf, target_mode)?;

                PayloadStreamer::stream_to_writer(
                    reader,
                    header.size,
                    header.sha256,
                    &mut out_file,
                    path_str,
                )?;

                declared_files.insert(path_str.to_string());
                files_accepted += 1;
                total_bytes_accepted += header.size;

                report_accepted.push(AcceptedPath {
                    path: path_str.to_string(),
                    kind: "file".to_string(),
                    mode: format!("{target_mode:04o}"),
                    size: header.size,
                    sha256: format_hex(&header.sha256),
                });

                if !base_index.contains_key(path_str) {
                    new_files.push(path_str.to_string());
                }
            }
            RecordType::EndOfStream => unreachable!(),
        }
    }

    report_flags.extend(case_collision_flags(
        base_index.keys().chain(all_seen_paths.iter()),
    ));

    // 5. Shadowing checks for new files
    for new_path in &new_files {
        if let Some(flag) =
            check_shadowing(new_path, &config.import_roots, &config.installed_packages)
        {
            report_flags.push(flag);
        }
    }

    // 6. Tree manifest generation
    let (tree_manifest_sha256, tree_file_count, tree_total_bytes) =
        generate_tree_manifest_fd(&staging_fd)?;

    // 7. Atomic publication
    publish_atomically(&parent_fd, &out_fd, &staging_fd, &tmp_name, &out_name)?;
    cleanup_guard.disarm();

    // 8. Assemble report
    let totals = ReportTotals {
        records_received,
        files_accepted,
        directories_accepted,
        deletions_accepted,
        total_bytes_accepted,
        paths_dropped,
        paths_restored,
        tree_file_count,
        tree_total_bytes,
    };

    let mut report = ExtractReport {
        accepted: report_accepted,
        dropped: report_dropped,
        restored: report_restored,
        flags: report_flags,
        totals,
        tree_manifest_sha256,
    };

    report.sort_deterministic();
    Ok(report)
}

fn case_collision_flags<'a>(paths: impl Iterator<Item = &'a String>) -> Vec<ReportFlag> {
    let mut prefixes = BTreeSet::new();
    for path in paths {
        let mut prefix = String::new();
        for component in path.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            prefixes.insert(prefix.clone());
        }
    }
    let mut folded = HashMap::new();
    let mut flags = Vec::new();
    for path in prefixes {
        let key = path.to_lowercase();
        if let Some(existing) = folded.get(&key) {
            flags.push(ReportFlag {
                flag_type: "case_fold_collision".into(),
                path: path.clone(),
                detail: format!("collides with '{existing}' under case-folding"),
            });
        } else if !path.is_ascii() {
            // Lowercasing is not full Unicode case folding. Flag these paths
            // conservatively rather than silently miss multi-character folds.
            flags.push(ReportFlag {
                flag_type: "case_fold_collision".into(),
                path: path.clone(),
                detail: "possible Unicode case-fold collision requires review".into(),
            });
        }
        folded.entry(key).or_insert(path);
    }
    flags
}
