#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::config::{ExtractConfig, TaskClass};
use crate::error::{ExtractError, FormatError, PathError, QuotaError, TaskClassError};
use crate::format::{
    format_hex, PayloadStreamer, RecordHeader, RecordType, RECORD_HEADER_SIZE, STREAM_MAGIC,
    STREAM_VERSION,
};
use crate::report::{
    generate_tree_manifest, AcceptedPath, DroppedPath, ExtractReport, ReportFlag, ReportTotals,
    RestoredPath,
};
use crate::restore::{
    is_section_restored_file, is_whole_path_test_infra, restore_file_sections, RestoreOutcome,
};
use crate::safe_fs::{
    copy_base_tree, create_directory, create_file_exclusive, create_staging_dir, delete_entry,
    prepare_output_dir, publish_atomically, resolve_or_create_parent_dir, CleanupGuard,
};
use crate::shadowing::check_shadowing;

/// Validates a stream from `reader` and extracts it into `out_dir` according to `class` and `config`.
pub fn validate_stream<R: Read>(
    reader: &mut R,
    base_dir: &Path,
    out_dir: &Path,
    class: TaskClass,
    config: &ExtractConfig,
) -> Result<ExtractReport, ExtractError> {
    // 1. Prepare output directory and staging directory
    let (parent_fd, out_name, tmp_name) = prepare_output_dir(out_dir)?;
    let mut cleanup_guard = CleanupGuard::new(&parent_fd, tmp_name.clone());
    let staging_fd = create_staging_dir(&parent_fd, &tmp_name)?;

    // 2. If task class is Patch, copy pristine base tree to staging directory first
    if class == TaskClass::Patch {
        copy_base_tree(base_dir, &staging_fd)?;
    }

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

    // 4. Processing loop
    let mut records_received = 0u64;
    let mut files_accepted = 0u64;
    let mut directories_accepted = 0u64;
    let mut deletions_accepted = 0u64;
    let mut total_bytes_accepted = 0u64;
    let mut total_stream_file_bytes = 0u64;
    let mut paths_dropped = 0u64;
    let mut paths_restored = 0u64;

    let mut declared_files: HashSet<String> = HashSet::new();
    let mut declared_directories: HashSet<String> = HashSet::new();
    let mut all_seen_paths: HashSet<String> = HashSet::new();
    let mut case_folded_map: HashMap<String, String> = HashMap::new();

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
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
                Err(e) => return Err(ExtractError::Io(e)),
            }

            break;
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
        if path_len > config.max_path_bytes {
            return Err(ExtractError::Format(FormatError::OversizedField {
                field: "path_len",
                size: path_len,
                cap: config.max_path_bytes,
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
        if components.len() > config.max_path_depth {
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

        // Case-fold collision check
        let lower = path_str.to_lowercase();
        if let Some(existing) = case_folded_map.get(&lower) {
            report_flags.push(ReportFlag {
                flag_type: "case_fold_collision".to_string(),
                path: path_str.to_string(),
                detail: format!("collides with '{existing}' under case-folding"),
            });
        }
        case_folded_map.insert(lower, path_str.to_string());

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
            total_stream_file_bytes = total_stream_file_bytes.saturating_add(header.size);
            if total_stream_file_bytes > config.max_total_bytes {
                return Err(ExtractError::Quota(QuotaError::TotalBytesExceeded {
                    total: total_stream_file_bytes,
                    cap: config.max_total_bytes,
                }));
            }
        }

        if header.record_type == RecordType::RegularFile {
            if files_accepted + 1 > config.max_file_count {
                return Err(ExtractError::Quota(QuotaError::FileCountExceeded {
                    count: files_accepted + 1,
                    cap: config.max_file_count,
                }));
            }
        } else if header.record_type == RecordType::Directory
            && directories_accepted + 1 > config.max_dir_count
        {
            return Err(ExtractError::Quota(QuotaError::DirCountExceeded {
                count: directories_accepted + 1,
                cap: config.max_dir_count,
            }));
        }

        // -------------------------------------------------------------------
        // Test infrastructure checks (whole path drop and restore)
        // -------------------------------------------------------------------
        if let Some(reason) = is_whole_path_test_infra(path_str, &config.test_paths) {
            paths_dropped += 1;
            report_dropped.push(DroppedPath {
                path: path_str.to_string(),
                reason: reason.to_string(),
            });

            // Stream and discard payload, verifying SHA-256 and size
            PayloadStreamer::discard_and_hash(reader, header.size, header.sha256, path_str)
                .map_err(ExtractError::Format)?;

            // If it exists in base, record it as restored
            if base_dir.join(path_str).exists() {
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
        if is_section_restored_file(path_str) {
            let mut payload = vec![0u8; header.size as usize];
            reader.read_exact(&mut payload).map_err(|_e| {
                ExtractError::Format(FormatError::Truncated("incomplete section file payload"))
            })?;

            let mut hasher = Sha256::new();
            hasher.update(&payload);
            let actual_hash: [u8; 32] = hasher.finalize().into();
            if actual_hash != header.sha256 {
                return Err(ExtractError::Format(FormatError::HashMismatch {
                    path: path_str.to_string(),
                    declared: format_hex(&header.sha256),
                    actual: format_hex(&actual_hash),
                }));
            }

            let agent_text = std::str::from_utf8(&payload).ok();
            let base_file_path = base_dir.join(path_str);
            let base_text = std::fs::read_to_string(&base_file_path).ok();

            match agent_text {
                Some(agent_str) => {
                    match restore_file_sections(path_str, base_text.as_deref(), agent_str) {
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
                            if base_file_path.exists() {
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
                            if !base_dir.join(path_str).exists() {
                                new_files.push(path_str.to_string());
                            }
                        }
                    }
                }
                None => {
                    // Non-UTF-8: conservative rule restores whole file from base
                    if base_file_path.exists() {
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
                let (p_fd, leaf) = resolve_or_create_parent_dir(&staging_fd, path_str)?;
                delete_entry(&p_fd, &leaf)?;
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
                )
                .map_err(ExtractError::Format)?;

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

                if !base_dir.join(path_str).exists() {
                    new_files.push(path_str.to_string());
                }
            }
            RecordType::EndOfStream => unreachable!(),
        }
    }

    // 5. Shadowing checks for new files
    for new_path in &new_files {
        if let Some(flag) =
            check_shadowing(new_path, &config.import_roots, &config.installed_packages)
        {
            report_flags.push(flag);
        }
    }

    // 6. Tree manifest generation
    let staging_proc_path = format!("/proc/self/fd/{}", staging_fd.as_raw_fd());
    let (tree_manifest_sha256, tree_file_count, tree_total_bytes) =
        generate_tree_manifest(Path::new(&staging_proc_path)).map_err(ExtractError::Io)?;

    // 7. Atomic publication
    publish_atomically(&parent_fd, &tmp_name, &out_name)?;
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
