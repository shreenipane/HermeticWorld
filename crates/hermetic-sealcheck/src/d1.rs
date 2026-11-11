use std::collections::{HashSet, VecDeque};
use std::path::Path;

use crate::benchmark::check_d9_content;
use crate::containers::scan_container_or_unit_with_root_prefix;
use crate::fingerprint::FingerprintSet;
use crate::gitstore::{compute_git_sha1, is_hex_oid, GitError, GitStore, ObjectType, Tag};
use crate::scan::{match_unit, Finding, ScanOptions, Severity};

pub fn scan_git_repo(git_dir: &Path, fp: &FingerprintSet, opts: &ScanOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    let git_dir_str = git_dir.display().to_string();

    let gate_finding = |channel: &str, p: String, ev: String| Finding {
        detector: "D1".into(),
        channel: channel.into(),
        path: p,
        visibility: opts.visibility,
        severity: Severity::Gate,
        confidence: 1.0,
        hunk: None,
        evidence: vec![ev],
    };

    // 1. Check config file
    let config_path = git_dir.join("config");
    findings.extend(check_git_config(&config_path, &git_dir_str, opts));

    // 2. Check state files
    findings.extend(check_git_state_files(git_dir, opts));

    // 3. Check shallow
    let shallow_path = git_dir.join("shallow");
    if shallow_path.is_file() {
        findings.push(Finding {
            detector: "D1".into(),
            channel: "git_shallow".into(),
            path: shallow_path.display().to_string(),
            visibility: opts.visibility,
            severity: Severity::Info,
            confidence: 1.0,
            hunk: None,
            evidence: vec!["shallow file present".into()],
        });
    }

    // 4. Check unknown files in objects/
    let objects_dir = git_dir.join("objects");
    findings.extend(check_unknown_files_in_objects(&objects_dir, opts));

    // 5. Open GitStore
    let mut store = match GitStore::open(git_dir, opts) {
        Ok(s) => s,
        Err(GitError::Unsupported(msg)) => {
            findings.push(gate_finding("git_unsupported", git_dir_str.clone(), msg));
            return findings;
        }
        Err(GitError::Corrupt(msg)) => {
            findings.push(gate_finding("git_corrupt", git_dir_str.clone(), msg));
            return findings;
        }
        Err(e) => {
            findings.push(gate_finding(
                "git_corrupt",
                git_dir_str.clone(),
                format!("failed to open git store: {e}"),
            ));
            return findings;
        }
    };

    // 6. Check base commit presence
    let base_commit = match &opts.base_commit {
        Some(bc) if !bc.is_empty() => bc.to_lowercase(),
        _ => {
            findings.push(gate_finding(
                "git_base_missing",
                git_dir_str.clone(),
                "base commit not specified".into(),
            ));
            return findings;
        }
    };

    let all_object_ids = match store.enumerate_object_ids() {
        Ok(ids) => ids,
        Err(e) => {
            findings.push(gate_finding(
                "git_corrupt",
                git_dir_str.clone(),
                format!("failed to enumerate object ids: {e}"),
            ));
            return findings;
        }
    };

    if !all_object_ids.contains(&base_commit) {
        findings.push(gate_finding(
            "git_base_missing",
            git_dir_str.clone(),
            format!("base commit {} is not in the store", base_commit),
        ));
        return findings;
    }

    // 7. Read refs (loose and packed)
    let (all_refs, invalid_refs) = read_all_refs(git_dir);
    for (ref_name, why) in invalid_refs {
        findings.push(gate_finding("git_ref", ref_name, why));
    }

    // 8. Resolve HEAD and check git_head
    let head_path = git_dir.join("HEAD");
    let resolved_head = resolve_head(&head_path, &all_refs);
    match resolved_head {
        Some(head_oid) if head_oid == base_commit => {}
        Some(head_oid) => {
            findings.push(gate_finding(
                "git_head",
                head_path.display().to_string(),
                format!(
                    "HEAD resolves to {} instead of base commit {}",
                    head_oid, base_commit
                ),
            ));
        }
        None => {
            findings.push(gate_finding(
                "git_head",
                head_path.display().to_string(),
                "HEAD cannot be resolved".into(),
            ));
        }
    }

    // 9. Ancestor walk from base commit to populate ancestors set
    let mut ancestors = HashSet::new();
    let mut commit_walk_queue = VecDeque::new();
    commit_walk_queue.push_back(base_commit.clone());

    while let Some(c_oid) = commit_walk_queue.pop_front() {
        if !ancestors.insert(c_oid.clone()) {
            continue;
        }
        if let Ok(obj) = store.read_object(&c_oid) {
            if obj.obj_type == ObjectType::Commit {
                if let Ok(commit) = store.parse_commit(&obj.data) {
                    for parent in commit.parents {
                        commit_walk_queue.push_back(parent.to_lowercase());
                    }
                }
            }
        }
    }

    // 10. Validate refs and identify allowed tags
    let mut allowed_tags: Vec<AllowedTag> = Vec::new();

    for (ref_name, ref_oid) in &all_refs {
        if ref_name.starts_with("refs/heads/") {
            if ref_oid != &base_commit {
                findings.push(gate_finding(
                    "git_ref",
                    ref_name.clone(),
                    format!(
                        "branch {} points to {} instead of base commit {}",
                        ref_name, ref_oid, base_commit
                    ),
                ));
            }
        } else if let Some(tag_name) = ref_name.strip_prefix("refs/tags/") {
            // Check §6.1 tag rule
            match check_tag(
                &mut store,
                ref_oid,
                tag_name,
                &ancestors,
                opts.t_clock,
                fp,
                opts,
            ) {
                Ok(allowed_tag) => {
                    allowed_tags.push(allowed_tag);
                }
                Err(tag_finding) => {
                    findings.push(*tag_finding);
                }
            }
        } else {
            // Any other ref: refs/pull/*, refs/original/*, refs/stash, refs/notes/*, remote refs, etc.
            findings.push(gate_finding(
                "git_ref",
                ref_name.clone(),
                format!("unallowed ref: {}", ref_name),
            ));
        }
    }

    // 11. Reachability walk from base_commit and allowed tags
    let mut reachable = HashSet::new();
    let mut commit_queue = VecDeque::new();
    let mut tree_queue = VecDeque::new();

    // Mark tag objects as reachable, and queue their targets
    for tag in &allowed_tags {
        for tag_obj in &tag.tag_objects {
            reachable.insert(tag_obj.clone());
        }
        match tag.target_type {
            ObjectType::Commit => commit_queue.push_back(tag.target_oid.clone()),
            ObjectType::Tree => tree_queue.push_back(tag.target_oid.clone()),
            ObjectType::Blob | ObjectType::Tag => {
                reachable.insert(tag.target_oid.clone());
            }
        }
    }

    commit_queue.push_back(base_commit.clone());

    // Walk commits
    while let Some(c_oid) = commit_queue.pop_front() {
        if !reachable.insert(c_oid.clone()) {
            continue;
        }

        let obj = match store.read_object(&c_oid) {
            Ok(o) => o,
            Err(e) => {
                findings.push(gate_finding(
                    "git_corrupt",
                    git_dir_str.clone(),
                    format!("failed to read commit {}: {}", c_oid, e),
                ));
                continue;
            }
        };

        if compute_git_sha1(obj.obj_type, &obj.data) != c_oid {
            findings.push(gate_finding(
                "git_corrupt",
                git_dir_str.clone(),
                format!("hash mismatch for commit {}", c_oid),
            ));
        }

        match store.parse_commit(&obj.data) {
            Ok(commit) => {
                tree_queue.push_back(commit.tree.to_lowercase());
                for parent in commit.parents {
                    commit_queue.push_back(parent.to_lowercase());
                }
            }
            Err(e) => findings.push(gate_finding(
                "git_corrupt",
                git_dir_str.clone(),
                format!("failed to parse commit {}: {}", c_oid, e),
            )),
        }
    }

    // Walk trees
    while let Some(t_oid) = tree_queue.pop_front() {
        if !reachable.insert(t_oid.clone()) {
            continue;
        }

        let obj = match store.read_object(&t_oid) {
            Ok(o) => o,
            Err(e) => {
                findings.push(gate_finding(
                    "git_corrupt",
                    git_dir_str.clone(),
                    format!("failed to read tree {}: {}", t_oid, e),
                ));
                continue;
            }
        };

        if compute_git_sha1(obj.obj_type, &obj.data) != t_oid {
            findings.push(gate_finding(
                "git_corrupt",
                git_dir_str.clone(),
                format!("hash mismatch for tree {}", t_oid),
            ));
        }

        match store.parse_tree(&obj.data) {
            Ok(tree) => {
                for entry in tree.entries {
                    let entry_oid = entry.oid.to_lowercase();
                    if entry.mode == 0o160000 {
                        // Gitlink mode 160000: recorded and not followed
                        reachable.insert(entry_oid);
                    } else if entry.mode & 0o170000 == 0o040000 {
                        tree_queue.push_back(entry_oid);
                    } else {
                        reachable.insert(entry_oid);
                    }
                }
            }
            Err(e) => findings.push(gate_finding(
                "git_corrupt",
                git_dir_str.clone(),
                format!("failed to parse tree {}: {}", t_oid, e),
            )),
        }
    }

    // 12. Find unreachable objects
    let mut unreachable_ids: Vec<String> = all_object_ids
        .into_iter()
        .filter(|id| !reachable.contains(id))
        .collect();
    unreachable_ids.sort();

    if !unreachable_ids.is_empty() {
        let count = unreachable_ids.len();
        let preview: Vec<String> = unreachable_ids.iter().take(20).cloned().collect();
        findings.push(gate_finding(
            "git_unreachable_object",
            git_dir_str.clone(),
            format!("{} unreachable object(s): {}", count, preview.join(", ")),
        ));

        // Unreachable content scan (TR-SC-6)
        for oid in &unreachable_ids {
            let item_path = format!("{}#{}", git_dir_str, oid);
            if let Ok(obj) = store.read_object(oid) {
                match obj.obj_type {
                    ObjectType::Blob => {
                        if compute_git_sha1(ObjectType::Blob, &obj.data) != *oid {
                            findings.push(gate_finding(
                                "git_corrupt",
                                git_dir_str.clone(),
                                format!("hash mismatch for unreachable blob {}", oid),
                            ));
                        }
                        let unit_findings = scan_container_or_unit_with_root_prefix(
                            &item_path,
                            &obj.data,
                            fp,
                            &opts.signatures,
                            opts,
                            0,
                        );
                        findings.extend(unit_findings);
                    }
                    ObjectType::Commit => {
                        if let Ok(commit) = store.parse_commit(&obj.data) {
                            findings.extend(check_d9_content(
                                &item_path,
                                &commit.message,
                                &opts.signatures,
                                opts.visibility,
                            ));
                            findings.extend(match_unit(
                                &commit.message,
                                fp,
                                opts,
                                "D2",
                                "commit_message",
                                &item_path,
                            ));
                        }
                    }
                    ObjectType::Tag => {
                        if let Ok(tag) = store.parse_tag(&obj.data) {
                            findings.extend(check_d9_content(
                                &item_path,
                                &tag.message,
                                &opts.signatures,
                                opts.visibility,
                            ));
                            findings.extend(match_unit(
                                &tag.message,
                                fp,
                                opts,
                                "D2",
                                "tag_message",
                                &item_path,
                            ));
                        }
                    }
                    ObjectType::Tree => {}
                }
            }
        }
    }

    // 13. LFS objects must be referenced by the base tree
    findings.extend(check_lfs_objects(git_dir, &mut store, &base_commit, opts));

    // 14. Check commit-graph
    findings.extend(check_commit_graphs(git_dir, &reachable, opts));

    findings
}

struct AllowedTag {
    tag_objects: Vec<String>,
    target_oid: String,
    target_type: ObjectType,
}

fn check_tag(
    store: &mut GitStore,
    tag_oid: &str,
    tag_name: &str,
    ancestors: &HashSet<String>,
    t_clock: Option<time::OffsetDateTime>,
    fp: &FingerprintSet,
    opts: &ScanOptions,
) -> Result<AllowedTag, Box<Finding>> {
    let gate_finding = |ev: String| {
        Box::new(Finding {
            detector: "D1".into(),
            channel: "git_tag".into(),
            path: format!("refs/tags/{}", tag_name),
            visibility: opts.visibility,
            severity: Severity::Gate,
            confidence: 1.0,
            hunk: None,
            evidence: vec![ev],
        })
    };

    let obj = match store.read_object(tag_oid) {
        Ok(o) => o,
        Err(_) => return Err(gate_finding("tag object not found in store".into())),
    };

    match obj.obj_type {
        ObjectType::Commit => {
            // Lightweight tag pointing directly to a commit
            if !ancestors.contains(tag_oid) {
                return Err(gate_finding(format!(
                    "tag points to non-ancestor commit {}",
                    tag_oid
                )));
            }
            Ok(AllowedTag {
                tag_objects: Vec::new(),
                target_oid: tag_oid.to_string(),
                target_type: ObjectType::Commit,
            })
        }
        ObjectType::Tag => {
            // Recompute tag id
            if compute_git_sha1(obj.obj_type, &obj.data) != tag_oid {
                return Err(Box::new(Finding {
                    detector: "D1".into(),
                    channel: "git_corrupt".into(),
                    path: format!("refs/tags/{}", tag_name),
                    visibility: opts.visibility,
                    severity: Severity::Gate,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![format!("hash mismatch for tag {}", tag_oid)],
                }));
            }

            // Annotated tag object
            let tag = match store.parse_tag(&obj.data) {
                Ok(t) => t,
                Err(e) => return Err(gate_finding(format!("failed to parse tag object: {e}"))),
            };

            // Every annotated tag in a chain must pass the date and message rules
            let tag_problem = |t: &Tag| -> Option<String> {
                match (t.tagger_time, t_clock) {
                    (None, _) => return Some("annotated tag has no tagger date".into()),
                    (Some(ts), Some(tc)) if ts > tc.unix_timestamp() => {
                        return Some(format!(
                            "annotated tagger date {} is after T_clock {}",
                            ts,
                            tc.unix_timestamp()
                        ));
                    }
                    _ => {}
                }
                let path = format!("refs/tags/{}", tag_name);
                if match_unit(&t.message, fp, opts, "D1", "git_tag", &path).is_empty() {
                    None
                } else {
                    Some("tag message matches leaked fingerprint".into())
                }
            };
            if let Some(problem) = tag_problem(&tag) {
                return Err(gate_finding(problem));
            }

            // Peel target to verify ancestor
            let mut tag_objects = vec![tag_oid.to_string()];
            let mut current_target = tag.target_oid.to_lowercase();
            let mut current_type = tag.target_type;

            loop {
                if current_type == ObjectType::Commit && ancestors.contains(&current_target) {
                    break;
                }
                match store.read_object(&current_target) {
                    Ok(next_obj) if next_obj.obj_type == ObjectType::Tag => {
                        tag_objects.push(current_target.clone());
                        if compute_git_sha1(next_obj.obj_type, &next_obj.data) != current_target {
                            return Err(Box::new(Finding {
                                detector: "D1".into(),
                                channel: "git_corrupt".into(),
                                path: format!("refs/tags/{}", tag_name),
                                visibility: opts.visibility,
                                severity: Severity::Gate,
                                confidence: 1.0,
                                hunk: None,
                                evidence: vec![format!(
                                    "hash mismatch for intermediate tag {}",
                                    current_target
                                )],
                            }));
                        }
                        if let Ok(next_tag) = store.parse_tag(&next_obj.data) {
                            if let Some(problem) = tag_problem(&next_tag) {
                                return Err(gate_finding(problem));
                            }
                            current_target = next_tag.target_oid.to_lowercase();
                            current_type = next_tag.target_type;
                        } else {
                            return Err(gate_finding(format!(
                                "peeled tag points to non-ancestor {}",
                                current_target
                            )));
                        }
                    }
                    _ => {
                        return Err(gate_finding(format!(
                            "tag points to non-ancestor {}",
                            current_target
                        )));
                    }
                }
            }

            Ok(AllowedTag {
                tag_objects,
                target_oid: current_target,
                target_type: current_type,
            })
        }
        _ => Err(gate_finding("tag points to unsupported object type".into())),
    }
}

fn check_git_config(config_path: &Path, gitdir: &str, opts: &ScanOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !config_path.is_file() {
        return findings;
    }

    let text = match std::fs::read_to_string(config_path) {
        Ok(t) => t,
        Err(_) => return findings,
    };

    let mut in_remote_section = false;
    let mut in_extensions_section = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = trimmed[1..trimmed.len() - 1].trim();
            if section.to_ascii_lowercase().starts_with("remote") {
                in_remote_section = true;
                findings.push(Finding {
                    detector: "D1".into(),
                    channel: "git_config".into(),
                    path: config_path.display().to_string(),
                    visibility: opts.visibility,
                    severity: Severity::Gate,
                    confidence: 1.0,
                    hunk: None,
                    evidence: vec![format!("remote section found: {}", trimmed)],
                });
            } else {
                in_remote_section = false;
            }

            in_extensions_section = section.eq_ignore_ascii_case("extensions");
        }

        if in_extensions_section && trimmed.to_ascii_lowercase().starts_with("objectformat") {
            if let Some((_, val)) = trimmed.split_once('=') {
                if val.trim().eq_ignore_ascii_case("sha256") {
                    findings.push(Finding {
                        detector: "D1".into(),
                        channel: "git_unsupported".into(),
                        path: gitdir.to_string(),
                        visibility: opts.visibility,
                        severity: Severity::Review,
                        confidence: 1.0,
                        hunk: None,
                        evidence: vec!["extensions.objectformat = sha256".into()],
                    });
                }
            }
        }

        // Check for embedded credentials in URLs: ://[^/@\s]+@
        if let Some(pos) = trimmed.find("://") {
            let rest = &trimmed[pos + 3..];
            if let Some(at_pos) = rest.find('@') {
                let user_info = &rest[..at_pos];
                if !user_info.is_empty() && !user_info.contains('/') && !user_info.contains(' ') {
                    findings.push(Finding {
                        detector: "D1".into(),
                        channel: "git_config".into(),
                        path: config_path.display().to_string(),
                        visibility: opts.visibility,
                        severity: Severity::Gate,
                        confidence: 1.0,
                        hunk: None,
                        evidence: vec!["URL with embedded credentials in config".into()],
                    });
                }
            }
        }
    }

    let _ = in_remote_section;
    findings
}

fn check_git_state_files(git_dir: &Path, opts: &ScanOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    let gate_finding = |p: String, ev: String| Finding {
        detector: "D1".into(),
        channel: "git_state_file".into(),
        path: p,
        visibility: opts.visibility,
        severity: Severity::Gate,
        confidence: 1.0,
        hunk: None,
        evidence: vec![ev],
    };

    // 1. logs/ holding any file
    let logs_dir = git_dir.join("logs");
    if logs_dir.is_dir() {
        let has_files = walkdir::WalkDir::new(&logs_dir)
            .into_iter()
            .flatten()
            .any(|e| e.file_type().is_file());
        if has_files {
            findings.push(gate_finding(
                logs_dir.display().to_string(),
                "logs/ directory contains reflog files".into(),
            ));
        }
    }

    // 2. State files
    let state_file_names = [
        "FETCH_HEAD",
        "ORIG_HEAD",
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
    ];
    for name in state_file_names {
        let p = git_dir.join(name);
        if p.is_file() {
            findings.push(gate_finding(
                p.display().to_string(),
                format!("{} exists", name),
            ));
        }
    }

    // 3. worktrees/
    let wt_dir = git_dir.join("worktrees");
    if wt_dir.is_dir() {
        if let Ok(mut rd) = std::fs::read_dir(&wt_dir) {
            if rd.next().is_some() {
                findings.push(gate_finding(
                    wt_dir.display().to_string(),
                    "worktrees/ directory contains entries".into(),
                ));
            }
        }
    }

    // 4. modules/ holding a repository
    let modules_dir = git_dir.join("modules");
    if modules_dir.is_dir() {
        let has_repo = walkdir::WalkDir::new(&modules_dir)
            .into_iter()
            .flatten()
            .any(|e| e.file_type().is_file() && e.file_name() == "HEAD");
        if has_repo {
            findings.push(gate_finding(
                modules_dir.display().to_string(),
                "modules/ directory holds a repository".into(),
            ));
        }
    }

    // 5. objects/info/alternates
    let alternates = git_dir.join("objects").join("info").join("alternates");
    if alternates.is_file() {
        findings.push(gate_finding(
            alternates.display().to_string(),
            "objects/info/alternates file exists".into(),
        ));
    }

    findings
}

/// Collect the sha256 ids named by LFS pointer files in the tree at `base_commit`.
fn lfs_pointer_ids(store: &mut GitStore, base_commit: &str) -> HashSet<String> {
    let mut ids = HashSet::new();
    let root = store
        .read_object(base_commit)
        .ok()
        .and_then(|o| store.parse_commit(&o.data).ok())
        .map(|c| c.tree.to_lowercase());
    let mut queue: VecDeque<String> = root.into_iter().collect();
    let mut seen = HashSet::new();
    while let Some(oid) = queue.pop_front() {
        if !seen.insert(oid.clone()) {
            continue;
        }
        let Ok(obj) = store.read_object(&oid) else {
            continue;
        };
        match obj.obj_type {
            ObjectType::Tree => {
                if let Ok(tree) = store.parse_tree(&obj.data) {
                    for entry in tree.entries {
                        if entry.mode != 0o160000 {
                            queue.push_back(entry.oid.to_lowercase());
                        }
                    }
                }
            }
            ObjectType::Blob if obj.data.starts_with(b"version https://git-lfs") => {
                let text = String::from_utf8_lossy(&obj.data);
                if let Some(id) = text.lines().find_map(|l| l.strip_prefix("oid sha256:")) {
                    ids.insert(id.trim().to_lowercase());
                }
            }
            _ => {}
        }
    }
    ids
}

fn check_lfs_objects(
    git_dir: &Path,
    store: &mut GitStore,
    base_commit: &str,
    opts: &ScanOptions,
) -> Vec<Finding> {
    let lfs_dir = git_dir.join("lfs").join("objects");
    let files: Vec<_> = walkdir::WalkDir::new(&lfs_dir)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .collect();
    if files.is_empty() {
        return Vec::new();
    }

    let referenced = lfs_pointer_ids(store, base_commit);
    files
        .iter()
        .filter(|e| !referenced.contains(&e.file_name().to_string_lossy().to_lowercase()))
        .map(|e| Finding {
            detector: "D1".into(),
            channel: "git_state_file".into(),
            path: e.path().display().to_string(),
            visibility: opts.visibility,
            severity: Severity::Gate,
            confidence: 1.0,
            hunk: None,
            evidence: vec!["LFS object not referenced by the base tree".into()],
        })
        .collect()
}

fn check_unknown_files_in_objects(objects_dir: &Path, opts: &ScanOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !objects_dir.is_dir() {
        return findings;
    }

    for entry in walkdir::WalkDir::new(objects_dir).into_iter().flatten() {
        if entry.file_type().is_dir() {
            continue;
        }

        let path = entry.path();
        let rel = match path.strip_prefix(objects_dir) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let parts: Vec<&str> = rel_str.split('/').collect();

        let is_allowed = (entry.file_type().is_file()
            && parts.len() == 2
            && parts[0].len() == 2
            && parts[1].len() == 38
            && parts[0].chars().all(|c| c.is_ascii_hexdigit())
            && parts[1].chars().all(|c| c.is_ascii_hexdigit()))
            || (parts.len() == 2 && parts[0] == "pack" && is_valid_pack_file(path))
            || (rel_str == "info/packs" && is_valid_info_packs(path))
            || rel_str == "info/commit-graph"
            || rel_str.starts_with("info/commit-graphs/")
            || rel_str == "commit-graph"
            || rel_str.starts_with("commit-graphs/");

        if !is_allowed {
            findings.push(Finding {
                detector: "D1".into(),
                channel: "git_unknown_file".into(),
                path: path.display().to_string(),
                visibility: opts.visibility,
                severity: Severity::Gate,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!("unknown file under objects: {}", rel_str)],
            });
        }
    }

    findings
}

/// A pack-directory file is valid when it's named `pack-<40 hex>.<ext>`, has the magic of
/// its format, and its `.pack` and `.idx` both exist. Anything else could hide content,
/// because the ordinary walk skips `objects/`.
fn is_valid_pack_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    let magic: &[u8; 4] = match ext {
        "pack" => b"PACK",
        "idx" => b"\xfftOc",
        "rev" => b"RIDX",
        "mtimes" => b"MTME",
        _ => return false,
    };
    let Some(hash) = stem.strip_prefix("pack-") else {
        return false;
    };
    if hash.len() != 40 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    if !path.with_extension("pack").is_file() || !path.with_extension("idx").is_file() {
        return false;
    }
    let mut head = [0u8; 4];
    let magic_ok = std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
        .is_ok()
        && &head == magic;
    if !magic_ok {
        return false;
    }

    // .rev and .mtimes have a fixed size, so nothing can be appended to them unnoticed.
    if ext == "rev" || ext == "mtimes" {
        let Some(count) = pack_object_count(&path.with_extension("pack")) else {
            return false;
        };
        return path
            .metadata()
            .is_ok_and(|m| m.len() == 12 + 4 * count + 40);
    }
    true
}

fn pack_object_count(pack: &Path) -> Option<u64> {
    let mut header = [0u8; 12];
    std::fs::File::open(pack)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut header))
        .ok()?;
    Some(u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as u64)
}

/// `objects/info/packs` is either empty or lines of `P pack-<hex>.pack`.
fn is_valid_info_packs(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    String::from_utf8_lossy(&bytes).lines().all(|line| {
        let line = line.trim();
        line.is_empty()
            || line
                .strip_prefix("P pack-")
                .and_then(|l| l.strip_suffix(".pack"))
                .is_some_and(is_hex_oid)
    })
}

type NamedRefs = Vec<(String, String)>;

/// Returns the valid refs, and the name and reason for each malformed or symbolic one.
fn read_all_refs(git_dir: &Path) -> (NamedRefs, NamedRefs) {
    let mut all_refs = Vec::new();
    let mut invalid = Vec::new();

    // 1. Loose refs
    let refs_dir = git_dir.join("refs");
    if refs_dir.is_dir() {
        for entry in walkdir::WalkDir::new(&refs_dir).into_iter().flatten() {
            if entry.file_type().is_file() {
                let path = entry.path();
                if let Ok(rel) = path.strip_prefix(git_dir) {
                    let ref_name = rel.to_string_lossy().replace('\\', "/");
                    let content = std::fs::read(path).unwrap_or_default();
                    let text = String::from_utf8_lossy(&content);
                    let trimmed = text.trim();
                    if is_hex_oid(trimmed) {
                        all_refs.push((ref_name, trimmed.to_lowercase()));
                    } else {
                        invalid.push((ref_name, "ref is symbolic or malformed".to_string()));
                    }
                }
            }
        }
    }

    // 2. Packed refs
    let packed_refs_path = git_dir.join("packed-refs");
    if packed_refs_path.is_file() {
        if let Ok(content) = std::fs::read_to_string(&packed_refs_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('^') {
                    continue;
                }
                match trimmed.split_once(' ') {
                    Some((oid, ref_name)) if is_hex_oid(oid.trim()) => {
                        let oid_clean = oid.trim().to_lowercase();
                        let ref_clean = ref_name.trim().to_string();
                        // Only add if not already present from loose
                        if !all_refs.iter().any(|(r, _)| r == &ref_clean) {
                            all_refs.push((ref_clean, oid_clean));
                        }
                    }
                    _ => invalid.push((
                        "packed-refs".to_string(),
                        format!(
                            "malformed line: {}",
                            trimmed.chars().take(80).collect::<String>()
                        ),
                    )),
                }
            }
        }
    }

    (all_refs, invalid)
}

fn resolve_head(head_path: &Path, all_refs: &[(String, String)]) -> Option<String> {
    let content = std::fs::read_to_string(head_path).ok()?;
    let trimmed = content.trim();

    if let Some(ref_target) = trimmed.strip_prefix("ref: ") {
        let target_name = ref_target.trim();
        for (name, oid) in all_refs {
            if name == target_name {
                return Some(oid.clone());
            }
        }
        None
    } else if trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(trimmed.to_lowercase())
    } else {
        None
    }
}

fn check_commit_graphs(
    git_dir: &Path,
    reachable: &HashSet<String>,
    opts: &ScanOptions,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut candidates = Vec::new();
    let p1 = git_dir.join("objects").join("info").join("commit-graph");
    if p1.is_file() {
        candidates.push(p1);
    }
    let p2 = git_dir.join("objects").join("commit-graph");
    if p2.is_file() {
        candidates.push(p2);
    }
    let p3 = git_dir.join("commit-graph");
    if p3.is_file() {
        candidates.push(p3);
    }
    for dir in &[
        git_dir.join("objects").join("info").join("commit-graphs"),
        git_dir.join("objects").join("commit-graphs"),
        git_dir.join("commit-graphs"),
    ] {
        if dir.is_dir() {
            for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
                if entry.file_type().is_file() {
                    if entry.file_name() == "commit-graph-chain" {
                        findings.extend(check_commit_graph_chain(entry.path(), opts));
                    } else {
                        candidates.push(entry.into_path());
                    }
                }
            }
        }
    }

    for path in &candidates {
        if path.is_file() {
            if let Ok(bytes) = std::fs::read(path) {
                match parse_commit_graph_oidl(&bytes) {
                    Ok(oids) => {
                        let mut unreachable_graph_oids = Vec::new();
                        for oid in oids {
                            if !reachable.contains(&oid) {
                                unreachable_graph_oids.push(oid);
                            }
                        }
                        if !unreachable_graph_oids.is_empty() {
                            findings.push(Finding {
                                detector: "D1".into(),
                                channel: "git_commit_graph".into(),
                                path: path.display().to_string(),
                                visibility: opts.visibility,
                                severity: Severity::Gate,
                                confidence: 1.0,
                                hunk: None,
                                evidence: vec![format!(
                                    "commit-graph contains unreachable commit(s): {}",
                                    unreachable_graph_oids.join(", ")
                                )],
                            });
                        }
                    }
                    Err(e) => {
                        findings.push(Finding {
                            detector: "D1".into(),
                            channel: "git_commit_graph".into(),
                            path: path.display().to_string(),
                            visibility: opts.visibility,
                            severity: Severity::Gate,
                            confidence: 1.0,
                            hunk: None,
                            evidence: vec![format!("corrupt commit graph: {e}")],
                        });
                    }
                }
            }
        }
    }

    findings
}

/// The chain file of a split commit-graph is a list of graph hashes, one per line.
fn check_commit_graph_chain(path: &Path, opts: &ScanOptions) -> Option<Finding> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let dir = path.parent()?;
    let bad = text
        .lines()
        .map(str::trim)
        .find(|line| !is_hex_oid(line) || !dir.join(format!("graph-{line}.graph")).is_file())?;
    Some(Finding {
        detector: "D1".into(),
        channel: "git_commit_graph".into(),
        path: path.display().to_string(),
        visibility: opts.visibility,
        severity: Severity::Gate,
        confidence: 1.0,
        hunk: None,
        evidence: vec![format!(
            "invalid commit-graph chain line: {}",
            bad.chars().take(80).collect::<String>()
        )],
    })
}

fn parse_commit_graph_oidl(bytes: &[u8]) -> Result<Vec<String>, GitError> {
    if bytes.len() < 8 || &bytes[0..4] != b"CGPH" {
        return Err(GitError::Corrupt("invalid commit graph magic".into()));
    }

    let num_chunks = bytes[6] as usize;
    let chunk_table_start = 8;
    let chunk_table_len = (num_chunks + 1) * 12;

    if chunk_table_start + chunk_table_len > bytes.len() {
        return Err(GitError::Corrupt(
            "truncated commit graph chunk table".into(),
        ));
    }

    let mut chunks = Vec::new();
    for i in 0..=num_chunks {
        let entry_offset = chunk_table_start + i * 12;
        let chunk_id = &bytes[entry_offset..entry_offset + 4];
        let offset = u64::from_be_bytes(
            bytes[entry_offset + 4..entry_offset + 12]
                .try_into()
                .map_err(|_| GitError::Corrupt("chunk offset read error".into()))?,
        );
        chunks.push((chunk_id.to_vec(), offset));
    }

    let mut oidl_range = None;
    for i in 0..num_chunks {
        if &chunks[i].0 == b"OIDL" {
            oidl_range = Some((chunks[i].1 as usize, chunks[i + 1].1 as usize));
            break;
        }
    }

    let mut oids = Vec::new();
    if let Some((start, end)) = oidl_range {
        if start > bytes.len() || end > bytes.len() || start > end {
            return Err(GitError::Corrupt("invalid OIDL chunk offsets".into()));
        }
        for chunk in bytes[start..end].as_chunks::<20>().0 {
            oids.push(hex::encode(chunk));
        }
    }

    Ok(oids)
}
