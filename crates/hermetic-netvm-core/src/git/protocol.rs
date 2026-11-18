#![forbid(unsafe_code)]

//! Git Smart Transfer Protocol v2 engine for upload-pack.
//!
//! Implements protocol v2 capability advertisement, `ls-refs`, and `fetch` with
//! shallow/deepen support, serving only objects reachable from the sealed repository binding.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use hermetic_netvm_http::pkt_line::{
    parse_pkt_line, write_delim, write_flush, write_pkt_line, write_sideband_data, PktLine,
    BAND_DATA, MAX_REQUEST_PKT_LINES,
};

use super::pack::build_packfile;
use super::repo::{parse_commit_parents, parse_commit_tree, parse_tree_entries, SealedRepoBinding};
use super::types::{is_hex_oid, GitError, ObjectType};

pub const MAX_WANTS: usize = 256;
pub const MAX_HAVES: usize = 1024;
pub const MAX_SHALLOWS: usize = 256;
pub const MAX_PREFIXES: usize = 64;
pub const MAX_DEPTH: u32 = 10_000;

/// Generates the standard Git Protocol v2 capability advertisement.
pub fn capability_advertisement() -> Vec<u8> {
    let mut out = Vec::new();
    // "# service=git-upload-pack\n" followed by flush
    let _ = write_pkt_line(&mut out, b"# service=git-upload-pack\n");
    write_flush(&mut out);
    // Protocol v2 capabilities
    let _ = write_pkt_line(&mut out, b"version 2\n");
    let _ = write_pkt_line(&mut out, b"agent=hermetic-world/1\n");
    let _ = write_pkt_line(&mut out, b"ls-refs\n");
    let _ = write_pkt_line(&mut out, b"fetch=shallow\n");
    let _ = write_pkt_line(&mut out, b"object-format=sha1\n");
    write_flush(&mut out);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPackRequest {
    pub command: String,
    pub wants: Vec<String>,
    pub haves: Vec<String>,
    pub shallows: Vec<String>,
    pub deepen: Option<u32>,
    pub deepen_since: Option<i64>,
    pub deepen_not: Vec<String>,
    pub prefixes: Vec<String>,
    pub peel: bool,
    pub symrefs: bool,
    pub done: bool,
}

/// Parses a Git protocol v2 upload-pack request body.
pub fn parse_upload_pack_request(mut body: &[u8]) -> Result<UploadPackRequest, GitError> {
    let mut command: Option<String> = None;
    let mut wants = Vec::new();
    let mut haves = Vec::new();
    let mut shallows = Vec::new();
    let mut deepen = None;
    let mut deepen_since = None;
    let mut deepen_not = Vec::new();
    let mut prefixes = Vec::new();
    let mut peel = false;
    let mut symrefs = false;
    let mut done = false;

    let mut line_count = 0usize;
    let mut in_args = false;

    while !body.is_empty() {
        line_count = line_count.saturating_add(1);
        if line_count > MAX_REQUEST_PKT_LINES {
            return Err(GitError::LimitExceeded("too many pkt-lines in request".into()));
        }

        let (pkt, consumed) = parse_pkt_line(body).map_err(|e| GitError::Protocol(e.to_string()))?;
        body = &body[consumed..];

        match pkt {
            PktLine::Delimiter => {
                in_args = true;
            }
            PktLine::Flush | PktLine::ResponseEnd => {
                break;
            }
            PktLine::Data(data) => {
                let text = std::str::from_utf8(data)
                    .map_err(|_| GitError::Protocol("non-utf8 pkt-line data".into()))?
                    .trim_end_matches(['\n', '\r']);

                if !in_args {
                    if let Some(cmd) = text.strip_prefix("command=") {
                        if command.is_some() {
                            return Err(GitError::Protocol("duplicate command in request".into()));
                        }
                        command = Some(cmd.to_string());
                    }
                } else {
                    let cmd_name = command.as_deref().unwrap_or_default();
                    match cmd_name {
                        "ls-refs" => {
                            if text == "peel" {
                                peel = true;
                            } else if text == "symrefs" {
                                symrefs = true;
                            } else if let Some(prefix) = text.strip_prefix("ref-prefix ") {
                                if prefixes.len() >= MAX_PREFIXES {
                                    return Err(GitError::LimitExceeded("too many ref prefixes".into()));
                                }
                                prefixes.push(prefix.trim().to_string());
                            }
                        }
                        "fetch" => {
                            if let Some(want) = text.strip_prefix("want ") {
                                let w = want.trim();
                                if !is_hex_oid(w) {
                                    return Err(GitError::Protocol(format!("invalid want oid: {w}")));
                                }
                                if wants.len() >= MAX_WANTS {
                                    return Err(GitError::LimitExceeded("too many wants".into()));
                                }
                                wants.push(w.to_string());
                            } else if let Some(have) = text.strip_prefix("have ") {
                                let h = have.trim();
                                if !is_hex_oid(h) {
                                    return Err(GitError::Protocol(format!("invalid have oid: {h}")));
                                }
                                if haves.len() >= MAX_HAVES {
                                    return Err(GitError::LimitExceeded("too many haves".into()));
                                }
                                haves.push(h.to_string());
                            } else if let Some(shallow) = text.strip_prefix("shallow ") {
                                let s = shallow.trim();
                                if !is_hex_oid(s) {
                                    return Err(GitError::Protocol(format!("invalid shallow oid: {s}")));
                                }
                                if shallows.len() >= MAX_SHALLOWS {
                                    return Err(GitError::LimitExceeded("too many shallows".into()));
                                }
                                shallows.push(s.to_string());
                            } else if let Some(d_str) = text.strip_prefix("deepen ") {
                                let d: u32 = d_str
                                    .trim()
                                    .parse()
                                    .map_err(|_| GitError::Protocol("invalid deepen depth".into()))?;
                                if d == 0 || d > MAX_DEPTH {
                                    return Err(GitError::Protocol(format!(
                                        "deepen depth must be between 1 and {MAX_DEPTH}"
                                    )));
                                }
                                deepen = Some(d);
                            } else if let Some(ds_str) = text.strip_prefix("deepen-since ") {
                                let ds: i64 = ds_str
                                    .trim()
                                    .parse()
                                    .map_err(|_| GitError::Protocol("invalid deepen-since timestamp".into()))?;
                                deepen_since = Some(ds);
                            } else if let Some(dn) = text.strip_prefix("deepen-not ") {
                                deepen_not.push(dn.trim().to_string());
                            } else if text == "done" {
                                done = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    let cmd = command.ok_or_else(|| GitError::Protocol("missing command in protocol v2 request".into()))?;
    if cmd != "ls-refs" && cmd != "fetch" {
        return Err(GitError::Protocol(format!("unsupported protocol v2 command: {cmd}")));
    }

    Ok(UploadPackRequest {
        command: cmd,
        wants,
        haves,
        shallows,
        deepen,
        deepen_since,
        deepen_not,
        prefixes,
        peel,
        symrefs,
        done,
    })
}

/// Executes `command=ls-refs` against a sealed repository binding.
pub fn handle_ls_refs(
    repo: &SealedRepoBinding,
    req: &UploadPackRequest,
) -> Result<Vec<u8>, GitError> {
    let mut out = Vec::new();

    for (refname, oid) in &repo.refs {
        let matches_prefix = if req.prefixes.is_empty() {
            true
        } else {
            req.prefixes.iter().any(|prefix| refname.starts_with(prefix))
        };

        if !matches_prefix {
            continue;
        }

        let mut line = if req.symrefs && refname == "HEAD" {
            if let Some(ref target) = repo.head_symref {
                format!("{oid} {refname} symref-target:{target}")
            } else {
                format!("{oid} {refname}")
            }
        } else {
            format!("{oid} {refname}")
        };

        if req.peel {
            // If it's an annotated tag, check peeled commit
            if let Ok(obj) = repo.read_object(oid) {
                if obj.obj_type == ObjectType::Tag {
                    let text = String::from_utf8_lossy(&obj.data);
                    for l in text.lines() {
                        if let Some(target) = l.strip_prefix("object ") {
                            let peeled = target.trim();
                            if is_hex_oid(peeled) {
                                line.push_str(&format!(" peeled:{peeled}"));
                                break;
                            }
                        }
                    }
                }
            }
        }

        line.push('\n');
        write_pkt_line(&mut out, line.as_bytes()).map_err(|e| GitError::Protocol(e.to_string()))?;
    }

    write_flush(&mut out);
    Ok(out)
}

/// Executes `command=fetch` with shallow/deepen against a sealed repository binding.
///
/// Refuses any requested object that is not reachable from the sealed repository binding.
pub fn handle_fetch(
    repo: &SealedRepoBinding,
    req: &UploadPackRequest,
) -> Result<Vec<u8>, GitError> {
    if req.wants.is_empty() {
        return Err(GitError::Protocol("fetch command missing wants".into()));
    }

    // 1. Strict Reachability Check: every single want MUST be in reachable_commits
    for want in &req.wants {
        if !repo.is_reachable_commit(want) {
            return Err(GitError::Unreachable(format!(
                "requested want {want} is not reachable from sealed repository binding"
            )));
        }
    }

    // 2. Ancestor depth traversal for shallow/deepen
    let depth_limit = req.deepen.unwrap_or(u32::MAX);

    let mut visited_commits: HashSet<String> = HashSet::new();
    let mut commit_depths: HashMap<String, u32> = HashMap::new();
    let mut queue: VecDeque<(String, u32)> = VecDeque::new();

    for want in &req.wants {
        visited_commits.insert(want.clone());
        commit_depths.insert(want.clone(), 1);
        queue.push_back((want.clone(), 1));
    }

    let mut shallow_roots: BTreeSet<String> = BTreeSet::new();

    while let Some((current_oid, current_depth)) = queue.pop_front() {
        let commit_obj = repo.read_object(&current_oid)?;
        let parents = parse_commit_parents(&commit_obj.data);

        if current_depth < depth_limit {
            for parent in parents {
                if visited_commits.insert(parent.clone()) {
                    let next_depth = current_depth.saturating_add(1);
                    commit_depths.insert(parent.clone(), next_depth);
                    queue.push_back((parent, next_depth));
                }
            }
        } else {
            // At the depth limit: parents are NOT traversed or sent.
            // If this commit has parents, it becomes a shallow root!
            if !parents.is_empty() {
                shallow_roots.insert(current_oid);
            }
        }
    }

    // Unshallow commits: commits client claimed as shallow that are now deepened past
    let mut unshallow_commits: BTreeSet<String> = BTreeSet::new();
    for client_shallow in &req.shallows {
        if visited_commits.contains(client_shallow) && !shallow_roots.contains(client_shallow) {
            unshallow_commits.insert(client_shallow.clone());
        }
    }

    // 3. Object Collection: commits, trees, blobs
    let mut collected_objects: BTreeMap<String, (ObjectType, Vec<u8>)> = BTreeMap::new();
    let mut tree_queue: VecDeque<String> = VecDeque::new();

    // Collect commits
    for commit_oid in &visited_commits {
        let obj = repo.read_object(commit_oid)?;
        let tree_oid = parse_commit_tree(&obj.data)?;
        tree_queue.push_back(tree_oid);
        collected_objects.insert(commit_oid.clone(), (obj.obj_type, obj.data));
    }

    // Collect trees and blobs recursively
    let mut visited_trees: HashSet<String> = HashSet::new();
    while let Some(tree_oid) = tree_queue.pop_front() {
        if !visited_trees.insert(tree_oid.clone()) {
            continue;
        }

        let tree_obj = repo.read_object(&tree_oid)?;
        let entries = parse_tree_entries(&tree_obj.data)?;
        collected_objects.insert(tree_oid, (tree_obj.obj_type, tree_obj.data));

        for entry in entries {
            if entry.is_tree {
                tree_queue.push_back(entry.oid);
            } else if !collected_objects.contains_key(&entry.oid) {
                let blob_obj = repo.read_object(&entry.oid)?;
                collected_objects.insert(entry.oid, (blob_obj.obj_type, blob_obj.data));
            }
        }
    }

    // 4. Generate packfile
    let pack_items: Vec<(ObjectType, &[u8])> = collected_objects
        .values()
        .map(|(t, d)| (*t, d.as_slice()))
        .collect();
    let pack_bytes = build_packfile(&pack_items)?;

    // 5. Encode protocol v2 response
    let mut out = Vec::new();

    if req.deepen.is_some() || !req.shallows.is_empty() {
        write_pkt_line(&mut out, b"shallow-info\n").map_err(|e| GitError::Protocol(e.to_string()))?;
        for shallow in &shallow_roots {
            let line = format!("shallow {shallow}\n");
            write_pkt_line(&mut out, line.as_bytes()).map_err(|e| GitError::Protocol(e.to_string()))?;
        }
        for unshallow in &unshallow_commits {
            let line = format!("unshallow {unshallow}\n");
            write_pkt_line(&mut out, line.as_bytes()).map_err(|e| GitError::Protocol(e.to_string()))?;
        }
        write_delim(&mut out);
    }

    write_pkt_line(&mut out, b"packfile\n").map_err(|e| GitError::Protocol(e.to_string()))?;
    write_sideband_data(&mut out, BAND_DATA, &pack_bytes)
        .map_err(|e| GitError::Protocol(e.to_string()))?;
    write_flush(&mut out);

    Ok(out)
}
