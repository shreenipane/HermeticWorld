#![forbid(unsafe_code)]
//! Cross-crate tests: streams written by the guest agent must be accepted by the host
//! validator (`hermetic-extract`), and tampered agent streams must be refused.

use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use hermetic_extract::config::{ExtractConfig, TaskClass as HostClass};
use hermetic_extract::error::{ExtractError as HostError, FormatError};
use hermetic_extract::format::{StreamEncoder, RECORD_HEADER_SIZE as HOST_HEADER_SIZE};
use hermetic_extract::validator::validate_stream;
use hermetic_extract_agent::stream::RECORD_HEADER_SIZE;
use hermetic_extract_agent::{
    decode, extract, parse_task_class, Caps, ExtractError, Record, TaskClass,
};
use tempfile::TempDir;

fn write(path: &Path, content: &[u8], mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// Snapshot of a tree: relative path -> Some((exec bit, bytes)) for files, None for dirs.
fn snapshot(root: &Path) -> BTreeMap<String, Option<(bool, Vec<u8>)>> {
    fn rec(root: &Path, dir: &Path, out: &mut BTreeMap<String, Option<(bool, Vec<u8>)>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                out.insert(rel, None);
                rec(root, &path, out);
            } else {
                assert!(meta.is_file(), "unexpected entry type at {rel}");
                let exec = meta.permissions().mode() & 0o111 != 0;
                out.insert(rel, Some((exec, fs::read(&path).unwrap())));
            }
        }
    }
    let mut out = BTreeMap::new();
    rec(root, root, &mut out);
    out
}

struct Fixture {
    _tmp: TempDir,
    base: std::path::PathBuf,
    work: std::path::PathBuf,
    scratch: std::path::PathBuf,
}

/// Base and work trees covering new, modified, unchanged, executable, deleted files,
/// a deleted directory, a new nested directory and a new empty directory.
fn fixture() -> Fixture {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base");
    let work = tmp.path().join("work");
    let scratch = tmp.path().join("scratch");
    for d in [&base, &work, &scratch] {
        fs::create_dir_all(d).unwrap();
    }
    write(&base.join("keep.txt"), b"same\n", 0o644);
    write(&base.join("mod.py"), b"def f():\n    return 1\n", 0o644);
    write(&base.join("gone.txt"), b"bye\n", 0o644);
    write(&base.join("olddir/inner.txt"), b"old\n", 0o644);
    write(&base.join("pkg/a.txt"), b"a\n", 0o644);

    write(&work.join("keep.txt"), b"same\n", 0o644);
    write(&work.join("mod.py"), b"def f():\n    return 2\n", 0o644);
    write(&work.join("pkg/a.txt"), b"a\n", 0o644);
    write(&work.join("pkg/run.sh"), b"#!/bin/sh\necho hi\n", 0o755);
    write(&work.join("newdir/sub/new.txt"), b"fresh\n", 0o644);
    fs::create_dir_all(work.join("emptydir")).unwrap();
    // Ignored by the agent at any depth.
    write(&work.join(".git/HEAD"), b"ref: refs/heads/main\n", 0o644);
    Fixture {
        _tmp: tmp,
        base,
        work,
        scratch,
    }
}

fn agent_stream(fx: &Fixture, class: &TaskClass) -> Vec<u8> {
    let mut stream = Vec::new();
    extract(&fx.base, &fx.work, class, &Caps::default(), &mut stream).unwrap();
    stream
}

fn root_config() -> ExtractConfig {
    ExtractConfig {
        repo_dir: Some(String::new()),
        ..ExtractConfig::default()
    }
}

fn validate(fx: &Fixture, stream: &[u8], name: &str) -> Result<(), HostError> {
    let out = fx.scratch.join(name);
    validate_stream(
        &mut Cursor::new(stream),
        &fx.base,
        &out,
        HostClass::Patch,
        &root_config(),
    )
    .map(|_| ())
}

#[test]
fn agent_stream_validates_and_publishes_work_tree() {
    let fx = fixture();
    let stream = agent_stream(&fx, &parse_task_class("patch:").unwrap());

    let out = fx.scratch.join("published");
    let report = validate_stream(
        &mut Cursor::new(&stream),
        &fx.base,
        &out,
        HostClass::Patch,
        &root_config(),
    )
    .expect("host validator must accept the agent stream");

    let mut expected = snapshot(&fx.work);
    expected.retain(|k, _| k != ".git" && !k.starts_with(".git/"));
    let published = snapshot(&out);
    assert_eq!(published, expected);
    assert!(!published.contains_key("gone.txt"));
    assert!(!published.contains_key("olddir"));
    assert!(published["pkg/run.sh"].as_ref().unwrap().0);
    assert!(!published["mod.py"].as_ref().unwrap().0);

    // Totals agree with the agent's own decoding of the same bytes.
    let records = decode(&stream[..]).unwrap();
    let Some(Record::End {
        record_count,
        total_bytes,
    }) = records.last()
    else {
        panic!("missing end record");
    };
    assert_eq!(report.totals.records_received, record_count + 1);
    assert_eq!(report.totals.total_bytes_accepted, *total_bytes);
}

#[test]
fn agent_subdirectory_stream_validates_with_matching_repo_dir() {
    let fx = fixture();
    let stream = agent_stream(&fx, &parse_task_class("patch:pkg").unwrap());
    let out = fx.scratch.join("published");
    let config = ExtractConfig {
        repo_dir: Some("pkg".to_string()),
        ..ExtractConfig::default()
    };
    validate_stream(
        &mut Cursor::new(&stream),
        &fx.base,
        &out,
        HostClass::Patch,
        &config,
    )
    .unwrap();
    let published = snapshot(&out);
    assert_eq!(
        published["pkg/run.sh"],
        Some((true, b"#!/bin/sh\necho hi\n".to_vec()))
    );
    // Outside the repo directory the base is kept as is.
    assert!(published.contains_key("gone.txt"));
}

#[test]
fn agent_bytes_equal_host_encoder_bytes() {
    let fx = fixture();
    let stream = agent_stream(&fx, &parse_task_class("patch:").unwrap());
    assert_eq!(RECORD_HEADER_SIZE, HOST_HEADER_SIZE);

    let mut host = Vec::new();
    StreamEncoder::write_stream_header(&mut host).unwrap();
    for record in decode(&stream[..]).unwrap() {
        match record {
            Record::File {
                path, mode, data, ..
            } => StreamEncoder::write_file(&mut host, &path, mode, &data).unwrap(),
            Record::Dir { path, mode } => {
                StreamEncoder::write_directory(&mut host, &path, mode).unwrap()
            }
            Record::Delete { path } => StreamEncoder::write_deletion(&mut host, &path).unwrap(),
            Record::End {
                record_count,
                total_bytes,
            } => StreamEncoder::write_end(&mut host, record_count, total_bytes).unwrap(),
        }
    }
    assert_eq!(stream, host);
}

#[test]
fn tampered_agent_stream_is_refused() {
    let fx = fixture();
    let stream = agent_stream(&fx, &parse_task_class("patch:").unwrap());
    validate(&fx, &stream, "clean").unwrap();

    let records = decode(&stream[..]).unwrap();
    // Locate the first file record: its header start and its payload start.
    let (file_record_start, first_file_payload_offset) = {
        let mut off = 8usize;
        let mut found = None;
        for r in &records {
            match r {
                Record::File { path, .. } => {
                    found = Some((off, off + RECORD_HEADER_SIZE + path.len()));
                    break;
                }
                Record::Dir { path, .. } | Record::Delete { path } => {
                    off += RECORD_HEADER_SIZE + path.len();
                }
                Record::End { .. } => break,
            }
        }
        found.expect("fixture has a file record")
    };

    // Flipped payload byte: SHA-256 mismatch.
    let mut flipped = stream.clone();
    flipped[first_file_payload_offset] ^= 0x01;
    assert!(matches!(
        validate(&fx, &flipped, "flip-payload"),
        Err(HostError::Format(FormatError::HashMismatch { .. }))
    ));
    assert!(!fx.scratch.join("flip-payload").join("keep.txt").exists());

    // Flipped declared hash byte.
    let mut flipped = stream.clone();
    flipped[file_record_start + 28] ^= 0x80;
    assert!(matches!(
        validate(&fx, &flipped, "flip-hash"),
        Err(HostError::Format(FormatError::HashMismatch { .. }))
    ));

    // Flipped magic, version, flags and reserved bytes.
    for (idx, name) in [
        (0, "flip-magic"),
        (4, "flip-version"),
        (9, "flip-flags"),
        (10, "flip-reserved"),
    ] {
        let mut flipped = stream.clone();
        flipped[idx] ^= 0x01;
        assert!(validate(&fx, &flipped, name).is_err(), "{name} accepted");
    }

    // Flipped end-record count and total bytes.
    let end = stream.len() - RECORD_HEADER_SIZE;
    for (idx, name) in [(end + 12, "flip-total"), (end + 20, "flip-count")] {
        let mut flipped = stream.clone();
        flipped[idx] ^= 0x01;
        assert!(matches!(
            validate(&fx, &flipped, name),
            Err(HostError::Format(
                FormatError::TotalBytesMismatch { .. } | FormatError::CountMismatch { .. }
            ))
        ));
    }

    // Truncated at every offset.
    for cut in 0..stream.len() {
        assert!(
            validate(&fx, &stream[..cut], &format!("cut-{cut}")).is_err(),
            "truncated stream at {cut} accepted"
        );
    }

    // Extra trailing bytes.
    let mut trailing = stream.clone();
    trailing.push(0);
    assert!(matches!(
        validate(&fx, &trailing, "trailing"),
        Err(HostError::Format(FormatError::TrailingGarbage))
    ));
}

#[test]
fn tree_root_spelling_is_one_representation_on_both_sides() {
    // Agent: the root is `patch:`; `.` is refused with a typed error.
    assert_eq!(
        parse_task_class("patch:").unwrap(),
        TaskClass::Patch {
            repo_dir: String::new()
        }
    );
    for bad in ["patch:.", "patch:./", "patch:/"] {
        assert!(matches!(
            parse_task_class(bad),
            Err(ExtractError::InvalidTaskClass { .. })
        ));
    }
    // Validator: the root is `repo_dir: ""`; `.` is refused with a typed config error.
    assert!(root_config().validate().is_ok());
    for bad in [".", "./", "/"] {
        let config = ExtractConfig {
            repo_dir: Some(bad.to_string()),
            ..ExtractConfig::default()
        };
        assert!(matches!(config.validate(), Err(HostError::Config(_))));
    }
}
