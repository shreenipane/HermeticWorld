#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Cursor, Read};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use hermetic_extract::config::{ExtractConfig, TaskClass};
use hermetic_extract::error::{ExtractError, FormatError, PathError, QuotaError};
use hermetic_extract::format::{RecordHeader, RecordType, StreamEncoder};
use hermetic_extract::validator::{validate_stream, MAX_SECTION_BYTES, MAX_STREAM_RECORDS};
use tempfile::tempdir;

fn stream_file(path: &str, data: &[u8]) -> Vec<u8> {
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, path, 0o644, data).unwrap();
    StreamEncoder::write_end(&mut stream, 1, data.len() as u64).unwrap();
    stream
}

fn assert_empty(path: &Path) {
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

#[test]
fn section_length_is_capped_before_payload_read_or_allocation() {
    let base = tempdir().unwrap();
    let parent = tempdir().unwrap();
    let out = parent.path().join("out");
    fs::create_dir(&out).unwrap();
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    let header = RecordHeader {
        record_type: RecordType::RegularFile,
        flags: 0,
        reserved: [0, 0],
        path_len: 9,
        mode: 0o644,
        size: u64::MAX,
        record_count: 0,
        sha256: [0; 32],
    };
    stream.extend_from_slice(&header.to_bytes());
    stream.extend_from_slice(b"setup.cfg");
    let config = ExtractConfig {
        max_file_bytes: u64::MAX,
        max_total_bytes: u64::MAX,
        ..Default::default()
    };
    assert!(matches!(
        validate_stream(
            &mut Cursor::new(stream),
            base.path(),
            &out,
            TaskClass::Patch,
            &config
        ),
        Err(ExtractError::Quota(QuotaError::ResourceLimit(
            "MAX_SECTION_BYTES"
        )))
    ));
    assert_empty(&out);
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
}

#[test]
fn path_allocation_has_a_hard_cap_even_with_unlimited_config() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    let header = RecordHeader {
        record_type: RecordType::RegularFile,
        flags: 0,
        reserved: [0, 0],
        path_len: u32::MAX,
        mode: 0o644,
        size: 0,
        record_count: 0,
        sha256: [0; 32],
    };
    stream.extend_from_slice(&header.to_bytes());
    let config = ExtractConfig {
        max_path_bytes: usize::MAX,
        ..Default::default()
    };
    assert!(matches!(
        validate_stream(
            &mut Cursor::new(stream),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config
        ),
        Err(ExtractError::Format(FormatError::OversizedField {
            field: "path_len",
            ..
        }))
    ));
}

#[test]
fn dropped_files_and_directories_count_at_exact_quota_boundary() {
    for directory in [false, true] {
        for count in [1, 2] {
            let base = tempdir().unwrap();
            let out = tempdir().unwrap();
            let mut stream = Vec::new();
            StreamEncoder::write_stream_header(&mut stream).unwrap();
            for i in 0..count {
                if directory {
                    StreamEncoder::write_directory(&mut stream, &format!("p{i}.egg-info"), 0o755)
                        .unwrap();
                } else {
                    StreamEncoder::write_file(&mut stream, &format!("p{i}.pth"), 0o644, b"")
                        .unwrap();
                }
            }
            StreamEncoder::write_end(&mut stream, count, 0).unwrap();
            let config = ExtractConfig {
                max_file_count: 1,
                max_dir_count: 1,
                ..Default::default()
            };
            let result = validate_stream(
                &mut Cursor::new(stream),
                base.path(),
                out.path(),
                TaskClass::Patch,
                &config,
            );
            if count == 1 {
                assert_eq!(result.unwrap().dropped.len(), 1);
            } else if directory {
                assert!(matches!(
                    result,
                    Err(ExtractError::Quota(QuotaError::DirCountExceeded { .. }))
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(ExtractError::Quota(QuotaError::FileCountExceeded { .. }))
                ));
            }
        }
    }
}

#[test]
fn implicit_directories_count_at_exact_quota_boundary() {
    for cap in [1, 2] {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let config = ExtractConfig {
            max_dir_count: cap,
            ..Default::default()
        };
        let result = validate_stream(
            &mut Cursor::new(stream_file("a/b/file", b"x")),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        );
        if cap == 2 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(ExtractError::Quota(QuotaError::DirCountExceeded {
                    count: 2,
                    cap: 1
                }))
            ));
        }
    }
}

#[test]
fn deletion_records_have_a_named_cap() {
    for count in [MAX_STREAM_RECORDS, MAX_STREAM_RECORDS + 1] {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        for i in 0..count {
            StreamEncoder::write_deletion(&mut stream, &format!("absent{i}")).unwrap();
        }
        StreamEncoder::write_end(&mut stream, count, 0).unwrap();
        let result = validate_stream(
            &mut Cursor::new(stream),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &ExtractConfig::default(),
        );
        if count == MAX_STREAM_RECORDS {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(ExtractError::Quota(QuotaError::ResourceLimit(
                    "MAX_STREAM_RECORDS"
                )))
            ));
        }
    }
}

#[test]
fn test_directory_descendants_and_ancestor_deletions_are_protected() {
    for target in ["pkg", "pkg/tests", "pkg/tests/test_it.py"] {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        fs::create_dir_all(base.path().join("pkg/tests")).unwrap();
        fs::write(base.path().join("pkg/tests/test_it.py"), "pristine").unwrap();
        let config = ExtractConfig {
            test_paths: vec!["pkg/tests".into()],
            ..Default::default()
        };
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_deletion(&mut stream, target).unwrap();
        StreamEncoder::write_end(&mut stream, 1, 0).unwrap();
        let report = validate_stream(
            &mut Cursor::new(stream),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(out.path().join("pkg/tests/test_it.py")).unwrap(),
            "pristine"
        );
        assert_eq!(report.dropped[0].path, target);
    }
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    let config = ExtractConfig {
        test_paths: vec!["tests".into()],
        ..Default::default()
    };
    let report = validate_stream(
        &mut Cursor::new(stream_file("tests/new.py", b"evil")),
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap();
    assert_eq!(report.dropped.len(), 1);
    assert_empty(out.path());
}

#[test]
fn builtin_protected_descendant_survives_parent_deletion() {
    for filename in [
        "conftest.py",
        "pyproject.toml",
        "setup.cfg",
        "p.dist-info/entry_points.txt",
    ] {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let path = base.path().join("pkg").join(filename);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "pristine").unwrap();
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_deletion(&mut stream, "pkg").unwrap();
        StreamEncoder::write_end(&mut stream, 1, 0).unwrap();
        let report = validate_stream(
            &mut Cursor::new(stream),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &ExtractConfig::default(),
        )
        .unwrap();
        assert_eq!(report.dropped.len(), 1);
        assert_eq!(
            fs::read_to_string(out.path().join("pkg").join(filename)).unwrap(),
            "pristine"
        );
    }
}

#[test]
fn section_file_deletion_and_directory_records_cannot_replace_base() {
    for directory in [false, true] {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let original = "[metadata]\nname = base\n[tool:pytest]\naddopts = -q\n";
        fs::write(base.path().join("setup.cfg"), original).unwrap();
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        if directory {
            StreamEncoder::write_directory(&mut stream, "setup.cfg", 0o755).unwrap();
        } else {
            StreamEncoder::write_deletion(&mut stream, "setup.cfg").unwrap();
        }
        StreamEncoder::write_end(&mut stream, 1, 0).unwrap();
        let report = validate_stream(
            &mut Cursor::new(stream),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &ExtractConfig::default(),
        )
        .unwrap();
        assert_eq!(report.dropped.len(), 1);
        assert_eq!(
            fs::read_to_string(out.path().join("setup.cfg")).unwrap(),
            original
        );
    }
}

#[test]
fn artifact_restore_copies_actual_base_bytes() {
    for (name, agent) in [
        ("conftest.py", b"evil".as_slice()),
        ("setup.cfg", b"\xff".as_slice()),
    ] {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        fs::write(base.path().join(name), "pristine").unwrap();
        let config = ExtractConfig {
            artifact_paths: vec![name.into()],
            ..Default::default()
        };
        let report = validate_stream(
            &mut Cursor::new(stream_file(name, agent)),
            base.path(),
            out.path(),
            TaskClass::Artifact,
            &config,
        )
        .unwrap();
        assert_eq!(report.restored.len(), 1);
        assert_eq!(
            fs::read_to_string(out.path().join(name)).unwrap(),
            "pristine"
        );
    }
}

#[test]
fn ambiguous_toml_and_unparseable_base_restore_whole_file() {
    let base_text = "[project]\nname = 'base'\n[tool.pytest.ini_options]\naddopts = '-q'\n";
    for agent in [
        "[tool.'pytest'.ini_options]\naddopts = '--evil'\n",
        "[tool . pytest . ini_options]\naddopts = '--evil'\n",
        "tool.pytest.ini_options.addopts = '--evil'\n",
        "[tool]\npytest = { ini_options = { addopts = '--evil' } }\n",
        "[project.entry-points.'pytest11']\nevil = 'evil:main'\n",
        "[project]\nname = '''\n[tool.pytest.ini_options]\n'''\n",
    ] {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        fs::write(base.path().join("pyproject.toml"), base_text).unwrap();
        let report = validate_stream(
            &mut Cursor::new(stream_file("pyproject.toml", agent.as_bytes())),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &ExtractConfig::default(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(out.path().join("pyproject.toml")).unwrap(),
            base_text
        );
        assert!(report.restored[0].reason.contains("whole"));
    }
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    let ambiguous_base = "[tool.'pytest'.ini_options]\naddopts = '-q'\n";
    fs::write(base.path().join("pyproject.toml"), ambiguous_base).unwrap();
    validate_stream(
        &mut Cursor::new(stream_file("pyproject.toml", b"[project]\nname = 'edit'\n")),
        base.path(),
        out.path(),
        TaskClass::Patch,
        &ExtractConfig::default(),
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(out.path().join("pyproject.toml")).unwrap(),
        ambiguous_base
    );
}

#[test]
fn removed_ini_entry_point_section_is_recreated_and_case_alias_filtered() {
    for agent in [
        "[metadata]\nname = changed\n",
        "[options.entry_points]\nPyTest11 =\n    evil = evil:main\n",
    ] {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        fs::write(
            base.path().join("setup.cfg"),
            "[options.entry_points]\npytest11 =\n    good = good:main\n",
        )
        .unwrap();
        validate_stream(
            &mut Cursor::new(stream_file("setup.cfg", agent.as_bytes())),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &ExtractConfig::default(),
        )
        .unwrap();
        let result = fs::read_to_string(out.path().join("setup.cfg")).unwrap();
        assert!(result.contains("good = good:main"));
        assert!(!result.contains("evil"));
    }
}

#[test]
fn dropped_regular_file_declarations_still_block_descendant_paths() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "a.pth", 0o644, b"").unwrap();
    StreamEncoder::write_file(&mut stream, "a.pth/child", 0o644, b"").unwrap();
    StreamEncoder::write_end(&mut stream, 2, 0).unwrap();
    assert!(matches!(
        validate_stream(
            &mut Cursor::new(stream),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &ExtractConfig::default()
        ),
        Err(ExtractError::PathValidation(
            PathError::TraversesRegularFile { .. }
        ))
    ));
}

#[test]
fn component_base_and_unicode_case_collisions_are_reported() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    fs::create_dir(base.path().join("Pkg")).unwrap();
    fs::write(base.path().join("Pkg/base"), "base").unwrap();
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    for name in ["pkg/new", "STRASSE.py", "straße.py"] {
        StreamEncoder::write_file(&mut stream, name, 0o644, b"").unwrap();
    }
    StreamEncoder::write_end(&mut stream, 3, 0).unwrap();
    let report = validate_stream(
        &mut Cursor::new(stream),
        base.path(),
        out.path(),
        TaskClass::Patch,
        &ExtractConfig::default(),
    )
    .unwrap();
    assert!(report
        .flags
        .iter()
        .any(|f| f.path == "pkg" && f.flag_type == "case_fold_collision"));
    assert!(report
        .flags
        .iter()
        .any(|f| f.path == "straße.py" && f.flag_type == "case_fold_collision"));
}

#[test]
fn unknown_flags_are_rejected_including_end_record() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    for kind in [
        RecordType::RegularFile,
        RecordType::Directory,
        RecordType::Deletion,
        RecordType::EndOfStream,
    ] {
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        let header = RecordHeader {
            record_type: kind,
            flags: 1,
            reserved: [0, 0],
            path_len: 0,
            mode: 0,
            size: 0,
            record_count: 0,
            sha256: [0; 32],
        };
        stream.extend_from_slice(&header.to_bytes());
        assert!(matches!(
            validate_stream(
                &mut Cursor::new(stream),
                base.path(),
                out.path(),
                TaskClass::Patch,
                &ExtractConfig::default()
            ),
            Err(ExtractError::Format(_))
        ));
    }
}

#[test]
fn invalid_stream_header_does_not_create_output() {
    let base = tempdir().unwrap();
    let parent = tempdir().unwrap();
    let out = parent.path().join("out");
    assert!(validate_stream(
        &mut Cursor::new(b"BAD!\x01\0\0\0"),
        base.path(),
        &out,
        TaskClass::Patch,
        &ExtractConfig::default()
    )
    .is_err());
    assert_empty(parent.path());
}

#[test]
fn host_path_symlinks_are_rejected_at_every_component() {
    let parent = tempdir().unwrap();
    let base = parent.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("setup.cfg"), "[metadata]\nname = base\n").unwrap();
    let link = parent.path().join("link");
    symlink(&base, &link).unwrap();
    let out = tempdir().unwrap();
    let mut empty = Vec::new();
    StreamEncoder::write_stream_header(&mut empty).unwrap();
    StreamEncoder::write_end(&mut empty, 0, 0).unwrap();
    assert!(validate_stream(
        &mut Cursor::new(&empty),
        &link,
        out.path(),
        TaskClass::Patch,
        &ExtractConfig::default()
    )
    .is_err());
    assert!(validate_stream(
        &mut Cursor::new(&empty),
        &base,
        &link.join("out"),
        TaskClass::Patch,
        &ExtractConfig::default()
    )
    .is_err());
    assert!(!base.join("out").exists());
    assert!(ExtractConfig::load_from_file(link.join("setup.cfg")).is_err());
}

#[test]
fn base_depth_is_bounded_before_recursive_stack_growth() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    let mut dir = base.path().to_path_buf();
    for _ in 0..65 {
        dir.push("d");
        fs::create_dir(&dir).unwrap();
    }
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_end(&mut stream, 0, 0).unwrap();
    assert!(matches!(
        validate_stream(
            &mut Cursor::new(stream),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &ExtractConfig::default()
        ),
        Err(ExtractError::Quota(_))
    ));
    assert_empty(out.path());
}

struct BeforeEof<F: FnMut()> {
    cursor: Cursor<Vec<u8>>,
    callback: F,
    fired: bool,
}
impl<F: FnMut()> Read for BeforeEof<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.fired && self.cursor.position() == self.cursor.get_ref().len() as u64 {
            self.fired = true;
            (self.callback)();
        }
        self.cursor.read(buf)
    }
}

#[test]
fn replaced_destination_is_detected_before_publication() {
    let parent = tempdir().unwrap();
    let base = tempdir().unwrap();
    let out = parent.path().join("out");
    fs::create_dir(&out).unwrap();
    let mut reader = BeforeEof {
        cursor: Cursor::new(stream_file("file", b"x")),
        fired: false,
        callback: || {
            fs::rename(&out, parent.path().join("original")).unwrap();
            fs::create_dir(&out).unwrap();
        },
    };
    assert!(validate_stream(
        &mut reader,
        base.path(),
        &out,
        TaskClass::Patch,
        &ExtractConfig::default()
    )
    .is_err());
    assert_empty(&out);
    assert_empty(&parent.path().join("original"));
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 2);
}

#[test]
fn exclusive_file_creation_does_not_unlink_a_symlink() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    fs::write(&target, "secret").unwrap();
    symlink(&target, dir.path().join("link")).unwrap();
    let fd = hermetic_extract::safe_fs::open_dir_path(dir.path()).unwrap();
    assert!(hermetic_extract::safe_fs::create_file_exclusive(&fd, "link", 0o644).is_err());
    assert!(fs::symlink_metadata(dir.path().join("link"))
        .unwrap()
        .is_symlink());
    assert_eq!(fs::read_to_string(target).unwrap(), "secret");
}

#[test]
fn fixed_manifest_fixture_binds_empty_directories_and_escaped_paths() {
    use sha2::{Digest, Sha256};
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join("empty")).unwrap();
    fs::set_permissions(dir.path().join("empty"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(dir.path().join("a\nb"), b"").unwrap();
    fs::set_permissions(dir.path().join("a\nb"), fs::Permissions::from_mode(0o644)).unwrap();
    let manifest = concat!(
        "\"a\\nb\" 0644 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
        "\"empty\" 0755 0000000000000000000000000000000000000000000000000000000000000000\n"
    );
    let expected = hermetic_extract::format::format_hex(&Sha256::digest(manifest.as_bytes()));
    let (hash, count, bytes) =
        hermetic_extract::report::generate_tree_manifest(dir.path()).unwrap();
    assert_eq!(hash, expected);
    assert_eq!((count, bytes), (1, 0));
}

#[test]
fn section_cap_boundary_accepts_complete_payload() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    let mut data = vec![b'#'; MAX_SECTION_BYTES as usize];
    *data.last_mut().unwrap() = b'\n';
    assert!(validate_stream(
        &mut Cursor::new(stream_file("setup.cfg", &data)),
        base.path(),
        out.path(),
        TaskClass::Patch,
        &ExtractConfig::default()
    )
    .is_ok());
    let out = tempdir().unwrap();
    data.push(b'#');
    assert!(matches!(
        validate_stream(
            &mut Cursor::new(stream_file("setup.cfg", &data)),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &ExtractConfig::default()
        ),
        Err(ExtractError::Quota(QuotaError::ResourceLimit(
            "MAX_SECTION_BYTES"
        )))
    ));
}

#[test]
fn stdlib_inventory_is_fixed_sorted_and_covers_private_and_platform_modules() {
    let names: Vec<_> = include_str!("../src/data/python_stdlib_3_11.txt")
        .lines()
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    for name in [
        "__future__",
        "_io",
        "_ssl",
        "ntpath",
        "opcode",
        "pyexpat",
        "this",
        "json",
        "tomllib",
    ] {
        assert!(
            hermetic_extract::shadowing::check_shadowing(&format!("{name}.py"), &["".into()], &[])
                .is_some(),
            "{name}"
        );
    }
    for name in ["binhex", "formatter", "parser", "symbol"] {
        assert!(!names.contains(&name));
    }
}

#[test]
fn deleting_absent_descendant_does_not_create_directories() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_deletion(&mut stream, "absent/child").unwrap();
    StreamEncoder::write_end(&mut stream, 1, 0).unwrap();
    validate_stream(
        &mut Cursor::new(stream),
        base.path(),
        out.path(),
        TaskClass::Patch,
        &ExtractConfig::default(),
    )
    .unwrap();
    assert_empty(out.path());
}

#[test]
fn payload_io_errors_are_operational_errors() {
    use hermetic_extract::format::PayloadStreamer;
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }
    struct Full;
    impl io::Write for Full {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::StorageFull))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let error = PayloadStreamer::stream_to_writer(&mut Broken, 1, [0; 32], &mut io::sink(), "file")
        .unwrap_err();
    assert!(!error.is_rejection());
    let error =
        PayloadStreamer::stream_to_writer(&mut Cursor::new(b"x"), 1, [0; 32], &mut Full, "file")
            .unwrap_err();
    assert!(!error.is_rejection());
}

#[test]
fn empty_report_has_literal_known_answer_json() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_end(&mut stream, 0, 0).unwrap();
    let report = validate_stream(
        &mut Cursor::new(stream),
        base.path(),
        out.path(),
        TaskClass::State,
        &ExtractConfig::default(),
    )
    .unwrap();
    assert_eq!(serde_json::to_string(&report).unwrap(), concat!(
        "{\"accepted\":[],\"dropped\":[],\"restored\":[],\"flags\":[],\"totals\":{",
        "\"records_received\":1,\"files_accepted\":0,\"directories_accepted\":0,\"deletions_accepted\":0,",
        "\"total_bytes_accepted\":0,\"paths_dropped\":0,\"paths_restored\":0,\"tree_file_count\":0,\"tree_total_bytes\":0},",
        "\"tree_manifest_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}"));
}

#[test]
fn report_is_independent_of_record_order_and_host_output_path() {
    let base = tempdir().unwrap();
    let mut reports = Vec::new();
    for names in [["HELLO", "Hello", "hello"], ["hello", "Hello", "HELLO"]] {
        let out = tempdir().unwrap();
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        for name in names {
            StreamEncoder::write_file(&mut stream, name, 0o644, b"").unwrap();
        }
        StreamEncoder::write_end(&mut stream, 3, 0).unwrap();
        reports.push(
            validate_stream(
                &mut Cursor::new(stream),
                base.path(),
                out.path(),
                TaskClass::Patch,
                &ExtractConfig::default(),
            )
            .unwrap(),
        );
    }
    assert_eq!(reports[0], reports[1]);
}

#[test]
fn cleanup_guard_does_not_remove_a_preexisting_staging_collision() {
    if std::env::var_os("EXTRACT_COLLISION_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cleanup_guard_does_not_remove_a_preexisting_staging_collision",
            ])
            .env("EXTRACT_COLLISION_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let parent = tempdir().unwrap();
    let base = tempdir().unwrap();
    let out = parent.path().join("out");
    fs::create_dir(&out).unwrap();
    let collision = parent
        .path()
        .join(format!(".extract_tmp_{}_1", std::process::id()));
    fs::create_dir(&collision).unwrap();
    fs::write(collision.join("keep"), "keep").unwrap();
    assert!(validate_stream(
        &mut Cursor::new(stream_file("file", b"x")),
        base.path(),
        &out,
        TaskClass::Patch,
        &ExtractConfig::default()
    )
    .is_err());
    assert_eq!(fs::read_to_string(collision.join("keep")).unwrap(), "keep");
}

#[test]
fn modes_ignore_umask_in_isolated_process() {
    if std::env::var_os("EXTRACT_UMASK_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "modes_ignore_umask_in_isolated_process"])
            .env("EXTRACT_UMASK_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "a/plain", 0o7666, b"").unwrap();
    StreamEncoder::write_file(&mut stream, "a/exec", 0o7755, b"").unwrap();
    StreamEncoder::write_directory(&mut stream, "dir", 0o7777).unwrap();
    StreamEncoder::write_end(&mut stream, 3, 0).unwrap();
    validate_stream(
        &mut Cursor::new(stream),
        base.path(),
        out.path(),
        TaskClass::Patch,
        &ExtractConfig::default(),
    )
    .unwrap();
    for (path, mode) in [
        ("a/plain", 0o644),
        ("a/exec", 0o755),
        ("a", 0o755),
        ("dir", 0o755),
        ("", 0o755),
    ] {
        assert_eq!(
            fs::metadata(out.path().join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            mode
        );
    }
}

#[test]
fn invalid_configuration_paths_fail_before_touching_output() {
    let base = tempdir().unwrap();
    let parent = tempdir().unwrap();
    let out = parent.path().join("out");
    let config = ExtractConfig {
        test_paths: vec!["a/".repeat(5000)],
        ..Default::default()
    };
    assert!(matches!(
        validate_stream(
            &mut Cursor::new(stream_file("file", b"x")),
            base.path(),
            &out,
            TaskClass::Patch,
            &config
        ),
        Err(ExtractError::Config(_))
    ));
    assert_empty(parent.path());
}

#[test]
fn special_host_files_are_refused_without_blocking() {
    use hermetic_extract::safe_fs::{open_dir_path, open_regular_path};
    let base = tempdir().unwrap();
    let fd = open_dir_path(base.path()).unwrap();
    rustix::fs::mkfifoat(&fd, "fifo", rustix::fs::Mode::from_raw_mode(0o600)).unwrap();
    assert!(open_regular_path(&base.path().join("fifo")).is_err());
    assert!(ExtractConfig::load_from_file(base.path().join("fifo")).is_err());
    let out = tempdir().unwrap();
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_end(&mut stream, 0, 0).unwrap();
    assert!(validate_stream(
        &mut Cursor::new(stream),
        base.path(),
        out.path(),
        TaskClass::Patch,
        &ExtractConfig::default()
    )
    .is_err());
    assert_empty(out.path());
}

#[test]
fn ini_preserves_other_groups_and_same_indent_options() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();
    fs::write(
        base.path().join("setup.cfg"),
        "[options.entry_points]\n pytest11 =\n     good = good:main\n",
    )
    .unwrap();
    let agent = "[options.entry_points]\n pytest11 =\n     evil = evil:main\n pytest110 =\n     other = other:main\n console_scripts =\n     cli = cli:main\n";
    validate_stream(
        &mut Cursor::new(stream_file("setup.cfg", agent.as_bytes())),
        base.path(),
        out.path(),
        TaskClass::Patch,
        &ExtractConfig::default(),
    )
    .unwrap();
    let text = fs::read_to_string(out.path().join("setup.cfg")).unwrap();
    assert!(text.contains("good = good:main"));
    assert!(!text.contains("evil"));
    assert!(text.contains("pytest110 =\n     other = other:main"));
    assert!(text.contains("console_scripts =\n     cli = cli:main"));
}

#[test]
fn malformed_ini_options_restore_whole_base() {
    let original = "[metadata]\nname = pristine\n[tool:pytest]\naddopts = -q\n";
    for agent in [
        "[metadata]\nnot an option\n",
        "[metadata]\nname = a\nname = b\n",
        "[DEFAULT]\naddopts = evil\n",
    ] {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        fs::write(base.path().join("setup.cfg"), original).unwrap();
        validate_stream(
            &mut Cursor::new(stream_file("setup.cfg", agent.as_bytes())),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &ExtractConfig::default(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(out.path().join("setup.cfg")).unwrap(),
            original
        );
    }
}

#[test]
fn cli_redacts_host_paths_and_config_text_and_handles_non_utf8_args() {
    use std::os::unix::ffi::OsStringExt;
    use std::process::Command;
    let bin = env!("CARGO_BIN_EXE_hermetic-extract-validate");
    let parent = tempdir().unwrap();
    let config = parent.path().join("HOST_IDENTITY_SECRET.json");
    fs::write(&config, r#"{"task_class":"CONFIG_SECRET_TEXT"}"#).unwrap();
    let output = Command::new(bin)
        .args([
            "--stream", "unused", "--base", "unused", "--out", "unused", "--class", "patch",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.contains("HOST_IDENTITY_SECRET"));
    assert!(!error.contains("CONFIG_SECRET_TEXT"));
    assert!(!error.contains(parent.path().to_str().unwrap()));
    let output = Command::new(bin)
        .arg(std::ffi::OsString::from_vec(vec![0xff]))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
}

#[test]
fn invalid_utf8_and_bad_version_reach_the_validator_and_fail_closed() {
    let base = tempdir().unwrap();
    let parent = tempdir().unwrap();
    for bad_version in [false, true] {
        let out = parent.path().join("out");
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        if bad_version {
            stream[4..8].copy_from_slice(&2u32.to_le_bytes());
        } else {
            let header = RecordHeader {
                record_type: RecordType::RegularFile,
                flags: 0,
                reserved: [0, 0],
                path_len: 1,
                mode: 0o644,
                size: 0,
                record_count: 0,
                sha256: [0; 32],
            };
            stream.extend_from_slice(&header.to_bytes());
            stream.push(0xff);
        }
        let err = validate_stream(
            &mut Cursor::new(stream),
            base.path(),
            &out,
            TaskClass::Patch,
            &ExtractConfig::default(),
        )
        .unwrap_err();
        if bad_version {
            assert!(matches!(
                err,
                ExtractError::Format(FormatError::UnsupportedVersion(2))
            ));
        } else {
            assert!(matches!(
                err,
                ExtractError::Format(FormatError::InvalidUtf8Path)
            ));
            assert_empty(&out);
        }
        for entry in fs::read_dir(parent.path()).unwrap() {
            assert!(!entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .starts_with(".extract_tmp_"));
        }
    }
}

#[test]
fn protected_and_section_payloads_must_match_hash_and_size() {
    for name in ["conftest.py", "setup.cfg"] {
        for truncated in [false, true] {
            let base = tempdir().unwrap();
            let out = tempdir().unwrap();
            let mut stream = Vec::new();
            StreamEncoder::write_stream_header(&mut stream).unwrap();
            let header = RecordHeader {
                record_type: RecordType::RegularFile,
                flags: 0,
                reserved: [0, 0],
                path_len: name.len() as u32,
                mode: 0o644,
                size: 5,
                record_count: 0,
                sha256: [0xff; 32],
            };
            stream.extend_from_slice(&header.to_bytes());
            stream.extend_from_slice(name.as_bytes());
            stream.extend_from_slice(if truncated { b"x" } else { b"hello" });
            let err = validate_stream(
                &mut Cursor::new(stream),
                base.path(),
                out.path(),
                TaskClass::Patch,
                &ExtractConfig::default(),
            )
            .unwrap_err();
            if truncated {
                assert!(matches!(
                    err,
                    ExtractError::Format(FormatError::Truncated(_))
                ));
            } else {
                assert!(matches!(
                    err,
                    ExtractError::Format(FormatError::HashMismatch { .. })
                ));
            }
            assert_empty(out.path());
        }
    }
}

#[test]
fn output_symlink_and_manifest_symlink_are_refused() {
    let base = tempdir().unwrap();
    let target = tempdir().unwrap();
    let parent = tempdir().unwrap();
    symlink(target.path(), parent.path().join("out")).unwrap();
    assert!(validate_stream(
        &mut Cursor::new(stream_file("file", b"x")),
        base.path(),
        &parent.path().join("out"),
        TaskClass::Patch,
        &ExtractConfig::default()
    )
    .is_err());
    assert_empty(target.path());
    symlink(base.path(), target.path().join("link")).unwrap();
    assert!(hermetic_extract::report::generate_tree_manifest(target.path()).is_err());
}
