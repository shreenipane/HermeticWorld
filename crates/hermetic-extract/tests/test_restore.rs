#![forbid(unsafe_code)]

use std::fs;
use std::io::Cursor;
use tempfile::tempdir;

use hermetic_extract::config::{ExtractConfig, TaskClass};
use hermetic_extract::format::StreamEncoder;
use hermetic_extract::validator::validate_stream;

#[test]
fn test_restore_whole_files_and_directories() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();

    // Populate base tree with pristine test files
    fs::write(base.path().join("conftest.py"), b"# base conftest").unwrap();
    fs::write(base.path().join("pytest.ini"), b"# base pytest.ini").unwrap();
    fs::write(base.path().join("tox.ini"), b"# base tox.ini").unwrap();
    fs::write(
        base.path().join("sitecustomize.py"),
        b"# base sitecustomize",
    )
    .unwrap();
    fs::write(
        base.path().join("usercustomize.py"),
        b"# base usercustomize",
    )
    .unwrap();
    fs::write(base.path().join("custom.pth"), b"# base pth").unwrap();

    fs::create_dir_all(base.path().join("tests")).unwrap();
    fs::write(
        base.path().join("tests/test_suite.py"),
        b"# base test suite",
    )
    .unwrap();

    fs::create_dir_all(base.path().join("pkg.egg-info")).unwrap();
    fs::write(
        base.path().join("pkg.egg-info/entry_points.txt"),
        b"# base entry points",
    )
    .unwrap();

    let config = ExtractConfig {
        test_paths: vec!["tests/test_suite.py".to_string()],
        ..Default::default()
    };

    // Agent stream attempts to overwrite all these test files with malicious content
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();

    StreamEncoder::write_file(&mut stream, "conftest.py", 0o644, b"malicious conftest").unwrap();
    StreamEncoder::write_file(&mut stream, "pytest.ini", 0o644, b"malicious pytest.ini").unwrap();
    StreamEncoder::write_file(&mut stream, "tox.ini", 0o644, b"malicious tox.ini").unwrap();
    StreamEncoder::write_file(
        &mut stream,
        "sitecustomize.py",
        0o644,
        b"malicious sitecustomize",
    )
    .unwrap();
    StreamEncoder::write_file(
        &mut stream,
        "usercustomize.py",
        0o644,
        b"malicious usercustomize",
    )
    .unwrap();
    StreamEncoder::write_file(&mut stream, "custom.pth", 0o644, b"malicious pth").unwrap();
    StreamEncoder::write_file(
        &mut stream,
        "tests/test_suite.py",
        0o644,
        b"malicious test suite",
    )
    .unwrap();
    StreamEncoder::write_file(
        &mut stream,
        "pkg.egg-info/entry_points.txt",
        0o644,
        b"malicious egg-info",
    )
    .unwrap();

    // Also attempt to create a NEW conftest in a subdirectory (which base didn't have)
    StreamEncoder::write_file(
        &mut stream,
        "tests/conftest.py",
        0o644,
        b"new malicious conftest",
    )
    .unwrap();

    // Normal non-test file edited by agent
    StreamEncoder::write_file(&mut stream, "src/main.py", 0o644, b"legitimate fix").unwrap();

    let total_bytes = b"malicious conftest".len()
        + b"malicious pytest.ini".len()
        + b"malicious tox.ini".len()
        + b"malicious sitecustomize".len()
        + b"malicious usercustomize".len()
        + b"malicious pth".len()
        + b"malicious test suite".len()
        + b"malicious egg-info".len()
        + b"new malicious conftest".len()
        + b"legitimate fix".len();

    StreamEncoder::write_end(&mut stream, 10, total_bytes as u64).unwrap();

    let mut cursor = Cursor::new(stream);
    let report = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap();

    // Verify all malicious attempts were dropped
    assert_eq!(report.dropped.len(), 9);
    assert_eq!(report.restored.len(), 8); // 8 existed in base, 1 was new

    // Verify output directory files match pristine base version
    assert_eq!(
        fs::read(out.path().join("conftest.py")).unwrap(),
        b"# base conftest"
    );
    assert_eq!(
        fs::read(out.path().join("pytest.ini")).unwrap(),
        b"# base pytest.ini"
    );
    assert_eq!(
        fs::read(out.path().join("tox.ini")).unwrap(),
        b"# base tox.ini"
    );
    assert_eq!(
        fs::read(out.path().join("sitecustomize.py")).unwrap(),
        b"# base sitecustomize"
    );
    assert_eq!(
        fs::read(out.path().join("usercustomize.py")).unwrap(),
        b"# base usercustomize"
    );
    assert_eq!(
        fs::read(out.path().join("custom.pth")).unwrap(),
        b"# base pth"
    );
    assert_eq!(
        fs::read(out.path().join("tests/test_suite.py")).unwrap(),
        b"# base test suite"
    );
    assert_eq!(
        fs::read(out.path().join("pkg.egg-info/entry_points.txt")).unwrap(),
        b"# base entry points"
    );

    // New conftest was dropped and should NOT exist in output
    assert!(!out.path().join("tests/conftest.py").exists());

    // Legitimate fix was applied
    assert_eq!(
        fs::read(out.path().join("src/main.py")).unwrap(),
        b"legitimate fix"
    );
}

#[test]
fn test_restore_setup_cfg_sections() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();

    let base_cfg = r#"[metadata]
name = myproject
version = 1.0.0

[options]
install_requires =
    requests>=2.0

[tool:pytest]
addopts = -ra -q

[options.entry_points]
console_scripts =
    my-cli = myproject.cli:main
pytest11 =
    my_plugin = myproject.plugin
"#;

    fs::write(base.path().join("setup.cfg"), base_cfg).unwrap();

    // Agent modifies dependencies in [options] (legitimate), but tries to tamper with
    // [tool:pytest] and add a hostile pytest11 entry point
    let agent_cfg = r#"[metadata]
name = myproject
version = 1.0.0

[options]
install_requires =
    requests>=2.0
    new-dependency>=1.0

[tool:pytest]
addopts = --disable-pytest-warnings --override-all-tests-to-pass

[options.entry_points]
console_scripts =
    my-cli = myproject.cli:main
pytest11 =
    hostile_plugin = myproject.trojan
"#;

    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "setup.cfg", 0o644, agent_cfg.as_bytes()).unwrap();
    StreamEncoder::write_end(&mut stream, 1, agent_cfg.len() as u64).unwrap();

    let config = ExtractConfig::default();
    let mut cursor = Cursor::new(stream);
    let report = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap();

    assert!(report
        .restored
        .iter()
        .any(|r| r.path == "setup.cfg" && r.reason == "test_runner_sections_restored"));

    let result_content = fs::read_to_string(out.path().join("setup.cfg")).unwrap();

    // Verify legitimate change is kept
    assert!(result_content.contains("new-dependency>=1.0"));

    // Verify test runner section was restored from base
    assert!(result_content.contains("addopts = -ra -q"));
    assert!(!result_content.contains("--override-all-tests-to-pass"));

    // Verify pytest11 entry point was restored from base
    assert!(result_content.contains("my_plugin = myproject.plugin"));
    assert!(!result_content.contains("hostile_plugin = myproject.trojan"));
}

#[test]
fn test_restore_pyproject_toml_sections() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();

    let base_toml = r#"[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "pkg"
dependencies = ["flask"]

[tool.pytest.ini_options]
minversion = "6.0"
addopts = "-q"
"#;

    fs::write(base.path().join("pyproject.toml"), base_toml).unwrap();

    // Agent adds a dependency (legitimate) but tampers with [tool.pytest.ini_options]
    let agent_toml = r#"[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "pkg"
dependencies = [
    "flask",
    "click>=8.0"
]

[tool.pytest.ini_options]
addopts = "--skip-failing"
"#;

    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "pyproject.toml", 0o644, agent_toml.as_bytes()).unwrap();
    StreamEncoder::write_end(&mut stream, 1, agent_toml.len() as u64).unwrap();

    let config = ExtractConfig::default();
    let mut cursor = Cursor::new(stream);
    let report = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap();

    assert!(report.restored.iter().any(|r| r.path == "pyproject.toml"));

    let result = fs::read_to_string(out.path().join("pyproject.toml")).unwrap();
    assert!(result.contains("click>=8.0"));
    assert!(result.contains("minversion = \"6.0\""));
    assert!(!result.contains("--skip-failing"));
}

#[test]
fn test_unparseable_configuration_file_restores_whole_from_base() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();

    let base_cfg = "[metadata]\nname = valid_base\n";
    fs::write(base.path().join("setup.cfg"), base_cfg).unwrap();

    // Corrupt, unparseable agent config
    let agent_corrupt = b"[[[[[unclosed bracket syntax error \0 binary\xff";

    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "setup.cfg", 0o644, agent_corrupt).unwrap();
    StreamEncoder::write_end(&mut stream, 1, agent_corrupt.len() as u64).unwrap();

    let config = ExtractConfig::default();
    let mut cursor = Cursor::new(stream);
    let report = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap();

    assert!(report.restored.iter().any(|r| r.path == "setup.cfg"
        && r.reason == "safe_fallback_unparseable_restored_whole_from_base"));

    let result = fs::read_to_string(out.path().join("setup.cfg")).unwrap();
    assert_eq!(result, base_cfg);
}

#[test]
fn review_native_pytest_table_is_restored() {
    let agent = "[project]\nname = \"fixed\"\n[tool.pytest]\naddopts = \"-p agent_plugin\"\n";
    for base_config in [
        None,
        Some("[tool.pytest]\naddopts = \"-q\"\n"),
        Some("[tool.pytest.ini_options]\naddopts = \"-q\"\n"),
    ] {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        if let Some(content) = base_config {
            fs::write(base.path().join("pyproject.toml"), content).unwrap();
        }
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_file(&mut stream, "pyproject.toml", 0o644, agent.as_bytes()).unwrap();
        StreamEncoder::write_end(&mut stream, 1, agent.len() as u64).unwrap();
        validate_stream(
            &mut Cursor::new(stream),
            base.path(),
            out.path(),
            TaskClass::Patch,
            &ExtractConfig::default(),
        )
        .unwrap();
        let actual = fs::read_to_string(out.path().join("pyproject.toml")).unwrap();
        assert!(!actual.contains("agent_plugin"), "{actual}");
        assert!(actual.contains("name = \"fixed\""));
        if let Some(content) = base_config {
            assert!(actual.contains(content));
        } else {
            assert!(!actual.contains("[tool.pytest]"));
        }
    }
}

#[test]
fn review_alternate_pytest_configs_are_whole_file_protected() {
    for name in [".pytest.ini", "pytest.toml", ".pytest.toml"] {
        for existing in [false, true] {
            let base = tempdir().unwrap();
            let out = tempdir().unwrap();
            let path = format!("pkg/{name}");
            if existing {
                fs::create_dir(base.path().join("pkg")).unwrap();
                fs::write(base.path().join(&path), b"# pristine").unwrap();
            }
            let payload = b"[pytest]\naddopts = [\"-p\", \"agent_plugin\"]\n";
            let mut stream = Vec::new();
            StreamEncoder::write_stream_header(&mut stream).unwrap();
            StreamEncoder::write_file(&mut stream, &path, 0o644, payload).unwrap();
            StreamEncoder::write_end(&mut stream, 1, payload.len() as u64).unwrap();
            let report = validate_stream(
                &mut Cursor::new(stream),
                base.path(),
                out.path(),
                TaskClass::Patch,
                &ExtractConfig::default(),
            )
            .unwrap();
            assert_eq!(report.dropped.len(), 1, "{name}");
            if existing {
                assert_eq!(fs::read(out.path().join(&path)).unwrap(), b"# pristine");
                assert_eq!(report.restored.len(), 1);
            } else {
                assert!(!out.path().join(&path).exists());
            }
        }
    }
}
