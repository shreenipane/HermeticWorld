use hermetic_sealcheck::{check_d11, D11Options, Severity};
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_d11_test_infra_files_depth_0_and_3() {
    let infra_names = [
        "conftest.py",
        "pytest.ini",
        "tox.ini",
        "sitecustomize.py",
        "usercustomize.py",
        "custom_plugin.pth",
    ];

    for name in infra_names {
        // Depth 0
        let patch_depth_0 = format!(
            "diff --git a/{name} b/{name}\n\
             --- a/{name}\n\
             +++ b/{name}\n\
             @@ -1,1 +1,2 @@\n\
              existing\n\
             +new_line\n"
        );
        let findings_d0 = check_d11(&patch_depth_0, &D11Options::default());
        assert_eq!(
            findings_d0.len(),
            1,
            "Expected depth 0 {name} to be flagged as test_infra_file"
        );
        assert_eq!(findings_d0[0].channel, "test_infra_file");
        assert_eq!(findings_d0[0].severity, Severity::Review);
        assert_eq!(findings_d0[0].detector, "D11");

        // Depth 3
        let path_depth_3 = format!("a/b/c/{name}");
        let patch_depth_3 = format!(
            "diff --git a/{path_depth_3} b/{path_depth_3}\n\
             --- a/{path_depth_3}\n\
             +++ b/{path_depth_3}\n\
             @@ -1,1 +1,2 @@\n\
              existing\n\
             +new_line\n"
        );
        let findings_d3 = check_d11(&patch_depth_3, &D11Options::default());
        assert_eq!(
            findings_d3.len(),
            1,
            "Expected depth 3 {path_depth_3} to be flagged as test_infra_file"
        );
        assert_eq!(findings_d3[0].channel, "test_infra_file");
    }
}

#[test]
fn test_d11_dist_info_and_egg_info() {
    let patch = "\
diff --git a/foo-1.0.dist-info/METADATA b/foo-1.0.dist-info/METADATA
--- a/foo-1.0.dist-info/METADATA
+++ b/foo-1.0.dist-info/METADATA
@@ -1,1 +1,2 @@
 Version: 1.0
+Author: agent
diff --git a/pkg/my_pkg.egg-info/PKG-INFO b/pkg/my_pkg.egg-info/PKG-INFO
--- a/pkg/my_pkg.egg-info/PKG-INFO
+++ b/pkg/my_pkg.egg-info/PKG-INFO
@@ -1,1 +1,2 @@
 Name: my_pkg
+Description: changed
";
    let findings = check_d11(patch, &D11Options::default());
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].channel, "test_infra_file");
    assert_eq!(findings[1].channel, "test_infra_file");
}

#[test]
fn test_d11_benchmark_test_file() {
    let opts = D11Options {
        benchmark_test_files: vec![
            "tests/test_benchmark.py".to_string(),
            "a/tests/test_other.py".to_string(),
        ],
        installed_packages: vec![],
    };

    let patch = "\
diff --git a/tests/test_benchmark.py b/tests/test_benchmark.py
--- a/tests/test_benchmark.py
+++ b/tests/test_benchmark.py
@@ -1,2 +1,3 @@
 def test_foo():
+    pass
     assert True
";
    let findings = check_d11(patch, &opts);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "benchmark_test_file");
    assert_eq!(findings[0].path, "tests/test_benchmark.py");
}

#[test]
fn test_d11_setup_cfg_sections() {
    // inside [metadata]: not flagged
    let patch_metadata = "\
diff --git a/setup.cfg b/setup.cfg
--- a/setup.cfg
+++ b/setup.cfg
@@ -1,4 +1,4 @@
 [metadata]
-version = 1.0.0
+version = 1.0.1
 name = testpkg
";
    let findings_meta = check_d11(patch_metadata, &D11Options::default());
    assert!(
        findings_meta.is_empty(),
        "setup.cfg [metadata] should not be flagged"
    );

    // inside [tool:pytest]: flagged
    let patch_pytest = "\
diff --git a/setup.cfg b/setup.cfg
--- a/setup.cfg
+++ b/setup.cfg
@@ -10,3 +10,4 @@
 [tool:pytest]
-addopts = -v
+addopts = -ra
";
    let findings_pytest = check_d11(patch_pytest, &D11Options::default());
    assert_eq!(findings_pytest.len(), 1);
    assert_eq!(findings_pytest[0].channel, "runner_config_section");
}

#[test]
fn test_d11_pyproject_toml_sections() {
    // [project] dependencies: not flagged
    let patch_deps = "\
diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -1,5 +1,6 @@
 [project]
 dependencies = [
+    \"requests\",
 ]
";
    let findings_deps = check_d11(patch_deps, &D11Options::default());
    assert!(
        findings_deps.is_empty(),
        "pyproject [project] dependencies should not be flagged"
    );

    // [tool.pytest.ini_options]: flagged
    let patch_pytest = "\
diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -10,3 +10,4 @@
 [tool.pytest.ini_options]
-minversion = \"6.0\"
+minversion = \"7.0\"
";
    let findings_pytest = check_d11(patch_pytest, &D11Options::default());
    assert_eq!(findings_pytest.len(), 1);
    assert_eq!(findings_pytest[0].channel, "runner_config_section");
}

#[test]
fn test_d11_pytest11_entry_point_all_three_files() {
    // 1. setup.cfg [options.entry_points]
    let patch_cfg = "\
diff --git a/setup.cfg b/setup.cfg
--- a/setup.cfg
+++ b/setup.cfg
@@ -20,3 +20,4 @@
 [options.entry_points]
+pytest11 = myplugin = mypkg.plugin
";
    let f_cfg = check_d11(patch_cfg, &D11Options::default());
    assert_eq!(f_cfg.len(), 1);
    assert_eq!(f_cfg[0].channel, "runner_config_section");

    // 2. pyproject.toml
    let patch_toml = "\
diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -15,3 +15,4 @@
 [project.entry-points.\"pytest11\"]
+myplugin = \"mypkg.plugin\"
";
    let f_toml = check_d11(patch_toml, &D11Options::default());
    assert_eq!(f_toml.len(), 1);
    assert_eq!(f_toml[0].channel, "runner_config_section");

    // 3. setup.py added line mentioning pytest11
    let patch_py = "\
diff --git a/setup.py b/setup.py
--- a/setup.py
+++ b/setup.py
@@ -1,3 +1,4 @@
 from setuptools import setup
 setup(
+    entry_points={'pytest11': ['myplugin = mypkg.plugin']},
 )
";
    let f_py = check_d11(patch_py, &D11Options::default());
    assert_eq!(f_py.len(), 1);
    assert_eq!(f_py[0].channel, "runner_config_section");
}

#[test]
fn test_d11_monkeypatch_rules() {
    let flagged_patch = "\
diff --git a/src/test_hack.py b/src/test_hack.py
--- a/src/test_hack.py
+++ b/src/test_hack.py
@@ -1,1 +1,4 @@
+pytest.skip = lambda *a: None
+setattr(unittest.TestCase, \"run\", f)
+sys.modules[\"requests\"] = fake
";
    let findings = check_d11(flagged_patch, &D11Options::default());
    assert_eq!(findings.len(), 3);
    for f in &findings {
        assert_eq!(f.channel, "monkeypatch");
    }

    let unflagged_patch = "\
diff --git a/src/test_clean.py b/src/test_clean.py
--- a/src/test_clean.py
+++ b/src/test_clean.py
@@ -1,1 +1,3 @@
+x = \"pytest.skip = 1\"
+# pytest.skip = 1
";
    let findings_clean = check_d11(unflagged_patch, &D11Options::default());
    assert!(
        findings_clean.is_empty(),
        "String and comment mentions must not be flagged"
    );
}

#[test]
fn test_d11_shadowing() {
    let opts = D11Options {
        benchmark_test_files: vec![],
        installed_packages: vec!["requests".to_string()],
    };

    let patch = "\
diff --git a/json.py b/json.py
new file mode 100644
--- /dev/null
+++ b/json.py
@@ -0,0 +1,2 @@
+def loads():
+    return {}
diff --git a/typing/__init__.py b/typing/__init__.py
new file mode 100644
--- /dev/null
+++ b/typing/__init__.py
@@ -0,0 +1,1 @@
+# fake typing
diff --git a/mylib.py b/mylib.py
new file mode 100644
--- /dev/null
+++ b/mylib.py
@@ -0,0 +1,1 @@
+x = 1
diff --git a/requests.py b/requests.py
new file mode 100644
--- /dev/null
+++ b/requests.py
@@ -0,0 +1,1 @@
+# fake requests
";
    let findings = check_d11(patch, &opts);
    // json.py (stdlib), typing/__init__.py (stdlib), requests.py (installed package)
    // mylib.py must NOT be flagged
    assert_eq!(findings.len(), 3);
    let paths: Vec<&str> = findings.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.contains(&"json.py"));
    assert!(paths.contains(&"typing/__init__.py"));
    assert!(paths.contains(&"requests.py"));
    assert!(!paths.contains(&"mylib.py"));

    // Now test with installed_packages empty: requests.py must not be flagged
    let opts_empty = D11Options::default();
    let findings_no_pkg = check_d11(patch, &opts_empty);
    assert_eq!(findings_no_pkg.len(), 2);
    let paths_no_pkg: Vec<&str> = findings_no_pkg.iter().map(|f| f.path.as_str()).collect();
    assert!(paths_no_pkg.contains(&"json.py"));
    assert!(paths_no_pkg.contains(&"typing/__init__.py"));
    assert!(!paths_no_pkg.contains(&"requests.py"));
}

#[test]
fn test_d11_clean_fix_patch() {
    let clean_patch = "\
diff --git a/src/calculator.py b/src/calculator.py
--- a/src/calculator.py
+++ b/src/calculator.py
@@ -10,3 +10,3 @@
 def add(a, b):
-    return a - b
+    return a + b
";
    let findings = check_d11(clean_patch, &D11Options::default());
    assert!(
        findings.is_empty(),
        "Realistic clean fix patch must yield 0 findings"
    );
}

#[test]
fn test_d11_garbage_input_gives_patch_error() {
    let garbage = "This is not a unified diff @@ invalid @@ @@ header";
    let findings = check_d11(garbage, &D11Options::default());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector, "D11");
    assert_eq!(findings[0].channel, "patch_error");
    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn test_d11_cli_execution_and_json_shape() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let dir = tempdir().expect("tempdir");
    let patch_file = dir.path().join("agent.patch");
    let out_file = dir.path().join("report.json");

    let patch_content = "\
diff --git a/conftest.py b/conftest.py
--- a/conftest.py
+++ b/conftest.py
@@ -1,1 +1,2 @@
 import pytest
+pytest.skip = lambda *a: None
";
    fs::write(&patch_file, patch_content).expect("write patch");

    let status = Command::new(bin_path)
        .arg("d11")
        .arg("--patch")
        .arg(&patch_file)
        .arg("--format")
        .arg("json")
        .arg("--out")
        .arg(&out_file)
        .status()
        .expect("run hermetic-sealcheck d11");

    assert_eq!(status.code(), Some(0), "D11 advisory command must exit 0");

    let report_str = fs::read_to_string(&out_file).expect("read report");
    let json: Value = serde_json::from_str(&report_str).expect("parse json");

    assert_eq!(json["schema"], "hermetic-sealcheck/v0");
    assert_eq!(json["instance_id"], "");
    assert_eq!(json["mode"], "d11");
    assert_eq!(json["gate"], false);
    assert_eq!(json["fingerprints"]["lines"], 0);

    let findings = json["findings"].as_array().expect("findings array");
    assert!(!findings.is_empty());
}

#[test]
fn test_d11_pytest11_continuation_line_flagged() {
    let patch = "\
diff --git a/setup.cfg b/setup.cfg
--- a/setup.cfg
+++ b/setup.cfg
@@ -10,3 +10,4 @@
 [options.entry_points]
 pytest11 =
+    myplugin = mypkg.plugin
 console_scripts =
";
    let findings = check_d11(patch, &D11Options::default());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "runner_config_section");
    assert_eq!(findings[0].path, "setup.cfg");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|e| e.contains("myplugin = mypkg.plugin")));
}

#[test]
fn test_d11_renames_both_directions_including_no_hunks() {
    // 1. Rename away: conftest.py -> disabled.py (no hunks)
    let patch_away_no_hunks = "\
diff --git a/conftest.py b/disabled.py
similarity index 100%
rename from conftest.py
rename to disabled.py
";
    let f_away = check_d11(patch_away_no_hunks, &D11Options::default());
    assert_eq!(f_away.len(), 1);
    assert_eq!(f_away[0].channel, "test_infra_file");
    assert_eq!(f_away[0].path, "conftest.py");
    assert_eq!(
        f_away[0].evidence,
        vec!["renamed to disabled.py".to_string()]
    );

    // 2. Rename to: normal.py -> conftest.py (no hunks)
    let patch_to_no_hunks = "\
diff --git a/normal.py b/conftest.py
similarity index 100%
rename from normal.py
rename to conftest.py
";
    let f_to = check_d11(patch_to_no_hunks, &D11Options::default());
    assert_eq!(f_to.len(), 1);
    assert_eq!(f_to[0].channel, "test_infra_file");
    assert_eq!(f_to[0].path, "conftest.py");
    assert!(f_to[0].evidence[0].contains("Test infrastructure file modified or added"));

    // 3. Benchmark test file rename away: tests/test_bench.py -> tests/disabled_bench.py
    let opts = D11Options {
        benchmark_test_files: vec!["tests/test_bench.py".to_string()],
        installed_packages: vec![],
    };
    let patch_bench_away = "\
diff --git a/tests/test_bench.py b/tests/disabled_bench.py
similarity index 100%
rename from tests/test_bench.py
rename to tests/disabled_bench.py
";
    let f_bench_away = check_d11(patch_bench_away, &opts);
    assert_eq!(f_bench_away.len(), 1);
    assert_eq!(f_bench_away[0].channel, "benchmark_test_file");
    assert_eq!(f_bench_away[0].path, "tests/test_bench.py");
    assert_eq!(
        f_bench_away[0].evidence,
        vec!["renamed to tests/disabled_bench.py".to_string()]
    );

    // 4. Benchmark test file rename to: tests/old.py -> tests/test_bench.py
    let patch_bench_to = "\
diff --git a/tests/old.py b/tests/test_bench.py
similarity index 100%
rename from tests/old.py
rename to tests/test_bench.py
";
    let f_bench_to = check_d11(patch_bench_to, &opts);
    assert_eq!(f_bench_to.len(), 1);
    assert_eq!(f_bench_to[0].channel, "benchmark_test_file");
    assert_eq!(f_bench_to[0].path, "tests/test_bench.py");
    assert!(f_bench_to[0].evidence[0].contains("Benchmark test file modified"));
}

#[test]
fn test_d11_unknown_section_in_setup_cfg_and_pyproject() {
    // "addopts = --ignore=tests" with no header in hunk: flagged as section unknown
    let patch_unknown = "\
diff --git a/setup.cfg b/setup.cfg
--- a/setup.cfg
+++ b/setup.cfg
@@ -10,1 +10,1 @@
+addopts = --ignore=tests
";
    let f_unknown = check_d11(patch_unknown, &D11Options::default());
    assert_eq!(f_unknown.len(), 1);
    assert_eq!(f_unknown[0].channel, "runner_config_section");
    assert_eq!(
        f_unknown[0].evidence,
        vec![
            "section unknown (header outside the diff context): addopts = --ignore=tests"
                .to_string()
        ]
    );

    // change under visible [metadata] header: still NOT flagged
    let patch_metadata = "\
diff --git a/setup.cfg b/setup.cfg
--- a/setup.cfg
+++ b/setup.cfg
@@ -1,3 +1,3 @@
 [metadata]
-name = old
+name = new
";
    let f_meta = check_d11(patch_metadata, &D11Options::default());
    assert!(
        f_meta.is_empty(),
        "change under visible [metadata] header must not be flagged"
    );
}

#[test]
fn test_d11_double_prefix_stripping() {
    // new file a/json.py gives no shadowing finding
    let patch_a_json = "\
diff --git a/a/json.py b/a/json.py
new file mode 100644
--- /dev/null
+++ b/a/json.py
@@ -0,0 +1,2 @@
+def loads():
+    return {}
";
    let f_json = check_d11(patch_a_json, &D11Options::default());
    assert!(
        f_json.is_empty(),
        "a/json.py is inside directory 'a/' and must NOT be flagged as top-level shadowing"
    );

    // benchmark entry written as "b/tests/test_x.py" still matches tests/test_x.py
    let opts = D11Options {
        benchmark_test_files: vec!["b/tests/test_x.py".to_string()],
        installed_packages: vec![],
    };
    let patch_bench = "\
diff --git a/tests/test_x.py b/tests/test_x.py
--- a/tests/test_x.py
+++ b/tests/test_x.py
@@ -1,1 +1,2 @@
 def test_x():
+    pass
";
    let f_bench = check_d11(patch_bench, &opts);
    assert_eq!(f_bench.len(), 1);
    assert_eq!(f_bench[0].channel, "benchmark_test_file");
    assert_eq!(f_bench[0].path, "tests/test_x.py");
}

#[test]
fn test_d11_cli_sarif_garbage_input_has_note_for_patch_error() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let dir = tempdir().expect("tempdir");
    let patch_file = dir.path().join("garbage.patch");
    let out_file = dir.path().join("report.sarif");

    fs::write(&patch_file, "this is not a valid git diff @@ bad @@").expect("write garbage");

    let status = Command::new(bin_path)
        .arg("d11")
        .arg("--patch")
        .arg(&patch_file)
        .arg("--format")
        .arg("sarif")
        .arg("--out")
        .arg(&out_file)
        .status()
        .expect("run hermetic-sealcheck d11");

    assert_eq!(status.code(), Some(0));

    let sarif_str = fs::read_to_string(&out_file).expect("read sarif");
    let json: Value = serde_json::from_str(&sarif_str).expect("parse sarif json");

    let results = json["runs"][0]["results"]
        .as_array()
        .expect("results array");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ruleId"], "D11");
    assert_eq!(results[0]["level"], "note");
    assert!(results[0]["message"]["text"]
        .as_str()
        .unwrap()
        .contains("patch_error"));
}

#[test]
fn test_sarif_scan_unchanged_drops_info() {
    use hermetic_sealcheck::{generate_sarif, Finding, Severity, Visibility};

    let findings = vec![
        Finding {
            detector: "D1".to_string(),
            channel: "git_branch".to_string(),
            path: "repo/.git".to_string(),
            visibility: Visibility::AgentVisible,
            severity: Severity::Gate,
            confidence: 1.0,
            hunk: None,
            evidence: vec!["leaked branch".to_string()],
        },
        Finding {
            detector: "D12".to_string(),
            channel: "skipped_symlink".to_string(),
            path: "repo/link".to_string(),
            visibility: Visibility::AgentVisible,
            severity: Severity::Info,
            confidence: 1.0,
            hunk: None,
            evidence: vec!["symlink not followed".to_string()],
        },
    ];

    let default_sarif = generate_sarif(&findings);
    let run = &default_sarif.runs[0];
    assert_eq!(run.results.len(), 1);
    assert_eq!(run.results[0].rule_id, "D1");
    assert_eq!(run.results[0].level, "error");
}

#[test]
fn test_d11_setup_cfg_comment_in_entry_points_preserves_group() {
    let patch_hash = "\
diff --git a/setup.cfg b/setup.cfg
--- a/setup.cfg
+++ b/setup.cfg
@@ -10,4 +10,5 @@
 [options.entry_points]
 pytest11 =
 # plugins
+    myplugin = pkg.plugin
 console_scripts =
";
    let findings_hash = check_d11(patch_hash, &D11Options::default());
    assert_eq!(findings_hash.len(), 1);
    assert_eq!(findings_hash[0].channel, "runner_config_section");
    assert_eq!(findings_hash[0].path, "setup.cfg");
    assert!(findings_hash[0]
        .evidence
        .iter()
        .any(|e| e.contains("myplugin = pkg.plugin")));

    let patch_semi = "\
diff --git a/setup.cfg b/setup.cfg
--- a/setup.cfg
+++ b/setup.cfg
@@ -10,4 +10,5 @@
 [options.entry_points]
 pytest11 =
 ; plugins
+    myplugin = pkg.plugin
 console_scripts =
";
    let findings_semi = check_d11(patch_semi, &D11Options::default());
    assert_eq!(findings_semi.len(), 1);
    assert_eq!(findings_semi[0].channel, "runner_config_section");
    assert_eq!(findings_semi[0].path, "setup.cfg");
    assert!(findings_semi[0]
        .evidence
        .iter()
        .any(|e| e.contains("myplugin = pkg.plugin")));
}

#[test]
fn test_d11_setup_py_unchanged_inline_followed_by_changed_version_gives_no_finding() {
    let patch = "\
diff --git a/setup.py b/setup.py
--- a/setup.py
+++ b/setup.py
@@ -10,4 +10,4 @@
     entry_points={'pytest11': ['plugin = pkg.plugin']},
-    version=\"1.0.0\",
+    version=\"2.0.0\",
     description=\"pkg\",
";
    let findings = check_d11(patch, &D11Options::default());
    assert!(
        findings.is_empty(),
        "Unchanged inline pytest11 group followed by changed version= must give no finding"
    );
}

#[test]
fn test_d11_setup_py_multiline_pytest11_changed_middle_line_flagged() {
    let patch = "\
diff --git a/setup.py b/setup.py
--- a/setup.py
+++ b/setup.py
@@ -10,5 +10,6 @@
 entry_points={
     'pytest11': [
+        'plugin = pkg.plugin',
     ],
 }
";
    let findings = check_d11(patch, &D11Options::default());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "runner_config_section");
    assert_eq!(findings[0].path, "setup.py");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|e| e.contains("plugin = pkg.plugin")));
}

#[test]
fn test_d11_setup_py_changed_line_with_inline_pytest11_flagged() {
    let patch = "\
diff --git a/setup.py b/setup.py
--- a/setup.py
+++ b/setup.py
@@ -10,3 +10,4 @@
 from setuptools import setup
 setup(
+    entry_points={'pytest11': ['plugin = pkg.plugin']},
 )
";
    let findings = check_d11(patch, &D11Options::default());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "runner_config_section");
    assert_eq!(findings[0].path, "setup.py");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|e| e.contains("entry_points={'pytest11': ['plugin = pkg.plugin']}")));
}

#[test]
fn test_d11_setup_py_entry_points_variable_followed_by_changed_version_gives_no_finding() {
    let patch = "\
diff --git a/setup.py b/setup.py
--- a/setup.py
+++ b/setup.py
@@ -10,4 +10,4 @@
     entry_points={'pytest11': plugins},
-    version=\"1.0.0\",
+    version=\"2.0.0\",
     description=\"pkg\",
";
    let findings = check_d11(patch, &D11Options::default());
    assert!(
        findings.is_empty(),
        "Unchanged entry_points with variable followed by changed version= must give no finding"
    );
}

#[test]
fn test_d11_setup_py_multiline_pytest11_comment_bracket_does_not_close_group() {
    let patch = "\
diff --git a/setup.py b/setup.py
--- a/setup.py
+++ b/setup.py
@@ -10,6 +10,7 @@
 entry_points={
     'pytest11': [
         # ]
+        'plugin = pkg.plugin',
     ],
 }
";
    let findings = check_d11(patch, &D11Options::default());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "runner_config_section");
    assert_eq!(findings[0].path, "setup.py");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|e| e.contains("plugin = pkg.plugin")));
}

#[test]
fn test_d11_setup_py_string_element_with_bracket_does_not_close_group() {
    let patch = "\
diff --git a/setup.py b/setup.py
--- a/setup.py
+++ b/setup.py
@@ -10,6 +10,7 @@
 entry_points={
     'pytest11': [
         'p = pkg:x]',
+        'q = pkg:y',
     ],
 }
";
    let findings = check_d11(patch, &D11Options::default());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "runner_config_section");
    assert_eq!(findings[0].path, "setup.py");
    assert!(findings[0].evidence.iter().any(|e| e.contains("q = pkg:y")));
}

#[test]
fn test_d11_setup_py_inline_string_element_with_bracket_followed_by_changed_version_gives_no_finding(
) {
    let patch = "\
diff --git a/setup.py b/setup.py
--- a/setup.py
+++ b/setup.py
@@ -10,4 +10,4 @@
     entry_points={'pytest11': ['p = pkg:x]']},
-    version=\"1.0.0\",
+    version=\"2.0.0\",
     description=\"pkg\",
";
    let findings = check_d11(patch, &D11Options::default());
    assert!(
        findings.is_empty(),
        "Inline string element containing ']' followed by changed version= must give no finding"
    );
}
