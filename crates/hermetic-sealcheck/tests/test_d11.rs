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
