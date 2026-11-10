"""Tests for hermetic_slice grader, patch validation, log evaluation, and Docker integration."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import uuid

import pytest

from hermetic_slice.__main__ import main
from hermetic_slice.dockerutil import is_docker_available, run_docker
from hermetic_slice.gitutil import run_git
from hermetic_slice.grader import (
    PatchRejected,
    _resolve_case,
    evaluate_log,
    grade,
    grade_status_map,
    oracle_check,
    split_patch,
    validate_patch,
)
from hermetic_slice.log_parsers import parse_log_pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "grader"
requires_docker = pytest.mark.skipif(
    not is_docker_available(),
    reason="Docker is not available or docker info failed",
)


def _read_row_fixture(instance_id: str) -> dict:
    path = FIXTURES_DIR / f"{instance_id}.row.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _read_log_fixture(name: str) -> str:
    path = FIXTURES_DIR / name
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        return f.read()


# =============================================================================
# split_patch and validate_patch Tests
# =============================================================================


@pytest.mark.parametrize(
    "instance_id",
    [
        "astropy__astropy-12907",
        "django__django-11099",
        "psf__requests-2317",
        "pytest-dev__pytest-6202",
        "sympy__sympy-20590",
    ],
)
def test_validate_patch_real_gold_patches_pass_unchanged(instance_id: str) -> None:
    """Verify all real benchmark gold patches pass validation without drops or rejections."""
    row = _read_row_fixture(instance_id)
    gold_patch = row["patch"]
    test_patch = row["test_patch"]

    test_patches = split_patch(test_patch)
    test_files = {p.path for p in test_patches} | {p.old_path for p in test_patches if p.old_path}

    kept_diff, findings = validate_patch(gold_patch, test_files=test_files)
    assert kept_diff == gold_patch
    assert findings == []


def test_validate_patch_rejection_rules() -> None:
    """Verify PatchRejected is raised on absolute path, .., symlink, binary, mode, and submodule."""
    test_files = {"tests/test_foo.py"}

    # Absolute path
    diff_abs = "diff --git a//etc/passwd b//etc/passwd\n--- a//etc/passwd\n+++ b//etc/passwd\n"
    with pytest.raises(PatchRejected, match="Absolute path"):
        validate_patch(diff_abs, test_files=test_files)

    # Path traversal ..
    diff_dotdot = "diff --git a/../escape.py b/../escape.py\n--- a/../escape.py\n+++ b/../escape.py\n"
    with pytest.raises(PatchRejected, match=r"\.\."):
        validate_patch(diff_dotdot, test_files=test_files)

    # Symlink (mode 120000)
    diff_symlink = (
        "diff --git a/link b/link\n"
        "new file mode 120000\n"
        "--- /dev/null\n"
        "+++ b/link\n"
        "@@ -0,0 +1 @@\n"
        "+target\n"
    )
    with pytest.raises(PatchRejected, match="Symlink"):
        validate_patch(diff_symlink, test_files=test_files)

    # Binary patch (GIT binary patch)
    diff_binary = (
        "diff --git a/bin.dat b/bin.dat\n"
        "GIT binary patch\nliteral 10\n"
    )
    with pytest.raises(PatchRejected, match="Binary"):
        validate_patch(diff_binary, test_files=test_files)

    # Binary patch (Binary files ... differ)
    diff_binary2 = "diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n"
    with pytest.raises(PatchRejected, match="Binary"):
        validate_patch(diff_binary2, test_files=test_files)

    # Disallowed mode (e.g. 100777)
    diff_bad_mode = (
        "diff --git a/script.sh b/script.sh\n"
        "new file mode 100777\n"
        "--- /dev/null\n"
        "+++ b/script.sh\n"
    )
    with pytest.raises(PatchRejected, match="Disallowed mode"):
        validate_patch(diff_bad_mode, test_files=test_files)

    # Submodule (mode 160000)
    diff_submodule = (
        "diff --git a/submod b/submod\n"
        "new file mode 160000\n"
        "--- /dev/null\n"
        "+++ b/submod\n"
    )
    with pytest.raises(PatchRejected, match="Submodule"):
        validate_patch(diff_submodule, test_files=test_files)


def test_validate_patch_drop_rules() -> None:
    """Verify test infrastructure drops with D11 finding, including renames and nesting."""
    test_files = {"tests/test_unit.py"}

    # 1. Touches test file from benchmark test patch
    diff_test_file = (
        "diff --git a/tests/test_unit.py b/tests/test_unit.py\n"
        "--- a/tests/test_unit.py\n"
        "+++ b/tests/test_unit.py\n"
        "@@ -1 +1 @@\n"
        "-assert False\n"
        "+assert True\n"
    )
    kept, findings = validate_patch(diff_test_file, test_files=test_files)
    assert kept == ""
    assert len(findings) == 1
    assert findings[0]["kind"] == "test_infra_restored"
    assert findings[0]["detector"] == "D11"

    # 2. conftest.py at depth
    diff_conftest = (
        "diff --git a/sub/deep/conftest.py b/sub/deep/conftest.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/sub/deep/conftest.py\n"
        "@@ -0,0 +1 @@\n"
        "+import pytest\n"
    )
    kept, findings = validate_patch(diff_conftest, test_files=test_files)
    assert kept == ""
    assert findings[0]["kind"] == "test_infra_restored"

    # 3. .pth file
    diff_pth = (
        "diff --git a/backdoor.pth b/backdoor.pth\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/backdoor.pth\n"
    )
    kept, findings = validate_patch(diff_pth, test_files=test_files)
    assert kept == ""
    assert findings[0]["kind"] == "test_infra_restored"

    # 4. Under egg-info or dist-info
    diff_egg = (
        "diff --git a/pkg.egg-info/entry_points.txt b/pkg.egg-info/entry_points.txt\n"
        "--- a/pkg.egg-info/entry_points.txt\n"
        "+++ b/pkg.egg-info/entry_points.txt\n"
    )
    kept, findings = validate_patch(diff_egg, test_files=test_files)
    assert kept == ""
    assert findings[0]["kind"] == "test_infra_restored"

    # 5. Rename of conftest.py
    diff_rename_conftest = (
        "diff --git a/conftest.py b/helper.py\n"
        "rename from conftest.py\n"
        "rename to helper.py\n"
    )
    kept, findings = validate_patch(diff_rename_conftest, test_files=test_files)
    assert kept == ""
    assert findings[0]["kind"] == "test_infra_restored"


def test_validate_patch_stdlib_shadowing_finding_only() -> None:
    """Verify new top-level stdlib package (json/__init__.py) produces finding but is not dropped."""
    diff_stdlib = (
        "diff --git a/json/__init__.py b/json/__init__.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/json/__init__.py\n"
        "@@ -0,0 +1 @@\n"
        "+# fake json\n"
    )
    kept, findings = validate_patch(diff_stdlib, test_files=set())
    # Not dropped!
    assert kept == diff_stdlib
    assert len(findings) == 1
    assert findings[0]["kind"] == "stdlib_shadowing"
    assert findings[0]["module"] == "json"
    assert findings[0]["detector"] == "D11"


# =============================================================================
# Log Evaluation and Resolution Tests
# =============================================================================


def test_resolve_case_truncated_param_agree_and_disagree() -> None:
    """Verify _resolve_case prefix-matches truncated param ids only when outcomes agree."""
    sm_agree = {
        "test_foo[param_alpha_1]": "PASSED",
        "test_foo[param_alpha_2]": "PASSED",
    }
    # count of [ > count of ]
    assert _resolve_case("test_foo[param_alpha_", sm_agree) is not None

    sm_disagree = {
        "test_foo[param_beta_1]": "PASSED",
        "test_foo[param_beta_2]": "FAILED",
    }
    assert _resolve_case("test_foo[param_beta_", sm_disagree) is None

    # Normal exact match keeps exact semantics
    assert _resolve_case("exact_test", {"exact_test": "PASSED"}) == "exact_test"


def test_evaluate_log_bad_markers_and_exit_code() -> None:
    """Verify evaluate_log returns None on bad markers and non-zero exit codes with no failures."""
    content_bad = (
        ">>>>> Start Test Output\n"
        "PASSED test_1\n"
        ">>>>> Patch Apply Failed\n"
        ">>>>> End Test Output\n"
    )
    status_map, _ = evaluate_log(content_bad, parse_log_pytest)
    assert status_map is None

    # Exit code non-zero but all tests passed -> suspicious, unparsed
    content_exit_mismatch = (
        ">>>>> Start Test Output\n"
        "PASSED test_1\n"
        ">>>>> End Test Output\n"
        ">>>>> Test Exit Code: 1\n"
    )
    status_map, exit_code = evaluate_log(content_exit_mismatch, parse_log_pytest)
    assert status_map is None
    assert exit_code == 1


def test_grading_reports_on_real_logs() -> None:
    """Verify grading resolution on pytest-6202 gold and empty real eval logs."""
    row = _read_row_fixture("pytest-dev__pytest-6202")
    f2p = row["FAIL_TO_PASS"]
    p2p = row["PASS_TO_PASS"]

    gold_log = _read_log_fixture("pytest-dev__pytest-6202.gold.log.gz")
    gold_map, _ = evaluate_log(gold_log, parse_log_pytest)
    assert gold_map is not None
    res_gold, resolved_gold, f2p_g, p2p_g = grade_status_map(gold_map, f2p, p2p)
    assert res_gold == "RESOLVED_FULL"
    assert resolved_gold is True
    assert len(f2p_g["success"]) == 1
    assert len(f2p_g["failure"]) == 0

    empty_log = _read_log_fixture("pytest-dev__pytest-6202.empty.log.gz")
    empty_map, _ = evaluate_log(empty_log, parse_log_pytest)
    assert empty_map is not None
    res_empty, resolved_empty, f2p_e, p2p_e = grade_status_map(empty_map, f2p, p2p)
    assert res_empty == "RESOLVED_NO"
    assert resolved_empty is False
    assert len(f2p_e["success"]) == 0
    assert len(f2p_e["failure"]) == 1


# =============================================================================
# CLI Subcommand Tests (fetch-eval-specs and oracle validation)
# =============================================================================


def test_cli_fetch_eval_specs_and_oracle_unknown_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify CLI subcommands handle --only, exit 1 on unknown ID, and ASCII output."""
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Unknown ID on fetch-eval-specs exits 1
    ret = main([
        "fetch-eval-specs",
        "--tasks-dir", str(tasks_dir),
        "--cache", str(cache_dir),
        "--only", "nonexistent-task",
    ])
    assert ret == 1

    # Unknown ID on oracle exits 1
    ret_oracle = main([
        "oracle",
        "--tasks-dir", str(tasks_dir),
        "--only", "nonexistent-task",
    ])
    assert ret_oracle == 1


# =============================================================================
# Docker Integration Tests
# =============================================================================


@pytest.fixture(scope="module")
def docker_test_env(tmp_path_factory: pytest.TempPathFactory):
    """Build a tiny test image FROM python:3.9-slim with git and pytest repo at /testbed."""
    if not is_docker_available():
        pytest.skip("Docker is not available")

    random_id = uuid.uuid4().hex[:8]
    image_tag = f"hermetic-t05-test-{random_id}"

    ctx_dir = tmp_path_factory.mktemp("docker_t05_ctx")
    repo_dir = ctx_dir / "testbed"
    repo_dir.mkdir(parents=True, exist_ok=True)

    # Init testbed git repo
    run_git(["init", "-b", "main"], cwd=repo_dir)
    run_git(["config", "user.name", "TestUser"], cwd=repo_dir)
    run_git(["config", "user.email", "test@example.com"], cwd=repo_dir)

    (repo_dir / "target.py").write_text("def solve(x):\n    return x\n", encoding="utf-8")
    (repo_dir / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='target', py_modules=['target'])\n",
        encoding="utf-8",
    )
    run_git(["add", "."], cwd=repo_dir)
    run_git(["commit", "-m", "Initial commit"], cwd=repo_dir)
    base_commit = run_git(["rev-parse", "HEAD"], cwd=repo_dir).decode("ascii").strip()

    # Dockerfile
    dockerfile = (
        "FROM python:3.9-slim\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends git \\\n"
        " && rm -rf /var/lib/apt/lists/* \\\n"
        " && pip install --no-cache-dir pytest\n"
        "COPY testbed /testbed\n"
        "WORKDIR /testbed\n"
        "RUN pip install -e .\n"
    )
    (ctx_dir / "Dockerfile").write_text(dockerfile, encoding="utf-8")

    run_docker(["build", "-t", image_tag, str(ctx_dir)], check=True)

    yield {
        "image": image_tag,
        "base_commit": base_commit,
    }

    # Finalizer: remove image
    run_docker(["rmi", "-f", image_tag], check=False)


@requires_docker
def test_docker_grade_and_oracle_integration(tmp_path: Path, docker_test_env: dict) -> None:
    """Verify grade and oracle_check end-to-end in container with no network."""
    image = docker_test_env["image"]
    base_commit = docker_test_env["base_commit"]
    instance_id = "test-task__integration-1"

    task_dir = tmp_path / instance_id
    staging_dir = task_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    # 1. Gold patch fixes solve() to return x + 1
    gold_patch_text = (
        "diff --git a/target.py b/target.py\n"
        "--- a/target.py\n"
        "+++ b/target.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def solve(x):\n"
        "-    return x\n"
        "+    return x + 1\n"
    )
    (staging_dir / "gold.patch").write_text(gold_patch_text, encoding="utf-8", newline="")

    # 2. Test patch adds test_solve (assert solve(1) == 2) and test_network (assert urllib to 1.1.1.1 fails)
    test_patch_text = (
        "diff --git a/test_target.py b/test_target.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/test_target.py\n"
        "@@ -0,0 +1,10 @@\n"
        "+import urllib.request\n"
        "+import pytest\n"
        "+from target import solve\n"
        "+\n"
        "+def test_solve():\n"
        "+    assert solve(1) == 2\n"
        "+\n"
        "+def test_network():\n"
        "+    with pytest.raises(Exception):\n"
        "+        urllib.request.urlopen('http://1.1.1.1', timeout=1)\n"
    )
    (staging_dir / "test.patch").write_text(test_patch_text, encoding="utf-8", newline="")

    f2p = ["test_target.py::test_solve"]
    p2p = ["test_target.py::test_network"]

    task_json_data = {
        "base_commit": base_commit,
        "image": image,
        "instance_id": instance_id,
        "schema": "hermetic-slice-task/v1",
        "tests": {
            "FAIL_TO_PASS": f2p,
            "PASS_TO_PASS": p2p,
        },
    }
    (task_dir / "task.json").write_text(json.dumps(task_json_data, indent=2), encoding="utf-8")

    # 3. eval.sh matching official shape
    eval_sh_content = (
        "#!/bin/bash\n"
        "set -uxo pipefail\n"
        "source /opt/miniconda3/bin/activate || true\n"
        "conda activate testbed || true\n"
        "cd /testbed\n"
        "git config --global --add safe.directory /testbed\n"
        "git status\n"
        "python -m pip install -e .\n"
        f"git checkout {base_commit} test_target.py || true\n"
        "git apply -v - <<'EOF_TEST'\n"
        f"{test_patch_text}\n"
        "EOF_TEST\n"
        ": '>>>>> Start Test Output'\n"
        "pytest -rA test_target.py\n"
        ": '>>>>> End Test Output'\n"
        f"git checkout {base_commit} test_target.py || true\n"
    )
    eval_sh_bytes = eval_sh_content.encode("utf-8")
    (staging_dir / "eval.sh").write_bytes(eval_sh_bytes)
    eval_sha = hashlib.sha256(eval_sh_bytes).hexdigest()

    spec = {
        "eval_sh_sha256": eval_sha,
        "eval_type": "pass_and_fail",
        "instance_id": instance_id,
        "log_parser": "parse_log_pytest",
        "schema": "hermetic-slice-eval-spec/v1",
        "sha256": eval_sha,
    }
    (staging_dir / "eval_spec.json").write_text(json.dumps(spec, indent=2), encoding="utf-8")

    # Check 1: Gold-style patch gives RESOLVED_FULL
    gold_grade = grade(task_dir, gold_patch_text, image=image, out_dir=tmp_path / "out_gold")
    assert gold_grade["status"] == "graded"
    assert gold_grade["resolution"] == "RESOLVED_FULL"
    assert gold_grade["resolved"] is True
    assert len(gold_grade["f2p"]["success"]) == 1

    # Check 2: Empty patch gives RESOLVED_NO with FAIL_TO_PASS failing
    empty_grade = grade(task_dir, "", image=image, out_dir=tmp_path / "out_empty")
    assert empty_grade["status"] == "graded"
    assert empty_grade["resolution"] == "RESOLVED_NO"
    assert empty_grade["resolved"] is False
    assert len(empty_grade["f2p"]["failure"]) == 1

    # Check 3: A patch that adds conftest.py forcing passes is dropped (finding D11) and stays RESOLVED_NO
    malicious_patch = (
        "diff --git a/conftest.py b/conftest.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/conftest.py\n"
        "@@ -0,0 +1,4 @@\n"
        "+import pytest\n"
        "+@pytest.hookimpl(tryfirst=True)\n"
        "+def pytest_runtest_makereport(item, call):\n"
        "+    pass\n"
    )
    tamper_grade = grade(task_dir, malicious_patch, image=image, out_dir=tmp_path / "out_tamper")
    assert tamper_grade["resolution"] == "RESOLVED_NO"
    assert any(f["kind"] == "test_infra_restored" and f["detector"] == "D11" for f in tamper_grade["findings"])

    # Check 4: Oracle check end to end
    oracle_res = oracle_check(task_dir, image=image, out_root=task_dir / "oracle")
    assert oracle_res["oracle_ok"] is True
    assert oracle_res["gold_resolved"] is True
    assert oracle_res["empty_f2p_all_fail"] is True
    assert (task_dir / "oracle" / "oracle.json").exists()
