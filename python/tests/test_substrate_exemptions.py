"""Offline tests for substrate inventory, named exemptions (D4/D6), and runner integration."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import zipfile

import pytest

from hermetic_slice.substrate import (
    MAX_DEPTH,
    MAX_SUBSTRATE_EXEMPTIONS,
    generate_exemptions,
    inventory_substrate,
    is_repo_or_task_dep,
    validate_exemption_path,
    write_substrate_outputs,
)

T_CLOCK = datetime(2024, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
T_CLOCK_SECS = int(T_CLOCK.timestamp())


def _find_sealcheck_bin() -> str | None:
    env_bin = os.environ.get("HERMETIC_SEALCHECK_BIN")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    cargo_target = os.environ.get("CARGO_TARGET_DIR")
    candidates = []
    if cargo_target:
        candidates.extend([
            Path(cargo_target) / "debug" / "hermetic-sealcheck",
            Path(cargo_target) / "debug" / "sealcheck",
        ])
    top = Path(__file__).resolve().parents[2]
    worktree_name = top.name
    candidates.extend([
        top / "target/debug/hermetic-sealcheck",
        top / "target/debug/sealcheck",
        Path(f"{Path.home()}/hermetic/cargo-target/{worktree_name}/debug/hermetic-sealcheck"),
        Path(f"{Path.home()}/hermetic/cargo-target/{worktree_name}/debug/sealcheck"),
    ])
    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK):
            return str(p.resolve())
    return None


def test_is_repo_or_task_dep():
    assert is_repo_or_task_dep("testbed")
    assert is_repo_or_task_dep("testbed/src/app.py")
    assert is_repo_or_task_dep(".git/config")
    assert is_repo_or_task_dep("sub/testbed/file.py")
    assert is_repo_or_task_dep("opt/miniconda3/envs/testbed/bin/python")
    assert is_repo_or_task_dep("opt/conda/envs/my_env/lib.py")

    assert not is_repo_or_task_dep("usr/bin/python3")
    assert not is_repo_or_task_dep("opt/miniconda3/bin/python3")
    assert not is_repo_or_task_dep("etc/passwd")


def test_validate_exemption_path_safety():
    # Valid relative substrate paths
    assert validate_exemption_path("usr/bin/python3") == "usr/bin/python3"
    assert validate_exemption_path("/usr/bin/python3") == "usr/bin/python3"
    assert validate_exemption_path("./usr/bin/python3") == "usr/bin/python3"

    # Forbidden repository paths
    with pytest.raises(ValueError, match="Forbidden exemption inside repository"):
        validate_exemption_path("testbed")
    with pytest.raises(ValueError, match="Forbidden exemption inside repository"):
        validate_exemption_path("testbed/foo.py")
    with pytest.raises(ValueError, match="Forbidden exemption inside repository"):
        validate_exemption_path("a/testbed/b.py")

    # Forbidden task dependency paths
    with pytest.raises(ValueError, match="Forbidden exemption inside task dependency"):
        validate_exemption_path("opt/miniconda3/envs/testbed/bin/python")
    with pytest.raises(ValueError, match="Forbidden exemption inside task dependency"):
        validate_exemption_path("opt/conda/envs/foo/lib.py")

    # Forbidden pattern and directory exemptions
    with pytest.raises(ValueError, match="Pattern or directory exemption is forbidden"):
        validate_exemption_path("usr/bin/*")
    with pytest.raises(ValueError, match="Pattern or directory exemption is forbidden"):
        validate_exemption_path("usr/bin/")
    with pytest.raises(ValueError, match="Pattern or directory exemption is forbidden"):
        validate_exemption_path("usr/lib/?.so")

    # Forbidden traversal
    with pytest.raises(ValueError, match="relative components"):
        validate_exemption_path("usr/../bin/python3")


def test_inventory_skips_repository_and_task_dependencies(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()

    # Substrate files
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/python3").write_bytes(b"#!/bin/sh\necho py\n")
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/libssl.so").write_bytes(b"\x7fELFfake")

    # Repository files (must be skipped)
    (root / "testbed").mkdir(parents=True)
    (root / "testbed/setup.py").write_text("from setuptools import setup", encoding="utf-8")
    (root / "testbed/.git").mkdir(parents=True)
    (root / "testbed/.git/config").write_text("[core]", encoding="utf-8")

    # Task dependency closure (must be skipped)
    (root / "opt/miniconda3/envs/testbed/bin").mkdir(parents=True)
    (root / "opt/miniconda3/envs/testbed/bin/pytest").write_bytes(b"pytest-bin")
    (root / "opt/conda/envs/testbed/lib").mkdir(parents=True)
    (root / "opt/conda/envs/testbed/lib/libdep.so").write_bytes(b"libdep")

    inv = inventory_substrate(root)
    paths = [e["path"] for e in inv["entries"]]

    assert "usr/bin/python3" in paths
    assert "usr/lib/libssl.so" in paths

    # None of the repository or dependency files should be present
    for p in paths:
        assert not p.startswith("testbed")
        assert not p.startswith(".git")
        assert not p.startswith("opt/miniconda3/envs")
        assert not p.startswith("opt/conda/envs")


def test_inventory_archive_members(tmp_path: Path):
    root = tmp_path / "root"
    whl_dir = root / "opt/miniconda3/lib/python3.8/site-packages"
    whl_dir.mkdir(parents=True)
    whl_path = whl_dir / "pip-23.0-py3-none-any.whl"

    member_data = b"__version__ = '23.0'\n"
    with zipfile.ZipFile(whl_path, "w") as zf:
        zf.writestr("pip/__init__.py", member_data)

    inv = inventory_substrate(root)
    paths = [e["path"] for e in inv["entries"]]

    member_rel = "opt/miniconda3/lib/python3.8/site-packages/pip-23.0-py3-none-any.whl!/pip/__init__.py"
    assert "opt/miniconda3/lib/python3.8/site-packages/pip-23.0-py3-none-any.whl" in paths
    assert member_rel in paths

    member_entry = next(e for e in inv["entries"] if e["path"] == member_rel)
    assert member_entry["sha256"] == hashlib.sha256(member_data).hexdigest()


def test_generate_exemptions_d4_and_d6(tmp_path: Path):
    root = tmp_path / "root"
    sub_bin = root / "usr/bin"
    sub_bin.mkdir(parents=True)
    py_path = sub_bin / "python3"
    py_path.write_bytes(b"python3 binary")
    # Set post-cutoff mtime
    os.utime(py_path, (T_CLOCK_SECS + 500, T_CLOCK_SECS + 500))

    # Add pip wheel with late member date
    whl_dir = root / "opt/pip"
    whl_dir.mkdir(parents=True)
    whl_path = whl_dir / "pip-23.0.whl"
    with zipfile.ZipFile(whl_path, "w") as zf:
        info = zipfile.ZipInfo("pip/_vendor/six.py", (2026, 6, 1, 12, 0, 0))
        zf.writestr(info, b"six module")
    os.utime(whl_path, (T_CLOCK_SECS - 100, T_CLOCK_SECS - 100))

    # OCI inspect file with post-cutoff Created date
    inspect_path = tmp_path / "source-inspect.json"
    inspect_json = [
        {
            "Id": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "Created": "2026-08-15 06:04:51 +0000 UTC",
            "Config": {"Env": []},
        }
    ]
    inspect_path.write_text(json.dumps(inspect_json), encoding="utf-8")

    inv = inventory_substrate(root)
    exemptions_doc = generate_exemptions(
        root,
        inv,
        T_CLOCK,
        oci_inspect_path=inspect_path,
    )

    exs = exemptions_doc["exemptions"]
    assert exemptions_doc["substrate_at_t"] == "partial"
    assert len(exs) == 3

    detectors = {e["detector"] for e in exs}
    assert detectors == {"D4", "D6"}

    d6_ex = next(e for e in exs if e["detector"] == "D6")
    assert d6_ex["path"] == "source-inspect.json"
    assert d6_ex["reason"] == "post_cutoff_image_created"

    d4_paths = [e["path"] for e in exs if e["detector"] == "D4"]
    assert "usr/bin/python3" in d4_paths
    assert "opt/pip/pip-23.0.whl!/pip/_vendor/six.py" in d4_paths

    # Verify exemption_list is strictly sorted and unique
    ex_list = exemptions_doc["exemption_list"]
    assert ex_list == sorted(list(set(ex_list)))


def test_determinism(tmp_path: Path):
    root = tmp_path / "root"
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/b_tool").write_bytes(b"b")
    (root / "usr/bin/a_tool").write_bytes(b"a")
    (root / "usr/bin/c_tool").write_bytes(b"c")

    inv1 = inventory_substrate(root)
    inv2 = inventory_substrate(root)
    assert inv1 == inv2
    assert inv1["inventory_digest"] == inv2["inventory_digest"]

    # Entries must be strictly sorted by path
    paths = [e["path"] for e in inv1["entries"]]
    assert paths == sorted(paths)

    ex1 = generate_exemptions(root, inv1, T_CLOCK)
    ex2 = generate_exemptions(root, inv2, T_CLOCK)
    assert ex1 == ex2
    assert ex1["exemption_list_digest"] == ex2["exemption_list_digest"]


def test_caps_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "root"
    (root / "usr").mkdir(parents=True)
    (root / "usr/file").write_bytes(b"data")

    import hermetic_slice.substrate as sub_mod
    monkeypatch.setattr(sub_mod, "MAX_SUBSTRATE_FILES", 0)
    with pytest.raises(ValueError, match="Substrate file count exceeds cap"):
        inventory_substrate(root)

    monkeypatch.setattr(sub_mod, "MAX_DEPTH", 0)
    with pytest.raises(ValueError, match="Directory traversal exceeded depth limit"):
        inventory_substrate(root)


def test_sealcheck_cli_offline_fixture_passes_with_exemptions(tmp_path: Path):
    sealcheck = _find_sealcheck_bin()
    if not sealcheck:
        pytest.skip("sealcheck binary not available in target/debug")

    # Prepare base tree, task tree, and source tree
    base_tree = tmp_path / "base-tree"
    base_tree.mkdir()
    source_tree = tmp_path / "source-tree"
    source_tree.mkdir()
    task_dir = tmp_path / "task"
    task_dir.mkdir()

    # Task input
    task_json = {
        "instance_id": "fixture_task_001",
        "repo": "owner/fixture_repo",
        "base_commit": "0123456789abcdef0123456789abcdef01234567",
        "version": "1.0",
        "problem_statement": "Fix the issue in the fixture.",
        "gold_patch": "",
        "test_patch": "",
        "passing_fixes": [],
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-02T00:00:00Z",
        },
    }
    (task_dir / "task.json").write_text(json.dumps(task_json), encoding="utf-8")
    staging_dir = task_dir / "staging"
    staging_dir.mkdir()
    (staging_dir / "gold.patch").write_text("", encoding="utf-8")
    (staging_dir / "test.patch").write_text("", encoding="utf-8")
    agent_dir = task_dir / "agent"
    agent_dir.mkdir()
    (agent_dir / "problem_statement.md").write_text("Fix the issue in the fixture.", encoding="utf-8")

    # 1. Post-cutoff substrate file
    sub_bin = source_tree / "usr/bin"
    sub_bin.mkdir(parents=True)
    py_path = sub_bin / "python3"
    py_path.write_bytes(b"#!/bin/sh\necho py\n")
    os.utime(py_path, (T_CLOCK_SECS + 500, T_CLOCK_SECS + 500))

    # Backdate directories
    for p in (source_tree, source_tree / "usr", sub_bin):
        os.utime(p, (T_CLOCK_SECS - 100, T_CLOCK_SECS - 100))

    # OCI inspect file with post-cutoff Created date
    inspect_path = tmp_path / "source-inspect.json"
    inspect_json = [
        {
            "Id": "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            "Created": "2026-08-15 06:04:51 +0000 UTC",
            "Config": {"Env": []},
        }
    ]
    inspect_path.write_text(json.dumps(inspect_json), encoding="utf-8")

    # Generate substrate inventory and exemptions
    inv = inventory_substrate(source_tree)
    exemptions_doc = generate_exemptions(
        source_tree,
        inv,
        T_CLOCK,
        oci_inspect_path=inspect_path,
    )
    inv_file, ex_file = write_substrate_outputs(tmp_path, inv, exemptions_doc)

    # 1. Scan WITHOUT exemptions -> Gates on D4 and D6
    cmd_no_ex = [
        sealcheck, "scan",
        "--task", str(task_dir),
        "--base-tree", str(base_tree),
        "--root", str(source_tree),
        "--oci-inspect", str(inspect_path),
    ]
    res_no_ex = subprocess.run(cmd_no_ex, capture_output=True, text=True, check=False)
    assert res_no_ex.returncode == 2  # Gated!
    report_no_ex = json.loads(res_no_ex.stdout)
    assert report_no_ex["gate"] is True
    assert any(f["detector"] == "D4" for f in report_no_ex["findings"])
    assert any(f["detector"] == "D6" for f in report_no_ex["findings"])

    # 2. Scan WITH exemptions -> Passes (exit 0, gate = false)
    cmd_ex = cmd_no_ex + ["--exemptions", str(ex_file)]
    res_ex = subprocess.run(cmd_ex, capture_output=True, text=True, check=False)
    assert res_ex.returncode == 0  # Passed!
    report_ex = json.loads(res_ex.stdout)
    assert report_ex["gate"] is False

    # 3. Tamper with digest -> Fails!
    tampered_doc = dict(exemptions_doc)
    tampered_doc["exemptions"] = [
        dict(e, sha256="0000000000000000000000000000000000000000000000000000000000000000")
        for e in exemptions_doc["exemptions"]
    ]
    tampered_file = tmp_path / "tampered_exemptions.json"
    tampered_file.write_text(json.dumps(tampered_doc), encoding="utf-8")

    cmd_tampered = cmd_no_ex + ["--exemptions", str(tampered_file)]
    res_tampered = subprocess.run(cmd_tampered, capture_output=True, text=True, check=False)
    assert res_tampered.returncode == 2  # Gated!
    report_tampered = json.loads(res_tampered.stdout)
    assert report_tampered["gate"] is True

    # 4. Post-cutoff repository file STILL fails even with exemptions
    repo_src = source_tree / "testbed"
    repo_src.mkdir(parents=True)
    repo_file = repo_src / "solution.py"
    repo_file.write_bytes(b"# repo fix\n")
    os.utime(repo_file, (T_CLOCK_SECS + 500, T_CLOCK_SECS + 500))
    os.utime(repo_src, (T_CLOCK_SECS - 100, T_CLOCK_SECS - 100))

    res_repo = subprocess.run(cmd_ex, capture_output=True, text=True, check=False)
    assert res_repo.returncode == 2  # Gated on repository file!
    report_repo = json.loads(res_repo.stdout)
    assert report_repo["gate"] is True
    repo_findings = [f for f in report_repo["findings"] if f["path"] == "testbed/solution.py"]
    assert len(repo_findings) == 1
    assert repo_findings[0]["detector"] == "D4"


def test_load_run_exemptions_authoritative_entries(tmp_path: Path):
    from hermetic_slice.runner import load_run_exemptions

    # 1. Accepted document format {"exemptions": [...]}
    task_dir1 = tmp_path / "task1"
    seal_dir1 = task_dir1 / "seal"
    seal_dir1.mkdir(parents=True)
    doc_json = {
        "exemptions": [
            {
                "path": "usr/bin/python3",
                "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "detector": "D4",
                "reason": "base_interpreter",
            }
        ]
    }
    (seal_dir1 / "exemptions.json").write_text(json.dumps(doc_json), encoding="utf-8")
    status1, ex_list1 = load_run_exemptions(task_dir1)
    assert status1 == "partial"
    assert ex_list1 == ["usr/bin/python3"]

    # 2. Top-level array format [...]
    task_dir2 = tmp_path / "task2"
    task_dir2.mkdir()
    arr_json = [
        {
            "path": "source-inspect.json",
            "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "detector": "D6",
            "reason": "oci_metadata",
        }
    ]
    (task_dir2 / "exemptions.json").write_text(json.dumps(arr_json), encoding="utf-8")
    status2, ex_list2 = load_run_exemptions(task_dir2)
    assert status2 == "partial"
    assert ex_list2 == ["source-inspect.json"]

    # 3. Validated empty exemption set
    task_dir3 = tmp_path / "task3"
    task_dir3.mkdir()
    (task_dir3 / "exemptions.json").write_text(json.dumps({"exemptions": []}), encoding="utf-8")
    status3, ex_list3 = load_run_exemptions(task_dir3)
    assert status3 == "full"
    assert ex_list3 == []

    # 4. Corrupt / invalid exemptions file -> "none"
    task_dir4 = tmp_path / "task4"
    task_dir4.mkdir()
    (task_dir4 / "exemptions.json").write_text("{invalid json", encoding="utf-8")
    status4, ex_list4 = load_run_exemptions(task_dir4)
    assert status4 == "none"
    assert ex_list4 == []

    # 5. Nonexistent exemptions file -> "full"
    task_dir5 = tmp_path / "task5"
    task_dir5.mkdir()
    status5, ex_list5 = load_run_exemptions(task_dir5)
    assert status5 == "full"
    assert ex_list5 == []


def test_inventory_zip_duplicate_and_corrupt_members(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    whl_path = root / "test.whl"

    # Create zip with duplicate member names having different contents
    with zipfile.ZipFile(whl_path, "w") as zf:
        info1 = zipfile.ZipInfo("dup.txt", (2024, 1, 1, 0, 0, 0))
        zf.writestr(info1, b"first content")
        info2 = zipfile.ZipInfo("dup.txt", (2024, 1, 1, 0, 0, 0))
        zf.writestr(info2, b"second content")

    inv = inventory_substrate(root)
    dup_entries = [e for e in inv["entries"] if e["path"].endswith("!/dup.txt")]
    assert len(dup_entries) == 2
    # Verify each member entry was hashed from its own distinct ZipInfo
    hashes = {e["sha256"] for e in dup_entries}
    assert hashes == {
        hashlib.sha256(b"first content").hexdigest(),
        hashlib.sha256(b"second content").hexdigest(),
    }


def test_generate_exemptions_opens_archive_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "root"
    root.mkdir()
    whl_path = root / "multi.whl"

    with zipfile.ZipFile(whl_path, "w") as zf:
        zf.writestr(zipfile.ZipInfo("a.py", (2026, 1, 1, 0, 0, 0)), b"a")
        zf.writestr(zipfile.ZipInfo("b.py", (2026, 1, 1, 0, 0, 0)), b"b")
        zf.writestr(zipfile.ZipInfo("c.py", (2026, 1, 1, 0, 0, 0)), b"c")
    os.utime(whl_path, (T_CLOCK_SECS - 100, T_CLOCK_SECS - 100))

    inv = inventory_substrate(root)
    open_count = 0
    orig_zipfile_init = zipfile.ZipFile.__init__

    def counting_zipfile_init(self, *args, **kwargs):
        nonlocal open_count
        open_count += 1
        orig_zipfile_init(self, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "__init__", counting_zipfile_init)
    exemptions_doc = generate_exemptions(root, inv, T_CLOCK)
    assert len(exemptions_doc["exemptions"]) == 3
    # Archive should only be opened once for all 3 members
    assert open_count == 1


def test_inventory_substrate_unhashable_file_fails_closed(tmp_path: Path):
    from hermetic_safe_io import UnsafePathError

    root = tmp_path / "root"
    sub_dir = root / "usr/bin"
    sub_dir.mkdir(parents=True)
    big_file = sub_dir / "oversized_tool"

    # Write file exceeding MAX_VERIFY_FILE_BYTES
    import hermetic_slice.substrate as sub_mod
    orig_cap = sub_mod.MAX_VERIFY_FILE_BYTES
    try:
        sub_mod.MAX_VERIFY_FILE_BYTES = 10
        big_file.write_bytes(b"0123456789_toolarge")
        with pytest.raises((ValueError, UnsafePathError)):
            inventory_substrate(root)
    finally:
        sub_mod.MAX_VERIFY_FILE_BYTES = orig_cap
