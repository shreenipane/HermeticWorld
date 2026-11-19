"""Unit and integration tests for scripts/hermetic-sealer."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

TOP = Path(__file__).resolve().parent.parent.parent
SEALER_PATH = TOP / "scripts" / "hermetic-sealer"

# Ensure sealer is executable
if SEALER_PATH.is_file():
    os.chmod(SEALER_PATH, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def make_dummy_repo(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True, capture_output=True)
    (path / "hello.py").write_text("print('hello')\n")
    subprocess.run(["git", "add", "hello.py"], cwd=path, check=True, capture_output=True)
    env = os.environ.copy()
    env["GIT_AUTHOR_DATE"] = "2020-01-01T00:00:00Z"
    env["GIT_COMMITTER_DATE"] = "2020-01-01T00:00:00Z"
    subprocess.run(["git", "commit", "-m", "initial", "--date=2020-01-01T00:00:00Z"], cwd=path, check=True, env=env, capture_output=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True).stdout.strip()
    return commit


@pytest.fixture
def sealer_fixtures(tmp_path: Path):
    src = tmp_path / "src"
    commit = make_dummy_repo(src)
    out = tmp_path / "out"
    out.mkdir(mode=0o700)

    pkg_rec = tmp_path / "packages.json"
    pkg_rec.write_text(json.dumps({
        "closure_root": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "baseline_month": "2020-01",
        "baseline_root": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    }))

    sub = tmp_path / "substrate.json"
    sub.write_text(json.dumps({
        "substrate": [],
        "substrate_at_t": "none",
        "exemptions": [],
    }))

    run_spec = tmp_path / "run_spec.json"
    run_spec.write_text(json.dumps({
        "env": {"PATH": "/usr/bin:/bin"},
        "workdir": "/testbed",
        "user": "root",
        "entrypoint": ["/bin/sh"],
        "resources": {
            "vcpus": 2,
            "memory_mib": 4096,
            "disk_mib": 8192,
            "wall_time_s": 1800,
        },
    }))

    dns = tmp_path / "dns.json"
    dns.write_text(json.dumps({
        "records": [{"name": "example.com", "a": ["10.9.0.1"], "aaaa": []}],
    }))

    return {
        "src": src,
        "commit": commit,
        "out": out,
        "packages": pkg_rec,
        "substrate": sub,
        "run_spec": run_spec,
        "dns": dns,
    }


def test_sealer_refuses_non_repo_only(sealer_fixtures):
    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(sealer_fixtures["src"]),
            "--out", str(sealer_fixtures["out"]),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "test-world",
            "--seal-level", "strict",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 65
    assert "unsupported seal_level: only repo_only is supported" in res.stderr


def test_sealer_refuses_missing_packages_record(sealer_fixtures):
    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(sealer_fixtures["src"]),
            "--out", str(sealer_fixtures["out"]),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "test-world",
            "--seal-level", "repo_only",
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 65
    assert "missing required input: --packages-record" in res.stderr


def test_sealer_refuses_missing_substrate(sealer_fixtures):
    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(sealer_fixtures["src"]),
            "--out", str(sealer_fixtures["out"]),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "test-world",
            "--seal-level", "repo_only",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 65
    assert "missing required input: --substrate" in res.stderr


def test_sealer_refuses_missing_run_spec(sealer_fixtures, tmp_path: Path):
    isolated = tmp_path / "isolated_no_spec"
    isolated.mkdir()
    empty_src = isolated / "src"
    make_dummy_repo(empty_src)
    out = isolated / "out"
    out.mkdir(mode=0o700)

    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(empty_src),
            "--out", str(out),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "test-world",
            "--seal-level", "repo_only",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 65
    assert "missing required input: run_spec" in res.stderr


def test_sealer_refuses_missing_dns_table(sealer_fixtures, tmp_path: Path):
    isolated = tmp_path / "isolated_no_dns"
    isolated.mkdir()
    empty_src = isolated / "src"
    make_dummy_repo(empty_src)
    out = isolated / "out"
    out.mkdir(mode=0o700)

    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(empty_src),
            "--out", str(out),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "test-world",
            "--seal-level", "repo_only",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 65
    assert "missing required input: dns_table" in res.stderr


def test_sealer_happy_path(sealer_fixtures):
    src = sealer_fixtures["src"]
    out = sealer_fixtures["out"]

    expected_tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=src,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(src),
            "--out", str(out),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "fixture-world",
            "--seal-level", "repo_only",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"sealer failed with exit {res.returncode}:\nstdout: {res.stdout}\nstderr: {res.stderr}"

    manifest_file = out / "world_manifest.json"
    assert manifest_file.is_file(), "world_manifest.json must be created"

    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert manifest["spec_version"] == "hermetic-world/v1"
    assert manifest["task_id"] == "fixture-world"
    assert manifest["seal_level"] == "repo_only"
    assert manifest["repo_tree_digest"] == f"sha1:{expected_tree}"
    assert manifest["rootfs_digest"].startswith("sha256:")
    assert manifest["world_ca_cert_sha256"].startswith("sha256:")
    assert len(manifest["world_ca_cert_sha256"]) == 71  # "sha256:" + 64 hex
    assert manifest["trust_store_paths"] == ["/etc/ssl/certs/ca-certificates.crt"]
    assert manifest["dns_table"] == ["example.com"]
    assert manifest["run_spec"]["workdir"] == "/testbed"
    assert manifest["run_spec"]["user"] == "root"
    assert manifest["run_spec"]["resources"]["vcpus"] == 2
    assert manifest["run_spec"]["resources"]["memory_mib"] == 4096
    assert manifest["run_spec"]["resources"]["disk_mib"] == 8192
    assert manifest["run_spec"]["resources"]["wall_time_s"] == 1800
    assert manifest["sealcheck_report_digest"].startswith("sha256:")

    # Verify rootfs.img exists
    assert (out / "rootfs.img").is_file()


def test_sealer_refuses_parent_traversal_workdir(sealer_fixtures, tmp_path: Path):
    bad_spec = tmp_path / "bad_run_spec.json"
    bad_spec.write_text(json.dumps({
        "env": {"PATH": "/usr/bin:/bin"},
        "workdir": "../../victim",
        "user": "root",
        "entrypoint": ["/bin/sh"],
        "resources": {
            "vcpus": 2,
            "memory_mib": 4096,
            "disk_mib": 8192,
            "wall_time_s": 1800,
        },
    }))
    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(sealer_fixtures["src"]),
            "--out", str(sealer_fixtures["out"]),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "test-world",
            "--seal-level", "repo_only",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(bad_spec),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 65
    assert "workdir contains parent traversal" in res.stderr


def test_sealer_rejects_operational_scan_failures(sealer_fixtures, tmp_path: Path):
    counter = tmp_path / "counter"
    counter.write_text("0")
    fake_sealcheck = tmp_path / "fake_sealcheck"
    fake_sealcheck.write_text(f"""#!/bin/sh
if [ "$2" = "--help" ]; then
    exit 0
fi
cnt=$(cat "{counter}")
echo $((cnt + 1)) > "{counter}"
if [ "$cnt" -eq 0 ]; then
    echo '{{"verdict":"pass","findings":[]}}'
    exit 0
fi
exit 74
""")
    fake_sealcheck.chmod(0o755)

    env = dict(os.environ, HERMETIC_SEALCHECK_BIN=str(fake_sealcheck))
    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(sealer_fixtures["src"]),
            "--out", str(sealer_fixtures["out"]),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "test-world-failure",
            "--seal-level", "repo_only",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 74
    assert not (sealer_fixtures["out"] / "world_manifest.json").exists()


def test_sealer_rejects_empty_scan_output(sealer_fixtures, tmp_path: Path):
    counter = tmp_path / "counter_empty"
    counter.write_text("0")
    fake_sealcheck = tmp_path / "fake_sealcheck_empty"
    fake_sealcheck.write_text(f"""#!/bin/sh
if [ "$2" = "--help" ]; then
    exit 0
fi
cnt=$(cat "{counter}")
echo $((cnt + 1)) > "{counter}"
if [ "$cnt" -eq 0 ]; then
    echo '{{"verdict":"pass","findings":[]}}'
    exit 0
fi
exit 0
""")
    fake_sealcheck.chmod(0o755)

    env = dict(os.environ, HERMETIC_SEALCHECK_BIN=str(fake_sealcheck))
    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(sealer_fixtures["src"]),
            "--out", str(sealer_fixtures["out"]),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "test-world-empty",
            "--seal-level", "repo_only",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 70
    assert not (sealer_fixtures["out"] / "world_manifest.json").exists()
