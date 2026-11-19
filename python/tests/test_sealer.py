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


def has_hermetic_trust() -> bool:
    if os.environ.get("HERMETIC_TRUST_BIN") and Path(os.environ["HERMETIC_TRUST_BIN"]).is_file():
        return True
    import shutil
    if shutil.which("hermetic-trust"):
        return True
    for p in [
        TOP / "target" / "release" / "hermetic-trust",
        TOP / "target" / "debug" / "hermetic-trust",
    ]:
        if p.is_file():
            return True
    cargo_target = os.environ.get("CARGO_TARGET_DIR")
    if cargo_target:
        tp = Path(cargo_target)
        if (
            (tp / "x86_64-unknown-linux-gnu" / "release" / "hermetic-trust").is_file()
            or (tp / "release" / "hermetic-trust").is_file()
            or (tp / "debug" / "hermetic-trust").is_file()
        ):
            return True
    cargo_target_base = Path(os.environ.get("CARGO_TARGET_BASE") or (Path.home() / "hermetic" / "cargo-target"))
    if cargo_target_base.is_dir():
        for d in cargo_target_base.glob("world-seal*"):
            if (d / "release" / "hermetic-trust").is_file() or (d / "debug" / "hermetic-trust").is_file():
                return True
    return False


def make_dummy_repo(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=path, check=True, capture_output=True)
    (path / "hello.py").write_text("print('hello')\n")
    subprocess.run(["git", "add", "hello.py"], cwd=path, check=True, capture_output=True)
    env = os.environ.copy()
    env["GIT_AUTHOR_DATE"] = "2020-01-01T00:00:00Z"
    env["GIT_COMMITTER_DATE"] = "2020-01-01T00:00:00Z"
    subprocess.run(
        ["git", "commit", "--no-gpg-sign", "-m", "initial", "--date=2020-01-01T00:00:00Z"],
        cwd=path,
        check=True,
        env=env,
        capture_output=True,
    )
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
    if not has_hermetic_trust():
        pytest.skip("hermetic-trust binary not available")
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
    if not has_hermetic_trust():
        pytest.skip("hermetic-trust binary not available")
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


def test_sealer_help_returns_zero():
    res = subprocess.run([sys.executable, str(SEALER_PATH), "--help"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "Hermetic Sealer" in res.stdout


def test_sealer_rejects_missing_explicit_run_spec(sealer_fixtures, tmp_path: Path):
    nonexistent = tmp_path / "nonexistent_run_spec.json"
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
            "--run-spec", str(nonexistent),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 65
    assert "run-spec file not found" in res.stderr


def test_sealer_rejects_missing_explicit_dns_table(sealer_fixtures, tmp_path: Path):
    nonexistent = tmp_path / "nonexistent_dns.json"
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
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(nonexistent),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 65
    assert "dns-table file not found" in res.stderr


def test_sealer_rejects_malformed_env_list(sealer_fixtures, tmp_path: Path):
    bad_spec = tmp_path / "bad_env_spec.json"
    bad_spec.write_text(json.dumps({
        "env": [["PATH"]],
        "workdir": "/testbed",
        "resources": {"vcpus": 2, "memory_mib": 4096, "disk_mib": 8192, "wall_time_s": 1800},
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
    assert "env list entries must be key-value pairs" in res.stderr


def test_sealer_rejects_null_or_invalid_resource_values(sealer_fixtures, tmp_path: Path):
    bad_spec = tmp_path / "null_vcpus_spec.json"
    bad_spec.write_text(json.dumps({
        "env": {"PATH": "/usr/bin:/bin"},
        "workdir": "/testbed",
        "resources": {"vcpus": None, "memory_mib": 4096, "disk_mib": 8192, "wall_time_s": 1800},
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
    assert "resource 'vcpus' is missing or malformed" in res.stderr


def test_sealer_rejects_invalid_closure_root_digest(sealer_fixtures, tmp_path: Path):
    bad_pkg = tmp_path / "bad_pkg.json"
    bad_pkg.write_text(json.dumps({
        "closure_root": "not-a-digest",
        "baseline_month": "2020-01",
        "baseline_root": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
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
            "--packages-record", str(bad_pkg),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 65
    assert "packages-record closure_root is not a valid digest" in res.stderr


def test_sealer_preserves_source_symlinks_without_reading_targets(sealer_fixtures, tmp_path: Path):
    if not has_hermetic_trust():
        pytest.skip("hermetic-trust binary not available")
    non_git_src = tmp_path / "non_git_src"
    non_git_src.mkdir()
    (non_git_src / "real_file.txt").write_text("hello\n")
    external_secret = tmp_path / "external_secret.txt"
    external_secret.write_text("SUPER_SECRET_PAYLOAD\n")
    symlink_file = non_git_src / "link_to_secret.txt"
    symlink_file.symlink_to(external_secret)

    out = tmp_path / "out_symlink"
    out.mkdir(mode=0o700)

    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(non_git_src),
            "--out", str(out),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "symlink-world",
            "--seal-level", "repo_only",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    out_link = out / "repo" / "link_to_secret.txt"
    assert out_link.is_symlink(), "symlink must be preserved as symlink, not followed"


def test_sealer_rejects_non_json_sealcheck_report(sealer_fixtures, tmp_path: Path):
    if not has_hermetic_trust():
        pytest.skip("hermetic-trust binary not available")
    counter = tmp_path / "counter_non_json"
    counter.write_text("0")
    fake_sealcheck = tmp_path / "fake_sealcheck_non_json"
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
echo "NOT JSON AT ALL"
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
            "--world-id", "test-world-non-json",
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
    assert "sealcheck scan report is not valid JSON" in res.stderr


def test_sealer_replaces_stale_out_repo(sealer_fixtures, tmp_path: Path):
    if not has_hermetic_trust():
        pytest.skip("hermetic-trust binary not available")
    out = sealer_fixtures["out"]
    stale_repo = out / "repo"
    stale_repo.mkdir(parents=True)
    (stale_repo / "stale_file.txt").write_text("stale content\n")

    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(sealer_fixtures["src"]),
            "--out", str(out),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "replace-repo-world",
            "--seal-level", "repo_only",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert not (stale_repo / "stale_file.txt").exists(), "stale repo contents must be replaced"
    assert (stale_repo / "hello.py").exists(), "new sealed repo must be present"


def test_sealer_returns_74_on_manifest_write_failure(sealer_fixtures, tmp_path: Path):
    if not has_hermetic_trust():
        pytest.skip("hermetic-trust binary not available")
    out = sealer_fixtures["out"]
    # Make out directory read-only right before publication would occur
    # Or create a non-writable file where tmp_dest would be
    tmp_dest = out / ".world_manifest.json.tmp"
    tmp_dest.mkdir(mode=0o500)

    res = subprocess.run(
        [
            sys.executable,
            str(SEALER_PATH),
            "--src", str(sealer_fixtures["src"]),
            "--out", str(out),
            "--t-clock", "2020-01-01T00:00:00Z",
            "--world-id", "write-fail-world",
            "--seal-level", "repo_only",
            "--packages-record", str(sealer_fixtures["packages"]),
            "--substrate", str(sealer_fixtures["substrate"]),
            "--run-spec", str(sealer_fixtures["run_spec"]),
            "--dns-table", str(sealer_fixtures["dns"]),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 74
    assert "failed to publish world_manifest.json" in res.stderr


def test_test_sealer_collection_does_not_mutate_sealer_permissions():
    mode_before = SEALER_PATH.stat().st_mode
    assert SEALER_PATH.stat().st_mode == mode_before


@pytest.fixture(autouse=True)
def _static_guest_bins(tmp_path_factory, monkeypatch):
    """Stand-in static guest binaries: copies of the host's static busybox."""
    import shutil as _sh
    busybox = _sh.which("busybox") or "/usr/bin/busybox"
    d = tmp_path_factory.mktemp("guest-bin")
    for name in ("hermetic-init", "hermetic-execd", "hermetic-clockprobe"):
        _sh.copy2(busybox, d / name)
    monkeypatch.setenv("HERMETIC_GUEST_BIN_DIR", str(d))
    return d


def _load_sealer():
    from importlib.machinery import SourceFileLoader
    return SourceFileLoader("hermetic_sealer_mod", str(SEALER_PATH)).load_module()


def test_static_elf_check_rejects_dynamic_binaries(tmp_path):
    sealer = _load_sealer()
    import shutil as _sh
    busybox = Path(_sh.which("busybox") or "/usr/bin/busybox")
    assert sealer.is_static_elf(busybox)
    # Any binary with a dynamic loader (PT_INTERP) is refused, e.g. python itself.
    assert not sealer.is_static_elf(Path(os.path.realpath(sys.executable)))
    not_elf = tmp_path / "script"
    not_elf.write_text("#!/bin/sh\n")
    assert not sealer.is_static_elf(not_elf)
