"""Offline descriptor-pinned snapshot file verification on disk."""

import hashlib
import json
import os
import stat
import pytest

import hermetic_state_snapshot as s
from tests.test_phase4_state_snapshot import encode, recipe, sha


def create_fixture_files(tmp_path):
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir(mode=0o700)
    bodies = {
        name: f"snapshot-payload-{name}".encode("ascii")
        for name in s.ARTIFACT_CAPS
    }
    paths = {}
    for name, data in bodies.items():
        file_path = artifacts_dir / name
        file_path.write_bytes(data)
        file_path.chmod(0o600)
        paths[name] = str(file_path)

    manifest_data = recipe()
    manifest_data["artifacts"] = {
        name: {"sha256": sha(data), "size": len(data)}
        for name, data in bodies.items()
    }
    raw_manifest = encode(manifest_data)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(raw_manifest)
    manifest_path.chmod(0o600)

    expected_sha = sha(raw_manifest)
    run_sha = manifest_data["run_sha256"]
    runtime_sha = sha(encode(manifest_data["runtime"]))

    return manifest_path, artifacts_dir, paths, expected_sha, run_sha, runtime_sha, bodies


def test_load_snapshot_files_known_answer_and_immutable_records(tmp_path, monkeypatch):
    for env_var in ("HOME", "HOSTNAME", "TZ", "LANG", "SOURCE_DATE_EPOCH"):
        monkeypatch.setenv(env_var, "host-secret")

    manifest_path, artifacts_dir, paths, expected_sha, run_sha, runtime_sha, bodies = create_fixture_files(tmp_path)

    files = s.load_snapshot_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)
    assert files.handoff.sha256 == expected_sha
    assert files.handoff.tests_drive == "tests"
    assert files.handoff.network_interfaces == ("eth0",)
    assert len(files.artifacts) == 4

    names_in_order = [item.name for item in files.artifacts]
    assert names_in_order == sorted(s.ARTIFACT_CAPS)

    for item in files.artifacts:
        assert item.size == len(bodies[item.name])
        assert item.sha256 == sha(bodies[item.name])
        assert item.path == paths[item.name]

    # Verify loading immutable bytes from files
    artifacts = s.load_snapshot_artifacts_from_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)
    assert artifacts.handoff.sha256 == expected_sha
    assert artifacts.artifacts == tuple(sorted(bodies.items()))


def test_load_snapshot_files_supports_dict_of_paths(tmp_path):
    manifest_path, _, paths, expected_sha, run_sha, runtime_sha, bodies = create_fixture_files(tmp_path)

    files = s.load_snapshot_files(manifest_path, paths, expected_sha, run_sha, runtime_sha)
    assert files.handoff.sha256 == expected_sha
    assert len(files.artifacts) == 4
    for item in files.artifacts:
        assert item.size == len(bodies[item.name])
        assert item.sha256 == sha(bodies[item.name])


def test_load_snapshot_files_refuses_symlink_manifest(tmp_path):
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, _ = create_fixture_files(tmp_path)

    symlink_manifest = tmp_path / "symlink_manifest.json"
    symlink_manifest.symlink_to(manifest_path)

    with pytest.raises(s.SnapshotError):
        s.load_snapshot_files(symlink_manifest, artifacts_dir, expected_sha, run_sha, runtime_sha)


@pytest.mark.parametrize("name", ["state", "memory", "base", "overlay"])
def test_load_snapshot_files_refuses_symlink_artifact(tmp_path, name):
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, _ = create_fixture_files(tmp_path)

    target_file = artifacts_dir / name
    real_file = tmp_path / f"real_{name}"
    target_file.rename(real_file)
    target_file.symlink_to(real_file)

    with pytest.raises(s.SnapshotError):
        s.load_snapshot_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)


def test_load_snapshot_files_refuses_fifo_artifact(tmp_path):
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, _ = create_fixture_files(tmp_path)

    fifo_file = artifacts_dir / "memory"
    fifo_file.unlink()
    os.mkfifo(str(fifo_file), 0o600)

    with pytest.raises(s.SnapshotError):
        s.load_snapshot_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)


def test_load_snapshot_files_refuses_directory_artifact(tmp_path):
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, _ = create_fixture_files(tmp_path)

    dir_file = artifacts_dir / "base"
    dir_file.unlink()
    dir_file.mkdir(mode=0o700)

    with pytest.raises(s.SnapshotError):
        s.load_snapshot_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)


def test_load_snapshot_files_refuses_missing_file(tmp_path):
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, _ = create_fixture_files(tmp_path)

    (artifacts_dir / "state").unlink()

    with pytest.raises(s.SnapshotError):
        s.load_snapshot_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)


def test_load_snapshot_files_refuses_tampered_digest(tmp_path):
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, bodies = create_fixture_files(tmp_path)

    tampered = bytearray(bodies["overlay"])
    tampered[0] ^= 0x01
    (artifacts_dir / "overlay").write_bytes(tampered)

    with pytest.raises(s.SnapshotError, match="snapshot payload digest mismatch"):
        s.load_snapshot_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)


def test_load_snapshot_files_refuses_size_mismatch(tmp_path):
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, bodies = create_fixture_files(tmp_path)

    (artifacts_dir / "overlay").write_bytes(bodies["overlay"] + b"x")

    with pytest.raises(s.SnapshotError):
        s.load_snapshot_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)


@pytest.mark.parametrize("pin", ["expected_sha", "run_sha", "runtime_sha"])
def test_load_snapshot_files_refuses_wrong_pin(tmp_path, pin):
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, _ = create_fixture_files(tmp_path)
    pins = {
        "expected_sha": expected_sha,
        "run_sha": run_sha,
        "runtime_sha": runtime_sha,
    }
    pins[pin] = "0" * 64

    with pytest.raises(s.SnapshotError):
        s.load_snapshot_files(manifest_path, artifacts_dir, pins["expected_sha"], pins["run_sha"], pins["runtime_sha"])


def test_load_snapshot_files_refuses_dict_with_wrong_keys(tmp_path):
    manifest_path, _, paths, expected_sha, run_sha, runtime_sha, _ = create_fixture_files(tmp_path)
    bad_paths = dict(paths)
    del bad_paths["state"]

    with pytest.raises(s.SnapshotError):
        s.load_snapshot_files(manifest_path, bad_paths, expected_sha, run_sha, runtime_sha)


def test_load_snapshot_files_diagnostics_never_leak_host_paths_or_names(tmp_path):
    secret_dir = tmp_path / "super-secret-host-dir"
    secret_dir.mkdir(mode=0o700)
    manifest_path, _, _, expected_sha, run_sha, runtime_sha, _ = create_fixture_files(secret_dir)

    # Induce an error by passing a nonexistent artifacts dir inside secret_dir
    with pytest.raises(s.SnapshotError) as exc_info:
        s.load_snapshot_files(manifest_path, secret_dir / "nonexistent", expected_sha, run_sha, runtime_sha)

    assert "super-secret-host-dir" not in str(exc_info.value)
    assert "/" not in str(exc_info.value)


def test_load_snapshot_files_handles_short_reads(tmp_path, monkeypatch):
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, bodies = create_fixture_files(tmp_path)
    real_read = os.read

    def short_read(fd, n):
        return real_read(fd, min(n, 3))

    monkeypatch.setattr(os, "read", short_read)
    files = s.load_snapshot_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)
    assert len(files.artifacts) == 4

    artifacts = s.load_snapshot_artifacts_from_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)
    assert artifacts.artifacts == tuple(sorted(bodies.items()))


def test_load_snapshot_artifacts_from_files_read_error_raises_snapshot_error(tmp_path, monkeypatch):
    import errno
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, _ = create_fixture_files(tmp_path)
    real_read = os.read
    read_count = 0

    def failing_read(fd, n):
        nonlocal read_count
        read_count += 1
        if read_count > 5:
            raise OSError(errno.EIO, "simulated I/O error")
        return real_read(fd, n)

    monkeypatch.setattr(os, "read", failing_read)
    with pytest.raises(s.SnapshotError, match="snapshot artifact read failed"):
        s.load_snapshot_artifacts_from_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)


def test_load_snapshot_artifacts_from_files_authenticates_exact_bytes(tmp_path):
    manifest_path, artifacts_dir, _, expected_sha, run_sha, runtime_sha, bodies = create_fixture_files(tmp_path)

    tampered = bytearray(bodies["state"])
    tampered[0] ^= 0x01
    (artifacts_dir / "state").write_bytes(tampered)

    with pytest.raises(s.SnapshotError, match="snapshot payload digest mismatch"):
        s.load_snapshot_artifacts_from_files(manifest_path, artifacts_dir, expected_sha, run_sha, runtime_sha)
