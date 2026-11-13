
"""Comprehensive tests for Hermetic World Experiment E7."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import hermetic_e7.compare as compare_mod
import hermetic_e7.tree as tree_mod
from hermetic_e7.__main__ import main
from hermetic_e7.compare import EXT4_BLOCK_SIZE, classify_file, compare_worlds, format_report
from hermetic_e7.tree import (
    CapExceededError,
    UnsupportedEntryError,
    WorldPathError,
    build_manifest,
    canonical_manifest_bytes,
)


def _populate_sample_world(root: Path) -> None:
    """Build a deterministic fixture world containing dirs, text, binary, and executable files."""
    (root / "empty_dir").mkdir(parents=True)
    sub = root / "sub"
    sub.mkdir(parents=True)
    (root / "readme.txt").write_text("line 1\nline 2\nline 3\n", encoding="utf-8")
    script = sub / "run.sh"
    script.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    os.chmod(script, 0o755)
    (sub / "data.bin").write_bytes(b"\x00\x01\x02\x03\xff")


def test_identical_trees_manifest_and_reproducible(tmp_path: Path) -> None:
    """Requirement 1 & 2: Identical trees produce identical canonical root hashes and reproducible report."""
    world_a = tmp_path / "world_a"
    world_b = tmp_path / "world_b"
    world_a.mkdir()
    world_b.mkdir()
    _populate_sample_world(world_a)
    _populate_sample_world(world_b)

    # Set distinct mtimes on world_b to prove timestamps on disk do not affect sealing.
    os.utime(world_b / "readme.txt", (1_700_000_000, 1_700_000_000))

    manifest_a = build_manifest(world_a)
    manifest_b = build_manifest(world_b)

    assert manifest_a == manifest_b
    paths = [entry["path"] for entry in manifest_a["entries"]]
    assert paths == sorted(paths, key=lambda p: p.encode("utf-8"))
    assert "empty_dir" in paths
    assert "sub" in paths

    run_entry = next(e for e in manifest_a["entries"] if e["path"] == "sub/run.sh")
    assert run_entry["executable"] is True
    assert run_entry["size"] == len(b"#!/bin/sh\necho ok\n")
    assert run_entry["sha256"] == hashlib.sha256(b"#!/bin/sh\necho ok\n").hexdigest()

    # Verify root equals SHA-256 of canonical JSON manifest (sorted keys, no spaces).
    canonical = json.dumps({"entries": manifest_a["entries"]}, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    assert canonical == canonical_manifest_bytes({"entries": manifest_a["entries"]})
    assert manifest_a["root"] == hashlib.sha256(canonical).hexdigest()

    report = compare_worlds(world_a, world_b)
    assert report.reproducible is True
    assert report.status == "reproducible"
    assert format_report(report).startswith("reproducible")


def test_one_byte_change_and_classifications(tmp_path: Path) -> None:
    """Requirement 2 & 3: One-byte change, mode diff, and file classification by name."""
    world_a = tmp_path / "a"
    world_b = tmp_path / "b"
    world_a.mkdir()
    world_b.mkdir()

    for w in (world_a, world_b):
        (w / "notes.txt").write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
        (w / "disk.img").write_bytes(b"\x00" * 4096)
        (w / "pack.tar").write_bytes(b"tar-a")
        (w / "bundle.tar.gz").write_bytes(b"tgz-a")
        (w / "meta.json").write_text('{"k": 1}', encoding="utf-8")
        (w / "blob.bin").write_bytes(b"\x10\x20")
        perm = w / "tool.py"
        perm.write_text("print('hi')\n", encoding="utf-8")
        os.chmod(perm, 0o644)

    # Change 1 byte on line 2 of notes.txt in world_b and flip executable bit on tool.py.
    (world_b / "notes.txt").write_text("alpha\nbetX\ngamma\n", encoding="utf-8")
    os.chmod(world_b / "tool.py", 0o755)
    # Also modify tar, tar.gz, and other files by 1 byte to verify their classifications.
    (world_b / "pack.tar").write_bytes(b"tar-b")
    (world_b / "bundle.tar.gz").write_bytes(b"tgz-b")
    (world_b / "blob.bin").write_bytes(b"\x10\x21")

    assert classify_file("disk.img") == "ext4 image"
    assert classify_file("pack.tar") == "tar"
    assert classify_file("bundle.tar.gz") == "tar"
    assert classify_file("meta.json") == "JSON"
    assert classify_file("notes.txt") == "text"
    assert classify_file("blob.bin") == "other"

    report = compare_worlds(world_a, world_b)
    assert report.reproducible is False
    assert report.status == "differs"

    by_path = {d.path: d for d in report.size_hash_diffs}
    assert by_path["notes.txt"].classification == "text"
    assert by_path["notes.txt"].text_loc is not None
    assert by_path["notes.txt"].text_loc.first_diff_line == 2
    assert any("-beta" in line for line in by_path["notes.txt"].text_loc.diff_lines)
    assert any("+betX" in line for line in by_path["notes.txt"].text_loc.diff_lines)

    assert by_path["pack.tar"].classification == "tar"
    assert by_path["bundle.tar.gz"].classification == "tar"
    assert by_path["blob.bin"].classification == "other"

    assert len(report.mode_diffs) == 1
    assert report.mode_diffs[0].path == "tool.py"
    assert report.mode_diffs[0].classification == "text"

    rendered = format_report(report)
    assert "size/hash differences:" in rendered
    assert "mode differences:" in rendered
    assert "first differing line: 2" in rendered


def test_json_timestamp_localised_with_suspected_cause(tmp_path: Path) -> None:
    """Requirement 3 & 4: Localise JSON differing paths (like $.files[3].mtime) and report suspected cause."""
    world_a = tmp_path / "a"
    world_b = tmp_path / "b"
    world_a.mkdir()
    world_b.mkdir()

    doc_a = {
        "files": [
            {"name": "f0"},
            {"name": "f1"},
            {"name": "f2"},
            {"name": "f3", "mtime": 1700000001},
        ],
        "build_timestamp": "2026-01-01T00:00:00Z",
        "host": {"hostname": "builder-1", "user": "alice", "uuid": "1111-aaaa"},
    }
    doc_b = {
        "files": [
            {"name": "f0"},
            {"name": "f1"},
            {"name": "f2"},
            {"name": "f3", "mtime": 1700000999},
        ],
        "build_timestamp": "2026-01-02T00:00:00Z",
        "host": {"hostname": "builder-2", "user": "bob", "uuid": "2222-bbbb"},
    }
    # Also include a JSON without cause keywords to ensure suspected cause is only emitted when matched.
    plain_a = {"items": [{"count": 1}]}
    plain_b = {"items": [{"count": 2}]}

    (world_a / "manifest_meta.json").write_text(json.dumps(doc_a), encoding="utf-8")
    (world_b / "manifest_meta.json").write_text(json.dumps(doc_b), encoding="utf-8")
    (world_a / "plain.json").write_text(json.dumps(plain_a), encoding="utf-8")
    (world_b / "plain.json").write_text(json.dumps(plain_b), encoding="utf-8")

    report = compare_worlds(world_a, world_b)
    by_path = {d.path: d for d in report.size_hash_diffs}

    meta_diff = by_path["manifest_meta.json"]
    assert meta_diff.classification == "JSON"
    assert meta_diff.json_loc is not None
    assert "$.files[3].mtime" in meta_diff.json_loc.differing_paths
    assert "$.build_timestamp" in meta_diff.json_loc.differing_paths
    assert "$.host.hostname" in meta_diff.json_loc.differing_paths
    assert "$.host.user" in meta_diff.json_loc.differing_paths
    assert "$.host.uuid" in meta_diff.json_loc.differing_paths

    cause_keys = {c.key_name for c in meta_diff.json_loc.suspected_causes}
    assert {"mtime", "build_timestamp", "hostname", "user", "uuid"} <= cause_keys

    plain_diff = by_path["plain.json"]
    assert plain_diff.json_loc is not None
    assert plain_diff.json_loc.differing_paths == ["$.items[0].count"]
    assert plain_diff.json_loc.suspected_causes == []

    rendered = format_report(report)
    assert "$.files[3].mtime" in rendered
    assert "suspected cause:" in rendered


def test_image_4kib_block_difference_report(tmp_path: Path) -> None:
    """Requirement 3: ext4 *.img compared in 4 KiB blocks (first, last, count) with no ext4 parsing."""
    world_a = tmp_path / "a"
    world_b = tmp_path / "b"
    world_a.mkdir()
    world_b.mkdir()

    # Create 10 raw 4 KiB blocks (no ext4 superblock magic) with differences in blocks 2 and 7.
    blocks_a = [bytes([i]) * EXT4_BLOCK_SIZE for i in range(10)]
    blocks_b = list(blocks_a)
    blocks_b[2] = b"\xaa" * EXT4_BLOCK_SIZE
    blocks_b[7] = b"\xbb" * EXT4_BLOCK_SIZE

    (world_a / "rootfs.img").write_bytes(b"".join(blocks_a))
    (world_b / "rootfs.img").write_bytes(b"".join(blocks_b))

    report = compare_worlds(world_a, world_b)
    assert len(report.size_hash_diffs) == 1
    img_diff = report.size_hash_diffs[0]
    assert img_diff.classification == "ext4 image"
    assert img_diff.image_loc is not None
    assert img_diff.image_loc.first_diff_block == 2
    assert img_diff.image_loc.last_diff_block == 7
    assert img_diff.image_loc.diff_block_count == 2

    rendered = format_report(report)
    assert "first differing block: 2" in rendered
    assert "last differing block: 7" in rendered
    assert "differing block count: 2" in rendered


def test_only_in_one_side(tmp_path: Path) -> None:
    """Requirement 2: Entries present only in A or only in B are listed separately."""
    world_a = tmp_path / "a"
    world_b = tmp_path / "b"
    world_a.mkdir()
    world_b.mkdir()

    (world_a / "shared.txt").write_text("same\n", encoding="utf-8")
    (world_b / "shared.txt").write_text("same\n", encoding="utf-8")
    (world_a / "left_only.json").write_text("{}", encoding="utf-8")
    (world_b / "right_only.tar.gz").write_bytes(b"gz")
    (world_b / "extra_dir").mkdir()

    report = compare_worlds(world_a, world_b)
    assert report.reproducible is False
    assert [(e.path, e.entry_type, e.classification) for e in report.only_in_a] == [
        ("left_only.json", "file", "JSON")
    ]
    assert [(e.path, e.entry_type, e.classification) for e in report.only_in_b] == [
        ("extra_dir", "dir", None),
        ("right_only.tar.gz", "file", "tar"),
    ]

    rendered = format_report(report)
    assert "only-in-A:\n  - left_only.json (file, JSON)" in rendered
    assert "only-in-B:\n  - extra_dir (dir)\n  - right_only.tar.gz (file, tar)" in rendered


def test_refused_special_objects_and_symlinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement 1 & 5: Refuse symlinks, hard links, FIFOs, sockets, and devices with typed errors."""
    # 1. Symlink inside directory
    w_sym = tmp_path / "w_sym"
    w_sym.mkdir()
    target = w_sym / "real.txt"
    target.write_text("hello", encoding="utf-8")
    os.symlink(target, w_sym / "bad_link.txt")
    with pytest.raises(UnsupportedEntryError) as exc_sym:
        build_manifest(w_sym)
    assert "bad_link.txt" in str(exc_sym.value)
    assert main(["manifest", str(w_sym)]) == 1

    # 2. Hard link inside directory
    w_hard = tmp_path / "w_hard"
    w_hard.mkdir()
    orig = w_hard / "orig.txt"
    orig.write_text("hello", encoding="utf-8")
    os.link(orig, w_hard / "hard_copy.txt")
    with pytest.raises(UnsupportedEntryError) as exc_hard:
        build_manifest(w_hard)
    assert exc_hard.value.entry_kind == "hard link"
    assert exc_hard.value.path in {"hard_copy.txt", "orig.txt"}

    # 3. FIFO (named pipe)
    w_fifo = tmp_path / "w_fifo"
    w_fifo.mkdir()
    os.mkfifo(w_fifo / "pipe.fifo")
    with pytest.raises(UnsupportedEntryError) as exc_fifo:
        build_manifest(w_fifo)
    assert "pipe.fifo" in str(exc_fifo.value)

    # 4. Unix domain socket
    w_sock = tmp_path / "w_sock"
    w_sock.mkdir()
    sock_path = w_sock / "control.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        srv.bind(str(sock_path))
        with pytest.raises(UnsupportedEntryError) as exc_sock:
            build_manifest(w_sock)
        assert "control.sock" in str(exc_sock.value)
    finally:
        srv.close()

    # 5. Character device (simulated via lstat since mknod requires root)
    w_dev = tmp_path / "w_dev"
    w_dev.mkdir()
    dev_file = w_dev / "tty0"
    dev_file.write_bytes(b"")
    real_lstat = os.lstat

    def fake_lstat(path: str | os.PathLike[str]) -> os.stat_result:
        st = real_lstat(path)
        if Path(path) == dev_file:
            return os.stat_result(
                (
                    stat.S_IFCHR | 0o600,
                    st.st_ino,
                    st.st_dev,
                    1,
                    st.st_uid,
                    st.st_gid,
                    0,
                    st.st_atime,
                    st.st_mtime,
                    st.st_ctime,
                )
            )
        return st

    monkeypatch.setattr(os, "lstat", fake_lstat)
    with pytest.raises(UnsupportedEntryError) as exc_dev:
        build_manifest(w_dev)
    assert "tty0" in str(exc_dev.value)


def test_cli_determinism_and_exit_codes(tmp_path: Path) -> None:
    """Requirement 5: CLI manifest and compare are byte-deterministic and enforce exit codes 0, 2, 1."""
    world_a = tmp_path / "world_a"
    world_b = tmp_path / "world_b"
    world_c = tmp_path / "world_c"
    world_a.mkdir()
    world_b.mkdir()
    world_c.mkdir()

    _populate_sample_world(world_a)
    _populate_sample_world(world_b)
    _populate_sample_world(world_c)
    (world_c / "readme.txt").write_text("line 1\nchanged\nline 3\n", encoding="utf-8")

    # Manifest CLI determinism across repeated subprocess invocations
    res_m1 = subprocess.run(
        [sys.executable, "-m", "hermetic_e7", "manifest", str(world_a)],
        capture_output=True,
        text=True,
        check=False,
    )
    res_m2 = subprocess.run(
        [sys.executable, "-m", "hermetic_e7", "manifest", str(world_a)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_m1.returncode == 0
    assert res_m1.stdout == res_m2.stdout
    parsed = json.loads(res_m1.stdout)
    assert "root" in parsed and "entries" in parsed

    # Compare CLI: reproducible -> exit 0, deterministic stdout
    res_eq1 = subprocess.run(
        [sys.executable, "-m", "hermetic_e7", "compare", str(world_a), str(world_b)],
        capture_output=True,
        text=True,
        check=False,
    )
    res_eq2 = subprocess.run(
        [sys.executable, "-m", "hermetic_e7", "compare", str(world_a), str(world_b)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_eq1.returncode == 0
    assert res_eq1.stdout == res_eq2.stdout
    assert "reproducible" in res_eq1.stdout

    # Compare CLI: differs -> exit 2, deterministic stdout
    res_diff1 = subprocess.run(
        [sys.executable, "-m", "hermetic_e7", "compare", str(world_a), str(world_c)],
        capture_output=True,
        text=True,
        check=False,
    )
    res_diff2 = subprocess.run(
        [sys.executable, "-m", "hermetic_e7", "compare", str(world_a), str(world_c)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_diff1.returncode == 2
    assert res_diff1.stdout == res_diff2.stdout
    assert "differs" in res_diff1.stdout

    # Error cases -> exit 1 without unhandled traceback
    res_err = subprocess.run(
        [sys.executable, "-m", "hermetic_e7", "compare", str(world_a), str(tmp_path / "missing")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_err.returncode == 1
    assert "Traceback" not in res_err.stderr


def test_named_caps_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rules: Verify named constant caps bound tree traversal and JSON path reporting."""
    w1 = tmp_path / "w1"
    w2 = tmp_path / "w2"
    w1.mkdir()
    w2.mkdir()
    (w1 / "big.json").write_text('{"a": 1, "b": 2, "c": 3, "d": 4}', encoding="utf-8")
    (w2 / "big.json").write_text('{"a": 9, "b": 9, "c": 9, "d": 9}', encoding="utf-8")

    monkeypatch.setattr(compare_mod, "MAX_REPORTED_JSON_PATHS", 2)
    report = compare_worlds(w1, w2)
    loc = report.size_hash_diffs[0].json_loc
    assert loc is not None
    assert len(loc.differing_paths) == 2
    assert loc.truncated is True

    monkeypatch.setattr(tree_mod, "MAX_TREE_ENTRIES", 0)
    with pytest.raises(CapExceededError):
        build_manifest(w1)

    with pytest.raises(WorldPathError):
        build_manifest(tmp_path / "does_not_exist")




@pytest.mark.parametrize(
    "payload_a,payload_b",
    [
        ("[" * 200_000 + "]" * 200_000, "[" * 200_000 + "1" + "]" * 200_000),
        ('{"n": ' + "1" * 6000 + "}", '{"n": ' + "2" * 6000 + "}"),
    ],
)
def test_hostile_json_is_parse_error_not_exception(
    tmp_path: Path, payload_a: str, payload_b: str
) -> None:
    """Deeply nested or over-long-number JSON localises as a parse error, never raises."""
    world_a = tmp_path / "a"
    world_b = tmp_path / "b"
    world_a.mkdir()
    world_b.mkdir()
    (world_a / "state.json").write_text(payload_a, encoding="utf-8")
    (world_b / "state.json").write_text(payload_b, encoding="utf-8")

    report = compare_worlds(world_a, world_b)
    assert report.reproducible is False
    [diff] = report.size_hash_diffs
    assert diff.json_loc is not None
    assert diff.json_loc.parse_error
    assert "JSON parse error" in format_report(report)


def test_localisation_never_follows_symlinked_parent(tmp_path: Path) -> None:
    """Files read for localisation are opened component by component without following links."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "notes.txt").write_text("host secret\n", encoding="utf-8")
    world = tmp_path / "world"
    world.mkdir()
    os.symlink(outside, world / "linked")
    other = tmp_path / "other"
    other.mkdir()
    (other / "notes.txt").write_text("other\n", encoding="utf-8")

    with pytest.raises(UnsupportedEntryError):
        compare_mod._localize_text(world / "linked" / "notes.txt", other / "notes.txt", "linked/notes.txt")
    with pytest.raises(UnsupportedEntryError):
        tree_mod._hash_regular_file(world / "linked" / "notes.txt", "linked/notes.txt")
