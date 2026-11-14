"""Offline regressions for production substrate metadata and the full clock smoke."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tarfile

import pytest

from hermetic_slice import guest_kernel as kernel, netvm, rootfs, substrate
from test_rootfs import _mock_toolchain

T = datetime.fromtimestamp(1700000000, timezone.utc)


def _lock(tmp_path, release="2024-02-29T00:00:00Z"):
    lock = json.loads((kernel.DEFAULT_KERNEL_DIR / "kernel.lock.json").read_bytes())
    lock["release_date"] = release
    path = tmp_path / "kernel.lock.json"
    path.write_text(json.dumps(lock))
    return path


def _extractor(tmp_path, body="sys.stdout.buffer.write(b'2023-03-01\\n2024-02-29\\n')"):
    image = tmp_path / "vmlinux"
    image.write_bytes(b"pinned image")
    binary = tmp_path / "clockprobe"
    binary.write_text("#!/usr/bin/python3\nimport sys\n"
                      "assert sys.argv[1:] == ['--extract-substrate-dates']\n"
                      "assert sys.stdin.buffer.read() == b'pinned image'\n" + body + "\n")
    binary.chmod(0o700)
    return dict(kernel_image=image, clockprobe_bin=binary)


@pytest.mark.parametrize("parents", [False, True])
def test_production_rootfs_installs_kernel_metadata_without_mutating_source(tmp_path, monkeypatch, parents):
    src = tmp_path / "src"
    src.mkdir()
    if parents:
        (src / "etc/hermetic").mkdir(parents=True)
        # A source link is replaced only in the archive; its host target stays untouched.
        secret = tmp_path / "secret"
        secret.write_bytes(b"host secret")
        (src / substrate.BOUND_PATH).symlink_to(secret)
        (src / substrate.DATES_PATH).write_bytes(b"2099-01-01\n")
    lock = _lock(tmp_path)
    metadata = _extractor(tmp_path)
    _mock_toolchain(monkeypatch)
    original = rootfs.write_rootfs_tar
    archives = []

    def capture(*args, **kwargs):
        result = original(*args, **kwargs)
        archive = Path(f"/proc/self/fd/{kwargs['dir_fd']}") / args[1]
        archives.append(archive.read_bytes())
        with tarfile.open(archive) as tf:
            for path, data in [(substrate.BOUND_PATH, b"2024-02-29\n"),
                               (substrate.DATES_PATH, b"2023-03-01\n2024-02-29\n")]:
                assert tf.getnames().count(path) == 1
                info = tf.getmember(path)
                assert (info.uid, info.gid, info.mode, info.mtime) == (0, 0, 0o644, int(T.timestamp()))
                assert tf.extractfile(info).read() == data
        return result

    monkeypatch.setattr(rootfs, "write_rootfs_tar", capture)
    for name in ("a.img", "b.img"):
        rootfs.build_rootfs(src, tmp_path / name, t_clock=T, world_id="world", work_dir=tmp_path,
                           kernel_lock=lock, **metadata)
    assert archives[0] == archives[1]
    if parents:
        assert (src / substrate.BOUND_PATH).is_symlink()
        assert secret.read_bytes() == b"host secret"
        assert (src / substrate.DATES_PATH).read_bytes() == b"2099-01-01\n"
    else:
        assert list(src.iterdir()) == []


def test_rootfs_defaults_to_the_pinned_release_date(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    _mock_toolchain(monkeypatch)
    original = rootfs.write_rootfs_tar
    seen = []
    def capture(*args, **kwargs):
        seen.append(kwargs["substrate_files"])
        return original(*args, **kwargs)
    monkeypatch.setattr(rootfs, "write_rootfs_tar", capture)
    rootfs.build_rootfs(src, tmp_path / "out.img", t_clock=T, world_id="world", work_dir=tmp_path)
    assert seen == [{substrate.BOUND_PATH: b"2026-10-21\n"}]


def test_rootfs_does_not_trust_source_substrate_dates_without_matching_image(tmp_path, monkeypatch):
    src = tmp_path / "src"
    (src / "etc/hermetic").mkdir(parents=True)
    (src / substrate.DATES_PATH).write_bytes(b"2099-01-01\n")
    _mock_toolchain(monkeypatch)
    original = rootfs.write_rootfs_tar
    def capture(*args, **kwargs):
        result = original(*args, **kwargs)
        with tarfile.open(Path(f"/proc/self/fd/{kwargs['dir_fd']}") / args[1]) as tf:
            assert substrate.BOUND_PATH in tf.getnames()
            assert substrate.DATES_PATH not in tf.getnames()
        return result
    monkeypatch.setattr(rootfs, "write_rootfs_tar", capture)
    rootfs.build_rootfs(src, tmp_path / "out.img", t_clock=T, world_id="world", work_dir=tmp_path)
    assert (src / substrate.DATES_PATH).read_bytes() == b"2099-01-01\n"


@pytest.mark.parametrize("parent", ["etc", "etc/hermetic"])
def test_rootfs_refuses_symlinked_substrate_parents(tmp_path, monkeypatch, parent):
    src = tmp_path / "src"
    (src / parent).parent.mkdir(parents=True)
    (src / parent).symlink_to(tmp_path, target_is_directory=True)
    _mock_toolchain(monkeypatch)
    with pytest.raises(ValueError, match="real directory"):
        rootfs.build_rootfs(src, tmp_path / "out.img", t_clock=T, world_id="world", work_dir=tmp_path)
    assert not (tmp_path / "out.img").exists()


@pytest.mark.parametrize("limit", [dict(max_bytes=10), dict(max_logical_bytes=10),
                                  dict(max_entries=2), dict(max_depth=1)])
def test_generated_substrate_counts_toward_resource_caps(tmp_path, limit):
    src = tmp_path / "src"
    src.mkdir()
    with pytest.raises(rootfs.RootfsLimitError):
        rootfs.write_rootfs_tar(src, tmp_path / "tree.tar", mtime_ceiling=int(T.timestamp()),
                               limits=rootfs.RootfsLimits(**limit),
                               substrate_files={substrate.BOUND_PATH: b"2024-02-29\n"})


@pytest.mark.parametrize("release", ["2024-02-30T00:00:00Z", "host-secret", "2024-01-01"])
def test_bad_kernel_lock_fails_before_outputs(tmp_path, release):
    lock = _lock(tmp_path, release)
    with pytest.raises(ValueError, match="invalid substrate kernel lock") as error:
        rootfs.build_rootfs(tmp_path / "missing", tmp_path / "out/image", t_clock=T,
                           world_id="world", kernel_lock=lock)
    assert "host-secret" not in str(error.value)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "oversized"])
def test_substrate_lock_refuses_links_special_files_and_byte_overflow(tmp_path, kind):
    lock = _lock(tmp_path)
    if kind == "symlink":
        path = tmp_path / "link"
        path.symlink_to(lock)
    elif kind == "fifo":
        path = tmp_path / "fifo"
        os.mkfifo(path)
    else:
        path = lock
        lock.write_bytes(b"x" * (kernel.MAX_LOCK_BYTES + 1))
    with pytest.raises(OSError):
        substrate.substrate_files(path)


@pytest.mark.parametrize("body", ["sys.exit(2)", "sys.stdout.write('2024-02-30\\n')",
    "sys.stdout.write('2024-02-29\\n2024-02-29\\n')", "sys.stdout.write('x' * 45057)",
    "sys.stdout.write('2024-02-29')"])
def test_substrate_extractor_failure_or_malformed_output_is_rejected(tmp_path, body):
    with pytest.raises(ValueError):
        substrate.substrate_files(_lock(tmp_path), **_extractor(tmp_path, body))


def test_substrate_extractor_timeout_and_input_pair_are_bounded(tmp_path, monkeypatch):
    inputs = _extractor(tmp_path, "import time; time.sleep(60)")
    monkeypatch.setattr(substrate, "EXTRACT_TIMEOUT_S", 0.1)
    with pytest.raises(ValueError, match="timed out"):
        substrate.substrate_files(_lock(tmp_path), **inputs)
    with pytest.raises(ValueError, match="supplied together"):
        substrate.substrate_files(tmp_path / "absent", kernel_image=inputs["kernel_image"])


def test_netvm_world_tree_installs_same_kernel_metadata(tmp_path):
    for name in ("netvm", "busybox"):
        (tmp_path / name).write_bytes(b"binary")
    (tmp_path / "dns.json").write_bytes(b'{"records":[]}')
    tree = netvm.build_netvm_tree(tmp_path / "tree", netvm_bin=tmp_path / "netvm",
        busybox_bin=tmp_path / "busybox", dns_table=tmp_path / "dns.json", t_clock=T,
        kernel_lock=_lock(tmp_path), **_extractor(tmp_path))
    assert (tree / substrate.BOUND_PATH).read_bytes() == b"2024-02-29\n"
    assert (tree / substrate.DATES_PATH).read_bytes() == b"2023-03-01\n2024-02-29\n"
    for path in (substrate.BOUND_PATH, substrate.DATES_PATH):
        assert (tree / path).stat().st_mode & 0o777 == 0o644
        assert (tree / path).stat().st_mtime == int(T.timestamp())


def test_legacy_ptys_are_disabled_and_unix98_ptys_are_retained():
    assert kernel.RULES["CONFIG_LEGACY_PTYS"].value == "n"
    values = {name: rule.value for name, rule in kernel.RULES.items()}
    for value in ("y", "m"):
        values["CONFIG_LEGACY_PTYS"] = value
        text = "# Linux/x86 6.6.160 Kernel Configuration\n" + "\n".join(f"{k}={v}" for k, v in values.items())
        assert [f.option for f in kernel.check_config(text)] == ["CONFIG_LEGACY_PTYS"]
    fragment = kernel.parse_config((kernel.DEFAULT_KERNEL_DIR / "hermetic.config").read_bytes())
    assert fragment["CONFIG_LEGACY_PTYS"] == "n"
    assert kernel.RULES["CONFIG_UNIX98_PTYS"].value == "y"


def test_phase_checklist_counts_match_deliverables():
    import re
    text = (Path(__file__).resolve().parents[2] / "PHASES.md").read_text()
    for name, body in re.findall(r"## Phase ([^\n]+)\n(.*?)(?=\n## Phase |\Z)", text, re.S):
        done = len(re.findall(r"^\s*- \[x\]", body, re.M))
        total = len(re.findall(r"^\s*- \[[ x]\]", body, re.M))
        assert f"| {name} | done {done} of {total} |" in text
