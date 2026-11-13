from pathlib import Path
import os
import subprocess
import sys

import pytest

from hermetic_pytest_env import ScanError, scan
import importlib
scanner = importlib.import_module("hermetic_pytest_env.scan")


def dist(site, name="pytest", version="3.7.4", ep=None, dirname=None):
    d = site / (dirname or f"{name}-{version}.dist-info")
    d.mkdir(parents=True)
    (d / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n")
    if ep is not None:
        (d / "entry_points.txt").write_text(ep)
    return d


def test_review_ancestor_symlink_refused(tmp_path):
    site = tmp_path / "real" / "site"
    site.mkdir(parents=True)
    dist(site)
    (tmp_path / "link").symlink_to(site.parent, target_is_directory=True)
    with pytest.raises(ScanError):
        scan([str(tmp_path / "link" / "site")])


def test_review_directory_replacement_is_not_followed(tmp_path, monkeypatch):
    site = tmp_path / "site"
    site.mkdir()
    victim = dist(site, "safe", "1")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "METADATA").write_text("Name: pytest\nVersion: 99\n")
    (outside / "entry_points.txt").write_text("[pytest11]\nleaked = outside.secret\n")
    original_open = os.open
    swapped = False
    def replace_then_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and (str(path).endswith("METADATA") or str(path).endswith(victim.name)):
            swapped = True
            victim.rename(site / "moved")
            victim.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", replace_then_open)
    inv = scan([str(site)])
    assert swapped
    assert inv.pytest_version is None
    assert not inv.plugins


def test_review_fifo_metadata_never_blocks(tmp_path):
    site = tmp_path / "site"
    d = dist(site)
    (d / "METADATA").unlink()
    os.mkfifo(d / "METADATA")
    proc = subprocess.run([sys.executable, "-m", "hermetic_pytest_env", str(site)],
                          capture_output=True, text=True, timeout=3)
    assert 'not_regular_file' in proc.stdout


def test_review_all_inputs_validated_before_io(tmp_path, monkeypatch):
    calls = []
    original = os.lstat
    def recording(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)
    monkeypatch.setattr(os, "lstat", recording)
    with pytest.raises(ScanError):
        scan([str(tmp_path), "bad\x00path"])
    assert calls == []


def test_review_error_does_not_echo_metadata(tmp_path):
    site = tmp_path / "site"
    d = dist(site)
    (d / "METADATA").write_bytes(b"Name: canary-secret\xff\nVersion: 1\n")
    inv = scan([str(site)])
    assert "canary-secret" not in inv.to_json()
    assert inv.refused[0]["reason"] == "metadata_decode_error"


def test_review_conflicting_pytest_is_never_guessed(tmp_path):
    for same_dir in [True, False]:
        base = tmp_path / str(same_dir)
        site = base / "site"
        dist(site, version="3.7.4")
        other = site if same_dir else base / "other"
        dist(other, version="9.0")
        inv = scan([str(site)] if same_dir else [str(site), str(other)])
        assert inv.pytest_version is None
        assert inv.pytest_older_than_3_8 is None
        assert inv.conflicts


def test_review_pep440_post_dev_ordering_and_local():
    parse = scanner.parse_pep440
    versions = ["1.0a1.dev1", "1.0a1", "1.0a1.post1.dev1", "1.0a1.post1", "1.0", "1.0+abc", "1.0+1"]
    keys = [parse(v).sort_key() for v in versions]
    assert all(a < b for a, b in zip(keys, keys[1:]))


@pytest.mark.parametrize("ep", ["[DEFAULT]\nsecret = host.module\n[pytest11]\n", "[pytest11]\nx = invalid module\n", "[pytest11]\nx = mod [unterminated\n"])
def test_review_entry_points_refuse_ambiguity(tmp_path, ep):
    site = tmp_path / "site"
    dist(site, ep=ep)
    inv = scan([str(site)])
    assert not inv.plugins
    assert inv.refused


def test_review_aggregate_caps(tmp_path, monkeypatch):
    site = tmp_path / "site"
    dist(site, "first", "1")
    dist(site, "second", "1")
    monkeypatch.setattr(scanner, "MAX_DISTRIBUTIONS", 1, raising=False)
    with pytest.raises(ScanError):
        scan([str(site)])


def test_review_host_os_errors_are_fixed_codes(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError(13, "host-locale-canary")
    monkeypatch.setattr(os, "lstat", fail)
    with pytest.raises(ScanError) as exc:
        scan([str(tmp_path)])
    assert "host-locale-canary" not in str(exc.value)


def test_review_path_cap_before_io(monkeypatch):
    monkeypatch.setattr(scanner, "MAX_PATH_BYTES", 4, raising=False)
    with pytest.raises(ScanError, match="too long"):
        scan(["long-path"])


def test_review_total_bytes_and_plugin_caps(tmp_path, monkeypatch):
    site = tmp_path / "site"
    dist(site, ep="[pytest11]\none = one.plugin\ntwo = two.plugin\n")
    monkeypatch.setattr(scanner, "MAX_TOTAL_READ_BYTES", 8, raising=False)
    with pytest.raises(ScanError, match="byte limit"):
        scan([str(site)])
    monkeypatch.setattr(scanner, "MAX_TOTAL_READ_BYTES", 10000)
    monkeypatch.setattr(scanner, "MAX_TOTAL_PLUGINS", 1, raising=False)
    with pytest.raises(ScanError, match="plugin limit"):
        scan([str(site)])


def test_review_version_requires_ascii():
    assert scanner.parse_pep440("1.0+İ") is None


def test_review_metadata_symlink_and_device_are_not_opened(tmp_path, monkeypatch):
    site = tmp_path / "site"
    d = dist(site)
    (d / "METADATA").unlink()
    (d / "METADATA").symlink_to("/dev/zero")
    original = os.open
    opened = []
    def record(path, flags, *args, **kwargs):
        opened.append(str(path))
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", record)
    assert scan([str(site)]).refused
    assert "METADATA" not in opened


@pytest.mark.parametrize("replacement", ["symlink", "fifo"])
def test_review_replaced_metadata_is_pinned_before_read_open(tmp_path, monkeypatch, replacement):
    site = tmp_path / "site"
    d = dist(site)
    original = os.open
    read_opens = []
    def swap(path, flags, *args, **kwargs):
        if str(path) == "METADATA":
            (d / "METADATA").unlink()
            if replacement == "symlink":
                (d / "METADATA").symlink_to("/dev/zero")
            else:
                os.mkfifo(d / "METADATA")
            if not flags & getattr(os, "O_PATH", 0):
                read_opens.append(path)
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", swap)
    inv = scan([str(site)])
    assert inv.refused
    assert not read_opens


def test_review_metadata_mutation_during_read_refused(tmp_path, monkeypatch):
    site = tmp_path / "site"
    d = dist(site)
    original = os.read
    changed = False
    def mutate(fd, count):
        nonlocal changed
        data = original(fd, count)
        if data and not changed:
            changed = True
            (d / "METADATA").write_text("Name: pytest\nVersion: 99.99\n")
        return data
    monkeypatch.setattr(os, "read", mutate)
    inv = scan([str(site)])
    assert changed
    assert inv.refused
    assert inv.pytest_version is None


@pytest.mark.parametrize("ep", ["[pytest11]\nx: mod.plugin\n", "[pytest11]trailing\nx = mod.plugin\n"])
def test_review_entry_point_delimiters_and_sections_are_exact(tmp_path, ep):
    site = tmp_path / "site"
    dist(site, ep=ep)
    inv = scan([str(site)])
    assert inv.refused
    assert not inv.plugins


@pytest.mark.parametrize("separator", ["\r", "\x85", "\u2028"])
def test_review_metadata_header_line_boundaries_are_exact(tmp_path, separator):
    site = tmp_path / "site"
    d = dist(site)
    (d / "METADATA").write_text(f"Name: pytest{separator}Version: 9\n")
    inv = scan([str(site)])
    assert inv.refused
    assert inv.pytest_version is None


def test_review_entry_point_open_disappearance_is_refused(tmp_path, monkeypatch):
    site = tmp_path / "site"
    dist(site, ep="[pytest11]\nx = x.plugin\n")
    original = os.open
    def missing(path, flags, *args, **kwargs):
        if str(path) == "entry_points.txt":
            raise FileNotFoundError("read-open-canary")
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", missing)
    inv = scan([str(site)])
    assert inv.refused
    assert "read-open-canary" not in inv.to_json()


@pytest.mark.parametrize("name", ["../bad", "bad/name", "bad name", "-bad"])
def test_review_invalid_distribution_names_are_refused(tmp_path, name):
    site = tmp_path / "site"
    dist(site, name=name, dirname="bad.dist-info", ep="[pytest11]\nx = mod.plugin\n")
    inv = scan([str(site)])
    assert inv.refused
    assert not inv.plugins


def test_review_unavailable_safe_open_flags_fail_closed(monkeypatch):
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(ScanError, match="safe filesystem operations unavailable"):
        scan([])


def test_review_read_budget_accumulates_across_files(tmp_path, monkeypatch):
    site = tmp_path / "site"
    dist(site, "first", "1")
    dist(site, "second", "1")
    monkeypatch.setattr(scanner, "MAX_TOTAL_READ_BYTES", 40)
    with pytest.raises(ScanError, match="byte limit"):
        scan([str(site)])


def test_review_plugin_budget_accumulates_across_distributions(tmp_path, monkeypatch):
    site = tmp_path / "site"
    for name in ["first", "second"]:
        dist(site, name, "1", ep=f"[pytest11]\n{name} = {name}.plugin\n")
    monkeypatch.setattr(scanner, "MAX_TOTAL_PLUGINS", 1)
    with pytest.raises(ScanError, match="plugin limit"):
        scan([str(site)])


@pytest.mark.parametrize("header", ["Name : pytest", "Name\t: pytest"])
def test_review_metadata_header_names_are_exact(tmp_path, header):
    site = tmp_path / "site"
    d = dist(site)
    (d / "METADATA").write_text(f"{header}\nVersion: 9\n")
    inv = scan([str(site)])
    assert inv.refused
    assert inv.pytest_version is None
