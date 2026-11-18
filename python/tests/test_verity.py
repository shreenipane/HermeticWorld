"""Offline tests for deterministic dm-verity Merkle tree encoder (TR-NET-1)."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from hermetic_safe_io import UnsafePathError
from hermetic_slice import guest_kernel, verity

T_CLOCK = datetime.fromtimestamp(1700000000, timezone.utc)


def test_derive_verity_salt():
    salt1 = verity.derive_verity_salt("world-alpha")
    salt2 = verity.derive_verity_salt("world-beta")
    assert len(salt1) == 64 and len(salt2) == 64
    assert salt1 != salt2
    assert salt1 == verity.derive_verity_salt("world-alpha")

    for bad in ["", "x" * 257, "\0", "control\nchar"]:
        with pytest.raises(verity.VerityError):
            verity.derive_verity_salt(bad)


def test_validate_salt():
    valid_hex = "a" * 64
    b = verity.validate_salt(valid_hex)
    assert b == bytes.fromhex(valid_hex)
    assert verity.validate_salt(valid_hex.upper()) == b
    assert verity.validate_salt(b) == b

    for bad in ["a" * 63, "a" * 65, "g" * 64, b"\x00" * 31, b"\x00" * 33, 123]:
        with pytest.raises(verity.VerityError):
            verity.validate_salt(bad)


def test_calculate_tree_layout():
    assert verity.calculate_tree_layout(1) == ([], 0)
    assert verity.calculate_tree_layout(128) == ([1], 1)
    assert verity.calculate_tree_layout(129) == ([2, 1], 3)
    assert verity.calculate_tree_layout(16384) == ([128, 1], 129)
    assert verity.calculate_tree_layout(16385) == ([129, 2, 1], 132)

    for bad in [0, -1, verity.MAX_DATA_BLOCKS + 1, "128"]:
        with pytest.raises(verity.VerityError):
            verity.calculate_tree_layout(bad)


def test_known_answer_verity_tree(tmp_path: Path):
    salt_hex = "00" * 32
    salt_bytes = bytes.fromhex(salt_hex)

    # 1 data block of 'A' * 4096
    data_file = tmp_path / "single_block.img"
    data_content = b"A" * 4096
    data_file.write_bytes(data_content)

    # For 1 data block, Linux dm-verity uses zero hash levels.
    # The root digest is SHA-256 of salt followed by the data block.
    expected_root_hash = hashlib.sha256(salt_bytes + data_content).hexdigest()

    hash_file = tmp_path / "single_block_hash.img"
    info = verity.build_verity_image(
        data_file, hash_file, salt=salt_hex, t_clock=T_CLOCK
    )
    assert info["root_hash"] == expected_root_hash
    assert info["data_blocks"] == 1
    assert info["hash_blocks"] == 0
    assert hash_file.stat().st_size == 0
    assert hash_file.read_bytes() == b""

    # Verify round-trip with verify_verity_tree
    data_fd = os.open(data_file, os.O_RDONLY)
    hash_fd = os.open(hash_file, os.O_RDONLY)
    try:
        assert verity.verify_verity_tree(
            data_fd,
            hash_fd,
            salt=salt_hex,
            expected_root_hash=expected_root_hash,
            num_data_blocks=1,
        )
    finally:
        os.close(data_fd)
        os.close(hash_fd)


def test_known_answer_multi_level_tree(tmp_path: Path):
    salt_hex = "0123456789abcdef" * 4
    salt_bytes = bytes.fromhex(salt_hex)

    # 129 data blocks
    data_file = tmp_path / "multi_block.img"
    blocks = [bytes([i % 256]) * 4096 for i in range(129)]
    data_file.write_bytes(b"".join(blocks))

    # Compute expected:
    digests_l0 = [hashlib.sha256(salt_bytes + b).digest() for b in blocks]
    block_0_l0 = b"".join(digests_l0[:128])
    block_1_l0 = digests_l0[128] + b"\x00" * (4096 - 32)

    digest_b0 = hashlib.sha256(salt_bytes + block_0_l0).digest()
    digest_b1 = hashlib.sha256(salt_bytes + block_1_l0).digest()
    root_block = digest_b0 + digest_b1 + b"\x00" * (4096 - 64)
    expected_root_hash = hashlib.sha256(salt_bytes + root_block).hexdigest()

    expected_hash_image = root_block + block_0_l0 + block_1_l0

    hash_file = tmp_path / "multi_block_hash.img"
    info = verity.build_verity_image(
        data_file, hash_file, salt=salt_hex, t_clock=T_CLOCK
    )
    assert info["root_hash"] == expected_root_hash
    assert info["data_blocks"] == 129
    assert info["hash_blocks"] == 3
    assert hash_file.read_bytes() == expected_hash_image


def test_encode_and_verify_tamper_detection(tmp_path: Path):
    data_file = tmp_path / "data.img"
    hash_file = tmp_path / "hash.img"
    # 256 blocks = 1 MiB
    data_bytes = bytearray(b"".join(bytes([i % 251]) * 4096 for i in range(256)))
    data_file.write_bytes(data_bytes)

    info = verity.build_verity_image(
        data_file, hash_file, world_id="test-world-42", t_clock=T_CLOCK
    )

    data_fd = os.open(data_file, os.O_RDONLY)
    hash_fd = os.open(hash_file, os.O_RDONLY)
    try:
        assert verity.verify_verity_tree(
            data_fd,
            hash_fd,
            salt=info["salt"],
            expected_root_hash=info["root_hash"],
            num_data_blocks=256,
        )
    finally:
        os.close(data_fd)
        os.close(hash_fd)

    # 1. Tamper 1 byte in block 0 of data
    tampered_data = bytearray(data_bytes)
    tampered_data[10] ^= 0x55
    data_file.write_bytes(tampered_data)
    data_fd = os.open(data_file, os.O_RDONLY)
    hash_fd = os.open(hash_file, os.O_RDONLY)
    try:
        assert not verity.verify_verity_tree(
            data_fd,
            hash_fd,
            salt=info["salt"],
            expected_root_hash=info["root_hash"],
            num_data_blocks=256,
        )
    finally:
        os.close(data_fd)
        os.close(hash_fd)

    # Restore data
    data_file.write_bytes(data_bytes)

    # 2. Tamper 1 byte in hash file (root block)
    hash_bytes = bytearray(hash_file.read_bytes())
    tampered_hash = bytearray(hash_bytes)
    tampered_hash[5] ^= 0xAA
    hash_file.chmod(0o600)
    hash_file.write_bytes(tampered_hash)
    data_fd = os.open(data_file, os.O_RDONLY)
    hash_fd = os.open(hash_file, os.O_RDONLY)
    try:
        assert not verity.verify_verity_tree(
            data_fd,
            hash_fd,
            salt=info["salt"],
            expected_root_hash=info["root_hash"],
            num_data_blocks=256,
        )
    finally:
        os.close(data_fd)
        os.close(hash_fd)

    # 3. Tamper 1 byte in hash file (leaf hash block)
    tampered_hash = bytearray(hash_bytes)
    tampered_hash[4096 + 10] ^= 0xAA
    hash_file.write_bytes(tampered_hash)
    data_fd = os.open(data_file, os.O_RDONLY)
    hash_fd = os.open(hash_file, os.O_RDONLY)
    try:
        assert not verity.verify_verity_tree(
            data_fd,
            hash_fd,
            salt=info["salt"],
            expected_root_hash=info["root_hash"],
            num_data_blocks=256,
        )
    finally:
        os.close(data_fd)
        os.close(hash_fd)

    # 4. Truncated hash file
    hash_file.write_bytes(hash_bytes[: 4096])
    data_fd = os.open(data_file, os.O_RDONLY)
    hash_fd = os.open(hash_file, os.O_RDONLY)
    try:
        assert not verity.verify_verity_tree(
            data_fd,
            hash_fd,
            salt=info["salt"],
            expected_root_hash=info["root_hash"],
            num_data_blocks=256,
        )
    finally:
        os.close(data_fd)
        os.close(hash_fd)


def test_build_verity_image_reproducibility(tmp_path: Path):
    data_file = tmp_path / "data.img"
    data_file.write_bytes(b"\xaa" * (8 * 4096))

    h1 = tmp_path / "hash1.img"
    h2 = tmp_path / "hash2.img"

    r1 = verity.build_verity_image(data_file, h1, world_id="repro-world", t_clock=T_CLOCK)
    r2 = verity.build_verity_image(data_file, h2, world_id="repro-world", t_clock=T_CLOCK)

    assert r1["root_hash"] == r2["root_hash"]
    assert r1["hash_sha256"] == r2["hash_sha256"]
    assert h1.read_bytes() == h2.read_bytes()
    assert oct(h1.stat().st_mode & 0o777) == "0o400"
    assert h1.stat().st_mtime == 1700000000


def test_hostile_inputs_refused(tmp_path: Path):
    data_file = tmp_path / "data.img"
    hash_file = tmp_path / "hash.img"

    # Non-multiple of 4096
    data_file.write_bytes(b"A" * 4095)
    with pytest.raises(verity.VerityError):
        verity.build_verity_image(data_file, hash_file, world_id="w")

    # Zero bytes
    data_file.write_bytes(b"")
    with pytest.raises(verity.VerityError):
        verity.build_verity_image(data_file, hash_file, world_id="w")

    # Symlinked data image
    data_file.write_bytes(b"A" * 4096)
    symlink_data = tmp_path / "symlink_data.img"
    os.symlink(data_file, symlink_data)
    with pytest.raises(UnsafePathError):
        verity.build_verity_image(symlink_data, hash_file, world_id="w")

    # Neither salt nor world_id
    with pytest.raises(verity.VerityError):
        verity.build_verity_image(data_file, hash_file)


def test_format_and_parse_dm_create():
    root_hash = "a" * 64
    salt = "b" * 64
    cmd = verity.format_dm_create("netvm", 2048, root_hash, salt)
    assert (
        cmd
        == f'dm-mod.create="netvm,,,ro,0 16384 verity 1 /dev/vda /dev/vdb 4096 4096 2048 0 sha256 {root_hash} {salt} 1 restart_on_corruption"'
    )

    parsed = verity.parse_dm_create(cmd)
    assert parsed["name"] == "netvm"
    assert parsed["flags"] == "ro"
    assert parsed["data_blocks"] == 2048
    assert parsed["num_sectors"] == 16384
    assert parsed["root_hash"] == root_hash
    assert parsed["salt"] == salt
    assert parsed["error_behavior"] == "restart_on_corruption"

    # Panic on corruption
    cmd_panic = verity.format_dm_create(
        "netvm", 2048, root_hash, salt, error_behavior="panic_on_corruption"
    )
    assert "panic_on_corruption" in cmd_panic
    parsed_panic = verity.parse_dm_create(cmd_panic)
    assert parsed_panic["error_behavior"] == "panic_on_corruption"

    # Hostile tables
    for bad in [
        cmd.replace("ro", "rw"),
        cmd.replace("0 16384", "1 16384"),
        cmd.replace("16384", "16383"),
        cmd.replace("/dev/vda", "/dev/vda1"),
        cmd.replace("/dev/vdb", "/dev/vdc"),
        cmd.replace("4096 4096", "512 512"),
        cmd.replace("sha256", "sha1"),
        cmd.replace("restart_on_corruption", "ignore_corruption"),
        cmd.replace('"', ""),
        'dm-mod.create="invalid"',
    ]:
        with pytest.raises(verity.VerityError):
            verity.parse_dm_create(bad)


def test_guest_kernel_role_separation_and_netvm_boot():
    root_hash = "c" * 64
    salt = "d" * 64
    dm_create = verity.format_dm_create("netvm", 2048, root_hash, salt)

    netvm_args = guest_kernel.spec_netvm_boot_arguments(1700000000, dm_create)
    assert guest_kernel.check_boot_arguments(netvm_args, role="netvm") == []

    # Agent role must refuse NetVM boot arguments (dm-mod.create and dm-0)
    agent_findings = guest_kernel.check_boot_arguments(netvm_args, role="agent")
    assert any(
        "dm-mod.create and root=/dev/dm-0 are only permitted for NetVM" in f.message
        for f in agent_findings
    )

    # NetVM role must refuse unverified root (/dev/vda)
    bad_netvm = netvm_args.replace("root=/dev/dm-0", "root=/dev/vda")
    netvm_findings = guest_kernel.check_boot_arguments(bad_netvm, role="netvm")
    assert any("required boot argument missing" in f.message for f in netvm_findings)

    # NetVM role must refuse missing dm-mod.create
    no_dm = " ".join(t for t in guest_kernel.split_boot_tokens(netvm_args) if not t.startswith("dm-mod.create"))
    findings_no_dm = guest_kernel.check_boot_arguments(no_dm, role="netvm")
    assert any("dm-mod.create" in f.option for f in findings_no_dm)

    # NetVM role must refuse tampered dm-mod.create
    tampered_dm = netvm_args.replace("ro", "rw")
    findings_tampered = guest_kernel.check_boot_arguments(tampered_dm, role="netvm")
    assert any("dm-mod.create" in f.option for f in findings_tampered)


def test_parse_verity_table_optionless_reports_eio():
    root_hash = "a" * 64
    salt = "b" * 64
    # 13-token table without optional parameter must report eio
    table = f"0 16384 verity 1 /dev/vda /dev/vdb 4096 4096 2048 0 sha256 {root_hash} {salt}"
    parsed = verity.parse_verity_table(table)
    assert parsed["error_behavior"] == "eio"


def test_parse_verity_table_rejects_noncanonical_decimal():
    root_hash = "a" * 64
    salt = "b" * 64
    # Underscores in sector count
    table_underscores = f"0 16_384 verity 1 /dev/vda /dev/vdb 4096 4096 2048 0 sha256 {root_hash} {salt}"
    with pytest.raises(verity.VerityError, match="canonical"):
        verity.parse_verity_table(table_underscores)

    # Underscores in data_blocks
    table_blocks_underscores = f"0 16384 verity 1 /dev/vda /dev/vdb 4096 4096 2_048 0 sha256 {root_hash} {salt}"
    with pytest.raises(verity.VerityError, match="canonical"):
        verity.parse_verity_table(table_blocks_underscores)

    # Leading zeros in sector count
    table_leading_zeros = f"0 016384 verity 1 /dev/vda /dev/vdb 4096 4096 2048 0 sha256 {root_hash} {salt}"
    with pytest.raises(verity.VerityError, match="canonical"):
        verity.parse_verity_table(table_leading_zeros)

    # Signs in sector count
    table_plus_sign = f"0 +16384 verity 1 /dev/vda /dev/vdb 4096 4096 2048 0 sha256 {root_hash} {salt}"
    with pytest.raises(verity.VerityError, match="canonical"):
        verity.parse_verity_table(table_plus_sign)
