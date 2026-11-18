"""Deterministic dm-verity Merkle tree encoder and parser for NetVM (TR-NET-1).

Constructs dm-verity v1 Merkle trees with SHA-256 and fixed 4096-byte blocks,
in strict accordance with Linux device-mapper verity specification.
Layout on the hash device starts at block 0 with the topmost root level, followed
sequentially down to level 0 (the hashes of data blocks), matching the kernel's
hash_level_block layout.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import stat
from datetime import datetime
from pathlib import Path

from hermetic_safe_io import open_parent, open_regular, UnsafePathError

BLOCK_SIZE: int = 4096
DIGEST_SIZE: int = 32  # SHA-256 output size in bytes
DIGESTS_PER_BLOCK: int = BLOCK_SIZE // DIGEST_SIZE  # 128 digests per 4096-byte block
MAX_DATA_BLOCKS: int = 4_194_304  # 16 GiB cap (16 * 1024^3 / 4096)
MAX_LEVELS: int = 8
SALT_HEX_LEN: int = 64
MAX_TEMP_ATTEMPTS: int = 64
IO_CHUNK_BLOCKS: int = 16
IO_CHUNK_BYTES: int = IO_CHUNK_BLOCKS * BLOCK_SIZE


class VerityError(Exception):
    """Raised when verity parameters, images or metadata fail validation."""


def derive_verity_salt(world_id: str) -> str:
    """Derive a fixed, deterministic 64-hex salt from a world identifier."""
    if not isinstance(world_id, str) or not world_id:
        raise VerityError("world_id must be a non-empty string")
    if len(world_id) > 256 or any(ord(c) < 32 or ord(c) > 126 for c in world_id):
        raise VerityError("world_id must contain bounded printable ASCII characters")
    return hashlib.sha256(f"hermetic.dm-verity.salt:{world_id}".encode("utf-8")).hexdigest()


def validate_salt(salt: str | bytes) -> bytes:
    """Validate and normalize a 32-byte (64 hex character) salt."""
    if isinstance(salt, str):
        if len(salt) != SALT_HEX_LEN or not re.fullmatch(r"[0-9a-fA-F]{64}", salt):
            raise VerityError("salt must be a 64-character hexadecimal string")
        return bytes.fromhex(salt.lower())
    if isinstance(salt, (bytes, bytearray)):
        if len(salt) != DIGEST_SIZE:
            raise VerityError("salt bytes must be exactly 32 bytes")
        return bytes(salt)
    raise VerityError("salt must be a string or bytes")


def calculate_tree_layout(num_data_blocks: int) -> tuple[list[int], int]:
    """Calculate the block counts for each level of the Merkle tree.

    Level 0 contains digests of data blocks.
    Level k contains digests of Level k-1 blocks.
    The highest level has exactly 1 block (the root block).

    Returns:
        (level_blocks, total_hash_blocks)
        where level_blocks is [blocks_at_level_0, blocks_at_level_1, ..., 1].
    """
    if not isinstance(num_data_blocks, int) or num_data_blocks <= 0:
        raise VerityError("num_data_blocks must be a positive integer")
    if num_data_blocks > MAX_DATA_BLOCKS:
        raise VerityError("num_data_blocks exceeds maximum permitted data size")
    if num_data_blocks == 1:
        return [], 0

    level_blocks: list[int] = []
    current_blocks = num_data_blocks
    for _ in range(MAX_LEVELS):
        needed = (current_blocks + DIGESTS_PER_BLOCK - 1) // DIGESTS_PER_BLOCK
        level_blocks.append(needed)
        if needed == 1:
            break
        current_blocks = needed
    else:
        raise VerityError("tree depth exceeds maximum allowed levels")

    total_hash_blocks = sum(level_blocks)
    return level_blocks, total_hash_blocks


def encode_verity_tree(
    data_fd: int,
    hash_fd: int,
    *,
    salt: bytes,
    num_data_blocks: int,
) -> tuple[str, int]:
    """Read data blocks from data_fd and write the Merkle tree to hash_fd.

    Layout on hash_fd:
      - Block 0: Root block (Level L-1, 1 block)
      - Blocks 1 .. : Level L-2 blocks (if any)
      - ...
      - Last: Level 0 blocks

    Returns:
        (root_hash_hex, total_hash_blocks)
    """
    if len(salt) != DIGEST_SIZE:
        raise VerityError("salt must be 32 bytes")
    if num_data_blocks == 1:
        os.lseek(data_fd, 0, os.SEEK_SET)
        chunk = os.read(data_fd, BLOCK_SIZE)
        if len(chunk) != BLOCK_SIZE:
            raise VerityError("unexpected EOF or short read from data image")
        root_hash = hashlib.sha256(salt + chunk).hexdigest()
        os.lseek(hash_fd, 0, os.SEEK_SET)
        os.ftruncate(hash_fd, 0)
        os.fsync(hash_fd)
        return root_hash, 0

    level_blocks, total_hash_blocks = calculate_tree_layout(num_data_blocks)
    num_levels = len(level_blocks)

    # 1. Compute Level 0 hashes from data blocks
    os.lseek(data_fd, 0, os.SEEK_SET)
    levels: list[list[bytes]] = [[] for _ in range(num_levels)]

    current_hash_block = bytearray()
    blocks_processed = 0

    while blocks_processed < num_data_blocks:
        to_read = min(IO_CHUNK_BLOCKS, num_data_blocks - blocks_processed)
        chunk = os.read(data_fd, to_read * BLOCK_SIZE)
        if len(chunk) != to_read * BLOCK_SIZE:
            raise VerityError("unexpected EOF or short read from data image")
        for i in range(to_read):
            block_bytes = chunk[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]
            digest = hashlib.sha256(salt + block_bytes).digest()
            current_hash_block.extend(digest)
            if len(current_hash_block) == BLOCK_SIZE:
                levels[0].append(bytes(current_hash_block))
                current_hash_block.clear()
        blocks_processed += to_read

    if current_hash_block:
        pad_len = BLOCK_SIZE - len(current_hash_block)
        current_hash_block.extend(b"\x00" * pad_len)
        levels[0].append(bytes(current_hash_block))
        current_hash_block.clear()

    if len(levels[0]) != level_blocks[0]:
        raise VerityError("level 0 block count mismatch during tree construction")

    # 2. Build successive levels upwards
    for level_idx in range(1, num_levels):
        prev_blocks = levels[level_idx - 1]
        for prev_block in prev_blocks:
            digest = hashlib.sha256(salt + prev_block).digest()
            current_hash_block.extend(digest)
            if len(current_hash_block) == BLOCK_SIZE:
                levels[level_idx].append(bytes(current_hash_block))
                current_hash_block.clear()
        if current_hash_block:
            pad_len = BLOCK_SIZE - len(current_hash_block)
            current_hash_block.extend(b"\x00" * pad_len)
            levels[level_idx].append(bytes(current_hash_block))
            current_hash_block.clear()
        if len(levels[level_idx]) != level_blocks[level_idx]:
            raise VerityError(f"level {level_idx} block count mismatch")

    # Root level is the highest level, containing exactly 1 block
    root_block = levels[-1][0]
    root_hash = hashlib.sha256(salt + root_block).hexdigest()

    # 3. Write blocks to hash_fd in top-down order (Level L-1 down to 0)
    os.lseek(hash_fd, 0, os.SEEK_SET)
    written_blocks = 0
    for level_idx in range(num_levels - 1, -1, -1):
        for block in levels[level_idx]:
            written = 0
            while written < BLOCK_SIZE:
                n = os.write(hash_fd, block[written:])
                if n <= 0:
                    raise VerityError("write error to hash image")
                written += n
            written_blocks += 1

    if written_blocks != total_hash_blocks:
        raise VerityError("total written hash blocks mismatch")

    os.fsync(hash_fd)
    return root_hash, total_hash_blocks


def build_verity_image(
    data_image: Path,
    out_hash_image: Path,
    *,
    salt: str | None = None,
    world_id: str | None = None,
    t_clock: datetime | int | None = None,
    work_dir: Path | None = None,
) -> dict:
    """Build a dm-verity hash image for data_image and return verification metadata.

    The hash image is written atomically into out_hash_image with read-only permissions
    and clamped timestamp.
    """
    if salt is not None:
        salt_bytes = validate_salt(salt)
        salt_hex = salt.lower()
    elif world_id is not None:
        salt_hex = derive_verity_salt(world_id)
        salt_bytes = validate_salt(salt_hex)
    else:
        raise VerityError("either salt or world_id must be provided to build_verity_image")

    if t_clock is not None:
        if isinstance(t_clock, datetime):
            if t_clock.tzinfo is None or t_clock.utcoffset() is None:
                raise VerityError("t_clock must be timezone-aware")
            epoch = int(t_clock.timestamp())
        elif isinstance(t_clock, int):
            epoch = t_clock
        else:
            raise VerityError("invalid t_clock type")
    else:
        epoch = 1700000000

    max_bytes = MAX_DATA_BLOCKS * BLOCK_SIZE
    data_fd = open_regular(data_image, max_bytes)
    try:
        data_stat = os.fstat(data_fd)
        data_size = data_stat.st_size
        if data_size == 0 or data_size % BLOCK_SIZE != 0:
            raise VerityError("data image size must be a non-zero multiple of 4096 bytes")
        num_data_blocks = data_size // BLOCK_SIZE
        if num_data_blocks > MAX_DATA_BLOCKS:
            raise VerityError("data image exceeds maximum allowed blocks")

        out_parent, out_leaf = open_parent(out_hash_image)
        temp_name = None
        hash_fd = None
        try:
            for attempt in range(MAX_TEMP_ATTEMPTS):
                candidate = f".verity-hash.{attempt}"
                if candidate == out_leaf:
                    continue
                try:
                    hash_fd = os.open(
                        candidate,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600,
                        dir_fd=out_parent,
                    )
                except FileExistsError:
                    continue
                temp_name = candidate
                break

            if hash_fd is None or temp_name is None:
                raise OSError(errno.EEXIST, "temporary hash file attempts exhausted")

            root_hash, total_hash_blocks = encode_verity_tree(
                data_fd, hash_fd, salt=salt_bytes, num_data_blocks=num_data_blocks
            )

            # Compute SHA-256 of the generated hash image
            os.lseek(hash_fd, 0, os.SEEK_SET)
            h = hashlib.sha256()
            read_bytes = 0
            expected_bytes = total_hash_blocks * BLOCK_SIZE
            while read_bytes < expected_bytes:
                chunk = os.read(hash_fd, min(IO_CHUNK_BYTES, expected_bytes - read_bytes))
                if not chunk:
                    break
                h.update(chunk)
                read_bytes += len(chunk)
            if read_bytes != expected_bytes:
                raise VerityError("hash image size mismatch during verification read")
            hash_sha256 = h.hexdigest()

            os.fchmod(hash_fd, 0o400)
            os.utime(hash_fd, (epoch, epoch))
            os.fsync(hash_fd)

            # Atomic publication via renameat2(RENAME_NOREPLACE)
            libc = ctypes.CDLL(None, use_errno=True)
            rename = libc.renameat2
            rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            rename.restype = ctypes.c_int
            if rename(out_parent, os.fsencode(temp_name), out_parent, os.fsencode(out_leaf), 1) != 0:
                raise OSError(ctypes.get_errno(), "cannot publish verity hash image")
            os.fsync(out_parent)
            temp_name = None
        finally:
            if hash_fd is not None:
                os.close(hash_fd)
            if temp_name is not None:
                try:
                    os.unlink(temp_name, dir_fd=out_parent)
                except OSError:
                    pass
            os.close(out_parent)
    finally:
        os.close(data_fd)

    dm_create_str = format_dm_create("netvm", num_data_blocks, root_hash, salt_hex)

    return {
        "root_hash": root_hash,
        "salt": salt_hex,
        "data_blocks": num_data_blocks,
        "hash_blocks": total_hash_blocks,
        "data_block_size": BLOCK_SIZE,
        "hash_block_size": BLOCK_SIZE,
        "hash_image": str(out_hash_image),
        "hash_sha256": hash_sha256,
        "sectors": num_data_blocks * 8,
        "dm_create": dm_create_str,
    }


def format_dm_create(
    name: str,
    num_data_blocks: int,
    root_hash: str,
    salt: str,
    *,
    error_behavior: str = "restart_on_corruption",
) -> str:
    """Format dm-mod.create command line argument for NetVM verity root."""
    if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", name):
        raise VerityError("device name must be 1-32 alphanumeric characters")
    if not isinstance(num_data_blocks, int) or not 0 < num_data_blocks <= MAX_DATA_BLOCKS:
        raise VerityError("invalid num_data_blocks")
    if not isinstance(root_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", root_hash.lower()):
        raise VerityError("root_hash must be a 64-character lowercase hex string")
    if not isinstance(salt, str) or not re.fullmatch(r"[0-9a-f]{64}", salt.lower()):
        raise VerityError("salt must be a 64-character lowercase hex string")
    if error_behavior not in ("restart_on_corruption", "panic_on_corruption"):
        raise VerityError("error_behavior must be restart_on_corruption or panic_on_corruption")

    num_sectors = num_data_blocks * 8
    table = (
        f"0 {num_sectors} verity 1 /dev/vda /dev/vdb 4096 4096 "
        f"{num_data_blocks} 0 sha256 {root_hash.lower()} {salt.lower()} 1 {error_behavior}"
    )
    return f'dm-mod.create="{name},,,ro,{table}"'


def parse_dm_create(arg: str) -> dict:
    """Parse and strictly validate a dm-mod.create argument for NetVM dm-verity."""
    if not isinstance(arg, str):
        raise VerityError("dm-mod.create argument must be a string")
    match = re.fullmatch(r'dm-mod\.create="([^"]+)"', arg)
    if not match:
        raise VerityError("dm-mod.create must be quoted and have valid prefix")
    body = match.group(1)
    parts = body.split(",", 4)
    if len(parts) != 5:
        raise VerityError("dm-mod.create requires 5 comma-separated components")
    name, uuid, minor, flags, table = parts
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", name):
        raise VerityError("invalid dm-mod device name")
    if uuid and not re.fullmatch(r"[a-fA-F0-9-]{1,36}", uuid):
        raise VerityError("invalid dm-mod uuid")
    if minor and minor != "0":
        raise VerityError("dm-mod minor must be empty or 0")
    if flags != "ro":
        raise VerityError("dm-mod flags must be strictly 'ro'")

    table_data = parse_verity_table(table)
    return {
        "name": name,
        "uuid": uuid,
        "minor": minor,
        "flags": flags,
        **table_data,
    }


def parse_verity_table(table: str) -> dict:
    """Parse and validate the verity target line."""
    tokens = table.split(" ")
    if len(tokens) not in (13, 15):
        raise VerityError("invalid verity table token count")

    if tokens[0] != "0":
        raise VerityError("start_sector must be 0")
    if not (re.fullmatch(r"(?:0|[1-9][0-9]*)", tokens[1]) and re.fullmatch(r"(?:0|[1-9][0-9]*)", tokens[8])):
        raise VerityError("sectors and data_blocks must be canonical ASCII decimal integers")
    try:
        num_sectors = int(tokens[1])
        data_blocks = int(tokens[8])
    except ValueError:
        raise VerityError("sectors and data_blocks must be integers") from None

    if data_blocks <= 0 or data_blocks > MAX_DATA_BLOCKS:
        raise VerityError("data_blocks out of range")
    if num_sectors != data_blocks * 8:
        raise VerityError("num_sectors must equal data_blocks * 8")

    if tokens[2] != "verity":
        raise VerityError("target type must be verity")
    if tokens[3] != "1":
        raise VerityError("verity version must be 1")
    if tokens[4] != "/dev/vda":
        raise VerityError("data device must be /dev/vda")
    if tokens[5] != "/dev/vdb":
        raise VerityError("hash device must be /dev/vdb")
    if tokens[6] != "4096" or tokens[7] != "4096":
        raise VerityError("block sizes must be 4096")
    if tokens[9] != "0":
        raise VerityError("hash start block must be 0")
    if tokens[10] != "sha256":
        raise VerityError("algorithm must be sha256")
    root_hash = tokens[11]
    if not re.fullmatch(r"[0-9a-f]{64}", root_hash):
        raise VerityError("root_hash must be 64 lowercase hex characters")
    salt = tokens[12]
    if not re.fullmatch(r"[0-9a-f]{64}", salt):
        raise VerityError("salt must be 64 lowercase hex characters")

    if len(tokens) == 15:
        if tokens[13] != "1":
            raise VerityError("optional parameter count must be 1")
        if tokens[14] not in ("restart_on_corruption", "panic_on_corruption"):
            raise VerityError("optional parameter must be restart_on_corruption or panic_on_corruption")
        error_behavior = tokens[14]
    else:
        error_behavior = "eio"

    return {
        "num_sectors": num_sectors,
        "data_blocks": data_blocks,
        "root_hash": root_hash,
        "salt": salt,
        "error_behavior": error_behavior,
    }


def verify_verity_tree(
    data_fd: int,
    hash_fd: int,
    *,
    salt: str | bytes,
    expected_root_hash: str,
    num_data_blocks: int,
) -> bool:
    """Verify an existing hash image against data blocks and expected root hash.

    Returns True if verification succeeds, False if corrupted.
    """
    salt_bytes = validate_salt(salt)
    expected_root_hash = expected_root_hash.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_root_hash):
        return False

    try:
        level_blocks, total_hash_blocks = calculate_tree_layout(num_data_blocks)
    except VerityError:
        return False

    # Check hash_fd size
    hash_stat = os.fstat(hash_fd)
    if hash_stat.st_size != total_hash_blocks * BLOCK_SIZE:
        return False

    if num_data_blocks == 1:
        os.lseek(data_fd, 0, os.SEEK_SET)
        chunk = os.read(data_fd, BLOCK_SIZE)
        if len(chunk) != BLOCK_SIZE:
            return False
        computed_root = hashlib.sha256(salt_bytes + chunk).hexdigest()
        return computed_root == expected_root_hash

    # Read root block (first block of hash_fd)
    os.lseek(hash_fd, 0, os.SEEK_SET)
    root_block = os.read(hash_fd, BLOCK_SIZE)
    if len(root_block) != BLOCK_SIZE:
        return False
    computed_root = hashlib.sha256(salt_bytes + root_block).hexdigest()
    if computed_root != expected_root_hash:
        return False

    # Read all hash blocks into memory (bounded by total_hash_blocks <= 32768 for up to 16GB)
    num_levels = len(level_blocks)
    levels: list[list[bytes]] = [[] for _ in range(num_levels)]

    os.lseek(hash_fd, 0, os.SEEK_SET)
    for level_idx in range(num_levels - 1, -1, -1):
        for _ in range(level_blocks[level_idx]):
            block = os.read(hash_fd, BLOCK_SIZE)
            if len(block) != BLOCK_SIZE:
                return False
            levels[level_idx].append(block)

    # Verify each upper level authenticates the level beneath it
    for level_idx in range(num_levels - 1, 0, -1):
        parent_blocks = levels[level_idx]
        child_blocks = levels[level_idx - 1]
        for child_idx, child_block in enumerate(child_blocks):
            parent_block_idx = child_idx // DIGESTS_PER_BLOCK
            offset_in_parent = (child_idx % DIGESTS_PER_BLOCK) * DIGEST_SIZE
            expected_digest = parent_blocks[parent_block_idx][offset_in_parent : offset_in_parent + DIGEST_SIZE]
            actual_digest = hashlib.sha256(salt_bytes + child_block).digest()
            if actual_digest != expected_digest:
                return False

    # Verify Level 0 authenticates data blocks
    os.lseek(data_fd, 0, os.SEEK_SET)
    level_0_blocks = levels[0]
    blocks_checked = 0
    while blocks_checked < num_data_blocks:
        to_read = min(IO_CHUNK_BLOCKS, num_data_blocks - blocks_checked)
        chunk = os.read(data_fd, to_read * BLOCK_SIZE)
        if len(chunk) != to_read * BLOCK_SIZE:
            return False
        for i in range(to_read):
            data_block_idx = blocks_checked + i
            parent_block_idx = data_block_idx // DIGESTS_PER_BLOCK
            offset_in_parent = (data_block_idx % DIGESTS_PER_BLOCK) * DIGEST_SIZE
            expected_digest = level_0_blocks[parent_block_idx][offset_in_parent : offset_in_parent + DIGEST_SIZE]
            actual_digest = hashlib.sha256(salt_bytes + chunk[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]).digest()
            if actual_digest != expected_digest:
                return False
        blocks_checked += to_read

    return True

