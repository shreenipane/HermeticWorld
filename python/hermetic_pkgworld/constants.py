"""Constants and named safety bounds for hermetic_pkgworld."""

from __future__ import annotations

# Domain tags for cryptographic leaf, internal node, and empty tree hashing
PKG_LEAF_TAG: bytes = b"hw-pkg-leaf\0"
PKG_NODE_TAG: bytes = b"hw-pkg-node\0"
PKG_EMPTY_TAG: bytes = b"hw-pkg-empty\0"

# Named safety caps bounding file sizes, entries, and tree traversal
MAX_MANIFEST_BYTES: int = 32 * 1024 * 1024  # 32 MiB
MAX_PLAN_BYTES: int = 64 * 1024 * 1024      # 64 MiB
MAX_FILE_BYTES: int = 512 * 1024 * 1024     # 512 MiB per distribution file
MAX_TOTAL_FILES: int = 100_000
MAX_DIR_ENTRIES: int = 100_000
MAX_PROJECT_SUB_ENTRIES: int = 2
MAX_DEPTH: int = 64
FILE_CHUNK_BYTES: int = 65_536              # 64 KiB
