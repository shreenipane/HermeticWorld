"""Named caps and constants bounding all network, filesystem, and parsing operations."""

from __future__ import annotations

# Named caps bounding request lines, headers, concurrency, and socket timeouts.
MAX_REQUEST_LINE_BYTES: int = 4096
MAX_HEADER_LINE_BYTES: int = 8192
MAX_HEADER_COUNT: int = 64
MAX_TOTAL_HEADERS_BYTES: int = 32768
MAX_DRAIN_BODY_BYTES: int = 65536
MAX_CONCURRENT_CONNECTIONS: int = 64
REQUEST_QUEUE_SIZE: int = 64
SOCKET_TIMEOUT_SECONDS: float = 10.0
DEFAULT_SOCKET_TIMEOUT: float = SOCKET_TIMEOUT_SECONDS
CONNECT_TIMEOUT_SECONDS: float = 5.0
DEFAULT_CONNECT_TIMEOUT: float = CONNECT_TIMEOUT_SECONDS
REQUEST_READ_DEADLINE_SECONDS: float = 20.0

# Bounded upstream response sizes.
MAX_INDEX_RESPONSE_BYTES: int = 32 * 1024 * 1024  # 32 MiB
MAX_DIST_FILE_BYTES: int = 512 * 1024 * 1024  # 512 MiB
MAX_MANIFEST_BYTES: int = 32 * 1024 * 1024  # 32 MiB
MAX_MISS_LOG_BYTES: int = 10 * 1024 * 1024  # 10 MiB

# Bounds on collections.
MAX_PROJECTS_COUNT: int = 50_000
MAX_FILES_PER_PROJECT: int = 10_000
MAX_TOTAL_FILES_COUNT: int = 100_000
MAX_REDIRECTS: int = 3
MAX_TEMP_ATTEMPTS: int = 256
MAX_DIR_ENTRIES: int = 100_000

# String and chunk sizes.
MAX_PROJECT_NAME_BYTES: int = 256
MAX_FILENAME_BYTES: int = 255
FILE_CHUNK_BYTES: int = 65536  # 64 KiB
SHA256_HEX_LEN: int = 64
MAX_RANGE_DIGITS: int = 20

# MIME types.
PEP691_JSON_MIME: str = "application/vnd.pypi.simple.v1+json"
PEP503_HTML_MIME: str = "text/html; charset=utf-8"
TEXT_PLAIN_MIME: str = "text/plain; charset=utf-8"
OCTET_STREAM_MIME: str = "application/octet-stream"

# Manifest schema version.
MANIFEST_SCHEMA: str = "hermetic.pkgrec.manifest/1"
