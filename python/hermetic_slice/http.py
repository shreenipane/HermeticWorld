"""HTTP client with disk cache, exponential backoff, and GitHub token support."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import os
from pathlib import Path
import socket
import tempfile
import time
import urllib.error
import urllib.request


class HttpError(Exception):
    """Raised when an HTTP request fails."""

    def __init__(self, url: str, status: int) -> None:
        self.url = url
        self.status = status
        super().__init__(f"HTTP {status} for {url}")


HttpGet = Callable[[str], bytes]


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write data to a temp file in path's parent directory and atomically replace destination."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False, prefix=f".{path.name}.", suffix=".tmp") as tmp:
            tmp.write(data)
            tmp.flush()
            tmp_path = Path(tmp.name)
        os.replace(tmp_path, path)
    except BaseException:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise


def make_http_get(
    cache_dir: Path,
    *,
    sleep: Callable[[float], None] = time.sleep,
    token: str | None = None,
) -> HttpGet:
    """Create an HttpGet callable backed by a disk cache and retry logic."""
    http_cache_dir = cache_dir / "http"

    def http_get(url: str) -> bytes:
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
        cache_file = http_cache_dir / f"{url_hash}.body"
        if cache_file.exists():
            return cache_file.read_bytes()

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "hermetic-world-intake/0.1")
        if token and url.startswith("https://api.github.com/"):
            req.add_header("Authorization", f"Bearer {token}")

        retry_delays = [2, 4, 8, 16]
        max_attempts = 5
        last_status = 0

        for attempt in range(max_attempts):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    status = resp.status
                    body = resp.read()
                    if status == 200:
                        atomic_write_bytes(cache_file, body)
                    return body
            except urllib.error.HTTPError as exc:
                last_status = exc.code
                if exc.code == 429 or (500 <= exc.code < 600):
                    if attempt < len(retry_delays):
                        sleep(retry_delays[attempt])
                        continue
                elif 400 <= exc.code < 500:
                    raise HttpError(url, exc.code) from None
                if attempt < len(retry_delays):
                    sleep(retry_delays[attempt])
                    continue
            except (urllib.error.URLError, TimeoutError, socket.timeout):
                last_status = 0
                if attempt < len(retry_delays):
                    sleep(retry_delays[attempt])
                    continue

        raise HttpError(url, last_status) from None

    return http_get
