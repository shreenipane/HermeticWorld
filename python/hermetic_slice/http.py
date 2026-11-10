"""HTTP client with disk cache, exponential backoff, and GitHub token support."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
from pathlib import Path
import socket
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
                    status = getattr(resp, "status", None)
                    if status is None:
                        getcode = getattr(resp, "getcode", None)
                        status = getcode() if callable(getcode) else getattr(resp, "code", 200)
                    body = resp.read()
                    if status == 200:
                        http_cache_dir.mkdir(parents=True, exist_ok=True)
                        cache_file.write_bytes(body)
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
