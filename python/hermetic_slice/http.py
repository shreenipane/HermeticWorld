"""HTTP client with disk cache, exponential backoff, and GitHub token support."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import time
from typing import Any
import urllib.error
import urllib.request
import uuid


class HttpError(Exception):
    """Raised when an HTTP request fails."""

    def __init__(self, url: str, status: int) -> None:
        self.url = url
        self.status = status
        super().__init__(f"HTTP {status} for {url}")


HttpGet = Callable[[str], bytes]
HttpPostJson = Callable[[str, Any], Any]


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


def make_http_post_json(
    cache_dir: Path,
    *,
    sleep: Callable[[float], None] = time.sleep,
    token: str | None = None,
    snapshot_id: str | None = None,
    refresh: bool = False,
) -> HttpPostJson:
    """Create an HttpPostJson callable backed by a disk cache, token handling, and retry logic.

    Mutable GraphQL data is cached per consistent snapshot. A unique snapshot_id isolates
    intake runs so cached pages from an older run are not reused across runs, while pages
    within one run are cached and reused.
    """
    http_cache_dir = cache_dir / "http"
    if snapshot_id is None or refresh:
        snapshot_id = uuid.uuid4().hex

    def http_post_json_fn(url: str, payload: Any) -> Any:
        if isinstance(payload, str):
            body_str = payload
        else:
            body_str = json.dumps(payload, sort_keys=True)

        cache_key = hashlib.sha256((url + body_str).encode("utf-8")).hexdigest()
        cache_file = http_cache_dir / f"{snapshot_id}_{cache_key}.body"
        if cache_file.exists():
            return json.loads(cache_file.read_bytes().decode("utf-8"))

        data = body_str.encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("User-Agent", "hermetic-world-intake/0.1")
        req.add_header("Content-Type", "application/json")
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
                    data_obj = json.loads(body.decode("utf-8"))
                    # Never cache responses containing GraphQL errors
                    has_errors = isinstance(data_obj, dict) and bool(data_obj.get("errors"))
                    if status == 200 and not has_errors:
                        atomic_write_bytes(cache_file, body)
                    return data_obj
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

    return http_post_json_fn


def http_post_json(
    url: str,
    payload: Any,
    *,
    cache_dir: Path | None = None,
    sleep: Callable[[float], None] = time.sleep,
    token: str | None = None,
    snapshot_id: str | None = None,
    refresh: bool = False,
) -> Any:
    """Execute an HTTP POST request sending JSON, optionally cached."""
    if cache_dir is not None:
        caller = make_http_post_json(
            cache_dir,
            sleep=sleep,
            token=token,
            snapshot_id=snapshot_id,
            refresh=refresh,
        )
        return caller(url, payload)

    if isinstance(payload, str):
        body_str = payload
    else:
        body_str = json.dumps(payload, sort_keys=True)

    data = body_str.encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("User-Agent", "hermetic-world-intake/0.1")
    req.add_header("Content-Type", "application/json")
    if token and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", f"Bearer {token}")

    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))
