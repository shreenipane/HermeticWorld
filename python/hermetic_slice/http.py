"""HTTP client with disk cache, exponential backoff, and GitHub token support."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
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
        super().__init__(f"HTTP {status}")


HttpGet = Callable[[str], bytes]
HttpPostJson = Callable[[str, Any], Any]


MAX_HTTP_BODY_BYTES = 8 * 1024 * 1024
MAX_HTTP_REQUEST_BYTES = 1024 * 1024
MAX_CACHE_PATH_PARTS = 128
MAX_SNAPSHOT_ID_BYTES = 1024


def open_secure_directory(path: Path) -> int:
    """Open/create a directory through checked, no-follow directory descriptors.

    Operator roots follow the same fail-closed policy as their descendants: callers
    must supply a physical path with no symlink components, including trusted prefixes.
    """
    path = Path(path).absolute()
    parts = path.parts[1:]
    if len(parts) > MAX_CACHE_PATH_PARTS or any(p in (".", "..") for p in parts):
        raise ValueError("invalid_cache_path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            try:
                info = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=fd)
                info = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("invalid_cache_directory")
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def bounded_read(stream: Any) -> bytes:
    """Bound both network and cache response reads before decoding."""
    body = stream.read(MAX_HTTP_BODY_BYTES + 1)
    if not isinstance(body, bytes) or len(body) > MAX_HTTP_BODY_BYTES:
        raise ValueError("http_body_limit")
    return body


def _read_cache(path: Path) -> bytes | None:
    parent_fd = open_secure_directory(path.parent)
    try:
        try:
            info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_HTTP_BODY_BYTES:
            raise ValueError("invalid_cache_file")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("invalid_cache_file")
            return bounded_read(stream)
    finally:
        os.close(parent_fd)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Publish a private file atomically through a no-follow directory descriptor."""
    path = Path(path)
    parent_fd = open_secure_directory(path.parent)
    temp_name = "." + uuid.uuid4().hex + ".tmp"
    try:
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent_fd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    finally:
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


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
        cached = _read_cache(cache_file)
        if cached is not None:
            return cached

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
                    body = bounded_read(resp)
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

    if not isinstance(snapshot_id, str) or len(snapshot_id.encode("utf-8")) > MAX_SNAPSHOT_ID_BYTES:
        raise ValueError("invalid_snapshot_id")
    snapshot_key = hashlib.sha256(snapshot_id.encode("utf-8")).hexdigest()

    def http_post_json_fn(url: str, payload: Any) -> Any:
        if isinstance(payload, str):
            body_str = payload
        else:
            body_str = json.dumps(payload, sort_keys=True)

        cache_key = hashlib.sha256((url + body_str).encode("utf-8")).hexdigest()
        cache_file = http_cache_dir / f"{snapshot_key}_{cache_key}.body"
        cached = _read_cache(cache_file)
        if cached is not None:
            return json.loads(cached.decode("utf-8"))

        data = body_str.encode("utf-8")
        if len(data) > MAX_HTTP_REQUEST_BYTES:
            raise ValueError("http_request_limit")
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
                    body = bounded_read(resp)
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

    # Intake establishes a fresh run boundary even for supplied production clients.
    def begin_snapshot(snapshot_id: str | None = None, refresh: bool = False) -> HttpPostJson:
        return make_http_post_json(cache_dir, sleep=sleep, token=token,
                                   snapshot_id=snapshot_id, refresh=refresh)

    http_post_json_fn.begin_snapshot = begin_snapshot
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
        return json.loads(bounded_read(resp).decode("utf-8"))
