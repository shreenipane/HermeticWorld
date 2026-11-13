"""Tests for HTTP client, disk cache, backoff retry, and token handling."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from hermetic_slice.http import HttpError, atomic_write_bytes, make_http_get, make_http_post_json


def test_make_http_get_retry_and_backoff(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    sleep_calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    # 502, 502, then 200 succeeds with sleeps [2, 4]
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b"success payload"
    mock_resp.__enter__.return_value = mock_resp

    err502 = urllib.error.HTTPError("http://example.com", 502, "Bad Gateway", {}, None)  # type: ignore

    with patch(
        "urllib.request.urlopen",
        side_effect=[err502, err502, mock_resp],
    ) as mock_urlopen:
        http_get = make_http_get(cache_dir, sleep=fake_sleep)
        res = http_get("http://example.com/test")

        assert res == b"success payload"
        assert sleep_calls == [2, 4]
        assert mock_urlopen.call_count == 3


def test_make_http_get_404_no_retry(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    sleep_calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    err404 = urllib.error.HTTPError("http://example.com/missing", 404, "Not Found", {}, None)  # type: ignore

    with patch("urllib.request.urlopen", side_effect=err404) as mock_urlopen:
        http_get = make_http_get(cache_dir, sleep=fake_sleep)
        with pytest.raises(HttpError) as exc_info:
            http_get("http://example.com/missing")

        assert exc_info.value.status == 404
        assert exc_info.value.url == "http://example.com/missing"
        assert sleep_calls == [], "404 must not trigger any sleep/retry"
        assert mock_urlopen.call_count == 1


def test_make_http_get_cache_hit_makes_no_network_call(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    sleep_calls: list[float] = []

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b"cached data"
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        http_get = make_http_get(cache_dir, sleep=sleep_calls.append)
        res1 = http_get("http://example.com/item")
        assert res1 == b"cached data"
        assert mock_urlopen.call_count == 1

        # Second call is a cache hit
        res2 = http_get("http://example.com/item")
        assert res2 == b"cached data"
        assert mock_urlopen.call_count == 1, "Cache hit must make zero network calls"


def test_make_http_get_token_handling(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    secret_token = "ghp_SECRET_TOKEN_XYZ_98765"

    captured_requests: list[urllib.request.Request] = []

    def fake_urlopen(req: urllib.request.Request, timeout: int = 60) -> MagicMock:
        captured_requests.append(req)
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"status": "ok"}'
        mock_resp.__enter__.return_value = mock_resp
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        http_get = make_http_get(cache_dir, token=secret_token)

        # 1. GitHub API URL -> token is sent
        http_get("https://api.github.com/repos/owner/repo")
        assert len(captured_requests) == 1
        assert captured_requests[0].get_header("Authorization") == f"Bearer {secret_token}"

        # 2. Non-GitHub API URL -> token is NOT sent
        http_get("https://datasets-server.huggingface.co/rows?test=1")
        assert len(captured_requests) == 2
        assert captured_requests[1].get_header("Authorization") is None

    # Verify token never appears in any cache file
    for cache_file in (cache_dir / "http").iterdir():
        file_bytes = cache_file.read_bytes()
        assert secret_token.encode("utf-8") not in file_bytes

    # Verify token never appears in exception messages
    err500 = urllib.error.HTTPError("https://api.github.com/fail", 500, "Internal Server Error", {}, None)  # type: ignore
    with patch("urllib.request.urlopen", side_effect=err500):
        http_get_fail = make_http_get(tmp_path / "cache_fail", sleep=lambda s: None, token=secret_token)
        with pytest.raises(HttpError) as exc_info:
            http_get_fail("https://api.github.com/fail")
        assert secret_token not in str(exc_info.value)
        assert secret_token not in repr(exc_info.value)


def test_atomic_write_bytes_failure_leaves_no_file(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache" / "sample.txt"
    with patch("os.replace", side_effect=OSError("replace failed")):
        with pytest.raises(OSError, match="replace failed"):
            atomic_write_bytes(cache_path, b"some content")

    assert not cache_path.exists()
    # Ensure no partial or temporary files left in parent directory
    assert list(cache_path.parent.glob("*.tmp")) == []


def test_make_http_post_json_retry_and_backoff(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    sleep_calls: list[float] = []

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b'{"data": {"status": "ok"}}'
    mock_resp.__enter__.return_value = mock_resp

    err502 = urllib.error.HTTPError("http://example.com/graphql", 502, "Bad Gateway", {}, None)  # type: ignore

    with patch(
        "urllib.request.urlopen",
        side_effect=[err502, err502, mock_resp],
    ) as mock_urlopen:
        http_post = make_http_post_json(cache_dir, sleep=sleep_calls.append)
        res = http_post("http://example.com/graphql", {"query": "test"})

        assert res == {"data": {"status": "ok"}}
        assert sleep_calls == [2, 4]
        assert mock_urlopen.call_count == 3


def test_make_http_post_json_404_no_retry(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    sleep_calls: list[float] = []

    err404 = urllib.error.HTTPError("http://example.com/missing", 404, "Not Found", {}, None)  # type: ignore

    with patch("urllib.request.urlopen", side_effect=err404) as mock_urlopen:
        http_post = make_http_post_json(cache_dir, sleep=sleep_calls.append)
        with pytest.raises(HttpError) as exc_info:
            http_post("http://example.com/missing", {"query": "test"})

        assert exc_info.value.status == 404
        assert exc_info.value.url == "http://example.com/missing"
        assert sleep_calls == []
        assert mock_urlopen.call_count == 1


def test_make_http_post_json_cache_hit(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    sleep_calls: list[float] = []

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b'{"data": {"item": 1}}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        http_post = make_http_post_json(cache_dir, sleep=sleep_calls.append)
        res1 = http_post("http://example.com/graphql", {"query": "q1"})
        assert res1 == {"data": {"item": 1}}
        assert mock_urlopen.call_count == 1

        # Second call is a cache hit
        res2 = http_post("http://example.com/graphql", {"query": "q1"})
        assert res2 == {"data": {"item": 1}}
        assert mock_urlopen.call_count == 1, "Cache hit must make zero network calls"


def test_make_http_post_json_token_handling(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    secret_token = "ghp_POST_SECRET_TOKEN_123"

    captured_requests: list[urllib.request.Request] = []

    def fake_urlopen(req: urllib.request.Request, timeout: int = 60) -> MagicMock:
        captured_requests.append(req)
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"data": "ok"}'
        mock_resp.__enter__.return_value = mock_resp
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        http_post = make_http_post_json(cache_dir, token=secret_token)

        # 1. GitHub API URL -> token is sent
        http_post("https://api.github.com/graphql", {"query": "test"})
        assert len(captured_requests) == 1
        assert captured_requests[0].get_header("Authorization") == f"Bearer {secret_token}"
        assert captured_requests[0].get_header("Content-type") == "application/json"

        # 2. Non-GitHub API URL -> token is NOT sent
        http_post("https://other.com/graphql", {"query": "test"})
        assert len(captured_requests) == 2
        assert captured_requests[1].get_header("Authorization") is None

    # Verify token never appears in any cache file
    for cache_file in (cache_dir / "http").iterdir():
        file_bytes = cache_file.read_bytes()
        assert secret_token.encode("utf-8") not in file_bytes


def test_make_http_post_json_errors_not_cached(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b'{"data": null, "errors": [{"message": "Field not found"}]}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        http_post = make_http_post_json(cache_dir)
        res1 = http_post("https://api.github.com/graphql", {"query": "bad_query"})
        assert res1 == {"data": None, "errors": [{"message": "Field not found"}]}
        assert mock_urlopen.call_count == 1

        # Because response contained errors, no cache file should be written!
        http_cache = cache_dir / "http"
        assert not http_cache.exists() or list(http_cache.iterdir()) == []

        # Calling again triggers another network call because errors were not cached
        res2 = http_post("https://api.github.com/graphql", {"query": "bad_query"})
        assert res2 == res1
        assert mock_urlopen.call_count == 2


def _post_cache_file(cache_dir: Path, snapshot: str = "snapshot") -> Path:
    import hashlib
    import json
    key = hashlib.sha256(("https://api.github.com/graphql" + json.dumps({"query": "q"}, sort_keys=True)).encode()).hexdigest()
    snapshot_key = hashlib.sha256(snapshot.encode()).hexdigest()
    return cache_dir / "http" / f"{snapshot_key}_{key}.body"


@pytest.mark.parametrize("method", ["get", "post"])
@pytest.mark.parametrize("source", ["network", "cache"])
def test_http_body_reads_are_bounded(tmp_path: Path, method: str, source: str) -> None:
    import hashlib
    import hermetic_slice.http as module
    cache = tmp_path / "cache"
    url = "https://api.github.com/graphql"
    cache_file = (cache / "http" / (hashlib.sha256(url.encode()).hexdigest() + ".body")) if method == "get" else _post_cache_file(cache)
    # Cache stat passes; the read itself must detect growth past the cap.
    oversized = b"x" * (64 if source == "cache" else 65)
    if source == "cache":
        cache_file.parent.mkdir(parents=True)
        cache_file.write_bytes(oversized)
    class Transport(io.BytesIO):
        status = 200
        def read(self, size=-1):
            assert size == 65, "response reads must use the named byte cap"
            return super().read(size)
    real_bounded_read = module.bounded_read
    def cache_grew(stream):
        with cache_file.open("ab") as writer:
            writer.write(b"x")
        return real_bounded_read(stream)
    factory = make_http_get if method == "get" else make_http_post_json
    options = {} if method == "get" else {"snapshot_id": "snapshot"}
    client = factory(cache, **options)
    with patch.object(module, "MAX_HTTP_BODY_BYTES", 64), patch("urllib.request.urlopen", return_value=Transport(oversized)) as network, patch.object(module, "bounded_read", side_effect=cache_grew if source == "cache" else real_bounded_read) as read:
        with pytest.raises(ValueError, match="http_body_limit|invalid_cache_file"):
            client(url) if method == "get" else client(url, {"query": "q"})
    read.assert_called_once()
    assert network.call_count == (1 if source == "network" else 0)
    if source == "network":
        assert not cache_file.exists()


def test_snapshot_traversal_is_hashed_inside_cache(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    snapshot = "../escape"
    class Transport(io.BytesIO):
        status = 200
    client = make_http_post_json(cache, snapshot_id=snapshot)
    with patch("urllib.request.urlopen", return_value=Transport(b'{"data":{}}')) as network:
        assert client("https://api.github.com/graphql", {"query": "q"}) == {"data": {}}
        assert client("https://api.github.com/graphql", {"query": "q"}) == {"data": {}}
    assert network.call_count == 1
    expected = _post_cache_file(cache, snapshot)
    assert list(cache.rglob("*.body")) == [expected]
    assert not list(tmp_path.glob("escape*"))
    assert expected.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("kind", ["file_symlink", "directory_symlink", "ancestor_symlink", "fifo"])
def test_cache_rejects_links_and_special_files_without_opening(tmp_path: Path, kind: str) -> None:
    import os
    cache = tmp_path / "cache"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "secret"
    sentinel.write_bytes(b'{"data":"outside secret"}')
    if kind == "ancestor_symlink":
        cache.symlink_to(outside, target_is_directory=True)
    else:
        cache.mkdir()
        if kind == "directory_symlink":
            (cache / "http").symlink_to(outside, target_is_directory=True)
        else:
            (cache / "http").mkdir()
            path = _post_cache_file(cache)
            if kind == "file_symlink":
                path.symlink_to(sentinel)
            else:
                os.mkfifo(path)
    client = make_http_post_json(cache, snapshot_id="snapshot")
    # A path-based read would follow links or block on the FIFO. Guard it so
    # this regression itself terminates against the vulnerable implementation.
    with patch.object(Path, "read_bytes", side_effect=AssertionError("unchecked_path_read")), patch("urllib.request.urlopen") as network:
        with pytest.raises(ValueError, match="invalid_cache_directory|invalid_cache_file"):
            client("https://api.github.com/graphql", {"query": "q"})
    assert network.call_count == 0
    assert sentinel.read_bytes() == b'{"data":"outside secret"}'
    assert sorted(p.name for p in outside.iterdir()) == ["secret"]
