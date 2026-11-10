"""Tests for HTTP client, disk cache, backoff retry, and token handling."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from hermetic_slice.http import HttpError, make_http_get


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
