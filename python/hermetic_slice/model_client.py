"""Gemini API model client for hermetic agent runs."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import time
from typing import Any, Callable, Mapping
import urllib.error
import urllib.request


class ModelError(Exception):
    """Raised when model loading, generation, or retries fail."""

    def __init__(self, message_or_status: Any, body: str = "") -> None:
        self.status: int | None
        self.body: str
        if isinstance(message_or_status, int):
            self.status = message_or_status
            self.body = body
            super().__init__(f"HTTP {message_or_status}: {body}".strip())
        else:
            self.status = None
            self.body = str(message_or_status)
            super().__init__(str(message_or_status))


def load_api_key(env: Mapping[str, str] = os.environ) -> str:
    """Read the Gemini API key from the file named by HERMETIC_GEMINI_KEY_FILE.

    Raises ModelError on missing variable, missing file, or read failure,
    without echoing the key's contents.
    """
    path_str = env.get("HERMETIC_GEMINI_KEY_FILE")
    if not path_str:
        raise ModelError("HERMETIC_GEMINI_KEY_FILE environment variable is not set")

    key_file = Path(path_str)
    if not key_file.is_file():
        raise ModelError(f"HERMETIC_GEMINI_KEY_FILE points to nonexistent file: {key_file}")

    try:
        key = key_file.read_text(encoding="utf-8").strip()
    except Exception as exc:
        raise ModelError(f"Failed to read key file {key_file}: {exc.__class__.__name__}")

    if not key:
        raise ModelError(f"Key file {key_file} is empty")

    return key


@dataclass(frozen=True)
class ModelReply:
    """Parsed model response from Gemini API."""

    text: str
    finish_reason: str
    usage: dict[str, Any]
    latency_s: float
    attempts: int


class PostResult(tuple):
    """2-tuple with optional headers attribute for HTTP responses."""

    def __new__(cls, status: int, body: bytes, headers: dict[str, str] | None = None):
        obj = super().__new__(cls, (status, body))
        obj.headers = {k.lower(): v for k, v in (headers or {}).items()}
        return obj


def _default_http_post(
    url: str,
    headers: dict[str, str],
    body_bytes: bytes,
    timeout: float = 300,
) -> tuple[int, bytes]:
    """Default HTTP POST implementation using urllib.request."""
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read()
            resp_headers = dict(resp.headers)
            return PostResult(status, body, resp_headers)
    except urllib.error.HTTPError as exc:
        body = exc.read()
        resp_headers = dict(exc.headers)
        return PostResult(exc.code, body, resp_headers)
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return PostResult(0, b"")


RETRYABLE_STATUSES = {0, 429, 500, 502, 503, 504}
BACKOFF_DELAYS = [5, 10, 20, 40, 80, 160]


class GeminiClient:
    """Client for generating completions using Google Gemini API."""

    def __init__(
        self,
        model: str,
        api_key: str,
        *,
        http_post: Callable[..., tuple[int, bytes]] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 7,
        request_timeout: float = 300,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.http_post = http_post or _default_http_post
        self.sleep = sleep
        self.max_attempts = max_attempts
        self.request_timeout = request_timeout

    def _scrub(self, text: str) -> str:
        if self.api_key and self.api_key in text:
            text = text.replace(self.api_key, "[REDACTED]")
        return text

    def generate(self, system: str, messages: list[dict[str, str]]) -> ModelReply:
        """Call generateContent and return ModelReply."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        headers = {
            "x-goog-api-key": self.api_key,
            "Content-Type": "application/json",
        }

        contents = []
        for msg in messages:
            contents.append({
                "role": msg["role"],
                "parts": [{"text": msg["text"]}],
            })

        body_dict: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": 16384,
            },
        }
        if system:
            body_dict["systemInstruction"] = {
                "parts": [{"text": system}],
            }

        body_bytes = json.dumps(body_dict).encode("utf-8")

        t0 = time.monotonic()
        last_status = 0
        last_body = ""

        for attempt in range(1, self.max_attempts + 1):
            res = self.http_post(url, headers, body_bytes, timeout=self.request_timeout)
            status = res[0]
            body_bytes_out = res[1]

            if status == 200:
                latency_s = time.monotonic() - t0
                try:
                    data = json.loads(body_bytes_out.decode("utf-8"))
                except Exception as exc:
                    scrubbed = self._scrub(str(exc))
                    raise ModelError(200, f"Failed to parse JSON response: {scrubbed[:500]}")

                candidates = data.get("candidates", [])
                text_parts = []
                finish_reason = ""
                if candidates:
                    cand = candidates[0]
                    finish_reason = cand.get("finishReason", "")
                    content = cand.get("content", {})
                    parts = content.get("parts", [])
                    for part in parts:
                        if not part.get("thought", False):
                            text_parts.append(part.get("text", ""))

                text = "".join(text_parts)
                usage = data.get("usageMetadata", {})
                return ModelReply(
                    text=text,
                    finish_reason=finish_reason,
                    usage=usage,
                    latency_s=latency_s,
                    attempts=attempt,
                )

            # Non-200 status
            last_status = status
            raw_body_str = body_bytes_out.decode("utf-8", errors="replace")
            last_body = self._scrub(raw_body_str)

            if status in RETRYABLE_STATUSES and attempt < self.max_attempts:
                # Check for Retry-After header
                resp_headers = getattr(res, "headers", {})
                retry_after_val = resp_headers.get("retry-after")
                delay: float | None = None
                if retry_after_val is not None:
                    try:
                        delay = float(retry_after_val)
                    except ValueError:
                        delay = None
                if delay is None:
                    idx = min(attempt - 1, len(BACKOFF_DELAYS) - 1)
                    delay = float(BACKOFF_DELAYS[idx])
                self.sleep(delay)
                continue
            else:
                raise ModelError(status, last_body[:500])

        raise ModelError(last_status, last_body[:500])
