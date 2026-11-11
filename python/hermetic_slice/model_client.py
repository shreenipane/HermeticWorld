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


def load_api_key(
    env: Mapping[str, str] = os.environ,
    var: str = "HERMETIC_GEMINI_KEY_FILE",
) -> str:
    """Read an API key from the file named by the environment variable `var`.

    Raises ModelError on missing variable, missing file, or read failure,
    without echoing the key's contents.
    """
    path_str = env.get(var)
    if not path_str:
        raise ModelError(f"{var} environment variable is not set")

    key_file = Path(path_str)
    if not key_file.is_file():
        raise ModelError(f"{var} points to nonexistent file: {key_file}")

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

    def _build_request(
        self, system: str, messages: list[dict[str, str]]
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        """Return the URL, headers and JSON body of a generateContent call."""
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
        return url, headers, body_dict

    def _embedded_error(self, data: dict[str, Any]) -> tuple[int, str] | None:
        """Return (status, body) when a 200 response actually carries an error."""
        return None

    def _parse_reply(self, data: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        """Return the text, finish reason and usage of a successful response."""
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

        return "".join(text_parts), finish_reason, data.get("usageMetadata", {})

    def generate(self, system: str, messages: list[dict[str, str]]) -> ModelReply:
        """Call the model API and return ModelReply."""
        url, headers, body_dict = self._build_request(system, messages)
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

                embedded = self._embedded_error(data)
                if embedded is None:
                    text, finish_reason, usage = self._parse_reply(data)
                    return ModelReply(
                        text=text,
                        finish_reason=finish_reason,
                        usage=usage,
                        latency_s=latency_s,
                        attempts=attempt,
                    )
                status, raw_body_str = embedded
            else:
                raw_body_str = body_bytes_out.decode("utf-8", errors="replace")

            # Failed call
            last_status = status
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


class OpenRouterClient(GeminiClient):
    """Client for OpenRouter's free models, through its chat completions API."""

    def __init__(self, model: str, api_key: str, **kwargs: Any) -> None:
        # Fail closed: a free-tier run must never reach a priced model.
        if not model.endswith(":free"):
            raise ModelError(f"OpenRouter model must be a ':free' model, got: {model}")
        super().__init__(model, api_key, **kwargs)

    def _build_request(
        self, system: str, messages: list[dict[str, str]]
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        chat = [{"role": "system", "content": system}] if system else []
        for msg in messages:
            role = "assistant" if msg["role"] == "model" else msg["role"]
            chat.append({"role": role, "content": msg["text"]})

        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        return url, headers, {
            "model": self.model,
            "messages": chat,
            "temperature": 0,
            "max_tokens": 16384,
        }

    def _embedded_error(self, data: dict[str, Any]) -> tuple[int, str] | None:
        # OpenRouter can answer 200 with an upstream provider's error in the body.
        error = data.get("error")
        if not error:
            return None
        code = error.get("code") if isinstance(error, dict) else None
        return (code if isinstance(code, int) else 502), json.dumps(error)

    def _parse_reply(self, data: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        text = ""
        finish_reason = ""
        choices = data.get("choices", [])
        if choices:
            choice = choices[0]
            finish_reason = choice.get("finish_reason") or ""
            text = (choice.get("message") or {}).get("content") or ""

        # The agent loop totals usage under Gemini's field names.
        raw = data.get("usage") or {}
        usage = {
            "promptTokenCount": raw.get("prompt_tokens", 0),
            "candidatesTokenCount": raw.get("completion_tokens", 0),
            "totalTokenCount": raw.get("total_tokens", 0),
            "thoughtsTokenCount": (raw.get("completion_tokens_details") or {}).get("reasoning_tokens", 0),
        }
        return text, finish_reason, usage
