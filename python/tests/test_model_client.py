"""Unit tests for GeminiClient and model client utilities."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from hermetic_slice.model_client import (
    GeminiClient,
    ModelError,
    ModelReply,
    PostResult,
    load_api_key,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "model"


def test_model_client_parses_real_fixture() -> None:
    fixture_path = FIXTURES_DIR / "gemma-4-31b-it_generate.json"
    fixture_data = json.loads(fixture_path.read_text(encoding="utf-8"))
    cand_resp = fixture_data["with_systemInstruction"]["response"]
    body_bytes = json.dumps(cand_resp).encode("utf-8")

    captured_req: dict = {}

    def fake_post(url: str, headers: dict[str, str], body: bytes, timeout: float = 300):
        captured_req["url"] = url
        captured_req["headers"] = headers
        captured_req["body"] = json.loads(body.decode("utf-8"))
        return PostResult(200, body_bytes)

    fake_key = "fake-gemini-key-12345"
    client = GeminiClient("gemma-4-31b-it", fake_key, http_post=fake_post)

    reply = client.generate(
        system="You are a terse assistant.",
        messages=[{"role": "user", "text": "Print READY"}],
    )

    assert isinstance(reply, ModelReply)
    assert reply.text == "```bash\necho READY\n```"
    assert reply.finish_reason == "STOP"
    assert reply.usage.get("promptTokenCount") == 25
    assert reply.usage.get("totalTokenCount") == 144
    assert reply.attempts == 1

    # Verify request body and headers
    assert fake_key not in captured_req["url"]
    assert captured_req["headers"]["x-goog-api-key"] == fake_key
    assert "systemInstruction" in captured_req["body"]
    assert captured_req["body"]["systemInstruction"]["parts"][0]["text"] == "You are a terse assistant."
    assert captured_req["body"]["contents"][0]["role"] == "user"
    assert captured_req["body"]["contents"][0]["parts"][0]["text"] == "Print READY"


def test_model_client_retry_500_then_200() -> None:
    fake_key = "secret-key-999"
    sleep_calls: list[float] = []

    def fake_sleep(d: float) -> None:
        sleep_calls.append(d)

    call_count = 0
    resp_body = json.dumps({
        "candidates": [{"content": {"parts": [{"text": "success"}]}, "finishReason": "STOP"}],
        "usageMetadata": {"totalTokenCount": 10},
    }).encode("utf-8")

    def fake_post(url: str, headers: dict[str, str], body: bytes, timeout: float = 300):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return (500, b'{"error": "Internal Server Error"}')
        return (200, resp_body)

    client = GeminiClient("gemma-4-31b-it", fake_key, http_post=fake_post, sleep=fake_sleep)
    reply = client.generate(system="", messages=[{"role": "user", "text": "hi"}])

    assert reply.text == "success"
    assert reply.attempts == 3
    assert sleep_calls == [5.0, 10.0]


def test_model_client_retry_exhausted_raises_scrubbed_error() -> None:
    fake_key = "super-secret-key-xyz"
    sleep_calls: list[float] = []

    def fake_sleep(d: float) -> None:
        sleep_calls.append(d)

    def fake_post(url: str, headers: dict[str, str], body: bytes, timeout: float = 300):
        # Simulate server error mentioning the key
        return (503, f"Service unavailable for key {fake_key}".encode("utf-8"))

    client = GeminiClient(
        "gemma-4-31b-it",
        fake_key,
        http_post=fake_post,
        sleep=fake_sleep,
        max_attempts=3,
    )

    with pytest.raises(ModelError) as exc_info:
        client.generate(system="", messages=[{"role": "user", "text": "hi"}])

    err_msg = str(exc_info.value)
    assert fake_key not in err_msg
    assert "[REDACTED]" in err_msg
    assert exc_info.value.status == 503
    assert len(sleep_calls) == 2
    assert sleep_calls == [5.0, 10.0]


def test_load_api_key_missing_env_var() -> None:
    with pytest.raises(ModelError) as exc_info:
        load_api_key({})
    assert "HERMETIC_GEMINI_KEY_FILE" in str(exc_info.value)


def test_load_api_key_nonexistent_file(tmp_path: Path) -> None:
    fake_path = tmp_path / "does_not_exist.key"
    with pytest.raises(ModelError) as exc_info:
        load_api_key({"HERMETIC_GEMINI_KEY_FILE": str(fake_path)})
    assert str(fake_path) in str(exc_info.value)


def test_load_api_key_valid_file(tmp_path: Path) -> None:
    key_file = tmp_path / "gemini.key"
    key_file.write_text("  my-gemini-api-key  \n", encoding="utf-8")
    loaded = load_api_key({"HERMETIC_GEMINI_KEY_FILE": str(key_file)})
    assert loaded == "my-gemini-api-key"


def test_load_api_key_empty_file(tmp_path: Path) -> None:
    key_file = tmp_path / "empty.key"
    key_file.write_text("   \n", encoding="utf-8")
    with pytest.raises(ModelError) as exc_info:
        load_api_key({"HERMETIC_GEMINI_KEY_FILE": str(key_file)})
    assert "empty" in str(exc_info.value).lower()
