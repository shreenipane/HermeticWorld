"""D12 real-date sentinel (TR-SEC-5) in the Mode H harness: prompts and observations."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import hermetic_slice.runner as runner
from hermetic_slice.agent_loop import Limits, run_agent
from hermetic_slice.date_sentinel import DateSentinel, SentinelSummary, decode_escapes, merge_summaries
from hermetic_slice.model_client import ModelReply

REAL = dt.date(2030, 6, 15)


def _sentinel(**kw: Any) -> DateSentinel:
    return DateSentinel(REAL, host_names=["buildhost-7"], host_paths=["/srv/hostonly"], **kw)


@pytest.mark.parametrize("text", [
    "2030-06-15", "2030/06/15", "20300615", "06/15/2030", "15.06.2030", "15-06-2030",
    "Jun 15, 2030", "June 15th 2030", "15 June 2030", "Sat, 15 Jun 2030 10:00:00 GMT",
    "2030-06-14", "2030-06-16",
    str(int(dt.datetime(2030, 6, 15, 12, tzinfo=dt.timezone.utc).timestamp())),
    str(int(dt.datetime(2030, 6, 15, 12, tzinfo=dt.timezone.utc).timestamp()) * 1000),
])
def test_real_date_formats_detected(text: str) -> None:
    s = _sentinel()
    s.scan_text("observation", f"x {text} y")
    assert s.summary().hits.get("observation:real_date", 0) >= 1, text


@pytest.mark.parametrize("text", ["2030-06-17", "2026-11-11", "120300615", "2030-13-45", "build 1234567890"])
def test_out_of_window_not_detected(text: str) -> None:
    s = _sentinel()
    s.scan_text("observation", text)
    assert not s.summary().date_leak_observed, text


@pytest.mark.parametrize("text", [
    "2030\\u002d06\\u002d15", "2030%2D06%2D15", "06\\/15\\/2030", "2030&#45;06&#x2d;15",
    "２０３０-０６-１５", "2030−06−15",
])
def test_encoded_dates_detected(text: str) -> None:
    s = _sentinel()
    s.scan_text("observation", text)
    assert s.summary().date_leak_observed, text


def test_decode_escapes_unchanged_is_none() -> None:
    assert decode_escapes("plain text") is None


def test_host_name_and_path_counted_without_echo() -> None:
    s = _sentinel()
    s.scan_text("observation", "on BUILDHOST-7 at /srv/hostonly/x; not buildhost-77")
    d = s.summary().to_dict()
    assert d["hits"] == {"observation:host_name": 1, "observation:host_path": 1}
    blob = json.dumps(d) + repr(s)
    assert "buildhost" not in blob.lower() and "hostonly" not in blob


def test_bytes_input_scanned() -> None:
    s = _sentinel()
    s.scan_text("observation", b"\xff\xfe 2030-06-15")
    assert s.summary().date_leak_observed


def test_stream_split_across_chunks_counted_once() -> None:
    s = _sentinel()
    st = s.stream("observation")
    for chunk in ["log 2030-0", "6-15 then", " more", " text"]:
        st.feed(chunk)
    assert s.summary().hits == {"observation:real_date": 1}


def test_byte_cap_fails_closed() -> None:
    s = _sentinel(max_chars=10)
    s.scan_text("observation", "short")
    assert not s.summary().date_leak_observed
    s.scan_text("observation", "pushes past the cap")
    sm = s.summary()
    assert sm.scan_incomplete and sm.date_leak_observed
    assert sm.incomplete == {"observation:run_byte_cap": 1}


def test_option_caps_refused() -> None:
    with pytest.raises(ValueError):
        DateSentinel(REAL, host_names=["h"] * 10_001)
    with pytest.raises(ValueError):
        DateSentinel(REAL, host_paths=["/" + "a" * 5000])


def test_merge_fails_closed_on_missing_or_malformed() -> None:
    clean = SentinelSummary().to_dict()
    assert merge_summaries([clean, clean])["date_leak_observed"] is False
    assert merge_summaries([clean, None])["date_leak_observed"] is True
    assert merge_summaries([clean, {"date_leak_observed": "no"}])["date_leak_observed"] is True
    gw = {"date_leak_observed": True, "scan_incomplete": False,
          "hits": {"upstream_stream:real_date": 2}, "incomplete": {}, "bytes_scanned": 9}
    m = merge_summaries([clean, gw])
    assert m["date_leak_observed"] is True and m["hits"] == {"upstream_stream:real_date": 2}


class _Model:
    model = "fake"

    def __init__(self, replies: list[str]) -> None:
        self.replies = list(replies)

    def generate(self, system: str, messages: list[dict[str, str]]) -> ModelReply:
        return ModelReply(text=self.replies.pop(0), finish_reason="STOP",
                          usage={"totalTokenCount": 1}, latency_s=0.0, attempts=1)


def test_agent_loop_scans_observations_before_truncation() -> None:
    s = _sentinel()
    # The date sits in the middle of the output, inside the part the truncation elides.
    output = "a" * 5000 + " 2030-06-15 " + "b" * 5000
    model = _Model(["```bash\nls\n```", "```bash\necho HERMETIC_SUBMIT\n```"])
    run_agent(model, lambda c, t: (0, output), "fix it",
              limits=Limits(max_output_chars=100), sentinel=s)
    assert s.summary().hits == {"observation:real_date": 1}


def test_agent_loop_scans_prompts_and_format_error_turns() -> None:
    s = _sentinel()
    model = _Model(["no block", "```bash\necho HERMETIC_SUBMIT\n```"])
    run_agent(model, lambda c, t: (0, ""), "As of 15 June 2030 on buildhost-7", sentinel=s)
    hits = s.summary().hits
    assert hits.get("prompt:real_date") == 1 and hits.get("prompt:host_name") == 1


def test_agent_loop_clean_run_not_flagged() -> None:
    s = _sentinel()
    model = _Model(["```bash\nls\n```", "```bash\necho HERMETIC_SUBMIT\n```"])
    run_agent(model, lambda c, t: (0, "file.py 2020-01-01"), "fix it", sentinel=s)
    assert not s.summary().date_leak_observed


def _task_dir(tmp_path: Path) -> Path:
    task_dir = tmp_path / "x__y-1"
    (task_dir / "agent").mkdir(parents=True)
    (task_dir / "index").mkdir()
    (task_dir / "world").mkdir()
    (task_dir / "task.json").write_text(json.dumps({"instance_id": "x__y-1", "base_commit": "abc"}), encoding="utf-8")
    (task_dir / "agent" / "problem_statement.md").write_text("fix it", encoding="utf-8")
    (task_dir / "index" / "index-report.json").write_text("{}", encoding="utf-8")
    (task_dir / "world" / "probe.json").write_text('{"all_ok": true}', encoding="utf-8")
    return task_dir


@pytest.mark.parametrize("output,extra,expected", [
    ("clean 2020-01-01", None, False),
    ("leak 2030-06-15", None, True),
    ("clean", [{"date_leak_observed": True, "scan_incomplete": False,
                "hits": {"agent_request:real_date": 1}, "incomplete": {}, "bytes_scanned": 1}], True),
    ("clean", [{"bogus": 1}], True),
])
def test_run_record_date_leak_observed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                       output: str, extra: Any, expected: bool) -> None:
    monkeypatch.setattr(runner, "start_world", lambda *a, **k: SimpleNamespace(agent_container="c"))
    monkeypatch.setattr(runner, "world_exec", lambda *a, **k: (0, output))
    monkeypatch.setattr(runner, "stop_world", lambda w: None)
    monkeypatch.setattr(runner, "extract_patch", lambda *a, **k: ("", {"files_changed": 0}))
    monkeypatch.setattr(runner, "run_docker", lambda *a, **k: b"sha256:x")
    model = _Model(["```bash\nls\n```", "```bash\necho HERMETIC_SUBMIT\n```"])
    record = runner.run_task(
        _task_dir(tmp_path), model=model, grade_fn=lambda *a, **k: {"status": "ok"},
        run_dir=tmp_path / "run", limits=Limits(max_steps=3), sentinel=_sentinel(),
        extra_sentinel_summaries=extra,
    )
    assert record["date_leak_observed"] is expected
    assert record["date_sentinel"]["date_leak_observed"] is expected
    saved = json.loads((tmp_path / "run" / "run.json").read_text(encoding="utf-8"))
    assert saved["date_leak_observed"] is expected
    assert "2030-06-15" not in json.dumps(saved["date_sentinel"])


def test_default_sentinel_uses_today(monkeypatch: pytest.MonkeyPatch) -> None:
    s = runner._default_sentinel()
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    s.scan_text("observation", today)
    assert s.summary().date_leak_observed
