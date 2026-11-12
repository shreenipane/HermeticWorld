"""Comprehensive offline tests for hermetic_grader_records."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from hermetic_grader_records.plugin import (
    ENV_RESULT_FD,
    HermeticResultPlugin,
    PluginError,
)
from hermetic_grader_records.record import (
    EndRecord,
    FinishRecord,
    HEADER_STRUCT,
    MAGIC,
    MAX_NODEID_LEN,
    MAX_RECORD,
    READ_CHUNK_SIZE,
    RecordError,
    RecordType,
    StartRecord,
    StreamEncoder,
    decode_stream,
    encode_end,
    encode_finish,
    encode_record,
    encode_start,
)
from hermetic_grader_records.supervisor import (
    UnsafeFileError,
    evaluate_stream,
    read_results,
    read_results_from_file,
    read_results_json,
    write_report_atomic,
)


def _build_valid_three_record_stream() -> bytes:
    enc = StreamEncoder()
    return (
        MAGIC
        + enc.start("test_sample.py::test_alpha")
        + enc.finish("test_sample.py::test_alpha", "passed", 12)
        + enc.end()
    )


class _ChunkTrackingReader(io.RawIOBase):
    """Binary stream wrapper recording all read sizes and enforcing chunk limits."""

    def __init__(self, data: bytes) -> None:
        self._buf = io.BytesIO(data)
        self.read_sizes: list[int] = []

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self._buf.read(size)


class TestEncoderDecoder:
    def test_round_trip_multiple_outcomes_and_empty_stream(self) -> None:
        enc = StreamEncoder()
        stream = b"".join(
            [
                MAGIC,
                enc.start("t.py::test_pass"),
                enc.finish("t.py::test_pass", "passed", 5),
                enc.start("t.py::test_fail"),
                enc.finish("t.py::test_fail", "failed", 17),
                enc.start("t.py::test_skip"),
                enc.finish("t.py::test_skip", "skipped", 0),
                enc.start("t.py::test_err[param-ü]"),
                enc.finish("t.py::test_err[param-ü]", "error", 42),
                enc.end(),
            ]
        )

        records = decode_stream(io.BytesIO(stream))
        assert records == [
            StartRecord(seq=0, nodeid="t.py::test_pass"),
            FinishRecord(seq=1, nodeid="t.py::test_pass", outcome="passed", duration_ms=5),
            StartRecord(seq=2, nodeid="t.py::test_fail"),
            FinishRecord(seq=3, nodeid="t.py::test_fail", outcome="failed", duration_ms=17),
            StartRecord(seq=4, nodeid="t.py::test_skip"),
            FinishRecord(seq=5, nodeid="t.py::test_skip", outcome="skipped", duration_ms=0),
            StartRecord(seq=6, nodeid="t.py::test_err[param-ü]"),
            FinishRecord(seq=7, nodeid="t.py::test_err[param-ü]", outcome="error", duration_ms=42),
            EndRecord(count=8),
        ]

        # Empty valid session (0 tests)
        empty_enc = StreamEncoder()
        empty_stream = MAGIC + empty_enc.end()
        assert decode_stream(io.BytesIO(empty_stream)) == [EndRecord(count=0)]

    def test_truncated_at_every_byte_offset_of_valid_three_record_stream(self) -> None:
        valid = _build_valid_three_record_stream()
        full = decode_stream(io.BytesIO(valid))
        assert len(full) == 3

        # Cutting at EVERY byte offset 0 .. len(valid) - 1 must raise RecordError
        for offset in range(len(valid)):
            truncated = valid[:offset]
            with pytest.raises(RecordError):
                decode_stream(io.BytesIO(truncated))

    def test_bounded_chunk_reads_and_oversized_cap_before_allocation(self) -> None:
        large_nodeid = "a" * MAX_NODEID_LEN
        enc = StreamEncoder()
        records_bytes = [MAGIC]
        for i in range(16):
            nid = f"{i:02d}_" + large_nodeid[:-3]
            records_bytes.append(enc.start(nid))
            records_bytes.append(enc.finish(nid, "passed", i))
        records_bytes.append(enc.end())
        stream = b"".join(records_bytes)

        tracker = _ChunkTrackingReader(stream)
        decoded = decode_stream(tracker)  # type: ignore[arg-type]
        assert len(decoded) == 33
        assert all(0 < sz <= READ_CHUNK_SIZE for sz in tracker.read_sizes)

        # Oversized payload header (MAX_RECORD + 1) must reject immediately without reading payload
        oversized_header = MAGIC + HEADER_STRUCT.pack(RecordType.START, MAX_RECORD + 1)
        huge_tracker = _ChunkTrackingReader(oversized_header + b"x" * 1024)
        with pytest.raises(RecordError, match="MAX_RECORD"):
            decode_stream(huge_tracker)  # type: ignore[arg-type]
        assert huge_tracker.read_sizes == [4, 5]

        # Encoder also rejects oversized payload > MAX_RECORD
        with pytest.raises(RecordError, match="MAX_RECORD"):
            encode_record(RecordType.START, b"{" + b" " * MAX_RECORD + b"}")

    @pytest.mark.parametrize(
        "bad_stream",
        [
            b"",
            b"HGR",
            b"HGR0" + encode_end(0),
            b"NOPE" + encode_end(0),
            MAGIC + encode_end(0) + b"\x00",
        ],
    )
    def test_bad_magic_and_trailing_data(self, bad_stream: bytes) -> None:
        with pytest.raises(RecordError):
            decode_stream(io.BytesIO(bad_stream))

    @pytest.mark.parametrize("bad_type", [0, 4, 99, 255])
    def test_unknown_record_type(self, bad_type: int) -> None:
        payload = b'{"count":0}'
        raw = MAGIC + HEADER_STRUCT.pack(bad_type, len(payload)) + payload
        with pytest.raises(RecordError, match="Unknown record type"):
            decode_stream(io.BytesIO(raw))

    def test_invalid_utf8_and_invalid_json(self) -> None:
        bad_utf8 = b'\xff\xfe{"count":0}'
        raw_utf8 = MAGIC + HEADER_STRUCT.pack(RecordType.END, len(bad_utf8)) + bad_utf8
        with pytest.raises(RecordError, match="UTF-8"):
            decode_stream(io.BytesIO(raw_utf8))

        bad_json_payloads = [
            b"{broken",
            b'{"count":0}trailing',
            b"[1, 2, 3]",
            b'"just a string"',
            b"123",
            b"null",
            b'{"count":NaN}',
            b'{"count":0,"count":1}',
        ]
        for payload in bad_json_payloads:
            raw = MAGIC + HEADER_STRUCT.pack(RecordType.END, len(payload)) + payload
            with pytest.raises(RecordError):
                decode_stream(io.BytesIO(raw))

    @pytest.mark.parametrize(
        "raw_payload_record",
        [
            encode_record(RecordType.START, b'{"seq":"0","nodeid":"t"}'),
            encode_record(RecordType.START, b'{"seq":true,"nodeid":"t"}'),
            encode_record(RecordType.START, b'{"seq":-1,"nodeid":"t"}'),
            encode_record(RecordType.START, b'{"seq":0,"nodeid":123}'),
            encode_record(RecordType.START, b'{"seq":0,"nodeid":""}'),
            encode_record(
                RecordType.FINISH,
                b'{"seq":1,"nodeid":"t","outcome":"xfail","duration_ms":1}',
            ),
            encode_record(
                RecordType.FINISH,
                b'{"seq":1,"nodeid":"t","outcome":"passed","duration_ms":true}',
            ),
            encode_record(
                RecordType.FINISH,
                b'{"seq":1,"nodeid":"t","outcome":"passed","duration_ms":-5}',
            ),
            encode_record(RecordType.END, b'{"count":true}'),
            encode_record(RecordType.END, b'{"count":-1}'),
            encode_record(RecordType.START, b'{"seq":0,"nodeid":"t","extra":1}'),
            encode_record(RecordType.START, b'{"seq":0}'),
            encode_record(
                RecordType.FINISH,
                b'{"seq":1,"nodeid":"t","outcome":"passed","duration_ms":1,"extra":2}',
            ),
            encode_record(
                RecordType.FINISH,
                b'{"seq":1,"nodeid":"t","outcome":"passed"}',
            ),
            encode_record(RecordType.END, b'{"count":0,"extra":1}'),
            encode_record(RecordType.END, b"{}"),
        ],
    )
    def test_wrong_field_types_and_extra_or_missing_fields(
        self, raw_payload_record: bytes
    ) -> None:
        prefix = b""
        if raw_payload_record[0] == RecordType.FINISH:
            prefix = encode_start(0, "t")
        stream = MAGIC + prefix + raw_payload_record
        with pytest.raises(RecordError):
            decode_stream(io.BytesIO(stream))

    def test_sequence_and_state_machine_errors(self) -> None:
        # seq out of order at start
        s1 = MAGIC + encode_start(1, "a") + encode_finish(2, "a", "passed", 1) + encode_end(3)
        with pytest.raises(RecordError, match="sequence"):
            decode_stream(io.BytesIO(s1))

        # seq gap between START and FINISH
        s2 = MAGIC + encode_start(0, "a") + encode_finish(2, "a", "passed", 1) + encode_end(3)
        with pytest.raises(RecordError, match="sequence"):
            decode_stream(io.BytesIO(s2))

        # FINISH without matching START (at stream start)
        s3 = MAGIC + encode_finish(0, "a", "passed", 1) + encode_end(1)
        with pytest.raises(RecordError, match="FINISH without matching START"):
            decode_stream(io.BytesIO(s3))

        # FINISH with mismatched nodeid
        s4 = MAGIC + encode_start(0, "a") + encode_finish(1, "b", "passed", 1) + encode_end(2)
        with pytest.raises(RecordError, match="does not match"):
            decode_stream(io.BytesIO(s4))

        # Two STARTs without FINISH
        s5 = (
            MAGIC
            + encode_start(0, "a")
            + encode_start(1, "b")
            + encode_finish(2, "b", "passed", 1)
            + encode_end(3)
        )
        with pytest.raises(RecordError, match="still active"):
            decode_stream(io.BytesIO(s5))

        # Duplicate nodeid
        s6 = (
            MAGIC
            + encode_start(0, "a")
            + encode_finish(1, "a", "passed", 1)
            + encode_start(2, "a")
            + encode_finish(3, "a", "passed", 1)
            + encode_end(4)
        )
        with pytest.raises(RecordError, match="Duplicate nodeid"):
            decode_stream(io.BytesIO(s6))

        # END with wrong count
        s7 = MAGIC + encode_start(0, "a") + encode_finish(1, "a", "passed", 1) + encode_end(1)
        with pytest.raises(RecordError, match="count"):
            decode_stream(io.BytesIO(s7))


class TestSupervisorAndSafeFiles:
    def test_supervisor_valid_prefix_on_stream_error_and_unexpected_nodeids(self) -> None:
        enc = StreamEncoder()
        valid_prefix = (
            MAGIC
            + enc.start("test_a.py::test_1")
            + enc.finish("test_a.py::test_1", "passed", 3)
            + enc.start("test_extra.py::test_unlisted")
            + enc.finish("test_extra.py::test_unlisted", "passed", 2)
        )
        corrupt_stream = valid_prefix + b"\x99\x05\x00\x00\x00hello"

        expected = ["test_a.py::test_1", "test_a.py::test_2", "test_a.py::test_3"]
        report = evaluate_stream(io.BytesIO(corrupt_stream), expected)

        assert report.outcomes == {
            "test_a.py::test_1": "passed",
            "test_a.py::test_2": "failed",
            "test_a.py::test_3": "failed",
        }
        assert report.unexpected == ["test_extra.py::test_unlisted"]
        assert report.unexpected_count == 1
        assert report.error is not None
        assert read_results(io.BytesIO(corrupt_stream), expected) == report.outcomes

    def test_determinism_and_no_host_leaks(self, tmp_path: Path) -> None:
        enc = StreamEncoder()
        stream = (
            MAGIC
            + enc.start("b.py::test_2")
            + enc.finish("b.py::test_2", "failed", 9)
            + enc.start("a.py::test_1")
            + enc.finish("a.py::test_1", "passed", 4)
            + enc.start("u2.py::test_z")
            + enc.finish("u2.py::test_z", "passed", 1)
            + enc.start("u1.py::test_a")
            + enc.finish("u1.py::test_a", "skipped", 1)
            + enc.end()
        )

        json_a = read_results_json(
            io.BytesIO(stream), ["b.py::test_2", "a.py::test_1", "c.py::test_missing"]
        )
        json_b = read_results_json(
            io.BytesIO(stream), ["c.py::test_missing", "a.py::test_1", "b.py::test_2"]
        )
        assert json_a == json_b

        parsed = json.loads(json_a)
        assert list(parsed.keys()) == ["error", "outcomes", "unexpected", "unexpected_count"]
        assert list(parsed["outcomes"].keys()) == [
            "a.py::test_1",
            "b.py::test_2",
            "c.py::test_missing",
        ]
        assert parsed["unexpected"] == ["u1.py::test_a", "u2.py::test_z"]
        assert str(tmp_path) not in json_a

    def test_refuses_symlinks_fifos_devices_and_writes_atomically(self, tmp_path: Path) -> None:
        valid_bytes = _build_valid_three_record_stream()
        regular_file = tmp_path / "results.bin"
        regular_file.write_bytes(valid_bytes)

        rep = read_results_from_file(regular_file, ["test_sample.py::test_alpha"])
        assert rep.outcomes == {"test_sample.py::test_alpha": "passed"}

        symlink_file = tmp_path / "symlink_results.bin"
        symlink_file.symlink_to(regular_file)
        with pytest.raises(UnsafeFileError):
            read_results_from_file(symlink_file, ["test_sample.py::test_alpha"])

        fifo_file = tmp_path / "fifo_results.bin"
        os.mkfifo(fifo_file)
        with pytest.raises(UnsafeFileError):
            read_results_from_file(fifo_file, ["test_sample.py::test_alpha"])

        if os.path.exists("/dev/null"):
            with pytest.raises(UnsafeFileError):
                read_results_from_file("/dev/null", ["test_sample.py::test_alpha"])

        out_report = tmp_path / "report.json"
        write_report_atomic(out_report, rep)
        assert out_report.is_file() and not out_report.is_symlink()
        assert out_report.read_text(encoding="utf-8") == rep.to_json()
        leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".tmp.hgr.")]
        assert leftovers == []

        symlink_out = tmp_path / "symlink_report.json"
        symlink_out.symlink_to(out_report)
        with pytest.raises(UnsafeFileError):
            write_report_atomic(symlink_out, rep)


class TestPytestPluginSubprocess:
    def test_real_pytest_subprocess_outcomes_fake_summary_and_os_exit(
        self, tmp_path: Path
    ) -> None:
        test_file = tmp_path / "test_suite.py"
        test_file.write_text(
            """
import errno
import os
import pytest


@pytest.fixture
def broken_setup():
    raise RuntimeError("setup boom")


@pytest.fixture
def broken_teardown():
    yield
    raise RuntimeError("teardown boom")


def test_01_pass():
    assert 1 + 1 == 2


def test_02_fail():
    assert 1 == 2


@pytest.mark.skip(reason="explicit skip")
def test_03_skip():
    assert True


def test_04_setup_error(broken_setup):
    assert True


def test_05_teardown_error(broken_teardown):
    assert True


@pytest.mark.xfail(reason="known bug")
def test_06_xfail():
    assert False


@pytest.mark.xfail(strict=False, reason="unexpectedly passes")
def test_07_xpass():
    assert True


def test_08_fake_summary_and_closed_orig_fd(capsys):
    assert "HERMETIC_RESULT_FD" not in os.environ
    for probe_fd in (3, 4, 5):
        try:
            st = os.fstat(probe_fd)
        except OSError as exc:
            assert exc.errno == errno.EBADF
    print("\\n========================= 99 passed in 0.01s =========================")
    assert False, "real failure despite fake summary"


def test_09_crash_os_exit():
    os._exit(0)


def test_10_never_reached():
    assert True
""".lstrip(),
            encoding="utf-8",
        )

        r_fd, w_fd = os.pipe()
        repo_root = Path(__file__).resolve().parent.parent
        env = os.environ.copy()
        env[ENV_RESULT_FD] = str(w_fd)
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            f"{repo_root}{os.pathsep}{existing_pp}" if existing_pp else str(repo_root)
        )

        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "hermetic_grader_records.plugin",
                str(test_file),
            ],
            cwd=str(tmp_path),
            env=env,
            pass_fds=(w_fd,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(w_fd)

        try:
            with os.fdopen(r_fd, "rb") as pipe_reader:
                expected = [
                    "test_suite.py::test_01_pass",
                    "test_suite.py::test_02_fail",
                    "test_suite.py::test_03_skip",
                    "test_suite.py::test_04_setup_error",
                    "test_suite.py::test_05_teardown_error",
                    "test_suite.py::test_06_xfail",
                    "test_suite.py::test_07_xpass",
                    "test_suite.py::test_08_fake_summary_and_closed_orig_fd",
                    "test_suite.py::test_09_crash_os_exit",
                    "test_suite.py::test_10_never_reached",
                ]
                outcomes = read_results(pipe_reader, expected)
        finally:
            stdout_bytes, _ = proc.communicate(timeout=15)

        assert proc.returncode == 0
        assert b"99 passed" in stdout_bytes
        assert outcomes == {
            "test_suite.py::test_01_pass": "passed",
            "test_suite.py::test_02_fail": "failed",
            "test_suite.py::test_03_skip": "skipped",
            "test_suite.py::test_04_setup_error": "error",
            "test_suite.py::test_05_teardown_error": "error",
            "test_suite.py::test_06_xfail": "failed",
            "test_suite.py::test_07_xpass": "failed",
            "test_suite.py::test_08_fake_summary_and_closed_orig_fd": "failed",
            "test_suite.py::test_09_crash_os_exit": "failed",
            "test_suite.py::test_10_never_reached": "missing",
        }

    def test_fd_identity_change_stops_writing(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test_tamper.py"
        test_file.write_text(
            """
import os
import stat


def test_1_before_tamper():
    assert True


def test_2_tamper_fd():
    devnull = os.open("/dev/null", os.O_WRONLY)
    for candidate in range(64, 1024):
        if candidate == devnull:
            continue
        try:
            st = os.fstat(candidate)
        except OSError:
            continue
        if stat.S_ISFIFO(st.st_mode):
            os.dup2(devnull, candidate)
    os.close(devnull)
    assert True


def test_3_after_tamper():
    assert True
""".lstrip(),
            encoding="utf-8",
        )

        r_fd, w_fd = os.pipe()
        repo_root = Path(__file__).resolve().parent.parent
        env = os.environ.copy()
        env[ENV_RESULT_FD] = str(w_fd)
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            f"{repo_root}{os.pathsep}{existing_pp}" if existing_pp else str(repo_root)
        )

        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "hermetic_grader_records.plugin",
                str(test_file),
            ],
            cwd=str(tmp_path),
            env=env,
            pass_fds=(w_fd,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(w_fd)

        try:
            with os.fdopen(r_fd, "rb") as pipe_reader:
                expected = [
                    "test_tamper.py::test_1_before_tamper",
                    "test_tamper.py::test_2_tamper_fd",
                    "test_tamper.py::test_3_after_tamper",
                ]
                outcomes = read_results(pipe_reader, expected)
        finally:
            proc.communicate(timeout=15)

        assert outcomes == {
            "test_tamper.py::test_1_before_tamper": "passed",
            "test_tamper.py::test_2_tamper_fd": "failed",
            "test_tamper.py::test_3_after_tamper": "missing",
        }

    def test_plugin_direct_unit_fd_identity_check_and_invalid_env(self) -> None:
        with pytest.raises(PluginError):
            HermeticResultPlugin(orig_fd=1)

        r_fd, w_fd = os.pipe()
        try:
            plugin = HermeticResultPlugin(w_fd)
            assert not plugin.disabled

            with pytest.raises(OSError):
                os.fstat(w_fd)

            devnull = os.open("/dev/null", os.O_WRONLY)
            try:
                os.dup2(devnull, plugin.fd)
            finally:
                os.close(devnull)

            assert plugin._write_checked(encode_end(0)) is False
            assert plugin.disabled is True
            plugin._close_stream()
        finally:
            os.close(r_fd)
