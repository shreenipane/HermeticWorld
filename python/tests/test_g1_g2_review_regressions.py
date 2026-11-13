"""Security regressions for record framing, file access, and assertion dependencies."""

from __future__ import annotations

import io
import json
import os
import stat

import pytest

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.flow import analyze_flow
from hermetic_assert_flow.cli import run_cli
from hermetic_assert_flow.io_utils import atomic_write_bytes, read_regular_file_bounded
from hermetic_grader_records.plugin import PluginError, _parse_env_fd
from hermetic_grader_records import record, supervisor
import hermetic_safe_io as safe_io


def _flow(body, raising=2):
    return analyze_flow(("def test_case(flag):\n" + body).encode(), "test_case", raising)


@pytest.mark.parametrize("body", [
    '    cfg = {"clean": 42}\n    cfg["bad"] = boom()\n    assert cfg["clean"] == 42\n',
    '    cfg = Config()\n    cfg.bad = boom()\n    assert cfg.clean == 42\n',
])
def test_independent_fields_are_not_eligible(body):
    assert _flow(body, raising=3).eligible == []


def test_exact_stored_field_remains_eligible():
    result = _flow('    cfg = {}\n    cfg["bad"] = boom()\n    assert cfg["bad"] == 1\n', 3)
    assert result.eligible == ["test_case#0"]


@pytest.mark.parametrize("conditional", ["False", "flag"])
def test_branch_requires_dependency_on_all_paths(conditional):
    body = f'    x = boom()\n    y = 42\n    if {conditional}:\n        y = x\n    assert y == 42\n'
    assert _flow(body).eligible == []


@pytest.mark.parametrize("assignment,expected", [
    ("x, y = y, x", ["test_case#0"]),
    ("y, x = x, y", ["test_case#0"]),
    ("(x, (y, z)) = (y, (x, x))", ["test_case#0"]),
])
def test_unpack_rhs_uses_original_state(assignment, expected):
    body = f'    x = 42\n    y = boom()\n    {assignment}\n    assert x == 1\n    assert y == 42\n'
    assert _flow(body, 3).eligible == expected


@pytest.mark.parametrize("statement", ["x = boom(); y = 42", "x = boom(); assert True"])
def test_ambiguous_raising_line_gives_up(statement):
    result = _flow(f'    {statement}\n    assert y == 42\n')
    assert result.gave_up
    assert result.eligible == []


@pytest.mark.parametrize("control", ["break", "continue"])
def test_unreachable_after_loop_control_is_excluded(control):
    body = f'    x = boom()\n    y = 42\n    for i in [1]:\n        {control}\n        y = x\n    assert y == 42\n'
    assert _flow(body).eligible == []


def test_exhaustive_match_overwrite_clears_dependency():
    assert _flow('    x = boom()\n    match 1:\n        case _:\n            x = 42\n    assert x == 42\n').eligible == []


@pytest.mark.parametrize("expression", ["False and x", "True or x", "42 if True else x", "x if False else 42"])
def test_unreachable_expression_operands_are_excluded(expression):
    assert _flow(f'    x = boom()\n    y = {expression}\n    assert y == 42\n').eligible == []


@pytest.mark.parametrize("statement", ["if (x := boom()):", "(x := boom())"])
def test_raising_walrus_is_seeded_or_explicitly_unsupported(statement):
    body = f'    {statement}\n' + ('        assert x == 1\n' if statement.endswith(":") else '    assert x == 1\n')
    result = _flow(body)
    assert result.gave_up or result.eligible == ["test_case#0"]


@pytest.mark.parametrize("termination", ["return", "raise RuntimeError()"])
def test_finally_assertions_after_termination(termination):
    result = _flow(f'    x = boom()\n    try:\n        {termination}\n    finally:\n        assert x == 1\n')
    assert result.eligible == ["test_case#0"]


@pytest.mark.parametrize("raw", ["²", "١", "１２"])
def test_ascii_decimal_input_errors(raw, capsys, monkeypatch):
    import hermetic_assert_flow.cli as cli
    def forbidden(*args, **kwargs):
        pytest.fail("file read before numeric input validation")
    monkeypatch.setattr(cli, "read_regular_file_bounded", forbidden)
    with pytest.raises(PluginError):
        _parse_env_fd(raw)
    assert run_cli(["--file", "unused", "--function", "test_case", "--raising-line", raw]) == 1
    assert "Traceback" not in capsys.readouterr().err


def test_unknown_cli_argument_does_not_disclose_secret(capsys):
    assert run_cli(["--file", "unused", "--function", "test_case", "--raising-line", "1", "/private/TOKEN_SENTINEL"]) == 1
    assert "TOKEN_SENTINEL" not in capsys.readouterr().err


def test_supervisor_consumes_end_and_rejects_trailing_data():
    enc = record.StreamEncoder()
    stream = record.MAGIC + enc.start("t") + enc.finish("t", "passed", 0) + enc.end()
    for tail in (b"garbage", record.encode_end(2)):
        report = supervisor.evaluate_stream(io.BytesIO(stream + tail), ["t"])
        assert report.error is not None


def test_record_json_depth_is_bounded():
    for opening, closing in ((b"[", b"]"), (b'{"x":', b"}")):
        payload = opening * 2000 + b"0" + closing * 2000
        stream = record.MAGIC + record.encode_record(record.RecordType.END, payload)
        with pytest.raises(record.RecordError, match="MAX_JSON_DEPTH"):
            record.decode_stream(io.BytesIO(stream))


def test_exact_record_count_boundary():
    enc = record.StreamEncoder()
    parts = [record.MAGIC]
    for i in range(record.MAX_RECORDS // 2):
        nodeid = str(i)
        parts.extend((enc.start(nodeid), enc.finish(nodeid, "passed", 0)))
    parts.append(enc.end())
    decoded = record.decode_stream(io.BytesIO(b"".join(parts)))
    assert decoded[-1] == record.EndRecord(record.MAX_RECORDS)
    with pytest.raises(record.RecordError):
        enc.start("extra")
    over = b"".join(parts[:-1]) + record.encode_start(record.MAX_RECORDS, "extra")
    with pytest.raises(record.RecordError):
        record.decode_stream(io.BytesIO(over))


@pytest.mark.parametrize("fragment", [1, 3, 7])
def test_short_reads_are_valid(fragment):
    class Fragmented(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, fragment))
    enc = record.StreamEncoder()
    stream = record.MAGIC + enc.start("a" * 100) + enc.finish("a" * 100, "passed", 0) + enc.end()
    assert len(record.decode_stream(Fragmented(stream))) == 3


def test_report_cap_applies_to_every_json_api(monkeypatch):
    report = supervisor.SupervisorReport({"😀\\\"" * 300: "passed"}, [])
    exact = len(json.dumps(report.to_dict(), sort_keys=True, indent=2) + "\n")
    monkeypatch.setattr(supervisor, "MAX_REPORT_BYTES", exact)
    assert len(report.to_json()) == exact
    monkeypatch.setattr(supervisor, "MAX_REPORT_BYTES", exact - 1)
    with pytest.raises(supervisor.SupervisorError):
        report.to_json()
    monkeypatch.setattr(supervisor, "MAX_REPORT_BYTES", 128)
    with pytest.raises(supervisor.SupervisorError):
        supervisor.read_results_json(io.BytesIO(record.MAGIC + record.encode_end(0)), ["😀" * 100])


@pytest.mark.parametrize("operation", [supervisor.open_regular_file_ro, lambda p: supervisor.write_report_atomic(p, supervisor.SupervisorReport({}, []))])
def test_nul_paths_rejected_before_filesystem(operation, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("filesystem touched for invalid path")
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(os, "lstat", forbidden)
    with pytest.raises(supervisor.SupervisorError):
        operation("bad\0path")


@pytest.mark.parametrize("depth", [1, 2, 3])
def test_all_ancestor_symlinks_rejected(tmp_path, depth):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "input").write_bytes(b"ok")
    root = tmp_path / "root"
    root.mkdir()
    for i in range(depth - 1):
        root = root / str(i)
        root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    for operation, error in ((read_regular_file_bounded, FlowError), (supervisor.open_regular_file_ro, supervisor.SupervisorError)):
        with pytest.raises(error):
            operation(root / "link" / "input")
    for operation, error in ((lambda p: atomic_write_bytes(p, b"changed"), FlowError), (lambda p: supervisor.write_report_atomic(p, supervisor.SupervisorReport({}, [])), supervisor.SupervisorError)):
        with pytest.raises(error):
            operation(root / "link" / "output")
    assert not (outside / "output").exists()


@pytest.mark.parametrize("kind", ["fifo", "device"])
def test_special_files_are_not_opened_for_reading(tmp_path, monkeypatch, kind):
    target = tmp_path / "fifo"
    if kind == "fifo":
        os.mkfifo(target)
    else:
        target = "/dev/null"
    original = os.open
    def inspected_open(path, flags, *args, **kwargs):
        if os.fspath(path) == os.fspath(target) or os.fspath(path) == "fifo":
            assert flags & os.O_PATH, "special object acquired as readable handle"
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", inspected_open)
    with pytest.raises(FlowError):
        read_regular_file_bounded(target)
    with pytest.raises(supervisor.SupervisorError):
        supervisor.open_regular_file_ro(target)


@pytest.mark.parametrize("writer", [lambda p: atomic_write_bytes(p, b"new"), lambda p: supervisor.write_report_atomic(p, supervisor.SupervisorReport({}, []))])
def test_parent_exchange_does_not_redirect_publication(tmp_path, monkeypatch, writer):
    parent = tmp_path / "parent"
    moved = tmp_path / "moved"
    outside = tmp_path / "outside"
    parent.mkdir()
    outside.mkdir()
    (outside / "output").write_bytes(b"secret")
    original = os.open
    original_lstat = os.lstat
    exchanged = False
    def swap():
        nonlocal exchanged
        parent.rename(moved)
        parent.symlink_to(outside, target_is_directory=True)
        exchanged = True
    def inspect(path, *args, **kwargs):
        result = original_lstat(path, *args, **kwargs)
        if os.fspath(path) == str(parent) and not exchanged:
            swap()
        return result
    monkeypatch.setattr(os, "lstat", inspect)
    def exchange(path, flags, *args, **kwargs):
        nonlocal exchanged
        result = original(path, flags, *args, **kwargs)
        if os.path.basename(os.fspath(path)) == "parent" and flags & os.O_DIRECTORY and not exchanged:
            swap()
        return result
    monkeypatch.setattr(os, "open", exchange)
    writer(parent / "output")
    assert exchanged
    assert (outside / "output").read_bytes() == b"secret"
    assert sorted(p.name for p in outside.iterdir()) == ["output"]
    assert (moved / "output").stat().st_mode & 0o777 == 0o600


def test_unpack_rhs_walrus_evaluated_once_in_order():
    assert _flow('    x = boom()\n    x, y = x, (x := 42)\n    assert x == 1\n    assert y == 42\n').eligible == ["test_case#0"]


def test_short_circuit_assert_call_is_not_evaluated():
    assert _flow('    x = boom()\n    False and self.assertEqual(x, 1)\n').eligible == []


def test_loop_site_requires_dependency_on_each_iteration():
    assert _flow('    x = boom()\n    for i in [1, 2]:\n        assert x == 1\n        x = 42\n').eligible == []


def test_definite_dependencies_survive_branches_and_finite_loops():
    body = ('    x = boom()\n    if flag:\n        y = x\n    else:\n        y = x + 1\n'
            '    assert y == 1\n    for item in [1, 2]:\n        total = y + item\n        assert total > 0\n'
            '    assert total > 0\n')
    assert _flow(body).eligible == ["test_case#0", "test_case#1", "test_case#2"]


@pytest.mark.parametrize("expression", ["[x for i in []]", "[x for i in [1] if False]", "{i: x for i in []}"])
def test_unreachable_comprehension_body_is_excluded(expression):
    assert _flow(f'    x = boom()\n    y = {expression}\n    assert y == []\n').eligible == []


def test_ambiguous_raising_walrus_does_not_seed_old_constant():
    result = _flow('    x = 42\n    if boom() and (x := later()):\n        pass\n    assert x == 42\n', 3)
    assert result.gave_up
    assert result.eligible == []


def test_walrus_in_raising_assignment_seeds_both_targets():
    assert _flow('    y = (x := boom())\n    assert x == 1\n    assert y == 1\n').eligible == ["test_case#0", "test_case#1"]


def test_short_file_reads_and_writes_make_bounded_progress(tmp_path, monkeypatch):
    original_read = os.read
    original_write = os.write
    monkeypatch.setattr(os, "read", lambda fd, count: original_read(fd, min(count, 1)))
    monkeypatch.setattr(os, "write", lambda fd, data: original_write(fd, data[:1]))
    target = tmp_path / "input"
    target.write_bytes(b"x" * 1000)
    assert read_regular_file_bounded(target) == b"x" * 1000
    atomic_write_bytes(tmp_path / "output", b"y" * 1000)
    assert (tmp_path / "output").read_bytes() == b"y" * 1000
    report = supervisor.SupervisorReport({"test": "passed"}, [])
    supervisor.write_report_atomic(tmp_path / "report", report)
    assert (tmp_path / "report").read_text() == report.to_json()


def test_invalid_cli_fields_precede_file_access(monkeypatch, capsys):
    import hermetic_assert_flow.cli as cli
    def forbidden(*args, **kwargs):
        pytest.fail("file read before argument validation")
    monkeypatch.setattr(cli, "read_regular_file_bounded", forbidden)
    for options in (["--function", "bad-name"], ["--reached", ""], ["--output", "bad\0path"]):
        assert run_cli(["--file", "unused", "--function", "test_case", "--raising-line", "2", *options]) == 1
        assert capsys.readouterr().out == ""


@pytest.mark.parametrize("limit,value", [("max_bytes", 1024 * 1024 + 1), ("max_depth", 129), ("max_nodes", 50001), ("max_bytes", None)])
def test_parser_caps_cannot_be_disabled(limit, value):
    from hermetic_assert_flow.parse import parse_source
    with pytest.raises(FlowError):
        parse_source(b"x = 1", **{limit: value})


def test_supervisor_validates_expected_tests_before_open(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("input file opened before validating expected tests")
    monkeypatch.setattr(supervisor, "open_regular_file_ro", forbidden)
    with pytest.raises(supervisor.SupervisorError):
        supervisor.read_results_from_file("unused", [""])


@pytest.mark.parametrize("value", [None, 123, "site"])
def test_reached_site_sequence_type_is_validated(value):
    with pytest.raises(FlowError):
        analyze_flow(b"def test_case():\n    x = boom()\n", "test_case", 2, value)


@pytest.mark.parametrize("overwrite", ['cfg[flag] = 42', 'cfg[True] = 42', 'cfg[1.0] = 42', 'cfg.clear()', 'alias = cfg; alias[1] = 42'])
def test_field_dependencies_are_invalidated_by_possible_aliases(overwrite):
    body = f'    x = boom()\n    cfg = {{}}\n    cfg[1] = x\n    {overwrite}\n    assert cfg[1] == 42\n'
    assert _flow(body).eligible == []



def test_checked_arguments_observe_walrus_evaluation_order():
    assert _flow('    x = boom()\n    self.assertEqual((x := 42), x)\n').eligible == []


def test_assertion_return_value_is_independent():
    assert _flow('    x = boom()\n    y = self.assertTrue(x)\n    assert y is None\n').eligible == ["test_case#0"]


@pytest.mark.parametrize("replace", ['(cfg := {"bad": 42})', 'match {"bad": 42}:\n        case cfg:\n            pass'])
def test_field_dependencies_do_not_survive_rebinding(replace):
    assert _flow(f'    x = boom()\n    cfg = {{}}\n    cfg["bad"] = x\n    {replace}\n    assert cfg["bad"] == 42\n').eligible == []



def test_raising_aggregate_cannot_seed_independent_elements():
    result = _flow('    x, y = 42, boom()\n    assert x == 42\n    assert y == 1\n')
    assert result.gave_up
    assert result.eligible == []


@pytest.mark.parametrize("control", ["break", "continue", "if flag: break"])
def test_finally_updates_loop_transfer_state(control):
    result = _flow(f'    x = boom()\n    for i in [1]:\n        try:\n            {control}\n        finally:\n            x = 42\n    assert x == 42\n')
    assert result.eligible == []
