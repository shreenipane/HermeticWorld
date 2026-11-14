"""Offline snapshot handoff authentication and shared grading-path policy."""

import hashlib
import json

import pytest

import hermetic_state_snapshot as s


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def recipe():
    return dict(schema="hermetic-state-snapshot/v1", run_sha256="a" * 64,
                runtime={key: "b" * 64 for key in s.RUNTIME_FIELDS},
                artifacts={key: dict(sha256="c" * 64, size=4096) for key in s.ARTIFACT_CAPS},
                tests_drive="tests", network_interfaces=["eth0"],
                access_closed=True, paused=True, clock="faked")


def verify(raw=None, **updates):
    value = recipe()
    raw = encode(value) if raw is None else raw
    args = dict(raw_manifest=raw, expected_sha256=sha(raw), run_sha256=value["run_sha256"],
                runtime_sha256=sha(encode(value["runtime"])))
    args.update(updates)
    return s.verify_snapshot_handoff(**args)


def result(path="live", reason=None):
    return dict(path=path, fallback_reason=reason, tests=dict(sha256="d" * 64, size=4096),
                result=dict(sha256="e" * 64, size=23))


def record(value):
    raw = encode(recipe())
    return s.build_state_grade_record(raw, sha(raw), "a" * 64,
                                     sha(encode(recipe()["runtime"])), encode(value))


def test_snapshot_handoff_known_answer_and_immutable_inventory(monkeypatch):
    expected = encode(recipe())
    for name in ("HOME", "HOSTNAME", "TZ", "LANG", "SOURCE_DATE_EPOCH"):
        monkeypatch.setenv(name, "host-secret")
    # Pretty printing and reverse field order produce exactly the same bytes.
    value = dict(reversed(list(recipe().items())))
    assert s.prepare_snapshot_handoff(json.dumps(value, indent=2).encode()) == expected
    handoff = verify(expected)
    assert handoff.manifest == expected
    assert handoff.tests_drive == "tests"
    assert handoff.network_interfaces == ("eth0",)
    assert handoff.sha256 == sha(expected)
    assert handoff.runtime_sha256 == sha(encode(recipe()["runtime"]))
    assert b"host-secret" not in expected


@pytest.mark.parametrize("field", ["expected_sha256", "run_sha256", "runtime_sha256"])
def test_snapshot_handoff_refuses_wrong_trusted_pin(field):
    with pytest.raises(s.SnapshotError):
        verify(**{field: "f" * 64})


@pytest.mark.parametrize("pin", ["firecracker", "cpu_model", "cpu_template", "kernel", "initramfs"])
def test_snapshot_handoff_refuses_incompatible_restore_runtime(pin):
    value = recipe()
    value["runtime"][pin] = "f" * 64
    # Even with an authenticated snapshot digest, the destination's runtime
    # compatibility pin must agree before any future runner restores it.
    with pytest.raises(s.SnapshotError):
        verify(encode(value))


def test_snapshot_handoff_refuses_noncanonical_authenticated_bytes():
    with pytest.raises(s.SnapshotError):
        verify(json.dumps(recipe(), indent=2).encode())


@pytest.mark.parametrize("field,value", [
    ("schema", "host-secret"), ("run_sha256", []), ("runtime", []), ("artifacts", []),
    ("access_closed", False), ("access_closed", 1), ("paused", False), ("paused", 1),
    ("clock", "hidden"), ("tests_drive", "../host-secret"), ("tests_drive", "root"),
    ("tests_drive", "overlay"), ("tests_drive", "x" * 33), ("tests_drive", []),
    ("network_interfaces", "eth0"), ("network_interfaces", ["eth1"]),
    ("network_interfaces", ["eth0", "eth1"]), ("network_interfaces", [["host-secret"]]),
])
def test_snapshot_handoff_hostile_policy_and_topology(field, value):
    data = recipe()
    data[field] = value
    with pytest.raises(s.SnapshotError) as error:
        s.prepare_snapshot_handoff(encode(data))
    assert "host-secret" not in str(error.value)


@pytest.mark.parametrize("size", [None, True, 0, -1, s.MAX_MEMORY_BYTES + 1])
def test_snapshot_handoff_refuses_invalid_artifact_size(size):
    value = recipe()
    value["artifacts"]["memory"]["size"] = size
    with pytest.raises(s.SnapshotError):
        s.prepare_snapshot_handoff(encode(value))


@pytest.mark.parametrize("target", ["runtime", "artifacts"])
@pytest.mark.parametrize("mutation", ["missing", "extra", "digest", "type"])
def test_snapshot_handoff_requires_exact_complete_artifact_and_runtime_pins(target, mutation):
    value = recipe()
    key = next(iter(value[target]))
    if mutation == "missing":
        del value[target][key]
    elif mutation == "extra":
        value[target]["host-secret"] = "a" * 64
    elif mutation == "digest":
        if target == "runtime":
            value[target][key] = "host-secret"
        else:
            value[target][key]["sha256"] = "host-secret"
    else:
        value[target][key] = []
    with pytest.raises(s.SnapshotError):
        s.prepare_snapshot_handoff(encode(value))


@pytest.mark.parametrize("cap", ["MAX_DOCUMENT_BYTES", "MAX_TOTAL_ARTIFACT_BYTES", "MAX_DRIVE_ID_BYTES"])
def test_snapshot_handoff_named_caps(monkeypatch, cap):
    monkeypatch.setattr(s, cap, 1)
    with pytest.raises(s.SnapshotError):
        s.prepare_snapshot_handoff(encode(recipe()))


@pytest.mark.parametrize("name", ["state", "memory", "base", "overlay"])
def test_snapshot_handoff_artifact_exact_size_boundary(name):
    value = recipe()
    cap = s.ARTIFACT_CAPS[name]
    value["artifacts"][name]["size"] = cap
    assert verify(s.prepare_snapshot_handoff(encode(value)))
    value["artifacts"][name]["size"] = cap + 1
    with pytest.raises(s.SnapshotError):
        s.prepare_snapshot_handoff(encode(value))


@pytest.mark.parametrize("raw", [None, [], b"null", b"{}", b"\xff", b'{"x":1,"x":2}',
                               b'{"x":"\\ud800"}', b'{"x":1e999}', b"[" * 30])
def test_snapshot_handoff_malformed_input_is_typed(raw):
    with pytest.raises(s.SnapshotError):
        s.prepare_snapshot_handoff(raw)


def test_snapshot_handoff_arbitrary_single_byte_input_has_typed_errors():
    for value in range(256):
        with pytest.raises(s.SnapshotError):
            s.prepare_snapshot_handoff(bytes([value]))


def test_state_grade_record_live_known_answer_and_shared_isolation():
    raw = record(result())
    assert raw == (b'{"fallback_reason":null,"grader_isolation":"shared","path":"live",'
                   b'"result":{"sha256":"' + b"e" * 64 + b'","size":23},"run_sha256":"' +
                   b"a" * 64 + b'","schema":"hermetic-state-grade/v1","snapshot_sha256":"' +
                   sha(encode(recipe())).encode() + b'","tests":{"sha256":"' + b"d" * 64 +
                   b'","size":4096}}')


@pytest.mark.parametrize("reason", ["execd_unresponsive", "no_live_state"])
def test_state_grade_record_fallback_path_is_explicit(reason):
    value = json.loads(record(result("reboot", reason)))
    assert value["path"] == "reboot"
    assert value["fallback_reason"] == reason
    assert value["grader_isolation"] == "shared"


@pytest.mark.parametrize("path,reason", [("live", "no_live_state"), ("reboot", None),
    ("reboot", "host-secret"), ("reboot", []), ([], None), ("clean", None)])
def test_state_grade_record_refuses_invalid_path_and_fallback(path, reason):
    with pytest.raises(s.SnapshotError):
        record(result(path, reason))


@pytest.mark.parametrize("name,cap", [("tests", s.MAX_TESTS_BYTES), ("result", s.MAX_RESULT_BYTES)])
def test_state_grade_record_binds_bounded_test_and_result_artifacts(name, cap):
    value = result()
    value[name]["size"] = cap
    assert json.loads(record(value))[name]["size"] == cap
    value[name]["size"] = cap + 1
    with pytest.raises(s.SnapshotError):
        record(value)


def test_state_grade_record_authenticates_snapshot_before_result():
    with pytest.raises(s.SnapshotError):
        s.build_state_grade_record(encode(recipe()), "0" * 64, "a" * 64,
                                   sha(encode(recipe()["runtime"])), encode(result()))


def test_snapshot_without_network_interface_is_valid():
    value = recipe()
    value["network_interfaces"] = []
    assert verify(s.prepare_snapshot_handoff(encode(value))).network_interfaces == ()
