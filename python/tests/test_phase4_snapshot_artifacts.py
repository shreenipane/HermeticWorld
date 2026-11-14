"""Authenticate actual immutable snapshot bytes before a restore consumer uses them."""

import json

import pytest

import hermetic_state_snapshot as s
from tests.test_phase4_state_snapshot import encode, recipe, sha


def fixture():
    bodies = {name: ("snapshot-" + name).encode() for name in s.ARTIFACT_CAPS}
    value = recipe()
    value["artifacts"] = {name: dict(sha256=sha(body), size=len(body))
                          for name, body in bodies.items()}
    raw = encode(value)
    return raw, bodies


def verify(raw, bodies, **updates):
    args = dict(raw_manifest=raw, expected_sha256=sha(raw), run_sha256="a" * 64,
                runtime_sha256=sha(encode(recipe()["runtime"])), artifacts=bodies)
    args.update(updates)
    return s.verify_snapshot_artifacts(**args)


def test_snapshot_artifacts_known_bytes_order_and_immutable_inventory(monkeypatch):
    raw, bodies = fixture()
    for name in ("HOME", "HOSTNAME", "TZ", "LANG", "SOURCE_DATE_EPOCH"):
        monkeypatch.setenv(name, "host-secret")
    expected = tuple(sorted(bodies.items()))
    verified = verify(raw, dict(reversed(list(bodies.items()))))
    assert verified.handoff.manifest == raw
    assert verified.handoff.sha256 == sha(raw)
    assert verified.artifacts == expected
    assert b"host-secret" not in raw + b"".join(body for _, body in verified.artifacts)
    bodies.clear()
    assert verified.artifacts == expected


@pytest.mark.parametrize("name", ["state", "memory", "base", "overlay"])
@pytest.mark.parametrize("mutation", ["corrupt", "truncated", "grown", "empty", "type", "missing"])
def test_snapshot_artifacts_refuse_wrong_bytes_for_every_role(name, mutation):
    raw, bodies = fixture()
    if mutation == "corrupt":
        bodies[name] = b"!" * len(bodies[name])
    elif mutation == "truncated":
        bodies[name] = bodies[name][:-1]
    elif mutation == "grown":
        bodies[name] += b"!"
    elif mutation == "empty":
        bodies[name] = b""
    elif mutation == "type":
        bodies[name] = bytearray(bodies[name])
    else:
        del bodies[name]
    with pytest.raises(s.SnapshotError) as caught:
        verify(raw, bodies)
    assert "snapshot-" not in str(caught.value)


@pytest.mark.parametrize("bodies", [None, [], {}, {"../host-secret": b"host-secret"}])
def test_snapshot_artifacts_refuse_noninventory_inputs(bodies):
    raw, _ = fixture()
    with pytest.raises(s.SnapshotError) as caught:
        verify(raw, bodies)
    assert "host-secret" not in str(caught.value)


def test_snapshot_artifacts_refuse_extras_even_with_a_matching_payload():
    raw, bodies = fixture()
    bodies["host-secret"] = bodies["state"]
    with pytest.raises(s.SnapshotError):
        verify(raw, bodies)


@pytest.mark.parametrize("pin", ["expected_sha256", "run_sha256", "runtime_sha256"])
def test_snapshot_artifacts_authenticate_before_considering_inventory(pin):
    raw, _ = fixture()
    with pytest.raises(s.SnapshotError, match="authentication or compatibility"):
        verify(raw, None, **{pin: "0" * 64})


def test_snapshot_artifacts_validate_all_lengths_before_hashing_any_payload(monkeypatch):
    raw, bodies = fixture()
    original = dict(bodies)
    bodies["overlay"] += b"host-secret"
    hashed = []
    digest = s._sha

    def observe(body):
        hashed.append(body)
        return digest(body)

    monkeypatch.setattr(s, "_sha", observe)
    with pytest.raises(s.SnapshotError):
        verify(raw, bodies)
    assert not any(body in hashed for body in original.values())


def test_snapshot_artifacts_return_the_verified_objects_if_input_mapping_changes(monkeypatch):
    raw, bodies = fixture()
    expected = tuple(sorted(bodies.items()))
    digest = s._sha

    def replace_inventory_during_hash(body):
        if body == b"snapshot-base":
            bodies["memory"] = b"unverified-memory"
        return digest(body)

    monkeypatch.setattr(s, "_sha", replace_inventory_during_hash)
    verified = verify(raw, bodies)
    assert bodies["memory"] == b"unverified-memory"
    assert verified.artifacts == expected
    assert all(actual is original for (_, actual), (_, original)
               in zip(verified.artifacts, expected))


def test_snapshot_artifacts_require_the_independently_authenticated_manifest():
    raw, bodies = fixture()
    changed = json.loads(raw)
    bodies["memory"] = b"substituted-memory"
    changed["artifacts"]["memory"] = dict(sha256=sha(bodies["memory"]), size=len(bodies["memory"]))
    with pytest.raises(s.SnapshotError):
        verify(encode(changed), bodies, expected_sha256=sha(raw))


@pytest.mark.parametrize("cap", ["MAX_TOTAL_ARTIFACT_BYTES", "MAX_DOCUMENT_BYTES"])
def test_snapshot_artifacts_enforce_named_caps_before_hashing_bodies(monkeypatch, cap):
    raw, bodies = fixture()
    monkeypatch.setattr(s, cap, 1)
    with pytest.raises(s.SnapshotError):
        verify(raw, bodies)


@pytest.mark.parametrize("name", ["state", "memory", "base", "overlay"])
def test_snapshot_artifacts_enforce_each_role_cap(monkeypatch, name):
    raw, bodies = fixture()
    monkeypatch.setitem(s.ARTIFACT_CAPS, name, len(bodies[name]))
    assert verify(raw, bodies).artifacts == tuple(sorted(bodies.items()))
    monkeypatch.setitem(s.ARTIFACT_CAPS, name, len(bodies[name]) - 1)
    with pytest.raises(s.SnapshotError):
        verify(raw, bodies)
