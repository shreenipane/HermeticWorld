"""Snapshot inventory validation and consumption must use the same mapping."""

import pytest

import hermetic_state_snapshot as snapshot
from tests.test_phase4_snapshot_artifacts import fixture, verify


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_snapshot_inventory_is_retained_before_validation(monkeypatch, change):
    raw, bodies = fixture()
    expected = tuple(sorted(bodies.items()))
    changed = False

    def change_before_collection(entries):
        # Simulate a caller scheduled between key validation and collection of
        # payloads. A dict_items view still observes changes to its mapping.
        nonlocal changed
        changed = True
        if change == "missing":
            del bodies["memory"]
        else:
            bodies["unexpected"] = b"unverified"
        return sorted(entries)

    monkeypatch.setattr(snapshot, "sorted", change_before_collection, raising=False)
    verified = verify(raw, bodies)
    assert changed
    assert verified.artifacts == expected
