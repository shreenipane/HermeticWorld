"""Go admission must consume the info bytes covered by its aggregate budget."""

import pytest

from hermetic_ecosystem_cut import cut
from tests.test_ecosystem_cut import BEFORE, CUTOFF, info


@pytest.mark.parametrize("mutation", ["replace", "remove"])
def test_go_info_inventory_is_retained_after_aggregate_validation(monkeypatch, mutation):
    listing = b"v1.0.0\nv1.1.0\n"
    infos = {version: info(version) for version in ("v1.0.0", "v1.1.0")}
    expected = cut.cut_go_versions(listing, infos, CUTOFF)
    budget = len(listing) + sum(map(len, infos.values()))
    monkeypatch.setattr(cut, "MAX_INPUT_BYTES", budget)
    replacement = info("v1.1.0", BEFORE, Origin={"URL": "x" * budget})
    assert len(listing) + len(infos["v1.0.0"]) + len(replacement) > budget
    assert len(replacement) < cut.MAX_RECORD_BYTES
    parse = cut._json
    changed = False

    def mutate_after_first_parse(raw):
        nonlocal changed
        value = parse(raw)
        if not changed:
            changed = True
            if mutation == "replace":
                infos["v1.1.0"] = replacement
            else:
                del infos["v1.1.0"]
        return value

    monkeypatch.setattr(cut, "_json", mutate_after_first_parse)
    assert cut.cut_go_versions(listing, infos, CUTOFF) == expected
    assert changed
    assert infos.get("v1.1.0") == (replacement if mutation == "replace" else None)
