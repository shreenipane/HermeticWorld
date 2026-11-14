"""The direct npm boundary must retain the tree covered by its input caps."""

import pytest

from hermetic_npm_cut import cut

CUTOFF = "2023-04-01T00:00:00Z"


@pytest.mark.parametrize("mutation", ["oversize", "cycle", "remove", "time"])
def test_npm_direct_filter_retains_validated_tree(monkeypatch, mutation):
    source = {
        "name": "demo",
        "versions": {"1.0.0": {"description": "original"}},
        "time": {"1.0.0": CUTOFF},
    }
    expected, expected_report = cut.cut_packument(source, CUTOFF)
    expected_bytes = cut.canonical_json_bytes(expected)
    monkeypatch.setattr(cut, "DEFAULT_PACKUMENT_CAP_BYTES", 512)
    validate = cut._validate_str
    changed = False

    def mutate_after_tree_validation(value, field, max_len=cut.MAX_STRING_LEN):
        nonlocal changed
        result = validate(value, field, max_len)
        if field == "name" and not changed:
            changed = True
            if mutation == "oversize":
                source["versions"]["1.0.0"]["description"] = "x" * 1024
            elif mutation == "cycle":
                source["versions"]["1.0.0"]["description"] = source
            elif mutation == "remove":
                source["versions"].clear()
            else:
                source["time"]["1.0.0"] = "2024-01-01T00:00:00Z"
        return result

    monkeypatch.setattr(cut, "_validate_str", mutate_after_tree_validation)
    actual, report = cut.cut_packument(source, CUTOFF)
    assert changed
    assert cut.canonical_json_bytes(actual) == expected_bytes
    assert report == expected_report


@pytest.mark.parametrize("mutation", ["add", "remove"])
def test_npm_direct_filter_refuses_dictionary_resize_during_validation(monkeypatch, mutation):
    source = {"name": "demo", "versions": {}, "time": {}}
    encode = cut.json.dumps
    changed = False

    def mutate_during_validation(value, **kwargs):
        nonlocal changed
        if value == "name" and not changed:
            changed = True
            if mutation == "add":
                source["private-value"] = "secret-marker"
            else:
                del source["versions"]
        return encode(value, **kwargs)

    monkeypatch.setattr(cut.json, "dumps", mutate_during_validation)
    with pytest.raises(cut.ValidationError, match="changed during validation") as error:
        cut.cut_packument(source, CUTOFF)
    assert changed
    assert "secret-marker" not in str(error.value)
