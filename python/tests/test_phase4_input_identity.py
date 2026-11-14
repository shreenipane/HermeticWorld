"""The npm publisher reads the input it inspected, across path substitutions."""

import json

import pytest

from hermetic_npm_cut import cut

CUTOFF = "2023-04-01T00:00:00Z"


@pytest.mark.parametrize("substitution", ["parent", "inode"])
def test_npm_input_identity_survives_preflight_path_substitution(tmp_path, monkeypatch, substitution):
    parent = tmp_path / "input"
    parent.mkdir()
    source = parent / "source.json"
    original = dict(name="original", versions={}, time={})
    source.write_text(json.dumps(original))
    output, report = tmp_path / "output.json", tmp_path / "report.json"
    real_parent = cut.open_parent

    def substitute(path):
        result = real_parent(path)
        if path == str(report):
            if substitution == "parent":
                parent.rename(tmp_path / "moved")
                parent.mkdir()
            else:
                source.rename(parent / "old.json")
            source.write_text(json.dumps(dict(name="substituted", versions={}, time={})))
        return result

    monkeypatch.setattr(cut, "open_parent", substitute)
    if substitution == "inode":
        with pytest.raises(cut.FileSafetyError):
            cut.cut_packument_files(source, CUTOFF, output, report)
        assert not output.exists()
        assert not report.exists()
    else:
        cut.cut_packument_files(source, CUTOFF, output, report)
        assert json.loads(output.read_bytes())["name"] == "original"
    assert json.loads(source.read_bytes())["name"] == "substituted"
