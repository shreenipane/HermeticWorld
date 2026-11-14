"""The shared public npm byte parser must refuse malformed API inputs safely."""

import pytest

from hermetic_npm_cut.cut import HermeticNpmCutError, parse_json_bytes


@pytest.mark.parametrize("raw", [None, 1, "host-secret", {}, [], memoryview(b"{}")])
def test_npm_byte_parser_refuses_nonbytes_with_typed_error(raw):
    with pytest.raises(HermeticNpmCutError) as error:
        parse_json_bytes(raw, 1024)
    assert "host-secret" not in str(error.value)


@pytest.mark.parametrize("cap", [None, "host-secret", True, 1.5, float("inf"), -1, 2**63])
def test_npm_byte_parser_refuses_invalid_cap_before_parsing(cap):
    with pytest.raises(HermeticNpmCutError) as error:
        parse_json_bytes(b"0", cap)
    assert "host-secret" not in str(error.value)
