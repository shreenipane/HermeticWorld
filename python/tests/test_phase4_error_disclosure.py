"""Library failures must stay sanitized when callers log exception chains."""

import traceback

import pytest

from hermetic_npm_cut import cut


PRIVATE_DETAIL = "private-host-path-and-credential"


def fail_with_private_detail(*args, **kwargs):
    raise OSError(PRIVATE_DETAIL)


@pytest.mark.parametrize("operation", ["open", "stat", "read", "write"])
def test_npm_io_exception_chain_omits_private_os_details(tmp_path, monkeypatch, operation):
    source = tmp_path / "source.json"
    source.write_bytes(b"{}")
    if operation == "open":
        monkeypatch.setattr(cut, "open_regular", fail_with_private_detail)
    elif operation in {"stat", "read"}:
        opened = cut.open_regular(source, 1024)
        monkeypatch.setattr(cut, "open_regular", lambda *args: opened)
        monkeypatch.setattr(cut.os, "fstat" if operation == "stat" else "read",
                            fail_with_private_detail)
    else:
        monkeypatch.setattr(cut, "atomic_write", fail_with_private_detail)
    with pytest.raises(cut.FileSafetyError) as caught:
        if operation == "write":
            cut.write_file_atomic(tmp_path / "out.json", b"{}")
        else:
            cut.read_regular_file_bounded(source, 1024)
    monkeypatch.undo()
    diagnostic = "".join(traceback.format_exception(caught.value))
    assert PRIVATE_DETAIL not in diagnostic


def test_npm_missing_input_error_chain_omits_supplied_path(tmp_path):
    with pytest.raises(cut.FileSafetyError) as caught:
        cut.read_regular_file_bounded(tmp_path / PRIVATE_DETAIL, 1024)
    assert PRIVATE_DETAIL not in "".join(traceback.format_exception(caught.value))
