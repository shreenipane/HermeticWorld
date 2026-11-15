

def test_output_dirs_are_created_without_following_symlinks(tmp_path):
    """T2.4: missing output directories are created relative to held descriptors."""
    import os
    import stat

    import pytest

    from hermetic_slice.rootfs import _make_output_dirs

    old = os.umask(0)
    try:
        _make_output_dirs(tmp_path / "a" / "b" / "c")
    finally:
        os.umask(old)
    for level in ("a", "a/b", "a/b/c"):
        assert stat.S_IMODE(os.lstat(tmp_path / level).st_mode) == 0o755
    _make_output_dirs(tmp_path / "a" / "b" / "c")  # existing levels are fine

    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "link").symlink_to(outside)
    with pytest.raises(OSError):
        _make_output_dirs(tmp_path / "link" / "new")
    assert not (outside / "new").exists()

    (tmp_path / "file").write_text("x")
    with pytest.raises(OSError):
        _make_output_dirs(tmp_path / "file" / "new")
