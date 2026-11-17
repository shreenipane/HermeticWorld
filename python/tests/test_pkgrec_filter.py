"""Tests covering cutoff filtering at exact boundaries, missing upload-times, and yank rewriting."""

from __future__ import annotations

import json
import pytest

from hermetic_pkgrec.errors import CutoffError
from hermetic_pkgrec.filter import (
    filter_project_files,
    normalize_project_name,
    parse_iso8601_ns,
    parse_upstream_page,
    render_project_html,
    render_project_json,
    validate_filename,
    validate_sha256,
)
from hermetic_pkgrec.models import UpstreamFileEntry


def test_parse_iso8601_exact_nanoseconds() -> None:
    # 2023-01-01T12:00:00Z
    t1 = parse_iso8601_ns("2023-01-01T12:00:00Z")
    t2 = parse_iso8601_ns("2023-01-01T12:00:00.000000000Z")
    assert t1 == t2

    # Check 1 nanosecond difference.
    t3 = parse_iso8601_ns("2023-01-01T12:00:00.000000001Z")
    assert t3 == t1 + 1

    # Check offset calculation.
    t_utc = parse_iso8601_ns("2023-01-01T12:00:00Z")
    t_offset = parse_iso8601_ns("2023-01-01T14:00:00+02:00")
    assert t_utc == t_offset


def test_parse_iso8601_invalid() -> None:
    with pytest.raises(CutoffError):
        parse_iso8601_ns("not-a-date")
    with pytest.raises(CutoffError):
        parse_iso8601_ns("2023-02-29T12:00:00Z")  # 2023 is not a leap year.


def test_normalize_project_name() -> None:
    assert normalize_project_name("Foo_Bar.Baz-qux") == "foo-bar-baz-qux"
    assert normalize_project_name("Flask") == "flask"
    with pytest.raises(CutoffError):
        normalize_project_name("")
    with pytest.raises(CutoffError):
        normalize_project_name("invalid name with spaces")


def test_validate_sha256_and_filename() -> None:
    valid_sha = "a" * 64
    assert validate_sha256(valid_sha) == valid_sha
    assert validate_sha256(valid_sha.upper()) == valid_sha

    with pytest.raises(CutoffError):
        validate_sha256("short")
    with pytest.raises(CutoffError):
        validate_sha256("g" * 64)


def test_validate_sha256_rejects_trailing_newline() -> None:
    bad_sha = "a" * 64 + "\n"
    with pytest.raises(CutoffError):
        validate_sha256(bad_sha)

    assert validate_filename("pkg-1.0.whl") == "pkg-1.0.whl"
    with pytest.raises(CutoffError):
        validate_filename("../escape")
    with pytest.raises(CutoffError):
        validate_filename("/root")


def test_cutoff_filtering_exact_boundary_second() -> None:
    cutoff_str = "2023-06-15T12:00:00Z"
    cutoff_ns = parse_iso8601_ns(cutoff_str)

    sha_before = "1" * 64
    sha_exact = "2" * 64
    sha_after = "3" * 64

    entries = [
        UpstreamFileEntry(
            filename="pkg-1.0.0-py3-none-any.whl",
            url="https://example.com/files/pkg-1.0.0.whl",
            sha256=sha_before,
            upload_time="2023-06-15T11:59:59Z",
            yanked=False,
        ),
        UpstreamFileEntry(
            filename="pkg-1.0.1-py3-none-any.whl",
            url="https://example.com/files/pkg-1.0.1.whl",
            sha256=sha_exact,
            upload_time="2023-06-15T12:00:00Z",  # Exact boundary!
            yanked=False,
        ),
        UpstreamFileEntry(
            filename="pkg-1.0.2-py3-none-any.whl",
            url="https://example.com/files/pkg-1.0.2.whl",
            sha256=sha_after,
            upload_time="2023-06-15T12:00:01Z",  # 1 second after cutoff!
            yanked=False,
        ),
    ]

    result = filter_project_files("pkg", entries, cutoff_ns)

    # Exact boundary and before are kept; after is dropped.
    kept_filenames = [f.filename for f in result.files]
    assert "pkg-1.0.0-py3-none-any.whl" in kept_filenames
    assert "pkg-1.0.1-py3-none-any.whl" in kept_filenames
    assert "pkg-1.0.2-py3-none-any.whl" not in kept_filenames

    assert len(result.dropped_after_cutoff) == 1
    assert result.dropped_after_cutoff[0]["filename"] == "pkg-1.0.2-py3-none-any.whl"


def test_missing_upload_time_refused_and_listed() -> None:
    cutoff_str = "2023-06-15T12:00:00Z"
    cutoff_ns = parse_iso8601_ns(cutoff_str)

    entries = [
        UpstreamFileEntry(
            filename="valid-1.0.0.whl",
            url="https://example.com/files/valid.whl",
            sha256="a" * 64,
            upload_time="2023-01-01T00:00:00Z",
            yanked=False,
        ),
        UpstreamFileEntry(
            filename="undated-1.0.0.whl",
            url="https://example.com/files/undated.whl",
            sha256="b" * 64,
            upload_time=None,  # Missing upload-time!
            yanked=False,
        ),
        UpstreamFileEntry(
            filename="empty-date-1.0.0.whl",
            url="https://example.com/files/empty.whl",
            sha256="c" * 64,
            upload_time="",  # Empty upload-time!
            yanked=False,
        ),
    ]

    result = filter_project_files("test-pkg", entries, cutoff_ns)

    kept_filenames = [f.filename for f in result.files]
    assert kept_filenames == ["valid-1.0.0.whl"]

    # Both undated files must be refused and listed!
    missing_filenames = [m["filename"] for m in result.missing_upload_time]
    assert "undated-1.0.0.whl" in missing_filenames
    assert "empty-date-1.0.0.whl" in missing_filenames
    for m in result.missing_upload_time:
        assert m["project"] == "test-pkg"


def test_yank_rewriting_both_cases() -> None:
    cutoff_str = "2023-06-15T12:00:00Z"
    cutoff_ns = parse_iso8601_ns(cutoff_str)

    entries = [
        # Case 1: Yanked after cutoff -> served as not yanked.
        UpstreamFileEntry(
            filename="yanked-after-1.0.0.whl",
            url="https://example.com/files/yanked-after.whl",
            sha256="1" * 64,
            upload_time="2023-01-01T00:00:00Z",
            yanked="CVE-2023-99999",
            yank_time="2023-06-15T12:00:01Z",  # 1 sec after cutoff
        ),
        # Case 2: Unknown yank date -> served as not yanked and listed.
        UpstreamFileEntry(
            filename="yanked-unknown-1.0.0.whl",
            url="https://example.com/files/yanked-unknown.whl",
            sha256="2" * 64,
            upload_time="2023-01-01T00:00:00Z",
            yanked=True,  # Yanked, but no yank timestamp available!
            yank_time=None,
        ),
        # Control: Yanked before cutoff -> remains yanked.
        UpstreamFileEntry(
            filename="yanked-before-1.0.0.whl",
            url="https://example.com/files/yanked-before.whl",
            sha256="3" * 64,
            upload_time="2023-01-01T00:00:00Z",
            yanked="Broken build",
            yank_time="2023-06-15T11:59:59Z",  # Before cutoff
        ),
        # Control: Never yanked -> remains not yanked.
        UpstreamFileEntry(
            filename="clean-1.0.0.whl",
            url="https://example.com/files/clean.whl",
            sha256="4" * 64,
            upload_time="2023-01-01T00:00:00Z",
            yanked=False,
        ),
    ]

    result = filter_project_files("yank-test", entries, cutoff_ns)

    file_by_name = {f.filename: f for f in result.files}

    # Case 1: Yanked after cutoff is served as NOT yanked.
    y_after = file_by_name["yanked-after-1.0.0.whl"]
    assert y_after.yanked is False
    assert y_after.yank_decision == "unyanked_after_cutoff"
    assert any(x["filename"] == "yanked-after-1.0.0.whl" for x in result.unyanked_after_cutoff)

    # Case 2: Unknown yank date is served as NOT yanked and LISTED.
    y_unknown = file_by_name["yanked-unknown-1.0.0.whl"]
    assert y_unknown.yanked is False
    assert y_unknown.yank_decision == "unyanked_unknown_date"
    assert any(x["filename"] == "yanked-unknown-1.0.0.whl" for x in result.unyanked_unknown_date)

    # Control 1: Yanked before cutoff stays yanked with yanked=True and no reason text.
    y_before = file_by_name["yanked-before-1.0.0.whl"]
    assert y_before.yanked is True
    assert y_before.yank_decision == "yanked"

    # Control 2: Not yanked stays not yanked.
    clean = file_by_name["clean-1.0.0.whl"]
    assert clean.yanked is False
    assert clean.yank_decision == "not_yanked"


def test_parse_and_render_pep691_json() -> None:
    raw_json = json.dumps({
        "meta": {"api-version": "1.0"},
        "name": "demo-pkg",
        "files": [
            {
                "filename": "demo_pkg-1.0.0-py3-none-any.whl",
                "url": "https://example.com/packages/demo_pkg-1.0.0-py3-none-any.whl",
                "hashes": {"sha256": "f" * 64},
                "upload-time": "2022-01-01T00:00:00Z",
                "requires-python": ">=3.11",
                "yanked": False,
            }
        ],
    }).encode("utf-8")

    entries = parse_upstream_page(raw_json, "application/vnd.pypi.simple.v1+json")
    assert len(entries) == 1
    assert entries[0].filename == "demo_pkg-1.0.0-py3-none-any.whl"
    assert entries[0].sha256 == "f" * 64
    assert entries[0].upload_time == "2022-01-01T00:00:00Z"
    assert entries[0].requires_python == ">=3.11"

    cutoff_ns = parse_iso8601_ns("2023-01-01T00:00:00Z")
    res = filter_project_files("demo-pkg", entries, cutoff_ns)
    rendered_json = render_project_json("demo-pkg", res.files)

    parsed_back = json.loads(rendered_json.decode("utf-8"))
    assert parsed_back["name"] == "demo-pkg"
    assert len(parsed_back["files"]) == 1
    file_entry = parsed_back["files"][0]
    assert file_entry["url"] == f"/files/{'f'*64}/demo_pkg-1.0.0-py3-none-any.whl"
    assert file_entry["hashes"]["sha256"] == "f" * 64
    assert file_entry["requires-python"] == ">=3.11"


def test_render_project_url_encodes_filename() -> None:
    from hermetic_pkgrec.models import FilteredFileEntry
    sha = "e" * 64
    entry = FilteredFileEntry(
        filename="demo-1.0#build.tar.gz",
        url="https://example.com/demo-1.0%23build.tar.gz",
        sha256=sha,
        upload_time="2022-01-01T00:00:00Z",
        yanked=False,
        yank_decision="not_yanked",
    )
    json_bytes = render_project_json("demo", [entry])
    parsed = json.loads(json_bytes.decode("utf-8"))
    assert parsed["files"][0]["filename"] == "demo-1.0#build.tar.gz"
    assert parsed["files"][0]["url"] == f"/files/{sha}/demo-1.0%23build.tar.gz"

    html_bytes = render_project_html("demo", [entry])
    html_text = html_bytes.decode("utf-8")
    assert f'href="/files/{sha}/demo-1.0%23build.tar.gz#sha256={sha}"' in html_text
    assert ">demo-1.0#build.tar.gz</a>" in html_text


def test_parse_and_render_pep503_html() -> None:
    html_text = (
        '<!DOCTYPE html><html><body>'
        '<a href="https://example.com/pkg-0.1.tar.gz#sha256=' + ("a" * 64) + '" '
        'data-upload-time="2022-05-01T12:00:00Z" '
        'data-yanked="reason" '
        'data-requires-python="&gt;=3.10">pkg-0.1.tar.gz</a>'
        '</body></html>'
    )

    entries = parse_upstream_page(html_text.encode("utf-8"), "text/html")
    assert len(entries) == 1
    assert entries[0].filename == "pkg-0.1.tar.gz"
    assert entries[0].sha256 == "a" * 64
    assert entries[0].upload_time == "2022-05-01T12:00:00Z"
    assert entries[0].yanked == "reason"
    assert entries[0].requires_python == ">=3.10"


def test_filter_records_missing_hash_invalid_hash_invalid_filename() -> None:
    cutoff_ns = parse_iso8601_ns("2023-01-01T00:00:00Z")
    entries = [
        # Missing hash
        UpstreamFileEntry(
            filename="missing-hash-1.0.whl",
            url="https://example.com/missing-hash.whl",
            sha256=None,
            upload_time="2022-01-01T00:00:00Z",
            yanked=False,
        ),
        # Invalid hash
        UpstreamFileEntry(
            filename="invalid-hash-1.0.whl",
            url="https://example.com/invalid-hash.whl",
            sha256="not-a-valid-sha256-hex-digest",
            upload_time="2022-01-01T00:00:00Z",
            yanked=False,
        ),
        # Invalid filename (path traversal)
        UpstreamFileEntry(
            filename="../evil/invalid-filename-1.0.whl",
            url="https://example.com/invalid-filename.whl",
            sha256="a" * 64,
            upload_time="2022-01-01T00:00:00Z",
            yanked=False,
        ),
        # Valid control file
        UpstreamFileEntry(
            filename="valid-file-1.0.whl",
            url="https://example.com/valid-file.whl",
            sha256="b" * 64,
            upload_time="2022-01-01T00:00:00Z",
            yanked=False,
        ),
    ]

    res = filter_project_files("filter-defect4-test", entries, cutoff_ns)
    assert len(res.files) == 1
    assert res.files[0].filename == "valid-file-1.0.whl"

    assert len(res.missing_hash) == 1
    assert res.missing_hash[0]["filename"] == "missing-hash-1.0.whl"
    assert res.missing_hash[0]["project"] == "filter-defect4-test"

    assert len(res.invalid_hash) == 1
    assert res.invalid_hash[0]["filename"] == "invalid-hash-1.0.whl"
    assert res.invalid_hash[0]["project"] == "filter-defect4-test"

    assert len(res.invalid_filename) == 1
    assert res.invalid_filename[0]["filename"] == "../evil/invalid-filename-1.0.whl"
    assert res.invalid_filename[0]["project"] == "filter-defect4-test"


def test_filter_fails_closed_when_over_file_cap(monkeypatch) -> None:
    from hermetic_pkgrec.errors import ProjectOverFileCapError
    import hermetic_pkgrec.filter as flt

    cutoff_ns = parse_iso8601_ns("2023-01-01T00:00:00Z")
    monkeypatch.setattr(flt, "MAX_FILES_PER_PROJECT", 3)

    entries = [
        UpstreamFileEntry(
            filename=f"pkg-1.0.{i}.whl",
            url=f"https://example.com/pkg-1.0.{i}.whl",
            sha256="c" * 64,
            upload_time="2022-01-01T00:00:00Z",
            yanked=False,
        )
        for i in range(5)
    ]

    with pytest.raises(ProjectOverFileCapError):
        filter_project_files("overcap-test", entries, cutoff_ns)


def test_yank_handling_matches_hermetic_yank() -> None:
    """Feed the same page through hermetic_yank and filter_project_files; compare decisions."""
    from hermetic_yank.simple_index import rewrite_simple_index

    cutoff = "2023-04-01T00:00:00Z"
    cutoff_ns = parse_iso8601_ns(cutoff)

    secret_reason = "SECRET_VULNERABILITY_DETAILS"
    raw_page = {
        "meta": {"api-version": "1.0"},
        "name": "yank-compare",
        "versions": ["1.0.0", "1.1.0", "1.2.0", "2.0.0"],
        "files": [
            # Yanked before cutoff
            {
                "filename": "yank_compare-1.0.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/yank_compare-1.0.0-py3-none-any.whl",
                "hashes": {"sha256": "1" * 64},
                "upload-time": "2023-01-01T00:00:00Z",
                "yanked": secret_reason,
            },
            # Yanked after cutoff
            {
                "filename": "yank_compare-1.1.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/yank_compare-1.1.0-py3-none-any.whl",
                "hashes": {"sha256": "2" * 64},
                "upload-time": "2023-01-01T00:00:00Z",
                "yanked": "yanked later",
            },
            # Yanked unknown date (not in yank table)
            {
                "filename": "yank_compare-1.2.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/yank_compare-1.2.0-py3-none-any.whl",
                "hashes": {"sha256": "3" * 64},
                "upload-time": "2023-01-01T00:00:00Z",
                "yanked": True,
            },
            # Dropped after cutoff
            {
                "filename": "yank_compare-2.0.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/yank_compare-2.0.0-py3-none-any.whl",
                "hashes": {"sha256": "4" * 64},
                "upload-time": "2023-05-01T00:00:00Z",
                "yanked": False,
            },
            # Not yanked
            {
                "filename": "yank_compare-0.9.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/yank_compare-0.9.0-py3-none-any.whl",
                "hashes": {"sha256": "5" * 64},
                "upload-time": "2022-12-01T00:00:00Z",
                "yanked": False,
            },
        ],
    }

    yank_table = {
        "yank_compare-1.0.0-py3-none-any.whl": "2023-03-01T00:00:00Z",  # before cutoff
        "yank_compare-1.1.0-py3-none-any.whl": "2023-05-01T00:00:00Z",  # after cutoff
    }

    # Run through hermetic_yank
    rewritten_yank, report_yank = rewrite_simple_index(raw_page, yank_table, cutoff)

    # Run through hermetic_pkgrec filter_project_files
    page_bytes = json.dumps(raw_page).encode("utf-8")
    entries = parse_upstream_page(page_bytes, "application/vnd.pypi.simple.v1+json")
    result = filter_project_files("yank-compare", entries, cutoff_ns, yank_table=yank_table)

    # Compare decisions
    assert report_yank["dropped_after_cutoff"] == [x["filename"] for x in result.dropped_after_cutoff]
    assert report_yank["unyanked_after_cutoff"] == [x["filename"] for x in result.unyanked_after_cutoff]
    assert report_yank["unyanked_unknown_date"] == [x["filename"] for x in result.unyanked_unknown_date]

    # Verify kept files match
    yank_kept = {f["filename"]: f for f in rewritten_yank["files"]}
    rec_kept = {f.filename: f for f in result.files}
    assert set(yank_kept.keys()) == set(rec_kept.keys())

    # For yanked before cutoff: served with yanked=True and no reason text
    y_before = rec_kept["yank_compare-1.0.0-py3-none-any.whl"]
    assert y_before.yanked is True
    assert y_before.yank_decision == "yanked"

    # HTML rendering check: data-yanked="" with NO reason text
    html_bytes = render_project_html("yank-compare", result.files)
    html_str = html_bytes.decode("utf-8")
    assert 'data-yanked=""' in html_str
    assert secret_reason not in html_str

    # JSON rendering check: "yanked": true with NO reason text
    json_bytes = render_project_json("yank-compare", result.files)
    json_obj = json.loads(json_bytes.decode("utf-8"))
    json_files = {f["filename"]: f for f in json_obj["files"]}
    assert json_files["yank_compare-1.0.0-py3-none-any.whl"]["yanked"] is True
    assert secret_reason not in json_bytes.decode("utf-8")

