"""Offline tests for Phase 4 web archive importers.

Covers Common Crawl WARC/CDX, Wayback CDX, Software Heritage snapshots,
and Stack Exchange data dumps rebuilt from post history as of cutoff.
Tests exact cutoff boundaries, undated reporting (never guessed),
post-history rollbacks/edits, hostile inputs and caps, environment independence,
and integration with replay and BM25 index builders.
"""

import base64
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
import shutil
import tempfile
import zlib

import pytest

from hermetic_archive import (
    ArchiveError,
    ImportReport,
    ReplayIndex,
    SearchIndex,
    build_replay_index,
    build_search_index,
    import_common_crawl_cdx,
    import_common_crawl_warc,
    import_software_heritage,
    import_stack_exchange,
    import_wayback_cdx,
)
from hermetic_archive import formats as f
from hermetic_archive.importers import (
    MAX_RECORDS,
    MAX_TEXT_BYTES,
    _bounded_decompress_http_payload,
    _read_blobs_dir_bounded,
    extract_html_title_and_text,
)
from hermetic_archive.__main__ import _write_outputs


CUTOFF = "2023-04-01T00:00:00Z"
MONTH = "2023-04"


def _gzip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()


def _warc_record(url: str, date: str, status: int, body: bytes, warc_type: str = "response",
                 content_type: str = "text/html; charset=utf-8", location: str | None = None) -> bytes:
    http_headers = [f"HTTP/1.1 {status} OK", f"Content-Type: {content_type}"]
    if location:
        http_headers.append(f"Location: {location}")
    http_block = ("\r\n".join(http_headers) + "\r\n\r\n").encode("utf-8") + body

    warc_headers = [
        "WARC/1.1",
        f"WARC-Type: {warc_type}",
        f"WARC-Target-URI: {url}",
        f"WARC-Date: {date}",
        "WARC-Record-ID: <urn:uuid:12345678-1234-1234-1234-123456789abc>",
        "Content-Type: application/http; msgtype=response",
        f"Content-Length: {len(http_block)}",
    ]
    return ("\r\n".join(warc_headers) + "\r\n\r\n").encode("utf-8") + http_block + b"\r\n\r\n"


# ---------------------------------------------------------------------------
# 1. Common Crawl Tests
# ---------------------------------------------------------------------------

def test_common_crawl_warc_cutoff_boundary_and_decompression():
    url_admitted_old = "https://example.org/old"
    url_admitted_exact = "https://example.org/exact"
    url_future = "https://example.org/future"
    url_undated = "https://example.org/undated"

    r1 = _warc_record(url_admitted_old, "2023-03-15T12:00:00Z", 200, b"<html><head><title>Old Page</title></head><body>Ancient text</body></html>")
    r2 = _warc_record(url_admitted_exact, CUTOFF, 200, b"<html><head><title>Exact Page</title></head><body>Boundary text</body></html>")
    r3 = _warc_record(url_future, "2023-04-01T00:00:01Z", 200, b"<html><head><title>Future</title></head><body>Post cutoff secret</body></html>")
    r4 = _warc_record(url_undated, "invalid-date", 200, b"<html><body>No date</body></html>")

    raw_warc = r1 + r2 + r3 + r4
    report_plain = import_common_crawl_warc(raw_warc, CUTOFF)

    # Assert admissions
    kept_urls = [c["url"] for c in report_plain.kept]
    assert kept_urls == [url_admitted_exact, url_admitted_old]
    assert report_plain.after_cutoff == (url_future,)
    assert report_plain.undated == (url_undated,)

    # Test gzipped WARC
    raw_warc_gz = _gzip(raw_warc)
    report_gz = import_common_crawl_warc(raw_warc_gz, CUTOFF)
    assert report_gz.kept == report_plain.kept
    assert report_gz.search_documents == report_plain.search_documents
    assert report_gz.blobs == report_plain.blobs
    assert report_gz.after_cutoff == report_plain.after_cutoff
    assert report_gz.undated == report_plain.undated


def test_common_crawl_cdx_and_cdxj_parsing():
    url_kept = "https://example.org/valid"
    url_future = "https://example.org/future"
    url_undated = "https://example.org/undated"

    body_kept = b"<html><head><title>Valid</title></head><body>Valid content</body></html>"
    digest_kept = f.sha(body_kept)

    # CDX line format: urlkey timestamp original mimetype statuscode digest redirect
    cdx_lines = [
        f"org,example)/valid 20230301120000 {url_kept} text/html 200 {digest_kept} -",
        f"org,example)/future 20230501120000 {url_future} text/html 200 future_digest -",
        f"org,example)/undated bad-timestamp {url_undated} text/html 200 undated_digest -",
    ]
    raw_cdx = "\n".join(cdx_lines).encode("utf-8")
    blobs = {digest_kept: body_kept}

    report = import_common_crawl_cdx(raw_cdx, blobs, CUTOFF)
    assert [c["url"] for c in report.kept] == [url_kept]
    assert report.after_cutoff == (url_future,)
    assert report.undated == (url_undated,)

    # CDXJ line format
    cdxj_lines = [
        f'org,example)/valid 20230301120000 {{"url": "{url_kept}", "mime": "text/html", "status": "200", "digest": "{digest_kept}"}}',
        f'org,example)/future 20230501120000 {{"url": "{url_future}", "mime": "text/html", "status": "200", "digest": "fut"}}',
    ]
    raw_cdxj = "\n".join(cdxj_lines).encode("utf-8")
    report_cdxj = import_common_crawl_cdx(raw_cdxj, blobs, CUTOFF)
    assert [c["url"] for c in report_cdxj.kept] == [url_kept]
    assert report_cdxj.after_cutoff == (url_future,)


# ---------------------------------------------------------------------------
# 2. Wayback CDX Tests
# ---------------------------------------------------------------------------

def test_wayback_cdx_text_and_json_api():
    url_kept = "https://example.org/article"
    url_redirect = "https://example.org/redir"
    url_dest = "https://example.org/destination"
    url_future = "https://example.org/future"
    url_undated = "https://example.org/bad-date"

    body_art = b"<html><head><title>Article</title></head><body>Article Body</body></html>"
    digest_art = f.sha(body_art)
    digest_empty = f.sha(b"")

    # Wayback JSON API format
    json_data = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "redirect"],
        ["org,example)/article", "20230320153000", url_kept, "text/html", "200", digest_art, "-"],
        ["org,example)/redir", "20230321153000", url_redirect, "text/html", "301", digest_empty, url_dest],
        ["org,example)/future", "20240101000000", url_future, "text/html", "200", "fdigest", "-"],
        ["org,example)/bad-date", "NOTADATE", url_undated, "text/html", "200", "baddigest", "-"],
    ]
    raw_json = json.dumps(json_data).encode("utf-8")
    blobs = {digest_art: body_art, digest_empty: b""}

    report = import_wayback_cdx(raw_json, blobs, CUTOFF)
    kept_urls = [c["url"] for c in report.kept]
    assert url_kept in kept_urls
    assert url_redirect in kept_urls
    assert report.after_cutoff == (url_future,)
    assert report.undated == (url_undated,)

    redir_entry = next(c for c in report.kept if c["url"] == url_redirect)
    assert redir_entry["status"] == 301
    assert redir_entry["location"] == url_dest


# ---------------------------------------------------------------------------
# 3. Software Heritage Tests
# ---------------------------------------------------------------------------

def test_software_heritage_snapshot_admission():
    url_repo = "https://github.com/example/lib"
    readme_body = b"# Example Lib\nFast and reliable.\n"
    code_body = b"def run(): return 42\n"

    readme_sha = f.sha(readme_body)
    code_sha = f.sha(code_body)

    snapshot_doc = {
        "schema": "hermetic-swh-snapshot/v1",
        "origin": url_repo,
        "visit_date": "2023-01-10T12:00:00Z",
        "snapshot_id": "swh:1:snp:0123456789abcdef",
        "entries": [
            {
                "path": "README.md",
                "sha256": readme_sha,
                "size": len(readme_body),
                "content_type": "text/markdown",
                "captured": "2023-01-10T12:00:00Z",
            },
            {
                "path": "src/run.py",
                "sha256": code_sha,
                "size": len(code_body),
                "content_type": "text/x-python",
                "captured": "2023-01-10T12:00:00Z",
            },
            {
                "path": "future/secret.py",
                "sha256": "f" * 64,
                "size": 10,
                "captured": "2024-01-01T00:00:00Z",
            },
            {
                "path": "undated/broken.py",
                "sha256": "0" * 64,
                "size": 10,
                "captured": "not-a-date",
            },
        ],
    }

    raw_doc = json.dumps(snapshot_doc).encode("utf-8")
    blobs = {readme_sha: readme_body, code_sha: code_body}

    report = import_software_heritage(raw_doc, blobs, CUTOFF)

    kept_paths = [c["url"] for c in report.kept]
    assert f"{url_repo}/raw/HEAD/README.md" in kept_paths
    assert f"{url_repo}/raw/HEAD/src/run.py" in kept_paths
    assert any("future/secret.py" in u for u in report.after_cutoff)
    assert any("undated/broken.py" in u for u in report.undated)


# ---------------------------------------------------------------------------
# 4. Stack Exchange Rebuilder Tests (Mutable Content Rule §4)
# ---------------------------------------------------------------------------

def test_stack_exchange_rebuild_from_post_history_rollback_and_cutoff():
    """Verify that edits after cutoff are rolled back to pre-cutoff revisions,
    posts created after cutoff are excluded, deleted posts are excluded,
    and undated posts are listed.
    """
    # Post 1: Question created 2022-01-01, edited 2022-06-01 (pre-cutoff), edited 2024-01-01 (post-cutoff)
    # Post 2: Question created 2024-01-01 (post-cutoff) -> after_cutoff
    # Post 3: Question deleted before cutoff -> excluded
    # Post 4: Question with corrupted date -> undated
    xml_content = b"""<?xml version="1.0" encoding="utf-8"?>
<posthistory>
  <!-- Post 1 events -->
  <row Id="1" PostHistoryTypeId="1" PostId="100" CreationDate="2022-01-01T10:00:00.000" Text="Initial Title" />
  <row Id="2" PostHistoryTypeId="2" PostId="100" CreationDate="2022-01-01T10:00:00.000" Text="Initial Body" />
  <row Id="3" PostHistoryTypeId="4" PostId="100" CreationDate="2022-06-01T12:00:00.000" Text="Pre-Cutoff Edited Title" />
  <row Id="4" PostHistoryTypeId="5" PostId="100" CreationDate="2022-06-01T12:00:00.000" Text="Pre-Cutoff Edited Body" />
  <row Id="5" PostHistoryTypeId="4" PostId="100" CreationDate="2024-01-01T15:00:00.000" Text="Future Post-Cutoff Title LEAK" />
  <row Id="6" PostHistoryTypeId="5" PostId="100" CreationDate="2024-01-01T15:00:00.000" Text="Future Post-Cutoff Body LEAK" />

  <!-- Post 2 events: created after cutoff -->
  <row Id="7" PostHistoryTypeId="1" PostId="200" CreationDate="2024-01-01T00:00:00.000" Text="Future Question Title" />
  <row Id="8" PostHistoryTypeId="2" PostId="200" CreationDate="2024-01-01T00:00:00.000" Text="Future Question Body" />

  <!-- Post 3 events: deleted before cutoff -->
  <row Id="9" PostHistoryTypeId="1" PostId="300" CreationDate="2022-01-01T00:00:00.000" Text="Deleted Post Title" />
  <row Id="10" PostHistoryTypeId="2" PostId="300" CreationDate="2022-01-01T00:00:00.000" Text="Deleted Post Body" />
  <row Id="11" PostHistoryTypeId="12" PostId="300" CreationDate="2022-02-01T00:00:00.000" Text="Post Deleted" />

  <!-- Post 4 events: invalid date -->
  <row Id="12" PostHistoryTypeId="1" PostId="400" CreationDate="INVALID-DATE" Text="Undated Post Title" />
  <row Id="13" PostHistoryTypeId="2" PostId="400" CreationDate="INVALID-DATE" Text="Undated Post Body" />
</posthistory>
"""
    posts_xml = b"""<?xml version="1.0" encoding="utf-8"?>
<posts>
  <row Id="100" PostTypeId="1" Score="10" Title="Future Post-Cutoff Title LEAK" Body="Future Post-Cutoff Body LEAK" />
  <row Id="200" PostTypeId="1" Score="0" Title="Future Question Title" Body="Future Question Body" />
  <row Id="300" PostTypeId="1" Score="0" Title="Deleted Post Title" Body="Deleted Post Body" />
</posts>
"""
    report = import_stack_exchange(xml_content, CUTOFF, site_url="https://stackoverflow.com", posts_xml=posts_xml)

    # 1. Post 1 must be kept with its PRE-CUTOFF state, NOT future leak!
    post1_url = "https://stackoverflow.com/questions/100"
    kept_urls = [c["url"] for c in report.kept]
    assert kept_urls == [post1_url]

    # Check that payload contains Pre-Cutoff text, never future leak
    blobs_dict = report.to_blobs_dict()
    post1_entry = report.kept[0]
    post1_html = blobs_dict[post1_entry["payload_sha256"]].decode("utf-8")
    assert "Pre-Cutoff Edited Title" in post1_html
    assert "Pre-Cutoff Edited Body" in post1_html
    assert "Future Post-Cutoff" not in post1_html
    assert "LEAK" not in post1_html

    # Check search document
    post1_doc = report.search_documents[0]
    assert post1_doc["title"] == "Pre-Cutoff Edited Title"
    post1_text = blobs_dict[post1_doc["text_sha256"]].decode("utf-8")
    assert "Pre-Cutoff Edited Body" in post1_text
    assert "LEAK" not in post1_text

    # 2. Post 2 created after cutoff must be in after_cutoff
    assert "https://stackoverflow.com/questions/200" in report.after_cutoff

    # 3. Post 3 deleted before cutoff must be excluded from kept
    assert "https://stackoverflow.com/questions/300" not in kept_urls

    # 4. Post 4 with invalid date must be in undated, never guessed
    assert "https://stackoverflow.com/questions/400" in report.undated


def test_stack_exchange_undelete_restores_post():
    xml = b"""<?xml version="1.0" encoding="utf-8"?>
<posthistory>
  <row Id="1" PostHistoryTypeId="1" PostId="500" CreationDate="2022-01-01T00:00:00Z" Text="Title" />
  <row Id="2" PostHistoryTypeId="2" PostId="500" CreationDate="2022-01-01T00:00:00Z" Text="Body" />
  <row Id="3" PostHistoryTypeId="12" PostId="500" CreationDate="2022-02-01T00:00:00Z" Text="Deleted" />
  <row Id="4" PostHistoryTypeId="13" PostId="500" CreationDate="2022-03-01T00:00:00Z" Text="Undeleted" />
</posthistory>
"""
    report = import_stack_exchange(xml, CUTOFF, site_url="https://stackoverflow.com")
    assert [c["url"] for c in report.kept] == ["https://stackoverflow.com/questions/500"]


# ---------------------------------------------------------------------------
# 5. Hostile Inputs and Caps Tests
# ---------------------------------------------------------------------------

def test_hostile_xml_entity_and_doctype_rejected():
    xml_with_entity = b"""<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <posthistory><row Id="1" PostHistoryTypeId="1" PostId="1" Text="&xxe;" /></posthistory>"""

    with pytest.raises(ArchiveError, match="XML external entities"):
        import_stack_exchange(xml_with_entity, CUTOFF)


def test_oversized_input_rejected():
    oversized = b"WARC/1.1\r\n" * (65 * 1024 * 1024 // 10)
    with pytest.raises(ArchiveError, match="exceeds byte cap"):
        import_common_crawl_warc(oversized, CUTOFF)


def test_gzip_bomb_fails_closed():
    # Construct a high-ratio gzip stream
    bomb = _gzip(b"0" * 10_000_000)
    # Decompress with a tight cap should fail
    with pytest.raises(ArchiveError, match="exceeds byte cap"):
        from hermetic_archive.importers import _bounded_decompress_gzip
        _bounded_decompress_gzip(bomb, cap=1024 * 1024)


# ---------------------------------------------------------------------------
# 6. Environment Independence and Determinism
# ---------------------------------------------------------------------------

def test_importer_determinism_and_environment_independence(monkeypatch):
    xml = b"""<?xml version="1.0" encoding="utf-8"?>
<posthistory>
  <row Id="2" PostHistoryTypeId="2" PostId="1" CreationDate="2022-01-01T00:00:00Z" Text="Body" />
  <row Id="1" PostHistoryTypeId="1" PostId="1" CreationDate="2022-01-01T00:00:00Z" Text="Title" />
</posthistory>
"""
    first_report = import_stack_exchange(xml, CUTOFF)

    # Perturb host environment
    for var in ("HOME", "HOSTNAME", "USER", "TZ", "LANG", "LC_ALL", "SOURCE_DATE_EPOCH"):
        monkeypatch.setenv(var, "host-leak-test")

    second_report = import_stack_exchange(xml, CUTOFF)
    assert first_report == second_report


# ---------------------------------------------------------------------------
# 7. End-to-End Integration with Replay and Search Builders
# ---------------------------------------------------------------------------

def test_e2e_replay_and_search_index_integration():
    url = "https://example.org/python-tutorial"
    html = b"<html><head><title>Python Requests Guide</title></head><body>Learn Python requests library today.</body></html>"
    warc = _warc_record(url, "2023-03-01T12:00:00Z", 200, html)

    report = import_common_crawl_warc(warc, CUTOFF)
    replay_recipe = report.to_replay_recipe(CUTOFF)
    search_recipe = report.to_search_recipe(MONTH)
    replay_blobs = report.to_replay_blobs_dict()
    search_blobs = report.to_search_blobs_dict()

    # 1. Build replay index
    raw_replay_recipe = f.bounded_encoding(replay_recipe)
    replay_build = build_replay_index(raw_replay_recipe, replay_blobs)
    index = ReplayIndex(replay_build.index, dict(replay_build.blobs), f.sha(replay_build.index), CUTOFF)

    resp = index.lookup(url)
    assert resp is not None
    assert resp.status == 200
    assert b"Python requests library" in resp.body

    # 2. Build search index
    raw_search_recipe = f.bounded_encoding(search_recipe)
    search_raw = build_search_index(raw_search_recipe, search_blobs)
    search_idx = SearchIndex(search_raw, f.sha(search_raw), MONTH)

    hits = search_idx.lookup_terms("requests")
    assert url in hits
    hits_python = search_idx.lookup_terms("python guide")
    assert url in hits_python


# ---------------------------------------------------------------------------
# 8. CLI Execution Test
# ---------------------------------------------------------------------------

def test_importer_cli_execution():
    with tempfile.TemporaryDirectory() as tmp_dir:
        warc_path = os.path.join(tmp_dir, "test.warc")
        out_dir = os.path.join(tmp_dir, "out")
        url = "https://example.org/cli-test"
        html = b"<html><head><title>CLI Test</title></head><body>CLI test content</body></html>"
        with open(warc_path, "wb") as f_warc:
            f_warc.write(_warc_record(url, "2023-02-01T00:00:00Z", 200, html))

        from hermetic_archive.__main__ import main
        import sys

        argv_backup = sys.argv
        sys.argv = [
            "hermetic_archive",
            "import-common-crawl-warc",
            "--warc", warc_path,
            "--cutoff", CUTOFF,
            "--output-dir", out_dir,
        ]
        try:
            main()
        finally:
            sys.argv = argv_backup

        assert os.path.exists(os.path.join(out_dir, "replay-recipe.json"))
        assert os.path.exists(os.path.join(out_dir, "search-recipe.json"))
        assert os.path.exists(os.path.join(out_dir, "report.json"))

        # Verify permissions 0600 on files
        st_file = os.stat(os.path.join(out_dir, "replay-recipe.json"))
        assert (st_file.st_mode & 0o777) == 0o600


# ---------------------------------------------------------------------------
# 9. CodeRabbit Review Findings Regression Tests
# ---------------------------------------------------------------------------

def test_regression_stack_exchange_withholds_posts_with_undated_events():
    """Finding 13: Withhold Stack Exchange posts when state-changing events are undated."""
    xml = b"""<?xml version="1.0" encoding="utf-8"?>
<posthistory>
  <row Id="1" PostHistoryTypeId="1" PostId="1" CreationDate="2022-01-01T00:00:00Z" Text="Post 1 Title" />
  <row Id="2" PostHistoryTypeId="2" PostId="1" CreationDate="2022-01-01T00:00:00Z" Text="Post 1 Body" />
  <row Id="3" PostHistoryTypeId="12" PostId="1" CreationDate="INVALID" Text="Post 1 Deletion Undated" />

  <row Id="4" PostHistoryTypeId="1" PostId="2" CreationDate="2022-01-01T00:00:00Z" Text="Post 2 Title" />
  <row Id="5" PostHistoryTypeId="2" PostId="2" CreationDate="2022-01-01T00:00:00Z" Text="Post 2 Body" />
</posthistory>
"""
    report = import_stack_exchange(xml, CUTOFF)
    kept_urls = [c["url"] for c in report.kept]
    assert "https://stackoverflow.com/questions/1" not in kept_urls
    assert "https://stackoverflow.com/questions/1" in report.undated
    assert "https://stackoverflow.com/questions/2" in kept_urls


def test_regression_cli_does_not_follow_symlinks():
    """Finding 14: Do not follow symlinks when writing archive outputs."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_dir = os.path.join(tmp_dir, "out")
        os.makedirs(out_dir, mode=0o700)
        victim = os.path.join(tmp_dir, "victim.txt")
        with open(victim, "w") as vf:
            vf.write("PROTECTED")

        symlink_dest = os.path.join(out_dir, "replay-recipe.json")
        os.symlink(victim, symlink_dest)

        report = ImportReport(
            source="common-crawl",
            kept=(),
            search_documents=(),
            blobs=(),
            after_cutoff=(),
            undated=(),
        )

        with pytest.raises(ArchiveError, match="symlink"):
            _write_outputs(report, CUTOFF, out_dir)

        with open(victim, "r") as vf:
            assert vf.read() == "PROTECTED"


def test_regression_stack_exchange_reconstruction_per_consumer_cutoff():
    """Finding 15: Reconstruct Stack Exchange posts for each consumer's boundary."""
    xml = b"""<?xml version="1.0" encoding="utf-8"?>
<posthistory>
  <row Id="1" PostHistoryTypeId="1" PostId="1" CreationDate="2023-03-01T00:00:00Z" Text="March Title" />
  <row Id="2" PostHistoryTypeId="2" PostId="1" CreationDate="2023-03-01T00:00:00Z" Text="March Body" />
  <row Id="3" PostHistoryTypeId="5" PostId="1" CreationDate="2023-04-05T00:00:00Z" Text="April Body" />

  <row Id="4" PostHistoryTypeId="1" PostId="2" CreationDate="2023-03-01T00:00:00Z" Text="Post 2 Title" />
  <row Id="5" PostHistoryTypeId="2" PostId="2" CreationDate="2023-03-01T00:00:00Z" Text="Post 2 PreCutoff Body" />
  <row Id="6" PostHistoryTypeId="5" PostId="2" CreationDate="2023-04-15T00:00:00Z" Text="Post 2 Exact Cutoff Edit LEAK" />
</posthistory>
"""
    cutoff = "2023-04-15T00:00:00Z"
    report = import_stack_exchange(xml, cutoff)

    # 1. Replay recipe strictly < 2023-04-15T00:00:00Z
    replay_recipe = report.to_replay_recipe(cutoff)
    replay_blobs = report.to_replay_blobs_dict()
    replay_build = build_replay_index(f.bounded_encoding(replay_recipe), replay_blobs)
    idx = ReplayIndex(replay_build.index, dict(replay_build.blobs), f.sha(replay_build.index), cutoff)

    resp1 = idx.lookup("https://stackoverflow.com/questions/1")
    assert resp1 is not None
    assert b"April Body" in resp1.body

    resp2 = idx.lookup("https://stackoverflow.com/questions/2")
    assert resp2 is not None
    assert b"Post 2 PreCutoff Body" in resp2.body
    assert b"Exact Cutoff Edit LEAK" not in resp2.body

    # 2. Search recipe for month 2023-04 (boundary 2023-04-01T00:00:00Z)
    search_recipe = report.to_search_recipe("2023-04")
    search_blobs = report.to_search_blobs_dict("2023-04")
    raw_search = build_search_index(f.bounded_encoding(search_recipe), search_blobs)
    s_idx = SearchIndex(raw_search, f.sha(raw_search), "2023-04")

    hits_march = s_idx.lookup_terms("march")
    assert "https://stackoverflow.com/questions/1" in hits_march
    hits_april = s_idx.lookup_terms("april")
    assert "https://stackoverflow.com/questions/1" not in hits_april


def test_regression_xml_row_cap_exceeded_rejected():
    """Finding 16: Reject history that exceeds the XML row cap."""
    cap = MAX_RECORDS * 4
    rows = [f'<row Id="{i}" PostHistoryTypeId="1" PostId="{i}" CreationDate="2022-01-01T00:00:00Z" Text="T" />' for i in range(cap + 1)]
    xml = f"<posthistory>{''.join(rows)}</posthistory>".encode("utf-8")
    with pytest.raises(ArchiveError, match="XML row cap exceeded"):
        import_stack_exchange(xml, CUTOFF)


def test_regression_warc_record_limit_leaves_captures_unread():
    """Finding 17: Report when the WARC record limit leaves captures unread."""
    non_response = (
        b"WARC/1.1\r\nWARC-Type: warcinfo\r\nWARC-Date: 2022-01-01T00:00:00Z\r\n"
        b"WARC-Record-ID: <urn:uuid:info>\r\nContent-Length: 0\r\n\r\n\r\n\r\n"
    )
    oversized_warc = non_response * (MAX_RECORDS + 1)
    with pytest.raises(ArchiveError, match="WARC record cap exceeded"):
        import_common_crawl_warc(oversized_warc, CUTOFF)

    exact_warc = non_response * MAX_RECORDS
    rep = import_common_crawl_warc(exact_warc, CUTOFF)
    assert len(rep.kept) == 0


def test_regression_extract_html_title_and_text_valid_utf8_truncation():
    """Finding 19: Keep capped search text valid UTF-8."""
    char = "\u20ac"  # 3-byte UTF-8 symbol: \xe2\x82\xac
    count = (MAX_TEXT_BYTES // 3) + 10
    body = f"<html><head><title>Title</title></head><body>{char * count}</body></html>".encode("utf-8")
    title, text_bytes = extract_html_title_and_text(body, fallback_title="Fallback")
    assert len(text_bytes) <= MAX_TEXT_BYTES
    decoded = text_bytes.decode("utf-8")
    assert len(decoded) > 0


def test_regression_cdx_excess_records_rejected():
    """Finding 20: Reject excess CDX records instead of silently dropping them."""
    header = b"CDX a b m s k r\n"
    data_line = b"http://example.com/ 20220101000000 text/html 200 DIGEST -\n"
    text_cdx = header + (data_line * (MAX_RECORDS + 1))
    with pytest.raises(ArchiveError, match="CDX record cap exceeded"):
        import_wayback_cdx(text_cdx, {}, CUTOFF)

    exact_text_cdx = header + (data_line * MAX_RECORDS)
    rep = import_wayback_cdx(exact_text_cdx, {}, CUTOFF)
    assert "http://example.com/" in rep.undated

    header_row = ["url", "timestamp", "mime", "status", "digest"]
    data_row = ["http://example.com/", "20220101000000", "text/html", "200", "DIGEST"]
    json_cdx = json.dumps([header_row] + [data_row] * (MAX_RECORDS + 1)).encode("utf-8")
    with pytest.raises(ArchiveError, match="CDX record cap exceeded"):
        import_wayback_cdx(json_cdx, {}, CUTOFF)

    exact_json_cdx = json.dumps([header_row] + [data_row] * MAX_RECORDS).encode("utf-8")
    rep_json = import_wayback_cdx(exact_json_cdx, {}, CUTOFF)
    assert "http://example.com/" in rep_json.undated


def test_regression_unsupported_content_encoding_rejected():
    """Finding 21: Reject content encodings that the replay recipe cannot represent."""
    http_headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: br\r\n\r\n"
    http_block = http_headers.encode("utf-8") + b"brotli-compressed-bytes"
    warc_headers = (
        "WARC/1.1\r\nWARC-Type: response\r\nWARC-Target-URI: https://example.org/br\r\n"
        "WARC-Date: 2022-01-01T00:00:00Z\r\nWARC-Record-ID: <urn:uuid:br>\r\n"
        f"Content-Length: {len(http_block)}\r\n\r\n"
    )
    raw = warc_headers.encode("utf-8") + http_block + b"\r\n\r\n"
    with pytest.raises(ArchiveError, match="unsupported content encoding"):
        import_common_crawl_warc(raw, CUTOFF)


def test_regression_deflate_bounded_decompression():
    """Finding 22: Bound deflate output before allocating it."""
    large_payload = b"0" * 10000
    compressed = zlib.compress(large_payload)
    with pytest.raises(ArchiveError, match="decompressed archive data exceeds byte cap"):
        _bounded_decompress_http_payload(compressed, "deflate", cap=500)

    small_payload = b"Hello Deflate World"
    comp = zlib.compress(small_payload)
    decomp = _bounded_decompress_http_payload(comp, "deflate", cap=500)
    assert decomp == small_payload


def test_regression_normalize_timestamp_explicit_offset():
    """Finding 23: Normalize explicit timestamp offsets before testing the cutoff."""
    doc = {
        "origin": "https://example.org/repo",
        "date": "2023-03-01T05:00:00+05:00",
        "entries": [
            {"path": "file.txt", "sha256": f.sha(b"Content")}
        ]
    }
    blobs = {f.sha(b"Content"): b"Content"}
    cutoff = "2023-03-01T01:00:00Z"
    rep = import_software_heritage(json.dumps(doc).encode("utf-8"), blobs, cutoff)
    assert len(rep.kept) == 1
    assert rep.kept[0]["captured"] == "2023-03-01T00:00:00Z"


def test_regression_cdx_no_rehashing_on_miss():
    """Finding 24: Do not rehash the blob inventory on each CDX lookup miss."""
    lines = [
        b"CDX a b m s k r",
        b"http://example.com/1 20220101000000 text/html 200 NONEXISTENT1 -",
        b"http://example.com/2 20220101000000 text/html 200 NONEXISTENT2 -",
    ]
    raw = b"\n".join(lines)
    blobs = {f.sha(b"valid"): b"valid"}
    rep = import_wayback_cdx(raw, blobs, CUTOFF)
    assert len(rep.kept) == 0
    assert "http://example.com/1" in rep.undated
    assert "http://example.com/2" in rep.undated


def test_regression_cli_outputs_enforce_private_permissions():
    """Finding 25: Make archive outputs private before writing any bytes."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_dir = os.path.join(tmp_dir, "traversable_out")
        os.makedirs(out_dir, mode=0o777)
        url = "https://example.org/perms-test"
        body = b"hello"
        report = import_common_crawl_warc(_warc_record(url, "2022-01-01T00:00:00Z", 200, body), CUTOFF)
        _write_outputs(report, CUTOFF, out_dir)

        st_dir = os.stat(out_dir)
        assert (st_dir.st_mode & 0o777) == 0o700

        for f_name in ("replay-recipe.json", "search-recipe.json", "report.json"):
            st_file = os.stat(os.path.join(out_dir, f_name))
            assert (st_file.st_mode & 0o777) == 0o600


def test_regression_cli_atomic_staging_preserves_valid_output():
    """Finding 26: Do not replace a valid output set until the new import is complete."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_dir = os.path.join(tmp_dir, "out")
        os.makedirs(out_dir, mode=0o700)
        orig_replay = os.path.join(out_dir, "replay-recipe.json")
        with open(orig_replay, "w") as f_orig:
            f_orig.write("VALID_ORIGINAL_REPLAY")

        def bad_builder(m):
            raise ArchiveError("simulated recipe encoding error")

        report = ImportReport(
            source="common-crawl",
            kept=(),
            search_documents=(),
            blobs=(),
            after_cutoff=(),
            undated=(),
            _search_recipe_builder=bad_builder,
        )

        with pytest.raises(ArchiveError, match="simulated recipe encoding error"):
            _write_outputs(report, CUTOFF, out_dir)

        with open(orig_replay, "r") as f_orig:
            assert f_orig.read() == "VALID_ORIGINAL_REPLAY"


def test_regression_blob_directory_capacity_exceeded():
    """Finding 27: Do not return an order-dependent partial blob inventory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        for i in range(MAX_RECORDS + 1):
            with open(os.path.join(tmp_dir, f"blob_{i}"), "wb") as f_b:
                f_b.write(b"a")
        with pytest.raises(ArchiveError, match="blob directory capacity exceeded"):
            _read_blobs_dir_bounded(tmp_dir)


def test_regression_native_cdx_sha1_base32_matching():
    """Finding 28: Match native CDX SHA-1 base32 digests; unmatched reported as undated."""
    body = b"<html><body>Hello Native CDX</body></html>"
    sha1_digest = hashlib.sha1(body).digest()
    sha1_b32 = base64.b32encode(sha1_digest).decode("ascii")

    line = f"http://example.com/ 20220101000000 text/html 200 {sha1_b32} -\n".encode("utf-8")
    header = b"CDX a b m s k r\n"
    raw_cdx = header + line

    blobs = {f.sha(body): body}
    rep = import_wayback_cdx(raw_cdx, blobs, CUTOFF)
    assert len(rep.kept) == 1
    assert rep.kept[0]["size"] == len(body)
    assert rep.to_blobs_dict()[rep.kept[0]["payload_sha256"]] == body

    line_unmatched = b"http://example.com/unmatched 20220101000000 text/html 200 UNMATCHEDDIGEST -\n"
    rep_unmatched = import_wayback_cdx(header + line_unmatched, blobs, CUTOFF)
    assert len(rep_unmatched.kept) == 0
    assert "http://example.com/unmatched" in rep_unmatched.undated


def test_regression_cli_partitions_search_and_replay_blobs():
    """Finding 29: Write only search text blobs to blobs/ and replay payloads to replay-blobs/."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_dir = os.path.join(tmp_dir, "out")
        url = "https://example.org/test"
        html = b"<html><head><title>Test Page</title></head><body>Unique searchable content</body></html>"
        report = import_common_crawl_warc(_warc_record(url, "2022-01-01T00:00:00Z", 200, html), CUTOFF)

        _write_outputs(report, CUTOFF, out_dir)

        with open(os.path.join(out_dir, "search-recipe.json"), "r") as sf:
            search_rec = json.load(sf)
        search_digests = {doc["text_sha256"] for doc in search_rec["documents"]}
        disk_search_blobs = set(os.listdir(os.path.join(out_dir, "blobs")))
        assert disk_search_blobs == search_digests

        with open(os.path.join(out_dir, "replay-recipe.json"), "r") as rf:
            replay_rec = json.load(rf)
        replay_digests = {cap["payload_sha256"] for cap in replay_rec["captures"]}
        disk_replay_blobs = set(os.listdir(os.path.join(out_dir, "replay-blobs")))
        assert disk_replay_blobs == replay_digests

        with open(os.path.join(out_dir, "search-recipe.json"), "rb") as sf:
            raw_search_rec = sf.read()
        search_blobs_dict = {
            fname: open(os.path.join(out_dir, "blobs", fname), "rb").read()
            for fname in disk_search_blobs
        }
        raw_idx = build_search_index(raw_search_rec, search_blobs_dict)
        s_idx = SearchIndex(raw_idx, f.sha(raw_idx), MONTH)
        assert url in s_idx.lookup_terms("searchable")
