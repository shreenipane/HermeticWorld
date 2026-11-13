"""Tests for hermetic_classifier (TR-CLS-1, TR-CLS-2)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import pytest

from hermetic_classifier import (
    ClassifierError,
    DEFAULT_MIN_QUALIFYING_LINES,
    EvidenceSpan,
    MalformedDiffError,
    Result,
    ValidationError,
    audit_predicate_to_json,
    build_audit_predicate,
    classify,
    compute_confidence,
    normalize_line,
    parse_patch,
    run_status_hint,
    safe_read_file,
    validate_run_digest,
)
from hermetic_classifier.__main__ import main


# -----------------------------------------------------------------------------
# Fixtures and helpers
# -----------------------------------------------------------------------------

VALID_DIGEST = "sha256:" + "a" * 64


def make_diff(file_path: str, old_lines: list[str], new_lines: list[str], *, start_line: int = 1) -> str:
    """Generate a simple unified git diff for testing."""
    diff_lines = [
        f"diff --git a/{file_path} b/{file_path}",
        f"--- a/{file_path}",
        f"+++ b/{file_path}",
        f"@@ -{start_line},{len(old_lines)} +{start_line},{len(new_lines)} @@",
    ]
    for l in old_lines:
        diff_lines.append(f"-{l}")
    for l in new_lines:
        diff_lines.append(f"+{l}")
    return "\n".join(diff_lines) + "\n"


# -----------------------------------------------------------------------------
# 1. Normalisation Tests
# -----------------------------------------------------------------------------

def test_normalize_line_blank_and_comments():
    """Drop blank lines and pure Python comment lines; preserve code with inline comments."""
    assert normalize_line("") is None
    assert normalize_line("   \t  ") is None
    assert normalize_line("# pure comment") is None
    assert normalize_line("   # indented comment") is None
    assert normalize_line("\t# tab indented comment") is None

    # Code lines with inline comments are kept
    assert normalize_line("x = 1  # inline comment") == "x = 1 # inline comment"


def test_normalize_line_whitespace_collapsing():
    """Strip trailing whitespace, collapse internal runs of spaces and tabs."""
    # Trailing whitespace
    assert normalize_line("x = 1   \t\n") == "x = 1"
    # Multiple spaces and tabs collapsed to single space
    assert normalize_line("def   func(   a, \t  b   ):") == "def func( a, b ):"
    # Leading whitespace collapsed to single space
    assert normalize_line("    return 42") == " return 42"
    assert normalize_line("\t\treturn 42") == " return 42"
    assert normalize_line("  return 42") == " return 42"


# -----------------------------------------------------------------------------
# 2. Exact match with reordered files and shifted hunks
# -----------------------------------------------------------------------------

def test_exact_match_reordered_files_and_shifted_hunks():
    """Exact match succeeds when files are reordered and hunks are shifted."""
    file_a_hunk1_gold = (
        "diff --git a/pkg/alpha.py b/pkg/alpha.py\n"
        "--- a/pkg/alpha.py\n"
        "+++ b/pkg/alpha.py\n"
        "@@ -10,2 +10,3 @@\n"
        " def foo():\n"
        "-    old_val = 1\n"
        "+    new_val = 2\n"
        "+    extra_val = 3\n"
    )
    file_b_hunk1_gold = (
        "diff --git a/pkg/beta.py b/pkg/beta.py\n"
        "--- a/pkg/beta.py\n"
        "+++ b/pkg/beta.py\n"
        "@@ -5,1 +5,1 @@\n"
        "-    pass\n"
        "+    return 42\n"
    )

    # Gold diff: alpha first, then beta
    gold_diff = file_a_hunk1_gold + file_b_hunk1_gold

    # Agent diff: beta first, then alpha with shifted hunk line numbers (line 100 instead of 10)
    file_a_hunk1_agent_shifted = (
        "diff --git a/pkg/alpha.py b/pkg/alpha.py\n"
        "--- a/pkg/alpha.py\n"
        "+++ b/pkg/alpha.py\n"
        "@@ -100,2 +100,3 @@\n"
        " def foo():\n"
        "-    old_val = 1\n"
        "+    new_val = 2\n"
        "+    extra_val = 3\n"
    )
    agent_diff = file_b_hunk1_gold + file_a_hunk1_agent_shifted

    result = classify(agent_diff, gold_diff)
    assert result.exact_match is True
    assert result.label == "retrieved"
    assert result.confidence == 1000
    assert result.added_line_overlap == 1000
    assert len(result.evidence) > 0


# -----------------------------------------------------------------------------
# 3. Whitespace-only and comment-only differences
# -----------------------------------------------------------------------------

def test_whitespace_and_comment_only_differences_still_match():
    """Changes in comments and whitespace formatting still result in exact match."""
    gold_diff = (
        "diff --git a/pkg/mod.py b/pkg/mod.py\n"
        "--- a/pkg/mod.py\n"
        "+++ b/pkg/mod.py\n"
        "@@ -1,1 +1,4 @@\n"
        " def run():\n"
        "+    # Gold explanation comment\n"
        "+    result = 42\n"
        "+    return result\n"
    )
    agent_diff = (
        "diff --git a/pkg/mod.py b/pkg/mod.py\n"
        "--- a/pkg/mod.py\n"
        "+++ b/pkg/mod.py\n"
        "@@ -1,1 +1,5 @@\n"
        " def run():\n"
        "+    # Agent wrote a totally different comment\n"
        "+    \n"
        "+        result   =   42   \n"
        "+\treturn result\n"
    )

    result = classify(agent_diff, gold_diff)
    assert result.exact_match is True
    assert result.label == "retrieved"
    assert result.confidence == 1000


# -----------------------------------------------------------------------------
# 4. One-token change does not match
# -----------------------------------------------------------------------------

def test_one_token_change_does_not_match():
    """A one-token semantic difference causes exact match to fail."""
    gold_lines = [
        "val_alpha = 100",
        "val_bravo = 200",
        "val_charlie = 300",
        "val_delta = 400",
        "val_echo = 500",
        "val_foxtrot = 600",
    ]
    # Agent differs by a single token ('999' instead of '100')
    agent_lines = [
        "val_alpha = 999",
        "val_bravo = 200",
        "val_charlie = 300",
        "val_delta = 400",
        "val_echo = 500",
        "val_foxtrot = 600",
    ]

    gold_diff = make_diff("pkg/mod.py", [], gold_lines)
    agent_diff = make_diff("pkg/mod.py", [], agent_lines)

    result = classify(agent_diff, gold_diff)
    assert result.exact_match is False
    # 5 out of 6 matching = 833 per-mille (above 800 threshold)
    assert result.added_line_overlap == 833
    assert result.label == "retrieved"


def test_one_token_change_below_threshold_is_derived():
    """A one-token difference in a small patch drops overlap below threshold."""
    gold_lines = [
        "statement_one = 1",
        "statement_two = 2",
        "statement_three = 3",
        "statement_four = 4",
        "statement_five = 5",
    ]
    # Agent changes 2 out of 5 statements
    agent_lines = [
        "statement_one = 99",
        "statement_two = 98",
        "statement_three = 3",
        "statement_four = 4",
        "statement_five = 5",
    ]

    gold_diff = make_diff("pkg/mod.py", [], gold_lines)
    agent_diff = make_diff("pkg/mod.py", [], agent_lines)

    result = classify(agent_diff, gold_diff)
    assert result.exact_match is False
    # 3 / 5 = 600 per-mille (< 800)
    assert result.added_line_overlap == 600
    assert result.label == "derived"
    assert result.confidence == 700


# -----------------------------------------------------------------------------
# 5. Overlap threshold boundaries
# -----------------------------------------------------------------------------

def test_overlap_threshold_boundaries():
    """Test exact overlap boundaries at 799‰ and 800‰."""
    # 1000 qualifying lines to test precision
    # For a test of 10 qualifying lines:
    # 7 out of 10 = 700‰ -> derived
    # 8 out of 10 = 800‰ -> retrieved
    gold_lines = [f"qualified_line_{i} = {i * 10}" for i in range(10)]
    gold_diff = make_diff("pkg/mod.py", [], gold_lines)

    # 7 matching lines (700‰)
    agent_7 = gold_lines[:7] + ["unrelated_code_a = 1", "unrelated_code_b = 2", "unrelated_code_c = 3"]
    agent_diff_7 = make_diff("pkg/mod.py", [], agent_7)

    res_7 = classify(agent_diff_7, gold_diff)
    assert res_7.exact_match is False
    assert res_7.added_line_overlap == 700
    assert res_7.label == "derived"

    # 8 matching lines (800‰)
    agent_8 = gold_lines[:8] + ["unrelated_code_a = 1", "unrelated_code_b = 2"]
    agent_diff_8 = make_diff("pkg/mod.py", [], agent_8)

    res_8 = classify(agent_diff_8, gold_diff)
    assert res_8.exact_match is False
    assert res_8.added_line_overlap == 800
    assert res_8.label == "retrieved"

    # Custom threshold boundary: 750‰
    res_custom = classify(agent_diff_7, gold_diff, overlap_threshold_per_mille=750)
    assert res_custom.added_line_overlap == 700
    assert res_custom.label == "derived"

    res_custom_pass = classify(agent_diff_8, gold_diff, overlap_threshold_per_mille=750)
    assert res_custom_pass.added_line_overlap == 800
    assert res_custom_pass.label == "retrieved"


# -----------------------------------------------------------------------------
# 6. Tiny gold patches never give retrieved by overlap alone
# -----------------------------------------------------------------------------

def test_tiny_gold_patches_never_give_retrieved_by_overlap_alone():
    """When qualifying lines < MIN_QUALIFYING_LINES, high overlap alone gives derived."""
    # Gold patch has only 2 qualifying lines (below DEFAULT_MIN_QUALIFYING_LINES = 5)
    gold_lines = [
        "short_fix_one = 100",
        "short_fix_two = 200",
    ]
    gold_diff = make_diff("pkg/mod.py", [], gold_lines)

    # Agent has both lines (100% overlap), but is NOT exact match (adds extra lines)
    agent_lines = [
        "short_fix_one = 100",
        "short_fix_two = 200",
        "agent_extra_line_a = 1",
        "agent_extra_line_b = 2",
    ]
    agent_diff = make_diff("pkg/mod.py", [], agent_lines)

    result = classify(agent_diff, gold_diff)
    assert result.exact_match is False
    assert result.added_line_overlap == 1000
    assert result.label == "derived"
    assert result.confidence == 600  # Documented table value for tiny gold patch

    # If the tiny gold patch IS an exact match, it should be retrieved
    exact_agent_diff = make_diff("pkg/mod.py", [], gold_lines)
    exact_res = classify(exact_agent_diff, gold_diff)
    assert exact_res.exact_match is True
    assert exact_res.label == "retrieved"
    assert exact_res.confidence == 1000


# -----------------------------------------------------------------------------
# 7. Hostile diffs raise typed error MalformedDiffError
# -----------------------------------------------------------------------------

def test_hostile_oversized_diff_raises():
    """A diff exceeding MAX_PATCH_BYTES raises MalformedDiffError."""
    # Create patch larger than 10 MB
    header = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n+"
    oversized = header + ("x" * 10_000_100)
    with pytest.raises(MalformedDiffError, match="exceeds limit"):
        classify(oversized, "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n+ok\n")


def test_hostile_oversized_line_raises():
    """A diff with a line exceeding MAX_LINE_LENGTH raises MalformedDiffError."""
    header = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n+"
    long_line_patch = header + ("y" * 10_005) + "\n"
    with pytest.raises(MalformedDiffError, match="Line length"):
        classify(long_line_patch, "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n+ok\n")


def test_hostile_binary_diff_raises():
    """Binary diffs raise MalformedDiffError."""
    binary_diff_1 = (
        "diff --git a/bin.dat b/bin.dat\n"
        "index 0000000..1111111\n"
        "GIT binary patch\n"
        "literal 5\n"
        "Mc$@<O00001\n"
    )
    with pytest.raises(MalformedDiffError, match="Binary diffs"):
        classify(binary_diff_1, binary_diff_1)

    binary_diff_2 = (
        "diff --git a/bin.dat b/bin.dat\n"
        "Binary files a/bin.dat and b/bin.dat differ\n"
    )
    with pytest.raises(MalformedDiffError, match="Binary diffs"):
        classify(binary_diff_2, binary_diff_2)


def test_hostile_nul_byte_raises():
    """Diff containing NUL bytes raises MalformedDiffError."""
    nul_diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n+\x00bad\n"
    with pytest.raises(MalformedDiffError, match="NUL byte"):
        classify(nul_diff, nul_diff)


def test_hostile_no_headers_raises():
    """Non-empty diff with no headers raises MalformedDiffError."""
    garbage = "def func():\n    return 42\n+ added without header\n"
    with pytest.raises(MalformedDiffError, match="No diff headers"):
        classify(garbage, garbage)


def test_hostile_many_hunks_raises():
    """A diff with runaway hunks (100,000 hunks) raises MalformedDiffError."""
    # Generate hunks exceeding MAX_HUNKS (10,000)
    hunk_block = ["diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py"]
    for i in range(10_005):
        hunk_block.append(f"@@ -{i},0 +{i + 1},1 @@\n+x = {i}")
    massive_diff = "\n".join(hunk_block) + "\n"

    with pytest.raises(MalformedDiffError, match="Hunk count exceeds limit"):
        classify(massive_diff, "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -0,0 +1,1 @@\n+x = 1\n")


# -----------------------------------------------------------------------------
# 8. Determinism and Known-Answer Test
# -----------------------------------------------------------------------------

def test_determinism_known_answer():
    """Known-answer test verifying stable JSON output, exact fields, and no floating-point values."""
    agent_diff = (
        "diff --git a/pkg/calc.py b/pkg/calc.py\n"
        "--- a/pkg/calc.py\n"
        "+++ b/pkg/calc.py\n"
        "@@ -10,1 +10,4 @@\n"
        " def solve():\n"
        "+    init_state = True\n"
        "+    accumulate = 100\n"
        "+    finalize_now = False\n"
    )
    gold_diff = (
        "diff --git a/pkg/calc.py b/pkg/calc.py\n"
        "--- a/pkg/calc.py\n"
        "+++ b/pkg/calc.py\n"
        "@@ -10,1 +10,4 @@\n"
        " def solve():\n"
        "+    init_state = True\n"
        "+    accumulate = 100\n"
        "+    finalize_now = False\n"
    )

    result = classify(agent_diff, gold_diff)
    assert result.exact_match is True
    assert result.label == "retrieved"
    assert result.confidence == 1000

    run_digest = "sha256:" + "0123456789abcdef" * 4
    predicate = build_audit_predicate(
        run_digest=run_digest,
        label=result.label,
        confidence=result.confidence,
        evidence=result.evidence,
    )

    json_compact = audit_predicate_to_json(predicate, indent=None)
    json_pretty = audit_predicate_to_json(predicate, indent=2)

    # 1. Verify JSON structure and sorted keys
    parsed = json.loads(json_compact)
    assert list(parsed.keys()) == ["confidence", "evidence_spans", "label", "run_digest"]
    assert parsed["confidence"] == 1000
    assert parsed["label"] == "retrieved"
    assert parsed["run_digest"] == run_digest
    assert len(parsed["evidence_spans"]) == 3
    assert parsed["evidence_spans"][0] == {"agent_line": 11, "file": "pkg/calc.py", "gold_line": 11}
    assert parsed["evidence_spans"][1] == {"agent_line": 12, "file": "pkg/calc.py", "gold_line": 12}
    assert parsed["evidence_spans"][2] == {"agent_line": 13, "file": "pkg/calc.py", "gold_line": 13}

    # 2. Known SHA256 of deterministic compact JSON
    expected_compact_sha256 = hashlib.sha256(json_compact.encode("utf-8")).hexdigest()
    # Re-running produces exact same bytes
    repeat_compact = audit_predicate_to_json(predicate, indent=None)
    assert hashlib.sha256(repeat_compact.encode("utf-8")).hexdigest() == expected_compact_sha256

    # 3. Verify no floats anywhere in the output
    assert "." not in json_compact.replace("pkg/calc.py", "")


# -----------------------------------------------------------------------------
# 9. Status Rule (TR-CLS-2) Table-Driven Test (All 8 combinations)
# -----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,world_sealed,gate_says_leak,expected_hint",
    [
        ("retrieved", True, True, "review"),
        ("retrieved", True, False, "review"),
        ("retrieved", False, True, None),
        ("retrieved", False, False, "review"),
        ("derived", True, True, "review"),
        ("derived", True, False, None),
        ("derived", False, True, "review"),
        ("derived", False, False, None),
    ],
)
def test_run_status_hint_table_driven(
    label: str,
    world_sealed: bool,
    gate_says_leak: bool,
    expected_hint: str | None,
):
    """Test all 8 combinations of (label, world_sealed, gate_says_leak)."""
    assert run_status_hint(label, world_sealed, gate_says_leak) == expected_hint


def test_run_status_hint_invalid_label():
    """Invalid labels raise ValueError."""
    with pytest.raises(ValueError, match="Invalid label"):
        run_status_hint("unknown", True, False)


# -----------------------------------------------------------------------------
# 10. Audit Record Payload and Validation
# -----------------------------------------------------------------------------

def test_validate_run_digest():
    """Run digest validation enforces 'sha256:' and 64 hex characters."""
    validate_run_digest("sha256:" + "0" * 64)
    validate_run_digest("sha256:" + "abcdef0123456789" * 4)

    # Invalid cases
    with pytest.raises(ValidationError, match="Invalid run_digest"):
        validate_run_digest("sha256:" + "A" * 64)  # Uppercase not allowed
    with pytest.raises(ValidationError, match="Invalid run_digest"):
        validate_run_digest("sha256:" + "0" * 63)  # Too short
    with pytest.raises(ValidationError, match="Invalid run_digest"):
        validate_run_digest("md5:" + "0" * 32)
    with pytest.raises(ValidationError, match="Invalid run_digest"):
        validate_run_digest("not-a-digest")


def test_build_audit_predicate_validation():
    """build_audit_predicate validates confidence, label, and evidence elements."""
    with pytest.raises(ValidationError, match="Invalid label"):
        build_audit_predicate(VALID_DIGEST, label="forged", confidence=1000)

    with pytest.raises(ValidationError, match="Invalid confidence"):
        build_audit_predicate(VALID_DIGEST, label="derived", confidence=1001)

    with pytest.raises(ValidationError, match="Invalid confidence"):
        build_audit_predicate(VALID_DIGEST, label="derived", confidence=-1)

    with pytest.raises(ValidationError, match="Invalid confidence"):
        build_audit_predicate(VALID_DIGEST, label="derived", confidence=True)  # type: ignore

    # Evidence item line numbers must be >= 1
    with pytest.raises(ValidationError, match="line numbers must be >= 1"):
        build_audit_predicate(
            VALID_DIGEST,
            label="derived",
            confidence=900,
            evidence=[{"file": "a.py", "agent_line": 0, "gold_line": 1}],
        )


# -----------------------------------------------------------------------------
# 11. Safe File Reading & Symlink Protection
# -----------------------------------------------------------------------------

def test_safe_read_file_regular_and_bounds(tmp_path: Path):
    """safe_read_file reads normal files and respects size cap."""
    sample = tmp_path / "sample.diff"
    content = "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n+x\n"
    sample.write_text(content, encoding="utf-8")

    read_back = safe_read_file(sample)
    assert read_back == content

    # Size cap
    with pytest.raises(ClassifierError, match="exceeds cap"):
        safe_read_file(sample, max_bytes=10)


def test_safe_read_file_rejects_symlink(tmp_path: Path):
    """safe_read_file strictly refuses to follow symlinks."""
    target = tmp_path / "target.txt"
    target.write_text("secret target", encoding="utf-8")

    link = tmp_path / "link.txt"
    link.symlink_to(target)

    with pytest.raises(ClassifierError, match="Symlinks are rejected"):
        safe_read_file(link)


def test_safe_read_file_rejects_directory(tmp_path: Path):
    """safe_read_file rejects directory paths."""
    sub_dir = tmp_path / "somedir"
    sub_dir.mkdir()

    with pytest.raises(ClassifierError, match="Not a regular file"):
        safe_read_file(sub_dir)


# -----------------------------------------------------------------------------
# 12. CLI Tests
# -----------------------------------------------------------------------------

def test_cli_success(tmp_path: Path, capsys: pytest.CaptureFixture):
    """CLI runs successfully and outputs valid JSON predicate and status hint."""
    agent_file = tmp_path / "agent.patch"
    gold_file = tmp_path / "gold.patch"

    diff_content = (
        "diff --git a/pkg/mod.py b/pkg/mod.py\n"
        "--- a/pkg/mod.py\n"
        "+++ b/pkg/mod.py\n"
        "@@ -1,1 +1,2 @@\n"
        " def foo():\n"
        "+    return 42\n"
    )
    agent_file.write_text(diff_content, encoding="utf-8")
    gold_file.write_text(diff_content, encoding="utf-8")

    rc = main([
        "--agent-patch", str(agent_file),
        "--gold-patch", str(gold_file),
        "--run-digest", VALID_DIGEST,
        "--sealed",
    ])
    assert rc == 0

    captured = capsys.readouterr()
    assert "status_hint: review" in captured.out
    assert VALID_DIGEST in captured.out
    # Parse json portion
    json_part = captured.out.split("status_hint:")[0].strip()
    payload = json.loads(json_part)
    assert payload["label"] == "retrieved"
    assert payload["confidence"] == 1000


def test_cli_errors(tmp_path: Path, capsys: pytest.CaptureFixture):
    """CLI handles errors with exit code 1 and clean error messages."""
    agent_file = tmp_path / "agent.patch"
    gold_file = tmp_path / "gold.patch"
    valid_diff = make_diff("a.py", [], ["x = 1"])
    agent_file.write_text(valid_diff, encoding="utf-8")
    gold_file.write_text(valid_diff, encoding="utf-8")

    # 1. Missing arguments
    assert main([]) == 1

    # 2. Invalid digest
    assert main([
        "--agent-patch", str(agent_file),
        "--gold-patch", str(gold_file),
        "--run-digest", "bad-digest",
    ]) == 1

    # 3. Nonexistent file
    assert main([
        "--agent-patch", str(tmp_path / "nonexistent.patch"),
        "--gold-patch", str(gold_file),
        "--run-digest", VALID_DIGEST,
    ]) == 1

    # 4. Symlink file
    sym = tmp_path / "sym.patch"
    sym.symlink_to(agent_file)
    assert main([
        "--agent-patch", str(sym),
        "--gold-patch", str(gold_file),
        "--run-digest", VALID_DIGEST,
    ]) == 1

    # 5. Malformed diff in file
    bad_file = tmp_path / "bad.patch"
    bad_file.write_text("random corrupted diff without headers\n", encoding="utf-8")
    assert main([
        "--agent-patch", str(bad_file),
        "--gold-patch", str(gold_file),
        "--run-digest", VALID_DIGEST,
    ]) == 1


# -----------------------------------------------------------------------------
# 13. Confidence Table Fixed Mapping Verification
# -----------------------------------------------------------------------------

def test_confidence_table_all_rows():
    """Verify compute_confidence produces expected integer per-mille for all table conditions."""
    # 1. Exact match
    assert compute_confidence(True, True, 1000, 10, 5) == 1000
    assert compute_confidence(True, False, 0, 0, 5) == 1000

    # 2. Retrieved via overlap
    assert compute_confidence(False, True, 1000, 10, 5) == 950
    assert compute_confidence(False, True, 950, 10, 5) == 900
    assert compute_confidence(False, True, 900, 10, 5) == 900
    assert compute_confidence(False, True, 850, 10, 5) == 850
    assert compute_confidence(False, True, 800, 10, 5) == 850

    # 3. Derived
    # Tiny gold patch (< min_qualifying_lines) with high overlap
    assert compute_confidence(False, False, 1000, 3, 5) == 600
    assert compute_confidence(False, False, 850, 2, 5) == 600
    # Overlap 0
    assert compute_confidence(False, False, 0, 10, 5) == 950
    # Overlap 1..200
    assert compute_confidence(False, False, 150, 10, 5) == 900
    assert compute_confidence(False, False, 200, 10, 5) == 900
    # Overlap 201..500
    assert compute_confidence(False, False, 300, 10, 5) == 800
    assert compute_confidence(False, False, 500, 10, 5) == 800
    # Overlap 501..799
    assert compute_confidence(False, False, 600, 10, 5) == 700
    assert compute_confidence(False, False, 799, 10, 5) == 700


# -----------------------------------------------------------------------------
# 14. Standard Diff and File Creation/Deletion Support
# -----------------------------------------------------------------------------

def test_parse_patch_standard_diff():
    """Support parsing unified diffs without 'diff --git' headers."""
    standard_diff = (
        "--- a/simple.py\n"
        "+++ b/simple.py\n"
        "@@ -1,1 +1,2 @@\n"
        " def foo():\n"
        "+    return 999\n"
    )
    parsed = parse_patch(standard_diff)
    assert "simple.py" in parsed
    assert parsed["simple.py"].added_lines == [" return 999"]


def test_parse_patch_file_creation_and_deletion():
    """Support new file creation (--- /dev/null) and file deletion (+++ /dev/null)."""
    create_diff = (
        "diff --git a/new_file.py b/new_file.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/new_file.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+def created():\n"
        "+    pass\n"
    )
    parsed_new = parse_patch(create_diff)
    assert "new_file.py" in parsed_new
    assert len(parsed_new["new_file.py"].added_lines) == 2

    delete_diff = (
        "diff --git a/old_file.py b/old_file.py\n"
        "deleted file mode 100644\n"
        "--- a/old_file.py\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-def deleted():\n"
        "-    pass\n"
    )
    parsed_del = parse_patch(delete_diff)
    assert "old_file.py" in parsed_del
    assert len(parsed_del["old_file.py"].removed_lines) == 2


# -----------------------------------------------------------------------------
# 15. CLI Invocation via subprocess (python -m hermetic_classifier)
# -----------------------------------------------------------------------------

def test_subprocess_cli_module_execution(tmp_path: Path):
    """Verify python -m hermetic_classifier execution via subprocess."""
    import subprocess
    import sys

    agent_file = tmp_path / "agent.patch"
    gold_file = tmp_path / "gold.patch"
    content = make_diff("mod.py", [], ["x = 100000000"])
    agent_file.write_text(content, encoding="utf-8")
    gold_file.write_text(content, encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "hermetic_classifier",
            "--agent-patch",
            str(agent_file),
            "--gold-patch",
            str(gold_file),
            "--run-digest",
            VALID_DIGEST,
            "--gate-leak",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "status_hint: None" in proc.stdout
    assert VALID_DIGEST in proc.stdout



# -----------------------------------------------------------------------------
# 16. Regression tests from review
# -----------------------------------------------------------------------------

def _git_file(path: str, body: list[str], header: str) -> str:
    return "\n".join([f"diff --git a/{path} b/{path}", f"--- a/{path}", f"+++ b/{path}", header, *body]) + "\n"


def test_run_digest_rejects_trailing_newline():
    """'$' would accept a trailing newline; the digest must match the whole string."""
    with pytest.raises(ValidationError, match="Invalid run_digest"):
        validate_run_digest(VALID_DIGEST + "\n")
    with pytest.raises(ValidationError):
        build_audit_predicate(VALID_DIGEST + "\n", label="derived", confidence=900)


def test_rename_to_keeps_real_directory_prefix():
    """'rename to' paths carry no a/ b/ prefix; a real 'b/' directory must be kept."""
    pure_rename = (
        "diff --git a/old.py b/b/mod.py\n"
        "similarity index 100%\n"
        "rename from old.py\n"
        "rename to b/mod.py\n"
    )
    assert list(parse_patch(pure_rename)) == ["b/mod.py"]

    rename_with_hunk = (
        "diff --git a/old.py b/b/mod.py\n"
        "similarity index 90%\n"
        "rename from old.py\n"
        "rename to b/mod.py\n"
        "--- a/old.py\n"
        "+++ b/b/mod.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-value_before = 1\n"
        "+value_after = 2\n"
    )
    modify = _git_file("b/mod.py", ["-value_before = 1", "+value_after = 2"], "@@ -1,1 +1,1 @@")
    assert list(parse_patch(rename_with_hunk)) == ["b/mod.py"]
    assert classify(rename_with_hunk, modify).exact_match is True


def test_overlap_matching_is_linear_in_duplicate_lines():
    """Many identical qualifying lines must not trigger quadratic matching."""
    import time

    count = 40_000
    body = [f"+repeated_value = 1" for _ in range(count)]
    diff = _git_file("pkg/mod.py", body, f"@@ -0,0 +1,{count} @@")
    started = time.monotonic()
    result = classify(diff, diff)
    elapsed = time.monotonic() - started
    assert result.added_line_overlap == 1000
    assert len(result.evidence) == 1000  # MAX_EVIDENCE_COUNT
    # One-to-one matching in order: agent line i pairs with gold line i.
    assert all(span.agent_line == span.gold_line for span in result.evidence)
    assert elapsed < 15.0


def test_git_quoted_path_escapes_are_decoded():
    """core.quotePath output must resolve to the same key as the raw UTF-8 name."""
    quoted = (
        'diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"\n'
        '--- "a/caf\\303\\251.py"\n'
        '+++ "b/caf\\303\\251.py"\n'
        "@@ -0,0 +1,1 @@\n"
        "+menu_item = 'espresso'\n"
    )
    raw = _git_file("café.py", ["+menu_item = 'espresso'"], "@@ -0,0 +1,1 @@")
    assert list(parse_patch(quoted)) == ["café.py"]
    assert classify(quoted, raw).exact_match is True

    bad_escape = quoted.replace("\\303\\251", "\\9")
    with pytest.raises(MalformedDiffError):
        parse_patch(bad_escape)


def test_hunk_counts_must_match_body():
    """Truncated or overlong hunks (declared counts vs body) raise the typed error."""
    truncated = _git_file("a.py", ["+only_one_line = 1"], "@@ -0,0 +1,5 @@")
    with pytest.raises(MalformedDiffError, match="Truncated hunk"):
        parse_patch(truncated)

    truncated_mid = _git_file("a.py", ["+only_one_line = 1"], "@@ -0,0 +1,5 @@") + _git_file(
        "b.py", ["+x_value = 2"], "@@ -0,0 +1,1 @@"
    )
    with pytest.raises(MalformedDiffError):
        parse_patch(truncated_mid)

    too_long = _git_file("a.py", ["-old_value = 0", "+new_value = 1", "+extra_value = 2"], "@@ -1,1 +1,1 @@")
    with pytest.raises(MalformedDiffError):
        parse_patch(too_long)

    with pytest.raises(MalformedDiffError, match="Empty hunk"):
        parse_patch(_git_file("a.py", [], "@@ -1,0 +1,0 @@"))


def test_header_like_content_inside_hunk_is_content():
    """Added '++ x' / removed '-- y' lines are hunk content, never file headers."""
    git_diff = _git_file("pkg/mod.py", ["+++ counter_value", "+other_line = 2"], "@@ -0,0 +1,2 @@")
    parsed = parse_patch(git_diff)
    assert list(parsed) == ["pkg/mod.py"]
    assert parsed["pkg/mod.py"].added_lines == ["++ counter_value", "other_line = 2"]

    std_diff = (
        "--- a/doc.txt\n"
        "+++ b/doc.txt\n"
        "@@ -1,2 +1,2 @@\n"
        "--- old heading text\n"
        "+++ new heading text\n"
        " context line\n"
    )
    parsed_std = parse_patch(std_diff)
    assert list(parsed_std) == ["doc.txt"]
    assert parsed_std["doc.txt"].removed_lines == ["-- old heading text"]
    assert parsed_std["doc.txt"].added_lines == ["++ new heading text"]


def test_unicode_line_separators_are_payload():
    """U+2028, U+2029 and form feed inside a line do not split diff records."""
    diff = _git_file("pkg/mod.py", ["+text_value = 'a b c\x0cd'"], "@@ -0,0 +1,1 @@")
    parsed = parse_patch(diff)
    assert parsed["pkg/mod.py"].added_lines == ["text_value = 'a b c\x0cd'"]


def test_audit_evidence_rejects_non_integral_line_numbers():
    """Fractional, boolean or string line numbers are rejected, not truncated."""
    for bad in (7.9, 7.0, True, "7"):
        with pytest.raises(ValidationError, match="integers"):
            build_audit_predicate(
                VALID_DIGEST, label="derived", confidence=900,
                evidence=[{"file": "a.py", "agent_line": bad, "gold_line": 1}],
            )
    with pytest.raises(ValidationError):
        build_audit_predicate(
            VALID_DIGEST, label="derived", confidence=900,
            evidence=[{"file": 5, "agent_line": 1, "gold_line": 1}],
        )


def test_binary_marker_text_inside_hunk_is_not_binary():
    """Marker text added as content does not make a text diff binary."""
    diff = _git_file(
        "pkg/mod.py",
        ['+message = "GIT binary patch"', "+GIT binary patch", "+Binary files a and b differ"],
        "@@ -0,0 +1,3 @@",
    )
    parsed = parse_patch(diff)
    assert len(parsed["pkg/mod.py"].added_lines) == 3


def test_standard_diff_timestamps_are_not_part_of_path():
    """GNU diff header timestamps (after a TAB) are separated from the file name."""
    with_ts = (
        "--- a/simple.py\t2026-11-01 12:00:00.000000000 +0000\n"
        "+++ b/simple.py\t2026-11-02 08:30:00.000000000 +0000\n"
        "@@ -0,0 +1,1 @@\n"
        "+return_value = 999\n"
    )
    other_ts = with_ts.replace("2026-11-02 08:30", "2025-01-01 00:00")
    assert list(parse_patch(with_ts)) == ["simple.py"]
    assert classify(other_ts, with_ts).exact_match is True


def test_hash_lines_are_code_outside_python_files():
    """Comment dropping applies to Python only; '#include' in C is code."""
    gold = _git_file("src/main.c", ["+#include <alpha_header.h>"], "@@ -0,0 +1,1 @@")
    agent = _git_file("src/main.c", ["+#include <bravo_header.h>"], "@@ -0,0 +1,1 @@")
    assert classify(agent, gold).exact_match is False
    assert parse_patch(gold)["src/main.c"].added_lines == ["#include <alpha_header.h>"]
    # Python comments are still dropped.
    py = _git_file("src/main.py", ["+# just a comment"], "@@ -0,0 +1,1 @@")
    assert parse_patch(py)["src/main.py"].added_lines == []
    assert normalize_line("#include <x.h>", python=False) == "#include <x.h>"


def test_hostile_inputs_raise_typed_error_only():
    """Huge hunk numbers, unencodable text and non-text inputs give MalformedDiffError."""
    ok = make_diff("a.py", [], ["x_value = 1"])
    huge = _git_file("a.py", ["+x_value = 1"], "@@ -" + "9" * 5000 + " +1 @@")
    with pytest.raises(MalformedDiffError):
        classify(huge, ok)
    with pytest.raises(MalformedDiffError):
        classify("diff --git a/a b/a\n\ud800\n", ok)
    with pytest.raises(MalformedDiffError):
        classify(b"diff --git a/a b/a\n", ok)  # type: ignore[arg-type]
    with pytest.raises(MalformedDiffError):
        classify(None, ok)  # type: ignore[arg-type]
    with pytest.raises(MalformedDiffError, match="Hunk without a file header"):
        parse_patch("@@ -0,0 +1,1 @@\n+x_value = 1\n--- a/a.py\n+++ b/a.py\n")
    with pytest.raises(MalformedDiffError, match="Invalid hunk start"):
        parse_patch(_git_file("a.py", ["+x_value = 1"], "@@ -0,0 +0,1 @@"))


def test_hostile_100000_hunks_raise():
    """The brief's 100000-hunk diff raises the typed error."""
    parts = ["diff --git a/a.py b/a.py", "--- a/a.py", "+++ b/a.py"]
    for i in range(100_000):
        parts.append(f"@@ -{i},0 +{i + 1},1 @@")
        parts.append("+x")
    with pytest.raises(MalformedDiffError, match="Hunk count exceeds limit"):
        parse_patch("\n".join(parts) + "\n")


def test_hostile_file_count_raises():
    """More than MAX_FILES file sections raise the typed error."""
    diff = "".join(_git_file(f"f{i}.py", ["+x_value = 1"], "@@ -0,0 +1,1 @@") for i in range(1_001))
    with pytest.raises(MalformedDiffError, match="File count"):
        parse_patch(diff)


def test_absolute_and_traversal_paths_rejected():
    """Absolute or '..' file paths (possible host paths) fail closed."""
    for target in ("/home/someone/repo/x.py", "b/../../etc/passwd"):
        diff = f"--- a/x.py\n+++ {target}\n@@ -0,0 +1,1 @@\n+x_value = 1\n"
        with pytest.raises(MalformedDiffError, match="path"):
            parse_patch(diff)


def test_parse_errors_do_not_echo_patch_content():
    """Error messages name line numbers, never gold or agent patch text."""
    secret = "SECRET_GOLD_TOKEN_42"
    bodies = [
        _git_file("a.py", [secret], "@@ -0,0 +1,1 @@"),
        _git_file("a.py", ["+x"], f"@@ bogus {secret} @@"),
    ]
    for diff in bodies:
        with pytest.raises(MalformedDiffError) as info:
            parse_patch(diff)
        assert secret not in str(info.value)


def test_status_hint_rejects_non_boolean_flags():
    """Truthy strings must not be mistaken for booleans."""
    with pytest.raises(ValidationError):
        run_status_hint("derived", "false", False)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        run_status_hint("retrieved", False, 1)  # type: ignore[arg-type]


def test_classify_rejects_invalid_parameters():
    """Thresholds and minima are validated integers in range."""
    ok = make_diff("a.py", [], ["x_value = 1"])
    for kwargs in (
        {"overlap_threshold_per_mille": 1001},
        {"overlap_threshold_per_mille": -1},
        {"overlap_threshold_per_mille": True},
        {"overlap_threshold_per_mille": 0.8},
        {"min_line_length": -1},
        {"min_qualifying_lines": -1},
    ):
        with pytest.raises(ValidationError):
            classify(ok, ok, **kwargs)


def test_tiny_gold_confidence_follows_configured_threshold():
    """The tiny-gold confidence row applies at or above the configured threshold."""
    assert compute_confidence(False, False, 850, 2, 5, overlap_threshold_per_mille=900) == 700
    gold_lines = [f"tiny_patch_line_{i} = {i}" for i in range(4)]
    agent_lines = gold_lines[:3] + ["something_else_entirely = 9"]
    gold = make_diff("pkg/mod.py", [], gold_lines)
    agent = make_diff("pkg/mod.py", [], agent_lines)
    result = classify(agent, gold, overlap_threshold_per_mille=700)
    assert result.added_line_overlap == 750
    assert result.label == "derived"
    assert result.confidence == 600


def test_audit_evidence_count_is_bounded():
    """More than MAX_EVIDENCE_COUNT evidence spans are refused by the payload builder."""
    spans = [{"file": "a.py", "agent_line": i + 1, "gold_line": i + 1} for i in range(1_001)]
    with pytest.raises(ValidationError, match="limit"):
        build_audit_predicate(VALID_DIGEST, label="retrieved", confidence=900, evidence=spans)


def test_audit_predicate_known_answer_bytes():
    """Fixed input gives fixed JSON bytes (sorted keys, sorted spans, no floats)."""
    agent = (
        "diff --git a/z.py b/z.py\n--- a/z.py\n+++ b/z.py\n@@ -0,0 +1,1 @@\n+zulu_value = 26\n"
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -3,0 +4,2 @@\n+alpha_value = 1\n+bravo_value = 2\n"
    )
    gold = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -0,0 +1,2 @@\n+bravo_value = 2\n+alpha_value = 1\n"
        "diff --git a/z.py b/z.py\n--- a/z.py\n+++ b/z.py\n@@ -0,0 +1,1 @@\n+zulu_value = 26\n"
    )
    result = classify(agent, gold)
    predicate = build_audit_predicate("sha256:" + "0123456789abcdef" * 4, result)
    assert audit_predicate_to_json(predicate, indent=None) == (
        '{"confidence":600,"evidence_spans":['
        '{"agent_line":4,"file":"a.py","gold_line":2},'
        '{"agent_line":5,"file":"a.py","gold_line":1},'
        '{"agent_line":1,"file":"z.py","gold_line":1}],'
        '"label":"derived",'
        '"run_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}'
    )


def test_safe_read_file_rejects_symlinked_parent_directory(tmp_path: Path):
    """No symlink anywhere in the path is followed, not only the last component."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "p.diff").write_text("x", encoding="utf-8")
    link_dir = tmp_path / "linkdir"
    link_dir.symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(ClassifierError, match="Symlinks are rejected"):
        safe_read_file(link_dir / "p.diff")


def test_safe_read_file_rejects_fifo_and_device(tmp_path: Path):
    """FIFOs and character devices are refused without blocking."""
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(ClassifierError, match="Not a regular file"):
        safe_read_file(fifo)
    with pytest.raises(ClassifierError, match="Not a regular file"):
        safe_read_file("/dev/null")


def test_safe_read_file_detects_swap_between_lstat_and_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A file replaced between lstat and open is refused (dev/ino check)."""
    import hermetic_classifier.baseline as baseline

    target = tmp_path / "p.diff"
    target.write_text("original", encoding="utf-8")
    other = tmp_path / "other.diff"
    other.write_text("swapped", encoding="utf-8")
    real_open = os.open

    def swapping_open(path, flags, *args, **kwargs):
        if str(path).endswith("p.diff"):
            os.replace(other, target)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(baseline.os, "open", swapping_open)
    with pytest.raises(ClassifierError, match="swapped"):
        safe_read_file(target)


def test_safe_read_file_rejects_invalid_utf8_and_nul(tmp_path: Path):
    """Undecodable or NUL-containing files raise the typed error."""
    bad = tmp_path / "bad.diff"
    bad.write_bytes(b"\xff\xfe")
    with pytest.raises(MalformedDiffError, match="UTF-8"):
        safe_read_file(bad)
    nul = tmp_path / "nul.diff"
    nul.write_bytes(b"a\x00b")
    with pytest.raises(MalformedDiffError, match="NUL"):
        safe_read_file(nul)


def test_cli_rejects_fifo_and_trailing_newline_digest(tmp_path: Path):
    """CLI exits 1 on a FIFO patch path and on a digest with a trailing newline."""
    gold = tmp_path / "gold.patch"
    gold.write_text(make_diff("a.py", [], ["x_value = 1"]), encoding="utf-8")
    fifo = tmp_path / "agent.fifo"
    os.mkfifo(fifo)
    assert main(["--agent-patch", str(fifo), "--gold-patch", str(gold), "--run-digest", VALID_DIGEST]) == 1
    assert main(["--agent-patch", str(gold), "--gold-patch", str(gold), "--run-digest", VALID_DIGEST + "\n"]) == 1
