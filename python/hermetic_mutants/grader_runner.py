"""Production grader validation runner and pipeline (TR-GR-1, TR-GR-5, TR-GR-8, TR-GR-9).

Bridges the host-side variant validation and E4 oracle analysis with dev-unjailed
or production GraderVMs. In validation mode, each test run boots a fresh GraderVM
on either the "base" or "gold" tree, returning test outcomes.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from hermetic_mutants.differential import (
    DISK_BYTES,
    DifferentialError,
    DiskTamper,
    GradingPlan,
    build_plan,
    decode_disk,
)
from hermetic_mutants.finder import FinderResult, find_base_failing_sites, parse_recorder_log
from hermetic_mutants.rewrite import MutantError
from hermetic_mutants.validate import (
    Runner,
    Selection,
    check_outcomes,
    validate_and_select,
)
from hermetic_oracle.analyse import (
    DEFAULT_MAX_BAD_F2P_PERMILLE,
    OracleError,
    run_oracle_with_runner,
)

MAX_TEST_TEXT_BYTES: int = 16 * 1024 * 1024
MAX_LOG_BYTES: int = 8 * 1024 * 1024
MAX_TIMEOUT_S: float = 6 * 3600.0
VALID_VALIDATION_TREES: tuple[str, str] = ("base", "gold")


class GraderRunnerError(MutantError):
    """Raised when validation runner or pipeline execution fails."""


def _read_file_nofollow(path: str, max_bytes: int) -> bytes:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise GraderRunnerError("invalid file path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise GraderRunnerError("target is not a regular file")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        total = sum(len(c) for c in chunks)
        if total > max_bytes:
            raise GraderRunnerError(f"file exceeds max bytes ({max_bytes})")
        return b"".join(chunks)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class GraderValidationRunner:
    """Invokes a GraderVM command for validation on base or gold trees.

    Contract: ``argv + [tree, TEST_FILE, OUT_DISK]`` where tree is ``"base"`` or
    ``"gold"``; boots a fresh GraderVM on the specified tree with TEST_FILE as
    the hidden test file and writes the 1 MiB result disk image to OUT_DISK.
    The result disk is strictly decoded and validated.
    """

    argv: tuple[str, ...]
    timeout_s: float = 600.0
    env: Mapping[str, str] = field(default_factory=dict)

    def __call__(self, tree: str, text: str) -> Mapping[str, str]:
        if not self.argv:
            raise GraderRunnerError("empty validation runner command")
        if tree not in VALID_VALIDATION_TREES:
            raise GraderRunnerError(f"invalid tree name: {tree!r} (must be 'base' or 'gold')")
        if not isinstance(text, str):
            raise GraderRunnerError("test text must be a string")
        encoded_text = text.encode("utf-8")
        if len(encoded_text) > MAX_TEST_TEXT_BYTES:
            raise GraderRunnerError("test text exceeds size cap")
        if "\x00" in text:
            raise GraderRunnerError("test text contains NUL byte")
        if self.timeout_s <= 0 or self.timeout_s > MAX_TIMEOUT_S:
            raise GraderRunnerError("timeout out of bounds")

        work = tempfile.mkdtemp(prefix="hw-val-")
        try:
            os.chmod(work, 0o700)
            test_path = os.path.join(work, "hidden_test.py")
            out_path = os.path.join(work, "result.img")
            fd = os.open(test_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(encoded_text)

            subprocess.run(
                [*self.argv, tree, test_path, out_path],
                env=dict(self.env),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout_s,
                check=True,
            )
            raw_disk = _read_file_nofollow(out_path, DISK_BYTES)
            run_result = decode_disk(raw_disk)
            expected_vs = hashlib.sha256(encoded_text).hexdigest()
            if run_result.variant_set.lower() != expected_vs.lower():
                raise GraderRunnerError("variant_set_mismatch")
            return check_outcomes(run_result.tests)
        except (subprocess.SubprocessError, OSError, DifferentialError, DiskTamper) as exc:
            raise GraderRunnerError(f"validation runner error on {tree}: {exc}") from exc
        finally:
            shutil.rmtree(work, ignore_errors=True)


def record_base_tree_with_cmd(
    argv: Sequence[str],
    test_file_rel: str,
    test_source: bytes,
    *,
    timeout_s: float = 300.0,
    env: Mapping[str, str] | None = None,
) -> bytes:
    """Obtain recorder log by running an external recorder runner command.

    Contract: ``argv + [TEST_FILE, OUT_LOG]``.
    """
    if not argv:
        raise GraderRunnerError("empty recorder command")
    if not isinstance(test_source, (bytes, bytearray)):
        raise GraderRunnerError("test source must be bytes")
    if len(test_source) > MAX_TEST_TEXT_BYTES:
        raise GraderRunnerError("test source exceeds size cap")

    work = tempfile.mkdtemp(prefix="hw-rec-")
    try:
        os.chmod(work, 0o700)
        test_path = os.path.join(work, "test_file.py")
        log_path = os.path.join(work, "assert_log.json")
        fd = os.open(test_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(test_source)

        sub_env = dict(env or {})
        sub_env["HERMETIC_ASSERT_LOG"] = log_path
        subprocess.run(
            [*argv, test_path, log_path],
            env=sub_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s,
            check=True,
        )
        raw_log = _read_file_nofollow(log_path, MAX_LOG_BYTES)
        parse_recorder_log(raw_log)
        return raw_log
    except (subprocess.SubprocessError, OSError, MutantError) as exc:
        raise GraderRunnerError(f"recorder command failed: {exc}") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)


def record_base_tree_in_repo(
    repo_dir: str,
    test_file_rel: str,
    test_source: bytes,
    *,
    python_bin: str = sys.executable,
    timeout_s: float = 300.0,
    env: Mapping[str, str] | None = None,
) -> bytes:
    """Run tests against base tree in repo_dir with hermetic_assert_recorder."""
    if not isinstance(repo_dir, str) or not repo_dir or not os.path.isdir(repo_dir):
        raise GraderRunnerError("repo_dir must be an existing directory")
    if not isinstance(test_file_rel, str) or not test_file_rel or ".." in test_file_rel.split("/"):
        raise GraderRunnerError("test_file_rel must be a safe relative path")
    if os.path.isabs(test_file_rel):
        raise GraderRunnerError("test_file_rel must not be absolute")
    if len(test_source) > MAX_TEST_TEXT_BYTES:
        raise GraderRunnerError("test source exceeds size cap")

    work = tempfile.mkdtemp(prefix="hw-reclog-")
    try:
        os.chmod(work, 0o700)
        log_path = os.path.join(work, "assert_log.json")
        repo_root = os.path.abspath(repo_dir)
        norm_rel = os.path.normpath(test_file_rel)
        if norm_rel == "." or norm_rel.startswith("..") or os.path.isabs(norm_rel):
            raise GraderRunnerError("test file path escapes repository root")
        target_path = os.path.normpath(os.path.join(repo_root, norm_rel))
        if not (target_path == repo_root or target_path.startswith(repo_root + os.sep)):
            raise GraderRunnerError("test file path escapes repository root")
        if target_path == repo_root:
            raise GraderRunnerError("test file path escapes repository root")

        rel_dir, filename = os.path.split(norm_rel)
        if not filename or filename in (".", ".."):
            raise GraderRunnerError("invalid test file name")
        parts = [p for p in rel_dir.split(os.sep) if p and p != "."]
        if len(parts) > 128:
            raise GraderRunnerError("path depth exceeds limit")

        curr_fd = os.open(repo_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in parts:
                next_fd = -1
                try:
                    try:
                        next_fd = os.open(
                            part,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=curr_fd,
                        )
                    except FileNotFoundError:
                        try:
                            os.mkdir(part, 0o755, dir_fd=curr_fd)
                        except FileExistsError:
                            pass
                        next_fd = os.open(
                            part,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=curr_fd,
                        )
                except BaseException:
                    if next_fd >= 0:
                        os.close(next_fd)
                    raise
                os.close(curr_fd)
                curr_fd = next_fd

            fd = os.open(
                filename,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=curr_fd,
            )
        finally:
            os.close(curr_fd)

        with os.fdopen(fd, "wb") as fh:
            fh.write(test_source)

        sub_env = dict(env or os.environ)
        sub_env["HERMETIC_ASSERT_LOG"] = log_path
        sub_env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

        cmd = [
            python_bin,
            "-s",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-p",
            "hermetic_assert_recorder.plugin",
            "-q",
            test_file_rel,
        ]
        # Pytest on base tree typically exits 1 when FAIL_TO_PASS tests fail, which is expected.
        subprocess.run(
            cmd,
            cwd=repo_dir,
            env=sub_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s,
        )
        raw_log = _read_file_nofollow(log_path, MAX_LOG_BYTES)
        parse_recorder_log(raw_log)
        return raw_log
    except (subprocess.SubprocessError, OSError, MutantError) as exc:
        raise GraderRunnerError(f"base tree recording failed: {exc}") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_e4_oracle(
    runner: Runner,
    test_text: str,
    f2p: Sequence[str],
    p2p: Sequence[str],
    *,
    repeats: int = 3,
    max_bad_f2p_permille: int = DEFAULT_MAX_BAD_F2P_PERMILLE,
) -> dict[str, Any]:
    """Run E4 oracle validation using the injected runner."""
    try:
        return run_oracle_with_runner(
            runner,
            test_text,
            f2p,
            p2p,
            repeats=repeats,
            max_bad_f2p_permille=max_bad_f2p_permille,
        )
    except OracleError as exc:
        raise GraderRunnerError(f"E4 oracle failed: {exc}") from exc


@dataclass(frozen=True)
class ValidationPipelineResult:
    """Full outcome of the validation pipeline."""

    selection: Selection
    oracle: dict[str, Any]
    finder: FinderResult
    plan: GradingPlan
    base_log_sha256: str


def run_validation_pipeline(
    source: bytes,
    test_file: str,
    hidden_lines: Iterable[int],
    seed: str,
    runner: Runner,
    f2p: Sequence[str],
    p2p: Sequence[str],
    *,
    recorder_log: bytes | None = None,
    base_repo_dir: str | None = None,
    recorder_cmd: Sequence[str] | None = None,
    n_equivalents: int = 4,
    repeats: int = 2,
    max_bad_f2p_permille: int = DEFAULT_MAX_BAD_F2P_PERMILLE,
) -> ValidationPipelineResult:
    """Run the complete production validation pipeline (TR-GR-5, TR-GR-8, TR-GR-9).

    1. Obtains the base-tree recorder log (from parameter, repo execution, or runner).
    2. Runs E4 oracle analysis (3 base runs, 3 gold runs) to classify flaky tests.
       Fails closed if the oracle is unusable.
    3. Discovers eligible base-failing assertion sites using the recorder log.
    4. Validates variants and selects R1/R2, excluding E4 flaky tests from comparison.
    5. Builds the differential grading plan.
    """
    if not isinstance(source, (bytes, bytearray)):
        raise GraderRunnerError("source must be bytes")
    try:
        source_text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GraderRunnerError("source is not valid UTF-8") from exc

    # Step 1: Base-tree recorder log
    if recorder_log is not None:
        rec_log = recorder_log
        try:
            parse_recorder_log(rec_log)
        except MutantError as exc:
            raise GraderRunnerError(f"invalid recorder_log supplied: {exc}") from exc
    elif base_repo_dir is not None:
        rec_log = record_base_tree_in_repo(base_repo_dir, test_file, source)
    elif recorder_cmd is not None:
        rec_log = record_base_tree_with_cmd(recorder_cmd, test_file, source)
    else:
        raise GraderRunnerError("must provide recorder_log, base_repo_dir, or recorder_cmd")

    # Step 2: E4 Oracle Wiring
    oracle_report = run_e4_oracle(
        runner,
        source_text,
        f2p,
        p2p,
        repeats=3,
        max_bad_f2p_permille=max_bad_f2p_permille,
    )
    if oracle_report.get("result") != "valid":
        res_label = str(oracle_report.get("result", "invalid"))
        rule_label = str(oracle_report.get("deciding_rule", res_label))
        raise GraderRunnerError(
            f"E4 oracle judged tests {res_label}: {rule_label}"
        )
    flaky_tests = oracle_report.get("flaky", [])

    # Step 3: Base-failing assertion finder
    try:
        finder_res = find_base_failing_sites(source, rec_log, test_file, hidden_lines)
    except MutantError as exc:
        raise GraderRunnerError(f"base-failing assertion finder failed: {exc}") from exc

    if not finder_res.eligible_sites:
        raise GraderRunnerError("no eligible base-failing assertion sites found")

    # Step 4: Validate variants and select R1/R2
    try:
        selection = validate_and_select(
            source,
            test_file,
            seed,
            finder_res.eligible_sites,
            runner,
            n_equivalents=n_equivalents,
            repeats=repeats,
            flaky=flaky_tests,
        )
    except MutantError as exc:
        raise GraderRunnerError(f"variant validation and selection failed: {exc}") from exc

    if selection.r1_text is None or selection.r2_text is None:
        raise GraderRunnerError("failed to select valid R1 and R2 variants")

    # Step 5: Build grading plan
    plan = build_plan(f2p, p2p, selection.mutated_tests, selection.compared_tests)
    base_log_sha256 = hashlib.sha256(rec_log).hexdigest()

    return ValidationPipelineResult(
        selection=selection,
        oracle=oracle_report,
        finder=finder_res,
        plan=plan,
        base_log_sha256=base_log_sha256,
    )
