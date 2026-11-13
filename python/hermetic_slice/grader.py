# Behaviour ported from SWE-bench (MIT License), swebench 5.0.2 harness.
"""Clean grader and oracle checking for hermetic SWE-bench task grading."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import TYPE_CHECKING, Callable
import uuid

from .dockerutil import DockerError, run_docker
from .eval_spec import (
    END_TEST_OUTPUT,
    START_TEST_OUTPUT,
    EvalSpecError,
    prepare_eval_script,
)
from .log_parsers import get_log_parser
from .test_services import load_test_services, service_source


class PatchRejected(Exception):
    """Raised when a patch is rejected due to security or integrity rules."""


class GraderError(Exception):
    """Raised when patch evaluation or grading fails unexpectedly."""


@dataclass(frozen=True)
class FilePatch:
    """Parsed single-file diff chunk."""

    path: str
    old_path: str | None
    text: str
    is_new: bool
    is_deleted: bool
    mode: str | None
    is_binary: bool
    is_symlink: bool


TEST_INFRA_NAMES = frozenset({
    "conftest.py",
    "pytest.ini",
    "tox.ini",
    "sitecustomize.py",
    "usercustomize.py",
})

BAD_MARKERS = [
    ">>>>> Patch Apply Failed",
    ">>>>> Reset Failed",
    ">>>>> Tests Errored",
    ">>>>> Tests Timed Out",
]

TEST_EXIT_CODE_RE = re.compile(r">>>>> Test Exit Code:\s*(-?\d+)")


def split_patch(diff: str) -> list[FilePatch]:
    """Split unified git diff into individual FilePatch records."""
    if not diff:
        return []

    diff_starts = [m.start() for m in re.finditer(r"(?m)^diff --git\s+", diff)]
    if not diff_starts:
        return []

    chunks: list[str] = []
    for i, start in enumerate(diff_starts):
        end = diff_starts[i + 1] if i + 1 < len(diff_starts) else len(diff)
        chunks.append(diff[start:end])

    patches: list[FilePatch] = []
    for chunk in chunks:
        lines = chunk.splitlines()
        first_line = lines[0] if lines else ""

        # Parse diff --git a/path b/path
        p1: str | None = None
        p2: str | None = None
        m_hdr = re.match(r"^diff --git\s+(?:\"?a/(.*?)\"?)\s+(?:\"?b/(.*?)\"?)$", first_line)
        if m_hdr:
            p1 = m_hdr.group(1).strip('"')
            p2 = m_hdr.group(2).strip('"')
        else:
            # Fallback for paths with spaces or alternate shapes
            tokens = first_line.split()
            if len(tokens) >= 4 and tokens[2].startswith("a/") and tokens[3].startswith("b/"):
                p1 = tokens[2][2:].strip('"')
                p2 = tokens[3][2:].strip('"')

        is_new = bool(re.search(r"(?m)^new file mode", chunk) or re.search(r"(?m)^---\s+/dev/null", chunk))
        is_deleted = bool(
            re.search(r"(?m)^deleted file mode", chunk) or re.search(r"(?m)^\+\+\+\s+/dev/null", chunk)
        )
        is_binary = bool("GIT binary patch" in chunk or re.search(r"(?m)^Binary files ", chunk))

        # Mode parsing
        mode: str | None = None
        m_mode = re.search(
            r"(?m)^(?:new file mode|new mode|deleted file mode|old mode)\s+(\d+)",
            chunk,
        )
        if m_mode:
            mode = m_mode.group(1)

        is_symlink = (mode == "120000")

        # Rename headers
        rename_from: str | None = None
        m_rf = re.search(r"(?m)^rename from\s+(.*)", chunk)
        if m_rf:
            rename_from = m_rf.group(1).strip().strip('"')

        rename_to: str | None = None
        m_rt = re.search(r"(?m)^rename to\s+(.*)", chunk)
        if m_rt:
            rename_to = m_rt.group(1).strip().strip('"')

        # --- and +++ lines
        minus_path: str | None = None
        m_minus = re.search(r"(?m)^---\s+(?:\"?a/(.*?)\"?|/dev/null)$", chunk)
        if m_minus and m_minus.group(1):
            minus_path = m_minus.group(1).strip().strip('"')

        plus_path: str | None = None
        m_plus = re.search(r"(?m)^\+\+\+\s+(?:\"?b/(.*?)\"?|/dev/null)$", chunk)
        if m_plus and m_plus.group(1):
            plus_path = m_plus.group(1).strip().strip('"')

        # Determine old_path
        if rename_from:
            old_path = rename_from
        elif minus_path:
            old_path = minus_path
        elif is_new:
            old_path = None
        else:
            old_path = p1

        # Determine path
        if rename_to:
            path = rename_to
        elif plus_path:
            path = plus_path
        elif is_deleted:
            path = old_path or p1 or ""
        else:
            path = p2 or p1 or ""

        patches.append(
            FilePatch(
                path=path,
                old_path=old_path,
                text=chunk,
                is_new=is_new,
                is_deleted=is_deleted,
                mode=mode,
                is_binary=is_binary,
                is_symlink=is_symlink,
            )
        )

    return patches


def validate_patch(diff: str, *, test_files: set[str]) -> tuple[str, list[dict]]:
    """Validate patch according to architecture §10 rules; return kept diff and findings."""
    patches = split_patch(diff)
    if not patches:
        if diff.strip():
            # Never silently grade a non-empty submission as the empty patch.
            raise PatchRejected("Non-empty patch has no 'diff --git' file sections")
        return ("", [])

    # 1. Whole patch rejection rules
    for fp in patches:
        paths_to_check = [p for p in (fp.path, fp.old_path) if p]
        for p in paths_to_check:
            norm = p.replace("\\", "/")
            if norm.startswith("/"):
                raise PatchRejected(f"Absolute path not allowed: {p}")
            parts = norm.split("/")
            if ".." in parts:
                raise PatchRejected(f"Path traversal '..' not allowed: {p}")

        if fp.is_symlink or fp.mode == "120000":
            raise PatchRejected(f"Symlink (mode 120000) not allowed: {fp.path}")

        if fp.is_binary:
            raise PatchRejected(f"Binary patch not allowed: {fp.path}")

        if fp.mode is not None:
            if fp.mode == "160000":
                raise PatchRejected(f"Submodule (mode 160000) not allowed: {fp.path}")
            if fp.mode not in ("100644", "100755"):
                raise PatchRejected(f"Disallowed mode {fp.mode}: {fp.path}")

    # 2. File section drop rules and findings
    # Known Phase 0 gap: section-level restore of setup.cfg and pyproject.toml.
    findings: list[dict] = []
    kept_chunks: list[str] = []

    for fp in patches:
        paths_to_check = [p for p in (fp.path, fp.old_path) if p]
        should_drop = False
        for p in paths_to_check:
            norm = p.replace("\\", "/")
            base_name = norm.split("/")[-1]
            parts = norm.split("/")

            if p in test_files or norm in test_files:
                should_drop = True
                break
            if base_name in TEST_INFRA_NAMES:
                should_drop = True
                break
            if base_name.endswith(".pth"):
                should_drop = True
                break
            if any(part.endswith(".egg-info") or part.endswith(".dist-info") for part in parts):
                should_drop = True
                break

        if should_drop:
            findings.append({
                "detector": "D11",
                "kind": "test_infra_restored",
                "path": fp.path,
            })
        else:
            kept_chunks.append(fp.text)
            # Stdlib shadowing check for new top-level modules or packages
            if fp.is_new:
                norm = fp.path.replace("\\", "/")
                parts = norm.split("/")
                mod_name: str | None = None
                if len(parts) == 1 and parts[0].endswith(".py"):
                    mod_name = parts[0][:-3]
                elif len(parts) >= 2 and parts[1] == "__init__.py":
                    mod_name = parts[0]

                if mod_name and mod_name in sys.stdlib_module_names:
                    findings.append({
                        "detector": "D11",
                        "kind": "stdlib_shadowing",
                        "module": mod_name,
                        "path": fp.path,
                    })

    kept_diff = "".join(kept_chunks)
    return kept_diff, findings


def parse_test_exit_code(content: str) -> int | None:
    """Extract SWEBENCH_TEST_EXIT_CODE from log output if recorded."""
    m = TEST_EXIT_CODE_RE.search(content)
    return int(m.group(1)) if m else None


def _resolve_case(case: str, sm: dict[str, str]) -> str | None:
    """Return status map key for case, supporting truncated parameter ids."""
    if case in sm:
        return case
    if case.count("[") > case.count("]"):
        matches = [k for k in sm if k.startswith(case)]
        passing = {"PASSED", "XFAIL"}
        if matches and len({sm[k] in passing for k in matches}) == 1:
            return matches[0]
    return None


def test_passed(case: str, sm: dict[str, str]) -> bool:
    """True if test resolved to PASSED or XFAIL."""
    key = _resolve_case(case, sm)
    return key is not None and sm[key] in ("PASSED", "XFAIL")


def test_maintained(case: str, sm: dict[str, str]) -> bool:
    """True if test maintained its passing or skipped state (P2P semantics)."""
    key = _resolve_case(case, sm)
    return test_passed(case, sm) or (key is not None and sm[key] == "SKIPPED")


def evaluate_log(
    content: str,
    parser: Callable[[str], dict[str, str]],
) -> tuple[dict[str, str] | None, int | None]:
    """Parse log content using official get_logs_eval rules."""
    exit_code = parse_test_exit_code(content)

    for bad in BAD_MARKERS:
        if bad in content:
            return None, exit_code

    if START_TEST_OUTPUT not in content or END_TEST_OUTPUT not in content:
        return None, exit_code

    sliced = content.split(START_TEST_OUTPUT)[1].split(END_TEST_OUTPUT)[0]
    status_map = parser(sliced)
    if not status_map:
        status_map = parser(content)

    if not status_map:
        return None, exit_code

    if exit_code not in (None, 0):
        if not any(st in ("FAILED", "ERROR") for st in status_map.values()):
            return None, exit_code

    return status_map, exit_code


def grade_status_map(
    status_map: dict[str, str] | None,
    f2p_targets: list[str],
    p2p_targets: list[str],
) -> tuple[str, bool, dict[str, list[str]], dict[str, list[str]]]:
    """Evaluate F2P and P2P success/failure lists and overall resolution status."""
    if status_map is None:
        return (
            "RESOLVED_NO",
            False,
            {"failure": list(f2p_targets), "success": []},
            {"failure": list(p2p_targets), "success": []},
        )

    f2p_success: list[str] = []
    f2p_failure: list[str] = []
    for case in f2p_targets:
        if test_passed(case, status_map):
            f2p_success.append(case)
        else:
            f2p_failure.append(case)

    p2p_success: list[str] = []
    p2p_failure: list[str] = []
    for case in p2p_targets:
        if test_maintained(case, status_map):
            p2p_success.append(case)
        else:
            p2p_failure.append(case)

    f2p_total = len(f2p_success) + len(f2p_failure)
    f2p_rate = len(f2p_success) / f2p_total if f2p_total > 0 else 1.0

    p2p_total = len(p2p_success) + len(p2p_failure)
    p2p_rate = len(p2p_success) / p2p_total if p2p_total > 0 else 1.0

    if f2p_rate == 1.0 and p2p_rate == 1.0:
        resolution = "RESOLVED_FULL"
    elif 0.0 < f2p_rate < 1.0 and p2p_rate == 1.0:
        resolution = "RESOLVED_PARTIAL"
    else:
        resolution = "RESOLVED_NO"

    resolved = (resolution == "RESOLVED_FULL")
    return (
        resolution,
        resolved,
        {"failure": f2p_failure, "success": f2p_success},
        {"failure": p2p_failure, "success": p2p_success},
    )


def grade(
    task_dir: Path,
    patch_text: str,
    *,
    image: str,
    out_dir: Path,
    timeout: int = 1800,
) -> dict:
    """Grade a patch in a fresh container with no network, logging results to out_dir."""
    task_dir = Path(task_dir)
    out_dir = Path(out_dir)

    t0 = time.time()
    patch_sha256 = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()

    # Step 1: Load staging/eval.sh and eval_spec.json
    staging_dir = task_dir / "staging"
    eval_sh_path = staging_dir / "eval.sh"
    eval_spec_path = staging_dir / "eval_spec.json"

    if not eval_sh_path.exists():
        raise GraderError(f"Missing eval.sh in {staging_dir}")
    if not eval_spec_path.exists():
        raise GraderError(f"Missing eval_spec.json in {staging_dir}")

    eval_sh_bytes = eval_sh_path.read_bytes()
    eval_spec = json.loads(eval_spec_path.read_text(encoding="utf-8"))

    expected_sha = eval_spec.get("eval_sh_sha256") or eval_spec.get("sha256")
    actual_sha = hashlib.sha256(eval_sh_bytes).hexdigest()
    if actual_sha != expected_sha:
        raise EvalSpecError(f"eval.sh sha256 mismatch: {actual_sha} vs {expected_sha}")

    script_for_grader, removed_eval_lines = prepare_eval_script(eval_sh_bytes.decode("utf-8"))

    task_json = json.loads((task_dir / "task.json").read_text(encoding="utf-8"))
    services = load_test_services(task_dir, task_json)
    source = service_source() if services.names else None
    out_dir.mkdir(parents=True, exist_ok=True)
    instance_id = task_json["instance_id"]
    f2p_targets = task_json.get("tests", {}).get("FAIL_TO_PASS", [])
    p2p_targets = task_json.get("tests", {}).get("PASS_TO_PASS", [])

    # Step 2: Validate patch
    test_patch_path = staging_dir / "test.patch"
    if not test_patch_path.exists():
        raise GraderError(f"Missing test.patch in {staging_dir}")
    test_patch_text = test_patch_path.read_text(encoding="utf-8")
    test_patches = split_patch(test_patch_text)
    test_files = {p.path for p in test_patches} | {p.old_path for p in test_patches if p.old_path}

    try:
        kept_diff, findings = validate_patch(patch_text, test_files=test_files)
    except PatchRejected as exc:
        duration_s = time.time() - t0
        result = {
            "duration_s": duration_s,
            "f2p": {"failure": list(f2p_targets), "success": []},
            "findings": [{"detector": "D11", "kind": "patch_rejected", "reason": str(exc)}],
            "image": image,
            "instance_id": instance_id,
            "network": "none",
            "p2p": {"failure": list(p2p_targets), "success": []},
            "patch_sha256": patch_sha256,
            "removed_eval_lines": removed_eval_lines,
            "resolution": "RESOLVED_NO",
            "resolved": False,
            "schema": "hermetic-slice-grade/v1",
            "status": "patch_rejected",
            "test_exit_code": None,
        }
        (out_dir / "grade.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result

    # Step 3: Create container
    random_id = uuid.uuid4().hex[:12]
    cid_name = f"hermetic-grade-{random_id}"

    run_docker([
        "create",
        "--network", "none",
        "--name", cid_name,
        "--entrypoint", "/bin/bash",
        image,
        "-c", "sleep infinity",
    ])

    try:
        run_docker(["start", cid_name])

        with tempfile.TemporaryDirectory(prefix="grader_staging_") as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)
            eval_file = tmp_dir / "eval.sh"
            eval_file.write_text(script_for_grader, encoding="utf-8", newline="\n")
            run_docker(["cp", str(eval_file), f"{cid_name}:/eval.sh"])

            # Step 4: Apply patch if kept_diff isn't empty
            if kept_diff.strip():
                patch_file = tmp_dir / "patch.diff"
                patch_file.write_text(kept_diff, encoding="utf-8", newline="\n")
                run_docker(["cp", str(patch_file), f"{cid_name}:/tmp/patch.diff"])

                apply_chain = [
                    "git apply --verbose",
                    "git apply --verbose --3way",
                    "git apply --verbose --reject",
                    "patch --batch --forward --fuzz=5 -p1 -i",
                ]
                # The sealed tree carries kept env-setup edits (unstaged) and may hold untracked
                # files. Snapshot it as a throwaway commit so a failed fallback attempt is undone
                # back to exactly this state, not to the index; HEAD and index are restored after.
                snap_script = (
                    "set -e; ORIG=$(git rev-parse HEAD); "
                    "git -c core.hooksPath=/dev/null add -A; "
                    "git -c core.hooksPath=/dev/null -c user.name=hermetic -c user.email=hermetic@localhost "
                    "commit -q --allow-empty --no-verify -m pre-apply; "
                    "echo $ORIG $(git rev-parse HEAD)"
                )
                orig_sha, snap_sha = (
                    run_docker(["exec", "-w", "/testbed", cid_name, "/bin/bash", "-c", snap_script])
                    .decode("ascii").split()[-2:]
                )
                applied = False
                last_apply_out = ""
                for attempt, cmd in enumerate(apply_chain):
                    if attempt > 0:
                        run_docker(
                            ["exec", "-w", "/testbed", cid_name, "/bin/bash", "-c",
                             f"git reset -q --hard {snap_sha} && git clean -fdq"],
                            check=False,
                        )
                    try:
                        run_docker(
                            ["exec", "-w", "/testbed", cid_name, "/bin/bash", "-c", f"{cmd} /tmp/patch.diff"],
                            combine_output=True,
                        )
                        applied = True
                        break
                    except DockerError as exc:
                        last_apply_out = exc.stderr

                if not applied:
                    try:
                        run_docker([
                            "exec", "-w", "/testbed", cid_name,
                            "/bin/bash", "-c", "git apply --check --reverse /tmp/patch.diff",
                        ])
                        applied = True
                    except DockerError:
                        pass

                run_docker(
                    ["exec", "-w", "/testbed", cid_name, "/bin/bash", "-c", f"git reset -q --mixed {orig_sha}"],
                )

                if not applied:
                    duration_s = time.time() - t0
                    (out_dir / "test_output.txt").write_text(
                        f">>>>> Patch Apply Failed\n{last_apply_out}", encoding="utf-8"
                    )
                    result = {
                        "duration_s": duration_s,
                        "f2p": {"failure": list(f2p_targets), "success": []},
                        "findings": findings,
                        "image": image,
                        "instance_id": instance_id,
                        "network": "none",
                        "p2p": {"failure": list(p2p_targets), "success": []},
                        "patch_sha256": patch_sha256,
                        "removed_eval_lines": removed_eval_lines,
                        "resolution": "RESOLVED_NO",
                        "resolved": False,
                        "schema": "hermetic-slice-grade/v1",
                        "status": "patch_apply_failed",
                        "test_exit_code": None,
                    }
                    (out_dir / "grade.json").write_text(
                        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                    )
                    return result

        # Step 5: Run /eval.sh with timeout
        timed_out = False
        test_output = ""
        try:
            # check=False: the eval script's own exit status is not the verdict.
            out = run_docker(
                services.command(cid_name),
                **({"input": source} if source is not None else {}),
                check=False,
                timeout=timeout,
                combine_output=True,
            )
            test_output = out.decode("utf-8", "replace")
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            run_docker(["kill", cid_name], check=False)
            test_output = (exc.stdout or b"").decode("utf-8", "replace")
            test_output += f"\n\n>>>>> Tests Timed Out\nTimeout error: {timeout} seconds exceeded."

        (out_dir / "test_output.txt").write_text(test_output, encoding="utf-8")

        if timed_out:
            duration_s = time.time() - t0
            result = {
                "duration_s": duration_s,
                "f2p": {"failure": list(f2p_targets), "success": []},
                "findings": findings,
                "image": image,
                "instance_id": instance_id,
                "network": "none",
                "p2p": {"failure": list(p2p_targets), "success": []},
                "patch_sha256": patch_sha256,
                "removed_eval_lines": removed_eval_lines,
                "resolution": "RESOLVED_NO",
                "resolved": False,
                "schema": "hermetic-slice-grade/v1",
                "status": "timeout",
                "test_exit_code": None,
            }
            (out_dir / "grade.json").write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return result

        # Step 7: Grade the log
        parser_name = eval_spec.get("log_parser", "")
        parser_fn = get_log_parser(parser_name)
        status_map, exit_code = evaluate_log(test_output, parser_fn)
        duration_s = time.time() - t0

        if status_map is None:
            status = "log_unparsed"
            resolution = "RESOLVED_NO"
            resolved = False
            f2p = {"failure": list(f2p_targets), "success": []}
            p2p = {"failure": list(p2p_targets), "success": []}
        else:
            status = "graded"
            resolution, resolved, f2p, p2p = grade_status_map(status_map, f2p_targets, p2p_targets)

        result = {
            "duration_s": duration_s,
            "f2p": f2p,
            "findings": findings,
            "image": image,
            "instance_id": instance_id,
            "network": "none",
            "p2p": p2p,
            "patch_sha256": patch_sha256,
            "removed_eval_lines": removed_eval_lines,
            "resolution": resolution,
            "resolved": resolved,
            "schema": "hermetic-slice-grade/v1",
            "status": status,
            "test_exit_code": exit_code,
            "test_services": list(services.names),
        }
        (out_dir / "grade.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result

    finally:
        # Step 6: Always remove the container
        run_docker(["rm", "-f", cid_name], check=False)


def oracle_check(
    task_dir: Path,
    *,
    image: str,
    out_root: Path,
    timeout: int = 1800,
) -> dict:
    """Run gold and empty patch evaluations; record oracle.json."""
    task_dir = Path(task_dir)
    out_root = Path(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    gold_patch_path = task_dir / "staging" / "gold.patch"
    if not gold_patch_path.exists():
        raise GraderError(f"Missing gold.patch in {task_dir / 'staging'}")
    # Bytes, not read_text: universal newlines would turn a CRLF file's \r\n into \n.
    gold_patch = gold_patch_path.read_bytes().decode("utf-8")

    gold_out = out_root / "gold"
    gold_grade = grade(task_dir, gold_patch, image=image, out_dir=gold_out, timeout=timeout)

    empty_out = out_root / "empty"
    empty_grade = grade(task_dir, "", image=image, out_dir=empty_out, timeout=timeout)

    gold_resolved = bool(gold_grade.get("resolved", False))
    # Only a completed empty-patch grade shows that the base fails: a timeout, apply failure
    # or rejected run lists every target as failing without having run them.
    empty_graded = empty_grade.get("status") == "graded"
    empty_f2p_success = empty_grade.get("f2p", {}).get("success", [])
    empty_f2p_all_fail = empty_graded and len(empty_f2p_success) == 0
    empty_f2p_failures = empty_grade.get("f2p", {}).get("failure", [])

    empty_p2p_failures = empty_grade.get("p2p", {}).get("failure", [])
    gold_f2p_failures = gold_grade.get("f2p", {}).get("failure", [])
    gold_p2p_failures = gold_grade.get("p2p", {}).get("failure", [])

    # Some upstream FAIL_TO_PASS lists include tests that already pass without the fix
    # (django__django-11099 lists test_help_text). The task still discriminates as long as
    # the empty patch is not resolved; those tests are recorded, not hidden.
    empty_resolved = bool(empty_grade.get("resolved", False))
    oracle_ok = bool(empty_graded and gold_resolved and not empty_resolved and empty_f2p_failures)

    oracle_result = {
        "empty_f2p_all_fail": empty_f2p_all_fail,
        "empty_graded": empty_graded,
        "empty_resolved": empty_resolved,
        "f2p_pass_without_fix": sorted(empty_f2p_success),
        "empty_p2p_failures": empty_p2p_failures,
        "gold_f2p_failures": gold_f2p_failures,
        "gold_p2p_failures": gold_p2p_failures,
        "gold_resolved": gold_resolved,
        "instance_id": task_dir.name,
        "oracle_ok": oracle_ok,
        "schema": "hermetic-slice-oracle/v1",
    }
    (out_root / "oracle.json").write_text(
        json.dumps(oracle_result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return oracle_result
