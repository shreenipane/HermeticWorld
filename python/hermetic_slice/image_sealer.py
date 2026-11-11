"""SWE-bench task image sealing and verification."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import json
from pathlib import Path
import shutil

from hermetic_slice.cutoffs import ensure_utc
from hermetic_slice.dockerutil import run_docker
from hermetic_slice.gitutil import run_git
from hermetic_slice.repo_sealer import SealReport, rmtree_force, seal_repo


class ImageSealError(Exception):
    """Raised when sealed image verification fails."""


IN_CONTAINER_MEASURE_BASH = r'''#!/usr/bin/env bash
set -euo pipefail

PY_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PY_BIN=python3
elif command -v python >/dev/null 2>&1; then
    PY_BIN=python
else
    echo "No python found in container" >&2
    exit 1
fi

cat << 'EOF_PYTHON' > /tmp/measure_inner.py
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

def run_git_cmd(*args):
    proc = subprocess.run(
        ["git", "-C", "/testbed", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.returncode, proc.stdout, proc.stderr

def git_stdout(*args):
    code, out, err = run_git_cmd(*args)
    if code != 0:
        raise RuntimeError(f"git {' '.join(args)} failed (exit {code}): {err.decode('utf-8', 'replace')}")
    return out

base = os.environ.get("HERMETIC_BASE", "").strip()
fix_commits_env = os.environ.get("HERMETIC_FIX_COMMITS", "").strip()
fix_commit_targets = [fc.strip() for fc in fix_commits_env.split(",") if fc.strip()]

# Read gold lines from stdin
raw_stdin = sys.stdin.read()
gold_lines_list = [line.strip() for line in raw_stdin.splitlines() if line.strip()]
gold_lines_set = set(gold_lines_list)

head = git_stdout("rev-parse", "HEAD").decode("ascii").strip()
head_is_base = bool(base and head == base)

# branch
code, branch_out, _ = run_git_cmd("symbolic-ref", "--short", "-q", "HEAD")
branch = branch_out.decode("utf-8", "replace").strip() if code == 0 else None
if not branch:
    branch = None

# extra_commits
extra_commits = []
if base and head != base:
    log_out = git_stdout("log", f"{base}..HEAD", "--format=%H%x00%an <%ae>%x00%aI%x00%s").decode("utf-8", "replace")
    for l in log_out.splitlines():
        if not l.strip():
            continue
        parts = l.split("\0")
        if len(parts) >= 4:
            extra_commits.append({
                "sha": parts[0],
                "author": parts[1],
                "author_date": parts[2],
                "subject": parts[3],
            })

# base ancestors
base_ancestors = set()
if base:
    rev_out = git_stdout("rev-list", base).decode("ascii", "replace")
    base_ancestors = {l.strip() for l in rev_out.splitlines() if l.strip()}

# refs
refs_out = git_stdout("for-each-ref", "--format=%(objectname)%00%(*objectname)").decode("ascii", "replace")
refs_total = 0
refs_not_ancestor_of_base = 0
for l in refs_out.splitlines():
    l = l.strip()
    if not l:
        continue
    refs_total += 1
    parts = l.split("\0")
    target = parts[1].strip() if (len(parts) > 1 and parts[1].strip()) else parts[0].strip()
    if target not in base_ancestors:
        refs_not_ancestor_of_base += 1

# base reachable objects
base_reachable_objects = set()
if base:
    code, rev_obj_out, _ = run_git_cmd("rev-list", "--objects", "--no-object-names", base)
    if code == 0:
        base_reachable_objects = {l.strip() for l in rev_obj_out.decode("ascii", "replace").splitlines() if l.strip()}

# objects in store vs reachable
cat_out = git_stdout("cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)").decode("ascii", "replace")
objects_not_reachable_from_base = {
    "commit": 0,
    "tree": 0,
    "blob": 0,
    "tag": 0,
}
unreachable_shas_to_scan = []
store_commits = set()
for l in cat_out.splitlines():
    parts = l.strip().split()
    if len(parts) >= 2:
        sha, otype = parts[0], parts[1]
        if otype == "commit":
            store_commits.add(sha)
        if sha not in base_reachable_objects:
            objects_not_reachable_from_base[otype] = objects_not_reachable_from_base.get(otype, 0) + 1
            if otype in ("blob", "commit", "tag"):
                unreachable_shas_to_scan.append(sha)

commits_in_store_not_reachable_from_base = objects_not_reachable_from_base.get("commit", 0) if base else len(store_commits)

# fix_commits_present
fix_commits_present = []
for fc in fix_commit_targets:
    code, _, _ = run_git_cmd("cat-file", "-e", f"{fc}^{{commit}}")
    if code == 0:
        fix_commits_present.append(fc)

# remotes
remotes_out = git_stdout("remote").decode("utf-8", "replace")
remotes = [r.strip() for r in remotes_out.splitlines() if r.strip()]

# reflog_entries
reflog_code, reflog_out, _ = run_git_cmd("reflog")
reflog_lines = [l for l in reflog_out.decode("utf-8", "replace").splitlines() if l.strip()]
reflog_entries = len(reflog_lines)

# stash_entries
stash_code, stash_out, _ = run_git_cmd("stash", "list")
stash_lines = [l for l in stash_out.decode("utf-8", "replace").splitlines() if l.strip()]
stash_entries = len(stash_lines)

# git_meta_files_present
git_dir = Path("/testbed/.git")
meta_present = []
if (git_dir / "ORIG_HEAD").exists():
    meta_present.append("ORIG_HEAD")
if (git_dir / "FETCH_HEAD").exists():
    meta_present.append("FETCH_HEAD")
logs_dir = git_dir / "logs"
if logs_dir.exists() and any(logs_dir.rglob("*")):
    meta_present.append("logs")
if (git_dir / "COMMIT_EDITMSG").exists():
    meta_present.append("COMMIT_EDITMSG")
hooks_dir = git_dir / "hooks"
if hooks_dir.exists():
    non_sample = [f for f in hooks_dir.iterdir() if not f.name.endswith(".sample")]
    if non_sample:
        meta_present.append("hooks")
git_meta_files_present = meta_present

# tracked_modified_vs_base
if base:
    diff_out = git_stdout("diff", "--name-only", base).decode("utf-8", "replace")
    tracked_modified_vs_base = len([l for l in diff_out.splitlines() if l.strip()])
    # Split into content edits and executable-bit-only flips. SWE-bench's env
    # setup edits some files on purpose (version pins in setup.py, -rA in
    # tox.ini); those are kept. Mode flips are restored by the sealer.
    # numstat, not core.fileMode=false: the index may itself carry the flipped
    # modes. A mode-only change is "0<TAB>0<TAB>path".
    numstat_out = git_stdout("diff", "--no-renames", "--numstat", base).decode("utf-8", "replace")
    tracked_content_modified_vs_base = sorted(
        parts[2] for parts in (l.split("\t", 2) for l in numstat_out.splitlines())
        if len(parts) == 3 and (parts[0], parts[1]) != ("0", "0")
    )
    summary_out = git_stdout("diff", "--summary", base).decode("utf-8", "replace")
    tracked_mode_changes_vs_base = sum(1 for l in summary_out.splitlines() if l.strip().startswith("mode change"))
else:
    tracked_modified_vs_base = 0
    tracked_content_modified_vs_base = []
    tracked_mode_changes_vs_base = 0

# gold_lines_found_in_unreachable (streaming git cat-file --batch)
found_in_unreachable = set()
if gold_lines_set and unreachable_shas_to_scan:
    p = subprocess.Popen(
        ["git", "-C", "/testbed", "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        for sha in unreachable_shas_to_scan:
            if len(found_in_unreachable) == len(gold_lines_set):
                break
            p.stdin.write(sha.encode("ascii") + b"\n")
            p.stdin.flush()
            header = p.stdout.readline()
            if not header:
                break
            parts = header.split()
            if len(parts) >= 3:
                size = int(parts[2])
                to_read = size + 1
                chunks = []
                while to_read > 0:
                    chunk = p.stdout.read(to_read)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    to_read -= len(chunk)
                content = b"".join(chunks)
                data = content[:size]
                for bline in data.splitlines():
                    stripped = bline.strip().decode("utf-8", "ignore")
                    if stripped in gold_lines_set:
                        found_in_unreachable.add(stripped)
            # "<sha> missing" carries no body: skip it and keep scanning.
    finally:
        try:
            if p.stdin:
                p.stdin.close()
            if p.stdout:
                p.stdout.close()
            p.wait()
        except OSError:
            pass
gold_lines_found_in_unreachable = len(found_in_unreachable)

# gold_lines_found_in_tree
found_in_tree = set()
if gold_lines_set:
    testbed_path = Path("/testbed")
    for root, dirs, files in os.walk(testbed_path):
        if ".git" in dirs:
            dirs.remove(".git")
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "rb") as f:
                    for line in f:
                        stripped = line.strip().decode("utf-8", "ignore")
                        if stripped in gold_lines_set:
                            found_in_tree.add(stripped)
            except OSError:
                pass
gold_lines_found_in_tree = len(found_in_tree)

# newest_mtime
max_mtime = 0.0
for root, dirs, files in os.walk("/testbed"):
    for fname in files:
        fpath = os.path.join(root, fname)
        try:
            mt = os.path.getmtime(fpath)
            if mt > max_mtime:
                max_mtime = mt
        except OSError:
            pass
if max_mtime > 0:
    newest_mtime = datetime.fromtimestamp(max_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
else:
    newest_mtime = None

# cache_sizes
cache_sizes = {}
for target in ["/opt/miniconda3/pkgs", "/root/.cache", "/root/.bash_history"]:
    tpath = Path(target)
    if tpath.exists():
        if tpath.is_file() or tpath.is_symlink():
            cache_sizes[target] = tpath.stat().st_size
        else:
            total_sz = 0
            for r, _, flist in os.walk(tpath):
                for fn in flist:
                    try:
                        total_sz += os.path.getsize(os.path.join(r, fn))
                    except OSError:
                        pass
            cache_sizes[target] = total_sz

result = {
    "head": head,
    "head_is_base": head_is_base,
    "branch": branch,
    "extra_commits": extra_commits,
    "refs_total": refs_total,
    "refs_not_ancestor_of_base": refs_not_ancestor_of_base,
    "commits_in_store_not_reachable_from_base": commits_in_store_not_reachable_from_base,
    "objects_not_reachable_from_base": objects_not_reachable_from_base,
    "fix_commits_present": fix_commits_present,
    "remotes": remotes,
    "reflog_entries": reflog_entries,
    "stash_entries": stash_entries,
    "git_meta_files_present": git_meta_files_present,
    "tracked_modified_vs_base": tracked_modified_vs_base,
    "tracked_content_modified_vs_base": tracked_content_modified_vs_base,
    "tracked_mode_changes_vs_base": tracked_mode_changes_vs_base,
    "gold_lines_found_in_unreachable": gold_lines_found_in_unreachable,
    "gold_lines_found_in_tree": gold_lines_found_in_tree,
    "newest_mtime": newest_mtime,
    "cache_sizes": cache_sizes,
}
print(json.dumps(result))
EOF_PYTHON

exec "$PY_BIN" /tmp/measure_inner.py
'''


def gold_lines(task_dir: Path, sealed_repo: Path, base: str) -> list[str]:
    """Extract and baseline-subtract added secret lines from task patches."""
    candidate_lines: set[str] = set()

    staging_dir = task_dir / "staging"
    patch_paths = [
        staging_dir / "gold.patch",
        staging_dir / "test.patch",
    ]

    for p in patch_paths:
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                stripped = line[1:].strip()
                if len(stripped) >= 12:
                    candidate_lines.add(stripped)

    if not candidate_lines:
        return []

    # Baseline subtraction: drop any line that already occurs anywhere in the base tree.
    ls_out = run_git(["ls-tree", "-r", "-z", base], cwd=sealed_repo)
    blob_shas: list[str] = []
    for entry in ls_out.split(b"\0"):
        if not entry:
            continue
        tab_idx = entry.find(b"\t")
        meta = entry[:tab_idx] if tab_idx != -1 else entry
        parts = meta.split()
        if len(parts) >= 3 and parts[1] == b"blob":
            blob_shas.append(parts[2].decode("ascii"))

    unique_blob_shas = sorted(set(blob_shas))
    remaining = set(candidate_lines)

    if unique_blob_shas and remaining:
        input_shas = b"\n".join(sha.encode("ascii") for sha in unique_blob_shas) + b"\n"
        cat_out = run_git(["cat-file", "--batch"], cwd=sealed_repo, input=input_shas)
        idx = 0
        total_len = len(cat_out)
        while idx < total_len and remaining:
            nl = cat_out.find(b"\n", idx)
            if nl == -1:
                break
            header = cat_out[idx:nl].decode("ascii", errors="replace")
            idx = nl + 1
            parts = header.split()
            if len(parts) >= 3 and parts[1] == "blob":
                size = int(parts[2])
                content = cat_out[idx:idx + size]
                idx += size + 1
                for bline in content.splitlines():
                    stripped = bline.strip().decode("utf-8", errors="ignore")
                    if stripped in remaining:
                        remaining.remove(stripped)
                        if not remaining:
                            break
            else:
                break

    return sorted(remaining)


def measure(image: str, task: dict, lines: list[str]) -> dict:
    """Run one container from image and measure git/environment state."""
    base = task.get("base_commit", "")
    fix_commits = task.get("dates", {}).get("fix_commits", [])
    fix_shas = [fc["sha"] if isinstance(fc, dict) else str(fc) for fc in fix_commits]

    input_bytes = "\n".join(lines).encode("utf-8") if lines else b""

    args = [
        "run",
        "--rm",
        "--network", "none",
        "-i",
        "--entrypoint", "/bin/bash",
        "-e", f"HERMETIC_BASE={base}",
        "-e", f"HERMETIC_FIX_COMMITS={','.join(fix_shas)}",
        image,
        "-c",
        IN_CONTAINER_MEASURE_BASH,
    ]
    stdout = run_docker(args, input=input_bytes, check=True)
    return json.loads(stdout.decode("utf-8"))


# SWE-bench's extra HEAD commit flips every tracked file to 100755 in many images
# (django, sympy, astropy, ...): content equals the base, only the executable bit
# differs. With HEAD reset to the base, `git status` would list thousands of
# changes, so restore each tracked file's mode from the base tree. Content is
# never touched.
RESTORE_MODES_SH = r"""#!/bin/bash
set -euo pipefail
TARGET_DIR="${1:-/testbed}"
cd "$TARGET_DIR"

PYTHON_BIN=$(command -v python3 || command -v python)
"$PYTHON_BIN" - "$TARGET_DIR" <<'PY_EOF'
import os
import stat
import subprocess
import sys

target_dir = sys.argv[1]
proc = subprocess.run(
    ["git", "ls-tree", "-r", "-z", "--full-tree", "HEAD"],
    stdout=subprocess.PIPE,
    check=True,
    cwd=target_dir,
)

root_fd = os.open(target_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    for entry in proc.stdout.split(b"\0"):
        if not entry:
            continue
        try:
            meta, path_bytes = entry.split(b"\t", 1)
            mode = meta.split(b" ")[0]
        except ValueError:
            continue

        if mode == b"100644":
            target_mode = 0o644
        elif mode == b"100755":
            target_mode = 0o755
        else:
            continue

        parts = [p for p in path_bytes.split(b"/") if p and p != b"."]
        if not parts or any(p == b".." for p in parts):
            continue

        curr_fd = root_fd
        close_curr = False
        skip = False

        for part in parts[:-1]:
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=curr_fd)
            except OSError:
                skip = True
                break
            if close_curr:
                os.close(curr_fd)
            curr_fd = next_fd
            close_curr = True

        if not skip:
            file_name = parts[-1]
            try:
                file_fd = os.open(file_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=curr_fd)
                try:
                    st = os.fstat(file_fd)
                    if stat.S_ISREG(st.st_mode):
                        os.fchmod(file_fd, target_mode)
                finally:
                    os.close(file_fd)
            except OSError:
                pass

        if close_curr:
            os.close(curr_fd)
finally:
    os.close(root_fd)

subprocess.run(["git", "update-index", "-q", "--refresh"], cwd=target_dir, check=False)
PY_EOF
"""


def render_dockerfile(image: str) -> str:
    """Render Dockerfile text for building the sealed image."""
    return (
        f"FROM {image}\n"
        "RUN rm -rf /testbed/.git /root/.cache /root/.bash_history \\\n"
        " && (conda clean --all --yes || true)\n"
        "COPY sealed.git /testbed/.git\n"
        "COPY restore-modes.sh /tmp/restore-modes.sh\n"
        "RUN bash /tmp/restore-modes.sh && rm -f /tmp/restore-modes.sh\n"
    )


def verification_problems(after: dict, before: dict | None = None) -> list[str]:
    """Verify after report meets all hermetic sealing requirements."""
    problems: list[str] = []
    if not after.get("head_is_base"):
        problems.append("head_is_base is False")
    if after.get("extra_commits") != []:
        problems.append(f"extra_commits is not empty: {after.get('extra_commits')}")
    if after.get("refs_not_ancestor_of_base", 0) != 0:
        problems.append(f"refs_not_ancestor_of_base is {after.get('refs_not_ancestor_of_base')}")
    if after.get("commits_in_store_not_reachable_from_base", 0) != 0:
        problems.append(f"commits_in_store_not_reachable_from_base is {after.get('commits_in_store_not_reachable_from_base')}")
    unreachable_objs = after.get("objects_not_reachable_from_base", {})
    for otype in ("commit", "tree", "blob"):
        if unreachable_objs.get(otype, 0) != 0:
            problems.append(f"unreachable {otype} objects present: {unreachable_objs.get(otype)}")
    for otype, count in unreachable_objs.items():
        if otype not in ("commit", "tree", "blob", "tag") and count != 0:
            problems.append(f"unreachable unexpected {otype} objects present: {count}")
    if after.get("fix_commits_present") != []:
        problems.append(f"fix_commits_present is not empty: {after.get('fix_commits_present')}")
    if after.get("remotes"):
        problems.append(f"remotes present: {after.get('remotes')}")
    if after.get("reflog_entries"):
        problems.append(f"reflog entries present: {after.get('reflog_entries')}")
    if after.get("stash_entries"):
        problems.append(f"stash entries present: {after.get('stash_entries')}")
    if after.get("git_meta_files_present") != []:
        problems.append(f"git_meta_files_present is not empty: {after.get('git_meta_files_present')}")
    if after.get("tracked_mode_changes_vs_base", 0) != 0:
        problems.append(f"tracked_mode_changes_vs_base is {after.get('tracked_mode_changes_vs_base')}")
    content_modified = after.get("tracked_content_modified_vs_base")
    if content_modified is None:
        if after.get("tracked_modified_vs_base", 0) != 0:
            problems.append(f"tracked_modified_vs_base is {after.get('tracked_modified_vs_base')}")
    else:
        # Content edits already in the original image (SWE-bench's env setup) are
        # allowed; anything else means the seal changed the tree.
        allowed = set((before or {}).get("tracked_content_modified_vs_base") or [])
        extra = sorted(set(content_modified) - allowed)
        if extra:
            problems.append(f"tracked files modified vs base that the original image did not modify: {extra[:20]}")
    if after.get("gold_lines_found_in_unreachable", 0) != 0:
        problems.append(f"gold_lines_found_in_unreachable is {after.get('gold_lines_found_in_unreachable')}")
    if after.get("gold_lines_found_in_tree", 0) != 0:
        problems.append(f"gold_lines_found_in_tree is {after.get('gold_lines_found_in_tree')}")
    return problems


def seal_image(task_dir: Path, work_dir: Path, *, tag: str | None = None) -> dict:
    """Measure, seal, and verify a SWE-bench task image."""
    task_json_path = task_dir / "task.json"
    if not task_json_path.exists():
        raise FileNotFoundError(f"Missing task.json in {task_dir}")
    task = json.loads(task_json_path.read_text(encoding="utf-8"))

    image = task["image"]
    base = task["base_commit"]
    t_clock_raw = task["cutoffs"]["t_clock"]
    t_clock = ensure_utc(datetime.fromisoformat(t_clock_raw), "t_clock")
    instance_id = task["instance_id"]

    orig_dir = work_dir / "orig"
    sealed_dir = work_dir / "sealed"
    context_dir = work_dir / "context"

    if orig_dir.exists():
        rmtree_force(orig_dir)
    if sealed_dir.exists():
        rmtree_force(sealed_dir)
    if context_dir.exists():
        rmtree_force(context_dir)
    # A report left by an earlier run must not be read as this run's result.
    (task_dir / "seal" / "report.json").unlink(missing_ok=True)

    orig_dir.mkdir(parents=True, exist_ok=True)

    # Step 2: Extract original repo
    cid = run_docker(["create", image]).decode("utf-8").strip()
    try:
        run_docker(["cp", f"{cid}:/testbed/.git", str(orig_dir / ".git")])
    finally:
        run_docker(["rm", "-f", cid])

    # Step 3: Seal repo
    seal_report = seal_repo(src=orig_dir, base_commit=base, dest=sealed_dir, t_clock=t_clock)

    # Step 4: Gold lines and measure original image
    lines = gold_lines(task_dir, sealed_dir, base)
    before = measure(image, task, lines)

    # Step 5: Build sealed image
    context_dir.mkdir(parents=True, exist_ok=True)
    df_content = render_dockerfile(image)
    (context_dir / "Dockerfile").write_text(df_content, encoding="utf-8", newline="\n")
    (context_dir / "restore-modes.sh").write_text(RESTORE_MODES_SH, encoding="utf-8", newline="\n")
    shutil.copytree(sealed_dir / ".git", context_dir / "sealed.git")

    sealed_tag = tag or f"hermetic/{instance_id.lower()}:sealed"
    run_docker(["build", "--network", "none", "-t", sealed_tag, str(context_dir)])

    # Step 6: Verify sealed image
    after = measure(sealed_tag, task, lines)
    problems = verification_problems(after, before)

    # Step 7: Write report.json (always written before potential raise)
    try:
        inspect_out = run_docker(["image", "inspect", sealed_tag])
        inspect_data = json.loads(inspect_out.decode("utf-8"))
        sealed_image_id = inspect_data[0]["Id"]
    except Exception:
        sealed_image_id = ""

    notes = [
        "file mtimes not normalised (Phase 0, clock: real)",
        "original layers still exist under the sealed image; deleted files are hidden from the container by overlayfs but present in the image tarball (Phase 0 gap; flattened rootfs comes with mke2fs in Phase 2)",
    ]
    if len(lines) == 0:
        notes.append("no checkable gold/test lines after baseline subtraction")
    kept_edits = after.get("tracked_content_modified_vs_base") or []
    if kept_edits:
        notes.append(
            "kept SWE-bench env-setup edits to tracked files (present in the original image, "
            f"checked for gold lines): {', '.join(kept_edits)}"
        )

    status = "failed" if problems else "sealed"
    report_data = {
        "after": after,
        "before": before,
        "gold_lines_checked": len(lines),
        "instance_id": instance_id,
        "notes": notes,
        "original_image": image,
        "problems": problems,
        "schema": "hermetic-slice-seal/v1",
        "seal_report": asdict(seal_report),
        "sealed_image": sealed_tag,
        "sealed_image_id": sealed_image_id,
        "status": status,
    }

    seal_out_dir = task_dir / "seal"
    seal_out_dir.mkdir(parents=True, exist_ok=True)
    (seal_out_dir / "report.json").write_text(
        json.dumps(report_data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    if problems:
        raise ImageSealError("Sealed image verification failed:\n" + "\n".join(problems))

    return report_data
