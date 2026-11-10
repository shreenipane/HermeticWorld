"""Patch extraction from untrusted agent container using clean extractor."""

from __future__ import annotations

import hashlib
from pathlib import Path
import secrets
from typing import Any

from hermetic_slice.dockerutil import DockerError, run_docker


class ExtractError(Exception):
    """Raised when extraction fails or patch is too large."""


def extract_patch(
    agent_container: str,
    sealed_image: str,
    work_dir: Path,
    *,
    max_patch_bytes: int = 5_000_000,
) -> tuple[str, dict[str, Any]]:
    """Extract agent's patch against the clean sealed image.

    Returns (patch_text, report_dict).
    """
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    rand_id = secrets.token_hex(6)
    tar_path = work_dir / f"agent_testbed_{rand_id}.tar"
    patch_path = work_dir / f"extracted_{rand_id}.diff"
    extractor_container = f"hermetic-extract-{rand_id}"

    try:
        # 1. Stream docker cp <agent>:/testbed - to a file in work_dir
        run_docker(["cp", f"{agent_container}:/testbed", "-"], stdout_path=tar_path, check=True)
        tar_bytes = tar_path.stat().st_size

        # 2. Create extractor container from sealed image
        run_docker([
            "run",
            "-d",
            "--name", extractor_container,
            "--network", "none",
            "--entrypoint", "/bin/bash",
            sealed_image,
            "-c", "sleep infinity",
        ], check=True)

        # Copy the tar into it
        run_docker(["cp", str(tar_path), f"{extractor_container}:/tmp/agent.tar"], check=True)

        # 3. Inside the extractor, record clean state, wipe testbed, extract tar without .git, and diff
        script = (
            "set -euo pipefail\n"
            "cd /testbed\n"
            "git -c core.hooksPath=/dev/null add -A\n"
            "git -c core.hooksPath=/dev/null -c user.name=hermetic -c user.email=hermetic@localhost commit -q --allow-empty --no-verify -m clean\n"
            "CLEAN=$(git -c core.hooksPath=/dev/null rev-parse HEAD)\n"
            "find /testbed -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +\n"
            "tar --no-same-owner --no-same-permissions --exclude='testbed/.git' --exclude='testbed/.git/*' --exclude='.git' --exclude='.git/*' -xf /tmp/agent.tar -C /\n"
            "git -c core.hooksPath=/dev/null add -A\n"
            "git -c core.hooksPath=/dev/null diff --cached --binary --no-color --no-ext-diff --no-textconv $CLEAN > /tmp/patch.diff\n"
            "git -c core.hooksPath=/dev/null diff --cached --name-status $CLEAN\n"
        )

        name_status_bytes = run_docker(
            ["exec", extractor_container, "/bin/bash", "-lc", script],
            check=True,
        )

        # Copy patch file out
        run_docker(["cp", f"{extractor_container}:/tmp/patch.diff", str(patch_path)], check=True)

        patch_bytes = patch_path.stat().st_size
        if patch_bytes > max_patch_bytes:
            raise ExtractError("patch_too_large")

        patch_raw = patch_path.read_bytes()
        patch_text = patch_raw.decode("utf-8", errors="replace")
        patch_sha256 = hashlib.sha256(patch_raw).hexdigest()

        # Parse name-status lines
        name_status_str = name_status_bytes.decode("utf-8", errors="replace")
        files_changed = 0
        files_added = 0
        files_deleted = 0

        for line in name_status_str.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            code = parts[0]
            if code.startswith("A"):
                files_added += 1
            elif code.startswith("D"):
                files_deleted += 1
            elif code.startswith("M") or code.startswith("R") or code.startswith("T"):
                files_changed += 1

        report = {
            "files_changed": files_changed,
            "files_added": files_added,
            "files_deleted": files_deleted,
            "patch_bytes": patch_bytes,
            "tar_bytes": tar_bytes,
            "sha256": patch_sha256,
        }

        return (patch_text, report)

    finally:
        # 4. docker rm -f extractor in finally block
        try:
            run_docker(["rm", "-f", extractor_container], check=False)
        except Exception:
            pass

        # Cleanup temporary host files
        if tar_path.exists():
            try:
                tar_path.unlink()
            except Exception:
                pass
        if patch_path.exists():
            try:
                patch_path.unlink()
            except Exception:
                pass
