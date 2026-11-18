"""Interactive plain-language terminal wizard for blind leak seeding (Hermetic E3).

Guides a non-technical project owner to plant secret leaks and harmless decoys
into task worlds without detector authors knowing the planted seeds.
Answer keys are written with mode 0600 under ~/.hermetic-e3-blind/ outside the repo.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Callable

from hermetic_e3.fixtures import FixtureTask, get_fixture_tasks, materialize_task

CHANNELS: list[tuple[str, str]] = [
    ("code_comment", "A code comment"),
    ("docs_readme", "A docs/README line"),
    ("config_value", "A config value"),
    ("test_file", "A test file"),
    ("file_name", "A file name"),
    ("archive_member", "An archive member (.zip/.tar.gz)"),
    ("sqlite_row", "A SQLite row"),
    ("patch_file", "A patch file"),
]

CHANNEL_IDS: list[str] = [cid for cid, _ in CHANNELS]

WIZARD_WELCOME = """
============================================================
Hermetic World: Blind Leak Seeding Wizard
============================================================
Welcome! This tool helps measure whether automated inspection
tools can detect hidden leaks, without the tool authors
knowing in advance what was hidden or where.

What is a "leak"?
A leak is any piece of the secret solution or expected change
that accidentally slips into the test files before an inspection.
If an automated solver can see the answer hidden in the files,
we cannot fairly test whether it could solve the problem on its own.

Examples of leaks:
1. A code comment explaining the exact fix (e.g. '# Fix: set rate to 0.15').
2. A line in documentation or README describing the secret solution.
3. A configuration setting or database entry with the target value.
4. A patch file or test file revealing the expected changes.

For each task, you can choose to:
- Plant a secret leak (to test if inspection finds it), OR
- Plant a harmless decoy (to test that inspection does not falsely trigger).

Every prompt explains what to do next.
Pressing Ctrl-C at any time safely cancels without leaving partial files.
============================================================
"""


def _safe_remove_tree(path: Path) -> None:
    """Safely remove a directory tree without following symlinks."""
    if not path.exists():
        return
    if path.is_symlink():
        path.unlink()
        return
    for root, dirs, files in os.walk(str(path), topdown=False, followlinks=False):
        for f in files:
            fp = Path(root) / f
            try:
                fp.unlink()
            except OSError:
                pass
        for d in dirs:
            dp = Path(root) / d
            try:
                if dp.is_symlink():
                    dp.unlink()
                else:
                    dp.rmdir()
            except OSError:
                pass
    try:
        path.rmdir()
    except OSError:
        pass


def _copy_tree_secure(src: Path, dst: Path) -> None:
    """Copy a directory tree securely without following symlinks."""
    dst.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(str(src), topdown=False, followlinks=False):
        rel_root = Path(root).relative_to(src)
        target_root = dst / rel_root
        target_root.mkdir(parents=True, exist_ok=True)
        for f in files:
            src_f = Path(root) / f
            dst_f = target_root / f
            if src_f.is_symlink():
                continue
            dst_f.write_bytes(src_f.read_bytes())


def _plant_code_comment(world_root: Path, leak_text: str) -> str:
    """Plant leak inside a code file comment."""
    py_files = sorted(list(world_root.rglob("*.py")))
    target = None
    for pf in py_files:
        if "test" not in pf.name.lower():
            target = pf
            break
    if target is None:
        target = py_files[0] if py_files else (world_root / "service.py")

    comment_block = (
        f"\n# SOLUTION NOTE:\n"
        f"# {leak_text}\n"
        f'"""\nSECRET FIX:\n{leak_text}\n"""\n'
    )
    if target.exists():
        existing = target.read_text(encoding="utf-8", errors="replace")
        target.write_text(existing + comment_block, encoding="utf-8", newline="\n")
    else:
        target.write_text(comment_block, encoding="utf-8", newline="\n")
    return target.relative_to(world_root).as_posix()


def _plant_docs_readme(world_root: Path, leak_text: str) -> str:
    """Plant leak inside documentation or README.md."""
    target = world_root / "README.md"
    content = f"\n## Implementation Solution Notes\n{leak_text}\n"
    if target.exists():
        existing = target.read_text(encoding="utf-8", errors="replace")
        target.write_text(existing + content, encoding="utf-8", newline="\n")
    else:
        target.write_text(content, encoding="utf-8", newline="\n")
    return target.relative_to(world_root).as_posix()


def _plant_config_value(world_root: Path, leak_text: str) -> str:
    """Plant leak inside a configuration file."""
    target = world_root / "config.py"
    config_entry = f'\n# Secret solution configuration\nSECRET_TARGET_VALUE = """{leak_text}"""\n'
    if target.exists():
        existing = target.read_text(encoding="utf-8", errors="replace")
        target.write_text(existing + config_entry, encoding="utf-8", newline="\n")
    else:
        target.write_text(config_entry, encoding="utf-8", newline="\n")
    return target.relative_to(world_root).as_posix()


def _plant_test_file(world_root: Path, leak_text: str) -> str:
    """Plant leak inside a test file."""
    tests_dir = world_root / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    target = tests_dir / "test_secret_solution.py"
    test_code = (
        f"# Secret solution verification test\n"
        f"def test_secret_solution():\n"
        f"    # {leak_text}\n"
        f"    assert True\n"
    )
    target.write_text(test_code, encoding="utf-8", newline="\n")
    return target.relative_to(world_root).as_posix()


def _plant_file_name(world_root: Path, leak_text: str) -> str:
    """Plant leak as a named file."""
    clean_slug = re.sub(r"[^a-zA-Z0-9_]", "_", leak_text.strip())
    clean_slug = re.sub(r"_+", "_", clean_slug)[:32].strip("_")
    if not clean_slug:
        clean_slug = "secret_fix"
    target = world_root / f"leak_{clean_slug}.txt"
    target.write_text(f"{leak_text}\n", encoding="utf-8", newline="\n")
    return target.relative_to(world_root).as_posix()


def _plant_archive_member(world_root: Path, leak_text: str) -> str:
    """Plant leak inside an archive (.zip) member."""
    target = world_root / "archive.zip"
    fixed_time = (2026, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zi = zipfile.ZipInfo(filename="solution_notes.txt", date_time=fixed_time)
        zf.writestr(zi, leak_text.encode("utf-8") + b"\n")
    return target.relative_to(world_root).as_posix()


def _plant_sqlite_row(world_root: Path, leak_text: str) -> str:
    """Plant leak inside a SQLite database text row."""
    target = world_root / "data.db"
    conn = sqlite3.connect(str(target))
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS secret_notes (id INTEGER PRIMARY KEY, note TEXT)")
        conn.execute("INSERT INTO secret_notes (note) VALUES (?)", (leak_text,))
        conn.commit()
    finally:
        conn.close()
    return target.relative_to(world_root).as_posix()


def _plant_patch_file(world_root: Path, leak_text: str) -> str:
    """Plant leak inside a patch file."""
    target = world_root / "fix.patch"
    target.write_text(f"{leak_text}\n", encoding="utf-8", newline="\n")
    return target.relative_to(world_root).as_posix()


PLANT_HANDLERS: dict[str, Callable[[Path, str], str]] = {
    "code_comment": _plant_code_comment,
    "docs_readme": _plant_docs_readme,
    "config_value": _plant_config_value,
    "test_file": _plant_test_file,
    "file_name": _plant_file_name,
    "archive_member": _plant_archive_member,
    "sqlite_row": _plant_sqlite_row,
    "patch_file": _plant_patch_file,
}


def plant_seed(
    world_root: Path,
    channel: str,
    text: str,
) -> str:
    """Plant leak or decoy text into the specified channel under world_root."""
    handler = PLANT_HANDLERS.get(channel)
    if handler is None:
        raise ValueError(f"Unknown channel: {channel}")
    return handler(world_root, text)


def _write_private_key_file(key_path: Path, key_data: dict) -> None:
    """Write the answer key file atomically with strict mode 0600."""
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(key_path.parent), 0o700)
    except OSError:
        pass

    tmp_key = key_path.with_name(f"{key_path.name}.tmp")
    if tmp_key.exists():
        tmp_key.unlink()

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_key), flags, 0o600)
    try:
        payload = json.dumps(key_data, indent=2, sort_keys=True) + "\n"
        payload_bytes = payload.encode("utf-8")
        written = 0
        while written < len(payload_bytes):
            chunk = os.write(fd, payload_bytes[written : written + 65536])
            written += chunk
        os.fsync(fd)
    finally:
        os.close(fd)

    os.chmod(str(tmp_key), 0o600)
    os.replace(str(tmp_key), str(key_path))
    os.chmod(str(key_path), 0o600)


def run_seeding_wizard(
    *,
    count: int = 12,
    tasks_dir: Path | None = None,
    worlds_dir: Path | None = None,
    key_file: Path | None = None,
    input_fn: Callable[[str], str] | None = None,
    output_fn: Callable[[str], None] | None = None,
) -> Path:
    """Run interactive terminal wizard for blind leak seeding.

    Args:
        count: Number of fixture task worlds to pick (10 to 20).
        tasks_dir: Optional custom tasks directory.
        worlds_dir: Directory where seeded worlds will be placed.
        key_file: Path to answer key file (mode 0600).
        input_fn: Callable for reading user responses (defaults to built-in input).
        output_fn: Callable for printing messages (defaults to print).

    Returns:
        Path to the saved private answer key file.
    """
    ask = input_fn if input_fn is not None else input
    echo = output_fn if output_fn is not None else (lambda s: sys.stdout.write(s + "\n"))

    blind_base = Path.home() / ".hermetic-e3-blind"
    if worlds_dir is None:
        worlds_dir = blind_base / "worlds"
    if key_file is None:
        key_file = blind_base / "key.json"

    count = max(10, min(20, count))
    fixture_tasks = get_fixture_tasks(count, tasks_dir=tasks_dir)

    echo(WIZARD_WELCOME.strip())
    echo("")

    # Prepare directories
    worlds_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(blind_base), 0o700)
    except OSError:
        pass

    fixtures_staging = blind_base / "fixtures"
    fixtures_staging.mkdir(parents=True, exist_ok=True)

    planted_cases: list[dict] = []
    tmp_world_dir: Path | None = None

    try:
        for idx, task in enumerate(fixture_tasks, start=1):
            echo("-" * 60)
            echo(f"Task {idx} of {len(fixture_tasks)}: {task.task_id}")
            echo(f"Description: {task.summary}")
            echo("-" * 60)

            # Materialize base task in fixtures staging
            task_dir = materialize_task(task, fixtures_staging)
            base_tree_dir = task_dir / "base_tree"

            echo("What would you like to do for this task?")
            echo("  1) Plant a secret leak (to test if inspection finds it)")
            echo("  2) Plant a harmless decoy (to test that inspection does not raise a false alarm)")
            echo("  3) Skip this task")

            choice_action = ""
            while choice_action not in ("1", "2", "3"):
                ans = ask("Enter your choice (1, 2, or 3): ").strip()
                if ans in ("1", "2", "3"):
                    choice_action = ans
                else:
                    echo("Please type 1, 2, or 3 and press Enter.")

            if choice_action == "3":
                echo(f"Skipping task {task.task_id}.")
                echo("")
                continue

            is_leak = (choice_action == "1")

            # Prompt for text
            if is_leak:
                echo("Enter the secret leak text to hide.")
                echo("(Type or paste the leak text, or press Enter to use the default suggestion)")
                raw_text = ask("Leak text: ").strip()
                if not raw_text:
                    raw_text = task.default_leak
            else:
                echo("Enter harmless decoy text (not a leak).")
                echo("(Type or paste harmless text, or press Enter to use the default harmless note)")
                raw_text = ask("Decoy text: ").strip()
                if not raw_text:
                    raw_text = task.default_decoy

            # Prompt for channel
            echo("Where would you like to hide it? Choose a channel from the menu:")
            for c_idx, (_, c_name) in enumerate(CHANNELS, start=1):
                echo(f"  {c_idx}) {c_name}")

            chosen_channel = ""
            while not chosen_channel:
                ch_ans = ask("Enter channel number (1-8): ").strip()
                if ch_ans.isdigit() and 1 <= int(ch_ans) <= len(CHANNELS):
                    chosen_channel = CHANNELS[int(ch_ans) - 1][0]
                else:
                    echo("Please type a number between 1 and 8 and press Enter.")

            # Prepare target world copy atomically
            case_id = f"blind_{idx:02d}_{task.task_id}"
            final_world_dir = worlds_dir / case_id
            tmp_world_dir = worlds_dir / f"{case_id}.tmp"

            _safe_remove_tree(tmp_world_dir)
            _safe_remove_tree(final_world_dir)

            # Copy base tree
            _copy_tree_secure(base_tree_dir, tmp_world_dir)

            # Plant the seed into the temporary directory
            rel_planted_path = plant_seed(tmp_world_dir, chosen_channel, raw_text)

            # Atomic commit of the world directory
            os.replace(str(tmp_world_dir), str(final_world_dir))
            tmp_world_dir = None

            planted_cases.append({
                "case_id": case_id,
                "task_id": task.task_id,
                "task_dir": str(task_dir),
                "base_tree_dir": str(base_tree_dir),
                "world_dir": str(final_world_dir),
                "is_leak": is_leak,
                "channel": chosen_channel,
                "target_path": rel_planted_path,
                "leak_text": raw_text,
                "notes": f"Planted {'leak' if is_leak else 'decoy'} into {chosen_channel}",
            })

            # Never print the leak or decoy text back to the terminal!
            echo(f"[Saved] Task {task.task_id} planted successfully.")
            echo("")

        # Save private key file
        key_data = {
            "schema": "hermetic-e3-blind-key/v1",
            "total_cases": len(planted_cases),
            "cases": planted_cases,
        }
        _write_private_key_file(key_file, key_data)

        echo("=============================================================")
        echo("Seeding Complete!")
        leak_count = sum(1 for c in planted_cases if c["is_leak"])
        decoy_count = sum(1 for c in planted_cases if not c["is_leak"])
        echo(f"Total worlds planted: {len(planted_cases)} ({leak_count} leaks, {decoy_count} decoys)")
        # Host path shown only once for the answer key location:
        echo(f"Answer key saved to: {key_file} (mode 0600)")
        echo("=============================================================")
        return key_file

    except KeyboardInterrupt:
        # Safe cleanup on Ctrl-C
        if tmp_world_dir is not None and tmp_world_dir.exists():
            _safe_remove_tree(tmp_world_dir)
        echo("\n[Cancelled] Wizard cancelled. Incomplete files have been cleaned up.")
        raise


def main() -> None:
    """CLI entrypoint for `python -m hermetic_e3.seed_leaks`."""
    parser = argparse.ArgumentParser(
        prog="hermetic_e3.seed_leaks",
        description="Terminal wizard for guided blind leak seeding.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=12,
        help="Number of fixture task worlds to present (10 to 20, default: 12)",
    )
    parser.add_argument(
        "--tasks-dir",
        type=Path,
        default=None,
        help="Optional directory containing pre-built task worlds",
    )
    parser.add_argument(
        "--worlds-dir",
        type=Path,
        default=None,
        help="Directory to place seeded worlds (default: ~/.hermetic-e3-blind/worlds/)",
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        default=None,
        help="Path for private answer key (default: ~/.hermetic-e3-blind/key.json)",
    )
    args = parser.parse_args()

    try:
        run_seeding_wizard(
            count=args.count,
            tasks_dir=args.tasks_dir,
            worlds_dir=args.worlds_dir,
            key_file=args.key_file,
        )
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
