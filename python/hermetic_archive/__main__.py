"""CLI for hermetic web archive importers."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .formats import ArchiveError, bounded_encoding
from .importers import (
    ImportReport,
    import_common_crawl_cdx_files,
    import_common_crawl_warc_file,
    import_software_heritage_files,
    import_stack_exchange_files,
    import_wayback_cdx_files,
)
from hermetic_safe_io import validate_path


def _write_outputs(report: ImportReport, cutoff: str, output_dir: str) -> None:
    validate_path(output_dir + "/.probe")
    if os.path.islink(output_dir):
        raise ArchiveError("output directory cannot be a symlink")

    if os.path.exists(output_dir):
        if not os.path.isdir(output_dir):
            raise ArchiveError("output path exists and is not a directory")
        os.chmod(output_dir, 0o700)
    else:
        os.makedirs(output_dir, mode=0o700, exist_ok=True)
        os.chmod(output_dir, 0o700)

    # 1. Reconstruct recipes for each consumer's boundary and encode in memory before disk writes
    month = cutoff[:7]
    replay_recipe = report.to_replay_recipe(cutoff)
    search_recipe = report.to_search_recipe(month)

    encoded_replay = bounded_encoding(replay_recipe)
    encoded_search = bounded_encoding(search_recipe)

    report_data = {
        "source": report.source,
        "kept_count": len(report.kept),
        "search_count": len(search_recipe.get("documents", [])),
        "after_cutoff": list(report.after_cutoff),
        "undated": list(report.undated),
    }
    encoded_report = json.dumps(report_data, indent=2, sort_keys=True).encode("utf-8")

    # 2. Partition blobs: text_sha256 to blobs/, replay payloads to replay-blobs/
    search_blobs_map = report.to_search_blobs_dict(month)
    search_keys = {doc["text_sha256"] for doc in search_recipe.get("documents", [])}
    search_blobs = {k: v for k, v in search_blobs_map.items() if k in search_keys}

    replay_blobs_map = report.to_replay_blobs_dict()
    replay_keys = {entry["payload_sha256"] for entry in replay_recipe.get("captures", [])}
    replay_blobs = {k: v for k, v in replay_blobs_map.items() if k in replay_keys}

    # 3. Stage everything in private directory with mode 0700 and 0600 files (no symlink following)
    staging_dir = os.path.join(output_dir, ".staging")
    if os.path.islink(staging_dir):
        raise ArchiveError("staging directory cannot be a symlink")
    if os.path.exists(staging_dir):
        for root, dirs, files in os.walk(staging_dir, topdown=False):
            for name in files:
                os.unlink(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(staging_dir)

    os.makedirs(staging_dir, mode=0o700)
    os.chmod(staging_dir, 0o700)

    try:
        def _write_safe_file(parent_dir: str, filename: str, content: bytes) -> str:
            path = os.path.join(parent_dir, filename)
            if os.path.islink(path):
                raise ArchiveError("output file cannot be a symlink")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
                written = 0
                while written < len(content):
                    n = os.write(fd, content[written:])
                    if n <= 0:
                        raise ArchiveError("failed to write output file")
                    written += n
            finally:
                os.close(fd)
            return path

        _write_safe_file(staging_dir, "replay-recipe.json", encoded_replay)
        _write_safe_file(staging_dir, "search-recipe.json", encoded_search)
        _write_safe_file(staging_dir, "report.json", encoded_report)

        stage_blobs_dir = os.path.join(staging_dir, "blobs")
        os.makedirs(stage_blobs_dir, mode=0o700)
        os.chmod(stage_blobs_dir, 0o700)
        for digest, body in sorted(search_blobs.items()):
            _write_safe_file(stage_blobs_dir, digest, body)

        stage_replay_blobs_dir = os.path.join(staging_dir, "replay-blobs")
        os.makedirs(stage_replay_blobs_dir, mode=0o700)
        os.chmod(stage_replay_blobs_dir, 0o700)
        for digest, body in sorted(replay_blobs.items()):
            _write_safe_file(stage_replay_blobs_dir, digest, body)

        # 4. Atomic publication only after all writes succeed
        dest_blobs = os.path.join(output_dir, "blobs")
        if os.path.islink(dest_blobs):
            raise ArchiveError("blobs destination cannot be a symlink")
        if os.path.exists(dest_blobs):
            for entry in os.scandir(dest_blobs):
                if entry.is_symlink():
                    raise ArchiveError("symlink inside destination blobs directory")
                os.unlink(entry.path)
            os.rmdir(dest_blobs)
        os.replace(stage_blobs_dir, dest_blobs)

        dest_replay_blobs = os.path.join(output_dir, "replay-blobs")
        if os.path.islink(dest_replay_blobs):
            raise ArchiveError("replay-blobs destination cannot be a symlink")
        if os.path.exists(dest_replay_blobs):
            for entry in os.scandir(dest_replay_blobs):
                if entry.is_symlink():
                    raise ArchiveError("symlink inside destination replay-blobs directory")
                os.unlink(entry.path)
            os.rmdir(dest_replay_blobs)
        os.replace(stage_replay_blobs_dir, dest_replay_blobs)

        for filename in ("replay-recipe.json", "search-recipe.json", "report.json"):
            dest_file = os.path.join(output_dir, filename)
            if os.path.islink(dest_file):
                raise ArchiveError("destination file cannot be a symlink")
            os.replace(os.path.join(staging_dir, filename), dest_file)
    finally:
        if os.path.exists(staging_dir):
            for root, dirs, files in os.walk(staging_dir, topdown=False):
                for name in files:
                    try:
                        os.unlink(os.path.join(root, name))
                    except OSError:
                        pass
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except OSError:
                        pass
            try:
                os.rmdir(staging_dir)
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Hermetic web archive importers")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # common-crawl-warc
    p_cc = subparsers.add_parser("import-common-crawl-warc")
    p_cc.add_argument("--warc", required=True, help="Path to WARC file (.warc or .warc.gz)")
    p_cc.add_argument("--cutoff", required=True, help="RFC 3339 UTC cutoff timestamp")
    p_cc.add_argument("--output-dir", required=True, help="Directory to store recipes and blobs")

    # common-crawl-cdx
    p_cc_cdx = subparsers.add_parser("import-common-crawl-cdx")
    p_cc_cdx.add_argument("--cdx", required=True, help="Path to CDX/CDXJ file")
    p_cc_cdx.add_argument("--blobs", required=True, help="Path to blobs directory")
    p_cc_cdx.add_argument("--cutoff", required=True, help="RFC 3339 UTC cutoff timestamp")
    p_cc_cdx.add_argument("--output-dir", required=True, help="Directory to store recipes and blobs")

    # wayback-cdx
    p_wb = subparsers.add_parser("import-wayback-cdx")
    p_wb.add_argument("--cdx", required=True, help="Path to CDX file or JSON")
    p_wb.add_argument("--blobs", required=True, help="Path to blobs directory")
    p_wb.add_argument("--cutoff", required=True, help="RFC 3339 UTC cutoff timestamp")
    p_wb.add_argument("--output-dir", required=True, help="Directory to store recipes and blobs")

    # software-heritage
    p_swh = subparsers.add_parser("import-software-heritage")
    p_swh.add_argument("--snapshot", required=True, help="Path to Software Heritage snapshot JSON")
    p_swh.add_argument("--blobs", required=True, help="Path to blobs directory")
    p_swh.add_argument("--cutoff", required=True, help="RFC 3339 UTC cutoff timestamp")
    p_swh.add_argument("--output-dir", required=True, help="Directory to store recipes and blobs")

    # stack-exchange
    p_se = subparsers.add_parser("import-stack-exchange")
    p_se.add_argument("--history", required=True, help="Path to PostHistory.xml")
    p_se.add_argument("--posts", default=None, help="Optional path to Posts.xml")
    p_se.add_argument("--site-url", default="https://stackoverflow.com", help="Canonical site URL")
    p_se.add_argument("--cutoff", required=True, help="RFC 3339 UTC cutoff timestamp")
    p_se.add_argument("--output-dir", required=True, help="Directory to store recipes and blobs")

    args = parser.parse_args()

    try:
        if args.command == "import-common-crawl-warc":
            report = import_common_crawl_warc_file(args.warc, args.cutoff)
        elif args.command == "import-common-crawl-cdx":
            report = import_common_crawl_cdx_files(args.cdx, args.blobs, args.cutoff)
        elif args.command == "import-wayback-cdx":
            report = import_wayback_cdx_files(args.cdx, args.blobs, args.cutoff)
        elif args.command == "import-software-heritage":
            report = import_software_heritage_files(args.snapshot, args.blobs, args.cutoff)
        elif args.command == "import-stack-exchange":
            report = import_stack_exchange_files(args.history, args.cutoff, args.site_url, args.posts)
        else:
            sys.exit(64)

        _write_outputs(report, args.cutoff, args.output_dir)
    except ArchiveError as exc:
        sys.stderr.write(f"Archive error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
