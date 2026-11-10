"""Frozen package index builder and environment inspection."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import re
from typing import Any

from hermetic_slice.dockerutil import run_docker
from hermetic_slice.http import HttpError, HttpGet


class IndexBuildError(Exception):
    """Raised when package index construction or file download fails."""


def normalize_name(name: str) -> str:
    """Normalize package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_iso(dt_str: str) -> datetime:
    """Parse an ISO 8601 string into a timezone-aware UTC datetime."""
    s = dt_str.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        if len(s) == 10 and s.count("-") == 2:
            dt = datetime.strptime(s, "%Y-%m-%d")
        else:
            raise
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


IN_CONTAINER_ENV_INFO_BASH = r'''#!/usr/bin/env bash
set -e

if [ -f /opt/miniconda3/etc/profile.d/conda.sh ]; then
    . /opt/miniconda3/etc/profile.d/conda.sh
    conda activate testbed 2>/dev/null || true
elif command -v conda >/dev/null 2>&1; then
    conda activate testbed 2>/dev/null || true
fi

PY_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PY_BIN=python3
elif command -v python >/dev/null 2>&1; then
    PY_BIN=python
else
    echo "No python found in container" >&2
    exit 1
fi

"$PY_BIN" -c '
import json, sys, subprocess

py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
impl = "cp" if sys.implementation.name == "cpython" else sys.implementation.name
impl_tag = f"{impl}{sys.version_info.major}{sys.version_info.minor}"

def get_pip(args):
    # Must run on Python 3.6 (the django-11099 env): no capture_output or text kwargs.
    proc = subprocess.run([sys.executable, "-m", "pip", "list", *args, "--format=json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if proc.returncode != 0:
        return []
    try:
        return json.loads(proc.stdout)
    except Exception:
        return []

pkgs_raw = get_pip([])
packages = [{"name": p["name"], "version": p["version"]} for p in pkgs_raw if "name" in p and "version" in p]

edit_raw = get_pip(["--editable"])
editable = [p["name"] for p in edit_raw if "name" in p]

result = {
    "python_version": py_ver,
    "implementation_tag": impl_tag,
    "packages": packages,
    "editable": editable,
}
print(json.dumps(result))
'
'''


def env_info(image: str) -> dict[str, Any]:
    """Inspect python environment in a container from image."""
    args = [
        "run",
        "--rm",
        "--network", "none",
        "-i",
        "--entrypoint", "/bin/bash",
        image,
        "-c",
        IN_CONTAINER_ENV_INFO_BASH,
    ]
    stdout = run_docker(args, check=True)
    return json.loads(stdout.decode("utf-8"))


def wheel_compatible(filename: str, py: str) -> bool:
    """Determine whether a wheel filename is compatible with target python version."""
    if not filename.endswith(".whl"):
        return False

    stem = filename[:-4]
    parts = stem.split("-")
    if len(parts) == 5:
        _, _, py_tag, abi_tag, plat_tag = parts
    elif len(parts) == 6:
        _, _, build_tag, py_tag, abi_tag, plat_tag = parts
        if not build_tag or not build_tag[0].isdigit():
            return False
    else:
        return False

    try:
        major_str, minor_str = py.split(".")
        major = int(major_str)
        minor = int(minor_str)
    except Exception:
        return False

    py_tags = py_tag.split(".")
    abi_tags = abi_tag.split(".")
    plat_tags = plat_tag.split(".")

    # ABI check: must be none, abi3, or cp<major><minor>
    allowed_abi = {"none", "abi3", f"cp{major}{minor}"}
    if not any(a in allowed_abi for a in abi_tags):
        return False

    has_abi3 = "abi3" in abi_tags

    # Python tag check:
    # some python tag is py3, py<major><minor> or cp<major><minor>,
    # or (with abi abi3) any cp3x where x <= minor
    def is_py_tag_compatible(tag: str) -> bool:
        if tag in ("py3", f"py{major}{minor}", f"cp{major}{minor}"):
            return True
        if has_abi3 and tag.startswith("cp3") and tag[3:].isdigit():
            x = int(tag[3:])
            if x <= minor:
                return True
        return False

    if not any(is_py_tag_compatible(t) for t in py_tags):
        return False

    # Platform tag check:
    # some platform tag is any, or starts with manylinux and ends with x86_64, or is linux_x86_64
    def is_plat_tag_compatible(p: str) -> bool:
        if p in ("any", "linux_x86_64"):
            return True
        if p.startswith("manylinux") and p.endswith("x86_64"):
            return True
        return False

    if not any(is_plat_tag_compatible(p) for p in plat_tags):
        return False

    return True


def build_index(
    task: dict,
    env: dict,
    http_get: HttpGet,
    index_dir: Path,
    *,
    versions_per_package: int = 5,
) -> dict[str, Any]:
    """Build PEP 503 frozen package index and return index report."""
    index_dir = Path(index_dir)
    files_dir = index_dir / "files"
    simple_dir = index_dir / "simple"
    files_dir.mkdir(parents=True, exist_ok=True)
    simple_dir.mkdir(parents=True, exist_ok=True)

    cutoff_str = task["cutoffs"]["t_world"]
    cutoff_dt = parse_iso(cutoff_str)

    # Determine target project names to exclude
    excluded_names: set[str] = set()
    repo = task.get("repo", "")
    if repo:
        repo_last = repo.split("/")[-1]
        excluded_names.add(normalize_name(repo_last))
    for edit_pkg in env.get("editable", []):
        excluded_names.add(normalize_name(edit_pkg))

    py_version = env.get("python_version", "3.9")
    installed_packages = env.get("packages", [])

    package_reports: list[dict[str, Any]] = []
    served_projects: set[str] = set()

    for pkg_item in installed_packages:
        pkg_name = pkg_item["name"]
        installed_ver = pkg_item.get("version", "")
        norm_pkg_name = normalize_name(pkg_name)

        if norm_pkg_name in excluded_names:
            continue

        url = f"https://pypi.org/pypi/{pkg_name}/json"
        try:
            body = http_get(url)
        except HttpError as exc:
            if exc.status != 404:
                raise
            # Conda envs carry packages that PyPI doesn't have (or has under
            # another name). They can't be served; record them instead of failing.
            package_reports.append({
                "name": pkg_name,
                "installed_version": installed_ver,
                "on_pypi": False,
                "installed_version_uploaded": None,
                "installed_newer_than_t_world": False,
                "served_versions": [],
                "served_files": [],
                "yanked_served": [],
            })
            continue
        pypi_data = json.loads(body.decode("utf-8"))
        releases: dict[str, list[dict[str, Any]]] = pypi_data.get("releases", {})

        # Compute installed version upload time and whether it is newer than t_world
        installed_files = releases.get(installed_ver, [])
        installed_version_uploaded: str | None = None
        if installed_files:
            upload_dts = []
            for f in installed_files:
                if "upload_time_iso_8601" in f:
                    upload_dts.append(parse_iso(f["upload_time_iso_8601"]))
            if upload_dts:
                earliest_installed = min(upload_dts)
                installed_version_uploaded = earliest_installed.strftime("%Y-%m-%dT%H:%M:%SZ")

        installed_newer_than_t_world = False
        if installed_version_uploaded is not None:
            if parse_iso(installed_version_uploaded) > cutoff_dt:
                installed_newer_than_t_world = True

        # Find eligible versions and keep files uploaded <= cutoff
        candidates: list[tuple[str, datetime, list[dict[str, Any]]]] = []
        for ver_str, files_list in releases.items():
            files_before_cutoff = [
                f for f in files_list
                if "upload_time_iso_8601" in f and parse_iso(f["upload_time_iso_8601"]) <= cutoff_dt
            ]
            if not files_before_cutoff:
                continue

            kept_for_version: list[dict[str, Any]] = []
            for f in files_before_cutoff:
                fname = f.get("filename", "")
                ptype = f.get("packagetype", "")
                if ptype == "sdist" or fname.endswith((".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz")):
                    kept_for_version.append(f)
                elif ptype == "bdist_wheel" or fname.endswith(".whl"):
                    if wheel_compatible(fname, py_version):
                        kept_for_version.append(f)

            if kept_for_version:
                earliest_kept = min(parse_iso(f["upload_time_iso_8601"]) for f in kept_for_version)
                candidates.append((ver_str, earliest_kept, kept_for_version))

        # Sort versions by earliest upload time of kept files, descending (newest first)
        candidates.sort(key=lambda c: c[1], reverse=True)
        selected_versions = candidates[:versions_per_package]

        served_versions: list[str] = []
        served_files: list[str] = []
        yanked_served: list[str] = []
        files_for_html: list[dict[str, Any]] = []

        for ver_str, _, kept_files in selected_versions:
            served_versions.append(ver_str)
            for f in kept_files:
                fname = f["filename"]
                furl = f["url"]
                expected_sha256 = f.get("digests", {}).get("sha256")

                file_data = http_get(furl)
                actual_sha256 = hashlib.sha256(file_data).hexdigest()
                if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
                    raise IndexBuildError(
                        f"SHA256 mismatch for {fname}: expected {expected_sha256}, got {actual_sha256}"
                    )

                dest_path = files_dir / fname
                dest_path.write_bytes(file_data)

                served_files.append(fname)
                if f.get("yanked"):
                    yanked_served.append(fname)
                files_for_html.append({
                    "filename": fname,
                    "sha256": actual_sha256,
                    "requires_python": f.get("requires_python"),
                })

        if files_for_html:
            served_projects.add(norm_pkg_name)
            pkg_simple_dir = simple_dir / norm_pkg_name
            pkg_simple_dir.mkdir(parents=True, exist_ok=True)

            links: list[str] = []
            for finfo in files_for_html:
                fname = finfo["filename"]
                sha = finfo["sha256"]
                req_py = finfo["requires_python"]
                req_attr = f' data-requires-python="{html.escape(req_py, quote=True)}"' if req_py else ""
                href = f"../../files/{fname}#sha256={sha}"
                links.append(f'    <a href="{href}"{req_attr}>{html.escape(fname)}</a>')

            pkg_html = (
                "<!DOCTYPE html>\n"
                "<html>\n"
                "  <head>\n"
                '    <meta name="pypi:repository-version" content="1.0">\n'
                f"    <title>Links for {norm_pkg_name}</title>\n"
                "  </head>\n"
                "  <body>\n"
                f"    <h1>Links for {norm_pkg_name}</h1>\n"
                + "\n".join(links)
                + "\n  </body>\n"
                "</html>\n"
            )
            (pkg_simple_dir / "index.html").write_text(pkg_html, encoding="utf-8")

        package_reports.append({
            "name": pkg_name,
            "installed_version": installed_ver,
            "on_pypi": True,
            "installed_version_uploaded": installed_version_uploaded,
            "installed_newer_than_t_world": installed_newer_than_t_world,
            "served_versions": served_versions,
            "served_files": served_files,
            "yanked_served": yanked_served,
        })

    # Write root simple/index.html
    root_links = [
        f'    <a href="{proj}/">{proj}</a>'
        for proj in sorted(served_projects)
    ]
    root_html = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "  <head>\n"
        '    <meta name="pypi:repository-version" content="1.0">\n'
        "    <title>Simple index</title>\n"
        "  </head>\n"
        "  <body>\n"
        + "\n".join(root_links)
        + "\n  </body>\n"
        "</html>\n"
    )
    (simple_dir / "index.html").write_text(root_html, encoding="utf-8")

    report: dict[str, Any] = {
        "t_world": cutoff_str,
        "packages": package_reports,
        "excluded": sorted(excluded_names),
        "totals": {
            "installed_packages": len(installed_packages),
            "served_packages": len(served_projects),
            "served_versions": sum(len(p["served_versions"]) for p in package_reports),
            "served_files": sum(len(p["served_files"]) for p in package_reports),
            "yanked_served": sum(len(p["yanked_served"]) for p in package_reports),
            "newer_than_t_world": sum(1 for p in package_reports if p["installed_newer_than_t_world"]),
            "not_on_pypi": sum(1 for p in package_reports if not p["on_pypi"]),
        },
    }

    report_path = index_dir / "index-report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def class_b_warnings(report: dict[str, Any]) -> list[str]:
    """Return warning lines for installed packages newer than T_world."""
    t_world = report.get("t_world", "")
    t_world_date = t_world[:10]
    warnings: list[str] = []
    for pkg in report.get("packages", []):
        if pkg.get("installed_newer_than_t_world"):
            uploaded = pkg.get("installed_version_uploaded") or ""
            uploaded_date = uploaded[:10]
            name = pkg["name"]
            ver = pkg["installed_version"]
            warnings.append(
                f"{name} {ver} installed (uploaded {uploaded_date}) is newer than T_world {t_world_date} (repo_only: listed, not rebuilt)"
            )
    return warnings
