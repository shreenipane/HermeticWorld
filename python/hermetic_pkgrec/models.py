"""Data models representing index entries, filtered files, and manifest records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class UpstreamFileEntry:
    """Raw distribution file entry extracted from an upstream index page."""

    filename: str
    url: str
    sha256: str | None
    upload_time: str | None
    yanked: bool | str
    yank_time: str | None = None
    requires_python: str | None = None


@dataclass(frozen=True, slots=True)
class FilteredFileEntry:
    """Distribution file that satisfied cutoff requirements with rewritten yank status."""

    filename: str
    url: str
    sha256: str
    upload_time: str
    yanked: bool | str
    yank_decision: str
    requires_python: str | None = None


@dataclass(frozen=True, slots=True)
class ManifestRecord:
    """Manifest entry for a single fetched and verified distribution file."""

    project: str
    filename: str
    sha256: str
    upload_time: str
    yank_decision: str

    def __getitem__(self, key: str) -> str:
        if key == "project":
            return self.project
        if key == "filename":
            return self.filename
        if key == "sha256":
            return self.sha256
        if key in ("upload-time", "upload_time"):
            return self.upload_time
        if key in ("yank_decision", "yank-decision"):
            return self.yank_decision
        raise KeyError(key)

    def to_dict(self) -> dict[str, str]:
        return {
            "filename": self.filename,
            "project": self.project,
            "sha256": self.sha256,
            "upload-time": self.upload_time,
            "yank_decision": self.yank_decision,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ManifestRecord:
        proj = data.get("project")
        fname = data.get("filename")
        sha = data.get("sha256")
        utime = data.get("upload-time") or data.get("upload_time")
        ydec = data.get("yank_decision") or data.get("yank-decision") or "not_yanked"

        if not isinstance(proj, str) or not proj:
            raise ValueError("ManifestRecord missing valid 'project'")
        if not isinstance(fname, str) or not fname:
            raise ValueError("ManifestRecord missing valid 'filename'")
        if not isinstance(sha, str) or not sha:
            raise ValueError("ManifestRecord missing valid 'sha256'")
        if not isinstance(utime, str) or not utime:
            raise ValueError("ManifestRecord missing valid 'upload-time'")
        if not isinstance(ydec, str):
            raise ValueError("ManifestRecord missing valid 'yank_decision'")

        return cls(
            project=proj,
            filename=fname,
            sha256=sha.lower(),
            upload_time=utime,
            yank_decision=ydec,
        )


@dataclass(frozen=True, slots=True)
class ProjectFilterResult:
    """Result of filtering a project's upstream file entries against cutoff and yank rules."""

    project: str
    files: list[FilteredFileEntry]
    missing_upload_time: list[dict[str, str]]
    unyanked_after_cutoff: list[dict[str, str]]
    unyanked_unknown_date: list[dict[str, str]]
    dropped_after_cutoff: list[dict[str, str]]
    missing_hash: list[dict[str, str]] = field(default_factory=list)
    invalid_hash: list[dict[str, str]] = field(default_factory=list)
    invalid_filename: list[dict[str, str]] = field(default_factory=list)
