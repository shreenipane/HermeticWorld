"""Deterministic canonical JSON manifest tracking recorded package closures."""

from __future__ import annotations

import json
import os
from pathlib import Path
import threading
from typing import Any

from hermetic_pkgrec.constants import (
    FILE_CHUNK_BYTES,
    MANIFEST_SCHEMA,
    MAX_MANIFEST_BYTES,
    MAX_TOTAL_FILES_COUNT,
)
from hermetic_pkgrec.errors import ManifestError, SymlinkError
from hermetic_pkgrec.models import ManifestRecord
import hermetic_safe_io


def canonical_json_bytes(payload: Any) -> bytes:
    """Format payload as canonical JSON (sorted keys, compact separators, UTF-8)."""
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


class Manifest:
    """In-memory and file-backed canonical JSON manifest for Layer 1 package recording."""

    def __init__(
        self,
        cutoff: str,
        *,
        files: list[ManifestRecord] | None = None,
        missing_upload_time: list[dict[str, str]] | None = None,
        unyanked_after_cutoff: list[dict[str, str]] | None = None,
        unyanked_unknown_date: list[dict[str, str]] | None = None,
        missing_hash: list[dict[str, str]] | None = None,
        invalid_hash: list[dict[str, str]] | None = None,
        invalid_filename: list[dict[str, str]] | None = None,
        project_over_file_cap: list[dict[str, str]] | list[str] | None = None,
    ) -> None:
        self.cutoff = cutoff
        self._lock = threading.Lock()
        self._save_lock = threading.Lock()
        self._files: dict[tuple[str, str, str], ManifestRecord] = {}
        self._missing_upload_time: set[tuple[str, str]] = set()
        self._unyanked_after_cutoff: set[tuple[str, str]] = set()
        self._unyanked_unknown_date: set[tuple[str, str]] = set()
        self._missing_hash: set[tuple[str, str]] = set()
        self._invalid_hash: set[tuple[str, str]] = set()
        self._invalid_filename: set[tuple[str, str]] = set()
        self._project_over_file_cap: set[str] = set()

        if files:
            for f in files:
                self._files[(f.project, f.filename, f.sha256)] = f
        if missing_upload_time:
            for item in missing_upload_time:
                self._missing_upload_time.add((item["project"], item["filename"]))
        if unyanked_after_cutoff:
            for item in unyanked_after_cutoff:
                self._unyanked_after_cutoff.add((item["project"], item["filename"]))
        if unyanked_unknown_date:
            for item in unyanked_unknown_date:
                self._unyanked_unknown_date.add((item["project"], item["filename"]))
        if missing_hash:
            for item in missing_hash:
                self._missing_hash.add((item["project"], item["filename"]))
        if invalid_hash:
            for item in invalid_hash:
                self._invalid_hash.add((item["project"], item["filename"]))
        if invalid_filename:
            for item in invalid_filename:
                self._invalid_filename.add((item["project"], item["filename"]))
        if project_over_file_cap:
            for item in project_over_file_cap:
                if isinstance(item, dict):
                    self._project_over_file_cap.add(item["project"])
                elif isinstance(item, str):
                    self._project_over_file_cap.add(item)

    def record_file(
        self,
        project: str,
        filename: str,
        sha256: str,
        upload_time: str,
        yank_decision: str,
    ) -> ManifestRecord:
        with self._lock:
            if len(self._files) >= MAX_TOTAL_FILES_COUNT:
                raise ManifestError("Manifest total file count limit reached.")
            rec = ManifestRecord(
                project=project,
                filename=filename,
                sha256=sha256.lower(),
                upload_time=upload_time,
                yank_decision=yank_decision,
            )
            self._files[(project, filename, rec.sha256)] = rec
            return rec

    def record_missing_upload_time(self, project: str, filename: str) -> None:
        with self._lock:
            self._missing_upload_time.add((project, filename))

    def record_unyanked_after_cutoff(self, project: str, filename: str) -> None:
        with self._lock:
            self._unyanked_after_cutoff.add((project, filename))

    def record_unyanked_unknown_date(self, project: str, filename: str) -> None:
        with self._lock:
            self._unyanked_unknown_date.add((project, filename))

    def record_missing_hash(self, project: str, filename: str) -> None:
        with self._lock:
            self._missing_hash.add((project, filename))

    def record_invalid_hash(self, project: str, filename: str) -> None:
        with self._lock:
            self._invalid_hash.add((project, filename))

    def record_invalid_filename(self, project: str, filename: str) -> None:
        with self._lock:
            self._invalid_filename.add((project, filename))

    def record_project_over_file_cap(self, project: str) -> None:
        with self._lock:
            self._project_over_file_cap.add(project)

    @property
    def files(self) -> list[ManifestRecord]:
        with self._lock:
            return sorted(self._files.values(), key=lambda r: (r.project, r.filename, r.sha256))

    @property
    def missing_upload_time(self) -> list[dict[str, str]]:
        with self._lock:
            items = sorted(self._missing_upload_time)
            return [{"filename": fn, "project": pr} for pr, fn in items]

    @property
    def unyanked_after_cutoff(self) -> list[dict[str, str]]:
        with self._lock:
            items = sorted(self._unyanked_after_cutoff)
            return [{"filename": fn, "project": pr} for pr, fn in items]

    @property
    def unyanked_unknown_date(self) -> list[dict[str, str]]:
        with self._lock:
            items = sorted(self._unyanked_unknown_date)
            return [{"filename": fn, "project": pr} for pr, fn in items]

    @property
    def missing_hash(self) -> list[dict[str, str]]:
        with self._lock:
            items = sorted(self._missing_hash)
            return [{"filename": fn, "project": pr} for pr, fn in items]

    @property
    def invalid_hash(self) -> list[dict[str, str]]:
        with self._lock:
            items = sorted(self._invalid_hash)
            return [{"filename": fn, "project": pr} for pr, fn in items]

    @property
    def invalid_filename(self) -> list[dict[str, str]]:
        with self._lock:
            items = sorted(self._invalid_filename)
            return [{"filename": fn, "project": pr} for pr, fn in items]

    @property
    def project_over_file_cap(self) -> list[dict[str, str]]:
        with self._lock:
            items = sorted(self._project_over_file_cap)
            return [{"project": pr} for pr in items]

    def __len__(self) -> int:
        with self._lock:
            return len(self._files)

    def __iter__(self):
        return iter(self.files)

    def __getitem__(self, index: int) -> ManifestRecord:
        return self.files[index]

    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to deterministic JSON-serializable dictionary."""
        with self._lock:
            sorted_files = sorted(
                self._files.values(), key=lambda r: (r.project, r.filename, r.sha256)
            )
            files_dict = [f.to_dict() for f in sorted_files]
            sorted_mut = sorted(self._missing_upload_time)
            sorted_uac = sorted(self._unyanked_after_cutoff)
            sorted_uud = sorted(self._unyanked_unknown_date)
            sorted_mh = sorted(self._missing_hash)
            sorted_ih = sorted(self._invalid_hash)
            sorted_ifn = sorted(self._invalid_filename)
            sorted_pofc = sorted(self._project_over_file_cap)

            return {
                "cutoff": self.cutoff,
                "files": files_dict,
                "invalid_filename": [{"filename": fn, "project": pr} for pr, fn in sorted_ifn],
                "invalid_hash": [{"filename": fn, "project": pr} for pr, fn in sorted_ih],
                "missing_hash": [{"filename": fn, "project": pr} for pr, fn in sorted_mh],
                "missing_upload_time": [{"filename": fn, "project": pr} for pr, fn in sorted_mut],
                "project_over_file_cap": [{"project": pr} for pr in sorted_pofc],
                "schema": MANIFEST_SCHEMA,
                "unyanked_after_cutoff": [{"filename": fn, "project": pr} for pr, fn in sorted_uac],
                "unyanked_unknown_date": [{"filename": fn, "project": pr} for pr, fn in sorted_uud],
            }

    def to_canonical_json(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def save(self, path: str | Path) -> None:
        """Atomically persist manifest to disk as canonical JSON with mode 0600."""
        target_path = Path(path).resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with self._save_lock:
            payload = self.to_canonical_json()
            try:
                hermetic_safe_io.atomic_write(target_path, payload)
            except hermetic_safe_io.UnsafePathError as exc:
                raise SymlinkError("Refusing unsafe path for manifest write.") from exc
            except (ValueError, OSError) as exc:
                raise ManifestError(f"Failed writing manifest to {target_path}: {exc}") from exc

    @classmethod
    def load(cls, path: str | Path) -> Manifest:
        """Load manifest from disk verifying size cap and strict schema."""
        target_path = Path(path).resolve()
        try:
            fd = hermetic_safe_io.open_regular(target_path, MAX_MANIFEST_BYTES)
        except hermetic_safe_io.UnsafePathError as exc:
            raise SymlinkError("Refusing symlink or unsafe manifest file.") from exc
        except FileNotFoundError as exc:
            raise ManifestError(f"Manifest file not found: {target_path}") from exc
        except OSError as exc:
            raise ManifestError(f"Cannot open manifest file: {exc}") from exc

        chunks: list[bytes] = []
        total = 0
        try:
            max_loops = (MAX_MANIFEST_BYTES // FILE_CHUNK_BYTES) + 2
            for _ in range(max_loops):
                chunk = os.read(fd, FILE_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_MANIFEST_BYTES:
                    raise ManifestError("Manifest file exceeds size cap.")
                chunks.append(chunk)
        finally:
            os.close(fd)

        raw = b"".join(chunks)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestError("Corrupted manifest JSON.") from exc

        if isinstance(data, list):
            # Hand-written or legacy list format.
            try:
                records = [ManifestRecord.from_dict(item) for item in data]
                return cls(cutoff="", files=records)
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                raise ManifestError(f"Malformed manifest record: {exc}") from exc

        if not isinstance(data, dict):
            raise ManifestError("Manifest root must be a JSON object or array.")

        schema = data.get("schema")
        if schema != MANIFEST_SCHEMA:
            raise ManifestError(f"Unsupported or missing manifest schema: {schema!r}")

        cutoff = data.get("cutoff", "")
        raw_files = data.get("files", [])
        if not isinstance(raw_files, list):
            raise ManifestError("Manifest 'files' must be a list.")

        try:
            records = [ManifestRecord.from_dict(item) for item in raw_files]
            mut = data.get("missing_upload_time", [])
            uac = data.get("unyanked_after_cutoff", [])
            uud = data.get("unyanked_unknown_date", [])
            mh = data.get("missing_hash", [])
            ih = data.get("invalid_hash", [])
            ifn = data.get("invalid_filename", [])
            pofc = data.get("project_over_file_cap", [])

            return cls(
                cutoff=cutoff,
                files=records,
                missing_upload_time=mut if isinstance(mut, list) else None,
                unyanked_after_cutoff=uac if isinstance(uac, list) else None,
                unyanked_unknown_date=uud if isinstance(uud, list) else None,
                missing_hash=mh if isinstance(mh, list) else None,
                invalid_hash=ih if isinstance(ih, list) else None,
                invalid_filename=ifn if isinstance(ifn, list) else None,
                project_over_file_cap=pofc if isinstance(pofc, list) else None,
            )
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ManifestError(f"Malformed manifest entry: {exc}") from exc
