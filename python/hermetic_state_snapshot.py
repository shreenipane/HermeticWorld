"""Offline state-task handoff and grading records for architecture section 11.4.

These bytes are produced by the trusted harness after access is closed and the
VM is paused. They do not attest that those actions happened. The consumer must
obtain the expected digests independently, verify artifact bytes before use, and
perform restore in an isolated VM. No guest disk is opened or mounted here.
"""

from dataclasses import dataclass
import hashlib
import json
import os
import re

from hermetic_npm_cut.cut import HermeticNpmCutError, parse_json_bytes
from hermetic_safe_io import IO_CHUNK_BYTES, UnsafePathError, open_regular

MAX_DOCUMENT_BYTES = 16 * 1024
MAX_STATE_BYTES = 64 * 1024 * 1024
MAX_MEMORY_BYTES = 128 * 1024 * 1024 * 1024
MAX_DISK_BYTES = 64 * 1024 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 256 * 1024 * 1024 * 1024
MAX_TESTS_BYTES = MAX_DISK_BYTES
MAX_RESULT_BYTES = 1024 * 1024
MAX_DRIVE_ID_BYTES = 32
RUNTIME_FIELDS = frozenset({"firecracker", "cpu_model", "cpu_template", "kernel", "initramfs"})
ARTIFACT_CAPS = {"state": MAX_STATE_BYTES, "memory": MAX_MEMORY_BYTES,
                 "base": MAX_DISK_BYTES, "overlay": MAX_DISK_BYTES}
HANDOFF_FIELDS = {"schema", "run_sha256", "runtime", "artifacts", "tests_drive",
                  "network_interfaces", "access_closed", "paused", "clock"}


class SnapshotError(ValueError):
    """Fixed diagnostics contain no input values or host information."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value) -> str:
    if (type(value) is not str or len(value) != 64
            or re.fullmatch(r"[0-9a-f]{64}", value) is None):
        raise SnapshotError("invalid snapshot digest")
    return value


def _encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _object(raw: bytes, fields: set[str]) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_DOCUMENT_BYTES:
        raise SnapshotError("snapshot document byte cap or type violation")
    try:
        value = parse_json_bytes(raw, MAX_DOCUMENT_BYTES)
    except HermeticNpmCutError:
        raise SnapshotError("invalid snapshot JSON") from None
    if type(value) is not dict or set(value) != fields:
        raise SnapshotError("invalid snapshot document fields")
    return value


def _artifact(value, cap: int) -> int:
    if (type(value) is not dict or set(value) != {"sha256", "size"}
            or type(value["size"]) is not int or not 0 < value["size"] <= cap):
        raise SnapshotError("invalid snapshot artifact or byte cap")
    _digest(value["sha256"])
    return value["size"]


def _handoff(raw: bytes) -> dict:
    value = _object(raw, HANDOFF_FIELDS)
    if (value["schema"] != "hermetic-state-snapshot/v1" or value["clock"] != "faked"
            or value["access_closed"] is not True or value["paused"] is not True):
        raise SnapshotError("invalid snapshot handoff policy")
    _digest(value["run_sha256"])
    runtime = value["runtime"]
    if type(runtime) is not dict or set(runtime) != RUNTIME_FIELDS:
        raise SnapshotError("invalid snapshot runtime fields")
    for pin in runtime.values():
        _digest(pin)
    artifacts = value["artifacts"]
    if type(artifacts) is not dict or set(artifacts) != set(ARTIFACT_CAPS):
        raise SnapshotError("invalid snapshot artifact inventory")
    total = sum(_artifact(artifacts[name], cap) for name, cap in ARTIFACT_CAPS.items())
    if total > MAX_TOTAL_ARTIFACT_BYTES:
        raise SnapshotError("snapshot aggregate artifact byte cap exceeded")
    drive = value["tests_drive"]
    if (type(drive) is not str or not 0 < len(drive) <= MAX_DRIVE_ID_BYTES
            or re.fullmatch(r"[a-z][a-z0-9_-]*", drive) is None
            or drive in {"root", "overlay"}):
        raise SnapshotError("invalid reserved tests drive")
    # AgentVM has at most its single link to NetVM. Every restored interface
    # must be redirected to a tap with no peer before resuming any vCPU.
    if type(value["network_interfaces"]) is not list or value["network_interfaces"] not in ([], ["eth0"]):
        raise SnapshotError("invalid snapshot network inventory")
    return value


def prepare_snapshot_handoff(raw_recipe: bytes) -> bytes:
    """Validate all fields and produce canonical bytes without accessing files."""
    return _encode(_handoff(raw_recipe))


@dataclass(frozen=True)
class SnapshotHandoff:
    manifest: bytes
    sha256: str
    runtime_sha256: str
    tests_drive: str
    network_interfaces: tuple[str, ...]


def verify_snapshot_handoff(raw_manifest: bytes, expected_sha256: str,
                            run_sha256: str, runtime_sha256: str) -> SnapshotHandoff:
    """Require trusted run, manifest and destination-runtime pins before restore.

    runtime_sha256 hashes the canonical runtime object, including the approved
    CPU model and exact Firecracker build. It must be supplied by the destination
    harness, rather than copied from the received handoff. Paths and host names
    are deliberately absent; artifact resolution belongs to the isolated runner.
    """
    for pin in (expected_sha256, run_sha256, runtime_sha256):
        _digest(pin)
    value = _handoff(raw_manifest)
    if (_sha(raw_manifest) != expected_sha256 or _encode(value) != raw_manifest
            or value["run_sha256"] != run_sha256
            or _sha(_encode(value["runtime"])) != runtime_sha256):
        raise SnapshotError("snapshot handoff authentication or compatibility failed")
    return SnapshotHandoff(raw_manifest, expected_sha256, runtime_sha256,
                           value["tests_drive"], tuple(value["network_interfaces"]))


@dataclass(frozen=True)
class SnapshotArtifacts:
    handoff: SnapshotHandoff
    artifacts: tuple[tuple[str, bytes], ...]


def verify_snapshot_artifacts(raw_manifest: bytes, expected_sha256: str,
                              run_sha256: str, runtime_sha256: str,
                              artifacts: dict[str, bytes]) -> SnapshotArtifacts:
    """Authenticate supplied immutable bytes against independent handoff pins.

    Bound the complete inventory before hashing any payload. Returned bytes are
    the exact verified objects, independent of later changes to the input mapping.
    This in-memory boundary does not open files, mount disks or restore a VM;
    a runner must consume these bytes rather than reopening acquisition paths.
    """
    handoff = verify_snapshot_handoff(raw_manifest, expected_sha256, run_sha256, runtime_sha256)
    declarations = _handoff(handoff.manifest)["artifacts"]
    if type(artifacts) is not dict or len(artifacts) != len(ARTIFACT_CAPS):
        raise SnapshotError("invalid snapshot payload inventory")
    # Validate and collect from one private inventory across caller mutations.
    artifacts = artifacts.copy()
    if len(artifacts) != len(ARTIFACT_CAPS) or set(artifacts) != set(ARTIFACT_CAPS):
        raise SnapshotError("invalid snapshot payload inventory")
    ordered = tuple(sorted(artifacts.items()))
    total = 0
    for name, body in ordered:
        if (type(body) is not bytes or not 0 < len(body) <= ARTIFACT_CAPS[name]
                or len(body) != declarations[name]["size"]):
            raise SnapshotError("snapshot payload size or type mismatch")
        total += len(body)
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            raise SnapshotError("snapshot aggregate payload byte cap exceeded")
    for name, body in ordered:
        if _sha(body) != declarations[name]["sha256"]:
            raise SnapshotError("snapshot payload digest mismatch")
    return SnapshotArtifacts(handoff, ordered)


def build_state_grade_record(raw_manifest: bytes, expected_sha256: str,
                             run_sha256: str, runtime_sha256: str, raw_result: bytes) -> bytes:
    """Bind a grading-path record to the authenticated handoff and test/result pins.

    A reboot uses the pinned trusted kernel/initramfs and a copy of the overlay;
    live restore uses the snapshot's memory and disk. Both retain shared isolation.
    This record carries no pass/fail claim: a leftover root process can forge
    guest results, as section 11.4 explains. The run attestation must embed it.
    """
    handoff = verify_snapshot_handoff(raw_manifest, expected_sha256, run_sha256, runtime_sha256)
    result = _object(raw_result, {"path", "fallback_reason", "tests", "result"})
    path, reason = result["path"], result["fallback_reason"]
    if not ((path == "live" and reason is None)
            or (path == "reboot" and type(reason) is str
                and reason in {"execd_unresponsive", "no_live_state"})):
        raise SnapshotError("invalid state grading path or fallback reason")
    _artifact(result["tests"], MAX_TESTS_BYTES)
    _artifact(result["result"], MAX_RESULT_BYTES)
    record = dict(result, schema="hermetic-state-grade/v1", grader_isolation="shared",
                  snapshot_sha256=handoff.sha256, run_sha256=run_sha256)
    raw = _encode(record)
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise SnapshotError("snapshot record output byte cap exceeded")
    return raw


@dataclass(frozen=True)
class VerifiedArtifactFile:
    name: str
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class SnapshotFiles:
    handoff: SnapshotHandoff
    artifacts: tuple[VerifiedArtifactFile, ...]


def load_snapshot_files(manifest_path: str | os.PathLike[str],
                        artifacts_dir: str | os.PathLike[str] | dict[str, str | os.PathLike[str]],
                        expected_sha256: str,
                        run_sha256: str,
                        runtime_sha256: str) -> SnapshotFiles:
    """Safely verify immutable snapshot files on disk using descriptor-pinned I/O.

    Rejects symlinks, FIFOs, special devices, directory mutations, and tampered
    or oversized files. Streams contents in bounded chunks without loading
    large disks into memory. Fixed errors never leak host paths or names.
    """
    try:
        manifest_raw_path = os.fspath(manifest_path)
    except Exception:
        raise SnapshotError("invalid snapshot manifest path") from None

    try:
        manifest_fd = open_regular(manifest_raw_path, MAX_DOCUMENT_BYTES)
    except (UnsafePathError, OSError, ValueError):
        raise SnapshotError("snapshot manifest file access failed") from None

    try:
        try:
            chunks = []
            total = 0
            while total <= MAX_DOCUMENT_BYTES:
                chunk = os.read(manifest_fd, IO_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                chunks.append(chunk)
            if total > MAX_DOCUMENT_BYTES:
                raise SnapshotError("snapshot document byte cap or type violation")
            raw_manifest = b"".join(chunks)
        except OSError:
            raise SnapshotError("snapshot manifest read failed") from None
    finally:
        os.close(manifest_fd)

    handoff = verify_snapshot_handoff(raw_manifest, expected_sha256, run_sha256, runtime_sha256)
    declarations = _handoff(handoff.manifest)["artifacts"]

    if isinstance(artifacts_dir, dict):
        if set(artifacts_dir) != set(ARTIFACT_CAPS):
            raise SnapshotError("invalid snapshot payload inventory")
        paths = {}
        for name in ARTIFACT_CAPS:
            try:
                paths[name] = os.fspath(artifacts_dir[name])
            except Exception:
                raise SnapshotError("invalid snapshot artifact path") from None
    elif isinstance(artifacts_dir, (str, os.PathLike)):
        try:
            base_dir = os.fspath(artifacts_dir)
            paths = {name: os.path.join(base_dir, name) for name in ARTIFACT_CAPS}
        except Exception:
            raise SnapshotError("invalid snapshot artifacts directory") from None
    else:
        raise SnapshotError("invalid snapshot artifacts specification")

    total_size = 0
    verified_list = []
    for name in sorted(ARTIFACT_CAPS):
        cap = ARTIFACT_CAPS[name]
        expected_size = declarations[name]["size"]
        expected_sha = declarations[name]["sha256"]
        file_path = paths[name]

        try:
            fd = open_regular(file_path, cap)
        except (UnsafePathError, OSError, ValueError):
            raise SnapshotError("snapshot artifact file access failed") from None

        try:
            try:
                st = os.fstat(fd)
                if st.st_size != expected_size:
                    raise SnapshotError("snapshot payload size or type mismatch")
                total_size += st.st_size
                if total_size > MAX_TOTAL_ARTIFACT_BYTES:
                    raise SnapshotError("snapshot aggregate payload byte cap exceeded")

                hasher = hashlib.sha256()
                bytes_read = 0
                while bytes_read <= expected_size:
                    chunk = os.read(fd, IO_CHUNK_BYTES)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    hasher.update(chunk)
                if bytes_read != expected_size:
                    raise SnapshotError("snapshot payload size or type mismatch")
                if hasher.hexdigest() != expected_sha:
                    raise SnapshotError("snapshot payload digest mismatch")
            except OSError:
                raise SnapshotError("snapshot artifact read failed") from None
        finally:
            os.close(fd)

        verified_list.append(VerifiedArtifactFile(name=name, path=file_path, size=expected_size, sha256=expected_sha))

    return SnapshotFiles(handoff, tuple(verified_list))


def load_snapshot_artifacts_from_files(manifest_path: str | os.PathLike[str],
                                       artifacts_dir: str | os.PathLike[str] | dict[str, str | os.PathLike[str]],
                                       expected_sha256: str,
                                       run_sha256: str,
                                       runtime_sha256: str) -> SnapshotArtifacts:
    """Verify snapshot files on disk and return verified immutable bytes in memory."""
    try:
        manifest_raw_path = os.fspath(manifest_path)
    except Exception:
        raise SnapshotError("invalid snapshot manifest path") from None

    try:
        manifest_fd = open_regular(manifest_raw_path, MAX_DOCUMENT_BYTES)
    except (UnsafePathError, OSError, ValueError):
        raise SnapshotError("snapshot manifest file access failed") from None

    try:
        try:
            chunks = []
            total = 0
            while total <= MAX_DOCUMENT_BYTES:
                chunk = os.read(manifest_fd, IO_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                chunks.append(chunk)
            if total > MAX_DOCUMENT_BYTES:
                raise SnapshotError("snapshot document byte cap or type violation")
            raw_manifest = b"".join(chunks)
        except OSError:
            raise SnapshotError("snapshot manifest read failed") from None
    finally:
        os.close(manifest_fd)

    handoff = verify_snapshot_handoff(raw_manifest, expected_sha256, run_sha256, runtime_sha256)
    declarations = _handoff(handoff.manifest)["artifacts"]

    if isinstance(artifacts_dir, dict):
        if set(artifacts_dir) != set(ARTIFACT_CAPS):
            raise SnapshotError("invalid snapshot payload inventory")
        paths = {}
        for name in ARTIFACT_CAPS:
            try:
                paths[name] = os.fspath(artifacts_dir[name])
            except Exception:
                raise SnapshotError("invalid snapshot artifact path") from None
    elif isinstance(artifacts_dir, (str, os.PathLike)):
        try:
            base_dir = os.fspath(artifacts_dir)
            paths = {name: os.path.join(base_dir, name) for name in ARTIFACT_CAPS}
        except Exception:
            raise SnapshotError("invalid snapshot artifacts directory") from None
    else:
        raise SnapshotError("invalid snapshot artifacts specification")

    total_size = 0
    loaded = {}
    for name in sorted(ARTIFACT_CAPS):
        cap = ARTIFACT_CAPS[name]
        expected_size = declarations[name]["size"]
        expected_sha = declarations[name]["sha256"]
        file_path = paths[name]

        try:
            fd = open_regular(file_path, cap)
        except (UnsafePathError, OSError, ValueError):
            raise SnapshotError("snapshot artifact file access failed") from None

        try:
            try:
                st = os.fstat(fd)
                if st.st_size != expected_size:
                    raise SnapshotError("snapshot payload size or type mismatch")
                total_size += st.st_size
                if total_size > MAX_TOTAL_ARTIFACT_BYTES:
                    raise SnapshotError("snapshot aggregate payload byte cap exceeded")

                chunks = []
                bytes_read = 0
                while bytes_read <= expected_size:
                    chunk = os.read(fd, IO_CHUNK_BYTES)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    chunks.append(chunk)
                if bytes_read != expected_size:
                    raise SnapshotError("snapshot payload size or type mismatch")
                data = b"".join(chunks)
                if hashlib.sha256(data).hexdigest() != expected_sha:
                    raise SnapshotError("snapshot payload digest mismatch")
                loaded[name] = data
            except OSError:
                raise SnapshotError("snapshot artifact read failed") from None
        finally:
            os.close(fd)

    return SnapshotArtifacts(handoff, tuple(sorted(loaded.items())))

