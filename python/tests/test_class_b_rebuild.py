"""Offline tests for Class B rebuild with repo_only fallback and labelling."""

from __future__ import annotations

import pytest

from hermetic_pkgbase.resolver import ResolvedFile, ResolvedRelease
from hermetic_slice.class_b import (
    ClassBError,
    ClassBRebuildResult,
    rebuild_class_b_environment,
)

CUTOFF = "2023-04-01T00:00:00Z"
PRE_CUTOFF = "2023-03-01T00:00:00Z"
POST_CUTOFF = "2023-05-01T00:00:00Z"


class MockResolver:
    """Mock pre-cutoff resolver for tests."""

    def __init__(self, table: dict[str, str | None]) -> None:
        self.table = table

    def resolve_package(self, project: str, cutoff_epoch_ns: int, ecosystem: str = "pypi") -> ResolvedRelease | None:
        version = self.table.get(project)
        if version is None:
            return None
        file_meta = ResolvedFile(
            filename=f"{project}-{version}.tar.gz",
            sha256="a" * 64,
            upload_time=PRE_CUTOFF,
            size_bytes=100,
            upload_time_ns=cutoff_epoch_ns - 1,
            project=project,
            ecosystem=ecosystem,
        )
        return ResolvedRelease(
            project=project,
            version=version,
            upload_time=PRE_CUTOFF,
            upload_time_ns=cutoff_epoch_ns - 1,
            files=(file_meta,),
            dependencies=(),
            ecosystem=ecosystem,
        )


def test_strict_rebuild_success_when_packages_already_at_cutoff():
    installed = [
        {"name": "numpy", "version": "1.22.0", "upload_time": PRE_CUTOFF},
        {"name": "scipy", "version": "1.8.0", "upload_time": PRE_CUTOFF},
    ]
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="strict")
    assert res.seal_level == "strict"
    assert res.class_b_status == "rebuilt_strict"
    assert res.fallback_reason is None
    assert res.d5b_warning_list is None
    assert res.warnings == ()
    assert len(res.rebuilt_packages) == 2
    assert res.rebuilt_packages[0]["version"] == "1.22.0"


def test_strict_rebuild_success_with_resolver():
    installed = [
        {"name": "requests", "version": "2.31.0", "upload_time": POST_CUTOFF},
    ]
    resolver = MockResolver({"requests": "2.28.2"})
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="strict", resolver=resolver)
    assert res.seal_level == "strict"
    assert res.class_b_status == "rebuilt_strict"
    assert res.fallback_reason is None
    assert res.d5b_warning_list is None
    assert len(res.rebuilt_packages) == 1
    assert res.rebuilt_packages[0]["name"] == "requests"
    assert res.rebuilt_packages[0]["version"] == "2.28.2"


def test_strict_rebuild_fallback_when_resolver_missing():
    installed = [
        {"name": "requests", "version": "2.31.0", "upload_time": POST_CUTOFF},
    ]
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="strict", resolver=None)
    assert res.seal_level == "repo_only"
    assert res.class_b_status == "fallback_repo_only"
    assert res.fallback_reason is not None
    assert "no resolver provided" in res.fallback_reason
    assert res.d5b_warning_list == ("requests==2.31.0",)
    assert len(res.warnings) == 1
    assert "requests 2.31.0 installed" in res.warnings[0]


def test_strict_rebuild_fallback_when_package_unresolvable_at_cutoff():
    installed = [
        {"name": "futurepkg", "version": "1.0.0", "upload_time": POST_CUTOFF},
    ]
    resolver = MockResolver({"futurepkg": None})  # Package did not exist at cutoff
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="strict", resolver=resolver)
    assert res.seal_level == "repo_only"
    assert res.class_b_status == "fallback_repo_only"
    assert res.fallback_reason is not None
    assert "no pre-cutoff release found for futurepkg" in res.fallback_reason
    assert res.d5b_warning_list == ("futurepkg==1.0.0",)


def test_strict_rebuild_fallback_when_resolver_raises():
    class FailingResolver:
        def resolve_package(self, project: str, cutoff_epoch_ns: int, ecosystem: str = "pypi"):
            raise RuntimeError("simulated resolver failure")

    installed = [
        {"name": "pkg", "version": "2.0.0", "upload_time": POST_CUTOFF},
    ]
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="strict", resolver=FailingResolver())
    assert res.seal_level == "repo_only"
    assert res.class_b_status == "fallback_repo_only"
    assert res.fallback_reason is not None
    assert "simulated resolver failure" in res.fallback_reason


def test_repo_only_mode_never_rebuilds_and_lists_warnings():
    installed = [
        {"name": "pkg_old", "version": "1.0.0", "upload_time": PRE_CUTOFF},
        {"name": "pkg_new", "version": "2.0.0", "upload_time": POST_CUTOFF},
        {"name": "pkg_unknown", "version": "3.0.0"},
    ]
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="repo_only")
    assert res.seal_level == "repo_only"
    assert res.class_b_status == "fallback_repo_only"
    assert res.fallback_reason is None
    assert res.d5b_warning_list == ("pkg_new==2.0.0", "pkg_unknown==3.0.0")
    assert len(res.warnings) == 2


def test_validation_errors():
    with pytest.raises(ClassBError, match="Invalid target_mode"):
        rebuild_class_b_environment([], CUTOFF, target_mode="invalid")

    with pytest.raises(ClassBError, match="installed_packages must be a list"):
        rebuild_class_b_environment("not a list", CUTOFF)  # type: ignore[arg-type]

    with pytest.raises(ClassBError, match="Invalid package name"):
        rebuild_class_b_environment([{"name": "../evil", "version": "1.0.0"}], CUTOFF)

    with pytest.raises(ClassBError, match="Invalid package version"):
        rebuild_class_b_environment([{"name": "ok", "version": "1.0/bad"}], CUTOFF)


def test_canonical_dictionary_output():
    installed = [
        {"name": "mypkg", "version": "2.0.0", "upload_time": POST_CUTOFF},
    ]
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="repo_only")
    d = res.to_dict()
    assert d["seal_level"] == "repo_only"
    assert d["class_b_status"] == "fallback_repo_only"
    assert d["d5b_warning_list"] == ["mypkg==2.0.0"]
    assert "mypkg 2.0.0 installed" in d["warnings"][0]


def test_invalid_cutoff_raises_class_b_error():
    with pytest.raises(ClassBError, match="Invalid cutoff timestamp"):
        rebuild_class_b_environment([], "not-a-date")


def test_unknown_upload_time_warning_unverified():
    installed = [
        {"name": "pkg_no_time", "version": "1.0.0"},
        {"name": "pkg_bad_time", "version": "1.0.0", "upload_time": "garbage"},
        {"name": "pkg_newer", "version": "1.0.0", "upload_time": POST_CUTOFF},
    ]
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="repo_only")
    assert res.d5b_warning_list == (
        "pkg_bad_time==1.0.0",
        "pkg_newer==1.0.0",
        "pkg_no_time==1.0.0",
    )
    assert "pkg_no_time 1.0.0 installed upload time could not be verified (repo_only: listed, not rebuilt)" in res.warnings
    assert "pkg_bad_time 1.0.0 installed upload time could not be verified (repo_only: listed, not rebuilt)" in res.warnings
    assert "pkg_newer 1.0.0 installed (uploaded 2023-05-01) is newer than T_world 2023-04-01 (repo_only: listed, not rebuilt)" in res.warnings


def test_cutoff_boundary_inclusion_exact_and_after():
    from hermetic_apt_snapshot.select import parse_rfc3339_utc_nanos

    cutoff_ns = parse_rfc3339_utc_nanos(CUTOFF)

    class BoundaryResolver:
        def __init__(self, upload_ns: int) -> None:
            self.upload_ns = upload_ns

        def resolve_package(self, project: str, cutoff_epoch_ns: int, ecosystem: str = "pypi") -> ResolvedRelease | None:
            if self.upload_ns >= cutoff_epoch_ns:
                return None
            file_meta = ResolvedFile(
                filename=f"{project}-1.0.0.tar.gz",
                sha256="b" * 64,
                upload_time=CUTOFF,
                size_bytes=100,
                upload_time_ns=self.upload_ns,
                project=project,
                ecosystem=ecosystem,
            )
            return ResolvedRelease(
                project=project,
                version="1.0.0",
                upload_time=CUTOFF,
                upload_time_ns=self.upload_ns,
                files=(file_meta,),
                dependencies=(),
                ecosystem=ecosystem,
            )

    installed = [{"name": "mypkg", "version": "2.0.0", "upload_time": POST_CUTOFF}]

    res_exact = rebuild_class_b_environment(
        installed, CUTOFF, target_mode="strict", resolver=BoundaryResolver(cutoff_ns)
    )
    assert res_exact.seal_level == "strict"
    assert res_exact.class_b_status == "rebuilt_strict"
    assert res_exact.rebuilt_packages[0]["version"] == "1.0.0"

    res_after = rebuild_class_b_environment(
        installed, CUTOFF, target_mode="strict", resolver=BoundaryResolver(cutoff_ns + 1)
    )
    assert res_after.seal_level == "repo_only"
    assert res_after.class_b_status == "fallback_repo_only"


def test_strict_rebuild_fallback_resolver_oserror_no_host_path():
    class PathLeakingResolver:
        def resolve_package(self, project: str, cutoff_epoch_ns: int, ecosystem: str = "pypi"):
            raise OSError("/home/user/secret/workspace/path/failed.txt")

    installed = [{"name": "pkg", "version": "2.0.0", "upload_time": POST_CUTOFF}]
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="strict", resolver=PathLeakingResolver())
    assert res.seal_level == "repo_only"
    assert res.class_b_status == "fallback_repo_only"
    assert res.fallback_reason is not None
    assert "/home" not in res.fallback_reason
    assert "/home" not in str(res.to_dict())


def test_strict_rebuild_fallback_when_resolver_missing_unknown_upload_time():
    installed = [
        {"name": "requests", "version": "2.31.0"},
    ]
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="strict", resolver=None)
    assert res.seal_level == "repo_only"
    assert res.class_b_status == "fallback_repo_only"
    assert res.fallback_reason == "class_b_rebuild_failed: package requests 2.31.0 upload time could not be verified and no resolver provided"
    assert "upload time could not be verified" in res.warnings[0]


def test_strict_rebuild_fallback_resolver_canonical_result_no_exception_detail():
    class PathLeakingResolver:
        def resolve_package(self, project: str, cutoff_epoch_ns: int, ecosystem: str = "pypi"):
            raise RuntimeError("/home/user/secret/workspace/path/failed.txt with a very long message " * 10)

    installed = [{"name": "pkg", "version": "2.0.0", "upload_time": POST_CUTOFF}]
    res = rebuild_class_b_environment(installed, CUTOFF, target_mode="strict", resolver=PathLeakingResolver())
    assert res.seal_level == "repo_only"
    assert res.class_b_status == "fallback_repo_only"
    assert res.fallback_reason == "class_b_rebuild_failed: resolver error for pkg"
    d = res.to_dict()
    assert d["fallback_reason"] == "class_b_rebuild_failed: resolver error for pkg"
    assert "/home" not in str(d)
    assert len(d["fallback_reason"]) <= 256
