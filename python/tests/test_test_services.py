"""Service declarations, safe reads, and offline container lifecycle regressions."""

import hashlib
import json
import os
import uuid

import pytest

from hermetic_safe_io import UnsafePathError
from hermetic_slice import grader
from hermetic_slice import test_services as ts
from hermetic_slice.dockerutil import is_docker_available, run_docker

CLOCK = "2015-07-01T00:00:00Z"


def task():
    return {"instance_id": "psf__requests-2317", "repo": "psf/requests",
            "base_commit": ts.REQUESTS_BASE, "cutoffs": {"t_clock": CLOCK}}


def test_service_declaration_and_legacy_task_migration(tmp_path):
    plan = ts.load_test_services(tmp_path, task())
    assert plan.names == ("httpbin-v1",)
    assert plan.t_clock == 1435708800
    assert ts.declared_services("psf/requests", "0" * 40) == []
    assert ts.declared_services("other/repo", ts.REQUESTS_BASE) == []
    assert ts.load_test_services(tmp_path, {"repo": "other/repo"}).names == ()
    assert ts.load_test_services(tmp_path, dict(task(), test_services=[])).names == ()
    assert ts.load_test_services(tmp_path, {}).command("container") == ["exec", "container", "/bin/bash", "/eval.sh"]


def test_sealed_manifest_is_authoritative_and_conflicts_fail_closed(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"test_services": [], "cutoffs": {"t_clock": CLOCK}}))
    assert ts.load_test_services(tmp_path, task()).names == ()
    with pytest.raises(ValueError, match="conflicting"):
        ts.load_test_services(tmp_path, dict(task(), test_services=["httpbin-v1"]))
    (tmp_path / "manifest.json").write_text(json.dumps({"test_services": ["httpbin-v1"], "cutoffs": {"t_clock": CLOCK}}))
    assert ts.load_test_services(tmp_path, task()).names == ("httpbin-v1",)


@pytest.mark.parametrize("names", [None, "httpbin-v1", ["arbitrary-command"], ["httpbin-v1", "httpbin-v1"], [{}]])
def test_invalid_manifest_services_are_rejected(tmp_path, names):
    (tmp_path / "manifest.json").write_text(json.dumps({"test_services": names}))
    with pytest.raises(ValueError):
        ts.load_test_services(tmp_path, task())


@pytest.mark.parametrize("clock", [None, "2015-07-01T00:00:00", "2015-07-01T00:00:00.1Z", "1970-01-01T00:00:00Z", "2101-01-01T00:00:00Z", "secret-invalid-clock"])
def test_service_clock_requires_an_explicit_bounded_cutoff(tmp_path, clock):
    with pytest.raises(ValueError, match="^invalid test-service clock$"):
        ts.load_test_services(tmp_path, dict(task(), cutoffs={"t_clock": clock}))


@pytest.mark.parametrize("raw", [b'{"test_services":[],"test_services":["httpbin-v1"]}', b"[", b"[]", b"[" * 2000])
def test_malformed_or_ambiguous_manifest_is_rejected(tmp_path, raw):
    (tmp_path / "manifest.json").write_bytes(raw)
    with pytest.raises(ValueError):
        ts.load_test_services(tmp_path, task())


def test_manifest_reads_reject_links_special_files_and_byte_overflow(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text('{"test_services":[]}')
    manifest = tmp_path / "manifest.json"
    manifest.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        ts.load_test_services(tmp_path, task())
    manifest.unlink()
    os.mkfifo(manifest)
    with pytest.raises(UnsafePathError):
        ts.load_test_services(tmp_path, task())
    manifest.unlink()
    with manifest.open("wb") as stream:
        stream.truncate(ts.MAX_MANIFEST_BYTES + 1)
    with pytest.raises(UnsafePathError):
        ts.load_test_services(tmp_path, task())
    manifest.unlink()
    directory = tmp_path / "link"
    directory.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(UnsafePathError):
        ts.load_test_services(directory, task())


def _write_task(directory, declaration):
    directory.mkdir()
    staging = directory / "staging"
    staging.mkdir()
    script = b": '>>>>> Start Test Output'\necho 'PASSED test_httpbin'\n: '>>>>> End Test Output'\n"
    (staging / "eval.sh").write_bytes(script)
    (staging / "eval_spec.json").write_text(json.dumps({"eval_sh_sha256": hashlib.sha256(script).hexdigest(), "log_parser": "parse_log_pytest"}))
    (staging / "test.patch").write_text("")
    data = dict(task(), test_services=declaration, tests={"PASS_TO_PASS": ["test_httpbin"]})
    (directory / "task.json").write_text(json.dumps(data))


def test_grader_validates_services_before_creating_files_or_container(tmp_path, monkeypatch):
    directory = tmp_path / "task"
    _write_task(directory, ["untrusted-command"])
    monkeypatch.setattr(grader, "run_docker", lambda *a, **kw: pytest.fail("created a container"))
    with pytest.raises(ValueError, match="unknown test service"):
        grader.grade(directory, "", image="offline", out_dir=tmp_path / "result")
    assert not (tmp_path / "result").exists()


def test_grader_injects_service_and_launches_it_only_for_declared_tasks(tmp_path, monkeypatch):
    calls, sources = [], []

    def docker(args, **kwargs):
        calls.append(args)
        if "input" in kwargs:
            sources.append(kwargs["input"])
        return b">>>>> Start Test Output\nPASSED test_httpbin\n>>>>> End Test Output\n>>>>> Test Exit Code: 0\n"

    monkeypatch.setattr(grader, "run_docker", docker)
    for name, declaration in (("with-service", ["httpbin-v1"]), ("without-service", [])):
        directory = tmp_path / name
        _write_task(directory, declaration)
        result = grader.grade(directory, "", image="offline", out_dir=tmp_path / (name + "-out"))
        assert result["resolved"] is True
        assert result["test_services"] == declaration
        assert calls[-1][0:2] == ["rm", "-f"]
    assert sources == [ts.service_source()]
    creates = [args for args in calls if args[0] == "create"]
    assert len(creates) == 2 and all(args[1:3] == ["--network", "none"] for args in creates)
    launches = [args for args in calls if args[0] == "exec"]
    assert "--t-clock 1435708800 --run /bin/bash /eval.sh" in launches[0][-1]
    assert launches[1][-2:] == ["/bin/bash", "/eval.sh"]


@pytest.mark.docker
@pytest.mark.skipif(not is_docker_available(), reason="Docker unavailable")
def test_grader_runs_declared_httpbin_in_the_networkless_sandbox(tmp_path):
    directory = tmp_path / "task"
    _write_task(directory, ["httpbin-v1"])
    script = b"""set -ex
: '>>>>> Start Test Output'
python -I - <<'PY'
import json, os, urllib.request
with urllib.request.urlopen(os.environ['HTTPBIN_URL'] + 'get', timeout=3) as response:
    assert response.headers['Date'] == 'Wed, 01 Jul 2015 00:00:00 GMT'
    assert json.load(response)['args'] == {}
print('PASSED test_httpbin')
PY
: '>>>>> End Test Output'
"""
    (directory / "staging" / "eval.sh").write_bytes(script)
    (directory / "staging" / "eval_spec.json").write_text(json.dumps({
        "eval_sh_sha256": hashlib.sha256(script).hexdigest(), "log_parser": "parse_log_pytest"}))
    result = grader.grade(directory, "", image="python:3.9-slim", out_dir=tmp_path / "result", timeout=30)
    assert result["status"] == "graded"
    assert result["resolved"] is True
    assert result["p2p"] == {"success": ["test_httpbin"], "failure": []}
    assert result["network"] == "none"
    assert result["test_services"] == ["httpbin-v1"]


def test_intake_publishes_the_selected_service_profile(tmp_path, monkeypatch):
    from hermetic_slice import intake
    from tests.helpers import build_intake_synthetic_repo
    from tests.test_intake import make_fake_http_get

    http = make_fake_http_get()
    rows = intake.load_verified(http, tmp_path / "cache")
    repo = build_intake_synthetic_repo(tmp_path, base_date="2019-11-15T00:00:00Z")
    row = dict(rows["pytest-dev__pytest-6202"], base_commit=repo.base_sha)
    selected = []

    def select(repo_name, base):
        selected.append((repo_name, base))
        return ["httpbin-v1"]

    monkeypatch.setattr(intake, "declared_services", select)
    directory = intake.intake_task("pytest-dev__pytest-6202", {"pytest-dev__pytest-6202": row},
                                  http, tmp_path / "cache", tmp_path / "out", clone_url=str(repo.path))
    published = json.loads((directory / "task.json").read_text())
    assert selected == [("pytest-dev/pytest", repo.base_sha)]
    assert published["test_services"] == ["httpbin-v1"]


@pytest.mark.docker
@pytest.mark.skipif(not is_docker_available(), reason="Docker unavailable")
def test_declared_service_runs_inside_offline_container_and_cleans_up(tmp_path):
    # No builds, pulls, target repository, or external network are used.
    name = "hermetic-t05-test-" + uuid.uuid4().hex[:12]
    script = r'''
import json, os, socket, urllib.request
assert os.environ['HTTPBIN_URL'] == 'http://127.0.0.1:8765/'
assert 'HTTP_PROXY' not in os.environ and 'ALL_PROXY' not in os.environ
with urllib.request.urlopen(os.environ['HTTPBIN_URL'] + 'get', timeout=3) as r:
    assert r.headers['Date'] == 'Wed, 01 Jul 2015 00:00:00 GMT'
    assert json.load(r)['origin'] == '127.0.0.1'
try:
    socket.create_connection(('1.1.1.1', 80), timeout=0.1)
except OSError:
    pass
else:
    raise AssertionError('external network reachable')
print('service-ok')
'''
    try:
        run_docker(["create", "--pull=never", "--network", "none", "--name", name,
                    "-e", "HTTP_PROXY=http://must-not-be-used.invalid", "-e", "ALL_PROXY=http://must-not-be-used.invalid",
                    "python:3.9-slim", "sleep", "infinity"])
        run_docker(["start", name])
        output = run_docker(["exec", "-i", name, "python", "-I", "-c", ts.GUEST_LOADER,
                             "--t-clock", "1435708800", "--run", "python", "-I", "-c", script],
                            input=ts.service_source(), timeout=30)
        assert output == b"service-ok\n"
        # The wrapper has returned and released the listener while the sandbox
        # still exists. A subsequent run cannot reach an orphaned service.
        check = "import socket; s=socket.socket(); assert s.connect_ex(('127.0.0.1',8765)) != 0"
        run_docker(["exec", name, "python", "-I", "-c", check], timeout=5)
        assert run_docker(["inspect", "--format", "{{.HostConfig.NetworkMode}}", name]).strip() == b"none"
    finally:
        run_docker(["rm", "-f", name], check=False)

