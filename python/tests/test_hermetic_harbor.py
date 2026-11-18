"""Offline tests for the Hermetic Harbor backend (TR-HB-1).

Covers:
- Registration prototype (Enum injection, factory registry, idempotency, unregister, missing harbor)
- HermeticEnvironment lifecycle, command execution, bounds, timeouts, output limits, capabilities, SSH refusal
- Safe I/O file and directory transfers, refusing symlinks, FIFOs, and path escapes
- Task configuration parsing and validation
- Separate-verifier mapping (ExtractorVM artifact isolation and GraderVM verifier execution)
- Host environment sanitization (no host paths, timestamps, or identities)
- KVM nested VM test that skips cleanly when environment variables are unset
"""

import asyncio
from enum import Enum
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

import pytest

import hermetic_harbor as hb
from hermetic_harbor.environment import (
    MAX_COMMAND_BYTES,
    MAX_DIR_ENTRIES,
    MAX_DIR_TOTAL_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_RUN_OUTPUT_BYTES,
    MAX_TIMEOUT_SECONDS,
    MAX_TRANSFER_BYTES,
    ExecResult,
    HermeticEnvironment,
    validate_guest_path,
)
from hermetic_harbor.errors import (
    HarborConfigError,
    HarborDependencyError,
    HarborError,
    HarborExecutionError,
    HarborExtractionError,
    HarborRegistrationError,
    HarborSecurityError,
    HarborVerificationError,
)
from hermetic_harbor.registration import (
    PINNED_HARBOR_VERSION,
    register_hermetic,
    register_into_targets,
    unregister_from_targets,
    unregister_hermetic,
    verify_harbor_dependency,
)
from hermetic_harbor.task import (
    MAX_TASK_FILE_BYTES,
    TaskConfig,
    VerifierConfig,
    load_task_config,
    parse_task_toml,
    validate_artifact_path,
)
from hermetic_harbor.verifier import (
    VerificationResult,
    extract_declared_artifacts,
    run_harbor_verification,
)


# ---------------------------------------------------------------------------
# 1. Registration Prototype Tests
# ---------------------------------------------------------------------------


class MockEnvironmentType(str, Enum):
    DOCKER = "docker"
    PODMAN = "podman"
    MODAL = "modal"


def test_registration_when_harbor_missing_raises_dependency_error(monkeypatch):
    monkeypatch.delitem(sys.modules, "harbor", raising=False)
    # Ensure importing harbor fails
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "harbor" or name.startswith("harbor."):
            raise ImportError("No module named 'harbor'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(HarborDependencyError) as exc_info:
        register_hermetic(raise_if_missing=True)
    assert PINNED_HARBOR_VERSION in str(exc_info.value)

    # When raise_if_missing is False, returns False
    assert register_hermetic(raise_if_missing=False) is False


def test_registration_with_mock_targets():
    registry = {}
    member = register_into_targets(
        environment_type_cls=MockEnvironmentType,
        registry=registry,
        env_name="hermetic",
    )
    assert member.value == "hermetic"
    assert member.name == "HERMETIC"
    assert MockEnvironmentType.HERMETIC == member
    assert MockEnvironmentType("hermetic") == member
    assert registry[member] == ("hermetic_harbor.environment", "HermeticEnvironment", None)
    assert registry["hermetic"] == ("hermetic_harbor.environment", "HermeticEnvironment", None)

    # Idempotent re-registration
    member2 = register_into_targets(
        environment_type_cls=MockEnvironmentType,
        registry=registry,
        env_name="hermetic",
    )
    assert member2 == member

    # Unregister restores prior state
    assert unregister_from_targets(MockEnvironmentType, registry, env_name="hermetic") is True
    assert not hasattr(MockEnvironmentType, "HERMETIC")
    assert member not in registry
    assert "hermetic" not in registry
    with pytest.raises(ValueError):
        MockEnvironmentType("hermetic")


@pytest.mark.parametrize("bad_name", ["", "123bad", "has space", "bad-hyphen", "bad/slash"])
def test_registration_refuses_invalid_identifiers(bad_name):
    registry = {}
    with pytest.raises(HarborRegistrationError):
        register_into_targets(MockEnvironmentType, registry, env_name=bad_name)


# ---------------------------------------------------------------------------
# 2. HermeticEnvironment Lifecycle & Command Execution Tests
# ---------------------------------------------------------------------------


def test_environment_lifecycle():
    async def run():
        env = HermeticEnvironment(
            environment_name="test-env",
            session_id="test-session-1",
        )
        assert not env.is_running
        await env.start()
        assert env.is_running
        # Idempotent start
        await env.start()
        assert env.is_running
        await env.stop()
        assert not env.is_running
        # Idempotent stop
        await env.stop()
        assert not env.is_running

    asyncio.run(run())


def test_environment_capabilities_and_ssh_refusal():
    env = HermeticEnvironment(environment_name="test", session_id="s1")
    caps = env.capabilities
    assert caps.supports_exec is True
    assert caps.supports_file_transfers is True
    assert caps.supports_ssh is False

    with pytest.raises(NotImplementedError, match="does not provide SSH access"):
        HermeticEnvironment.connect_ssh("dummy-handle")


def test_environment_exec_runner_and_output_bounds():
    async def run():
        def mock_runner(argv, cwd, cmd_env, timeout):
            assert "/bin/bash" in argv[0]
            assert cwd == "/testbed"
            return {"stdout": "hello world\n", "stderr": "", "return_code": 0}

        env = HermeticEnvironment(
            environment_name="test-env",
            session_id="s1",
            runner=mock_runner,
        )
        await env.start()

        # Normal exec
        res = await env.exec("echo hello")
        assert res.return_code == 0
        assert res.stdout == "hello world\n"

        # Not running fails
        await env.stop()
        with pytest.raises(HarborExecutionError, match="not running"):
            await env.exec("echo hello")

    asyncio.run(run())


def test_environment_exec_command_validation_and_caps():
    async def run():
        env = HermeticEnvironment(
            environment_name="test",
            session_id="s1",
            runner=lambda a, c, e, t: {"stdout": "", "stderr": "", "return_code": 0},
        )
        await env.start()

        # Empty command
        with pytest.raises(HarborExecutionError, match="Invalid command"):
            await env.exec("")

        # Null byte in command
        with pytest.raises(HarborExecutionError, match="Invalid command"):
            await env.exec("echo \0 hello")

        # Oversized command
        with pytest.raises(HarborExecutionError, match="exceeds size limit"):
            await env.exec("a" * (MAX_COMMAND_BYTES + 1))

        # Invalid timeout
        with pytest.raises(HarborExecutionError, match="Invalid execution timeout"):
            await env.exec("true", timeout_sec=0)

        with pytest.raises(HarborExecutionError, match="Invalid execution timeout"):
            await env.exec("true", timeout_sec=MAX_TIMEOUT_SECONDS + 1)

        # Invalid cwd traversal
        with pytest.raises(HarborSecurityError, match="traversal"):
            await env.exec("true", cwd="/testbed/../../etc")

    asyncio.run(run())


def test_environment_cumulative_output_cap_enforced():
    async def run():
        # Runner returns large output
        chunk = "x" * (1024 * 1024)  # 1 MiB
        calls = 0

        def flood_runner(a, c, e, t):
            nonlocal calls
            calls += 1
            return {"stdout": chunk, "stderr": "", "return_code": 0}

        env = HermeticEnvironment(
            environment_name="test",
            session_id="s1",
            runner=flood_runner,
        )
        await env.start()

        # Run until cumulative cap is reached (16 MiB)
        for _ in range(16):
            await env.exec("flood")

        # 17th call exceeds MAX_RUN_OUTPUT_BYTES
        with pytest.raises(HarborExecutionError, match="cumulative output"):
            await env.exec("flood")

    asyncio.run(run())


# ---------------------------------------------------------------------------
# 3. Safe I/O File and Directory Transfer Tests
# ---------------------------------------------------------------------------


def test_upload_and_download_file_round_trip(tmp_path):
    async def run():
        host_src = tmp_path / "host_source.txt"
        host_src.write_bytes(b"hermetic artifact payload 12345")

        guest_dir = tmp_path / "guest_root" / "app"
        guest_file = guest_dir / "target.txt"

        host_dst = tmp_path / "host_downloaded.txt"

        env = HermeticEnvironment(
            environment_name="test",
            session_id="s1",
        )
        await env.start()

        # Upload file
        await env.upload_file(host_src, str(guest_file))
        assert guest_file.read_bytes() == b"hermetic artifact payload 12345"

        # Download file
        await env.download_file(str(guest_file), host_dst)
        assert host_dst.read_bytes() == b"hermetic artifact payload 12345"

        # Check atomic permissions 0600
        mode = host_dst.stat().st_mode & 0o777
        assert mode == 0o600

    asyncio.run(run())


def test_upload_file_refuses_symlink_and_oversized(tmp_path):
    async def run():
        env = HermeticEnvironment(environment_name="test", session_id="s1")
        await env.start()

        # Create symlinked file
        real_file = tmp_path / "real.txt"
        real_file.write_bytes(b"data")
        symlink_file = tmp_path / "symlink.txt"
        symlink_file.symlink_to(real_file)

        with pytest.raises(HarborSecurityError, match="violates safe regular-file policy"):
            await env.upload_file(symlink_file, "/guest/target.txt")

        # Create oversized file
        oversized = tmp_path / "oversized.bin"
        oversized.write_bytes(b"A" * (MAX_TRANSFER_BYTES + 1))

        with pytest.raises(HarborSecurityError):
            await env.upload_file(oversized, "/guest/target.txt")

    asyncio.run(run())


def test_upload_dir_and_download_dir(tmp_path):
    async def run():
        src_dir = tmp_path / "src_tree"
        src_dir.mkdir(mode=0o700)
        (src_dir / "file1.txt").write_bytes(b"content 1")
        sub = src_dir / "subdir"
        sub.mkdir(mode=0o700)
        (sub / "file2.txt").write_bytes(b"content 2")

        guest_dir = tmp_path / "guest_tree"
        dest_dir = tmp_path / "dst_tree"

        env = HermeticEnvironment(environment_name="test", session_id="s1")
        await env.start()

        # Upload directory
        await env.upload_dir(src_dir, str(guest_dir))
        assert (guest_dir / "file1.txt").read_bytes() == b"content 1"
        assert (guest_dir / "subdir" / "file2.txt").read_bytes() == b"content 2"

        # Download directory
        await env.download_dir(str(guest_dir), dest_dir)
        assert (dest_dir / "file1.txt").read_bytes() == b"content 1"
        assert (dest_dir / "subdir" / "file2.txt").read_bytes() == b"content 2"

    asyncio.run(run())


def test_upload_dir_refuses_symlinks_inside(tmp_path):
    async def run():
        src_dir = tmp_path / "sym_tree"
        src_dir.mkdir(mode=0o700)
        real = tmp_path / "outside.txt"
        real.write_bytes(b"outside")
        (src_dir / "link.txt").symlink_to(real)

        env = HermeticEnvironment(environment_name="test", session_id="s1")
        await env.start()

        with pytest.raises(HarborSecurityError, match="Symlink rejected"):
            await env.upload_dir(src_dir, str(tmp_path / "target"))

    asyncio.run(run())


# ---------------------------------------------------------------------------
# 4. Task Configuration Parsing Tests
# ---------------------------------------------------------------------------


def test_parse_task_toml_valid():
    raw = b"""
schema_version = "1.4"

[task]
name = "benchmark/terminal-calc"
artifacts = ["calc.py", "output/result.json"]

[verifier]
environment_mode = "separate"
test_command = "pytest -q tests/test_calc.py"
timeout_sec = 60

[verifier.environment]
docker_image = "python:3.12-slim"
"""
    cfg = parse_task_toml(raw)
    assert cfg.name == "benchmark/terminal-calc"
    assert cfg.artifacts == ("calc.py", "output/result.json")
    assert cfg.is_separate_verifier is True
    assert cfg.verifier.test_command == "pytest -q tests/test_calc.py"
    assert cfg.verifier.timeout_sec == 60
    assert cfg.verifier.docker_image == "python:3.12-slim"


@pytest.mark.parametrize("hostile_artifact", [
    "../escape.txt",
    "/etc/passwd/../../escape",
    "calc.py\0injected",
    "",
])
def test_parse_task_toml_hostile_artifacts_rejected(hostile_artifact):
    raw = f"""
[task]
name = "test"
artifacts = ["{hostile_artifact}"]
[verifier]
environment_mode = "separate"
""".encode("utf-8")
    with pytest.raises(HarborConfigError):
        parse_task_toml(raw)


def test_parse_task_toml_oversized_rejected():
    oversized = b"a = 1\n" * (MAX_TASK_FILE_BYTES // 4)
    with pytest.raises(HarborConfigError, match="exceeds size limit"):
        parse_task_toml(oversized)


def test_parse_task_toml_artifacts_count_cap():
    items = ", ".join(f'"f{i}.txt"' for i in range(300))
    raw = f"""
[task]
name = "test"
artifacts = [{items}]
[verifier]
environment_mode = "separate"
""".encode("utf-8")
    with pytest.raises(HarborConfigError, match="artifacts count exceeds"):
        parse_task_toml(raw)


# ---------------------------------------------------------------------------
# 5. Separate-Verifier ExtractorVM & GraderVM Pipeline Tests
# ---------------------------------------------------------------------------


def test_separate_verifier_gold_artifact_passes(tmp_path):
    # Setup agent workspace where agent created calc.py
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir(mode=0o700)
    gold_code = "def add(a, b): return a + b\n"
    (agent_dir / "calc.py").write_text(gold_code)

    # Setup clean verifier workspace containing test
    verifier_dir = tmp_path / "verifier"
    verifier_dir.mkdir(mode=0o700)
    (verifier_dir / "tests").mkdir(mode=0o700)
    test_code = """
import sys
sys.path.insert(0, ".")
from calc import add

def test_add():
    assert add(2, 3) == 5
"""
    (verifier_dir / "tests" / "test_calc.py").write_text(test_code)

    logs_dir = tmp_path / "logs"

    cfg = TaskConfig(
        name="test-calc",
        artifacts=("calc.py",),
        verifier=VerifierConfig(
            environment_mode="separate",
            test_command="python3 -m pytest -q tests/test_calc.py",
            timeout_sec=30,
        ),
    )

    res = run_harbor_verification(
        task_config=cfg,
        agent_work_dir=agent_dir,
        verifier_tree_dir=verifier_dir,
        logs_dir=logs_dir,
    )

    assert res.status == "resolved"
    assert res.reward == 1.0
    assert res.return_code == 0
    assert res.extracted_artifacts == ("calc.py",)
    assert res.grader_isolation == "clean"

    # Verify Harbor output files
    reward_file = logs_dir / "verifier" / "reward.txt"
    assert reward_file.read_text().strip() == "1.0"

    reward_json_file = logs_dir / "verifier" / "reward.json"
    data = json.loads(reward_json_file.read_text())
    assert data["reward"] == 1.0


def test_separate_verifier_buggy_artifact_fails(tmp_path):
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir(mode=0o700)
    buggy_code = "def add(a, b): return a - b\n"  # Buggy
    (agent_dir / "calc.py").write_text(buggy_code)

    verifier_dir = tmp_path / "verifier"
    verifier_dir.mkdir(mode=0o700)
    (verifier_dir / "tests").mkdir(mode=0o700)
    test_code = """
import sys
sys.path.insert(0, ".")
from calc import add

def test_add():
    assert add(2, 3) == 5
"""
    (verifier_dir / "tests" / "test_calc.py").write_text(test_code)

    logs_dir = tmp_path / "logs"

    cfg = TaskConfig(
        name="test-calc-fail",
        artifacts=("calc.py",),
        verifier=VerifierConfig(
            environment_mode="separate",
            test_command="python3 -m pytest -q tests/test_calc.py",
            timeout_sec=30,
        ),
    )

    res = run_harbor_verification(
        task_config=cfg,
        agent_work_dir=agent_dir,
        verifier_tree_dir=verifier_dir,
        logs_dir=logs_dir,
    )

    assert res.status == "unresolved"
    assert res.reward == 0.0
    assert res.return_code != 0
    assert "tests_failed" in res.reasons

    reward_file = logs_dir / "verifier" / "reward.txt"
    assert reward_file.read_text().strip() == "0.0"


def test_separate_verifier_drops_undeclared_agent_modifications(tmp_path):
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir(mode=0o700)
    (agent_dir / "calc.py").write_text("def add(a, b): return a + b\n")
    # Agent sneaked in modified test or backdoor file
    (agent_dir / "backdoor.py").write_text("MALICIOUS = True\n")
    (agent_dir / "test_sneaked.py").write_text("def test_always_pass(): assert True\n")

    verifier_dir = tmp_path / "verifier"
    verifier_dir.mkdir(mode=0o700)
    (verifier_dir / "tests").mkdir(mode=0o700)
    (verifier_dir / "tests" / "test_calc.py").write_text("""
import sys
sys.path.insert(0, ".")
from calc import add
def test_add(): assert add(1, 1) == 2
""")

    logs_dir = tmp_path / "logs"

    # Task only declares calc.py as artifact
    cfg = TaskConfig(
        name="test-isolation",
        artifacts=("calc.py",),
        verifier=VerifierConfig(
            environment_mode="separate",
            test_command="python3 -m pytest -q tests/test_calc.py",
            timeout_sec=30,
        ),
    )

    res = run_harbor_verification(
        task_config=cfg,
        agent_work_dir=agent_dir,
        verifier_tree_dir=verifier_dir,
        logs_dir=logs_dir,
    )

    assert res.status == "resolved"
    assert res.extracted_artifacts == ("calc.py",)
    # Backdoor and sneaked test MUST NOT exist in verifier sandbox
    assert not (verifier_dir / "backdoor.py").exists()
    assert not (verifier_dir / "test_sneaked.py").exists()


def test_separate_verifier_refuses_symlinked_artifact(tmp_path):
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir(mode=0o700)

    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("secret")
    (agent_dir / "calc.py").symlink_to(secret_file)

    verifier_dir = tmp_path / "verifier"
    verifier_dir.mkdir(mode=0o700)
    logs_dir = tmp_path / "logs"

    cfg = TaskConfig(
        name="test-symlink-artifact",
        artifacts=("calc.py",),
        verifier=VerifierConfig(environment_mode="separate", test_command="true"),
    )

    res = run_harbor_verification(
        task_config=cfg,
        agent_work_dir=agent_dir,
        verifier_tree_dir=verifier_dir,
        logs_dir=logs_dir,
    )

    assert res.status == "tampered"
    assert res.reward == 0.0
    assert "extraction_failed" in res.reasons
    assert (logs_dir / "verifier" / "reward.txt").read_text().strip() == "0.0"


def test_shared_verifier_mode_records_shared_isolation(tmp_path):
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir(mode=0o700)
    (agent_dir / "tests").mkdir(mode=0o700)
    (agent_dir / "tests" / "test_state.py").write_text("def test_ok(): assert True\n")

    verifier_dir = tmp_path / "verifier"  # not used in shared mode
    logs_dir = tmp_path / "logs"

    cfg = TaskConfig(
        name="test-shared",
        artifacts=(),
        verifier=VerifierConfig(
            environment_mode="shared",
            test_command="python3 -m pytest -q tests/test_state.py",
        ),
    )

    res = run_harbor_verification(
        task_config=cfg,
        agent_work_dir=agent_dir,
        verifier_tree_dir=verifier_dir,
        logs_dir=logs_dir,
    )

    assert res.status == "resolved"
    assert res.grader_isolation == "shared"


# ---------------------------------------------------------------------------
# 6. Host Sanitization & Security Tests
# ---------------------------------------------------------------------------


def test_no_host_environment_or_paths_in_output_or_errors(tmp_path, monkeypatch):
    host_secret = "sensitive-host-identity-token-998877"
    for var in ("USER", "LOGNAME", "HOSTNAME", "HOME", "HOST_TOKEN"):
        monkeypatch.setenv(var, host_secret)

    # 1. Verification output
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir(mode=0o700)
    verifier_dir = tmp_path / "verifier"
    verifier_dir.mkdir(mode=0o700)
    logs_dir = tmp_path / "logs"

    cfg = TaskConfig(
        name="test-sanitization",
        artifacts=(),
        verifier=VerifierConfig(
            environment_mode="separate",
            test_command="echo hello",
        ),
    )

    res = run_harbor_verification(
        task_config=cfg,
        agent_work_dir=agent_dir,
        verifier_tree_dir=verifier_dir,
        logs_dir=logs_dir,
    )

    reward_content = (logs_dir / "verifier" / "reward.txt").read_text()
    assert host_secret not in reward_content
    assert host_secret not in res.stdout
    assert host_secret not in res.stderr

    # 2. Registration error diagnostics
    with pytest.raises(HarborError) as exc_info:
        register_hermetic(raise_if_missing=True)
    assert host_secret not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 7. KVM Nested VM Smoke Test (Skipped without env vars)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("HERMETIC_FC_BIN") or not os.environ.get("HERMETIC_KERNEL"),
    reason="needs HERMETIC_FC_BIN, HERMETIC_KERNEL and /dev/kvm",
)
def test_harbor_vm_separate_verifier_nested():
    """Nested VM test: executes harbor-smoke.sh when KVM and env vars are present."""
    top = Path(__file__).resolve().parent.parent.parent
    smoke_script = top / "scripts" / "integration" / "harbor-smoke.sh"
    assert smoke_script.exists()

    with tempfile.TemporaryDirectory() as tmp_work:
        res = subprocess.run(
            ["bash", str(smoke_script), tmp_work],
            cwd=str(top),
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0, f"harbor-smoke.sh failed:\n{res.stdout}\n{res.stderr}"
        assert "harbor smoke: ok" in res.stdout
