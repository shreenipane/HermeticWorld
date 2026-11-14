"""Dev-unjailed GraderVM integration for the differential runs (opt-in, needs KVM).

Skipped unless ``HERMETIC_DIFFERENTIAL_VM_RUNNER`` names an executable that
implements the ``CommandRunner`` contract: ``RUNNER RUN_ID TEST_FILE OUT_DISK``
boots a fresh dev-unjailed GraderVM on the submitted work for the fixture task,
uses TEST_FILE as the hidden test file and writes the 1 MiB result disk to
OUT_DISK. ``HERMETIC_DIFFERENTIAL_VM_EXPECT`` is the expected verdict status
(``resolved`` for the gold patch, ``unresolved`` for the empty patch).

The hidden test text and plan are the hand-written fixture; validation uses the
in-process fixture runner, the three grading runs use the VM runner in parallel.
"""

from __future__ import annotations

import os

import pytest

from hermetic_mutants.differential import CommandRunner, build_plan, build_requests, run_differential
from hermetic_mutants.finder import find_base_failing_sites
from hermetic_mutants.validate import validate_and_select
from tests.mutants_fixture import SOURCE, TEST_FILE, base_log, exec_runner, nodeid

RUNNER = os.environ.get("HERMETIC_DIFFERENTIAL_VM_RUNNER", "")


@pytest.mark.skipif(not RUNNER, reason="needs HERMETIC_DIFFERENTIAL_VM_RUNNER and /dev/kvm")
def test_differential_runs_in_grader_vms() -> None:
    found = find_base_failing_sites(SOURCE.encode(), base_log(), TEST_FILE, range(1, 14))
    sel = validate_and_select(SOURCE.encode(), TEST_FILE, "5eed", found.eligible_sites, exec_runner)
    assert sel.r1_text is not None and sel.r2_text is not None
    reqs = build_requests(SOURCE, sel.r1_text, sel.r2_text, with_r3=False)
    plan = build_plan([nodeid("test_add"), nodeid("test_add_neg")], [nodeid("test_double")],
                      sel.mutated_tests, sel.compared_tests)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/")}
    runner = CommandRunner((RUNNER,), timeout_s=900, env=env)
    verdict = run_differential(reqs, plan, runner, timeout_s=1200)
    assert verdict.status == os.environ.get("HERMETIC_DIFFERENTIAL_VM_EXPECT", "resolved"), (
        verdict.to_json()
    )
