"""Hand-written complete inputs for disposition verification."""


def complete_manifest(task_id):
    def digest(number):
        return "sha256:" + f"{number:064x}"
    return {
        "spec_version": "hermetic-world/v1", "task_id": task_id,
        "task_class": "dated", "seal_level": "strict",
        "cutoffs": {"t_world": "2024-01-01T00:00:00Z", "t_clock": "2024-01-01T00:00:00Z",
                    "base_commit": "a" * 40, "pkg_cutoff": "2024-01-01T00:00:00Z"},
        "repo_tree_digest": digest(1), "rootfs_digest": digest(2),
        "packages": {"closure_root": digest(3), "baseline_month": "2024-01", "baseline_root": digest(4)},
        "substrate_at_t": "full", "world_ca_cert_sha256": digest(5),
        "run_spec": {"env": {}, "workdir": "/testbed", "user": "root", "entrypoint": ["/bin/sh"],
                     "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024, "wall_time_s": 60}},
        "sealcheck_report_digest": digest(6), "dispositions": [],
    }


def complete_task(task_id):
    return {"instance_id": task_id, "repo": "example/project", "base_commit": "a" * 40,
            "cutoffs": {"t_world": "2024-01-01T00:00:00Z", "t_clock": "2024-01-01T00:00:00Z"}}


def report(task_id="task_one", findings=None, **extra):
    findings = findings if findings is not None else []
    return {"task_id": task_id, "findings": findings, "gate": bool(findings), "not_covered": [], **extra}


def d0(evidence="LEAK_VALUE"):
    return {"detector": "D0", "severity": "gate", "visibility": "agent_visible", "evidence": [evidence],
            "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0}
