"""Build development Mode G inputs with /opt/agent volume."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

TOP = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(TOP / "python"))
sys.path.insert(0, str(TOP / "scripts/integration"))

import agent_h_image
from hermetic_safe_io import atomic_write, validate_path
from hermetic_slice.agent_volume import build_agent_volume_image

WORK_USAGE = (
    "Fresh output under an existing parent owned by the caller.\n"
    "Parent: no symlink components; no group-writable or\n"
    "world-writable mode."
)


def build_mode_g_fixture(work: Path) -> None:
    work = Path(work)
    res = agent_h_image.run(["fixture", str(work)])
    if res != 0:
        raise RuntimeError(f"agent_h_image fixture build failed with code {res}")

    agent_files = {
        "run": b"#!/bin/bash\nset -e\nsed -i 's/return a - b/return a + b/' /testbed/calc.py\n",
    }
    t_clock = datetime.fromisoformat(agent_h_image.FIXTURE_CLOCK.replace("Z", "+00:00"))
    volume_res = build_agent_volume_image(
        tree=work / "agent_tree",
        out_image=work / "agent.img",
        files=agent_files,
        t_clock=t_clock,
        world_id="agent-g-fixture",
        sealcheck_bin=work / "sealcheck",
        work_dir=work,
        size_mib=16,
    )

    world_manifest_path = work / "world.json"
    with open(world_manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    manifest["agent_mode"] = "G"
    manifest["agent_volume_digest"] = volume_res["agent_volume_digest"]

    atomic_write(world_manifest_path, json.dumps(manifest, indent=2).encode("utf-8"))
    print("Agent G image ready: rootfs.img, agent.img, world.json, issue.txt (D4 pass)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    fixture = sub.add_parser(
        "fixture",
        allow_abbrev=False,
        formatter_class=argparse.RawTextHelpFormatter,
        help="Build development Mode G fixture",
    )
    fixture.add_argument("work", help=WORK_USAGE)
    args = parser.parse_args(argv)

    validate_path(args.work)
    try:
        build_mode_g_fixture(Path(args.work))
        return 0
    except Exception as e:
        print(f"Agent G image build refused: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
