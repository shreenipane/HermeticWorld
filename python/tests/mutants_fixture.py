"""Shared hand-written fixture for the finder, validation and differential tests.

The fixture test module is written here and is pure, so executing it with
``exec`` in a fresh namespace is safe. It is a hidden test file for the grader
smoke task (``scripts/integration/fixtures/grader-task``): ``import calc`` is
served from ``work(tree)``, where ``base`` has the buggy ``add`` and ``gold``
the fixed one.
"""

from __future__ import annotations

import builtins
import types

TEST_FILE = "tests/test_calc.py"

SOURCE = (
    "from calc import add, double\n"  # 1
    "\n"                              # 2
    "def test_add():\n"               # 3
    "    result = add(2, 2)\n"        # 4
    "    assert result == 4\n"        # 5
    "\n"                              # 6
    "def test_double():\n"            # 7
    "    value = double(3)\n"         # 8
    "    assert value == 6\n"         # 9
    "\n"                              # 10
    "def test_add_neg():\n"           # 11
    "    got = add(5, -2)\n"          # 12
    "    assert got == 3\n"           # 13
)

TEST_NAMES = ("test_add", "test_add_neg", "test_double")


def work(tree: str) -> dict:
    """The fixture task's calc.py (scripts/integration/fixtures/grader-task)."""
    if tree == "base":
        return {"add": lambda a, b: a - b, "double": lambda x: x * 2}
    return {"add": lambda a, b: a + b, "double": lambda x: x * 2}


def nodeid(name: str) -> str:
    return f"{TEST_FILE}::{name}"


def exec_tests(text: str, env: dict) -> dict[str, str]:
    """Run each test function of ``text`` against ``env`` and report outcomes."""
    calc = types.ModuleType("calc")
    calc.__dict__.update(env)

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "calc" and level == 0:
            return calc
        raise ImportError(name)

    namespace: dict = {"__builtins__": dict(vars(builtins), __import__=fake_import)}
    exec(compile(text, "<fixture>", "exec"), namespace)  # noqa: S102 - own fixture
    out: dict[str, str] = {}
    for name in sorted(k for k in namespace if k.startswith("test_")):
        try:
            namespace[name]()
        except AssertionError:
            out[nodeid(name)] = "failed"
        except Exception:
            out[nodeid(name)] = "error"
        else:
            out[nodeid(name)] = "passed"
    return out


def exec_runner(tree: str, text: str) -> dict[str, str]:
    return exec_tests(text, work(tree))


def recorder_log(entries: dict, internal_errors: list | None = None) -> bytes:
    import json

    return json.dumps(
        {"tests": entries, "internal_errors": internal_errors or []}, sort_keys=True
    ).encode("utf-8")


def base_log() -> bytes:
    """What hermetic_assert_recorder writes for SOURCE on the base tree."""
    return recorder_log(
        {
            nodeid("test_add"): {
                "file": TEST_FILE, "outcome": "failed", "raising_line": 5,
                "reached": [{"line": 5, "index": 0, "site_id": "test_add#0", "passed": False}],
            },
            nodeid("test_double"): {
                "file": TEST_FILE, "outcome": "passed", "raising_line": None,
                "reached": [{"line": 9, "index": 0, "site_id": "test_double#0", "passed": True}],
            },
            nodeid("test_add_neg"): {
                "file": TEST_FILE, "outcome": "failed", "raising_line": 13,
                "reached": [{"line": 13, "index": 0, "site_id": "test_add_neg#0",
                             "passed": False}],
            },
        }
    )
