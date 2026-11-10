# Behaviour ported from SWE-bench (MIT License), swebench 5.0.2 harness.
"""Log parsers for SWE-bench test runner outputs."""

from __future__ import annotations

from collections.abc import Callable
import re
from typing import Any

TEST_STATUSES = ("FAILED", "PASSED", "SKIPPED", "ERROR", "XFAIL")

_SKIP_SUMMARY_COUNT = re.compile(r"^\[\d+\]$")


def _is_skip_summary(status: str, name: str) -> bool:
    """True for pytest's SKIPPED [N] summary, where [N] is not a test."""
    return status == "SKIPPED" and bool(_SKIP_SUMMARY_COUNT.match(name))


def parse_log_pytest(log: str, test_spec: Any = None) -> dict[str, str]:
    """Parser for test logs generated with PyTest framework."""
    test_status_map: dict[str, str] = {}
    for line in log.split("\n"):
        if any(line.startswith(x) for x in TEST_STATUSES):
            if line.startswith("FAILED"):
                line = line.replace(" - ", " ")
            test_case = line.split()
            if len(test_case) <= 1:
                continue
            if _is_skip_summary(test_case[0], test_case[1]):
                continue
            test_status_map[test_case[1]] = test_case[0]
    return test_status_map


def parse_log_pytest_options(log: str, test_spec: Any = None) -> dict[str, str]:
    """Parser for test logs generated with PyTest framework with options."""
    option_pattern = re.compile(r"(.*?)\[(.*)\]")
    test_status_map: dict[str, str] = {}
    for line in log.split("\n"):
        if any(line.startswith(x) for x in TEST_STATUSES):
            if line.startswith("FAILED"):
                line = line.replace(" - ", " ")
            test_case = line.split()
            if len(test_case) <= 1:
                continue
            if _is_skip_summary(test_case[0], test_case[1]):
                continue
            has_option = option_pattern.search(test_case[1])
            if has_option:
                main, option = has_option.groups()
                if (
                    option.startswith("/")
                    and not option.startswith("//")
                    and "*" not in option
                ):
                    option = "/" + option.split("/")[-1]
                test_name = f"{main}[{option}]"
            else:
                test_name = test_case[1]
            test_status_map[test_name] = test_case[0]
    return test_status_map


def parse_log_pytest_v2(log: str, test_spec: Any = None) -> dict[str, str]:
    """Parser for test logs generated with PyTest framework (Later Version)."""
    test_status_map: dict[str, str] = {}
    escapes = "".join(chr(char) for char in range(1, 32))
    translator = str.maketrans("", "", escapes)
    for line in log.split("\n"):
        line = re.sub(r"\[(\d+)m", "", line)
        line = line.translate(translator)
        if any(line.startswith(x) for x in TEST_STATUSES):
            if line.startswith("FAILED"):
                line = line.split(" - ", 1)[0]
            test_case = line.split()
            if len(test_case) >= 2 and not _is_skip_summary(test_case[0], test_case[1]):
                test_status_map[" ".join(test_case[1:])] = test_case[0]
        elif any(line.endswith(x) for x in TEST_STATUSES):
            test_case = line.split()
            if len(test_case) >= 2:
                test_status_map[" ".join(test_case[:-1])] = test_case[-1]
    return test_status_map


def parse_log_django(log: str, test_spec: Any = None) -> dict[str, str]:
    """Parser for test logs generated with Django tester framework."""
    test_status_map: dict[str, str] = {}
    lines = log.split("\n")

    prev_test: str | None = None
    for line in lines:
        line = line.strip()

        if "--version is equivalent to version" in line:
            test_status_map["--version is equivalent to version"] = "PASSED"

        if " ... " in line:
            prev_test = line.split(" ... ")[0]

        pass_suffixes = (" ... ok", " ... OK", " ...  OK")
        for suffix in pass_suffixes:
            if line.endswith(suffix):
                if line.strip().startswith(
                    "Applying sites.0002_alter_domain_unique...test_no_migrations"
                ):
                    line = line.split("...", 1)[-1].strip()
                test = line.rsplit(suffix, 1)[0]
                test_status_map[test] = "PASSED"
                break

        if " ... skipped" in line:
            test = line.split(" ... skipped")[0]
            test_status_map[test] = "SKIPPED"
        if line.endswith(" ... FAIL"):
            test = line.split(" ... FAIL")[0]
            test_status_map[test] = "FAILED"
        if line.startswith("FAIL:"):
            test = line.split()[1].strip()
            test_status_map[test] = "FAILED"
        if line.endswith(" ... ERROR"):
            test = line.split(" ... ERROR")[0]
            test_status_map[test] = "ERROR"
        if line.startswith("ERROR:"):
            test = line.split()[1].strip()
            test_status_map[test] = "ERROR"

        if line.lstrip().startswith("ok") and prev_test is not None:
            test = prev_test
            test_status_map[test] = "PASSED"

    patterns = [
        r"^(.*?)\s\.\.\.\sTesting\ against\ Django\ installed\ in\ ((?s:.*?))\ silenced\)\.\nok$",
        r"^(.*?)\s\.\.\.\sInternal\ Server\ Error:\ \/(.*)\/\nok$",
        r"^(.*?)\s\.\.\.\sSystem check identified no issues \(0 silenced\)\nok$",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, log, re.MULTILINE):
            test_name = match.group(1)
            test_status_map[test_name] = "PASSED"

    return test_status_map


def parse_log_sympy(log: str, test_spec: Any = None) -> dict[str, str]:
    """Parser for test logs generated with Sympy framework."""
    test_status_map: dict[str, str] = {}
    pattern = r"(_*) (.*)\.py:(.*) (_*)"
    matches = re.findall(pattern, log)
    for match in matches:
        test_case = f"{match[1]}.py:{match[2]}"
        test_status_map[test_case] = "FAILED"
    for line in log.split("\n"):
        line = line.strip()
        if line.startswith("test_"):
            if line.endswith(" E"):
                test = line.split()[0]
                test_status_map[test] = "ERROR"
            if line.endswith(" F"):
                test = line.split()[0]
                test_status_map[test] = "FAILED"
            if line.endswith(" ok"):
                test = line.split()[0]
                test_status_map[test] = "PASSED"
    return test_status_map


def parse_log_matplotlib(log: str, test_spec: Any = None) -> dict[str, str]:
    """Parser for test logs generated with matplotlib PyTest framework."""
    test_status_map: dict[str, str] = {}
    for line in log.split("\n"):
        line = line.replace("MouseButton.LEFT", "1")
        line = line.replace("MouseButton.RIGHT", "3")
        if any(line.startswith(x) for x in TEST_STATUSES):
            if line.startswith("FAILED"):
                line = line.replace(" - ", " ")
            test_case = line.split()
            if len(test_case) <= 1:
                continue
            if _is_skip_summary(test_case[0], test_case[1]):
                continue
            test_status_map[test_case[1]] = test_case[0]
    return test_status_map


parse_log_xarray = parse_log_pytest
parse_log_requests = parse_log_pytest_options
parse_log_pylint = parse_log_pytest_options
parse_log_astropy = parse_log_pytest_v2
parse_log_scikit = parse_log_pytest_v2
parse_log_sphinx = parse_log_pytest_v2

PARSER_REGISTRY: dict[str, Callable[[str], dict[str, str]]] = {
    "parse_log_pytest": parse_log_pytest,
    "parse_log_xarray": parse_log_xarray,
    "parse_log_requests": parse_log_requests,
    "parse_log_pylint": parse_log_pylint,
    "parse_log_astropy": parse_log_astropy,
    "parse_log_scikit": parse_log_scikit,
    "parse_log_sphinx": parse_log_sphinx,
    "parse_log_django": parse_log_django,
    "parse_log_sympy": parse_log_sympy,
    "parse_log_matplotlib": parse_log_matplotlib,
}


def get_log_parser(name: str) -> Callable[[str], dict[str, str]]:
    """Return parser function by registry name, or raise KeyError."""
    if name not in PARSER_REGISTRY:
        raise KeyError(f"Unknown log parser: {name!r}")
    return PARSER_REGISTRY[name]
