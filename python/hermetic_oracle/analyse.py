
import json

import os

import stat

from typing import Any, Dict, List, Set, Tuple



MAX_RUN_FILE_BYTES = 16 * 1024 * 1024

MAX_LIST_FILE_BYTES = 4 * 1024 * 1024

MAX_TESTS_PER_RUN = 200000

MAX_DECLARED_TESTS = 200000

MAX_NODE_ID_LEN = 4096

MAX_JSON_DEPTH = 12

READ_CHUNK_BYTES = 65536

EXPECTED_RUN_COUNT = 6

RUNS_PER_TREE = 3

DEFAULT_MAX_BAD_F2P_PERMILLE = 200



VALID_TREES = ("base", "gold")

VALID_OUTCOMES = ("passed", "failed", "skipped", "error", "missing")





class OracleError(Exception):

    """Typed error for E4 oracle analysis failures."""





def safe_read_bytes(path: str, max_bytes: int) -> bytes:

    if not isinstance(path, str) or not path or "\x00" in path:

        raise OracleError("invalid file path")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)

    try:

        fd = os.open(path, flags)

    except OSError as exc:

        raise OracleError("failed to open input file safely") from exc

    try:

        st = os.fstat(fd)

        if not stat.S_ISREG(st.st_mode):

            raise OracleError("input path is not a regular file")

        if st.st_size > max_bytes:

            raise OracleError("input file exceeds size cap")

        chunks: List[bytes] = []

        total = 0

        max_loops = (max_bytes // READ_CHUNK_BYTES) + 2

        for _ in range(max_loops):

            chunk = os.read(fd, READ_CHUNK_BYTES)

            if not chunk:

                break

            total += len(chunk)

            if total > max_bytes:

                raise OracleError("input file exceeded cap during read")

            chunks.append(chunk)

        else:

            raise OracleError("read loop cap exceeded")

        return b"".join(chunks)

    except OSError as exc:

        raise OracleError("error reading file") from exc

    finally:

        try:

            os.close(fd)

        except OSError:

            pass





def _no_dup_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:

    out: Dict[str, Any] = {}

    for k, v in pairs:

        if not isinstance(k, str) or len(k) > MAX_NODE_ID_LEN or "\x00" in k:

            raise OracleError("invalid JSON key")

        if k in out:

            raise OracleError(f"duplicate JSON key: {k}")

        out[k] = v

    return out





def _check_depth(obj: Any, max_depth: int) -> None:

    stack: List[Tuple[Any, int]] = [(obj, 0)]

    while stack:

        curr, depth = stack.pop()

        if depth > max_depth:

            raise OracleError("JSON nesting depth exceeded")

        if isinstance(curr, str):

            if len(curr) > MAX_NODE_ID_LEN or "\x00" in curr:

                raise OracleError("string exceeds length cap or contains NUL")

        elif isinstance(curr, dict):

            for v in curr.values():

                stack.append((v, depth + 1))

        elif isinstance(curr, list):

            for item in curr:

                stack.append((item, depth + 1))





def load_json_bounded(raw: bytes, max_bytes: int) -> Any:

    if len(raw) > max_bytes:

        raise OracleError("payload exceeds size cap")

    try:

        text = raw.decode("utf-8")

    except UnicodeDecodeError as exc:

        raise OracleError("invalid UTF-8") from exc

    try:

        data = json.loads(text, object_pairs_hook=_no_dup_hook)

    except OracleError:

        raise

    except (json.JSONDecodeError, RecursionError, ValueError) as exc:

        raise OracleError("malformed JSON") from exc

    _check_depth(data, MAX_JSON_DEPTH)

    return data





def _normalize_outcome_for_flakiness(outcome: str) -> str:

    if outcome in ("error", "missing"):

        return "failed"

    return outcome





def _parse_declared_list(data: Any, label: str) -> List[str]:

    if not isinstance(data, list):

        raise OracleError(f"{label} must be a JSON array")

    if len(data) > MAX_DECLARED_TESTS:

        raise OracleError(f"{label} count exceeds cap")

    seen: Set[str] = set()

    out: List[str] = []

    for idx in range(len(data)):

        item = data[idx]

        if not isinstance(item, str) or not item or len(item) > MAX_NODE_ID_LEN or "\x00" in item:

            raise OracleError(f"invalid test node id in {label}")

        if item in seen:

            raise OracleError(f"duplicate test node id in {label}")

        seen.add(item)

        out.append(item)

    return out





def _parse_runs(run_objs: List[Any]) -> Dict[str, Dict[int, Dict[str, str]]]:

    if not isinstance(run_objs, list) or len(run_objs) != EXPECTED_RUN_COUNT:

        raise OracleError("must supply exactly 6 run objects")

    by_tree: Dict[str, Dict[int, Dict[str, str]]] = {"base": {}, "gold": {}}

    allowed_keys = {"tree", "run", "results"}

    for idx in range(EXPECTED_RUN_COUNT):

        obj = run_objs[idx]

        if not isinstance(obj, dict) or set(obj.keys()) != allowed_keys:

            raise OracleError("run object has missing or unknown fields")

        tree = obj["tree"]

        run_no = obj["run"]

        results = obj["results"]

        if tree not in VALID_TREES:

            raise OracleError("invalid tree name")

        if isinstance(run_no, bool) or not isinstance(run_no, int) or run_no not in (1, 2, 3):

            raise OracleError("run number must be integer 1, 2, or 3")

        if run_no in by_tree[tree]:

            raise OracleError(f"duplicate run {run_no} for tree {tree}")

        if not isinstance(results, dict) or len(results) > MAX_TESTS_PER_RUN:

            raise OracleError("invalid or oversized results map")

        validated_res: Dict[str, str] = {}

        for tid, outcome in results.items():

            if not isinstance(tid, str) or not tid or len(tid) > MAX_NODE_ID_LEN:

                raise OracleError("invalid test id in results")

            if outcome not in VALID_OUTCOMES:

                raise OracleError(f"invalid test outcome: {outcome}")

            validated_res[tid] = outcome

        by_tree[tree][run_no] = validated_res



    for tree in VALID_TREES:

        if set(by_tree[tree].keys()) != {1, 2, 3}:

            raise OracleError(f"tree {tree} missing required runs 1..3")

    return by_tree





def analyse_oracle_runs(

    run_objs: List[Any],

    f2p_data: Any,

    p2p_data: Any,

    max_bad_f2p_permille: int = DEFAULT_MAX_BAD_F2P_PERMILLE,

) -> Dict[str, Any]:

    if isinstance(max_bad_f2p_permille, bool) or not isinstance(max_bad_f2p_permille, int):

        raise OracleError("max_bad_f2p_permille must be an integer")

    if max_bad_f2p_permille < 0 or max_bad_f2p_permille > 1000:

        raise OracleError("max_bad_f2p_permille must be in 0..1000")



    by_tree = _parse_runs(run_objs)

    f2p_list = _parse_declared_list(f2p_data, "FAIL_TO_PASS")

    p2p_list = _parse_declared_list(p2p_data, "PASS_TO_PASS")



    if not f2p_list:

        raise OracleError("FAIL_TO_PASS must not be empty")

    if set(f2p_list) & set(p2p_list):

        raise OracleError("FAIL_TO_PASS and PASS_TO_PASS must be disjoint")



    all_test_ids: Set[str] = set(f2p_list) | set(p2p_list)

    for tree in VALID_TREES:

        for r in (1, 2, 3):

            all_test_ids.update(by_tree[tree][r].keys())



    if len(all_test_ids) > MAX_TESTS_PER_RUN * 2:

        raise OracleError("total distinct test ids exceeds cap")



    flaky_base: Set[str] = set()

    flaky_gold: Set[str] = set()



    for tid in sorted(all_test_ids):

        base_raw = [by_tree["base"][r].get(tid, "missing") for r in (1, 2, 3)]

        base_norm = [_normalize_outcome_for_flakiness(x) for x in base_raw]

        if len(set(base_norm)) > 1:

            flaky_base.add(tid)



        gold_raw = [by_tree["gold"][r].get(tid, "missing") for r in (1, 2, 3)]

        gold_norm = [_normalize_outcome_for_flakiness(x) for x in gold_raw]

        if len(set(gold_norm)) > 1:

            flaky_gold.add(tid)



    flaky_all: Set[str] = flaky_base | flaky_gold



    violations: List[Dict[str, str]] = []

    missing_declared: Set[str] = set()



    for tid in sorted(f2p_list):

        if tid in flaky_all:

            continue

        base_raw_all = [by_tree["base"][r].get(tid, "missing") for r in (1, 2, 3)]

        gold_raw_all = [by_tree["gold"][r].get(tid, "missing") for r in (1, 2, 3)]

        if all(x == "missing" for x in base_raw_all) or all(x == "missing" for x in gold_raw_all):

            missing_declared.add(tid)

            violations.append({"test": tid, "kind": "declared_test_missing"})

            continue



        base_eff = _normalize_outcome_for_flakiness(base_raw_all[0])

        gold_eff = _normalize_outcome_for_flakiness(gold_raw_all[0])



        if base_eff != "failed":

            violations.append({"test": tid, "kind": "f2p_passes_on_base"})

        if gold_eff != "passed":

            violations.append({"test": tid, "kind": "f2p_fails_on_gold"})



    for tid in sorted(p2p_list):

        if tid in flaky_all:

            continue

        base_raw_all = [by_tree["base"][r].get(tid, "missing") for r in (1, 2, 3)]

        gold_raw_all = [by_tree["gold"][r].get(tid, "missing") for r in (1, 2, 3)]

        if all(x == "missing" for x in base_raw_all) or all(x == "missing" for x in gold_raw_all):

            missing_declared.add(tid)

            violations.append({"test": tid, "kind": "declared_test_missing"})

            continue



        base_eff = _normalize_outcome_for_flakiness(base_raw_all[0])

        gold_eff = _normalize_outcome_for_flakiness(gold_raw_all[0])



        if base_eff != "passed":

            violations.append({"test": tid, "kind": "p2p_fails_on_base"})

        if gold_eff != "passed":

            violations.append({"test": tid, "kind": "p2p_fails_on_gold"})



    violations.sort(key=lambda v: (v["test"], v["kind"]))



    bad_f2p_set = {t for t in f2p_list if (t in flaky_all) or (t in missing_declared)}

    bad_f2p_count = len(bad_f2p_set)

    total_f2p = len(f2p_list)



    # Rule 3: Integer per-mille arithmetic, no floats:

    # bad_f2p / total_f2p > max_bad_f2p_permille / 1000

    # iff bad_f2p * 1000 > max_bad_f2p_permille * total_f2p

    is_unusable = (bad_f2p_count * 1000) > (max_bad_f2p_permille * total_f2p)



    if is_unusable:

        result = "unusable"

        deciding_rule = "rule_3_f2p_flaky_or_missing_exceeds_threshold"

    elif violations:

        result = "invalid"

        deciding_rule = "rule_2_oracle_validity_violation"

    else:

        result = "valid"

        deciding_rule = "rule_2_all_non_flaky_declared_tests_valid"



    return {

        "result": result,

        "deciding_rule": deciding_rule,

        "flaky": sorted(flaky_all),

        "flaky_base": sorted(flaky_base),

        "flaky_gold": sorted(flaky_gold),

        "missing_declared": sorted(missing_declared),

        "violations": violations,

        "counts": {

            "f2p_total": total_f2p,

            "p2p_total": len(p2p_list),

            "flaky_total": len(flaky_all),

            "f2p_flaky_or_missing": bad_f2p_count,

            "violations_total": len(violations),

            "threshold_permille": max_bad_f2p_permille,

        },

    }





def run_oracle_from_paths(

    run_paths: List[str],

    f2p_path: str,

    p2p_path: str,

    max_bad_f2p_permille: int = DEFAULT_MAX_BAD_F2P_PERMILLE,

) -> Dict[str, Any]:

    if len(run_paths) != EXPECTED_RUN_COUNT:

        raise OracleError("must supply exactly 6 run file paths")

    run_objs: List[Any] = []

    for idx in range(EXPECTED_RUN_COUNT):

        raw = safe_read_bytes(run_paths[idx], MAX_RUN_FILE_BYTES)

        run_objs.append(load_json_bounded(raw, MAX_RUN_FILE_BYTES))

    f2p_raw = safe_read_bytes(f2p_path, MAX_LIST_FILE_BYTES)

    p2p_raw = safe_read_bytes(p2p_path, MAX_LIST_FILE_BYTES)

    f2p_json = load_json_bounded(f2p_raw, MAX_LIST_FILE_BYTES)

    p2p_json = load_json_bounded(p2p_raw, MAX_LIST_FILE_BYTES)

    return analyse_oracle_runs(run_objs, f2p_json, p2p_json, max_bad_f2p_permille)

