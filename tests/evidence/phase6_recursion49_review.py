#!/usr/bin/env python3
"""Read-only independent integrity check for the retained partial Plan49 tracer."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/49-evidence"
PUBLIC = ROOT / "evidence/phase6-recursion49.json"
EXPECTED_STEPS = 3600
MAX_FIELDS = 7200
MAX_CALLS = 100_000_000
MAX_EVENTS = 64
REQUIRED_PREDICATES = ("early_dependency_interaction", "two_echoes_at_boot_cap",
                       "crossed_generated_door", "late_program_stable")


class ReviewError(ValueError):
    pass


def _sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: pathlib.Path):
    if path.is_symlink() or not path.is_file():
        raise ReviewError("missing-or-symlink:" + str(path))
    return json.loads(path.read_text(encoding="utf-8"))


def validate_report_semantics(report: dict, manifest: dict, oracle: dict) -> dict:
    """Validate retained partial-report counters and oracle correspondence."""
    def require(condition: bool, reason: str) -> None:
        if not condition:
            raise ReviewError(reason)

    require(report.get("schema") == "genewhip-route-native-v1", "report:schema")
    require(type(report.get("selected_boundary_calls")) is int and
            report["selected_boundary_calls"] == MAX_CALLS and
            manifest.get("selected_boundary_call_cap") == MAX_CALLS,
            "cap:selected_boundary_calls")
    for key, limit in (("boundary_calls", MAX_CALLS), ("fields", MAX_FIELDS)):
        value = report.get(key)
        require(type(value) is int and 0 <= value <= limit, f"counter:{key}:range")
        require(value == manifest.get("actual_" + key), f"counter:{key}:manifest")
    steps = report.get("active_ticks")
    require(type(steps) is int and steps == EXPECTED_STEPS - 1,
            "counter:active_ticks:expected-3599")
    require(steps == manifest.get("actual_source_steps"), "counter:active_ticks:manifest")
    inputs = report.get("inputs")
    require(type(inputs) is list and len(inputs) <= MAX_EVENTS, "counter:inputs:cap")
    require(len(inputs) == manifest.get("actual_events"), "counter:inputs:manifest")
    high_water = report.get("queue_high_water")
    require(type(high_water) is int and 0 <= high_water <= MAX_EVENTS,
            "counter:queue_high_water:cap")
    require(high_water == manifest.get("queue_high_water"),
            "counter:queue_high_water:manifest")

    expected = oracle.get("predicates")
    observed = report.get("predicates")
    require(type(expected) is list and len(expected) == len(REQUIRED_PREDICATES),
            "oracle:predicate-roster")
    require(tuple(item.get("id") for item in expected) == REQUIRED_PREDICATES,
            "oracle:predicate-identities")
    require(type(observed) is list and len(observed) == len(expected), "predicate:count")
    for index, (definition, result) in enumerate(zip(expected, observed)):
        require(type(result) is dict and result.get("reached") is True,
                f"predicate:reached:{index}")
        require(result.get("value") == definition.get("equals"), f"predicate:value:{index}")
        clock = result.get("clock")
        window = definition.get("field_window")
        require(type(window) is list and len(window) == 2 and type(clock) is int and
                window[0] <= clock <= window[1], f"predicate:clock-window:{index}")

    samples = report.get("samples")
    require(type(samples) is list and len(samples) == EXPECTED_STEPS - 1,
            "terminal:samples-count")
    last = samples[-1]
    require(last.get("active_ticks") == EXPECTED_STEPS - 1, "terminal:active-ticks")
    require(last.get("state") == 2 and last.get("tick") == 719, "terminal:state-tick")
    require(report.get("first_stop_tick") is None, "terminal:first_stop_tick")
    require(report.get("stop_reason") == 5, "terminal:stop_reason")
    return {"source_steps": steps, "fields": report["fields"],
            "boundary_calls": report["boundary_calls"], "events": len(inputs),
            "predicate_count": len(observed), "terminal_tick": last["tick"]}


def review_retained49(root: pathlib.Path) -> dict:
    """Recompute the one-run result and return a truthful partial disposition."""
    attempt = root / "attempts/rec-02-tracer-full-route"
    manifest = _json(attempt / "manifest.json")
    receipt = _json(attempt / "process-receipt.json")
    report_path = attempt / "report.json"
    report = _json(report_path)
    descriptor_path = attempt / "route.gwrc"
    public = _json(PUBLIC)
    oracle = _json(ROOT / "fixtures/phase5-b/oracle.json")
    if (manifest.get("schema") != "genewhip-plan49-attempt-v1" or
            manifest.get("attempt_id") != "rec-02-tracer-full-route" or
            manifest.get("stage") != "tracer" or manifest.get("case_id") != "full-route"):
        raise ReviewError("attempt-identity-mismatch")
    if (receipt.get("process_started") is not True or receipt.get("process_reaped") is not True or
            receipt.get("process_exit_code") != 1 or manifest.get("process_exit_code") != 1):
        raise ReviewError("retained-child-outcome-mismatch")
    if (_sha(report_path) != manifest.get("report_sha256") or
            _sha(descriptor_path) != manifest.get("descriptor_sha256")):
        raise ReviewError("raw-report-or-descriptor-identity-mismatch")
    validated = validate_report_semantics(report, manifest, oracle)
    if (public.get("status") != "partial-incomplete" or
            public.get("observed", {}).get("boundary_calls") != report["boundary_calls"] or
            public.get("observed", {}).get("physical_fields") != report["fields"] or
            public.get("observed", {}).get("completed_source_steps") != report["active_ticks"] or
            public.get("observed", {}).get("dispatched_events") != validated["events"] or
            public.get("assessment", {}).get("step_acceptance_met") is not False or
            public.get("pending", {}).get("six_final_rec_runs") != 6):
        raise ReviewError("public-partial-result-mismatch")
    return {"schema": "genewhip-plan49-independent-review-v1", "verdict": "PARTIAL-INCOMPLETE",
            "accepted_final_cases": 0, "observed_exploratory_runs": 1,
            "checks": {"manifest_report_receipt_identity": "pass", "selected_caps": "pass",
                       "four_predicates_observed": "pass", "terminal_state_at_3599": "pass",
                       "3600_step_acceptance": "fail", "phase_qualification": "not-attempted"},
            "counts": {"calls": report["boundary_calls"], "fields": report["fields"],
                       "source_steps": report["active_ticks"], "events": validated["events"],
                       "queue_high_water": report["queue_high_water"]},
            "predicate_oracle_validation": "pass",
            "cpu_or_bus_correction_indicated": False,
            "historical_plan48_cause": "unknown"}


def semantic_mutations49(root: pathlib.Path) -> dict:
    """Exercise the same production validator used by review_retained49."""
    original = _json(root / "attempts/rec-02-tracer-full-route/report.json")
    manifest = _json(root / "attempts/rec-02-tracer-full-route/manifest.json")
    oracle = _json(ROOT / "fixtures/phase5-b/oracle.json")
    mutations = []
    cases = (
        ("source_steps_rounded_up", lambda x: x.__setitem__("active_ticks", 3600), "counter:active_ticks:expected-3599"),
        ("calls_over_cap", lambda x: x.__setitem__("boundary_calls", MAX_CALLS + 1), "counter:boundary_calls:range"),
        ("field_over_cap", lambda x: x.__setitem__("fields", MAX_FIELDS + 1), "counter:fields:range"),
        ("events_over_cap", lambda x: x["inputs"].extend(
            copy.deepcopy(x["inputs"][-1]) for _ in range(MAX_EVENTS + 1 - len(x["inputs"]))), "counter:inputs:cap"),
        ("false_first_stop_tick", lambda x: x.__setitem__("first_stop_tick", 7200), "terminal:first_stop_tick"),
        ("false_cpu_fault", lambda x: x.__setitem__("stop_reason", 3), "terminal:stop_reason"),
        ("predicate_value_disagrees_with_oracle", lambda x: x["predicates"][0].__setitem__("value", 0), "predicate:value:0"),
        ("predicate_outside_oracle_window", lambda x: x["predicates"][0].__setitem__("clock", 601), "predicate:clock-window:0"),
        ("manifest_counter_mismatch", lambda x: x.__setitem__("fields", x["fields"] - 1), "counter:fields:manifest"),
    )
    for name, mutate, expected_reason in cases:
        changed = copy.deepcopy(original)
        mutate(changed)
        try:
            validate_report_semantics(changed, manifest, oracle)
        except ReviewError as error:
            actual_reason = str(error)
        else:
            raise ReviewError("semantic-mutation-survived:" + name)
        if actual_reason != expected_reason:
            raise ReviewError(f"semantic-mutation-wrong-reason:{name}:{actual_reason}")
        mutations.append({"name": name, "expected_rejection": expected_reason,
                          "actual_rejection": actual_reason,
                          "status": "rejected-by-shared-validator"})
    return {"schema": "genewhip-plan49-semantic-mutations-v2", "status": "pass",
            "validator": "validate_report_semantics used by review_retained49",
            "os_children_started": 0, "project_modules_imported": False, "mutations": mutations}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = semantic_mutations49(args.root) if args.mutations else review_retained49(args.root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ReviewError, OSError, ValueError, KeyError, TypeError) as error:
        print("REJECT: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
