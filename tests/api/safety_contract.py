#!/usr/bin/env python3
"""Finite API-safety protocol and fail-closed summary checker.

The same validate_summary function checks live harness output and named mutants,
so negative controls exercise the production acceptance predicate.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path


# This is the bounded product roster selected by phase6_game's safety mode.
# Keep it explicit: discovery is evidence only after these exact registered
# tests have been compared with the live CTest JSON.
REQUIRED_VARIANT_TESTS = (
    "load_contract",
    "time_contract",
    "reset_contract",
    "bus_boundary_contract",
    "gameplay_bus_contract",
    "movem_contract",
    "phase6_repairs_contract",
    "session_contract",
    "input_log_contract",
    "phase6_chunk_contract",
    "phase6_safety",
    "phase6_delivery_map_contract",
)


def _exact_int(value):
    return type(value) is int


def validate_phase6_safety_report(report):
    """Validate actual three-variant Plan53 safety evidence, fail closed.

    Expected shape is deliberately small and contains observed outcomes rather
    than a producer-supplied `passed` flag. This function is safe to call from
    the phase harness and from semantic mutation controls.
    """
    variants = report.get("variants") if isinstance(report, dict) else None
    if not isinstance(variants, list) or len(variants) != 3:
        return "variant-denominator"
    expected = ("native", "sanitize", "hooks-off")
    seen = set()
    for row in variants:
        if not isinstance(row, dict):
            return "variant-row"
        variant = row.get("variant")
        if variant not in expected or variant in seen:
            return "variant-identity"
        seen.add(variant)
        tests = row.get("selected_tests")
        if not isinstance(tests, list) or any(not isinstance(name, str) for name in tests):
            return "test-roster-type"
        if len(tests) != len(REQUIRED_VARIANT_TESTS) or set(tests) != set(REQUIRED_VARIANT_TESTS):
            return "test-roster"
        for field, wanted in (("denominator", 12), ("pass", 12), ("fail", 0),
                              ("unknown", 0), ("skipped", 0)):
            value = row.get(field)
            if not _exact_int(value) or value != wanted:
                return f"{variant}-{field}"
        for field in ("steps", "step_limit", "tick_budget", "max_tick", "returned_frames",
                      "output_cap", "guards_checked", "allocation_count_peak",
                      "steady_allocations", "owned_bytes_peak", "owned_bytes_limit"):
            if not _exact_int(row.get(field)) or row[field] < 0:
                return f"{variant}-{field}-type"
        if row["step_limit"] == 0 or row["steps"] > row["step_limit"]:
            return f"{variant}-step-bound"
        if row["max_tick"] > row["tick_budget"]:
            return f"{variant}-tick-bound"
        if row["returned_frames"] > row["output_cap"]:
            return f"{variant}-output-bound"
        if row["owned_bytes_limit"] == 0 or row["owned_bytes_peak"] > row["owned_bytes_limit"]:
            return f"{variant}-memory-bound"
        if row["guards_checked"] < 1:
            return f"{variant}-guards"
        instrumented = row.get("allocation_instrumented")
        if type(instrumented) is not bool:
            return f"{variant}-allocation-identity"
        if variant == "hooks-off":
            if instrumented is not False:
                return "hooks-off-allocation-identity"
        elif instrumented is not True:
            return f"{variant}-allocation-identity"
        if instrumented and (row["allocation_count_peak"] > 2 or row["steady_allocations"] != 0):
            return f"{variant}-allocation-bound"
        fuzz = row.get("bounded_fuzz")
        if not isinstance(fuzz, dict):
            return f"{variant}-fuzz-summary"
        for field, wanted in (("denominator", 4096), ("pass", 4096), ("fail", 0),
                              ("unknown", 0), ("skipped", 0), ("tick_budget", 128)):
            if not _exact_int(fuzz.get(field)) or fuzz[field] != wanted:
                return f"{variant}-fuzz-{field}"
        accepted, rejected = fuzz.get("accepted_loads"), fuzz.get("rejected_loads")
        if (not _exact_int(accepted) or not _exact_int(rejected) or accepted <= 0 or rejected <= 0 or
                accepted + rejected != 4096):
            return f"{variant}-fuzz-load-counts"
    if seen != set(expected):
        return "variant-denominator"
    return None


def validate_summary(report, *, mode, cases, step_budget, tick_budget, output_cap,
                     require_allocations):
    if report.get("mode") != "safety":
        return "summary-mode"
    if report.get("denominator") != cases:
        return "case-denominator"
    if report.get("pass") != cases or report.get("fail") != 0 or report.get("unknown") != 0 or report.get("skipped") != 0:
        return "outcome-denominator"
    if report.get("continuation_match") is not True:
        return "continuation"
    if report.get("guards_checked", 0) < cases:
        return "guard-count"
    if report.get("returned_frames", cases * output_cap + 1) > cases * output_cap:
        return "output-cap"
    if report.get("step_budget") != step_budget or report.get("steps", cases * step_budget + 1) > cases * step_budget:
        return "step-budget"
    if report.get("tick_budget") != tick_budget or report.get("max_tick", tick_budget + 1) > tick_budget:
        return "tick-budget"
    if require_allocations:
        if report.get("allocation_instrumented") is not True:
            return "allocation-instrumentation"
        if report.get("allocation_count_peak", 3) > 2:
            return "allocation-count-cap"
        if report.get("steady_allocations", 1) != 0:
            return "steady-allocation"
    elif report.get("allocation_instrumented") is not False:
        return "hooks-off-identity"
    return None


def run_negative_controls():
    base = {
        "mode": "safety", "denominator": 16, "pass": 16, "fail": 0,
        "unknown": 0, "skipped": 0, "continuation_match": True,
        "guards_checked": 16, "returned_frames": 64, "step_budget": 8,
        "steps": 128, "tick_budget": 180000, "max_tick": 179000,
        "allocation_instrumented": True, "allocation_count_peak": 2,
        "steady_allocations": 0,
    }
    mutants = [
        ("continuation", {"continuation_match": False}, "continuation"),
        ("guard", {"guards_checked": 15}, "guard-count"),
        ("output-count", {"returned_frames": 2049}, "output-cap"),
        ("step-budget", {"steps": 129}, "step-budget"),
        ("tick-budget", {"max_tick": 180001}, "tick-budget"),
        ("allocation", {"steady_allocations": 1}, "steady-allocation"),
    ]
    for name, mutation, expected in mutants:
        corrupted = dict(base)
        corrupted.update(mutation)
        observed = validate_summary(corrupted, mode="pr", cases=16,
            step_budget=8, tick_budget=180000, output_cap=128,
            require_allocations=True)
        if observed != expected:
            raise RuntimeError(f"negative control {name}: expected {expected}, got {observed}")
    phase6_base = {"variants": []}
    for variant in ("native", "sanitize", "hooks-off"):
        phase6_base["variants"].append({
            "variant": variant,
            "selected_tests": list(REQUIRED_VARIANT_TESTS),
            "denominator": 12, "pass": 12, "fail": 0, "unknown": 0, "skipped": 0,
            "steps": 4096, "step_limit": 4096, "tick_budget": 128, "max_tick": 128,
            "returned_frames": 4096, "output_cap": 8192, "guards_checked": 12,
            "allocation_instrumented": variant != "hooks-off",
            "allocation_count_peak": 2, "steady_allocations": 0,
            "owned_bytes_peak": 1048576, "owned_bytes_limit": 2097152,
            "bounded_fuzz": {"denominator": 4096, "pass": 4096, "fail": 0,
                "unknown": 0, "skipped": 0, "tick_budget": 128,
                "accepted_loads": 2048, "rejected_loads": 2048},
        })
    if validate_phase6_safety_report(phase6_base) is not None:
        raise RuntimeError("phase6 safety validator rejected its complete control fixture")
    phase6_mutants = [
        ("missing-test", lambda r: r["variants"][0]["selected_tests"].pop(), "test-roster"),
        ("bool-count", lambda r: r["variants"][0].update({"pass": True}), "native-pass"),
        ("memory-cap", lambda r: r["variants"][0].update(owned_bytes_peak=2097153), "native-memory-bound"),
        ("work-cap", lambda r: r["variants"][0].update(steps=4097), "native-step-bound"),
        ("fuzz-denominator", lambda r: r["variants"][0]["bounded_fuzz"].update(denominator=4095), "native-fuzz-denominator"),
        ("hooks-identity", lambda r: r["variants"][2].update(allocation_instrumented=True), "hooks-off-allocation-identity"),
    ]
    for name, mutate, expected in phase6_mutants:
        import copy
        corrupted = copy.deepcopy(phase6_base)
        mutate(corrupted)
        observed = validate_phase6_safety_report(corrupted)
        if observed != expected:
            raise RuntimeError(f"phase6 negative control {name}: expected {expected}, got {observed}")
    return len(mutants) + len(phase6_mutants)


def run(command, timeout):
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"process-timeout: {command[0]} exceeded {timeout}s") from exc
    if result.returncode != 0:
        raise RuntimeError(f"process-exit: {command[0]} returned {result.returncode}: {result.stderr.strip()}")
    return result.stdout


def last_json(stdout, label):
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise RuntimeError(f"summary-json: {label} emitted no JSON summary")


def run_binary_summary(binary, args, timeout, label):
    stdout = run([str(binary), *args], timeout)
    return last_json(stdout, label)


def check_generic_summary(report, label, expected_cases):
    if report.get("denominator") != expected_cases:
        raise RuntimeError(f"{label}-denominator: expected {expected_cases}, got {report.get('denominator')}")
    if report.get("pass") != expected_cases or report.get("fail") != 0:
        raise RuntimeError(f"{label}-outcome: pass/fail {report.get('pass')}/{report.get('fail')}")
    if report.get("unknown", 0) != 0 or report.get("skipped", 0) != 0:
        raise RuntimeError(f"{label}-nonpass: unknown/skipped {report.get('unknown')}/{report.get('skipped')}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--mode", choices=("pr", "scheduled", "production", "negative-controls"), required=True)
    parser.add_argument("--out", type=Path, help="write the exact validated JSON summary to this path")
    args = parser.parse_args()
    mutants = run_negative_controls()
    if args.mode == "negative-controls":
        print(json.dumps({"mode": args.mode, "negative_controls": mutants, "pass": mutants, "fail": 0}))
        return 0

    build = args.build.resolve()
    fuzz = build / "gw_bounded_fuzz"
    load = build / "load_contract"
    time_contract = build / "time_contract"
    for path in (fuzz, load, time_contract):
        if not path.is_file():
            raise RuntimeError(f"missing-test: required executable not found: {path.name}")
    if args.mode == "scheduled":
        cases, steps, ticks, output_cap, timeout = 512, 32, 720000, 256, 240
        require_allocations = True
    elif args.mode == "production":
        cases, steps, ticks, output_cap, timeout = 16, 8, 180000, 128, 90
        require_allocations = False
    else:
        cases, steps, ticks, output_cap, timeout = 16, 8, 180000, 128, 90
        require_allocations = True

    # These established contracts cover malformed ROM/vector spans, descriptor
    # size/version/reserved fields, event capacity/order, audio endpoint neighbors,
    # output-cap arithmetic, and caller-owned buffer preservation.
    for binary, label in ((load, "load-contract"), (time_contract, "time-contract")):
        stdout = run([str(binary)], timeout)
        if f"{label.replace('-', '_')}: PASS" not in stdout:
            raise RuntimeError(f"{label}-identity: expected named PASS marker")

    seed = 0x47573105
    report = run_binary_summary(fuzz, ["safety", "--seed", str(seed), "--cases", str(cases),
        "--step-budget", str(steps), "--tick-budget", str(ticks), "--output-cap", str(output_cap)],
        timeout, "bounded-safety")
    reason = validate_summary(report, mode=args.mode, cases=cases, step_budget=steps,
        tick_budget=ticks, output_cap=output_cap, require_allocations=require_allocations)
    if reason:
        raise RuntimeError(f"{reason}: bounded safety summary rejected")

    audio = run_binary_summary(fuzz, ["audio-calls"], timeout, "audio-calls")
    check_generic_summary(audio, "audio-calls", 256)
    result = {"mode": args.mode, "seed": f"{seed:08x}", "cases": cases,
        "steps_per_case": steps, "tick_budget": ticks, "output_cap_frames": output_cap,
        "steps": report["steps"], "max_tick": report["max_tick"],
        "returned_frames": report["returned_frames"], "guards_checked": report["guards_checked"],
        "safety_pass": report["pass"], "audio_pass": audio["pass"],
        "negative_controls": mutants, "allocation_instrumented": report["allocation_instrumented"],
        "allocation_count_peak": report["allocation_count_peak"],
        "steady_allocations": report["steady_allocations"]}
    encoded = json.dumps(result, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(encoded + "\n")
    print(encoded)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError) as error:
        print(f"safety_contract: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
