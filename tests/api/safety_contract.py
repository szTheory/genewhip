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
    return len(mutants)


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
        "safety_pass": report["pass"], "audio_pass": audio["pass"],
        "negative_controls": mutants, "allocation_instrumented": report["allocation_instrumented"],
        "allocation_count_peak": report["allocation_count_peak"],
        "steady_allocations": report["steady_allocations"]}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError) as error:
        print(f"safety_contract: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
