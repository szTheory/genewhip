#!/usr/bin/env python3
"""Collect the frozen Phase 5 denominator through the admitted public client."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / "build/phase5/tools/session/gw_headless"
ROSTER = ROOT / "evidence/phase5-baseline-roster.json"
REPORT = ROOT / "evidence/phase5-baseline.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def admitted(fixture_id: str) -> Path:
    manifest_arg = "fixtures/manifest.json"
    result = load_baseline().process_tools().run([sys.executable, "-I", str(ROOT / "scripts/fixtures/run_admitted.py"),
                                 "--root", str(ROOT), "--manifest", manifest_arg,
                                 "--fixture-id", fixture_id], cwd=ROOT,
                                timeout=30)
    if result.returncode:
        raise ValueError("production admission refused fixture")
    path = Path(result.stdout.strip()).resolve()
    if ROOT not in path.parents:
        raise ValueError("admission consumer resolved a ROM outside repository")
    return path


def collect() -> dict:
    collection_started = time.monotonic()
    module = load_baseline()
    process = module.process_tools()
    roster = json.loads(ROSTER.read_text())
    module.validate_roster(roster)
    if module.file_identity(CLIENT) != roster["client"]:
        raise ValueError("selected client differs from frozen client before execution")
    proofs = []
    for fixture_id in dict.fromkeys(c["fixture_id"] for c in roster["cases"]):
        rom = admitted(fixture_id)
        cases = [c for c in roster["cases"] if c["fixture_id"] == fixture_id]
        if module.file_identity(rom) != cases[0]["rom"]:
            raise ValueError("admission resolved different frozen ROM")
        if cases[0]["kind"] == "control":
            for rep in (1, 2):
                path = ROOT / f"build/phase5/control-repetition-{rep}.json"
                path.unlink(missing_ok=True)
                command = ["python3", "-I", "tests/fixtures/phase4_game.py",
                           CLIENT.relative_to(ROOT).as_posix(), "--report", path.relative_to(ROOT).as_posix()]
                start = time.monotonic()
                result = process.run(command, cwd=ROOT, timeout=remaining(collection_started))
                if result.returncode:
                    raise ValueError("unchanged six-case control process failed")
                if path.stat().st_size > 1048576:
                    raise ValueError("control process report byte cap")
                actual = json.loads(path.read_text())
                process.public(actual)
                for name in ("rom", "scenario", "oracle", "source"):
                    if actual.get(name + "_sha256") != cases[0][name]["sha256"]:
                        raise ValueError("control process report identity differs")
                if (actual.get("client_sha256") != [roster["client"]["sha256"]]
                        or actual.get("build_configuration_sha256") != roster["cmake_configuration"]["sha256"]
                        or actual.get("visual_observations") != {
                            "title_to_play_field_10_changed": True,
                            "start_idle_to_moved_marker_field_19_changed": True}
                        or [r["id"] for r in actual.get("results", [])] != [c["case_id"] for c in cases]):
                    raise ValueError("unchanged six-case control process predicates differ")
                for case, observation in zip(cases, actual["results"]):
                    proofs.append(receipt(case, rep, command, start, result, observation,
                                          roster["client"]["sha256"]))
        else:
            fields = int(json.loads((ROOT / cases[0]["scenario"]["path"]).read_text())["budget"].get("boot_fields", 60))
            for case in cases:
                for rep in (1, 2):
                    # Diagnostic final output exposes the existing stop trace; do not retain peek/RAM bytes.
                    trace_path = ROOT / f"build/phase5/baseline-{fixture_id}-{case['case_id']}-{rep}.jsonl"
                    trace_path.unlink(missing_ok=True)
                    command = [CLIENT.relative_to(ROOT).as_posix(), rom.relative_to(ROOT).as_posix(),
                               "--fields", str(fields), "--peek", "0xff0000", "1",
                               "--dump-instruction-trace", trace_path.relative_to(ROOT).as_posix()]
                    start = time.monotonic()
                    result = process.run(command, cwd=ROOT, timeout=remaining(collection_started))
                    selected = []
                    for line in result.stdout.splitlines():
                        if line.startswith("{"):
                            try:
                                value = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            if "fields" in value:
                                selected.append({k: v for k, v in value.items() if k in (
                                    "fields", "ram_fnv1a64", "unsupported", "stop_reason", "instruction_address",
                                    "opcode", "fault_address", "pc", "tick", "access_width")})
                    observation = selected[-1] if selected else None
                    if trace_path.is_file():
                        if trace_path.stat().st_size > 1048576:
                            raise ValueError("instruction receipt byte cap")
                        traces = [json.loads(line) for line in trace_path.read_text().splitlines()]
                        earliest = next((t for t in traces if t.get("stop_reason")), None)
                        if observation is not None:
                            observation["earliest_stop"] = earliest
                            observation["trace_dropped"] = traces[-1].get("dropped") if traces else None
                            # A bounded trace can overflow before the stop. Preserve the final
                            # machine clock separately; never label it an exact first-stop tick.
                            state = traces[-1].get("state", {}) if traces else {}
                            observation["final_machine_tick"] = state.get("tick")
                            observation["final_machine_pc"] = state.get("pc")
                    proof = receipt(case, rep, command, start, result, observation, roster["client"]["sha256"])
                    proof.update(requested_fields=fields,
                                 rejection="invalid-rom" if "REJECT: invalid-rom" in result.stderr else None)
                    proofs.append(proof)
    order = {(c["fixture_id"], c["case_id"]): i for i, c in enumerate(roster["cases"])}
    proofs.sort(key=lambda p: (order[(p["fixture_id"], p["case_id"])], p["repetition"]))
    receipts = {"schema": "genewhip-phase5-process-v1", "context": "actual-public-client", "processes": proofs}
    rows = module.project_records(roster, receipts)
    process.public(receipts)
    process.public(rows)
    proof_path = ROOT / "evidence/phase5-baseline-process.json"
    proof_path.write_text(json.dumps(receipts, sort_keys=True, indent=2) + "\n")
    report = {"schema": module.REPORT_SCHEMA, "roster_sha256": module.digest(canonical(roster)),
              "repetitions": [1, 2], "records": rows, "process_receipts": module.file_identity(proof_path),
              "collection": {name + "_sha256": roster[name]["sha256"] for name in module.ROSTER_IDENTITIES}}
    report["collection"]["elapsed_seconds"] = round(time.monotonic() - collection_started, 6)
    module.validate_report(report, roster)
    screening = json.loads((ROOT / "fixtures/candidate-screening-v2.json").read_text())
    inventory = {"schema": "genewhip-phase5-failure-inventory-v1",
        "baseline_sha256": module.digest(canonical(report)), "baseline_roster_sha256": report["roster_sha256"],
        "reference_report_sha256": roster["reference_report"]["sha256"],
        "screening_ledger": module.file_identity(ROOT / "fixtures/candidate-screening-v2.json"),
        "screening_dispositions": [{k: c.get(k) for k in ("id", "lineage_id", "state", "outcome", "reason")}
                                   for c in screening["candidates"]],
        "records": [r for r in rows if r["kind"] == "candidate" and r["outcome"] != "pass"],
        "classification_limits": {"source_state_controller": "unsupported by retained public client",
                                  "reference_qualification": "separate from Genewhip playability"}}
    process.public(inventory)
    REPORT.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    inventory_path = ROOT / "evidence/phase5-failure-inventory.json"
    inventory_path.write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n")
    module.validate_handoff(inventory_path, report)
    return report


def remaining(start: float) -> float:
    seconds = 600 - (time.monotonic() - start)
    if seconds <= 0:
        raise ValueError("baseline collection exceeded 600-second budget")
    return seconds


def load_baseline():
    import importlib.util
    spec = importlib.util.spec_from_file_location("phase5_baseline", ROOT / "scripts/evidence/phase5_baseline.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def receipt(case, repetition, command, start, result, observation, client_sha256):
    return {"fixture_id": case["fixture_id"], "case_id": case["case_id"], "repetition": repetition,
            "command": command, "wall_seconds": round(time.monotonic() - start, 6),
            "returncode": result.returncode, "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
            "client_sha256": client_sha256, "observation": observation}


def self_test():
    process = load_baseline().process_tools()
    result = process.run([sys.executable, "-c", "print('bounded-status')"], cwd=ROOT)
    if result.returncode or result.stdout.strip() != "bounded-status":
        raise ValueError("offline subprocess status self-test failed")
    for command, kwargs, expected in (
        ([sys.executable, "-c", "import os; os.write(1,b'x'*8192)"], {"cap": 1024}, "byte cap"),
        ([sys.executable, "-c", "import time; time.sleep(2)"], {"timeout": .1}, "timeout")):
        try:
            process.run(command, cwd=ROOT, **kwargs)
        except ValueError as exc:
            if expected not in str(exc): raise
        else:
            raise ValueError("offline process bound self-test failed")
    try:
        remaining(time.monotonic() - 601)
    except ValueError:
        print(json.dumps({"outcome": "pass", "checks": ["process-status", "output-cap", "timeout", "collection-chronology"]}))
        return
    raise ValueError("collection chronology self-test failed")


def sanitized_failure_label(error: BaseException) -> str:
    """Expose only exception/receipt enums in CI; never echo messages or commands."""
    exception_names = {"OSError", "ValueError", "KeyError", "TypeError",
                       "SubprocessError", "ProcessCaptureError", "RuntimeError"}
    labels = [type(error).__name__ if type(error).__name__ in exception_names else "other"]
    receipt = getattr(error, "process_receipt", None)
    if isinstance(receipt, dict):
        allowed = {
            "failure_type": {"ValueError", "TimeoutExpired", "KeyboardInterrupt",
                             "OSError", "ProcessCaptureError"},
            "process_group_cleanup": {"not-launched", "pending", "confirmed", "unconfirmed"},
            "cleanup_error": {"PermissionError", "ProcessLookupError", "OSError", "TimeoutExpired"},
        }
        for key, values in allowed.items():
            value = receipt.get(key)
            if value is not None:
                labels.append(f"{key}={value if isinstance(value, str) and value in values else 'other'}")
    return " ".join(labels)


def main() -> int:
    global CLIENT, ROSTER, REPORT
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--freeze-roster", action="store_true")
    parser.add_argument("--collect", type=Path)
    parser.add_argument("--roster", type=Path, default=ROSTER)
    parser.add_argument("--output", type=Path, default=REPORT)
    args = parser.parse_args()
    try:
        base_spec = __import__("importlib.util").util.spec_from_file_location(
            "phase5_baseline", ROOT / "scripts/evidence/phase5_baseline.py")
        base = __import__("importlib.util").util.module_from_spec(base_spec)
        base_spec.loader.exec_module(base)
        if args.self_test:
            self_test()
        elif args.freeze_roster:
            roster = base.freeze_roster()
            base.validate_roster(roster)
            args.output.write_text(json.dumps(roster, sort_keys=True, indent=2) + "\n")
            print(json.dumps({"outcome": "pass", "cases": roster["case_count"], "stages": len(roster["stages"])}))
        elif args.collect:
            CLIENT, ROSTER, REPORT = args.collect.resolve(), args.roster.resolve(), args.output.resolve()
            report = collect()
            print(json.dumps({"outcome": "pass", "rows": len(report["records"]),
                              "elapsed_seconds": report["collection"]["elapsed_seconds"],
                              "baseline_bytes": REPORT.stat().st_size,
                              "failure_inventory_bytes": (ROOT / "evidence/phase5-failure-inventory.json").stat().st_size}))
        else:
            parser.error("choose --self-test, --freeze-roster, or --collect CLIENT")
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("BLOCKED: baseline collection or validation failed "
              f"[{sanitized_failure_label(exc)}]", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
