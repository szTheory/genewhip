#!/usr/bin/env python3
"""Freeze and validate Phase 5 baseline rows without upgrading unknowns to passes."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import subprocess
import tempfile
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
STAGES = ("load", "boot", "interaction", "sustained", "completion")
STATUSES = {"pass", "fail", "unsupported", "skipped", "unknown", "infrastructure-error"}
ROSTER_IDENTITIES = ("admission_eligibility", "admission_validator", "baseline_validator",
                     "client", "cmake_configuration", "cmake_source", "consumer",
                     "consumer_adapter", "process_helper", "control_runner", "current_reference", "manifest", "reference_report", "runner")
ROSTER_SCHEMA = "genewhip-phase5-baseline-roster-v1"
REPORT_SCHEMA = "genewhip-phase5-baseline-v1"
SCHEMA = "genewhip-phase5-evidence-v1"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"required evidence module unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tracer_output_path(path: Path) -> Path:
    """Allow only the dedicated generated Phase 5 report path."""
    output = path if path.is_absolute() else ROOT / path
    resolved = output.resolve()
    expected = (ROOT / "build/phase5/phase5-tracer.json").resolve()
    if resolved != expected:
        raise ValueError("tracer output must be build/phase5/phase5-tracer.json")
    return resolved


def tracer(headless: Path) -> dict:
    records_module = load_module("phase5_records", ROOT / "tools/evidence/phase5_records.py")
    stages = records_module.STAGES

    headless = headless.resolve()
    if not headless.is_file():
        raise ValueError("headless client is unavailable")
    scenario_path = ROOT / "fixtures/independent-game-v2/scenario.json"
    oracle_path = ROOT / "fixtures/independent-game-v2/oracle.json"
    source_path = ROOT / "fixtures/independent-game-v2/src/game.s"
    rom_path = ROOT / "fixtures/independent-game-v2/game.bin"
    notices_path = ROOT / "fixtures/independent-game-v2/NOTICES.md"
    lock_path = ROOT / "fixtures/independent-game-v2/toolchain.lock"
    scenario = json.loads(scenario_path.read_text())
    oracle = json.loads(oracle_path.read_text())
    case = next(item for item in scenario["cases"] if item["id"] == "title-no-start")

    validator = load_module("fixture_manifest", ROOT / "tools/evidence/fixture_manifest.py")
    provenance = load_module("source_provenance", ROOT / "scripts/fixtures/source_provenance.py")
    manifest = json.loads((ROOT / "fixtures/manifest.json").read_text())
    row = next(item for item in manifest["fixtures"]
               if item.get("id") == "genewhip-independent-game-v2")
    with provenance.source_identity_context(validator, row, ROOT):
        admitted_rom = provenance.require_admitted(validator, ROOT, "fixtures/manifest.json",
                                                   row["id"], Path("build/phase5/diagnostic.bin"))
    if Path(admitted_rom).resolve() != rom_path.resolve():
        raise ValueError("admission resolved a different control ROM")
    if sha(rom_path) != row.get("sha256") or sha(source_path) != row.get("source_sha256"):
        raise ValueError("admitted source or ROM identity differs from the manifest")
    if "fixtures/independent-game-v2/NOTICES.md" not in row.get("notices", []):
        raise ValueError("admitted control notice is missing")

    cache = headless.parents[2] / "CMakeCache.txt"
    if not cache.is_file():
        raise ValueError("headless build configuration identity is unavailable")
    toolchain = json.loads(lock_path.read_text())
    if toolchain.get("reference_capability", {}).get("status") != "pass":
        raise ValueError("recorded reference capability is not passing")
    reference = json.loads((ROOT / "evidence/independent-game-v2.json").read_text())
    reference_validator = load_module("phase5_reference", ROOT / "tests/fixtures/game_successor_reference.py")
    reference_result = reference_validator.validate_evidence(reference)
    if reference_result != "ok":
        raise ValueError("independent reference evidence failed validation: " + reference_result)
    identities = reference.get("identities", {})
    expected_reference = {"source_sha256": sha(source_path), "rom_sha256": sha(rom_path),
                          "scenario_sha256": sha(scenario_path), "oracle_sha256": sha(oracle_path),
                          "mame_lock_sha256": sha(lock_path)}
    actual_reference = {"source_sha256": identities.get("source_sha256"),
                        "rom_sha256": identities.get("rom_sha256"),
                        "scenario_sha256": identities.get("scenario_sha256"),
                        "oracle_sha256": identities.get("oracle_sha256"),
                        "mame_lock_sha256": identities.get("mame_lock_sha256")}
    if actual_reference != expected_reference:
        raise ValueError("reference evidence identities differ from the admitted control")
    reference_case = next(item for item in reference["cases"] if item.get("id") == case["id"])

    game = load_module("phase4_game", ROOT / "tests/fixtures/phase4_game.py")
    with tempfile.TemporaryDirectory(prefix="gw-phase5-control-") as tmp:
        observed = game.execute(headless, rom_path, case, Path(tmp) / case["id"])
    if observed["play_state"] != case["expect"]["play_state"]:
        raise ValueError("control source predicate title-no-start failed")
    if observed["position"] not in range(case["expect"]["position_min"],
                                         case["expect"]["position_max"] + 1):
        raise ValueError("control source position predicate title-no-start failed")
    if observed["final"]["fields"] != case["frames"] or observed["final"]["unsupported"] != 0:
        raise ValueError("public headless client returned an incomplete control result")

    common = {
        "schema": SCHEMA,
        "fixture_id": row["id"],
        "title_id": "genewhip-independent-game-v2",
        "source_revision": row["revision"],
        "source_sha256": sha(source_path),
        "build_configuration_sha256": sha(cache),
        "toolchain_sha256": sha(lock_path),
        "rom_sha256": sha(rom_path),
        "notices_sha256": sha(notices_path),
        "reference_evidence_sha256": sha(ROOT / "evidence/independent-game-v2.json"),
        "profile": scenario["profile"],
        "scenario_sha256": sha(scenario_path),
        "input_sha256": observed["input_sha256"],
        "oracle_sha256": sha(oracle_path),
        "client_sha256": sha(headless),
        "run_id": "control-title-no-start-01",
        "case_id": case["id"],
    }
    stage_details = {
        "documentary": {"reason": "existing source, notice and manifest admission validated",
                         "observations": {"source_predicate": case["id"], "manifest_status": row["status"]}},
        "build": {"reason": "admitted ROM and existing pinned build identity validated",
                  "observations": {"rom_bytes": rom_path.stat().st_size,
                                   "rom_matches_manifest": True, "notices_match_manifest": True}},
        "reference": {"reason": "independent MAME reference and source oracle validated",
                      "observations": {"reference_outcome": reference_case["outcome"],
                                       "reference_status": reference_case["status"],
                                       "frames": reference_case["frames"]}},
        "core": {"reason": "unchanged admitted control title-no-start passed through public headless client",
                 "observations": {"fields": observed["final"]["fields"],
                                  "unsupported": observed["final"]["unsupported"],
                                  "stop_reason": observed["final"]["stop_reason"],
                                  "fault_address": observed["final"]["fault_address"],
                                  "play_state": observed["play_state"], "position": observed["position"],
                                  "source_predicate": case["id"]}},
    }
    records = []
    for stage in stages:
        detail = stage_details[stage]
        records.append({**common, "stage": stage, "outcome": "pass",
                        "reason": detail["reason"], "observations": detail["observations"]})
    document = {"schema": SCHEMA, "fixture_id": row["id"], "case_id": case["id"],
                "denominator": len(records), "records": records}
    return records_module.validate_dataset(document)



def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_identity(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": path.resolve().relative_to(ROOT).as_posix(), "sha256": digest(data), "bytes": len(data)}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def freeze_roster() -> dict:
    manifest = json.loads((ROOT / "fixtures/manifest.json").read_text())
    rows = {row["id"]: row for row in manifest["fixtures"]}
    control_scenario = json.loads((ROOT / "fixtures/independent-game-v2/scenario.json").read_text())
    control_oracle = json.loads((ROOT / "fixtures/independent-game-v2/oracle.json").read_text())
    client = ROOT / "build/phase5/tools/session/gw_headless"
    cmake = ROOT / "build/phase5/CMakeCache.txt"
    if not client.is_file() or not cmake.is_file():
        raise ValueError("configured Phase 5 public headless client is required")
    cases = []
    for case in control_scenario["cases"]:
        cases.append({"fixture_id": "genewhip-independent-game-v2", "title_id": "genewhip-independent-game-v2",
                      "case_id": case["id"], "kind": "control", "stage_rows": list(STAGES),
                      "profile": control_scenario["profile"], "scenario": file_identity(ROOT / "fixtures/independent-game-v2/scenario.json"),
                      "oracle": file_identity(ROOT / "fixtures/independent-game-v2/oracle.json"),
                      "input_sha256": digest(json.dumps(case["input_schedule"], sort_keys=True, separators=(",", ":")).encode()),
                      "input_events": case["input_schedule"], "expectations": case["expect"], "fields": case["frames"],
                      "source_revision": rows["genewhip-independent-game-v2"]["revision"],
                      "source": file_identity(ROOT / control_scenario["source"]["relative_path"]),
                      "build": file_identity(ROOT / rows["genewhip-independent-game-v2"]["build"]["source"]),
                      "toolchain": file_identity(ROOT / "fixtures/independent-game-v2/toolchain.lock"),
                      "reference_evidence": file_identity(ROOT / "evidence/independent-game-v2.json"),
                      "materials": {"notice": file_identity(ROOT / "fixtures/independent-game-v2/NOTICES.md"),
                                    "license": rows["genewhip-independent-game-v2"]["license"]},
                      "rom": file_identity(ROOT / rows["genewhip-independent-game-v2"]["rom"])})
    for fixture_id, title, slot in (("genewhip-phase5-a", "tank-battle", "a"), ("genewhip-phase5-b", "recursion94", "b")):
        row = rows.get(fixture_id)
        if not row or row.get("status") != "admitted":
            raise ValueError(f"fixture has not passed strict production admission: {fixture_id}")
        scenario_path = ROOT / f"fixtures/phase5-{slot}/scenario.json"
        oracle_path = ROOT / f"fixtures/phase5-{slot}/oracle.json"
        scenario = json.loads(scenario_path.read_text())
        for case in scenario["cases"]:
            case_inputs = [event for event in scenario["input_schedule"]
                           if case["id"] in event.get("cases", [])]
            cases.append({"fixture_id": fixture_id, "title_id": title, "case_id": case["id"],
                          "kind": "candidate", "stage_rows": list(STAGES), "profile": scenario["profile"],
                          "scenario": file_identity(scenario_path), "oracle": file_identity(oracle_path),
                          "input_sha256": digest(canonical({"input_schedule": scenario["input_schedule"],
                                                               "input_program": scenario["input_program"]})),
                          "input_events": case_inputs, "input_program": scenario["input_program"],
                          "expectation_ref": {"oracle_sha256": file_identity(oracle_path)["sha256"],
                                              "case_id": case["id"]},
                          "source_revision": row["revision"],
                          "source": file_identity(ROOT / row["source"]),
                          "admission": file_identity(ROOT / row["admission"]["path"]),
                          "build": file_identity(ROOT / f"fixtures/phase5-{slot}/build-record.json"),
                          "recipe": file_identity(ROOT / f"fixtures/phase5-{slot}/build-recipe.json"),
                          "toolchain": file_identity(ROOT / f"fixtures/phase5-{slot}/toolchain.lock"),
                          "materials": file_identity(ROOT / f"fixtures/phase5-{slot}/materials.json"),
                          "notices": file_identity(ROOT / f"fixtures/phase5-{slot}/notice-index.json"),
                          "route_input_schedule": file_identity(ROOT / f"fixtures/phase5-{slot}/input-schedule.json"),
                          "route_input_program": file_identity(ROOT / f"fixtures/phase5-{slot}/input-program.json"),
                          "reference_script": file_identity(ROOT / f"fixtures/phase5-{slot}/mame.lua"),
                          "reference_executable": file_identity(ROOT / f"fixtures/phase5-{slot}/reference-executable-pin.json"),
                          "reference_build": file_identity(ROOT / f"fixtures/phase5-{slot}/reference-build-record.json"),
                          "reference_evidence": file_identity(ROOT / "evidence/phase5-reference-d118.json"),
                          "rom": file_identity(ROOT / row["rom"])})
    return {"schema": ROSTER_SCHEMA, "case_count": len(cases), "repetitions": [1, 2],
            "stages": list(STAGES), "client": file_identity(client), "cmake_configuration": file_identity(cmake),
            "reference_report": file_identity(ROOT / "evidence/phase5-reference-d118.json"),
            "current_reference": file_identity(ROOT / "evidence/phase5-current-reference.json"),
            "admission_eligibility": file_identity(ROOT / "evidence/phase5-eligibility-v2.json"),
            "manifest": file_identity(ROOT / "fixtures/manifest.json"),
            "runner": file_identity(ROOT / "tests/fixtures/phase5_game.py"),
            "process_helper": file_identity(ROOT / "scripts/evidence/phase5_process.py"),
            "control_runner": file_identity(ROOT / "tests/fixtures/phase4_game.py"),
            "baseline_validator": file_identity(ROOT / "scripts/evidence/phase5_baseline.py"),
            "admission_validator": file_identity(ROOT / "tools/evidence/phase5_records.py"),
            "consumer": file_identity(ROOT / "scripts/fixtures/run_admitted.py"),
            "consumer_adapter": file_identity(ROOT / "scripts/fixtures/source_provenance.py"),
            "cmake_source": file_identity(ROOT / "CMakeLists.txt"), "cases": cases}


def validate_roster(roster: object, *, synthetic: bool = False) -> dict:
    if not isinstance(roster, dict) or roster.get("schema") != ROSTER_SCHEMA:
        raise ValueError("roster schema is missing")
    cases = roster.get("cases")
    if not isinstance(cases, list) or len(cases) != 12 or roster.get("case_count") != 12:
        raise ValueError("frozen roster must contain all 12 cases")
    if roster.get("repetitions") != [1, 2] or roster.get("stages") != list(STAGES):
        raise ValueError("frozen roster repetitions or stage order changed")
    for name in ROSTER_IDENTITIES:
        identity = roster.get(name)
        if (not isinstance(identity, dict) or not isinstance(identity.get("path"), str)
                or not isinstance(identity.get("bytes"), int) or identity["bytes"] <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", str(identity.get("sha256", "")))):
            raise ValueError(f"frozen roster lacks exact {name} identity")
    keys = [(row.get("fixture_id"), row.get("case_id")) for row in cases]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate case identity in frozen roster")
    if [row.get("kind") for row in cases].count("control") != 6:
        raise ValueError("unchanged six-case control denominator is missing")
    if [row.get("kind") for row in cases].count("candidate") != 6:
        raise ValueError("both admitted three-case candidate routes are required")
    for row in cases:
        for name in ("fixture_id", "title_id", "case_id", "profile", "input_sha256"):
            if not isinstance(row.get(name), str) or not row[name]:
                raise ValueError(f"roster identity missing: {name}")
        events = row.get("input_events")
        if not isinstance(events, list):
            raise ValueError("frozen input event list is missing")
        orders = [event.get("order") for event in events if "order" in event]
        if orders != sorted(orders) or len(orders) != len(set(orders)):
            raise ValueError("frozen input event order changed or duplicated")
        if row.get("kind") == "candidate" and not isinstance(row.get("input_program"), dict):
            raise ValueError("candidate input program is not preserved in the roster")
        for name in ("source", "build", "toolchain", "rom", "scenario", "oracle", "reference_evidence"):
            identity = row.get(name)
            if (not isinstance(identity, dict) or not isinstance(identity.get("path"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", str(identity.get("sha256", "")))):
                raise ValueError(f"frozen roster lacks exact {name} identity")
        if row.get("kind") == "candidate":
            for name in ("admission", "recipe", "materials", "notices", "route_input_schedule",
                         "route_input_program", "reference_script", "reference_executable", "reference_build"):
                if not isinstance(row.get(name), dict) or not re.fullmatch(
                        r"[0-9a-f]{64}", str(row[name].get("sha256", ""))):
                    raise ValueError(f"candidate frozen roster identity is missing: {name}")
    if not synthetic and roster != freeze_roster():
        raise ValueError("frozen roster differs from current bytes or source cases")
    return roster


def process_tools():
    return load_module("phase5_process", ROOT / "scripts/evidence/phase5_process.py")


def stage_evidence(case: dict, stage: str, proof: dict) -> tuple:
    """Project named predicates from retained process evidence, never from status claims."""
    if case["kind"] == "control":
        observed = proof["observation"]
        expected = case["expectations"]
        if (proof["returncode"] != 0 or observed.get("id") != case["case_id"]
                or observed.get("outcome") != "pass" or observed.get("fields") != case["fields"]
                or observed.get("unsupported") != 0
                or observed.get("play_state") != expected["play_state"]
                or not expected["position_min"] <= observed.get("position", -1) <= expected["position_max"]
                or observed.get("psg") != expected["psg_writes"]
                or not re.fullmatch(r"[0-9a-f]{16}", str(observed.get("machine_digest", "")))
                or (case["case_id"] == "action-no-trigger" and observed.get("ac_range") != 0)
                or (expected["psg_writes"] and observed.get("ac_range", 0) <= 0)):
            raise ValueError("control named source-state/PSG/field predicate failed")
        if stage == "completion":
            return "unknown", False, "control oracle declares no completion predicate", None
        if stage == "sustained" and case["case_id"] != "sustained-play":
            return "skipped", False, "sustained stage applies only to sustained-play", None
        return "pass", True, "unchanged control source-state/PSG/field assertions passed", observed
    final = proof.get("observation")
    if final is not None:
        if (not isinstance(final, dict)
                or any(type(final.get(k)) is not int or final[k] < 0 for k in (
                    "fields", "unsupported", "stop_reason", "instruction_address", "opcode", "fault_address"))
                or not re.fullmatch(r"[0-9a-f]{16}", str(final.get("ram_fnv1a64", "")))):
            raise ValueError("candidate named public-client final predicate is missing")
    rejected = proof.get("rejection") == "invalid-rom"
    stopped = bool(final and (final.get("stop_reason") or final.get("unsupported") or final.get("fault_address")))
    completed = bool(final and proof["returncode"] == 0 and final.get("fields") == proof["requested_fields"])
    if rejected:
        return ("fail", True, "public core rejected admitted ROM: invalid-rom", {"reported_stop": "invalid-rom", "exit_code": proof["returncode"]}) if stage == "load" else (
            "skipped", False, "unreached after invalid-rom load rejection", None)
    if stage == "load" and final:
        return "pass", True, "public core loaded admitted ROM", final
    if stage == "boot" and stopped:
        return "fail", True, "public core stopped during bounded boot prefix", final
    if not completed or stopped:
        if stage in ("load", "boot"):
            return "infrastructure-error", False, "bounded client did not report complete boot prefix", final
        return "skipped", False, "unreached after bounded boot failure", None
    if stage == "boot":
        return "unknown", False, "boot-vector completion is not separately observable", final
    if stage in ("interaction", "sustained"):
        return "unsupported", False, "source-conditioned input program is not dispatchable by retained client", None
    return "unknown", False, "completion is not independently demonstrated", None


def project_records(roster: dict, receipts: dict) -> list:
    expected = [(c["fixture_id"], c["case_id"], rep) for c in roster["cases"] for rep in (1, 2)]
    proofs = receipts.get("processes", [])
    if [(p.get("fixture_id"), p.get("case_id"), p.get("repetition")) for p in proofs] != expected:
        raise ValueError("process receipt denominator/order differs")
    rows = []
    for case, group in zip(roster["cases"], (proofs[i:i+2] for i in range(0, len(proofs), 2))):
        for proof in group:
            if proof.get("client_sha256") != roster["client"]["sha256"]:
                raise ValueError("process receipt client identity differs")
            if not isinstance(proof.get("wall_seconds"), (int, float)) or not math.isfinite(proof["wall_seconds"]) or not 0 <= proof["wall_seconds"] <= 600:
                raise ValueError("process receipt chronology differs")
            if receipts["context"] == "actual-public-client":
                rep = proof["repetition"]
                if case["kind"] == "control":
                    command = ["python3", "-I", roster["control_runner"]["path"], roster["client"]["path"],
                               "--report", f"build/phase5/control-repetition-{rep}.json"]
                else:
                    fields = json.loads((ROOT / case["scenario"]["path"]).read_text())["budget"].get("boot_fields", 60)
                    command = [roster["client"]["path"], case["rom"]["path"], "--fields", str(fields),
                               "--peek", "0xff0000", "1", "--dump-instruction-trace",
                               f"build/phase5/baseline-{case['fixture_id']}-{case['case_id']}-{rep}.jsonl"]
                    if proof.get("requested_fields") != fields:
                        raise ValueError("process requested fields differs")
                if proof.get("command") != command:
                    raise ValueError("process command differs from frozen case")
                for key in ("stdout_sha256", "stderr_sha256"):
                    if not re.fullmatch(r"[0-9a-f]{64}", str(proof.get(key, ""))):
                        raise ValueError("process output receipt digest missing")
            for stage in STAGES:
                outcome, reached, reason, observations = stage_evidence(case, stage, proof)
                rows.append({"fixture_id": case["fixture_id"], "title_id": case["title_id"],
                    "kind": case["kind"], "case_id": case["case_id"], "repetition": proof["repetition"],
                    "stage": stage, "profile": case["profile"],
                    **{name + "_sha256": case[name]["sha256"] for name in ("scenario", "oracle", "rom")},
                    "input_sha256": case["input_sha256"], "client_sha256": roster["client"]["sha256"],
                    "cmake_configuration_sha256": roster["cmake_configuration"]["sha256"],
                    "process_sha256": digest(canonical(proof)), "outcome": outcome, "reached": reached,
                    "reason": reason, "observations": observations, "command": proof["command"],
                    "wall_seconds": proof["wall_seconds"]})
    return rows


def validate_report(report: object, roster: dict | None = None, *, synthetic: bool = False,
                    receipts: dict | None = None) -> dict:
    if not isinstance(report, dict) or report.get("schema") != REPORT_SCHEMA:
        raise ValueError("baseline schema is missing")
    if roster is None:
        roster = json.loads((ROOT / "evidence/phase5-baseline-roster.json").read_text())
    process_tools().public(report)
    validate_roster(roster, synthetic=synthetic)
    if report.get("roster_sha256") != digest(canonical(roster)):
        raise ValueError("baseline roster identity differs from the frozen report")
    rows = report.get("records")
    expected = [(case["fixture_id"], case["case_id"], rep, stage)
                for case in roster["cases"] for rep in (1, 2) for stage in STAGES]
    actual = [(row.get("fixture_id"), row.get("case_id"), row.get("repetition"), row.get("stage"))
              for row in rows] if isinstance(rows, list) else []
    if len(actual) != 120 or actual != expected:
        raise ValueError("baseline must preserve the exact 120-row case/repetition/stage denominator and order")
    collection = report.get("collection", {})
    if not synthetic and (not isinstance(collection.get("elapsed_seconds"), (int, float))
            or not math.isfinite(collection["elapsed_seconds"]) or not 0 <= collection["elapsed_seconds"] <= 600):
        raise ValueError("collection chronology exceeds 600-second budget")
    for name in ROSTER_IDENTITIES:
        if collection.get(name + "_sha256") != roster[name]["sha256"]:
            raise ValueError("collection identity differs: " + name)
    if report.get("repetitions") != [1, 2]:
        raise ValueError("baseline repetitions differ")
    if not synthetic:
        identity = report.get("process_receipts", {})
        path = ROOT / "evidence/phase5-baseline-process.json"
        if identity != file_identity(path):
            raise ValueError("frozen process receipt identity differs")
        receipts = json.loads(path.read_text())
    if not isinstance(receipts, dict) or receipts.get("context") != ("synthetic-unit" if synthetic else "actual-public-client"):
        raise ValueError("process receipt context differs")
    process_tools().public(receipts)
    for row in rows:
        if row.get("outcome") not in STATUSES or not isinstance(row.get("reason"), str) or not row["reason"].strip():
            raise ValueError("baseline row has an invalid outcome or missing reason")
        if row["outcome"] == "pass" and row.get("observations") in (None, {}, []):
            raise ValueError("pass row lacks observable evidence")
        if row["outcome"] == "pass" and row.get("reached") is not True:
            raise ValueError("pass row cannot be unreached")
        if row["outcome"] in ("unsupported", "skipped", "unknown") and row.get("reached") is True:
            raise ValueError("unproven stage cannot be marked reached")
    projected = project_records(roster, receipts)
    if rows != projected:
        raise ValueError("baseline row identity or named predicate differs from frozen process proof")
    control = [row for row in rows if row.get("kind") == "control"]
    for rep in (1, 2):
        sustained = [row for row in control if row.get("repetition") == rep
                     and row.get("case_id") == "sustained-play" and row.get("stage") == "sustained"]
        if len(sustained) != 1 or sustained[0].get("outcome") != "pass" or sustained[0].get("observations", {}).get("fields") != 720:
            raise ValueError("unchanged control sustained-play must pass 720 fields twice")
    return report


def validate_handoff(path: Path, report: dict, *, synthetic: bool = False) -> dict:
    doc = json.loads(path.read_text())
    process_tools().public(doc)
    if not isinstance(doc, dict) or doc.get("schema") != "genewhip-phase5-failure-inventory-v1":
        raise ValueError("failure inventory schema is missing")
    records = report["records"]
    expected_failures = [row for row in records if row["kind"] == "candidate"
                         and row["outcome"] in ("fail", "unsupported", "skipped", "unknown", "infrastructure-error")]
    if doc.get("baseline_sha256") != digest(canonical(report)):
        raise ValueError("failure inventory is stale for the exact baseline")
    if doc.get("records") != expected_failures:
        raise ValueError("failure inventory does not preserve every candidate failure/skip/unknown")
    if not synthetic:
        ledger = ROOT / "fixtures/candidate-screening-v2.json"
        dispositions = [{k: c.get(k) for k in ("id", "lineage_id", "state", "outcome", "reason")}
                        for c in json.loads(ledger.read_text())["candidates"]]
        if (doc.get("baseline_roster_sha256") != report["roster_sha256"]
                or doc.get("reference_report_sha256") != report["collection"]["reference_report_sha256"]
                or doc.get("screening_ledger") != file_identity(ledger)
                or doc.get("screening_dispositions") != dispositions):
            raise ValueError("failure inventory identity or screening disposition differs")
    return doc


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--tracer", type=Path)
    group.add_argument("--validate", type=Path)
    group.add_argument("--validate-handoff", type=Path)
    group.add_argument("--freeze-roster", action="store_true")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.tracer:
            document = tracer(args.tracer)
            if args.output is None:
                parser.error("--tracer requires --output")
            output = tracer_output_path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
            print(json.dumps({"outcome": "pass", "denominator": len(document["records"])}))
        elif args.freeze_roster:
            roster = freeze_roster()
            validate_roster(roster)
            out = ROOT / "evidence/phase5-baseline-roster.json"
            out.write_text(json.dumps(roster, sort_keys=True, indent=2) + "\n")
            print(json.dumps({"outcome": "pass", "cases": len(roster["cases"]), "repetitions": 2, "stages": 5}))
        else:
            report_path = args.baseline if args.validate_handoff else (args.validate or ROOT / "evidence/phase5-baseline.json")
            if args.validate_handoff and args.baseline is None:
                parser.error("--validate-handoff requires --baseline")
            report = json.loads(report_path.read_text())
            validate_report(report)
            if args.validate_handoff:
                validate_handoff(args.validate_handoff, report)
            print(json.dumps({"outcome": "pass", "rows": len(report["records"])}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("BLOCKED: baseline evidence validation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
