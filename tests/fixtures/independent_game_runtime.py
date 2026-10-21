#!/usr/bin/env python3
"""Run and bind the bounded, non-admission MAME candidate qualification."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/independent-game"
LOCK_PATH = FIXTURE / "toolchain.lock"
SCENARIO_PATH = FIXTURE / "scenario.json"
EVIDENCE_PATH = ROOT / "evidence/independent-game.json"
MAX_BYTES = 134_217_728
MAX_ROWS = 3_000_000
STATES = ("pass", "fail", "unknown", "unsupported", "skipped", "infrastructure_error")

spec = importlib.util.spec_from_file_location("gw_trace", FIXTURE / "trace.py")
trace = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(trace)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    return sha(path.read_bytes())


def run_mame(executable: Path, rom: Path, script: Path, timeout: int) -> tuple[bytes, bytes, int]:
    with tempfile.TemporaryDirectory(prefix="gw-mame-run-") as temp:
        work = Path(temp)
        command = [str(executable), "genesis", "-cart", str(rom), "-noreadconfig",
                   "-video", "none", "-sound", "none", "-skip_gameinfo",
                   "-seconds_to_run", "5", "-log",
                   "-autoboot_script", str(script), "-autoboot_delay", "0"]
        env = {**os.environ, "SDL_VIDEODRIVER": "dummy", "SDL_AUDIODRIVER": "dummy"}
        result = subprocess.run(command, cwd=work, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout, check=False)
        log_path = work / "error.log"
        if log_path.exists() and log_path.stat().st_size > MAX_BYTES:
            raise ValueError(f"MAME trace file exceeds byte bound: {log_path.stat().st_size} > {MAX_BYTES}")
        error_log = log_path.read_bytes() if log_path.exists() else b""
        return result.stdout, error_log, result.returncode


def choose_trace(stdout: bytes, error_log: bytes) -> bytes:
    candidates = [stdout, error_log]
    candidates = [data for data in candidates if data.count(b"GWTRACE,")]
    if not candidates:
        raise ValueError("MAME emitted no GWTRACE records to stdout or error.log")
    return max(candidates, key=lambda data: data.count(b"GWTRACE,"))


def access_counts(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = f"{row['space']}:{row['operation']}"
        counts[key] = counts.get(key, 0) + 1
    return counts


def capture_run(name: str, executable: Path, rom: Path, script: Path, timeout: int) -> tuple[dict, bytes, list[dict], bytes]:
    stdout, error_log, returncode = run_mame(executable, rom, script, timeout)
    raw = choose_trace(stdout, error_log)
    rows = trace.parse(raw, MAX_BYTES, MAX_ROWS)
    combined = stdout + b"\n" + error_log
    if returncode:
        raise ValueError(f"MAME {name} process exited {returncode}")
    details = {"name": name, "status": "pass", "trace": trace.trace_summary(raw, rows)}
    return details, raw, rows, combined


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] != "--verify":
        print(f"usage: {sys.argv[0]} --verify", file=sys.stderr)
        return 2
    doc = json.loads(LOCK_PATH.read_text())
    scenario = json.loads(SCENARIO_PATH.read_text())
    mame = doc["mame"]
    source = Path(os.environ.get("GENEWHIP_MAME_SOURCE_DIR", "/tmp/genewhip-mame289/base")).resolve()
    executable = source / "genewhip"
    rom = FIXTURE / scenario["rom"]["relative_path"].split("fixtures/independent-game/", 1)[-1]
    audit_path = FIXTURE / "route_audit.json"
    patch_path = FIXTURE / "mame.patch"
    script_path = FIXTURE / "mame_build.sh"
    audit = json.loads(audit_path.read_text())
    evidence = {
        "schema_version": 1,
        "purpose": "bounded runtime qualification evidence; candidate remains not admitted",
        "status": "unknown",
        "candidate_disposition": "not admitted",
        "pong_disposition": "rejected",
        "identities": {
            "mame_version": mame.get("version"),
            "mame_source_revision": mame.get("source_revision"),
            "mame_source_archive_sha256": mame.get("source_archive_sha256"),
            "mame_source_signature": mame.get("source_signature"),
            "mame_configuration_sha256": mame.get("source_configuration_identity"),
            "mame_executable_sha256": mame.get("executable_build_sha256"),
            "mame_build_script_sha256": mame.get("build_script_sha256"),
            "mame_patch_sha256": mame.get("patch_sha256"),
            "route_audit_sha256": sha_file(audit_path),
            "route_audit_status": audit.get("status"),
            "trace_parser_sha256": sha_file(FIXTURE / "trace.py"),
            "runtime_harness_sha256": sha_file(Path(__file__).resolve()),
            "candidate_notice_sha256": sha_file(FIXTURE / "NOTICES.md"),
            "rom_relative_path": scenario["rom"]["relative_path"],
            "rom_sha256": sha_file(rom),
            "candidate_source_relative_path": "fixtures/independent-game/src/game.s",
            "candidate_source_sha256": sha_file(FIXTURE / "src/game.s"),
            "candidate_toolchain_lock_sha256": sha_file(LOCK_PATH),
            "scenario_sha256": sha_file(SCENARIO_PATH),
            "input_script_sha256": sha_file(FIXTURE / "mame.lua"),
            "input_schedule_sha256": sha(json.dumps(scenario["input_schedule"], sort_keys=True, separators=(",", ":")).encode()),
            "profile": scenario["machine"]["profile"],
        },
        "device_map": audit.get("machine", {}).get("map_entries", []),
        "spaces": audit.get("spaces", []),
        "routes": audit.get("routes", []),
        "instrumented_address_ranges": audit.get("applicable_transactions", {}),
        "coverage": {
            "route_audit_status": audit.get("status"),
            "source_route_to_hook": "pass" if audit.get("status") == "pass" else audit.get("status", "unknown"),
            "m68000_address_mask": "0xFFFFFF",
            "trace_complete_and_ordered": False,
            "runtime_progression": "unknown",
            "forbidden_candidate_accesses": {"storage": 0, "enable_control": 0},
        },
        "scenario": scenario,
        "runs": [],
        "outcome_denominator": 2,
        "outcome_counts": {state: 0 for state in STATES},
        "errors": [],
    }
    try:
        if mame.get("status") != "pass" or audit.get("status") != "pass":
            raise ValueError("locked MAME build and complete source-route audit must both pass")
        if mame.get("executable_build_sha256") != sha_file(executable):
            raise ValueError("executed MAME binary differs from the locked executable digest")
        if evidence["identities"]["rom_sha256"] != scenario["rom"]["sha256"]:
            raise ValueError("candidate ROM differs from scenario identity")
        if sha_file(patch_path) != mame.get("patch_sha256") or sha_file(script_path) != mame.get("build_script_sha256"):
            raise ValueError("patch or MAME build script differs from locked identity")
        subprocess.run(["bash", str(FIXTURE / "mame_build.sh"), "--verify-toolchain-lock"],
                       env={**os.environ, "GENEWHIP_MAME_SOURCE_DIR": str(source)},
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        if scenario["budget"]["max_trace_bytes"] != MAX_BYTES or scenario["budget"]["max_trace_rows"] != MAX_ROWS:
            raise ValueError("scenario and parser bounds differ")

        sentinel_source = FIXTURE / "src/sram_sentinel.s"
        sentinel_builder = FIXTURE / "build-sram-sentinel.sh"
        with tempfile.TemporaryDirectory(prefix="gw-sram-rom-") as temp:
            sentinel_rom = Path(temp) / "sram-sentinel.bin"
            build_result = subprocess.run(["bash", str(sentinel_builder), "--output", str(sentinel_rom)],
                                          env={**os.environ, "GENEWHIP_MAME_SOURCE_DIR": str(source)},
                                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1800, check=True)
            evidence["identities"]["sram_sentinel_source_relative_path"] = "fixtures/independent-game/src/sram_sentinel.s"
            evidence["identities"]["sram_sentinel_source_sha256"] = sha_file(sentinel_source)
            evidence["identities"]["sram_sentinel_builder_sha256"] = sha_file(sentinel_builder)
            evidence["identities"]["sram_sentinel_rom_sha256"] = sha_file(sentinel_rom)
            evidence["identities"]["sram_sentinel_build_log_sha256"] = sha(build_result.stdout)
            sentinel, sentinel_raw, sentinel_rows, sentinel_text = capture_run(
                "sram-route-sentinel", executable, sentinel_rom, FIXTURE / "sram-sentinel.lua", scenario["budget"]["hard_timeout_seconds"])
        storage_lo, storage_hi = int(scenario["forbidden_cartridge_sram"]["storage_start"], 16), int(scenario["forbidden_cartridge_sram"]["storage_end"], 16)
        control_lo, control_hi = int(scenario["forbidden_cartridge_sram"]["enable_control_start"], 16), int(scenario["forbidden_cartridge_sram"]["enable_control_end"], 16)
        sentinel_matches = [row for row in sentinel_rows if
                            (storage_lo <= row["address"] <= storage_hi) or (control_lo <= row["address"] <= control_hi)]
        if not any(row["address"] == 0x200000 and row["operation"] == "W" for row in sentinel_matches):
            raise ValueError("seeded SRAM storage write was not observed by the hook")
        if not any(row["address"] == 0x200000 and row["operation"] == "R" for row in sentinel_matches):
            raise ValueError("seeded SRAM storage read was not observed by the hook")
        if not any(control_lo <= row["address"] <= control_hi and row["operation"] == "W" for row in sentinel_matches):
            raise ValueError("seeded cartridge SRAM enable/control write was not observed by the hook")
        if not any(control_lo <= row["address"] <= control_hi and row["operation"] == "R" for row in sentinel_matches):
            raise ValueError("seeded cartridge SRAM enable/control read was not observed by the hook")
        if b"GWSENTINEL," not in sentinel_text:
            raise ValueError("SRAM/control sentinel Lua script did not finish")
        sentinel["sentinel_observations"] = {"sram_storage_reads": 1, "sram_storage_writes": 1,
                                             "sram_enable_control_reads": 1, "sram_enable_control_writes": 1}
        evidence["runs"].append(sentinel)
        evidence["calibration_trace"] = trace.trace_summary(sentinel_raw, sentinel_rows)

        gameplay, gameplay_raw, gameplay_rows, gameplay_text = capture_run(
            "bounded-gameplay-scenario", executable, rom, FIXTURE / "mame.lua", scenario["budget"]["hard_timeout_seconds"])
        evidence["runs"].append(gameplay)
        evidence["gameplay_trace"] = trace.trace_summary(gameplay_raw, gameplay_rows)
        observation_frame = scenario["budget"]["frames"]
        marker = re.search(rb"GWOBS,scenario=genewhip-independent-game-start-right-ntscu-v1,frame=" + str(observation_frame).encode() + rb",position=(\d+)", gameplay_text)
        if not marker:
            raise ValueError(f"bounded gameplay did not emit its frame-{observation_frame} observation")
        if not marker:
            raise ValueError("independent progression oracle observation is malformed")
        position = int(marker.group(1))
        oracle = scenario["oracle"]
        gameplay["oracle"] = {"address": oracle["address"], "observed_position": position,
                               "expected_minimum": oracle["expected_minimum"], "expected_maximum": oracle["expected_maximum"],
                               "passed": oracle["expected_minimum"] <= position <= oracle["expected_maximum"]}
        forbidden = scenario["forbidden_cartridge_sram"]
        storage_lo, storage_hi = int(forbidden["storage_start"], 16), int(forbidden["storage_end"], 16)
        control_lo, control_hi = int(forbidden["enable_control_start"], 16), int(forbidden["enable_control_end"], 16)
        violations = [row for row in gameplay_rows if storage_lo <= row["address"] <= storage_hi or control_lo <= row["address"] <= control_hi]
        gameplay["sram_accesses"] = {"storage": sum(storage_lo <= row["address"] <= storage_hi for row in gameplay_rows),
                                     "enable_control": sum(control_lo <= row["address"] <= control_hi for row in gameplay_rows)}
        evidence["coverage"]["trace_complete_and_ordered"] = True
        evidence["coverage"]["forbidden_candidate_accesses"] = gameplay["sram_accesses"]
        gameplay["expected_hardware_io"] = {key: value for key, value in access_counts(gameplay_rows).items() if key == "AS_PROGRAM:W"}
        if not gameplay["oracle"]["passed"]:
            evidence["coverage"]["runtime_progression"] = "fail"
            raise ValueError(f"candidate progression oracle failed: position {position}")
        evidence["coverage"]["runtime_progression"] = "pass"
        if violations:
            raise ValueError(f"candidate accessed forbidden cartridge SRAM storage/control: {len(violations)} bus rows")
        if not any(row["space"] == "AS_CPU_SPACE" and row["operation"] == "R" for row in gameplay_rows):
            raise ValueError("runtime CPU-space acknowledge sentinel did not reach the hook")
        if not any(row["space"] == "AS_PROGRAM" and row["operation"] == "R" and row["address"] == 0xa10002 and row["mem_mask"] & 0x00ff for row in gameplay_rows):
            raise ValueError("controller input read at odd byte lane A10003 did not reach aligned AS_PROGRAM hook")
        if not any(row["space"] == "AS_PROGRAM" and row["operation"] == "W" and row["address"] == 0xc00004 for row in gameplay_rows):
            raise ValueError("VDP control write did not reach AS_PROGRAM hook")
        if not any(row["space"] == "AS_PROGRAM" and row["operation"] == "R" and row["pc"] >= 0x200 for row in gameplay_rows):
            raise ValueError("program/opcode fetch sentinel did not reach AS_PROGRAM hook")
        if not all(gameplay_rows[index]["sequence"] < gameplay_rows[index + 1]["sequence"] for index in range(len(gameplay_rows) - 1)):
            raise ValueError("gameplay trace ordering check failed")
        evidence["outcome_counts"]["pass"] = 2
        evidence["status"] = "pass"
    except subprocess.TimeoutExpired as exc:
        evidence["errors"].append(f"bounded MAME subprocess timed out after {exc.timeout}s")
        evidence["outcome_counts"]["infrastructure_error"] = 1
        evidence["outcome_counts"]["unknown"] = 1
        evidence["runs"].append({"name": "bounded-run", "status": "infrastructure_error", "reason": evidence["errors"][-1]})
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        evidence["errors"].append(str(exc))
        if not evidence["runs"]:
            state = "infrastructure_error" if isinstance(exc, OSError) else "unknown"
            evidence["outcome_counts"][state] = 1
            evidence["outcome_counts"]["skipped"] = 1
            evidence["runs"].append({"name": "sram-route-sentinel", "status": state, "reason": str(exc)})
            evidence["runs"].append({"name": "bounded-gameplay-scenario", "status": "skipped", "reason": "prior sentinel/infrastructure gate did not pass"})
        else:
            if len(evidence["runs"]) >= 2 and evidence["runs"][1].get("name") == "bounded-gameplay-scenario":
                evidence["runs"][1]["status"] = "fail"
                evidence["runs"][1]["reason"] = str(exc)
            else:
                evidence["outcome_counts"]["unknown"] = 1
                evidence["runs"].append({"name": "bounded-gameplay-scenario", "status": "unknown", "reason": str(exc)})
            evidence["outcome_counts"]["pass"] = sum(run.get("status") == "pass" for run in evidence["runs"])
            evidence["outcome_counts"]["fail"] = sum(run.get("status") == "fail" for run in evidence["runs"])
            evidence["outcome_counts"]["unknown"] = max(evidence["outcome_counts"]["unknown"], sum(run.get("status") == "unknown" for run in evidence["runs"]))
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(f"{evidence['status'].upper()}: {evidence['outcome_counts']} ({len(evidence['errors'])} errors)")
    for error in evidence["errors"]:
        print(f"BLOCKED: {error}", file=sys.stderr)
    return 0 if evidence["status"] == "pass" else 1


import re

if __name__ == "__main__":
    raise SystemExit(main())
