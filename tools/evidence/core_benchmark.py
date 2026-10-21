#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce the qualified 720-field core benchmark and validate its evidence."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "fixtures/independent-game-v2/scenario.json"
ORACLE = ROOT / "fixtures/independent-game-v2/oracle.json"
ROM = ROOT / "fixtures/independent-game-v2/game.bin"
PROTOCOL = {"warmup_fields": 120, "measured_fields": 600, "fresh_runs": 5}
MODES = ((0, "sampled"), (0, "aggregate"), (1, "sampled"), (1, "aggregate"))
RUN_SCHEMA = "genewhip-core-benchmark-run-v1"
REPORT_SCHEMA = "genewhip-core-benchmark-v1"


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest(value):
    return sha_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def source_identity():
    paths = git("ls-files", "-z", "src", "include/genewhip", "CMakeLists.txt",
                "tools/evidence/core_benchmark.c", "tools/evidence/core_benchmark.py",
                "tests/evidence/benchmark_contract.py", "scripts/evidence/phase4_report.py",
                "tests/fixtures/phase4_game.py", "fixtures/manifest.json",
                "fixtures/independent-game-v2").split("\0")
    digest = hashlib.sha256()
    for relative in sorted(path for path in paths if path):
        digest.update(relative.encode() + b"\0")
        digest.update(Path(ROOT / relative).read_bytes())
    return digest.hexdigest()


def workload_identity():
    scenario = json.loads(SCENARIO.read_text())
    events = ((1, 128), (2, 0), (4, 8), (84, 0), (121, 16), (122, 0))
    input_log = "genewhip-input-log 1\n" + "".join(
        f"{field * 896040} pad 0 {mask:x}\n" for field, mask in events)
    return {"fixture_id": scenario["fixture_id"], "profile": "VA3-NTSC-U",
            "rom_sha256": scenario["rom"]["sha256"], "source_sha256": scenario["source"]["sha256"],
            "scenario_sha256": sha_file(SCENARIO), "oracle_sha256": sha_file(ORACLE),
            "input_sha256": sha_bytes(input_log.encode()), "audio_rate_hz": 48000,
            "audio_mix_id": 1, "audio_filter_id": 1}


def load_report_module():
    path = ROOT / "scripts/evidence/phase4_report.py"
    spec = importlib.util.spec_from_file_location("gw_phase4_report", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_identity(build):
    cache = Path(build) / "CMakeCache.txt"
    values = {}
    for line in cache.read_text(errors="replace").splitlines():
        if ":" in line and "=" in line:
            key, value = line.split("=", 1)[0].split(":", 1)[0], line.split("=", 1)[1]
            if key in {"CMAKE_BUILD_TYPE", "CMAKE_C_COMPILER", "CMAKE_C_COMPILER_ID",
                       "CMAKE_C_COMPILER_VERSION", "CMAKE_GENERATOR", "CMAKE_C_FLAGS",
                       "CMAKE_C_FLAGS_RELEASE", "CMAKE_EXE_LINKER_FLAGS_RELEASE",
                       "GENEWHIP_BUILD_DESKTOP", "GENEWHIP_TEST_HOOKS"}:
                values[key] = value
    compiler = Path(values.get("CMAKE_C_COMPILER", ""))
    generator = values.get("CMAKE_GENERATOR")
    build_rules = build_rules_file(build, generator)
    version = subprocess.run([str(compiler), "--version"], cwd=ROOT, check=True,
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.splitlines()[0]
    model_result = subprocess.run(["/usr/sbin/sysctl", "-n", "hw.model"], cwd=ROOT, check=False,
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    model = model_result.stdout.strip() if model_result.returncode == 0 else "unavailable in benchmark process"
    return {"cmake": values, "compiler_sha256": sha_file(compiler), "compiler_version_line": version,
            "build_rules_sha256": sha_file(build_rules),
            "host_system": platform.system(), "host_release": platform.release(),
            "host_macos_version": platform.mac_ver()[0], "host_machine": platform.machine(),
            "host_model": model,
            "build_configuration_sha256": sha_file(cache)}


def build_rules_file(build, generator):
    generator_files = {"Ninja": "build.ninja", "Unix Makefiles": "Makefile"}
    if generator not in generator_files:
        raise ValueError(f"unsupported benchmark build generator: {generator or 'unknown'}")
    build_rules = Path(build) / generator_files[generator]
    if not build_rules.is_file():
        raise ValueError(f"build rules for {generator} are missing: {build_rules.name}")
    return build_rules


def run_child(binary, mode, diagnostics, warmup, fields, rom=ROM):
    command = [str(binary), str(rom), mode, str(diagnostics), str(warmup), str(fields)]
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True)
    try:
        stdout, stderr = process.communicate(timeout=240)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise ValueError("benchmark child exceeded its 240-second wall timeout")
    if process.returncode:
        raise ValueError(f"benchmark child failed ({process.returncode}): {stderr.strip()[:500]}")
    try:
        row = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("benchmark child emitted malformed result JSON") from exc
    if row.get("schema") != RUN_SCHEMA or row.get("mode") != mode or row.get("diagnostics_enabled") is not bool(diagnostics):
        raise ValueError("benchmark child identity/mode mismatch")
    row["process_id"] = process.pid
    row["process_instance"] = str(uuid.uuid4())
    return row


def output_identity(run):
    return {"video": [(field.get("sequence"), field.get("end_tick"), field.get("width"),
                       field.get("height"), field.get("sha256"))
                      for field in run.get("video_fields", [])],
            "pcm_frames": run.get("pcm_frames"), "pcm_sha256": run.get("pcm_sha256"),
            "ram_sha256": run.get("ram_sha256"), "machine_sha256": run.get("machine_sha256")}


def percentile(values, rank):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(rank * len(ordered)) - 1)]


def workload_qualification(build):
    evidence = Path(build) / "evidence/phase4-gameplay.json"
    if not evidence.is_file():
        raise ValueError("exact six-case headless/desktop gameplay qualification is missing")
    observed = json.loads(evidence.read_text())
    module = load_report_module()
    expected = {"build_configuration_sha256": sha_file(Path(build) / "CMakeCache.txt"),
                "client_sha256": [sha_file(Path(build) / "tools/session/gw_headless"),
                                  sha_file(Path(build) / "tools/desktop/genewhip-desktop")]}
    problems = module.validate_gameplay(observed, qualification=True, expected_identity=expected)
    if problems:
        raise ValueError(f"gameplay qualification rejected: {problems}")
    sustained = next((case for case in observed["results"] if case["id"] == "sustained-play"), None)
    if not sustained or sustained.get("fields") != 720 or sustained.get("outcome") != "pass" or sustained.get("unsupported") != 0:
        raise ValueError("sustained workload qualification is not the exact passing 720-field scenario")
    return {"schema": observed["schema"], "fixture_id": observed["fixture_id"],
            "source_sha256": observed["source_sha256"], "rom_sha256": observed["rom_sha256"],
            "scenario_sha256": observed["scenario_sha256"], "oracle_sha256": observed["oracle_sha256"],
            "build_configuration_sha256": observed["build_configuration_sha256"],
            "clients": observed["clients"], "client_sha256": observed["client_sha256"],
            "denominator": observed["denominator"], "fields": observed["fields"],
            "sustained_fields": sustained["fields"], "sustained_outcome": sustained["outcome"]}


def run_protocol(build, quick):
    build = Path(build).resolve()
    binary = build / "gw_core_benchmark"
    if not binary.is_file():
        raise ValueError("gw_core_benchmark is missing from build")
    if platform.system() != "Darwin":
        raise ValueError("Darwin is required because ru_maxrss is reported in bytes on macOS")
    cmake = build_identity(build)
    cache = cmake["cmake"]
    validate_protocol_build(cache, quick)
    if not quick and cache.get("GENEWHIP_BUILD_DESKTOP") != "ON":
        raise ValueError("full benchmark requires same-build headless and desktop clients")
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT,
                           check=True, text=True, stdout=subprocess.PIPE).stdout
    dirty = [line[3:].strip() for line in status.splitlines()
             if line[3:].strip() and not line[3:].strip().startswith(".planning/")]
    if dirty and not quick:
        raise ValueError("source files must be committed before measuring: " + ", ".join(dirty))
    qualification = None if quick else workload_qualification(build)
    warmup, fields, repetitions = (2, 4, 1) if quick else (120, 600, 5)
    runs = []
    by_key = {}
    for repetition in range(repetitions):
        group = {}
        for diagnostics, mode in MODES:
            child = run_child(binary, mode, diagnostics, warmup, fields)
            if child["warmup_fields"] != warmup or child["measured_fields"] != fields or child["fields_completed"] != fields:
                raise ValueError("child completed-field denominator differs from requested work")
            if mode == "sampled" and len(child["field_ns"]) != fields:
                raise ValueError("sampled mode did not report one timing for every measured field")
            if mode == "aggregate" and (child.get("timed_samples") is not False or child["field_ns"]):
                raise ValueError("aggregate timing unexpectedly contains per-field samples")
            if child.get("last_stop_reason") != 5 or child.get("ticks_completed", 0) <= 0:
                raise ValueError("benchmark stopped or reported no completed emulated ticks")
            if len(child.get("video_fields", [])) != fields or any(
                    not isinstance(row.get("sha256"), str) or len(row["sha256"]) != 64
                    for row in child["video_fields"]):
                raise ValueError("complete measured video field denominator is missing")
            if child.get("process_ru_maxrss_bytes", 0) <= 0:
                raise ValueError("memory measurements are absent")
            if not quick:
                if child.get("core_owned_current_bytes", 0) <= 0:
                    raise ValueError("core-owned memory measurements are absent")
                if child.get("core_owned_peak_bytes", 0) < child.get("core_owned_current_bytes", 0):
                    raise ValueError("core-owned peak bytes below current bytes")
            key = (diagnostics, mode)
            group[key] = child
            by_key.setdefault(key, []).append(child)
            runs.append(child)
        baseline = output_identity(group[(0, "sampled")])
        if any(output_identity(run) != baseline for run in group.values()):
            raise ValueError("diagnostics or per-field observer mode changed measured machine/video/PCM output")
    if quick:
        return {"schema": REPORT_SCHEMA, "version": 1, "outcome": "pass", "qualification": False,
                "profile": "quick-contract", "protocol": {"warmup_fields": warmup,
                "measured_fields": fields, "fresh_runs": repetitions}, "runs": runs,
                "counts": {"fresh_processes": len(runs), "measured_fields_per_process": fields},
                "identities": workload_identity(), "reason": "bounded contract smoke only; not a sustained measurement"}

    sampled_rows = [run for (diag, mode), rows in by_key.items() if mode == "sampled" for run in rows]
    all_samples = [value for row in sampled_rows for value in row["field_ns"]]
    if len(all_samples) < 1000:
        raise ValueError("p99 exposure requires at least 1000 comparable field samples")
    mode_reports = []
    for diagnostics, mode in MODES:
        values = by_key[(diagnostics, mode)]
        latencies = [value for row in values for value in row["field_ns"]]
        mode_reports.append({"diagnostics_enabled": bool(diagnostics), "observer": mode,
            "runs": [{"process_id": row["process_id"], "process_instance": row["process_instance"],
                      "elapsed_ns": row["elapsed_ns"], "fields": row["fields_completed"],
                      "ticks": row["ticks_completed"], "actual_tick_start": row["actual_tick_start"],
                      "actual_tick_end": row["actual_tick_end"], "stop_reason": row["last_stop_reason"],
                      "fields_per_second": fields / (row["elapsed_ns"] / 1e9),
                      "field_latency_ns": ({"samples": fields, "median": int(statistics.median(row["field_ns"])),
                                            "p95": percentile(row["field_ns"], .95),
                                            "observed_maximum": max(row["field_ns"])} if mode == "sampled" else None),
                      "core_owned_current_bytes": row["core_owned_current_bytes"],
                      "core_owned_peak_bytes": row["core_owned_peak_bytes"],
                      "process_ru_maxrss_bytes": row["process_ru_maxrss_bytes"],
                      "diagnostic_records": row["diagnostic_records"],
                      "diagnostic_dropped": row["diagnostic_dropped"],
                      "output_identity": output_identity(row),
                      "field_ns": row["field_ns"]} for row in values],
            "aggregate_elapsed_ns_median": int(statistics.median(row["elapsed_ns"] for row in values)),
            "aggregate_elapsed_ns_total": sum(row["elapsed_ns"] for row in values),
            "aggregate_completed_fields": sum(row["fields_completed"] for row in values),
            "aggregate_completed_ticks": sum(row["ticks_completed"] for row in values),
            "aggregate_fields_per_second": fields * len(values) /
                (sum(row["elapsed_ns"] for row in values) / 1e9),
            "latency_ns": ({"samples": len(latencies), "median": int(statistics.median(latencies)),
                            "p95": percentile(latencies, .95), "p99": percentile(latencies, .99),
                            "observed_maximum": max(latencies)} if mode == "sampled" else None)})
    timing_pairs = []
    for diagnostics in (0, 1):
        samples = by_key[(diagnostics, "sampled")]
        aggregate = by_key[(diagnostics, "aggregate")]
        for index, (sampled, aggregated) in enumerate(zip(samples, aggregate), 1):
            timing_pairs.append({"diagnostics_enabled": bool(diagnostics), "run": index,
                "sampled_elapsed_ns": sampled["elapsed_ns"], "aggregate_elapsed_ns": aggregated["elapsed_ns"],
                "observer_overhead_percent": (sampled["elapsed_ns"] - aggregated["elapsed_ns"]) * 100.0 /
                    aggregated["elapsed_ns"]})
    diag_pairs = []
    for mode in ("sampled", "aggregate"):
        for index, (off, on) in enumerate(zip(by_key[(0, mode)], by_key[(1, mode)]), 1):
            diag_pairs.append({"observer": mode, "run": index,
                "disabled_elapsed_ns": off["elapsed_ns"], "enabled_elapsed_ns": on["elapsed_ns"],
                "throughput_delta_percent": (off["elapsed_ns"] - on["elapsed_ns"]) * 100.0 / off["elapsed_ns"],
                "capacity_records": 256, "enabled_records": on["diagnostic_records"],
                "enabled_dropped": on["diagnostic_dropped"],
                "output_equivalent": output_identity(off) == output_identity(on)})
    return {"schema": REPORT_SCHEMA, "version": 1, "outcome": "pass", "qualification": True,
        "profile": "sustained-qualified-workload", "source_revision": git("rev-parse", "HEAD"),
        "source_state": "clean implementation and fixture sources; planning-only local edits excluded",
        "build_identity": cmake, "benchmark_binary_sha256": sha_file(binary),
        "source_identity_sha256": source_identity(),
        "workload": workload_identity(), "qualification_evidence": qualification,
        "protocol": {**PROTOCOL, "processes_per_mode": 5, "fresh_process_per_run": True,
                      "reset_policy": "one fresh process and machine for each measured run; guest starts at power-on reset",
                      "drain_api": "gw_get_video_field plus one gw_audio_read with capacity 4096 frames per field",
                      "timed_window": "600 public gw_run_until field stops, video pixel copies, and bounded PCM drains; no formatting, hashes, or filesystem I/O",
                      "p99_minimum_comparable_field_samples": 1000},
        "resource_exposure": {"max_fresh_processes": 20, "max_parallel_processes": 1,
                              "wall_timeout_seconds_per_process": 240,
                              "preallocated_video_capture_bytes": 600 * 320 * 224 * 4,
                              "preallocated_pcm_capture_bytes": 600 * 4096 * 2 * 2,
                              "os_address_space_limit_enforced": False},
        "memory_units": {"core_owned": "bytes", "process_ru_maxrss": "bytes"},
        "rss_scope": "fresh-process macOS whole-process high-water; includes executable, libraries, allocator, and preallocated capture buffers; not steady RSS",
        "modes": mode_reports, "sampled_vs_aggregate_pairs": timing_pairs,
        "diagnostics_pairs": diag_pairs, "runs": runs,
        "counts": {"fresh_processes": len(runs), "measured_fields_per_process": fields,
                   "comparable_field_timing_samples": len(all_samples), "outputs_equivalent": True}}


def validate_protocol_build(cmake, quick):
    """Keep bounded public smoke build-agnostic; full measurement needs Release hooks."""
    if not quick and (cmake.get("CMAKE_BUILD_TYPE") != "Release" or
                      cmake.get("GENEWHIP_TEST_HOOKS") != "ON"):
        raise ValueError("full benchmark requires identified Release build with private hooks enabled")


def validate_report(report, qualification=False, expected=None):
    problems = []
    if not isinstance(report, dict) or report.get("schema") != REPORT_SCHEMA or report.get("version") != 1:
        return ["schema"]
    if report.get("outcome") != "pass": problems.append("outcome")
    if report.get("qualification") is not True:
        if qualification: problems.append("workload-qualification")
        if report.get("profile") != "quick-contract": problems.append("profile")
        return problems
    protocol = report.get("protocol", {})
    if any(protocol.get(key) != value for key, value in PROTOCOL.items()): problems.append("sample-count")
    if protocol.get("fresh_process_per_run") is not True: problems.append("process-reused")
    if protocol.get("processes_per_mode") != 5 or \
            protocol.get("reset_policy") != "one fresh process and machine for each measured run; guest starts at power-on reset" or \
            protocol.get("drain_api") != "gw_get_video_field plus one gw_audio_read with capacity 4096 frames per field" or \
            protocol.get("timed_window") != "600 public gw_run_until field stops, video pixel copies, and bounded PCM drains; no formatting, hashes, or filesystem I/O":
        problems.append("sample-count")
    if protocol.get("p99_minimum_comparable_field_samples") != 1000: problems.append("percentile-exposure")
    if report.get("memory_units") != {"core_owned": "bytes", "process_ru_maxrss": "bytes"}: problems.append("memory-units")
    if not str(report.get("rss_scope", "")).startswith("fresh-process macOS whole-process high-water"):
        problems.append("memory-units")
    exposure = report.get("resource_exposure", {})
    if exposure.get("max_fresh_processes") != 20 or exposure.get("max_parallel_processes") != 1 or \
            exposure.get("wall_timeout_seconds_per_process") != 240 or \
            exposure.get("preallocated_video_capture_bytes") != 600 * 320 * 224 * 4 or \
            exposure.get("preallocated_pcm_capture_bytes") != 600 * 4096 * 2 * 2 or \
            exposure.get("os_address_space_limit_enforced") is not False:
        problems.append("sample-count")
    revision = report.get("source_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision) or \
            report.get("source_state") != "clean implementation and fixture sources; planning-only local edits excluded":
        problems.append("stale-identity")
    if report.get("workload") != workload_identity(): problems.append("stale-identity")
    if not isinstance(report.get("build_identity"), dict) or not report.get("benchmark_binary_sha256"):
        problems.append("stale-identity")
    if report.get("source_identity_sha256") != source_identity(): problems.append("stale-identity")
    if expected:
        if (expected.get("source_revision") is not None and
                report.get("source_revision") != expected.get("source_revision")) or \
                report.get("build_identity", {}).get("build_configuration_sha256") != expected.get("build_configuration_sha256") or \
                report.get("benchmark_binary_sha256") != expected.get("benchmark_binary_sha256") or \
                report.get("source_identity_sha256") != expected.get("source_identity_sha256"):
            problems.append("stale-identity")
    qualified = report.get("qualification_evidence", {})
    workload = report.get("workload", {})
    build_hash = report.get("build_identity", {}).get("build_configuration_sha256")
    if not isinstance(qualified, dict) or qualified.get("sustained_fields") != 720 or \
            qualified.get("sustained_outcome") != "pass" or qualified.get("denominator") != 6 or \
            qualified.get("fields") != 840 or qualified.get("clients") != ["headless", "desktop"] or \
            not isinstance(qualified.get("client_sha256"), list) or len(qualified["client_sha256"]) != 2 or \
            any(not isinstance(value, str) or len(value) != 64 for value in qualified.get("client_sha256", [])) or \
            qualified.get("build_configuration_sha256") != build_hash or \
            any(qualified.get(key) != workload.get(key) for key in
                ("fixture_id", "source_sha256", "rom_sha256", "scenario_sha256", "oracle_sha256")):
        problems.append("workload-qualification")
    modes = report.get("modes", [])
    expected_modes = {(False, "sampled"), (False, "aggregate"), (True, "sampled"), (True, "aggregate")}
    actual_modes = {(row.get("diagnostics_enabled"), row.get("observer")) for row in modes if isinstance(row, dict)}
    if actual_modes != expected_modes: problems.append("mode-roster")
    pids, instances, outputs = [], [], []
    for row in modes:
        if not isinstance(row, dict): continue
        runs = row.get("runs", [])
        if len(runs) != 5: problems.append("sample-count")
        if row.get("observer") == "sampled":
            latency = row.get("latency_ns")
            if not isinstance(latency, dict) or latency.get("samples") != 3000 or latency.get("p99") is None:
                problems.append("percentile-exposure")
            samples = [value for run in runs for value in run.get("field_ns", [])]
            if len(samples) == 3000 and isinstance(latency, dict):
                if latency.get("median") != int(statistics.median(samples)) or \
                        latency.get("p95") != percentile(samples, .95) or \
                        latency.get("p99") != percentile(samples, .99) or \
                        latency.get("observed_maximum") != max(samples):
                    problems.append("timing-units")
        elif row.get("latency_ns") is not None: problems.append("percentile-exposure")
        for run in runs:
            if run.get("fields") != 600 or run.get("ticks") != 600 * 896040 or \
                    run.get("stop_reason") != 5 or run.get("elapsed_ns", 0) <= 0:
                problems.append("incomplete-samples")
            if row.get("observer") == "sampled" and len(run.get("field_ns", [])) != 600:
                problems.append("incomplete-samples")
            if row.get("observer") == "sampled" and (not isinstance(run.get("field_latency_ns"), dict) or
                    run["field_latency_ns"].get("samples") != 600 or run["field_latency_ns"].get("p99") is not None):
                problems.append("incomplete-samples")
            if row.get("observer") == "sampled" and isinstance(run.get("field_latency_ns"), dict):
                field_samples = run.get("field_ns", [])
                summary = run["field_latency_ns"]
                if len(field_samples) == 600 and (summary.get("median") != int(statistics.median(field_samples)) or
                        summary.get("p95") != percentile(field_samples, .95) or
                        summary.get("observed_maximum") != max(field_samples)):
                    problems.append("timing-units")
            if row.get("observer") == "aggregate" and run.get("field_ns"):
                problems.append("incomplete-samples")
            if row.get("observer") == "aggregate" and run.get("field_latency_ns") is not None:
                problems.append("incomplete-samples")
            pids.append(run.get("process_id")); instances.append(run.get("process_instance"))
            output = run.get("output_identity")
            video = output.get("video", []) if isinstance(output, dict) else []
            if not isinstance(output, dict) or len(video) != 600 or \
                    not all(isinstance(value, str) and len(value) == 64 for value in
                            (output.get("pcm_sha256"), output.get("ram_sha256"), output.get("machine_sha256"))) or \
                    not isinstance(output.get("pcm_frames"), int) or output["pcm_frames"] <= 0:
                problems.append("incomplete-samples")
            if video:
                if any(not isinstance(field, (list, tuple)) or len(field) != 5 for field in video):
                    problems.append("incomplete-samples")
                elif ([field[0] for field in video] != list(range(120, 720)) or
                      any(field[2] not in (256, 320) or field[3] != 224 or
                          not isinstance(field[4], str) or len(field[4]) != 64 for field in video)):
                    problems.append("incomplete-samples")
            outputs.append(output)
            if run.get("process_ru_maxrss_bytes", 0) <= 0 or run.get("core_owned_current_bytes", 0) <= 0 or \
                    run.get("core_owned_peak_bytes", 0) < run.get("core_owned_current_bytes", 0):
                problems.append("memory-units")
            if row.get("diagnostics_enabled") and run.get("diagnostic_records") != 256:
                problems.append("diagnostic-capacity")
            if not row.get("diagnostics_enabled") and (run.get("diagnostic_records") != 0 or
                    run.get("diagnostic_dropped") != 0):
                problems.append("diagnostic-capacity")
            if not isinstance(run.get("diagnostic_dropped"), int) or run["diagnostic_dropped"] < 0:
                problems.append("diagnostic-capacity")
    if None in pids or len(set(pids)) != len(pids) or len(set(instances)) != len(instances):
        problems.append("process-reused")
    if outputs and any(value != outputs[0] for value in outputs[1:]): problems.append("output-divergence")
    if len(report.get("sampled_vs_aggregate_pairs", [])) != 10 or len(report.get("diagnostics_pairs", [])) != 10:
        problems.append("sample-count")
    if any(pair.get("output_equivalent") is not True for pair in report.get("diagnostics_pairs", [])):
        problems.append("output-divergence")
    if report.get("counts", {}).get("comparable_field_timing_samples") != 6000:
        problems.append("percentile-exposure")
    return sorted(set(problems))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--quick", action="store_true", help="bounded contract smoke; never a sustained result")
    args = parser.parse_args(argv)
    try:
        report = run_protocol(args.build, args.quick)
        expected = {"source_revision": git("rev-parse", "HEAD"),
                    "build_configuration_sha256": report.get("build_identity", {}).get("build_configuration_sha256"),
                    "benchmark_binary_sha256": report.get("benchmark_binary_sha256"),
                    "source_identity_sha256": source_identity()}
        problems = validate_report(report, qualification=not args.quick,
                                   expected=None if args.quick else expected)
        if problems: raise ValueError("production benchmark validator rejected report: " + ", ".join(problems))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print("core benchmark: %s; processes=%d; completed_fields=%d each" %
              (report["profile"], report["counts"]["fresh_processes"], report["protocol"]["measured_fields"]))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print("core benchmark: REJECT: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
