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
import resource
import tempfile
import time
import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "fixtures/independent-game-v2/scenario.json"
ORACLE = ROOT / "fixtures/independent-game-v2/oracle.json"
ROM = ROOT / "fixtures/independent-game-v2/game.bin"
PROTOCOL = {"warmup_fields": 120, "measured_fields": 600, "fresh_runs": 5}
MODES = ((0, "sampled"), (0, "aggregate"), (1, "sampled"), (1, "aggregate"))
RUN_SCHEMA = "genewhip-core-benchmark-run-v1"
REPORT_SCHEMA = "genewhip-core-benchmark-v1"
V02_REPORT_SCHEMA = "genewhip-core-benchmark-v2"
PUBLIC_PERFORMANCE_SCHEMA = "genewhip.public-performance.v1"
WORKLOADS = ("control", "recursion94", "tank-battle")
MAX_CAPTURE_BYTES = 2 * 1024 * 1024 * 1024
_ACTIVE_BATCH_START = None
_ACTIVE_BATCH_LIMIT_SECONDS = 43200
_ACTIVE_QUALIFICATION_START = None
_ACTIVE_RUNTIME_LIMIT_SECONDS = 64800
_ACTIVE_JOURNAL = None


def enforce_batch_wall_limit():
    now = time.time()
    if (_ACTIVE_QUALIFICATION_START is not None
            and now - _ACTIVE_QUALIFICATION_START >= _ACTIVE_RUNTIME_LIMIT_SECONDS):
        raise ValueError("qualification runtime partition exceeded its shared deadline")
    if (_ACTIVE_BATCH_START is not None and
            time.monotonic() - _ACTIVE_BATCH_START >= _ACTIVE_BATCH_LIMIT_SECONDS):
        raise ValueError("benchmark sub-batch exceeded its 12-hour hard wall limit")


def qualification_runtime_remaining(scope, started_at, now=None):
    """Compute the remaining runtime partition from immutable Actions run creation time."""
    batch = scope.get("qualification_batch") if isinstance(scope, dict) else None
    runtime = batch.get("runtime_wall_seconds") if isinstance(batch, dict) else None
    if not isinstance(runtime, int) or isinstance(runtime, bool) or runtime <= 0:
        raise ValueError("qualification-runtime-partition-invalid")
    try:
        start = datetime.datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        current = (datetime.datetime.now(datetime.timezone.utc) if now is None else
                   datetime.datetime.fromisoformat(now.replace("Z", "+00:00")))
        if start.tzinfo is None or current.tzinfo is None:
            raise ValueError("timezone")
        elapsed = (current - start).total_seconds()
    except (AttributeError, ValueError, TypeError):
        raise ValueError("qualification-runtime-clock-invalid") from None
    if elapsed < 0:
        raise ValueError("qualification-runtime-clock-invalid")
    remaining = runtime - elapsed
    if remaining <= 0:
        raise ValueError("qualification-runtime-partition-deadline-exhausted")
    return remaining


def bounded_child_limits(limits, *, child_cap=None):
    """Clamp one launch to its child cap and both active qualification deadlines."""
    enforce_batch_wall_limit()
    bounded = dict(limits)
    candidates = [float(limits["wall_seconds"])]
    if child_cap is not None:
        candidates.append(float(child_cap))
    if _ACTIVE_QUALIFICATION_START is not None:
        remaining = (_ACTIVE_RUNTIME_LIMIT_SECONDS -
                     (time.time() - _ACTIVE_QUALIFICATION_START))
        candidates.append(remaining)
    if _ACTIVE_BATCH_START is not None:
        remaining = (_ACTIVE_BATCH_LIMIT_SECONDS -
                     (time.monotonic() - _ACTIVE_BATCH_START))
        candidates.append(remaining)
    timeout = min(candidates)
    if timeout <= 0:
        raise ValueError("benchmark child has no shared deadline remaining")
    bounded["wall_seconds"] = timeout
    return timeout, bounded


class MeasurementJournal:
    """Persist each child's launch, exit, resource receipt and partial evidence."""
    def __init__(self, path, attempt):
        self.path = Path(path)
        self.data = {"schema": "genewhip-v02-benchmark-attempt-v1", "attempt": attempt,
            "status": "running", "children": [], "partial_report": None, "failure": None,
            "started_unix_seconds": int(time.time())}
        self._flush()

    def _flush(self):
        self.data["observed_exposure"] = {
            "child_launch_attempts": len(self.data["children"]),
            "child_process_starts": sum(1 for child in self.data["children"] if
                (child.get("resource_receipt") or {}).get("pid") is not None or
                child.get("observed", {}).get("process_id") is not None),
            "timed_child_starts": sum(1 for child in self.data["children"]
                if child.get("repetition", 0) and ((child.get("resource_receipt") or {}).get("pid") is not None or
                    child.get("observed", {}).get("process_id") is not None)),
            "untimed_child_starts": sum(1 for child in self.data["children"]
                if not child.get("repetition", 0) and ((child.get("resource_receipt") or {}).get("pid") is not None or
                    child.get("observed", {}).get("process_id") is not None))}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            stream.write(json.dumps(self.data, sort_keys=True, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)

    def launch(self, workload, mode, diagnostics, repetition, argv, *, fields, warmup):
        executable = Path(argv[0]) if argv else None
        if executable and executable.is_absolute():
            try:
                executable_label = str(executable.resolve().relative_to(ROOT))
            except ValueError:
                executable_label = executable.name
        else:
            executable_label = str(executable) if executable else ""
        safe_argv = []
        for argument in map(str, argv):
            candidate = Path(argument)
            if candidate.is_absolute():
                try:
                    argument = str(candidate.resolve().relative_to(ROOT))
                except ValueError:
                    argument = candidate.name
            safe_argv.append(argument)
        entry = {"index": len(self.data["children"]) + 1, "status": "launched",
            "workload": workload, "observer": mode, "diagnostics_enabled": bool(diagnostics),
            "repetition": repetition, "fields": fields, "warmup_fields": warmup,
            "argv_sha256": sha_bytes(json.dumps(list(map(str, argv)), separators=(",", ":")).encode()),
            "argv": safe_argv, "executable": executable_label,
            "executable_sha256": (sha_file(executable) if executable and executable.is_file() else None),
            "launch_unix_seconds": int(time.time()), "exit_code": None, "resource_receipt": None}
        self.data["children"].append(entry)
        self._flush()
        return entry

    def finish(self, entry, *, exit_code, receipt, row=None, stderr=None, stdout=None):
        success = exit_code == 0 and isinstance(receipt, dict) and \
            receipt.get("process_group_cleanup") == "confirmed" and not receipt.get("bound_violation")
        status = "launch-failed" if isinstance(receipt, dict) and receipt.get("status") == "launch-failed" else \
            ("completed" if success else "failed")
        entry.update({"status": status, "exit_code": exit_code,
            "resource_receipt": receipt, "completed_unix_seconds": int(time.time())})
        if stderr is not None:
            entry["stderr"] = str(stderr)[:4000]
        if stdout is not None:
            entry["stdout_sha256"] = sha_bytes(str(stdout).encode())
            entry["stdout_bytes"] = len(str(stdout).encode())
        if isinstance(row, dict):
            entry["observed"] = {key: row.get(key) for key in
                ("process_id", "process_ru_maxrss_bytes", "elapsed_ns", "fields_completed",
                 "ticks_completed", "route_status", "untimed", "output_identity") if key in row}
        self._flush()

    def set_partial_report(self, report):
        self.data["partial_report"] = report
        self._flush()

    def fail(self, reason):
        self.data["status"] = "non-qualifying"
        self.data["failure"] = str(reason)
        self.data["finished_unix_seconds"] = int(time.time())
        self._flush()

    def complete(self, report):
        self.data["status"] = "complete"
        self.data["failure"] = None
        self.data["partial_report"] = report
        self.data["finished_unix_seconds"] = int(time.time())
        self._flush()


def checked_capture_size(fields, pcm_frames_per_field=4096, metadata_bytes_per_field=256,
                        fixed_capture_bytes=4096 * 40 + 64 * 24 + 4096):
    """Return checked video, PCM, and total capture byte capacities."""
    values = (fields, pcm_frames_per_field, metadata_bytes_per_field)
    if any(type(value) is not int or value <= 0 for value in values):
        raise ValueError("capture dimensions must be positive integers")
    limit = min(sys.maxsize, MAX_CAPTURE_BYTES)
    pixel_unit = 320 * 224 * 4
    pcm_unit = pcm_frames_per_field * 2 * 2
    if fields > limit // pixel_unit or fields > limit // pcm_unit:
        raise ValueError("capture-size-overflow")
    pixels, pcm = fields * pixel_unit, fields * pcm_unit
    metadata = fields * metadata_bytes_per_field
    if pixels > limit - pcm or pixels + pcm > limit - metadata:
        raise ValueError("capture-size-limit")
    total = pixels + pcm + metadata
    if fixed_capture_bytes < 0 or total > limit - fixed_capture_bytes:
        raise ValueError("capture-size-limit")
    return pixels, pcm, total + fixed_capture_bytes


def measurement_roster():
    """Return the exact serial measurement and untimed-reference roster."""
    timed = [{"workload": workload, "diagnostics_enabled": diagnostics,
              "observer": observer, "repetition": repetition}
             for workload in WORKLOADS
             for diagnostics, observer in ((False, "sampled"), (False, "aggregate"),
                                            (True, "sampled"), (True, "aggregate"))
             for repetition in range(1, 6)]
    return {"timed": timed, "untimed": [{"workload": workload} for workload in WORKLOADS]}


def summarize_performance_samples(values, *, sample_kind, host_id, workload_id):
    """Summarize comparable samples without pooling workload or host identities."""
    if isinstance(host_id, (list, tuple, set)) or isinstance(workload_id, (list, tuple, set)):
        raise ValueError("samples must have one host and workload identity")
    if not isinstance(host_id, str) or not host_id or not isinstance(workload_id, str) or not workload_id:
        raise ValueError("samples must have one host and workload identity")
    if sample_kind not in ("whole_run", "field"):
        raise ValueError("unknown performance sample kind")
    samples = list(values)
    if not samples or any(type(value) is not int or value <= 0 for value in samples):
        raise ValueError("performance samples must be positive integers")
    p99 = percentile(samples, .99) if sample_kind == "field" and len(samples) >= 1000 else None
    return {"samples": len(samples), "median": int(statistics.median(samples)),
            "p95": percentile(samples, .95), "observed_maximum": max(samples),
            "p99": p99, "p99_reason": None if p99 is not None else
            "requires 1000 comparable field samples",
            "sample_kind": sample_kind, "host_id": host_id, "workload_id": workload_id}


def workload_spec(workload, scope):
    if workload == "all":
        return [workload_spec(name, scope) for name in ("control", "recursion94", "tank-battle")]
    limits = scope.get("workload", {}) if isinstance(scope, dict) else {}
    if workload == "control":
        if 120 + 600 > limits.get("max_fields", 0):
            raise ValueError("control workload exceeds declared execution field cap")
        return {"workload": workload, "warmup_fields": 120, "completed_fields": 600,
                "expected_active_steps": None, "fresh_runs": 5}
    if workload not in ("recursion94", "tank-battle"):
        raise ValueError("unsupported benchmark workload")
    fields = 3631 if workload == "recursion94" else 4196
    if fields > limits.get("max_fields", 0):
        raise ValueError("workload exceeds declared execution field cap")
    return {"workload": workload, "warmup_fields": 0, "completed_fields": fields,
            "expected_active_steps": 3600 if workload == "recursion94" else None, "fresh_runs": 5}


def validate_workload_run(row, spec):
    if not isinstance(row, dict) or row.get("fields_completed", row.get("completed_fields")) != spec["completed_fields"] or \
            row.get("warmup_fields") != spec["warmup_fields"] or row.get("route_status", 0) != 0 or \
            (not row.get("untimed") and row.get("elapsed_ns", 0) <= 0):
        raise ValueError("incomplete-workload-run")
    ticks = row.get("ticks_completed", row.get("terminal_tick", 0))
    tick_start, tick_end = row.get("actual_tick_start", 0), row.get("actual_tick_end", row.get("terminal_tick", 0))
    if type(ticks) is not int or ticks <= 0 or type(tick_start) is not int or type(tick_end) is not int or tick_end <= tick_start:
        raise ValueError("invalid-workload-ticks")
    identity = row.get("output_identity")
    if spec.get("workload") == "control":
        valid_identity = (isinstance(identity, dict) and
            set(identity) == {"video", "pcm_frames", "pcm_sha256", "ram_sha256", "machine_sha256"} and
            isinstance(identity.get("video"), list) and bool(identity["video"]) and
            all(isinstance(identity.get(key), str) and len(identity[key]) == 64
                for key in ("pcm_sha256", "ram_sha256", "machine_sha256")) and
            type(identity.get("pcm_frames")) is int and identity["pcm_frames"] > 0)
    else:
        valid_identity = (isinstance(identity, dict) and all(not isinstance(identity.get(key), bool) and
            isinstance(identity.get(key), str) and len(identity[key]) == 64
            for key in ("ram_sha256", "cpu_sha256", "controller_sha256", "video_sha256", "pcm_sha256")))
    if not valid_identity:
        raise ValueError("workload-output-identity")
    if not row.get("untimed") and identity != row.get("untimed_output_identity"):
        raise ValueError("workload-output-divergence")
    if spec["expected_active_steps"] is not None and row.get("completed_steps") != spec["expected_active_steps"]:
        raise ValueError("workload-step-denominator")
    if "capture_capacity_bytes" in row and (type(row["capture_capacity_bytes"]) is not int or
            row["capture_capacity_bytes"] <= 0 or row["capture_capacity_bytes"] > MAX_CAPTURE_BYTES):
        raise ValueError("workload-capture-capacity")
    if "timer_boundary" in row and row["timer_boundary"] != \
            "first public guest boundary through terminal observation and PCM drain":
        raise ValueError("workload-timer-boundary")
    return True


def validate_control_reference(row, limits):
    if row.get("untimed") is not True or row.get("elapsed_ns") != 0 or \
            row.get("fields_completed") != 600 or row.get("warmup_fields") != 120:
        raise ValueError("control-reference-window")
    if row.get("rss_unit_source") != "Darwin getrusage(2) ru_maxrss bytes" or \
            type(row.get("process_ru_maxrss_bytes")) is not int or \
            row["process_ru_maxrss_bytes"] <= 0 or row["process_ru_maxrss_bytes"] > limits["max_rss_bytes"]:
        raise ValueError("control-reference-rss-provenance")
    receipt = row.get("resource_receipt", {})
    if receipt.get("process_group_cleanup") != "confirmed" or receipt.get("bound_violation"):
        raise ValueError("control-reference-child-cleanup")
    if not output_identity(row).get("video") or not row.get("machine_sha256") or not row.get("pcm_sha256"):
        raise ValueError("control-reference-output")
    return True


def run_workload(build, workload, scope_path, out, *, untimed=False, contracts_only=False,
                 source_sha=None):
    """Run an identified v2 route roster through the existing bounded child launcher."""
    build, scope_path, out = Path(build).resolve(strict=True), Path(scope_path).resolve(strict=True), Path(out).resolve()
    v02 = load_v02_launcher()
    scope, limits = v02.validate_execution_scope(scope_path, "smoke")
    global _ACTIVE_BATCH_START, _ACTIVE_BATCH_LIMIT_SECONDS, _ACTIVE_QUALIFICATION_START
    global _ACTIVE_RUNTIME_LIMIT_SECONDS, _ACTIVE_JOURNAL
    if not contracts_only:
        started_at = os.environ.get("GENEWHIP_QUALIFICATION_STARTED_AT")
        if started_at:
            try:
                _ACTIVE_QUALIFICATION_START = datetime.datetime.fromisoformat(
                    started_at.replace("Z", "+00:00")).timestamp()
            except ValueError as error:
                raise ValueError("qualification-batch-start-invalid") from error
        else:
            started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            _ACTIVE_QUALIFICATION_START = time.time()
        _ACTIVE_RUNTIME_LIMIT_SECONDS = scope["qualification_batch"]["runtime_wall_seconds"]
        _ACTIVE_BATCH_START = time.monotonic()
        _ACTIVE_BATCH_LIMIT_SECONDS = min(scope["qualification_batch"]["benchmark_sub_batch_seconds"],
            qualification_runtime_remaining(scope, started_at))
        prior_attempts = sorted(out.parent.glob("attempt-*.json"))
        attempt = len(prior_attempts) + 1
        _ACTIVE_JOURNAL = MeasurementJournal(out.parent / f"attempt-{attempt:02d}.json", attempt)
    limits = scope.get("per_child_limits", {})
    if scope.get("workload", {}).get("serial_children") is not True:
        raise ValueError("serial-child-policy")
    if limits.get("max_capture_bytes", 0) > MAX_CAPTURE_BYTES or limits.get("max_rss_bytes", 0) > 4 * 1024**3:
        raise ValueError("declared-child-cap-exceeds-plan")
    if not any(out.is_relative_to((ROOT / root).resolve(strict=True)) for root in scope.get("owned_roots", [])):
        raise ValueError("output-outside-owned-scope")
    if platform.system() != "Darwin":
        raise ValueError("Darwin getrusage(2) ru_maxrss byte provenance is unverified on this platform")
    identity = source_identity()
    if source_sha is not None and source_sha != identity:
        raise ValueError("source-identity-mismatch")
    if workload == "control" or (workload == "all" and contracts_only):
        if contracts_only:
            return {"schema": "genewhip-core-benchmark-contract-plan-v2", "workload": workload,
                    "qualification": False, "child_starts": 0,
                    "planned_roster": [{"workload": row["workload"],
                        "completed_fields": row["completed_fields"], "warmup_fields": row["warmup_fields"]}
                        for row in workload_spec(workload, scope)], "protocol": PROTOCOL,
                    "source_identity_sha256": identity, "scope_id": scope["scope_id"]}
    if workload == "control":
        if contracts_only:
            return run_protocol(build, quick=False, v02_control=True)
        control = run_protocol(build, quick=False, v02_control=True)
        reference = run_control_reference(build, scope, limits)
        timed = normalize_control_rows(control)
        for row in timed:
            row.update({"workload": "control", "fields_completed": row.get("fields"),
                "warmup_fields": 120, "ticks_completed": row.get("ticks"),
                "last_stop_reason": row.get("stop_reason"), "untimed": False,
                "output_identity": output_identity(row),
                "untimed_output_identity": reference["output_identity"]})
        build_info = control["build_identity"]
        workload_report = {"schema": "genewhip.v02-workload-benchmark-v1", "workload": workload,
            "outcome": "pass", "qualification": True, "source_identity_sha256": identity,
            "source_revision": control["source_revision"], "head_sha": control["source_revision"],
            "base_sha": workflow_base_sha(control["source_revision"]), "scope_id": scope["scope_id"],
            "scope_sha256": hashlib.sha256(scope_path.read_bytes()).hexdigest(),
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
            "build_identity": build_info,
            "host_identity": {key: build_info[key] for key in
                ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")},
            "timed_runs": timed, "untimed_reference": reference,
            "counts": {"timed_children": 20, "untimed_references": 1,
                "process_starts": 21, "timed_samples_per_mode": 5}}
        problems = validate_workload_report(workload_report, workload, identity, scope["scope_id"])
        if problems:
            raise ValueError("control workload validator rejected report: " + ", ".join(problems))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(workload_report, sort_keys=True, indent=2) + "\n")
        if _ACTIVE_JOURNAL:
            _ACTIVE_JOURNAL.complete(workload_report)
        _ACTIVE_BATCH_START = None; _ACTIVE_QUALIFICATION_START = None; _ACTIVE_JOURNAL = None
        return workload_report
    if workload == "all" and untimed:
        raise ValueError("--untimed cannot represent the measured legacy control warmup/field split")
    control_benchmark = None
    if workload == "all":
        control_benchmark = run_protocol(build, quick=False, v02_control=True)
    selected = ("recursion94", "tank-battle") if workload == "all" else (workload,)
    specs = [workload_spec(name, scope) for name in selected]
    capture = max(checked_capture_size(spec["completed_fields"])[2] for spec in specs)
    available = v02.available_memory_bytes()
    v02.require_memory_reserve(available, capture + 512 * 1024 * 1024)
    report = {"schema": V02_REPORT_SCHEMA, "version": 2, "workload": workload,
        "qualification": False, "source_identity_sha256": identity, "scope_id": scope["scope_id"],
        "capture_capacity_bytes": capture, "max_child_rss_bytes": limits["max_rss_bytes"],
        "memory_available_bytes_before_launch": available, "serial_children": True, "runs": [],
        "untimed_references": []}
    if control_benchmark is not None:
        report["control_benchmark"] = control_benchmark
        if _ACTIVE_JOURNAL:
            _ACTIVE_JOURNAL.set_partial_report(report)
    if contracts_only:
        report["planned_roster"] = [{"workload": spec["workload"], "completed_fields": spec["completed_fields"],
            "warmup_fields": spec["warmup_fields"], "fresh_runs": spec["fresh_runs"]} for spec in specs]
        report["child_starts"] = 0
        return report
    routes_module = load_phase6_routes()
    mapping = json.loads((ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json").read_text())
    routes = routes_module.compile_routes(mapping, "public-core")["routes"]
    route_contract = load_route_contract()
    hooks_on = build_identity(build)["cmake"].get("GENEWHIP_TEST_HOOKS") == "ON"
    with tempfile.TemporaryDirectory(prefix="gw-bench-v02-", dir=build / "v02") as scratch_name:
        scratch = Path(scratch_name)
        for spec in specs:
            title = spec["workload"]
            route = next(row for row in routes if row["fixture"] == title and row["case"]["id"] == "full-route")
            call_limit = (scope["workload"].get("tank_route_max_calls", limits["max_calls"])
                          if title == "tank-battle" else limits["max_calls"])
            plan_bytes, _ = routes_module.lower_route(route, call_limit,
                mapping if title == "recursion94" else None, client="public-core")
            plan_path = scratch / f"{title}.gwrc"
            plan_path.write_bytes(plan_bytes)
            rom = ROOT / routes_module.SOURCES[title][3]
            if untimed:
                raise ValueError("--untimed is a reference run and cannot replace the timed workload roster")

            def run_route(mode, diagnostics, reference=False, repetition=0):
                enforce_batch_wall_limit()
                command = [str(build / "gw_core_benchmark"), str(rom), mode,
                    str(int(diagnostics)), "0", str(spec["completed_fields"]),
                    "--route-plan", str(plan_path), "--route-capture-limit",
                    str(limits["max_capture_bytes"])]
                if reference:
                    command.append("--untimed")
                receipt = []
                v02.require_memory_reserve(v02.available_memory_bytes(), capture + 512 * 1024 * 1024)
                journal_entry = (_ACTIVE_JOURNAL.launch(title, mode, diagnostics, repetition,
                    command, fields=spec["completed_fields"], warmup=0) if _ACTIVE_JOURNAL else None)
                try:
                    timeout, child_limits = bounded_child_limits(limits)
                    result = _run_journaled_client(route_contract, build / "gw_core_benchmark", command, receipt, journal_entry,
                        report=scratch / f"{title}-{repetition}-{mode}-{int(diagnostics)}.json",
                        timeout=timeout, cwd=scratch, limits=child_limits, scratch_roots=(scratch,))
                except BaseException:
                    if _ACTIVE_JOURNAL and journal_entry:
                        _ACTIVE_JOURNAL.finish(journal_entry, exit_code=1,
                            receipt=receipt[0] if receipt else None)
                    raise
                if _ACTIVE_JOURNAL and journal_entry:
                    _ACTIVE_JOURNAL.finish(journal_entry, exit_code=result.returncode,
                        receipt=receipt[0] if receipt else None)
                enforce_batch_wall_limit()
                if (result.returncode or len(receipt) != 1 or
                        receipt[0].get("process_group_cleanup") != "confirmed" or receipt[0].get("bound_violation")):
                    raise ValueError(f"{title} child failed: returncode={result.returncode} "
                        f"receipt={receipt} stderr={result.stderr[-2000:]}")
                row = json.loads(result.stdout)
                row["resource_receipt"] = receipt[0]
                row["process_id"] = receipt[0]["pid"]
                row["process_instance"] = str(uuid.uuid4())
                row["output_identity"] = row.get("output_identity")
                if _ACTIVE_JOURNAL and journal_entry:
                    _ACTIVE_JOURNAL.finish(journal_entry, exit_code=result.returncode,
                        receipt=receipt[0], row=row, stderr=result.stderr, stdout=result.stdout)
                if (row.get("rss_unit_source") != "Darwin getrusage(2) ru_maxrss bytes" or
                        type(row.get("process_ru_maxrss_bytes")) is not int or
                        row["process_ru_maxrss_bytes"] > limits["max_rss_bytes"]):
                    raise ValueError(f"{title} process RSS provenance or cap violated")
                if row.get("capture_capacity_bytes") != checked_capture_size(spec["completed_fields"])[2]:
                    raise ValueError(f"{title} reported capture allocation differs from checked capacity")
                if hooks_on:
                    if (type(row.get("core_owned_current_bytes")) is not int or
                            type(row.get("core_owned_peak_bytes")) is not int or
                            row["core_owned_peak_bytes"] < row["core_owned_current_bytes"] or
                            row.get("allocation_unavailable_reason") is not None):
                        raise ValueError(f"{title} omitted test-hook core allocation facts")
                elif (row.get("core_owned_current_bytes") is not None or
                        row.get("core_owned_peak_bytes") is not None or
                        row.get("allocation_calls_total") is not None or
                        row.get("allocation_unavailable_reason") != "test-hooks-disabled"):
                    raise ValueError(f"{title} fabricated unavailable core allocation facts")
                if reference and (row.get("untimed") is not True or row.get("elapsed_ns") != 0):
                    raise ValueError(f"{title} reference is not untimed")
                if not reference and row.get("untimed") is True:
                    raise ValueError(f"{title} timed sample was marked untimed")
                return row

            baseline = run_route("aggregate", False, reference=True)
            validate_workload_run(baseline, spec)
            baseline["workload"] = title
            report["untimed_references"].append(baseline)
            if _ACTIVE_JOURNAL:
                _ACTIVE_JOURNAL.set_partial_report(report)
            repetitions = 1 if contracts_only else spec["fresh_runs"]
            for diagnostics, mode in MODES:
                for repetition in range(1, repetitions + 1):
                    row = run_route(mode, diagnostics, repetition=repetition)
                    row["workload"] = title
                    row["diagnostics_enabled"] = bool(diagnostics)
                    row["observer"] = mode
                    row["repetition"] = repetition
                    row["untimed_output_identity"] = baseline["output_identity"]
                    validate_workload_run(row, spec)
                    if row["output_identity"] != baseline["output_identity"]:
                        raise ValueError(f"{title} timed route diverged from untimed correctness reference")
                    if mode == "sampled" and (row.get("timed_samples") is not True or
                            len(row.get("field_ns", [])) != spec["completed_fields"] or
                            any(type(value) is not int or value <= 0 for value in row["field_ns"])):
                        raise ValueError(f"{title} sampled timing contract failed")
                    if mode == "aggregate" and (row.get("timed_samples") is not False or row.get("field_ns")):
                        raise ValueError(f"{title} aggregate mode exposed sampled timing")
                    report["runs"].append(row)
                    if _ACTIVE_JOURNAL:
                        _ACTIVE_JOURNAL.set_partial_report(report)
    if workload in ("recursion94", "tank-battle") and not contracts_only:
        reference = next(row for row in report["untimed_references"] if row.get("workload") == workload)
        timed = [row for row in report["runs"] if row.get("workload") == workload]
        build_info = build_identity(build)
        workload_report = {"schema": "genewhip.v02-workload-benchmark-v1", "workload": workload,
            "outcome": "pass", "qualification": True, "source_identity_sha256": identity,
            "source_revision": git("rev-parse", "HEAD"), "head_sha": git("rev-parse", "HEAD"),
            "base_sha": workflow_base_sha(git("rev-parse", "HEAD")), "scope_id": scope["scope_id"],
            "scope_sha256": hashlib.sha256(scope_path.read_bytes()).hexdigest(),
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
            "build_identity": build_info,
            "host_identity": {key: build_info[key] for key in
                ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")},
            "timed_runs": timed, "untimed_reference": reference,
            "counts": {"timed_children": 20, "untimed_references": 1,
                "process_starts": 21, "timed_samples_per_mode": 5}}
        problems = validate_workload_report(workload_report, workload, identity, scope["scope_id"])
        if problems:
            raise ValueError(f"{workload} workload validator rejected report: " + ", ".join(problems))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(workload_report, sort_keys=True, indent=2) + "\n")
        if _ACTIVE_JOURNAL:
            _ACTIVE_JOURNAL.complete(workload_report)
        _ACTIVE_BATCH_START = None; _ACTIVE_QUALIFICATION_START = None; _ACTIVE_JOURNAL = None
        return workload_report
    if control_benchmark is not None and not contracts_only:
        control_ref = run_control_reference(build, scope, limits)
        control_rows = []
        for raw in normalize_control_rows(control_benchmark):
            row = dict(raw)
            row.update({"workload": "control", "fields_completed": raw["fields"],
                "warmup_fields": 120, "ticks_completed": raw["ticks"],
                "last_stop_reason": raw["stop_reason"], "untimed": False})
            row["untimed_output_identity"] = control_ref["output_identity"]
            if row["output_identity"] != control_ref["output_identity"]:
                raise ValueError("control timed output diverged from untimed reference")
            control_rows.append(row)
        report["untimed_references"].append({"workload": "control", **control_ref})
        if _ACTIVE_JOURNAL:
            _ACTIVE_JOURNAL.set_partial_report(report)
        route_sources = {}
        for title in ("recursion94", "tank-battle"):
            scenario_path, oracle_path, _, rom_path = routes_module.SOURCES[title]
            scenario = json.loads((ROOT / scenario_path).read_text())
            oracle = json.loads((ROOT / oracle_path).read_text())
            route_sources[title] = {"fixture_id": scenario.get("fixture_id", title),
                "profile": "VA3-NTSC-U", "source_sha256": scenario.get("source", {}).get("sha256"),
                "scenario_sha256": sha_file(ROOT / scenario_path), "oracle_sha256": sha_file(ROOT / oracle_path),
                "rom_sha256": sha_file(ROOT / rom_path), "source_revision": scenario.get("source", {}).get("revision"),
                "expected_active_steps": 3600 if title == "recursion94" else None,
                "oracle_case_count": len(oracle.get("cases", [])) if isinstance(oracle, dict) else None}
        control_identity = workload_identity()
        workloads = {"control": {"input_identity": control_identity, "warmup_fields": 120,
            "completed_fields": 600, "timed_runs": control_rows, "untimed_reference": control_ref}}
        for title in ("recursion94", "tank-battle"):
            title_rows = [row for row in report["runs"] if row.get("workload") == title]
            reference = next(row for row in report["untimed_references"] if row.get("workload") == title)
            workloads[title] = {"input_identity": route_sources[title], "warmup_fields": 0,
                "completed_fields": 3631 if title == "recursion94" else 4196,
                "timed_runs": title_rows, "untimed_reference": reference}
        cmake_identity = control_benchmark["build_identity"]
        public_build = {"build_configuration_sha256": cmake_identity["build_configuration_sha256"],
            "compiler_sha256": cmake_identity["compiler_sha256"],
            "compiler_version_line": cmake_identity["compiler_version_line"],
            "build_rules_sha256": cmake_identity["build_rules_sha256"],
            "configuration": {key: value for key, value in cmake_identity["cmake"].items()
                if key not in ("CMAKE_C_COMPILER",)},
            "benchmark_binary_sha256": control_benchmark["benchmark_binary_sha256"]}
        host = {key: cmake_identity[key] for key in ("host_system", "host_release", "host_macos_version",
                "host_machine", "host_model")}
        report.update({"outcome": "pass", "runtime_source_revision": control_benchmark["source_revision"],
            "runtime_source_state": "private runtime-input source revision; not a public-source SHA",
            "build_identity": cmake_identity, "public_build_identity": public_build,
            "host_identity": host, "workloads": workloads,
            "protocol": {"timed_children": 60, "untimed_correctness_references": 3,
                "repetitions_per_mode": 5, "diagnostics_modes": [False, True],
                "observer_modes": ["sampled", "aggregate"], "serial_children": True,
                "control_warmup_fields": 120, "control_measured_fields": 600,
                "new_title_warmup_fields": 0,
                "new_title_completed_fields": {"recursion94": 3631, "tank-battle": 4196},
                "p99_minimum_comparable_field_samples": 1000,
                "maximum_child_wall_seconds": limits["wall_seconds"],
                "maximum_child_rss_bytes": limits["max_rss_bytes"],
                "maximum_capture_bytes": limits["max_capture_bytes"],
                "maximum_sub_batch_wall_seconds": scope["qualification_batch"]["benchmark_sub_batch_seconds"]},
            "counts": {"timed_children": 60, "untimed_references": 3,
                "process_starts": 63, "timed_samples_per_workload": 20}})
        # Validation gates qualification. Setting the candidate bit here lets the
        # validator check the same complete report that will be persisted.
        report["qualification"] = True
        problems = validate_v02_report(report, expected_source_identity=identity)
        if problems:
            raise ValueError("production v02 benchmark validator rejected report: " + ", ".join(problems))
        report["performance_summary"] = render_performance_summary(report)
        report["qualification"] = True
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    if workload == "all":
        _ACTIVE_BATCH_START = None; _ACTIVE_QUALIFICATION_START = None
        if _ACTIVE_JOURNAL:
            _ACTIVE_JOURNAL.complete(report)
        _ACTIVE_JOURNAL = None
    return report


def load_v02_launcher():
    path = ROOT / "scripts/evidence/v02_run.py"
    spec = importlib.util.spec_from_file_location("gw_core_benchmark_v02", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_phase6_routes():
    path = ROOT / "scripts/evidence/phase6_routes.py"
    spec = importlib.util.spec_from_file_location("gw_core_benchmark_routes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_route_contract():
    path = ROOT / "tests/session/phase6_route_contract.py"
    spec = importlib.util.spec_from_file_location("gw_core_benchmark_route_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    paths = git("ls-files", "-z", "src", "include/genewhip", "CMakeLists.txt", "tools/session/CMakeLists.txt",
                "tools/evidence/core_benchmark.c", "tools/evidence/core_benchmark.py",
                "tools/session/session.c", "tools/session/session.h",
                "tools/session/route_controller.c", "tools/session/route_controller.h",
                "scripts/evidence/phase6_routes.py", "fixtures/phase6/recursion94-consumed-map-v1.json",
                "fixtures/phase5-a", "fixtures/phase5-b",
                "scripts/evidence/phase4_report.py",
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


def workflow_base_sha(head_sha):
    value = os.environ.get("GITHUB_BASE_SHA")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not value and event_path:
        try:
            event = json.loads(Path(event_path).read_text(encoding="utf-8"))
            value = event.get("before") or event.get("pull_request", {}).get("base", {}).get("sha")
        except (OSError, ValueError, TypeError):
            value = None
    return value or head_sha


def build_rules_file(build, generator):
    generator_files = {"Ninja": "build.ninja", "Unix Makefiles": "Makefile"}
    if generator not in generator_files:
        raise ValueError(f"unsupported benchmark build generator: {generator or 'unknown'}")
    build_rules = Path(build) / generator_files[generator]
    if not build_rules.is_file():
        raise ValueError(f"build rules for {generator} are missing: {build_rules.name}")
    return build_rules


def _run_journaled_client(boundary, binary, command, receipts, journal_entry, **kwargs):
    """Retain ownership before monitoring and finalize every exceptional exit."""
    spec = importlib.util.spec_from_file_location("benchmark_process_receipt",
        ROOT / "scripts/evidence/phase5_process.py")
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    journal = _ACTIVE_JOURNAL if journal_entry is not None else None
    root = journal.path.parent if journal else Path(kwargs["cwd"])
    relative = Path(f"{journal.path.stem}-child-{journal_entry['index']:04d}.json"
        if journal else "bounded-child-process.json")

    def owned(receipt):
        if journal:
            journal_entry["resource_receipt"] = receipt
            journal._flush()

    try:
        with capture.receipt_file(root, relative) as stream:
            result = boundary._run_client(binary, command, receipts,
                process_receipt_stream=stream, ownership_callback=owned, **kwargs)
    except BaseException as error:
        if journal:
            journal.finish(journal_entry, exit_code=1,
                receipt=receipts[0] if receipts else None, stderr=str(error))
            journal.fail(type(error).__name__ + ": " + str(error))
        raise
    if journal:
        journal.finish(journal_entry, exit_code=result.returncode,
            receipt=receipts[0] if receipts else None, stderr=result.stderr, stdout=result.stdout)
    return result


def run_child(binary, mode, diagnostics, warmup, fields, rom=ROM, repetition=0):
    load_route_contract().require_host_process_context()
    enforce_batch_wall_limit()
    command = [str(binary), str(rom), mode, str(diagnostics), str(warmup), str(fields)]
    journal_entry = (_ACTIVE_JOURNAL.launch("control", mode, diagnostics, repetition, command,
        fields=fields, warmup=warmup) if _ACTIVE_JOURNAL and fields > 4 else None)
    if fields > 4 or warmup > 2 or _ACTIVE_QUALIFICATION_START is not None:
        scope_path = ROOT / "evidence/v02-execution.json"
        v02 = load_v02_launcher()
        scope, limits = v02.validate_execution_scope(scope_path, "smoke")
        capture = checked_capture_size(fields)[2]
        v02.require_memory_reserve(v02.available_memory_bytes(), capture + 512 * 1024 * 1024)
        route_contract = load_route_contract()
        build_root = Path(binary).resolve().parent
        scratch_parent = build_root / "v02"
        scratch_parent.mkdir(parents=True, exist_ok=True)
        receipts = []
        try:
            with tempfile.TemporaryDirectory(prefix="gw-bench-control-", dir=scratch_parent) as temporary:
                scratch = Path(temporary)
                timeout, child_limits = bounded_child_limits(limits, child_cap=240)
                result = _run_journaled_client(route_contract, binary, command, receipts, journal_entry,
                    report=scratch / "child.json", timeout=timeout, cwd=scratch,
                    limits=child_limits, scratch_roots=(scratch,))
        except BaseException as exc:
            if _ACTIVE_JOURNAL and journal_entry:
                _ACTIVE_JOURNAL.finish(journal_entry, exit_code=1,
                    receipt=receipts[0] if receipts else None, stderr=str(exc))
            raise
        if _ACTIVE_JOURNAL and journal_entry:
            _ACTIVE_JOURNAL.finish(journal_entry, exit_code=result.returncode,
                receipt=receipts[0] if receipts else None, stderr=result.stderr, stdout=result.stdout)
        if (result.returncode or len(receipts) != 1 or
                receipts[0].get("process_group_cleanup") != "confirmed" or
                receipts[0].get("bound_violation")):
            raise ValueError("bounded benchmark child failed: returncode=%s receipt=%s stderr=%s" %
                (result.returncode, receipts, result.stderr[-2000:]))
        stdout, stderr = result.stdout, result.stderr
        child_pid = receipts[0].get("pid")
    else:
        timeout = None
        if _ACTIVE_QUALIFICATION_START is not None or _ACTIVE_BATCH_START is not None:
            timeout, _ = bounded_child_limits({"wall_seconds": 240}, child_cap=240)
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout or 240)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise ValueError("benchmark child exceeded its 240-second wall timeout")
        if process.returncode:
            raise ValueError(f"benchmark child failed ({process.returncode}): {stderr.strip()[:500]}")
        child_pid = process.pid
    try:
        row = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("benchmark child emitted malformed result JSON") from exc
    if row.get("schema") != RUN_SCHEMA or row.get("mode") != mode or row.get("diagnostics_enabled") is not bool(diagnostics):
        raise ValueError("benchmark child identity/mode mismatch")
    row["process_id"] = child_pid
    row["process_instance"] = str(uuid.uuid4())
    if fields > 4 or warmup > 2:
        row["resource_receipt"] = receipts[0]
    if _ACTIVE_JOURNAL and journal_entry:
        _ACTIVE_JOURNAL.finish(journal_entry, exit_code=0,
            receipt=receipts[0] if fields > 4 or warmup > 2 else None, row=row,
            stderr=stderr, stdout=stdout)
    enforce_batch_wall_limit()
    return row


def run_control_reference(build, scope, limits):
    """Run the control's 120+600 field window without collecting timing values."""
    enforce_batch_wall_limit()
    build = Path(build).resolve(strict=True)
    binary = build / "gw_core_benchmark"
    v02 = load_v02_launcher()
    capture = checked_capture_size(600)[2]
    v02.require_memory_reserve(v02.available_memory_bytes(), capture + 512 * 1024 * 1024)
    route_contract = load_route_contract()
    scratch_parent = Path(build) / "v02"
    scratch_parent.mkdir(parents=True, exist_ok=True)
    command = [str(binary), str(ROM), "aggregate", "0", "120", "600", "--untimed"]
    with tempfile.TemporaryDirectory(prefix="gw-bench-control-reference-", dir=scratch_parent) as name:
        scratch = Path(name)
        receipts = []
        journal_entry = (_ACTIVE_JOURNAL.launch("control", "aggregate", False, 0,
            command, fields=600, warmup=120) if _ACTIVE_JOURNAL else None)
        try:
            timeout, child_limits = bounded_child_limits(limits)
            result = _run_journaled_client(route_contract, binary, command, receipts, journal_entry,
                report=scratch / "reference.json", timeout=timeout, cwd=scratch,
                limits=child_limits, scratch_roots=(scratch,))
        except BaseException as exc:
            if _ACTIVE_JOURNAL and journal_entry:
                _ACTIVE_JOURNAL.finish(journal_entry, exit_code=1,
                    receipt=receipts[0] if receipts else None, stderr=str(exc))
            raise
        if _ACTIVE_JOURNAL and journal_entry:
            _ACTIVE_JOURNAL.finish(journal_entry, exit_code=result.returncode,
                receipt=receipts[0] if receipts else None, stderr=result.stderr, stdout=result.stdout)
    enforce_batch_wall_limit()
    if (result.returncode or len(receipts) != 1 or
            receipts[0].get("process_group_cleanup") != "confirmed" or
            receipts[0].get("bound_violation")):
        raise ValueError("control correctness reference failed: returncode=%s receipt=%s stderr=%s" %
            (result.returncode, receipts, result.stderr[-2000:]))
    row = json.loads(result.stdout)
    row["resource_receipt"] = receipts[0]
    validate_control_reference(row, limits)
    row["output_identity"] = output_identity(row)
    row["process_id"] = receipts[0]["pid"]
    row["process_instance"] = str(uuid.uuid4())
    if _ACTIVE_JOURNAL and journal_entry:
        _ACTIVE_JOURNAL.finish(journal_entry, exit_code=0, receipt=receipts[0], row=row,
            stderr=result.stderr, stdout=result.stdout)
    return row


def output_identity(run):
    return {"video": [(field.get("sequence"), field.get("end_tick"), field.get("width"),
                       field.get("height"), field.get("sha256"))
                      for field in run.get("video_fields", [])],
            "pcm_frames": run.get("pcm_frames"), "pcm_sha256": run.get("pcm_sha256"),
            "ram_sha256": run.get("ram_sha256"), "machine_sha256": run.get("machine_sha256")}


def render_performance_summary(report):
    """Create a public-safe, host-local summary from a validated measurement report."""
    host = report.get("host_identity", {})
    host_id = digest(host)
    result = {"schema": "genewhip-public-performance-v2", "source_revision": report.get("source_revision"),
              "source_identity_sha256": report.get("source_identity_sha256"),
              "build_identity": report.get("public_build_identity"),
              "host_identity": host, "workloads": []}
    for workload in WORKLOADS:
        group = report["workloads"][workload]
        rows = group["timed_runs"]
        elapsed = [row["elapsed_ns"] for row in rows]
        field_sets = {diagnostics: [value for row in rows
            if row["observer"] == "sampled" and row["diagnostics_enabled"] is diagnostics
            for value in row["field_ns"]] for diagnostics in (False, True)}
        by_mode = []
        for diagnostics, observer in MODES:
            selected = [row for row in rows if row["diagnostics_enabled"] == bool(diagnostics) and
                        row["observer"] == observer]
            by_mode.append({"diagnostics_enabled": bool(diagnostics), "observer": observer,
                "runs": [{"repetition": row["repetition"], "elapsed_ns": row["elapsed_ns"],
                          "fields": row["fields_completed"], "ticks": row["ticks_completed"],
                          "fields_per_second": row["fields_completed"] / (row["elapsed_ns"] / 1e9),
                          "core_owned_current_bytes": row.get("core_owned_current_bytes"),
                          "core_owned_peak_bytes": row.get("core_owned_peak_bytes"),
                          "process_ru_maxrss_bytes": row["process_ru_maxrss_bytes"],
                          "diagnostic_records": row.get("diagnostic_records"),
                          "diagnostic_dropped": row.get("diagnostic_dropped"),
                          "field_ns": row["field_ns"]} for row in selected],
                "elapsed_ns": summarize_performance_samples([row["elapsed_ns"] for row in selected],
                    sample_kind="whole_run", host_id=host_id, workload_id=workload),
                "field_latency_ns": (summarize_performance_samples(
                    [value for row in selected for value in row["field_ns"]], sample_kind="field",
                    host_id=host_id, workload_id=workload) if observer == "sampled" else None)})
        timing_pairs = []
        diagnostic_pairs = []
        for diagnostics in (False, True):
            sampled = {row["repetition"]: row for row in rows if row["diagnostics_enabled"] == diagnostics
                       and row["observer"] == "sampled"}
            aggregate = {row["repetition"]: row for row in rows if row["diagnostics_enabled"] == diagnostics
                         and row["observer"] == "aggregate"}
            for repetition in range(1, 6):
                timing_pairs.append({"diagnostics_enabled": diagnostics, "repetition": repetition,
                    "sampled_elapsed_ns": sampled[repetition]["elapsed_ns"],
                    "aggregate_elapsed_ns": aggregate[repetition]["elapsed_ns"],
                    "observer_overhead_percent": (sampled[repetition]["elapsed_ns"] -
                        aggregate[repetition]["elapsed_ns"]) * 100.0 / aggregate[repetition]["elapsed_ns"]})
        for observer in ("sampled", "aggregate"):
            disabled = {row["repetition"]: row for row in rows if not row["diagnostics_enabled"]
                        and row["observer"] == observer}
            enabled = {row["repetition"]: row for row in rows if row["diagnostics_enabled"]
                       and row["observer"] == observer}
            for repetition in range(1, 6):
                off, on = disabled[repetition], enabled[repetition]
                diagnostic_pairs.append({"observer": observer, "repetition": repetition,
                    "disabled_elapsed_ns": off["elapsed_ns"], "enabled_elapsed_ns": on["elapsed_ns"],
                    "diagnostics_cost_percent": (on["elapsed_ns"] - off["elapsed_ns"]) * 100.0 /
                        off["elapsed_ns"], "output_equivalent": off["output_identity"] == on["output_identity"]})
        result["workloads"].append({"workload": workload, "input_identity": group["input_identity"],
            "warmup_fields": group["warmup_fields"], "completed_fields": group["completed_fields"],
            "untimed_reference": {"fields": group["untimed_reference"]["fields_completed"],
                "ticks": group["untimed_reference"]["ticks_completed"],
                "output_identity": digest(group["untimed_reference"]["output_identity"])},
            "timed_samples": len(rows), "whole_run_exposure": summarize_performance_samples(
                elapsed, sample_kind="whole_run", host_id=host_id, workload_id=workload),
            "field_latency_by_diagnostics": {str(diagnostics): summarize_performance_samples(
                field_sets[diagnostics], sample_kind="field", host_id=host_id, workload_id=workload)
                for diagnostics in (False, True)}, "modes": by_mode,
            "sampled_vs_aggregate_pairs": timing_pairs, "diagnostics_pairs": diagnostic_pairs,
            "memory_exposure": {"core_owned_current_bytes_max": max(
                (row.get("core_owned_current_bytes") or 0 for row in rows), default=0),
                "core_owned_peak_bytes_max": max((row.get("core_owned_peak_bytes") or 0 for row in rows), default=0),
                "process_ru_maxrss_bytes_max": max(row["process_ru_maxrss_bytes"] for row in rows)}})
    return result


def validate_v02_report(report, expected_source_identity=None):
    """Validate exact per-title child rosters, process identities and correctness joins."""
    problems = []
    if not isinstance(report, dict) or report.get("schema") != V02_REPORT_SCHEMA or report.get("version") != 2:
        return ["schema"]
    if report.get("outcome") != "pass" or report.get("qualification") is not True:
        problems.append("outcome")
    if report.get("serial_children") is not True:
        problems.append("serial-policy")
    source_id = report.get("source_identity_sha256")
    if not isinstance(source_id, str) or not re.fullmatch(r"[0-9a-f]{64}", source_id) or \
            (expected_source_identity is not None and source_id != expected_source_identity):
        problems.append("source-identity")
    workloads = report.get("workloads")
    if not isinstance(workloads, dict) or set(workloads) != set(WORKLOADS):
        return sorted(set(problems + ["workload-roster"]))
    process_ids, process_instances = [], []
    expected_fields = {"control": (600, 120), "recursion94": (3631, 0), "tank-battle": (4196, 0)}
    for workload, (fields, warmup) in expected_fields.items():
        group = workloads[workload]
        rows, reference = group.get("timed_runs"), group.get("untimed_reference")
        if not isinstance(rows, list) or len(rows) != 20 or not isinstance(reference, dict):
            problems.append("sample-count")
            continue
        if group.get("completed_fields") != fields or group.get("warmup_fields") != warmup:
            problems.append("completed-work")
        if reference.get("untimed") is not True or reference.get("elapsed_ns") != 0 or \
                reference.get("fields_completed") != fields or reference.get("warmup_fields") != warmup:
            problems.append("reference")
        if reference.get("rss_unit_source") != "Darwin getrusage(2) ru_maxrss bytes" or \
                reference.get("process_ru_maxrss_bytes", 0) <= 0 or \
                reference.get("process_ru_maxrss_bytes", 0) > 4 * 1024**3:
            problems.append("memory-units")
        ref_identity = reference.get("output_identity")
        if not isinstance(ref_identity, dict):
            problems.append("reference")
        process_ids.append(reference.get("process_id")); process_instances.append(reference.get("process_instance"))
        modes = {(row.get("diagnostics_enabled"), row.get("observer")) for row in rows
                 if isinstance(row, dict)}
        if modes != {(False, "sampled"), (False, "aggregate"), (True, "sampled"), (True, "aggregate")}:
            problems.append("mode-roster")
        for diagnostics, observer in MODES:
            selected = [row for row in rows if row.get("diagnostics_enabled") == bool(diagnostics)
                        and row.get("observer") == observer]
            if len(selected) != 5 or {row.get("repetition") for row in selected} != {1, 2, 3, 4, 5}:
                problems.append("sample-count")
        for row in rows:
            process_ids.append(row.get("process_id")); process_instances.append(row.get("process_instance"))
            stop_ok = (row.get("last_stop_reason") == 5 if workload == "control" else
                       row.get("route_status") == 0 and row.get("terminal_tick", 0) > 0)
            if row.get("fields_completed") != fields or row.get("warmup_fields") != warmup or \
                    row.get("elapsed_ns", 0) <= 0 or row.get("ticks_completed", 0) <= 0 or \
                    not stop_ok or row.get("untimed") is True:
                problems.append("incomplete-samples")
            if row.get("output_identity") != ref_identity or row.get("untimed_output_identity") != ref_identity:
                problems.append("output-divergence")
            if row.get("observer") == "sampled" and (not isinstance(row.get("field_ns"), list) or
                    len(row["field_ns"]) != fields or any(type(value) is not int or value <= 0 for value in row["field_ns"])):
                problems.append("field-samples")
            if row.get("observer") == "aggregate" and row.get("field_ns"):
                problems.append("field-samples")
            if row.get("process_ru_maxrss_bytes", 0) <= 0 or row.get("process_ru_maxrss_bytes", 0) > 4 * 1024**3:
                problems.append("memory-bound")
            if row.get("rss_unit_source") != "Darwin getrusage(2) ru_maxrss bytes":
                problems.append("memory-units")
            receipt = row.get("resource_receipt", {})
            if receipt.get("process_group_cleanup") != "confirmed" or receipt.get("bound_violation"):
                problems.append("child-cleanup")
        reference_receipt = reference.get("resource_receipt", {})
        if reference_receipt.get("process_group_cleanup") != "confirmed" or \
                reference_receipt.get("bound_violation"):
            problems.append("child-cleanup")
        input_identity = group.get("input_identity", {})
        for key in ("rom_sha256", "scenario_sha256", "oracle_sha256"):
            if workload != "control" and not re.fullmatch(r"[0-9a-f]{64}", str(input_identity.get(key, ""))):
                problems.append("workload-identity")
    if len(process_ids) != 63 or None in process_ids or len(set(process_ids)) != 63 or \
            None in process_instances or len(set(process_instances)) != 63:
        problems.append("process-identity")
    if report.get("counts") != {"timed_children": 60, "untimed_references": 3,
            "process_starts": 63, "timed_samples_per_workload": 20}:
        problems.append("sample-count")
    return sorted(set(problems))


def validate_workload_report(report, workload, expected_source_identity, expected_scope_id):
    """Validate one independently hosted exact 20+1 benchmark workload report."""
    problems = []
    if (not isinstance(report, dict) or report.get("schema") != "genewhip.v02-workload-benchmark-v1" or
            report.get("workload") != workload):
        return ["workload-report-schema-or-id"]
    if report.get("outcome") != "pass" or report.get("qualification") is not True:
        problems.append("workload-report-outcome")
    if report.get("source_identity_sha256") != expected_source_identity:
        problems.append("workload-report-source-identity")
    if report.get("scope_id") != expected_scope_id:
        problems.append("workload-report-scope")
    if (not isinstance(report.get("source_revision"), str) or
            not re.fullmatch(r"[0-9a-f]{40}", report["source_revision"])):
        problems.append("workload-report-revision")
    if (not isinstance(report.get("run_id"), str) or not report["run_id"] or
            not isinstance(report.get("run_attempt"), str) or not report["run_attempt"].isdigit() or
            report.get("head_sha") != report.get("source_revision") or
            not isinstance(report.get("base_sha"), str) or not re.fullmatch(r"[0-9a-f]{40}", report["base_sha"])):
        problems.append("workload-report-run-identity")
    build = report.get("build_identity")
    host = report.get("host_identity")
    host_keys = ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")
    if (not isinstance(build, dict) or any(key not in build for key in host_keys) or
            not isinstance(host, dict) or host != {key: build[key] for key in host_keys}):
        problems.append("workload-report-host-identity")
    if (not isinstance(build, dict) or
            any(not re.fullmatch(r"[0-9a-f]{64}", str(build.get(key, "")))
                for key in ("compiler_sha256", "build_rules_sha256", "build_configuration_sha256")) or
            not isinstance(build.get("compiler_version_line"), str) or not build["compiler_version_line"] or
            not isinstance(build.get("cmake"), dict)):
        problems.append("workload-report-build-identity")
    timed = report.get("timed_runs")
    reference = report.get("untimed_reference")
    if not isinstance(timed, list) or len(timed) != 20 or not isinstance(reference, dict):
        return sorted(set(problems + ["workload-report-counts"]))
    if report.get("counts") != {"timed_children": 20, "untimed_references": 1,
            "process_starts": 21, "timed_samples_per_mode": 5}:
        problems.append("workload-report-counts")
    spec = workload_spec(workload, {"workload": {"max_fields": 7200, "max_calls": 100000000,
        "tank_route_max_calls": 10000000}})
    try:
        validate_workload_run(reference, spec)
    except ValueError as error:
        problems.append("workload-reference:" + str(error))
    modes = {(row.get("diagnostics_enabled"), row.get("observer")) for row in timed if isinstance(row, dict)}
    if modes != {(False, "sampled"), (False, "aggregate"), (True, "sampled"), (True, "aggregate")}:
        problems.append("workload-report-mode-roster")
    ids, instances = [], []
    for diagnostics, observer in MODES:
        rows = [row for row in timed if row.get("diagnostics_enabled") == bool(diagnostics) and row.get("observer") == observer]
        if len(rows) != 5 or {row.get("repetition") for row in rows} != {1, 2, 3, 4, 5}:
            problems.append("workload-report-repetition-roster")
    for row in timed:
        try:
            validate_workload_run(row, spec)
        except ValueError as error:
            problems.append("workload-run:" + str(error))
        if row.get("output_identity") != reference.get("output_identity") or row.get("untimed_output_identity") != reference.get("output_identity"):
            problems.append("workload-report-output-divergence")
        ids.append(row.get("process_id")); instances.append(row.get("process_instance"))
    ids.append(reference.get("process_id")); instances.append(reference.get("process_instance"))
    if (None in ids or len(set(ids)) != 21 or None in instances or len(set(instances)) != 21):
        problems.append("workload-report-process-identity")
    return sorted(set(problems))


def _canonical_json_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _public_build_identity(build):
    """Keep reproducible build facts while omitting paths and raw local flags."""
    allowed = {"CMAKE_BUILD_TYPE", "CMAKE_C_COMPILER_ID", "CMAKE_C_COMPILER_VERSION",
               "CMAKE_GENERATOR", "GENEWHIP_BUILD_DESKTOP", "GENEWHIP_TEST_HOOKS"}
    return {key: build[key] for key in (
        "cmake", "compiler_sha256", "compiler_version_line", "build_rules_sha256",
        "build_configuration_sha256", "host_system", "host_release", "host_macos_version",
        "host_machine", "host_model") if key != "cmake"} | {
            "cmake": {key: value for key, value in build.get("cmake", {}).items() if key in allowed}}


def build_public_performance_projection(reports, raw_report_digests, *, identity, source_identity_sha256,
                                        scope_id, scope_sha256):
    """Validate three exact-attempt reports and emit host-separated public evidence."""
    expected_workloads = set(WORKLOADS)
    if set(reports) != expected_workloads or set(raw_report_digests) != expected_workloads:
        raise ValueError("public-performance-workload-roster")
    projection = {"schema": PUBLIC_PERFORMANCE_SCHEMA, "identity": identity,
        "source_identity_sha256": source_identity_sha256, "scope_id": scope_id,
        "scope_sha256": scope_sha256, "workloads": {}}
    for workload in WORKLOADS:
        report = reports[workload]
        errors = validate_workload_report(report, workload, source_identity_sha256, scope_id)
        if (errors or report.get("source_revision") != identity.get("source_sha") or
                report.get("head_sha") != identity.get("head_sha") or
                report.get("base_sha") != identity.get("base_sha") or
                report.get("run_id") != identity.get("run_id") or
                report.get("run_attempt") != identity.get("run_attempt") or
                report.get("scope_sha256") != scope_sha256 or
                not re.fullmatch(r"[0-9a-f]{64}", str(raw_report_digests[workload]))):
            raise ValueError("public-performance-report-rejected:" + workload + ":" + ",".join(errors))
        public_report = dict(report)
        public_report["build_identity"] = _public_build_identity(report["build_identity"])
        public_report["host_identity"] = {key: public_report["build_identity"][key] for key in
            ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")}
        projection["workloads"][workload] = {"source_report_sha256": raw_report_digests[workload],
            "public_report_sha256": _canonical_json_sha256(public_report),
            "host_identity": public_report["host_identity"],
            "build_identity": public_report["build_identity"], "report": public_report}
    return projection


def validate_public_performance_projection(projection, *, identity, source_identity_sha256,
                                           scope_id, scope_sha256, expected_reports=None,
                                           raw_report_digests=None):
    if (not isinstance(projection, dict) or projection.get("schema") != PUBLIC_PERFORMANCE_SCHEMA or
            projection.get("identity") != identity or
            projection.get("source_identity_sha256") != source_identity_sha256 or
            projection.get("scope_id") != scope_id or projection.get("scope_sha256") != scope_sha256 or
            not isinstance(projection.get("workloads"), dict) or
            set(projection["workloads"]) != set(WORKLOADS)):
        return ["public-performance-envelope"]
    problems = []
    for workload in WORKLOADS:
        entry = projection["workloads"][workload]
        report = entry.get("report") if isinstance(entry, dict) else None
        if not isinstance(report, dict):
            problems.append("public-performance-report:" + workload)
            continue
        errors = validate_workload_report(report, workload, source_identity_sha256, scope_id)
        if (errors or report.get("source_revision") != identity.get("source_sha") or
                report.get("head_sha") != identity.get("head_sha") or
                report.get("base_sha") != identity.get("base_sha") or
                report.get("run_id") != identity.get("run_id") or
                report.get("run_attempt") != identity.get("run_attempt") or
                report.get("scope_sha256") != scope_sha256):
            problems.extend("public-performance-" + workload + ":" + item for item in errors)
        if (entry.get("host_identity") != report.get("host_identity") or
                entry.get("build_identity") != report.get("build_identity") or
                entry.get("public_report_sha256") != _canonical_json_sha256(report) or
                not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("source_report_sha256", "")))):
            problems.append("public-performance-binding:" + workload)
    if expected_reports is not None or raw_report_digests is not None:
        if not isinstance(expected_reports, dict) or not isinstance(raw_report_digests, dict):
            problems.append("public-performance-source-reports-missing")
        else:
            try:
                expected = build_public_performance_projection(expected_reports, raw_report_digests,
                    identity=identity, source_identity_sha256=source_identity_sha256,
                    scope_id=scope_id, scope_sha256=scope_sha256)
                if projection != expected:
                    problems.append("public-performance-source-projection-mismatch")
            except (ValueError, KeyError, TypeError) as error:
                problems.append("public-performance-source-reports-rejected:" + str(error))
    return sorted(set(problems))


def normalize_control_rows(control_benchmark):
    """Add explicit roster indices to legacy mode runs before v02 validation."""
    rows = []
    for mode_row in control_benchmark["modes"]:
        for repetition, raw in enumerate(mode_row["runs"], 1):
            row = dict(raw)
            row["diagnostics_enabled"] = bool(mode_row["diagnostics_enabled"])
            row["observer"] = mode_row["observer"]
            row["repetition"] = repetition
            rows.append(row)
    return rows


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


def run_protocol(build, quick, *, v02_control=False):
    build = Path(build).resolve()
    binary = build / "gw_core_benchmark"
    if not binary.is_file():
        raise ValueError("gw_core_benchmark is missing from build")
    if platform.system() != "Darwin":
        raise ValueError("Darwin is required because ru_maxrss is reported in bytes on macOS")
    cmake = build_identity(build)
    cache = cmake["cmake"]
    validate_protocol_build(cache, quick)
    if not quick and not v02_control and cache.get("GENEWHIP_BUILD_DESKTOP") != "ON":
        raise ValueError("full benchmark requires same-build headless and desktop clients")
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT,
                           check=True, text=True, stdout=subprocess.PIPE).stdout
    dirty = [line[3:].strip() for line in status.splitlines()
             if line[3:].strip() and not line[3:].strip().startswith(".planning/")]
    if dirty and not quick:
        raise ValueError("source files must be committed before measuring: " + ", ".join(dirty))
    qualification = None if quick or v02_control else workload_qualification(build)
    warmup, fields, repetitions = (2, 4, 1) if quick else (120, 600, 5)
    runs = []
    by_key = {}
    for repetition in range(repetitions):
        group = {}
        for diagnostics, mode in MODES:
            child = run_child(binary, mode, diagnostics, warmup, fields, repetition=repetition + 1)
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
                      "rss_unit_source": row.get("rss_unit_source"),
                      "resource_receipt": row.get("resource_receipt"),
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
    return {"schema": REPORT_SCHEMA, "version": 1, "outcome": "pass", "qualification": not v02_control,
        "profile": "v02-control-workload" if v02_control else "sustained-qualified-workload",
        "source_revision": git("rev-parse", "HEAD"),
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
    parser.add_argument("--build", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--validate-v02", type=Path)
    parser.add_argument("--report-only", action="store_true",
                         help="validate an existing v02 report and refresh its sanitized summary")
    parser.add_argument("--quick", action="store_true", help="bounded contract smoke; never a sustained result")
    parser.add_argument("--workload", choices=("control", "recursion94", "tank-battle", "all"))
    parser.add_argument("--scope", type=Path)
    parser.add_argument("--contracts-only", action="store_true")
    parser.add_argument("--untimed", action="store_true")
    parser.add_argument("--source-sha")
    args = parser.parse_args(argv)
    try:
        if args.validate_v02:
            report = json.loads(args.validate_v02.read_text())
            problems = validate_v02_report(report, expected_source_identity=source_identity())
            if problems:
                raise ValueError("production v02 benchmark validator rejected report: " + ", ".join(problems))
            summary = render_performance_summary(report)
            if args.report_only:
                summary_path = args.validate_v02.parent / "public" / "performance.json"
                summary_path.parent.mkdir(parents=True, exist_ok=True)
                summary_path.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
                print("core benchmark: validated v02 report; refreshed sanitized per-workload summary")
            else:
                print("core benchmark: v02 report valid; 60 timed samples and 3 untimed references")
            return 0
        if not args.build or not args.out:
            raise ValueError("--build and --out are required unless --validate-v02 is used")
        if args.report_only:
            raise ValueError("--report-only requires --validate-v02")
        if args.workload:
            if args.quick or not args.scope:
                raise ValueError("v2 workload requires --scope and cannot be combined with --quick")
            if args.workload == "control" and args.untimed and not args.contracts_only:
                raise ValueError("legacy control workload has a measured warmup split and cannot be wholly untimed")
            report = run_workload(args.build, args.workload, args.scope, args.out,
                untimed=args.untimed, contracts_only=args.contracts_only, source_sha=args.source_sha)
            if args.contracts_only or args.workload != "control":
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
                print(f"core benchmark: v2 workload {args.workload}; "
                      f"timed={report.get('counts', {}).get('timed_children', 0)}; "
                      f"references={report.get('counts', {}).get('untimed_references', 0)}")
                return 0
        else:
            if args.scope or args.contracts_only or args.untimed or args.source_sha:
                raise ValueError("v2 workload flags require --workload")
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
    except (OSError, ValueError, KeyError, TypeError, RuntimeError,
            subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        if _ACTIVE_JOURNAL:
            _ACTIVE_JOURNAL.fail(exc)
        print("core benchmark: REJECT: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    if "--contracts-only" not in sys.argv:
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    raise SystemExit(main())
