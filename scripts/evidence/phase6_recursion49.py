#!/usr/bin/env python3
"""Bounded Plan49 RECURSION supervisor; imports route tooling only after guard review."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
REL = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes"
EVIDENCE = ROOT / REL / "49-evidence"
PLAN_SHA = "3a3e5ccae40fd8c2bcfb88d42db52331e2b4490b47e1cbc0151b3e450383493b"
AUTHORITY_PATH = ".planning/quick/261028-cs9-unblock-plan49-through-reviewed-workload/SELECTION.json"
AUTHORITY_SHA = "bdccc817c26a37d54f12b921df6f7a0d16a0fc43aac52c5cb26e52ae65ebb743"
NATIVE_RECONCILIATION_SHA = "bac8476460161461305e30192f8a3282392650968844d2111275aa104967ca81"
BASE_HEAD = "c65914dbb717dbf89b0ae590bb77bf1404b30d2f"
SELECTION_PATH = EVIDENCE / "selection.json"
AMENDED_CHECK_PATH = ROOT / REL / "06-49-PLAN-AMENDED-CHECK.md"
WINDOW = EVIDENCE / "window.json"
RUNTIME = EVIDENCE / "runtime.json"
WRITER_LOCK = EVIDENCE / "writer.lock"
STREAM_LIMIT = 1 << 20
REPORT_LIMIT = 16 << 20
TRACE_LIMIT = 24 << 20
RAW_TOTAL_LIMIT = 2 << 30
OWNED_DISK_LIMIT = 8 << 30
BUILD_LIMIT = 6 << 30
FINAL_RESERVE = 5400
TERMINAL_RESERVE = 1500
GROUP_LIMIT = 600
GROUP_CLEANUP = 2
REVIEW_PATHS = (
    "scripts/evidence/phase6_recursion49.py",
    "tests/evidence/phase6_recursion49_contract.py",
    "scripts/evidence/phase6_routes.py",
    "tools/session/route_controller.c",
    "tools/session/session.c",
    "tests/session/phase6_route_contract.py",
)
SOURCE_PATHS = REVIEW_PATHS + (
    "src/cpu68000.c", "src/bus.c", "src/core.c", "include/genewhip/genewhip.h",
    "tools/headless/main.c", "docs/core.md", "docs/cpu.md",
)
_CREATE_DENIALS: set[str] = set()


class Invalid(RuntimeError):
    pass


def _json(path: pathlib.Path, *, limit=REPORT_LIMIT):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise Invalid("missing-or-oversized-json:" + str(path))
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Invalid("nonfinite-json")))


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate-json-key")
        result[key] = value
    return result


def _dump_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _atomic(path, data):
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _hashes(paths=SOURCE_PATHS):
    return {name: _sha(ROOT / name) for name in paths}


def _validate_review(review, expected_hashes):
    if (review.get("schema") != "genewhip-plan49-guard-review-v1" or
            review.get("verdict") != "PASS" or review.get("source_sha256") != expected_hashes or
            review.get("reviewed_plan_sha256") != PLAN_SHA or
            review.get("reviewed_before_import_or_workload") is not True):
        raise Invalid("guard-review-missing-or-stale")
    return True


def _validate_cap_agreement(selected, serialized, maximum=100_000_000):
    if type(selected) is not int or type(serialized) is not int or not 1 <= selected <= maximum:
        raise Invalid("selected-cap-range")
    if serialized != selected:
        raise Invalid("serialized-cap-disagrees-with-selection")
    return True


def _admit_attempt(*, slots, slot_limit, prior_group_pending, workload_left, exposure,
                   final_reserve, window_left, terminal_reserve):
    if type(slots) is not int or slots < 0 or slots >= slot_limit:
        raise Invalid("attempt-slot-cap")
    if prior_group_pending:
        raise Invalid("unfinished-prior-workload-group")
    if type(exposure) not in (int, float) or exposure <= 0 or workload_left < exposure + final_reserve:
        raise Invalid("next-attempt-plus-final-reserve-does-not-fit")
    if window_left < exposure + terminal_reserve:
        raise Invalid("window-plus-terminal-reserve-does-not-fit")
    return True


def _bounded_block(current, block, limit):
    if type(current) is not int or current < 0 or type(limit) is not int or limit < 0:
        raise Invalid("stream-counter-invalid")
    if len(block) > limit - current:
        raise Invalid("child-stream-limit")
    return block


def _enforce_disk_sizes(*, evidence, build, owned):
    if evidence > RAW_TOTAL_LIMIT:
        raise Invalid("retained-evidence-limit")
    if build > BUILD_LIMIT:
        raise Invalid("build-tree-limit")
    if owned > OWNED_DISK_LIMIT:
        raise Invalid("owned-disk-limit")
    return True


def _snapshot_candidate(source_hashes):
    candidate_id = hashlib.sha256(json.dumps(source_hashes, sort_keys=True,
                                              separators=(",", ":")).encode()).hexdigest()[:20]
    candidate_root = EVIDENCE / "candidates" / candidate_id
    if candidate_root.exists():
        manifest = _json(candidate_root / "source-manifest.json")
        if manifest.get("source_sha256") != source_hashes:
            raise Invalid("candidate-snapshot-identity-mismatch")
        return candidate_id
    candidate_root.mkdir(parents=True, exist_ok=False)
    snapshots = {}
    for relative, expected in source_hashes.items():
        source = ROOT / relative
        if source.is_symlink() or not source.is_file() or source.stat().st_size > (2 << 20):
            raise Invalid("source-snapshot-input-invalid:" + relative)
        target = candidate_root / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as incoming, target.open("xb") as outgoing:
            while True:
                block = incoming.read(65536)
                if not block:
                    break
                outgoing.write(block)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        observed = _sha(target)
        if observed != expected:
            raise Invalid("source-changed-during-snapshot:" + relative)
        snapshots[relative] = observed
    _dump_new(candidate_root / "source-manifest.json", {
        "schema": "genewhip-plan49-candidate-source-v1", "candidate_id": candidate_id,
        "source_sha256": source_hashes, "snapshot_sha256": snapshots,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat()})
    return candidate_id


def _verify_selection(path, review_path):
    if pathlib.Path(path).resolve() != SELECTION_PATH.resolve():
        raise Invalid("noncanonical-selection-path")
    if pathlib.Path(review_path).resolve() != (EVIDENCE / "guard-review.json").resolve():
        raise Invalid("noncanonical-guard-review-path")
    selected = _json(path)
    authority_path = ROOT / AUTHORITY_PATH
    limits = selected.get("resource_limits", {})
    expected_limits = {"whole_window_seconds": 16200, "protected_terminal_seconds": 1500,
                       "shared_workload_wall_seconds": 9000, "rec_starts": 12,
                       "exploratory_rec_starts": 6, "final_rec_starts": 6,
                       "rec_boundary_calls_each": 100000000,
                       "rec_boundary_calls_shared": 1200000000,
                       "rec_fields_each": 7200, "rec_source_steps_each": 3600,
                       "authored_native_children": 64,
                       "whole_owned_disk_bytes": 8589934592,
                       "workload_os_starts": 28, "workload_top_level_groups": 16,
                       "authored_calls_each": 200000, "authored_fields_each": 4096,
                       "retained_evidence_disk_bytes": 2147483648,
                       "build_tree_disk_bytes": 6442450944}
    if (selected.get("schema") != "genewhip-plan49-run-selection-v1" or
            selected.get("status") != "selected-and-dispatched" or
            selected.get("plan_sha256") != PLAN_SHA or
            selected.get("dispatch_scope") != "ONLY Plan49" or
            any(limits.get(key) != value for key, value in expected_limits.items()) or
            selected.get("authority_record") != AUTHORITY_PATH or
            selected.get("authority_record_sha256") != AUTHORITY_SHA or
            not authority_path.is_file() or authority_path.is_symlink() or
            _sha(authority_path) != AUTHORITY_SHA):
        raise Invalid("selection-authority-mismatch")
    authority = _json(authority_path)
    plan_path = ROOT / REL / "06-49-PLAN.md"
    amended_check = AMENDED_CHECK_PATH
    if (not plan_path.is_file() or plan_path.is_symlink() or _sha(plan_path) != PLAN_SHA or
            selected.get("plan_path") != f"{REL}/06-49-PLAN.md" or
            selected.get("plan_sha256") != PLAN_SHA or
            selected.get("amended_review_path") != f"{REL}/06-49-PLAN-AMENDED-CHECK.md" or
            selected.get("amended_review_sha256") != "de082072c4c25f4759457e7fc78dd5f9d43ce017b6d60efc73f54fd4cf40176d" or
            not amended_check.is_file() or amended_check.is_symlink() or
            _sha(amended_check) != "de082072c4c25f4759457e7fc78dd5f9d43ce017b6d60efc73f54fd4cf40176d" or
            authority.get("schema") != "genewhip-plan49-delegated-selection-v1" or
            authority.get("status") != "selected-for-later-requested-dispatch" or
            authority.get("authority_boundary", {}).get("engineering_started") is not False or
            authority.get("authority_boundary", {}).get("resource_allocation_started") is not False or
            authority.get("authority_boundary", {}).get("dispatch_command") != "$gsd-execute-phase 6" or
            authority.get("authority_boundary", {}).get("dispatch_scope") != selected.get("dispatch_scope") + ", only after a later requested execute-phase dispatch; never raw queue or a wave selector." or
            authority.get("plan", {}).get("path") != selected.get("plan_path") or
            authority.get("plan", {}).get("amended_sha256") != PLAN_SHA or
            authority.get("plan", {}).get("amended_review_path") != selected.get("amended_review_path") or
            authority.get("plan", {}).get("amended_review_sha256") != selected.get("amended_review_sha256") or
            authority.get("prospective_limits", {}).get("whole_engineering_window_seconds") != 16200 or
            authority.get("prospective_limits", {}).get("protected_terminal_seconds") != 1500 or
            authority.get("prospective_limits", {}).get("shared_workload_wall_seconds") != 9000):
        raise Invalid("plan-or-amended-check-identity-mismatch")
    review = _json(review_path)
    expected = _hashes(REVIEW_PATHS)
    _validate_review(review, expected)
    return selected, review


def _window():
    data = _json(WINDOW)
    expected = {"window_seconds": 16200, "shared_workload_wall_seconds": 9000,
                "protected_terminal_seconds": 1500, "workload_starts_total": 28,
                "workload_groups_total": 16, "rec_starts": 12, "exploratory_rec_max": 6,
                "final_rec_max": 6, "rec_calls_each": 100000000,
                "rec_calls_shared": 1200000000, "rec_fields_each": 7200,
                "rec_steps_each": 3600, "authored_native_children": 64,
                "rec_events_each": 64, "rec_events_shared": 768,
                "rec_group_seconds": 600, "max_final_workload_reserve_seconds": 5400,
                "control_driver_starts": 2, "control_child_starts": 12,
                "control_fields_each": [12, 20, 40, 24, 24, 720],
                "control_fields_shared": 1680, "control_group_seconds_each": 600,
                "tank_starts": 2, "tank_calls_each": 10000000,
                "tank_calls_shared": 20000000, "tank_fields_each": 4500,
                "tank_active_fields_each": 3600, "tank_fields_shared": 9000,
                "tank_events_each": 64, "tank_group_seconds_each": 300,
                "authored_calls_each": 200000, "authored_fields_each": 4096,
                "authored_events_each": 64, "authored_child_seconds": 30,
                "authored_calls_shared": 12800000, "authored_fields_shared": 262144,
                "authored_events_shared": 4096, "authored_check_wall_seconds": 900,
                "setup_wall_seconds": 2700, "setup_jobs": 2,
                "build_group_seconds": 300, "named_test_group_seconds": 60,
                "stdout_stderr_bytes_each": STREAM_LIMIT, "report_bytes_each": REPORT_LIMIT,
                "trace_bytes_each": TRACE_LIMIT, "trace_rows_each": 100000,
                "retained_evidence_bytes": RAW_TOTAL_LIMIT,
                "build_tree_bytes": BUILD_LIMIT, "owned_disk_bytes": OWNED_DISK_LIMIT,
                "nonworkload_process_wall_seconds": 4500}
    if (data.get("schema") != "genewhip-plan49-execution-window-v1" or
            data.get("plan_sha256") != PLAN_SHA or data.get("status") != "active" or
            any(data.get(key) != value for key, value in expected.items())):
        raise Invalid("window-identity")
    return data


def _runtime():
    if RUNTIME.exists():
        return _json(RUNTIME)
    data = {"schema": "genewhip-plan49-runtime-v1", "attempts": [], "groups": [],
            "attempt_slots_consumed": 0, "groups_reserved": 0,
            "workload_os_starts_observed": 0, "workload_groups_started": 0,
            "workload_wall_seconds": 0.0,
            "host_groups": [], "host_groups_started": 0, "native_test_starts": [],
            "setup_wall_seconds": 0.0, "authored_wall_seconds": 0.0,
            "actual_boundary_calls": 0, "unknown_boundary_calls_reserved": 0,
            "actual_events": 0, "unknown_events_reserved": 0,
            "physical_fields": 0, "completed_source_steps": 0,
            "authored_children": 0, "authored_child_slots_reserved": 0,
            "authored_calls": 0, "authored_calls_reserved": 0,
            "authored_fields": 0, "authored_fields_reserved": 0,
            "authored_events": 0, "authored_events_reserved": 0,
            "authored_wall_seconds": 0.0, "authored_wall_reserved_seconds": 0.0,
            "nonworkload_wall_seconds": 0.0,
            "terminal_started": False, "status": "active"}
    return data


def _unresolved_process_receipts():
    unresolved = []
    for path in EVIDENCE.rglob("process-receipt.json"):
        receipt = _json(path)
        if receipt.get("process_started") is True and receipt.get("process_reaped") is not True:
            unresolved.append(str(path.relative_to(ROOT)))
    return unresolved


def _clock_left(exposure=0):
    window = _window()
    observed = float(window["initial_monotonic_observation_ns"]) / 1_000_000_000
    elapsed = float(window["monotonic_start_lag_seconds"]) + (time.monotonic() - observed)
    left = window["window_seconds"] - elapsed
    if left < exposure + window["protected_terminal_seconds"]:
        raise Invalid("window-plus-terminal-reserve-does-not-fit")
    return left, elapsed


def _walk_files(root):
    if not root.exists():
        return
    for path in root.rglob("*"):
        try:
            st = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode):
            raise Invalid("symlink-in-owned-tree:" + str(path.relative_to(ROOT)))
        if stat.S_ISREG(st.st_mode):
            yield path, st.st_size


def _disk(attempt_dir=None):
    owned = (EVIDENCE, ROOT / "build/phase6-49")
    sizes = {root: sum(size for _, size in _walk_files(root)) for root in owned}
    _enforce_disk_sizes(evidence=sizes[EVIDENCE], build=sizes[ROOT / "build/phase6-49"],
                        owned=sum(sizes.values()))
    raw_total = 0
    for path, size in _walk_files(EVIDENCE):
        if path.name.endswith(("stdout.bin", "stderr.bin", ".raw")) or "trace" in path.name:
            raw_total += size
        if path.name.endswith(("stdout.bin", "stderr.bin")) and size > STREAM_LIMIT:
            raise Invalid("stream-limit")
        if "trace" in path.name and size > TRACE_LIMIT:
            raise Invalid("trace-limit")
        if "trace" in path.name:
            try:
                with path.open("rb") as stream:
                    if sum(1 for _ in stream) > 100000:
                        raise Invalid("trace-row-limit")
            except FileNotFoundError:
                continue
        if path.name.endswith((".raw", "report.json")) and size > REPORT_LIMIT:
            raise Invalid("report-limit")
    if raw_total > RAW_TOTAL_LIMIT:
        raise Invalid("aggregate-raw-limit")


def reserve_attempt49(stage, *, call_cap=0, exposure=GROUP_LIMIT, case_id="full-route"):
    """Atomically spend one exploratory slot before an OS creation attempt."""
    data, window = _runtime(), _window()
    if stage not in ("tracer", "feedback", "qualify", "affected"):
        raise Invalid("stage-invalid")
    if window.get("initial_workload_starts") != 0 or data.get("status") != "active":
        raise Invalid("window-or-runtime-not-open")
    if data.get("workload_os_starts_observed", 0) >= window["workload_starts_total"] or data.get("groups_reserved", 0) >= window["workload_groups_total"]:
        raise Invalid("workload-start-or-group-cap")
    if data.get("actual_events", 0) + data.get("unknown_events_reserved", 0) + 64 > window["rec_events_shared"]:
        raise Invalid("shared-event-reservation-exhausted")
    pending = any(group.get("status") in ("reserved", "creation-attempted", "running") for group in data.get("groups", []))
    wall_left = window["shared_workload_wall_seconds"] - data.get("workload_wall_seconds", 0.0)
    total_left, _ = _clock_left()
    _admit_attempt(slots=data.get("attempt_slots_consumed", 0), slot_limit=6,
                   prior_group_pending=pending, workload_left=wall_left, exposure=exposure,
                   final_reserve=FINAL_RESERVE, window_left=total_left,
                   terminal_reserve=TERMINAL_RESERVE)
    if type(call_cap) is not int or not 1 <= call_cap <= window["rec_calls_each"]:
        raise Invalid("attempt-call-cap")
    if type(exposure) not in (int, float) or not 1 <= exposure <= GROUP_LIMIT:
        raise Invalid("attempt-wall-cap")
    _clock_left(exposure)
    _disk()
    number = data.get("attempt_slots_consumed", 0) + 1
    attempt_id = f"rec-{number:02d}-{stage}-{case_id}"
    attempt_dir = EVIDENCE / "attempts" / attempt_id
    attempt_dir.mkdir(parents=True, exist_ok=False)
    if attempt_dir.is_symlink():
        raise Invalid("attempt-directory-symlink")
    source_hashes = _hashes(SOURCE_PATHS)
    guard_hashes = _hashes(REVIEW_PATHS)
    candidate_id = _snapshot_candidate(source_hashes)
    fixture_paths = ("fixtures/phase5-b/scenario.json", "fixtures/phase5-b/oracle.json",
                     "fixtures/phase5-b/input-program.json", "fixtures/phase5-b/game.bin",
                     "fixtures/phase5-b/source.tar", "build/phase6-49/native/tools/session/gw_headless")
    manifest = {"schema": "genewhip-plan49-attempt-v1", "attempt_id": attempt_id,
                "stage": stage, "case_id": case_id, "status": "reserved-before-create",
                "candidate_id": candidate_id, "candidate_source_sha256": source_hashes,
                "guard_source_sha256": guard_hashes,
                "profile_sha256": {name: source_hashes[name] for name in
                                   ("include/genewhip/genewhip.h", "tools/headless/main.c", "src/core.c")},
                "fixture_build_sha256":
                {name: _sha(ROOT / name) for name in fixture_paths},
                "descriptor_sha256": None, "selected_boundary_call_cap": call_cap,
                "max_fields": 7200, "max_source_steps": 3600, "max_events": 64,
                "max_starts": 1, "max_wall_seconds": exposure,
                "max_stdout_bytes": STREAM_LIMIT, "max_stderr_bytes": STREAM_LIMIT,
                "max_report_bytes": REPORT_LIMIT,
                "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "process_creation_attempted": False, "process_started": False,
                "process_exit_code": None, "process_reaped": False,
                "actual_boundary_calls": None, "actual_fields": None,
                "actual_source_steps": None, "actual_events": None, "queue_high_water": None,
                "failure": None}
    _dump_new(attempt_dir / "manifest.json", manifest)
    data["attempt_slots_consumed"] = number
    data["groups_reserved"] = data.get("groups_reserved", 0) + 1
    data["attempts"].append({"attempt_id": attempt_id, "status": "reserved", "call_cap": call_cap,
                             "wall_reserved_seconds": exposure})
    data["groups"].append({"group_id": attempt_id, "status": "reserved",
                           "wall_reserved_seconds": exposure, "attempt_ids": [attempt_id]})
    _atomic(RUNTIME, data)
    return attempt_dir, manifest


def _create_process(attempt_id, command, **options):
    if attempt_id in _CREATE_DENIALS:
        raise PermissionError("sticky-create-denial")
    try:
        return subprocess.Popen(command, **options)
    except BaseException:
        _CREATE_DENIALS.add(attempt_id)
        raise


def _group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _bounded_create(command, cwd, output_dir, report_path, timeout, *, attempt_id="unidentified",
                    separate_session=True, kill_group_on_exit=True, receipt_path=None):
    """Run one process group, retaining bounded prefixes and observed reap facts."""
    receipt = {"process_creation_attempted": False, "process_started": False,
               "process_exit_code": None, "process_reaped": False,
               "command_sha256": hashlib.sha256(json.dumps(command).encode()).hexdigest(),
               "stdout_bytes": 0, "stderr_bytes": 0, "failure": None}
    output_dir.mkdir(parents=True, exist_ok=True)
    streams = {name: (output_dir / (name + ".bin")).open("xb") for name in ("stdout", "stderr")}
    process = None
    started = time.monotonic()
    terminate_requested = False
    old_handlers = {}
    def request_termination(signum, frame):
        nonlocal terminate_requested
        terminate_requested = True
    for signum in (signal.SIGTERM, signal.SIGINT):
        old_handlers[signum] = signal.signal(signum, request_termination)
    def persist_receipt():
        if receipt_path is not None:
            _atomic(receipt_path, receipt)
    selector = selectors.DefaultSelector()
    buffers = {name: 0 for name in streams}
    try:
        _clock_left(timeout)
        _disk(output_dir)
        receipt["process_creation_attempted"] = True
        persist_receipt()
        process = _create_process(attempt_id, command, cwd=cwd, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  start_new_session=separate_session, bufsize=0)
        # start_new_session makes the new session's process-group ID equal its leader PID.
        receipt.update(process_started=True, pid=process.pid, pgid=process.pid)
        persist_receipt()
        for name in streams:
            selector.register(getattr(process, name), selectors.EVENT_READ, name)
        while selector.get_map() or process.poll() is None:
            if terminate_requested:
                raise Invalid("supervisor-termination-requested")
            elapsed = time.monotonic() - started
            if elapsed > max(0.0, timeout - GROUP_CLEANUP):
                raise Invalid("group-watchdog-timeout")
            _clock_left()
            _disk(output_dir)
            if report_path.exists() and report_path.stat().st_size > REPORT_LIMIT:
                raise Invalid("report-stream-limit")
            for key, _ in selector.select(.05):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                _bounded_block(buffers[key.data], block, STREAM_LIMIT)
                streams[key.data].write(block)
                streams[key.data].flush()
                buffers[key.data] += len(block)
                receipt[key.data + "_bytes"] = buffers[key.data]
        receipt["process_exit_code"] = process.wait()
    except BaseException as error:
        receipt["failure"] = type(error).__name__ + ":" + str(error)
    finally:
        if process is not None:
            if kill_group_on_exit:
                try:
                    os.killpg(receipt.get("pgid", process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif process.poll() is None:
                process.kill()
            receipt["process_exit_code"] = process.wait()
            group_gone = not kill_group_on_exit
            if kill_group_on_exit:
                cleanup_deadline = time.monotonic() + GROUP_CLEANUP
                while time.monotonic() < cleanup_deadline:
                    if not _group_exists(receipt.get("pgid", process.pid)):
                        group_gone = True
                        break
                    time.sleep(.02)
            receipt["process_reaped"] = process.returncode is not None and group_gone
            if not group_gone:
                receipt["failure"] = (receipt.get("failure") or "") + ";process-group-survived-cleanup"
        else:
            receipt["process_reaped"] = False
        for stream in streams.values():
            stream.close()
        selector.close()
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    receipt["wall_seconds"] = time.monotonic() - started
    persist_receipt()
    return receipt


def run_named49(command, cwd, attempt_dir, report_path, exposure):
    receipt = _bounded_create(command, cwd, attempt_dir, report_path, exposure,
                              attempt_id=attempt_dir.name,
                              receipt_path=attempt_dir / "process-receipt.json")
    return receipt


NATIVE_TESTS49 = ("load_contract", "time_contract", "reset_contract", "bus_boundary_contract",
                  "gameplay_bus_contract", "movem_contract", "phase6_repairs_contract",
                  "session_contract", "input_log_contract", "phase6_chunk_contract")


def _native_input_hashes():
    paths = {ROOT / "CMakeLists.txt", ROOT / "tools/session/CMakeLists.txt",
             ROOT / "fixtures/phase5-a/game.bin"}
    for root in (ROOT / "src", ROOT / "include", ROOT / "tools/headless", ROOT / "tools/session"):
        paths.update(path for path in root.rglob("*") if path.is_file() and path.suffix in (".c", ".h"))
    paths.update(ROOT / "tests/api" / (name + ".c") for name in NATIVE_TESTS49
                 if name in {"load_contract", "time_contract", "reset_contract", "bus_boundary_contract",
                             "gameplay_bus_contract", "movem_contract", "phase6_repairs_contract"})
    paths.update(ROOT / "tests/session" / (name + ".c") for name in
                 ("session_contract", "input_log_contract", "phase6_chunk_contract"))
    result = {}
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise Invalid("native-input-missing-or-symlink:" + str(path.relative_to(ROOT)))
        result[str(path.relative_to(ROOT))] = _sha(path)
    return result


def _native_lanes_reusable(runtime):
    reconciliation_path = EVIDENCE / "native-lane-reconciliation.json"
    if reconciliation_path.is_symlink() or _sha(reconciliation_path) != NATIVE_RECONCILIATION_SHA:
        return None
    report = _json(reconciliation_path)
    if (report.get("schema") != "genewhip-plan49-native-lane-reconciliation-v1" or
            report.get("status") != "verified-retained-lanes" or
            report.get("base_head") != BASE_HEAD or
            report.get("candidate_id") != "d6dc63baa2e711659d49" or
            report.get("test_roster") != list(NATIVE_TESTS49)):
        return None
    manifest_path = ROOT / report.get("candidate_manifest_path", "")
    if (manifest_path.is_symlink() or not manifest_path.is_file() or
            _sha(manifest_path) != report.get("candidate_manifest_sha256")):
        return None
    manifest = _json(manifest_path)
    if manifest.get("candidate_id") != report.get("candidate_id"):
        return None
    source_rows = report.get("native_inputs", [])
    current_inputs = _native_input_hashes()
    if ({row.get("path"): row.get("current_sha256") for row in source_rows} != current_inputs or
            any(row.get("matches_base_head") is False and
                manifest.get("source_sha256", {}).get(row.get("path")) != row.get("current_sha256")
                for row in source_rows)):
        return None
    group_ids = {row.get("group_id") for row in report.get("groups", [])}
    expected_groups = {"host-06-configure-native", "host-07-build-native",
                       "host-08-configure-sanitize", "host-09-build-sanitize",
                       "host-10-ctest-native", "host-11-ctest-sanitize"}
    if group_ids != expected_groups:
        return None
    snapshot_time = dt.datetime.fromisoformat(manifest.get("created_utc"))
    for row in report["groups"]:
        if dt.datetime.fromisoformat(row.get("receipt_utc")) <= snapshot_time:
            return None
        directory = EVIDENCE / "host-groups" / row["group_id"]
        receipt_path, output_path = directory / "process-receipt.json", directory / "stdout.bin"
        if (_sha(receipt_path) != row.get("receipt_sha256") or
                _sha(output_path) != row.get("stdout_sha256")):
            return None
        receipt = _json(receipt_path)
        if (receipt.get("command_sha256") != row.get("expected_command_sha256") or
                receipt.get("process_started") is not True or receipt.get("process_reaped") is not True or
                receipt.get("process_exit_code") != 0):
            return None
        if row["group_id"].startswith("host-1") and "ctest-" in row["group_id"] and row.get("passed_tests") != list(NATIVE_TESTS49):
            return None
    for row in report.get("build_artifacts", []):
        path = ROOT / row.get("path", "")
        if path.is_symlink() or not path.is_file() or _sha(path) != row.get("sha256"):
            return None
    test_evidence = {lane: next(row for row in report["groups"] if row["group_id"] == group_id)
                     for lane, group_id in (("native", "host-10-ctest-native"),
                                            ("sanitize", "host-11-ctest-sanitize"))}
    build_evidence = {suffix: next(row for row in report["groups"] if row["group_id"] == group_id)
                      for suffix, group_id in (("configure-native", "host-06-configure-native"),
                                               ("build-native", "host-07-build-native"),
                                               ("configure-sanitize", "host-08-configure-sanitize"),
                                               ("build-sanitize", "host-09-build-sanitize"))}
    return {"schema": "genewhip-plan49-native-lane-checkpoint-v1", "status": "pass",
            "native_input_sha256": current_inputs, "test_rosters": {"native": "host-10-ctest-native",
                "sanitize": "host-11-ctest-sanitize"},
            "test_evidence": test_evidence, "build_evidence": build_evidence,
            "all_named_tests_passed": list(NATIVE_TESTS49),
            "reconciliation_path": str(reconciliation_path.relative_to(ROOT)),
            "reconciliation_sha256": NATIVE_RECONCILIATION_SHA}


def _run_host_group(name, command, timeout, *, setup=False, test_roster=()):
    runtime = _runtime()
    used = float(runtime.get("nonworkload_wall_seconds", 0.0))
    authored_reserve = max(0.0, 900.0 - float(runtime.get("authored_wall_seconds", 0.0)) -
                           float(runtime.get("authored_wall_reserved_seconds", 0.0)))
    if used + timeout + authored_reserve > 4500 or timeout + TERMINAL_RESERVE > _clock_left()[0]:
        raise Invalid("nonworkload-or-terminal-budget")
    setup_used = float(runtime.get("setup_wall_seconds", 0.0))
    if setup and setup_used + timeout > 2700:
        raise Invalid("setup-wall-reserve")
    number = len(runtime.get("host_groups", [])) + 1
    group_id = f"host-{number:02d}-{name}"
    output_dir = EVIDENCE / "host-groups" / group_id
    if test_roster:
        slot_count = len(test_roster)
        child_wall_reserve = min(float(timeout), slot_count * 30.0)
        if (runtime["authored_children"] + runtime["authored_child_slots_reserved"] + slot_count > 64 or
                runtime["authored_calls_reserved"] + slot_count * 200000 > 12800000 or
                runtime["authored_fields_reserved"] + slot_count * 4096 > 262144 or
                runtime["authored_events_reserved"] + slot_count * 64 > 4096 or
                runtime["authored_wall_reserved_seconds"] + child_wall_reserve > 900):
            raise Invalid("authored-native-child-reserve-exhausted")
        runtime["authored_child_slots_reserved"] += slot_count
        runtime["authored_calls_reserved"] += slot_count * 200000
        runtime["authored_fields_reserved"] += slot_count * 4096
        runtime["authored_events_reserved"] += slot_count * 64
        runtime["authored_wall_reserved_seconds"] += child_wall_reserve
        runtime.setdefault("authored_child_groups", []).append({"group_id": group_id,
            "names": list(test_roster), "slots": slot_count,
            "reserved_calls": slot_count * 200000, "reserved_fields": slot_count * 4096,
            "reserved_events": slot_count * 64, "reserved_wall_seconds": child_wall_reserve})
        _atomic(RUNTIME, runtime)
    output_dir.mkdir(parents=True, exist_ok=False)
    report = output_dir / "unused-report.json"
    receipt = _bounded_create(command, ROOT, output_dir, report, timeout, attempt_id=group_id,
                              receipt_path=output_dir / "process-receipt.json")
    runtime = _runtime()
    if receipt.get("process_started"):
        runtime["host_groups_started"] = runtime.get("host_groups_started", 0) + 1
        runtime["nonworkload_wall_seconds"] = used + min(float(receipt.get("wall_seconds", timeout)), timeout)
        if setup:
            runtime["setup_wall_seconds"] = setup_used + min(float(receipt.get("wall_seconds", timeout)), timeout)
    item = {"group_id": group_id, "command_sha256": receipt["command_sha256"],
            "started": receipt["process_started"], "exit_code": receipt["process_exit_code"],
            "reaped": receipt["process_reaped"], "wall_seconds": receipt.get("wall_seconds"),
            "setup": setup, "test_roster": list(test_roster), "failure": receipt.get("failure")}
    runtime.setdefault("host_groups", []).append(item)
    if test_roster:
        output = (output_dir / "stdout.bin").read_text(encoding="utf-8", errors="replace")
        test_label = lambda test: r"Test #[0-9]+: " + re.escape(test) + r"[ .]+"
        observed = [test for test in test_roster if re.search(test_label(test), output)]
        passed = [test for test in observed if re.search(test_label(test) + r"Passed(?:\s|$)", output)]
        runtime["native_test_starts"].extend({"name": test, "group": group_id, "start_observed": True,
                                              "outcome": "passed" if test in passed else "failed-or-unknown"}
                                             for test in observed)
        runtime["authored_children"] += len(observed)
        runtime["authored_child_slots_reserved"] -= len(observed)
        runtime.setdefault("authored_unknown_child_slots", []).extend(test for test in test_roster if test not in observed)
        missing = [test for test in test_roster if test not in observed]
        failed = [test for test in test_roster if test in observed and test not in passed]
        _atomic(RUNTIME, runtime)
        if missing or failed:
            raise Invalid("named-test-roster-incomplete:" + ",".join(missing + failed))
    else:
        _atomic(RUNTIME, runtime)
    if not receipt.get("process_started") or not receipt.get("process_reaped") or receipt.get("process_exit_code") != 0:
        raise Invalid("host-group-failed:" + group_id)
    return item


def _run_contract_lanes(args):
    build_root = (ROOT / args.build).resolve()
    native = build_root / "native"
    sanitize = build_root / "sanitize"
    common = ["-DGENEWHIP_BUILD_TOOLS=ON", "-DGENEWHIP_BUILD_DESKTOP=OFF",
              "-DBUILD_TESTING=ON", "-DGENEWHIP_TEST_HOOKS=ON", "-DCMAKE_BUILD_TYPE=Debug"]
    cmake = "cmake"
    runtime_before = _runtime()
    reusable = _native_lanes_reusable(runtime_before)
    if reusable and reusable.get("native_input_sha256") == _native_input_hashes():
        runtime_before["native_lane_checkpoint"] = reusable
        _atomic(RUNTIME, runtime_before)
    else:
        _run_host_group("configure-native", [cmake, "-S", str(ROOT), "-B", str(native), "-G", "Unix Makefiles", *common], 300, setup=True)
        targets = ["gw_headless", *NATIVE_TESTS49]
        _run_host_group("build-native", [cmake, "--build", str(native), "--target", *targets, "--parallel", "2"], 300, setup=True)
        sanitizer_flags = "-fsanitize=address,undefined -fno-omit-frame-pointer"
        sanitizer = [*common, "-DCMAKE_C_FLAGS=" + sanitizer_flags,
                     "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined"]
        _run_host_group("configure-sanitize", [cmake, "-S", str(ROOT), "-B", str(sanitize), "-G", "Unix Makefiles", *sanitizer], 300, setup=True)
        _run_host_group("build-sanitize", [cmake, "--build", str(sanitize), "--target", *targets, "--parallel", "2"], 300, setup=True)
        pattern = "^" + "$|^".join(NATIVE_TESTS49) + "$"
        ctest_native = ["ctest", "--test-dir", str(native), "--output-on-failure", "--no-tests=error",
                        "--timeout", "30", "-R", pattern]
        ctest_sanitize = ["ctest", "--test-dir", str(sanitize), "--output-on-failure", "--no-tests=error",
                          "--timeout", "30", "-R", pattern]
        _run_host_group("ctest-native", ctest_native, 60, test_roster=NATIVE_TESTS49)
        _run_host_group("ctest-sanitize", ctest_sanitize, 60, test_roster=NATIVE_TESTS49)
    contract = ROOT / "tests/evidence/phase6_recursion49_contract.py"
    runtime_before = _runtime()
    prior_dirs = [int(match.group(1)) for path in EVIDENCE.glob("synthetic-*")
                  if (match := re.fullmatch(r"synthetic-([0-9]+)", path.name))]
    prior_dirs += [int(match.group(1)) for path in EVIDENCE.glob("causal-*")
                   if (match := re.fullmatch(r"causal-([0-9]+)", path.name))]
    preflight_runs = max([int(runtime_before.get("preflight_runs", 0)), *prior_dirs]) + 1
    runtime_before["preflight_runs"] = preflight_runs
    _atomic(RUNTIME, runtime_before)
    synthetic_output = EVIDENCE / f"synthetic-{preflight_runs:02d}"
    _run_host_group("synthetic-denial-contract",
                    [sys.executable, "-I", str(contract), "--synthetic", "--output", str(synthetic_output)], 60)
    causal_output = EVIDENCE / f"causal-{preflight_runs:02d}"
    _run_host_group("causal-public-core-contract",
                    [sys.executable, "-I", str(contract), "--causal", "--selection",
                     str(args.selection), "--review", str(args.review), "--build", str(build_root),
                     "--output", str(causal_output)], 60)
    causal = _json(causal_output / "causal.json")
    if causal.get("status") != "pass" or causal.get("observed_latched_values") != [1, 2, 3]:
        raise Invalid("causal-public-core-evidence-invalid")
    runtime = _runtime()
    receipt = causal.get("process_receipt", {})
    if receipt.get("process_started") and receipt.get("process_reaped"):
        runtime["authored_children"] += 1
        runtime["authored_child_slots_reserved"] -= 1
        runtime["authored_guest_attempts"] = runtime.get("authored_guest_attempts", 0) + 1
        runtime.setdefault("authored_child_receipts", []).append(receipt)
        runtime["authored_wall_seconds"] = runtime.get("authored_wall_seconds", 0.0) + float(receipt.get("wall_seconds", 0.0))
        runtime["authored_wall_reserved_seconds"] -= 30.0
        counters = causal.get("native_counters", {})
        for key, value in (("authored_calls", counters.get("boundary_calls")),
                           ("authored_fields", counters.get("physical_fields")),
                           ("authored_events", counters.get("events"))):
            if type(value) is int and value >= 0:
                runtime[key] += value
                if key == "authored_events":
                    runtime["authored_events_reserved"] -= 64
    runtime["preflight"] = {"native_build": "pass", "sanitize_build": "pass",
                            "native_tests": list(NATIVE_TESTS49), "sanitizer_tests": list(NATIVE_TESTS49),
                            "synthetic": "pass", "causal": "pass", "source_sha256": _hashes(SOURCE_PATHS)}
    _atomic(RUNTIME, runtime)


def launch_checked49(args, *, spawn=None):
    """Build exact native descriptor, verify agreement, and launch actual headless guest."""
    selected, _ = _verify_selection(args.selection, args.review)
    if args.stage not in ("tracer", "feedback"):
        raise Invalid("stage-not-implemented-in-current-slice")
    current_sources = _hashes(SOURCE_PATHS)
    _snapshot_candidate(current_sources)
    if args.stage == "tracer" or _runtime().get("preflight", {}).get("source_sha256") != current_sources:
        _run_contract_lanes(args)
    elif _runtime().get("preflight", {}).get("causal") != "pass":
        raise Invalid("feedback-requires-completed-tracer-preflight")
    attempt_dir, manifest = reserve_attempt49(args.stage, call_cap=100_000_000)
    route_module_path = ROOT / "scripts/evidence/phase6_routes.py"
    spec = importlib.util.spec_from_file_location("phase6_routes_plan49", route_module_path)
    if spec is None or spec.loader is None:
        raise Invalid("route-module-load-failed")
    route_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(route_module)
    roster = route_module.compile_routes()
    route = next((row for row in roster["routes"] if row["fixture"] == "recursion94" and row["case"]["id"] == "full-route"), None)
    if route is None:
        raise Invalid("original-full-case-missing")
    descriptor, lowered = route_module.lower_route(route, boundary_call_limit=100_000_000)
    serialized_cap = int.from_bytes(descriptor[120:124], "little") if len(descriptor) >= 124 else -1
    _validate_cap_agreement(100_000_000, serialized_cap)
    if len(descriptor) < 128 or len(descriptor) % 4:
        raise Invalid("serialized-call-cap-mismatch")
    descriptor_path = attempt_dir / "route.gwrc"
    with descriptor_path.open("xb") as stream:
        stream.write(descriptor); stream.flush(); os.fsync(stream.fileno())
    manifest["descriptor_sha256"] = hashlib.sha256(descriptor).hexdigest()
    manifest["lowered_identity"] = lowered.get("identity")
    manifest["status"] = "descriptor-frozen"
    _atomic(attempt_dir / "manifest.json", manifest)
    if _hashes(SOURCE_PATHS) != manifest["candidate_source_sha256"]:
        raise Invalid("source-changed-after-freeze")
    rom = ROOT / "fixtures/phase5-b/game.bin"
    report = attempt_dir / "report.json"
    binary = (ROOT / args.build / "native/tools/session/gw_headless").resolve()
    if not binary.is_file() or binary.is_symlink():
        raise Invalid("headless-binary-missing-or-symlink")
    command = [str(binary), "--route-plan", str(descriptor_path), "--route-report", str(report), str(rom)]
    manifest["status"] = "launch-ready"
    _atomic(attempt_dir / "manifest.json", manifest)
    if spawn is not None:
        receipt = spawn(command, ROOT, attempt_dir, report, GROUP_LIMIT)
    else:
        receipt = run_named49(command, ROOT, attempt_dir, report, GROUP_LIMIT)
    manifest.update({key: receipt.get(key) for key in (
        "process_creation_attempted", "process_started", "process_exit_code", "process_reaped", "failure")})
    manifest["status"] = "process-reaped" if receipt.get("process_started") and receipt.get("process_reaped") else "creation-denied"
    counter_safety_fault = False
    if report.exists() and report.stat().st_size <= REPORT_LIMIT:
        manifest["report_sha256"] = _sha(report)
        try:
            row = _json(report)
            manifest["actual_boundary_calls"] = row.get("boundary_calls")
            manifest["actual_fields"] = row.get("fields")
            manifest["actual_source_steps"] = row.get("active_ticks")
            input_rows = row.get("inputs")
            manifest["actual_events"] = len(input_rows) if isinstance(input_rows, list) else None
            manifest["queue_high_water"] = row.get("queue_high_water")
            manifest["stop_reason"] = row.get("stop_reason")
            manifest["first_stop_tick"] = row.get("first_stop_tick")
            manifest["predicates"] = row.get("predicates")
            manifest["inputs"] = row.get("inputs")
            if (row.get("selected_boundary_calls") != 100_000_000 or
                    type(row.get("boundary_calls")) is not int or not 0 <= row["boundary_calls"] <= 100_000_000 or
                    type(row.get("fields")) is not int or not 0 <= row["fields"] <= 7200 or
                    type(row.get("active_ticks")) is not int or not 0 <= row["active_ticks"] <= 3600 or
                    not isinstance(input_rows, list) or len(input_rows) > 64 or
                    type(row.get("queue_high_water")) is not int or not 0 <= row["queue_high_water"] <= 64 or
                    type(row.get("boundary_attempts")) is not int or
                    row["boundary_attempts"] != row["boundary_calls"] + row.get("rejected_boundary_attempts", 0)):
                counter_safety_fault = True
                raise Invalid("native-counter-or-selected-cap-mismatch")
        except (Invalid, ValueError) as error:
            manifest["failure"] = "report-parse:" + str(error)
    else:
        manifest["failure"] = manifest.get("failure") or "report-missing-or-oversized"
    _atomic(attempt_dir / "manifest.json", manifest)
    runtime = _runtime()
    if receipt.get("process_started"):
        runtime["workload_os_starts_observed"] = runtime.get("workload_os_starts_observed", 0) + 1
        runtime["workload_groups_started"] = runtime.get("workload_groups_started", 0) + 1
    if receipt.get("process_started"):
        runtime["workload_wall_seconds"] += min(float(receipt.get("wall_seconds", GROUP_LIMIT)), GROUP_LIMIT)
        if type(manifest.get("actual_boundary_calls")) is int:
            runtime["actual_boundary_calls"] += manifest["actual_boundary_calls"]
        else:
            runtime["unknown_boundary_calls_reserved"] += 100_000_000
        runtime["physical_fields"] += manifest.get("actual_fields") if type(manifest.get("actual_fields")) is int else 7200
        runtime["completed_source_steps"] += manifest.get("actual_source_steps") if type(manifest.get("actual_source_steps")) is int else 3600
        if type(manifest.get("actual_events")) is int:
            runtime["actual_events"] += manifest["actual_events"]
        else:
            runtime["unknown_events_reserved"] += 64
    for attempt in runtime["attempts"]:
        if attempt["attempt_id"] == attempt_dir.name:
            attempt["status"] = manifest["status"]
            attempt["actual_boundary_calls"] = manifest.get("actual_boundary_calls")
            attempt["source_steps"] = manifest.get("actual_source_steps")
            attempt["fields"] = manifest.get("actual_fields")
    for group in runtime["groups"]:
        if group["group_id"] == attempt_dir.name:
            group["status"] = "reaped" if receipt.get("process_started") and receipt.get("process_reaped") else "creation-denied"
            group["observed_wall_seconds"] = receipt.get("wall_seconds")
    _atomic(RUNTIME, runtime)
    _disk(attempt_dir)
    if counter_safety_fault:
        runtime["status"] = "halted-native-counter-or-cap-mismatch"
        _atomic(RUNTIME, runtime)
        raise Invalid("native-counter-or-selected-cap-mismatch")
    if not receipt.get("process_started") or not receipt.get("process_reaped") or not report.exists():
        raise Invalid("tracer-start-reap-or-report-missing")
    manifest["outcome"] = "process-zero-with-report" if receipt.get("process_exit_code") == 0 else "nonzero-exit-with-retained-report"
    _atomic(attempt_dir / "manifest.json", manifest)
    return {"attempt": str(attempt_dir.relative_to(ROOT)), "manifest": manifest,
            "receipt": receipt, "selected": selected["plan_sha256"]}


def consume_attempt49(root):
    """Read-only retained check; does not import route tools or launch work."""
    rows = []
    for manifest_path in sorted((root / "attempts").glob("*/manifest.json")):
        manifest = _json(manifest_path)
        rows.append({"attempt_id": manifest.get("attempt_id"), "status": manifest.get("status"),
                     "source_sha256": manifest.get("candidate_source_sha256"),
                     "calls": manifest.get("actual_boundary_calls"),
                     "fields": manifest.get("actual_fields"),
            "steps": manifest.get("actual_source_steps"),
            "events": manifest.get("actual_events"),
            "queue_high_water": manifest.get("queue_high_water")})
    return {"schema": "genewhip-plan49-retained-check-v1", "attempts": rows}


class Writer:
    def __enter__(self):
        try:
            self.fd = os.open(WRITER_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as error:
            raise Invalid("writer-lock-exists-or-interrupted-run") from error
        os.write(self.fd, f"pid={os.getpid()} utc={dt.datetime.now(dt.timezone.utc).isoformat()}\n".encode())
        os.fsync(self.fd)
        os.close(self.fd)
        return self

    def __exit__(self, *_):
        WRITER_LOCK.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("tracer", "feedback", "qualify", "affected"))
    parser.add_argument("--selection", type=pathlib.Path)
    parser.add_argument("--review", type=pathlib.Path)
    parser.add_argument("--build", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--check-stage", choices=("tracer", "feedback"))
    parser.add_argument("--root", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        if args.check_stage:
            if not args.root:
                raise Invalid("retained-root-required")
            result = consume_attempt49(args.root)
            print(json.dumps(result, sort_keys=True))
            return 0
        if not all((args.stage, args.selection, args.review, args.build, args.output)):
            parser.error("stage execution needs --stage, --selection, --review, --build and --output")
        _verify_selection(args.selection, args.review)
        args.output.mkdir(parents=True, exist_ok=True)
        with Writer():
            runtime = _runtime()
            if any(group.get("status") in ("reserved", "creation-attempted", "running")
                   for group in runtime.get("groups", [])) or _unresolved_process_receipts():
                raise Invalid("unresolved-prior-process-group")
            result = launch_checked49(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Invalid, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("REJECT: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
