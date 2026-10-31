#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite Plan48 launcher. No legacy executor or accounting imports.

Group supervision follows phase4_game.bounded_run and Plan47's retained-file
mechanics; copied locally so those executable modules are never imported.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
REL = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes"
EVIDENCE = ROOT / REL / "48-evidence"
PLAN_SHA256 = "3932a45adb6f63de2e87952d2a94f89c29b1574e9a86faa0816982c512015cf6"
WINDOW = EVIDENCE / "window-forward.json"
WRITER_LOCK = EVIDENCE / "writer-forward.lock"
STREAM_LIMIT = 1 << 20
REPORT_LIMIT = 8 << 20
RAW_LIMIT = 256 << 20
TREE_LIMIT = 8 << 30
SOURCE_PATHS = ("scripts/evidence/phase6_feedback48.py", "tests/evidence/phase6_feedback48_contract.py",
                "scripts/evidence/phase6_routes.py", "tools/session/route_controller.c",
                "tools/headless/main.c", "tests/fixtures/phase4_game.py", "src/bus.c", "src/cpu68000.c")
SOURCE_PATHS += ("tests/api/phase6_repairs_contract.c",)
SOURCE_PATHS += ("src/z80_bus.c", REL + "/48-evidence/integration_checks.py")
HOST_WORK_REL = REL + "/48-evidence/host-work-continuation.json"
# Authority bytes are reviewed and frozen with the source before every launch.
SOURCE_PATHS += (HOST_WORK_REL,)
SOURCE_PATHS += (REL + "/48-evidence/qualify48.py",)
QUALIFICATION_SLOTS = (("48-qual-tank-001", "tank", 1000000),
                       ("48-qual-tank-002", "tank", 1000000),
                       ("48-qual-control-001", "control", 0),
                       ("48-qual-control-002", "control", 0))
_QUALIFICATION_TOKEN = object()
COUNT_PREFIX_KEYS = ("authored_native", "control_children", "control_drivers", "ctest_direct",
                     "misclassified_prior_native_cap_starts", "python_direct", "setup_direct", "tank_launches")
RESOURCE_PREFIX_KEYS = ("authored_call_reserved", "ctest_test_binary_reserved", "nonworkload_reserved",
                        "nonworkload_seconds", "prior_nonworkload_upper_bound_seconds",
                        "prior_unvalidated_workload_reserved_seconds", "setup_reserved", "setup_seconds",
                        "tank_call_actual", "tank_call_charged", "tank_call_reserved", "tank_workload_reserved",
                        "tank_workload_seconds", "workload_reserved", "workload_seconds", "workload_starts")
TESTS = ("load_contract", "time_contract", "reset_contract", "bus_boundary_contract",
         "gameplay_bus_contract", "movem_contract", "phase6_repairs_contract")


class Invalid(ValueError):
    pass


def sha(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate-json-key")
        result[key] = value
    return result


def load(path, limit=REPORT_LIMIT):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise Invalid("missing-or-oversized-json")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Invalid("nonfinite-json")))


def create_json(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def _save_window(data):
    temporary = WINDOW.with_suffix(".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, WINDOW)


def _clock(data, exposure=0):
    if data.get("started_utc") != "2026-10-27T14:24:16Z" or data.get("deadline_utc") != "2026-10-27T18:24:16Z":
        raise Invalid("window-clock-identity")
    utc_left = datetime.datetime.fromisoformat(data["deadline_utc"].replace("Z", "+00:00")).timestamp() - time.time()
    anchor = data["monotonic_dispatch_anchor_seconds"]
    if type(anchor) not in (float, int) or not 0 < anchor < time.monotonic():
        raise Invalid("invalid-monotonic-anchor")
    mono_left = 14400 - (time.monotonic() - anchor)
    left = min(utc_left, mono_left)
    if left < exposure + 900:
        raise Invalid("deadline-plus-terminal-reserve")
    return left


def validate_selection48(root, selection_path, cap=None):
    if sha(root / REL / "06-48-PLAN.md") != PLAN_SHA256:
        raise Invalid("selected-plan-bytes-changed")
    selected = load(selection_path)
    expected = {"tank_attempts_including_qualification": 12, "control_driver_attempts": 4,
                "control_native_children": 24, "total_workload_starts": 40,
                "tank_call_budget": 100000000, "tank_call_tiers": [1000000, 5000000, 20000000],
                "workload_wall_seconds": 7200, "whole_window_seconds": 14400,
                "terminal_reserve_seconds": 900, "evidence_tree_bytes": TREE_LIMIT}
    if (selected.get("plan_sha256") != PLAN_SHA256 or
            selected.get("dispatch_started_utc") != "2026-10-27T14:24:16Z" or
            any(selected.get("limits", {}).get(k) != v for k, v in expected.items())):
        raise Invalid("selection-mismatch")
    authority = load(root / REL / "48-evidence/forward-continuation.json")
    if (authority.get("user_response") != "Authorize this scope correction and continue (Recommended)" or
            authority.get("deadline_utc") != "2026-10-27T18:24:16Z"):
        raise Invalid("forward-authority-missing")
    if cap is not None and (type(cap) is not int or cap not in expected["tank_call_tiers"]):
        raise Invalid("unselected-cap")
    validate_host_work48(root)
    return selected


def validate_host_work48(root):
    """Only the actual prospective host-count correction changes admission."""
    authority = load(root / HOST_WORK_REL)
    preserved = {
        "original_start_utc": "2026-10-27T14:24:16Z", "deadline_utc": "2026-10-27T18:24:16Z",
        "terminal_start_utc": "2026-10-27T18:09:16Z", "setup_wall_seconds": 2400,
        "nonworkload_wall_seconds": 3600, "setup_watchdog_seconds": 600,
        "ctest_watchdog_seconds": 120, "ordinary_python_watchdog_seconds": 55,
        "build_parallelism": 2, "tank_launches": 12, "control_drivers": 4,
        "control_children": 24, "workload_os_starts": 40, "tank_call_budget": 100000000,
        "authored_executions": 96, "authored_calls": 6144, "authored_fields_each": 1,
        "authored_seconds_each": 5, "workload_wall_seconds": 7200,
        "streams_bytes_each": 1048576, "evidence_and_build_bytes": 8589934592,
        "workload_watchdog_seconds": 600, "authored_calls_each": 64, "authored_events_each": 16,
        "tank_call_tiers": [1000000, 5000000, 20000000], "native_report_bytes": 8388608,
        "authored_report_bytes": 1048576, "trace_bytes_each": 16777216,
        "trace_rows_each": 100000, "attempt_bytes": 268435456,
        "control_attempt_bytes": 1073741824, "aggregate_raw_bytes": 268435456,
    }
    removed = {"setup_direct": 16, "ctest_direct": 20, "python_direct": 40,
               "ctest_test_binary_reserved": 140}
    if (authority.get("schema") != "genewhip-plan48-host-work-forward-authority-v1" or
            authority.get("actual_user_excerpts") != [
                "find set of recommendations that are coherent auto follow those...",
                "<-- fan out plan it out and unblock and then move us forward ...."] or
            authority.get("removed_host_count_ceilings") != removed or
            any(type(authority.get("preserved", {}).get(k)) is not type(v) or
                authority["preserved"][k] != v for k, v in preserved.items())):
        raise Invalid("host-work-authority-mismatch")
    for section, keys in (("consumed_at_authority", COUNT_PREFIX_KEYS),
                          ("resources_at_authority", RESOURCE_PREFIX_KEYS)):
        snapshot = authority.get(section, {})
        if not isinstance(snapshot, dict) or any(
                type(snapshot.get(k)) not in ((int,) if section == "consumed_at_authority" else (int, float)) or
                not 0 <= snapshot[k] < float("inf") for k in keys):
            raise Invalid("host-work-authority-prefix-invalid")
    return authority


def validate_cap48(descriptor, selected, *, authored=False):
    maximum = 64 if authored else 20_000_000
    if type(selected) is not int or not 1 <= selected <= maximum:
        raise Invalid("selected-cap-range")
    if not isinstance(descriptor, bytes) or len(descriptor) < 128 or len(descriptor) > 1048576 or len(descriptor) % 4:
        raise Invalid("descriptor-length")
    words = struct.unpack("<" + "I" * (len(descriptor) // 4), descriptor)
    if words[0] != int.from_bytes(b"GWRC", "little") or words[1] != 1 or words[31]:
        raise Invalid("descriptor-header")
    if words[30] != selected:
        raise Invalid("serialized-cap-disagrees-with-selection")
    if words[2] not in (1, 2, 3) or not 1 <= words[3] <= (1 if authored else 4500) or not 1 <= words[4] <= (1 if authored else 3600):
        raise Invalid("descriptor-bounds")
    counts, strides = words[6:14], (4, 2, 5, 2, 4, 3, 6, 4)
    if (not 1 <= counts[0] <= 128 or counts[6] > (16 if authored else 64) or
            sum(counts) > 4096 or 32 + sum(a * b for a, b in zip(counts, strides)) != len(words)):
        raise Invalid("descriptor-section-length")
    return words


def fingerprint(descriptor):
    value = 14695981039346656037
    for byte in descriptor:
        value = ((value ^ byte) * 1099511628211) & 0xffffffffffffffff
    return f"{value:016x}"


def _identities(paths):
    return {str(path): sha(path) for path in paths}


def _same(identities):
    if any(sha(path) != digest for path, digest in identities.items()):
        raise Invalid("frozen-identity-changed")


def _review(path):
    record = load(path)
    actual = {name: sha(ROOT / name) for name in SOURCE_PATHS}
    if (record.get("schema") != "genewhip-plan48-source-review-v1" or
            record.get("reviewer_identity") != "/root/repair_and_feedback48/review48" or
            record.get("verdict") != "ACCEPT" or record.get("findings") != [] or
            any(record.get("source_hashes", {}).get(k) != v for k, v in actual.items())):
        raise Invalid("independent-source-review-mismatch")
    return actual


def _bind_review(path, frozen, expected_sources, expected_review_sha):
    """Reject changes between review validation, identity capture and launch."""
    _same(frozen)
    if sha(path) != expected_review_sha:
        raise Invalid("review-receipt-changed-before-launch")
    current = _review(path)
    if current != expected_sources or any(frozen.get(str(ROOT / name)) != digest for name, digest in current.items()):
        raise Invalid("review-to-frozen-source-race")
    if sha(path) != expected_review_sha:
        raise Invalid("review-receipt-changed-during-read")
    _same(frozen)


def _bind_selection(path, frozen, expected_sha):
    if sha(path) != expected_sha or frozen.get(str(pathlib.Path(path).resolve())) != expected_sha:
        raise Invalid("selection-to-frozen-identity-race")
    validate_selection48(ROOT, path)
    _same(frozen)


def _live_files(root):
    """Observe each live entry once; successful workspace cleanup may race us."""
    for path in root.rglob("*"):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise Invalid("attempt-symlink")
        if stat.S_ISREG(metadata.st_mode):
            yield path, metadata.st_size


def _size(root):
    return sum(size for _, size in _live_files(root))


def _disk(output, control=False):
    if _size(output) > (1 << 30 if control else 256 << 20):
        raise Invalid("attempt-disk-limit")
    if sum(_size(p) for p in (EVIDENCE, ROOT / "build/phase6-feedback48", ROOT / "build/phase6-feedback48-sanitize")) > TREE_LIMIT:
        raise Invalid("aggregate-evidence-build-limit")
    raw_bytes = 0
    for path, size in _live_files(EVIDENCE):
        if path.name.endswith(("stdout.bin", "stderr.bin", ".raw")) or "trace" in path.name:
            raw_bytes += size
    if raw_bytes > RAW_LIMIT:
        raise Invalid("aggregate-raw-limit")
    for path, size in _live_files(output):
        if path.name.endswith(("stdout.bin", "stderr.bin", ".raw")) and size > STREAM_LIMIT:
            raise Invalid("descendant-stream-limit")
        if "trace" in path.name:
            if size > 16 << 20:
                raise Invalid("trace-byte-limit")
            try:
                with path.open("rb") as stream:
                    if sum(1 for _ in stream) > 100000:
                        raise Invalid("trace-row-limit")
            except FileNotFoundError:
                continue
        if path.name in ("native.json", "report.json") and size > REPORT_LIMIT:
            raise Invalid("report-limit")


class Writer:
    def __enter__(self):
        try:
            self.fd = os.open(WRITER_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as error:
            raise Invalid("another-or-interrupted-plan48-writer") from error
        os.write(self.fd, f"pid={os.getpid()}\n".encode())
        os.close(self.fd)
        return self

    def __exit__(self, *_):
        WRITER_LOCK.unlink()


def _consumed_prefix48(data, authority):
    counts, resources = data["counts"], data["resources"]
    for current, snapshot, keys in (
            (counts, authority["consumed_at_authority"], COUNT_PREFIX_KEYS),
            (resources, authority["resources_at_authority"], RESOURCE_PREFIX_KEYS)):
        # These are consumed-prefix floors, not last in-flight reservations.
        # Setup/nonworkload reserved baselines are zero; workload's 1800s
        # unknown historical exposure remains reserved after every settlement.
        numeric_types = (int,) if current is counts else (int, float)
        if any(type(current.get(k)) not in numeric_types or
               not snapshot[k] <= current[k] < float("inf") for k in keys):
            raise Invalid("lost-host-authority-consumption")
    if counts["tank_launches"] < 4 or resources["workload_starts"] < 4 or resources["tank_call_actual"] < 16:
        raise Invalid("lost-historical-consumption")


def reserve48(lane, *, cap=0, qualification=False, roster=1, exposure=600):
    authority = validate_host_work48(ROOT)
    data = load(WINDOW)
    if data.get("safety_stop"):
        raise Invalid("prior-enforcement-safety-stop")
    if qualification:
        raise Invalid("qualification-requires-atomic-reviewed-full-batch")
    if data.get("qualification_batch"):
        raise Invalid("qualification-batch-holds-active")
    _clock(data, exposure)
    _consumed_prefix48(data, authority)
    counts, resources = data["counts"], data["resources"]
    if lane in ("setup", "ctest", "python"):
        # Counts stay cumulative observations; only their ceilings were removed.
        key, increment = lane + "_direct", roster
    else:
        key, increment, limit = {"tank": ("tank_launches", 1, 12),
                                 "control": ("control_drivers", 1, 4),
                                 "authored": ("authored_native", roster, 96)}[lane]
        if counts[key] + increment > limit:
            raise Invalid("lane-count-exhausted")
    if lane in ("tank", "control"):
        spare_tank, spare_driver, spare_children = (0, 0, 0) if qualification else (2, 2, 12)
        starts = 1 if lane == "tank" else 7
        if (counts["tank_launches"] + (lane == "tank") + spare_tank > 12 or
                counts["control_drivers"] + (lane == "control") + spare_driver > 4 or
                counts["control_children"] + (6 if lane == "control" else 0) + spare_children > 24 or
                resources["workload_starts"] + starts + spare_tank + spare_driver + spare_children > 40 or
                resources.get("tank_call_charged", resources["tank_call_reserved"]) + cap + (0 if qualification else 2_000_000) > 100_000_000 or
                resources.get("workload_seconds", resources["tank_workload_seconds"]) + resources.get("workload_reserved", resources.get("tank_workload_reserved", 0)) + exposure + (0 if qualification else 2400) > 7200):
            raise Invalid("full-qualification-reserve-exhausted")
        _clock(data, exposure + (0 if qualification else 2400))
        resources["workload_starts"] += starts
        resources["tank_call_reserved"] += cap
        resources["tank_call_charged"] = resources.get("tank_call_charged", resources["tank_call_reserved"] - cap) + cap
        resources["workload_reserved"] = resources.get("workload_reserved", resources.get("tank_workload_reserved", 0)) + exposure
        counts["control_children"] += 6 if lane == "control" else 0
    else:
        if resources.get("nonworkload_seconds", 0) + resources.get("nonworkload_reserved", 0) + exposure > 3600:
            raise Invalid("nonworkload-wall-exhausted")
        if lane == "setup" and resources.get("setup_seconds", 0) + resources.get("setup_reserved", 0) + exposure > 2400:
            raise Invalid("setup-wall-exhausted")
        resources["nonworkload_reserved"] = resources.get("nonworkload_reserved", 0) + exposure
        if lane == "setup":
            resources["setup_reserved"] = resources.get("setup_reserved", 0) + exposure
        if lane == "ctest":
            # Existing five direct batches conservatively reserve seven each.
            prior = resources.get("ctest_test_binary_reserved", 35)
            resources["ctest_test_binary_reserved"] = prior + roster * 7
        if lane == "authored":
            prior = resources.get("authored_call_reserved", 0)
            if prior + roster * 64 > 6144:
                raise Invalid("authored-call-roster-exhausted")
            resources["authored_call_reserved"] = prior + roster * 64
    counts[key] += increment
    _save_window(data)
    return {"lane": lane, "cap": cap, "exposure": exposure}


def charge48(reservation, process, actual=None):
    data = load(WINDOW)
    if "qualification_slot" in reservation:
        q = data.get("qualification_batch", {})
        index = reservation["qualification_slot"]
        if (q.get("status") != "active" or q.get("next") != index or
                q.get("pending") != QUALIFICATION_SLOTS[index][0]):
            raise Invalid("qualification-slot-already-charged-or-not-pending")
        q["remaining_wall"] -= 600
        q["next"] += 1
        q["pending"] = None
    resources = data["resources"]
    lane, exposure = reservation["lane"], reservation["exposure"]
    wall = process["wall_seconds"]
    if lane in ("tank", "control"):
        resources["workload_reserved"] -= exposure
        resources["workload_seconds"] = resources.get("workload_seconds", resources["tank_workload_seconds"]) + wall
        if lane == "tank":
            resources["tank_workload_seconds"] += wall
            if actual is not None:
                resources["tank_call_actual"] += actual
                resources["tank_call_charged"] -= reservation["cap"] - actual
    else:
        resources["nonworkload_reserved"] -= exposure
        resources["nonworkload_seconds"] = resources.get("nonworkload_seconds", 0) + wall
        if lane == "setup":
            resources["setup_reserved"] -= exposure
            resources["setup_seconds"] = resources.get("setup_seconds", 0) + wall
    _save_window(data)


def _qualification_writer48():
    if WRITER_LOCK.is_symlink() or not WRITER_LOCK.is_file() or WRITER_LOCK.read_text() != f"pid={os.getpid()}\n":
        raise Invalid("qualification-requires-current-writer")


def begin_qualification48(frozen, directory):
    """Hold one fixed batch atomically; held slots are not observed starts."""
    _qualification_writer48()
    authority, data = validate_host_work48(ROOT), load(WINDOW)
    _consumed_prefix48(data, authority)
    if data.get("safety_stop") or data.get("qualification_batch"):
        raise Invalid("qualification-batch-spent-or-safety-stop")
    _same(frozen)
    _clock(data, 2400)
    _disk(directory, control=True)
    # Four attempt maxima, all raw-prefix room, and the whole tree must fit.
    if (_size(EVIDENCE) + _size(ROOT / "build/phase6-feedback48") +
            _size(ROOT / "build/phase6-feedback48-sanitize") + (256 << 20) * 2 + (1 << 30) * 2 > TREE_LIMIT):
        raise Invalid("qualification-batch-disk-reserve")
    raw = sum(p.stat().st_size for p in EVIDENCE.rglob("*") if p.is_file() and not p.is_symlink() and
              (p.name.endswith(("stdout.bin", "stderr.bin", ".raw")) or "trace" in p.name))
    # Two Tank streams pairs plus two drivers and their twelve native pairs.
    if raw + 32 * STREAM_LIMIT + 2 * (16 << 20) > RAW_LIMIT:
        raise Invalid("qualification-batch-raw-reserve")
    c, r = data["counts"], data["resources"]
    if (c["tank_launches"] + 2 > 12 or c["control_drivers"] + 2 > 4 or
            c["control_children"] + 12 > 24 or r["workload_starts"] + 16 > 40 or
            r["tank_call_charged"] + 2000000 > 100000000 or
            r["workload_seconds"] + r["workload_reserved"] + 2400 > 7200):
        raise Invalid("full-qualification-reserve-exhausted")
    r["workload_reserved"] += 2400
    r["tank_call_charged"] += 2000000
    r["tank_call_reserved"] += 2000000
    data["qualification_batch"] = {"schema": "genewhip-plan48-fixed-qualification-v1", "status": "active",
        "slots": [list(slot) for slot in QUALIFICATION_SLOTS], "next": 0, "pending": None,
        "remaining_wall": 2400, "held_calls": 2000000,
        "held_counts": {"tank_launches": 2, "control_drivers": 2, "control_children": 12, "workload_starts": 16},
        "candidate_identities": frozen, "directory": str(directory), "qualified": False}
    _save_window(data)
    return data["qualification_batch"]


def _qualification_slot48(args, data):
    q = data.get("qualification_batch", {})
    index = q.get("next", 4)
    if (getattr(args, "_qualification_context", None) is not _QUALIFICATION_TOKEN or
            q.get("status") != "active" or q.get("pending") is not None or
            q.get("slots") != [list(slot) for slot in QUALIFICATION_SLOTS] or not 0 <= index < 4 or
            (args.attempt_id, args.kind, args.call_cap or 0) != QUALIFICATION_SLOTS[index] or
            args.output.resolve() != pathlib.Path(q["directory"]) / (args.attempt_id + ".json")):
        raise Invalid("qualification-requires-matching-next-fixed-slot")
    _same(q["candidate_identities"])
    return q, index


def claim_qualification48(args):
    _qualification_writer48()
    data = load(WINDOW)
    _consumed_prefix48(data, validate_host_work48(ROOT))
    if data.get("safety_stop"):
        raise Invalid("prior-enforcement-safety-stop")
    q, index = _qualification_slot48(args, data)
    _clock(data, q["remaining_wall"])
    _disk(pathlib.Path(q["directory"]), control=True)
    counts, resources = data["counts"], data["resources"]
    increments = {"tank_launches": 1, "workload_starts": 1} if args.kind == "tank" else {
        "control_drivers": 1, "control_children": 6, "workload_starts": 7}
    for key, increment in increments.items():
        if q["held_counts"][key] < increment:
            raise Invalid("qualification-held-count-underflow")
        q["held_counts"][key] -= increment
        (resources if key == "workload_starts" else counts)[key] += increment
    if args.kind == "tank":
        q["held_calls"] -= 1000000
    else:
        counts["python_direct"] += 1  # actual original control-driver interpreter
    q["pending"] = args.attempt_id
    _save_window(data)  # durable spent slot immediately before OS creation
    return {"lane": args.kind, "cap": args.call_cap or 0, "exposure": 600, "qualification_slot": index}


def finish_qualification48(success):
    _qualification_writer48()
    data = load(WINDOW)
    q = data["qualification_batch"]
    complete = q["next"] == 4 and q["pending"] is None
    q["status"] = "captured-frozen-batch" if success and complete else "stopped"
    q["qualified"] = False
    _save_window(data)
    return q


def run_bounded(command, cwd, output_dir, report_path, timeout=600, *, control=False, authored=False, inherited_group=False):
    """Retain bounded prefixes and a receipt on every exit, including creation failure."""
    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    receipt = {"process_attempted": True, "process_started": False, "process_reaped": False,
               "returncode": None, "failure": None, "command_sha256": hashlib.sha256(json.dumps(command).encode()).hexdigest()}
    proc = None
    selector = selectors.DefaultSelector()
    streams = {}
    try:
        for name in ("stdout", "stderr"):
            streams[name] = (output_dir / (name + ".bin")).open("xb")
        _clock(load(WINDOW), timeout)
        _disk(output_dir, control)
        proc = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=not inherited_group, bufsize=0)
        receipt.update(process_started=True, pid=proc.pid, pgid=os.getpgid(proc.pid), inherited_group=inherited_group)
        for name in streams:
            selector.register(getattr(proc, name), selectors.EVENT_READ, name)
        lengths = dict.fromkeys(streams, 0)
        while selector.get_map() or proc.poll() is None:
            if time.monotonic() - started > timeout:
                raise Invalid("process-group-wall-limit")
            _clock(load(WINDOW), 0)
            _disk(output_dir, control)
            if report_path.exists() and report_path.stat().st_size > (1 << 20 if authored else REPORT_LIMIT):
                raise Invalid("report-limit")
            for key, _ in selector.select(.05):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                room = STREAM_LIMIT - lengths[key.data]
                streams[key.data].write(block[:room])
                streams[key.data].flush()
                lengths[key.data] += min(len(block), room)
                if len(block) > room:
                    raise Invalid("process-stream-limit")
        _disk(output_dir, control)
    except BaseException as error:
        receipt["failure"] = type(error).__name__ + ":" + str(error)
    finally:
        if proc is not None:
            # Kill surviving descendants even if the direct process exited first.
            if inherited_group:
                # Only trusted authored native binaries use this opt-in. The
                # owning contract's outer watchdog supervises the whole group.
                if proc.poll() is None:
                    proc.kill()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait()
            receipt.update(returncode=proc.returncode, process_reaped=True)
        selector.close()
        if proc is not None:
            proc.stdout.close()
            proc.stderr.close()
        for stream in streams.values():
            stream.close()
        receipt["wall_seconds"] = round(time.monotonic() - started, 6)
        for name in streams:
            path = output_dir / (name + ".bin")
            receipt[name + "_bytes"] = path.stat().st_size
            receipt[name + "_sha256"] = sha(path)
        create_json(output_dir / "process.json", receipt)
    return receipt


def launch_checked48(descriptor, selected, identities, launcher, *args, authored=False):
    """The production seam, shared with no-process tests; fake only launcher."""
    validate_cap48(descriptor, selected, authored=authored)
    _same(identities)
    result = launcher(*args)
    _same(identities)
    return result


def consume_attempt48(raw, descriptor, selected, process, *, authored=False):
    words = validate_cap48(descriptor, selected, authored=authored)
    if not isinstance(raw, dict) or raw.get("schema") != "genewhip-route-native-v1":
        raise Invalid("native-schema")
    names = ("selected_boundary_calls", "boundary_calls", "boundary_attempts", "rejected_boundary_attempts")
    if any(type(raw.get(name)) is not int or raw[name] < 0 for name in names):
        raise Invalid("counter-type-or-negative")
    cap, calls, attempts, rejected = (raw[name] for name in names)
    if cap != selected or calls > cap or rejected not in (0, 1) or attempts != calls + rejected or (rejected and calls != cap):
        raise Invalid("counter-contradiction")
    if raw.get("plan_fnv1a64") != fingerprint(descriptor):
        raise Invalid("native-descriptor-identity")
    if process.get("failure") or process.get("process_reaped") is not True or process.get("returncode") not in (0, 1):
        raise Invalid("native-process-failure")
    if type(raw.get("status")) is not int or type(raw.get("fields")) is not int or not 0 <= raw["fields"] <= words[3]:
        raise Invalid("native-status-or-fields")
    if not isinstance(raw.get("samples"), list) or len(raw["samples"]) > (4096 if authored else 100000):
        raise Invalid("native-sample-bound")
    if (raw["status"] == 0) != (process["returncode"] == 0) or raw.get("termination") != ("error" if raw["status"] else "active-limit") and not (raw["status"] == 0 and raw.get("termination") == "field-limit"):
        raise Invalid("native-status-termination")
    if rejected and raw["status"] != 8:
        raise Invalid("capacity-rejection-status")
    return {"boundary_calls_actual": calls, "boundary_attempts_rejected": rejected,
            "counter_check": "bounded", "native_schema_check": "complete" if raw["status"] == 0 else "partial",
            "predicates": raw.get("predicates", [])}


def _routes():
    spec = importlib.util.spec_from_file_location("phase6_routes48_subject", ROOT / "scripts/evidence/phase6_routes.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_attempt48(args):
    if getattr(args, "qualification", False):
        _qualification_slot48(args, load(WINDOW))
    if args.kind == "tank" and args.call_cap != 1_000_000:
        raise Invalid("escalation-requires-retained-safe-cap-and-new-hypothesis")
    validate_selection48(ROOT, args.selection, args.call_cap if args.kind == "tank" else None)
    source_hashes = _review(args.source_review)
    _clock(load(WINDOW), 0)
    output = args.output.resolve()
    if output.exists() or output.is_symlink() or not output.is_relative_to(EVIDENCE):
        raise Invalid("spent-or-outside-evidence-output")
    if args.build.resolve() != ROOT / "build/phase6-feedback48":
        raise Invalid("unselected-build-tree")
    return source_hashes


def _public_identity(identities):
    return {pathlib.Path(path).relative_to(ROOT).as_posix(): digest for path, digest in identities.items()}


def _control_consume(raw, binary, children_path):
    cases = ("title-no-start", "start-idle", "start-move", "action-sound", "action-no-trigger", "sustained-play")
    fields = (12, 20, 40, 24, 24, 720)
    rows = raw.get("results", [])
    if (raw.get("schema") != "genewhip-phase4-gameplay-v1" or raw.get("outcome") != "pass" or
            raw.get("denominator") != 6 or raw.get("fields") != 840 or raw.get("clients") != ["headless"] or
            raw.get("client_sha256") != [sha(binary)] or len(rows) != 6):
        raise Invalid("control-denominator")
    for row, case, count in zip(rows, cases, fields):
        if row.get("id") != case or row.get("fields") != count or row.get("outcome") != "pass" or row.get("unsupported") != 0:
            raise Invalid("control-case")
        pcm = row.get("retained_pcm", {})
        path = ROOT / pcm.get("path", "")
        if (not path.is_file() or not path.resolve().is_relative_to(EVIDENCE) or pcm.get("sha256") != sha(path) or
                pcm.get("bytes") != path.stat().st_size or type(row.get("pcm_frames")) is not int or
                row["pcm_frames"] != count * 896040 * 48000 // 53693175 or path.stat().st_size != row["pcm_frames"] * 4):
            raise Invalid("control-complete-pcm")
    children = raw.get("native_child_processes", [])
    if len(children) != 6 or any(row.get("return_code") != 0 for row in children):
        raise Invalid("control-child-receipts")
    receipts = load(children_path).get("processes", [])
    if len(receipts) != 6 or any(row.get("returncode") != 0 or row.get("outer_process_group") is not True or
            row.get("pgid") != row.get("driver_pgid") or row.get("status") != "finished" for row in receipts):
        raise Invalid("control-inherited-process-group")
    return {"control_check": "complete-six-cases-full-pcm", "case_count": 6}


def run_attempt48(args):
    selection_digest = sha(args.selection)
    review_digest = sha(args.source_review)
    sources = prepare_attempt48(args)
    if not args.attempt_id or not args.attempt_id.startswith("48-") or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in args.attempt_id):
        raise Invalid("attempt-id")
    output = args.output.resolve()
    raw_dir = output.parent / (args.attempt_id + "-raw")
    raw_dir.mkdir(parents=True, exist_ok=False)
    binary = args.build.resolve() / "tools/session/gw_headless"
    paths = [ROOT / path for path in SOURCE_PATHS] + [binary, args.selection.resolve(), args.source_review.resolve(), args.build.resolve() / "CMakeCache.txt"]
    descriptor = None
    metadata = None
    if args.kind == "tank":
        rom = ROOT / "fixtures/phase5-a/game.bin"
        paths.append(rom)
        routes = _routes()
        route = next(r for r in routes.compile_routes()["routes"] if r["fixture"] == "tank-battle" and r["case"]["id"] == "full-route")
        descriptor, metadata = routes.lower_route(route, args.call_cap)
        validate_cap48(descriptor, args.call_cap)
        plan, report = raw_dir / "route.gwrc", raw_dir / "native.json"
        with plan.open("xb") as stream:
            stream.write(descriptor)
        paths.append(plan)
        command = [str(binary), "--route-plan", str(plan), "--route-report", str(report), str(rom)]
    else:
        paths.extend(ROOT / path for path in ("fixtures/independent-game-v2/game.bin", "fixtures/independent-game-v2/scenario.json", "fixtures/independent-game-v2/oracle.json"))
        report = raw_dir / "report.json"
        command = [sys.executable, "-I", str(ROOT / "tests/fixtures/phase4_game.py"), str(binary),
                   "--outer-process-group", "--report", str(report), "--retain-artifacts", str(raw_dir / "control"),
                   "--process-receipt", str(raw_dir / "children.json")]
    identities = _identities(paths)
    manifest = {"schema": "genewhip-phase6-feedback48-manifest-v1", "attempt_id": args.attempt_id,
                "kind": args.kind, "qualification": args.qualification, "plan_sha256": PLAN_SHA256,
                "selection_sha256": sha(args.selection), "source_sha256": sources,
                "reviewed_source_sha256": sources, "review_path": args.source_review.resolve().relative_to(ROOT).as_posix(),
                "review_sha256": sha(args.source_review), "identities": _public_identity(identities),
                "call_cap_selected": args.call_cap, "call_cap_serialized": args.call_cap,
                "metadata": metadata, "command": [str(pathlib.Path(item).relative_to(ROOT)) if pathlib.Path(item).is_absolute() and pathlib.Path(item).is_relative_to(ROOT) else pathlib.Path(item).name if pathlib.Path(item).is_absolute() else item for item in command],
                "command_sha256": hashlib.sha256(json.dumps(command).encode()).hexdigest()}
    create_json(raw_dir / "manifest.json", manifest)
    reservation = None if args.qualification else reserve48(args.kind, cap=args.call_cap or 0)
    validate_selection48(ROOT, args.selection, args.call_cap)
    _bind_review(args.source_review, identities, sources, review_digest)
    _bind_selection(args.selection, identities, selection_digest)
    _clock(load(WINDOW), 600)
    if args.qualification:
        reservation = claim_qualification48(args)
    if descriptor is None:
        _same(identities)
        process = run_bounded(command, ROOT, raw_dir, report, control=True)
    else:
        process = launch_checked48(descriptor, args.call_cap, identities, run_bounded, command, ROOT, raw_dir, report)
    result = dict(manifest, schema="genewhip-phase6-feedback48-attempt-v1", process=process,
                  outcome="rejected", raw_report_path=report.relative_to(ROOT).as_posix(),
                  raw_report_sha256=sha(report) if report.is_file() else None)
    actual = None
    try:
        _same(identities)
        raw = load(report)
        result["native_report"] = raw
        if args.kind == "tank":
            result.update(consume_attempt48(raw, descriptor, args.call_cap, process))
            actual = result["boundary_calls_actual"]
            result["outcome"] = "partial" if raw["status"] else "bounded-route"
        else:
            if process["failure"] or process["returncode"] != 0:
                raise Invalid("control-driver-failed")
            result.update(_control_consume(raw, binary, raw_dir / "children.json"))
            result["outcome"] = "bounded-control"
    except Exception as error:
        result["rejection"] = str(error)
    finally:
        charge48(reservation, process, actual)
        result["raw_hashes"] = {p.relative_to(ROOT).as_posix(): sha(p) for p in raw_dir.rglob("*") if p.is_file()}
        create_json(output, result)
    return result


def prepare48(args):
    selection_digest = sha(args.selection)
    review_digest = sha(args.source_review)
    sources = prepare_attempt48(args)
    base = args.output.parent / (args.output.stem + "-raw")
    base.mkdir(parents=True, exist_ok=False)
    commands = []
    for tree, sanitize in ((args.build, False), (args.build.with_name(args.build.name + "-sanitize"), True)):
        command = ["cmake", "-S", ".", "-B", str(tree), "-G", "Ninja", "-DBUILD_TESTING=ON",
                   "-DGENEWHIP_BUILD_TOOLS=ON", "-DGENEWHIP_BUILD_DESKTOP=OFF", "-DGENEWHIP_TEST_HOOKS=ON"]
        if sanitize:
            command += ["-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer", "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined"]
        commands += [command, ["cmake", "--build", str(tree), "--parallel", "2", "--target", "gw_headless", *TESTS]]
    # Complete four-command setup maximum is 2400 seconds, plus terminal.
    reservation = reserve48("setup", roster=4, exposure=2400)
    rows = []
    frozen = _identities([ROOT / path for path in SOURCE_PATHS] + [args.selection.resolve(), args.source_review.resolve()])
    for index, command in enumerate(commands):
        _bind_review(args.source_review, frozen, sources, review_digest)
        _bind_selection(args.selection, frozen, selection_digest)
        row = run_bounded(command, ROOT, base / str(index), base / str(index) / "unused-report.json", 600)
        rows.append(row)
        if row["failure"] or row["returncode"]:
            break
    process = {"wall_seconds": sum(row["wall_seconds"] for row in rows)}
    charge48(reservation, process)
    _same(frozen)
    result = {"schema": "genewhip-phase6-feedback48-prepare-v1", "source_sha256": sources,
              "commands": commands, "processes": rows, "outcome": "prepared" if len(rows) == 4 and all(not row["failure"] and row["returncode"] == 0 for row in rows) else "rejected"}
    create_json(args.output, result)
    return result


def _named_build_path48(tree):
    parent, path = ROOT / "build", ROOT / tree
    if (parent.is_symlink() or not parent.is_dir() or parent.resolve() != parent or
            path.is_symlink() or path.exists() and (not path.is_dir() or path.resolve() != path)):
        raise Invalid("named-build-path-symlink-or-outside-tree")


def run_named48(command, lane, output_dir, selection_path, review_path):
    """Reviewed incremental setup/CTest boundary for the existing two trees.

    No arbitrary program dispatch: only a selected CMake build or the named
    seven-test CTest roster/subset. Caller retains the returned raw receipt.
    """
    selection_digest = sha(selection_path)
    validate_selection48(ROOT, selection_path)
    review_digest = sha(review_path)
    reviewed_sources = _review(review_path)
    trees = {"build/phase6-feedback48", "build/phase6-feedback48-sanitize"}
    if lane == "setup":
        build_command = (len(command) >= 7 and command[:2] == ["cmake", "--build"] and
                         command[2] in trees and command[3:6] == ["--parallel", "2", "--target"] and
                         all(target in ("gw_headless", *TESTS) for target in command[6:]) and
                         len(command[6:]) == len(set(command[6:])))
        configure_commands = []
        for tree in sorted(trees):
            configure = ["cmake", "-S", ".", "-B", tree, "-G", "Ninja", "-DBUILD_TESTING=ON",
                         "-DGENEWHIP_BUILD_TOOLS=ON", "-DGENEWHIP_BUILD_DESKTOP=OFF", "-DGENEWHIP_TEST_HOOKS=ON"]
            if tree.endswith("-sanitize"):
                configure += ["-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer",
                              "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined"]
            configure_commands.append(configure)
        valid = build_command or command in configure_commands
        if build_command and not (ROOT / command[2]).is_dir():
            raise Invalid("named-build-tree-missing")
        timeout = 600
    elif lane == "ctest":
        valid = (len(command) == 7 and command[:2] == ["ctest", "--test-dir"] and command[2] in trees and
                 command[3:6] == ["--output-on-failure", "--no-tests=error", "-R"])
        if valid:
            expression = command[6]
            allowed = {"^(" + "|".join(TESTS) + ")$", *("^" + name + "$" for name in TESTS)}
            valid = expression in allowed
        timeout = 120
    else:
        raise Invalid("unselected-named-lane")
    if not valid:
        raise Invalid("unselected-named-command")
    tree = command[4] if command[:2] == ["cmake", "-S"] else command[2]
    _named_build_path48(tree)
    output_dir = pathlib.Path(output_dir).resolve()
    if output_dir.exists() or not output_dir.is_relative_to(EVIDENCE):
        raise Invalid("spent-or-outside-named-output")
    with Writer():
        reserve48("python", exposure=0)
        reservation = reserve48(lane, exposure=timeout)
        output_dir.mkdir(parents=True)
        frozen = _identities([ROOT / path for path in SOURCE_PATHS] + [pathlib.Path(selection_path), pathlib.Path(review_path)])
        create_json(output_dir / "manifest.json", {"lane": lane, "command": command,
                    "identities": _public_identity(frozen), "timeout_seconds": timeout,
                    "ctest_binary_roster_upper_bound": 7 if lane == "ctest" else 0})
        _bind_review(review_path, frozen, reviewed_sources, review_digest)
        _bind_selection(selection_path, frozen, selection_digest)
        _named_build_path48(tree)
        process = run_bounded(command, ROOT, output_dir, output_dir / "unused-report.json", timeout)
        charge48(reservation, process)
        _same(frozen)
        return process


def run_contract48(mode, output_dir, selection_path, review_path, build_path):
    """One exact Python contract under its whole55s process-group boundary."""
    if mode not in ("self-test", "native-cap"):
        raise Invalid("unselected-contract-mode")
    selection_digest, review_digest = sha(selection_path), sha(review_path)
    validate_selection48(ROOT, selection_path)
    sources = _review(review_path)
    build_path = pathlib.Path(build_path).resolve()
    if build_path != ROOT / "build/phase6-feedback48":
        raise Invalid("unselected-contract-build")
    output_dir = pathlib.Path(output_dir).resolve()
    if output_dir.exists() or not output_dir.is_relative_to(EVIDENCE):
        raise Invalid("spent-or-outside-contract-output")
    report = output_dir / "contract.json"
    command = [sys.executable, "-I", str(ROOT / "tests/evidence/phase6_feedback48_contract.py"),
               "--" + mode, "--outer-process-group", "--output", str(report)]
    if mode == "native-cap":
        command += ["--build", str(build_path), "--selection", str(pathlib.Path(selection_path).resolve()),
                    "--source-review", str(pathlib.Path(review_path).resolve())]
    with Writer():
        # The calling Python wrapper and actual contract interpreter are both
        # observed direct Python invocations; elapsed wall is charged once.
        reservation = reserve48("python", roster=2, exposure=55)
        output_dir.mkdir(parents=True)
        paths = [ROOT / path for path in SOURCE_PATHS] + [pathlib.Path(selection_path).resolve(), pathlib.Path(review_path).resolve()]
        if mode == "native-cap":
            paths.append(build_path / "tools/session/gw_headless")
        frozen = _identities(paths)
        create_json(output_dir / "manifest.json", {"mode": mode, "command": ["python3", "-I", "tests/evidence/phase6_feedback48_contract.py", "--" + mode],
                    "identities": _public_identity(frozen), "group_timeout_seconds": 55,
                    "observed_python_direct_reserved": 2})
        _bind_review(review_path, frozen, sources, review_digest)
        _bind_selection(selection_path, frozen, selection_digest)
        process = run_bounded(command, ROOT, output_dir, report, 55, authored=True)
        charge48(reservation, process)
        _same(frozen)
        return process


def verify_retained48(args):
    prepare_attempt48(args)
    retained = load(args.verify_retained)
    if retained.get("schema") != "genewhip-phase6-feedback48-attempt-v1":
        raise Invalid("retained-attempt-schema")
    if retained.get("plan_sha256") != PLAN_SHA256 or retained.get("selection_sha256") != sha(args.selection):
        raise Invalid("retained-selection")
    identities = {ROOT / path: digest for path, digest in retained["identities"].items()}
    _same(identities)
    for path, digest in retained["raw_hashes"].items():
        if sha(ROOT / path) != digest:
            raise Invalid("retained-raw-changed")
    raw = load(ROOT / retained["raw_report_path"])
    if raw != retained.get("native_report"):
        raise Invalid("retained-raw-summary-disagrees")
    if retained["kind"] == "tank":
        descriptor_path = next(ROOT / path for path in retained["identities"] if path.endswith("route.gwrc"))
        checks = consume_attempt48(raw, descriptor_path.read_bytes(), retained["call_cap_selected"], retained["process"])
        outcome = "partial" if raw["status"] else "bounded-route-unqualified"
    else:
        checks = _control_consume(raw, args.build / "tools/session/gw_headless", (ROOT / retained["raw_report_path"]).parent / "children.json")
        outcome = "bounded-control"
    result = {"schema": "genewhip-phase6-feedback48-check-v1", "outcome": outcome, "checks": checks,
              "retained_sha256": sha(args.verify_retained), "qualified": False,
              "pending_duties": ["independent frozen candidate review", "two Tank declared checkpoint repeats", "two original six-case controls and complete PCM", "original Phase6 product/host/safety duties"]}
    create_json(args.output, result)
    return result


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--prepare", action="store_true")
    modes.add_argument("--attempt", action="store_true")
    modes.add_argument("--verify-retained", type=pathlib.Path)
    parser.add_argument("--kind", choices=("tank", "control"))
    parser.add_argument("--attempt-id")
    parser.add_argument("--call-cap", type=int)
    parser.add_argument("--qualification", action="store_true")
    parser.add_argument("--source-review", type=pathlib.Path, required=True)
    parser.add_argument("--selection", type=pathlib.Path, required=True)
    parser.add_argument("--build", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.attempt:
        if not args.kind or not args.attempt_id or (args.kind == "tank" and args.call_cap is None) or (args.kind == "control" and args.call_cap is not None):
            parser.error("attempt requires kind/id; explicit call-cap only for tank")
    elif args.kind or args.attempt_id or args.call_cap is not None or args.qualification:
        parser.error("attempt-only flags outside attempt mode")
    try:
        validate_selection48(ROOT, args.selection, args.call_cap)
        _review(args.source_review)
        with Writer():
            reserve48("python", exposure=0)
            result = run_attempt48(args) if args.attempt else prepare48(args) if args.prepare else verify_retained48(args)
        print(json.dumps({"outcome": result["outcome"]}))
        return 1 if result["outcome"] in ("rejected", "partial", "bounded-route-unqualified") else 0
    except Exception as error:
        print(json.dumps({"outcome": "rejected", "reason": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
