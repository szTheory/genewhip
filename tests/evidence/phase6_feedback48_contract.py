#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate no-process seam assertions and counted original synthetic guests."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/evidence/phase6_feedback48.py"


def import_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def monitor_tests(helper):
    """Specified live-scan contract, independent of Plan48 admission/clock."""
    rows = []
    with tempfile.TemporaryDirectory(prefix="gw-monitor-") as directory:
        root = pathlib.Path(directory)
        helper.ROOT, helper.EVIDENCE = root, root / "evidence"
        helper.EVIDENCE.mkdir()
        output = helper.EVIDENCE / "attempt"
        output.mkdir()
        original_stat, original_lstat = pathlib.Path.stat, pathlib.Path.lstat
        original_is_file, original_open = pathlib.Path.is_file, pathlib.Path.open

        def run(name, callback, expected=None):
            try:
                value = callback()
                if expected is not None:
                    raise AssertionError("expected rejection: " + name)
                rows.append({"case": name, "outcome": "pass", "value": value})
            except Exception as error:
                if expected is None or not isinstance(error, expected[0]) or (expected[1] and str(error) != expected[1]):
                    rows.append({"case": name, "outcome": "fail", "error": type(error).__name__ + ":" + str(error)})
                else:
                    rows.append({"case": name, "outcome": "pass", "rejection": type(error).__name__ + ":" + str(error)})

        vanished = output / "field.bin"
        vanished.write_bytes(b"abc")
        survivor = output / "survivor.bin"
        survivor.write_bytes(b"seven!!")

        def gone_stat(path, *args, **kwargs):
            if path == vanished:
                raise FileNotFoundError("injected enumerated entry disappeared")
            return original_stat(path, *args, **kwargs)

        def gone_lstat(path, *args, **kwargs):
            if path == vanished:
                raise FileNotFoundError("injected enumerated entry disappeared")
            return original_lstat(path, *args, **kwargs)

        # Old is_file observed True before deletion; new lstat sees disappearance.
        with patch.object(pathlib.Path, "is_file", lambda path: True if path == vanished else original_is_file(path)), patch.object(pathlib.Path, "stat", gone_stat), patch.object(pathlib.Path, "lstat", gone_lstat):
            run("enumerated-disappearance-size-excludes-only-gone", lambda: _equal(helper._size(output), 7))
            run("enumerated-disappearance-disk-continues", lambda: helper._disk(output))
        vanished.unlink()
        run("empty-size", lambda: _equal(helper._size(output / "absent"), 0))
        run("survivor-size", lambda: _equal(helper._size(output), 7))

        trace = output / "trace.jsonl"
        trace.write_bytes(b"line\n")

        def opening(path, *args, **kwargs):
            if path == trace:
                raise FileNotFoundError("injected trace disappeared before open")
            return original_open(path, *args, **kwargs)
        with patch.object(pathlib.Path, "open", opening):
            run("trace-open-disappearance", lambda: helper._disk(output))
        trace.unlink()
        for suffix, limit, rejection in (("stdout.bin", helper.STREAM_LIMIT, "descendant-stream-limit"),
                                         ("report.json", helper.REPORT_LIMIT, "report-limit"),
                                         ("trace.jsonl", 16 << 20, "trace-byte-limit")):
            target = output / suffix
            for delta in (-1, 0, 1):
                with target.open("wb") as stream:
                    stream.truncate(limit + delta)
                run(suffix + ":" + str(delta), lambda: helper._disk(output),
                    (helper.Invalid, rejection) if delta == 1 else None)
            target.unlink()
        trace.write_bytes(b"x\n" * 100000)
        run("trace-rows-at-limit", lambda: helper._disk(output))
        with trace.open("ab") as stream:
            stream.write(b"x\n")
        run("trace-rows-over-limit", lambda: helper._disk(output), (helper.Invalid, "trace-row-limit"))

        for exception in (PermissionError, OSError):
            def bad_stat(path, *args, **kwargs):
                if path == survivor:
                    raise exception("injected real metadata failure")
                return original_stat(path, *args, **kwargs)
            def bad_lstat(path, *args, **kwargs):
                if path == survivor:
                    raise exception("injected real metadata failure")
                return original_lstat(path, *args, **kwargs)
            with patch.object(pathlib.Path, "stat", bad_stat), patch.object(pathlib.Path, "lstat", bad_lstat):
                run(exception.__name__ + "-metadata", lambda: helper._disk(output), (exception, None))
            def bad_open(path, *args, **kwargs):
                if path == trace:
                    raise exception("injected real open failure")
                return original_open(path, *args, **kwargs)
            with patch.object(pathlib.Path, "open", bad_open):
                run(exception.__name__ + "-open", lambda: helper._disk(output), (exception, None))
        trace.unlink()
        link = output / "link"
        link.symlink_to(survivor)
        run("symlink-rejected", lambda: helper._disk(output), (helper.Invalid, "attempt-symlink"))
        link.unlink()
        run("missing-final-report-rejected", lambda: helper.load(output / "missing.json"), (helper.Invalid, "missing-or-oversized-json"))
    return rows


def _equal(actual, expected):
    assert actual == expected, (actual, expected)
    return actual


def descriptor(cap, encoder=None):
    # Original one-field no-input observer, one RAM byte, no predicates/events.
    # Instruction-probe mode uses subfield boundaries; never probe-only exit.
    header = [0] * 32
    header[0] = int.from_bytes(b"GWRC", "little")
    header[1:5] = [1, 3, 1, 1]
    header[6] = 1
    header[30] = cap
    sections = [[[0xff0000, 0xff0000, 1, 0]], [], [], [], [], [], [], []]
    if encoder:
        return encoder(header, sections)
    return struct.pack("<36I", *header, *sections[0][0])


def authored_rom():
    # Original machine bytes: supervisor stack, reset PC, BRA.S -2 self-loop.
    rom = bytearray(514)
    rom[:8] = struct.pack(">II", 0x00ffff00, 0x200)
    rom[512:514] = bytes.fromhex("60fe")
    return bytes(rom)


def self_test(helper):
    rows = []
    guard_hits = []

    def deny(event, args):
        if event == "subprocess.Popen" or event == "os.system" or event.startswith(("os.exec", "os.spawn", "os.posix_spawn", "os.fork")) or event == "pty.spawn":
            guard_hits.append(event)
            raise PermissionError("sticky-plan48-no-process")

    # Installed BEFORE importing either changed helper or route subject.
    sys.addaudithook(deny)
    for callback in (lambda: subprocess.Popen(["/__plan48_no_client__"]),
                     lambda: __import__("os").system("/__plan48_no_client__")):
        try:
            callback()
        except PermissionError as error:
            assert str(error) == "sticky-plan48-no-process"
        else:
            raise AssertionError("process-denial-self-proof-failed")
    assert len(guard_hits) == 2
    baseline = len(guard_hits)
    helper = import_file("feedback48_contract_subject", HELPER)
    assert len(guard_hits) == baseline, "sticky-denial-caught-during-helper-import"

    def reject(name, expected, callback, group="selected_cap_chain48"):
        try:
            callback()
        except helper.Invalid as error:
            assert str(error) == expected, (name, str(error), expected)
        else:
            raise AssertionError("mutant-survived:" + name)
        rows.append({"group": group, "case": name, "assertion": expected, "outcome": "rejected-as-required"})

    with tempfile.TemporaryDirectory(prefix="plan48-no-process-") as temporary:
        root = pathlib.Path(temporary).resolve()
        helper.ROOT = root
        helper.EVIDENCE = root / "evidence"
        helper.EVIDENCE.mkdir()
        helper.WINDOW = root / "window-forward.json"
        helper.WRITER_LOCK = root / "writer.lock"
        # Synthetic ROOT contains no ROM, binary or executable. Only inert identity bytes.
        identity = root / "identity.txt"
        identity.write_text("inert selected identity\n")
        identities = {str(identity): helper.sha(identity)}
        launched = []
        routes = import_file("feedback48_synthetic_lowering_subject", ROOT / "scripts/evidence/phase6_routes.py")
        routes.ROOT = root
        helper.create_json(root / "fixtures/independent-game-v2/oracle.json", {
            "observations": {"play_state": {"address": "0xFF0000"}, "position": {"address": "0xFF0002"}}})
        route = {"fixture": "genewhip-independent-game-v2", "identity": {"kind": "authored-synthetic"},
                 "execution_blockers": [], "case": {"frames": 1, "input_schedule": []},
                 "definitions": {"source_scenario": {}, "input_program": {}, "addresses": [], "predicates": []}}
        for selected in (None, True, 0, -1, 20_000_001, 0x100000000):
            try:
                routes.lower_route(route, selected)
            except routes.Invalid as error:
                assert str(error) == "boundary-call-limit"
            else:
                raise AssertionError("invalid-lowering-cap-survived")
            rows.append({"group": "selected_cap_chain48", "case": "lowering-invalid-" + str(selected),
                         "assertion": "boundary-call-limit", "outcome": "rejected-as-required"})
        for selected in (1, 2, 3):
            lowered, _ = routes.lower_route(route, selected)
            assert int.from_bytes(lowered[120:124], "little") == selected
            helper.launch_checked48(lowered, selected, identities, lambda: None, authored=True)
            rows.append({"group": "selected_cap_chain48", "case": "actual-lowering-" + str(selected),
                         "assertion": "serialized-word30-equals-selected", "outcome": "pass"})

        def os_seam():
            launched.append("fake-lowest-os-seam")
            return {"process_reaped": True, "returncode": 1, "failure": None}

        good = descriptor(2)
        for selected in (None, True, 0, -1, 65, 0x100000000):
            reject("invalid-selected-" + str(selected), "selected-cap-range",
                   lambda selected=selected: helper.launch_checked48(good, selected, identities, os_seam, authored=True))
        for cap in (1, 3):
            reject("serialized-neighbor-" + str(cap), "serialized-cap-disagrees-with-selection",
                   lambda cap=cap: helper.launch_checked48(descriptor(cap), 2, identities, os_seam, authored=True))
        for label, blob, reason in (("short", good[:124], "descriptor-length"),
                                    ("trailing", good + b"\0\0\0\0", "descriptor-section-length"),
                                    ("unaligned", good + b"\0", "descriptor-length"),
                                    ("magic", b"FAIL" + good[4:], "descriptor-header")):
            reject("malformed-" + label, reason,
                   lambda blob=blob: helper.launch_checked48(blob, 2, identities, os_seam, authored=True))
        assert launched == []
        helper.launch_checked48(good, 2, identities, os_seam, authored=True)
        assert len(launched) == 1
        rows.append({"group": "selected_cap_chain48", "case": "valid-production-seam", "assertion": "exactly-one-fake-lowest-os-call", "outcome": "pass"})
        identity.write_text("stale")
        reject("stale-source", "frozen-identity-changed", lambda: helper.launch_checked48(good, 2, identities, os_seam, authored=True))
        reject("missing-selection", "missing-or-oversized-json", lambda: helper.load(root / "missing-selection.json"))
        duplicate = root / "duplicate.json"
        duplicate.write_text('{"selected":2,"selected":3}')
        reject("duplicate-selection", "duplicate-json-key", lambda: helper.load(duplicate))
        for name in helper.SOURCE_PATHS:
            source = root / name
            source.parent.mkdir(parents=True, exist_ok=True)
            if name != helper.HOST_WORK_REL:
                source.write_text("inert authored source identity\n")
        # Independently authored SYNTHETIC authority; never copy real records,
        # load a real fixture, or carry a usable client into this root.
        authority_path = root / helper.HOST_WORK_REL
        synthetic_authority = {
            "schema": "genewhip-plan48-host-work-forward-authority-v1",
            "synthetic_test_data": True,
            "actual_user_excerpts": ["find set of recommendations that are coherent auto follow those...",
                "<-- fan out plan it out and unblock and then move us forward ...."],
            "removed_host_count_ceilings": {"setup_direct": 16, "ctest_direct": 20,
                "python_direct": 40, "ctest_test_binary_reserved": 140},
            "preserved": {
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
                "control_attempt_bytes": 1073741824, "aggregate_raw_bytes": 268435456},
            "consumed_at_authority": {"setup_direct": 15, "ctest_direct": 12, "python_direct": 35,
                "authored_native": 13, "tank_launches": 8, "control_drivers": 0, "control_children": 0,
                "misclassified_prior_native_cap_starts": 3},
            "resources_at_authority": {"workload_starts": 8, "tank_call_actual": 250030,
                "tank_call_reserved": 5000006, "tank_call_charged": 250030,
                "tank_workload_seconds": 0.577388, "workload_seconds": 0.577388,
                "workload_reserved": 1800, "tank_workload_reserved": 1800,
                "ctest_test_binary_reserved": 84, "authored_call_reserved": 832,
                "setup_seconds": 1353.305709, "setup_reserved": 0,
                "nonworkload_seconds": 1362.515446, "nonworkload_reserved": 0,
                "prior_nonworkload_upper_bound_seconds": 1347,
                "prior_unvalidated_workload_reserved_seconds": 1800}}
        helper.create_json(authority_path, synthetic_authority)
        reviewed_sources = {name: helper.sha(root / name) for name in helper.SOURCE_PATHS}
        review = root / "review.json"
        helper.create_json(review, {"schema": "genewhip-plan48-source-review-v1",
            "reviewer_identity": "/root/repair_and_feedback48/review48", "verdict": "ACCEPT", "findings": [],
            "source_hashes": reviewed_sources})
        review_digest = helper.sha(review)
        frozen = helper._identities([root / name for name in helper.SOURCE_PATHS] + [review])
        helper._bind_review(review, frozen, reviewed_sources, review_digest)
        reject("review-hash-race", "review-receipt-changed-before-launch",
               lambda: helper._bind_review(review, frozen, reviewed_sources, "0" * 64))
        reject("source-review-snapshot-race", "review-to-frozen-source-race",
               lambda: helper._bind_review(review, frozen, {}, review_digest))
        # The production reservation path sees only this inert synthetic window.
        # Use already-over-old-ceiling counts to expose a surviving old guard.
        synthetic_window = {
            "started_utc": "2026-10-27T14:24:16Z", "deadline_utc": "2026-10-27T18:24:16Z",
            "monotonic_dispatch_anchor_seconds": time.monotonic() - 1,
            "counts": {"setup_direct": 17, "ctest_direct": 21, "python_direct": 41,
                       "authored_native": 13, "tank_launches": 8, "control_drivers": 0, "control_children": 0,
                       "misclassified_prior_native_cap_starts": 3},
            "resources": {"workload_starts": 8, "tank_call_actual": 250030,
                "tank_call_reserved": 5000006, "tank_call_charged": 250030,
                "tank_workload_seconds": 0.577388, "workload_seconds": 0.577388,
                "workload_reserved": 1800, "tank_workload_reserved": 1800, "ctest_test_binary_reserved": 147,
                "authored_call_reserved": 832, "setup_seconds": 1353.305709,
                "setup_reserved": 0, "nonworkload_seconds": 1362.515446, "nonworkload_reserved": 0,
                "prior_nonworkload_upper_bound_seconds": 1347,
                "prior_unvalidated_workload_reserved_seconds": 1800}}
        helper.create_json(helper.WINDOW, synthetic_window)
        for lane in ("setup", "ctest", "python"):
            helper.reserve48(lane, exposure=1)
        after = helper.load(helper.WINDOW)
        assert [after["counts"][k] for k in ("setup_direct", "ctest_direct", "python_direct")] == [18, 22, 42]
        assert after["resources"]["ctest_test_binary_reserved"] == 154
        assert after["resources"]["workload_reserved"] == 1800 and after["resources"]["tank_call_actual"] == 250030
        assert after["counts"]["tank_launches"] == 8 and after["counts"]["authored_native"] == 13
        rows.append({"group": "host_work_authority48", "case": "over-old-counts",
                     "assertion": "host-counts-increment-without-reset-or-guest-refund", "outcome": "pass"})
        # Fresh, create-once synthetic records for each mutant, never overwrite
        # a retained authority or review receipt (including in the test root).
        for label, field, value in (("schema", "schema", "invented"),
                ("removed-key", "removed_host_count_ceilings", {"setup_direct": 16}),
                ("missing-bound", "preserved", {k: v for k, v in synthetic_authority["preserved"].items() if k != "aggregate_raw_bytes"}),
                ("deadline", "preserved", dict(synthetic_authority["preserved"], deadline_utc="2026-10-28T18:24:16Z")),
                ("guest-budget", "preserved", dict(synthetic_authority["preserved"], tank_call_budget=100000001))):
            mutant_root = root / ("authority-" + label)
            helper.create_json(mutant_root / helper.HOST_WORK_REL, dict(synthetic_authority, **{field: value}))
            reject("host-authority-" + label, "host-work-authority-mismatch",
                   lambda mutant_root=mutant_root: helper.validate_host_work48(mutant_root), "host_work_authority48")
            helper.ROOT = mutant_root
            reject("host-reservation-" + label, "host-work-authority-mismatch",
                   lambda: helper.reserve48("setup", exposure=1), "host_work_authority48")
            helper.ROOT = root
        reject("host-authority-missing", "missing-or-oversized-json",
               lambda: helper.validate_host_work48(root / "missing-authority"), "host_work_authority48")
        helper.ROOT = root / "missing-authority"
        reject("host-reservation-missing", "missing-or-oversized-json",
               lambda: helper.reserve48("setup", exposure=1), "host_work_authority48")
        helper.ROOT = root
        assert helper.load(helper.WINDOW) == after, "denied-authority-consumed-or-reset-counters"
        for label, section, field, value in (
                ("counter-reset", "counts", "setup_direct", 14),
                ("counter-missing", "counts", "python_direct", None),
                ("tank-count-reset", "counts", "tank_launches", 7),
                ("setup-time-reset", "resources", "setup_seconds", 1353),
                ("nonworkload-time-missing", "resources", "nonworkload_seconds", None),
                ("unknown-reserve-reset", "resources", "workload_reserved", 1799),
                ("unknown-basis-reset", "resources", "prior_unvalidated_workload_reserved_seconds", 0),
                ("actual-calls-reset", "resources", "tank_call_actual", 250029)):
            changed = dict(synthetic_window[section])
            if value is None:
                del changed[field]
            else:
                changed[field] = value
            prefix_window = root / ("prefix-" + label + ".json")
            helper.create_json(prefix_window, dict(synthetic_window, **{section: changed}))
            helper.WINDOW = prefix_window
            reject(label, "lost-host-authority-consumption", lambda: helper.reserve48("python", exposure=1),
                   "host_work_authority48")
        for label, section, field, value in (
                ("missing-count", "consumed_at_authority", "setup_direct", None),
                ("boolean-count", "consumed_at_authority", "tank_launches", True),
                ("missing-time", "resources_at_authority", "setup_seconds", None),
                ("negative-unknown", "resources_at_authority", "prior_unvalidated_workload_reserved_seconds", -1)):
            changed = dict(synthetic_authority[section])
            if value is None:
                del changed[field]
            else:
                changed[field] = value
            mutant_root = root / ("snapshot-" + label)
            helper.create_json(mutant_root / helper.HOST_WORK_REL, dict(synthetic_authority, **{section: changed}))
            reject(label, "host-work-authority-prefix-invalid",
                   lambda mutant_root=mutant_root: helper.validate_host_work48(mutant_root), "host_work_authority48")
        settled_window = root / "window-settled.json"
        helper.create_json(settled_window, dict(synthetic_window, resources=dict(synthetic_window["resources"],
            setup_reserved=1, nonworkload_reserved=1)))
        helper.WINDOW = settled_window
        helper.charge48({"lane": "setup", "exposure": 1}, {"wall_seconds": 0.25})
        helper.reserve48("python", exposure=0)
        settled = helper.load(settled_window)
        assert settled["resources"]["setup_reserved"] == settled["resources"]["nonworkload_reserved"] == 0
        assert settled["resources"]["workload_reserved"] == 1800
        rows.append({"group": "host_work_authority48", "case": "settled-inflight-reservations",
                     "assertion": "release-to-zero-allowed-with-unknown-floor-retained", "outcome": "pass"})
        # Pure fixed-batch admission/settlement; no fixture or client is present.
        qdir = root / "qualification-synthetic"
        qdir.mkdir()
        qwindow = dict(synthetic_window, counts=dict(synthetic_window["counts"], tank_launches=10),
                       resources=dict(synthetic_window["resources"], workload_starts=10))
        helper.WINDOW = root / "qualification-window.json"
        helper.create_json(helper.WINDOW, qwindow)
        with helper.Writer():
            q = helper.begin_qualification48(frozen, qdir)
            held = helper.load(helper.WINDOW)
            assert held["counts"] == qwindow["counts"]
            assert held["resources"]["workload_starts"] == 10
            assert held["resources"]["workload_reserved"] == 4200
            assert held["resources"]["tank_call_charged"] == 2250030
            assert held["monotonic_dispatch_anchor_seconds"] == qwindow["monotonic_dispatch_anchor_seconds"]
            reject("qualification-duplicate-batch", "qualification-batch-spent-or-safety-stop",
                   lambda: helper.begin_qualification48(frozen, qdir), "fixed_qualification48")
            reject("qualification-ordinary-interleave", "qualification-batch-holds-active",
                   lambda: helper.reserve48("tank", cap=1000000), "fixed_qualification48")
            first = SimpleNamespace(attempt_id="48-qual-tank-001", kind="tank", call_cap=1000000,
                output=qdir / "48-qual-tank-001.json", qualification=True,
                _qualification_context=helper._QUALIFICATION_TOKEN)
            public = SimpleNamespace(**dict(vars(first), _qualification_context=None))
            reject("qualification-cli-no-context", "qualification-requires-matching-next-fixed-slot",
                   lambda: helper.prepare_attempt48(public), "fixed_qualification48")
            wrong = SimpleNamespace(**dict(vars(first), attempt_id="48-qual-tank-002"))
            reject("qualification-wrong-slot", "qualification-requires-matching-next-fixed-slot",
                   lambda: helper.claim_qualification48(wrong), "fixed_qualification48")
            reservation = helper.claim_qualification48(first)
            claimed = helper.load(helper.WINDOW)
            assert claimed["counts"]["tank_launches"] == 11
            assert claimed["resources"]["workload_starts"] == 11
            assert claimed["qualification_batch"]["held_counts"]["tank_launches"] == 1
            assert claimed["resources"]["workload_reserved"] == 4200  # no second reservation
            reject("qualification-duplicate-claim", "qualification-requires-matching-next-fixed-slot",
                   lambda: helper.claim_qualification48(first), "fixed_qualification48")
            helper.charge48(reservation, {"wall_seconds": 0.25}, actual=4196)
            settled_q = helper.load(helper.WINDOW)
            assert settled_q["qualification_batch"]["next"] == 1
            assert settled_q["qualification_batch"]["remaining_wall"] == 1800
            assert settled_q["resources"]["workload_reserved"] == 3600
            assert settled_q["resources"]["tank_call_actual"] == 254226
            assert settled_q["resources"]["tank_call_charged"] == 1254226
            reject("qualification-double-charge", "qualification-slot-already-charged-or-not-pending",
                   lambda: helper.charge48(reservation, {"wall_seconds": 0.25}, actual=4196), "fixed_qualification48")
            assert helper.load(helper.WINDOW) == settled_q
            ended = helper.finish_qualification48(False)
            assert ended["status"] == "stopped" and ended["qualified"] is False
            assert ended["held_counts"]["tank_launches"] == 1 and ended["remaining_wall"] == 1800
        rows.append({"group": "fixed_qualification48", "case": "atomic-hold-claim-settle-stop",
                     "assertion": "held-not-observed-once-only-consumption-same-clock-no-refund", "outcome": "pass"})
        for label, section, changes, reason in (
                ("tank-slots", "counts", {"tank_launches": 11}, "full-qualification-reserve-exhausted"),
                ("driver-slots", "counts", {"control_drivers": 3}, "full-qualification-reserve-exhausted"),
                ("children-slots", "counts", {"control_children": 13}, "full-qualification-reserve-exhausted"),
                ("all-starts", "resources", {"workload_starts": 25}, "full-qualification-reserve-exhausted"),
                ("all-calls", "resources", {"tank_call_charged": 99000000}, "full-qualification-reserve-exhausted"),
                ("all-wall", "resources", {"workload_seconds": 3001}, "full-qualification-reserve-exhausted"),
                ("unknown-lost", "resources", {"workload_reserved": 1799}, "lost-host-authority-consumption")):
            helper.WINDOW = root / ("qualification-deny-" + label + ".json")
            mutant = dict(qwindow, **{section: dict(qwindow[section], **changes)})
            helper.create_json(helper.WINDOW, mutant)
            with helper.Writer():
                reject("qualification-" + label, reason, lambda: helper.begin_qualification48(frozen, qdir),
                       "fixed_qualification48")
            assert helper.load(helper.WINDOW) == mutant
        helper.WINDOW = root / "qualification-stale.json"
        helper.create_json(helper.WINDOW, qwindow)
        with helper.Writer():
            stale = dict(frozen, **{str(identity): "0" * 64})
            reject("qualification-stale-candidate", "frozen-identity-changed",
                   lambda: helper.begin_qualification48(stale, qdir), "fixed_qualification48")
        helper.WINDOW = root / "qualification-terminal.json"
        terminal = dict(qwindow, monotonic_dispatch_anchor_seconds=time.monotonic() - 12000)
        helper.create_json(helper.WINDOW, terminal)
        with helper.Writer():
            reject("qualification-terminal-reserve", "deadline-plus-terminal-reserve",
                   lambda: helper.begin_qualification48(frozen, qdir), "fixed_qualification48")
        for label, field, value, lane, reason in (
                ("setup-wall", "setup_seconds", 2400, "setup", "setup-wall-exhausted"),
                ("nonworkload-wall", "nonworkload_seconds", 3600, "python", "nonworkload-wall-exhausted"),
                ("total-starts", "workload_starts", 40, "tank", "full-qualification-reserve-exhausted"),
                ("tank-calls", "tank_call_charged", 100000000, "tank", "full-qualification-reserve-exhausted"),
                ("authored-calls", "authored_call_reserved", 6144, "authored", "authored-call-roster-exhausted")):
            window_path = root / ("window-" + label + ".json")
            helper.create_json(window_path, dict(synthetic_window,
                resources=dict(synthetic_window["resources"], **{field: value})))
            helper.WINDOW = window_path
            reject(label, reason, lambda lane=lane: helper.reserve48(lane, cap=1000000 if lane == "tank" else 0, exposure=1),
                   "host_work_authority48")
        authored_window = root / "window-authored-count.json"
        helper.create_json(authored_window, dict(synthetic_window,
            counts=dict(synthetic_window["counts"], authored_native=96)))
        helper.WINDOW = authored_window
        reject("authored-count", "lane-count-exhausted", lambda: helper.reserve48("authored", exposure=0), "host_work_authority48")
        # A changed authority cannot inherit the already-reviewed identities.
        race_authority = root / "authority-race.json"
        helper.create_json(race_authority, dict(synthetic_authority, synthetic_test_data="changed"))
        race_frozen = dict(frozen, **{str(authority_path): helper.sha(race_authority)})
        reject("authority-frozen-race", "frozen-identity-changed",
               lambda: helper._bind_review(review, race_frozen, reviewed_sources, review_digest), "host_work_authority48")
        selection = root / "selected.json"
        selection.write_text("{}")
        reject("selection-snapshot-race", "selection-to-frozen-identity-race",
               lambda: helper._bind_selection(selection, {str(selection): helper.sha(selection)}, "0" * 64))
        with helper.Writer():
            reject("duplicate-writer", "another-or-interrupted-plan48-writer", lambda: helper.Writer().__enter__())
        helper.create_json(root / "spent.json", {})
        try:
            helper.create_json(root / "spent.json", {})
        except FileExistsError:
            rows.append({"group": "retained_consumer48", "case": "spent-id", "assertion": "create-once", "outcome": "rejected-as-required"})
        else:
            raise AssertionError("spent-id-survived")
        window = {"started_utc": "2026-10-27T14:24:16Z", "deadline_utc": "2026-10-27T18:24:16Z",
                  "monotonic_dispatch_anchor_seconds": time.monotonic() - 14000}
        reject("terminal", "deadline-plus-terminal-reserve", lambda: helper._clock(window, 600))
        original_limit = helper.TREE_LIMIT
        helper.TREE_LIMIT = 0
        (helper.EVIDENCE / "nonempty").write_text("x")
        reject("disk-limit", "aggregate-evidence-build-limit", lambda: helper._disk(root))
        helper.TREE_LIMIT = original_limit
        stream = root / "stdout.bin"
        with stream.open("wb") as output:
            output.truncate((1 << 20) + 1)
        reject("stream-limit", "descendant-stream-limit", lambda: helper._disk(root))
        stream.unlink()

        process = {"process_reaped": True, "returncode": 1, "failure": None}
        raw = {"schema": "genewhip-route-native-v1", "selected_boundary_calls": 2,
               "boundary_calls": 2, "boundary_attempts": 3, "rejected_boundary_attempts": 1,
               "plan_fnv1a64": helper.fingerprint(good), "status": 8, "fields": 0,
               "samples": [], "termination": "error", "predicates": []}
        check = helper.consume_attempt48(raw, good, 2, process, authored=True)
        assert check["boundary_calls_actual"] == 2 and check["boundary_attempts_rejected"] == 1
        rows.append({"group": "retained_consumer48", "case": "actual-N-rejected-next", "assertion": "actual2-attempts3-rejected1", "outcome": "pass"})
        mutations = (("selected_boundary_calls", 1, "counter-contradiction"),
                     ("selected_boundary_calls", 3, "counter-contradiction"),
                     ("boundary_calls", 1, "counter-contradiction"),
                     ("boundary_calls", 3, "counter-contradiction"),
                     ("boundary_calls", -1, "counter-type-or-negative"),
                     ("boundary_calls", True, "counter-type-or-negative"),
                     ("boundary_attempts", 2, "counter-contradiction"),
                     ("rejected_boundary_attempts", 0, "counter-contradiction"),
                     ("rejected_boundary_attempts", 2, "counter-contradiction"),
                     ("plan_fnv1a64", "0" * 16, "native-descriptor-identity"),
                     ("status", 0, "native-status-termination"),
                     ("fields", 2, "native-status-or-fields"),
                     ("termination", "diagnostic-prefix", "native-status-termination"))
        for field, value, reason in mutations:
            mutant = dict(raw, **{field: value})
            reject("counter-mutant-" + field + "-" + str(value), reason,
                   lambda mutant=mutant: helper.consume_attempt48(mutant, good, 2, process, authored=True), "retained_consumer48")
        missing = dict(raw)
        del missing["boundary_attempts"]
        reject("counter-deletion", "counter-type-or-negative", lambda: helper.consume_attempt48(missing, good, 2, process, authored=True), "retained_consumer48")
        # Counter assertions cannot count as CPU/bus semantics; that named group
        # is the independently authored C public-API contract, not a fake pass.
        rows.append({"group": "bus_semantics48", "case": "public-api-c-contract", "outcome": "not-run-here",
                     "owner": "tests/api/phase6_repairs_contract.c", "reason": "separate counted native/sanitizer CTest lane"})
        assert not list(root.rglob("*.gwrc")) and not list(root.rglob("*.rom")) and not list(root.rglob("gw_headless"))
    assert len(guard_hits) == baseline, "sticky-denial-caught-during-test"
    return {"schema": "genewhip-phase6-feedback48-synthetic-v1", "outcome": "passed",
            "assertions": sum(row["outcome"] != "not-run-here" for row in rows), "os_children": 0,
            "guard_self_proofs": 2, "guard_attempts_after_self_proof": 0, "rows": rows}


def native_cap(args):
    helper = import_file("feedback48_native_contract_subject", HELPER)
    selection_digest = helper.sha(args.selection)
    helper.validate_selection48(ROOT, args.selection)
    review_digest = helper.sha(args.source_review)
    reviewed_sources = helper._review(args.source_review)
    build = args.build.resolve(strict=True)
    if build != ROOT / "build/phase6-feedback48":
        raise helper.Invalid("unselected-native-build")
    client = build / "tools/session/gw_headless"
    if not client.is_file():
        raise helper.Invalid("native-client-missing")
    if args.output.exists() or not args.output.resolve().is_relative_to(helper.EVIDENCE):
        raise helper.Invalid("spent-or-outside-output")
    raw_root = args.output.parent / (args.output.stem + "-raw")
    raw_root.mkdir(parents=True, exist_ok=False)
    # Roster fixed before admission. Nine actual native cases, all <=64 calls,
    # one field, no events, five seconds per guest. Each malformed case also
    # retains process/descriptor/report path, including absent native reports.
    roster = [("exact-" + str(n), n, None) for n in (1, 2, 3)] + [
        ("malformed-zero", 2, "zero"), ("malformed-over-limit", 2, "over"),
        ("malformed-truncated", 2, "truncated"), ("malformed-trailing", 2, "trailing"),
        ("malformed-reserved", 2, "reserved"), ("malformed-section", 2, "section")]
    result = {"schema": "genewhip-phase6-feedback48-native-cap-v2", "outcome": "rejected",
              "roster": [row[0] for row in roster], "authored_native_reserved": len(roster), "rows": [],
              "fixture_classification": "original-synthetic-bra-self-loop", "fixture_sha256": hashlib.sha256(authored_rom()).hexdigest()}
    # The reviewed outer wrapper owns the one writer lock, Python counts and
    # complete55s reservation; this child owns only its finite authored roster.
    with contextlib.nullcontext():
        helper.reserve48("authored", roster=len(roster), exposure=0)
        started = time.monotonic()
        try:
            routes = helper._routes()
            lowering_root = raw_root / "authored-lowering-root"
            helper.create_json(lowering_root / "fixtures/independent-game-v2/oracle.json", {
                "observations": {"play_state": {"address": "0xFF0000"}, "position": {"address": "0xFF0002"}}})
            routes.ROOT = lowering_root
            # Existing field-clock lowering discriminator, entirely authored
            # route/addresses/oracle and original ROM; no admitted-game input.
            route = {"fixture": "genewhip-independent-game-v2", "identity": {"kind": "authored-synthetic"},
                     "execution_blockers": [], "case": {"frames": 1, "input_schedule": []},
                     "definitions": {"source_scenario": {}, "input_program": {}, "addresses": [], "predicates": []}}
            frozen = helper._identities([ROOT / path for path in helper.SOURCE_PATHS] + [client, args.selection.resolve(), args.source_review.resolve()])
            for label, cap, mutation in roster:
                if time.monotonic() - started > 50:
                    raise helper.Invalid("authored-contract-group-wall-limit")
                helper._bind_review(args.source_review, frozen, reviewed_sources, review_digest)
                helper._bind_selection(args.selection, frozen, selection_digest)
                directory = raw_root / label
                directory.mkdir()
                plan, report, rom = directory / "route.gwrc", directory / "native.json", directory / "authored.rom"
                blob, _metadata = routes.lower_route(route, cap)
                helper.validate_cap48(blob, cap, authored=True)
                if mutation in ("zero", "over", "reserved", "section"):
                    words = list(struct.unpack("<" + "I" * (len(blob) // 4), blob))
                    if mutation == "zero": words[30] = 0
                    if mutation == "over": words[30] = 20_000_001
                    if mutation == "reserved": words[31] = 1
                    if mutation == "section": words[6] += 1
                    blob = struct.pack("<" + "I" * len(words), *words)
                if mutation == "truncated": blob = blob[:124]
                if mutation == "trailing": blob += b"\0\0\0\0"
                with plan.open("xb") as stream: stream.write(blob)
                with rom.open("xb") as stream: stream.write(authored_rom())
                helper.create_json(directory / "manifest.json", {"case": label, "selected_cap": cap, "mutation": mutation,
                    "descriptor_sha256": helper.sha(plan), "fixture_sha256": helper.sha(rom), "binary_sha256": helper.sha(client),
                    "settings": {"field_ceiling": 1, "call_ceiling": 64, "event_ceiling": 16, "timeout_seconds": 5,
                                 "instruction_probe_pc": 512, "probe_only": False},
                    "fixture_classification": "original-synthetic", "source_hashes": {path: helper.sha(ROOT / path) for path in helper.SOURCE_PATHS}})
                command = [str(client), "--route-plan", str(plan), "--route-report", str(report),
                           "--route-instruction-probe", "512", str(rom)]
                helper._bind_review(args.source_review, frozen, reviewed_sources, review_digest)
                helper._bind_selection(args.selection, frozen, selection_digest)
                helper._same(frozen)
                if mutation is None:
                    def authored_launch(*run_args):
                        return helper.run_bounded(*run_args, authored=True, inherited_group=True)
                    process = helper.launch_checked48(blob, cap, frozen, authored_launch,
                        command, ROOT, directory, report, 5, authored=True)
                else:
                    # Explicit parser-negative lane: malformed descriptors are
                    # expected rejected before guest work by native parsing.
                    process = helper.run_bounded(command, ROOT, directory, report, 5, authored=True, inherited_group=True)
                helper._same(frozen)
                row = {"group": "native_exact_n48", "case": label, "process": process,
                       "descriptor_sha256": helper.sha(plan), "report_sha256": helper.sha(report) if report.exists() else None}
                result["rows"].append(row)
                if mutation:
                    stderr = (directory / "stderr.bin").read_bytes()
                    if process["failure"] or process["returncode"] != 1 or report.exists() or stderr != b"REJECT: route-plan\n":
                        raise AssertionError("native-malformed-not-rejected:" + label)
                    row["assertion"] = "native-parser-exit1-route-plan-no-guest-report"
                else:
                    raw = helper.load(report, 1 << 20)
                    check = helper.consume_attempt48(raw, blob, cap, process, authored=True)
                    actual = [raw[name] for name in ("selected_boundary_calls", "boundary_calls", "boundary_attempts", "rejected_boundary_attempts")]
                    if actual != [cap, cap, cap + 1, 1] or raw["status"] != 8 or raw["fields"] != 0 or raw["active_ticks"] != 0:
                        raise AssertionError("native-exact-N-or-subfield-ceiling:" + label)
                    for neighbor in (cap - 1, cap + 1):
                        if actual == [cap, neighbor, neighbor + 1, 1]:
                            raise AssertionError("neighbor-oracle-survived")
                    # Exercise production consumer against actual retained raw
                    # report mutations; do not merely print mutant labels.
                    rejected = []
                    for field, value in (("boundary_calls", cap + 1), ("boundary_calls", cap - 1),
                                         ("boundary_attempts", cap), ("rejected_boundary_attempts", 0)):
                        try:
                            helper.consume_attempt48(dict(raw, **{field: value}), blob, cap, process, authored=True)
                        except helper.Invalid:
                            rejected.append(field + ":" + str(value))
                        else:
                            raise AssertionError("native-consumer-mutant-survived")
                    row.update(assertion="actual-N-attempts-Nplus1-rejected1-zero-fields", actual=actual,
                               check=check, consumer_mutants_rejected=rejected)
                row["outcome"] = "pass"
            if time.monotonic() - started > 55:
                raise helper.Invalid("authored-contract-group-wall-limit")
            result["outcome"] = "passed"
        except BaseException as error:
            result["failure"] = type(error).__name__ + ":" + str(error)
        finally:
            result["inner_wall_seconds_observed_not_additive"] = round(time.monotonic() - started, 6)
            result["raw_hashes"] = {p.relative_to(ROOT).as_posix(): helper.sha(p) for p in raw_root.rglob("*") if p.is_file()}
            helper.create_json(args.output, result)
    return result


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", "--preimport-denial", dest="self_test", action="store_true")
    mode.add_argument("--native-cap", action="store_true")
    parser.add_argument("--build", type=pathlib.Path)
    parser.add_argument("--selection", type=pathlib.Path)
    parser.add_argument("--source-review", type=pathlib.Path)
    parser.add_argument("--outer-process-group", action="store_true")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    # Trusted local launcher opt-in, matching the original control-driver
    # convention. This is accidental-execution protection, not authentication.
    lock = ROOT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/48-evidence/writer-forward.lock"
    if (not args.outer_process_group or os.getpgrp() != os.getpid() or
            lock.is_symlink() or not lock.is_file() or lock.read_text() != f"pid={os.getppid()}\n"):
        parser.error("contract requires reviewed55s outer group and parent writer lock")
    if args.native_cap and (args.build is None or args.selection is None or args.source_review is None):
        parser.error("native-cap requires build, selection and source-review")
    try:
        if args.self_test:
            result = self_test(None)
            # No project subject module is imported before guard installation.
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, sort_keys=True, indent=2)
                stream.write("\n")
        else:
            result = native_cap(args)
    except Exception as error:
        result = {"schema": "genewhip-phase6-feedback48-contract-failure-v1", "outcome": "rejected",
                  "failure": type(error).__name__ + ":" + str(error), "rows": []}
        # Preserve any report already retained by the inner failure path.
        if not args.output.exists() and not args.output.is_symlink():
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, sort_keys=True, indent=2)
                stream.write("\n")
    print(json.dumps({"outcome": result["outcome"], "rows": len(result["rows"])}))
    return 0 if result["outcome"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
