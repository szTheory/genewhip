#!/usr/bin/env python3
"""Integration contracts for the Phase 6 public route clients."""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import platform
import re
import resource
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

MAX_STREAM_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_TRACE_BYTES = 16 * 1024 * 1024
MAX_TRACE_ROWS = 100000
DARWIN_RSS_MAX_PIDS = 4096
SAFE_CLEANUP_REASONS = frozenset({
    "group-inactive", "group-observer-cleanup-unconfirmed", "group-status-budget-exhausted",
    "group-cleanup-os-error", "cleanup-permission-denied",
    "group-leader-reap-unconfirmed", "group-leader-wait-unconfirmed",
    "group-reported-active", "group-signal-permission-denied", "group-signal-visible",
    "group-status-unavailable", "cleanup-unclassified", "not-observed",
})
BASELINE_SHA256 = "e044daa65a617d3a1e3cd32a877bf40c2f9b3fad21fef1241f6335e4d7516209"
PLAN_START_STATE_COMMIT = "89784ff3e240c56a584e6d7f830030cb818bc20d"
HOST_PROCESS_CONTEXT = "host-cleanup-v1"


def require_host_process_context() -> None:
    """Admission for tooling children, not a claim about OS permissions.

    Production executable entry points declare their host context. Imported
    contracts require an explicit CLI opt-in (or the declared CI host marker).
    Pure/fake tests can scope this marker while independently denying OS starts.
    """
    if os.environ.get("GENEWHIP_PROCESS_CONTEXT") != HOST_PROCESS_CONTEXT:
        raise RuntimeError("process-host-admission-required:non-qualifying:before-Popen")


def _observed_stop_signatures(records: list[dict[str, object]]) -> list[str]:
    """Count observed next stops as well as targeted repairs, by stable identity."""
    targets = {"tank-reset-stack-physical-frame": "tank-battle:load:invalid-rom",
               "recursion-movem-1822-48e7": "recursion94:cpu:001822:48e7:2"}
    seen = set()
    for row in records:
        if row.get("record_type") in ("history-correction", "filing-correction"):
            continue
        stop_id = row.get("stop_id")
        if stop_id:
            seen.add(row.get("target_stop_signature", targets.get(stop_id, str(stop_id))))
        stop = row.get("native_report") or row.get("post_behavior", {}).get("first_next_stop", {})
        if stop.get("stop_reason") in (2, 3, 4):
            pc = stop.get("instruction_address", stop.get("pc"))
            opcode = stop.get("opcode")
            if isinstance(pc, int) and isinstance(opcode, int):
                seen.add(f"{row['title_id']}:cpu:{pc:06x}:{opcode:04x}:{stop['stop_reason']}")
    return sorted(seen)


def _effective_attempt_receipts(records: list[dict[str, object]], stop_id: str) -> tuple[dict[str, tuple[str, int]], dict[str, dict[str, object]]]:
    executions: dict[str, tuple[str, int]] = {}
    collisions: dict[str, dict[str, object]] = {}
    for index, row in enumerate(records, start=1):
        if row.get("stop_id") != stop_id or row.get("record_type") in ("history-correction", "filing-correction"):
            continue
        record_id = str(row.get("record_id"))
        digest = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
        if record_id in executions:
            previous_digest, previous_index = executions[record_id]
            if digest != previous_digest:
                raise RuntimeError(f"duplicate execution record ID has conflicting contents: {record_id}")
            collision = collisions.setdefault(record_id, {"digest": digest, "indexes": [previous_index]})
            collision["indexes"].append(index)
        else:
            executions[record_id] = (digest, index)
    return executions, collisions


class RepairLedgerContract(unittest.TestCase):
    def test_distinct_budget_includes_discovered_next_stops_once(self) -> None:
        rows = [{"stop_id": "tank-reset-stack-physical-frame", "title_id": "tank-battle",
                 "post_behavior": {"first_next_stop": {"pc": 0x204, "opcode": 0x4e67, "stop_reason": 2}}},
                {"stop_id": "recursion-movem-1822-48e7", "title_id": "recursion94",
                 "native_report": {"instruction_address": 0x2528, "opcode": 0xc0fc, "stop_reason": 2}}]
        signatures = _observed_stop_signatures(rows + rows)
        self.assertEqual(signatures, ["recursion94:cpu:001822:48e7:2", "recursion94:cpu:002528:c0fc:2",
                                      "tank-battle:cpu:000204:4e67:2", "tank-battle:load:invalid-rom"])

    def test_identical_duplicate_receipt_is_counted_once(self) -> None:
        row = {"record_id": "attempt-1", "stop_id": "tank", "measurement": 12.5}
        executions, collisions = _effective_attempt_receipts([row, dict(row)], "tank")
        self.assertEqual(len(executions), 1)
        self.assertEqual(collisions["attempt-1"]["indexes"], [1, 2])

    def test_conflicting_duplicate_receipt_is_rejected(self) -> None:
        first = {"record_id": "attempt-1", "stop_id": "tank", "measurement": 12.5}
        forged = {"record_id": "attempt-1", "stop_id": "tank", "measurement": 13.5}
        with self.assertRaisesRegex(RuntimeError, "conflicting contents"):
            _effective_attempt_receipts([first, forged], "tank")

    def test_forged_history_correction_does_not_count_as_execution(self) -> None:
        forged = {"record_id": "correction-1", "record_type": "history-correction",
                  "stop_id": "tank", "recheck": {"control_outcome": "pass"}}
        executions, collisions = _effective_attempt_receipts([forged], "tank")
        self.assertEqual(executions, {})
        self.assertEqual(collisions, {})


class TracerContract(unittest.TestCase):
    client: pathlib.Path
    desktop: pathlib.Path
    runs: list[dict[str, object]]

    def test_truncated_route_is_rejected_before_report_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-phase6-invalid-route-") as directory:
            root = pathlib.Path(directory)
            rom, plan, report = root / "tracer.bin", root / "route.bin", root / "report.json"
            _write_tracer_rom(rom)
            plan.write_bytes(_plan([(1, 0)])[:-1])
            result = _run_client(self.client,
                [str(self.client), "--route-plan", str(plan), "--route-report", str(report), str(rom)],
                self.runs, report=report, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("REJECT: route-plan", result.stderr)
            self.assertFalse(report.exists(), "rejected route mutated the session/report path")

    def test_route_plan_and_report_are_accepted(self) -> None:
        """The public headless client accepts a bounded route plan and report path."""
        with tempfile.TemporaryDirectory(prefix="gw-phase6-route-interface-") as directory:
            root = pathlib.Path(directory)
            rom, plan, report = root / "tracer.bin", root / "route.bin", root / "report.json"
            _write_tracer_rom(rom)
            plan.write_bytes(_plan([(1, 0)]))
            result = _run_client(self.client,
                [str(self.client), "--route-plan", str(plan), "--route-report", str(report), str(rom)],
                self.runs, report=report, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(report.exists(), "route report was not written")

    def test_completed_marker_dispatch_reaches_guest_poll(self) -> None:
        """The completed marker gates Right; the following poll sees press then release."""
        with tempfile.TemporaryDirectory(prefix="gw-phase6-tracer-") as directory:
            root = pathlib.Path(directory)
            rom = root / "tracer.bin"
            plan = root / "route.bin"
            report = root / "report.json"
            _write_tracer_rom(rom)
            control_plan = root / "control.bin"
            control_report = root / "control.json"
            control_plan.write_bytes(_plan([(1, 0), (3, 0)]))
            control = _run_client(self.client,
                [str(self.client), "--route-plan", str(control_plan), "--route-report", str(control_report),
                 str(rom)], self.runs, report=control_report, timeout=30)
            self.assertEqual(control.returncode, 0, control.stderr)
            control_observations = json.loads(control_report.read_text())["observations"]
            self.assertEqual([item["value"] for item in control_observations], [1, 3])
            desktop_control_report = root / "desktop-control.json"
            desktop_control = _run_desktop(self.desktop, control_plan, desktop_control_report, rom, root, self.runs)
            self.assertEqual(desktop_control.returncode, 0, desktop_control.stderr)
            self.assertEqual([item["value"] for item in json.loads(desktop_control_report.read_text())["observations"]], [1, 3])
            self.assertTrue(json.loads(desktop_control_report.read_text())["host"]["audio_open"])

            plan.write_bytes(_plan([(1, 8), (2, 0), (3, 0)]))
            result = _run_client(self.client,
                [str(self.client), "--route-plan", str(plan), "--route-report", str(report),
                 str(rom)], self.runs, report=report, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr + (report.read_text() if report.exists() else ""))
            observations = json.loads(report.read_text())["observations"]
            self.assertEqual([item["value"] for item in observations], [1, 2, 3])
            self.assertEqual([item["mask"] for item in observations], [8, 0, 0])
            desktop_report = root / "desktop-report.json"
            desktop = _run_desktop(self.desktop, plan, desktop_report, rom, root, self.runs)
            self.assertEqual(desktop.returncode, 0, desktop.stderr)
            desktop_observations = json.loads(desktop_report.read_text())["observations"]
            self.assertEqual([item["value"] for item in desktop_observations], [1, 2, 3])
            self.assertEqual([item["mask"] for item in desktop_observations], [8, 0, 0])
            self.assertTrue(json.loads(desktop_report.read_text())["host"]["audio_open"])


class NativeParserContract(unittest.TestCase):
    client: pathlib.Path
    desktop: pathlib.Path
    clients: tuple[pathlib.Path, ...]
    runs: list[dict[str, object]]

    def test_phase7_launcher_keeps_shorter_caller_deadline(self) -> None:
        self.runs = []
        with tempfile.TemporaryDirectory(prefix="gw-short-caller-deadline-") as directory:
            root = pathlib.Path(directory)
            limits = {"wall_seconds": 5, "cleanup_grace_seconds": 1,
                "max_rss_bytes": 1024 * 1024 * 1024, "max_stdout_stderr_bytes": 4096,
                "max_json_bytes": 4096, "max_binary_file_bytes": 4096,
                "max_capture_bytes": 4096, "max_scratch_bytes": 4096,
                "max_retained_bytes": 4096, "max_fields": 10, "max_calls": 10}
            started = time.monotonic()
            result = _run_client(pathlib.Path(sys.executable),
                [sys.executable, "-c", "import time; time.sleep(30)"], self.runs,
                report=root / "none.json", timeout=0.3, cwd=root, limits=limits,
                scratch_roots=(root,))
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 2)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.runs[-1]["bound_violation_reason"], "phase7-wall-timeout")
            self.assertEqual(self.runs[-1]["process_group_cleanup"], "confirmed")
            receipt_path = os.environ.get("GENEWHIP_F1_RECEIPT")
            if receipt_path:
                receipt = {"schema": "genewhip.phase7-f1-deadline-check.v1", "outcome": "pass",
                    "caller_timeout_seconds": 0.3, "child_limit_seconds": limits["wall_seconds"],
                    "elapsed_seconds": round(elapsed, 3),
                    "bound_violation_reason": self.runs[-1]["bound_violation_reason"],
                    "process_group_cleanup": self.runs[-1]["process_group_cleanup"]}
                destination = pathlib.Path(receipt_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")

    def test_darwin_group_liveness_distinguishes_zombies(self) -> None:
        for states, expected in ((["Z"], False), (["Z", "R+"], True),
                                 (["S"], True), ([], False)):
            with mock.patch.object(sys, "platform", "darwin"), mock.patch(
                    __name__ + "._darwin_status_states", return_value=(states, True)):
                self.assertEqual(_process_group_exists(42), expected)
        for cleanup_ok in (False,):
            with mock.patch.object(sys, "platform", "darwin"), mock.patch(
                    __name__ + "._darwin_status_states", return_value=(None, cleanup_ok)), mock.patch(
                    "os.killpg", side_effect=PermissionError("denied")):
                self.assertTrue(_process_group_exists(42), "unknown query remains conservatively live")
        with mock.patch.object(sys, "platform", "darwin"), mock.patch(
                __name__ + "._darwin_status_states", return_value=(None, True)), mock.patch(
                "os.killpg", side_effect=ProcessLookupError()):
            self.assertFalse(_process_group_exists(42))

    def test_partial_json_cannot_erase_completed_process_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-partial-report-") as directory:
            report=pathlib.Path(directory)/"partial.json"
            before=len(self.runs)
            code="import pathlib;pathlib.Path("+repr(str(report))+").write_text('{broken')"
            with self.assertRaises(json.JSONDecodeError):
                _run_client(self.client,[sys.executable,"-c",code],self.runs,report=report,timeout=10)
            self.assertEqual(len(self.runs),before+1,"malformed report cannot erase completed process receipt")
            self.assertEqual(self.runs[-1]["return_code"],0)
            self.assertEqual(self.runs[-1]["report_parse_failure"],"invalid-json")

    def test_bounded_malformed_route_matrix_both_clients(self) -> None:
        operations = [_operation()]
        invalid = {
            "unknown-op": _plan_ops([_operation(op_type=2)]),
            "zero-spans": _plan_ops([_operation(span_count=0, include_spans=False)]),
            "too-many-spans": _plan_ops([_operation(span_count=65, include_spans=False)]),
            "zero-length": _plan_ops([_operation(span_length=0)]),
            "oversized-span": _plan_ops([_operation(span_length=65)]),
            "bad-port": _plan_ops([_operation(port=2)]),
            "bad-mask": _plan_ops([_operation(mask=256)]),
            "reserved-nonzero": _plan_ops([_operation(reserved=1)]),
            "bad-address": _plan_ops([_operation(address=0x1000000)]),
            "wrapping-address": _plan_ops([_operation(address=0xFFFFF0, span_length=64)]),
            "out-of-order-ticks": _plan_ops([_operation(tick=20), _operation(tick=19)]),
            "explicit-after-observation-tick": _plan_ops([_operation(tick=0xFFFFFFFFFFFFFFFF), _operation(tick=20)]),
            "tick-overflow": _plan_ops([_operation(tick=(2**64 - 1) - (1 << 32) + 1)]),
            "truncated": _plan_ops(operations)[:-1],
            "extra-bytes": _plan_ops(operations) + b"x",
            "too-many-operations": struct.pack("<4sHHI", b"GWRP", 1, 4097, 0),
            "oversized-file": struct.pack("<4sHHI", b"GWRP", 1, 1, 0) + bytes(MAX_STREAM_BYTES + 1),
        }
        with tempfile.TemporaryDirectory(prefix="gw-phase6-malformed-matrix-") as directory:
            root = pathlib.Path(directory)
            rom = root / "tracer.bin"
            _write_tracer_rom(rom)
            for name, payload in invalid.items():
                for client in self.clients:
                    plan, report = root / f"{name}.bin", root / f"{name}.json"
                    plan.write_bytes(payload)
                    result = _run_client(client,
                        [str(client), "--route-plan", str(plan), "--route-report", str(report), str(rom)],
                        self.runs, report=report, timeout=15)
                    self.assertNotEqual(result.returncode, 0, name)
                    self.assertIn("REJECT: route-plan", result.stderr, name)
                    self.assertFalse(report.exists(), f"{name} mutated report/session state")

    def test_process_group_and_stream_caps_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-phase6-process-bounds-") as directory:
            root = pathlib.Path(directory)
            child_pid = root / "child.pid"
            code = ("import subprocess,sys,time,pathlib; "
                    "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); "
                    f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid)); "
                    "sys.stdout.write('x'*3000000);sys.stdout.flush();time.sleep(30)")
            helper_error = None
            try:
                result = _run_client(self.client, [sys.executable, "-c", code], self.runs,
                                     report=root / "none.json", timeout=10)
            except RuntimeError as error:
                helper_error = error
                result = None
            finally:
                if child_pid.is_file():
                    child = int(child_pid.read_text())
                    launch = self.runs[-1] if self.runs else {}
                    group = launch.get("pgid")
                    try:
                        child_group = os.getpgid(child)
                    except ProcessLookupError:
                        child_group = None
                    if child_group is not None and (not isinstance(group, int) or child_group != group):
                        self.fail("test cleanup refused a PID outside the helper's recorded process group")
                    if child_group is not None:
                        try:
                            os.kill(child, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        deadline = time.monotonic() + 1
                        while time.monotonic() < deadline:
                            try:
                                os.kill(child, 0)
                            except ProcessLookupError:
                                break
                            time.sleep(0.02)
                        else:
                            os.kill(child, signal.SIGKILL)
                            deadline = time.monotonic() + 1
                            while time.monotonic() < deadline:
                                try:
                                    os.kill(child, 0)
                                except ProcessLookupError:
                                    break
                                time.sleep(0.02)
                            else:
                                self.fail("test cleanup could not reap the exact helper child")
            if helper_error is not None:
                self.fail(f"bounded process helper preserved but could not confirm group cleanup: {helper_error}")
            assert result is not None
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(self.runs[-1]["bound_violation"])
            child = int(child_pid.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail("watchdog left a spawned process running outside its process group")

    def test_process_group_is_killed_when_leader_exits_first(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-process-leader-exit-") as directory:
            root = pathlib.Path(directory)
            child_pid = root / "child.pid"
            child_code = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)"
            code = ("import subprocess,sys,pathlib; "
                    f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
                    f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid))")
            before = len(self.runs)
            result = _run_client(self.client, [sys.executable, "-c", code], self.runs,
                                 report=root / "none.json", timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(len(self.runs), before + 1)
            self.assertTrue(self.runs[-1]["bound_violation"])
            child = int(child_pid.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail("watchdog left a descendant alive after its leader exited")

    @mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": HOST_PROCESS_CONTEXT})
    def test_monitored_symlink_is_rejected_before_process_start(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-monitored-output-") as directory:
            root = pathlib.Path(directory)
            target = root / "target"
            target.write_text("safe")
            link = root / "sdlaudio.raw"
            link.symlink_to(target)
            starts = []
            with mock.patch("subprocess.Popen", side_effect=lambda *a, **k: starts.append(a)):
                with self.assertRaisesRegex(RuntimeError, "unsafe monitored output path"):
                    _run_client(self.client, [sys.executable, "-c", "pass"], self.runs,
                        report=root/"report.json", timeout=2, cwd=root,
                        monitored_files=((link, 1024),))
            self.assertEqual(starts, [], "symlink output denial must precede process creation")

    def test_preimport_popen_denial_is_observed_and_sticky(self) -> None:
        """A denied no-ROM synthetic launch stays denied across helper import/use."""
        require_host_process_context()
        code = ("import subprocess,runpy,sys\ncalls=[]\n"
            "subprocess.Popen=lambda *a,**k:(calls.append(a), (_ for _ in ()).throw(RuntimeError('DENIED')))[1]\n"
            f"runpy.run_path({str(pathlib.Path(__file__).resolve())!r},run_name='guard_probe')\n"
            "try:\n subprocess.Popen([sys.executable,'-c','pass'])\n"
            "except RuntimeError as e:\n assert str(e)=='DENIED'\n"
            "assert len(calls)==1\n")
        result = subprocess.run([sys.executable, "-c", code], text=True,
                                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_popen_mock_does_not_replace_the_launch_boundary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-wrong-popen-mock-") as directory:
            root=pathlib.Path(directory)
            wrong_mock_calls=[]
            before=len(self.runs)
            with mock.patch("os.popen", side_effect=lambda *a,**k:wrong_mock_calls.append(a)):
                result=_run_client(self.client,[sys.executable,"-c","pass"],self.runs,
                    report=root/"report.json",timeout=5,cwd=root)
            self.assertEqual(result.returncode,0)
            self.assertEqual(wrong_mock_calls,[])
            self.assertEqual(len(self.runs),before+1,"subprocess.Popen boundary receipt proves the child actually started")

    @mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": HOST_PROCESS_CONTEXT})
    def test_sigterm_during_popen_is_deferred_until_the_group_is_owned(self) -> None:
        class FakeProcess:
            pid = 424242

            def poll(self):
                return None

            def wait(self, timeout=None):
                return -signal.SIGTERM

        with tempfile.TemporaryDirectory(prefix="gw-sigterm-popen-window-") as directory:
            root = pathlib.Path(directory)
            runs = []
            prior = signal.getsignal(signal.SIGTERM)
            process = FakeProcess()
            calls = []

            def launch(*_args, **_kwargs):
                signal.raise_signal(signal.SIGTERM)
                return process

            try:
                with mock.patch("subprocess.Popen", side_effect=launch), mock.patch(
                        f"{__name__}._terminate_process_group", side_effect=lambda *a, **k: calls.append(a) or True):
                    with self.assertRaisesRegex(KeyboardInterrupt, "bounded child cleanup"):
                        _run_client(pathlib.Path(sys.executable), [sys.executable, "-c", "pass"],
                            runs, report=root / "report.json", timeout=2, cwd=root)
                self.assertTrue(calls, "pending SIGTERM must terminate the newly owned group")
                self.assertEqual(runs[-1]["pid"], process.pid)
                self.assertEqual(runs[-1]["process_group_cleanup"], "confirmed")
            finally:
                self.assertIs(signal.getsignal(signal.SIGTERM), prior,
                    "prior SIGTERM disposition must be restored after cancellation")

    @mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": HOST_PROCESS_CONTEXT})
    def test_sigterm_after_pid_registration_uses_owned_group_cleanup(self) -> None:
        class FakeProcess:
            pid = 424243
            signalled = False

            def poll(self):
                if not self.signalled:
                    self.signalled = True
                    signal.raise_signal(signal.SIGTERM)
                return None

            def wait(self, timeout=None):
                return -signal.SIGTERM

        with tempfile.TemporaryDirectory(prefix="gw-sigterm-owned-pid-") as directory:
            root = pathlib.Path(directory)
            runs = []
            prior = signal.getsignal(signal.SIGTERM)
            process = FakeProcess()
            calls = []
            try:
                with mock.patch("subprocess.Popen", return_value=process), mock.patch(
                        f"{__name__}._terminate_process_group", side_effect=lambda *a, **k: calls.append(a) or True):
                    with self.assertRaisesRegex(KeyboardInterrupt, "bounded child cleanup"):
                        _run_client(pathlib.Path(sys.executable), [sys.executable, "-c", "pass"],
                            runs, report=root / "report.json", timeout=2, cwd=root)
                self.assertTrue(calls)
                self.assertEqual(runs[-1]["process_group_cleanup"], "confirmed")
            finally:
                self.assertIs(signal.getsignal(signal.SIGTERM), prior)

    @mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": HOST_PROCESS_CONTEXT})
    def test_sigterm_and_launch_error_restore_previous_handler_without_owned_child(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-sigterm-launch-error-") as directory:
            root = pathlib.Path(directory)
            runs = []
            prior = signal.getsignal(signal.SIGTERM)

            def fail_launch(*_args, **_kwargs):
                signal.raise_signal(signal.SIGTERM)
                raise OSError("synthetic launch failure")

            try:
                with mock.patch("subprocess.Popen", side_effect=fail_launch):
                    result = _run_client(pathlib.Path(sys.executable), [sys.executable, "-c", "pass"],
                        runs, report=root / "report.json", timeout=2, cwd=root)
                self.assertEqual(result.returncode, 127)
                self.assertEqual(runs[-1]["process_group_cleanup"], "not-launched")
            finally:
                self.assertIs(signal.getsignal(signal.SIGTERM), prior,
                    "failed Popen must restore the previous SIGTERM disposition")

    @mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": HOST_PROCESS_CONTEXT})
    def test_runner_setup_error_restores_previous_handler_before_any_launch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-sigterm-setup-error-") as directory:
            root = pathlib.Path(directory)
            runs = []
            target = root / "target"
            target.write_text("safe")
            report = root / "report.json"
            report.symlink_to(target)
            prior = signal.getsignal(signal.SIGTERM)
            with mock.patch("subprocess.Popen", side_effect=AssertionError("launch-must-not-run")):
                with self.assertRaisesRegex(RuntimeError, "unsafe report output path"):
                    _run_client(pathlib.Path(sys.executable), [sys.executable, "-c", "pass"],
                        runs, report=report, timeout=2, cwd=root)
            self.assertIs(signal.getsignal(signal.SIGTERM), prior,
                "prelaunch setup failure must restore previous SIGTERM disposition")


class DesktopOutputContract(unittest.TestCase):
    def _desktop_module(self):
        path=pathlib.Path(__file__).resolve().parents[1]/"desktop/phase6_routes.py"
        spec=importlib.util.spec_from_file_location("phase6_desktop_output_contract",path)
        assert spec is not None and spec.loader is not None
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_json_writer_rejects_existing_hardlink_without_truncation(self):
        module=self._desktop_module()
        with tempfile.TemporaryDirectory(prefix="gw-json-hardlink-") as directory:
            root=pathlib.Path(directory)
            original=root/"original.json"
            output=root/"output.json"
            original.write_text("protected")
            os.link(original,output)
            with self.assertRaisesRegex(RuntimeError,"non-exclusive JSON output"):
                module.write_json(output,{"replacement":True})
            self.assertEqual(original.read_text(),"protected")
            self.assertEqual(original.stat().st_nlink,2)


class ScratchTreeContract(unittest.TestCase):
    def test_scratch_symlink_stays_rejected_and_records_private_relative_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-scratch-symlink-") as directory:
            root = pathlib.Path(directory)
            target = root / "target"
            target.write_text("safe")
            (root / "link").symlink_to(target)
            diagnostics: list[dict[str, object]] = []
            self.assertIsNone(_safe_tree_bytes(root, diagnostics))
            self.assertEqual(diagnostics, [{"kind": "symlink-file", "path": "link",
                                           "link_count": 1, "owned": True}])

    def test_file_disappearing_after_enumeration_is_recorded_and_skipped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-scratch-disappeared-") as directory:
            root = pathlib.Path(directory)
            target = root / "changing"
            target.write_text("safe")
            diagnostics: list[dict[str, object]] = []
            original_lstat = pathlib.Path.lstat

            def unlink_before_lstat(path: pathlib.Path):
                if path == target:
                    path.unlink()
                return original_lstat(path)

            with mock.patch.object(pathlib.Path, "lstat", unlink_before_lstat):
                measured = _safe_tree_bytes(root, diagnostics)
            self.assertEqual(measured, 0, "a path absent at lstat contributes no live scratch bytes")
            self.assertEqual(diagnostics, [{"kind": "path-disappeared-during-scan", "errno": 2,
                                           "path": "changing"}])

    def test_permission_scan_error_stays_rejected_and_records_errno(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-scratch-permission-") as directory:
            root = pathlib.Path(directory)
            target = root / "protected"
            target.write_text("safe")
            diagnostics: list[dict[str, object]] = []
            error = PermissionError(13, "simulated inaccessible file", str(target))
            with mock.patch.object(pathlib.Path, "lstat", side_effect=error):
                measured = _safe_tree_bytes(root, diagnostics)
            self.assertIsNone(measured, "permission failures must remain fail-closed")
            self.assertEqual(diagnostics, [{"kind": "scan-oserror", "errno": 13,
                                           "error_type": "PermissionError", "path": "protected"}])

    def test_file_disappearing_after_lstat_uses_safe_metadata_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-scratch-renamed-") as directory:
            root = pathlib.Path(directory)
            target = root / "changing"
            target.write_text("safe")
            diagnostics: list[dict[str, object]] = []
            original_lstat = pathlib.Path.lstat

            def unlink_after_lstat(path: pathlib.Path):
                info = original_lstat(path)
                if path == target:
                    path.unlink()
                return info

            with mock.patch.object(pathlib.Path, "lstat", unlink_after_lstat):
                measured = _safe_tree_bytes(root, diagnostics)
            self.assertEqual(measured, 4, "count the lstat size conservatively after path replacement")
            self.assertFalse(target.exists())
            self.assertEqual(diagnostics, [])

    def test_hardlink_stays_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-scratch-hardlink-") as directory:
            root = pathlib.Path(directory)
            original = root / "original"
            original.write_text("safe")
            os.link(original, root / "alias")
            diagnostics: list[dict[str, object]] = []
            self.assertIsNone(_safe_tree_bytes(root, diagnostics))
            self.assertEqual(diagnostics[0]["kind"], "hardlink-file")

    def test_special_file_stays_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-scratch-special-") as directory:
            root = pathlib.Path(directory)
            os.mkfifo(root / "pipe")
            diagnostics: list[dict[str, object]] = []
            self.assertIsNone(_safe_tree_bytes(root, diagnostics))
            self.assertEqual(diagnostics[0]["kind"], "non-regular-file")

    def test_foreign_owner_stays_rejected(self) -> None:
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory(prefix="gw-scratch-owner-") as directory:
            root = pathlib.Path(directory)
            (root / "owned-by-other").write_text("safe")
            diagnostics: list[dict[str, object]] = []
            foreign = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1,
                                      st_uid=os.getuid() + 1, st_size=4)
            with mock.patch.object(pathlib.Path, "lstat", return_value=foreign):
                self.assertIsNone(_safe_tree_bytes(root, diagnostics))
            self.assertEqual(diagnostics[0]["kind"], "foreign-owner-file")

    def test_scratch_byte_cap_remains_enforced_with_private_scan_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-scratch-cap-") as directory:
            root = pathlib.Path(directory)
            scratch = root / "scratch"
            scratch.mkdir()
            (scratch / "large").write_bytes(b"too large")
            diagnostics: list[dict[str, object]] = []
            runs: list[dict[str, object]] = []
            limits = {"wall_seconds": 5, "cleanup_grace_seconds": 2,
                      "max_rss_bytes": 4 * 1024**3, "max_stdout_stderr_bytes": 1024,
                      "max_json_bytes": 1024, "max_binary_file_bytes": 1024,
                      "max_capture_bytes": 1024, "max_scratch_bytes": 1,
                      "max_retained_bytes": 1024, "max_fields": 10, "max_calls": 10}
            result = _run_client(pathlib.Path(sys.executable),
                [sys.executable, "-c", "import time; time.sleep(5)"], runs,
                report=root / "report.json", timeout=5, cwd=root, limits=limits,
                scratch_roots=(scratch,), scratch_diagnostics=diagnostics)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(runs[-1]["bound_violation_reason"], "phase7-scratch-byte-limit")
            self.assertEqual(runs[-1]["process_group_cleanup"], "confirmed")
            self.assertEqual(diagnostics, [])



def _write_tracer_rom(path: pathlib.Path) -> None:
    rom_bytes = bytearray(514)
    struct.pack_into(">II", rom_bytes, 0, 0x00FF0000, 0x00000200)
    # Setup, completed marker 1, poll active-low Right and publish 2 when
    # pressed or 3 when released, then repeat the poll.
    rom_bytes[512:] = bytes.fromhex(
        "13fc004000a10009 13fc004000a10003 "
        "33fc000100ff0000 103900a10003 08000003 670a "
        "33fc000300ff0000 60ea 33fc000200ff0000 60e0"
    )
    path.write_bytes(rom_bytes)


def _plan(steps: list[tuple[int, int]]) -> bytes:
    records = []
    for value, mask in steps:
        records.append(_operation(value=value, mask=mask))
    return _plan_ops(records)


def _operation(*, value: int = 1, mask: int = 0, op_type: int = 1, port: int = 0,
               span_count: int = 1, include_spans: bool = True, span_length: int = 2,
               address: int = 0xFF0000, tick: int = 0xFFFFFFFFFFFFFFFF, reserved: int = 0) -> bytes:
    header = struct.pack("<BBHIIQQ", op_type, port, span_count, mask, reserved, 100000, tick)
    spans = b""
    if include_spans:
        spans = struct.pack("<IB3s", address, span_length, b"\0\0\0") + struct.pack(">H", value)
    return header + spans


def _plan_ops(operations: list[bytes]) -> bytes:
    return struct.pack("<4sHHI", b"GWRP", 1, len(operations), 0) + b"".join(operations)


def _run_desktop(client: pathlib.Path, plan: pathlib.Path, report: pathlib.Path,
                 rom: pathlib.Path, cwd: pathlib.Path,
                 runs: list[dict[str, object]], extra=()) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["SDL_VIDEODRIVER"] = "dummy"
    environment["SDL_AUDIODRIVER"] = "disk"
    return _run_client(client,
        [str(client), "--route-plan", str(plan), "--route-report", str(report), *extra, str(rom)],
        runs, report=report, timeout=60, cwd=cwd, env=environment)


def _run_client(client: pathlib.Path, command: list[str], runs: list[dict[str, object]], *,
                report: pathlib.Path, timeout: int, cwd: pathlib.Path | None = None,
                env: dict[str, str] | None = None,
                retained_streams: dict | None = None,
                monitored_files: tuple[tuple[pathlib.Path, int], ...] = (),
                monitored_directories: tuple[tuple[pathlib.Path, int, int], ...] = (),
                limits: dict[str, object] | None = None,
                scratch_roots: tuple[pathlib.Path, ...] = (),
                scratch_diagnostics: list[dict[str, object]] | None = None,
                process_receipt_stream=None, ownership_callback=None) -> subprocess.CompletedProcess[str]:
    """Keep SIGTERM deferred until the launched child's ownership is explicit."""
    require_host_process_context()
    if ownership_callback is not None and process_receipt_stream is None:
        raise ValueError("owned callback requires durable receipt sink")
    def persist_receipt():
        if process_receipt_stream is not None:
            process_receipt_stream.seek(0)
            json.dump({"processes": runs}, process_receipt_stream, sort_keys=True, indent=2)
            process_receipt_stream.write("\n")
            process_receipt_stream.truncate()
            process_receipt_stream.flush()
            os.fsync(process_receipt_stream.fileno())

    def record_ownership():
        persist_receipt()
        if ownership_callback is not None:
            ownership_callback(runs[-1])

    # A failing or unsafe sink must fail before any child can be created.
    persist_receipt()
    cancellation = {"requested": False}
    prior_sigterm = None
    installed = False
    if threading.current_thread() is threading.main_thread():
        prior_sigterm = signal.getsignal(signal.SIGTERM)

        def defer_sigterm(_signum, _frame):
            cancellation["requested"] = True

        signal.signal(signal.SIGTERM, defer_sigterm)
        installed = True
    try:
        return _run_client_owned(client, command, runs, report=report, timeout=timeout,
            cwd=cwd, env=env, retained_streams=retained_streams,
            monitored_files=monitored_files, monitored_directories=monitored_directories,
            limits=limits, scratch_roots=scratch_roots,
            scratch_diagnostics=scratch_diagnostics, _cancellation=cancellation,
            _ownership_callback=record_ownership)
    except BaseException as error:
        error.process_receipts = runs
        raise
    finally:
        try:
            persist_receipt()
        except BaseException as error:
            error.process_receipts = runs
            raise
        finally:
            if installed:
                signal.signal(signal.SIGTERM, prior_sigterm)


def _run_client_owned(client: pathlib.Path, command: list[str], runs: list[dict[str, object]], *,
                report: pathlib.Path, timeout: int, cwd: pathlib.Path | None = None,
                env: dict[str, str] | None = None,
                retained_streams: dict | None = None,
                monitored_files: tuple[tuple[pathlib.Path, int], ...] = (),
                monitored_directories: tuple[tuple[pathlib.Path, int, int], ...] = (),
                limits: dict[str, object] | None = None,
                scratch_roots: tuple[pathlib.Path, ...] = (),
                scratch_diagnostics: list[dict[str, object]] | None = None,
                _cancellation: dict[str, bool] | None = None,
                _ownership_callback=None) -> subprocess.CompletedProcess[str]:
    # None deliberately preserves the historical Phase 6 contract. Phase 7
    # callers opt into these per-child limits without changing old receipts.
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("child-timeout-invalid")
    if limits is not None:
        required = {"wall_seconds", "cleanup_grace_seconds", "max_rss_bytes",
                    "max_stdout_stderr_bytes", "max_json_bytes", "max_binary_file_bytes",
                    "max_capture_bytes", "max_scratch_bytes", "max_retained_bytes",
                    "max_fields", "max_calls"}
        if (set(limits) != required or any(type(value) not in (int, float) or
                not math.isfinite(value) or value <= 0 for value in limits.values())):
            raise ValueError("phase7-child-limits-invalid")
        if not scratch_roots or any(path.is_symlink() or not path.is_dir() for path in scratch_roots):
            raise ValueError("phase7-scratch-root-invalid")
        if scratch_diagnostics is None:
            scratch_diagnostics = []
        # The caller may be enforcing a shared batch deadline. Preserve that
        # remaining budget while applying the per-child ceiling.
        timeout = min(float(timeout), float(limits["wall_seconds"]))
    started = time.perf_counter()
    bound_violation = None
    timed_out = False
    cleanup_confirmed = True
    with tempfile.TemporaryDirectory(prefix="gw-phase6-child-output-") as capture_dir:
        stdout_path, stderr_path = pathlib.Path(capture_dir) / "stdout", pathlib.Path(capture_dir) / "stderr"
        with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
            if report.is_symlink() or (report.exists() and not report.is_file()):
                raise RuntimeError(f"unsafe report output path: {report}")
            if report.exists():
                previous = report.lstat()
                if previous.st_uid != os.getuid() or previous.st_nlink != 1:
                    raise RuntimeError(f"report output is not exclusively owned: {report}")
                report.unlink()
            for path, ceiling in monitored_files:
                if ceiling < 0 or path.is_symlink():
                    raise RuntimeError(f"unsafe monitored output path: {path}")
            for directory, file_count, ceiling in monitored_directories:
                info = directory.lstat()
                if (not directory.is_dir() or directory.is_symlink() or info.st_uid != os.getuid() or
                        file_count < 0 or ceiling < 0 or any(directory.iterdir())):
                    raise RuntimeError(f"unsafe monitored output directory: {directory}")
            if _cancellation and _cancellation["requested"]:
                raise KeyboardInterrupt("parent requested bounded child cleanup before launch")
            kwargs: dict[str, object] = {"cwd": cwd, "env": env, "stdout": stdout_file, "stderr": stderr_file}
            if os.name == "posix":
                kwargs["start_new_session"] = True
                kwargs["preexec_fn"] = _limit_child_file_size
            # Check again at the actual creation seam, including callers of
            # the owned helper and admission removed during prelaunch setup.
            require_host_process_context()
            try:
                process = subprocess.Popen(command, **kwargs)
            except Exception as error:
                entry = {"pid": None, "pgid": None, "status": "launch-failed",
                         "launch_error": f"{type(error).__name__}: {error}",
                         "wall_seconds": time.perf_counter() - started,
                         "process_group_cleanup": "not-launched", "bound_violation": True}
                runs.append(entry)
                return subprocess.CompletedProcess(command, 127, "",
                    f"launch failed: {type(error).__name__}: {error}")
            process_entry: dict[str, object] = {
                "pid": process.pid,
                "pgid": process.pid if os.name == "posix" else None,
                "status": "started",
            }
            runs.append(process_entry)
            cleanup_status_budget = {
                "remaining": _DARWIN_CLEANUP_MAX_STATUS_QUERIES,
                "attempted": 0,
                "last_reason": "cleanup-unclassified",
                "status_reason": "not-observed",
            }

            def terminate_group() -> bool:
                nonlocal cleanup_confirmed, bound_violation
                # At most one finite termination sequence per owned child.
                if "process_group_cleanup" in process_entry:
                    return cleanup_confirmed
                try:
                    grace = limits["cleanup_grace_seconds"] if limits is not None else None
                    if sys.platform == "darwin":
                        terminated = _terminate_process_group(
                            process, grace_seconds=grace, status_budget=cleanup_status_budget)
                    else:
                        terminated = _terminate_process_group(process, grace_seconds=grace)
                    cleanup_confirmed = terminated and cleanup_confirmed
                except PermissionError as error:
                    # Keep the exact launch identity and cleanup failure visible.
                    # Kill/reap only the direct child here; descendants remain an
                    # explicit containment failure for the caller to reconcile.
                    cleanup_confirmed = False
                    bound_violation = bound_violation or "process-group-cleanup-permission-denied"
                    cleanup_status_budget["last_reason"] = "cleanup-permission-denied"
                    process_entry["cleanup_error"] = f"{type(error).__name__}: {error}"
                    try:
                        process.terminate()
                        process.wait(timeout=2)
                    except ProcessLookupError:
                        pass
                    except subprocess.TimeoutExpired:
                        try:
                            process.kill()
                            process.wait(timeout=2)
                        except (OSError, subprocess.TimeoutExpired) as direct_error:
                            process_entry["direct_child_cleanup_error"] = f"{type(direct_error).__name__}: {direct_error}"
                    except OSError as direct_error:
                        process_entry["direct_child_cleanup_error"] = f"{type(direct_error).__name__}: {direct_error}"
                except OSError as error:
                    cleanup_confirmed = False
                    bound_violation = bound_violation or "process-group-cleanup-os-error"
                    cleanup_status_budget["last_reason"] = "group-cleanup-os-error"
                    try:
                        process.terminate()
                        process.wait(timeout=2)
                    except ProcessLookupError:
                        pass
                    except subprocess.TimeoutExpired:
                        try:
                            process.kill()
                            process.wait(timeout=2)
                        except (OSError, subprocess.TimeoutExpired) as direct_error:
                            process_entry["direct_child_cleanup_error"] = f"{type(direct_error).__name__}: {direct_error}"
                    except OSError as direct_error:
                        process_entry["direct_child_cleanup_error"] = f"{type(direct_error).__name__}: {direct_error}"
                process_entry["process_group_cleanup"] = "confirmed" if cleanup_confirmed else "unconfirmed"
                if not cleanup_confirmed:
                    reason = cleanup_status_budget.get("last_reason")
                    process_entry["cleanup_reason"] = (
                        reason if reason in SAFE_CLEANUP_REASONS else "cleanup-unclassified")
                    process_entry["cleanup_observation_attempts"] = min(
                        _DARWIN_CLEANUP_MAX_STATUS_QUERIES,
                        max(0, int(cleanup_status_budget.get("attempted", 0))))
                    status_reason = cleanup_status_budget.get("status_reason")
                    process_entry["cleanup_status_observation"] = (
                        status_reason if status_reason in SAFE_CLEANUP_REASONS else "cleanup-unclassified")
                return cleanup_confirmed

            def inspect_outputs() -> None:
                nonlocal bound_violation
                for directory, file_count, ceiling in monitored_directories:
                    entries = list(os.scandir(directory))
                    total = 0
                    if len(entries) > file_count:
                        bound_violation = f"monitored output file count exceeded: {directory.name}"
                        return
                    for item in entries:
                        info = item.stat(follow_symlinks=False)
                        if (item.is_symlink() or not item.is_file(follow_symlinks=False) or
                                info.st_uid != os.getuid() or info.st_nlink != 1):
                            bound_violation = f"unsafe monitored output entry: {item.name}"
                            return
                        total += info.st_size
                    if total > ceiling:
                        bound_violation = f"monitored output byte ceiling exceeded: {directory.name}"
                        return
                    if limits is not None and total > limits["max_binary_file_bytes"]:
                        bound_violation = f"phase7-binary-file-byte-limit:{directory.name}"
                        return
                if limits is not None:
                    if report.exists() and report.stat().st_size > limits["max_json_bytes"]:
                        bound_violation = "phase7-json-byte-limit"
                        return
                    if report.exists() and report.stat().st_size > MAX_REPORT_BYTES:
                        bound_violation = "phase7-json-byte-limit"
                        return
                    for path, ceiling in monitored_files:
                        if path.exists() and path.stat().st_size > min(ceiling, limits["max_binary_file_bytes"]):
                            bound_violation = f"phase7-binary-file-byte-limit:{path.name}"
                            return
                    scratch_bytes = 0
                    for scratch_root in scratch_roots:
                        measured = _safe_tree_bytes(scratch_root, scratch_diagnostics)
                        if measured is None:
                            if scratch_diagnostics:
                                process_entry["scratch_tree_diagnostics"] = scratch_diagnostics[:8]
                            bound_violation = "phase7-scratch-tree-unsafe"
                            return
                        scratch_bytes += measured
                    if scratch_bytes > limits["max_scratch_bytes"]:
                        bound_violation = "phase7-scratch-byte-limit"
                        return
                    capture_bytes = stdout_path.stat().st_size + stderr_path.stat().st_size
                    if capture_bytes > limits["max_stdout_stderr_bytes"]:
                        bound_violation = "phase7-stdout-stderr-byte-limit"
                        return
                    if capture_bytes > limits["max_capture_bytes"]:
                        bound_violation = "phase7-capture-byte-limit"
                        return
                    rss_bytes = _process_group_rss_bytes(process.pid)
                    process_entry["rss_bytes_observed"] = rss_bytes
                    if rss_bytes is None:
                        bound_violation = "phase7-rss-observation-unavailable"
                        return
                    process_entry["rss_bytes_peak"] = max(
                        int(process_entry.get("rss_bytes_peak", 0)), rss_bytes)
                    if rss_bytes > limits["max_rss_bytes"]:
                        bound_violation = "phase7-rss-byte-limit"
                        return

            try:
                # Ownership is durable before monitoring, cancellation or output
                # decoding can raise. A sink failure still cleans this child.
                if _ownership_callback is not None:
                    _ownership_callback()
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if _cancellation and _cancellation["requested"]:
                        bound_violation = bound_violation or "parent-termination-requested"
                        terminate_group()
                        raise KeyboardInterrupt("parent requested bounded child cleanup")
                    if stdout_path.stat().st_size > MAX_STREAM_BYTES or stderr_path.stat().st_size > MAX_STREAM_BYTES:
                        bound_violation = ("phase7-stdout-stderr-byte-limit" if limits is not None
                                           else "stdout/stderr byte ceiling exceeded")
                    elif report.exists() and report.stat().st_size > MAX_REPORT_BYTES:
                        bound_violation = "report byte ceiling exceeded"
                    elif time.monotonic() > deadline:
                        timed_out = True
                    else:
                        inspect_outputs()
                        for path, ceiling in monitored_files:
                            if path.is_symlink():
                                bound_violation = f"monitored output became a symlink: {path.name}"
                                break
                            if path.exists() and path.stat().st_size > ceiling:
                                bound_violation = f"monitored output byte ceiling exceeded: {path.name}"
                    if bound_violation or timed_out:
                        terminate_group()
                        break
                    time.sleep(0.01)
                if timed_out:
                    bound_violation = bound_violation or "phase7-wall-timeout"
                if os.name == "posix" and (
                        _group_exists_with_budget(process.pid, cleanup_status_budget)
                        if sys.platform == "darwin" else _process_group_exists(process.pid)):
                    bound_violation = bound_violation or "process group outlived its leader"
                    terminate_group()
                if stdout_path.stat().st_size > MAX_STREAM_BYTES or stderr_path.stat().st_size > MAX_STREAM_BYTES:
                    bound_violation = bound_violation or "stdout/stderr byte ceiling exceeded"
                    terminate_group()
                if report.exists() and report.stat().st_size > MAX_REPORT_BYTES:
                    bound_violation = bound_violation or "report byte ceiling exceeded"
                    terminate_group()
                returncode = process.wait(timeout=5)
                inspect_outputs()
                for path, ceiling in monitored_files:
                    if path.is_symlink() or (path.exists() and path.stat().st_size > ceiling):
                        bound_violation = bound_violation or f"monitored output byte ceiling exceeded: {path.name}"
                if _cancellation and _cancellation["requested"]:
                    bound_violation = bound_violation or "parent-termination-requested"
                    terminate_group()
                    raise KeyboardInterrupt("parent requested bounded child cleanup")
                if bound_violation:
                    terminate_group()
            except BaseException as error:
                terminate_group()
                process_entry["status"] = "exception"
                process_entry["failure_type"] = type(error).__name__
                process_entry["bound_violation"] = True
                process_entry["wall_seconds"] = time.perf_counter() - started
                process_entry["process_group_cleanup"] = "confirmed" if cleanup_confirmed else "unconfirmed"
                raise
        # Subsequent operations (including exception paths) are covered by the
        # outer receipt logic below; group cleanup is attempted before leaving.
        stdout = stdout_path.read_bytes()[:MAX_STREAM_BYTES + 1]
        stderr = stderr_path.read_bytes()[:MAX_STREAM_BYTES + 1]
        if limits is not None:
            captured = stdout_path.stat().st_size + stderr_path.stat().st_size
            if captured > limits["max_stdout_stderr_bytes"]:
                bound_violation = bound_violation or "phase7-stdout-stderr-byte-limit"
            if captured > limits["max_capture_bytes"]:
                bound_violation = bound_violation or "phase7-capture-byte-limit"
            if len(stdout) + len(stderr) > limits["max_retained_bytes"]:
                bound_violation = bound_violation or "phase7-retained-byte-limit"
            if report.exists() and report.stat().st_size > limits["max_json_bytes"]:
                bound_violation = bound_violation or "phase7-json-byte-limit"
        if retained_streams is not None:
            # Persist before temporary cleanup and optional report decoding.
            # At most one MiB per stream; truncation remains explicit.
            for name,path,data in (('stdout',stdout_path,stdout),('stderr',stderr_path,stderr)):
                retained=data[:MAX_STREAM_BYTES]
                retained_streams[name]={'text':retained.decode('utf-8',errors='replace'),
                    'sha256':hashlib.sha256(retained).hexdigest(),
                    'retained_bytes':len(retained),'observed_bytes':path.stat().st_size,
                    'truncated':path.stat().st_size>len(retained)}
    if not cleanup_confirmed:
        bound_violation = bound_violation or "process group cleanup unconfirmed"
    if bound_violation:
        stderr += ("\nBOUND: " + bound_violation).encode()
    if timed_out:
        stderr += b"\nBOUND: watchdog expired"
    result = subprocess.CompletedProcess(command, returncode,
        stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"))
    entry: dict[str, object] = {
        "status": "completed" if not bound_violation and not timed_out else "failed",
        "client": "desktop" if "desktop" in str(client) else "headless",
        "return_code": result.returncode,
        "wall_seconds": time.perf_counter() - started,
        "stdout_bytes": len(result.stdout.encode()),
        "stderr_bytes": len(result.stderr.encode()),
        "bound_violation": bool(bound_violation or timed_out),
        "process_group_cleanup": "confirmed" if cleanup_confirmed else "unconfirmed",
    }
    if limits is not None:
        entry["bound_violation_reason"] = bound_violation or ("phase7-wall-timeout" if timed_out else None)
    # File the completed process before decoding optional output. A terminated
    # diagnostic prefix can contain partial JSON; that must not erase the
    # execution/time/resource receipt when parsing raises.
    process_entry.update(entry)
    entry = process_entry
    if not cleanup_confirmed:
        entry["bound_violation"] = True
        entry["report_parse_failure"] = "skipped-unconfirmed-process-group-cleanup"
        raise RuntimeError("bounded child process group remains live after termination; refusing further work")
    if report.exists():
        if report.stat().st_size > MAX_REPORT_BYTES:
            entry["bound_violation"] = True
            entry["report_bytes"] = report.stat().st_size
            return result
        try:
            parsed = json.loads(report.read_text())
        except (ValueError, UnicodeError):
            entry["report_parse_failure"] = "invalid-json"
            raise
        if "observations" in parsed:
            entry["observations"] = parsed.get("observations", [])
            if parsed.get("schema") == "genewhip-route-native-v1":
                entry["native_clock"] = {key: parsed[key] for key in ("active_ticks", "fields", "status", "boundary_calls")}
            entry["queue_high_water"] = parsed["queue_high_water"]
            if "host" in parsed:
                entry["host"] = parsed["host"]
        else:
            entry["report_schema"] = parsed.get("schema")
            entry["report_status"] = parsed.get("outcome", parsed.get("status"))
            entry["report_bytes"] = report.stat().st_size
    return result


def _limit_child_file_size() -> None:
    if hasattr(resource, "RLIMIT_FSIZE"):
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_TRACE_BYTES, MAX_TRACE_BYTES))


def _scratch_relative_path(root: pathlib.Path, path: pathlib.Path | str) -> str:
    try:
        return pathlib.Path(path).relative_to(root).as_posix()
    except (ValueError, TypeError):
        return "<outside-root>"


def _record_scratch_diagnostic(diagnostics: list[dict[str, object]] | None,
                               entry: dict[str, object]) -> None:
    # These bounded relative-path facts are private execution diagnostics, not
    # public proof fields. Keep the array small even if a child repeatedly fails.
    if diagnostics is not None and len(diagnostics) < 8:
        diagnostics.append(entry)


def _safe_tree_bytes(root: pathlib.Path,
                     diagnostics: list[dict[str, object]] | None = None) -> int | None:
    total = 0
    try:
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = pathlib.Path(current)
            if current_path.is_symlink():
                _record_scratch_diagnostic(diagnostics, {
                    "kind": "symlink-directory", "path": _scratch_relative_path(root, current_path)})
                return None
            for name in directories:
                path = current_path / name
                if path.is_symlink():
                    _record_scratch_diagnostic(diagnostics, {
                        "kind": "symlink-directory", "path": _scratch_relative_path(root, path)})
                    return None
            for name in files:
                path = current_path / name
                try:
                    info = path.lstat()
                except FileNotFoundError as error:
                    _record_scratch_diagnostic(diagnostics, {
                        "kind": "path-disappeared-during-scan",
                        "path": _scratch_relative_path(root, path), "errno": error.errno})
                    continue
                except OSError as error:
                    _record_scratch_diagnostic(diagnostics, {
                        "kind": "scan-oserror", "path": _scratch_relative_path(root, path),
                        "errno": error.errno, "error_type": type(error).__name__})
                    return None
                regular_file = stat.S_ISREG(info.st_mode)
                if not regular_file or info.st_nlink != 1 or info.st_uid != os.getuid():
                    if stat.S_ISLNK(info.st_mode):
                        kind = "symlink-file"
                    elif not regular_file:
                        kind = "non-regular-file"
                    elif info.st_nlink != 1:
                        kind = "hardlink-file"
                    else:
                        kind = "foreign-owner-file"
                    _record_scratch_diagnostic(diagnostics, {
                        "kind": kind, "path": _scratch_relative_path(root, path),
                        "link_count": info.st_nlink, "owned": info.st_uid == os.getuid()})
                    return None
                total += info.st_size
    except OSError as error:
        _record_scratch_diagnostic(diagnostics, {
            "kind": "scan-oserror", "path": _scratch_relative_path(root, getattr(error, "filename", root)),
            "errno": error.errno, "error_type": type(error).__name__})
        return None
    return total


def _process_group_rss_bytes(group_id: int) -> int | None:
    """Return resident bytes for live processes in a child group, or fail closed."""
    if sys.platform.startswith("linux"):
        total = 0
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            for entry in pathlib.Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    stat_text = (entry / "stat").read_text()
                    fields = stat_text[stat_text.rfind(")") + 2:].split()
                    if len(fields) < 22 or int(fields[2]) != group_id or fields[0] == "Z":
                        continue
                    resident_pages = int((entry / "statm").read_text().split()[1])
                    total += resident_pages * page_size
                except (FileNotFoundError, PermissionError, ValueError, IndexError):
                    continue
            return total
        except (OSError, ValueError):
            return None
    if sys.platform == "darwin":
        # proc_taskinfo starts with virtual_size and resident_size uint64 fields.
        try:
            libproc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            libproc.proc_listpids.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_int]
            libproc.proc_listpids.restype = ctypes.c_int
            libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
            libproc.proc_pidinfo.restype = ctypes.c_int
            count = libproc.proc_listpids(1, 0, None, 0)
            int_size = ctypes.sizeof(ctypes.c_int)
            max_pid_bytes = DARWIN_RSS_MAX_PIDS * int_size
            if count <= 0 or count % int_size or count > max_pid_bytes:
                return None
            # One fixed sentinel slot detects a saturated copy without allowing
            # a host process count to determine allocation size.
            pids = (ctypes.c_int * (DARWIN_RSS_MAX_PIDS + 1))()
            copied = libproc.proc_listpids(1, 0, pids, ctypes.sizeof(pids))
            capacity_bytes = ctypes.sizeof(pids)
            if (copied <= 0 or copied % int_size or copied > max_pid_bytes
                    or copied >= capacity_bytes):
                return None
            total = 0
            seen_pids: set[int] = set()
            task_info = ctypes.create_string_buffer(256)
            for index in range(copied // int_size):
                pid = int(pids[index])
                if pid <= 0:
                    continue
                if pid in seen_pids:
                    return None
                seen_pids.add(pid)
                try:
                    if os.getpgid(pid) != group_id:
                        continue
                except ProcessLookupError:
                    continue
                except (PermissionError, OSError, ValueError):
                    return None
                actual = libproc.proc_pidinfo(pid, 4, 0, task_info, len(task_info))
                if actual < 16 or actual > len(task_info):
                    return None
                total += int.from_bytes(task_info.raw[8:16], byteorder=sys.byteorder)
            return total
        except (AttributeError, OSError, ValueError, OverflowError):
            return None
    return None


_DARWIN_CLEANUP_MAX_STATUS_QUERIES = 16


def _terminate_process_group(process: subprocess.Popen[bytes], *, grace_seconds: float | None = None,
                             status_budget: dict[str, int] | None = None) -> bool:
    if status_budget is None:
        status_budget = {"remaining": _DARWIN_CLEANUP_MAX_STATUS_QUERIES, "attempted": 0}
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                status_budget["last_reason"] = "group-leader-wait-unconfirmed"
                return False
            return not _group_exists_with_budget(process.pid, status_budget)
        grace_deadline = time.monotonic() + (0.25 if grace_seconds is None else grace_seconds)
        while (time.monotonic() < grace_deadline and
               (not sys.platform.startswith("darwin") or status_budget["remaining"] > 0) and
               _group_exists_with_budget(process.pid, status_budget)):
            time.sleep(0.01)
        if _group_exists_with_budget(process.pid, status_budget):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            reap_deadline = time.monotonic() + 2
            while (time.monotonic() < reap_deadline and
                   (not sys.platform.startswith("darwin") or status_budget["remaining"] > 0) and
                   _group_exists_with_budget(process.pid, status_budget)):
                time.sleep(0.01)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            status_budget["last_reason"] = "group-leader-wait-unconfirmed"
            process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                status_budget["last_reason"] = "group-leader-reap-unconfirmed"
                return False
        return not _group_exists_with_budget(process.pid, status_budget)
    else:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            if status_budget is not None:
                status_budget["last_reason"] = "group-leader-reap-unconfirmed"
            return False
        # Killing the direct child does not prove descendants were contained.
        return False


def _process_group_exists(group_id: int, *, status_budget: dict[str, int] | None = None) -> bool:
    if os.name != "posix":
        return False
    if sys.platform.startswith("linux"):
        try:
            for entry in pathlib.Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    stat_text = (entry / "stat").read_text()
                    fields = stat_text[stat_text.rfind(")") + 2:].split()
                    if len(fields) > 2 and int(fields[2]) == group_id and fields[0] != "Z":
                        return True
                except (FileNotFoundError, PermissionError, ValueError):
                    continue
            return False
        except OSError:
            pass
    if sys.platform == "darwin":
        # killpg(...,0) also sees an orphan zombie group on Darwin; signaling
        # that group can return EPERM even though no process can execute.
        # Distinguish zombies using status only (never collect command lines).
        # If the OS query is unavailable, retain the conservative signal probe.
        if status_budget is None:
            status_budget = {"remaining": _DARWIN_CLEANUP_MAX_STATUS_QUERIES,
                             "attempted": 0, "absent_observed": False,
                             "status_reason": "not-observed"}
        else:
            # The private threaded counter is still a boundary input: clamp it
            # so a reset or malformed caller cannot enlarge the policy.
            status_budget["remaining"] = min(
                _DARWIN_CLEANUP_MAX_STATUS_QUERIES,
                max(0, int(status_budget.get("remaining", 0))))
        status_budget.setdefault("last_reason", "cleanup-unclassified")
        if status_budget["remaining"] <= 0:
            status_budget["last_reason"] = (
                "group-inactive" if status_budget.get("absent_observed", False)
                else "group-status-budget-exhausted")
            return not bool(status_budget.get("absent_observed", False))
        # A new attempt supersedes earlier absence, even if it fails to start
        # or cannot establish a usable status observation.
        status_budget["absent_observed"] = False
        status_budget["remaining"] -= 1
        status_budget["attempted"] += 1
        states, cleanup_ok = _darwin_status_states(group_id)
        if not cleanup_ok:
            # An uncertain status child must never turn into an absent group.
            status_budget["status_reason"] = "group-observer-cleanup-unconfirmed"
            status_budget["last_reason"] = "group-observer-cleanup-unconfirmed"
            return True
        if states is None:
            status_budget["status_reason"] = "group-status-unavailable"
            status_budget["last_reason"] = "group-status-unavailable"
        if states is not None:
            exists = any(not state.startswith("Z") for state in states)
            status_budget["status_reason"] = "group-reported-active" if exists else "group-inactive"
            if not exists:
                status_budget["absent_observed"] = True
            status_budget["last_reason"] = "group-reported-active" if exists else "group-inactive"
            return exists
    try:
        os.killpg(group_id, 0)
        if status_budget is not None:
            status_budget["last_reason"] = "group-signal-visible"
        return True
    except ProcessLookupError:
        if status_budget is not None:
            status_budget["last_reason"] = "group-inactive"
        return False
    except PermissionError:
        if status_budget is not None:
            status_budget["last_reason"] = "group-signal-permission-denied"
        return True


def _group_exists_with_budget(group_id: int, status_budget: dict[str, int]) -> bool:
    """Keep older private test seams callable while passing budgets to production."""
    try:
        return _process_group_exists(group_id, status_budget=status_budget)
    except TypeError as error:
        if "unexpected keyword argument 'status_budget'" not in str(error):
            raise
        # Python rejects the argument before entering a legacy replacement, so
        # this compatibility path cannot consume an unmetered production query.
        if _process_group_exists is _ORIGINAL_PROCESS_GROUP_EXISTS:
            raise
        return _process_group_exists(group_id)


_ORIGINAL_PROCESS_GROUP_EXISTS = _process_group_exists


_DARWIN_STATUS_MAX_BYTES = 64 * 1024
_DARWIN_STATUS_CHUNK_BYTES = 8192
_DARWIN_STATUS_BUDGET_SECONDS = 1.0
_DARWIN_STATUS_BASE_STATES = frozenset("IRSTUZ")
_DARWIN_STATUS_MODIFIERS = frozenset("+<>AELNSsVWX")


def _parse_darwin_status(data: bytes, group_id: int) -> list[str] | None:
    """Parse only a complete, strictly decoded pgid/stat status stream."""
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return None
    if isinstance(group_id, bool) or not isinstance(group_id, int) or group_id <= 0:
        return None
    states: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 2:
            return None
        if re.fullmatch(r"[1-9][0-9]*", fields[0]) is None:
            return None
        try:
            row_group = int(fields[0], 10)
        except ValueError:
            return None
        state = fields[1]
        if not state or state[0] not in _DARWIN_STATUS_BASE_STATES:
            return None
        modifiers = state[1:]
        if any(char not in _DARWIN_STATUS_MODIFIERS for char in modifiers):
            return None
        if len(set(modifiers)) != len(modifiers):
            return None
        if row_group == group_id:
            states.append(state)
    return states


def _darwin_status_states(group_id: int) -> tuple[list[str] | None, bool]:
    """Return parsed statuses and cleanup certainty for a bounded Darwin ps query.

    The one-second budget bounds communication after Popen succeeds. Process
    creation, direct-child kill/reap, and OS scheduling overhead are excluded;
    this is not a whole-call hard wall or an OS containment guarantee.
    """
    process = None
    selector = None
    stream = None
    output = bytearray()
    states: list[str] | None = None
    query_complete = False
    query_failed = False
    primary: BaseException | None = None
    try:
        # Keep this observer outside the group whose RSS is being measured.
        # On macOS the observer's effective identity may differ from its caller,
        # and the RSS sampler must see only workload-group members.
        process = subprocess.Popen(["/bin/ps", "-axo", "pgid=,stat="],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=False, bufsize=0,
            start_new_session=True)
        stream = process.stdout
        if stream is None:
            raise OSError("Darwin status pipe was not created")
        os.set_blocking(stream.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + _DARWIN_STATUS_BUDGET_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                query_failed = True
                break
            ready = selector.select(remaining)
            if not ready:
                query_failed = True
                break
            allowance = _DARWIN_STATUS_MAX_BYTES + 1 - len(output)
            if allowance <= 0:
                query_failed = True
                break
            request = min(_DARWIN_STATUS_CHUNK_BYTES, allowance)
            chunk = os.read(stream.fileno(), request)
            if len(chunk) > request:
                query_failed = True
                break
            if not chunk:
                query_complete = True
                break
            output.extend(chunk)
            if len(output) > _DARWIN_STATUS_MAX_BYTES:
                query_failed = True
                break
        if query_complete and not query_failed:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                query_failed = True
            else:
                states = _parse_darwin_status(bytes(output), group_id)
                if states is None:
                    query_failed = True
    except BaseException as error:
        if isinstance(error, Exception):
            query_failed = True
        else:
            primary = error

    cleanup_ok = True
    for resource in (selector, stream):
        if resource is not None:
            try:
                resource.close()
            except BaseException as error:
                cleanup_ok = False
                if primary is None and not isinstance(error, Exception):
                    primary = error
    if process is not None:
        child_state = None
        try:
            child_state = process.poll()
        except BaseException as error:
            # A broken poll does not prove that the owned child is settled.
            # Continue through the direct-child kill/wait path below.
            if primary is None and not isinstance(error, Exception):
                primary = error
        if child_state is None:
            try:
                process.kill()
            except BaseException as error:
                if primary is None and not isinstance(error, Exception):
                    primary = error
            try:
                process.wait(timeout=1.0)
            except BaseException as error:
                cleanup_ok = False
                if primary is None and not isinstance(error, Exception):
                    primary = error
        elif process.returncode is None:
            try:
                process.wait(timeout=1.0)
            except BaseException as error:
                cleanup_ok = False
                if primary is None and not isinstance(error, Exception):
                    primary = error
    if primary is not None:
        raise primary
    if not cleanup_ok or query_failed or not query_complete:
        return None, cleanup_ok
    return states, True


def _phase_plan_started_at(root: pathlib.Path) -> tuple[str, str]:
    command = ["git", "show", f"{PLAN_START_STATE_COMMIT}:.planning/STATE.md"]
    result = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=10, check=False)
    if result.returncode != 0:
        raise RuntimeError("cannot read the committed pre-dispatch state time anchor")
    match = re.search(r'^last_updated: "([^"]+)"$', result.stdout, re.MULTILINE)
    if not match:
        raise RuntimeError("pre-dispatch state time anchor is missing last_updated")
    return match.group(1), PLAN_START_STATE_COMMIT


def _elapsed_seconds(started_at: str) -> float:
    start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    return max(0.0, (datetime.now(timezone.utc) - start).total_seconds())


def _phase6_probe_load(build: pathlib.Path) -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    headless = build / "tools/session/gw_headless"
    tank_rom = root / "fixtures/phase5-a/game.bin"
    control_script = root / "tests/fixtures/phase4_game.py"
    evidence_path = root / "evidence/phase6-repairs.json"
    started = time.perf_counter()
    runs: list[dict[str, object]] = []
    stop_id = "tank-reset-stack-physical-frame"
    base_record_id = "GW-06-02-TANK-RESET-STACK"
    if evidence_path.exists():
        ledger = json.loads(evidence_path.read_text())
        if ledger.get("schema") != "genewhip-phase6-repairs-v1" or ledger.get("baseline_sha256") != BASELINE_SHA256:
            raise RuntimeError("existing Phase 6 repair ledger has incompatible identity")
    else:
        started_at, start_commit = _phase_plan_started_at(root)
        ledger = {"schema": "genewhip-phase6-repairs-v1", "phase": "GW-06",
                  "baseline_sha256": BASELINE_SHA256,
                  "budgets": {"distinct_stops": 12, "attempts_per_stop": 3,
                              "investigation_seconds_per_stop": 5400, "cumulative_repair_seconds": 43200,
                              "route_case": {"watchdog_seconds": 600, "stdout_bytes": MAX_STREAM_BYTES,
                                             "stderr_bytes": MAX_STREAM_BYTES, "trace_bytes": MAX_TRACE_BYTES,
                                             "trace_rows": MAX_TRACE_ROWS, "summary_bytes": MAX_REPORT_BYTES,
                                             "event_capacity": 64}},
                  "plan_started_at": started_at,
                  "plan_start_anchor": {"kind": "committed pre-dispatch STATE last_updated", "commit": start_commit},
                  "usage": {}, "records": []}
    if "plan_started_at" not in ledger:
        started_at, start_commit = _phase_plan_started_at(root)
        ledger["plan_started_at"] = started_at
        ledger["plan_start_anchor"] = {"kind": "committed pre-dispatch STATE last_updated", "commit": start_commit}
    elapsed_before = _elapsed_seconds(ledger["plan_started_at"])
    executions, collisions = _effective_attempt_receipts(ledger["records"], stop_id)
    prior_attempts = len(executions)
    if collisions:
        collision_id = f"{base_record_id}-DUPLICATE-FILING-CORRECTION-001"
        if not any(row.get("record_id") == collision_id for row in ledger["records"]):
            ledger["records"].append({
                "record_id": collision_id,
                "record_type": "filing-correction",
                "stop_id": stop_id,
                "collision_policy": "identical-by-canonical-json-sha256; count once as an effective execution and preserve both raw list entries by Git history",
                "collisions": [{"record_id": key, "raw_record_indexes": value["indexes"],
                                "canonical_json_sha256": value["digest"],
                                "effective_record_id": key, "effective_execution_count": 1}
                               for key, value in sorted(collisions.items())],
                "supersedes_record_id": f"{base_record_id}-HISTORY-CORRECTION-001",
                "superseding_correction": "The prior history-correction described the two byte-identical ATTEMPT-002 filings as two reruns. They are one effective recorded process receipt; prior effective execution count is two (legacy base record plus ATTEMPT-002), and one bounded attempt remains.",
            })
    prior_stops = {row.get("stop_id", row["record_id"]) for row in ledger["records"]}
    if prior_attempts >= ledger["budgets"]["attempts_per_stop"]:
        raise RuntimeError("attempt budget exhausted; no cached receipt is accepted as a probe execution")
    if len(prior_stops) > ledger["budgets"]["distinct_stops"] or \
            elapsed_before > ledger["budgets"]["investigation_seconds_per_stop"] or \
            elapsed_before > ledger["budgets"]["cumulative_repair_seconds"]:
        raise RuntimeError("Phase 6 wall-clock search bound is exhausted before probe start")

    if not headless.is_file():
        raise RuntimeError("phase6 probe requires the existing headless client")
    if hashlib.sha256(tank_rom.read_bytes()).hexdigest() != \
            "ceb75f72a08565424e88ed0a38d0d682e2c7f7cbb6e98b920f442b108e09f723":
        raise RuntimeError("admitted Tank fixture identity changed")

    with tempfile.TemporaryDirectory(prefix="gw-phase6-load-probe-") as directory:
        temp = pathlib.Path(directory)
        trace = temp / "tank-instruction-trace.jsonl"
        no_report = temp / "no-report.json"
        tank_command = [str(headless), str(tank_rom), "--fields", "60", "--peek", "0xff0000", "4",
                        "--dump-instruction-trace", str(trace)]
        tank_result = _run_client(headless, tank_command, runs, report=no_report, timeout=600)
        if tank_result.stderr.count("BOUND:") or not trace.is_file():
            raise RuntimeError("Tank boot probe exceeded a process/output bound or did not write its trace")
        trace_bytes = trace.stat().st_size
        trace_lines = trace.read_text().splitlines()
        if trace_bytes > MAX_TRACE_BYTES or len(trace_lines) > MAX_TRACE_ROWS:
            raise RuntimeError("Tank instruction trace exceeded its 16 MiB / 100000-row limit")
        trace_rows = [json.loads(line) for line in trace_lines]
        trace_state = next((row["state"] for row in reversed(trace_rows) if "state" in row), None)
        if trace_state is None:
            raise RuntimeError("Tank instruction trace lacks final machine state")
        output_rows = [json.loads(line) for line in tank_result.stdout.splitlines() if line.startswith("{")]
        final_output = next((row for row in reversed(output_rows) if "fields" in row), None)
        if final_output is None:
            raise RuntimeError("Tank 60-field probe lacks final client summary")
        completed_field_rows = [row for row in output_rows if "sequence" in row and "fnv1a64" in row]
        completed_fields = len(completed_field_rows)
        last_video_sequence = completed_field_rows[-1]["sequence"] if completed_field_rows else None
        stop_events = [row for row in trace_rows if "stop_reason" in row and row["stop_reason"] in (2, 3, 4)]
        first_stop = stop_events[0] if stop_events else None
        if first_stop is not None:
            first_stop = dict(first_stop, pc_hex=f"0x{first_stop['pc']:04x}",
                              opcode_hex=f"0x{first_stop['opcode']:04x}")
        if tank_result.returncode not in (0, 1):
            raise RuntimeError(f"Tank probe exited unexpectedly: {tank_result.returncode}")
        if tank_result.returncode == 1 and first_stop is None:
            raise RuntimeError("Tank probe failed without an exact unsupported-stop event")
        if tank_result.returncode == 0 and final_output.get("fields") != 60:
            raise RuntimeError("Tank boot prefix did not reach its exact 60-field bound")

        control_reports = []
        baseline = json.loads((root / "evidence/phase5-baseline-process.json").read_text())
        baseline_control = {row["case_id"]: row["observation"] for row in baseline["processes"]
                            if row["fixture_id"] == "genewhip-independent-game-v2" and row["repetition"] == 1}
        if len(baseline_control) != 6:
            raise RuntimeError("pinned legacy control baseline does not contain six cases")
        for repetition in (1, 2):
            report = temp / f"control-{repetition}.json"
            command = [sys.executable, "-I", str(control_script), str(headless),
                       "--report", str(report)]
            result = _run_client(headless, command, runs, report=report, timeout=600, cwd=root)
            if result.returncode != 0 or result.stderr:
                raise RuntimeError(f"unchanged control repetition {repetition} failed: {result.stderr[-1000:]}")
            control = json.loads(report.read_text())
            if control.get("outcome") != "pass" or control.get("denominator") != 6:
                raise RuntimeError("unchanged control did not pass all six cases")
            for row in control["results"]:
                expected = baseline_control.get(row["id"])
                if expected is None:
                    raise RuntimeError(f"control case missing from pinned baseline: {row['id']}")
                for field in ("outcome", "fields", "input_sha256", "field_hashes_sha256",
                              "raw_geometry_sha256", "pcm_frames", "play_state", "position",
                              "psg", "ac_range", "machine_digest", "unsupported"):
                    if row.get(field) != expected.get(field):
                        raise RuntimeError(f"unchanged control drift in {row['id']} field {field}")
            control_reports.append(control)
        if control_reports[0]["results"] != control_reports[1]["results"]:
            raise RuntimeError("unchanged control repetitions differ")

        scenario = json.loads((root / "fixtures/phase5-a/scenario.json").read_text())
        stages = []
        for case in scenario["cases"]:
            stages.append({
                "case_id": case["id"],
                "load": {"status": "pass", "client": "public-headless", "rom_sha256": scenario["identities"]["rom_sha256"]},
                "boot_prefix": {"status": "pass" if tank_result.returncode == 0 else "stop",
                                "fields_requested": 60, "fields_reached": completed_fields,
                                "session_field_step_attempts": final_output.get("fields"),
                                "last_video_sequence": last_video_sequence,
                                "stop_reason": trace_state.get("stop_reason"),
                                "first_stop": first_stop},
                "interaction": {"status": "unreached", "reason": "bounded probe stops after the frozen 60-field boot prefix"},
                "sustained": {"status": "unreached", "reason": "interaction stage not reached; no gameplay claim"},
            })

        attempt_number = 1 + max((int(match.group(1)) for row in ledger["records"]
                                  if (match := re.search(r"-ATTEMPT-(\d+)$", row.get("record_id", "")))),
                                 default=0)
        record_id = f"{base_record_id}-ATTEMPT-{attempt_number:03d}"
        if any(row.get("record_id") == record_id for row in ledger["records"]):
            raise RuntimeError(f"append-only repair record already exists: {record_id}")
        has_original = any(row.get("record_id") == base_record_id for row in ledger["records"])
        has_correction = any(row.get("corrects_record_id") == base_record_id for row in ledger["records"])
        record = {
            "record_id": record_id,
            "record_type": "correction-recheck" if has_original and not has_correction else "probe-attempt",
            "stop_id": stop_id,
            "baseline_sha256": BASELINE_SHA256,
            "fixture_id": "genewhip-phase5-a",
            "title_id": "tank-battle",
            "rom_sha256": scenario["identities"]["rom_sha256"],
            "reproduction_args": {
                "tank_boot": ["build/phase6/tools/session/gw_headless", "fixtures/phase5-a/game.bin",
                              "--fields", "60", "--peek", "0xff0000", "4",
                              "--dump-instruction-trace", "<temp-trace>"],
                "legacy_control": ["python3", "-I", "tests/fixtures/phase4_game.py",
                                   "build/phase6/tools/session/gw_headless", "--report", "<temp-report>"]},
            "pre_behavior": {"load": "invalid-rom", "boot": "unreached", "interaction": "unreached", "sustained": "unreached"},
            "post_behavior": {"load": "pass", "boot_prefix_fields_requested": 60,
                              "completed_video_fields": completed_fields,
                              "session_field_step_attempts": final_output.get("fields"),
                              "last_video_sequence": last_video_sequence,
                              "first_next_stop": first_stop or {"status": "none-within-60-field-prefix",
                                                               "tick": trace_state.get("tick"),
                                                               "pc": trace_state.get("pc"),
                                                               "stop_reason": trace_state.get("stop_reason")},
                              "route_cases": stages,
                              "unchanged_control": {"status": "pass", "cases": 6, "repetitions": 2,
                                                    "clients": ["headless"],
                                                    "case_results": control_reports[0]["results"]}},
            "authority_locator": ["NXP M68000 User's Manual sections 2.1 and 2.3.2",
                                  "docs/core.md reset stack predicate contract",
                                  "fixtures/phase5-a/game.bin reset vector 0xe1000000"],
            "regression_command": ["cmake --build build/phase6 --parallel 2",
                                   "ctest --test-dir build/phase6 --output-on-failure --no-tests=error -R ^load_contract$",
                                   "python3 -I tests/session/phase6_route_contract.py --probe-load --build build/phase6"],
            "touched_files": ["src/core.c", "src/internal.h", "tests/api/load_contract.c", "CMakeLists.txt", "docs/core.md"],
            "measurements": {"probe_process_wall_seconds": round(time.perf_counter() - started, 3),
                             "tank_stdout_bytes": runs[0]["stdout_bytes"],
                             "tank_stderr_bytes": runs[0]["stderr_bytes"],
                             "tank_trace_bytes": trace_bytes, "tank_trace_rows": len(trace_rows),
                             "control_wall_seconds": [row["wall_seconds"] for row in runs[1:]],
                             "control_max_stdout_bytes": max(row["stdout_bytes"] for row in runs[1:]),
                             "control_max_stderr_bytes": max(row["stderr_bytes"] for row in runs[1:]),
                             "control_report_bytes": [row.get("report_bytes", 0) for row in runs[1:]]},
            "stage_outcomes": stages,
        }
        if has_original and not has_correction:
            record["corrects_record_id"] = base_record_id
            record["corrections"] = {
                "fields_reached": "The earlier value 1 was a session field-step attempt count; the corrected count is completed JSON video-field rows (0).",
                "desktop_control_attempt": "The earlier timeout field was hard-coded in the probe output. This repeatable probe launches no desktop process.",
                "historical_desktop_attempt": {
                    "status": "observed-infrastructure-timeout",
                    "case_id": "title-no-start",
                    "timeout_seconds": 240,
                    "command_context": "tests/fixtures/phase4_game.py with the Phase 6 headless and desktop clients",
                    "desktop_binary_sha256": None,
                    "identity_status": "not captured at the time of the observed timeout",
                    "outcome_scope": "host process timeout; no core result inferred",
                },
                "time_accounting": "Prior process-only seconds undercounted plan elapsed time. This correction uses elapsed UTC wall time from the committed pre-dispatch STATE timestamp, including investigation and waiting; child process timings remain separate.",
            }
        ledger["records"].append(record)
        attempts_for_stop = len({row.get("record_id") for row in ledger["records"]
                                 if row.get("stop_id") == stop_id and
                                 row.get("record_type") not in ("history-correction", "filing-correction")})
        elapsed_after = max(elapsed_before, _elapsed_seconds(ledger["plan_started_at"]))
        process_wall_seconds = sum(float(row.get("measurements", {}).get("probe_process_wall_seconds",
                                                 row.get("measurements", {}).get("probe_wall_seconds", 0)))
                                   for row in {row.get("record_id"): row for row in ledger["records"]
                                               if row.get("stop_id") == stop_id and
                                               row.get("record_type") not in ("history-correction", "filing-correction")}.values())
        previous_cumulative = float(ledger.get("usage", {}).get("cumulative_repair_seconds", 0))
        ledger["usage"] = {"distinct_stops": len({row.get("stop_id", row["record_id"]) for row in ledger["records"]}),
                           "attempts_for_this_stop": attempts_for_stop,
                           "investigation_seconds_for_this_stop": round(max(elapsed_after, previous_cumulative), 3),
                           "elapsed_wall_seconds_since_plan_start": round(elapsed_after, 3),
                           "cumulative_repair_seconds": round(max(elapsed_after, previous_cumulative), 3),
                           "bounded_process_wall_seconds_sum": round(process_wall_seconds, 3),
                           "time_basis": "UTC wall elapsed from the pre-dispatch STATE last_updated in plan_start_anchor; includes investigation and waiting. Child process times are measured separately."}
        if (ledger["usage"]["distinct_stops"] > ledger["budgets"]["distinct_stops"] or
                ledger["usage"]["attempts_for_this_stop"] > ledger["budgets"]["attempts_per_stop"] or
                ledger["usage"]["investigation_seconds_for_this_stop"] > ledger["budgets"]["investigation_seconds_per_stop"] or
                ledger["usage"]["cumulative_repair_seconds"] > ledger["budgets"]["cumulative_repair_seconds"]):
            raise RuntimeError("Phase 6 repair search budget exhausted; emit a blocked receipt")
        evidence_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")

    print(json.dumps({"status": "pass", "evidence": str(evidence_path.relative_to(root)),
                      "record_id": record_id, "tank_fields": completed_fields,
                      "session_field_step_attempts": final_output.get("fields"),
                      "tank_stop": record["post_behavior"]["first_next_stop"],
                      "control_cases": 6, "control_repetitions": 2,
                      "probe_process_wall_seconds": record["measurements"]["probe_process_wall_seconds"]}, sort_keys=True))
    return 0


def _phase6_probe_movem(build: pathlib.Path) -> int:
    """One fresh bounded production GWRC execution, never the spent loader search.

    Anchors include investigation/wait wall time. Old records remain untouched;
    closed-stop accounting is retained separately from current-stop elapsed time.
    """
    root = pathlib.Path(__file__).resolve().parents[2]
    evidence_path = root / "evidence/phase6-repairs.json"
    ledger = json.loads(evidence_path.read_text())
    if ledger.get("schema") != "genewhip-phase6-repairs-v1" or ledger.get("baseline_sha256") != BASELINE_SHA256:
        raise RuntimeError("incompatible repair ledger")
    stop_id = "recursion-movem-1822-48e7"
    anchor = "2026-10-23T19:46:25.042Z"
    sessions = ledger.setdefault("stop_sessions", {})
    if stop_id not in sessions:
        sessions[stop_id] = {"started_at": anchor,
                             "anchor": {"kind": "committed pre-dispatch STATE last_updated",
                                        "commit": "5536160"},
                             "status": "investigating"}
        sessions["tank-reset-stack-physical-frame"] = {
            "status": "closed-loader-repair; next stop belongs to06-04",
            "closed_usage": dict(ledger["usage"])}
    elapsed = _elapsed_seconds(sessions[stop_id]["started_at"])
    executions, collisions = _effective_attempt_receipts(ledger["records"], stop_id)
    if collisions:
        raise RuntimeError("MOVEM probe has duplicate filings requiring explicit resolution")
    signatures = sorted(set(_observed_stop_signatures(ledger["records"])) |
                        {"recursion94:cpu:001822:48e7:2"})
    cumulative = max(float(ledger["usage"]["cumulative_repair_seconds"]),
                     _elapsed_seconds(ledger["plan_started_at"]))
    bounds = ledger["budgets"]
    if (len(executions) >= bounds["attempts_per_stop"] or len(signatures) > bounds["distinct_stops"] or
            elapsed > bounds["investigation_seconds_per_stop"] or cumulative > bounds["cumulative_repair_seconds"]):
        raise RuntimeError("MOVEM repair search bound exhausted before execution")
    # Persist the anchor before launching any experiment, even if its process fails.
    evidence_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")
    spec = importlib.util.spec_from_file_location("phase6_movem_compiler", root / "scripts/evidence/phase6_routes.py")
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    route = next(row for row in compiler.compile_routes()["routes"]
                 if row["fixture"] == "recursion94" and row["case"]["id"] == "full-route")
    binary, metadata = compiler.lower_route(route)
    pre = json.loads((root / "evidence/phase6-movem-pre.json").read_text())
    if (pre["compiled_sha256"] != hashlib.sha256(binary).hexdigest() or
            pre["report"]["instruction_address"] != 0x1822 or pre["report"]["opcode"] != 0x48e7 or
            pre["report"]["stop_reason"] != 2 or pre["report"]["first_stop_tick"] is None):
        raise RuntimeError("pre-repair MOVEM receipt does not match exact production route")
    client = build / "tools/session/gw_headless"
    runs: list[dict[str, object]] = []
    commands = []
    control_results = []
    baseline = json.loads((root / "evidence/phase5-baseline-process.json").read_text())
    expected_control = {row["case_id"]: row["observation"] for row in baseline["processes"]
                        if row["fixture_id"] == "genewhip-independent-game-v2" and row["repetition"] == 1}
    if len(expected_control) != 6:
        raise RuntimeError("control baseline denominator changed")
    # Relative arguments keep the actual executed commands reproducible and private-path free.
    with tempfile.TemporaryDirectory(prefix="movem-probe-", dir=build.relative_to(root)) as directory:
        temp = pathlib.Path(directory)
        plan, report = temp / "route.bin", temp / "recursion.json"
        plan.write_bytes(binary)
        command = [str(client.relative_to(root)), "--route-plan", str(plan), "--route-report", str(report),
                   "fixtures/phase5-b/game.bin"]
        commands.append(command)
        # Reserve before process launch: malformed/missing output also consumes an attempt.
        attempt = len(executions) + 1
        record = {"record_id": f"GW-06-03-MOVEM-ATTEMPT-{attempt:03d}", "record_type": "probe-attempt",
                  "stop_id": stop_id, "fixture_id": "genewhip-phase5-b", "title_id": "recursion94",
                  "baseline_sha256": BASELINE_SHA256,
                  "compiled_sha256": hashlib.sha256(binary).hexdigest(),
                  "rom_sha256": hashlib.sha256((root / "fixtures/phase5-b/game.bin").read_bytes()).hexdigest(),
                  "client_binary_sha256": hashlib.sha256(client.read_bytes()).hexdigest(),
                  "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True, timeout=10).strip(),
                  "pre_receipt": "evidence/phase6-movem-pre.json", "native_report": None,
                  "commands": commands, "processes": runs, "status": "collecting",
                  "authority_locator": ["NXP M68000PRM pp231-233", "MC68000UM table8-10", "docs/cpu.md#movem-gw-06-03"],
                  "regressions": ["tests/api/movem_contract.c", "evidence/phase6-movem-red.json", "evidence/phase6-movem-mutations.json"]}
        ledger["records"].append(record)

        def retain(status: str) -> None:
            current_elapsed = _elapsed_seconds(sessions[stop_id]["started_at"])
            current_cumulative = max(cumulative, _elapsed_seconds(ledger["plan_started_at"]))
            record["status"] = status
            record["measurements"] = {"investigation_wall_seconds": round(current_elapsed, 3),
                                      "bounded_process_wall_seconds": round(sum(float(r["wall_seconds"]) for r in runs), 6)}
            current_signatures = _observed_stop_signatures(ledger["records"])
            ledger["observed_stop_signatures"] = current_signatures
            ledger["usage"] = {"distinct_stops": len(current_signatures),
                               "repair_targets": len({row.get("stop_id") for row in ledger["records"]}),
                               "attempts_for_this_stop": attempt,
                               "investigation_seconds_for_this_stop": round(current_elapsed, 3),
                               "cumulative_repair_seconds": round(current_cumulative, 3),
                               "time_basis": "Current stop: elapsed from its committed pre-dispatch anchor. Global: monotonic elapsed from original Phase6 repair start, including investigation, waits and inter-plan wall time. Loader closed usage retained in stop_sessions."}
            evidence_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")

        retain("collecting")
        try:
            result = _run_client(client, command, runs, report=report, timeout=600, cwd=root)
            native = json.loads(report.read_text()) if report.exists() else None
            record["native_report"] = native
            if result.returncode not in (0, 1) or runs[-1]["bound_violation"] or native is None:
                raise RuntimeError("MOVEM production observer failed its process/report bound")
            if native.get("schema") != "genewhip-route-native-v1":
                raise RuntimeError("MOVEM requires the production GWRC observer")
            if native["instruction_address"] == 0x1822 and native["opcode"] == 0x48e7:
                raise RuntimeError("original MOVEM stop remains")
            if result.returncode == 1 and (native["stop_reason"] not in (2, 3, 4) or native["first_stop_tick"] is None):
                raise RuntimeError("probe failed without an exact next unsupported stop")
            if native["boundary_calls"] > 100000000 or len(native["samples"]) > MAX_TRACE_ROWS:
                raise RuntimeError("production observer row/work bound exceeded")
            for repetition in (1, 2):
                control_report = temp / f"control-{repetition}.json"
                command = [sys.executable, "-I", "tests/fixtures/phase4_game.py", str(client.relative_to(root)),
                           "--report", str(control_report)]
                commands.append(command)
                record["interpreter_sha256"] = hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest()
                control = _run_client(client, command, runs, report=control_report, timeout=600, cwd=root)
                if control.returncode != 0 or control.stderr or runs[-1]["bound_violation"]:
                    raise RuntimeError("unchanged control process failed")
                parsed = json.loads(control_report.read_text())
                if parsed.get("outcome") != "pass" or parsed.get("denominator") != 6:
                    raise RuntimeError("control denominator or outcome changed")
                for row in parsed["results"]:
                    expected = expected_control[row["id"]]
                    for field in ("outcome", "fields", "input_sha256", "field_hashes_sha256", "raw_geometry_sha256",
                                  "pcm_frames", "play_state", "position", "psg", "ac_range", "machine_digest", "unsupported"):
                        if row.get(field) != expected.get(field):
                            raise RuntimeError(f"unchanged control drift: {row['id']}:{field}")
                control_results.append(parsed["results"])
            if control_results[0] != control_results[1]:
                raise RuntimeError("control repetitions differ")
            record["post_behavior"] = {
                "load": "pass", "original_movem_stop": "passed",
                "completed_video_fields": native["fields"], "active_ticks": native["active_ticks"],
                "first_next_stop": {key: native[key] for key in
                                    ("first_stop_tick", "instruction_address", "opcode", "stop_reason")},
                "route_outcome": "stop" if result.returncode else "completed",
                "interaction": "unreached" if native["active_ticks"] == 0 else "not-qualified-by-this-probe",
                "sustained": "unreached" if native["active_ticks"] == 0 else "not-qualified-by-this-probe",
                "unchanged_control": {"cases": 6, "repetitions": 2, "status": "pass", "results": control_results[0]}}
            if (len(_observed_stop_signatures(ledger["records"])) > bounds["distinct_stops"] or
                    _elapsed_seconds(anchor) > bounds["investigation_seconds_per_stop"] or
                    _elapsed_seconds(ledger["plan_started_at"]) > bounds["cumulative_repair_seconds"]):
                raise RuntimeError("MOVEM search wall bound exhausted during probe")
            sessions[stop_id]["status"] = "closed-MOVEM-repair; next stop belongs to06-04"
            retain("pass")
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
            record["failure"] = str(error)
            retain("blocked")
            raise
    print(json.dumps({"status": "pass", "record_id": record["record_id"],
                      "next_stop": record["post_behavior"]["first_next_stop"],
                      "completed_video_fields": native["fields"], "control": "6 cases twice",
                      "usage": ledger["usage"]}, sort_keys=True))
    return 0


class MediaConsumerContract(unittest.TestCase):
    build: pathlib.Path

    def test_source_clock_must_match_the_declared_media_scene(self) -> None:
        spec = importlib.util.spec_from_file_location("phase6_media_compiler", pathlib.Path(__file__).resolve().parents[2] / "scripts/evidence/phase6_routes.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = next(x for x in module.load(module.ROOT / "fixtures/phase6/media-expectations-v1.json")["captures"] if x["fixture"] == "recursion94")
        with self.assertRaisesRegex(module.Invalid, "media-rec-scene-metadata-clock"):
            module._validate_media_image("recursion94", {"attempt":4,"source_tick":690}, source,
                {"attempt":4,"source_tick":689,"actor_x_px":288,"actor_y_px":112}, bytes(320*224*4))

    def test_source_tone_analysis_rejects_silence_and_wrong_pitch(self) -> None:
        import math
        spec = importlib.util.spec_from_file_location("phase6_media_tones", pathlib.Path(__file__).resolve().parents[2] / "scripts/evidence/phase6_routes.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        correct = module.tone_features([1000*math.sin(2*math.pi*800*i/48000) for i in range(4096)],800)
        wrong = module.tone_features([1000*math.sin(2*math.pi*1200*i/48000) for i in range(4096)],800)
        self.assertGreater(correct["prominence_ratio"],4)
        self.assertGreater(correct["periodicity"],.55)
        self.assertLess(wrong["prominence_ratio"],4)
        with self.assertRaisesRegex(module.Invalid,"media-audio-source-signal"):
            module.tone_features([252.0-252.0]*4096,800)

    def test_boot_score_consumer_checks_programmed_pcm_pitch(self) -> None:
        import math
        import array
        spec = importlib.util.spec_from_file_location("phase6_score_consumer", pathlib.Path(__file__).resolve().parents[2] / "scripts/evidence/phase6_routes.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        expectations=module.load(module.ROOT/"fixtures/phase6/media-expectations-v1.json")
        source=expectations["audio_checks"]["recursion94"]
        evidence_dir = self.build / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="authored-score-",dir=evidence_dir) as directory:
            work=pathlib.Path(directory)
            writes=[];segments=[]
            for index,(fnum,period) in enumerate(zip(source["fm0_fnums"],source["psg_periods"])):
                tick=round(.05*53693175)+index*source["note_fields"]*896040
                frequency=fnum*(2**source["block"])*53693175/(7*144*2097152)
                segments.append((round(tick*48000/53693175),frequency))
                for offset,(chip,reg,value) in enumerate(((1,0x28,0),(1,0xA4,source["high_register"]),(1,0xA0,fnum&255),
                        (3,0,0x80|(period&15)),(3,0,period>>4),(1,0x28,0xF0),(3,1,0x90|source["psg_volume"]))):
                    writes.append({"chip":chip,"reg":reg,"value":value,"tick":tick+offset})
            trace=work/"trace.jsonl";trace.write_text("\n".join(json.dumps(x) for x in [*writes,{"dropped":0}])+"\n")
            native=work/"native.json";native.write_text("{}\n")
            reference=lambda p:{"path":str(p.relative_to(module.ROOT)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
            record={"audio_trace":reference(trace),"native_report":reference(native)}
            def signal(wrong=False):
                values=array.array("h",[0])*(170000*2)
                for index,(first,hz) in enumerate(segments):
                    end=segments[index+1][0] if index+1<len(segments) else 170000
                    for frame in range(first,end):
                        value=round(1000*math.sin(2*math.pi*(2000 if wrong else hz)*(frame-first)/48000))
                        values[2*frame]=values[2*frame+1]=value
                if sys.byteorder!="little":values.byteswap()
                return values.tobytes()
            features=module.validate_source_audio("recursion94",record,signal(),expectations)
            self.assertEqual(features["score"],"selected-v1-vblank-motif")
            self.assertEqual(len(features["notes"]),3)
            with self.assertRaisesRegex(module.Invalid,"media-rec-score-pcm"):
                module.validate_source_audio("recursion94",record,signal(True),expectations)

    def test_source_image_features_and_tank_palette_reject_pixel_mutants(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "phase6_media_compiler", pathlib.Path(__file__).resolve().parents[2] / "scripts/evidence/phase6_routes.py")
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        root = pathlib.Path(__file__).resolve().parents[2]
        expectations = json.loads((root / "fixtures/phase6/media-expectations-v1.json").read_text())
        rec = next(row for row in expectations["captures"] if row["fixture"] == "recursion94")
        mask = module._reference_actor_mask(rec)
        region = rec["image"]["expected_actor_region_px"]
        pixels = bytearray(320 * 224 * 4)
        for y in range(region["y"][0], region["y"][1]):
            for x in range(region["x"][0], region["x"][1]):
                if mask[y * 320 + x]:
                    pixels[(y * 320 + x) * 4:(y * 320 + x) * 4 + 4] = b"\xff\xff\xff\0"
        rec_row = {"attempt":4,"source_tick":690}
        rec_scene = {"attempt":4,"source_tick":690,"actor_x_px":288,"actor_y_px":112}
        module._validate_media_image("recursion94", rec_row, rec, rec_scene, bytes(pixels))
        pixels[:] = bytes(len(pixels))
        with self.assertRaisesRegex(module.Invalid, "media-rec-source-actor-mask"):
            module._validate_media_image("recursion94", rec_row, rec, rec_scene, bytes(pixels))

        with self.assertRaisesRegex(module.Invalid, "media-rec-source-actor-mask"):
            module._validate_media_image("recursion94", rec_row, rec, rec_scene, b"\xff\xff\xff\0"*(320*224))

        tank = next(row for row in expectations["captures"] if row["fixture"] == "tank-battle")
        tank_row = {"field":120}
        tank_scene = {"field":120,"p1_x":3,"p1_y":9,"p2_x":32,"p2_y":9}
        pixels = bytearray(320 * 224 * 4)
        for ty,line in enumerate(tank["image"]["reference_arena_rows"]):
            for tx,cell in enumerate(line):
                if cell != "#":continue
                for py in range(24+ty*8,24+(ty+1)*8):
                    for px in range(16+tx*8,16+(tx+1)*8):
                        offset=(py*320+px)*4
                        pixels[offset:offset+4] = bytes.fromhex(tank["image"]["wall_pixel_xrgb_le_hex"])
        module._validate_media_image("tank-battle", tank_row, tank, tank_scene, bytes(pixels))
        pixels[(24 * 320 + 16) * 4] ^= 1
        with self.assertRaisesRegex(module.Invalid, "media-tank-source-tile"):
            module._validate_media_image("tank-battle", tank_row, tank, tank_scene, bytes(pixels))
        pixels[(24 * 320 + 16) * 4] ^= 1
        pixels[(32 * 320 + 24) * 4:(32 * 320 + 24) * 4+4] = bytes.fromhex(tank["image"]["wall_pixel_xrgb_le_hex"])
        with self.assertRaisesRegex(module.Invalid, "media-tank-source-empty-corridor"):
            module._validate_media_image("tank-battle", tank_row, tank, tank_scene, bytes(pixels))



SAFE_FAILURE_DIAGNOSTIC_METHODS = frozenset(
    f"{case.__name__}.{name}"
    for case in (NativeParserContract, RepairLedgerContract, MediaConsumerContract)
    for name in unittest.defaultTestLoader.getTestCaseNames(case)
)
SAFE_EXCEPTION_CATEGORIES = frozenset({
    "AssertionError", "PermissionError", "FileNotFoundError", "TimeoutExpired",
    "OSError", "RuntimeError", "ValueError", "TypeError", "KeyError", "IndexError", "other",
})
SAFE_BOUND_CATEGORIES = frozenset({
    "phase7-capture-byte-limit", "phase7-json-byte-limit", "phase7-retained-byte-limit",
    "phase7-rss-byte-limit", "phase7-rss-observation-unavailable", "phase7-scratch-byte-limit",
    "phase7-scratch-root-invalid", "phase7-scratch-tree-unsafe", "phase7-stdout-stderr-byte-limit",
    "phase7-wall-timeout", "none", "other", "unspecified-bound-violation",
})
SAFE_CLEANUP_CATEGORIES = frozenset({"confirmed", "unconfirmed", "missing"})
SAFE_CLEANUP_REASON_CATEGORIES = SAFE_CLEANUP_REASONS | frozenset({"missing", "other"})
SAFE_CLEANUP_ATTEMPTS = frozenset(str(value) for value in range(17)) | frozenset({"other"})


class SafeDiagnosticTextTestResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.safe_exception_by_test = {}
        self.safe_cleanup_by_test = {}
        self._runs_at_test_start = {}

    def startTest(self, test):
        runs = getattr(test, "runs", None)
        self._runs_at_test_start[id(test)] = (runs, len(runs) if isinstance(runs, list) else 0)
        super().startTest(test)

    def _snapshot_cleanup(self, test):
        runs = getattr(test, "runs", None)
        previous, start = self._runs_at_test_start.get(id(test), (None, 0))
        if not isinstance(runs, list):
            row = {}
        else:
            first_new = start if runs is previous else 0
            row = runs[-1] if len(runs) > first_new and isinstance(runs[-1], dict) else {}
        cleanup = row.get("process_group_cleanup")
        cleanup = cleanup if cleanup in SAFE_CLEANUP_CATEGORIES else "missing"
        bound = row.get("bound_violation_reason")
        bound = (bound if bound in SAFE_BOUND_CATEGORIES else
                 ("other" if bound else ("unspecified-bound-violation"
                  if row.get("bound_violation") is True else "none")))
        reason = row.get("cleanup_reason")
        reason = reason if reason in SAFE_CLEANUP_REASON_CATEGORIES else ("other" if reason else "missing")
        status = row.get("cleanup_status_observation")
        status = status if status in SAFE_CLEANUP_REASON_CATEGORIES else ("other" if status else "missing")
        attempts = row.get("cleanup_observation_attempts", 0)
        attempts = str(attempts) if type(attempts) is int and 0 <= attempts <= 16 else "other"
        self.safe_cleanup_by_test[id(test)] = (cleanup, bound, reason, status, attempts)

    def addFailure(self, test, err):
        self.safe_exception_by_test[id(test)] = "AssertionError"
        self._snapshot_cleanup(test)
        super().addFailure(test, err)

    def addError(self, test, err):
        error_type = err[0] if isinstance(err, tuple) and err else None
        name = getattr(error_type, "__name__", "")
        self.safe_exception_by_test[id(test)] = name if name in SAFE_EXCEPTION_CATEGORIES else "other"
        self._snapshot_cleanup(test)
        super().addError(test, err)


def _emit_safe_failure_diagnostics(result):
    for kind, rows in (("failure", result.failures), ("error", result.errors)):
        for test, _ in rows:
            method = f"{test.__class__.__name__}.{test._testMethodName}"
            if method in SAFE_FAILURE_DIAGNOSTIC_METHODS:
                exception = getattr(result, "safe_exception_by_test", {}).get(id(test), "other")
                cleanup, bound, reason, status_observation, attempts = getattr(
                    result, "safe_cleanup_by_test", {}).get(
                        id(test), ("missing", "none", "missing", "missing", "0"))
                print(f"GENEWHIP_TEST_RESULT:{method}:{kind}:{exception}:{cleanup}:{bound}:"
                      f"{reason}:{status_observation}:{attempts}",
                      file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tracer", action="store_true")
    parser.add_argument("--contract", action="store_true")
    parser.add_argument("--media-contract", action="store_true")
    parser.add_argument("--probe-load", action="store_true")
    parser.add_argument("--probe-movem", action="store_true")
    parser.add_argument("--desktop", action="store_true",
                        help="include the selected CMake tree's desktop client in this contract roster")
    parser.add_argument("--build", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.media_contract:
        MediaConsumerContract.build = args.build.resolve()
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(MediaConsumerContract)
        result = unittest.TextTestRunner(verbosity=2, resultclass=SafeDiagnosticTextTestResult).run(suite)
        _emit_safe_failure_diagnostics(result)
        return 0 if result.wasSuccessful() else 1
    if args.probe_load or args.probe_movem:
        try:
            probe = _phase6_probe_movem if args.probe_movem else _phase6_probe_load
            return probe(args.build.resolve())
        except (OSError, RuntimeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            print(f"BLOCKED: {error}", file=sys.stderr)
            return 1
    if args.contract:
        build = args.build.resolve()
        NativeParserContract.desktop = build / "tools/desktop/genewhip-desktop"
        if args.desktop and not NativeParserContract.desktop.is_file():
            parser.error("--desktop selected but desktop client is missing from build")
        require_host_process_context()
        script = pathlib.Path(__file__).resolve().parents[2] / "scripts/evidence/phase6_routes.py"
        result = subprocess.run([sys.executable, "-I", str(script), "--self-test"],
                                text=True, capture_output=True, timeout=30)
        if result.returncode:
            print(result.stdout + result.stderr, file=sys.stderr)
            return result.returncode
        NativeParserContract.client = build / "tools/session/gw_headless"
        NativeParserContract.clients = ((NativeParserContract.client, NativeParserContract.desktop)
            if args.desktop else (NativeParserContract.client,))
        NativeParserContract.runs = []
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeParserContract)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(RepairLedgerContract))
        MediaConsumerContract.build = build
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(MediaConsumerContract))
        result = unittest.TextTestRunner(verbosity=2, resultclass=SafeDiagnosticTextTestResult).run(suite)
        _emit_safe_failure_diagnostics(result)
        return 0 if result.wasSuccessful() else 1
    if not args.tracer:
        parser.error("select --tracer")
    build = args.build.resolve()
    TracerContract.client = build / "tools/session/gw_headless"
    TracerContract.desktop = build / "tools/desktop/genewhip-desktop"
    TracerContract.runs = []
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TracerContract)
    successful = unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()
    child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    rss_bytes = int(child_usage.ru_maxrss * (1 if platform.system() == "Darwin" else 1024))
    instruction_count = sum(int(observation.get("instructions", 0))
        for run in TracerContract.runs for observation in run.get("observations", []))
    boundary_count = sum(int(observation.get("observations", 0))
        for run in TracerContract.runs for observation in run.get("observations", []))
    bounded = all(not run.get("bound_violation") and float(run["wall_seconds"]) <= 600 and
        int(run["stdout_bytes"]) <= MAX_STREAM_BYTES and int(run["stderr_bytes"]) <= MAX_STREAM_BYTES and
        int(run.get("report_bytes", 0)) <= MAX_REPORT_BYTES for run in TracerContract.runs)
    successful = successful and bounded and instruction_count > 0
    evidence = {
        "schema": "genewhip-phase6-tracer-evidence-v1",
        "status": "pass" if successful else "fail",
        "measurements": {
            "wall_seconds": sum(float(run["wall_seconds"]) for run in TracerContract.runs),
            "peak_child_rss_bytes": rss_bytes,
            "source_step_observations_per_instruction": boundary_count / instruction_count if instruction_count else None,
            "source_step_observations": boundary_count,
            "source_instructions": instruction_count,
            "queue_high_water": max((int(run.get("queue_high_water", 0)) for run in TracerContract.runs), default=0),
        },
        "bounds": {"wall_seconds": 600, "stdout_bytes": 1048576, "stderr_bytes": 1048576,
                   "queued_events": 64, "trace_rows": 100000},
        "runs": TracerContract.runs,
    }
    evidence_path = build / "evidence/tracer.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    return 0 if successful else 1


if __name__ == "__main__":
    if "--host-process-context" in sys.argv:
        sys.argv.remove("--host-process-context")
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = HOST_PROCESS_CONTEXT
    elif not any(flag in sys.argv for flag in ("--contract", "--media-contract", "--tracer")):
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = HOST_PROCESS_CONTEXT
    raise SystemExit(main())
