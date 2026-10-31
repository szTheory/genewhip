#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Denied actual-caller contracts for creation-time process receipts."""
from __future__ import annotations

import importlib.util as _real_importlib_util
from pathlib import Path
import sys
denial = None
if "--verify-artifacts" not in sys.argv:
    _spec = _real_importlib_util.spec_from_file_location("creation_sticky_denial",
        Path(__file__).with_name("phase7_sticky_denial.py"))
    denial = _real_importlib_util.module_from_spec(_spec)
    _spec.loader.exec_module(denial)
    denial.install()

import contextlib
import ast
import datetime
import hashlib
import importlib.abc
import json
import os
import re
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
REAL_SPEC = _real_importlib_util.spec_from_file_location
REAL_FSYNC = os.fsync
CASES: list[str] = []
MUTANTS: list[str] = []
OWNED: list[str] = []
OWNED_TOTAL: list[str] = []
REACHED: list[str] = []
MUTANT_RESULTS: list[dict[str, str]] = []
CONTROL_RESULTS: list[dict[str, str]] = []
LAST_RUN: dict[str, int] = {"tests_run": 0, "failures": 0, "errors": 0}


class AliasLoader(importlib.abc.Loader):
    def __init__(self, source): self.source = source
    def create_module(self, spec): return None
    def exec_module(self, module): module.__dict__.update(self.source.__dict__)


class ReceiptStream:
    def __init__(self, stream, owner): self.stream, self.owner = stream, owner
    def __getattr__(self, name): return getattr(self.stream, name)
    def flush(self):
        self.owner.persistence_events.append("flush")
        self.owner.stream_flushes += 1
        if self.owner.fail_flush_on == self.owner.stream_flushes:
            raise OSError("injected-flush-failure")
        return self.stream.flush()


class ReceiptLoader(importlib.abc.Loader):
    def __init__(self, owner): self.owner = owner
    def create_module(self, spec): return None
    def exec_module(self, module):
        path = ROOT / "scripts/evidence/phase5_process.py"
        module.__file__ = str(path)
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
        original = module.receipt_file
        @contextlib.contextmanager
        def observed_receipt_file(root, relative, **kwargs):
            with original(root, relative, **kwargs) as stream:
                yield ReceiptStream(stream, self.owner)
        module.receipt_file = observed_receipt_file


def load(relative, name, source_override=None):
    path = ROOT / relative
    spec = REAL_SPEC(name, path)
    module = importlib.util.module_from_spec(spec)
    source = source_override if source_override is not None else path.read_bytes()
    if source_override is not None:
        module.__file__ = str(path)
        exec(compile(source, str(path), "exec"), module.__dict__)
    else:
        spec.loader.exec_module(module)
    return module


boundary = None
game = None
coordinator = None


class CreationContracts(unittest.TestCase):
    def setUp(self):
        import signal
        self.signal = signal
        global boundary, game, coordinator
        if boundary is None:
            boundary = load("tests/session/phase6_route_contract.py", "creation_boundary")
            game = load("tests/fixtures/phase6_game.py", "creation_game")
            coordinator = load("scripts/release/v02_qualification.py", "creation_coordinator")
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        OWNED.clear()
        REACHED.clear()
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="gw-creation-fake-"))).resolve()
        self.work = self.root / "work"
        self.work.mkdir()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.build = self.root / "build"
        self.build.mkdir()
        fake_client = self.build / "missing-client"
        fake_client.touch(mode=0o600)
        self.assertEqual(fake_client.stat().st_size, 0)
        self.assertFalse(os.access(fake_client, os.X_OK))
        self.assertEqual(list(self.root.rglob("*.bin")), [])
        self.limits = {"wall_seconds": 10, "cleanup_grace_seconds": 1,
            "max_rss_bytes": 1024**3, "max_stdout_stderr_bytes": 4096,
            "max_json_bytes": 4096, "max_binary_file_bytes": 4096,
            "max_capture_bytes": 4096, "max_scratch_bytes": 1024**2,
            "max_retained_bytes": 1024**2, "max_fields": 5000, "max_calls": 100}
        self.scope = {"scope_id": "fake-scope", "per_child_limits": self.limits}
        self.patch(game, "ROOT", self.root)
        self.patch(coordinator, "ROOT", self.root)
        self.patch(game, "_EXECUTION_SCOPE", self.scope)
        self.patch(game, "_V02_STATE", {"workload_wall_seconds": 0,
            "workload_wall_upper_bound_seconds": 0, "process_records": []})
        self.patch(game, "_V02_DEADLINE", __import__("time").monotonic() + 60)
        self.patch(game, "_write_window", lambda *_: None)
        self.patch(game, "_read_window", lambda: {"owned_artifact_roots": []})
        self.patch(game, "tree_bytes", lambda *_: 0)
        def write_json(path, value):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(json.dumps(value))
        self.patch(game, "write_json", write_json)
        self.patch(boundary, "_run_client_owned", self.owned)
        self.stack.enter_context(mock.patch.dict(os.environ,
            {"GENEWHIP_PROCESS_CONTEXT": boundary.HOST_PROCESS_CONTEXT}))
        self.prior_handler = self.signal.getsignal(self.signal.SIGTERM)
        self.fsyncs = 0
        self.failure = None
        self.cleanup = "confirmed"
        self.bound_violation = False
        self.returncode = 0
        self.stream_flushes = 0
        self.fail_flush_on = None
        self.fail_fsync_on = None
        self.persistence_events = []
        self.seam_calls = 0
        self.monitoring_started = 0
        self.deadline_after_owned = False
        self.last_command = None
        self.last_work = None
        self.patch(boundary.os, "fsync", self.count_fsync)
        self.patch(importlib.util, "spec_from_file_location", self.spec_router)

    def patch(self, obj, name, value):
        return self.stack.enter_context(mock.patch.object(obj, name, value))

    def reached(self, name):
        REACHED.append(name)

    def spec_router(self, name, path, *args, **kwargs):
        if Path(path).name == "phase6_route_contract.py":
            return importlib.machinery.ModuleSpec(name, AliasLoader(boundary))
        if Path(path).name == "phase5_process.py":
            return importlib.machinery.ModuleSpec(name, ReceiptLoader(self))
        return REAL_SPEC(name, path, *args, **kwargs)

    def count_fsync(self, fd):
        self.fsyncs += 1
        self.persistence_events.append("fsync")
        if self.fail_fsync_on == self.fsyncs:
            raise OSError("injected-fsync-failure")
        return REAL_FSYNC(fd)

    def owned(self, client, command, runs, **kwargs):
        self.seam_calls += 1
        self.last_command = command
        self.last_work = kwargs.get("cwd")
        self.assertEqual(kwargs.get("limits"), self.limits,
            "wrapper must preserve the admitted child limits")
        self.assertTrue(kwargs.get("scratch_roots"), "wrapper must preserve owned scratch roots")
        entry = {"pid": 831001 + len(OWNED), "pgid": 831001 + len(OWNED),
            "status": "started", "process_group_cleanup": "pending",
            "bound_violation": self.bound_violation or self.cleanup != "confirmed"}
        runs.append(entry)
        kwargs["_ownership_callback"]()
        self.reached("ownership-persistence-order")
        self.assertEqual(self.persistence_events[-2:], ["flush", "fsync"],
            "ownership flush/fsync must finish before monitoring")
        self.reached("premonitor-fsyncs")
        self.assertTrue(self.fsyncs >= 2, "creation and ownership records must fsync before monitoring")
        receipts = []
        for path in self.root.rglob("*.json"):
            try: value = json.loads(path.read_text())
            except (OSError, ValueError): continue
            if isinstance(value, dict) and value.get("processes") == [entry]: receipts.append(path)
        self.reached("premonitor-owned-receipt-readable")
        self.assertTrue(receipts, "owned PID/PGID must be readable before monitoring")
        self.monitoring_started += 1
        entry.update(status="failed" if self.failure else "exited",
            process_group_cleanup=self.cleanup)
        if self.cleanup != "confirmed":
            entry.update(bound_violation=True,
                report_parse_failure="skipped-unconfirmed-process-group-cleanup")
        OWNED.append(client.name)
        OWNED_TOTAL.append(client.name)
        if self.deadline_after_owned:
            game._V02_DEADLINE = __import__("time").monotonic() - 1
        if self.failure is not None:
            raise self.failure
        return types.SimpleNamespace(args=command, returncode=self.returncode,
            stdout="fake-out", stderr="fake-err")

    def route_actual_boundary(self, name, path, *args, **kwargs):
        if Path(path).resolve() == (ROOT / "tests/session/phase6_route_contract.py").resolve():
            return REAL_SPEC(name, path, *args, **kwargs)
        return REAL_SPEC(name, path, *args, **kwargs)

    def call_shared(self):
        try:
            result, receipt, streams = game.shared_launch(self.build / "missing-client",
                [str(self.build / "missing-client")], self.work, self.work / "report.json", 10)
        except Exception as error:
            self.reached("shared-wrapper-normal-result")
            self.fail("shared wrapper failed its actual caller contract: " + type(error).__name__)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(receipt["process_group_cleanup"], "confirmed")
        self.assertIn("stdout", streams)

    def call_coordinator(self, label="same-label", check=True):
        try:
            before = len(list((self.scratch / "process-receipts").glob("*.json")))
            result = coordinator._bounded_command([str(self.build / "missing-client")],
                limits=self.limits, scratch=self.scratch, timeout=10, label=label, check=check)
            after = len(list((self.scratch / "process-receipts").glob("*.json")))
            self.assertEqual(after, before + 1, "coordinator must retain its distinct creation receipt")
            self.assertEqual(result["schema"], "genewhip.v02-coordinator-child-attempt.v1")
            self.assertEqual(result["label"], label)
            self.assertEqual(result["stdout_tail"], "fake-out")
            self.assertEqual(result["stderr_tail"], "fake-err")
            self.assertEqual(result["process_group_cleanup"], "confirmed")
            return result
        except Exception as error:
            self.reached("coordinator-wrapper-normal-result")
            self.fail("coordinator failed its actual caller contract: " + type(error).__name__)

    def test_both_actual_wrappers_create_before_owned_monitoring(self):
        self.call_shared()
        self.call_coordinator()
        records = list(self.root.rglob("process-receipts/*.json"))
        self.assertEqual(len(records), 2)
        self.assertEqual(len({path.name for path in records}), 2)
        self.assertEqual(len(OWNED), 2)
        self.assertIs(self.signal.getsignal(self.signal.SIGTERM), self.prior_handler)
        CASES.append("both-actual-wrappers-durable-before-monitor")

    def test_reused_work_and_label_keep_distinct_creation_receipts(self):
        self.call_shared(); self.call_shared()
        self.call_coordinator(); self.call_coordinator()
        paths = list(self.root.rglob("process-receipts/*.json"))
        self.assertEqual(len(paths), 4)
        values = [json.loads(path.read_text())["processes"][0]["pid"] for path in paths]
        self.assertEqual(len(set(values)), 4)
        CASES.append("reused-directory-and-label-distinct-receipts")

    def test_receipt_collision_preserves_prior_bytes_and_prevents_ownership(self):
        path = self.work / "process-receipts" / "collision.json"
        path.parent.mkdir()
        path.write_bytes(b"prior-bytes\n")
        starts = len(OWNED)
        with mock.patch.object(game.uuid, "uuid4", return_value=types.SimpleNamespace(hex="collision")):
            with self.assertRaises(RuntimeError) as caught:
                game.shared_launch(self.build / "missing-client", ["missing-client"],
                    self.work, self.work / "report.json", 10)
        self.assertIsInstance(caught.exception.__cause__, FileExistsError)
        self.assertEqual(path.read_bytes(), b"prior-bytes\n")
        self.assertEqual(len(OWNED), starts)
        coordinator_path = self.scratch / "process-receipts" / "collision.json"
        coordinator_path.parent.mkdir()
        coordinator_path.write_bytes(b"prior-coordinator-bytes\n")
        with mock.patch.object(coordinator.uuid, "uuid4", return_value=types.SimpleNamespace(hex="collision")):
            with self.assertRaises(RuntimeError):
                coordinator._bounded_command([str(self.build / "missing-client")],
                    limits=self.limits, scratch=self.scratch, timeout=10, label="collision")
        self.assertEqual(coordinator_path.read_bytes(), b"prior-coordinator-bytes\n")
        self.assertEqual(len(OWNED), starts)
        CASES.append("creation-collision-prior-bytes-preserved-zero-ownership")

    def test_owned_exception_and_cancellation_keep_causality_and_terminal_receipt(self):
        for error in (ValueError("owned-error"), KeyboardInterrupt("owned-cancel")):
            with self.subTest(error=type(error).__name__):
                self.failure = error
                with self.assertRaisesRegex(RuntimeError, "phase7-bounded-child-boundary-error") as caught:
                    game.shared_launch(self.build / "missing-client", ["missing-client"],
                        self.work, self.work / "report.json", 10)
                self.reached("shared-error-identity-cause")
                self.assertIs(caught.exception.__cause__, error,
                    "wrapper translation must retain original exception identity")
                records = list(self.work.glob("process-receipts/*.json"))
                self.assertEqual(len(records), 1)
                self.reached("terminal-status-retained")
                self.assertEqual(json.loads(records[0].read_text())["processes"][0]["status"], "failed",
                    "terminal process record retained")
                self.failure = None
                self.work = self.root / ("work-" + type(error).__name__)
                self.work.mkdir()
        CASES.append("owned-error-and-cancellation-terminal-causality")

    def test_owned_error_terminal_mutant_target(self):
        primary = ValueError("terminal-target")
        self.failure = primary
        with self.assertRaisesRegex(RuntimeError, "phase7-bounded-child-boundary-error"):
            game.shared_launch(self.build / "missing-client", ["missing-client"],
                self.work, self.work / "report.json", 10)
        record = json.loads(next(self.work.glob("process-receipts/*.json")).read_text())["processes"][0]
        self.reached("terminal-status-retained")
        self.assertEqual(record["status"], "failed", "terminal process record retained")

    def test_shared_failure_translation_mutant_target(self):
        primary = ValueError("translation-target")
        self.failure = primary
        with self.assertRaisesRegex(RuntimeError, "phase7-bounded-child-boundary-error") as caught:
            game.shared_launch(self.build / "missing-client", ["missing-client"],
                self.work, self.work / "report.json", 10)
        self.reached("shared-error-identity-cause")
        self.assertIs(caught.exception.__cause__, primary,
            "wrapper translation must retain original exception identity")

    def test_initial_and_terminal_fsync_failures_remain_nonqualifying(self):
        initial_calls = len(OWNED)
        with mock.patch.object(boundary.os, "fsync", side_effect=OSError("initial-fsync")):
            with self.assertRaisesRegex(RuntimeError, "phase7-bounded-child-boundary-error") as caught:
                game.shared_launch(self.build / "missing-client", ["missing-client"],
                    self.work, self.work / "report.json", 10)
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertEqual(len(OWNED), initial_calls, "initial durability fault must precede owned helper")

        calls = 0
        real_fsync = REAL_FSYNC
        def fail_final(fd):
            nonlocal calls
            calls += 1
            if calls == 3: raise OSError("terminal-fsync")
            return real_fsync(fd)
        with mock.patch.object(boundary.os, "fsync", side_effect=fail_final):
            with self.assertRaisesRegex(RuntimeError, "phase7-bounded-child-boundary-error") as caught:
                game.shared_launch(self.build / "missing-client", ["missing-client"],
                    self.work, self.work / "report.json", 10)
        self.assertIsInstance(caught.exception.__cause__, OSError)
        CASES.append("initial-and-terminal-fsync-failure-nonqualifying")

    def test_flush_fsync_faults_at_initial_ownership_terminal_for_both_wrappers(self):
        for wrapper in ("shared", "coordinator"):
            for failure_kind in ("flush", "fsync"):
                for stage, ordinal in (("initial", 1), ("ownership", 2), ("terminal", 3)):
                    with self.subTest(wrapper=wrapper, failure_kind=failure_kind, stage=stage):
                        seam_before, monitor_before = self.seam_calls, self.monitoring_started
                        if failure_kind == "flush": self.fail_flush_on = self.stream_flushes + ordinal
                        else: self.fail_fsync_on = self.fsyncs + ordinal
                        try:
                            with self.assertRaises(RuntimeError):
                                if wrapper == "shared":
                                    work = self.root / ("fault-" + failure_kind + "-" + stage)
                                    work.mkdir()
                                    game.shared_launch(self.build / "missing-client", ["missing-client"],
                                        work, work / "report.json", 10)
                                else:
                                    coordinator._bounded_command([str(self.build / "missing-client")],
                                        limits=self.limits, scratch=self.scratch, timeout=10,
                                        label=wrapper + "-" + failure_kind + "-" + stage)
                        finally:
                            self.fail_flush_on = self.fail_fsync_on = None
                        seam_delta = self.seam_calls - seam_before
                        monitor_delta = self.monitoring_started - monitor_before
                        self.assertEqual(seam_delta, 0 if stage == "initial" else 1,
                            "initial failures precede the owned seam; later faults enter it once")
                        self.assertEqual(monitor_delta, 1 if stage == "terminal" else 0,
                            "ownership durability failure must stop before monitoring")
        CASES.append("both-wrappers-initial-ownership-terminal-flush-fsync-faults")

    def test_primary_error_survives_caller_final_persistence_failure(self):
        primary = ValueError("fake-primary")
        self.failure = primary
        def fail_caller_write(path, value):
            if Path(path).name == "process.json": raise OSError("fake-final-persistence")
        self.patch(game, "write_json", fail_caller_write)
        with self.assertRaisesRegex(OSError, "fake-final-persistence") as caught:
            game.shared_launch(self.build / "missing-client", ["missing-client"],
                self.work, self.work / "report.json", 10)
        self.assertIs(caught.exception.__cause__, primary)
        self.assertGreater(game._V02_STATE["workload_wall_seconds"], 0,
            "caller final-write failure must not skip elapsed accounting")
        self.assertEqual(game._V02_STATE["workload_wall_seconds"],
            game._V02_STATE["workload_wall_upper_bound_seconds"])
        self.assertEqual(len(game._V02_STATE["process_records"]), 1,
            "caller final-write failure must retain one process record")
        CASES.append("primary-and-caller-final-persistence-causality")

    def test_coordinator_caller_final_write_only_and_combined_failures(self):
        original = ValueError("coordinator-primary")
        def fail_write(*_args, **_kwargs): raise OSError("coordinator-final-write")
        self.patch(coordinator, "_write_json", fail_write)
        with self.assertRaisesRegex(OSError, "coordinator-final-write") as caught:
            coordinator._bounded_command([str(self.build / "missing-client")],
                limits=self.limits, scratch=self.scratch, timeout=10, label="final-only")
        self.assertIsNone(caught.exception.__cause__)
        self.assertGreater(len(OWNED), 0)
        self.failure = original
        with self.assertRaisesRegex(OSError, "coordinator-final-write") as caught:
            coordinator._bounded_command([str(self.build / "missing-client")],
                limits=self.limits, scratch=self.scratch, timeout=10, label="final-combined")
        self.assertIs(caught.exception.__cause__, original)
        CASES.append("coordinator-final-only-and-primary-final-causality")

    def test_primary_exception_survives_helper_terminal_fsync_failure_both_wrappers(self):
        for wrapper in ("shared", "coordinator"):
            primary = ValueError(wrapper + "-primary")
            self.failure = primary
            self.fail_fsync_on = self.fsyncs + 3
            try:
                with self.assertRaises(RuntimeError) as caught:
                    if wrapper == "shared":
                        game.shared_launch(self.build / "missing-client", ["missing-client"],
                            self.work, self.work / "report.json", 10)
                    else:
                        coordinator._bounded_command([str(self.build / "missing-client")],
                            limits=self.limits, scratch=self.scratch, timeout=10, label="helper-final")
            finally:
                self.fail_fsync_on = None
                self.failure = None
            translation = caught.exception
            helper_error = translation.__cause__
            self.assertIsInstance(helper_error, OSError)
            self.assertIs(helper_error.__context__, primary,
                "helper final-persistence failure must retain the primary exception as context")
        CASES.append("helper-terminal-fsync-plus-primary-causality-both-wrappers")

    def test_final_write_only_failure_is_accounted_once(self):
        def fail_caller_write(path, value):
            if Path(path).name == "process.json": raise OSError("final-only")
        self.patch(game, "write_json", fail_caller_write)
        with self.assertRaisesRegex(OSError, "final-only"):
            game.shared_launch(self.build / "missing-client", ["missing-client"],
                self.work, self.work / "report.json", 10)
        state = game._V02_STATE
        self.assertGreater(state["workload_wall_seconds"], 0,
            "final-write-only failure must retain elapsed accounting")
        self.assertEqual(state["workload_wall_seconds"], state["workload_wall_upper_bound_seconds"])
        self.assertEqual(len(state["process_records"]), 1,
            "final-write-only failure must retain exactly one process record")
        CASES.append("caller-final-only-failure-accounted-once")

    def test_coordinator_owned_error_and_cancellation_keep_causality(self):
        for error in (ValueError("coordinator-primary"), KeyboardInterrupt("coordinator-cancel")):
            self.failure = error
            with self.assertRaisesRegex(RuntimeError, "qualification-child-boundary-error") as caught:
                coordinator._bounded_command([str(self.build / "missing-client")],
                    limits=self.limits, scratch=self.scratch, timeout=10, label="raised")
            self.assertIs(caught.exception.__cause__, error)
            attempt = json.loads((self.scratch / "raised.attempt.json").read_text())
            self.assertIn(type(error).__name__, attempt["launch_error"])
            self.assertEqual(attempt["processes"][0]["status"], "failed")
            self.failure = None
        CASES.append("coordinator-owned-error-cancellation-causality")

    def test_unconfirmed_cleanup_helper_exception_shape_is_preserved(self):
        self.cleanup = "unconfirmed"
        primary = RuntimeError(
            "bounded child process group remains live after termination; refusing further work")
        self.failure = primary
        with self.assertRaisesRegex(RuntimeError, "phase7-bounded-child-boundary-error") as caught:
            game.shared_launch(self.build / "missing-client", ["missing-client"],
                self.work, self.work / "report.json", 10)
        self.assertIs(caught.exception.__cause__, primary)
        retained = json.loads(next(self.work.glob("process-receipts/*.json")).read_text())["processes"][0]
        self.assertEqual(retained["process_group_cleanup"], "unconfirmed")
        self.assertTrue(retained["bound_violation"])
        self.assertEqual(retained["report_parse_failure"], "skipped-unconfirmed-process-group-cleanup")
        self.assertEqual(primary.process_receipts, [retained])
        self.failure = None
        scratch = self.root / "scratch-unconfirmed"
        scratch.mkdir()
        self.failure = primary
        with self.assertRaisesRegex(RuntimeError, "qualification-child-boundary-error") as caught:
            coordinator._bounded_command([str(self.build / "missing-client")],
                limits=self.limits, scratch=scratch, timeout=10, label="unconfirmed-exception")
        self.assertIs(caught.exception.__cause__, primary)
        attempt = json.loads((scratch / "unconfirmed-exception.attempt.json").read_text())
        self.assertEqual(attempt["processes"][0]["process_group_cleanup"], "unconfirmed")
        self.assertTrue(attempt["processes"][0]["bound_violation"])
        self.assertEqual(attempt["processes"][0]["report_parse_failure"],
            "skipped-unconfirmed-process-group-cleanup")
        CASES.append("unconfirmed-helper-error-shape-through-real-persistence")

    def test_shared_bound_and_deadline_rejection_owners_are_unchanged(self):
        self.bound_violation = True
        work = self.root / "work-bound"
        work.mkdir()
        _result, receipt, _streams = game.shared_launch(self.build / "missing-client",
            ["missing-client"], work, self.root / "report-bound.json", 10)
        self.assertTrue(receipt["bound_violation"], "shared wrapper must return bound result to core consumer")
        starts = len(OWNED)
        old_deadline = game._V02_DEADLINE
        game._V02_DEADLINE = __import__("time").monotonic() - 1
        with self.assertRaisesRegex(RuntimeError, "phase7-runtime-batch-deadline-exhausted"):
            game.shared_launch(self.build / "missing-client", ["missing-client"],
                work, self.root / "report-deadline.json", 10)
        self.assertEqual(len(OWNED), starts, "pre-entry deadline rejection must precede helper ownership")
        self.assertEqual(len(game._V02_STATE["process_records"]), 1)
        game._V02_DEADLINE = old_deadline
        CASES.append("shared-bound-return-and-preentry-deadline-owner")

    def test_coordinator_bound_and_missing_receipt_remain_rejected(self):
        self.bound_violation = True
        with self.assertRaisesRegex(RuntimeError, "qualification-child-failed"):
            coordinator._bounded_command([str(self.build / "missing-client")],
                limits=self.limits, scratch=self.scratch, timeout=10, label="bound")
        attempt = json.loads((self.scratch / "bound.attempt.json").read_text())
        self.assertTrue(attempt["processes"][0]["bound_violation"])
        self.bound_violation = False
        self.patch(boundary, "_run_client_owned", lambda *_a, **_k:
            types.SimpleNamespace(returncode=0, stdout="", stderr=""))
        with self.assertRaisesRegex(RuntimeError, "qualification-child-failed"):
            coordinator._bounded_command([str(self.build / "missing-client")],
                limits=self.limits, scratch=self.scratch, timeout=10, label="missing")
        attempt = json.loads((self.scratch / "missing.attempt.json").read_text())
        self.assertEqual(attempt["processes"], [])
        self.assertEqual(attempt["process_group_cleanup"], "missing")
        CASES.append("coordinator-bound-and-missing-receipt-rejection")

    def test_actual_collect_case_and_original_control_reject_bound_results(self):
        route = {"fixture": "recursion94", "case": {"id": "full-route"},
            "identity": "fake-route-id", "definitions": {"predicates": []}}
        work = self.root / "collect-case"
        self.bound_violation = True
        with self.assertRaisesRegex(RuntimeError, "process failed"):
            game.collect_case(self.build, route, {}, {}, work, 1,
                remaining_seconds=10, compiled_binary=b"bounded-fake-plan")
        self.assertTrue((work / "process.json").is_file())
        self.assertTrue(json.loads((work / "run.json").read_text())["reason"] == "client-process-failed")

        now = datetime.datetime.now(datetime.timezone.utc)
        window = {"owned_artifact_roots": [], "workload_cutoff":
            (now + datetime.timedelta(hours=1)).isoformat(), "workload_wall_seconds": 0,
            "workload_wall_upper_bound_seconds": 0, "started_at": now.isoformat(),
            "deadline": (now + datetime.timedelta(hours=1)).isoformat()}
        self.patch(game, "_read_window", lambda: window)
        self.patch(game, "_write_window", lambda *_: None)
        self.patch(game, "_EXECUTION_SCOPE", {**self.scope, "_scope_path": str(self.root / "scope.json")})
        self.patch(game.compiler, "validate_delivery_map", lambda *_: None)
        self.patch(game.compiler, "compile_routes", lambda: {"routes": [
            {"fixture": "genewhip-independent-game-v2", "case": {"id": "probe"},
             "identity": "fake-control-id"}]})
        self.patch(game, "preflight_compiled_roster", lambda *_: {})
        self.patch(game, "freeze_candidate", lambda *_: {})
        self.patch(game, "freeze_build_provenance", lambda *_: None)
        self.patch(game, "contextual_stages", lambda *_: [])
        self.patch(game, "reader_provenance", lambda: {})
        self.patch(game, "validation_identities", lambda: {})
        self.bound_violation = True
        output = self.root / "core-report.json"
        mapping_path = self.root / "mapping.json"
        mapping_path.write_text("{}")
        with self.assertRaisesRegex(RuntimeError, "original control driver failed"):
            game.core(self.build, mapping_path, self.root / "candidate.json", output)
        self.assertIsNotNone(self.last_work)
        nested = Path(self.last_command[self.last_command.index("--process-receipt") + 1])
        wrapper_receipt = next(self.last_work.glob("process-receipts/*.json"))
        self.assertEqual(nested, self.last_work / "nested-processes.json")
        self.assertNotEqual(nested, wrapper_receipt)
        self.assertNotEqual(nested, self.last_work / "process.json")
        self.assertIn("--outer-process-group", self.last_command)
        CASES.append("actual-collect-and-original-control-rejection-and-distinct-sinks")

    def test_unscoped_shared_launch_ast_is_bytecode_ir_equivalent_to_entry(self):
        tree = ast.parse((ROOT / "tests/fixtures/phase6_game.py").read_text())
        function = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "shared_launch")
        branch_index = next(index for index, node in enumerate(function.body) if isinstance(node, ast.If))
        unscoped = ast.Module(body=function.body[branch_index + 1:], type_ignores=[])
        identity = hashlib.sha256(ast.dump(unscoped, include_attributes=False).encode()).hexdigest()
        self.assertEqual(identity, "26697b55d2758d441cf23a1f10d3e18bbe9d22b186442c83205a34d9686b54ab",
            "unscoped shared_launch AST changed from the entry source")
        CASES.append("unscoped-shared-launch-ast-exact-preservation")

    def test_artifact_privacy_filter_rejects_private_markers(self):
        self.assertTrue(is_public_text("Relative project paths only."))
        private_path = "/" + "Users" + "/example/private-rom.bin"
        self.assertFalse(is_public_text(private_path))
        self.assertFalse(is_public_text("tester@example.invalid"))
        self.assertFalse(is_public_text("api_key=example-secret-value"))
        CASES.append("artifact-privacy-filter-positive-negative-controls")

    def test_final_review_pin_contract_rejects_stale_source_and_evidence(self):
        pins = {"source.py": "a" * 64}
        review = {"reviewed_source_sha256": pins, "evidence_sha256": "b" * 64,
            "verdict": "SECURED", "unresolved_high_critical": 0}
        self.assertTrue(review_pins_match(review, pins, "b" * 64))
        self.assertFalse(review_pins_match(review, {"source.py": "c" * 64}, "b" * 64))
        self.assertFalse(review_pins_match(review, pins, "d" * 64))
        self.assertFalse(review_pins_match({**review, "verdict": "OPEN_THREATS"}, pins, "b" * 64))
        CASES.append("final-review-source-evidence-pin-positive-negative-controls")

    def test_post_call_deadline_and_exceptional_accounting(self):
        self.failure = ValueError("accounted-primary")
        with self.assertRaisesRegex(RuntimeError, "phase7-bounded-child-boundary-error"):
            game.shared_launch(self.build / "missing-client", ["missing-client"],
                self.work, self.work / "report.json", 10)
        error_state = game._V02_STATE
        self.assertGreater(error_state["workload_wall_seconds"], 0)
        self.assertEqual(len(error_state["process_records"]), 1)
        self.failure = None
        self.deadline_after_owned = True
        work = self.root / "work-post-deadline"
        work.mkdir()
        with self.assertRaisesRegex(RuntimeError, "phase7-runtime-batch-deadline-exceeded"):
            game.shared_launch(self.build / "missing-client", ["missing-client"],
                work, work / "report.json", 10)
        self.assertEqual(len(game._V02_STATE["process_records"]), 2)
        self.assertEqual(game._V02_STATE["workload_wall_seconds"],
            game._V02_STATE["workload_wall_upper_bound_seconds"])
        CASES.append("post-call-deadline-and-exceptional-accounting")

    def test_coordinator_check_and_cleanup_rejection_owners_remain(self):
        self.returncode = 7
        accepted = self.call_coordinator(label="unchecked", check=False)
        self.assertEqual(accepted["returncode"], 7)
        with self.assertRaisesRegex(RuntimeError, "qualification-child-failed"):
            coordinator._bounded_command([str(self.build / "missing-client")],
                limits=self.limits, scratch=self.scratch, timeout=10, label="checked", check=True)
        self.returncode = 0
        self.cleanup = "unconfirmed"
        unconfirmed_work = self.root / "work-unconfirmed"
        unconfirmed_work.mkdir()
        with self.assertRaisesRegex(RuntimeError, "phase7-shared-child-cleanup-unconfirmed"):
            game.shared_launch(self.build / "missing-client", ["missing-client"],
                unconfirmed_work, self.root / "report.json", 10)
        receipt = json.loads((unconfirmed_work / "process.json").read_text())["processes"][0]
        self.assertEqual(receipt["process_group_cleanup"], "unconfirmed")
        with self.assertRaisesRegex(RuntimeError, "qualification-child-failed"):
            coordinator._bounded_command([str(self.build / "missing-client")],
                limits=self.limits, scratch=self.scratch, timeout=10, label="unconfirmed")
        CASES.append("coordinator-check-and-cleanup-policy-shared-preservation")

    def test_shared_accounting_is_exactly_once(self):
        self.call_shared()
        state = game._V02_STATE
        self.reached("shared-accounting-increment")
        self.assertGreater(state["workload_wall_seconds"], 0, "caller accounting increment")
        self.assertEqual(state["workload_wall_seconds"], state["workload_wall_upper_bound_seconds"])
        self.assertEqual(len(state["process_records"]), 1)
        CASES.append("shared-accounting-exactly-once")

    def test_source_mutants_are_killed_by_actual_callers(self):
        cases = (
            ("game-sink", "game", "tests/fixtures/phase6_game.py", "process_receipt_stream=receipt_stream", "process_receipt_stream=None", "test_both_actual_wrappers_create_before_owned_monitoring"),
            ("coordinator-sink", "coordinator", "scripts/release/v02_qualification.py", "process_receipt_stream=receipt_stream", "process_receipt_stream=None", "test_both_actual_wrappers_create_before_owned_monitoring"),
            ("bypass-flush", "boundary", "tests/session/phase6_route_contract.py", "process_receipt_stream.flush()", "pass  # mutant skips flush", "test_both_actual_wrappers_create_before_owned_monitoring"),
            ("bypass-fsync", "boundary", "tests/session/phase6_route_contract.py", "os.fsync(process_receipt_stream.fileno())", "pass  # mutant skips fsync", "test_both_actual_wrappers_create_before_owned_monitoring"),
            ("defer-ownership-persist", "boundary", "tests/session/phase6_route_contract.py", "_ownership_callback=record_ownership", "_ownership_callback=lambda: None", "test_both_actual_wrappers_create_before_owned_monitoring"),
            ("overwrite-reused-identity", "game", "tests/fixtures/phase6_game.py", "uuid.uuid4().hex", "'fixed-identity'", "test_reused_work_and_label_keep_distinct_creation_receipts"),
            ("suppress-terminal-retention", "boundary", "tests/session/phase6_route_contract.py", "finally:\n        try:\n            persist_receipt()", "finally:\n        try:\n            pass  # mutant suppresses terminal record", "test_owned_error_terminal_mutant_target"),
            ("change-shared-failure-translation", "game", "tests/fixtures/phase6_game.py", "raise RuntimeError(\"phase7-bounded-child-boundary-error:\"+boundary_error) from boundary_exception", "raise RuntimeError(\"phase7-bounded-child-boundary-error:\"+boundary_error)", "test_shared_failure_translation_mutant_target"),
            ("change-shared-accounting", "game", "tests/fixtures/phase6_game.py", "_V02_STATE[\"workload_wall_seconds\"] += elapsed", "_V02_STATE[\"workload_wall_seconds\"] = 0", "test_shared_accounting_is_exactly_once"),
            ("change-coordinator-check-policy", "coordinator", "scripts/release/v02_qualification.py", "if check and returncode != 0:", "if returncode != 0:", "test_coordinator_check_and_cleanup_rejection_owners_remain"),
        )
        markers = {
            "game-sink": ("shared-wrapper-normal-result", "shared wrapper failed its actual caller contract"),
            "coordinator-sink": ("coordinator-wrapper-normal-result", "coordinator failed its actual caller contract"),
            "bypass-flush": ("ownership-persistence-order", "ownership flush/fsync must finish before monitoring"),
            "bypass-fsync": ("ownership-persistence-order", "ownership flush/fsync must finish before monitoring"),
            "defer-ownership-persist": ("premonitor-fsyncs", "creation and ownership records must fsync before monitoring"),
            "overwrite-reused-identity": ("shared-wrapper-normal-result", "shared wrapper failed its actual caller contract"),
            "suppress-terminal-retention": ("terminal-status-retained", "terminal process record retained"),
            "change-shared-failure-translation": ("shared-error-identity-cause", "wrapper translation must retain original exception identity"),
            "change-shared-accounting": ("shared-accounting-increment", "caller accounting increment"),
            "change-coordinator-check-policy": ("coordinator-wrapper-normal-result", "coordinator failed its actual caller contract"),
        }
        for label, target, relative, old, new, selected in cases:
            source = (ROOT / relative).read_text()
            self.assertEqual(source.count(old), 1)
            source_digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            original_module = getattr(sys.modules[__name__], target)
            baseline = unittest.TestResult()
            with mock.patch.object(sys.modules[__name__], target, original_module):
                CreationContracts(selected).run(baseline)
            self.assertTrue(baseline.wasSuccessful(), label + " unchanged routed control failed")
            self.assertEqual(baseline.errors, [], label + " unchanged control had harness errors")
            self.assertEqual(baseline.testsRun, 1, label + " unchanged control did not run exactly once")
            CONTROL_RESULTS.append({"mutation": label, "selected_test": selected,
                "baseline": "passed", "tests_run": 1, "errors": 0})
            mutant_source = source.replace(old, new)
            mutant = load(relative, "creation_mutant_" + label,
                mutant_source.encode())
            result = unittest.TestResult()
            with mock.patch.object(sys.modules[__name__], target, mutant):
                CreationContracts(selected).run(result)
            self.assertEqual(result.testsRun, 1, label + " selected test did not run exactly once")
            self.assertEqual(len(result.failures), 1, label + " must fail at one intended assertion")
            self.assertEqual(result.errors, [], label + " produced a harness error")
            marker, signature = markers[label]
            self.assertIn(marker, REACHED, label + " did not reach the named falsifier")
            self.assertIn(signature, result.failures[0][1], label + " failed at an unrelated assertion")
            self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), source_digest,
                label + " changed the source file on disk")
            MUTANTS.append(label)
            MUTANT_RESULTS.append({"name": label, "selected_test": selected,
                "baseline": "passed", "reached": marker, "failure_signature": signature,
                "failures": 1, "errors": 0, "source_unchanged": True})
        CASES.append("source-mutants-killed")


def source_hashes():
    paths = ("tests/fixtures/phase6_game.py", "scripts/release/v02_qualification.py",
        "tests/evidence/phase7_creation_receipts_contract.py", "tests/session/phase6_route_contract.py",
        "scripts/evidence/phase5_process.py")
    return {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}


PRIVACY_PATTERN = re.compile(
    r"/(?:Users|home)/[^\s\"']+|/private/var/[^\s\"']+|"
    r"[A-Za-z]:\\Users\\[^\s\"']+|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9]{20,})\b|"
    r"(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]",
    re.IGNORECASE)


def is_public_text(value):
    return PRIVACY_PATTERN.search(value) is None


def review_pins_match(review_data, source_pins, evidence_hash):
    return (review_data.get("reviewed_source_sha256") == source_pins
        and review_data.get("evidence_sha256") == evidence_hash
        and review_data.get("verdict") == "SECURED"
        and review_data.get("unresolved_high_critical") == 0)


def artifact_mode(write=False, pre_review=False):
    directory = ROOT / ".planning/quick/261029-nzg-prepare-creation-time-durable-receipt-si"
    evidence = directory / "EVIDENCE.json"
    pins = directory / "SOURCE-PINS.json"
    unrelated = {
        ".planning/milestones/v0.1-phases/GW-01-consumable-diagnostic-machine/01-RESEARCH.md": "d0fc7d12bc70a35979f0869297b5148f420bbd2a57ad80813acb88ce688129e2",
        ".planning/state.json": "bfb932cd678bc0f8755f8034de46a7e5f110755d3979a73d263172ce8f177b86",
        ".planning/forensics/report-20261025-191402.md": "2cfd6d09d9735b08ef83f4c1990ceb9dd9e95edf0b29691becadaac2d212d8c1",
        ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-04-red-task1.json": "2f2e94fcb8a2eefa24218fc3257b50056be562e2db5c22948dc9aaafd922620d",
        ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-04-red-task2.json": "bae552109833d97c7571bee5e77c24fce574568a4caf41f02f78b0190a25357a"}
    dirty_now = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in unrelated}
    if dirty_now != unrelated:
        print("unrelated dirty hash mismatch: " + ", ".join(
            path for path in unrelated if dirty_now.get(path) != unrelated[path]), file=sys.stderr); return 1
    if write:
        pin_data = {"schema": "genewhip.phase7-creation-receipts-source-pins.v1",
            "entry_source_sha256": {"tests/fixtures/phase6_game.py": "c39a423dc86071831dcd7f61cb64c8150991bfbdbcecfa1a5a7e8cd9538c42cf",
                "scripts/release/v02_qualification.py": "647b7fee85df5f1facce7329f79feb9a3e2b6e30ac8cf02852a3f339583ff6f7"},
            "sources": source_hashes(), "unrelated_dirty_sha256": unrelated}
        evidence_data = {"schema": "genewhip.phase7-creation-receipts-evidence.v1",
            "contract_cases": sorted(set(CASES)), "mutants_killed": MUTANTS,
            "mutant_results": MUTANT_RESULTS, "unchanged_control_results": CONTROL_RESULTS,
            "fake_owned_calls": len(OWNED_TOTAL), "mutants_expected": 10,
            "tests_run": LAST_RUN["tests_run"], "test_failures": LAST_RUN["failures"],
            "test_errors": LAST_RUN["errors"], "unchanged_controls_expected": 10,
            "independent_control_errors": 0,
            "real_child_starts": 0, "unexpected_denials": denial.receipt()["unexpected_denials"],
            "sticky_denial": denial.receipt(),
            "current_source_sha256": source_hashes(), "historical_identity_liveness": "UNKNOWN",
            "t_07_07": "OPEN/high", "delivery": "halted", "phase7_plan10": "partial",
            "review_status": "pending independent affected-source review"}
        pins.write_text(json.dumps(pin_data, sort_keys=True, indent=2) + "\n")
        evidence.write_text(json.dumps(evidence_data, sort_keys=True, indent=2) + "\n")
        return 0
    if not evidence.is_file() or not pins.is_file():
        print("artifact-verification: missing evidence or source pins", file=sys.stderr); return 1
    data, pin_data = json.loads(evidence.read_text()), json.loads(pins.read_text())
    if (data.get("historical_identity_liveness") != "UNKNOWN" or data.get("delivery") != "halted"
            or data.get("real_child_starts") != 0 or data.get("unexpected_denials") != 0):
        print("artifact-verification: status or exposure mismatch", file=sys.stderr); return 1
    if (data.get("mutants_expected") != 10 or len(data.get("mutant_results", [])) != 10
            or any(row.get("failures") != 1 or row.get("errors") != 0
                or row.get("source_unchanged") is not True for row in data.get("mutant_results", []))
            or data.get("unchanged_controls_expected") != 10
            or len(data.get("unchanged_control_results", [])) != 10
            or any(row.get("baseline") != "passed" or row.get("errors") != 0
                for row in data.get("unchanged_control_results", []))
            or data.get("test_failures") != 0 or data.get("test_errors") != 0):
        print("artifact-verification: contract/mutation denominators incomplete", file=sys.stderr); return 1
    if pin_data.get("sources") != source_hashes() or data.get("current_source_sha256") != source_hashes():
        print("artifact-verification: current source pin mismatch", file=sys.stderr); return 1
    if pin_data.get("unrelated_dirty_sha256") != dirty_now:
        print("artifact-verification: unrelated dirty pin mismatch", file=sys.stderr); return 1
    handoff = directory / "HANDOFF.md"
    if not handoff.is_file() or "T-07-07 remains **OPEN/high**" not in handoff.read_text():
        print("artifact-verification: handoff halt mismatch", file=sys.stderr); return 1
    # Public evidence must stay path/secret safe. Scan the retained initial review
    # as well as the current packet because historical failed evidence is immutable.
    for path in directory.iterdir():
        if path.is_file() and path.suffix in (".json", ".md"):
            if not is_public_text(path.read_text(encoding="utf-8", errors="replace")):
                print("artifact-verification: privacy pattern detected", file=sys.stderr); return 1
    review_data_path = directory / "REVIEW-DATA.json"
    review_report_path = directory / "SECURITY-REVIEW.md"
    if pre_review:
        if data.get("review_status") != "pending independent affected-source review":
            print("artifact-verification: pre-review status mismatch", file=sys.stderr); return 1
        return 0
    if not review_data_path.is_file() or not review_report_path.is_file():
        print("artifact-verification: independent review artifacts missing", file=sys.stderr); return 1
    review_data = json.loads(review_data_path.read_text(encoding="utf-8"))
    current_source_pin = pin_data["sources"]
    current_evidence_hash = hashlib.sha256(evidence.read_bytes()).hexdigest()
    if not review_pins_match(review_data, current_source_pin, current_evidence_hash):
        print("artifact-verification: independent review pins are stale", file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--tracer", action="store_true")
    parser.add_argument("--write-evidence", action="store_true")
    parser.add_argument("--verify-artifacts", action="store_true")
    parser.add_argument("--pre-review", action="store_true",
        help="verify the frozen implementation packet while independent review is pending")
    args = parser.parse_args()
    if args.verify_artifacts:
        raise SystemExit(artifact_mode(pre_review=args.pre_review))
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(CreationContracts))
    LAST_RUN.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors))
    denial.self_test("after-fakes-restored")
    exposure = denial.receipt()
    report = {"tests_run": result.testsRun, "cases": sorted(set(CASES)), "mutants_killed": MUTANTS,
        "fake_owned_calls": len(OWNED_TOTAL), "mutant_runs": len(MUTANT_RESULTS),
        "unchanged_control_runs": len(CONTROL_RESULTS), "exposure": exposure,
        "failures": len(result.failures), "errors": len(result.errors)}
    print(json.dumps(report, sort_keys=True))
    if args.write_evidence and result.wasSuccessful(): artifact_mode(write=True)
    raise SystemExit(0 if result.wasSuccessful() and exposure["unexpected_denials"] == 0 else 1)
