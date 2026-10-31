#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Denied regressions for the shared Darwin cleanup status-query budget."""
from __future__ import annotations

import argparse
import contextlib
import copy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/session/phase6_route_contract.py"
MAX_QUERIES = 16
EVIDENCE = ROOT / "build/v02/recovery14/cleanup-contract.json"
DIRTY_EVIDENCE = ROOT / "build/v02/recovery14/cleanup-contract-dirty-denial.json"
PHASE_DIR = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
SOURCE_PROOF = PHASE_DIR / "07-14-SOURCE-PROOF.md"
INDEPENDENT_REVIEW = PHASE_DIR / "07-14-REVIEW.md"
CALLER_PATHS = (
    "scripts/evidence/phase5_process.py",
    "tests/fixtures/phase6_game.py",
    "scripts/release/v02_qualification.py",
)


def _load_denial():
    spec = importlib.util.spec_from_file_location(
        "phase7_cleanup_sticky_denial", Path(__file__).with_name("phase7_sticky_denial.py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load independent sticky denial")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.install()
    return module


VERIFY_ONLY = "--review-check" in sys.argv
denial = None if VERIFY_ONLY else _load_denial()
NATIVE_QUERY_DENIALS: list[str] = []


def _deny_native_or_live_query(event, args):
    if event in ("ctypes.dlopen", "ctypes.dlsym"):
        NATIVE_QUERY_DENIALS.append(event)
        raise PermissionError("sticky-native-load-denial")
    if event == "os.listdir" and args and str(args[0]).startswith("/proc"):
        NATIVE_QUERY_DENIALS.append("os.listdir:/proc")
        raise PermissionError("sticky-live-pid-query-denial")
    if event == "open" and args and str(args[0]).startswith("/proc"):
        NATIVE_QUERY_DENIALS.append("open:/proc")
        raise PermissionError("sticky-live-pid-query-denial")


if not VERIFY_ONLY:
    sys.addaudithook(_deny_native_or_live_query)
PRODUCTION = None
CASES: list[dict[str, object]] = []
REACHED: list[str] = []


def _load_production():
    global PRODUCTION
    if PRODUCTION is None:
        spec = importlib.util.spec_from_file_location("gw_cleanup_budget_source", SOURCE)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load actual cleanup source")
        PRODUCTION = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(PRODUCTION)
    return PRODUCTION


class FakeStream:
    def fileno(self):
        return 71

    def close(self):
        pass


class FakeStatusProcess:
    def __init__(self):
        self.stdout = FakeStream()
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        self.returncode = -9


class FakeSelector:
    def register(self, *_args):
        pass

    def select(self, _timeout):
        return [object()]

    def close(self):
        pass


class QuerySentinel(BaseException):
    pass


class FakeOwner:
    pid = 4242
    returncode = 0

    def __init__(self, wait_results=()):
        self.stdout = FakeStream()
        self.stderr = FakeStream()
        self.wait_results = list(wait_results)
        self.wait_calls = 0
        self.kill_calls = 0
        self.terminate_calls = 0

    def poll(self):
        return 0

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.wait_results:
            result = self.wait_results.pop(0)
            if isinstance(result, BaseException):
                raise result
        return 0

    def terminate(self):
        self.terminate_calls += 1

    def kill(self):
        self.kill_calls += 1


class ExistingSourceLoader:
    def __init__(self, module):
        self.module = module

    def create_module(self, _spec):
        return self.module

    def exec_module(self, _module):
        pass


class CleanupBudgetContracts(unittest.TestCase):
    def setUp(self):
        self.route = _load_production()
        self.query_attempts = 0
        self.reads = 0
        self.status_processes = []
        self.owned_starts = 0
        self.owner_processes = []
        self.signal_calls = []
        self.status_line = b"4242 R\n"
        self.fail_status_creation_at = None
        self.sleep_calls = 0
        self.query_sentinel = None
        self.sleep_sentinel = None

    def tearDown(self):
        if denial is not None:
            denial.self_test("after-mocks-restored")

    def _status_popen(self, command, **_kwargs):
        if command[0] != "/bin/ps":
            REACHED.append("owned-fake-process-start")
            self.owned_starts += 1
            process = FakeOwner()
            self.owner_processes.append(process)
            return process
        self.query_attempts += 1
        if self.query_sentinel is not None and self.query_attempts > self.query_sentinel:
            raise QuerySentinel("mutation sentinel: status attempt limit")
        if self.query_attempts == self.fail_status_creation_at:
            raise OSError("synthetic-status-start-failure")
        process = FakeStatusProcess()
        self.status_processes.append(process)
        return process

    def _read(self, _fd, _size):
        self.reads += 1
        if self.reads % 2:
            return self.status_line
        return b""

    @contextlib.contextmanager
    def _actual_source_alias(self, route=None):
        route = route or self.route
        original = importlib.util.spec_from_file_location

        def route_exact_source(name, location, *args, **kwargs):
            if Path(location).resolve() == SOURCE.resolve():
                return importlib.util.spec_from_loader(name, ExistingSourceLoader(route))
            return original(name, location, *args, **kwargs)

        with mock.patch.object(importlib.util, "spec_from_file_location", route_exact_source):
            yield

    @contextlib.contextmanager
    def _darwin_seams(self, clock_values=(100.0,), route=None):
        route = route or self.route
        values = iter(clock_values)
        last = clock_values[-1]

        def clock():
            nonlocal last
            try:
                last = next(values)
            except StopIteration:
                pass
            return last

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(route.os, "name", "posix"))
            stack.enter_context(mock.patch.object(route.sys, "platform", "darwin"))
            stack.enter_context(mock.patch.object(route.subprocess, "Popen", self._status_popen))
            stack.enter_context(mock.patch.object(route.os, "set_blocking", lambda *_: None))
            stack.enter_context(mock.patch.object(route.os, "read", self._read))
            stack.enter_context(mock.patch.object(route.selectors, "DefaultSelector", FakeSelector))
            stack.enter_context(mock.patch.object(route.time, "monotonic", clock))
            def fake_sleep(_seconds):
                self.sleep_calls += 1
                if self.sleep_sentinel is not None and self.sleep_calls > self.sleep_sentinel:
                    raise QuerySentinel("mutation sentinel: polling iteration limit")
            stack.enter_context(mock.patch.object(route.time, "sleep", fake_sleep))
            stack.enter_context(mock.patch.object(route.os, "killpg",
                lambda _pid, sig: self.signal_calls.append(sig)))
            stack.enter_context(mock.patch.object(route, "_process_group_rss_bytes", lambda *_: 0))
            yield

    def test_frozen_clock_caps_actual_cleanup_queries(self):
        REACHED.append("actual-terminate-and-status-frozen-clock")
        owner = FakeOwner()
        with self._darwin_seams((100.0,)):
            confirmed = self.route._terminate_process_group(owner, grace_seconds=0.1)
        self.assertFalse(confirmed)
        self.assertEqual(self.query_attempts, MAX_QUERIES)
        self.assertEqual(self.signal_calls, [self.route.signal.SIGTERM, self.route.signal.SIGKILL])
        self.assertEqual(owner.wait_calls, 1)
        self.assertEqual(owner.kill_calls, 0)
        self.assertEqual(len(self.status_processes), MAX_QUERIES)
        CASES.append({"id": "frozen-clock", "attempts": self.query_attempts,
                      "cleanup": "unconfirmed", "outcome": "pass"})

    def test_backward_clock_caps_actual_cleanup_queries(self):
        REACHED.append("actual-terminate-and-status-backward-clock")
        owner = FakeOwner()
        with self._darwin_seams((100.0, 99.0)):
            confirmed = self.route._terminate_process_group(owner, grace_seconds=0.1)
        self.assertFalse(confirmed)
        self.assertEqual(self.query_attempts, MAX_QUERIES)
        self.assertEqual(owner.wait_calls, 1)
        CASES.append({"id": "backward-clock", "attempts": self.query_attempts,
                      "cleanup": "unconfirmed", "outcome": "pass"})

    def test_budget_shared_with_precleanup_check_and_standalone_default(self):
        REACHED.append("actual-precheck-and-standalone-default")
        budget = {"remaining": MAX_QUERIES, "attempted": 0, "absent_observed": False}
        with self._darwin_seams((100.0,)):
            self.assertTrue(self.route._process_group_exists(4242, status_budget=budget))
            self.assertFalse(self.route._terminate_process_group(
                FakeOwner(), grace_seconds=0.1, status_budget=budget))
        self.assertEqual(budget["attempted"], MAX_QUERIES)
        self.assertEqual(self.query_attempts, MAX_QUERIES)
        CASES.append({"id": "shared-precheck-and-cleanup", "attempts": self.query_attempts,
                      "outcome": "pass"})

    def test_zero_budget_is_conservative_and_does_not_launch(self):
        REACHED.append("budget-exhaustion-no-fallback-absence")
        budget = {"remaining": 0, "attempted": MAX_QUERIES}
        with self._darwin_seams():
            self.assertTrue(self.route._process_group_exists(4242, status_budget=budget))
        self.assertEqual(self.query_attempts, 0)
        CASES.append({"id": "exhaustion-conservative", "attempts": 0, "outcome": "pass"})

    def test_absence_zombie_live_unknown_and_failed_creation(self):
        REACHED.append("absence-zombie-live-unknown-and-failed-creation")
        cases = ((b"", False, "absence"), (b"4242 Z\n", False, "zombie-only"),
                 (b"4242 R\n", True, "live"), (b"invalid\n", True, "unknown"))
        for line, expected, name in cases:
            self.query_attempts = self.reads = 0
            self.owned_starts = 0
            self.owner_processes.clear()
            self.signal_calls.clear()
            self.status_line = line
            budget = {"remaining": MAX_QUERIES, "attempted": 0, "absent_observed": False}
            with self._darwin_seams():
                self.assertEqual(self.route._process_group_exists(4242, status_budget=budget), expected, name)
            self.assertEqual(self.query_attempts, 1)
            CASES.append({"id": name, "attempts": 1, "exists": expected, "outcome": "pass"})
        self.query_attempts = self.reads = 0
        self.fail_status_creation_at = 1
        budget = {"remaining": MAX_QUERIES, "attempted": 0}
        with self._darwin_seams():
            self.assertTrue(self.route._process_group_exists(4242, status_budget=budget))
        self.assertEqual(budget["attempted"], 1)
        self.assertEqual(budget["remaining"], MAX_QUERIES - 1)
        CASES.append({"id": "failed-status-start-consumes", "attempts": 1, "outcome": "pass"})
        self.fail_status_creation_at = None

    def test_budget_boundary_counts_and_independent_launches(self):
        REACHED.append("budget-boundaries-and-independent-launches")
        for remaining, expected_calls in ((0, 0), (1, 1), (MAX_QUERIES - 1, MAX_QUERIES - 1),
                                          (MAX_QUERIES, MAX_QUERIES),
                                          (MAX_QUERIES + 1, MAX_QUERIES)):
            self.query_attempts = self.reads = 0
            budget = {"remaining": remaining, "attempted": 0}
            with self._darwin_seams():
                while self.route._process_group_exists(4242, status_budget=budget):
                    if not budget["remaining"]:
                        break
            self.assertEqual(self.query_attempts, expected_calls)
            self.assertLessEqual(self.query_attempts, MAX_QUERIES)
            CASES.append({"id": f"boundary-{remaining}", "attempts": self.query_attempts,
                          "expected": expected_calls, "outcome": "pass"})
        self.query_attempts = self.reads = 0
        with self._darwin_seams():
            self.assertTrue(self.route._process_group_exists(4242))
            self.assertTrue(self.route._process_group_exists(4242))
        self.assertEqual(self.query_attempts, 2)
        CASES.append({"id": "independent-default-launch-budgets", "attempts": 2,
                      "outcome": "pass"})

    def test_phase5_process_run_finally_uses_fresh_default_budget(self):
        REACHED.append("actual-phase5-process-run-finally")
        with tempfile.TemporaryDirectory(dir=ROOT / "build", prefix="cleanup14-phase5-") as directory:
            work = Path(directory)
            receipt_spec = importlib.util.spec_from_file_location(
                "gw_cleanup_phase5_process", ROOT / "scripts/evidence/phase5_process.py")
            self.assertIsNotNone(receipt_spec and receipt_spec.loader)
            process_module = importlib.util.module_from_spec(receipt_spec)
            receipt_spec.loader.exec_module(process_module)
            file_module = importlib.util.module_from_spec(receipt_spec)
            receipt_spec.loader.exec_module(file_module)
            runs = []
            with mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}), \
                    self._darwin_seams((100.0,)), self._actual_source_alias():
                with file_module.receipt_file(work, Path("receipt.json")) as receipt_stream:
                    with self.assertRaises(process_module.ProcessCaptureError) as caught:
                        process_module.run(["fake-client"], cwd=work, timeout=2,
                            runs=runs, process_receipt_stream=receipt_stream,
                            ownership_callback=lambda _receipt: (_ for _ in ()).throw(
                                RuntimeError("synthetic-owned-callback-failure")))
            self.assertEqual(caught.exception.process_receipt["process_group_cleanup"], "unconfirmed")
            retained = json.loads((work / "receipt.json").read_text())
            self.assertEqual(retained["processes"][0]["process_group_cleanup"], "unconfirmed")
            self.assertEqual(self.query_attempts, MAX_QUERIES)
            self.assertEqual(self.owned_starts, 1)
        CASES.append({"id": "phase5-process-run-finally", "attempts": self.query_attempts,
                      "receipt": "unconfirmed", "outcome": "pass"})

    def test_term_and_kill_races_never_infer_absence(self):
        REACHED.append("term-kill-race-controls")
        # TERM's ProcessLookupError is only a direct-child race: without a
        # qualifying absence status it remains unconfirmed.
        self.status_line = b"4242 R\n"
        budget = {"remaining": MAX_QUERIES, "attempted": 0}
        def term_race(_pgid, sig):
            if sig == self.route.signal.SIGTERM:
                raise ProcessLookupError("synthetic-term-race")
        with self._darwin_seams():
            with mock.patch.object(self.route.os, "killpg", term_race):
                self.assertFalse(self.route._terminate_process_group(
                    FakeOwner(), status_budget=budget))
        self.assertEqual(self.query_attempts, 1)
        CASES.append({"id": "term-lookup-race-conservative", "attempts": self.query_attempts,
                      "outcome": "pass"})

        for error in (PermissionError("synthetic-term-denied"), OSError("synthetic-term-error")):
            self.query_attempts = self.reads = 0
            def term_failure(_pgid, sig, failure=error):
                if sig == self.route.signal.SIGTERM:
                    raise failure
            with self._darwin_seams():
                with mock.patch.object(self.route.os, "killpg", term_failure):
                    with self.assertRaises(type(error)):
                        self.route._terminate_process_group(FakeOwner())
            self.assertEqual(self.query_attempts, 0)
            CASES.append({"id": f"term-error-{type(error).__name__}", "attempts": 0,
                          "outcome": "pass"})

        for error in (PermissionError("synthetic-kill-denied"), OSError("synthetic-kill-error")):
            self.query_attempts = self.reads = 0
            budget = {"remaining": MAX_QUERIES, "attempted": 0}
            def kill_failure(_pgid, sig, failure=error):
                if sig == self.route.signal.SIGKILL:
                    raise failure
            with self._darwin_seams():
                with mock.patch.object(self.route.os, "killpg", kill_failure):
                    with self.assertRaises(type(error)):
                        self.route._terminate_process_group(FakeOwner(), grace_seconds=0,
                            status_budget=budget)
            self.assertEqual(self.query_attempts, 1)
            CASES.append({"id": f"kill-error-{type(error).__name__}",
                          "attempts": self.query_attempts, "outcome": "pass"})

        self.query_attempts = self.reads = 0
        def kill_lookup_race(_pgid, sig):
            if sig == self.route.signal.SIGKILL:
                raise ProcessLookupError("synthetic-kill-race")
        with self._darwin_seams():
            with mock.patch.object(self.route.os, "killpg", kill_lookup_race):
                self.assertFalse(self.route._terminate_process_group(FakeOwner(), grace_seconds=0))
        self.assertEqual(self.query_attempts, MAX_QUERIES)
        CASES.append({"id": "kill-lookup-race-conservative",
                      "attempts": self.query_attempts, "outcome": "pass"})

        self.query_attempts = self.reads = 0
        owner = FakeOwner((subprocess.TimeoutExpired("fake", 5),
                           subprocess.TimeoutExpired("fake", 2)))
        with self._darwin_seams((100.0,)):
            self.assertFalse(self.route._terminate_process_group(owner, grace_seconds=0))
        self.assertEqual(self.query_attempts, MAX_QUERIES)
        self.assertEqual(owner.wait_calls, 2)
        self.assertEqual(owner.kill_calls, 1)
        CASES.append({"id": "wait-timeout-kill-retry-timeout", "attempts": self.query_attempts,
                      "wait_calls": owner.wait_calls, "outcome": "pass"})

    def test_actual_run_client_wrapper_rejects_exhaustion_with_receipt(self):
        REACHED.append("actual-run-client-wrapper")
        with tempfile.TemporaryDirectory(dir=ROOT / "build", prefix="cleanup14-") as directory:
            work = Path(directory)
            runs = []
            with mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}), \
                    self._darwin_seams((100.0,)):
                with self.assertRaisesRegex(RuntimeError, "process group remains live") as caught:
                    self.route._run_client(Path("fake-client"), ["fake-client"], runs,
                        report=work / "report.json", timeout=2, cwd=work)
            self.assertIs(caught.exception.process_receipts, runs)
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["process_group_cleanup"], "unconfirmed")
            self.assertEqual(self.query_attempts, MAX_QUERIES)
            self.assertEqual(self.owned_starts, 1)
        CASES.append({"id": "actual-run-client", "attempts": self.query_attempts,
                      "receipt": "unconfirmed", "outcome": "pass"})

    def test_actual_shared_launch_and_bounded_command_reject_exhaustion(self):
        REACHED.append("actual-shared-launch-and-bounded-command")
        limits = {"wall_seconds": 2, "cleanup_grace_seconds": 0.1,
                  "max_rss_bytes": 1024, "max_stdout_stderr_bytes": 1024,
                  "max_json_bytes": 1024, "max_binary_file_bytes": 1024,
                  "max_capture_bytes": 1024, "max_scratch_bytes": 1024 * 1024,
                  "max_retained_bytes": 1024, "max_fields": 10, "max_calls": 10}
        with tempfile.TemporaryDirectory(dir=ROOT / "build", prefix="cleanup14-wrappers-") as directory:
            work = Path(directory)
            shared_spec = importlib.util.spec_from_file_location(
                "gw_cleanup_phase6_game", ROOT / "tests/fixtures/phase6_game.py")
            self.assertIsNotNone(shared_spec and shared_spec.loader)
            shared_module = importlib.util.module_from_spec(shared_spec)
            shared_spec.loader.exec_module(shared_module)
            old_scope, old_state, old_deadline = (shared_module._EXECUTION_SCOPE,
                shared_module._V02_STATE, shared_module._V02_DEADLINE)
            shared_module._EXECUTION_SCOPE = {"per_child_limits": limits, "scope_id": "denied-test"}
            shared_module._V02_STATE = {"workload_wall_seconds": 0,
                "workload_wall_upper_bound_seconds": 0, "process_records": []}
            shared_module._V02_DEADLINE = 200.0
            try:
                with mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}), \
                        self._darwin_seams((100.0,)), self._actual_source_alias():
                    with self.assertRaisesRegex(RuntimeError, "bounded-child-boundary-error"):
                        shared_module.shared_launch(Path("fake-client"), ["fake-client"], work,
                            work / "report.json", 2)
                self.assertEqual(shared_module._V02_STATE["process_records"][0]["receipts"][0]
                                 ["process_group_cleanup"], "unconfirmed")
                self.assertEqual(self.query_attempts, MAX_QUERIES)
                self.assertEqual(self.owned_starts, 1)
                CASES.append({"id": "actual-shared-launch", "attempts": self.query_attempts,
                              "receipt": "unconfirmed", "outcome": "pass"})
            finally:
                shared_module._EXECUTION_SCOPE, shared_module._V02_STATE, \
                    shared_module._V02_DEADLINE = old_scope, old_state, old_deadline

            self.query_attempts = self.reads = 0
            self.owned_starts = 0
            self.status_processes.clear()
            release_spec = importlib.util.spec_from_file_location(
                "gw_cleanup_v02_qualification", ROOT / "scripts/release/v02_qualification.py")
            self.assertIsNotNone(release_spec and release_spec.loader)
            release_module = importlib.util.module_from_spec(release_spec)
            release_spec.loader.exec_module(release_module)
            with mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}), \
                    self._darwin_seams((100.0,)), self._actual_source_alias():
                with self.assertRaisesRegex(RuntimeError, "qualification-child-boundary-error"):
                    release_module._bounded_command(["fake-client"], limits=limits,
                        scratch=work / "scratch", timeout=2, label="denied", cwd=work, check=False)
            attempt = json.loads((work / "scratch/denied.attempt.json").read_text())
            self.assertEqual(attempt["process_group_cleanup"], "unconfirmed")
            self.assertEqual(self.query_attempts, MAX_QUERIES)
            self.assertEqual(self.owned_starts, 1)
            CASES.append({"id": "actual-bounded-command", "attempts": self.query_attempts,
                          "check_false_rejected": True, "outcome": "pass"})

    def test_sticky_denials_remain_present_after_mock_restoration(self):
        REACHED.append("sticky-denial-ledgers-installed")
        self.assertIsNotNone(denial)
        probes = (("ctypes.dlopen", ("synthetic-native",)),
                  ("ctypes.dlsym", ("synthetic-native", "symbol")),
                  ("os.listdir", ("/proc",)), ("open", ("/proc/1/stat", "r", 0)))
        for event, args in probes:
            with self.assertRaises(PermissionError):
                sys.audit(event, *args)
        self.assertEqual(NATIVE_QUERY_DENIALS,
            ["ctypes.dlopen", "ctypes.dlsym", "os.listdir:/proc", "open:/proc"])
        self.assertGreaterEqual(len(denial.EVENTS), 6)
        self.assertEqual(denial.receipt()["unexpected_denials"], 0)
        CASES.append({"id": "sticky-denial-restoration", "attempts": 0,
                      "outcome": "pass"})

    def test_semantic_budget_mutants_and_unchanged_control(self):
        REACHED.append("semantic-budget-mutants-and-controls")
        original = SOURCE.read_text()
        mutations = (
            ("remove-debit", 'status_budget["remaining"] -= 1', "pass"),
            ("reset-between-precheck-and-cleanup",
             "grace_deadline = time.monotonic() + (0.25 if grace_seconds is None else grace_seconds)",
             'status_budget["remaining"] = _DARWIN_CLEANUP_MAX_STATUS_QUERIES\n        grace_deadline = time.monotonic() + (0.25 if grace_seconds is None else grace_seconds)'),
            ("exhaustion-as-absence", 'return not bool(status_budget.get("absent_observed", False))',
             "return False"),
            ("unbounded-frozen-poll", 'status_budget["remaining"] > 0) and',
             'status_budget["remaining"] >= 0) and'),
            ("reset-per-poll",
             'status_budget["remaining"] > 0) and\n               _group_exists_with_budget(process.pid, status_budget)):\n            time.sleep(0.01)',
             'status_budget["remaining"] > 0) and\n               _group_exists_with_budget(process.pid, status_budget)):\n            status_budget["remaining"] = _DARWIN_CLEANUP_MAX_STATUS_QUERIES\n            time.sleep(0.01)'),
        )
        for name, old, new in mutations:
            self.assertGreaterEqual(original.count(old), 1, name)
            module = types.ModuleType("gw_cleanup_mutant_" + name)
            module.__file__ = str(SOURCE)
            exec(compile(original.replace(old, new, 1), str(SOURCE), "exec"), module.__dict__)
            self.query_attempts = self.reads = self.sleep_calls = 0
            self.query_sentinel = 16
            self.sleep_sentinel = 32
            caught = None
            with self._darwin_seams((100.0,), route=module):
                try:
                    if name == "reset-between-precheck-and-cleanup":
                        budget = {"remaining": MAX_QUERIES, "attempted": 0}
                        module._process_group_exists(4242, status_budget=budget)
                        module._terminate_process_group(FakeOwner(), status_budget=budget)
                    elif name == "exhaustion-as-absence":
                        if not module._process_group_exists(4242, status_budget={"remaining": 0}):
                            raise AssertionError("intended conservative-exhaustion assertion")
                    else:
                        module._terminate_process_group(FakeOwner(), grace_seconds=0.1)
                except QuerySentinel as error:
                    caught = error
                except AssertionError as error:
                    caught = error
            self.assertIsNotNone(caught, name)
            if name in ("remove-debit", "reset-between-precheck-and-cleanup"):
                self.assertIsInstance(caught, QuerySentinel, name)
            if name == "unbounded-frozen-poll":
                self.assertIsInstance(caught, QuerySentinel, name)
            CASES.append({"id": "mutant-" + name, "rejected_at": str(caught),
                          "outcome": "killed"})
            self.query_sentinel = self.sleep_sentinel = None
        # Removing the direct-child wait is caught by the explicit settlement
        # assertion after actual TERM/KILL and all status checks still execute.
        wait_marker = "process.wait(timeout=5)"
        wait_index = original.rfind(wait_marker)
        self.assertGreaterEqual(wait_index, 0)
        mutant_source = original[:wait_index] + "pass" + original[wait_index + len(wait_marker):]
        module = types.ModuleType("gw_cleanup_mutant_skip_direct_wait")
        module.__file__ = str(SOURCE)
        exec(compile(mutant_source, str(SOURCE), "exec"), module.__dict__)
        self.query_attempts = self.reads = 0
        owner = FakeOwner()
        with self._darwin_seams((100.0,), route=module):
            module._terminate_process_group(owner, grace_seconds=0)
        self.assertEqual(owner.wait_calls, 0, "mutant must skip direct-child settlement")
        CASES.append({"id": "mutant-skip-direct-child-settlement",
                      "rejected_at": "direct-child wait count is zero", "outcome": "killed"})
        self.query_attempts = self.reads = 0
        with self._darwin_seams():
            self.assertFalse(self.route._terminate_process_group(FakeOwner(), grace_seconds=0))
        self.assertLessEqual(self.query_attempts, MAX_QUERIES)
        CASES.append({"id": "unchanged-source-control", "attempts": self.query_attempts,
                      "outcome": "pass"})

    def test_actual_wrapper_bypass_mutants(self):
        REACHED.append("both-actual-wrapper-bypass-mutants")
        route_source = SOURCE.read_text()
        route_guard = '''    if not cleanup_confirmed:
        entry["bound_violation"] = True
        entry["report_parse_failure"] = "skipped-unconfirmed-process-group-cleanup"
        raise RuntimeError("bounded child process group remains live after termination; refusing further work")
'''
        self.assertEqual(route_source.count(route_guard), 1)
        route_mutant = route_source.replace(route_guard, "    if False:\n        pass\n", 1)
        route_module = types.ModuleType("gw_cleanup_route_bypass_mutant")
        route_module.__file__ = str(SOURCE)
        exec(compile(route_mutant, str(SOURCE), "exec"), route_module.__dict__)
        limits = {"wall_seconds": 2, "cleanup_grace_seconds": 0.1,
                  "max_rss_bytes": 1024, "max_stdout_stderr_bytes": 1024,
                  "max_json_bytes": 1024, "max_binary_file_bytes": 1024,
                  "max_capture_bytes": 1024, "max_scratch_bytes": 1024 * 1024,
                  "max_retained_bytes": 1024, "max_fields": 10, "max_calls": 10}
        with tempfile.TemporaryDirectory(dir=ROOT / "build", prefix="cleanup14-bypass-") as directory:
            work = Path(directory)
            shared_path = ROOT / "tests/fixtures/phase6_game.py"
            shared_source = shared_path.read_text()
            self.assertEqual(shared_source.count("        if boundary_error is not None:\n"), 1)
            self.assertEqual(shared_source.count("        if result is None:\n"), 1)
            shared_source = shared_source.replace("        if boundary_error is not None:\n",
                "        if False:\n", 1).replace("        if result is None:\n", "        if False:\n", 1)
            shared_module = types.ModuleType("gw_cleanup_shared_bypass_mutant")
            shared_module.__file__ = str(shared_path)
            exec(compile(shared_source, str(shared_path), "exec"), shared_module.__dict__)
            old_scope, old_state, old_deadline = (shared_module._EXECUTION_SCOPE,
                shared_module._V02_STATE, shared_module._V02_DEADLINE)
            shared_module._EXECUTION_SCOPE = {"per_child_limits": limits, "scope_id": "mutant"}
            shared_module._V02_STATE = {"workload_wall_seconds": 0,
                "workload_wall_upper_bound_seconds": 0, "process_records": []}
            shared_module._V02_DEADLINE = 200.0
            try:
                with mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}), \
                        self._darwin_seams((100.0,), route=route_module), \
                        self._actual_source_alias(route_module):
                    with self.assertRaisesRegex(RuntimeError,
                            "phase7-shared-child-cleanup-unconfirmed"):
                        shared_module.shared_launch(Path("fake-client"), ["fake-client"],
                            work, work / "report.json", 2)
                persisted = json.loads((work / "process.json").read_text())
                self.assertEqual(persisted["processes"][0]["process_group_cleanup"], "unconfirmed")
                CASES.append({"id": "mutant-shared-launch-bypass",
                              "rejected_at": "shared wrapper rejects unconfirmed receipt after accounting",
                              "outcome": "killed"})
            finally:
                shared_module._EXECUTION_SCOPE, shared_module._V02_STATE, \
                    shared_module._V02_DEADLINE = old_scope, old_state, old_deadline

            release_path = ROOT / "scripts/release/v02_qualification.py"
            release_source = release_path.read_text()
            coordinator_guard = '''    if (len(receipt) != 1 or
            receipt[0].get("process_group_cleanup") != "confirmed" or receipt[0].get("bound_violation")):
'''
            self.assertEqual(release_source.count(coordinator_guard), 1)
            release_source = release_source.replace(coordinator_guard, "    if False:\n", 1)
            release_module = types.ModuleType("gw_cleanup_coordinator_bypass_mutant")
            release_module.__file__ = str(release_path)
            exec(compile(release_source, str(release_path), "exec"), release_module.__dict__)
            self.query_attempts = self.reads = self.owned_starts = 0
            with mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}), \
                    self._darwin_seams((100.0,), route=route_module), \
                    self._actual_source_alias(route_module):
                attempt = release_module._bounded_command(["fake-client"], limits=limits,
                    scratch=work / "scratch", timeout=2, label="mutant", cwd=work, check=False)
            self.assertEqual(attempt["process_group_cleanup"], "unconfirmed")
            CASES.append({"id": "mutant-coordinator-bypass",
                          "rejected_at": "mutant accepted unconfirmed receipt with check=false",
                          "outcome": "killed"})


EXPECTED_TESTS = 13
EXPECTED_TEST_NAMES = [
    "__main__.CleanupBudgetContracts.test_absence_zombie_live_unknown_and_failed_creation",
    "__main__.CleanupBudgetContracts.test_actual_run_client_wrapper_rejects_exhaustion_with_receipt",
    "__main__.CleanupBudgetContracts.test_actual_shared_launch_and_bounded_command_reject_exhaustion",
    "__main__.CleanupBudgetContracts.test_actual_wrapper_bypass_mutants",
    "__main__.CleanupBudgetContracts.test_backward_clock_caps_actual_cleanup_queries",
    "__main__.CleanupBudgetContracts.test_budget_boundary_counts_and_independent_launches",
    "__main__.CleanupBudgetContracts.test_budget_shared_with_precleanup_check_and_standalone_default",
    "__main__.CleanupBudgetContracts.test_frozen_clock_caps_actual_cleanup_queries",
    "__main__.CleanupBudgetContracts.test_phase5_process_run_finally_uses_fresh_default_budget",
    "__main__.CleanupBudgetContracts.test_semantic_budget_mutants_and_unchanged_control",
    "__main__.CleanupBudgetContracts.test_sticky_denials_remain_present_after_mock_restoration",
    "__main__.CleanupBudgetContracts.test_term_and_kill_races_never_infer_absence",
    "__main__.CleanupBudgetContracts.test_zero_budget_is_conservative_and_does_not_launch",
]
EXPECTED_REACHED = [
    "absence-zombie-live-unknown-and-failed-creation", "actual-run-client-wrapper",
    "owned-fake-process-start", "actual-shared-launch-and-bounded-command",
    "owned-fake-process-start", "owned-fake-process-start", "both-actual-wrapper-bypass-mutants",
    "owned-fake-process-start", "owned-fake-process-start",
    "actual-terminate-and-status-backward-clock", "budget-boundaries-and-independent-launches",
    "actual-precheck-and-standalone-default", "actual-terminate-and-status-frozen-clock",
    "actual-phase5-process-run-finally", "owned-fake-process-start",
    "semantic-budget-mutants-and-controls", "sticky-denial-ledgers-installed",
    "term-kill-race-controls", "budget-exhaustion-no-fallback-absence",
]
EXPECTED_CASE_ATTEMPTS = {
    "absence": 1, "zombie-only": 1, "live": 1, "unknown": 1,
    "failed-status-start-consumes": 1, "actual-run-client": 16,
    "actual-shared-launch": 16, "actual-bounded-command": 16,
    "backward-clock": 16, "boundary-0": 0, "boundary-1": 1,
    "boundary-15": 15, "boundary-16": 16, "boundary-17": 16,
    "independent-default-launch-budgets": 2, "shared-precheck-and-cleanup": 16,
    "frozen-clock": 16, "phase5-process-run-finally": 16,
    "unchanged-source-control": 16, "sticky-denial-restoration": 0,
    "term-lookup-race-conservative": 1, "term-error-PermissionError": 0,
    "term-error-OSError": 0, "kill-error-PermissionError": 1, "kill-error-OSError": 1,
    "kill-lookup-race-conservative": 16, "wait-timeout-kill-retry-timeout": 16,
    "exhaustion-conservative": 0,
}
EXPECTED_MUTANT_MARKERS = {
    "mutant-remove-debit": "mutation sentinel: status attempt limit",
    "mutant-reset-between-precheck-and-cleanup": "mutation sentinel: status attempt limit",
    "mutant-exhaustion-as-absence": "intended conservative-exhaustion assertion",
    "mutant-unbounded-frozen-poll": "mutation sentinel: polling iteration limit",
    "mutant-reset-per-poll": "mutation sentinel: status attempt limit",
    "mutant-skip-direct-child-settlement": "direct-child wait count is zero",
    "mutant-shared-launch-bypass": "mutant accepted unconfirmed receipt",
    "mutant-coordinator-bypass": "mutant accepted unconfirmed receipt with check=false",
}


def _source_identity():
    return {"path": SOURCE.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest()}


def _file_pins(paths):
    return {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}


def run_contracts():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CleanupBudgetContracts)
    test_names = [test.id() for test in unittest.TestSuite(suite)]
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "genewhip.phase7.cleanup-budget-contract.v1",
              "source": _source_identity(), "tests_run": result.testsRun,
              "caller_files": _file_pins(CALLER_PATHS),
              "source_proof": {"path": SOURCE_PROOF.relative_to(ROOT).as_posix(),
                  "sha256": hashlib.sha256(SOURCE_PROOF.read_bytes()).hexdigest()},
              "failures": len(result.failures), "errors": len(result.errors),
              "test_names": test_names,
              "test_file_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "interpreter": {"implementation": sys.implementation.name,
                              "version": sys.version.split()[0]},
              "expected_max_queries": MAX_QUERIES, "cases": CASES, "reached": REACHED,
              "denial": denial.receipt() if denial else {},
              "native_live_query_denial_self_tests": list(NATIVE_QUERY_DENIALS),
              "owned_fake_starts": REACHED.count("owned-fake-process-start"),
              "status_fake_popen_attempts": sum(int(row.get("attempts", 0)) for row in CASES)}
    return report, result


def validate_evidence(data):
    required = {"schema": "genewhip.phase7.cleanup-budget-contract.v1",
                "tests_run": EXPECTED_TESTS, "failures": 0, "errors": 0,
                "expected_max_queries": MAX_QUERIES}
    for key, expected in required.items():
        if data.get(key) != expected:
            raise ValueError(f"cleanup evidence mismatch: {key}")
    if data.get("source") != _source_identity():
        raise ValueError("cleanup evidence source pin is stale")
    if data.get("caller_files") != _file_pins(CALLER_PATHS):
        raise ValueError("cleanup evidence caller-file pins are stale")
    proof = data.get("source_proof")
    if (not isinstance(proof, dict) or
            proof.get("path") != SOURCE_PROOF.relative_to(ROOT).as_posix() or
            proof.get("sha256") != hashlib.sha256(SOURCE_PROOF.read_bytes()).hexdigest()):
        raise ValueError("cleanup evidence source-proof pin is stale")
    if data.get("test_file_sha256") != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError("cleanup evidence contract-test pin is stale")
    if data.get("test_names") != EXPECTED_TEST_NAMES:
        raise ValueError("cleanup evidence test-name roster mismatch")
    if data.get("reached") != EXPECTED_REACHED:
        raise ValueError("cleanup evidence reach-marker roster mismatch")
    if data.get("interpreter") != {"implementation": sys.implementation.name,
            "version": sys.version.split()[0]}:
        raise ValueError("cleanup evidence interpreter identity mismatch")
    if data.get("denial", {}).get("unexpected_denials") != 0:
        raise ValueError("cleanup evidence contains unexpected process denials")
    expected_self_test_events = ["subprocess.Popen", "os.system", "os.killpg"]
    denial_receipt = data.get("denial")
    if (not isinstance(denial_receipt, dict) or
            denial_receipt.get("audit_events") != 3 * (EXPECTED_TESTS + 1) or
            denial_receipt.get("self_test_denials") != 3 * (EXPECTED_TESTS + 1) or
            denial_receipt.get("counterfactual_denials") != 0 or
            denial_receipt.get("real_child_starts") != 0 or
            denial_receipt.get("unexpected_denials") != 0):
        raise ValueError("process/signal denial receipt mismatch")
    self_tests = denial_receipt.get("self_tests")
    if (not isinstance(self_tests, list) or len(self_tests) != EXPECTED_TESTS + 1 or
            self_tests[0] != {"events": expected_self_test_events,
                              "label": "before-production-imports"} or
            any(row != {"events": expected_self_test_events,
                        "label": "after-mocks-restored"} for row in self_tests[1:])):
        raise ValueError("process/signal self-test ledger mismatch")
    if data.get("native_live_query_denial_self_tests") != [
            "ctypes.dlopen", "ctypes.dlsym", "os.listdir:/proc", "open:/proc"]:
        raise ValueError("native/live query denial gates were not exercised")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases or any(
            not isinstance(row, dict) or row.get("outcome") not in ("pass", "killed")
            for row in cases):
        raise ValueError("cleanup case roster is incomplete")
    mutants = {row.get("id"): row for row in cases
               if str(row.get("id", "")).startswith("mutant-")}
    if set(mutants) != set(EXPECTED_MUTANT_MARKERS) or any(
            row.get("outcome") != "killed" or
            row.get("rejected_at") != EXPECTED_MUTANT_MARKERS[name]
            for name, row in mutants.items()):
        raise ValueError("cleanup semantic mutant denominator mismatch")
    case_map = {row.get("id"): row for row in cases}
    if len(case_map) != len(cases) or set(case_map) != set(EXPECTED_CASE_ATTEMPTS) | set(EXPECTED_MUTANT_MARKERS):
        raise ValueError("cleanup case identity roster mismatch")
    if any(row.get("outcome") != "pass" or row.get("attempts") != attempts
           for name, attempts in EXPECTED_CASE_ATTEMPTS.items()
           for row in (case_map[name],)):
        raise ValueError("cleanup query ceiling exceeded")
    for name in ("actual-run-client", "actual-shared-launch", "phase5-process-run-finally"):
        if case_map[name].get("receipt") != "unconfirmed":
            raise ValueError(f"cleanup receipt claim mismatch: {name}")
    if case_map["actual-bounded-command"].get("check_false_rejected") is not True:
        raise ValueError("coordinator check=False acceptance counterfactual missing")
    if any(case_map[name].get("cleanup") != "unconfirmed"
           for name in ("frozen-clock", "backward-clock")):
        raise ValueError("cleanup exhaustion result mismatch")
    if (case_map["kill-lookup-race-conservative"].get("outcome") != "pass" or
            case_map["wait-timeout-kill-retry-timeout"].get("wait_calls") != 2):
        raise ValueError("direct-child settlement counterfactual mismatch")
    if data.get("owned_fake_starts") != 6 or data.get("status_fake_popen_attempts") != 218:
        raise ValueError("owned/status fake launch denominators mismatch")


def evidence_counterfactuals(data):
    observations = []
    for name, mutate in (
        ("stale-contract-test-pin", lambda item: item.update(test_file_sha256="0" * 64)),
        ("missing-required-wrapper-case", lambda item: item["cases"].__setitem__(
            slice(None), [row for row in item["cases"] if row.get("id") != "actual-shared-launch"])),
        ("substituted-mutant-identity", lambda item: [
            row.update(id="mutant-invented-kill") for row in item["cases"]
            if row.get("id") == "mutant-remove-debit"]),
        ("forged-test-name", lambda item: item["test_names"].__setitem__(0, "forged-test")),
        ("forged-reach-marker", lambda item: item["reached"].__setitem__(0, "forged-reach")),
        ("forged-launch-denominator", lambda item: item.update(owned_fake_starts=7)),
        ("forged-denial-receipt", lambda item: item["denial"].update(real_child_starts=1)),
        ("altered-mutant-rejection-marker", lambda item: next(
            row for row in item["cases"] if row.get("id") == "mutant-remove-debit").update(
                rejected_at="wrong assertion")),
        ("stale-caller-file-pin", lambda item: item["caller_files"].update(
            {"scripts/evidence/phase5_process.py": "0" * 64})),
        ("stale-source-proof-pin", lambda item: item["source_proof"].update(sha256="0" * 64)),
    ):
        mutant = copy.deepcopy(data)
        mutate(mutant)
        try:
            validate_evidence(mutant)
        except ValueError as error:
            observations.append({"id": name, "outcome": "rejected", "reason": str(error)})
        else:
            raise RuntimeError(f"review counterfactual unexpectedly accepted: {name}")
    return observations


def validate_independent_review(data, review_text=None, *, check_counterfactuals=True):
    review = INDEPENDENT_REVIEW.read_text() if review_text is None else review_text
    if not review.startswith("---\n") or "\n---\n" not in review[4:]:
        raise ValueError("independent review frontmatter missing")
    frontmatter = review.split("---\n", 2)[1]
    status = re.search(r"^status:\s*(\S+)\s*$", frontmatter, re.MULTILINE)
    unresolved = re.search(r"^unresolved_high_critical:\s*(\d+)\s*$", frontmatter, re.MULTILINE)
    if status is None or status.group(1) != "accepted":
        raise ValueError("independent review is not accepted")
    if unresolved is None or int(unresolved.group(1)) != 0:
        raise ValueError("independent review has unresolved high/critical findings")
    critical = re.search(r"^  critical:\s*(\d+)\s*$", frontmatter, re.MULTILINE)
    high = re.search(r"^  high:\s*(\d+)\s*$", frontmatter, re.MULTILINE)
    if ((critical is not None and int(critical.group(1)) != 0) or
            (high is not None and int(high.group(1)) != 0)):
        raise ValueError("independent review reports high/critical findings")
    pins = dict(re.findall(r"^\| `([^\`]+)` \| `([0-9a-f]{64})` \|$",
                           review, re.MULTILINE))
    expected = {SOURCE.relative_to(ROOT).as_posix(): data["source"]["sha256"],
        Path(__file__).resolve().relative_to(ROOT).as_posix(): data["test_file_sha256"],
        **data["caller_files"],
        data["source_proof"]["path"]: data["source_proof"]["sha256"],
        EVIDENCE.relative_to(ROOT).as_posix(): hashlib.sha256(EVIDENCE.read_bytes()).hexdigest()}
    for path, digest in expected.items():
        if pins.get(path) != digest:
            raise ValueError(f"independent review pin mismatch: {path}")
    observations = []
    if check_counterfactuals:
        observations = review_text_counterfactuals(data, review)
        if (len(observations) != 4 or
                any(row.get("outcome") != "rejected" for row in observations)):
            raise ValueError("independent review counterfactual coverage mismatch")
    return {"status": status.group(1), "unresolved_high_critical": int(unresolved.group(1)),
            "pins_checked": len(expected), "counterfactuals": observations}


def review_text_counterfactuals(data, review):
    observations = []
    mutations = (
        ("unaccepted-review", lambda value: re.sub(
            r"(?m)^status:\s*accepted\s*$", "status: issues_found", value, count=1)),
        ("unresolved-review-finding", lambda value: re.sub(
            r"(?m)^unresolved_high_critical:\s*0\s*$",
            "unresolved_high_critical: 1", value, count=1)),
        ("stale-review-caller-pin", lambda value: re.sub(
            r"(?m)^(\| `scripts/evidence/phase5_process.py` \| `)[0-9a-f]{64}(` \|)$",
            r"\g<1>" + "0" * 64 + r"\2", value, count=1)),
        ("stale-review-source-proof-pin", lambda value: re.sub(
            r"(?m)^(\| `[^`]*07-14-SOURCE-PROOF.md` \| `)[0-9a-f]{64}(` \|)$",
            r"\g<1>" + "0" * 64 + r"\2", value, count=1)),
    )
    for name, mutate in mutations:
        changed = mutate(review)
        if changed == review:
            raise RuntimeError(f"review counterfactual has no matching input: {name}")
        try:
            validate_independent_review(data, changed, check_counterfactuals=False)
        except ValueError as error:
            observations.append({"id": name, "outcome": "rejected", "reason": str(error)})
        else:
            raise RuntimeError(f"review counterfactual unexpectedly accepted: {name}")
    return observations


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tracer", action="store_true")
    parser.add_argument("--contracts", action="store_true")
    parser.add_argument("--review-check", action="store_true")
    parser.add_argument("--dirty-denial-probe", action="store_true")
    parser.add_argument("--write-evidence", action="store_true")
    args = parser.parse_args()
    if args.review_check:
        if PRODUCTION is not None:
            raise RuntimeError("review check imported production source")
        data = json.loads(EVIDENCE.read_text())
        validate_evidence(data)
        counterfactuals = evidence_counterfactuals(data)
        if (len(counterfactuals) != 10 or
                any(row.get("outcome") != "rejected" for row in counterfactuals)):
            raise ValueError("evidence counterfactual coverage mismatch")
        review = validate_independent_review(data)
        print(json.dumps({"outcome": "pass", "tests_run": data["tests_run"],
                          "source": data["source"], "review": review,
                          "evidence_counterfactuals": counterfactuals,
                          "review_counterfactuals": review["counterfactuals"]}, sort_keys=True))
        return 0
    if not (args.tracer or args.contracts or args.dirty_denial_probe or args.write_evidence):
        parser.error("select --tracer or --contracts")
    report, result = run_contracts()
    if args.dirty_denial_probe:
        before = len(denial.EVENTS)
        try:
            os.killpg(987654321, 0)
        except PermissionError as error:
            if str(error) != "sticky-process-and-signal-denial":
                raise
        else:
            raise RuntimeError("dirty denial probe unexpectedly escaped")
        report["denial"] = denial.receipt()
        report["dirty_denial_probe"] = {"new_denials": len(denial.EVENTS) - before,
                                          "outcome": "deliberately-rejected"}
        DIRTY_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        DIRTY_EVIDENCE.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(json.dumps({"clean": False, "reason": "deliberate unexpected denial",
                          "unexpected_denials": report["denial"]["unexpected_denials"],
                          "dirty_evidence": DIRTY_EVIDENCE.relative_to(ROOT).as_posix()}, sort_keys=True))
        return 1
    clean = (result.testsRun == EXPECTED_TESTS and not result.failures and not result.errors and
             all(row.get("outcome") in ("pass", "killed") for row in CASES) and
             {row.get("id") for row in CASES if str(row.get("id", "")).startswith("mutant-")} == {
                 "mutant-remove-debit", "mutant-reset-between-precheck-and-cleanup",
                 "mutant-exhaustion-as-absence", "mutant-unbounded-frozen-poll",
                 "mutant-reset-per-poll", "mutant-skip-direct-child-settlement",
                 "mutant-shared-launch-bypass", "mutant-coordinator-bypass"} and
             not report["denial"].get("unexpected_denials") and
             report["native_live_query_denial_self_tests"] == [
                 "ctypes.dlopen", "ctypes.dlsym", "os.listdir:/proc", "open:/proc"])
    if args.write_evidence and clean:
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"tests_run": result.testsRun, "failures": len(result.failures),
                      "errors": len(result.errors), "cases": CASES,
                      "reached": REACHED, "clean": clean}, sort_keys=True))
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
