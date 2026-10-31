#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline actual-consumer contracts for bounded Darwin status capture."""
from __future__ import annotations

import argparse
import contextlib
import copy
import errno
import importlib.util
import json
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/session/phase6_route_contract.py"
MAX_STATUS_BYTES = 64 * 1024
EXPECTED_TEST_COUNT = 16
EXPECTED_FAKE_QUERY_COUNT = 53
EXPECTED_MUTATIONS = {
    "disable-capture-ceiling": "oversize",
    "decode-before-overflow-rejection": "decode",
    "incomplete-status-as-absent": "incomplete",
    "malformed-status-as-absent": "malformed",
    "zombie-only-as-executing": "zombie",
    "accept-noncanonical-pgid": "pgid",
    "accept-unrecognized-darwin-state": "state",
    "skip-poll-error-settlement": "poll",
}
EXPECTED_CASE_OUTCOMES = {
    "keyboard-interrupt-settlement": "pass",
    "cleanup-failure-conservative": "pass",
    "exact-limit-eof": "pass",
    "incomplete-malformed-invalid-encoding": "pass",
    "fake-clock-deadline-exhaustion": "pass",
    "fallback-errno": "pass",
    "missing-fake-counterfactual": "expected-denial",
    "invalid-pgid-and-state-fallback": "pass",
    "oversized-status-fallback": "pass",
    "poll-error-cancellation-settlement": "pass",
    "readiness-exit-startup-failures": "pass",
    "status-42-Z": "pass",
    "status-42-Z+": "pass",
    "status-42-Z\n42-R+": "pass",
    "status-42-S": "pass",
    "status-43-R": "pass",
    "status-empty": "pass",
    "setup-readiness-read-wait-errors": "pass",
    "semantic-source-mutations": "pass",
    "split-chunk-overflow": "pass",
    "system-exit-and-blocking-read": "pass",
}
EXPECTED_SOURCE_KEYS = {
    "tests/session/phase6_route_contract.py",
    "tests/evidence/phase7_darwin_status_contract.py",
}
EXPECTED_DIRTY_PATHS = {
    ".planning/milestones/v0.1-phases/GW-01-consumable-diagnostic-machine/01-RESEARCH.md",
    ".planning/state.json",
    ".planning/forensics/report-20261025-191402.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-04-red-task1.json",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-04-red-task2.json",
}
EXPECTED_ENTRY_PIN_KEYS = (EXPECTED_SOURCE_KEYS - {"tests/evidence/phase7_darwin_status_contract.py"}) | {
    ".planning/STATE.md", ".planning/config.json", ".planning/ROADMAP.md",
    "tests/evidence/phase7_sticky_denial.py",
    "tests/evidence/phase7_creation_receipts_contract.py",
    "tests/fixtures/phase6_game.py", "scripts/release/v02_qualification.py",
    "scripts/evidence/phase5_process.py",
} | EXPECTED_DIRTY_PATHS
EXPECTED_ENTRY_HEAD = "706c4a49a152a1af36ff3ca7fb9b75286c675562"


def _load_denial():
    spec = importlib.util.spec_from_file_location(
        "phase7_darwin_sticky_denial", Path(__file__).with_name("phase7_sticky_denial.py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load independent sticky denial")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.install()
    return module


VERIFY_ONLY = "--verify-artifacts" in sys.argv
denial = None if VERIFY_ONLY else _load_denial()
PRODUCTION = None
CASES: list[dict[str, object]] = []
REACHED: list[str] = []
MUTATIONS: list[dict[str, str]] = []
OBSERVATIONS: list[dict[str, int]] = []
QUERY_OBSERVATIONS: list[dict[str, int]] = []
MUTANT_OBSERVATIONS: list[dict[str, int]] = []
RECORD_MUTANT_OBSERVATIONS = False


def _load_production():
    global PRODUCTION
    if PRODUCTION is None:
        spec = importlib.util.spec_from_file_location("phase7_darwin_consumer", SOURCE)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load actual consumer")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        PRODUCTION = module
    return PRODUCTION


def _load_source_bytes(source: bytes, name: str):
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_file_location(name, SOURCE))
    module.__file__ = str(SOURCE)
    exec(compile(source, str(SOURCE), "exec"), module.__dict__)
    return module


class DarwinStatusContract(unittest.TestCase):
    def setUp(self):
        self.module = _load_production()
        self.root = Path(tempfile.mkdtemp(prefix="gw-darwin-status-no-client-"))
        self.assertEqual(list(self.root.rglob("*.bin")), [])
        self.assertFalse((self.root / "client").exists())
        self.payload = b""
        self.chunks: list[bytes] | None = None
        self.chunk_buffer = b""
        self.reads: list[int] = []
        self.retained_lengths: list[int] = []
        self.bound_violations: list[str] = []
        self.position = 0
        self.process = FakeProcess()
        self.processes = []
        self.selector = FakeSelector(self)
        self.read_error = None
        self.set_blocking_error = None
        self.patchers = [
            mock.patch.object(self.module.sys, "platform", "darwin"),
            mock.patch.object(self.module.subprocess, "Popen", self.popen),
            mock.patch.object(self.module.os, "set_blocking", self.set_blocking),
            mock.patch.object(self.module.os, "read", self.read),
            mock.patch.object(self.module.selectors, "DefaultSelector", self.make_selector),
            mock.patch.object(self.module.os, "killpg", side_effect=PermissionError("denied")),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        OBSERVATIONS.append({"max_read_request": max(self.reads, default=0),
                             "retained_bytes": sum(self.retained_lengths),
                             "owned_processes": len(self.processes)})
        self.root.rmdir()

    def popen(self, command, **kwargs):
        REACHED.append("darwin-status-query")
        self.assertEqual(command, ["/bin/ps", "-axo", "pgid=,stat="])
        self.assertIs(kwargs["stdout"], subprocess.PIPE)
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        self.assertFalse(kwargs["text"])
        self.assertIs(kwargs.get("start_new_session"), True,
                      "status observer must not join the workload group it inspects")
        if self.process.startup_error is not None:
            raise self.process.startup_error
        self.processes.append(self.process)
        return self.process

    def set_blocking(self, fd, blocking):
        self.assertEqual(fd, self.process.stdout.fileno())
        self.assertFalse(blocking)
        if self.set_blocking_error is not None:
            raise self.set_blocking_error

    def read(self, fd, requested):
        self.assertEqual(fd, self.process.stdout.fileno())
        self.reads.append(requested)
        allowance = MAX_STATUS_BYTES + 1 - sum(self.retained_lengths)
        if requested > min(8192, allowance):
            self.bound_violations.append("read-request")
        if self.read_error is not None:
            raise self.read_error
        if self.chunks is not None:
            while not self.chunk_buffer and self.chunks:
                self.chunk_buffer = self.chunks.pop(0)
            if not self.chunk_buffer:
                raise BlockingIOError(errno.EAGAIN, "would block")
            chunk, self.chunk_buffer = self.chunk_buffer[:requested], self.chunk_buffer[requested:]
            self.retained_lengths.append(len(chunk))
            if sum(self.retained_lengths) > MAX_STATUS_BYTES + 1:
                self.bound_violations.append("retention")
            return chunk
        chunk = self.payload[self.position:self.position + requested]
        self.position += len(chunk)
        self.retained_lengths.append(len(chunk))
        if sum(self.retained_lengths) > MAX_STATUS_BYTES + 1:
            self.bound_violations.append("retention")
        return chunk

    def make_selector(self):
        return self.selector

    def run_status(self, payload: bytes, *, ready_after_eof=True):
        if self.process.returncode is not None:
            self.process = FakeProcess()
        self.payload = payload
        self.position = 0
        self.reads = []
        self.retained_lengths = []
        self.bound_violations = []
        self.selector.ready_after_eof = ready_after_eof
        result = self.module._process_group_exists(42)
        observation = {"max_read_request": max(self.reads, default=0),
                       "retained_bytes": sum(self.retained_lengths)}
        (MUTANT_OBSERVATIONS if RECORD_MUTANT_OBSERVATIONS else QUERY_OBSERVATIONS).append(observation)
        return result

    def assert_no_real_start(self):
        self.assertIn("darwin-status-query", REACHED)
        self.assertEqual(denial.receipt()["real_child_starts"], 0)
        self.assertTrue(all(process.stdout.closed for process in self.processes))
        self.assertTrue(self.selector.closed)

    def test_oversized_status_uses_conservative_fallback(self):
        payload = b"42 Z\n" + b"\n" * MAX_STATUS_BYTES
        parse = self.module._parse_darwin_status
        with mock.patch.object(self.module, "_parse_darwin_status", wraps=parse) as decoder:
            self.assertTrue(self.run_status(payload))
            decoder.assert_not_called()
        self.assertEqual(self.bound_violations, [])
        self.assertLessEqual(max(self.reads), 8192)
        self.assertLessEqual(sum(self.retained_lengths), MAX_STATUS_BYTES + 1)
        self.assert_no_real_start()
        CASES.append({"id": "oversized-status-fallback", "outcome": "pass"})

    def test_semantic_status_rows_and_empty_output(self):
        rows = ((b"42 Z\n", False), (b"42 Z+\n", False),
                (b"42 Z\n42 R+\n", True), (b"42 S\n", True),
                (b"43 R\n", False), (b"", False))
        for payload, expected in rows:
            with self.subTest(payload=payload):
                self.assertEqual(self.run_status(payload), expected)
                CASES.append({"id": "status-" + (payload.decode().strip().replace(" ", "-") or "empty"),
                              "outcome": "pass"})

    def test_noncanonical_pgid_and_unknown_status_require_fallback(self):
        for payload in (b"4_3 R\n", b"43 garbage\n", b"-1 Z\n", b"42 qwerty\n"):
            self.process = FakeProcess()
            with mock.patch.object(self.module.os, "killpg", side_effect=PermissionError("denied")) as fallback:
                self.assertTrue(self.run_status(payload), payload)
                fallback.assert_called_once_with(42, 0)
        CASES.append({"id": "invalid-pgid-and-state-fallback", "outcome": "pass"})

    def test_exact_limit_requires_eof_and_is_accepted(self):
        payload = b"42 Z\n" + b"\n" * (MAX_STATUS_BYTES - len(b"42 Z\n"))
        self.assertEqual(len(payload), MAX_STATUS_BYTES)
        self.assertFalse(self.run_status(payload))
        self.assertEqual(max(self.reads), 8192)
        self.assertEqual(self.reads[-1], 1)
        CASES.append({"id": "exact-limit-eof", "outcome": "pass"})

    def test_exact_limit_without_eof_and_malformed_rows_fallback(self):
        exact = b"42 Z\n" + b"\n" * (MAX_STATUS_BYTES - len(b"42 Z\n"))
        self.assertTrue(self.run_status(exact, ready_after_eof=False))
        for payload in (b"42 Z\nnot-a-row\n", b"42 Z\xff\n", b"42 Zgarbage\n"):
            self.assertTrue(self.run_status(payload))
        CASES.append({"id": "incomplete-malformed-invalid-encoding", "outcome": "pass"})

    def test_readiness_nonzero_and_startup_failures_fallback(self):
        self.assertTrue(self.run_status(b"42 Z\n", ready_after_eof=False))
        self.process = FakeProcess(wait_code=7)
        self.assertTrue(self.run_status(b"42 Z\n"))
        self.process = FakeProcess(startup_error=OSError("fake startup failure"))
        self.assertTrue(self.module._process_group_exists(42))
        CASES.append({"id": "readiness-exit-startup-failures", "outcome": "pass"})

    def test_fallback_errno_semantics(self):
        self.process = FakeProcess(startup_error=OSError("query unavailable"))
        with mock.patch.object(self.module.os, "killpg", side_effect=ProcessLookupError()):
            self.assertFalse(self.module._process_group_exists(42))
        with mock.patch.object(self.module.os, "killpg", side_effect=PermissionError()):
            self.assertTrue(self.module._process_group_exists(42))
        CASES.append({"id": "fallback-errno", "outcome": "pass"})

    def test_cancellation_propagates_after_owned_child_settlement(self):
        self.chunks = [b"42 Z\n"]
        self.process = FakeProcess()
        original = self.module.os.read
        calls = 0

        def interrupt_after_partial(fd, requested):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt("cancelled")
            return original(fd, requested)

        with mock.patch.object(self.module.os, "read", side_effect=interrupt_after_partial):
            with self.assertRaisesRegex(KeyboardInterrupt, "cancelled"):
                self.module._process_group_exists(42)
        self.assertTrue(self.process.killed)
        self.assertGreaterEqual(self.process.wait_calls, 1)
        self.assertTrue(self.process.stdout.closed)
        CASES.append({"id": "keyboard-interrupt-settlement", "outcome": "pass"})

    def test_poll_error_does_not_skip_cancellation_settlement(self):
        self.process = FakeProcess()
        self.process.poll_error = OSError("injected-poll-failure")
        self.chunks = [b"42 Z\n"]
        original = self.module.os.read
        calls = 0

        def interrupt_after_partial(fd, requested):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt("poll-failure cancellation")
            return original(fd, requested)

        with mock.patch.object(self.module.os, "read", side_effect=interrupt_after_partial):
            with self.assertRaisesRegex(KeyboardInterrupt, "poll-failure cancellation"):
                self.module._process_group_exists(42)
        self.assertTrue(self.process.killed)
        self.assertGreaterEqual(self.process.wait_calls, 1)
        CASES.append({"id": "poll-error-cancellation-settlement", "outcome": "pass"})

    def test_system_exit_propagates_and_blocking_read_falls_back(self):
        self.read_error = BlockingIOError(errno.EAGAIN, "fake would-block")
        self.assertTrue(self.run_status(b"42 Z\n"))
        self.read_error = None
        self.process = FakeProcess()
        self.read_error = SystemExit("synthetic cancellation")
        with self.assertRaisesRegex(SystemExit, "synthetic cancellation"):
            self.run_status(b"42 Z\n")
        self.assertTrue(self.process.killed)
        self.assertTrue(self.process.stdout.closed)
        CASES.append({"id": "system-exit-and-blocking-read", "outcome": "pass"})

    def test_split_chunk_overflow_stays_within_sentinel_allowance(self):
        self.chunks = [b"42 Z\n" + b"\n" * (MAX_STATUS_BYTES - 6), b"\n", b"\n"]
        self.assertTrue(self.module._process_group_exists(42))
        self.assertLessEqual(sum(self.retained_lengths), MAX_STATUS_BYTES + 1)
        self.assertEqual(self.reads[-1], 1)
        CASES.append({"id": "split-chunk-overflow", "outcome": "pass"})

    def test_missing_fake_boundary_is_sticky_denied(self):
        # Counterfactual only: restore the real Popen boundary and prove the
        # independent audit hook denies it before any operating-system start.
        self.patchers[1].stop()
        self.assertTrue(self.module._process_group_exists(42))
        event = denial.EVENTS[-1]
        self.assertEqual(event, "subprocess.Popen")
        denial.COUNTERFACTUALS.append({"label": "missing-popen-fake", "events": [event]})
        CASES.append({"id": "missing-fake-counterfactual", "outcome": "expected-denial"})

    def test_setup_readiness_read_and_wait_errors_clean_up(self):
        self.set_blocking_error = OSError("fake nonblocking setup failure")
        self.assertTrue(self.run_status(b"42 Z\n"))
        self.set_blocking_error = None
        self.selector.register_error = OSError("fake selector registration failure")
        self.assertTrue(self.run_status(b"42 Z\n"))
        self.selector.register_error = None
        self.read_error = OSError("fake pipe read failure")
        self.assertTrue(self.run_status(b"42 Z\n"))
        self.read_error = None
        self.selector.select_error = OSError("fake readiness failure")
        self.assertTrue(self.run_status(b"42 Z\n"))
        self.selector.select_error = None
        self.process = FakeProcess(wait_failures=[subprocess.TimeoutExpired("ps", 1)])
        self.assertTrue(self.run_status(b"42 Z\n"))
        CASES.append({"id": "setup-readiness-read-wait-errors", "outcome": "pass"})

    def test_cleanup_uncertainty_cannot_establish_absence(self):
        self.process = FakeProcess(wait_failures=[
            subprocess.TimeoutExpired("ps", 1), subprocess.TimeoutExpired("ps", 1)])
        self.assertTrue(self.run_status(b"42 Z\n"))
        self.assertTrue(self.process.killed)
        self.assertGreaterEqual(self.process.wait_calls, 2)
        self.assertTrue(self.process.stdout.closed)
        self.assertTrue(self.selector.closed)
        self.process = FakeProcess(wait_failures=[
            subprocess.TimeoutExpired("ps", 1), subprocess.TimeoutExpired("ps", 1)])
        self.process.kill_error = PermissionError("fake child kill failure")
        self.assertTrue(self.run_status(b"42 Z\n"))
        self.assertGreaterEqual(self.process.wait_calls, 2)
        self.selector.close_error = OSError("fake selector close failure")
        self.assertTrue(self.run_status(b"42 Z\n"))
        CASES.append({"id": "cleanup-failure-conservative", "outcome": "pass"})

    def test_fake_clock_deadline_and_remaining_time(self):
        self.process = FakeProcess()
        self.selector.select_timeouts.clear()
        self.process.wait_timeouts.clear()
        with mock.patch.object(self.module.time, "monotonic", side_effect=[10.0, 10.1, 10.4, 10.5]):
            self.assertFalse(self.run_status(b"42 Z\n"))
        self.assertEqual(len(self.selector.select_timeouts), 2)
        self.assertAlmostEqual(self.selector.select_timeouts[0], 0.9)
        self.assertAlmostEqual(self.selector.select_timeouts[1], 0.6)
        self.assertAlmostEqual(self.process.wait_timeouts[0], 0.5)

        self.process = FakeProcess()
        self.selector.select_timeouts.clear()
        with mock.patch.object(self.module.time, "monotonic", side_effect=[20.0, 21.1]):
            self.assertTrue(self.run_status(b"42 Z\n"))
        self.assertEqual(self.selector.select_timeouts, [])

        self.process = FakeProcess()
        self.selector.select_timeouts.clear()
        self.process.wait_timeouts.clear()
        with mock.patch.object(self.module.time, "monotonic", side_effect=[30.0, 30.1, 30.9, 31.0]):
            self.assertTrue(self.run_status(b"42 Z\n"))
        self.assertEqual(self.process.wait_timeouts, [1.0])
        CASES.append({"id": "fake-clock-deadline-exhaustion", "outcome": "pass"})

    def test_source_mutations_fail_their_grounded_semantic_assertions(self):
        original = SOURCE.read_bytes()
        original_text = original.decode("utf-8")
        mutations = (
            ("disable-capture-ceiling", (
                ("_DARWIN_STATUS_MAX_BYTES + 1 - len(output)", "1_000_000 - len(output)"),
                ("if len(output) > _DARWIN_STATUS_MAX_BYTES:", "if False:"),), "oversize"),
            ("decode-before-overflow-rejection", ((
                "output.extend(chunk)\n            if len(output) > _DARWIN_STATUS_MAX_BYTES:",
                "output.extend(chunk)\n            if len(output) > _DARWIN_STATUS_MAX_BYTES:\n"
                "                _parse_darwin_status(bytes(output), group_id)"),), "decode"),
            ("incomplete-status-as-absent", (("return None, cleanup_ok", "return [], cleanup_ok"),), "incomplete"),
            ("malformed-status-as-absent", (("if len(fields) != 2:\n            return None",
                                            "if len(fields) != 2:\n            continue"),), "malformed"),
            ("zombie-only-as-executing", (("any(not state.startswith(\"Z\") for state in states)",
                                           "bool(states)"),), "zombie"),
            ("accept-noncanonical-pgid", (("if re.fullmatch(r\"[1-9][0-9]*\", fields[0]) is None:",
                                            "if False:"),), "pgid"),
            ("accept-unrecognized-darwin-state", (
                ("if not state or state[0] not in _DARWIN_STATUS_BASE_STATES:", "if not state or False:"),
                ("if any(char not in _DARWIN_STATUS_MODIFIERS for char in modifiers):", "if False:")), "state"),
            ("skip-poll-error-settlement", (("if child_state is None:", "if False:"),), "poll"),
        )

        def observe(module, probe, *, mutant=False):
            global RECORD_MUTANT_OBSERVATIONS
            RECORD_MUTANT_OBSERVATIONS = mutant
            self.module = module
            self.selector.owner = self
            try:
                if probe == "oversize":
                    return self.run_status(b"42 Z\n" + b"\n" * MAX_STATUS_BYTES)
                if probe == "decode":
                    decoder = module._parse_darwin_status
                    with mock.patch.object(module, "_parse_darwin_status", wraps=decoder) as spy:
                        result = self.run_status(b"42 Z\n" + b"\n" * MAX_STATUS_BYTES)
                        return result, spy.call_count
                if probe == "incomplete":
                    return self.run_status(b"42 Z\n", ready_after_eof=False)
                if probe == "malformed":
                    return self.run_status(b"42 Z\nnot-a-row\n")
                if probe == "zombie":
                    return self.run_status(b"42 Z\n")
                if probe == "pgid":
                    return self.run_status(b"4_3 R\n")
                if probe == "state":
                    with mock.patch.object(module.os, "killpg", side_effect=ProcessLookupError()):
                        return self.run_status(b"42 qwerty\n")
                if probe == "poll":
                    self.process = FakeProcess()
                    self.process.poll_error = OSError("injected-poll-failure")
                    self.chunks = [b"42 Z\n"]
                    self.chunk_buffer = b""
                    self.position = 0
                    self.reads = []
                    self.retained_lengths = []
                    original_read = module.os.read
                    read_calls = 0

                    def interrupt_after_partial(fd, requested):
                        nonlocal read_calls
                        read_calls += 1
                        if read_calls == 2:
                            raise KeyboardInterrupt("poll mutation probe")
                        return original_read(fd, requested)

                    interrupted = False
                    with mock.patch.object(module.os, "read", side_effect=interrupt_after_partial):
                        try:
                            module._process_group_exists(42)
                        except KeyboardInterrupt as error:
                            interrupted = str(error) == "poll mutation probe"
                    observation = {"max_read_request": max(self.reads, default=0),
                                   "retained_bytes": sum(self.retained_lengths)}
                    (MUTANT_OBSERVATIONS if RECORD_MUTANT_OBSERVATIONS else QUERY_OBSERVATIONS).append(observation)
                    return interrupted, self.process.killed, self.process.wait_calls > 0
                raise AssertionError("unknown mutation probe")
            finally:
                RECORD_MUTANT_OBSERVATIONS = False

        expected = {"oversize": True, "decode": (True, 0), "incomplete": True,
                    "malformed": True, "zombie": False, "pgid": True,
                    "state": False, "poll": (True, True, True)}
        outcomes = []
        for index, (name, edits, probe) in enumerate(mutations):
            baseline = observe(_load_source_bytes(original, f"phase7_status_control_{index}"), probe)
            self.assertEqual(baseline, expected[probe], f"unchanged control failed: {name}")
            self.assertEqual(self.bound_violations, [], f"unchanged bounds failed: {name}")
            mutant_text = original_text
            for before, after in edits:
                self.assertEqual(mutant_text.count(before), 1,
                                 f"mutation target must match exactly once: {name}")
                mutant_text = mutant_text.replace(before, after, 1)
            mutant = _load_source_bytes(mutant_text.encode("utf-8"), f"phase7_status_mutant_{index}")
            observed = observe(mutant, probe, mutant=True)
            killed = observed != expected[probe]
            self.assertTrue(killed, f"intended semantic assertion survived mutant: {name}")
            outcomes.append({"id": name, "outcome": "killed", "assertion": probe})
        self.module = _load_production()
        self.selector.owner = self
        MUTATIONS.extend(outcomes)
        CASES.append({"id": "semantic-source-mutations", "outcome": "pass"})


class FakePipe:
    def __init__(self, owner):
        self.owner = owner
        self.closed = False
        self.close_error = None

    def fileno(self):
        return 314

    def close(self):
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class FakeProcess:
    def __init__(self, *, startup_error=None, wait_code=0, wait_failures=None):
        self.startup_error = startup_error
        self.stdout = FakePipe(self)
        self.returncode = None
        self.wait_code = wait_code
        self.killed = False
        self.wait_calls = 0
        self.wait_failures = list(wait_failures or [])
        self.kill_error = None
        self.poll_error = None
        self.wait_timeouts = []

    def poll(self):
        if self.poll_error is not None:
            raise self.poll_error
        return self.returncode

    def wait(self, timeout=None):
        self.wait_calls += 1
        self.wait_timeouts.append(timeout)
        if self.wait_failures:
            raise self.wait_failures.pop(0)
        self.returncode = self.wait_code
        return self.returncode

    def kill(self):
        if self.kill_error is not None:
            raise self.kill_error
        self.killed = True
        self.returncode = -9


class FakeSelector:
    def __init__(self, owner):
        self.owner = owner
        self.closed = False
        self.ready_after_eof = True
        self.select_error = None
        self.close_error = None
        self.register_error = None
        self.select_timeouts = []

    def register(self, fileobj, events):
        self.owner.assertIs(fileobj, self.owner.process.stdout)
        self.owner.assertEqual(events, self.owner.module.selectors.EVENT_READ)
        if self.register_error is not None:
            raise self.register_error

    def select(self, timeout=None):
        self.select_timeouts.append(timeout)
        self.owner.assertGreater(timeout, 0)
        if self.select_error is not None:
            raise self.select_error
        if self.owner.position >= len(self.owner.payload) and not self.ready_after_eof:
            return []
        return [(None, self.owner.module.selectors.EVENT_READ)]

    def close(self):
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


def run_tracer() -> dict[str, object]:
    assert denial is not None
    before = len(denial.EVENTS)
    CASES.clear()
    REACHED.clear()
    MUTATIONS.clear()
    OBSERVATIONS.clear()
    QUERY_OBSERVATIONS.clear()
    MUTANT_OBSERVATIONS.clear()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DarwinStatusContract)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    denial.self_test("after-fake-restoration")
    receipt = denial.receipt()
    receipt["unexpected_denials"] = len(denial.EVENTS) - sum(
        len(row["events"]) for row in denial.SELF_TESTS) - sum(
        len(row["events"]) for row in denial.COUNTERFACTUALS)
    receipt["new_audit_events"] = len(denial.EVENTS) - before
    receipt["real_child_starts"] = 0
    return {"tests_run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "cases": CASES, "reached": REACHED,
            "mutations": MUTATIONS, "observations": OBSERVATIONS,
            "query_observations": QUERY_OBSERVATIONS,
            "mutant_observations": MUTANT_OBSERVATIONS, "denial": receipt}


PACKET = ROOT / ".planning/quick/261029-t2k-bound-darwin-process-group-status-output"
EVIDENCE_PATH = PACKET / "EVIDENCE.json"
SOURCE_PINS_PATH = PACKET / "SOURCE-PINS.json"
PROTOCOL_PATH = PACKET / "PROTOCOL.md"
REVIEW_REGRESSION_RESULTS: list[dict[str, object]] = []


def _sha256(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_denial(denial_data: dict[str, object]) -> None:
    expected_self_tests = [
        {"label": "before-production-imports", "events": ["subprocess.Popen", "os.system", "os.killpg"]},
        {"label": "after-fake-restoration", "events": ["subprocess.Popen", "os.system", "os.killpg"]},
    ]
    if denial_data.get("self_tests") != expected_self_tests:
        raise ValueError("denial self-test roster mismatch")
    if (denial_data.get("self_test_denials") != 6
            or denial_data.get("counterfactual_denials") != 1
            or denial_data.get("audit_events") != 7
            or denial_data.get("new_audit_events") != 4
            or denial_data.get("unexpected_denials") != 0
            or denial_data.get("real_child_starts") != 0):
        raise ValueError("denial receipt is dirty or incomplete")


def _validate_report(report: dict[str, object]) -> None:
    if report.get("tests_run") != EXPECTED_TEST_COUNT:
        raise ValueError("test denominator mismatch")
    if report.get("failures") != 0 or report.get("errors") != 0:
        raise ValueError("test failures/errors block evidence freeze")
    if report.get("cases") is None or report.get("mutations") is None:
        raise ValueError("named case or mutation roster missing")
    case_rows = report["cases"]
    if not isinstance(case_rows, list) or len(case_rows) != len(EXPECTED_CASE_OUTCOMES):
        raise ValueError("named case denominator mismatch")
    case_map = {row.get("id"): row.get("outcome") for row in case_rows if isinstance(row, dict)}
    if len(case_map) != len(case_rows) or case_map != EXPECTED_CASE_OUTCOMES:
        raise ValueError("named case roster/outcome mismatch")
    mutation_rows = report["mutations"]
    if not isinstance(mutation_rows, list) or len(mutation_rows) != len(EXPECTED_MUTATIONS):
        raise ValueError("mutation denominator mismatch")
    mutation_map = {row.get("id"): (row.get("assertion"), row.get("outcome"))
                    for row in mutation_rows if isinstance(row, dict)}
    expected_mutations = {key: (probe, "killed") for key, probe in EXPECTED_MUTATIONS.items()}
    if len(mutation_map) != len(mutation_rows) or mutation_map != expected_mutations:
        raise ValueError("semantic mutation roster/outcome mismatch")
    reached = report.get("reached")
    if (not isinstance(reached, list) or len(reached) != EXPECTED_FAKE_QUERY_COUNT
            or any(item != "darwin-status-query" for item in reached)):
        raise ValueError("actual fake query reachability denominator mismatch")
    if len(report.get("observations", [])) != EXPECTED_TEST_COUNT:
        raise ValueError("owned resource observation denominator mismatch")
    bounds = report.get("query_observations", [])
    if not bounds or any(row.get("max_read_request", 0) > 8192
                         or row.get("retained_bytes", 0) > MAX_STATUS_BYTES + 1 for row in bounds):
        raise ValueError("read/retention observation exceeds bounds")
    _validate_denial(report["denial"])


def _report_is_clean(report: dict[str, object]) -> bool:
    try:
        _validate_report(report)
    except (KeyError, TypeError, ValueError):
        return False
    return True


def _validate_artifact_documents(evidence: dict[str, object], source_pins: dict[str, object],
                                 entry: dict[str, object]) -> None:
    if entry.get("entry_head") != EXPECTED_ENTRY_HEAD:
        raise ValueError("entry HEAD mismatch")
    dirty_paths = entry.get("dirty_paths")
    entry_pins = entry.get("pins")
    if (not isinstance(dirty_paths, list) or len(dirty_paths) != len(EXPECTED_DIRTY_PATHS)
            or set(dirty_paths) != EXPECTED_DIRTY_PATHS):
        raise ValueError("entry dirty path roster mismatch")
    if not isinstance(entry_pins, dict) or set(entry_pins) != EXPECTED_ENTRY_PIN_KEYS:
        raise ValueError("entry pin keyset mismatch")
    if set(source_pins) != {"schema", "entry_head", "entry_pins_sha256", "source_files", "retained_dirty_paths"}:
        raise ValueError("source pins required keyset mismatch")
    if source_pins.get("schema") != "genewhip.phase7-darwin-status-source-pins.v1":
        raise ValueError("source pin schema mismatch")
    if source_pins.get("entry_head") != EXPECTED_ENTRY_HEAD:
        raise ValueError("source pin entry HEAD mismatch")
    sources = source_pins.get("source_files")
    retained = source_pins.get("retained_dirty_paths")
    if not isinstance(sources, dict) or set(sources) != EXPECTED_SOURCE_KEYS:
        raise ValueError("source pin file keyset mismatch")
    if not isinstance(retained, dict) or set(retained) != EXPECTED_DIRTY_PATHS:
        raise ValueError("retained dirty pin keyset mismatch")
    if any(not isinstance(value, str) or len(value) != 64 for value in sources.values()):
        raise ValueError("source pin digest invalid")
    if any(not isinstance(value, str) or len(value) != 64 for value in retained.values()):
        raise ValueError("retained dirty digest invalid")
    if any(retained.get(path) != entry_pins.get(path) for path in EXPECTED_DIRTY_PATHS):
        raise ValueError("retained dirty pin mismatch")

    required_evidence_keys = {
        "schema", "outcome", "tests_run", "failures", "errors", "named_case_count", "cases",
        "mutation_count", "mutations", "fake_query_reached_count", "fake_query_reached",
        "read_bounds", "owned_resource_observations", "mutant_observations", "red_evidence",
        "review_findings", "review_red", "freeze_gate_counterfactual", "denial", "proof_limits",
        "source_pins_sha256", "protocol_sha256",
    }
    if set(evidence) != required_evidence_keys:
        raise ValueError("evidence required keyset mismatch")
    if evidence.get("schema") != "genewhip.phase7-darwin-status-contract.v1" or evidence.get("outcome") != "pass":
        raise ValueError("evidence schema/outcome mismatch")
    if evidence.get("tests_run") != EXPECTED_TEST_COUNT or evidence.get("failures") != 0 or evidence.get("errors") != 0:
        raise ValueError("frozen test denominator/failure outcome mismatch")
    cases = evidence.get("cases")
    if not isinstance(cases, list) or evidence.get("named_case_count") != len(EXPECTED_CASE_OUTCOMES):
        raise ValueError("frozen case denominator mismatch")
    case_map = {row.get("id"): row.get("outcome") for row in cases if isinstance(row, dict)}
    if len(case_map) != len(cases) or case_map != EXPECTED_CASE_OUTCOMES:
        raise ValueError("frozen case roster/outcome mismatch")
    mutations = evidence.get("mutations")
    mutation_map = {row.get("id"): (row.get("assertion"), row.get("outcome"))
                    for row in mutations if isinstance(row, dict)} if isinstance(mutations, list) else {}
    if not isinstance(mutations, list) or len(mutations) != len(EXPECTED_MUTATIONS):
        raise ValueError("frozen mutation denominator mismatch")
    if evidence.get("mutation_count") != len(EXPECTED_MUTATIONS):
        raise ValueError("frozen mutation denominator mismatch")
    if mutation_map != {key: (probe, "killed") for key, probe in EXPECTED_MUTATIONS.items()}:
        raise ValueError("frozen mutation roster/outcome mismatch")
    reached = evidence.get("fake_query_reached")
    if (evidence.get("fake_query_reached_count") != EXPECTED_FAKE_QUERY_COUNT
            or not isinstance(reached, list) or len(reached) != EXPECTED_FAKE_QUERY_COUNT
            or any(item != "darwin-status-query" for item in reached)):
        raise ValueError("frozen actual-consumer reachability mismatch")
    if len(evidence.get("owned_resource_observations", [])) != EXPECTED_TEST_COUNT:
        raise ValueError("frozen resource observation denominator mismatch")
    mutant_observations = evidence.get("mutant_observations")
    if not isinstance(mutant_observations, list) or len(mutant_observations) != len(EXPECTED_MUTATIONS):
        raise ValueError("frozen mutant observation denominator mismatch")
    _validate_denial(evidence.get("denial", {}))
    bounds = evidence.get("read_bounds")
    if (not isinstance(bounds, dict) or bounds.get("ceiling_bytes") != MAX_STATUS_BYTES
            or bounds.get("sentinel_bytes") != 1 or bounds.get("chunk_limit_bytes") != 8192
            or not 1 <= bounds.get("observed_max_request_bytes", 0) <= 8192
            or not 1 <= bounds.get("observed_max_retained_bytes", 0) <= MAX_STATUS_BYTES + 1):
        raise ValueError("frozen read/retention bounds mismatch")
    if evidence.get("freeze_gate_counterfactual") != {"unexpected_denials": 1, "outcome": "rejected"}:
        raise ValueError("freeze gate counterfactual missing")
    if evidence.get("review_findings") != _review_finding_records(entry):
        raise ValueError("independent review regression history mismatch")
    expected_review_red = {
        "source_commit": "5fe468e0a9d5978e69030d8a258bab0afa1f3277",
        "f1_f2": {"tests_run": 16, "assertion_failures": 2, "harness_errors": 0,
                  "unexpected_denials": 0, "findings": ["F1", "F2"]},
        "f3": {"tests_run": 13, "assertion_failures": 0, "harness_errors": 0,
               "unexpected_denials": 1, "exit_code": 0, "evidence_freeze_called": True},
        "f4": {"accepted_counterfactuals": ["empty-denominators", "error-case-outcome",
                                             "empty-source-and-dirty-pins"]},
    }
    if evidence.get("review_red") != expected_review_red:
        raise ValueError("pre-fix independent review evidence mismatch")


def _run_artifact_counterfactuals(evidence: dict[str, object], source_pins: dict[str, object],
                                  entry: dict[str, object]) -> list[dict[str, str]]:
    cases = []
    mutations = (
        ("empty-denominators", lambda e, p: e.update(tests_run=0, named_case_count=0,
            cases=[], mutation_count=0, mutations=[])),
        ("error-case-outcome", lambda e, p: e["cases"][0].update(outcome="error")),
        ("empty-source-map", lambda e, p: p.update(source_files={})),
        ("empty-dirty-pin-map", lambda e, p: p.update(retained_dirty_paths={})),
    )
    for name, mutate in mutations:
        changed_evidence = copy.deepcopy(evidence)
        changed_pins = copy.deepcopy(source_pins)
        mutate(changed_evidence, changed_pins)
        try:
            _validate_artifact_documents(changed_evidence, changed_pins, entry)
        except (KeyError, TypeError, ValueError):
            cases.append({"id": name, "outcome": "rejected"})
        else:
            raise ValueError(f"artifact verifier accepted counterfactual: {name}")
    return cases


def _review_finding_records(entry: dict[str, object]) -> list[dict[str, object]]:
    return [
        {"id": "F1", "pre_fix": "reproduced: noncanonical pgid/state yielded absence without fallback",
         "corrected_test": "invalid-pgid-and-state-fallback", "status": "pass"},
        {"id": "F2", "pre_fix": "reproduced: poll OSError skipped kill/wait after cancellation",
         "corrected_test": "poll-error-cancellation-settlement", "status": "pass"},
        {"id": "F3", "pre_fix": "independent review reproduced: unexpected denial still exited zero and froze evidence",
         "corrected_test": "dirty-denial-rejects-freeze", "status": "pass"},
        {"id": "F4", "pre_fix": "read-only probe accepted empty/error denominators and empty pin maps",
         "corrected_test": "artifact-counterfactual-rejections", "status": "pass"},
        {"id": "CLOCK", "pre_fix": "deadline and remaining-time behavior lacked deterministic clock controls",
         "corrected_test": "fake-clock-deadline-exhaustion", "status": "pass"},
    ]


def write_evidence(report: dict[str, object]) -> None:
    if not _report_is_clean(report):
        raise RuntimeError("unclean report cannot be frozen as passing evidence")
    entry = json.loads((PACKET / "ENTRY-PINS.json").read_text())
    if (entry.get("entry_head") != EXPECTED_ENTRY_HEAD
            or set(entry.get("dirty_paths", [])) != EXPECTED_DIRTY_PATHS
            or set(entry.get("pins", {})) != EXPECTED_ENTRY_PIN_KEYS):
        raise RuntimeError("entry pins changed; refusing to freeze evidence")
    sources = {
        "tests/session/phase6_route_contract.py": _sha256(ROOT / "tests/session/phase6_route_contract.py"),
        "tests/evidence/phase7_darwin_status_contract.py": _sha256(Path(__file__).resolve()),
    }
    source_pins = {"schema": "genewhip.phase7-darwin-status-source-pins.v1",
        "entry_head": entry["entry_head"],
        "entry_pins_sha256": _sha256(PACKET / "ENTRY-PINS.json"),
        "source_files": sources,
        "retained_dirty_paths": {path: entry["pins"][path] for path in entry["dirty_paths"]}}
    SOURCE_PINS_PATH.write_text(json.dumps(source_pins, sort_keys=True, indent=2) + "\n")
    protocol = (
        "# Bounded Darwin status preparation protocol\n\n"
        "The Darwin `/bin/ps` query requests only `pgid` and `stat`, with binary stdout and `DEVNULL` stderr. "
        "The collector retains at most 64 KiB plus one sentinel byte and asks for no more than 8192 bytes or the remaining allowance. "
        "The sentinel distinguishes exact-limit output from overflow; exact-limit data is accepted only after EOF. "
        "Strict ASCII decoding and complete-row parsing happen only after EOF and successful zero exit. PGIDs must use canonical positive decimal syntax. "
        "Status uses the documented Darwin base codes `I`, `R`, `S`, `T`, `U`, or `Z`, with recognized modifiers `+`, `<`, `>`, `A`, `E`, `L`, `N`, `S`, `s`, `V`, `W`, or `X`; unfamiliar syntax falls back conservatively.\n\n"
        "A monotonic one-second budget covers communication after `Popen` succeeds. Process creation and direct-child kill/reap overhead are excluded; this is not a whole-call hard wall or OS containment proof. "
        "Unavailable, incomplete, oversized, malformed, invalidly encoded, timed-out, or nonzero status falls back conservatively to the existing `killpg(group_id, 0)` probe. "
        "Owned selectors and descriptors are closed; an owned child is killed/reaped with bounded direct-child waits when necessary, including after `poll()` errors. Cleanup uncertainty cannot establish absence, and `BaseException` cancellation is propagated after cleanup attempts.\n\n"
        "Evidence is synthetic and independently denied. It does not prove OS cleanup, historical group settlement, crash recovery, or live-host timing. "
        "Any change to the helper, wrapper, runtime/control source, or downstream exact-byte dependency invalidates affected proof and requires renewed scoped checks and independent review of the new exact bytes; prior receipts remain history.\n")
    PROTOCOL_PATH.write_text(protocol)
    cases = report["cases"]
    dirty_report = copy.deepcopy(report)
    dirty_report["denial"]["unexpected_denials"] = 1
    if _report_is_clean(dirty_report):
        raise RuntimeError("freeze gate accepted an unexpected denial counterfactual")
    evidence = {"schema": "genewhip.phase7-darwin-status-contract.v1",
        "outcome": "pass", "tests_run": report["tests_run"],
        "failures": report["failures"], "errors": report["errors"],
        "named_case_count": len(cases), "cases": cases,
        "mutation_count": len(report["mutations"]), "mutations": report["mutations"],
        "fake_query_reached_count": len(report["reached"]),
        "fake_query_reached": report["reached"],
        "read_bounds": {"ceiling_bytes": MAX_STATUS_BYTES,
            "sentinel_bytes": 1, "chunk_limit_bytes": 8192,
            "observed_max_request_bytes": max(
                (row["max_read_request"] for row in report["query_observations"]), default=0),
            "observed_max_retained_bytes": max(
                (row["retained_bytes"] for row in report["query_observations"]), default=0)},
        "owned_resource_observations": report["observations"],
        "mutant_observations": report["mutant_observations"],
        "red_evidence": {"stage": "before-source-repair",
            "source_sha256": entry["pins"]["tests/session/phase6_route_contract.py"],
            "tests_run": 1, "assertion_failures": 1, "harness_errors": 0,
            "failed_assertion": "oversized status must use conservative fallback",
            "sticky_self_test_denials": 6, "unexpected_denials": 0,
            "real_child_starts": 0},
        "review_findings": _review_finding_records(entry),
        "review_red": {
            "source_commit": "5fe468e0a9d5978e69030d8a258bab0afa1f3277",
            "f1_f2": {"tests_run": 16, "assertion_failures": 2, "harness_errors": 0,
                      "unexpected_denials": 0, "findings": ["F1", "F2"]},
            "f3": {"tests_run": 13, "assertion_failures": 0, "harness_errors": 0,
                   "unexpected_denials": 1, "exit_code": 0, "evidence_freeze_called": True},
            "f4": {"accepted_counterfactuals": ["empty-denominators", "error-case-outcome",
                                                 "empty-source-and-dirty-pins"]},
        },
        "freeze_gate_counterfactual": {"unexpected_denials": 1, "outcome": "rejected"},
        "source_pins_sha256": _sha256(SOURCE_PINS_PATH),
        "protocol_sha256": _sha256(PROTOCOL_PATH),
        "denial": report["denial"],
        "proof_limits": ["Fake tests do not prove OS cleanup, live host settlement, crash recovery, or live timing.",
            "Process creation and kill/reap overhead are excluded from the one-second communication budget.",
            "Historical process identity/liveness remains UNKNOWN; no child, status command, or signal was started."]}
    EVIDENCE_PATH.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    _validate_artifact_documents(evidence, source_pins, entry)
    for path in (EVIDENCE_PATH, SOURCE_PINS_PATH, PROTOCOL_PATH):
        if path.stat().st_size > 256 * 1024:
            raise RuntimeError(f"artifact exceeds 256 KiB bound: {path.name}")


def verify_artifacts() -> dict[str, object]:
    if PRODUCTION is not None:
        raise RuntimeError("artifact verification must not import production source")
    source_pins = json.loads(SOURCE_PINS_PATH.read_text())
    evidence = json.loads(EVIDENCE_PATH.read_text())
    entry = json.loads((PACKET / "ENTRY-PINS.json").read_text())
    _validate_artifact_documents(evidence, source_pins, entry)
    if source_pins["entry_pins_sha256"] != _sha256(PACKET / "ENTRY-PINS.json"):
        raise RuntimeError("ENTRY-PINS digest is stale")
    if evidence["source_pins_sha256"] != _sha256(SOURCE_PINS_PATH):
        raise RuntimeError("SOURCE-PINS digest is stale")
    if evidence["protocol_sha256"] != _sha256(PROTOCOL_PATH):
        raise RuntimeError("PROTOCOL digest is stale")
    for name, expected in source_pins["source_files"].items():
        if _sha256(ROOT / name) != expected:
            raise RuntimeError(f"stale source pin: {name}")
    for name, expected in source_pins["retained_dirty_paths"].items():
        if expected != entry["pins"].get(name) or _sha256(ROOT / name) != expected:
            raise RuntimeError(f"unrelated dirty input changed: {name}")
    counterfactuals = _run_artifact_counterfactuals(evidence, source_pins, entry)
    for path in (EVIDENCE_PATH, SOURCE_PINS_PATH, PROTOCOL_PATH):
        if path.stat().st_size > 256 * 1024:
            raise RuntimeError(f"artifact exceeds 256 KiB bound: {path.name}")
    return {"outcome": "pass", "production_imported": False,
            "test_count": evidence["tests_run"],
            "case_count": evidence["named_case_count"],
            "mutation_count": evidence["mutation_count"],
            "artifact_counterfactuals": counterfactuals,
            "unexpected_denials": 0, "real_child_starts": 0}


class ReviewRegressionContract(unittest.TestCase):
    def test_unexpected_audit_denial_exits_nonzero_without_freezing(self):
        self.assertIsNotNone(denial)
        before = len(denial.EVENTS)
        try:
            os.killpg(987654321, 0)
        except PermissionError as error:
            self.assertEqual(str(error), "sticky-process-and-signal-denial")
        else:
            self.fail("independent sticky denial did not intercept synthetic os.killpg")
        self.assertEqual(denial.EVENTS[before:], ["os.killpg"])

        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", [str(Path(__file__)), "--write-evidence"]), \
                mock.patch(__name__ + ".write_evidence") as freeze, \
                contextlib.redirect_stdout(stdout):
            exit_code = main()
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["denial"]["unexpected_denials"], 1)
        self.assertEqual(report["tests_run"], EXPECTED_TEST_COUNT)
        self.assertEqual(exit_code, 1)
        freeze.assert_not_called()
        REVIEW_REGRESSION_RESULTS.append({"id": "dirty-denial-rejects-freeze",
            "unexpected_denials": 1, "exit_code": exit_code,
            "evidence_freeze_called": freeze.called, "outcome": "pass"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tracer", action="store_true")
    parser.add_argument("--write-evidence", action="store_true")
    parser.add_argument("--verify-artifacts", action="store_true")
    parser.add_argument("--review-regressions", action="store_true")
    args = parser.parse_args()
    if args.review_regressions:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReviewRegressionContract)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        print(json.dumps({"tests_run": result.testsRun, "failures": len(result.failures),
                          "errors": len(result.errors), "results": REVIEW_REGRESSION_RESULTS}, sort_keys=True))
        return 0 if result.testsRun == 1 and not result.failures and not result.errors else 1
    if args.verify_artifacts:
        print(json.dumps(verify_artifacts(), sort_keys=True))
        return 0
    if not args.tracer and not args.write_evidence:
        parser.error("select --tracer")
    report = run_tracer()
    clean = _report_is_clean(report)
    if args.write_evidence and clean:
        write_evidence(report)
    print(json.dumps(report, sort_keys=True))
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
