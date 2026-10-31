#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Denied transition checks through actual cleanup and Darwin status consumers."""
from __future__ import annotations

import contextlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

# The existing fixture installs sticky process/signal/native-query denial before
# importing production. Reuse its fake external resources, never its helper mocks.
spec = importlib.util.spec_from_file_location(
    "gw_cleanup_transition_fixture", Path(__file__).with_name("phase7_cleanup_budget_contract.py"))
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load denied cleanup fixture")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class CleanupTransitionContracts(unittest.TestCase):
    setUp = fixture.CleanupBudgetContracts.setUp
    _status_popen = fixture.CleanupBudgetContracts._status_popen

    def tearDown(self):
        fixture.denial.self_test("transition-after-mocks-restored")
        self.assertEqual(fixture.denial.receipt()["unexpected_denials"], 0)
        self.assertEqual(fixture.NATIVE_QUERY_DENIALS, [])

    def _read(self, _fd, _size):
        # Each fake query has its own stream; empty output is already EOF.
        if self.read_query != self.query_attempts:
            self.read_query = self.query_attempts
            return self.observations[min(self.query_attempts, len(self.observations)) - 1]
        return b""

    @contextlib.contextmanager
    def _external_seams(self):
        with contextlib.ExitStack() as stack:
            for target, name, replacement in (
                (self.route.os, "name", "posix"),
                (self.route.sys, "platform", "darwin"),
                (self.route.subprocess, "Popen", self._status_popen),
                (self.route.os, "set_blocking", lambda *_: None),
                (self.route.os, "read", self._read),
                (self.route.selectors, "DefaultSelector", fixture.FakeSelector),
                (self.route.time, "monotonic", lambda: 100.0),
                (self.route.time, "sleep", lambda *_: None),
                (self.route.os, "killpg", lambda _pid, sig: self.signal_calls.append(sig)),
            ):
                stack.enter_context(mock.patch.object(target, name, replacement))
            yield

    def _transition(self, observations, expected, attempts, remaining=fixture.MAX_QUERIES,
                    failed_start=None):
        self.observations = observations
        self.read_query = 0
        self.query_sentinel = fixture.MAX_QUERIES
        self.fail_status_creation_at = failed_start
        owner = fixture.FakeOwner()
        budget = {"remaining": remaining, "attempted": 0, "absent_observed": False}
        with self._external_seams():
            confirmed = self.route._terminate_process_group(
                owner, grace_seconds=0.1, status_budget=budget)
        self.assertEqual(confirmed, expected, "cleanup must reflect the latest attempted observation")
        self.assertEqual(self.query_attempts, attempts)
        self.assertEqual(budget["attempted"], attempts)
        self.assertEqual(budget["remaining"], remaining - attempts)
        self.assertEqual(owner.wait_calls, 1)
        self.assertEqual(owner.kill_calls, 0)
        self.assertEqual(self.owned_starts, 0)
        self.assertTrue(all(child.returncode is not None for child in self.status_processes))

    def test_absence_then_live_through_exhaustion_is_unconfirmed(self):
        self._transition([b"", b"4242 R\n"], False, fixture.MAX_QUERIES)

    def test_absence_then_unknown_through_exhaustion_is_unconfirmed(self):
        self._transition([b"", b"invalid\n"], False, fixture.MAX_QUERIES)

    def test_absence_then_failed_final_start_is_unconfirmed(self):
        self._transition([b""], False, 2, remaining=2, failed_start=2)

    def test_last_valid_absence_survives_exhaustion_without_new_attempt(self):
        self._transition([b"4242 R\n", b""], True, 2, remaining=2)

    def test_single_last_absence_survives_exhaustion_without_new_attempt(self):
        self._transition([b""], True, 1, remaining=1)

    def test_ordinary_live_then_absence_confirms_cleanup(self):
        self._transition([b"4242 R\n", b""], True, 4)


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(CleanupTransitionContracts))
    print(json.dumps({"tests_run": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "denial": fixture.denial.receipt(),
        "native_query_denials": fixture.NATIVE_QUERY_DENIALS}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
