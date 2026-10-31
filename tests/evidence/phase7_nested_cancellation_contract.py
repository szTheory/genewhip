#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Semantic synthetic C/A/B contracts. No production client, ROM or OS start."""
import importlib.util
from pathlib import Path

_denial_spec = importlib.util.spec_from_file_location("nested_sticky_denial",
    Path(__file__).with_name("phase7_sticky_denial.py"))
denial = importlib.util.module_from_spec(_denial_spec)
_denial_spec.loader.exec_module(denial)

# Must precede any production import or fake boundary installation.
denial.install()

import copy
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load("tests/evidence/phase7_nested_cancellation_probe.py", "nested_probe_contract")
outer = load("scripts/evidence/phase5_process.py", "nested_outer_contract")
route = outer.process_boundary()
desktop = load("tests/desktop/phase4_sessions.py", "nested_desktop_contract")


class FakeSubjects:
    """Two fake interpreters: distinct signal domains and fresh fake identities.

    A runs the actual supervisor/wrapper/shared helper in a Python thread;
    B is a silent finite fake at Popen. No real signaling or child creation.
    """
    A, B = 710001, 710002

    def __init__(self, case, root, fault=None):
        self.case, self.root, self.fault = case, root, fault
        self.local = threading.local()
        self.children = {}
        self.handlers = {self.A: signal.SIG_DFL, 0: signal.getsignal(signal.SIGTERM)}
        self.births = {self.A: "Mon Oct 26 12:00:01 2026", self.B: "Mon Oct 26 12:00:02 2026"}
        self.creations, self.signals, self.observations, self.loads = [], [], [], []
        self.trace = []
        self.threads = []
        self.thread_errors = []
        self.real_pid = os.getpid()

    def domain(self):
        return getattr(self.local, "pid", 0)

    def getsignal(self, _sig):
        return self.handlers.get(self.domain(), signal.SIG_DFL)

    def setsignal(self, _sig, handler):
        old = self.getsignal(_sig)
        self.handlers[self.domain()] = handler
        return old

    def getpid(self):
        return self.domain() or self.real_pid

    def imported(self, relative, name):
        self.loads.append(relative)
        if relative == "scripts/evidence/phase5_process.py":
            return outer
        if relative == "tests/desktop/phase4_sessions.py":
            return desktop
        raise AssertionError("unreviewed-production-import:" + relative)

    def killpg(self, pgid, sig):
        self.signals.append((pgid, sig))
        self.case.assertIn(pgid, self.children, "signal must use a freshly fake-owned group")
        if sig == 0:
            return
        if self.children[pgid].poll() is not None:
            raise ProcessLookupError("fake-settled-owned-group")
        if pgid == self.A:
            self.trace.append("cancel-A")
            if self.fault == "signal-denied":
                raise PermissionError("fake-controller-signal-denied")
            handler = self.handlers[self.A]
            if callable(handler):
                if self.fault != "ignore-cancel":
                    handler(sig, None)
            else:
                raise AssertionError("A did not install shared cancellation handler")
        else:
            self.children[pgid].returncode = -int(sig)

    def status(self, command, **kwargs):
        self.case.assertEqual(command[0], "/bin/ps")
        self.case.assertEqual(kwargs["timeout"], probe.STATUS_SECONDS)
        if command[1] == "-p":
            pid = int(command[2])
            self.observations.append(pid)
            if self.fault == "observer-failed":
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            child = self.children[pid]
            if child.poll() is not None:
                return subprocess.CompletedProcess(command, 1, "", "")
            birth = self.births[pid]
            if self.fault == "reuse" and pid == self.A and self.observations.count(pid) > 1:
                birth = "Mon Oct 26 12:00:09 2026"
            return subprocess.CompletedProcess(command, 0, f"{pid} {pid} {birth} S\n", "")
        self.case.assertEqual(command, ["/bin/ps", "-axo", "pgid=,stat="])
        output = ""
        if self.fault == "B-group-remains":
            output = f"{self.B} S\n"
        return subprocess.CompletedProcess(command, 0, output, "")

    def popen(self, command, **kwargs):
        self.case.assertTrue(kwargs["start_new_session"])
        if "--supervisor" in command:
            self.case.assertEqual(self.creations, [])
            self.creations.append(self.A)
            self.trace.append("create-A")
            read_out, write_out = os.pipe()
            read_err, write_err = os.pipe()
            child = self.Child(self.A)
            child.stdout, child.stderr = os.fdopen(read_out, "rb"), os.fdopen(read_err, "rb")
            self.children[self.A] = child
            def run_a():
                self.local.pid = self.A
                try:
                    child.returncode = probe.supervisor(self.root)
                except BaseException as error:
                    self.thread_errors.append(type(error).__name__ + ":" + str(error))
                    child.returncode = 1
                finally:
                    os.close(write_out)
                    os.close(write_err)
            worker = threading.Thread(target=run_a, name="fake-A")
            self.threads.append(worker)
            worker.start()
            return child
        self.case.assertIn("--leaf", command)
        self.case.assertEqual(self.creations, [self.A])
        self.case.assertTrue((self.root / "release-A.json").is_file())
        a = probe.owned(probe.read(self.root, "A-ownership.json"))
        self.case.assertEqual(a["pid"], self.A)
        self.creations.append(self.B)
        self.trace.append("create-B")
        child = self.Child(self.B)
        self.children[self.B] = child
        probe.publish(outer, self.root, "B-ready.json", {"pid": self.B, "scope_id": probe.SCOPE_ID})
        return child

    class Child:
        def __init__(self, pid):
            self.pid, self.returncode = pid, None

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            deadline = time.monotonic() + timeout
            while self.returncode is None and time.monotonic() < deadline:
                time.sleep(.001)
            if self.returncode is None:
                raise subprocess.TimeoutExpired("fake-subject", timeout)
            return self.returncode

    def exercise(self):
        # Replace only audited OS seams and interpreter-local signal domains;
        # execute the actual outer helper, supervisor, desktop and shared client.
        signals = SimpleNamespace(SIGTERM=signal.SIGTERM, SIGKILL=signal.SIGKILL,
                                  getsignal=self.getsignal, signal=self.setsignal, alarm=lambda _n: 0)
        local_threading = SimpleNamespace(current_thread=lambda: 1, main_thread=lambda: 1)
        def spec_for(_name, path):
            self.case.assertIn(str(Path(path).relative_to(ROOT)),
                               ("tests/session/phase6_route_contract.py", "scripts/evidence/phase5_process.py"))
            return SimpleNamespace(path=path, loader=SimpleNamespace(exec_module=lambda _m: None))
        imports = SimpleNamespace(util=SimpleNamespace(spec_from_file_location=spec_for,
                    module_from_spec=lambda spec: route if str(spec.path).endswith("phase6_route_contract.py") else outer))
        before = len(denial.EVENTS)
        with mock.patch.object(probe, "load", side_effect=self.imported), \
             mock.patch.object(probe, "signal", signals), \
             mock.patch.object(outer, "signal", signals), \
             mock.patch.object(route, "signal", signals), \
             mock.patch.object(outer, "threading", local_threading), \
             mock.patch.object(route, "threading", local_threading), \
             mock.patch.object(desktop, "importlib", imports), \
             mock.patch.object(os, "getpid", side_effect=self.getpid), \
             mock.patch.object(subprocess, "Popen", side_effect=self.popen), \
             mock.patch.object(subprocess, "run", side_effect=self.status), \
             mock.patch.object(os, "killpg", side_effect=self.killpg), \
             mock.patch.object(route, "_process_group_exists", side_effect=lambda pid: self.children[pid].poll() is None), \
             mock.patch.object(route, "_process_group_rss_bytes", return_value=4096):
            packet = probe.controller(self.root)
            for worker in self.threads:
                worker.join(timeout=2)
                self.case.assertFalse(worker.is_alive(), "fake A must settle before mocks restore")
        self.case.assertEqual(len(denial.EVENTS), before, "unexpected audited OS seam")
        return packet


class NestedContracts(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="gw-nested-contract-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertFalse((self.root / "client").exists())
        self.assertEqual(list(self.root.rglob("*.bin")), [])
        self.environment = mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_actual_composition_cancels_only_after_both_durable_births(self):
        fake = FakeSubjects(self, self.root)
        packet = fake.exercise()
        self.assertEqual(fake.thread_errors, [])
        self.assertTrue(probe.oracle(packet), packet)
        self.assertTrue(packet["diagnostic_qualifying"])
        self.assertEqual(fake.creations, [fake.A, fake.B])
        self.assertEqual(fake.trace, ["create-A", "create-B", "cancel-A"])
        self.assertEqual(fake.signals, [(fake.A, signal.SIGTERM), (fake.B, signal.SIGTERM), (fake.A, signal.SIGTERM)])
        # The last A TERM is the existing outer helper's owned cleanup after
        # A has already returned; fake lookup must model ESRCH there.
        self.assertIn("tests/desktop/phase4_sessions.py", fake.loads)
        self.assertEqual(packet["historical_identity"], "UNKNOWN")
        self.assertEqual(packet["historical_liveness"], "UNKNOWN")
        self.assertLess(packet["root_bytes"], probe.DISK_CAP)
        self.assertEqual(packet["A_outcome"]["status"], "cancelled")
        self.assertEqual(packet["outer_returncode"], 130)
        # Every semantic control calls the actual acceptance consumer.
        edits = (
            ("outer_returncode", 0), ("outer_handler_restored", False),
            ("wall_seconds", 61), ("root_bytes", probe.DISK_CAP + 1),
            ("errors", ["unknown"]), ("B_ready", {"pid": fake.A}),
            ("A_settlement", {"pid": fake.A, "pgid": fake.A, "state": "active"}),
            ("B_settlement", {"pid": fake.B, "pgid": fake.B, "state": "group-remains"}),
        )
        for key, value in edits:
            broken = copy.deepcopy(packet)
            broken[key] = value
            with self.subTest(key=key):
                self.assertFalse(probe.oracle(broken))
        for section, key, value in (
                ("A_outcome", "cancellation_acknowledged", False),
                ("A_outcome", "handler_restored", False),
                ("signal_attempt", "call_returned", False),
                ("A_before_signal", "birth", "reused"),
                ("B_before_signal", "state", "absent")):
            broken = copy.deepcopy(packet)
            broken[section][key] = value
            with self.subTest(section=section, key=key):
                self.assertFalse(probe.oracle(broken))
        for subject in ("A", "B"):
            broken = copy.deepcopy(packet)
            broken[subject]["processes"][0]["process_group_cleanup"] = "unconfirmed"
            self.assertFalse(probe.oracle(broken))

    def test_observer_and_reuse_faults_cannot_signal_or_qualify(self):
        # Short fake-only deadlines bound negative readiness without waiting
        # for the proposed real envelope. Production constants remain fixed.
        for fault in ("observer-failed", "reuse", "signal-denied", "B-group-remains", "ignore-cancel"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir=self.root) as directory:
                fake = FakeSubjects(self, Path(directory), fault)
                with mock.patch.object(probe, "OUTER_SECONDS", .3), \
                     mock.patch.object(probe, "GATE_SECONDS", .15), \
                     mock.patch.object(probe, "READY_SECONDS", .2), \
                     mock.patch.object(probe, "INNER_SECONDS", .15):
                    packet = fake.exercise()
                self.assertFalse(probe.oracle(packet))
                if fault in ("reuse", "observer-failed"):
                    self.assertIs(packet["signal_attempt"]["attempted"], False)

    def test_default_cli_refuses_all_roles_before_import_or_launch(self):
        for argv in ([], ["--leaf", str(self.root)], ["--supervisor", str(self.root)]):
            with mock.patch.object(sys, "argv", ["probe", *argv]), \
                 mock.patch.object(probe, "load") as imported, \
                 self.assertRaisesRegex(SystemExit, "preparation-only"):
                probe.main()
            imported.assert_not_called()

    def test_separate_scope_and_bounded_leaf(self):
        production = json.loads((ROOT / "evidence/v02-execution.json").read_text())
        self.assertEqual(production["per_child_limits"]["cleanup_grace_seconds"], 30)
        self.assertEqual(probe.SCOPE["per_child_limits"]["cleanup_grace_seconds"], .25)
        self.assertIs(probe.SCOPE["historical_window_access"], False)
        self.assertNotEqual(probe.SCOPE["scope_id"], production["scope_id"])
        with mock.patch.object(probe.signal, "alarm") as alarm, \
             mock.patch.object(probe.time, "sleep") as sleep:
            self.assertEqual(probe.leaf(self.root), 1)
        alarm.assert_called_once_with(12)
        sleep.assert_called_once_with(10)

    def test_nominal_budget_fits_without_changing_production_grace(self):
        # Source-derived waits; allowances are explicitly unmeasured and no
        # user-space sum is a hard guarantee for blocked OS operations.
        helper_cleanup = .25 + 1.01 + 1 + 2 + 1.01 + 5 + 2 + 1
        conservative_outer_cleanup = helper_cleanup + 2
        estimate = 2 + probe.OUTER_SECONDS + .1 + conservative_outer_cleanup + 1 + 4 * probe.STATUS_SECONDS + 2
        self.assertAlmostEqual(helper_cleanup, 13.27)
        self.assertAlmostEqual(estimate, 59.37)
        self.assertLess(estimate, probe.TOTAL_SECONDS)
        # Cancellation requested by8s plus inner cleanup/fallbacks fits inside
        # outer supervision; the two cleanup paths overlap in elapsed time.
        self.assertLess(probe.READY_SECONDS + helper_cleanup + 4 + 2, probe.OUTER_SECONDS)

    def test_caps_and_unsafe_receipts_fail_closed(self):
        path = self.root / "receipt.json"
        path.write_bytes(b"x" * (probe.CAP + 1))
        with self.assertRaisesRegex(ValueError, "unsafe-diagnostic-receipt"):
            probe.read(self.root, path.name)
        with self.assertRaisesRegex(ValueError, "unsafe-diagnostic-owned-root"):
            probe.check_disk(self.root)
        path.unlink()
        path.symlink_to(self.root / "no-client")
        with self.assertRaises(ValueError):
            probe.check_disk(self.root)
        with self.assertRaises(ValueError):
            probe.write(io.StringIO(), {"payload": "x" * probe.CAP})

    def test_missing_admission_cannot_reach_process_boundary(self):
        os.environ.pop("GENEWHIP_PROCESS_CONTEXT")
        before = len(denial.EVENTS)
        with self.assertRaisesRegex(RuntimeError, "process-host-admission-required"):
            probe.controller(self.root)
        self.assertEqual(len(denial.EVENTS), before)

    def test_counterfactual_missing_fake_hits_sticky_denial(self):
        before = len(denial.EVENTS)
        with self.assertRaisesRegex(PermissionError, "sticky-process-and-signal-denial") as raised:
            outer.run([str(self.root / "no-client")], cwd=self.root)
        self.assertIsNone(raised.exception.process_receipt["pid"])
        self.assertEqual(denial.EVENTS[before:], ["subprocess.Popen"])
        denial.COUNTERFACTUALS.append({"label": "missing-fake-at-actual-outer-Popen",
                                     "events": denial.EVENTS[before:]})

    def outer_fake(self, **kwargs):
        child = mock.Mock(pid=720001, returncode=0)
        child.stdout, child.stderr = io.BytesIO(), io.BytesIO()
        child.poll.return_value = 0
        selector = mock.Mock()
        selector.get_map.return_value = {}
        return child, selector

    def test_outer_receipt_is_durable_before_callback_and_callback_failure_cleans(self):
        for stage in ("ok", "callback-failed", "cancel-in-callback", "cancel-in-popen"):
            with self.subTest(stage=stage):
                child, selector = self.outer_fake()
                called = []
                path = self.root / (stage + ".json")
                fsyncs = []
                original_fsync = os.fsync
                def fsync(fd):
                    fsyncs.append(json.loads(path.read_text())["processes"][0]["status"])
                    original_fsync(fd)
                def owned_callback(receipt):
                    called.append(receipt["pid"])
                    self.assertEqual(fsyncs, ["not-launched", "started"])
                    self.assertEqual(json.loads(path.read_text())["processes"], [receipt])
                    if stage == "callback-failed":
                        raise OSError("fake-owned-callback-failure")
                    if stage == "cancel-in-callback":
                        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                def spawn(*_args, **_kwargs):
                    if stage == "cancel-in-popen":
                        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                    return child
                prior = signal.getsignal(signal.SIGTERM)
                with path.open("w+") as stream, \
                     mock.patch.object(os, "fsync", side_effect=fsync), \
                     mock.patch.object(outer.selectors, "DefaultSelector", return_value=selector), \
                     mock.patch.object(subprocess, "Popen", side_effect=spawn), \
                     mock.patch.object(route, "_terminate_process_group", return_value=True) as cleanup:
                    if stage == "ok":
                        outer.run([str(self.root / "no-client")], cwd=self.root,
                                  process_receipt_stream=stream, ownership_callback=owned_callback)
                    else:
                        with self.assertRaises(OSError if stage == "callback-failed" else KeyboardInterrupt):
                            outer.run([str(self.root / "no-client")], cwd=self.root,
                                      process_receipt_stream=stream, ownership_callback=owned_callback)
                    cleanup.assert_called_once_with(child)
                self.assertEqual(called, [] if stage == "cancel-in-popen" else [child.pid])
                self.assertIs(signal.getsignal(signal.SIGTERM), prior)
                final = json.loads(path.read_text())["processes"][0]
                self.assertEqual(final["process_group_cleanup"], "confirmed")
                self.assertEqual(final["status"], "completed" if stage == "ok" else "failed")

    def test_outer_sink_failure_never_releases_gate_and_keeps_identity_after_birth(self):
        child, selector = self.outer_fake()
        callback = mock.Mock()
        for fail_at in (1, 2, 3):
            with self.subTest(fail_at=fail_at):
                runs, writes = [], []
                def fsync(_fd):
                    writes.append(True)
                    if len(writes) >= fail_at:
                        raise OSError("fake-fsync-failure")
                prior = signal.getsignal(signal.SIGTERM)
                with (self.root / f"sink-{fail_at}.json").open("w+") as stream, \
                     mock.patch.object(os, "fsync", side_effect=fsync), \
                     mock.patch.object(outer.selectors, "DefaultSelector", return_value=selector), \
                     mock.patch.object(subprocess, "Popen", return_value=child) as creation, \
                     mock.patch.object(route, "_terminate_process_group", return_value=True) as cleanup:
                    with self.assertRaisesRegex(OSError, "fake-fsync-failure"):
                        outer.run([str(self.root / "no-client")], cwd=self.root, runs=runs,
                                  process_receipt_stream=stream, ownership_callback=callback)
                    self.assertEqual(creation.call_count, 0 if fail_at == 1 else 1)
                    self.assertEqual(cleanup.call_count, 0 if fail_at == 1 else 1)
                self.assertIs(signal.getsignal(signal.SIGTERM), prior)
                self.assertEqual(runs[0]["pid"], None if fail_at == 1 else child.pid)
        self.assertEqual(callback.call_count, 1)  # only final-write failure releases after durable birth

    def test_owned_callbacks_require_actual_durable_scoped_sinks(self):
        with mock.patch.object(subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(ValueError, "durable receipt"):
                outer.run(["no-client"], cwd=self.root, ownership_callback=lambda _: None)
            with self.assertRaisesRegex(ValueError, "durable receipt"):
                route._run_client(self.root / "no-client", ["no-client"], [],
                                  report=self.root / "unused", timeout=1, ownership_callback=lambda _: None)
            with mock.patch.object(desktop, "EXECUTION_SCOPE", None):
                with self.assertRaisesRegex(ValueError, "scoped desktop"):
                    desktop.run(["no-client"], {}, ownership_callback=lambda _: None)
            spawn.assert_not_called()

    def test_malformed_ownership_and_status_never_qualify(self):
        for document in (None, {}, {"processes": [None]}, {"processes": None},
                         {"processes": [{"pid": True, "pgid": True}]},
                         {"processes": [{"pid": 9, "pgid": "9"}]}):
            with self.subTest(document=document), self.assertRaises(ValueError):
                probe.owned(document)
        self.assertFalse(probe.same_active(None, None))
        self.assertFalse(probe.oracle({"A": {"processes": [None]}}))
        entry = {"pid": 740001, "pgid": 740001}
        for result in (subprocess.CompletedProcess([], 0, "malformed", ""),
                       subprocess.CompletedProcess([], 2, "", "unavailable")):
            with mock.patch.object(subprocess, "run", return_value=result), self.assertRaises(ValueError):
                probe.observe(entry)

    def test_inner_callback_runs_after_fsync_and_cancellation_restores_handler(self):
        path = self.root / "inner.json"
        child = mock.Mock(pid=730001, returncode=-signal.SIGTERM)
        child.poll.return_value = None
        writes, callback_calls, runs = [], [], []
        original_fsync = os.fsync
        def fsync(fd):
            writes.append(json.loads(path.read_text())["processes"].copy())
            original_fsync(fd)
        def after_birth(entry):
            callback_calls.append(entry["pid"])
            self.assertEqual(len(writes), 2)
            self.assertEqual(writes[-1][0]["status"], "started")
            self.assertEqual(json.loads(path.read_text())["processes"], [entry])
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        prior = signal.getsignal(signal.SIGTERM)
        with path.open("w+") as stream, \
             mock.patch.object(os, "fsync", side_effect=fsync), \
             mock.patch.object(subprocess, "Popen", return_value=child), \
             mock.patch.object(route, "_terminate_process_group", return_value=True) as cleanup:
            with self.assertRaises(KeyboardInterrupt):
                route._run_client(self.root / "no-client", ["no-client"], runs,
                    report=self.root / "unused.json", timeout=1,
                    process_receipt_stream=stream, ownership_callback=after_birth)
            cleanup.assert_called_once()
        self.assertEqual(callback_calls, [child.pid])
        self.assertIs(signal.getsignal(signal.SIGTERM), prior)
        final = json.loads(path.read_text())["processes"][0]
        self.assertEqual(final["failure_type"], "KeyboardInterrupt")
        self.assertEqual(final["process_group_cleanup"], "confirmed")

    def test_source_mutations_of_both_durability_orders_are_detected(self):
        # Compile exact local source with one source change in memory. Run the
        # same semantic tests against it, under the already-sticky audit hook.
        mutations = (
            ("scripts/evidence/phase5_process.py", "outer",
             "        persist_receipt()\n        if cancelled:",
             "        # MUTANT omits birth durability\n        if cancelled:",
             "test_outer_receipt_is_durable_before_callback_and_callback_failure_cleans"),
            ("tests/session/phase6_route_contract.py", "route",
             "    def record_ownership():\n        persist_receipt()\n        if ownership_callback is not None:\n            ownership_callback(runs[-1])",
             "    def record_ownership():\n        if ownership_callback is not None:\n            ownership_callback(runs[-1])\n        persist_receipt()",
             "test_inner_callback_runs_after_fsync_and_cancellation_restores_handler"),
        )
        for relative, name, before, after, contract in mutations:
            with self.subTest(source=relative):
                source = (ROOT / relative).read_text()
                self.assertEqual(source.count(before), 1)
                mutant = types.ModuleType("nested_source_mutant_" + name)
                mutant.__file__ = str(ROOT / relative)
                exec(compile(source.replace(before, after), relative, "exec"), mutant.__dict__)
                if name == "outer":
                    mutant.process_boundary = lambda: route
                result = unittest.TestResult()
                with mock.patch.object(sys.modules[__name__], name, mutant):
                    NestedContracts(contract).run(result)
                self.assertGreater(len(result.failures), 0, "semantic test failed to kill source mutant")
                self.assertEqual(result.errors, [], "mutation must fail the intended assertion")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NestedContracts))
    denial.self_test("after-all-fakes-restored")
    exposure = denial.receipt()
    assert exposure["unexpected_denials"] == 0, exposure
    assert exposure["counterfactual_denials"] == 1, exposure
    print(json.dumps(exposure, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
