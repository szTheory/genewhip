#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded actual-caller retention contracts; fake ownership, no OS children.

Oracle: specified exact creation identity, terminal cleanup and cancellation
propagation, with real exclusive sinks and MeasurementJournal serialization.
"""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location("caller_sticky_denial",
    Path(__file__).with_name("phase7_sticky_denial.py"))
denial = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(denial)
denial.install()  # Independently tested before any production import.

import contextlib
import datetime
import importlib.abc
import json
import os
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2]
SOURCE_OVERRIDE = Path(os.environ.get("GW_CALLER_SOURCE_ROOT", str(SOURCE)))
REAL_SPEC = importlib.util.spec_from_file_location


def load(relative, name):
    path = SOURCE / relative
    spec = REAL_SPEC(name, path)
    module = importlib.util.module_from_spec(spec)
    override = SOURCE_OVERRIDE / relative
    if SOURCE_OVERRIDE != SOURCE and override.is_file():
        exec(compile(override.read_bytes(), str(path), "exec"), module.__dict__)
    else:
        spec.loader.exec_module(module)
    return module


boundary = load("tests/session/phase6_route_contract.py", "caller_boundary")
capture = load("scripts/evidence/phase5_process.py", "caller_capture")
smoke = load("scripts/evidence/v02_run.py", "caller_smoke")
inputs = load("tests/desktop/phase6_routes.py", "caller_inputs")
nested = load("tests/fixtures/phase4_game.py", "caller_nested")
game = load("tests/fixtures/phase6_game.py", "caller_game")
bench = load("tools/evidence/core_benchmark.py", "caller_bench")
CASES = []
MUTATIONS = []
FAKE_OWNERSHIPS = []


class AliasLoader(importlib.abc.Loader):
    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__dict__.update(boundary.__dict__)


def nested_spec(name, path, *args, **kwargs):
    if Path(path).name == "phase6_route_contract.py":
        return importlib.util.spec_from_loader(name, AliasLoader())
    if Path(path).name == "phase5_process.py":
        return REAL_SPEC(name, SOURCE / "scripts/evidence/phase5_process.py")
    return REAL_SPEC(name, path, *args, **kwargs)


class CallerContracts(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="gw-caller-fake-"))).resolve()
        self.build = self.root / "build"
        self.build.mkdir()
        # Empty markers satisfy preflights but cannot execute or supply ROM data.
        client = self.build / "tools/desktop/genewhip-desktop"
        client.parent.mkdir(parents=True)
        client.touch(mode=0o600)
        self.assertEqual(client.stat().st_size, 0)
        self.assertFalse(os.access(client, os.X_OK))
        self.assertEqual(list(self.root.rglob("*.bin")), [])
        (self.root / "fixtures/phase6").mkdir(parents=True)
        (self.root / "fixtures/phase6/recursion94-consumed-map-v1.json").write_text("{}")
        self.map = self.root / "map.json"
        self.map.write_text(json.dumps({"events": [{"effective_mask": 0}] * 19}))
        self.limits = {"wall_seconds": 10, "max_capture_bytes": 1024,
            "max_rss_bytes": 1024**3, "max_calls": 100, "max_binary_file_bytes": 1024}
        self.scope = {"scope_id": "fake-caller-scope", "per_child_limits": self.limits,
            "owned_roots": ["build"], "workload": {"serial_children": True, "max_fields": 5000},
            "qualification_batch": {"runtime_wall_seconds": 60, "benchmark_sub_batch_seconds": 60},
            "_scope_path": str(self.root / "scope.json")}
        (self.root / "scope.json").write_text("{}")
        for module in (smoke, inputs, nested, game, bench):
            self.patch(module, "ROOT", self.root)
        self.patch(bench, "_ACTIVE_JOURNAL", None)
        self.patch(bench, "ROM", self.root / "missing.rom")
        self.patch(bench, "_ACTIVE_BATCH_START", None)
        self.patch(bench, "_ACTIVE_QUALIFICATION_START", None)
        self.stack.enter_context(mock.patch.dict(os.environ,
            {"GENEWHIP_PROCESS_CONTEXT": boundary.HOST_PROCESS_CONTEXT}))
        self.stack.enter_context(mock.patch("importlib.util.spec_from_file_location", side_effect=nested_spec))
        self.calls = 0
        self.files = []
        self.error = RuntimeError("fake-monitor-error")
        self.cleanup = "confirmed"
        self.prior_handler = signal.getsignal(signal.SIGTERM)
        self.patch(boundary, "_run_client_owned", self.owned)

    def patch(self, obj, name, value):
        return self.stack.enter_context(mock.patch.object(obj, name, value))

    def owned(self, client, command, runs, **kwargs):
        self.calls += 1
        FAKE_OWNERSHIPS.append(str(client.name))
        entry = {"pid": 810000 + self.calls, "pgid": 810000 + self.calls,
            "status": "started", "process_group_cleanup": "pending", "bound_violation": False}
        runs.append(entry)
        kwargs["_ownership_callback"]()
        # Read durable files BEFORE monitoring changes ownership state.
        owned_files = []
        for path in self.root.rglob("*.json"):
            raw = path.read_text()
            if not raw.strip():
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and data.get("processes") == [entry]:
                owned_files.append(path)
        self.assertTrue(owned_files, "no durable creation receipt at first monitoring")
        self.files.extend(owned_files)
        if bench._ACTIVE_JOURNAL:
            data = json.loads(bench._ACTIVE_JOURNAL.path.read_text())
            self.assertEqual(data["children"][-1]["resource_receipt"], entry)
            self.assertEqual(data["observed_exposure"]["child_process_starts"], 1)
        entry.update(status="failed" if self.error else "exited",
            process_group_cleanup=self.cleanup)
        if self.error:
            raise self.error
        return subprocess.CompletedProcess(command, 0, json.dumps({"schema": bench.RUN_SCHEMA,
            "mode": "aggregate", "diagnostics_enabled": False}), "")

    def assert_retained(self, label):
        self.assertEqual(self.calls, 1, "actual named caller did not reach fake owned seam exactly once")
        self.assertTrue(self.files)
        for path in self.files:
            data = json.loads(path.read_text())
            self.assertEqual(data["processes"][0]["pid"], 810001)
            self.assertEqual(data["processes"][0]["pgid"], 810001)
            self.assertEqual(data["processes"][0]["process_group_cleanup"], self.cleanup)
        self.assertIs(signal.getsignal(signal.SIGTERM), self.prior_handler)
        CASES.append(label)

    def smoke_call(self, host=False):
        compiler = types.SimpleNamespace(compile_routes=lambda *_: {"routes": [
            {"fixture": "recursion94", "case": {"id": "full-route"}}]},
            lower_route=lambda *_args, **_kwargs: (b"fake-plan", {}),
            SOURCES={"recursion94": [0, 0, 0, "missing.rom"]})
        fixture = types.SimpleNamespace(compiler=compiler, set_execution_scope=lambda *_: None,
            freeze_candidate=lambda *_: {}, shared_launch=None)
        def collect(build, route, mapping, candidate, work, *_args, **_kwargs):
            work.mkdir()
            if host:
                (work / "native.json").write_text("{}")
                return {"status": "synthetic-placeholder", "completed_fields": 0,
                    "predicate_results": [], "process": {}, "compiled_sha256": "fake-plan"}
            return fixture.shared_launch(work / "missing-client", ["missing-client"], work, work / "native.json", 10)
        fixture.collect_case = collect
        modules = {"gw_v02_smoke_boundary": boundary, "gw_v02_smoke_fixture": fixture,
            "gw_v02_smoke_desktop": types.SimpleNamespace(set_execution_scope=lambda *_: None),
            "gw_smoke_receipt": capture}
        self.patch(smoke, "_module", lambda path, name: modules[name])
        self.patch(smoke, "validate_execution_scope", lambda *_: (self.scope, self.limits))
        self.patch(smoke, "plan_mode", lambda *_: {})
        self.patch(smoke, "_isolation_preflight", lambda *_: {})
        return smoke.run_smoke(self.build, self.root / "scope.json", self.root / "smoke.json")

    def input_call(self, backend):
        self.patch(inputs.phase6_game, "_EXECUTION_SCOPE", self.scope)
        self.patch(inputs.compiler, "validate_delivery_map", lambda *_args, **_kwargs: None)
        self.patch(inputs, "process_contract", boundary)
        self.patch(inputs, "load_module", lambda *_: capture)
        return inputs.input_contract(self.build, self.map, self.root / "output.json", self.root / "candidate.json", backend)

    def nested_call(self):
        self.patch(nested, "V02_EXECUTION_SCOPE", self.scope)
        self.patch(nested, "PROCESS_RECEIPTS", [])
        self.patch(nested, "PROCESS_RECEIPT_PATH", self.root / "aggregate.json")
        return nested.bounded_run([str(self.build / "missing-client"), "--dump-fields",
            str(self.root / "fields.json")], timeout=10)

    def benchmark_call(self, kind):
        v02 = types.SimpleNamespace(validate_execution_scope=lambda *_: (self.scope, self.limits),
            available_memory_bytes=lambda: 8 * 1024**3, require_memory_reserve=lambda *_: None)
        self.patch(bench, "load_v02_launcher", lambda: v02)
        self.patch(bench, "load_route_contract", lambda: boundary)
        if kind not in ("route", "route-tank"):
            self.patch(bench, "_ACTIVE_JOURNAL", bench.MeasurementJournal(self.root / "attempt.json", 1))
        if kind == "measured":
            return bench.run_child(self.build / "missing-client", "aggregate", False, 120, 600,
                rom=self.root / "missing.rom", repetition=1)
        if kind == "reference":
            return bench.run_control_reference(self.build, self.scope, self.limits)
        self.patch(bench, "source_identity", lambda: "fake-source")
        self.patch(bench.platform, "system", lambda: "Darwin")
        self.patch(bench, "build_identity", lambda *_: {"cmake": {}})
        title = "tank-battle" if kind == "route-tank" else "recursion94"
        routes = types.SimpleNamespace(compile_routes=lambda *_: {"routes": [
            {"fixture": title, "case": {"id": "full-route"}}]},
            lower_route=lambda *_args, **_kwargs: (b"fake-plan", {}), SOURCES={title: [0, 0, 0, "missing.rom"]})
        self.patch(bench, "load_phase6_routes", lambda: routes)
        (self.build / "v02").mkdir(exist_ok=True)
        return bench.run_workload(self.build, title, self.root / "scope.json", self.build / "v02/out.json")

    def check_journal(self):
        journal = bench._ACTIVE_JOURNAL
        data = json.loads(journal.path.read_text())
        self.assertEqual(data["status"], "non-qualifying")
        self.assertEqual(data["children"][0]["status"], "failed")
        self.assertEqual(data["children"][0]["resource_receipt"]["pid"], 810001)
        self.assertEqual(data["children"][0]["resource_receipt"]["process_group_cleanup"], self.cleanup)
        self.assertEqual(data["observed_exposure"]["child_launch_attempts"], 1)
        self.assertEqual(data["observed_exposure"]["child_process_starts"], 1)

    def test_actual_original_control_dispatch(self):
        self.patch(game, "_EXECUTION_SCOPE", self.scope)
        self.patch(game.compiler, "validate_delivery_map", lambda *_: None)
        self.patch(game.compiler, "compile_routes", lambda: {"routes": []})
        for name in ("preflight_compiled_roster", "freeze_candidate", "freeze_build_provenance",
                "reader_provenance", "validation_identities", "contextual_stages"):
            self.patch(game, name, lambda *_: {})
        now = datetime.datetime.now(datetime.timezone.utc)
        window = {"workload_cutoff": (now + datetime.timedelta(hours=1)).isoformat(),
            "workload_wall_seconds": 0, "started_at": now.isoformat(), "deadline": now.isoformat()}
        self.patch(game, "_read_window", lambda: window)
        self.patch(game, "_write_window", lambda *_: None)
        def dispatch(client, command, work, report, timeout):
            self.assertIn("--execution-scope", command)
            self.assertIn("--process-receipt", command)
            destination = Path(command[command.index("--process-receipt") + 1])
            self.assertEqual(destination, work / "nested-processes.json")
            self.patch(nested, "V02_EXECUTION_SCOPE", self.scope)
            self.patch(nested, "PROCESS_RECEIPTS", [])
            self.patch(nested, "PROCESS_RECEIPT_PATH", destination)
            return nested.bounded_run([str(client), "--dump-fields", str(work / "artifacts/fields.json")], timeout=10)
        self.patch(game, "shared_launch", dispatch)
        with self.assertRaises(RuntimeError) as caught:
            game.core(self.build, self.map, self.root / "candidate.json", self.root / "core.json")
        self.assertIs(caught.exception, self.error)
        self.assert_retained("actual-original-control-dispatch")
        aggregate = list(self.root.rglob("nested-processes.json"))
        self.assertEqual(len(aggregate), 1)
        self.assertEqual(json.loads(aggregate[0].read_text())["processes"][0]["pid"], 810001)

    def test_successful_measured_child_still_completes(self):
        self.error = None
        result = self.benchmark_call("measured")
        self.assertEqual(result["process_id"], 810001)
        self.assert_retained("measured-success-neighbor")
        data = json.loads(bench._ACTIVE_JOURNAL.path.read_text())
        self.assertEqual(data["children"][0]["status"], "completed")
        self.assertEqual(data["observed_exposure"]["timed_child_starts"], 1)

    def test_nested_success_keeps_distinct_child_receipts(self):
        self.error = None
        self.nested_call()
        result = nested.bounded_run([str(self.build / "missing-client"), "--dump-fields",
            str(self.root / "fields.json")], timeout=10)
        self.assertEqual(result.returncode, 0)
        files = sorted(self.root.glob("bounded-child-process-*.json"))
        self.assertEqual(len(files), 2)
        self.assertEqual([json.loads(path.read_text())["processes"][0]["pid"] for path in files], [810001, 810002])
        self.assertEqual(len(nested.PROCESS_RECEIPTS), 2)
        CASES.append("nested-success-two-distinct-children")

    def test_receipt_collision_rejects_without_launch_or_overwrite(self):
        path = self.root / "bounded-child-process-0000.json"
        path.write_bytes(b"preserved-old-receipt\n")
        with self.assertRaises(FileExistsError):
            self.nested_call()
        self.assertEqual(self.calls, 0)
        self.assertEqual(path.read_bytes(), b"preserved-old-receipt\n")
        CASES.append("nested-existing-receipt-rejected")

    def test_preownership_benchmark_cancellation_counts_zero_starts(self):
        def cancelled(*_args, **_kwargs):
            raise KeyboardInterrupt("fake-before-ownership")
        self.patch(boundary, "_run_client_owned", cancelled)
        with self.assertRaises(KeyboardInterrupt):
            self.benchmark_call("measured")
        data = json.loads(bench._ACTIVE_JOURNAL.path.read_text())
        self.assertEqual(data["status"], "non-qualifying")
        self.assertEqual(data["observed_exposure"]["child_launch_attempts"], 1)
        self.assertEqual(data["observed_exposure"]["child_process_starts"], 0)
        self.assertIsNone(data["children"][0]["resource_receipt"])
        CASES.append("benchmark-preownership-cancel-zero-starts")

    def test_source_mutations_are_rejected_by_actual_callers(self):
        mutations = (
            ("smoke", "scripts/evidence/v02_run.py", "process_receipt_stream=receipt_stream", "process_receipt_stream=None", "test_smoke_cancel_confirmed"),
            ("inputs", "tests/desktop/phase6_routes.py", "process_receipt_stream=receipt_stream", "process_receipt_stream=None", "test_input_native_cancel_confirmed"),
            ("nested", "tests/fixtures/phase4_game.py", "process_receipt_stream=receipt_stream", "process_receipt_stream=None", "test_nested_cancel_confirmed"),
            ("game", "tests/fixtures/phase6_game.py", ',\n                    "--process-receipt",str(work/"nested-processes.json")', "", "test_actual_original_control_dispatch"),
            ("bench", "tools/evidence/core_benchmark.py", "except BaseException as error:\n        if journal:", "except Exception as error:\n        if journal:", "test_measured_cancel_confirmed"),
            ("bench", "tools/evidence/core_benchmark.py", 'journal_entry["resource_receipt"] = receipt', "pass  # missing creation ownership", "test_reference_cancel_confirmed"),
        )
        for name, relative, before, after, selected in mutations:
            with self.subTest(source=relative, mutation=before):
                source = (SOURCE / relative).read_text()
                self.assertEqual(source.count(before), 1)
                mutant = types.ModuleType("caller_mutant_" + name)
                mutant.__file__ = str(SOURCE / relative)
                exec(compile(source.replace(before, after), relative, "exec"), mutant.__dict__)
                result = unittest.TestResult()
                count = len(CASES)
                with mock.patch.object(sys.modules[__name__], name, mutant):
                    CallerContracts(selected).run(result)
                del CASES[count:]
                self.assertTrue(result.failures, "actual-caller assertion must kill the source mutant")
                self.assertEqual(result.errors, [], "kill must be an intended assertion, not an import/error accident")
                MUTATIONS.append(relative + ":" + selected)
        CASES.append("six-source-mutations-rejected")


def contract(caller, outcome):
    def run(self):
        if outcome == "cancel-confirmed":
            self.error = KeyboardInterrupt("fake-deferred-cancellation")
        elif outcome == "cancel-unconfirmed":
            self.error = KeyboardInterrupt("fake-deferred-cancellation")
            self.cleanup = "unconfirmed"
        elif outcome == "cleanup-unconfirmed":
            self.error = RuntimeError("fake-unconfirmed-cleanup")
            self.cleanup = "unconfirmed"
        call = {"smoke": self.smoke_call, "smoke-host": lambda: self.smoke_call(host=True),
            "input-software": lambda: self.input_call("software"),
            "input-native": lambda: self.input_call("native"), "nested": self.nested_call,
            "route": lambda: self.benchmark_call("route"),
            "route-tank": lambda: self.benchmark_call("route-tank"),
            "measured": lambda: self.benchmark_call("measured"),
            "reference": lambda: self.benchmark_call("reference")}[caller]
        with self.assertRaises(type(self.error)) as caught:
            call()
        self.assertIs(caught.exception, self.error, "caller must propagate the original exception")
        self.assert_retained(caller + ":" + outcome)
        if caller in ("route", "route-tank", "measured", "reference"):
            self.check_journal()
        if caller == "nested":
            self.assertEqual(json.loads((self.root / "aggregate.json").read_text())["processes"], nested.PROCESS_RECEIPTS)
    return run


for _caller in ("smoke", "smoke-host", "input-software", "input-native", "nested", "route", "route-tank", "measured", "reference"):
    for _outcome in ("monitor-error", "cleanup-unconfirmed", "cancel-confirmed", "cancel-unconfirmed"):
        setattr(CallerContracts, "test_" + _caller.replace("-", "_") + "_" + _outcome.replace("-", "_"),
            contract(_caller, _outcome))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CallerContracts)
    if SOURCE_OVERRIDE != SOURCE:
        # The baseline overlay measures the 41 driving/neighbor contracts;
        # source mutation checks independently exercise current source only.
        suite = unittest.TestSuite(test for test in suite
            if test._testMethodName != "test_source_mutations_are_rejected_by_actual_callers")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    denial.self_test("after-fakes-restored")
    exposure = denial.receipt()
    assert exposure["unexpected_denials"] == 0, exposure
    assert exposure["real_child_starts"] == 0, exposure
    print(json.dumps({"tests_run": result.testsRun, "completed_cases": len(CASES),
        "source_mutants_killed": len(MUTATIONS), "fake_owned_calls": len(FAKE_OWNERSHIPS),
        "failures": len(result.failures), "errors": len(result.errors), "exposure": exposure}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
