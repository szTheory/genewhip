#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure contracts for the one-case native diagnostic collector."""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MAP_MASKS = [8, 0, 8, 0, 8, 0, 32, 0, 8, 0, 32, 0, 1, 0, 8, 0, 2, 0, 16]
ROUTE_MASKS = [8, 0, 8, 0, 32, 0, 8, 0, 32, 0, 1, 0, 8, 0, 2, 0, 16, 0]


def load(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError("native-diagnostic-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = load("scripts/evidence/v02_run.py", "phase7_native_diagnostic_runner")


class FakeCompiler:
    compile_clients: list[str] = []
    lowered_clients: list[str] = []

    @staticmethod
    def compile_routes(_mapping=None, _client="public-core"):
        FakeCompiler.compile_clients.append(_client)
        return {"routes": [{"fixture": "recursion94", "case": {"id": "withhold-first-plate"}}]}

    @staticmethod
    def lower_route(_route, **kwargs):
        FakeCompiler.lowered_clients.append(kwargs.get("client"))
        return b"bounded fake route", {}

    @staticmethod
    def canonical_digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class FakeFixture:
    compiler = FakeCompiler()

    def __init__(self, root: Path, calls: list[str], fail_core: bool = False,
                 fail_core_receipt_only: bool = False, malformed_core_receipt: bool = False):
        self.root, self.calls, self.fail_core = root, calls, fail_core
        self.fail_core_receipt_only = fail_core_receipt_only
        self.malformed_core_receipt = malformed_core_receipt
        self.scope = None

    def set_execution_scope(self, scope):
        self.scope = scope

    @staticmethod
    def canonical_sha(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def freeze_candidate(self, _build, _mapping, output):
        candidate = {"schema": "fake-candidate"}
        output.write_text(json.dumps(candidate))
        return candidate

    def collect_case(self, _build, _route, _mapping, _candidate, work, repetition, remaining, compiled_binary=None):
        self.calls.append("headless-reference")
        assert repetition == 1 and 0 < remaining <= 600 and compiled_binary == b"bounded fake route"
        work.mkdir(mode=0o700)
        if self.fail_core_receipt_only:
            (work / "process.json").write_text("{" if self.malformed_core_receipt else json.dumps({"processes": [{
                "status": "unconfirmed", "return_code": 17,
                "process_group_cleanup": "unconfirmed", "bound_violation": True,
            }]}))
            raise RuntimeError("synthetic-core-cleanup-failure")
        (work / "fields").mkdir()
        native = work / "native.json"
        core_events = [{"port": 0, "desired": mask, "effective": mask,
            "joystick_mask": mask} for mask in ROUTE_MASKS]
        native.write_text(json.dumps({"status": 0, "active_ticks": 3600, "fields": 3631,
            "boundary_calls": 99, "inputs": core_events}))
        row = {"fixture": "recursion94", "case": "withhold-first-plate", "repetition": 1,
            "client": "public-core", "status": "pass", "native_report": {
                "path": str(native.relative_to(self.root))},
            "predicate_results": {
                "early_dependency_interaction": {"reached": False, "value": 0, "field": 0},
                "two_echoes_at_boot_cap": {"reached": True, "value": 2, "field": 1441},
                "crossed_generated_door": {"reached": True, "value": 1, "field": 3530},
                "late_program_stable": {"reached": True, "value": 1, "field": 3600}},
            "process": {"return_code": 0, "status": "completed", "process_group_cleanup": "confirmed",
                "bound_violation": False}}
        (work / "run.json").write_text(json.dumps(row))
        if self.fail_core:
            row["status"] = "fail"
            (work / "run.json").write_text(json.dumps(row))
            raise RuntimeError("synthetic-core-failure")
        return row


class FakeDesktop:
    compiler = FakeCompiler()

    def __init__(self, calls: list[str], input_ok: bool = True, host_ok: bool = True,
                 input_mutation: str | None = None):
        self.calls, self.input_ok, self.host_ok = calls, input_ok, host_ok
        self.input_mutation = input_mutation
        self.scope = None

    def set_execution_scope(self, scope):
        self.scope = scope

    def input_contract(self, _build, _mapping, output, _candidate, backend):
        self.calls.append("input-contract")
        assert backend == "native"
        events = [{"effective_mask": mask} for mask in MAP_MASKS]
        expected = [(0, event["effective_mask"]) for event in events] + [(1, 2), (1, 0), (1, 16), (1, 0)]
        observations = [{"port": port, "requested_mask": mask, "effective_mask": mask,
            "joystick_mask": mask if port == 0 else 0} for port, mask in expected]
        proof = {"schema": "genewhip-phase6-sdl-virtual-input-contract-v1",
            "backend": "native", "video_driver": "cocoa", "rom_used": False,
            "delivery_map_sha256": self.compiler.canonical_digest({"events": events}),
            "desktop_sha256": hashlib.sha256(b"fake executable identity").hexdigest(),
            "desktop_source_sha256": hashlib.sha256(b"fake desktop source").hexdigest(),
            "outcome": "pass" if self.input_ok else "fail", "requested_count": 23,
            "port_isolation_verified": True, "observations": observations,
            "process": {"return_code": 0, "status": "completed",
                "process_group_cleanup": "confirmed" if self.input_ok else "unconfirmed",
                "bound_violation": False}}
        if self.input_mutation == "mask":
            proof["observations"][0]["effective_mask"] = 31
        elif self.input_mutation == "bound":
            proof["process"]["bound_violation"] = True
        elif self.input_mutation == "return":
            proof["process"]["return_code"] = 1
        output.write_text("{" if self.input_mutation == "invalid-json" else json.dumps(proof))
        return 0 if self.input_ok else 1

    def _retained_host_case(self, _build, _desktop, _route, _mapping, _core, _core_path,
                            backend, work, _candidate):
        self.calls.append("native-sdl-comparison")
        assert backend == "native"
        native_events = [{"port": 0, "desired": mask, "effective": mask,
            "joystick_mask": mask} for mask in ROUTE_MASKS]
        host_events = [{"port": 0, "requested_mask": mask, "effective_mask": mask,
            "handler": "SDL_Gamepad/sample_port"} for mask in ROUTE_MASKS]
        diagnostic_dir = runner.ROOT / "build/v02/diagnostic-host"
        diagnostic_dir.mkdir(parents=True, exist_ok=True)
        native_path, host_path = diagnostic_dir / "native.json", diagnostic_dir / "host.json"
        native_path.write_text(json.dumps({"status": 0, "active_ticks": 3600, "fields": 3631,
            "boundary_calls": 99, "inputs": native_events}))
        host_path.write_text(json.dumps({"input_events": host_events}))
        return {"fixture": "recursion94", "case": "withhold-first-plate", "backend": "native",
            "status": "pass" if self.host_ok else "fail", "core_outcome": "pass",
            "host_outcome": "pass-diagnostic" if self.host_ok else "fail",
            "process": {"return_code": 0, "status": "completed", "process_group_cleanup": "confirmed",
                "bound_violation": False},
            "raw_outputs": {"native": {"path": "build/v02/diagnostic-host/native.json"},
                "host": {"path": "build/v02/diagnostic-host/host.json"}},
            "common_boundary": {"source_samples_equal": True, "renderer_pixel_equal": True,
                "full_pcm_equal": True, "inputs": {"equal": True, "core_count": 18, "host_count": 18,
            "rows": [{"index": index, "equal": True, "port": 0,
                        "desired": mask, "effective": mask}
                for index, mask in enumerate(ROUTE_MASKS)]}},
            "renderer": {"renderer_readback_activity": True},
            "audio": {"audio_device_activity": True, "audio_submitted_frames": 20,
                "audio_device_consumed_frames": 19}}


class NativeDiagnosticContract(unittest.TestCase):
    @staticmethod
    def public_identity():
        return {"source_sha": "a" * 40, "head_sha": "b" * 40,
            "base_sha": "c" * 40, "run_id": "12345", "run_attempt": "1"}

    @classmethod
    def public_report(cls, result, outer=None, root=None):
        with mock.patch.object(runner, "ROOT", root or runner.ROOT):
            report = runner.safe_native_diagnostic(result, outer)
        report.update({"identity": cls.public_identity(), "outer_rejection": None})
        return report

    def run_pipeline(self, *, input_ok=True, host_ok=True, fail_core=False,
                     fail_core_receipt_only=False, malformed_core_receipt=False,
                     input_mutation=None, clock=True):
        temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for directory in ("batch", "build/v02", "fixtures/phase6", "tools/desktop"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        mapping = {"events": [{"effective_mask": mask} for mask in MAP_MASKS]}
        (root / "fixtures/phase6/recursion94-consumed-map-v1.json").write_text(json.dumps(mapping))
        (root / "tools/desktop/main_sdl.c").write_text("fake desktop source")
        build = root / "build/v02/build"
        build.mkdir()
        (build / "tools/desktop").mkdir(parents=True)
        (build / "tools/desktop/genewhip-desktop").write_bytes(b"fake executable identity")
        scope_path = root / "scope.json"
        scope_path.write_text("{}")
        out = root / "batch/diagnostic.json"
        start = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scope = {"owned_roots": ["batch", "build/v02"], "qualification_batch": {"runtime_wall_seconds": 64800}}
        limits = {"wall_seconds": 600}
        FakeCompiler.compile_clients.clear()
        FakeCompiler.lowered_clients.clear()
        calls: list[str] = []
        fixture = FakeFixture(root, calls, fail_core, fail_core_receipt_only, malformed_core_receipt)
        desktop = FakeDesktop(calls, input_ok, host_ok, input_mutation)
        process_module = object()

        def module_loader(path, name):
            if "phase6_game.py" in str(path):
                return fixture
            if "phase6_routes.py" in str(path):
                return desktop
            return process_module

        now = datetime.datetime.fromisoformat(start) + datetime.timedelta(seconds=1)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(runner, "ROOT", root))
            stack.enter_context(mock.patch.object(runner, "validate_execution_scope", return_value=(scope, limits)))
            stack.enter_context(mock.patch.object(runner, "_module", side_effect=module_loader))
            stack.enter_context(mock.patch.object(runner, "_isolation_preflight", return_value={"production_child_starts": 0}))
            dt = stack.enter_context(mock.patch.object(runner.datetime, "datetime", wraps=datetime.datetime))
            dt.now.return_value = now
            stack.enter_context(mock.patch.dict(os.environ, {"GENEWHIP_QUALIFICATION_STARTED_AT": start,
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GENEWHIP_NATIVE_DIAGNOSTIC_CASE": "recursion94-withhold-first-plate"}, clear=False))
            result = runner.run_native_diagnostic(build, scope_path, out)
        return result, calls, out, root

    def test_exact_three_stage_order_and_safe_output(self):
        result, calls, out, root = self.run_pipeline()
        self.assertEqual(calls, ["input-contract", "headless-reference", "native-sdl-comparison"])
        self.assertEqual(FakeCompiler.compile_clients, ["public-core", "sdl"])
        self.assertEqual(FakeCompiler.lowered_clients, ["public-core"])
        self.assertEqual([row["name"] for row in result["stages"]], list(runner._NATIVE_DIAGNOSTIC_STAGES))
        self.assertEqual(result["status"], "pass")
        self.assertIs(result["qualification_accepted"], False)
        safe = runner.safe_native_diagnostic(result, {"returncode": 0, "launch_error": None, "processes": [{"return_code": 0,
            "status": "completed", "process_group_cleanup": "confirmed", "bound_violation": False}],
            "process_group_cleanup": "confirmed"})
        self.assertEqual(safe["status"], "pass")
        self.assertTrue(safe["diagnostic_only"])
        self.assertEqual(safe["stages"][0]["input"]["requested_count"], 23)
        self.assertEqual(len(safe["stages"][0]["input"]["masks"]), 23)
        route = safe["stages"][1]["route"]
        self.assertEqual(route["active_ticks"], 3600)
        self.assertEqual(route["predicate_count"], 4)
        self.assertEqual([item["id"] for item in route["predicates"]], [
            "early_dependency_interaction", "two_echoes_at_boot_cap",
            "crossed_generated_door", "late_program_stable"])
        self.assertEqual(route["predicates"][0], {"id": "early_dependency_interaction",
            "reached": False, "value": 0, "field": 0})
        text = json.dumps(safe)
        for forbidden in (str(root), "fake executable", "private-workload", "candidate_sha256", "renderer-field.bin"):
            self.assertNotIn(forbidden, text)
        private = json.loads((out.parent / out.stem / "private-workload.json").read_text())
        self.assertEqual(private["private_workload"]["headless_row"]["case"], "withhold-first-plate")
        inconsistent_outer = {"returncode": 0, "launch_error": None, "process_group_cleanup": "unconfirmed",
            "processes": [{"return_code": 0, "status": "completed", "process_group_cleanup": "confirmed",
                "bound_violation": False}]}
        self.assertEqual(runner.safe_native_diagnostic(result, inconsistent_outer)["status"], "fail")

    def test_raw_stage_names_must_be_exact_and_ordered(self):
        record = {"status": "pass", "stages": [
            {"name": name, "status": "pass", "process": {"status": "completed", "return_code": 0,
                "process_group_cleanup": "confirmed", "bound_violation": False}}
            for name in runner._NATIVE_DIAGNOSTIC_STAGES]}
        outer = {"returncode": 0, "launch_error": None, "process_group_cleanup": "confirmed",
            "processes": [{"return_code": 0, "status": "completed", "process_group_cleanup": "confirmed",
                "bound_violation": False}]}
        self.assertEqual(runner.safe_native_diagnostic(record, outer)["status"], "pass")
        wrong_name = json.loads(json.dumps(record))
        wrong_name["stages"][1]["name"] = "native-sdl-comparison"
        self.assertEqual(runner.safe_native_diagnostic(wrong_name, outer)["status"], "fail")
        reordered = json.loads(json.dumps(record))
        reordered["stages"][1], reordered["stages"][2] = reordered["stages"][2], reordered["stages"][1]
        self.assertEqual(runner.safe_native_diagnostic(reordered, outer)["status"], "fail")

    def test_public_consumer_validates_pass_and_partial_failure_without_reprojection(self):
        result, _calls, _out, _root = self.run_pipeline()
        outer = {"returncode": 0, "launch_error": None, "process_group_cleanup": "confirmed",
            "processes": [{"return_code": 0, "status": "completed",
                "process_group_cleanup": "confirmed", "bound_violation": False}],
            "process_group_cleanup": "confirmed"}
        report = self.public_report(result, outer, _root)
        expected = self.public_identity()
        self.assertTrue(runner.validate_native_diagnostic_public(report, expected))

        failed, _calls, _out, _root = self.run_pipeline(input_ok=False)
        partial = self.public_report(failed, root=_root)
        self.assertEqual(partial["status"], "fail")
        self.assertTrue(runner.validate_native_diagnostic_public(partial, expected))

        mutations = []
        def changed(change):
            value = json.loads(json.dumps(report))
            change(value)
            mutations.append(value)
        changed(lambda value: value.update(qualification_accepted=True))
        changed(lambda value: value["identity"].update(source_sha="d" * 40))
        changed(lambda value: value["identity"].update(run_id="54321"))
        changed(lambda value: value.update(case="other-case"))
        changed(lambda value: value["stages"][1].update(name="native-sdl-comparison"))
        changed(lambda value: value["stages"].reverse())
        changed(lambda value: value["outer_process"].update(cleanup="unconfirmed"))
        changed(lambda value: value["stages"][2].update(path="/private/secret"))
        changed(lambda value: value["stages"][2]["comparison"].update(device_name="private device"))
        changed(lambda value: value["stages"][0]["input"].update(outcome="unavailable"))
        changed(lambda value: value["stages"][0]["input"].update(requested_count="missing"))
        changed(lambda value: value["stages"][0]["input"].update(port_isolation_verified=False))
        changed(lambda value: value["stages"][0]["input"]["masks"].__setitem__(0, 0))
        changed(lambda value: value["stages"][0]["input"]["observations"][0].update(requested_mask=0))
        changed(lambda value: value["stages"][0]["input"]["observations"][0].update(effective_mask=0))
        changed(lambda value: value["stages"][0]["input"]["observations"][0].update(joystick_mask=0))
        changed(lambda value: value["stages"][0]["input"]["observations"][19].update(joystick_mask=1))
        changed(lambda value: value["stages"][0]["input"]["observations"][0].update(requested_mask=False))
        changed(lambda value: value["stages"][1]["route"].update(active_ticks=3599))
        changed(lambda value: value["stages"][1]["route"].update(status=False))
        changed(lambda value: value["stages"][1]["route"]["input_events"][0].update(port=1))
        changed(lambda value: value["stages"][1]["route"]["predicates"].pop())
        changed(lambda value: value["stages"][1]["route"]["predicates"][0].update(reached=True))
        changed(lambda value: value["stages"][1]["route"]["predicates"][1].update(value=0))
        changed(lambda value: value["stages"][2]["comparison"].update(input_equal=False))
        changed(lambda value: value["stages"][2]["comparison"].update(audio_device_activity=False))
        changed(lambda value: value["stages"][2]["comparison"].update(native_status=False))
        changed(lambda value: value["stages"][2]["comparison"]["input_rows"].pop())
        changed(lambda value: value["stages"][2]["comparison"]["input_rows"][0].update(port=False))
        changed(lambda value: value["stages"][2]["comparison"]["native_input_events"][0].update(port=False))
        def substitute_comparison(value):
            facts = value["stages"][2]["comparison"]
            facts["input_rows"][0].update(desired=255, effective=255)
            for key in ("native_input_events", "host_input_events"):
                facts[key][0].update(requested_mask=255, effective_mask=255)
        changed(substitute_comparison)
        changed(lambda value: value["stages"][1]["route"]["input_events"][0].update(effective_mask=0))
        for index, invalid in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaisesRegex(ValueError, "^phase7-native-diagnostic-public-report-invalid$"):
                    runner.validate_native_diagnostic_public(invalid, expected)

    def test_actual_full_scope_validation_exposes_native_caps_without_fake_flag(self):
        scope, limits = runner.validate_execution_scope(ROOT / "evidence/v02-execution.json", "full")
        self.assertEqual(scope["scope_id"], "phase7-serial-child-workloads")
        self.assertNotIn("require_native", limits)
        self.assertEqual(limits["wall_seconds"], 600)
        self.assertTrue(limits["max_json_bytes"] > 0)

    def test_unconfirmed_input_stops_before_headless_or_native_comparison(self):
        result, calls, out, _ = self.run_pipeline(input_ok=False)
        self.assertEqual(calls, ["input-contract"])
        self.assertEqual(result["status"], "fail")
        self.assertEqual([row["status"] for row in result["stages"]], ["fail", "not-run", "not-run"])
        safe = runner.safe_native_diagnostic(result)
        self.assertEqual(safe["stages"][0]["process"]["cleanup"], "unconfirmed")
        self.assertIs(result["qualification_accepted"], False)
        self.assertTrue(out.exists())

    def test_invalid_input_masks_or_receipt_never_reaches_later_stage(self):
        for mutation in ("mask", "bound", "return", "invalid-json"):
            result, calls, _out, _root = self.run_pipeline(input_mutation=mutation)
            self.assertEqual(calls, ["input-contract"], mutation)
            self.assertEqual(result["status"], "fail", mutation)
            self.assertEqual([row["status"] for row in result["stages"]],
                ["fail", "not-run", "not-run"], mutation)

    def test_headless_failure_is_retained_and_prevents_native_comparison(self):
        result, calls, out, _ = self.run_pipeline(fail_core=True)
        self.assertEqual(calls, ["input-contract", "headless-reference"])
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stages"][1]["status"], "fail")
        self.assertEqual(result["stages"][2]["status"], "not-run")
        private = json.loads((out.parent / out.stem / "private-workload.json").read_text())
        self.assertEqual(private["failure_category"], "bounded-workload-failed")

    def test_headless_receipt_survives_cleanup_exception_before_run_json(self):
        result, calls, out, _ = self.run_pipeline(fail_core_receipt_only=True)
        self.assertEqual(calls, ["input-contract", "headless-reference"])
        self.assertEqual(result["failure_category"], "bounded-workload-failed")
        stage = result["stages"][1]
        self.assertEqual(stage["status"], "fail")
        self.assertEqual(stage["process"], {"status": "unconfirmed", "return_code": 17,
            "process_group_cleanup": "unconfirmed", "bound_violation": True})
        self.assertEqual(result["stages"][2]["status"], "not-run")
        safe = runner.safe_native_diagnostic(result)
        self.assertEqual(safe["stages"][1]["process"]["cleanup"], "unconfirmed")
        self.assertEqual(safe["stages"][1]["process"]["return_code"], "nonzero")
        self.assertTrue(out.exists())

    def test_malformed_owned_headless_receipt_does_not_mask_original_failure(self):
        result, calls, _out, _ = self.run_pipeline(
            fail_core_receipt_only=True, malformed_core_receipt=True)
        self.assertEqual(calls, ["input-contract", "headless-reference"])
        self.assertEqual(result["failure_category"], "bounded-workload-failed")
        self.assertEqual(result["stages"][1]["name"], "headless-reference")
        self.assertIsNone(result["stages"][1]["process"])
        self.assertEqual(result["stages"][2]["status"], "not-run")

    def test_host_failure_is_one_case_and_never_qualification(self):
        result, calls, _, _ = self.run_pipeline(host_ok=False)
        self.assertEqual(calls, ["input-contract", "headless-reference", "native-sdl-comparison"])
        self.assertEqual(result["status"], "fail")
        safe = runner.safe_native_diagnostic(result, {"returncode": 0, "launch_error": None, "processes": [{"return_code": 0,
            "status": "completed", "process_group_cleanup": "confirmed", "bound_violation": False}]})
        self.assertEqual(safe["stages"][2]["comparison"]["host_outcome"], "fail")
        self.assertIs(result["qualification_accepted"], False)

    def test_missing_start_clock_rejects_before_output_or_collector_load(self):
        with mock.patch.dict(os.environ, {"GENEWHIP_QUALIFICATION_STARTED_AT": "",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GENEWHIP_NATIVE_DIAGNOSTIC_CASE": "recursion94-withhold-first-plate"}, clear=False):
            with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
                root = Path(temporary)
                (root / "owned").mkdir()
                scope_path = root / "scope.json"
                build = root / "build"
                build.mkdir()
                out = root / "owned/result.json"
                with mock.patch.object(runner, "ROOT", root), \
                     mock.patch.object(runner, "validate_execution_scope", return_value=(
                         {"owned_roots": ["owned"], "qualification_batch": {"runtime_wall_seconds": 64800}},
                         {"require_native": True})), \
                     mock.patch.object(runner, "_module") as loader:
                    with self.assertRaisesRegex(ValueError, "start-required"):
                        runner.run_native_diagnostic(build, scope_path, out)
                    loader.assert_not_called()
                    self.assertFalse(out.exists())

    def test_future_start_clock_rejects_before_output_or_collector_load(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)
            (root / "owned").mkdir()
            build = root / "build"
            build.mkdir()
            out = root / "owned/result.json"
            future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=2)
            with mock.patch.dict(os.environ, {"GENEWHIP_QUALIFICATION_STARTED_AT": future.isoformat(),
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GENEWHIP_NATIVE_DIAGNOSTIC_CASE": "recursion94-withhold-first-plate"}, clear=False), \
                 mock.patch.object(runner, "ROOT", root), \
                 mock.patch.object(runner, "validate_execution_scope", return_value=(
                     {"owned_roots": ["owned"], "qualification_batch": {"runtime_wall_seconds": 64800}},
                     {"require_native": True})), \
                 mock.patch.object(runner, "_module") as loader:
                with self.assertRaisesRegex(ValueError, "start-in-future"):
                    runner.run_native_diagnostic(build, root / "scope.json", out)
                loader.assert_not_called()
                self.assertFalse(out.exists())

    def test_unknown_selector_rejects_before_scope_or_collector_work(self):
        with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch",
                "GENEWHIP_NATIVE_DIAGNOSTIC_CASE": "other"}, clear=False), \
             mock.patch.object(runner, "validate_execution_scope") as validate, \
             mock.patch.object(runner, "_module") as loader:
            with self.assertRaisesRegex(ValueError, "fixed-selector-required"):
                runner.run_native_diagnostic(Path("."), Path("scope"), Path("output"))
            validate.assert_not_called()
            loader.assert_not_called()

    def test_cli_dispatches_diagnostic_and_rejects_plan_only(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), mock.patch.object(runner, "run_native_diagnostic",
                return_value={"status": "fail"}) as run:
            status = runner.main(["--mode", "native-diagnostic", "--build", "build",
                "--scope", "scope.json", "--out", "report.json"])
        self.assertEqual(status, 1)
        self.assertEqual(run.call_count, 1)
        self.assertIn("qualification_accepted=false", output.getvalue())
        with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(runner, "plan_mode") as plan:
            status = runner.main(["--mode", "native-diagnostic", "--build", "build",
                "--scope", "scope.json", "--out", "report.json", "--plan-only"])
        self.assertEqual(status, 1)
        plan.assert_not_called()

    def test_mismatched_input_count_preserves_actual_masks_and_safe_reason(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)
            native_dir = root / "build/v02/native"
            native_dir.mkdir(parents=True)
            native_path = native_dir / "native.json"
            host_path = native_dir / "host.json"
            native_events = [{"port": 0, "desired": 256, "effective": 256, "joystick_mask": 256}]
            native_events.extend({"port": 0, "desired": n % 32, "effective": n % 32,
                "joystick_mask": n % 32} for n in range(1, 18))
            native_events.append({"port": 1, "desired": 16, "effective": 16, "joystick_mask": 0})
            native_path.write_text(json.dumps({"status": 0, "active_ticks": 3600, "fields": 9,
                "boundary_calls": 77, "inputs": native_events}))
            host_path.write_text(json.dumps({"input_events": [{"port": 0, "requested_mask": n % 32,
                "effective_mask": n % 32, "handler": "SDL_Gamepad/sample_port",
                "audio_device_name": "private"} for n in range(18)]}))
            row = {"status": "fail", "reason": "core-input-progress-or-common-boundary-mismatch",
                "core_outcome": "pass", "host_outcome": "fail-diagnostic",
                "raw_outputs": {"native": {"path": str(native_path.relative_to(root))},
                    "host": {"path": str(host_path.relative_to(root))}},
                "common_boundary": {"inputs": {"equal": False, "core_count": 19, "host_count": 18}},
                "failure_diagnostic": {"capture_field_matches": False, "renderer_named": True,
                    "video_driver_named": True, "audio_driver_named": False}}
            stages = [
                {"name": "input-contract", "status": "pass", "process": {"return_code": 0,
                    "status": "completed", "process_group_cleanup": "confirmed", "bound_violation": False},
                    "proof": {"outcome": "pass", "requested_count": 23, "port_isolation_verified": True,
                        "masks": [1] * 23, "observations": []}},
                {"name": "headless-reference", "status": "pass", "process": {"return_code": 0,
                    "status": "completed", "process_group_cleanup": "confirmed", "bound_violation": False},
                    "facts": {"native": {"status": 0, "active_ticks": 3600, "fields": 9,
                        "boundary_calls": 77, "inputs": []}}},
                {"name": "native-sdl-comparison", "status": "fail", "process": {"return_code": 0,
                    "status": "completed", "process_group_cleanup": "confirmed", "bound_violation": False},
                    "facts": {"row": row}}]
            with mock.patch.object(runner, "ROOT", root):
                safe = runner.safe_native_diagnostic({"status": "fail", "stages": stages})
            comparison = safe["stages"][2]["comparison"]
            self.assertEqual(comparison["core_input_count"], 19)
            self.assertEqual(comparison["host_input_count"], 18)
            self.assertEqual(len(comparison["native_input_events"]), 19)
            self.assertEqual(comparison["native_input_events"][0]["requested_mask"], "out-of-range")
            self.assertFalse(comparison["native_input_events"][0]["requested_mask_valid"])
            self.assertEqual(comparison["native_input_events"][-1]["requested_mask"], 16)
            self.assertEqual(comparison["native_input_events"][-1]["effective_mask"], 16)
            self.assertEqual(comparison["native_input_events"][-1]["joystick_mask"], 0)
            self.assertTrue(comparison["native_input_events"][-1]["joystick_mask_valid"])
            self.assertEqual(comparison["reason"], "core-input-progress-or-common-boundary-mismatch")
            self.assertIs(comparison["failure_presence"]["capture_field_matches"], False)
            self.assertNotIn("private", json.dumps(safe))

    def test_projection_rejects_untyped_fields_without_leaking_them(self):
        hostile = {"status": "pass", "failure_category": [], "stages": [
            {"status": "pass", "process": {"return_code": True, "status": ["secret"],
                "process_group_cleanup": "private path", "bound_violation": "unknown"},
             "proof": {"requested_count": True, "outcome": "pass", "port_isolation_verified": "yes",
                       "masks": [1, True, 256, "device"]}},
            {"status": "pass", "facts": {"native": {"status": 0, "active_ticks": True,
                "fields": 7, "boundary_calls": 4, "inputs": [{"port": 0, "desired": 1,
                    "effective": 1, "device_name": "secret"}]}}},
            {"status": "pass", "facts": {"row": {"status": "pass", "core_outcome": "pass",
                "host_outcome": "pass-diagnostic", "audio": {"audio_device_name": "secret",
                    "audio_submitted_frames": True}, "common_boundary": {"inputs": {"equal": True,
                    "rows": [{"index": 0, "equal": True, "port": 0, "desired": 1,
                        "effective": 1, "name": "secret"}]}}}}}]}
        rows = hostile["stages"][2]["facts"]["row"]["common_boundary"]["inputs"]["rows"]
        rows.extend({"index": value, "equal": True} for value in (None, True, "secret", [], {}))
        safe = runner.safe_native_diagnostic(hostile)
        encoded = json.dumps(safe)
        self.assertNotIn("secret", encoded)
        self.assertNotIn("audio_device_name", encoded)
        self.assertNotIn("audio_device_id", encoded)
        self.assertEqual(safe["stages"][0]["input"]["masks"], [1, "untyped", "out-of-range", "untyped"])
        self.assertEqual(safe["stages"][0]["input"]["mask_validity"], [True, False, False, False])
        self.assertEqual(safe["stages"][0]["process"]["return_code"], "untyped")
        self.assertEqual(len(safe["stages"][2]["comparison"]["input_rows"]), 1)
        self.assertIs(safe["qualification_accepted"], False)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeDiagnosticContract)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
