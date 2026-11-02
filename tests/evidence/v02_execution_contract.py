#!/usr/bin/env python3
"""Phase 7 bounded execution scope and historical-window isolation contracts."""
from __future__ import annotations

import pathlib
import json
import os
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]


class SmokeFailureDiagnosticContract(unittest.TestCase):
    def test_smoke_failure_logs_only_safe_fields_after_persisting_current_receipt(self) -> None:
        import importlib.util
        import types
        spec = importlib.util.spec_from_file_location("v02_smoke_failure_receipt",
            ROOT / "scripts/evidence/v02_run.py")
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        private = "/private/example/secret-command"
        rows = [
            {"status": "failed", "process_group_cleanup": cleanup, "bound_violation": True,
             "bound_violation_reason": "phase7-rss-observation-unavailable",
             "rss_observation_reason": "task-info-unavailable", "rss_observation_errno": "esrch",
             "rss_observation_result": "missing", "argv": [private], "stderr": private}
            for cleanup in ("confirmed", "unconfirmed")]
        rows += [{"status": private, "process_group_cleanup": private,
            "bound_violation_reason": private, "rss_observation_reason": private,
            "rss_observation_errno": [private], "rss_observation_result": {private: True}}, None]
        with tempfile.TemporaryDirectory(prefix="gw-smoke-failure-receipt-", dir=ROOT / "build/v02") as directory:
            for index, row in enumerate(rows):
                work = pathlib.Path(directory) / str(index); work.mkdir()
                captured = []
                def fake_boundary(_client, _command, runs, **kwargs):
                    if row is not None:
                        runs.append(row)
                    raise RuntimeError(private)
                def emitted(message, **kwargs):
                    # The receipt is complete before the summary leaves this boundary.
                    persisted = json.loads((work / "process.json").read_text())
                    captured.append((message, persisted))
                boundary = types.SimpleNamespace(_run_client=fake_boundary)
                with patch("builtins.print", side_effect=emitted), self.assertRaisesRegex(RuntimeError, private):
                    runner._run_smoke_child(boundary, {}, [private], report=work / "native.json",
                        timeout=1, cwd=work)
                self.assertEqual(len(captured), 1)
                message, persisted = captured[0]
                self.assertEqual(persisted["processes"], [] if row is None else [row])
                self.assertTrue(message.startswith("SMOKE_CHILD_FAILURE "))
                self.assertNotIn(private, message)
                summary = json.loads(message.split(" ", 1)[1])
                if index < 2:
                    self.assertEqual(summary["process_group_cleanup"], row["process_group_cleanup"])
                    self.assertEqual(summary["rss_observation_errno"], "esrch")
                    self.assertEqual(summary["rss_observation_result"], "missing")
                else:
                    self.assertTrue(all(value == "unavailable" for key, value in summary.items()
                        if key != "schema"))
            work = pathlib.Path(directory) / "success"; work.mkdir()
            def successful(_client, _command, runs, **kwargs):
                runs.append({"status": "completed", "bound_violation": False,
                    "process_group_cleanup": "confirmed"})
                return subprocess.CompletedProcess([private], 0)
            with patch("builtins.print") as emitted:
                result, receipt, _ = runner._run_smoke_child(types.SimpleNamespace(_run_client=successful),
                    {}, [private], report=work / "native.json", timeout=1, cwd=work)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(receipt["process_group_cleanup"], "confirmed")
            emitted.assert_not_called()

            work = pathlib.Path(directory) / "closed-log"; work.mkdir()
            def failed(_client, _command, runs, **kwargs):
                runs.append(rows[0])
                raise RuntimeError("original-child-failure")
            with patch("builtins.print", side_effect=BrokenPipeError("closed-log")), \
                 self.assertRaisesRegex(RuntimeError, "original-child-failure"):
                runner._run_smoke_child(types.SimpleNamespace(_run_client=failed), {}, [private],
                    report=work / "native.json", timeout=1, cwd=work)
            persisted = json.loads((work / "process.json").read_text())
            self.assertEqual(persisted["processes"], [rows[0]])


class Phase7ExecutionContract(unittest.TestCase):
    def test_four_hour_prospective_scope_is_separate_from_immutable_legacy_scope(self) -> None:
        import hashlib

        legacy_path = ROOT / "evidence/v02-execution.json"
        prospective_path = ROOT / "evidence/v02-phase7-full-execution-scope.json"
        legacy_raw = legacy_path.read_bytes()
        prospective_raw = prospective_path.read_bytes()
        self.assertEqual(hashlib.sha256(legacy_raw).hexdigest(),
            "05eb7f5fa91d759fbef8fb86bbc9db402dc41812261235bcf5085a0e2aa9b1a5")
        self.assertEqual(hashlib.sha256(prospective_raw).hexdigest(),
            "6deaf18aab75f45ac412a141caf9e089158f5c39d3971d49cb9bb7bb1be58df4")
        self.assertNotEqual(legacy_path, prospective_path)

        legacy = json.loads(legacy_raw)
        prospective = json.loads(prospective_raw)
        expected_prospective = json.loads(legacy_raw)
        expected_prospective["qualification_batch"].update({
            "wall_seconds": 14400, "runtime_wall_seconds": 10800,
            "package_wall_seconds": 2700, "close_wall_seconds": 900})
        self.assertEqual(prospective, expected_prospective,
            "the prospective scope changes only its four-hour qualification budgets")
        legacy_partitions = {key: legacy["qualification_batch"][key] for key in (
            "wall_seconds", "runtime_wall_seconds", "package_wall_seconds", "close_wall_seconds")}
        self.assertEqual(legacy_partitions, {
            "wall_seconds": 86400, "runtime_wall_seconds": 64800,
            "package_wall_seconds": 14400, "close_wall_seconds": 7200})
        self.assertEqual(prospective["qualification_batch"]["wall_seconds"], 14400)
        self.assertEqual(prospective["qualification_batch"]["runtime_wall_seconds"], 10800)
        self.assertEqual(prospective["qualification_batch"]["package_wall_seconds"], 2700)
        self.assertEqual(prospective["qualification_batch"]["close_wall_seconds"], 900)

    def test_four_hour_window_partitions_and_queue_delay_use_one_fixed_start(self) -> None:
        import datetime
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "phase7_four_hour_window_contract", ROOT / "scripts/release/v02_window.py")
        window_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(window_module)
        self.assertEqual((window_module.STARTED_AT, window_module.RUNTIME_CUTOFF,
            window_module.PACKAGE_CUTOFF, window_module.GLOBAL_CUTOFF), (
                "2026-11-02T16:56:30+00:00", "2026-11-02T19:56:30+00:00",
                "2026-11-02T20:41:30+00:00", "2026-11-02T20:56:30+00:00"))
        window = {"started_at": window_module.STARTED_AT,
            "scope_sha256": window_module.SCOPE_SHA256}
        start = datetime.datetime.fromisoformat(window_module.STARTED_AT)
        runtime = datetime.datetime.fromisoformat(window_module.RUNTIME_CUTOFF)
        package = datetime.datetime.fromisoformat(window_module.PACKAGE_CUTOFF)
        hard = datetime.datetime.fromisoformat(window_module.GLOBAL_CUTOFF)

        at_start = window_module.check_window(window, phase="preparation", now=start)
        self.assertEqual(at_start["remaining_seconds"], 10800)
        self.assertEqual(at_start["phase_cutoff"], window_module.RUNTIME_CUTOFF)
        self.assertEqual(at_start["hard_cutoff"], window_module.GLOBAL_CUTOFF)
        self.assertEqual(window_module.check_window(window, phase="close",
            now=start)["remaining_seconds"], 14400)
        self.assertEqual(window_module.check_window(window, phase="runtime",
            now=runtime - datetime.timedelta(seconds=1))["remaining_seconds"], 1)
        self.assertEqual(window_module.check_window(window, phase="package",
            now=runtime)["remaining_seconds"], 2700)
        self.assertEqual(window_module.check_window(window, phase="package",
            now=package - datetime.timedelta(seconds=1))["remaining_seconds"], 1)
        self.assertEqual(window_module.check_window(window, phase="close",
            now=package)["remaining_seconds"], 900)
        self.assertEqual(window_module.check_window(window, phase="close",
            now=hard - datetime.timedelta(seconds=1))["remaining_seconds"], 1)

        for phase, boundary in (("runtime", runtime), ("package", package), ("close", hard)):
            with self.subTest(phase=phase, boundary="exclusive"):
                with self.assertRaisesRegex(ValueError, "phase7-window-phase-expired"):
                    window_module.check_window(window, phase=phase, now=boundary)
        with self.assertRaisesRegex(ValueError, "phase7-window-not-started"):
            window_module.check_window(window, phase="preparation",
                now=start - datetime.timedelta(seconds=1))

        queued_at = start + datetime.timedelta(hours=2)
        consumed = window_module.check_window(window, phase="runtime", now=queued_at,
            workflow_created_at=(start + datetime.timedelta(hours=1)).isoformat())
        self.assertEqual(consumed["remaining_seconds"], 3600)
        retried_at = start + datetime.timedelta(hours=2, minutes=30)
        retried = window_module.check_window(window, phase="runtime", now=retried_at,
            workflow_created_at=retried_at.isoformat())
        self.assertEqual(retried["remaining_seconds"], 1800,
            "a retry consumes the original runtime allowance instead of restarting it")
        with self.assertRaisesRegex(ValueError, "phase7-window-start-replaced"):
            window_module.check_window(window, phase="runtime", now=queued_at,
                started_at=queued_at.isoformat())
        with self.assertRaisesRegex(ValueError, "phase7-window-start-replaced"):
            window_module.check_window({**window, "started_at": queued_at.isoformat()},
                phase="runtime", now=queued_at)
        with self.assertRaisesRegex(ValueError, "phase7-window-context-invalid"):
            window_module.check_window({**window, "scope_sha256": "0" * 64},
                phase="runtime", now=queued_at)
        with self.assertRaisesRegex(ValueError, "phase7-window-workflow-clock-invalid"):
            window_module.check_window(window, phase="runtime", now=queued_at,
                workflow_created_at=(queued_at + datetime.timedelta(seconds=1)).isoformat())
        with self.assertRaisesRegex(ValueError, "phase7-window-workflow-clock-invalid"):
            window_module.check_window(window, phase="runtime", now=queued_at,
                workflow_created_at=(start - datetime.timedelta(seconds=1)).isoformat())

    def test_four_hour_window_loader_rejects_legacy_or_unpinned_scope_selection(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "phase7_four_hour_window_scope_pin_contract", ROOT / "scripts/release/v02_window.py")
        window_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(window_module)
        with self.assertRaisesRegex(ValueError, "phase7-window-authority-or-scope-pin-invalid"):
            window_module.load_window(ROOT, scope_path=window_module.LEGACY_SCOPE_PATH)
        with self.assertRaisesRegex(ValueError, "phase7-window-authority-or-scope-pin-invalid"):
            window_module.load_window(ROOT, scope_sha256="0" * 64)

    def test_public_runner_clock_reopens_both_scope_snapshots_and_charges_queue_time(self) -> None:
        import datetime
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "phase7_four_hour_public_clock_contract", ROOT / "scripts/release/v02_window.py")
        window_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(window_module)
        start = datetime.datetime.fromisoformat(window_module.STARTED_AT)
        current = start + datetime.timedelta(hours=2)
        queued = start + datetime.timedelta(hours=1)
        with tempfile.TemporaryDirectory(prefix="phase7-window-public-clock-") as temporary:
            root = pathlib.Path(temporary).resolve()
            evidence = root / "evidence"
            evidence.mkdir()
            new_scope = ROOT / window_module.SCOPE_PATH
            legacy_scope = ROOT / window_module.LEGACY_SCOPE_PATH
            (evidence / new_scope.name).write_bytes(new_scope.read_bytes())
            (evidence / legacy_scope.name).write_bytes(legacy_scope.read_bytes())

            checked = window_module.validate_public_clock(root,
                scope_path=window_module.SCOPE_PATH.as_posix(),
                scope_sha256=window_module.SCOPE_SHA256,
                started_at=window_module.STARTED_AT, phase="runtime", now=current,
                workflow_created_at=queued.isoformat())
            self.assertEqual(checked["remaining_seconds"], 3600)
            self.assertEqual(window_module.load_public_scope(root)["qualification_batch"],
                json.loads(new_scope.read_bytes())["qualification_batch"])

            (evidence / new_scope.name).write_bytes(new_scope.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "phase7-window-scope-stale"):
                window_module.validate_public_clock(root,
                    scope_path=window_module.SCOPE_PATH.as_posix(),
                    scope_sha256=window_module.SCOPE_SHA256,
                    started_at=window_module.STARTED_AT, phase="runtime", now=current,
                    workflow_created_at=queued.isoformat())
            (evidence / new_scope.name).write_bytes(new_scope.read_bytes())
            (evidence / legacy_scope.name).write_bytes(b"{}\n")
            with self.assertRaisesRegex(ValueError, "phase7-window-legacy-scope-stale"):
                window_module.load_public_scope(root)

    def test_four_hour_source_event_window_selection_charges_queue_and_never_falls_back(self) -> None:
        import datetime
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "phase7_four_hour_source_event_selector", ROOT / "scripts/release/v02_window.py")
        window_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(window_module)
        start = datetime.datetime.fromisoformat(window_module.STARTED_AT)
        runtime = datetime.datetime.fromisoformat(window_module.RUNTIME_CUTOFF)
        hard = datetime.datetime.fromisoformat(window_module.GLOBAL_CUTOFF)
        with tempfile.TemporaryDirectory(prefix="phase7-source-event-window-") as temporary:
            root = pathlib.Path(temporary).resolve()
            evidence = root / "evidence"
            evidence.mkdir()
            for relative in (window_module.SCOPE_PATH, window_module.LEGACY_SCOPE_PATH):
                (root / relative).write_bytes((ROOT / relative).read_bytes())

            selected = window_module.select_public_event_window(root,
                workflow_created_at=(start + datetime.timedelta(minutes=1)).isoformat(),
                now=start + datetime.timedelta(minutes=5))
            self.assertTrue(selected["selected"])
            self.assertEqual(selected["scope_path"], window_module.SCOPE_PATH.as_posix())
            self.assertEqual(selected["scope_sha256"], window_module.SCOPE_SHA256)
            self.assertEqual(selected["started_at"], window_module.STARTED_AT)
            self.assertEqual(selected["remaining_seconds"], 10500)

            with self.assertRaisesRegex(ValueError, "phase7-window-phase-expired"):
                window_module.select_public_event_window(root,
                    workflow_created_at=(start + datetime.timedelta(minutes=1)).isoformat(),
                    now=runtime)

            with self.assertRaisesRegex(ValueError, "phase7-window-workflow-clock-invalid"):
                window_module.select_public_event_window(root,
                    workflow_created_at=(start + datetime.timedelta(minutes=10)).isoformat(),
                    now=start + datetime.timedelta(minutes=5))

            for outside, observed in ((start - datetime.timedelta(seconds=1), start),
                    (hard, hard)):
                with self.subTest(workflow_created_at=outside.isoformat()):
                    legacy = window_module.select_public_event_window(root,
                        workflow_created_at=outside.isoformat(), now=observed)
                    self.assertFalse(legacy["selected"])
                    self.assertEqual(legacy["scope_path"],
                        window_module.LEGACY_SCOPE_PATH.as_posix())
                    self.assertEqual(legacy["scope_sha256"],
                        window_module.LEGACY_SCOPE_SHA256)
                    self.assertIsNone(legacy["started_at"])

            with self.assertRaisesRegex(ValueError, "phase7-window-public-scope-pin-invalid"):
                window_module.validate_public_clock(root,
                    scope_path=selected["scope_path"],
                    scope_sha256=window_module.LEGACY_SCOPE_SHA256,
                    started_at=selected["started_at"], phase="preparation",
                    now=start + datetime.timedelta(minutes=5))

    def test_child_runner_rejects_legacy_scope_under_four_hour_window_environment(self) -> None:
        import importlib.util
        from unittest import mock

        spec = importlib.util.spec_from_file_location(
            "phase7_four_hour_child_scope_contract", ROOT / "scripts/evidence/v02_run.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory(prefix="phase7-window-child-scope-") as temporary:
            root = pathlib.Path(temporary).resolve()
            for relative in (pathlib.Path("evidence/v02-phase7-full-execution-scope.json"),
                    pathlib.Path("evidence/v02-execution.json"),
                    pathlib.Path("scripts/release/v02_window.py")):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            runner.ROOT = root
            new_scope = root / "evidence/v02-phase7-full-execution-scope.json"
            old_scope = root / "evidence/v02-execution.json"
            env = {"GENEWHIP_QUALIFICATION_SCOPE_PATH": new_scope.relative_to(root).as_posix(),
                "GENEWHIP_QUALIFICATION_SCOPE_SHA256":
                    "6deaf18aab75f45ac412a141caf9e089158f5c39d3971d49cb9bb7bb1be58df4",
                "GENEWHIP_QUALIFICATION_STARTED_AT": "2026-11-02T16:56:30+00:00",
                "GENEWHIP_QUALIFICATION_PHASE": "runtime"}
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(ValueError, "phase7-window-scope-profile-invalid"):
                    runner.validate_execution_scope(old_scope, "smoke")

    def test_active_scope_cmake_provenance_uses_the_consumer_build_root(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "phase7_active_scope_cmake_provenance", ROOT / "tests/fixtures/phase6_game.py")
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        route_spec = importlib.util.spec_from_file_location(
            "phase7_active_scope_cmake_consumer", ROOT / "scripts/evidence/phase6_routes.py")
        route = importlib.util.module_from_spec(route_spec); route_spec.loader.exec_module(route)
        old_root, old_scope = fixture.ROOT, fixture._EXECUTION_SCOPE
        with tempfile.TemporaryDirectory(prefix="gw-v02-cmake-provenance-", dir=ROOT / "build/v02") as temporary:
            root = pathlib.Path(temporary).resolve()
            fixture.ROOT = root
            fixture._EXECUTION_SCOPE = {"scope_id": "synthetic-active-scope",
                "owned_roots": ["build/v02", "artifacts/v02"]}
            route.ROOT = root
            try:
                source_files = {
                    "CMakeLists.txt": b"synthetic root CMake input\n",
                    "tools/session/CMakeLists.txt": b"synthetic session CMake input\n",
                    "scripts/evidence/phase6_routes.py": b"synthetic route source\n",
                    "tests/fixtures/phase6_game.py": b"synthetic reader provenance\n",
                    "tests/session/phase6_route_contract.py": b"synthetic reader contract\n",
                    "fixtures/phase6/media-expectations-v1.json": b"{}\n",
                    "fixtures/phase6/delivery-map.json": b"{}\n",
                }
                for relative, payload in source_files.items():
                    source = root / relative
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_bytes(payload)
                build = root / "build/v02/runtime-build"
                client = build / "tools/session/gw_headless"
                client.parent.mkdir(parents=True, exist_ok=True)
                client.write_bytes(b"synthetic, never executed\n")
                cache = build / "CMakeCache.txt"
                cache.write_text("synthetic actual cache digest\n")
                mapping = json.loads((root / "fixtures/phase6/delivery-map.json").read_text())
                candidate = {
                    "source_files": {relative: fixture.sha(root / relative) for relative in source_files},
                    "client_identities": {"public-core": {
                        "path": client.relative_to(root).as_posix(), "sha256": fixture.sha(client)}},
                    "build_identity": {"cmake_cache_sha256": fixture.sha(cache)},
                    "configuration_identity": {"audio_rate_hz": 48000, "profile": "VA3-NTSC-U", "test_hooks": True},
                    "compiler_identity": {"path": "scripts/evidence/phase6_routes.py",
                        "sha256": fixture.sha(root / "scripts/evidence/phase6_routes.py")},
                    "delivery_map_identity": {"path": "fixtures/phase6/delivery-map.json",
                        "sha256": route.canonical_digest(mapping)}}

                fixture.freeze_build_provenance(candidate, build)

                consumer_root = client.resolve().parents[2] / "evidence/build-provenance"
                for relative, expected in candidate["source_files"].items():
                    if pathlib.PurePosixPath(relative).name != "CMakeLists.txt":
                        continue
                    retained = consumer_root / f"{expected}.cmake"
                    self.assertEqual(retained.read_bytes(), source_files[relative])
                    self.assertEqual(fixture.sha(retained), expected)
                self.assertFalse((root / "build/v02/runtime/build-provenance").exists())

                candidate_path = root / "candidate.json"
                candidate_path.write_text(json.dumps(candidate))
                report = {"schema": "genewhip-phase6-product-report-v1",
                    "candidate_sha256": route.canonical_digest(candidate),
                    "candidate_manifest": {"path": "candidate.json", "sha256": route.digest(candidate_path)},
                    "validation_identities": {
                        "reader_provenance": {name: route.digest(root / name) for name in route.READER_PROVENANCE_PATHS},
                        "media_expectations_sha256": route.digest(root / "fixtures/phase6/media-expectations-v1.json")},
                    "roster": [], "runs": []}
                with patch.object(route, "validate_delivery_map"), \
                     patch.object(route, "compile_routes", return_value={"routes": []}):
                    with self.assertRaisesRegex(route.Invalid, "product-run-count"):
                        route.validate_product_report(report, candidate)

                retained = consumer_root / f"{candidate['source_files']['CMakeLists.txt']}.cmake"
                retained.unlink()
                with patch.object(route, "validate_delivery_map"), \
                     patch.object(route, "compile_routes", return_value={"routes": []}):
                    with self.assertRaisesRegex(route.Invalid, "product-stale-source"):
                        route.validate_product_report(report, candidate)

                fixture.freeze_build_provenance(candidate, build)
                retained.write_bytes(b"stale provenance\n")
                with patch.object(route, "validate_delivery_map"), \
                     patch.object(route, "compile_routes", return_value={"routes": []}):
                    with self.assertRaisesRegex(route.Invalid, "product-stale-source"):
                        route.validate_product_report(report, candidate)

                retained.write_bytes(b"stale provenance\n")
                with self.assertRaisesRegex(fixture.compiler.Invalid,
                                            "candidate-cmake-provenance-collision"):
                    fixture.freeze_build_provenance(candidate, build)

                unowned_build = root / "unowned-build"
                unowned_build.mkdir()
                with self.assertRaisesRegex(fixture.compiler.Invalid,
                                            "candidate-cmake-build-root-unowned"):
                    fixture.freeze_build_provenance(candidate, unowned_build)

                symlink_build = root / "build/v02/symlinked-build"
                symlink_build.mkdir(parents=True)
                outside = root / "outside"; outside.mkdir()
                (symlink_build / "evidence").symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(fixture.compiler.Invalid,
                                            "candidate-cmake-provenance-path-invalid"):
                    fixture.freeze_build_provenance(candidate, symlink_build)
                self.assertFalse((outside / "build-provenance").exists())

                source_link = root / "tools/session/CMakeLists.txt"
                saved_source = root / "tools/session/CMakeLists.regular"
                source_link.replace(saved_source)
                linked_source = outside / "CMakeLists.txt"
                linked_source.write_bytes(source_files["tools/session/CMakeLists.txt"])
                source_link.symlink_to(linked_source)
                symlink_input_build = root / "build/v02/symlink-input-build"
                symlink_input_build.mkdir(parents=True)
                with self.assertRaisesRegex(fixture.compiler.Invalid,
                                            "candidate-cmake-provenance-mismatch"):
                    fixture.freeze_build_provenance(candidate, symlink_input_build)
                source_link.unlink()
                saved_source.replace(source_link)

                oversized = root / "tools/session/CMakeLists.txt"
                oversized.write_bytes(b"x" * 131073)
                candidate["source_files"]["tools/session/CMakeLists.txt"] = fixture.sha(oversized)
                oversized_build = root / "build/v02/oversized-build"
                oversized_build.mkdir(parents=True)
                with self.assertRaisesRegex(fixture.compiler.Invalid,
                                            "candidate-cmake-provenance-size"):
                    fixture.freeze_build_provenance(candidate, oversized_build)
            finally:
                fixture.ROOT, fixture._EXECUTION_SCOPE = old_root, old_scope

    def _isolated_plan_inputs(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        root.mkdir(parents=True, exist_ok=True)
        scope = json.loads((ROOT / "evidence/v02-execution.json").read_text())
        scope_path = root / "scope.json"
        scope_path.write_text(json.dumps(scope))
        mapping = root / "fixtures/phase6/recursion94-consumed-map-v1.json"
        mapping.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json", mapping)
        build = root / "build/v02/synthetic-plan-only"
        build.mkdir(parents=True)
        (build / "CMakeCache.txt").write_text("synthetic, never built\n")
        client = build / "tools/session/gw_headless"
        client.parent.mkdir(parents=True)
        client.write_text("synthetic unusable production client\n")
        return scope_path, build

    def test_plan_mode_accepts_absent_optional_root_through_scope_validation(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("phase7_plan_mode_optional_root", ROOT / "scripts/evidence/v02_run.py")
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        compiler_spec = importlib.util.spec_from_file_location("phase7_plan_mode_compiler", ROOT / "scripts/evidence/phase6_routes.py")
        compiler = importlib.util.module_from_spec(compiler_spec); compiler_spec.loader.exec_module(compiler)
        with tempfile.TemporaryDirectory(prefix="gw-v02-plan-roots-", dir=ROOT / "build/v02") as temporary:
            root = pathlib.Path(temporary)
            scope_path, build = self._isolated_plan_inputs(root)
            denied_starts = []
            def deny_process(*args, **kwargs):
                denied_starts.append(args)
                raise AssertionError("plan_mode attempted a child process")
            old_root = runner.ROOT
            runner.ROOT = root
            try:
                with patch.object(runner, "_module", return_value=compiler), \
                     patch.object(runner, "source_identity", return_value={"source_sha256": "a" * 64}), \
                     patch.object(runner, "current_git_head", return_value="b" * 40), \
                     patch.object(runner.subprocess, "Popen", deny_process):
                    out = root / "artifacts/v02/smoke.json"
                    plan = runner.plan_mode("smoke", build, scope_path, out)
            finally:
                runner.ROOT = old_root
            self.assertEqual(plan["required_child_count"], 4)
            self.assertEqual(plan["plan_only_child_starts"], 0)
            self.assertEqual(len(plan["commands"]), 4)
            self.assertEqual(denied_starts, [])
            self.assertFalse((root / "artifacts/v02").exists())

    def test_plan_mode_rejects_output_root_traversal_symlink_and_missing_build(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("phase7_plan_mode_root_guards", ROOT / "scripts/evidence/v02_run.py")
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        old_root = runner.ROOT
        with tempfile.TemporaryDirectory(prefix="gw-v02-plan-root-guards-", dir=ROOT / "build/v02") as temporary:
            root = pathlib.Path(temporary)
            runner.ROOT = root
            try:
                fixture_root = root / "traversal"
                scope_path, build = self._isolated_plan_inputs(fixture_root)
                runner.ROOT = fixture_root
                scope = json.loads(scope_path.read_text()); scope["owned_roots"] = ["build/v02", "../escaped"]
                scope_path.write_text(json.dumps(scope))
                with self.assertRaisesRegex(ValueError, "phase7-owned-output-root-invalid"):
                    runner.plan_mode("smoke", build, scope_path, build / "smoke.json")

                fixture_root = root / "symlink"
                scope_path, build = self._isolated_plan_inputs(fixture_root)
                runner.ROOT = fixture_root
                outside = root / "outside"; outside.mkdir()
                (fixture_root / "artifacts").symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "phase7-owned-output-root-invalid"):
                    runner.plan_mode("smoke", build, scope_path, build / "smoke.json")

                fixture_root = root / "missing-build"
                scope_path, _ = self._isolated_plan_inputs(fixture_root)
                runner.ROOT = fixture_root
                missing_build = fixture_root / "build/v02/required-build-not-created"
                with self.assertRaises(FileNotFoundError):
                    runner.plan_mode("smoke", missing_build, scope_path, fixture_root / "build/v02/smoke.json")
            finally:
                runner.ROOT = old_root

    @classmethod
    def setUpClass(cls) -> None:
        variants = (
            ("phase6", "ON", ""),
            ("phase6-sanitize", "ON", "-fsanitize=address,undefined -fno-omit-frame-pointer"),
            ("phase6-hooks-off", "OFF", ""),
        )
        for name, hooks, flags in variants:
            build = ROOT / "build" / name
            result = subprocess.run(["cmake", "-S", str(ROOT), "-B", str(build),
                "-DGENEWHIP_BUILD_TOOLS=ON", "-DBUILD_TESTING=ON",
                "-DGENEWHIP_BUILD_DESKTOP=OFF", f"-DGENEWHIP_TEST_HOOKS={hooks}",
                f"-DCMAKE_C_FLAGS={flags}"], cwd=ROOT, text=True, capture_output=True, timeout=60)
            if result.returncode:
                raise RuntimeError("plan-only test CMake configuration failed")
            for relative in ("tools/session/gw_headless", "tools/desktop/genewhip-desktop",
                             "tools/session/phase6_chunk_contract", "gw_bounded_fuzz"):
                path = build / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_bytes(b"synthetic plan-only identity; never executed")

    def setUp(self) -> None:
        # Legacy execution tests must be independent of the prospective
        # Phase 7 window environment inherited by CI jobs. Window-specific
        # contracts below install their own explicit scope and clock values.
        from unittest import mock
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        for key in ("GENEWHIP_QUALIFICATION_STARTED_AT", "GENEWHIP_QUALIFICATION_PHASE",
                    "GENEWHIP_QUALIFICATION_NONCE", "GENEWHIP_QUALIFICATION_SCOPE_PATH",
                    "GENEWHIP_QUALIFICATION_SCOPE_SHA256"):
            os.environ.pop(key, None)
        (ROOT / "build/v02").mkdir(parents=True, exist_ok=True)
        (ROOT / "build/phase6").mkdir(parents=True, exist_ok=True)
        (ROOT / "artifacts/v02").mkdir(parents=True, exist_ok=True)
        cache = ROOT / "build/phase6/CMakeCache.txt"
        if not cache.is_file():
            cache.write_text("synthetic plan-only build identity\n")
        headless = ROOT / "build/phase6/tools/session/gw_headless"
        headless.parent.mkdir(parents=True, exist_ok=True)
        if not headless.is_file():
            headless.write_bytes(b"synthetic plan-only client identity")

    def test_safety_build_identity_retains_hashed_inputs_without_launching_children(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("phase7_safety_retention", ROOT / "scripts/evidence/v02_run.py")
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory(prefix="gw-v02-safety-retention-", dir=ROOT / "build/v02") as temporary:
            root = pathlib.Path(temporary)
            runner.ROOT = root
            build = root / "build/v02/runtime-build"
            variants = []
            for name, relative in (("native", "build/v02/runtime-build"),
                    ("sanitize", "build/v02/runtime/safety/asan-ubsan"),
                    ("hooks-off", "build/v02/runtime/safety/hooks-off")):
                directory = root / relative
                directory.mkdir(parents=True)
                settings = {
                    "native": {"CMAKE_BUILD_TYPE": "Debug", "CMAKE_GENERATOR": "Ninja", "CMAKE_C_FLAGS": "",
                        "CMAKE_EXE_LINKER_FLAGS": "", "BUILD_TESTING": "ON", "GENEWHIP_BUILD_TOOLS": "ON",
                        "GENEWHIP_BUILD_DESKTOP": "ON", "GENEWHIP_TEST_HOOKS": "ON"},
                    "sanitize": {"CMAKE_BUILD_TYPE": "Debug", "CMAKE_GENERATOR": "Ninja",
                        "CMAKE_C_FLAGS": "-fsanitize=address,undefined -fno-omit-frame-pointer",
                        "CMAKE_EXE_LINKER_FLAGS": "-fsanitize=address,undefined", "BUILD_TESTING": "ON",
                        "GENEWHIP_BUILD_TOOLS": "ON", "GENEWHIP_BUILD_DESKTOP": "OFF", "GENEWHIP_TEST_HOOKS": "ON"},
                    "hooks-off": {"CMAKE_BUILD_TYPE": "Debug", "CMAKE_GENERATOR": "Ninja", "CMAKE_C_FLAGS": "",
                        "CMAKE_EXE_LINKER_FLAGS": "", "BUILD_TESTING": "ON", "GENEWHIP_BUILD_TOOLS": "ON",
                        "GENEWHIP_BUILD_DESKTOP": "OFF", "GENEWHIP_TEST_HOOKS": "OFF"}}
                cache = "\n".join(f"{key}:STRING={value}" for key, value in {
                    **settings[name], "CMAKE_C_COMPILER_ID": "AppleClang", "CMAKE_C_COMPILER_VERSION": "15.0.0"}.items())
                files = {"CMakeCache.txt": cache.encode(), "phase6_safety": b"safety-bin", "probe": b"test-bin"}
                for filename, payload in files.items(): (directory / filename).write_bytes(payload)
                variants.append({"variant": name, "build_directory": relative,
                    "build_identity": {"cache_sha256": runner.sha(directory / "CMakeCache.txt"),
                        "phase6_safety_sha256": runner.sha(directory / "phase6_safety"),
                        "test_executables": {(directory / "probe").relative_to(root).as_posix(): runner.sha(directory / "probe")}}})
            runtime = root / "build/v02/runtime-observation"
            runtime.mkdir(parents=True)
            report_path = runtime / "safety.json"
            report_path.write_text(json.dumps({"variants": variants}))
            identity = {"schema": "test-only", "run_id": "synthetic"}
            ref = runner.retain_safety_build_evidence(build, runtime, report_path, identity)
            manifest = json.loads((root / ref["path"]).read_text())
            self.assertEqual(manifest["entry_count"], 9)
            self.assertEqual(manifest["identity"], identity)
            self.assertEqual(json.loads(report_path.read_text())["build_evidence"], ref)
            for item in manifest["entries"]:
                self.assertEqual(runner.sha(root / item["path"]), item["sha256"])
                self.assertEqual(runner.sha(root / item["source_path"]), item["source_sha256"])
            facts = json.loads((root / "build/v02/runtime-observation/safety-build-evidence/hooks-off.json").read_text())
            facts["build_facts"]["GENEWHIP_TEST_HOOKS"] = "ON"
            facts_module_spec = importlib.util.spec_from_file_location("phase7_facts_policy",
                ROOT / "scripts/evidence/v02_safety_build_facts.py")
            facts_module = importlib.util.module_from_spec(facts_module_spec); facts_module_spec.loader.exec_module(facts_module)
            expected_sources = {row["source_path"]: row["source_sha256"] for row in manifest["entries"]
                if row["variant"] == "hooks-off"}
            self.assertEqual(facts_module.validate_projection(facts, "hooks-off", expected_sources),
                "configuration:GENEWHIP_TEST_HOOKS")

    def test_full_dispatch_routes_exact_collectors_with_one_safe_synthetic_child(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("phase7_dispatch_isolation", ROOT / "scripts/evidence/v02_run.py")
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        original_module = runner._module
        original_retain_safety = runner.retain_safety_build_evidence
        modules = {}
        routed = {"core": 0, "input": [], "host": [], "safety": 0, "chunk": 0}
        def load(path, name):
            key = str(path)
            if key in modules:
                return modules[key]
            value = original_module(path, name)
            modules[key] = value
            if pathlib.Path(key).name == "phase6_game.py":
                def fake_candidate(build, mapping, output):
                    candidate = {"candidate": "synthetic"}
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(json.dumps(candidate))
                    return candidate
                value.freeze_candidate = fake_candidate
                value.compiler.validate_product_report = lambda report, candidate: None
                value.compiler.validate_host_report = lambda report, candidate: None
                def fake_core(build, mapping, candidate, output):
                    routed["core"] += 1
                    work = output.parent / "safe-synthetic-child"
                    work.mkdir()
                    _, receipt, _ = value.shared_launch(pathlib.Path(sys.executable),
                        [sys.executable, "-I", "-c", "print('safe synthetic collector child')"],
                        work, work / "safe-child-report.json", 5, plan_id="07-09-isolation")
                    output.write_text(json.dumps({"schema":"genewhip-phase6-product-report-v1", "runs":[], "stages":[]}))
                    routed["child_receipt"] = receipt
                value.core = fake_core
                value.media = lambda build, candidate, output, core=None: output.write_text(json.dumps({"result":"pass"})) or 0
                value.safety = lambda build, candidate, output: (routed.__setitem__("safety", routed["safety"] + 1), output.write_text("{}"))
                value.chunk = lambda build, candidate, mapping, output: (routed.__setitem__("chunk", routed["chunk"] + 1), output.write_text("{}"))
            elif pathlib.Path(key).name == "phase6_routes.py" and key.endswith("tests/desktop/phase6_routes.py"):
                value.compiler.validate_host_report = lambda report, candidate: None
                def fake_input(build, mapping, output, candidate, backend):
                    routed["input"].append(backend)
                    output.write_text("{}")
                    return 0
                value.input_contract = fake_input
                def fake_hosts(backend, build, core, mapping, output, candidate):
                    routed["host"].append(backend)
                    output.write_text(json.dumps({"schema":"genewhip-phase6-host-v1", "backend":backend,
                        "status":"pass-diagnostic", "outcome":"pass", "runs":[]}))
                    return 0
                value.host_batch = fake_hosts
            elif pathlib.Path(key).name == "v02_matrix.py":
                value.validate_host_report = lambda report, candidate: None
            return value
        runner._module = load
        runner.retain_safety_build_evidence = lambda build, runtime, report, identity: {
            "path": str((runtime / "safety-build-evidence.json").relative_to(ROOT)), "sha256": "a" * 64}
        output = None
        try:
            with tempfile.TemporaryDirectory(prefix="gw-v02-dispatch-isolation-", dir=ROOT / "build/v02") as directory:
                output = pathlib.Path(directory) / "runtime-observation.json"
                with patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}):
                    result = runner.run_execution("full", ROOT / "build/phase6",
                        ROOT / "evidence/v02-execution.json", output)
                self.assertEqual(result["status"], "pass")
                self.assertEqual(routed["core"], 1, "the complete 24-execution core collector runs once")
                self.assertEqual(sorted(routed["input"]), ["native", "software"])
                self.assertEqual(sorted(routed["host"]), ["native", "software"])
                self.assertEqual((routed["safety"], routed["chunk"]), (1, 1))
                self.assertEqual(routed["child_receipt"]["status"], "completed")
                self.assertEqual(routed["child_receipt"]["process_group_cleanup"], "confirmed")
                self.assertEqual(result["isolation_preflight"]["production_child_starts"], 0)
                self.assertEqual(len(result["process_records"]), 1)
                self.assertEqual(result["process_records"][0]["plan"], "07-09-isolation")
                child = result["process_records"][0]["receipts"][0]
                self.assertNotIn(child.get("client"), {"gw_headless", "genewhip-desktop"})
                self.assertEqual(child["status"], "completed")
        finally:
            runner._module = original_module
            runner.retain_safety_build_evidence = original_retain_safety

    def test_smoke_plan_resolves_all_declared_title_and_host_work_without_launch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-v02-plan-", dir=ROOT / "build/v02") as directory:
            output = pathlib.Path(directory) / "smoke-plan.json"
            result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/evidence/v02_run.py"),
                "--mode", "smoke", "--build", str(ROOT / "build/phase6"),
                "--scope", str(ROOT / "evidence/v02-execution.json"), "--plan-only",
                "--out", str(output)], cwd=ROOT, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(output.is_file())
            self.assertIn('"plan_only_child_starts": 0', output.read_text())

    def test_full_safety_and_chunk_plans_resolve_exact_rosters_and_finite_exposure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gw-v02-roster-plan-", dir=ROOT / "build/v02") as directory:
            root = pathlib.Path(directory)
            expected_tests = ["load_contract", "time_contract", "reset_contract", "bus_boundary_contract",
                "gameplay_bus_contract", "movem_contract", "phase6_repairs_contract", "session_contract",
                "input_log_contract", "phase6_chunk_contract", "phase6_safety", "phase6_delivery_map_contract"]
            plans = {}
            for mode in ("full", "safety", "chunk"):
                output = root / f"{mode}.json"
                result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/evidence/v02_run.py"),
                    "--mode", mode, "--build", str(ROOT / "build/phase6"),
                    "--scope", str(ROOT / "evidence/v02-execution.json"), "--plan-only",
                    "--out", str(output)], cwd=ROOT, text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                plans[mode] = json.loads(output.read_text())
                self.assertEqual(plans[mode]["plan_only_child_starts"], 0)
            self.assertEqual(plans["full"].get("workloads"), {
                "core_title_executions": 12, "core_original_control_executions": 12,
                "software_sdl_title_cases": 6, "native_sdl_title_cases": 6,
                "separate_original_host_control_rosters": 2})
            self.assertEqual((plans["safety"].get("safety") or {}).get("test_names"), expected_tests)
            self.assertEqual((plans["safety"].get("safety") or {}).get("variants"), ["native", "asan-ubsan", "hooks-off"])
            self.assertEqual((plans["safety"].get("safety") or {}).get("malformed_load_cases_per_variant"), 4096)
            self.assertEqual(len((plans["safety"].get("safety") or {}).get("test_names", [])), 12)
            self.assertEqual((plans["chunk"].get("chunk") or {}).get("titles"), ["recursion94", "tank-battle"])
            self.assertEqual((plans["chunk"].get("chunk") or {}).get("instruction_events_required"), True)
            self.assertTrue(plans["chunk"].get("requires_fresh_two_title_smoke"))
            self.assertTrue(plans["chunk"].get("requires_fresh_full_core_report_before_execution"))
            for plan in plans.values():
                for command in plan["commands"]:
                    for argument in command.get("argv", []):
                        self.assertNotIn("<", str(argument), f"unresolved argv placeholder: {argument}")

    def test_execution_observation_mutants_reject_at_the_production_assertion(self) -> None:
        spec = __import__("importlib.util").util.spec_from_file_location(
            "v02_observation_validator", ROOT / "scripts/evidence/v02_run.py")
        runner = __import__("importlib.util").util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        expected = {"scope_id":"phase7-serial-child-workloads", "source_sha256":"source-current",
            "build_identity":{"cache":"cache-current"}, "launch_identities":{"client":"client-current"},
            "require_native":True}
        base = {"schema":"genewhip-v02-execution-observation-v1", "scope_id":expected["scope_id"],
            "source_sha256":expected["source_sha256"], "build_identity":expected["build_identity"],
            "launch_identities":expected["launch_identities"], "historical_window_access":False,
            "process":{"process_group_cleanup":"confirmed","bound_violation":False},
            "capabilities":{"native":"observed"},
            "comparisons":{"ram":True,"cpu_explicit_fields":True,"video":True,"pcm":True,
                "terminal_state":True,"instruction_events":True}, "dropped_instruction_events":0}

        def signed(value):
            payload = {key:item for key,item in value.items() if key != "payload_sha256"}
            value["payload_sha256"] = __import__("hashlib").sha256(
                json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            return value

        runner.validate_execution_observation(signed(dict(base)), expected)
        mutants = [
            ("phase7-comparison-missing:ram", lambda x: x["comparisons"].update(ram=False)),
            ("phase7-comparison-missing:pcm", lambda x: x["comparisons"].pop("pcm")),
            ("phase7-stale-launch-identity:launch_identities", lambda x: x.update(launch_identities={"client":"stale"})),
            ("phase7-process-cleanup-or-bound", lambda x: x["process"].update(process_group_cleanup="unconfirmed")),
            ("phase7-native-capability-missing", lambda x: x["capabilities"].update(native="blocked-capability")),
            ("phase7-historical-window-access", lambda x: x.update(historical_window_access=True)),
            ("phase7-instruction-events-dropped", lambda x: x.update(dropped_instruction_events=1)),
        ]
        for reason, mutate in mutants:
            with self.subTest(reason=reason):
                altered = json.loads(json.dumps(base))
                mutate(altered)
                with self.assertRaisesRegex(RuntimeError, reason):
                    runner.validate_execution_observation(signed(altered), expected)

    def test_phase7_scope_uses_fresh_in_memory_accounting_without_touching_phase6_window(self) -> None:
        spec = __import__("importlib.util").util.spec_from_file_location(
            "phase7_fixture_scope_contract", ROOT / "tests/fixtures/phase6_game.py")
        fixture = __import__("importlib.util").util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        scope = __import__("json").loads((ROOT / "evidence/v02-execution.json").read_text())
        fixture.set_execution_scope(scope)
        try:
            before = fixture._read_window()
            self.assertEqual(before["workload_wall_seconds"], 0.0)
            fixture._write_window(before)
            self.assertIs(fixture._read_window(), before)
            self.assertEqual(before["process_records"], [])
            historical_window = ROOT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-50-53-EXECUTION.json"
            if historical_window.exists():
                self.assertGreater(historical_window.stat().st_mtime_ns, 0)
            else:
                self.assertFalse((ROOT / ".planning").exists(),
                    "sanitized public checkout must not acquire private planning history")
        finally:
            fixture.set_execution_scope(None)

    def test_rebinding_scope_cannot_renew_common_qualification_deadline(self) -> None:
        import datetime
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "phase7_fixture_clock_contract", ROOT / "tests/fixtures/phase6_game.py")
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        scope = json.loads((ROOT / "evidence/v02-execution.json").read_text())
        now = datetime.datetime.now(datetime.timezone.utc)
        scope["qualification_started_at"] = now.isoformat()
        scope["qualification_deadline"] = (now + datetime.timedelta(seconds=120)).isoformat()
        fixture.set_execution_scope(scope)
        first_deadline = fixture._V02_DEADLINE
        try:
            fixture.set_execution_scope({**scope, "_core_report_path": "synthetic-core.json"})
            self.assertEqual(fixture._V02_DEADLINE, first_deadline)
            with self.assertRaisesRegex(RuntimeError, "shared-cutoff-mutated"):
                fixture.set_execution_scope({**scope, "qualification_deadline": "mutated"})
            fixture.set_execution_scope(None)
            expired = {**scope, "qualification_deadline": (now - datetime.timedelta(seconds=1)).isoformat()}
            with self.assertRaisesRegex(RuntimeError, "shared-cutoff-exhausted-or-renewed"):
                fixture.set_execution_scope(expired)
        finally:
            fixture.set_execution_scope(None)

    def test_failed_scoped_launch_keeps_attempt_receipt_and_bounded_streams(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("phase7_durable_failure", ROOT / "tests/fixtures/phase6_game.py")
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        scope = json.loads((ROOT / "evidence/v02-execution.json").read_text())
        setup_root = ROOT / "build/v02/runtime/setup"
        setup_root.mkdir(parents=True, exist_ok=True)
        before = set(setup_root.glob("phase7-setup-*"))
        original = fixture.subprocess.Popen
        starts = []
        def deny(*args, **kwargs):
            starts.append(args[0])
            raise OSError("synthetic production launch denied")
        fixture.subprocess.Popen = deny
        fixture.set_execution_scope({**scope, "_scope_path": str(ROOT / "evidence/v02-execution.json")})
        try:
            with patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}):
                result = fixture._command(["/unusable-production-client"], 2)
            self.assertEqual(result.returncode, 127)
        finally:
            fixture.set_execution_scope(None); fixture.subprocess.Popen = original
        attempts = sorted(setup_root.glob("phase7-setup-*"))
        attempts = [path for path in attempts if path not in before]
        self.assertEqual(len(starts), 1, "synthetic denial must observe zero production starts")
        self.assertEqual(len(attempts), 1)
        journal = json.loads((attempts[0] / "process.json").read_text())
        self.assertEqual(len(journal["processes"]), 1)
        receipt = journal["processes"][0]
        self.assertEqual(receipt["status"], "launch-failed")
        self.assertIsNone(receipt.get("pid"))
        self.assertIsNone(receipt.get("pgid"))
        self.assertEqual(receipt.get("process_group_cleanup"), "not-launched")
        self.assertIs(receipt.get("bound_violation"), True)
        self.assertNotIn("started_at", receipt)
        self.assertNotEqual(result.returncode, 0,
                            "a launch-failure receipt must remain a nonqualifying command result")
        self.assertEqual(journal["scope_id"], scope["scope_id"])
        self.assertIn("stdout", journal["streams"])
        self.assertIn("stderr", journal["streams"])
        self.assertEqual(journal["streams"]["stdout"]["status"], "not-started")
        self.assertEqual(journal["streams"]["stderr"]["status"], "not-started")

    def test_only_exact_zero_child_launch_failure_is_returnable(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "phase7_launch_failure_guard", ROOT / "tests/fixtures/phase6_game.py")
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        result = subprocess.CompletedProcess(["client"], 127, "", "launch failed")
        receipt = {"status": "launch-failed", "pid": None, "pgid": None,
            "process_group_cleanup": "not-launched", "bound_violation": True}
        self.assertTrue(fixture._is_unlaunched_launch_failure(result, receipt))
        mutants = (
            ({**receipt, "pid": 42}, result),
            ({**receipt, "pgid": 42}, result),
            ({**receipt, "process_group_cleanup": "unconfirmed"}, result),
            ({**receipt, "status": "started"}, result),
            ({**receipt, "bound_violation": False}, result),
            (receipt, subprocess.CompletedProcess(["client"], 0, "", "")),
            (receipt, subprocess.CompletedProcess(["client"], True, "", "")),
        )
        for altered_receipt, altered_result in mutants:
            with self.subTest(receipt=altered_receipt, returncode=altered_result.returncode):
                self.assertFalse(fixture._is_unlaunched_launch_failure(altered_result, altered_receipt))

    def test_started_synthetic_child_survives_later_semantic_rejection(self) -> None:
        import hashlib
        import importlib.util
        spec = importlib.util.spec_from_file_location("phase7_poststart_failure", ROOT / "tests/fixtures/phase6_game.py")
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        runner_spec = importlib.util.spec_from_file_location("phase7_poststart_validator", ROOT / "scripts/evidence/v02_run.py")
        runner = importlib.util.module_from_spec(runner_spec); runner_spec.loader.exec_module(runner)
        scope = json.loads((ROOT / "evidence/v02-execution.json").read_text())
        work_root = ROOT / "build/v02/runtime/setup"
        work_root.mkdir(parents=True, exist_ok=True)
        import tempfile
        work = pathlib.Path(tempfile.mkdtemp(prefix="poststart-synthetic-", dir=work_root))
        prior = work / "prior-receipt.json"
        prior.write_text('{"attempt":"earlier-preserved"}\n')
        report = work / "synthetic-report.json"
        fixture.set_execution_scope({**scope, "_scope_path": str(ROOT / "evidence/v02-execution.json")})
        try:
            with patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}):
                result, receipt, streams = fixture.shared_launch(pathlib.Path(sys.executable),
                    [sys.executable, "-I", "-c", "print('bounded synthetic child')"], work, report, 5,
                    plan_id="07-09-poststart-synthetic")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(receipt.get("status"), "completed")
            self.assertEqual(receipt.get("process_group_cleanup"), "confirmed")
            self.assertIn("bounded synthetic child", streams["stdout"]["text"])
            bad = {"schema":"genewhip-v02-execution-observation-v1", "payload_sha256":"0" * 64}
            with self.assertRaisesRegex(RuntimeError, "payload-digest"):
                runner.validate_execution_observation(bad, {})
        finally:
            fixture.set_execution_scope(None)
        journal = json.loads((work / "process.json").read_text())
        self.assertEqual(len(journal["processes"]), 1)
        self.assertEqual(journal["processes"][0]["status"], "completed")
        self.assertEqual(journal["processes"][0]["process_group_cleanup"], "confirmed")
        self.assertEqual(journal["streams"]["stdout"]["sha256"], hashlib.sha256(b"bounded synthetic child\n").hexdigest())
        self.assertEqual(prior.read_text(), '{"attempt":"earlier-preserved"}\n')


if __name__ == "__main__":
    if sys.argv[1:] == ["--contracts"]:
        unittest.main(argv=[sys.argv[0]])
    else:
        unittest.main()
