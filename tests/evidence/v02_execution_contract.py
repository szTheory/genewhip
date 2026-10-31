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


class Phase7ExecutionContract(unittest.TestCase):
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
