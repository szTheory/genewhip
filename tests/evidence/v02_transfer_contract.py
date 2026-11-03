#!/usr/bin/env python3
"""Privacy and exact-member contracts for the scheduled runtime artifact export."""
import hashlib
import importlib.util
import json
import contextlib
import copy
import io
import os
import pathlib
import stat
import tempfile
from types import SimpleNamespace
import unittest
import tarfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("gw_v02_transfer_contract", ROOT / "scripts/release/v02_transfer.py")
TRANSFER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSFER)


class RuntimeTransferContract(unittest.TestCase):
    def _valid_benchmark_workload_report(self, scope_path, scope_sha256):
        fixture_spec = importlib.util.spec_from_file_location(
            "gw_benchmark_report_fixtures", ROOT / "tests/evidence/benchmark_contract.py")
        fixtures = importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixtures)
        benchmark = TRANSFER._load_benchmark_module()
        scope = json.loads(pathlib.Path(scope_path).read_text(encoding="utf-8"))
        workload = copy.deepcopy(fixtures.valid_v02_report()["workloads"]["control"])
        identity = {"video": [[1, 1, 256, 224, "a" * 64]], "pcm_frames": 480619,
            "pcm_sha256": "b" * 64, "ram_sha256": "c" * 64, "machine_sha256": "d" * 64}
        reference = workload["untimed_reference"]
        reference["actual_tick_start"], reference["actual_tick_end"] = 0, 100
        reference["output_identity"] = identity
        for row in workload["timed_runs"]:
            row["actual_tick_start"], row["actual_tick_end"] = 0, 100
            row["output_identity"] = identity
            row["untimed_output_identity"] = identity
            row["route_status"] = 0
        build = {
            "compiler_sha256": "1" * 64,
            "compiler_version_line": "Clang fixture version",
            "build_rules_sha256": "2" * 64,
            "build_configuration_sha256": "3" * 64,
            "cmake": {},
            "host_system": "Darwin",
            "host_release": "fixture-release",
            "host_macos_version": "fixture-version",
            "host_machine": "arm64",
            "host_model": "fixture-model",
        }
        host_keys = ("host_system", "host_release", "host_macos_version", "host_machine", "host_model")
        report = {
            "schema": "genewhip.v02-workload-benchmark-v1",
            "workload": "control",
            "outcome": "pass",
            "qualification": True,
            "source_identity_sha256": benchmark.source_identity(),
            "source_revision": "a" * 40,
            "head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "run_id": "123",
            "run_attempt": "1",
            "scope_id": scope["scope_id"],
            "scope_sha256": scope_sha256,
            "build_identity": build,
            "host_identity": {key: build[key] for key in host_keys},
            "counts": {"timed_children": 20, "untimed_references": 1,
                "process_starts": 21, "timed_samples_per_mode": 5},
            **workload,
        }
        return report

    def _run_benchmark_cli(self, report_path, scope_arg, selectors):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, selectors, clear=False), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = TRANSFER.main([
                "benchmark", "--report", str(report_path), "--workload", "control",
                "--scope", str(scope_arg), "--source-sha", "a" * 40,
                "--head-sha", "a" * 40, "--base-sha", "b" * 40,
                "--run-id", "123", "--run-attempt", "1"])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_scope_profiles_and_benchmark_transfer_cli_use_shared_exact_pins(self):
        scope = importlib.util.spec_from_file_location(
            "gw_core_benchmark_scope_contract", ROOT / "tools/evidence/core_benchmark.py")
        benchmark = importlib.util.module_from_spec(scope)
        scope.loader.exec_module(benchmark)
        profiles = TRANSFER._SCOPE.SCOPE_PROFILES
        with mock.patch.dict(os.environ, {
                "GENEWHIP_QUALIFICATION_SCOPE_PATH": "",
                "GENEWHIP_QUALIFICATION_SCOPE_SHA256": ""}, clear=False):
            self.assertEqual(benchmark.qualification_scope_path(), ROOT / TRANSFER._SCOPE.LEGACY_SCOPE_REL)
            self.assertEqual(TRANSFER._qualification_scope_path(ROOT),
                ROOT / TRANSFER._SCOPE.LEGACY_SCOPE_REL)
            with self.assertRaisesRegex(ValueError, "transfer-qualification-scope-not-selected"):
                TRANSFER._qualification_scope_path(ROOT, ROOT / "evidence/v02-phase7-authorized-execution-scope.json")
        for digest, relative in profiles.items():
            selectors = {"GENEWHIP_QUALIFICATION_SCOPE_PATH": relative.as_posix(),
                "GENEWHIP_QUALIFICATION_SCOPE_SHA256": digest}
            with self.subTest(profile=relative.name), mock.patch.dict(os.environ, selectors, clear=False):
                selected = ROOT / relative
                self.assertEqual(benchmark.qualification_scope_path(), selected)
                self.assertEqual(TRANSFER._qualification_scope_path(ROOT, selected), selected)

        authorized_sha = next(digest for digest, relative in profiles.items()
            if relative.name == "v02-phase7-authorized-execution-scope.json")
        authorized_rel = profiles[authorized_sha]
        authorized_path = ROOT / authorized_rel
        selectors = {"GENEWHIP_QUALIFICATION_SCOPE_PATH": authorized_rel.as_posix(),
            "GENEWHIP_QUALIFICATION_SCOPE_SHA256": authorized_sha}
        report = self._valid_benchmark_workload_report(authorized_path, authorized_sha)
        with tempfile.TemporaryDirectory(prefix="gw-transfer-scope-cli-") as temporary:
            report_path = pathlib.Path(temporary) / "benchmark.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            result, stdout, stderr = self._run_benchmark_cli(report_path, authorized_rel, selectors)
            self.assertEqual(result, 0, stderr)
            self.assertEqual(json.loads(stdout)["status"], "pass")

            wrong_digest = copy.deepcopy(report)
            wrong_digest["scope_sha256"] = "0" * 64
            report_path.write_text(json.dumps(wrong_digest), encoding="utf-8")
            result, _stdout, stderr = self._run_benchmark_cli(report_path, authorized_rel, selectors)
            self.assertEqual(result, 1)
            self.assertIn("transfer-benchmark-scope-digest-mismatch", stderr)

            mismatched_path_selectors = {**selectors,
                "GENEWHIP_QUALIFICATION_SCOPE_PATH": "evidence/v02-phase7-full-execution-scope.json"}
            result, _stdout, stderr = self._run_benchmark_cli(report_path, authorized_rel,
                mismatched_path_selectors)
            self.assertEqual(result, 1)
            self.assertIn("transfer-qualification-scope-profile-invalid", stderr)

            report_path.write_text("[]", encoding="utf-8")
            result, _stdout, stderr = self._run_benchmark_cli(report_path, authorized_rel, selectors)
            self.assertEqual(result, 1)
            self.assertIn("transfer-benchmark-report-object-required", stderr)

    def test_benchmark_cli_rejects_tampered_selected_scope_bytes(self):
        authorized_sha = "c77556022454459deb731ea1d50f7f1a1ba0d20370c540a101e2144175c3986a"
        relative = pathlib.Path("evidence/v02-phase7-authorized-execution-scope.json")
        with tempfile.TemporaryDirectory(prefix="gw-transfer-scope-tamper-") as temporary:
            root = pathlib.Path(temporary) / "checkout"
            scope_path = root / relative
            scope_path.parent.mkdir(parents=True)
            scope_path.write_bytes((ROOT / relative).read_bytes() + b" ")
            report_path = pathlib.Path(temporary) / "benchmark.json"
            report_path.write_text("{}", encoding="utf-8")
            selectors = {"GENEWHIP_QUALIFICATION_SCOPE_PATH": relative.as_posix(),
                "GENEWHIP_QUALIFICATION_SCOPE_SHA256": authorized_sha}
            with mock.patch.object(TRANSFER, "ROOT", root):
                result, _stdout, stderr = self._run_benchmark_cli(report_path, relative, selectors)
            self.assertEqual(result, 1)
            self.assertIn("transfer-qualification-scope-profile-invalid", stderr)

    def test_transfer_uses_verified_scope_snapshot_after_path_replacement(self):
        authorized_sha = "c77556022454459deb731ea1d50f7f1a1ba0d20370c540a101e2144175c3986a"
        relative = pathlib.Path("evidence/v02-phase7-authorized-execution-scope.json")
        original = (ROOT / relative).read_bytes()
        changed_scope = json.loads(original)
        changed_scope["scope_id"] = "replaced-after-selection"
        replacement = json.dumps(changed_scope, sort_keys=True).encode()
        replacement_sha = hashlib.sha256(replacement).hexdigest()
        report = self._valid_benchmark_workload_report(ROOT / relative, authorized_sha)
        report["scope_sha256"] = replacement_sha
        benchmark = TRANSFER._load_benchmark_module()
        observed = []
        real_read_scope = TRANSFER._SCOPE.read_scope

        with tempfile.TemporaryDirectory(prefix="gw-transfer-scope-snapshot-") as temporary:
            root = pathlib.Path(temporary) / "checkout"
            scope_path = root / relative
            scope_path.parent.mkdir(parents=True)
            scope_path.write_bytes(original)
            report_path = pathlib.Path(temporary) / "benchmark.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            def replace_after_verified_read(*args, **kwargs):
                path, raw = real_read_scope(*args, **kwargs)
                path.write_bytes(replacement)
                observed.append((path, raw))
                return path, raw

            selectors = {"GENEWHIP_QUALIFICATION_SCOPE_PATH": relative.as_posix(),
                "GENEWHIP_QUALIFICATION_SCOPE_SHA256": authorized_sha}
            with mock.patch.object(TRANSFER, "ROOT", root), \
                    mock.patch.object(TRANSFER, "_load_benchmark_module", return_value=benchmark), \
                    mock.patch.object(TRANSFER._SCOPE, "read_scope",
                        side_effect=replace_after_verified_read), \
                    mock.patch.dict(os.environ, selectors, clear=False):
                with self.assertRaisesRegex(ValueError,
                        "transfer-benchmark-scope-digest-mismatch"):
                    TRANSFER.validate_benchmark_report(report_path, "control", relative,
                        source_sha="a" * 40, head_sha="a" * 40, base_sha="b" * 40,
                        run_id="123", run_attempt="1")
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0][1], original)
            self.assertEqual(observed[0][0].read_bytes(), replacement)

    def test_scope_resolver_opens_nonblocking_and_rejects_special_file_race(self):
        scope_module = TRANSFER._SCOPE
        digest = "c77556022454459deb731ea1d50f7f1a1ba0d20370c540a101e2144175c3986a"
        relative = pathlib.Path("evidence/v02-phase7-authorized-execution-scope.json")
        real_open, real_fstat = scope_module.os.open, scope_module.os.fstat
        observed_flags = []

        def tracked_open(path, flags):
            observed_flags.append(flags)
            return real_open(path, flags)

        def raced_fifo_fstat(_descriptor):
            return SimpleNamespace(st_mode=stat.S_IFIFO, st_nlink=1, st_size=0)

        with mock.patch.object(scope_module.os, "open", side_effect=tracked_open), \
                mock.patch.object(scope_module.os, "fstat", side_effect=raced_fifo_fstat):
            with self.assertRaises(scope_module.ScopeSelectionError) as rejected:
                scope_module.resolve_scope(ROOT, ROOT / relative,
                    scope_path=relative.as_posix(), scope_sha256=digest)
        self.assertEqual(rejected.exception.reason, "profile-invalid")
        self.assertTrue(observed_flags[0] & os.O_NONBLOCK)
        self.assertTrue(observed_flags[0] & os.O_NOFOLLOW)

    def _fixture(self, root, *, payload=bytes(320 * 224 * 4), unsafe_path=None):
        image_name = unsafe_path or "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/fields/field-120.bin"
        image = root / image_name
        image.parent.mkdir(parents=True, exist_ok=True)
        image.write_bytes(payload)
        for name in TRANSFER.DIRECT_MEMBERS:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if name.endswith("runtime-identity.json"):
                body = json.dumps({"schema": "genewhip-v02-runtime-identity-v1",
                    "source_sha256": "a" * 64, "git_head": "a" * 40, "base_sha": "a" * 40,
                    "run_id": "123", "run_attempt": "4"}).encode()
            elif name.endswith("core-report.json"):
                body = json.dumps({"schema": "genewhip-phase6-product-report-v1", "runs": [
                    {"image": {"path": image_name, "sha256": hashlib.sha256(payload).hexdigest()}}]}).encode()
            elif name.endswith("runtime-observation.json"):
                body = json.dumps({"schema": "genewhip-v02-runtime-observation-v1", "status": "pass",
                    "observed": {}}).encode()
            elif name.endswith("execution-scope.json"):
                body = json.dumps({"schema": "genewhip-v02-execution-v1", "scope_id": "fixture"}).encode()
            elif name.endswith("candidate.json"):
                body = json.dumps({"schema": "genewhip-phase6-candidate-v1"}).encode()
            elif name.endswith("media-report.json"):
                body = json.dumps({"schema": "genewhip-phase6-media-v1", "result": "pass"}).encode()
            elif name.endswith(("host-software.json", "host-native.json")):
                body = json.dumps({"schema": "genewhip-phase6-host-v1", "backend": "software",
                    "outcome": "pass-diagnostic"}).encode()
            elif name.endswith("safety.json"):
                body = json.dumps({"schema": "genewhip-phase6-safety-v1", "status": "pass"}).encode()
            elif name.endswith("chunk.json"):
                body = json.dumps({"schema": "genewhip-phase6-chunk-v1", "status": "pass"}).encode()
            elif "/runtime/input-contract/" in name:
                body = json.dumps({"schema": "genewhip-phase6-sdl-virtual-input-contract-v1", "outcome": "pass"}).encode()
            elif name.endswith("safety-build-evidence.json"):
                body = json.dumps({"schema": "genewhip.v02-safety-build-evidence.v2", "entries": []}).encode()
            elif name.endswith("inventory.json"):
                body = json.dumps({"schema": "fixture-inventory"}).encode()
            elif name == "build/v02/public/roster.json":
                roster_document = json.loads((ROOT / "evidence/v02-roster.json").read_bytes())
                body = (json.dumps(roster_document, sort_keys=True, separators=(",", ":")) + "\n").encode()
            elif name == TRANSFER.PUBLIC_SCHEMA_MEMBER:
                schema_document = json.loads((ROOT / TRANSFER.CANONICAL_SCHEMA_SOURCE).read_bytes())
                body = (json.dumps(schema_document, sort_keys=True, separators=(",", ":")) + "\n").encode()
            elif name == "build/v02/public/observations.json":
                body = json.dumps([{"workload": "fixture", "status": "pass"}]).encode()
            else:
                body = json.dumps({"schema": "fixture-public", "outcome": "pass"}).encode()
            path.write_bytes(body)

    def _runtime_reference_fixture(self, root, *, private_renderer_path=False, stream_text=None):
        """Synthetic fixture matching the observed runtime reference/identity shapes."""
        self._fixture(root)

        def write_bytes(name, data):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            return path

        def write_json(name, document):
            data = json.dumps(document, sort_keys=True).encode("utf-8")
            return write_bytes(name, data)

        def ref(name, document=None):
            path = root / name
            data = path.read_bytes() if document is None else json.dumps(document, sort_keys=True).encode("utf-8")
            return {"path": name, "sha256": hashlib.sha256(data).hexdigest()}

        write_json("build/v02/public/execution-identity.json", {
            "schema": "genewhip-v02-runtime-identity-v1", "source_sha256": "a" * 64,
            "git_head": "a" * 40, "base_sha": "a" * 40, "run_id": "123", "run_attempt": "1"})

        identity_files = {
            "build/v02/runtime-build/tools/session/gw_headless": b"core executable fixture",
            "scripts/evidence/phase6_routes.py": b"compiler identity fixture",
            "fixtures/phase6/recursion94-consumed-map-v1.json": json.dumps({
                "schema": "genewhip-consumed-input-map-v1", "map_id": "recursion94-genewhip-public-client-v1",
                "source": {"input_program_sha256": "a" * 64}}, sort_keys=True).encode(),
            "fixtures/phase6/media-expectations-v1.json": b"media identity fixture",
            "tests/session/phase6_chunk_contract.c": b"chunk test source fixture",
            "build/v02/runtime-build/tools/session/phase6_chunk_contract": b"chunk executable fixture",
            "build/v02/runtime-build/tools/desktop/genewhip-desktop": b"desktop executable fixture",
        }
        for name, data in identity_files.items():
            write_bytes(name, data)
        map_path = "fixtures/phase6/recursion94-consumed-map-v1.json"
        mapping = json.loads((root / map_path).read_text(encoding="utf-8"))
        map_canonical_sha = hashlib.sha256(
            json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        map_raw_sha = hashlib.sha256(identity_files[map_path]).hexdigest()
        identity_refs = {
            "build/v02/runtime-build/tools/session/gw_headless",
            "scripts/evidence/phase6_routes.py", map_path,
            "fixtures/phase6/media-expectations-v1.json",
            "tests/session/phase6_chunk_contract.c",
            "build/v02/runtime-build/tools/session/phase6_chunk_contract",
            "build/v02/runtime-build/tools/desktop/genewhip-desktop",
        }

        core_base = "build/v02/runtime/core-work/canonical-core-fixture"
        core_case = core_base + "/recursion94-full-route-1"
        core_pcm = core_case + "/audio.pcm"
        core_native = core_case + "/native.json"
        core_process = core_case + "/process.json"
        core_trace = core_case + "/audio-trace.jsonl"
        core_scene = core_case + "/fields/route-capture.json"
        image_path = "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/fields/field-120.bin"
        core_candidate = core_base + "/candidate.json"
        control_path = core_base + "/controls-1/control.json"
        control_pcm = core_base + "/controls-1/artifacts/start-idle.pcm"
        stdout_path = core_base + "/controls-1/artifacts/start-idle/headless/child.stdout.raw"
        stderr_path = core_base + "/controls-1/artifacts/start-idle/headless/child.stderr.raw"
        write_bytes(core_pcm, b"core pcm fixture")
        write_json(core_native, {"schema": "genewhip-route-native-v1", "status": "pass"})
        write_json(core_process, {"processes": []})
        write_bytes(core_trace, b'{"event":"fixture"}\n')
        write_json(core_scene, {"schema": "genewhip-phase6-route-capture-v1", "status": "pass"})
        write_json(core_candidate, {"schema": "genewhip-phase6-candidate-v1"})
        write_bytes(control_pcm, b"control pcm fixture")
        stdout_data, stderr_data = b"bounded child output", b""
        write_bytes(stdout_path, stdout_data)
        write_bytes(stderr_path, stderr_data)

        def stream_ref(path, data):
            return {"path": path, "sha256": hashlib.sha256(data).hexdigest(),
                "observed_bytes": len(data), "retained_bytes": len(data), "truncated": False}

        control_report = {
            "results": [{"retained_pcm": ref(control_pcm), "process_streams": {
                "stdout": stream_ref(stdout_path, stdout_data),
                "stderr": stream_ref(stderr_path, stderr_data)}}],
            "native_child_processes": [{"streams": {
                "stdout": stream_ref(stdout_path, stdout_data),
                "stderr": stream_ref(stderr_path, stderr_data)}}],
        }
        write_json(control_path, control_report)
        image_ref = ref(image_path)
        write_json("build/v02/runtime-observation/candidate.json", {
            "schema": "genewhip-phase6-candidate-v1",
            "client_identities": {"public-core": ref("build/v02/runtime-build/tools/session/gw_headless")},
            "compiler_identity": ref("scripts/evidence/phase6_routes.py"),
            "delivery_map_identity": {"path": map_path, "sha256": map_canonical_sha, "schema": mapping["schema"]},
            "media_expectations_identity": ref("fixtures/phase6/media-expectations-v1.json"),
        })
        core_report = {
            "schema": "genewhip-phase6-product-report-v1",
            "candidate_manifest": ref(core_candidate),
            "controls": [ref(control_path)],
            "runs": [{"image": image_ref, "pcm": ref(core_pcm), "native_report": ref(core_native),
                "process_receipt": ref(core_process), "audio_trace": ref(core_trace),
                "scene_metadata": ref(core_scene)}],
        }
        write_json("build/v02/runtime-observation/core-report.json", core_report)
        core_report_ref = ref("build/v02/runtime-observation/core-report.json")
        write_json("build/v02/runtime-observation/media-report.json", {
            "schema": "genewhip-phase6-media-v1", "core_routes": core_report_ref})

        chunk_work = "build/v02/runtime/chunk-work/phase6-chunk-recursion94-fixture"
        chunk_report_path = chunk_work + "/chunk.json"
        write_json(chunk_report_path, {"schema": "genewhip-phase6-title-chunk-v1", "status": "pass"})
        write_json(chunk_work + "/process.json", {"processes": []})
        write_bytes(chunk_work + "/actual-inputs.csv", b"event_id,frame\n")
        write_json("build/v02/runtime-observation/chunk.json", {
            "schema": "genewhip-phase6-chunk-v1",
            "test_source": ref("tests/session/phase6_chunk_contract.c"),
            "test_executable": ref("build/v02/runtime-build/tools/session/phase6_chunk_contract"),
            "routes": [{"chunk_report": ref(chunk_report_path), "input_log": ref(chunk_work + "/actual-inputs.csv"),
                "source_run": {"full_pcm": ref(core_pcm), "native_report": ref(core_native),
                    "selected_media": image_ref}}],
        })

        host_base = "build/v02/runtime-build/evidence/phase6-sdl-host-fixture1"
        host_case = host_base + "/recursion94-full-route-attempt1"
        host_pcm = host_case + "/audio.pcm"
        host_renderer = host_case + "/renderer-field.bin"
        host_json = host_case + "/host.json"
        host_native = host_case + "/native.json"
        host_process = host_case + "/process.json"
        host_root_process = host_base + "/process.json"
        original_controls = host_base + "/original-host-controls-attempt1.json"
        write_bytes(host_pcm, b"desktop pcm fixture")
        write_bytes(host_renderer, bytes(320 * 224 * 4))
        private_renderer_path_value = ("/" + "Users" + "/" + "alice/" + "private/project/"
            + "renderer-field.bin")
        renderer_capture_path = (private_renderer_path_value if private_renderer_path else host_renderer)
        write_json(host_json, {"schema": "genewhip-phase6-sdl-diagnostic-v1",
            "input_path": "fixtures/phase6/input.gwrc", "renderer_capture_path": renderer_capture_path})
        write_json(host_native, {"schema": "genewhip-route-native-v1", "status": "pass"})
        write_json(host_process, {"processes": []})
        write_json(host_root_process, {"processes": []})
        write_json(original_controls, {"schema": "genewhip-phase4-host-sessions",
            "process_receipts": [], "runs": []})
        input_contract_path = "build/v02/runtime/input-contract/software.json"
        input_contract_native_path = "build/v02/runtime/input-contract/native.json"
        input_contract_ref = ref(input_contract_path)
        metadata_stdout = {"observed_bytes": len(stream_text or b""),
            "retained_bytes": len(stream_text or b""), "sha256": hashlib.sha256(stream_text or b"").hexdigest(),
            "truncated": False}
        if stream_text is not None:
            metadata_stdout["text"] = stream_text.decode("utf-8", errors="replace")
        host_attempt = {
            "route_metadata": {"client": "sdl", "map_id": mapping["map_id"],
                "original_input_sha256": "b" * 64, "schema": mapping["schema"], "sha256": map_canonical_sha},
            "streams": {"stdout": metadata_stdout,
                "stderr": {"observed_bytes": 0, "retained_bytes": 0,
                    "sha256": hashlib.sha256(b"").hexdigest(), "truncated": False}},
            "raw_outputs": {"host": ref(host_json), "native": ref(host_native),
                "pcm": ref(host_pcm), "renderer": ref(host_renderer)},
            "common_boundary": {"desktop_pcm": ref(host_pcm), "headless_pcm": ref(core_pcm),
                "headless_pixel": image_ref, "renderer_pixel": ref(host_renderer)},
            "process_receipt": ref(host_process),
        }
        host_common = {"schema": "genewhip-phase6-host-v1",
            "host_identity": {"core_report": core_report_ref, "desktop_binary": ref(
                "build/v02/runtime-build/tools/desktop/genewhip-desktop"),
                "delivery_map": {"path": map_path, "sha256": map_canonical_sha},
                "input_contract": input_contract_ref},
            "controls": {"report": ref(original_controls)},
            "process_receipt": ref(host_root_process), "attempts": [host_attempt]}
        write_json("build/v02/runtime-observation/host-software.json", host_common)
        write_json("build/v02/runtime-observation/host-native.json", host_common)

        api_keys = {"allocation_count_peak": 0, "allocation_instrumented": True, "audio_pass": 0,
            "cases": 0, "guards_checked": 0, "max_tick": 0, "mode": "pr", "negative_controls": 0,
            "output_cap_frames": 0, "returned_frames": 0, "safety_pass": 0, "seed": "47573105",
            "steady_allocations": 0, "steps": 0, "steps_per_case": 0, "tick_budget": 0}
        for name in ("native-api.json", "sanitize-api.json", "hooks-off-api.json"):
            write_json("build/v02/runtime/safety/" + name, api_keys)
        write_json("build/v02/runtime/safety/native-parser.json", {
            "schema": "genewhip-phase6-controller-contract-v1", "status": "fail", "tests": 1, "runs": []})
        build_identity_path = "build/v02/runtime-build/CMakeFiles/4.4.3/CMakeCCompiler.cmake"
        build_identity_bytes = b"compiler configuration fixture"
        write_bytes(build_identity_path, build_identity_bytes)
        compiler_identity = {"source_path": build_identity_path,
            "sha256": hashlib.sha256(build_identity_bytes).hexdigest(), "size": len(build_identity_bytes)}
        safety_evidence_row_path = "build/v02/runtime-observation/safety-build-evidence/native.json"
        cache_path = "build/v02/runtime-build/CMakeCache.txt"
        cache_bytes = b"cmake cache fixture"
        write_bytes(cache_path, cache_bytes)
        build_facts = {"schema": "genewhip.v02-portable-build-facts.v1", "variant": "native",
            "raw_build_artifact_identities": [{"source_path": cache_path,
                "sha256": hashlib.sha256(cache_bytes).hexdigest(), "size": len(cache_bytes)}]}
        write_json(safety_evidence_row_path, build_facts)
        safety_build_evidence_path = "build/v02/runtime-observation/safety-build-evidence.json"
        write_json(safety_build_evidence_path, {"schema": "genewhip.v02-safety-build-evidence.v2",
            "entries": [{**ref(safety_evidence_row_path), "size": (root / safety_evidence_row_path).stat().st_size,
                "source_path": cache_path, "source_sha256": hashlib.sha256(cache_bytes).hexdigest(),
                "source_size": len(cache_bytes), "variant": "native"}]})
        write_json("build/v02/runtime-observation/safety.json", {
            "schema": "genewhip-phase6-safety-v1", "status": "fail",
            "build_evidence": ref(safety_build_evidence_path), "parser_rejection": ref(
                "build/v02/runtime/safety/native-parser.json"),
            "variants": [{"api_contract": ref("build/v02/runtime/safety/native-api.json"),
                "build_identity": {"compiler_metadata": compiler_identity}}],
        })
        observed = {
            "chunk": ref("build/v02/runtime-observation/chunk.json"),
            "core": core_report_ref,
            "host-native": {**ref("build/v02/runtime-observation/host-native.json"), "capability": "native"},
            "host-software": {**ref("build/v02/runtime-observation/host-software.json"), "capability": "software"},
            "input-native": {**ref(input_contract_native_path), "capability": "native"},
            "input-software": {**input_contract_ref, "capability": "software"},
            "media": ref("build/v02/runtime-observation/media-report.json"),
            "safety": {**ref("build/v02/runtime-observation/safety.json"),
                "build_evidence": ref(safety_build_evidence_path)},
        }
        write_json("build/v02/runtime-observation.json", {
            "schema": "genewhip-v02-runtime-observation-v1", "status": "failed",
            "observed": observed})
        return identity_refs | {stdout_path, stderr_path, cache_path, build_identity_path}

    def test_actual_runtime_reference_shapes_export_verify_and_install_without_identities(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-actual-shapes-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            excluded = self._runtime_reference_fixture(root)
            out = root / "build/v02/runtime-transfer"
            inventory = TRANSFER.export(root, out)
            members = inventory["members"]
            expected_artifacts = {
                "build/v02/runtime/core-work/canonical-core-fixture/controls-1/control.json",
                "build/v02/runtime/core-work/canonical-core-fixture/controls-1/artifacts/start-idle.pcm",
                "build/v02/runtime-observation/safety-build-evidence/native.json",
                "build/v02/public/execution-identity.json",
                "build/v02/runtime/safety/native-api.json",
                "build/v02/runtime/safety/native-parser.json",
                "build/v02/runtime-build/evidence/phase6-sdl-host-fixture1/"
                    "recursion94-full-route-attempt1/host.json",
                "build/v02/runtime-build/evidence/phase6-sdl-host-fixture1/"
                    "recursion94-full-route-attempt1/renderer-field.bin",
            }
            self.assertTrue(expected_artifacts.issubset(members))
            self.assertTrue(excluded.isdisjoint(members))
            self.assertLessEqual(len(members), TRANSFER.MAX_MEMBERS)
            self.assertLessEqual(inventory["total_bytes"], TRANSFER.MAX_TOTAL_BYTES)
            transferred_observation = json.loads(
                (out / "payload/build/v02/runtime-observation.json").read_text(encoding="utf-8"))
            self.assertEqual(transferred_observation["status"], "failed")
            self.assertEqual(TRANSFER.verify(out / "payload", out / "inventory.json"), inventory)

            installed = pathlib.Path(temp) / "consumer"
            installed.mkdir()
            installed_inventory = TRANSFER.install(out / "payload", out / "inventory.json", installed)
            self.assertEqual(installed_inventory, inventory)
            self.assertFalse((installed / "scripts/evidence/phase6_routes.py").exists())
            self.assertFalse((installed / "build/v02/runtime-build/tools/session/gw_headless").exists())
            self.assertTrue((installed / "build/v02/runtime/safety/native-api.json").is_file())

    def test_optional_execution_identity_requires_exact_path_and_schema(self):
        self.assertTrue(TRANSFER._runtime_member_allowed("build/v02/public/execution-identity.json"))
        self.assertFalse(TRANSFER._runtime_member_allowed("build/v02/public/other/execution-identity.json"))
        with tempfile.TemporaryDirectory(prefix="gw-runtime-execution-identity-schema-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._runtime_reference_fixture(root)
            TRANSFER._collect(root)
            identity_path = root / "build/v02/public/execution-identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            identity["schema"] = "other-runtime-identity-v1"
            identity_path.write_text(json.dumps(identity), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "transfer-json-schema-role-mismatch"):
                TRANSFER._collect(root)

    def test_runtime_safety_api_seed_requires_eight_lowercase_hex_digits(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-safety-api-seed-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._runtime_reference_fixture(root)
            name = "build/v02/runtime/safety/native-api.json"
            api_report = json.loads((root / name).read_text(encoding="utf-8"))
            self.assertEqual(api_report["seed"], "47573105")
            TRANSFER._validate_runtime_json(name, api_report)
            for invalid_seed in (47573105, "4757310g"):
                with self.subTest(seed=invalid_seed):
                    mutant = {**api_report, "seed": invalid_seed}
                    with self.assertRaisesRegex(ValueError, "transfer-safety-api-contract-shape"):
                        TRANSFER._validate_runtime_json(name, mutant)

    def test_public_observations_requires_a_list_of_objects(self):
        name = "build/v02/public/observations.json"
        TRANSFER._validate_runtime_json(name, [{"workload": "fixture"}])
        for invalid in ({"observations": []}, [{"workload": "fixture"}, "bad-row"]):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "transfer-public-observations-shape"):
                    TRANSFER._validate_runtime_json(name, invalid)
        with self.assertRaisesRegex(ValueError, "transfer-json-role-not-object"):
            TRANSFER._validate_runtime_json("build/v02/public/manifest.json", [])
        self.assertFalse(TRANSFER._runtime_member_allowed("build/v02/public/unknown.json"))

    def test_public_schema_references_are_bound_to_canonical_source(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-public-schema-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._fixture(root)
            name = TRANSFER.PUBLIC_SCHEMA_MEMBER
            schema_path = root / name
            schema_bytes = schema_path.read_bytes()
            schema_document = json.loads(schema_bytes)
            self.assertEqual(schema_document["schema"], "genewhip-v02-schema-document-v1")
            TRANSFER._validate_references(schema_document, {}, document_name=name,
                document_bytes=schema_bytes)

            mutated_document = copy.deepcopy(schema_document)
            mutated_document["properties"]["schema"]["const"] = "mutated-schema"
            mutated_bytes = (json.dumps(mutated_document, sort_keys=True, separators=(",", ":"))
                + "\n").encode()
            with self.assertRaisesRegex(ValueError, "transfer-public-schema-not-canonical"):
                TRANSFER._validate_references(mutated_document, {}, document_name=name,
                    document_bytes=mutated_bytes)

            canonical_root = pathlib.Path(temp) / "canonical-source"
            source_path = canonical_root / TRANSFER.CANONICAL_SCHEMA_SOURCE
            source_path.parent.mkdir(parents=True)
            source_path.write_bytes((ROOT / TRANSFER.CANONICAL_SCHEMA_SOURCE).read_bytes())
            source_document = json.loads(source_path.read_bytes())
            source_document["properties"]["scope"]["enum"].append("mutated")
            source_path.write_text(json.dumps(source_document), encoding="utf-8")
            with mock.patch.object(TRANSFER, "ROOT", canonical_root):
                with self.assertRaisesRegex(ValueError, "transfer-public-schema-not-canonical"):
                    TRANSFER._validate_references(schema_document, {}, document_name=name,
                        document_bytes=schema_bytes)

    def test_control_session_roster_is_pinned_hash_only_metadata(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-control-roster-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._fixture(root)
            roster_path = root / "build/v02/public/roster.json"
            roster_document = json.loads(roster_path.read_text(encoding="utf-8"))
            record = roster_document["matrix"]["control_session_roster"]
            self.assertEqual(TRANSFER._classify_reference("control_session_roster", record), "metadata")
            members, _total = TRANSFER._collect(root)
            self.assertIn("build/v02/public/roster.json", members)
            self.assertFalse(any("control-session" in name for name in members))

        mutations = ("omitted-hash", "null-hash", "wrong-hash", "wrong-schema", "wrong-sessions", "extra-key")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                    prefix="gw-runtime-control-roster-mutant-") as temp:
                root = pathlib.Path(temp) / "producer"
                root.mkdir()
                self._fixture(root)
                roster_path = root / "build/v02/public/roster.json"
                roster_document = json.loads(roster_path.read_text(encoding="utf-8"))
                record = roster_document["matrix"]["control_session_roster"]
                if mutation == "omitted-hash":
                    record.pop("sha256")
                elif mutation == "null-hash":
                    record["sha256"] = None
                elif mutation == "wrong-hash":
                    record["sha256"] = "0" * 64
                elif mutation == "wrong-schema":
                    record["schema"] = "other-roster-v1"
                elif mutation == "wrong-sessions":
                    record["sessions"] = ["unreviewed-session"]
                else:
                    record["unreviewed"] = True
                roster_path.write_text(json.dumps(roster_document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "transfer-hash-metadata-invalid:control_session_roster"):
                    TRANSFER._collect(root)

    def test_runtime_identity_role_path_hash_and_unknown_metadata_are_rejected(self):
        mutations = ("unknown-path", "wrong-hash", "unknown-hash-record")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                    prefix="gw-runtime-transfer-identity-mutant-") as temp:
                root = pathlib.Path(temp) / "producer"
                root.mkdir()
                self._runtime_reference_fixture(root)
                candidate_path = root / "build/v02/runtime-observation/candidate.json"
                candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
                identity = candidate["client_identities"]["public-core"]
                if mutation == "unknown-path":
                    identity["path"] = "fixtures/phase6/private.rom"
                    reason = "transfer-identity-role-or-reference-invalid:public-core"
                elif mutation == "wrong-hash":
                    identity["sha256"] = "0" * 64
                    reason = "transfer-identity-source-digest-mismatch:public-core"
                else:
                    candidate["unreviewed_hash_record"] = {
                        "source_path": "fixtures/phase6/private.rom", "sha256": "1" * 64, "size": 10}
                    reason = "transfer-reference-role-or-identity-invalid:unreviewed_hash_record"
                candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, reason):
                    TRANSFER._collect(root)

    def test_known_identity_metadata_requires_sha256(self):
        records = (
            ("compiler_metadata", {
                "source_path": "build/v02/runtime-build/CMakeFiles/4.4.3/CMakeCCompiler.cmake",
                "sha256": "a" * 64, "size": 1}),
            ("raw_build_artifact_identities", {
                "source_path": "build/v02/runtime-build/CMakeCache.txt",
                "sha256": "b" * 64, "size": 1}),
        )
        for role, record_template in records:
            for mutation in ("omitted", "null"):
                with self.subTest(role=role, mutation=mutation):
                    record = dict(record_template)
                    if mutation == "omitted":
                        record.pop("sha256")
                    else:
                        record["sha256"] = None
                    with self.assertRaisesRegex(ValueError, "transfer-hash-metadata-invalid:" + role):
                        TRANSFER._classify_reference(role, record)

        with self.assertRaisesRegex(ValueError, "transfer-identity-role-or-reference-invalid:delivery_map_identity"):
            TRANSFER._classify_reference("delivery_map_identity", {})
        self.assertIsNone(TRANSFER._classify_reference("unstructured", {}))

    def test_runtime_transfer_keeps_privacy_rejection_for_private_paths_and_stream_bytes(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-private-host-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._runtime_reference_fixture(root, private_renderer_path=True)
            with self.assertRaisesRegex(ValueError, "transfer-private-path:"):
                TRANSFER._collect(root)
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-private-stream-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._runtime_reference_fixture(root, stream_text=b"github_pat_" + b"a" * 40)
            with self.assertRaisesRegex(ValueError, "transfer-secret-pattern:"):
                TRANSFER._collect(root)

    def test_identity_snapshot_reader_rejects_links_special_files_changes_and_growth(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-owned-snapshot-") as temp:
            root = pathlib.Path(temp)
            (root / "regular").write_bytes(b"owned")
            (root / "symlink").symlink_to("regular")
            with self.assertRaisesRegex(ValueError, "transfer-owned-file-invalid"):
                TRANSFER._read_owned_file_snapshot(root, "symlink", label="symlink")

            os.link(root / "regular", root / "hardlink")
            with self.assertRaisesRegex(ValueError, "transfer-owned-file-invalid"):
                TRANSFER._read_owned_file_snapshot(root, "hardlink", label="hardlink")

            fifo = root / "fifo-race"
            fifo.write_bytes(b"regular before open")
            real_open = os.open
            observed_flags = []

            def replace_with_fifo(path, flags, *args, **kwargs):
                if path == fifo.name:
                    fifo.unlink()
                    os.mkfifo(fifo)
                    observed_flags.append(flags)
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(TRANSFER.os, "open", side_effect=replace_with_fifo):
                with self.assertRaisesRegex(ValueError, "transfer-owned-file-invalid"):
                    TRANSFER._read_owned_file_snapshot(root, fifo.name, label="fifo-race")
            self.assertTrue(observed_flags[0] & os.O_NOFOLLOW)
            self.assertTrue(observed_flags[0] & os.O_NONBLOCK)

        with tempfile.TemporaryDirectory(prefix="gw-transfer-owned-snapshot-replace-") as temp:
            root = pathlib.Path(temp)
            target = root / "identity"
            target.write_bytes(b"before")
            real_read = os.read
            replaced = False

            def replace_path_after_read(descriptor, count):
                nonlocal replaced
                data = real_read(descriptor, count)
                if not replaced:
                    replacement = root / "replacement"
                    replacement.write_bytes(b"after!")
                    os.replace(replacement, target)
                    replaced = True
                return data

            with mock.patch.object(TRANSFER.os, "read", side_effect=replace_path_after_read):
                with self.assertRaisesRegex(ValueError, "transfer-owned-file-changed-during-read"):
                    TRANSFER._read_owned_file_snapshot(root, target.name, label="replacement-race")

        with tempfile.TemporaryDirectory(prefix="gw-transfer-owned-snapshot-grow-") as temp:
            root = pathlib.Path(temp)
            target = root / "grow"
            target.write_bytes(b"1234")
            real_read = os.read

            def grow_after_read(descriptor, count):
                data = real_read(descriptor, count)
                target.write_bytes(b"123456789")
                return data

            with mock.patch.object(TRANSFER, "MAX_FILE_BYTES", 4), \
                    mock.patch.object(TRANSFER.os, "read", side_effect=grow_after_read):
                with self.assertRaisesRegex(ValueError, "transfer-owned-file-size-limit"):
                    TRANSFER._read_owned_file_snapshot(root, target.name, label="grow-race")

    def test_snapshot_reader_rejects_symlinked_parent_and_parent_swap(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-parent-symlink-") as temp:
            base = pathlib.Path(temp)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "file").write_bytes(b"outside bytes")
            (root / "parent").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "transfer-owned-file-read-failed"):
                TRANSFER._read_owned_file_snapshot(root, "parent/file", label="parent-symlink")

        with tempfile.TemporaryDirectory(prefix="gw-transfer-parent-swap-") as temp:
            base = pathlib.Path(temp)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "parent").mkdir()
            (root / "parent/file").write_bytes(b"inside bytes")
            (outside / "file").write_bytes(b"outside bytes")
            real_open = os.open
            swapped = False

            def swap_parent_after_open(path, flags, *args, **kwargs):
                nonlocal swapped
                descriptor = real_open(path, flags, *args, **kwargs)
                if path == "parent" and kwargs.get("dir_fd") is not None and not swapped:
                    os.rename(root / "parent", root / "parent-held")
                    (root / "parent").symlink_to(outside, target_is_directory=True)
                    swapped = True
                return descriptor

            with mock.patch.object(TRANSFER.os, "open", side_effect=swap_parent_after_open):
                with self.assertRaisesRegex(ValueError, "transfer-owned-file-read-failed|transfer-owned-parent-changed"):
                    TRANSFER._read_owned_file_snapshot(root, "parent/file", label="parent-swap")
            self.assertTrue(swapped)
            self.assertEqual((outside / "file").read_bytes(), b"outside bytes")

    def test_snapshot_reader_closes_parent_fd_when_fstat_fails(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-parent-fstat-failure-") as temp:
            root = pathlib.Path(temp)
            (root / "parent").mkdir()
            (root / "parent/file").write_bytes(b"inside bytes")
            real_open, real_fstat = os.open, os.fstat
            opened_parent_fds = []

            def track_parent_open(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                if path == "parent" and kwargs.get("dir_fd") is not None:
                    opened_parent_fds.append(descriptor)
                return descriptor

            def fail_parent_fstat(descriptor):
                if descriptor in opened_parent_fds:
                    raise OSError("injected parent fstat failure")
                return real_fstat(descriptor)

            with mock.patch.object(TRANSFER.os, "open", side_effect=track_parent_open), \
                    mock.patch.object(TRANSFER.os, "fstat", side_effect=fail_parent_fstat):
                with self.assertRaisesRegex(ValueError, "transfer-owned-file-read-failed"):
                    TRANSFER._read_owned_file_snapshot(root, "parent/file", label="parent-fstat-failure")
            self.assertEqual(len(opened_parent_fds), 1)
            with self.assertRaises(OSError):
                real_fstat(opened_parent_fds[0])

    def test_collect_total_cap_is_incremental_before_snapshot_retention(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-incremental-cap-") as temp:
            root = pathlib.Path(temp)
            first_name = "build/v02/runtime-observation.json"
            second_name = "build/v02/runtime-identity.json"
            first = json.dumps({"schema": "genewhip-v02-runtime-observation-v1",
                "status": "pass", "observed": {}}).encode()
            second = json.dumps({"schema": "genewhip-v02-runtime-identity-v1",
                "source_sha256": "a" * 64, "git_head": "a" * 40,
                "base_sha": "a" * 40, "run_id": "123", "run_attempt": "1"}).encode()
            for name, data in ((first_name, first), (second_name, second)):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            snapshots = {}
            with mock.patch.object(TRANSFER, "DIRECT_MEMBERS", (first_name, second_name)), \
                    mock.patch.object(TRANSFER, "MAX_TOTAL_BYTES", len(first)):
                with self.assertRaisesRegex(ValueError, "transfer-total-byte-limit"):
                    TRANSFER._collect(root, captured_bytes=snapshots)
            self.assertEqual(set(snapshots), {first_name})
            self.assertLessEqual(sum(map(len, snapshots.values())), len(first))

    def test_export_writes_captured_bytes_after_source_changes(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-snapshot-export-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            original = bytes(320 * 224 * 4)
            replacement = b"x" * len(original)
            self._fixture(root, payload=original)
            image_name = "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/fields/field-120.bin"
            image_path = root / image_name
            real_collect = TRANSFER._collect

            def collect_then_replace(source_root, *, captured_bytes=None):
                result = real_collect(source_root, captured_bytes=captured_bytes)
                image_path.write_bytes(replacement)
                return result

            out = root / "build/v02/runtime-transfer"
            with mock.patch.object(TRANSFER, "_collect", side_effect=collect_then_replace):
                inventory = TRANSFER.export(root, out)
            payload_image = out / "payload" / image_name
            self.assertEqual(image_path.read_bytes(), replacement)
            self.assertEqual(payload_image.read_bytes(), original)
            self.assertEqual(inventory["members"][image_name]["sha256"], hashlib.sha256(original).hexdigest())

    def test_runtime_receiver_rejects_symlinked_member_parent_and_inventory(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-receiver-parent-link-") as temp:
            base = pathlib.Path(temp)
            root = base / "producer"
            root.mkdir()
            self._fixture(root)
            out = root / "build/v02/runtime-transfer"
            TRANSFER.export(root, out)
            image_name = "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/fields/field-120.bin"
            payload = out / "payload"
            fields = (payload / image_name).parent
            outside = base / "outside"
            outside.mkdir()
            (outside / "field-120.bin").write_bytes(bytes(320 * 224 * 4))
            moved = fields.with_name("fields-held")
            fields.rename(moved)
            fields.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "transfer-unsafe-entry|transfer-unlisted-or-missing-member"):
                TRANSFER.verify(payload, out / "inventory.json")

        with tempfile.TemporaryDirectory(prefix="gw-transfer-receiver-inventory-link-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._fixture(root)
            out = root / "build/v02/runtime-transfer"
            TRANSFER.export(root, out)
            inventory_link = out / "inventory-link.json"
            inventory_link.symlink_to(out / "inventory.json")
            with self.assertRaisesRegex(ValueError, "transfer-owned-file-invalid"):
                TRANSFER.verify(out / "payload", inventory_link)

    def test_runtime_inventory_uses_one_bounded_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-inventory-snapshot-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._fixture(root)
            out = root / "build/v02/runtime-transfer"
            inventory = TRANSFER.export(root, out)
            inventory_path = out / "inventory.json"
            original = inventory_path.read_bytes()
            replacement = b"{}"
            real_reader = TRANSFER._read_owned_file_snapshot
            replaced = False

            def replace_after_snapshot(*args, **kwargs):
                nonlocal replaced
                data = real_reader(*args, **kwargs)
                if kwargs.get("label") == "runtime-transfer-inventory" and not replaced:
                    inventory_path.write_bytes(replacement)
                    replaced = True
                return data

            with mock.patch.object(TRANSFER, "_read_owned_file_snapshot", side_effect=replace_after_snapshot):
                self.assertEqual(TRANSFER.verify(out / "payload", inventory_path), inventory)
            self.assertTrue(replaced)
            self.assertEqual(inventory_path.read_bytes(), replacement)

            inventory_path.write_bytes(original)
            with mock.patch.object(TRANSFER, "MAX_FILE_BYTES", 32):
                with self.assertRaisesRegex(ValueError, "transfer-owned-file-size-limit:runtime-transfer-inventory"):
                    TRANSFER.verify(out / "payload", inventory_path)

    def test_install_writes_the_snapshot_verified_before_payload_replacement(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-install-snapshot-") as temp:
            base = pathlib.Path(temp)
            root = base / "producer"
            root.mkdir()
            original = bytes(320 * 224 * 4)
            replacement = b"x" * len(original)
            self._fixture(root, payload=original)
            out = root / "build/v02/runtime-transfer"
            TRANSFER.export(root, out)
            image_name = "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/fields/field-120.bin"
            source_image = out / "payload" / image_name
            real_verify = TRANSFER.verify

            def verify_then_replace(payload_root, inventory_path, *, captured_bytes=None):
                inventory = real_verify(payload_root, inventory_path, captured_bytes=captured_bytes)
                source_image.write_bytes(replacement)
                return inventory

            installed = base / "installed"
            installed.mkdir()
            with mock.patch.object(TRANSFER, "verify", side_effect=verify_then_replace):
                TRANSFER.install(out / "payload", out / "inventory.json", installed)
            self.assertEqual(source_image.read_bytes(), replacement)
            self.assertEqual((installed / image_name).read_bytes(), original)

    def test_install_rejects_symlinked_destination_parent(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-install-parent-link-") as temp:
            base = pathlib.Path(temp)
            producer = base / "producer"
            producer.mkdir()
            self._fixture(producer)
            transfer_root = producer / "build/v02/runtime-transfer"
            TRANSFER.export(producer, transfer_root)
            outside = base / "outside"
            outside.mkdir()
            installed = base / "installed"
            installed.mkdir()
            (installed / "build").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "transfer-install-parent-open-failed"):
                TRANSFER.install(transfer_root / "payload", transfer_root / "inventory.json", installed)
            self.assertEqual(list(outside.iterdir()), [])

    def test_install_rejects_existing_destination_leaf(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-install-leaf-collision-") as temp:
            base = pathlib.Path(temp)
            producer = base / "producer"
            producer.mkdir()
            self._fixture(producer)
            transfer_root = producer / "build/v02/runtime-transfer"
            inventory = TRANSFER.export(producer, transfer_root)
            installed = base / "installed"
            installed.mkdir()
            name = sorted(inventory["members"])[0]
            collision = installed / name
            collision.parent.mkdir(parents=True)
            collision.write_bytes(b"keep existing bytes")

            with self.assertRaisesRegex(ValueError, "transfer-install-collision"):
                TRANSFER.install(transfer_root / "payload", transfer_root / "inventory.json", installed)
            self.assertEqual(collision.read_bytes(), b"keep existing bytes")

    def test_install_detects_destination_parent_swap_and_removes_its_leaf(self):
        with tempfile.TemporaryDirectory(prefix="gw-transfer-install-parent-swap-") as temp:
            base = pathlib.Path(temp)
            producer = base / "producer"
            producer.mkdir()
            self._fixture(producer)
            transfer_root = producer / "build/v02/runtime-transfer"
            inventory = TRANSFER.export(producer, transfer_root)
            installed = base / "installed"
            installed.mkdir()
            outside = base / "outside"
            outside.mkdir()
            moved_parent = outside / "moved-parent"
            attacker_parent = outside / "attacker-parent"
            attacker_parent.mkdir()
            name = sorted(inventory["members"])[0]
            relative = pathlib.PurePosixPath(name)
            destination_parent = installed.joinpath(*relative.parts[:-1])
            leaf = relative.parts[-1]
            real_open = os.open
            swapped = False

            def swap_parent_before_leaf(path, flags, *args, **kwargs):
                nonlocal swapped
                if (not swapped and path == leaf and kwargs.get("dir_fd") is not None
                        and flags & getattr(os, "O_EXCL", 0)):
                    destination_parent.rename(moved_parent)
                    destination_parent.symlink_to(attacker_parent, target_is_directory=True)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(TRANSFER.os, "open", side_effect=swap_parent_before_leaf):
                with self.assertRaisesRegex(ValueError,
                        "transfer-owned-parent-changed|transfer-owned-file-open-failed|transfer-install-write-failed"):
                    TRANSFER.install(transfer_root / "payload", transfer_root / "inventory.json", installed)

            self.assertTrue(swapped)
            self.assertTrue(destination_parent.is_symlink())
            self.assertEqual(list(moved_parent.iterdir()), [])
            self.assertEqual(list(attacker_parent.iterdir()), [])

    def test_export_preserves_all_dimension_inputs_and_exact_references(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-") as temp:
            root = pathlib.Path(temp) / "project"
            root.mkdir()
            self._fixture(root)
            out = root / "build/v02/runtime-transfer"
            result = TRANSFER.export(root, out)
            self.assertGreaterEqual(result["member_count"], len(TRANSFER.DIRECT_MEMBERS) + 1)
            self.assertEqual(TRANSFER.verify(out / "payload", out / "inventory.json"), result)
            expected = {"build/v02/runtime-observation/core-report.json",
                "build/v02/runtime-observation/host-software.json",
                "build/v02/runtime-observation/host-native.json",
                "build/v02/runtime-observation/media-report.json",
                "build/v02/runtime-observation/safety.json",
                "build/v02/runtime-observation/chunk.json",
                "build/v02/runtime/input-contract/software.json",
                "build/v02/runtime/input-contract/native.json",
                "build/v02/public/manifest.json",
                "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/fields/field-120.bin"}
            self.assertTrue(expected.issubset(result["members"]))
            field_path = "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/fields/field-120.bin"
            self.assertEqual((out / "payload" / field_path).read_bytes(), bytes(320 * 224 * 4))
            installed = pathlib.Path(temp) / "installed"
            installed.mkdir()
            TRANSFER.install(out / "payload", out / "inventory.json", installed)
            self.assertEqual((installed / field_path).read_bytes(), bytes(320 * 224 * 4))

    def test_export_rejects_private_path_secret_and_unsafe_reference(self):
        cases = ((b"/" + b"Users" + b"/alice/private/project", "transfer-private-path"),
                 (b"ghp_" + b"abcdefghijklmnopqrstuvwxyz0123456789", "transfer-secret-pattern"),
                 (b"github_pat_" + b"a" * 40, "transfer-secret-pattern"),
                 (b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----", "transfer-secret-pattern"))
        for index, (payload, reason) in enumerate(cases):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-reject-") as temp:
                root = pathlib.Path(temp) / "project"
                root.mkdir()
                self._fixture(root, payload=payload.ljust(320 * 224 * 4, b"\x00"))
                with self.assertRaisesRegex(ValueError, reason):
                    TRANSFER.export(root, root / "build/v02/runtime-transfer")
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-path-") as temp:
            root = pathlib.Path(temp) / "project"
            root.mkdir()
            self._fixture(root, unsafe_path="../outside.bin")
            with self.assertRaisesRegex(ValueError, "transfer-reference-role-or-identity-invalid"):
                TRANSFER.export(root, root / "build/v02/runtime-transfer")
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-private-field-") as temp:
            root = pathlib.Path(temp) / "project"
            root.mkdir()
            self._fixture(root)
            observation = root / "build/v02/runtime-observation.json"
            document = json.loads(observation.read_text())
            document["token"] = "fixture-token-value"
            observation.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "transfer-private-field:token"):
                TRANSFER.export(root, root / "build/v02/runtime-transfer")

    def test_download_verifier_rejects_unlisted_or_unsafe_member(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-unlisted-") as temp:
            root = pathlib.Path(temp) / "project"
            root.mkdir()
            self._fixture(root)
            out = root / "build/v02/runtime-transfer"
            TRANSFER.export(root, out)
            (out / "payload/build/v02/runtime/unlisted.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "transfer-unlisted-or-missing-member"):
                TRANSFER.verify(out / "payload", out / "inventory.json")

    def test_pinned_artifact_relative_root_installs_from_download_directory(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-artifact-layout-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._fixture(root)
            transfer_root = root / "build/v02/runtime-transfer"
            TRANSFER.export(root, transfer_root)

            # upload-artifact v4 preserves paths relative to the least common
            # ancestor of the supplied paths: runtime-transfer here.
            extracted = pathlib.Path(temp) / "consumer/build/v02/runtime-transfer"
            extracted.mkdir(parents=True)
            for source in (transfer_root / "payload", transfer_root / "inventory.json"):
                destination = extracted / source.relative_to(transfer_root)
                if source.is_dir():
                    import shutil
                    shutil.copytree(source, destination)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
            installed = pathlib.Path(temp) / "consumer"
            self.assertEqual(TRANSFER.install(extracted / "payload", extracted / "inventory.json", installed)["member_count"],
                TRANSFER.verify(extracted / "payload", extracted / "inventory.json")["member_count"])

    def test_package_artifact_layout_verifies_before_install_and_rejects_unlisted_rom(self):
        with tempfile.TemporaryDirectory(prefix="gw-package-artifact-layout-") as temp:
            source_sha = "a" * 40  # Git revision, not the product-content digest.
            content_sha = "b" * 64
            runtime_identity = {"schema": "genewhip-v02-runtime-identity-v1",
                "source_sha256": content_sha, "git_head": source_sha, "base_sha": "c" * 40,
                "run_id": "123", "run_attempt": "2", "scope_sha256": "d" * 64,
                "candidate_sha256": "e" * 64, "build_identity": {key: "f" * 64 for key in
                    ("cmake_cache_sha256", "configuration_sha256", "headless_sha256", "desktop_sha256")}}
            identity = {"source_sha": source_sha, "head_sha": source_sha, "base_sha": "c" * 40,
                "run_id": "123", "run_attempt": "2"}
            candidate_name = "build/v02/runtime-observation/candidate.json"
            candidate_bytes = json.dumps({"schema": "genewhip-phase6-candidate-v1"}).encode()
            closure_paths = {candidate_name}
            payload = pathlib.Path(temp) / "producer/build/v02/package-transfer/payload"
            payload.mkdir(parents=True)
            names = TRANSFER.expected_package_members(source_sha, closure_paths)
            members = {}
            archive_bytes = io.BytesIO()
            with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
                item = tarfile.TarInfo("README.txt")
                item.size = 7
                archive.addfile(item, io.BytesIO(b"offline\n"))
            for name in names:
                path = payload / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if name.endswith(".tar.gz"):
                    data = archive_bytes.getvalue()
                elif name == "artifacts/release-assets/inventory.json":
                    data = json.dumps({"source_revision": source_sha,
                        "assets": {item: {} for item in TRANSFER._package_asset_names(source_sha)}}).encode()
                elif name == "build/v02/runtime-identity.json":
                    data = json.dumps(runtime_identity).encode()
                elif name == candidate_name:
                    data = candidate_bytes
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["core"]:
                    data = json.dumps({"schema": "genewhip-phase6-product-report-v1",
                        "candidate_manifest": {"path": candidate_name,
                            "sha256": hashlib.sha256(candidate_bytes).hexdigest()}}).encode()
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["host"]:
                    data = json.dumps({"schema": "genewhip-phase6-host-v1"}).encode()
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["host-native"]:
                    data = json.dumps({"schema": "genewhip-phase6-host-v1"}).encode()
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["media"]:
                    data = json.dumps({"schema": "genewhip-phase6-media-v1"}).encode()
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["safety"]:
                    data = json.dumps({"schema": "genewhip-phase6-safety-v1"}).encode()
                elif name == TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS["determinism"]:
                    data = json.dumps({"schema": "genewhip-phase6-chunk-v1"}).encode()
                else:
                    data = b"{}"
                path.write_bytes(data)
                members[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            closure = {"schema": "genewhip.v02-evidence-closure.v1", "identity": identity,
                "dimensions": {name: {"path": TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS[name],
                    "sha256": members[TRANSFER.PACKAGE_DIMENSION_SOURCE_PATHS[name]]["sha256"], "identity": identity}
                    for name in TRANSFER.DIMENSIONS},
                "referenced_files": {candidate_name: hashlib.sha256(candidate_bytes).hexdigest()}}
            closure_bytes = json.dumps(closure).encode()
            closure_path = payload / "build/v02/qualification-evidence-closure.json"
            closure_path.write_bytes(closure_bytes)
            members["build/v02/qualification-evidence-closure.json"] = {
                "sha256": hashlib.sha256(closure_bytes).hexdigest(), "size": len(closure_bytes)}
            produced_names, produced_git, produced_content, _ = TRANSFER._package_files(payload,
                expected_git_revision=source_sha, expected_product_content_sha256=content_sha)
            self.assertEqual((produced_git, produced_content), (source_sha, content_sha))
            self.assertIn(candidate_name, produced_names)
            inventory = {"schema": "genewhip.v02-package-transfer.v1", "source_sha": source_sha,
                "product_content_sha256": content_sha,
                "members": members, "member_count": len(members),
                "total_bytes": sum(row["size"] for row in members.values())}
            self.assertEqual(inventory["source_sha"], source_sha)
            self.assertEqual(inventory["product_content_sha256"], content_sha)
            transfer_root = pathlib.Path(temp) / "producer/build/v02/package-transfer"
            inventory_path = transfer_root / "inventory.json"
            inventory_path.write_text(json.dumps(inventory))

            # Mirror the pinned upload-artifact root and download directory.
            extracted = pathlib.Path(temp) / "consumer/build/v02/package-transfer"
            import shutil
            shutil.copytree(transfer_root, extracted)
            consumer = pathlib.Path(temp) / "consumer"
            TRANSFER.install_package(extracted / "payload", extracted / "inventory.json", consumer,
                expected_source_sha=source_sha, expected_product_content_sha256=content_sha)
            self.assertTrue((consumer / "artifacts/release-assets/inventory.json").is_file())
            self.assertEqual((consumer / candidate_name).read_bytes(), candidate_bytes)

            for field, wrong in (("source_sha", content_sha), ("product_content_sha256", "9" * 64)):
                changed_identity = json.loads(json.dumps(inventory))
                changed_identity[field] = wrong
                inventory_path.write_text(json.dumps(changed_identity))
                with self.assertRaisesRegex(ValueError, "transfer-package-inventory-schema-or-roster"):
                    TRANSFER.verify_package(extracted / "payload", inventory_path,
                        expected_source_sha=source_sha, expected_product_content_sha256=content_sha)
            inventory_path.write_text(json.dumps(inventory))
            identity_path = extracted / "payload/build/v02/runtime-identity.json"
            for field, wrong in (("git_head", "9" * 40), ("source_sha256", "8" * 64)):
                changed_runtime_identity = dict(runtime_identity)
                changed_runtime_identity[field] = wrong
                changed_bytes = json.dumps(changed_runtime_identity).encode()
                identity_path.write_bytes(changed_bytes)
                changed_inventory = json.loads(json.dumps(inventory))
                changed_inventory["members"]["build/v02/runtime-identity.json"] = {
                    "sha256": hashlib.sha256(changed_bytes).hexdigest(), "size": len(changed_bytes)}
                changed_inventory["total_bytes"] = sum(row["size"] for row in changed_inventory["members"].values())
                inventory_path.write_text(json.dumps(changed_inventory))
                with self.assertRaisesRegex(ValueError, "transfer-package-source-identity-mismatch"):
                    TRANSFER.verify_package(extracted / "payload", inventory_path,
                        expected_source_sha=source_sha, expected_product_content_sha256=content_sha)
            identity_path.write_bytes(json.dumps(runtime_identity).encode())
            inventory_path.write_text(json.dumps(inventory))

            incomplete = json.loads(json.dumps(inventory))
            closure["referenced_files"] = {}
            changed_closure = json.dumps(closure).encode()
            closure_path.write_bytes(changed_closure)
            incomplete["members"].pop(candidate_name)
            incomplete["members"]["build/v02/qualification-evidence-closure.json"] = {
                "sha256": hashlib.sha256(changed_closure).hexdigest(), "size": len(changed_closure)}
            incomplete["member_count"] = len(incomplete["members"])
            incomplete["total_bytes"] = sum(row["size"] for row in incomplete["members"].values())
            (extracted / "payload" / candidate_name).unlink()
            (extracted / "inventory.json").write_text(json.dumps(incomplete))
            with self.assertRaisesRegex(ValueError, "transfer-package-evidence-reference-inventory-mismatch"):
                TRANSFER.verify_package(extracted / "payload", extracted / "inventory.json",
                    expected_source_sha=source_sha, expected_product_content_sha256=content_sha)
            closure_path.write_bytes(closure_bytes)
            shutil.rmtree(extracted)
            shutil.copytree(transfer_root, extracted)

            receipt_name = "artifacts/release-assets/SHA256SUMS"
            receipt_path = extracted / "payload" / receipt_name
            for secret in (b"/" + b"Users" + b"/alice/private/project", b"github_pat_" + b"a" * 40,
                           b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----"):
                body = json.dumps({"evidence": secret.decode("ascii")}).encode()
                receipt_path.write_bytes(body)
                inventory["members"][receipt_name] = {"sha256": hashlib.sha256(body).hexdigest(),
                    "size": len(body)}
                inventory["total_bytes"] = sum(row["size"] for row in inventory["members"].values())
                inventory_path.write_text(json.dumps(inventory))
                with self.assertRaisesRegex(ValueError, "transfer-private-path|transfer-secret-pattern"):
                    TRANSFER.verify_package(extracted / "payload", inventory_path,
                        expected_source_sha=source_sha, expected_product_content_sha256=content_sha)

            private = extracted / "payload/build/v02/runtime-observation/private.rom"
            private.write_bytes(b"private")
            with self.assertRaisesRegex(ValueError, "transfer-package-unlisted-or-unsafe-member"):
                TRANSFER.verify_package(extracted / "payload", extracted / "inventory.json",
                    expected_source_sha=source_sha, expected_product_content_sha256=content_sha)

    def test_recomputed_inventory_and_reference_cannot_admit_private_rom(self):
        with tempfile.TemporaryDirectory(prefix="gw-runtime-transfer-reference-mutant-") as temp:
            root = pathlib.Path(temp) / "producer"
            root.mkdir()
            self._fixture(root)
            out = root / "build/v02/runtime-transfer"
            TRANSFER.export(root, out)
            payload = out / "payload"
            inventory_path = out / "inventory.json"
            inventory = json.loads(inventory_path.read_text())
            core_rel = "build/v02/runtime-observation/core-report.json"
            core_path = payload / core_rel
            report = json.loads(core_path.read_text())
            private_name = "build/v02/runtime/core-work/canonical-core-fixture/recursion94-full-route-1/private.rom"
            private_data = b"private synthetic ROM member"
            private_path = payload / private_name
            private_path.parent.mkdir(parents=True, exist_ok=True)
            private_path.write_bytes(private_data)
            report["runs"][0]["image"] = {"path": private_name,
                "sha256": hashlib.sha256(private_data).hexdigest()}
            core_bytes = json.dumps(report).encode()
            core_path.write_bytes(core_bytes)
            inventory["members"][core_rel] = {"sha256": hashlib.sha256(core_bytes).hexdigest(), "size": len(core_bytes)}
            inventory["members"][private_name] = {"sha256": hashlib.sha256(private_data).hexdigest(),
                "size": len(private_data)}
            inventory["member_count"] = len(inventory["members"])
            inventory["total_bytes"] = sum(row["size"] for row in inventory["members"].values())
            inventory_path.write_text(json.dumps(inventory))
            with self.assertRaisesRegex(ValueError, "transfer-reference-role-or-identity-invalid|transfer-unsafe-entry|transfer-member-path-invalid"):
                TRANSFER.verify(payload, inventory_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
