#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure contracts for the non-qualifying original-control diagnostic."""
from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import unittest
import uuid
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/evidence/phase7_control_diagnostic.py"
SECRET = "private-path-token ROM-bytes-token raw-stderr-token"


def load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("module-load-failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


diagnostic = load(SCRIPT, "phase7_control_diagnostic_target")
runtime = load(ROOT / "scripts/evidence/v02_run.py", "phase7_control_runtime")
fixture = runtime._module(ROOT / "tests/fixtures/phase6_game.py", "phase7_control_fixture")
phase4 = runtime._module(ROOT / "tests/fixtures/phase4_game.py", "phase7_control_phase4")
report_module = load(ROOT / "scripts/evidence/phase4_report.py", "phase7_control_report")


class ControlDiagnosticContract(unittest.TestCase):
    def setUp(self):
        self.label = "phase7-control-test-" + uuid.uuid4().hex
        base = ROOT / "build/v02"
        self.out, self.work_root = base / (self.label + ".json"), base / self.label
        self.build = base / (self.label + "-build")
        self.headless = self.build / "tools/session/gw_headless"
        self.build.mkdir(parents=True)
        self.headless.parent.mkdir(parents=True)
        (self.build / "CMakeCache.txt").write_text("CMAKE_BUILD_TYPE:STRING=Debug\n", encoding="utf-8")
        self.headless.write_bytes(b"identified synthetic executable")
        self.headless.chmod(0o755)
        self.scope = json.loads((ROOT / "evidence/v02-phase7-authorized-execution-scope.json").read_text())
        self.limits = dict(self.scope["per_child_limits"])
        self.now = datetime.datetime.now(datetime.timezone.utc)
        self.started = self.now - datetime.timedelta(seconds=30)
        self.launches = []

    def tearDown(self):
        fixture.set_execution_scope(None)
        for path in (self.out, self.work_root, self.build):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)

    def test_two_runs_use_phase4_validator_and_never_qualify(self):
        result = self.run_with(self.successful_launch)
        self.assertEqual(result["status"], "pass", result)
        self.assertFalse(result["qualification_accepted"])
        self.assertTrue(result["diagnostic_only"])
        self.assertEqual([row["repetition"] for row in result["runs"]], [1, 2])
        self.assertTrue(all(len(row["case_outcomes"]) == 6 for row in result["runs"]))
        self.assertEqual(len(self.launches), 2)
        self.assertTrue(all(call[0][2] == str(ROOT / "tests/fixtures/phase4_game.py") for call in self.launches))
        self.assertTrue(all("--outer-process-group" in call[0] and "--process-receipt" in call[0]
            for call in self.launches))
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn(SECRET, encoded)
        self.assertNotIn(str(self.build), encoded)
        self.assertTrue(self.out.is_file())

    def test_first_nested_failure_stops_before_repetition_two_and_is_redacted(self):
        def fail(client, command, work, report_path, timeout):
            self.launches.append((list(command), timeout))
            self.write_nested(work, fail_case="start-move", return_code=7)
            return self.outer_failure("start-move: headless exit 7: " + SECRET)

        result = self.run_with(fail)
        self.assertEqual(len(self.launches), 1)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["runs"][0]["failure_reason"], "nested-child-failure")
        self.assertEqual(result["runs"][0]["nested_failure"]["case"], "start-move")
        self.assertNotIn(SECRET, json.dumps(result, sort_keys=True))

    def test_second_failure_is_retained_and_stops(self):
        def launch(client, command, work, report_path, timeout):
            self.launches.append((list(command), timeout))
            if len(self.launches) == 1:
                self.write_success(report_path, command, work)
                return self.outer_success()
            self.write_nested(work, fail_case="sustained-play", return_code=9)
            return self.outer_failure("sustained-play: headless exit 9")

        result = self.run_with(launch)
        self.assertEqual([row["status"] for row in result["runs"]], ["pass", "fail"])
        self.assertEqual(result["runs"][1]["nested_failure"]["case"], "sustained-play")
        self.assertEqual(len(self.launches), 2)

    def test_expired_claim_writes_unknown_without_launch(self):
        self.started = self.now - datetime.timedelta(seconds=diagnostic.DIAGNOSTIC_SECONDS)
        result = self.run_with(lambda *args: self.fail("expired claim launched"), now=self.now)
        self.assertEqual((result["status"], result["failure_reason"]),
            ("unknown", "diagnostic-deadline-exhausted"))
        self.assertFalse(self.launches)
        self.assertTrue(self.out.is_file())

    def test_preflight_time_consumes_claim_clock(self):
        self.started = self.now - datetime.timedelta(seconds=
            diagnostic.DIAGNOSTIC_SECONDS - diagnostic.CLEANUP_RESERVE_SECONDS - 70)
        clock = [100.0]
        original_read = diagnostic._read

        def slow_read(path, maximum):
            value = original_read(path, maximum)
            if pathlib.Path(path) == self.headless:
                clock[0] += 40
            return value

        with mock.patch.object(diagnostic.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(diagnostic, "_read", side_effect=slow_read):
            result = self.run_with(lambda *args: self.fail("preflight renewed claim clock"), now=self.now)
        self.assertEqual((result["status"], result["failure_reason"]),
            ("unknown", "insufficient-headroom"))
        self.assertFalse(self.launches)

    def test_scope_runtime_deadline_remains_stricter_than_diagnostic_cap(self):
        self.scope["qualification_batch"]["runtime_wall_seconds"] = 300
        self.limits = dict(self.scope["per_child_limits"])
        result = self.run_with(self.successful_launch)
        self.assertEqual(result["status"], "pass", result)
        self.assertLess(result["budget"]["runtime_deadline"], result["budget"]["diagnostic_deadline"])
        self.assertTrue(all(30 <= timeout <= 300 for _, timeout in self.launches))

    def test_wrong_well_formed_input_digest_fails(self):
        def launch(client, command, work, report_path, timeout):
            self.write_success(report_path, command, work)
            report = json.loads(report_path.read_text())
            report["results"][2]["input_sha256"] = "4" * 64
            report_path.write_text(json.dumps(report), encoding="utf-8")
            return self.outer_success()

        result = self.run_with(launch)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["runs"][0]["failure_reason"], "control-report-invalid")

    def test_missing_malformed_symlink_oversized_and_mutated_reports_do_not_pass(self):
        for mode in ("missing", "malformed", "symlink", "oversized", "mutated"):
            with self.subTest(mode=mode):
                self.tearDown()
                self.setUp()

                def launch(client, command, work, report_path, timeout):
                    self.write_nested(work)
                    if mode == "missing":
                        return self.outer_success()
                    if mode == "malformed":
                        report_path.write_text("{broken", encoding="utf-8")
                    elif mode == "symlink":
                        target = work / "target.json"
                        target.write_text("{}", encoding="utf-8")
                        report_path.symlink_to(target)
                    elif mode == "oversized":
                        report_path.write_bytes(b"x" * (64 * 1024 + 1))
                    else:
                        self.write_success(report_path, command, work)
                        report = json.loads(report_path.read_text())
                        report["results"][2]["position"] = 999
                        report_path.write_text(json.dumps(report), encoding="utf-8")
                    return self.outer_success()

                result = self.run_with(launch, max_json_bytes=64 * 1024 if mode == "oversized" else None)
                self.assertIn(result["status"], ("unknown", "fail"))
                self.assertFalse(result["qualification_accepted"])

    def run_with(self, launcher, *, now=None, max_json_bytes=None):
        scope, limits = json.loads(json.dumps(self.scope)), dict(self.limits)
        if max_json_bytes is not None:
            limits["max_json_bytes"] = max_json_bytes
        env = {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1",
            "GENEWHIP_QUALIFICATION_STARTED_AT": self.started.isoformat(),
            "GENEWHIP_CONTROL_DIAGNOSTIC_STARTED_AT": self.started.isoformat()}
        original_module = diagnostic._module

        def module(path, name):
            relative = pathlib.Path(path).relative_to(ROOT).as_posix()
            known = {"scripts/evidence/v02_run.py": runtime,
                "tests/fixtures/phase6_game.py": fixture,
                "tests/fixtures/phase4_game.py": phase4,
                "scripts/evidence/phase4_report.py": report_module}
            return known[relative] if relative in known else original_module(path, name)

        with mock.patch.object(diagnostic, "_module", side_effect=module), \
                mock.patch.object(diagnostic, "utc_now", return_value=now or self.now), \
                mock.patch.object(runtime, "validate_execution_scope", return_value=(scope, limits)), \
                mock.patch.object(runtime, "resolve_owned_output_roots", return_value=(ROOT / "build/v02",)), \
                mock.patch.object(fixture, "shared_launch", side_effect=launcher), \
                mock.patch.dict(os.environ, env, clear=False), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("process denied")), \
                mock.patch("subprocess.run", side_effect=AssertionError("process denied")), \
                mock.patch("subprocess.call", side_effect=AssertionError("process denied")), \
                mock.patch("os.system", side_effect=AssertionError("process denied")), \
                mock.patch("socket.create_connection", side_effect=AssertionError("network denied")), \
                mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network denied")):
            result, code = diagnostic.run_diagnostic(self.build,
                pathlib.Path("evidence/v02-phase7-authorized-execution-scope.json"), self.out)
        self.assertEqual(code, 0 if result["status"] == "pass" else 1)
        if self.out.is_file():
            self.assertEqual(json.loads(self.out.read_text()), result)
        self.limits = dict(self.scope["per_child_limits"])
        return result

    def successful_launch(self, client, command, work, report_path, timeout):
        self.launches.append((list(command), timeout))
        self.write_success(report_path, command, work)
        return self.outer_success()

    def outer_success(self):
        return (type("Result", (), {"returncode": 0})(),
            {"return_code": 0, "status": "completed", "bound_violation": False,
             "process_group_cleanup": "confirmed", "wall_seconds": 0.5},
            {"stdout": {"text": ""}, "stderr": {"text": ""}})

    def outer_failure(self, stderr):
        return (type("Result", (), {"returncode": 1})(),
            {"return_code": 1, "status": "completed", "bound_violation": False,
             "process_group_cleanup": "confirmed", "wall_seconds": 0.5},
            {"stdout": {"text": ""}, "stderr": {"text": stderr}})

    def write_nested(self, work, fail_case=None, return_code=0):
        cases = report_module.GAME_CASES if fail_case is None else [fail_case]
        rows = [{"status": "completed", "return_code": return_code if case == fail_case else 0,
            "bound_violation": False, "process_group_cleanup": "confirmed", "client": "headless",
            "wall_seconds": 0.5, "rss_bytes_peak": 1024, "stdout_bytes": len(b"driver text"), "stderr_bytes": 0}
            for case in cases]
        (work / "nested-processes.json").write_text(json.dumps({"processes": rows}), encoding="utf-8")

    def write_success(self, report_path, command, work):
        self.write_nested(work)
        cache_sha = hashlib.sha256((self.build / "CMakeCache.txt").read_bytes()).hexdigest()
        client_sha = hashlib.sha256(self.headless.read_bytes()).hexdigest()
        stdout, stderr = b"driver text", b""
        out_sha, err_sha = hashlib.sha256(stdout).hexdigest(), hashlib.sha256(stderr).hexdigest()
        rows, children = [], []
        scenario = json.loads((ROOT / "fixtures/independent-game-v2/scenario.json").read_text())
        cases = {row["id"]: row for row in scenario["cases"]}
        for index, case_id in enumerate(report_module.GAME_CASES):
            play, low, high, psg, ac_min, _ = report_module.GAME_EXPECTATIONS[index]
            process = {"client": "gw_headless", "return_code": 0, "executable_sha256": client_sha,
                "executable_path": str((self.build / "tools/session/gw_headless").relative_to(ROOT)), "cwd": ".",
                "stdout_bytes": len(stdout), "stderr_bytes": len(stderr), "stdout_sha256": out_sha,
                "stderr_sha256": err_sha}
            streams = {name: {"observed_bytes": len(raw), "sha256": digest, "truncated": False}
                for name, raw, digest in (("stdout", stdout, out_sha), ("stderr", stderr, err_sha))}
            rows.append({"id": case_id, "outcome": "pass", "fields": report_module.GAME_FIELDS[index],
                "unsupported": 0, "play_state": play, "position": low, "psg": psg,
                "input_sha256": hashlib.sha256(phase4.input_log(cases[case_id])).hexdigest(), "ac_range": ac_min,
                "machine_digest": "1" * 16, "field_hashes_sha256": "2" * 64,
                "process": process, "process_streams": streams})
            children.append({"case": case_id, **process})
        report = {"schema": "genewhip-phase4-gameplay-v1", "version": 1, "outcome": "pass",
            "fixture_id": "genewhip-independent-game-v2", "source_sha256": report_module.GAME_IDENTITIES["source_sha256"],
            "rom_sha256": report_module.GAME_IDENTITIES["rom_sha256"],
            "scenario_sha256": report_module.GAME_IDENTITIES["scenario_sha256"],
            "oracle_sha256": report_module.GAME_IDENTITIES["oracle_sha256"], "profile": "VA3-NTSC-U",
            "build_configuration_sha256": cache_sha, "client_sha256": [client_sha], "clients": ["headless"],
            "denominator": 6, "fields": sum(report_module.GAME_FIELDS), "results": rows,
            "native_child_processes": children, "visual_observations": {
                "title_to_play_field_10_changed": True, "start_idle_to_moved_marker_field_19_changed": True}}
        report_path.write_text(json.dumps(report), encoding="utf-8")


if __name__ == "__main__":
    unittest.main(verbosity=2)
