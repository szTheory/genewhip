#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Admission regression: independent, sticky OS-process denial; no guest inputs."""
import importlib.util
import io
import json
import os
import runpy
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MARKER = "GENEWHIP_PROCESS_CONTEXT"
HOST = "host-cleanup-v1"
DENIED = []


def deny_processes(event, args):
    if (event in ("subprocess.Popen", "os.system", "os.fork", "os.forkpty", "pty.spawn")
            or event.startswith(("os.exec", "os.spawn", "os.posix_spawn"))):
        DENIED.append(event)
        raise PermissionError("independent-process-denial")


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ProcessAdmissionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The audit hook cannot be removed by restoring a mocked API. Self-test
        # the original creation API before importing the production boundaries.
        sys.addaudithook(deny_processes)
        with cls.assertRaises(cls, PermissionError):
            subprocess.Popen(["/__no_usable_client__"])
        if DENIED != ["subprocess.Popen"]:
            raise AssertionError("independent-denial-self-test-not-reached")
        cls.route = load("tests/session/phase6_route_contract.py", "gw_admission_route")
        cls.coordinator = load("scripts/release/v02_qualification.py", "gw_admission_coordinator")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="gw-process-admission-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.client = self.root / "no-client"
        self.assertFalse(self.client.exists())
        self.assertEqual(list(self.root.rglob("*.bin")), [])
        self.denials_before = len(DENIED)
        self.environment = mock.patch.dict(os.environ)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop(MARKER, None)

    def run_boundary(self, *, owned=False):
        runs = []
        function = self.route._run_client_owned if owned else self.route._run_client
        result = function(self.client, [str(self.client)], runs,
            report=self.root / "report.json", cwd=self.root, timeout=1)
        return result, runs

    def test_missing_and_invalid_admission_reject_before_popen_and_signal_change(self):
        original = signal.getsignal(signal.SIGTERM)
        for marker in (None, "", "host", "sandbox", HOST + " "):
            if marker is None:
                os.environ.pop(MARKER, None)
            else:
                os.environ[MARKER] = marker
            for owned in (False, True):
                reached = []
                with mock.patch.object(subprocess, "Popen", side_effect=lambda *a, **k: reached.append(a)):
                    with self.assertRaisesRegex(RuntimeError, "process-host-admission-required:non-qualifying:before-Popen"):
                        self.run_boundary(owned=owned)
                self.assertEqual(reached, [])
                self.assertIs(signal.getsignal(signal.SIGTERM), original)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_admission_is_rechecked_at_actual_creation_seam(self):
        os.environ[MARKER] = HOST
        actual = self.route._run_client_owned
        def remove_admission(*args, **kwargs):
            os.environ.pop(MARKER)
            return actual(*args, **kwargs)
        with mock.patch.object(self.route, "_run_client_owned", side_effect=remove_admission):
            with self.assertRaisesRegex(RuntimeError, "process-host-admission-required"):
                self.run_boundary()
        self.assertEqual(len(DENIED), self.denials_before)

    def test_admitted_fake_seam_reached_without_os_starts_and_denial_stays_sticky(self):
        os.environ[MARKER] = HOST
        reached = []
        def fake(*args, **kwargs):
            reached.append(args[0])
            raise OSError("intended-fake-launch")
        with mock.patch.object(subprocess, "Popen", side_effect=fake):
            result, runs = self.run_boundary()
        self.assertEqual(reached, [[str(self.client)]])
        self.assertEqual(result.returncode, 127)
        self.assertEqual(runs[0]["status"], "launch-failed")
        self.assertEqual(sum(row.get("pid") is not None for row in runs), 0)
        with self.assertRaisesRegex(PermissionError, "independent-process-denial"):
            subprocess.Popen([str(self.client)])
        self.assertEqual(DENIED[self.denials_before:], ["subprocess.Popen"])

    def test_coordinator_import_preserves_denial_and_named_attempt(self):
        destination = self.root / "tests/session/phase6_route_contract.py"
        destination.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "tests/session/phase6_route_contract.py", destination)
        evidence = self.root / "evidence/v02-execution.json"
        evidence.parent.mkdir()
        shutil.copyfile(ROOT / "evidence/v02-execution.json", evidence)
        with mock.patch.object(self.coordinator, "ROOT", self.root):
            with self.assertRaisesRegex(RuntimeError, "process-host-admission-required"):
                self.coordinator._bounded_command([str(self.client)],
                    limits=json.loads(evidence.read_text())["per_child_limits"],
                    scratch=self.root / "attempts", timeout=1, label="missing-admission")
            attempt = json.loads((self.root / "attempts/missing-admission.attempt.json").read_text())
            self.assertIn("process-host-admission-required", attempt["launch_error"])
            self.assertEqual(attempt["processes"], [])
            self.assertIsNone(attempt["returncode"])
            with self.assertRaisesRegex(ValueError, "hosted-delivery-command-unavailable"):
                self.coordinator._external([str(self.client)], cwd=self.root, timeout=1)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_direct_real_controls_fail_before_any_fixture_subprocess(self):
        qualification = load("tests/evidence/v02_qualification_contract.py", "gw_admission_qualification_tests")
        matrix = load("tests/evidence/v02_matrix_contract.py", "gw_admission_matrix_tests")
        selected = (
            qualification.QualificationCoordinatorContract("test_parent_term_cleans_nested_bounded_runner_process_group"),
            qualification.QualificationCoordinatorContract("test_external_timeout_uses_monitored_process_group_and_retains_cleanup_receipt"),
            qualification.QualificationCoordinatorContract("test_public_snapshot_reopens_exact_public_parent_and_filtered_tree"),
            matrix.PublicMatrixContract("test_optional_phase7_limits_kill_children_and_record_reason_and_cleanup"),
            matrix.SchemaClosureContract("test_external_consumer_runs_from_copied_closure_without_checkout_dependency"))
        selected += (self.route.NativeParserContract("test_preimport_popen_denial_is_observed_and_sticky"),)
        for case in selected:
            result = unittest.TestResult()
            case.run(result)
            self.assertEqual(len(result.errors), 1)
            self.assertIn("process-host-admission-required:non-qualifying:before-Popen", result.errors[0][1])
            self.assertEqual(result.skipped, [])
        pure = qualification.QualificationCoordinatorContract("test_hosted_run_identity_rejects_wrong_event_source_attempt_and_conclusion")
        result = unittest.TestResult()
        pure.run(result)
        self.assertTrue(result.wasSuccessful(), result.errors)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_mocked_cancellation_lifecycle_and_handler_restoration(self):
        methods = (
            "test_monitored_symlink_is_rejected_before_process_start",
            "test_sigterm_during_popen_is_deferred_until_the_group_is_owned",
            "test_sigterm_after_pid_registration_uses_owned_group_cleanup",
            "test_sigterm_and_launch_error_restore_previous_handler_without_owned_child",
            "test_runner_setup_error_restores_previous_handler_before_any_launch")
        cases = [self.route.NativeParserContract(name) for name in methods]
        for case in cases:
            case.client = self.client
            case.runs = []
        suite = unittest.TestSuite(cases)
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        self.assertTrue(result.wasSuccessful(), str(result.errors) + str(result.failures))
        self.assertNotIn(MARKER, os.environ)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_top_level_contract_commands_reject_without_admission(self):
        commands = (("tests/evidence/v02_qualification_contract.py", ["--contracts"]),
                    ("tests/evidence/v02_matrix_contract.py", ["--contracts"]),
                    ("tests/evidence/v02_matrix_contract.py", ["--tracer", "--build", str(self.root)]),
                    ("tests/session/phase6_route_contract.py", ["--contract", "--build", str(self.root)]))
        for relative, args in commands:
            with mock.patch.object(sys, "argv", [relative, *args]):
                with self.assertRaisesRegex(RuntimeError, "process-host-admission-required:non-qualifying:before-Popen"):
                    runpy.run_path(str(ROOT / relative), run_name="__main__")
            self.assertNotIn(MARKER, os.environ)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_tracer_cli_without_admission_fails_before_popen(self):
        reached = []
        with mock.patch.object(sys, "argv", ["phase6_route_contract.py", "--tracer",
                "--build", str(self.root)]), \
             mock.patch.object(subprocess, "Popen", side_effect=lambda *a, **k: reached.append(a)), \
             mock.patch.object(sys, "stderr", io.StringIO()), \
             self.assertRaises(SystemExit) as raised:
            runpy.run_path(str(ROOT / "tests/session/phase6_route_contract.py"), run_name="__main__")
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(reached, [])
        self.assertNotIn(MARKER, os.environ)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_chunk_formatter_emits_parser_compatible_lf_rows_without_processes(self):
        import csv
        runner = load("scripts/evidence/v02_run.py", "gw_admission_chunk_formatter")
        payload = runner._format_chunk_inputs([
            {"machine_tick": 112, "port": 0, "effective": 3},
            {"machine_tick": 224, "port": 1, "effective": 255}])
        self.assertEqual(payload, b"112,0,3\n224,1,255\n")
        with io.StringIO(payload.decode("utf-8"), newline="") as stream:
            self.assertEqual(list(csv.reader(stream, strict=True)),
                [["112", "0", "3"], ["224", "1", "255"]])
        self.assertTrue(payload.endswith(b"\n"))
        self.assertNotIn(b"\\n", payload)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_pr_body_file_is_utf8_and_removed_after_mocked_create_success_or_failure(self):
        module = self.coordinator
        with mock.patch.object(module, "_valid_packet_for_delivery", return_value={
                    "repository": "example/repo", "public_identity": {
                        "head_sha": "a" * 40, "base_sha": "b" * 40}}), \
             mock.patch.object(module, "_fresh_public_policy", return_value={"ok": True}), \
             mock.patch.object(module, "_write_json"), \
             mock.patch.object(module, "_external") as external:
            for fail_create in (False, True):
                with self.subTest(fail_create=fail_create), tempfile.TemporaryDirectory(
                        prefix="gw-pr-body-", dir=self.root) as temporary:
                    candidate = Path(temporary) / "publication"
                    candidate.mkdir()
                    journal = Path(temporary) / "journal.json"
                    calls = []

                    def fake_external(command, **kwargs):
                        calls.append(list(command))
                        if command[:3] == ["git", "push", "origin"]:
                            return subprocess.CompletedProcess(command, 0, "", "")
                        if command[:3] == ["gh", "pr", "list"]:
                            return subprocess.CompletedProcess(command, 0, "[]", "")
                        self.assertEqual(command[0:3], ["gh", "pr", "create"])
                        body_path = Path(command[command.index("--body-file") + 1])
                        raw = body_path.read_bytes()
                        self.assertIn(b"-> one-parent public-main commit", raw)
                        self.assertEqual(raw.decode("utf-8").encode("utf-8"), raw)
                        self.assertIn(b"\n", raw)
                        self.assertNotIn(b"\r\n", raw)
                        if fail_create:
                            raise RuntimeError("mocked-create-failure")
                        return subprocess.CompletedProcess(command, 0, "invalid-pr-url", "")

                    external.side_effect = fake_external
                    with mock.patch.dict(os.environ, {"GENEWHIP_QUALIFICATION_STARTED_AT":
                            "2026-10-29T00:00:00+00:00"}):
                        if fail_create:
                            with self.assertRaisesRegex(RuntimeError, "mocked-create-failure"):
                                module.publish_sanitized_source(Path("packet"), candidate, journal)
                        else:
                            with self.assertRaisesRegex(ValueError, "github-pull-request-number-unavailable"):
                                module.publish_sanitized_source(Path("packet"), candidate, journal)
                    create = next(command for command in calls if command[:3] == ["gh", "pr", "create"])
                    self.assertFalse(Path(create[create.index("--body-file") + 1]).exists())
        self.assertEqual(len(DENIED), self.denials_before)

    def test_invalid_matrix_selection_does_not_grant_host_context(self):
        module = load("tests/evidence/v02_matrix_contract.py", "gw_admission_bad_selection")
        with mock.patch.object(sys, "argv", ["matrix", "--tracer", "--contracts", "--host-process-context"]):
            with mock.patch.object(sys, "stderr", io.StringIO()), self.assertRaises(SystemExit):
                module.main()
        self.assertNotIn(MARKER, os.environ)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_production_imports_do_not_establish_admission(self):
        for index, relative in enumerate(("scripts/release/v02_qualification.py",
                "scripts/evidence/v02_run.py", "tools/evidence/core_benchmark.py",
                "tests/package/docs_commands.py", "tests/package/desktop_smoke.py")):
            load(relative, "gw_admission_import_" + str(index))
            self.assertNotIn(MARKER, os.environ)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_default_unittest_suites_do_not_reach_any_os_process_seam(self):
        qualification = load("tests/evidence/v02_qualification_contract.py", "gw_admission_default_qualification")
        matrix = load("tests/evidence/v02_matrix_contract.py", "gw_admission_default_matrix")
        for module in (qualification, matrix):
            suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            result = unittest.TestResult()
            suite.run(result)
            self.assertEqual(result.failures, [], result.failures)
            self.assertGreater(len(result.errors), 0)
            self.assertTrue(all("process-host-admission-required" in error for _, error in result.errors), result.errors)
            self.assertEqual(result.skipped, [])
        self.assertEqual(len(DENIED), self.denials_before)

    def test_revert_admission_reaches_independent_denial_then_reapply_rejects(self):
        # Disable exactly the shared predicate in memory. The independent audit
        # hook remains installed, so reproducing the old path starts no child.
        with mock.patch.object(self.route, "require_host_process_context", return_value=None):
            result, runs = self.run_boundary()
        self.assertEqual(result.returncode, 127)
        self.assertEqual(runs[0]["status"], "launch-failed")
        self.assertIn("independent-process-denial", runs[0]["launch_error"])
        self.assertEqual(DENIED[self.denials_before:], ["subprocess.Popen"])
        self.assertEqual(sum(row.get("pid") is not None for row in runs), 0)
        with self.assertRaisesRegex(RuntimeError, "process-host-admission-required"):
            self.run_boundary()
        self.assertEqual(len(DENIED), self.denials_before + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
