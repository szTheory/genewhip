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
        for key in tuple(os.environ):
            if key.startswith(("GENEWHIP_QUALIFICATION_", "GENEWHIP_FRESH_BATCH_")):
                os.environ.pop(key, None)

    def run_boundary(self, *, owned=False):
        runs = []
        function = self.route._run_client_owned if owned else self.route._run_client
        result = function(self.client, [str(self.client)], runs,
            report=self.root / "report.json", cwd=self.root, timeout=1)
        return result, runs

    def assert_cleanup_call_uses_bounded_status_budget(self, cleanup, boundary, child,
                                                       last_reason="cleanup-unclassified"):
        if sys.platform == "darwin":
            cleanup.assert_called_once_with(child, status_budget={
                "remaining": boundary._DARWIN_CLEANUP_MAX_STATUS_QUERIES,
                "attempted": 0,
                "last_reason": last_reason,
                "status_reason": "not-observed",
            })
        else:
            cleanup.assert_called_once_with(child)

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

    def test_route_creation_receipt_survives_unconfirmed_cleanup_and_monitor_error(self):
        os.environ[MARKER] = HOST
        for failure in (None, OSError("monitor-failed")):
            with self.subTest(failure=failure):
                runs = []
                path = self.root / "owned.json"
                child = mock.Mock(pid=424242, returncode=0)
                def observe():
                    stored = json.loads(path.read_text())["processes"][0]
                    self.assertEqual((stored["pid"], stored["pgid"]), (424242, 424242))
                    self.assertEqual(stored["status"], "started")
                    if failure:
                        raise failure
                    return 0
                child.poll.side_effect = observe
                child.wait.return_value = 0
                prior = signal.getsignal(signal.SIGTERM)
                with path.open("w+") as stream, \
                     mock.patch.object(subprocess, "Popen", return_value=child) as launch, \
                     mock.patch.object(self.route, "_process_group_exists", return_value=True), \
                     mock.patch.object(self.route, "_terminate_process_group", return_value=False) as cleanup:
                    with self.assertRaises((RuntimeError, OSError)) as raised:
                        self.route._run_client(self.client, [str(self.client)], runs,
                            report=self.root / "none.json", timeout=1, cwd=self.root,
                            process_receipt_stream=stream)
                launch.assert_called_once()
                cleanup.assert_called_once()
                self.assertIs(raised.exception.process_receipts, runs)
                stored = json.loads(path.read_text())["processes"][0]
                self.assertEqual(stored["pid"], 424242)
                self.assertEqual(stored["process_group_cleanup"], "unconfirmed")
                self.assertTrue(stored["bound_violation"])
                self.assertIs(signal.getsignal(signal.SIGTERM), prior)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_route_receipt_sink_failure_before_and_after_creation_is_error_safe(self):
        os.environ[MARKER] = HOST
        prior = signal.getsignal(signal.SIGTERM)
        with mock.patch.object(subprocess, "Popen") as launch:
            with self.assertRaises(OSError):
                self.route._run_client(self.client, [str(self.client)], [], report=self.root / "none.json",
                    timeout=1, process_receipt_stream=mock.Mock(seek=mock.Mock(side_effect=OSError("sink"))))
            launch.assert_not_called()
        child = mock.Mock(pid=424242)
        runs = []
        sink = mock.Mock()
        sink.fileno.return_value = -1
        with mock.patch.object(self.route.os, "fsync", side_effect=[None, OSError("sink"), OSError("sink")]), \
             mock.patch.object(subprocess, "Popen", return_value=child), \
             mock.patch.object(self.route, "_terminate_process_group", return_value=True) as cleanup:
            with self.assertRaises(OSError) as raised:
                self.route._run_client(self.client, [str(self.client)], runs, report=self.root / "none.json",
                    timeout=1, process_receipt_stream=sink)
        cleanup.assert_called_once()
        self.assertEqual(runs[0]["pid"], 424242)
        self.assertEqual(runs[0]["process_group_cleanup"], "confirmed")
        self.assertIs(raised.exception.process_receipts, runs)
        self.assertIs(signal.getsignal(signal.SIGTERM), prior)

    def test_route_nonfinite_bounds_reject_before_launch(self):
        os.environ[MARKER] = HOST
        with mock.patch.object(subprocess, "Popen") as launch:
            for timeout in (0, -1, float("nan"), float("inf")):
                with self.subTest(timeout=timeout), self.assertRaisesRegex(ValueError, "child-timeout-invalid"):
                    self.route._run_client(self.client, [str(self.client)], [],
                        report=self.root / "none.json", timeout=timeout)
            launch.assert_not_called()
            limits = json.loads((ROOT / "evidence/v02-execution.json").read_text())["per_child_limits"]
            for key in ("wall_seconds", "cleanup_grace_seconds"):
                for value in (0, -1, float("nan"), float("inf")):
                    with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "phase7-child-limits-invalid"):
                        self.route._run_client(self.client, [str(self.client)], [],
                            report=self.root / "none.json", timeout=1,
                            limits={**limits, key: value}, scratch_roots=(self.root,))
            launch.assert_not_called()

    def test_route_signal_denial_keeps_identity_and_uses_only_finite_direct_waits(self):
        os.environ[MARKER] = HOST
        runs = []
        child = mock.Mock(pid=424242, returncode=0)
        child.poll.return_value = 0
        child.wait.side_effect = [subprocess.TimeoutExpired("fake", 2), 0, 0]
        path = self.root / "denied.json"
        with path.open("w+") as stream, \
             mock.patch.object(subprocess, "Popen", return_value=child), \
             mock.patch.object(self.route, "_process_group_exists", return_value=True), \
             mock.patch.object(self.route, "_terminate_process_group", side_effect=PermissionError("denied")) as cleanup:
            with self.assertRaisesRegex(RuntimeError, "remains live"):
                self.route._run_client(self.client, [str(self.client)], runs,
                    report=self.root / "none.json", timeout=1, process_receipt_stream=stream)
        cleanup.assert_called_once()
        child.terminate.assert_called_once()
        child.kill.assert_called_once()
        self.assertTrue(all(0 < call.kwargs["timeout"] <= 5 for call in child.wait.call_args_list))
        stored = json.loads(path.read_text())["processes"][0]
        self.assertEqual(stored["pid"], 424242)
        self.assertEqual(stored["process_group_cleanup"], "unconfirmed")
        self.assertIn("PermissionError", stored["cleanup_error"])
        self.assertEqual(len(DENIED), self.denials_before)

    def test_desktop_receipt_is_open_before_call_and_finally_retains_failure(self):
        desktop = load("tests/desktop/phase4_sessions.py", "gw_cleanup_desktop")
        helper = load("scripts/evidence/phase5_process.py", "gw_cleanup_receipt")
        from types import SimpleNamespace
        desktop.EXECUTION_SCOPE = {"scope_id": "synthetic-only", "per_child_limits": {"wall_seconds": 1}}
        desktop.PROCESS_RECEIPTS = []
        fake_calls = []
        def fail(_client, _command, receipts, **kwargs):
            fake_calls.append(True)
            receipts.append({"pid": 424242, "pgid": 424242, "process_group_cleanup": "unconfirmed"})
            self.assertFalse(kwargs["process_receipt_stream"].closed)
            raise RuntimeError("fake-unconfirmed")
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _module: None))
        with mock.patch.object(desktop.importlib.util, "spec_from_file_location", return_value=spec), \
             mock.patch.object(desktop.importlib.util, "module_from_spec",
                               side_effect=[SimpleNamespace(_run_client=fail), helper]):
            with self.assertRaisesRegex(RuntimeError, "fake-unconfirmed"):
                desktop.run([self.client, "--dump-audio", self.root / "none.pcm"], {})
        self.assertEqual(fake_calls, [True])
        stored = json.loads((self.root / "bounded-child-process-0000.json").read_text())
        self.assertEqual(stored["processes"], desktop.PROCESS_RECEIPTS)
        self.assertEqual(stored["processes"][0]["pid"], 424242)
        self.assertEqual(stored["scope_id"], "synthetic-only")
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
        public_identity = load("tests/evidence/phase5_public_source_identity_contract.py",
                               "gw_admission_public_source_identity")
        with mock.patch.object(public_identity, "_self_test") as exercise:
            with self.assertRaisesRegex(RuntimeError,
                    "process-host-admission-required:non-qualifying:before-Popen"):
                public_identity.self_test(ROOT)
            exercise.assert_not_called()
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

    def test_selected_desktop_roster_requires_built_client_before_any_process(self):
        route = self.route
        controller = load("tests/session/phase6_controller_contract.py", "gw_admission_controller_roster")
        for module, argv in (
                (route, ["route", "--contract", "--build", str(self.root), "--desktop"]),
                (controller, ["controller", "--build", str(self.root), "--desktop"])):
            with mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "stderr", io.StringIO()), \
                 self.assertRaises(SystemExit) as stopped:
                module.main()
            self.assertEqual(stopped.exception.code, 2)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_production_imports_do_not_establish_admission(self):
        for index, relative in enumerate(("scripts/release/v02_qualification.py",
                "scripts/evidence/v02_run.py", "tools/evidence/core_benchmark.py",
                "tests/package/docs_commands.py", "tests/package/desktop_smoke.py")):
            load(relative, "gw_admission_import_" + str(index))
            self.assertNotIn(MARKER, os.environ)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_baseline_missing_admission_and_counterfactual_are_zero_start(self):
        helper = load("scripts/evidence/phase5_process.py", "gw_admission_baseline_helper")
        boundary = helper.process_boundary()
        for marker in (None, "", "host", HOST + " "):
            if marker is None:
                os.environ.pop(MARKER, None)
            else:
                os.environ[MARKER] = marker
            with self.assertRaisesRegex(RuntimeError, "process-host-admission-required"):
                helper.run([str(self.client)], cwd=self.root)
        with mock.patch.object(boundary, "require_host_process_context", return_value=None):
            with self.assertRaisesRegex(PermissionError, "independent-process-denial") as error:
                helper.run([str(self.client)], cwd=self.root)
        self.assertIsNone(error.exception.process_receipt["pid"])
        self.assertEqual(DENIED[self.denials_before:], ["subprocess.Popen"])
        os.environ.pop(MARKER, None)
        with self.assertRaisesRegex(RuntimeError, "process-host-admission-required"):
            helper.run([str(self.client)], cwd=self.root)
        self.assertEqual(len(DENIED), self.denials_before + 1)

    def test_baseline_fake_cleanup_failures_keep_identity_and_restore_handler(self):
        helper = load("scripts/evidence/phase5_process.py", "gw_admission_baseline_cleanup")
        boundary = helper.process_boundary()
        os.environ[MARKER] = HOST
        prior = signal.getsignal(signal.SIGTERM)
        for cleanup in (True, False, PermissionError("denied")):
            child = mock.Mock(pid=987654, returncode=0)
            child.stdout, child.stderr = io.BytesIO(), io.BytesIO()
            child.poll.return_value = 0
            selector = mock.Mock()
            selector.get_map.return_value = {}
            runs = []
            with mock.patch.object(helper.selectors, "DefaultSelector", return_value=selector), \
                 mock.patch.object(subprocess, "Popen", return_value=child) as creation, \
                 mock.patch.object(boundary, "_terminate_process_group",
                    side_effect=cleanup if isinstance(cleanup, BaseException) else None,
                    return_value=cleanup) as terminate:
                if cleanup is True:
                    result = helper.run([str(self.client)], cwd=self.root, runs=runs)
                    self.assertIs(result.process_receipt, runs[0])
                    self.assertEqual(runs[0]["process_group_cleanup"], "confirmed")
                else:
                    with self.assertRaisesRegex(ValueError, "cleanup unconfirmed") as failed:
                        helper.run([str(self.client)], cwd=self.root, runs=runs)
                    self.assertIs(failed.exception.process_receipt, runs[0])
                    self.assertEqual(runs[0]["process_group_cleanup"], "unconfirmed")
                creation.assert_called_once()
                self.assert_cleanup_call_uses_bounded_status_budget(terminate, boundary, child,
                    last_reason="cleanup-permission-denied" if isinstance(cleanup, PermissionError)
                    else "cleanup-unclassified")
            self.assertEqual((runs[0]["pid"], runs[0]["pgid"]), (987654, 987654))
            self.assertTrue(child.stdout.closed and child.stderr.closed)
            selector.close.assert_called_once()
            self.assertIs(signal.getsignal(signal.SIGTERM), prior)
            if isinstance(cleanup, PermissionError):
                child.kill.assert_called_once()
                child.wait.assert_called_once_with(timeout=2)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_baseline_default_suite_and_cli_reject_without_os_starts(self):
        module = load("tests/evidence/phase5_baseline_contract.py", "gw_admission_baseline_contract")
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
        result = unittest.TestResult()
        suite.run(result)
        self.assertEqual(result.failures, [], result.failures)
        self.assertEqual(len(result.errors), 2, result.errors)
        self.assertTrue(all("process-host-admission-required" in error for _, error in result.errors))
        self.assertEqual(result.skipped, [])
        names = unittest.defaultTestLoader.getTestCaseNames(module.BaselineRecordContract)
        self.assertIn("test_tracer_diagnostic_rom_rejects_outside_symlink", names)
        for argv in (["baseline", "--self-test"], ["baseline", "--tracer", str(self.client)],
                     ["baseline", "--validate", str(self.root / "report.json")]):
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaisesRegex(RuntimeError, "process-host-admission-required"):
                    module.main()
        process = module.baseline.process_tools()
        with mock.patch.object(module.baseline, "ROOT", self.root), \
             mock.patch.object(module.baseline, "process_tools", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "process-host-admission-required"):
                module.baseline.tracer(self.client)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_baseline_fake_cancel_and_setup_failure_always_cleanup(self):
        helper = load("scripts/evidence/phase5_process.py", "gw_admission_baseline_cancel")
        boundary = helper.process_boundary()
        os.environ[MARKER] = HOST
        prior = signal.getsignal(signal.SIGTERM)
        for stage in ("cancel", "register"):
            child = mock.Mock(pid=987654, returncode=0)
            child.stdout, child.stderr = io.BytesIO(), io.BytesIO()
            selector = mock.Mock()
            selector.get_map.return_value = {1: True}
            if stage == "register":
                selector.register.side_effect = OSError("fake-register-error")
            def spawn(*args, **kwargs):
                if stage == "cancel":
                    signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                return child
            runs = []
            with mock.patch.object(helper.selectors, "DefaultSelector", return_value=selector), \
                 mock.patch.object(subprocess, "Popen", side_effect=spawn), \
                 mock.patch.object(boundary, "_terminate_process_group", return_value=True) as cleanup:
                with self.assertRaises(KeyboardInterrupt if stage == "cancel" else OSError) as failed:
                    helper.run([str(self.client)], cwd=self.root, runs=runs)
                self.assert_cleanup_call_uses_bounded_status_budget(cleanup, boundary, child)
            self.assertIs(failed.exception.process_receipt, runs[0])
            self.assertEqual((runs[0]["pid"], runs[0]["pgid"]), (987654, 987654))
            self.assertEqual(runs[0]["process_group_cleanup"], "confirmed")
            self.assertTrue(child.stdout.closed and child.stderr.closed)
            self.assertIs(signal.getsignal(signal.SIGTERM), prior)
        self.assertEqual(len(DENIED), self.denials_before)

    def _run_forced_non_darwin_fake_cleanup(self, *, cancel):
        helper = load("scripts/evidence/phase5_process.py", "gw_admission_non_darwin_cleanup")
        boundary = helper.process_boundary()
        os.environ[MARKER] = HOST
        prior = signal.getsignal(signal.SIGTERM)
        child = mock.Mock(pid=987654, returncode=0)
        child.stdout, child.stderr = io.BytesIO(), io.BytesIO()
        selector = mock.Mock()
        selector.get_map.return_value = {}
        runs = []

        def spawn(*args, **kwargs):
            if cancel:
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return child

        with mock.patch.object(helper.selectors, "DefaultSelector", return_value=selector), \
             mock.patch.object(subprocess, "Popen", side_effect=spawn) as creation, \
             mock.patch.object(boundary, "_terminate_process_group", return_value=True) as cleanup, \
             mock.patch.object(helper.sys, "platform", "linux"):
            if cancel:
                with self.assertRaises(KeyboardInterrupt) as failed:
                    helper.run([str(self.client)], cwd=self.root, runs=runs)
                self.assertIs(failed.exception.process_receipt, runs[0])
            else:
                result = helper.run([str(self.client)], cwd=self.root, runs=runs)
                self.assertEqual(result.returncode, 0)
            creation.assert_called_once()
            self.assert_cleanup_call_uses_bounded_status_budget(cleanup, boundary, child)
        self.assertEqual((runs[0]["pid"], runs[0]["pgid"]), (987654, 987654))
        self.assertEqual(runs[0]["process_group_cleanup"], "confirmed")
        self.assertTrue(child.stdout.closed and child.stderr.closed)
        selector.close.assert_called_once()
        self.assertIs(signal.getsignal(signal.SIGTERM), prior)
        self.assertEqual(len(DENIED), self.denials_before)

    def test_forced_non_darwin_normal_cleanup_keeps_child_only_call_shape(self):
        self._run_forced_non_darwin_fake_cleanup(cancel=False)

    def test_forced_non_darwin_cancel_cleanup_keeps_child_only_call_shape(self):
        self._run_forced_non_darwin_fake_cleanup(cancel=True)

    def test_baseline_receipt_sink_rejects_links_and_tracer_validates_before_launch(self):
        helper = load("scripts/evidence/phase5_process.py", "gw_admission_baseline_receipt")
        target = self.root / "preserve"
        target.write_text("preserve")
        destination = self.root / "receipts"
        destination.mkdir()
        (destination / "linked.json").symlink_to(target)
        os.link(target, destination / "hardlinked.json")
        (self.root / "linked-dir").symlink_to(destination, target_is_directory=True)
        for relative in ("receipts/linked.json", "receipts/hardlinked.json", "linked-dir/new.json"):
            with self.assertRaises(OSError):
                with helper.receipt_file(self.root, Path(relative)):
                    self.fail("unsafe receipt sink opened")
        self.assertEqual(target.read_text(), "preserve")
        for relative in ("receipts/linked.json", "receipts/hardlinked.json", "linked-dir/new.json"):
            with self.assertRaises((OSError, ValueError)):
                with helper.receipt_file(self.root, Path(relative), replace=True):
                    self.fail("unsafe replace sink opened")
        self.assertEqual(target.read_text(), "preserve")
        with helper.receipt_file(self.root, Path("new/receipt.json")) as stream:
            stream.write('{"processes": []}\n')
        self.assertEqual(json.loads((self.root / "new/receipt.json").read_text()), {"processes": []})
        baseline = load("scripts/evidence/phase5_baseline.py", "gw_admission_baseline_cli")
        report = self.root / "build/phase5/phase5-tracer.json"
        report.parent.mkdir(parents=True)
        report.symlink_to(target)
        with mock.patch.object(baseline, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "symlinks"):
                baseline.tracer_output_path(report)
        self.assertEqual(target.read_text(), "preserve")
        for args in (["--tracer", str(self.client)],
                     ["--tracer", str(self.client), "--output", "docs/unsafe.json"]):
            with mock.patch.object(sys, "argv", ["baseline", *args]), \
                 mock.patch.object(baseline, "tracer") as tracer, \
                 mock.patch.object(sys, "stderr", io.StringIO()):
                if "--output" not in args:
                    with self.assertRaises(SystemExit):
                        baseline.main()
                else:
                    self.assertEqual(baseline.main(), 1)
                tracer.assert_not_called()
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
