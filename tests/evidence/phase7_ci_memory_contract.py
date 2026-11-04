#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mocked contracts for the fixed Phase 7 CI package process boundary."""
from __future__ import annotations

import hashlib
import importlib.util
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/release/v02_qualification.py"


def load_module():
    spec = importlib.util.spec_from_file_location("gw_phase7_ci_memory_qualification", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("qualification-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_external(calls, *, fail=False, rss_peak=1024**3):
    """Write a bounded synthetic attempt receipt; never launch a child."""
    def run(*args, **kwargs):
        calls.append((args, kwargs))
        scratch = kwargs["fresh_batch_scratch"]
        scratch.mkdir(parents=True, exist_ok=True)
        failed = {
            "returncode": 7 if fail else 0,
            "process_group_cleanup": "confirmed",
            "processes": [{"rss_bytes_peak": rss_peak, "wall_seconds": 2.5,
                "process_group_cleanup": "confirmed", "bound_violation": fail}],
            "streams": {"stdout": {"text": "private output"},
                "stderr": {"text": "private diagnostics"}},
        }
        (scratch / "external-contract.attempt.json").write_text(
            json.dumps(failed, sort_keys=True), encoding="utf-8")
        if fail:
            raise ValueError("monitored-builder-failed")
        return subprocess.CompletedProcess(args[0], 0, "private output", "")
    return run


class Phase7CiMemoryContract(unittest.TestCase):
    def test_scope_pair_selectors_are_exact_and_keep_legacy_profile_immutable(self):
        module = load_module()
        old_scope = ROOT / module.PHASE7_AUTHORIZED_SCOPE_PATH
        new_scope = ROOT / module.PHASE7_CI_MEMORY_SCOPE_PATH
        self.assertEqual(hashlib.sha256(old_scope.read_bytes()).hexdigest(),
            module.PHASE7_AUTHORIZED_SCOPE_SHA256)
        self.assertEqual(hashlib.sha256(new_scope.read_bytes()).hexdigest(),
            module.PHASE7_CI_MEMORY_SCOPE_SHA256)
        self.assertEqual(json.loads(old_scope.read_text())["per_child_limits"]["max_rss_bytes"],
            4 * 1024**3)
        self.assertEqual(json.loads(new_scope.read_text())["per_child_limits"]["max_rss_bytes"],
            2 * 1024**3)

        reader = mock.Mock()
        with mock.patch.object(module, "_load_phase7_window_module", return_value=reader):
            for scope_path, scope_sha in (
                    (module.PHASE7_AUTHORIZED_SCOPE_PATH, module.PHASE7_AUTHORIZED_SCOPE_SHA256),
                    (module.PHASE7_CI_MEMORY_SCOPE_PATH, module.PHASE7_CI_MEMORY_SCOPE_SHA256)):
                window = {
                    "authority_path": "build/v02/phase7-ci-memory/authorization.json",
                    "authority_sha256": "a" * 64,
                    "scope_path": scope_path.as_posix(), "scope_sha256": scope_sha,
                    "attempt_namespace": "build/v02/phase7-ci-memory/attempts",
                    "started_at": "2026-11-04T00:00:00+00:00",
                    "source_ancestor": "b" * 40,
                    "budget": {"wall_seconds": 14400},
                }
                reader.load_authorized_window.return_value = window
                selected = module._phase7_window_profile(scope_path=scope_path,
                    scope_sha256=scope_sha,
                    authorization_path=Path(window["authority_path"]),
                    authorization_sha256=window["authority_sha256"])
                self.assertEqual(selected["profile_id"], "authorized-run")
                self.assertEqual(reader.load_authorized_window.call_args.kwargs["scope_path"],
                    scope_path)
                self.assertEqual(reader.load_authorized_window.call_args.kwargs["scope_sha256"],
                    scope_sha)

        with mock.patch.object(module, "_load_phase7_window_module", return_value=reader):
            for wrong_path, wrong_sha in (
                    (module.PHASE7_AUTHORIZED_SCOPE_PATH, module.PHASE7_CI_MEMORY_SCOPE_SHA256),
                    (module.PHASE7_CI_MEMORY_SCOPE_PATH, "c" * 64)):
                with self.subTest(path=wrong_path, sha=wrong_sha):
                    with self.assertRaisesRegex(ValueError, "scope-or-authority-profile-invalid"):
                        module._phase7_window_profile(scope_path=wrong_path,
                            scope_sha256=wrong_sha,
                            authorization_path=Path(window["authority_path"]),
                            authorization_sha256=window["authority_sha256"])

    def test_public_scope_pair_rejects_wrong_path_hash_and_authority_fallback(self):
        module = load_module()
        reader = mock.Mock()
        reader.load_public_scope.return_value = {"scope_id": "phase7-serial-child-workloads"}
        with mock.patch.object(module, "_load_phase7_window_module", return_value=reader), \
             mock.patch.dict(os.environ, {}, clear=True):
            selected = module._phase7_public_window_profile(
                scope_path=module.PHASE7_CI_MEMORY_SCOPE_PATH,
                scope_sha256=module.PHASE7_CI_MEMORY_SCOPE_SHA256)
            self.assertEqual(selected["profile_id"], "authorized-run-public")
            self.assertEqual(reader.load_public_scope.call_args.kwargs["scope_path"],
                module.PHASE7_CI_MEMORY_SCOPE_PATH.as_posix())

        bad_authority = mock.Mock()
        bad_authority.load_authorized_window.side_effect = ValueError("authority-invalid")
        with mock.patch.object(module, "_load_phase7_window_module", return_value=bad_authority), \
             mock.patch.dict(os.environ, {
                "GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH": "build/v02/phase7-ci-memory/authorization.json",
                "GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256": "a" * 64,
             }, clear=True):
            with self.assertRaisesRegex(ValueError, "authority-invalid"):
                module._phase7_public_window_profile(
                    scope_path=module.PHASE7_CI_MEMORY_SCOPE_PATH,
                    scope_sha256=module.PHASE7_CI_MEMORY_SCOPE_SHA256)
        bad_authority.load_public_scope.assert_not_called()

        for wrong_path, wrong_sha in (
                (module.PHASE7_AUTHORIZED_SCOPE_PATH, module.PHASE7_CI_MEMORY_SCOPE_SHA256),
                (module.PHASE7_CI_MEMORY_SCOPE_PATH, "d" * 64)):
            with self.subTest(path=wrong_path, sha=wrong_sha), \
                 mock.patch.object(module, "_load_phase7_window_module", return_value=reader), \
                 mock.patch.dict(os.environ, {}, clear=True):
                reader.load_public_scope.reset_mock()
                with self.assertRaisesRegex(ValueError, "scope-or-authority-profile-invalid"):
                    module._phase7_public_window_profile(scope_path=wrong_path,
                        scope_sha256=wrong_sha)
                reader.load_public_scope.assert_not_called()

    def test_package_step_uses_fixed_command_scoped_caps_and_unique_scratch(self):
        module = load_module()
        limits = {"wall_seconds": 600, "max_binary_file_bytes": 2 * 1024**3,
            "max_rss_bytes": 2 * 1024**3, "max_json_bytes": 32 * 1024**2,
            "max_scratch_bytes": 16 * 1024**3, "max_stdout_stderr_bytes": 16 * 1024**2,
            "max_capture_bytes": 2 * 1024**3, "max_retained_bytes": 4 * 1024**3}
        scope = {"scope_id": "phase7-serial-child-workloads", "per_child_limits": limits}
        resolver_calls = []
        external_calls = []
        summaries = []

        def resolve_profile(**kwargs):
            resolver_calls.append(kwargs)
            return {"profile_id": "authorized-run-public",
                "scope_path": module.PHASE7_CI_MEMORY_SCOPE_PATH,
                "scope_sha256": module.PHASE7_CI_MEMORY_SCOPE_SHA256}

        with tempfile.TemporaryDirectory(prefix="phase7-ci-package-contract-") as temporary:
            root = Path(temporary).resolve()
            original_root = module.ROOT
            module.ROOT = root
            try:
                with mock.patch.object(module, "_phase7_public_window_profile",
                        side_effect=resolve_profile), \
                     mock.patch.object(module, "_load_phase7_window_module",
                        return_value=mock.Mock(load_public_scope=mock.Mock(return_value=scope))), \
                     mock.patch.object(module, "_external", side_effect=fake_external(external_calls)), \
                     contextlib.redirect_stdout(io.StringIO()), \
                     mock.patch.dict(os.environ, {
                        "GENEWHIP_QUALIFICATION_SCOPE_PATH": "evidence/v02-execution.json",
                        "GENEWHIP_QUALIFICATION_SCOPE_SHA256": "",
                        "GENEWHIP_QUALIFICATION_STARTED_AT": "",
                        "GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH": "",
                        "GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256": "",
                     }, clear=True):
                    module.ci_package_step("sdk")
                    module.ci_package_step("desktop")
                    summaries = [json.loads((Path(kwargs["fresh_batch_scratch"]).parent
                        / "summary.json").read_text()) for _args, kwargs in external_calls]
            finally:
                module.ROOT = original_root

        self.assertEqual(resolver_calls, [
            {"scope_path": module.PHASE7_CI_MEMORY_SCOPE_PATH.as_posix(),
             "scope_sha256": module.PHASE7_CI_MEMORY_SCOPE_SHA256},
            {"scope_path": module.PHASE7_CI_MEMORY_SCOPE_PATH.as_posix(),
             "scope_sha256": module.PHASE7_CI_MEMORY_SCOPE_SHA256},
        ])
        self.assertEqual(len(external_calls), 2)
        scratch_roots = []
        for index, (args, kwargs) in enumerate(external_calls):
            role = ("sdk", "desktop")[index]
            self.assertEqual(args[0][1], "-I")
            self.assertEqual(Path(args[0][2]).name, f"package_{role}.py")
            self.assertEqual(kwargs["phase"], "package")
            self.assertEqual(kwargs["timeout"], 600)
            self.assertEqual(kwargs["file_size_limit_bytes"], 2 * 1024**3)
            self.assertTrue(kwargs["allow_build_file_links"])
            self.assertEqual(kwargs["env"]["GENEWHIP_QUALIFICATION_SCOPE_PATH"],
                module.PHASE7_CI_MEMORY_SCOPE_PATH.as_posix())
            self.assertEqual(kwargs["env"]["GENEWHIP_QUALIFICATION_SCOPE_SHA256"],
                module.PHASE7_CI_MEMORY_SCOPE_SHA256)
            self.assertEqual(kwargs["env"]["GENEWHIP_CI_PACKAGE_OUTER_GROUP"], "1")
            scratch_roots.append(kwargs["fresh_batch_scratch"])
        self.assertNotEqual(scratch_roots[0], scratch_roots[1])
        self.assertTrue(all("coordinator-external-attempts" not in str(path)
            for path in scratch_roots))
        self.assertEqual([row["role"] for row in summaries], ["sdk", "desktop"])
        self.assertTrue(all(row["outcome"] == "passed"
            and row["process_group_cleanup"] == "confirmed"
            and row["rss_bytes_peak"] == 1024**3
            and row["scope_sha256"] == module.PHASE7_CI_MEMORY_SCOPE_SHA256
            and "receipt_sha256" in row for row in summaries))
        self.assertTrue(all("private" not in json.dumps(row) for row in summaries))

    def test_package_step_retains_authenticated_window_and_fails_closed(self):
        module = load_module()
        scope = {"scope_id": "phase7-serial-child-workloads", "per_child_limits": {
            "wall_seconds": 600, "max_binary_file_bytes": 2 * 1024**3,
            "max_rss_bytes": 2 * 1024**3, "max_json_bytes": 32 * 1024**2,
            "max_scratch_bytes": 16 * 1024**3, "max_stdout_stderr_bytes": 16 * 1024**2,
            "max_capture_bytes": 2 * 1024**3, "max_retained_bytes": 4 * 1024**3}}
        seen = {}

        def resolve_profile(**kwargs):
            seen["selection"] = kwargs
            return {"profile_id": "authorized-run", "scope_path": module.PHASE7_CI_MEMORY_SCOPE_PATH,
                "scope_sha256": module.PHASE7_CI_MEMORY_SCOPE_SHA256}

        formal = {
            "GENEWHIP_QUALIFICATION_SCOPE_PATH": module.PHASE7_CI_MEMORY_SCOPE_PATH.as_posix(),
            "GENEWHIP_QUALIFICATION_SCOPE_SHA256": module.PHASE7_CI_MEMORY_SCOPE_SHA256,
            "GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH": "build/v02/phase7-ci-memory/authorization.json",
            "GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256": "e" * 64,
            "GENEWHIP_QUALIFICATION_STARTED_AT": "2026-11-04T00:00:00+00:00",
        }
        with tempfile.TemporaryDirectory(prefix="phase7-ci-package-auth-") as temporary:
            root = Path(temporary).resolve()
            original_root = module.ROOT
            module.ROOT = root
            try:
                with mock.patch.object(module, "_phase7_public_window_profile",
                        side_effect=resolve_profile), \
                     mock.patch.object(module, "_load_phase7_window_module",
                        return_value=mock.Mock(load_public_scope=mock.Mock(return_value=scope))), \
                     mock.patch.object(module, "_external", side_effect=fake_external([])) as external, \
                     contextlib.redirect_stdout(io.StringIO()), \
                     mock.patch.dict(os.environ, formal, clear=True):
                    module.ci_package_step("sdk")
                forwarded = external.call_args.kwargs["env"]
                for name in ("GENEWHIP_QUALIFICATION_SCOPE_PATH",
                        "GENEWHIP_QUALIFICATION_SCOPE_SHA256",
                        "GENEWHIP_QUALIFICATION_WINDOW_AUTH_PATH",
                        "GENEWHIP_QUALIFICATION_WINDOW_AUTH_SHA256",
                        "GENEWHIP_QUALIFICATION_STARTED_AT"):
                    self.assertEqual(forwarded[name], formal[name])

                with mock.patch.object(module, "_phase7_public_window_profile",
                        side_effect=ValueError("phase7-window-profile-invalid")), \
                     mock.patch.object(module, "_load_phase7_window_module",
                        return_value=mock.Mock(load_public_scope=mock.Mock(return_value=scope))), \
                     mock.patch.object(module, "_external") as forbidden, \
                     mock.patch.dict(os.environ, {**formal,
                        "GENEWHIP_QUALIFICATION_SCOPE_PATH": "evidence/v02-execution.json"}, clear=True):
                    with self.assertRaisesRegex(ValueError, "phase7-window-profile-invalid"):
                        module.ci_package_step("sdk")
                    forbidden.assert_not_called()
            finally:
                module.ROOT = original_root

    def test_failed_builder_keeps_local_receipt_and_emits_failed_summary(self):
        module = load_module()
        scope = {"scope_id": "phase7-serial-child-workloads", "per_child_limits": {
            "wall_seconds": 600, "max_binary_file_bytes": 2 * 1024**3,
            "max_rss_bytes": 2 * 1024**3, "max_json_bytes": 32 * 1024**2,
            "max_scratch_bytes": 16 * 1024**3, "max_stdout_stderr_bytes": 16 * 1024**2,
            "max_capture_bytes": 2 * 1024**3, "max_retained_bytes": 4 * 1024**3}}
        profile = {"profile_id": "authorized-run-public",
            "scope_path": module.PHASE7_CI_MEMORY_SCOPE_PATH,
            "scope_sha256": module.PHASE7_CI_MEMORY_SCOPE_SHA256}
        calls = []
        with tempfile.TemporaryDirectory(prefix="phase7-ci-package-failure-") as temporary:
            root = Path(temporary).resolve()
            original_root = module.ROOT
            module.ROOT = root
            output = io.StringIO()
            try:
                with mock.patch.object(module, "_phase7_public_window_profile", return_value=profile), \
                     mock.patch.object(module, "_load_phase7_window_module",
                        return_value=mock.Mock(load_public_scope=mock.Mock(return_value=scope))), \
                     mock.patch.object(module, "_external", side_effect=fake_external(calls, fail=True)), \
                     contextlib.redirect_stdout(output), \
                     mock.patch.dict(os.environ, {}, clear=True):
                    with self.assertRaisesRegex(ValueError, "monitored-builder-failed"):
                        module.ci_package_step("desktop")
            finally:
                module.ROOT = original_root

            attempt_root = calls[0][1]["fresh_batch_scratch"].parent
            summary_path = attempt_root / "summary.json"
            self.assertTrue(summary_path.is_file())
            summary = json.loads(summary_path.read_text())
            self.assertEqual(summary["outcome"], "failed")
            self.assertEqual(summary["returncode"], 7)
            self.assertTrue(summary["bound_violation"])
            self.assertEqual(summary["process_group_cleanup"], "confirmed")
            self.assertEqual(summary["rss_bytes_peak"], 1024**3)
            self.assertNotIn("private", summary_path.read_text())
            self.assertIn('"outcome":"failed"', output.getvalue())

    def test_external_process_boundary_receives_the_selected_rss_and_scratch_limits(self):
        module = load_module()
        for relative, digest, expected_rss in (
                (module.PHASE7_AUTHORIZED_SCOPE_PATH,
                    module.PHASE7_AUTHORIZED_SCOPE_SHA256, 4 * 1024**3),
                (module.PHASE7_CI_MEMORY_SCOPE_PATH,
                    module.PHASE7_CI_MEMORY_SCOPE_SHA256, 2 * 1024**3)):
            with self.subTest(scope=relative), \
                 tempfile.TemporaryDirectory(prefix="phase7-ci-memory-boundary-") as temporary:
                root = Path(temporary).resolve()
                scope_path = root / relative
                scope_path.parent.mkdir(parents=True)
                scope_path.write_bytes((ROOT / relative).read_bytes())
                original_root = module.ROOT
                module.ROOT = root
                observed = {}

                def bounded(command, **kwargs):
                    observed.update(kwargs)
                    return {"returncode": 0, "process_group_cleanup": "confirmed",
                        "streams": {"stdout": {"text": ""}, "stderr": {"text": ""}}}

                try:
                    with mock.patch.object(module, "_bounded_command", side_effect=bounded):
                        result = module._external(["fixed-builder"], timeout=600, phase="package",
                            env={"GENEWHIP_QUALIFICATION_SCOPE_PATH": relative.as_posix(),
                                "GENEWHIP_QUALIFICATION_SCOPE_SHA256": digest},
                            fresh_batch_scratch=root / "build/v02/unique-ci-package-attempt",
                            file_size_limit_bytes=2 * 1024**3)
                finally:
                    module.ROOT = original_root

                self.assertEqual(result.returncode, 0)
                self.assertEqual(observed["limits"]["max_rss_bytes"], expected_rss)
                self.assertEqual(observed["limits"]["max_scratch_bytes"], 16 * 1024**3)
                self.assertEqual(observed["limits"]["max_retained_bytes"], 4 * 1024**3)
                self.assertEqual(observed["file_size_limit_bytes"], 2 * 1024**3)
                roots = observed["scratch_roots"]
                self.assertEqual(len(roots), 1)
                self.assertIn("external-", roots[0].name)

    def test_package_step_rejects_any_non_fixed_action(self):
        module = load_module()
        with self.assertRaisesRegex(ValueError, "ci-package-step-invalid"):
            module.ci_package_step("../../arbitrary-command")

    def test_new_attempt_namespace_cannot_bypass_missing_or_crossed_authority(self):
        module = load_module()
        with tempfile.TemporaryDirectory(prefix="phase7-ci-memory-namespace-") as temporary:
            root = Path(temporary).resolve()
            original_root = module.ROOT
            module.ROOT = root
            attempt = Path("build/v02/phase7-ci-memory/attempts/attempt-0001")
            common = {"batch_authorization": None, "batch_authorization_sha256": None,
                "batch_admission": None, "batch_admission_sha256": None,
                "stage": "source-preparation", "scope_path": module.PHASE7_CI_MEMORY_SCOPE_PATH,
                "journal_path": attempt / "hosted-delivery-journal.json",
                "publication_copy": attempt / "candidate/publication-copy",
                "preflight_path": attempt / "candidate/preparation.json",
                "output_path": attempt / "source-validation.json"}
            try:
                valid_path_only = {
                    "GENEWHIP_QUALIFICATION_SCOPE_PATH":
                        module.PHASE7_CI_MEMORY_SCOPE_PATH.as_posix(),
                    "GENEWHIP_QUALIFICATION_SCOPE_SHA256":
                        module.PHASE7_CI_MEMORY_SCOPE_SHA256,
                }
                with mock.patch.dict(os.environ, valid_path_only, clear=True), \
                     mock.patch.object(module, "_load_phase7_window_module") as window_reader, \
                     mock.patch.object(module, "_external") as external:
                    with self.assertRaisesRegex(ValueError,
                            "phase7-window-scope-or-authority-profile-invalid"):
                        module._fresh_batch_guard(**common)
                    window_reader.assert_not_called()
                    external.assert_not_called()

                crossed_pair = {**valid_path_only,
                    "GENEWHIP_QUALIFICATION_SCOPE_SHA256":
                        module.PHASE7_AUTHORIZED_SCOPE_SHA256}
                with mock.patch.dict(os.environ, crossed_pair, clear=True), \
                     mock.patch.object(module, "_load_phase7_window_module") as window_reader, \
                     mock.patch.object(module, "_external") as external:
                    with self.assertRaisesRegex(ValueError,
                            "phase7-window-scope-or-authority-profile-invalid"):
                        module._fresh_batch_guard(**common)
                    window_reader.assert_not_called()
                    external.assert_not_called()
            finally:
                module.ROOT = original_root

    def test_cli_inherits_new_scope_only_when_flag_is_omitted_and_forwards_it(self):
        module = load_module()
        with tempfile.TemporaryDirectory(prefix="phase7-ci-memory-cli-") as temporary:
            root = Path(temporary).resolve()
            (root / module.PHASE7_CI_MEMORY_SCOPE_PATH).parent.mkdir(parents=True)
            (root / module.PHASE7_CI_MEMORY_SCOPE_PATH).write_bytes(
                (ROOT / module.PHASE7_CI_MEMORY_SCOPE_PATH).read_bytes())
            (root / "evidence/v02-execution.json").write_bytes(
                (ROOT / "evidence/v02-execution.json").read_bytes())
            original_root = module.ROOT
            module.ROOT = root
            captured = {}

            class StopAtBoundary(BaseException):
                pass

            def stop(command, **kwargs):
                captured["command"] = command
                captured["kwargs"] = kwargs
                raise StopAtBoundary()

            def public_profile(**kwargs):
                return {"profile_id": "authorized-run-public",
                    "scope_path": module.PHASE7_CI_MEMORY_SCOPE_PATH,
                    "scope_sha256": module.PHASE7_CI_MEMORY_SCOPE_SHA256}

            try:
                with mock.patch.object(module, "_phase7_public_window_profile",
                        side_effect=public_profile), \
                     mock.patch.object(module, "_check_environment_clock"), \
                     mock.patch.object(module, "_selected_semantic_identity", return_value={
                        "source_sha": "a" * 40, "head_sha": "b" * 40,
                        "base_sha": "c" * 40, "run_id": "123", "run_attempt": "1"}), \
                     mock.patch.object(module, "_external", side_effect=stop), \
                     mock.patch.dict(os.environ, {
                        "GENEWHIP_QUALIFICATION_SCOPE_PATH":
                            module.PHASE7_CI_MEMORY_SCOPE_PATH.as_posix(),
                        "GENEWHIP_QUALIFICATION_SCOPE_SHA256":
                            module.PHASE7_CI_MEMORY_SCOPE_SHA256}, clear=True):
                    with self.assertRaises(StopAtBoundary):
                        module.main(["--mode", "semantic-mutants", "--out",
                            "build/v02/semantic-mutants.json"])
                    command = captured["command"]
                    self.assertIn("--scope", command)
                    scope_index = command.index("--scope") + 1
                    self.assertEqual(Path(command[scope_index]),
                        module.PHASE7_CI_MEMORY_SCOPE_PATH)

                captured.clear()
                with mock.patch.object(module, "_phase7_public_window_profile") as unused_profile, \
                     mock.patch.object(module, "_check_environment_clock"), \
                     mock.patch.object(module, "_selected_semantic_identity", return_value={
                        "source_sha": "a" * 40, "head_sha": "b" * 40,
                        "base_sha": "c" * 40, "run_id": "123", "run_attempt": "1"}), \
                     mock.patch.object(module, "_external", side_effect=stop), \
                     mock.patch.dict(os.environ, {}, clear=True):
                    with self.assertRaises(StopAtBoundary):
                        module.main(["--mode", "semantic-mutants", "--out",
                            "build/v02/semantic-mutants-legacy.json"])
                    command = captured["command"]
                    scope_index = command.index("--scope") + 1
                    self.assertEqual(Path(command[scope_index]),
                        root / "evidence/v02-execution.json")
                    unused_profile.assert_not_called()
            finally:
                module.ROOT = original_root

            conflict_capture = {}
            def forbidden(*args, **kwargs):
                conflict_capture["called"] = True
                raise StopAtBoundary()
            with mock.patch.object(module, "_external", side_effect=forbidden), \
                 mock.patch.dict(os.environ, {
                    "GENEWHIP_QUALIFICATION_SCOPE_PATH":
                        module.PHASE7_CI_MEMORY_SCOPE_PATH.as_posix(),
                    "GENEWHIP_QUALIFICATION_SCOPE_SHA256":
                        module.PHASE7_CI_MEMORY_SCOPE_SHA256}, clear=True):
                result = module.main(["--mode", "semantic-mutants", "--scope",
                    "evidence/v02-phase7-authorized-execution-scope.json", "--out",
                    "build/v02/semantic-mutants.json"])
                self.assertEqual(result, 1)
                self.assertNotIn("called", conflict_capture)


if __name__ == "__main__":
    unittest.main(verbosity=2)
