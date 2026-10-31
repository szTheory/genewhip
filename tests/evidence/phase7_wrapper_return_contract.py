#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Denied source-bound contracts for renewed Phase 7 return admission."""
from __future__ import annotations

import importlib.util
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
_denial_spec = importlib.util.spec_from_file_location("return_sticky_denial",
    ROOT / "tests/evidence/phase7_sticky_denial.py")
denial = importlib.util.module_from_spec(_denial_spec)
_denial_spec.loader.exec_module(denial)
denial.install()

def load(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


coordinator = load("scripts/release/v02_qualification.py", "return_coordinator_contract")
probe = load("tests/evidence/phase7_wrapper_return.py", "return_probe_contract")
archive_contract = load("tests/evidence/phase7_return_archive_contract.py", "return_archive_fixture")

def prearchive_fixture(test):
    """Historical preentry assertions use temp copies, never current spent state."""
    def isolated(self):
        with archive_contract.fixture() as (root, _packet, _coordinator), \
             mock.patch.object(sys.modules[__name__], "ROOT", root), \
             mock.patch.object(coordinator, "ROOT", root), \
             mock.patch.object(probe, "ROOT", root):
            return test(self)
    return isolated

def create_admission_fixture(root: Path) -> str:
    path = root / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ADMISSION.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"fixture":"admission"}\n')
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReturnContracts(unittest.TestCase):
    def test_hosted_cli_threads_selected_journal(self):
        seen = []
        def hosted(*args):
            seen.extend(args)
            return {"status": "prepared", "source_sha": "x", "run_id": "0", "run_attempt": "0"}
        with mock.patch.object(coordinator, "run_hosted_qualification", side_effect=hosted), \
             mock.patch.object(coordinator, "_campaign_projection", return_value={}) as campaign_gate:
            result = coordinator.main(["--mode", "hosted", "--out", "build/v02/campaign15/out.json",
                "--publication-copy", "build/v02/campaign15/publication", "--scope", "evidence/v02-execution.json",
                "--journal", "build/v02/campaign15/hosted-delivery-journal.json",
                "--preflight", "build/v02/campaign15/preflight.json",
                "--campaign", "build/v02/campaign15/campaign.json", "--campaign-sha256", "0" * 64])
        self.assertEqual(result, 0)
        self.assertEqual(len(seen), 7)
        self.assertEqual(seen[4], ROOT / "build/v02/campaign15/hosted-delivery-journal.json")
        self.assertEqual(campaign_gate.call_count, 1)

    def test_campaign_projection_requires_started_owned_canonical_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "campaign.json"
            path.write_text('{"schema":"genewhip.v02-recovery-campaign.v1","status":"authorized-not-started"}')
            with self.assertRaisesRegex(ValueError, "recovery-campaign-path-invalid"):
                coordinator._campaign_projection(path, ROOT / "evidence/v02-execution.json")

    def test_campaign_selected_hosted_entry_rejects_before_dispatch_without_campaign(self):
        invoked = []
        with mock.patch.object(coordinator, "run_hosted_qualification",
                side_effect=lambda *args: invoked.append(args)):
            result = coordinator.main(["--mode", "hosted", "--out", "build/v02/campaign15/out.json",
                "--publication-copy", "build/v02/campaign15/publication", "--scope", "evidence/v02-execution.json",
                "--journal", "build/v02/campaign15/hosted-delivery-journal.json",
                "--preflight", "build/v02/campaign15/preflight.json",
                "--campaign", "build/v02/campaign15/campaign.json", "--campaign-sha256", "0" * 64])
        self.assertEqual(result, 1)
        self.assertEqual(invoked, [])

    def test_selected_journal_prepare_only_rejects_before_preflight(self):
        invoked = []
        with mock.patch.object(coordinator, "prepare_public_snapshot",
                side_effect=lambda *args: invoked.append(args)):
            result = coordinator.main(["--mode", "stage-public", "--prepare-only",
                "--out", "build/v02/campaign15/preparation.json",
                "--publication-copy", "build/v02/campaign15/public-source",
                "--journal", "build/v02/campaign15/hosted-delivery-journal.json",
                "--scope", "evidence/v02-execution.json"])
        self.assertEqual(result, 1)
        self.assertEqual(invoked, [])

    def test_selected_campaign_rejects_legacy_preflight_before_hosted_dispatch(self):
        invoked = []
        with mock.patch.object(coordinator, "run_hosted_qualification",
                side_effect=lambda *args: invoked.append(args)):
            result = coordinator.main(["--mode", "hosted", "--out", "build/v02/campaign15/out.json",
                "--publication-copy", "build/v02/campaign15/publication",
                "--scope", "evidence/v02-execution.json",
                "--journal", "build/v02/campaign15/hosted-delivery-journal.json",
                "--preflight", "build/v02/preflight.json",
                "--campaign", "build/v02/campaign15/campaign.json", "--campaign-sha256", "0" * 64])
        self.assertEqual(result, 1)
        self.assertEqual(invoked, [])

    def test_campaign_helper_does_not_create_campaign_on_invalid_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "not-canonical/campaign.json"
            with self.assertRaisesRegex(ValueError, "return-campaign-must-be-new-canonical-file"):
                probe.create_campaign(target, {})
            self.assertFalse(target.exists())
        self.assertEqual(denial.receipt()["unexpected_denials"], 0)

    def test_admission_binds_interpreter_before_reviewed_entry(self):
        with mock.patch.object(probe.sys, "executable", new="/usr/bin/python3"):
            with self.assertRaisesRegex(ValueError, "return-admission-interpreter-stale"):
                probe.validate_interpreter_pin({"executable": "/opt/python",
                    "sha256": "0" * 64, "version": "3.x", "platform": {"system": "Darwin"}})

    def test_packet_pins_exact_owner_and_leaf_argv(self):
        packet_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ADMISSION.json"
        with mock.patch.object(probe, "packet_and_review") as packet_gate:
            packet_gate.return_value = (json.loads(packet_path.read_text()), packet_path.with_name("07-15-REVIEW.md"))
            packet = packet_gate.return_value[0]
            packet["owner_argv"][-1] = "replaced"
            with self.assertRaisesRegex(ValueError, "return-owner-command-template-mismatch"):
                probe.validate_packet_for_entry(packet_path)

    def test_leaf_template_is_specific_to_actual_wrapper_cwd(self):
        packet_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ADMISSION.json"
        with mock.patch.object(probe, "packet_and_review") as packet_gate:
            packet_gate.return_value = (json.loads(packet_path.read_text()), packet_path.with_name("07-15-REVIEW.md"))
            packet = packet_gate.return_value[0]
            packet["leaf_argv"]["shared_launch"][-3] = "tests/evidence/phase7_wrapper_return.py"
            with self.assertRaisesRegex(ValueError, "return-leaf-command-template-mismatch"):
                probe.validate_packet_for_entry(packet_path)

    def test_failed_attempt_manifest_requires_measured_and_conservative_campaign_reserve(self):
        expected = probe.CUMULATIVE_LIMITS
        self.assertEqual(coordinator.ATTEMPT3_CUMULATIVE_LIMITS, expected)
        probe.validate_cumulative_limits(expected)
        self.assertEqual(expected["campaign_host_invocations"], 4)
        self.assertEqual(expected["campaign_wrapper_calls"], 4)
        self.assertEqual(expected["campaign_start_events"], 130)
        self.assertEqual(expected["campaign_status_helper_starts"], 124)
        self.assertEqual(expected["campaign_observer_queries"], 24)
        self.assertEqual(expected["campaign_rss_samples"], 2048)
        self.assertEqual(expected["campaign_native_rss_pid_queries"], 8_388_608)
        self.assertEqual(expected["campaign_retained_bytes"], 8_408_394)
        self.assertEqual(expected["campaign_control_bytes"], 66_833)
        self.assertEqual(expected["campaign_control_entries"], 3)
        self.assertEqual(expected["campaign_status_output_bytes"], 10_485_760)
        self.assertEqual(expected["campaign_elapsed_seconds"], 360)
        historical = probe.PRIOR_CUMULATIVE_LIMITS
        self.assertEqual(historical["prior_starts_reserved"],
            historical["prior_controller_starts_measured"] + historical["prior_owner_starts_unknown_reserved"])
        self.assertEqual(historical["prior_native_rss_queries_reserved"],
            (historical["prior_owner_rss_samples_unknown_reserved"]
             + historical["prior_rss_samples_measured"]) * 4096)
        self.assertEqual((expected["prior_host_invocations_used"],
            expected["prior_wrapper_calls_used"], expected["future_wrapper_calls_reserved"]), (3, 2, 2))
        self.assertLessEqual(expected["prior_starts_reserved"] + expected["future_starts_reserved"],
            expected["campaign_start_events"])
        with self.assertRaisesRegex(ValueError, "return-cumulative-attempt-budget-invalid"):
            probe.validate_cumulative_limits(dict(expected, future_starts_reserved=126))

    def test_attempt4_adds_only_host_and_control_debits(self):
        expected = probe.ATTEMPT4_CUMULATIVE_LIMITS
        self.assertEqual(expected["campaign_host_invocations"], 5)
        self.assertEqual(expected["prior_host_invocations_used"], 4)
        self.assertEqual(expected["future_host_invocations_reserved"], 1)
        self.assertEqual(expected["campaign_control_bytes"], 69222)
        self.assertEqual(expected["prior_control_bytes_measured"], 3686)
        self.assertEqual(expected["future_control_bytes_reserved"], 65536)
        self.assertEqual(expected["campaign_control_entries"], 4)
        self.assertEqual(expected["prior_control_entries_measured"], 3)
        self.assertEqual(expected["prior_elapsed_seconds_reserved"], 360)
        self.assertEqual(expected["future_elapsed_seconds_reserved"], 120)
        self.assertEqual(expected["campaign_elapsed_seconds"], 480)
        probe.validate_cumulative_limits(expected, attempt_number=4)
        self.assertEqual(coordinator.ATTEMPT4_CUMULATIVE_LIMITS, expected)
        for key in ("campaign_start_events", "campaign_status_helper_starts",
                    "campaign_observer_queries", "campaign_rss_samples",
                    "campaign_native_rss_pid_queries", "campaign_status_output_bytes",
                    "future_starts_reserved",
                    "future_status_helpers_reserved", "future_rss_samples_reserved"):
            self.assertEqual(expected[key], probe.CUMULATIVE_LIMITS[key], key)

    def test_corrected_attempt_consumption_is_durable_and_one_shot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign_root = root / "build/v02/campaign15"
            campaign_root.mkdir(parents=True)
            packet = {"packet_sha256": "a" * 64,
                "resume_campaign": {"failed_attempt": {"sha256": "b" * 64}}}
            with mock.patch.object(probe, "ROOT", root):
                probe.require_corrected_invocation_unconsumed()
                digest = probe.consume_corrected_invocation(packet, "c" * 64,
                    "2026-10-30T16:50:39.837827+00:00")
                marker = campaign_root / "attempt2-started.json"
                self.assertTrue(marker.is_file())
                self.assertEqual(hashlib.sha256(marker.read_bytes()).hexdigest(), digest)
                with self.assertRaisesRegex(ValueError, "return-corrected-invocation-already-consumed"):
                    probe.require_corrected_invocation_unconsumed()
                with self.assertRaisesRegex(ValueError, "return-corrected-invocation-already-consumed"):
                    probe.consume_corrected_invocation(packet, "c" * 64,
                        "2026-10-30T16:50:39.837827+00:00")

    def test_actual_retry_measurements_fit_persistent_campaign_reserves(self):
        cases = [{"starts": 42, "status_helper_starts": 40,
            "observer_queries": 8, "rss_samples": 512} for _ in range(2)]
        usage = probe.validate_campaign_usage(cases, 2, 120, 19786, 8 * 1024 * 1024)
        self.assertEqual(usage["campaign_used"], {
            "host_invocations": 4, "wrapper_calls": 4, "start_events": 130,
            "status_helper_starts": 124, "observer_queries": 24,
            "rss_samples": 2048, "native_rss_pid_queries": 8388608,
            "retained_bytes": 8408394, "status_output_bytes_reserved": 10485760,
            "elapsed_seconds_reserved": 360.0, "control_bytes_reserved": 66833,
            "control_entries_reserved": 3})
        with self.assertRaisesRegex(ValueError, "return-cumulative-campaign-counter-invalid"):
            probe.validate_campaign_usage(cases, 1, 120, 19786, 8 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, "return-cumulative-campaign-counter-invalid"):
            probe.validate_campaign_usage(cases, 2, float("nan"), 19786, 8 * 1024 * 1024)

    def test_failed_attempt_resume_validates_before_and_after_atomic_archive(self):
        phase_rel = Path(".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery")
        packet_path = ROOT / phase_rel / "07-15-ATTEMPT2-ADMISSION.json"
        packet = json.loads(packet_path.read_bytes())
        campaign_path = ROOT / "build/v02/campaign15/campaign.json"
        campaign = json.loads(campaign_path.read_bytes())
        campaign_sha = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
        packet_sha = hashlib.sha256(packet_path.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="return-attempt-state-") as temporary:
            root = Path(temporary)
            copied_phase = root / phase_rel
            copied_phase.mkdir(parents=True)
            for name in ("07-15-PRESTART-REVIEW.md", "07-15-PRESTART-SECURITY.md",
                         "07-15-PRESTART-REJECTION.md", "07-15-ATTEMPT1-FAILURE.json",
                         "07-15-ATTEMPT1-REVIEW.md", "07-15-ATTEMPT1-SECURITY.md"):
                shutil.copy2(ROOT / phase_rel / name, copied_phase / name)
            shutil.copytree(ROOT / "build/v02/recovery15-attempt1", root / "build/v02/recovery15")
            resume = packet["resume_campaign"]
            with mock.patch.object(coordinator, "ROOT", root):
                self.assertTrue(coordinator._validate_failed_attempt1(packet, resume,
                    campaign_sha, campaign["started_at"], packet_sha))
                archive = root / "build/v02/recovery15-attempt1"
                recovery = root / "build/v02/recovery15"
                campaign_root = root / "build/v02/campaign15"
                campaign_root.mkdir(parents=True)
                marker_packet = {"packet_sha256": packet_sha,
                    "resume_campaign": resume}
                with mock.patch.object(probe, "ROOT", root):
                    probe.consume_corrected_invocation(marker_packet, campaign_sha,
                        campaign["started_at"])
                recovery.rename(archive)
                recovery.mkdir(mode=0o700)
                (recovery / ".limits.lock").write_bytes(b"")
                self.assertTrue(coordinator._validate_failed_attempt1(packet, resume,
                    campaign_sha, campaign["started_at"], packet_sha))
                marker = campaign_root / "attempt2-started.json"
                marker.unlink()
                self.assertFalse(coordinator._validate_failed_attempt1(packet, resume,
                    campaign_sha, campaign["started_at"], packet_sha))

    def test_live_counter_verifier_rejects_negative_boolean_and_over_limit(self):
        for value in (-1, True, 9):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "return-live-counter-invalid:observer_queries"):
                    probe.require_bounded_count(value, 8, "observer_queries")

    def test_live_case_roster_rejects_reused_case_one_paths(self):
        def row(case, root, controller_pid):
            return {"case": case, "case_root": root,
                "controller_receipt_path": root + "/controller/process.json",
                "wrapper_result_path": root + "/owner-work/wrapper-result.json",
                "owner_process_count_path": root + "/owner-process-count.json",
                "release-A_path": root + "/release-A.json",
                "release-B_path": root + "/release-B.json",
                "leaf_receipt": root + "/owner-work/process-receipts/leaf.json",
                "controller_pid": controller_pid}
        first = row("shared_launch", "build/v02/recovery15/case-1", 100)
        second = row("bounded_command", "build/v02/recovery15/case-2", 101)
        probe.validate_live_case_roster([first, second])
        reused = dict(first, case="bounded_command")
        with self.assertRaisesRegex(ValueError, "return-live-case-path-binding-invalid"):
            probe.validate_live_case_roster([first, reused])

    def test_live_wrapper_result_requires_exact_case_wrapper_and_pins(self):
        valid = {"wrapper": "shared_launch", "case": "shared_launch",
            "campaign_sha256": "a" * 64, "packet_sha256": "b" * 64,
            "returncode": 0}
        probe.validate_wrapper_result_identity("shared_launch", valid, "a" * 64, "b" * 64)
        second = {**valid, "wrapper": "_bounded_command", "case": "bounded_command"}
        probe.validate_wrapper_result_identity("bounded_command", second, "a" * 64, "b" * 64)
        for case, row in (("shared_launch", second), ("bounded_command", valid)):
            with self.subTest(case=case), self.assertRaisesRegex(ValueError,
                    "return-live-wrapper-identity-invalid"):
                probe.validate_wrapper_result_identity(case, row, "a" * 64, "b" * 64)

    def test_final_absence_observation_is_bound_to_pid_query_and_cap(self):
        valid = {"pid": 123, "query": list(probe.LIMITS["observer_argv"]),
            "identity": None, "group_members": [], "bytes": 5,
            "status_sha256": "a" * 64}
        probe.validate_final_observation(valid, 123)
        mutants = [dict(valid, pid=124), dict(valid, query=["/bin/ps"]),
            dict(valid, bytes=probe.CAP + 1)]
        for mutant in mutants:
            with self.subTest(mutant=mutant), self.assertRaisesRegex(ValueError,
                    "return-live-final-absence-observation-invalid"):
                probe.validate_final_observation(mutant, 123)

    def test_host_clock_markers_are_rejected_before_campaign_creation(self):
        for marker in ("GENEWHIP_QUALIFICATION_STARTED_AT", "GENEWHIP_QUALIFICATION_PHASE",
                       "GENEWHIP_QUALIFICATION_NONCE", "GENEWHIP_RECOVERY_CAMPAIGN_SHA256"):
            with self.subTest(marker=marker), mock.patch.dict(os.environ, {marker: "forged"}):
                with self.assertRaisesRegex(ValueError, "return-host-environment-clock-not-clean"):
                    probe.require_clean_host_environment()

    def test_observer_parser_rejects_malformed_identity_birth_or_state(self):
        good = b"1 1 Fri Oct 30 12:00:00 2026 Ss\n"
        self.assertIn(1, probe.parse_observer_status(good))
        for raw in (b"0 1 Fri Oct 30 12:00:00 2026 S\n",
                    b"1 0 Fri Oct 30 12:00:00 2026 S\n",
                    b"1 1 Someday Oct 30 12:00:00 2026 S\n",
                    b"1 1 Fri Oct 30 12:00:00 2026 Q\n",
                    b"1 1 Fri Oct 30 12:00:00 2026 S++\n",
                    b"1 1 Fri Oct 30 12:00:00 2026\n"):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "return-observer-status-decode-invalid"):
                    probe.parse_observer_status(raw)

    def test_owned_tree_cap_rejects_before_opening_overflow_file(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(probe, "ROOT", Path(temporary)):
            recovery = Path(temporary) / "build/v02/recovery15"
            recovery.mkdir(parents=True)
            probe.create_limits_lock(recovery)
            case_root = recovery / "case-1"
            case_root.mkdir()
            for index in range(probe.LIMITS["maximum_tree_entries"]):
                (case_root / f"evidence-{index}.bin").write_bytes(b"x")
            target = case_root / "overflow.json"
            with self.assertRaisesRegex(ValueError, "return-output-prospective-ceiling"):
                probe.write_record(target, {"would": "exceed cap"})
            self.assertFalse(target.exists())
            unlocked = recovery / "after-cap-check.json"
            probe.write_record(unlocked, {"lock": "reusable"})
            self.assertTrue(unlocked.is_file())

    def test_bounded_wrapper_writer_delegates_and_rejects_oversize_before_write(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(probe, "ROOT", Path(temporary)):
            recovery = Path(temporary) / "build/v02/recovery15"
            recovery.mkdir(parents=True)
            probe.create_limits_lock(recovery)
            case_root = recovery / "case-1"
            work = case_root / "owner-work"
            work.mkdir(parents=True)
            calls = []
            def writer(path, value):
                calls.append(path)
                path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
            bounded = probe.bounded_json_writer(case_root, work, writer)
            target = work / "attempt.json"
            bounded(target, {"ordinary": "receipt"})
            self.assertEqual(calls, [target])
            oversized = work / "oversized.json"
            with self.assertRaisesRegex(ValueError, "return-wrapper-json-byte-cap"):
                bounded(oversized, {"data": "x" * probe.CAP})
            self.assertFalse(oversized.exists())
            self.assertEqual(len(calls), 1)

    def test_direct_owner_role_rejects_without_reviewed_controller_authority(self):
        result = probe.main(["--owner", "shared_launch", "build/v02/recovery15/case-1"])
        self.assertEqual(result, 1)
        self.assertEqual(denial.receipt()["unexpected_denials"], 0)

    def test_attempt3_consumption_binds_all_prior_usage_and_is_one_shot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign_root = root / "build/v02/campaign15"
            campaign_root.mkdir(parents=True)
            campaign_path = campaign_root / "campaign.json"
            campaign_path.write_bytes(b'{"started_at":"start"}' + b" " * (672 - len(b'{"started_at":"start"}')))
            old_marker = campaign_root / "attempt2-started.json"
            old_value = {"schema": "genewhip.phase7-wrapper-return-attempt-entry.v1",
                "attempt": 2, "campaign_sha256": hashlib.sha256(campaign_path.read_bytes()).hexdigest(),
                "campaign_started_at": "start", "packet_sha256": "e" * 64}
            old_value["record_sha256"] = hashlib.sha256(json.dumps(old_value,
                sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            old_raw = json.dumps(old_value, sort_keys=True, separators=(",", ":")).encode()
            old_marker.write_bytes(old_raw + b" " * (625 - len(old_raw)))
            phase_root = root / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
            phase_root.mkdir(parents=True)
            attempt2_path = phase_root / "07-15-ATTEMPT2-FAILURE.json"
            attempt2_path.write_bytes(b"attempt 2 failure")
            packet = {"packet_sha256": "a" * 64, "resume_campaign": {
                "attempt_number": 3,
                "failed_attempt": {"sha256": "1" * 64},
                "attempt2_failure": {"path": ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ATTEMPT2-FAILURE.json",
                    "sha256": hashlib.sha256(attempt2_path.read_bytes()).hexdigest()},
                "attempt2_marker_sha256": hashlib.sha256(old_marker.read_bytes()).hexdigest()}}
            with mock.patch.object(probe, "ROOT", root):
                campaign_sha = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
                entry = probe.consume_final_invocation(packet, campaign_sha, "start")
            self.assertEqual(entry, "build/v02/campaign15/attempt3-started.json")
            marker = json.loads((campaign_root / "attempt3-started.json").read_text())
            self.assertEqual(marker["attempt"], 3)
            self.assertEqual(marker["prior_host_invocations_used"], 3)
            self.assertEqual(marker["prior_wrapper_calls_used"], 2)
            self.assertEqual(marker["attempt2_failure_manifest_sha256"], packet["resume_campaign"]["attempt2_failure"]["sha256"])
            self.assertEqual(marker["attempt2_marker_sha256"], packet["resume_campaign"]["attempt2_marker_sha256"])
            with self.assertRaisesRegex(ValueError, "return-final-invocation-already-consumed"):
                with mock.patch.object(probe, "ROOT", root):
                    probe.consume_final_invocation(packet, campaign_sha, "start")
        self.assertEqual(denial.receipt()["unexpected_denials"], 0)

    def test_attempt3_controller_accounts_both_cases_and_stops_on_failure(self):
        for fail_first in (False, True):
            with self.subTest(fail_first=fail_first), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "scripts/release").mkdir(parents=True)
                (root / "evidence").mkdir()
                (root / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery").mkdir(parents=True)
                coordinator_path = root / "scripts/release/v02_qualification.py"
                coordinator_path.write_text(
                    "def _campaign_projection(*args, **kwargs): return {}\n"
                    "def _require_hosted_budget(*args, **kwargs): return 10000\n")
                scope_path = root / "evidence/v02-execution.json"
                scope_path.write_text("{}")
                campaign_dir = root / "build/v02/campaign15"
                campaign_dir.mkdir(parents=True)
                campaign_path = campaign_dir / "campaign.json"
                campaign_path.write_bytes(b"x" * 672)
                recovery = root / "build/v02/recovery15"
                recovery.mkdir(parents=True)
                (recovery / ".limits.lock").write_bytes(b"")
                attempt1_archive = root / "build/v02/recovery15-attempt1"
                attempt2_archive = root / "build/v02/recovery15-attempt2"
                attempt1_archive.mkdir()
                attempt2_archive.mkdir()
                (attempt1_archive / "retained.bin").write_bytes(b"a" * 9665)
                (attempt2_archive / "retained.bin").write_bytes(b"b" * 10121)
                packet = {"resume_campaign": {"attempt_number": 3}, "packet_sha256": "a" * 64,
                    "sources": {}}
                review_path = root / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-REVIEW.md"
                review_path.write_text("review")
                case_calls = []
                order = []
                def run_case(index, case, counters, campaign_sha, packet_sha):
                    case_calls.append(case)
                    order.append(f"case{index}")
                    counts_path = recovery / f"owner-count-{index}.json"
                    counts_path.write_text('{"wrapper_calls":1}\n')
                    return {"case": case, "status": "failed" if fail_first and index == 1 else "pass",
                        "owner_settled": True, "leaf_settled": True,
                        "starts": 42, "status_helper_starts": 40,
                        "observer_queries": 8, "rss_samples": 512,
                        "owner_process_count_path": counts_path.relative_to(root).as_posix()}
                marker_path = campaign_dir / "attempt3-started.json"
                marker_path.write_bytes(b"marker")
                def consume(*args):
                    order.append("debit")
                    return "build/v02/campaign15/attempt3-started.json"
                def archive():
                    order.append("archive")
                campaign_sha = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
                with mock.patch.object(probe, "ROOT", root), \
                     mock.patch.object(probe, "validate_packet_for_entry", return_value=(packet, review_path)), \
                     mock.patch.object(probe, "require_clean_host_environment"), \
                     mock.patch.object(probe, "validate_prechild_resume_state",
                        return_value=({"started_at": "start", "journal_path": "journal.json"}, campaign_sha, True)), \
                     mock.patch.object(probe, "consume_final_invocation", side_effect=consume), \
                     mock.patch.object(probe, "archive_failed_attempt2_and_prepare_recovery", side_effect=archive), \
                     mock.patch.object(probe, "run_case", side_effect=run_case):
                    result = probe.run_selected(Path("packet.json"), Path("build/v02/campaign15/campaign.json"),
                        Path("build/v02/recovery15/live.json"))
                    live = json.loads((recovery / "live.json").read_text())
                self.assertEqual(result, 1 if fail_first else 0)
                self.assertEqual(order[:3], ["debit", "archive", "case1"])
                self.assertEqual(case_calls, ["shared_launch"] if fail_first else ["shared_launch", "bounded_command"])
                self.assertEqual(live["attempt_number"], 3)
                if not fail_first:
                    self.assertEqual(live["cumulative_accounting"]["campaign_used"]["host_invocations"], 4)
                    self.assertEqual(live["cumulative_accounting"]["campaign_used"]["wrapper_calls"], 4)
                else:
                    self.assertEqual(live["status"], "failed")
            self.assertEqual(denial.receipt()["unexpected_denials"], 0)

    @prearchive_fixture
    def test_coordinator_reopens_both_failed_attempt_sources_before_attempt3(self):
        phase = ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/"
        campaign_path = ROOT / "build/v02/campaign15/campaign.json"
        campaign_sha = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
        started = json.loads(campaign_path.read_bytes())["started_at"]
        old_packet = ROOT / (phase + "07-15-ATTEMPT2-ADMISSION.json")
        manifest = ROOT / (phase + "07-15-ATTEMPT2-FAILURE.json")
        marker = ROOT / "build/v02/campaign15/attempt2-started.json"
        resume = {
            "attempt_number": 3,
            "campaign_sha256": campaign_sha,
            "campaign_started_at": started,
            "attempt2_marker_path": "build/v02/campaign15/attempt2-started.json",
            "attempt2_marker_sha256": hashlib.sha256(marker.read_bytes()).hexdigest(),
            "attempt2_failure": {"path": phase + "07-15-ATTEMPT2-FAILURE.json",
                "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()},
            "attempt2_packet_sha256": hashlib.sha256(old_packet.read_bytes()).hexdigest(),
            "attempt2_admission_path": phase + "07-15-ATTEMPT2-ADMISSION.json",
            "attempt2_admission_sha256": hashlib.sha256(old_packet.read_bytes()).hexdigest(),
            "attempt2_review_path": phase + "07-15-ATTEMPT2-REVIEW.md",
            "attempt2_review_sha256": hashlib.sha256((ROOT / (phase + "07-15-ATTEMPT2-REVIEW.md")).read_bytes()).hexdigest(),
            "attempt2_security_path": phase + "07-15-ATTEMPT2-SECURITY.md",
            "attempt2_security_sha256": hashlib.sha256((ROOT / (phase + "07-15-ATTEMPT2-SECURITY.md")).read_bytes()).hexdigest(),
            "attempt2_denied_path": phase + "07-15-DENIED-FOLLOWUP.md",
            "attempt2_denied_sha256": hashlib.sha256((ROOT / (phase + "07-15-DENIED-FOLLOWUP.md")).read_bytes()).hexdigest(),
        }
        self.assertTrue(coordinator._validate_failed_attempt2(
            {"cumulative_limits": probe.CUMULATIVE_LIMITS}, resume, campaign_sha, started,
            hashlib.sha256((ROOT / (phase + "07-15-ADMISSION.json")).read_bytes()).hexdigest()))
        altered = dict(resume)
        altered["attempt2_marker_sha256"] = "0" * 64
        self.assertFalse(coordinator._validate_failed_attempt2(
            {"cumulative_limits": probe.CUMULATIVE_LIMITS}, altered, campaign_sha, started,
            hashlib.sha256((ROOT / (phase + "07-15-ADMISSION.json")).read_bytes()).hexdigest()))
        admission = json.loads(old_packet.read_bytes())
        admission["cumulative_limits"] = probe.CUMULATIVE_LIMITS
        admission["resume_campaign"].update(resume)
        admission["resume_campaign"].update({
            "attempt3_marker_path": "build/v02/campaign15/attempt3-started.json",
            "attempt2_return_path": phase + "07-15-RETURN.md",
            "attempt2_return_sha256": hashlib.sha256((ROOT / (phase + "07-15-RETURN.md")).read_bytes()).hexdigest(),
        })
        campaign = json.loads(campaign_path.read_bytes())
        self.assertTrue(coordinator._validate_campaign_resume(
            admission, campaign, campaign_sha, "f" * 64))

    @prearchive_fixture
    def test_attempt3_readonly_gate_reopens_current_campaign_and_both_failures(self):
        phase = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
        packet = json.loads((phase / "07-15-ADMISSION.json").read_bytes())
        campaign_path = ROOT / "build/v02/campaign15/campaign.json"
        before_campaign = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
        before_attempt2 = hashlib.sha256((ROOT / "build/v02/recovery15/live.json").read_bytes()).hexdigest()
        with mock.patch.dict(os.environ, {}, clear=True):
            started, campaign_sha, needs_archive = probe.validate_final_prechild_resume_state(
                campaign_path, packet)
        self.assertEqual(started["started_at"], "2026-10-30T16:50:39.837827+00:00")
        self.assertEqual(campaign_sha, before_campaign)
        self.assertTrue(needs_archive)
        self.assertEqual(hashlib.sha256(campaign_path.read_bytes()).hexdigest(), before_campaign)
        self.assertEqual(hashlib.sha256((ROOT / "build/v02/recovery15/live.json").read_bytes()).hexdigest(), before_attempt2)
        self.assertFalse((ROOT / "build/v02/recovery15-attempt2").exists())
        invalid = dict(packet)
        invalid["resume_campaign"] = dict(packet["resume_campaign"], attempt_number=4)
        with mock.patch.dict(os.environ, {}, clear=True), \
             self.assertRaisesRegex(ValueError, "return-final-campaign-binding-invalid"):
            probe.validate_final_prechild_resume_state(campaign_path, invalid)

    def test_campaign_record_is_bound_to_external_digest_and_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evidence").mkdir()
            (root / "build/v02/campaign15").mkdir(parents=True)
            scope = {"qualification_batch": {"wall_seconds": 86400,
                "runtime_wall_seconds": 64800, "package_wall_seconds": 14400,
                "close_wall_seconds": 7200, "publication_reserve_seconds": 7200,
                "benchmark_sub_batch_seconds": 43200}}
            scope_path = root / "evidence/v02-execution.json"
            scope_path.write_text(json.dumps(scope))
            scope_sha = hashlib.sha256(scope_path.read_bytes()).hexdigest()
            admission_sha = create_admission_fixture(root)
            started = (datetime.datetime.now(datetime.timezone.utc) -
                       datetime.timedelta(seconds=30)).isoformat()
            record = {"schema": "genewhip.v02-recovery-campaign.v1", "status": "started",
                "campaign_id": "phase7-renewed-2026-10-30", "started_at": started,
                "scope_path": "evidence/v02-execution.json", "scope_sha256": scope_sha,
                "admission_sha256": admission_sha,
                "journal_path": "build/v02/campaign15/hosted-delivery-journal.json"}
            start = datetime.datetime.fromisoformat(started)
            record.update(runtime_cutoff=(start + datetime.timedelta(seconds=64800)).isoformat(),
                package_cutoff=(start + datetime.timedelta(seconds=79200)).isoformat(),
                global_cutoff=(start + datetime.timedelta(seconds=86400)).isoformat())
            record["record_sha256"] = hashlib.sha256(json.dumps(record, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            campaign_path = root / "build/v02/campaign15/campaign.json"
            campaign_path.write_text(json.dumps(record, sort_keys=True))
            pin = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
            with mock.patch.object(coordinator, "ROOT", root):
                accepted = coordinator._campaign_projection(Path("build/v02/campaign15/campaign.json"),
                    Path("evidence/v02-execution.json"),
                    Path("build/v02/campaign15/hosted-delivery-journal.json"),
                    expected_sha256=pin, require_return=False)
                self.assertEqual(accepted["started_at"], started)
                changed = dict(record)
                changed["started_at"] = (start - datetime.timedelta(seconds=1)).isoformat()
                altered_start = datetime.datetime.fromisoformat(changed["started_at"])
                changed.update(runtime_cutoff=(altered_start + datetime.timedelta(seconds=64800)).isoformat(),
                    package_cutoff=(altered_start + datetime.timedelta(seconds=79200)).isoformat(),
                    global_cutoff=(altered_start + datetime.timedelta(seconds=86400)).isoformat())
                changed["record_sha256"] = hashlib.sha256(json.dumps(
                    {key: value for key, value in changed.items() if key != "record_sha256"},
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                campaign_path.write_text(json.dumps(changed, sort_keys=True))
                with self.assertRaisesRegex(ValueError, "recovery-campaign-identity-invalid"):
                    coordinator._campaign_projection(Path("build/v02/campaign15/campaign.json"),
                        Path("evidence/v02-execution.json"), expected_sha256=pin,
                        require_return=False)
                future = start + datetime.timedelta(days=2)
                changed = dict(record)
                changed.update(started_at=future.isoformat(),
                    runtime_cutoff=(future + datetime.timedelta(seconds=64800)).isoformat(),
                    package_cutoff=(future + datetime.timedelta(seconds=79200)).isoformat(),
                    global_cutoff=(future + datetime.timedelta(seconds=86400)).isoformat())
                changed["record_sha256"] = hashlib.sha256(json.dumps(
                    {key: value for key, value in changed.items() if key != "record_sha256"},
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                campaign_path.write_text(json.dumps(changed, sort_keys=True))
                future_pin = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
                with self.assertRaisesRegex(ValueError, "recovery-campaign-clock-invalid"):
                    coordinator._campaign_projection(Path("build/v02/campaign15/campaign.json"),
                        Path("evidence/v02-execution.json"), expected_sha256=future_pin,
                        require_return=False)

    def test_campaign_resume_requires_prior_review_security_and_prechild_rejection(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(coordinator, "ROOT", Path(temporary)):
            root = Path(temporary)
            phase = root / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
            phase.mkdir(parents=True)
            paths = {
                "prior_review_path": ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PRESTART-REVIEW.md",
                "prior_security_path": ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PRESTART-SECURITY.md",
                "rejection_path": ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-PRESTART-REJECTION.md",
            }
            old_packet, campaign_sha, started = "a" * 64, "b" * 64, "2026-10-30T16:50:39.837827+00:00"
            contents = {
                "prior_review_path": f"Independent review: ACCEPTED\npacket_sha256: {old_packet}\n",
                "prior_security_path": f"Independent source-level diagnostic eligibility: ACCEPTED\npacket_sha256: {old_packet}\n",
                "rejection_path": f"initial packet SHA-256: `{old_packet}`\ncampaign SHA-256 after rejection: `{campaign_sha}`\npersisted started_at: `{started}`\nrecovery-campaign-scope-policy-mismatch\nbefore any controller/owner/leaf child start\n",
            }
            resume = {"schema": "genewhip.phase7-return-campaign-resume.v1",
                "campaign_sha256": campaign_sha, "campaign_started_at": started,
                "original_admission_sha256": old_packet,
                "rejection_code": "recovery-campaign-scope-policy-mismatch"}
            for key, relative in paths.items():
                (root / relative).write_text(contents[key])
                resume[key] = relative
                resume[key.replace("_path", "_sha256")] = hashlib.sha256(contents[key].encode()).hexdigest()
            admission = {"resume_campaign": resume}
            campaign = {"started_at": started, "admission_sha256": old_packet}
            self.assertTrue(coordinator._validate_campaign_resume(admission, campaign,
                campaign_sha, "c" * 64))
            resume["rejection_sha256"] = "0" * 64
            self.assertFalse(coordinator._validate_campaign_resume(admission, campaign,
                campaign_sha, "c" * 64))

    def test_entry_check_routes_existing_campaign_through_readonly_resume_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build/v02/campaign15").mkdir(parents=True)
            (root / "build/v02/campaign15/campaign.json").write_text("{}\n")
            recovery = root / "build/v02/recovery15"
            recovery.mkdir(parents=True)
            (recovery / ".limits.lock").write_bytes(b"")
            with mock.patch.object(probe, "ROOT", root), \
                 mock.patch.object(probe, "validate_packet_for_entry", return_value=({}, Path("review"))), \
                 mock.patch.object(probe, "validate_prechild_resume_state", return_value=({}, "a" * 64)) as resume:
                result = probe.main(["--entry-check", "--packet", "admission.json"])
            self.assertEqual(result, 0)
            resume.assert_called_once_with(root / "build/v02/campaign15/campaign.json", {})

    def test_final_attempt_rejects_missing_persisted_campaign_before_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build/v02/campaign15").mkdir(parents=True)
            (root / "scripts/release").mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/release/v02_qualification.py",
                root / "scripts/release/v02_qualification.py")
            packet = {"resume_campaign": {"attempt_number": 3}}
            with mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(probe, "ROOT", root), \
                 mock.patch.object(probe, "validate_packet_for_entry", return_value=(packet, Path("review"))), \
                 mock.patch.object(probe, "create_campaign") as create:
                with self.assertRaisesRegex(ValueError, "return-campaign-required-for-corrected-attempt"):
                    probe.run_selected(Path("packet.json"), Path("build/v02/campaign15/campaign.json"),
                        Path("build/v02/recovery15/live.json"))
                create.assert_not_called()
            self.assertFalse((root / "build/v02/campaign15/attempt3-started.json").exists())
            self.assertFalse((root / "build/v02/recovery15").exists())

    def test_attempt3_rejects_reentry_and_unrecognized_attempt_selector(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign_root = root / "build/v02/campaign15"
            campaign_root.mkdir(parents=True)
            campaign = campaign_root / "campaign.json"
            campaign.write_text("{}")
            (campaign_root / "attempt3-started.json").write_text("consumed")
            with mock.patch.object(probe, "ROOT", root), \
                 mock.patch.object(probe, "packet_and_review",
                    return_value=({"resume_campaign": {"attempt_number": 3}}, Path("review"))):
                with self.assertRaisesRegex(ValueError, "return-final-invocation-already-consumed"):
                    probe.validate_prechild_resume_state(campaign)
            packet = {"resume_campaign": {"attempt_number": 5}}
            with mock.patch.object(probe, "ROOT", root), \
                 mock.patch.object(probe, "validate_packet_for_entry", return_value=(packet, Path("review"))), \
                 mock.patch.object(probe, "require_clean_host_environment"):
                with self.assertRaisesRegex(ValueError, "return-corrected-attempt-selector-invalid"):
                    probe.run_selected(Path("packet.json"), Path("build/v02/campaign15/campaign.json"),
                        Path("build/v02/recovery15/live.json"))
            self.assertFalse((root / "build/v02/recovery15").exists())

    def test_owner_binds_packet_digest_before_wrapper_result_receipts(self):
        tree = ast.parse((ROOT / "tests/evidence/phase7_wrapper_return.py").read_text())
        owner_fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == "owner")
        bindings = [node for node in ast.walk(owner_fn) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "packet_sha"
                for target in node.targets)]
        self.assertTrue(any(isinstance(node.value, ast.Subscript)
            and isinstance(node.value.value, ast.Name) and node.value.value.id == "packet"
            and isinstance(node.value.slice, ast.Constant)
            and node.value.slice.value == "packet_sha256" for node in bindings),
            "owner must bind packet_sha from its validated packet before writing wrapper receipts")

    def test_owner_runs_both_real_wrappers_and_writes_packet_bound_receipts(self):
        packet_source = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ADMISSION.json"
        scope_source = ROOT / "evidence/v02-execution.json"

        class FakeProcess:
            next_pid = 980000
            def __init__(self, argv, **kwargs):
                self.argv = argv
                self.pid = FakeProcess.next_pid
                FakeProcess.next_pid += 1
                self.returncode = 0
                self.stdout = None
                self.stderr = None
                for stream in ("stdout", "stderr"):
                    if kwargs.get(stream) == subprocess.PIPE:
                        read_fd, write_fd = os.pipe()
                        os.close(write_fd)
                        setattr(self, stream, os.fdopen(read_fd, "rb", buffering=0))
            def poll(self): return self.returncode
            def wait(self, timeout=None): return self.returncode
            def kill(self): self.returncode = -9
            def terminate(self): self.returncode = -15

        with tempfile.TemporaryDirectory(prefix="return-owner-both-", dir=ROOT / "build/v02") as temporary:
            project = Path(temporary)
            packet_path = project / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ADMISSION.json"
            packet_path.parent.mkdir(parents=True)
            shutil.copy2(packet_source, packet_path)
            packet = json.loads(packet_path.read_bytes())
            packet["packet_sha256"] = hashlib.sha256(packet_path.read_bytes()).hexdigest()
            for relative in ("scripts/release/v02_qualification.py", "scripts/evidence/phase5_process.py",
                             "scripts/evidence/phase6_routes.py",
                             "tests/evidence/phase7_wrapper_return.py", "tests/fixtures/phase6_game.py",
                             "tests/session/phase6_route_contract.py",
                             "fixtures/phase6/media-expectations-v1.json"):
                destination = project / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            scope_path = project / "evidence/v02-execution.json"
            scope_path.parent.mkdir(parents=True)
            shutil.copy2(scope_source, scope_path)
            campaign_path = project / "build/v02/campaign15/campaign.json"
            campaign_path.parent.mkdir(parents=True)
            started = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30)
            campaign = {"schema": "genewhip.v02-recovery-campaign.v1", "status": "started",
                "campaign_id": "phase7-renewed-2026-10-30", "started_at": started.isoformat(),
                "scope_path": "evidence/v02-execution.json",
                "scope_sha256": hashlib.sha256(scope_path.read_bytes()).hexdigest(),
                "admission_sha256": packet["packet_sha256"],
                "journal_path": "build/v02/campaign15/hosted-delivery-journal.json",
                "runtime_cutoff": (started + datetime.timedelta(seconds=64800)).isoformat(),
                "package_cutoff": (started + datetime.timedelta(seconds=79200)).isoformat(),
                "global_cutoff": (started + datetime.timedelta(seconds=86400)).isoformat()}
            campaign["record_sha256"] = hashlib.sha256(json.dumps(campaign,
                sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            campaign_path.write_text(json.dumps(campaign, sort_keys=True, separators=(",", ":")))
            campaign_sha = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
            roots = {1: project / "build/v02/recovery15/case-1",
                     2: project / "build/v02/recovery15/case-2"}
            (project / "build/v02/recovery15").mkdir(parents=True)
            (project / "build/v02/recovery15/.limits.lock").write_bytes(b"")
            for case_index, case in ((1, "shared_launch"), (2, "bounded_command")):
                root = roots[case_index]
                root.mkdir()
                nonce = ("a" if case_index == 1 else "b") * 64
                probe.write_record(root / "release-A.json", {"pid": os.getpid(),
                    "scope_id": probe.SCOPE_ID, "case": case,
                    "controller_pid": os.getppid(), "controller_nonce": nonce,
                    "packet_sha256": packet["packet_sha256"],
                    "campaign_sha256": campaign_sha})
            with mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}, clear=True), \
                 mock.patch.object(probe, "ROOT", project), \
                 mock.patch.object(probe, "case_root", side_effect=lambda index: roots[index]), \
                 mock.patch.object(probe, "validate_packet_for_entry", return_value=(packet, Path("review"))), \
                 mock.patch.object(subprocess, "Popen", FakeProcess), \
                 mock.patch("os.killpg", side_effect=ProcessLookupError):
                for case_index, case in ((1, "shared_launch"), (2, "bounded_command")):
                    root = roots[case_index]
                    nonce = ("a" if case_index == 1 else "b") * 64
                    self.assertEqual(probe.owner(case, root, controller_pid=os.getppid(),
                        controller_nonce=nonce, packet_path=packet_path,
                        campaign_path=campaign_path, campaign_sha256=campaign_sha), 0)
                    wrapper = json.loads((root / "owner-work/wrapper-result.json").read_bytes())
                    counts = json.loads((root / "owner-process-count.json").read_bytes())
                    self.assertEqual(wrapper["wrapper"], case if case == "shared_launch" else "_bounded_command")
                    self.assertEqual(wrapper["packet_sha256"], packet["packet_sha256"])
                    self.assertEqual(wrapper["campaign_sha256"], campaign_sha)
                    self.assertEqual(wrapper["case"], case)
                    self.assertEqual(wrapper["returncode"], 0)
                    self.assertEqual(counts["wrapper_calls"], 1)
                    self.assertGreater(counts["starts"], 0)
                    self.assertGreater(counts["status_helper_starts"], 0)
                    self.assertGreater(counts["rss_observations"], 0)

    def test_campaign_projection_accepts_current_return_for_reviewed_packet_successor(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(coordinator, "ROOT", Path(temporary)), mock.patch.dict(os.environ):
            root = Path(temporary)
            phase = root / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery"
            phase.mkdir(parents=True)
            scope = {"qualification_batch": {"wall_seconds": 86400,
                "runtime_wall_seconds": 64800, "package_wall_seconds": 14400,
                "close_wall_seconds": 7200, "publication_reserve_seconds": 7200,
                "benchmark_sub_batch_seconds": 43200}}
            scope_path = root / "evidence/v02-execution.json"
            scope_path.parent.mkdir(parents=True)
            scope_path.write_text(json.dumps(scope, sort_keys=True))
            started_dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=60)
            started = started_dt.isoformat()
            original_packet = "a" * 64
            campaign = {"schema": "genewhip.v02-recovery-campaign.v1", "status": "started",
                "campaign_id": "phase7-renewed-2026-10-30", "started_at": started,
                "runtime_cutoff": (started_dt + datetime.timedelta(seconds=64800)).isoformat(),
                "package_cutoff": (started_dt + datetime.timedelta(seconds=79200)).isoformat(),
                "global_cutoff": (started_dt + datetime.timedelta(seconds=86400)).isoformat(),
                "scope_path": "evidence/v02-execution.json",
                "scope_sha256": hashlib.sha256(scope_path.read_bytes()).hexdigest(),
                "admission_sha256": original_packet,
                "journal_path": "build/v02/campaign15/hosted-delivery-journal.json"}
            campaign["record_sha256"] = hashlib.sha256(json.dumps(campaign,
                sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            campaign_path = root / "build/v02/campaign15/campaign.json"
            campaign_path.parent.mkdir(parents=True)
            campaign_path.write_text(json.dumps(campaign, sort_keys=True))
            campaign_sha = hashlib.sha256(campaign_path.read_bytes()).hexdigest()

            source_files = ["scripts/release/v02_qualification.py",
                "tests/evidence/phase7_wrapper_return.py",
                "tests/evidence/phase7_wrapper_return_contract.py"]
            sources = {}
            for relative in source_files:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative + "\n")
                sources[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            protocol_path = phase / "07-15-PROTOCOL.md"
            protocol_path.write_text("reviewed protocol\n")
            protocol_sha = hashlib.sha256(protocol_path.read_bytes()).hexdigest()
            old_review_path = phase / "07-15-PRESTART-REVIEW.md"
            old_review_path.write_text(f"Independent review: ACCEPTED\npacket_sha256: {original_packet}\n")
            old_security_path = phase / "07-15-PRESTART-SECURITY.md"
            old_security_path.write_text(f"Independent source-level diagnostic eligibility: ACCEPTED\npacket_sha256: {original_packet}\n")
            rejection_path = phase / "07-15-PRESTART-REJECTION.md"
            rejection_path.write_text(f"initial packet SHA-256: `{original_packet}`\ncampaign SHA-256 after rejection: `{campaign_sha}`\npersisted started_at: `{started}`\nrecovery-campaign-scope-policy-mismatch\nbefore any controller/owner/leaf child start\n")
            resume = {"schema": "genewhip.phase7-return-campaign-resume.v1",
                "campaign_sha256": campaign_sha, "campaign_started_at": started,
                "original_admission_sha256": original_packet,
                "prior_review_path": str(old_review_path.relative_to(root)),
                "prior_review_sha256": hashlib.sha256(old_review_path.read_bytes()).hexdigest(),
                "prior_security_path": str(old_security_path.relative_to(root)),
                "prior_security_sha256": hashlib.sha256(old_security_path.read_bytes()).hexdigest(),
                "rejection_path": str(rejection_path.relative_to(root)),
                "rejection_sha256": hashlib.sha256(rejection_path.read_bytes()).hexdigest(),
                "rejection_code": "recovery-campaign-scope-policy-mismatch"}
            admission = {"schema": "genewhip.phase7-wrapper-return-admission.v1",
                "status": "candidate", "sources": sources, "protocol_sha256": protocol_sha,
                "interpreter": {"executable": sys.executable,
                    "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                    "version": sys.version, "platform": {"system": probe.platform.system(),
                        "release": probe.platform.release(), "machine": probe.platform.machine()}},
                "resume_campaign": resume}
            admission_path = phase / "07-15-ADMISSION.json"
            admission_path.write_text(json.dumps(admission, sort_keys=True))
            admission_sha = hashlib.sha256(admission_path.read_bytes()).hexdigest()
            source_review_path = phase / "07-15-REVIEW.md"
            source_review_path.write_text(f"Independent review: ACCEPTED\nreviewer_role: gsd-code-reviewer\nreviewer_model: gpt-6-luna\nauthor_role: gsd-executor\nsource-review: current-source-and-packet\nunresolved high/critical: 0\npacket_sha256: {admission_sha}\nprotocol_sha256: {protocol_sha}\n")
            source_review_sha = hashlib.sha256(source_review_path.read_bytes()).hexdigest()
            pin_map_sha = hashlib.sha256(json.dumps(sources, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            security_path = phase / "07-15-SECURITY.md"
            security_path.write_text(f"Independent security disposition: ACCEPTED\nreviewer_role: gsd-security-auditor\nreviewer_model: gpt-6.1-sol\nunresolved current high/critical: 0\npacket_sha256: {admission_sha}\nsource_pins_sha256: {pin_map_sha}\nresidual T-07-07: nonblocking\nhistorical identity/liveness: UNKNOWN\n")
            security_sha = hashlib.sha256(security_path.read_bytes()).hexdigest()
            live_path = root / "build/v02/recovery15/live.json"
            live_path.parent.mkdir(parents=True)
            live = {"status": "pass", "campaign_sha256": campaign_sha,
                "packet_sha256": admission_sha, "review_sha256": source_review_sha,
                "source_pins": sources}
            live_path.write_text(json.dumps(live, sort_keys=True))
            live_sha = hashlib.sha256(live_path.read_bytes()).hexdigest()
            common = (f"campaign_sha256: {campaign_sha}\nlive_sha256: {live_sha}\n"
                f"packet_sha256: {admission_sha}\nsource_pins_sha256: {pin_map_sha}\n"
                f"source_review_sha256: {source_review_sha}\nsecurity_sha256: {security_sha}\n")
            (phase / "07-15-RETURN.md").write_text("status: accepted\n" + common + "requirements_qualified: []\n")
            (phase / "07-15-RETURN-REVIEW.md").write_text("Independent review: ACCEPTED\nreviewer_role: gsd-code-reviewer\nreviewer_model: gpt-6-luna\nunresolved high/critical: 0\n" + common)
            before = campaign_path.read_bytes()
            accepted = coordinator._campaign_projection(Path("build/v02/campaign15/campaign.json"),
                Path("evidence/v02-execution.json"), Path(campaign["journal_path"]),
                phase="runtime", expected_sha256=campaign_sha, require_return=True)
            self.assertEqual(accepted["started_at"], started)
            self.assertEqual(campaign_path.read_bytes(), before)

    def test_campaign_env_clock_must_match_reopened_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evidence").mkdir()
            (root / "build/v02/campaign15").mkdir(parents=True)
            scope_path = root / "evidence/v02-execution.json"
            scope_path.write_text(json.dumps({"qualification_batch": {
                "wall_seconds": 86400, "runtime_wall_seconds": 64800,
                "package_wall_seconds": 14400, "close_wall_seconds": 7200}}))
            scope_sha = hashlib.sha256(scope_path.read_bytes()).hexdigest()
            admission_sha = create_admission_fixture(root)
            start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
            record = {"schema": "genewhip.v02-recovery-campaign.v1", "status": "started",
                "campaign_id": "phase7-renewed-2026-10-30", "started_at": start.isoformat(),
                "scope_path": "evidence/v02-execution.json", "scope_sha256": scope_sha,
                "admission_sha256": admission_sha,
                "journal_path": "build/v02/campaign15/hosted-delivery-journal.json",
                "runtime_cutoff": (start + datetime.timedelta(seconds=64800)).isoformat(),
                "package_cutoff": (start + datetime.timedelta(seconds=79200)).isoformat(),
                "global_cutoff": (start + datetime.timedelta(seconds=86400)).isoformat()}
            record["record_sha256"] = hashlib.sha256(json.dumps(record, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            campaign = root / "build/v02/campaign15/campaign.json"
            campaign.write_text(json.dumps(record, sort_keys=True))
            pin = hashlib.sha256(campaign.read_bytes()).hexdigest()
            with mock.patch.object(coordinator, "ROOT", root), mock.patch.dict(os.environ,
                    {"GENEWHIP_QUALIFICATION_STARTED_AT": "2026-10-30T00:00:00+00:00"}):
                with self.assertRaisesRegex(ValueError, "recovery-campaign-environment-clock-conflict"):
                    coordinator._campaign_projection(Path("build/v02/campaign15/campaign.json"),
                        Path("evidence/v02-execution.json"), expected_sha256=pin)

    def test_budget_partition_equalities_reject(self):
        scope = {"qualification_batch": {"wall_seconds": 86400,
            "runtime_wall_seconds": 64800, "package_wall_seconds": 14400,
            "close_wall_seconds": 7200}}
        start = datetime.datetime(2026, 10, 30, tzinfo=datetime.timezone.utc)
        for offset, phase, reason in ((64800, "runtime", "qualification-runtime-partition-deadline-exhausted"),
                                      (79200, "package", "qualification-package-partition-deadline-exhausted"),
                                      (86400, "close", "qualification-common-cutoff-exhausted")):
            with self.subTest(offset=offset):
                now = (start + datetime.timedelta(seconds=offset)).isoformat()
                with self.assertRaisesRegex(ValueError, reason):
                    coordinator._require_hosted_budget(start.isoformat(), now, scope, phase=phase)


class ActualWrapperTracer(unittest.TestCase):
    def test_both_actual_wrappers_reach_shared_helper_and_receipt_accounting(self):
        fixture = load("tests/fixtures/phase6_game.py", "return_phase6_fixture")
        sequence = []
        owned_callbacks = []
        class FakeProcess:
            next_pid = 910000
            last_subject_pid = None
            live_status = False
            def __init__(self, argv, **kwargs):
                self.argv = argv
                self.pid = FakeProcess.next_pid
                FakeProcess.next_pid += 1
                self.returncode = 0
                self.stdout = None
                if kwargs.get("stdout") == subprocess.PIPE:
                    read, write = os.pipe()
                    if str(argv[0]) == "/bin/ps" and FakeProcess.live_status:
                        os.write(write, f"{FakeProcess.last_subject_pid} S\n".encode())
                    os.close(write)
                    self.stdout = os.fdopen(read, "rb", buffering=0)
                if kwargs.get("stderr") == subprocess.PIPE:
                    read, write = os.pipe()
                    os.close(write)
                    self.stderr = os.fdopen(read, "rb", buffering=0)
                sequence.append({"argv0": str(argv[0]), "pid": self.pid})
                if str(argv[0]) != "/bin/ps":
                    FakeProcess.last_subject_pid = self.pid
            def poll(self): return self.returncode
            def wait(self, timeout=None): return self.returncode
            def kill(self): self.returncode = -9
            def terminate(self): self.returncode = -15
        scope = dict(probe.SCOPE)
        previous_context = os.environ.get("GENEWHIP_PROCESS_CONTEXT")
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
        fixture.set_execution_scope(scope)
        try:
            with tempfile.TemporaryDirectory(prefix="return-denied-", dir=ROOT / "build/v02") as temporary:
                area = Path(temporary)
                work1 = area / "shared-work"
                work1.mkdir()
                with mock.patch.object(subprocess, "Popen", side_effect=FakeProcess), \
                     mock.patch("os.killpg", side_effect=ProcessLookupError):
                    result, receipt, streams = fixture.shared_launch(Path(sys.executable),
                        [sys.executable, "-I", str(Path(__file__).resolve()), "--leaf", str(area)],
                        work1, work1 / "report.json", 20, plan_id="GW-07-15")
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(receipt.get("process_group_cleanup"), "confirmed")
                    persisted = list((work1 / "process-receipts").glob("*.json"))
                    self.assertEqual(len(persisted), 1)
                    self.assertEqual(json.loads(persisted[0].read_bytes())["processes"][0]["pid"], receipt["pid"])
                    uncertain = work1 / "uncertain-work"
                    uncertain.mkdir()
                    FakeProcess.live_status = True
                    with mock.patch.object(subprocess, "Popen", side_effect=FakeProcess), \
                         mock.patch("os.killpg", side_effect=PermissionError("synthetic denied signal")):
                        try:
                            bad_result = fixture.shared_launch(Path(sys.executable), [sys.executable], uncertain,
                                uncertain / "report.json", 20, plan_id="GW-07-15")
                        except RuntimeError as error:
                            self.assertTrue("phase7-shared-child-cleanup-unconfirmed" in str(error)
                                or "bounded child process group remains live" in str(error))
                        else:
                            self.fail("shared_launch accepted uncertain cleanup: " + repr(bad_result[1]))
                    FakeProcess.live_status = False
                    uncertain_receipts = list((uncertain / "process-receipts").glob("*.json"))
                    self.assertEqual(len(uncertain_receipts), 1)
                    uncertain_row = json.loads(uncertain_receipts[0].read_bytes())["processes"][0]
                    self.assertEqual(uncertain_row["process_group_cleanup"], "unconfirmed")
                    work2 = area / "coordinator-work"
                    attempt = coordinator._bounded_command([sys.executable, "-I", str(Path(__file__).resolve())],
                        limits=dict(probe.SCOPE["per_child_limits"]), scratch=work2,
                        timeout=20, label="bounded-return", env=dict(os.environ), cwd=ROOT,
                        scratch_roots=(work2,), ownership_callback=lambda row: owned_callbacks.append(
                            {"pid": row.get("pid"), "group": row.get("pgid")}))
                    self.assertEqual(attempt["returncode"], 0)
                    self.assertEqual(attempt["process_group_cleanup"], "confirmed")
                    self.assertEqual(len(attempt["processes"]), 1)
                    self.assertEqual(attempt["processes"][0]["pgid"], attempt["processes"][0]["pid"])
                    self.assertEqual(owned_callbacks[-1]["pid"], attempt["processes"][0]["pid"])
                    self.assertEqual(owned_callbacks[-1]["group"], attempt["processes"][0]["pgid"])
                subjects = [row for row in sequence if row["argv0"] == sys.executable]
                status_helpers = [row for row in sequence if row["argv0"] == "/bin/ps"]
                self.assertEqual(len(subjects), 3)
                self.assertGreaterEqual(len(status_helpers), 2)
                self.assertEqual(denial.receipt()["unexpected_denials"], 0)
        finally:
            fixture.set_execution_scope(None)
            if previous_context is None:
                os.environ.pop("GENEWHIP_PROCESS_CONTEXT", None)
            else:
                os.environ["GENEWHIP_PROCESS_CONTEXT"] = previous_context


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--tracer", action="store_true")
    parser.add_argument("--contracts", action="store_true")
    parser.add_argument("--entry-check", action="store_true")
    parser.add_argument("--packet", type=Path)
    parser.add_argument("--verify-live", action="store_true")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--review-check", action="store_true")
    parser.add_argument("--return-check", action="store_true")
    parser.add_argument("--red-hosted-baseline", action="store_true")
    args = parser.parse_args(argv)
    if args.entry_check:
        if args.packet is None:
            print("REJECT: return-packet-required")
            return 1
        return probe.main(["--entry-check", "--packet", str(args.packet)])
    if args.verify_live:
        if args.evidence is None:
            print("REJECT: return-live-evidence-required")
            return 1
        return probe.main(["--verify-live", "--evidence", str(args.evidence)])
    if args.review_check:
        try:
            packet_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ADMISSION.json"
            packet, review_path = probe.packet_and_review(packet_path)
            review = review_path.read_text(encoding="utf-8")
            digest = hashlib.sha256(packet_path.read_bytes()).hexdigest()
            if (f"packet_sha256: {digest}" not in review
                    or f"protocol_sha256: {packet['protocol_sha256']}" not in review
                    or "reviewer_role: gsd-code-reviewer" not in review
                    or "reviewer_model: gpt-6-luna" not in review
                    or "author_role: gsd-executor" not in review
                    or "unresolved high/critical: 0" not in review):
                raise ValueError("return-independent-source-review-incomplete")
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            print("REJECT: " + str(error), file=sys.stderr)
            return 1
        print("phase7-wrapper-return: independent source/admission review accepted")
        return 0
    if args.return_check:
        try:
            live = ROOT / "build/v02/recovery15/live.json"
            probe.verify_live(live)
            security = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-SECURITY.md"
            returned = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-RETURN.md"
            review = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-RETURN-REVIEW.md"
            for item in (security, returned, review):
                if item.is_symlink() or not item.is_file() or item.stat().st_size > 65536:
                    raise ValueError("return-current-artifact-missing-or-invalid")
            security_text = security.read_text(encoding="utf-8")
            return_text = returned.read_text(encoding="utf-8")
            review_text = review.read_text(encoding="utf-8")
            campaign = ROOT / "build/v02/campaign15/campaign.json"
            campaign_sha = hashlib.sha256(campaign.read_bytes()).hexdigest()
            live_sha = hashlib.sha256(live.read_bytes()).hexdigest()
            admission_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-ADMISSION.json"
            admission = probe.safe_json(admission_path)
            packet_sha = hashlib.sha256(admission_path.read_bytes()).hexdigest()
            source_pins_sha = hashlib.sha256(json.dumps(admission["sources"], sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            source_review = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-15-REVIEW.md"
            campaign_record = probe.safe_json(campaign)
            coordinator._campaign_projection(campaign, ROOT / "evidence/v02-execution.json",
                ROOT / campaign_record["journal_path"], phase="runtime",
                expected_sha256=campaign_sha, require_return=True)
            if ("status: accepted" not in return_text
                    or f"campaign_sha256: {campaign_sha}" not in return_text
                    or f"live_sha256: {live_sha}" not in return_text
                    or f"packet_sha256: {packet_sha}" not in return_text
                    or f"source_pins_sha256: {source_pins_sha}" not in return_text
                    or f"source_review_sha256: {hashlib.sha256(source_review.read_bytes()).hexdigest()}" not in return_text
                    or f"security_sha256: {hashlib.sha256(security.read_bytes()).hexdigest()}" not in return_text
                    or f"source_pins_sha256: {source_pins_sha}" not in review_text
                    or f"packet_sha256: {packet_sha}" not in review_text
                    or f"source_review_sha256: {hashlib.sha256(source_review.read_bytes()).hexdigest()}" not in review_text
                    or f"security_sha256: {hashlib.sha256(security.read_bytes()).hexdigest()}" not in review_text
                    or "Independent review: ACCEPTED" not in review_text
                    or "reviewer_role: gsd-code-reviewer" not in review_text
                    or "reviewer_model: gpt-6-luna" not in review_text
                    or "unresolved high/critical: 0" not in review_text
                    or "residual T-07-07: nonblocking" not in security_text
                    or "reviewer_role: gsd-security-auditor" not in security_text
                    or "reviewer_model: gpt-6.1-sol" not in security_text
                    or "Independent security disposition: ACCEPTED" not in security_text
                    or "unresolved current high/critical: 0" not in security_text
                    or "historical identity/liveness: UNKNOWN" not in security_text
                    or "requirements_qualified: []" not in return_text):
                raise ValueError("return-current-conjunction-rejected")
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            print("REJECT: " + str(error), file=sys.stderr)
            return 1
        print("phase7-wrapper-return: exact current return gate accepted")
        return 0
    if args.red_hosted_baseline:
        baseline = os.environ.get("GENEWHIP_TDD_BASELINE")
        if not baseline:
            parser.error("GENEWHIP_TDD_BASELINE must name the captured pre-fix coordinator")
        spec = importlib.util.spec_from_file_location("return_coordinator_baseline", baseline)
        coordinator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(coordinator)
        globals()["coordinator"] = coordinator
        selected = unittest.defaultTestLoader.loadTestsFromName(
            "ReturnContracts.test_hosted_cli_threads_selected_journal", sys.modules[__name__])
        result = unittest.TextTestRunner(verbosity=2).run(selected)
        return 0 if result.wasSuccessful() else 1
    if not args.tracer and not args.contracts:
        parser.error("select --tracer or --contracts")
    selected = (unittest.defaultTestLoader.loadTestsFromTestCase(ActualWrapperTracer)
                if args.tracer else unittest.defaultTestLoader.loadTestsFromTestCase(ReturnContracts))
    suite = selected
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if denial.receipt()["unexpected_denials"] != 0:
        print("unexpected-denied-effect", flush=True)
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
