#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation contracts for the bounded actual-module callback route report."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/evidence/libretro_route.py"
SPEC = importlib.util.spec_from_file_location("gw_libretro_route", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("route evidence module is unavailable")
route = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(route)


def load_report(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > route.MAX_REPORT_BYTES:
        raise ValueError("report-size")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("report-json")
    return value


class LibretroRouteContract(unittest.TestCase):
    report: dict
    library: Path

    def validate(self, value: dict) -> str:
        return route.validate_report(value, library_path=self.library)

    def test_actual_local_report_is_bounded_and_route_observations_pass(self):
        self.assertEqual(self.validate(self.report), "ok")
        self.assertEqual(self.report["route_status"], "pass")
        self.assertEqual(self.report["status"], "unknown")
        self.assertIn(self.report["reason"], {
            "working-tree-not-clean", "host-platform-not-linux-x86_64",
            "host-run-identity-incomplete"})
        self.assertEqual([row["id"] for row in self.report["cases"]],
                         ["title-no-start", "start-idle", "start-move"])

    def test_unknown_report_can_explain_missing_toolchain_identity(self):
        changed = copy.deepcopy(self.report)
        changed["reason"] = "toolchain-identity-incomplete"
        changed["toolchain"] = {key: "unknown" for key in changed["toolchain"]}
        self.assertEqual(self.validate(changed), "ok")

    def test_fixture_and_library_identity_mutations_fail(self):
        changed = copy.deepcopy(self.report)
        changed["rom_sha256"] = "0" * 64
        self.assertEqual(self.validate(changed), "fixture-identity")
        changed = copy.deepcopy(self.report)
        changed["fixture_source_sha256"] = "0" * 64
        self.assertEqual(self.validate(changed), "fixture-identity")
        changed = copy.deepcopy(self.report)
        changed["library_sha256"] = "0" * 64
        self.assertEqual(self.validate(changed), "library-identity")

    def test_expected_source_is_enforced_for_adopted_reports(self):
        self.assertEqual(route.validate_report(self.report, library_path=self.library,
                                               require_source=self.report["source_sha"]), "ok")
        self.assertEqual(route.validate_report(self.report, library_path=self.library,
                                               require_source="f" * 40), "required-source-mismatch")
        self.assertEqual(route.validate_report(self.report, library_path=self.library,
                                               require_hosted=True), "hosted-status-required")

    def test_expected_hosted_run_identity_is_enforced(self):
        hosted_report = copy.deepcopy(self.report)
        hosted_report.update({"run_id": "123456", "run_attempt": 1,
                              "event": "pull_request", "ref": "refs/pull/1/merge"})
        expected = {"require_run_id": hosted_report["run_id"],
                    "require_run_attempt": str(hosted_report["run_attempt"]),
                    "require_event": hosted_report["event"],
                    "require_ref": hosted_report["ref"]}
        self.assertEqual(route.validate_report(hosted_report, library_path=self.library,
                                               **expected), "ok")
        for field, value, code in (("require_run_id", "0", "required-run-id-mismatch"),
                                   ("require_run_attempt", "99", "required-run-attempt-mismatch"),
                                   ("require_event", "schedule", "required-event-mismatch"),
                                   ("require_ref", "refs/heads/other", "required-ref-mismatch")):
            with self.subTest(field=field):
                self.assertEqual(route.validate_report(hosted_report, library_path=self.library,
                                                       **(expected | {field: value})), code)

    def test_admission_evidence_digest_matches_manifest_and_rejects_substitution(self):
        expected = route.sha_file(ROOT / "evidence/independent-game-v2.json")
        self.assertEqual(self.report["admission_evidence_sha256"], expected)
        self.assertEqual(self.validate(self.report), "ok")
        changed = copy.deepcopy(self.report)
        changed["admission_evidence_sha256"] = "0" * 64
        self.assertEqual(self.validate(changed), "admission-evidence-identity")

    def test_missing_controls_and_swapped_schedules_fail(self):
        changed = copy.deepcopy(self.report)
        changed["cases"].pop(0)
        self.assertEqual(self.validate(changed), "route-controls")
        changed = copy.deepcopy(self.report)
        changed["cases"][1]["input_schedule"] = changed["cases"][2]["input_schedule"]
        self.assertEqual(self.validate(changed), "input-schedule")

    def test_false_marker_progress_and_title_control_fail(self):
        changed = copy.deepcopy(self.report)
        changed["marker_observations"]["moved_position"] = 0
        self.assertEqual(self.validate(changed), "route-marker-progress")
        changed = copy.deepcopy(self.report)
        changed["marker_observations"]["title_to_play_pixel_changed"] = False
        self.assertEqual(self.validate(changed), "route-marker-progress")

    def test_malformed_geometry_and_missing_callback_denominator_fail(self):
        changed = copy.deepcopy(self.report)
        changed["geometry"]["pitch"] = 1
        changed["pitch"] = 1
        self.assertEqual(self.validate(changed), "route-geometry")
        changed = copy.deepcopy(self.report)
        changed["callback_counts"]["video"] -= 1
        self.assertEqual(self.validate(changed), "route-callback-denominator")

    def test_private_fields_and_oversized_reports_fail(self):
        changed = copy.deepcopy(self.report)
        changed["runner"] = "/" + "Users" + "/private/runner"
        self.assertEqual(self.validate(changed), "report-private-field")
        changed = copy.deepcopy(self.report)
        changed["private_token"] = "credential-value"
        self.assertEqual(self.validate(changed), "report-fields")
        changed = copy.deepcopy(self.report)
        changed["ref"] = "/" + "Users" + "/private/repo"
        self.assertEqual(self.validate(changed), "report-private-field")
        changed = copy.deepcopy(self.report)
        changed["padding"] = "x" * route.MAX_REPORT_BYTES
        self.assertEqual(self.validate(changed), "report-size")


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[0] != "--report" or argv[2] != "--library":
        print("usage: libretro_route_contract.py --report FILE --library MODULE", file=sys.stderr)
        return 2
    try:
        LibretroRouteContract.report = load_report(Path(argv[1]))
        LibretroRouteContract.library = Path(argv[3])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print("BLOCKED: route report cannot be loaded", file=sys.stderr)
        return 1
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LibretroRouteContract)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
