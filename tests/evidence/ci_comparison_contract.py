#!/usr/bin/env python3
"""Contracts for conservative, source-bound CI comparisons."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.evidence import ci_comparison  # noqa: E402


def observation(run_id, attempt=1, *, event="pull_request", graph="a" * 64,
                workflow="b" * 64, runner="macos", critical=100.0,
                runner_seconds=500.0, conclusion="success", jobs=None):
    return {
        "run_id": run_id,
        "run_attempt": attempt,
        "event": event,
        "workflow_sha256": workflow,
        "graph_sha256": graph,
        "status": "completed",
        "conclusion": conclusion,
        "runner_os": [runner],
        "critical_path_seconds": critical,
        "runner_seconds_by_os": {runner: runner_seconds},
        "required_jobs": jobs or ["safety", "libretro", "required-aggregate"],
    }


class CiComparisonContract(unittest.TestCase):
    def test_empty_and_single_observations_never_establish_savings(self):
        self.assertEqual(ci_comparison.compare_summaries([], [])[
            "status"], "insufficient")
        result = ci_comparison.compare_summaries(
            [observation(1)], [observation(2)])
        self.assertEqual(result["status"], "insufficient")
        self.assertIsNone(result["critical_path_delta_seconds"])

    def test_equal_metrics_have_zero_delta(self):
        result = ci_comparison.compare_pair(observation(1), observation(2))
        self.assertEqual(result["status"], "comparable")
        self.assertEqual(result["critical_path_delta_seconds"], 0.0)
        self.assertEqual(result["runner_seconds_delta_by_os"], {"macos": 0.0})

    def test_stable_order_uses_run_id_then_attempt(self):
        rows = [observation(9, 1), observation(3, 2), observation(3, 1)]
        self.assertEqual([(row["run_id"], row["run_attempt"])
                          for row in ci_comparison.stable_order(rows)],
                         [(3, 1), (3, 2), (9, 1)])

    def test_mixed_event_graph_workflow_runner_or_required_roster_is_incomparable(self):
        before = observation(1)
        for after in (
            observation(2, event="push"),
            observation(2, graph="c" * 64),
            observation(2, workflow="d" * 64),
            observation(2, runner="linux"),
            observation(2, jobs=["safety", "required-aggregate"]),
        ):
            with self.subTest(after=after):
                self.assertEqual(ci_comparison.compare_pair(before, after)["status"],
                                 "incomparable")

    def test_missing_timing_stays_unknown(self):
        after = observation(2, critical=None, runner_seconds=None)
        result = ci_comparison.compare_pair(observation(1), after)
        self.assertEqual(result["status"], "comparable")
        self.assertIsNone(result["critical_path_delta_seconds"])
        self.assertEqual(result["runner_seconds_delta_by_os"], {})

    def test_failed_latest_attempt_blocks_credit_for_earlier_success(self):
        rows = [observation(4, 1), observation(4, 2, conclusion="failure")]
        latest = ci_comparison.latest_attempts(rows)
        self.assertEqual([(row["run_id"], row["run_attempt"])
                          for row in latest], [(4, 2)])
        self.assertEqual(ci_comparison.successful_observations(rows), [])

    def test_phase8_unknowns_are_preserved(self):
        phase8 = ci_comparison.phase8_baseline_summary()
        self.assertEqual(phase8["critical_path_seconds"], 901.0)
        self.assertIsNone(phase8["workflow_wall_seconds"])
        self.assertEqual(phase8["job_queue"], "unknown")
        self.assertEqual(phase8["public_standard_runner_billing"], "not_applicable")

    def test_build_and_validate_keep_no_change_and_release_identity_explicit(self):
        first_release = ci_comparison._first_release(ROOT / "evidence/phase9-release.json")
        entry, observations = ci_comparison._report_entry(
            ROOT / "evidence/phase8-ci-baseline.json")
        record = ci_comparison.build_comparison(
            before_reports=[(entry, observations)], after_reports=[],
            rejected_reports=[], first_release=first_release)
        self.assertEqual(ci_comparison.validate_comparison(
            record, first_release=first_release), [])
        self.assertEqual(record["decision"], "no-change")
        self.assertEqual(record["after"]["status"], "not_applicable")
        self.assertEqual(record["later_release"], "not_applicable")
        wrong_release = dict(first_release, source_sha="0" * 40)
        self.assertIn("comparison-first-release-mismatch",
                      ci_comparison.validate_comparison(record, first_release=wrong_release))


if __name__ == "__main__":
    unittest.main(verbosity=2)
