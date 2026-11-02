#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded shell contracts for CI stage timing and failure propagation."""
from __future__ import annotations

import subprocess
import unittest


class TimingContract(unittest.TestCase):
    def run_shell(self, script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["/bin/bash", "-c", script], text=True, capture_output=True,
            timeout=5, check=False)

    def test_success_emits_fixed_stage_label_and_elapsed_time(self):
        result = self.run_shell("set -euo pipefail; TIMEFORMAT='ci-stage fixture-success %3R seconds'; time true")
        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stderr, r"ci-stage fixture-success [0-9]+\.[0-9]{3} seconds")

    def test_failure_keeps_status_and_stops_following_stages(self):
        result = self.run_shell("set -euo pipefail; TIMEFORMAT='ci-stage fixture-failure %3R seconds'; if { time bash -c 'exit 23'; }; then status=0; else status=$?; fi; exit \"$status\"; printf 'continued\\n'")
        self.assertEqual(result.returncode, 23)
        self.assertIn("ci-stage fixture-failure", result.stderr)
        self.assertNotIn("continued", result.stdout)

    def test_pipefail_survives_timed_pipeline(self):
        result = self.run_shell("set -euo pipefail; TIMEFORMAT='ci-stage fixture-pipeline %3R seconds'; if { time bash -c 'exit 19' | cat; }; then status=0; else status=$?; fi; exit \"$status\"; printf 'continued\\n'")
        self.assertEqual(result.returncode, 19)
        self.assertIn("ci-stage fixture-pipeline", result.stderr)
        self.assertNotIn("continued", result.stdout)



if __name__ == "__main__":
    unittest.main(verbosity=2)
