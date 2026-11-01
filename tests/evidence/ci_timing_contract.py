#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded shell contracts for CI stage timing and failure propagation."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
import re


class TimingContract(unittest.TestCase):
    def run_shell(self, script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", "-c", script], text=True, capture_output=True,
            timeout=5, check=False)

    def test_success_emits_fixed_stage_label_and_elapsed_time(self):
        result = self.run_shell("set -euo pipefail; TIMEFORMAT='ci-stage fixture-success %3R seconds'; time true")
        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stderr, r"ci-stage fixture-success [0-9]+\.[0-9]{3} seconds")

    def test_failure_keeps_status_and_stops_following_stages(self):
        result = self.run_shell("set -euo pipefail; TIMEFORMAT='ci-stage fixture-failure %3R seconds'; time bash -c 'exit 23'; printf 'continued\\n'")
        self.assertEqual(result.returncode, 23)
        self.assertIn("ci-stage fixture-failure", result.stderr)
        self.assertNotIn("continued", result.stdout)

    def test_pipefail_survives_timed_pipeline(self):
        result = self.run_shell("set -euo pipefail; TIMEFORMAT='ci-stage fixture-pipeline %3R seconds'; time bash -c 'exit 19' | cat; printf 'continued\\n'")
        self.assertEqual(result.returncode, 19)
        self.assertIn("ci-stage fixture-pipeline", result.stderr)
        self.assertNotIn("continued", result.stdout)

    def test_production_ctest_helper_times_and_preserves_failure_processing(self):
        source = (Path(__file__).resolve().parents[2] / "scripts/ci/required-gate.sh").read_text()
        match = re.search(r"(?ms)^run_required_ctest\(\) \{\n(.*?)^\}", source)
        self.assertIsNotNone(match)
        helper = "run_required_ctest() {\n" + match.group(1) + "}\n"
        self.assertRegex(helper, r"(?m)^  if time ASAN_OPTIONS=detect_leaks=\$leaks UBSAN_OPTIONS=halt_on_error=1 \\\n    ctest ")
        script = """set -euo pipefail
""" + helper + """
ctest() {
  printf 'ctest-env ASAN=%s UBSAN=%s args=%s\\n' "$ASAN_OPTIONS" "$UBSAN_OPTIONS" "$*"
  [[ "$ASAN_OPTIONS" == detect_leaks=0 && "$UBSAN_OPTIONS" == halt_on_error=1 ]]
  return 23
}
python3() { printf 'python3-call %s\\n' "$*"; }
set +e
run_required_ctest native fixture-junit.xml 0
status=$?
set -e
printf 'helper-status=%s\\n' "$status"
[[ "$status" -eq 23 ]]
"""
        with tempfile.TemporaryDirectory(prefix="ci-timing-helper-") as temp:
            result = subprocess.run(["bash", "-c", script], cwd=temp, text=True,
                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stderr, r"ci-stage native-ctest [0-9]+\.[0-9]{3} seconds")
        self.assertIn("ctest-env ASAN=detect_leaks=0 UBSAN=halt_on_error=1", result.stdout)
        self.assertIn("safety-sanitize-junit", result.stdout)
        self.assertIn("check_ctest_skips.py", result.stdout)
        self.assertIn("helper-status=23", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
