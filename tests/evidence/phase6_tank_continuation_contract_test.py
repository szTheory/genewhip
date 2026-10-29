#!/usr/bin/env python3
"""TDD gate for the independent no-launch continuation proof checker."""
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tests/evidence/phase6_tank_continuation_contract.py"


class ContinuationCheckerContract(unittest.TestCase):
    def test_self_test_command_is_available_and_passes_offline_mutants(self):
        result = subprocess.run([sys.executable, "-I", str(CHECKER), "--self-test"],
                                cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
