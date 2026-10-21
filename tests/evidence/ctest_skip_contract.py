#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Only the two admitted v1 executable-identity unknowns may skip in CTest."""
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_ctest_skips", ROOT / "scripts/ci/check_ctest_skips.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CTestSkipContract(unittest.TestCase):
    def write(self, skipped):
        body = "".join(
            '<testcase name="%s" classname="suite">%s</testcase>' %
            (name, "<skipped/>" if is_skipped else "")
            for name, is_skipped in skipped)
        path = pathlib.Path(self.tmp.name, "ctest.xml")
        path.write_text("<testsuites><testsuite tests=\"%d\">%s</testsuite></testsuites>" %
                        (len(skipped), body))
        return path

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_exact_v1_identity_unknown_skips_are_permitted(self):
        path = self.write([("independent_game_admission", True),
                           ("independent_game_consumer", True),
                           ("safety_contract", False)])
        self.assertEqual(MODULE.unexpected_skips(path), [])

    def test_any_new_skip_fails(self):
        path = self.write([("z80_toolchain", True)])
        self.assertEqual(MODULE.unexpected_skips(path), ["z80_toolchain"])

    def test_opt_in_live_row_cannot_hide_as_a_skip(self):
        path = self.write([("runner_live_audio", True)])
        self.assertEqual(MODULE.unexpected_skips(path), ["runner_live_audio"])

    def test_unskipped_legacy_tests_are_still_valid(self):
        path = self.write([("independent_game_admission", False),
                           ("independent_game_consumer", False)])
        self.assertEqual(MODULE.unexpected_skips(path), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
