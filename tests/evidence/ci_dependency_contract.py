#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep required hosted lanes bound to the pinned macOS/tool evidence inputs."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class CIDependencyContract(unittest.TestCase):
    def test_prepare_script_builds_each_locked_evidence_dependency(self):
        script = (ROOT / "scripts/ci/prepare_evidence_dependencies.sh").read_text()
        self.assertIn("bash scripts/fixtures/z80-as.sh", script)
        self.assertIn("bash scripts/fixtures/m68k-as.sh", script)
        self.assertIn("python3 tools/evidence/fm_compare/compare.py --fetch --build", script)

    def test_safety_and_desktop_provision_dependencies_before_ctest(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        safety = workflow.split("  safety:\n", 1)[1].split("  gameplay:\n", 1)[0]
        desktop = workflow.split("  desktop:\n", 1)[1].split("  package:\n", 1)[0]
        self.assertLess(safety.index("prepare_evidence_dependencies.sh"),
                        safety.index("scripts/ci/required-gate.sh"))
        self.assertLess(desktop.index("prepare_evidence_dependencies.sh"),
                        desktop.index("ctest --test-dir build/desktop"))

    def test_required_tests_and_packages_use_the_locked_native_host(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertGreaterEqual(workflow.count("runs-on: macos-26"), 7)
        self.assertNotIn("runs-on: macos-15", workflow)

    def test_native_gate_and_desktop_lane_reject_unapproved_skips(self):
        required = (ROOT / "scripts/ci/required-gate.sh").read_text()
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(required.count("scripts/ci/check_ctest_skips.py"), 2)
        self.assertEqual(required.count("--output-junit ctest-junit.xml"), 2)
        desktop = workflow.split("  desktop:\n", 1)[1].split("  package:\n", 1)[0]
        self.assertIn("scripts/ci/check_ctest_skips.py build/desktop/ctest-junit.xml", desktop)
        self.assertIn("--output-junit ctest-junit.xml", desktop)


if __name__ == "__main__":
    unittest.main(verbosity=2)
