#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep required hosted lanes bound to the pinned macOS/tool evidence inputs."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class CIDependencyContract(unittest.TestCase):
    def test_prepare_script_builds_each_locked_evidence_dependency(self):
        script = (ROOT / "scripts/ci/prepare_evidence_dependencies.sh").read_text()
        self.assertIn("--current-host", script, "missing-current-host-toolchain-receipt")
        self.assertNotIn("brew install coreutils", script, "unreviewed-latest-coreutils-bootstrap")
        self.assertIn("bash scripts/fixtures/z80-as.sh", script)
        self.assertIn("bash scripts/fixtures/m68k-as.sh", script)
        self.assertIn("python3 tools/evidence/fm_compare/compare.py --fetch --build", script)
        self.assertIn("build-original-roms.sh --verify-reproducible", script)
        self.assertIn("--validate-current-receipt", script)

    def test_current_receipt_is_a_separate_validated_host_record(self):
        recipe = (ROOT / "fixtures/independent-game/toolchain/build-binutils.sh").read_text()
        validator = (ROOT / "tests/evidence/independent_game_toolchain.py").read_text()
        self.assertIn("--record-current", recipe)
        self.assertIn("--receipt", recipe)
        self.assertIn("--validate-current-receipt", validator)
        self.assertIn("validate_current_receipt", validator)
        self.assertIn("genewhip-current-host-toolchain-v1", recipe)
        self.assertIn("--self-test-current-receipt", (ROOT / "scripts/ci/required-gate.sh").read_text())
        self.assertIn("tests/evidence/independent_game_toolchain.py", (ROOT / "scripts/ci/required-gate.sh").read_text())
        self.assertIn("toolchain.lock", recipe)

    def test_current_receipt_cache_reuse_and_executable_tamper_rejection(self):
        for target, script in (("z80-elf", "z80-as.sh"), ("m68k-elf", "m68k-as.sh")):
            binary = ROOT / "build/tool-cache" / f"{target}-as"
            receipt = ROOT / "build/tool-cache" / f"{target}-as.receipt.json"
            self.assertTrue(binary.is_file(), f"current-{target}-assembler-not-built")
            self.assertTrue(receipt.is_file(), f"current-{target}-receipt-not-built")
            with tempfile.TemporaryDirectory(prefix="genewhip-receipt-cache-") as temporary:
                cache = pathlib.Path(temporary)
                shutil.copyfile(binary, cache / binary.name)
                shutil.copyfile(receipt, cache / receipt.name)
                args = ["bash", str(ROOT / "scripts/fixtures" / script), "--cache", str(cache)]
                accepted = subprocess.run(args, text=True, capture_output=True)
                self.assertEqual(accepted.returncode, 0, f"current-{target}-receipt-cache-rejected")
                tampered = cache / binary.name
                tampered.write_bytes(tampered.read_bytes() + b"tamper")
                rejected = subprocess.run(args, text=True, capture_output=True)
                self.assertNotEqual(rejected.returncode, 0, f"tampered-{target}-receipt-cache-accepted")
                self.assertIn("receipt", rejected.stderr.lower(), f"tampered-{target}-rejection-not-named")

    def test_locked_assembler_recipe_uses_macos_base_tools_for_signature_checks(self):
        recipe = (ROOT / "fixtures/independent-game/toolchain/build-binutils.sh").read_text()
        self.assertNotRegex(recipe, r"\brg\b", "macos-runner-missing-ripgrep-dependency")
        self.assertIn("grep -E -q", recipe, "portable-signature-status-check-missing")
        self.assertIn("grep -E -v", recipe, "portable-linked-image-check-missing")

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
