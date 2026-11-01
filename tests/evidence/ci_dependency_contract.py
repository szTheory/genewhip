#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep required hosted lanes bound to the pinned macOS/tool evidence inputs."""
import pathlib
import json
import hashlib
import os
import re
import shutil
import sys
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class CIDependencyContract(unittest.TestCase):
    def test_current_keyring_pin_is_updated_without_rewriting_historical_lock(self):
        expected_current = "8013de59880f7a59f53b6bd207f4d2a408d67b84a82fa9cba1dbbf443428e2db"
        historical = "0fe55175b96a8ea1c4b670cc3fe11d56b341e4eff81b161ea49958ae550be6ca"
        recipe = (ROOT / "fixtures/independent-game/toolchain/build-binutils.sh").read_text()
        validator = (ROOT / "tests/evidence/independent_game_toolchain.py").read_text()
        lock = json.loads((ROOT / "fixtures/independent-game/toolchain.lock").read_text())
        self.assertIn(f"KEYRING_SHA={expected_current}", recipe)
        self.assertIn(f'CURRENT_KEYRING_SHA = "{expected_current}"', validator)
        self.assertEqual(lock["assembler"]["signature"]["keyring_sha256"], historical)

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
                cached_assembler = cache / binary.name
                cached_assembler.chmod(0o755)
                args = ["bash", str(ROOT / "scripts/fixtures" / script), "--cache", str(cache)]
                accepted = subprocess.run(args, text=True, capture_output=True)
                self.assertEqual(accepted.returncode, 0, f"current-{target}-receipt-cache-rejected")
                returned_path = accepted.stdout.strip()
                self.assertEqual(pathlib.Path(returned_path), cached_assembler.resolve(),
                                 f"current-{target}-wrapper-returned-unexpected-path")
                invoked = subprocess.run([returned_path, "--version"], text=True,
                                         capture_output=True)
                self.assertEqual(invoked.returncode, 0,
                                 f"current-{target}-returned-assembler-not-executable")
                self.assertIn("GNU assembler (GNU Binutils) 2.47.", invoked.stdout,
                              f"current-{target}-returned-assembler-wrong-tool")
                for mode, label in ((0o644, "no-execute-bits"),
                                    (0o401, "execute-bit-on-other-class")):
                    cached_assembler.chmod(mode)
                    rejected_mode = subprocess.run(args, text=True, capture_output=True)
                    self.assertNotEqual(rejected_mode.returncode, 0,
                                        f"{label}-{target}-receipt-cache-accepted")
                    self.assertIn("current-host assembler is not executable",
                                  rejected_mode.stderr,
                                  f"{label}-{target}-rejection-not-named")
                cached_assembler.chmod(0o755)
                tampered = cache / binary.name
                tampered.write_bytes(tampered.read_bytes() + b"tamper")
                rejected = subprocess.run(args, text=True, capture_output=True)
                self.assertNotEqual(rejected.returncode, 0, f"tampered-{target}-receipt-cache-accepted")
                self.assertIn("receipt", rejected.stderr.lower(), f"tampered-{target}-rejection-not-named")

    def test_validated_receipt_logs_redacted_reproducible_identity(self):
        for target in ("z80-elf", "m68k-elf"):
            receipt_path = ROOT / "build/tool-cache" / f"{target}-as.receipt.json"
            binary_path = ROOT / "build/tool-cache" / f"{target}-as"
            result = subprocess.run([
                "python3", str(ROOT / "tests/evidence/independent_game_toolchain.py"),
                "--validate-current-receipt", str(receipt_path), "--target", target,
                "--assembler", str(binary_path),
            ], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, f"{target}-receipt-identity-validation-failed")
            identity_lines = [line for line in result.stdout.splitlines()
                              if line.startswith("CURRENT_HOST_RECEIPT: ")]
            self.assertEqual(len(identity_lines), 1, f"{target}-receipt-identity-log-missing")
            identity = json.loads(identity_lines[0].split(": ", 1)[1])
            self.assertEqual(identity["schema"], "genewhip-current-host-toolchain-v1")
            self.assertEqual(identity["target"], target)
            self.assertEqual(identity["receipt_sha256"],
                             hashlib.sha256(receipt_path.read_bytes()).hexdigest())
            self.assertEqual(identity["binutils"]["source_archive_sha256"],
                             "3068128c75cda9f898ccb4211d360246e8e195ffcc9dfb655b23ae23a54800e8")
            self.assertEqual(identity["assembler"]["sha256"],
                             hashlib.sha256(binary_path.read_bytes()).hexdigest())
            self.assertNotIn("/Users/", identity_lines[0])
            self.assertNotIn("/home/", identity_lines[0])

    def test_locked_assembler_recipe_uses_macos_base_tools_for_signature_checks(self):
        recipe = (ROOT / "fixtures/independent-game/toolchain/build-binutils.sh").read_text()
        self.assertNotRegex(recipe, r"\brg\b", "macos-runner-missing-ripgrep-dependency")
        self.assertIn("grep -E -q", recipe, "portable-signature-status-check-missing")
        self.assertIn("grep -E -v", recipe, "portable-linked-image-check-missing")

    def test_apple_utility_fallback_binds_real_system_executable_bytes(self):
        recipe_path = ROOT / "fixtures/independent-game/toolchain/build-binutils.sh"
        recipe = recipe_path.read_text()
        self.assertIn("record_apple_tools", recipe)
        self.assertIn("else\n  [ \"$MODE\" = --record-current ] || fail 'GNU Coreutils gmkdir/ginstall build inputs unavailable'\n  record_apple_tools", recipe)
        fallback = subprocess.run(["bash", str(recipe_path), "--self-test-apple-tools"],
                                  text=True, capture_output=True)
        self.assertEqual(fallback.returncode, 0,
                         "apple-utility-fallback-missing-or-identity-mismatch")
        self.assertIn("PASS: Apple utility fallback binds /bin/mkdir and /usr/bin/install bytes",
                      fallback.stdout)

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
        helper = re.search(r"(?ms)^run_required_ctest\(\) \{\n.*?^\}", required)
        self.assertIsNotNone(helper, "required CTest helper missing")
        helper_body = helper.group(0)
        self.assertIn('--output-junit ctest-junit.raw.xml', helper_body)
        self.assertIn('scripts/evidence/phase4_report.py safety-sanitize-junit', helper_body)
        self.assertIn('scripts/evidence/phase4_report.py safety-ctest-failure-summary', helper_body)
        self.assertIn('scripts/ci/check_ctest_skips.py "$junit"', helper_body)
        self.assertLess(helper_body.index('safety-sanitize-junit'),
                        helper_body.index('safety-ctest-failure-summary'))
        self.assertLess(helper_body.index('safety-ctest-failure-summary'),
                        helper_body.index('check_ctest_skips.py'))
        self.assertIn('run_required_ctest "$lane" "$junit" "$leaks"', required)
        self.assertIn('run_required_ctest production build/ci/production/ctest-junit.xml "$leaks"', required)
        self.assertNotIn('scripts/ci/check_ctest_skips.py "$junit"', required.replace(helper_body, ""))
        self.assertNotIn("--output-junit ctest-junit.xml", required)
        desktop = workflow.split("  desktop:\n", 1)[1].split("  package:\n", 1)[0]
        self.assertIn("scripts/ci/check_ctest_skips.py build/desktop/ctest-junit.xml", desktop)
        self.assertIn("--output-junit ctest-junit.xml", desktop)

    def test_failed_required_ctest_is_sanitized_before_nonzero_return(self):
        gate = (ROOT / "scripts/ci/required-gate.sh").read_text()
        helper = re.search(r"(?ms)^run_required_ctest\(\) \{\n.*?^\}", gate)
        self.assertIsNotNone(helper, "required CTest sanitizing helper missing")
        with tempfile.TemporaryDirectory(prefix="required-ctest-failure-") as temporary:
            root = pathlib.Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            build = root / "build/ci/native"
            build.mkdir(parents=True)
            junit = build / "ctest-junit.xml"
            events = root / "events.log"
            ctest = tools / "ctest"
            ctest.write_text("""#!/bin/sh
printf 'ctest\\n' >> "$EVENTS"
test "$ASAN_OPTIONS" = detect_leaks=0 || exit 96
test "$UBSAN_OPTIONS" = halt_on_error=1 || exit 97
for arg in "$@"; do
  if [ "$arg" = --output-on-failure ]; then printf 'PRIVATE_TEST_OUTPUT_MARKER\\n'; fi
done
test_dir=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = --test-dir ]; then shift; test_dir=$1; fi
  shift
done
printf '<testsuites><testsuite><testcase name="phase6_route_contract"><failure message="PRIVATE_TEST_OUTPUT_MARKER"/>\\
<system-out>GENEWHIP_TEST_RESULT:NativeParserContract.test_bounded_malformed_route_matrix_both_clients:failure\\n\\
GENEWHIP_TEST_RESULT:NativeParserContract.test_process_group_and_stream_caps_are_enforced:error\\n\\
PRIVATE_TEST_OUTPUT_MARKER private command</system-out></testcase></testsuite></testsuites>\\n' \\
  > "$test_dir/ctest-junit.raw.xml"
exit 7
""")
            ctest.chmod(0o755)
            python = tools / "python3"
            python.write_text("""#!/bin/sh
case "$1" in
  */phase4_report.py)
    case "$2" in
      safety-sanitize-junit) printf 'sanitize\\n' >> "$EVENTS" ;;
      safety-ctest-failure-summary) printf 'failure-summary\\n' >> "$EVENTS" ;;
      *) exit 91 ;;
    esac
    shift
    exec "$REAL_PYTHON" "$REPORT_SCRIPT" "$@"
    ;;
  */check_ctest_skips.py)
    test -f "$2" || exit 93
    printf 'skip-check\\n' >> "$EVENTS"
    ;;
  *) exit 94 ;;
esac
""")
            python.chmod(0o755)
            source = (helper.group(0) + "\nset -euo pipefail\n"
                + 'run_required_ctest "$1" "$2" 0 || exit $?\n'
                + 'printf "continued\\n" >> "$EVENTS"\n')
            # Exercise the system Bash used by macOS CI (3.2), even when PATH has Bash 5.
            result = subprocess.run(["/bin/bash", "-c", source, "test", "native", str(junit)],
                cwd=root, text=True, capture_output=True,
                env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
                     "EVENTS": str(events), "REAL_PYTHON": sys.executable,
                     "REPORT_SCRIPT": str(ROOT / "scripts/evidence/phase4_report.py")})
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertRegex(result.stderr, r"ci-stage native-ctest [0-9.]+ seconds")
            self.assertNotIn("PRIVATE_TEST_OUTPUT_MARKER", result.stdout + result.stderr)
            self.assertIn("NativeParserContract.test_bounded_malformed_route_matrix_both_clients [failure]",
                          result.stdout)
            self.assertIn("NativeParserContract.test_process_group_and_stream_caps_are_enforced [error]",
                          result.stdout)
            self.assertNotIn("private command", result.stdout + result.stderr)
            self.assertEqual(events.read_text().splitlines(),
                             ["ctest", "sanitize", "failure-summary", "skip-check"])
            self.assertIn("PRIVATE_TEST_OUTPUT_MARKER", (build / "ctest-junit.raw.xml").read_text())
            self.assertNotIn("PRIVATE_TEST_OUTPUT_MARKER", junit.read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
