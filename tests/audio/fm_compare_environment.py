#!/usr/bin/env python3
"""Synthetic-marker checks for FM comparison child process boundaries."""
import importlib.util
import json
import os
import pathlib
import subprocess
import shlex
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPARE = ROOT / "tools/evidence/fm_compare/compare.py"
BUILD_SCRIPT = ROOT / "tools/evidence/fm_compare/build_refs.sh"
SPEC = importlib.util.spec_from_file_location("fm_compare", COMPARE)
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)
MARKER = "GW_SYNTHETIC_SECRET_MARKER"


class ChildEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)

    def test_reference_adapter_does_not_receive_caller_marker(self):
        trace = self.directory / "trace.tsv"
        trace.write_text("synthetic trace\n")
        marker_result = self.directory / "adapter-marker.txt"
        fake = self.directory / "ymfm_replay"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            f"pathlib.Path({str(marker_result)!r}).write_text(str(int({MARKER!r} in os.environ)))\n"
            "print('1 0 0 0')\n"
        )
        fake.chmod(0o755)
        compare.BIN = self.directory
        os.environ[MARKER] = "synthetic-only"
        self.addCleanup(os.environ.pop, MARKER, None)
        self.assertEqual(compare.run_adapter("ymfm_replay", trace, self.directory), [(1, 0, 0, 0)])
        self.assertEqual(marker_result.read_text(), "0")

    def test_direct_build_script_cleans_environment_before_compiler(self):
        marker_result = self.directory / "compiler-marker.txt"
        fake_compiler = self.directory / "fake-cc"
        fake_compiler.write_text(
            "#!/bin/bash\n"
            f"marker=0; [[ ${{{MARKER}+x}} == x ]] && marker=1\n"
            "function=0; [[ $(type -t GW_SYNTHETIC_AUDIT_FN 2>/dev/null || true) == function ]] && function=1\n"
            f"printf '%s\\t%s\\t%s\\t%s\\n' \"$marker\" \"$function\" \"${{SDKROOT-}}\" \"${{DEVELOPER_DIR-}}\" >> {shlex.quote(str(marker_result))}\n"
        )
        fake_compiler.chmod(0o755)
        env = os.environ.copy()
        env[MARKER] = "synthetic-only"
        env["CC"] = str(fake_compiler)
        env["CXX"] = str(fake_compiler)
        env["SDKROOT"] = "/synthetic/sdk"
        env["DEVELOPER_DIR"] = "/synthetic/developer"
        result = subprocess.run(
            ["bash", "-c",
             "GW_SYNTHETIC_AUDIT_FN() { :; }; export -f GW_SYNTHETIC_AUDIT_FN; "
             "exec bash \"$1\" --test-compiler-env", "fm-env-test", str(BUILD_SCRIPT)],
            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("\t") for line in marker_result.read_text().splitlines()]
        self.assertEqual(len(rows), 2, "CC and CXX both run through the clean environment")
        for marker, function, sdkroot, developer_dir in rows:
            self.assertEqual(marker, "0")
            self.assertEqual(function, "0")
            self.assertEqual(sdkroot, "/synthetic/sdk")
            self.assertEqual(developer_dir, "/synthetic/developer")

    def test_git_head_advertisement_parser_rejects_malformed_or_ambiguous_refs(self):
        result = subprocess.run(
            ["bash", str(BUILD_SCRIPT), "--test-head-parser"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("head advertisement controls: 4/4 passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
