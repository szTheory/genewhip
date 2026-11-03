#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure contracts for finite original-control failure diagnostics."""
import ast
import json
import os
import stat
from unittest import mock
import pathlib
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/fixtures/phase6_game.py"
tree = ast.parse(SOURCE.read_text())
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and
    n.name == "_original_control_failure_summary")
namespace = {"json": json, "os": os, "stat": stat}
exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), "exec"), namespace)
summary = namespace[node.name]
SECRET = "sensitive-path-token sensitive-user-token SDL_error"

class Reporting(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name) / "nested.json"
        self.result = types.SimpleNamespace(returncode=1)
        self.driver = {"return_code": 1, "status": "completed", "bound_violation": False,
            "process_group_cleanup": "confirmed"}
    def call(self, stderr="", driver=None):
        raw = summary(self.result, self.driver if driver is None else driver,
            {"stderr": {"text": stderr}}, self.path)
        self.assertNotIn(SECRET, raw)
        self.assertLess(len(raw), 2048)
        return json.loads(raw)
    def test_descriptor_open_is_no_follow_and_nonblocking(self):
        self.path.write_text(json.dumps({"processes": []}))
        with mock.patch.object(os, "open", wraps=os.open) as opened:
            self.call()
        flags = opened.call_args.args[1]
        self.assertTrue(flags & os.O_NOFOLLOW)
        self.assertTrue(flags & os.O_NONBLOCK)
    def test_replacement_symlink_is_rejected_by_descriptor_open(self):
        target = self.path.with_name("target.json")
        target.write_text(json.dumps({"processes": [{"return_code": 1}]}))
        self.path.symlink_to(target)
        with mock.patch.object(pathlib.Path, "is_symlink", return_value=False):
            self.assertEqual(self.call()["nested"], "unreadable")
    def test_deep_json_does_not_replace_primary_failure(self):
        self.path.write_text("[" * 2000 + "]" * 2000)
        with mock.patch.object(json, "loads", side_effect=RecursionError):
            raw = summary(self.result, self.driver, {"stderr": {"text": ""}}, self.path)
        self.assertEqual(json.loads(raw)["nested"], "unreadable")
    def test_missing_receipt_is_unknown_and_outer_cleanup_stays_distinct(self):
        result = self.call(SECRET)
        self.assertEqual(result["nested"], "unavailable")
        self.assertEqual(result["driver"]["cleanup"], "confirmed")
        self.assertEqual(result["stderr_reason"], "unclassified")
    def test_nested_bound_failure_survives_outer_nonbound(self):
        self.path.write_text(json.dumps({"processes": [{"return_code": 0},
            {"return_code": -9, "status": "failed", "bound_violation": True,
             "bound_violation_reason": "phase7-rss-byte-limit", "process_group_cleanup": "confirmed"}]}))
        result = self.call(SECRET)
        self.assertFalse(result["driver"]["bound"])
        self.assertTrue(result["nested"]["bound"])
        self.assertEqual(result["nested"]["return"], -9)
        self.assertEqual(result["nested"]["bound_reason"], "phase7-rss-byte-limit")
        self.assertEqual(result["nested_count"], 2)
    def test_finite_stderr_case_and_reason(self):
        result = self.call("BLOCKED: start-move: headless exit -9:" + SECRET)
        self.assertEqual(result["case"], "start-move")
        self.assertEqual(result["stderr_reason"], "headless-nonzero")
    def test_preexec_failure(self):
        self.path.write_text(json.dumps({"processes": [{"status": "launch-failed",
            "process_group_cleanup": "not-launched", "bound_violation": True}]}))
        result = self.call("Exception occurred in preexec_fn." + SECRET)
        self.assertEqual(result["nested"]["status"], "launch-failed")
        self.assertEqual(result["stderr_reason"], "preexec-failure")
    def test_zero_exit_does_not_hide_nested_unconfirmed_cleanup(self):
        self.path.write_text(json.dumps({"processes": [{"return_code": 0,
            "status": "completed", "bound_violation": False,
            "process_group_cleanup": "unconfirmed"}]}))
        self.assertEqual(self.call()["nested"]["cleanup"], "unconfirmed")
    def test_hostile_private_types_stay_unavailable(self):
        for value in (SECRET, True, [], {}, None):
            row = {"return_code": value, "status": value, "bound_violation": value,
                "process_group_cleanup": value, "bound_violation_reason": value}
            result = self.call(SECRET, row)
            self.assertEqual(result["driver"]["status"], "unavailable")
            self.assertEqual(result["driver"]["bound_reason"], "unavailable")
    def test_malformed_oversized_and_symlink_receipts(self):
        self.path.write_text("{broken")
        self.assertEqual(self.call()["nested"], "unreadable")
        self.path.write_text("x" * 65537)
        self.assertEqual(self.call()["nested"], "unavailable")
        self.path.unlink()
        target = self.path.with_name("target")
        target.write_text(SECRET)
        self.path.symlink_to(target)
        self.assertEqual(self.call()["nested"], "unavailable")
    def test_all_completed_receipts_do_not_invent_nested_failure(self):
        self.path.write_text(json.dumps({"processes": [{"return_code": 0,
            "status": "completed", "bound_violation": False}]}))
        self.assertEqual(self.call()["nested"], "no-recorded-failure")
    def test_actual_core_failure_callsite_uses_summary(self):
        core = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "core")
        calls = [n for n in ast.walk(core) if isinstance(n, ast.Call) and
            isinstance(n.func, ast.Name) and n.func.id == "_original_control_failure_summary"]
        self.assertEqual(len(calls), 1)

if __name__ == "__main__":
    unittest.main(verbosity=2)
