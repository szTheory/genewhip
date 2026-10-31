import ctypes
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("runtime_diagnostic", ROOT / "scripts/evidence/v02_run.py")
runtime = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runtime
spec.loader.exec_module(runtime)

class FakeDesktop:
    def __init__(self, report, return_code):
        self.report = report
        self.return_code = return_code
        self.calls = 0
    def host_batch(self, backend, build, core_path, mapping_path, host_path, candidate_path):
        self.calls += 1
        pathlib.Path(host_path).write_text(json.dumps(self.report))
        return self.return_code

class Validator:
    def __init__(self):
        self.calls = []
    def validate_host_report(self, report, candidate):
        self.calls.append((report, candidate))

def call(desktop, compiler, host_path, candidate):
    with mock.patch.object(runtime.subprocess, "Popen", side_effect=AssertionError("Popen denied")), \
         mock.patch.object(runtime.os, "killpg", side_effect=AssertionError("signal denied")), \
         mock.patch.object(ctypes, "CDLL", side_effect=AssertionError("native denied")):
        return runtime._collect_checked_host_batch(
            desktop, compiler, "software", pathlib.Path("build"), pathlib.Path("core.json"),
            pathlib.Path("mapping.json"), host_path, pathlib.Path("candidate.json"), candidate)

def main():
    secret = "PRIVATE_TOKEN PRIVATE_PATH_MARKER"
    failed = {"schema": "genewhip-phase6-host-v1", "status": "fail", "backend": "software",
        "runs": [{"fixture": "recursion94", "case": "full-route", "status": "fail",
            "error": secret, "process": {"process_group_cleanup": "unconfirmed",
                "bound_violation": True, "bound_violation_reason": "phase7-wall-timeout",
                "cleanup_reason": "group-status-budget-exhausted",
                "cleanup_status_observation": "group-status-unavailable",
                "cleanup_observation_attempts": 16}}]}
    with tempfile.TemporaryDirectory() as temporary:
        path = pathlib.Path(temporary) / "host.json"
        desktop, validator = FakeDesktop(failed, 1), Validator()
        try:
            call(desktop, validator, path, {"candidate": "current"})
        except ValueError as error:
            message = str(error)
        else:
            raise AssertionError("nonzero host batch was accepted")
        assert desktop.calls == 1

        # New bounded cleanup reasons survive the production host-batch sanitizer;
        # unrecognized input remains the fixed "other" category.
        for reason in ("cleanup-permission-denied", "group-cleanup-os-error",
                       "group-leader-wait-unconfirmed", "group-leader-reap-unconfirmed"):
            safe = runtime._safe_host_batch_failure("software", 1, {
                "status": "fail", "runs": [{"fixture": "recursion94", "case": "full-route",
                    "status": "fail", "process": {"cleanup_reason": reason,
                    "cleanup_status_observation": reason}}]})
            assert f"cleanup_reason={reason}" in safe and f"status_observation={reason}" in safe, safe
        unknown_reason = runtime._safe_host_batch_failure("software", 1, {
            "status": "fail", "runs": [{"fixture": "recursion94", "case": "full-route",
                "status": "fail", "process": {"cleanup_reason": "private-reason"}}]})
        assert "cleanup_reason=other" in unknown_reason and "private-reason" not in unknown_reason
        assert validator.calls == [], validator.calls
        assert "phase7-host-batch-failed:" in message, message
        assert "backend=software" in message and "case=recursion94/full-route" in message, message
        assert "row=fail" in message and "return=1" in message, message
        assert "cleanup=unconfirmed" in message, message
        assert "cleanup_reason=group-status-budget-exhausted" in message, message
        assert "status_observation=group-status-unavailable" in message, message
        assert "cleanup_queries=16" in message, message
        assert secret not in message and "PRIVATE_PATH_MARKER" not in message and "PRIVATE_TOKEN" not in message, message

        unknown = {"status": "fail", "runs": [{"fixture": "private-fixture",
            "case": "private-case", "status": "fail", "error": secret}]}
        desktop, validator = FakeDesktop(unknown, 1), Validator()
        try:
            call(desktop, validator, path, {"candidate": "current"})
        except ValueError as error:
            unknown_message = str(error)
        else:
            raise AssertionError("unknown host identity was accepted")
        assert "case=unrecognized" in unknown_message, unknown_message
        assert "private-fixture" not in unknown_message and "private-case" not in unknown_message, unknown_message
        assert secret not in unknown_message and validator.calls == [], unknown_message

        passed = {"schema": "genewhip-phase6-host-v1", "status": "pass",
                  "backend": "software", "runs": [{"fixture": "recursion94",
                  "case": "full-route", "status": "pass"}]}
        desktop, validator = FakeDesktop(passed, 0), Validator()
        result = call(desktop, validator, path, {"candidate": "current"})
        assert result == passed
        assert validator.calls == [(passed, {"candidate": "current"})]
        assert desktop.calls == 1
    print("failure-path: safe method-independent host case and cleanup enums; validator skipped")
    print("unknown-id: redacted to unrecognized; raw error omitted")
    print("success-path: report object unchanged; validator called once")
    print("denied effects: fake host producer only; real Popen=0, signals=0, native calls=0")

if __name__ == "__main__":
    main()
