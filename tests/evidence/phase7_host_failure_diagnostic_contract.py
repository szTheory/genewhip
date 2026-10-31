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
desktop_spec = importlib.util.spec_from_file_location(
    "host_failure_producer", ROOT / "tests/desktop/phase6_routes.py")
desktop_routes = importlib.util.module_from_spec(desktop_spec)
sys.modules[desktop_spec.name] = desktop_routes
desktop_spec.loader.exec_module(desktop_routes)

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
            "reason": "host-renderer-pcm-or-device-mismatch", "core_outcome": "pass",
            "host_outcome": "fail-diagnostic", "error": secret,
            "observed_clocks": {"status": 0, "active_ticks": 3601, "fields": "7200", "boundary_calls": -1},
            "common_boundary": {"source_samples_equal": True, "inputs": {"equal": False},
                "renderer_pixel_equal": None, "full_pcm_equal": False},
            "renderer": {"renderer_readback_activity": True},
            "audio": {"audio_device_activity": False, "audio_submitted_frames": 28_800_001,
                "audio_device_consumed_frames": None},
            "failure_diagnostic": {"capture_field_matches": False, "renderer_named": True,
                "video_driver_named": False, "audio_driver_named": True},
            "process": {"return_code": -15, "process_group_cleanup": "unconfirmed",
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
            projected = json.loads(safe)
            assert projected["cleanup_reason"] == reason and projected["status_observation"] == reason, projected
        unknown_reason = runtime._safe_host_batch_failure("software", 1, {
            "status": "fail", "runs": [{"fixture": "recursion94", "case": "full-route",
                "status": "fail", "process": {"cleanup_reason": "private-reason"}}]})
        assert json.loads(unknown_reason)["cleanup_reason"] == "other" and "private-reason" not in unknown_reason
        assert validator.calls == [], validator.calls
        assert "phase7-host-batch-failed:" in message, message
        summary_text = message.split("phase7-host-batch-failed:", 1)[1]
        summary = json.loads(summary_text)
        assert summary["backend"] == "software" and summary["case"] == "recursion94/full-route", summary
        assert summary["row"] == "fail" and summary["batch_return"] == "1", summary
        assert summary["cleanup"] == "unconfirmed" and summary["cleanup_reason"] == "group-status-budget-exhausted", summary
        assert summary["status_observation"] == "group-status-unavailable" and summary["cleanup_queries"] == "16", summary
        assert summary["child_exit"] == "signaled", summary
        assert summary["reason"] == "host-renderer-pcm-or-device-mismatch", summary
        assert summary["core_outcome"] == "pass" and summary["host_outcome"] == "fail-diagnostic", summary
        assert summary["active_ticks"] == "overrange" and summary["fields"] == "untyped", summary
        assert summary["boundary_calls"] == "negative" and summary["audio_submitted_frames"] == "overrange", summary
        assert summary["audio_consumed_frames"] == "missing" and summary["native_status"] == "zero", summary
        assert summary["source_samples_equal"] == "true" and summary["input_equal"] == "false", summary
        assert summary["renderer_pixel_equal"] == "unavailable" and summary["pcm_equal"] == "false", summary
        assert summary["readback_activity"] == "true" and summary["audio_activity"] == "false", summary
        assert summary["capture_field_matches"] == "false" and summary["renderer_named"] == "true", summary
        assert len(message.encode("utf-8")) <= 4096, len(message)
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
        unknown_summary = json.loads(unknown_message.split("phase7-host-batch-failed:", 1)[1])
        assert unknown_summary["case"] == "unrecognized", unknown_summary
        assert "private-fixture" not in unknown_message and "private-case" not in unknown_message, unknown_message
        assert secret not in unknown_message and validator.calls == [], unknown_message

        # The sanitizer accepts only exact strings/booleans/integers. Weird or
        # unhashable values become fixed categories and never escape to the log.
        malicious = json.loads(json.dumps(failed))
        bad = malicious["runs"][0]
        bad.update({"fixture": {"private": secret}, "case": [secret], "reason": [secret],
                    "core_outcome": {}, "host_outcome": []})
        bad["process"].update({"process_group_cleanup": [], "bound_violation_reason": {},
            "cleanup_reason": [secret], "cleanup_status_observation": {secret: secret},
            "cleanup_observation_attempts": True, "return_code": False})
        bad["observed_clocks"].update({"status": {}, "active_ticks": True, "fields": -1,
            "boundary_calls": 100_000_001})
        bad["audio"].update({"audio_submitted_frames": "not-a-number", "audio_device_consumed_frames": {}})
        bad["common_boundary"].update({"source_samples_equal": [], "renderer_pixel_equal": {}})
        bad["failure_diagnostic"].update({"capture_field_matches": 1, "renderer_named": secret,
            "video_driver_named": {}, "audio_driver_named": []})
        safe_malicious = runtime._safe_host_batch_failure("software", 1, malicious)
        assert len(safe_malicious.encode("utf-8")) <= 4096, len(safe_malicious)
        assert secret not in safe_malicious and "private" not in safe_malicious, safe_malicious
        malformed_summary = json.loads(safe_malicious)
        assert malformed_summary["case"] == "unrecognized" and malformed_summary["reason"] == "other", malformed_summary
        assert malformed_summary["active_ticks"] == "untyped" and malformed_summary["fields"] == "negative", malformed_summary
        assert malformed_summary["child_exit"] == "untyped" and malformed_summary["cleanup"] == "other", malformed_summary
        assert malformed_summary["native_status"] == "untyped", malformed_summary
        malformed_status = runtime._safe_host_batch_failure("software", 1, {
            "status": {secret: secret}, "runs": [{"status": {secret: secret},
                "fixture": [secret], "case": {secret: secret}}]})
        assert len(malformed_status.encode("utf-8")) <= 4096, len(malformed_status)

        # Exercise the exact producer projection used by _retained_host_case.
        # It emits only booleans, even when identifying strings contain secrets.
        producer = desktop_routes._host_failure_presence({"renderer_capture_field": 42,
            "renderer": secret, "video_driver": "", "audio_driver": "SDL-private"}, 42)
        assert producer == {"capture_field_matches": True, "renderer_named": True,
            "video_driver_named": False, "audio_driver_named": True}, producer
        assert not any(isinstance(value, str) for value in producer.values()), producer
        legacy_truthiness = desktop_routes._host_failure_presence({"renderer_capture_field": True,
            "renderer": [secret], "video_driver": 0, "audio_driver": {}}, 1)
        assert legacy_truthiness == {"capture_field_matches": True, "renderer_named": True,
            "video_driver_named": False, "audio_driver_named": False}, legacy_truthiness

        # Keep diagnostically distinct values distinct without printing counts.
        def summary_for(clocks, audio_values):
            source = json.loads(json.dumps(failed))
            source["runs"][0]["observed_clocks"].update(clocks)
            source["runs"][0]["audio"].update(audio_values)
            return json.loads(runtime._safe_host_batch_failure("software", 1, source))
        exact = summary_for({"active_ticks": 3600, "status": 1},
            {"audio_submitted_frames": 1, "audio_device_consumed_frames": 0})
        near = summary_for({"active_ticks": 3599},
            {"audio_submitted_frames": 0, "audio_device_consumed_frames": 1})
        assert exact["active_ticks"] == "expected" and near["active_ticks"] == "mismatch", (exact, near)
        assert exact["native_status"] == "nonzero", exact
        assert exact["audio_submitted_frames"] == "positive" and exact["audio_consumed_frames"] == "zero", exact
        assert near["audio_submitted_frames"] == "zero" and near["audio_consumed_frames"] == "positive", near

        passed = {"schema": "genewhip-phase6-host-v1", "status": "pass",
                  "backend": "software", "runs": [{"fixture": "recursion94",
                  "case": "full-route", "status": "pass"}]}
        desktop, validator = FakeDesktop(passed, 0), Validator()
        result = call(desktop, validator, path, {"candidate": "current"})
        assert result == passed
        assert validator.calls == [(passed, {"candidate": "current"})]
        assert desktop.calls == 1
    print("failure-path: bounded failure projection, outcomes, comparisons, counters and cleanup enums; validator skipped")
    print("unknown-id: redacted to unrecognized; raw error omitted")
    print("success-path: report object unchanged; validator called once")
    print("denied effects: fake host producer only; real Popen=0, signals=0, native calls=0")

if __name__ == "__main__":
    main()
