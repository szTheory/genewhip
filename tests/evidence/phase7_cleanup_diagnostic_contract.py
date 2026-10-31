import contextlib
import ast
import importlib.util
import io
import json
import pathlib
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]

def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

route = load("tests/session/phase6_route_contract.py", "route_cleanup_reason")
report = load("scripts/evidence/phase4_report.py", "report_cleanup_reason")
METHOD = "test_process_group_and_stream_caps_are_enforced"

class FakePopen:
    def __init__(self, *args, **kwargs):
        self.pid = 54321
        self.returncode = None
        FakePopen.calls += 1
        command = args[0]
        code = command[2] if len(command) > 2 else ""
        for node in ast.walk(ast.parse(code)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
                    node.func.attr == "write_text" and node.args and
                    isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) and
                    node.args[0].value.endswith("/child.pid")):
                pathlib.Path(node.args[0].value).write_text(str(self.pid))
                break
        kwargs["stdout"].write(b"x" * (route.MAX_STREAM_BYTES + 1))
    def poll(self):
        return None
    def wait(self, timeout=None):
        self.returncode = -15
        return self.returncode
    def terminate(self):
        self.returncode = -15
    def kill(self):
        self.returncode = -9

FakePopen.calls = 0

class FakeSuccessfulPopen:
    calls = 0
    def __init__(self, *args, **kwargs):
        type(self).calls += 1
        self.pid = 54322
        self.returncode = 0
    def poll(self):
        return 0
    def wait(self, timeout=None):
        return 0

def exercise_status_provider(status_result, signal_error=None):
    case = route.NativeParserContract(METHOD)
    old_marker = route.os.environ.get("GENEWHIP_PROCESS_CONTEXT")
    route.os.environ["GENEWHIP_PROCESS_CONTEXT"] = route.HOST_PROCESS_CONTEXT
    FakePopen.calls = 0
    old_argv = sys.argv
    sys.argv = ["phase6_route_contract.py", "--contract", "--build", str(ROOT / "fake-build")]
    loader = unittest.defaultTestLoader
    test = case
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        out = io.StringIO()
        run_stub = mock.Mock(return_value=subprocess.CompletedProcess(["self-test"], 0, "", ""))
        def only_case(cls):
            return unittest.TestSuite([test]) if cls is route.NativeParserContract else unittest.TestSuite()
        try:
            with mock.patch.object(route.subprocess, "run", run_stub), \
                 mock.patch.object(route.subprocess, "Popen", FakePopen), \
                 mock.patch.object(route.os, "killpg", side_effect=signal_error, return_value=None), \
                 mock.patch.object(route.os, "getpgid", side_effect=ProcessLookupError), \
                 mock.patch.object(route.ctypes, "CDLL", side_effect=AssertionError("native denied")), \
                 mock.patch.object(route.sys, "platform", "darwin"), \
                 mock.patch.object(route, "_darwin_status_states", return_value=status_result), \
                 mock.patch.object(loader, "loadTestsFromTestCase", side_effect=only_case), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                exit_code = route.main()
        finally:
            sys.argv = old_argv
            if old_marker is None:
                route.os.environ.pop("GENEWHIP_PROCESS_CONTEXT", None)
            else:
                route.os.environ["GENEWHIP_PROCESS_CONTEXT"] = old_marker
        captured = out.getvalue()
        assert exit_code == 1
        assert FakePopen.calls == 1, FakePopen.calls
        assert run_stub.call_count == 1, run_stub.call_count
        marker = next(line for line in captured.splitlines() if line.startswith("GENEWHIP_TEST_RESULT:"))
        raw_xml = root / "raw.xml"; safe_xml = root / "safe.xml"
        raw_xml.write_text("<testsuites><testsuite><testcase name=\"phase6_route_contract\">"
            "<failure/><system-err>" +
            (captured + " PRIVATE_DIAGNOSTIC_MARKER").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") +
            "</system-err></testcase></testsuite></testsuites>")
        report.sanitize_ctest_junit(raw_xml, safe_xml)
        safe = safe_xml.read_text()
        assert "PRIVATE_DIAGNOSTIC_MARKER" not in safe
        assert "PRIVATE_PATH_MARKER" not in safe
        summary = report.summarize_sanitized_ctest_failures(safe_xml)
        return marker, summary, test.runs[-1]

def verify_success_receipt_unchanged():
    old_marker = route.os.environ.get("GENEWHIP_PROCESS_CONTEXT")
    route.os.environ["GENEWHIP_PROCESS_CONTEXT"] = route.HOST_PROCESS_CONTEXT
    FakeSuccessfulPopen.calls = 0
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        runs = []
        with mock.patch.object(route.subprocess, "Popen", FakeSuccessfulPopen), \
             mock.patch.object(route.os, "killpg", return_value=None), \
             mock.patch.object(route.sys, "platform", "darwin"), \
             mock.patch.object(route, "_darwin_status_states", return_value=([], True)), \
             mock.patch.object(route.ctypes, "CDLL", side_effect=AssertionError("native denied")):
            result = route._run_client(pathlib.Path(sys.executable), [sys.executable, "-c", "pass"],
                runs, report=root / "none.json", timeout=1, cwd=root)
    if old_marker is None:
        route.os.environ.pop("GENEWHIP_PROCESS_CONTEXT", None)
    else:
        route.os.environ["GENEWHIP_PROCESS_CONTEXT"] = old_marker
    assert FakeSuccessfulPopen.calls == 1
    assert result.returncode == 0
    assert runs[0]["process_group_cleanup"] == "confirmed"
    assert runs[0]["status"] == "completed"
    assert not {"cleanup_reason", "cleanup_status_observation", "cleanup_observation_attempts"} & set(runs[0])

def verify_legacy_sanitizer_shape():
    marker = f"GENEWHIP_TEST_RESULT:NativeParserContract.{METHOD}:failure"
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        raw, safe = root / "legacy.xml", root / "legacy-safe.xml"
        raw.write_text("<testsuites><testsuite><testcase name=\"phase6_route_contract\">"
            "<failure/><system-err>" + marker + "</system-err></testcase></testsuite></testsuites>")
        report.sanitize_ctest_junit(raw, safe)
        assert report.summarize_sanitized_ctest_failures(safe) == [
            f"CTest failure [failure]",
            f"CTest subtest failure: NativeParserContract.{METHOD} [failure]",
        ]

for label, provider in (("status-unavailable", (None, True)), ("group-active", (["S"], True))):
    marker, summary, receipt = exercise_status_provider(provider)
    assert receipt["process_group_cleanup"] == "unconfirmed", receipt
    assert receipt["cleanup_observation_attempts"] <= 16, receipt
    assert any("NativeParserContract.test_process_group_and_stream_caps_are_enforced" in line
               and "cleanup=unconfirmed" in line
               and "cleanup_reason=group-status-budget-exhausted" in line
               and "cleanup_queries=16" in line
               and ("status_observation=group-status-unavailable" in line
                    or "status_observation=group-reported-active" in line)
               for line in summary), summary
    print(label, marker, summary)
verify_success_receipt_unchanged()
print("success-path: confirmed process receipt has no new diagnostic fields")
verify_legacy_sanitizer_shape()
print("legacy-path: existing method/kind marker sanitizes to unchanged summary")

def result_for_failure_snapshot():
    class NativeParserContract(unittest.TestCase):
        runs = []
        def test_process_group_and_stream_caps_are_enforced(self):
            self.runs.append({"process_group_cleanup": "unconfirmed", "cleanup_reason": "group-status-unavailable",
                              "cleanup_status_observation": "group-status-unavailable", "cleanup_observation_attempts": 3})
            self.fail("private")
        def test_later_control(self):
            self.runs.append({"process_group_cleanup": "confirmed", "cleanup_reason": "group-inactive",
                              "cleanup_status_observation": "group-inactive", "cleanup_observation_attempts": 1})
    suite = unittest.TestSuite([NativeParserContract("test_process_group_and_stream_caps_are_enforced"),
                                NativeParserContract("test_later_control")])
    result = route.SafeDiagnosticTextTestResult(io.StringIO(), True, 1)
    suite.run(result)
    stream = io.StringIO()
    with contextlib.redirect_stderr(stream):
        route._emit_safe_failure_diagnostics(result)
    assert ":unconfirmed:" in stream.getvalue() and ":confirmed:" not in stream.getvalue(), stream.getvalue()

    case3 = NativeParserContract("test_process_group_and_stream_caps_are_enforced")
    result3 = route.SafeDiagnosticTextTestResult(io.StringIO(), True, 1)
    result3.startTest(case3)
    case3.runs.append({"process_group_cleanup": "confirmed", "cleanup_reason": "group-inactive"})
    case3.runs.append({"process_group_cleanup": "unconfirmed", "cleanup_reason": "group-leader-reap-unconfirmed"})
    result3.addFailure(case3, (AssertionError, AssertionError("private"), None))
    stream = io.StringIO()
    with contextlib.redirect_stderr(stream):
        route._emit_safe_failure_diagnostics(result3)
    assert ":unconfirmed:" in stream.getvalue() and "group-leader-reap-unconfirmed" in stream.getvalue(), stream.getvalue()

    result2 = route.SafeDiagnosticTextTestResult(io.StringIO(), True, 1)
    case2 = NativeParserContract("test_process_group_and_stream_caps_are_enforced")
    case2.runs = [{"process_group_cleanup": "confirmed", "cleanup_reason": "group-inactive"}]
    result2.startTest(case2)
    result2.addFailure(case2, (AssertionError, AssertionError("private"), None))
    stream = io.StringIO()
    with contextlib.redirect_stderr(stream):
        route._emit_safe_failure_diagnostics(result2)
    assert ":missing:none:missing:missing:0" in stream.getvalue(), stream.getvalue()

result_for_failure_snapshot()
print("failure snapshot: later receipt cannot replace failing test receipt; no-new-receipt stays missing")

for exc, expected in ((PermissionError("denied"), "cleanup-permission-denied"),
                      (OSError("io"), "group-cleanup-os-error")):
    marker, _, receipt = exercise_status_provider((None, True), signal_error=exc)
    assert receipt["cleanup_reason"] == expected, receipt
    assert expected in marker, marker
    print("signal-error:", expected)

def mixed_legacy_extended_sort():
    method = f"NativeParserContract.{METHOD}"
    legacy = f"GENEWHIP_TEST_RESULT:{method}:failure"
    extended = (f"GENEWHIP_TEST_RESULT:{method}:failure:AssertionError:unconfirmed:none:"
                "group-status-unavailable:group-status-unavailable:3")
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        raw, safe = root / "mixed.xml", root / "mixed-safe.xml"
        raw.write_text("<testsuites><testsuite><testcase name=\"phase6_route_contract\"><failure/>"
                       "<system-err>" + legacy + "\n" + extended + "</system-err></testcase></testsuite></testsuites>")
        report.sanitize_ctest_junit(raw, safe)
        summary = report.summarize_sanitized_ctest_failures(safe)
        assert len(summary) == 3, summary
mixed_legacy_extended_sort()
print("mixed legacy/extended diagnostics: deterministic sanitization and summary")

def verify_false_wait_reason():
    class TimedOutProcess:
        pid = 99123
        def __init__(self): self.waits = 0
        def wait(self, timeout=None):
            self.waits += 1
            raise subprocess.TimeoutExpired("child", timeout)
        def kill(self): pass
    budget = {"remaining": 16, "attempted": 0, "last_reason": "group-inactive"}
    process = TimedOutProcess()
    with mock.patch.object(route.os, "killpg", side_effect=ProcessLookupError), \
         mock.patch.object(route, "_group_exists_with_budget", return_value=False):
        assert route._terminate_process_group(process, status_budget=budget) is False
    assert budget["last_reason"] == "group-leader-wait-unconfirmed", budget

    budget = {"remaining": 16, "attempted": 0, "last_reason": "group-inactive"}
    process = TimedOutProcess()
    with mock.patch.object(route.os, "killpg", return_value=None), \
         mock.patch.object(route, "_group_exists_with_budget", return_value=True):
        assert route._terminate_process_group(process, grace_seconds=0, status_budget=budget) is False
    assert budget["last_reason"] == "group-leader-reap-unconfirmed", budget
verify_false_wait_reason()
print("false waits: bounded leader wait/reap failures retain explicit reason enums")

def verify_darwin_presignal_status_prevents_zombie_eperm():
    class ReapedLeader:
        pid = 99125
        def __init__(self): self.waits = 0
        def wait(self, timeout=None):
            self.waits += 1
            return 0

    budget = {"remaining": 16, "attempted": 0, "last_reason": "cleanup-unclassified"}
    process = ReapedLeader()
    with mock.patch.object(route.os, "name", "posix"), \
         mock.patch.object(route.sys, "platform", "darwin"), \
         mock.patch.object(route, "_darwin_status_states",
                           side_effect=[([], True), (["Z"], True)]), \
         mock.patch.object(route.os, "killpg", side_effect=PermissionError("must not signal")) as signal_group:
        assert route._terminate_process_group(process, status_budget=budget) is True
    assert process.waits == 1, process.waits
    assert signal_group.call_count == 0, signal_group.call_count
    assert budget["attempted"] == 2 and budget["last_reason"] == "group-inactive", budget

    for remaining in (0, 1):
        budget = {"remaining": remaining, "attempted": 0, "last_reason": "cleanup-unclassified"}
        process = ReapedLeader()
        with mock.patch.object(route.os, "name", "posix"), \
             mock.patch.object(route.sys, "platform", "darwin"), \
             mock.patch.object(route, "_darwin_status_states", return_value=([], True)), \
             mock.patch.object(route.os, "killpg", side_effect=PermissionError("insufficient budget")) as signal_group:
            try:
                route._terminate_process_group(process, status_budget=budget)
            except PermissionError:
                pass
            else:
                raise AssertionError("cached absence with insufficient query budget was accepted")
        assert process.waits == 0, process.waits
        assert signal_group.call_count == 1, signal_group.call_count
        assert budget["attempted"] == 0, budget

    budget = {"remaining": 16, "attempted": 0, "last_reason": "cleanup-unclassified"}
    process = ReapedLeader()
    with mock.patch.object(route.os, "name", "posix"), \
         mock.patch.object(route.sys, "platform", "darwin"), \
         mock.patch.object(route, "_darwin_status_states", return_value=(None, True)), \
         mock.patch.object(route.os, "killpg", side_effect=ProcessLookupError) as signal_group:
        assert route._terminate_process_group(process, status_budget=budget) is True
    assert [call.args[1] for call in signal_group.call_args_list] == [
        0, route.signal.SIGTERM, 0], signal_group.call_args_list
    assert process.waits == 1 and budget["status_reason"] == "group-status-unavailable", budget

    for status_result in ((["R"], True), (None, True)):
        budget = {"remaining": 16, "attempted": 0, "last_reason": "cleanup-unclassified"}
        process = ReapedLeader()
        signal_errors = ([PermissionError("status probe"), PermissionError("signal"),
                          PermissionError("recovery probe")]
                         if status_result[0] is None else PermissionError("active group"))
        status_results = ([status_result, status_result]
                          if status_result[0] is not None else [status_result, status_result])
        with mock.patch.object(route.os, "name", "posix"), \
             mock.patch.object(route.sys, "platform", "darwin"), \
             mock.patch.object(route, "_darwin_status_states", side_effect=status_results), \
             mock.patch.object(route.os, "killpg", side_effect=signal_errors) as signal_group:
            try:
                route._terminate_process_group(process, status_budget=budget)
            except PermissionError:
                pass
            else:
                raise AssertionError("active or unknown group was treated as cleaned")
        assert signal_group.call_count >= 1
        assert process.waits == 0, process.waits

verify_darwin_presignal_status_prevents_zombie_eperm()
print("Darwin cleanup: two absent status observations plus leader reap avoid signaling; active/unknown remains unconfirmed")

def verify_darwin_term_permission_recovery_uses_fresh_status_and_reap():
    class ReapedLeader:
        pid = 99126
        def __init__(self, fail_wait=False): self.waits = 0; self.fail_wait = fail_wait
        def wait(self, timeout=None):
            self.waits += 1
            if self.fail_wait == "os-error":
                raise OSError("private wait detail")
            if self.fail_wait:
                raise subprocess.TimeoutExpired("owned leader", timeout)
            return 0

    # First observation says active, TERM receives EPERM, then two fresh
    # complete inactive observations bracket a successful leader reap.
    budget = {"remaining": 16, "attempted": 0, "last_reason": "cleanup-unclassified",
              "status_reason": "not-observed", "absent_observed": True}
    process = ReapedLeader()
    with mock.patch.object(route.os, "name", "posix"), \
         mock.patch.object(route.sys, "platform", "darwin"), \
         mock.patch.object(route, "_darwin_status_states",
                           side_effect=[(["S"], True), ([], True), (["Z"], True)]) as status, \
         mock.patch.object(route.os, "killpg", side_effect=PermissionError("private errno detail")) as signal_group:
        assert route._terminate_process_group(process, status_budget=budget) is True
    assert status.call_count == 3, status.call_count
    assert signal_group.call_count == 1 and signal_group.call_args.args[1] == route.signal.SIGTERM
    assert process.waits == 1 and budget["attempted"] == 3
    assert budget["last_reason"] == "group-inactive" and budget["status_reason"] == "group-inactive", budget

    # Permission alone, incomplete observations, exhausted budgets, a failed
    # leader reap, or activity in the second snapshot never confirms cleanup.
    scenarios = (
        ([(["S"], True), (["S"], True)], 16, False, 2, "group-reported-active", "group-reported-active"),
        ([(["S"], True), (None, True)], 16, False, 2, "group-signal-permission-denied", "group-status-unavailable"),
        ([(["S"], True), ([], True)], 1, False, 0, "cleanup-unclassified", "not-observed"),
        ([(["S"], True), ([], True), (["S"], True)], 16, False, 3, "group-reported-active", "group-reported-active"),
        ([(["S"], True), ([], True), (["Z"], True)], 16, True, 2, "group-leader-wait-unconfirmed", "group-inactive"),
        ([(["S"], True), ([], True), (["Z"], True)], 16, "os-error", 2, "group-leader-wait-unconfirmed", "group-inactive"),
    )
    for statuses, remaining, fail_wait, expected_queries, expected_reason, expected_status in scenarios:
        budget = {"remaining": remaining, "attempted": 0, "last_reason": "cleanup-unclassified",
                  "status_reason": "not-observed", "absent_observed": True}
        process = ReapedLeader(fail_wait=fail_wait)
        error = PermissionError("private errno detail")
        def group_signal(_group, sig):
            if sig == 0:
                raise PermissionError("private probe detail")
            raise error
        with mock.patch.object(route.os, "name", "posix"), \
             mock.patch.object(route.sys, "platform", "darwin"), \
             mock.patch.object(route, "_darwin_status_states", side_effect=statuses), \
             mock.patch.object(route.os, "killpg", side_effect=group_signal) as signal_group:
            try:
                route._terminate_process_group(process, status_budget=budget)
            except PermissionError as observed:
                assert observed is error
            else:
                raise AssertionError("EPERM or incomplete cleanup was treated as group absence")
        assert budget["attempted"] == expected_queries, budget
        assert budget["last_reason"] == expected_reason, budget
        assert budget["status_reason"] == expected_status, budget
        assert process.waits == (1 if fail_wait or (remaining >= 2 and len(statuses) >= 3) else 0), process.waits
        assert signal_group.call_count >= 1
    print("Darwin TERM EPERM: only fresh inactive snapshots plus leader reap confirm; all uncertain cases reject")

verify_darwin_term_permission_recovery_uses_fresh_status_and_reap()

def verify_phase5_output_cap_keeps_original_error_only_after_cleanup():
    process_module = load("scripts/evidence/phase5_process.py", "phase5_process_cap_recovery")
    baseline_contract = load("tests/evidence/phase5_baseline_contract.py",
                             "phase5_baseline_cap_recovery_contract")
    subcase = "stdout-cap"

    def invoke(statuses):
        class CapturedChild:
            calls = 0
            def __init__(self, *_args, **kwargs):
                type(self).calls += 1
                self.pid = 99127
                self.returncode = None
                out_read, out_write = os.pipe()
                os.write(out_write, b"x" * 8192)
                os.close(out_write)
                err_read, err_write = os.pipe()
                os.close(err_write)
                self.stdout = os.fdopen(out_read, "rb", buffering=0)
                self.stderr = os.fdopen(err_read, "rb", buffering=0)
                self.kill_calls = 0
                self.wait_calls = 0
            def poll(self): return None
            def wait(self, timeout=None):
                self.wait_calls += 1
                self.returncode = 0
                return 0
            def kill(self): self.kill_calls += 1

        runs = []
        caught = []
        old_context = os.environ.get("GENEWHIP_PROCESS_CONTEXT")
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = route.HOST_PROCESS_CONTEXT
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                receipt_path = root / "process.json"
                def work():
                    try:
                        with process_module.receipt_file(root, pathlib.Path("process.json")) as stream:
                            process_module.run(["fake-child", "private-argv"], cwd=root, cap=1024,
                                runs=runs, process_receipt_stream=stream)
                    except BaseException as error:
                        caught.append(error)
                worker = __import__("threading").Thread(target=work)
                with mock.patch.object(process_module, "process_boundary", return_value=route), \
                     mock.patch.object(process_module.subprocess, "Popen", CapturedChild), \
                     mock.patch.object(route.os, "name", "posix"), \
                     mock.patch.object(route.sys, "platform", "darwin"), \
                     mock.patch.object(route, "_darwin_status_states", side_effect=statuses), \
                     mock.patch.object(route.os, "killpg", side_effect=PermissionError("private EPERM")) as killpg:
                    worker.start(); worker.join(timeout=5)
                    assert not worker.is_alive(), "bounded fake Phase 5 invocation did not settle"
                assert len(caught) == 1 and isinstance(caught[0], process_module.ProcessCaptureError), caught
                return caught[0], dict(runs[-1]), json.loads(receipt_path.read_text()), CapturedChild.calls, killpg.call_count
        finally:
            if old_context is None:
                os.environ.pop("GENEWHIP_PROCESS_CONTEXT", None)
            else:
                os.environ["GENEWHIP_PROCESS_CONTEXT"] = old_context

    confirmed_error, confirmed_row, confirmed_saved, confirmed_starts, confirmed_signals = invoke(
        [(["S"], True), ([], True), (["Z"], True)])
    assert "bounded process output byte cap" in str(confirmed_error), confirmed_error
    assert confirmed_row["process_group_cleanup"] == "confirmed", confirmed_row
    assert confirmed_row.get("returncode") is None
    assert not {"cleanup_reason", "cleanup_status_observation", "cleanup_observation_attempts"} & set(confirmed_row)
    assert confirmed_saved["processes"][0]["process_group_cleanup"] == "confirmed"
    assert confirmed_starts == 1 and confirmed_signals == 1

    failed_error, failed_row, failed_saved, failed_starts, failed_signals = invoke(
        [(["S"], True), (["S"], True)])
    assert "cleanup unconfirmed" in str(failed_error), failed_error
    assert failed_row["failure_type"] == "ValueError", failed_row
    assert failed_row["process_group_cleanup"] == "unconfirmed"
    assert failed_row["cleanup_error"] == "PermissionError"
    assert failed_row["cleanup_reason"] == "cleanup-permission-denied"
    assert failed_row["cleanup_status_observation"] == "group-reported-active"
    assert failed_row["cleanup_observation_attempts"] == 2
    assert failed_saved["processes"][0] == failed_row
    assert failed_starts == 1 and failed_signals == 1

    diagnostic = baseline_contract.safe_process_diagnostic(
        subcase, [failed_row], 0, failed_error)
    diagnostic["pid_private"] = "must-not-emit"
    class BaselineRecordContract:
        _testMethodName = "test_real_process_output_cap_timeout_and_status"
    test = BaselineRecordContract()
    test._phase5_process_diagnostic = diagnostic
    result = type("Result", (), {"failures": [(test, (ValueError, failed_error, None))], "errors": []})()
    output = io.StringIO()
    with contextlib.redirect_stderr(output):
        baseline_contract.emit_safe_failure_diagnostics(result)
    emitted = output.getvalue().strip()
    assert emitted.endswith(":cleanup-unconfirmed:cleanup-permission-denied:group-reported-active:2"), emitted
    for secret in ("private-argv", "private EPERM", "must-not-emit", str(failed_row.get("pid"))):
        assert secret not in emitted, emitted
    print("Phase 5 finally: output-cap preserved only after complete cleanup; unconfirmed cleanup overrides and emits bounded enums")

verify_phase5_output_cap_keeps_original_error_only_after_cleanup()

def verify_status_probe_permission_reason():
    budget = {"remaining": 16, "attempted": 0, "last_reason": "cleanup-unclassified"}
    with mock.patch.object(route.sys, "platform", "freebsd"), \
         mock.patch.object(route.os, "killpg", side_effect=PermissionError("probe denied")):
        assert route._process_group_exists(99124, status_budget=budget) is True
    assert budget["last_reason"] == "group-signal-permission-denied", budget
verify_status_probe_permission_reason()
print("status probe: exact killpg permission failure retains its specific enum")

def verify_reason_pipeline():
    method = f"NativeParserContract.{METHOD}"
    for reason in ("cleanup-permission-denied", "group-cleanup-os-error",
                   "group-signal-permission-denied",
                   "group-leader-wait-unconfirmed", "group-leader-reap-unconfirmed"):
        case_type = type("NativeParserContract", (unittest.TestCase,), {METHOD: lambda self: None})
        case = case_type(METHOD)
        result = route.SafeDiagnosticTextTestResult(io.StringIO(), True, 1)
        result.startTest(case)
        case.runs = [{"process_group_cleanup": "unconfirmed", "cleanup_reason": reason,
                      "cleanup_status_observation": reason, "cleanup_observation_attempts": 2}]
        result.addFailure(case, (AssertionError, AssertionError("private"), None))
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream):
            route._emit_safe_failure_diagnostics(result)
        line = stream.getvalue().strip()
        assert line.endswith(f":{reason}:{reason}:2"), line
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            raw, safe = root / "raw.xml", root / "safe.xml"
            raw.write_text("<testsuites><testsuite><testcase name=\"phase6_route_contract\"><failure/>"
                           "<system-err>" + line + "</system-err></testcase></testsuite></testsuites>")
            report.sanitize_ctest_junit(raw, safe)
            summary = report.summarize_sanitized_ctest_failures(safe)
            assert any(f"cleanup_reason={reason}; status_observation={reason}" in item for item in summary), summary
    case_type = type("NativeParserContract", (unittest.TestCase,), {METHOD: lambda self: None})
    unknown = case_type(METHOD)
    result = route.SafeDiagnosticTextTestResult(io.StringIO(), True, 1)
    result.startTest(unknown)
    unknown.runs = [{"process_group_cleanup": "unconfirmed", "cleanup_reason": "private-reason"}]
    result.addFailure(unknown, (AssertionError, AssertionError("private"), None))
    stream = io.StringIO()
    with contextlib.redirect_stderr(stream):
        route._emit_safe_failure_diagnostics(result)
    assert "private-reason" not in stream.getvalue() and ":other:" in stream.getvalue(), stream.getvalue()
verify_reason_pipeline()
print("reason pipeline: new enums survive emitter and JUnit sanitizer; unknown reason remains other")
