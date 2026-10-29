#!/usr/bin/env python3
"""Authoritative D128 test entry: pinned stdlib admission precedes tests."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import unittest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pin", required=True)
    parser.add_argument("--pin-sha256", required=True)
    parser.add_argument("--variant", choices=("red", "green"), required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[2]
    # Bootstrap helper is stdlib-only and independently source reviewed before use.
    pin_bytes = (root / args.pin).read_bytes()
    if hashlib.sha256(pin_bytes).hexdigest() != args.pin_sha256:
        raise RuntimeError("d128-entry-pin-digest-invalid")
    pin = json.loads(pin_bytes)
    source = root / "scripts/evidence/d128_seam.py"
    if source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest() != pin["inventory"][args.variant]["scripts/evidence/d128_seam.py"]:
        raise RuntimeError("d128-entry-helper-stale")
    spec = importlib.util.spec_from_file_location("d128_lifecycle", source)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    boot = helper.host_boot()
    admission = helper.admit(root, args.pin, args.pin_sha256, args.variant, time.monotonic(), boot,
                             observer=helper.observe)
    attempts = []
    def deny(event, arguments):
        if event in {"subprocess.Popen", "os.system", "os.exec", "os.fork", "os.forkpty", "os.posix_spawn", "os.spawn"}:
            attempts.append(event)
            raise RuntimeError("d128-process-denied:" + event)
    cached_popen, cached_system = subprocess.Popen, os.system
    sys.addaudithook(deny)
    for event in ("subprocess.Popen", "os.system", "os.exec", "os.fork", "os.forkpty", "os.posix_spawn", "os.spawn"):
        before = len(attempts)
        try:
            sys.audit(event, "d128-denial-probe")
        except RuntimeError:
            pass
        if len(attempts) != before + 1:
            raise RuntimeError("d128-audit-denial-missing")
    for callback in (lambda: cached_popen(["d128-forbidden"]), lambda: cached_system("d128-forbidden")):
        before = len(attempts)
        try:
            callback()
        except RuntimeError as exc:
            if "d128-process-denied" not in str(exc):
                raise
        if len(attempts) != before + 1:
            raise RuntimeError("d128-cached-api-denial-missing")
    def blocked(*_a, **_kw):
        attempts.append("direct-api")
        raise RuntimeError("d128-process-denied:direct-api")
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        setattr(subprocess, name, blocked)
    for name in dir(os):
        if name in {"system", "popen", "startfile"} or name.startswith(("fork", "spawn", "exec", "posix_spawn")):
            if callable(getattr(os, name)):
                setattr(os, name, blocked)
    # Admission and all denial probes are complete before the test module loads.
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("d128-55-second-deadline")))
    signal.alarm(55)
    started = time.monotonic()
    spec = importlib.util.spec_from_file_location("d128_tests", root / "tests/evidence/test_d128_seam.py")
    module = importlib.util.module_from_spec(spec)
    module.HELPER = helper
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    result = unittest.TestResult()
    suite.run(result)
    signal.alarm(0)
    report = {"variant": args.variant, "admission": admission,
              "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "failure_messages": [{"test": str(test), "message": text} for test, text in result.failures],
              "error_messages": [{"test": str(test), "message": text} for test, text in result.errors],
              "process_denial_probes": 9, "unexpected_process_requests": len(attempts) - 9,
              "elapsed_seconds": time.monotonic() - started,
              "retained_synthetic_roots": module.RETAINED_ROOTS}
    helper.write(helper.safe(root, args.output), helper.encode(report), once=True)
    print(json.dumps(report))
    return 0 if result.wasSuccessful() and len(attempts) == 9 else 1


if __name__ == "__main__":
    sys.exit(main())
