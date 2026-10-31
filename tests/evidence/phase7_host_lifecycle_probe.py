#!/usr/bin/env python3
"""Finite benign actual-host diagnostic; invoke only through reviewed host admission.

No guest data or descendants. Default invocation refuses before any process start.
The CLI flag records selection, not OS permission: execution requires the host tool
approval separately. Result is diagnostic only, never historical settlement.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(stream, value):
    json.dump(value, stream, sort_keys=True, indent=2)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--actual-host-reviewed", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not args.actual_host_reviewed:
        parser.error("actual-host-tool-approval-required: zero starts")
    # This marker is necessary for the imported helper, never sufficient host admission.
    os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    helper = load("scripts/evidence/phase5_process.py", "probe_receipts")
    route = helper.process_boundary()
    args.out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    results = []
    sources = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in (
        "tests/session/phase6_route_contract.py", "scripts/evidence/phase5_process.py",
        "tests/evidence/phase7_host_lifecycle_probe.py")}
    for name in ("normal", "timeout-kill", "durable-sink-error"):
        runs, signals = [], []
        birth_written = False
        injected = False
        original_killpg = route.os.killpg

        def observe_signal(pgid, sig):
            if sig != 0:
                signals.append({"pgid": pgid, "signal": int(sig)})
            return original_killpg(pgid, sig)

        with helper.receipt_file(args.out, Path(name + "-ownership.json")) as sink:
            class DurableSink:
                def __getattr__(self, key):
                    return getattr(sink, key)

                def flush(self):
                    nonlocal birth_written, injected
                    sink.flush()
                    os.fsync(sink.fileno())
                    if runs and runs[0].get("status") == "started" and not birth_written:
                        pid = runs[0]["pid"]
                        # Status-only birth identity; no argv or private host details.
                        observed = subprocess.run(["/bin/ps", "-p", str(pid), "-o",
                            "pid=,pgid=,lstart=,stat="], capture_output=True, text=True,
                            timeout=1, check=True).stdout.strip()
                        parts = observed.split()
                        assert len(parts) >= 8 and int(parts[0]) == pid and int(parts[1]) == pid
                        with helper.receipt_file(args.out, Path(name + "-birth.json")) as birth:
                            write(birth, {"pid": pid, "pgid": pid, "status_identity": observed,
                                "ownership_durable_before_monitor": True})
                        birth_written = True
                        if name == "durable-sink-error" and not injected:
                            injected = True
                            raise OSError("intentional-after-durable-ownership")

            code = "import signal,time; signal.alarm(6); "
            code += ("signal.signal(signal.SIGTERM,signal.SIG_IGN); " if name == "timeout-kill" else "")
            code += "time.sleep(" + ("0.15" if name == "normal" else "4") + ")"
            error = None
            result = None
            route.os.killpg = observe_signal
            try:
                result = route._run_client(Path(sys.executable), [sys.executable, "-I", "-c", code],
                    runs, report=args.out / (name + "-unused.json"), timeout=0.5,
                    process_receipt_stream=DurableSink())
            except OSError as caught:
                error = str(caught)
            finally:
                route.os.killpg = original_killpg
            assert birth_written and len(runs) == 1
            entry = runs[0]
            assert entry["process_group_cleanup"] == "confirmed", "unconfirmed cleanup: stop"
            if name == "normal":
                assert result.returncode == 0 and entry["status"] == "completed"
            elif name == "timeout-kill":
                assert result.returncode == -signal.SIGKILL and entry["bound_violation"]
                assert [s["signal"] for s in signals] == [signal.SIGTERM, signal.SIGKILL]
            else:
                assert error == "intentional-after-durable-ownership" and entry["status"] == "exception"
                assert signals and signals[0]["signal"] == signal.SIGTERM
            assert all(s["pgid"] == entry["pgid"] for s in signals)
            results.append({"case": name, "process": entry, "signals": signals,
                            "expected_error": error, "passed": True})
    with helper.receipt_file(args.out, Path("result.json")) as stream:
        write(stream, {"schema": "genewhip-benign-host-lifecycle-v1", "cases": results,
            "source_sha256": sources, "wall_seconds": time.monotonic() - started,
            "historical_identity": "UNKNOWN", "historical_liveness": "UNKNOWN",
            "independent_settlement": "pending"})
    print("benign-host-lifecycle: 3/3; independent settlement pending")


if __name__ == "__main__":
    main()
