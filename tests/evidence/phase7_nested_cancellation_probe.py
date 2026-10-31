#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepared single benign C→A→B cancellation diagnostic; no live run admitted.

The controller uses phase5_process.run; supervisor A uses the existing scoped
desktop run→shared _run_client path; silent B has no children. Only the guest
command is substituted. The explicit CLI selection flag is necessary, never OS
tool approval. Future host admission must review exact bytes and limitations.
"""
from __future__ import annotations

import importlib.util
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
SCOPE_ID = "phase7-benign-nested-cancellation-preparation-v1"
CAP = 65536
DISK_CAP = 1048576
TOTAL_SECONDS = 60
OUTER_SECONDS = 38
INNER_SECONDS = 20
GATE_SECONDS = 5
READY_SECONDS = 8
STATUS_SECONDS = .25
LIMITS = {
    "wall_seconds": INNER_SECONDS, "cleanup_grace_seconds": .25,
    "max_rss_bytes": 268435456, "max_stdout_stderr_bytes": CAP,
    "max_json_bytes": CAP, "max_binary_file_bytes": CAP,
    "max_capture_bytes": CAP, "max_scratch_bytes": DISK_CAP,
    "max_retained_bytes": CAP, "max_fields": 1, "max_calls": 1,
}
SCOPE = {"schema": "genewhip-benign-nested-diagnostic-v1", "scope_id": SCOPE_ID,
         "historical_window_access": False, "per_child_limits": LIMITS}


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(stream, value):
    encoded = json.dumps(value, sort_keys=True, indent=2) + "\n"
    if len(encoded.encode()) > CAP:
        raise ValueError("diagnostic-receipt-byte-cap")
    stream.seek(0)
    stream.write(encoded)
    stream.truncate()
    stream.flush()
    os.fsync(stream.fileno())


def read(root, name):
    path = root / name
    if not path.exists():
        return None
    info = path.lstat()
    if (path.is_symlink() or not path.is_file() or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_size > CAP):
        raise ValueError("unsafe-diagnostic-receipt")
    try:
        return json.loads(path.read_bytes())
    except json.JSONDecodeError:
        # A concurrent in-place fsynced sink is not yet a readiness message.
        return None


def check_disk(root):
    total = 0
    for path in root.iterdir():
        info = path.lstat()
        if (path.is_symlink() or not path.is_file() or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_size > CAP):
            raise ValueError("unsafe-diagnostic-owned-root")
        total += info.st_size
    if total > DISK_CAP:
        raise ValueError("diagnostic-owned-root-byte-cap")
    return total


def publish(helper, root, name, value):
    with helper.receipt_file(root, Path(name)) as stream:
        write(stream, value)
    check_disk(root)


def owned(document):
    rows = document.get("processes", []) if isinstance(document, dict) else []
    if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
            or type(rows[0].get("pid")) is not int or type(rows[0].get("pgid")) is not int
            or rows[0]["pid"] <= 1 or rows[0]["pgid"] != rows[0]["pid"]):
        raise ValueError("diagnostic-exact-ownership-required")
    return rows[0]


def observe(entry):
    """Status-only observer independent of either helper's cleanup assertion."""
    pid = owned({"processes": [entry]})["pid"]
    result = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "pid=,pgid=,lstart=,stat="],
                            capture_output=True, text=True, timeout=STATUS_SECONDS, check=False)
    if len(result.stdout.encode()) + len(result.stderr.encode()) > 4096:
        raise ValueError("observer-output-byte-cap")
    if result.returncode == 1 and not result.stdout.strip():
        # Query the entire group too: absent leader alone cannot settle a group.
        groups = subprocess.run(["/bin/ps", "-axo", "pgid=,stat="], capture_output=True,
                                text=True, timeout=STATUS_SECONDS, check=False)
        if groups.returncode != 0 or len(groups.stdout.encode()) > CAP:
            raise ValueError("observer-group-query-unavailable")
        states = []
        for line in groups.stdout.splitlines():
            parts = line.split()
            if len(parts) != 2 or not parts[0].isdigit():
                raise ValueError("observer-group-query-ambiguous")
            if int(parts[0]) == pid:
                states.append(parts[1])
        return {"pid": pid, "pgid": pid, "state": "absent" if not states else "group-remains"}
    parts = result.stdout.split()
    if (result.returncode != 0 or len(parts) != 8
            or parts[0] != str(pid) or parts[1] != str(pid)):
        raise ValueError("observer-identity-ambiguous")
    return {"pid": pid, "pgid": pid, "birth": " ".join(parts[2:7]),
            "state": "zombie" if parts[7].startswith("Z") else "active"}


def same_active(observation, birth):
    return (isinstance(observation, dict) and isinstance(birth, dict)
            and observation == birth and observation.get("state") == "active")


def wait_record(root, name, deadline, stop=None):
    while time.monotonic() < deadline:
        if stop is not None and stop.is_set():
            raise InterruptedError("controller-stopped")
        check_disk(root)
        value = read(root, name)
        if value is not None:
            return value
        time.sleep(.02)
    raise TimeoutError("diagnostic-readiness-deadline:" + name)


def supervisor(root):
    """A begins at a bounded gate. It cannot start B before C's durable A birth."""
    signal.alarm(35)
    helper = load("scripts/evidence/phase5_process.py", "nested_A_receipts")
    prior = signal.getsignal(signal.SIGTERM)
    gate = wait_record(root, "release-A.json", time.monotonic() + GATE_SECONDS)
    a = owned(read(root, "A-ownership.json"))
    if gate != {"pid": os.getpid(), "scope_id": SCOPE_ID} or a["pid"] != os.getpid():
        raise ValueError("outer-gate-ownership-mismatch")
    desktop = load("tests/desktop/phase4_sessions.py", "nested_A_desktop")
    desktop.EXECUTION_SCOPE = SCOPE
    desktop.PROCESS_RECEIPTS = []
    outcome = {"status": "non-qualifying", "cancellation_acknowledged": False}
    def inner_owned(entry):
        # The shared client invokes this after its ownership fsync returns.
        birth = observe(entry)
        if birth["state"] != "active":
            raise ValueError("inner-not-active-at-birth")
        publish(helper, root, "B-durable.json", {"processes": [entry.copy()], "birth": birth})
    try:
        # --dump-audio supplies the existing wrapper's owned scratch root; B
        # ignores this benign argument and writes no audio or guest data.
        result = desktop.run([sys.executable, "-I", str(Path(__file__).resolve()),
                              "--actual-host-reviewed", "--leaf", str(root),
                              "--dump-audio", root / "unused.pcm"],
                             dict(os.environ), timeout=INNER_SECONDS, ownership_callback=inner_owned)
        outcome["returncode"] = result.returncode
    except KeyboardInterrupt:
        outcome.update(status="cancelled", cancellation_acknowledged=True)
    except BaseException as error:
        outcome["failure_type"] = type(error).__name__
    finally:
        outcome["handler_restored"] = signal.getsignal(signal.SIGTERM) is prior
        outcome["processes"] = desktop.PROCESS_RECEIPTS
        publish(helper, root, "A-outcome.json", outcome)
        signal.alarm(0)
    # The diagnostic's intended subject result is terminal and non-pass.
    return 130 if outcome["status"] == "cancelled" else 1


def leaf(root):
    signal.alarm(12)
    helper = load("scripts/evidence/phase5_process.py", "nested_B_receipts")
    publish(helper, root, "B-ready.json", {"pid": os.getpid(), "scope_id": SCOPE_ID})
    # Finite, silent, no descendants, no emulator command or ROM.
    time.sleep(10)
    return 1


def oracle(packet):
    """Conjunction of independent facts; no helper return or signal is a pass."""
    try:
        a, b = owned(packet["A"]), owned(packet["B"])
        outcome, attempt = packet["A_outcome"], packet["signal_attempt"]
        return (a["pid"] != b["pid"] and packet["scope"] == SCOPE
                and 0 <= packet["wall_seconds"] <= TOTAL_SECONDS
                and 0 <= packet["root_bytes"] <= DISK_CAP and packet["errors"] == []
                and packet["outer_returncode"] == 130 and a["status"] == "completed"
                and a["process_group_cleanup"] == "confirmed"
                and b["status"] == "exception" and b["failure_type"] == "KeyboardInterrupt"
                and b["bound_violation"] is True and b["process_group_cleanup"] == "confirmed"
                and outcome["processes"] == packet["B"]["processes"]
                and outcome["status"] == "cancelled"
                and outcome["cancellation_acknowledged"] is True
                and outcome["handler_restored"] is True
                and packet["outer_handler_restored"] is True
                and attempt == {"pgid": a["pgid"], "signal": int(signal.SIGTERM),
                                "attempted": True, "call_returned": True}
                and same_active(packet["A_before_signal"], packet["A_birth"])
                and same_active(packet["B_before_signal"], packet["B_birth"])
                and packet["A_birth"]["pid"] == packet["A_birth"]["pgid"] == a["pid"]
                and packet["B_birth"]["pid"] == packet["B_birth"]["pgid"] == b["pid"]
                and packet["B_ready"] == {"pid": b["pid"], "scope_id": SCOPE_ID}
                and packet["A_settlement"] == {"pid": a["pid"], "pgid": a["pgid"], "state": "absent"}
                and packet["B_settlement"] == {"pid": b["pid"], "pgid": b["pgid"], "state": "absent"})
    except (KeyError, TypeError, ValueError):
        return False


def controller(root):
    """Prepared callable; no actual-host admission is provided by this task.

    C watchdog is separate from the helpers under test; deadline observation
    cannot interrupt an indefinitely blocked kernel operation. No retries.
    """
    started = time.monotonic()
    deadline = started + TOTAL_SECONDS
    helper = load("scripts/evidence/phase5_process.py", "nested_C_outer")
    helper.process_boundary().require_host_process_context()
    if (root.is_symlink() or not root.is_dir() or root.stat().st_uid != os.getuid()
            or any(root.iterdir())):
        raise ValueError("diagnostic-empty-owned-root-required")
    packet = {"scope": SCOPE, "errors": [], "signal_attempt": {"attempted": False}}
    stop = threading.Event()
    released = threading.Event()
    prior = signal.getsignal(signal.SIGTERM)

    def release(receipt):
        # run invokes this only after fsync of the exact ownership sink.
        a = owned(read(root, "A-ownership.json"))
        if a != receipt:
            raise ValueError("outer-durable-birth-mismatch")
        packet["A_birth"] = observe(a)
        if packet["A_birth"]["state"] != "active":
            raise ValueError("outer-not-active-at-birth")
        publish(helper, root, "release-A.json", {"pid": a["pid"], "scope_id": SCOPE_ID})
        released.set()

    def watchdog():
        try:
            ready_deadline = min(deadline, started + READY_SECONDS)
            while not released.wait(.02):
                if stop.is_set():
                    return
                if time.monotonic() >= ready_deadline:
                    raise TimeoutError("outer-gate-not-released")
            b_doc = wait_record(root, "B-durable.json", ready_deadline, stop)
            b = owned(b_doc)
            if b["status"] != "started":
                raise ValueError("inner-not-active-at-cancellation")
            packet["B_ready"] = wait_record(root, "B-ready.json", ready_deadline, stop)
            if packet["B_ready"] != {"pid": b["pid"], "scope_id": SCOPE_ID}:
                raise ValueError("inner-readiness-identity-mismatch")
            a = owned(read(root, "A-ownership.json"))
            packet["B_birth"] = b_doc["birth"]
            packet["A_before_signal"] = observe(a)
            packet["B_before_signal"] = observe(b)
            if (a["pid"] == b["pid"] or not same_active(packet["A_before_signal"], packet["A_birth"])
                    or not same_active(packet["B_before_signal"], packet["B_birth"])):
                raise ValueError("pre-signal-identity-ambiguous")
            if stop.is_set() or time.monotonic() >= ready_deadline:
                raise TimeoutError("cancellation-deadline")
            packet["signal_attempt"] = {"pgid": a["pgid"], "signal": int(signal.SIGTERM),
                                        "attempted": True, "call_returned": False}
            os.killpg(a["pgid"], signal.SIGTERM)
            packet["signal_attempt"]["call_returned"] = True
            if not stop.wait(max(0, deadline - time.monotonic())):
                raise TimeoutError("independent-controller-deadline")
        except BaseException as error:
            packet["errors"].append("watchdog:" + type(error).__name__)

    watcher = threading.Thread(target=watchdog, name="nested-C-watchdog", daemon=True)
    watcher.start()
    try:
        try:
            with helper.receipt_file(root, Path("A-ownership.json")) as sink:
                result = helper.run([sys.executable, "-I", str(Path(__file__).resolve()),
                                     "--actual-host-reviewed", "--supervisor", str(root)],
                                    cwd=root, timeout=OUTER_SECONDS,
                                    cap=CAP, process_receipt_stream=sink, ownership_callback=release)
                packet["outer_returncode"] = result.returncode
        except BaseException as error:
            packet["errors"].append("outer:" + type(error).__name__)
        finally:
            packet["outer_handler_restored"] = signal.getsignal(signal.SIGTERM) is prior
        for label, name in (("A", "A-ownership.json"), ("B", "bounded-child-process-0000.json")):
            try:
                packet[label] = read(root, name)
                packet[label + "_settlement"] = observe(owned(packet[label]))
            except BaseException as error:
                packet["errors"].append(label + ":" + type(error).__name__)
        packet["A_outcome"] = read(root, "A-outcome.json")
        packet["root_bytes"] = check_disk(root)
        packet["wall_seconds"] = time.monotonic() - started
        packet["diagnostic_qualifying"] = oracle(packet)
        packet["historical_identity"] = packet["historical_liveness"] = "UNKNOWN"
        publish(helper, root, "controller-result.json", packet)
    finally:
        # Keep the independent watchdog active through settlement and fsync.
        stop.set()
        watcher.join(timeout=1)
        if watcher.is_alive():
            packet["errors"].append("watchdog-unsettled")
    packet["wall_seconds"] = time.monotonic() - started
    packet["root_bytes"] = check_disk(root)
    packet["diagnostic_qualifying"] = oracle(packet)
    # Final closeout may update elapsed time/errors, never retry the case.
    with helper.receipt_file(root, Path("controller-result.json"), replace=True) as stream:
        write(stream, packet)
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actual-host-reviewed", action="store_true")
    role = parser.add_mutually_exclusive_group(required=True)
    role.add_argument("--controller", type=Path)
    role.add_argument("--supervisor", type=Path)
    role.add_argument("--leaf", type=Path)
    parser.add_argument("--dump-audio")  # existing scoped wrapper scratch-path argument
    # Refuse before role dispatch, import, mkdir, alarm or child creation.
    if "--actual-host-reviewed" not in sys.argv[1:]:
        raise SystemExit("preparation-only: no actual-host entry admitted; zero starts")
    args = parser.parse_args()
    if args.controller is not None:
        return 0 if controller(args.controller)["diagnostic_qualifying"] else 1
    if args.supervisor is not None:
        return supervisor(args.supervisor)
    return leaf(args.leaf)


if __name__ == "__main__":
    raise SystemExit(main())
