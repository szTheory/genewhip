#!/usr/bin/env python3
"""Bounded D128 admission/terminal seam; stdlib only, no workload launcher.

Lock/revalidation and durable intent/create-once publication follow reviewed
Plan25 G02/G03 and G04 algorithms, with narrow D128 authority and bindings.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import pathlib
import stat
import subprocess
import tempfile
import time
import uuid

BASELINE = "1997aa8e4b9268b8c5beca4741ceb2ea5d9aecc608aac995cc4704af1180b1b6"
FLOOR = 44323.64335841696
START = 438541.297958625
PREFIX = 300.0
BOOT = "boot-session:2493cd26-ed27-49e3-ba91-bc1afadea884"
PURPOSE = "D128-admission-forecast-wr01-seam"
OWNER = "06-D128-seam-debug"
CAP = 3600.0
GLOBAL = 57600.0
TERMINAL = 600.0
PROCESS = 1794.135
KEY = "d128_admission_wr01"
LEDGER = "evidence/phase6-repairs.json"
RECEIPT = "evidence/phase6-d128-seam-close.json"
AUTHORITY = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D128-APPROVAL.json"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise RuntimeError("d128-nonfinite-or-nonnumeric")
    return float(value)


def host_boot():
    result = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
                            check=True, capture_output=True, text=True, timeout=5)
    return "boot-session:" + str(uuid.UUID(result.stdout.strip())).lower()


def observe():
    return time.monotonic(), host_boot()


def safe(root, relative):
    path = root / relative
    if pathlib.Path(relative).is_absolute() or ".." in pathlib.Path(relative).parts:
        raise RuntimeError("d128-path-escape")
    for component in (path, *path.parents):
        if component == root.parent:
            break
        if component.is_symlink():
            raise RuntimeError("d128-symlink-denied")
    if path.parent.resolve(strict=True) != path.parent:
        raise RuntimeError("d128-parent-escape")
    return path


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write(path, payload, once=False):
    fd, name = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    tmp = pathlib.Path(name)
    try:
        if path.exists() and not once:
            os.fchmod(fd, stat.S_IMODE(path.stat().st_mode))
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if once:
            os.link(tmp, path, follow_symlinks=False)
        else:
            os.replace(tmp, path)
        sync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


@contextlib.contextmanager
def locked(root):
    ledger = safe(root, LEDGER)
    lock = pathlib.Path(tempfile.gettempdir()) / ("genewhip-phase6-accounting-" + sha(str(ledger).encode()) + ".lock")
    fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield ledger
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def bindings(root, pin_relative, pin_digest, variant, boot):
    """Called under ledger lock; pin is parent-observed independent decision."""
    raw = safe(root, pin_relative).read_bytes()
    if sha(raw) != pin_digest:
        raise RuntimeError("d128-pin-stale")
    pin = json.loads(raw)
    if (pin.get("decision") != "ACCEPT" or pin.get("blocking_findings") != 0 or
            pin.get("reviewer_terminal_status") != "completed" or
            not pin.get("reviewer_identity") or pin.get("boot_identity") != boot):
        raise RuntimeError("d128-independent-pin-invalid")
    inventory = pin["inventory"][variant]
    required = {"scripts/evidence/d128_seam.py", "tests/evidence/d128_guard.py",
                "tests/evidence/test_d128_seam.py", "scripts/evidence/phase6_accounting.py",
                "tests/evidence/test_engineering25_accounting.py", AUTHORITY,
                ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D128-AMENDMENT.md",
                pin["review_path"]}
    if set(inventory) != required:
        raise RuntimeError("d128-inventory-incomplete")
    for relative, digest in inventory.items():
        if sha(safe(root, relative).read_bytes()) != digest:
            raise RuntimeError("d128-source-or-authority-stale:" + relative)
    authority = json.loads(safe(root, AUTHORITY).read_bytes())
    if (authority.get("decision") != "approved" or authority.get("purpose") != PURPOSE or
            authority.get("baseline_ledger_sha256") != BASELINE or
            authority.get("purpose_cap_seconds") != CAP or authority.get("global_cap_seconds") != GLOBAL or
            authority.get("terminal_reserve_seconds") != TERMINAL or
            authority.get("protected_process_seconds") != PROCESS or
            authority.get("workloads_authorized") is not False or
            authority.get("amendment_sha256") != inventory[".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D128-AMENDMENT.md"]):
        raise RuntimeError("d128-authority-invalid")
    return {"pin_path": pin_relative, "pin_sha256": pin_digest,
            "authority_sha256": inventory[AUTHORITY], "variant": variant}


def headroom(state, now, boot, exposure):
    if state.get("status") != "active" or state.get("purpose") != PURPOSE or boot != state.get("boot_identity"):
        raise RuntimeError("d128-owner-terminal-or-boot-stale")
    elapsed = number(now) - number(state["started_monotonic"])
    if elapsed < 0:
        raise RuntimeError("d128-clock-rollback")
    charge = PREFIX + elapsed
    forecasts = [number(v) for v in state["remaining_forecast"].values()]
    if not forecasts or any(v < 0 for v in forecasts):
        raise RuntimeError("d128-invalid-complete-forecast")
    remaining = sum(forecasts)
    exposure = number(exposure)
    if exposure <= 0 or exposure > remaining:
        raise RuntimeError("d128-invalid-batch-exposure")
    if CAP - charge < remaining + TERMINAL or GLOBAL - FLOOR - charge < remaining + TERMINAL + PROCESS:
        raise RuntimeError("d128-complete-forecast-denied")
    return {"charge_seconds": charge, "remaining_forecast_seconds": remaining,
            "purpose_remaining_seconds": CAP - charge, "global_remaining_seconds": GLOBAL - FLOOR - charge,
            "batch_exposure_seconds": exposure}


def install(root, pin, pin_sha, now, boot, observer=None):
    with locked(root) as ledger:
        if observer is not None:
            now, boot = observer()
        binding = bindings(root, pin, pin_sha, "red", boot)
        before = ledger.read_bytes()
        if boot != BOOT or sha(before) != BASELINE:
            raise RuntimeError("d128-bootstrap-baseline-or-boot-stale")
        value = json.loads(before)
        if KEY in value:
            raise RuntimeError("d128-purpose-already-created")
        state = {"purpose": PURPOSE, "owner": OWNER, "status": "active", "boot_identity": boot,
                 "started_monotonic": START, "baseline_ledger_sha256": BASELINE,
                 "global_floor_seconds": FLOOR, "purpose_cap_seconds": CAP,
                 "terminal_reserve_seconds": TERMINAL, "protected_process_seconds": PROCESS,
                 "entry_binding": binding, "active_anchor": {"monotonic": START, "boot_identity": boot},
                 "remaining_forecast": {"seam": 600.0, "review_handoff": 600.0, "uncertainty": 300.0},
                 "completed_forecast": [{"row": "bootstrap_binding", "seconds": 900.0,
                    "basis": "Entry and terminal paths prepared and independently source-reviewed; exact authority/source bindings checked under lock", "pin_sha256": pin_sha}],
                 "admissions": []}
        state["entry_admission"] = headroom(state, now, boot, 55.0)
        bindings(root, pin, pin_sha, "red", boot)
        if observer is not None:
            now, boot = observer()
            if boot != BOOT:
                raise RuntimeError("d128-boot-changed-under-lock")
            state["entry_admission"] = headroom(state, now, boot, 55.0)
        if ledger.read_bytes() != before:
            raise RuntimeError("d128-bootstrap-ledger-changed")
        value[KEY] = state
        write(ledger, encode(value))
        return state


def admit(root, pin, pin_sha, variant, now, boot, exposure=55.0, observer=None):
    with locked(root) as ledger:
        if observer is not None:
            now, boot = observer()
        binding = bindings(root, pin, pin_sha, variant, boot)
        value = json.loads(ledger.read_bytes())
        state = value[KEY]
        if binding["authority_sha256"] != state["entry_binding"]["authority_sha256"]:
            raise RuntimeError("d128-entry-authority-stale")
        bindings(root, pin, pin_sha, variant, boot)
        if observer is not None:
            now, boot = observer()
        result = headroom(state, now, boot, exposure)
        result.update(binding)
        state["admissions"].append(result)
        write(ledger, encode(value))
        return result


def retire_seam(root, pin, pin_sha, report_relative, now, boot, observer=None):
    """Retire only the named seam row after its guarded successful denominator."""
    with locked(root) as ledger:
        if observer is not None:
            now, boot = observer()
        bindings(root, pin, pin_sha, "green", boot)
        value = json.loads(ledger.read_bytes())
        state = value[KEY]
        headroom(state, now, boot, 1.0)
        raw = safe(root, report_relative).read_bytes()
        report = json.loads(raw)
        if (report.get("variant") != "green" or report.get("failures") != 0 or report.get("errors") != 0 or
                report.get("unexpected_process_requests") != 0 or report.get("process_denial_probes") != 9 or
                type(report.get("tests_run")) is not int or report["tests_run"] < 9 or
                report.get("admission") not in state["admissions"] or
                report["admission"].get("pin_sha256") != pin_sha or
                state["remaining_forecast"].get("seam") != 600.0):
            raise RuntimeError("d128-seam-completion-evidence-invalid")
        del state["remaining_forecast"]["seam"]
        state.setdefault("completed_forecast", []).append({"row": "seam", "seconds": 600.0,
            "basis": "Guarded named synthetic seam denominator completed successfully; no broader delivery credit",
            "evidence_path": report_relative, "evidence_sha256": sha(raw)})
        write(ledger, encode(value))
        return state["completed_forecast"][-1]


def close(root, now, boot, status, reason, final_path=None, final_sha=None, observer=None):
    """Also records bootstrap refusal under a separate closed debug charge."""
    if status not in ("HALTED", "accepted-seam") or not reason:
        raise RuntimeError("d128-terminal-status-or-reason-invalid")
    with locked(root) as ledger:
        if observer is not None:
            now, boot = observer()
        raw = ledger.read_bytes()
        value = json.loads(raw)
        state = value.get(KEY)
        output = safe(root, RECEIPT)
        if state and state.get("terminal_intent"):
            if output.is_symlink():
                raise RuntimeError("d128-terminal-symlink-denied")
            intent = state["terminal_intent"].encode()
            if sha(intent) != state.get("terminal_sha256"):
                raise RuntimeError("d128-terminal-intent-corrupt")
            if output.exists():
                if output.read_bytes() != intent:
                    raise RuntimeError("d128-terminal-conflict")
                sync_dir(output.parent)
            else:
                write(output, intent, once=True)
            return json.loads(intent)
        if boot != BOOT or number(now) < START:
            raise RuntimeError("d128-terminal-boot-or-clock-invalid")
        if state is None and sha(raw) != BASELINE:
            raise RuntimeError("d128-refusal-baseline-changed")
        if state is not None and (state.get("status") != "active" or state.get("boot_identity") != boot):
            raise RuntimeError("d128-terminal-owner-invalid")
        final_binding = None
        if status == "accepted-seam":
            final_raw = safe(root, final_path or "missing-final-review").read_bytes()
            final = json.loads(final_raw)
            if (sha(final_raw) != final_sha or final.get("decision") != "ACCEPT" or
                    final.get("blocking_findings") != 0 or final.get("reviewer_terminal_status") != "completed" or
                    not final.get("reviewer_identity") or final.get("purpose") != PURPOSE or
                    final.get("preterminal_ledger_sha256") != sha(raw)):
                raise RuntimeError("d128-independent-final-result-invalid")
            for relative, digest in final["evidence_inventory"].items():
                if sha(safe(root, relative).read_bytes()) != digest:
                    raise RuntimeError("d128-final-evidence-stale")
            final_binding = {"path": final_path, "sha256": final_sha}
        if observer is not None:
            now, boot = observer()
            if boot != BOOT or number(now) < START:
                raise RuntimeError("d128-terminal-boot-or-clock-invalid")
        total = PREFIX + number(now) - START + 120.0
        if status == "accepted-seam" and (total > CAP or GLOBAL - FLOOR - total < PROCESS):
            raise RuntimeError("d128-accepted-close-cap-or-protection-denied")
        if output.exists():
            raise RuntimeError("d128-uncommitted-receipt-conflict")
        receipt = {"purpose": PURPOSE, "owner": OWNER, "status": status, "reason": reason,
                   "baseline_ledger_sha256": BASELINE, "preterminal_ledger_sha256": sha(raw),
                   "boot_identity": boot, "closed_monotonic": now,
                   "measured_wall_seconds": now - START, "discovery_prefix_seconds": PREFIX,
                   "final_allowance_seconds": 120.0, "final_allowance_deadline_monotonic": now + 120.0,
                   "owner_total_charge_seconds": total, "global_used_seconds": FLOOR + total,
                   "global_cap_seconds": GLOBAL, "purpose_cap_seconds": CAP,
                   "protected_process_seconds": PROCESS, "terminal_reserve_seconds": TERMINAL,
                   "cap_exceeded": total > CAP, "process_protection_shortfall": max(0, PROCESS - (GLOBAL - FLOOR - total)),
                   "pea_used_seconds": 7098.193, "process_used_seconds": 5.865, "attempts_used": 2,
                   "workloads": 0, "fresh_count": 0, "retained_count": 0,
                   "phase6_complete": False, "phase7_started": False, "auto_advance": False,
                   "independent_final_review": final_binding}
        intent = encode(receipt)
        state = state or {"purpose": PURPOSE, "owner": OWNER, "bootstrap_refused": True}
        state.update(status=status, active_anchor=None, terminal_intent=intent.decode(),
                     terminal_sha256=sha(intent), global_used_seconds=FLOOR + total,
                     owner_total_charge_seconds=total)
        value[KEY] = state
        write(ledger, encode(value))
        try:
            write(output, intent, once=True)
        except FileExistsError:
            if output.is_symlink() or output.read_bytes() != intent:
                raise RuntimeError("d128-terminal-conflict")
        return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("install", "halt", "recover", "accept", "retire"))
    parser.add_argument("--pin")
    parser.add_argument("--pin-sha256")
    parser.add_argument("--reason", default="bounded seam halted")
    parser.add_argument("--final-review")
    parser.add_argument("--final-review-sha256")
    parser.add_argument("--report")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[2]
    boot = host_boot()
    now = time.monotonic()
    if args.action == "install":
        result = install(root, args.pin, args.pin_sha256, now, boot, observer=observe)
    elif args.action == "retire":
        result = retire_seam(root, args.pin, args.pin_sha256, args.report, now, boot, observer=observe)
    else:
        result = close(root, now, boot, "accepted-seam" if args.action == "accept" else "HALTED", args.reason,
                       args.final_review, args.final_review_sha256, observer=observe)
    print(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    main()
