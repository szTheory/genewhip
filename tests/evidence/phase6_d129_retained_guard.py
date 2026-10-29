#!/usr/bin/env python3
"""D129 stdlib-only admission, process boundary, and terminal guard.

The entry path intentionally does not import project code. It uses only the
standard library until authority, source review, immutable history, and the
full-remaining forecast have passed under the production ledger lock.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

APPROVAL_SHA = "15e7b9593f0537a3c76286cdd312a212df0fe81b169c1806fa9c2c1d2b02ead2"
LEDGER_SHA = "18fd6dbc2f892e4aa5c4c1847adf3b272e6cc71e31f91093d8a6fe1dd6281e5a"
G01_SHA = "2c187e368ff143f65a4cbd15decd0fd65aaae6fc69cf12796985ff10051ec66c"
G01_PIN_SHA = "3712323b5a9dce5f431fe85618ccf5e78aaf801f77419693946f8f2fcca74f7a"
BASELINE_COUNT = 68
GLOBAL_CAP, PURPOSE_CAP, TERMINAL, PROCESS_RESERVE = 57600.0, 9900.0, 600.0, 1794.135
PREFIX, FORECAST, BOOTSTRAP = 300.0, 9600.0, 900.0
FINAL_ALLOWANCE = 30.0
PROJECT = pathlib.Path(__file__).resolve().parents[2]
LEDGER_REL = "evidence/phase6-repairs.json"
TERMINAL_REL = "evidence/phase6-d129-engineering26-close.json"
DENIALS: list[dict] = []
EXPECTED_PROBES: list[str] = []
UNEXPECTED: list[str] = []
_DENIAL_INSTALLED = False


class GateError(RuntimeError):
    pass


def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _sha(path):
    return _sha_bytes(pathlib.Path(path).read_bytes())


def _contained(path, root=PROJECT, *, exists=True):
    p = pathlib.Path(path)
    if p.is_symlink():
        raise GateError("symlink-denied:" + str(p))
    try:
        p = p.resolve(strict=exists)
        base = pathlib.Path(root).resolve(strict=True)
    except OSError as exc:
        raise GateError("path-unreadable:" + str(p)) from exc
    if p != base and base not in p.parents:
        raise GateError("path-escape:" + str(p))
    return p


@contextlib.contextmanager
def _lock(path):
    name = hashlib.sha256(str(path.resolve(strict=True)).encode()).hexdigest()
    lock_path = pathlib.Path(tempfile.gettempdir()) / ("genewhip-phase6-accounting-" + name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _boot():
    try:
        raw = subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
                                      text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError("boot-observation-failed") from exc
    value = raw.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value):
        raise GateError("boot-observation-invalid")
    return "boot-session:" + value


def _approval():
    p = _contained(PROJECT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D129-APPROVAL.json")
    if _sha(p) != APPROVAL_SHA:
        raise GateError("approval-sha-stale")
    a = json.loads(p.read_bytes())
    if (a.get("schema") != "genewhip-d129-approval-v1" or a.get("status") != "approved" or
            a.get("owner") != "06-26" or a.get("auto_advance") is not False or
            a.get("auto_chain_active") is not False or a.get("stop") !=
            "accepted-engineering26 or genuine HALT; no automatic next plan"):
        raise GateError("approval-authority-invalid")
    for binding in a.get("bindings", {}).values():
        p = _contained(PROJECT / binding["path"])
        if _sha(p) != binding["sha256"]:
            raise GateError("approval-binding-stale:" + binding["path"])
    limits = a.get("limits", {})
    if (limits.get("global_seconds") != GLOBAL_CAP or limits.get("purpose_seconds") != PURPOSE_CAP or
            limits.get("terminal_reserve_seconds") != TERMINAL or
            limits.get("process_reserve_seconds") != PROCESS_RESERVE or
            limits.get("complete_forecast_seconds") != FORECAST or
            limits.get("discovery_prefix_seconds") != PREFIX):
        raise GateError("approval-limits-invalid")
    return a


def _history(value, approval):
    baseline = approval.get("baseline", {})
    hashes = baseline.get("top_level_object_sha256", {})
    if len(hashes) != BASELINE_COUNT or len(value) != BASELINE_COUNT:
        raise GateError("baseline-object-count-invalid")
    for key, digest in hashes.items():
        if key not in value or _sha_bytes(_canon(value[key])) != digest:
            raise GateError("historical-object-changed:" + key)
    if (baseline.get("sha256") != LEDGER_SHA or baseline.get("top_level_object_count") != BASELINE_COUNT or
            value.get("phase6_accounting", {}).get("active_anchor") is not None or
            value.get("current_pea_outcome", {}).get("pea_attempts_remaining") != 2 or
            value.get("usage", {}).get("attempts_for_this_stop") != 2):
        raise GateError("baseline-history-invalid")


def _atomic(path, data):
    raw = (json.dumps(data, indent=2, sort_keys=False, allow_nan=False) + "\n").encode()
    fd, tmp_name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    tmp = pathlib.Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        tmp.unlink(missing_ok=True)


def _publish_once(path, data):
    raw = (json.dumps(data, indent=2, sort_keys=False, allow_nan=False) + "\n").encode()
    fd, tmp_name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    tmp = pathlib.Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        try: os.link(tmp, path)
        except FileExistsError as exc: raise GateError("terminal-output-exists-or-symlink") from exc
        dfd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        tmp.unlink(missing_ok=True)


def _terminal_path(path):
    p = pathlib.Path(path)
    if p.is_symlink():
        raise GateError("terminal-output-symlink")
    parent = _contained(p.parent)
    if p.exists():
        return _contained(p)
    return parent / p.name


def recover_terminal():
    ledger = _contained(PROJECT / LEDGER_REL)
    with _lock(ledger):
        output = _terminal_path(PROJECT / TERMINAL_REL)
        value = json.loads(ledger.read_bytes())
        approval = _approval()
        _history_after_terminal(value, approval)
        saved = value.get("d129_engineering26_terminal_receipt")
        policy = value.get("d129_engineering26_policy", {})
        if (not isinstance(saved, dict) or policy.get("schema") != "phase6-d129-engineering26-v1" or
                policy.get("status") != "terminal-halted" or policy.get("pre_policy_halt") is not True or
                policy.get("purpose") != approval.get("purpose") or policy.get("anchor") is not None or
                policy.get("review_sha256") != G01_SHA or policy.get("parent_pin_sha256") != G01_PIN_SHA or
                policy.get("terminal_snapshot") != saved.get("payload") or
                value.get("phase6_accounting", {}).get("active_anchor") is not None):
            raise GateError("terminal-intent-required")
        if saved.get("path") != output.relative_to(PROJECT).as_posix():
            raise GateError("terminal-intent-path-mismatch")
        receipt = saved.get("payload")
        if (not isinstance(receipt, dict) or receipt.get("schema") != "phase6-d129-engineering26-terminal-v1" or
                receipt.get("status") != "HALTED" or receipt.get("owner") != "06-26" or
                receipt.get("purpose") != approval.get("purpose") or receipt.get("receipt_anchor") is not None or
                receipt.get("requirements_completed") != [] or receipt.get("actual_counts") !=
                {"tracer": 0, "retained": 0, "fresh": 0} or
                receipt.get("tasks_completed") != 0 or receipt.get("tasks_total") != 3):
            raise GateError("terminal-payload-invalid")
        closure = receipt.get("closure", {})
        elapsed = _finite_nonnegative(closure.get("elapsed_including_prefix_seconds"), "terminal-elapsed")
        allowance = _finite_nonnegative(closure.get("prepaid_final_allowance_seconds"), "terminal-allowance")
        terminal_elapsed = _finite_nonnegative(closure.get("measured_terminal_elapsed_seconds"), "terminal-delta")
        purpose_charge = elapsed + allowance
        terminal_charge = terminal_elapsed + allowance
        global_baseline = _finite_nonnegative(approval["baseline"].get("global_used_seconds"), "approved-global-baseline")
        global_used = global_baseline + purpose_charge
        close_time = _finite_nonnegative(closure.get("monotonic_closed_at"), "terminal-close-time")
        start_time = _finite_nonnegative(closure.get("active_start_monotonic"), "terminal-start-time")
        decision_time = _finite_nonnegative(closure.get("terminal_decision_monotonic"), "terminal-decision-time")
        pin_path = _contained(PROJECT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-26-PARENT-PREIMPORT-G01.json")
        review_path = _contained(PROJECT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-26-PREIMPORT-G01.md")
        if _sha(pin_path) != G01_PIN_SHA or _sha(review_path) != G01_SHA:
            raise GateError("terminal-g01-pin-stale")
        pin = json.loads(pin_path.read_bytes())
        if (closure.get("event") != "terminal" or closure.get("status") != "HALTED" or
                closure.get("reason") != "independent-preimport-source-review-rejected" or
                closure.get("pre_policy") is not True or closure.get("anchor") is not None or
                closure.get("review_sha256") != G01_SHA or closure.get("parent_pin_sha256") != G01_PIN_SHA or
                receipt.get("reason") != closure.get("reason") or allowance != FINAL_ALLOWANCE or
                elapsed != PREFIX + close_time - start_time or terminal_elapsed != close_time - decision_time or
                start_time != approval["prospective_entry"]["active_start_monotonic"] or
                purpose_charge != closure.get("purpose_charge_seconds") or purpose_charge != closure.get("global_charge_seconds") or
                purpose_charge != policy.get("purpose_charge_seconds") or purpose_charge != policy.get("global_charge_seconds") or
                global_baseline != approval["baseline"].get("global_used_seconds") or
                global_baseline != closure.get("global_baseline_seconds") or
                global_baseline != policy.get("global_baseline_seconds") or
                global_used != closure.get("global_used_after_close_seconds") or
                global_used != policy.get("global_used_after_close_seconds") or
                terminal_charge != closure.get("terminal_reserve_consumed_seconds") or
                terminal_charge != policy.get("terminal_spent_seconds") or
                close_time + allowance != closure.get("final_allowance_deadline_monotonic") or
                decision_time != pin.get("terminal_decision_monotonic") or
                allowance != TERMINAL or terminal_charge > TERMINAL or purpose_charge > PURPOSE_CAP or
                global_used + PROCESS_RESERVE > GLOBAL_CAP or
                closure.get("boot_identity") != "boot-session:" + approval["prospective_entry"]["boot_session_uuid"].lower()):
            raise GateError("terminal-charge-or-boot-binding-invalid")
        expected_policy = {"schema": "phase6-d129-engineering26-v1", "status": "terminal-halted",
            "plan": "06-26", "purpose": approval["purpose"], "game_admission": False,
            "approval_sha256": APPROVAL_SHA, "baseline_ledger_sha256": LEDGER_SHA,
            "baseline_object_count": BASELINE_COUNT, "anchor": None, "pre_policy_halt": True,
            "review_sha256": G01_SHA, "parent_pin_sha256": G01_PIN_SHA,
            "purpose_charge_seconds": purpose_charge, "terminal_spent_seconds": terminal_charge,
            "global_charge_seconds": purpose_charge, "global_baseline_seconds": global_baseline,
            "global_used_after_close_seconds": global_used, "terminal_snapshot": receipt,
            "requirements_completed": []}
        if policy != expected_policy:
            raise GateError("terminal-policy-binding-invalid")
        if (value.get("d129_engineering26_events") != [closure] or
                value.get("d129_engineering26_activities") != [] or
                value.get("d129_engineering26_reviews") != [{"event": "source-review-rejected",
                    "path": ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-26-PREIMPORT-G01.md",
                    "sha256": G01_SHA,
                    "parent_pin_path": ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-26-PARENT-PREIMPORT-G01.json",
                    "parent_pin_sha256": G01_PIN_SHA, "reviewer_identity": "/root/review26"}]
                or set(value) != set(approval["baseline"]["top_level_object_sha256"]) |
                    {"d129_engineering26_policy", "d129_engineering26_events", "d129_engineering26_activities",
                     "d129_engineering26_reviews", "d129_engineering26_terminal_receipt"}):
            raise GateError("terminal-d129-namespace-invalid")
        expected_internal = receipt.get("terminal_sha256")
        unsigned = {k: v for k, v in receipt.items() if k != "terminal_sha256"}
        if expected_internal != _sha_bytes(_canon(unsigned)):
            raise GateError("terminal-internal-digest-mismatch")
        payload = (json.dumps(receipt, indent=2)+"\n").encode()
        if _sha_bytes(payload) != saved.get("payload_sha256"):
            raise GateError("terminal-intent-digest-mismatch")
        if output.exists():
            if output.is_symlink() or output.read_bytes() != payload:
                raise GateError("terminal-output-conflict")
            dfd = os.open(output.parent, os.O_RDONLY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
            return {"status": "recovered-identical", "ledger_write": False, "charge": 0}
        _publish_once(output, saved["payload"])
        return {"status": "recovered-absent", "ledger_write": False, "charge": 0}


def halt_only():
    """Close the rejected pre-import attempt; this path cannot admit engineering."""
    ledger = _contained(PROJECT / LEDGER_REL)
    receipt_path = _terminal_path(PROJECT / TERMINAL_REL)
    with _lock(ledger):
        # Re-read every authority and observation byte only after acquiring the
        # same lock used by the phase6 accounting writer.
        approval = _approval()
        review_path = _contained(PROJECT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-26-PREIMPORT-G01.md")
        pin_path = _contained(PROJECT / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-26-PARENT-PREIMPORT-G01.json")
        if _sha(review_path) != G01_SHA or _sha(pin_path) != G01_PIN_SHA:
            raise GateError("g01-observation-pin-stale")
        review_text = review_path.read_text()
        pin = json.loads(pin_path.read_bytes())
        expected_sources = {
            "scripts/evidence/phase6_accounting.py": "de726be6a1d7da627c88200105eb0ea67b8e6032bbab3029b6060d9ba96a4d65",
            "tests/evidence/phase6_d129_retained_guard.py": "eab503f0b7ab1bbc394bc8cb3821914150564c1c295861559c19db8cf4979b48",
        }
        if ("decision: rejected" not in review_text or "bootstrap_terminal_complete: false" not in review_text or
                pin.get("schema") != "genewhip-d129-parent-source-observation-v1" or
                pin.get("decision") != "rejected" or pin.get("actual_separate_completion_observed") is not True or
                pin.get("ledger_mutated") is not False or pin.get("project_imports") != 0 or
                pin.get("review_sha256") != G01_SHA or pin.get("reviewer_identity") != "/root/review26" or
                pin.get("source_inventory") != expected_sources or
                any(name not in review_text or digest not in review_text for name, digest in expected_sources.items())):
            raise GateError("g01-independent-rejection-invalid")
        before = _sha(ledger)
        if before != LEDGER_SHA:
            raise GateError("baseline-ledger-sha-stale")
        value = json.loads(ledger.read_bytes())
        _history(value, approval)
        boot = _boot()
        expected_boot = approval["prospective_entry"]["boot_session_uuid"].lower()
        if boot.removeprefix("boot-session:") != expected_boot:
            raise GateError("halt-boot-session-changed")
        receipt_path = _terminal_path(PROJECT / TERMINAL_REL)
        if receipt_path.exists() or receipt_path.is_symlink():
            raise GateError("halt-terminal-output-must-be-absent")
        _install_denial()
        now = time.monotonic()
        start = approval["prospective_entry"]["active_start_monotonic"]
        decision = pin["terminal_decision_monotonic"]
        elapsed = PREFIX + now - start
        since_decision = now - decision
        if (elapsed < PREFIX or since_decision < 0 or since_decision + FINAL_ALLOWANCE > TERMINAL or
                PURPOSE_CAP - elapsed < FINAL_ALLOWANCE):
            raise GateError("halt-terminal-reserve-or-deadline-exhausted")
        base_global = _finite_nonnegative(approval["baseline"].get("global_used_seconds"), "approved-global-baseline")
        charge = elapsed + FINAL_ALLOWANCE
        if GLOBAL_CAP - (base_global + charge) < PROCESS_RESERVE:
            raise GateError("halt-process-protection-unaffordable")
        closure = {"event": "terminal", "status": "HALTED", "reason": "independent-preimport-source-review-rejected",
            "boot_identity": boot, "monotonic_closed_at": now, "active_start_monotonic": start,
            "terminal_decision_monotonic": decision, "elapsed_including_prefix_seconds": elapsed,
            "measured_terminal_elapsed_seconds": since_decision,
            "prepaid_final_allowance_seconds": FINAL_ALLOWANCE, "final_allowance_deadline_monotonic": now+FINAL_ALLOWANCE,
            "purpose_charge_seconds": charge, "terminal_reserve_consumed_seconds": since_decision+FINAL_ALLOWANCE,
            "global_charge_seconds": charge, "global_baseline_seconds": base_global,
            "global_used_after_close_seconds": base_global+charge,
            "discovery_prefix_seconds": PREFIX, "anchor": None, "pre_policy": True,
            "review_sha256": G01_SHA, "parent_pin_sha256": G01_PIN_SHA}
        receipt = {"schema": "phase6-d129-engineering26-terminal-v1", "status": "HALTED",
            "reason": closure["reason"], "owner": "06-26", "purpose": approval["purpose"],
            "receipt_anchor": None, "actual_counts": {"tracer": 0, "retained": 0, "fresh": 0},
            "tasks_completed": 0, "tasks_total": 3,
            "requirements_completed": [], "downstream_blocked": ["06-12", "06-09", "06-05", "06-06", "06-07"],
            "closure": closure}
        receipt["terminal_sha256"] = _sha_bytes(_canon(receipt))
        value["d129_engineering26_policy"] = {"schema": "phase6-d129-engineering26-v1",
            "status": "terminal-halted", "plan": "06-26", "purpose": approval["purpose"],
            "game_admission": False, "approval_sha256": APPROVAL_SHA, "baseline_ledger_sha256": LEDGER_SHA,
            "baseline_object_count": BASELINE_COUNT, "anchor": None, "pre_policy_halt": True,
            "review_sha256": G01_SHA, "parent_pin_sha256": G01_PIN_SHA,
            "purpose_charge_seconds": charge, "terminal_spent_seconds": since_decision+FINAL_ALLOWANCE,
            "global_baseline_seconds": base_global,
            "global_charge_seconds": charge,
            "global_used_after_close_seconds": base_global+charge, "terminal_snapshot": receipt,
            "requirements_completed": []}
        value["d129_engineering26_events"] = [closure]
        value["d129_engineering26_activities"] = []
        value["d129_engineering26_reviews"] = [{"event": "source-review-rejected", "path": review_path.relative_to(PROJECT).as_posix(),
            "sha256": G01_SHA, "parent_pin_path": pin_path.relative_to(PROJECT).as_posix(),
            "parent_pin_sha256": G01_PIN_SHA, "reviewer_identity": "/root/review26"}]
        payload = (json.dumps(receipt, indent=2)+"\n").encode()
        value["d129_engineering26_terminal_receipt"] = {"path": receipt_path.relative_to(PROJECT).as_posix(),
            "payload_sha256": _sha_bytes(payload), "payload": receipt}
        _atomic(ledger, value)
        _publish_once(receipt_path, receipt)
        return {"status": "HALTED", "receipt_sha256": _sha_bytes(payload), "ledger_sha256": _sha(ledger),
                "global_charge_seconds": charge, "terminal_elapsed_seconds": since_decision,
                "prepaid_final_allowance_seconds": FINAL_ALLOWANCE, "anchor": None,
                "project_imports": 0, "expected_process_probes": len(EXPECTED_PROBES),
                "unexpected_process_requests": len(UNEXPECTED)}


def _history_after_terminal(value, approval):
    hashes = approval["baseline"]["top_level_object_sha256"]
    if len(value) != BASELINE_COUNT + 5:
        raise GateError("terminal-ledger-object-count-invalid")
    for key, digest in hashes.items():
        if key not in value or _sha_bytes(_canon(value[key])) != digest:
            raise GateError("terminal-historical-object-changed:" + key)


def _finite_nonnegative(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise GateError(name + "-invalid")
    return float(value)


def _install_denial():
    global _DENIAL_INSTALLED
    if _DENIAL_INSTALLED:
        raise GateError("process-denial-double-install")

    def audit(event, args):
        if event == "subprocess.Popen":
            name = "audit-subprocess:" + str(args[0] if args else "unknown")
            DENIALS.append({"event": name, "expected": False})
            UNEXPECTED.append(name)
            raise PermissionError("D129 process denial: " + name)
        if event in ("os.system", "os.posix_spawn", "os.fork", "os.forkpty", "os.exec", "os.spawn", "socket.__new__"):
            name = "audit-" + event
            DENIALS.append({"event": name, "expected": False}); UNEXPECTED.append(name)
            raise PermissionError("D129 process denial: " + name)
    sys.addaudithook(audit)
    original_popen = subprocess.Popen
    def denied_popen(*args, **kwargs):
        name = "subprocess.Popen"
        DENIALS.append({"event": name, "expected": False}); UNEXPECTED.append(name)
        raise PermissionError("D129 process denial: " + name)
    subprocess.Popen = denied_popen
    if original_popen is subprocess.Popen:
        raise GateError("process-denial-patch-failed")
    _DENIAL_INSTALLED = True


def _cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=("terminal",))
    parser.add_argument("--case", required=True, choices=("halt", "recovery"))
    args = parser.parse_args()
    if args.case == "halt":
        result = halt_only()
    elif args.case == "recovery":
        result = recover_terminal()
    else:
        raise GateError("terminal-case-invalid")
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result.get("status") in ("admitted", "recovered-identical", "recovered-absent") else 2


if __name__ == "__main__":
    try:
        raise SystemExit(_cli())
    except (GateError, OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc), "expected_process_probes": len(EXPECTED_PROBES),
                          "unexpected_process_requests": len(UNEXPECTED), "project_imports": 0}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)
