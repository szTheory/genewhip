#!/usr/bin/env python3
"""Small stdlib authorization and reservation helpers for Phase 6 evidence."""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import time
from typing import Callable, Any


class AccountingError(RuntimeError):
    """A resource reservation is invalid or exhausted."""


PEA_SIGNATURE = "tank-battle:cpu:00ec32:4879:2"
INDEPENDENT_CASES = {
    "tank-pea-regression": PEA_SIGNATURE,
}
TANK_CONTINUATION_CASE = "tank-pea-continuation-1"
TANK_CONTINUATION_CONTROLS = ("control-repeat-1", "control-repeat-2")
TANK_CONTINUATION_WATCHDOG_SECONDS = 600
PEA_SHORT_CASES = (
    "native-red-c-driver", "native-red-public-client",
    "native-green-c-driver", "native-green-public-client",
    "sanitize-green-c-driver", "sanitize-green-public-client",
    "hooks-off-green-c-driver", "hooks-off-green-public-client",
    "native-mutant-wrong-address", "native-mutant-stack-order",
)
PEA_CONTROL_CASES = ("control-repeat-1", "control-repeat-2")
OBSERVER_BUILD_CASE = "stack-observer-builds-1"
OBSERVER_PROOF_PURPOSES = {
    "stack-observer-native-1": "stack-observer-native-1",
    "stack-observer-sanitize-1": "stack-observer-sanitize-1",
    "stack-observer-hooks-off-1": "stack-observer-hooks-off-1",
}
OBSERVER_BUILD_WATCHDOG_SECONDS = 300
OBSERVER_PROOF_WATCHDOG_SECONDS = 30
OBSERVER_PROOF_TOTAL_SECONDS = 90
OFFLINE_SEGMENT_SECONDS = 1800
OFFLINE_PREVIOUS_CHARGE_SECONDS = 657.822
D122_PEA_CAP_SECONDS = 9403.235
D122_BUILD_PARTITION_SECONDS = 300.0
D122_PROOF_PARTITION_SECONDS = 90.0
D122_PROCESS_PARTITION_SECONDS = 1800.0
D122_OTHER_PARTITION_SECONDS = 400.251
D122_CLOSEOUT_RESERVE_SECONDS = 120.0
D122_APPROVAL_CONTEXT_SHA256 = "d46cf45515502f3a90cff6414b197a80d155ee6ab98f6e43cd6bcd6bb79767a5"
D122_PLAN_CHECK_SHA256 = "7c40ba20c4871488bbb14f935e4765ccadc4454640a2d523c6ff3220d34e7f26"
D122_17_SUMMARY_SHA256 = "8526d3c3cc139e51258d3141a0ceeb448bbc15d69ebeecdd291703b5bfbd7f89"
D123_GLOBAL_FLOOR_SECONDS = 18627.534
D123_PEA_FLOOR_SECONDS = 6813.497
D123_GLOBAL_CAP_SECONDS = 43200.0
D123_PEA_CAP_SECONDS = 9403.235
D123_PROTECTED_14_SECONDS = 2200.251
D123_CLOSEOUT_RESERVE_SECONDS = 120.0
D123_PLAN_ID = "06-19"
D124_GLOBAL_FLOOR_SECONDS = 21358.138
D124_PEA_FLOOR_SECONDS = 7092.328
D124_GLOBAL_CAP_SECONDS = 43200.0
D124_PEA_CAP_SECONDS = 9403.235
D124_PROCESS_RESERVE_SECONDS = 1800.0
D124_CLOSEOUT_RESERVE_SECONDS = 120.0
D124_PLAN_ID = "06-20"
D124_PROPOSAL_SHA256 = "f553a1164b834ee236bf81c81c18f50d51b0d2605f6ab7c869ec26c4e25bf873"
D125_PLAN_ID = "06-22"
D125_CASES = ("d125-tank-pea-continuation-1", "d125-replacement-control-1", "d125-replacement-control-2")
TEST_FIXTURE_D125_AUTHORITY = None
D129_APPROVAL_SHA256 = "15e7b9593f0537a3c76286cdd312a212df0fe81b169c1806fa9c2c1d2b02ead2"
D129_LEDGER_SHA256 = "18fd6dbc2f892e4aa5c4c1847adf3b272e6cc71e31f91093d8a6fe1dd6281e5a"
D129_GLOBAL_CAP = 57600.0
D129_PURPOSE_CAP = 9900.0
D129_TERMINAL = 600.0
D129_PROCESS_PROTECTED = 1794.135
D129_BASELINE_OBJECTS = 68
D129_FIELDS = ("d129_engineering26_policy", "d129_engineering26_events", "d129_engineering26_activities",
               "d129_engineering26_reviews", "d129_engineering26_terminal_receipt")


def _d129_boot_identity():
    """The only permitted production subprocess during D129 bootstrap."""
    try:
        output = subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
                                         text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AccountingError("d129-boot-identity-unavailable") from exc
    identity = output.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", identity):
        raise AccountingError("d129-boot-identity-unparseable")
    return "boot-session:" + identity


def _d129_authority(root, approval_path, approval_sha256):
    root = pathlib.Path(root).resolve(strict=True)
    approval_path = _safe_path(pathlib.Path(approval_path), root)
    if (approval_sha256 != D129_APPROVAL_SHA256 or ledger_digest(approval_path) != D129_APPROVAL_SHA256):
        raise AccountingError("d129-explicit-approval-stale")
    try:
        approval = json.loads(approval_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise AccountingError("d129-approval-unreadable") from exc
    expected = {
        "schema": "genewhip-d129-approval-v1", "status": "approved", "owner": "06-26",
        "purpose": "D129-engineering26-retained-consumer-closure",
        "stop": "accepted-engineering26 or genuine HALT; no automatic next plan",
    }
    if any(approval.get(k) != v for k, v in expected.items()):
        raise AccountingError("d129-approval-not-selected")
    for name, binding in approval.get("bindings", {}).items():
        path = _safe_path(root / binding.get("path", ""), root)
        if ledger_digest(path) != binding.get("sha256"):
            raise AccountingError("d129-approved-binding-stale:" + name)
    limits = approval.get("limits", {})
    if (limits.get("global_seconds") != D129_GLOBAL_CAP or limits.get("purpose_seconds") != D129_PURPOSE_CAP or
            limits.get("terminal_reserve_seconds") != D129_TERMINAL or
            limits.get("process_reserve_seconds") != D129_PROCESS_PROTECTED or
            limits.get("complete_forecast_seconds") != 9600 or limits.get("discovery_prefix_seconds") != 300):
        raise AccountingError("d129-approved-limits-invalid")
    return approval


def _d129_history(value, approval):
    if len(value) != D129_BASELINE_OBJECTS + sum(k in value for k in D129_FIELDS):
        raise AccountingError("d129-ledger-object-count-invalid")
    hashes = approval["baseline"]["top_level_object_sha256"]
    if len(hashes) != D129_BASELINE_OBJECTS:
        raise AccountingError("d129-baseline-roster-invalid")
    for key, digest in hashes.items():
        if key not in value or hashlib.sha256(_canonical(value[key])).hexdigest() != digest:
            raise AccountingError("d129-historical-object-changed:" + key)
    state = value.get("phase6_accounting", {})
    if state.get("active_anchor") is not None:
        raise AccountingError("d129-production-anchor-not-null")
    pea = value.get("current_pea_outcome", {})
    usage = value.get("usage", {})
    if (pea.get("status") != "halted-infrastructure" or pea.get("pea_attempts_remaining") != 2 or
            usage.get("attempts_for_this_stop") != 2):
        raise AccountingError("d129-protected-history-invalid")


def install_d129_owner(ledger_path, *, project_root, approval_path, approval_sha256,
                       source_review_path, source_review_sha256, reviewer_identity):
    """Install D129 only after its complete source and terminal path are reviewed."""
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(pathlib.Path(ledger_path), root)
    approval = _d129_authority(root, approval_path, approval_sha256)
    review_path = _safe_path(pathlib.Path(source_review_path), root)
    if not re.fullmatch(r"[0-9a-f]{64}", str(source_review_sha256)) or ledger_digest(review_path) != source_review_sha256:
        raise AccountingError("d129-source-review-pin-stale")
    try:
        review = json.loads(review_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise AccountingError("d129-source-review-unreadable") from exc
    if (review.get("decision") != "accepted" or review.get("reviewer_role") != "gsd-code-reviewer" or
            review.get("reviewer_identity") != reviewer_identity or not reviewer_identity or
            review.get("bootstrap_terminal_complete") is not True or review.get("blockers") not in ([], None)):
        raise AccountingError("d129-source-review-not-accepted")
    ledger_before = ledger_digest(path)
    if ledger_before != D129_LEDGER_SHA256:
        raise AccountingError("d129-baseline-ledger-stale")
    with _locked(path):
        value = _load(path, root)
        boot = _d129_boot_identity()
        if ledger_digest(path) != ledger_before:
            raise AccountingError("d129-ledger-drift-under-lock")
        _d129_history(value, approval)
        now = time.monotonic()
        E = 300.0 + max(0.0, now - approval["prospective_entry"]["active_start_monotonic"])
        G = _closed_seconds(value["phase6_accounting"])
        if (approval["prospective_entry"].get("boot_session_uuid", "").lower() != boot.removeprefix("boot-session:") or
                57600.0 - G < 8100.0 + 1794.135 + 600.0 or 9900.0 - E < 8100.0 + 600.0 or E > 1200.0):
            raise AccountingError("d129-complete-forecast-admission-denied")
        policy = {"schema": "phase6-d129-engineering26-v1", "status": "active", "plan": "06-26",
            "purpose": "D129-engineering26-retained-consumer-closure", "game_admission": False,
            "global_cap_seconds": 57600.0, "purpose_cap_seconds": 9900.0,
            "terminal_reserve_seconds": 600.0, "process_protected_seconds": 1794.135,
            "bootstrap_completed": True, "bootstrap_evidence": review["bootstrap_evidence"],
            "review_path": review_path.relative_to(root).as_posix(), "review_sha256": source_review_sha256,
            "reviewer_identity": reviewer_identity, "approval_sha256": approval_sha256,
            "baseline_ledger_sha256": D129_LEDGER_SHA256, "baseline_object_count": 68,
            "boot_identity": boot, "active_started_monotonic": now, "active_prefix_seconds": E,
            "conservative_discovery_prefix_seconds": 300.0,
            "global_baseline_seconds": G,
            "elapsed_at_install_seconds": E, "remaining_nonterminal_seconds": 8100.0,
            "terminal_remaining_seconds": 600.0, "requirements_completed": []}
        value["d129_engineering26_policy"] = policy
        value["d129_engineering26_events"] = [{"event": "admitted", "monotonic": now,
            "boot_identity": boot, "source_review_sha256": source_review_sha256}]
        value["d129_engineering26_activities"] = []
        value["d129_engineering26_reviews"] = []
        value["d129_engineering26_terminal_receipt"] = None
        _write(path, value)
        return policy


def halt_d129_before_install(ledger_path, *, output, reason, project_root, approval_path,
                             approval_sha256, source_review_path, source_review_sha256,
                             reviewer_identity):
    """Durably close a denied bootstrap without installing an owner or anchor."""
    if not isinstance(reason, str) or not reason.strip():
        raise AccountingError("d129-bootstrap-halt-reason-required")
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(pathlib.Path(ledger_path), root)
    target = _d129_terminal_path(pathlib.Path(output), root)
    approval = _d129_authority(root, approval_path, approval_sha256)
    review_path = _safe_path(pathlib.Path(source_review_path), root)
    if ledger_digest(review_path) != source_review_sha256:
        raise AccountingError("d129-source-review-pin-stale")
    review = json.loads(review_path.read_bytes())
    if (review.get("decision") != "accepted" or review.get("reviewer_role") != "gsd-code-reviewer" or
            review.get("reviewer_identity") != reviewer_identity or review.get("bootstrap_terminal_complete") is not True):
        raise AccountingError("d129-source-review-not-accepted")
    original = ledger_digest(path)
    if original != D129_LEDGER_SHA256:
        raise AccountingError("d129-baseline-ledger-stale")
    with _locked(path):
        value = _load(path, root)
        boot = _d129_boot_identity()
        if ledger_digest(path) != original:
            raise AccountingError("d129-ledger-drift-under-lock")
        _d129_history(value, approval)
        now = time.monotonic()
        elapsed = 300.0 + max(0.0, now - approval["prospective_entry"]["active_start_monotonic"])
        event = {"event": "terminal", "status": "HALTED", "reason": reason,
            "boot_identity": boot, "monotonic_closed_at": now, "measured_active_seconds": elapsed,
            "prefix_seconds": 300.0, "anchor": None, "pre_policy": True}
        receipt = {"schema": "phase6-d129-engineering26-terminal-v1", "status": "HALTED",
            "reason": reason, "owner": "06-26", "purpose": approval["purpose"],
            "receipt_anchor": None, "actual_counts": {"tracer": 0, "retained": 0, "fresh": 0},
            "requirements_completed": [], "downstream_blocked": ["06-12", "06-09", "06-05", "06-06", "06-07"],
            "closure": event}
        receipt["terminal_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
        value["d129_engineering26_policy"] = {"schema": "phase6-d129-engineering26-v1",
            "status": "terminal-halted", "plan": "06-26", "purpose": approval["purpose"],
            "game_admission": False, "approval_sha256": approval_sha256,
            "baseline_ledger_sha256": original, "baseline_object_count": 68,
            "boot_identity": boot, "anchor": None, "terminal_spent_seconds": elapsed,
            "pre_policy_halt": True, "terminal_snapshot": receipt, "requirements_completed": []}
        value["d129_engineering26_events"] = [event]
        value["d129_engineering26_activities"] = []
        value["d129_engineering26_reviews"] = [{"event": "source-review", "path": review_path.relative_to(root).as_posix(),
            "sha256": source_review_sha256, "reviewer_identity": reviewer_identity}]
        value["d129_engineering26_terminal_receipt"] = {"path": target.relative_to(root).as_posix(),
            "payload_sha256": hashlib.sha256(_receipt_payload(receipt)).hexdigest(), "payload": receipt}
        _write(path, value)
        _publish_receipt_once(target, receipt)
        return receipt


def d129_remaining(value, *, monotonic_now, boot_identity):
    policy = value.get("d129_engineering26_policy", {})
    if (policy.get("schema") != "phase6-d129-engineering26-v1" or policy.get("status") != "active" or
            policy.get("boot_identity") != boot_identity):
        raise AccountingError("d129-owner-not-live")
    now = _numeric(monotonic_now, "d129-monotonic-now")
    elapsed = _numeric(policy.get("active_prefix_seconds"), "d129-prefix") + now - _numeric(
        policy.get("active_started_monotonic"), "d129-start")
    if elapsed < 0:
        raise AccountingError("d129-clock-rollback")
    global_used = _numeric(policy.get("global_baseline_seconds"), "d129-global-baseline") + elapsed
    return {"elapsed_seconds": elapsed, "global_used_seconds": global_used,
        "global_remaining_seconds": max(0.0, 57600.0-global_used),
        "purpose_remaining_seconds": max(0.0, 9900.0-elapsed),
        "terminal_remaining_seconds": max(0.0, 600.0-_numeric(policy.get("terminal_spent_seconds", 0), "d129-terminal-spent"))}


def close_d129_owner(ledger_path, *, output, status, reason, boot_identity, project_root,
                     approval_path, approval_sha256):
    """Persist exact terminal intent before create-once receipt publication."""
    if status not in ("HALTED", "accepted-engineering26") or not isinstance(reason, str) or not reason.strip():
        raise AccountingError("d129-terminal-disposition-invalid")
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(pathlib.Path(ledger_path), root)
    target = _safe_create_path(pathlib.Path(output), root)
    _d129_authority(root, approval_path, approval_sha256)
    with _locked(path):
        value = _load(path, root)
        observed_boot = _d129_boot_identity()
        if observed_boot != boot_identity:
            raise AccountingError("d129-terminal-boot-mismatch")
        policy = value.get("d129_engineering26_policy", {})
        if policy.get("schema") != "phase6-d129-engineering26-v1" or policy.get("status") != "active":
            raise AccountingError("d129-terminal-owner-not-active")
        if policy.get("boot_identity") != boot_identity:
            raise AccountingError("d129-terminal-boot-mismatch")
        if value.get("phase6_accounting", {}).get("active_anchor") is not None:
            raise AccountingError("d129-terminal-production-anchor-changed")
        now = time.monotonic()
        remaining = d129_remaining(value, monotonic_now=now, boot_identity=boot_identity)
        elapsed = remaining["elapsed_seconds"]
        if elapsed > 9900.0:
            raise AccountingError("d129-terminal-purpose-overrun")
        event = {"event": "terminal", "status": status, "reason": reason,
            "monotonic_closed_at": now, "boot_identity": boot_identity,
            "measured_active_seconds": elapsed, "prefix_seconds": policy.get("active_prefix_seconds"),
            "final_allowance_seconds": min(120.0, max(0.0, 600.0-elapsed)),
            "global_used_seconds": remaining["global_used_seconds"], "anchor": None}
        receipt = {"schema": "phase6-d129-engineering26-terminal-v1", "status": status,
            "reason": reason, "owner": "06-26", "purpose": policy["purpose"],
            "receipt_anchor": None, "actual_counts": policy.get("actual_counts", {}),
            "requirements_completed": [], "downstream_blocked": ["06-12", "06-09", "06-05", "06-06", "06-07"],
            "closure": event}
        receipt["terminal_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
        value["d129_engineering26_events"].append(event)
        value["d129_engineering26_terminal_receipt"] = {"path": target.relative_to(root).as_posix(),
            "payload_sha256": hashlib.sha256(_receipt_payload(receipt)).hexdigest(), "payload": receipt}
        policy["status"] = "terminal-halted" if status == "HALTED" else "terminal-accepted"
        policy["terminal_spent_seconds"] = elapsed
        policy["anchor"] = None
        policy["terminal_snapshot"] = receipt
        _write(path, value)
        _publish_receipt_once(target, receipt)
        return receipt


def recover_d129_receipt(ledger_path, *, output, project_root):
    """Idempotent no-charge recovery for absent or byte-identical terminal output."""
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(pathlib.Path(ledger_path), root)
    target = _d129_terminal_path(pathlib.Path(output), root)
    with _locked(path):
        value = _load(path, root)
        saved = value.get("d129_engineering26_terminal_receipt")
        policy = value.get("d129_engineering26_policy", {})
        if (not isinstance(saved, dict) or policy.get("status") not in ("terminal-halted", "terminal-accepted") or
                policy.get("anchor") is not None or value["phase6_accounting"].get("active_anchor") is not None):
            raise AccountingError("d129-terminal-intent-required")
        if saved.get("path") != target.relative_to(root).as_posix():
            raise AccountingError("d129-terminal-path-mismatch")
        payload = _receipt_payload(saved.get("payload"))
        if hashlib.sha256(payload).hexdigest() != saved.get("payload_sha256"):
            raise AccountingError("d129-terminal-intent-corrupt")
        try:
            existing = target.read_bytes()
        except FileNotFoundError:
            _publish_receipt_once(target, saved["payload"])
        except OSError as exc:
            raise AccountingError("d129-terminal-output-unreadable") from exc
        else:
            if target.is_symlink() or existing != payload:
                raise AccountingError("d129-terminal-output-conflict")
            _fsync_directory(target.parent)
        return {"status": "recovered-identical" if target.exists() else "published", "sha256": hashlib.sha256(payload).hexdigest()}


def _d129_terminal_path(path, root):
    target = pathlib.Path(path)
    if target.is_symlink():
        raise AccountingError("d129-terminal-output-symlink")
    try:
        base = pathlib.Path(root).resolve(strict=True)
        parent = target.parent.resolve(strict=True)
        if parent != base and base not in parent.parents:
            raise AccountingError("ledger-path-escape-denied")
        if target.exists():
            resolved = target.resolve(strict=True)
            if resolved.parent != parent or not resolved.is_file():
                raise AccountingError("d129-terminal-output-invalid")
            return resolved
        return parent / target.name
    except OSError as exc:
        raise AccountingError("d129-terminal-parent-unreadable") from exc


def qualification23_owner(value, *, project_root, boot_identity=None):
    """Explicit engineering selector; never selects or revives a runtime owner."""
    root = pathlib.Path(project_root).resolve(strict=True)
    policy = value.get("d125_qualification23_policy", {})
    anchor = value.get("phase6_accounting", {}).get("active_anchor")
    constants = {"schema": "phase6-d125-qualification23-v1", "plan": "06-23",
        "status": "engineering-only", "game_admission": False, "test_fixture_only": False,
        "global_floor_seconds": 34259.66586724999, "pea_floor_seconds": 7098.193,
        "process_floor_seconds": 5.865, "attempts_floor": 2, "global_cap_seconds": 43200.0,
        "pea_cap_seconds": 9403.235, "process_cap_seconds": 1800.0, "attempts_cap": 3,
        "protected_process_seconds": 1794.135, "closeout_reserve_seconds": 120.0}
    if any(type(policy.get(k)) is not type(v) or policy.get(k) != v for k, v in constants.items()):
        raise AccountingError("qualification23-policy-invalid-or-terminal")
    if value.get("test_fixture_only") or TEST_FIXTURE_D125_AUTHORITY is not None:
        raise AccountingError("qualification23-live-fixture-authority-denied")
    if (not isinstance(anchor, dict) or anchor.get("id") != policy.get("anchor_id") or
            anchor.get("pea_charge") is not False or anchor.get("boot_identity") != policy.get("boot_identity") or
            anchor.get("monotonic_started_at") != policy.get("entry", {}).get("monotonic")):
        raise AccountingError("qualification23-anchor-invalid")
    if boot_identity is not None and boot_identity != policy["boot_identity"]:
        raise AccountingError("qualification23-boot-mismatch")
    required = {".planning/phases/GW-06-shared-repairs-and-two-playable-routes/" + p
        for p in ("06-23-PLAN.md", "06-23-PLAN-CHECK.md", "06-CONTEXT.md")}
    required.add(".planning/context/OPERATING.md")
    bindings = policy.get("bindings", {})
    if set(bindings) != required or any(ledger_digest(_safe_path(root / p, root)) != h for p, h in bindings.items()):
        raise AccountingError("qualification23-plan-binding-stale")
    # Runtime history remains terminal. The engineering selector owns no record,
    # purpose, attempt or process charge in the historical runtime namespace.
    if (value.get("d125_recovery_policy", {}).get("status") != "terminal-halted-containment-acceptance-failure" or
            not any(e.get("event") == "terminal" for e in value.get("d125_owner_events", [])) or
            value.get("usage", {}).get("attempts_for_this_stop") != 2):
        raise AccountingError("qualification23-runtime-history-invalid")
    runtime_rows = [r for r in value.get("records", []) if r.get("d125_owner") == "06-22"]
    process = sum(_numeric(r.get("process_active_seconds", 0), "qualification23-historical-process") for r in runtime_rows)
    attempts = 1 + sum(r.get("new_target_attempts", 0) for r in runtime_rows)
    if abs(5.244 + process - 5.865) > 1e-9 or abs(7097.572 + process - 7098.193) > 1e-9 or type(attempts) is not int or attempts != 2:
        raise AccountingError("qualification23-game-counters-changed")
    _accounting_state(value)
    return policy


def engineering24_owner(value, *, project_root, boot_identity=None):
    """Return the distinct no-game Plan 24 owner, never the terminal 23 selector."""
    root = pathlib.Path(project_root).resolve(strict=True)
    policy = value.get("d125_engineering24_policy", {})
    required = {
        "schema": "phase6-d125-engineering24-v1", "plan": "06-24",
        "status": "engineering-only", "game_admission": False,
        "test_fixture_only": False, "retained_count": 3, "fresh_count": 0,
        "global_cap_seconds": 43200.0,
        "pea_floor_seconds": 7098.193, "process_floor_seconds": 5.865,
        "attempts_floor": 2, "pea_cap_seconds": 9403.235,
        "process_cap_seconds": 1800.0, "attempts_cap": 3,
        "protected_process_seconds": 1794.135, "closeout_reserve_seconds": 120.0,
    }
    if any(type(policy.get(k)) is not type(v) or policy.get(k) != v for k, v in required.items()):
        raise AccountingError("engineering24-policy-invalid-or-terminal")
    if value.get("test_fixture_only") or TEST_FIXTURE_D125_AUTHORITY is not None:
        raise AccountingError("engineering24-live-fixture-authority-denied")
    anchor = policy.get("anchor")
    entry_path = _safe_path(root / "build/phase6/d125-engineering24/entry.json", root)
    closeout_path = _safe_path(root / "evidence/phase6-d125-proof-receipt-debug-closeout.json", root)
    entry = json.loads(entry_path.read_bytes())
    closeout = json.loads(closeout_path.read_bytes())
    if (not isinstance(anchor, dict) or anchor.get("status") != "active" or
            anchor.get("pea_charge") is not False or
            anchor.get("boot_identity") != policy.get("boot_identity") or
            anchor.get("entry_sha256") != policy.get("entry_sha256") or
            anchor.get("entry_sha256") != ledger_digest(entry_path) or
            not re.fullmatch(r"[0-9a-f]{64}", str(anchor.get("entry_sha256", ""))) or
            entry.get("schema") != "phase6-d125-engineering24-entry-v1" or
            entry.get("status") != "active" or
            entry.get("global_closed_floor_seconds") != closeout.get("global_used_seconds") or
            closeout.get("debug_anchor_closed") is not True or closeout.get("production_anchor") is not None):
        raise AccountingError("engineering24-anchor-invalid")
    if boot_identity is not None and boot_identity != policy["boot_identity"]:
        raise AccountingError("engineering24-boot-mismatch")
    if policy.get("entry_ledger_sha256") != entry.get("final_entry_ledger_sha256"):
        raise AccountingError("engineering24-entry-ledger-mismatch")
    if (policy.get('global_floor_seconds') != entry.get('global_closed_floor_seconds') or
            policy.get('parent_active_discovery_prefix_seconds') != entry.get('parent_active_discovery_prefix_seconds') or
            policy.get('debug_closeout_sha256') != ledger_digest(closeout_path) or
            entry.get('debug_closeout_sha256') != ledger_digest(closeout_path) or
            anchor.get('monotonic_started_at') != entry.get('monotonic_started_at') or
            entry.get('boot_identity') != policy.get('boot_identity')):
        raise AccountingError('engineering24-source-binding-stale')
    for key in ('global_floor_seconds', 'parent_active_discovery_prefix_seconds'):
        if _numeric(policy.get(key), 'engineering24-' + key) < 0:
            raise AccountingError('engineering24-negative-accounting-input')
    required_bindings = {'.planning/context/OPERATING.md', *(
        '.planning/phases/GW-06-shared-repairs-and-two-playable-routes/' + name
        for name in ('06-24-PLAN.md', '06-24-PLAN-CHECK.md'))}
    if (not isinstance(policy.get('bindings'), dict) or set(policy['bindings']) != required_bindings or
            policy['bindings'] != entry.get('input_sha256')):
        raise AccountingError('engineering24-binding-roster-invalid')
    for relative, expected in policy.get("bindings", {}).items():
        if ledger_digest(_safe_path(root / relative, root)) != expected:
            raise AccountingError("engineering24-binding-stale:" + relative)
    if not isinstance(value.get("d125_engineering24_activities"), list) or not isinstance(
            value.get("d125_engineering24_reviews"), list):
        raise AccountingError("engineering24-history-invalid")
    return policy


def install_engineering24_policy(ledger_path, *, project_root):
    """Install the distinct global-only owner from the immutable reviewed entry."""
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    entry_path = _safe_path(root / "build/phase6/d125-engineering24/entry.json", root)
    closeout_path = _safe_path(root / "evidence/phase6-d125-proof-receipt-debug-closeout.json", root)
    with _locked(path):
        value = _load(path, root)
        if "d125_engineering24_policy" in value:
            raise AccountingError("engineering24-policy-already-installed")
        entry = json.loads(entry_path.read_bytes())
        closeout = json.loads(closeout_path.read_bytes())
        if (entry.get("schema") != "phase6-d125-engineering24-entry-v1" or
                entry.get("status") != "active" or entry.get("boot_identity") != closeout.get("boot_identity") or
                entry.get("final_entry_ledger_sha256") != ledger_digest(path) or
                entry.get('debug_closeout_sha256') != ledger_digest(closeout_path) or
                entry.get('global_closed_floor_seconds') != closeout.get('global_used_seconds') or
                closeout.get("debug_anchor_closed") is not True or closeout.get("production_anchor") is not None):
            raise AccountingError("engineering24-entry-not-reconciled")
        bindings = entry.get("input_sha256", {})
        if not isinstance(bindings, dict) or any(
                ledger_digest(_safe_path(root / name, root)) != digest for name, digest in bindings.items()):
            raise AccountingError("engineering24-entry-binding-stale")
        policy = {"schema": "phase6-d125-engineering24-v1", "plan": "06-24",
            "status": "engineering-only", "game_admission": False, "test_fixture_only": False,
            "retained_count": 3, "fresh_count": 0, "global_cap_seconds": 43200.0,
            "global_floor_seconds": closeout["global_used_seconds"],
            "parent_active_discovery_prefix_seconds": entry["parent_active_discovery_prefix_seconds"],
            "pea_floor_seconds": 7098.193, "process_floor_seconds": 5.865,
            "attempts_floor": 2, "pea_cap_seconds": 9403.235, "process_cap_seconds": 1800.0,
            "attempts_cap": 3, "protected_process_seconds": 1794.135,
            "closeout_reserve_seconds": 120.0, "boot_identity": entry["boot_identity"],
            "entry_ledger_sha256": entry["final_entry_ledger_sha256"],
            "debug_closeout_sha256": entry["debug_closeout_sha256"],
            "entry_sha256": ledger_digest(entry_path), "bindings": bindings,
            "anchor": {"status": "active", "monotonic_started_at": entry["monotonic_started_at"],
                       "started_at": entry["started_at"], "boot_identity": entry["boot_identity"],
                       "entry_sha256": ledger_digest(entry_path), "pea_charge": False}}
        value["d125_engineering24_policy"] = policy
        value["d125_engineering24_activities"] = []
        value["d125_engineering24_reviews"] = []
        engineering24_owner(value, project_root=root, boot_identity=entry['boot_identity'])
        _write(path, value)
        return dict(policy)


def _engineering24_headroom(value, policy, now, forecast):
    forecast = _numeric(forecast, "engineering24-complete-forecast")
    if forecast < 0:
        raise AccountingError("engineering24-negative-forecast")
    elapsed = now - _numeric(policy["anchor"]["monotonic_started_at"], "engineering24-anchor-start")
    if elapsed < 0:
        raise AccountingError("engineering24-anchor-rollback")
    remaining = (43200.0 - policy["global_floor_seconds"] -
                 policy["parent_active_discovery_prefix_seconds"] - elapsed)
    if remaining < forecast + 1794.135 + 120.0:
        raise AccountingError("engineering24-forecast-and-reserves-insufficient")
    return remaining


def begin_engineering24_activity(ledger_path, *, activity_id, stage, exposure_seconds,
                                 remaining_forecast_seconds, boot_identity, project_root):
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    if not re.fullmatch(r"d125-engineering24-[a-z0-9][a-z0-9-]{0,90}", activity_id):
        raise AccountingError("engineering24-activity-id-invalid")
    limits = {"engineering": 900.0, "closure": 250.0, "review": 500.0,
              "reconciliation": 150.0}
    exposure = _numeric(exposure_seconds, "engineering24-exposure")
    if stage not in limits or exposure <= 0 or exposure > limits[stage]:
        raise AccountingError("engineering24-stage-or-exposure-invalid")
    with _locked(path):
        value = _load(path, root)
        policy = engineering24_owner(value, project_root=root, boot_identity=boot_identity)
        rows = value["d125_engineering24_activities"]
        if any(r.get("activity_id") == activity_id for r in rows):
            raise AccountingError("engineering24-activity-spent")
        if any(r.get("status") == "reserved" for r in rows):
            raise AccountingError("engineering24-activity-overlap")
        now = time.monotonic()
        remaining = _engineering24_headroom(value, policy, now, remaining_forecast_seconds)
        if remaining_forecast_seconds < exposure:
            raise AccountingError("engineering24-forecast-smaller-than-batch")
        row = {"activity_id": activity_id, "stage": stage, "exposure_seconds": exposure,
            "remaining_forecast_seconds": remaining_forecast_seconds,
            "global_remaining_at_admission": remaining, "status": "reserved",
            "reserved_at_monotonic": now, "boot_identity": boot_identity,
            "game_admission": False, "pea_charge_seconds": 0.0, "created_at": _now()}
        rows.append(row)
        _write(path, value)
        return dict(row)


def finalize_engineering24_activity(ledger_path, *, activity_id, status, boot_identity,
                                    project_root, result=None):
    if status not in ("completed", "interrupted"):
        raise AccountingError("engineering24-activity-status-invalid")
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    with _locked(path):
        value = _load(path, root)
        engineering24_owner(value, project_root=root, boot_identity=boot_identity)
        rows = [r for r in value["d125_engineering24_activities"] if r.get("activity_id") == activity_id]
        if len(rows) != 1 or rows[0].get("status") != "reserved":
            raise AccountingError("engineering24-reservation-changed")
        row = rows[0]
        elapsed = _numeric(time.monotonic() - row["reserved_at_monotonic"], "engineering24-elapsed")
        exceeded = elapsed < 0 or elapsed > row["exposure_seconds"]
        row.update(status="interrupted" if exceeded else status, elapsed_seconds=elapsed,
                   finalized_at=_now())
        if result is not None:
            encoded = json.dumps(result, sort_keys=True, allow_nan=False)
            row["result_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()
            row["result"] = json.loads(encoded.replace(str(root), "$PROJECT_ROOT"))
        _write(path, value)
    if exceeded:
        raise AccountingError("engineering24-exposure-exceeded")
    return dict(row)


def close_engineering24(ledger_path, *, output, status, reason, boot_identity, project_root,
                        closeout_allowance_seconds=120.0):
    """Commit a terminal global-only snapshot and its exact create-once receipt intent."""
    if status not in ("HALTED", "accepted-engineering24"):
        raise AccountingError("engineering24-terminal-status-invalid")
    if status == 'accepted-engineering24':
        raise AccountingError('engineering24-accepted-close-unsupported-current-proof-tuple-required')
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    receipt = _safe_create_path(output, root)
    allowance = _numeric(closeout_allowance_seconds, "engineering24-closeout-allowance")
    if allowance < 120.0:
        raise AccountingError("engineering24-closeout-reserve-required")
    with _locked(path):
        value = _load(path, root)
        receipt = _safe_create_path(output, root)
        policy = engineering24_owner(value, project_root=root, boot_identity=boot_identity)
        now = time.monotonic()
        elapsed = now - policy["anchor"]["monotonic_started_at"]
        if elapsed < 0:
            raise AccountingError("engineering24-anchor-rollback")
        for row in value["d125_engineering24_activities"]:
            if row.get("status") == "reserved":
                row.update(status="interrupted", elapsed_seconds=now-row["reserved_at_monotonic"],
                           failure="engineering24-terminal-halt")
        report = {"schema": "phase6-d125-engineering24-terminal-v1", "status": status,
            "reason": reason, "plan": "06-24", "game_admission": False,
            "retained_count": 3, "fresh_count": 0, "anchor": None,
            "global_used_seconds": policy["global_floor_seconds"] +
                policy["parent_active_discovery_prefix_seconds"] + elapsed + allowance,
            "global_remaining_seconds": 43200.0 - policy["global_floor_seconds"] -
                policy["parent_active_discovery_prefix_seconds"] - elapsed - allowance,
            "pea_used_seconds": 7098.193, "process_used_seconds": 5.865,
            "attempts_used": 2, "measured_owner_seconds": elapsed,
            "parent_active_discovery_prefix_seconds": policy["parent_active_discovery_prefix_seconds"],
            "closeout_allowance_seconds": allowance, "monotonic_closed_at": now,
            "monotonic_allowance_deadline": now + allowance,
            "entry_ledger_sha256": policy["entry_ledger_sha256"],
            "entry_sha256": policy["entry_sha256"], "reason_recorded_at": _now()}
        receipt_bytes = _receipt_payload(report)
        policy.update(status="terminal-halted" if status == "HALTED" else "terminal-accepted",
                      anchor=None, terminal_snapshot=report,
                      receipt_intent={"path": receipt.relative_to(root).as_posix(),
                          "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                          "bytes": receipt_bytes.decode("utf-8")})
        _write(path, value)
    _publish_receipt_once(receipt, report)
    return report


def recover_engineering24_receipt(ledger_path, *, output, project_root):
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    with _locked(path):
        value = _load(path, root)
        policy = value.get("d125_engineering24_policy", {})
        intent = policy.get("receipt_intent")
        if policy.get("status") not in ("terminal-halted", "terminal-accepted") or policy.get("anchor") is not None:
            raise AccountingError("engineering24-terminal-snapshot-required")
        candidate = pathlib.Path(output)
        if candidate.is_symlink():
            raise AccountingError('engineering24-receipt-conflict')
        receipt = (_safe_path(candidate, root) if candidate.exists()
                   else _safe_create_path(candidate, root))
        if not isinstance(intent, dict) or intent.get("path") != receipt.relative_to(root).as_posix():
            raise AccountingError("engineering24-receipt-intent-mismatch")
        raw = intent.get("bytes", "").encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != intent.get("sha256"):
            raise AccountingError("engineering24-receipt-intent-corrupt")
        report = json.loads(raw)
        if receipt.exists():
            if receipt.is_symlink() or receipt.read_bytes() != raw:
                raise AccountingError("engineering24-receipt-conflict")
            return report
    _publish_receipt_once(receipt, report)
    return report


def _qualification23_headroom(value, policy, now, forecast):
    forecast = _numeric(forecast, "qualification23-complete-forecast")
    if forecast < 0:
        raise AccountingError("qualification23-negative-forecast")
    remaining = 43200.0 - _closed_seconds(value["phase6_accounting"]) - _active_elapsed(
        value["phase6_accounting"], now, policy["boot_identity"])
    if remaining < forecast + 1794.135 + 120.0:
        raise AccountingError("qualification23-complete-forecast-and-reserves-insufficient")
    return remaining


def begin_qualification23_activity(ledger_path, *, activity_id, stage, exposure_seconds,
                                  boot_identity, project_root, remaining_forecast_seconds=None):
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    if not re.fullmatch(r"(?:d123-qual-g23-|qualification23-)[a-z0-9][a-z0-9-]{0,100}", activity_id):
        raise AccountingError("qualification23-activity-id-invalid")
    limits = {"build": 300.0, "diagnostic": 30.0, "qualification": 30.0,
              "engineering": 4200.0, "review": 1500.0, "reconciliation": 300.0}
    exposure = _numeric(exposure_seconds, "qualification23-exposure")
    if stage not in limits or exposure <= 0 or exposure > limits[stage]:
        raise AccountingError("qualification23-stage-or-exposure-invalid")
    with _locked(path):
        value = _load(path, root)
        policy = qualification23_owner(value, project_root=root, boot_identity=boot_identity)
        rows = value["d125_qualification23_activities"]
        if any(r.get("activity_id") == activity_id for r in rows):
            raise AccountingError("qualification23-activity-spent")
        if any(r.get("status") == "reserved" for r in rows):
            raise AccountingError("qualification23-activity-overlap")
        if stage == "qualification" and (activity_id not in
                {"d123-qual-g23-" + name for name in ("native", "sanitize", "hooks-off")} or
                sum(r.get("stage") == "qualification" for r in rows) >= 3):
            raise AccountingError("qualification23-exact-three-purposes-required")
        if stage == "build" and sum(_numeric(r.get("elapsed_seconds", 0), "build-elapsed")
                for r in rows if r.get("stage") == "build") + exposure > 300.0:
            raise AccountingError("qualification23-aggregate-build-exhausted")
        forecasts = [r for r in value["d125_qualification23_reviews"] if r.get("event") == "forecast-refresh"]
        latest_forecast = forecasts[-1]["remaining_forecast_seconds"] if forecasts else policy["remaining_forecast_seconds"]
        forecast = latest_forecast if remaining_forecast_seconds is None else remaining_forecast_seconds
        forecast = _numeric(forecast, "qualification23-complete-forecast")
        if forecast < exposure:
            raise AccountingError("qualification23-forecast-smaller-than-batch")
        now = time.monotonic()
        remaining = _qualification23_headroom(value, policy, now, forecast)
        row = {"activity_id": activity_id, "stage": stage, "exposure_seconds": exposure,
            "remaining_forecast_seconds": forecast, "global_remaining_at_admission": remaining,
            "status": "reserved", "reserved_at_monotonic": now, "boot_identity": boot_identity,
            "game_admission": False, "pea_charge_seconds": 0.0, "created_at": _now()}
        rows.append(row)
        _write(path, value)
        return dict(row)


def finalize_qualification23_activity(ledger_path, *, activity_id, status, boot_identity, project_root,
                                     result=None):
    if status not in ("completed", "interrupted"):
        raise AccountingError("qualification23-activity-status-invalid")
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    with _locked(path):
        value = _load(path, root)
        qualification23_owner(value, project_root=root, boot_identity=boot_identity)
        rows = [r for r in value["d125_qualification23_activities"] if r.get("activity_id") == activity_id]
        if len(rows) != 1 or rows[0].get("status") != "reserved":
            raise AccountingError("qualification23-reservation-changed")
        row = rows[0]
        elapsed = _numeric(time.monotonic() - row["reserved_at_monotonic"], "qualification23-elapsed")
        if elapsed < 0:
            raise AccountingError("qualification23-negative-elapsed")
        exceeded = elapsed > row["exposure_seconds"]
        row.update(status="interrupted" if exceeded else status, elapsed_seconds=elapsed,
                   finalized_at=_now())
        if result is not None:
            encoded = json.dumps(result, sort_keys=True, allow_nan=False)
            row["result_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()
            row["result"] = json.loads(encoded.replace(str(root), "$PROJECT_ROOT"))
        _write(path, value)
    if exceeded:
        raise AccountingError("qualification23-exposure-exceeded")
    return dict(row)


def close_qualification23(ledger_path, *, output, status, reason, boot_identity, project_root,
                         closeout_allowance_seconds=120.0):
    """Close global-only accounting once; successful acceptance requires separate review."""
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    output = _safe_create_path(output, root)
    if status not in ("HALTED", "accepted-affected-qualification-and-consumers"):
        raise AccountingError("qualification23-terminal-status-invalid")
    allowance = _numeric(closeout_allowance_seconds, "qualification23-closeout-allowance")
    if allowance < 120.0:
        raise AccountingError("qualification23-closeout-reserve-required")
    with _locked(path):
        value = _load(path, root)
        # A racing closer must not commit a second terminal interval.
        output = _safe_create_path(output, root)
        policy = qualification23_owner(value, project_root=root, boot_identity=boot_identity)
        qualification_count = sum(r.get("stage") == "qualification" and r.get("status") == "completed"
                                  for r in value["d125_qualification23_activities"])
        acceptance_files = {}
        if status != "HALTED":
            phase = root / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes"
            review_path = _safe_path(phase / "06-23-FINAL-REVIEW.json", root)
            pin_path = _safe_path(phase / "06-23-PARENT-FINAL.json", root)
            review = json.loads(review_path.read_bytes()); pin = json.loads(pin_path.read_bytes())
            if (review.get("decision") != "accepted" or review.get("high_count") != 0 or review.get("critical_count") != 0 or
                    pin.get("origin") != "parent-observed-separate-reviewer-completion" or
                    pin.get("tool_handoff_result") != "completed" or pin.get("decision") != "accepted" or
                    pin.get("reviewer_identity") != review.get("reviewer_identity") or
                    pin.get("reviewer_role") != "gsd-code-reviewer" or pin.get("test_fixture_only") is True or
                    pin.get("review_sha256") != ledger_digest(review_path) or qualification_count != 3):
                raise AccountingError("qualification23-current-independent-acceptance-required")
            acceptance_files = pin.get("file_sha256", {})
            required = {"build/phase6/d125-debug/plan23/final-chain.json",
                        "evidence/phase6-tank-observer-bridge-d125-g23.json",
                        "evidence/phase6-tank-observer-review-check-d125-g23.json"}
            if not required.issubset(acceptance_files) or any(ledger_digest(_safe_path(root/p,root)) != h
                                                           for p,h in acceptance_files.items()):
                raise AccountingError("qualification23-final-reviewed-tuple-stale")
            chain = json.loads((root / "build/phase6/d125-debug/plan23/final-chain.json").read_bytes())
            if (chain.get("status") != "passed" or chain.get("game_admission") is not False or
                    chain.get("fake_leaf_calls") != ["capture", "control", "control"] or
                    chain.get("counts", {}).get("control_evidence", {}).get("full_pcm_files") != 12 or
                    chain.get("guard", {}).get("attempted") != 0 or chain.get("guard", {}).get("permitted") != 0 or
                    not chain.get("checks") or not all(r.get("passed") is True for r in chain["checks"])):
                raise AccountingError("qualification23-complete-real-consumer-evidence-required")
            import importlib.util
            spec = importlib.util.spec_from_file_location("qualification23_close_checker", root / "tests/evidence/phase6_tank_continuation_contract.py")
            checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(checker)
            checker.verify_qualification23_companion(root / "evidence/phase6-tank-observer-bridge-d125-g23.json",
                phase / "06-23-PROOF-REVIEW.md", root / "evidence/phase6-tank-observer-review-check-d125-g23.json", root / "build/phase6")
        now = time.monotonic()
        state = value["phase6_accounting"]
        anchor = state["active_anchor"]
        elapsed = _active_elapsed(state, now, boot_identity)
        for row in value["d125_qualification23_activities"]:
            if row.get("status") == "reserved":
                row.update(status="interrupted", elapsed_seconds=now-row["reserved_at_monotonic"],
                           failure="qualification23-terminal-halt")
        state["closed_intervals"].extend([
            {"id": policy["anchor_id"]+"-measured-close", "active": True, "active_seconds": elapsed,
             "monotonic_started_at": anchor["monotonic_started_at"], "monotonic_closed_at": now,
             "boot_identity": boot_identity, "pea_charge_seconds": 0.0,
             "basis": "Measured same-boot Plan23 engineering/reviews/handoffs globally once"},
            {"id": policy["anchor_id"]+"-final-closeout-allowance", "active": True,
             "active_seconds": allowance, "monotonic_allowance_started_at": now,
             "monotonic_allowance_deadline": now+allowance, "pea_charge_seconds": 0.0,
             "basis": "Conservative labelled final bookkeeping/commit/parent handoff allowance; excess appended separately"}])
        state["active_anchor"] = None
        policy["status"] = "terminal-halted" if status == "HALTED" else "terminal-accepted-engineering-only"
        report = {"schema": "phase6-d125-qualification23-terminal-v1", "status": status,
            "reason": reason, "game_admission": False, "anchor": None, "qualification_count": qualification_count,
            "qualification_planned": 3, "global_used_seconds": _closed_seconds(state),
            "global_remaining_seconds": 43200.0-_closed_seconds(state), "pea_used_seconds": 7098.193,
            "process_used_seconds": 5.865, "attempts_used": 2, "measured_owner_seconds": elapsed,
            "closeout_allowance_seconds": allowance, "monotonic_closed_at": now,
            "monotonic_allowance_deadline": now+allowance, "boot_identity": boot_identity,
            "phase6_complete": False, "phase7_started": False, "auto_advance": False,
            "game_purpose_created": False, "closed_at": _now()}
        report["accepted_file_sha256"] = acceptance_files
        value["d125_qualification23_reviews"].append({"event": "terminal", "status": status,
            "reason": reason, "closed_at": report["closed_at"]})
        # Commit the exact publication intent with accounting. Publication can
        # fail after this durable write; recovery must never rerun the close.
        value["d125_qualification23_terminal_receipt"] = {
            "path": output.relative_to(root).as_posix(), "report": report,
            "sha256": hashlib.sha256(_receipt_payload(report)).hexdigest()}
        _write(path, value)
        _publish_receipt_once(output, report)
        return report


def recover_qualification23_receipt(ledger_path, *, output, project_root):
    """Publish only the exact committed receipt, without reopening accounting.

    Legacy terminal ledgers without a stored publication intent require separate
    audited recovery; this function never reconstructs or revises their history.
    An already complete identical receipt is an idempotent recovery observation,
    not an overwrite or a second close.
    """
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    target = pathlib.Path(output)
    if target.is_symlink():
        raise AccountingError("qualification23-recovery-output-symlink")
    try:
        parent = target.parent.resolve(strict=True)
    except OSError as exc:
        raise AccountingError("qualification23-recovery-output-parent-invalid") from exc
    target = parent / target.name
    if not target.is_relative_to(root):
        raise AccountingError("ledger-path-escape-denied")
    with _locked(path):
        value = _load(path, root)
        saved = value.get("d125_qualification23_terminal_receipt", {})
        report = saved.get("report")
        policy = value.get("d125_qualification23_policy", {})
        if (not isinstance(report, dict) or saved.get("path") != target.relative_to(root).as_posix() or
                report.get("schema") != "phase6-d125-qualification23-terminal-v1" or
                report.get("status") not in {"HALTED", "accepted-affected-qualification-and-consumers"} or
                policy.get("status") != ("terminal-halted" if report["status"] == "HALTED" else "terminal-accepted-engineering-only") or
                value["phase6_accounting"].get("active_anchor") is not None or
                report.get("anchor") is not None or report.get("game_admission") is not False or
                saved.get("sha256") != hashlib.sha256(_receipt_payload(report)).hexdigest()):
            raise AccountingError("qualification23-committed-receipt-required")
        payload = _receipt_payload(report)
        if target.is_symlink():
            raise AccountingError("qualification23-recovery-output-symlink")
        if target.exists():
            if not target.is_file() or target.read_bytes() != payload:
                raise AccountingError("qualification23-recovery-output-conflict")
            _fsync_directory(parent)
        else:
            _publish_receipt_once(target, report)
        return report


def _d125_fixture_authorized(value, root):
    authority = TEST_FIXTURE_D125_AUTHORITY
    if authority is None:
        if value.get("test_fixture_only") is True:
            raise AccountingError("d125-fixture-authority-required")
        return False
    checkout = next((p for p in root.parents if (p / ".git").exists()), None)
    marker = root / "metadata/d125-authored-root.json"
    if (checkout is None or root == checkout or
            not root.is_relative_to(checkout / "build/phase6/d125-debug") or
            not root.name.startswith("synthetic-consumer-") or
            authority != {"schema": "d125-authored-owner-authority-v1", "root": str(root), "test_fixture_only": True} or
            value.get("test_fixture_only") is not True or marker.is_symlink() or
            json.loads(marker.read_bytes()) != {"schema": "d125-authored-root-v1", "test_fixture_only": True}):
        raise AccountingError("d125-fixture-authority-denied")
    return True


def selected_recovery_owner(value, *, project_root=None, require_runtime=False):
    """Select explicit immutable22 lineage, never infer permission from old policies."""
    root = pathlib.Path(project_root or pathlib.Path(__file__).resolve().parents[2]).resolve(strict=True)
    fixture = _d125_fixture_authorized(value, root)
    generations = value.get("d125_owner_generations", [])
    if not isinstance(generations, list) or not generations:
        raise AccountingError("d125-owner-missing")
    ids = [g.get("generation_id") for g in generations]
    if len(set(ids)) != len(ids) or any(not isinstance(g, str) or not g for g in ids):
        raise AccountingError("d125-owner-ambiguous")
    for index, item in enumerate(generations[1:], 1):
        if item.get("parent_generation_sha256") != hashlib.sha256(_canonical(generations[index-1])).hexdigest():
            raise AccountingError("d125-owner-lineage-stale")
    generation = generations[-1]
    if (generation.get("plan") != D125_PLAN_ID or generation.get("immutable_generation") is not True or
            generation.get("test_fixture_only", False) is not fixture or
            generation.get("status") not in ("engineering-only", "prospective-bound") or
            generation.get("global_floor_seconds") != 28286.671 or
            generation.get("global_cap_seconds") != 43200.0 or generation.get("pea_floor_seconds") != 7097.572 or
            generation.get("pea_cap_seconds") != 9403.235 or generation.get("process_floor_seconds") != 5.244 or
            generation.get("process_cap_seconds") != 1800.0 or generation.get("attempts_floor") != 1 or
            generation.get("attempts_cap") != 3):
        raise AccountingError("d125-owner-constants-or-status-invalid")
    if type(generation.get("attempts_floor")) is not int or type(generation.get("attempts_cap")) is not int:
        raise AccountingError("d125-owner-constants-or-status-invalid")
    anchor = value["phase6_accounting"].get("active_anchor")
    if (not isinstance(anchor, dict) or anchor.get("id") != generation.get("anchor_id") or
            anchor.get("purpose") != "d125-owner22-global-engineering" or anchor.get("pea_charge") is not False or
            anchor.get("boot_identity") != generation.get("boot_identity")):
        raise AccountingError("d125-owner-anchor-invalid")
    if not fixture:
        bindings = generation.get("bindings", {})
        required = {".planning/phases/GW-06-shared-repairs-and-two-playable-routes/" + name for name in
                    ("06-CONTEXT.md", "06-22-PLAN.md", "06-D125-22-PLAN-CHECK.md")}
        required.add(".planning/context/OPERATING.md")
        if set(bindings) != required or any(not (root / p).is_file() or ledger_digest(root / p) != h for p, h in bindings.items()):
            raise AccountingError("d125-owner-plan-binding-stale")
    events = value.get("d125_owner_events", [])
    if any(e.get("event") == "terminal" and e.get("generation_id") in ids for e in events):
        raise AccountingError("d125-owner-terminal")
    if require_runtime:
        activations = [e for e in events if e.get("event") == "owner-activated"]
        if len(activations) != 1:
            raise AccountingError("d125-owner-activation-missing-or-ambiguous")
        event = activations[0]
        if (event.get("generation_id") != generation["generation_id"] or
                event.get("generation_sha256") != hashlib.sha256(_canonical(generation)).hexdigest() or
                generation.get("status") != "prospective-bound"):
            raise AccountingError("d125-owner-activation-stale")
        binding = generation.get("runtime_binding", {})
        forecast=generation.get("launch_forecast",{})
        if set(forecast)!={"nonprocess_seconds","final_review_seconds","remaining_engineering_seconds","process_seconds","closeout_seconds"}:
            raise AccountingError("d125-owner-complete-launch-forecast-required")
        numbers={k:_numeric(v,"d125-owner-forecast-"+k) for k,v in forecast.items()}
        if (numbers["final_review_seconds"]<=0 or numbers["remaining_engineering_seconds"]<0 or
                numbers["nonprocess_seconds"]!=numbers["final_review_seconds"]+numbers["remaining_engineering_seconds"] or
                numbers["process_seconds"]!=1794.756 or numbers["closeout_seconds"]<120):
            raise AccountingError("d125-owner-complete-launch-forecast-invalid")
        if set(binding) != {"source_identity", "bridge", "proof_review", "review_check", "component_review", "parent_pin"}:
            raise AccountingError("d125-owner-runtime-binding-incomplete")
        if binding["source_identity"] != source_identity(root):
            raise AccountingError("d125-owner-source-stale")
        for key in ("bridge", "proof_review", "review_check", "component_review", "parent_pin"):
            item = binding[key]
            target = _safe_path(root / item.get("path", ""), root)
            if target.stat().st_nlink != 1 or ledger_digest(target) != item.get("sha256"):
                raise AccountingError("d125-owner-tuple-stale:" + key)
        if not fixture:
            pin = json.loads((root / binding["parent_pin"]["path"]).read_bytes())
            if (pin.get("origin") != "parent-observed-separate-reviewer-completion" or
                    pin.get("decision") != "accepted" or pin.get("tool_handoff_result") != "completed" or
                    pin.get("reviewer_role") != "gsd-code-reviewer" or pin.get("test_fixture_only") is True or
                    not pin.get("reviewer_identity")):
                raise AccountingError("d125-owner-real-review-required")
            if pin.get("launch_forecast")!=forecast:
                raise AccountingError("d125-owner-forecast-review-binding-stale")
    return generation


def install_d125_owner(ledger_path, *, generation, boot_identity, project_root):
    """Append a bound generation and explicit activation; never change bootstrap/history."""
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    with _locked(path):
        value = _load(path, root)
        previous = selected_recovery_owner(value, project_root=root)
        if generation.get("boot_identity") != boot_identity or boot_identity != previous["boot_identity"]:
            raise AccountingError("d125-boot-identity-mismatch")
        if generation.get("generation_id") in [g["generation_id"] for g in value["d125_owner_generations"]]:
            raise AccountingError("d125-owner-generation-replayed")
        if generation.get("parent_generation_sha256") != hashlib.sha256(_canonical(previous)).hexdigest():
            raise AccountingError("d125-owner-lineage-stale")
        value["d125_owner_generations"].append(generation)
        value.setdefault("d125_owner_events", []).append({"event": "owner-activated", "generation_id": generation["generation_id"],
            "generation_sha256": hashlib.sha256(_canonical(generation)).hexdigest(), "created_at": _now()})
        selected_recovery_owner(value, project_root=root, require_runtime=True)
        for case in ("control-repeat-1", "control-repeat-2"):
            value.setdefault("d125_spent_purposes", []).append({"case": case, "disposition": "spent-not-accepted",
                "production_reservation_created": False, "attempts_added": 0, "charge_already_in_floor": True})
        _write(path, value)
        return generation


def d125_remaining(value, *, monotonic_now, boot_identity, project_root=None):
    owner = selected_recovery_owner(value, project_root=project_root)
    now = _numeric(monotonic_now, "d125-monotonic-now")
    if boot_identity != owner["boot_identity"]:
        raise AccountingError("d125-boot-identity-mismatch")
    global_used = _closed_seconds(value["phase6_accounting"]) + _active_elapsed(value["phase6_accounting"], now, boot_identity)
    rows = [r for r in value["records"] if r.get("d125_owner") == D125_PLAN_ID]
    charges = [_numeric(r.get("process_active_seconds", 0), "d125-process-seconds") for r in rows]
    if any(charge < 0 for charge in charges):
        raise AccountingError("d125-negative-process-charge")
    process = sum(charges)
    attempts = 1 + sum(r.get("new_target_attempts", 0) for r in rows)
    if type(attempts) is not int or attempts not in (1, 2, 3):
        raise AccountingError("d125-attempts-invalid")
    # Do not round balances upward: a 599.9999 remainder cannot fund600.
    return {"global_used_seconds": global_used, "global_remaining_seconds": max(0.0, 43200.0 - global_used),
        "process_used_seconds": 5.244 + process, "process_remaining_seconds": max(0.0, 1800.0 - 5.244 - process),
        "pea_used_seconds": 7097.572 + process, "pea_remaining_seconds": max(0.0, 9403.235 - 7097.572 - process),
        "attempts_used": attempts, "closeout_reserve_seconds": 120.0}


def _d125_process_preflight(value, *, case, monotonic_now, boot_identity, project_root=None):
    owner = selected_recovery_owner(value, project_root=project_root, require_runtime=True)
    if case not in D125_CASES:
        raise AccountingError("d125-process-purpose-not-selected")
    rows = [r for r in value["records"] if r.get("d125_owner") == D125_PLAN_ID]
    if any(r.get("status") == "reserved" for r in rows):
        raise AccountingError("d125-process-already-active")
    index = D125_CASES.index(case)
    if [r.get("case") for r in rows] != list(D125_CASES[:index]) or any(r.get("status") != "completed" for r in rows):
        raise AccountingError("d125-process-replayed-or-out-of-order")
    remaining = d125_remaining(value, monotonic_now=monotonic_now, boot_identity=boot_identity, project_root=project_root)
    if any(remaining[name] < 600.0 for name in ("global_remaining_seconds", "pea_remaining_seconds", "process_remaining_seconds")):
        raise AccountingError("d125-next600-headroom-insufficient")
    if remaining["global_remaining_seconds"] < remaining["process_remaining_seconds"] + 120.0:
        raise AccountingError("d125-protected-global-reserve-insufficient")
    return remaining


def admit_d125_forecast(ledger_path, *, activity_id, nonprocess_seconds, process_seconds,
                        boot_identity, project_root, closeout_seconds=120.0):
    nonprocess = _numeric(nonprocess_seconds, "d125-forecast-nonprocess")
    process = _numeric(process_seconds, "d125-forecast-process")
    closeout = _numeric(closeout_seconds, "d125-forecast-closeout")
    if nonprocess < 0 or process < 0 or closeout < 120 or not re.fullmatch(r"d125-[a-z0-9-]{1,100}", activity_id):
        raise AccountingError("d125-forecast-invalid")
    root = pathlib.Path(project_root).resolve(strict=True); path = _safe_path(ledger_path, root)
    with _locked(path):
        value = _load(path, root)
        owner=selected_recovery_owner(value,project_root=root)
        remaining = d125_remaining(value, monotonic_now=time.monotonic(), boot_identity=boot_identity, project_root=root)
        if any(row.get("activity_id") == activity_id for row in value.get("d125_admissions", [])):
            raise AccountingError("d125-forecast-replayed")
        if (remaining["global_remaining_seconds"] < nonprocess + process + closeout or
                remaining["process_remaining_seconds"] < process):
            raise AccountingError("d125-complete-forecast-insufficient")
        row = {"schema":"phase6-d125-forecast-admission-v1","status":"admitted","activity_id": activity_id, "nonprocess_seconds": nonprocess, "process_seconds": process,
            "closeout_seconds": closeout, "remaining": remaining, "admitted_at_monotonic": time.monotonic(), "boot_identity": boot_identity}
        row.update(generation_id=owner["generation_id"],generation_sha256=hashlib.sha256(_canonical(owner)).hexdigest(),
            source_identity=source_identity(root),launch_forecast_sha256=hashlib.sha256(_canonical(owner.get("launch_forecast"))).hexdigest())
        value.setdefault("d125_admissions", []).append(row)
        value.setdefault("d125_owner_events",[]).append({"event":"forecast-admitted","activity_id":activity_id,
            "admission_sha256":hashlib.sha256(_canonical(row)).hexdigest(),"generation_id":owner["generation_id"]})
        _write(path, value)
        return row


def _d125_validate_launch_forecast(value, owner, remaining, *, monotonic_now, boot_identity):
    admissions=value.get("d125_admissions",[])
    if not admissions:raise AccountingError("d125-complete-forecast-required")
    row=admissions[-1]
    expected={"schema":"phase6-d125-forecast-admission-v1","status":"admitted","boot_identity":boot_identity,
        "generation_id":owner["generation_id"],"generation_sha256":hashlib.sha256(_canonical(owner)).hexdigest(),
        "source_identity":owner["runtime_binding"]["source_identity"],
        "launch_forecast_sha256":hashlib.sha256(_canonical(owner["launch_forecast"])).hexdigest()}
    events=[e for e in value.get("d125_owner_events",[]) if e.get("event")=="forecast-admitted" and
        e.get("activity_id")==row.get("activity_id") and e.get("generation_id")==owner["generation_id"]]
    if (any(row.get(k)!=v for k,v in expected.items()) or not re.fullmatch(r"d125-[a-z0-9-]{1,100}",str(row.get("activity_id",""))) or
            len(events)!=1 or events[0].get("admission_sha256")!=hashlib.sha256(_canonical(row)).hexdigest()):
        raise AccountingError("d125-launch-forecast-invalid")
    admitted=_numeric(row.get("admitted_at_monotonic"),"d125-forecast-time")
    nonprocess=_numeric(row.get("nonprocess_seconds"),"d125-process-forecast")
    process=_numeric(row.get("process_seconds"),"d125-process-forecast-process")
    closeout=_numeric(row.get("closeout_seconds"),"d125-process-forecast-closeout")
    if (not 0<=monotonic_now-admitted<=60 or nonprocess<owner["launch_forecast"]["nonprocess_seconds"] or
            process!=remaining["process_remaining_seconds"] or closeout<owner["launch_forecast"]["closeout_seconds"]):
        raise AccountingError("d125-launch-forecast-stale-or-incomplete")
    if remaining["global_remaining_seconds"]<nonprocess+process+closeout:
        raise AccountingError("d125-complete-process-forecast-insufficient")
    return row


def begin_d125_activity(ledger_path, *, activity_id, stage, exposure_seconds, boot_identity, project_root):
    exposure = _numeric(exposure_seconds, "d125-exposure")
    if exposure <= 0 or exposure > 9000 or not re.fullmatch(r"d125-[a-z0-9-]{1,100}", activity_id):
        raise AccountingError("d125-activity-invalid")
    root = pathlib.Path(project_root).resolve(strict=True); path = _safe_path(ledger_path, root)
    with _locked(path):
        value = _load(path, root)
        remaining = d125_remaining(value, monotonic_now=time.monotonic(), boot_identity=boot_identity, project_root=root)
        runs = value.setdefault("d125_runs", [])
        if any(row.get("activity_id") == activity_id for row in runs):
            raise AccountingError("d125-activity-replayed")
        if any(row.get("status") == "reserved" for row in runs):
            raise AccountingError("d125-activity-already-active")
        if remaining["global_remaining_seconds"] < exposure + remaining["process_remaining_seconds"] + 120:
            raise AccountingError("d125-protected-global-reserve-insufficient")
        row = {"activity_id": activity_id, "stage": stage, "exposure_seconds": exposure, "status": "reserved",
            "reserved_at_monotonic": time.monotonic(), "boot_identity": boot_identity, "pea_charge_seconds": 0.0}
        runs.append(row); _write(path, value); return dict(row)


def finalize_d125_activity(ledger_path, *, activity_id, status, boot_identity, allowed_root=None):
    if status not in ("completed", "interrupted"):
        raise AccountingError("d125-finalization-status-invalid")
    path = _safe_path(ledger_path, allowed_root)
    with _locked(path):
        value = _load(path, allowed_root)
        selected_recovery_owner(value, project_root=allowed_root)
        rows = [r for r in value.get("d125_runs", []) if r.get("activity_id") == activity_id]
        if len(rows) != 1 or rows[0].get("status") != "reserved":
            raise AccountingError("d125-activity-not-live-or-replayed")
        row = rows[0]
        if boot_identity != row["boot_identity"]:
            raise AccountingError("d125-boot-identity-mismatch")
        elapsed = time.monotonic() - _numeric(row["reserved_at_monotonic"], "d125-activity-start")
        if elapsed < 0:
            raise AccountingError("d125-clock-rollback")
        exceeded = elapsed > row["exposure_seconds"]
        row.update(status="interrupted" if exceeded else status, elapsed_seconds=elapsed, finalized_at=_now())
        _write(path, value)
        if exceeded:
            raise AccountingError("d125-exposure-exceeded")
        return dict(row)


def close_d125_owner(ledger_path, *, output, status, reason, boot_identity, project_root):
    """Terminal global-only closure;120s labelled allowance covers the parent handoff."""
    if status not in ("HALTED", "accepted-original14-recovery") or not isinstance(reason,str) or not reason:
        raise AccountingError("d125-terminal-disposition-invalid")
    root=pathlib.Path(project_root).resolve(strict=True);path=_safe_path(ledger_path,root)
    target=_safe_create_path(pathlib.Path(output),root)
    with _locked(path):
        value=_load(path,root);owner=selected_recovery_owner(value,project_root=root)
        if any(r.get("status")=="reserved" for r in value.get("records",[]) if r.get("d125_owner")==D125_PLAN_ID):
            raise AccountingError("d125-terminal-process-still-active")
        now=time.monotonic();remaining=d125_remaining(value,monotonic_now=now,boot_identity=boot_identity,project_root=root)
        state=value["phase6_accounting"];anchor=state["active_anchor"]
        elapsed=_active_elapsed(state,now,boot_identity)
        rows=[r for r in value["records"] if r.get("d125_owner")==D125_PLAN_ID]
        actual={"tank":sum(r.get("purpose")=="tank-continuation" for r in rows),
            "controls":sum(r.get("purpose")=="tank-continuation-control" for r in rows),
            "children":sum(len(r.get("launcher_result",{}).get("native_child_processes",[])) for r in rows if isinstance(r.get("launcher_result"),dict)),
            "pcm":sum(sum(isinstance(item.get("retained_pcm"),dict) for item in r.get("launcher_result",{}).get("results",[]))
                for r in rows if isinstance(r.get("launcher_result"),dict))}
        pointer=value.get("current_tank_continuation_receipt",{})
        if status=="accepted-original14-recovery" and (actual!={"tank":1,"controls":2,"children":12,"pcm":12} or
                any(r.get("status")!="completed" for r in rows) or not validate_tank_continuation_receipt(value)):
            raise AccountingError("d125-terminal-acceptance-incomplete")
        for row in value.get("d125_runs",[]):
            if row.get("status")=="reserved":
                row.update(status="interrupted",elapsed_seconds=now-row["reserved_at_monotonic"],failure="owner-terminal-close")
        state["closed_intervals"].append({"id":anchor["id"]+"-measured-close", "active_seconds":elapsed,
            "basis":"same-boot measured owner22 wall; includes process/review/handoff wall once", "monotonic_closed_at":now,
            "boot_identity":boot_identity,"pea_charge":False})
        state["closed_intervals"].append({"id":anchor["id"]+"-parent-final-allowance", "active_seconds":120.0,
            "basis":"conservative labelled parent closeout allowance; measured excess appended separately", "pea_charge":False})
        state["active_anchor"]=None
        event={"event":"terminal","generation_id":owner["generation_id"],"status":status,"reason":reason,
            "monotonic_closed_at":now,"parent_allowance_seconds":120.0,"parent_allowance_deadline_monotonic":now+120,
            "measured_owner_seconds":elapsed,"global_cumulative_seconds":_closed_seconds(state),"actual_counts":actual,"created_at":_now()}
        value.setdefault("d125_owner_events",[]).append(event);_write(path,value)
        report={"schema":"phase6-d125-owner22-terminal-v1","status":status,"reason":reason,"anchor":None,
            "ledger_sha256":ledger_digest(path),"actual_counts":actual,"accounting":{**remaining,
                "global_used_seconds":_closed_seconds(state),"global_remaining_seconds":max(0,43200-_closed_seconds(state))},
            "closure":event,"checked_receipt_sha256":pointer.get("checked_receipt_sha256"),
            "final_review_sha256":pointer.get("final_acceptance_review_sha256"),"phase6_complete":False,
            "downstream_blocked":["06-12","06-09","06-05","06-06","06-07"]}
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
        with os.fdopen(fd,"w") as stream:
            json.dump(report,stream,sort_keys=True,indent=2,allow_nan=False);stream.write("\n");stream.flush();os.fsync(stream.fileno())
        return report


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_boot_identity() -> str:
    try:
        # kern.boottime's timeval drifts slightly between reads on this host,
        # so new anchors use the stable kernel boot-session UUID. Historical
        # persisted identities remain unchanged.
        output = subprocess.check_output(["sysctl", "-n", "kern.bootsessionuuid"], text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AccountingError("boot-identity-unavailable") from exc
    identity = output.strip().lower()
    if not identity or any(ch.isspace() for ch in identity):
        raise AccountingError("boot-identity-unparseable")
    return f"boot-session:{identity}"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def ledger_digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity(project_root: pathlib.Path) -> str:
    """Hash the live source and coordinator inputs that can change authorization."""
    root = pathlib.Path(project_root).resolve(strict=True)
    files = sorted((root / "src").rglob("*.c")) + sorted((root / "src").rglob("*.h"))
    # The report is produced through the public API and host/session tools.
    # Mutating those inputs must invalidate a proof just like a core mutation.
    for directory in ("include", "tools"):
        files += sorted((root / directory).rglob("*.c"))
        files += sorted((root / directory).rglob("*.h"))
    files += [root / "CMakeLists.txt"]
    files += sorted((root / "tools").rglob("CMakeLists.txt"))
    files += sorted((root / "cmake").rglob("*.cmake"))
    files += [root / "scripts/evidence/phase6_routes.py",
              root / "scripts/evidence/phase6_accounting.py",
              root / "tests/fixtures/phase6_repairs.py",
              root / "tests/fixtures/phase4_game.py",
              root / "tests/evidence/phase6_stack_observation_contract.py",
              root / "tests/evidence/phase6_tank_continuation_contract.py",
              root / "tests/evidence/phase6_d125_consumers_contract.py",
              root / "tests/evidence/phase6_d125_authored_fixture.py",
              root / "tests/session/phase6_capture_argv_contract.py",
              root / "tests/session/phase6_stack_forward_contract.c",
              root / "tests/session/phase6_route_contract.py",
              root / "tests/api/phase6_repairs_contract.c"]
    digest = hashlib.sha256()
    for path in sorted(set(files)):
        if path.is_file():
            relative = path.relative_to(root).as_posix().encode()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _safe_path(path: pathlib.Path, allowed_root: pathlib.Path | None = None) -> pathlib.Path:
    path = pathlib.Path(path)
    if path.is_symlink():
        raise AccountingError("ledger-path-symlink-denied")
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise AccountingError("ledger-path-not-file")
        if allowed_root is not None:
            root = pathlib.Path(allowed_root).resolve(strict=True)
            if resolved != root and root not in resolved.parents:
                raise AccountingError("ledger-path-escape-denied")
        return resolved
    except OSError as exc:
        raise AccountingError("ledger-path-unreadable") from exc


def _safe_create_path(path: pathlib.Path, allowed_root: pathlib.Path) -> pathlib.Path:
    """Resolve a not-yet-created file beneath the checked project root."""
    target = pathlib.Path(path)
    if target.is_symlink() or target.exists():
        raise AccountingError("d124-anchor-output-exists-or-symlink")
    try:
        root = pathlib.Path(allowed_root).resolve(strict=True)
        parent = target.parent.resolve(strict=True)
    except OSError as exc:
        raise AccountingError("d124-anchor-output-parent-unreadable") from exc
    if parent != root and root not in parent.parents:
        raise AccountingError("ledger-path-escape-denied")
    return parent / target.name


@contextmanager
def _locked(path: pathlib.Path, *, lock_root: pathlib.Path | None = None,
            timeout_seconds: float | None = None):
    lock_name = hashlib.sha256(str(path).encode()).hexdigest()
    if lock_root is None:
        directory = pathlib.Path(tempfile.gettempdir())
    else:
        directory = pathlib.Path(lock_root)
        if directory.is_symlink():
            raise AccountingError("transaction-lock-root-symlink")
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        if not directory.is_dir():
            raise AccountingError("transaction-lock-root-invalid")
    if timeout_seconds is not None:
        timeout_seconds = _numeric(timeout_seconds, "transaction-lock-timeout")
        if timeout_seconds <= 0 or timeout_seconds > 2:
            raise AccountingError("transaction-lock-timeout-invalid")
    lock_path = directory / f"genewhip-phase6-accounting-{lock_name}.lock"
    if lock_root is not None and lock_path.is_symlink():
        raise AccountingError("transaction-lock-file-symlink")
    flags = os.O_CREAT | os.O_RDWR
    if lock_root is not None:
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    acquired = False
    try:
        if timeout_seconds is None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        else:
            deadline = time.monotonic() + timeout_seconds
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise AccountingError("transaction-lock-timeout") from exc
                    time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        acquired = True
        yield
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _immutable_snapshot(value: dict[str, Any], count: int | None = None) -> dict[str, Any]:
    records = value.get("records")
    if not isinstance(records, list):
        raise AccountingError("ledger-schema-invalid")
    count = len(records) if count is None else count
    if len(records) < count:
        raise AccountingError("immutable-history-changed")
    fields = {
        "records": records[:count],
        "recovery_accounting": value.get("recovery_accounting", []),
        "halt": value.get("halt", {}),
        "usage": value.get("usage", {}),
        "budgets": value.get("budgets", {}),
        "plan_started_at": value.get("plan_started_at"),
        "plan_start_anchor": value.get("plan_start_anchor"),
    }
    return fields


def _baseline(value: dict[str, Any]) -> float:
    usage = value.get("usage")
    if not isinstance(usage, dict):
        raise AccountingError("active-time-accounting-unknown")
    values = [_numeric(usage.get("cumulative_repair_seconds"), "closed-baseline")]
    recovery = value.get("recovery_accounting", [])
    if not isinstance(recovery, list):
        raise AccountingError("closed-accounting-history-invalid")
    for row in recovery:
        if not isinstance(row, dict):
            raise AccountingError("closed-accounting-history-invalid")
        values.append(_numeric(row.get("cumulative_seconds"), "closed-history-cumulative"))
    return max(values)


def _accounting_state(value: dict[str, Any]) -> dict[str, Any]:
    state = value.get("phase6_accounting")
    if state is None:
        state = {
            "schema": "phase6-accounting-v1",
            "closed_baseline_seconds": _baseline(value),
            "closed_intervals": [],
            "active_anchor": None,
            "immutable_prefix_count": len(value["records"]),
            "immutable_prefix_sha256": hashlib.sha256(_canonical(_immutable_snapshot(value))).hexdigest(),
        }
        value["phase6_accounting"] = state
    if not isinstance(state, dict) or state.get("schema") != "phase6-accounting-v1":
        raise AccountingError("accounting-schema-invalid")
    prefix_count = state.get("immutable_prefix_count")
    if type(prefix_count) is not int or prefix_count < 0:
        raise AccountingError("immutable-prefix-invalid")
    snapshot = _immutable_snapshot(value, prefix_count)
    digest = hashlib.sha256(_canonical(snapshot)).hexdigest()
    if digest != state.get("immutable_prefix_sha256"):
        raise AccountingError("immutable-history-changed")
    if not isinstance(state.get("closed_intervals"), list):
        raise AccountingError("closed-intervals-invalid")
    return state


def _receipt_payload(value: dict[str, Any]) -> bytes:
    try:
        return (json.dumps(value, indent=2, sort_keys=False, allow_nan=False) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise AccountingError("receipt-nonfinite-or-invalid-value") from exc


def _fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_receipt_once(path: pathlib.Path, value: dict[str, Any]) -> None:
    """Publish fully flushed bytes atomically, with no destination replacement.

    A same-directory hard link installs the complete file or fails if *any*
    destination exists, including a dangling symlink. A crash before link leaves
    no receipt; after link it leaves the complete committed snapshot. Recovery
    owns retrying directory fsync. This is a local filesystem operation, not a
    cross-filesystem or hostile-directory transaction.
    """
    payload = _receipt_payload(value)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise AccountingError("receipt-output-exists-or-symlink") from exc
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write(path: pathlib.Path, value: dict[str, Any]) -> None:
    try:
        payload = json.dumps(value, indent=2, sort_keys=False, allow_nan=False) + "\n"
    except (TypeError, ValueError) as exc:
        raise AccountingError("ledger-nonfinite-or-invalid-value") from exc
    mode = stat.S_IMODE(path.stat().st_mode)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _load(path: pathlib.Path, allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    path = _safe_path(path, allowed_root)
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AccountingError("ledger-unreadable") from exc
    if not isinstance(value, dict) or not isinstance(value.get("records"), list):
        raise AccountingError("ledger-schema-invalid")
    _accounting_state(value)
    return value


def _write(path: pathlib.Path, value: dict[str, Any]) -> None:
    """Atomic same-directory replacement after immutable-prefix validation."""
    _accounting_state(value)
    _atomic_write(path, value)


def _transaction_path(raw, root: pathlib.Path, *, flat=False) -> pathlib.Path:
    """Reject redirected aliases before handing files to canonical helpers."""
    spelling = os.fspath(raw)
    if not isinstance(spelling, str) or ".." in spelling.split("/"):
        raise AccountingError("transaction-path-escape")
    path = pathlib.Path(spelling)
    if not path.is_absolute():
        path = root / path
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise AccountingError("transaction-path-escape") from exc
    if not relative.parts or (flat and (len(relative.parts) != 1 or "\\" in relative.name)):
        raise AccountingError("transaction-flat-destination-required")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise AccountingError("transaction-path-symlink")
    if path.resolve() != path:
        raise AccountingError("transaction-path-alias")
    return path


def _transaction_arguments(ledger_path, project_root, transaction_id,
                           receipt_path, expected_objects, lock_root):
    if not isinstance(transaction_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", transaction_id):
        raise AccountingError("transaction-id-invalid")
    root = pathlib.Path(project_root)
    if (not root.is_absolute() or ".." in os.fspath(root).split("/") or
            root.is_symlink() or root.resolve(strict=True) != root):
        raise AccountingError("transaction-root-alias-or-symlink")
    if not root.is_dir():
        raise AccountingError("transaction-root-invalid")
    path = _transaction_path(ledger_path, root)
    receipt = _transaction_path(receipt_path, root, flat=True)
    locks = _transaction_path(lock_root, root)
    if path == receipt or locks in (path, receipt) or locks == path.parent:
        raise AccountingError("transaction-path-overlap")
    if (not isinstance(expected_objects, dict) or not expected_objects or
            len(expected_objects) > 1024 or "ledger_transactions_v1" in expected_objects or
            any(not isinstance(key, str) or not isinstance(value, str) or
                not re.fullmatch(r"[0-9a-f]{64}", value)
                for key, value in expected_objects.items())):
        raise AccountingError("transaction-baseline-map-invalid")
    return root, path, receipt, locks, dict(expected_objects)


def _transaction_record(record):
    if not isinstance(record, dict) or record.get("kind") != "engineering-metadata":
        raise AccountingError("transaction-record-invalid")
    # JSON-native data only: avoid key coercion, custom encoders and nonfinite
    # values. The recursive scan has bounded depth and encoded size.
    remaining_nodes = [65536]
    def validate(value, depth=0):
        remaining_nodes[0] -= 1
        if remaining_nodes[0] < 0 or (isinstance(value, (str, list, dict)) and len(value) > 65536):
            raise AccountingError("transaction-record-too-large")
        if depth > 32:
            raise AccountingError("transaction-record-depth")
        if value is None or type(value) in (str, bool, int):
            return
        if type(value) is float and math.isfinite(value):
            return
        if type(value) is list:
            for item in value:
                validate(item, depth + 1)
            return
        if type(value) is dict and all(type(key) is str for key in value):
            for item in value.values():
                validate(item, depth + 1)
            return
        raise AccountingError("transaction-record-invalid")
    validate(record)
    try:
        encoded = _canonical(record)
    except (TypeError, ValueError, OverflowError) as exc:
        raise AccountingError("transaction-record-invalid") from exc
    if len(encoded) > 65536:
        raise AccountingError("transaction-record-too-large")
    return json.loads(encoded)


def _transaction_intent(identifier, relative, record, expected):
    semantic = {"schema": "ledger-transaction-intent-v1", "transaction_id": identifier,
                "receipt_path": relative, "record": record, "expected_objects": expected}
    intent_bytes = _canonical(semantic)
    intent_digest = hashlib.sha256(intent_bytes).hexdigest()
    payload = {"schema": "ledger-transaction-receipt-v1", "transaction_id": identifier,
               "receipt_path": relative, "record": record, "intent_sha256": intent_digest}
    receipt_bytes = _receipt_payload(payload)
    return dict(semantic, intent_bytes=intent_bytes.decode("utf-8"),
                intent_sha256=intent_digest, receipt_bytes=receipt_bytes.decode("utf-8"),
                receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest())


def _transaction_journal(value, expected):
    if set(value) - {"ledger_transactions_v1"} != set(expected):
        raise AccountingError("transaction-original-roster-changed")
    for key, digest in expected.items():
        if hashlib.sha256(_canonical(value[key])).hexdigest() != digest:
            raise AccountingError("transaction-original-object-changed")
    journal = value.get("ledger_transactions_v1")
    if journal is None and "ledger_transactions_v1" not in value:
        return {"schema": "ledger-transactions-v1", "transactions": {}}
    if (not isinstance(journal, dict) or set(journal) != {"schema", "transactions"} or
            journal.get("schema") != "ledger-transactions-v1" or
            not isinstance(journal.get("transactions"), dict) or
            len(journal["transactions"]) > 128):
        raise AccountingError("transaction-journal-invalid")
    for identifier, row in journal["transactions"].items():
        if (not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", identifier)
                or not isinstance(row, dict) or row.get("transaction_id") != identifier or
                row.get("expected_objects") != expected):
            raise AccountingError("transaction-intent-invalid")
        relative = row.get("receipt_path")
        if (not isinstance(relative, str) or not relative or relative in (".", "..") or
                "/" in relative or "\\" in relative):
            raise AccountingError("transaction-intent-invalid")
        record = _transaction_record(row.get("record"))
        if row != _transaction_intent(identifier, relative, record, expected):
            raise AccountingError("transaction-intent-digest-mismatch")
    return journal


def _transaction_publish(receipt, row):
    payload = row["receipt_bytes"].encode("utf-8")
    def verify_existing():
        if receipt.is_symlink():
            raise AccountingError("transaction-path-symlink")
        if not receipt.is_file() or receipt.read_bytes() != payload:
            raise AccountingError("transaction-receipt-conflict")
    if receipt.is_symlink():
        raise AccountingError("transaction-path-symlink")
    if receipt.exists():
        verify_existing()
        return
    # Decode immutable persisted bytes; the canonical publisher's serialization
    # must reproduce those exact bytes, never mutable caller state.
    persisted = json.loads(row["receipt_bytes"])
    if _receipt_payload(persisted) != payload:
        raise AccountingError("transaction-intent-digest-mismatch")
    try:
        _publish_receipt_once(receipt, persisted)
    except AccountingError as exc:
        if str(exc) != "receipt-output-exists-or-symlink":
            raise
        verify_existing()  # actual FileExistsError collision, under same lock
    verify_existing()


def _ledger_transaction(ledger_path, *, project_root, transaction_id, receipt_path,
                        record, expected_objects, lock_root, checkpoint, recover):
    root, path, receipt, locks, expected = _transaction_arguments(
        ledger_path, project_root, transaction_id, receipt_path, expected_objects, lock_root)
    frozen_record = None if recover else _transaction_record(record)
    if checkpoint is not None and not callable(checkpoint):
        raise AccountingError("transaction-checkpoint-invalid")
    def boundary(name):
        if checkpoint is not None:
            checkpoint(name)
    with _locked(path, lock_root=locks, timeout_seconds=2):
        # Revalidate paths and original objects while holding the actual lock.
        _transaction_arguments(path, root, transaction_id, receipt, expected, locks)
        value = _load(path, root)
        journal = _transaction_journal(value, expected)
        boundary("before_intent")
        row = journal["transactions"].get(transaction_id)
        if recover:
            if row is None:
                raise AccountingError("transaction-intent-missing")
            if row["receipt_path"] != receipt.relative_to(root).as_posix():
                raise AccountingError("transaction-identity-conflict")
        else:
            proposed = _transaction_intent(transaction_id, receipt.relative_to(root).as_posix(),
                                           frozen_record, expected)
            if row is not None and row != proposed:
                raise AccountingError("transaction-identity-conflict")
            if row is None:
                if len(journal["transactions"]) >= 128:
                    raise AccountingError("transaction-journal-full")
                row = proposed
                journal["transactions"][transaction_id] = row
                value["ledger_transactions_v1"] = journal
                _write(path, value)
        boundary("after_intent")
        boundary("before_publication")
        _transaction_publish(receipt, row)
        boundary("after_publication")
        reloaded = _load(path, root)
        checked = _transaction_journal(reloaded, expected)
        if checked["transactions"].get(transaction_id) != row or receipt.read_bytes() != row["receipt_bytes"].encode("utf-8"):
            raise AccountingError("transaction-verification-failed")
        boundary("after_verification")
        return {"transaction_id": transaction_id, "receipt_sha256": row["receipt_sha256"],
                "status": "metadata-published"}


def commit_ledger_transaction(ledger_path, *, project_root, transaction_id,
                              receipt_path, record, expected_objects, lock_root,
                              checkpoint=None):
    """Commit bounded engineering metadata, preserving all original objects.

    Caller owns project_root and its flat receipt directory. D132 execution is
    authorized on disposable exact-ledger copies only; this API grants no
    accounting settlement, reservation, recovery-close or game authority.
    """
    return _ledger_transaction(ledger_path, project_root=project_root,
        transaction_id=transaction_id, receipt_path=receipt_path, record=record,
        expected_objects=expected_objects, lock_root=lock_root,
        checkpoint=checkpoint, recover=False)


def recover_ledger_transaction(ledger_path, *, project_root, transaction_id,
                               receipt_path, expected_objects, lock_root,
                               checkpoint=None):
    """Republish exact persisted receipt bytes without adding another intent."""
    return _ledger_transaction(ledger_path, project_root=project_root,
        transaction_id=transaction_id, receipt_path=receipt_path, record=None,
        expected_objects=expected_objects, lock_root=lock_root,
        checkpoint=checkpoint, recover=True)


def _numeric(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise AccountingError(f"{name}-invalid")
    return float(value)


def _closed_seconds(state: dict[str, Any]) -> float:
    total = _numeric(state.get("closed_baseline_seconds"), "closed-baseline")
    seen: set[str] = set()
    for row in state["closed_intervals"]:
        if not isinstance(row, dict):
            raise AccountingError("closed-intervals-invalid")
        identifier = row.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in seen:
            raise AccountingError("duplicate-or-invalid-interval")
        seen.add(identifier)
        charge = _numeric(row.get("active_seconds"), "interval-active-seconds")
        total += charge
    return total


def close_interval(ledger_path: pathlib.Path, *, interval_id: str, active: bool,
                   started_monotonic: float | None, closed_monotonic: float | None,
                   boot_identity: str | None, expected_digest: str | None = None,
                   allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Close one measured interval exactly once; inactive review is charged zero."""
    if type(active) is not bool or not isinstance(interval_id, str) or not interval_id:
        raise AccountingError("interval-identity-invalid")
    path = _safe_path(ledger_path, allowed_root)
    with _locked(path):
        before = ledger_digest(path)
        if expected_digest is not None and before != expected_digest:
            raise AccountingError("stale-ledger-writer")
        value = _load(path, allowed_root)
        state = value["phase6_accounting"]
        if any(row.get("id") == interval_id for row in state["closed_intervals"]):
            raise AccountingError("duplicate-interval-finalization")
        if active:
            start = _numeric(started_monotonic, "monotonic-start")
            end = _numeric(closed_monotonic, "monotonic-close")
            if boot_identity is None or end < start:
                raise AccountingError("active-clock-anchor-invalid")
            charge = round(end - start, 3)
            basis = "monotonic-active-wall"
        else:
            # Deliberately do not derive active work from an inactive UTC span.
            charge = 0.0
            basis = "inactive-review-no-charge"
        row = {"id": interval_id, "active": active, "active_seconds": charge,
               "basis": basis, "boot_identity": boot_identity}
        if active:
            row.update({"monotonic_started_at": start, "monotonic_closed_at": end})
        state["closed_intervals"].append(row)
        _write(path, value)
        return row


def initialize_ledger(ledger_path: pathlib.Path, *, monotonic_started_at: float,
                      boot_identity: str, allowed_root: pathlib.Path | None = None) -> None:
    """Persist a fresh active anchor for temporary-ledger contracts."""
    path = _safe_path(ledger_path, allowed_root)
    start = _numeric(monotonic_started_at, "monotonic-start")
    if not isinstance(boot_identity, str) or not boot_identity:
        raise AccountingError("active-clock-anchor-invalid")
    with _locked(path):
        value = _load(path, allowed_root)
        state = value["phase6_accounting"]
        state["active_anchor"] = {"id": "temporary-active-anchor",
                                  "monotonic_started_at": start,
                                  "boot_identity": boot_identity}
        _write(path, value)


def _write_anchor_file(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def close_external_interval(ledger_path: pathlib.Path, anchor_path: pathlib.Path, *,
                            source_anchor: dict[str, Any], monotonic_now: float,
                            boot_identity: str, allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Close the supplied parent interval once, then persist a fresh active anchor."""
    path = _safe_path(ledger_path, allowed_root)
    start = _numeric(source_anchor.get("monotonic_started_at"), "monotonic-start")
    now = _numeric(monotonic_now, "monotonic-now")
    prior = _numeric(source_anchor.get("prior_cumulative_seconds"), "prior-cumulative")
    if source_anchor.get("boot_identity") != boot_identity or now < start:
        raise AccountingError("active-clock-anchor-mismatch-or-reboot")
    with _locked(path):
        before = ledger_digest(path)
        value = _load(path, allowed_root)
        state = value["phase6_accounting"]
        interval_id = str(source_anchor.get("id", "GW-06-D120-execution"))
        if any(row.get("id") == interval_id for row in state["closed_intervals"]):
            raise AccountingError("duplicate-interval-finalization")
        if abs(_closed_seconds(state) - prior) > 0.0005:
            raise AccountingError("supplied-anchor-baseline-mismatch")
        charge = round(now - start, 3)
        closed = {"id": interval_id, "active": True, "active_seconds": charge,
                  "basis": "persisted-parent-monotonic-anchor; parallel wall counted once",
                  "monotonic_started_at": start, "monotonic_closed_at": now,
                  "boot_identity": boot_identity, "prior_cumulative_seconds": prior,
                  "cumulative_seconds": round(prior + charge, 3)}
        state["closed_intervals"].append(closed)
        next_anchor = {"id": f"GW-06-10-active-{hashlib.sha256(before.encode()).hexdigest()[:12]}",
                       "monotonic_started_at": now, "boot_identity": boot_identity,
                       "prior_cumulative_seconds": round(prior + charge, 3),
                       "started_at": _now(), "basis": "persisted-before-follow-on-work"}
        state["active_anchor"] = next_anchor
        _write(path, value)
    _write_anchor_file(anchor_path, next_anchor)
    return {"closed_interval": closed, "active_anchor": next_anchor,
            "ledger_sha256": ledger_digest(path)}


def import_d122_anchor(ledger_path: pathlib.Path, anchor_path: pathlib.Path, *,
                       monotonic_now: float, boot_identity: str,
                       expected_anchor_id: str = "GW-06-D122-18-global-engineering",
                       allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Import a pre-persisted D122 anchor and its separate global-only prefix once."""
    path = _safe_path(ledger_path, allowed_root)
    source_path = pathlib.Path(anchor_path)
    source = json.loads(source_path.read_text())
    start = _numeric(source.get("monotonic_started_at"), "monotonic-start")
    now = _numeric(monotonic_now, "monotonic-now")
    prior = _numeric(source.get("prior_cumulative_seconds"), "prior-cumulative")
    prefix = _numeric(source.get("conservative_preanchor_seconds"), "preanchor-prefix")
    if source.get("id") != expected_anchor_id or source.get("purpose") != "d122-global-engineering":
        raise AccountingError("d122-anchor-identity-mismatch")
    if source.get("boot_identity") != boot_identity or now < start or prefix < 0:
        raise AccountingError("active-clock-anchor-mismatch-or-reboot")
    if source.get("engineering_closeout_reserve_seconds") != 120:
        raise AccountingError("d122-closeout-reserve-invalid")
    with _locked(path):
        value = _load(path, allowed_root)
        state = value["phase6_accounting"]
        if state.get("active_anchor") is not None:
            raise AccountingError("active-anchor-already-present")
        if abs(_closed_seconds(state) - prior) > 0.0005:
            raise AccountingError("supplied-anchor-baseline-mismatch")
        if any(row.get("id") in (expected_anchor_id, expected_anchor_id + "-bootstrap")
               for row in state["closed_intervals"]):
            raise AccountingError("duplicate-interval-finalization")
        measured = round(now - start, 3)
        closed = {"id": expected_anchor_id, "active": True,
                  "active_seconds": measured,
                  "basis": "persisted D122 parent monotonic anchor; parallel wall counted once",
                  "monotonic_started_at": start, "monotonic_closed_at": now,
                  "boot_identity": boot_identity, "prior_cumulative_seconds": prior,
                  "cumulative_seconds": round(prior + measured, 3),
                  "pea_charge_seconds": 0.0}
        bootstrap = {"id": expected_anchor_id + "-bootstrap", "active": True,
                     "active_seconds": prefix,
                     "basis": "separate conservative pre-anchor UTC upper bound; global only, zero PEA",
                     "boot_identity": boot_identity,
                     "prior_cumulative_seconds": round(prior + measured, 3),
                     "cumulative_seconds": round(prior + measured + prefix, 3),
                     "pea_charge_seconds": 0.0}
        next_anchor = {"id": expected_anchor_id + "-imported", "monotonic_started_at": now,
                       "boot_identity": boot_identity,
                       "prior_cumulative_seconds": round(prior + measured + prefix, 3),
                       "started_at": _now(), "basis": "imported D122 anchor; global-only engineering",
                       "pea_charge": False,
                       "engineering_closeout_reserve_seconds": 120}
        state["closed_intervals"].extend((closed, bootstrap))
        state["active_anchor"] = next_anchor
        _write(path, value)
    _write_anchor_file(source_path, next_anchor)
    return {"closed_interval": closed, "bootstrap_prefix": bootstrap,
            "active_anchor": next_anchor, "ledger_sha256": ledger_digest(path)}


def close_plan_anchor(ledger_path: pathlib.Path, anchor_path: pathlib.Path, *,
                      monotonic_now: float, boot_identity: str,
                      allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Close one plan interval and clear its root anchor without renewing time."""
    path = _safe_path(ledger_path, allowed_root)
    source = json.loads(pathlib.Path(anchor_path).read_text())
    start = _numeric(source.get("monotonic_started_at"), "monotonic-start")
    now = _numeric(monotonic_now, "monotonic-now")
    prior = _numeric(source.get("prior_cumulative_seconds"), "prior-cumulative")
    if source.get("boot_identity") != boot_identity or now < start:
        raise AccountingError("active-clock-anchor-mismatch-or-reboot")
    with _locked(path):
        value = _load(path, allowed_root)
        state = value["phase6_accounting"]
        active = state.get("active_anchor")
        if active != source or abs(_closed_seconds(state) - prior) > 0.0005:
            raise AccountingError("active-anchor-or-baseline-mismatch")
        interval_id = source.get("id")
        if any(row.get("id") == interval_id for row in state["closed_intervals"]):
            raise AccountingError("duplicate-interval-finalization")
        elapsed = round(now - start, 3)
        closed = {"id": interval_id, "active": True, "active_seconds": elapsed,
                  "basis": "persisted-plan-monotonic-anchor; parallel wall counted once",
                  "monotonic_started_at": start, "monotonic_closed_at": now,
                  "boot_identity": boot_identity, "prior_cumulative_seconds": prior,
                  "cumulative_seconds": round(prior + elapsed, 3)}
        target_process = sum(
            _numeric(row.get("target_active_seconds", 0), "target-active-seconds")
            for row in value["records"] if row.get("target_stop_signature") == PEA_SIGNATURE and
            row.get("record_type") == "authorization-reservation" and
            _numeric(row.get("monotonic_started_at", 0), "target-monotonic-start") >= start)
        target_charge = (round(max(0.0, elapsed - target_process), 3)
                         if source.get("pea_charge", True) else 0.0)
        state["closed_intervals"].append(closed)
        state["active_anchor"] = None
        if target_charge:
            value["records"].append({"record_id": f"{interval_id}-target-investigation",
                "record_type": "target-investigation-time", "target_stop_signature": PEA_SIGNATURE,
                "active_seconds": target_charge, "new_target_attempts": 0,
                "basis": "same plan interval; subtract target process wall already recorded"})
        _write(path, value)
    closed_anchor = {"id": interval_id, "status": "closed-inactive-review",
                     "closed_at": _now(), "boot_identity": boot_identity,
                     "prior_cumulative_seconds": round(prior + elapsed, 3),
                     "basis": "plan stopped; no active anchor remains"}
    _write_anchor_file(pathlib.Path(anchor_path), closed_anchor)
    return {"closed_interval": closed, "target_investigation_seconds": target_charge,
            "active_anchor": None, "ledger_sha256": ledger_digest(path)}


def start_d124_anchor(ledger_path: pathlib.Path, anchor_path: pathlib.Path, *,
                      project_root: pathlib.Path, boot_identity: str,
                      bootstrap_started_at: str) -> dict[str, Any]:
    """Persist a fresh D124 global-only anchor and conservative pre-anchor UTC prefix."""
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    anchor_file = _safe_create_path(anchor_path, root)
    try:
        start_utc = datetime.fromisoformat(bootstrap_started_at.replace("Z", "+00:00"))
        end_utc = datetime.now(timezone.utc)
    except (TypeError, ValueError) as exc:
        raise AccountingError("d124-bootstrap-time-invalid") from exc
    prefix = max(0.0, (end_utc - start_utc).total_seconds())
    now = time.monotonic()
    anchor_id = f"GW-06-D124-20-global-{__import__('uuid').uuid4()}"
    with _locked(path):
        value = _load(path, root)
        state = value["phase6_accounting"]
        if state.get("active_anchor") is not None:
            raise AccountingError("d124-active-anchor-already-present")
        if value.get("d124_recovery_policy") is not None:
            raise AccountingError("d124-policy-already-installed")
        if abs(_closed_seconds(state) - D124_GLOBAL_FLOOR_SECONDS) > 0.0005:
            raise AccountingError("d124-global-floor-mismatch")
        attempts, pea_used = _target_usage(value.get("records", []), PEA_SIGNATURE)
        pea_used += sum(d122_partition_spent(value, partition) for partition in
                        ("observer_builds", "observer_proofs", "14_other"))
        pea_used += d122_control_process_spent(value)
        if attempts != 1 or abs(pea_used - D124_PEA_FLOOR_SECONDS) > 0.001:
            raise AccountingError("d124-pea-or-attempt-floor-mismatch")
        if value.get("d123_recovery_policy", {}).get("status") != "active":
            raise AccountingError("d124-prior-policy-missing")
        if any(row.get("activity_id") and row.get("status") == "reserved"
               for row in value.get("d123_runs", [])):
            raise AccountingError("d124-prior-activity-still-active")
        prefix_id = anchor_id + "-bootstrap"
        prior = _closed_seconds(state)
        prefix_row = {"id": prefix_id, "active": True,
            "active_seconds": round(prefix, 3),
            "basis": "conservative UTC upper bound from persisted STATE last_updated; required reads and anchor bootstrap; monotonic prefix unavailable; global-only",
            "started_at": start_utc.isoformat(), "closed_at": end_utc.isoformat(),
            "boot_identity": boot_identity, "prior_cumulative_seconds": prior,
            "cumulative_seconds": round(prior + prefix, 3), "pea_charge_seconds": 0.0}
        state["closed_intervals"].append(prefix_row)
        anchor = {"id": anchor_id, "purpose": "d124-global-engineering",
            "monotonic_started_at": now, "boot_identity": boot_identity,
            "prior_cumulative_seconds": round(prior + prefix, 3),
            "started_at": _now(), "basis": "fresh D124 same-boot global-only anchor",
            "pea_charge": False,
            "engineering_closeout_reserve_seconds": D124_CLOSEOUT_RESERVE_SECONDS}
        state["active_anchor"] = anchor
        value.setdefault("d124_runs", [])
        _write(path, value)
    _write_anchor_file(anchor_file, anchor)
    return {"bootstrap_prefix": prefix_row, "active_anchor": anchor,
            "ledger_sha256": ledger_digest(path)}


def _validate_d124_policy(value: dict[str, Any], *, project_root: pathlib.Path | None = None) -> dict[str, Any]:
    policy = value.get("d124_recovery_policy")
    if not isinstance(policy, dict) or policy.get("schema") != "phase6-d124-recovery-v1" or policy.get("status") != "active":
        raise AccountingError("d124-policy-missing-or-invalid")
    anchor = value.get("phase6_accounting", {}).get("active_anchor")
    if (not isinstance(anchor, dict) or anchor.get("id") != policy.get("anchor_id") or
            anchor.get("purpose") != "d124-global-engineering" or anchor.get("pea_charge") is not False or
            anchor.get("engineering_closeout_reserve_seconds") != D124_CLOSEOUT_RESERVE_SECONDS or
            anchor.get("boot_identity") != policy.get("boot_identity")):
        raise AccountingError("d124-active-anchor-mismatch")
    if (policy.get("global_floor_seconds") != D124_GLOBAL_FLOOR_SECONDS or
            policy.get("pea_floor_seconds") != D124_PEA_FLOOR_SECONDS or
            policy.get("global_cap_seconds") != D124_GLOBAL_CAP_SECONDS or
            policy.get("pea_cap_seconds") != D124_PEA_CAP_SECONDS or
            policy.get("process_reserve_seconds") != D124_PROCESS_RESERVE_SECONDS or
            policy.get("closeout_reserve_seconds") != D124_CLOSEOUT_RESERVE_SECONDS or
            policy.get("attempts_floor") != 1 or policy.get("attempts_cap") != 3):
        raise AccountingError("d124-policy-constants-mismatch")
    if project_root is not None:
        root = pathlib.Path(project_root).resolve(strict=True)
        plan = root / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-20-PLAN.md"
        checked = root / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D124-PLAN-CHECK.md"
        proposal = root / ".planning/quick/261024-oh9-diagnose-phase6-recovery-loop-synthesize/261024-oh9-RECOMMENDATIONS.md"
        if (hashlib.sha256(plan.read_bytes()).hexdigest() != policy.get("plan_sha256") or
                hashlib.sha256(checked.read_bytes()).hexdigest() != policy.get("plan_check_sha256") or
                "## VERIFICATION PASSED" not in checked.read_text() or
                hashlib.sha256(proposal.read_bytes()).hexdigest() != D124_PROPOSAL_SHA256 or
                policy.get("proposal_sha256") != D124_PROPOSAL_SHA256):
            raise AccountingError("d124-approval-or-plan-binding-mismatch")
    if _closed_seconds(value["phase6_accounting"]) + 1e-9 < D124_GLOBAL_FLOOR_SECONDS:
        raise AccountingError("d124-global-floor-mismatch")
    return policy


def install_d124_policy(ledger_path: pathlib.Path, anchor_path: pathlib.Path, *,
                        project_root: pathlib.Path, boot_identity: str) -> dict[str, Any]:
    """Install the user-approved D124 policy against its checked plan and fresh anchor."""
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    anchor_file = _safe_path(anchor_path, root)
    plan = root / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-20-PLAN.md"
    checked = root / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D124-PLAN-CHECK.md"
    proposal = root / ".planning/quick/261024-oh9-diagnose-phase6-recovery-loop-synthesize/261024-oh9-RECOMMENDATIONS.md"
    plan_sha = hashlib.sha256(plan.read_bytes()).hexdigest()
    checked_sha = hashlib.sha256(checked.read_bytes()).hexdigest()
    proposal_sha = hashlib.sha256(proposal.read_bytes()).hexdigest()
    if proposal_sha != D124_PROPOSAL_SHA256 or "## VERIFICATION PASSED" not in checked.read_text():
        raise AccountingError("d124-explicit-approval-or-check-missing")
    with _locked(path):
        value = _load(path, root)
        anchor = value.get("phase6_accounting", {}).get("active_anchor")
        sidecar = json.loads(anchor_file.read_text()) if anchor_file.is_file() else None
        if (not isinstance(anchor, dict) or not isinstance(sidecar, dict) or anchor != sidecar or
                anchor.get("purpose") != "d124-global-engineering" or
                anchor.get("boot_identity") != boot_identity):
            raise AccountingError("d124-active-anchor-mismatch")
        attempts, pea_used = _target_usage(value.get("records", []), PEA_SIGNATURE)
        pea_used += sum(d122_partition_spent(value, partition) for partition in
                        ("observer_builds", "observer_proofs", "14_other"))
        pea_used += d122_control_process_spent(value)
        if attempts != 1 or abs(pea_used - D124_PEA_FLOOR_SECONDS) > 0.001:
            raise AccountingError("d124-pea-or-attempt-floor-mismatch")
        if value.get("d124_recovery_policy") is not None:
            existing = _validate_d124_policy(value, project_root=root)
            if existing.get("plan_sha256") != plan_sha:
                raise AccountingError("d124-policy-already-bound-differently")
            return dict(existing)
        policy = {"schema": "phase6-d124-recovery-v1", "status": "active",
            "plan": D124_PLAN_ID, "approval": "D124", "proposal_sha256": proposal_sha,
            "plan_sha256": plan_sha, "plan_check_sha256": checked_sha,
            "global_floor_seconds": D124_GLOBAL_FLOOR_SECONDS,
            "pea_floor_seconds": D124_PEA_FLOOR_SECONDS,
            "global_cap_seconds": D124_GLOBAL_CAP_SECONDS,
            "pea_cap_seconds": D124_PEA_CAP_SECONDS,
            "historical_14_other_seconds": 278.831,
            "historical_14_other_unused_seconds": 121.420,
            "process_reserve_seconds": D124_PROCESS_RESERVE_SECONDS,
            "closeout_reserve_seconds": D124_CLOSEOUT_RESERVE_SECONDS,
            "attempts_floor": 1, "attempts_cap": 3,
            "anchor_id": anchor["id"], "boot_identity": boot_identity,
            "historical_d122_preserved": True, "created_at": _now()}
        value["d124_recovery_policy"] = policy
        value.setdefault("d124_runs", [])
        _validate_d124_policy(value, project_root=root)
        _write(path, value)
        return dict(policy)


def d124_process_seconds(value: dict[str, Any]) -> float:
    """Return only actual original14 process wall already finalized under D124."""
    legacy = d122_partition_spent(value, "14_processes")
    current = sum(_numeric(row.get("process_active_seconds", 0), "d124-process-seconds")
        for row in value.get("records", []) if row.get("plan") == "06-14" and
        row.get("purpose") in ("tank-continuation", "tank-continuation-control") and
        row.get("d124_successor") == D124_PLAN_ID)
    return legacy + current


def d124_remaining(value: dict[str, Any], *, monotonic_now: float,
                   boot_identity: str) -> dict[str, float]:
    policy = _validate_d124_policy(value)
    state = value["phase6_accounting"]
    active = _active_elapsed(state, monotonic_now, boot_identity)
    global_used = _closed_seconds(state) + active
    global_remaining = max(0.0, D124_GLOBAL_CAP_SECONDS - global_used)
    process_used = d124_process_seconds(value)
    process_remaining = max(0.0, D124_PROCESS_RESERVE_SECONDS - process_used)
    pea_attempts, pea_used = _target_usage(value.get("records", []), PEA_SIGNATURE,
        boot_identity, monotonic_now)
    pea_used += sum(d122_partition_spent(value, part) for part in
                    ("observer_builds", "observer_proofs", "14_other"))
    pea_used += d122_control_process_spent(value)
    pea_remaining = max(0.0, D124_PEA_CAP_SECONDS - pea_used)
    if pea_attempts < 1 or pea_attempts > 3:
        raise AccountingError("d124-target-attempt-count-invalid")
    return {"global_used_seconds": round(global_used, 3),
        "global_remaining_seconds": round(global_remaining, 3),
        "process_used_seconds": round(process_used, 3),
        "process_remaining_seconds": round(process_remaining, 3),
        "pea_used_seconds": round(pea_used, 3),
        "pea_remaining_seconds": round(pea_remaining, 3),
        "closeout_reserve_seconds": D124_CLOSEOUT_RESERVE_SECONDS}


def d124_admit_forecast(ledger_path: pathlib.Path, *, activity_id: str,
                        nonprocess_seconds: float, process_seconds: float,
                        closeout_seconds: float = D124_CLOSEOUT_RESERVE_SECONDS,
                        boot_identity: str, project_root: pathlib.Path) -> dict[str, Any]:
    """Append a full forecast admission while preserving process and closeout reserves."""
    if not re.fullmatch(r"d124-[a-z0-9][a-z0-9-]{0,90}", activity_id):
        raise AccountingError("d124-activity-id-invalid")
    nonprocess = _numeric(nonprocess_seconds, "d124-forecast-nonprocess")
    process = _numeric(process_seconds, "d124-forecast-process")
    closeout = _numeric(closeout_seconds, "d124-forecast-closeout")
    if nonprocess < 0 or process < 0 or closeout < D124_CLOSEOUT_RESERVE_SECONDS:
        raise AccountingError("d124-forecast-invalid")
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    now = time.monotonic()
    with _locked(path):
        value = _load(path, root);policy = _validate_d124_policy(value, project_root=root)
        if policy.get("boot_identity") != boot_identity:
            raise AccountingError("d124-boot-identity-mismatch")
        if any(row.get("activity_id") == activity_id for row in value.get("d124_admissions", [])):
            raise AccountingError("d124-activity-id-spent")
        remaining = d124_remaining(value, monotonic_now=now, boot_identity=boot_identity)
        required = nonprocess + process + closeout
        if remaining["global_remaining_seconds"] + 1e-9 < required:
            raise AccountingError("d124-complete-forecast-insufficient")
        if remaining["process_remaining_seconds"] + 1e-9 < process:
            raise AccountingError("d124-process-forecast-insufficient")
        row = {"activity_id": activity_id, "status": "admitted",
            "nonprocess_forecast_seconds": nonprocess,
            "process_forecast_seconds": process,
            "closeout_reserve_seconds": closeout,
            "required_global_seconds": round(required, 3),
            "remaining_at_admission": remaining,
            "boot_identity": boot_identity, "admitted_at": _now(),
            "basis": "complete D124 remaining forecast; actual process exposure included once"}
        value.setdefault("d124_admissions", []).append(row)
        _write(path, value)
        return dict(row)


def begin_d124_activity(ledger_path: pathlib.Path, *, activity_id: str, stage: str,
                        exposure_seconds: float, boot_identity: str,
                        project_root: pathlib.Path) -> dict[str, Any]:
    """Atomically reserve one finite non-process batch under the global anchor."""
    if not re.fullmatch(r"d124-(?:dev|integration|revalidate|review|closeout|final-check)-[a-z0-9][a-z0-9-]{0,80}", activity_id):
        raise AccountingError("d124-activity-id-invalid")
    exposure = _numeric(exposure_seconds, "d124-exposure")
    if exposure <= 0 or exposure > 8100:
        raise AccountingError("d124-activity-exposure-invalid")
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    with _locked(path):
        value = _load(path, root);policy = _validate_d124_policy(value, project_root=root)
        if policy.get("boot_identity") != boot_identity:
            raise AccountingError("d124-boot-identity-mismatch")
        runs = value.setdefault("d124_runs", [])
        if any(row.get("activity_id") == activity_id for row in runs):
            raise AccountingError("d124-activity-id-spent")
        if any(row.get("status") == "reserved" for row in runs):
            raise AccountingError("d124-activity-already-active")
        now = time.monotonic()
        remaining = d124_remaining(value, monotonic_now=now, boot_identity=boot_identity)
        required = exposure + remaining["process_remaining_seconds"] + D124_CLOSEOUT_RESERVE_SECONDS
        if remaining["global_remaining_seconds"] + 1e-9 < required:
            raise AccountingError("d124-protected-global-reserve-insufficient")
        row = {"activity_id": activity_id, "stage": stage, "status": "reserved",
            "exposure_seconds": exposure,
            "protected_process_seconds": remaining["process_remaining_seconds"],
            "closeout_reserve_seconds": D124_CLOSEOUT_RESERVE_SECONDS,
            "global_remaining_at_reservation": remaining["global_remaining_seconds"],
            "reserved_at_monotonic": now, "boot_identity": boot_identity,
            "pea_charge_seconds": 0.0, "created_at": _now()}
        runs.append(row);_write(path, value)
        return dict(row)


def finalize_d124_activity(ledger_path: pathlib.Path, *, activity_id: str,
                           status: str, boot_identity: str,
                           allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    if status not in ("completed", "interrupted"):
        raise AccountingError("d124-finalization-status-invalid")
    path = _safe_path(ledger_path, allowed_root)
    with _locked(path):
        value = _load(path, allowed_root);_validate_d124_policy(value)
        rows = [row for row in value.get("d124_runs", []) if row.get("activity_id") == activity_id]
        if len(rows) != 1 or rows[0].get("status") != "reserved":
            raise AccountingError("d124-activity-not-live-or-replayed")
        row = rows[0]
        if row.get("boot_identity") != boot_identity:
            raise AccountingError("d124-boot-identity-mismatch")
        now = time.monotonic()
        if now < _numeric(row.get("reserved_at_monotonic"), "d124-activity-start"):
            raise AccountingError("d124-clock-rollback")
        elapsed = round(now - row["reserved_at_monotonic"], 3)
        row.update(status="interrupted" if elapsed > row["exposure_seconds"] else status,
            elapsed_seconds=elapsed, finalized_at=_now())
        if elapsed > row["exposure_seconds"]:
            row["failure"] = "d124-exposure-exceeded"
        _write(path, value)
        if elapsed > row["exposure_seconds"]:
            raise AccountingError("d124-exposure-exceeded")
        return dict(row)


def _active_elapsed(state: dict[str, Any], monotonic_now: float,
                    boot_identity: str) -> float:
    anchor = state.get("active_anchor")
    if not isinstance(anchor, dict):
        raise AccountingError("active-clock-anchor-missing")
    start = _numeric(anchor.get("monotonic_started_at"), "monotonic-start")
    now = _numeric(monotonic_now, "monotonic-now")
    if anchor.get("boot_identity") != boot_identity or now < start:
        raise AccountingError("active-clock-anchor-mismatch-or-reboot")
    return now - start


def _target_usage(records: list[dict[str, Any]], signature: str,
                  boot_identity: str | None = None,
                  monotonic_now: float | None = None) -> tuple[int, float]:
    attempts = 0
    seconds = 0.0
    for row in records:
        if row.get("target_stop_signature") != signature:
            continue
        record_type = row.get("record_type")
        if record_type == "authorization-reservation":
            amount = row.get("new_target_attempts", 0)
            if type(amount) is not int or amount < 0:
                raise AccountingError("target-attempt-counter-invalid")
            attempts += amount
            seconds += _numeric(row.get("target_active_seconds", 0), "target-active-seconds")
            if amount and row.get("status") == "reserved":
                if boot_identity is None or monotonic_now is None or row.get("boot_identity") != boot_identity:
                    raise AccountingError("unfinished-target-clock-unknown")
                start = _numeric(row.get("monotonic_started_at"), "target-monotonic-start")
                if monotonic_now < start:
                    raise AccountingError("unfinished-target-clock-rollback")
                seconds += monotonic_now - start
        elif record_type == "probe-attempt":
            attempts += 1
            process_rows = row.get("processes", [])
            if not isinstance(process_rows, list):
                raise AccountingError("target-process-rows-invalid")
            seconds += sum(_numeric(item.get("wall_seconds", 0), "target-process-seconds")
                           for item in process_rows if isinstance(item, dict))
        elif record_type == "target-investigation-time":
            charge = _numeric(row.get("active_seconds"), "target-investigation-seconds")
            if charge < 0:
                raise AccountingError("target-investigation-seconds-invalid")
            seconds += charge
    return attempts, seconds


def _authorization(value: dict[str, Any], *, purpose: str, plan: str,
                   case: str, target_signature: str | None) -> None:
    if value.get("d125_owner_generations"):
        owner = selected_recovery_owner(value, require_runtime=True)
        expected = D125_CASES[0] if purpose == "tank-continuation" else None
        if (plan != "06-14" or purpose not in ("tank-continuation", "tank-continuation-control") or
                (expected is not None and (case != expected or target_signature != PEA_SIGNATURE)) or
                (expected is None and (case not in D125_CASES[1:] or target_signature is not None))):
            raise AccountingError("d125-selected-scope-denied")
        if purpose == "tank-continuation-control" and not validate_tank_continuation_receipt(value, require_checked=False):
            raise AccountingError("d125-control-requires-current-capture")
        return
    if purpose == "independent-pea":
        expected = INDEPENDENT_CASES.get(case)
        if plan != "06-11" or expected is None or target_signature != expected:
            raise AccountingError("independent-pea-scope-denied")
        # The historical REC binding halt is deliberately irrelevant here.
        return
    if purpose == "tank-continuation":
        d124 = value.get("d124_recovery_policy")
        if isinstance(d124, dict):
            binding = value.get("d124_observer_bridge_binding", {})
            disposition = value.get("d124_component_disposition", {})
            required = ("bridge_sha256", "review_sha256", "trusted_handoff_sha256",
                        "review_check_sha256", "source_identity", "component_disposition_sha256")
            prior = value.get("d123_observer_bridge_binding", {})
            if (d124.get("status") != "active" or d124.get("plan") != D124_PLAN_ID or plan != "06-14" or
                    binding.get("status") != "independently-accepted" or
                    disposition.get("status") != "independently-accepted" or
                    not all(re.fullmatch(r"[0-9a-f]{64}", str(binding.get(key, ""))) for key in required) or
                    binding.get("component_disposition_sha256") != disposition.get("sha256") or
                    binding.get("d123_bridge_sha256") != prior.get("bridge_sha256") or
                    binding.get("d123_review_sha256") != prior.get("review_sha256") or
                    binding.get("d123_trusted_handoff_sha256") != prior.get("trusted_handoff_sha256")):
                raise AccountingError("d124-independent-component-review-required")
        d123 = value.get("d123_recovery_policy")
        d122 = value.get("d122_recovery_exception")
        if isinstance(d123, dict) and not isinstance(d124, dict):
            anchor = value.get("phase6_accounting", {}).get("active_anchor", {})
            bridge = value.get("d123_observer_bridge_binding", {})
            review = value.get("d123_observer_review", {})
            manifest = value.get("d123_observer_manifest", {})
            digest = lambda item: isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) is not None
            if (d123.get("schema") != "phase6-d123-recovery-v1" or d123.get("status") != "active" or
                    anchor.get("id") != d123.get("anchor_id") or anchor.get("purpose") != "d123-global-engineering" or
                    anchor.get("pea_charge") is not False or plan != "06-14" or
                    bridge.get("status") != "independently-accepted" or
                    not all(digest(bridge.get(key)) for key in
                        ("bridge_sha256", "review_sha256", "trusted_handoff_sha256", "review_check_sha256",
                         "manifest_sha256", "qualification_sha256")) or
                    review.get("status") != "accepted" or
                    review.get("bridge_sha256") != bridge.get("bridge_sha256") or
                    review.get("review_sha256") != bridge.get("review_sha256") or
                    review.get("source_identity") != bridge.get("source_identity") or
                    manifest.get("status") != "frozen" or
                    manifest.get("sha256") != bridge.get("manifest_sha256") or
                    manifest.get("source_identity") != bridge.get("producer_source_identity")):
                raise AccountingError("d123-independent-observer-review-required")
        elif d122 is not None and not isinstance(d124, dict):
            validate_d122_exception(value)
            bridge = value.get("d122_observer_bridge_binding", {})
            if (plan != "06-14" or bridge.get("status") != "independently-accepted" or
                    not re.fullmatch(r"[0-9a-f]{64}", str(bridge.get("bridge_sha256", ""))) or
                    not re.fullmatch(r"[0-9a-f]{64}", str(bridge.get("review_sha256", ""))) or
                    not re.fullmatch(r"[0-9a-f]{64}", str(bridge.get("trusted_handoff_sha256", "")))):
                raise AccountingError("d122-independent-observer-review-required")
        proof = value.get("tank_proof_revalidation", {})
        if (plan != "06-14" or case != TANK_CONTINUATION_CASE or
                target_signature != PEA_SIGNATURE or proof.get("status") != "passed" or
                proof.get("source_identity") is None or proof.get("binary_identity") is None or
                proof.get("contract_identity") is None):
            raise AccountingError("tank-continuation-scope-or-proof-denied")
        if isinstance(d123, dict) and not isinstance(d124, dict):
            bridge = value.get("d123_observer_bridge_binding", {})
            if (proof.get("source_identity") != bridge.get("source_identity") or
                    proof.get("binary_identity") != bridge.get("binary_identity") or
                    proof.get("contract_identity") != bridge.get("bridge_sha256")):
                raise AccountingError("d123-current-proof-identity-mismatch")
        elif isinstance(d124, dict):
            bridge = value.get("d124_observer_bridge_binding", {})
            if (proof.get("source_identity") != bridge.get("source_identity") or
                    proof.get("binary_identity") != bridge.get("control_client_binary_sha256") or
                    proof.get("contract_identity") != bridge.get("bridge_sha256")):
                raise AccountingError("d124-current-proof-identity-mismatch")
        return
    if purpose == "tank-continuation-control":
        if (plan != "06-14" or case not in TANK_CONTINUATION_CONTROLS or target_signature is not None or
                not validate_tank_continuation_receipt(value, require_checked=False)):
            raise AccountingError("tank-control-requires-current-capture")
        return
    if purpose == "rec-validation":
        if plan != "06-12" or case != "rec-validation":
            raise AccountingError("rec-validation-scope-denied")
        proof = value.get("current_frame_start_proof", {})
        if proof.get("status") != "passed" or not validate_tank_continuation_receipt(value, require_checked=True):
            raise AccountingError("rec-validation-requires-current-12-proof-and-checked-14-receipt")
        return
    if purpose == "joint-qualification":
        if plan != "06-09" or case != "joint-qualification":
            raise AccountingError("joint-qualification-scope-denied")
        proof = value.get("current_frame_start_proof", {})
        receipt = value.get("current_rec_validation", {})
        if proof.get("status") != "passed" or receipt.get("status") != "resolved" or not validate_tank_continuation_receipt(value, require_checked=True):
            raise AccountingError("joint-qualification-requires-current-12-and-checked-14-receipt")
        return
    if purpose == "independent-control":
        if plan != "06-11" or case not in PEA_CONTROL_CASES or target_signature is not None:
            raise AccountingError("independent-control-scope-denied")
        return
    raise AccountingError("generic-capture-denied")


def effective_target_limit(value: dict[str, Any], target_signature: str | None) -> float:
    """Resolve the one approved target cap; other signatures retain the original cap."""
    budgets = value.get("budgets", {})
    base = _numeric(budgets.get("investigation_seconds_per_stop", 5400), "target-time-limit")
    if target_signature != PEA_SIGNATURE:
        return base
    amendment = value.get("d121_recovery_amendment", {})
    if (not isinstance(amendment, dict) or amendment.get("status") != "prospective-approved" or
            amendment.get("target_stop_signature") != PEA_SIGNATURE or
            amendment.get("prior_target_cap_seconds") != 5400 or
            amendment.get("effective_target_cap_seconds") != 9000 or
            amendment.get("global_cap_seconds") != budgets.get("cumulative_repair_seconds") or
            amendment.get("global_cap_seconds") != 43200 or
            amendment.get("other_target_cap_seconds") != 5400):
        raise AccountingError("pea-cap-amendment-invalid")
    d122 = value.get("d122_recovery_exception")
    if d122 is not None:
        validate_d122_exception(value)
        return D122_PEA_CAP_SECONDS
    return 9000.0


def validate_d122_exception(value: dict[str, Any]) -> dict[str, Any]:
    """Validate the exact D122 exception and its nontransferable partitions."""
    d122 = value.get("d122_recovery_exception")
    expected = {
        "schema": "phase6-d122-recovery-v1", "status": "prospective-approved",
        "plan_scope": ["06-18", "06-14"],
        "approval_context_sha256": D122_APPROVAL_CONTEXT_SHA256,
        "plan_check_sha256": D122_PLAN_CHECK_SHA256,
        "prior_pea_cap_seconds": 9000.0, "effective_pea_cap_seconds": D122_PEA_CAP_SECONDS,
        "historical_global_floor_seconds": 13163.411,
        "historical_pea_floor_seconds": 6812.984,
        "historical_offline_seconds": 1813.235,
        "historical_offline_limit_seconds": 1800.0,
        "partitions": {"observer_builds": D122_BUILD_PARTITION_SECONDS,
                       "observer_proofs": D122_PROOF_PARTITION_SECONDS,
                       "14_processes": D122_PROCESS_PARTITION_SECONDS,
                       "14_other": D122_OTHER_PARTITION_SECONDS},
        "global_cap_seconds": 43200.0,
        "other_target_cap_seconds": 5400.0,
        "attempts_renewed": 0, "processes_added": 0, "acceptance_reduced": False,
    }
    if not isinstance(d122, dict) or any(d122.get(key) != val for key, val in expected.items()):
        raise AccountingError("d122-recovery-exception-invalid")
    if _numeric(value.get("budgets", {}).get("cumulative_repair_seconds"), "cumulative-limit") != 43200:
        raise AccountingError("d122-global-cap-invalid")
    if _numeric(value.get("usage", {}).get("cumulative_repair_seconds"), "historical-global-floor") != 5095.179:
        raise AccountingError("d122-historical-ledger-floor-invalid")
    return d122


def d122_partition_spent(value: dict[str, Any], partition: str) -> float:
    """Return finalized D122 purpose wall for one bucket, without elapsed global wall."""
    validate_d122_exception(value)
    if partition == "observer_builds":
        rows = (row for row in value.get("records", []) if row.get("observer_activity_kind") == "build")
        return round(sum(_numeric(row.get("observer_active_seconds", 0), "observer-active-seconds")
                         for row in rows), 3)
    if partition == "observer_proofs":
        rows = (row for row in value.get("records", []) if row.get("observer_activity_kind") == "proof")
        return round(sum(_numeric(row.get("observer_active_seconds", 0), "observer-active-seconds")
                         for row in rows), 3)
    if partition == "14_processes":
        rows = (row for row in value.get("records", [])
                if row.get("plan") == "06-14" and row.get("purpose") in
                ("tank-continuation", "tank-continuation-control"))
        return round(sum(_numeric(row.get("process_active_seconds", 0), "process-active-seconds")
                         for row in rows), 3)
    if partition == "14_other":
        return round(sum(_numeric(row.get("seconds", 0), "d122-other-seconds")
                         for row in value.get("d122_accounting", {}).get("other_charges", [])), 3)
    raise AccountingError("d122-partition-unknown")


def d122_control_process_spent(value: dict[str, Any]) -> float:
    """Control drivers have no target attempt, so add their wall to PEA separately."""
    return round(sum(_numeric(row.get("process_active_seconds", 0), "process-active-seconds")
        for row in value.get("records", []) if row.get("plan") == "06-14" and
        row.get("purpose") == "tank-continuation-control"), 3)


D122_OTHER_PURPOSES = frozenset({"tank-preflight", "tank-interprocess",
                                 "independent-final-review", "d122-closeout"})
D122_OTHER_CLOSEOUT_RESERVE_SECONDS = 120.0


def begin_d122_other_interval(ledger_path: pathlib.Path, *, purpose: str, interval_id: str,
                              source_identity: str, boot_identity: str,
                              allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Admit a single measured, non-process 06-14 interval against its fixed reserve."""
    if purpose not in D122_OTHER_PURPOSES or not interval_id or not re.fullmatch(r"[0-9a-f]{40,64}", source_identity):
        raise AccountingError("d122-other-interval-identity-invalid")
    if source_identity != globals()["source_identity"](pathlib.Path(__file__).resolve().parents[2]):
        raise AccountingError("d122-other-source-identity-stale")
    path = _safe_path(ledger_path, allowed_root)
    with _locked(path):
        value = _load(path, allowed_root); state = value["phase6_accounting"]
        validate_d122_exception(value)
        if any(row.get("record_type") == "authorization-reservation" and row.get("plan") == "06-14" and row.get("status") == "reserved"
               for row in value.get("records", [])):
            raise AccountingError("d122-other-process-overlap")
        charges=value.setdefault("d122_accounting", {}).setdefault("other_charges", [])
        if any(row.get("interval_id") == interval_id for row in charges):
            raise AccountingError("d122-other-interval-replay")
        if any(row.get("status") == "active" for row in charges):
            raise AccountingError("d122-other-interval-already-active")
        anchor=state.get("active_anchor", {})
        elapsed=_active_elapsed(state, time.monotonic(), boot_identity)
        cumulative=_closed_seconds(state)+elapsed
        global_limit=_numeric(value.get("budgets",{}).get("cumulative_repair_seconds"),"cumulative-limit")
        spent=d122_partition_spent(value,"14_other")
        protected_other=0.0 if purpose=="d122-closeout" else D122_OTHER_CLOSEOUT_RESERVE_SECONDS
        protected_global=0.0 if purpose=="d122-closeout" else D122_CLOSEOUT_RESERVE_SECONDS
        pea_attempts,pea_seconds=_target_usage(value.get("records",[]),PEA_SIGNATURE,boot_identity,time.monotonic())
        pea_seconds+=sum(d122_partition_spent(value,p) for p in ("observer_builds","observer_proofs","14_other"))
        pea_seconds+=d122_control_process_spent(value)
        if (spent + protected_other >= D122_OTHER_PARTITION_SECONDS or
            cumulative + protected_global >= global_limit or
            pea_seconds >= effective_target_limit(value,PEA_SIGNATURE)):
            raise AccountingError("d122-other-reserve-insufficient")
        row={"interval_id":interval_id,"purpose":purpose,"source_identity":source_identity,
             "boot_identity":boot_identity,"monotonic_started_at":time.monotonic(),"status":"active"}
        charges.append(row);_write(path,value);return dict(row)


def d122_other_interval_deadline(ledger_path: pathlib.Path, *, interval_id: str,
                                 boot_identity: str, monotonic_now: float | None = None,
                                 allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Read the active interval's earliest safe stop deadline from all live D122 caps."""
    path=_safe_path(ledger_path,allowed_root);value=_load(path,allowed_root)
    validate_d122_exception(value)
    rows=[row for row in value.get("d122_accounting",{}).get("other_charges",[])
          if row.get("interval_id")==interval_id and row.get("status")=="active"]
    if len(rows)!=1:raise AccountingError("d122-other-interval-not-live")
    row=rows[0]
    if row.get("boot_identity")!=boot_identity:raise AccountingError("boot-session-changed")
    if row.get("source_identity")!=globals()["source_identity"](pathlib.Path(__file__).resolve().parents[2]):
        raise AccountingError("d122-other-source-identity-stale")
    now=time.monotonic() if monotonic_now is None else _numeric(monotonic_now,"monotonic-now")
    start=_numeric(row.get("monotonic_started_at"),"d122-other-start")
    if now<start:raise AccountingError("d122-other-clock-rollback")
    live=now-start;purpose=row.get("purpose")
    other_settled=sum(_numeric(item.get("seconds",0),"d122-other-seconds") for item in
        value.get("d122_accounting",{}).get("other_charges",[]) if item is not row)
    other_protect=0.0 if purpose=="d122-closeout" else D122_OTHER_CLOSEOUT_RESERVE_SECONDS
    other_remaining=max(0.0,D122_OTHER_PARTITION_SECONDS-other_settled-live-other_protect)
    state=value["phase6_accounting"];global_live=_active_elapsed(state,now,boot_identity)
    global_protect=0.0 if purpose=="d122-closeout" else D122_CLOSEOUT_RESERVE_SECONDS
    global_limit=_numeric(value.get("budgets",{}).get("cumulative_repair_seconds"),"cumulative-limit")
    global_remaining=max(0.0,global_limit-_closed_seconds(state)-global_live-global_protect)
    _,pea_used=_target_usage(value.get("records",[]),PEA_SIGNATURE,boot_identity,now)
    pea_used+=sum(d122_partition_spent(value,name) for name in ("observer_builds","observer_proofs"))
    pea_used+=d122_control_process_spent(value)
    pea_used+=other_settled+live
    pea_remaining=max(0.0,effective_target_limit(value,PEA_SIGNATURE)-pea_used)
    allowed=max(0.0,min(other_remaining,global_remaining,pea_remaining))
    return {"status":"active-deadline","interval_id":interval_id,"purpose":purpose,
        "boot_identity":boot_identity,"source_identity":row["source_identity"],
        "monotonic_now":now,"active_elapsed_seconds":round(live,3),
        "remaining_other_seconds":round(other_remaining,3),
        "remaining_global_seconds":round(global_remaining,3),
        "remaining_pea_seconds":round(pea_remaining,3),
        "allowed_seconds":round(allowed,3),"deadline_monotonic":now+allowed,
        "read_only":True}


def finalize_d122_other_interval(ledger_path: pathlib.Path, *, interval_id: str,
                                 status: str = "completed", boot_identity: str,
                                 allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Close the one live non-process interval exactly once, including interruption."""
    if status not in ("completed", "interrupted"):
        raise AccountingError("d122-other-finalization-invalid")
    path=_safe_path(ledger_path,allowed_root)
    with _locked(path):
        value=_load(path,allowed_root);validate_d122_exception(value)
        matches=[row for row in value.get("d122_accounting",{}).get("other_charges",[]) if row.get("interval_id")==interval_id]
        if len(matches)!=1:raise AccountingError("d122-other-interval-not-live")
        if matches[0].get("status")!="active":raise AccountingError("d122-other-interval-replay")
        row=matches[0]
        if row.get("boot_identity")!=boot_identity:raise AccountingError("boot-session-changed")
        if row.get("source_identity")!=globals()["source_identity"](pathlib.Path(__file__).resolve().parents[2]):
            raise AccountingError("d122-other-source-identity-stale")
        row["seconds"]=round(max(0.0,time.monotonic()-_numeric(row["monotonic_started_at"],"d122-other-start")),3)
        row["status"]=status;row["finalized_at"]=_now()
        elapsed=_active_elapsed(value["phase6_accounting"],time.monotonic(),boot_identity)
        cumulative=_closed_seconds(value["phase6_accounting"])+elapsed
        global_limit=_numeric(value.get("budgets",{}).get("cumulative_repair_seconds"),"cumulative-limit")
        _,pea_seconds=_target_usage(value.get("records",[]),PEA_SIGNATURE,boot_identity,time.monotonic())
        pea_seconds+=sum(d122_partition_spent(value,p) for p in ("observer_builds","observer_proofs","14_other"))
        pea_seconds+=d122_control_process_spent(value)
        exhausted=(d122_partition_spent(value,"14_other")>D122_OTHER_PARTITION_SECONDS or
                   pea_seconds>effective_target_limit(value,PEA_SIGNATURE) or cumulative>global_limit)
        if exhausted:row["status"]="interrupted"
        _write(path,value)
        if exhausted:raise AccountingError("d122-other-partition-exhausted")
        return dict(row)


def install_d122_exception(ledger_path: pathlib.Path, anchor_path: pathlib.Path, *,
                           allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Append the approved D122 resolver without changing sealed historical rows."""
    path = _safe_path(ledger_path, allowed_root)
    anchor_file = _safe_path(anchor_path, allowed_root)
    project_root = pathlib.Path(allowed_root).resolve(strict=True) if allowed_root is not None else path.parent.parent.resolve(strict=True)
    with _locked(path):
        value = _load(path, allowed_root)
        if value.get("d122_recovery_exception") is not None:
            validate_d122_exception(value)
            parent_interval = next((row for row in value["phase6_accounting"]["closed_intervals"]
                                    if row.get("id") == "GW-06-D122-18-global-engineering"), None)
            if not isinstance(parent_interval, dict):
                raise AccountingError("d122-parent-anchor-import-missing")
            imported = value["d122_recovery_exception"].get("imported_anchor", {})
            exact_start = parent_interval.get("monotonic_started_at")
            if imported.get("monotonic_started_at") != exact_start:
                imported["monotonic_started_at"] = exact_start
                imported["monotonic_closed_at"] = parent_interval.get("monotonic_closed_at")
                imported["measured_live_seconds"] = parent_interval.get("active_seconds")
                imported["preanchor_prefix_seconds"] = 120.0
                imported["preanchor_pea_seconds"] = 0.0
                value["d122_recovery_exception"]["imported_anchor"] = imported
                _write(path, value)
            return dict(value["d122_recovery_exception"])
        state = value["phase6_accounting"]
        anchor = state.get("active_anchor")
        if (not isinstance(anchor, dict) or anchor.get("id") != "GW-06-D122-18-global-engineering-imported" or
                anchor.get("pea_charge") is not False or
                anchor.get("engineering_closeout_reserve_seconds") != D122_CLOSEOUT_RESERVE_SECONDS):
            raise AccountingError("d122-imported-global-anchor-required")
        prior = value.get("d121_recovery_amendment", {})
        if prior.get("status") != "prospective-approved" or prior.get("effective_target_cap_seconds") != 9000:
            raise AccountingError("d121-approved-baseline-required")
        original_manifest = value.get("stack_observer_manifest", {})
        if (original_manifest.get("status") != "frozen" or
                original_manifest.get("sha256") != hashlib.sha256(
                    (project_root / original_manifest.get("path", "")).read_bytes()).hexdigest()):
            raise AccountingError("original-observer-manifest-freeze-mismatch")
        source_summary = project_root / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-17-SUMMARY.md"
        if hashlib.sha256(source_summary.read_bytes()).hexdigest() != D122_17_SUMMARY_SHA256:
            raise AccountingError("halted-17-summary-mutated")
        if any(row.get("observer_activity_kind") for row in value["records"]):
            raise AccountingError("observer-activity-already-started")
        d122 = {
            "schema": "phase6-d122-recovery-v1", "status": "prospective-approved",
            "plan_scope": ["06-18", "06-14"],
            "approval_context_sha256": D122_APPROVAL_CONTEXT_SHA256,
            "plan_check_sha256": D122_PLAN_CHECK_SHA256,
            "prior_pea_cap_seconds": 9000.0, "effective_pea_cap_seconds": D122_PEA_CAP_SECONDS,
            "historical_global_floor_seconds": 13163.411,
            "historical_pea_floor_seconds": 6812.984,
            "historical_offline_seconds": 1813.235,
            "historical_offline_limit_seconds": 1800.0,
            "partitions": {"observer_builds": D122_BUILD_PARTITION_SECONDS,
                           "observer_proofs": D122_PROOF_PARTITION_SECONDS,
                           "14_processes": D122_PROCESS_PARTITION_SECONDS,
                           "14_other": D122_OTHER_PARTITION_SECONDS},
            "global_cap_seconds": 43200.0, "other_target_cap_seconds": 5400.0,
            "attempts_renewed": 0, "processes_added": 0, "acceptance_reduced": False,
            "halted_17_summary_sha256": D122_17_SUMMARY_SHA256,
            "original_manifest_sha256": original_manifest["sha256"],
            "original_manifest_source_identity": original_manifest["source_identity"],
            "imported_anchor": {"id": "GW-06-D122-18-global-engineering",
                "monotonic_started_at": next(row.get("monotonic_started_at")
                    for row in state["closed_intervals"]
                    if row.get("id") == "GW-06-D122-18-global-engineering"),
                "monotonic_closed_at": next(row.get("monotonic_closed_at")
                    for row in state["closed_intervals"]
                    if row.get("id") == "GW-06-D122-18-global-engineering"),
                "measured_live_seconds": next(row.get("active_seconds")
                    for row in state["closed_intervals"]
                    if row.get("id") == "GW-06-D122-18-global-engineering"),
                "prior_cumulative_seconds": 13163.411,
                "preanchor_prefix_seconds": 120.0, "preanchor_pea_seconds": 0.0,
                "closeout_reserve_seconds": D122_CLOSEOUT_RESERVE_SECONDS,
                "global_cumulative_at_import": anchor.get("prior_cumulative_seconds"),
                "boot_identity": anchor.get("boot_identity")},
        }
        value["d122_recovery_exception"] = d122
        value["d122_accounting"] = {"other_charges": [], "status": "active-global-engineering"}
        validate_d122_exception(value)
        _write(path, value)
        return dict(d122)


def _validate_d123_policy(value: dict[str, Any], *, project_root: pathlib.Path | None = None) -> dict[str, Any]:
    policy = value.get("d123_recovery_policy")
    if not isinstance(policy, dict) or policy.get("schema") != "phase6-d123-recovery-v1" or policy.get("status") != "active":
        raise AccountingError("d123-policy-missing-or-invalid")
    state = value.get("phase6_accounting", {})
    anchor = state.get("active_anchor")
    if (not isinstance(anchor, dict) or anchor.get("id") != policy.get("anchor_id") or
            anchor.get("purpose") != "d123-global-engineering" or anchor.get("pea_charge") is not False or
            anchor.get("engineering_closeout_reserve_seconds") != D123_CLOSEOUT_RESERVE_SECONDS):
        raise AccountingError("d123-active-anchor-mismatch")
    if (policy.get("global_floor_seconds") != D123_GLOBAL_FLOOR_SECONDS or
            policy.get("pea_floor_seconds") != D123_PEA_FLOOR_SECONDS or
            policy.get("global_cap_seconds") != D123_GLOBAL_CAP_SECONDS or
            policy.get("pea_cap_seconds") != D123_PEA_CAP_SECONDS or
            policy.get("protected_14_seconds") != D123_PROTECTED_14_SECONDS or
            policy.get("closeout_reserve_seconds") != D123_CLOSEOUT_RESERVE_SECONDS or
            policy.get("attempts_floor") != 1 or policy.get("attempts_cap") != 3):
        raise AccountingError("d123-policy-constants-mismatch")
    if _closed_seconds(state) + 1e-9 < D123_GLOBAL_FLOOR_SECONDS:
        raise AccountingError("d123-global-floor-mismatch")
    scope = state.get("scope_approval", {})
    if scope.get("id") != "GW-06-16-observer-scope-approval" or scope.get("status") != "approved":
        raise AccountingError("d123-observer-scope-approval-missing")
    if project_root is not None:
        plan = project_root / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-19-PLAN.md"
        checked = project_root / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D123-PLAN-CHECK.md"
        operating = project_root / ".planning/context/OPERATING.md"
        report = project_root / ".planning/forensics/report-20261024-193248.md"
        if (hashlib.sha256(plan.read_bytes()).hexdigest() != policy.get("plan_sha256") or
                hashlib.sha256(checked.read_bytes()).hexdigest() != policy.get("plan_check_sha256") or
                "## VERIFICATION PASSED" not in checked.read_text() or
                hashlib.sha256(operating.read_bytes()).hexdigest() != policy.get("operating_contract_sha256") or
                hashlib.sha256(report.read_bytes()).hexdigest() != policy.get("approval_context_sha256") or
                policy.get("approval") != "D123/P1"):
            raise AccountingError("d123-checked-plan-binding-mismatch")
    return policy


def install_d123_policy(ledger_path: pathlib.Path, anchor_path: pathlib.Path, *,
                        project_root: pathlib.Path, boot_identity: str) -> dict[str, Any]:
    """Install the selected D123 global-only policy against the checked plan and live anchor."""
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    anchor_file = _safe_path(anchor_path, root)
    plan_path = root / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-19-PLAN.md"
    check_path = root / ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D123-PLAN-CHECK.md"
    operating_path = root / ".planning/context/OPERATING.md"
    report_path = root / ".planning/forensics/report-20261024-193248.md"
    plan_digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    check_digest = hashlib.sha256(check_path.read_bytes()).hexdigest()
    operating_digest = hashlib.sha256(operating_path.read_bytes()).hexdigest()
    report_digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    if "D123 / P1" not in operating_path.read_text() or "APPROVED as D123" not in report_path.read_text():
        raise AccountingError("d123-explicit-approval-binding-missing")
    with _locked(path):
        value = _load(path, root)
        state = value["phase6_accounting"]
        anchor = state.get("active_anchor")
        if not isinstance(anchor, dict) or anchor.get("id") != json.loads(anchor_file.read_text()).get("id"):
            raise AccountingError("d123-active-anchor-mismatch")
        if anchor.get("boot_identity") != boot_identity or anchor.get("purpose") != "d123-global-engineering":
            raise AccountingError("d123-anchor-boot-or-purpose-mismatch")
        if abs(_closed_seconds(state) - D123_GLOBAL_FLOOR_SECONDS) > 0.0005:
            raise AccountingError("d123-global-floor-mismatch")
        if abs(_numeric(value.get("d121_recovery_amendment", {}).get("pea_floor_seconds", D123_PEA_FLOOR_SECONDS), "d123-pea-floor") - D123_PEA_FLOOR_SECONDS) > 0.0005:
            raise AccountingError("d123-pea-floor-mismatch")
        attempts, _ = _target_usage(value["records"], PEA_SIGNATURE)
        if attempts != 1:
            raise AccountingError("d123-attempt-floor-mismatch")
        if value.get("d123_recovery_policy") is not None:
            existing = _validate_d123_policy(value, project_root=root)
            if existing.get("plan_sha256") != plan_digest or existing.get("plan_check_sha256") != check_digest:
                raise AccountingError("d123-policy-already-bound-differently")
            return dict(existing)
        if value.get("d122_recovery_exception") is not None:
            # D122 is historical evidence. Its objects remain readable and immutable;
            # D123 is a distinct prospective authority and purpose namespace.
            validate_d122_exception(value)
        policy = {"schema": "phase6-d123-recovery-v1", "status": "active",
            "plan": D123_PLAN_ID, "approval": "D123/P1", "approval_context_sha256": report_digest,
            "operating_contract_sha256": operating_digest, "plan_sha256": plan_digest,
            "plan_check_sha256": check_digest, "global_floor_seconds": D123_GLOBAL_FLOOR_SECONDS,
            "pea_floor_seconds": D123_PEA_FLOOR_SECONDS, "global_cap_seconds": D123_GLOBAL_CAP_SECONDS,
            "pea_cap_seconds": D123_PEA_CAP_SECONDS, "protected_14_seconds": D123_PROTECTED_14_SECONDS,
            "closeout_reserve_seconds": D123_CLOSEOUT_RESERVE_SECONDS, "attempts_floor": 1,
            "attempts_cap": 3, "anchor_id": anchor["id"], "boot_identity": boot_identity,
            "historical_d122_preserved": True, "created_at": _now()}
        value["d123_recovery_policy"] = policy
        value.setdefault("d123_runs", [])
        _validate_d123_policy(value, project_root=root)
        _write(path, value)
        return dict(policy)


def authorize_d123_activity(ledger_path: pathlib.Path, *, activity_id: str, stage: str,
                            exposure_seconds: float, boot_identity: str,
                            project_root: pathlib.Path, launcher: Callable[[dict[str, Any]], Any],
                            hypothesis: str | None = None,
                            relevant_change: str | None = None, evidence_identity: str | None = None,
                            no_new_evidence: bool = False, engineering_owner: str | None = None) -> Any:
    """Reserve one bounded D123 child before launch; charge enclosing global anchor once."""
    if engineering_owner is not None:
        if engineering_owner != "06-23":
            raise AccountingError("qualification23-engineering-owner-invalid")
        row = begin_qualification23_activity(ledger_path, activity_id=activity_id, stage=stage,
            exposure_seconds=exposure_seconds, boot_identity=boot_identity, project_root=project_root)
        status = "interrupted"
        result = None
        try:
            result = launcher(row)
            status = "completed"
            return result
        finally:
            finalize_qualification23_activity(ledger_path, activity_id=activity_id, status=status,
                boot_identity=boot_identity, project_root=project_root, result=result)
    if not re.fullmatch(r"d123-(?:dev|qual)-[a-z0-9][a-z0-9-]{0,90}", activity_id):
        raise AccountingError("d123-activity-id-invalid")
    exposure = _numeric(exposure_seconds, "d123-exposure")
    maximum = 300.0 if stage == "build" else 30.0
    if exposure <= 0 or exposure > maximum:
        raise AccountingError("d123-activity-exposure-invalid")
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    started = time.monotonic()
    row: dict[str, Any]
    with _locked(path):
        value = _load(path, root)
        policy = _validate_d123_policy(value, project_root=root)
        if policy.get("boot_identity") != boot_identity:
            raise AccountingError("d123-boot-identity-mismatch")
        if any(item.get("activity_id") == activity_id for item in value.get("d123_runs", [])):
            raise AccountingError("d123-activity-id-spent")
        if any(item.get("status") == "reserved" for item in value.get("d123_runs", [])):
            raise AccountingError("d123-activity-already-active")
        if stage == "diagnostic":
            if (not isinstance(hypothesis, str) or not hypothesis.strip() or
                    not isinstance(relevant_change, str) or not relevant_change.strip() or
                    not isinstance(evidence_identity, str) or not re.fullmatch(r"[0-9a-f]{64}", evidence_identity)):
                raise AccountingError("d123-diagnostic-causal-identity-required")
            history = [item for item in value.get("d123_runs", [])
                       if item.get("stage") == "diagnostic" and item.get("hypothesis") == hypothesis]
            if history and history[-1].get("status") == "interrupted" and \
                    history[-1].get("relevant_change") == relevant_change:
                raise AccountingError("d123-repeat-failure-without-relevant-change")
            no_evidence_streak = 0
            for item in reversed(history):
                if item.get("no_new_evidence") is not True:
                    break
                no_evidence_streak += 1
            if no_new_evidence and no_evidence_streak >= 2:
                raise AccountingError("d123-two-no-new-evidence-iterations")
        active = _active_elapsed(value["phase6_accounting"], started, boot_identity)
        global_used = _closed_seconds(value["phase6_accounting"]) + active
        global_remaining = D123_GLOBAL_CAP_SECONDS - global_used
        required = exposure + D123_PROTECTED_14_SECONDS + D123_CLOSEOUT_RESERVE_SECONDS
        if global_remaining + 1e-9 < required:
            raise AccountingError("d123-protected-global-reserve-insufficient")
        row = {"activity_id": activity_id, "stage": stage, "status": "reserved",
            "exposure_seconds": exposure, "protected_14_seconds": D123_PROTECTED_14_SECONDS,
            "closeout_reserve_seconds": D123_CLOSEOUT_RESERVE_SECONDS,
            "global_remaining_at_reservation": global_remaining,
            "reserved_at_monotonic": started, "boot_identity": boot_identity,
            "pea_charge_seconds": 0.0, "hypothesis": hypothesis,
            "relevant_change": relevant_change, "evidence_identity": evidence_identity,
            "no_new_evidence": bool(no_new_evidence), "created_at": _now()}
        value["d123_runs"].append(row)
        _write(path, value)
    try:
        result = launcher(dict(row))
        elapsed = round(time.monotonic() - started, 3)
        if elapsed > exposure:
            row.update(status="interrupted", elapsed_seconds=elapsed, failure="d123-exposure-exceeded")
            raise AccountingError("d123-exposure-exceeded")
        row.update(status="completed", elapsed_seconds=elapsed)
        if isinstance(result, (dict, list, str, int, float, bool)) or result is None:
            # Keep public evidence independent of the operator's home directory.
            # Bind the exact launcher payload before replacing the checkout prefix.
            encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            row["launcher_result_sha256"] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            public_result = result
            if isinstance(result, (dict, list, str)):
                public_result = json.loads(encoded.replace(str(root), "$PROJECT_ROOT"))
            row["launcher_result"] = public_result
        return result
    except BaseException as exc:
        row.update(status="interrupted", elapsed_seconds=round(time.monotonic() - started, 3),
                   failure=type(exc).__name__)
        raise
    finally:
        with _locked(path):
            latest = _load(path, root)
            current = next((item for item in latest.get("d123_runs", []) if item.get("activity_id") == activity_id), None)
            if not isinstance(current, dict) or current.get("status") != "reserved":
                raise AccountingError("d123-reservation-changed-during-activity")
            current.update(row)
            current["finalized_at"] = _now()
            _write(path, latest)


def freeze_d123_observer_manifest(ledger_path: pathlib.Path, manifest_path: pathlib.Path, *,
                                  project_root: pathlib.Path, boot_identity: str, engineering_owner=None) -> dict[str, Any]:
    """Bind the exercised D123 qualification closure exactly once before qualification runs."""
    root = pathlib.Path(project_root).resolve(strict=True)
    path = _safe_path(ledger_path, root)
    manifest_file = _safe_path(manifest_path, root)
    document = json.loads(manifest_file.read_text())
    digest = hashlib.sha256(manifest_file.read_bytes()).hexdigest()
    if (document.get("schema") != "phase6-d123-stack-observation-manifest-v1" or
            document.get("status") != "frozen" or
            not re.fullmatch(r"[0-9a-f]{64}", str(document.get("source_identity", ""))) or
            document.get("source_identity") != source_identity(root) or
            [row.get("variant") for row in document.get("cases", [])] != ["native", "sanitize", "hooks-off"] or
            [row.get("variant") for row in document.get("builds", [])] != ["native", "sanitize", "hooks-off"]):
        raise AccountingError("d123-manifest-content-or-source-invalid")
    component_map = document.get("component_sha256", {})
    if not isinstance(component_map, dict) or not component_map:
        raise AccountingError("d123-manifest-component-map-missing")
    for name, expected in component_map.items():
        candidate = _safe_path(root / name, root)
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != expected:
            raise AccountingError("d123-manifest-component-drift:" + name)
    with _locked(path):
        value = _load(path, root)
        if engineering_owner is not None:
            if engineering_owner!='06-23' or document.get('engineering_owner')!='06-23' or document.get('generation')!='23' or document.get('game_admission') is not False:
                raise AccountingError('qualification23-manifest-explicit-owner-required')
            policy=qualification23_owner(value,project_root=root,boot_identity=boot_identity)
            if 'd125_qualification23_manifest' in value:raise AccountingError('qualification23-manifest-replayed')
            if [r.get('purpose_id') for r in document['cases']]!=['d123-qual-g23-'+v for v in ('native','sanitize','hooks-off')]:
                raise AccountingError('qualification23-exact-three-purposes-required')
            frozen={'status':'frozen','path':manifest_file.relative_to(root).as_posix(),'sha256':digest,
                'source_identity':document['source_identity'],'generation':'23','game_admission':False,'frozen_at':_now()}
            value['d125_qualification23_manifest']=frozen
            _write(path,value)
            return dict(frozen)
        policy = _validate_d123_policy(value, project_root=root)
        if policy.get("boot_identity") != boot_identity:
            raise AccountingError("d123-boot-identity-mismatch")
        previous = value.get("d123_observer_manifest")
        if previous is not None:
            if previous.get("status") != "frozen" or previous.get("sha256") == digest or \
                    previous.get("qualification_generation") == document.get("generation"):
                raise AccountingError("d123-observer-manifest-generation-replay")
            value.setdefault("d123_observer_manifest_history", []).append(previous)
        neighbors = next((row for row in reversed(value.get("d123_runs", []))
                          if row.get("stage") == "diagnostic" and
                          row.get("launcher_result", {}).get("real_forwarding_neighbors") == "accepted"), None)
        if not isinstance(neighbors, dict) or neighbors.get("status") != "completed":
            raise AccountingError("d123-real-neighbor-evidence-required-before-freeze")
        frozen = {"status": "frozen", "path": manifest_file.relative_to(root).as_posix(),
            "sha256": digest, "source_identity": document["source_identity"],
            "qualification_generation": document.get("generation"),
            "frozen_at": _now(), "approval": policy["approval"],
            "approval_context_sha256": policy["approval_context_sha256"],
            "plan_sha256": policy["plan_sha256"], "plan_check_sha256": policy["plan_check_sha256"]}
        value["d123_observer_manifest"] = frozen
        _write(path, value)
        return dict(frozen)


def freeze_observer_manifest(ledger_path: pathlib.Path, manifest_path: pathlib.Path, *,
                             source_identity: str, boot_identity: str,
                             allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Bind exact authored manifest bytes to the approved observer scope without launching."""
    path = _safe_path(ledger_path, allowed_root)
    manifest = _safe_path(manifest_path, allowed_root)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or not re.fullmatch(r"[0-9a-f]{40,64}", source_identity):
        raise AccountingError("observer-manifest-identity-invalid")
    with _locked(path):
        value = _load(path, allowed_root)
        approval = value.get("phase6_accounting", {}).get("scope_approval", {})
        if approval.get("status") != "approved" or approval.get("id") != "GW-06-16-observer-scope-approval":
            raise AccountingError("observer-scope-approval-required")
        state = value["phase6_accounting"]
        _active_elapsed(state, time.monotonic(), boot_identity)
        existing = value.get("stack_observer_manifest")
        frozen = {"status": "frozen", "path": manifest.relative_to(pathlib.Path(allowed_root or path.parent).resolve()).as_posix(),
                  "sha256": digest, "source_identity": source_identity, "frozen_at": _now(),
                  "purpose_ids": list(OBSERVER_PROOF_PURPOSES)}
        if existing is not None and existing != frozen:
            # Plan17 may finalize Python checker/coordinator identities before any
            # activity. Exact authored manifest bytes remain fixed across that bind.
            if (not isinstance(existing, dict) or existing.get("status") != "frozen" or
                    existing.get("sha256") != digest):
                raise AccountingError("observer-manifest-already-frozen")
            if existing.get("source_identity") == source_identity:
                return dict(existing)
            if any(row.get("observer_activity_kind") for row in value["records"]):
                raise AccountingError("observer-source-rebind-after-activity")
            history = list(existing.get("source_identity_history", [existing["source_identity"]]))
            if source_identity not in history:
                history.append(source_identity)
            frozen["source_identity_history"] = history
        value["stack_observer_manifest"] = frozen
        _write(path, value)
        return dict(frozen)


def _observer_activity_authorization(value: dict[str, Any], *, purpose: str, case: str,
                                     source_identity: str, binary_identity: str,
                                     command_identity: str, manifest_sha256: str,
                                     plan: str) -> tuple[str, int, int]:
    approval = value.get("phase6_accounting", {}).get("scope_approval", {})
    d122 = value.get("d122_recovery_exception")
    manifest = value.get("d122_successor_manifest", {}) if d122 is not None else value.get("stack_observer_manifest", {})
    if approval.get("status") != "approved":
        raise AccountingError("observer-scope-approval-required")
    expected_plan = "06-18" if d122 is not None else "06-17"
    if d122 is not None:
        validate_d122_exception(value)
        successor = value.get("d122_successor_manifest", {})
        if successor.get("status") != "frozen" or successor.get("sha256") != manifest_sha256:
            raise AccountingError("d122-successor-manifest-mismatch")
    if plan != expected_plan or manifest.get("status") != "frozen" or manifest.get("sha256") != manifest_sha256:
        raise AccountingError("observer-manifest-or-plan-mismatch")
    bound_source = manifest.get("source_identity")
    if bound_source != source_identity:
        raise AccountingError("observer-source-identity-mismatch")
    for name, value_to_check in (("source", source_identity), ("binary", binary_identity),
                                 ("command", command_identity), ("manifest", manifest_sha256)):
        if not isinstance(value_to_check, str) or not re.fullmatch(r"[0-9a-f]{40,64}", value_to_check):
            raise AccountingError(f"observer-{name}-identity-invalid")
    if purpose == "stack-observer-builds":
        if case != OBSERVER_BUILD_CASE:
            raise AccountingError("observer-build-case-denied")
        return "build", OBSERVER_BUILD_WATCHDOG_SECONDS, 300
    if (purpose not in OBSERVER_PROOF_PURPOSES or case != OBSERVER_PROOF_PURPOSES[purpose]):
        raise AccountingError("observer-proof-purpose-denied")
    return "proof", OBSERVER_PROOF_WATCHDOG_SECONDS, OBSERVER_PROOF_TOTAL_SECONDS


def authorize_observer_activity(ledger_path: pathlib.Path, *, purpose: str, plan: str,
                                case: str, source_identity: str, current_source_identity: str,
                                binary_identity: str, command_identity: str,
                                manifest_sha256: str, launcher: Callable[[dict[str, Any]], Any],
                                boot_identity: str, allowed_root: pathlib.Path | None = None, engineering_owner=None) -> Any:
    """Reserve one approved build/proof activity, call its bounded launcher and finalize actual wall."""
    if source_identity != current_source_identity:
        raise AccountingError("stale-source-identity")
    if engineering_owner is not None:
        if engineering_owner!='06-23' or plan!='06-23' or purpose!=case or case not in {'d123-qual-g23-'+v for v in ('native','sanitize','hooks-off')}:
            raise AccountingError('qualification23-observer-purpose-denied')
        value=_load(_safe_path(ledger_path,allowed_root),allowed_root)
        policy=qualification23_owner(value,project_root=allowed_root,boot_identity=boot_identity)
        frozen=value.get('d125_qualification23_manifest',{})
        if frozen.get('sha256')!=manifest_sha256 or frozen.get('source_identity')!=source_identity:
            raise AccountingError('qualification23-observer-manifest-stale')
        return authorize_d123_activity(ledger_path,activity_id=case,stage='qualification',exposure_seconds=30,
            boot_identity=boot_identity,project_root=allowed_root,launcher=launcher,engineering_owner='06-23')
    path = _safe_path(ledger_path, allowed_root)
    with _locked(path):
        value = _load(path, allowed_root)
        kind, watchdog, total_limit = _observer_activity_authorization(
            value, purpose=purpose, case=case, source_identity=source_identity,
            binary_identity=binary_identity, command_identity=command_identity,
            manifest_sha256=manifest_sha256, plan=plan)
        state = value["phase6_accounting"]
        elapsed = _active_elapsed(state, time.monotonic(), boot_identity)
        anchor = state["active_anchor"]
        d122 = value.get("d122_recovery_exception")
        if d122 is None:
            offline_start = _numeric(anchor.get("offline_remaining_at_anchor_seconds"), "offline-remaining")
            if elapsed >= offline_start or offline_start - elapsed < watchdog:
                raise AccountingError("observer-offline-headroom-insufficient")
        global_limit = _numeric(value.get("budgets", {}).get("cumulative_repair_seconds"), "cumulative-limit")
        global_remaining = global_limit - (_closed_seconds(state) + elapsed)
        records = value["records"]
        reservations = [row for row in records if row.get("observer_activity_kind") == kind]
        expected_purpose = "stack-observer-builds" if kind == "build" else purpose
        identifier = f"GW-06-AUTH-{expected_purpose}-{case}"
        if any(row.get("record_id") == identifier for row in records):
            raise AccountingError("observer-purpose-already-spent")
        if any(row.get("status") == "reserved" and row.get("observer_activity_kind") for row in records):
            raise AccountingError("observer-activity-already-active")
        spent = (d122_partition_spent(value, "observer_builds" if kind == "build" else "observer_proofs")
                 if d122 is not None else
                 sum(_numeric(row.get("observer_active_seconds", 0), "observer-active-seconds")
                     for row in reservations))
        if spent + watchdog > total_limit:
            raise AccountingError("observer-activity-budget-exhausted")
        if d122 is not None:
            protected = (D122_PROCESS_PARTITION_SECONDS - d122_partition_spent(value, "14_processes") +
                         D122_OTHER_PARTITION_SECONDS - d122_partition_spent(value, "14_other") +
                         D122_CLOSEOUT_RESERVE_SECONDS)
            if global_remaining - watchdog < protected:
                raise AccountingError("d122-protected-global-reserve-insufficient")
        row = {"record_id": identifier, "record_type": "authorization-reservation",
               "purpose": expected_purpose, "plan": plan, "case": case,
               "source_identity": source_identity, "binary_identity": binary_identity,
               "command_identity": command_identity, "manifest_sha256": manifest_sha256,
               "target_stop_signature": None, "new_target_attempts": 0,
               "process_count": 3 if kind == "build" else 1, "case_count": 1, "observer_activity_kind": kind,
               "observer_watchdog_seconds": watchdog, "observer_active_seconds": 0.0,
               "monotonic_started_at": time.monotonic(), "boot_identity": boot_identity,
               "status": "reserved", "created_at": _now()}
        records.append(row)
        _write(path, value)
    try:
        result = launcher(dict(row))
        elapsed_actual = round(time.monotonic() - row["monotonic_started_at"], 3)
        if elapsed_actual > watchdog:
            row["status"] = "interrupted"
            row["failure_type"] = "observer-watchdog-exceeded"
            row["observer_active_seconds"] = elapsed_actual
            raise AccountingError("observer-watchdog-exceeded")
        row["status"] = "completed"
        row["observer_active_seconds"] = elapsed_actual
        if isinstance(result, (dict, list, str, int, float, bool)) or result is None:
            row["launcher_result"] = result
        return result
    except BaseException as exc:
        row["status"] = "interrupted"
        row["failure_type"] = type(exc).__name__
        row["observer_active_seconds"] = round(time.monotonic() - row["monotonic_started_at"], 3)
        raise
    finally:
        with _locked(path):
            latest = _load(path, allowed_root)
            matches = [item for item in latest["records"] if item.get("record_id") == identifier]
            if len(matches) != 1 or matches[0].get("status") != "reserved":
                raise AccountingError("observer-reservation-changed-during-activity")
            matches[0].update(row)
            matches[0]["finalized_at"] = _now()
            _write(path, latest)


def validate_tank_continuation_receipt(value: dict[str, Any], *, require_checked: bool = True) -> bool:
    """Validate the current 06-14 capture pointer, optionally requiring independent checking."""
    receipt=value.get("current_tank_continuation_receipt", {})
    if value.get("d125_owner_generations"):
        try:owner = selected_recovery_owner(value, require_runtime=True)
        except AccountingError:return False
        binding = owner["runtime_binding"]
        expected_id = "GW-06-AUTH-tank-continuation-" + D125_CASES[0]
        if (receipt.get("status") != ("passed" if require_checked else "captured") or receipt.get("record_id") != expected_id or
                receipt.get("recovery_owner") != D125_PLAN_ID or receipt.get("generation_id") != owner["generation_id"] or
                receipt.get("source_identity") != binding["source_identity"] or receipt.get("purpose") != "tank-continuation" or
                receipt.get("plan") != "06-14" or any(receipt.get(key) != binding[name]["sha256"] for key,name in
                (("bridge_file_sha256","bridge"),("proof_review_sha256","proof_review"),("observer_review_check_file_sha256","review_check")))):
            return False
        return (not require_checked or (receipt.get("independently_checked") is True and all(
            re.fullmatch(r"[0-9a-f]{64}",str(receipt.get(key,""))) for key in
            ("checked_receipt_sha256","checker_sha256","final_acceptance_review_sha256","trusted_final_handoff_sha256"))))
    if not isinstance(receipt,dict) or receipt.get("status") != ("passed" if require_checked else "captured"):
        return False
    if receipt.get("record_id")!="GW-06-AUTH-tank-continuation-tank-pea-continuation-1" or \
       receipt.get("purpose")!="tank-continuation" or receipt.get("plan")!="06-14" or \
       not isinstance(receipt.get("source_identity"),str) or not isinstance(receipt.get("contract_identity"),str) or \
       not re.fullmatch(r"[0-9a-f]{64}",str(receipt.get("capture_sha256",""))):
        return False
    if require_checked and (receipt.get("independently_checked") is not True or
       not re.fullmatch(r"[0-9a-f]{64}",str(receipt.get("checked_receipt_sha256",""))) or
       not re.fullmatch(r"[0-9a-f]{64}",str(receipt.get("checker_sha256","")))):
        return False
    if isinstance(value.get("d124_recovery_policy"), dict):
        binding = value.get("d124_observer_bridge_binding", {})
        if (binding.get("status") != "independently-accepted" or
                receipt.get("bridge_sha256") != binding.get("bridge_sha256") or
                receipt.get("observer_review_check_path") != binding.get("review_check_path") or
                receipt.get("observer_review_check_file_sha256") != binding.get("review_check_file_sha256") or
                receipt.get("component_disposition_sha256") !=
                    value.get("d124_component_disposition", {}).get("sha256") or
                not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("bridge_file_sha256", ""))) or
                not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("observer_review_check_file_sha256", "")))):
            return False
        if require_checked and (not re.fullmatch(r"[0-9a-f]{64}",
                str(receipt.get("final_acceptance_review_sha256", ""))) or
                not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("trusted_final_handoff_sha256", "")))):
            return False
    return True


def authorize_launch(ledger_path: pathlib.Path, *, purpose: str, plan: str,
                     case: str, source_identity: str, current_source_identity: str,
                     contract_identity: str, target_signature: str | None,
                     launcher: Callable[[dict[str, Any]], Any],
                     boot_identity: str, allowed_root: pathlib.Path | None = None) -> Any:
    """Authorize, reserve, then call a launcher; failures remain spent."""
    if plan in ('06-23', '06-24'):
        raise AccountingError('engineering-owner-game-launch-denied')
    if not isinstance(source_identity, str) or not re.fullmatch(r"[0-9a-f]{40,64}", source_identity):
        raise AccountingError("source-identity-invalid")
    if source_identity != current_source_identity:
        raise AccountingError("stale-source-identity")
    if not isinstance(contract_identity, str) or not contract_identity.strip():
        raise AccountingError("contract-identity-invalid")
    path = _safe_path(ledger_path, allowed_root)
    if _load(path, allowed_root).get("d125_owner_generations"):
        return _authorize_d125_launch(path, purpose=purpose, plan=plan, case=case, source=source_identity,
            contract=contract_identity, target=target_signature, launcher=launcher, boot_identity=boot_identity,
            project_root=pathlib.Path(allowed_root or pathlib.Path(__file__).resolve().parents[2]))
    with _locked(path):
        before = ledger_digest(path)
        value = _load(path, allowed_root)
        state = value["phase6_accounting"]
        d124 = isinstance(value.get("d124_recovery_policy"), dict)
        if (purpose == "tank-continuation" and not isinstance(value.get("d124_recovery_policy"), dict) and
                isinstance(value.get("d123_recovery_policy"), dict)):
            authority=value.get("d123_observer_bridge_binding", {})
            if authority.get("source_identity") != source_identity:
                raise AccountingError("d123-stale-source-authority")
        if isinstance(value.get("d124_recovery_policy"), dict):
            policy = _validate_d124_policy(value)
            if policy.get("boot_identity") != boot_identity:
                raise AccountingError("d124-boot-identity-mismatch")
        _authorization(value, purpose=purpose, plan=plan, case=case,
                       target_signature=target_signature)
        if (plan == "06-14" and not d124 and
            any(row.get("status") == "active" for row in value.get("d122_accounting", {}).get("other_charges", []))):
            raise AccountingError("d122-other-process-overlap")
        if purpose == "tank-continuation":
            proof = value["tank_proof_revalidation"]
            if proof.get("source_identity") != source_identity or proof.get("contract_identity") != contract_identity:
                raise AccountingError("tank-continuation-proof-identity-mismatch")
        if purpose == "tank-continuation-control":
            receipt = value["current_tank_continuation_receipt"]
            if receipt.get("source_identity") != source_identity or receipt.get("contract_identity") != contract_identity:
                raise AccountingError("tank-control-receipt-identity-mismatch")
        records = value["records"]
        reservation_id = f"GW-06-AUTH-{purpose}-{case}"
        reservations = [r for r in records if r.get("record_type") == "authorization-reservation"]
        if any(r.get("record_id") == reservation_id for r in reservations):
            raise AccountingError("duplicate-reservation")
        elapsed = _active_elapsed(state, time.monotonic(), boot_identity)
        cumulative = _closed_seconds(state) + elapsed
        limit = _numeric(value.get("budgets", {}).get("cumulative_repair_seconds"), "cumulative-limit")
        if cumulative >= limit:
            raise AccountingError("cumulative-active-time-exhausted")
        watchdog = TANK_CONTINUATION_WATCHDOG_SECONDS if purpose in (
            "tank-continuation", "tank-continuation-control") else 0
        watchdog_preflight = None
        if watchdog:
            if any(r.get("status") == "reserved" and r.get("limits", {}).get("watchdog_seconds")
                   for r in reservations):
                raise AccountingError("watchdog-reservation-already-active")
            if limit - cumulative < watchdog:
                raise AccountingError("cumulative-watchdog-headroom-insufficient")
            if d124:
                remaining = d124_remaining(value, monotonic_now=time.monotonic(), boot_identity=boot_identity)
                process_used = remaining["process_used_seconds"]
                if process_used + watchdog > D124_PROCESS_RESERVE_SECONDS:
                    raise AccountingError("d124-process-reserve-exhausted")
                protected = (D124_PROCESS_RESERVE_SECONDS - process_used - watchdog) + D124_CLOSEOUT_RESERVE_SECONDS
                if remaining["global_remaining_seconds"] < watchdog + protected:
                    raise AccountingError("d124-protected-global-reserve-insufficient")
                if remaining["pea_remaining_seconds"] < watchdog:
                    raise AccountingError("d124-pea-watchdog-headroom-insufficient")
            elif value.get("d122_recovery_exception") is not None:
                validate_d122_exception(value)
                process_spent = d122_partition_spent(value, "14_processes")
                other_spent = d122_partition_spent(value, "14_other")
                if purpose in ("tank-continuation", "tank-continuation-control"):
                    if process_spent + watchdog > D122_PROCESS_PARTITION_SECONDS:
                        raise AccountingError("d122-process-partition-exhausted")
                    remaining_process = D122_PROCESS_PARTITION_SECONDS - process_spent - watchdog
                    protected = remaining_process + (D122_OTHER_PARTITION_SECONDS - other_spent) + D122_CLOSEOUT_RESERVE_SECONDS
                    if limit - cumulative < watchdog + protected:
                        raise AccountingError("d122-protected-global-reserve-insufficient")
        target_attempts = 1 if purpose in ("independent-pea", "tank-continuation") and case in (
            "tank-pea-regression", TANK_CONTINUATION_CASE) else 0
        budget_signature = PEA_SIGNATURE if watchdog else target_signature
        if (target_attempts and target_signature) or watchdog:
            used, target_seconds = _target_usage(records, budget_signature,
                                                 boot_identity, time.monotonic())
            anchor_start = _numeric(state.get("active_anchor", {}).get("monotonic_started_at"),
                                    "monotonic-start")
            # Active plan wall is charged conservatively to the target. Process
            # wall already represented by this plan's target reservations is
            # removed so the same time is never charged twice.
            current_target_process = sum(
                _numeric(r.get("target_active_seconds", 0), "target-active-seconds")
                for r in records if r.get("target_stop_signature") == budget_signature and
                r.get("record_type") == "authorization-reservation" and
                _numeric(r.get("monotonic_started_at", 0), "target-monotonic-start") >= anchor_start)
            if isinstance(value.get("d124_recovery_policy"), dict):
                target_seconds += d122_partition_spent(value, "observer_builds")
                target_seconds += d122_partition_spent(value, "observer_proofs")
                target_seconds += d122_control_process_spent(value)
                target_seconds += d122_partition_spent(value, "14_other")
            elif value.get("d122_recovery_exception") is not None:
                target_seconds += d122_partition_spent(value, "observer_builds")
                target_seconds += d122_partition_spent(value, "observer_proofs")
                target_seconds += d122_control_process_spent(value)
                target_seconds += d122_partition_spent(value, "14_other")
            elif state.get("active_anchor", {}).get("pea_charge") is not False:
                target_seconds = max(0.0, target_seconds + elapsed - current_target_process)
            time_limit = effective_target_limit(value, budget_signature)
            if target_attempts:
                cap_number = _numeric(value.get("budgets", {}).get("attempts_per_stop", 3), "attempt-limit")
                if not cap_number.is_integer() or cap_number <= 0:
                    raise AccountingError("attempt-limit-invalid")
                cap = int(cap_number)
                if used >= cap:
                    raise AccountingError("target-attempt-budget-exhausted")
            if target_seconds >= time_limit:
                raise AccountingError("target-time-budget-exhausted")
            target_remaining = max(0.0, time_limit - target_seconds)
            if watchdog and time_limit - target_seconds < watchdog:
                raise AccountingError("target-watchdog-headroom-insufficient")
            if watchdog:
                watchdog_preflight = {"global_remaining_seconds": round(limit - cumulative, 3),
                                      "target_remaining_seconds": round(target_remaining, 3),
                                      "required_watchdog_seconds": watchdog}
        reservation = {
            "record_id": reservation_id,
            "record_type": "authorization-reservation",
            "purpose": purpose,
            "plan": plan,
            "case": case,
            "source_identity": source_identity,
            "contract_identity": contract_identity,
            "target_stop_signature": target_signature,
            "title_id": "tank-battle" if purpose in ("independent-pea", "tank-continuation") else
                       "tank-battle-control" if purpose == "independent-control" else
                       "tank-battle-control" if purpose == "tank-continuation-control" else
                       "recursion94" if purpose == "rec-validation" else "joint-qualification",
            "process_count": 1,
            "case_count": 1,
            "new_target_attempts": target_attempts,
            "target_active_seconds": 0.0,
            "process_active_seconds": 0.0,
            "monotonic_started_at": time.monotonic(),
            "boot_identity": boot_identity,
            "status": "reserved",
            "created_at": _now(),
            "reservation_ledger_sha256": before,
        }
        if d124 and watchdog and plan == "06-14":
            reservation["d124_successor"] = D124_PLAN_ID
        if watchdog:
            reservation["limits"] = {"watchdog_seconds": watchdog}
            reservation["preflight_remaining_seconds"] = watchdog_preflight
        records.append(reservation)
        _write(path, value)
        reserved_digest = ledger_digest(path)
    try:
        result = launcher(reservation)
        reservation["status"] = "completed"
        elapsed_process = round(time.monotonic() - reservation["monotonic_started_at"], 3)
        reservation["target_active_seconds"] = elapsed_process if target_attempts else 0.0
        reservation["process_active_seconds"] = elapsed_process if watchdog and plan == "06-14" else 0.0
        if isinstance(result, (dict, list, str, int, float, bool)) or result is None:
            reservation["launcher_result"] = result
        return result
    except BaseException as exc:
        reservation["status"] = "interrupted"
        reservation["failure_type"] = type(exc).__name__
        elapsed_process = round(time.monotonic() - reservation["monotonic_started_at"], 3)
        reservation["target_active_seconds"] = elapsed_process if target_attempts else 0.0
        reservation["process_active_seconds"] = elapsed_process if watchdog and plan == "06-14" else 0.0
        raise
    finally:
        with _locked(path):
            latest = _load(path, allowed_root)
            if hashlib.sha256(_canonical(_immutable_snapshot(latest, latest["phase6_accounting"]["immutable_prefix_count"]))).hexdigest() != latest["phase6_accounting"]["immutable_prefix_sha256"]:
                raise AccountingError("immutable-history-changed")
            if ledger_digest(path) != reserved_digest:
                raise AccountingError("stale-ledger-writer")
            matches = [r for r in latest["records"] if r.get("record_id") == reservation_id]
            if len(matches) != 1 or matches[0].get("status") != "reserved":
                raise AccountingError("reserved-attempt-changed-during-launch")
            finalized = dict(reservation)
            finalized["finalized_at"] = _now()
            matches[0].clear()
            matches[0].update(finalized)
            _write(path, latest)


def _authorize_d125_launch(path, *, purpose, plan, case, source, contract, target, launcher, boot_identity, project_root):
    """One durable serial reservation. Driver wall is charged once; children are subsidiary."""
    root = pathlib.Path(project_root).resolve(strict=True)
    with _locked(path):
        value = _load(path, root)
        owner = selected_recovery_owner(value, project_root=root, require_runtime=True)
        _authorization(value, purpose=purpose, plan=plan, case=case, target_signature=target)
        balances = _d125_process_preflight(value, case=case, monotonic_now=time.monotonic(), boot_identity=boot_identity, project_root=root)
        bridge = json.loads((root / owner["runtime_binding"]["bridge"]["path"]).read_bytes())
        if source != owner["runtime_binding"]["source_identity"] or contract != bridge.get("bridge_sha256"):
            raise AccountingError("d125-process-source-or-contract-stale")
        _d125_validate_launch_forecast(value,owner,balances,monotonic_now=time.monotonic(),boot_identity=boot_identity)
        if purpose == "tank-continuation" and balances["attempts_used"] >= 3:
            raise AccountingError("d125-target-attempt-budget-exhausted")
        reservation_id=f"GW-06-AUTH-{purpose}-{case}"
        if any(r.get("record_id")==reservation_id for r in value["records"]):
            raise AccountingError("duplicate-reservation")
        row={"record_id":reservation_id,"record_type":"authorization-reservation","purpose":purpose,"plan":plan,"case":case,
            "d125_owner":D125_PLAN_ID,"generation_id":owner["generation_id"],"source_identity":source,"contract_identity":contract,
            "target_stop_signature":target,"new_target_attempts":int(purpose=="tank-continuation"),"process_count":1,"case_count":1,
            "status":"reserved","monotonic_started_at":time.monotonic(),"boot_identity":boot_identity,"created_at":_now(),
            "process_active_seconds":0.0,"target_active_seconds":0.0,"limits":{"watchdog_seconds":600},
            "preflight_remaining_seconds":balances,"reservation_ledger_sha256":ledger_digest(path),
            "owner_generation_sha256":hashlib.sha256(_canonical(owner)).hexdigest()}
        value["records"].append(row);_write(path,value);reserved_digest=ledger_digest(path)
    try:
        # Immediate prespawn consumers revalidate the exact owner tuple again.
        current=_load(path,root)
        current_owner=selected_recovery_owner(current,project_root=root,require_runtime=True)
        if ledger_digest(path)!=reserved_digest:raise AccountingError("d125-ledger-changed-before-process")
        current_balances=d125_remaining(current,monotonic_now=time.monotonic(),boot_identity=boot_identity,project_root=root)
        _d125_validate_launch_forecast(current,current_owner,current_balances,monotonic_now=time.monotonic(),boot_identity=boot_identity)
        result=launcher(row)
        row["status"]="completed"
        if isinstance(result,(dict,list,str,int,float,bool)) or result is None:row["launcher_result"]=result
        return result
    except BaseException as exc:
        row.update(status="interrupted",failure_type=type(exc).__name__,failure_detail=str(exc))
        raise
    finally:
        elapsed=time.monotonic()-row["monotonic_started_at"]
        row["process_active_seconds"]=math.ceil(max(0,elapsed)*1000)/1000
        row["target_active_seconds"]=row["process_active_seconds"] if row["new_target_attempts"] else 0.0
        if elapsed<0 or elapsed>600:
            row.update(status="interrupted",failure_detail="d125-process-clock-or-watchdog-exceeded")
        with _locked(path):
            latest=_load(path,root)
            if ledger_digest(path)!=reserved_digest:raise AccountingError("stale-ledger-writer")
            matches=[r for r in latest["records"] if r.get("record_id")==reservation_id]
            if len(matches)!=1 or matches[0].get("status")!="reserved":raise AccountingError("reserved-attempt-changed-during-launch")
            matches[0].clear();matches[0].update(row,finalized_at=_now());_write(path,latest)
        if elapsed<0 or elapsed>600:raise AccountingError("d125-process-clock-or-watchdog-exceeded")


def reserve_finite_processes(ledger_path: pathlib.Path, *, cases: tuple[str, ...],
                             source_identity: str, contract_identity: str,
                             boot_identity: str, allowed_root: pathlib.Path | None = None) -> list[dict[str, Any]]:
    """Persist one predeclared finite process roster atomically before any launch."""
    if cases != PEA_SHORT_CASES:
        raise AccountingError("pea-short-roster-mismatch")
    if not re.fullmatch(r"[0-9a-f]{40,64}", source_identity):
        raise AccountingError("source-identity-invalid")
    if not contract_identity.strip() or not boot_identity:
        raise AccountingError("process-roster-identity-invalid")
    path = _safe_path(ledger_path, allowed_root)
    with _locked(path):
        value = _load(path, allowed_root)
        state = value["phase6_accounting"]
        _active_elapsed(state, time.monotonic(), boot_identity)
        used = {row.get("case") for row in value["records"]
                if row.get("record_type") == "authorization-reservation"
                and row.get("purpose") == "pea-short-contract"}
        if used.intersection(cases):
            raise AccountingError("pea-short-roster-already-spent")
        start = time.monotonic()
        rows = []
        for case in cases:
            rows.append({
                "record_id": f"GW-06-AUTH-pea-short-contract-{case}",
                "record_type": "authorization-reservation", "purpose": "pea-short-contract",
                "plan": "06-11", "case": case, "source_identity": source_identity,
                "contract_identity": contract_identity, "target_stop_signature": None,
                "title_id": "tank-battle", "process_count": 1, "case_count": 1,
                "new_target_attempts": 0, "target_active_seconds": 0.0,
                "monotonic_started_at": start, "boot_identity": boot_identity,
                "status": "reserved", "created_at": _now(),
                "limits": {"watchdog_seconds": 60, "guest_instructions": 128, "fields": 8},
            })
        value["records"].extend(rows)
        _write(path, value)
        return rows


def finalize_finite_process(ledger_path: pathlib.Path, *, case: str,
                            status: str, result: dict[str, Any],
                            allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Finalize a pre-reserved short process row without permitting relaunch."""
    if case not in PEA_SHORT_CASES or status not in ("completed", "interrupted"):
        raise AccountingError("pea-short-finalization-invalid")
    path = _safe_path(ledger_path, allowed_root)
    with _locked(path):
        value = _load(path, allowed_root)
        matches = [row for row in value["records"] if row.get("record_id") ==
                   f"GW-06-AUTH-pea-short-contract-{case}"]
        if len(matches) != 1 or matches[0].get("status") != "reserved":
            raise AccountingError("pea-short-reservation-not-live")
        matches[0]["status"] = status
        matches[0]["launcher_result"] = result
        matches[0]["finalized_at"] = _now()
        matches[0]["target_active_seconds"] = 0.0
        _write(path, value)
        return dict(matches[0])


def preflight(ledger_path: pathlib.Path, *, monotonic_now: float | None = None,
              boot_identity: str | None = None, require_active_anchor: bool = False,
              allowed_root: pathlib.Path | None = None) -> dict[str, Any]:
    """Read-only report using the closed research baseline and persisted anchor."""
    value = _load(pathlib.Path(ledger_path), allowed_root)
    state = value["phase6_accounting"]
    closed = _closed_seconds(state)
    active = 0.0
    anchor = state.get("active_anchor")
    if require_active_anchor and (not isinstance(anchor, dict) or boot_identity is None or monotonic_now is None):
        raise AccountingError("active-clock-anchor-missing")
    if isinstance(anchor, dict):
        if boot_identity is None or monotonic_now is None:
            if require_active_anchor:
                raise AccountingError("active-clock-anchor-missing")
        else:
            active = _active_elapsed(state, monotonic_now, boot_identity)
    cumulative = closed + active
    limit = _numeric(value.get("budgets", {}).get("cumulative_repair_seconds"), "cumulative-limit")
    history_total = next((row.get("cumulative_seconds") for row in value.get("recovery_accounting", [])
                          if row.get("plan") == "06-08"), 5827.378)
    research = next((row.get("active_seconds") for row in value.get("recovery_accounting", [])
                     if row.get("id") == "GW-06-D120-REVIEW"), 0.0)
    observed = set(value.get("observed_stop_signatures", []))
    for row in value.get("records", []):
        result = row.get("launcher_result") if isinstance(row, dict) else None
        if not isinstance(result, dict):
            continue
        native = result.get("native_report") or result.get("post_behavior", {}).get("first_next_stop", {})
        if not isinstance(native, dict) or native.get("stop_reason") not in (2, 3, 4):
            continue
        pc = native.get("instruction_address", native.get("pc"))
        opcode = native.get("opcode")
        if type(pc) is int and type(opcode) is int:
            observed.add(f"{row.get('title_id', 'unknown')}:cpu:{pc:06x}:{opcode:04x}:{native['stop_reason']}")
    reserved = [row for row in value.get("records", [])
                if row.get("record_type") == "authorization-reservation"]
    pea_attempts, pea_seconds = _target_usage(value.get("records", []), PEA_SIGNATURE,
                                              boot_identity, monotonic_now) if boot_identity is not None and monotonic_now is not None else _target_usage(value.get("records", []), PEA_SIGNATURE)
    if (isinstance(anchor, dict) and boot_identity is not None and monotonic_now is not None and
            anchor.get("pea_charge") is not False):
        anchor_start = _numeric(anchor.get("monotonic_started_at"), "monotonic-start")
        current_target_process = sum(
            _numeric(row.get("target_active_seconds", 0), "target-active-seconds")
            for row in value.get("records", [])
            if row.get("target_stop_signature") == PEA_SIGNATURE and
            row.get("record_type") == "authorization-reservation" and
            _numeric(row.get("monotonic_started_at", 0), "target-monotonic-start") >= anchor_start)
        pea_seconds = max(0.0, pea_seconds + active - current_target_process)
    pea_effective_limit = effective_target_limit(value, PEA_SIGNATURE)
    d122 = value.get("d122_recovery_exception")
    if d122 is not None:
        pea_seconds = round(pea_seconds + d122_partition_spent(value, "observer_builds") +
                            d122_partition_spent(value, "observer_proofs") +
                            d122_control_process_spent(value) +
                            d122_partition_spent(value, "14_other"), 3)
        if any(row.get("status") == "active" for row in value.get("d122_accounting", {}).get("other_charges", [])):
            raise AccountingError("d122-other-interval-unfinalized")
    offline_at_anchor = (_numeric(anchor.get("offline_remaining_at_anchor_seconds"), "offline-remaining")
                         if isinstance(anchor, dict) and "offline_remaining_at_anchor_seconds" in anchor else None)
    offline_remaining = max(0.0, offline_at_anchor - active) if offline_at_anchor is not None else None
    observer_records = [row for row in value.get("records", [])
                        if isinstance(row, dict) and row.get("observer_activity_kind") in ("build", "proof")]
    d124_report = None
    if value.get("d125_owner_generations"):
        d124_report = {"selected_owner": D125_PLAN_ID, **d125_remaining(value,
            monotonic_now=monotonic_now if monotonic_now is not None else time.monotonic(),
            boot_identity=boot_identity, project_root=pathlib.Path(ledger_path).resolve().parent.parent)}
    elif isinstance(value.get("d124_recovery_policy"), dict):
        project_root = pathlib.Path(ledger_path).resolve().parent.parent
        policy = _validate_d124_policy(value, project_root=project_root)
        if boot_identity is not None:
            d124_report = d124_remaining(value, monotonic_now=monotonic_now if monotonic_now is not None else time.monotonic(),
                                         boot_identity=boot_identity)
            if policy.get("boot_identity") != boot_identity:
                raise AccountingError("d124-boot-identity-mismatch")
        else:
            d124_report = {"status": "boot-identity-required", "global_floor_seconds": D124_GLOBAL_FLOOR_SECONDS,
                "pea_floor_seconds": D124_PEA_FLOOR_SECONDS,
                "process_reserve_seconds": D124_PROCESS_RESERVE_SECONDS,
                "closeout_reserve_seconds": D124_CLOSEOUT_RESERVE_SECONDS}
    return {
        "status": "ready" if cumulative < limit else "blocked",
        "historical_closed_cumulative_seconds": round(_numeric(history_total, "historical-cumulative"), 3),
        "finalized_research_seconds": round(_numeric(research, "research-charge"), 3),
        "closed_cumulative_seconds": round(closed, 3),
        "active_seconds_since_anchor": round(active, 3),
        "cumulative_seconds_including_current": round(cumulative, 3),
        "remaining_cumulative_seconds": round(max(0, limit - cumulative), 3),
        "observed_signatures_used": len(observed),
        "observed_signatures_remaining": max(0, int(value.get("budgets", {}).get("distinct_stops", 12)) - len(observed)),
        "tank_pea_attempts_used": pea_attempts,
        "tank_pea_attempts_remaining": max(0, int(value.get("budgets", {}).get("attempts_per_stop", 3)) - pea_attempts),
        "tank_pea_active_seconds_used": round(pea_seconds, 3),
        "tank_pea_effective_limit_seconds": pea_effective_limit,
        "tank_pea_active_seconds_remaining": round(max(0, pea_effective_limit - pea_seconds), 3),
        "offline_remaining_seconds": round(offline_remaining, 3) if offline_remaining is not None else None,
        "d122_partitions_seconds": ({name: {"limit": limit,
            "spent": d122_partition_spent(value, name),
            "remaining": round(max(0.0, limit - d122_partition_spent(value, name)), 3)}
            for name, limit in {"observer_builds": D122_BUILD_PARTITION_SECONDS,
                                "observer_proofs": D122_PROOF_PARTITION_SECONDS,
                                "14_processes": D122_PROCESS_PARTITION_SECONDS,
                                "14_other": D122_OTHER_PARTITION_SECONDS}.items()}
            if d122 is not None else None),
        "observer_build_seconds_spent": round(sum(_numeric(row.get("observer_active_seconds", 0), "observer-build-seconds")
                                                    for row in observer_records if row.get("observer_activity_kind") == "build"), 3),
        "observer_proof_seconds_spent": round(sum(_numeric(row.get("observer_active_seconds", 0), "observer-proof-seconds")
                                                    for row in observer_records if row.get("observer_activity_kind") == "proof"), 3),
        "reserved_process_rows": sum(int(row.get("process_count", 0)) for row in reserved),
        "reserved_case_rows": sum(int(row.get("case_count", 0)) for row in reserved),
        "authorization_reservations": len(reserved),
        "historical_binding_rec_halt": bool(value.get("halt", {}).get("binding")),
        "d124_accounting": d124_report,
        "launches": 0,
        "read_only": True,
    }
