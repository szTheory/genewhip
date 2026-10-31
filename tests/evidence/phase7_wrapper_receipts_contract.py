#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Static-only verifier for a source-grounded rejected receipt admission.

The Darwin RSS path lacks a practical source-enforced diagnostic envelope. This
module inspects source bytes and inert packet JSON only; it imports no
production module, creates no probe, and dispatches no role. Install and
self-test phase7_sticky_denial before importing this module.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / ".planning/quick/261029-txs-prepare-and-independently-review-a-benig"
SOURCE = ROOT / "tests/session/phase6_route_contract.py"
PROBE = ROOT / "tests/evidence/phase7_wrapper_receipts_probe.py"
RSS_BLOCKER = "darwin-proc-listpids-host-count-has-no-source-enforced-finite-cap"
EXPECTED_ENTRY_HEAD = "457175158ba8b2f41d9d28cca905b6551ed3f177"
HISTORICAL_ENTRY_ONLY = {".planning/STATE.md": "7fd64b3a61cb033426ffe81f0ed7457082c17f70d5db6c4c627ef5e30cd11733"}
PRESERVED_INITIAL_PINS_SHA256 = "1addd93770ec2224fb789cec6fe6c0aa2fb6b9d3724e384482d82345eeda46e0"
EXPECTED_SOURCE_KEYS = {
    ".planning/ROADMAP.md", ".planning/STATE.md", ".planning/config.json",
    ".planning/quick/261029-sm1-prepare-and-independently-review-a-benig/PROTOCOL.md",
    ".planning/quick/261029-t2k-bound-darwin-process-group-status-output/HANDOFF.md",
    ".planning/quick/261029-t2k-bound-darwin-process-group-status-output/PROTOCOL.md",
    ".planning/quick/261029-t2k-bound-darwin-process-group-status-output/SECURITY-REVIEW.md",
    "scripts/evidence/phase5_process.py", "scripts/release/v02_qualification.py",
    "tests/evidence/phase7_creation_receipts_contract.py",
    "tests/evidence/phase7_darwin_status_contract.py",
    "tests/evidence/phase7_sticky_denial.py", "tests/fixtures/phase6_game.py",
    "tests/session/phase6_route_contract.py",
}
EXPECTED_DIRTY_KEYS = {
    ".planning/forensics/report-20261025-191402.md",
    ".planning/milestones/v0.1-phases/GW-01-consumable-diagnostic-machine/01-RESEARCH.md",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-04-red-task1.json",
    ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-04-red-task2.json",
    ".planning/state.json",
}
EXPECTED_ENTRY_STATUS = [
    " M .planning/milestones/v0.1-phases/GW-01-consumable-diagnostic-machine/01-RESEARCH.md",
    " M .planning/state.json",
    "?? .planning/forensics/report-20261025-191402.md",
    "?? .planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-04-red-task1.json",
    "?? .planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-04-red-task2.json",
    "?? .planning/quick/261029-txs-prepare-and-independently-review-a-benig/261029-txs-PLAN.md",
]
EXPECTED_FINAL_KEYS = {
    ".planning/quick/261029-txs-prepare-and-independently-review-a-benig/ADMISSION.json",
    ".planning/quick/261029-txs-prepare-and-independently-review-a-benig/EVIDENCE.json",
    ".planning/quick/261029-txs-prepare-and-independently-review-a-benig/PROTOCOL.md",
    "tests/evidence/phase7_wrapper_receipts_contract.py",
}
EXPECTED_SOURCE_CHECK_KEYS = {
    "darwin_branch_reached", "host_count_query_reached", "host_count_sizes_array",
    "copied_pid_slice_iterated", "per_pid_native_query",
    "shared_launch_active_scope_passes_nonnull_limits",
    "bounded_command_passes_required_limits", "run_client_reaches_owned_helper",
    "owned_helper_inspects_in_poll_loop", "owned_helper_inspects_after_wait",
    "inspect_outputs_guards_rss_on_nonnull_limits",
}
EXPECTED_EVENT_TRIPLET = ["subprocess.Popen", "os.system", "os.killpg"]
EVIDENCE_SELF_TEST_LABELS = [
    "before-production-imports", "outer-before-contract-import",
    "contract-after-static-restoration",
]
CURRENT_RUN_SELF_TEST_LABELS = [
    "before-production-imports", "outer-before-contract-import",
]
EXPECTED_ADMISSION_KEYS = {
    "schema", "status", "live_selected", "admissible_cases", "runtime_evidence",
    "probe_created", "launch_command", "candidate", "blocker", "blocker_source",
    "historical_identity_liveness", "t_07_07", "delivery",
}
EXPECTED_EVIDENCE_KEYS = {
    "schema", "disposition", "reason", "source", "source_sha256",
    "reached_source_checks", "counterfactuals", "counterfactual_count",
    "runtime_roles_started", "darwin_status_queries", "signals_sent",
    "real_child_starts", "production_imports", "probe_created", "denial_receipt",
    "independent_review", "limitations",
}
EXPECTED_COUNTERFACTUALS = [
    {"name": "false-ready", "result": "rejected", "signature": "blocked-admission-not-zero-case-inert"},
    {"name": "missing-blocker", "result": "rejected", "signature": "blocked-admission-blocker-missing-or-invented"},
    {"name": "invented-numeric-cap", "result": "rejected", "signature": "unsupported-cap-must-not-be-accepted"},
    {"name": "runtime-settlement-label", "result": "rejected", "signature": "blocked-admission-claims-runtime-evidence"},
    {"name": "fake-fsync-proof", "result": "rejected", "signature": "unsupported-proof-label-must-not-be-accepted"},
    {"name": "forged-source-digest", "result": "rejected", "signature": "source-pin-content-mismatch"},
    {"name": "empty-source-roster", "result": "rejected", "signature": "source-pin-roster-invalid"},
    {"name": "empty-dirty-roster", "result": "rejected", "signature": "dirty-pin-roster-invalid"},
    {"name": "empty-entry-status", "result": "rejected", "signature": "entry-status-invalid"},
    {"name": "single-final-pin", "result": "rejected", "signature": "final-pin-roster-invalid"},
    {"name": "wrong-entry-head", "result": "rejected", "signature": "entry-head-invalid"},
    {"name": "stale-final-pin", "result": "rejected", "signature": "final-pin-content-mismatch"},
    {"name": "fabricated-runtime-counts", "result": "rejected", "signature": "evidence-runtime-count-nonzero"},
    {"name": "empty-reached-source-roster", "result": "rejected", "signature": "evidence-source-check-roster-invalid"},
    {"name": "dirty-denial-receipt", "result": "rejected", "signature": "dirty-sticky-denial-ledger"},
    {"name": "missing-evidence-control", "result": "rejected", "signature": "evidence-counterfactual-roster-invalid"},
    {"name": "forged-guard-identity", "result": "rejected", "signature": "denial-self-test-identities-invalid"},
    {"name": "stale-evidence-source", "result": "rejected", "signature": "evidence-source-pin-stale"},
    {"name": "rss-call-severed", "result": "rejected", "signature": "rss-blocker-source-reachability-changed"},
    {"name": "actual-wrapper-limits-severed", "result": "rejected", "signature": "rss-blocker-source-reachability-changed"},
    {"name": "post-wait-inspection-severed", "result": "rejected", "signature": "rss-blocker-source-reachability-changed"},
]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _assert_rejected_admission(admission: object) -> None:
    if not isinstance(admission, dict):
        raise ValueError("admission-not-object")
    if "blocker" not in admission:
        raise ValueError("blocked-admission-blocker-missing-or-invented")
    if admission.get("pid_cap") is not None:
        raise ValueError("unsupported-cap-must-not-be-accepted")
    if admission.get("fsync_return_observed") is True:
        raise ValueError("unsupported-proof-label-must-not-be-accepted")
    if set(admission) != EXPECTED_ADMISSION_KEYS:
        raise ValueError("blocked-admission-schema-invalid")
    if (admission.get("schema") != "phase7-wrapper-receipts-admission-v1" or
            admission.get("status") != "rejected-inert" or
            admission.get("live_selected") is not False or
            type(admission.get("admissible_cases")) is not int or admission["admissible_cases"] != 0):
        raise ValueError("blocked-admission-not-zero-case-inert")
    if admission.get("blocker") != RSS_BLOCKER:
        raise ValueError("blocked-admission-blocker-missing-or-invented")
    if any(admission.get(key) is not None for key in ("launch_command", "candidate")):
        raise ValueError("blocked-admission-contains-executable-candidate")
    if (admission.get("runtime_evidence") is not False or admission.get("probe_created") is not False):
        raise ValueError("blocked-admission-claims-runtime-evidence")
    if admission.get("historical_identity_liveness") != "UNKNOWN" or admission.get("t_07_07") != "OPEN/high" or admission.get("delivery") != "halted":
        raise ValueError("blocked-admission-history-or-halt-mutated")
    blocker_source = admission.get("blocker_source")
    if (not isinstance(blocker_source, dict) or
            blocker_source.get("path") != "tests/session/phase6_route_contract.py" or
            blocker_source.get("function") != "_process_group_rss_bytes" or
            blocker_source.get("reachable_from") != "_run_client_owned ordinary completion at line 926"):
        raise ValueError("blocked-admission-source-boundary-invalid")


def _validate_pins(pins: object) -> None:
    if not isinstance(pins, dict) or set(pins) != {
            "schema", "entry_head", "immutable_entry", "immutable_entry_canonical_sha256",
            "final_source_packet_sha256", "post_publication_historical_entry_paths"}:
        raise ValueError("entry-pins-schema-invalid")
    if pins.get("schema") != "phase7-wrapper-receipts-entry-pins-v1":
        raise ValueError("entry-pins-schema-invalid")
    if pins.get("entry_head") != EXPECTED_ENTRY_HEAD:
        raise ValueError("entry-head-invalid")
    if pins.get("post_publication_historical_entry_paths") != sorted(HISTORICAL_ENTRY_ONLY):
        raise ValueError("historical-entry-pin-policy-invalid")
    immutable = pins.get("immutable_entry")
    if not isinstance(immutable, dict) or set(immutable) != {
            "source_and_context_sha256", "preexisting_dirty_sha256", "entry_status"}:
        raise ValueError("immutable-entry-schema-invalid")
    source_hashes = immutable["source_and_context_sha256"]
    dirty_hashes = immutable["preexisting_dirty_sha256"]
    if not isinstance(source_hashes, dict) or set(source_hashes) != EXPECTED_SOURCE_KEYS:
        raise ValueError("source-pin-roster-invalid")
    if not isinstance(dirty_hashes, dict) or set(dirty_hashes) != EXPECTED_DIRTY_KEYS:
        raise ValueError("dirty-pin-roster-invalid")
    if immutable["entry_status"] != EXPECTED_ENTRY_STATUS:
        raise ValueError("entry-status-invalid")
    canonical = hashlib.sha256(json.dumps(immutable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if pins.get("immutable_entry_canonical_sha256") != canonical:
        raise ValueError("immutable-entry-pin-digest-invalid")
    for roster, hashes in (("source", source_hashes), ("dirty", dirty_hashes)):
        for relative, expected in hashes.items():
            path = ROOT / relative
            if not _digest(expected):
                raise ValueError(roster + "-pin-digest-invalid:" + relative)
            if not path.is_file():
                raise ValueError(roster + "-pin-artifact-missing:" + relative)
            if roster == "source" and relative in HISTORICAL_ENTRY_ONLY:
                if expected != HISTORICAL_ENTRY_ONLY[relative]:
                    raise ValueError("historical-entry-pin-invalid:" + relative)
                preserved = PACKET / "history/initial-packet/ENTRY-PINS.json"
                if not preserved.is_file() or _sha(preserved) != PRESERVED_INITIAL_PINS_SHA256:
                    raise ValueError("historical-entry-source-record-invalid")
                original = json.loads(preserved.read_text())
                original_hash = original.get("immutable_entry", {}).get("source_and_context_sha256", {}).get(relative)
                if original_hash != expected:
                    raise ValueError("historical-entry-source-record-mismatch")
                continue
            if _sha(path) != expected:
                raise ValueError(roster + "-pin-content-mismatch:" + relative)
    final = pins.get("final_source_packet_sha256")
    if not isinstance(final, dict) or set(final) != EXPECTED_FINAL_KEYS:
        raise ValueError("final-pin-roster-invalid")
    for relative, expected in final.items():
        path = ROOT / relative
        if not _digest(expected):
            raise ValueError("final-pin-digest-invalid:" + relative)
        if not path.is_file():
            raise ValueError("final-pin-artifact-missing:" + relative)
        if _sha(path) != expected:
            raise ValueError("final-pin-content-mismatch:" + relative)


def _function(tree: ast.AST, name: str) -> ast.FunctionDef:
    node = next((item for item in ast.walk(tree) if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name), None)
    if not isinstance(node, ast.FunctionDef):
        raise ValueError("source-function-missing:" + name)
    return node


def _calls(node: ast.AST, name: str) -> list[ast.Call]:
    found = []
    for item in ast.walk(node):
        if not isinstance(item, ast.Call):
            continue
        called = item.func.id if isinstance(item.func, ast.Name) else (item.func.attr if isinstance(item.func, ast.Attribute) else None)
        if called == name:
            found.append(item)
    return found


def _passes_limits(call: ast.Call) -> bool:
    return any(keyword.arg == "limits" and isinstance(keyword.value, ast.Name) and keyword.value.id == "limits" for keyword in call.keywords)


def _guard_contains_call(node: ast.AST, guard: str, called: str) -> bool:
    return any(isinstance(item, ast.If) and guard in ast.unparse(item.test) and _calls(item, called)
               for item in ast.walk(node))


def _inspect_source(source: bytes, shared_source: bytes, coordinator_source: bytes) -> dict[str, bool]:
    tree = ast.parse(source, filename=SOURCE.as_posix())
    shared_tree = ast.parse(shared_source, filename="tests/fixtures/phase6_game.py")
    coordinator_tree = ast.parse(coordinator_source, filename="scripts/release/v02_qualification.py")
    rss_helper = _function(tree, "_process_group_rss_bytes")
    rss_text = ast.unparse(rss_helper)
    owned = _function(tree, "_run_client_owned")
    run_client = _function(tree, "_run_client")
    shared_launch = _function(shared_tree, "shared_launch")
    bounded_command = _function(coordinator_tree, "_bounded_command")
    inspect = next((node for node in ast.walk(owned) if isinstance(node, ast.FunctionDef) and node.name == "inspect_outputs"), None)
    if inspect is None:
        raise ValueError("source-function-missing:inspect_outputs")
    inspect_text = ast.unparse(inspect)
    owned_text = ast.unparse(owned)
    shared_text = ast.unparse(shared_launch)
    bounded_text = ast.unparse(bounded_command)
    run_client_text = ast.unparse(run_client)
    checks = {
        "darwin_branch_reached": "sys.platform == 'darwin'" in rss_text,
        "host_count_query_reached": "proc_listpids(1, 0, None, 0)" in rss_text,
        "host_count_sizes_array": "count // ctypes.sizeof(ctypes.c_int) + 16" in rss_text,
        "copied_pid_slice_iterated": "pids[:copied // ctypes.sizeof(ctypes.c_int)]" in rss_text,
        "per_pid_native_query": "proc_pidinfo(pid, 4, 0, task_info, len(task_info))" in rss_text,
        "shared_launch_active_scope_passes_nonnull_limits": (
            "_EXECUTION_SCOPE.get('per_child_limits')" in shared_text and
            "not isinstance(limits, dict)" in shared_text and
            _guard_contains_call(shared_launch, "_EXECUTION_SCOPE is not None", "_run_client") and
            any(_passes_limits(call) for call in _calls(shared_launch, "_run_client"))),
        "bounded_command_passes_required_limits": (
            "limits['wall_seconds']" in bounded_text and
            any(_passes_limits(call) for call in _calls(bounded_command, "_run_client"))),
        "run_client_reaches_owned_helper": (
            any(call.func.id == "_run_client_owned" for call in _calls(run_client, "_run_client_owned")) and
            "_ownership_callback=record_ownership" in run_client_text),
        "owned_helper_inspects_in_poll_loop": any(
            isinstance(node, ast.While) and "process.poll()" in ast.unparse(node.test) and
            any(call.func.id == "inspect_outputs" for call in _calls(node, "inspect_outputs"))
            for node in ast.walk(owned) if isinstance(node, ast.While)),
        "owned_helper_inspects_after_wait": (
            any("process.wait(timeout=5)" in ast.unparse(node) for node in ast.walk(owned)) and
            len(_calls(owned, "inspect_outputs")) >= 2 and
            max(call.lineno for call in _calls(owned, "inspect_outputs")) >
            max(call.lineno for call in ast.walk(owned) if isinstance(call, ast.Call) and
                isinstance(call.func, ast.Attribute) and call.func.attr == "wait" and
                isinstance(call.func.value, ast.Name) and call.func.value.id == "process")),
        "inspect_outputs_guards_rss_on_nonnull_limits": (
            _guard_contains_call(inspect, "limits is not None", "_process_group_rss_bytes")),
    }
    if set(checks) != EXPECTED_SOURCE_CHECK_KEYS or not all(checks.values()):
        raise ValueError("rss-blocker-source-reachability-changed")
    return checks


def _expected_evidence(admission: dict, pins: dict, source_checks: dict[str, bool], receipt: dict) -> dict:
    return {
        "schema": "phase7-wrapper-receipts-evidence-v1", "disposition": "static-only-rejected",
        "reason": RSS_BLOCKER, "source": "tests/session/phase6_route_contract.py",
        "source_sha256": _sha(SOURCE), "reached_source_checks": source_checks,
        "counterfactuals": EXPECTED_COUNTERFACTUALS, "counterfactual_count": len(EXPECTED_COUNTERFACTUALS),
        "runtime_roles_started": 0, "darwin_status_queries": 0, "signals_sent": 0,
        "real_child_starts": 0, "production_imports": 0, "probe_created": False,
        "denial_receipt": receipt, "independent_review": "pending-independent-review",
        "limitations": [
            "Static source reachability only; no Darwin host measurement.",
            "No whole-call wall, OS containment, settlement, or fsync-return proof.",
            "Historical identity/liveness remains UNKNOWN; T-07-07 remains OPEN/high.",
        ],
    }


def _validate_guard_receipt(receipt: object, labels: list[str]) -> None:
    if not isinstance(receipt, dict) or receipt.get("unexpected_denials") != 0:
        raise ValueError("dirty-sticky-denial-ledger")
    if set(receipt) != {"audit_events", "counterfactual_denials", "real_child_starts", "self_test_denials", "self_tests", "unexpected_denials"}:
        raise ValueError("denial-ledger-schema-invalid")
    tests = receipt.get("self_tests")
    if not isinstance(tests, list) or [row.get("label") for row in tests if isinstance(row, dict)] != labels:
        raise ValueError("denial-self-test-identities-invalid")
    if any(row.get("events") != EXPECTED_EVENT_TRIPLET for row in tests if isinstance(row, dict)):
        raise ValueError("denial-self-test-events-invalid")
    expected_events = len(labels) * len(EXPECTED_EVENT_TRIPLET)
    if (receipt.get("audit_events") != expected_events or receipt.get("self_test_denials") != expected_events or
            receipt.get("counterfactual_denials") != 0 or receipt.get("real_child_starts") != 0):
        raise ValueError("denial-ledger-counts-invalid")


def _validate_evidence(evidence: object, admission: dict, pins: dict) -> None:
    if not isinstance(evidence, dict) or set(evidence) != EXPECTED_EVIDENCE_KEYS:
        raise ValueError("evidence-schema-or-roster-invalid")
    if evidence.get("disposition") != "static-only-rejected" or evidence.get("reason") != RSS_BLOCKER:
        raise ValueError("evidence-disposition-invalid")
    for field in ("runtime_roles_started", "darwin_status_queries", "signals_sent", "real_child_starts", "production_imports"):
        if type(evidence.get(field)) is not int or evidence[field] != 0:
            raise ValueError("evidence-runtime-count-nonzero")
    if evidence.get("probe_created") is not False:
        raise ValueError("evidence-runtime-count-nonzero")
    if evidence.get("source") != "tests/session/phase6_route_contract.py" or evidence.get("source_sha256") != _sha(SOURCE):
        raise ValueError("evidence-source-pin-stale")
    checks = evidence.get("reached_source_checks")
    if not isinstance(checks, dict) or set(checks) != EXPECTED_SOURCE_CHECK_KEYS or any(value is not True for value in checks.values()):
        raise ValueError("evidence-source-check-roster-invalid")
    if evidence.get("counterfactual_count") != len(EXPECTED_COUNTERFACTUALS) or evidence.get("counterfactuals") != EXPECTED_COUNTERFACTUALS:
        raise ValueError("evidence-counterfactual-roster-invalid")
    _validate_guard_receipt(evidence.get("denial_receipt"), EVIDENCE_SELF_TEST_LABELS)
    if evidence.get("independent_review") != "pending-independent-review":
        raise ValueError("evidence-independent-review-status-invalid")
    if evidence.get("limitations") != [
            "Static source reachability only; no Darwin host measurement.",
            "No whole-call wall, OS containment, settlement, or fsync-return proof.",
            "Historical identity/liveness remains UNKNOWN; T-07-07 remains OPEN/high."]:
        raise ValueError("evidence-limitations-invalid")
    if admission.get("live_selected") is not False or admission.get("admissible_cases") != 0:
        raise ValueError("evidence-admission-not-inert")
    if not isinstance(pins, dict):
        raise ValueError("evidence-pins-not-validated")


def _expected_signature(fn, value: object, expected: str) -> None:
    try:
        fn(value)
    except ValueError as error:
        if str(error).startswith(expected):
            return
        raise AssertionError("counterfactual-wrong-rejection:" + expected + ":" + str(error)) from error
    raise AssertionError("counterfactual-accepted:" + expected)


def _counterfactuals(admission: dict, pins: dict, evidence: dict,
                     source: bytes, shared_source: bytes, coordinator_source: bytes) -> list[dict[str, str]]:
    outcomes = []

    def record(name: str, fn, value: object, signature: str) -> None:
        _expected_signature(fn, value, signature)
        outcomes.append({"name": name, "result": "rejected", "signature": signature})

    for name, mutate, signature in [
            ("false-ready", lambda v: v.update(status="prepared-inert"), "blocked-admission-not-zero-case-inert"),
            ("missing-blocker", lambda v: v.pop("blocker"), "blocked-admission-blocker-missing-or-invented"),
            ("invented-numeric-cap", lambda v: v.update(pid_cap=4096), "unsupported-cap-must-not-be-accepted"),
            ("runtime-settlement-label", lambda v: v.update(runtime_evidence=True), "blocked-admission-claims-runtime-evidence"),
            ("fake-fsync-proof", lambda v: v.update(fsync_return_observed=True), "unsupported-proof-label-must-not-be-accepted")]:
        candidate = dict(admission)
        mutate(candidate)
        record(name, _assert_rejected_admission, candidate, signature)

    for name, mutate, signature in [
            ("forged-source-digest", lambda v: v["immutable_entry"]["source_and_context_sha256"].__setitem__("tests/session/phase6_route_contract.py", "0" * 64), "source-pin-content-mismatch"),
            ("empty-source-roster", lambda v: v["immutable_entry"].update(source_and_context_sha256={}), "source-pin-roster-invalid"),
            ("empty-dirty-roster", lambda v: v["immutable_entry"].update(preexisting_dirty_sha256={}), "dirty-pin-roster-invalid"),
            ("empty-entry-status", lambda v: v["immutable_entry"].update(entry_status=[]), "entry-status-invalid"),
            ("single-final-pin", lambda v: v.update(final_source_packet_sha256={next(iter(EXPECTED_FINAL_KEYS)): "0" * 64}), "final-pin-roster-invalid"),
            ("wrong-entry-head", lambda v: v.update(entry_head="0" * 40), "entry-head-invalid"),
            ("stale-final-pin", lambda v: v["final_source_packet_sha256"].__setitem__(next(iter(EXPECTED_FINAL_KEYS)), "0" * 64), "final-pin-content-mismatch")]:
        candidate = json.loads(json.dumps(pins))
        mutate(candidate)
        immutable = candidate["immutable_entry"]
        candidate["immutable_entry_canonical_sha256"] = hashlib.sha256(json.dumps(immutable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        record(name, _validate_pins, candidate, signature)

    for name, mutate, signature in [
            ("fabricated-runtime-counts", lambda v: v.update(production_imports=7, runtime_roles_started=2, darwin_status_queries=4, signals_sent=8, probe_created=True), "evidence-runtime-count-nonzero"),
            ("empty-reached-source-roster", lambda v: v.update(reached_source_checks={}), "evidence-source-check-roster-invalid"),
            ("dirty-denial-receipt", lambda v: v["denial_receipt"].update(unexpected_denials=99), "dirty-sticky-denial-ledger"),
            ("missing-evidence-control", lambda v: v["counterfactuals"].pop(), "evidence-counterfactual-roster-invalid"),
            ("forged-guard-identity", lambda v: v["denial_receipt"]["self_tests"][0].update(label="forged"), "denial-self-test-identities-invalid"),
            ("stale-evidence-source", lambda v: v.update(source_sha256="0" * 64), "evidence-source-pin-stale")]:
        candidate = json.loads(json.dumps(evidence))
        mutate(candidate)
        record(name, lambda x: _validate_evidence(x, admission, pins), candidate, signature)
    mutants = [
        ("rss-call-severed", source.replace(
            b"actual = libproc.proc_pidinfo(pid, 4, 0, task_info, len(task_info))",
            b"actual = libproc.proc_pidinfo_removed(pid, 4, 0, task_info, len(task_info))", 1),
         source, shared_source),
        ("actual-wrapper-limits-severed", shared_source.replace(
            b"monitored_directories=directories, limits=limits,",
            b"monitored_directories=directories, limits=None,", 1),
         source, None),
        ("post-wait-inspection-severed", source.replace(
            b"                inspect_outputs()\n                for path, ceiling in monitored_files:",
            b"                # inspection removed by counterfactual\n                for path, ceiling in monitored_files:", 1),
         source, shared_source),
    ]
    for name, mutant, base_source, base_shared in mutants:
        if mutant == base_source if base_shared is not None else mutant == shared_source:
            raise AssertionError("source-counterfactual-mutation-not-applied:" + name)
        try:
            _inspect_source(mutant if base_shared is not None else base_source,
                            mutant if base_shared is None else base_shared, coordinator_source)
        except ValueError as error:
            if str(error) != "rss-blocker-source-reachability-changed":
                raise AssertionError("source-counterfactual-wrong-rejection:" + name + ":" + str(error)) from error
            outcomes.append({"name": name, "result": "rejected", "signature": "rss-blocker-source-reachability-changed"})
        else:
            raise AssertionError("source-counterfactual-accepted:" + name)
    if outcomes != EXPECTED_COUNTERFACTUALS:
        raise AssertionError("counterfactual-roster-does-not-match-independent-expected-list")
    return outcomes


def _production_modules_loaded() -> list[str]:
    paths = {
        SOURCE.resolve(), (ROOT / "tests/fixtures/phase6_game.py").resolve(),
        (ROOT / "scripts/release/v02_qualification.py").resolve(),
    }
    loaded = []
    for name, module in tuple(sys.modules.items()):
        filename = getattr(module, "__file__", None)
        if filename is not None:
            try:
                if Path(filename).resolve() in paths:
                    loaded.append(name)
            except OSError:
                continue
    return sorted(loaded)


def _current_denial(denial, expected_labels: list[str]) -> dict:
    receipt = denial.receipt()
    _validate_guard_receipt(receipt, expected_labels)
    return receipt


def _artifact_inputs() -> tuple[dict, dict, dict]:
    pins = json.loads((PACKET / "ENTRY-PINS.json").read_text())
    _validate_pins(pins)
    admission = json.loads((PACKET / "ADMISSION.json").read_text())
    _assert_rejected_admission(admission)
    evidence = json.loads((PACKET / "EVIDENCE.json").read_text())
    _validate_evidence(evidence, admission, pins)
    return pins, admission, evidence


def offline_main(argv: list[str] | None = None) -> int:
    """Run guarded source/packet checks; all modes remain static-only."""
    args = list(sys.argv[1:] if argv is None else argv)
    allowed = {"--tracer", "--write-evidence", "--pre-review", "--verify-artifacts", "--dirty-ledger-regression"}
    if not args or any(arg not in allowed for arg in args):
        print("unknown-or-empty-offline-mode", file=sys.stderr)
        return 2
    if "--pre-review" in args and "--write-evidence" not in args:
        print("pre-review-requires-evidence-freeze", file=sys.stderr)
        return 2
    try:
        import phase7_sticky_denial as denial
        if not getattr(denial, "INSTALLED", False):
            raise ValueError("sticky-denial-not-installed-before-contract")
        if _production_modules_loaded():
            raise ValueError("production-module-import-detected")
        if PROBE.exists():
            raise ValueError("probe-file-present-in-rejected-branch")

        if "--dirty-ledger-regression" in args:
            before = _sha(PACKET / "EVIDENCE.json")
            try:
                denial.os.system("/__gw_txs_denied_counterfactual__")
            except PermissionError as error:
                if str(error) != "sticky-process-and-signal-denial":
                    raise ValueError("dirty-ledger-regression-wrong-denial") from error
            else:
                raise ValueError("dirty-ledger-regression-not-denied")
            pins, admission, evidence = _artifact_inputs()
            try:
                _validate_evidence(evidence, admission, pins)
                _current_denial(denial, CURRENT_RUN_SELF_TEST_LABELS)
            except ValueError as error:
                if str(error) != "dirty-sticky-denial-ledger":
                    raise AssertionError("dirty-ledger-regression-wrong-signature:" + str(error)) from error
            else:
                raise AssertionError("dirty-ledger-regression-accepted")
            if _sha(PACKET / "EVIDENCE.json") != before:
                raise AssertionError("dirty-ledger-regression-froze-evidence")
            print("dirty-sticky-denial-ledger; evidence-freeze=unchanged")
            return 0

        admission = json.loads((PACKET / "ADMISSION.json").read_text())
        _assert_rejected_admission(admission)
        source_checks = _inspect_source(
            SOURCE.read_bytes(), (ROOT / "tests/fixtures/phase6_game.py").read_bytes(),
            (ROOT / "scripts/release/v02_qualification.py").read_bytes())
        if "--verify-artifacts" in args:
            pins, admission, evidence = _artifact_inputs()
            current = _current_denial(denial, CURRENT_RUN_SELF_TEST_LABELS)
            _validate_evidence(evidence, admission, pins)
            if _counterfactuals(admission, pins, evidence, SOURCE.read_bytes(),
                    (ROOT / "tests/fixtures/phase6_game.py").read_bytes(),
                    (ROOT / "scripts/release/v02_qualification.py").read_bytes()) != EXPECTED_COUNTERFACTUALS:
                raise ValueError("counterfactual-roster-invalid")
            if current.get("unexpected_denials") != 0:
                raise ValueError("dirty-sticky-denial-ledger")
            print(f"static-artifacts-verified; counterfactuals={len(EXPECTED_COUNTERFACTUALS)}; real_child_starts=0")
            return 0

        outcomes = EXPECTED_COUNTERFACTUALS
        denial.self_test("contract-after-static-restoration")
        receipt = _current_denial(denial, EVIDENCE_SELF_TEST_LABELS)
        pins = json.loads((PACKET / "ENTRY-PINS.json").read_text())
        _validate_pins(pins)
        evidence = _expected_evidence(admission, pins, source_checks, receipt)
        _validate_evidence(evidence, admission, pins)
        _counterfactuals(admission, pins, evidence, SOURCE.read_bytes(),
            (ROOT / "tests/fixtures/phase6_game.py").read_bytes(),
            (ROOT / "scripts/release/v02_qualification.py").read_bytes())
        if "--write-evidence" in args:
            (PACKET / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"status": "rejected-static-only", "source_checks": len(source_checks),
                          "counterfactuals": len(outcomes), "real_child_starts": 0}, sort_keys=True))
        return 0
    except (OSError, ValueError, AssertionError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(offline_main())
