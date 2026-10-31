#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert, exact-byte-bound preparation for the Phase 7 two-wrapper diagnostic."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-13-ADMISSION.json"
PROTOCOL = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-13-PROTOCOL.md"
EVIDENCE = ROOT / "build/v02/recovery13/contract-evidence.json"
SCHEMA = "genewhip-wrapper-diagnostic-admission-v1"
SELECTION_SCHEMA = "genewhip-wrapper-diagnostic-selection-v1"
ORIGINAL_CUTOFF = "2026-10-30T12:02:07.199751+00:00"
SOURCE_PATHS = (
    "tests/evidence/phase7_wrapper_diagnostic.py",
    "tests/evidence/phase7_wrapper_diagnostic_contract.py",
    "tests/session/phase6_route_contract.py",
    "tests/fixtures/phase6_game.py",
    "scripts/release/v02_qualification.py",
    "scripts/evidence/phase5_process.py",
    "tests/evidence/phase7_sticky_denial.py",
    "tests/evidence/phase7_rss_contract.py",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_pins() -> dict[str, str]:
    return {name: sha256((ROOT / name).read_bytes()) for name in SOURCE_PATHS}


def interpreter_pin() -> dict[str, object]:
    executable = Path(sys.executable).resolve()
    return {"implementation": sys.implementation.name,
        "version": platform.python_version(), "cache_tag": sys.implementation.cache_tag,
        "executable_basename": executable.name,
        "executable_sha256": sha256(executable.read_bytes()),
        "isolated_mode_required": True}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_hash(value: object) -> str:
    return sha256(canonical_bytes(value))


def packet_integrity(packet: dict) -> str:
    unsigned = {key: value for key, value in packet.items() if key != "integrity_sha256"}
    return canonical_hash(unsigned)


def load_packet(path: Path = PACKET) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("packet-object-required")
    return value


def validate_packet(packet: dict, *, verify_evidence: bool = True) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if packet.get("schema") != SCHEMA:
        errors.append("packet-schema")
    if packet.get("integrity_sha256") != packet_integrity(packet):
        errors.append("packet-integrity")
    if packet.get("protocol_sha256") != sha256(PROTOCOL.read_bytes()):
        errors.append("stale-protocol-pin")
    if packet.get("live_selected") is not False or packet.get("delivery_authorized") is not False:
        errors.append("authority-flags")
    if packet.get("historical", {}).get("identity_liveness") != "UNKNOWN":
        errors.append("historical-unknown-erased")
    if packet.get("historical", {}).get("delivery") != "halted":
        errors.append("delivery-halt-erased")
    window = packet.get("original_window", {})
    if window.get("global_cutoff") != ORIGINAL_CUTOFF:
        errors.append("original-window-changed")
    if type(window.get("expired_by_seconds")) not in (int, float) or window.get("expired_by_seconds", 0) <= 0:
        errors.append("original-window-not-expired")
    cases = packet.get("cases")
    if cases != [] or packet.get("status") != "rejected-zero-case-admission":
        errors.append("admission-not-rejected-zero-case")
    if not packet.get("rejection", {}).get("reason") or packet.get("rejection", {}).get("status_helper_processes_bounded") is not False:
        errors.append("rejection-rationale")
    topology = packet.get("topology", {})
    if topology.get("admitted_process_starts") != 0 or topology.get("admitted_wrapper_calls") != 0:
        errors.append("rejected-topology-not-zero")
    if not isinstance(packet.get("source_sha256"), dict) or set(packet["source_sha256"]) != set(SOURCE_PATHS):
        errors.append("source-pin-roster")
    else:
        for name, digest in packet["source_sha256"].items():
            if len(str(digest)) != 64 or sha256((ROOT / name).read_bytes()) != digest:
                errors.append("stale-source-pin:" + name)
    if packet.get("interpreter") != interpreter_pin():
        errors.append("interpreter-pin")
    budget = packet.get("budget")
    if not isinstance(budget, dict):
        errors.append("budget-object")
    else:
        aggregate = budget.get("aggregate", {})
        per_case = budget.get("per_case", {})
        required_positive = ("process_starts", "max_concurrent_processes", "wrapper_calls",
            "max_native_rss_samples", "max_proc_listpids_calls", "max_darwin_pid_visits",
            "max_darwin_getpgid_calls", "max_darwin_task_queries",
            "max_status_helper_processes", "max_poll_iterations",
            "status_output_bytes", "stdout_stderr_bytes", "json_bytes", "receipt_bytes",
            "scratch_bytes", "disk_bytes", "rss_bytes", "ordinary_work_seconds",
            "gate_wait_seconds", "cleanup_grace_seconds", "estimated_wall_seconds",
            "retained_failure_reserve_bytes")
        if aggregate.get("max_status_helper_processes") is not None:
            errors.append("unbounded-helper-not-marked")
        if aggregate.get("process_starts") != 0 or aggregate.get("wrapper_calls") != 0:
            errors.append("rejected-budget-not-zero")
        if not budget.get("uncertainties"):
            errors.append("uncertainties-missing")
    evidence = packet.get("evidence", {})
    if evidence.get("real_child_starts") != 0 or evidence.get("unexpected_denials") != 0:
        errors.append("denied-evidence-status")
    if evidence.get("fsync_return_claim") is not False or evidence.get("whole_call_deadline_claim") is not False:
        errors.append("unsupported-proof-claim")
    evidence_digest = evidence.get("sha256")
    if verify_evidence and (not isinstance(evidence_digest, str) or len(evidence_digest) != 64 or not EVIDENCE.is_file()):
        errors.append("denied-evidence-missing")
    elif verify_evidence and sha256(EVIDENCE.read_bytes()) != evidence_digest:
        errors.append("denied-evidence-stale")
    elif verify_evidence and not errors:
        try:
            receipt = json.loads(EVIDENCE.read_text(encoding="utf-8"))
            rows = {row.get("mode"): row for row in receipt.get("records", [])}
            tracer = rows.get("tracer", {}).get("tracer") or {}
            if receipt.get("schema") != "genewhip.phase7-wrapper-diagnostic-contract.v1":
                errors.append("denied-evidence-schema")
            if receipt.get("source_sha256") != packet.get("source_sha256"):
                errors.append("denied-evidence-source-pins")
            if set(rows) != {"tracer", "contracts"}:
                errors.append("denied-evidence-mode-roster")
            if any(row.get("tests_run", 0) <= 0 or row.get("failures") != 0 or row.get("errors") != 0
                   or row.get("unexpected_denials") != 0 for row in rows.values()):
                errors.append("denied-evidence-test-outcome")
            if (tracer.get("status") != "pass" or tracer.get("real_child_starts") != 0
                    or tracer.get("wrapper_reaches") != ["shared_launch", "_bounded_command"]
                    or tracer.get("rss_observations", 0) < 2):
                errors.append("denied-evidence-tracer-semantics")
        except (OSError, ValueError, TypeError):
            errors.append("denied-evidence-unreadable")
    if packet.get("review", {}).get("required") is not True:
        errors.append("review-required")
    return not errors, errors


def validate_selection(packet: dict, selection: object, *, packet_digest: str | None = None,
                       verify_evidence: bool = True) -> tuple[bool, list[str]]:
    errors: list[str] = []
    accepted, packet_errors = validate_packet(packet, verify_evidence=verify_evidence)
    if not accepted:
        errors.extend("packet:" + item for item in packet_errors)
    if not isinstance(selection, dict) or selection.get("schema") != SELECTION_SCHEMA:
        return False, errors + ["selection-required"]
    if packet_digest is None:
        errors.append("selection-packet-bytes-required")
    elif selection.get("packet_sha256") != packet_digest:
        errors.append("selection-packet-hash")
    if packet.get("status") == "rejected-zero-case-admission":
        errors.append("admission-rejected-zero-cases")
    if selection.get("live_selected") is not True or selection.get("delivery_authorized") is not False:
        errors.append("selection-authority")
    host = selection.get("actual_host_permission")
    if not isinstance(host, dict) or host.get("explicit_user_permission") is not True or not host.get("evidence_sha256"):
        errors.append("actual-host-permission-required")
    if selection.get("source_sha256") != packet.get("source_sha256"):
        errors.append("selection-source-pins")
    if selection.get("interpreter") != packet.get("interpreter"):
        errors.append("selection-interpreter-pin")
    if selection.get("case_ids") != [row["id"] for row in packet.get("cases", [])]:
        errors.append("selection-case-roster")
    return not errors, errors


def authorize_role(role: str, directory: str | None, case_id: str | None,
                   packet: dict | None, selection: dict | None, *, packet_digest: str | None = None,
                   verify_evidence: bool = True) -> None:
    if packet is None or selection is None:
        raise ValueError("selection-required")
    if packet.get("status") == "rejected-zero-case-admission":
        raise ValueError("admission-rejected-zero-cases")
    accepted, errors = validate_selection(packet, selection, packet_digest=packet_digest,
        verify_evidence=verify_evidence)
    if not accepted:
        raise ValueError("selection-rejected:" + ",".join(errors))
    if role not in ("owner", "observer", "leaf"):
        raise ValueError("role-rejected")
    allowed_cases = {row["id"] for row in packet["cases"]}
    if case_id not in allowed_cases:
        raise ValueError("case-identity-rejected")
    if directory is None:
        raise ValueError("owned-directory-required")
    target = Path(directory)
    if not target.is_absolute() or target.is_symlink() or not target.is_dir():
        raise ValueError("owned-directory-invalid")
    info = target.stat()
    if info.st_uid != os.getuid() or info.st_nlink < 1:
        raise ValueError("owned-directory-not-owned")
    raise ValueError("original-window-expired")


def run_denied_tracer() -> dict[str, object]:
    """Run existing actual-wrapper contracts under sticky denial; fakes own all effects."""
    path = ROOT / "tests/evidence/phase7_rss_contract.py"
    spec = importlib.util.spec_from_file_location("phase7_wrapper_diagnostic_rss_contract", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("rss-contract-loader-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fake_libproc = module.FakeLibProc
    fake_libproc_instances = []
    class CountingFakeLibProc(fake_libproc):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            fake_libproc_instances.append(self)
    module.FakeLibProc = CountingFakeLibProc
    selected = (
        (module.ActualWrapperTracer, "test_finite_measurement_flows_through_actual_shared_wrapper_and_receipt"),
        (module.ActualWrapperTracer, "test_coordinator_check_false_preserves_exit_policy_but_rejects_rss_failure"),
    )
    reached = []
    failures = []
    tests = 0
    observations = 0
    for cls, method in selected:
        result = module.run_one(cls, method)
        tests += result.testsRun
        observations += sum(len(instance.list_calls) // 2 for instance in fake_libproc_instances)
        fake_libproc_instances.clear()
        if result.wasSuccessful() and result.testsRun == 1:
            reached.append("shared_launch" if "shared_wrapper" in method else "_bounded_command")
        else:
            failures.extend(text for _, text in result.failures + result.errors)
    module.denial.self_test("after-diagnostic-restoration")
    reports = len(reached)
    return {"status": "pass" if not failures and reached == ["shared_launch", "_bounded_command"] else "fail",
        "wrapper_reaches": reached, "rss_observations": observations, "caller_reports": reports,
        "fake_process_starts": 3,
        "real_child_starts": 0, "tests_run": tests, "failures": failures,
        "unexpected_denials": module.denial.receipt()["unexpected_denials"],
        "production_import_in_prepare_only": False,
        "proof_limit": "fake process/native/status seams; no actual OS cleanup, fsync-return, or elapsed-time claim"}


def verify_packet(path: Path = PACKET) -> int:
    try:
        packet = load_packet(path)
        ok, errors = validate_packet(packet)
        review_path = ROOT / ".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery/07-13-REVIEW.md"
        if not review_path.is_file():
            errors.append("independent-review-missing")
        else:
            review = review_path.read_text(encoding="utf-8")
            blocks = re.findall(r"```json\s*(\{.*?\})\s*```", review, flags=re.S)
            try:
                review_record = json.loads(blocks[-1])
            except (IndexError, json.JSONDecodeError):
                review_record = {}
            if review_record.get("independent") is not True:
                errors.append("review-independence")
            if review_record.get("verdict") != "SECURED":
                errors.append("review-verdict")
            if review_record.get("packet_sha256") != sha256(path.read_bytes()):
                errors.append("review-packet-pin")
            if review_record.get("protocol_sha256") != sha256(PROTOCOL.read_bytes()):
                errors.append("review-protocol-pin")
            if review_record.get("source_sha256") != packet.get("source_sha256"):
                errors.append("review-source-pins")
            if review_record.get("evidence_sha256") != packet.get("evidence", {}).get("sha256"):
                errors.append("review-evidence-pin")
            if review_record.get("admission") != "rejected-zero-case" or review_record.get("unresolved_high_critical") != 0:
                errors.append("review-rejection-disposition")
        if errors:
            print("packet rejected: " + ", ".join(errors), file=sys.stderr)
            return 1
        print("packet and independent review verified")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print("packet rejected: " + type(error).__name__, file=sys.stderr)
        return 1


def prepare_only() -> int:
    accepted, errors = validate_packet(load_packet())
    if not accepted:
        print("inert preparation rejected: " + ", ".join(errors), file=sys.stderr)
        return 1
    print(json.dumps({"status": "rejected-zero-case-admission", "live_selected": False,
        "delivery_authorized": False, "admissible_cases": 0, "packet_sha256": sha256(PACKET.read_bytes()),
        "source_sha256": source_pins(), "real_child_starts": 0}, sort_keys=True))
    return 0


def entry_check(path: Path = PACKET) -> int:
    packet = load_packet(path)
    accepted, errors = validate_packet(packet)
    if not accepted:
        print("entry blocked: packet rejected: " + ", ".join(errors), file=sys.stderr)
        return 1
    print("entry blocked: admission-rejected-zero-cases; original-window-expired; cutoff=" + ORIGINAL_CUTOFF, file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--tracer", action="store_true")
    group.add_argument("--contracts", action="store_true")
    group.add_argument("--prepare-only", action="store_true")
    group.add_argument("--verify-packet", action="store_true")
    group.add_argument("--entry-check", action="store_true")
    group.add_argument("--run-selected", action="store_true")
    parser.add_argument("--packet", "--admission", dest="packet", type=Path, default=PACKET)
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--owner", nargs=2, metavar=("DIR", "CASE"))
    parser.add_argument("--observer", nargs=2, metavar=("DIR", "CASE"))
    parser.add_argument("--leaf", nargs=2, metavar=("DIR", "CASE"))
    args = parser.parse_args()
    if args.tracer:
        result = run_denied_tracer()
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "pass" and result["unexpected_denials"] == 0 else 1
    if args.contracts:
        print("contract tests are owned by phase7_wrapper_diagnostic_contract.py", file=sys.stderr)
        return 2
    if args.prepare_only:
        return prepare_only()
    if args.verify_packet:
        return verify_packet(args.packet)
    if args.entry_check:
        return entry_check(args.packet)
    roles = [(name, getattr(args, name)) for name in ("owner", "observer", "leaf") if getattr(args, name)]
    if len(roles) != 1 or args.selection is None:
        print("entry blocked: one role and a separate selection are required", file=sys.stderr)
        return 1
    try:
        role, values = roles[0]
        authorize_role(role, values[0], values[1], load_packet(args.packet),
                json.loads(args.selection.read_text()), packet_digest=sha256(args.packet.read_bytes()))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("entry blocked: " + str(error), file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
