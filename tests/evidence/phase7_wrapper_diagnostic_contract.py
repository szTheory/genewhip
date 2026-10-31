#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Denied source-bound contracts for the Phase 7 wrapper diagnostic packet."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
DIAGNOSTIC = ROOT / "tests/evidence/phase7_wrapper_diagnostic.py"
EVIDENCE = ROOT / "build/v02/recovery13/contract-evidence.json"
LAST_TRACER_RESULT: dict[str, object] = {}
def load_diagnostic():
    spec = importlib.util.spec_from_file_location("phase7_wrapper_diagnostic_contract_target", DIAGNOSTIC)
    if spec is None or spec.loader is None:
        raise RuntimeError("diagnostic-loader-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TracerContract(unittest.TestCase):
    def test_inert_tracer_reaches_both_real_wrappers_and_helper(self):
        result = load_diagnostic().run_denied_tracer()
        LAST_TRACER_RESULT.update(result)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["real_child_starts"], 0)
        self.assertEqual(result["wrapper_reaches"], ["shared_launch", "_bounded_command"])
        self.assertGreaterEqual(result["rss_observations"], 4)
        self.assertEqual(result["caller_reports"], 2)
        self.assertEqual(result["unexpected_denials"], 0)


class PacketContract(unittest.TestCase):
    def test_packet_is_concretely_rejected_with_zero_admitted_cases(self):
        diagnostic = load_diagnostic()
        packet = diagnostic.load_packet()
        accepted, reasons = diagnostic.validate_packet(packet, verify_evidence=False)
        self.assertTrue(accepted, reasons)
        self.assertEqual(packet["live_selected"], False)
        self.assertEqual(packet["delivery_authorized"], False)
        self.assertEqual(packet["cases"], [])
        self.assertEqual(packet["status"], "rejected-zero-case-admission")
        self.assertEqual(packet["budget"]["aggregate"]["process_starts"], 0)
        self.assertIsNone(packet["budget"]["aggregate"]["max_status_helper_processes"])
        self.assertTrue(packet["budget"]["uncertainties"])

    def test_selection_is_separate_hash_bound_and_denied_without_host_permission(self):
        diagnostic = load_diagnostic()
        packet = diagnostic.load_packet()
        selection = {"schema": diagnostic.SELECTION_SCHEMA,
            "packet_sha256": diagnostic.sha256(diagnostic.PACKET.read_bytes()),
            "live_selected": True, "delivery_authorized": False,
            "actual_host_permission": {"explicit_user_permission": True, "evidence_sha256": "a" * 64},
            "source_sha256": packet["source_sha256"], "interpreter": packet["interpreter"],
            "case_ids": [row["id"] for row in packet["cases"]]}
        packet_digest = diagnostic.sha256(diagnostic.PACKET.read_bytes())
        accepted, errors = diagnostic.validate_selection(packet, selection, packet_digest=packet_digest,
            verify_evidence=False)
        self.assertFalse(accepted)
        self.assertIn("admission-rejected-zero-cases", errors)
        stale = dict(selection, packet_sha256="0" * 64)
        self.assertIn("selection-packet-hash", diagnostic.validate_selection(packet, stale,
            packet_digest=packet_digest, verify_evidence=False)[1])
        reserialized = json.dumps(packet, sort_keys=True).encode("utf-8")
        self.assertNotEqual(diagnostic.sha256(reserialized), packet_digest)
        self.assertIn("selection-packet-hash", diagnostic.validate_selection(packet, selection,
            packet_digest=diagnostic.sha256(reserialized), verify_evidence=False)[1])
        missing_host = dict(selection, actual_host_permission=None)
        self.assertIn("actual-host-permission-required", diagnostic.validate_selection(packet, missing_host,
            packet_digest=packet_digest, verify_evidence=False)[1])
        with self.assertRaisesRegex(ValueError, "admission-rejected-zero-cases"):
            diagnostic.authorize_role("owner", str(ROOT), "shared-launch", packet, selection,
                packet_digest=packet_digest, verify_evidence=False)

    def test_role_launch_requires_exact_packet_and_selection(self):
        diagnostic = load_diagnostic()
        with self.assertRaisesRegex(ValueError, "selection-required"):
            diagnostic.authorize_role("owner", None, None, None, None)

    def test_recomputed_digest_semantic_mutants_reject_at_intended_contract(self):
        diagnostic = load_diagnostic()
        base = diagnostic.load_packet()
        mutants = (
            ("wrong-status", lambda p: p.update(status="proposed"), "admission-not-rejected-zero-case"),
            ("nonzero-topology", lambda p: p["topology"].update(admitted_process_starts=1), "rejected-topology-not-zero"),
            ("unbounded-status-hidden", lambda p: p["budget"]["aggregate"].update(max_status_helper_processes=8), "unbounded-helper-not-marked"),
            ("stale-protocol", lambda p: p.update(protocol_sha256="0" * 64), "stale-protocol-pin"),
            ("missing-rejection-reason", lambda p: p["rejection"].update(reason=""), "rejection-rationale"),
            ("stale-source-pin", lambda p: p["source_sha256"].update({"tests/session/phase6_route_contract.py": "0" * 64}), "stale-source-pin:tests/session/phase6_route_contract.py"),
            ("unexpected-denial", lambda p: p["evidence"].update(unexpected_denials=1), "denied-evidence-status"),
            ("wrong-authority", lambda p: p.update(live_selected=True), "authority-flags"),
        )
        for name, mutate, expected in mutants:
            with self.subTest(name=name):
                mutant = json.loads(json.dumps(base))
                mutate(mutant)
                mutant["integrity_sha256"] = diagnostic.packet_integrity(mutant)
                accepted, errors = diagnostic.validate_packet(mutant, verify_evidence=False)
                self.assertFalse(accepted, name)
                self.assertIn(expected, errors, name)


def write_evidence(mode: str, result: unittest.TestResult) -> bool:
    diagnostic = load_diagnostic()
    pins = diagnostic.source_pins()
    payload = {"schema": "genewhip.phase7-wrapper-diagnostic-contract.v1", "mode": mode,
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "unexpected_denials": int(LAST_TRACER_RESULT.get("unexpected_denials", 0)),
        "real_child_starts": 0, "source_sha256": pins,
        "tracer": LAST_TRACER_RESULT or None}
    if result.failures or result.errors or payload["unexpected_denials"]:
        return False
    records = []
    if EVIDENCE.is_file():
        try:
            previous = json.loads(EVIDENCE.read_text(encoding="utf-8"))
            if previous.get("source_sha256") == pins:
                records = previous.get("records", [])
        except (OSError, ValueError):
            records = []
    records = [row for row in records if row.get("mode") != mode]
    records.append({"mode": mode, "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "unexpected_denials": payload["unexpected_denials"], "tracer": payload["tracer"]})
    payload["records"] = records
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--tracer", action="store_true")
    modes.add_argument("--tracer-worker", action="store_true")
    modes.add_argument("--contracts", action="store_true")
    modes.add_argument("--prepare-only", action="store_true")
    modes.add_argument("--verify-packet", action="store_true")
    modes.add_argument("--entry-check", action="store_true")
    parser.add_argument("--packet", type=Path)
    args = parser.parse_args()
    if args.tracer or args.contracts:
        selected = [TracerContract] if args.tracer else [PacketContract]
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(item) for item in selected)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if not write_evidence("tracer" if args.tracer else "contracts", result):
            return 1
        return 0 if result.wasSuccessful() else 1
    diagnostic = load_diagnostic()
    if args.tracer_worker:
        print(json.dumps(diagnostic.run_denied_tracer(), sort_keys=True))
        return 0
    if args.verify_packet:
        return diagnostic.verify_packet(args.packet or diagnostic.PACKET)
    if args.entry_check:
        return diagnostic.entry_check(args.packet or diagnostic.PACKET)
    if args.prepare_only:
        return diagnostic.prepare_only()
    parser.error("unreachable mode dispatch")


if __name__ == "__main__":
    raise SystemExit(main())
