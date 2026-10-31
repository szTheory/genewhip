#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Denied contracts for the one-shot Phase 7 attempt-4 diagnostic."""
from __future__ import annotations

import ast
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]

_denial_spec = importlib.util.spec_from_file_location(
    "wrapper16_sticky_denial", ROOT / "tests/evidence/phase7_sticky_denial.py")
denial = importlib.util.module_from_spec(_denial_spec)
_denial_spec.loader.exec_module(denial)
denial.install()

def load(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

runner = load("tests/evidence/phase7_wrapper_return.py", "wrapper16_runner")
coordinator = load("scripts/release/v02_qualification.py", "wrapper16_coordinator")

PHASE = Path(".planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery")

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def fixture(root: Path):
    shutil.copytree(ROOT / PHASE, root / PHASE)
    for relative in runner.SOURCES16:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    (root / "evidence").mkdir(exist_ok=True)
    shutil.copy2(ROOT / "evidence/v02-execution.json", root / "evidence/v02-execution.json")
    runtime = root / "build/v02"
    (runtime / "campaign15").mkdir(parents=True)
    for name in ("campaign.json", "attempt2-started.json", "attempt3-started.json"):
        shutil.copy2(ROOT / "build/v02/campaign15" / name, runtime / "campaign15" / name)
    for name in ("recovery15-attempt1", "recovery15-attempt2"):
        shutil.copytree(ROOT / "build/v02" / name, runtime / name)
    active = runtime / "recovery15"
    active.mkdir()
    (active / ".limits.lock").write_bytes(b"")

    protocol = root / PHASE / "07-16-PROTOCOL.md"
    protocol.write_text("# Plan 16 temporary contract protocol\n", encoding="utf-8")
    review = root / PHASE / "07-16-REVIEW.md"
    security = root / PHASE / "07-16-SECURITY.md"
    auth = root / PHASE / "07-16-AUTHORIZATION.md"
    supersession = root / PHASE / "07-16-SUPERSESSION.md"
    old_packet_path = root / PHASE / "07-15-ADMISSION.json"
    old_packet = json.loads(old_packet_path.read_bytes())
    old_resume = old_packet["resume_campaign"]
    campaign_path = runtime / "campaign15/campaign.json"
    campaign = json.loads(campaign_path.read_bytes())
    old_packet_sha = digest(old_packet_path)
    resume = {
        "schema": "genewhip.phase7-return-campaign-resume.v1",
        "attempt_number": 4,
        "attempt4_marker_path": "build/v02/campaign15/attempt4-started.json",
        "attempt3_marker_path": "build/v02/campaign15/attempt3-started.json",
        "attempt3_marker_sha256": digest(runtime / "campaign15/attempt3-started.json"),
        "campaign_sha256": digest(campaign_path),
        "campaign_started_at": campaign["started_at"],
        "prior_host_invocations_used": 4,
        "prior_host_invocations_unknown_reserved": 0,
        "prior_wrapper_calls_used": 2,
        "prior_packet_path": (PHASE / "07-15-ADMISSION.json").as_posix(),
        "prior_packet_sha256": old_packet_sha,
        "prior_protocol_path": (PHASE / "07-15-PROTOCOL.md").as_posix(),
        "prior_protocol_sha256": digest(root / PHASE / "07-15-PROTOCOL.md"),
        "prior_return_path": (PHASE / "07-15-RETURN.md").as_posix(),
        "prior_return_sha256": digest(root / PHASE / "07-15-RETURN.md"),
        "prior_summary_path": (PHASE / "07-15-SUMMARY.md").as_posix(),
        "prior_summary_sha256": digest(root / PHASE / "07-15-SUMMARY.md"),
        "authorization_path": (PHASE / "07-16-AUTHORIZATION.md").as_posix(),
        "authorization_sha256": digest(auth),
        "supersession_path": (PHASE / "07-16-SUPERSESSION.md").as_posix(),
        "supersession_sha256": digest(supersession),
        "attempt1_failure_manifest_sha256": old_resume["failed_attempt"]["sha256"],
        "attempt2_failure_manifest_sha256": old_resume["attempt2_failure"]["sha256"],
        "attempt3_failure_before_case": {"host_invocation": 4, "case_starts": 0,
            "reason": "recovery-campaign-identity-invalid"},
    }
    packet = dict(old_packet)
    packet.update(plan="GW-07-16", cumulative_limits=runner.ATTEMPT4_CUMULATIVE_LIMITS,
        protocol_sha256=digest(protocol), sources={relative: digest(root / relative)
            for relative in runner.SOURCES16}, resume_campaign=resume)
    packet["command"] = [sys.executable, "-I", "tests/evidence/phase7_wrapper_return.py",
        "--run-selected", "--packet", (PHASE / "07-16-ADMISSION.json").as_posix(),
        "--campaign", "build/v02/campaign15/campaign.json", "--out", "build/v02/recovery15/live.json"]
    packet["owner_argv"] = [sys.executable, "-I", "tests/evidence/phase7_wrapper_return.py",
        "--owner", "{case}", "{root}", "--controller-pid", "{controller_pid}",
        "--controller-nonce", "{controller_nonce}", "--packet",
        (PHASE / "07-16-ADMISSION.json").as_posix(), "--campaign",
        "build/v02/campaign15/campaign.json", "--campaign-sha256", "{campaign_sha256}"]
    packet_path = root / PHASE / "07-16-ADMISSION.json"
    packet_path.write_text(json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8")
    packet_sha = digest(packet_path)
    review.write_text("---\nphase: GW-07\nplan: '16'\nstatus: accepted\n"
        "reviewer_role: gsd-code-reviewer\nreviewer_model: gpt-6-luna\n"
        "author_role: gsd-executor\nsource-review: current-source-and-packet\n"
        "unresolved high/critical: 0\ncritical: 0\nhigh: 0\n"
        f"protocol_sha256: {packet['protocol_sha256']}\npacket_sha256: {packet_sha}\n---\n"
        "Independent review: ACCEPTED\n",
        encoding="utf-8")
    source_pins_sha = hashlib.sha256(json.dumps(packet["sources"], sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    security.write_text("prospective diagnostic source eligibility: accepted\n"
        "reviewer_role: gsd-security-auditor\nreviewer_model: gpt-6.1-sol\n"
        "unresolved current high/critical: 0\n"
        f"packet_sha256: {packet_sha}\nprotocol_sha256: {packet['protocol_sha256']}\n"
        f"source_pins_sha256: {source_pins_sha}\nhistorical identity/liveness: UNKNOWN\n"
        "T-07-07: OPEN/high\n---\n", encoding="utf-8")
    return root, packet_path, packet, campaign_path


class Wrapper16Contracts(unittest.TestCase):
    def test_attempt_four_is_explicitly_supported(self):
        source = (ROOT / "tests/evidence/phase7_wrapper_return.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        selectors = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "attempt_number":
                for comparator in node.comparators:
                    if isinstance(comparator, (ast.Tuple, ast.List, ast.Set)):
                        selectors.extend(item.value for item in comparator.elts
                            if isinstance(item, ast.Constant) and type(item.value) is int)
        self.assertIn(4, selectors, "attempt 4 must be an explicit one-shot selector")

    def test_review_admission_rejects_duplicate_or_issue_bearing_frontmatter(self):
        good = ("---\nstatus: accepted\nreviewer_role: gsd-code-reviewer\n"
            "reviewer_model: gpt-6-luna\nauthor_role: gsd-executor\n"
            "source-review: current-source-and-packet\nunresolved high/critical: 0\n"
            "critical: 0\nhigh: 0\npacket_sha256: p\nprotocol_sha256: q\n---\n")
        self.assertTrue(runner._accepted_review(good, packet_sha256="p", protocol_sha256="q",
            reviewer_role="gsd-code-reviewer", reviewer_model="gpt-6-luna"))
        self.assertTrue(coordinator._review_frontmatter_accepted(good, packet_sha256="p",
            protocol_sha256="q", reviewer_role="gsd-code-reviewer", reviewer_model="gpt-6-luna"))
        for bad in (good.replace("status: accepted", "status: rejected"),
                    good.replace("critical: 0", "critical: 1"),
                    good.replace("---\n", "status: rejected\n---\n", 1),
                    good.replace("high: 0\n", "high: 0\nhigh: 1\n"),
                    good.replace("---\n", "'status': rejected\n---\n", 1),
                    "---\nreview: |\n" + "".join("  " + line + "\n"
                        for line in good.splitlines()[1:-1]) + "---\n"):
            self.assertFalse(runner._accepted_review(bad, packet_sha256="p", protocol_sha256="q",
                reviewer_role="gsd-code-reviewer", reviewer_model="gpt-6-luna"))
            self.assertFalse(coordinator._review_frontmatter_accepted(bad, packet_sha256="p",
                protocol_sha256="q", reviewer_role="gsd-code-reviewer", reviewer_model="gpt-6-luna"))
        security = ("prospective diagnostic source eligibility: accepted\n"
            "reviewer_role: gsd-security-auditor\nreviewer_model: gpt-6.1-sol\n"
            "unresolved current high/critical: 0\npacket_sha256: p\nprotocol_sha256: q\n"
            "source_pins_sha256: s\nhistorical identity/liveness: UNKNOWN\n"
            "T-07-07: OPEN/high\n---\n")
        self.assertTrue(coordinator._security_disposition_accepted(security,
            packet_sha256="p", protocol_sha256="q", source_pins_sha256="s"))
        fenced_security = ("# Assessment\n```yaml\n" + security + "```\n")
        self.assertFalse(coordinator._security_disposition_accepted(fenced_security,
            packet_sha256="p", protocol_sha256="q", source_pins_sha256="s"))
        self.assertFalse(runner._accepted_security_report(fenced_security, {
            "prospective diagnostic source eligibility": "accepted",
            "reviewer_role": "gsd-security-auditor", "reviewer_model": "gpt-6.1-sol",
            "unresolved current high/critical": "0", "packet_sha256": "p",
            "protocol_sha256": "q", "source_pins_sha256": "s",
            "historical identity/liveness": "UNKNOWN", "T-07-07": "OPEN/high"}))

    def test_real_attempt4_transition_debits_before_cases_and_accounts_failure(self):
        for fail_first in (False, True):
            with self.subTest(fail_first=fail_first), tempfile.TemporaryDirectory(prefix="gw16-") as temporary:
                root, packet_path, packet, campaign_path = fixture(Path(temporary).resolve())
                case_calls = []
                def fake_case(index, case, _counters, campaign_sha, packet_sha, **kwargs):
                    case_calls.append(case)
                    self.assertEqual(kwargs["packet_path"], root / PHASE / "07-16-ADMISSION.json")
                    self.assertEqual((root / "build/v02/campaign15/attempt4-started.json").is_file(), True)
                    case_root = root / "build/v02/recovery15" / f"case-{index}"
                    case_root.mkdir()
                    counts = case_root / "owner-process-count.json"
                    counts.write_text(json.dumps({"wrapper_calls": 1,
                        "campaign_sha256": campaign_sha, "packet_sha256": packet_sha,
                        "case": case, "starts": 1, "status_helper_starts": 1,
                        "rss_observations": 1}), encoding="utf-8")
                    return {"case": case, "status": "failed" if fail_first and index == 1 else "pass",
                        "owner_settled": True, "leaf_settled": True, "starts": 1,
                        "status_helper_starts": 1, "observer_queries": 1, "rss_samples": 1,
                        "owner_process_count_path": counts.relative_to(root).as_posix()}
                with mock.patch.object(runner, "ROOT", root), \
                     mock.patch.dict(os.environ, {}, clear=True), \
                     mock.patch.object(runner, "run_case", side_effect=fake_case):
                    result = runner.run_selected(packet_path, Path("build/v02/campaign15/campaign.json"),
                        Path("build/v02/recovery15/live.json"))
                marker = root / "build/v02/campaign15/attempt4-started.json"
                marker_doc = json.loads(marker.read_bytes())
                self.assertEqual(marker_doc["attempt"], 4)
                self.assertEqual(marker_doc["prior_host_invocations_used"], 4)
                self.assertEqual(marker_doc["cumulative_limits"], runner.ATTEMPT4_CUMULATIVE_LIMITS)
                self.assertEqual(case_calls, ["shared_launch"] if fail_first else
                    ["shared_launch", "bounded_command"])
                live = json.loads((root / "build/v02/recovery15/live.json").read_bytes())
                self.assertEqual(live["status"], "failed" if fail_first else "pass")
                accounting = live["cumulative_accounting"]
                self.assertEqual(accounting["campaign_caps"]["host_invocations"], 5)
                self.assertEqual(accounting["campaign_caps"]["elapsed_seconds_reserved"], 480)
                self.assertEqual(accounting["prior_failed_attempts_usage_and_reserves"][
                    "prior_elapsed_seconds_reserved"], 360)
                self.assertEqual(accounting["campaign_used"]["control_bytes_reserved"], 69222)
                self.assertEqual(accounting["campaign_used"]["control_entries_reserved"], 4)
                self.assertEqual(denial.receipt()["unexpected_denials"], 0)

    def test_cumulative_attempt4_envelope_preserves_unknown_reserves(self):
        limits = runner.ATTEMPT4_CUMULATIVE_LIMITS
        self.assertEqual(limits["prior_owner_starts_unknown_reserved"], 34)
        self.assertEqual(limits["prior_owner_status_helpers_unknown_reserved"], 34)
        self.assertEqual(limits["prior_owner_rss_samples_unknown_reserved"], 1016)
        self.assertEqual(limits["prior_starts_reserved"], 46)
        self.assertEqual(limits["campaign_start_events"], 130)
        self.assertEqual(limits["campaign_control_bytes"], 69222)
        self.assertEqual(limits["campaign_retained_bytes"], 8408394)
        runner.validate_cumulative_limits(limits, attempt_number=4)

    def test_history_corruption_rejects_before_attempt4_debit_or_case(self):
        with tempfile.TemporaryDirectory(prefix="gw16-corrupt-") as temporary:
            root, packet_path, _packet, campaign_path = fixture(Path(temporary).resolve())
            marker3 = root / "build/v02/campaign15/attempt3-started.json"
            marker3.write_bytes(b"{}\n")
            cases = []
            with mock.patch.object(runner, "ROOT", root), \
                 mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(runner, "run_case", side_effect=lambda *args, **kwargs: cases.append(args)):
                with self.assertRaisesRegex(ValueError, "recovery-campaign-identity-invalid"):
                    runner.run_selected(packet_path, Path("build/v02/campaign15/campaign.json"),
                        Path("build/v02/recovery15/live.json"))
            self.assertFalse((root / "build/v02/campaign15/attempt4-started.json").exists())
            self.assertEqual(cases, [])
            self.assertEqual(campaign_path.stat().st_size, 672)
            self.assertEqual(sorted(item.name for item in (root / "build/v02/recovery15").iterdir()),
                [".limits.lock"])
            self.assertEqual(denial.receipt()["unexpected_denials"], 0)

    def test_frozen_verify_live_accepts_two_cases_and_rejects_rehashed_mutant(self):
        with tempfile.TemporaryDirectory(prefix="gw16-oracle-") as temporary:
            root, packet_path, _packet, campaign_path = fixture(Path(temporary).resolve())
            def fake_case(index, case, _counters, campaign_sha, packet_sha, **_kwargs):
                case_root = root / "build/v02/recovery15" / f"case-{index}"
                case_root.mkdir()
                counts = case_root / "owner-process-count.json"
                runner.write_record(counts, {"wrapper_calls": 1, "campaign_sha256": campaign_sha,
                    "packet_sha256": packet_sha, "case": case, "starts": 1,
                    "status_helper_starts": 1, "rss_observations": 1})
                return {"case": case, "status": "pass", "owner_settled": True,
                    "leaf_settled": True, "starts": 2, "status_helper_starts": 2,
                    "observer_queries": 1, "rss_samples": 2, "controller_starts": 1,
                    "owner_starts": 1, "owner_rss_samples": 1, "observer_rss_samples": 1,
                    "owner_process_count_path": counts.relative_to(root).as_posix()}
            with mock.patch.object(runner, "ROOT", root), \
                 mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(runner, "run_case", side_effect=fake_case):
                runner.run_selected(packet_path, Path("build/v02/campaign15/campaign.json"),
                    Path("build/v02/recovery15/live.json"))
                packet, review_path = runner.validate_packet_for_entry(packet_path)
                campaign_sha = digest(campaign_path)
                campaign = json.loads(campaign_path.read_bytes())
                rows = []
                for index, case in enumerate(("shared_launch", "bounded_command"), start=1):
                    case_root = root / "build/v02/recovery15" / f"case-{index}"
                    (case_root / "controller").mkdir()
                    work = case_root / "owner-work"
                    (work / "process-receipts").mkdir(parents=True)
                    owner_pid, leaf_pid, controller_pid = 920000 + index * 10, 920001 + index * 10, 910000 + index
                    nonce = ("c" if index == 1 else "d") * 64
                    owner_birth = {"pid": owner_pid, "pgid": owner_pid, "birth": f"owner-{index}", "state": "S"}
                    leaf_birth = {"pid": leaf_pid, "pgid": leaf_pid, "birth": f"leaf-{index}", "state": "S"}
                    absent = {"pid": owner_pid, "query": runner.LIMITS["observer_argv"],
                        "identity": None, "group_members": [], "bytes": 0,
                        "status_sha256": hashlib.sha256(b"").hexdigest()}
                    absent_leaf = dict(absent, pid=leaf_pid)
                    controller_path = case_root / "controller/process.json"
                    wrapper_path = work / "wrapper-result.json"
                    leaf_path = work / "process-receipts/leaf.json"
                    count_path = case_root / "owner-process-count.json"
                    release_a = case_root / "release-A.json"
                    release_b = case_root / "release-B.json"
                    runner.write_record(controller_path, {"processes": [dict(owner_birth,
                        process_group_cleanup="confirmed")]})
                    runner.write_record(leaf_path, {"processes": [dict(leaf_birth,
                        process_group_cleanup="confirmed")]})
                    wrapper_name = "shared_launch" if case == "shared_launch" else "_bounded_command"
                    runner.write_record(wrapper_path, {"wrapper": wrapper_name, "case": case,
                        "campaign_sha256": campaign_sha, "packet_sha256": packet["packet_sha256"],
                        "returncode": 0, "receipt": dict(leaf_birth, process_group_cleanup="confirmed")})
                    runner.write_record(release_a, {"pid": owner_pid, "scope_id": runner.SCOPE_ID,
                        "case": case, "controller_pid": controller_pid, "controller_nonce": nonce,
                        "packet_sha256": packet["packet_sha256"], "campaign_sha256": campaign_sha})
                    runner.write_record(release_b, {"pid": leaf_pid, "scope_id": runner.SCOPE_ID})
                    row = {"case": case, "case_root": case_root.relative_to(root).as_posix(),
                        "status": "pass", "returncode": 0, "owner_settled": True, "leaf_settled": True,
                        "case_elapsed_seconds": .1, "controller_pid": controller_pid,
                        "owner_birth": dict(owner_birth, rss_bytes=100), "leaf_birth": dict(leaf_birth, rss_bytes=100),
                        "owner_final_observation": absent, "leaf_final_observation": absent_leaf,
                        "starts": 2, "controller_starts": 1, "owner_starts": 1,
                        "status_helper_starts": 2, "observer_queries": 1, "rss_samples": 2,
                        "owner_rss_samples": 1, "observer_rss_samples": 1,
                        "rss_bytes": {"owner": 100, "leaf": 100},
                        "controller_receipt_path": controller_path.relative_to(root).as_posix(),
                        "controller_receipt_sha256": digest(controller_path),
                        "wrapper_result_path": wrapper_path.relative_to(root).as_posix(),
                        "wrapper_result_sha256": digest(wrapper_path),
                        "leaf_receipt": leaf_path.relative_to(root).as_posix(),
                        "leaf_receipt_sha256": digest(leaf_path),
                        "owner_process_count_path": count_path.relative_to(root).as_posix(),
                        "owner_process_count_sha256": digest(count_path),
                        "release-A_path": release_a.relative_to(root).as_posix(),
                        "release-A_sha256": digest(release_a),
                        "release-B_path": release_b.relative_to(root).as_posix(),
                        "release-B_sha256": digest(release_b)}
                    rows.append(row)
                live_path = root / "build/v02/recovery15/live.json"
                live = json.loads(live_path.read_bytes())
                live["cases"] = rows
                live["review_sha256"] = digest(review_path)
                runner.write_record(live_path, live, exclusive=False)
                self.assertEqual(runner.verify_live(live_path), 0)
                mutant = dict(live)
                mutant["cases"] = [dict(row) for row in rows]
                mutant["cases"][0]["owner_settled"] = False
                mutant_path = root / "mutant.json"
                mutant_path.write_text(json.dumps(mutant), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "return-live-case-not-independently-settled"):
                    runner.verify_live(mutant_path)

    def test_attempt4_owner_executes_both_real_wrapper_receipt_paths(self):
        class FakeProcess:
            next_pid = 980000
            def __init__(self, argv, **kwargs):
                self.argv = argv
                self.pid = FakeProcess.next_pid
                FakeProcess.next_pid += 1
                self.returncode = 0
                for stream in ("stdout", "stderr"):
                    setattr(self, stream, None)
                    if kwargs.get(stream) == __import__("subprocess").PIPE:
                        read_fd, write_fd = os.pipe()
                        os.close(write_fd)
                        setattr(self, stream, os.fdopen(read_fd, "rb", buffering=0))
            def poll(self): return self.returncode
            def wait(self, timeout=None): return self.returncode
            def kill(self): self.returncode = -9
            def terminate(self): self.returncode = -15

        with tempfile.TemporaryDirectory(prefix="gw16-owner-") as temporary:
            root, packet_path, _packet, campaign_path = fixture(Path(temporary).resolve())
            with mock.patch.object(runner, "ROOT", root), mock.patch.dict(os.environ, {}, clear=True):
                packet, _review = runner.validate_packet_for_entry(packet_path)
                started, campaign_sha, needs_debit = runner.validate_prechild_resume_state(
                    campaign_path, packet)
                self.assertTrue(needs_debit)
                runner.consume_attempt4_invocation(packet, campaign_sha, started["started_at"])
                for index, case in enumerate(("shared_launch", "bounded_command"), start=1):
                    case_root = root / "build/v02/recovery15" / f"case-{index}"
                    case_root.mkdir()
                    nonce = ("a" if index == 1 else "b") * 64
                    runner.write_record(case_root / "release-A.json", {"pid": os.getpid(),
                        "scope_id": runner.SCOPE_ID, "case": case, "controller_pid": os.getppid(),
                        "controller_nonce": nonce, "packet_sha256": packet["packet_sha256"],
                        "campaign_sha256": campaign_sha})
                    with mock.patch.dict(os.environ, {"GENEWHIP_PROCESS_CONTEXT": "host-cleanup-v1"}, clear=True), \
                         mock.patch.object(__import__("subprocess"), "Popen", FakeProcess), \
                         mock.patch("os.killpg", side_effect=ProcessLookupError):
                        self.assertEqual(runner.owner(case, case_root, controller_pid=os.getppid(),
                            controller_nonce=nonce, packet_path=packet_path,
                            campaign_path=campaign_path, campaign_sha256=campaign_sha), 0)
                    wrapper = json.loads((case_root / "owner-work/wrapper-result.json").read_bytes())
                    counts = json.loads((case_root / "owner-process-count.json").read_bytes())
                    expected_wrapper = "shared_launch" if case == "shared_launch" else "_bounded_command"
                    self.assertEqual(wrapper["wrapper"], expected_wrapper)
                    self.assertEqual(wrapper["case"], case)
                    self.assertEqual(wrapper["packet_sha256"], packet["packet_sha256"])
                    self.assertEqual(wrapper["campaign_sha256"], campaign_sha)
                    self.assertEqual(wrapper["returncode"], 0)
                    self.assertEqual(counts["wrapper_calls"], 1)
                    self.assertEqual(counts["packet_sha256"], packet["packet_sha256"])
                    self.assertEqual(counts["campaign_sha256"], campaign_sha)
                    self.assertGreater(counts["starts"], 0)
                    self.assertGreater(counts["rss_observations"], 0)


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--tracer", action="store_true")
    parser.add_argument("--contracts", action="store_true")
    parser.add_argument("--entry-check", action="store_true")
    parser.add_argument("--packet", type=Path)
    parser.add_argument("--verify-live", action="store_true")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--review-check", action="store_true")
    args = parser.parse_args(argv)
    if args.entry_check:
        if args.packet is None:
            print("REJECT: return-packet-required", file=sys.stderr)
            return 1
        return runner.main(["--entry-check", "--packet", str(args.packet)])
    if args.verify_live:
        if args.packet is None or args.evidence is None:
            print("REJECT: return-live-arguments-required", file=sys.stderr)
            return 1
        attempt_path = runner.ROOT / runner.PACKET16
        if args.packet != attempt_path:
            print("REJECT: return-attempt4-packet-path-invalid", file=sys.stderr)
            return 1
        return runner.main(["--verify-live", "--evidence", str(args.evidence)])
    if args.review_check:
        try:
            packet, review_path = runner.validate_packet_for_entry(
                args.packet or runner.ROOT / runner.PACKET16)
            if packet.get("resume_campaign", {}).get("attempt_number") != 4 or not review_path.is_file():
                raise ValueError("return-attempt4-review-stale")
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            print("REJECT: " + str(error), file=sys.stderr)
            return 1
        print("phase7-wrapper-return: attempt4 review and entry pins accepted")
        return 0
    if not (args.tracer or args.contracts):
        parser.error("select --tracer, --contracts, --entry-check, --verify-live, or --review-check")
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Wrapper16Contracts))
    denial.self_test("after-mock-restoration")
    receipt = denial.receipt()
    print(json.dumps(receipt, sort_keys=True))
    return 0 if result.wasSuccessful() and receipt["unexpected_denials"] == 0 else 1

if __name__ == "__main__":
    raise SystemExit(main())
