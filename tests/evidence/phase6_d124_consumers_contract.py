#!/usr/bin/env python3
"""No-guest D124 consumer regressions on isolated project-shaped ledgers."""
from __future__ import annotations

# This historical suite read the live ledger and patched the wrong execution
# module. Keep every entry (including discovery/import) closed. The D125 authored
# transaction replaces its integration path; no caller-provided token bypasses it.
raise RuntimeError("unsafe-legacy-d124-entry-disabled-use-reviewed-d125")

import argparse
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import shutil
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEDGER = ROOT / "evidence/phase6-repairs.json"
COORDINATOR = ROOT / "tests/fixtures/phase6_repairs.py"
CHECKER = ROOT / "tests/evidence/phase6_tank_continuation_contract.py"
PHASE = ".planning/phases/GW-06-shared-repairs-and-two-playable-routes"
DOCS = (
    f"{PHASE}/06-20-PLAN.md",
    f"{PHASE}/06-D124-PLAN-CHECK.md",
    ".planning/quick/261024-oh9-diagnose-phase6-recovery-loop-synthesize/261024-oh9-RECOMMENDATIONS.md",
)
SELECTION = None
RUN_ID = ""


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"module-load-failed:{path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class D124ConsumersContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phase6-d124-consumers-")
        self.root = pathlib.Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.ledger = self.root / "evidence/phase6-repairs.json"
        self.ledger.parent.mkdir(parents=True)
        value = json.loads(LEDGER.read_bytes())
        self.anchor = value["phase6_accounting"]["active_anchor"]
        self.boot = self.anchor["boot_identity"]
        self.anchor_path = self.root / "build/phase6/d124-global-anchor.json"
        self.anchor_path.parent.mkdir(parents=True)
        self.anchor_path.write_text(json.dumps(self.anchor, sort_keys=True))
        self.ledger.write_text(json.dumps(value, sort_keys=True))
        for relative in DOCS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        self.accounting = _load("d124_accounting_contract", ROOT / "scripts/evidence/phase6_accounting.py")

    def tearDown(self):
        self.temp.cleanup()

    def test_selected_continuation_cli_forwards_all_explicit_artifacts(self):
        coordinator = _load("d124_consumer_coordinator", COORDINATOR)
        coordinator.ROOT = self.root
        coordinator.LEDGER = self.ledger
        bridge = pathlib.Path("evidence/phase6-tank-observer-bridge-d124-g01.json")
        review = pathlib.Path(f"{PHASE}/06-20-PRELAUNCH-REVIEW.md")
        check = pathlib.Path("evidence/phase6-tank-observer-review-check-d124-g01.json")
        with mock.patch.object(coordinator, "tank_continuation_once", return_value=0) as consumer, \
             mock.patch.object(coordinator.sys, "argv", ["phase6_repairs.py", "--tank-continuation-once",
                 "--build", "build/phase6", "--output", "evidence/receipt.json", "--bridge", str(bridge),
                 "--proof-review", str(review), "--review-check", str(check)]):
            self.assertEqual(coordinator.main(), 0)
        consumer.assert_called_once_with(pathlib.Path("build/phase6").resolve(), self.root / "evidence/receipt.json",
            bridge, review, check)

    def test_selected_receipt_cli_forwards_review_check_to_real_checker_entry(self):
        checker = _load("d124_consumer_checker", CHECKER)
        bridge = pathlib.Path("evidence/phase6-tank-observer-bridge-d124-g01.json")
        review = pathlib.Path(f"{PHASE}/06-20-PRELAUNCH-REVIEW.md")
        check = pathlib.Path("evidence/phase6-tank-observer-review-check-d124-g01.json")
        captured = []
        with mock.patch.object(checker, "verify_receipt_file", side_effect=lambda *args: captured.append(args) or {"launches": 0}), \
             mock.patch.object(checker.sys, "argv", ["checker.py", "--verify-receipt", "evidence/receipt.json",
                 "--bridge", str(bridge), "--proof-review", str(review), "--review-check", str(check),
                 "--build", "build/phase6", "--acceptance-review", f"{PHASE}/06-20-ACCEPTANCE-REVIEW.md",
                 "--output", "evidence/checked.json"]):
            self.assertEqual(checker.main(), 0)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0][1], (ROOT / bridge).resolve())
        self.assertEqual(captured[0][2], (ROOT / review).resolve())
        self.assertEqual(captured[0][-1], (ROOT / check).resolve())

    def test_global_only_forecast_keeps_pea_floor_and_process_reserve(self):
        before = json.loads(self.ledger.read_bytes())
        self.assertEqual(self.accounting.install_d124_policy(self.ledger, self.anchor_path,
            project_root=self.root, boot_identity=self.boot)["plan"], "06-20")
        row = self.accounting.d124_admit_forecast(self.ledger, activity_id="d124-test-consumer-forecast-01",
            nonprocess_seconds=30.0, process_seconds=0.0, closeout_seconds=120.0,
            boot_identity=self.boot, project_root=self.root)
        after = json.loads(self.ledger.read_bytes())
        self.assertEqual(row["status"], "admitted")
        self.assertEqual(row["process_forecast_seconds"], 0.0)
        self.assertEqual(after["d124_recovery_policy"]["pea_floor_seconds"], 7092.328)
        self.assertEqual(after["d124_recovery_policy"]["process_reserve_seconds"], 1800.0)
        self.assertEqual(after["records"], before["records"])
        self.assertEqual(after["d122_accounting"]["other_charges"], before["d122_accounting"]["other_charges"])
        report = self.accounting.preflight(self.ledger, monotonic_now=self.anchor["monotonic_started_at"] + 0.01,
            boot_identity=self.boot, allowed_root=self.root)
        self.assertEqual(report["d124_accounting"]["pea_used_seconds"], 7092.328)
        self.assertEqual(report["d124_accounting"]["process_remaining_seconds"], 1800.0)

    def test_tank_reservation_denies_without_accepted_component_and_current_observer(self):
        self.accounting.install_d124_policy(self.ledger, self.anchor_path,
            project_root=self.root, boot_identity=self.boot)
        before = self.ledger.read_bytes()
        launches = []
        current = json.loads(before)
        source = current["d123_observer_bridge_binding"]["source_identity"]
        bridge = current["d123_observer_bridge_binding"]["bridge_sha256"]
        with self.assertRaisesRegex(self.accounting.AccountingError,
                                    "d124-independent-component-review-required"):
            self.accounting.authorize_launch(self.ledger, purpose="tank-continuation", plan="06-14",
                case=self.accounting.TANK_CONTINUATION_CASE, source_identity=source,
                current_source_identity=source, contract_identity=bridge,
                target_signature=self.accounting.PEA_SIGNATURE,
                launcher=lambda row: launches.append(row), boot_identity=self.boot,
                allowed_root=self.root)
        self.assertEqual(launches, [])
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_actual_coordinator_selection_reaches_only_fake_process_boundaries(self):
        production_ledger_before = LEDGER.read_bytes()
        coordinator = _load("d124_real_consumer_coordinator", COORDINATOR)
        coordinator.ROOT = ROOT
        test_area = ROOT / "build/phase6/d124-consumers"
        isolated = tempfile.TemporaryDirectory(prefix=f"{RUN_ID}-ledger-", dir=test_area)
        ledger = pathlib.Path(isolated.name) / "evidence/phase6-repairs.json"
        ledger.parent.mkdir(parents=True)
        ledger.write_bytes(LEDGER.read_bytes())
        self.ledger = ledger
        bridge, proof_review, check = SELECTION or self._create_synthetic_accepted_bundle()
        coordinator.LEDGER = ledger
        boot = json.loads(ledger.read_bytes())["d124_recovery_policy"]["boot_identity"]
        coordinator.accounting.read_boot_identity = lambda: boot
        original_module = coordinator.module
        fake_processes = []
        checker = original_module("d124_fake_native_fixture", "tests/evidence/phase6_tank_continuation_contract.py")

        def fake_client(_client, command, processes, *, report, retained_streams, **_kwargs):
            current = json.loads(self.ledger.read_bytes())
            reservation = next((row for row in reversed(current["records"])
                if row.get("case") == "tank-pea-continuation-1"), None)
            if reservation is None or reservation.get("status") != "reserved":
                raise RuntimeError("d124-fake-capture-reached-before-durable-reservation")
            with tempfile.TemporaryDirectory(prefix="d124-synthetic-pea-") as temp:
                native = checker._fake_receipt(pathlib.Path(temp))["native_report"]
            plan_path = ROOT / command[command.index("--route-plan") + 1]
            native["plan_fnv1a64"] = coordinator.compiler.plan_fingerprint(plan_path.read_bytes())
            native["samples"] = []
            report.write_text(json.dumps(native, sort_keys=True))
            processes.append({"return_code": 1, "wall_seconds": 0.01, "timed_out": False,
                "bound_violation": False, "stdout_bytes": 0, "stderr_bytes": 0})
            for name in ("stdout", "stderr"):
                retained_streams[name] = {"text": "", "sha256": hashlib.sha256(b"").hexdigest(),
                    "retained_bytes": 0, "observed_bytes": 0, "truncated": False}
            fake_processes.append("capture-boundary")
            return type("FakeCompletedProcess", (), {"returncode": 1})()

        coordinator.contracts._run_client = fake_client

        def fake_control_run(command, *, timeout, cap):
            report_path = pathlib.Path(command[command.index("--report") + 1])
            current = json.loads(self.ledger.read_bytes())
            expected = next((row["post_behavior"]["unchanged_control"]["results"] for row in
                reversed(current["records"]) if row.get("post_behavior", {}).get("unchanged_control", {}).get("status") == "pass"), None)
            if not expected or len(expected) != 6:
                raise RuntimeError("test-control-baseline-missing")
            control_root = report_path.parent / "pcm"
            control_root.mkdir(parents=True, exist_ok=True)
            children = []
            binary_sha = hashlib.sha256((ROOT / "build/phase6/tools/session/gw_headless").read_bytes()).hexdigest()
            for index, row in enumerate(expected):
                pcm = bytes(row["pcm_frames"] * 4)
                pcm_path = control_root / f"{index:02d}-{row['id']}.pcm"
                pcm_path.write_bytes(pcm)
                row["retained_pcm"] = {"path": pcm_path.relative_to(ROOT).as_posix(),
                    "bytes": len(pcm), "sha256": hashlib.sha256(pcm).hexdigest()}
                streams = {}
                for stream_name in ("stdout", "stderr"):
                    raw_path = report_path.parent / f"child-{index:02d}.{stream_name}.raw"
                    raw_path.write_bytes(b"")
                    streams[stream_name] = {"path": raw_path.relative_to(ROOT).as_posix(),
                        "sha256": hashlib.sha256(b"").hexdigest(), "retained_bytes": 0,
                        "observed_bytes": 0, "truncated": False}
                children.append({"case": row["id"], "return_code": 0,
                    "executable_path": "build/phase6/tools/session/gw_headless",
                    "executable_sha256": binary_sha,
                    "command_sha256": hashlib.sha256(f"synthetic-child-{index}".encode()).hexdigest(),
                    "streams": streams})
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps({"outcome": "pass", "results": copy.deepcopy(expected),
                "native_child_processes": children}, sort_keys=True))
            fake_processes.append("control-boundary")
            return type("FakeControlCompletedProcess", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

        def load_real_module(name, path):
            loaded = original_module(name, path)
            if path == "tests/evidence/phase4_game.py":
                loaded.bounded_run = fake_control_run
            elif path == "tests/evidence/phase6_tank_continuation_contract.py":
                loaded.LEDGER = self.ledger
            return loaded

        coordinator.module = load_real_module
        output = ROOT / "build/phase6/d124-consumers" / f"{RUN_ID}-coordinator-receipt.json"
        argv = ["phase6_repairs.py", "--tank-continuation-once", "--build", "build/phase6",
            "--output", str(output), "--bridge", str(bridge), "--proof-review", str(proof_review),
            "--review-check", str(check)]
        captured = io.StringIO()
        with mock.patch.object(coordinator.sys, "argv", argv), contextlib.redirect_stdout(captured):
            self.assertEqual(coordinator.main(), 0, captured.getvalue())
        receipt = json.loads(output.read_bytes())
        self.assertEqual(receipt.get("status"), "passed-capture")
        self.assertEqual(len(receipt.get("controls", [])), 2)
        self.assertEqual(fake_processes, ["capture-boundary", "control-boundary", "control-boundary"])
        rows = [row for row in json.loads(self.ledger.read_bytes())["records"] if
            row.get("plan") == "06-14" and row.get("purpose") in
            ("tank-continuation", "tank-continuation-control")]
        self.assertEqual(len(rows), 3)
        self.assertEqual(sum(row.get("new_target_attempts", 0) for row in rows), 1)

        # A synthetic, explicitly test-only final handoff drives the real receipt
        # verifier/locked publisher. It lives only in the isolated ledger and is
        # mechanical integration evidence, never production reviewer authority.
        checker = load_real_module("d124_actual_receipt_checker",
            "tests/evidence/phase6_tank_continuation_contract.py")
        checker.LEDGER = self.ledger
        if not self.ledger.resolve().is_relative_to(ROOT.resolve()):
            raise RuntimeError(f"synthetic-ledger-outside-root:{self.ledger.resolve()}:{ROOT.resolve()}")
        if not self.ledger.resolve().is_relative_to(checker.ROOT.resolve()):
            raise RuntimeError(f"checker-ledger-outside-root:{self.ledger.resolve()}:{checker.ROOT.resolve()}")
        acceptance = test_area / f"{RUN_ID}-synthetic-final-review.json"
        review = {"disposition": "accepted", "receipt_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "bridge_sha256": receipt["proof_revalidation_sha256"], "source_identity": receipt["source_identity"],
            "processes": 3, "control_cases": 12, "test_fixture_only": True}
        acceptance.write_text(json.dumps(review, sort_keys=True) + "\n")
        acceptance_sha = hashlib.sha256(acceptance.read_bytes()).hexdigest()
        current = json.loads(self.ledger.read_bytes())
        current.setdefault("d122_trusted_review_handoffs", []).append({
            "lane": "tank-final-acceptance", "status": "completed",
            "review_path": acceptance.relative_to(ROOT).as_posix(), "review_sha256": acceptance_sha,
            "bridge_sha256": receipt["proof_revalidation_sha256"], "source_identity": receipt["source_identity"],
            "tool_handoff_result": "completed", "reviewer_role": "gsd-code-reviewer",
            "reviewer_identity": "synthetic-fixture-reviewer", "producer_identity": "synthetic-fixture-producer",
            "disposition": "accepted", "critical_findings": 0, "high_findings": 0,
            "receipt_sha256": review["receipt_sha256"], "test_fixture_only": True})
        self.ledger.write_text(json.dumps(current, sort_keys=True))
        for stage in ("preflight", "interprocess", "final-review", "closeout", "final-check"):
            activity_id = f"d124-integration-{stage}-fixture"
            coordinator.accounting.begin_d124_activity(self.ledger, activity_id=activity_id, stage=stage,
                exposure_seconds=30, boot_identity=boot, project_root=ROOT)
            coordinator.accounting.finalize_d124_activity(self.ledger, activity_id=activity_id,
                status="completed", boot_identity=boot, allowed_root=ROOT)
        checked = test_area / f"{RUN_ID}-checked-receipt.json"
        checker_argv = ["checker.py", "--verify-receipt", str(output.relative_to(ROOT)),
            "--bridge", str(bridge.relative_to(ROOT)), "--proof-review", str(proof_review.relative_to(ROOT)),
            "--review-check", str(check.relative_to(ROOT)), "--build", "build/phase6",
            "--acceptance-review", str(acceptance.relative_to(ROOT)), "--output", str(checked.relative_to(ROOT))]
        with mock.patch.object(checker.sys, "argv", checker_argv):
            self.assertEqual(checker.main(), 0)
        published = json.loads(checked.read_bytes())
        self.assertEqual(published.get("status"), "independently-checked")
        self.assertEqual(published.get("counts", {}).get("control_native_children"), 12)
        self.assertEqual(json.loads(self.ledger.read_bytes())["current_tank_continuation_receipt"]["status"], "passed")
        self.assertEqual(LEDGER.read_bytes(), production_ledger_before)

    def _create_synthetic_accepted_bundle(self):
        """Build a mechanical D124 fixture with real verification and test-only trust."""
        checker = _load("d124_synthetic_bundle_checker", CHECKER)
        checker.LEDGER = self.ledger
        run = RUN_ID or "local-integration"
        area = ROOT / "build/phase6/d124-consumers"
        prior = ROOT / "evidence/phase6-tank-observer-bridge-d123-g02.json"
        bridge = area / f"{run}-synthetic-bridge.json"
        review = area / f"{run}-synthetic-review.md"
        check = area / f"{run}-synthetic-review-check.json"
        checker._d124_component_candidate(prior, review, ROOT / "build/phase6", bridge)
        candidate = json.loads(bridge.read_bytes())
        sections = ["historical-source-and-assertion-closure", "actual-d123-qualification-and-binaries",
            "stack-read-ownership-and-neighbor-cases", "raw-process-stream-and-global-accounting",
            "d124-accounting-and-component-consumer-disposition", "downstream-14-launch-guard"]
        payload = {"disposition": "accepted", "reviewer_role": "independent-reviewer",
            "reviewer_identity": "synthetic-fixture-reviewer",
            "bridge_sha256": candidate["bridge_sha256"],
            "source_identity": candidate["current_source_closure"]["source_identity"],
            "reviewed_sections": sections, "findings": [], "test_fixture_only": True}
        review.write_text("# Synthetic D124 consumer fixture\n\n```json\n" +
            json.dumps(payload, sort_keys=True, indent=2) + "\n```\n")
        ledger = json.loads(self.ledger.read_bytes())
        ledger.setdefault("d123_trusted_review_handoffs", []).append({
            "lane": "observer-proof-review", "status": "completed",
            "review_path": review.relative_to(ROOT).as_posix(),
            "review_sha256": hashlib.sha256(review.read_bytes()).hexdigest(),
            "bridge_sha256": candidate["bridge_sha256"],
            "source_identity": candidate["current_source_closure"]["source_identity"],
            "tool_handoff_result": "completed", "reviewer_role": "gsd-code-reviewer",
            "reviewer_identity": "synthetic-fixture-reviewer", "producer_identity": "synthetic-fixture-producer",
            "disposition": "accepted", "critical_findings": 0, "high_findings": 0,
            "test_fixture_only": True})
        self.ledger.write_text(json.dumps(ledger, sort_keys=True))
        if checker.LEDGER.resolve() != self.ledger.resolve():
            raise RuntimeError(f"checker-ledger-binding-drift:{checker.LEDGER}:{self.ledger}")
        if not checker.LEDGER.resolve().is_relative_to(checker.ROOT.resolve()):
            raise RuntimeError(f"checker-ledger-root-mismatch:{checker.LEDGER}:{checker.ROOT}")
        result = checker.verify_proof_review(bridge, review, ROOT / "build/phase6", check)
        self.assertEqual(result.get("status"), "accepted")
        self.assertEqual(checker.verify_acceptance_review(check, bridge, ROOT / "build/phase6").get("status"),
            "accepted-current-review")
        return bridge, review, check


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=("tracer", "expanded", "all"), required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--bridge", type=pathlib.Path)
    parser.add_argument("--proof-review", type=pathlib.Path)
    parser.add_argument("--review-check", type=pathlib.Path)
    parser.add_argument("--run-id", default="")
    args = parser.parse_args()
    supplied = (args.bridge, args.proof_review, args.review_check)
    if any(supplied) and not all(supplied):
        parser.error("--bridge, --proof-review, and --review-check must be supplied together")
    global SELECTION, RUN_ID
    if all(supplied):
        SELECTION = tuple(path if path.is_absolute() else (ROOT / path).resolve() for path in supplied)
        for path in SELECTION:
            path.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    if args.run_id and not args.run_id.replace("-", "").isalnum():
        parser.error("--run-id must contain only letters, digits, and hyphens")
    RUN_ID = args.run_id or f"run-{time.time_ns()}"
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.resolve().relative_to(ROOT.resolve())
    if output.is_symlink() or output.exists():
        parser.error("output must be a new non-symlink path")
    names = ["test_selected_continuation_cli_forwards_all_explicit_artifacts",
        "test_selected_receipt_cli_forwards_review_check_to_real_checker_entry",
        "test_global_only_forecast_keeps_pea_floor_and_process_reserve",
        "test_tank_reservation_denies_without_accepted_component_and_current_observer"]
    if args.stage in ("tracer", "all") or SELECTION is not None:
        names.append("test_actual_coordinator_selection_reaches_only_fake_process_boundaries")
    suite = unittest.TestSuite(D124ConsumersContract(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "phase6-d124-consumers-contract-v1", "stage": args.stage,
        "status": "passed" if result.wasSuccessful() else "failed", "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors), "guest_launches": 0,
        "builds": 0, "ledger": "temporary isolated project roots only"}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
