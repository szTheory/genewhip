#!/usr/bin/env python3
"""Versioned Phase 5 record and control-tracer contract."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "phase5_records", ROOT / "tools/evidence/phase5_records.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("phase5 evidence record parser unavailable")
records = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(records)
BASELINE_SPEC = importlib.util.spec_from_file_location(
    "phase5_baseline", ROOT / "scripts/evidence/phase5_baseline.py")
if BASELINE_SPEC is None or BASELINE_SPEC.loader is None:
    raise RuntimeError("phase5 baseline tracer unavailable")
baseline = importlib.util.module_from_spec(BASELINE_SPEC)
BASELINE_SPEC.loader.exec_module(baseline)


def row(**changes):
    value = {
        "schema": "genewhip-phase5-evidence-v1",
        "fixture_id": "genewhip-independent-game-v2",
        "title_id": "genewhip-independent-game-v2",
        "source_revision": "a" * 40,
        "source_sha256": "1" * 64,
        "build_configuration_sha256": "2" * 64,
        "toolchain_sha256": "3" * 64,
        "rom_sha256": "4" * 64,
        "notices_sha256": "9" * 64,
        "reference_evidence_sha256": "a" * 64,
        "profile": "VA3-NTSC-U",
        "scenario_sha256": "5" * 64,
        "input_sha256": "6" * 64,
        "oracle_sha256": "7" * 64,
        "client_sha256": "8" * 64,
        "run_id": "control-title-no-start-01",
        "case_id": "title-no-start",
        "stage": "core",
        "outcome": "pass",
        "reason": "unchanged admitted control title-no-start case passed",
        "observations": {"fields": 11, "stop_reason": 0, "unsupported": 0,
                          "fault_address": 0, "source_predicate": "title-no-start"},
    }
    value.update(changes)
    return value


def run_retained(process, command, *, label, **kwargs):
    import time
    process.process_boundary().require_host_process_context()
    runs = []
    destination = Path(f"build/v02/baseline-process-controls/control-{time.monotonic_ns()}.json")
    with process.receipt_file(ROOT, destination) as stream:
        try:
            return process.run(command, runs=runs, **kwargs)
        finally:
            stream.write(json.dumps({"test": label, "processes": runs},
                                    sort_keys=True, indent=2) + "\n")


class BaselineRecordContract(unittest.TestCase):
    def run_control(self, process, command, **kwargs):
        return run_retained(process, command, label=self.id().split(".")[-1], **kwargs)

    def test_tracer_diagnostic_rom_rejects_outside_symlink(self):
        with tempfile.TemporaryDirectory(prefix="gw-phase5-build-input-") as temp:
            root = Path(temp).resolve()
            build = root / "build/desktop"
            client = build / "tools/session/gw_headless"
            client.parent.mkdir(parents=True)
            client.write_bytes(b"selected client")
            (build / "CMakeCache.txt").write_text("selected build")
            diagnostic = build / "diagnostic.bin"
            diagnostic.write_bytes(b"exact generated diagnostic")
            with mock.patch.object(baseline, "ROOT", root):
                self.assertEqual(baseline.diagnostic_rom_path(client), Path("build/desktop/diagnostic.bin"))
                diagnostic.unlink()
                with self.assertRaisesRegex(ValueError, "tracer diagnostic ROM is missing"):
                    baseline.diagnostic_rom_path(client)
                escaped = root.parent / (root.name + "-outside-diagnostic.bin")
                escaped.write_bytes(b"outside")
                self.addCleanup(lambda: escaped.unlink(missing_ok=True))
                diagnostic.symlink_to(escaped)
                with self.assertRaisesRegex(ValueError, "tracer diagnostic ROM is outside"):
                    baseline.diagnostic_rom_path(client)

    def test_tracer_diagnostic_rom_is_selected_build_input(self):
        with tempfile.TemporaryDirectory(prefix="gw-phase5-build-input-") as temp:
            root = Path(temp).resolve()
            build = root / "build/desktop"
            client = build / "tools/session/gw_headless"
            client.parent.mkdir(parents=True)
            client.write_bytes(b"selected client")
            (build / "CMakeCache.txt").write_text("selected build")
            diagnostic = build / "diagnostic.bin"
            diagnostic.write_bytes(b"exact generated diagnostic")
            with mock.patch.object(baseline, "ROOT", root):
                self.assertEqual(baseline.diagnostic_rom_path(client), Path("build/desktop/diagnostic.bin"))
                diagnostic.unlink()
                with self.assertRaisesRegex(ValueError, "tracer diagnostic ROM is missing"):
                    baseline.diagnostic_rom_path(client)

    def test_control_admission_preserves_existing_file_and_symlink(self):
        spec = importlib.util.spec_from_file_location("phase5_game", ROOT / "tests/fixtures/phase5_game.py")
        game = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(game)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            old_path = root / "build/phase5/control-admission-manifest.json"
            old_path.parent.mkdir(parents=True)
            rom = root / "control.bin"
            rom.write_bytes(b"test ROM")
            target = root / "preserve.txt"
            target.write_text("preserve target")
            for symlink in (False, True):
                if symlink:
                    old_path.symlink_to(target)
                else:
                    old_path.write_text("preserve file")
                runner = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=str(rom), stderr=""))
                module = SimpleNamespace(process_tools=lambda: SimpleNamespace(run=runner))
                with mock.patch.object(game, "ROOT", root), mock.patch.object(game, "load_baseline", return_value=module):
                    self.assertEqual(game.admitted("genewhip-independent-game-v2"), rom)
                command = runner.call_args.args[0]
                self.assertEqual(command[command.index("--manifest") + 1], "fixtures/manifest.json")
                self.assertEqual(old_path.read_text(), "preserve target" if symlink else "preserve file")
                self.assertEqual(old_path.is_symlink(), symlink)
                self.assertEqual(target.read_text(), "preserve target")
                old_path.unlink()

    def test_valid_record_round_trips(self):
        value = row()
        self.assertEqual(records.validate_record(value), value)

    def test_status_only_pass_is_rejected(self):
        value = row()
        del value["observations"]
        with self.assertRaisesRegex(ValueError, "observations"):
            records.validate_record(value)

    def test_wrong_identity_is_rejected_by_case_key(self):
        value = row()
        other = row(rom_sha256="9" * 64)
        self.assertNotEqual(records.case_key(value), records.case_key(other))

    def test_reordered_stage_history_is_rejected(self):
        document = {"schema": records.SCHEMA, "records": [
            row(stage=stage) for stage in ("build", "documentary", "reference", "core")
        ]}
        with self.assertRaisesRegex(ValueError, "in order"):
            records.validate_dataset(document)

    def test_empty_denominator_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-empty"):
            records.validate_dataset({"schema": records.SCHEMA, "records": []})

    def test_duplicate_stage_identity_is_rejected(self):
        duplicate = row(stage="documentary")
        document = {"schema": records.SCHEMA, "records": [
            duplicate, dict(duplicate), row(stage="reference"), row(stage="core")
        ]}
        with self.assertRaisesRegex(ValueError, "duplicate case/stage"):
            records.validate_dataset(document)

    def test_identity_mutation_between_stages_is_rejected(self):
        document = {"schema": records.SCHEMA, "records": [
            row(stage=stage) for stage in records.STAGES
        ]}
        document["records"][2]["source_revision"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "identity changed"):
            records.validate_dataset(document)

    def test_historical_infrastructure_spellings_convert_explicitly(self):
        self.assertEqual(records.convert_historical_status(1, "infrastructure_error"),
                         "infrastructure-error")
        self.assertEqual(records.convert_historical_status("phase4-v1", "infrastructure-error"),
                         "infrastructure-error")

    def test_unknown_historical_pair_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "schema/status"):
            records.convert_historical_status(2, "infrastructure_error")

    def test_historical_spelling_is_bound_to_its_source_schema(self):
        with self.assertRaisesRegex(ValueError, "schema/status"):
            records.convert_historical_status(1, "infrastructure-error")

    def test_tracer_output_is_confined_to_dedicated_build_path(self):
        self.assertEqual(baseline.tracer_output_path(Path("build/phase5/phase5-tracer.json")),
                         ROOT / "build/phase5/phase5-tracer.json")
        with self.assertRaisesRegex(ValueError, "build/phase5/phase5-tracer.json"):
            baseline.tracer_output_path(ROOT / "docs/overwrite.md")

    def roster(self):
        identity = lambda name: {"path": name, "sha256": "a" * 64, "bytes": 1}
        source_cases = json.loads((ROOT / "fixtures/independent-game-v2/scenario.json").read_text())["cases"]
        cases = []
        for fixture, kind, ids in (
            ("synthetic-control", "control", [c["id"] for c in source_cases]),
            ("synthetic-a", "candidate", ["a", "b", "c"]),
            ("synthetic-b", "candidate", ["a", "b", "c"]),
        ):
            for case_id in ids:
                case = {"fixture_id": fixture, "title_id": fixture, "case_id": case_id,
                        "kind": kind, "profile": "VA3-NTSC-U", "input_sha256": "a" * 64,
                        "input_events": [], "input_program": {"kind": "synthetic"}}
                for name in ("source", "build", "toolchain", "rom", "scenario", "oracle", "reference_evidence",
                             "admission", "recipe", "materials", "notices", "route_input_schedule",
                             "route_input_program", "reference_script", "reference_executable", "reference_build"):
                    case[name] = identity("synthetic/" + name)
                if kind == "control":
                    source = next(c for c in source_cases if c["id"] == case_id)
                    case.update(expectations=source["expect"], fields=source["frames"])
                cases.append(case)
        return {"schema": baseline.ROSTER_SCHEMA, "case_count": 12, "repetitions": [1, 2],
                "stages": list(baseline.STAGES), "cases": cases,
                **{name: identity("synthetic/" + name) for name in baseline.ROSTER_IDENTITIES}}

    def report(self):
        roster = self.roster()
        proofs = []
        for case in roster["cases"]:
            for rep in (1, 2):
                observation = None
                if case["kind"] == "control":
                    e = case["expectations"]
                    observation = {"id": case["case_id"], "outcome": "pass", "fields": case["fields"],
                        "unsupported": 0, "play_state": e["play_state"], "position": e["position_min"],
                        "psg": e["psg_writes"], "ac_range": 100 if e["psg_writes"] else 0,
                        "machine_digest": "a" * 16}
                proofs.append({"fixture_id": case["fixture_id"], "case_id": case["case_id"],
                    "repetition": rep, "client_sha256": roster["client"]["sha256"], "returncode": 0 if observation else 1,
                    "observation": observation, "rejection": None if observation else "invalid-rom",
                    "requested_fields": 60, "command": ["synthetic-unit-process"], "wall_seconds": .01})
        self.receipts = {"context": "synthetic-unit", "processes": proofs}
        return roster, {"schema": baseline.REPORT_SCHEMA, "repetitions": [1, 2],
                        "roster_sha256": baseline.digest(baseline.canonical(roster)),
                        "collection": {name + "_sha256": roster[name]["sha256"] for name in baseline.ROSTER_IDENTITIES},
                        "records": baseline.project_records(roster, self.receipts)}

    def validate(self, report, roster):
        return baseline.validate_report(report, roster, synthetic=True, receipts=self.receipts)

    def test_exact_full_denominator_and_two_720_field_control_passes(self):
        roster, report = self.report()
        self.assertEqual(len(self.validate(report, roster)["records"]), 120)

    def test_report_binds_roster_and_production_admission_identity(self):
        roster, report = self.report()
        del roster["consumer_adapter"]
        with self.assertRaisesRegex(ValueError, "consumer_adapter identity"):
            self.validate(report, roster)
        roster, report = self.report()
        roster["consumer_adapter"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "roster identity differs"):
            self.validate(report, roster)

    def test_missing_and_duplicate_rows_fail_at_named_denominator_assertion(self):
        roster, report = self.report()
        with self.assertRaisesRegex(ValueError, "120-row"):
            self.validate({**report, "records": report["records"][:-1]}, roster)
        duplicate = list(report["records"])
        duplicate[-1] = dict(duplicate[-2])
        with self.assertRaisesRegex(ValueError, "120-row"):
            self.validate({**report, "records": duplicate}, roster)

    def test_unsupported_stage_cannot_be_laundered_as_a_pass(self):
        roster, report = self.report()
        row = next(r for r in report["records"] if r["kind"] == "candidate")
        row.update(outcome="pass", reached=False, observations=None)
        with self.assertRaisesRegex(ValueError, "pass row lacks observable evidence"):
            self.validate(report, roster)

    def test_unsupported_row_cannot_claim_reached_even_with_identity_intact(self):
        roster, report = self.report()
        report["records"][0].update(outcome="unsupported", reached=True, observations={"verified": True})
        with self.assertRaisesRegex(ValueError, "cannot be marked reached"):
            self.validate(report, roster)

    def test_row_identity_mutations_rejected(self):
        for key in ("title_id", "kind", "profile", "scenario_sha256", "oracle_sha256", "input_sha256",
                    "rom_sha256", "client_sha256", "cmake_configuration_sha256"):
            with self.subTest(key=key):
                roster, report = self.report()
                report["records"][60][key] = "forged"
                with self.assertRaisesRegex(ValueError, "identity or named predicate"):
                    self.validate(report, roster)

    def test_actual_failed_load_cannot_become_verified_false_pass(self):
        roster, report = self.report()
        report["records"][60].update(outcome="pass", reached=True, observations={"verified": False})
        with self.assertRaisesRegex(ValueError, "identity or named predicate"):
            self.validate(report, roster)

    def test_self_consistent_status_reason_observation_forgery_rejected(self):
        roster, report = self.report()
        report["records"][60].update(outcome="pass", reached=True,
            reason="public core loaded admitted ROM", observations={"fields": 60, "stop_reason": 0})
        with self.assertRaisesRegex(ValueError, "identity or named predicate"):
            self.validate(report, roster)

    def test_every_control_case_requires_named_predicates(self):
        for index in range(0, 12, 2):
            roster, report = self.report()
            self.receipts["processes"][index]["observation"]["play_state"] = -1
            with self.assertRaisesRegex(ValueError, "control named source-state"):
                self.validate(report, roster)

    def test_collection_identities_bound(self):
        roster, report = self.report()
        report["collection"]["manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "collection identity"):
            self.validate(report, roster)

    def test_selected_wrong_client_rejected_before_admission_or_execution(self):
        from unittest.mock import patch
        game = baseline.load_module("baseline_game_test", ROOT / "tests/fixtures/phase5_game.py")
        roster = self.roster()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "roster.json"
            path.write_text(json.dumps(roster))
            with patch.object(game, "ROSTER", path), patch.object(game, "load_baseline", return_value=baseline), \
                    patch.object(baseline, "validate_roster", return_value=roster), \
                    patch.object(baseline, "file_identity", return_value={"sha256": "wrong-client"}), \
                    patch.object(game, "admitted") as admission:
                with self.assertRaisesRegex(ValueError, "before execution"):
                    game.collect()
                admission.assert_not_called()

    def test_skip_or_unsupported_cannot_be_laundered_with_coherent_pass(self):
        for stage in ("boot", "interaction", "sustained", "completion"):
            roster, report = self.report()
            row = next(r for r in report["records"] if r["kind"] == "candidate" and r["stage"] == stage)
            row.update(outcome="pass", reached=True, reason="source predicate passed",
                       observations={"fields": 720, "play_state": 1, "unsupported": 0})
            with self.assertRaisesRegex(ValueError, "identity or named predicate"):
                self.validate(report, roster)

    def test_observable_core_stop_is_failure_not_infrastructure_or_unsupported(self):
        case = next(c for c in self.roster()["cases"] if c["kind"] == "candidate")
        proof = {"returncode": 0, "requested_fields": 60,
                 "observation": {"fields": 60, "stop_reason": 4, "unsupported": 1,
                                 "instruction_address": 4096, "opcode": 1234, "fault_address": 4096, "ram_fnv1a64": "a" * 16}}
        self.assertEqual(baseline.stage_evidence(case, "boot", proof)[:2], ("fail", True))
        self.assertEqual(baseline.stage_evidence(case, "interaction", proof)[:2], ("skipped", False))

    def test_synthetic_context_cannot_claim_actual_process(self):
        roster, report = self.report()
        self.receipts["context"] = "actual-public-client"
        with self.assertRaisesRegex(ValueError, "context differs"):
            self.validate(report, roster)

    def test_current_roster_cannot_be_substituted_with_self_claimed_hash(self):
        roster = self.roster()
        from unittest.mock import patch
        with patch.object(baseline, "freeze_roster", return_value={"different": "source bytes"}):
            with self.assertRaisesRegex(ValueError, "current bytes or source cases"):
                baseline.validate_roster(roster)

    def test_private_evidence_rejected_without_echo(self):
        for key in ("reason", "observations", "command"):
            for marker in ("/" + "Users" + "/fixture-owner/private",
                           "api" + "_key=fixture-sentinel-value", "-----BEGIN " + "PRIVATE KEY-----"):
                roster, report = self.report()
                report["records"][60][key] = marker
                with self.assertRaisesRegex(ValueError, "privacy rejection") as error:
                    self.validate(report, roster)
                self.assertNotIn(marker, str(error.exception))

    def test_real_process_output_cap_timeout_and_status(self):
        process = baseline.process_tools()
        process.process_boundary().require_host_process_context()
        result = self.run_control(process, [sys.executable, "-c", "print(42)"], cwd=ROOT)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "42"))
        for script, kwargs, message in (
            ("import os; os.write(1,b'x'*8192)", {"cap": 1024}, "output byte cap"),
            ("import time; time.sleep(5)", {"timeout": .1}, "timeout"),
            ("import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(5)'])",
             {"timeout": .1}, "timeout")):
            with self.assertRaisesRegex(ValueError, message):
                self.run_control(process, [sys.executable, "-c", script], cwd=ROOT, **kwargs)
        for count in (1023, 1024):
            result = self.run_control(process, [sys.executable, "-c", f"import os; os.write(1,b'x'*{count})"], cwd=ROOT, cap=1024)
            self.assertEqual(len(result.stdout), count)
        with self.assertRaisesRegex(ValueError, "output byte cap"):
            self.run_control(process, [sys.executable, "-c", "import os; os.write(2,b'x'*1025)"], cwd=ROOT, cap=1024)

    def test_dependent_process_terminated_even_after_parent_exits(self):
        import time
        process = baseline.process_tools()
        process.process_boundary().require_host_process_context()
        with tempfile.TemporaryDirectory() as temp:
            ready, late = Path(temp) / "ready", Path(temp) / "late"
            child = ("from pathlib import Path; import time; "
                     f"Path({str(ready)!r}).touch(); time.sleep(.3); Path({str(late)!r}).touch()")
            parent = ("import subprocess,sys,time; from pathlib import Path; "
                      f"subprocess.Popen([sys.executable,'-c',{child!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                      f"p=Path({str(ready)!r}); "
                      "exec('for i in range(100):\\n if p.exists(): break\\n time.sleep(.01)'); "
                      "assert p.exists()")
            result = self.run_control(process, [sys.executable, "-c", parent], cwd=ROOT, timeout=2)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(ready.exists())
            time.sleep(.4)
            self.assertFalse(late.exists(), "dependent process survived process-group cleanup")

    def test_handoff_private_injection_has_named_rejection(self):
        roster, report = self.report()
        failures = [r for r in report["records"] if r["kind"] == "candidate" and r["outcome"] != "pass"]
        document = {"schema": "genewhip-phase5-failure-inventory-v1",
                    "baseline_sha256": baseline.digest(baseline.canonical(report)), "records": failures,
                    "note": "to" + "ken=synthetic-privacy-sentinel"}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "handoff.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "privacy rejection"):
                baseline.validate_handoff(path, report, synthetic=True)

    def test_failure_handoff_keeps_every_candidate_fail_skip_and_unknown(self):
        roster, report = self.report()
        failures = [row for row in report["records"] if row["kind"] == "candidate"
                    and row["outcome"] in ("fail", "unsupported", "skipped", "unknown", "infrastructure-error")]
        handoff = {"schema": "genewhip-phase5-failure-inventory-v1",
                   "baseline_sha256": baseline.digest(baseline.canonical(report)), "records": failures}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "handoff.json"
            path.write_text(json.dumps(handoff))
            baseline.validate_handoff(path, report, synthetic=True)
            handoff["records"].pop()
            path.write_text(json.dumps(handoff))
            with self.assertRaisesRegex(ValueError, "every candidate failure/skip/unknown"):
                baseline.validate_handoff(path, report, synthetic=True)


def main() -> int:
    arguments = sys.argv[1:]
    if arguments == ["--self-test", "--host-process-context"]:
        import os
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
        arguments = ["--self-test"]
    if arguments == ["--self-test"]:
        baseline.process_tools().process_boundary().require_host_process_context()
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(BaselineRecordContract)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if len(sys.argv) == 2 and sys.argv[1] == "--tracer":
        print("--tracer requires a built gw_headless path", file=sys.stderr)
        return 2
    if len(sys.argv) == 3 and sys.argv[1] == "--tracer":
        process = baseline.process_tools()
        process.process_boundary().require_host_process_context()
        return run_retained(process, [sys.executable, str(ROOT / "scripts/evidence/phase5_baseline.py"),
                    "--tracer", sys.argv[2], "--output",
                    str(ROOT / "build/phase5/phase5-tracer.json")], cwd=ROOT,
                   timeout=300, label="tracer-wrapper").returncode
    if len(sys.argv) == 3 and sys.argv[1] == "--validate":
        return run_retained(baseline.process_tools(), [sys.executable, str(ROOT / "scripts/evidence/phase5_baseline.py"),
                    "--validate", sys.argv[2]], cwd=ROOT, label="validate-wrapper").returncode
    print("usage: phase5_baseline_contract.py --self-test | --tracer HEADLESS", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
