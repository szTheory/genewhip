"""Semantic negative controls for the bounded reference-route contract."""
from __future__ import annotations

import importlib.util
import argparse
import unittest
from pathlib import Path
import sys
import tempfile
import json
import copy
import hashlib
import shutil
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("phase5_reference", ROOT / "tests/fixtures/phase5_reference.py")
ref = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ref)


def route():
    scenario = {
        "schema": "genewhip-phase5-route-v1", "title_id": "sample",
        "profile": "VA3-NTSC-U", "reset": "fresh-process; source-defined initial state; no RAM pokes",
        "budget": {"boot_fields": 60, "interaction_fields": 240, "active_fields": 3600, "total_fields": 3660},
        "controls": ["P1 B"], "input_schedule": [
            {"field": 1, "control": "P1 B", "asserted": False},
            {"field": 2, "control": "P1 B", "asserted": True}],
        "cases": [{"id": "play"}, {"id": "withheld", "withheld_predicate": "late"}],
        "identities": {"source": "local-fixtures/phase5/sample/source.s", "source_sha256": "a"*64,
                       "build_sha256": "b"*64, "rom_sha256": "c"*64, "input_sha256": "d"*64}}
    oracle = {"schema": "genewhip-phase5-oracle-v1", "title_id": "sample",
              "authority": "Pinned source semantics define intended behavior.",
              "predicates": [{"id": "first", "field_window": [100, 140], "signal": "score", "equals": 1},
                             {"id": "late", "field_window": [2800, 3200], "signal": "score", "equals": 2}]}
    return scenario, oracle


class ReferenceContract(unittest.TestCase):
    def _delivery_fixture(self):
        root,ledger,elig,recovery=self._observation_fixture()
        prior_path=ref.CORRECTION_AUTH
        for name,value in (("DECISION","D-118"),("CORRECTION_AUTH",Path("evidence/delivery-plan.json")),
                            ("CORRECTION_FREEZE",Path("evidence/delivery-freeze.json")),
                            ("CORRECTION_ATTEMPT",Path("evidence/delivery-attempt.json"))):
            self.enterContext(patch.object(ref,name,value))
        ref.write_json(root/ref.CORRECTION_AUTH,{"prior_plan":{"path":prior_path.as_posix()},
                       "prior_d117_report":{},"prior_d117_attempt":{},"diagnostic_receipt":{}})
        ref.write_json(root/ref.CORRECTION_FREEZE,{"plan_sha256":"plan"})
        package=ref._route_package("recursion94");package.mkdir(parents=True);(package/"mame.lua").write_text("-- fixture")
        self.enterContext(patch.object(recovery,"verify_inherited_tank"))
        return root,ledger,elig,recovery

    def test_delivery_has_six_fresh_calls_no_diagnostic_and_no_replay(self):
        root,ledger,elig,recovery=self._delivery_fixture()
        def capture(scenario,case,*args):
            return {"case":case["id"],"rows":[1],"inputs":[],"audio_file":{"peak":1},"raw_capture":{}}
        with patch.object(ref,"_run_case",side_effect=capture) as run,patch.object(recovery,"primary_check"),patch.object(ref,"check_predicates"):
            output=root/"evidence/phase5-reference-d118.json"
            self.assertEqual(recovery.qualify(ref,ledger,elig,output,None),0)
            self.assertEqual(run.call_count,6)
            attempt=ref.read_json(root/ref.CORRECTION_ATTEMPT)
            self.assertEqual((attempt["prior_processes"],attempt["combined_native_process_ceiling"]),(1,7))
            self.assertTrue(all(p["stage"]=="qualification" for p in attempt["processes"]))
            self.assertNotIn("diagnostic",ref.read_json(output))
            with self.assertRaisesRegex(ValueError,"already-consumed"):
                recovery.qualify(ref,ledger,elig,output,None)
            self.assertEqual(run.call_count,6)

    def test_delivery_stops_on_first_failure_without_using_remaining_slots(self):
        root,ledger,elig,recovery=self._delivery_fixture()
        with patch.object(ref,"_run_case",side_effect=ValueError("frozen-progress-failure")) as run:
            self.assertEqual(recovery.qualify(ref,ledger,elig,root/"evidence/phase5-reference-d118.json",None),2)
            self.assertEqual(run.call_count,1)
            self.assertEqual(ref.read_json(root/ref.CORRECTION_ATTEMPT)["status"],"failed")

    def _observation_fixture(self):
        root=Path(self.enterContext(tempfile.TemporaryDirectory()))
        for name,value in (("ROOT",root),("LOCAL",root/"local-fixtures/phase5"),("DECISION","D-117"),
                ("CORRECTION_AUTH",Path("evidence/phase5-reference-observation-recovery-plan.json")),
                ("CORRECTION_FREEZE",Path("evidence/phase5-reference-observation-freeze.json")),
                ("CORRECTION_ATTEMPT",Path("evidence/phase5-reference-observation-attempt.json"))):
            self.enterContext(patch.object(ref,name,value))
        recovery=ref._observation_recovery()
        scenario,oracle=route();scenario["title_id"]=oracle["title_id"]="recursion94"
        scenario["identities"]["rom_path"]="fixture.bin"
        scenario["cases"]=[{"id":"full-route"},{"id":"control1"},{"id":"control2"}]
        package=ref._route_package("recursion94");package.mkdir(parents=True);(package/"mame.lua").write_text("-- fixture")
        ref.write_json(root/ref.CORRECTION_AUTH,{"prior_d116_report":{"path":"old.json","sha256":"old"}})
        ref.write_json(root/ref.CORRECTION_FREEZE,{"plan_sha256":"plan","producer_sha256":"old-producer"})
        ref.write_json(root/"evidence/phase5-reference-recovery-freeze.json",{"producer_sha256":"old-producer"})
        ref.write_json(root/"old.json",{"routes":[{"title_id":"tank-battle","status":"pass"}]})
        ledger=root/"ledger.json";elig=root/"eligibility.json"
        ref.write_json(ledger,{"candidates":[{"id":"recursion94","lineage_id":"distinct","source_revision":"a"*40}]})
        ref.write_json(elig,{"candidates":[]})
        self.enterContext(patch.object(ref,"_author_check"));self.enterContext(patch.object(ref,"_require_committed"))
        self.enterContext(patch.object(ref,"_routes",return_value=[(scenario,oracle,ref.freeze_route(scenario,oracle))]))
        self.enterContext(patch.object(ref,"_lua_script",return_value="-- fixture"))
        self.enterContext(patch.object(recovery,"verify_freeze",return_value={"plan_sha256":"plan"}))
        return root,ledger,elig,recovery

    def test_observation_diagnostic_failure_stops_after_one_and_replay_rejects(self):
        root,ledger,elig,recovery=self._observation_fixture()
        case={"case":"full-route","rows":[],"raw_capture":{"run_id":"fixture"}}
        with patch.object(ref,"_run_case",return_value=case) as run, \
             patch.object(recovery,"primary_check",side_effect=ValueError("missing-source-predicate")):
            self.assertEqual(recovery.qualify(ref,ledger,elig,root/recovery.REPORT,None),2)
            self.assertEqual(run.call_count,1)
            self.assertEqual(ref.read_json(root/ref.CORRECTION_ATTEMPT)["status"],"failed")
            with self.assertRaisesRegex(ValueError,"already-consumed"):
                recovery.qualify(ref,ledger,elig,root/recovery.REPORT,None)
            self.assertEqual(run.call_count,1)

    def test_observation_allows_exactly_diagnostic_plus_six_fresh_cases(self):
        root,ledger,elig,recovery=self._observation_fixture()
        def capture(scenario,case,*args):
            return {"case":case["id"],"rows":[{"field":10,"signals":{"active_ticks":3600}}],
                    "inputs":[],"audio_file":{"peak":1},"raw_capture":{"run_id":"fixture"}}
        with patch.object(ref,"_run_case",side_effect=capture) as run, \
             patch.object(recovery,"primary_check"),patch.object(ref,"check_predicates"):
            self.assertEqual(recovery.qualify(ref,ledger,elig,root/recovery.REPORT,None),0)
            self.assertEqual(run.call_count,7)
            self.assertEqual(len(ref.read_json(root/ref.CORRECTION_ATTEMPT)["processes"]),7)

    def test_observation_disagreement_stops_before_controls(self):
        root,ledger,elig,recovery=self._observation_fixture()
        values=[{"case":"full-route","rows":[1],"raw_capture":{}},
                {"case":"full-route","rows":[2],"raw_capture":{}}]
        with patch.object(ref,"_run_case",side_effect=values) as run,patch.object(recovery,"primary_check"):
            self.assertEqual(recovery.qualify(ref,ledger,elig,root/recovery.REPORT,None),2)
            self.assertEqual(run.call_count,2)
            self.assertIn("diagnostic-primary-disagreement",ref.read_json(root/recovery.REPORT)["errors"][0]["reason"])

    def test_observation_script_rejects_guest_write_and_non_nil_return(self):
        recovery=ref._observation_recovery()
        script='GW_PHASE_TAP = assert(space:install_write_tap(1,2,"x", function(offset, data, mask) return nil end), "phase tap unavailable")'
        recovery.validate_script(script)
        for unsafe in (script.replace("return nil","return 0"),script+"\nspace:write_u8(1,2)"):
            with self.assertRaisesRegex(ValueError,"unsafe-script|must-return-nil"):
                recovery.validate_script(unsafe)

    def _recovery_fixture(self):
        root, ledger_path, eligibility_path = self._correction_fixture()
        for name, value in (("DECISION", "D-116"),
                            ("CORRECTION_AUTH", Path("evidence/phase5-reference-recovery-authorization.json")),
                            ("CORRECTION_FREEZE", Path("evidence/phase5-reference-recovery-freeze.json")),
                            ("CORRECTION_ATTEMPT", Path("evidence/phase5-reference-recovery-attempt.json"))):
            self.enterContext(patch.object(ref, name, value))
        ledger, eligibility = ref.read_json(ledger_path), ref.read_json(eligibility_path)
        anchors = {"fixtures/candidate-screening-v2.json": ledger_path.read_bytes(),
                   "evidence/phase5-eligibility-v2.json": eligibility_path.read_bytes()}
        self.enterContext(patch.object(ref, "_historical_blob", side_effect=lambda revision,name: anchors[name]))
        old_auth = ref.read_json(root / "evidence/phase5-reference-correction-authorization.json")
        frozen = ref.read_json(root / "evidence/phase5-reference-correction-freeze.json")
        auth = {**old_auth, "decision": "D-116", "prior_revision": "fixture",
                "prior_ledger_sha256": hashlib.sha256(anchors["fixtures/candidate-screening-v2.json"]).hexdigest(),
                "prior_eligibility_sha256": hashlib.sha256(anchors["evidence/phase5-eligibility-v2.json"]).hexdigest()}
        auth["scope"].update({name: False for name in
                             ("new_builds", "new_titles", "weaken_gameplay_predicates", "candidate_baseline_before_pair", "phase6")})
        for path, key in (("evidence/phase5-reference.json", "prior_reference_sha256"),
                          ("evidence/phase5-reference-correction-attempt.json", "prior_d115_attempt_sha256")):
            ref.write_json(root / path, {"immutable": "D-115 failed"})
            auth[key] = ref.sha(root / path)
        for row in ledger["candidates"]:
            title = row["id"]
            prior = auth["prior_titles"][title]
            entry = frozen["routes"][title]
            prior.update(package=entry["package"], files=copy.deepcopy(entry["files"]), counters=copy.deepcopy(row["counters"]))
            if title == "tank-battle":
                old = root / entry["package"]
                entry["package"] = entry["package"].replace("route-v2", "route-v3")
                shutil.copytree(old, root / entry["package"])
            row["identity_history"].append({"event": "identity_observed", "sha256": "new-event", "details": {
                "decision": "D-116", "frozen": entry["frozen"], "exception_cycle_charge": 1}})
        ref.write_json(root / ref.CORRECTION_AUTH, auth)
        frozen.update(decision="D-116", authorization_sha256=ref.sha(root / ref.CORRECTION_AUTH))
        for row in ledger["candidates"]:
            row["identity_history"][-1]["details"]["authorization_sha256"] = frozen["authorization_sha256"]
        ref.write_json(root / ref.CORRECTION_FREEZE, frozen)
        ref.write_json(ledger_path, ledger)
        return root, ledger_path, eligibility_path

    def test_recovery_uses_distinct_consumed_receipt_without_counter_increment(self):
        root, ledger, eligibility = self._recovery_fixture()
        old_attempt = (root / "evidence/phase5-reference-correction-attempt.json").read_bytes()
        ref._verify_correction_freeze(ledger, eligibility)
        with patch.object(ref, "_require_committed"):
            started = ref._begin_correction_cycle(ledger, eligibility)
            self.assertEqual(started["decision"], "D-116")
            with self.assertRaisesRegex(ValueError, "already-consumed"):
                ref._begin_correction_cycle(ledger, eligibility)
        self.assertEqual((root / "evidence/phase5-reference-correction-attempt.json").read_bytes(), old_attempt)
        current = ref.read_json(ledger)
        current["candidates"][0]["counters"]["route_authoring_corrections"] = 2
        ref.write_json(ledger, current)
        with self.assertRaisesRegex(ValueError, "counter-or-build-change"):
            ref._verify_correction_freeze(ledger, eligibility)

    def test_recovery_rejects_d115_history_tamper_and_missing_exception_charge(self):
        root, ledger, eligibility = self._recovery_fixture()
        old = root / "evidence/phase5-reference.json"
        saved = old.read_bytes(); old.write_bytes(b"tamper")
        with self.assertRaisesRegex(ValueError, "d115-history-changed"):
            ref._verify_correction_freeze(ledger, eligibility)
        old.write_bytes(saved)
        current = ref.read_json(ledger)
        current["candidates"][0]["identity_history"][-1]["details"]["exception_cycle_charge"] = 0
        ref.write_json(ledger, current)
        with self.assertRaisesRegex(ValueError, "journal-charge"):
            ref._verify_correction_freeze(ledger, eligibility)

    def test_recovery_interrupt_and_wrong_output_cannot_launch_again(self):
        root, ledger, eligibility = self._recovery_fixture()
        with patch.object(ref, "_require_committed"), patch.object(ref, "_author_check"), \
             patch.object(ref, "_qualify_next_impl", side_effect=RuntimeError("fixture interruption")) as run:
            with self.assertRaisesRegex(ValueError, "output-path"):
                ref._qualify_next(ledger, eligibility, root / "evidence/phase5-reference.json")
            run.assert_not_called()
            output = root / "evidence/phase5-reference-d116.json"
            with self.assertRaisesRegex(RuntimeError, "fixture interruption"):
                ref._qualify_next(ledger, eligibility, output)
            with self.assertRaisesRegex(ValueError, "already-consumed"):
                ref._qualify_next(ledger, eligibility, output)
            self.assertEqual(run.call_count, 1)

    def _correction_fixture(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(ref, "ROOT", root))
        self.enterContext(patch.object(ref, "LOCAL", root / "local-fixtures/phase5"))
        auth = {"decision": "D-115", "status": "granted", "scope": {
            "titles": list(ref.TITLES), "qualification_cycles": 1, "repetitions_per_case": 2,
            "active_fields": 3600, "total_fields_ceiling": 7200, "further_retry": False}, "prior_titles": {}}
        ledger, eligibility = {"candidates": []}, {"candidates": []}
        frozen = {"status": "source-frozen", "producer_sha256": ref.sha(Path(ref.__file__)), "routes": {}}
        for title in ref.TITLES:
            old = Path(f"local-fixtures/phase5/{title}/route-v1")
            new = Path(f"local-fixtures/phase5/{title}/route-v2")
            (root / old).mkdir(parents=True)
            (root / old / "scenario.json").write_text("original failed scenario\n")
            scenario, oracle = route(); scenario["title_id"] = oracle["title_id"] = title
            ref.write_json(root / old / "scenario.json", {"identities": scenario["identities"]})
            ref.write_json(root / new / "scenario.json", scenario)
            ref.write_json(root / new / "oracle.json", oracle)
            (root / new / "mame.lua").write_text("-- source-frozen fixture\n")
            identity = ref.freeze_route(scenario, oracle)
            frozen["routes"][title] = {"package": new.as_posix(), "frozen": identity,
                "files": {name: ref.sha(root / new / name) for name in ("scenario.json", "oracle.json", "mame.lua")}}
            auth["prior_titles"][title] = {"package": old.as_posix(), "last_event_sha256": "original-event",
                "files": {"scenario.json": ref.sha(root / old / "scenario.json")},
                "counters": {"route_authoring_corrections": 0, "rom_build_invocations": 2},
                "build_evidence": {"immutable": "build-receipt"}}
            ledger["candidates"].append({"id": title, "identity_history": [{"sha256": "original-event"}],
                "counters": {"route_authoring_corrections": 1, "rom_build_invocations": 2},
                "build_evidence": {"immutable": "build-receipt"}})
            eligibility["candidates"].append({"title_id": title, "reference_route": {"frozen": identity}})
        ref.write_json(root / ref.CORRECTION_AUTH, auth)
        frozen["authorization_sha256"] = ref.sha(root / ref.CORRECTION_AUTH)
        ref.write_json(root / ref.CORRECTION_FREEZE, frozen)
        ref.write_json(root / "ledger.json", ledger)
        ref.write_json(root / "eligibility.json", eligibility)
        return root, root / "ledger.json", root / "eligibility.json"

    def test_correction_cycle_is_consumed_before_work_and_cannot_replay(self):
        root, ledger, eligibility = self._correction_fixture()
        with patch.object(ref, "_require_committed"):
            started = ref._begin_correction_cycle(ledger, eligibility)
            self.assertEqual(started["status"], "started")
            self.assertEqual(ref.read_json(root / ref.CORRECTION_ATTEMPT), started)
            with self.assertRaisesRegex(ValueError, "already-consumed"):
                ref._begin_correction_cycle(ledger, eligibility)
            with self.assertRaisesRegex(ValueError, "single-whole-pair-cycle"):
                ref._begin_correction_cycle(ledger, eligibility, "tank-battle")

    def test_correction_rejects_changed_frozen_bytes_and_build_counter_reset(self):
        root, ledger, eligibility = self._correction_fixture()
        ref._verify_correction_freeze(ledger, eligibility)
        script = root / "local-fixtures/phase5/tank-battle/route-v2/mame.lua"
        before = script.read_bytes(); script.write_bytes(before + b"-- changed\n")
        with self.assertRaisesRegex(ValueError, "frozen-file-changed"):
            ref._verify_correction_freeze(ledger, eligibility)
        script.write_bytes(before)
        current = ref.read_json(ledger); current["candidates"][0]["counters"]["rom_build_invocations"] = 0
        ref.write_json(ledger, current)
        with self.assertRaisesRegex(ValueError, "counter-or-build-change"):
            ref._verify_correction_freeze(ledger, eligibility)

    def test_correction_interrupt_is_terminal_without_another_native_call(self):
        root, ledger, eligibility = self._correction_fixture()
        with patch.object(ref, "_require_committed"), patch.object(ref, "_author_check"), \
             patch.object(ref, "_qualify_next_impl", side_effect=RuntimeError("fixture interruption")) as run:
            with self.assertRaisesRegex(RuntimeError, "fixture interruption"):
                ref._qualify_next(ledger, eligibility, root / "result.json")
            self.assertEqual(ref.read_json(root / ref.CORRECTION_ATTEMPT)["status"], "failed")
            with self.assertRaisesRegex(ValueError, "already-consumed"):
                ref._qualify_next(ledger, eligibility, root / "another-output.json")
            self.assertEqual(run.call_count, 1)

    def test_input_program_changes_are_part_of_input_identity(self):
        scenario, _ = route()
        scenario["input_program"] = {"actions": [{"hold": "P1 B"}]}
        before = ref._input_digest(scenario)
        scenario["input_program"]["actions"][0]["hold"] = "P1 A"
        self.assertNotEqual(before, ref._input_digest(scenario))

    def test_input_capture_rejects_unknown_controls_and_conflicting_transitions(self):
        scenario, _ = route()
        valid = b"GWINPUT,play,10,P1 B,true\nGWINPUT,play,11,P1 B,false\n"
        self.assertEqual(len(ref._parse_inputs(valid, scenario, "play")), 2)
        for data in (b"GWINPUT,play,10,P2 B,true\n",
                     valid + b"GWINPUT,play,10,P1 B,true\n",
                     b"GWINPUT,play,10,P1 B,true\nGWINPUT,play,10,P1 B,false\n"):
            with self.assertRaisesRegex(ValueError, "reference-input-capture"):
                ref._parse_inputs(data, scenario, "play")

    def test_declared_program_supports_empty_legacy_schedule_but_not_null(self):
        scenario, oracle = route()
        scenario["input_schedule"] = []
        scenario["input_program"] = {"kind": "read-only-controller", "actions": ["fire"]}
        ref.freeze_route(scenario, oracle)
        scenario["input_schedule"] = None
        with self.assertRaisesRegex(ValueError, "route-input-schedule"):
            ref.freeze_route(scenario, oracle)

    def test_active_endpoint_is_allowed_only_when_frozen_and_fully_observed(self):
        scenario, _ = route(); scenario["progress_clock"] = "active_ticks"
        rows = [{"field": 3601, "signals": {"active_ticks": 3600}}]
        self.assertFalse(ref._capture_complete(rows, scenario))
        scenario["stop_rule"] = {"kind": "active-fields-or-total", "active_fields": 3600}
        self.assertTrue(ref._capture_complete(rows, scenario))
        rows[0]["signals"]["active_ticks"] = 3599
        self.assertFalse(ref._capture_complete(rows, scenario))

    def test_streaming_cap_retains_only_bounded_stdout_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "fixture.py"
            executable.write_text(f'#!{sys.executable}\nimport sys\nsys.stdout.write("x" * 10000)\n')
            executable.chmod(0o755)
            rom = root / "fixture.bin"; rom.write_bytes(b"parser rejection fixture")
            lock = root / "lock.json"
            lock.write_text(json.dumps({"mame": {"executable_build_sha256": ref.sha(executable)}}))
            scenario, _ = route(); scenario["identities"]["rom_sha256"] = ref.sha(rom)
            with patch.object(ref, "ROOT", root), patch.object(ref, "LOCAL", root / "local-fixtures/phase5"), \
                 patch.object(ref, "MAME", executable), patch.object(ref, "LOCK", lock), \
                 patch.object(ref, "MAX_STDOUT", 128):
                with self.assertRaisesRegex(ref.CaptureFailure, "stdout-byte-budget") as raised:
                    ref._run_case(scenario, scenario["cases"][0], rom, "-- fixture")
                receipt = root / raised.exception.observations["raw_capture"]["receipt"]
                self.assertEqual((receipt.parent / "stdout").stat().st_size, 128)
                self.assertEqual(ref.read_json(receipt)["capture_status"], "error")

    def test_control_missing_progress_clock_is_not_a_causal_pass(self):
        scenario, oracle = route(); scenario["progress_clock"] = "active_ticks"
        captures = {"play": [{"field": 120, "signals": {"active_ticks": 120, "score": 1}},
                              {"field": 3000, "signals": {"active_ticks": 3000, "score": 2}}],
                    "withheld": [{"field": 3000, "signals": {"score": 1}}]}
        with self.assertRaisesRegex(ValueError, "missing-signal"):
            ref.check_predicates(scenario, oracle, captures)

    def test_distinct_statuses_without_two_actual_repetitions_reject(self):
        scenario, oracle = route(); frozen = ref.freeze_route(scenario, oracle)
        other = dict(scenario, title_id="other"); other_oracle = dict(oracle, title_id="other")
        other_frozen = ref.freeze_route(other, other_oracle)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "forged.json"
            path.write_text(json.dumps({"schema": "genewhip-phase5-reference-v1", "status": "pass",
                "candidate_genewhip_baseline": "not-run", "routes": [
                    {"title_id": "sample", "lineage_id": "a", "status": "pass", "frozen": frozen},
                    {"title_id": "other", "lineage_id": "b", "status": "pass", "frozen": other_frozen}]}))
            with patch.object(ref, "_author_check"), patch.object(ref, "_routes", return_value=[
                    (scenario, oracle, frozen), (other, other_oracle, other_frozen)]):
                with self.assertRaisesRegex(ValueError, "fresh-repetitions"):
                    ref._verify_pair(path)

    def test_failed_native_capture_keeps_raw_bytes_and_receipt(self):
        # This authored program is a malformed-output fixture, not MAME or a ROM.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "fixture.py"
            executable.write_text(f'#!{sys.executable}\nprint("GWCAP,broken")\n')
            executable.chmod(0o755)
            rom = root / "fixture.bin"
            rom.write_bytes(b"synthetic parser rejection input")
            lock = root / "lock.json"
            lock.write_text(json.dumps({"mame": {"executable_build_sha256": ref.sha(executable)}}))
            scenario, _ = route()
            scenario["identities"]["rom_sha256"] = ref.sha(rom)
            with patch.object(ref, "ROOT", root), patch.object(ref, "LOCAL", root / "local-fixtures/phase5"), \
                 patch.object(ref, "MAME", executable), patch.object(ref, "LOCK", lock):
                with self.assertRaisesRegex(ref.CaptureFailure, "malformed-row") as raised:
                    ref._run_case(scenario, scenario["cases"][0], rom, "-- authored fixture\n")
                raw = raised.exception.observations["raw_capture"]
                receipt_path = root / raw["receipt"]
                self.assertTrue(receipt_path.is_file())
                self.assertEqual(ref.sha(receipt_path), raw["receipt_sha256"])
                self.assertEqual((receipt_path.parent / "stdout").read_bytes(), b"GWCAP,broken\n")
                self.assertEqual((receipt_path.parent / "capture.csv").read_bytes(), b"GWCAP,broken\n")
                self.assertEqual(ref.read_json(receipt_path)["capture_status"], "error")

    def test_budget_failure_preserves_all_completed_cases_and_clock_maximum(self):
        scenario, oracle = route()
        scenario["progress_clock"] = "active_ticks"
        scenario["addresses"] = [{"name": "active_ticks", "address": "FF0000"}]
        def capture(scenario, case, *args):
            return {"case": case["id"], "rows": [{"field": 30, "signals": {"active_ticks": 17}}]}
        with patch.object(ref, "_run_case", side_effect=capture) as runner:
            with self.assertRaisesRegex(ref.CaptureFailure, "active-field-budget") as raised:
                ref.qualify_candidate(scenario, oracle, Path("unused"), "-- fixture")
        observed = raised.exception.observations
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(observed["completed_case_runs"], 2)
        self.assertEqual(observed["not_run_cases"], [])
        self.assertEqual(observed["repetitions_not_run"], [2])
        self.assertEqual(observed["active_clock_observation"]["maximum"], 17)
        self.assertEqual(len(observed["runs"][0]["cases"]), 2)

    def test_a_new_output_filename_cannot_repeat_an_observed_route(self):
        with tempfile.TemporaryDirectory() as directory:
            eligibility = Path(directory) / "eligibility.json"
            eligibility.write_text(json.dumps({"candidates": [{"title_id": "tank-battle",
                "reference_route": {"reference_observation": {"status": "unknown"}}}]}))
            with patch.object(ref, "_author_check") as author, patch.object(ref, "_run_case") as runner:
                with self.assertRaisesRegex(ValueError, "observed-route-requires-explicit-disposition"):
                    ref._qualify_next(Path("unused"), eligibility, Path(directory) / "fresh.json")
            author.assert_not_called()
            runner.assert_not_called()

    def test_pair_statuses_cannot_replace_distinct_lineage_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "forged.json"
            path.write_text(json.dumps({"schema": "genewhip-phase5-reference-v1", "status": "pass",
                "candidate_genewhip_baseline": "not-run", "routes": [
                    {"title_id": "a", "lineage_id": "same", "status": "pass"},
                    {"title_id": "b", "lineage_id": "same", "status": "pass"}]}))
            with self.assertRaisesRegex(ValueError, "distinct-lineages"):
                ref._verify_pair(path)

    def test_regressing_field_and_beyond_budget_rows_reject(self):
        scenario, _ = route()
        for data in (b'GWCAP,play,1,60,score=0\nGWCAP,play,2,30,score=1\n',
                     b'GWCAP,play,1,9999,score=0\n'):
            with self.assertRaisesRegex(ValueError, "row-order-or-identity"):
                ref.parse_capture(data, scenario)

    def test_old_progress_value_cannot_satisfy_a_late_milestone(self):
        scenario, oracle = route()
        captured = {"play": [{"field": 120, "signals": {"score": 1}},
                              {"field": 600, "signals": {"score": 2}},
                              {"field": 3000, "signals": {"score": 2}}],
                    "withheld": [{"field": 3000, "signals": {"score": 1}}]}
        with self.assertRaisesRegex(ValueError, "progress-before-window:late"):
            ref.check_predicates(scenario, oracle, captured)

    def test_valid_source_frozen_route_binds_identities(self):
        scenario, oracle = route()
        self.assertEqual(ref.freeze_route(scenario, oracle)["title_id"], "sample")

    def test_null_input_schedule_is_rejected(self):
        scenario, oracle = route(); scenario["input_schedule"] = None
        with self.assertRaisesRegex(ValueError, "route-input-schedule"):
            ref.freeze_route(scenario, oracle)

    def test_conflicting_same_tick_button_events_are_rejected(self):
        scenario, oracle = route()
        scenario["input_schedule"].append({"field": 2, "control": "P1 B", "asserted": False})
        with self.assertRaisesRegex(ValueError, "conflicting-same-control"):
            ref.freeze_route(scenario, oracle)

    def test_overlapping_predicate_windows_remain_distinct_and_fail(self):
        scenario, oracle = route(); oracle["predicates"][1]["field_window"] = [140, 180]
        with self.assertRaisesRegex(ValueError, "not-separated"):
            ref.freeze_route(scenario, oracle)

    def test_late_milestone_is_required(self):
        scenario, oracle = route(); oracle["predicates"][1]["field_window"] = [500, 600]
        with self.assertRaisesRegex(ValueError, "late-milestone"):
            ref.freeze_route(scenario, oracle)

    def test_budget_ceiling_is_checked_before_observation(self):
        scenario, oracle = route(); scenario["budget"]["total_fields"] = 7201
        with self.assertRaisesRegex(ValueError, "ceiling"):
            ref.freeze_route(scenario, oracle)

    def test_malformed_and_out_of_order_selected_rows_reject(self):
        scenario, _ = route()
        with self.assertRaisesRegex(ValueError, "malformed-row"):
            ref.parse_capture(b"{bad}\n", scenario)
        rows = b'GWCAP,play,2,30,score=0\nGWCAP,play,1,60,score=1\n'
        with self.assertRaisesRegex(ValueError, "row-order"):
            ref.parse_capture(rows, scenario)

    def test_trace_and_summary_limits_are_enforced(self):
        scenario, _ = route()
        with self.assertRaisesRegex(ValueError, "byte-budget"):
            ref.parse_capture(b" " * (ref.MAX_TRACE + 1), scenario)
        with self.assertRaisesRegex(ValueError, "summary-byte-budget"):
            ref.write_json(Path("/tmp/phase5-too-large.json"), {"data": "x" * ref.MAX_SUMMARY})

    def test_wrong_case_or_missing_progress_predicate_rejects(self):
        scenario, oracle = route()
        with self.assertRaisesRegex(ValueError, "case-roster"):
            ref.check_predicates(scenario, oracle, {"play": []})
        captures = {"play": [{"field": 120, "signals": {"score": 1}},
                              {"field": 3000, "signals": {"score": 2}}],
                    "withheld": [{"field": 120, "signals": {"score": 0}},
                                 {"field": 3000, "signals": {"score": 2}}]}
        with self.assertRaisesRegex(ValueError, "causal-withheld:late"):
            ref.check_predicates(scenario, oracle, captures)

    def test_progress_clock_uses_active_ticks_for_primary_and_control(self):
        scenario, oracle = route()
        scenario["progress_clock"] = "active_ticks"
        oracle["predicates"][0]["field_window"] = [10, 20]
        oracle["predicates"][1]["field_window"] = [2800, 3200]
        captures = {"play": [
            {"field": 600, "signals": {"active_ticks": 15, "score": 1}},
            {"field": 3300, "signals": {"active_ticks": 2900, "score": 2}}],
            "withheld": [{"field": 3300, "signals": {"active_ticks": 2900, "score": 1}}]}
        ref.check_predicates(scenario, oracle, captures)
        captures["withheld"][0]["signals"]["score"] = 2
        with self.assertRaisesRegex(ValueError, "causal-withheld:late"):
            ref.check_predicates(scenario, oracle, captures)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", required=True)
    parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReferenceContract)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
