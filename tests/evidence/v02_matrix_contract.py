#!/usr/bin/env python3
"""Contract checks for portable v0.2 compatibility evidence."""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "scripts/evidence/v02_matrix.py"
SCHEMA_PATH = ROOT / "evidence/v02-schema.json"
DEPENDENCIES_PATH = ROOT / "evidence/v02-proof-dependencies.json"


def require_process_context():
    spec = importlib.util.spec_from_file_location("gw_matrix_admission", ROOT / "tests/session/phase6_route_contract.py")
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)
    boundary.require_host_process_context()


class PublicMatrixContract(unittest.TestCase):
    @staticmethod
    def _module():
        spec = importlib.util.spec_from_file_location("v02_matrix_public_contract", MATRIX_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("v0.2 production matrix consumer is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_complete_independent_matrix_roster_has_fixed_denominators(self) -> None:
        module = self._module()
        self.assertTrue(callable(getattr(module, "validate_matrix_roster", None)),
                        "production matrix roster validator is missing")
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        self.assertEqual(module.validate_matrix_roster(roster), roster)
        self.assertEqual(roster["matrix"]["denominators"], {
            "titles": 3, "authored_source_lineages": 3, "scenarios": 3,
            "core_executions": 24, "core_stage_cells": 120,
            "software_sdl_cases": 6, "native_sdl_cases": 6,
        })
        self.assertEqual(set(roster["matrix"]["outcomes"]), {
            "pass", "fail", "unsupported", "skipped", "unknown", "infrastructure-error"})
        self.assertEqual(roster["matrix"]["stages"], ["load", "boot", "interaction", "sustained", "completion"])
        self.assertEqual(roster["completion_policy"], "unknown-unless-separate-source-oracle-proves-completion")
        history = roster["matrix"]["history"]
        self.assertEqual([row["id"] for row in history["screening_dispositions"]],
                         ["tank-battle", "alex-vs-bus", "space-shooter", "recursion94", "kleleatoms-md"])
        self.assertFalse(history["independently_verifiable"])

    def test_matrix_validation_uses_full_identity_and_source_progress(self) -> None:
        module = self._module()
        self.assertTrue(callable(getattr(module, "expected_matrix_rows", None)),
                        "production consumer does not derive complete matrix keys")
        self.assertTrue(callable(getattr(module, "validate_matrix_observation", None)),
                        "production matrix observation validator is missing")
        self.assertTrue(callable(getattr(module, "validate_matrix_observations", None)),
                        "production matrix roster assertion is missing")
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        rows = module.expected_matrix_rows(roster)
        self.assertEqual(len(rows), 180)
        # A load pass requires load evidence; progress is asserted on the interaction row.
        row = dict(rows[0])
        row.update(outcome="pass", reason="fixture loaded and identity matched", reached=True,
                   observation_dependencies={name: rows[0]["identity"][name] for name in
            ("scenario_sha256", "oracle_sha256", "rom_sha256", "source_sha256", "build_sha256",
             "configuration_sha256", "input_sha256", "delivery_map_sha256", "media_expectations_sha256")},
                   observations={"rom_loaded": True, "fixture_identity_matches": True})
        module.validate_matrix_observation(row, rows[0])
        interaction = rows[2]
        interacting = dict(interaction, outcome="pass", reason="source-derived interaction observed", reached=True,
                   observation_dependencies={name: interaction["identity"][name] for name in
             ("scenario_sha256", "oracle_sha256", "rom_sha256", "source_sha256", "build_sha256",
              "configuration_sha256", "input_sha256", "delivery_map_sha256", "media_expectations_sha256")},
                   observations={"play_state": 1, "position_in_source_range": True, "causal_control": True})
        module.validate_matrix_observation(interacting, interaction)
        bad = dict(interacting, observations={"play_state": 0, "position_in_source_range": True, "causal_control": True})
        with self.assertRaisesRegex(ValueError, "matrix-source-progress-invalid"):
            module.validate_matrix_observation(bad, interaction)
        unreached = dict(interacting, reached=False)
        with self.assertRaisesRegex(ValueError, "matrix-pass-not-reached"):
            module.validate_matrix_observation(unreached, interaction)
        no_evidence = dict(interacting, observation_dependencies={})
        with self.assertRaisesRegex(ValueError, "matrix-observation-dependency-missing"):
            module.validate_matrix_observation(no_evidence, interaction)

    def test_completion_pass_requires_a_separate_completion_oracle(self) -> None:
        module = self._module()
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        expected = next(row for row in module.expected_matrix_rows(roster) if row["stage"] == "completion")
        row = dict(expected, outcome="pass", reason="claimed completion", reached=True,
            observation_dependencies={name: expected["identity"][name] for name in
                ("scenario_sha256", "oracle_sha256", "rom_sha256", "source_sha256", "build_sha256",
                 "configuration_sha256", "input_sha256", "delivery_map_sha256", "media_expectations_sha256")},
            observations={"completion_oracle_proven": False, "completion_predicate": True})
        with self.assertRaisesRegex(ValueError, "matrix-completion-oracle-missing"):
            module.validate_matrix_observation(row, expected)

    def test_matrix_rejects_missing_rows_wrong_client_and_forged_denominator(self) -> None:
        module = self._module()
        self.assertTrue(callable(getattr(module, "expected_matrix_rows", None)),
                        "production consumer does not derive complete matrix keys")
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        rows = module.expected_matrix_rows(roster)
        with self.assertRaisesRegex(ValueError, "matrix-roster-mismatch"):
            module.validate_matrix_observations(rows[:-1], roster)
        wrong_client = dict(rows[0], outcome="unknown", reason="not measured", reached=False,
            observation_dependencies={}, observations={}, client_scope="native-sdl")
        with self.assertRaisesRegex(ValueError, "matrix-client-scope-mismatch"):
            module.validate_matrix_observation(wrong_client, rows[0])
        wrong_count = json.loads(json.dumps(roster))
        wrong_count["matrix"]["denominators"]["core_stage_cells"] = 119
        with self.assertRaisesRegex(ValueError, "matrix-denominator-mismatch"):
            module.validate_matrix_roster(wrong_count)
        missing_capability = json.loads(json.dumps(roster))
        del missing_capability["matrix"]["titles"][0]["client_identity"]["native-sdl"]
        with self.assertRaisesRegex(ValueError, "matrix-client-identity-invalid"):
            module.validate_matrix_roster(missing_capability)
        empty = json.loads(json.dumps(roster))
        empty["matrix"]["titles"] = []
        with self.assertRaisesRegex(ValueError, "matrix-title-roster-invalid"):
            module.validate_matrix_roster(empty)

    def test_production_consumer_exists(self) -> None:
        self.assertTrue(MATRIX_PATH.is_file(), "v0.2 production matrix consumer is missing")

    def test_forged_pass_reaches_source_observation_assertion(self) -> None:
        spec = importlib.util.spec_from_file_location("v02_matrix_under_test", MATRIX_PATH)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        row = {"case_id": "start-move", "status": "pass", "fields": 40,
               "play_state": 1, "position": 9, "psg_writes": [],
               "input_sha256": "a" * 64, "pcm_sha256": "b" * 64, "video_sha256": "c" * 64,
               "source_predicates": {"play_state": True, "position_in_source_range": False,
                                      "causal_control": True}}
        identity = {"fixture_id": "test-fixture", "profile": "VA3-NTSC-U", "machine": {"driver": "genesis"},
                    "scenario_sha256": "d" * 64, "oracle_sha256": "d" * 64,
                    "rom_sha256": "d" * 64, "source_sha256": "d" * 64,
                    "cmake_cache_sha256": "d" * 64, "executable_sha256": "d" * 64}
        bundle = {"schema": "genewhip-v02-evidence-v1", "scope": "control-tracer", "source_identity": identity,
                  "roster": ["start-move"], "observations": [row], "artifacts": {"receipt_sha256": "d" * 64}}
        with self.assertRaisesRegex(ValueError, "observation-source-predicate-invalid"):
            module.validate_public_bundle(bundle, expected_keys=["start-move"])
        private_bundle = json.loads(json.dumps(bundle))
        private_bundle["source_identity"]["fixture_id"] = "/" + "Users" + "/sample"
        with self.assertRaisesRegex(ValueError, "public-private-path-or-record"):
            module.validate_public_bundle(private_bundle, expected_keys=["start-move"])
        missing_identity = json.loads(json.dumps(bundle))
        del missing_identity["source_identity"]["executable_sha256"]
        with self.assertRaisesRegex(ValueError, "source-identity-shape-invalid"):
            module.validate_public_bundle(missing_identity, expected_keys=["start-move"])

    def test_versioned_historical_status_adapter_preserves_source_record(self) -> None:
        spec = importlib.util.spec_from_file_location("v02_status_adapter", MATRIX_PATH)
        if spec is None or spec.loader is None:
            self.fail("v0.2 production consumer is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        historical = {"schema": 1, "status": "infrastructure_error"}
        normalized = module.adapt_record(historical)
        self.assertEqual(normalized, {"adapter_id": "genewhip-v02-from-phase5-v1", "source_schema": 1,
                                      "status": "infrastructure-error"})
        self.assertEqual(historical["status"], "infrastructure_error")
        with self.assertRaisesRegex(ValueError, "unsupported-historical-evidence-schema"):
            module.adapt_record({"schema": "unknown-v0", "status": "pass"})

    def test_all_public_outcomes_round_trip_through_version_adapters(self) -> None:
        module = self._module()
        outcomes = ("pass", "fail", "unsupported", "skipped", "unknown", "infrastructure-error")
        for outcome in outcomes:
            with self.subTest(outcome=outcome):
                self.assertEqual(module.adapt_record({"schema": module.SCHEMA, "status": outcome})["status"], outcome)
                old = "infrastructure_error" if outcome == "infrastructure-error" else outcome
                for schema in ("genewhip-phase5-baseline-v1", "genewhip-phase5-failure-inventory-v1",
                               "genewhip-phase6-product-report-v1", "genewhip-phase6-host-v1"):
                    self.assertEqual(module.adapt_record({"schema": schema, "status": old})["status"], outcome)
        self.assertEqual(module.adapt_record({"schema": "genewhip-phase6-host-v1", "status": "unavailable"})["status"], "unsupported")
        self.assertEqual(module.adapt_record({"schema": "genewhip-phase6-host-v1", "status": "incomplete-failed"})["status"], "fail")

    def test_phase5_and_phase6_adapters_keep_prior_evidence_historical(self) -> None:
        module = self._module()
        phase5 = module.adapt_phase5(json.loads((ROOT / "evidence/phase5-baseline.json").read_text()),
                                     json.loads((ROOT / "evidence/phase5-failure-inventory.json").read_text()))
        self.assertEqual(phase5["historical_counts"]["pass"], 44)
        self.assertFalse(phase5["independently_verifiable"])
        self.assertTrue(any(row["outcome"] == "unknown" for row in phase5["screening_dispositions"]))
        phase6 = module.adapt_phase6(json.loads((ROOT / "evidence/phase6-core-routes.json").read_text()),
            json.loads((ROOT / "evidence/phase6-host-software-current.json").read_text()),
            json.loads((ROOT / "evidence/phase6-host-native.json").read_text()))
        self.assertEqual(phase6["historical_counts"]["core"]["pass"], 84)
        self.assertFalse(phase6["independently_verifiable"])
        module._public_scan(phase5)
        module._public_scan(phase6)

    def test_optional_phase7_limits_kill_children_and_record_reason_and_cleanup(self) -> None:
        require_process_context()
        spec = importlib.util.spec_from_file_location("v02_route_boundary", ROOT / "tests/session/phase6_route_contract.py")
        self.assertIsNotNone(spec)
        route = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(route)
        cases = (([sys.executable, "-c", "import os,time; os.write(1,b'x'*4096); time.sleep(5)"],
                  {"max_stdout_stderr_bytes": 1024, "max_capture_bytes": 4096}, "phase7-stdout-stderr-byte-limit"),
                 ([sys.executable, "-c", "import time; time.sleep(5)"],
                  {"max_rss_bytes": 1, "max_stdout_stderr_bytes": 4096, "max_capture_bytes": 4096},
                  "phase7-rss-byte-limit"),
                 ([sys.executable, "-c", "import time; time.sleep(5)"],
                  {"wall_seconds": 0.15, "max_rss_bytes": 1 << 30,
                   "max_stdout_stderr_bytes": 4096, "max_capture_bytes": 4096}, "phase7-wall-timeout"))
        with tempfile.TemporaryDirectory(prefix="gw-v02-process-contract-") as directory:
            root = pathlib.Path(directory)
            for index, (command, overrides, expected) in enumerate(cases):
                scratch = root / f"scratch-{index}"
                scratch.mkdir()
                limits = {"wall_seconds": 2, "cleanup_grace_seconds": 0.1, "max_rss_bytes": 1 << 30,
                    "max_stdout_stderr_bytes": 1 << 20, "max_json_bytes": 1 << 20,
                    "max_binary_file_bytes": 1 << 20, "max_capture_bytes": 1 << 20,
                    "max_scratch_bytes": 1 << 20, "max_retained_bytes": 1 << 20,
                    "max_fields": 7200, "max_calls": 100000000}
                limits.update(overrides)
                runs = []
                try:
                    result = route._run_client(pathlib.Path(sys.executable), command, runs,
                        report=scratch / "report.json", timeout=2, limits=limits, scratch_roots=(scratch,))
                except RuntimeError as error:
                    self.fail(f"child cleanup failed ({error}): {runs}")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(runs[0].get("bound_violation_reason"), expected)
                self.assertEqual(runs[0].get("process_group_cleanup"), "confirmed")


class SchemaClosureContract(unittest.TestCase):
    def test_current_positive_progress_requires_source_predicates_and_rejects_unreached_mutant(self) -> None:
        import hashlib
        module = PublicMatrixContract._module()
        route_spec = __import__("importlib.util").util.spec_from_file_location(
            "gw_v02_matrix_progress_route", ROOT / "scripts/evidence/phase6_routes.py")
        routes_module = __import__("importlib.util").util.module_from_spec(route_spec)
        route_spec.loader.exec_module(routes_module)
        route = next(row for row in routes_module.compile_routes()["routes"]
            if row["fixture"] == "tank-battle" and row["case"]["id"] == "full-route")
        facts = {item["id"]: {"reached": True, "value": item["equals"],
            "field": item["field_window"][0]} for item in route["definitions"]["predicates"]}
        run = {"predicate_results": facts}
        observed = module.validate_current_positive_predicates(route, run)
        self.assertEqual(len(observed), 2)
        self.assertGreater(observed[-1]["field"], observed[0]["field"])
        route_row = next(row for row in module.expected_matrix_rows(
            json.loads((ROOT / "evidence/v02-roster.json").read_text()))
            if row["title_id"] == "tank-battle" and row["case_id"] == "full-route" and
                row["client_scope"] == "core" and row["stage"] == "interaction" and row["repetition"] == 1)
        progress = {"play_state": 1, "position_in_source_range": True, "causal_control": True,
            "source_predicates": observed}
        module._validate_current_progress_observation(route_row, "interaction", progress)
        unreached_progress = json.loads(json.dumps(progress))
        unreached_progress["source_predicates"][0]["reached"] = False
        with self.assertRaisesRegex(ValueError, "matrix-current-source-predicate-invalid"):
            module._validate_current_progress_observation(route_row, "interaction", unreached_progress)
        mutant = json.loads(json.dumps(run))
        mutant["predicate_results"][observed[0]["id"]]["reached"] = False
        with self.assertRaisesRegex(ValueError, "current-positive-source-predicate-unreached"):
            module.validate_current_positive_predicates(route, mutant)
        forged_progress = json.loads(json.dumps(progress))
        forged_progress["source_predicates"][0]["field"] = 99999
        with self.assertRaisesRegex(ValueError, "matrix-current-source-predicate-invalid"):
            module._validate_current_progress_observation(route_row, "interaction", forged_progress)

        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        _, _, identity = self._current_inputs(module, roster)
        rows = [dict(expected, outcome="unknown", reason="not measured", reached=False,
            observation_dependencies={}, observations={}) for expected in module.expected_matrix_rows(roster)]
        for stage, facts in (("load", {"rom_loaded": True, "fixture_identity_matches": True}),
                ("boot", {"boot_ready": True, "boot_fields": 3600}),
                ("interaction", progress)):
            target = next(row for row in rows if row["title_id"] == "tank-battle" and
                row["case_id"] == "full-route" and row["client_scope"] == "core" and
                row["stage"] == stage and row["repetition"] == 1)
            dependencies = {name: target["identity"][name] for name in
                ("scenario_sha256", "oracle_sha256", "rom_sha256", "source_sha256", "input_sha256",
                 "delivery_map_sha256", "media_expectations_sha256")}
            dependencies["current_execution_identity_sha256"] = module._canonical_record_sha256(identity)
            target.update(outcome="pass", reason="source validated", reached=True,
                observation_dependencies=dependencies, observations=facts)
        with tempfile.TemporaryDirectory(prefix="gw-v02-current-progress-closure-") as directory:
            public = pathlib.Path(directory) / "public"
            module.project_public_closure(roster, rows, public, identity, identity)
            observations_path = public / "observations.json"
            stored = json.loads(observations_path.read_text())
            target = next(row for row in stored if row["title_id"] == "tank-battle" and
                row["case_id"] == "full-route" and row["client_scope"] == "core" and
                row["stage"] == "interaction" and row["repetition"] == 1)
            target["observations"]["source_predicates"][0]["field"] = 99999
            observations_path.write_text(json.dumps(stored, sort_keys=True, separators=(",", ":")) + "\n")
            manifest_path = public / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["members"]["observations.json"] = hashlib.sha256(observations_path.read_bytes()).hexdigest()
            manifest["closure_id"] = hashlib.sha256(json.dumps(manifest["members"], sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
            with self.assertRaisesRegex(ValueError, "matrix-current-source-predicate-invalid"):
                module.verify_public_closure(public, roster, identity)
            stored = json.loads(observations_path.read_text())
            target = next(row for row in stored if row["title_id"] == "tank-battle" and
                row["case_id"] == "full-route" and row["client_scope"] == "core" and
                row["stage"] == "interaction" and row["repetition"] == 1)
            target["observations"]["source_predicates"][0]["field"] = observed[0]["field"]
            target["observations"]["source_predicates"][0]["reached"] = False
            observations_path.write_text(json.dumps(stored, sort_keys=True, separators=(",", ":")) + "\n")
            manifest = json.loads(manifest_path.read_text())
            manifest["members"]["observations.json"] = hashlib.sha256(observations_path.read_bytes()).hexdigest()
            manifest["closure_id"] = hashlib.sha256(json.dumps(manifest["members"], sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
            with self.assertRaisesRegex(ValueError, "matrix-current-source-predicate-invalid"):
                module.verify_public_closure(public, roster, identity)

    def test_qualification_matrix_requires_positive_progress_and_counterfactual_dispositions(self) -> None:
        module = PublicMatrixContract._module()
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        rows = []
        positives = {"start-idle", "start-move", "action-sound", "sustained-play", "full-route"}
        for expected in module.expected_matrix_rows(roster):
            case, stage = expected["case_id"], expected["stage"]
            outcome = ("unknown" if stage == "completion" else "pass" if stage in ("load", "boot") or
                (case in positives and (stage == "interaction" or case in ("sustained-play", "full-route") and stage == "sustained"))
                else "skipped")
            rows.append({**expected, "outcome": outcome, "reached": outcome == "pass",
                "reason": "fixture", "observations": {}})
        module.validate_qualification_matrix(rows)
        target = next(row for row in rows if row["title_id"] == "tank-battle" and row["case_id"] == "full-route"
            and row["client_scope"] == "core" and row["stage"] == "interaction")
        target["outcome"] = "unknown"; target["reached"] = False
        with self.assertRaisesRegex(ValueError, "qualification-matrix-required-stage"):
            module.validate_qualification_matrix(rows)

    @staticmethod
    def _current_inputs(module, roster):
        rows = module.expected_matrix_rows(roster)
        core_runs = {}
        stages = []
        hosts = {"software-sdl": {}, "native-sdl": {}}
        for row in rows:
            key = (row["title_id"], row["case_id"], row["repetition"])
            if row["client_scope"] == "core":
                identity = row["identity"]
                core_runs[key] = {"fixture": row["title_id"], "case": row["case_id"],
                    "repetition": row["repetition"], "status": "pass", "completed_fields": 9,
                    "identity": {"scenario_sha256": identity["scenario_sha256"],
                        "oracle_sha256": identity["oracle_sha256"], "rom_sha256": identity["rom_sha256"],
                        "input_sha256": identity["input_sha256"]}}
                stages.append({"fixture": row["title_id"], "case": row["case_id"],
                    "repetition": row["repetition"], "stage": row["stage"],
                    "status": "unknown" if row["stage"] == "completion" else "pass",
                    "reached": row["stage"] != "completion"})
            elif row["client_scope"] in hosts:
                hosts[row["client_scope"]][(row["title_id"], row["case_id"])] = {
                    "fixture": row["title_id"], "case": row["case_id"],
                    "status": "pass", "backend": row["client_scope"].removesuffix("-sdl")}
        core = {"schema": "genewhip-phase6-product-report-v1", "runs": list(core_runs.values()), "stages": stages}
        host_reports = {client: {"schema": "genewhip-phase6-host-v1",
            "backend": client.removesuffix("-sdl"), "runs": list(cases.values())}
            for client, cases in hosts.items()}
        digest = "a" * 64
        identity = {"schema": "genewhip-v02-runtime-identity-v1", "source_sha256": digest,
            "git_head": "b" * 40, "base_sha": "c" * 40, "run_id": "123", "run_attempt": "2",
            "scope_sha256": "d" * 64, "candidate_sha256": "e" * 64,
            "build_identity": {"cmake_cache_sha256": "1" * 64, "configuration_sha256": "2" * 64,
                "headless_sha256": "3" * 64, "desktop_sha256": "4" * 64}}
        return core, host_reports, identity

    def test_current_runtime_adapter_preserves_history_and_binds_current_launch_identity(self) -> None:
        module = PublicMatrixContract._module()
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        core, hosts, identity = self._current_inputs(module, roster)
        rows = module.project_current_observations(roster, core, hosts, identity)
        self.assertEqual(len(rows), 180)
        self.assertTrue(any(row["outcome"] == "pass" for row in rows))
        self.assertTrue(all(row["identity"]["build_sha256"] == next(
            title["build_sha256"] for title in roster["matrix"]["titles"] if title["title_id"] == row["title_id"])
            for row in rows), "historical roster build identities must remain unchanged")
        self.assertTrue(all(row["observation_dependencies"].get("current_execution_identity_sha256") ==
            module._canonical_record_sha256(identity) for row in rows if row["outcome"] == "pass"))

    def test_current_execution_identity_mutants_reject_after_outer_digest_recompute(self) -> None:
        import hashlib
        module = PublicMatrixContract._module()
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        core, hosts, expected_identity = self._current_inputs(module, roster)
        observations = module.project_current_observations(roster, core, hosts, expected_identity)
        with tempfile.TemporaryDirectory(prefix="gw-v02-current-identity-") as directory:
            public = pathlib.Path(directory) / "public"
            module.project_public_closure(roster, observations, public, expected_identity, expected_identity)
            identity_path = public / "execution-identity.json"
            manifest_path = public / "manifest.json"
            for field_path in (("source_sha256",), ("build_identity", "cmake_cache_sha256"),
                    ("build_identity", "configuration_sha256"), ("build_identity", "headless_sha256"),
                    ("build_identity", "desktop_sha256")):
                mutated = json.loads(identity_path.read_text())
                target = mutated
                for part in field_path[:-1]:
                    target = target[part]
                target[field_path[-1]] = "f" * 64
                identity_path.write_text(json.dumps(mutated, sort_keys=True, separators=(",", ":")) + "\n")
                manifest = json.loads(manifest_path.read_text())
                manifest["members"]["execution-identity.json"] = hashlib.sha256(identity_path.read_bytes()).hexdigest()
                manifest["current_execution_identity_sha256"] = module._canonical_record_sha256(mutated)
                manifest["closure_id"] = hashlib.sha256(json.dumps(manifest["members"], sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest()
                manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
                with self.assertRaisesRegex(ValueError, "current-execution-identity-mismatch"):
                    module.verify_public_closure(public, roster, expected_identity)
                # Restore the trusted closure before exercising the next mutation.
                identity_path.write_text(json.dumps(expected_identity, sort_keys=True, separators=(",", ":")) + "\n")
                manifest["members"]["execution-identity.json"] = hashlib.sha256(identity_path.read_bytes()).hexdigest()
                manifest["current_execution_identity_sha256"] = module._canonical_record_sha256(expected_identity)
                manifest["closure_id"] = hashlib.sha256(json.dumps(manifest["members"], sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest()
                manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")

    def test_portable_closure_rejects_missing_and_forged_public_observation(self) -> None:
        module = PublicMatrixContract._module()
        self.assertTrue(callable(getattr(module, "project_public_closure", None)))
        self.assertTrue(callable(getattr(module, "verify_public_closure", None)))
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        rows = module.expected_matrix_rows(roster)
        observations = []
        for expected in rows:
            observations.append(dict(expected, outcome="unknown", reason="not measured in this proof",
                reached=False, observation_dependencies={}, observations={}))
        with tempfile.TemporaryDirectory(prefix="gw-v02-portable-closure-") as directory:
            public = pathlib.Path(directory) / "public"
            module.project_public_closure(roster, observations, public)
            self.assertTrue(module.verify_public_closure(public, roster)["independently_verifiable"])
            one = module.render_public_matrix(roster, observations)
            two = module.render_public_matrix(roster, list(reversed(observations)))
            self.assertEqual(one, two, "equivalent row order must render byte-identically")
            victim = public / "observations.json"
            victim.unlink()
            with self.assertRaisesRegex(ValueError, "public-closure-member-missing"):
                module.verify_public_closure(public, roster)

    def test_portable_closure_rejects_forged_identity_after_digest_recompute(self) -> None:
        module = PublicMatrixContract._module()
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        observations = [dict(expected, outcome="unknown", reason="not measured", reached=False,
            observation_dependencies={}, observations={}) for expected in module.expected_matrix_rows(roster)]
        with tempfile.TemporaryDirectory(prefix="gw-v02-closure-mutation-") as directory:
            public = pathlib.Path(directory) / "public"
            module.project_public_closure(roster, observations, public)
            rows = json.loads((public / "observations.json").read_text())
            rows[0]["identity"]["rom_sha256"] = "0" * 64
            observations_path = public / "observations.json"
            observations_path.write_text(json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n")
            manifest_path = public / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["members"]["observations.json"] = __import__("hashlib").sha256(observations_path.read_bytes()).hexdigest()
            manifest["closure_id"] = __import__("hashlib").sha256(json.dumps(manifest["members"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
            with self.assertRaisesRegex(ValueError, "matrix-identity-mismatch"):
                module.verify_public_closure(public, roster)

    def test_independent_roster_rejects_coordinated_closure_roster_change(self) -> None:
        module = PublicMatrixContract._module()
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        observations = [dict(expected, outcome="unknown", reason="not measured", reached=False,
            observation_dependencies={}, observations={}) for expected in module.expected_matrix_rows(roster)]
        with tempfile.TemporaryDirectory(prefix="gw-v02-independent-roster-") as directory:
            public = pathlib.Path(directory) / "public"
            module.project_public_closure(roster, observations, public)
            changed = json.loads((public / "roster.json").read_text())
            changed["matrix"]["titles"][1]["rom_sha256"] = "0" * 64
            roster_path = public / "roster.json"
            roster_path.write_text(json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n")
            manifest_path = public / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["members"]["roster.json"] = __import__("hashlib").sha256(roster_path.read_bytes()).hexdigest()
            manifest["closure_id"] = __import__("hashlib").sha256(json.dumps(manifest["members"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
            with self.assertRaisesRegex(ValueError, "public-independent-roster-mismatch"):
                module.verify_public_closure(public, roster)

    def test_portable_closure_rejects_unlisted_private_member_without_echo(self) -> None:
        module = PublicMatrixContract._module()
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        observations = [dict(expected, outcome="unknown", reason="not measured", reached=False,
            observation_dependencies={}, observations={}) for expected in module.expected_matrix_rows(roster)]
        with tempfile.TemporaryDirectory(prefix="gw-v02-closure-allowlist-") as directory:
            public = pathlib.Path(directory) / "public"
            module.project_public_closure(roster, observations, public)
            private_value = "SECRET_DO_NOT_ECHO_54a8"
            (public / "unexpected-private-member.rom").write_text(private_value)
            try:
                module.verify_public_closure(public, roster)
            except ValueError as error:
                self.assertEqual(str(error), "public-closure-unexpected-member")
                self.assertNotIn(private_value, str(error))
            else:
                self.fail("production closure consumer accepted an unlisted private member")

    def test_portable_closure_rejects_secret_value_without_echo(self) -> None:
        module = PublicMatrixContract._module()
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        observations = [dict(expected, outcome="unknown", reason="not measured", reached=False,
            observation_dependencies={}, observations={}) for expected in module.expected_matrix_rows(roster)]
        with tempfile.TemporaryDirectory(prefix="gw-v02-closure-secret-") as directory:
            public = pathlib.Path(directory) / "public"
            module.project_public_closure(roster, observations, public)
            value = "ghp_" + "AbCdEf0123456789AbCdEf0123456789"
            path = public / "observations.json"
            rows = json.loads(path.read_text())
            rows[0]["reason"] = value
            path.write_text(json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n")
            manifest_path = public / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["members"]["observations.json"] = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
            manifest["closure_id"] = __import__("hashlib").sha256(json.dumps(manifest["members"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
            with self.assertRaisesRegex(ValueError, "public-secret-material") as raised:
                module.verify_public_closure(public, roster)
            self.assertNotIn(value, str(raised.exception))

    def test_external_consumer_runs_from_copied_closure_without_checkout_dependency(self) -> None:
        require_process_context()
        module = PublicMatrixContract._module()
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        observations = [dict(expected, outcome="unknown", reason="not measured", reached=False,
            observation_dependencies={}, observations={}) for expected in module.expected_matrix_rows(roster)]
        with tempfile.TemporaryDirectory(prefix="gw-v02-isolated-review-") as directory:
            isolated = pathlib.Path(directory)
            public = isolated / "public"
            module.project_public_closure(roster, observations, public)
            independent_roster = isolated / "independent-roster.json"
            independent_roster.write_text(json.dumps(roster, sort_keys=True, separators=(",", ":")) + "\n")
            result = subprocess.run([sys.executable, "-I", str(public / "verifier.py"), "verify",
                "--root", str(public), "--independent-roster", str(independent_roster)], cwd=isolated, env={}, text=True,
                capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"independently_verifiable": true', result.stdout)
            self.assertNotIn(str(ROOT), result.stdout + result.stderr)

    def test_cli_projects_records_root_and_verifies_independent_roster(self) -> None:
        require_process_context()
        module = PublicMatrixContract._module()
        roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
        observations = [dict(expected, outcome="unknown", reason="not measured", reached=False,
            observation_dependencies={}, observations={}) for expected in module.expected_matrix_rows(roster)]
        with tempfile.TemporaryDirectory(prefix="gw-v02-project-cli-") as directory:
            base = pathlib.Path(directory)
            source, public = base / "records", base / "public"
            source.mkdir()
            (source / "roster.json").write_text(json.dumps(roster))
            (source / "observations.json").write_text(json.dumps(observations))
            independent_roster = base / "independent-roster.json"
            independent_roster.write_text(json.dumps(roster, sort_keys=True, separators=(",", ":")) + "\n")
            result = subprocess.run([sys.executable, "-I", str(MATRIX_PATH), "project", "--records-root",
                str(source), "--out", str(public)], cwd=base, env={}, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((public / "compatibility-matrix.md").is_file())
            verify = subprocess.run([sys.executable, "-I", str(public / "verifier.py"), "verify",
                "--root", str(public), "--independent-roster", str(independent_roster)], cwd=base, env={}, text=True,
                capture_output=True, timeout=10)
            self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_schema_and_dependency_documents_are_published(self) -> None:
        self.assertTrue(SCHEMA_PATH.is_file(), "v0.2 schema document is missing")
        self.assertTrue(DEPENDENCIES_PATH.is_file(), "v0.2 proof dependency map is missing")
        module = self._module()
        self.assertEqual(module.validate_schema_document(json.loads(SCHEMA_PATH.read_text())),
                         json.loads(SCHEMA_PATH.read_text()))
        self.assertEqual(module.validate_proof_dependencies(json.loads(DEPENDENCIES_PATH.read_text())),
                         json.loads(DEPENDENCIES_PATH.read_text()))

    def test_proof_dependency_validator_is_exposed(self) -> None:
        module = self._module()
        self.assertTrue(callable(getattr(module, "validate_proof_dependencies", None)),
                        "production proof dependency validator is missing")

    @staticmethod
    def _module():
        spec = importlib.util.spec_from_file_location("v02_dependency_surface", MATRIX_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("v0.2 production consumer is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_unknown_schema_and_duplicate_json_keys_have_exact_reasons(self) -> None:
        module = self._module()
        with self.assertRaisesRegex(ValueError, "unknown-v02-evidence-schema"):
            module.validate_public_bundle({"schema": "genewhip-v03-evidence-v1"})
        with tempfile.TemporaryDirectory(prefix="gw-v02-duplicate-json-") as directory:
            path = pathlib.Path(directory) / "duplicate.json"
            path.write_text('{"schema":"a","schema":"b"}')
            with self.assertRaisesRegex(ValueError, "duplicate-json-key"):
                module._load_json(path)

    def test_cyclic_proof_dependencies_reject_at_production_assertion(self) -> None:
        module = self._module()
        document = json.loads(DEPENDENCIES_PATH.read_text())
        document["proof_dependencies"]["core"] = ["final-close"]
        document["proof_dependencies"]["final-close"].append("core")
        with self.assertRaisesRegex(ValueError, "proof-dependency-cycle"):
            module.validate_proof_dependencies(document)

    def test_dependency_freshness_invalidates_stale_affected_but_preserves_unrelated_proof(self) -> None:
        module = self._module()
        dependencies = json.loads(DEPENDENCIES_PATH.read_text())
        proofs = {"docs": {"source_digests": {"docs/readme.md": "a" * 64}},
                  "package": {"source_digests": {"docs/readme.md": "a" * 64}},
                  "core": {"source_digests": {"src/core.c": "b" * 64}}}
        self.assertEqual(module.validate_proof_freshness(["docs/readme.md"], dependencies, proofs,
                          {"docs/readme.md": "a" * 64}), ["docs", "package"])
        self.assertNotIn("core", module.affected_proofs(["docs/readme.md"], dependencies))
        proofs["core"]["source_digests"]["src/core.c"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "stale-proof:core"):
            module.validate_proof_freshness(["src/core.c"], dependencies, proofs,
                                            {"src/core.c": "b" * 64})

    def test_external_consumer_rejects_path_escape(self) -> None:
        module = self._module()
        with tempfile.TemporaryDirectory(prefix="gw-v02-public-root-") as directory:
            root = pathlib.Path(directory) / "public"
            root.mkdir()
            roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
            schema = json.loads(SCHEMA_PATH.read_text())
            roster_path, schema_path = root / "roster.json", root / "schema.json"
            roster_path.write_text(json.dumps(roster))
            schema_path.write_text(json.dumps(schema))
            outside = pathlib.Path(directory) / "escaped.json"
            outside.write_text("{}")
            with self.assertRaisesRegex(ValueError, "public-path-escape"):
                module._verify_with_roster(outside, roster_path, schema_path)

    def test_insufficient_memory_reserve_blocks_before_workload(self) -> None:
        spec = importlib.util.spec_from_file_location("v02_memory_preflight", ROOT / "scripts/evidence/v02_run.py")
        if spec is None or spec.loader is None:
            self.fail("v0.2 bounded runner is unavailable")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with self.assertRaisesRegex(ValueError, "phase7-memory-reserve-insufficient"):
            runner.require_memory_reserve(4096, 4097)
        with self.assertRaisesRegex(ValueError, "phase7-memory-reserve-unobservable"):
            runner.require_memory_reserve(None, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tracer", action="store_true")
    parser.add_argument("--contracts", action="store_true")
    parser.add_argument("--host-process-context", action="store_true",
                        help="admit real controls only in a host context with group cleanup")
    parser.add_argument("--closure-test", action="store_true")
    parser.add_argument("--test", help="run one unittest by exact method name")
    parser.add_argument("--build", type=pathlib.Path)
    args = parser.parse_args()
    if sum((args.tracer, args.contracts, args.closure_test)) != 1:
        parser.error("select exactly one of --tracer, --contracts or --closure-test")
    if args.host_process_context:
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    if args.tracer or ((args.contracts or args.closure_test) and not args.test):
        require_process_context()
    if args.tracer:
        spec = importlib.util.spec_from_file_location("v02_run_under_test", ROOT / "scripts/evidence/v02_run.py")
        if spec is None or spec.loader is None:
            parser.error("v0.2 tracer is unavailable")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        try:
            result = runner.run_control(args.build.resolve(strict=True), ROOT / "evidence/v02-execution.json",
                                        ROOT / "build/v02/tracer")
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            print(f"BLOCKED: {error}", file=sys.stderr)
            return 1
        matrix_spec = importlib.util.spec_from_file_location("v02_matrix_test", MATRIX_PATH)
        self_matrix = importlib.util.module_from_spec(matrix_spec)
        matrix_spec.loader.exec_module(self_matrix)
        expected = result["bundle"]["roster"]
        self_matrix.validate_public_bundle(result["bundle"], expected_keys=expected)
        tracer = next(row for row in result["bundle"]["observations"] if row["case_id"] == "start-move")
        if tracer["status"] != "pass":
            print("BLOCKED: start-move source predicates did not pass", file=sys.stderr)
            return 1
        if result["matrix"] != self_matrix.render_matrix(result["bundle"]):
            print("BLOCKED: matrix rendering is not deterministic", file=sys.stderr)
            return 1
        print(f"tracer_cases={result['tracer_cases']}")
        print("external_validation=pass")
        print(f"matrix_contract_cases={len(result['bundle']['observations'])}")
        return 0
    suite = unittest.TestSuite()
    if args.test:
        suite.addTest(PublicMatrixContract(args.test) if hasattr(PublicMatrixContract, args.test)
                      else SchemaClosureContract(args.test))
    elif args.closure_test:
        for method in ("test_portable_closure_rejects_missing_and_forged_public_observation",
                       "test_portable_closure_rejects_forged_identity_after_digest_recompute",
                       "test_independent_roster_rejects_coordinated_closure_roster_change",
                       "test_portable_closure_rejects_unlisted_private_member_without_echo",
                       "test_portable_closure_rejects_secret_value_without_echo",
                       "test_external_consumer_runs_from_copied_closure_without_checkout_dependency",
                       "test_cli_projects_records_root_and_verifies_independent_roster"):
            suite.addTest(SchemaClosureContract(method))
    else:
        for test_class in [PublicMatrixContract, SchemaClosureContract]:
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test_class))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"matrix_contract_cases={result.testsRun}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
