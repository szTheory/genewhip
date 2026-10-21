#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Phase 4 report contract: each named mutation must fail for its own reason."""
import hashlib
import importlib.util
import copy
import math
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("phase4_report", ROOT / "scripts/evidence/phase4_report.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
bench_test_spec = importlib.util.spec_from_file_location(
    "gw_benchmark_contract_fixture", ROOT / "tests/evidence/benchmark_contract.py")
bench_test = importlib.util.module_from_spec(bench_test_spec)
bench_test_spec.loader.exec_module(bench_test)


IDENTITY = {"fixture": "fixtures/raster-toy", "profile": "VA3 NTSC-U",
            "source_sha256": "source-a", "scenario_sha256": "scenario-a", "rom_sha256": "rom-a",
            "input_sha256": "input-a", "build_configuration_sha256": "config-a",
            "headless_build_sha256": "headless-a", "desktop_build_sha256": "desktop-a"}
CONFIG = {"cmake": {"GENEWHIP_BUILD_DESKTOP": "ON"}, "host": {"system": "test", "machine": "test"}}
EXPECTED = {"source_revision": "test-head", "fixture_manifest_sha256": hashlib.sha256(
    (ROOT / "fixtures/manifest.json").read_bytes()).hexdigest(),
    "configuration_sha256": module.digest(CONFIG), "tracer_identity": IDENTITY}


def synthetic_host_report(mode):
    live = mode == "live"
    controls = __import__("json").loads((ROOT / "fixtures/independent-game-v2/host-controls.json").read_text())
    identities = {}
    for fixture, session in controls["sessions"].items():
        scenario_path = ROOT / session["scenario"]
        scenario = __import__("json").loads(scenario_path.read_text())
        source_path = ROOT / (scenario["source"]["relative_path"] if session["scenario_case"]
                              else scenario["rom"]["source"])
        identities[fixture] = {"fixture_id": session["fixture_id"],
                               "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                               "scenario_sha256": hashlib.sha256(scenario_path.read_bytes()).hexdigest(),
                               "rom_sha256": hashlib.sha256((ROOT / session["rom"]).read_bytes()).hexdigest()}
    runs = []
    for fixture in ("independent-game-v2", "sounded-diagnostic"):
        modes = ("live",) if live else ("software-dummy", "software-disk", "replace-drop", "missing-audio-negative")
        for run_mode in modes:
            unavailable = run_mode == "missing-audio-negative"
            settings = {"os": "Darwin", "os_release": "test", "os_version": "test", "architecture": "arm64",
                        "video_driver": "cocoa" if live else "dummy",
                        "display_identity": {"status": "observed", "displays": [{"_name": "test", "refresh_hz": 120.0}]},
                        "vsync_requested": True, "vsync_actual": "unknown: runner has no query",
                        "audio_backend_requested": "coreaudio" if live else "dummy/disk",
                        "audio_rate_hz": 48000,
                        "audio_queue_policy": {"target_source_frames": 2403, "cap_source_frames": 9612},
                        "renderer_readback": {"status": "unavailable", "reason": "no renderer API"},
                        "physical_scanout": "unobserved"}
            if run_mode == "replace-drop":
                settings["audio_backend_requested"] = "disk"
            stats = {"stats_version": 2, "present_errors": 0, "present_calls": 8,
                     "present_successes": 8, "presentation_error": 0,
                     "audio_available": 0 if unavailable else 1,
                     "queue_source_unit": "SDL input bytes and stereo source frames",
                     "clock_exposure_ns": 1000, "queue_exposure_ns": 1000, "queue_samples": 0,
                     "device_queue_observation": "unavailable"}
            deterministic = {"deterministic_join": True, "fields": 12,
                "machine_digest": "machine-a", "field_hashes_sha256": "4" * 64,
                "field_identity_sha256": "6" * 64, "core_pcm_frames": 10,
                "core_pcm_sha256": "5" * 64, "headless_machine_digest": "machine-a",
                "headless_field_hashes_sha256": "4" * 64,
                "headless_field_identity_sha256": "6" * 64,
                "headless_core_pcm_sha256": "5" * 64}
            runs.append({"id": fixture + ("-" + run_mode), "outcome": "skipped" if unavailable else "pass",
                         "controls_exercised": (["drop", "replace"] if run_mode == "replace-drop" else
                             ["drop", "exit", "mute", "pause", "reject-cartridge", "replace", "reset", "resume", "unmute"]),
                         "paused_fields": 1,
                         "rejected_cartridge_reason": "REJECT: missing genewhip-phase4-missing-cartridge.bin",
                         "fixture_id": controls["sessions"][fixture]["fixture_id"], **identities[fixture],
                         "input_log_sha256": "d" * 64, "input_script_sha256": "e" * 64,
                         "control_sha256": hashlib.sha256((ROOT / "fixtures/independent-game-v2/host-controls.json").read_bytes()).hexdigest(),
                         "build_configuration_sha256": "1" * 64,
                         "desktop_build_sha256": "2" * 64, "headless_build_sha256": "3" * 64,
                         "host_settings": settings, "elapsed_exposure_ns": 1000,
                         "stats_schema": 2, "stats": stats, "deterministic": deterministic,
                         "deterministic_identity_sha256": module.digest(deterministic),
                         "host_audio_queue_kind": "SDL queued source bytes/frames",
                         "device_queue_observation": "unavailable: SDL reports source queue",
                         "physical_audio_quality": "unobserved"})
            if run_mode == "replace-drop":
                replacement = "sounded-diagnostic" if fixture == "independent-game-v2" else "independent-game-v2"
                runs[-1].update(fields_by_segment=[20, 30, 30], complete_pcm_frames=10,
                                machine_digest="machine-a",
                                headless_machine_digest="machine-a",
                                primary=identities[fixture], replacement=identities[replacement],
                                field_hashes_sha256="4" * 64, field_identity_sha256="6" * 64,
                                headless_field_hashes_sha256="4" * 64,
                                headless_field_identity_sha256="6" * 64,
                                headless_core_pcm_sha256="5" * 64,
                                complete_pcm_sha256="5" * 64, deterministic_segment_join=True,
                                elapsed_exposure_ns=1000, host_audio_queue_kind="SDL queued source bytes/frames",
                                device_queue_observation="unavailable: source queue only")
    return {"schema": "genewhip-phase4-host-sessions", "version": 1,
            "outcome": "pass", "mode": mode, "source_revision": "test-head",
            "control_sha256": hashlib.sha256((ROOT / "fixtures/independent-game-v2/host-controls.json").read_bytes()).hexdigest(),
            "build_configuration_sha256": "1" * 64,
            "desktop_build_sha256": "2" * 64, "headless_build_sha256": "3" * 64,
            "host": runs[0]["host_settings"],
            "denominator": len(runs), "runs": runs,
            "counts": {"pass": sum(r["outcome"] == "pass" for r in runs),
                       "skipped": sum(r["outcome"] == "skipped" for r in runs), "fail": 0}}


def synthetic_game():
    rows = []
    for case_id, fields in zip(module.GAME_CASES, module.GAME_FIELDS):
        index = module.GAME_CASES.index(case_id)
        play, low, high, psg, minimum_ac, maximum_ac = module.GAME_EXPECTATIONS[index]
        rows.append({"id": case_id, "outcome": "pass", "unsupported": 0, "fields": fields,
                     "input_sha256": "a" * 64, "machine_digest": "ram", "field_hashes_sha256": "b" * 64,
                     "desktop_equal": True, "play_state": play, "position": low,
                     "psg": psg, "ac_range": minimum_ac})
    return {"schema": "genewhip-phase4-gameplay-v1", "version": 1, "outcome": "pass",
            "fixture_id": "genewhip-independent-game-v2", **module.GAME_IDENTITIES,
            "profile": "VA3-NTSC-U", "build_configuration_sha256": "c" * 64,
            "client_sha256": ["d" * 64, "e" * 64], "clients": ["headless", "desktop"],
            "visual_observations": {"title_to_play_field_10_changed": True,
                                    "start_idle_to_moved_marker_field_19_changed": True},
            "denominator": 6, "fields": sum(module.GAME_FIELDS), "results": rows}


def synthetic_report():
    tracer = {"schema": module.TRACER_SCHEMA, "version": 1, "outcome": "pass", **IDENTITY,
              "observations": {"ordered_field_summaries": 2}}
    delivery = {"schema": "genewhip.hosted-delivery.v1", "repository": "szTheory/genewhip",
                "pull_request": 12, "pull_request_head_sha": "a" * 40,
                "pull_request_base_sha": "b" * 40, "merged_source_sha": "c" * 40,
                "qualification_run_id": "101", "qualification_run_attempt": 1,
                "publisher_run_id": "102", "publisher_run_attempt": 1,
                "hosted_evidence": {"outcome": "success", "qualifies_rel_03": True},
                "release": {"release_url": "https://github.com/szTheory/genewhip/releases/tag/v0.1.0",
                            "source_sha": "c" * 40,
                            "inventory": {"source_revision": "c" * 40,
                                              "assets": {"asset-" + str(i): {"sha256": "d" * 64}
                                                         for i in range(6)}},
                                "assets": [{"name": name, "sha256": "d" * 64,
                                            "url": "https://github.com/szTheory/genewhip/releases/download/v0.1.0/" + name}
                                           for name in ["asset-" + str(i) for i in range(6)]
                                           + ["inventory.json", "SHA256SUMS"]]},
                "downloaded_package_adoption": "pass",
                "requirements": {"REL-03": "pass", "REL-02": "pass", "DOC-01": "pass"}}
    rows = []
    for row_id, required in module.ROSTER:
        observed = copy.deepcopy(tracer) if row_id == "diagnostic_public_clients" else {"evidence": "synthetic"}
        if row_id == "independent_gameplay": observed = synthetic_game()
        if row_id in ("exact_packages", "hosted_delivery"): observed = copy.deepcopy(delivery)
        outcome = "unknown" if row_id == "core_performance" else "pass"
        if row_id == "core_performance": observed = {"reason": "benchmark not in this report-contract fixture"}
        rows.append({"id": row_id, "required": required, "outcome": outcome, "observed": observed})
    return {"schema": module.SCHEMA, "version": module.VERSION, "source_revision": "test-head",
            "source_state": "clean", "fixture_manifest_sha256": EXPECTED["fixture_manifest_sha256"],
            "configuration": CONFIG, "configuration_sha256": module.digest(CONFIG),
            "rows": rows, "denominator": len(rows), "counts": module.count(rows),
            "tracer": {"path": "tests/fixtures/phase4_tracer.py", "sha256": "script-a"}}


class ReportContract(unittest.TestCase):
    def test_delivery_evidence_requires_bound_runs_release_and_downloaded_adoption(self):
        evidence = {"schema": "genewhip.hosted-delivery.v1", "repository": "szTheory/genewhip",
                    "pull_request": 12, "pull_request_head_sha": "a" * 40,
                    "pull_request_base_sha": "b" * 40, "merged_source_sha": "c" * 40,
                    "qualification_run_id": "101", "qualification_run_attempt": 1,
                    "publisher_run_id": "102", "publisher_run_attempt": 1,
                    "hosted_evidence": {"outcome": "success", "qualifies_rel_03": True},
                    "release": {"release_url": "https://github.com/szTheory/genewhip/releases/tag/v0.1.0",
                                "source_sha": "c" * 40,
                                "inventory": {"source_revision": "c" * 40,
                                              "assets": {"asset-" + str(i): {"sha256": "d" * 64}
                                                         for i in range(6)}},
                                "assets": [{"name": name, "sha256": "d" * 64,
                                            "url": "https://github.com/szTheory/genewhip/releases/download/v0.1.0/" + name}
                                           for name in ["asset-" + str(i) for i in range(6)]
                                           + ["inventory.json", "SHA256SUMS"]]},
                    "downloaded_package_adoption": "pass",
                    "requirements": {"REL-03": "pass", "REL-02": "pass", "DOC-01": "pass"}}
        self.assertEqual(module.validate_delivery_evidence(evidence), [])
        evidence["downloaded_package_adoption"] = "unknown"
        self.assertIn("delivery-adoption-not-passed",
                      module.validate_delivery_evidence(evidence))

    def assert_host_mutation_rejected(self, wanted, mutate):
        report = synthetic_report()
        evidence = {"software": synthetic_host_report("software"),
                    "live": synthetic_host_report("live")}
        row = next(item for item in report["rows"] if item["id"] == "desktop_pacing")
        row.update(outcome="pass", observed=evidence)
        report["counts"] = module.count(report["rows"])
        mutate(evidence)
        reasons = {name for name, _ in module.validate(report, expected=EXPECTED)}
        self.assertEqual(reasons, {wanted})

    def assert_malformed_live_display_rejected(self, mutate):
        evidence = {"software": synthetic_host_report("software"),
                    "live": synthetic_host_report("live")}
        mutate(evidence["live"]["runs"][0])
        problems = module.validate_host_sessions(evidence)
        reasons = {name for name, _ in problems}
        self.assertIn("desktop-host-capability", reasons)
        self.assertFalse(any("Traceback" in detail or "AttributeError" in detail
                             for _, detail in problems))

    def test_live_display_rejects_malformed_nested_evidence_with_named_problem(self):
        mutations = (
            lambda row: row.update(host_settings=None),
            lambda row: row["host_settings"].update(display_identity=None),
            lambda row: row["host_settings"]["display_identity"].update(displays=None),
            lambda row: row["host_settings"]["display_identity"].update(displays=[None]),
            lambda row: row["host_settings"]["display_identity"].update(displays=[{"refresh_hz": "60"}]),
            lambda row: row["host_settings"]["display_identity"].update(displays=[{"refresh_hz": True}]),
            lambda row: row["host_settings"]["display_identity"].update(displays=[{"refresh_hz": math.nan}]),
            lambda row: row["host_settings"]["display_identity"].update(displays=[{"refresh_hz": math.inf}]),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.assert_malformed_live_display_rejected(mutate)

    def test_desktop_session_rejects_missing_presentation_error_counter(self):
        report = synthetic_report()
        evidence = {"software": synthetic_host_report("software"),
                    "live": synthetic_host_report("live")}
        row = next(item for item in report["rows"] if item["id"] == "desktop_pacing")
        row.update(outcome="pass", observed=evidence)
        report["counts"] = module.count(report["rows"])
        run = evidence["software"]["runs"][0]
        del run["stats"]["present_errors"]
        reasons = {name for name, _ in module.validate(report, expected=EXPECTED)}
        self.assertEqual(reasons, {"desktop-host-presentation"})

    def test_desktop_session_rejects_source_queue_claimed_as_device_queue(self):
        self.assert_host_mutation_rejected("desktop-host-queue", lambda evidence:
            evidence["software"]["runs"][0]["stats"].update(
                queue_source_unit="physical device frames"))

    def test_desktop_session_requires_field_identity_separate_from_pixels(self):
        def mutate(evidence):
            run = evidence["software"]["runs"][0]
            run["deterministic"]["field_identity_sha256"] = run["deterministic"]["field_hashes_sha256"]
            run["deterministic"]["headless_field_identity_sha256"] = run["deterministic"]["field_identity_sha256"]
            run["deterministic_identity_sha256"] = module.digest(run["deterministic"])
        self.assert_host_mutation_rejected("desktop-host-deterministic-identity", mutate)

    def test_desktop_session_rejects_missing_audio_negative_control_fallback(self):
        def mutate(evidence):
            run = next(row for row in evidence["software"]["runs"]
                       if row["id"].endswith("missing-audio-negative"))
            run["stats"].pop("audio_available")
        self.assert_host_mutation_rejected("desktop-host-audio-fallback", mutate)

    def test_desktop_session_requires_host_setup_and_exposure(self):
        self.assert_host_mutation_rejected("desktop-host-setup", lambda evidence:
            evidence["live"]["runs"][0].update(elapsed_exposure_ns=0))

    def test_desktop_session_rejects_changed_stats_schema(self):
        self.assert_host_mutation_rejected("desktop-host-stats-version", lambda evidence:
            evidence["software"]["runs"][0].update(stats_schema=1))

    def test_desktop_session_rejects_stale_deterministic_output(self):
        def mutate(evidence):
            run = evidence["live"]["runs"][0]
            run["deterministic"]["machine_digest"] = "stale-machine"
            run["deterministic_identity_sha256"] = module.digest(run["deterministic"])
        self.assert_host_mutation_rejected("desktop-host-deterministic-identity", mutate)

    def test_desktop_replacement_rejects_missing_presentation_error_counter(self):
        def mutate(evidence):
            run = next(row for row in evidence["software"]["runs"] if row["id"].endswith("replace-drop"))
            del run["stats"]["present_errors"]
        self.assert_host_mutation_rejected("desktop-host-presentation", mutate)

    def test_desktop_replacement_rejects_stale_segment_pcm_identity(self):
        def mutate(evidence):
            run = next(row for row in evidence["software"]["runs"] if row["id"].endswith("replace-drop"))
            run["headless_core_pcm_sha256"] = "9" * 64
        self.assert_host_mutation_rejected("desktop-host-deterministic-identity", mutate)

    def test_stale_scenario_identity_rejected(self):
        report = synthetic_report()
        report["rows"][0]["observed"]["scenario_sha256"] = "scenario-stale"
        reasons = {name for name, _ in module.validate(report, expected=EXPECTED)}
        self.assertEqual(reasons, {"stale-scenario"})

    def assert_mutation_rejected(self, wanted, mutate, qualification=False):
        report = synthetic_report()
        mutate(report)
        reasons = {name for name, _ in module.validate(report, qualification=qualification, expected=EXPECTED)}
        self.assertEqual(reasons, {wanted})

    def test_exact_roster_mutations_rejected(self):
        def mutate(report):
            report["rows"].pop()
            report["denominator"] = len(report["rows"])
            report["counts"] = module.count(report["rows"])
        self.assert_mutation_rejected("missing-row", mutate)

    def test_extra_row_rejected(self):
        def mutate(report):
            report["rows"].append({"id": "extra", "required": False, "outcome": "unknown", "observed": {}})
            report["denominator"] = len(report["rows"])
            report["counts"] = module.count(report["rows"])
        self.assert_mutation_rejected("unexpected-row", mutate)

    def test_duplicate_row_rejected(self):
        def mutate(report):
            report["rows"].append(copy.deepcopy(report["rows"][0]))
            report["denominator"] = len(report["rows"])
            report["counts"] = module.count(report["rows"])
        self.assert_mutation_rejected("duplicate-row", mutate)

    def test_invalid_outcome_rejected(self):
        def mutate(report):
            report["rows"][0].update(outcome="maybe")
            report["counts"] = module.count(report["rows"])
        self.assert_mutation_rejected("invalid-outcome", mutate)

    def test_stale_source_identity_rejected(self):
        self.assert_mutation_rejected("stale-source", lambda r: r["rows"][0]["observed"].update(source_sha256="source-stale"))

    def test_stale_configuration_rejected(self):
        def mutate(report):
            report["configuration"] = {"cmake": {"GENEWHIP_BUILD_DESKTOP": "OFF"}, "host": CONFIG["host"]}
            report["configuration_sha256"] = module.digest(report["configuration"])
        self.assert_mutation_rejected("stale-configuration", mutate)

    def test_stale_rom_identity_rejected(self):
        self.assert_mutation_rejected("stale-rom", lambda r: r["rows"][0]["observed"].update(rom_sha256="rom-stale"))

    def test_changed_denominator_rejected(self):
        self.assert_mutation_rejected("denominator", lambda r: r.update(denominator=r["denominator"] + 1))

    def test_required_outcomes_cannot_qualify(self):
        for outcome in ("unsupported", "skipped", "unknown"):
            with self.subTest(outcome=outcome):
                def mutate(report):
                    report["rows"][0]["outcome"] = outcome
                    report["counts"] = module.count(report["rows"])
                self.assert_mutation_rejected("required-non-pass", mutate, qualification=True)

    def test_gameplay_roster_mutation_rejected(self):
        reasons = {name for name, _ in module.validate_gameplay(
            {**synthetic_game(), "results": synthetic_game()["results"][:-1], "denominator": 5})}
        self.assertEqual(reasons, {"gameplay-case-missing"})

    def test_gameplay_unknown_case_cannot_qualify(self):
        evidence = synthetic_game()
        evidence["results"][5]["outcome"] = "unknown"
        reasons = {name for name, _ in module.validate_gameplay(evidence, qualification=True)}
        self.assertEqual(reasons, {"gameplay-case-non-pass"})

    def test_gameplay_requires_both_public_clients(self):
        evidence = synthetic_game()
        evidence["clients"] = ["headless"]
        evidence["client_sha256"] = ["d" * 64]
        reasons = {name for name, _ in module.validate_gameplay(evidence, qualification=True)}
        self.assertEqual(reasons, {"gameplay-client-missing"})

    def test_gameplay_stale_source_identity_rejected(self):
        evidence = synthetic_game()
        evidence["scenario_sha256"] = "f" * 64
        reasons = {name for name, _ in module.validate_gameplay(evidence)}
        self.assertEqual(reasons, {"stale-game-scenario"})

    def test_gameplay_stale_build_identity_rejected(self):
        evidence = synthetic_game()
        expected = {"build_configuration_sha256": "c" * 64,
                    "client_sha256": ["d" * 64, "e" * 64]}
        evidence["build_configuration_sha256"] = "f" * 64
        reasons = {name for name, _ in module.validate_gameplay(evidence, expected_identity=expected)}
        self.assertEqual(reasons, {"gameplay-stale-configuration"})

    def test_hidden_unsupported_game_case_rejected(self):
        evidence = synthetic_game()
        evidence["results"][2]["unsupported"] = 1
        reasons = {name for name, _ in module.validate_gameplay(evidence, qualification=True)}
        self.assertEqual(reasons, {"gameplay-unsupported"})

    def test_core_performance_row_uses_production_benchmark_validator(self):
        report = synthetic_report()
        row = next(item for item in report["rows"] if item["id"] == "core_performance")
        evidence = bench_test.valid_report()
        row.update(outcome="pass", observed=evidence)
        report["counts"] = module.count(report["rows"])
        expected = copy.deepcopy(EXPECTED)
        expected["source_revision"] = "test-head"
        expected["performance_identity"] = {
            "build_configuration_sha256": "build-identity",
            "benchmark_binary_sha256": "e" * 64,
            "source_identity_sha256": bench_test.benchmark.source_identity()}
        self.assertEqual(module.validate(report, qualification=True, expected=expected), [])

    def test_stale_core_performance_source_is_rejected_by_report(self):
        report = synthetic_report()
        row = next(item for item in report["rows"] if item["id"] == "core_performance")
        evidence = bench_test.valid_report()
        evidence["source_revision"] = "stale-head"
        row.update(outcome="pass", observed=evidence)
        report["counts"] = module.count(report["rows"])
        expected = copy.deepcopy(EXPECTED)
        expected["source_revision"] = "test-head"
        expected["performance_identity"] = {
            "build_configuration_sha256": "build-identity",
            "benchmark_binary_sha256": "e" * 64,
            "source_identity_sha256": bench_test.benchmark.source_identity()}
        reasons = {name for name, _ in module.validate(report, qualification=False, expected=expected)}
        self.assertIn("performance-stale-identity", reasons)


if __name__ == "__main__":
    unittest.main(verbosity=2)
