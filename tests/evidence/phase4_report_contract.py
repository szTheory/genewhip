#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Phase 4 report contract: each named mutation must fail for its own reason."""
import hashlib
import importlib.util
import copy
import json
import math
import re
import tempfile
import unittest
import subprocess
import sys
from unittest.mock import patch
from pathlib import Path

SYNTHETIC_EXPORT = "--export-validator-synthetic" in sys.argv
PROCESS_DENIALS = []
if SYNTHETIC_EXPORT:
    sys.argv.remove("--export-validator-synthetic")

    def deny_process(event, args):
        if (event in {"subprocess.Popen", "os.system", "os.fork", "os.forkpty", "pty.spawn"}
                or event.startswith(("os.exec", "os.spawn", "os.posix_spawn"))):
            PROCESS_DENIALS.append(event)
            raise PermissionError("export-validator-independent-process-denial")

    # Install and independently exercise the original API before production imports.
    sys.addaudithook(deny_process)
    try:
        subprocess.Popen(["/__no_usable_export_client__"])
    except PermissionError:
        pass
    if PROCESS_DENIALS != ["subprocess.Popen"]:
        raise AssertionError("export-validator-preimport-denial-not-observed")

ROOT = Path(__file__).resolve().parents[2]
TEST_REVISION = "a" * 40
PRIVATE_TEST_PATH = "/" + "Users" + "/private"
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
EXPECTED = {"source_revision": TEST_REVISION, "fixture_manifest_sha256": hashlib.sha256(
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
        modes = ("live", "replace-drop") if live else ("software-dummy", "software-disk", "replace-drop", "missing-audio-negative")
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
            if run_mode == "replace-drop" and not live:
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
            "outcome": "pass", "mode": mode, "source_revision": TEST_REVISION,
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


def synthetic_safety_contracts():
    revision = "a" * 40
    run_id, tree_id = "b" * 32, "c" * 40
    lanes = {}
    for name, mode, instrumented in (("native", "pr", True), ("sanitizer", "pr", True),
                                      ("production", "production", False)):
        case_names = sorted(module.safety_required_tests(name))
        while len(case_names) < module.SAFETY_MIN_CASES[name]:
            case_names.append(f"safety_case_{len(case_names):03d}")
        lanes[name] = {
            "source_revision": revision,
            "run_id": run_id,
            "source_tree_id": tree_id,
            "ctest": {"denominator": 131 if name != "production" else 95,
                      "pass": 129 if name != "production" else 93, "fail": 0,
                      "error": 0, "skipped": ["independent_game_admission", "independent_game_consumer"],
                      "case_names": case_names,
                      "test_inventory_sha256": module.digest(sorted(case_names)),
                      "junit_sha256": "a" * 64},
            "summary": {"mode": mode, "seed": "47573105", "cases": 16, "safety_pass": 16, "audio_pass": 256,
                        "negative_controls": 12, "allocation_instrumented": instrumented,
                        "steps_per_case": 8, "tick_budget": 180000, "output_cap_frames": 128,
                        "allocation_count_peak": 2 if instrumented else 0,
                        "steady_allocations": 0},
            "summary_sha256": module.digest({"mode": mode, "seed": "47573105", "cases": 16, "safety_pass": 16,
                "audio_pass": 256, "negative_controls": 12, "allocation_instrumented": instrumented,
                "steps_per_case": 8, "tick_budget": 180000, "output_cap_frames": 128,
                "allocation_count_peak": 2 if instrumented else 0, "steady_allocations": 0}),
            "summary_file_sha256": "d" * 64,
            "configuration": synthetic_safety_config(name),
            "configuration_sha256": hashlib.sha256(
                module._json_bytes(synthetic_safety_config(name))).hexdigest(),
        }
    for name, lane in lanes.items():
        record = {"schema": module.SAFETY_COMPLETION_SCHEMA, "version": 1, "run_id": run_id,
                  "lane": name, "source_revision": revision, "source_tree_id": tree_id, **lane}
        lane.clear()
        lane.update(record, completion_record_sha256=module.digest(record))
    final = {"schema": module.SAFETY_FINAL_SCHEMA, "version": 1, "run_id": run_id,
             "source_revision": revision, "source_tree_id": tree_id,
             "lane_completion_sha256": {name: lane["completion_record_sha256"]
                                         for name, lane in lanes.items()}}
    return {"schema": "genewhip-phase4-safety-contracts-v1", "version": 1,
            "source_revision": revision, "source_tree_id": tree_id, "run_id": run_id,
            "final_record": final, "final_record_sha256": module.digest(final), "lanes": lanes}


def synthetic_safety_config(lane):
    return {"schema": module.SAFETY_CONFIG_SCHEMA, "version": 1, "lane": lane,
            "values": {"CMAKE_BUILD_TYPE": "Release", "CMAKE_GENERATOR": "Unix Makefiles",
                       "GENEWHIP_TEST_HOOKS": "OFF" if lane == "production" else "ON",
                       "CMAKE_C_COMPILER_ID": "AppleClang",
                       "CMAKE_C_COMPILER_VERSION": "17.0.0"}}


def resign_safety_evidence(evidence):
    for lane in evidence["lanes"].values():
        record = {key: value for key, value in lane.items() if key != "completion_record_sha256"}
        lane["completion_record_sha256"] = module.digest(record)
    final = evidence["final_record"]
    final["lane_completion_sha256"] = {
        name: lane["completion_record_sha256"] for name, lane in evidence["lanes"].items()}
    evidence["final_record_sha256"] = module.digest(final)


def create_complete_safety_build(build):
    identity = {"source_revision": TEST_REVISION, "source_tree_id": "c" * 40}
    expected = synthetic_safety_contracts()
    with patch.object(module, "public_source_identity", return_value=identity):
        module.safety_start(build)
        for name in module.SAFETY_LANES:
            lane_dir = Path(build) / "ci" / name
            lane_dir.mkdir(parents=True, exist_ok=True)
            hooks = "OFF" if name == "production" else "ON"
            (lane_dir / "CMakeCache.txt").write_text(
                "CMAKE_BUILD_TYPE:STRING=Release\nCMAKE_C_COMPILER_ID:STRING=AppleClang\n"
                "CMAKE_C_COMPILER_VERSION:STRING=17.0\nCMAKE_GENERATOR:INTERNAL=Ninja\n"
                "CMAKE_HOME_DIRECTORY:INTERNAL=" + PRIVATE_TEST_PATH + "/worktree\n"
                "CMAKE_CACHEFILE_DIR:INTERNAL=" + PRIVATE_TEST_PATH + "/worktree/build\n"
                f"GENEWHIP_BUILD_DESKTOP:BOOL=OFF\nGENEWHIP_TEST_HOOKS:BOOL={hooks}\n")
            cases = []
            for case_name in expected["lanes"][name]["ctest"]["case_names"]:
                if case_name in module.SAFETY_ALLOWED_SKIPS:
                    cases.append(f"<testcase name='{case_name}'><skipped/></testcase>")
                else:
                    cases.append(f"<testcase name='{case_name}'/>")
            xml = "<testsuites><testsuite>" + "".join(cases) + "</testsuite></testsuites>"
            (lane_dir / "ctest-junit.xml").write_text(xml)
            (lane_dir / "safety-contract.json").write_text(
                json.dumps(expected["lanes"][name]["summary"]))
            module.safety_complete_lane(build, name)
        module.safety_finish(build)
        (Path(build) / "ci/toolchain.txt").write_text("cmake version 4.4.3\nAppleClang 17.0.0\nDarwin arm64\n")


def synthetic_report():
    tracer = {"schema": module.TRACER_SCHEMA, "version": 1, "outcome": "pass", **IDENTITY,
              "observations": {"ordered_field_summaries": 2}}
    delivery = {"schema": "genewhip.hosted-delivery.v1", "repository": "szTheory/genewhip",
                "pull_request": 12, "pull_request_head_sha": "a" * 40,
                "pull_request_base_sha": "b" * 40, "merged_source_sha": "c" * 40,
                "publisher_source_sha": "d" * 40,
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
        if row_id == "safety_contracts": observed = synthetic_safety_contracts()
        if row_id in ("exact_packages", "hosted_delivery"): observed = copy.deepcopy(delivery)
        outcome = "unknown" if row_id == "core_performance" else "pass"
        if row_id == "core_performance": observed = {"reason": "benchmark not in this report-contract fixture"}
        rows.append({"id": row_id, "required": required, "outcome": outcome, "observed": observed})
    return {"schema": module.SCHEMA, "version": module.VERSION, "source_revision": TEST_REVISION,
            "source_state": "clean", "fixture_manifest_sha256": EXPECTED["fixture_manifest_sha256"],
            "configuration": CONFIG, "configuration_sha256": module.digest(CONFIG),
            "rows": rows, "denominator": len(rows), "counts": module.count(rows),
            "tracer": {"path": "tests/fixtures/phase4_tracer.py", "sha256": "script-a"}}


class ReportContract(unittest.TestCase):
    def test_producer_export_composition_accepts_actual_rosters(self):
        """Exercise the real roster producer and the public exporter without launching clients."""
        from types import SimpleNamespace
        producer_spec = importlib.util.spec_from_file_location(
            "phase4_session_producer", ROOT / "tests/desktop/phase4_sessions.py")
        producer = importlib.util.module_from_spec(producer_spec)
        producer_spec.loader.exec_module(producer)
        with tempfile.TemporaryDirectory(prefix="gw-host-producer-export-") as temporary:
            base = Path(temporary)
            build = base / "build"
            (build / "evidence").mkdir(parents=True)
            desktop = build / "tools/desktop/genewhip-desktop"
            headless = build / "tools/session/gw_headless"
            desktop.parent.mkdir(parents=True)
            headless.parent.mkdir(parents=True)
            desktop.write_bytes(b"synthetic desktop executable")
            headless.write_bytes(b"synthetic headless executable")
            cache = build / "CMakeCache.txt"
            cache.write_text("CMAKE_BUILD_TYPE:STRING=Release\n")
            identities = {"build_configuration_sha256": module.sha(cache),
                          "desktop_build_sha256": module.sha(desktop),
                          "headless_build_sha256": module.sha(headless)}
            expected = {mode: synthetic_host_report(mode) for mode in ("software", "live")}
            for report in expected.values():
                report.update(identities)
                for row in report["runs"]:
                    row.update(identities)

            def producer_rows(mode):
                return {row["id"]: row for row in expected[mode]["runs"]}

            with patch.object(producer, "ROOT", ROOT), \
                 patch.object(producer, "EXECUTION_SCOPE", None), \
                 patch.object(producer, "run_controls", side_effect=lambda name, *_args:
                              producer_rows("live" if name.endswith("-live") else "software")[name]), \
                 patch.object(producer, "run_missing_audio", side_effect=lambda name, *_args:
                              producer_rows("software")[name + "-missing-audio-negative"]), \
                 patch.object(producer, "run_replacement", side_effect=lambda name, *_args:
                              producer_rows("live" if _args and _args[-1] == "live" else "software")
                              [name + "-replace-drop"]), \
                 patch.object(producer.subprocess, "run", return_value=subprocess.CompletedProcess(
                     ["git", "rev-parse", "HEAD"], 0, TEST_REVISION + "\n", "")), \
                 patch.dict("os.environ", {"GENEWHIP_LIVE_DISPLAY": "1", "GENEWHIP_LIVE_AUDIO": "1"}):
                for mode, filename in (("software", "phase4-host-sessions.json"),
                                       ("live", "phase4-host-live.json")):
                    result = producer.run_all(SimpleNamespace(mode=mode, headless=headless,
                        desktop=desktop, build=build, out=build / "evidence" / filename))
                    self.assertEqual(result, 0)
                    generated = json.loads((build / "evidence" / filename).read_text())
                    self.assertEqual(generated["denominator"], len(expected[mode]["runs"]))
                    expected[mode] = generated

            hygiene = base / "scripts/ci/public_hygiene.py"
            hygiene.parent.mkdir(parents=True)
            hygiene.write_bytes((ROOT / "scripts/ci/public_hygiene.py").read_bytes())
            with patch.object(module, "public_source_identity", return_value={
                    "source_revision": TEST_REVISION, "source_tree_id": "f" * 40}):
                module.host_export(build, build / "host-export", "123456", 2,
                                   TEST_REVISION, root=base)

    def test_host_export_replacement_contract_through_real_consumer(self):
        identity = {"source_revision": TEST_REVISION, "source_tree_id": "f" * 40}
        mutations = ("valid", "missing", "extra", "duplicate", "wrong-video", "wrong-audio",
                     "software-video", "software-audio", "display", "controls", "primary", "replacement",
                     "stale-build", "stale-control", "pcm", "skip")
        reasons = {"missing": "roster", "extra": "roster", "duplicate": "roster",
                   "wrong-video": "setup", "wrong-audio": "setup", "software-video": "setup",
                   "software-audio": "setup", "display": "capability", "controls": "controls",
                   "primary": "source-identity", "replacement": "source-identity",
                   "stale-build": "stale-identity", "stale-control": "control-identity",
                   "pcm": "deterministic-identity", "skip": "outcome"}
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                build, reports = self._host_export_fixture(base)
                self.assertEqual((reports["software"]["denominator"], reports["live"]["denominator"]), (8, 4))
                self.assertFalse(list(base.rglob("*.bin")))
                self.assertFalse(any(path.stat().st_mode & 0o111 for path in build.rglob("*") if path.is_file()))
                live = reports["live"]
                row = next(r for r in live["runs"] if r["id"].endswith("replace-drop"))
                if mutation == "missing": live["runs"].remove(row)
                elif mutation == "extra": live["runs"].append(dict(row, id="unexpected-replace-drop"))
                elif mutation == "duplicate": live["runs"].append(copy.deepcopy(row))
                elif mutation == "wrong-video": row["host_settings"]["video_driver"] = "dummy"
                elif mutation == "wrong-audio": row["host_settings"]["audio_backend_requested"] = "disk"
                elif mutation.startswith("software-"):
                    row = next(r for r in reports["software"]["runs"] if r["id"].endswith("replace-drop"))
                    row["host_settings"]["video_driver" if mutation.endswith("video") else "audio_backend_requested"] = "cocoa" if mutation.endswith("video") else "coreaudio"
                elif mutation == "display": row["host_settings"]["display_identity"] = None
                elif mutation == "controls": row["controls_exercised"] = ["drop"]
                elif mutation in ("primary", "replacement"): row[mutation]["rom_sha256"] = "0" * 64
                elif mutation == "stale-build": row["desktop_build_sha256"] = "0" * 64
                elif mutation == "stale-control": row["control_sha256"] = "0" * 64
                elif mutation == "pcm": row["headless_core_pcm_sha256"] = "0" * 64
                elif mutation == "skip":
                    index = live["runs"].index(row)
                    live["runs"][index] = {"id": row["id"], "outcome": "skipped", "reason": "CoreAudio unavailable"}
                live["denominator"] = len(live["runs"])
                live["counts"] = {name: sum(r["outcome"] == name for r in live["runs"]) for name in ("pass", "skipped", "fail")}
                for mode, filename in (("software", "sessions"), ("live", "live")):
                    (build / f"evidence/phase4-host-{filename}.json").write_text(json.dumps(reports[mode]))
                hygiene = base / "scripts/ci/public_hygiene.py"
                hygiene.parent.mkdir(parents=True)
                hygiene.write_bytes((ROOT / "scripts/ci/public_hygiene.py").read_bytes())
                output = build / "export"
                with patch.object(module, "public_source_identity", return_value=identity) as seam:
                    if mutation == "valid":
                        module.host_export(build, output, "123456", 2, TEST_REVISION, root=base)
                        self.assertEqual(len(list(output.iterdir())), 3)
                        self.assertEqual(json.loads((output / "phase4-host-live.json").read_text())["denominator"], 4)
                    else:
                        with self.assertRaisesRegex(ValueError, "desktop-host-" + reasons[mutation]):
                            module.host_export(build, output, "123456", 2, TEST_REVISION, root=base)
                        self.assertFalse(output.exists())
                    seam.assert_called_once_with(base)

    def _host_export_fixture(self, base):
        build = base / "desktop-build"
        (build / "evidence").mkdir(parents=True)
        desktop = build / "tools/desktop/genewhip-desktop"
        headless = build / "tools/session/gw_headless"
        desktop.parent.mkdir(parents=True)
        headless.parent.mkdir(parents=True)
        desktop.write_bytes(b"desktop executable identity")
        headless.write_bytes(b"headless executable identity")
        (build / "CMakeCache.txt").write_text(
            "CMAKE_BUILD_TYPE:STRING=Release\n"
            "CMAKE_C_COMPILER_ID:STRING=AppleClang\n"
            "CMAKE_C_COMPILER_VERSION:STRING=17.0.0\n"
            "CMAKE_GENERATOR:INTERNAL=Unix Makefiles\n"
            "GENEWHIP_BUILD_DESKTOP:BOOL=ON\n"
            "GENEWHIP_TEST_HOOKS:BOOL=OFF\n")
        reports = {mode: synthetic_host_report(mode) for mode in ("software", "live")}
        identity = {"build_configuration_sha256": module.sha(build / "CMakeCache.txt"),
                    "desktop_build_sha256": module.sha(desktop),
                    "headless_build_sha256": module.sha(headless)}
        for mode, report in reports.items():
            report.update(identity)
            for row in report["runs"]:
                row.update(identity)
            (build / "evidence" / f"phase4-host-{('sessions' if mode == 'software' else 'live')}.json").write_text(
                json.dumps(report, sort_keys=True) + "\n")
        return build, reports

    def test_host_export_is_run_attempt_bound_and_curated(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            build, reports = self._host_export_fixture(base)
            output = build / "host-export"
            identity = {"source_revision": TEST_REVISION, "source_tree_id": "f" * 40}
            with patch.object(module, "public_source_identity", return_value=identity):
                module.host_export(build, output, "123456", 2, TEST_REVISION)
            self.assertEqual(sorted(path.name for path in output.iterdir()),
                             ["host-evidence.json", "phase4-host-live.json", "phase4-host-sessions.json"])
            receipt = json.loads((output / "host-evidence.json").read_text())
            self.assertEqual((receipt["run_id"], receipt["run_attempt"]), ("123456", 2))
            self.assertEqual(receipt["source_revision"], TEST_REVISION)
            self.assertEqual(receipt["source_tree_id"], "f" * 40)
            for mode, filename in (("software", "phase4-host-sessions.json"),
                                   ("live", "phase4-host-live.json")):
                payload = (output / filename).read_bytes()
                self.assertEqual(receipt["reports"][mode]["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertEqual(json.loads(payload)["source_revision"], TEST_REVISION)

    def test_host_export_rejects_stale_or_private_reports_without_output(self):
        identity = {"source_revision": TEST_REVISION, "source_tree_id": "f" * 40}
        for mutation in ("stale-source", "private-path", "live-skip"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                build, reports = self._host_export_fixture(base)
                live = reports["live"]
                if mutation == "stale-source":
                    live["source_revision"] = "b" * 40
                elif mutation == "private-path":
                    live["host"]["display_identity"]["displays"][0]["_name"] = PRIVATE_TEST_PATH + "/display"
                else:
                    live["outcome"] = "skipped"
                    live["counts"] = {"pass": 0, "skipped": live["denominator"], "fail": 0}
                    for row in live["runs"]:
                        row["outcome"] = "skipped"
                        row["reason"] = "device unavailable"
                (build / "evidence/phase4-host-live.json").write_text(json.dumps(live, sort_keys=True) + "\n")
                output = build / "host-export"
                with patch.object(module, "public_source_identity", return_value=identity):
                    with self.assertRaises(ValueError):
                        module.host_export(build, output, "123456", 2, TEST_REVISION)
                self.assertFalse(output.exists(), "rejected host reports were staged")

    def test_host_export_rejects_output_overlapping_build_without_deleting_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            build, _ = self._host_export_fixture(base)
            identity = {"source_revision": TEST_REVISION, "source_tree_id": "f" * 40}
            sentinel = build / "keep-me.txt"
            sentinel.write_text("preserve source build")
            with patch.object(module, "public_source_identity", return_value=identity):
                with self.assertRaisesRegex(ValueError, "host-export-output-overlaps-source"):
                    module.host_export(build, build, "123456", 2, TEST_REVISION)
            self.assertEqual(sentinel.read_text(), "preserve source build")

    def test_host_export_rejects_non_object_json_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            build, _ = self._host_export_fixture(base)
            identity = {"source_revision": TEST_REVISION, "source_tree_id": "f" * 40}
            (build / "evidence/phase4-host-live.json").write_text("[]\n")
            output = build / "host-export"
            with patch.object(module, "public_source_identity", return_value=identity):
                with self.assertRaisesRegex(ValueError, "host-export-report-invalid"):
                    module.host_export(build, output, "123456", 2, TEST_REVISION)
            self.assertFalse(output.exists())

    def test_host_export_reports_only_path_free_live_capability_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            build, reports = self._host_export_fixture(base)
            identity = {"source_revision": TEST_REVISION, "source_tree_id": "f" * 40}
            live = reports["live"]
            live["runs"][0]["host_settings"]["display_identity"] = {
                "status": "unavailable", "reason": PRIVATE_TEST_PATH, "displays": []}
            live["runs"][0]["host_settings"]["video_driver"] = "dummy"
            live["runs"][1]["id"] = PRIVATE_TEST_PATH + "/fixture"
            (build / "evidence/phase4-host-live.json").write_text(json.dumps(live, sort_keys=True) + "\n")
            output = build / "host-export"
            with patch.object(module, "public_source_identity", return_value=identity):
                with self.assertRaisesRegex(ValueError, "host-export-validation:desktop-host-capability") as caught:
                    module.host_export(build, output, "123456", 2, TEST_REVISION)
            message = str(caught.exception)
            self.assertIn('"case_index":0', message)
            self.assertIn('"display_observed":false', message)
            self.assertIn('"display_count":0', message)
            self.assertIn('"refresh_count":0', message)
            self.assertNotIn(PRIVATE_TEST_PATH, message)

    def test_ci_desktop_job_uploads_only_attempt_bound_curated_host_reports(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        desktop_job = workflow.split("  desktop:\n", 1)[1].split("\n  package:", 1)[0]
        self.assertIn("name: Export exact-source host session evidence", desktop_job)
        export_command = re.search(
            r"python3 scripts/evidence/phase4_report\.py host-export\s+--build\s+(\S+)\s+--out\s+(\S+)",
            desktop_job, re.DOTALL)
        self.assertIsNotNone(export_command)
        build_path, output_path = map(Path, export_command.groups())
        self.assertNotEqual(output_path, build_path)
        self.assertTrue(output_path.is_relative_to(build_path),
                        "host-export output must stay below the build root")
        self.assertIn("name: phase4-host-evidence-${{ github.run_id }}-${{ github.run_attempt }}", desktop_job)
        upload_path = re.search(r"(?m)^\s+path:\s*(\S+)\s*$", desktop_job)
        self.assertIsNotNone(upload_path)
        self.assertEqual(upload_path.group(1), output_path.as_posix() + "/")

    def test_exported_package_snapshot_without_safety_inputs_builds_unknown_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            build = Path(temporary) / "build"
            (root / "fixtures").mkdir(parents=True)
            (root / "tests/fixtures").mkdir(parents=True)
            build.mkdir()
            (root / "fixtures/manifest.json").write_text("{}\n")
            (root / "tests/fixtures/phase4_tracer.py").write_text("# snapshot fixture\n")
            (build / "CMakeCache.txt").write_text(
                "CMAKE_BUILD_TYPE:STRING=Release\nCMAKE_GENERATOR:INTERNAL=Ninja\n")
            with patch.object(module, "ROOT", root), patch.object(
                    module, "public_source_identity", side_effect=AssertionError(
                        "missing snapshot safety inputs must not query Git")), patch.dict(
                        "os.environ", {"GENEWHIP_SOURCE_SNAPSHOT": "1",
                                       "GENEWHIP_SOURCE_REVISION": TEST_REVISION}):
                config = module.configuration(build)
                expected = {"source_revision": TEST_REVISION,
                            "fixture_manifest_sha256": module.sha(root / "fixtures/manifest.json"),
                            "configuration_sha256": module.digest(config)}
                report = module.build_report(build)
                problems = module.validate(report, expected=expected)
            self.assertEqual(problems, [])
            safety = next(row for row in report["rows"] if row["id"] == "safety_contracts")
            self.assertEqual(safety["outcome"], "unknown")
            self.assertEqual(safety["validation_errors"][0]["reason"], "safety-evidence-missing")

        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            ci = build / "ci"
            ci.mkdir()
            (ci / "safety-run.json").write_text("{}\n")
            with patch.object(module, "public_source_identity", side_effect=ValueError(
                    "safety-source-unverifiable")) as identity_check:
                _, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
            identity_check.assert_called_once()
            self.assertIn("safety-source-unverifiable", {reason for reason, _ in problems},
                          "partial-snapshot-safety-evidence-bypassed-source-identity")

    def test_ci_safety_job_uploads_only_curated_sanitized_evidence(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        safety_job = workflow.split("  safety:\n", 1)[1].split("\n  gameplay:", 1)[0]
        self.assertIn("name: Export exact-source safety evidence", safety_job)
        self.assertIn("if: always()", safety_job)
        self.assertIn("name: safety-evidence-${{ github.run_id }}-${{ github.run_attempt }}", safety_job)
        self.assertIn("run: python3 scripts/evidence/phase4_report.py safety-export", safety_job)
        self.assertIn("path: build/safety-export/", safety_job)
        self.assertNotIn("build/ci/", safety_job)
        gate = (ROOT / "scripts/ci/required-gate.sh").read_text()
        default_gate = gate.split('if [[ "${1:-}" == "--phase6-local" ]]; then', 1)[1]
        default_gate = default_gate.split("\nfi\n", 1)[1]
        self.assertIn("ctest-junit.raw.xml", gate)
        self.assertIn("safety-sanitize-junit", gate)
        self.assertTrue(gate.startswith("#!/usr/bin/env bash\nset -euo pipefail"),
                        "CTest failure must remain fatal before artifact sanitization")
        self.assertLess(gate.index("ctest --test-dir \"build/ci/$lane\""),
                        gate.index("safety-sanitize-junit"))
        self.assertLess(gate.index("safety-sanitize-junit"), gate.index("check_ctest_skips.py"))
        self.assertNotIn("--output-on-failure", default_gate)
        self.assertNotIn("ctest-junit.raw.xml", safety_job)
        for path in ("build/ci/native/CMakeCache.txt", "build/ci/sanitizer/CMakeCache.txt",
                     "build/ci/production/CMakeCache.txt"):
            self.assertNotIn(path, safety_job)

    def test_safety_junit_sanitizer_removes_freeform_output_but_keeps_outcomes(self):
        source_xml = ("<testsuites><testsuite><testcase name='test_pass' classname='" +
                      PRIVATE_TEST_PATH + "/class' file='" + PRIVATE_TEST_PATH +
                      "/source.c'><system-out>" + PRIVATE_TEST_PATH +
                      "/stdout</system-out><system-err>" + PRIVATE_TEST_PATH +
                      "/stderr</system-err></testcase><testcase name='independent_game_consumer'>"
                      "<skipped message='" + PRIVATE_TEST_PATH +
                      "/skip'/></testcase><testcase name='test_failure'><failure message='" +
                      PRIVATE_TEST_PATH + "/failure'/></testcase></testsuite></testsuites>")
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "raw.xml"
            output = Path(temporary) / "safe.xml"
            source.write_text(source_xml)
            module.sanitize_ctest_junit(source, output)
            payload = output.read_bytes()
            root = module.ET.fromstring(payload)
            cases = root.findall(".//testcase")
            self.assertEqual([case.get("name") for case in cases],
                             ["test_pass", "independent_game_consumer", "test_failure"])
            self.assertEqual([child.tag for child in cases[1]], ["skipped"])
            self.assertEqual([child.tag for child in cases[2]], ["failure"])
            self.assertEqual(set(cases[0].attrib), {"name"})
            self.assertNotIn(PRIVATE_TEST_PATH.encode(), payload)
            self.assertIsNone(module.PERSONAL_HOME_PATH.search(payload))

    def test_sanitized_ctest_failure_summary_identifies_only_allowlisted_methods(self):
        route_spec = importlib.util.spec_from_file_location(
            "phase6_route_diagnostic_contract", ROOT / "tests/session/phase6_route_contract.py")
        route = importlib.util.module_from_spec(route_spec)
        route_spec.loader.exec_module(route)
        phase5_spec = importlib.util.spec_from_file_location(
            "phase5_baseline_diagnostic_contract", ROOT / "tests/evidence/phase5_baseline_contract.py")
        phase5 = importlib.util.module_from_spec(phase5_spec)
        phase5_spec.loader.exec_module(phase5)
        self.assertEqual(route.SAFE_FAILURE_DIAGNOSTIC_METHODS |
                         phase5.SAFE_FAILURE_DIAGNOSTIC_METHODS,
                         module.SAFE_CTEST_DIAGNOSTIC_METHODS)
        with tempfile.TemporaryDirectory() as temporary:
            source_xml = Path(temporary) / "raw.xml"
            sanitized = Path(temporary) / "safe.xml"
            source_xml.write_text(
                "<testsuites><testsuite><testcase name='phase6_route_contract'>"
                "<failure message='" + PRIVATE_TEST_PATH + "/secret'>" +
                PRIVATE_TEST_PATH + "/traceback private command</failure>"
                "<system-err>GENEWHIP_TEST_RESULT:NativeParserContract."
                "test_bounded_malformed_route_matrix_both_clients:failure\n"
                "GENEWHIP_TEST_RESULT:NativeParserContract."
                "test_process_group_and_stream_caps_are_enforced:error\n" +
                PRIVATE_TEST_PATH + "/raw output</system-err>"
                "</testcase><testcase name='/tmp/PRIVATE_TOKEN&#10;private-command'>"
                "<error message='raw detail'/></testcase></testsuite></testsuites>")
            module.sanitize_ctest_junit(source_xml, sanitized)
            output = sanitized.read_bytes()
            self.assertNotIn(PRIVATE_TEST_PATH.encode(), output)
            self.assertNotIn(b"traceback private command", output)
            self.assertNotIn(b"raw output", output)
            self.assertEqual(module.summarize_sanitized_ctest_failures(sanitized), [
                "CTest failure [error]",
                "CTest failure [failure]",
                "CTest subtest failure: NativeParserContract.test_bounded_malformed_route_matrix_both_clients [failure]",
                "CTest subtest failure: NativeParserContract.test_process_group_and_stream_caps_are_enforced [error]",
            ])
            self.assertNotIn("PRIVATE_TOKEN", "\n".join(
                module.summarize_sanitized_ctest_failures(sanitized)))
            unowned = Path(temporary) / "unowned.xml"
            unowned_output = Path(temporary) / "unowned-safe.xml"
            unowned.write_text(
                "<testsuites><testsuite><testcase name='phase6_route_contract'>"
                "<failure/><system-out>GENEWHIP_TEST_RESULT:NativeParserContract."
                "test_injected_private_command:failure</system-out></testcase></testsuite></testsuites>")
            with self.assertRaisesRegex(ValueError, "safety-ctest-diagnostic-invalid"):
                module.sanitize_ctest_junit(unowned, unowned_output)
            self.assertFalse(unowned_output.exists())

    def test_phase6_runner_emits_only_owned_failure_method_and_kind(self):
        route_spec = importlib.util.spec_from_file_location(
            "phase6_route_diagnostic_contract", ROOT / "tests/session/phase6_route_contract.py")
        route = importlib.util.module_from_spec(route_spec)
        route_spec.loader.exec_module(route)
        failure = route.NativeParserContract("test_bounded_malformed_route_matrix_both_clients")
        error = route.NativeParserContract("test_process_group_and_stream_caps_are_enforced")
        result = type("TestResult", (), {
            "failures": [(failure, PRIVATE_TEST_PATH + "/traceback")],
            "errors": [(error, PRIVATE_TEST_PATH + "/exception")]})()
        with tempfile.TemporaryFile(mode="w+t") as diagnostic:
            with patch("sys.stderr", diagnostic):
                route._emit_safe_failure_diagnostics(result)
            diagnostic.seek(0)
            emitted = diagnostic.read()
        self.assertEqual(emitted.splitlines(), [
            "GENEWHIP_TEST_RESULT:NativeParserContract.test_bounded_malformed_route_matrix_both_clients:failure",
            "GENEWHIP_TEST_RESULT:NativeParserContract.test_process_group_and_stream_caps_are_enforced:error",
        ])
        self.assertNotIn(PRIVATE_TEST_PATH, emitted)

    def test_phase5_runner_failure_is_sanitized_to_exact_method_and_kind(self):
        import contextlib
        import io
        from types import SimpleNamespace

        phase5_spec = importlib.util.spec_from_file_location(
            "phase5_baseline_diagnostic_contract", ROOT / "tests/evidence/phase5_baseline_contract.py")
        phase5 = importlib.util.module_from_spec(phase5_spec)
        phase5_spec.loader.exec_module(phase5)
        methods = frozenset("BaselineRecordContract." + name
            for name, value in vars(phase5.BaselineRecordContract).items()
            if name.startswith("test_") and callable(value))
        self.assertEqual(phase5.SAFE_FAILURE_DIAGNOSTIC_METHODS, methods)
        self.assertTrue(methods <= module.SAFE_CTEST_DIAGNOSTIC_METHODS)

        suite = unittest.TestSuite([
            phase5.BaselineRecordContract("test_valid_record_round_trips"),
            phase5.BaselineRecordContract("test_status_only_pass_is_rejected")])
        private_token = "PRIVATE" + "_TOKEN"
        private_message = PRIVATE_TEST_PATH + "/" + private_token
        process_tools = SimpleNamespace(process_boundary=lambda: SimpleNamespace(
            require_host_process_context=lambda: None))
        with tempfile.TemporaryDirectory() as temporary:
            raw_output = io.StringIO()
            with patch.object(phase5.baseline, "process_tools", return_value=process_tools), \
                    patch.object(phase5.unittest.defaultTestLoader, "loadTestsFromTestCase",
                        return_value=suite), \
                    patch.object(phase5.BaselineRecordContract, "test_valid_record_round_trips",
                        side_effect=AssertionError(private_message)), \
                    patch.object(phase5.BaselineRecordContract, "test_status_only_pass_is_rejected",
                        side_effect=RuntimeError(private_message)), \
                    patch.object(sys, "argv", ["phase5_baseline_contract.py", "--self-test"]), \
                    contextlib.redirect_stderr(raw_output):
                self.assertEqual(phase5.main(), 1)
            expected_markers = [
                "GENEWHIP_TEST_RESULT:BaselineRecordContract.test_valid_record_round_trips:failure",
                "GENEWHIP_TEST_RESULT:BaselineRecordContract.test_status_only_pass_is_rejected:error",
            ]
            raw_text = raw_output.getvalue()
            self.assertTrue(all(marker in raw_text for marker in expected_markers))
            raw_xml = Path(temporary) / "raw.xml"
            safe_xml = Path(temporary) / "safe.xml"
            root = module.ET.Element("testsuites")
            suite_node = module.ET.SubElement(root, "testsuite")
            case = module.ET.SubElement(suite_node, "testcase", {"name": "phase5_baseline_contract"})
            module.ET.SubElement(case, "failure", {"message": private_message}).text = private_message
            module.ET.SubElement(case, "system-err").text = raw_text
            raw_xml.write_bytes(module.ET.tostring(root, encoding="utf-8"))
            module.sanitize_ctest_junit(raw_xml, safe_xml)
            sanitized = safe_xml.read_bytes()
            self.assertNotIn(PRIVATE_TEST_PATH.encode(), sanitized)
            self.assertNotIn(private_token.encode(), sanitized)
            self.assertNotIn(b"AssertionError", sanitized)
            self.assertNotIn(b"RuntimeError", sanitized)
            self.assertEqual(module.summarize_sanitized_ctest_failures(safe_xml), [
                "CTest failure [failure]",
                "CTest subtest failure: BaselineRecordContract.test_status_only_pass_is_rejected [error]",
                "CTest subtest failure: BaselineRecordContract.test_valid_record_round_trips [failure]",
            ])

            unknown_xml = Path(temporary) / "unknown.xml"
            unknown_safe = Path(temporary) / "unknown-safe.xml"
            unknown_root = module.ET.Element("testsuites")
            unknown_suite = module.ET.SubElement(unknown_root, "testsuite")
            unknown_case = module.ET.SubElement(unknown_suite, "testcase",
                {"name": "phase5_baseline_contract"})
            module.ET.SubElement(unknown_case, "failure")
            module.ET.SubElement(unknown_case, "system-out").text = (
                "GENEWHIP_TEST_RESULT:BaselineRecordContract.test_injected_" + private_token + ":failure")
            unknown_xml.write_bytes(module.ET.tostring(unknown_root, encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "safety-ctest-diagnostic-invalid"):
                module.sanitize_ctest_junit(unknown_xml, unknown_safe)
            self.assertFalse(unknown_safe.exists())

    def test_safety_junit_residual_private_path_rejects_without_output(self):
        windows_marker = "C:" + chr(92) + "Users" + chr(92) + "example" + chr(92) + "leak"
        for marker in (PRIVATE_TEST_PATH + "/leak", windows_marker):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / "raw.xml"
                output = Path(temporary) / "safe.xml"
                source.write_text("<testsuites><testsuite><testcase name='" +
                                  marker + "'/></testsuite></testsuites>")
                with self.assertRaisesRegex(ValueError, "safety-ctest-personal-path"):
                    module.sanitize_ctest_junit(source, output)
                self.assertFalse(output.exists(), "unsafe JUnit destination was emitted")

    def test_failed_ctest_cannot_export_safety_artifacts(self):
        identity = {"source_revision": TEST_REVISION, "source_tree_id": "c" * 40}
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            create_complete_safety_build(build)
            lane = build / "ci/native"
            raw = lane / "failed.raw.xml"
            failed_report = module.ET.parse(lane / "ctest-junit.xml").getroot()
            failed_case = failed_report.find(".//testcase")
            module.ET.SubElement(failed_case, "failure").text = "test failed"
            raw.write_bytes(module.ET.tostring(failed_report, encoding="utf-8"))
            module.sanitize_ctest_junit(raw, lane / "ctest-junit.xml")
            output = build / "safety-export"
            output.mkdir()
            (output / "stale.txt").write_text("must be invalidated")
            with patch.object(module, "public_source_identity", return_value=identity):
                with self.assertRaisesRegex(ValueError, "safety-ctest-outcome"):
                    module.safety_complete_lane(build, "native")
                with self.assertRaisesRegex(ValueError, "safety-ctest-outcome|safety-lane-artifact-mismatch"):
                    module.safety_export(build, output)
            self.assertFalse(output.exists(), "failed CTest evidence was exported")

    def test_safety_export_is_curated_and_binds_the_sanitized_junit_bytes(self):
        identity = {"source_revision": TEST_REVISION, "source_tree_id": "c" * 40}
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            create_complete_safety_build(build)
            for lane in module.SAFETY_LANES:
                (build / "ci" / lane / "CMakeCache.txt").unlink()
            output = build / "safety-export"
            with patch.object(module, "public_source_identity", return_value=identity):
                module.safety_export(build, output)
                evidence, problems = module.collect_safety_contracts(
                    build, expected_revision=TEST_REVISION)
            self.assertTrue((output / "native/ctest-junit.xml").is_file())
            self.assertFalse(any(path.name in {"CMakeCache.txt", "ctest-junit.raw.xml"}
                                 for path in output.rglob("*")))
            for lane in module.SAFETY_LANES:
                exported = output / lane / "ctest-junit.xml"
                live = build / "ci" / lane / "ctest-junit.xml"
                self.assertEqual(exported.read_bytes(), live.read_bytes())
            self.assertEqual(problems, [])
            self.assertEqual(module.sha(output / "native/ctest-junit.xml"),
                             evidence["lanes"]["native"]["ctest"]["junit_sha256"])

    def test_safety_contract_row_requires_three_source_bound_gate_lanes(self):
        evidence = synthetic_safety_contracts()
        self.assertEqual(module.validate_safety_contracts(evidence, expected_revision=TEST_REVISION), [])

    def test_safety_config_rejects_unexpected_fields_and_private_values(self):
        evidence = synthetic_safety_contracts()
        evidence["lanes"]["native"]["configuration"]["values"]["CMAKE_HOME_DIRECTORY"] = PRIVATE_TEST_PATH + "/src"
        reasons = {name for name, _ in module.validate_safety_contracts(
            evidence, expected_revision=TEST_REVISION)}
        self.assertIn("safety-config-invalid", reasons,
                      "unexpected-path-bearing-config-field-accepted")

        identity = {"source_revision": TEST_REVISION, "source_tree_id": "c" * 40}
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            with patch.object(module, "public_source_identity", return_value=identity):
                module.safety_start(build)
                lane_dir = build / "ci/native"
                lane_dir.mkdir(parents=True)
                (lane_dir / "CMakeCache.txt").write_text(
                    "CMAKE_BUILD_TYPE:STRING=Release\nCMAKE_GENERATOR:INTERNAL=Unix Makefiles\n"
                    "GENEWHIP_TEST_HOOKS:BOOL=ON\nCMAKE_C_COMPILER_ID:STRING=AppleClang\n"
                    "CMAKE_C_COMPILER_VERSION:STRING=" + PRIVATE_TEST_PATH + "/toolchain\n")
                with self.assertRaisesRegex(ValueError, "safety-config-invalid"):
                    module.safety_complete_lane(build, "native")
            self.assertFalse((lane_dir / "safety-config.json").exists(),
                             "private CMake value was emitted as sanitized config")

        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            create_complete_safety_build(build)
            for lane in module.SAFETY_LANES:
                (build / "ci" / lane / "CMakeCache.txt").unlink()
            config_path = build / "ci/native/safety-config.json"
            config = json.loads(config_path.read_text())
            config["values"]["CMAKE_C_COMPILER_VERSION"] = PRIVATE_TEST_PATH + "/compiler"
            config_path.write_text(json.dumps(config))
            with patch.object(module, "public_source_identity", return_value=identity):
                _, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
            self.assertIn("safety-config-invalid", {reason for reason, _ in problems},
                          "private sanitized-config-value-accepted")

    def test_safety_config_extracts_compiler_identity_from_cmake_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            (build / "CMakeCache.txt").write_text(
                "CMAKE_BUILD_TYPE:STRING=Release\nCMAKE_GENERATOR:INTERNAL=Unix Makefiles\n"
                "GENEWHIP_TEST_HOOKS:BOOL=ON\nCMAKE_C_COMPILER:FILEPATH=" + PRIVATE_TEST_PATH + "/bin/cc\n")
            compiler_file = build / "CMakeFiles/4.4.3/CMakeCCompiler.cmake"
            compiler_file.parent.mkdir(parents=True)
            compiler_file.write_text(
                'set(CMAKE_C_COMPILER_ID "AppleClang")\n'
                'set(CMAKE_C_COMPILER_VERSION "21.0.0.21000101")\n'
                'set(CMAKE_C_COMPILER "' + PRIVATE_TEST_PATH + '/bin/cc")\n')
            normalized = module._safety_configuration_from_cache(build / "CMakeCache.txt", "native")
            self.assertEqual(normalized["values"]["CMAKE_C_COMPILER_ID"], "AppleClang")
            self.assertEqual(normalized["values"]["CMAKE_C_COMPILER_VERSION"], "21.0.0.21000101")
            self.assertNotIn(PRIVATE_TEST_PATH, json.dumps(normalized))

    def test_safety_config_accepts_only_supported_single_config_generators(self):
        for generator in ("Unix Makefiles", "Ninja"):
            with self.subTest(generator=generator):
                config = synthetic_safety_config("native")
                config["values"]["CMAKE_GENERATOR"] = generator
                self.assertEqual(module._validate_safety_configuration(config, "native"), config)

        for generator in ("Ninja Multi-Config", "Xcode"):
            with self.subTest(generator=generator):
                evidence = synthetic_safety_contracts()
                evidence["lanes"]["native"]["configuration"]["values"]["CMAKE_GENERATOR"] = generator
                reasons = {name for name, _ in module.validate_safety_contracts(
                    evidence, expected_revision=TEST_REVISION)}
                self.assertIn("safety-config-invalid", reasons,
                              "production-validator-accepted-unsupported-generator")

        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "CMakeCache.txt"
            cache.write_text(
                "CMAKE_BUILD_TYPE:STRING=Release\nCMAKE_GENERATOR:INTERNAL=Xcode\n"
                "GENEWHIP_TEST_HOOKS:BOOL=ON\nCMAKE_C_COMPILER_ID:STRING=AppleClang\n"
                "CMAKE_C_COMPILER_VERSION:STRING=21.0.0\n")
            with self.assertRaisesRegex(ValueError, "safety-config-invalid"):
                module._safety_configuration_from_cache(cache, "native")

        identity = {"source_revision": TEST_REVISION, "source_tree_id": "c" * 40}
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            create_complete_safety_build(build)
            for lane in module.SAFETY_LANES:
                (build / "ci" / lane / "CMakeCache.txt").unlink()
            config_path = build / "ci/native/safety-config.json"
            config = json.loads(config_path.read_text())
            config["values"]["CMAKE_GENERATOR"] = "Ninja Multi-Config"
            config_path.write_text(json.dumps(config))
            with patch.object(module, "public_source_identity", return_value=identity):
                _, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
            self.assertIn("safety-config-invalid", {reason for reason, _ in problems},
                          "collector-accepted-unsupported-generator")

    def test_safety_contract_row_rejects_unexpected_skip_and_failed_ctest(self):
        evidence = synthetic_safety_contracts()
        evidence["lanes"]["native"]["ctest"]["skipped"] = ["independent_game_admission", "unexpected-new-skip"]
        reasons = {name for name, _ in module.validate_safety_contracts(evidence, expected_revision=TEST_REVISION)}
        self.assertIn("safety-unexpected-skip", reasons)
        evidence = synthetic_safety_contracts()
        evidence["lanes"]["sanitizer"]["ctest"]["fail"] = 1
        reasons = {name for name, _ in module.validate_safety_contracts(evidence, expected_revision=TEST_REVISION)}
        self.assertIn("safety-ctest-outcome", reasons)

    def test_safety_contract_accepts_any_subset_of_legacy_skips(self):
        for skipped in ([], ["independent_game_admission"],
                        ["independent_game_consumer"]):
            with self.subTest(skipped=skipped):
                evidence = synthetic_safety_contracts()
                for lane in evidence["lanes"].values():
                    lane["ctest"]["skipped"] = list(skipped)
                    lane["ctest"]["pass"] = lane["ctest"]["denominator"] - len(skipped)
                resign_safety_evidence(evidence)
                self.assertEqual(module.validate_safety_contracts(
                    evidence, expected_revision=TEST_REVISION), [])

    def test_safety_contract_rejects_duplicate_skip_entries(self):
        evidence = synthetic_safety_contracts()
        evidence["lanes"]["native"]["ctest"]["skipped"] = [
            "independent_game_admission", "independent_game_admission"]
        reasons = {name for name, _ in module.validate_safety_contracts(
            evidence, expected_revision=TEST_REVISION)}
        self.assertIn("safety-duplicate-skip", reasons)

    def test_safety_ctest_requires_the_recorded_denominator_and_critical_roster(self):
        evidence = synthetic_safety_contracts()
        evidence["lanes"]["native"]["ctest"]["case_names"].remove("gameplay_bus_contract")
        evidence["lanes"]["native"]["ctest"]["case_names"].append("replacement-test")
        evidence["lanes"]["native"]["ctest"]["test_inventory_sha256"] = module.digest(
            sorted(evidence["lanes"]["native"]["ctest"]["case_names"]))
        reasons = {name for name, _ in module.validate_safety_contracts(
            evidence, expected_revision=TEST_REVISION)}
        self.assertIn("safety-ctest-roster", reasons,
                      "missing-critical-CTest-case-accepted-at-full-denominator")
        evidence = synthetic_safety_contracts()
        evidence["lanes"]["production"]["ctest"]["denominator"] -= 1
        evidence["lanes"]["production"]["ctest"]["case_names"].pop()
        evidence["lanes"]["production"]["ctest"]["test_inventory_sha256"] = module.digest(
            sorted(evidence["lanes"]["production"]["ctest"]["case_names"]))
        reasons = {name for name, _ in module.validate_safety_contracts(
            evidence, expected_revision=TEST_REVISION)}
        self.assertIn("safety-ctest-roster", reasons,
                      "reduced-production-CTest-denominator-accepted")

    def test_safety_contract_row_rejects_stale_source_and_mutated_contract_summary(self):
        evidence = synthetic_safety_contracts()
        evidence["lanes"]["production"]["source_revision"] = "stale-head"
        reasons = {name for name, _ in module.validate_safety_contracts(evidence, expected_revision=TEST_REVISION)}
        self.assertIn("safety-stale-source", reasons)
        evidence = synthetic_safety_contracts()
        evidence["lanes"]["native"]["summary"]["audio_pass"] = 255
        evidence["lanes"]["native"]["summary_sha256"] = module.digest(
            evidence["lanes"]["native"]["summary"])
        reasons = {name for name, _ in module.validate_safety_contracts(evidence, expected_revision=TEST_REVISION)}
        self.assertIn("safety-summary-contract", reasons)
        evidence = synthetic_safety_contracts()
        evidence["lanes"]["production"]["summary"]["negative_controls"] = 6
        evidence["lanes"]["production"]["summary_sha256"] = module.digest(
            evidence["lanes"]["production"]["summary"])
        reasons = {name for name, _ in module.validate_safety_contracts(evidence, expected_revision=TEST_REVISION)}
        self.assertIn("safety-summary-contract", reasons,
                      "stale negative-control denominator accepted with matching identity")

    def test_safety_producer_reads_and_hashes_gate_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            identity = {"source_revision": TEST_REVISION, "source_tree_id": "c" * 40}
            (build / "ci").mkdir()
            summary_values = {}
            expected = synthetic_safety_contracts()
            with patch.object(module, "public_source_identity", return_value=identity):
                module.safety_start(build)
                for name in module.SAFETY_LANES:
                    lane_dir = build / "ci" / name
                    lane_dir.mkdir(parents=True, exist_ok=True)
                    hooks = "OFF" if name == "production" else "ON"
                    (lane_dir / "CMakeCache.txt").write_text(
                        "CMAKE_BUILD_TYPE:STRING=Release\nCMAKE_C_COMPILER_ID:STRING=AppleClang\n"
                        "CMAKE_C_COMPILER_VERSION:STRING=17.0\nCMAKE_GENERATOR:INTERNAL=Ninja\n"
                        "CMAKE_HOME_DIRECTORY:INTERNAL=" + PRIVATE_TEST_PATH + "/worktree\n"
                        "CMAKE_CACHEFILE_DIR:INTERNAL=" + PRIVATE_TEST_PATH + "/worktree/build\n"
                        f"GENEWHIP_BUILD_DESKTOP:BOOL=OFF\nGENEWHIP_TEST_HOOKS:BOOL={hooks}\n")
                    summary = expected["lanes"][name]["summary"]
                    summary_values[name] = summary
                    cases = []
                    for case_name in expected["lanes"][name]["ctest"]["case_names"]:
                        if case_name in module.SAFETY_ALLOWED_SKIPS:
                            cases.append(f"<testcase name='{case_name}'><skipped/></testcase>")
                        else:
                            cases.append(f"<testcase name='{case_name}'/>")
                    xml = "<testsuites><testsuite>" + "".join(cases) + "</testsuite></testsuites>"
                    (lane_dir / "ctest-junit.xml").write_text(xml)
                    (lane_dir / "safety-contract.json").write_text(json.dumps(summary))
                    module.safety_complete_lane(build, name)
                module.safety_finish(build)
                for name in module.SAFETY_LANES:
                    cache_path = build / "ci" / name / "CMakeCache.txt"
                    config_path = build / "ci" / name / "safety-config.json"
                    self.assertTrue(config_path.is_file())
                    self.assertNotIn(str(build), config_path.read_text())
                    self.assertNotIn(PRIVATE_TEST_PATH, config_path.read_text())
                    self.assertNotIn("CMAKE_HOME_DIRECTORY", config_path.read_text())
                    self.assertNotIn("CMAKE_CACHEFILE_DIR", config_path.read_text())
                    cache_path.unlink()
                evidence, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
            self.assertEqual(problems, [])
            self.assertEqual(evidence["lanes"]["native"]["ctest"]["denominator"], 131)
            self.assertEqual(evidence["lanes"]["native"]["ctest"]["pass"], 129)
            self.assertRegex(evidence["lanes"]["native"]["ctest"]["junit_sha256"], r"^[0-9a-f]{64}$")
            config_path = build / "ci/native/safety-config.json"
            config_bytes = config_path.read_bytes()
            config_path.unlink()
            with patch.object(module, "public_source_identity", return_value=identity):
                _, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
            self.assertIn("safety-evidence-incomplete", {reason for reason, _ in problems},
                          "collector-accepted-missing-sanitized-config")
            config_path.write_bytes(config_bytes)
            lane = build / "ci/native/ctest-junit.xml"
            lane.write_text(lane.read_text() + "\n")
            with patch.object(module, "public_source_identity", return_value=identity):
                evidence, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
            self.assertIn("safety-lane-artifact-mismatch", {reason for reason, _ in problems},
                          "producer-accepted-mutated-CTest-output")

    def test_safety_producer_rejects_partial_stale_mutated_and_dirty_runs(self):
        identity = {"source_revision": TEST_REVISION, "source_tree_id": "c" * 40}
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            with patch.object(module, "public_source_identity", return_value=identity):
                module.safety_start(build)
                evidence, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
            self.assertIn("safety-evidence-incomplete", {reason for reason, _ in problems},
                          "interrupted-run-without-completion-accepted")

        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            create_complete_safety_build(build)
            with patch.object(module, "public_source_identity", return_value=identity):
                completion = build / "ci/sanitizer/safety-completion.json"
                record = json.loads(completion.read_text())
                record["run_id"] = "f" * 32
                completion.write_text(json.dumps(record))
                _, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
            self.assertIn("safety-lane-run-mismatch", {reason for reason, _ in problems},
                          "stale-lane-completion-accepted")

        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            create_complete_safety_build(build)
            with patch.object(module, "public_source_identity", side_effect=ValueError("safety-source-dirty")):
                _, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
            self.assertIn("safety-source-dirty", {reason for reason, _ in problems},
                          "dirty-public-source-acquired-fresh-safety-label")

    def test_safety_producer_rejects_non_object_run_lane_and_final_records(self):
        identity = {"source_revision": TEST_REVISION, "source_tree_id": "c" * 40}
        malformed = ([], None, "scalar")
        for value in malformed:
            with self.subTest(record="run", value=value), tempfile.TemporaryDirectory() as temporary:
                build = Path(temporary)
                ci = build / "ci"
                ci.mkdir()
                (ci / "safety-run.json").write_text(json.dumps(value))
                with patch.object(module, "public_source_identity", return_value=identity):
                    _, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
                self.assertIn("safety-run-invalid", {reason for reason, _ in problems})
                with self.assertRaisesRegex(ValueError, "safety-run-invalid"):
                    module.safety_complete_lane(build, "native")
                with self.assertRaisesRegex(ValueError, "safety-run-invalid"):
                    module.safety_finish(build)

            with self.subTest(record="lane", value=value), tempfile.TemporaryDirectory() as temporary:
                build = Path(temporary)
                create_complete_safety_build(build)
                lane_record = build / "ci/native/safety-completion.json"
                lane_record.write_text(json.dumps(value))
                with patch.object(module, "public_source_identity", return_value=identity):
                    _, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
                self.assertIn("safety-lane-record-invalid", {reason for reason, _ in problems})
                with patch.object(module, "public_source_identity", return_value=identity):
                    with self.assertRaisesRegex(ValueError, "safety-lane-record-invalid"):
                        module.safety_finish(build)

            with self.subTest(record="final", value=value), tempfile.TemporaryDirectory() as temporary:
                evidence = synthetic_safety_contracts()
                evidence["final_record"] = value
                self.assertIn("safety-final-record-invalid", {
                    reason for reason, _ in module.validate_safety_contracts(
                        evidence, expected_revision=TEST_REVISION)})
                build = Path(temporary)
                create_complete_safety_build(build)
                (build / "ci/safety-complete.json").write_text(json.dumps(value))
                with patch.object(module, "public_source_identity", return_value=identity):
                    _, problems = module.collect_safety_contracts(build, expected_revision=TEST_REVISION)
                self.assertIn("safety-final-record-invalid", {reason for reason, _ in problems})

    def test_delivery_evidence_requires_bound_runs_release_and_downloaded_adoption(self):
        evidence = {"schema": "genewhip.hosted-delivery.v1", "repository": "szTheory/genewhip",
                    "pull_request": 12, "pull_request_head_sha": "a" * 40,
                    "pull_request_base_sha": "b" * 40, "merged_source_sha": "c" * 40,
                    "publisher_source_sha": "d" * 40,
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
        evidence["publisher_source_sha"] = "not-a-commit"
        self.assertIn("delivery-identity-invalid", module.validate_delivery_evidence(evidence))
        evidence["publisher_source_sha"] = "d" * 40
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

    def test_live_display_inventory_unknown_is_retained_without_claiming_refresh(self):
        evidence = {"software": synthetic_host_report("software"),
                    "live": synthetic_host_report("live")}
        evidence["live"]["runs"][0]["host_settings"]["display_identity"] = {
            "status": "unavailable", "reason": "system_profiler returned no display rows"}
        evidence["live"]["runs"][1]["host_settings"]["display_identity"] = {
            "status": "observed", "displays": [{"refresh_hz": None}]}
        self.assertEqual(module.validate_host_sessions(evidence), [])

    def test_live_display_unavailable_requires_reason_and_cocoa_driver(self):
        for mutate in (
            lambda row: row["host_settings"].update(
                display_identity={"status": "unavailable", "displays": []}),
            lambda row: row["host_settings"].update(video_driver="dummy"),
        ):
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
        expected["source_revision"] = TEST_REVISION
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
        expected["source_revision"] = TEST_REVISION
        expected["performance_identity"] = {
            "build_configuration_sha256": "build-identity",
            "benchmark_binary_sha256": "e" * 64,
            "source_identity_sha256": bench_test.benchmark.source_identity()}
        reasons = {name for name, _ in module.validate(report, qualification=False, expected=expected)}
        self.assertIn("performance-stale-identity", reasons)


if __name__ == "__main__":
    if SYNTHETIC_EXPORT:
        names = [name for name in unittest.defaultTestLoader.getTestCaseNames(ReportContract)
                 if name.startswith(("test_host_export", "test_producer_export", "test_live_display",
                                     "test_desktop_", "test_ci_desktop"))]
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(ReportContract(name) for name in names))
        production_attempts = len(PROCESS_DENIALS) - 1
        production_denied = len(PROCESS_DENIALS[1:])
        # Exercise restored original API again: caught denials stay observable.
        try:
            subprocess.Popen(["/__no_usable_export_client__"])
        except PermissionError:
            pass
        sticky = PROCESS_DENIALS == ["subprocess.Popen", "subprocess.Popen"]
        print(json.dumps({"preimport_denial": PROCESS_DENIALS[:1], "sticky_denial": sticky,
                          "production_process_attempts": production_attempts,
                          "production_process_denied": production_denied,
                          "production_process_starts": production_attempts - production_denied,
                          "tests_run": result.testsRun}, sort_keys=True))
        sys.exit(0 if result.wasSuccessful() and production_attempts == 0 and sticky else 1)
    else:
        unittest.main(verbosity=2)
