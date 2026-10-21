#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect and validate the versioned Phase 4 evidence roster."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "genewhip-phase4-evidence"
VERSION = 1
TRACER_SCHEMA = "genewhip-phase4-tracer"
OUTCOMES = ("pass", "fail", "unknown", "unsupported", "skipped", "infrastructure-error")
ROSTER = (
    ("diagnostic_public_clients", True),
    ("independent_gameplay", True),
    ("safety_contracts", True),
    ("core_performance", True),
    ("desktop_pacing", True),
    ("exact_packages", True),
    ("hosted_delivery", True),
)
CONFIG_KEYS = ("CMAKE_BUILD_TYPE", "CMAKE_C_COMPILER_ID", "CMAKE_C_COMPILER_VERSION",
               "CMAKE_GENERATOR", "GENEWHIP_BUILD_DESKTOP", "GENEWHIP_TEST_HOOKS")
GAME_CASES = ("title-no-start", "start-idle", "start-move", "action-sound",
              "action-no-trigger", "sustained-play")
GAME_FIELDS = (12, 20, 40, 24, 24, 720)
GAME_EXPECTATIONS = ((0, 0, 0, [], 0, None), (1, 0, 0, [], 0, None),
                     (1, 1, 39, [], 0, None), (1, 0, 0, [132, 2, 144], 1, None),
                     (1, 1, 39, [], 0, 0), (1, 39, 39, [132, 2, 144], 1, None))
GAME_IDENTITIES = {"source_sha256": "b74cd12ec371767e8fb338feca808e59e63f569eb93298bb2470d20f8e4e9cfe",
                   "rom_sha256": "7bdffe43fc1b6e4ac623e16298e3bd0a775de6cb4db2758695dbef0e200f4adb",
                   "scenario_sha256": "c702dd10287a9363405fd9269e05989954eb447d0973246bb59a10f74920dbb2",
                   "oracle_sha256": "1a9d99cb01496f26fe3dc33d0c1bcb0cf22bd9178088fa183e5bba37a8600f42"}
HOST_SCHEMA = "genewhip-phase4-host-sessions"
HOST_CONTROLS = ROOT / "fixtures/independent-game-v2/host-controls.json"
HOST_HEX = re.compile(r"^[0-9a-f]{64}$")


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def count(rows):
    return {name: sum(row.get("outcome") == name for row in rows) for name in OUTCOMES}


def git_head():
    snapshot_revision = os.environ.get("GENEWHIP_SOURCE_REVISION")
    if snapshot_revision:
        return snapshot_revision
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                          text=True, stdout=subprocess.PIPE).stdout.strip()


def source_state():
    if os.environ.get("GENEWHIP_SOURCE_SNAPSHOT") == "1":
        return "clean"
    result = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT,
                            check=True, text=True, stdout=subprocess.PIPE)
    return "dirty" if result.stdout else "clean"


def configuration(build):
    cache = Path(build) / "CMakeCache.txt"
    if not cache.is_file():
        raise ValueError("CMakeCache.txt is missing from build directory")
    values = {}
    for line in cache.read_text(errors="replace").splitlines():
        match = re.match(r"^([^:]+):[^=]+=(.*)$", line)
        if match and match.group(1) in CONFIG_KEYS:
            values[match.group(1)] = match.group(2)
    return {"cmake": values, "host": {"system": platform.system(), "machine": platform.machine()}}


def expected_tracer_identity(build):
    scenario_path = ROOT / "fixtures/raster-toy/scenario.json"
    scenario = json.loads(scenario_path.read_text())
    source_path = ROOT / scenario["rom"]["source"]
    rom_path = ROOT / scenario["rom"]["path"]
    ticks = scenario["inputs"]["ticks_per_field"]
    input_bytes = ("genewhip-input-log 1\n" + "".join(
        "%d pad %d %x\n" % (int(entry["field"]) * ticks, int(entry["port"]), int(entry["mask"], 0))
        for entry in scenario["inputs"]["entries"])).encode()
    build = Path(build).resolve()
    headless, desktop = build / "tools/session/gw_headless", build / "tools/desktop/genewhip-desktop"
    identity = {
        "fixture": "fixtures/raster-toy",
        "profile": "VA3 NTSC-U",
        "source_sha256": sha(source_path),
        "scenario_sha256": sha(scenario_path),
        "rom_sha256": sha(rom_path),
        "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
        "build_configuration_sha256": digest(configuration(build)),
        "headless_build_sha256": sha(headless) if headless.is_file() else None,
        "desktop_build_sha256": sha(desktop) if desktop.is_file() else None,
    }
    return identity


def validate_gameplay(evidence, qualification=False, expected_identity=None):
    problems = []
    if not isinstance(evidence, dict) or evidence.get("schema") != "genewhip-phase4-gameplay-v1" or evidence.get("version") != 1:
        return [("gameplay-schema", "invalid gameplay schema/version")]
    if evidence.get("outcome") != "pass":
        problems.append(("gameplay-outcome", str(evidence.get("outcome"))))
    if evidence.get("fixture_id") != "genewhip-independent-game-v2":
        problems.append(("gameplay-fixture", "unexpected fixture id"))
    for key, value in GAME_IDENTITIES.items():
        if evidence.get(key) != value:
            problems.append(("stale-game-" + key.removesuffix("_sha256"), key))
    if evidence.get("profile") != "VA3-NTSC-U":
        problems.append(("stale-game-profile", str(evidence.get("profile"))))
    visual = evidence.get("visual_observations")
    if not isinstance(visual, dict) or visual.get("title_to_play_field_10_changed") is not True or \
            visual.get("start_idle_to_moved_marker_field_19_changed") is not True:
        problems.append(("gameplay-visual-oracle", "title/movement rendered pixels did not satisfy source-derived comparisons"))
    for key in ("build_configuration_sha256",):
        if not isinstance(evidence.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", evidence[key]):
            problems.append(("gameplay-identity", key))
    clients = evidence.get("clients")
    if not isinstance(clients, list) or any(name not in ("headless", "desktop") for name in clients) or len(set(clients)) != len(clients):
        problems.append(("gameplay-clients", "invalid client roster"))
    if qualification and clients != ["headless", "desktop"]:
        problems.append(("gameplay-client-missing", "headless and desktop are both required"))
    client_digests = evidence.get("client_sha256")
    if not isinstance(client_digests, list) or len(client_digests) != (len(clients) if isinstance(clients, list) else -1) or any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in client_digests):
        problems.append(("gameplay-identity", "client_sha256"))
    if expected_identity:
        for key, reason in (("build_configuration_sha256", "gameplay-stale-configuration"),
                            ("client_sha256", "gameplay-stale-client")):
            if evidence.get(key) != expected_identity.get(key):
                problems.append((reason, key))
    rows = evidence.get("results")
    if not isinstance(rows, list):
        return problems + [("gameplay-roster", "results must be a list")]
    if evidence.get("denominator") != len(rows):
        problems.append(("gameplay-denominator", "case denominator differs"))
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            problems.append(("gameplay-row", "case must be an object")); continue
        case_id = row.get("id")
        if case_id not in GAME_CASES or case_id in seen:
            problems.append(("gameplay-case-roster", str(case_id))); continue
        seen.add(case_id)
        index = GAME_CASES.index(case_id)
        play, low, high, psg, minimum_ac, maximum_ac = GAME_EXPECTATIONS[index]
        if row.get("outcome") != "pass": problems.append(("gameplay-case-non-pass", case_id))
        if row.get("unsupported") != 0: problems.append(("gameplay-unsupported", case_id))
        if row.get("fields") != GAME_FIELDS[index]: problems.append(("gameplay-field-budget", case_id))
        if row.get("play_state") != play or not isinstance(row.get("position"), int) or not low <= row["position"] <= high:
            problems.append(("gameplay-source-state", case_id))
        if row.get("psg") != psg:
            problems.append(("gameplay-causal-psg", case_id))
        if not isinstance(row.get("ac_range"), int) or row["ac_range"] < minimum_ac or \
                (maximum_ac is not None and row["ac_range"] != maximum_ac):
            problems.append(("gameplay-waveform", case_id))
        if not isinstance(row.get("input_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["input_sha256"]):
            problems.append(("gameplay-identity", case_id + " input"))
        if not isinstance(row.get("machine_digest"), str) or not isinstance(row.get("field_hashes_sha256"), str):
            problems.append(("gameplay-observation", case_id))
        if clients == ["headless", "desktop"] and row.get("desktop_equal") is not True:
            problems.append(("gameplay-client-divergence", case_id))
    for case_id in set(GAME_CASES) - seen:
        problems.append(("gameplay-case-missing", case_id))
    if evidence.get("fields") != sum(GAME_FIELDS):
        problems.append(("gameplay-total-fields", "expected full frozen denominator"))
    return problems


def host_fixture_identities():
    document = json.loads(HOST_CONTROLS.read_text())
    result = {}
    for key, session in document["sessions"].items():
        scenario_path = ROOT / session["scenario"]
        scenario = json.loads(scenario_path.read_text())
        source_path = ROOT / (scenario["source"]["relative_path"] if session["scenario_case"]
                              else scenario["rom"]["source"])
        result[key] = {"fixture_id": session["fixture_id"],
                       "scenario_sha256": sha(scenario_path), "source_sha256": sha(source_path),
                       "rom_sha256": sha(ROOT / session["rom"])}
    return result


def validate_host_sessions(evidence, expected_revision=None, expected_identity=None):
    """Validate finite desktop observations and their exact build/fixture identities."""
    problems = []
    if not isinstance(evidence, dict) or not {"software", "live"} <= set(evidence):
        return [("desktop-host-schema", "software and live evidence are required")]
    expected_identity = expected_identity or {}
    fixture_identities = host_fixture_identities()
    control_sha = sha(HOST_CONTROLS)
    all_ids = set()
    for mode in ("software", "live"):
        report = evidence.get(mode)
        if not isinstance(report, dict) or report.get("schema") != HOST_SCHEMA or report.get("version") != 1:
            problems.append(("desktop-host-schema", mode)); continue
        if report.get("mode") != mode:
            problems.append(("desktop-host-schema", mode + " mode mismatch"))
        if expected_revision and report.get("source_revision") != expected_revision:
            problems.append(("desktop-host-stale-source", mode))
        if report.get("control_sha256") != control_sha:
            problems.append(("desktop-host-control-identity", mode))
        for field, reason in (("build_configuration_sha256", "desktop-host-stale-build"),
                              ("desktop_build_sha256", "desktop-host-stale-build"),
                              ("headless_build_sha256", "desktop-host-stale-build")):
            expected = expected_identity.get(field)
            if expected and report.get(field) != expected:
                problems.append((reason, mode + " " + field))
        if report.get("outcome") not in (("pass",) if mode == "software" else ("pass", "skipped")):
            problems.append(("desktop-host-outcome", mode))
        if mode == "live" and report.get("outcome") == "skipped" and not report.get("reason"):
            problems.append(("desktop-host-capability", "live skip requires a reason"))
        runs = report.get("runs")
        if not isinstance(runs, list) or report.get("denominator") != len(runs):
            problems.append(("desktop-host-denominator", mode)); continue
        counts = {name: sum(isinstance(row, dict) and row.get("outcome") == name for row in runs)
                  for name in ("pass", "skipped", "fail")}
        if report.get("counts") != counts:
            problems.append(("desktop-host-counts", mode))
        if mode == "live" and report.get("outcome") == "skipped" and not runs:
            continue
        expected_modes = (("live",) if mode == "live" else
                          ("software-dummy", "software-disk", "missing-audio-negative", "replace-drop"))
        expected_ids = {fixture + "-" + run_mode for fixture in fixture_identities for run_mode in expected_modes}
        actual_ids = {row.get("id") for row in runs if isinstance(row, dict)}
        if actual_ids != expected_ids:
            problems.append(("desktop-host-roster", mode))
        if report.get("outcome") == "pass" and any(row.get("outcome") == "fail" for row in runs):
            problems.append(("desktop-host-outcome", mode + " contains failed run"))
        host = report.get("host")
        if not isinstance(host, dict) or not host.get("video_driver") or not host.get("audio_backend_requested") or \
                not isinstance(host.get("audio_rate_hz"), int) or not isinstance(host.get("audio_queue_policy"), dict):
            problems.append(("desktop-host-setup", mode))
        for row in runs:
            if not isinstance(row, dict):
                problems.append(("desktop-host-schema", mode + " row must be object")); continue
            row_id = row.get("id")
            if row_id in all_ids:
                problems.append(("desktop-host-roster", "duplicate " + str(row_id)))
            all_ids.add(row_id)
            if row.get("outcome") == "fail":
                problems.append(("desktop-host-outcome", str(row_id)))
            if mode == "live" and row.get("outcome") == "skipped" and row.get("reason"):
                continue
            if row_id and row_id.endswith("missing-audio-negative"):
                stats = row.get("stats", {})
                if row.get("outcome") != "skipped" or stats.get("audio_available") != 0 or stats.get("queue_samples") != 0:
                    problems.append(("desktop-host-audio-fallback", str(row_id)))
                continue
            fixture = next((key for key in fixture_identities if row_id and row_id.startswith(key + "-")), None)
            if fixture is None:
                problems.append(("desktop-host-roster", str(row_id))); continue
            if row_id.endswith("replace-drop"):
                replacement_key = "sounded-diagnostic" if fixture == "independent-game-v2" else "independent-game-v2"
                for label, key in (("primary", fixture), ("replacement", replacement_key)):
                    actual = row.get(label)
                    identity = fixture_identities[key]
                    if not isinstance(actual, dict) or any(actual.get(field) != value
                                                          for field, value in identity.items()):
                        problems.append(("desktop-host-source-identity", str(row_id) + " " + label))
                if row.get("outcome") != "pass":
                    problems.append(("desktop-host-outcome", str(row_id)))
                deterministic = {key: row.get(key) for key in ("fields_by_segment", "complete_pcm_frames",
                    "machine_digest", "field_hashes_sha256", "field_identity_sha256", "complete_pcm_sha256")}
                stats = row.get("stats", {})
                settings = row.get("host_settings")
                if row.get("controls_exercised") != ["drop", "replace"]:
                    problems.append(("desktop-host-controls", str(row_id)))
                if row.get("deterministic_segment_join") is not True or \
                        not all(isinstance(deterministic[key], (list, int, str)) for key in deterministic) or \
                        deterministic["machine_digest"] != row.get("headless_machine_digest") or \
                        row.get("field_hashes_sha256") != row.get("headless_field_hashes_sha256") or \
                        row.get("field_identity_sha256") != row.get("headless_field_identity_sha256") or \
                        row.get("complete_pcm_sha256") != row.get("headless_core_pcm_sha256"):
                    problems.append(("desktop-host-deterministic-identity", str(row_id)))
                if stats.get("stats_version") != 2:
                    problems.append(("desktop-host-stats-version", str(row_id)))
                if row.get("elapsed_exposure_ns", 0) <= 0 or not isinstance(settings, dict) or \
                        settings.get("video_driver") != "dummy" or settings.get("audio_backend_requested") != "disk":
                    problems.append(("desktop-host-setup", str(row_id)))
                if "present_errors" not in stats or not isinstance(stats.get("present_errors"), int) or \
                        stats.get("present_errors") != 0 or stats.get("presentation_error") != 0 or \
                        stats.get("present_calls", 0) != stats.get("present_successes", 0) + stats.get("present_errors", 0) or \
                        stats.get("present_calls", 0) < 1:
                    problems.append(("desktop-host-presentation", str(row_id)))
                if stats.get("audio_available") != 1 or \
                        stats.get("queue_source_unit") != "SDL input bytes and stereo source frames" or \
                        stats.get("queue_exposure_ns", 0) <= 0 or \
                        row.get("host_audio_queue_kind") != "SDL queued source bytes/frames" or \
                        "unavailable" not in row.get("device_queue_observation", ""):
                    problems.append(("desktop-host-queue", str(row_id)))
                for field in ("input_log_sha256", "input_script_sha256", "control_sha256",
                              "build_configuration_sha256", "desktop_build_sha256", "headless_build_sha256"):
                    if not HOST_HEX.fullmatch(str(row.get(field, ""))):
                        problems.append(("desktop-host-stale-identity", str(row_id) + " " + field))
                    expected = expected_identity.get(field)
                    if expected and row.get(field) != expected:
                        problems.append(("desktop-host-stale-identity", str(row_id) + " " + field))
                if row.get("control_sha256") != control_sha:
                    problems.append(("desktop-host-control-identity", str(row_id)))
                continue
            for field, value in fixture_identities[fixture].items():
                if row.get(field) != value:
                    problems.append(("desktop-host-source-identity", str(row_id) + " " + field))
            if row.get("outcome") != "pass":
                problems.append(("desktop-host-outcome", str(row_id)))
            settings = row.get("host_settings")
            required_settings = ("os", "os_release", "os_version", "architecture", "video_driver",
                                 "display_identity", "vsync_requested", "vsync_actual", "audio_backend_requested",
                                 "audio_rate_hz", "audio_queue_policy", "renderer_readback", "physical_scanout")
            if not isinstance(settings, dict) or any(key not in settings for key in required_settings) or \
                    not row.get("elapsed_exposure_ns", 0) > 0:
                problems.append(("desktop-host-setup", str(row_id)))
            if mode == "live":
                display = settings.get("display_identity") if isinstance(settings, dict) else None
                displays = display.get("displays") if isinstance(display, dict) else None
                has_refresh = isinstance(displays, list) and any(
                    isinstance(item, dict)
                    and isinstance(item.get("refresh_hz"), (int, float))
                    and not isinstance(item.get("refresh_hz"), bool)
                    and item.get("refresh_hz") > 0
                    and (not isinstance(item.get("refresh_hz"), float)
                         or math.isfinite(item.get("refresh_hz")))
                    for item in displays
                )
                if (not isinstance(settings, dict) or settings.get("video_driver") != "cocoa"
                        or not isinstance(display, dict) or display.get("status") != "observed"
                        or not has_refresh):
                    problems.append(("desktop-host-capability", str(row_id)))
            stats = row.get("stats")
            if not isinstance(stats, dict) or row.get("stats_schema") != 2 or stats.get("stats_version") != 2:
                problems.append(("desktop-host-stats-version", str(row_id)))
                continue
            expected_controls = ["drop", "exit", "mute", "pause", "reject-cartridge", "replace", "reset", "resume", "unmute"]
            if row.get("controls_exercised") != expected_controls or row.get("rejected_cartridge_reason") != \
                    "REJECT: missing genewhip-phase4-missing-cartridge.bin" or row.get("paused_fields", 0) <= 0:
                problems.append(("desktop-host-controls", str(row_id)))
            if "present_errors" not in stats or not isinstance(stats.get("present_errors"), int) or \
                    stats.get("present_calls", 0) != stats.get("present_successes", 0) + stats.get("present_errors", 0) or \
                    stats.get("present_errors") != 0 or stats.get("presentation_error") != 0:
                problems.append(("desktop-host-presentation", str(row_id)))
            if stats.get("audio_available") != 1 or stats.get("queue_source_unit") != "SDL input bytes and stereo source frames" or \
                    stats.get("queue_exposure_ns", 0) <= 0 or row.get("host_audio_queue_kind") != "SDL queued source bytes/frames" or \
                    "unavailable" not in row.get("device_queue_observation", ""):
                problems.append(("desktop-host-queue", str(row_id)))
            deterministic = row.get("deterministic")
            if not isinstance(deterministic, dict) or deterministic.get("deterministic_join") is not True or \
                    not isinstance(deterministic.get("fields"), int) or deterministic["fields"] <= 0 or \
                    not isinstance(deterministic.get("machine_digest"), str) or \
                    not HOST_HEX.fullmatch(str(deterministic.get("field_hashes_sha256", ""))) or \
                    not HOST_HEX.fullmatch(str(deterministic.get("field_identity_sha256", ""))) or \
                    deterministic.get("field_hashes_sha256") == deterministic.get("field_identity_sha256") or \
                    not HOST_HEX.fullmatch(str(deterministic.get("core_pcm_sha256", ""))) or \
                    not isinstance(deterministic.get("core_pcm_frames"), int) or deterministic["core_pcm_frames"] <= 0 or \
                    deterministic.get("machine_digest") != deterministic.get("headless_machine_digest") or \
                    deterministic.get("field_hashes_sha256") != deterministic.get("headless_field_hashes_sha256") or \
                    deterministic.get("field_identity_sha256") != deterministic.get("headless_field_identity_sha256") or \
                    deterministic.get("core_pcm_sha256") != deterministic.get("headless_core_pcm_sha256") or \
                    row.get("deterministic_identity_sha256") != digest(deterministic):
                problems.append(("desktop-host-deterministic-identity", str(row_id)))
            for field in ("input_log_sha256", "input_script_sha256", "control_sha256",
                          "build_configuration_sha256", "desktop_build_sha256", "headless_build_sha256"):
                if not HOST_HEX.fullmatch(str(row.get(field, ""))):
                    problems.append(("desktop-host-stale-identity", str(row_id) + " " + field))
                expected = expected_identity.get(field)
                if expected and row.get(field) != expected:
                    problems.append(("desktop-host-stale-identity", str(row_id) + " " + field))
            if row.get("control_sha256") != control_sha:
                problems.append(("desktop-host-control-identity", str(row_id)))
    return problems


def validate_delivery_evidence(evidence):
    """Require actual protected run identities, complete release assets and adoption."""
    if not isinstance(evidence, dict) or evidence.get("schema") != "genewhip.hosted-delivery.v1":
        return ["delivery-schema-invalid"]
    problems = []
    sha_pattern = re.compile(r"^[0-9a-f]{40}$")
    for key in ("pull_request_head_sha", "pull_request_base_sha", "merged_source_sha"):
        if not isinstance(evidence.get(key), str) or not sha_pattern.fullmatch(evidence[key]):
            problems.append("delivery-identity-invalid")
    if evidence.get("repository") != "szTheory/genewhip":
        problems.append("delivery-repository-mismatch")
    if not isinstance(evidence.get("pull_request"), int) or evidence["pull_request"] < 1:
        problems.append("delivery-pr-identity-invalid")
    for key in ("qualification_run_id", "publisher_run_id"):
        if not isinstance(evidence.get(key), str) or not evidence[key].isdigit():
            problems.append("delivery-run-identity-invalid")
    for key in ("qualification_run_attempt", "publisher_run_attempt"):
        if not isinstance(evidence.get(key), int) or evidence[key] < 1:
            problems.append("delivery-run-attempt-invalid")
    hosted = evidence.get("hosted_evidence")
    if not isinstance(hosted, dict) or hosted.get("outcome") != "success" \
            or hosted.get("qualifies_rel_03") is not True:
        problems.append("delivery-hosted-qualification-not-passed")
    if evidence.get("downloaded_package_adoption") != "pass":
        problems.append("delivery-adoption-not-passed")
    requirements = evidence.get("requirements")
    if not isinstance(requirements, dict) or any(
            requirements.get(key) != "pass" for key in ("REL-03", "REL-02", "DOC-01")):
        problems.append("delivery-requirements-not-passed")
    release = evidence.get("release")
    source = evidence.get("merged_source_sha")
    if not isinstance(release, dict) or release.get("source_sha") != source:
        problems.append("delivery-release-source-mismatch")
    else:
        inventory = release.get("inventory")
        assets = release.get("assets")
        if not isinstance(inventory, dict) or inventory.get("source_revision") != source \
                or not isinstance(inventory.get("assets"), dict) or len(inventory["assets"]) != 6:
            problems.append("delivery-inventory-invalid")
        if not isinstance(assets, list) or len(assets) != 8:
            problems.append("delivery-asset-roster-invalid")
        else:
            names = set()
            prefix = "https://github.com/szTheory/genewhip/releases/download/v0.1.0/"
            for row in assets:
                if not isinstance(row, dict) or not isinstance(row.get("name"), str) \
                        or row["name"] in names or not re.fullmatch(r"[A-Za-z0-9._-]+", row["name"]) \
                        or not isinstance(row.get("sha256"), str) or not HOST_HEX.fullmatch(row["sha256"]) \
                        or not isinstance(row.get("url"), str) or not row["url"].startswith(prefix):
                    problems.append("delivery-asset-identity-invalid")
                    break
                names.add(row["name"])
            if isinstance(inventory, dict) and isinstance(inventory.get("assets"), dict):
                expected_names = set(inventory["assets"]) | {"inventory.json", "SHA256SUMS"}
                if names != expected_names:
                    problems.append("delivery-asset-inventory-mismatch")
                indexed = {row.get("name"): row for row in assets if isinstance(row, dict)}
                for name, record in inventory["assets"].items():
                    if not isinstance(record, dict) or indexed.get(name, {}).get("sha256") != record.get("sha256"):
                        problems.append("delivery-inventory-asset-digest-mismatch")
                        break
        release_url = release.get("release_url")
        if release_url != "https://github.com/szTheory/genewhip/releases/tag/v0.1.0":
            problems.append("delivery-release-url-invalid")
    return sorted(set(problems))


def expected_for(build=None, head=None):
    expected = {"source_revision": head or git_head(),
                "fixture_manifest_sha256": sha(ROOT / "fixtures/manifest.json")}
    if build is not None:
        expected["configuration_sha256"] = digest(configuration(build))
        expected["tracer_identity"] = expected_tracer_identity(build)
        build = Path(build).resolve()
        expected["gameplay_identity"] = {
            "build_configuration_sha256": sha(build / "CMakeCache.txt"),
            "client_sha256": [sha(build / "tools/session/gw_headless")] +
                ([sha(build / "tools/desktop/genewhip-desktop")]
                 if (build / "tools/desktop/genewhip-desktop").is_file() else []),
        }
        expected["host_identity"] = {
            "build_configuration_sha256": sha(build / "CMakeCache.txt"),
            "desktop_build_sha256": sha(build / "tools/desktop/genewhip-desktop"),
            "headless_build_sha256": sha(build / "tools/session/gw_headless"),
        }
        benchmark = build / "gw_core_benchmark"
        if benchmark.is_file() and (build / "phase4-performance.json").is_file():
            path = ROOT / "tools/evidence/core_benchmark.py"
            spec = importlib.util.spec_from_file_location("gw_core_benchmark_identity", path)
            benchmark_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(benchmark_module)
            expected["performance_identity"] = {
                "build_configuration_sha256": sha(build / "CMakeCache.txt"),
                "benchmark_binary_sha256": sha(benchmark),
                "source_identity_sha256": benchmark_module.source_identity(),
            }
    return expected


def build_report(build):
    build = Path(build).resolve()
    tracer_path = build / "evidence/phase4-tracer.json"
    if tracer_path.is_file():
        tracer = json.loads(tracer_path.read_text())
        outcome, observed = tracer.get("outcome", "infrastructure-error"), tracer
    else:
        outcome, observed = "unknown", {"reason": "phase4_tracer has not produced evidence in this build"}
    gameplay_path = build / "evidence/phase4-gameplay.json"
    gameplay = json.loads(gameplay_path.read_text()) if gameplay_path.is_file() else None
    host_software_path = build / "evidence/phase4-host-sessions.json"
    host_live_path = build / "evidence/phase4-host-live.json"
    host_evidence = None
    host_outcome = "unknown"
    if host_software_path.is_file() and host_live_path.is_file():
        host_evidence = {"software": json.loads(host_software_path.read_text()),
                         "live": json.loads(host_live_path.read_text())}
        host_problems = validate_host_sessions(host_evidence, expected_revision=git_head(),
                                               expected_identity=expected_for(build).get("host_identity"))
        live_outcome = host_evidence["live"].get("outcome")
        host_outcome = "infrastructure-error" if host_problems else ("pass" if live_outcome == "pass" else "skipped")
        if host_problems:
            host_evidence["validation_errors"] = [{"reason": reason, "detail": detail}
                                                  for reason, detail in host_problems]
    else:
        host_evidence = {"reason": "phase4 host software and live lanes have not both produced evidence"}
    rows = []
    for row_id, required in ROSTER:
        if row_id == "diagnostic_public_clients":
            rows.append({"id": row_id, "required": required, "outcome": outcome, "observed": observed})
        elif row_id == "independent_gameplay":
            rows.append({"id": row_id, "required": required,
                         "outcome": gameplay.get("outcome", "infrastructure-error") if gameplay else "unknown",
                         "observed": gameplay if gameplay else {"reason": "phase4 gameplay clients have not produced evidence in this build"}})
        elif row_id == "core_performance":
            performance_path = build / "phase4-performance.json"
            performance = json.loads(performance_path.read_text()) if performance_path.is_file() else None
            rows.append({"id": row_id, "required": required,
                         "outcome": performance.get("outcome", "infrastructure-error") if performance else "unknown",
                         "observed": performance if performance else {"reason": "qualified core benchmark has not produced evidence in this build"}})
        elif row_id == "desktop_pacing":
            rows.append({"id": row_id, "required": required, "outcome": host_outcome,
                         "observed": host_evidence})
        elif row_id in ("exact_packages", "hosted_delivery"):
            delivery_path = ROOT / "build/phase4/delivery-evidence.json"
            try:
                delivery = json.loads(delivery_path.read_text())
            except (OSError, json.JSONDecodeError):
                delivery = None
            problems = validate_delivery_evidence(delivery)
            if row_id == "exact_packages":
                passed = not problems and delivery.get("downloaded_package_adoption") == "pass"
            else:
                passed = not problems
            rows.append({"id": row_id, "required": required,
                         "outcome": "pass" if passed else "unknown",
                         "observed": delivery if delivery else {
                             "reason": "no verified hosted-delivery record is available"},
                         **({"validation_errors": problems} if problems else {})})
        else:
            rows.append({"id": row_id, "required": required, "outcome": "unknown",
                         "observed": {"reason": "capability is owned by a later Phase 4 plan"}})
    config = configuration(build)
    report = {"schema": SCHEMA, "version": VERSION, "source_revision": git_head(),
              "source_state": source_state(), "configuration": config,
              "configuration_sha256": digest(config),
              "fixture_manifest_sha256": sha(ROOT / "fixtures/manifest.json"),
              "tracer": {"path": "tests/fixtures/phase4_tracer.py",
                         "sha256": sha(ROOT / "tests/fixtures/phase4_tracer.py")},
              "rows": rows, "denominator": len(rows), "counts": count(rows)}
    return report


def validate(report, head=None, qualification=False, expected=None):
    expected = expected or expected_for(head=head)
    problems = []
    if not isinstance(report, dict) or report.get("schema") != SCHEMA or report.get("version") != VERSION:
        return [("schema", "invalid schema/version")]
    if report.get("source_revision") != expected.get("source_revision"):
        problems.append(("stale-revision", "source revision does not match expected revision"))
    if report.get("fixture_manifest_sha256") != expected.get("fixture_manifest_sha256"):
        problems.append(("stale-fixture-manifest", "fixture manifest digest differs"))
    config = report.get("configuration")
    if not isinstance(config, dict) or report.get("configuration_sha256") != digest(config):
        problems.append(("configuration-digest", "configuration digest does not match configuration"))
    elif expected.get("configuration_sha256") and report.get("configuration_sha256") != expected["configuration_sha256"]:
        problems.append(("stale-configuration", "build configuration differs from expected configuration"))

    rows = report.get("rows")
    if not isinstance(rows, list):
        return problems + [("schema", "rows must be a list")]
    required = dict(ROSTER)
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            problems.append(("schema", "row must be an object"))
            continue
        row_id = row.get("id")
        if row_id not in required:
            problems.append(("unexpected-row", str(row_id)))
            continue
        if row_id in seen:
            problems.append(("duplicate-row", row_id))
            continue
        seen.add(row_id)
        if row.get("required") is not required[row_id]:
            problems.append(("requiredness", row_id))
        outcome = row.get("outcome")
        if outcome not in OUTCOMES:
            problems.append(("invalid-outcome", row_id))
        if not isinstance(row.get("observed"), dict):
            problems.append(("observed", row_id))
        if qualification and required[row_id] and outcome != "pass":
            problems.append(("required-non-pass", row_id))
        identity = expected.get("tracer_identity")
        observed = row.get("observed")
        if row_id == "diagnostic_public_clients" and outcome == "pass" and identity:
            if not isinstance(observed, dict) or observed.get("schema") != TRACER_SCHEMA or observed.get("version") != 1:
                problems.append(("tracer-schema", row_id))
            else:
                reasons = {
                    "source_sha256": "stale-source", "scenario_sha256": "stale-scenario",
                    "rom_sha256": "stale-rom", "input_sha256": "stale-input",
                    "build_configuration_sha256": "stale-configuration",
                    "headless_build_sha256": "stale-build", "desktop_build_sha256": "stale-build",
                    "profile": "stale-profile", "fixture": "stale-fixture",
                }
                for field, reason in reasons.items():
                    if observed.get(field) != identity.get(field):
                        problems.append((reason, field))
        if row_id == "independent_gameplay" and outcome == "pass":
            problems.extend(validate_gameplay(observed, qualification=qualification,
                                               expected_identity=expected.get("gameplay_identity")))
        if row_id == "core_performance" and outcome == "pass":
            benchmark_path = ROOT / "tools/evidence/core_benchmark.py"
            bench_spec = importlib.util.spec_from_file_location("gw_core_benchmark_validator", benchmark_path)
            benchmark = importlib.util.module_from_spec(bench_spec)
            bench_spec.loader.exec_module(benchmark)
            problems.extend(("performance-" + reason, reason)
                            for reason in benchmark.validate_report(observed, qualification=True,
                                expected={"build_configuration_sha256":
                                    (expected.get("performance_identity") or {}).get("build_configuration_sha256"),
                                    "benchmark_binary_sha256": (expected.get("performance_identity") or {}).get("benchmark_binary_sha256"),
                                    "source_identity_sha256": (expected.get("performance_identity") or {}).get("source_identity_sha256")}))
            identity = expected.get("performance_identity") or {}
            actual_build = observed.get("build_identity", {})
            if actual_build.get("build_configuration_sha256") != identity.get("build_configuration_sha256"):
                problems.append(("performance-stale-build", "benchmark CMake configuration differs"))
            if observed.get("benchmark_binary_sha256") != identity.get("benchmark_binary_sha256"):
                problems.append(("performance-stale-build", "benchmark executable differs"))
            if observed.get("source_identity_sha256") != identity.get("source_identity_sha256"):
                problems.append(("performance-stale-source", "benchmark source files differ"))
        if row_id == "desktop_pacing" and isinstance(observed, dict) and set(observed) >= {"software", "live"}:
            problems.extend(validate_host_sessions(observed, expected_revision=expected.get("source_revision"),
                                                   expected_identity=expected.get("host_identity")))
        if row_id in ("exact_packages", "hosted_delivery") and outcome == "pass":
            problems.extend(("delivery-" + reason, reason)
                            for reason in validate_delivery_evidence(observed))
    for row_id in required.keys() - seen:
        problems.append(("missing-row", row_id))
    if report.get("denominator") != len(rows):
        problems.append(("denominator", "row denominator differs from row list"))
    if report.get("counts") != count(rows):
        problems.append(("counts", "outcome counts differ from rows"))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    build_cmd = sub.add_parser("build")
    build_cmd.add_argument("--build", type=Path, required=True)
    build_cmd.add_argument("--out", type=Path, required=True)
    check = sub.add_parser("validate")
    check.add_argument("--report", type=Path, required=True)
    check.add_argument("--build", type=Path, required=True)
    check.add_argument("--head", default=None)
    check.add_argument("--qualification", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "build":
        report = build_report(args.build)
        problems = validate(report, expected=expected_for(args.build))
        if problems:
            print("invalid built report: %r" % problems, file=sys.stderr)
            return 1
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print("phase4 report: %d rows; %s" % (report["denominator"], report["counts"]))
        return 0
    report = json.loads(args.report.read_text())
    problems = validate(report, args.head, args.qualification, expected_for(args.build, args.head))
    if problems:
        for reason, detail in problems:
            print("REJECT: %s %s" % (reason, detail), file=sys.stderr)
        return 1
    print("phase4 report valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
