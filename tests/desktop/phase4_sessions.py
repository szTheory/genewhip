#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite, source-bound host sessions for the admitted Phase 4 fixtures."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROLS = ROOT / "fixtures/independent-game-v2/host-controls.json"
REQUIRED_CONTROLS = {"pause", "resume", "reset", "mute", "unmute", "replace", "drop",
                     "reject-cartridge", "exit"}
FIELD_TICKS = 896040
MASTER_HZ = 53693175
RATE = 48000
TIMEOUT = 180
BUTTONS = {"Start": 128, "Right": 8, "Left": 4, "Up": 1, "Down": 2, "A": 64,
           "B": 16, "C": 32}
HASH_LINE = re.compile(r'^\{"(?:sequence|fields)":')


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_controls() -> dict:
    document = json.loads(CONTROLS.read_text())
    if document.get("schema") != "genewhip-phase4-host-controls" or document.get("version") != 1:
        raise ValueError("host-control schema/version mismatch")
    sessions = document.get("sessions")
    if not isinstance(sessions, dict) or set(sessions) != {"independent-game-v2", "sounded-diagnostic"}:
        raise ValueError("host-control session roster mismatch")
    for name, session in sessions.items():
        controls = session.get("controls", [])
        ids = [row.get("id") for row in controls]
        if len(ids) != len(set(ids)) or set(ids) != REQUIRED_CONTROLS:
            raise ValueError("host-control action roster mismatch for " + name)
    return document


class HostControlsContract(unittest.TestCase):
    def test_both_admitted_clients_cover_every_named_control(self):
        document = load_controls()
        sessions = document["sessions"]
        for name, session in sessions.items():
            with self.subTest(session=name):
                controls = {row["id"] for row in session["controls"]}
                self.assertEqual(controls, REQUIRED_CONTROLS)
                self.assertGreater(session["emulated_fields"], 0)
                self.assertTrue(session["rom"].startswith("fixtures/"))
                self.assertTrue(session["scenario"].startswith("fixtures/"))


def json_rows(output: str) -> list[dict]:
    return [json.loads(line) for line in output.splitlines() if HASH_LINE.match(line)]


def run(args: list[object], env: dict[str, str], timeout: int = TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(list(map(str, args)), cwd=ROOT, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)


def input_actions(session: dict, scenario: dict) -> list[tuple[int, str]]:
    actions: list[tuple[int, str]] = []
    if session["scenario_case"]:
        case = next(row for row in scenario["cases"] if row["id"] == session["scenario_case"])
        if case["frames"] != session["emulated_fields"]:
            raise ValueError("source scenario field budget changed")
        for event in case["input_schedule"]:
            port, _, control = event["control"].partition(" ")
            name = control
            if port not in ("P1", "P2") or name not in BUTTONS:
                raise ValueError("source scenario contains unknown host input")
            state = "asserted" if event["asserted"] else "released"
            mask = BUTTONS[name] if state == "asserted" else 0
            actions.append((event["frame"], "press " + port[1] + " " + format(mask, "02x")))
    else:
        ticks = scenario["inputs"]["ticks_per_field"]
        if ticks != FIELD_TICKS:
            raise ValueError("diagnostic field clock changed")
        for event in scenario["inputs"]["entries"]:
            actions.append((int(event["field"]), "press " + str(int(event["port"]) + 1) + " " +
                            format(int(event["mask"], 0), "02x")))
    for control in session["controls"]:
        if control["id"] in {"replace", "drop"}:
            continue
        if control["id"] == "reject-cartridge":
            action = "drop genewhip-phase4-missing-cartridge.bin"
        else:
            action = control["command"]
        actions.append((control["frame"], action))
    return sorted(actions, key=lambda row: row[0])


def script_text(actions: list[tuple[int, str]]) -> str:
    return "".join(f"{frame} {action}\n" for frame, action in actions)


def final_state(rows: list[dict], name: str) -> dict:
    found = next((row for row in reversed(rows) if "ram_fnv1a64" in row and "fields" in row), None)
    if found is None:
        raise ValueError(name + " has no complete final machine digest")
    return found


def compare_desktop_headless(desktop_rows: list[dict], headless_rows: list[dict],
                             desktop_pcm: bytes, headless_pcm: bytes, name: str) -> dict:
    desktop_fields = [row for row in desktop_rows if "sequence" in row]
    headless_fields = [row for row in headless_rows if "sequence" in row]
    if len(desktop_fields) != len(headless_fields) or not desktop_fields:
        raise ValueError(name + " field denominator mismatch")
    if desktop_fields != headless_fields:
        raise ValueError(name + " ordered core field identity/pixels differ from headless replay")
    desktop_final, headless_final = final_state(desktop_rows, name), final_state(headless_rows, name)
    if desktop_final["ram_fnv1a64"] != headless_final["ram_fnv1a64"]:
        raise ValueError(name + " final machine RAM digest differs from headless replay")
    if desktop_pcm != headless_pcm:
        raise ValueError(name + " complete raw core PCM differs from headless replay")
    field_identity = hashlib.sha256(json.dumps([row["sequence"] for row in desktop_fields],
                                               separators=(",", ":")).encode()).hexdigest()
    headless_identity = hashlib.sha256(json.dumps([row["sequence"] for row in headless_fields],
                                                  separators=(",", ":")).encode()).hexdigest()
    return {"fields": len(desktop_fields), "machine_digest": desktop_final["ram_fnv1a64"],
            "field_hashes_sha256": hashlib.sha256(json.dumps(desktop_fields, sort_keys=True).encode()).hexdigest(),
            "field_identity_sha256": field_identity,
            "core_pcm_frames": len(desktop_pcm) // 4,
            "core_pcm_sha256": hashlib.sha256(desktop_pcm).hexdigest(),
            "headless_machine_digest": headless_final["ram_fnv1a64"],
            "headless_field_hashes_sha256": hashlib.sha256(json.dumps(headless_fields, sort_keys=True).encode()).hexdigest(),
            "headless_field_identity_sha256": headless_identity,
            "headless_core_pcm_sha256": hashlib.sha256(headless_pcm).hexdigest(),
            "deterministic_join": True}


def deterministic_identity(join: dict) -> str:
    return hashlib.sha256(json.dumps(join, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def display_identity() -> dict:
    if sys.platform != "darwin":
        return {"status": "unavailable", "reason": "system_profiler display inventory is macOS-only"}
    try:
        result = subprocess.run(["system_profiler", "-json", "SPDisplaysDataType"], check=True,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        document = json.loads(result.stdout)
        displays = []
        for device in document.get("SPDisplaysDataType", []):
            for display in device.get("spdisplays_ndrvs", []):
                row = {key: display.get(key) for key in
                       ("_name", "_spdisplays_pixels", "_spdisplays_resolution") if key in display}
                resolution = str(display.get("_spdisplays_resolution", ""))
                refresh = re.search(r"@\s*([0-9]+(?:\.[0-9]+)?)\s*Hz", resolution)
                row["refresh_hz"] = float(refresh.group(1)) if refresh else None
                displays.append(row)
        if not displays:
            return {"status": "unavailable", "reason": "system_profiler returned no display rows"}
        return {"status": "observed", "displays": displays}
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "reason": type(exc).__name__}


def host_settings(video_driver: str, audio_backend: str) -> dict:
    return {"os": platform.system(), "os_release": platform.release(), "os_version": platform.mac_ver()[0],
            "architecture": platform.machine(), "video_driver": video_driver,
            "display_identity": display_identity(), "vsync_requested": True,
            "vsync_actual": "unknown: runner ignores SDL_SetRenderVSync result and exposes no query",
            "audio_backend_requested": audio_backend, "audio_rate_hz": RATE,
            "audio_queue_policy": {"target_source_frames": 2403, "cap_source_frames": 9612,
                                   "sample_api": "SDL_GetAudioStreamQueued input bytes converted to stereo source frames"},
            "renderer_readback": {"status": "unavailable",
                                  "reason": "runner hashes core field pixels before SDL submission; it exposes no renderer readback"},
            "physical_scanout": "unobserved"}


def load_fixture(session: dict) -> tuple[Path, dict, dict]:
    rom = ROOT / session["rom"]
    scenario_path = ROOT / session["scenario"]
    scenario = json.loads(scenario_path.read_text())
    if session["scenario_case"]:
        scenario_case = next((row for row in scenario["cases"] if row["id"] == session["scenario_case"]), None)
        if scenario_case is None or scenario_case["frames"] != session["emulated_fields"]:
            raise ValueError("source-qualified game scenario or its 720-field budget changed")
        source_path = ROOT / scenario["source"]["relative_path"]
        source_digest = scenario["source"]["sha256"]
        rom_digest = scenario["rom"]["sha256"]
        if sha(source_path) != source_digest or sha(rom) != rom_digest:
            raise ValueError("independent-game source or ROM identity changed")
    else:
        source_path = ROOT / scenario["rom"]["source"]
        rom_digest = scenario["rom"]["sha256"] if "sha256" in scenario["rom"] else sha(rom)
        source_digest = sha(source_path)
        if sha(rom) != rom_digest:
            raise ValueError("sounded diagnostic ROM identity changed")
    return rom, scenario, {"fixture_id": session["fixture_id"], "source_sha256": source_digest,
                           "rom_sha256": rom_digest, "scenario_sha256": sha(scenario_path),
                           "rom_path": session["rom"], "scenario_path": session["scenario"]}


def run_controls(name: str, session: dict, headless: Path, desktop: Path, build: Path,
                 mode: str, temp: Path) -> dict:
    rom, scenario, identity = load_fixture(session)
    actions = input_actions(session, scenario)
    script = temp / (name + "-controls.script")
    log = temp / (name + "-recorded.input")
    pcm = temp / (name + "-desktop-core.pcm")
    stats_path = temp / (name + "-stats.json")
    script.write_text(script_text(actions))
    if mode == "software-dummy":
        env = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy")
        backend = "dummy"
    elif mode == "software-disk":
        disk = temp / (name + "-disk-sink.pcm")
        env = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="disk",
                   SDL_AUDIO_DISK_OUTPUT_FILE=str(disk))
        backend = "disk"
    elif mode == "missing-audio":
        env = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="genewhip-no-such-driver")
        backend = "unavailable-injected"
    else:
        video = "cocoa"
        audio = "coreaudio"
        if os.environ.get("GENEWHIP_LIVE_DISPLAY") != "1" or os.environ.get("GENEWHIP_LIVE_AUDIO") != "1":
            return {"id": name, "outcome": "skipped", "reason": "live display/audio opt-in flags are not both set",
                    "capabilities": {"display": "not-attempted", "audio": "not-attempted"}}
        env = dict(os.environ, SDL_VIDEODRIVER=video, SDL_AUDIODRIVER=audio)
        backend = audio

    started = time.monotonic_ns()
    desktop_result = run([desktop, "--fields", session["emulated_fields"], "--host-script", script,
                          "--record", log, "--print-field-hashes", "--dump-audio", pcm,
                          "--stats", stats_path, rom], env)
    elapsed_ns = time.monotonic_ns() - started
    if desktop_result.returncode:
        if mode == "live" and ("Could not initialise SDL video" in desktop_result.stderr or
                                "Could not create the window or renderer" in desktop_result.stderr):
            return {"id": name, "outcome": "skipped", "reason": "real macOS window/display could not be opened",
                    "stderr_reason": desktop_result.stderr.splitlines()[0] if desktop_result.stderr else "window unavailable"}
        raise ValueError(name + " desktop runner failed: " + desktop_result.stderr[-1000:])
    desktop_rows = json_rows(desktop_result.stdout)
    if len(desktop_rows) < 2:
        raise ValueError(name + " desktop emitted no complete field/result sequence")
    stats = json.loads(stats_path.read_text())
    field_count = len([row for row in desktop_rows if "sequence" in row])
    log_bytes = log.read_bytes()
    if stats.get("stats_version") != 2:
        raise ValueError(name + " runner stats schema is not version 2")
    if stats.get("emulated_fields") != field_count or field_count != session["emulated_fields"]:
        raise ValueError(name + " emulated field denominator differs from frozen session budget")
    if stats.get("present_errors") != 0 or stats.get("present_calls", 0) < 1 or \
            stats.get("present_successes", 0) + stats.get("present_errors", 0) != stats.get("present_calls"):
        raise ValueError(name + " renderer submission counter/error assertion failed")
    if stats.get("clock_exposure_ns", 0) <= 0 or (stats.get("audio_available") and stats.get("queue_exposure_ns", 0) <= 0):
        raise ValueError(name + " host/audio exposure is missing")
    if stats.get("queue_source_unit") != "SDL input bytes and stereo source frames":
        raise ValueError(name + " queue is not identified as SDL source-side depth")
    if stats.get("audio_available") != 1:
        if mode == "live":
            return {"id": name, "outcome": "skipped", "reason": "requested CoreAudio device unavailable",
                    "host_settings": host_settings("cocoa", "coreaudio"), "stats": stats,
                    "elapsed_exposure_ns": elapsed_ns}
        if mode != "missing-audio":
            raise ValueError(name + " required dummy/disk audio backend fell back")
    elif mode == "missing-audio":
        raise ValueError(name + " missing-audio negative control unexpectedly opened audio")
    if stats.get("mute_transitions") != 2 or stats.get("audio_muted") != 0:
        raise ValueError(name + " mute/unmute controls were not both observed")
    status = re.search(r"fields=(\d+) paused_fields=(\d+) resets=(\d+)", desktop_result.stdout)
    if not status or int(status.group(2)) < 1 or int(status.group(3)) < 1:
        raise ValueError(name + " pause/resume or reset did not change host session state")
    if stats.get("present_errors") != 0 or stats.get("presentation_error") != 0:
        raise ValueError(name + " presentation error persisted")
    if "resets=1" not in desktop_result.stdout or b" reset\n" not in log_bytes:
        raise ValueError(name + " reset was not recorded and counted")
    if "REJECT: missing genewhip-phase4-missing-cartridge.bin" not in desktop_result.stderr:
        raise ValueError(name + " rejected-cartridge negative control missed its intended reason")
    if not any(row["id"] == "exit" for row in session["controls"]):
        raise ValueError(name + " has no bounded exit action")
    core_pcm = pcm.read_bytes()
    if len(core_pcm) != (field_count * FIELD_TICKS * RATE // MASTER_HZ) * 4:
        raise ValueError(name + " complete core PCM frame denominator differs from master-tick count")

    head_pcm = temp / (name + "-headless-core.pcm")
    head_fields = temp / (name + "-headless-fields")
    head_fields.mkdir()
    headless_result = run([headless, rom, "--fields", field_count, "--replay", log,
                           "--port-device", "pad3", "pad3", "--peek", "0xff0000", "4",
                           "--dump-fields", head_fields, "--audio-rate", RATE, "--dump-audio", head_pcm],
                          dict(os.environ))
    if headless_result.returncode:
        raise ValueError(name + " headless replay failed: " + headless_result.stderr[-1000:])
    head_rows = json_rows(headless_result.stdout)
    join = compare_desktop_headless(desktop_rows, head_rows, core_pcm, head_pcm.read_bytes(), name)
    record = {"id": name, "outcome": "pass", **identity,
              "controls_exercised": sorted(REQUIRED_CONTROLS),
              "paused_fields": int(status.group(2)),
              "rejected_cartridge_reason": "REJECT: missing genewhip-phase4-missing-cartridge.bin",
              "control_sha256": sha(CONTROLS), "input_log_sha256": hashlib.sha256(log_bytes).hexdigest(),
              "input_script_sha256": sha(script), "build_configuration_sha256": sha(build / "CMakeCache.txt"),
              "desktop_build_sha256": sha(desktop), "headless_build_sha256": sha(headless),
              "host_settings": host_settings("cocoa" if mode == "live" else "dummy", backend),
              "elapsed_exposure_ns": elapsed_ns, "stats_schema": stats["stats_version"],
              "stats": stats, "deterministic": join,
              "host_audio_queue_kind": "SDL queued source bytes/frames",
              "device_queue_observation": "unavailable: SDL reports source queue, not physical device consumption",
              "physical_audio_quality": "unobserved"}
    record["deterministic_identity_sha256"] = deterministic_identity(join)
    if mode == "software-disk":
        sink = temp / (name + "-disk-sink.pcm")
        if not sink.is_file() or sink.stat().st_size == 0:
            raise ValueError(name + " SDL disk audio sink produced no output")
        record["disk_sink_bytes"] = sink.stat().st_size
        record["disk_sink_sha256"] = sha(sink)
    return record


def run_replacement(name: str, session: dict, headless: Path, desktop: Path,
                    temp: Path) -> dict:
    primary, _, primary_identity = load_fixture(session)
    other_name = "sounded-diagnostic" if name == "independent-game-v2" else "independent-game-v2"
    other_session = load_controls()["sessions"][other_name]
    replacement, _, replacement_identity = load_fixture(other_session)
    start_fields, first_tail, second_tail = 20, 30, 30
    script = temp / (name + "-replace.script")
    log = temp / (name + "-replace.input")
    desktop_pcm_path = temp / (name + "-replace-desktop.pcm")
    stats_path = temp / (name + "-replace-stats.json")
    script.write_text(f"{start_fields} drop {replacement.relative_to(ROOT)}\n"
                      f"{start_fields + first_tail} drop {primary.relative_to(ROOT)}\n"
                      f"{start_fields + first_tail + second_tail} quit\n")
    env = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="disk",
               SDL_AUDIO_DISK_OUTPUT_FILE=str(temp / (name + "-replace-sink.pcm")))
    started = time.monotonic_ns()
    result = run([desktop, "--fields", 1000, "--host-script", script, "--record", log,
                  "--print-field-hashes", "--dump-audio", desktop_pcm_path, "--stats", stats_path, primary], env)
    elapsed_ns = time.monotonic_ns() - started
    if result.returncode or "LOADED: " not in result.stderr:
        raise ValueError(name + " cartridge replacement/drop did not load: " + result.stderr[-1000:])
    rows = json_rows(result.stdout)
    field_rows = [row for row in rows if "sequence" in row]
    if len(field_rows) != start_fields + first_tail + second_tail:
        raise ValueError(name + " replacement session field denominator mismatch")
    if [row["sequence"] for row in field_rows] != list(range(start_fields)) + list(range(first_tail)) + list(range(second_tail)):
        raise ValueError(name + " replacement/drop did not begin a new core field identity")
    expected_parts = []
    expected_hash_parts = []
    expected_final = None
    for label, rom, count in (("initial", primary, start_fields), ("replacement", replacement, first_tail),
                              ("reloaded", primary, second_tail)):
        pcm = temp / f"{name}-{label}.pcm"
        head = run([headless, rom, "--fields", count, "--audio-rate", RATE, "--dump-audio", pcm],
                   dict(os.environ))
        if head.returncode:
            raise ValueError(name + " headless " + label + " segment failed: " + head.stderr[-1000:])
        expected_parts.append(pcm.read_bytes())
        head_rows = json_rows(head.stdout)
        expected_hash_parts.append([row for row in head_rows if "sequence" in row])
        if label == "reloaded":
            expected_final = final_state(head_rows, name + " reloaded segment")
    expected_hashes = [row for part in expected_hash_parts for row in part]
    if field_rows != expected_hashes:
        raise ValueError(name + " full replacement/drop field sequence differs from headless segments")
    if final_state(rows, name + " replacement/drop session").get("ram_fnv1a64") != expected_final.get("ram_fnv1a64"):
        raise ValueError(name + " reloaded machine digest differs from its complete headless segment")
    expected_pcm = b"".join(expected_parts)
    if desktop_pcm_path.read_bytes() != expected_pcm:
        raise ValueError(name + " full replacement/drop PCM differs from complete headless segments")
    if not log.read_text().startswith("genewhip-input-log 1\n"):
        raise ValueError(name + " replacement session did not produce a valid input log")
    return {"id": name + "-replace-drop", "outcome": "pass",
            "controls_exercised": sorted(("replace", "drop")),
            "primary": primary_identity, "replacement": replacement_identity,
            "fields_by_segment": [start_fields, first_tail, second_tail],
            "complete_pcm_frames": len(expected_pcm) // 4,
            "machine_digest": final_state(rows, name + " replacement/drop session")["ram_fnv1a64"],
            "field_hashes_sha256": hashlib.sha256(json.dumps(field_rows, sort_keys=True).encode()).hexdigest(),
            "field_identity_sha256": hashlib.sha256(json.dumps([row["sequence"] for row in field_rows],
                                                                 separators=(",", ":")).encode()).hexdigest(),
            "complete_pcm_sha256": hashlib.sha256(expected_pcm).hexdigest(),
            "headless_machine_digest": expected_final["ram_fnv1a64"],
            "headless_field_hashes_sha256": hashlib.sha256(json.dumps(expected_hashes, sort_keys=True).encode()).hexdigest(),
            "headless_field_identity_sha256": hashlib.sha256(json.dumps([row["sequence"] for row in expected_hashes],
                                                                          separators=(",", ":")).encode()).hexdigest(),
            "headless_core_pcm_sha256": hashlib.sha256(expected_pcm).hexdigest(),
            "input_log_sha256": sha(log), "control_sha256": sha(CONTROLS),
            "input_script_sha256": sha(script),
            "build_configuration_sha256": sha(headless.parent.parent.parent / "CMakeCache.txt"),
            "desktop_build_sha256": sha(desktop), "headless_build_sha256": sha(headless),
            "host_settings": host_settings("dummy", "disk"), "elapsed_exposure_ns": elapsed_ns,
            "host_audio_queue_kind": "SDL queued source bytes/frames",
            "device_queue_observation": "unavailable: SDL reports source queue, not physical device consumption",
            "physical_audio_quality": "unobserved",
            "deterministic_segment_join": True,
            "stats": json.loads(stats_path.read_text())}


def run_missing_audio(name: str, session: dict, headless: Path, desktop: Path, build: Path,
                      temp: Path) -> dict:
    record = run_controls(name, session, headless, desktop, build, "missing-audio", temp)
    if record.get("stats", {}).get("audio_available") != 0:
        raise ValueError(name + " missing-audio control did not report device unavailable")
    if record["stats"].get("queue_samples") != 0:
        raise ValueError(name + " missing-audio control reported source queue samples")
    record["id"] = name + "-missing-audio-negative"
    record["outcome"] = "skipped"
    record["reason"] = "injected unavailable SDL audio backend; core PCM still compared exactly"
    return record


def run_all(args) -> int:
    controls = load_controls()
    headless, desktop, build = args.headless.resolve(), args.desktop.resolve(), args.build.resolve()
    if not headless.is_file() or not desktop.is_file() or not (build / "CMakeCache.txt").is_file():
        raise ValueError("identified desktop/headless binaries and CMakeCache are required")
    if args.mode == "live":
        if platform.system() != "Darwin":
            result = {"schema": "genewhip-phase4-host-sessions", "version": 1, "outcome": "skipped",
                      "reason": "real host lane is macOS-only", "runs": []}
            write_report(args.out, result)
            print("SKIP: phase4_host_live (real host lane is macOS-only)")
            return 77
        if os.environ.get("GENEWHIP_LIVE_DISPLAY") != "1" or os.environ.get("GENEWHIP_LIVE_AUDIO") != "1":
            result = {"schema": "genewhip-phase4-host-sessions", "version": 1, "outcome": "skipped",
                      "reason": "set GENEWHIP_LIVE_DISPLAY=1 and GENEWHIP_LIVE_AUDIO=1", "runs": []}
            write_report(args.out, result)
            print("SKIP: phase4_host_live (both real display and audio opt-ins are required)")
            return 77
    runs = []
    with tempfile.TemporaryDirectory(prefix="gw-phase4-host-") as directory:
        temp = Path(directory)
        if args.mode == "software":
            for client_name, session in controls["sessions"].items():
                for mode in ("software-dummy", "software-disk"):
                    runs.append(run_controls(client_name + "-" + mode, session, headless, desktop,
                                             build, mode, temp))
                runs.append(run_missing_audio(client_name, session, headless, desktop, build, temp))
                runs.append(run_replacement(client_name, session, headless, desktop, temp))
        else:
            for client_name, session in controls["sessions"].items():
                runs.append(run_controls(client_name + "-live", session, headless, desktop,
                                         build, "live", temp))
    passing = all(row.get("outcome") == "pass" for row in runs if not row["id"].endswith("missing-audio-negative"))
    capability_skips = [row for row in runs if row.get("outcome") == "skipped" and
                         not row["id"].endswith("missing-audio-negative")]
    outcome = "pass" if passing and not capability_skips else ("skipped" if capability_skips and args.mode == "live" else "fail")
    report = {"schema": "genewhip-phase4-host-sessions", "version": 1, "outcome": outcome,
              "mode": args.mode, "source_revision": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
              check=True, text=True, stdout=subprocess.PIPE).stdout.strip(),
              "control_sha256": sha(CONTROLS),
              "build_configuration_sha256": sha(build / "CMakeCache.txt"),
              "desktop_build_sha256": sha(desktop), "headless_build_sha256": sha(headless),
              "host": host_settings("cocoa" if args.mode == "live" else "dummy",
                                    "coreaudio" if args.mode == "live" else "dummy/disk"),
              "denominator": len(runs), "runs": runs,
              "counts": {"pass": sum(r.get("outcome") == "pass" for r in runs),
                         "skipped": sum(r.get("outcome") == "skipped" for r in runs),
                         "fail": sum(r.get("outcome") == "fail" for r in runs)}}
    write_report(args.out, report)
    print(json.dumps({"outcome": report["outcome"], "denominator": report["denominator"],
                      "counts": report["counts"]}, sort_keys=True))
    if args.mode == "live" and outcome == "skipped":
        return 77
    return 0 if outcome == "pass" else 1


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("contract", "software", "live"))
    parser.add_argument("--headless", type=Path)
    parser.add_argument("--desktop", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if args.mode == "contract":
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(HostControlsContract))
        return 0 if result.wasSuccessful() else 1
    if not args.headless or not args.desktop or not args.build or not args.out:
        parser.error("software/live modes require --headless, --desktop, --build and --out")
    try:
        return run_all(args)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
