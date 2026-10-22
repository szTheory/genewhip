#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Required source-derived v2 gameplay contract through public clients."""
from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIO_PATH = ROOT / "fixtures/independent-game-v2/scenario.json"
ORACLE_PATH = ROOT / "fixtures/independent-game-v2/oracle.json"
SCENARIO_SHA = "c702dd10287a9363405fd9269e05989954eb447d0973246bb59a10f74920dbb2"
ORACLE_SHA = "1a9d99cb01496f26fe3dc33d0c1bcb0cf22bd9178088fa183e5bba37a8600f42"
SOURCE_SHA = "b74cd12ec371767e8fb338feca808e59e63f569eb93298bb2470d20f8e4e9cfe"
FIELD_TICKS = 896040
MASTER_HZ = 53693175
BUTTONS = {"Start": 128, "Right": 8, "Left": 4, "Up": 1, "Down": 2, "A": 64, "B": 16, "C": 32}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def input_log(case: dict) -> bytes:
    held = [0, 0]
    lines = ["genewhip-input-log 1"]
    for event in sorted(case["input_schedule"], key=lambda row: row["frame"]):
        port_name, _, button = event["control"].partition(" ")
        if port_name not in ("P1", "P2") or button not in BUTTONS:
            raise ValueError("scenario contains an unknown controller event")
        port = int(port_name[1]) - 1
        held[port] = held[port] | BUTTONS[button] if event["asserted"] else held[port] & ~BUTTONS[button]
        lines.append(f"{event['frame'] * FIELD_TICKS} pad {port} {held[port]:x}")
    return ("\n".join(lines) + "\n").encode()


def execute(client: Path, rom: Path, case: dict, temp: Path, desktop: bool = False) -> dict:
    temp.mkdir(parents=True, exist_ok=True)
    log = temp / "input.log"
    log.write_bytes(input_log(case))
    audio = temp / ("desktop.pcm" if desktop else "headless.pcm")
    fields_dir = temp / "fields"
    fields_dir.mkdir(exist_ok=True)
    if desktop:
        args = [str(client), "--fields", str(case["frames"]), "--replay", str(log),
                "--print-field-hashes", "--dump-audio", str(audio), str(rom)]
    else:
        trace = temp / "audio-trace.jsonl"
        args = [str(client), str(rom), "--fields", str(case["frames"]), "--replay", str(log),
                "--port-device", "pad3", "pad3", "--peek", "0xff0000", "4",
                "--dump-fields", str(fields_dir), "--audio-rate", "48000",
                "--dump-audio", str(audio), "--dump-audio-trace", str(trace)]
    result = subprocess.run(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=240, check=False)
    if result.returncode:
        raise ValueError(f"{case['id']}: {('desktop' if desktop else 'headless')} exit {result.returncode}: {result.stderr.strip()}")
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    hashes = [row["fnv1a64"] for row in rows if "fnv1a64" in row and "sequence" in row]
    if desktop:
        if len(hashes) != case["frames"]:
            raise ValueError(f"{case['id']}: desktop rendered {len(hashes)} fields, expected {case['frames']}")
        final = next((dict(row) for row in reversed(rows) if "fields" in row), None)
        if final is None:
            raise ValueError(f"{case['id']}: desktop did not report final field count")
        if final.get("fields") != case["frames"] or not final.get("ram_fnv1a64"):
            raise ValueError(f"{case['id']}: desktop final machine observation is incomplete")
        return {"hashes": hashes, "audio": audio.read_bytes(), "final": final,
                "machine_digest": final["ram_fnv1a64"]}

    final = next((row for row in reversed(rows) if "unsupported" in row), None)
    if final is None or final["fields"] != case["frames"] or final["unsupported"] != 0 or final["stop_reason"] != 0 or final["fault_address"] != 0:
        raise ValueError(f"{case['id']}: incomplete/unsupported headless result {final}")
    if len(hashes) != case["frames"]:
        raise ValueError(f"{case['id']}: headless field denominator {len(hashes)} != {case['frames']}")
    state = bytes.fromhex(final["peek"])
    play_state, position = int.from_bytes(state[:2], "big"), int.from_bytes(state[2:4], "big")
    expected = dict(case["expect"])
    if temp.name == "negative-control":
        expected["play_state"] = 1 - expected["play_state"]
    if play_state != expected["play_state"] or not expected["position_min"] <= position <= expected["position_max"]:
        raise ValueError(f"{case['id']}: source state mismatch play={play_state} position={position}")
    trace_rows = [json.loads(line) for line in trace.read_text().splitlines()]
    dropped = trace_rows.pop()["dropped"]
    psg = [row["value"] for row in trace_rows if row["chip"] == 3]
    if dropped or psg != expected["psg_writes"]:
        raise ValueError(f"{case['id']}: causal PSG writes {psg}, expected {expected['psg_writes']} (dropped={dropped})")
    raw = audio.read_bytes()
    expected_frames = case["frames"] * FIELD_TICKS * 48000 // MASTER_HZ
    if len(raw) != expected_frames * 4:
        raise ValueError(f"{case['id']}: PCM frame denominator {len(raw)//4} != {expected_frames}")
    samples = struct.unpack("<" + "h" * (len(raw) // 2), raw)
    ac = max(samples) - min(samples) if samples else 0
    if expected["psg_writes"] and ac == 0:
        raise ValueError(f"{case['id']}: PSG action has no non-DC captured PCM")
    if not expected["psg_writes"] and psg:
        raise ValueError(f"{case['id']}: no-trigger case emitted PSG writes")
    geometry_paths = sorted(fields_dir.glob("field-*.bin"), key=lambda path: int(path.stem.split("-")[1]))
    if len(geometry_paths) != case["frames"]:
        raise ValueError(f"{case['id']}: raw rendered geometry denominator is incomplete")
    geometry = [sha(path) for path in geometry_paths]
    return {"hashes": hashes, "geometry": geometry, "audio": raw, "final": final,
            "input_sha256": hashlib.sha256(log.read_bytes()).hexdigest(), "play_state": play_state,
            "position": position, "psg": psg, "ac_range": ac,
            "machine_digest": final["ram_fnv1a64"]}


def main() -> int:
    args = sys.argv[1:]
    negative = "--negative-control" in args
    report_path = None
    if "--report" in args:
        index = args.index("--report")
        if index + 1 >= len(args):
            print("--report requires a path", file=sys.stderr)
            return 2
        report_path = Path(args[index + 1]).resolve()
        del args[index:index + 2]
    args = [arg for arg in args if arg != "--negative-control"]
    if len(args) not in (1, 2):
        print("usage: phase4_game.py HEADLESS [DESKTOP] [--negative-control] [--report FILE]", file=sys.stderr)
        return 2
    clients = [Path(arg).resolve() for arg in args]
    try:
        scenario = json.loads(SCENARIO_PATH.read_text())
        oracle = json.loads(ORACLE_PATH.read_text())
        rom = ROOT / scenario["rom"]["relative_path"]
        if sha(SCENARIO_PATH) != SCENARIO_SHA: raise ValueError("roster identity changed")
        if sha(ORACLE_PATH) != ORACLE_SHA: raise ValueError("source oracle identity changed")
        if sha(ROOT / scenario["source"]["relative_path"]) != SOURCE_SHA: raise ValueError("source identity changed")
        if sha(rom) != scenario["rom"]["sha256"]: raise ValueError("ROM identity changed")
        if scenario["cases"][-1]["id"] != oracle["case_ids"][-1]:
            raise ValueError("sustained scenario id changed")
        if scenario["cases"][-1]["frames"] != oracle["sustained_protocol"]["minimum_total_fields"]:
            raise ValueError("sustained workload denominator changed")
        build = clients[0].parents[2]
        cache = build / "CMakeCache.txt"
        if not cache.is_file(): raise ValueError("identified CMake build configuration is missing")
        results = []
        geometry_by_id = {}
        with tempfile.TemporaryDirectory(prefix="gw-phase4-game-") as tmp:
            base = Path(tmp)
            for case in scenario["cases"]:
                if negative and len(clients) == 1:
                    try:
                        execute(clients[0], rom, case, base / "negative-control")
                    except ValueError as exc:
                        if "source state mismatch" not in str(exc):
                            raise ValueError("negative control missed intended source-play-state assertion") from exc
                        print("REJECT: source-play-state (negative control reached production semantic validator)")
                        return 0
                    raise ValueError("negative control mutant unexpectedly passed")
                headless = execute(clients[0], rom, case, base / case["id"])
                geometry_by_id[case["id"]] = headless["geometry"]
                # comparison runs intentionally use the existing public runner field hashes and PCM capture
                desktop = None
                if len(clients) > 1:
                    desktop = execute(clients[1], rom, case, base / (case["id"] + "-desktop"), True)
                    if desktop["hashes"] != headless["hashes"]:
                        if negative:
                            print("REJECT: desktop-headless-rendered-fields (negative control)")
                            return 0
                        raise ValueError(f"{case['id']}: ordered desktop/headless rendered field hashes differ")
                    if negative and desktop["audio"]:
                        desktop["audio"] = bytes([desktop["audio"][0] ^ 1]) + desktop["audio"][1:]
                    if desktop["audio"] != headless["audio"]:
                        if negative:
                            print("REJECT: desktop-headless-raw-pcm (negative control reached production comparator)")
                            return 0
                        raise ValueError(f"{case['id']}: complete raw PCM differs between clients")
                    if desktop["machine_digest"] != headless["machine_digest"]:
                        if negative:
                            print("REJECT: desktop-headless-machine-state (negative control)")
                            return 0
                        raise ValueError(f"{case['id']}: complete final RAM observation differs between clients")
                result = {key: value for key, value in headless.items() if key not in ("audio", "hashes", "geometry", "final")}
                result.update(id=case["id"], fields=case["frames"], pcm_frames=len(headless["audio"]) // 4,
                              outcome="pass", unsupported=0,
                              field_hashes_sha256=hashlib.sha256("\n".join(headless["hashes"]).encode()).hexdigest(),
                              raw_geometry_sha256=hashlib.sha256("\n".join(headless["geometry"]).encode()).hexdigest())
                if desktop:
                    result["desktop_equal"] = True
                results.append(result)
        if len(results) != len(oracle["case_ids"]) or [r["id"] for r in results] != oracle["case_ids"]:
            raise ValueError("required roster denominator/order mismatch")
        by_id = {row["id"]: row for row in results}
        title_to_play = geometry_by_id["title-no-start"][10] != geometry_by_id["start-idle"][10]
        moved_marker = geometry_by_id["start-idle"][19] != geometry_by_id["start-move"][19]
        if not title_to_play:
            raise ValueError("source title-to-play geometry did not transition")
        if not moved_marker:
            raise ValueError("source movement did not change rendered marker geometry")
        if by_id["action-sound"]["ac_range"] <= 0 or by_id["action-no-trigger"]["ac_range"] != 0:
            raise ValueError("action-sound/no-trigger matched waveform control failed")
        evidence = {"schema": "genewhip-phase4-gameplay-v1", "version": 1, "outcome": "pass",
                          "fixture_id": scenario["fixture_id"], "source_sha256": SOURCE_SHA,
                          "rom_sha256": scenario["rom"]["sha256"], "scenario_sha256": SCENARIO_SHA,
                          "oracle_sha256": ORACLE_SHA, "denominator": len(results), "fields": sum(r["fields"] for r in results),
                          "profile": scenario["profile"], "build_configuration_sha256": sha(cache),
                          "client_sha256": [sha(client) for client in clients],
                          "clients": ["headless", "desktop"] if len(clients) > 1 else ["headless"],
                          "visual_observations": {"title_to_play_field_10_changed": title_to_play,
                                                   "start_idle_to_moved_marker_field_19_changed": moved_marker},
                          "results": results}
        rendered = json.dumps(evidence, sort_keys=True)
        if report_path:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(rendered + "\n")
        print(rendered)
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
