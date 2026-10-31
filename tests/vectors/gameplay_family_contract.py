#!/usr/bin/env python3
"""Run the frozen successor cases through the public headless client."""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "fixtures/independent-game-v2/scenario.json"
ROM = ROOT / "fixtures/independent-game-v2/game.bin"
SCENARIO_SHA256 = "c702dd10287a9363405fd9269e05989954eb447d0973246bb59a10f74920dbb2"
BUTTONS = {"Start": 128, "Right": 8, "Left": 4, "Up": 1,
           "Down": 2, "A": 64, "B": 16, "C": 32}


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replay_for(case: dict, path: pathlib.Path) -> None:
    held = [0, 0]
    lines = ["genewhip-input-log 1"]
    for event in sorted(case["input_schedule"], key=lambda row: row["frame"]):
        port_name, _, button = event["control"].partition(" ")
        if port_name not in ("P1", "P2") or button not in BUTTONS:
            raise ValueError("scenario contains an unknown controller event")
        port = int(port_name[1]) - 1
        if event["asserted"]:
            held[port] |= BUTTONS[button]
        else:
            held[port] &= ~BUTTONS[button]
        lines.append(f"{event['frame'] * 896040} pad {port} {held[port]:x}")
    path.write_text("\n".join(lines) + "\n")


def run_case(runner: pathlib.Path, scenario: dict, case: dict, temp: pathlib.Path) -> dict:
    replay, audio_trace = temp / "input.log", temp / "audio.jsonl"
    replay_for(case, replay)
    command = [str(runner), str(ROM), "--fields", str(case["frames"]),
               "--replay", str(replay), "--port-device", "pad3", "pad3",
               "--peek", "0xff0000", "4", "--dump-audio-trace", str(audio_trace)]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                            timeout=120, check=False)
    if result.returncode != 0:
        raise ValueError(f"{case['id']}: public runner exit {result.returncode}: {result.stderr.strip()}")
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    final = next((row for row in reversed(rows) if "unsupported" in row), None)
    fields = [row for row in rows if "fnv1a64" in row and "sequence" in row]
    if final is None or len(fields) != case["frames"] or final["fields"] != case["frames"]:
        raise ValueError(f"{case['id']}: public run did not complete its frozen field denominator")
    if final["unsupported"] != 0 or final["stop_reason"] != 0 or final["fault_address"] != 0:
        raise ValueError(f"{case['id']}: public run stopped: {final}")
    expected = case["expect"]
    state = bytes.fromhex(final["peek"])
    play_state = int.from_bytes(state[:2], "big")
    position = int.from_bytes(state[2:4], "big")
    if play_state != expected["play_state"]:
        raise ValueError(f"{case['id']}: public play state {play_state} outside source expectation")
    if not expected["position_min"] <= position <= expected["position_max"]:
        raise ValueError(f"{case['id']}: public position {position} outside source expectation")
    trace_rows = [json.loads(line) for line in audio_trace.read_text().splitlines()]
    dropped = trace_rows.pop()["dropped"]
    psg_values = [row["value"] for row in trace_rows if row["chip"] == 3]
    if dropped != 0 or psg_values != expected["psg_writes"]:
        raise ValueError(f"{case['id']}: public PSG writes {psg_values}, expected {expected['psg_writes']} (dropped={dropped})")
    return {"id": case["id"], "fields": len(fields), "unsupported": 0,
            "play_state": play_state, "position": position, "psg_writes": psg_values,
            "field_hashes_sha256": hashlib.sha256(
                "\n".join(row["fnv1a64"] for row in fields).encode()).hexdigest()}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: gameplay_family_contract.py HEADLESS_RUNNER", file=sys.stderr)
        return 2
    try:
        runner = pathlib.Path(sys.argv[1]).resolve()
        scenario = json.loads(SCENARIO.read_text())
        if digest(SCENARIO) != SCENARIO_SHA256:
            raise ValueError("successor scenario differs from the frozen 04-03 identity")
        if digest(ROM) != scenario["rom"]["sha256"]:
            raise ValueError("successor ROM identity differs from frozen scenario")
        if digest(ROOT / scenario["source"]["relative_path"]) != scenario["source"]["sha256"]:
            raise ValueError("successor source identity differs from frozen scenario")
        if not runner.is_file():
            raise ValueError("public headless client does not exist")
        results = []
        with tempfile.TemporaryDirectory(prefix="gw-gameplay-family-") as directory:
            temp = pathlib.Path(directory)
            for case in scenario["cases"]:
                case_work = temp / case["id"]
                case_work.mkdir()
                results.append(run_case(runner, scenario, case, case_work))
        if len(results) != len(scenario["cases"]):
            raise ValueError("scenario denominator changed during execution")
        print(json.dumps({"schema": "genewhip-gameplay-family-v1",
                          "rom_sha256": digest(ROM), "scenario_sha256": digest(SCENARIO),
                          "denominator": len(results), "unsupported": 0,
                          "outcomes": results}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            subprocess.TimeoutExpired) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
