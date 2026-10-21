#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Non-gating smoke: the admitted independent game through gw_headless (plan GW-02-13, D-31).

Usage: independent_game_core_smoke.py ROOT GW_HEADLESS [--rom PATH] [--check-digest-rejection]

Converts the scenario's input_schedule (frame n -> tick n * GW_FIELD_TICKS, cumulative held
state per port) into a genewhip-input-log 1 file, replays it for the scenario's frame budget
and reads the oracle word through `gw_headless --peek`. Prints one JSON outcome line.
Outcomes: pass, fail, unsupported (with stop reason, opcode, address) or unknown. This is a
smoke, not a compatibility claim. Exit 0 for every outcome; non-zero only for infrastructure
errors (missing ROM or scenario, digest mismatch, tool failure, malformed output).
"""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

GW_FIELD_TICKS = 896040
BUTTONS = {"Start": 128, "Right": 8, "Left": 4, "Up": 1, "Down": 2, "A": 64, "B": 16, "C": 32}
STOP_NAMES = {1: "cpu-stopped", 2: "unsupported-instruction", 3: "unsupported-address",
              4: "unsupported-state"}


def infra(message):
    print(json.dumps({"outcome": "infrastructure_error", "reason": message}))
    sys.exit(1)


def build_log(schedule):
    """Cumulative held masks per port, one log line per change, in frame order."""
    held = [0, 0]
    lines = ["genewhip-input-log 1"]
    for entry in sorted(schedule, key=lambda e: e["frame"]):
        port_name, _, button = entry["control"].partition(" ")
        if port_name not in ("P1", "P2") or button not in BUTTONS:
            infra("unknown control " + entry["control"])
        port = int(port_name[1]) - 1
        if entry["asserted"]:
            held[port] |= BUTTONS[button]
        else:
            held[port] &= ~BUTTONS[button]
        lines.append(f"{entry['frame'] * GW_FIELD_TICKS} pad {port} {held[port]:x}")
    return "\n".join(lines) + "\n"


def run(root, headless, rom_override):
    scenario = json.loads((root / "fixtures/independent-game/scenario.json").read_text())
    rom = Path(rom_override) if rom_override else root / scenario["rom"]["relative_path"]
    if not rom.is_file():
        infra("rom missing")
    if hashlib.sha256(rom.read_bytes()).hexdigest() != scenario["rom"]["sha256"]:
        infra("rom digest mismatch")
    oracle = scenario["oracle"]
    address = int(oracle["address"], 16)
    frames = scenario["budget"]["frames"]
    with tempfile.TemporaryDirectory(prefix="gw-smoke-") as temp:
        log = Path(temp) / "input.log"
        log.write_text(build_log(scenario["input_schedule"]))
        try:
            result = subprocess.run([str(headless), str(rom), "--fields", str(frames), "--replay", str(log),
                                     "--port-device", "pad3", "pad3", "--peek", hex(address), "2"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=scenario["budget"]["hard_timeout_seconds"],
                                    check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            infra("tool failed: " + type(error).__name__)
    # gw_headless exits 1 when the core rejects a run after a sticky unsupported stop; the final
    # line still carries the stop fields, so judge the output before the exit status.
    try:
        final = json.loads(result.stdout.decode().strip().splitlines()[-1])
        peek = bytes.fromhex(final["peek"])
        stepped = int(final["fields"])
    except (ValueError, KeyError, IndexError):
        infra(f"malformed final line (tool exit {result.returncode})")
    if result.returncode != 0 and not final.get("unsupported"):
        infra(f"tool exit {result.returncode}")
    outcome = {"scenario_id": scenario["scenario_id"], "budget_frames": frames, "fields": stepped,
               "oracle_address": oracle["address"], "expected_minimum": oracle["expected_minimum"],
               "expected_maximum": oracle["expected_maximum"], "non_gating": True,
               "claim": "none: smoke only, no compatibility claim"}
    if final.get("unsupported"):
        outcome.update(outcome="unsupported", stop_reason=STOP_NAMES.get(final["stop_reason"], str(final["stop_reason"])),
                       opcode=hex(final["opcode"]), address=hex(final["instruction_address"]),
                       fault_address=hex(final["fault_address"]))
    elif stepped != frames or len(peek) != 2:
        outcome.update(outcome="unknown", reason="budget ended without a determinable value")
    else:
        value = int.from_bytes(peek, "big")
        ok = oracle["expected_minimum"] <= value <= oracle["expected_maximum"]
        outcome.update(outcome="pass" if ok else "fail", observed=value)
    print(json.dumps(outcome, sort_keys=True))
    return 0


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    root, headless = Path(args[0]), Path(args[1])
    rom_override = None
    if "--rom" in args:
        rom_override = args[args.index("--rom") + 1]
    if "--check-digest-rejection" in args:
        scenario = json.loads((root / "fixtures/independent-game/scenario.json").read_text())
        data = bytearray((root / scenario["rom"]["relative_path"]).read_bytes())
        data[len(data) // 2] ^= 0xFF
        with tempfile.TemporaryDirectory(prefix="gw-smoke-neg-") as temp:
            flipped = Path(temp) / "game.bin"
            flipped.write_bytes(bytes(data))
            result = subprocess.run([sys.executable, "-I", __file__, str(root), str(headless), "--rom", str(flipped)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode != 1 or b"rom digest mismatch" not in result.stdout:
            print("wrong rejection: flipped ROM was not rejected by digest", file=sys.stderr)
            return 1
        print("digest rejection ok")
        return 0
    return run(root, headless, rom_override)


if __name__ == "__main__":
    sys.exit(main())
