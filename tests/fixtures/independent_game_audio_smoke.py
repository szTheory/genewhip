#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rights-aware, non-gating PCM smoke for the admitted independent game."""
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

FIELD_TICKS = 896040
BUTTONS = {"Start": 128, "Right": 8, "Left": 4, "Up": 1, "Down": 2, "A": 64, "B": 16, "C": 32}


def input_log(scenario):
    held = [0, 0]
    rows = ["genewhip-input-log 1"]
    for event in sorted(scenario["input_schedule"], key=lambda item: item["frame"]):
        port, _, button = event["control"].partition(" ")
        if port not in ("P1", "P2") or button not in BUTTONS:
            raise ValueError("unknown scenario input")
        index = int(port[1]) - 1
        held[index] = held[index] | BUTTONS[button] if event["asserted"] else held[index] & ~BUTTONS[button]
        rows.append("%d pad %d %x" % (event["frame"] * FIELD_TICKS, index, held[index]))
    return "\n".join(rows) + "\n"


def main():
    root, headless = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    manifest = json.loads((root / "fixtures/manifest.json").read_text())
    pong = next((r for r in manifest.get("fixtures", []) if "pong" in str(r).lower()), None)
    scenario = json.loads((root / "fixtures/independent-game/scenario.json").read_text())
    rom = root / scenario["rom"]["relative_path"]
    if hashlib.sha256(rom.read_bytes()).hexdigest() != scenario["rom"]["sha256"]:
        print(json.dumps({"outcome": "infrastructure-error", "reason": "admitted fixture digest mismatch"}))
        return 1
    with tempfile.TemporaryDirectory(prefix="gw-game-audio-") as td:
        audio = Path(td) / "capture.pcm"
        events = Path(td) / "input.log"
        events.write_text(input_log(scenario))
        try:
            run = subprocess.run([str(headless), str(rom), "--fields", str(scenario["budget"]["frames"]),
                                  "--audio-rate", "48000", "--dump-audio", str(audio), "--replay", str(events),
                                  "--port-device", "pad3", "pad3", "--peek", scenario["oracle"]["address"], "2"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 timeout=scenario["budget"]["hard_timeout_seconds"])
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(json.dumps({"outcome": "infrastructure-error", "reason": type(exc).__name__}))
            return 1
        final = {}
        for line in reversed(run.stdout.strip().splitlines()):
            try:
                candidate = json.loads(line)
            except ValueError:
                continue
            if "fields" in candidate:
                final = candidate
                break
        if run.returncode and not final.get("unsupported"):
            print(json.dumps({"outcome": "infrastructure-error", "reason": "headless exited unexpectedly"}))
            return 1
        if final.get("unsupported"):
            out = {"outcome": "unsupported", "stop_reason": final.get("stop_reason"),
                   "fault_address": final.get("fault_address"), "address": final.get("instruction_address"),
                   "claim": "smoke only; no game audio compatibility claim"}
        elif final.get("fields") != scenario["budget"]["frames"]:
            out = {"outcome": "unknown", "reason": "field budget ended without a terminal stop record",
                   "fields": final.get("fields"), "claim": "smoke only; no game audio compatibility claim"}
        elif not audio.exists() or audio.stat().st_size < 4:
            out = {"outcome": "unknown", "reason": "audio capture absent or too short"}
        else:
            data = audio.read_bytes()
            raw = data[:len(data) // 2 * 2]
            samples = struct.unpack("<%dh" % (len(raw) // 2), raw)
            # A DC idle YM baseline does not count as sound: require temporal AC range.
            ac = max(samples) - min(samples) if samples else 0
            out = {"outcome": "pass" if ac > 0 else "unknown", "frames": len(samples) // 2,
                   "sample_range": ac, "reason": None if ac > 0 else "no temporal AC activity",
                   "claim": "smoke only; no game audio compatibility claim"}
        out["pong"] = "skipped: not admitted"
        print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
