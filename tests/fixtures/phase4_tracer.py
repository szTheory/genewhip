#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the sounded raster-toy replay through the public headless and desktop clients."""
import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "fixtures/raster-toy/scenario.json"
ROM = ROOT / "fixtures/raster-toy/toy.bin"
RATE = 48000
FIELD_TICKS = 896040
MASTER_HZ = 53693175
TIMEOUT = 90
HASH_LINE = re.compile(r'^\{"(?:sequence|fields)":')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_configuration(binary):
    build = Path(binary).resolve().parents[2]
    cache = build / "CMakeCache.txt"
    if not cache.is_file():
        raise RuntimeError("build configuration cache is missing: " + str(cache))
    keys = ("CMAKE_BUILD_TYPE", "CMAKE_C_COMPILER_ID", "CMAKE_C_COMPILER_VERSION",
            "CMAKE_GENERATOR", "GENEWHIP_BUILD_DESKTOP", "GENEWHIP_TEST_HOOKS")
    values = {}
    for line in cache.read_text(errors="replace").splitlines():
        for key in keys:
            if line.startswith(key + ":"):
                values[key] = line.split("=", 1)[-1]
    identity = {"cmake": values, "host": {"system": platform.system(), "machine": platform.machine()}}
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run(args, env=None):
    result = subprocess.run(list(map(str, args)), cwd=ROOT, env=env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT)
    if result.returncode:
        raise RuntimeError("command failed (%d): %s\n%s" %
                           (result.returncode, " ".join(map(str, args)), result.stderr[-3000:]))
    if re.search(r"(?:^|\n)STOP:", result.stderr):
        raise RuntimeError("client reported unsupported stop: " + result.stderr[-1000:])
    return result


def json_records(output):
    rows = []
    for line in output.splitlines():
        if HASH_LINE.match(line):
            rows.append(json.loads(line))
    if not rows:
        raise RuntimeError("client emitted no field/final summaries")
    return rows


def run_tracer(headless, desktop, out):
    scenario = json.loads(SCENARIO.read_text())
    fields = max(s["fields"][1] for s in scenario["samples"] if "fields" in s) + 1
    ticks = scenario["inputs"]["ticks_per_field"]
    entries = scenario["inputs"]["entries"]
    with tempfile.TemporaryDirectory(prefix="gw-phase4-tracer-") as td:
        temp = Path(td)
        replay = temp / "raster-toy.input"
        replay.write_text("genewhip-input-log 1\n" + "".join(
            "%d pad %d %x\n" % (int(e["field"]) * ticks, int(e["port"]), int(e["mask"], 0))
            for e in entries))
        head_pcm, desktop_pcm = temp / "headless.pcm", temp / "desktop.pcm"
        head_trace = temp / "headless.trace"
        head_args = [headless, ROM, "--fields", fields, "--replay", replay, "--audio-rate", RATE,
                     "--dump-audio", head_pcm, "--dump-audio-trace", head_trace]
        head = run(head_args)
        expected_frames = fields * FIELD_TICKS * RATE // MASTER_HZ
        if head_pcm.stat().st_size != expected_frames * 4:
            raise RuntimeError("headless PCM frame count differs from integer master-tick count")
        head_rows = json_records(head.stdout)
        if len(head_rows) != fields + 1 or head_rows[-1].get("fields") != fields:
            raise RuntimeError("headless field summary denominator mismatch")

        dummy_env = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy")
        desk = run([desktop, "--fields", fields, "--replay", replay,
                    "--print-field-hashes", ROM], env=dummy_env)
        if "audio=on" not in desk.stdout or "audio: disabled" in desk.stderr:
            raise RuntimeError("desktop audio device fallback or disabled output")
        desk_rows = json_records(desk.stdout)
        if len(desk_rows) != fields + 1 or desk_rows[-1].get("fields") != fields:
            raise RuntimeError("desktop field summary denominator mismatch")
        if head_rows != desk_rows:
            raise RuntimeError("headless and desktop machine/ordered field summaries differ")

        # SDL's disk backend writes queued frames as they are consumed. Two extra
        # replay fields drain the requested prefix before process shutdown; only
        # that exact source-frame prefix is compared below.
        disk_env = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="disk",
                        SDL_AUDIO_DISK_OUTPUT_FILE=str(temp / "host-device.raw"))
        disk = run([desktop, "--fields", fields + 2, "--replay", replay,
                    "--dump-audio", desktop_pcm,
                    "--print-field-hashes", ROM], env=disk_env)
        if "audio=on" not in disk.stdout or "audio: disabled" in disk.stderr:
            raise RuntimeError("desktop disk audio device fallback or disabled output")
        drained_rows = json_records(disk.stdout)
        if drained_rows[:fields] != head_rows[:fields]:
            raise RuntimeError("disk-driver replay changed requested field identities/pixels")
        desktop_bytes = desktop_pcm.read_bytes()
        head_bytes = head_pcm.read_bytes()
        if len(desktop_bytes) < len(head_bytes) or desktop_bytes[:len(head_bytes)] != head_bytes:
            raise RuntimeError("complete requested headless and desktop PCM prefix differs (%d vs %d bytes)" %
                               (len(head_bytes), len(desktop_bytes)))

        # Reuse the independent source-derived fixture oracles for video, input and
        # causal PSG/FM/DAC sound assertions. They are bounded subprocesses too.
        run([sys.executable, "-I", ROOT / "tests/devices/raster_toy.py", str(ROOT), headless,
             "--test", "planes"])
        run([sys.executable, "-I", ROOT / "tests/devices/raster_toy.py", str(ROOT), headless,
             "--test", "sprites"])
        run([sys.executable, "-I", ROOT / "tests/devices/raster_toy_sound.py", str(ROOT), headless])

        trace = [json.loads(line) for line in head_trace.read_text().splitlines()]
        writes = [r for r in trace if "tick" in r and r.get("source") == 2]
        if not writes or any("dropped" in r and r["dropped"] for r in trace):
            raise RuntimeError("source-derived diagnostic audio trace missing or dropped")
        report = {
            "schema": "genewhip-phase4-tracer",
            "version": 1,
            "outcome": "pass",
            "fixture": "fixtures/raster-toy",
            "scenario_id": scenario["scenario_id"],
            "profile": "VA3 NTSC-U",
            "fields": fields,
            "audio_rate_hz": RATE,
            "source_sha256": sha(ROOT / scenario["rom"]["source"]),
            "scenario_sha256": sha(SCENARIO),
            "rom_sha256": sha(ROM),
            "input_sha256": sha(replay),
            "build_configuration_sha256": build_configuration(headless),
                "headless_build": str(Path(headless).resolve().relative_to(ROOT)),
                "headless_build_sha256": sha(Path(headless)),
                "desktop_build": str(Path(desktop).resolve().relative_to(ROOT)),
                "desktop_build_sha256": sha(Path(desktop)),
            "host": {"system": platform.system(), "machine": platform.machine()},
            "observations": {
                "ordered_field_summaries": len(head_rows) - 1,
                "final_machine_summary": head_rows[-1],
                "headless_pcm_bytes": len(head_bytes),
                "desktop_pcm_bytes": len(desktop_bytes),
                "pcm_sha256": hashlib.sha256(head_bytes).hexdigest(),
                "source_audio_writes": len(writes),
            },
        }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print("phase4 tracer pass: %d fields, %d PCM frames; headless/desktop equal" % (fields, expected_frames))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--headless", required=True, type=Path)
    parser.add_argument("--desktop", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        run_tracer(args.headless.resolve(), args.desktop.resolve(), args.out)
    except (AssertionError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
