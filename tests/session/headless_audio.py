#!/usr/bin/env python3
"""Check deterministic, self-describing PCM emitted by gw_headless."""
import json
import pathlib
import subprocess
import sys
import tempfile

MASTER_HZ = 53_693_175
FIELD_TICKS = 896_040
RATE = 48_000
FNV_OFFSET = 14_695_981_039_346_656_037
FNV_PRIME = 1_099_511_628_211


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def fnv(data, value=FNV_OFFSET):
    for byte in data:
        value = ((value ^ byte) * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return value


def u32le(value):
    return value.to_bytes(4, "little")


def expected_hash(metadata, audio):
    seed = (u32le(metadata["audio_rate_hz"]) + u32le(metadata["mix_id"]) +
            u32le(metadata["filter_id"]) + b"S16LE2")
    return fnv(audio, fnv(seed))


def run(executable, rom, output):
    return subprocess.run(
        [executable, rom, "--fields", "3", "--audio-rate", str(RATE),
         "--dump-audio", str(output)],
        check=False, capture_output=True, text=True, timeout=60)


def main():
    negative = "--negative-control" in sys.argv
    args = [arg for arg in sys.argv[1:] if arg != "--negative-control"]
    if len(args) != 2:
        return fail("usage: headless_audio.py gw_headless psg_tone.bin [--negative-control]")
    executable, rom = args
    with tempfile.TemporaryDirectory(prefix="genewhip-headless-audio-") as temp:
        path = pathlib.Path(temp) / "audio.pcm"
        first = run(executable, rom, path)
        if first.returncode != 0:
            return fail(f"headless run failed: {first.stderr.strip()}")
        lines = [line for line in first.stdout.splitlines() if line.startswith('{')]
        try:
            metadata = next(json.loads(line) for line in lines if '"audio_rate_hz"' in line)
        except (StopIteration, json.JSONDecodeError):
            return fail("audio summary JSON line is missing or malformed")
        pcm = path.read_bytes()
        expected_frames = (3 * FIELD_TICKS * RATE) // MASTER_HZ
        if metadata.get("frames") != expected_frames or len(pcm) != 4 * expected_frames:
            return fail(f"PCM length mismatch: expected {expected_frames} frames, got {metadata.get('frames')}")
        if not metadata.get("complete") or metadata.get("lost") != 0:
            return fail("audio output is not complete")
        if metadata.get("fnv1a64") != f"{expected_hash(metadata, pcm):016x}":
            return fail("audio hash mismatch")
        audio_line = next(line for line in lines if '"audio_rate_hz"' in line)
        if negative:
            changed = bytearray(pcm)
            changed[0] ^= 1
            if metadata["fnv1a64"] == f"{expected_hash(metadata, changed):016x}":
                return fail("audio hash mismatch negative control was not detected")
            print("headless_audio negative control: audio hash mismatch")
            return 0
        second_path = pathlib.Path(temp) / "audio-second.pcm"
        second = run(executable, rom, second_path)
        if second.returncode != 0:
            return fail(f"replay failed: {second.stderr.strip()}")
        second_line = next((line for line in second.stdout.splitlines()
                            if '"audio_rate_hz"' in line), None)
        if second_line != audio_line or second_path.read_bytes() != pcm:
            return fail("identical runs produced different audio evidence")
    print("headless_audio: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
