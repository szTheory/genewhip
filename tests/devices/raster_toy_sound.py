#!/usr/bin/env python3
"""Source-derived sound evidence for the original raster-toy cartridge."""
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

TICKS_PER_FIELD = 896040
MASTER_HZ = 53693175
AUDIO_RATE = 48000
SOURCE_Z80 = 2
CHIP_PSG = 3
CHIP_YM_PORT0 = 1


def fail(message):
    raise AssertionError(message)


def constants(path):
    source = path.read_text()
    values = {}
    for name, value in re.findall(r"^\s*\.equ\s+([A-Z0-9_]+),\s*(0x[0-9a-fA-F]+|[0-9]+)\s*$", source, re.M):
        values[name] = int(value, 0)
    return source, values


def sample_range(pcm, start_field, end_field):
    """AC range from stereo samples; idle YM2612 DC is intentionally retained."""
    first = start_field * TICKS_PER_FIELD * AUDIO_RATE // MASTER_HZ
    last = end_field * TICKS_PER_FIELD * AUDIO_RATE // MASTER_HZ
    if first >= last:
        fail(f"empty PCM window {start_field}..{end_field}")
    samples = struct.unpack_from("<" + "h" * ((last - first) * 2), pcm, first * 4)
    return max(samples) - min(samples)


def run(root, headless, negative):
    fixture = root / "fixtures/raster-toy"
    scenario = json.loads((fixture / "scenario.json").read_text())
    driver, c = constants(fixture / "z80/driver.s")
    toy, tc = constants(fixture / "src/toy.s")
    for key in ("SND_PSG_BLIP", "SND_FM_NOTE", "SND_DAC_SAMPLE", "MAILBOX",
                "PSG_TONE_PERIOD", "PSG_ATTENUATION", "PSG_DECAY_FIELDS",
                "YM_FNUM_HIGH", "YM_FNUM_LOW", "YM_FNUM_HIGH_REG", "YM_FNUM_LOW_REG",
                "YM_KEY_REG", "YM_CHANNEL", "YM_KEY_ON", "YM_DAC_REG", "YM_DAC_ENABLE_REG",
                "DAC_TABLE_LENGTH"):
        if key not in c:
            fail(f"source constant {key} is missing from driver.s")
    if "PAD_A_MASK" not in tc or "PAD_B_MASK" not in tc or "PAD_C_MASK" not in tc:
        fail("source constants PAD_A_MASK/PAD_B_MASK/PAD_C_MASK are missing from toy.s")
    if tc.get("Z80_MAILBOX") != c["MAILBOX"] or "(0x00a00000+Z80_MAILBOX)" not in toy:
        fail("68000 upload/mailbox address does not match the Z80 guest constant")
    if [c["SND_PSG_BLIP"], c["SND_FM_NOTE"], c["SND_DAC_SAMPLE"]] != [1, 2, 4]:
        fail("Z80 command constants do not match the A/B/C edge bits wired by toy.s")
    if "0x80 + (dac_i * 4)" not in driver or "(DAC_TABLE_LENGTH - 1 - dac_i) * 4" not in driver:
        fail("DAC source-table expression is outside the oracle's documented arithmetic")

    expected_period = c["PSG_TONE_PERIOD"] ^ (1 if negative else 0)
    expected_dac = [0x80 + (i * 4 if i < c["DAC_TABLE_LENGTH"] // 2
                            else (c["DAC_TABLE_LENGTH"] - 1 - i) * 4)
                    for i in range(c["DAC_TABLE_LENGTH"])]
    entries = scenario["inputs"]["entries"]
    for field, mask in ((3, tc["PAD_A_MASK"]), (30, tc["PAD_B_MASK"]), (60, tc["PAD_C_MASK"])):
        if not any(e["field"] == field and int(e["mask"], 0) & mask for e in entries):
            fail(f"scenario has no source-constant button edge at field {field}")
    ticks = scenario["inputs"]["ticks_per_field"]
    with tempfile.TemporaryDirectory(prefix="gw-raster-toy-sound-") as directory:
        base = Path(directory)
        replay = base / "input.log"
        replay.write_text("genewhip-input-log 1\n" + "".join(
            f"{e['field'] * ticks} pad {e['port']} {int(e['mask'], 0):x}\n" for e in entries))
        pcm_path, trace_path = base / "sound.raw", base / "trace.jsonl"
        fields = scenario["samples"][0]["fields"][1] + 1
        result = subprocess.run([str(headless), str(root / scenario["rom"]["path"]),
                                 "--fields", str(fields), "--replay", str(replay),
                                 "--audio-rate", str(AUDIO_RATE), "--dump-audio", str(pcm_path),
                                 "--dump-audio-trace", str(trace_path)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            fail(f"headless replay failed ({result.returncode}): {result.stderr}")
        pcm = pcm_path.read_bytes()
        if len(pcm) != fields * TICKS_PER_FIELD * AUDIO_RATE * 4 // MASTER_HZ:
            # Integer output follows N(t)=floor(t*rate/master); validate the exact terminal count.
            expected_bytes = ((fields * TICKS_PER_FIELD * AUDIO_RATE // MASTER_HZ) * 4)
            if len(pcm) != expected_bytes:
                fail(f"PCM length {len(pcm)} differs from exact native-rate count {expected_bytes}")
        records = [json.loads(line) for line in trace_path.read_text().splitlines()]
        dropped = [r for r in records if "dropped" in r]
        writes = [r for r in records if "tick" in r and r["source"] == SOURCE_Z80]
        if len(dropped) != 1 or dropped[0]["dropped"]:
            fail("audio trace dropped records")

        def window(record, start, end):
            return start * TICKS_PER_FIELD <= record["tick"] <= end * TICKS_PER_FIELD

        psg_any = [r for r in writes if r["chip"] == CHIP_PSG and window(r, 3, 30)]
        psg_values = [r["value"] for r in psg_any]
        expected_psg = [0x80 | (expected_period & 0x0f), (expected_period >> 4) & 0x3f,
                        0x90 | c["PSG_ATTENUATION"]]
        fm = [r for r in writes if r["chip"] == CHIP_YM_PORT0 and window(r, 30, 60)]
        dac = [r for r in writes if r["chip"] == CHIP_YM_PORT0 and r["reg"] == c["YM_DAC_REG"]]
        failures = []
        if not any(psg_values[i:i + len(expected_psg)] == expected_psg
                   for i in range(len(psg_values) - len(expected_psg) + 1)):
            failures.append("PSG_TONE_PERIOD: source-derived PSG divider/attenuation sequence absent/mismatched")
        if len(psg_any) < 4:
            failures.append("PSG trace: Z80 tone/attenuation writes absent")
        if not any(r["reg"] == c["YM_FNUM_HIGH_REG"] and r["value"] == c["YM_FNUM_HIGH"] for r in fm):
            failures.append("YM_FNUM_HIGH: source-derived high F-number write absent/mismatched")
        if not any(r["reg"] == c["YM_FNUM_LOW_REG"] and r["value"] == c["YM_FNUM_LOW"] for r in fm):
            failures.append("YM_FNUM_LOW: source-derived low F-number write absent/mismatched")
        if not any(r["reg"] == c["YM_KEY_REG"] and r["value"] == c["YM_KEY_ON"] for r in fm):
            failures.append("YM_CHANNEL: source-derived FM key-on write absent/mismatched")
        if [r["value"] for r in dac] != expected_dac:
            failures.append(f"DAC_TABLE_LENGTH: expected {len(expected_dac)} source-derived DAC writes, got {len(dac)}")

        # There is no Z80 voice before A. YM2612's documented emulator idle level
        # is a DC baseline (native 504 scaled by mix 3/4); only AC variation is silence.
        before = [r for r in writes if r["tick"] < 3 * TICKS_PER_FIELD]
        pre_ac = sample_range(pcm, 1, 3)
        if before:
            failures.append("pre-press trace: Z80 wrote audio before the first button edge")
        if pre_ac > 32:
            failures.append(f"pre-press AC range {pre_ac} exceeds startup baseline tolerance 32")

        for label, lo, hi in (("PSG", 4, 18), ("FM", 32, 48), ("DAC", 61, 63)):
            span = sample_range(pcm, lo, hi)
            if span < 128:
                failures.append(f"{label} PCM window {lo}..{hi} has AC range {span}, expected >=128")
            else:
                print(f"pass {label} PCM activity fields {lo}-{hi}: AC range {span}")

        if negative:
            if len(failures) != 1 or not failures[0].startswith("PSG_TONE_PERIOD:"):
                fail("negative control did not isolate the source-period mutation: " + repr(failures))
            print("negative control: altered PSG_TONE_PERIOD expectation rejected as required")
            return
        if failures:
            fail("; ".join(failures))
        print(f"pass Z80 mailbox: PSG period {c['PSG_TONE_PERIOD']:#x}, FM channel {c['YM_CHANNEL']}, "
              f"F-number {c['YM_FNUM_HIGH']:#04x}/{c['YM_FNUM_LOW']:#04x}, DAC {len(expected_dac)} samples")
        print(f"pass idle oracle: no pre-press Z80 writes; AC range {pre_ac}, DC retained")


def main(argv):
    negative = "--negative-control" in argv
    args = [arg for arg in argv[1:] if arg != "--negative-control"]
    if len(args) != 2:
        raise SystemExit("usage: raster_toy_sound.py ROOT GW_HEADLESS [--negative-control]")
    run(Path(args[0]), Path(args[1]), negative)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        raise SystemExit(1)
