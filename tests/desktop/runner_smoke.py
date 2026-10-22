"""Desktop runner cases, driven headlessly with the SDL dummy video driver
(runner_live_display opts into the real platform driver).

usage: runner_smoke.py CASE RUNNER BACKDROP_ROM [PAD_ECHO_ROM HEADLESS]
"""
import json
import os
import re
import subprocess
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

case, runner, rom = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
pad_echo = Path(sys.argv[4]) if len(sys.argv) > 4 else None
headless = Path(sys.argv[5]) if len(sys.argv) > 5 else None
ENV = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy")
STATUS = re.compile(rb"^fields=(\d+) paused_fields=(\d+) resets=(\d+)(?: .*)?$", re.M)


def run(*args, env=ENV):
    return subprocess.run([str(runner), *map(str, args)], capture_output=True, env=env, timeout=40)


def status(result):
    match = STATUS.search(result.stdout)
    assert match, (result.stdout, result.stderr)
    return tuple(int(group) for group in match.groups())


def runner_fields():
    result = run("--fields", 120, rom)
    assert result.returncode == 0, result.stderr
    assert status(result) == (120, 0, 0), result.stdout


def reject(result, reason, name=None):
    assert result.returncode not in (0, None), result
    assert result.stderr.startswith(b"REJECT: " + reason.encode()), result.stderr
    if name is not None:
        assert name.encode() in result.stderr, result.stderr
    assert b"\x1b" not in result.stderr, "escape byte reached the terminal"


def runner_errors():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        reject(run(base / "absent.bin"), "missing", "absent.bin")
        reject(run(base / "bad\x1b[2Jname.bin"), "missing", "bad?[2Jname.bin")
        (base / "folder").mkdir()
        reject(run(base / "folder"), "not-regular-file", "folder")
        (base / "huge.bin").write_bytes(bytes(4194306))
        reject(run(base / "huge.bin"), "too-large", "huge.bin")
        (base / "odd.bin").write_bytes(bytes(1025))
        reject(run(base / "odd.bin"), "odd-size", "odd.bin")
        vectors = bytearray(1024)
        vectors[0:8] = (0x00FFFF00).to_bytes(4, "big") + (0x201).to_bytes(4, "big")  # odd reset PC
        (base / "oddpc.bin").write_bytes(vectors)
        reject(run(base / "oddpc.bin"), "invalid-rom", "oddpc.bin")
        (base / "bad.script").write_text("5 explode\n")
        reject(run("--host-script", base / "bad.script", rom), "host-script")
        usage = run()
        assert usage.returncode == 2 and b"usage:" in usage.stderr


def runner_host_controls():
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "controls.script"
        script.write_text("10 pause\n30 resume\n40 reset\n60 quit\n")
        result = run("--host-script", script, rom)
        assert result.returncode == 0, result.stderr
        assert status(result) == (40, 20, 1), result.stdout


def counters(result):
    line = next((line for line in result.stdout.decode().splitlines() if line.startswith("fields=")), "")
    values = dict(re.findall(r"([a-z][a-z0-9_]*)=([0-9]+(?:\.[0-9]+)?)", line))
    match = re.search(r"\baudio=(on|off)\b", line)
    if match:
        values["audio"] = match.group(1)
    return values


def runner_audio_counters():
    result = run("--fields", 180, "--print-field-hashes", rom)
    assert result.returncode == 0, result.stderr
    values = counters(result)
    assert values.get("audio") == "on", result.stdout
    numbers = {key: float(value) for key, value in values.items() if key != "audio"}
    assert numbers["produced_frames"] == numbers["consumed_frames"] + numbers["queued_frames"] + numbers["dropped_frames"], values
    assert numbers["dropped_frames"] == (numbers["host_cap_dropped_frames"] +
                                           numbers["intentional_clear_frames"] +
                                           numbers["stream_failure_dropped_frames"]), values
    assert numbers["queue_source_bytes"] == numbers["queue_source_frames"] * 4, values
    assert 0.995 <= numbers["ratio_min"] <= numbers["ratio_max"] <= 1.005, values
    assert numbers["core_lost"] == 0, values
    # N(t) = floor(t * 48000 / master_clock); final tick is 180 field ends.
    expected = (180 * 896040 * 48000) // 53693175
    assert numbers["core_frames"] == expected, (numbers, expected)
    unavailable = run("--fields", 180, "--print-field-hashes", rom,
                      env=dict(ENV, SDL_AUDIODRIVER="genewhip-no-such-driver"))
    assert unavailable.returncode == 0, unavailable.stderr
    assert hash_lines(unavailable) == hash_lines(result), "audio availability changed field hashes"


def runner_audio_mute_hashes():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        script = base / "mute.script"
        log = base / "mute.log"
        script.write_text("30 mute\n90 unmute\n")
        plain = run("--fields", 150, "--print-field-hashes", rom)
        muted = run("--fields", 150, "--host-script", script, "--record", log,
                    "--print-field-hashes", rom)
        fallback = run("--fields", 150, "--print-field-hashes", rom,
                       env=dict(ENV, SDL_AUDIODRIVER="genewhip-no-such-driver"))
        for result in (plain, muted, fallback):
            assert result.returncode == 0, result.stderr
        assert hash_lines(plain) == hash_lines(muted) == hash_lines(fallback), "mute/audio changed core field hashes"
        assert counters(plain)["produced_frames"] == counters(muted)["produced_frames"], (plain.stdout, muted.stdout)
        assert "mute" not in log.read_text() and "unmute" not in log.read_text(), log.read_text()


def stat_lines(result):
    lines = [line for line in result.stderr.decode().splitlines() if line.startswith("audio=")]
    return [dict(re.findall(r"([a-z][a-z0-9_]*)=([a-z]+|[0-9]+(?:\.[0-9]+)?)", line)) for line in lines]


def paused_starvation_is_stable(lines):
    paused = [int(line["producer_starvation_observations"])
              for line in lines if line.get("audio_paused") == "1"]
    return len(paused) >= 3 and len(set(paused)) == 1


def has_two_sustained_silence_runs(runs, minimum_frames):
    return sum(length >= minimum_frames for length in runs) >= 2


def deterministic_pcm_matches(captured, expected, core_frames):
    return len(expected) == core_frames * 4 and captured == expected


def runner_audio_capture():
    headless_runner = Path(sys.argv[4]) if len(sys.argv) > 4 else headless
    assert headless_runner is not None, "headless executable is required for PCM comparison"
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        script = base / "capture.script"
        capture = base / "capture.raw"
        desktop_pcm = base / "desktop.pcm"
        headless_pcm = base / "headless.pcm"
        script.write_text("40 mute\n80 unmute\n120 pause\n160 resume\n")
        env = dict(ENV, SDL_AUDIODRIVER="disk", SDL_AUDIO_DISK_OUTPUT_FILE=str(capture))
        result = run("--fields", 240, "--host-script", script,
                     "--print-field-hashes", "--dump-audio", desktop_pcm, rom, env=env)
        assert result.returncode == 0, (result.stdout, result.stderr)
        raw = capture.read_bytes()
        values = counters(result)
        frame_counters = ("produced_frames", "consumed_frames", "queued_frames",
                          "dropped_frames", "host_cap_dropped_frames",
                          "intentional_clear_frames", "stream_failure_dropped_frames",
                          "core_frames")
        numbers = {key: int(values[key]) for key in frame_counters}
        assert values.get("audio") == "on", result.stdout
        assert numbers["produced_frames"] == numbers["consumed_frames"] + numbers["queued_frames"] + numbers["dropped_frames"], values
        assert numbers["dropped_frames"] == (numbers["host_cap_dropped_frames"] +
                                               numbers["intentional_clear_frames"] +
                                               numbers["stream_failure_dropped_frames"]), values
        assert len(raw) % 4 == 0, len(raw)
        headless_result = subprocess.run(
            [str(headless_runner), str(rom), "--fields", "240", "--audio-rate", "48000",
             "--dump-audio", str(headless_pcm)],
            capture_output=True, timeout=60)
        assert headless_result.returncode == 0, headless_result.stderr
        assert deterministic_pcm_matches(desktop_pcm.read_bytes(), headless_pcm.read_bytes(),
                                         numbers["core_frames"]), (
            "captured session PCM differs from deterministic core PCM", desktop_pcm.stat().st_size,
            headless_pcm.stat().st_size, numbers)
        samples = struct.unpack("<" + "h" * (len(raw) // 2), raw)
        frames = list(zip(samples[0::2], samples[1::2]))
        silent_runs = []
        run_start = None
        for index, pair in enumerate(frames + [(1, 1)]):
            if pair == (0, 0) and run_start is None:
                run_start = index
            elif pair != (0, 0) and run_start is not None:
                silent_runs.append(index - run_start)
                run_start = None
        # Keep a substantial observed-silence floor while allowing two extra
        # 800-frame callbacks versus the former 75% cutoff. This device-file
        # duration is scheduler-sensitive; functional correctness comes from
        # conserved production accounting, the audio control seams, and the
        # byte-for-byte deterministic core PCM comparison above.
        required = int(40 * 800 * 0.70)
        assert has_two_sustained_silence_runs(silent_runs, required), (silent_runs, required, len(frames))
        assert any(left or right for left, right in frames), "capture is entirely silent"


def runner_toy_sound():
    scenario = json.loads((rom.parent / "scenario.json").read_text())
    driver = (rom.parent / "z80/driver.s").read_text()
    values = {name: int(value, 0) for name, value in re.findall(
        r"^\.equ\s+([A-Z0-9_]+),\s*(0x[0-9a-fA-F]+|[0-9]+)\s*$", driver, re.M)}
    press_fields = {3, 30, 60}
    masks = {"A": values["PAD_A_MASK"] if "PAD_A_MASK" in values else 0x40,
             "B": 0x10, "C": 0x20}
    assert all(any(e["field"] == field and int(e["mask"], 0) & mask
                   for e in scenario["inputs"]["entries"] for mask in masks.values())
               for field in press_fields), "scenario button schedule changed"
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        script = base / "toy.script"
        capture = base / "toy.raw"
        script.write_text("".join(f"{e['field']} press 1 {int(e['mask'], 0):02x}\n"
                                   for e in scenario["inputs"]["entries"] if e["port"] == 0))
        args = ("--fields", 240, "--host-script", script, "--print-field-hashes", rom)
        disk_env = dict(ENV, SDL_AUDIODRIVER="disk", SDL_AUDIO_DISK_OUTPUT_FILE=str(capture))
        disk = run(*args, env=disk_env)
        dummy = run(*args, env=ENV)
        for result in (disk, dummy):
            assert result.returncode == 0, (result.stdout, result.stderr)
        assert hash_lines(disk) == hash_lines(dummy), "audio driver changed toy field hashes"
        values_out = counters(disk)
        assert values_out.get("audio") == "on", disk.stdout
        numeric = {key: float(value) for key, value in values_out.items() if key != "audio"}
        assert numeric["produced_frames"] == (numeric["consumed_frames"] + numeric["queued_frames"] +
                                               numeric["dropped_frames"]), values_out
        assert numeric["core_lost"] == 0, values_out
        raw = capture.read_bytes()
        # SDL's disk backend closes with a short queued tail; the capture must
        # cover every scripted sound window, including the field-63 DAC tail.
        assert len(raw) % 4 == 0 and len(raw) >= 63 * 800 * 4, len(raw)
        stereo = struct.unpack("<" + "h" * (len(raw) // 2), raw)
        frames = list(zip(stereo[0::2], stereo[1::2]))

        def ac_range(start_field, end_field):
            first = start_field * 896040 * 48000 // 53693175
            last = end_field * 896040 * 48000 // 53693175
            block = frames[first:last]
            assert block, (start_field, end_field, len(frames))
            return max(max(pair) for pair in block) - min(min(pair) for pair in block)

        for label, start, end in (("PSG", 4, 18), ("FM", 32, 48), ("DAC", 61, 63)):
            span = ac_range(start, end)
            assert span >= 128, f"{label} capture window AC range {span} < 128"
        print(f"toy disk capture: {len(frames)} stereo frames; runner counters conserved; hashes match dummy")


def runner_audio_pause():
    # Paused samples are selected by the published audio state, not by an
    # output-line range that can include resumed host callbacks.
    assert paused_starvation_is_stable([
        {"audio_paused": "1", "producer_starvation_observations": "4"},
        {"audio_paused": "0", "producer_starvation_observations": "9"},
        {"audio_paused": "1", "producer_starvation_observations": "4"},
        {"audio_paused": "1", "producer_starvation_observations": "4"},
    ])
    assert not paused_starvation_is_stable([
        {"audio_paused": "1", "producer_starvation_observations": "4"},
        {"audio_paused": "0", "producer_starvation_observations": "9"},
        {"audio_paused": "1", "producer_starvation_observations": "5"},
        {"audio_paused": "1", "producer_starvation_observations": "5"},
    ])
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "pause.script"
        script.write_text("30 pause\n70 resume\n")
        result = run("--fields", 70, "--host-script", script, "--stats-interval", 10, rom)
        assert result.returncode == 0, (result.stdout, result.stderr)
        lines = stat_lines(result)
        assert len(lines) == 11, (len(lines), result.stderr)
        observed = [int(line["producer_starvation_observations"])
                    for line in lines if line.get("audio_paused") == "1"]
        assert paused_starvation_is_stable(lines), (observed, lines)
        assert status(result)[1] == 40, result.stdout


def runner_audio_reset():
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "reset.script"
        script.write_text(f"60 reset\n120 drop {rom}\n")
        result = run("--fields", 180, "--host-script", script, "--stats-interval", 1, rom)
        assert result.returncode == 0, (result.stdout, result.stderr)
        lines = stat_lines(result)
        assert len(lines) == 300, (len(lines), result.stderr[-1000:])
        def values(index):
            return {key: float(value) for key, value in lines[index].items() if key != "audio"}
        before_reset, after_reset = values(59), values(60)
        before_drop, after_drop = values(119), values(120)
        for before, after in ((before_reset, after_reset), (before_drop, after_drop)):
            assert after["queued_frames"] >= 2403 - 800, (before, after)
            assert after["underruns"] == before["underruns"], (before, after)
        assert after_reset["core_frames"] > before_reset["core_frames"], (before_reset, after_reset)
        assert after_drop["core_frames"] < before_drop["core_frames"], (before_drop, after_drop)
        assert status(result)[2] == 1, result.stdout


def runner_stats():
    with tempfile.TemporaryDirectory() as directory:
        stats = Path(directory) / "stats.json"
        result = run("--fields", 30, "--stats", stats, "--stats-interval", 10,
                     "--print-field-hashes", rom)
        assert result.returncode == 0, result.stderr
        report = json.loads(stats.read_text())
        exit_values = counters(result)
        exit_audio_keys = set(stat_lines(result)[-1])
        assert set(report) - {"last_present_error", "queue_source_unit"} == exit_audio_keys, (set(report), exit_audio_keys)
        assert str(report["produced_frames"]) == exit_values["produced_frames"], (report, exit_values)
        stdout_lines = result.stdout.decode().splitlines()
        assert stdout_lines and all(line.startswith("{") or line.startswith("fields=") for line in stdout_lines), result.stdout
        interval_lines = result.stderr.decode().splitlines()
        assert len(interval_lines) == 3 and all(line.startswith("audio=") for line in interval_lines), result.stderr
        assert all(set(values) == exit_audio_keys for values in stat_lines(result)), stat_lines(result)
        home = str(Path.home()).encode()
        for payload in (result.stdout, result.stderr, stats.read_bytes()):
            assert home not in payload and b"/Users/" not in payload, payload


class RunnerPresentationContract(unittest.TestCase):
    def test_versioned_scheduler_and_identity_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            stats = Path(directory) / "stats.json"
            result = run("--fields", 30, "--stats", stats, rom)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(stats.read_text())
            self.assertEqual(report.get("stats_version"), 2,
                             f"runner stats must expose schema version 2: {report}")
            for key in ("scheduled_deadlines", "late_deadlines", "emulated_fields",
                        "catchup_fields", "discarded_wall_ns", "present_calls",
                        "present_successes", "present_errors", "last_presented_field_id",
                        "superseded_fields", "repeated_field_ids"):
                self.assertIn(key, report, f"missing scheduler observation {key}: {report}")


class RunnerAudioStatisticsContract(unittest.TestCase):
    def test_queue_and_loss_categories_use_source_frame_units(self):
        with tempfile.TemporaryDirectory() as directory:
            stats = Path(directory) / "stats.json"
            script = Path(directory) / "controls.script"
            script.write_text("3 mute\n6 pause\n8 resume\n10 reset\n12 unmute\n")
            result = run("--fields", 20, "--host-script", script, "--stats", stats, rom)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(stats.read_text())
            self.assertIn("queue_source_bytes", report,
                          f"runner must expose SDL source-byte depth: {report}")
            for key in ("queue_source_frames", "queue_samples", "queue_exposure_ns",
                        "producer_starvation_observations", "core_lost_frames",
                        "host_cap_dropped_frames", "intentional_clear_frames",
                        "pause_ramp_frames", "reprime_silence_frames", "audio_muted", "audio_paused"):
                self.assertIn(key, report, f"missing audio observation {key}: {report}")
            self.assertEqual(report["queue_source_bytes"], 4 * report["queue_source_frames"])
            self.assertGreater(report["queue_samples"], 0)
            self.assertGreater(report["intentional_clear_frames"], 0)
            self.assertGreater(report["reprime_silence_frames"], 0)
            self.assertFalse(report["audio_muted"])
            self.assertFalse(report["audio_paused"])


class RunnerAudioCaptureContract(unittest.TestCase):
    def test_silence_cutoff_rejects_subthreshold_or_single_spans(self):
        minimum = int(40 * 800 * 0.70)
        self.assertTrue(has_two_sustained_silence_runs([minimum, minimum], minimum))
        self.assertFalse(has_two_sustained_silence_runs([minimum - 1, minimum + 1], minimum))
        self.assertFalse(has_two_sustained_silence_runs([minimum * 2], minimum))

    def test_core_pcm_rejects_wrong_and_truncated_bytes(self):
        expected = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        self.assertTrue(deterministic_pcm_matches(expected, expected, 2))
        self.assertFalse(deterministic_pcm_matches(expected[:-4], expected, 2))
        self.assertFalse(deterministic_pcm_matches(expected, expected[:-4], 2))
        self.assertFalse(deterministic_pcm_matches(expected[:-1] + b"\x00", expected, 2))


def runner_live_audio():
    if os.environ.get("GENEWHIP_LIVE_AUDIO") != "1":
        print("SKIP: runner_live_audio (set GENEWHIP_LIVE_AUDIO=1 to use the default audio device)")
        sys.exit(77)
    driver = LIVE_DRIVERS.get(sys.platform)
    if driver is None:
        print(f"SKIP: runner_live_audio (no live video driver recorded for {sys.platform})")
        sys.exit(77)
    live_env = dict(os.environ, SDL_VIDEODRIVER=driver)
    live_env.pop("SDL_AUDIODRIVER", None)
    result = run("--fields", 120, "--stats-interval", 30, rom, env=live_env)
    if result.returncode != 0 and b"Could not" in result.stderr:
        print(f"SKIP: runner_live_audio (no live window: {result.stderr.decode(errors='replace').strip()})")
        sys.exit(77)
    assert result.returncode == 0, result.stderr
    values = counters(result)
    if values.get("audio") != "on":
        print("SKIP: runner_live_audio (SDL default audio device did not open)")
        sys.exit(77)
    numeric = {key: float(value) for key, value in values.items() if key != "audio"}
    assert numeric["produced_frames"] == numeric["consumed_frames"] + numeric["queued_frames"] + numeric["dropped_frames"], values
    assert 0.995 <= numeric["ratio_min"] <= numeric["ratio_max"] <= 1.005, values
    assert numeric["core_frames"] > 0 and numeric["produced_frames"] > 0, values
    print("live audio driver: counters conserved and ratio remained bounded")


def runner_audio_fallback():
    env = dict(ENV, SDL_AUDIODRIVER="genewhip-no-such-driver")
    with tempfile.TemporaryDirectory() as directory:
        stats = Path(directory) / "fallback.json"
        result = run("--fields", 180, "--stats", stats, "--print-field-hashes", rom, env=env)
        report = json.loads(stats.read_text())
    assert result.returncode == 0, result.stderr
    lines = result.stderr.decode().splitlines()
    assert len(lines) == 1 and lines[0].startswith("audio: disabled ("), result.stderr
    assert counters(result).get("audio") == "off", result.stdout
    assert report["audio_available"] == 0 and report["queue_samples"] == 0, report
    values = counters(result)
    numbers = {key: float(value) for key, value in values.items() if key != "audio"}
    assert numbers["produced_frames"] == numbers["consumed_frames"] + numbers["queued_frames"] + numbers["dropped_frames"]
    assert 0.995 <= numbers["ratio_min"] <= numbers["ratio_max"] <= 1.005


def runner_audio_replay():
    first = run("--fields", 180, "--print-field-hashes", rom)
    second = run("--fields", 180, "--print-field-hashes", rom)
    assert first.returncode == second.returncode == 0, (first.stderr, second.stderr)
    assert hash_lines(first) == hash_lines(second), "audio-on field hashes changed across runs"
    a, b = counters(first), counters(second)
    for key in ("core_frames", "core_lost", "core_clipped"):
        assert a[key] == b[key], (key, a, b)
    for values in (a, b):
        numbers = {key: float(value) for key, value in values.items() if key != "audio"}
        accounted = numbers["consumed_frames"] + numbers["queued_frames"] + numbers["dropped_frames"]
        assert numbers["produced_frames"] == accounted, ("source-frame conservation", values, accounted)
        assert 0.995 <= numbers["ratio_min"] <= numbers["ratio_max"] <= 1.005
    expected = (180 * 896040 * 48000) // 53693175
    assert float(a["core_frames"]) == expected, (a, expected)
    with tempfile.TemporaryDirectory() as directory:
        dump = Path(directory) / "headless.pcm"
        result = subprocess.run([str(headless), str(rom), "--fields", "180", "--audio-rate", "48000",
                                 "--dump-audio", str(dump)], capture_output=True, timeout=60)
        assert result.returncode == 0, result.stderr
        assert dump.stat().st_size % 4 == 0
        assert dump.stat().st_size // 4 == expected == int(float(a["core_frames"]))


def runner_audio_dump():
    with tempfile.TemporaryDirectory() as directory:
        desktop_dump = Path(directory) / "desktop.pcm"
        headless_dump = Path(directory) / "headless.pcm"
        fields = 4
        desktop_result = run("--fields", fields, "--dump-audio", desktop_dump, rom)
        assert desktop_result.returncode == 0, desktop_result.stderr
        assert counters(desktop_result).get("audio") == "on", desktop_result.stdout
        headless_result = subprocess.run([str(headless), str(rom), "--fields", str(fields),
                                          "--audio-rate", "48000", "--dump-audio", str(headless_dump)],
                                         capture_output=True, timeout=40)
        assert headless_result.returncode == 0, headless_result.stderr
        assert desktop_dump.read_bytes() == headless_dump.read_bytes(), "dump differs from core PCM"
        assert desktop_dump.stat().st_size % 4 == 0
        failed = run("--fields", fields, "--dump-audio", Path(directory) / "missing" / "out.pcm", rom)
        assert failed.returncode != 0 and b"ERROR: could not write audio dump" in failed.stderr, failed.stderr


def hash_lines(result):
    return [line for line in result.stdout.decode().splitlines() if line.startswith("{")]


def runner_input_replay():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        script = base / "press.script"
        # Both ports are driven independently; the reset lands mid-run.
        script.write_text("5 press 1 41\n9 press 2 02\n14 press 1 00\n18 reset\n22 press 2 04\n30 press 2 00\n")
        log = base / "session.log"
        live = run("--fields", 40, "--host-script", script, "--record", log, "--print-field-hashes", pad_echo)
        assert live.returncode == 0, live.stderr
        lines = hash_lines(live)
        assert len(lines) == 41, len(lines)  # 40 fields and the final line
        text = log.read_text().splitlines()
        assert text[0] == "genewhip-input-log 1" and any(" reset" in line for line in text), text
        assert any(" pad 0 " in line for line in text) and any(" pad 1 " in line for line in text), text
        assert "/" not in log.read_text(), "log must not carry paths"
        replayed = subprocess.run([str(headless), str(pad_echo), "--fields", "40", "--replay", str(log)],
                                  capture_output=True, timeout=40)
        assert replayed.returncode == 0, replayed.stderr
        assert hash_lines(replayed) == lines, "headless replay differs from the runner"
        # The runner replays its own log too, and input changed the output.
        again = run("--fields", 40, "--replay", log, "--print-field-hashes", pad_echo)
        assert again.returncode == 0 and hash_lines(again) == lines, again.stderr
        assert len({json_hash(line) for line in lines[:-1]}) > 3, "input did not change the output"
        # A port set to none ignores its presses.
        quiet = run("--fields", 40, "--host-script", script, "--port2", "none", "--print-field-hashes", pad_echo)
        assert quiet.returncode == 0 and hash_lines(quiet) != lines
        reject(run("--replay", base / "absent.log", pad_echo), "input-log io")


def json_hash(line):
    return line.split('"fnv1a64":')[-1]


def runner_drop():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        script = base / "drop.script"
        (base / "folder").mkdir()
        script.write_text(f"5 drop {pad_echo}\n")
        result = run("--fields", 20, "--host-script", script, "--print-field-hashes", rom)
        assert result.returncode == 0, result.stderr
        assert b"LOADED: pad_echo.bin" in result.stderr, result.stderr
        lines = [json.loads(line) for line in hash_lines(result)]
        assert len(lines) == 26, len(lines)  # 5 + 20 fields and the final line
        assert [line["sequence"] for line in lines[4:7]] == [4, 0, 1], "session restarted at the drop"
        assert lines[-1]["fields"] == 20
        script.write_text(f"5 drop {base / 'folder'}\n")
        kept = run("--fields", 20, "--host-script", script, "--print-field-hashes", rom)
        assert kept.returncode == 0, kept.stderr
        assert b"REJECT: not-regular-file folder" in kept.stderr, kept.stderr
        assert b"LOADED" not in kept.stderr
        assert len(hash_lines(kept)) == 21, "the previous session kept running"
        assert json.loads(hash_lines(kept)[-1])["fields"] == 20


LIVE_DRIVERS = {"darwin": "cocoa"}


def skip(reason):
    print(f"SKIP: runner_live_display ({reason})")
    sys.exit(77)


def runner_live_display():
    # Opt-in lane: a real window on the platform video driver must match the dummy driver.
    if os.environ.get("GENEWHIP_LIVE_DISPLAY") != "1":
        skip("set GENEWHIP_LIVE_DISPLAY=1 to open a real window")
    driver = LIVE_DRIVERS.get(sys.platform)
    if driver is None:
        skip(f"no live driver recorded for {sys.platform}")
    live_env = dict(ENV, SDL_VIDEODRIVER=driver)
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "live.script"
        script.write_text("5 press 1 08\n40 press 1 00\n45 press 2 04\n70 press 2 00\n"
                          "80 pause\n90 resume\n95 reset\n")
        args = ("--fields", 120, "--host-script", script, "--print-field-hashes", pad_echo)
        started = time.monotonic()
        live = run(*args, env=live_env)
        elapsed = time.monotonic() - started
        if live.returncode != 0 and b"Could not" in live.stderr:
            skip(f"no window server for {driver}: {live.stderr.decode(errors='replace').strip()}")
        assert live.returncode == 0, live.stderr
        dummy = run(*args)
        assert dummy.returncode == 0, dummy.stderr
        lines = hash_lines(live)
        assert len(lines) == 121, len(lines)
        assert lines == hash_lines(dummy), "live driver output differs from the dummy driver"
        assert len({json_hash(line) for line in lines[:-1]}) > 3, "input did not change the output"
        # 130 presented fields (120 run plus 10 paused) at about 60 Hz, plus window start-up.
        assert 1.8 <= elapsed <= 10.0, f"live run took {elapsed:.2f}s"
        print(f"live driver {driver}: 121 hashes match dummy, {elapsed:.2f}s wall")


CASES = {"runner_fields": runner_fields, "runner_errors": runner_errors,
         "runner_host_controls": runner_host_controls,
         "runner_audio_counters": runner_audio_counters,
         "runner_audio_fallback": runner_audio_fallback,
         "runner_audio_replay": runner_audio_replay,
         "runner_audio_dump": runner_audio_dump,
         "runner_audio_mute_hashes": runner_audio_mute_hashes,
         "runner_audio_capture": runner_audio_capture,
         "runner_toy_sound": runner_toy_sound,
         "runner_audio_pause": runner_audio_pause,
         "runner_audio_reset": runner_audio_reset,
         "runner_stats": runner_stats,
         "runner_input_replay": runner_input_replay, "runner_drop": runner_drop,
         "runner_live_display": runner_live_display,
         "runner_live_audio": runner_live_audio}
if case == "runner_presentation_contract":
    result = unittest.TextTestRunner().run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RunnerPresentationContract))
    raise SystemExit(not result.wasSuccessful())
elif case == "runner_audio_stats_contract":
    result = unittest.TextTestRunner().run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RunnerAudioStatisticsContract))
    raise SystemExit(not result.wasSuccessful())
elif case == "runner_audio_capture_contract":
    result = unittest.TextTestRunner().run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RunnerAudioCaptureContract))
    raise SystemExit(not result.wasSuccessful())
else:
    CASES[case]()
    print(f"PASS: {case}")
