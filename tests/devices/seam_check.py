#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Seam checker: runs gw_seam_runner on an original seam ROM and judges the observed
work-RAM window against authored expectations (NAME.expect.json). Standard library only.

Outcomes per case: pass, fail (reason mismatch), unknown, unsupported,
infrastructure-error. Oracle classes: documented, documented-conflicted, REF-derived,
unknown. All except unknown are judged; unknown cases report the observed bytes.
The exit status is 0 only when every judged case passes. REF-derived passes are
reported separately and are never counted as documented hardware evidence.
Documented-conflicted passes establish selected-model conformance while retaining
the primary-source conflict; they do not resolve hardware truth.

Optional "field_samples" judge single pixels of the newest completed field the runner
dumps at the end of a run (--dump-field): {"id", "oracle_class", "citation", "run", "x",
"y", "expected_cram"} where expected_cram is the CRAM word whose conversion
(docs/video.md, level table below) the pixel must show; "unknown" samples carry no
expectation and report the observed XRGB value. A run may override "run_ticks".
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

CLASSES = ("documented", "documented-conflicted", "REF-derived", "guest-source-derived-arithmetic", "unknown")
OUTCOMES = ("pass", "fail", "unknown", "unsupported", "infrastructure-error")
UNSUPPORTED_STOPS = (2, 3, 4)  # GW_STOP_UNSUPPORTED_{INSTRUCTION,ADDRESS,STATE}
LEVELS = [0, 27, 49, 71, 87, 103, 119, 130, 146, 157, 174, 190, 206, 228, 255]  # docs/video.md


def cram_to_xrgb(word):
    """Genewhip CRAM convention: 3-bit channel v maps to LEVELS[2 * v] (docs/video.md)."""
    return (LEVELS[2 * ((word >> 1) & 7)] << 16) | (LEVELS[2 * ((word >> 5) & 7)] << 8) | LEVELS[2 * ((word >> 9) & 7)]


def reject(message):
    print("REJECT: " + message, file=sys.stderr)
    sys.exit(2)


def load_runs(spec):
    """Optional "runs": [{"id", "events": [[tick, port, "mask-hex"]...], "port_device": [p1, p2]}].
    Without runs there is one implicit run with no events and the runner's default devices."""
    runs = spec.get("runs") or [{"id": "default"}]
    ids = set()
    for run in runs:
        if run["id"] in ids:
            reject("duplicate run id: " + str(run["id"]))
        ids.add(run["id"])
        for tick, port, mask in run.get("events", []):
            if not (isinstance(tick, int) and port in (0, 1) and int(mask, 16) >= 0):
                reject("bad event in run " + run["id"])
        if "run_ticks" in run and not (isinstance(run["run_ticks"], int) and run["run_ticks"] > 0):
            reject("bad run_ticks in run " + run["id"])
        if "port_device" in run and (len(run["port_device"]) != 2 or
                                     any(d not in ("none", "pad3") for d in run["port_device"])):
            reject("bad port_device in run " + run["id"])
    spec["runs"] = runs
    for case in spec["cases"] + spec.get("field_samples", []):
        case.setdefault("run", runs[0]["id"])
        if case["run"] not in ids:
            reject("unknown run for case: " + case["id"])


def load_expectations(path):
    try:
        spec = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError):
        reject("unreadable expectations")
    try:
        window = (spec["ram_offset"], spec["ram_length"])
        if not all(isinstance(v, int) and v >= 0 for v in window) or window[1] == 0:
            reject("bad RAM window")
        if not isinstance(spec["run_ticks"], int) or spec["run_ticks"] <= 0:
            reject("bad run_ticks")
        seen = set()
        for case in spec["cases"]:
            if case["id"] in seen or case["oracle_class"] not in CLASSES:
                reject("duplicate id or unknown oracle class: " + str(case["id"]))
            seen.add(case["id"])
            if not case["citation"]:
                reject("missing citation: " + case["id"])
            kind = case.get("kind", "ram")
            if kind == "ram_bit_sequence":
                count_offset = case["count_offset"]
                if (not isinstance(case.get("bit"), int) or not 0 <= case["bit"] <= 7 or
                        not isinstance(case.get("offset"), int) or
                        not isinstance(case.get("length"), int) or case["length"] < 2 or
                        case["offset"] < window[0] or
                        case["offset"] + case["length"] > window[0] + window[1] or
                        not isinstance(count_offset, int) or count_offset < window[0] or
                        count_offset + 2 > window[0] + window[1] or
                        case.get("pattern") not in ("ones_then_zeroes",)):
                    reject("bad bit-sequence pattern: " + case["id"])
                if not (isinstance(case.get("min_reads", 2), int) and case.get("min_reads", 2) >= 2):
                    reject("bad bit-sequence minimum: " + case["id"])
                continue
            if kind in ("pcm_frequency", "pcm_silence", "pcm_nonsilent", "trace"):
                if kind.startswith("pcm_") and (not isinstance(case.get("start_write"), int) or
                        not isinstance(case.get("end_write"), int) or
                        case["end_write"] <= case["start_write"]):
                    reject("bad PCM write window: " + case["id"])
                if kind == "pcm_frequency" and (not isinstance(case.get("expected_hz"), (int, float)) or
                        not isinstance(case.get("tolerance_pct"), (int, float)) or
                        case["expected_hz"] <= 0 or case["tolerance_pct"] <= 0):
                    reject("bad PCM frequency: " + case["id"])
                if kind == "trace" and not isinstance(case.get("records"), list):
                    reject("bad trace expectation: " + case["id"])
                if kind == "trace" and "spacing_ticks" in case:
                    spacing = case["spacing_ticks"]
                    if (not isinstance(spacing, dict) or
                            not all(isinstance(spacing.get(k), int) for k in ("from_index", "to_index", "ticks")) or
                            spacing["from_index"] < 1 or spacing["to_index"] <= spacing["from_index"] or
                            spacing["ticks"] <= 0):
                        reject("bad trace spacing rule: " + case["id"])
                if kind == "trace" and "field_window" in case:
                    field_window = case["field_window"]
                    if (not isinstance(field_window, dict) or
                            not all(isinstance(field_window.get(k), int) for k in
                                    ("first_vblank_tick", "field_ticks", "slack_ticks")) or
                            field_window["first_vblank_tick"] < 0 or field_window["field_ticks"] <= 0 or
                            field_window["slack_ticks"] < 0):
                        reject("bad trace field window: " + case["id"])
                if kind.startswith("pcm_") and not isinstance(spec.get("audio_rate"), int):
                    reject("audio_rate is required for PCM cases")
                continue
            length = case["length"]
            if not (isinstance(case["offset"], int) and isinstance(length, int) and length > 0
                    and case["offset"] >= window[0] and case["offset"] + length <= window[0] + window[1]):
                reject("case outside the RAM window: " + case["id"])
            if case["oracle_class"] != "unknown":
                if len(bytes.fromhex(case["expected"])) != length:
                    reject("expected length differs: " + case["id"])
                if "mask" in case and len(bytes.fromhex(case["mask"])) != length:
                    reject("mask length differs: " + case["id"])
        if not spec["cases"]:
            reject("no cases")
        for sample in spec.get("field_samples", []):
            if sample["id"] in seen or sample["oracle_class"] not in CLASSES or not sample["citation"]:
                reject("duplicate id, unknown oracle class or missing citation: " + str(sample["id"]))
            seen.add(sample["id"])
            if not (isinstance(sample["x"], int) and isinstance(sample["y"], int) and
                    0 <= sample["x"] < 320 and 0 <= sample["y"] < 224):
                reject("sample outside the field: " + sample["id"])
            if sample["oracle_class"] != "unknown" and not 0 <= int(sample["expected_cram"], 16) <= 0xfff:
                reject("bad expected_cram: " + sample["id"])
        load_runs(spec)
    except (KeyError, TypeError, ValueError):
        reject("malformed expectations")
    return spec


def run_runner(runner, rom, spec, run, trace_output=None):
    """Return (observation, None) or (None, error text)."""
    command = [runner, rom, str(run.get("run_ticks", spec["run_ticks"])), str(spec["ram_offset"]),
               str(spec["ram_length"])]
    wants_field = any(f["run"] == run["id"] for f in spec.get("field_samples", []))
    try:
        with tempfile.TemporaryDirectory() as scratch:
            audio_path = pathlib.Path(scratch) / "audio.raw"
            trace_path = pathlib.Path(scratch) / "trace.jsonl"
            wants_audio = any(c.get("kind", "ram").startswith("pcm_") for c in spec["cases"])
            wants_trace = any(c.get("kind") == "trace" for c in spec["cases"])
            if wants_audio:
                command += ["--audio-rate", str(spec["audio_rate"]), "--dump-audio", str(audio_path)]
            if wants_trace:
                command += ["--dump-audio-trace", str(trace_path)]
            if wants_field:
                command += ["--dump-field", str(pathlib.Path(scratch) / "field.bin")]
            if run.get("events"):
                path = pathlib.Path(scratch) / "events.txt"
                path.write_text("".join("%d %d %s\n" % (t, p, m) for t, p, m in run["events"]))
                command += ["--events", str(path)]
            if "port_device" in run:
                command += ["--port-device"] + run["port_device"]
            done = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if done.returncode != 0:
                return None, "runner exit %d: %s" % (done.returncode, done.stderr.strip())
            observation = json.loads(done.stdout)
            ram = bytes.fromhex(observation["ram"])
            if len(ram) != spec["ram_length"]:
                return None, "runner returned a short RAM window"
            observation["ram"] = ram
            if wants_audio:
                raw = audio_path.read_bytes()
                if len(raw) % 4:
                    return None, "audio dump size is not a stereo S16 frame multiple"
                observation["audio"] = raw
            if wants_trace:
                observation["trace"] = [json.loads(line) for line in trace_path.read_text().splitlines()]
                if trace_output:
                    output_path = pathlib.Path(trace_output)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text("".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
                                                    for item in observation["trace"]))
            if wants_field:
                info = observation["field"]
                pixels = (pathlib.Path(scratch) / "field.bin").read_bytes()
                if len(pixels) != info["width"] * info["height"] * 4:
                    return None, "runner returned a short field"
                observation["pixels"] = pixels
            return observation, None
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        return None, "runner failure: %s" % error


def evaluate(spec, results):
    """results maps run id -> (observation, error)."""
    rows = []
    for case in spec["cases"]:
        observation, error = results[case["run"]]
        row = {"id": case["id"], "oracle_class": case["oracle_class"], "citation": case["citation"]}
        if len(spec["runs"]) > 1 or case["run"] != "default":
            row["run"] = case["run"]
        kind = case.get("kind", "ram")
        if error is not None:
            row.update(outcome="infrastructure-error", reason=error)
        elif observation["stop_reason"] in UNSUPPORTED_STOPS:
            row.update(outcome="unsupported", reason="stop-reason-%d" % observation["stop_reason"])
        elif kind.startswith("pcm_"):
            trace = observation.get("trace", [])
            try:
                start = trace[case["start_write"]]["tick"]
                end = trace[case["end_write"]]["tick"]
                rate = spec["audio_rate"]
                first = max(0, start * rate // 53693175)
                last = min(len(observation["audio"]) // 4, end * rate // 53693175)
                samples = [int.from_bytes(observation["audio"][i * 4 + case.get("channel", 0) * 2:
                    i * 4 + case.get("channel", 0) * 2 + 2], "little", signed=True)
                    for i in range(first, last)]
                if kind == "pcm_frequency":
                    settle = 16
                    samples = samples[settle:]
                    crossings = [i for i in range(1, len(samples)) if samples[i - 1] < 0 <= samples[i]]
                    observed_hz = rate * (len(crossings) - 1) / (crossings[-1] - crossings[0]) if len(crossings) > 1 else 0.0
                    row["observed_hz"] = observed_hz
                    good = abs(observed_hz - case["expected_hz"]) <= case["expected_hz"] * case["tolerance_pct"] / 100
                elif kind == "pcm_silence":
                    samples = samples[case.get("settle_frames", 16):]
                    good = len(samples) > 0 and all(value == samples[0] for value in samples)
                else:
                    good = any(value != 0 for value in samples)
                row.update(outcome="pass" if good else "fail")
                if not good:
                    row["reason"] = "pcm expectation mismatch"
            except (IndexError, KeyError, ZeroDivisionError):
                row.update(outcome="infrastructure-error", reason="invalid PCM trace window")
        elif kind == "trace":
            actual = observation.get("trace", [])
            names = {"psg": 3, "ym_port0": 1, "ym_port1": 2}
            sources = {"68000": 1, "z80": 2}
            expected = []
            for item in case["records"]:
                if isinstance(item, list) and len(item) == 3:
                    bank, reg, value = item
                    expected.append({"chip": 1 + bank, "reg": reg + bank * 256,
                                     "value": value, "source": 2})
                elif isinstance(item, dict) and isinstance(item.get("values"), dict):
                    values = item["values"]
                    if values.get("pattern") != "triangle8" or values.get("count") != 256:
                        row.update(outcome="infrastructure-error", reason="unsupported source-value trace pattern")
                        rows.append(row)
                        continue
                    table = [i * 2 if i < 128 else (255 - i) * 2 for i in range(256)]
                    expected.extend({"chip": names[item["chip"]], "reg": item["reg"],
                                     "value": value, "source": sources[item["source"]]} for value in table)
                else:
                    expected.append({"chip": names.get(item["chip"], item.get("chip")),
                                     "reg": item["reg"], "value": item["value"],
                                     "source": sources.get(item["source"], item.get("source"))})
            start_index = case.get("start_index", 0)
            end_index = case.get("end_index", len(actual))
            selected = actual[start_index:end_index]
            good = len(selected) == len(expected) and all(
                selected[i]["chip"] == item["chip"] and selected[i]["reg"] == item["reg"] and
                selected[i]["value"] == item["value"] and selected[i]["source"] == item["source"]
                for i, item in enumerate(expected))
            if good and "field_window" in case:
                window = case["field_window"]
                for i, record in enumerate(actual):
                    first = window["first_vblank_tick"] + i * window["field_ticks"]
                    if not first <= record["tick"] <= first + window["slack_ticks"]:
                        good = False
                        break
            if good and "spacing_ticks" in case:
                spacing = case["spacing_ticks"]
                good = all(actual[i]["tick"] - actual[i - 1]["tick"] == spacing["ticks"]
                           for i in range(spacing["from_index"] + 1, spacing["to_index"] + 1))
            row.update(outcome="pass" if good else "fail")
            if not good:
                row["reason"] = ("trace spacing differs" if "spacing_ticks" in case else
                                 "trace field window differs" if "field_window" in case else
                                 "trace records differ")
        elif case.get("kind") == "ram_bit_sequence":
            start = case["offset"] - spec["ram_offset"]
            count_at = case["count_offset"] - spec["ram_offset"]
            count = int.from_bytes(observation["ram"][count_at:count_at + 2], "big")
            seen = observation["ram"][start:start + min(case["length"], count)]
            bits = [((value >> case["bit"]) & 1) for value in seen]
            row["observed"] = "".join(str(value) for value in bits)
            row["poll_count"] = count
            if case["oracle_class"] == "unknown":
                row.update(outcome="unknown", reason="no independent expected value")
            else:
                good = (len(bits) == count and count >= case.get("min_reads", 2) and
                        bits[0] == 1 and bits[-1] == 0 and
                        all(not (bits[i - 1] == 0 and bits[i] == 1) for i in range(1, len(bits))))
                row.update(outcome="pass" if good else "fail")
                if not good:
                    row["reason"] = "bit sequence pattern mismatch"
        else:
            start = case["offset"] - spec["ram_offset"]
            seen = observation["ram"][start:start + case["length"]]
            row["observed"] = seen.hex()
            if case["oracle_class"] == "unknown":
                row.update(outcome="unknown", reason="no independent expected value")
            else:
                expected = bytes.fromhex(case["expected"])
                mask = bytes.fromhex(case["mask"]) if "mask" in case else b"\xff" * len(expected)
                row["expected"] = case["expected"]
                if "mask" in case:
                    row["mask"] = case["mask"]
                good = all((a ^ b) & m == 0 for a, b, m in zip(seen, expected, mask))
                row.update(outcome="pass" if good else "fail")
                if not good:
                    row["reason"] = "mismatch"
        rows.append(row)
    for sample in spec.get("field_samples", []):
        observation, error = results[sample["run"]]
        row = {"id": sample["id"], "oracle_class": sample["oracle_class"], "citation": sample["citation"],
               "run": sample["run"], "x": sample["x"], "y": sample["y"]}
        if error is not None:
            row.update(outcome="infrastructure-error", reason=error)
        elif observation["stop_reason"] in UNSUPPORTED_STOPS:
            row.update(outcome="unsupported", reason="stop-reason-%d" % observation["stop_reason"])
        elif sample["x"] >= observation["field"]["width"]:
            row.update(outcome="infrastructure-error", reason="sample column outside the field width")
        else:
            at = (sample["y"] * observation["field"]["width"] + sample["x"]) * 4
            seen = int.from_bytes(observation["pixels"][at:at + 4], "little")
            row["observed"] = "%06x" % seen
            if sample["oracle_class"] == "unknown":
                row.update(outcome="unknown", reason="no independent expected value")
            else:
                want = cram_to_xrgb(int(sample["expected_cram"], 16))
                row["expected"] = "%06x" % want
                row.update(outcome="pass" if seen == want else "fail")
                if seen != want:
                    row["reason"] = "mismatch"
        rows.append(row)
    return rows


def summarize(spec, results, rows):
    observation = results[spec["runs"][0]["id"]][0]
    counts = {name: sum(1 for r in rows if r["outcome"] == name) for name in OUTCOMES}
    by_class = {c: {n: sum(1 for r in rows if r["oracle_class"] == c and r["outcome"] == n)
                    for n in OUTCOMES} for c in CLASSES}
    report = {"version": 1, "seam": spec.get("seam"), "rom": spec.get("rom"),
              "denominator": len(rows), "counts": counts, "by_class": by_class,
              "rows": rows}
    if observation is not None:
        for key in ("source_revision", "configuration", "stop_reason", "actual_tick",
                    "instruction_address", "fault_address"):
            report[key] = observation[key]
    return report


def judged_ok(rows):
    allowed = {"pass", "unknown"}
    return all(r["outcome"] in allowed and
               (r["oracle_class"] == "unknown" or r["outcome"] == "pass")
               for r in rows)


def negative_control(spec, results):
    """Perturb one documented expectation and require exactly that case to fail."""
    flipped = json.loads(json.dumps(spec))
    target = next((c for c in flipped["cases"] if c["oracle_class"] in ("documented", "documented-conflicted") and
                   c.get("kind") == "pcm_frequency"), None)
    if target is None:
        target = next((c for c in flipped["cases"] if c["oracle_class"] in ("documented", "documented-conflicted", "guest-source-derived-arithmetic") and
                       c.get("kind") == "trace" and "spacing_ticks" in c), None)
    if target is None:
        target = next((c for c in flipped["cases"] if c["oracle_class"] in ("documented", "documented-conflicted") and
                       c.get("kind", "ram") == "ram"), None)
    if target is None:
        reject("no documented case for the negative control")
    if target.get("kind") == "pcm_frequency":
        target["expected_hz"] *= 1.05
        expected_reason = "pcm expectation mismatch"
    elif target.get("kind") == "trace" and "spacing_ticks" in target:
        target["spacing_ticks"]["ticks"] += 1
        expected_reason = "trace spacing differs"
    else:
        data = bytearray.fromhex(target["expected"])
        mask = bytes.fromhex(target["mask"]) if "mask" in target else b"\xff" * len(data)
        index = next((i for i, m in enumerate(mask) if m), None)
        if index is None:
            reject("negative-control target has an empty mask")
        data[index] ^= mask[index]
        target["expected"] = data.hex()
        expected_reason = "mismatch"
    clean = evaluate(spec, results)
    rows = evaluate(flipped, results)
    failed = [r["id"] for r in rows if r["outcome"] == "fail"]
    others_same = all(a["outcome"] == b["outcome"] for a, b in zip(clean, rows) if a["id"] != target["id"])
    mismatch = next(r for r in rows if r["id"] == target["id"]).get("reason") == expected_reason
    good = (judged_ok(clean) and failed == [target["id"]] and mismatch and others_same and
            all(e is None for _, e in results.values()))
    names = [target["id"]]
    # Preserve the original rule and inject a reversed guest observation. This
    # exercises actual rejection of 0...1, rather than changing the rule to pass it.
    for case in spec["cases"]:
        if case.get("kind") != "ram_bit_sequence" or case["oracle_class"] == "unknown":
            continue
        observation, error = results[case["run"]]
        if error is not None:
            return False, case["id"]
        ram = bytearray(observation["ram"])
        start = case["offset"] - spec["ram_offset"]
        count_at = case["count_offset"] - spec["ram_offset"]
        count = int.from_bytes(ram[count_at:count_at + 2], "big")
        if not 2 <= count <= case["length"]:
            return False, case["id"]
        ram[start] &= ~(1 << case["bit"])
        ram[start + count - 1] |= 1 << case["bit"]
        changed = dict(results)
        changed[case["run"]] = (dict(observation, ram=bytes(ram)), None)
        rejected = evaluate(spec, changed)
        good = good and [r["id"] for r in rejected if r["outcome"] == "fail"] == [case["id"]]
        good = good and next(r for r in rejected if r["id"] == case["id"]).get("reason") == "bit sequence pattern mismatch"
        names.append(case["id"])
    return good, ", ".join(names)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runner")
    parser.add_argument("--rom")
    parser.add_argument("--expect")
    parser.add_argument("--report")
    parser.add_argument("--trace-output")
    parser.add_argument("--negative-control", action="store_true")
    parser.add_argument("--compare", nargs=2)
    args = parser.parse_args()
    if args.compare:
        try:
            a, b = [json.loads(pathlib.Path(path).read_text()) for path in args.compare]
        except (OSError, ValueError):
            reject("unreadable repeat reports")
        good = a == b and a.get("audio_sha256") and a.get("trace_sha256")
        print("seam repeat comparison: %s" % ("PASS" if good else "FAIL"))
        return 0 if good else 1
    if not args.runner or not args.rom or not args.expect:
        reject("runner, ROM and expectation file are required")
    spec = load_expectations(args.expect)
    results = {run["id"]: run_runner(args.runner, args.rom, spec, run, args.trace_output)
               for run in spec["runs"]}
    if args.negative_control:
        good, case_id = negative_control(spec, results)
        print("seam negative control: %s (%s)" % ("PASS" if good else "FAIL", case_id))
        return 0 if good else 1
    rows = evaluate(spec, results)
    report = summarize(spec, results, rows)
    first_observation = results[spec["runs"][0]["id"]][0]
    if first_observation is not None:
        if "audio" in first_observation:
            report["audio_sha256"] = hashlib.sha256(first_observation["audio"]).hexdigest()
        if "trace" in first_observation:
            report["trace_sha256"] = hashlib.sha256(json.dumps(first_observation["trace"],
                sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if args.report:
        pathlib.Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    for row in rows:
        print("%-12s %-11s %s%s" % (row["outcome"], row["oracle_class"], row["id"],
              " (%s)" % row["reason"] if "reason" in row else ""))
    print("seam %s: denominator %d, %s" % (spec.get("seam"), report["denominator"],
          ", ".join("%s %d" % (n, c) for n, c in report["counts"].items())))
    return 0 if judged_ok(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
