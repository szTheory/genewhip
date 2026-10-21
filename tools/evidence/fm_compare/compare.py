#!/usr/bin/env python3
"""Offline three-adapter YM2612 comparison; reference sources stay in build/audio-refs."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
HERE = pathlib.Path(__file__).resolve().parent
LOCK_PATH = HERE / "refs.lock.json"
LOCK = json.loads(LOCK_PATH.read_text())
REFS = ROOT / "build/audio-refs"
BIN = REFS / "bin"
SCRIPTS = {
    "fm_script.bin": (60_000_000, 62),
    "dac.bin": (2_000_000, 257),
}
VARIANT = "YM2612 discrete, VA3 Model 1"
SOURCE_URL = "https://i.imgur.com/wrmj9Pa.jpg"
SOURCE_SHA = "61f923b534fe0d46e23a4e124e093ced09252ee4fcfa1911d8957bbee375ddb5"


class EvidenceError(Exception):
    pass


def visible_skip(reason):
    print(f"SKIP: {reason}", file=sys.stderr)
    raise SystemExit(77)


def need_adapters(names):
    missing = [str(BIN / name) for name in names if not (BIN / name).is_file()]
    if missing:
        visible_skip("fm refs absent (run compare.py --fetch --build)")
    if not shutil_which(os.environ.get("CXX", "c++")):
        visible_skip("C++ compiler absent (required for pinned ymfm adapter)")


def shutil_which(name):
    from shutil import which
    return which(name)


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def child_environment(build_tools=False):
    """Small environment for adapters and the pinned reference build.

    Adapters get path/locale/temp/platform essentials. The build additionally
    gets explicit compiler and Apple SDK selectors; credentials and arbitrary
    caller variables are never forwarded.
    """
    allowed = ("PATH", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "WINDIR")
    env = {name: os.environ[name] for name in allowed if name in os.environ}
    env["LC_ALL"] = "C"
    if build_tools:
        for name in ("CC", "CXX", "SDKROOT", "DEVELOPER_DIR", "MACOSX_DEPLOYMENT_TARGET"):
            if name in os.environ:
                env[name] = os.environ[name]
    return env


def capture(seam_runner, directory):
    outputs = {}
    for name, (ticks, expected_count) in SCRIPTS.items():
        trace = directory / (name + ".jsonl")
        rom = ROOT / "tests/devices/roms" / name
        run([seam_runner, str(rom), str(ticks), "0", "1", "--dump-audio-trace", str(trace)],
            stdout=subprocess.DEVNULL)
        records = []
        for line_no, line in enumerate(trace.read_text().splitlines(), 1):
            item = json.loads(line)
            if item["chip"] in (1, 2):
                records.append((int(item["tick"]), int(item["reg"]), int(item["value"])))
        if len(records) != expected_count:
            raise EvidenceError(f"{name}: expected {expected_count} YM writes, captured {len(records)}")
        if records != sorted(records, key=lambda r: r[0]):
            raise EvidenceError(f"{name}: YM trace timestamps are not ordered")
        path = directory / (name + ".tsv")
        path.write_text("".join(f"{t} {reg} {value}\n" for t, reg, value in records))
        outputs[name] = {"records": records, "path": path, "max_tick": max(r[0] for r in records)}
    return outputs


def run_adapter(exe, trace, directory, port_runner=None):
    binary = pathlib.Path(port_runner) if exe == "port_replay" else BIN / exe
    proc = run([str(binary), str(trace)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
               env=child_environment())
    samples = []
    for line_no, line in enumerate(proc.stdout.splitlines(), 1):
        fields = line.split()
        if len(fields) != 4:
            raise EvidenceError(f"{exe}: malformed sample row {line_no}")
        samples.append(tuple(map(int, fields)))
    if not samples or any(row[0] != i + 1 for i, row in enumerate(samples)):
        raise EvidenceError(f"{exe}: missing or non-contiguous native samples")
    return samples


def assert_audible_fm_script(samples, name):
    if name != "fm_script.bin":
        return None
    values = [value for row in samples for value in row[1:3]]
    span = max(values) - min(values)
    unique = len(set(values))
    if span < 1000 or unique < 8:
        raise EvidenceError(f"fm_script.bin is not meaningfully audible: PCM span={span}, unique_values={unique}")
    return {"pcm_min": min(values), "pcm_max": max(values), "pcm_span": span,
            "unique_pcm_values": unique}


def check_fidelity(seam_runner, directory, port_runner):
    traces = capture(seam_runner, directory)
    report = {"schema": "genewhip-fm-fidelity", "version": 1,
              "ymfm_commit": LOCK["ymfm"]["commit"], "scripts": {}}
    for name, data in traces.items():
        port = run_adapter("port_replay", data["path"], directory, port_runner)
        activity = assert_audible_fm_script(port, name)
        ymfm = run_adapter("ymfm_replay", data["path"], directory)
        if len(port) != len(ymfm):
            raise EvidenceError(f"{name}: fidelity denominator mismatch {len(port)} != {len(ymfm)}")
        first = next((i for i, (a, b) in enumerate(zip(port, ymfm)) if a != b), None)
        if first is not None:
            raise EvidenceError(f"{name}: port/ymfm first mismatch sample={first + 1} port={port[first]} ymfm={ymfm[first]}")
        report["scripts"][name] = {"writes": len(data["records"]), "samples": len(port),
                                    "exact_samples": len(port), "first_mismatch": None}
        if activity:
            report["scripts"][name]["audible_activity"] = activity
        print(f"fidelity: PASS {name} {len(port)} samples (writes={len(data['records'])})")
    return report


def calibration_trace(directory):
    rows = []
    # A single channel-zero key-on, one DAC-enable write, then one DAC-data write.
    setup = [(0x30, 1), (0x40, 0), (0x50, 31), (0x60, 8), (0x70, 4),
             (0x80, 0x0f), (0x90, 0), (0xa4, 0x22), (0xa0, 0x69),
             (0xb0, 7), (0xb4, 0xc0), (0x28, 0xf0)]
    # Leave > one 24-slot Nuked frame between setup writes. This is calibration
    # evidence, not an emulation-time sequence; real traces retain their ticks.
    tick = 1200
    for reg, value in setup:
        rows.append((tick, reg, value)); tick += 1008
    rows.extend([(tick, 0x2b, 0x80), (tick + 1008, 0x2a, 0xff),
                 (tick + 250_000, 0x22, 0)])  # disabled-LFO no-op anchors a useful calibration window
    path = directory / "calibration.tsv"
    path.write_text("".join(f"{t} {r} {v}\n" for t, r, v in rows))
    return path


def choose_alignment(port, nuked):
    candidates = []
    for offset in range(-8, 9):
        pairs = [(port[i], nuked[i + offset]) for i in range(len(port))
                 if 0 <= i + offset < len(nuked) and i > 2]
        energy = sum(abs(a[1]) + abs(a[2]) for a, _ in pairs)
        if energy == 0:
            continue
        error = sum(abs(a[1] - b[1]) + abs(a[2] - b[2]) for a, b in pairs)
        candidates.append((error, abs(offset), offset, len(pairs)))
    if not candidates:
        raise EvidenceError("calibration produced no non-silent samples")
    best = min(candidates)
    return {"nuked_index_offset": best[2], "l1_error": best[0], "paired_samples": best[3],
            "search": "integer offset -8..+8; minimum absolute L/R error over all non-leading native samples; ties prefer smallest absolute offset"}


def calibrate(directory, port_runner):
    path = calibration_trace(directory)
    port = run_adapter("port_replay", path, directory, port_runner)
    ymfm = run_adapter("ymfm_replay", path, directory)
    nuked = run_adapter("nuked_replay", path, directory)
    if len(port) != len(ymfm) or port != ymfm:
        raise EvidenceError("calibration port/ymfm fidelity failed")
    # Align key-on onset against each adapter's pre-event baseline. A global
    # least-error fit is invalid here: a large amplitude mismatch overwhelms
    # the temporal signal and can drive the fit to a search boundary.
    baseline_count = min(12, len(port), len(nuked))
    pbase = tuple(round(sum(row[c] for row in port[:baseline_count]) / baseline_count) for c in (1, 2))
    nbase = tuple(round(sum(row[c] for row in nuked[:baseline_count]) / baseline_count) for c in (1, 2))
    def onset(rows, base):
        for index, row in enumerate(rows, 1):
            if max(abs(row[1] - base[0]), abs(row[2] - base[1])) > max(4, 4 * max(abs(x) for x in base)):
                return index
        raise EvidenceError("calibration did not produce a measurable key-on onset")
    p_onset, n_onset = onset(port, pbase), onset(nuked, nbase)
    offset = n_onset - p_onset
    active = [(port[i], nuked[i + offset]) for i in range(max(p_onset - 1, 0), len(port))
              if 0 <= i + offset < len(nuked)]
    p_mean = sum((abs(a[1]) + abs(a[2])) / 2 for a, _ in active) / max(1, len(active))
    n_mean = sum((abs(b[1]) + abs(b[2])) / 2 for _, b in active) / max(1, len(active))
    result = {"nuked_index_offset": offset, "alignment_method": "first key-on sample exceeding 4x its pre-event baseline (minimum 4 LSB), paired from a single-key-on calibration; no waveform-fit search",
              "port_keyon_onset_sample": p_onset, "nuked_keyon_onset_sample": n_onset,
              "port_baseline": list(pbase), "nuked_baseline": list(nbase),
              "active_mean_abs_port": round(p_mean, 3), "active_mean_abs_nuked_after_source_derived_rational": round(n_mean, 3),
              "port_to_nuked_amplitude_ratio": round(p_mean / n_mean, 3) if n_mean else None,
              "l1_error_diagnostic_only": choose_alignment(port, nuked)["l1_error"],
              "paired_samples": len(active)}
    result["port_ymfm_exact_samples"] = len(port)
    print("calibration: " + json.dumps(result, sort_keys=True))
    return result


def model_compare(seam_runner, directory, ledger_path, alignment=None, variant_source=None,
                  write_ledger=True, input_override=None, port_runner=None):
    traces = capture(seam_runner, directory)
    tolerance_path = HERE / "tolerance.json"
    tolerance = json.loads(tolerance_path.read_text())
    offset = int(alignment["nuked_index_offset"] if alignment else tolerance["alignment"]["nuked_index_offset"])
    report = {"schema": "genewhip-fm-model-report", "version": 1,
              "variant": VARIANT, "variant_source": {"url": SOURCE_URL, "sha256": SOURCE_SHA},
              "nuked_commit": LOCK["nuked"]["commit"], "ymfm_commit": LOCK["ymfm"]["commit"],
              "nuked_chip_type": "ym3438_mode_ym2612", "readmode": "unset",
              "step_mapping": "floor(tick/42); 24 Nuked steps per 1008-tick FM sample",
              "normalization": "six valid Nuked multiplex slots: sum raw mol/mor and multiply by exact ymfm output-stage rational 8192/1170 (raw x3 scale, six-channel sum-to-average, then 128*64/(6*65)); truncating toward zero",
              "alignment": tolerance["alignment"], "scripts": {}}
    ledger = {"schema": "genewhip-fm-ledger", "version": 1, "variant": VARIANT,
              "variant_source": report["variant_source"], "nuked": {"commit": LOCK["nuked"]["commit"],
                  "license": LOCK["nuked"]["license"], "chip_type": "ym3438_mode_ym2612", "readmode": "unset"},
              "ymfm": {"commit": LOCK["ymfm"]["commit"], "license": LOCK["ymfm"]["license"]},
              "tolerance_file_git_blob": subprocess.check_output(["git", "hash-object", str(tolerance_path)], cwd=ROOT, text=True).strip(),
              "reset_coverage": "Trace is write-only and contains no guest reset/release events. Both adapters start from a cold chip at tick 0 with the YM released; guest reset timing is excluded.",
              "timer_coverage": "Port and ymfm timer/status callbacks are advanced to native-sample boundaries; Nuked status is sampled at the same boundaries.",
              "scripts": {}, "skipped": [], "unknown": ["Envelope/phase internals are not compared: the adapters do not expose equivalent stable state fields."]}
    all_status_mismatches = []
    for name, data in traces.items():
        port = run_adapter("port_replay", data["path"], directory, port_runner)
        activity = assert_audible_fm_script(port, name)
        nuked = run_adapter("nuked_replay", data["path"], directory)
        dac_samples = set()
        if name == "dac.bin":
            for tick, reg, _ in data["records"]:
                if reg in (0x2a, 0x2b, 0x2c):
                    event_sample = max(1, (tick + 1007) // 1008)
                    dac_samples.update(range(max(1, event_sample - 1), event_sample + 2))
        counts = {"exact": 0, "within_lsb": 0, "dac-discontinuity": 0, "deviating": 0, "unknown_alignment": 0}
        deviations = []
        status = []
        n_lsb = int(tolerance["classes"]["within_lsb"]["n"])
        for index, p in enumerate(port, 1):
            ni = index + offset
            if not 1 <= ni <= len(nuked):
                counts["unknown_alignment"] += 1
                continue
            q = nuked[ni - 1]
            dl, dr = p[1] - q[1], p[2] - q[2]
            error = max(abs(dl), abs(dr))
            if error == 0:
                cls = "exact"
            elif error <= n_lsb:
                cls = "within_lsb"
            elif index in dac_samples:
                cls = "dac-discontinuity"
            else:
                cls = "deviating"
            if cls != "exact":
                deviations.append([index, p[1], p[2], q[1], q[2], tolerance["classes"][cls]["code"]])
            counts[cls] += 1
            if p[3] != q[3]:
                status.append([name, index, p[3], q[3]])
        all_status_mismatches.extend(status)
        script_report = {"writes": len(data["records"]), "port_samples": len(port),
                         "nuked_samples": len(nuked), "paired_samples": sum(counts.values()) - counts["unknown_alignment"],
                         "classes": counts, "status_transition_mismatches": len(status),
                         "dac_discontinuity_samples": len(dac_samples),
                         "port_samples_changed_from_initial_output": sum(1 for row in port[1:] if row[1:3] != port[0][1:3]),
                         "nuked_samples_changed_from_initial_output": sum(1 for row in nuked[1:] if row[1:3] != nuked[0][1:3])}
        if activity:
            script_report["audible_activity"] = activity
        report["scripts"][name] = script_report
        ledger["scripts"][name] = {**script_report, "differences": deviations,
                                    "status_mismatches": status}
    ledger["status_mismatches"] = all_status_mismatches
    report["ledger_sha256"] = None
    report_bytes = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    if write_ledger:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        ledger_bytes = (json.dumps(ledger, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(ledger_bytes) > 2 * 1024 * 1024:
            raise EvidenceError(f"ledger exceeds 2 MiB: {len(ledger_bytes)} bytes; stop for scope decision")
        ledger_path.write_bytes(ledger_bytes)
        report["ledger_sha256"] = hashlib.sha256(ledger_bytes).hexdigest()
        report_bytes = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    return report_bytes, ledger if write_ledger else None


def check_tolerance_precedes_ledger():
    commits = {}
    for name in ("tools/evidence/fm_compare/tolerance.json", "evidence/fm-deviation-ledger.json"):
        raw = subprocess.run(["git", "rev-list", "--reverse", "HEAD", "--", name], cwd=ROOT,
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if raw.returncode != 0:
            raise EvidenceError(f"git rev-list failed for {name}: {raw.stderr.strip()}")
        history = raw.stdout.splitlines()
        if not history:
            raise EvidenceError(f"no committed history for {name}")
        commits[name] = history[0]
    result = subprocess.run(["git", "merge-base", "--is-ancestor", commits["tools/evidence/fm_compare/tolerance.json"],
                             commits["evidence/fm-deviation-ledger.json"]], cwd=ROOT)
    if result.returncode != 0:
        raise EvidenceError("first tolerance commit is not an ancestor of first ledger commit")
    print("tolerance-precedence: PASS " + commits["tools/evidence/fm_compare/tolerance.json"][:7] + " < " + commits["evidence/fm-deviation-ledger.json"][:7])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--check-tolerance-precedes-ledger", action="store_true")
    parser.add_argument("--fidelity", action="store_true")
    parser.add_argument("--model", action="store_true")
    parser.add_argument("--calibrate", action="store_true")
    parser.add_argument("--negative-control", action="store_true")
    parser.add_argument("--repeat", action="store_true")
    parser.add_argument("--seam-runner")
    parser.add_argument("--port-runner")
    parser.add_argument("--report")
    parser.add_argument("--ledger", default=str(ROOT / "evidence/fm-deviation-ledger.json"))
    args = parser.parse_args()
    try:
        if args.fetch or args.build:
            run(["bash", str(HERE / "build_refs.sh")], env=child_environment(build_tools=True))
        if args.check_tolerance_precedes_ledger:
            check_tolerance_precedes_ledger(); return 0
        if not any((args.fidelity, args.model, args.calibrate, args.negative_control, args.repeat)):
            return 0
        if not args.seam_runner and (args.fidelity or args.model or args.repeat):
            raise EvidenceError("--seam-runner is required for guest trace replay")
        if (args.fidelity or args.model or args.calibrate or args.repeat or args.negative_control) and not args.port_runner:
            raise EvidenceError("--port-runner is required for C17 port replay")
        if args.port_runner and not pathlib.Path(args.port_runner).is_file():
            raise EvidenceError(f"C17 port replay binary missing: {args.port_runner}")
        need_adapters(["ymfm_replay"] + (["nuked_replay"] if args.model or args.calibrate or args.repeat or args.negative_control else []))
        with tempfile.TemporaryDirectory(prefix="gw-fm-compare-") as tmp:
            directory = pathlib.Path(tmp)
            if args.calibrate:
                calibrate(directory, args.port_runner); return 0
            if args.repeat:
                snapshots = []
                for repeat in range(2):
                    tmp_report = directory / f"report-{repeat}.json"
                    tmp_ledger = directory / f"ledger-{repeat}.json"
                    fidelity = check_fidelity(args.seam_runner, directory, args.port_runner)
                    model_bytes, ledger = model_compare(args.seam_runner, directory, tmp_ledger, port_runner=args.port_runner)
                    payload = {"fidelity": fidelity, "model": json.loads(model_bytes)}
                    tmp_report.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
                    snapshots.append((tmp_report.read_bytes(), tmp_ledger.read_bytes()))
                if snapshots[0] != snapshots[1]: raise EvidenceError("repeat report or ledger differs byte-for-byte")
                print("repeat: PASS byte-identical fidelity/model reports and ledger")
                return 0
            if args.fidelity:
                report = check_fidelity(args.seam_runner, directory, args.port_runner)
                if args.report: pathlib.Path(args.report).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
            if args.model:
                report_bytes, ledger = model_compare(args.seam_runner, directory, pathlib.Path(args.ledger), port_runner=args.port_runner)
                pathlib.Path(args.report).write_bytes(report_bytes) if args.report else None
                for name, data in ledger["scripts"].items():
                    print(f"model: {name} variant={VARIANT} samples={data['port_samples']} classes={json.dumps(data['classes'], sort_keys=True)} status_mismatches={data['status_transition_mismatches']}")
                print(f"ledger: {args.ledger} bytes={pathlib.Path(args.ledger).stat().st_size}")
            if args.negative_control:
                traces = capture(args.seam_runner, directory)
                records = traces["fm_script.bin"]["records"]
                target = next((i for i, r in enumerate(records) if r[1] == 0x40), None)
                if target is None: raise EvidenceError("negative control found no total-level register write")
                tick, reg, value = records[target]
                changed = records.copy(); changed[target] = (tick, reg, value ^ 0x7f)
                trace = directory / "negative.tsv"
                trace.write_text("".join(f"{t} {r} {v}\n" for t, r, v in changed))
                original_trace = directory / "original.tsv"
                original_trace.write_text("".join(f"{t} {r} {v}\n" for t, r, v in records))
                original_port = run_adapter("port_replay", original_trace, directory, args.port_runner)
                noop_port = run_adapter("port_replay", original_trace, directory, args.port_runner)
                noop_changed = sum(1 for base, noop in zip(original_port, noop_port)
                                   if (base[1], base[2]) != (noop[1], noop[2]))
                fm_mutated = run_adapter("port_replay", trace, directory, args.port_runner)
                fm_tl_delta = sum(1 for base, mutated in zip(original_port, fm_mutated)
                                  if (base[1], base[2]) != (mutated[1], mutated[2]))

                # The official fixture itself must make the TL mutation
                # observable. The independent calibration remains supplemental.
                cal = calibration_trace(directory)
                cal_rows = [tuple(map(int, line.split())) for line in cal.read_text().splitlines()]
                cal_base = run_adapter("port_replay", cal, directory, args.port_runner)
                cal_tl_index = next((i for i, row in enumerate(cal_rows) if row[1] == 0x40), None)
                if cal_tl_index is None: raise EvidenceError("calibration TL mutation found no 0x40 write")
                cal_rows[cal_tl_index] = (cal_rows[cal_tl_index][0], 0x40, cal_rows[cal_tl_index][2] ^ 0x7f)
                cal_mutant = directory / "calibration-mutant.tsv"
                cal_mutant.write_text("".join(f"{t} {r} {v}\n" for t, r, v in cal_rows))
                cal_changed = run_adapter("port_replay", cal_mutant, directory, args.port_runner)
                cal_tl_delta = sum(1 for base, mutated in zip(cal_base, cal_changed)
                                   if (base[1], base[2]) != (mutated[1], mutated[2]))

                timer_index = next((i for i, row in enumerate(records) if row[1] == 0x27), None)
                if timer_index is None: raise EvidenceError("fm_script timer mutation found no 0x27 write")
                timer_rows = records.copy()
                t, r, v = timer_rows[timer_index]
                timer_rows[timer_index] = (t, r, v ^ 0x43)
                timer_trace = directory / "timer-mutant.tsv"
                timer_trace.write_text("".join(f"{t} {r} {v}\n" for t, r, v in timer_rows))
                timer_mutant = run_adapter("port_replay", timer_trace, directory, args.port_runner)
                timer_status_delta = sum(1 for base, mutated in zip(original_port, timer_mutant) if base[3] != mutated[3])
                if noop_changed != 0 or fm_tl_delta == 0 or cal_tl_delta == 0 or timer_status_delta == 0:
                    raise EvidenceError("negative control failed: no-op rejection, official fm_script TL sample delta, calibration TL sample delta, or timer-status delta check failed")
                print(f"negative-control: PASS named_check=fm_script_TL_changes_output_samples fm_script_tl_reg=0x{reg:03x} fm_script_tl_audio_samples_changed={fm_tl_delta}; calibration_tl_samples_changed={cal_tl_delta}; fm_script_timer_status_samples_changed={timer_status_delta}; noop_samples_changed={noop_changed}")
        return 0
    except EvidenceError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
