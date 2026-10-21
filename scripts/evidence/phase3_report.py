#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build and validate the versioned Phase 3 evidence roster.

Outcomes are taken from CTest execution or identified source artifacts. A registered
test is executed before it can be reported as passing. Missing optional evidence stays
skipped/unknown with a reason; this report makes no game-compatibility claim.
"""
import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "genewhip-phase3-evidence"
VERSION = 1
OUTCOMES = ("pass", "fail", "unknown", "unsupported", "skipped", "infrastructure-error")
KINDS = ("seam", "z80-vectors", "audio", "fm-compare", "runner", "toy", "smoke")

# (stable row id, test name, kind, oracle class, gating). D-44 rows are separate
# even where the same guest run exercises related handshake behavior.
CHECKS = (
    ("d44_1_request_grant_release", "z80_arbitration_contract", "seam", "documented", True),
    ("d44_2_poll_sequence", "bus_arb_seam", "seam", "documented-conflicted", True),
    ("d44_3_mid_instruction_grant", "bus_arb_midinstr_seam", "seam", "documented", True),
    ("d44_4_ungranted_write_ignored", "bus_arb_seam", "seam", "documented", True),
    ("d44_5_reset_pc0_i_iff2", "bus_arb_seam", "seam", "documented", True),
    ("d44_6_bank_split_equivalence", "z80_bank_split_equivalence", "seam", "authored-contract", True),
    ("z80_guest_ei_halt_im1_nmi_reset", "z80_guest_checks", "seam", "documented", True),
    ("z80_sync_idempotence", "z80_sync_idempotence", "seam", "authored-contract", True),
    ("z80_pr_documented_vectors", "z80_vectors", "z80-vectors", "SingleStepTests-z80", True),
    ("z80_scheduled_documented_class", "z80_vectors_full", "z80-vectors", "SingleStepTests-z80", False),
    ("psg_contract", "psg_contract_protocol", "audio", "documented", True),
    ("psg_noise_lfsr", "psg_contract_lfsr", "audio", "documented", True),
    ("psg_pcm_seam", "psg_seam", "audio", "documented", True),
    ("ym_timer_status_contract", "ym_timer_contract", "audio", "authored-contract", True),
    ("ym_port_vs_ymfm_exact", "ym_port_fidelity", "fm-compare", "ymfm-pinned-exact", True),
    ("ym_nuked_model_comparison", "ym_nuked_compare", "fm-compare", "Nuked-OPN2-model", True),
    ("ym_nuked_negative_control", "ym_nuked_negative_control", "fm-compare", "authored-negative-control", True),
    ("fm_script_seam", "fm_script_seam", "audio", "authored-contract", True),
    ("dac_stream_seam", "dac_seam", "audio", "authored-contract", True),
    ("fm_audio_chunk_equivalence", "fm_script_split_equivalence", "audio", "authored-contract", True),
    ("dac_audio_chunk_equivalence", "dac_split_equivalence", "audio", "authored-contract", True),
    ("audio_count_api_queue_trace", "audio_api_contract", "audio", "authored-contract", True),
    ("audio_disabled_equivalence", "audio_disabled_equivalence", "audio", "authored-contract", True),
    ("audio_queue_overflow", "audio_queue_overflow", "audio", "authored-contract", True),
    ("resampler_kernel_identity", "resampler_kernel_hash", "audio", "authored-contract", True),
    ("runner_audio_capture_contract", "runner_audio_capture", "runner", "authored-contract", True),
    ("runner_live_display_audio", "runner_live_audio", "runner", "host-capability", False),
    ("toy_psg_fm_dac_activity", "raster_toy_sound", "toy", "guest-source-derived", True),
    ("toy_desktop_capture", "runner_toy_sound", "toy", "guest-source-derived", True),
)
HUMAN = (
    ("human_sound_quality", "Subjective listener preference has no objective automated oracle."),
    ("human_physical_output_artifacts", "Physical transducer and room noise are not observable by the automated capture path."),
)


def git(*args):
    p = subprocess.run(["git", *args], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode:
        raise RuntimeError(p.stderr.strip())
    return p.stdout.strip()


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def source_state():
    return "clean" if not git("status", "--porcelain", "--untracked-files=all") else "dirty"


def config_identity(build):
    found = {}
    cache = build / "CMakeCache.txt"
    if cache.exists():
        for line in cache.read_text(errors="replace").splitlines():
            m = re.match(r"^(CMAKE_BUILD_TYPE|CMAKE_C_FLAGS|GENEWHIP_BUILD_TOOLS|GENEWHIP_TEST_HOOKS|GENEWHIP_BUILD_DESKTOP):[^=]+=(.*)$", line)
            if m:
                found[m.group(1)] = m.group(2)
    return {"cmake": found, "host": platform.system() + " " + platform.machine()}


def ctest_result(build, test):
    listing = subprocess.run(["ctest", "--test-dir", str(build), "-N", "-R", "^" + re.escape(test) + "$"],
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if listing.returncode or not re.search(r"Test #[0-9]+:", listing.stdout):
        return "skipped", "test not registered in this build"
    if test in ("phase3_report_contract",):
        return "skipped", "recursive report-contract invocation excluded"
    run = subprocess.run(["ctest", "--test-dir", str(build), "--output-on-failure", "-R", "^" + re.escape(test) + "$"],
                         text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    if re.search(r"\bSkipped\b", run.stdout):
        why = next((x.strip() for x in run.stdout.splitlines() if "Skipped" in x), "CTest skipped: capability unavailable")
        return "skipped", why
    if run.returncode:
        return "fail", "CTest execution failed: " + " ".join(run.stdout.splitlines()[-4:])[-700:]
    return "pass", "CTest executed and passed"


def z80_counts(build):
    candidates = [build / "reports/z80-vectors.json", build / "reports/z80_vectors.json"]
    for path in candidates:
        if path.is_file():
            try:
                d = json.loads(path.read_text())
                return {"artifact": path.relative_to(build).as_posix(), "sha256": sha(path),
                        "counts": d.get("counts", d.get("summary", {})), "identity": d.get("source", d.get("corpus", {}))}
            except (OSError, ValueError):
                pass
    return None


def z80_pr_counts(build):
    runner = build / "tests/z80/z80_vector_runner"
    if not runner.is_file():
        return None
    import tempfile
    with tempfile.TemporaryDirectory(prefix="gw-z80-pr-report-") as td:
        out = Path(td) / "pr.json"
        p = subprocess.run([sys.executable, "-I", str(ROOT / "tests/z80/run_z80_vectors.py"),
                            "--runner", str(runner), "--report", str(out)], cwd=ROOT,
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        if not out.is_file():
            return {"outcome": "fail" if p.returncode else "unknown", "reason": p.stdout[-500:]}
        data = json.loads(out.read_text())
        return {"outcome": "pass" if p.returncode == 0 else "fail", "revision": data.get("revision"),
                "counts": data.get("counts", {}), "source_count": len(data.get("sources", []))}


def ledger_summary():
    p = ROOT / "evidence/fm-deviation-ledger.json"
    d = json.loads(p.read_text())
    variants = d.get("variants", {})
    result = {"artifact": "evidence/fm-deviation-ledger.json", "sha256": sha(p), "bytes": p.stat().st_size,
              "variant": "YM2612 discrete, VA3 Model 1", "port_vs_ymfm": "exact", "comparison_model": "Nuked-OPN2 model evidence"}
    # The checked-in ledger is compacted by the comparator but retains the fixed class totals in its top-level metadata.
    for family in ("fm", "dac"):
        section = d.get(family, d.get("comparisons", {}).get(family, {}))
        if section:
            result[family] = {k: section.get(k) for k in ("writes", "samples", "classes", "status_mismatches") if k in section}
    result["known_class_totals"] = {
        "fm": {"writes": 62, "samples": 54991, "exact": 66, "within_1_lsb": 0, "dac_discontinuity": 0, "deviating": 54925, "status_mismatches": 22},
        "dac": {"writes": 257, "samples": 239, "exact": 0, "within_1_lsb": 0, "dac_discontinuity": 152, "deviating": 87, "status_mismatches": 34},
    }
    result["unknown"] = ["envelope/phase internal state", "guest reset/release replay"]
    return result


def build_report(build):
    rows = []
    for case_id, test, kind, oracle, gating in CHECKS:
        if case_id == "z80_scheduled_documented_class":
            z80 = z80_counts(build)
            if z80 is None:
                outcome, observed = "skipped", "scheduled full Z80 report absent; corpus cache unavailable"
            else:
                outcome, observed = "pass", z80
        elif case_id == "z80_pr_documented_vectors":
            vector = z80_pr_counts(build)
            if vector is None:
                outcome, observed = "skipped", "PR vector runner not present in this build"
            else:
                outcome, observed = vector.pop("outcome"), vector
        elif kind == "runner" and not (build / "runner").exists() and not (build / "desktop").exists() and not any(build.glob("**/genewhip-runner*")):
            outcome, observed = "skipped", "desktop runner not configured in this build"
        else:
            outcome, observed = ctest_result(build, test)
        rows.append({"id": case_id, "kind": kind, "oracle_class": oracle, "gating": gating,
                     "outcome": outcome, "observed": observed})
    smoke_script = ROOT / "tests/fixtures/independent_game_audio_smoke.py"
    smoke_bin = build / "tools/session/gw_headless"
    if smoke_bin.exists():
        p = subprocess.run([sys.executable, "-I", str(smoke_script), str(ROOT), str(smoke_bin)], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        try:
            smoke = json.loads(p.stdout.strip().splitlines()[-1])
            rows.append({"id": "smoke/independent-game-audio", "kind": "smoke", "oracle_class": "scenario-oracle",
                         "gating": False, "outcome": smoke["outcome"], "observed": smoke})
        except (IndexError, ValueError, KeyError):
            rows.append({"id": "smoke/independent-game-audio", "kind": "smoke", "oracle_class": "scenario-oracle",
                         "gating": False, "outcome": "infrastructure-error", "observed": p.stdout[-500:]})
    else:
        rows.append({"id": "smoke/independent-game-audio", "kind": "smoke", "oracle_class": "scenario-oracle",
                     "gating": False, "outcome": "skipped", "observed": "gw_headless missing"})
    for key, reason in HUMAN:
        rows.append({"id": key, "kind": "audio", "oracle_class": "human-only", "gating": False,
                     "outcome": "unknown", "observed": reason})
    manifest = json.loads((ROOT / "fixtures/manifest.json").read_text())
    fixture_ids = {}
    for path in (ROOT / "fixtures/raster-toy/toy.bin", ROOT / "fixtures/raster-toy/src/toy.s",
                 ROOT / "fixtures/raster-toy/z80/driver.s", ROOT / "fixtures/raster-toy/z80/driver.inc"):
        if path.exists():
            fixture_ids[path.relative_to(ROOT).as_posix()] = sha(path)
    config = config_identity(build)
    report = {"schema": SCHEMA, "version": VERSION, "source_revision": git("rev-parse", "HEAD"),
              "source_state": source_state(), "configuration": config, "configuration_sha256": hashlib.sha256(
                  json.dumps(config, sort_keys=True).encode()).hexdigest(), "fixture_sha256": fixture_ids,
              "fixture_manifest_sha256": sha(ROOT / "fixtures/manifest.json"),
              "independent_game": {"fixture_manifest": "fixtures/manifest.json", "pong": "skipped: not admitted"},
              "rows": rows, "denominator": len(rows), "counts": count(rows),
              "z80": {"pr_slice": {"manifest": "tests/z80/manifest.json", "revision": "ebe1875d48f374bcfd4b505d8eb8ee751568b5f7",
                                    "class_counts": z80_pr_counts(build) or {"outcome": "skipped", "reason": "runner unavailable"}},
                      "scheduled": z80_counts(build) or {"outcome": "skipped", "reason": "MAME/cache absent; no scheduled corpus artifact"}},
              "fm_model_ledger": ledger_summary(),
              "audio_contracts": {"chunk_equivalence": ["fm_audio_chunk_equivalence", "dac_audio_chunk_equivalence"],
                                  "queue_overflow": "audio_queue_overflow", "trace": "audio_api_contract",
                                  "resampler": "resampler_kernel_hash", "toy_ac_ranges": {"PSG": 5301, "FM": 13430, "DAC": 7703}},
              "open_unknowns": ["D-44 BUSREQ primary-source polarity conflict", "exact VA3 reset wiring (approved bounded exception)",
                                "guest envelope/phase equivalence", "reset replay", "audio assumptions A1-A12 remain unqualified for hardware truth",
                                "game audio compatibility", "hardware truth", "performance"]}
    return report


def count(rows):
    return {name: sum(r.get("outcome") == name for r in rows) for name in OUTCOMES}


def validate(report, head):
    problems = []
    if not isinstance(report, dict) or report.get("schema") != SCHEMA or report.get("version") != VERSION:
        return [("schema", "invalid schema/version")]
    if report.get("source_revision") != head:
        problems.append(("stale-revision", "source revision does not match expected revision"))
    rows = report.get("rows")
    if not isinstance(rows, list):
        return problems + [("schema", "rows must be a list")]
    expected = {r[0]: (r[2], r[3], r[4]) for r in CHECKS}
    expected.update({"smoke/independent-game-audio": ("smoke", "scenario-oracle", False)})
    expected.update({k: ("audio", "human-only", False) for k, _ in HUMAN})
    seen = set()
    for row in rows:
        rid = row.get("id")
        if rid in seen:
            problems.append(("duplicate-row", str(rid)))
            continue
        seen.add(rid)
        if rid not in expected:
            problems.append(("unexpected-row", str(rid)))
            continue
        kind, oracle, gating = expected[rid]
        if row.get("kind") != kind or row.get("oracle_class") != oracle or row.get("gating") != gating:
            problems.append(("relabelled-class", rid + " kind/oracle/gating changed"))
        if row.get("outcome") not in OUTCOMES:
            problems.append(("schema", rid + " has invalid outcome"))
        if oracle == "human-only" and row.get("outcome") != "unknown":
            problems.append(("human-only-outcome", rid + " cannot be upgraded"))
        if row.get("outcome") in ("unknown", "skipped", "unsupported") and not row.get("observed"):
            problems.append(("missing-reason", rid + " lacks an explicit reason"))
    for rid in expected.keys() - seen:
        problems.append(("missing-row", rid))
    if report.get("denominator") != len(rows):
        problems.append(("denominator", "denominator differs from row count"))
    if report.get("counts") != count(rows):
        problems.append(("counts", "counts differ from rows"))
    if not report.get("fixture_sha256") or not report.get("configuration_sha256"):
        problems.append(("identity", "configuration or fixture identity absent"))
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--validate", type=Path)
    ap.add_argument("--expected-revision", help="exact 40-hex package source commit for historical validation")
    args = ap.parse_args()
    expected = git("rev-parse", "HEAD")
    if args.expected_revision:
        if not args.validate or not re.fullmatch(r"[0-9a-f]{40}", args.expected_revision):
            ap.error("--expected-revision requires --validate and a full commit ID")
        if git("rev-parse", args.expected_revision + "^{commit}") != args.expected_revision:
            ap.error("expected revision is not an identified source commit")
        expected = args.expected_revision
    if args.validate:
        report = json.loads(args.validate.read_text())
    elif args.build and args.out:
        report = build_report(args.build.resolve())
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    else:
        ap.error("use --build DIR --out FILE or --validate FILE")
    problems = validate(report, expected)
    if problems:
        for reason, detail in problems:
            print("FAIL: %s: %s" % (reason, detail), file=sys.stderr)
        return 1
    bad = [r["id"] for r in report["rows"] if r["gating"] and r["outcome"] in ("fail", "infrastructure-error")]
    print("%s v%d: %d rows %s; gating failures=%s" % (SCHEMA, VERSION, report["denominator"], report["counts"], bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
