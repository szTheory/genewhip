#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Phase 2 evidence aggregation and validation (plan GW-02-13).

Usage:
  phase2_report.py --build DIR --out FILE     run every Phase 2 check against a build directory,
                                              write the report, validate it, exit non-zero on any
                                              integrity problem or gating fail/infrastructure error
  phase2_report.py --validate FILE            validate an existing report against the roster and HEAD

Schema genewhip-phase2-evidence version 1. The expected roster below is explicit on purpose: a
silently dropped row, a duplicated row, or a row whose class was relabelled fails validation by
name. Outcomes and classes are never upgraded here: a seam case with no independent expected
value stays unknown, a vector source with unsupported records stays unsupported, and the
independent-game smoke stays non-gating. Reports hold repository-relative identifiers only.
"""
import argparse
import json
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "genewhip-phase2-evidence"
VERSION = 1
OUTCOMES = ("pass", "fail", "unknown", "unsupported", "skipped", "infrastructure-error")
KINDS = ("seam", "toy", "vectors", "session", "smoke")
PROFILE = "VA3-NTSC-U"

# Seam rosters: case/sample ids with their pinned oracle class (documented | REF-derived | unknown).
SEAMS = {
    "ports": {
        "name": "vdp-ports",
        "rows": [
            ("vram-write-readback", "documented"),
            ("cram-write-readback", "documented"),
            ("vsram-write-readback", "documented"),
            ("autoincrement-4", "documented"),
            ("port-mirrors-c00002-c00006", "documented"),
            ("status-fifo-empty-dma-pal", "documented"),
            ("status-vblank-display-disabled", "REF-derived"),
            ("status-via-c00006", "documented"),
            ("status-upper-bits-and-hblank", "unknown"),
            ("latch-cleared-by-status-read", "REF-derived"),
            ("hv-counter-word", "unknown"),
            ("vsram-entry-40-read", "unknown"),
            ("completion-marker", "documented"),
        ],
    },
    "th": {
        "name": "th-protocol",
        "rows": [
            ("port1-th-high", "documented"),
            ("port1-th-low", "documented"),
            ("port2-th-low", "documented"),
            ("port2-th-high", "documented"),
            ("th-low-bits-3-2-zero", "documented"),
            ("th-follows-data-write", "documented"),
            ("port1-th-input-reads-th-high-layout", "REF-derived"),
            ("port2-th-input-reads-th-high-layout", "REF-derived"),
            ("version-register-a10001", "unknown"),
            ("port1-unaffected-by-port2-none", "documented"),
            ("port2-none-reads-pull-ups", "REF-derived"),
            ("port2-none-th-input-reads-pull-ups", "REF-derived"),
            ("completion-marker", "documented"),
        ],
    },
    "dma": {
        "name": "vdp-dma",
        "rows": [
            ("dma68k-vram-first", "documented"),
            ("dma68k-vram-middle", "documented"),
            ("dma68k-vram-last", "documented"),
            ("dma68k-vram-past-end-untouched", "documented"),
            ("dma68k-cpu-halt-hv-counter", "unknown"),
            ("dma68k-cram-first", "documented"),
            ("dma68k-cram-last", "documented"),
            ("dma68k-vsram-first", "documented"),
            ("dma68k-vsram-last", "documented"),
            ("dma68k-source-128k-wrap", "REF-derived"),
            ("fill-interior-words", "documented"),
            ("fill-bounded-by-length", "documented"),
            ("fill-busy-flag-set", "documented"),
            ("fill-busy-flag-clear-after-poll", "documented"),
            ("fill-edge-first-word", "unknown"),
            ("fill-edge-last-word", "unknown"),
            ("copy-busy-flag-set", "documented"),
            ("copy-busy-flag-clear-after-poll", "documented"),
            ("copy-first-word", "documented"),
            ("copy-middle-word", "documented"),
            ("copy-last-word", "documented"),
            ("dma-length-zero", "unknown"),
            ("fill-trigger-byte-replication", "unknown"),
            ("fill-data-port-write-during-fill", "unknown"),
            ("completion-marker", "documented"),
        ],
    },
    "fifo": {
        "name": "vdp-fifo",
        "rows": [
            ("fifo-burst-order", "documented"),
            ("fifo-full-flag-in-burst", "documented"),
            ("fifo-empty-flag-after-wait", "documented"),
            ("fifo-no-full-in-blanking", "documented"),
            ("fifo-address-change-pending", "documented"),
            ("fifo-status-per-write", "unknown"),
            ("completion-marker", "documented"),
        ],
    },
    "irq": {
        "name": "vdp-irq",
        "rows": [
            ("vint-count-3", "documented"),
            ("vint-at-vblank-start", "documented"),
            ("vint-handler-sr", "documented"),
            ("hint-handler-sr", "documented"),
            ("hint-count-reg10-0", "REF-derived"),
            ("hint-count-reg10-7", "REF-derived"),
            ("hint-count-reg10-223", "REF-derived"),
            ("hint-count-next-window", "REF-derived"),
            ("hint-count-order-and-range", "documented"),
            ("hint-count-range-flags", "documented"),
            ("vint-priority-over-hint", "documented"),
            ("mask-6-blocks-vint-status-set", "documented"),
            ("mask-6-blocks-vint-count", "documented"),
            ("mask-6-status-after-delay", "unknown"),
            ("mask-lowered-takes-vint", "documented"),
            ("mask-lowered-latency-instructions", "unknown"),
            ("disabled-vint-not-taken", "documented"),
            ("enable-pending-vint-taken", "documented"),
            ("enable-pending-latency-instructions", "unknown"),
            ("marker-order-across-rte", "documented"),
            ("rte-restores-mask", "documented"),
            ("stop-wake-vint", "documented"),
            ("completion-marker", "documented"),
        ],
    },
    "sprites": {
        "name": "vdp-sprites",
        "rows": [
            ("completion-marker", "documented"),
            ("status-phase1-read1-collision-link-order", "REF-derived"),
            ("status-phase1-read2-flags-cleared-by-read", "REF-derived"),
            ("status-phase2-read1-h40-20-sprites-no-overflow", "REF-derived"),
            ("status-phase3-read1-h40-21-sprites-overflow", "REF-derived"),
            ("status-phase3-read2-flags-cleared-by-read", "REF-derived"),
            ("status-phase4-read1-h32-16-sprites-no-overflow", "REF-derived"),
            ("status-phase5-read1-h32-17-sprites-overflow", "REF-derived"),
            ("status-phase6-read1-h40-frame-bound-status", "unknown"),
            ("status-phase7-read1-h32-frame-bound-status", "unknown"),
            ("status-phase8-read1-h40-pixel-limit-status", "unknown"),
            ("status-phase9-read1-h32-pixel-limit-status", "unknown"),
            ("status-phase10-read1-partial-sprite-status", "unknown"),
            ("status-phase11-read1-x0-masking-status", "unknown"),
            ("status-phase12-read1-cyclic-list-status", "unknown"),
            ("p1-entry0-drawn", "documented"),
            ("p1-entry1-only-region", "documented"),
            ("p1-traversal-order-overlap-first-drawn-wins", "documented"),
            ("p1-entry2-right-edge", "documented"),
            ("p1-unlinked-entry3-not-drawn", "documented"),
            ("p2-first-of-20", "documented"),
            ("p2-twentieth-drawn", "documented"),
            ("p3-twentieth-drawn", "documented"),
            ("p3-twenty-first-not-drawn", "documented"),
            ("p4-sixteenth-drawn", "documented"),
            ("p5-sixteenth-drawn", "documented"),
            ("p5-seventeenth-not-drawn", "documented"),
            ("p6-entry0-drawn", "documented"),
            ("p6-entry79-drawn", "documented"),
            ("p6-entry80-not-drawn", "documented"),
            ("p6-entry99-not-drawn", "documented"),
            ("p7-entry63-drawn", "documented"),
            ("p7-entry64-not-drawn", "documented"),
            ("p7-entry69-not-drawn", "documented"),
            ("p8-first-ten-drawn", "documented"),
            ("p8-eleventh-over-320-pixels-not-drawn", "documented"),
            ("p9-first-eight-drawn", "documented"),
            ("p9-ninth-over-256-pixels-not-drawn", "documented"),
            ("p10-within-budget-drawn", "documented"),
            ("p10-crossing-sprite-column-147", "unknown"),
            ("p10-crossing-sprite-column-148", "unknown"),
            ("p11-before-x0-drawn", "documented"),
            ("p11-after-x0-sprite", "unknown"),
            ("p12-entry0-drawn", "documented"),
            ("p12-entry1-drawn", "documented"),
            ("p12-entry2-drawn", "documented"),
        ],
    },
}

# CPU vector sources in the selected corpus (tests/vectors/selected.json) and their test counts.
VECTOR_SOURCES = {
    "v1/ADD.b.json.bin": 32,
    "v1/ADD.l.json.bin": 32,
    "v1/ADD.w.json.bin": 32,
    "v1/ADDA.l.json.bin": 32,
    "v1/ADDA.w.json.bin": 32,
    "v1/AND.b.json.bin": 32,
    "v1/AND.l.json.bin": 32,
    "v1/AND.w.json.bin": 32,
    "v1/ANDItoCCR.json.bin": 32,
    "v1/ANDItoSR.json.bin": 32,
    "v1/ASL.b.json.bin": 32,
    "v1/ASL.l.json.bin": 32,
    "v1/ASL.w.json.bin": 32,
    "v1/ASR.b.json.bin": 32,
    "v1/ASR.l.json.bin": 32,
    "v1/ASR.w.json.bin": 32,
    "v1/BCHG.json.bin": 32,
    "v1/BCLR.json.bin": 32,
    "v1/BSET.json.bin": 32,
    "v1/BSR.json.bin": 32,
    "v1/BTST.json.bin": 32,
    "v1/Bcc.json.bin": 32,
    "v1/CLR.b.json.bin": 32,
    "v1/CLR.l.json.bin": 32,
    "v1/CLR.w.json.bin": 32,
    "v1/CMP.b.json.bin": 32,
    "v1/CMP.l.json.bin": 32,
    "v1/CMP.w.json.bin": 32,
    "v1/CMPA.l.json.bin": 32,
    "v1/CMPA.w.json.bin": 32,
    "v1/DBcc.json.bin": 32,
    "v1/EOR.b.json.bin": 32,
    "v1/EOR.l.json.bin": 32,
    "v1/EOR.w.json.bin": 32,
    "v1/EORItoCCR.json.bin": 32,
    "v1/EORItoSR.json.bin": 32,
    "v1/EXT.l.json.bin": 32,
    "v1/EXT.w.json.bin": 32,
    "v1/JMP.json.bin": 32,
    "v1/JSR.json.bin": 32,
    "v1/LEA.json.bin": 32,
    "v1/LSL.b.json.bin": 32,
    "v1/LSL.l.json.bin": 32,
    "v1/LSL.w.json.bin": 32,
    "v1/LSR.b.json.bin": 32,
    "v1/LSR.l.json.bin": 32,
    "v1/LSR.w.json.bin": 32,
    "v1/MOVE.b.json.bin": 32,
    "v1/MOVE.l.json.bin": 32,
    "v1/MOVE.q.json.bin": 32,
    "v1/MOVE.w.json.bin": 32,
    "v1/MOVEA.l.json.bin": 32,
    "v1/MOVEA.w.json.bin": 32,
    "v1/MOVEfromSR.json.bin": 32,
    "v1/MOVEtoCCR.json.bin": 32,
    "v1/MOVEtoSR.json.bin": 32,
    "v1/NEG.b.json.bin": 32,
    "v1/NEG.l.json.bin": 32,
    "v1/NEG.w.json.bin": 32,
    "v1/NOP.json.bin": 32,
    "v1/NOT.b.json.bin": 32,
    "v1/NOT.l.json.bin": 32,
    "v1/NOT.w.json.bin": 32,
    "v1/OR.b.json.bin": 32,
    "v1/OR.l.json.bin": 32,
    "v1/OR.w.json.bin": 32,
    "v1/ORItoCCR.json.bin": 32,
    "v1/ORItoSR.json.bin": 32,
    "v1/ROL.b.json.bin": 32,
    "v1/ROL.l.json.bin": 32,
    "v1/ROL.w.json.bin": 32,
    "v1/ROR.b.json.bin": 32,
    "v1/ROR.l.json.bin": 32,
    "v1/ROR.w.json.bin": 32,
    "v1/RTS.json.bin": 32,
    "v1/SUB.b.json.bin": 32,
    "v1/SUB.l.json.bin": 32,
    "v1/SUB.w.json.bin": 32,
    "v1/SUBA.l.json.bin": 32,
    "v1/SUBA.w.json.bin": 32,
    "v1/SWAP.json.bin": 32,
    "v1/TST.b.json.bin": 32,
    "v1/TST.l.json.bin": 32,
    "v1/TST.w.json.bin": 32,
}

VECTOR_EXTRA = ("vectors/cpu_interrupt",)
TOY_ROWS = {"toy/planes": "planes", "toy/scroll": "scroll", "toy/sprites": "sprites"}
SESSION_ROWS = ("session/session_cadence", "session/split_run_equivalence")
SMOKE_ROW = "smoke/independent-game-core"
VECTOR_TOTAL = sum(VECTOR_SOURCES.values())
# Oracle classes outside the seam vocabulary (documented | REF-derived | unknown).
CLASS_TOY = "authored-oracle"
CLASS_VECTORS = "MAME-derived"
CLASS_SESSION = "authored-contract"
CLASS_SMOKE = "scenario-oracle"


def roster():
    """Return {row id: (kind, pinned oracle class)} for every expected row."""
    rows = {}
    for key, seam in SEAMS.items():
        for case_id, klass in seam["rows"]:
            rows["seam/%s/%s" % (key, case_id)] = ("seam", klass)
    for row_id in TOY_ROWS:
        rows[row_id] = ("toy", CLASS_TOY)
    for source in VECTOR_SOURCES:
        rows["vectors/" + source] = ("vectors", CLASS_VECTORS)
    for row_id in VECTOR_EXTRA:
        rows[row_id] = ("vectors", CLASS_TOY)
    for row_id in SESSION_ROWS:
        rows[row_id] = ("session", CLASS_SESSION)
    rows[SMOKE_ROW] = ("smoke", CLASS_SMOKE)
    return rows


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          check=True).stdout.decode().strip()


def head_revision():
    return git("rev-parse", "HEAD")


def count(rows):
    return {name: sum(1 for r in rows if r.get("outcome") == name) for name in OUTCOMES}


def validate(report, head):
    """Return a list of (reason, detail). Reasons: schema, missing-row, duplicate-row,
    unexpected-row, stale-revision, denominator, counts, relabelled-outcome, relabelled-class."""
    problems = []
    if not isinstance(report, dict) or report.get("schema") != SCHEMA or report.get("version") != VERSION:
        return [("schema", "not a %s version %d report" % (SCHEMA, VERSION))]
    expected = roster()
    rows = report.get("rows")
    if not isinstance(rows, list):
        return [("schema", "rows is not a list")]
    if report.get("source_revision") != head:
        problems.append(("stale-revision", "report revision differs from HEAD"))
    seen = set()
    for row in rows:
        row_id = row.get("id")
        if row_id in seen:
            problems.append(("duplicate-row", str(row_id)))
        seen.add(row_id)
        if row_id not in expected:
            problems.append(("unexpected-row", str(row_id)))
            continue
        kind, klass = expected[row_id]
        if row.get("kind") != kind or row.get("outcome") not in OUTCOMES:
            problems.append(("schema", "bad kind or outcome on " + row_id))
            continue
        if row.get("oracle_class") != klass:
            problems.append(("relabelled-class", "%s is %s, pinned %s" % (row_id, row.get("oracle_class"), klass)))
        outcome, observed = row["outcome"], row.get("observed")
        if outcome == "pass":
            if klass == "unknown":
                problems.append(("relabelled-outcome", row_id + ": no independent expected value, cannot pass"))
            if kind == "vectors" and isinstance(observed, dict) and \
                    (observed.get("pass") != observed.get("total") or observed.get("unsupported") or observed.get("fail")):
                problems.append(("relabelled-outcome", row_id + ": counts are not all pass"))
            if kind == "smoke" and not (isinstance(observed, dict) and isinstance(observed.get("value"), int) and
                                        observed["minimum"] <= observed["value"] <= observed["maximum"]):
                problems.append(("relabelled-outcome", row_id + ": pass without an in-range observed value"))
        if outcome == "unsupported" and kind == "smoke" and not (isinstance(observed, dict) and observed.get("stop_reason")):
            problems.append(("relabelled-outcome", row_id + ": unsupported without a stop reason"))
        if kind == "vectors" and isinstance(observed, dict):
            if observed.get("total") != (VECTOR_SOURCES.get(row_id[len("vectors/"):], observed.get("total"))):
                problems.append(("denominator", row_id + ": source test count changed"))
    for row_id in expected:
        if row_id not in seen:
            problems.append(("missing-row", row_id))
    if report.get("denominator") != len(expected):
        problems.append(("denominator", "denominator %r, roster has %d" % (report.get("denominator"), len(expected))))
    if report.get("vector_denominator") != VECTOR_TOTAL:
        problems.append(("denominator", "vector denominator %r, expected %d" % (report.get("vector_denominator"), VECTOR_TOTAL)))
    if report.get("counts") != count(rows):
        problems.append(("counts", "counts do not match the rows"))
    return problems


def run(command, timeout=300, cwd=ROOT):
    try:
        result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, type(error).__name__
    return result.returncode, result.stdout.decode(errors="replace")


def row(row_id, outcome, klass, observed, gating, **extra):
    kind = roster()[row_id][0] if row_id in roster() else "seam"
    out = {"id": row_id, "kind": kind, "oracle_class": klass, "outcome": outcome, "observed": observed, "gating": gating}
    out.update(extra)
    return out


def seam_rows(build, tmp):
    rows = []
    runner = build / "tests/devices/gw_seam_runner"
    for key, seam in SEAMS.items():
        rom = ROOT / ("tests/devices/roms/%s.bin" % key)
        report_path = tmp / ("%s-seam.json" % key)
        rows_by_id = {}
        if runner.is_file():
            run([sys.executable, "-I", str(ROOT / "tests/devices/seam_check.py"), "--runner", str(runner), "--rom", str(rom),
                 "--expect", str(ROOT / ("tests/devices/roms/%s.expect.json" % key)), "--report", str(report_path)])
        if report_path.is_file():
            document = json.loads(report_path.read_text())
            rows_by_id = {r["id"]: r for r in document["rows"]}
            if document.get("seam") != seam["name"]:
                rows_by_id = {}
        for case_id, klass in seam["rows"]:
            source = rows_by_id.get(case_id)
            row_id = "seam/%s/%s" % (key, case_id)
            if source is None:
                rows.append(row(row_id, "infrastructure-error", klass, "no seam report row", True))
                continue
            extra = {k: source[k] for k in ("expected", "mask", "reason", "run") if k in source}
            rows.append(row(row_id, source["outcome"], source["oracle_class"], source.get("observed"),
                            source["oracle_class"] != "unknown", **extra))
    return rows


def command_row(row_id, klass, command, gating=True):
    code, text = run(command)
    lines = [line for line in text.splitlines() if line.strip()]
    if code == 0:
        return row(row_id, "pass", klass, lines[-1] if lines else "", gating)
    outcome = "infrastructure-error" if code == 127 else "fail"
    return row(row_id, outcome, klass, lines[-1] if lines else "", gating)


def toy_rows(build):
    headless = build / "tools/session/gw_headless"
    rows = []
    for row_id, test in TOY_ROWS.items():
        if not headless.is_file():
            rows.append(row(row_id, "infrastructure-error", CLASS_TOY, "gw_headless missing", True))
            continue
        rows.append(command_row(row_id, CLASS_TOY, [sys.executable, "-I", str(ROOT / "tests/devices/raster_toy.py"),
                                                    str(ROOT), str(headless), "--test", test]))
    return rows


def vector_rows(build, tmp):
    runner = build / "tests/vectors/cpu_vector_runner"
    rows = []
    if not runner.is_file():
        reason = "no vector runner in this build (hooks-off)"
        for source in VECTOR_SOURCES:
            rows.append(row("vectors/" + source, "skipped", CLASS_VECTORS, reason, False))
        rows.append(row("vectors/cpu_interrupt", "skipped", CLASS_TOY, reason, False))
        return rows
    report_path = tmp / "vectors.json"
    run([sys.executable, str(ROOT / "tests/vectors/run_vectors.py"), "--runner", str(runner), "--report", str(report_path)])
    cells = {}
    if report_path.is_file():
        document = json.loads(report_path.read_text())
        for outcome in document["outcomes"]:
            cell = cells.setdefault(outcome["source"], {"pass": 0, "fail": 0, "unsupported": 0, "total": 0})
            cell[outcome["status"]] = cell.get(outcome["status"], 0) + 1
            cell["total"] += 1
    for source in VECTOR_SOURCES:
        cell = cells.get(source)
        row_id = "vectors/" + source
        if cell is None:
            rows.append(row(row_id, "infrastructure-error", CLASS_VECTORS, "no vector report row", True))
            continue
        outcome = "fail" if cell["fail"] else "unsupported" if cell["unsupported"] else "pass"
        rows.append(row(row_id, outcome, CLASS_VECTORS, cell, True))
    interrupt = build / "tests/vectors/cpu_interrupt"
    rows.append(command_row("vectors/cpu_interrupt", CLASS_TOY, [str(interrupt)]))
    return rows


def session_rows(build):
    rom = str(ROOT / "tests/devices/roms/pad_echo.bin")
    return [command_row("session/session_cadence", CLASS_SESSION, [str(build / "tools/session/session_cadence"), rom]),
            command_row("session/split_run_equivalence", CLASS_SESSION, [str(build / "tests/devices/split_run_equivalence"), rom])]


def smoke_row(build):
    headless = build / "tools/session/gw_headless"
    code, text = run([sys.executable, "-I", str(ROOT / "tests/fixtures/independent_game_core_smoke.py"), str(ROOT), str(headless)])
    lines = [line for line in text.splitlines() if line.strip()]
    try:
        smoke = json.loads(lines[-1])
    except (ValueError, IndexError):
        return row(SMOKE_ROW, "infrastructure-error", CLASS_SMOKE, "no outcome line", False)
    if smoke.get("outcome") == "infrastructure_error":
        return row(SMOKE_ROW, "infrastructure-error", CLASS_SMOKE, smoke.get("reason"), False)
    observed = {"minimum": smoke["expected_minimum"], "maximum": smoke["expected_maximum"],
                "address": smoke["oracle_address"], "fields": smoke["fields"],
                "claim": "none: non-gating smoke, no compatibility claim"}
    for key in ("observed", "stop_reason", "opcode", "address", "fault_address", "reason"):
        if key in smoke:
            observed["value" if key == "observed" else "instruction_address" if key == "address" else key] = smoke[key]
    return row(SMOKE_ROW, smoke["outcome"], CLASS_SMOKE, observed, False)


def configuration(build):
    cache = {}
    cache_path = build / "CMakeCache.txt"
    if cache_path.is_file():
        for line in cache_path.read_text().splitlines():
            match = re.match(r"^(CMAKE_BUILD_TYPE|CMAKE_C_FLAGS|GENEWHIP_BUILD_TOOLS|GENEWHIP_TEST_HOOKS):[A-Z]+=(.*)$", line)
            if match:
                cache[match.group(1)] = match.group(2)
    compiler = {}
    for path in sorted(build.glob("CMakeFiles/*/CMakeCCompiler.cmake")):
        for line in path.read_text().splitlines():
            match = re.match(r'^set\(CMAKE_C_COMPILER_(ID|VERSION) "([^"]*)"\)', line)
            if match:
                compiler[match.group(1).lower()] = match.group(2)
        break
    return {"build_type": cache.get("CMAKE_BUILD_TYPE", ""), "c_flags": cache.get("CMAKE_C_FLAGS", ""),
            "test_hooks": cache.get("GENEWHIP_TEST_HOOKS", ""), "build_tools": cache.get("GENEWHIP_BUILD_TOOLS", ""),
            "c_compiler": compiler, "host": "%s %s" % (platform.system(), platform.machine())}


def api_version():
    text = (ROOT / "include/genewhip/genewhip.h").read_text()
    return int(re.search(r"#define GW_API_VERSION UINT32_C\((\d+)\)", text).group(1))


def source_state():
    """Same rule as the packagers: untracked files count, ignored paths do not."""
    dirty = git("status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude).planning")
    return "dirty" if dirty else "clean"


def build_report(build):
    with tempfile.TemporaryDirectory(prefix="gw-phase2-") as temp:
        tmp = Path(temp)
        rows = seam_rows(build, tmp) + toy_rows(build) + vector_rows(build, tmp) + session_rows(build) + [smoke_row(build)]
    return {"schema": SCHEMA, "version": VERSION, "source_revision": head_revision(),
            "source_state": source_state(), "configuration": configuration(build),
            "profile": PROFILE, "api_version": api_version(), "rows": rows, "denominator": len(roster()),
            "vector_denominator": VECTOR_TOTAL, "counts": count(rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--validate", type=Path)
    args = parser.parse_args()
    if args.validate:
        problems = validate(json.loads(args.validate.read_text()), head_revision())
        for reason, detail in problems:
            print("%s: %s" % (reason, detail))
        return 1 if problems else 0
    if not args.build or not args.out:
        parser.error("--build and --out are required")
    report = build_report(args.build.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    problems = validate(report, head_revision())
    for reason, detail in problems:
        print("INVALID %s: %s" % (reason, detail), file=sys.stderr)
    bad = [r["id"] for r in report["rows"] if r["gating"] and r["outcome"] in ("fail", "infrastructure-error")]
    for row_id in bad:
        print("GATING %s" % row_id, file=sys.stderr)
    print("phase2-evidence: %d rows, %s (source %s)" % (
        report["denominator"], ", ".join("%s %d" % kv for kv in report["counts"].items()), report["source_state"]))
    return 1 if problems or bad else 0


if __name__ == "__main__":
    sys.exit(main())
