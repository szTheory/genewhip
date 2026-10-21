#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Phase 2 evidence report contract with named-reason negative controls (plan GW-02-13).

Usage: phase2_report_contract.py ROOT BUILD_DIR

Builds the report from BUILD_DIR, requires it to validate, then mutates copies and requires
each mutation to be rejected with its own named reason. A rejection for any other reason is a
"wrong rejection" and fails the control (an unrelated failure must not count).
"""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BUILD = Path(sys.argv[2]).resolve()
spec = importlib.util.spec_from_file_location("phase2_report", ROOT / "scripts/evidence/phase2_report.py")
report_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report_module)


def reasons(report, head):
    return {reason for reason, _ in report_module.validate(report, head)}


def first(report, predicate):
    return next(r for r in report["rows"] if predicate(r))


def recount(report):
    report["counts"] = report_module.count(report["rows"])


def drop_seam_row(report):
    report["rows"].remove(first(report, lambda r: r["kind"] == "seam" and r["oracle_class"] == "documented"))
    recount(report)


def duplicate_row(report):
    report["rows"].append(copy.deepcopy(first(report, lambda r: r["kind"] == "seam")))
    recount(report)


def alter_denominator(report):
    report["denominator"] += 1


def stale(report):
    report["source_revision"] = "0" * 40


def unknown_to_pass(report):
    first(report, lambda r: r["kind"] == "seam" and r["oracle_class"] == "unknown")["outcome"] = "pass"
    recount(report)


def unsupported_to_pass(report):
    first(report, lambda r: r["kind"] == "vectors" and r["outcome"] == "unsupported")["outcome"] = "pass"
    recount(report)


def smoke_to_pass(report):
    smoke = first(report, lambda r: r["kind"] == "smoke")
    if smoke["outcome"] == "pass":  # keep the control meaningful if the core ever passes the smoke
        smoke["observed"]["value"] = smoke["observed"]["maximum"] + 1
    smoke["outcome"] = "pass"
    recount(report)


def ref_to_documented(report):
    first(report, lambda r: r["oracle_class"] == "REF-derived")["oracle_class"] = "documented"


CONTROLS = [
    ("missing-row", drop_seam_row, {"missing-row", "denominator"}),
    ("duplicate-row", duplicate_row, {"duplicate-row"}),
    ("denominator", alter_denominator, {"denominator"}),
    ("stale-revision", stale, {"stale-revision"}),
    ("relabelled-outcome", unknown_to_pass, {"relabelled-outcome"}),
    ("relabelled-outcome", unsupported_to_pass, {"relabelled-outcome"}),
    ("relabelled-outcome", smoke_to_pass, {"relabelled-outcome"}),
    ("relabelled-class", ref_to_documented, {"relabelled-class"}),
]


def source_state_counts_untracked():
    """An untracked public input must make the tree dirty (review WR-03)."""
    seen = []
    original = report_module.git
    try:
        report_module.git = lambda *args: seen.append(args) or "?? scripts/untracked.py"
        if report_module.source_state() != "dirty" or "--untracked-files=all" not in seen[0]:
            return "source_state ignores untracked files"
        report_module.git = lambda *args: ""
        if report_module.source_state() != "clean":
            return "source_state does not report a clean tree"
    finally:
        report_module.git = original
    return None


def main():
    problem = source_state_counts_untracked()
    if problem:
        print("FAIL: " + problem, file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="gw-phase2-contract-") as temp:
        out = Path(temp) / "phase2-evidence.json"
        result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/evidence/phase2_report.py"),
                                 "--build", str(BUILD), "--out", str(out)], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, check=False)
        if result.returncode != 0 or not out.is_file():
            print("report build failed:\n" + result.stdout.decode(errors="replace"), file=sys.stderr)
            return 1
        report = json.loads(out.read_text())
        head = report_module.head_revision()
        problems = report_module.validate(report, head)
        if problems:
            print("clean report rejected: %r" % problems, file=sys.stderr)
            return 1
        if report["counts"]["unknown"] <= 0 or report["counts"]["unsupported"] <= 0:
            print("unknown or unsupported rows were not preserved", file=sys.stderr)
            return 1
        if any(r["gating"] for r in report["rows"] if r["kind"] == "smoke"):
            print("smoke row must be non-gating", file=sys.stderr)
            return 1
        failed = False
        for wanted, mutate, allowed in CONTROLS:
            mutated = copy.deepcopy(report)
            mutate(mutated)
            got = reasons(mutated, head)
            if wanted not in got or not got <= allowed:
                print("wrong rejection: %s mutation %s gave %s" % (wanted, mutate.__name__, sorted(got)), file=sys.stderr)
                failed = True
            else:
                print("rejected %-20s by %s" % (mutate.__name__, wanted))
        # The command-line validator must agree: a stale file exits non-zero, a clean one zero.
        stale_report = copy.deepcopy(report)
        stale(stale_report)
        stale_path = Path(temp) / "stale.json"
        stale_path.write_text(json.dumps(stale_report))
        script = str(ROOT / "scripts/evidence/phase2_report.py")
        if subprocess.run([sys.executable, "-I", script, "--validate", str(stale_path)], stdout=subprocess.DEVNULL).returncode == 0:
            print("wrong rejection: --validate accepted a stale report", file=sys.stderr)
            failed = True
        if subprocess.run([sys.executable, "-I", script, "--validate", str(out)], stdout=subprocess.DEVNULL).returncode != 0:
            print("wrong rejection: --validate rejected the clean report", file=sys.stderr)
            failed = True
        print("phase2 report: %d rows, counts %s" % (report["denominator"], report["counts"]))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
