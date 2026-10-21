#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Phase 3 report contract: each mutation must fail for its named reason."""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root, build = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
spec = importlib.util.spec_from_file_location("phase3_report", root / "scripts/evidence/phase3_report.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def find(report, row_id):
    return next(r for r in report["rows"] if r["id"] == row_id)


def main():
    with tempfile.TemporaryDirectory(prefix="gw-phase3-contract-") as td:
        output = Path(td) / "phase3.json"
        p = subprocess.run([sys.executable, "-I", str(root / "scripts/evidence/phase3_report.py"), "--build",
                            str(build), "--out", str(output)], text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=600)
        if p.returncode or not output.exists():
            print("report build failed:\n" + p.stdout, file=sys.stderr)
            return 1
        base = json.loads(output.read_text())
        reasons = module.validate(base, module.git("rev-parse", "HEAD"))
        if reasons:
            print("clean report rejected: %r" % reasons, file=sys.stderr)
            return 1
        if sum(r["id"].startswith("d44_") for r in base["rows"]) != 6:
            print('FAIL: missing check: D-44 denominator is not six', file=sys.stderr)
            return 1
        if not any(r["kind"] == "smoke" and not r["gating"] for r in base["rows"]):
            print("FAIL: independent-game smoke is not visible and non-gating", file=sys.stderr)
            return 1
        mutations = []
        r = copy.deepcopy(base); find(r, "ym_nuked_model_comparison")["id"] = "ym_alternate_model_comparison"
        renamed = module.validate(r, base["source_revision"])
        if set(renamed) != {("unexpected-row", "ym_alternate_model_comparison"),
                            ("missing-row", "ym_nuked_model_comparison")}:
            raise ValueError("stable row rename did not produce exact missing/unexpected rejection")
        print("rejected stable comparator row rename: unexpected-row + missing-row")
        r = copy.deepcopy(base); r["rows"].pop(); r["denominator"] -= 1; r["counts"] = module.count(r["rows"])
        mutations.append(("missing-row", r))
        r = copy.deepcopy(base); r["rows"].append(copy.deepcopy(r["rows"][0])); r["denominator"] += 1; r["counts"] = module.count(r["rows"])
        mutations.append(("duplicate-row", r))
        r = copy.deepcopy(base); find(r, "d44_2_poll_sequence")["oracle_class"] = "documented"
        mutations.append(("relabelled-class", r))
        r = copy.deepcopy(base); find(r, "human_sound_quality")["outcome"] = "pass"; find(r, "human_sound_quality")["observed"] = "heard"; r["counts"] = module.count(r["rows"])
        mutations.append(("human-only-outcome", r))
        r = copy.deepcopy(base); r["counts"]["pass"] += 1
        mutations.append(("counts", r))
        failed = False
        for wanted, altered in mutations:
            got = {reason for reason, _ in module.validate(altered, module.git("rev-parse", "HEAD"))}
            if wanted not in got or got - {wanted}:
                print("wrong rejection: %s mutation yielded %s" % (wanted, sorted(got)), file=sys.stderr)
                failed = True
            else:
                print("rejected mutation by named reason: " + wanted)
        if failed:
            return 1
        print("phase3 report contract: %d rows; %s" % (base["denominator"], base["counts"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
