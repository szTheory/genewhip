#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline check: every original-rom manifest row's committed ROM matches its digests.

Usage: original_rom_bytes.py REPOSITORY_ROOT. Runs the admission validator's
original-rom rule (path, content, source, build, notice, oracle) on each row of the
repository manifest; no assembler and no network. Exits 1 on the first rejected row.
"""
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("admission", root / "tools/evidence/fixture_manifest.py")
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)
rows = [r for r in json.loads((root / "fixtures/manifest.json").read_text())["fixtures"]
        if r.get("kind") == admission.ORIGINAL_ROM_KIND]
if not rows:
    print("FAIL: no original-rom rows in the manifest")
    sys.exit(1)
for row in rows:
    verdict = admission._validate_original_rom(row, root)
    print("original-rom %s: %s" % (row.get("id"), verdict))
    if verdict != "ok":
        print("FAIL: original-rom %s rejected: %s" % (row.get("id"), verdict))
        sys.exit(1)
