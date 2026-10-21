#!/usr/bin/env python3
"""Prove the D-55 old-behavior mutant fails its named assertion."""
import subprocess
import sys

proc = subprocess.run([sys.argv[1], "--old-behavior-mutant"], text=True,
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
combined = proc.stdout + proc.stderr
if proc.returncode != 1 or "named_check=boundary_DAC_write_affects_same_native_sample" not in combined:
    print("FAIL: old-behavior mutant did not fail the named D-55 assertion", file=sys.stderr)
    print(combined, file=sys.stderr)
    raise SystemExit(1)
print("PASS: old-behavior mutant rejected by named D-55 boundary assertion")
