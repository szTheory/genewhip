#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reject every CTest skip except the two recorded v1 identity unknowns."""
import pathlib
import sys
import xml.etree.ElementTree as ET

ALLOWED_SKIPS = frozenset({"independent_game_admission", "independent_game_consumer"})


def unexpected_skips(path):
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    if not cases:
        raise ValueError("CTest JUnit report has no test cases")
    skipped = [case.get("name", "") for case in cases if case.find("skipped") is not None]
    if any(not name for name in skipped):
        raise ValueError("CTest JUnit report contains an unnamed skipped test")
    return sorted(set(skipped) - ALLOWED_SKIPS)


def main(argv):
    if len(argv) != 2:
        print("usage: check_ctest_skips.py CTEST_JUNIT.xml", file=sys.stderr)
        return 2
    path = pathlib.Path(argv[1])
    try:
        unexpected = unexpected_skips(path)
    except (OSError, ET.ParseError, ValueError) as exc:
        print("REJECT: CTest skip report invalid: " + type(exc).__name__, file=sys.stderr)
        return 2
    if unexpected:
        for name in unexpected:
            print("REJECT: unexpected CTest skip: " + name, file=sys.stderr)
        return 1
    print("CTest skip policy: PASS (only recorded v1 identity unknowns may skip)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
