#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contract entry point for successor MAME reference trust checks."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/evidence/prepare_game_reference.py"
spec = importlib.util.spec_from_file_location("game_reference", MODULE)
if spec is None or spec.loader is None:
    raise SystemExit("BLOCKED: cannot load reference preparation contract")
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def main() -> int:
    try:
        reference.self_test()
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
