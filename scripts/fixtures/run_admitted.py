#!/usr/bin/env python3
"""Resolve an admitted fixture only after full manifest and byte validation."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", default="fixtures/manifest.json")
    parser.add_argument("--fixture-id", required=True)
    parser.add_argument("--diagnostic-rom", default="build/ci/native/diagnostic.bin")
    args = parser.parse_args()
    root = args.root.resolve()
    module_path = root / "tools/evidence/fixture_manifest.py"
    spec = importlib.util.spec_from_file_location("fixture_manifest", module_path)
    if spec is None or spec.loader is None:
        print("BLOCKED: admission validator is unavailable", file=sys.stderr)
        return 2
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    provenance_spec = importlib.util.spec_from_file_location(
        "fixture_source_provenance", root / "scripts/fixtures/source_provenance.py")
    if provenance_spec is None or provenance_spec.loader is None:
        print("BLOCKED: fixture source provenance verifier is unavailable", file=sys.stderr)
        return 2
    provenance = importlib.util.module_from_spec(provenance_spec)
    provenance_spec.loader.exec_module(provenance)
    try:
        rom = provenance.require_admitted(validator,
            root, args.manifest, args.fixture_id, args.diagnostic_rom)
    except (OSError, ValueError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 1
    print(rom)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
