#!/usr/bin/env python3
"""Keep the vendored Libretro ABI header bound to its reviewed upstream bytes."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "src/libretro/vendor/libretro.h"
EXPECTED_SHA256 = "70b56ff4550e6085f72027b45372bf5d87804cf495764a10c50d7c1b831491a1"
UPSTREAM_REVISION = "d9597c359a5ca8399a4e244f816e7e975a92a2aa"


def main() -> int:
    data = HEADER.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        print(f"libretro-header-provenance: sha256 mismatch: {digest}", file=sys.stderr)
        return 1
    text = data.decode("utf-8")
    if "Permission is hereby granted" not in text or "THE SOFTWARE IS PROVIDED \"AS IS\"" not in text:
        print("libretro-header-provenance: upstream license notice missing", file=sys.stderr)
        return 1
    if UPSTREAM_REVISION not in (ROOT / "docs/libretro.md").read_text(encoding="utf-8"):
        print("libretro-header-provenance: documented immutable upstream revision missing", file=sys.stderr)
        return 1
    print("libretro-header-provenance: exact bytes, notice, and immutable revision verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
