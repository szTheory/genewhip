#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify generated kernel identity and detect a changed table digit."""
import argparse
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

EXPECTED_SHA256 = "904d72bbeef9f1e85fab1b20c6b8c6395d4c0d39e2ad858d4175797926fe53e8"


def validate(data):
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        raise ValueError("kernel hash mismatch")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--negative-control", action="store_true")
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    generator = root / "tools/audio/gen_kernel.py"
    committed_path = root / "src/audio_kernel.h"
    committed = committed_path.read_bytes()
    try:
        validate(committed)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    if args.negative_control:
        mutated = bytearray(committed)
        marker = b"static const int32_t gw_blep_kernel"
        table_start = mutated.index(marker)
        digit = next(i for i in range(table_start, len(mutated)) if 48 <= mutated[i] <= 57)
        mutated[digit] = 49 if mutated[digit] != 49 else 50
        try:
            validate(bytes(mutated))
        except ValueError as error:
            if str(error) == "kernel hash mismatch":
                print("kernel hash mismatch: negative control detected")
                return 0
        print("FAIL: negative control was not rejected", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as temporary:
        generated = Path(temporary) / "audio_kernel.h"
        subprocess.run([sys.executable, "-I", str(generator), "--output", str(generated)],
            cwd=root, check=True)
        if generated.read_bytes() != committed:
            print("FAIL: generated kernel differs from committed header", file=sys.stderr)
            return 1
    print("resampler_kernel_hash: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
