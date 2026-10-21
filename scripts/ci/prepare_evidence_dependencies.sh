#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

# These source-built assemblers and reference adapters are locked by exact
# source, signature, toolchain or file digests. Tests must not turn missing
# dependencies into a green-but-skipped qualification lane.
bash scripts/fixtures/z80-as.sh
bash scripts/fixtures/m68k-as.sh
python3 tools/evidence/fm_compare/compare.py --fetch --build
