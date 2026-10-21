#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

# These source-built assemblers and reference adapters are locked by exact
# source, signature, toolchain or file digests. Tests must not turn missing
# dependencies into a green-but-skipped qualification lane.
if ! command -v gmkdir >/dev/null 2>&1 || ! command -v ginstall >/dev/null 2>&1; then
  command -v brew >/dev/null 2>&1 || {
    echo 'BLOCKED: Homebrew is required to provision locked GNU Coreutils build inputs' >&2
    exit 77
  }
  brew install coreutils || {
    echo 'BLOCKED: GNU Coreutils provisioning failed; assembler identity cannot be qualified' >&2
    exit 77
  }
fi
bash scripts/fixtures/z80-as.sh
bash scripts/fixtures/m68k-as.sh
python3 tools/evidence/fm_compare/compare.py --fetch --build
