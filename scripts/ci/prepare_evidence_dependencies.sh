#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
TIMEFORMAT='ci-stage %3R seconds'

# Keep historical toolchain.lock immutable. On clean/current hosts, build both
# targets from the exact signature-verified upstream Binutils source and record
# host/compiler/Python/verifier/assembler identities in separate receipts.
TIMEFORMAT='ci-stage z80-assembler-build %3R seconds'; time bash scripts/fixtures/z80-as.sh --current-host
TIMEFORMAT='ci-stage m68k-assembler-build %3R seconds'; time bash scripts/fixtures/m68k-as.sh --current-host
TIMEFORMAT='ci-stage z80-receipt-validation %3R seconds'; time python3 tests/evidence/independent_game_toolchain.py --validate-current-receipt build/tool-cache/z80-elf-as.receipt.json --target z80-elf --assembler build/tool-cache/z80-elf-as
TIMEFORMAT='ci-stage m68k-receipt-validation %3R seconds'; time python3 tests/evidence/independent_game_toolchain.py --validate-current-receipt build/tool-cache/m68k-elf-as.receipt.json --target m68k-elf --assembler build/tool-cache/m68k-elf-as
# Rebuild every frozen source-built ROM with these exact current-host receipts;
# any output drift blocks the lane and requires fresh fixture admission.
TIMEFORMAT='ci-stage rom-reproduction %3R seconds'; time bash scripts/fixtures/build-original-roms.sh --verify-reproducible
TIMEFORMAT='ci-stage fm-comparison-preparation %3R seconds'; time python3 tools/evidence/fm_compare/compare.py --fetch --build
