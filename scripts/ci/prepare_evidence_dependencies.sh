#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

# Keep historical toolchain.lock immutable. On clean/current hosts, build both
# targets from the exact signature-verified upstream Binutils source and record
# host/compiler/Python/verifier/assembler identities in separate receipts.
bash scripts/fixtures/z80-as.sh --current-host
bash scripts/fixtures/m68k-as.sh --current-host
python3 tests/evidence/independent_game_toolchain.py --validate-current-receipt build/tool-cache/z80-elf-as.receipt.json --target z80-elf --assembler build/tool-cache/z80-elf-as
python3 tests/evidence/independent_game_toolchain.py --validate-current-receipt build/tool-cache/m68k-elf-as.receipt.json --target m68k-elf --assembler build/tool-cache/m68k-elf-as
# Rebuild every frozen source-built ROM with these exact current-host receipts;
# any output drift blocks the lane and requires fresh fixture admission.
bash scripts/fixtures/build-original-roms.sh --verify-reproducible
python3 tools/evidence/fm_compare/compare.py --fetch --build
