#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
cmake -S . -B build/extended -DCMAKE_BUILD_TYPE=Release -DGENEWHIP_TEST_HOOKS=ON \
  '-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined
cmake --build build/extended --parallel 2
leaks=1
if [[ "$(uname -s)" == Darwin ]]; then leaks=0; fi
export ASAN_OPTIONS=detect_leaks=$leaks UBSAN_OPTIONS=halt_on_error=1
mkdir -p build/extended/reports
git rev-parse HEAD > build/extended/reports/source-revision.txt
# Original ROMs rebuild byte-identically from source with the pinned toolchain (plan GW-02-13).
bash scripts/fixtures/build-original-roms.sh --verify-reproducible
python3 tests/vectors/run_vectors.py --runner build/extended/tests/vectors/cpu_vector_runner \
  --full --corpus-dir build/vector-corpus --fetch --report build/extended/reports/vectors.json
python3 tests/z80/run_z80_vectors.py --runner build/extended/tests/z80/z80_vector_runner --full --corpus-dir build/z80-vector-corpus --fetch --report build/extended/reports/z80-vectors.json
build/extended/gw_bounded_fuzz > build/extended/reports/fuzz.json
cat build/extended/reports/fuzz.json
# Random VDP register/command/DMA streams under ASan/UBSan (plan GW-02-08): exits non-zero
# on any memory error, undocumented stop reason or determinism mismatch.
build/extended/gw_bounded_fuzz vdp-stream > build/extended/reports/vdp-fuzz.json
cat build/extended/reports/vdp-fuzz.json
# Random sprite tables with link cycles and maximal sizes under ASan/UBSan (plan GW-02-19).
build/extended/gw_bounded_fuzz sprite-table > build/extended/reports/sprite-fuzz.json
cat build/extended/reports/sprite-fuzz.json
# Random 256-byte Z80 programs are uploaded through RESET/BUSREQ under ASan/UBSan;
# each program is repeated to compare public tick, stop reason, work RAM and PCM hash.
build/extended/gw_bounded_fuzz z80-stream > build/extended/reports/z80-fuzz.json
cat build/extended/reports/z80-fuzz.json
# Random audio creation rates, read capacities and trace capacities exercise failure bounds.
build/extended/gw_bounded_fuzz audio-calls > build/extended/reports/audio-fuzz.json
cat build/extended/reports/audio-fuzz.json
# Larger but still finite safety exposure. The Python checker gives every child a
# hard timeout and rejects incomplete, unknown, skipped or mismatched summaries.
python3 tests/api/safety_contract.py --build build/extended --mode scheduled \
  > build/extended/reports/api-safety.json
cat build/extended/reports/api-safety.json
# Versioned Phase 2 evidence report (plan GW-02-13): aggregates every seam, the raster toy, vector
# counts, session cadence/split-run and the non-gating independent-game smoke, then validates it.
python3 -I scripts/evidence/phase2_report.py --build build/extended --out build/extended/reports/phase2-evidence.json
# Versioned Phase 3 report retains the full seam/audio/runner denominator and named unknowns.
python3 -I scripts/evidence/phase3_report.py --build build/extended --out build/extended/reports/phase3-evidence.json
