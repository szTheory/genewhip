#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
bash scripts/ci/public-hygiene.sh --self-test
python3 tests/evidence/public_hygiene.py
python3 tests/evidence/ci_aggregate_contract.py
python3 tests/evidence/promotion_contract.py
python3 tests/evidence/phase4_report_contract.py
mkdir -p build/ci
git rev-parse HEAD > build/ci/source-revision.txt
cmake --version | head -n 1 > build/ci/toolchain.txt
"${CC:-cc}" --version | head -n 1 >> build/ci/toolchain.txt
uname -sm >> build/ci/toolchain.txt
leaks=1
if [[ "$(uname -s)" == Darwin ]]; then leaks=0; fi # Apple ASan has no LeakSanitizer.
for lane in native sanitizer; do
  if [[ "$lane" == sanitizer ]]; then
    cmake -S . -B "build/ci/$lane" -DCMAKE_BUILD_TYPE=Release -DGENEWHIP_TEST_HOOKS=ON \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
      -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined
  else
    cmake -S . -B "build/ci/$lane" -DCMAKE_BUILD_TYPE=Release -DGENEWHIP_TEST_HOOKS=ON
  fi
  cmake --build "build/ci/$lane" --parallel 2
  ASAN_OPTIONS=detect_leaks=$leaks UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir "build/ci/$lane" --output-on-failure --no-tests=error
  python3 tests/api/safety_contract.py --build "build/ci/$lane" --mode pr
done
cmake -S . -B build/ci/production -DCMAKE_BUILD_TYPE=Release -DGENEWHIP_TEST_HOOKS=OFF
cmake --build build/ci/production --parallel 2
ctest --test-dir build/ci/production --output-on-failure --no-tests=error
python3 tests/api/safety_contract.py --build build/ci/production --mode production
echo 'required-gate: PASS (native, ASan/UBSan, hooks-off, installed C/C++, hygiene, gameplay/report contracts)'
