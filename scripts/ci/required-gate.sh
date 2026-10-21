#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
bash scripts/ci/public-hygiene.sh --self-test
python3 tests/evidence/public_hygiene.py
mkdir -p build/ci
git rev-parse HEAD > build/ci/source-revision.txt
cmake --version | head -n 1 > build/ci/toolchain.txt
"${CC:-cc}" --version | head -n 1 >> build/ci/toolchain.txt
uname -sm >> build/ci/toolchain.txt
leaks=1
if [[ "$(uname -s)" == Darwin ]]; then leaks=0; fi # Apple ASan has no LeakSanitizer.
for lane in native sanitizer; do
  flags=()
  if [[ "$lane" == sanitizer ]]; then
    flags=(-DCMAKE_C_FLAGS=-fsanitize=address,undefined\ -fno-omit-frame-pointer
           -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined)
  fi
  cmake -S . -B "build/ci/$lane" -DCMAKE_BUILD_TYPE=Release -DGENEWHIP_TEST_HOOKS=ON "${flags[@]}"
  cmake --build "build/ci/$lane" --parallel 2
  ASAN_OPTIONS=detect_leaks=$leaks UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir "build/ci/$lane" --output-on-failure
done
cmake -S . -B build/ci/production -DCMAKE_BUILD_TYPE=Release -DGENEWHIP_TEST_HOOKS=OFF
cmake --build build/ci/production --parallel 2
ctest --test-dir build/ci/production --output-on-failure
echo 'required-gate: PASS (native, ASan/UBSan, hooks-off, installed C/C++, hygiene)'
