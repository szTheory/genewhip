#!/usr/bin/env bash
set -euo pipefail
cd "${BASH_SOURCE[0]%/*}/../.."
if [[ "${1:-}" == "--phase7-fast" ]]; then
  if [[ "${GENEWHIP_PROCESS_CONTEXT:-}" != "host-cleanup-v1" ]]; then
    echo 'process-host-admission-required:non-qualifying:before-Popen' >&2
    exit 1
  fi
  if [[ "$#" -ne 1 ]]; then
    echo 'usage: required-gate.sh [--phase7-fast]' >&2
    exit 2
  fi
  python3 -I tests/evidence/phase7_process_admission_contract.py
  python3 -I tests/evidence/v02_qualification_contract.py --contracts
  python3 -I tests/evidence/v02_matrix_contract.py --contracts
  python3 -I tests/evidence/v02_execution_contract.py --contracts
  python3 -I tests/evidence/v02_transfer_contract.py
  python3 -I tests/evidence/v02_package_contract.py
  python3 -I tests/evidence/promotion_contract.py
  python3 -I tests/evidence/v02_delivery_contract.py --publisher
  python3 -I tests/evidence/v02_delivery_contract.py --download
  python3 -I tests/evidence/public_hygiene.py
  echo 'required-gate: PASS (v0.2 semantic, privacy, rights and exact-byte contracts; no compatibility claim)'
  exit 0
fi
if [[ "${1:-}" == "--phase6-local" ]]; then
  if [[ "$#" -ne 1 ]]; then
    echo 'usage: required-gate.sh [--phase7-fast|--phase6-local]' >&2
    exit 2
  fi
  python3 -I tests/fixtures/phase6_game.py --mode reader-refresh --build build/phase6 \
    --candidate evidence/phase6-candidate.json --output build/phase6/evidence/phase6-reader-refresh.json
  python3 -I tests/fixtures/phase6_game.py --mode safety --build build/phase6 \
    --candidate evidence/phase6-candidate.json --output evidence/phase6-safety.json
  python3 -I tests/fixtures/phase6_game.py --mode contract --negative-controls \
    --build build/phase6 --candidate evidence/phase6-candidate.json \
    --output build/phase6/evidence/phase6-core-check.json
  ctest --test-dir build/phase6 --no-tests=error --output-on-failure \
    -R '^phase6_media_contract$'
  python3 scripts/evidence/phase6_routes.py --self-test
  python3 tests/desktop/phase6_routes.py --mode negative-controls --offline --build build/phase6 \
    --core evidence/phase6-core-routes.json \
    --delivery-map fixtures/phase6/recursion94-consumed-map-v1.json \
    --candidate evidence/phase6-candidate.json \
    --output build/phase6/evidence/phase6-host-check-offline.json
  python3 - <<'PY'
import hashlib
import json
from pathlib import Path

def artifact(path):
    data = Path(path).read_bytes()
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest()}

candidate = json.loads(Path("evidence/phase6-candidate.json").read_text())
candidate_sha = hashlib.sha256(json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
report = {
    "schema": "genewhip-phase6-local-ci-v1",
    "status": "pass",
    "candidate_sha256": candidate_sha,
    "new_admitted_title_launches": 0,
    "checks": ["reader-metadata-refresh", "three-variant-safety", "core-32-semantic-controls",
               "phase6-media-ctest", "phase6-route-self-test", "current-host-22-controls-offline"],
    "proofs": {
        "reader_refresh": artifact("build/phase6/evidence/phase6-reader-refresh.json"),
        "safety": artifact("evidence/phase6-safety.json"),
        "core_check": artifact("build/phase6/evidence/phase6-core-check.json"),
        "host_check_offline": artifact("build/phase6/evidence/phase6-host-check-offline.json"),
    },
}
Path("evidence/phase6-ci-local.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY
  echo 'required-gate: PASS (bounded Phase 6 local contracts; no admitted game workload)'
  exit 0
fi
if [[ "$#" -ne 0 ]]; then
  echo 'usage: required-gate.sh [--phase7-fast|--phase6-local]' >&2
  exit 2
fi
bash scripts/ci/public-hygiene.sh --self-test
python3 tests/evidence/public_hygiene.py
python3 tests/evidence/ci_aggregate_contract.py
python3 tests/evidence/promotion_contract.py
python3 tests/evidence/phase4_report_contract.py
python3 tests/evidence/ctest_skip_contract.py
python3 tests/evidence/ci_dependency_contract.py
python3 tests/evidence/independent_game_toolchain.py --self-test-current-receipt
python3 tests/evidence/independent_game_toolchain.py
python3 tests/evidence/independent_game_toolchain.py --validate-current-receipt build/tool-cache/z80-elf-as.receipt.json --target z80-elf --assembler build/tool-cache/z80-elf-as
python3 tests/evidence/independent_game_toolchain.py --validate-current-receipt build/tool-cache/m68k-elf-as.receipt.json --target m68k-elf --assembler build/tool-cache/m68k-elf-as
python3 scripts/evidence/phase4_report.py safety-start --build build
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
  junit="build/ci/$lane/ctest-junit.xml"
  ASAN_OPTIONS=detect_leaks=$leaks UBSAN_OPTIONS=halt_on_error=1 \
    ctest --test-dir "build/ci/$lane" --no-tests=error --output-junit ctest-junit.raw.xml
  python3 scripts/evidence/phase4_report.py safety-sanitize-junit \
    --input "build/ci/$lane/ctest-junit.raw.xml" --output "$junit"
  python3 scripts/ci/check_ctest_skips.py "$junit"
  python3 tests/api/safety_contract.py --build "build/ci/$lane" --mode pr \
    --out "build/ci/$lane/safety-contract.json"
  python3 scripts/evidence/phase4_report.py safety-lane-complete --build build --lane "$lane"
done
cmake -S . -B build/ci/production -DCMAKE_BUILD_TYPE=Release -DGENEWHIP_TEST_HOOKS=OFF
cmake --build build/ci/production --parallel 2
ctest --test-dir build/ci/production --no-tests=error \
  --output-junit ctest-junit.raw.xml
python3 scripts/evidence/phase4_report.py safety-sanitize-junit \
  --input build/ci/production/ctest-junit.raw.xml \
  --output build/ci/production/ctest-junit.xml
python3 scripts/ci/check_ctest_skips.py build/ci/production/ctest-junit.xml
python3 tests/api/safety_contract.py --build build/ci/production --mode production \
  --out build/ci/production/safety-contract.json
python3 scripts/evidence/phase4_report.py safety-lane-complete --build build --lane production
python3 scripts/evidence/phase4_report.py safety-finish --build build
echo 'required-gate: PASS (native, ASan/UBSan, hooks-off, installed C/C++, hygiene, gameplay/report contracts)'
