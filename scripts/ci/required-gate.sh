#!/usr/bin/env bash
set -euo pipefail
cd "${BASH_SOURCE[0]%/*}/../.."
TIMEFORMAT='ci-stage %3R seconds'
if [[ "${1:-}" == "--phase7-fast" ]]; then
  if [[ "${GENEWHIP_PROCESS_CONTEXT:-}" != "host-cleanup-v1" ]]; then
    echo 'process-host-admission-required:non-qualifying:before-Popen' >&2
    exit 1
  fi
  if [[ "$#" -ne 1 ]]; then
    echo 'usage: required-gate.sh [--phase7-fast]' >&2
    exit 2
  fi
  TIMEFORMAT='ci-stage phase7-process-admission %3R seconds'; time python3 -I tests/evidence/phase7_process_admission_contract.py
  TIMEFORMAT='ci-stage phase7-diagnostic %3R seconds'; time python3 -I tests/evidence/phase7_diagnostic_contract.py
  TIMEFORMAT='ci-stage phase7-fresh-batch %3R seconds'; time python3 -I tests/evidence/phase7_fresh_batch_contract.py
  TIMEFORMAT='ci-stage phase7-single-native-contract %3R seconds'; time python3 -I tests/evidence/phase7_single_native_contract.py
  TIMEFORMAT='ci-stage qualification-contracts %3R seconds'; time python3 -I tests/evidence/v02_qualification_contract.py --contracts
  TIMEFORMAT='ci-stage matrix-contracts %3R seconds'; time python3 -I tests/evidence/v02_matrix_contract.py --contracts
  TIMEFORMAT='ci-stage execution-contracts %3R seconds'; time python3 -I tests/evidence/v02_execution_contract.py --contracts
  TIMEFORMAT='ci-stage transfer-contract %3R seconds'; time python3 -I tests/evidence/v02_transfer_contract.py
  TIMEFORMAT='ci-stage package-contract %3R seconds'; time python3 -I tests/evidence/v02_package_contract.py
  TIMEFORMAT='ci-stage promotion-contract %3R seconds'; time python3 -I tests/evidence/promotion_contract.py
  TIMEFORMAT='ci-stage publisher-contract %3R seconds'; time python3 -I tests/evidence/v02_delivery_contract.py --publisher
  TIMEFORMAT='ci-stage download-contract %3R seconds'; time python3 -I tests/evidence/v02_delivery_contract.py --download
  TIMEFORMAT='ci-stage ci-timing-contract %3R seconds'; time python3 -I tests/evidence/ci_timing_contract.py
  TIMEFORMAT='ci-stage public-hygiene %3R seconds'; time python3 -I tests/evidence/public_hygiene.py
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
run_required_ctest() {
  local lane=$1 junit=$2 leaks=$3 ctest_status=0
  TIMEFORMAT="ci-stage $lane-ctest %3R seconds"
  if { time env ASAN_OPTIONS=detect_leaks=$leaks UBSAN_OPTIONS=halt_on_error=1 \
    ctest --test-dir "build/ci/$lane" --no-tests=error --output-junit ctest-junit.raw.xml; }; then
    :
  else
    ctest_status=$?
  fi
  python3 scripts/evidence/phase4_report.py safety-sanitize-junit \
    --input "build/ci/$lane/ctest-junit.raw.xml" --output "$junit" || return $?
  if (( ctest_status != 0 )); then
    python3 scripts/evidence/phase4_report.py safety-ctest-failure-summary --input "$junit" || true
  fi
  python3 scripts/ci/check_ctest_skips.py "$junit" || return $?
  return "$ctest_status"
}
TIMEFORMAT='ci-stage public-hygiene %3R seconds'; time bash scripts/ci/public-hygiene.sh --self-test
TIMEFORMAT='ci-stage public-hygiene-contract %3R seconds'; time python3 tests/evidence/public_hygiene.py
TIMEFORMAT='ci-stage aggregate-contract %3R seconds'; time python3 tests/evidence/ci_aggregate_contract.py
TIMEFORMAT='ci-stage promotion-contract %3R seconds'; time python3 tests/evidence/promotion_contract.py
TIMEFORMAT='ci-stage phase4-report-contract %3R seconds'; time python3 tests/evidence/phase4_report_contract.py
TIMEFORMAT='ci-stage phase7-diagnostic %3R seconds'; time python3 -I tests/evidence/phase7_diagnostic_contract.py
TIMEFORMAT='ci-stage phase7-fresh-batch %3R seconds'; time python3 -I tests/evidence/phase7_fresh_batch_contract.py
TIMEFORMAT='ci-stage ctest-skip-contract %3R seconds'; time python3 tests/evidence/ctest_skip_contract.py
TIMEFORMAT='ci-stage dependency-contract %3R seconds'; time python3 tests/evidence/ci_dependency_contract.py
TIMEFORMAT='ci-stage toolchain-receipt-self-test %3R seconds'; time python3 tests/evidence/independent_game_toolchain.py --self-test-current-receipt
TIMEFORMAT='ci-stage toolchain-build %3R seconds'; time python3 tests/evidence/independent_game_toolchain.py
TIMEFORMAT='ci-stage z80-receipt %3R seconds'; time python3 tests/evidence/independent_game_toolchain.py --validate-current-receipt build/tool-cache/z80-elf-as.receipt.json --target z80-elf --assembler build/tool-cache/z80-elf-as
TIMEFORMAT='ci-stage m68k-receipt %3R seconds'; time python3 tests/evidence/independent_game_toolchain.py --validate-current-receipt build/tool-cache/m68k-elf-as.receipt.json --target m68k-elf --assembler build/tool-cache/m68k-elf-as
python3 scripts/evidence/phase4_report.py safety-start --build build
TIMEFORMAT='ci-stage toolchain-identity %3R seconds'; time { cmake --version | head -n 1 > build/ci/toolchain.txt; "${CC:-cc}" --version | head -n 1 >> build/ci/toolchain.txt; }
uname -sm >> build/ci/toolchain.txt
leaks=1
if [[ "$(uname -s)" == Darwin ]]; then leaks=0; fi # Apple ASan has no LeakSanitizer.
for lane in native sanitizer; do
  if [[ "$lane" == sanitizer ]]; then
    TIMEFORMAT="ci-stage $lane-configure %3R seconds"; time cmake -S . -B "build/ci/$lane" -DCMAKE_BUILD_TYPE=Release -DGENEWHIP_TEST_HOOKS=ON \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
      -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined
  else
    TIMEFORMAT="ci-stage $lane-configure %3R seconds"; time cmake -S . -B "build/ci/$lane" -DCMAKE_BUILD_TYPE=Release -DGENEWHIP_TEST_HOOKS=ON
  fi
  TIMEFORMAT="ci-stage $lane-build %3R seconds"; time cmake --build "build/ci/$lane" --parallel 2
  junit="build/ci/$lane/ctest-junit.xml"
  run_required_ctest "$lane" "$junit" "$leaks" || exit $?
  TIMEFORMAT="ci-stage $lane-api-contract %3R seconds"; time python3 tests/api/safety_contract.py --build "build/ci/$lane" --mode pr \
    --out "build/ci/$lane/safety-contract.json"
  python3 scripts/evidence/phase4_report.py safety-lane-complete --build build --lane "$lane"
done
TIMEFORMAT='ci-stage production-configure %3R seconds'; time cmake -S . -B build/ci/production -DCMAKE_BUILD_TYPE=Release -DGENEWHIP_TEST_HOOKS=OFF
TIMEFORMAT='ci-stage production-build %3R seconds'; time cmake --build build/ci/production --parallel 2
run_required_ctest production build/ci/production/ctest-junit.xml "$leaks" || exit $?
TIMEFORMAT='ci-stage production-api-contract %3R seconds'; time python3 tests/api/safety_contract.py --build build/ci/production --mode production \
  --out build/ci/production/safety-contract.json
python3 scripts/evidence/phase4_report.py safety-lane-complete --build build --lane production
python3 scripts/evidence/phase4_report.py safety-finish --build build
echo 'required-gate: PASS (native, ASan/UBSan, hooks-off, installed C/C++, hygiene, gameplay/report contracts)'
