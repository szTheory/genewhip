#!/usr/bin/env bash
set -euo pipefail
# This script is also an entry point when invoked directly. Re-enter Bash with
# an explicit environment so neither arbitrary variables nor exported shell
# functions can reach curl, compilers, or other build children.
if [[ "${GW_FM_BUILD_ENV_PID:-}" != "$$" ]]; then
  CLEAN_ENV=("PATH=${PATH:-/usr/bin:/bin}" "GW_FM_BUILD_ENV_PID=$$")
  for name in TMPDIR TMP TEMP CC CXX SDKROOT DEVELOPER_DIR MACOSX_DEPLOYMENT_TARGET SYSTEMROOT WINDIR; do
    if [[ "${!name+x}" == x ]]; then CLEAN_ENV+=("$name=${!name}"); fi
  done
  exec /usr/bin/env -i "${CLEAN_ENV[@]}" /bin/bash "$0" "$@"
fi
unset GW_FM_BUILD_ENV_PID
CC=${CC:-cc}
CXX=${CXX:-c++}
if [[ "${1:-}" == "--test-compiler-env" ]]; then
  "$CC" --genewhip-env-probe
  "$CXX" --genewhip-env-probe
  exit 0
fi
extract_head_advertisement() {
  awk '$2 == "HEAD" && $1 !~ /^ref:/ { head=$1; count++ }
       END { if (count != 1) exit 1; print head }'
}
valid_git_sha() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }
if [[ "${1:-}" == "--test-head-parser" ]]; then
  expected=335747d78cb0abbc3b55b004e62dad9763140115
  advertised=$(printf 'ref: refs/heads/main\tHEAD\n%s\tHEAD\n' "$expected" | extract_head_advertisement)
  [[ "$advertised" == "$expected" ]] && valid_git_sha "$advertised" || exit 1
  if printf 'ref: refs/heads/main\tHEAD\n' | extract_head_advertisement >/dev/null 2>&1; then exit 1; fi
  if printf '%s\tHEAD\n%s\tHEAD\n' "$expected" "$expected" | extract_head_advertisement >/dev/null 2>&1; then exit 1; fi
  if valid_git_sha "${expected%?}z"; then exit 1; fi
  echo "head advertisement controls: 4/4 passed"
  exit 0
fi
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
LOCK="$ROOT/tools/evidence/fm_compare/refs.lock.json"
REFS="$ROOT/build/audio-refs"
TMP="$REFS/.fetch-$$"
BIN="$REFS/bin"
mkdir -p "$TMP/nuked" "$TMP/ymfm" "$REFS/nuked" "$REFS/ymfm-81aec25" "$BIN"
trap 'rm -rf "$TMP"' EXIT

check_file() {
  local group="$1" name="$2" url="$3" expected="$4" output="$5"
  if ! curl --fail --silent --show-error --location --retry 3 --retry-all-errors \
      --retry-delay 1 --retry-max-time 15 "$url" -o "$output"; then
    echo "FAIL: $group/$name download failed after bounded retries" >&2
    exit 1
  fi
  local got
  got=$(shasum -a 256 "$output" | awk '{print $1}')
  if [[ "$got" != "$expected" ]]; then
    echo "FAIL: $group/$name SHA-256 mismatch: expected $expected, got $got" >&2
    exit 1
  fi
}

NUKED_SHA=335747d78cb0abbc3b55b004e62dad9763140115
YMF_SHA=81aec25ccbb98f4873a255f7551ac4dadac59b4a
HEAD=""
for attempt in 1 2 3 4; do
  if ADVERTISEMENT=$(git -c http.connectTimeout=10 -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=10 \
      ls-remote --symref --exit-code https://github.com/nukeykt/Nuked-OPN2.git HEAD 2>/dev/null); then
    CANDIDATE=$(printf '%s\n' "$ADVERTISEMENT" | extract_head_advertisement) || CANDIDATE=""
    if valid_git_sha "$CANDIDATE"; then HEAD="$CANDIDATE"; break; fi
  fi
  sleep "$attempt"
done
if [[ -z "$HEAD" ]]; then
  echo "FAIL: Nuked HEAD advertisement failed after bounded retries" >&2
  exit 1
fi
LOCKED_HEAD=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["nuked"]["head_commit"])' "$LOCK")
if [[ "$HEAD" != "$LOCKED_HEAD" ]]; then
  echo "FAIL: Nuked HEAD changed since the locked check: expected $LOCKED_HEAD, got $HEAD" >&2
  exit 1
fi

check_file nuked ym3438.c "https://raw.githubusercontent.com/nukeykt/Nuked-OPN2/$NUKED_SHA/ym3438.c" \
  8fa385546f0f2d1c975d097002af00cd729ae2ae097c068e9c883ce08ddf3a76 "$TMP/nuked/ym3438.c"
check_file nuked ym3438.h "https://raw.githubusercontent.com/nukeykt/Nuked-OPN2/$NUKED_SHA/ym3438.h" \
  8e60e35f77049d0e600ad1a47bfc3dfc8b832483e614104473a83c1f33cd7189 "$TMP/nuked/ym3438.h"

for spec in \
  'LICENSE 2d2e9213c170a9866c616fa85b6da993a6724e10befc61f468ed9bfb84c4691c' \
  'ymfm.h f5ab6fed63c8669abab8403e0e93132e1dad0ae4d8e4954e7836ab9e5b228405' \
  'ymfm_fm.h 1b27bfb7fa4963d7c54cb06fd9bf659450362d8ed496c6af7d487b068cac45c9' \
  'ymfm_fm.ipp 4fb7fe59d4494a19e9f9c7888eb644a63d86e109fdefb27a8117bf6a5f6ab4b9' \
  'ymfm_opn.h 1950990c3ea0c6d492a20f66a683a372a7367ef39f7830aa65b20a20d1bcbef5' \
  'ymfm_opn.cpp 8734c6d5a6e1bf49a08eeb33d260d39c17cd1d26f5db506e5d0d3e416913b489' \
  'ymfm_adpcm.h 5933691971493b853a9be443f6e6fd74f63869aa21225f66dd89fc20de20914d' \
  'ymfm_ssg.h 27966b0887fe98f2d06a96be2776c911107e2f2a13a64f9a349e1ffc19cf7584' \
  'ymfm_adpcm.cpp 74e5ded129ea7e532112e5b637d0a7bd4e127fd83331f1fac32011723051d4e0' \
  'ymfm_ssg.cpp 73a3028a77f13f3769b7705079659eb8325431a67b8164ded25e12f324f42bfd'; do
  read -r name hash <<<"$spec"
  if [[ "$name" == "LICENSE" ]]; then
    source_path=LICENSE
  else
    source_path="src/$name"
  fi
  check_file ymfm "$name" "https://raw.githubusercontent.com/aaronsgiles/ymfm/$YMF_SHA/$source_path" "$hash" "$TMP/ymfm/$name"
done
cp "$TMP/nuked/"* "$REFS/nuked/"
cp "$TMP/ymfm/"* "$REFS/ymfm-81aec25/"
echo "Pinned reference hashes verified; compiling offline evidence adapters."

"$CC" -std=c17 -O2 -Wall -Wextra -Wpedantic -I"$REFS/nuked" \
  "$ROOT/tools/evidence/fm_compare/nuked_replay.c" "$REFS/nuked/ym3438.c" -o "$BIN/nuked_replay"
"$CXX" -std=c++17 -O2 -w -I"$REFS/ymfm-81aec25" \
  "$ROOT/tools/evidence/fm_compare/ymfm_replay.cpp" "$REFS/ymfm-81aec25/ymfm_opn.cpp" \
  "$REFS/ymfm-81aec25/ymfm_adpcm.cpp" "$REFS/ymfm-81aec25/ymfm_ssg.cpp" -o "$BIN/ymfm_replay"
echo "Reference adapters built under build/audio-refs/bin/."
