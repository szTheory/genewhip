#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
LOCK="$ROOT/tools/evidence/fm_compare/refs.lock.json"
REFS="$ROOT/build/audio-refs"
TMP="$REFS/.fetch-$$"
BIN="$REFS/bin"
mkdir -p "$TMP/nuked" "$TMP/ymfm" "$BIN"
trap 'rm -rf "$TMP"' EXIT

check_file() {
  local group="$1" name="$2" url="$3" expected="$4" output="$5"
  curl --fail --silent --show-error --location "$url" -o "$output"
  local got
  got=$(shasum -a 256 "$output" | awk '{print $1}')
  if [[ "$got" != "$expected" ]]; then
    echo "FAIL: $group/$name SHA-256 mismatch: expected $expected, got $got" >&2
    exit 1
  fi
}

NUKED_SHA=335747d78cb0abbc3b55b004e62dad9763140115
YMF_SHA=81aec25ccbb98f4873a255f7551ac4dadac59b4a
API=$(curl --fail --silent --show-error --location \
  "https://api.github.com/repos/nukeykt/Nuked-OPN2/commits?per_page=1")
HEAD=$(python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["sha"])' <<<"$API")
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

CC=${CC:-cc}
CXX=${CXX:-c++}
"$CC" -std=c17 -O2 -Wall -Wextra -Wpedantic -I"$REFS/nuked" \
  "$ROOT/tools/evidence/fm_compare/nuked_replay.c" "$REFS/nuked/ym3438.c" -o "$BIN/nuked_replay"
"$CXX" -std=c++17 -O2 -w -I"$REFS/ymfm-81aec25" \
  "$ROOT/tools/evidence/fm_compare/ymfm_replay.cpp" "$REFS/ymfm-81aec25/ymfm_opn.cpp" \
  "$REFS/ymfm-81aec25/ymfm_adpcm.cpp" "$REFS/ymfm-81aec25/ymfm_ssg.cpp" -o "$BIN/ymfm_replay"
echo "Reference adapters built under build/audio-refs/bin/."
