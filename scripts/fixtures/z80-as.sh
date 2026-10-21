#!/bin/bash
# Prints the path of the pinned GNU Binutils 2.47 z80-elf-as, building it
# through the signature-verifying recipe only when the cache does not already
# hold an executable whose SHA-256 equals toolchain.lock assembler_z80.executable.sha256.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
LOCK="$ROOT/fixtures/independent-game/toolchain.lock"
CACHE="$ROOT/build/tool-cache"
blocked() { printf 'BLOCKED: pinned z80 assembler unavailable: %s\n' "$*" >&2; exit 77; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --cache) [ -n "${2:-}" ] || blocked 'missing --cache directory'; CACHE=$2; shift 2 ;;
    *) blocked "usage: $0 [--cache DIR]" ;;
  esac
done
[ -f "$LOCK" ] || blocked 'toolchain.lock is missing'
EXPECTED=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["assembler_z80"]["executable"]["sha256"])' "$LOCK") \
  || blocked 'cannot read assembler.executable.sha256 from toolchain.lock'
case "$EXPECTED" in
  *[!0-9a-f]*|"") blocked 'toolchain.lock executable digest is not a SHA-256' ;;
esac
[ "${#EXPECTED}" -eq 64 ] || blocked 'toolchain.lock executable digest is not a SHA-256'
mkdir -p "$CACHE"
CACHE=$(cd "$CACHE" && pwd -P)
AS="$CACHE/z80-elf-as"
actual() { shasum -a 256 "$AS" 2>/dev/null | awk '{print $1}'; }
if [ -x "$AS" ] && [ "$(actual)" = "$EXPECTED" ]; then
  printf '%s\n' "$AS"
  exit 0
fi
rm -f "$AS"
printf 'z80-as: cache miss, rebuilding through build-binutils.sh --verify-lock\n' >&2
# build-binutils.sh copies the assembler into $CACHE only after the archive,
# signature and keyring SHA-256 checks and the GOODSIG/VALIDSIG check passed, and
# before it compares host-tool identities with the lock. A later host-identity
# drift (for example a changed Homebrew Python tree) can therefore fail the
# script after a correct assembler was produced. The pinned executable digest is
# the trust root: accept the build only when the cached bytes equal it.
BUILD_RC=0
bash "$ROOT/fixtures/independent-game/toolchain/build-binutils.sh" --target z80-elf --verify-lock --output "$CACHE" >&2 || BUILD_RC=$?
[ -x "$AS" ] || blocked 'pinned assembler build failed (needs native macOS arm64 and network access to ftp.gnu.org)'
[ "$(actual)" = "$EXPECTED" ] || { rm -f "$AS"; blocked "rebuilt assembler digest $(actual) differs from toolchain.lock $EXPECTED"; }
[ "$BUILD_RC" -eq 0 ] || printf 'z80-as: warning: build-binutils.sh exited %s after producing an assembler whose digest equals the lock (host-tool identity drift)\n' "$BUILD_RC" >&2
printf '%s\n' "$AS"
