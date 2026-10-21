#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
FIXTURE="$ROOT/fixtures/independent-game"
VALIDATOR="$ROOT/tests/evidence/independent_game_toolchain.py"
LOCK=${GENEWHIP_TOOLCHAIN_LOCK:-$FIXTURE/toolchain.lock}
OUTPUT=${GENEWHIP_CANDIDATE_PATH:-$FIXTURE/game.bin}

case "${1:-}" in
  --validate-only)
    exec python3 "$VALIDATOR" --validate-lock "$LOCK"
    ;;
  --verify-reproducible) ;;
  *) printf 'BLOCKED: usage: %s --verify-reproducible|--validate-only\n' "$0" >&2; exit 2 ;;
esac

python3 "$VALIDATOR" --validate-lock "$LOCK"
python3 "$VALIDATOR"
[ -f "$FIXTURE/src/game.s" ] || { echo 'BLOCKED: authored game source is missing' >&2; exit 1; }
grep -q 'solely authored for Genewhip' "$FIXTURE/NOTICES.md" || { echo 'BLOCKED: sole-authorship grant missing' >&2; exit 1; }
grep -q 'repository MIT license' "$FIXTURE/NOTICES.md" || { echo 'BLOCKED: repository MIT grant missing' >&2; exit 1; }
grep -iq 'no bundled assets' "$FIXTURE/NOTICES.md" || { echo 'BLOCKED: asset inventory missing' >&2; exit 1; }
grep -q 'not admitted' "$FIXTURE/NOTICES.md" || { echo 'BLOCKED: candidate disposition missing' >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/genewhip-independent-game.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
bash "$FIXTURE/toolchain/build-binutils.sh" --verify-lock --output "$TMP/tool"
AS="$TMP/tool/m68k-elf-as"
AS_SHA=$(shasum -a 256 "$AS" | awk '{print $1}')
SRC_SHA=$(shasum -a 256 "$FIXTURE/src/game.s" | awk '{print $1}')
BUILD_SHA=$(shasum -a 256 "$FIXTURE/build.sh" | awk '{print $1}')
VALIDATOR_SHA=$(shasum -a 256 "$VALIDATOR" | awk '{print $1}')
NOTICE_SHA=$(shasum -a 256 "$FIXTURE/NOTICES.md" | awk '{print $1}')
for n in one two; do
  mkdir "$TMP/$n"
  (cd "$TMP/$n" && "$AS" -o game.o "$FIXTURE/src/game.s") || { echo "BLOCKED: clean $n assembly failed" >&2; exit 1; }
  python3 - "$TMP/$n/game.o" "$TMP/$n/game.bin" <<'PY'
import pathlib, struct, sys
obj,out=map(pathlib.Path,sys.argv[1:]); b=obj.read_bytes()
if b[:7] != b"\x7fELF\x01\x02\x01": raise SystemExit("BLOCKED: expected big-endian ELF32 object")
fields=struct.unpack_from(">HHIIIIIHHHHHH",b,16)
if fields[1] != 4: raise SystemExit("BLOCKED: object machine is not Motorola 68000")
shoff,shentsize,shnum,shstrndx=fields[5],fields[10],fields[11],fields[12]
if shentsize != 40 or shstrndx >= shnum: raise SystemExit("BLOCKED: malformed ELF section table")
sections=[struct.unpack_from(">IIIIIIIIII",b,shoff+i*shentsize) for i in range(shnum)]
names_header=sections[shstrndx]; names=b[names_header[4]:names_header[4]+names_header[5]]
def section_name(offset):
 end=names.find(b"\0",offset)
 return names[offset:end].decode("ascii")
text=[(i,s) for i,s in enumerate(sections) if section_name(s[0])==".text"]
if len(text)!=1 or text[0][1][1]!=1: raise SystemExit("BLOCKED: missing or malformed .text section")
index,s=text[0]
if any(x[1] in (4,9) and x[7]==index for x in sections): raise SystemExit("BLOCKED: unresolved text relocations remain")
image=b[s[4]:s[4]+s[5]]
if len(image)!=0x4000: raise SystemExit("BLOCKED: assembled .text image is not exactly 16 KiB")
out.write_bytes(image)
PY
  [ -s "$TMP/$n/game.bin" ] || { echo "BLOCKED: clean $n assembly produced no bytes" >&2; exit 1; }
done
ROM_SHA_ONE=$(shasum -a 256 "$TMP/one/game.bin" | awk '{print $1}')
ROM_SHA_TWO=$(shasum -a 256 "$TMP/two/game.bin" | awk '{print $1}')
[ "$ROM_SHA_ONE" = "$ROM_SHA_TWO" ] || { echo "BLOCKED: clean candidate ROM builds differ: $ROM_SHA_ONE != $ROM_SHA_TWO" >&2; exit 1; }
python3 - "$TMP/one/game.bin" <<'PY'
import pathlib, struct, sys
b=pathlib.Path(sys.argv[1]).read_bytes()
if len(b) != 0x4000 or len(b) & 1: raise SystemExit('BLOCKED: ROM must be an even, exact 16 KiB image')
sp,pc=struct.unpack_from('>II',b,0)
if not 0x00ff0000 <= sp <= 0x01000000: raise SystemExit('BLOCKED: initial stack is outside work RAM')
if pc < 0x200 or pc >= len(b) or pc & 1: raise SystemExit('BLOCKED: reset vector is invalid')
if b[0x100:0x104] != b'SEGA': raise SystemExit('BLOCKED: console header signature missing')
if struct.unpack_from('>I',b,0x1a0)[0] != 0: raise SystemExit('BLOCKED: ROM start header mismatch')
if struct.unpack_from('>I',b,0x1a4)[0] != len(b)-1: raise SystemExit('BLOCKED: ROM end header mismatch')
if any(b[0x1a8:0x1b0]): raise SystemExit('BLOCKED: candidate advertises cartridge SRAM')
if b[0x1f0:0x1f3] != b'JUE': raise SystemExit('BLOCKED: expected NTSC-U/Europe/Japan region declaration missing')
print('PASS: ROM structure, reset vectors, 16 KiB bounds and region header')
PY
mkdir -p "$(dirname "$OUTPUT")"
cp "$TMP/one/game.bin" "$OUTPUT"
OUT_SHA=$(shasum -a 256 "$OUTPUT" | awk '{print $1}')
[ "$OUT_SHA" = "$ROM_SHA_ONE" ] || { rm -f "$OUTPUT"; echo 'BLOCKED: published candidate bytes changed during copy' >&2; exit 1; }
python3 - "$LOCK" "$SRC_SHA" "$BUILD_SHA" "$VALIDATOR_SHA" "$NOTICE_SHA" "$AS_SHA" "$ROM_SHA_ONE" <<'PY'
import json, pathlib, sys
lock,src,build,validator,notice,assembler,rom=sys.argv[1:]
d=json.loads(pathlib.Path(lock).read_text())['assembler']
print(json.dumps({'rights':'pass: solely authored, repository MIT, asset-free candidate','notice_sha256':notice,'source_sha256':src,'build_script_sha256':build,'validator_sha256':validator,'assembler_sha256':assembler,'archive_sha256':d['source_archive_sha256'],'signature_sha256':d['signature']['sha256'],'keyring_sha256':d['signature']['keyring_sha256'],'rom_sha256':rom,'rom_bytes':16384,'clean_builds':'pass: two clean builds are byte-identical','disposition':'candidate; not admitted'},sort_keys=True))
PY
