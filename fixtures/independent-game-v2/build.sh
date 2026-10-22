#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
FIXTURE="$ROOT/fixtures/independent-game-v2"
VALIDATOR="$ROOT/tests/evidence/independent_game_toolchain.py"
LOCK=${GENEWHIP_TOOLCHAIN_LOCK:-$FIXTURE/toolchain.lock}
OUTPUT=${GENEWHIP_CANDIDATE_PATH:-$FIXTURE/game.bin}

case "${1:-}" in
  --validate-only) exec python3 "$VALIDATOR" --validate-lock "$LOCK" ;;
  --verify-reproducible) ;;
  *) printf 'BLOCKED: usage: %s --verify-reproducible|--validate-only\n' "$0" >&2; exit 2 ;;
esac

python3 "$VALIDATOR" --validate-lock "$LOCK"
[ -f "$FIXTURE/src/game.s" ] || { echo 'BLOCKED: authored game source is missing' >&2; exit 1; }
grep -q 'solely authored for Genewhip' "$FIXTURE/NOTICES.md" || { echo 'BLOCKED: authorship notice missing' >&2; exit 1; }
grep -q 'repository MIT license' "$FIXTURE/NOTICES.md" || { echo 'BLOCKED: MIT grant missing' >&2; exit 1; }
grep -iq 'no bundled assets' "$FIXTURE/NOTICES.md" || { echo 'BLOCKED: asset inventory missing' >&2; exit 1; }
grep -q 'candidate; not admitted' "$FIXTURE/NOTICES.md" || { echo 'BLOCKED: candidate disposition missing' >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/genewhip-independent-game-v2.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
AS=${GENEWHIP_M68K_AS:-$ROOT/build/tool-cache/m68k-elf-as}
[ -x "$AS" ] || { echo 'BLOCKED: locked M68K assembler is unavailable in the verified local tool cache' >&2; exit 1; }
[ "$(shasum -a 256 "$AS" | awk '{print $1}')" = "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["assembler"]["executable"]["sha256"])' "$LOCK")" ] || { echo 'BLOCKED: assembler identity differs from v2 toolchain lock' >&2; exit 1; }
for n in one two; do
  mkdir "$TMP/$n"
  (cd "$TMP/$n" && "$AS" -o game.o "$FIXTURE/src/game.s")
  python3 - "$TMP/$n/game.o" "$TMP/$n/game.bin" <<'PY'
import pathlib, struct, sys
obj, out = map(pathlib.Path, sys.argv[1:])
b = obj.read_bytes()
if b[:7] != b"\x7fELF\x01\x02\x01": raise SystemExit("BLOCKED: expected big-endian ELF32 object")
fields = struct.unpack_from(">HHIIIIIHHHHHH", b, 16)
if fields[1] != 4: raise SystemExit("BLOCKED: object machine is not Motorola 68000")
shoff, shentsize, shnum, shstrndx = fields[5], fields[10], fields[11], fields[12]
if shentsize != 40 or shstrndx >= shnum: raise SystemExit("BLOCKED: malformed ELF section table")
sections = [struct.unpack_from(">IIIIIIIIII", b, shoff + i * shentsize) for i in range(shnum)]
names_section = sections[shstrndx]
names = b[names_section[4]:names_section[4] + names_section[5]]
def section_name(offset): return names[offset:names.find(b"\0", offset)].decode("ascii")
text = [(i, section) for i, section in enumerate(sections) if section_name(section[0]) == ".text"]
if len(text) != 1 or text[0][1][1] != 1: raise SystemExit("BLOCKED: missing or malformed .text section")
index, section = text[0]
if any(item[1] in (4, 9) and item[7] == index for item in sections): raise SystemExit("BLOCKED: unresolved text relocations remain")
image = b[section[4]:section[4] + section[5]]
if len(image) != 0x4000: raise SystemExit("BLOCKED: assembled image is not exactly 16 KiB")
out.write_bytes(image)
PY
done
python3 - "$TMP/one/game.bin" "$TMP/two/game.bin" <<'PY'
import hashlib, pathlib, struct, sys
one, two = (pathlib.Path(p).read_bytes() for p in sys.argv[1:])
if hashlib.sha256(one).digest() != hashlib.sha256(two).digest(): raise SystemExit("BLOCKED: clean ROM builds differ")
if len(one) != 0x4000 or len(one) & 1: raise SystemExit("BLOCKED: ROM size is outside exact 16 KiB bounds")
sp, pc = struct.unpack_from(">II", one)
if not 0x00ff0000 <= sp <= 0x01000000: raise SystemExit("BLOCKED: initial stack is outside work RAM")
if pc < 0x200 or pc >= len(one) or pc & 1: raise SystemExit("BLOCKED: reset vector is invalid")
if one[0x100:0x104] != b"SEGA": raise SystemExit("BLOCKED: console header signature missing")
if struct.unpack_from(">I", one, 0x1a0)[0] != 0 or struct.unpack_from(">I", one, 0x1a4)[0] != len(one) - 1: raise SystemExit("BLOCKED: ROM header bounds mismatch")
if any(one[0x1a8:0x1b0]): raise SystemExit("BLOCKED: candidate advertises cartridge SRAM")
if one[0x1f0:0x1f3] != b"JUE": raise SystemExit("BLOCKED: expected JUE region declaration missing")
print("PASS: two clean ROM builds match; 16 KiB structure, vectors, headers and SRAM declaration valid")
PY
mkdir -p "$(dirname "$OUTPUT")"
cp "$TMP/one/game.bin" "$OUTPUT"
[ "$(shasum -a 256 "$OUTPUT" | awk '{print $1}')" = "$(shasum -a 256 "$TMP/one/game.bin" | awk '{print $1}')" ] || { echo 'BLOCKED: canonical ROM changed during write' >&2; exit 1; }
python3 - "$FIXTURE/src/game.s" "$FIXTURE/build.sh" "$FIXTURE/NOTICES.md" "$LOCK" "$AS" "$OUTPUT" <<'PY'
import hashlib, json, pathlib, sys
source, build, notices, lock, assembler, rom = map(pathlib.Path, sys.argv[1:])
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
tool = json.loads(lock.read_text())["assembler"]
print(json.dumps({"rights":"pass: original authored source, repository MIT, no assets",
 "source_sha256":digest(source),"build_script_sha256":digest(build),
 "notice_sha256":digest(notices),"toolchain_lock_sha256":digest(lock),
 "assembler_sha256":digest(assembler),"archive_sha256":tool["source_archive_sha256"],
 "rom_sha256":digest(rom),"rom_bytes":rom.stat().st_size,
 "clean_builds":"pass: two clean builds are byte-identical",
 "disposition":"candidate; not admitted"},sort_keys=True))
PY
