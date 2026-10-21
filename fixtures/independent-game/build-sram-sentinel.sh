#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
FIXTURE="$ROOT/fixtures/independent-game"
OUTPUT=
if [ "${1:-}" != "--output" ] || [ -z "${2:-}" ]; then
  printf 'usage: %s --output <path>\n' "$0" >&2
  exit 2
fi
OUTPUT=$2
TMP=$(mktemp -d "${TMPDIR:-/tmp}/genewhip-sram-sentinel.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
bash "$FIXTURE/toolchain/build-binutils.sh" --verify-lock --output "$TMP/tool"
"$TMP/tool/m68k-elf-as" -o "$TMP/sentinel.o" "$FIXTURE/src/sram_sentinel.s"
python3 - "$TMP/sentinel.o" "$TMP/sentinel.bin" <<'PY'
import pathlib, struct, sys
obj, out = map(pathlib.Path, sys.argv[1:]); data = obj.read_bytes()
if data[:7] != b"\x7fELF\x01\x02\x01": raise SystemExit("BLOCKED: sentinel object is not big-endian ELF32")
fields = struct.unpack_from(">HHIIIIIHHHHHH", data, 16)
if fields[1] != 4: raise SystemExit("BLOCKED: sentinel object is not Motorola 68000")
shoff, shentsize, shnum, shstrndx = fields[5], fields[10], fields[11], fields[12]
if shentsize != 40 or shstrndx >= shnum: raise SystemExit("BLOCKED: malformed sentinel ELF section table")
sections = [struct.unpack_from(">IIIIIIIIII", data, shoff + i * shentsize) for i in range(shnum)]
names_header = sections[shstrndx]; names = data[names_header[4]:names_header[4] + names_header[5]]
def section_name(offset): return names[offset:names.find(b"\0", offset)].decode("ascii")
text = [(i, section) for i, section in enumerate(sections) if section_name(section[0]) == ".text"]
if len(text) != 1 or text[0][1][1] != 1: raise SystemExit("BLOCKED: sentinel .text section missing")
index, section = text[0]
if any(item[1] in (4, 9) and item[7] == index for item in sections): raise SystemExit("BLOCKED: sentinel contains unresolved text relocations")
image = data[section[4]:section[4] + section[5]]
if len(image) != 0x4000: raise SystemExit("BLOCKED: sentinel ROM is not exactly 16 KiB")
if image[0x100:0x104] != b"SEGA" or any(image[0x1a8:0x1b0]): raise SystemExit("BLOCKED: malformed sentinel header or advertised SRAM")
if b"JUE" not in image[0x1f0:0x200]: raise SystemExit("BLOCKED: sentinel region header is not NTSC-U capable")
out.write_bytes(image)
PY
mkdir -p "$(dirname "$OUTPUT")"
cp "$TMP/sentinel.bin" "$OUTPUT"
printf 'PASS: authored SRAM/control sentinel ROM sha256=%s\n' "$(shasum -a 256 "$OUTPUT" | awk '{print $1}')"
