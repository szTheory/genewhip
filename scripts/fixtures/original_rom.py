#!/usr/bin/env python3
"""Extract the .text image of an ELF32 m68k (big-endian) or Z80 (little-endian) object as a padded ROM.

Usage: original_rom.py extract OBJ OUT SIZE [--machine m68k|z80]
Z80 accepts SIZE=auto for the exact unpadded .text length.
Rejects unresolved text relocations, a .text larger than SIZE, any other non-empty
allocatable section (.data, .rodata, ...; they would silently vanish from the ROM) and
malformed objects, each with a BLOCKED: message. Pads with zero.
"""
import argparse
import pathlib
import struct
import sys


SHF_ALLOC = 0x2
SHT_PROGBITS, SHT_NOBITS = 1, 8


def extract(obj: pathlib.Path, size: int | None, machine: str = "m68k") -> bytes:
    try:
        return _extract(obj, size, machine)
    except (struct.error, IndexError, UnicodeDecodeError, OSError) as error:
        raise SystemExit(f"BLOCKED: malformed object ({type(error).__name__})")


def _extract(obj: pathlib.Path, size: int | None, machine: str) -> bytes:
    b = obj.read_bytes()
    # GNU Binutils 2.47 include/elf/common.h: EM_Z80 = 220 (0xDC);
    # the planned 0x69 is EM_MSP430 and must not be accepted as Z80.
    endian, encoding, number, label = ("<", 1, 0xDC, "Z80") if machine == "z80" else (">", 2, 4, "Motorola 68000")
    if b[:7] != b"\x7fELF\x01" + bytes([encoding, 1]):
        raise SystemExit("BLOCKED: expected " + ("little" if machine == "z80" else "big") + "-endian ELF32 object")
    fields = struct.unpack_from(endian + "HHIIIIIHHHHHH", b, 16)
    if fields[1] != number:
        raise SystemExit("BLOCKED: object machine is not " + label)
    shoff, shentsize, shnum, shstrndx = fields[5], fields[10], fields[11], fields[12]
    if shentsize != 40 or shstrndx >= shnum or shoff + shnum * shentsize > len(b):
        raise SystemExit("BLOCKED: malformed ELF section table")
    sections = [struct.unpack_from(endian + "IIIIIIIIII", b, shoff + i * shentsize) for i in range(shnum)]
    names_header = sections[shstrndx]
    if names_header[4] + names_header[5] > len(b):
        raise SystemExit("BLOCKED: section name table lies outside the object")
    names = b[names_header[4]:names_header[4] + names_header[5]]

    def section_name(offset: int) -> str:
        end = names.find(b"\0", offset)
        if offset >= len(names) or end < 0:
            raise SystemExit("BLOCKED: malformed section name")
        return names[offset:end].decode("ascii")

    text = [(i, s) for i, s in enumerate(sections) if section_name(s[0]) == ".text"]
    if len(text) != 1 or text[0][1][1] != SHT_PROGBITS:
        raise SystemExit("BLOCKED: missing or malformed .text section")
    index, s = text[0]
    if s[3] != 0:
        raise SystemExit("BLOCKED: .text must start at address zero")
    if s[4] + s[5] > len(b):
        raise SystemExit("BLOCKED: .text lies outside the object")
    for i, other in enumerate(sections):
        if i != index and other[1] in (SHT_PROGBITS, SHT_NOBITS) and other[2] & SHF_ALLOC and other[5]:
            raise SystemExit(f"BLOCKED: non-empty section {section_name(other[0])} would be dropped; "
                             "ROM sources may only use .text")
    if any(x[1] in (4, 9) and x[7] == index for x in sections):
        raise SystemExit("BLOCKED: unresolved text relocations remain")
    image = b[s[4]:s[4] + s[5]]
    if size is None:
        return image
    if len(image) > size:
        raise SystemExit(f"BLOCKED: assembled .text ({len(image)} bytes) exceeds image size {size}")
    return image + bytes(size - len(image))


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["extract"])
    parser.add_argument("obj", type=pathlib.Path)
    parser.add_argument("out", type=pathlib.Path)
    parser.add_argument("size")
    parser.add_argument("--machine", choices=["m68k", "z80"], default="m68k")
    args = parser.parse_args(argv[1:])
    try:
        size = None if args.machine == "z80" and args.size == "auto" else int(args.size, 0)
    except ValueError:
        raise SystemExit("BLOCKED: SIZE must be an integer")
    if size is not None and (size <= 0 or (args.machine == "m68k" and size % 2)):
        raise SystemExit("BLOCKED: SIZE must be a positive even number")
    args.out.write_bytes(extract(args.obj, size, args.machine))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
