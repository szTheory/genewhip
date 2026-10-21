#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare real z80-elf assembly with Zilog UM0080 instruction table bytes.

NOP=00, LD A,n=3E n, JP nn=C3 low high, per Z80 CPU User Manual
UM0080 instruction descriptions. Negative control alters the LD opcode only.
"""
import importlib.util
import pathlib
import struct
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def extractor_contract():
    # Independent minimal ELF32/LE fixture exercises rejection even on hosts
    # where the signed assembler cannot be built.
    spec = importlib.util.spec_from_file_location("original_rom", ROOT / "scripts/fixtures/original_rom.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    text = bytes.fromhex("00 3E 42 C3 34 12")
    names = b"\0.text\0.shstrtab\0"
    shoff = 52 + len(text) + len(names)
    header = b"\x7fELF\x01\x01\x01" + bytes(9) + struct.pack(
        "<HHIIIIIHHHHHH", 1, 0xDC, 1, 0, 0, shoff, 0, 52, 0, 0, 40, 3, 2)
    table = bytes(40) + struct.pack("<IIIIIIIIII", 1, 1, 6, 0, 52, 6, 0, 0, 1, 0)
    table += struct.pack("<IIIIIIIIII", 7, 3, 0, 0, 58, len(names), 0, 0, 1, 0)
    blob = header + text + names + table
    with tempfile.TemporaryDirectory() as tmp:
        obj = pathlib.Path(tmp, "test.o")
        obj.write_bytes(blob)
        if module.extract(obj, 8, "z80") != text + bytes(2):
            raise ValueError("Z80 extraction/padding differs")
        for label, bad, expected in (
            ("planned wrong machine", blob[:18] + bytes([0x69, 0]) + blob[20:], "object machine is not Z80"),
            ("machine", blob[:18] + bytes([4, 0]) + blob[20:], "object machine is not Z80"),
            ("endian", blob[:5] + bytes([2]) + blob[6:], "expected little-endian ELF32"),
            ("truncated", blob[:30], "malformed object"),
        ):
            obj.write_bytes(bad)
            try:
                module.extract(obj, 8, "z80")
            except SystemExit as exc:
                if expected not in str(exc):
                    raise ValueError("wrong extractor rejection: " + label)
            else:
                raise ValueError("extractor accepted " + label)
    print("PASS: Z80 extractor padding and named machine/endian/truncation rejections")


def main():
    extractor_contract()
    assembler = subprocess.run(["bash", str(ROOT / "scripts/fixtures/z80-as.sh")],
                               capture_output=True, text=True)
    if assembler.returncode == 77:
        print("SKIP: pinned z80 assembler unavailable")
        return 77
    if assembler.returncode:
        print("FAIL: assembler locator failed", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        outputs = []
        for name in ("one", "two"):
            work = pathlib.Path(tmp, name)
            work.mkdir()
            subprocess.run([assembler.stdout.strip(), "-o", "smoke.o",
                            str(ROOT / "tests/devices/roms/z80/smoke.s")], cwd=work, check=True)
            subprocess.run([sys.executable, "-I", str(ROOT / "scripts/fixtures/original_rom.py"),
                            "extract", "smoke.o", "smoke.bin", "6", "--machine", "z80"], cwd=work, check=True)
            outputs.append((work / "smoke.bin").read_bytes())
        if outputs[0] != outputs[1]:
            raise ValueError("clean z80 builds differ")
        expected = bytes.fromhex("00 3E 42 C3 34 12")
        negative = "--negative-control" in sys.argv
        if negative:
            expected = bytes.fromhex("00 3F 42 C3 34 12")
        mismatch = outputs[0] != expected
        if negative and mismatch:
            print("PASS: negative control rejected: z80 bytes mismatch")
            return 0
        if mismatch or negative:
            raise ValueError("z80 bytes mismatch" if mismatch else "negative control was accepted")
    print("PASS: reproducible Z80 bytes match hand-encoded Zilog opcodes")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
