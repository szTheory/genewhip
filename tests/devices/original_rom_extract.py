"""Contract for scripts/fixtures/original_rom.py on synthetic big-endian ELF32 m68k objects.

Usage: original_rom_extract.py REPOSITORY_ROOT. The extractor must keep a .text image, and
fail closed with a BLOCKED: message for a non-empty allocatable section other than .text
and for malformed objects, never a traceback.
"""
import pathlib
import struct
import subprocess
import sys
import tempfile


def elf(sections, text=b"\x4e\x71" * 4):
    """sections: list of (name, type, flags, payload). Index 0 is the null section."""
    names = b"\0"
    entries = [(0, 0, 0, 0, 0)]
    data = b""
    base = 52
    for name, kind, flags, payload in sections:
        entries.append((len(names), kind, flags, base + len(data), len(payload)))
        names += name.encode() + b"\0"
        data += payload
    strtab_name = len(names)
    names += b".shstrtab\0"
    entries.append((strtab_name, 3, 0, base + len(data), len(names)))
    data += names
    shoff = base + len(data)
    header = b"\x7fELF\x01\x02\x01" + bytes(9) + struct.pack(
        ">HHIIIIIHHHHHH", 1, 4, 1, 0, 0, shoff, 0, 52, 0, 0, 40, len(entries), len(entries) - 1)
    table = b"".join(struct.pack(">IIIIIIIIII", n, t, f, 0, o, s, 0, 0, 1, 0) for n, t, f, o, s in entries)
    return header + data + table


def extract(root, blob, size=64):
    with tempfile.TemporaryDirectory() as tmp:
        obj, out = pathlib.Path(tmp, "a.o"), pathlib.Path(tmp, "a.bin")
        obj.write_bytes(blob)
        run = subprocess.run([sys.executable, "-I", str(root / "scripts/fixtures/original_rom.py"),
                              "extract", str(obj), str(out), str(size)], capture_output=True, text=True)
        return run.returncode, run.stderr, out.read_bytes() if out.exists() else None


def main(argv):
    root = pathlib.Path(argv[1])
    text = (".text", 1, 6, b"\x4e\x71" * 4)
    rc, err, rom = extract(root, elf([text, (".data", 1, 3, b""), (".bss", 8, 3, b"")]))
    assert rc == 0 and rom == b"\x4e\x71" * 4 + bytes(56), (rc, err)
    for name, kind, flags in ((".data", 1, 3), (".rodata", 1, 2), (".bss", 8, 3)):
        rc, err, _ = extract(root, elf([text, (name, kind, flags, b"\x12\x34")]))
        assert rc == 1 and err.startswith("BLOCKED:") and name in err and "Traceback" not in err, (name, rc, err)
    good = elf([text])
    for label, blob in (("empty", b""), ("truncated header", good[:30]), ("truncated table", good[:-20]),
                        ("bad magic", b"MZ" + good[2:])):
        rc, err, _ = extract(root, blob)
        assert rc == 1 and err.startswith("BLOCKED:") and "Traceback" not in err, (label, rc, err)
    print("PASS: original_rom_extract")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
