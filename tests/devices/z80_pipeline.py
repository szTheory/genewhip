#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the real nested Z80/68000 build in a clean repository-shaped root."""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    assemblers = {}
    for cpu in ('z80', 'm68k'):
        run = subprocess.run(['bash', str(ROOT / f'scripts/fixtures/{cpu}-as.sh')],
                             capture_output=True, text=True)
        if run.returncode:
            print('SKIP: pinned assembler unavailable for nested ROM pipeline')
            return 77
        assemblers[cpu] = run.stdout.strip()
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        for name in ('scripts/fixtures/build-original-roms.sh', 'scripts/fixtures/original_rom.py',
                     'scripts/fixtures/z80-as.sh', 'scripts/fixtures/m68k-as.sh',
                     'fixtures/independent-game/toolchain.lock', 'tests/devices/roms/z80/smoke.s'):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        cache = root / 'build/tool-cache'
        cache.mkdir(parents=True)
        for cpu, path in assemblers.items():
            shutil.copy2(path, cache / (cpu + '-elf-as'))
        source = root / 'tests/devices/roms/nested.s'
        source.write_text('.cpu 68000\n.text\n.long 0x00ffff00\n.long 0x200\n.org 0x200\n.include "tests/devices/roms/z80/driver.inc"\n')
        doc = {'fixtures': [{'kind': 'original-rom', 'source': 'tests/devices/roms/nested.s',
                            'rom': 'tests/devices/roms/nested.bin', 'rom_bytes': 1024,
                            'build': {'name': 'nested', 'z80_source': 'tests/devices/roms/z80/smoke.s',
                                      'z80_include': 'tests/devices/roms/z80/driver.inc'}}]}
        (root / 'fixtures/manifest.json').write_text(json.dumps(doc))
        script = root / 'scripts/fixtures/build-original-roms.sh'
        subprocess.run(['bash', str(script), '--update', 'nested'], check=True)
        data = (root / 'tests/devices/roms/nested.bin').read_bytes()
        assert data[0x200:0x206] == bytes.fromhex('00 3e 42 c3 34 12'), 'nested Z80 bytes mismatch'
        subprocess.run(['bash', str(script), '--verify-reproducible', 'nested'], check=True)
        include = root / 'tests/devices/roms/z80/driver.inc'
        include.write_text(include.read_text() + '\n.byte 0\n')
        altered = include.read_bytes()
        run = subprocess.run(['bash', str(script), '--verify-reproducible', 'nested'], capture_output=True, text=True)
        assert run.returncode != 0 and 'z80 include differs' in run.stderr, 'wrong include rejection'
        assert include.read_bytes() == altered, 'verify mutated committed include'
        doc['fixtures'][0]['build']['z80_include'] = '../escape.inc'
        (root / 'fixtures/manifest.json').write_text(json.dumps(doc))
        run = subprocess.run(['bash', str(script), '--update', 'nested'], capture_output=True, text=True)
        assert run.returncode != 0 and 'invalid Z80 stage path' in run.stderr, 'wrong traversal rejection'
    print('PASS: nested Z80 ROM bytes, reproducibility, changed include and path rejection')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
