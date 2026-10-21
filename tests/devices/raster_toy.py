#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent pixel oracle for the Genewhip raster toy (plan GW-02-11).

Usage: raster_toy.py ROOT GW_HEADLESS [--test planes|scroll|sprites] [--negative-control]

Expected pixels are computed from the constants in fixtures/raster-toy/scenario.json and
the documented tile (4 bpp, 32 bytes, leftmost pixel in the high nibble), name-table
(priority 15, palette 14-13, V-flip 12, H-flip 11, tile 10-0), CRAM word
(0000 BBB0 GGG0 RRR0) and XRGB conventions of docs/video.md. Genewhip output is only
the thing being compared; it never supplies an expectation.

The sprites test (plan GW-02-12) writes the scenario's "inputs" as a genewhip-input-log 1 file,
replays it through gw_headless and compares each sampled field with the sprite position
computed from the scenario alone: start + step * (sum over handler runs c <= field of the
directions held at run c), where run c observes the last input entry whose field is <= c - 1.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

LEVELS = [0, 27, 49, 71, 87, 103, 119, 130, 146, 157, 174, 190, 206, 228, 255]


def cram_to_xrgb(word, intensity="normal"):
    """Genewhip convention (assumption A5): normal L[2v], shadow L[v], highlight L[v + 7]."""
    def level(v):
        return LEVELS[{"normal": 2 * v, "shadow": v, "highlight": v + 7}[intensity]]
    r = level((word >> 1) & 7)
    g = level((word >> 5) & 7)
    b = level((word >> 9) & 7)
    return (r << 16) | (g << 8) | b


def pack_tile(rows):
    out = bytearray()
    for row in rows:
        for x in range(0, 8, 2):
            out.append((row[x] << 4) | row[x + 1])
    return bytes(out)


class Model:
    """Builds the VRAM/CRAM image the toy's code leaves behind and renders sampled pixels."""

    def __init__(self, scenario, palette_override=None):
        self.sc = scenario
        self.cram = list(scenario["palette"]["words"])
        for index, word in (palette_override or {}).items():
            self.cram[index] = word
        self.tiles = b"".join(pack_tile(t) for t in scenario["tiles"]["pixels"])
        self.table_b = self.build_plane_b()
        self.table_a = self.build_plane_a()
        self.table_w = self.build_window()
        # Cell-mode table in the documented line layout (4 bytes per line, plane A then B): the
        # entry for cell k = y >> 3 sits at line 8k; the other seven slots hold decoy words.
        self.cell = b"".join(
            ((6 * ((y >> 3) & 3)).to_bytes(2, "big") + (5 * (y >> 3) + 3).to_bytes(2, "big")) if y % 8 == 0
            else (0x155).to_bytes(2, "big") + (0x2aa).to_bytes(2, "big")
            for y in range(224))
        self.line = b"".join(((1024 - (y & 15)) & 0x3ff).to_bytes(2, "big") + ((3 * y + 7) & 0x3ff).to_bytes(2, "big")
                             for y in range(224))
        self.vs2 = [v for k in range(20) for v in (9 * k, 13 * k + 3)]

    @staticmethod
    def build_plane_b():
        out = bytearray()
        for row in range(32):
            for col in range(64):
                if 20 <= row <= 23:
                    entry = 0
                else:
                    entry = (((col >> 4) & 3) << 13) + 1 + ((col + row) & 3)
                    if 10 <= row <= 13 and 14 <= col <= 29:
                        entry += 0x8000
                out += entry.to_bytes(2, "big")
        return bytes(out)

    @staticmethod
    def build_plane_a():
        out = bytearray()
        for row in range(32):
            for col in range(64):
                e = 0
                if 4 <= row <= 7 and 4 <= col <= 9:
                    e = 5 + (1 << 13) + ((col & 1) << 11) + ((row & 1) << 12)
                if 10 <= row <= 11 and 10 <= col <= 19:
                    e = 6 + (2 << 13)
                if 12 <= row <= 13 and 10 <= col <= 19:
                    e = 6 + (2 << 13) + 0x8000
                if 20 <= row <= 21 and 20 <= col <= 27:
                    e = 5 + (3 << 13)
                out += e.to_bytes(2, "big")
        return bytes(out)

    @staticmethod
    def build_window():
        out = bytearray()
        for row in range(3):
            for col in range(64):
                out += ((3 << 13) + 5 + ((col + row) & 1)).to_bytes(2, "big")
        return bytes(out)

    def rom_image_ok(self, rom):
        off = self.sc["rom_offsets"]
        pal = b"".join(w.to_bytes(2, "big") for w in self.sc["palette"]["words"])
        blocks = [("palette", pal), ("tiles", self.tiles), ("plane_b", self.table_b), ("plane_a", self.table_a),
                  ("window", self.table_w), ("hscroll_cell", self.cell), ("hscroll_line", self.line),
                  ("vscroll_2cell", b"".join(v.to_bytes(2, "big") for v in self.vs2))]
        for name, want in blocks:
            at = int(off[name], 0)
            if rom[at:at + len(want)] != want:
                return "ROM block %s differs from the scenario-derived bytes" % name
        return None

    def state(self, s):
        """Register and table state the toy leaves for the field with sequence s (c = s)."""
        c = s
        vram = bytearray(65536)
        vram[0:len(self.tiles)] = self.tiles
        vram[0xE000:0xE000 + len(self.table_b)] = self.table_b
        vram[0xC000:0xC000 + len(self.table_a)] = self.table_a
        vram[0xA000:0xA000 + len(self.table_w)] = self.table_w
        # Start-up writes both sprite entries off screen (Y = 0, X = 0); inputs rewrite them later.
        for n, item in enumerate(self.sc["sprites"]["items"]):
            at = int(item["entry_vram"], 0)
            link = 1 if n + 1 < len(self.sc["sprites"]["items"]) else 0
            pattern = 0x8000 + (item["palette_line"] << 13) + 7
            vram[at:at + 8] = b"".join(w.to_bytes(2, "big") for w in (0, link, pattern, 0))
        vsram = [0] * 40
        reg11 = 0
        if c < 16:
            vram[0xB802:0xB804] = ((3 * c) & 0xffff).to_bytes(2, "big")
        if c >= 16:
            reg11 = 2
            vram[0xB800:0xB800 + len(self.cell)] = self.cell
        if c >= 32:
            reg11 = 7
            vram[0xB800:0xB800 + len(self.line)] = self.line
            vsram = list(self.vs2)
        else:
            vsram[0] = 2 * c
        reg16 = 1 if c < 48 else (0 if c < 64 else 3)
        cells = {0: 32, 1: 64, 3: 128}
        band = self.sc["shadow_band"]
        return {"sh": c >= band["from_count"], "vram": vram, "vsram": vsram, "reg11": reg11,
                "w": cells[reg16 & 3], "h": cells[(reg16 >> 4) & 3]}

    @staticmethod
    def word(vram, addr):
        return (vram[addr & 0xffff] << 8) | vram[(addr + 1) & 0xffff]

    def hscroll(self, st, plane, y):
        mode = st["reg11"] & 3
        entry = y * 4 if mode == 3 else (y & ~7) * 4 if mode == 2 else 0
        return self.word(st["vram"], 0xB800 + entry + plane * 2) & 0x3ff

    def vscroll(self, st, plane, x):
        index = (x >> 4) * 2 + plane if st["reg11"] & 4 else plane
        return st["vsram"][index] & 0x3ff

    def tile_px(self, vram, entry, px, py):
        row = 7 - (py & 7) if entry & 0x1000 else py & 7
        col = 7 - (px & 7) if entry & 0x0800 else px & 7
        byte = vram[((entry & 0x7ff) * 32 + row * 4 + (col >> 1)) & 0xffff]
        nib = byte & 15 if col & 1 else byte >> 4
        return (((entry >> 9) & 0x30) + nib if nib else 0), entry

    def plane(self, st, base, plane, x, y):
        w, h = st["w"], st["h"]
        px = (x - self.hscroll(st, plane, y)) % (w * 8)
        py = (y + self.vscroll(st, plane, x)) % (h * 8)
        entry = self.word(st["vram"], base + ((py >> 3) * w + (px >> 3)) * 2)
        return self.tile_px(st["vram"], entry, px, py)

    def pixel(self, st, x, y):
        """Returns (XRGB, tags). Window: rows above line 24 (register 18 = 3, register 17 = 0)."""
        if y < 24:
            entry = self.word(st["vram"], 0xA000 + ((y >> 3) * 64 + (x >> 3)) * 2)
            a, ae = self.tile_px(st["vram"], entry, x, y)
            a_kind = "window"
        else:
            a, ae = self.plane(st, 0xC000, 0, x, y)
            a_kind = "A"
        b, be = self.plane(st, 0xE000, 1, x, y)
        a_hi, b_hi = bool(ae & 0x8000), bool(be & 0x8000)
        tags = set()
        if a and a_hi:
            idx, tags = a, {"A-hi"}
            if b and b_hi:
                tags.add("A-hi-over-B-hi")
        elif b and b_hi:
            idx, tags = b, {"B-hi"}
            if a:
                tags.add("B-hi-over-A-lo")
        elif a:
            idx, tags = a, {"A-lo"}
            if b:
                tags.add("A-lo-over-B")
        elif b:
            idx, tags = b, {"B-lo"}
        else:
            idx, tags = 0, {"backdrop"}
        high = bool(tags & {"A-hi", "B-hi"})
        if st["sh"]:
            tags.add("sh-normal" if high else "shadow")
        if idx and idx == a and a_kind == "window":
            tags.add("window")
        if idx:
            tags.add("pal%d" % (idx >> 4))
            src = ae if idx == a else be
            if (src & 0x7ff) == 5:
                if src & 0x0800:
                    tags.add("hflip")
                if src & 0x1000:
                    tags.add("vflip")
        shade = "normal" if not st["sh"] or high else "shadow"
        return cram_to_xrgb(self.cram[idx], shade), tags


def load_field(directory, sequence):
    data = (Path(directory) / ("field-%d.bin" % sequence)).read_bytes()
    meta = json.loads((Path(directory) / ("field-%d.json" % sequence)).read_text())
    return data, meta


def got_pixel(data, x, y):
    o = (y * 320 + x) * 4
    return int.from_bytes(data[o:o + 4], "little")


def compare_frame(model, data, meta, field, tagset):
    label = "field-%d" % field
    if meta["width"] != 320 or meta["height"] != 224 or len(data) != 320 * 224 * 4:
        print("fail %s: unexpected field geometry %r" % (label, meta))
        return False
    st = model.state(field)
    for y in range(224):
        for x in range(320):
            want, tags = model.pixel(st, x, y)
            tagset |= tags
            got = got_pixel(data, x, y)
            if got != want:
                print("fail %s: pixel (%d,%d) got %06x want %06x" % (label, x, y, got, want))
                return False
    print("pass %s: all 71680 pixels" % label)
    return True


def compare_grid(model, data, meta, field, stride):
    st = model.state(field)
    for y in range(1, 224, stride[1]):
        for x in range(3, 320, stride[0]):
            want, _ = model.pixel(st, x, y)
            got = got_pixel(data, x, y)
            if got != want:
                print("fail field-%d grid: pixel (%d,%d) got %06x want %06x" % (field, x, y, got, want))
                return False
    return True


def held_directions(mask):
    """(dx, dy) sign pair for a logical mask: Right +x, Left -x, Down +y, Up -y."""
    return ((1 if mask & 8 else 0) - (1 if mask & 4 else 0), (1 if mask & 2 else 0) - (1 if mask & 1 else 0))


def mask_at(scenario, port, field):
    """Logical mask the log holds for a port at a field (last entry with entry.field <= field)."""
    mask = 0
    for e in scenario["inputs"]["entries"]:
        if e["port"] == port and e["field"] <= field:
            mask = int(e["mask"], 0)
    return mask


def sprite_positions(scenario, item, last_field):
    """Map field -> (x, y) or None (sprite not yet drawn), from the scenario arithmetic only.

    The sprite follows the entries of its own port; the other port's entries never affect it."""
    entries = [e for e in scenario["inputs"]["entries"] if e["port"] == item["port"]]
    x, y = item["start"]
    step = item["step_per_pressed_run"]
    started = False
    out = {0: None}
    for field in range(1, last_field + 1):
        # Handler run c = field observes the last entry with entry.field <= field - 1.
        mask = 0
        for e in entries:
            if e["field"] <= field - 1:
                mask = int(e["mask"], 0)
        dx, dy = held_directions(mask)
        if mask & 15:
            started = True
            x += step * dx
            y += step * dy
        out[field] = (x, y) if started else None
    return out


def run_sprites(root, headless, scenario, rom_path, negative):
    items = scenario["sprites"]["items"]
    lo, hi = [s for s in scenario["samples"] if s["test"] == "sprites"][0]["fields"]
    positions = [sprite_positions(scenario, item, hi) for item in items]
    colours = [cram_to_xrgb(scenario["palette"]["words"][i["palette_line"] * 16 + i["colour"]]) for i in items]
    if len(set(colours)) != len(colours):
        print("fail setup: sprite colours are not distinct")
        return 1
    ticks = scenario["inputs"]["ticks_per_field"]
    if negative:  # Shift every expected start by one pixel: every drawn field must then fail.
        positions = [{f: (p[0] + 1, p[1]) if p else None for f, p in pos.items()} for pos in positions]
    with tempfile.TemporaryDirectory(prefix="gw-raster-toy-") as tmp:
        log = Path(tmp) / "input.log"
        lines = ["genewhip-input-log 1"] + ["%d pad %d %x" % (e["field"] * ticks, e["port"], int(e["mask"], 0))
                                           for e in scenario["inputs"]["entries"]]
        log.write_text("\n".join(lines) + "\n")
        fields_dir = Path(tmp) / "fields"
        fields_dir.mkdir()
        subprocess.run([headless, str(rom_path), "--fields", str(hi + 1), "--replay", str(log),
                        "--dump-fields", str(fields_dir)], check=True, stdout=subprocess.DEVNULL)
        ok_all = True
        seen = [set() for _ in items]
        for field in range(lo, hi + 1):
            data, meta = load_field(fields_dir, field)
            if meta["width"] != 320 or meta["height"] != 224:
                print("fail field-%d: unexpected geometry %r" % (field, meta))
                return 1
            pixels = [got_pixel(data, i % 320, i // 320) for i in range(320 * 224)]
            for n, item in enumerate(items):
                where = positions[n][field]
                hits = [(i % 320, i // 320) for i, p in enumerate(pixels) if p == colours[n]]
                if where is None:
                    good = not hits
                else:
                    x, y = where
                    want = [(x + dx, y + dy) for dy in range(8) for dx in range(8)]
                    good = sorted(hits) == sorted(want)
                    seen[n].add(where)
                if not good:
                    print("fail field-%d sprite %d (port %d): pixels %s, expected %s" % (
                        field, item["sprite"], item["port"] + 1, (min(hits), len(hits)) if hits else "none", where))
                    ok_all = False
            if not ok_all:
                break
        else:
            print("pass sprite positions on fields %d-%d (%s distinct positions per sprite)" % (
                lo, hi, "/".join(str(len(s)) for s in seen)))
        if ok_all:  # Independence: each sprite must have moved while the other port was released.
            for n, item in enumerate(items):
                alone = [f for f in range(lo + 1, hi + 1)
                         if positions[n][f] != positions[n][f - 1] and positions[n][f - 1] is not None
                         and not (mask_at(scenario, 1 - item["port"], f - 1) & 15)]
                if not alone:
                    print("fail coverage: sprite %d never moved while the other port was released" % item["sprite"])
                    ok_all = False
                else:
                    print("pass independence: sprite %d moved on %d fields with the other port released" % (
                        item["sprite"], len(alone)))
    if ok_all and any(len(s) < 8 for s in seen):
        print("fail coverage: only %s distinct sprite positions exercised" % "/".join(str(len(s)) for s in seen))
        ok_all = False
    if negative:
        print("negative control: shifted sprite expectation %s" % ("unexpectedly passed" if ok_all else "failed as required"))
        return 1 if ok_all else 0
    return 0 if ok_all else 1


def model_rom_problem(scenario, rom):
    return Model(scenario).rom_image_ok(rom)


def main(argv):
    negative = "--negative-control" in argv
    which = "planes"
    args = []
    it = iter(argv[1:])
    for a in it:
        if a == "--test":
            which = next(it)
        elif a != "--negative-control":
            args.append(a)
    root, headless = Path(args[0]), args[1]
    scenario = json.loads((root / "fixtures/raster-toy/scenario.json").read_text())
    rom_path = root / scenario["rom"]["path"]
    rom = rom_path.read_bytes()
    if which == "sprites":
        problem = model_rom_problem(scenario, rom)
        if problem:
            print("fail rom-image: " + problem)
            return 1
        return run_sprites(root, headless, scenario, rom_path, negative)
    spec = [s for s in scenario["samples"] if s["test"] == which][0]
    # The negative control alters the expected palette word of line 0, colour 1.
    override = {1: scenario["palette"]["words"][1] ^ 0x0002} if negative else None
    model = Model(scenario, override)
    problem = None if negative else model.rom_image_ok(rom)
    if problem:
        print("fail rom-image: " + problem)
        return 1
    ok_all = True
    tagset = set()
    last = max(spec["full_frames"] + ([spec["grid_fields"][1]] if "grid_fields" in spec else []))
    with tempfile.TemporaryDirectory(prefix="gw-raster-toy-") as tmp:
        subprocess.run([headless, str(rom_path), "--fields", str(last + 1), "--dump-fields", tmp],
                       check=True, stdout=subprocess.DEVNULL)
        frames = {}
        for field in spec["full_frames"]:
            data, meta = load_field(tmp, field)
            frames[field] = data
            ok_all = compare_frame(model, data, meta, field, tagset) and ok_all
        if "grid_fields" in spec and ok_all:
            lo, hi = spec["grid_fields"]
            for field in range(lo, hi + 1):
                data, meta = load_field(tmp, field)
                if not compare_grid(model, data, meta, field, spec["grid_stride"]):
                    ok_all = False
                    break
            else:
                print("pass grid fields %d-%d (stride %r)" % (lo, hi, spec["grid_stride"]))
            lo, hi = spec["moving_fields"]
            moved = all(load_field(tmp, f)[0] != load_field(tmp, f + 1)[0] for f in range(lo, hi))
            print(("pass" if moved else "fail") + " moving fields %d-%d each differ from the next" % (lo, hi))
            ok_all = ok_all and moved
    if which == "planes" and ok_all and not negative:
        missing = [t for t in scenario["coverage_planes"] if t not in tagset]
        if missing:
            print("fail coverage: not exercised: %s" % ", ".join(missing))
            ok_all = False
        else:
            print("pass coverage: %s" % ", ".join(scenario["coverage_planes"]))
    if negative:
        if ok_all:
            print("negative control: the altered expectation unexpectedly passed")
            return 1
        print("negative control: altered palette word failed as required")
        return 0
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
