#!/usr/bin/env python3
"""Pinned semantic vectors; standard library only, never invoked by the core."""
import argparse
import collections
import copy
import hashlib
import json
import pathlib
import runpy
import struct
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent
REGS = ["d" + str(i) for i in range(8)] + ["a" + str(i) for i in range(7)] + ["usp", "ssp", "sr"]


def checked(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("SHA256 mismatch: " + path.name)
    return data


def applicable(test):
    return test["initial"]["sr"] & 0xA000 == 0x2000


SR_FORMS = {0x003C: "ORItoCCR", 0x007C: "ORItoSR", 0x023C: "ANDItoCCR", 0x027C: "ANDItoSR",
            0x0A3C: "EORItoCCR", 0x0A7C: "EORItoSR"}
BIT_NAMES = ["BTST", "BCHG", "BCLR", "BSET"]
SHIFT_NAMES = ["AS", "LS", "ROX", "RO"]


def sub_form(op):
    """Mnemonic form of an opcode word, from the M68000PRM encoding groups.

    Register and memory (or register and immediate) variants of one mnemonic are
    separate sub-forms so that each denominator is visible."""
    group = op >> 12
    if op in SR_FORMS:
        return SR_FORMS[op]
    if group in (1, 2, 3):
        return "MOVEA" if (op >> 6) & 7 == 1 else "MOVE"
    if op & 0xF100 == 0x7000:
        return "MOVEQ"
    if op == 0x4E71:
        return "NOP"
    if op == 0x4E75:
        return "RTS"
    if op & 0xFFC0 == 0x4E80:
        return "JSR"
    if op & 0xFFC0 == 0x4EC0:
        return "JMP"
    if op & 0xF1C0 == 0x41C0:
        return "LEA"
    if op & 0xFF00 == 0x4200 and op & 0xC0 != 0xC0:
        return "CLR"
    if op & 0xFF00 == 0x4A00 and op & 0xC0 != 0xC0:
        return "TST"
    if op & 0xFF00 == 0x4400 and op & 0xC0 != 0xC0:
        return "NEG"
    if op & 0xFF00 == 0x4600 and op & 0xC0 != 0xC0:
        return "NOT"
    if op & 0xFFC0 == 0x40C0:
        return "MOVEfromSR"
    if op & 0xFFC0 == 0x44C0:
        return "MOVEtoCCR"
    if op & 0xFFC0 == 0x46C0:
        return "MOVEtoSR"
    if op & 0xFFF8 in (0x4880, 0x48C0):
        return "EXT"
    if op & 0xFFF8 == 0x4840:
        return "SWAP"
    if group == 6:
        cond = (op >> 8) & 15
        return "BRA" if cond == 0 else "BSR" if cond == 1 else "Bcc"
    if op & 0xF0F8 == 0x50C8:
        return "DBcc"
    if op & 0xF000 == 0x5000 and op & 0xC0 != 0xC0:
        return "SUBQ" if op & 0x100 else "ADDQ"
    if group == 0 and op & 0xF100 == 0x0100 and (op >> 3) & 7 != 1:
        return BIT_NAMES[(op >> 6) & 3] + ".reg"
    if group == 0 and op & 0xFF00 == 0x0800:
        return BIT_NAMES[(op >> 6) & 3] + ".imm"
    immediates = {0x0600: "ADDI", 0x0400: "SUBI", 0x0C00: "CMPI", 0x0200: "ANDI", 0x0000: "ORI",
                  0x0A00: "EORI"}
    if group == 0 and op & 0xC0 != 0xC0 and op & 0xFF00 in immediates:
        return immediates[op & 0xFF00]
    if group == 0xE:
        if (op >> 6) & 3 == 3:
            return SHIFT_NAMES[(op >> 9) & 3] + ("L" if op & 0x100 else "R") + ".mem"
        return SHIFT_NAMES[(op >> 3) & 3] + ("L" if op & 0x100 else "R")
    if group == 0xB and (op >> 6) & 7 in (4, 5, 6):
        return "CMPM" if (op >> 3) & 7 == 1 else "EOR"
    if group in (0x8, 0xC) and (op >> 6) & 7 not in (3, 7):
        if (op >> 6) & 7 >= 4 and (op >> 3) & 7 in (0, 1):
            return "other"
        return "OR" if group == 0x8 else "AND"
    arithmetic = {0xD: "ADD", 0x9: "SUB", 0xB: "CMP"}
    if group in arithmetic:
        return arithmetic[group] + ("A" if (op >> 6) & 3 == 3 else "")
    return "other"


def has_address_error(test):
    return any(row[0] in ("re", "we") for row in test["transactions"])


def final_ram(test):
    """Expected final bytes: every initial byte plus every byte actually written.

    The upstream state lists whole words, so a byte write also lists its untouched
    partner byte as zero; the partner is excluded unless it was initially listed."""
    initial = {address for address, _ in test["initial"]["ram"]}
    written = set()
    for row in test["transactions"]:
        if row[0] == "w":
            address, upper, lower = row[3], row[6], row[7]
            if upper:
                written.add(address & ~1)
            if lower:
                written.add(address | 1)
    return [pair for pair in test["final"]["ram"] if pair[0] in initial or pair[0] in written]


def ram_text(pairs):
    return [str(len(pairs))] + [str(v) for pair in pairs for v in pair]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", required=True)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--corpus-dir", type=pathlib.Path)
    parser.add_argument("--fetch", action="store_true", help="explicitly fetch pinned data only for --full")
    parser.add_argument("--negative-control", action="store_true")
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    manifest = json.loads((ROOT / "manifest.json").read_text())
    for item in manifest["retained_files"]:
        checked(ROOT / item["path"], item["sha256"])
    selected = json.loads(checked(ROOT / "selected.json", manifest["selected"]["sha256"]))
    for source in manifest["sources"]:
        if sum(source["sub_forms"].values()) != source["tests"]:
            raise ValueError("sub-form denominator mismatch: " + source["path"])
    entries = selected
    if args.fetch and not args.full:
        raise ValueError("--fetch requires --full")
    if args.full:
        if not args.corpus_dir:
            raise ValueError("--full requires --corpus-dir")
        if args.fetch:
            args.corpus_dir.mkdir(parents=True, exist_ok=True)
        decoder = runpy.run_path(str(ROOT / "upstream/decode.py"))
        entries = []
        for source in manifest["sources"]:
            path = args.corpus_dir / pathlib.PurePosixPath(source["path"]).name
            if args.fetch and not path.exists():
                url = manifest["raw_base"] + source["path"]
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = response.read(source["bytes"] + 1)
                if len(data) != source["bytes"] or hashlib.sha256(data).hexdigest() != source["sha256"]:
                    raise ValueError("download identity mismatch: " + source["path"])
                path.write_bytes(data)
            data = checked(path, source["sha256"])
            magic, count = struct.unpack_from("<II", data)
            if magic != 0x1A3F5D71 or count != source["tests"]:
                raise ValueError("binary denominator/header mismatch")
            offset = 8
            decoded = collections.Counter()
            for index in range(count):
                offset, test = decoder["decode_test"](data, offset)
                decoded[sub_form(test["initial"]["prefetch"][0])] += 1
                entries.append({"source": source["path"], "index": index, "test": test})
            if offset != len(data):
                raise ValueError("unconsumed binary bytes")
            if dict(decoded) != source["sub_forms"]:
                raise ValueError("sub-form denominator mismatch: " + source["path"])
        # Required subset must be exactly reproducible from the pinned originals.
        extracted = [entry for entry in entries if entry["index"] < 32]
        if extracted != selected:
            raise ValueError("selected records differ from pinned source")

    expected = manifest["scheduled" if args.full else "selected"]
    if len(entries) != expected["denominator"]:
        raise ValueError("denominator mismatch")
    families = {source["path"]: set(source["sub_forms"]) for source in manifest["sources"]}
    outcomes, inputs, active, vectors = [], [], [], []
    for entry in entries:
        test = entry["test"]
        row = {"source": entry["source"], "index": entry["index"], "name": test["name"]}
        before, after = test["initial"], test["final"]
        row["sub_form"] = sub_form(before["prefetch"][0])
        if row["sub_form"] not in families[entry["source"]]:
            raise ValueError("unexpected opcode family")
        if not applicable(test):
            row.update(status="unsupported", reason="user or trace state is outside this core subset")
        else:
            row.update(status="unknown")
            active.append(row)
            vectors.append(test)
            if before["usp"] != after["usp"]:
                raise ValueError("unsupported vector side effect")
            inputs.append([before["prefetch"][0]] + [before[r] for r in REGS] + [after[r] for r in REGS]
                          + [before["pc"], after["pc"]])
        outcomes.append(row)
    if len(active) != expected["applicable"] or not active:
        raise ValueError("applicable denominator mismatch")
    if args.negative_control:
        inputs = copy.deepcopy(inputs)
        inputs[0][1 + len(REGS)] ^= 1  # independent expected D0, never input state
    lines_in = []
    for fields, test in zip(inputs, vectors):
        lines_in.append(" ".join(map(str, fields + ram_text(test["initial"]["ram"])
                                     + ram_text(final_ram(test)))))
    process = subprocess.run([args.runner], input="\n".join(lines_in) + "\n",
                             text=True, capture_output=True, timeout=300)
    if process.returncode:
        raise ValueError("runner infrastructure failure: " + process.stderr.strip())
    lines = process.stdout.splitlines()
    if len(lines) != len(active):
        raise ValueError("runner dropped outcomes")
    for index, (row, test, line) in enumerate(zip(active, vectors, lines)):
        number, result = line.split(" ", 1)
        if number != str(index):
            raise ValueError("runner ordering mismatch")
        if result == "PASS":
            row.update(status="pass", observation=result)
        elif result == "UNSUPPORTED address" and has_address_error(test):
            row.update(status="unsupported", reason="address-error frame not modeled", observation=result)
        elif result == "UNSUPPORTED instruction":
            row.update(status="unsupported", reason="instruction form not implemented", observation=result)
        elif result == "UNSUPPORTED state":
            row.update(status="unsupported", reason="user or trace state is outside this core subset",
                       observation=result)
        else:
            row.update(status="fail", observation=result)
    forms = {}
    for row in outcomes:
        cell = forms.setdefault(row["source"], {}).setdefault(row["sub_form"], collections.Counter())
        cell[row["status"]] += 1
        cell["total"] += 1
    forms = {source: {name: dict(cell) for name, cell in sorted(names.items())}
             for source, names in sorted(forms.items())}
    counts = dict(collections.Counter(row["status"] for row in outcomes))
    report = {"schema_version": 1, "evidence_class": "MAME-derived CPU semantic agreement",
              "revision": manifest["revision"], "denominator": len(entries), "counts": counts,
              "unselected_source_records": 0 if args.full else sum(x["tests"] for x in manifest["sources"]) - len(entries),
              "sub_forms": forms,
              "out_of_scope_source_files": manifest["out_of_scope_source_files"],
              "unchecked": manifest["unchecked"], "outcomes": outcomes}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "outcomes"}, sort_keys=True))
    failures = [row for row in outcomes if row["status"] == "fail"]
    if args.negative_control:
        if len(failures) != 1 or failures[0] is not active[0] or failures[0]["observation"] != "register mismatch":
            raise ValueError("negative control did not detect intended D0 mismatch")
        print("negative control: detected expected register mismatch")
        return 0
    for failure in failures:
        print(json.dumps(failure))
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, struct.error, AssertionError) as error:
        print(json.dumps({"status": "infrastructure_error", "reason": str(error)}), file=sys.stderr)
        sys.exit(2)
