#!/usr/bin/env python3
"""Fail-closed identity checks for the independently authored game candidate."""
from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/independent-game"
DEFAULT_LOCK = FIXTURE / "toolchain.lock"
SHA = re.compile(r"^[0-9a-f]{64}$")


def reject(condition: bool, reason: str) -> None:
    if condition:
        raise ValueError(reason)


def validate_assembler(a: dict, target: str) -> None:
    reject(not isinstance(a, dict), "assembler record missing")
    reject(a.get("version") != "2.47", "assembler version is not pinned to 2.47")
    reject(a.get("source_url") != "https://ftp.gnu.org/gnu/binutils/binutils-2.47.tar.bz2", "source URL is not the official release archive")
    reject(a.get("source_archive_sha256") != "3068128c75cda9f898ccb4211d360246e8e195ffcc9dfb655b23ae23a54800e8", "z80 archive digest" if target == "z80-elf" else "archive digest mismatch")
    tree_match=re.search(r"extracted source tree SHA-256 ([0-9a-f]{64})$",a.get("source_revision", ""))
    reject(not tree_match, "extracted source identity missing or malformed")
    s = a.get("signature", {})
    reject(s.get("url") != "https://ftp.gnu.org/gnu/binutils/binutils-2.47.tar.bz2.sig", "signature URL is not official")
    reject(s.get("sha256") != "133e31f4eedfe16cd47fa30a15ceef7a953cb8027766028d0a00d5b5a9e14a28", "signature digest mismatch")
    reject(s.get("keyring_url") != "https://ftp.gnu.org/gnu/gnu-keyring.gpg", "official keyring identity missing")
    reject(s.get("keyring_sha256") != "0fe55175b96a8ea1c4b670cc3fe11d56b341e4eff81b161ea49958ae550be6ca", "keyring digest mismatch")
    reject(s.get("primary_fingerprint") != "3A24BC1E8FB409FA9F14371813FCEF89DD9E3C4F", "primary signing fingerprint mismatch")
    reject(s.get("signing_fingerprint") != "3A24BC1E8FB409FA9F14371813FCEF89DD9E3C4F", "signing fingerprint mismatch")
    reject(s.get("timestamp_unix") != 1785086752, "signature timestamp mismatch")
    reject(s.get("outcome") != "GOODSIG and VALIDSIG; no expired, revoked, bad-signature, or missing-key status", "signature did not pass all status gates")
    reject(s.get("release_announcement") != "https://sourceware.org/pipermail/binutils/2026-July/150520.html", "release announcement identity missing")
    for key in ("os", "os_build", "architecture", "xcode", "sdk_version", "sdk_build", "compiler", "make"):
        reject(not a.get("host", {}).get(key) or a["host"][key] == "unknown", f"host/build identity missing: {key}")
    exe = a.get("executable", {})
    reject(exe.get("name") != target + "-as" or exe.get("target") != target, "z80 target mismatch" if target == "z80-elf" else "assembler target/executable mismatch")
    reject(not SHA.fullmatch(exe.get("sha256", "")), "assembler executable digest missing or malformed")
    reject(exe.get("file_type") != "Mach-O 64-bit executable arm64", "assembler file type/architecture mismatch")
    reject("GNU assembler (GNU Binutils) 2.47." not in exe.get("version_output", ""), "assembler version output mismatch")
    links = exe.get("linked_images")
    reject(not links, "assembler linked-image inventory missing")
    for link in links:
        reject(not link.get("path") or not link.get("identity"), "assembler linked-image identity incomplete")
    licenses = a.get("upstream_license_notices")
    reject(not licenses or any(not item.get("path") or not SHA.fullmatch(item.get("sha256", "")) or not item.get("license") for item in licenses), "upstream license notice inventory incomplete")
    builder = a.get("candidate_builder", {})
    reject(builder.get("name") != "Python candidate builder and identity recorder", "candidate-builder identity missing")
    reject(builder.get("version") != "Python 3.14.4", "candidate-builder version mismatch")
    reject(builder.get("source_url") != "https://www.python.org/ftp/python/3.14.4/Python-3.14.4.tgz", "candidate-builder source URL mismatch")
    for key in ("sha256", "source_archive_sha256", "formula_sha256", "license_notice_sha256", "framework_sha256", "package_tree_sha256"):
        reject(not SHA.fullmatch(builder.get(key, "")), f"candidate-builder identity missing or malformed: {key}")
    reject(builder.get("license") != "Python-2.0", "candidate-builder license missing")
    reject(not builder.get("linked_images") or any(not item.get("image") or not item.get("license") or not (item.get("identity") or (item.get("package") and item.get("version") and SHA.fullmatch(item.get("sha256", "")))) for item in builder["linked_images"]), "candidate-builder linked-image inventory incomplete")
    deps = a.get("build_dependencies")
    reject(not deps, "build dependency inventory missing")
    for dep in deps:
        reject(not dep.get("name") or not dep.get("license") or dep.get("license") == "unknown", "build dependency license missing")
        if dep.get("sha256"):
            reject(not SHA.fullmatch(dep["sha256"]), f"build dependency digest malformed: {dep['name']}")
        for item in dep.get("linked_images", []):
            if isinstance(item, dict):
                has_identity = bool(item.get("identity")) or bool(item.get("package") and item.get("version") and SHA.fullmatch(item.get("sha256", "")))
                reject(not item.get("image") or not has_identity or not item.get("license"), "verifier linked-image identity/license incomplete")
            else:
                reject(not item, "empty linked-image identity")
        for item in dep.get("executables", []):
            reject(not item.get("name") or not SHA.fullmatch(item.get("sha256", "")), "build utility identity incomplete")
            reject(not item.get("linked_images"), "build utility linked-image inventory missing")
    reject(a.get("disposition") != "source-built from official archive; no Homebrew Binutils bottle used", "assembler source-build disposition missing")


def validate_lock(doc: dict) -> None:
    validate_assembler(doc.get("assembler"), "m68k-elf")
    if "assembler_z80" in doc:
        validate_assembler(doc["assembler_z80"], "z80-elf")
    mame = doc.get("mame", {})
    reject(mame.get("status") != "pass", "MAME source/build qualification is not pass")
    reject(mame.get("version") != "0.289" or "mame0289" not in mame.get("source_revision", ""), "MAME source revision is not pinned to 0.289")
    reject(mame.get("source_signature", {}).get("status") != "pass", "MAME source signature is not verified")
    reject(not SHA.fullmatch(mame.get("patch_sha256", "")), "MAME instrumentation patch identity missing")
    reject(not SHA.fullmatch(mame.get("executable_build_sha256", "")), "MAME executable identity missing")
    reject(not SHA.fullmatch(mame.get("source_configuration_identity", "")), "MAME configuration identity missing")


def validate_rom(data: bytes) -> None:
    reject(len(data) != 0x4000 or len(data) % 2 != 0, "ROM must be an even, exact 16 KiB image")
    sp = int.from_bytes(data[0:4], "big")
    pc = int.from_bytes(data[4:8], "big")
    reject(not 0x00FF0000 <= sp <= 0x01000000, "initial stack is outside work RAM")
    reject(pc < 0x200 or pc >= len(data) or pc & 1, "reset vector is invalid")
    reject(data[0x100:0x104] != b"SEGA", "console header signature missing")
    reject(int.from_bytes(data[0x1A0:0x1A4], "big") != 0, "ROM start header mismatch")
    reject(int.from_bytes(data[0x1A4:0x1A8], "big") != len(data) - 1, "ROM end header mismatch")
    reject(data[0x1A8:0x1B0] != bytes(8), "candidate advertises cartridge SRAM")
    reject(data[0x1F0:0x1F3] != b"JUE", "NTSC-U/Europe/Japan region declaration missing")


def validate_build_hashes(first: bytes, second: bytes) -> None:
    reject(hashlib.sha256(first).digest() != hashlib.sha256(second).digest(), "clean candidate ROM builds differ")


def validate_notice(text: str) -> None:
    for phrase in ("solely authored for Genewhip", "repository MIT license", "No bundled assets", "not admitted", "Pong remains rejected", "MAME 0.289 source/build", "bounded progression", "zero-SRAM/control qualification pass"):
        reject(phrase.lower() not in text.lower(), f"rights/disposition notice missing: {phrase}")
    for category in ("pass", "fail", "unknown", "unsupported", "skipped", "infrastructure-error"):
        reject(category not in text, f"evidence outcome category missing: {category}")
    reject("blocker reason" not in text.lower(), "durable blocker reasons missing")


def validate_source(text: str) -> None:
    reject(re.search(r"(?:0x)?(?:00200000|00a130f1|200000|a130f1)\b", text, re.I) is not None, "authored source references unsupported cartridge SRAM")
    reject("pong" in text.lower() or "diagnostic.s" in text.lower(), "candidate source is not independent of rejected Pong/diagnostic")
    reject(".ascii" not in text and ".long" not in text, "original source content missing")


def load_and_validate(path: pathlib.Path) -> dict:
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"lock unreadable or malformed: {exc}") from exc
    validate_lock(doc)
    return doc


def self_test(valid: dict) -> int:
    cases = []
    def case(label: str, mutate) -> None:
        altered = copy.deepcopy(valid)
        mutate(altered)
        cases.append((label, altered))
    case("archive digest", lambda d: d["assembler"].__setitem__("source_archive_sha256", "0"*64))
    case("signature digest", lambda d: d["assembler"]["signature"].__setitem__("sha256", "0"*64))
    case("keyring digest", lambda d: d["assembler"]["signature"].__setitem__("keyring_sha256", "0"*64))
    case("wrong signer", lambda d: d["assembler"]["signature"].__setitem__("primary_fingerprint", "0"*40))
    case("wrong timestamp", lambda d: d["assembler"]["signature"].__setitem__("timestamp_unix", 1))
    case("expired/revoked status", lambda d: d["assembler"]["signature"].__setitem__("outcome", "GOODSIG EXPKEYSIG"))
    case("missing source identity", lambda d: d["assembler"].__setitem__("source_revision", "unknown"))
    case("missing host identity", lambda d: d["assembler"]["host"].__setitem__("os_build", "unknown"))
    case("missing dependency license", lambda d: d["assembler"]["build_dependencies"][0].__setitem__("license", ""))
    case("missing candidate-builder identity", lambda d: d["assembler"].pop("candidate_builder"))
    case("missing candidate-builder source", lambda d: d["assembler"]["candidate_builder"].__setitem__("source_archive_sha256", "unknown"))
    case("missing executable hash", lambda d: d["assembler"]["executable"].__setitem__("sha256", "unknown"))
    case("missing linked image identity", lambda d: d["assembler"]["executable"].__setitem__("linked_images", []))
    case("changed MAME record", lambda d: d["mame"].__setitem__("source_revision", "built"))
    if "assembler_z80" in valid:
        for label, key, value in (("z80 target mismatch", "target", "m68k-elf"),
                                  ("z80 archive digest", "source_archive_sha256", "0" * 64)):
            altered = copy.deepcopy(valid)
            record = altered["assembler_z80"]["executable"] if key == "target" else altered["assembler_z80"]
            record[key] = value
            try:
                validate_lock(altered)
            except ValueError as exc:
                if str(exc) != label:
                    raise ValueError("wrong rejection for " + label + ": " + str(exc))
                print("PASS: rejected " + label)
            else:
                raise ValueError("accepted " + label)
    rejected = 0
    for label, document in cases:
        try:
            validate_lock(document)
        except (ValueError, KeyError, TypeError):
            rejected += 1
        else:
            print(f"FAIL: negative control passed unexpectedly: {label}", file=sys.stderr)
            return 1
    valid_rom = bytearray(0x4000)
    valid_rom[0:8] = bytes.fromhex("00ffff0000000200")
    valid_rom[0x100:0x104] = b"SEGA"
    valid_rom[0x1A4:0x1A8] = (0x3FFF).to_bytes(4, "big")
    valid_rom[0x1F0:0x1F3] = b"JUE"
    validate_rom(bytes(valid_rom))
    for label, bad in (("size", bytes(valid_rom[:-2])), ("reset vector", bytes(valid_rom[:4]+b"\xff\xff\xff\xff"+valid_rom[8:])), ("header", bytes(bytearray(valid_rom)[:0x100]+b"BAD!"+bytearray(valid_rom)[0x104:])), ("SRAM claim", bytes(bytearray(valid_rom)[:0x1a8]+b"RA\x00\x00\x00\x00\x00\x00"+bytearray(valid_rom)[0x1b0:]))):
        try:
            validate_rom(bad)
        except ValueError:
            rejected += 1
        else:
            print(f"FAIL: malformed ROM accepted: {label}", file=sys.stderr)
            return 1
    try:
        validate_build_hashes(b"candidate A", b"candidate B")
    except ValueError:
        rejected += 1
    else:
        print("FAIL: differing clean-build bytes were accepted", file=sys.stderr)
        return 1
    try:
        validate_source(".long 0x00a130f1")
    except ValueError:
        rejected += 1
    else:
        print("FAIL: SRAM-using source was accepted", file=sys.stderr)
        return 1
    print(f"PASS: {rejected} named non-pass identity, ROM, and reproducibility controls fail closed")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test-lock":
        try:
            return self_test(load_and_validate(DEFAULT_LOCK))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"BLOCKED: {exc}", file=sys.stderr)
            return 1
    if len(sys.argv) > 1 and sys.argv[1] == "--validate-lock":
        path = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_LOCK
        try:
            load_and_validate(path)
        except (ValueError, KeyError, TypeError) as exc:
            print(f"BLOCKED: {exc}", file=sys.stderr)
            return 1
        print("PASS: assembler and MAME source/build identities, license/dependency inventories, candidate gate, and runtime qualification notice")
        return 0
    try:
        doc = load_and_validate(DEFAULT_LOCK)
        validate_notice((FIXTURE / "NOTICES.md").read_text())
        validate_source((FIXTURE / "src/game.s").read_text())
        candidate = FIXTURE / "game.bin"
        if candidate.exists():
            validate_rom(candidate.read_bytes())
        result = self_test(doc)
        if result:
            return result
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
