#!/usr/bin/env python3
"""Offline checks for the SDL3 dependency record and the default (SDL-free) configure.

Modes:
  record [RECORD_JSON]            record fields, CMake pin equality and notice digest
  offline-configure SOURCE_DIR    fresh default configure leaves no SDL or FetchContent state
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SHA = re.compile(r"^[0-9a-f]{64}$")
FPR = re.compile(r"^[0-9A-F]{40}$")
FIELDS = ("schema_version", "name", "version", "tag", "url", "sha256", "bytes", "signature_url",
          "signature_sha256", "signers", "signer_keys_url", "signer_keys_sha256", "key_authenticity", "license", "license_file_sha256",
          "role", "build_options", "fetch_evidence")


def check(condition: bool, field: str, reason: str) -> None:
    if not condition:
        raise ValueError(f"{field}: {reason}")


def check_record(record_path: pathlib.Path) -> None:
    rec = json.loads(record_path.read_text(encoding="utf8"))
    for f in FIELDS:
        check(f in rec and rec[f] not in ("", None, [], {}), f, "missing or empty")
    ver = rec["version"]
    check(rec["tag"] == f"release-{ver}", "tag", "does not match version")
    base = f"https://github.com/libsdl-org/SDL/releases/download/release-{ver}/SDL3-{ver}.tar.gz"
    check(rec["url"] == base, "url", "is not the official release asset")
    check(rec["signature_url"] == base + ".sig", "signature_url", "is not the official signature asset")
    check(SHA.fullmatch(rec["sha256"]) is not None, "sha256", "malformed")
    check(SHA.fullmatch(rec["signature_sha256"]) is not None, "signature_sha256", "malformed")
    check(SHA.fullmatch(rec["license_file_sha256"]) is not None, "license_file_sha256", "malformed")
    check(isinstance(rec["bytes"], int) and rec["bytes"] > 0, "bytes", "not a positive integer")
    check(rec["license"] == "zlib", "license", "not zlib")
    check(all(FPR.fullmatch(s) for s in rec["signers"]), "signers", "malformed fingerprint")
    check(rec["key_authenticity"].startswith(("cross-checked", "trust-on-first-use")), "key_authenticity",
          "must state cross-checked or trust-on-first-use")
    cmake = (ROOT / "cmake/GenewhipDesktop.cmake").read_text(encoding="utf8")
    m = re.search(r'set\(GW_SDL3_URL "([^"]+)"\)', cmake)
    check(m is not None and m.group(1) == rec["url"], "url", "differs from cmake/GenewhipDesktop.cmake")
    h = re.search(r"URL_HASH SHA256=([0-9a-f]{64})", cmake)
    check(h is not None and h.group(1) == rec["sha256"], "sha256", "differs from URL_HASH in cmake/GenewhipDesktop.cmake")
    notice = ROOT / "packaging/notices/SDL3-LICENSE.txt"
    check(notice.is_file(), "license_file_sha256", "notice copy missing")
    check(hashlib.sha256(notice.read_bytes()).hexdigest() == rec["license_file_sha256"], "license_file_sha256",
          "differs from packaging/notices/SDL3-LICENSE.txt")
    check(SHA.fullmatch(rec["signer_keys_sha256"]) is not None, "signer_keys_sha256", "malformed")
    check(rec["signer_keys_url"].startswith("https://www.libsdl.org/"), "signer_keys_url", "is not SDL's site")
    check("keyring" not in rec and not (ROOT / "packaging/dependencies/sdl3-release-keys.asc").exists(),
          "keyring", "signer keys must not be committed")
    print("dependency_record: PASS")


def offline_configure(source: pathlib.Path) -> None:
    with tempfile.TemporaryDirectory(prefix="gw-offline-") as tmp:
        build = pathlib.Path(tmp) / "build"
        r = subprocess.run(["cmake", "-S", str(source), "-B", str(build), "-DGENEWHIP_BUILD_DESKTOP=OFF",
                            "-DCMAKE_DISABLE_FIND_PACKAGE_SDL3=TRUE"], capture_output=True, text=True)
        check(r.returncode == 0, "configure", "default configure failed:\n" + r.stdout[-800:] + r.stderr[-800:])
        check(not (build / "_deps").exists(), "_deps", "exists after a default configure")
        cache = (build / "CMakeCache.txt").read_text(encoding="utf8", errors="replace")
        check("FETCHCONTENT_BASE_DIR" not in cache, "FETCHCONTENT_BASE_DIR", "present in the default CMakeCache")
        found = [p for p in build.rglob("*") if p.is_dir() and "sdl3" in p.name.lower()]
        check(not found, "sdl3", "source directory appeared: " + str(found[:1]))
    print("default_configure_offline: PASS")


def main(argv: list[str]) -> int:
    try:
        if len(argv) >= 2 and argv[1] == "record":
            check_record(pathlib.Path(argv[2]) if len(argv) > 2 else ROOT / "packaging/dependencies/sdl3.json")
        elif len(argv) >= 2 and argv[1] == "offline-configure":
            offline_configure(pathlib.Path(argv[2]) if len(argv) > 2 else ROOT)
        else:
            print("usage: dependency_record.py record [RECORD] | offline-configure [SOURCE]", file=sys.stderr)
            return 2
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
