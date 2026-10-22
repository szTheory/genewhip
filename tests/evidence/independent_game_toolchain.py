#!/usr/bin/env python3
"""Fail-closed identity checks for the independently authored game candidate."""
from __future__ import annotations

import copy
import hashlib
import json
import os
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


def validate_current_receipt(doc: dict, target: str, assembler_path: pathlib.Path) -> None:
    reject(not isinstance(doc, dict), "current-host receipt must be an object")
    reject(doc.get("schema") != "genewhip-current-host-toolchain-v1", "current-host receipt schema mismatch")
    reject(doc.get("receipt_basis") != "fresh source build; separate from immutable historical toolchain.lock", "receipt is not identified as separate current-host evidence")
    lock_sha = hashlib.sha256(DEFAULT_LOCK.read_bytes()).hexdigest()
    reject(doc.get("historical_lock_sha256") != lock_sha, "receipt is bound to a different historical toolchain.lock")
    reject(doc.get("target") != target, "current-host receipt target mismatch")
    reject("/Users/" in json.dumps(doc) or "/home/" in json.dumps(doc), "current-host receipt contains a personal absolute path")
    record = doc.get("record", {})
    reject(not isinstance(record, dict), "current-host record must be an object")
    reject(record.get("version") != "2.47", "current-host assembler version mismatch")
    reject(record.get("source_url") != "https://ftp.gnu.org/gnu/binutils/binutils-2.47.tar.bz2", "current-host source URL mismatch")
    reject(record.get("source_archive_sha256") != "3068128c75cda9f898ccb4211d360246e8e195ffcc9dfb655b23ae23a54800e8", "current-host archive digest mismatch")
    sig = record.get("signature", {})
    reject(not isinstance(sig, dict), "current-host signature must be an object")
    reject(sig.get("url") != "https://ftp.gnu.org/gnu/binutils/binutils-2.47.tar.bz2.sig", "current-host signature URL mismatch")
    reject(sig.get("sha256") != "133e31f4eedfe16cd47fa30a15ceef7a953cb8027766028d0a00d5b5a9e14a28", "current-host signature digest mismatch")
    reject(sig.get("keyring_url") != "https://ftp.gnu.org/gnu/gnu-keyring.gpg", "current-host keyring URL mismatch")
    reject(sig.get("keyring_sha256") != "0fe55175b96a8ea1c4b670cc3fe11d56b341e4eff81b161ea49958ae550be6ca", "current-host keyring digest mismatch")
    reject(sig.get("primary_fingerprint") != "3A24BC1E8FB409FA9F14371813FCEF89DD9E3C4F" or sig.get("signing_fingerprint") != "3A24BC1E8FB409FA9F14371813FCEF89DD9E3C4F", "current-host signer identity mismatch")
    reject(sig.get("timestamp_unix") != 1785086752 or sig.get("outcome") != "GOODSIG and VALIDSIG; no expired, revoked, bad-signature, or missing-key status", "current-host signature outcome mismatch")
    reject(sig.get("release_announcement") != "https://sourceware.org/pipermail/binutils/2026-July/150520.html", "current-host release announcement mismatch")
    source_revision = record.get("source_revision", "")
    reject(not isinstance(source_revision, str), "current-host source revision must be a string")
    tree = re.search(r"extracted source tree SHA-256 ([0-9a-f]{64})$", source_revision)
    reject(not tree, "current-host source tree digest missing")
    locked_tree = re.search(r"extracted source tree SHA-256 ([0-9a-f]{64})$", load_and_validate(DEFAULT_LOCK)["assembler"].get("source_revision", ""))
    reject(not locked_tree or tree.group(1) != locked_tree.group(1), "current-host extracted source tree differs from historical evidence")
    host = record.get("host", {})
    reject(not isinstance(host, dict), "current-host host identity must be an object")
    for key in ("os", "os_build", "architecture", "xcode", "sdk_version", "sdk_build", "compiler", "make"):
        reject(not host.get(key) or host[key] == "unknown", f"current-host identity missing: {key}")
    reject(host.get("architecture") != "arm64" or not host.get("os", "").startswith("macOS "), "current-host platform is not native macOS arm64")
    builder = record.get("candidate_builder", {})
    reject(not isinstance(builder, dict), "current-host Python identity must be an object")
    reject(builder.get("name") != "Python candidate builder and identity recorder", "current-host Python builder identity missing")
    raw_python_version = builder.get("version", "")
    reject(not isinstance(raw_python_version, str), "current-host Python version must be a string")
    python_version = raw_python_version.removeprefix("Python ")
    reject(not re.fullmatch(r"3\.\d+\.\d+", python_version), "current-host Python version missing")
    reject(builder.get("source_url") != f"https://www.python.org/ftp/python/{python_version}/Python-{python_version}.tgz", "current-host Python source URL mismatch")
    reject(builder.get("license") != "Python-2.0", "current-host Python license missing")
    for key in ("sha256", "source_archive_sha256", "formula_sha256", "license_notice_sha256", "framework_sha256", "package_tree_sha256"):
        reject(not SHA.fullmatch(builder.get(key, "")), f"current-host Python digest missing: {key}")
    python_links = builder.get("linked_images", [])
    reject(not isinstance(python_links, list) or not python_links or any(not isinstance(item, dict) or not item.get("image") or not item.get("license") for item in python_links), "current-host Python linked-image inventory missing")
    dependencies = record.get("build_dependencies", [])
    reject(not isinstance(dependencies, list) or any(not isinstance(item, dict) for item in dependencies), "current-host build dependencies must be an object list")
    verifier = next((item for item in dependencies if item.get("name") == "GNU Binutils release verifier gpgv"), {})
    reject(not verifier.get("identity", "").startswith("gpgv (GnuPG) ") or not SHA.fullmatch(verifier.get("sha256", "")), "current-host gpgv identity/digest missing")
    linked_images = verifier.get("linked_images", [])
    reject(not isinstance(linked_images, list) or not linked_images or any(not isinstance(item, dict) or not item.get("image") or not item.get("license") for item in linked_images), "current-host gpgv linked-image inventory missing")
    compiler = next((item for item in dependencies if item.get("name") == "Apple clang driver"), {})
    reject(not compiler.get("identity") or not SHA.fullmatch(compiler.get("sha256", "")), "current-host compiler identity/digest missing")
    host_tools = [item for item in dependencies if item.get("name") in ("GNU Coreutils install tools", "Apple system directory/install utilities")]
    reject(len(host_tools) != 1 or not isinstance(host_tools[0].get("executables"), list) or any(not isinstance(x, dict) or not SHA.fullmatch(x.get("sha256", "")) for x in host_tools[0].get("executables", [])), "current-host mkdir/install identity missing")
    if host_tools[0].get("name") == "GNU Coreutils install tools":
        for key in ("source_archive_sha256", "formula_sha256", "license_notice_sha256"):
            reject(not SHA.fullmatch(host_tools[0].get(key, "")), f"current-host Coreutils digest missing: {key}")
    else:
        reject(not host_tools[0].get("identity", "").startswith("/bin/mkdir and /usr/bin/install on macOS "), "current-host Apple install utility identity missing")
    flags = record.get("flags", [])
    configure = "configure=--prefix=/usr/local --target=" + target + " --disable-nls --disable-werror --disable-gdb --disable-gdbserver --disable-gprofng --disable-gold --disable-ld --disable-sim --disable-shared --disable-plugins --disable-libctf --disable-readline --disable-tui --disable-gdbtk --disable-compressed-debug-sections --without-system-zlib --without-zstd; CFLAGS=-O2 -g0 -ffile-prefix-map=<BUILD_ROOT>=.; SOURCE_DATE_EPOCH=1785086752"
    expected_flags = ["target=" + target, configure, "build=make -j4 all-gas && make DESTDIR=<BUILD_ROOT>/stage install-gas"]
    reject(flags != expected_flags, "current-host configure/build flags mismatch")
    exe = record.get("executable", {})
    reject(not isinstance(exe, dict), "current-host executable identity must be an object")
    reject(exe.get("name") != target + "-as" or exe.get("target") != target, "current-host target/executable mismatch")
    reject(not SHA.fullmatch(exe.get("sha256", "")), "current-host executable digest malformed")
    reject(exe.get("file_type") != "Mach-O 64-bit executable arm64", "current-host executable is not arm64 Mach-O")
    version_output = exe.get("version_output", "")
    reject(not isinstance(version_output, str), "current-host assembler version output must be a string")
    reject("GNU assembler (GNU Binutils) 2.47." not in version_output, "current-host assembler version output mismatch")
    reject("target of `" + target + "'" not in version_output, "current-host assembler target output mismatch")
    executable = (os.access(assembler_path, os.X_OK, effective_ids=True)
                  if os.access in os.supports_effective_ids else
                  os.access(assembler_path, os.X_OK))
    reject(not assembler_path.is_file() or not executable,
           "current-host assembler is not executable")
    reject(hashlib.sha256(assembler_path.read_bytes()).hexdigest() != exe.get("sha256"),
           "current-host receipt does not match assembler bytes")


def current_receipt_log_identity(doc: dict, receipt_bytes: bytes) -> dict:
    """Return verifiable current-host provenance without machine-local paths."""
    record = doc["record"]
    signature = record["signature"]
    host = record["host"]
    builder = record["candidate_builder"]
    verifier = next(item for item in record["build_dependencies"]
                    if item["name"] == "GNU Binutils release verifier gpgv")
    install_tools = next(item for item in record["build_dependencies"]
                         if item["name"] in ("GNU Coreutils install tools",
                                              "Apple system directory/install utilities"))
    tree = re.search(r"extracted source tree SHA-256 ([0-9a-f]{64})$",
                     record["source_revision"])
    if tree is None:
        raise ValueError("current-host source tree identity unavailable")
    return {
        "schema": doc["schema"],
        "target": doc["target"],
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "historical_lock_sha256": doc["historical_lock_sha256"],
        "binutils": {
            "version": record["version"],
            "source_archive_sha256": record["source_archive_sha256"],
            "source_tree_sha256": tree.group(1),
            "signature_sha256": signature["sha256"],
            "keyring_sha256": signature["keyring_sha256"],
            "signing_fingerprint": signature["signing_fingerprint"],
        },
        "host": {
            key: host[key] for key in
            ("os", "os_build", "architecture", "xcode", "sdk_version", "sdk_build",
             "compiler", "make")
        },
        "python": {
            "version": builder["version"],
            "sha256": builder["sha256"],
            "framework_sha256": builder["framework_sha256"],
        },
        "gpgv": {"version": verifier["identity"], "sha256": verifier["sha256"]},
        "install_tools": {
            "name": install_tools["name"],
            "executables": [
                {"name": item["name"], "sha256": item["sha256"]}
                for item in install_tools["executables"]
            ],
        },
        "assembler": {
            "sha256": record["executable"]["sha256"],
            "file_type": record["executable"]["file_type"],
        },
    }


def self_test_current_receipt(lock: dict) -> int:
    record = copy.deepcopy(lock["assembler"])
    target = "m68k-elf"
    payload = {"schema": "genewhip-current-host-toolchain-v1",
               "receipt_basis": "fresh source build; separate from immutable historical toolchain.lock",
               "historical_lock_sha256": hashlib.sha256(DEFAULT_LOCK.read_bytes()).hexdigest(),
               "target": target, "record": record}
    accepted = 0
    with tempfile.TemporaryDirectory(prefix="genewhip-current-receipt-") as tmp:
        binary = pathlib.Path(tmp) / "m68k-elf-as"
        binary.write_bytes(b"current-host assembler fixture")
        binary.chmod(0o755)
        payload["record"]["executable"]["sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        validate_current_receipt(payload, target, binary)
        mutations = [
            ("historical lock binding", lambda d: d.__setitem__("historical_lock_sha256", "0" * 64)),
            ("signed archive identity", lambda d: d["record"].__setitem__("source_archive_sha256", "0" * 64)),
            ("signature signer", lambda d: d["record"]["signature"].__setitem__("signing_fingerprint", "0" * 40)),
            ("signature URL", lambda d: d["record"]["signature"].__setitem__("url", "https://example.invalid/source.sig")),
            ("source tree", lambda d: d["record"].__setitem__("source_revision", "extracted source tree SHA-256 " + "0" * 64)),
            ("configure flags", lambda d: d["record"]["flags"].__setitem__(1, "configure=changed")),
            ("Python identity", lambda d: d["record"]["candidate_builder"].__setitem__("sha256", "invalid")),
            ("assembler target output", lambda d: d["record"]["executable"].__setitem__("version_output", "GNU assembler (GNU Binutils) 2.47 for another target")),
            ("assembler bytes", lambda d: d["record"]["executable"].__setitem__("sha256", "0" * 64)),
            ("host architecture", lambda d: d["record"]["host"].__setitem__("architecture", "x86_64")),
            ("gpgv identity", lambda d: next(x for x in d["record"]["build_dependencies"] if x["name"] == "GNU Binutils release verifier gpgv").__setitem__("sha256", "invalid")),
            ("malformed receipt record", lambda d: d.__setitem__("record", [])),
            ("malformed dependency inventory", lambda d: d["record"].__setitem__("build_dependencies", {})),
        ]
        for label, mutate in mutations:
            altered = copy.deepcopy(payload)
            mutate(altered)
            try:
                validate_current_receipt(altered, target, binary)
            except ValueError:
                accepted += 1
                print(f"PASS: rejected current-host receipt mutation {label}")
            else:
                print(f"FAIL: current-host receipt mutation passed: {label}", file=sys.stderr)
                return 1
        binary.chmod(0o401)
        try:
            validate_current_receipt(payload, target, binary)
        except ValueError:
            accepted += 1
            print("PASS: rejected current-host assembler executable permission-class mutation")
        else:
            print("FAIL: current-host assembler permission-class mutation passed", file=sys.stderr)
            return 1
        binary.chmod(0o755)
        binary.write_bytes(b"mutated assembler bytes")
        try:
            validate_current_receipt(payload, target, binary)
        except ValueError:
            accepted += 1
        else:
            print("FAIL: assembler changed after receipt validation", file=sys.stderr)
            return 1
    print(f"PASS: {accepted} current-host receipt and executable mutations fail closed")
    return 0


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
    for phrase in ("solely authored for Genewhip", "repository MIT license", "No bundled assets",
                   "historical pre-admission capture", "two stored checks passed",
                   "SRAM remains unsupported", "no broad compatibility claim"):
        reject(phrase.lower() not in text.lower(), f"rights/disposition notice missing: {phrase}")
    for category in ("pass", "fail", "unknown", "unsupported", "skipped", "infrastructure_error"):
        reject(category not in text, f"evidence outcome category missing: {category}")
    reject("historical pre-admission capture" not in text.lower(), "historical evidence provenance missing")


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
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test-current-receipt":
        try:
            return self_test_current_receipt(load_and_validate(DEFAULT_LOCK))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"BLOCKED: {exc}", file=sys.stderr)
            return 1
    if len(sys.argv) > 1 and sys.argv[1] == "--validate-current-receipt":
        if len(sys.argv) != 7 or sys.argv[3] != "--target" or sys.argv[5] != "--assembler":
            print("BLOCKED: usage: --validate-current-receipt FILE --target m68k-elf|z80-elf --assembler FILE", file=sys.stderr)
            return 2
        try:
            receipt_path = pathlib.Path(sys.argv[2])
            receipt_bytes = receipt_path.read_bytes()
            receipt = json.loads(receipt_bytes)
            validate_current_receipt(receipt, sys.argv[4], pathlib.Path(sys.argv[6]))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"BLOCKED: {exc}", file=sys.stderr)
            return 1
        print(f"PASS: current-host {sys.argv[4]} receipt binds the signed Binutils source and exact assembler bytes")
        print("CURRENT_HOST_RECEIPT: " + json.dumps(current_receipt_log_identity(receipt, receipt_bytes),
                                                     sort_keys=True, separators=(",", ":")))
        return 0
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
