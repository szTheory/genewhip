#!/usr/bin/env python3
"""Build and validate the bounded Linux x86_64 Genewhip Libretro bundle."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import io

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import package_archive
from scripts.release import promote

VERSIONS = ("0.3.0", "0.3.1")
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MODULE_NAME = "genewhip_libretro.so"
MEMBERS = ("LICENSE", "LIBRETRO-HEADER-LICENSE.txt", "genewhip_libretro.info", MODULE_NAME)
INFO_KEYS = {"display_name", "corename", "version", "supported_extensions", "need_fullpath",
             "block_extract", "supports_no_game"}
INFO = ROOT / "packaging/libretro/genewhip_libretro.info"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _elf_x86_64(path: pathlib.Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return False
    return _elf_x86_64_bytes(data)


def _info_values(data: str) -> dict[str, str]:
    values = {}
    for line in data.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition(" = ")
        if not sep or key in values:
            raise ValueError("libretro-info-malformed")
        values[key] = value.strip().strip('"')
    return values


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with __import__("gzip").GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(files.items()):
                item = tarfile.TarInfo(name)
                item.size = len(data)
                item.mode = 0o755 if name == MODULE_NAME else 0o644
                item.uid = item.gid = 0
                item.uname = item.gname = ""
                item.mtime = 0
                archive.addfile(item, io.BytesIO(data))
    return raw.getvalue()


def _open_archive(data: bytes) -> dict[str, bytes]:
    package_archive.preflight_tar_gz(data, max_members=16, max_expanded_bytes=MAX_EXPANDED)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            rows = archive.getmembers()
            names = [row.name for row in rows]
            if (names != sorted(MEMBERS) or len(names) != len(set(names))
                    or any(not row.isfile() or row.size > MAX_EXPANDED for row in rows)):
                raise ValueError("libretro-archive-roster-invalid")
            return {row.name: archive.extractfile(row).read(row.size + 1) for row in rows}
    except (OSError, tarfile.TarError) as error:
        raise ValueError("libretro-archive-invalid") from error


def validate_bundle(directory: pathlib.Path, *, source_sha: str, version: str,
                    run_id: str = "local", run_attempt: str = "1") -> dict:
    if version not in VERSIONS or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("libretro-package-identity-invalid")
    name = f"genewhip-{version}-linux-x86_64-libretro.tar.gz"
    archive_path = directory / name
    data = archive_path.read_bytes()
    if len(data) > MAX_ARCHIVE:
        raise ValueError("libretro-archive-size-limit")
    files = _open_archive(data)
    if not _elf_x86_64_bytes(files[MODULE_NAME]):
        raise ValueError("libretro-module-not-linux-x86_64-elf")
    values = _info_values(files["genewhip_libretro.info"].decode("utf-8"))
    if set(values) != INFO_KEYS:
        raise ValueError("libretro-info-contract-mismatch")
    expected = {"display_name": "Genewhip", "corename": "genewhip_libretro", "version": "0.3.0",
                "supported_extensions": "bin|gen", "need_fullpath": "false", "supports_no_game": "false"}
    if any(values.get(key) != value for key, value in expected.items()):
        raise ValueError("libretro-info-contract-mismatch")
    if files["LICENSE"] != (ROOT / "LICENSE").read_bytes():
        raise ValueError("libretro-license-mismatch")
    rows = [{"name": key, "size": len(value), "sha256": digest(value)} for key, value in sorted(files.items())]
    if len(data) > MAX_ARCHIVE:
        raise ValueError("libretro-archive-size-limit")
    checksum = f"{digest(data)}  {name}\n".encode()
    qualification = {"schema": "genewhip-libretro-qualification-v1", "outcome": "pass",
                     "source_revision": source_sha, "run_id": str(run_id), "run_attempt": str(run_attempt),
                     "version": version, "module_version": values["version"], "archive": name,
                     "archive_sha256": digest(data), "members": rows}
    try:
        actual_qualification = json.loads((directory / (name + ".qualification.json")).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("libretro-qualification-invalid") from error
    if actual_qualification != qualification:
        raise ValueError("libretro-qualification-mismatch")
    assets = {name: {"size": len(data), "sha256": digest(data)},
              name + ".sha256": {"size": len(checksum), "sha256": digest(checksum)},
              name + ".qualification.json": {"size": len(_json(qualification)), "sha256": digest(_json(qualification))}}
    inventory = {"schema": "genewhip.release-inventory.v3", "version": version,
                 "module_version": values["version"], "source_revision": source_sha,
                 "run_id": str(run_id), "run_attempt": str(run_attempt), "assets": dict(sorted(assets.items()))}
    inv = _json(inventory)
    sums = "".join(f"{row['sha256']}  {asset}\n" for asset, row in sorted(assets.items()))
    sums += f"{digest(inv)}  inventory.json\n"
    expected_files = {name, name + ".sha256", name + ".qualification.json", "inventory.json", "SHA256SUMS"}
    actual_files = {path.name for path in directory.iterdir() if path.is_file() and not path.is_symlink()}
    if actual_files != expected_files:
        raise ValueError("libretro-release-roster-invalid")
    for asset, row in assets.items():
        payload = (directory / asset).read_bytes()
        if len(payload) != row["size"] or digest(payload) != row["sha256"]:
            raise ValueError("libretro-inventory-digest-mismatch")
    if (directory / "inventory.json").read_bytes() != inv or (directory / "SHA256SUMS").read_text() != sums:
        raise ValueError("libretro-sidecar-mismatch")
    blockers = promote.validate_release_inventory(directory, inventory)[1]
    if blockers:
        raise ValueError(blockers[0])
    return inventory


def _elf_x86_64_bytes(data: bytes) -> bool:
    if (len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or data[6] != 1
            or int.from_bytes(data[16:18], "little") != 3
            or int.from_bytes(data[18:20], "little") != 62
            or int.from_bytes(data[52:54], "little") != 64
            or int.from_bytes(data[54:56], "little") != 56):
        return False
    offset = int.from_bytes(data[32:40], "little")
    count = int.from_bytes(data[56:58], "little")
    if count == 0 or offset < 64 or offset + count * 56 > len(data):
        return False
    return any(int.from_bytes(data[offset + i * 56:offset + i * 56 + 4], "little") == 1
               for i in range(count))


def _validate_module_contract(path: pathlib.Path) -> None:
    """Load the real release module and compare exported identity to its .info."""
    if not _elf_x86_64(path):
        raise ValueError("libretro-module-invalid")
    if platform.system() != "Linux":
        return

    class SystemInfo(ctypes.Structure):
        _fields_ = [("library_name", ctypes.c_char_p), ("library_version", ctypes.c_char_p),
                    ("valid_extensions", ctypes.c_char_p), ("need_fullpath", ctypes.c_bool),
                    ("block_extract", ctypes.c_bool)]

    try:
        module = ctypes.CDLL(str(path))
        function = module.retro_get_system_info
        function.argtypes = [ctypes.POINTER(SystemInfo)]
        function.restype = None
        info = SystemInfo()
        function(ctypes.byref(info))
    except (OSError, AttributeError) as error:
        raise ValueError("libretro-module-invalid") from error
    if (info.library_name != b"Genewhip" or info.library_version != b"0.3.0"
            or info.valid_extensions != b"bin|gen" or info.need_fullpath or info.block_extract):
        raise ValueError("libretro-module-info-mismatch")


def _json(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def build(library: pathlib.Path, output_dir: pathlib.Path, source_sha: str, version: str,
          run_id: str, run_attempt: str) -> dict:
    if version not in VERSIONS or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("libretro-package-identity-invalid")
    if not re.fullmatch(r"[0-9]+", str(run_id)) or not re.fullmatch(r"[1-9][0-9]*", str(run_attempt)):
        raise ValueError("libretro-package-run-identity-invalid")
    _validate_module_contract(library)
    info = INFO.read_bytes()
    header = (ROOT / "src/libretro/vendor/libretro.h").read_text(encoding="utf-8")
    license_block = header.split("@paragraph LICENSE", 1)[1].split("*/", 1)[0]
    third_party = ("Libretro API header notice\n\n" + license_block.replace("\n *", "\n").strip() + "\n").encode()
    members = {"LICENSE": (ROOT / "LICENSE").read_bytes(), "genewhip_libretro.info": info,
               "LIBRETRO-HEADER-LICENSE.txt": third_party, MODULE_NAME: library.read_bytes()}
    archive = _tar_bytes(members)
    if len(archive) > MAX_ARCHIVE:
        raise ValueError("libretro-archive-size-limit")
    output_dir.mkdir(parents=True, exist_ok=True)
    name = f"genewhip-{version}-linux-x86_64-libretro.tar.gz"
    (output_dir / name).write_bytes(archive)
    (output_dir / (name + ".sha256")).write_text(f"{digest(archive)}  {name}\n", encoding="utf-8")
    values = _info_values(info.decode("utf-8"))
    if set(values) != INFO_KEYS or any(values.get(key) != value for key, value in {
            "display_name": "Genewhip", "corename": "genewhip_libretro", "version": "0.3.0",
            "supported_extensions": "bin|gen", "need_fullpath": "false",
            "block_extract": "false", "supports_no_game": "false"}.items()):
        raise ValueError("libretro-info-contract-mismatch")
    qualification = {"schema": "genewhip-libretro-qualification-v1", "outcome": "pass",
                     "source_revision": source_sha, "run_id": str(run_id), "run_attempt": str(run_attempt),
                     "version": version, "module_version": values.get("version"), "archive": name,
                     "archive_sha256": digest(archive),
                     "members": [{"name": n, "size": len(v), "sha256": digest(v)} for n, v in sorted(members.items())]}
    (output_dir / (name + ".qualification.json")).write_bytes(_json(qualification))
    return _write_inventory(output_dir, version, source_sha, str(run_id), str(run_attempt), values.get("version"))


def _write_inventory(directory, version, source_sha, run_id, run_attempt, module_version):
    name = f"genewhip-{version}-linux-x86_64-libretro.tar.gz"
    assets = {}
    for filename in (name, name + ".sha256", name + ".qualification.json"):
        data = (directory / filename).read_bytes()
        assets[filename] = {"size": len(data), "sha256": digest(data)}
    inventory = {"schema": "genewhip.release-inventory.v3", "version": version,
                 "module_version": module_version, "source_revision": source_sha,
                 "run_id": run_id, "run_attempt": run_attempt, "assets": dict(sorted(assets.items()))}
    inv = _json(inventory)
    (directory / "inventory.json").write_bytes(inv)
    sums = "".join(f"{row['sha256']}  {filename}\n" for filename, row in sorted(assets.items()))
    sums += f"{digest(inv)}  inventory.json\n"
    (directory / "SHA256SUMS").write_text(sums, encoding="utf-8")
    return inventory


def _self_test(library: pathlib.Path | None = None, source_sha: str | None = None) -> None:
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise ValueError("libretro-tracer-requires-linux-x86_64-host")
    supplied_library = None
    if library is not None:
        supplied_library = pathlib.Path(library).resolve(strict=True)
        if not supplied_library.is_file():
            raise ValueError("libretro-module-invalid")
    source = (subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
              if source_sha is None else source_sha)
    if not isinstance(source, str) or not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("libretro-tracer-source-identity-invalid")
    with tempfile.TemporaryDirectory(prefix="genewhip-libretro-tracer-") as temp:
        build_dir = pathlib.Path(temp) / "build"
        out = pathlib.Path(temp) / "release"
        if supplied_library is None:
            subprocess.run(["cmake", "-S", str(ROOT), "-B", str(build_dir), "-DBUILD_TESTING=ON",
                            "-DGENEWHIP_BUILD_LIBRETRO=ON", "-DGENEWHIP_BUILD_DESKTOP=OFF", "-DCMAKE_BUILD_TYPE=Release"], check=True, timeout=120)
            subprocess.run(["cmake", "--build", str(build_dir), "--target", "genewhip_libretro", "--parallel", "2"], check=True, timeout=180)
            module = build_dir / MODULE_NAME
        else:
            # Supplied failures must be rejected as-is; they must never fall
            # through to a second, unrelated local build.
            module = supplied_library
        build(module, out, source, "0.3.0", "1", "1")
        inventory = validate_bundle(out, source_sha=source, version="0.3.0", run_id="1", run_attempt="1")
        _recorded_publisher_closure(out, inventory, source)
    module_source = "supplied tested module" if supplied_library is not None else "temporary Release module"
    print(f"libretro-tracer: PASS ({module_source}; real Linux x86_64 module; production validators; "
          "recorded local publisher transport; no publication)")


def _recorded_publisher_closure(directory: pathlib.Path, inventory: dict, source_sha: str) -> None:
    """Exercise publisher identity, selection and complete upload closure in memory."""
    run_id, attempt = str(inventory["run_id"]), int(inventory["run_attempt"])
    event = {"repository": {"full_name": "local/genewhip"},
             "inputs": {"source_sha": source_sha, "run_id": run_id, "run_attempt": str(attempt)}}
    if promote.verify_dispatch_event(event, "local/genewhip", source_sha, run_id, attempt):
        raise ValueError("libretro-tracer-dispatch-identity-mismatch")
    run = {"id": int(run_id), "run_attempt": attempt, "name": "Required preview checks",
           "event": "push", "head_branch": "main", "head_sha": source_sha,
           "status": "completed", "conclusion": "success",
           "repository": {"id": 1, "full_name": "local/genewhip"},
           "head_repository": {"id": 1}}
    if promote.verify_run_event({"workflow_run": run}, "local/genewhip", source_sha,
                                run_id, attempt)[1]:
        raise ValueError("libretro-tracer-source-run-selection-mismatch")
    digests, blockers = promote.validate_release_inventory(directory, inventory)
    if blockers or promote.validate_qualified_inventory(directory, inventory, source_sha):
        raise ValueError("libretro-tracer-publisher-validation-failed")
    selected = promote.release_plan(release=None, tag_sha=None, source_sha=source_sha, desired=digests)
    if selected["state"] != "create-draft" or selected["upload"] != sorted(digests):
        raise ValueError("libretro-tracer-publisher-selection-mismatch")

    # This recorder is deliberately in-memory: it exercises exactly the selected
    # bytes and publication closure without opening a network or write transport.
    recorded = {}
    for name in selected["upload"]:
        data = (directory / name).read_bytes()
        recorded[name] = promote.sha256_bytes(data)
    closed = promote.release_plan(
        release={"tag_sha": source_sha,
                 "assets": [{"name": name, "sha256": digest} for name, digest in recorded.items()],
                 "published": False},
        tag_sha=source_sha, source_sha=source_sha, desired=digests)
    if closed["state"] != "resume-draft" or closed["upload"] or not closed["publish"]:
        raise ValueError("libretro-tracer-publisher-upload-closure-incomplete")
    missing = dict(recorded)
    missing.pop(selected["upload"][0])
    incomplete = promote.release_plan(
        release={"tag_sha": source_sha,
                 "assets": [{"name": name, "sha256": digest} for name, digest in missing.items()],
                 "published": False},
        tag_sha=source_sha, source_sha=source_sha, desired=digests)
    if incomplete["publish"] or not incomplete["upload"]:
        raise ValueError("libretro-tracer-premature-publication-allowed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=pathlib.Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--version", choices=VERSIONS, default="0.3.0")
    parser.add_argument("--output-dir", type=pathlib.Path)
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "local"))
    parser.add_argument("--run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--tracer", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.self_test and args.tracer:
            _self_test(args.library, args.source_sha)
            return 0
        if not args.library or not args.source_sha or not args.output_dir:
            parser.error("--library, --source-sha, and --output-dir are required")
        if args.validate:
            result = validate_bundle(args.output_dir, source_sha=args.source_sha, version=args.version,
                                     run_id=args.run_id, run_attempt=args.run_attempt)
        else:
            result = build(args.library, args.output_dir, args.source_sha, args.version, args.run_id, args.run_attempt)
        print(json.dumps({"outcome": "qualified", "version": result["version"], "source_revision": args.source_sha}, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, promote.PromotionError) as error:
        print("REJECT: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
