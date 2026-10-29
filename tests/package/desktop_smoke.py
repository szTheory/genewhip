#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate an exact desktop archive before extracting or executing its payload."""
import hashlib
import argparse
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("genewhip_package_desktop", ROOT / "scripts/package_desktop.py")
_PACKAGE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_PACKAGE)
EXPECTED_SHARE = {
    "README.md", "LICENSE", "SDL3-LICENSE.txt", "THIRD-PARTY-ymfm.txt", "sdl3.json", "manifest.json",
    "independent-game-v2.bin", "independent-game-v2.s", "independent-game-v2-NOTICES.md",
    "independent-game-v2-scenario.json", "independent-game-v2-oracle.json", "independent-game-v2-host-controls.json",
    "independent-game-v2-demo.log", "raster-toy.bin", "raster-toy.s", "raster-toy-z80-driver.s",
    "raster-toy-z80-driver.inc", "raster-toy-NOTICES.md", "raster-toy-scenario.json", "raster-toy-demo.log",
    "video.md", "input.md", "desktop.md", "phase4-gameplay.json", "phase4-diagnostic.json", "phase4-evidence.json",
}
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 64
MAX_V02_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_V02_EXPANDED_BYTES = 1024 * 1024 * 1024


def validate_archive(archive, digest, revision):
    archive = pathlib.Path(archive)
    if not archive.is_file() or archive.stat().st_size == 0:
        raise ValueError("archive-empty")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive-size-limit")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError("archive-checksum")
    _PACKAGE.package_archive.preflight_tar_gz(archive, max_members=MAX_MEMBERS,
        max_expanded_bytes=MAX_ARCHIVE_BYTES)
    try:
        tar = tarfile.open(archive, "r:*")
    except (OSError, tarfile.TarError) as error:
        raise ValueError("archive-malformed") from error
    with tar:
        rows = tar.getmembers()
        if not rows:
            raise ValueError("archive-empty")
        if len(rows) > MAX_MEMBERS:
            raise ValueError("archive-member-count")
        if sum(member.size for member in rows) > MAX_ARCHIVE_BYTES:
            raise ValueError("archive-size-limit")
        by_name = {}
        for member in rows:
            path = pathlib.PurePosixPath(member.name)
            if member.name in by_name:
                raise ValueError("archive-duplicate-member")
            if path.is_absolute() or ".." in path.parts or "\\" in member.name or any(p in ("", ".") for p in path.parts):
                raise ValueError("archive-path")
            if not member.isfile():
                raise ValueError("archive-member-type")
            if member.size < 0 or member.size > MAX_ARCHIVE_BYTES:
                raise ValueError("archive-member-size")
            by_name[member.name] = member
        roots = {pathlib.PurePosixPath(name).parts[0] for name in by_name}
        expected_root = "genewhip-0.1.0-playable-preview-macos-arm64-" + revision[:12]
        if roots != {expected_root}:
            raise ValueError("archive-root")
        prefix = expected_root + "/"
        files = {name[len(prefix):]: member for name, member in by_name.items()}
        if any(not name.startswith(prefix) for name in by_name):
            raise ValueError("archive-root")
        if "checksums.json" not in files:
            raise ValueError("archive-inventory-missing")
        inventory_stream = tar.extractfile(files["checksums.json"])
        try:
            inventory = json.loads(inventory_stream.read())
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("archive-inventory-invalid") from error
        expected_files = {"bin/genewhip-desktop", "bin/gw_headless", "metadata.json", "checksums.json"}
        expected_files.update("share/genewhip/" + name for name in EXPECTED_SHARE)
        if set(files) != expected_files:
            raise ValueError("archive-member-set")
        payload_names = expected_files - {"checksums.json"}
        if not isinstance(inventory, dict) or set(inventory) != payload_names:
            raise ValueError("archive-inventory-members")
        for name in sorted(payload_names):
            stream = tar.extractfile(files[name])
            if stream is None or hashlib.sha256(stream.read()).hexdigest() != inventory[name]:
                raise ValueError("archive-inventory-digest")
        def read(name):
            return tar.extractfile(files[name]).read()
        try:
            metadata = json.loads(read("metadata.json"))
            manifest = json.loads(read("share/genewhip/manifest.json"))
            gameplay = json.loads(read("share/genewhip/phase4-gameplay.json"))
            diagnostic = json.loads(read("share/genewhip/phase4-diagnostic.json"))
            evidence = json.loads(read("share/genewhip/phase4-evidence.json"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("archive-identity-invalid") from error
        if metadata.get("source_revision") != revision or metadata.get("source_state") != "clean":
            raise ValueError("package-revision")
        if metadata.get("api_version") != 4 or metadata.get("version") != "0.1.0":
            raise ValueError("package-api-version")
        if metadata.get("label") != "narrow playable preview":
            raise ValueError("package-label")
        if metadata.get("system") != "Darwin" or metadata.get("architecture") != "arm64" or metadata.get("architectures") != ["arm64"]:
            raise ValueError("package-platform")
        if metadata.get("signing") != "unsigned, unnotarized" or not metadata.get("tested_os") or not metadata.get("deployment_target"):
            raise ValueError("package-platform-signing")
        for path, name in (("bin/genewhip-desktop", "genewhip-desktop"), ("bin/gw_headless", "gw_headless")):
            member = files[path]
            stream = tar.extractfile(member)
            expected_binary = metadata.get("binary_sha256", {}).get(name)
            if not expected_binary or hashlib.sha256(stream.read()).hexdigest() != expected_binary:
                raise ValueError("package-binary-identity")
        if not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("configuration_sha256", ""))):
            raise ValueError("package-configuration")
        rows = manifest.get("fixtures")
        if not isinstance(rows, list):
            raise ValueError("package-fixture-manifest")
        admitted = {row.get("id"): row for row in rows if isinstance(row, dict)}
        for fixture_id, prefix_name, source_name, rom_name, scenario_name, oracle_name in (
                ("genewhip-independent-game-v2", "independent_game_v2", "independent-game-v2.s",
                 "independent-game-v2.bin", "independent-game-v2-scenario.json", "independent-game-v2-oracle.json"),
                ("genewhip-raster-toy-v1", "raster_toy", "raster-toy.s", "raster-toy.bin", "raster-toy-scenario.json", None)):
            row = admitted.get(fixture_id)
            if not row or row.get("status") != "admitted" or row.get("outcome") != "pass":
                raise ValueError("package-fixture-admission")
            identity = metadata.get("fixtures", {}).get(prefix_name, {})
            if identity.get("id") != fixture_id or identity.get("source_sha256") != row.get("source_sha256"):
                raise ValueError("package-fixture-source")
            if hashlib.sha256(read("share/genewhip/" + rom_name)).hexdigest() != row.get("sha256") or identity.get("rom_sha256") != row.get("sha256"):
                raise ValueError("package-fixture-rom")
            if hashlib.sha256(read("share/genewhip/" + source_name)).hexdigest() != row.get("source_sha256"):
                raise ValueError("package-fixture-source")
            if hashlib.sha256(read("share/genewhip/" + scenario_name)).hexdigest() != identity.get("scenario_sha256"):
                raise ValueError("package-fixture-scenario")
            if oracle_name and hashlib.sha256(read("share/genewhip/" + oracle_name)).hexdigest() != identity.get("oracle_sha256"):
                raise ValueError("package-fixture-oracle")
        if hashlib.sha256(read("share/genewhip/manifest.json")).hexdigest() != metadata.get("fixture_manifest_sha256"):
            raise ValueError("package-fixture-manifest")
        for name, document in (("phase4-gameplay.json", gameplay), ("phase4-diagnostic.json", diagnostic),
                               ("phase4-evidence.json", evidence)):
            expected_hash = metadata.get("evidence_sha256", {}).get(name)
            if hashlib.sha256(read("share/genewhip/" + name)).hexdigest() != expected_hash:
                raise ValueError("package-evidence-digest")
            if name == "phase4-evidence.json" and document.get("source_revision") != revision:
                raise ValueError("package-evidence-revision")
        if gameplay.get("outcome") != "pass" or gameplay.get("denominator") != 6 or gameplay.get("clients") != ["headless", "desktop"]:
            raise ValueError("package-gameplay-qualification")
        if diagnostic.get("outcome") != "pass" or evidence.get("source_state") != "clean" or evidence.get("source_revision") != revision:
            raise ValueError("package-evidence-qualification")
        if hashlib.sha256(read("share/genewhip/independent-game-v2-demo.log")).hexdigest() != metadata.get("input_sha256", {}).get("independent_game_v2"):
            raise ValueError("package-input-identity")
        if hashlib.sha256(read("share/genewhip/raster-toy-demo.log")).hexdigest() != metadata.get("input_sha256", {}).get("raster_toy"):
            raise ValueError("package-input-identity")
        notices = {
            "share/genewhip/SDL3-LICENSE.txt": ROOT / "packaging/notices/SDL3-LICENSE.txt",
            "share/genewhip/THIRD-PARTY-ymfm.txt": ROOT / "packaging/notices/THIRD-PARTY-ymfm.txt",
            "share/genewhip/independent-game-v2-NOTICES.md": ROOT / "fixtures/independent-game-v2/NOTICES.md",
            "share/genewhip/raster-toy-NOTICES.md": ROOT / "fixtures/raster-toy/NOTICES.md",
        }
        for member_name, source in notices.items():
            if read(member_name) != source.read_bytes():
                raise ValueError("package-notice-drift")
        for name in files:
            stream = tar.extractfile(files[name])
            data = stream.read() if stream else b""
            if _PACKAGE.PERSONAL_PATH.search(data) or str(ROOT).encode() in data:
                raise ValueError("package-private-path")
        return tar, files, expected_root


def validate_v02_archive(archive, digest, revision, roster_path):
    archive = pathlib.Path(archive)
    if not archive.is_file() or not 0 < archive.stat().st_size <= MAX_V02_ARCHIVE_BYTES:
        raise ValueError("archive-size-limit")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError("archive-checksum")
    _PACKAGE.package_archive.preflight_tar_gz(archive, max_members=MAX_MEMBERS,
        max_expanded_bytes=MAX_V02_EXPANDED_BYTES)
    roster = json.loads(pathlib.Path(roster_path).read_text())
    if roster.get("release_version") != "0.2.0":
        raise ValueError("package-roster-version")
    try:
        tar = tarfile.open(archive, "r:*")
    except (OSError, tarfile.TarError) as error:
        raise ValueError("archive-malformed") from error
    rows = tar.getmembers()
    if not rows or len(rows) > MAX_MEMBERS:
        tar.close()
        raise ValueError("archive-member-count")
    by_name, total = {}, 0
    for row in rows:
        path = pathlib.PurePosixPath(row.name)
        if row.name in by_name:
            tar.close()
            raise ValueError("archive-duplicate-member")
        if path.is_absolute() or ".." in path.parts or "\\" in row.name:
            tar.close()
            raise ValueError("archive-path")
        if not row.isfile() or row.issym() or row.islnk() or row.isdev():
            tar.close()
            raise ValueError("archive-member-type")
        total += row.size
        if row.size < 0 or row.size > MAX_V02_EXPANDED_BYTES or total > MAX_V02_EXPANDED_BYTES:
            tar.close()
            raise ValueError("archive-expanded-size-limit")
        by_name[row.name] = row
    roots = {pathlib.PurePosixPath(name).parts[0] for name in by_name}
    if len(roots) != 1:
        tar.close()
        raise ValueError("archive-root")
    root = roots.pop()
    prefix = root + "/"
    files = {name[len(prefix):]: member for name, member in by_name.items() if name.startswith(prefix)}
    if len(files) != len(by_name):
        tar.close()
        raise ValueError("archive-root")
    expected = {row["path"] for row in roster["desktop"]["members"]}
    if set(files) != expected:
        tar.close()
        raise ValueError("package-member-roster-mismatch")
    def read(name):
        stream = tar.extractfile(files[name])
        if stream is None:
            raise ValueError("archive-member-unreadable")
        return stream.read()
    try:
        metadata = json.loads(read("metadata.json"))
        inventory = json.loads(read("checksums.json"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        tar.close()
        raise ValueError("archive-identity-invalid") from error
    if metadata.get("release_version") != "0.2.0" or metadata.get("source_revision") != revision:
        tar.close()
        raise ValueError("package-revision")
    if metadata.get("source_state") not in ("clean", "development-only"):
        tar.close()
        raise ValueError("package-source-state")
    if metadata.get("api_version") != 4 or metadata.get("input_log_version") != 1:
        tar.close()
        raise ValueError("package-api-version")
    actual = {name: hashlib.sha256(read(name)).hexdigest() for name in files if name != "checksums.json"}
    if inventory != actual:
        tar.close()
        raise ValueError("archive-inventory-digest")
    rights = {row["path"]: row["rights"] for row in roster["desktop"]["members"]
              if row["path"] not in ("checksums.json", "metadata.json")}
    required = sorted(name for name in actual if name not in ("metadata.json", "checksums.json"))
    if metadata.get("member_rights") != rights or metadata.get("required_members") != required:
        tar.close()
        raise ValueError("package-rights-identity")
    performance_name = "share/genewhip/evidence/performance.json"
    if metadata.get("performance_evidence_digest") != hashlib.sha256(read(performance_name)).hexdigest():
        tar.close()
        raise ValueError("package-performance-evidence-identity")
    for row in roster["desktop"]["members"]:
        rights_record = roster["rights"][row["rights"]]
        notice = rights_record.get("notice_members", {}).get("desktop", rights_record.get("notice_member"))
        if notice not in expected:
            tar.close()
            raise ValueError("package-required-notice-missing")
        notice_row = next((item for item in roster["desktop"]["members"] if item["path"] == notice), None)
        if not notice_row or not notice_row.get("source"):
            tar.close()
            raise ValueError("package-notice-source-missing")
        if read(notice) != (ROOT / notice_row["source"]).read_bytes():
            tar.close()
            raise ValueError("package-notice-content-identity")
    tar.close()
    return roster, files, root


def extract_verified(archive, files, root, destination):
    dest = destination / root
    for relative, member in files.items():
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive, "r:*") as tar:
            source = tar.extractfile(root + "/" + relative)
            if source is None:
                raise ValueError("archive-member-unreadable")
            target.write_bytes(source.read())
        target.chmod(member.mode & 0o777)
    return dest


def field_rows(output):
    return [json.loads(line) for line in output.splitlines() if line.startswith("{\"sequence\"") or line.startswith("{\"fields\"")]


def mutate_archive(source, destination, member_name, replacement=None, *, remove=False, extra=None, refresh_inventory=True):
    with tarfile.open(source, "r:*") as tar:
        rows = [(row.name, tar.extractfile(row).read(), row.mode) for row in tar.getmembers() if row.isfile()]
    values = {name: (data, mode) for name, data, mode in rows}
    if remove:
        values.pop(member_name)
    else:
        mode = values[member_name][1] if member_name in values else 0o644
        values[member_name] = (replacement, mode)
    if extra:
        values[extra] = (b"unexpected payload", 0o644)
    checksums_name = next((name for name in values if name.endswith("/checksums.json")), None)
    if refresh_inventory and checksums_name:
        inventory = json.loads(values[checksums_name][0])
        if remove:
            inventory.pop(member_name.split("/", 1)[1], None)
        elif member_name.endswith("/checksums.json"):
            pass
        else:
            relative = member_name.split("/", 1)[1]
            if relative in inventory:
                inventory[relative] = hashlib.sha256(replacement).hexdigest()
        if extra:
            inventory[extra.split("/", 1)[1]] = hashlib.sha256(b"unexpected payload").hexdigest()
        values[checksums_name] = (json.dumps(inventory, indent=2).encode() + b"\n", values[checksums_name][1])
        # If this mutation was an inventory-entry corruption, preserve it rather
        # than rewriting the edited value from the payload.
        if member_name.endswith("/checksums.json"):
            values[checksums_name] = (replacement, values[checksums_name][1])
    with tarfile.open(destination, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(values):
            data, mode = values[name]
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))


def assert_archive_rejects(source, revision, tmp, case, member_name, replacement=None,
                           expected="archive-inventory-digest", **options):
    changed = pathlib.Path(tmp) / (case + ".tar.gz")
    mutate_archive(source, changed, member_name, replacement, **options)
    digest = hashlib.sha256(changed.read_bytes()).hexdigest()
    try:
        validate_archive(changed, digest, revision)
    except ValueError as error:
        if str(error) != expected:
            raise ValueError("negative-control-reason: " + case + " expected " + expected + ", got " + str(error)) from error
    else:
        raise ValueError("negative-control-not-detected: " + case)


def archive_negative_controls(archive, revision, tmp):
    with tarfile.open(archive, "r:*") as tar:
        root = pathlib.PurePosixPath(tar.getmembers()[0].name).parts[0]
        metadata_bytes = tar.extractfile(root + "/metadata.json").read()
        metadata = json.loads(metadata_bytes)
        inventory_bytes = tar.extractfile(root + "/checksums.json").read()
        inventory = json.loads(inventory_bytes)
    def metadata_change(change):
        changed = json.loads(json.dumps(metadata))
        change(changed)
        return json.dumps(changed, indent=2).encode() + b"\n"
    assert_archive_rejects(archive, revision, tmp, "omit", root + "/share/genewhip/README.md",
                          remove=True, expected="archive-member-set")
    assert_archive_rejects(archive, revision, tmp, "extra", root + "/extra.txt", extra=root + "/extra.txt",
                          expected="archive-member-set")
    assert_archive_rejects(archive, revision, tmp, "revision", root + "/metadata.json",
                          metadata_change(lambda m: m.update(source_revision="0" * 40)), expected="package-revision")
    assert_archive_rejects(archive, revision, tmp, "architecture", root + "/metadata.json",
                          metadata_change(lambda m: m.update(architecture="x86_64")), expected="package-platform")
    assert_archive_rejects(archive, revision, tmp, "api", root + "/metadata.json",
                          metadata_change(lambda m: m.update(api_version=3)), expected="package-api-version")
    assert_archive_rejects(archive, revision, tmp, "fixture", root + "/metadata.json",
                          metadata_change(lambda m: m["fixtures"]["independent_game_v2"].update(id="unknown-fixture")),
                          expected="package-fixture-source")
    notice = root + "/share/genewhip/independent-game-v2-NOTICES.md"
    original_notice = pathlib.Path(ROOT / "fixtures/independent-game-v2/NOTICES.md").read_bytes()
    assert_archive_rejects(archive, revision, tmp, "notice", notice, original_notice + b"tamper",
                          expected="package-notice-drift")
    manifest = root + "/share/genewhip/manifest.json"
    with tarfile.open(archive, "r:*") as tar:
        manifest_value = json.loads(tar.extractfile(manifest).read())
    manifest_value["fixtures"] = [row for row in manifest_value["fixtures"]
                                  if row.get("id") != "genewhip-independent-game-v2"]
    assert_archive_rejects(archive, revision, tmp, "stale-manifest", manifest,
                          json.dumps(manifest_value, indent=2).encode() + b"\n",
                          expected="package-fixture-admission")
    rom = root + "/share/genewhip/independent-game-v2.bin"
    with tarfile.open(archive, "r:*") as tar:
        rom_bytes = tar.extractfile(rom).read()
    assert_archive_rejects(archive, revision, tmp, "rom", rom, rom_bytes[:-1] + bytes([rom_bytes[-1] ^ 1]),
                          expected="package-fixture-rom")
    demo = root + "/share/genewhip/independent-game-v2-demo.log"
    with tarfile.open(archive, "r:*") as tar:
        demo_bytes = tar.extractfile(demo).read()
    assert_archive_rejects(archive, revision, tmp, "input", demo, demo_bytes.replace(b"genewhip-input-log 1", b"genewhip-input-log 9"),
                          expected="package-input-identity")
    assert_archive_rejects(archive, revision, tmp, "binary", root + "/bin/genewhip-desktop",
                          b"changed executable", expected="package-binary-identity")
    inventory_bad = dict(inventory)
    first = sorted(inventory_bad)[0]
    inventory_bad[first] = "0" * 64
    assert_archive_rejects(archive, revision, tmp, "inventory", root + "/checksums.json",
                          json.dumps(inventory_bad, indent=2).encode() + b"\n", refresh_inventory=False,
                          expected="archive-inventory-digest")


def game_log(case):
    return _PACKAGE.game_input_log(case)


def run_game_case(prefix, share, case, temp):
    temp.mkdir(parents=True, exist_ok=True)
    rom = share / "independent-game-v2.bin"
    log = temp / (case["id"] + ".log")
    log.write_bytes(game_log(case))
    head_pcm, desktop_pcm, trace = temp / "headless.pcm", temp / "desktop.pcm", temp / "trace.jsonl"
    fields = temp / "fields"
    fields.mkdir()
    env = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy")
    head = subprocess.run([str(prefix / "bin/gw_headless"), str(rom), "--fields", str(case["frames"]),
                           "--replay", str(log), "--port-device", "pad3", "pad3", "--peek", "0xff0000", "4",
                           "--dump-fields", str(fields), "--audio-rate", "48000", "--dump-audio", str(head_pcm),
                           "--dump-audio-trace", str(trace)], capture_output=True, text=True, env=env, timeout=180)
    desk = subprocess.run([str(prefix / "bin/genewhip-desktop"), "--fields", str(case["frames"]), "--replay", str(log),
                           "--print-field-hashes", "--dump-audio", str(desktop_pcm), str(rom)],
                          capture_output=True, text=True, env=env, timeout=180)
    if head.returncode or desk.returncode:
        raise ValueError("package-game-run: " + (head.stderr + desk.stderr).strip()[-3000:])
    hrows, drows = field_rows(head.stdout), field_rows(desk.stdout)
    if len(hrows) != case["frames"] + 1 or len(drows) != case["frames"] + 1:
        raise ValueError("package-game-denominator")
    head_hashes = [row.get("fnv1a64") for row in hrows if "fnv1a64" in row]
    desk_hashes = [row.get("fnv1a64") for row in drows if "fnv1a64" in row]
    if head_hashes != desk_hashes or head_pcm.read_bytes() != desktop_pcm.read_bytes():
        raise ValueError("package-game-client-join")
    final = next((row for row in reversed(hrows) if "peek" in row), None)
    if not final or final.get("fields") != case["frames"]:
        raise ValueError("package-game-final-state")
    peek = bytes.fromhex(final["peek"])
    expected = case["expect"]
    position = int.from_bytes(peek[2:4], "big")
    if int.from_bytes(peek[:2], "big") != expected["play_state"] or not expected["position_min"] <= position <= expected["position_max"]:
        raise ValueError("package-game-semantic-state")
    writes = [row["value"] for row in map(json.loads, trace.read_text().splitlines())
              if row.get("chip") == 3 and "value" in row]
    if writes != expected["psg_writes"]:
        raise ValueError("package-game-action-trace")
    raw = head_pcm.read_bytes()
    samples = memoryview(raw).cast("h")
    amplitude = max(samples) - min(samples) if samples else 0
    if (expected["psg_writes"] and amplitude <= 0) or (not expected["psg_writes"] and amplitude != 0):
        raise ValueError("package-game-action-audio")
    field_hashes = [row.get("fnv1a64") for row in hrows if "fnv1a64" in row]
    if len(field_hashes) != case["frames"]:
        raise ValueError("package-game-video-denominator")
    return field_hashes


def run_diagnostic(prefix, share, temp):
    scenario = json.loads((share / "raster-toy-scenario.json").read_text())
    fields = max(sample["fields"][1] for sample in scenario["samples"] if "fields" in sample) + 1
    log, head_pcm, desk_pcm, trace = (share / "raster-toy-demo.log", temp / "diagnostic-headless.pcm",
                                      temp / "diagnostic-desktop.pcm", temp / "diagnostic-trace.jsonl")
    env = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy")
    head = subprocess.run([str(prefix / "bin/gw_headless"), str(share / "raster-toy.bin"), "--fields", str(fields),
                           "--replay", str(log), "--audio-rate", "48000", "--dump-audio", str(head_pcm),
                           "--dump-audio-trace", str(trace)], capture_output=True, text=True, env=env, timeout=120)
    desk = subprocess.run([str(prefix / "bin/genewhip-desktop"), "--fields", str(fields), "--replay", str(log),
                           "--print-field-hashes", "--dump-audio", str(desk_pcm), str(share / "raster-toy.bin")],
                          capture_output=True, text=True, env=env, timeout=120)
    if head.returncode or desk.returncode or head_pcm.read_bytes() != desk_pcm.read_bytes():
        raise ValueError("package-diagnostic-run")
    if not any(row.get("chip") in (1, 2, 3) for row in map(json.loads, trace.read_text().splitlines())):
        raise ValueError("package-diagnostic-action-trace")
    if not any(head_pcm.read_bytes()):
        raise ValueError("package-diagnostic-action-audio")


def run_live_package_client(prefix, share, rom_name, log_path, fields, temp, name):
    env = dict(os.environ)
    env.pop("SDL_VIDEODRIVER", None)
    env.pop("SDL_AUDIODRIVER", None)
    stats_path = temp / (name + "-stats.json")
    pcm_path = temp / (name + "-live.pcm")
    desktop = subprocess.run([str(prefix / "bin/genewhip-desktop"), "--fields", str(fields), "--replay", str(log_path),
                              "--print-field-hashes", "--dump-audio", str(pcm_path), "--stats", str(stats_path),
                              str(share / rom_name)], capture_output=True, text=True, env=env, timeout=180)
    if desktop.returncode:
        raise ValueError("package-live-run: " + desktop.stderr[-2000:])
    stats = json.loads(stats_path.read_text())
    sequences = [row for row in field_rows(desktop.stdout) if "sequence" in row]
    if len(sequences) != fields or stats.get("stats_version") != 2 or stats.get("emulated_fields") != fields:
        raise ValueError("package-live-denominator")
    if stats.get("audio_available") != 1 or stats.get("present_calls", 0) < 1 or stats.get("present_errors") != 0:
        raise ValueError("package-live-capability-or-present-errors")
    if stats.get("clock_exposure_ns", 0) <= 0 or stats.get("present_successes", 0) + stats.get("present_errors", 0) != stats.get("present_calls"):
        raise ValueError("package-live-exposure-or-present-counters")
    return {"id": name, "fields": fields, "audio_available": stats["audio_available"],
            "present_calls": stats["present_calls"], "present_errors": stats["present_errors"],
            "clock_exposure_ns": stats["clock_exposure_ns"], "renderer_readback": "unavailable",
            "physical_scanout": "unobserved", "vsync_actual": "unknown"}


def live_package_smoke(prefix, share, scenario, temp):
    rows = []
    for case_id, rom_name, log_name, fields in (
            ("independent-game-v2", "independent-game-v2.bin", "independent-game-v2-demo.log", 40),
            ("raster-toy", "raster-toy.bin", "raster-toy-demo.log", 76)):
        log_path = share / log_name
        rows.append(run_live_package_client(prefix, share, rom_name, log_path, fields, temp, case_id))
    return {"outcome": "pass", "backend": "native SDL video/audio", "clients": rows}


def run_v02_smoke(archive, digest, revision, roster_path, scratch):
    roster, files, root = validate_v02_archive(archive, digest, revision, roster_path)
    with tarfile.open(archive, "r:*") as tar:
        prefix = scratch / root
        prefix.mkdir()
        for name, member in files.items():
            destination = prefix / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(tar.extractfile(member).read())
            destination.chmod(0o755 if member.mode & 0o111 else 0o644)
    _PACKAGE.check_staged_inventory(prefix)
    moved = scratch / "relocated"
    prefix.rename(moved)
    share = moved / "share/genewhip"
    public_roster = json.loads((share / "evidence/roster.json").read_text())
    expected_roster = json.loads((ROOT / "evidence/v02-roster.json").read_text())
    if public_roster != expected_roster:
        raise ValueError("package-independent-roster")
    matrix_spec = importlib.util.spec_from_file_location("gw_trusted_v02_matrix_consumer", ROOT / "scripts/evidence/v02_matrix.py")
    matrix_consumer = importlib.util.module_from_spec(matrix_spec)
    matrix_spec.loader.exec_module(matrix_consumer)
    closure = scratch / "public-closure"
    closure.mkdir()
    closure_names = ["compatibility-matrix.md", "manifest.json", "observations.json", "roster.json", "schema.json", "verifier.py"]
    if (share / "evidence/execution-identity.json").is_file():
        closure_names.append("execution-identity.json")
    for name in closure_names:
        (closure / name).write_bytes((share / "evidence" / name).read_bytes())
    current_identity = None
    if "execution-identity.json" in closure_names:
        current_identity = json.loads((closure / "execution-identity.json").read_text())
        if current_identity.get("git_head") != revision:
            raise ValueError("package-current-execution-source-identity")
    matrix_consumer.verify_public_closure(closure, ROOT / "evidence/v02-roster.json", current_identity)
    manifest = json.loads((share / "manifest.json").read_text())
    admitted = {row.get("id"): row for row in manifest.get("fixtures", []) if isinstance(row, dict)}
    for fixture_id in ("genewhip-independent-game-v2", "genewhip-phase5-a", "genewhip-phase5-b"):
        row = admitted.get(fixture_id)
        if not row or row.get("status") != "admitted" or row.get("outcome") != "pass":
            raise ValueError("package-fixture-admission")
    titles = {row["title_id"]: row for row in expected_roster["matrix"]["titles"]}
    for fixture, stem in (("genewhip-independent-game-v2", "independent-game-v2"),
                          ("tank-battle", "tank-battle"), ("recursion94", "recursion94")):
        if hashlib.sha256((share / (stem + ".bin")).read_bytes()).hexdigest() != titles[fixture]["rom_sha256"]:
            raise ValueError("package-fixture-rom")
    scope = json.loads((ROOT / "evidence/v02-execution.json").read_text())
    limits = scope["per_child_limits"]
    route_contract_spec = importlib.util.spec_from_file_location(
        "gw_v02_shared_child_boundary", ROOT / "tests/session/phase6_route_contract.py")
    route_contract = importlib.util.module_from_spec(route_contract_spec)
    route_contract_spec.loader.exec_module(route_contract)
    v02_run_spec = importlib.util.spec_from_file_location("gw_v02_run_preflight", ROOT / "scripts/evidence/v02_run.py")
    v02_run = importlib.util.module_from_spec(v02_run_spec)
    v02_run_spec.loader.exec_module(v02_run)
    _phase7_boundary_negative(route_contract, scratch, limits)

    spec = importlib.util.spec_from_file_location("gw_v02_phase6_route_compiler", ROOT / "scripts/evidence/phase6_routes.py")
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    delivery_map = json.loads((share / "recursion94-consumed-map-v1.json").read_text())
    route_roster = compiler.compile_routes(delivery_map, client="sdl")
    selected = (("tank-battle", "full-route", "tank-battle.bin"),
                ("recursion94", "full-route", "recursion94.bin"),
                ("genewhip-independent-game-v2", "sustained-play", "independent-game-v2.bin"))
    observations = []
    for fixture, case_id, rom_name in selected:
        route = next(row for row in route_roster["routes"] if row["fixture"] == fixture and row["case"]["id"] == case_id)
        route_call_cap = 10_000_000 if fixture == "tank-battle" else 100_000_000
        binary, _ = compiler.lower_route(route, boundary_call_limit=route_call_cap,
                                         delivery_map=delivery_map if fixture == "recursion94" else None,
                                         client="sdl")
        plan, report = scratch / (fixture + ".gwrc"), scratch / (fixture + ".json")
        plan.write_bytes(binary)
        for backend in ("software", "native"):
            report = scratch / (fixture + "-" + backend + ".json")
            env = dict(os.environ, SDL_AUDIODRIVER="dummy")
            if backend == "software":
                env["SDL_VIDEODRIVER"] = "dummy"
            else:
                env.pop("SDL_VIDEODRIVER", None)
            available = v02_run.available_memory_bytes()
            v02_run.require_memory_reserve(available, limits["max_rss_bytes"])
            if shutil.disk_usage(scratch).free < limits["max_scratch_bytes"]:
                raise ValueError("package-objective-route-scratch-reserve")
            processes = []
            command = [str(moved / "bin/genewhip-desktop"), "--route-plan", str(plan),
                       "--route-report", str(report), str(share / rom_name)]
            result = route_contract._run_client(moved / "bin/genewhip-desktop", command, processes,
                report=report, timeout=limits["wall_seconds"], cwd=scratch, env=env,
                monitored_files=((report, limits["max_json_bytes"]),), limits=limits,
                scratch_roots=(scratch,))
            process = processes[-1] if processes else {}
            if (result.returncode != 0 or not report.is_file() or process.get("status") != "completed" or
                    process.get("bound_violation") is not False or process.get("process_group_cleanup") != "confirmed" or
                    not isinstance(process.get("rss_bytes_peak"), int)):
                raise ValueError("package-objective-route:" + fixture + ":" + backend + ":" + result.stderr[-800:])
            facts = json.loads(report.read_text())
            if facts.get("schema") != "genewhip-route-native-v1":
                raise ValueError("package-objective-report:" + fixture + ":schema=" + str(facts.get("schema")) +
                                 ":keys=" + ",".join(sorted(facts)))
            evidence_root = ROOT / "build/v02/desktop-smoke"
            evidence_root.mkdir(parents=True, exist_ok=True)
            retained = evidence_root / (fixture + "-" + backend + ".json")
            shutil.copyfile(report, retained)
            receipt = {"compiled_sha256": hashlib.sha256(binary).hexdigest(),
                       "native_report": {"path": retained.relative_to(ROOT).as_posix(),
                                         "sha256": hashlib.sha256(retained.read_bytes()).hexdigest()},
                       "predicate_results": {predicate["id"]: {
                           "reached": observed.get("reached"), "value": observed.get("value"),
                           "field": observed.get("clock")}
                           for predicate, observed in zip(route["definitions"].get("predicates", []),
                                                          facts.get("predicates", []))}}
            compiler._validate_native_facts(route, "sustained", receipt,
                delivery_map=delivery_map if fixture == "recursion94" else None,
                boundary_call_limit=route_call_cap, client="sdl")
            observations.append({"fixture": fixture, "case": case_id, "outcome": "pass",
                                 "backend": "SDL software renderer" if backend == "software" else "native SDL window",
                                 "objective_samples": len(facts["samples"]), "process": process})
    evidence = json.loads((share / "evidence/manifest.json").read_text())
    if not re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("closure_id", ""))) or not (share / "evidence/compatibility-matrix.md").is_file():
        raise ValueError("package-public-evidence-identity")
    return {"schema": "genewhip-v02-desktop-package-smoke-v1", "outcome": "pass", "relocated": True,
            "source_state": json.loads((moved / "metadata.json").read_text())["source_state"],
            "objective_routes": observations, "public_matrix": "included; each outcome validated",
            "native_window_exercised": True, "physical_display": "unobserved",
            "archived_members": len(files)}


def _phase7_boundary_negative(route_contract, scratch, selected_limits):
    limits = dict(selected_limits)
    limits["wall_seconds"] = 0.25
    report = scratch / "phase7-boundary-negative.json"
    processes = []
    command = ["/bin/sleep", "10"]
    result = route_contract._run_client(pathlib.Path("/bin/sleep"), command, processes,
        report=report, timeout=600, cwd=scratch, env=dict(os.environ), limits=limits,
        scratch_roots=(scratch,))
    if (result.returncode == 0 or len(processes) != 1 or
            processes[0].get("bound_violation") is not True or
            processes[0].get("bound_violation_reason") != "phase7-wall-timeout" or
            processes[0].get("process_group_cleanup") != "confirmed"):
        raise ValueError("phase7-bounded-boundary-negative-failed")


class DesktopArchiveContract(unittest.TestCase):
    def make_archive(self, members):
        tmp = tempfile.TemporaryDirectory(prefix="gw-archive-contract-")
        path = pathlib.Path(tmp.name) / "contract.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        self.addCleanup(tmp.cleanup)
        return path

    def assert_reason(self, members, reason):
        archive = self.make_archive(members)
        with self.assertRaisesRegex(ValueError, "^" + re.escape(reason) + "$"):
            validate_archive(archive, hashlib.sha256(archive.read_bytes()).hexdigest(), "0" * 40)

    def test_duplicate_archive_member_is_rejected_before_payload_use(self):
        self.assert_reason([("root/a", b"a"), ("root/a", b"b")], "archive-duplicate-member")

    def test_traversal_is_rejected_before_payload_use(self):
        self.assert_reason([("../escape", b"x")], "archive-path")

    def test_wrong_archive_checksum_has_named_rejection(self):
        archive = self.make_archive([("root/file", b"payload")])
        with self.assertRaisesRegex(ValueError, "^archive-checksum$"):
            validate_archive(archive, "0" * 64, "0" * 40)

    def test_v02_rejects_recomputed_digest_with_missing_member(self):
        archive = self.make_archive([("root/bin/genewhip-desktop", b"runtime")])
        with self.assertRaisesRegex(ValueError, "^package-member-roster-mismatch$"):
            validate_v02_archive(archive, hashlib.sha256(archive.read_bytes()).hexdigest(), "0" * 40,
                                 ROOT / "packaging/v02-members.json")


def main():
    if sys.argv[1:] == ["--contract"]:
        unittest.main(argv=[sys.argv[0]])
        return
    if sys.argv[1:2] == ["--v02"]:
        parser = argparse.ArgumentParser()
        parser.add_argument("--v02", action="store_true")
        parser.add_argument("archive")
        parser.add_argument("digest")
        parser.add_argument("revision")
        parser.add_argument("roster_path")
        args = parser.parse_args()
        with tempfile.TemporaryDirectory(prefix="gw-v02-desktop-smoke-") as tmp:
            print(json.dumps(run_v02_smoke(args.archive, args.digest, args.revision, args.roster_path,
                                           pathlib.Path(tmp)), sort_keys=True))
        return
    archive, digest, revision = sys.argv[1:]
    validated, files, root = validate_archive(archive, digest, revision)
    validated.close()
    with tempfile.TemporaryDirectory(prefix="gw-desktop-smoke-") as tmp:
        scratch = pathlib.Path(tmp)
        archive_negative_controls(archive, revision, scratch)
        prefix = extract_verified(archive, files, root, scratch)
        share = prefix / "share/genewhip"
        # A changed notice and a changed executable are both caught by the exact
        # inventory before clients are run.
        for relative in ("share/genewhip/SDL3-LICENSE.txt", "bin/genewhip-desktop"):
            path = prefix / relative
            original = path.read_bytes()
            path.write_bytes(original + b"tamper")
            try:
                _PACKAGE.check_staged_inventory(prefix)
            except ValueError as error:
                if str(error) != "package-content-checksum":
                    raise
            else:
                raise ValueError("package-tamper-not-rejected")
            path.write_bytes(original)
        _PACKAGE.check_staged_inventory(prefix)
        moved = scratch / "relocated"
        prefix.rename(moved)
        share = moved / "share/genewhip"
        scenario = json.loads((share / "independent-game-v2-scenario.json").read_text())
        rows = {case["id"]: run_game_case(moved, share, case, scratch / case["id"])
                for case in scenario["cases"]}
        if rows["title-no-start"][10] == rows["start-idle"][10]:
            raise ValueError("package-game-title-transition")
        if rows["start-idle"][19] == rows["start-move"][19]:
            raise ValueError("package-game-movement-transition")
        run_diagnostic(moved, share, scratch)
        bad_log = scratch / "incompatible-input.log"
        bad_log.write_text("genewhip-input-log 99\n")
        bad_input = subprocess.run([str(moved / "bin/genewhip-desktop"), "--fields", "1", "--replay", str(bad_log),
                                    str(share / "independent-game-v2.bin")], capture_output=True, text=True,
                                   env=dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy"), timeout=60)
        if bad_input.returncode == 0 or not bad_input.stderr.startswith("REJECT: input-log"):
            raise ValueError("package-input-log-version-not-rejected")
        missing = subprocess.run([str(moved / "bin/genewhip-desktop"), str(scratch / "absent.bin")],
                                 capture_output=True, text=True, env=dict(os.environ, SDL_VIDEODRIVER="dummy",
                                 SDL_AUDIODRIVER="dummy"), timeout=60)
        if missing.returncode == 0 or not missing.stderr.startswith("REJECT: missing"):
            raise ValueError("package-load-error-not-rejected")
        truncated_rom = scratch / "truncated.bin"
        truncated_rom.write_bytes((share / "independent-game-v2.bin").read_bytes()[:512])
        truncated = subprocess.run([str(moved / "bin/genewhip-desktop"), "--fields", "1", str(truncated_rom)],
                                   capture_output=True, text=True,
                                   env=dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy"), timeout=60)
        if truncated.returncode == 0 or not truncated.stderr.startswith("REJECT: invalid-rom"):
            raise ValueError("package-truncated-cartridge-not-rejected")
        script = scratch / "drop-reload.script"
        script.write_text("1 drop " + str(share / "raster-toy.bin") + "\n"
                          "15 drop " + str(share / "independent-game-v2.bin") + "\n"
                          "30 quit\n")
        dropped = subprocess.run([str(moved / "bin/genewhip-desktop"), "--fields", "30", "--host-script", str(script),
                                  str(share / "independent-game-v2.bin")], capture_output=True, text=True,
                                env=dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy"), timeout=60)
        if dropped.returncode or "fields=30" not in dropped.stdout or "REJECT:" in dropped.stderr:
            raise ValueError("package-drop-reload: " + dropped.stderr[-1000:])
        live = live_package_smoke(moved, share, scenario, scratch) if os.environ.get("GENEWHIP_PACKAGE_LIVE") == "1" else None
        print(json.dumps({"schema": "genewhip-desktop-package-smoke", "version": 1, "outcome": "pass",
                          "game_cases": len(rows), "game_fields": sum(c["frames"] for c in scenario["cases"]),
                          "game_clients": ["headless", "desktop"], "diagnostic_audio": "pass",
                          "drop_reload": "pass", "incompatible_input_log": "rejected",
                          "truncated_cartridge": "rejected", "negative_controls": 12,
                          "relocated": True, "live_host": live or "not requested"}))


if __name__ == "__main__":
    if "--contract" not in sys.argv:
        os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    main()
