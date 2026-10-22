#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate an exact desktop archive before extracting or executing its payload."""
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
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


def validate_archive(archive, digest, revision):
    archive = pathlib.Path(archive)
    if not archive.is_file() or archive.stat().st_size == 0:
        raise ValueError("archive-empty")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive-size-limit")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError("archive-checksum")
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


def main():
    if sys.argv[1:] == ["--contract"]:
        unittest.main(argv=[sys.argv[0]])
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
    main()
