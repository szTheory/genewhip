"""Strict, content-bound fixture admission and consumer gate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

DIAGNOSTIC_ID = "genewhip-diagnostic-v1"
GAME_ID = "genewhip-independent-game-v1"
ORIGINAL_ROM_KIND = "original-rom"
ORIGINAL_ROM_BUILD_SCRIPT = "scripts/fixtures/build-original-roms.sh"
ORIGINAL_ROM_TOOLCHAIN = "fixtures/independent-game/toolchain.lock"
ORIGINAL_ROM_ORACLES = {"documented-hardware-behaviour", "guest-source-derived-arithmetic",
                        "documented-sn76489-formulas"}
OUTCOMES = {"pass", "fail", "blocked", "unknown", "unsupported", "skipped", "infrastructure_error"}
RUNTIME_OUTCOMES = OUTCOMES - {"blocked"}
SPACES = {"AS_PROGRAM", "AS_OPCODES", "AS_DATA", "AS_IO", "AS_USER_PROGRAM", "AS_USER_OPCODES", "AS_CPU_SPACE"}
ROUTES = {"opcode fetch", "normal data read", "normal data write", "memory-mapped I/O read/write",
          "user data read/write", "user opcode fetch", "interrupt acknowledge"}
MAX_SOURCE_ARCHIVE = 250 * 1024 * 1024
MAX_SOURCE_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_SOURCE_MEMBERS = 100_000


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_path(path: object) -> bool:
    return (isinstance(path, str) and bool(path) and not path.startswith("/")
            and "\\" not in path and ":" not in path
            and ".." not in PurePosixPath(path).parts)


def _json(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _same(value: object, expected: object, reason: str) -> str | None:
    return None if value == expected else reason


def _hash_row(path: Path, expected: object, reason: str) -> str | None:
    try:
        return None if isinstance(expected, str) and digest(path) == expected else reason
    except OSError:
        return reason


def _source_archive(root: Path, lock: dict, source_dir: Path) -> tuple[str | None, str | None]:
    """Verify the bounded lock-pinned MAME release archive and its source tree."""
    mame = lock.get("mame", {})
    revision = mame.get("source_revision", "")
    match = re.fullmatch(r"tag (mame[0-9]+); commit ([0-9a-f]{40}); signed tag object ([0-9a-f]{40})", revision)
    if not match or mame.get("source_url") != "https://github.com/mamedev/mame":
        return None, "source-pin"
    tag, commit, _tag_object = match.groups()
    expected = mame.get("source_archive_sha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return None, "source-pin"

    archive = source_dir.parent / f"{tag}.tar.gz"
    temp_context = None
    try:
        if archive.is_file():
            if archive.stat().st_size > MAX_SOURCE_ARCHIVE or digest(archive) != expected:
                return None, "source-archive-digest"
        else:
            temp_context = tempfile.TemporaryDirectory(prefix="gw-mame-source-")
            archive = Path(temp_context.name) / f"{tag}.tar.gz"
            url = f"{mame['source_url']}/archive/refs/tags/{tag}.tar.gz"
            request = urllib.request.Request(url, headers={"User-Agent": "Genewhip-fixture-validator/1"})
            with urllib.request.urlopen(request, timeout=30) as response, archive.open("wb") as out:
                final_url = response.geturl()
                if final_url != url and not re.fullmatch(
                        rf"https://codeload\.github\.com/mamedev/mame/(?:legacy\.tar\.gz|tar\.gz)/refs/tags/{re.escape(tag)}",
                        final_url):
                    return None, "source-redirect"
                total = 0
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_SOURCE_ARCHIVE:
                        return None, "source-archive-size"
                    out.write(block)
            if digest(archive) != expected:
                return None, "source-archive-digest"

        # The archive digest binds the upstream release bytes. Extract only into
        # a private temporary directory and reject traversal, links and bombs.
        with tarfile.open(archive, "r:gz") as bundle:
            expanded = 0
            members = {}
            root_names = set()
            count = 0
            for member in bundle:
                parts = PurePosixPath(member.name).parts
                count += 1
                if (count > MAX_SOURCE_MEMBERS or not parts or ".." in parts
                        or PurePosixPath(member.name).is_absolute()):
                    return None, "source-archive-shape"
                if member.issym() or member.islnk():
                    link = PurePosixPath(member.linkname)
                    if link.is_absolute() or ".." in link.parts:
                        return None, "source-archive-shape"
                    root_names.add(parts[0])
                    continue
                if not (member.isfile() or member.isdir()):
                    return None, "source-archive-shape"
                expanded += member.size
                if expanded > MAX_SOURCE_EXPANDED:
                    return None, "source-archive-size"
                root_names.add(parts[0])
                members[member.name] = member
            if len(root_names) != 1:
                return None, "source-archive-shape"
            archive_root = next(iter(root_names))
            checkout_commit = subprocess.run(
                ["git", "-C", str(source_dir), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True, timeout=10).stdout.strip()
            checkout_tag = subprocess.run(
                ["git", "-C", str(source_dir), "describe", "--exact-match", "--tags", "HEAD"],
                check=True, capture_output=True, text=True, timeout=10).stdout.strip()
            if checkout_commit != commit or checkout_tag != tag:
                return None, "source-revision"
            for relative in (
                "src/devices/cpu/m68000/m68000.cpp", "src/devices/cpu/m68000/m68kcpu.cpp",
                "src/devices/cpu/m68000/m68000-sdp.cpp", "src/devices/cpu/m68000/m68000.h",
                "src/devices/cpu/m68000/m68kcommon.h", "src/mame/sega/megadriv.cpp",
                "src/mame/sega/mdconsole.cpp", "src/emu/emumem_aspace.cpp",
                "src/emu/emumem.h", "src/emu/emumem_het.cpp", "src/emu/emumem_het.h", "src/emu/emumem.cpp"):
                member = members.get(f"{archive_root}/{relative}")
                if member is None:
                    return None, "source-archive-tree"
                archived = bundle.extractfile(member)
                original = subprocess.run(
                    ["git", "-C", str(source_dir), "show", f"{commit}:{relative}"],
                    check=True, capture_output=True, timeout=20).stdout
                if archived is None or archived.read() != original:
                    return None, "source-archive-tree"
        return expected, None
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError, KeyError):
        return None, "source-archive-error"
    finally:
        if temp_context:
            temp_context.cleanup()


def _run_current_route_audit(root: Path, lock_path: Path, source_dir: Path) -> tuple[dict | None, str | None]:
    audit_script = root / "fixtures/independent-game/route_audit.py"
    with tempfile.TemporaryDirectory(prefix="gw-route-audit-") as temp:
        output = Path(temp) / "route-audit.json"
        try:
            result = subprocess.run(
                ["python3", str(audit_script), "--verify-toolchain-lock", str(lock_path),
                 "--source", str(source_dir), "--output", str(output)],
                cwd=root, capture_output=True, text=True, timeout=120,
                env={**os.environ, "GENEWHIP_MAME_SOURCE_DIR": str(source_dir)})
        except (OSError, subprocess.TimeoutExpired):
            return None, "route-audit-infrastructure"
        if result.returncode != 0:
            return None, "route-audit-failed"
        audit = _json(output)
        if not audit or audit.get("status") != "pass" or audit.get("errors") != []:
            return None, "route-audit-result"
        return audit, None


def _validate_runtime(evidence: dict, scenario: dict) -> str | None:
    if not isinstance(evidence, dict) or not isinstance(scenario, dict):
        return "runtime-schema"
    if evidence.get("schema_version") != 1 or evidence.get("status") != "pass" or evidence.get("errors") != []:
        return "runtime-status"
    if (evidence.get("temporal_scope") != {
            "kind": "historical_pre_admission_snapshot"}
            or evidence.get("candidate_disposition") != {
                "scope": "runtime_evidence_capture",
                "status": "candidate",
            }):
        return "runtime-scope"
    if evidence.get("purpose") != "bounded runtime qualification evidence; historical pre-admission snapshot":
        return "qualification-purpose"
    if evidence.get("pong_disposition") != "rejected":
        return "pong-disposition"
    expected_counts = {state: 0 for state in RUNTIME_OUTCOMES}
    expected_counts["pass"] = 2
    if evidence.get("outcome_denominator") != 2 or evidence.get("outcome_counts") != expected_counts:
        return "outcome-denominator"
    runs = evidence.get("runs")
    if not isinstance(runs, list) or len(runs) != 2 or any(not isinstance(r, dict) for r in runs) or {r.get("name") for r in runs} != {
            "sram-route-sentinel", "bounded-gameplay-scenario"}:
        return "runtime-runs"
    sentinel = next((r for r in runs if r.get("name") == "sram-route-sentinel"), {})
    observed = sentinel.get("sentinel_observations", {})
    if sentinel.get("status") != "pass" or observed != {
            "sram_enable_control_reads": 1, "sram_enable_control_writes": 1,
            "sram_storage_reads": 1, "sram_storage_writes": 1}:
        return "sram-positive-control"
    gameplay = next((r for r in runs if r.get("name") == "bounded-gameplay-scenario"), {})
    if gameplay.get("status") != "pass" or gameplay.get("oracle", {}).get("passed") is not True:
        return "progression"
    if gameplay.get("sram_accesses") != {"storage": 0, "enable_control": 0}:
        return "sram-access"
    trace = gameplay.get("trace", {})
    if not isinstance(trace, dict):
        return "trace-completeness"
    budget = scenario.get("budget", {})
    if not isinstance(budget, dict):
        return "trace-completeness"
    rows = trace.get("rows")
    trace_bytes = trace.get("bytes")
    address_min, address_max = trace.get("address_min"), trace.get("address_max")
    if (not isinstance(rows, int) or rows <= 0 or trace.get("first_sequence") != 1
            or trace.get("last_sequence") != rows or not isinstance(trace_bytes, int) or trace_bytes <= 0
            or not isinstance(address_min, int) or not isinstance(address_max, int)
            or trace_bytes > budget.get("max_trace_bytes", 0)
            or rows > budget.get("max_trace_rows", 0)
            or address_min != 0 or address_max > 0xFFFFFF
            or not re.fullmatch(r"[0-9a-f]{64}", str(trace.get("sha256", "")))):
        return "trace-completeness"
    coverage = evidence.get("coverage", {})
    if not isinstance(coverage, dict):
        return "coverage"
    if (coverage.get("route_audit_status") != "pass" or coverage.get("source_route_to_hook") != "pass"
            or coverage.get("runtime_progression") != "pass"
            or coverage.get("trace_complete_and_ordered") is not True
            or coverage.get("forbidden_candidate_accesses") != {"storage": 0, "enable_control": 0}):
        return "coverage"
    return None


def _validate_notice_disposition(notice: str, fixture_status: str) -> str | None:
    """Reject notice claims about admission status that conflict with the manifest row."""
    if not isinstance(notice, str):
        return "notice-disposition"
    claims = re.finditer(
        r"\b(?:independent\s+game|fixture|rom|game|candidate)\b"
        r"[^.!?]{0,160}?\b(?:is|remains|stays|has)\s+"
        r"(?:(?:still|currently)\s+)?(?:a\s+)?"
        r"(not\s+(?:currently\s+|been\s+)?admitted|unadmitted|rejected|admitted|candidate)\b",
        notice,
        flags=re.IGNORECASE,
    )
    equivalent_statuses = {
        "admitted": {"admitted"},
        "candidate": {"candidate", "not admitted", "unadmitted"},
        "rejected": {"rejected"},
        "unadmitted": {"not admitted", "unadmitted"},
    }
    allowed = equivalent_statuses.get(fixture_status, {fixture_status})
    for claim in claims:
        claimed_status = " ".join(claim.group(1).casefold().split())
        if claimed_status in {"not currently admitted", "not been admitted"}:
            claimed_status = "not admitted"
        if claimed_status not in allowed:
            return "notice-disposition"
    return None


def _compare_audit(evidence: dict, audit: dict, audit_path: Path, lock: dict) -> str | None:
    if not all(isinstance(value, dict) for value in (evidence, audit, lock)):
        return "audit-schema"
    identities = evidence.get("identities", {})
    if evidence.get("device_map") != audit.get("machine", {}).get("map_entries"):
        return "audit-device-map"
    expected_spaces, actual_spaces = evidence.get("spaces"), audit.get("spaces")
    if not isinstance(expected_spaces, list) or not isinstance(actual_spaces, list):
        return "audit-spaces"
    expected_space_rows = {r.get("space"): r for r in expected_spaces if isinstance(r, dict)}
    actual_space_rows = {r.get("space"): r for r in actual_spaces if isinstance(r, dict)}
    if expected_space_rows.keys() != actual_space_rows.keys():
        return "audit-spaces"
    for name in SPACES:
        if expected_space_rows[name] != actual_space_rows[name]:
            if expected_space_rows[name].get("status") == "alias" or actual_space_rows[name].get("status") == "alias":
                return "audit-aliases"
            return "audit-spaces"
    if evidence.get("routes") != audit.get("routes"):
        return "audit-routes"
    expected_ranges, actual_ranges = evidence.get("instrumented_address_ranges"), audit.get("applicable_transactions")
    if not isinstance(expected_ranges, dict) or not isinstance(actual_ranges, dict) or expected_ranges.keys() != actual_ranges.keys():
        return "audit-applicable-spaces"
    for name in actual_ranges:
        expected_range, actual_range = expected_ranges[name], actual_ranges[name]
        if any(expected_range.get(key) != actual_range.get(key) for key in ("start", "end", "bits")):
            return "audit-full-address-span"
        if expected_range.get("transactions") != actual_range.get("transactions"):
            return "audit-access-kinds"
        if expected_range.get("hook") != actual_range.get("hook"):
            return "audit-ranges"
    checks = (
        (identities.get("mame_source_archive_sha256"), lock.get("mame", {}).get("source_archive_sha256"), "audit-source-digest"),
        (identities.get("mame_source_revision", "").split("commit ")[-1].split(";")[0],
         lock.get("mame", {}).get("source_revision", "").split("commit ")[-1].split(";")[0], "audit-source-revision"),
        (identities.get("mame_configuration_sha256"), audit.get("build", {}).get("source_configuration_identity"), "audit-build-config"),
        (identities.get("mame_executable_sha256"), audit.get("build", {}).get("executable_build_sha256"), "audit-build-executable"),
        (identities.get("mame_patch_sha256"), audit.get("build", {}).get("patch_sha256"), "audit-patch"),
        (identities.get("route_audit_sha256"), digest(audit_path), "audit-digest"),
    )
    for actual, expected, reason in checks:
        if actual != expected:
            return reason
    if not isinstance(audit.get("spaces"), list) or {r.get("space") for r in audit["spaces"]} != SPACES:
        return "audit-space-roster"
    space_rows = {r["space"]: r for r in audit["spaces"]}
    for name in SPACES:
        row = space_rows[name]
        if not row.get("source_disposition") or row.get("status") not in {"configured", "alias", "inapplicable"}:
            return "audit-space-disposition"
        if row["status"] == "alias" and row.get("hooked_alias") != "AS_PROGRAM":
            return "audit-aliases"
    ranges = audit.get("applicable_transactions", {})
    if set(ranges) != {"AS_PROGRAM", "AS_CPU_SPACE"}:
        return "audit-applicable-spaces"
    for name, row in ranges.items():
        if row.get("start") != "0x000000" or row.get("end") != "0xFFFFFF" or row.get("bits") != 24:
            return "audit-full-address-span"
        if row.get("hook") != "genewhip_trace" or not row.get("transactions"):
            return "audit-access-kinds"
    routes = audit.get("routes", [])
    if not isinstance(routes, list) or {r.get("route") for r in routes} != ROUTES:
        return "audit-routes"
    maps = audit.get("machine", {}).get("map_entries", [])
    if not isinstance(maps, list) or len(maps) < 1 or any(
            not isinstance(row.get("start"), str) or not isinstance(row.get("end"), str)
            or not row.get("mapping") or not row.get("access") for row in maps):
        return "audit-device-map"
    proof = audit.get("hook_proof", {})
    if (proof.get("root_passthrough_taps") is not True
            or proof.get("read_and_write_cache_invalidation") is not True
            or proof.get("tap_callbacks_delegate_to_original_handler") is not True
            or proof.get("tap_node_direct_read_pointer") != "nullptr"):
        return "audit-hook-proof"
    return None


def _validate_game(row: dict, root: Path, evidence: dict | None = None) -> str:
    evidence = evidence if evidence is not None else _json(root / "evidence/independent-game.json")
    if not isinstance(evidence, dict):
        return "runtime-evidence"
    if row.get("status") != "admitted" or row.get("outcome") != "pass":
        return "admission"
    required = {"id", "project", "revision", "source", "source_sha256", "license", "notices",
                "assets", "build", "sha256", "oracle", "profile", "input", "rom", "evidence_sha256"}
    if not required <= row.keys() or row.get("id") != GAME_ID:
        return "fields"
    if not public_path(row.get("source")) or row["source"] != "fixtures/independent-game/src/game.s":
        return "path"
    if row.get("license") != "MIT" or row.get("project") != "Genewhip" or row.get("assets") != []:
        return "rights"
    if not isinstance(row.get("notices"), list) or "fixtures/independent-game/NOTICES.md" not in row["notices"]:
        return "notice"
    for rel in row["notices"]:
        if not public_path(rel) or not (root / rel).is_file():
            return "notice"
    source = root / row["source"]
    if _hash_row(source, row.get("source_sha256"), "source"):
        return "source"
    identities = evidence.get("identities", {})
    tracked_evidence_path = root / "evidence/independent-game.json"
    tracked_evidence = _json(tracked_evidence_path)
    if evidence != tracked_evidence:
        return "evidence-stale"
    if row.get("evidence_sha256") != digest(tracked_evidence_path):
        return "evidence-digest"
    if identities.get("candidate_source_relative_path") != row["source"] or identities.get("candidate_source_sha256") != row["source_sha256"]:
        return "source"
    try:
        revision = subprocess.run(["git", "-C", str(root), "log", "--follow", "--format=%H", "-1", "--", row["source"]],
                                  check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "revision"
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or row.get("revision") != revision:
        return "revision"
    notices = root / "fixtures/independent-game/NOTICES.md"
    if identities.get("candidate_notice_sha256") != digest(notices):
        return "notice"
    try:
        notice_text = notices.read_text()
    except (OSError, UnicodeDecodeError):
        return "notice"
    if _validate_notice_disposition(notice_text, row.get("status")):
        return "notice-disposition"
    rom = root / "fixtures/independent-game/game.bin"
    if row.get("sha256") != identities.get("rom_sha256") or _hash_row(rom, row.get("sha256"), "rom"):
        return "rom"
    scenario = _json(root / "fixtures/independent-game/scenario.json")
    if not scenario or scenario.get("rom", {}).get("sha256") != row["sha256"]:
        return "scenario"
    if row.get("profile") != scenario.get("machine", {}).get("profile"):
        return "profile"
    if row.get("input") != scenario.get("scenario_id"):
        return "input"
    if row.get("oracle") != scenario.get("oracle", {}).get("kind"):
        return "oracle"
    if identities.get("scenario_sha256") != digest(root / "fixtures/independent-game/scenario.json"):
        return "scenario"
    input_script = root / "fixtures/independent-game/mame.lua"
    if identities.get("input_script_sha256") != digest(input_script):
        return "input"
    if evidence.get("scenario") != scenario:
        return "scenario"
    build = row.get("build")
    if not isinstance(build, dict) or build.get("source") != "fixtures/independent-game/build.sh":
        return "build"
    if build.get("sha256") != digest(root / build["source"]):
        return "build"
    if (build.get("toolchain") != "GNU Binutils 2.47 source-built m68k-elf-as"
            or build.get("command") != "fixtures/independent-game/build.sh --verify-reproducible"):
        return "build"
    lock_path = root / "fixtures/independent-game/toolchain.lock"
    lock = _json(lock_path)
    if not lock or identities.get("candidate_toolchain_lock_sha256") != digest(lock_path):
        return "tool"
    mame = lock.get("mame", {})
    toolchain = lock.get("assembler", {})
    assembler = toolchain
    if (assembler.get("version") != "2.47"
            or assembler.get("source_archive_sha256") != "3068128c75cda9f898ccb4211d360246e8e195ffcc9dfb655b23ae23a54800e8"
            or assembler.get("signature", {}).get("outcome") != "GOODSIG and VALIDSIG; no expired, revoked, bad-signature, or missing-key status"
            or assembler.get("executable", {}).get("target") != "m68k-elf"
            or not re.fullmatch(r"[0-9a-f]{64}", str(assembler.get("executable", {}).get("sha256", "")))
            or not assembler.get("candidate_builder", {}).get("source_archive_sha256")
            or mame.get("status") != "pass"
            or mame.get("source_signature", {}).get("status") != "pass"):
        return "tool"
    if identities.get("mame_patch_sha256") != digest(root / "fixtures/independent-game/mame.patch"):
        return "patch"
    if identities.get("mame_build_script_sha256") != digest(root / "fixtures/independent-game/mame_build.sh"):
        return "tool"
    if identities.get("trace_parser_sha256") != digest(root / "fixtures/independent-game/trace.py"):
        return "trace-parser"
    route_file = root / "fixtures/independent-game/route_audit.json"
    audit_hash = _hash_row(route_file, identities.get("route_audit_sha256"), "audit-digest")
    if audit_hash:
        return audit_hash
    if evidence.get("coverage", {}).get("route_audit_status") != "pass":
        return "route-audit"
    if evidence.get("identities", {}).get("rom_sha256") != row["sha256"]:
        return "rom"
    if evidence.get("identities", {}).get("profile") != row["profile"]:
        return "profile"
    if _validate_runtime(evidence, scenario):
        return _validate_runtime(evidence, scenario) or "runtime-evidence"
    return "ok"


def _validate_original_rom(row: dict, root: Path) -> str:
    """Admit an original assembled ROM only with complete, offline-checkable provenance.

    Reasons: path, content, source, build, notice, oracle. Rebuilding from source is
    a separate reproducibility command (scripts/fixtures/build-original-roms.sh).
    """
    root = Path(root)
    build = row.get("build")
    notices = row.get("notices")
    if (not isinstance(build, dict) or not isinstance(notices, list) or not notices
            or not public_path(row.get("source")) or not public_path(row.get("rom"))
            or not public_path(build.get("source"))
            or not all(public_path(item) for item in notices)):
        return "path"
    if row.get("status") != "admitted" or row.get("outcome") != "pass":
        return "admission"
    if row.get("license") != "MIT" or row.get("assets") != []:
        return "notice"
    size = row.get("rom_bytes")
    try:
        rom = (root / row["rom"]).read_bytes()
    except OSError:
        return "content"
    if (not isinstance(size, int) or isinstance(size, bool) or size <= 0
            or len(rom) != size or digest_bytes(rom) != row.get("sha256")):
        return "content"
    if _hash_row(root / row["source"], row.get("source_sha256"), "source"):
        return "source"
    if (build.get("source") != ORIGINAL_ROM_BUILD_SCRIPT
            or _hash_row(root / build["source"], build.get("sha256"), "build")
            or build.get("toolchain") != ORIGINAL_ROM_TOOLCHAIN
            or not isinstance(build.get("name"), str) or not build["name"]
            or not isinstance(build.get("command"), str) or not build["command"]):
        return "build"
    if any(not (root / item).is_file() for item in notices):
        return "notice"
    if row.get("oracle") not in ORIGINAL_ROM_ORACLES:
        return "oracle"
    return "ok"


def validate(document, root, rom, *, candidate_evidence=None):
    """Validate the complete manifest; admitted game rows require live evidence."""
    root = Path(root)
    rom = Path(rom)
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        return "manifest"
    rows = document.get("fixtures")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
        return "denominator"
    seen = set()
    fields = {"id", "status", "outcome", "project", "revision", "source", "source_sha256",
              "license", "notices", "assets", "build", "sha256", "oracle", "profile", "input"}
    diagnostic_seen = False
    game_seen = False
    for row in rows:
        if not isinstance(row, dict) or not fields <= row.keys():
            return "fields"
        if not isinstance(row["id"], str) or row["id"] in seen:
            return "duplicate"
        seen.add(row["id"])
        if row["id"] == DIAGNOSTIC_ID:
            diagnostic_seen = True
            if row["status"] != "admitted" or row["outcome"] != "pass":
                return "diagnostic"
            if not public_path(row["source"]):
                return "path"
            try:
                if digest(root / row["source"]) != row["source_sha256"]:
                    return "source"
                if digest(rom) != row["sha256"]:
                    return "content"
                build = row["build"]
                if not isinstance(build, dict) or not public_path(build["source"]):
                    return "path"
                if digest(root / build["source"]) != build["sha256"]:
                    return "build"
                if not build.get("toolchain") or not build.get("command"):
                    return "build"
                if any(not (root / p).is_file() for p in row["notices"]):
                    return "notice"
            except (OSError, KeyError, TypeError):
                return "source"
        elif row["id"] == GAME_ID:
            game_seen = True
            result = _validate_game(row, root, candidate_evidence)
            if result != "ok":
                return result
        elif row.get("kind") == ORIGINAL_ROM_KIND:
            result = _validate_original_rom(row, root)
            if result != "ok":
                return result
        else:
            if row["status"] == "admitted":
                return "admission"
            if row["status"] not in ("rejected", "unadmitted") or row["outcome"] not in OUTCOMES - {"pass"}:
                return "admission"
            if row.get("sha256") is not None:
                return "unverified-bytes"
            if not row.get("blocked_gates") or not row.get("replacement"):
                return "admission"
    if not diagnostic_seen:
        return "diagnostic"
    return "ok" if game_seen else "ok"


def validate_current_game(document, root, rom, *, candidate_evidence=None):
    """Validate a temporary admitted manifest against fresh pinned MAME route evidence."""
    result = validate(document, root, rom, candidate_evidence=candidate_evidence)
    if result != "ok":
        return result
    rows = document.get("fixtures", [])
    candidate = next((row for row in rows if isinstance(row, dict) and row.get("id") == GAME_ID), None)
    if candidate is None or candidate.get("status") != "admitted":
        return "admission"
    root = Path(root).resolve()
    lock_path = root / "fixtures/independent-game/toolchain.lock"
    lock = _json(lock_path)
    if not lock:
        return "tool"
    try:
        # This locator is owned by the checked-in audit, never by a manifest or
        # evidence field. All persisted identities remain repository-relative.
        audit_spec = __import__("importlib.util", fromlist=["spec_from_file_location"])
        spec = audit_spec.spec_from_file_location("gw_route_audit", root / "fixtures/independent-game/route_audit.py")
        module = audit_spec.module_from_spec(spec)
        spec.loader.exec_module(module)
        source_dir = Path(module.DEFAULT_SOURCE)
        archive_sha, archive_error = _source_archive(root, lock, source_dir)
        if archive_error:
            return archive_error
        if archive_sha != lock["mame"]["source_archive_sha256"]:
            return "source-archive-digest"
        audit, audit_error = _run_current_route_audit(root, lock_path, source_dir)
        if audit_error:
            return audit_error
    except (OSError, AttributeError, ImportError, TypeError):
        return "route-audit-infrastructure"
    evidence = candidate_evidence if candidate_evidence is not None else _json(root / "evidence/independent-game.json")
    if not evidence:
        return "runtime-evidence"
    scenario = _json(root / "fixtures/independent-game/scenario.json")
    if not scenario:
        return "scenario"
    audit_path = root / "fixtures/independent-game/route_audit.json"
    if audit != _json(audit_path):
        return "audit-recomputed-mismatch"
    return _compare_audit(evidence, audit, audit_path, lock) or "ok"


def require_admitted(root, manifest_path, fixture_id, diagnostic_rom):
    """Return only the repository-contained ROM for a fully validated record."""
    # Keep the stable CLI handle unversioned while manifest identities version
    # the fixture record and evidence contract explicitly.
    if fixture_id == "genewhip-independent-game":
        fixture_id = GAME_ID
    root = Path(root).resolve()
    manifest_path = Path(manifest_path)
    diagnostic_rom = Path(diagnostic_rom)
    try:
        if manifest_path.is_absolute() or not public_path(str(manifest_path)):
            raise ValueError("manifest-path")
        if diagnostic_rom.is_absolute() or not public_path(str(diagnostic_rom)):
            raise ValueError("diagnostic-rom-path")
        resolved_manifest = (root / manifest_path).resolve()
        if root not in resolved_manifest.parents or not resolved_manifest.is_file():
            raise ValueError("manifest-path")
        resolved_diagnostic = (root / diagnostic_rom).resolve()
        if root not in resolved_diagnostic.parents or not resolved_diagnostic.is_file():
            raise ValueError("diagnostic-rom-path")
        document = _json(resolved_manifest)
        if not document:
            raise ValueError("manifest")
        rows = document.get("fixtures", [])
        row = next((r for r in rows if isinstance(r, dict) and r.get("id") == fixture_id), None)
        if not row or row.get("status") != "admitted":
            raise ValueError("admission")
        if row.get("id") == GAME_ID:
            result = validate_current_game(document, root, resolved_diagnostic)
        else:
            result = validate(document, root, resolved_diagnostic)
        if result != "ok":
            raise ValueError(result)
        rom_path = row.get("rom", "fixtures/independent-game/game.bin" if fixture_id == GAME_ID else str(diagnostic_rom))
        if not public_path(rom_path):
            raise ValueError("rom-path")
        resolved_rom = (root / rom_path).resolve()
        if root not in resolved_rom.parents or not resolved_rom.is_file():
            raise ValueError("rom-path")
        expected = row.get("sha256")
        if not isinstance(expected, str) or digest(resolved_rom) != expected:
            raise ValueError("rom-hash")
        return resolved_rom
    except (OSError, TypeError, ValueError, AttributeError, KeyError) as exc:
        raise ValueError(f"fixture admission failed: {exc}") from exc
