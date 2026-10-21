"""Admission controls for the independently authored playable fixture."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
sys.dont_write_bytecode = True

root, diagnostic_rom = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
spec = importlib.util.spec_from_file_location(
    "fixture_manifest", root / "tools/evidence/fixture_manifest.py")
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)

manifest_bytes = (root / "fixtures/manifest.json").read_bytes()
document = json.loads(manifest_bytes)
evidence_bytes = (root / "evidence/independent-game.json").read_bytes()
evidence = json.loads(evidence_bytes)
candidate = copy.deepcopy(document["fixtures"][1])
candidate.update({
    "id": admission.GAME_ID,
    "status": "admitted",
    "outcome": "pass",
    "project": "Genewhip",
    "revision": subprocess.check_output(
        ["git", "-C", str(root), "log", "--follow", "--format=%H", "-1", "--",
         "fixtures/independent-game/src/game.s"], text=True).strip(),
    "source": "fixtures/independent-game/src/game.s",
    "source_sha256": admission.digest(root / "fixtures/independent-game/src/game.s"),
    "license": "MIT",
    "notices": ["fixtures/independent-game/NOTICES.md"],
    "assets": [],
    "build": {"source": "fixtures/independent-game/build.sh",
              "sha256": admission.digest(root / "fixtures/independent-game/build.sh"),
              "toolchain": "GNU Binutils 2.47 source-built m68k-elf-as",
              "command": "fixtures/independent-game/build.sh --verify-reproducible"},
    "sha256": admission.digest(root / "fixtures/independent-game/game.bin"),
    "rom": "fixtures/independent-game/game.bin",
    "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
    "oracle": "independent-work-ram-progression",
    "profile": "VA3-NTSC-U",
    "input": "genewhip-independent-game-start-right-ntscu-v1",
})
document["fixtures"][1] = candidate

def expect_rejection(name, actual, expected):
    if actual != expected:
        raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")

def candidate_rejection(name, mutate, expected):
    changed = copy.deepcopy(candidate)
    mutate(changed)
    expect_rejection(name, admission._validate_game(changed, root, evidence), expected)

candidate_rejection("missing license grant", lambda r: r.update(license=""), "rights")
candidate_rejection("missing source notice", lambda r: r.update(notices=[]), "notice")
candidate_rejection("stale candidate source", lambda r: r.update(source_sha256="0" * 64), "source")
candidate_rejection("stale candidate revision", lambda r: r.update(revision="0" * 40), "revision")
candidate_rejection("stale candidate build", lambda r: r["build"].update(sha256="0" * 64), "build")
candidate_rejection("stale candidate ROM", lambda r: r.update(sha256="0" * 64), "rom")
candidate_rejection("stale profile", lambda r: r.update(profile="PAL"), "profile")
candidate_rejection("stale input", lambda r: r.update(input="unscripted"), "input")
candidate_rejection("stale oracle", lambda r: r.update(oracle="trace-derived"), "oracle")
candidate_rejection("stale evidence digest", lambda r: r.update(evidence_sha256="0" * 64), "evidence-digest")
candidate_rejection("absolute source identity", lambda r: r.update(source="/private/rom.bin"), "path")
candidate_rejection("qualification cannot imply admission", lambda r: r.update(status="unadmitted"), "admission")
if (root / "fixtures/manifest.json").read_bytes() != manifest_bytes:
    raise AssertionError("tracked fixture manifest changed during controlled admission")

def runtime_rejection(name, mutate, expected):
    changed = copy.deepcopy(evidence)
    mutate(changed)
    expect_rejection(name, admission._validate_runtime(changed, evidence["scenario"]), expected)

runtime_rejection("unknown overall outcome", lambda e: e.update(status="unknown"), "runtime-status")
runtime_rejection("non-pass denominator", lambda e: e["outcome_counts"].update({"pass": 1, "unknown": 1}), "outcome-denominator")
runtime_rejection("missing SRAM positive control", lambda e: e["runs"][0]["sentinel_observations"].update(sram_storage_reads=0), "sram-positive-control")
runtime_rejection("candidate SRAM access", lambda e: e["runs"][1]["sram_accesses"].update(storage=1), "sram-access")
runtime_rejection("truncated trace", lambda e: e["runs"][1]["trace"].update(last_sequence=1), "trace-completeness")
runtime_rejection("failed progression", lambda e: e["runs"][1]["oracle"].update(passed=False), "progression")

audit = json.loads((root / "fixtures/independent-game/route_audit.json").read_text())
lock = json.loads((root / "fixtures/independent-game/toolchain.lock").read_text())
audit_path = root / "fixtures/independent-game/route_audit.json"
def audit_rejection(name, mutate, expected):
    changed = copy.deepcopy(evidence)
    mutate(changed)
    expect_rejection(name, admission._compare_audit(changed, audit, audit_path, lock), expected)

audit_rejection("missing device map row", lambda e: e["device_map"].pop(), "audit-device-map")
audit_rejection("missing logical space", lambda e: e["spaces"].pop(), "audit-spaces")
audit_rejection("missing alias", lambda e: e["spaces"].__setitem__(1, {**e["spaces"][1], "hooked_alias": None}), "audit-aliases")
audit_rejection("missing transaction kind", lambda e: e["instrumented_address_ranges"]["AS_PROGRAM"]["transactions"].pop(), "audit-access-kinds")
audit_rejection("partial address range", lambda e: e["instrumented_address_ranges"]["AS_PROGRAM"].update(end="0x7FFFFF"), "audit-full-address-span")
audit_rejection("missing route", lambda e: e["routes"].pop(), "audit-routes")
audit_rejection("missing route audit digest", lambda e: e["identities"].update(route_audit_sha256="0" * 64), "audit-digest")
audit_rejection("stale MAME build identity", lambda e: e["identities"].update(mame_configuration_sha256="0" * 64), "audit-build-config")
audit_rejection("extra logical space", lambda e: e["spaces"].append({"space": "AS_EXTRA"}), "audit-spaces")
audit_rejection("extra access route", lambda e: e["routes"].append({"route": "unproven route"}), "audit-routes")

route_spec = importlib.util.spec_from_file_location(
    "route_audit", root / "fixtures/independent-game/route_audit.py")
route_audit = importlib.util.module_from_spec(route_spec)
route_spec.loader.exec_module(route_audit)
mame_source = Path(route_audit.DEFAULT_SOURCE)
if not (mame_source / ".git").is_dir() or not (mame_source / "genewhip").is_file():
    # The recorded-evidence checks above ran; the fresh MAME route checks need a local build.
    shown = (mame_source.relative_to(root).as_posix() if root in mame_source.parents
             else "GENEWHIP_MAME_SOURCE_DIR")
    print(f"SKIP: MAME 0.289 checkout absent at {shown}; recorded-evidence rejection checks passed. "
          "Build it with GENEWHIP_MAME_WORK_ROOT=build/tool-cache/mame0289 "
          "fixtures/independent-game/mame_build.sh --build")
    sys.exit(77)

with tempfile.TemporaryDirectory(prefix=".gw-admission-", dir=root) as temp:
    temp_root = Path(temp)
    temporary_manifest = temp_root / "manifest.json"
    temporary_evidence = temp_root / "independent-game.json"
    temporary_manifest.write_text(json.dumps(document))
    temporary_evidence.write_bytes(evidence_bytes)
    controlled_manifest = json.loads(temporary_manifest.read_text())
    controlled_evidence = json.loads(temporary_evidence.read_text())
    actual = admission.validate_current_game(
        controlled_manifest, root, diagnostic_rom, candidate_evidence=controlled_evidence)
if actual != "ok":
    raise AssertionError(
        "controlled temporary manifest with current candidate evidence should admit; "
        f"got {actual!r}")
if (root / "fixtures/manifest.json").read_bytes() != manifest_bytes:
    raise AssertionError("tracked fixture manifest changed during controlled admission")

def mutated_route_control():
    source = mame_source
    commit = lock["mame"]["source_revision"].split("commit ")[-1].split(";")[0]
    source_files = [
        "src/devices/cpu/m68000/m68000.cpp", "src/devices/cpu/m68000/m68kcpu.cpp",
        "src/devices/cpu/m68000/m68000-sdp.cpp", "src/devices/cpu/m68000/m68000.h",
        "src/devices/cpu/m68000/m68kcommon.h", "src/mame/sega/megadriv.cpp",
        "src/mame/sega/mdconsole.cpp", "src/mame/sega/megadriv.h", "src/emu/emumem_aspace.cpp",
        "src/emu/emumem.h", "src/emu/emumem_het.cpp", "src/emu/emumem_het.h", "src/emu/emumem.cpp"]
    build_files = [row["path"] for row in lock["mame"]["source_configuration_files"]]
    with tempfile.TemporaryDirectory(prefix="gw-mutated-route-") as temp:
        clone = Path(temp) / "mame"
        subprocess.run(["git", "clone", "--quiet", "--shared", "--no-checkout", str(source), str(clone)],
                       check=True, capture_output=True, timeout=60)
        subprocess.run(["git", "-C", str(clone), "sparse-checkout", "init", "--no-cone"],
                       check=True, capture_output=True, timeout=20)
        sparse = ["/" + p for p in source_files + build_files]
        subprocess.run(["git", "-C", str(clone), "sparse-checkout", "set", "--no-cone", *sparse],
                       check=True, capture_output=True, timeout=20)
        subprocess.run(["git", "-C", str(clone), "checkout", "--quiet", "--detach", commit],
                       check=True, capture_output=True, timeout=30)
        for relative in ["genewhip", *build_files]:
            target = clone / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copyfile(source / relative, target)
        subprocess.run(["git", "-C", str(clone), "apply", str(root / "fixtures/independent-game/mame.patch")],
                       check=True, capture_output=True, timeout=20)
        callback = clone / "src/emu/emumem_het.cpp"
        changed = callback.read_text()
        needle = "m_tap(offset, data, mem_mask);"
        if needle not in changed:
            raise AssertionError("mutation setup cannot find the pinned read tap callback")
        callback.unlink()
        callback.write_text(changed.replace(needle, "/* deliberately removed route callback */"))
        output = Path(temp) / "audit.json"
        result = subprocess.run(
            ["python3", str(root / "fixtures/independent-game/route_audit.py"),
             "--verify-toolchain-lock", str(root / "fixtures/independent-game/toolchain.lock"),
             "--source", str(clone), "--output", str(output)],
            cwd=root, capture_output=True, text=True, timeout=120)
        combined = result.stdout + result.stderr
        if result.returncode == 0 or "read callback logger invocation" not in combined:
            raise AssertionError(
                "mutated route must fail by naming the removed read callback mapping; "
                f"exit={result.returncode}, output={combined[-1200:]!r}")

mutated_route_control()

if len(sys.argv) == 4 and sys.argv[3] == "--consumer-gate":
    consumer = root / "scripts/fixtures/run_admitted.py"
    with tempfile.TemporaryDirectory(prefix=".gw-consumer-", dir=root) as temp:
        temp_root = Path(temp)
        manifest_path = temp_root / "manifest.json"

        def invoke(manifest, *, diagnostic="build/ci/native/diagnostic.bin",
                   fixture_id=admission.GAME_ID):
            manifest_path.write_text(json.dumps(manifest))
            return subprocess.run(
                [sys.executable, str(consumer), "--root", str(root),
                 "--manifest", manifest_path.relative_to(root).as_posix(),
                 "--fixture-id", fixture_id, "--diagnostic-rom", diagnostic],
                cwd=root, capture_output=True, text=True, timeout=180)

        unadmitted = copy.deepcopy(document)
        unadmitted["fixtures"][1]["status"] = "candidate"
        if invoke(unadmitted).returncode == 0:
            raise AssertionError("normal consumer accepted the candidate before admission")
        if invoke(document, diagnostic="../outside.bin").returncode == 0:
            raise AssertionError("normal consumer accepted a path-escaping diagnostic")
        accepted = invoke(document)
        expected_rom = (root / candidate["rom"]).resolve()
        if accepted.returncode != 0 or Path(accepted.stdout.strip()) != expected_rom:
            raise AssertionError(f"consumer did not return the admitted exact ROM: {accepted.stderr!r}")
        stable_alias = invoke(document, fixture_id="genewhip-independent-game")
        if (stable_alias.returncode != 0
                or Path(stable_alias.stdout.strip()) != expected_rom):
            raise AssertionError(
                "consumer did not resolve the stable unversioned fixture ID to the "
                f"versioned admitted ROM: {stable_alias.stderr!r}")
        missing_alias = copy.deepcopy(document)
        missing_alias["fixtures"] = [row for row in missing_alias["fixtures"]
                                     if row.get("id") != admission.GAME_ID]
        missing = invoke(missing_alias, fixture_id="genewhip-independent-game")
        if (missing.returncode == 0
                or "BLOCKED: fixture admission failed: admission"
                not in missing.stdout + missing.stderr):
            raise AssertionError("stable alias must reject an absent versioned record")
        ambiguous_alias = copy.deepcopy(document)
        ambiguous_alias["fixtures"].append(copy.deepcopy(candidate))
        ambiguous = invoke(ambiguous_alias, fixture_id="genewhip-independent-game")
        if (ambiguous.returncode == 0
                or "BLOCKED: fixture admission failed: duplicate"
                not in ambiguous.stdout + ambiguous.stderr):
            raise AssertionError("stable alias must reject duplicate versioned records")

        altered_rom = temp_root / "altered-game.bin"
        altered_rom.write_bytes((root / candidate["rom"]).read_bytes())
        bad_rom_manifest = copy.deepcopy(document)
        bad_rom_manifest["fixtures"][1].update(
            rom=altered_rom.relative_to(root).as_posix(), sha256="0" * 64)
        if invoke(bad_rom_manifest).returncode == 0:
            raise AssertionError("normal consumer accepted a changed ROM hash")

        altered_diagnostic = temp_root / "altered-diagnostic.bin"
        altered_diagnostic.write_bytes(diagnostic_rom.read_bytes()[:-1] +
                                       bytes([diagnostic_rom.read_bytes()[-1] ^ 1]))
        if invoke(document, diagnostic=altered_diagnostic.relative_to(root).as_posix()).returncode == 0:
            raise AssertionError("normal consumer accepted altered diagnostic bytes")

print("PASS: current independent game passes controlled admission validation")
