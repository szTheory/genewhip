"""Exercise admission behavior, including forged positive gate claims."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
sys.dont_write_bytecode = True

root, rom = Path(sys.argv[1]), Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("admission", root / "tools/evidence/fixture_manifest.py")
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
document = {
    "schema_version": 1,
    "fixtures": [{
        "id": "genewhip-diagnostic-v1", "status": "admitted", "outcome": "pass",
        "project": "Genewhip", "revision": "955798e93d7ce3d9ca6f4935a34678746f68d2b8",
        "source": "tests/diagnostic/diagnostic.S", "source_sha256": sha(root / "tests/diagnostic/diagnostic.S"),
        "license": "MIT", "notices": ["LICENSE"], "assets": [],
        "build": {"source": "tests/diagnostic/build_rom.c", "sha256": sha(root / "tests/diagnostic/build_rom.c"),
                  "toolchain": "C17 data-directive emitter", "command": "gw_build_rom tests/diagnostic/diagnostic.S diagnostic.bin"},
        "sha256": sha(rom), "oracle": "original-authored-constants-v1",
        "profile": "va3-ntsc-u-v1", "input": "no-events-target-10000-v1"
    }]
}

def check(value, expected, name):
    actual = admission.validate(value, root, rom)
    if actual != expected:
        raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")


def _game_fixture_case(*, notice_text=None, evidence_change=None):
    """Validate copied candidate records after refreshing every changed digest."""
    temporary = tempfile.TemporaryDirectory(prefix="gw-fixture-semantic-test-")
    copied_root = Path(temporary.name)
    paths = (
        "fixtures/independent-game/src/game.s",
        "fixtures/independent-game/game.bin",
        "fixtures/independent-game/scenario.json",
        "fixtures/independent-game/build.sh",
        "fixtures/independent-game/toolchain.lock",
        "fixtures/independent-game/mame.patch",
        "fixtures/independent-game/mame_build.sh",
        "fixtures/independent-game/mame.lua",
        "fixtures/independent-game/trace.py",
        "fixtures/independent-game/route_audit.json",
        "fixtures/independent-game/NOTICES.md",
        "evidence/independent-game.json",
    )
    for relative in paths:
        source = root / relative
        target = copied_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    manifest = json.loads((root / "fixtures/manifest.json").read_text())
    row = next(item for item in manifest["fixtures"]
               if item.get("id") == admission.GAME_ID)
    notice = copied_root / row["notices"][0]
    if notice_text is not None:
        notice.write_text(notice_text)
    evidence_path = copied_root / "evidence/independent-game.json"
    evidence = json.loads(evidence_path.read_text())
    if evidence_change is not None:
        evidence_change(evidence)
    evidence.setdefault("identities", {})["candidate_notice_sha256"] = sha(notice)
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    row["evidence_sha256"] = sha(evidence_path)

    original_run = admission.subprocess.run
    admission.subprocess.run = lambda *_args, **_kwargs: SimpleNamespace(
        stdout=f"{row['revision']}\n")
    try:
        result = admission._validate_game(row, copied_root)
    finally:
        admission.subprocess.run = original_run
    return temporary, result, evidence


def _historical_scope(evidence):
    evidence["purpose"] = "bounded runtime qualification evidence; historical pre-admission snapshot"
    evidence["temporal_scope"] = {
        "kind": "historical_pre_admission_snapshot",
    }
    evidence["candidate_disposition"] = {
        "scope": "runtime_evidence_capture",
        "status": "candidate",
    }


def _clean_game_notice():
    return (
        "# Independent game fixture notices\n\n"
        "`src/game.s` is original source authored for Genewhip under the repository MIT license.\n"
        "It contains no third-party game sources or assets. The ROM was built reproducibly with\n"
        "source-built GNU Binutils 2.47; upstream notices and identities are recorded in the lock.\n"
    )


def _run_red_scope_probe():
    evidence = json.loads((root / "evidence/independent-game.json").read_text())
    scenario = json.loads((root / "fixtures/independent-game/scenario.json").read_text())
    expected = "runtime-scope"
    actual = admission._validate_runtime(evidence, scenario)
    if actual == expected:
        print("<testsuite tests=\"1\" failures=\"0\"><testcase name=\"historical_runtime_scope_required\" classname=\"fixture_manifest\" /></testsuite>")
        return 0
    print("<testsuite tests=\"1\" failures=\"1\"><testcase name=\"historical_runtime_scope_required\" classname=\"fixture_manifest\"><failure message=\"expected runtime-scope, got "
          + str(actual) + "\" /></testcase></testsuite>")
    return 1


def _run_red_notice_probe():
    from xml.sax.saxutils import escape, quoteattr

    cases = (
        ("reject_is_not_currently_admitted",
         "The independent game is not currently admitted."),
        ("reject_has_not_been_admitted",
         "The fixture has not been admitted."),
    )
    testcase_xml = []
    failures = 0
    for name, negative_claim in cases:
        temporary, result, _evidence = _game_fixture_case(
            notice_text=_clean_game_notice() + "\n" + negative_claim + "\n",
            evidence_change=_historical_scope)
        try:
            try:
                assert result == "notice-disposition", (
                    f"expected notice-disposition, got {result}")
            except AssertionError as exc:
                failures += 1
                message = str(exc)
                testcase_xml.append(
                    f"<testcase name={quoteattr(name)} classname=\"fixture_manifest\">"
                    f"<failure message={quoteattr(message)} type=\"AssertionError\">"
                    f"{escape(message)}</failure></testcase>")
            else:
                testcase_xml.append(
                    f"<testcase name={quoteattr(name)} classname=\"fixture_manifest\" />")
        finally:
            temporary.cleanup()

    print(
        f'<testsuite name="fixture_manifest" tests="{len(cases)}" failures="{failures}">'
        + "".join(testcase_xml)
        + "</testsuite>")
    return 1 if failures else 0


if len(sys.argv) == 5 and sys.argv[4] == "--red-notice-probe":
    raise SystemExit(_run_red_notice_probe())
if len(sys.argv) == 5 and sys.argv[4] == "--red-scope-probe":
    raise SystemExit(_run_red_scope_probe())


check(document, "ok", "accept original authored diagnostic with verified bytes")
check(None, "manifest", "reject null manifest")
bad = copy.deepcopy(document); bad["fixtures"] = []
check(bad, "denominator", "reject empty corpus")
bad = copy.deepcopy(document); bad["fixtures"] *= 33
check(bad, "denominator", "reject corpus above bounded manifest maximum")
bad = copy.deepcopy(document); bad["fixtures"] *= 2
check(bad, "duplicate", "reject duplicate fixture")
for field in ("source", "license", "notices", "assets", "build", "sha256", "oracle", "input", "profile", "revision"):
    bad = copy.deepcopy(document); del bad["fixtures"][0][field]
    check(bad, "fields", "require " + field)
bad = copy.deepcopy(document); bad["fixtures"][0]["sha256"] = "0" * 64
check(bad, "content", "reject changed ROM bytes")
bad = copy.deepcopy(document); bad["fixtures"][0]["source"] = "../private.S"
check(bad, "path", "reject nonpublic provenance")
bad = copy.deepcopy(document); bad["fixtures"][0]["source_sha256"] = "0" * 64
check(bad, "source", "reject changed authored source")
bad = copy.deepcopy(document); bad["fixtures"][0]["status"] = "candidate"
check(bad, "diagnostic", "require admitted diagnostic")


def _original_rom_cases():
    """Copied-root admission and tampering cases for the original-rom row kind."""
    temporary = tempfile.TemporaryDirectory(prefix="gw-original-rom-test-")
    copied = Path(temporary.name)
    try:
        for relative in ("tests/diagnostic/diagnostic.S", "tests/diagnostic/build_rom.c",
                         "LICENSE", "scripts/fixtures/build-original-roms.sh"):
            target = copied / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, target)
        (copied / "tests/devices/roms").mkdir(parents=True)
        (copied / "tests/devices/roms/synthetic.s").write_text(
            "/* SPDX-License-Identifier: MIT */\n        .cpu 68000\n")
        rom_bytes = bytes(range(64)) * 16
        (copied / "tests/devices/roms/synthetic.bin").write_bytes(rom_bytes)
        (copied / "tests/devices/roms/NOTICES.md").write_text("Original MIT-licensed test ROMs.\n")
        base = copy.deepcopy(document)
        base["fixtures"].append({
            "id": "synthetic-original-rom", "kind": "original-rom", "status": "admitted",
            "outcome": "pass", "project": "Genewhip", "revision": "0" * 40,
            "source": "tests/devices/roms/synthetic.s",
            "source_sha256": sha(copied / "tests/devices/roms/synthetic.s"),
            "license": "MIT", "notices": ["tests/devices/roms/NOTICES.md"], "assets": [],
            "build": {"source": "scripts/fixtures/build-original-roms.sh",
                      "sha256": sha(copied / "scripts/fixtures/build-original-roms.sh"),
                      "toolchain": "fixtures/independent-game/toolchain.lock",
                      "name": "synthetic",
                      "command": "scripts/fixtures/build-original-roms.sh --verify-reproducible synthetic"},
            "rom": "tests/devices/roms/synthetic.bin", "rom_bytes": len(rom_bytes),
            "sha256": hashlib.sha256(rom_bytes).hexdigest(),
            "oracle": "documented-hardware-behaviour",
            "profile": "va3-ntsc-u-v1", "input": "no-events-target-10000-v1"})

        def verdict(mutate):
            value = copy.deepcopy(base)
            mutate(value["fixtures"][-1])
            return admission.validate(value, copied, rom)

        def expect(mutate, expected, name):
            actual = verdict(mutate)
            if actual != expected:
                raise AssertionError(f"original-rom {name}: expected {expected!r}, got {actual!r}")

        expect(lambda r: None, "ok", "accept provenance-complete row")

        def flip_rom_byte(_row):
            data = bytearray(rom_bytes)
            data[7] ^= 1
            (copied / "tests/devices/roms/synthetic.bin").write_bytes(data)
        try:
            expect(flip_rom_byte, "content", "reject flipped ROM byte")
        finally:
            (copied / "tests/devices/roms/synthetic.bin").write_bytes(rom_bytes)

        expect(lambda r: r.update(rom_bytes=len(rom_bytes) + 2), "content", "reject wrong rom_bytes")
        expect(lambda r: r.update(notices=["tests/devices/roms/MISSING.md"]), "notice",
               "reject missing notice")
        expect(lambda r: r.update(license="GPL-3.0"), "notice", "reject non-MIT license")
        for oracle in ("genewhip-output", "emulator output", "", None):
            expect(lambda r, o=oracle: r.update(oracle=o), "oracle", f"reject oracle {oracle!r}")
        expect(lambda r: r.update(oracle="guest-source-derived-arithmetic"), "ok",
               "accept guest-source-derived-arithmetic oracle")
        expect(lambda r: r.update(oracle="documented-sn76489-formulas"), "ok",
               "accept documented SN76489 formulas oracle")
        expect(lambda r: r.update(source_sha256="0" * 64), "source", "reject changed source digest")
        expect(lambda r: r["build"].update(sha256="0" * 64), "build", "reject changed build digest")
        expect(lambda r: r["build"].update(toolchain="elsewhere/toolchain.lock"), "build",
               "reject other toolchain reference")
        expect(lambda r: r["build"].pop("name"), "build", "require build.name")
        expect(lambda r: r.update(source="/etc/passwd"), "path", "reject absolute source path")
        expect(lambda r: r.update(rom="../outside.bin"), "path", "reject parent ROM path")
        expect(lambda r: r.update(notices=["../NOTICES.md"]), "path", "reject parent notice path")
        expect(lambda r: r.update(status="candidate"), "admission", "reject unadmitted original-rom")

        # The admitted raster toy row, copied with its source, ROM and notice (plan GW-02-11).
        real_rows = json.loads((root / "fixtures/manifest.json").read_text())["fixtures"]
        toy = next(r for r in real_rows if r["id"] == "genewhip-raster-toy-v1")
        for relative in (toy["source"], toy["rom"], *toy["notices"]):
            target = copied / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, target)
        toy_base = copy.deepcopy(document)
        toy_base["fixtures"].append(copy.deepcopy(toy))

        def toy_verdict(mutate):
            value = copy.deepcopy(toy_base)
            mutate(value["fixtures"][-1])
            return admission.validate(value, copied, rom)

        def toy_expect(mutate, expected, name):
            actual = toy_verdict(mutate)
            if actual != expected:
                raise AssertionError(f"raster toy {name}: expected {expected!r}, got {actual!r}")

        toy_expect(lambda r: None, "ok", "accept the admitted toy row")
        toy_rom = copied / toy["rom"]
        pristine = toy_rom.read_bytes()

        def flip_toy_byte(_row):
            data = bytearray(pristine)
            data[0x1000] ^= 1
            toy_rom.write_bytes(data)
        try:
            toy_expect(flip_toy_byte, "content", "reject a flipped toy.bin byte")
        finally:
            toy_rom.write_bytes(pristine)
        notice = copied / toy["notices"][0]
        saved = notice.read_bytes()
        notice.unlink()
        try:
            toy_expect(lambda r: None, "notice", "reject a missing toy NOTICES")
        finally:
            notice.write_bytes(saved)
        toy_expect(lambda r: r.update(oracle="genewhip-captured-pixels"), "oracle",
                   "reject an oracle naming Genewhip output")
    finally:
        temporary.cleanup()


_original_rom_cases()

if len(sys.argv) == 4:
    real = json.loads((root / "fixtures/manifest.json").read_text())
    check(real, "ok", "repository fixture manifest")
    pong_index = next(index for index, row in enumerate(real["fixtures"])
                      if row.get("id") == "free-retro-games-pong")
    for gate in ("rights", "reproducible_build", "runtime_sram"):
        bad = copy.deepcopy(real)
        bad["fixtures"][pong_index]["status"] = "admitted"
        check(bad, "admission", "reject unevidenced " + gate)
    clean_notice = _clean_game_notice()
    temporary, result, _evidence = _game_fixture_case(
        notice_text=clean_notice, evidence_change=_historical_scope)
    try:
        assert result == "ok", f"accept exact admitted fixture and reconciled provenance: {result}"
    finally:
        temporary.cleanup()

    matching_notice = clean_notice + "\nThe independent game is admitted for its exact bounded scenario.\n"
    temporary, result, _evidence = _game_fixture_case(
        notice_text=matching_notice, evidence_change=_historical_scope)
    try:
        assert result == "ok", f"accept matching admitted-status claim: {result}"
    finally:
        temporary.cleanup()

    for negative_claim in (
            "The independent game is not currently admitted.",
            "The fixture has not been admitted."):
        temporary, result, _evidence = _game_fixture_case(
            notice_text=clean_notice + "\n" + negative_claim + "\n",
            evidence_change=_historical_scope)
        try:
            assert result == "notice-disposition", (
                f"reject digest-refreshed claim {negative_claim!r}: {result}")
        finally:
            temporary.cleanup()

    def absent_scope(evidence):
        evidence["purpose"] = "bounded runtime qualification evidence; historical pre-admission snapshot"
        evidence.pop("temporal_scope", None)
        evidence.pop("candidate_disposition", None)

    def invalid_scope(evidence):
        _historical_scope(evidence)
        evidence["temporal_scope"] = {"kind": "future"}

    def non_historical_scope(evidence):
        _historical_scope(evidence)
        evidence["temporal_scope"]["kind"] = "current_runtime"

    def unscoped_disposition(evidence):
        _historical_scope(evidence)
        evidence["candidate_disposition"] = "candidate"

    def wrong_disposition_scope(evidence):
        _historical_scope(evidence)
        evidence["candidate_disposition"]["scope"] = "current_fixture_status"

    for description, mutation in (
            ("absent", absent_scope),
            ("invalid", invalid_scope),
            ("non-historical", non_historical_scope),
            ("unscoped disposition", unscoped_disposition),
            ("wrong disposition scope", wrong_disposition_scope)):
        temporary, result, _evidence = _game_fixture_case(
            notice_text=clean_notice, evidence_change=mutation)
        try:
            assert result == "runtime-scope", (
                f"reject {description} scope with refreshed evidence digest: {result}")
        finally:
            temporary.cleanup()

    original = json.loads((root / "evidence/independent-game.json").read_text())
    scenario = json.loads((root / "fixtures/independent-game/scenario.json").read_text())
    _historical_scope(original)
    observations = (copy.deepcopy(original["runs"]),
                    copy.deepcopy(original["outcome_counts"]),
                    original["outcome_denominator"])
    assert admission._validate_runtime(original, scenario) is None, (
        "accept explicitly scoped historical runtime evidence")
    assert observations == (original["runs"], original["outcome_counts"],
                            original["outcome_denominator"]), (
        "preserve observations, six outcomes, and denominator")
print("PASS: fixture_manifest admission, byte identity, provenance and denominator controls")
