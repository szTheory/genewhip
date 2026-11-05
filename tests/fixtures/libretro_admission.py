#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve the exact v2 fixture admission while checking current wording."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ID = "genewhip-independent-game-v2"
ROM_SHA256 = "7bdffe43fc1b6e4ac623e16298e3bd0a775de6cb4db2758695dbef0e200f4adb"
SOURCE_SHA256 = "b74cd12ec371767e8fb338feca808e59e63f569eb93298bb2470d20f8e4e9cfe"
SCENARIO_SHA256 = "c702dd10287a9363405fd9269e05989954eb447d0973246bb59a10f74920dbb2"
ORACLE_SHA256 = "1a9d99cb01496f26fe3dc33d0c1bcb0cf22bd9178088fa183e5bba37a8600f42"
CONTROLS_SHA256 = "3bece05f616f9b152f222b9f4d930c117d9f73ff228062e381e218058611c6fb"
HISTORICAL_BUILD_SHA256 = "15f321b986db3c2f7df6a6d55ff5b49d9415399bccd0a241f518351ead7356f4"
HISTORICAL_NOTICE_SHA256 = "ab969e7a01aa9f3f6c1beb6856eb6540e3f6a18fab3ac82e65be14cbd385bf97"
HISTORICAL_CAPTURE_SHA256 = "1ddc13c4bdb92a399580f895002b8963521607e38947660d2779c34918b94f51"
HISTORICAL_MANIFEST_VALIDATOR_SHA256 = "1effa88749894c0bd9d6d8dd2613d2ffb59399cb372c7d613f8936001cc89865"
CASE_IDS = ("title-no-start", "start-idle", "start-move", "action-sound",
            "action-no-trigger", "sustained-play")
NOTICE_PATH = ROOT / "fixtures/independent-game-v2/NOTICES.md"
BUILD_PATH = ROOT / "fixtures/independent-game-v2/build.sh"


def diagnostic_rom_argument() -> str:
    path = Path(os.environ.get("GENEWHIP_DIAGNOSTIC_ROM", "build/ci/native/diagnostic.bin"))
    return path.resolve().relative_to(ROOT).as_posix()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


EVIDENCE_SHA256 = sha256(ROOT / "evidence/independent-game-v2.json")
SOURCE_REVISION = next(
    row["revision"] for row in json.loads((ROOT / "fixtures/manifest.json").read_text())
    ["fixtures"] if row.get("id") == FIXTURE_ID)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_contract(manifest, evidence, notice_text: str, build_text: str) -> str:
    rows = manifest.get("fixtures") if isinstance(manifest, dict) else None
    if not isinstance(rows, list):
        return "manifest-fixtures"
    row = next((item for item in rows if isinstance(item, dict)
                and item.get("id") == FIXTURE_ID), None)
    if row is None:
        return "fixture-missing"
    if row.get("status") != "admitted" or row.get("outcome") != "pass":
        return "manifest-disposition"
    if (row.get("sha256") != ROM_SHA256 or row.get("source_sha256") != SOURCE_SHA256
            or row.get("revision") != SOURCE_REVISION):
        return "manifest-identity"
    if row.get("evidence_sha256") != EVIDENCE_SHA256:
        return "manifest-evidence-binding"
    if not isinstance(evidence, dict) or evidence.get("fixture_id") != FIXTURE_ID:
        return "evidence-fixture"
    if (evidence.get("status") != "pass" or evidence.get("outcome") != "pass"
            or evidence.get("candidate_disposition") != "admitted"):
        return "evidence-disposition"
    if evidence.get("outcome_counts") != {
            "pass": 6, "fail": 0, "unknown": 0, "unsupported": 0,
            "skipped": 0, "infrastructure_error": 0}:
        return "evidence-denominator"
    consumer = evidence.get("consumer")
    if consumer != {"contract": "production fixture manifest and run_admitted consumer",
                    "passed": 6, "required": 6, "status": "pass"}:
        return "evidence-consumer"
    cases = evidence.get("cases")
    if not isinstance(cases, list) or [item.get("id") for item in cases] != list(CASE_IDS):
        return "evidence-case-roster"
    if any(item.get("status") != "pass" or item.get("outcome") != "pass" for item in cases):
        return "evidence-case-status"
    identities = evidence.get("identities")
    expected = {
        "source_revision": SOURCE_REVISION,
        "source_sha256": SOURCE_SHA256,
        "rom_sha256": ROM_SHA256,
        "scenario_sha256": SCENARIO_SHA256,
        "oracle_sha256": ORACLE_SHA256,
    }
    if not isinstance(identities, dict) or any(identities.get(key) != value
                                                for key, value in expected.items()):
        return "evidence-identity"
    if identities.get("source_sha256") in {
            identities.get("mame_source_archive_sha256"),
            identities.get("mame_executable_sha256"),
    }:
        return "source-reference-merged"
    if notice_text.count("admitted") == 0 or "candidate; not admitted" in notice_text:
        return "notice-builder-disagreement"
    if "candidate; not admitted" in build_text or '"disposition":"admitted"' not in build_text or \
            '"admission_evidence_sha256"' not in build_text:
        return "notice-builder-disagreement"
    if "libretro_admission.py" not in build_text:
        return "admission-verifier-not-wired"
    if build_text.index("libretro_admission.py") > build_text.index("--validate-lock"):
        return "admission-verifier-order"
    if row.get("build", {}).get("source") != "fixtures/independent-game-v2/build.sh":
        return "manifest-build-source"
    if row.get("build", {}).get("sha256") != sha256(BUILD_PATH):
        return "manifest-build-identity"
    return "ok"


def load_current():
    manifest = _load(ROOT / "fixtures/manifest.json")
    evidence = _load(ROOT / "evidence/independent-game-v2.json")
    return manifest, evidence, NOTICE_PATH.read_text(encoding="utf-8"), BUILD_PATH.read_text(encoding="utf-8")


class LibretroAdmissionContract(unittest.TestCase):
    def test_retained_v2_evidence_matches_admitted_manifest_and_current_wording(self):
        manifest, evidence, notice, builder = load_current()
        self.assertEqual(sha256(ROOT / "fixtures/independent-game-v2/game.bin"), ROM_SHA256)
        self.assertEqual(sha256(ROOT / "fixtures/independent-game-v2/src/game.s"), SOURCE_SHA256)
        self.assertEqual(sha256(ROOT / "fixtures/independent-game-v2/scenario.json"), SCENARIO_SHA256)
        self.assertEqual(sha256(ROOT / "fixtures/independent-game-v2/oracle.json"), ORACLE_SHA256)
        self.assertEqual(sha256(ROOT / "fixtures/independent-game-v2/host-controls.json"), CONTROLS_SHA256)
        self.assertEqual(sha256(ROOT / "evidence/independent-game-v2.json"), EVIDENCE_SHA256)
        self.assertEqual(evidence["identities"]["build_sha256"], HISTORICAL_BUILD_SHA256)
        self.assertEqual(evidence["identities"]["notices_sha256"], HISTORICAL_NOTICE_SHA256)
        self.assertEqual(evidence["identities"]["capture_script_sha256"], HISTORICAL_CAPTURE_SHA256)
        self.assertEqual(evidence["identities"]["manifest_validator_sha256"],
                         HISTORICAL_MANIFEST_VALIDATOR_SHA256)
        self.assertEqual(validate_contract(manifest, evidence, notice, builder), "ok")

    def test_production_read_only_admission_consumer_accepts_the_committed_rom(self):
        manifest, _evidence, _notice, _builder = load_current()
        diagnostic = next(item for item in manifest["fixtures"]
                          if item["id"] == "genewhip-diagnostic-v1")
        successor = next(item for item in manifest["fixtures"] if item["id"] == FIXTURE_ID)
        phase8_build = ROOT / "build/phase8"
        phase8_build.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="libretro-admission-", dir=phase8_build) as temp:
            temporary_manifest = Path(temp) / "manifest.json"
            temporary_manifest.write_text(json.dumps({"schema_version": 1,
                "fixtures": [diagnostic, successor]}), encoding="utf-8")
            manifest_argument = temporary_manifest.relative_to(ROOT).as_posix()
            result = subprocess.run([
                "python3", "-I", "scripts/fixtures/run_admitted.py",
                "--root", str(ROOT), "--manifest", manifest_argument,
                "--fixture-id", FIXTURE_ID,
                "--diagnostic-rom", diagnostic_rom_argument(),
            ], cwd=ROOT, capture_output=True, text=True, timeout=180, check=False)
        self.assertEqual(result.returncode, 0, "production-admission-verifier-failed")
        self.assertEqual(Path(result.stdout.strip()), ROOT / "fixtures/independent-game-v2/game.bin")

    def test_production_consumer_rejects_unproven_source_revision(self):
        manifest, _evidence, _notice, _builder = load_current()
        diagnostic = next(item for item in manifest["fixtures"]
                          if item["id"] == "genewhip-diagnostic-v1")
        successor = next(item for item in manifest["fixtures"] if item["id"] == FIXTURE_ID)
        successor["revision"] = "0" * 40
        phase8_build = ROOT / "build/phase8"
        phase8_build.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="libretro-admission-reject-", dir=phase8_build) as temp:
            temporary_manifest = Path(temp) / "manifest.json"
            temporary_manifest.write_text(json.dumps({"schema_version": 1,
                "fixtures": [diagnostic, successor]}), encoding="utf-8")
            result = subprocess.run([
                "python3", "-I", "scripts/fixtures/run_admitted.py",
                "--root", str(ROOT), "--manifest", temporary_manifest.relative_to(ROOT).as_posix(),
                "--fixture-id", FIXTURE_ID,
                "--diagnostic-rom", diagnostic_rom_argument(),
            ], cwd=ROOT, capture_output=True, text=True, timeout=180, check=False)
        self.assertNotEqual(result.returncode, 0, "production-admission-accepted-false-revision")
        self.assertIn("fixture-source-revision-unproven", result.stderr)

    def test_mutated_rom_and_source_identities_fail_by_name(self):
        manifest, evidence, notice, builder = load_current()
        mutated = copy.deepcopy(manifest)
        row = next(item for item in mutated["fixtures"] if item["id"] == FIXTURE_ID)
        row["sha256"] = "0" * 64
        self.assertEqual(validate_contract(mutated, evidence, notice, builder), "manifest-identity")
        mutated = copy.deepcopy(manifest)
        row = next(item for item in mutated["fixtures"] if item["id"] == FIXTURE_ID)
        row["source_sha256"] = "0" * 64
        self.assertEqual(validate_contract(mutated, evidence, notice, builder), "manifest-identity")

    def test_missing_or_failed_admission_and_wrong_status_are_rejected(self):
        manifest, evidence, notice, builder = load_current()
        mutated = copy.deepcopy(evidence)
        del mutated["consumer"]
        self.assertEqual(validate_contract(manifest, mutated, notice, builder), "evidence-consumer")
        mutated = copy.deepcopy(evidence)
        mutated["candidate_disposition"] = "candidate"
        self.assertEqual(validate_contract(manifest, mutated, notice, builder), "evidence-disposition")
        mutated = copy.deepcopy(manifest)
        row = next(item for item in mutated["fixtures"] if item["id"] == FIXTURE_ID)
        row["status"] = "candidate"
        self.assertEqual(validate_contract(mutated, evidence, notice, builder), "manifest-disposition")

    def test_notice_and_builder_must_share_the_admitted_disposition(self):
        manifest, evidence, notice, builder = load_current()
        self.assertEqual(validate_contract(manifest, evidence, notice,
                                           builder.replace('"disposition":"admitted"',
                                                           '"disposition":"candidate; not admitted"')),
                         "notice-builder-disagreement")
        self.assertEqual(validate_contract(manifest, evidence,
                         notice.replace("admitted", "candidate", 1), builder),
                         "notice-builder-disagreement")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--admission-only":
        integrated = {"test_production_read_only_admission_consumer_accepts_the_committed_rom",
                      "test_production_consumer_rejects_unproven_source_revision"}
        names = unittest.defaultTestLoader.getTestCaseNames(LibretroAdmissionContract)
        suite = unittest.TestSuite(LibretroAdmissionContract(name) for name in names
                                   if name not in integrated)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    if len(sys.argv) != 1:
        raise SystemExit("usage: libretro_admission.py [--admission-only]")
    unittest.main(verbosity=2)
