#!/usr/bin/env python3
"""CLI contract for sanitized, source-bound physical Deck observations."""

import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts/evidence/deck_route.py"
MAP = ROOT / "fixtures/phase6/recursion94-consumed-map-v1.json"


def invoke(*args):
    return subprocess.run([sys.executable, "-I", str(CLI), *map(str, args)], cwd=ROOT,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)


def complete_observation():
    return {
        "schema": "genewhip.deck-route-observation.v1",
        "status": "pass",
        "release": {
            "tag": "v0.3.0", "repository": "szTheory/genewhip",
            "source_sha": "a" * 40, "source_workflow": ".github/workflows/ci.yml",
            "source_run_id": "123456", "source_run_attempt": 1,
            "publisher_workflow": ".github/workflows/release.yml",
            "publisher_run_id": "123457", "publisher_run_attempt": 1,
            "archive_sha256": "b" * 64, "core_sha256": "c" * 64,
        },
        "route": {
            "map_id": "recursion94-genewhip-public-client-v1", "title_id": "recursion94",
            "route_id": "recursion94-personal-no-sram",
            "route_map_sha256": hashlib.sha256(MAP.read_bytes()).hexdigest(),
        },
        "copy_availability": "confirmed_lawful_no_sram",
        "device": {"model": "Steam Deck", "steamos": "3.x", "retroarch": "1.x",
                    "flatpak": "1.x", "es_de": "3.x", "conditions": "Desktop Mode"},
        "launches": [
            {"path": "direct-retroarch", "outcomes": {key: "pass" for key in
             ("controls", "progress", "audio", "close", "relaunch")}},
            {"path": "es-de", "outcomes": {key: "pass" for key in
             ("controls", "progress", "audio", "close", "relaunch")}},
        ],
    }


class DeckRouteContract(unittest.TestCase):
    def test_template_is_unknown_and_cannot_pass(self):
        self.assertTrue(CLI.is_file(), "Deck route CLI must implement the observation contract")
        template = invoke("--template")
        self.assertEqual(template.returncode, 0, template.stderr)
        data = json.loads(template.stdout)
        self.assertEqual(data["status"], "unknown")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "template.json"
            path.write_text(template.stdout, encoding="utf-8")
            rejected = invoke("--validate", path, "--require-pass")
            self.assertNotEqual(rejected.returncode, 0)

    def test_complete_record_is_shape_valid_but_not_observation_truth(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text(json.dumps(complete_observation()), encoding="utf-8")
            result = invoke("--validate", path, "--require-pass")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("shape", result.stdout.lower())
            self.assertNotIn("observed", result.stdout.lower())

    def test_missing_duplicate_or_incomplete_launch_paths_are_rejected(self):
        cases = []
        missing = complete_observation(); missing["launches"].pop()
        cases.append(missing)
        duplicate = complete_observation(); duplicate["launches"][1]["path"] = "direct-retroarch"
        cases.append(duplicate)
        incomplete = complete_observation(); del incomplete["launches"][0]["outcomes"]["audio"]
        cases.append(incomplete)
        self.assert_rejected(cases)

    def test_private_fields_wrong_release_and_fixture_substitution_are_rejected(self):
        private = complete_observation(); private["device"]["conditions"] = "/" + "home/private/game.bin"
        wrong_release = complete_observation(); wrong_release["release"]["source_workflow"] = "other.yml"
        authored_fixture = complete_observation(); authored_fixture["route"]["route_id"] = "phase8-authored-fixture"
        unavailable = complete_observation(); unavailable["copy_availability"] = "unavailable"
        self.assert_rejected([private, wrong_release, authored_fixture, unavailable])

    def test_unknown_outcome_cannot_satisfy_require_pass(self):
        record = complete_observation()
        record["launches"][0]["outcomes"]["progress"] = "unknown"
        self.assert_rejected([record])

    def assert_rejected(self, records):
        with tempfile.TemporaryDirectory() as directory:
            for index, record in enumerate(records):
                path = Path(directory) / f"record-{index}.json"
                path.write_text(json.dumps(record), encoding="utf-8")
                with self.subTest(index=index):
                    result = invoke("--validate", path, "--require-pass")
                    self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
