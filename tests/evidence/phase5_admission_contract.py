#!/usr/bin/env python3
"""Offline screening, eligibility, budget, and independent-pair contract."""
from __future__ import annotations

import importlib.util
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HISTORICAL_MANIFEST_ROWS_SHA256 = "dd50c8977a8f14b3bc9fc52dcf70f5a38b0c7d41d257f7409a435e239c481085"
SPEC = importlib.util.spec_from_file_location(
    "phase5_records", ROOT / "tools/evidence/phase5_records.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("phase5 screening parser unavailable")
records = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(records)
SCREENING = json.loads((ROOT / "fixtures/candidate-screening.json").read_text())
SYNTHETIC = json.loads((ROOT / "tests/evidence/fixtures/phase5-screening-synthetic.json").read_text())
ALL_CHECKS = {name: True for name in records.ELIGIBILITY_CHECKS}


def receipt(title, lineage, *, route="pass"):
    return {
        "title_id": title,
        "lineage_id": lineage,
        "decision": "eligible",
        "checks": dict(ALL_CHECKS),
        "materials": [{"path": "source/main.s", "license": "MIT", "notice": "NOTICES.md"}],
        "route_qualification": route,
        "independent_authorship_evidence": "source ancestry and author provenance inspected",
    }


class AdmissionContract(unittest.TestCase):
    def migration(self):
        policy = records.amended_policy()
        return records.migrate_screening(ROOT, policy)

    def test_versioned_policy_and_history_migration_exists(self):
        self.assertTrue(callable(getattr(records, "migrate_screening", None)),
                        "production anchored migration is not implemented")

    def test_migration_retains_exact_history_unknowns_and_separate_limits(self):
        ledger, eligibility, migration = self.migration()
        records.validate_policy_migration(ledger, eligibility, migration, ROOT)
        policy = records.effective_policy(ledger)
        self.assertEqual([policy[k] for k in ("linux_tasks_per_container", "cpus_per_container",
                                              "concurrent_build_jobs")], [64, 4, 4])
        self.assertEqual(records.SCREENING_LIMITS["build_processes"], 4)
        for old, new in zip(SCREENING["candidates"], ledger["candidates"]):
            self.assertEqual(new["identity_history"][:len(old["identity_history"])], old["identity_history"])
            self.assertEqual(new["counters"], old["counters"])
        original = json.loads((ROOT / "evidence/phase5-eligibility.json").read_text())
        self.assertEqual(eligibility["candidates"], original["candidates"])
        self.assertEqual(records.setup_continuation_state(ledger)["state"], "available")
        self.assertEqual(records.setup_continuation_state(ledger)["remaining_us"], 1420960613)

    def test_rehashed_rewritten_prefix_and_receipts_are_rejected(self):
        ledger, eligibility, migration = self.migration()
        for field in ("identity_sha256", "details"):
            bad = copy.deepcopy(ledger)
            history = bad["candidates"][0]["identity_history"]
            if field == "details":
                history[3][field]["probe_receipts"][0]["sha256"] = "0" * 64
            else:
                history[0][field] = "0" * 64
            previous = "0" * 64
            for event in history:
                event["previous_sha256"] = previous
                event["sha256"] = records._event_chain_digest(event)
                previous = event["sha256"]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "historical.*prefix"):
                records.validate_policy_migration(bad, eligibility, migration, ROOT)

    def test_policy_anchor_counter_and_status_only_mutants_reject(self):
        ledger, eligibility, migration = self.migration()
        for mutate, expected in (
            (lambda d: d["policy"].update(linux_tasks_per_container=128), "policy"),
            (lambda d: d["historical_anchors"].update({"fixtures/candidate-screening.json": "0" * 64}), "anchor"),
            (lambda d: d["candidates"][0]["counters"].update(build_environment_corrections=0), "counters"),
            (lambda d: d["candidates"][0].update(id="renamed-tank"), "roster"),
        ):
            bad = copy.deepcopy(ledger); mutate(bad)
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, expected):
                records.validate_policy_migration(bad, eligibility, migration, ROOT)
        eligibility["candidates"][0]["decision"] = "eligible"
        with self.assertRaisesRegex(ValueError, "material"):
            records.validate_policy_migration(ledger, eligibility, migration, ROOT)

    def test_continuation_is_single_use_cumulative_and_inclusive(self):
        ledger, _, _ = self.migration()
        ledger = records.begin_setup_continuation(ledger)
        with self.assertRaisesRegex(ValueError, "single-use"):
            records.begin_setup_continuation(ledger)
        for elapsed in (-1, float("nan"), float("inf"), 1.5, True, 1420960614):
            with self.subTest(elapsed=elapsed), self.assertRaisesRegex(ValueError, "elapsed|budget"):
                records.charge_setup_elapsed(ledger, elapsed)
        ledger = records.charge_setup_elapsed(ledger, 120000000, probe_elapsed_us=120000000)
        with self.assertRaisesRegex(ValueError, "reset"):
            records.charge_setup_elapsed(ledger, 119999999)
        with self.assertRaisesRegex(ValueError, "probe"):
            records.charge_setup_elapsed(ledger, 120000001, probe_elapsed_us=120000001)
        ledger = records.charge_setup_elapsed(ledger, 1420960613)
        self.assertEqual(records.setup_continuation_state(ledger)["remaining_us"], 0)
        ledger = records.complete_setup_continuation(ledger, success=False)
        with self.assertRaisesRegex(ValueError, "single-use"):
            records.begin_setup_continuation(ledger)
        self.assertEqual(records.setup_continuation_state(ledger)["state"], "failed")

    def test_continuation_persists_consumption_before_launch_and_restart(self):
        ledger, _, _ = self.migration()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            path.write_text(json.dumps(ledger))
            records.begin_setup_continuation(ledger, ledger_path=path)
            consumed = json.loads(path.read_text())
            self.assertEqual(records.setup_continuation_state(consumed)["state"], "in-flight")
            with self.assertRaisesRegex(ValueError, "single-use"):
                records.begin_setup_continuation(consumed, ledger_path=path)

    def test_schema_downgrade_dropped_reviews_and_legacy_setup_bypass_reject(self):
        ledger, eligibility, migration = self.migration()
        downgraded = {**ledger, 'schema': records.SCREENING_SCHEMA}
        with self.assertRaisesRegex(ValueError, 'downgraded'):
            records.validate_screening(downgraded)
        downgraded = {**eligibility, 'schema': 'genewhip-phase5-eligibility-v1'}
        with self.assertRaisesRegex(ValueError, 'downgraded'):
            records.validate_current_eligibility(downgraded)
        for field in ('materials', 'review', 'checks', 'unverified_categories'):
            bad = copy.deepcopy(eligibility)
            del bad['candidates'][0][field]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'material review fields'):
                records.validate_policy_migration(ledger, bad, migration)
        failed = records.complete_setup_continuation(records.begin_setup_continuation(ledger), success=False)
        with self.assertRaisesRegex(ValueError, 'single-use cumulative'):
            records.append_attempt(failed, 'tank-battle', 'build_setup_completed', {'run': 'renewed'},
                                   details={'elapsed_seconds': 1400})

    def test_migration_cli_is_offline_idempotent_and_never_renews_consumption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in records.HISTORICAL_ANCHORS:
                dest = root / relative; dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((ROOT / relative).read_bytes())
            policy = root / "fixtures/phase5-policy-v2.json"
            policy.write_text(json.dumps(records.amended_policy()))
            command = [sys.executable, "-I", str(ROOT / "scripts/fixtures/phase5_candidate.py"),
                       "--migrate-policy", "--ledger", str(root / "fixtures/candidate-screening.json"),
                       "--eligibility", str(root / "evidence/phase5-eligibility.json"), "--policy", str(policy)]
            first = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(first.returncode, 0, first.stderr)
            output = root / "fixtures/candidate-screening-v2.json"
            before = output.read_bytes()
            second = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(before, output.read_bytes())
            current = json.loads(before)
            records.begin_setup_continuation(current, ledger_path=output)
            consumed = output.read_bytes()
            repeated = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            self.assertEqual(consumed, output.read_bytes())

    def test_five_title_roster_and_actual_screen_disposition_are_preserved(self):
        validated = records.validate_screening(SCREENING)
        self.assertEqual([item["id"] for item in validated["candidates"]], list(records.SCREENING_IDS))
        tank = validated["candidates"][0]
        self.assertEqual(tank["counters"]["full_screens"], 1)
        self.assertEqual(tank["counters"]["build_environment_corrections"], 1)
        self.assertEqual(tank["counters"]["rom_build_invocations"], 0)
        self.assertEqual(tank["state"], "build-setup-blocked")
        self.assertEqual(tank["outcome"], "infrastructure-error")
        self.assertTrue(all(item["reason"] for item in validated["candidates"]))
        self.assertTrue(all(item["counters"]["full_screens"] == 0
                            for item in validated["candidates"][1:]))

    def test_production_eligibility_keeps_all_five_actual_review_dispositions(self):
        doc = json.loads((ROOT / "evidence/phase5-eligibility.json").read_text())
        self.assertEqual([item["title_id"] for item in doc["candidates"]], list(records.SCREENING_IDS))
        self.assertEqual(sum(bool(item.get("reviewed_materials")) for item in doc["candidates"]), 5)
        self.assertTrue(all(item.get("unverified_categories") for item in doc["candidates"]))

    def test_empty_and_null_rosters_are_rejected(self):
        for candidates in ([], None):
            with self.subTest(candidates=candidates), self.assertRaisesRegex(ValueError, "non-empty"):
                records.validate_screening({**SCREENING, "candidates": candidates})

    def test_single_receipt_cannot_satisfy_pair(self):
        with self.assertRaisesRegex(ValueError, "two independently"):
            records.require_pair([receipt("new-a", "lineage-a")])

    def test_same_lineage_titles_do_not_satisfy_pair(self):
        with self.assertRaisesRegex(ValueError, "distinct source lineages"):
            records.require_pair([receipt("tank-battle", "monteslu"),
                                  receipt("space-shooter", "monteslu")])

    def test_distinct_qualified_lineages_satisfy_pair(self):
        pair = records.require_pair([receipt("tank-battle", "monteslu"),
                                     receipt("alex-vs-bus", "alex-author")])
        self.assertEqual(len(pair), 2)

    def test_real_tank_payload_archive_and_canonical_route_identities(self):
        """Exercise current promoted bytes without minting admission evidence."""
        inventory = json.loads((ROOT / "fixtures/phase5-a/source-inventory.json").read_text())
        materials = json.loads((ROOT / "fixtures/phase5-a/materials.json").read_text())
        source_ref = inventory["source_archive"]
        source_bytes = records._bound_file(ROOT, source_ref)
        actual = records._read_source_archive(ROOT, source_ref)
        self.assertEqual(len(source_bytes), source_ref["bytes"])
        self.assertEqual(list(actual.values()), inventory["files"])
        self.assertEqual(hashlib.sha256(source_bytes).hexdigest(),
                         "0751013a99631e08b0309bfde06c8ff578abeda0113c3b208aaf81951a1e6753")
        by_path = {row["path"]: row for row in inventory["files"]}
        locations = {row["logical_path"]: row for row in materials["material_locations"]}
        for row in materials["materials"]:
            if row.get("origin", "workspace") == "image":
                continue
            location = locations[row["path"]]
            if location["kind"] == "reviewed-override":
                file_bytes = records._bound_file(ROOT, location["file"])
                self.assertEqual(hashlib.sha256(file_bytes).hexdigest(), row["sha256"])
            else:
                self.assertEqual(location["kind"], "archive-member")
                self.assertEqual(location["sha256"], row["sha256"])
                self.assertEqual(by_path[location["member_path"]]["sha256"], row["sha256"])
        scenario = json.loads((ROOT / "fixtures/phase5-a/scenario.json").read_text())
        oracle = json.loads((ROOT / "fixtures/phase5-a/oracle.json").read_text())
        eligibility = json.loads((ROOT / "evidence/phase5-eligibility-v2.json").read_text())
        tank = next(row for row in eligibility["candidates"] if row["title_id"] == "tank-battle")
        canonical = lambda doc: hashlib.sha256(json.dumps(
            doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(canonical(scenario), tank["reference_route"]["frozen"]["scenario_sha256"])
        self.assertEqual(canonical(oracle), tank["reference_route"]["frozen"]["oracle_sha256"])
        self.assertEqual(scenario["identities"]["rom_sha256"],
                         "ceb75f72a08565424e88ed0a38d0d682e2c7f7cbb6e98b920f442b108e09f723")


class ReviewedSourceExportContract(unittest.TestCase):
    def test_recursion_export_is_exact_and_preserves_origin_provenance(self):
        eligibility = json.loads((ROOT / "evidence/phase5-eligibility-v2.json").read_text())
        candidate = next(row for row in eligibility["candidates"] if row["title_id"] == "recursion94")
        source_revision = candidate["source_revision"]
        source_rows = [row for row in candidate["materials"]
                       if row.get("origin", "workspace") == "workspace"
                       and row.get("source_revision") == source_revision]
        origin_root = f"RECURSION94-{source_revision}"
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            archive_path = temp_root / "reviewed-export.tar.gz"
            original_root = ROOT / "local-fixtures/phase5/recursion94/clean-2"
            member_map = []
            with tarfile.open(archive_path, "w:gz") as archive:
                for row in sorted(source_rows, key=lambda item: item["path"]):
                    data = (original_root / row["path"]).read_bytes()
                    digest = hashlib.sha256(data).hexdigest()
                    self.assertEqual(digest, row["sha256"])
                    member = f"reviewed-export/{row['path']}"
                    info = tarfile.TarInfo(member); info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
                    member_map.append({"logical_path": row["path"], "origin_member": f"{origin_root}/{row['path']}",
                                       "bytes": len(data), "sha256": digest})
            export_ref = {"path": "reviewed-export.tar.gz",
                          "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()}
            archive_binding = {"path": export_ref["path"], "sha256": export_ref["sha256"]}
            actual = records._read_source_archive(temp_root, archive_binding)
            source_origin = {"schema": "genewhip-phase5-reviewed-source-export-v1",
                             "archive_sha256": candidate["source_archive_sha256"],
                             "source_revision": source_revision, "root_prefix": origin_root,
                             "member_map": member_map}
            records._validate_reviewed_source_export(source_origin, "reviewed-export", actual,
                                                     candidate["materials"], candidate, source_revision)
            bad = copy.deepcopy(source_origin); bad["member_map"].pop()
            with self.assertRaisesRegex(ValueError, "exactly the upstream source material set"):
                records._validate_reviewed_source_export(bad, "reviewed-export", actual,
                                                         candidate["materials"], candidate, source_revision)
            bad = copy.deepcopy(source_origin); bad["root_prefix"] = "forged-origin"
            with self.assertRaisesRegex(ValueError, "original archive ancestry"):
                records._validate_reviewed_source_export(bad, "reviewed-export", actual,
                                                         candidate["materials"], candidate, source_revision)
            changed = copy.deepcopy(actual)
            first = next(iter(changed))
            changed[first] = {**changed[first], "sha256": "0" * 64}
            with self.assertRaisesRegex(ValueError, "changes an upstream path, size, or digest"):
                records._validate_reviewed_source_export(source_origin, "reviewed-export", changed,
                                                         candidate["materials"], candidate, source_revision)
            extra = copy.deepcopy(actual)
            extra["reviewed-export/unreviewed.txt"] = {"path": "reviewed-export/unreviewed.txt",
                                                         "bytes": 1, "sha256": "0" * 64}
            with self.assertRaisesRegex(ValueError, "unreviewed or unmapped files"):
                records._validate_reviewed_source_export(source_origin, "reviewed-export", extra,
                                                         candidate["materials"], candidate, source_revision)

    def test_control_and_diagnostic_cannot_fill_new_game_slot(self):
        with self.assertRaisesRegex(ValueError, "control/diagnostic"):
            records.require_pair([receipt("genewhip-independent-game-v2", "control"),
                                  receipt("alex-vs-bus", "alex-author")])

    def test_unqualified_route_cannot_fill_pair(self):
        with self.assertRaisesRegex(ValueError, "route qualification"):
            records.require_pair([receipt("tank-battle", "monteslu", route="unknown"),
                                  receipt("alex-vs-bus", "alex-author")])

    def test_repository_license_summary_does_not_prove_material_rights(self):
        candidate = receipt("title", "lineage")
        candidate["materials"][0]["license"] = "repository-top-level-only"
        self.assertFalse(records.validate_eligibility(candidate))

    def test_unenforceable_isolation_blocks_eligibility(self):
        candidate = receipt("title", "lineage")
        candidate["checks"]["enforced_isolation"] = False
        self.assertFalse(records.validate_eligibility(candidate))

    def test_each_budget_accepts_cap_and_rejects_cap_plus_one(self):
        for name, cap in records.COUNTER_LIMITS.items():
            with self.subTest(counter=name):
                self.assertTrue(records.within_limit(cap, cap), f"{name} rejected its inclusive cap")
                self.assertFalse(records.within_limit(cap + 1, cap), f"{name} accepted cap+1")
        for name, cap in records.SCREENING_LIMITS.items():
            with self.subTest(resource=name):
                self.assertTrue(records.within_limit(cap, cap), f"{name} rejected its inclusive cap")
                self.assertFalse(records.within_limit(cap + 1, cap), f"{name} accepted cap+1")

    def test_identity_change_does_not_reset_title_counters(self):
        updated = records.append_screening_event(SYNTHETIC, "tank-battle", "screen_started", "1" * 64)
        updated = records.append_screening_event(updated, "tank-battle", "rom_build_invocation", "2" * 64)
        tank = updated["candidates"][0]
        self.assertEqual([event["identity_sha256"] for event in tank["identity_history"]],
                         ["1" * 64, "2" * 64])
        self.assertEqual(tank["counters"]["full_screens"], 1)
        self.assertEqual(tank["counters"]["rom_build_invocations"], 1)

    def test_counter_reset_after_identity_change_is_rejected(self):
        updated = records.append_screening_event(SYNTHETIC, "tank-battle", "screen_started", "1" * 64)
        updated = records.append_screening_event(updated, "tank-battle", "rom_build_invocation", "2" * 64)
        updated["candidates"][0]["counters"]["full_screens"] = 0
        with self.assertRaisesRegex(ValueError, "counters do not match"):
            records.validate_screening(updated)

    def test_fifth_full_title_screen_is_rejected_globally(self):
        updated = SYNTHETIC
        for title in records.SCREENING_IDS[:4]:
            updated = records.append_screening_event(updated, title, "screen_started", "3" * 64)
        with self.assertRaisesRegex(ValueError, "global four-title-screen"):
            records.append_screening_event(updated, records.SCREENING_IDS[4], "screen_started", "4" * 64)

    def test_rom_invocation_cap_is_per_title_and_persistent(self):
        updated = SYNTHETIC
        for index in range(4):
            updated = records.append_screening_event(updated, "alex-vs-bus", "rom_build_invocation",
                                                     str(index + 1) * 64)
        with self.assertRaisesRegex(ValueError, "rom_build_invocations"):
            records.append_screening_event(updated, "alex-vs-bus", "rom_build_invocation", "5" * 64)

    def test_setup_overrun_is_retained_only_as_terminal_failure(self):
        updated = records.append_attempt(SYNTHETIC, "tank-battle", "build_setup_started", {"run": 1})
        updated["candidates"][0].update(state="build-setup-blocked", outcome="infrastructure-error")
        updated = records.append_attempt(updated, "tank-battle", "build_setup_failed", {"run": 1},
                                         details={"elapsed_seconds": 1801,
                                                  "failure_sha256": "f" * 64})
        self.assertEqual(records.validate_screening(updated)["candidates"][0]["state"],
                         "build-setup-blocked")
        updated["candidates"][0].update(state="unattempted", outcome="unknown")
        with self.assertRaisesRegex(ValueError, "terminal infrastructure failure"):
            records.validate_screening(updated)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bound(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": relative, "sha256": hashlib.sha256(data).hexdigest()}


def synthetic_consumer_tree(root, *, status="admitted", with_admission=True):
    """Create ephemeral, explicitly synthetic bytes to exercise production gates."""
    (root / "tools/evidence").mkdir(parents=True)
    (root / "scripts/fixtures").mkdir(parents=True)
    for relative in ("tools/evidence/fixture_manifest.py", "tools/evidence/phase5_records.py",
                     "scripts/fixtures/source_provenance.py", "scripts/fixtures/run_admitted.py"):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative).read_bytes())
    for relative in ("fixtures/candidate-screening.json", "evidence/phase5-eligibility.json",
                     "fixtures/candidate-screening-v2.json",
                     ".planning/phases/GW-05-candidate-admission-and-baseline/05-02-SUMMARY.md"):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative).read_bytes())
    diagnostic = bound(root, "build/diagnostic.bin", b"synthetic diagnostic ROM")
    diag_source = bound(root, "tests/diagnostic.S", b"synthetic source")
    diag_builder = bound(root, "tests/build.py", b"synthetic builder")
    diag_notice = bound(root, "LICENSE", b"synthetic notice")

    source_bytes = (ROOT / "LICENSE").read_bytes()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        item = tarfile.TarInfo("synthetic/source.c")
        item.size = len(source_bytes)
        tar.addfile(item, io.BytesIO(source_bytes))
    source_archive = bound(root, "evidence/synthetic/source.tar.gz", archive.getvalue())
    ledger_doc = json.loads((root / "fixtures/candidate-screening-v2.json").read_text())
    selected_row = next(item for item in ledger_doc["selected_pair"] if item["title_id"] == "tank-battle")
    selected_materials = []
    archive_entries = []
    archive_root = "retro-homebrew-games-synthetic"
    for category, path, data in (("code", "LICENSE", source_bytes),
                                 ("code", "README.md", b"readme"),
                                 ("resources", "res/resources.res", b"resource"),
                                 ("runtime_objects", "src/runtime.bin", b"runtime"),
                                 ("fonts", "src/font.dat", b"font")):
        digest = hashlib.sha256(data).hexdigest()
        selected_materials.append({"path": path, "sha256": digest, "category": category,
                                   "source_revision": selected_row["source_revision"],
                                   "terms_source": "synthetic contract fixture", "license": "MIT",
                                   "notice": "synthetic/NOTICE", "origin": "workspace"})
        member_path = f"{archive_root}/LICENSE" if path == "LICENSE" else f"{archive_root}/genesis/tank-battle/{path}"
        archive_entries.append({"path": member_path, "bytes": len(data), "sha256": digest})
    override_revision = "0e04e1c2552fe174ecb3051adf270a65b2b2c819"
    override_bytes = {"Makefile": b"synthetic reviewed Makefile", "build.sh": b"synthetic reviewed build script"}
    material_locations = []
    for logical_path, data, promoted_path in (
            ("Makefile", override_bytes["Makefile"], "fixtures/phase5-a/source-overrides/Makefile"),
            ("build.sh", override_bytes["build.sh"], "fixtures/phase5-a/source-overrides/reviewed-build.sh")):
        digest = hashlib.sha256(data).hexdigest()
        selected_materials.append({"path": logical_path, "sha256": digest, "category": "build_tools",
                                   "source_revision": override_revision, "terms_source": "reviewed upstream override",
                                   "license": "MIT", "notice": "synthetic/NOTICE", "origin": "workspace"})
        target = root / promoted_path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        material_locations.append({"logical_path": logical_path, "kind": "reviewed-override",
                                   "file": {"path": promoted_path, "sha256": digest},
                                   "source_revision": override_revision})
    material_locations.extend({"logical_path": material["path"], "kind": "archive-member",
                               "member_path": row["path"], "sha256": row["sha256"]}
                              for material, row in zip(selected_materials[:5], archive_entries))
    selected_row["materials"] = selected_materials
    screening_ledger = bound(root, "fixtures/candidate-screening-v2.json",
                             json.dumps(ledger_doc, sort_keys=True, separators=(",", ":")).encode())
    archive = io.BytesIO()
    archive_data = {f"{archive_root}/LICENSE": source_bytes,
                    f"{archive_root}/genesis/tank-battle/README.md": b"readme",
                    f"{archive_root}/genesis/tank-battle/res/resources.res": b"resource",
                    f"{archive_root}/genesis/tank-battle/src/runtime.bin": b"runtime",
                    f"{archive_root}/genesis/tank-battle/src/font.dat": b"font"}
    added_dirs = set()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        for entry in archive_entries:
            parts = Path(entry["path"]).parts
            for index in range(1, len(parts)):
                directory_name = "/".join(parts[:index]) + "/"
                if directory_name not in added_dirs:
                    directory = tarfile.TarInfo(directory_name); directory.type = tarfile.DIRTYPE
                    tar.addfile(directory)
                    added_dirs.add(directory_name)
            data = archive_data[entry["path"]]
            item = tarfile.TarInfo(entry["path"]); item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
    source_archive = bound(root, "evidence/synthetic/source.tar.gz", archive.getvalue())
    inventory = bound(root, "evidence/synthetic/inventory.json",
                      json.dumps({"schema": "genewhip-phase5-content-inventory-v1", "archive_root": archive_root,
                                  "files": sorted(archive_entries, key=lambda item: item["path"])},
                                 sort_keys=True, separators=(",", ":")).encode())
    terms = bound(root, "evidence/synthetic/material-terms.json",
                  json.dumps({"schema": "genewhip-phase5-material-terms-v1", "materials": selected_materials,
                              "material_locations": material_locations},
                      sort_keys=True, separators=(",", ":")).encode())
    notice = bound(root, "fixtures/phase5-a/NOTICES.md", b"Synthetic notice retained for gate test.\n")
    notice["covers"] = sorted({item["notice"] for item in selected_materials})
    recipe = bound(root, "evidence/synthetic/build.recipe", b"synthetic reviewed recipe\n")
    tool_lock = bound(root, "evidence/synthetic/tool.lock", b"synthetic tool lock\n")
    runtime = bound(root, "evidence/synthetic/runtime.bin", b"synthetic linked runtime bytes")
    output_bytes = b"synthetic ROM bytes"
    output_a = bound(root, "evidence/synthetic/clean-a.rom", output_bytes)
    output_a["ordinal"] = 1
    output_b = bound(root, "evidence/synthetic/clean-b.rom", output_bytes)
    output_b["ordinal"] = 2
    canonical = bound(root, "fixtures/phase5-a/game.bin", output_bytes)
    build_receipt_sha = hashlib.sha256(b"synthetic source build receipt").hexdigest()
    source_build_summary = bound(root, "evidence/phase5-tank-build-summary.json",
                                 json.dumps({"schema": "synthetic-build-summary", "title_id": "tank-battle",
                                             "source_revision": "eb7dc3044f9d2f76047f3b3573971bf86575ca52",
                                             "receipt": {"sha256": build_receipt_sha},
                                             "comparison": {"raw_outputs": [
                                                 {"ordinal": 1, "bytes": len(output_bytes), "sha256": output_a["sha256"]},
                                                 {"ordinal": 2, "bytes": len(output_bytes), "sha256": output_b["sha256"]}]}},
                                           sort_keys=True, separators=(",", ":")).encode())
    executable_sha = hashlib.sha256(b"synthetic reference executable").hexdigest()
    scenario_doc = {"schema": "genewhip-phase5-route-v1", "title_id": "tank-battle",
                    "input_schedule": [],
                    "input_program": {"kind": "synthetic-contract-program", "events": []},
                    "identities": {"source_archive_sha256": source_archive["sha256"],
                                   "source_revision": selected_row["source_revision"],
                                   "rom_sha256": canonical["sha256"],
                                   "build_receipt_sha256": build_receipt_sha,
                                   "mame_script_sha256": hashlib.sha256(b"synthetic reference script").hexdigest(),
                                   "mame_build_sha256": executable_sha,
                                   "mame_source_revision": "a" * 40,
                                   "mame_source_sha256": hashlib.sha256(b"synthetic MAME source").hexdigest(),
                                   "mame_patch_sha256": hashlib.sha256(b"synthetic MAME patch").hexdigest(),
                                   "input_sha256": hashlib.sha256(json.dumps({"input_schedule": [],
                                       "input_program": {"kind": "synthetic-contract-program", "events": []}},
                                       sort_keys=True, separators=(",", ":")).encode()).hexdigest()}}
    scenario = bound(root, "evidence/synthetic/scenario.json",
                     json.dumps(scenario_doc, indent=2, sort_keys=True).encode())
    schedule = bound(root, "evidence/synthetic/input-schedule.json",
                     json.dumps(scenario_doc["input_schedule"], indent=2).encode())
    program = bound(root, "evidence/synthetic/input-program.json",
                    json.dumps(scenario_doc["input_program"], indent=2, sort_keys=True).encode())
    oracle_doc = {"schema": "genewhip-phase5-oracle-v1", "title_id": "tank-battle", "predicates": []}
    oracle = bound(root, "evidence/synthetic/oracle.json", json.dumps(oracle_doc, indent=2).encode())
    script = bound(root, "evidence/synthetic/reference.lua", b"synthetic reference script")
    executable_doc = {"schema": "genewhip-phase5-reference-executable-v1",
                      "executable_sha256": executable_sha,
                      "source_revision": scenario_doc["identities"]["mame_source_revision"],
                      "source_archive_sha256": scenario_doc["identities"]["mame_source_sha256"],
                      "patch_sha256": scenario_doc["identities"]["mame_patch_sha256"]}
    executable = bound(root, "evidence/synthetic/reference-executable.json",
                       json.dumps(executable_doc, indent=2, sort_keys=True).encode())
    trusted_runs = [{"repetition": ordinal, "status": "pass",
                     "cases": [{"case": "synthetic", "input_rows": [], "controls": []}]}
                    for ordinal in (1, 2)]
    reference_build = bound(root, "evidence/synthetic/reference-build.json",
                            json.dumps({"schema": "genewhip-phase5-reference-build-v1",
                                        "scenario_sha256": scenario["sha256"],
                                        "tool_lock_sha256": tool_lock["sha256"],
                                        "executable_sha256": executable_sha,
                                        "script_sha256": script["sha256"],
                                        "mame_source_revision": scenario_doc["identities"]["mame_source_revision"],
                                        "mame_source_sha256": scenario_doc["identities"]["mame_source_sha256"],
                                        "mame_patch_sha256": scenario_doc["identities"]["mame_patch_sha256"],
                                        "input_schedule_sha256": schedule["sha256"],
                                        "input_program_sha256": program["sha256"],
                                        "capture_sha256": [hashlib.sha256(json.dumps(run, sort_keys=True,
                                            separators=(",", ":")).encode()).hexdigest() for run in trusted_runs]},
                                       sort_keys=True, separators=(",", ":")).encode())
    eligibility_doc = json.loads((ROOT / "evidence/phase5-eligibility-v2.json").read_text())
    eligible_tank = next(item for item in eligibility_doc["candidates"] if item["title_id"] == "tank-battle")
    eligible_tank["source_archive_sha256"] = source_archive["sha256"]
    eligible_tank["build_evidence"]["receipt_sha256"] = build_receipt_sha
    frozen = {"scenario_sha256": hashlib.sha256(json.dumps(scenario_doc, sort_keys=True,
                                               separators=(",", ":")).encode()).hexdigest(),
              "oracle_sha256": hashlib.sha256(json.dumps(oracle_doc, sort_keys=True,
                                               separators=(",", ":")).encode()).hexdigest(),
              "script_sha256": script["sha256"], "title_id": "tank-battle", "cases": ["synthetic"]}
    eligible_tank["reference_route"]["frozen"] = frozen
    eligible_tank["reference_route"]["rom_sha256"] = canonical["sha256"]
    eligible_tank["generated_outputs"] = [
        {"category": "generated_rom", "ordinal": ordinal, "bytes": len(output_bytes),
         "sha256": hashlib.sha256(output_bytes).hexdigest()} for ordinal in (1, 2)]
    eligibility = bound(root, "evidence/phase5-eligibility-v2.json",
                        json.dumps(eligibility_doc, sort_keys=True, separators=(",", ":")).encode())
    report_doc = json.loads((ROOT / "evidence/phase5-reference-d118.json").read_text())
    report_route = next(item for item in report_doc["routes"] if item["title_id"] == "tank-battle")
    report_route.update(frozen=frozen, lineage_id="monteslu/retro-homebrew-games",
                        source_revision="eb7dc3044f9d2f76047f3b3573971bf86575ca52",
                        status="pass", runs=trusted_runs)
    reference_report = bound(root, "evidence/phase5-reference-d118.json",
                             json.dumps(report_doc, sort_keys=True, separators=(",", ":")).encode())
    ledger_doc = json.loads((root / "fixtures/candidate-screening-v2.json").read_text())
    selected_tank = next(item for item in ledger_doc["selected_pair"] if item["title_id"] == "tank-battle")
    selected_tank["reference_report"] = reference_report["path"]
    selected_tank["reference_report_sha256"] = reference_report["sha256"]
    screening_ledger = bound(root, "fixtures/candidate-screening-v2.json",
                             json.dumps(ledger_doc, sort_keys=True, separators=(",", ":")).encode())
    current_doc = json.loads((ROOT / "evidence/phase5-current-reference.json").read_text())
    current_doc["report"] = {"path": reference_report["path"], "sha256": reference_report["sha256"]}
    current_reference = bound(root, "evidence/phase5-current-reference.json",
                              json.dumps(current_doc, sort_keys=True, separators=(",", ":")).encode())
    identities = {
        "scenario": scenario["sha256"], "input_schedule": schedule["sha256"],
        "input_program": program["sha256"], "oracle": oracle["sha256"],
        "reference_script": script["sha256"], "reference_executable": executable["sha256"],
        "reference_build": reference_build["sha256"], "rom": canonical["sha256"],
    }
    runs = []
    pair_runs = []
    for ordinal in (1, 2):
        run_id = f"synthetic-run-{ordinal}"
        capture = bound(root, f"evidence/synthetic/run-{ordinal}.capture",
                        json.dumps(trusted_runs[ordinal - 1], sort_keys=True, separators=(",", ":")).encode())
        receipt_doc = {"schema": "genewhip-phase5-reference-run-v1", "status": "pass",
                       "run_id": run_id, "raw_capture_sha256": [capture["sha256"]]}
        receipt_data = json.dumps(receipt_doc, sort_keys=True, separators=(",", ":")).encode()
        receipt = bound(root, f"evidence/synthetic/run-{ordinal}.json", receipt_data)
        runs.append({"ordinal": ordinal, "run_id": run_id, "status": "pass", "fresh": True,
                     "receipt": receipt, "raw_captures": [capture]})
        pair_runs.append({"ordinal": ordinal, "run_id": run_id,
                          "receipt_sha256": receipt["sha256"], "raw_captures": [capture["sha256"]]})
    pair_doc = {"schema": "genewhip-phase5-reference-pair-v1", "status": "pass", "errors": [],
                "title_id": "tank-battle", "lineage_id": "monteslu/retro-homebrew-games",
                "reference_qualification": "qualified", "identities": identities, "runs": pair_runs}
    pair_data = json.dumps(pair_doc, sort_keys=True, separators=(",", ":")).encode()
    pair = bound(root, "evidence/synthetic/reference-pair.json", pair_data)
    notice_inventory = bound(root, "evidence/synthetic/notice-index.json",
                             json.dumps({"schema": "genewhip-phase5-notice-index-v1", "notices": [notice]},
                                        sort_keys=True, separators=(",", ":")).encode())
    build_record_doc = {
        "schema": "genewhip-phase5-build-record-v1", "title_id": "tank-battle",
        "source_revision": "eb7dc3044f9d2f76047f3b3573971bf86575ca52", "status": "pass",
        "comparison": "byte-identical", "build_recipe_sha256": recipe["sha256"],
        "tool_lock_sha256": tool_lock["sha256"], "linked_runtime_sha256": runtime["sha256"],
        "raw_outputs": [{"ordinal": 1, "bytes": len(output_bytes), "sha256": output_a["sha256"]},
                        {"ordinal": 2, "bytes": len(output_bytes), "sha256": output_b["sha256"]}],
        "canonical_rom_sha256": canonical["sha256"],
        "source_build_summary": source_build_summary,
    }
    build_record = bound(root, "evidence/synthetic/build-record.json",
                         json.dumps(build_record_doc, sort_keys=True, separators=(",", ":")).encode())
    route_freeze = hashlib.sha256(json.dumps({key: identities[key] for key in
        ("scenario", "input_schedule", "input_program", "oracle", "reference_script")},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    promotion = {"source_tree_identity": inventory["path"], "source_tree_sha256": inventory["sha256"],
                 "build_lock": tool_lock["path"], "build_lock_sha256": tool_lock["sha256"],
                 "notices": notice_inventory["path"], "notices_sha256": notice_inventory["sha256"],
                 "build_receipt_sha256": build_record["sha256"],
                 "rom": canonical["path"], "rom_sha256": canonical["sha256"]}
    route_evidence = {"canonical_rom_sha256": canonical["sha256"],
                      "frozen_route_sha256": route_freeze, "reference_pair_sha256": pair["sha256"]}
    record = {
        "schema": "genewhip-phase5-admission-v1", "fixture_id": "genewhip-phase5-a", "slot_id": "phase5-a",
        "title_id": "tank-battle", "lineage_id": "monteslu/retro-homebrew-games",
        "source_revision": "eb7dc3044f9d2f76047f3b3573971bf86575ca52",
        "status": "qualified", "outcome": "pass", "project": "Synthetic contract fixture",
        "license": "MIT", "assets": [],
        "gates": {"documentary": True, "build": True, "reference": True},
        "promotion": promotion, "route_evidence": route_evidence,
        "identities": {"screening_ledger": screening_ledger, "eligibility": eligibility,
                        "current_reference": current_reference, "reference_report": reference_report,
                        "source_archive": source_archive, "content_inventory": inventory,
                        "material_terms": terms, "build_recipe": recipe, "tool_lock": tool_lock,
                        "linked_runtime": runtime, "build_record": build_record,
                        "raw_outputs": [output_a, output_b], "canonical_rom": canonical,
                        "notices": [notice], "notice_inventory": notice_inventory, "scenario": scenario,
                        "input_schedule": schedule, "input_program": program, "oracle": oracle,
                        "reference_script": script, "reference_executable": executable,
                        "reference_build": reference_build, "reference_pair": pair, "runs": runs},
    }
    record_path = root / "evidence/synthetic/admission.json"
    record_sha = write_json(record_path, record)
    (root / "fixtures").mkdir(exist_ok=True)
    row = {"id": "genewhip-phase5-a", "kind": "phase5-independent-game-v1",
           "status": status, "outcome": "pass" if status == "admitted" else "unknown",
           "project": record["project"], "revision": record["source_revision"],
           "source": source_archive["path"], "source_sha256": source_archive["sha256"],
           "license": "MIT", "notices": [notice["path"]], "assets": [],
           "build": {"source": recipe["path"], "sha256": recipe["sha256"],
                     "toolchain": tool_lock["sha256"], "command": "reviewed recipe"},
           "sha256": canonical["sha256"], "rom": canonical["path"],
           "oracle": "source-derived-synthetic-control", "profile": "VA3-NTSC-U",
           "input": "synthetic-scenario-v1"}
    if with_admission:
        row["admission"] = {"path": "evidence/synthetic/admission.json", "sha256": record_sha}
    manifest = {"schema_version": 1, "fixtures": [
        {"id": "genewhip-diagnostic-v1", "status": "admitted", "outcome": "pass",
         "project": "Genewhip", "revision": "repository-tracked", "source": diag_source["path"],
         "source_sha256": diag_source["sha256"], "license": "MIT", "notices": [diag_notice["path"]],
         "assets": [], "build": {"source": diag_builder["path"], "sha256": diag_builder["sha256"],
                                  "toolchain": "synthetic", "command": "synthetic"},
         "sha256": diagnostic["sha256"], "oracle": "synthetic", "profile": "VA3-NTSC-U", "input": "none"}, row]}
    write_json(root / "fixtures/manifest.json", manifest)
    return record_path, root / "fixtures/manifest.json", canonical


class ProductionConsumerContract(unittest.TestCase):
    def consumer(self, root, manifest, expected=0):
        result = subprocess.run([sys.executable, "-I", str(root / "scripts/fixtures/run_admitted.py"),
                                 "--root", str(root), "--manifest", str(manifest.relative_to(root)),
                                 "--fixture-id", "genewhip-phase5-a",
                                 "--diagnostic-rom", "build/diagnostic.bin"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def test_admitted_pair_resolves_exact_promoted_rom_bytes(self):
        manifest = json.loads((ROOT / "fixtures/manifest.json").read_text())
        rows = {row.get("id"): row for row in manifest.get("fixtures", [])}
        expected = {
            "genewhip-phase5-a": "fixtures/phase5-a/game.bin",
            "genewhip-phase5-b": "fixtures/phase5-b/game.bin",
        }
        for fixture_id, rom_path in expected.items():
            with self.subTest(fixture_id=fixture_id):
                row = rows.get(fixture_id)
                self.assertIsNotNone(row, f"admitted pair row missing: {fixture_id}")
                self.assertEqual(row.get("kind"), "phase5-independent-game-v1")
                self.assertEqual(row.get("status"), "admitted")
                self.assertEqual(row.get("rom"), rom_path)
                result = subprocess.run(
                    [sys.executable, "-I", str(ROOT / "scripts/fixtures/run_admitted.py"),
                     "--root", str(ROOT), "--fixture-id", fixture_id],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(Path(result.stdout.strip()).read_bytes(), (ROOT / rom_path).read_bytes())

    def test_complete_synthetic_chain_resolves_exact_rom_after_promotion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, manifest, canonical = synthetic_consumer_tree(root)
            result = self.consumer(root, manifest)
            self.assertEqual(Path(result.stdout.strip()).read_bytes(), b"synthetic ROM bytes")
            self.assertEqual(Path(result.stdout.strip()).read_bytes(), canonical and b"synthetic ROM bytes")

    def test_status_only_and_missing_gate_are_refused(self):
        for with_admission, gate_failure in ((False, False), (True, True)):
            with self.subTest(with_admission=with_admission, gate_failure=gate_failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                record_path, manifest, _ = synthetic_consumer_tree(root, with_admission=with_admission)
                if gate_failure:
                    record = json.loads(record_path.read_text())
                    record["gates"]["reference"] = False
                    digest = write_json(record_path, record)
                    document = json.loads(manifest.read_text())
                    document["fixtures"][1]["admission"]["sha256"] = digest
                    write_json(manifest, document)
                self.consumer(root, manifest, expected=1)

    def test_modified_source_bytes_and_stale_reference_are_refused(self):
        mutations = ("screening_ledger", "eligibility", "current_reference", "reference_report",
                     "source_archive", "content_inventory", "material_terms", "build_recipe",
                     "tool_lock", "linked_runtime", "raw_output", "canonical_rom", "notice",
                     "scenario", "input_schedule", "input_program", "oracle", "reference_script",
                     "reference_executable", "reference_build", "reference_pair", "run_receipt", "raw_capture")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                record_path, manifest, _ = synthetic_consumer_tree(root)
                record = json.loads(record_path.read_text())
                identities = record["identities"]
                if mutation in ("raw_output", "notice"):
                    identity = identities["raw_outputs"][0] if mutation == "raw_output" else identities["notices"][0]
                elif mutation in ("run_receipt", "raw_capture"):
                    identity = identities["runs"][0]["receipt"] if mutation == "run_receipt" else identities["runs"][0]["raw_captures"][0]
                else:
                    identity = identities[mutation]
                (root / identity["path"]).write_bytes(b"changed after frozen identity")
                self.consumer(root, manifest, expected=1)

    def test_self_consistent_unanchored_source_and_route_are_refused(self):
        for mutation, expected_text in (("source", "source archive differs from anchored eligibility review"),
                                        ("route", "scenario ROM or embedded input identities do not match admission bytes"),
                                        ("reference-executable", "reference executable pin differs from frozen MAME source/build identities")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                record_path, manifest, _ = synthetic_consumer_tree(root)
                record = json.loads(record_path.read_text())
                identities = record["identities"]
                if mutation == "source":
                    source_ref = identities["source_archive"]
                    forged = b"self-consistent but unreviewed source archive"
                    (root / source_ref["path"]).write_bytes(forged)
                    source_ref["sha256"] = hashlib.sha256(forged).hexdigest()
                    scenario_path = root / identities["scenario"]["path"]
                    scenario = json.loads(scenario_path.read_text())
                    scenario["identities"]["source_archive_sha256"] = source_ref["sha256"]
                    scenario_bytes = json.dumps(scenario, sort_keys=True, separators=(",", ":")).encode()
                    scenario_path.write_bytes(scenario_bytes)
                    identities["scenario"]["sha256"] = hashlib.sha256(scenario_bytes).hexdigest()
                elif mutation == "route":
                    scenario_path = root / identities["scenario"]["path"]
                    scenario = json.loads(scenario_path.read_text())
                    scenario["unreviewed_route_change"] = True
                    scenario_bytes = json.dumps(scenario, sort_keys=True, separators=(",", ":")).encode()
                    scenario_path.write_bytes(scenario_bytes)
                    identities["scenario"]["sha256"] = hashlib.sha256(scenario_bytes).hexdigest()
                else:
                    pin_ref = identities["reference_executable"]
                    pin_path = root / pin_ref["path"]
                    pin_doc = json.loads(pin_path.read_text())
                    pin_doc["executable_sha256"] = "0" * 64
                    pin_bytes = json.dumps(pin_doc, sort_keys=True, separators=(",", ":")).encode()
                    pin_path.write_bytes(pin_bytes)
                    pin_ref["sha256"] = hashlib.sha256(pin_bytes).hexdigest()
                    build_ref = identities["reference_build"]
                    build_path = root / build_ref["path"]
                    build_doc = json.loads(build_path.read_text())
                    build_doc["executable_sha256"] = "0" * 64
                    build_bytes = json.dumps(build_doc, sort_keys=True, separators=(",", ":")).encode()
                    build_path.write_bytes(build_bytes)
                    build_ref["sha256"] = hashlib.sha256(build_bytes).hexdigest()
                pair_ref = identities["reference_pair"]
                pair_path = root / pair_ref["path"]
                pair_doc = json.loads(pair_path.read_text())
                pair_doc["identities"]["scenario"] = identities["scenario"]["sha256"]
                pair_bytes = json.dumps(pair_doc, sort_keys=True, separators=(",", ":")).encode()
                pair_path.write_bytes(pair_bytes)
                pair_ref["sha256"] = hashlib.sha256(pair_bytes).hexdigest()
                frozen_keys = ("scenario", "input_schedule", "input_program", "oracle", "reference_script")
                identities_by_key = {key: identities[key]["sha256"] for key in frozen_keys}
                record["route_evidence"]["frozen_route_sha256"] = records.identity_digest(identities_by_key)
                record["route_evidence"]["reference_pair_sha256"] = pair_ref["sha256"]
                self._rewrite_admission(root, record_path, manifest, record)
                result = self.consumer(root, manifest, expected=1)
                self.assertIn(expected_text, result.stderr)

    def test_pre_promotion_and_stale_canonical_selection_do_not_resolve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, manifest, _ = synthetic_consumer_tree(root, status="candidate")
            self.consumer(root, manifest, expected=1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, manifest, _ = synthetic_consumer_tree(root)
            document = json.loads(manifest.read_text())
            document["fixtures"][1]["rom"] = "fixtures/phase5-a/other.bin"
            write_json(manifest, document)
            self.consumer(root, manifest, expected=1)

    def _rewrite_admission(self, root, record_path, manifest, record):
        record_sha = write_json(record_path, record)
        document = json.loads(manifest.read_text())
        document["fixtures"][1]["admission"]["sha256"] = record_sha
        write_json(manifest, document)

    def test_missing_asset_or_runtime_terms_and_notices_are_refused(self):
        for category in ("resources", "runtime_objects", "fonts"):
            with self.subTest(category=category), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                record_path, manifest, _ = synthetic_consumer_tree(root)
                record = json.loads(record_path.read_text())
                terms_ref = record["identities"]["material_terms"]
                terms_path = root / terms_ref["path"]
                terms = json.loads(terms_path.read_text())
                terms["materials"] = [row for row in terms["materials"] if row.get("category") != category]
                terms_ref["sha256"] = write_json(terms_path, terms)
                self._rewrite_admission(root, record_path, manifest, record)
                self.consumer(root, manifest, expected=1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record_path, manifest, _ = synthetic_consumer_tree(root)
            record = json.loads(record_path.read_text())
            record["identities"]["notices"][0]["covers"] = []
            self._rewrite_admission(root, record_path, manifest, record)
            self.consumer(root, manifest, expected=1)

    def test_material_location_swaps_and_unpinned_overrides_are_refused(self):
        for mutation in ("archive-member", "reviewed-override"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                record_path, manifest, _ = synthetic_consumer_tree(root)
                record = json.loads(record_path.read_text())
                terms_ref = record["identities"]["material_terms"]
                terms_path = root / terms_ref["path"]
                terms = json.loads(terms_path.read_text())
                selected = next(row for row in terms["material_locations"] if row["kind"] == mutation)
                if mutation == "archive-member":
                    other = next(row for row in terms["material_locations"]
                                 if row["kind"] == mutation and row is not selected)
                    selected["member_path"] = other["member_path"]
                else:
                    selected["source_revision"] = "b" * 40
                terms_ref["sha256"] = write_json(terms_path, terms)
                self._rewrite_admission(root, record_path, manifest, record)
                self.consumer(root, manifest, expected=1)

    def test_private_path_and_secret_sentinels_are_refused(self):
        for sentinel in ("/" + "Users" + "/private/home/fixture", "to" + "ken=private-value"):
            with self.subTest(sentinel=sentinel), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                record_path, manifest, _ = synthetic_consumer_tree(root)
                record = json.loads(record_path.read_text())
                record["project"] += " " + sentinel
                self._rewrite_admission(root, record_path, manifest, record)
                self.consumer(root, manifest, expected=1)

    def test_symlink_escape_and_quarantine_paths_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            record_path, manifest, _ = synthetic_consumer_tree(root)
            record = json.loads(record_path.read_text())
            escaped = root / "evidence/synthetic/escape.capture"
            escaped.symlink_to(Path(outside) / "secret")
            (Path(outside) / "secret").write_bytes(b"private sentinel")
            record["identities"]["linked_runtime"] = {
                "path": "evidence/synthetic/escape.capture",
                "sha256": hashlib.sha256(b"private sentinel").hexdigest()}
            digest = write_json(record_path, record)
            document = json.loads(manifest.read_text())
            document["fixtures"][1]["admission"]["sha256"] = digest
            write_json(manifest, document)
            self.consumer(root, manifest, expected=1)


def run_consumer_self_tests():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProductionConsumerContract)
    return unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()


def verify_admitted_pair():
    manifest = json.loads((ROOT / "fixtures/manifest.json").read_text())
    rows = manifest.get("fixtures", [])
    historic = [row for row in rows if row.get("id") not in {"genewhip-phase5-a", "genewhip-phase5-b"}]
    historic_sha = hashlib.sha256(json.dumps(historic, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if historic_sha != HISTORICAL_MANIFEST_ROWS_SHA256:
        raise AssertionError("historical manifest rows changed during Phase 5 admission")
    by_id = {row.get("id"): row for row in rows}
    expected = {"genewhip-phase5-a": "fixtures/phase5-a/game.bin",
                "genewhip-phase5-b": "fixtures/phase5-b/game.bin"}
    empty_pair_manifest = ROOT / "build/phase5/admission-before-pair.json"
    empty_pair_manifest.parent.mkdir(parents=True, exist_ok=True)
    empty_pair_manifest.write_text(json.dumps({"schema_version": 1, "fixtures": historic},
                                               sort_keys=True, indent=2) + "\n")
    try:
        for fixture_id in expected:
            refused = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/fixtures/run_admitted.py"),
                                      "--root", str(ROOT), "--manifest", "build/phase5/admission-before-pair.json",
                                      "--fixture-id", fixture_id], cwd=ROOT,
                                     capture_output=True, text=True, timeout=30)
            if refused.returncode == 0:
                raise AssertionError(f"pre-admission manifest unexpectedly resolved {fixture_id}")
    finally:
        empty_pair_manifest.unlink(missing_ok=True)
    for fixture_id, rom_path in expected.items():
        row = by_id.get(fixture_id)
        if (not row or row.get("kind") != "phase5-independent-game-v1"
                or row.get("status") != "admitted" or row.get("outcome") != "pass"
                or row.get("rom") != rom_path):
            raise AssertionError(f"actual admitted pair row is incomplete: {fixture_id}")
        result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/fixtures/run_admitted.py"),
                                 "--root", str(ROOT), "--fixture-id", fixture_id],
                                cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(f"production consumer refused {fixture_id}: {result.stderr.strip()}")
        if Path(result.stdout.strip()).read_bytes() != (ROOT / rom_path).read_bytes():
            raise AssertionError(f"production consumer returned different ROM bytes: {fixture_id}")
    print(json.dumps({"outcome": "pass", "fixtures": list(expected),
                      "historical_rows_sha256": historic_sha}, sort_keys=True))


if __name__ == "__main__":
    if sys.argv[1:] not in (["--self-test"], ["--consumer-self-test"], ["--self-test", "--consumer-self-test"], ["--verify-admitted-pair"]):
        print("usage: phase5_admission_contract.py --self-test [--consumer-self-test] | --consumer-self-test | --verify-admitted-pair", file=sys.stderr)
        raise SystemExit(2)
    if sys.argv[1:] == ["--verify-admitted-pair"]:
        try:
            verify_admitted_pair()
        except (OSError, AssertionError, subprocess.SubprocessError) as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            raise SystemExit(1)
        raise SystemExit(0)
    success = True
    if "--self-test" in sys.argv:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(AdmissionContract)
        success = unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() and success
        export_suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReviewedSourceExportContract)
        success = unittest.TextTestRunner(verbosity=2).run(export_suite).wasSuccessful() and success
    if "--consumer-self-test" in sys.argv:
        success = run_consumer_self_tests() and success
    raise SystemExit(0 if success else 1)
