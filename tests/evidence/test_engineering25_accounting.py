"""Plan25 bounded accounting regressions; loaded only by the reviewed guard."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
ROOT = globals().get("SOURCE_ROOT", ROOT)
SPEC = importlib.util.spec_from_file_location(
    "phase6_accounting_engineering25_test", ROOT / "scripts/evidence/phase6_accounting.py")
ACCOUNTING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCOUNTING)
RETAINED_ROOTS = []


class Engineering25ForecastNormalizationTests(unittest.TestCase):
    def make_owner24_project(self, parent):
        root = pathlib.Path(parent)
        for name in (
            "build/phase6/d125-engineering24", "evidence", ".planning/context",
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes",
        ):
            (root / name).mkdir(parents=True, exist_ok=True)
        inputs = {
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-24-PLAN.md": b"plan\n",
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-24-PLAN-CHECK.md": b"check\n",
            ".planning/context/OPERATING.md": b"operating\n",
        }
        for name, data in inputs.items():
            (root / name).write_bytes(data)
        ledger_path = root / "evidence/phase6-repairs.json"
        base = {"records": [], "usage": {"cumulative_repair_seconds": 100.0}}
        ledger_path.write_text(json.dumps(base))
        digest = ACCOUNTING.ledger_digest(ledger_path)
        entry = {
            "schema": "phase6-d125-engineering24-entry-v1", "status": "active",
            "boot_identity": "synthetic-boot", "global_closed_floor_seconds": 100.0,
            "final_entry_ledger_sha256": digest, "pea_used_seconds": 7098.193,
            "parent_active_discovery_prefix_seconds": 0.0,
            "monotonic_started_at": time.monotonic(), "started_at": "synthetic",
            "process_used_seconds": 5.865, "attempts_used": 2,
            "input_sha256": {name: ACCOUNTING.ledger_digest(root / name) for name in inputs},
        }
        closeout = {
            "global_used_seconds": 100.0, "entry_ledger_sha256": digest,
            "boot_identity": "synthetic-boot", "debug_anchor_closed": True,
            "production_anchor": None,
        }
        closeout_path = root / "evidence/phase6-d125-proof-receipt-debug-closeout.json"
        closeout_path.write_text(json.dumps(closeout))
        entry["debug_closeout_sha256"] = ACCOUNTING.ledger_digest(closeout_path)
        entry_path = root / "build/phase6/d125-engineering24/entry.json"
        entry_path.write_text(json.dumps(entry))
        policy = {
            "schema": "phase6-d125-engineering24-v1", "plan": "06-24",
            "status": "engineering-only", "game_admission": False,
            "test_fixture_only": False, "retained_count": 3, "fresh_count": 0,
            "global_cap_seconds": 43200.0, "global_floor_seconds": 100.0,
            "parent_active_discovery_prefix_seconds": 0.0,
            "pea_floor_seconds": 7098.193, "process_floor_seconds": 5.865,
            "attempts_floor": 2, "pea_cap_seconds": 9403.235,
            "process_cap_seconds": 1800.0, "attempts_cap": 3,
            "protected_process_seconds": 1794.135, "closeout_reserve_seconds": 120.0,
            "boot_identity": "synthetic-boot", "entry_ledger_sha256": digest,
            "entry_sha256": ACCOUNTING.ledger_digest(entry_path),
            "debug_closeout_sha256": entry["debug_closeout_sha256"],
            "bindings": entry["input_sha256"],
            "anchor": {
                "status": "active", "pea_charge": False,
                "boot_identity": "synthetic-boot",
                "entry_sha256": ACCOUNTING.ledger_digest(entry_path),
                "monotonic_started_at": entry["monotonic_started_at"],
            },
        }
        ledger_path.write_text(json.dumps({
            **base, "d125_engineering24_policy": policy,
            "d125_engineering24_activities": [], "d125_engineering24_reviews": [],
        }))
        return root, ledger_path

    def test_numeric_string_forecast_is_normalized_before_exposure_comparison(self):
        """WR-01: a numeric string is accepted as a float, not leaked as TypeError."""
        temp = tempfile.mkdtemp(prefix="engineering25-wr01-")
        RETAINED_ROOTS.append(temp)
        root, ledger_path = self.make_owner24_project(temp)
        try:
            row = ACCOUNTING.begin_engineering24_activity(
                ledger_path, activity_id="d125-engineering24-wr01-string",
                stage="engineering", exposure_seconds=1.0,
                remaining_forecast_seconds="100.0", boot_identity="synthetic-boot",
                project_root=root,
            )
        except TypeError as error:
            self.fail(f"WR-01 leaked TypeError instead of normalizing forecast: {error}")
        self.assertEqual(row["remaining_forecast_seconds"], 100.0)
        self.assertIs(type(row["remaining_forecast_seconds"]), float)


if __name__ == "__main__":
    unittest.main()
