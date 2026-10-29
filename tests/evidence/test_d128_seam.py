"""Synthetic explicit-clock admission and real owner24 transaction regressions."""
import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("wr01_cases", ROOT / "tests/evidence/test_engineering25_accounting.py")
WR01 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(WR01)
RETAINED_ROOTS = WR01.RETAINED_ROOTS
H = globals()["HELPER"]


class WR01Tests(unittest.TestCase):
    make_owner24_project = WR01.Engineering25ForecastNormalizationTests.make_owner24_project

    def test_numeric_string_forecast_is_rejected_without_typeerror_or_mutation(self):
        temp = tempfile.mkdtemp(prefix="d128-wr01-contract-")
        RETAINED_ROOTS.append(temp)
        root, ledger = self.make_owner24_project(temp)
        before = ledger.read_bytes()
        with self.assertRaisesRegex(WR01.ACCOUNTING.AccountingError, "engineering24-complete-forecast-invalid"):
            WR01.ACCOUNTING.begin_engineering24_activity(ledger,
                activity_id="d125-engineering24-wr01-string", stage="engineering", exposure_seconds=1.0,
                remaining_forecast_seconds="100.0", boot_identity="synthetic-boot", project_root=root)
        self.assertEqual(before, ledger.read_bytes())

    def test_numeric_forecast_neighbors_and_rollback(self):
        for forecast in (0.0, 0.5, True, False, "bad", float("nan"), float("inf"), -1.0):
            temp = tempfile.mkdtemp(prefix="d128-wr01-neighbor-")
            RETAINED_ROOTS.append(temp)
            root, ledger = self.make_owner24_project(temp)
            before = ledger.read_bytes()
            with self.assertRaises(WR01.ACCOUNTING.AccountingError):
                WR01.ACCOUNTING.begin_engineering24_activity(ledger,
                    activity_id="d125-engineering24-boundary", stage="engineering", exposure_seconds=1.0,
                    remaining_forecast_seconds=forecast, boot_identity="synthetic-boot", project_root=root)
            self.assertEqual(before, ledger.read_bytes())
        for forecast in (1.0, 1.5):
            temp = tempfile.mkdtemp(prefix="d128-wr01-positive-")
            RETAINED_ROOTS.append(temp)
            root, ledger = self.make_owner24_project(temp)
            row = WR01.ACCOUNTING.begin_engineering24_activity(ledger,
                activity_id="d125-engineering24-boundary", stage="engineering", exposure_seconds=1.0,
                remaining_forecast_seconds=forecast, boot_identity="synthetic-boot", project_root=root)
            self.assertEqual(float(forecast), row["remaining_forecast_seconds"])
            self.assertIs(type(row["remaining_forecast_seconds"]), float)

    def test_unsupported24_neighbors_still_reject_without_mutation(self):
        temp = tempfile.mkdtemp(prefix="d128-unsupported-")
        RETAINED_ROOTS.append(temp)
        root, ledger = self.make_owner24_project(temp)
        before = ledger.read_bytes()
        with self.assertRaisesRegex(WR01.ACCOUNTING.AccountingError, "accepted-close-unsupported"):
            WR01.ACCOUNTING.close_engineering24(ledger, output=root / "evidence/no.json",
                status="accepted-engineering24", reason="not authorized", boot_identity="synthetic-boot", project_root=root)
        self.assertEqual(before, ledger.read_bytes())
        value = json.loads(before)
        value["d125_engineering24_policy"]["status"] = "HALTED"
        ledger.write_text(json.dumps(value))
        terminal = ledger.read_bytes()
        with self.assertRaises(WR01.ACCOUNTING.AccountingError):
            WR01.ACCOUNTING.begin_engineering24_activity(ledger,
                activity_id="d125-engineering24-terminal", stage="engineering", exposure_seconds=1.0,
                remaining_forecast_seconds=100.0, boot_identity="synthetic-boot", project_root=root)
        self.assertEqual(terminal, ledger.read_bytes())


class AdmissionTests(unittest.TestCase):
    def fixture(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="d128-bindings-")).resolve()
        RETAINED_ROOTS.append(str(root))
        paths = ["scripts/evidence/d128_seam.py", "tests/evidence/d128_guard.py",
                 "tests/evidence/test_d128_seam.py", "scripts/evidence/phase6_accounting.py",
                 "tests/evidence/test_engineering25_accounting.py", H.AUTHORITY,
                 ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D128-AMENDMENT.md",
                 "review.md"]
        for relative in paths:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic reviewed bytes")
        authority = {"decision": "approved", "purpose": H.PURPOSE, "baseline_ledger_sha256": H.BASELINE,
                     "purpose_cap_seconds": H.CAP, "global_cap_seconds": H.GLOBAL,
                     "terminal_reserve_seconds": H.TERMINAL, "protected_process_seconds": H.PROCESS,
                     "workloads_authorized": False,
                     "amendment_sha256": H.sha((root / paths[-2]).read_bytes())}
        (root / H.AUTHORITY).write_bytes(H.encode(authority))
        inventory = {p: H.sha((root / p).read_bytes()) for p in paths}
        pin = {"decision": "ACCEPT", "blocking_findings": 0, "reviewer_terminal_status": "completed",
               "reviewer_identity": "independent-synthetic-reviewer", "boot_identity": H.BOOT,
               "review_path": "review.md", "inventory": {"red": inventory, "green": inventory}}
        (root / "pin.json").write_bytes(H.encode(pin))
        (root / "evidence").mkdir()
        state = self.state()
        state["entry_binding"] = {"authority_sha256": inventory[H.AUTHORITY]}
        (root / H.LEDGER).write_bytes(H.encode({"old": [1, 2], H.KEY: state}))
        return root, H.sha((root / "pin.json").read_bytes())

    def test_actual_admit_revalidates_pins_authority_boot_and_rolls_back(self):
        root, pin_sha = self.fixture()
        ledger = root / H.LEDGER
        result = H.admit(root, "pin.json", pin_sha, "green", H.START + 1200.0, H.BOOT)
        self.assertEqual(2100.0, result["purpose_remaining_seconds"])
        before = ledger.read_bytes()
        for now, boot, digest in ((H.START + 1200.001, H.BOOT, pin_sha),
                                  (H.START, "stale", pin_sha), (H.START, H.BOOT, "0" * 64)):
            with self.assertRaises(RuntimeError):
                H.admit(root, "pin.json", digest, "green", now, boot)
            self.assertEqual(before, ledger.read_bytes())
        for relative in (H.AUTHORITY, "scripts/evidence/phase6_accounting.py"):
            path = root / relative
            original = path.read_bytes()
            path.write_bytes(original + b"stale")
            with self.assertRaisesRegex(RuntimeError, "stale"):
                H.admit(root, "pin.json", pin_sha, "green", H.START, H.BOOT)
            self.assertEqual(before, ledger.read_bytes())
            path.write_bytes(original)

    def test_locked_observation_overrides_stale_prelock_clock(self):
        root, pin_sha = self.fixture()
        ledger = root / H.LEDGER
        before = ledger.read_bytes()
        observations = []
        def delayed():
            observations.append(True)
            return H.START + 1200.001, H.BOOT
        with self.assertRaisesRegex(RuntimeError, "complete-forecast-denied"):
            H.admit(root, "pin.json", pin_sha, "green", H.START, H.BOOT, observer=delayed)
        self.assertEqual(2, len(observations))
        self.assertEqual(before, ledger.read_bytes())
        receipt = H.close(root, H.START, H.BOOT, "HALTED", "delayed close", observer=delayed)
        self.assertAlmostEqual(1620.001, receipt["owner_total_charge_seconds"])

    def state(self):
        return {"status": "active", "purpose": H.PURPOSE, "boot_identity": H.BOOT, "admissions": [],
                "started_monotonic": H.START, "remaining_forecast": {"seam": 600.0, "review": 600.0, "uncertainty": 300.0}}

    def test_exact_and_below_threshold(self):
        state = self.state()
        exact = H.START + 1200.0  # charge1500, remaining2100 = N1500+C600
        self.assertEqual(2100.0, H.headroom(state, exact, H.BOOT, 55.0)["purpose_remaining_seconds"])
        with self.assertRaisesRegex(RuntimeError, "complete-forecast-denied"):
            H.headroom(state, exact + 0.001, H.BOOT, 55.0)

    def test_elapsed_denies_unchanged_forecast_completed_work_admits(self):
        state = self.state()
        now = H.START + 1300.0
        with self.assertRaisesRegex(RuntimeError, "complete-forecast-denied"):
            H.headroom(state, now, H.BOOT, 55.0)
        # This models completed seam600, not elapsed-credit or borrowed terminal.
        del state["remaining_forecast"]["seam"]
        self.assertEqual(900.0, H.headroom(state, now, H.BOOT, 55.0)["remaining_forecast_seconds"])

    def test_retirement_requires_completed_guarded_evidence(self):
        root, pin_sha = self.fixture()
        admission = H.admit(root, "pin.json", pin_sha, "green", H.START, H.BOOT)
        ledger = root / H.LEDGER
        report = {"variant": "green", "tests_run": 10, "failures": 1, "errors": 0,
                  "unexpected_process_requests": 0, "process_denial_probes": 9, "admission": admission}
        path = root / "evidence/green.json"
        path.write_bytes(H.encode(report))
        before = ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "completion-evidence-invalid"):
            H.retire_seam(root, "pin.json", pin_sha, "evidence/green.json", H.START, H.BOOT)
        self.assertEqual(before, ledger.read_bytes())
        report["failures"] = 0
        path.write_bytes(H.encode(report))
        H.retire_seam(root, "pin.json", pin_sha, "evidence/green.json", H.START, H.BOOT)
        state = json.loads(ledger.read_bytes())[H.KEY]
        self.assertEqual(900.0, H.headroom(state, H.START + 1300.0, H.BOOT, 55.0)["remaining_forecast_seconds"])
        self.assertEqual(H.sha(path.read_bytes()), state["completed_forecast"][-1]["evidence_sha256"])
        after = ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "completion-evidence-invalid"):
            H.retire_seam(root, "pin.json", pin_sha, "evidence/green.json", H.START, H.BOOT)
        self.assertEqual(after, ledger.read_bytes())

    def test_malformed_clock_forecast_and_boot(self):
        for invalid in (True, "100", float("nan"), float("inf"), None):
            with self.assertRaises(RuntimeError):
                H.headroom(self.state(), invalid, H.BOOT, 55.0)
        for invalid in (True, "100", float("nan"), float("inf")):
            state = self.state()
            state["remaining_forecast"]["seam"] = invalid
            with self.assertRaises(RuntimeError):
                H.headroom(state, H.START, H.BOOT, 55.0)
        with self.assertRaisesRegex(RuntimeError, "rollback"):
            H.headroom(self.state(), H.START - 1.0, H.BOOT, 55.0)
        with self.assertRaisesRegex(RuntimeError, "boot-stale"):
            H.headroom(self.state(), H.START, "old-boot", 55.0)

    def test_terminal_create_once_recovery_and_idempotency(self):
        temp = tempfile.mkdtemp(prefix="d128-terminal-")
        RETAINED_ROOTS.append(temp)
        root = pathlib.Path(temp).resolve()
        (root / "evidence").mkdir()
        ledger = root / H.LEDGER
        state = self.state()
        ledger.write_bytes(H.encode({"old": {"immutable": [1, 2]}, H.KEY: state}))
        receipt = H.close(root, H.START + 10.0, H.BOOT, "HALTED", "synthetic halt")
        after = ledger.read_bytes()
        output = root / H.RECEIPT
        payload = output.read_bytes()
        self.assertEqual(430.0, receipt["owner_total_charge_seconds"])
        self.assertEqual({"immutable": [1, 2]}, json.loads(after)["old"])
        H.close(root, H.START + 99.0, H.BOOT, "HALTED", "recovery")
        self.assertEqual(after, ledger.read_bytes())
        output.unlink()
        H.close(root, H.START + 99.0, H.BOOT, "HALTED", "recovery")
        self.assertEqual(payload, output.read_bytes())
        self.assertEqual(after, ledger.read_bytes())
        target = root / "evidence/exact-intent.json"
        target.write_bytes(payload)
        output.unlink()
        output.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            H.close(root, H.START + 99.0, H.BOOT, "HALTED", "recovery")
        self.assertEqual(after, ledger.read_bytes())
        output.unlink()
        output.write_bytes(payload)
        output.write_bytes(b"conflict")
        with self.assertRaisesRegex(RuntimeError, "conflict"):
            H.close(root, H.START + 99.0, H.BOOT, "HALTED", "recovery")
        self.assertEqual(after, ledger.read_bytes())
