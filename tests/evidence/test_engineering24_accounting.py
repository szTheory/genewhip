import importlib.util
import json
import pathlib
import tempfile
import unittest
import time
import copy
import types
import shutil

RETAINED_ROOTS = []
class RetainedSyntheticDirectory:
    """Keep failed and passing synthetic ledgers available for independent review."""
    def __init__(self, dir=None):
        parent = dir or tempfile.gettempdir()
        self.name = tempfile.mkdtemp(prefix='synthetic-', dir=parent)
        RETAINED_ROOTS.append(self.name)
    def __enter__(self):
        return self.name
    def __exit__(self, *_):
        return False

ROOT = pathlib.Path(__file__).resolve().parents[2]
ROOT = globals().get('SOURCE_ROOT', ROOT)
SPEC = importlib.util.spec_from_file_location("phase6_accounting_engineering24_test",
    ROOT / "scripts/evidence/phase6_accounting.py")
ACCOUNTING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCOUNTING)


class Engineering24OwnerTests(unittest.TestCase):
    def make_project(self, parent):
        root = pathlib.Path(parent)
        for name in ("build/phase6/d125-engineering24", "evidence",
                     ".planning/context", ".planning/phases/GW-06-shared-repairs-and-two-playable-routes"):
            (root / name).mkdir(parents=True, exist_ok=True)
        inputs = {
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-24-PLAN.md": b"plan\n",
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-24-PLAN-CHECK.md": b"check\n",
            ".planning/context/OPERATING.md": b"operating\n",
        }
        for name, data in inputs.items():
            (root / name).write_bytes(data)
        ledger_path = root / 'evidence/phase6-repairs.json'
        base = {'records': [], 'usage': {'cumulative_repair_seconds': 100.0}}
        ledger_path.write_text(json.dumps(base))
        digest = ACCOUNTING.ledger_digest(ledger_path)
        entry = {"schema": "phase6-d125-engineering24-entry-v1", "status": "active",
            "boot_identity": "test-boot", "global_closed_floor_seconds": 100.0,
            "final_entry_ledger_sha256": digest, "pea_used_seconds": 7098.193,
            'parent_active_discovery_prefix_seconds': 0.0,
            'monotonic_started_at': time.monotonic(), 'started_at': 'synthetic',
            "process_used_seconds": 5.865, "attempts_used": 2,
            "input_sha256": {name: ACCOUNTING.ledger_digest(root / name) for name in inputs}}
        entry_path = root / "build/phase6/d125-engineering24/entry.json"
        closeout = {"global_used_seconds": 100.0, "entry_ledger_sha256": digest,
            "boot_identity": "test-boot", "debug_anchor_closed": True, "production_anchor": None}
        closeout_path = root / "evidence/phase6-d125-proof-receipt-debug-closeout.json"
        closeout_path.write_text(json.dumps(closeout))
        entry['debug_closeout_sha256'] = ACCOUNTING.ledger_digest(closeout_path)
        entry_path.write_text(json.dumps(entry))
        policy = {"schema": "phase6-d125-engineering24-v1", "plan": "06-24",
            "status": "engineering-only", "game_admission": False, "test_fixture_only": False,
            "retained_count": 3, "fresh_count": 0, "global_cap_seconds": 43200.0,
            "pea_floor_seconds": 7098.193, "process_floor_seconds": 5.865, "attempts_floor": 2,
            "pea_cap_seconds": 9403.235, "process_cap_seconds": 1800.0, "attempts_cap": 3,
            "protected_process_seconds": 1794.135, "closeout_reserve_seconds": 120.0,
            "global_floor_seconds": 100.0, "parent_active_discovery_prefix_seconds": 0.0,
            "boot_identity": "test-boot", "entry_ledger_sha256": digest,
            "entry_sha256": ACCOUNTING.ledger_digest(entry_path), "debug_closeout_sha256": entry['debug_closeout_sha256'],
            "bindings": entry["input_sha256"], "anchor": {"status": "active", "pea_charge": False,
                "boot_identity": "test-boot", "entry_sha256": ACCOUNTING.ledger_digest(entry_path),
                "monotonic_started_at": entry['monotonic_started_at']}}
        ledger = {**base, "d125_engineering24_policy": policy, "d125_engineering24_activities": [],
            "d125_engineering24_reviews": []}
        ledger_path.write_text(json.dumps(ledger))
        return root, ledger, next(iter(inputs))

    def test_owner_rejects_missing_bound_plan_input(self):
        with RetainedSyntheticDirectory() as temp:
            root, ledger, missing = self.make_project(temp)
            (root / missing).unlink()
            with self.assertRaises(ACCOUNTING.AccountingError):
                ACCOUNTING.engineering24_owner(ledger, project_root=root, boot_identity="test-boot")

    def test_owner_exact_floor_prefix_and_closeout(self):
        with RetainedSyntheticDirectory() as temp:
            root, ledger, _ = self.make_project(temp)
            ACCOUNTING.engineering24_owner(ledger, project_root=root)
            for key, val in [('global_floor_seconds',99.0), ('parent_active_discovery_prefix_seconds',-1.0),
                             ('debug_closeout_sha256','b'*64), ('bindings',{})]:
                bad = copy.deepcopy(ledger); bad['d125_engineering24_policy'][key] = val
                with self.subTest(key=key), self.assertRaises(ACCOUNTING.AccountingError):
                    ACCOUNTING.engineering24_owner(bad, project_root=root)

    def test_actual_bootstrap_ledger_digest(self):
        with RetainedSyntheticDirectory() as temp:
            root, ledger, _ = self.make_project(temp)
            path = root/'evidence/phase6-repairs.json'
            for key in list(ledger):
                if key.startswith('d125_engineering24'): del ledger[key]
            path.write_text(json.dumps(ledger))
            entry_path = root/'build/phase6/d125-engineering24/entry.json'
            entry = json.loads(entry_path.read_bytes())
            entry['final_entry_ledger_sha256'] = ACCOUNTING.ledger_digest(path)
            closeout_path=root/'evidence/phase6-d125-proof-receipt-debug-closeout.json'
            closeout=json.loads(closeout_path.read_bytes());closeout['entry_ledger_sha256']='a'*64
            closeout_path.write_text(json.dumps(closeout))
            entry['debug_closeout_sha256']=ACCOUNTING.ledger_digest(closeout_path)
            entry_path.write_text(json.dumps(entry))
            policy = ACCOUNTING.install_engineering24_policy(path, project_root=root)
            self.assertEqual(policy['entry_ledger_sha256'],entry['final_entry_ledger_sha256'])

    def test_accepted_close_is_fail_closed(self):
        with RetainedSyntheticDirectory() as temp:
            root, _, _ = self.make_project(temp); path=root/'evidence/phase6-repairs.json'
            before=path.read_bytes()
            with self.assertRaisesRegex(ACCOUNTING.AccountingError, 'accepted-close-unsupported'):
                ACCOUNTING.close_engineering24(path, output=root/'evidence/close.json', status='accepted-engineering24',
                    reason='synthetic', boot_identity='test-boot', project_root=root)
            self.assertEqual(before,path.read_bytes())

    def test_receipt_recovery_existing_absent_conflict_symlink(self):
        with RetainedSyntheticDirectory() as temp:
            root, _, _ = self.make_project(temp); path=root/'evidence/phase6-repairs.json'
            output=root/'evidence/close.json'
            report=ACCOUNTING.close_engineering24(path,output=output,status='HALTED',reason='synthetic',boot_identity='test-boot',project_root=root)
            before=path.read_bytes()
            self.assertEqual(ACCOUNTING.recover_engineering24_receipt(path,output=output,project_root=root),report)
            output.unlink()
            self.assertEqual(ACCOUNTING.recover_engineering24_receipt(path,output=output,project_root=root),report)
            output.write_text('{}')
            with self.assertRaises(ACCOUNTING.AccountingError): ACCOUNTING.recover_engineering24_receipt(path,output=output,project_root=root)
            output.unlink(); output.symlink_to(path)
            with self.assertRaises(ACCOUNTING.AccountingError): ACCOUNTING.recover_engineering24_receipt(path,output=output,project_root=root)
            self.assertEqual(path.read_bytes(),before)

    def test_real_owner24_activity_chain(self):
        with RetainedSyntheticDirectory() as temp:
            root, _, _ = self.make_project(temp)
            # The original implementation's ancestor discovery must reach only
            # authored data, so its RED tests the API path rather than setup.
            child=root/'nested'
            shutil.copytree(root,child)
            (root/'.git').mkdir()
            spec=importlib.util.spec_from_file_location('owner24_authored',ROOT/'tests/evidence/phase6_d125_authored_fixture.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            fixture=module.AuthoredFixture({'root':child})
            report=None
            try:
                report=fixture.engineering24_chain({'coordinator':types.SimpleNamespace(accounting=ACCOUNTING)},
                    types.SimpleNamespace(engineering_owner='06-24',case='engineering24-chain'),
                    types.SimpleNamespace(violation_count=0),types.SimpleNamespace(process_events=0))
            finally:
                rows=json.loads((child/'evidence/phase6-repairs.json').read_bytes())['d125_engineering24_activities']
                self.assertEqual(len(rows),1,'actual owner24 reservation API must commit one synthetic activity')
                self.assertEqual(rows[0]['status'],'completed')
            self.assertTrue(all(c['passed'] for c in report['checks']))
            self.assertFalse(report['current_tuple_accepted'])

    def test_selftest_cli_defined_and_retained_unsupported(self):
        spec=importlib.util.spec_from_file_location('owner24_cli',ROOT/'tests/evidence/phase6_d125_consumers_contract.py')
        GUARD=importlib.util.module_from_spec(spec);spec.loader.exec_module(GUARD)
        with RetainedSyntheticDirectory(dir=pathlib.Path(__file__).resolve().parents[2]/'build/phase6/d125-owner24-debug') as temp:
            output=pathlib.Path(temp)/'report.json'
            self.assertEqual(GUARD.main(['--engineering24-self-test','retained','--output',str(output)]),1)
            self.assertEqual(json.loads(output.read_bytes())['status'],'unsupported')


if __name__ == "__main__":
    unittest.main()
