#!/usr/bin/env python3
"""Temporary-ledger tests for bounded Phase 6 launch accounting."""
from __future__ import annotations

import importlib.util
import hashlib
import json
import pathlib
import sys
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
COORDINATOR_PATH = ROOT / "tests/fixtures/phase6_repairs.py"
LEDGER_PATH = ROOT / "evidence/phase6-repairs.json"


def load_coordinator():
    spec = importlib.util.spec_from_file_location("phase6_repairs_accounting_test", COORDINATOR_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Phase6AccountingContract(unittest.TestCase):
    def _d122_doc(self, value):
        a = self.coordinator.accounting
        value['d122_recovery_exception'] = {
            'schema':'phase6-d122-recovery-v1','status':'prospective-approved',
            'plan_scope':['06-18','06-14'],
            'approval_context_sha256':a.D122_APPROVAL_CONTEXT_SHA256,
            'plan_check_sha256':a.D122_PLAN_CHECK_SHA256,
            'prior_pea_cap_seconds':9000.0,'effective_pea_cap_seconds':a.D122_PEA_CAP_SECONDS,
            'historical_global_floor_seconds':13163.411,'historical_pea_floor_seconds':6812.984,
            'historical_offline_seconds':1813.235,'historical_offline_limit_seconds':1800.0,
            'partitions':{'observer_builds':300.0,'observer_proofs':90.0,
                '14_processes':1800.0,'14_other':400.251},
            'global_cap_seconds':43200.0,'other_target_cap_seconds':5400.0,
            'attempts_renewed':0,'processes_added':0,'acceptance_reduced':False}
        value['d122_accounting']={'other_charges':[]}
        value['d122_successor_manifest']={'status':'frozen','sha256':'d'*64,
            'source_identity':self.source_identity}
        value['phase6_accounting']['active_anchor'].update(
            monotonic_started_at=100.0,pea_charge=False,
            engineering_closeout_reserve_seconds=120.0)
        value['phase6_accounting']['scope_approval']={'id':'GW-06-16-observer-scope-approval','status':'approved'}
        return value

    def test_new_active_intervals_use_stable_boot_session_uuid(self):
        coordinator = load_coordinator()
        with mock.patch.object(coordinator.accounting.subprocess, 'check_output',
                               return_value='B1A2C3D4-5678-90AB-CDEF-1234567890AB\n') as run:
            self.assertEqual(coordinator.accounting.read_boot_identity(),
                             'boot-session:b1a2c3d4-5678-90ab-cdef-1234567890ab')
        run.assert_called_once_with(['sysctl', '-n', 'kern.bootsessionuuid'], text=True, timeout=5)

    def test_missing_current_d122_review_cannot_enter_partial_launcher(self):
        coordinator = load_coordinator()
        coordinator.LEDGER = self.ledger
        checker = mock.Mock()
        checker.verify_observer_bridge.side_effect=RuntimeError('d122-independent-observer-review-required')
        with mock.patch.object(coordinator, 'module', return_value=checker), \
             mock.patch.object(coordinator.accounting,'read_boot_identity',return_value=self.boot_identity), \
             mock.patch.object(coordinator.accounting,'begin_d122_other_interval',return_value={}), \
             mock.patch.object(coordinator.accounting,'finalize_d122_other_interval',return_value={}), \
             mock.patch.object(coordinator.accounting,'d122_other_interval_deadline',return_value={'deadline_monotonic':time.monotonic()+30}), \
             mock.patch.object(coordinator.accounting, 'authorize_launch') as authorize:
            with self.assertRaisesRegex(RuntimeError, 'd122-independent-observer-review-required'):
                coordinator.tank_continuation_once(pathlib.Path('unused'), pathlib.Path('unused'),
                    pathlib.Path('bridge.json'),pathlib.Path('review.md'),pathlib.Path('check.json'))
            authorize.assert_not_called()

    def test_preflight_includes_active_target_investigation(self):
        accounting = self.coordinator.accounting
        value = json.loads(self.ledger.read_text())
        anchor = value['phase6_accounting']['active_anchor']
        start = anchor['monotonic_started_at']
        report = accounting.preflight(self.ledger, monotonic_now=start + 10,
            boot_identity=self.boot_identity, require_active_anchor=True)
        _, closed_target = accounting._target_usage(value['records'], accounting.PEA_SIGNATURE)
        self.assertAlmostEqual(report['tank_pea_active_seconds_used'], closed_target + 10, places=3)

    def test_d121_resolver_grants_only_exact_pea_signature_9000_seconds(self):
        accounting = self.coordinator.accounting
        value = json.loads(self.ledger.read_text())
        self.assertEqual(accounting.effective_target_limit(value, accounting.PEA_SIGNATURE), 9000)
        self.assertEqual(accounting.effective_target_limit(value, "other:cpu:00ec32:4879:2"), 5400)
        value["d121_recovery_amendment"]["target_stop_signature"] = "other:cpu:00ec32:4879:2"
        with self.assertRaisesRegex(RuntimeError, "pea-cap-amendment-invalid"):
            accounting.effective_target_limit(value, accounting.PEA_SIGNATURE)

    def test_d122_resolver_is_exact_and_other_targets_keep_their_cap(self):
        a=self.coordinator.accounting
        value=self._d122_doc(json.loads(self.ledger.read_text()))
        self.assertEqual(a.effective_target_limit(value,a.PEA_SIGNATURE),9403.235)
        self.assertEqual(a.effective_target_limit(value,'other:cpu:00ec32:4879:2'),5400)
        for field,wrong in [('effective_pea_cap_seconds',9403.236),('historical_offline_seconds',1800.0),
                            ('processes_added',1),('acceptance_reduced',True)]:
            bad=json.loads(json.dumps(value));bad['d122_recovery_exception'][field]=wrong
            with self.assertRaisesRegex(RuntimeError,'d122-recovery-exception-invalid'):
                a.effective_target_limit(bad,a.PEA_SIGNATURE)

    def test_d122_observer_proofs_use_exact_partition_and_no_launcher_is_fake(self):
        a=self.coordinator.accounting
        value=self._d122_doc(json.loads(self.ledger.read_text()))
        value['stack_observer_manifest']={'status':'frozen','sha256':'d'*64,
            'source_identity':self.source_identity}
        self.ledger.write_text(json.dumps(value))
        launched=[]
        for purpose in a.OBSERVER_PROOF_PURPOSES:
            case=purpose
            with mock.patch.object(a.time,'monotonic',side_effect=[100.0,100.0,130.0]):
                result=a.authorize_observer_activity(self.ledger,purpose=purpose,plan='06-18',case=case,
                    source_identity=self.source_identity,current_source_identity=self.source_identity,
                    binary_identity='b'*64,command_identity='c'*64,manifest_sha256='d'*64,
                    launcher=lambda row: launched.append(row['record_id']) or {'fake_only':True},
                    boot_identity=self.boot_identity,allowed_root=pathlib.Path(self.temp.name))
            self.assertEqual(result,{'fake_only':True})
        self.assertEqual(len(launched),3)
        updated=json.loads(self.ledger.read_text())
        self.assertEqual(a.d122_partition_spent(updated,'observer_proofs'),90.0)
        self.assertEqual(a.effective_target_limit(updated,a.PEA_SIGNATURE),9403.235)
        before=self.ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError,'observer-purpose-already-spent'):
            a.authorize_observer_activity(self.ledger,purpose='stack-observer-native-1',plan='06-18',
                case='stack-observer-native-1',source_identity=self.source_identity,
                current_source_identity=self.source_identity,binary_identity='b'*64,
                command_identity='c'*64,manifest_sha256='d'*64,
                launcher=lambda row:self.fail('duplicate must be denied'),boot_identity=self.boot_identity,
                allowed_root=pathlib.Path(self.temp.name))
        self.assertEqual(before,self.ledger.read_bytes())

    def test_d122_build_partition_equality_and_protected_global_reserve(self):
        a=self.coordinator.accounting
        value=self._d122_doc(json.loads(self.ledger.read_text()))
        value['stack_observer_manifest']={'status':'frozen','sha256':'d'*64,
            'source_identity':self.source_identity}
        # Equality admits the 300-second build only while all 2,320.251 future
        # process/other/closeout seconds remain protected.
        base=a._closed_seconds(value['phase6_accounting'])
        need=300.0+1800.0+400.251+120.0
        value['phase6_accounting']['closed_intervals']=[{'id':'fake-history','active':True,
            'active_seconds':43200.0-base-need,'basis':'fake-clock-boundary'}]
        self.ledger.write_text(json.dumps(value))
        with mock.patch.object(a.time,'monotonic',side_effect=[100.0,100.0,400.0]):
            result=a.authorize_observer_activity(self.ledger,purpose='stack-observer-builds',
                plan='06-18',case=a.OBSERVER_BUILD_CASE,source_identity=self.source_identity,
                current_source_identity=self.source_identity,binary_identity='b'*64,
                command_identity='c'*64,manifest_sha256='d'*64,
                launcher=lambda row:{'fake_only':True},boot_identity=self.boot_identity,
                allowed_root=pathlib.Path(self.temp.name))
        self.assertEqual(result,{'fake_only':True})
        updated=json.loads(self.ledger.read_text())
        self.assertEqual(a.d122_partition_spent(updated,'observer_builds'),300.0)

    def test_d122_denies_old_plan_missing_reviews_concurrency_reboot_and_exhausted_reserve(self):
        a=self.coordinator.accounting
        value=self._d122_doc(json.loads(self.ledger.read_text()))
        value['stack_observer_manifest']={'status':'frozen','sha256':'d'*64,
            'source_identity':self.source_identity}
        args=dict(purpose='stack-observer-native-1',plan='06-18',case='stack-observer-native-1',
            source_identity=self.source_identity,current_source_identity=self.source_identity,
            binary_identity='b'*64,command_identity='c'*64,manifest_sha256='d'*64,
            launcher=lambda row:self.fail('denied admission called fake launcher'),
            boot_identity=self.boot_identity,allowed_root=pathlib.Path(self.temp.name))
        self.ledger.write_text(json.dumps(value));before=self.ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError,'active-clock-anchor-mismatch-or-reboot'):
            a.authorize_observer_activity(self.ledger,**{**args,'boot_identity':'other-boot'})
        self.assertEqual(before,self.ledger.read_bytes())
        value['records'].append({'record_id':'fake-active','record_type':'authorization-reservation',
            'observer_activity_kind':'proof','status':'reserved'})
        self.ledger.write_text(json.dumps(value));before=self.ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError,'observer-activity-already-active'):
            a.authorize_observer_activity(self.ledger,**args)
        self.assertEqual(before,self.ledger.read_bytes())
        value['records'].pop();base=a._closed_seconds(value['phase6_accounting'])
        value['phase6_accounting']['closed_intervals']=[{'id':'fake-exhaustion','active':True,
            'active_seconds':43200.0-base-100.0,'basis':'fake-exhausted-reserve'}]
        self.ledger.write_text(json.dumps(value));before=self.ledger.read_bytes()
        with mock.patch.object(a.time,'monotonic',side_effect=[100.0]):
            with self.assertRaisesRegex(RuntimeError,'d122-protected-global-reserve-insufficient'):
                a.authorize_observer_activity(self.ledger,**args)
        self.assertEqual(before,self.ledger.read_bytes())

    def test_d122_requires_actual_bridge_review_before_14_authorization(self):
        a=self.coordinator.accounting
        value=self._d122_doc(json.loads(self.ledger.read_text()))
        value['tank_proof_revalidation']={'status':'passed','source_identity':self.source_identity,
            'binary_identity':'b'*64,'contract_identity':'c'}
        self.ledger.write_text(json.dumps(value));before=self.ledger.read_bytes();launched=[]
        with self.assertRaisesRegex(RuntimeError,'d122-independent-observer-review-required'):
            a.authorize_launch(self.ledger,purpose='tank-continuation',plan='06-14',
                case='tank-pea-continuation-1',source_identity=self.source_identity,
                current_source_identity=self.source_identity,contract_identity='c',
                target_signature=a.PEA_SIGNATURE,launcher=lambda row:launched.append(row),
                boot_identity=self.boot_identity,allowed_root=pathlib.Path(self.temp.name))
        self.assertEqual(launched,[]);self.assertEqual(before,self.ledger.read_bytes())

    def test_d122_other_interval_is_measured_once_and_charged_to_pea(self):
        a=self.coordinator.accounting
        value=self._d122_doc(json.loads(self.ledger.read_text()))
        value['phase6_accounting']['active_anchor']['monotonic_started_at']=0.0
        self.ledger.write_text(json.dumps(value))
        with mock.patch.object(a.time,'monotonic',side_effect=[100.0,100.0,100.0,130.0,130.0,130.0]):
            a.begin_d122_other_interval(self.ledger,purpose='tank-preflight',interval_id='fake-preflight',
                source_identity=self.source_identity,boot_identity=self.boot_identity,
                allowed_root=pathlib.Path(self.temp.name))
            row=a.finalize_d122_other_interval(self.ledger,interval_id='fake-preflight',status='interrupted',
                boot_identity=self.boot_identity,allowed_root=pathlib.Path(self.temp.name))
        self.assertEqual(row['status'],'interrupted');self.assertEqual(row['seconds'],30.0)
        current=json.loads(self.ledger.read_text())
        self.assertEqual(a.d122_partition_spent(current,'14_other'),30.0)
        self.assertEqual(a.preflight(self.ledger)['tank_pea_active_seconds_used'],
            round(a._target_usage(current['records'],a.PEA_SIGNATURE)[1]+30.0,3))
        with self.assertRaisesRegex(RuntimeError,'d122-other-interval-replay'):
            a.begin_d122_other_interval(self.ledger,purpose='tank-preflight',interval_id='fake-preflight',
                source_identity=self.source_identity,boot_identity=self.boot_identity,
                allowed_root=pathlib.Path(self.temp.name))

    def test_d122_other_reserve_equality_epsilon_and_source_boot_replay_guards(self):
        a=self.coordinator.accounting;baseline=json.loads(self.ledger.read_text())
        for spent,admitted in ((280.251,False),(280.250,True)):
            with self.subTest(spent=spent):
                value=self._d122_doc(json.loads(json.dumps(baseline)))
                value['phase6_accounting']['active_anchor']['monotonic_started_at']=0.0
                value['d122_accounting']['other_charges']=[{'interval_id':'prior','purpose':'tank-preflight',
                    'seconds':spent,'status':'completed'}]
                self.ledger.write_text(json.dumps(value))
                with mock.patch.object(a.time,'monotonic',return_value=100.0):
                    if admitted:
                        a.begin_d122_other_interval(self.ledger,purpose='tank-preflight',interval_id='edge',
                            source_identity=self.source_identity,boot_identity=self.boot_identity,
                            allowed_root=pathlib.Path(self.temp.name))
                    else:
                        with self.assertRaisesRegex(RuntimeError,'d122-other-reserve-insufficient'):
                            a.begin_d122_other_interval(self.ledger,purpose='tank-preflight',interval_id='edge',
                                source_identity=self.source_identity,boot_identity=self.boot_identity,
                                allowed_root=pathlib.Path(self.temp.name))
                if admitted:
                    with self.assertRaisesRegex(RuntimeError,'boot-session-changed'):
                        a.finalize_d122_other_interval(self.ledger,interval_id='edge',boot_identity='other-boot',
                            allowed_root=pathlib.Path(self.temp.name))
                    with self.assertRaisesRegex(RuntimeError,'d122-other-source-identity-stale'):
                        with mock.patch.object(a,'source_identity',return_value='0'*64):
                            a.finalize_d122_other_interval(self.ledger,interval_id='edge',boot_identity=self.boot_identity,
                                allowed_root=pathlib.Path(self.temp.name))
                    with mock.patch.object(a.time,'monotonic',return_value=130.0):
                        a.finalize_d122_other_interval(self.ledger,interval_id='edge',boot_identity=self.boot_identity,
                            allowed_root=pathlib.Path(self.temp.name))
                    with self.assertRaisesRegex(RuntimeError,'d122-other-interval-replay'):
                        a.finalize_d122_other_interval(self.ledger,interval_id='edge',boot_identity=self.boot_identity,
                            allowed_root=pathlib.Path(self.temp.name))

    def test_d122_active_other_deadline_tracks_live_bucket_headroom(self):
        a=self.coordinator.accounting;value=self._d122_doc(json.loads(self.ledger.read_text()))
        value['phase6_accounting']['active_anchor']['monotonic_started_at']=0.0
        self.ledger.write_text(json.dumps(value))
        with mock.patch.object(a.time,'monotonic',return_value=100.0):
            a.begin_d122_other_interval(self.ledger,purpose='independent-final-review',interval_id='review-clock',
                source_identity=self.source_identity,boot_identity=self.boot_identity,
                allowed_root=pathlib.Path(self.temp.name))
        deadline=a.d122_other_interval_deadline(self.ledger,interval_id='review-clock',boot_identity=self.boot_identity,
            monotonic_now=150.0,allowed_root=pathlib.Path(self.temp.name))
        self.assertEqual(deadline['active_elapsed_seconds'],50.0)
        self.assertEqual(deadline['remaining_other_seconds'],230.251)
        self.assertEqual(deadline['allowed_seconds'],230.251)
        self.assertEqual(deadline['deadline_monotonic'],380.251)

    def test_d122_tank_and_two_controls_charge_actual_process_wall_once(self):
        a=self.coordinator.accounting;value=self._d122_doc(json.loads(self.ledger.read_text()))
        value['phase6_accounting']['active_anchor']['monotonic_started_at']=0.0
        value['d122_observer_bridge_binding']={'status':'independently-accepted','bridge_sha256':'a'*64,
            'review_sha256':'b'*64,'trusted_handoff_sha256':'c'*64}
        value['tank_proof_revalidation']={'status':'passed','source_identity':self.source_identity,
            'binary_identity':'d'*64,'contract_identity':'a'*64}
        self.ledger.write_text(json.dumps(value));clock=[100,100,100,130,140,140,140,170,180,180,180,210]
        with mock.patch.object(a.time,'monotonic',side_effect=clock):
            a.authorize_launch(self.ledger,purpose='tank-continuation',plan='06-14',
                case=a.TANK_CONTINUATION_CASE,source_identity=self.source_identity,
                current_source_identity=self.source_identity,contract_identity='a'*64,
                target_signature=a.PEA_SIGNATURE,launcher=lambda row:{'fake':True},
                boot_identity=self.boot_identity,allowed_root=pathlib.Path(self.temp.name))
            current=json.loads(self.ledger.read_text());tank=next(r for r in current['records'] if r.get('purpose')=='tank-continuation')
            current['current_tank_continuation_receipt']={'status':'captured','record_id':tank['record_id'],
                'purpose':'tank-continuation','plan':'06-14','source_identity':self.source_identity,
                'contract_identity':'a'*64,'capture_sha256':'e'*64}
            self.ledger.write_text(json.dumps(current))
            for case in a.TANK_CONTINUATION_CONTROLS:
                a.authorize_launch(self.ledger,purpose='tank-continuation-control',plan='06-14',case=case,
                    source_identity=self.source_identity,current_source_identity=self.source_identity,
                    contract_identity='a'*64,target_signature=None,launcher=lambda row:{'fake':True},
                    boot_identity=self.boot_identity,allowed_root=pathlib.Path(self.temp.name))
        final=json.loads(self.ledger.read_text());rows=[r for r in final['records'] if r.get('plan')=='06-14']
        self.assertEqual([r['process_active_seconds'] for r in rows],[30.0,30.0,30.0])
        self.assertEqual([r['new_target_attempts'] for r in rows],[1,0,0])
        self.assertEqual(a.d122_partition_spent(final,'14_processes'),90.0)
        self.assertEqual(a.d122_control_process_spent(final),60.0)
        self.assertEqual(a.preflight(self.ledger)['tank_pea_active_seconds_used'],
            round(a._target_usage(final['records'],a.PEA_SIGNATURE)[1]+60.0,3))
        total=a.preflight(self.ledger,monotonic_now=210.0,boot_identity=self.boot_identity,require_active_anchor=True)
        self.assertEqual(total['cumulative_seconds_including_current'],
            round(a._closed_seconds(final['phase6_accounting'])+210.0,3))

    def test_control_stream_symlink_injected_after_fake_launch_is_not_followed(self):
        coordinator=self.coordinator
        with tempfile.TemporaryDirectory(prefix='d122-control-toctou-',dir=ROOT/'build') as directory:
            root=pathlib.Path(directory);build=root/'build';client=build/'tools/session/gw_headless'
            client.parent.mkdir(parents=True);client.write_bytes(b'fake client')
            victim=root/'outside.raw';victim.write_bytes(b'preserve me')
            def fake_run(command,**_kwargs):
                report=pathlib.Path(command[command.index('--report')+1]);raw=report.parent/'driver.stdout.raw'
                raw.symlink_to(victim)
                return type('Result',(),{'stdout':b'captured prefix','stderr':b'','returncode':0})()
            fake_runner=type('Runner',(),{'bounded_run':staticmethod(fake_run),
                'BoundedProcessError':type('BoundedProcessError',(RuntimeError,),{})})
            with mock.patch.object(coordinator,'module',return_value=fake_runner):
                with self.assertRaisesRegex(RuntimeError,'raw-stream-collision-after-launch'):
                    coordinator._tank_control_driver(build,1,'a'*64,self.source_identity)
            self.assertEqual(victim.read_bytes(),b'preserve me')
            raw=build/'phase6/pea-controls/repetition-1/driver.stdout.raw'
            self.assertTrue(raw.is_symlink())

    def test_planned_task1_continuation_cli_accepts_review_inputs_with_fake_handler(self):
        coordinator=self.coordinator
        argv=['phase6_repairs.py','--tank-continuation-once','--bridge','evidence/bridge.json',
            '--proof-review','.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-18-PROOF-REVIEW.md',
            '--review-check','evidence/review-check.json',
            '--build','build/phase6','--output','evidence/phase6-tank-continuation.json']
        with mock.patch.object(sys,'argv',argv),mock.patch.object(coordinator,'tank_continuation_once',return_value=0) as handler:
            self.assertEqual(coordinator.main(),0)
        handler.assert_called_once()

    def test_preflight_applies_d121_pea_limit(self):
        accounting = self.coordinator.accounting
        value = json.loads(self.ledger.read_text())
        _, used = accounting._target_usage(value["records"], accounting.PEA_SIGNATURE)
        report = accounting.preflight(self.ledger)
        self.assertEqual(report["tank_pea_active_seconds_remaining"], round(9000 - used, 3))

    def _prepare_observer_manifest(self):
        value = json.loads(self.ledger.read_text())
        value["phase6_accounting"]["scope_approval"] = {"id": "GW-06-16-observer-scope-approval", "status": "approved"}
        value["phase6_accounting"]["active_anchor"]["offline_remaining_at_anchor_seconds"] = 962.178
        self.ledger.write_text(json.dumps(value))
        manifest = pathlib.Path(self.temp.name) / "observer-manifest.json"
        manifest.write_text('{"proofs":["stack-observer-native-1","stack-observer-sanitize-1","stack-observer-hooks-off-1"]}\n')
        frozen = self.coordinator.freeze_observer_manifest(
            manifest, ledger_path=self.ledger, boot_identity=self.boot_identity,
            allowed_root=pathlib.Path(self.temp.name))
        return frozen

    def test_observer_activity_is_manifest_bound_serial_fake_and_spent_once(self):
        frozen = self._prepare_observer_manifest()
        purposes = self.coordinator.accounting.OBSERVER_PROOF_PURPOSES
        calls = []
        for purpose, case in purposes.items():
            def fake_launcher(row):
                stored = self.coordinator.accounting._load(self.ledger, pathlib.Path(self.temp.name))["records"][-1]
                self.assertEqual(stored["status"], "reserved")
                self.assertEqual(stored["manifest_sha256"], frozen["sha256"])
                self.assertIsNone(stored["target_stop_signature"])
                self.assertEqual(stored["new_target_attempts"], 0)
                calls.append(row["record_id"])
                return {"fake_only": True}
            result = self.coordinator.authorize_observer_activity(
                purpose=purpose, plan="06-17", case=case, source_identity=self.source_identity,
                binary_identity="b" * 64, command_identity="c" * 64,
                manifest_sha256=frozen["sha256"], ledger_path=self.ledger,
                launcher=fake_launcher, boot_identity=self.boot_identity,
                allowed_root=pathlib.Path(self.temp.name))
            self.assertEqual(result, {"fake_only": True})
        self.assertEqual(len(calls), 3)
        rows = [row for row in json.loads(self.ledger.read_text())["records"]
                if row.get("observer_activity_kind") == "proof"]
        self.assertEqual([row["status"] for row in rows], ["completed"] * 3)
        self.assertTrue(all(row["new_target_attempts"] == 0 for row in rows))

    def test_observer_denies_unapproved_stale_alias_fourth_and_bad_clock_before_fake(self):
        frozen = self._prepare_observer_manifest()
        accounting = self.coordinator.accounting
        args = dict(purpose="stack-observer-native-1", plan="06-17",
            case="stack-observer-native-1", source_identity=self.source_identity,
            binary_identity="b" * 64, command_identity="c" * 64,
            manifest_sha256=frozen["sha256"], ledger_path=self.ledger,
            launcher=lambda row: self.fail("denied path called launcher"),
            boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name))
        before = self.ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "observer-proof-purpose-denied"):
            self.coordinator.authorize_observer_activity(**{**args, "purpose": "stack-observer-native-1-alias"})
        self.assertEqual(self.ledger.read_bytes(), before)
        with self.assertRaisesRegex(RuntimeError, "active-clock-anchor-mismatch-or-reboot"):
            self.coordinator.authorize_observer_activity(**{**args, "boot_identity": "wrong-boot"})
        self.assertEqual(self.ledger.read_bytes(), before)
        value = json.loads(self.ledger.read_text())
        value["phase6_accounting"]["scope_approval"]["status"] = "denied"
        self.ledger.write_text(json.dumps(value))
        denied = self.ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "observer-scope-approval-required"):
            self.coordinator.authorize_observer_activity(**args)
        self.assertEqual(self.ledger.read_bytes(), denied)

    def test_observer_exact_offline_watchdog_headroom_is_admitted(self):
        frozen = self._prepare_observer_manifest()
        value = json.loads(self.ledger.read_text())
        value["phase6_accounting"]["active_anchor"].update(
            monotonic_started_at=100.0, offline_remaining_at_anchor_seconds=40.0)
        self.ledger.write_text(json.dumps(value))
        with mock.patch.object(self.coordinator.accounting.time, "monotonic", return_value=110.0):
            result = self.coordinator.authorize_observer_activity(
                purpose="stack-observer-native-1", plan="06-17", case="stack-observer-native-1",
                source_identity=self.source_identity, binary_identity="b" * 64,
                command_identity="c" * 64, manifest_sha256=frozen["sha256"],
                ledger_path=self.ledger, launcher=lambda row: {"exact_headroom": True},
                boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name))
        self.assertEqual(result, {"exact_headroom": True})

    def test_observer_offline_watchdog_minus_equal_plus_one_second(self):
        frozen = self._prepare_observer_manifest()
        baseline = self.ledger.read_bytes()
        outcomes = []
        for remaining, admitted in ((29.999, False), (30.0, True), (30.001, True)):
            self.ledger.write_bytes(baseline)
            value = json.loads(baseline)
            value["phase6_accounting"]["active_anchor"].update(
                monotonic_started_at=100.0, offline_remaining_at_anchor_seconds=remaining)
            self.ledger.write_text(json.dumps(value))
            calls = []
            with mock.patch.object(self.coordinator.accounting.time, "monotonic", return_value=100.0):
                if admitted:
                    self.coordinator.authorize_observer_activity(
                        purpose="stack-observer-native-1", plan="06-17", case="stack-observer-native-1",
                        source_identity=self.source_identity, binary_identity="b" * 64,
                        command_identity="c" * 64, manifest_sha256=frozen["sha256"],
                        ledger_path=self.ledger, launcher=lambda row: calls.append(row) or {"ok": True},
                        boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name))
                else:
                    before = self.ledger.read_bytes()
                    with self.assertRaisesRegex(RuntimeError, "observer-offline-headroom-insufficient"):
                        self.coordinator.authorize_observer_activity(
                            purpose="stack-observer-native-1", plan="06-17", case="stack-observer-native-1",
                            source_identity=self.source_identity, binary_identity="b" * 64,
                            command_identity="c" * 64, manifest_sha256=frozen["sha256"],
                            ledger_path=self.ledger, launcher=lambda row: calls.append(row),
                            boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name))
                    self.assertEqual(self.ledger.read_bytes(), before)
            self.assertEqual(bool(calls), admitted)
            outcomes.append({"remaining": remaining, "admitted": admitted})
        self.assertEqual(outcomes, [{"remaining": 29.999, "admitted": False},
                                    {"remaining": 30.0, "admitted": True},
                                    {"remaining": 30.001, "admitted": True}])

    def setUp(self):
        self.production_digest = hashlib.sha256(LEDGER_PATH.read_bytes()).digest()
        self.original = json.loads(LEDGER_PATH.read_text())
        prefix_count = self.original['phase6_accounting']['immutable_prefix_count']
        self.original.pop("phase6_accounting", None)
        self.original.pop("stack_observer_manifest", None)
        self.original.pop("d122_recovery_exception", None)
        self.original.pop("d122_accounting", None)
        self.original.pop("d122_successor_manifest", None)
        self.original.pop("d122_observer_bridge_binding", None)
        self.original.pop("d123_recovery_policy", None)
        self.original.pop("d123_runs", None)
        self.original.pop("d124_recovery_policy", None)
        self.original.pop("d124_runs", None)
        # Each temporary-ledger case starts from the immutable pre-06-11
        # accounting history, not this plan's spent production reservations.
        self.original["records"] = self.original["records"][:prefix_count]
        self.temp = tempfile.TemporaryDirectory(prefix="phase6-accounting-")
        self.ledger = pathlib.Path(self.temp.name) / "ledger.json"
        self.ledger.write_text(json.dumps(self.original, sort_keys=True))
        self.coordinator = load_coordinator()
        self.coordinator.LEDGER = self.ledger
        self.source_identity = self.coordinator.accounting.source_identity(ROOT)
        self.boot_identity = "temporary-boot-identity"
        self.coordinator.accounting.initialize_ledger(
            self.ledger, monotonic_started_at=time.monotonic() - 10,
            boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name),
        )

    def tearDown(self):
        self.temp.cleanup()

    def _tank_receipt(self, *, checked=True, source=None, contract="frame-start-v1"):
        receipt={"status":"passed" if checked else "captured","independently_checked":checked,
            "record_id":"GW-06-AUTH-tank-continuation-tank-pea-continuation-1",
            "purpose":"tank-continuation","plan":"06-14","source_identity":source or self.source_identity,
            "contract_identity":contract,"capture_sha256":"a"*64}
        if checked:receipt.update(checked_receipt_sha256="b"*64,checker_sha256="c"*64)
        return receipt

    def test_independent_pea_reservation_is_not_blocked_by_rec_halt(self):
        """The REC binding halt must not deny the separately authorized Tank PEA lane."""
        self.assertTrue(self.original["halt"]["binding"])
        self.assertEqual(len(json.loads(self.ledger.read_text())["records"]), 34)
        source = self.source_identity
        observed = []

        def fake_launcher(reservation):
            current = json.loads(self.ledger.read_text())
            row = next(r for r in current["records"] if r["record_id"] == reservation["record_id"])
            self.assertEqual(row["status"], "reserved", "reservation must commit before launcher")
            observed.append(row)
            return {"launched": True}

        result = self.coordinator.authorize_capture(
            purpose="independent-pea", plan="06-11", case="tank-pea-regression",
            source_identity=source, current_source_identity=source,
            contract_identity="manufacturer-pea-v1",
            target_signature="tank-battle:cpu:00ec32:4879:2",
            ledger_path=self.ledger, launcher=fake_launcher,
            boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name),
        )
        self.assertEqual(result, {"launched": True})
        self.assertEqual(len(observed), 1)
        updated = json.loads(self.ledger.read_text())
        self.assertEqual(updated["records"][:34], self.original["records"])
        self.assertEqual(updated["records"][-1]["status"], "completed")

    def _deny(self, *, purpose, plan, case, source=None,
              current=None, target="tank-battle:cpu:00ec32:4879:2"):
        source = source or self.source_identity
        before = self.ledger.read_bytes()
        launched = []
        with self.assertRaises(Exception):
            self.coordinator.authorize_capture(
                purpose=purpose, plan=plan, case=case, source_identity=source,
                current_source_identity=current or source, contract_identity="contract-v1",
                target_signature=target, ledger_path=self.ledger,
                launcher=lambda row: launched.append(row),
                boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name),
            )
        self.assertEqual(launched, [], "denial must precede launcher")
        self.assertEqual(self.ledger.read_bytes(), before, "denial must not mutate ledger")

    def test_generic_capture_is_denied_without_mutation(self):
        self._deny(purpose="generic-capture", plan="06-11", case="tank-pea-regression")

    def test_tank_continuation_is_scoped_to_new_plan_case_and_watchdog(self):
        """Only the counted 06-14 continuation receives one serialized 600s reservation."""
        value = json.loads(self.ledger.read_text())
        value["tank_proof_revalidation"] = {"status": "passed", "source_identity": self.source_identity,
                                            "binary_identity": "b" * 64, "contract_identity": "proof-v1"}
        value["records"].append({"record_id": "existing-debug-floor", "record_type": "target-investigation-time",
                                 "target_stop_signature": self.coordinator.accounting.PEA_SIGNATURE,
                                 "active_seconds": 3124.95, "new_target_attempts": 0})
        self.ledger.write_text(json.dumps(value))
        calls = []

        def fake_launcher(row):
            current = json.loads(self.ledger.read_text())
            saved = next(r for r in current["records"] if r["record_id"] == row["record_id"])
            self.assertEqual(saved["status"], "reserved")
            self.assertEqual(saved["new_target_attempts"], 1)
            self.assertEqual(saved["process_count"], 1)
            self.assertEqual(saved["case_count"], 1)
            self.assertEqual(saved["limits"]["watchdog_seconds"], 600)
            self.assertGreaterEqual(saved["preflight_remaining_seconds"]["global_remaining_seconds"], 600)
            self.assertGreaterEqual(saved["preflight_remaining_seconds"]["target_remaining_seconds"], 600)
            calls.append(saved)
            raise InterruptedError("fake interrupted process")

        with self.assertRaisesRegex(InterruptedError, "fake interrupted process"):
            self.coordinator.authorize_capture(
                purpose="tank-continuation", plan="06-14", case="tank-pea-continuation-1",
                source_identity=self.source_identity, current_source_identity=self.source_identity,
                contract_identity="proof-v1", target_signature=self.coordinator.accounting.PEA_SIGNATURE,
                ledger_path=self.ledger, launcher=fake_launcher, boot_identity=self.boot_identity,
                allowed_root=pathlib.Path(self.temp.name))
        self.assertEqual(len(calls), 1)
        saved = json.loads(self.ledger.read_text())["records"][-1]
        self.assertEqual(saved["status"], "interrupted")
        self.assertEqual(saved["new_target_attempts"], 1)
        self.assertGreaterEqual(saved["target_active_seconds"], 0.0)

    def test_tank_watchdog_denies_when_target_headroom_is_short(self):
        value = json.loads(self.ledger.read_text())
        value["tank_proof_revalidation"] = {"status": "passed", "source_identity": self.source_identity,
                                            "binary_identity": "b" * 64, "contract_identity": "proof-v1"}
        value["records"].append({"record_id": "near-target-cap", "record_type": "target-investigation-time",
                                 "target_stop_signature": self.coordinator.accounting.PEA_SIGNATURE,
                                 "active_seconds": 4600, "new_target_attempts": 0})
        self.ledger.write_text(json.dumps(value))
        self._deny(purpose="tank-continuation", plan="06-14", case="tank-pea-continuation-1")

    def test_tank_watchdog_denies_when_global_headroom_is_short(self):
        value = json.loads(self.ledger.read_text())
        value["tank_proof_revalidation"] = {"status": "passed", "source_identity": self.source_identity,
                                            "binary_identity": "b" * 64, "contract_identity": "proof-v1"}
        value["phase6_accounting"]["closed_intervals"].append(
            {"id": "near-global-cap", "active": True,
             "active_seconds": 43200 - value["phase6_accounting"]["closed_baseline_seconds"] - 599.5})
        self.ledger.write_text(json.dumps(value))
        self._deny(purpose="tank-continuation", plan="06-14", case="tank-pea-continuation-1")

    def test_target_watchdog_accepts_exact_headroom_and_rejects_599_999(self):
        accounting = self.coordinator.accounting
        baseline = self.ledger.read_bytes()
        for target_used, accepted in ((8400.0, True), (8400.001, False), (8399.999, True)):
            with self.subTest(target_used=target_used):
                self.ledger.write_bytes(baseline)
                value = json.loads(baseline)
                value["tank_proof_revalidation"] = {"status": "passed", "source_identity": self.source_identity,
                    "binary_identity": "b" * 64, "contract_identity": "proof-v1"}
                existing = accounting._target_usage(value["records"], accounting.PEA_SIGNATURE)[1]
                value["records"].append({"record_id": f"target-fill-{target_used}",
                    "record_type": "target-investigation-time", "target_stop_signature": accounting.PEA_SIGNATURE,
                    "active_seconds": target_used-existing, "new_target_attempts": 0})
                value["phase6_accounting"]["active_anchor"]["monotonic_started_at"] = 1000.0
                self.ledger.write_text(json.dumps(value))
                launched = []
                with mock.patch.object(accounting.time, "monotonic", return_value=1000.0):
                    if accepted:
                        self.coordinator.authorize_capture(purpose="tank-continuation", plan="06-14",
                            case=accounting.TANK_CONTINUATION_CASE, source_identity=self.source_identity,
                            current_source_identity=self.source_identity, contract_identity="proof-v1",
                            target_signature=accounting.PEA_SIGNATURE, ledger_path=self.ledger,
                            launcher=lambda row: launched.append(row), boot_identity=self.boot_identity,
                            allowed_root=pathlib.Path(self.temp.name))
                    else:
                        with self.assertRaisesRegex(RuntimeError, "target-watchdog-headroom-insufficient"):
                            self.coordinator.authorize_capture(purpose="tank-continuation", plan="06-14",
                                case=accounting.TANK_CONTINUATION_CASE, source_identity=self.source_identity,
                                current_source_identity=self.source_identity, contract_identity="proof-v1",
                                target_signature=accounting.PEA_SIGNATURE, ledger_path=self.ledger,
                                launcher=lambda row: launched.append(row), boot_identity=self.boot_identity,
                                allowed_root=pathlib.Path(self.temp.name))
                self.assertEqual(len(launched), 1 if accepted else 0)

    def test_third_attempt_allowed_but_three_existing_attempts_deny(self):
        accounting = self.coordinator.accounting
        baseline = self.ledger.read_bytes()
        for existing_attempts, accepted in ((2, True), (3, False)):
            with self.subTest(existing_attempts=existing_attempts):
                self.ledger.write_bytes(baseline)
                value = json.loads(baseline)
                value["tank_proof_revalidation"] = {"status": "passed", "source_identity": self.source_identity,
                    "binary_identity": "b" * 64, "contract_identity": "proof-v1"}
                for index in range(existing_attempts):
                    value["records"].append({"record_id": f"spent-attempt-{index}",
                        "record_type": "authorization-reservation", "target_stop_signature": accounting.PEA_SIGNATURE,
                        "new_target_attempts": 1, "target_active_seconds": 0.0,
                        "monotonic_started_at": 0.0, "boot_identity": self.boot_identity, "status": "interrupted"})
                self.ledger.write_text(json.dumps(value))
                called = []
                if accepted:
                    self.coordinator.authorize_capture(purpose="tank-continuation", plan="06-14",
                        case=accounting.TANK_CONTINUATION_CASE, source_identity=self.source_identity,
                        current_source_identity=self.source_identity, contract_identity="proof-v1",
                        target_signature=accounting.PEA_SIGNATURE, ledger_path=self.ledger,
                        launcher=lambda row: called.append(row), boot_identity=self.boot_identity,
                        allowed_root=pathlib.Path(self.temp.name))
                else:
                    with self.assertRaisesRegex(RuntimeError, "target-attempt-budget-exhausted"):
                        self.coordinator.authorize_capture(purpose="tank-continuation", plan="06-14",
                            case=accounting.TANK_CONTINUATION_CASE, source_identity=self.source_identity,
                            current_source_identity=self.source_identity, contract_identity="proof-v1",
                            target_signature=accounting.PEA_SIGNATURE, ledger_path=self.ledger,
                            launcher=lambda row: called.append(row), boot_identity=self.boot_identity,
                            allowed_root=pathlib.Path(self.temp.name))
                self.assertEqual(len(called), 1 if accepted else 0)

    def test_conditional_control_is_denied_until_independent_current_receipt(self):
        self._deny(purpose="tank-continuation-control", plan="06-14", case="control-repeat-1", target=None)

    def test_watchdogs_are_sequential_and_charge_active_wall_once(self):
        accounting = self.coordinator.accounting
        value = json.loads(self.ledger.read_text())
        value["records"].append({"record_id": "existing-debug-floor", "record_type": "target-investigation-time",
                                 "target_stop_signature": accounting.PEA_SIGNATURE,
                                 "active_seconds": 3916.453, "new_target_attempts": 0})
        value["tank_proof_revalidation"] = {"status": "passed", "source_identity": self.source_identity,
                                            "binary_identity": "b" * 64, "contract_identity": "proof-v1"}
        value["phase6_accounting"]["active_anchor"]["monotonic_started_at"] = 1000.0
        self.ledger.write_text(json.dumps(value))
        clock = {"now": 1500.0}
        checks = []

        def launch(duration):
            def fake(row):
                current = json.loads(self.ledger.read_text())
                saved = next(r for r in current["records"] if r["record_id"] == row["record_id"])
                checks.append((saved["purpose"], saved["limits"]["watchdog_seconds"]))
                clock["now"] += duration
                return {"status": "ok"}
            return fake

        with mock.patch.object(accounting.time, "monotonic", side_effect=lambda: clock["now"]):
            accounting.authorize_launch(self.ledger, purpose="tank-continuation", plan="06-14",
                case="tank-pea-continuation-1", source_identity=self.source_identity,
                current_source_identity=self.source_identity, contract_identity="proof-v1",
                target_signature=accounting.PEA_SIGNATURE, launcher=launch(10),
                boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name))
            current = json.loads(self.ledger.read_text())
            current["current_tank_continuation_receipt"] = {
                "status": "captured", "independently_checked": False,
                "record_id":"GW-06-AUTH-tank-continuation-tank-pea-continuation-1",
                "purpose":"tank-continuation","plan":"06-14","capture_sha256":"d"*64,
                "source_identity": self.source_identity, "contract_identity": "control-v1"}
            self.ledger.write_text(json.dumps(current))
            for case, duration in (("control-repeat-1", 20), ("control-repeat-2", 20)):
                accounting.authorize_launch(self.ledger, purpose="tank-continuation-control", plan="06-14",
                    case=case, source_identity=self.source_identity, current_source_identity=self.source_identity,
                    contract_identity="control-v1", target_signature=None, launcher=launch(duration),
                    boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name))

        self.assertEqual(checks, [("tank-continuation", 600),
                                  ("tank-continuation-control", 600),
                                  ("tank-continuation-control", 600)])
        final = json.loads(self.ledger.read_text())
        used, process_seconds = accounting._target_usage(final["records"], accounting.PEA_SIGNATURE)
        active = accounting._active_elapsed(final["phase6_accounting"], clock["now"], self.boot_identity)
        overlap = sum(r["target_active_seconds"] for r in final["records"]
                      if r.get("target_stop_signature") == accounting.PEA_SIGNATURE and
                      r.get("record_type") == "authorization-reservation" and r["monotonic_started_at"] >= 1000)
        self.assertEqual(used, 1)
        self.assertEqual(process_seconds, 3926.453)
        self.assertAlmostEqual(process_seconds + active - overlap, 4466.453, places=6)
        self.assertAlmostEqual(5400 - (process_seconds + active - overlap), 933.547, places=6)

    def test_legacy_tank_continuation_alias_is_denied_before_launcher(self):
        self._deny(purpose="independent-pea", plan="06-11", case="tank-battle-continuation")

    def test_actual_capture_entry_cannot_route_rec_under_pea_permission(self):
        before = self.ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "capture-purpose-title-mismatch"):
            self.coordinator.capture(
                pathlib.Path(self.temp.name), "recursion94", 0xEC32,
                "tank-battle:cpu:00ec32:4879:2", "test", purpose="independent-pea",
                case="tank-pea-regression", contract_identity="manufacturer-pea-v1",
            )
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_actual_capture_entry_blocks_legacy_generic_route_search(self):
        before = self.ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "generic-capture-denied"):
            self.coordinator.capture(
                pathlib.Path(self.temp.name), "tank-battle", 0xEC32,
                "tank-battle:cpu:00ec32:4879:2", "legacy-default",
            )
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_capture_validation_failure_retains_native_report_in_spent_reservation(self):
        coordinator=self.coordinator
        temp_build=tempfile.TemporaryDirectory(prefix='fake-capture-',dir=ROOT/'build')
        self.addCleanup(temp_build.cleanup)
        build=pathlib.Path(temp_build.name)
        client=build/'tools/session/gw_headless'
        client.parent.mkdir(parents=True);client.write_bytes(b'fake-not-executable')
        native={'schema':'genewhip-route-native-v1','plan_fnv1a64':'fake-plan',
                'queue_high_water':0,'samples':[],'stop_reason':2,
                'last_boundary':None,'probe_boundary':None,
                'instruction_address':0x1234,'opcode':0x4840}
        def fake_client(_client,_command,processes,*,report,**_kwargs):
            processes.append({'bound_violation':False,'wall_seconds':0.01})
            report.write_text(json.dumps(native))
            return subprocess_result
        subprocess_result=type('FakeResult',(),{'returncode':1})()
        original_authorize=coordinator.authorize_capture
        def authorize_temporary(**kwargs):
            return original_authorize(**kwargs,ledger_path=self.ledger,
                                      allowed_root=pathlib.Path(self.temp.name))
        with mock.patch.object(coordinator,'authorize_capture',side_effect=authorize_temporary), \
             mock.patch.object(coordinator.accounting,'read_boot_identity',return_value=self.boot_identity), \
             mock.patch.object(coordinator.compiler,'compile_routes',return_value={
                 'routes':[{'fixture':'tank-battle','case':{'id':'full-route'},'identity':{}}]}), \
             mock.patch.object(coordinator.compiler,'lower_route',return_value=(b'fake-plan',{})), \
             mock.patch.object(coordinator.compiler,'plan_fingerprint',return_value='fake-plan'), \
             mock.patch.object(coordinator.contracts,'_run_client',side_effect=fake_client):
            with self.assertRaisesRegex(RuntimeError,'missing-instruction-boundary'):
                coordinator.capture(build,'tank-battle',0xec32,
                    coordinator.accounting.PEA_SIGNATURE,'fake-capture',
                    purpose='independent-pea',case='tank-pea-regression',
                    contract_identity='temporary-report-retention-test')
        row=json.loads(self.ledger.read_text())['records'][-1]
        self.assertEqual(row['status'],'interrupted')
        self.assertEqual(row['new_target_attempts'],1)
        self.assertIn('launcher_failure_receipt',row,'failed capture must retain native report before cleanup')
        failure=row['launcher_failure_receipt']
        self.assertEqual(failure['native_report'],native)
        self.assertEqual(failure['failure'],'missing-instruction-boundary')
        self.assertEqual(len(failure['processes']),1)
        self.assertFalse(list(build.glob('repairs-*')), 'temporary report cleaned only after receipt copied')

    def test_rec_validation_requires_current_proof(self):
        self._deny(purpose="rec-validation", plan="06-12", case="rec-validation")

    def _capture_report(self, native, *, launcher_parse_failure=False):
        """Use the actual capture consumer; no executable or guest is launched."""
        temp_build=tempfile.TemporaryDirectory(prefix='fake-boundary-',dir=ROOT/'build')
        self.addCleanup(temp_build.cleanup)
        build=pathlib.Path(temp_build.name)
        client=build/'tools/session/gw_headless'
        client.parent.mkdir(parents=True);client.write_bytes(b'fake-not-executable')
        def fake_client(_client,_command,processes,*,report,**_kwargs):
            processes.append({'bound_violation':False,'wall_seconds':0.01})
            report.write_text(native if isinstance(native,str) else json.dumps(native))
            if launcher_parse_failure:json.loads(report.read_text())
            return type('FakeResult',(),{'returncode':1})()
        with mock.patch.object(self.coordinator.compiler,'compile_routes',return_value={
                 'routes':[{'fixture':'tank-battle','case':{'id':'full-route'},'identity':{}}]}), \
             mock.patch.object(self.coordinator.compiler,'lower_route',return_value=(b'fake-plan',{})), \
             mock.patch.object(self.coordinator.compiler,'plan_fingerprint',return_value='fake-plan'), \
             mock.patch.object(self.coordinator.contracts,'_run_client',side_effect=fake_client):
            return self.coordinator._capture_reserved(build,'tank-battle',0xec32,
                self.coordinator.accounting.PEA_SIGNATURE,'offline-boundary-contract')

    def _boundary_report(self):
        def state(pc,tick,count):
            return {'pc':pc,'tick':tick,'instructions':count,'sr':0x2700,
                    'diagnostic_dropped':0,'a':[0]*8,'d':[0]*8,'spans':[]}
        pair={'before':state(0x1234,100,3),'after':state(0x1236,128,3),
              'instruction_address':0x1234,'opcode':0x4afc,'stop_reason':2,
              'target_tick':101,'returned_overshoot':27,'returned_undershoot':0,
              'retired':False,'fault_address':0}
        return {'schema':'genewhip-route-native-v1','plan_fnv1a64':'fake-plan',
                'queue_high_water':0,'samples':[],'stop_reason':2,'status':-1,
                'first_stop_tick':128,'final_tick':128,'fields':0,'active_ticks':0,
                'instruction_address':0x1234,'opcode':0x4afc,
                'last_boundary':pair,'probe_boundary':None}

    def test_earlier_stop_is_distinguished_from_missing_boundary(self):
        native=self._boundary_report()
        with self.assertRaisesRegex(self.coordinator.CaptureFailure,'probe-not-reached-before-stop') as caught:
            self._capture_report(native)
        receipt=caught.exception.receipt
        self.assertEqual(receipt['native_report'],native)
        self.assertEqual(receipt['boundary_disposition'],'stopped-before-requested-probe')
        self.assertEqual(receipt['native_report_sha256'],hashlib.sha256(
            receipt['native_report_raw'].encode()).hexdigest())
        self.assertEqual(len(receipt['processes']),1)

    def test_reached_probe_succeeds_but_inconsistent_stop_still_fails(self):
        native=self._boundary_report()
        probe=json.loads(json.dumps(native['last_boundary']))
        probe.update(instruction_address=0xec32,opcode=0x4879,stop_reason=0,retired=True)
        probe['before'].update(pc=0xec32,tick=1,instructions=0)
        probe['after'].update(pc=0xec38,tick=141,instructions=1)
        probe.update(target_tick=2,returned_overshoot=139)
        native['probe_boundary']=probe
        self.assertEqual(self._capture_report(native)['status'],'observed-stop')
        for key,bad in (('instruction_address',0x1236),('opcode',0x4e71),
                        ('stop_reason',3),('first_stop_tick',127)):
            with self.subTest(field=key):
                changed=json.loads(json.dumps(native));changed[key]=bad
                with self.assertRaisesRegex(self.coordinator.CaptureFailure,'stop-boundary-metadata-mismatch'):
                    self._capture_report(changed)

    def test_source_identity_binds_actual_report_producers(self):
        with tempfile.TemporaryDirectory(prefix='source-closure-') as directory:
            root=pathlib.Path(directory)
            for path in ('tools/session/route_controller.c','tools/session/session.c',
                         'tools/headless/main.c','tools/desktop/main_sdl.c',
                         'include/genewhip/genewhip.h','CMakeLists.txt'):
                file=root/path;file.parent.mkdir(parents=True,exist_ok=True);file.write_text('before')
                before=self.coordinator.accounting.source_identity(root)
                file.write_text('after')
                self.assertNotEqual(before,self.coordinator.accounting.source_identity(root),path)

    def test_malformed_raw_report_is_retained_before_temporary_cleanup(self):
        raw='{"schema":"genewhip-route-native-v1","samples":['
        for launcher_failure in (False,True):
            with self.subTest(launcher_parse_failure=launcher_failure):
                with self.assertRaises(self.coordinator.CaptureFailure) as caught:
                    self._capture_report(raw,launcher_parse_failure=launcher_failure)
                receipt=caught.exception.receipt
                self.assertIsNone(receipt['native_report'])
                self.assertEqual(receipt['native_report_raw'],raw)
                self.assertEqual(receipt['native_report_sha256'],hashlib.sha256(raw.encode()).hexdigest())
        # Exercise the actual subprocess wrapper's decode-failure path using
        # an authored Python process, never an emulator or game.
        report=pathlib.Path(self.temp.name)/'malformed.json';runs=[];streams={}
        command=[sys.executable,'-c',
                 'import pathlib,sys;print("retained stdout");print("retained stderr",file=sys.stderr);pathlib.Path(sys.argv[1]).write_text("{")',
                 str(report)]
        with self.assertRaises(ValueError):
            self.coordinator.contracts._run_client(pathlib.Path(sys.executable),command,runs,
                report=report,timeout=5,retained_streams=streams)
        self.assertEqual(streams['stdout']['text'],'retained stdout\n')
        self.assertEqual(streams['stderr']['text'],'retained stderr\n')
        self.assertFalse(streams['stdout']['truncated'])
        self.assertEqual(streams['stdout']['sha256'],hashlib.sha256(b'retained stdout\n').hexdigest())
        self.assertEqual(len(runs),1)

    def test_joint_qualification_requires_current_12_and_11_outcomes(self):
        self._deny(purpose="joint-qualification", plan="06-09", case="joint-qualification")

    def test_stale_source_identity_is_denied_without_mutation(self):
        self._deny(purpose="independent-pea", plan="06-11", case="tank-pea-regression",
                   source="a" * 40, current="c" * 40)

    def test_duplicate_reservation_is_rejected(self):
        source = self.source_identity
        args = dict(purpose="independent-pea", plan="06-11", case="tank-pea-regression",
                    source_identity=source, current_source_identity=source,
                    contract_identity="manufacturer-pea-v1",
                    target_signature="tank-battle:cpu:00ec32:4879:2",
                    ledger_path=self.ledger, launcher=lambda row: "done",
                    boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name))
        self.coordinator.authorize_capture(**args)
        before = self.ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "duplicate-reservation"):
            self.coordinator.authorize_capture(**args)
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_interrupted_launch_remains_spent(self):
        source = self.source_identity
        args = dict(purpose="independent-pea", plan="06-11", case="tank-pea-regression",
                    source_identity=source, current_source_identity=source,
                    contract_identity="manufacturer-pea-v1",
                    target_signature="tank-battle:cpu:00ec32:4879:2",
                    ledger_path=self.ledger,
                    launcher=lambda row: (_ for _ in ()).throw(RuntimeError("fake-interruption")),
                    boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name))
        with self.assertRaisesRegex(RuntimeError, "fake-interruption"):
            self.coordinator.authorize_capture(**args)
        rows = json.loads(self.ledger.read_text())["records"]
        self.assertEqual(rows[-1]["status"], "interrupted")
        self.assertEqual(rows[-1]["new_target_attempts"], 1)
        self.assertGreaterEqual(rows[-1]["target_active_seconds"], 0)
        with self.assertRaisesRegex(RuntimeError, "duplicate-reservation"):
            self.coordinator.authorize_capture(**args)

    def test_tests_never_write_production_ledger(self):
        self.assertEqual(hashlib.sha256(LEDGER_PATH.read_bytes()).digest(), self.production_digest)

    def _authorized(self, launcher, *, ledger=None, case="tank-pea-regression"):
        path = ledger or self.ledger
        source = self.source_identity
        return self.coordinator.authorize_capture(
            purpose="independent-pea", plan="06-11", case=case,
            source_identity=source, current_source_identity=source,
            contract_identity="manufacturer-pea-v1",
            target_signature="tank-battle:cpu:00ec32:4879:2",
            ledger_path=path, launcher=launcher,
            boot_identity=self.boot_identity,
            allowed_root=pathlib.Path(self.temp.name),
        )

    def test_atomic_finalize_rejects_stale_concurrent_writer(self):
        def competing_writer(_reservation):
            value = json.loads(self.ledger.read_text())
            value["concurrent_change"] = "stale-writer"
            self.ledger.write_text(json.dumps(value))
            return "done"

        with self.assertRaisesRegex(RuntimeError, "stale-ledger-writer"):
            self._authorized(competing_writer)

    def test_atomic_finalize_rejects_changed_historical_objects(self):
        def history_mutator(_reservation):
            value = json.loads(self.ledger.read_text())
            value["records"][0]["status"] = "rewritten"
            self.ledger.write_text(json.dumps(value))
            return "done"

        with self.assertRaisesRegex(RuntimeError, "immutable-history-changed"):
            self._authorized(history_mutator)

    def test_symlink_ledger_path_is_rejected(self):
        outside = pathlib.Path(self.temp.name) / "outside.json"
        outside.write_text(json.dumps(self.original))
        link = pathlib.Path(self.temp.name) / "ledger-link.json"
        link.symlink_to(outside)
        before = outside.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "ledger-path-symlink-denied"):
            self._authorized(lambda row: "must-not-run", ledger=link)
        self.assertEqual(outside.read_bytes(), before)

    def test_ledger_path_escape_is_rejected(self):
        outside = pathlib.Path(self.temp.name).parent / "phase6-accounting-outside.json"
        outside.write_text(json.dumps(self.original))
        try:
            with self.assertRaisesRegex(RuntimeError, "ledger-path-escape-denied"):
                self._authorized(lambda row: "must-not-run", ledger=outside)
        finally:
            outside.unlink(missing_ok=True)

    def test_nonfinite_cumulative_time_blocks_authorization(self):
        value = json.loads(self.ledger.read_text())
        value["phase6_accounting"]["active_anchor"]["monotonic_started_at"] = float("nan")
        self.ledger.write_text(json.dumps(value))
        before = self.ledger.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "monotonic-start-invalid"):
            self._authorized(lambda row: "must-not-run")
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_boolean_clock_counter_is_rejected(self):
        value = json.loads(self.ledger.read_text())
        value["phase6_accounting"]["active_anchor"]["monotonic_started_at"] = True
        self.ledger.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError, "monotonic-start-invalid"):
            self._authorized(lambda row: "must-not-run")

    def test_unsealed_nonfinite_and_boolean_cumulative_counters_are_rejected(self):
        for invalid in (float("nan"), True):
            value = dict(self.original)
            value["usage"] = dict(self.original["usage"])
            value["usage"]["cumulative_repair_seconds"] = invalid
            self.ledger.write_text(json.dumps(value))
            with self.assertRaisesRegex(RuntimeError, "closed-baseline-invalid"):
                self._authorized(lambda row: "must-not-run")

    def test_preflight_uses_closed_research_baseline_not_historical_usage(self):
        report = self.coordinator.accounting.preflight(self.ledger)
        self.assertEqual(report["closed_cumulative_seconds"], 7053.427)

    def test_active_time_limit_is_exhausted_before_launcher(self):
        value = json.loads(self.ledger.read_text())
        value["phase6_accounting"]["closed_intervals"].append(
            {"id": "exhausted", "active_seconds": 43200 - 7053.427, "active": True})
        self.ledger.write_text(json.dumps(value))
        before = self.ledger.read_bytes()
        launched = []
        with self.assertRaisesRegex(RuntimeError, "cumulative-active-time-exhausted"):
            self._authorized(lambda row: launched.append(row))
        self.assertEqual(launched, [])
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_interval_close_is_exactly_once_and_inactive_time_is_free(self):
        accounting = self.coordinator.accounting
        before = accounting.preflight(self.ledger)["closed_cumulative_seconds"]
        inactive = accounting.close_interval(
            self.ledger, interval_id="review-1", active=False,
            started_monotonic=None, closed_monotonic=None, boot_identity=None,
            allowed_root=pathlib.Path(self.temp.name),
        )
        self.assertEqual(inactive["active_seconds"], 0)
        self.assertEqual(accounting.preflight(self.ledger)["closed_cumulative_seconds"], before)
        with self.assertRaisesRegex(RuntimeError, "duplicate-interval-finalization"):
            accounting.close_interval(
                self.ledger, interval_id="review-1", active=False,
                started_monotonic=None, closed_monotonic=None, boot_identity=None,
                allowed_root=pathlib.Path(self.temp.name),
            )

    def test_active_interval_uses_monotonic_once_and_rejects_rollback(self):
        accounting = self.coordinator.accounting
        row = accounting.close_interval(
            self.ledger, interval_id="active-1", active=True,
            started_monotonic=100.0, closed_monotonic=125.25,
            boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name),
        )
        self.assertEqual(row["active_seconds"], 25.25)
        self.assertEqual(accounting.preflight(self.ledger)["closed_cumulative_seconds"], 7078.677)
        with self.assertRaisesRegex(RuntimeError, "duplicate-interval-finalization"):
            accounting.close_interval(
                self.ledger, interval_id="active-1", active=True,
                started_monotonic=100.0, closed_monotonic=125.25,
                boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name),
            )
        with self.assertRaisesRegex(RuntimeError, "active-clock-anchor-invalid"):
            accounting.close_interval(
                self.ledger, interval_id="rollback", active=True,
                started_monotonic=126.0, closed_monotonic=125.0,
                boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name),
            )

    def test_external_parent_interval_closes_once_and_restarts_anchor(self):
        anchor_path = pathlib.Path(self.temp.name) / "execution-anchor.json"
        self.ledger_value = json.loads(self.ledger.read_text())
        self.ledger_value["phase6_accounting"]["closed_intervals"].append(
            {"id": "already-closed-parent", "active": True, "active_seconds": 533.078})
        self.ledger.write_text(json.dumps(self.ledger_value))
        source = {"id": "GW-06-D120-execution", "monotonic_started_at": 100.0,
                  "prior_cumulative_seconds": 7586.505, "boot_identity": self.boot_identity}
        result = self.coordinator.accounting.close_external_interval(
            self.ledger, anchor_path, source_anchor=source, monotonic_now=160.0,
            boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name),
        )
        self.assertEqual(result["closed_interval"]["active_seconds"], 60.0)
        self.assertEqual(result["active_anchor"]["monotonic_started_at"], 160.0)
        self.assertEqual(json.loads(anchor_path.read_text()), result["active_anchor"])
        self.assertEqual(self.coordinator.accounting.preflight(self.ledger)["closed_cumulative_seconds"], 7646.505)
        with self.assertRaisesRegex(RuntimeError, "duplicate-interval-finalization"):
            self.coordinator.accounting.close_external_interval(
                self.ledger, anchor_path, source_anchor=source, monotonic_now=170.0,
                boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name),
            )

    def test_plan_anchor_close_charges_shared_wall_once_and_clears_anchor(self):
        accounting = self.coordinator.accounting
        value = json.loads(self.ledger.read_text())
        value["phase6_accounting"]["active_anchor"] = {
            "id": "GW-06-13-execution", "monotonic_started_at": 100.0,
            "boot_identity": self.boot_identity, "prior_cumulative_seconds": 7053.427}
        value["records"].append({"record_id": "target-process", "record_type": "authorization-reservation",
            "target_stop_signature": accounting.PEA_SIGNATURE, "target_active_seconds": 10.0,
            "new_target_attempts": 1, "monotonic_started_at": 110.0, "status": "completed"})
        self.ledger.write_text(json.dumps(value))
        anchor_path = pathlib.Path(self.temp.name) / "anchor.json"
        anchor = value["phase6_accounting"]["active_anchor"]
        anchor_path.write_text(json.dumps(anchor))
        closed = accounting.close_plan_anchor(self.ledger, anchor_path, monotonic_now=150.0,
            boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name))
        self.assertIsNone(closed["active_anchor"])
        self.assertEqual(closed["closed_interval"]["active_seconds"], 50.0)
        self.assertEqual(closed["target_investigation_seconds"], 40.0)
        final = json.loads(self.ledger.read_text())
        self.assertIsNone(final["phase6_accounting"]["active_anchor"])
        self.assertEqual(final["phase6_accounting"]["closed_intervals"][-1]["active_seconds"], 50.0)
        self.assertEqual(final["records"][-1]["active_seconds"], 40.0)
        self.assertEqual(json.loads(anchor_path.read_text())["status"], "closed-inactive-review")

    def test_rec_validation_requires_current_proof_and_checked_14_receipt(self):
        value = json.loads(self.ledger.read_text())
        value["current_frame_start_proof"] = {"status": "passed", "identity": "proof-v1"}
        value["current_tank_continuation_receipt"] = self._tank_receipt()
        self.ledger.write_text(json.dumps(value))
        called = []
        result = self.coordinator.authorize_capture(
            purpose="rec-validation", plan="06-12", case="rec-validation",
            source_identity=self.source_identity, current_source_identity=self.source_identity,
            contract_identity="frame-start-v1", target_signature=None,
            ledger_path=self.ledger, launcher=lambda row: called.append(row["status"]) or "reserved",
            boot_identity=self.boot_identity, allowed_root=pathlib.Path(self.temp.name),
        )
        self.assertEqual(result, "reserved")
        self.assertEqual(called, ["reserved"])

    def test_joint_qualification_accepts_only_current_11_and_12_outcomes(self):
        value = json.loads(self.ledger.read_text())
        value["current_frame_start_proof"] = {"status": "passed"}
        value["current_rec_validation"] = {"status": "resolved"}
        value["current_tank_continuation_receipt"] = self._tank_receipt()
        self.ledger.write_text(json.dumps(value))
        result = self.coordinator.authorize_capture(
            purpose="joint-qualification", plan="06-09", case="joint-qualification",
            source_identity=self.source_identity, current_source_identity=self.source_identity,
            contract_identity="joint-v1", target_signature=None, ledger_path=self.ledger,
            launcher=lambda row: row["status"], boot_identity=self.boot_identity,
            allowed_root=pathlib.Path(self.temp.name),
        )
        self.assertEqual(result, "reserved")

    def test_target_attempt_cap_is_separate_from_case_rows(self):
        value = json.loads(self.ledger.read_text())
        value["records"].extend({"record_id": f"old-{i}", "record_type": "probe-attempt",
                                 "target_stop_signature": "tank-battle:cpu:00ec32:4879:2"}
                                for i in range(3))
        self.ledger.write_text(json.dumps(value))
        before = self.ledger.read_bytes()
        launched = []
        with self.assertRaisesRegex(RuntimeError, "target-attempt-budget-exhausted"):
            self._authorized(lambda row: launched.append(row))
        self.assertEqual(launched, [])
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_target_active_time_cap_is_enforced_without_spending_a_case_row(self):
        value = json.loads(self.ledger.read_text())
        value["records"].append({"record_id": "spent-pea", "record_type": "authorization-reservation",
                                 "target_stop_signature": "tank-battle:cpu:00ec32:4879:2",
                                 "new_target_attempts": 1, "target_active_seconds": 9000,
                                 "status": "interrupted"})
        self.ledger.write_text(json.dumps(value))
        before = self.ledger.read_bytes()
        launched = []
        with self.assertRaisesRegex(RuntimeError, "target-time-budget-exhausted"):
            self._authorized(lambda row: launched.append(row))
        self.assertEqual(launched, [])
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_target_investigation_time_is_charged_before_launcher(self):
        value=json.loads(self.ledger.read_text())
        value['records'].append({'record_id':'investigation-wall',
            'record_type':'target-investigation-time',
            'target_stop_signature':self.coordinator.accounting.PEA_SIGNATURE,
            'active_seconds':9000,'new_target_attempts':0})
        self.ledger.write_text(json.dumps(value))
        before=self.ledger.read_bytes();launched=[]
        with self.assertRaisesRegex(RuntimeError,'target-time-budget-exhausted'):
            self._authorized(lambda row:launched.append(row))
        self.assertEqual(launched,[])
        self.assertEqual(self.ledger.read_bytes(),before)


class D123AccountingContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phase6-d123-accounting-")
        self.root = pathlib.Path(self.temp.name) / "repo"
        self.ledger = self.root / "evidence/phase6-repairs.json"
        self.boot = "boot-session:d123-test-boot"
        self.root.mkdir()
        value = json.loads(LEDGER_PATH.read_text())
        value.pop("d124_recovery_policy", None)
        value.pop("d124_runs", None)
        anchor = value["phase6_accounting"]["active_anchor"]
        anchor["id"] = "GW-06-D123-19-global-test"
        anchor["purpose"] = "d123-global-engineering"
        anchor["monotonic_started_at"] = 1000.0
        anchor["boot_identity"] = self.boot
        value["d123_recovery_policy"]["anchor_id"] = anchor["id"]
        value["d123_recovery_policy"]["boot_identity"] = self.boot
        for relative in (
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-19-PLAN.md",
            ".planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-D123-PLAN-CHECK.md",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / relative).read_bytes())
        # D123's approval binds the persistent contracts as they existed at
        # approval; D124 may append to OPERATING.md without rewriting history.
        for relative in (".planning/context/OPERATING.md",
                         ".planning/forensics/report-20261024-193248.md"):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            revision = "684fdd5bd4c3f6dc21a38498197f1d361ae66f8e"
            destination.write_bytes(subprocess.check_output(
                ["git", "show", f"{revision}:{relative}"], cwd=ROOT))
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        self.ledger.write_text(json.dumps(value, sort_keys=True))
        self.accounting = load_coordinator().accounting

    def tearDown(self):
        self.temp.cleanup()

    def _headroom(self, remaining):
        value = self.accounting._load(self.ledger, self.root)
        state = value["phase6_accounting"]
        current = self.accounting._closed_seconds(state)
        state["closed_intervals"].append({"id": "d123-test-headroom", "active": True,
            "active_seconds": 43200.0 - remaining - current})
        self.accounting._write(self.ledger, value)

    def _authorize(self, activity_id="d123-dev-99-case-native", *, boot=None, stage="diagnostic",
                   hypothesis="test hypothesis", relevant_change="test source delta", no_new_evidence=False,
                   launcher=None):
        import hashlib
        return self.accounting.authorize_d123_activity(self.ledger, activity_id=activity_id,
            stage=stage, exposure_seconds=30.0, boot_identity=boot or self.boot,
            project_root=self.root, launcher=launcher or (lambda _row: "ok"),
            hypothesis=hypothesis, relevant_change=relevant_change,
            evidence_identity=hashlib.sha256(relevant_change.encode()).hexdigest(),
            no_new_evidence=no_new_evidence)

    def test_d123_exact_protected_headroom_is_admitted_and_global_only(self):
        self._headroom(2350.251)
        launched = []
        with mock.patch.object(self.accounting.time, "monotonic", return_value=1000.0):
            result = self._authorize(launcher=lambda row: launched.append(row) or "ok")
        self.assertEqual(result, "ok")
        self.assertEqual(len(launched), 1)
        row = self.accounting._load(self.ledger, self.root)["d123_runs"][-1]
        self.assertEqual(row["status"], "completed")
        self.assertEqual(row["pea_charge_seconds"], 0.0)
        self.assertEqual(row["protected_14_seconds"], 2200.251)
        self.assertEqual(row["closeout_reserve_seconds"], 120.0)

    def test_d123_cap_plus_epsilon_denies_without_mutation_or_launch(self):
        self._headroom(2350.250)
        before = self.ledger.read_bytes()
        launched = []
        with mock.patch.object(self.accounting.time, "monotonic", return_value=1000.0):
            with self.assertRaisesRegex(RuntimeError, "d123-protected-global-reserve-insufficient"):
                self._authorize(launcher=lambda row: launched.append(row))
        self.assertEqual(launched, [])
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_d123_stale_boot_and_legacy_attempt_alias_are_denied(self):
        for activity, boot, expected in (
            ("d123-dev-99-stale-native", "boot-session:other", "d123-boot-identity-mismatch"),
            ("stack-observer-native-1", self.boot, "d123-activity-id-invalid"),
        ):
            launched = []
            with mock.patch.object(self.accounting.time, "monotonic", return_value=1000.0):
                with self.assertRaisesRegex(RuntimeError, expected):
                    self._authorize(activity, boot=boot, launcher=lambda row: launched.append(row))
            self.assertEqual(launched, [])

    def test_d123_missing_policy_checked_binding_and_concurrent_anchor_are_denied(self):
        baseline = self.ledger.read_bytes()
        cases = (
            (lambda value: value.pop("d123_recovery_policy"), "d123-policy-missing-or-invalid"),
            (lambda value: value["d123_recovery_policy"].update(plan_check_sha256="0" * 64),
             "d123-checked-plan-binding-mismatch"),
            (lambda value: value["phase6_accounting"]["active_anchor"].update(id="other-anchor"),
             "d123-active-anchor-mismatch"),
        )
        for mutate, expected in cases:
            self.ledger.write_bytes(baseline)
            value = json.loads(baseline)
            anchor = value["phase6_accounting"]["active_anchor"]
            anchor.update(id="GW-06-D123-19-global-test", monotonic_started_at=1000.0,
                boot_identity=self.boot)
            value["d123_recovery_policy"].update(anchor_id=anchor["id"], boot_identity=self.boot)
            mutate(value)
            self.accounting._write(self.ledger, value)
            before = self.ledger.read_bytes()
            launched = []
            with mock.patch.object(self.accounting.time, "monotonic", return_value=1000.0):
                with self.assertRaisesRegex(RuntimeError, expected):
                    self._authorize("d123-dev-99-authority-native", launcher=lambda row: launched.append(row))
            self.assertEqual(launched, [])
            self.assertEqual(self.ledger.read_bytes(), before)

    def test_d123_activity_id_is_create_once(self):
        with mock.patch.object(self.accounting.time, "monotonic", return_value=1000.0):
            self._authorize()
            before = self.ledger.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "d123-activity-id-spent"):
                self._authorize()
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_d123_repeat_failure_requires_change_and_two_empty_iterations_stop(self):
        value = self.accounting._load(self.ledger, self.root)
        value["d123_runs"].extend([
            {"activity_id": "d123-dev-98-first-native", "stage": "diagnostic", "status": "interrupted",
             "hypothesis": "test hypothesis", "relevant_change": "unchanged", "evidence_identity": "a" * 64},
            {"activity_id": "d123-dev-98-empty-a-native", "stage": "diagnostic", "status": "completed",
             "hypothesis": "no progress", "relevant_change": "same", "no_new_evidence": True},
            {"activity_id": "d123-dev-98-empty-b-native", "stage": "diagnostic", "status": "completed",
             "hypothesis": "no progress", "relevant_change": "same", "no_new_evidence": True},
        ])
        self.accounting._write(self.ledger, value)
        with mock.patch.object(self.accounting.time, "monotonic", return_value=1000.0):
            with self.assertRaisesRegex(RuntimeError, "d123-repeat-failure-without-relevant-change"):
                self._authorize("d123-dev-99-unchanged-native", relevant_change="unchanged")
            with self.assertRaisesRegex(RuntimeError, "d123-two-no-new-evidence-iterations"):
                self._authorize("d123-dev-99-empty-native", hypothesis="no progress",
                    relevant_change="same", no_new_evidence=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
