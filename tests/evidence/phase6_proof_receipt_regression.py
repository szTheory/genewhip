#!/usr/bin/env python3
"""Authored no-launch proof/receipt seam regressions; never production evidence.

Run with -I. All project imports occur after independent process denial. Bridge
recomputation is a named stub: this suite tests payload admission, not raw rows.
The actual verifier, ledger validation/lock/close and publishers run in synthetic
roots. --snapshot records the pre-repair implementations; --baseline selects them.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORK = ROOT / 'build/phase6/d125-proof-receipt-debug'
SOURCES = ('scripts/evidence/phase6_accounting.py',
           'tests/evidence/phase6_tank_continuation_contract.py')
SECTIONS = ['plan23-full-argv-and-later-stop-qualification-rows',
    'build-tool-cache-settings-and-current-binary-identities',
    'actual-report-predicate-and-raw-stream-denominator',
    'current-source-freeze-and-retained-component-disposition',
    'engineering-owner-counters-history-and-no-game-authority',
    'task1-g03-source-review-and-no-launch-guard-report',
    'proof-review-verifier-coverage-identity-and-findings-validation-source',
    'current-consumer-final-transaction-status-absent']
COUNTS = {'denied': 0, 'permitted': 0}

def denied(*args, **kwargs):
    COUNTS['denied'] += 1
    raise RuntimeError('regression-process-denied')

def audit(event, args):
    if event in ('subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'pty.spawn'):
        denied()

def install_denial():
    sys.addaudithook(audit)
    for module, names in ((subprocess, ('Popen', 'run', 'call', 'check_call', 'check_output')),
                          (os, ('system', 'popen', 'fork', 'forkpty', 'posix_spawn', 'posix_spawnp',
                                'spawnl', 'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve',
                                'spawnvp', 'spawnvpe', 'execl', 'execle', 'execlp', 'execlpe',
                                'execv', 'execve', 'execvp', 'execvpe'))):
        for name in names:
            if hasattr(module, name): setattr(module, name, denied)
    try: subprocess.run(['deliberately-unmocked-launch'])
    except RuntimeError as exc: assert str(exc) == 'regression-process-denied'
    else: raise AssertionError('preimport-denial-not-installed')

def load(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')

def finding(**changes):
    row={'severity':'low','classification':'observation','file':'synthetic.py',
         'line':'1','issue':'bounded observation','fix':'future named follow-up'}
    row.update(changes)
    return row

class Regression(unittest.TestCase):
    def setUp(self):
        # Retain every authored root/failed ledger for audit; never reuse it.
        self.root = pathlib.Path(tempfile.mkdtemp(prefix='proof-receipt-', dir=WORK))
        write(self.root/'case.json',{'test':self.id(),'synthetic_only':True})
        self.a = load('isolated_accounting', SOURCE_ROOT / SOURCES[0])
        self.c = load('isolated_checker', SOURCE_ROOT / SOURCES[1])
        self.c.ROOT = self.root
        self.c.LEDGER = self.root / 'evidence/ledger.json'
        self.ledger = self.c.LEDGER

    def proof(self, mutate=None, producer='executor'):
        (self.root/'accepted.json').unlink(missing_ok=True)
        bridge = {'bridge_sha256': 'a'*64, 'source_identity': 'b'*64}
        bp = self.root / 'bridge.json'; write(bp, bridge)
        payload = {'disposition': 'accepted', 'reviewer_role': 'independent-reviewer',
            'reviewer_identity': 'separate-reviewer', 'source_identity': bridge['source_identity'],
            'bridge_sha256': bridge['bridge_sha256'], 'reviewed_sections': SECTIONS, 'findings': []}
        if mutate: mutate(payload)
        rp = self.root / 'review.md'
        rp.write_text('Synthetic seam review only\n```json\n'+json.dumps(payload)+'\n```\n')
        pin = {'origin': 'parent-observed-separate-reviewer-completion', 'tool_handoff_result': 'completed',
            'decision': 'accepted', 'reviewer_identity': payload.get('reviewer_identity'),
            'producer_identity': producer, 'reviewer_role': 'gsd-code-reviewer',
            'review_sha256': self.c.sha(rp), 'source_identity': bridge['source_identity'],
            'bridge_file_sha256': self.c.sha(bp), 'test_fixture_only': False}
        pp = self.root / 'pin.json'; write(pp, pin)
        value = {'records': [], 'usage': {'cumulative_repair_seconds': 0},
            'd125_qualification23_reviews': [{'event': 'proof-review', 'review_sha256': self.c.sha(rp),
                'bridge_sha256': bridge['bridge_sha256'], 'parent_pin_path': 'pin.json',
                'parent_pin_sha256': self.c.sha(pp), 'reviewer_identity': payload.get('reviewer_identity')}]}
        self.a._accounting_state(value); write(self.ledger, value)
        self.c.load_module = lambda *args: self.a
        self.c.verify_qualification23_bridge = lambda *args: bridge
        out = self.root / 'accepted.json'
        return lambda: self.c.verify_qualification23_proof(bp, rp, self.root, out), out

    def test_proof_valid_payload(self):
        run, out = self.proof(); result = run()
        self.assertEqual(result['status'], 'accepted'); self.assertTrue(out.is_file())

    def test_proof_missing_coverage_rejected(self):
        run, out = self.proof(lambda p: p.pop('reviewed_sections'))
        with self.assertRaises(ValueError): run()
        self.assertFalse(out.exists())

    def test_proof_malformed_cases(self):
        changes = {
            'unsupported-schema': lambda p:p.update(schema='fabricated-v99'),
            'wrong-schema-type': lambda p:p.update(schema={}),
            'acceptance-alias': lambda p:p.update(status='accepted'),
            'coverage-empty': lambda p: p.update(reviewed_sections=[]),
            'coverage-one-missing': lambda p: p.update(reviewed_sections=SECTIONS[:-1]),
            'coverage-string': lambda p: p.update(reviewed_sections=' '.join(SECTIONS)),
            'coverage-object': lambda p: p.update(reviewed_sections=[{}]),
            'coverage-duplicate': lambda p: p.update(reviewed_sections=SECTIONS+[SECTIONS[0]]),
            'identity-missing': lambda p: p.pop('reviewer_identity'),
            'identity-empty': lambda p: p.update(reviewer_identity='  '),
            'identity-short': lambda p: p.update(reviewer_identity='ab'),
            'identity-nonstring': lambda p: p.update(reviewer_identity=42),
            'self-review': lambda p: p.update(reviewer_identity='authoring-agent'),
            'findings-missing': lambda p: p.pop('findings'),
            'findings-object': lambda p: p.update(findings={}),
            'findings-row': lambda p: p.update(findings=[None]),
            'severity-missing': lambda p: p.update(findings=[{k:v for k,v in finding().items() if k!='severity'}]),
            'severity-nonstring': lambda p: p.update(findings=[finding(severity=3)]),
            'severity-unknown': lambda p: p.update(findings=[finding(severity='harmless')]),
            'finding-text-missing': lambda p: p.update(findings=[{'severity':'low'}]),
            'finding-unknown-status': lambda p:p.update(findings=[finding(status='resolved')]),
            'finding-metadata-malformed': lambda p:p.update(findings=[finding(file={})]),
            'high-upper': lambda p: p.update(findings=[finding(severity='HIGH')]),
            'critical': lambda p: p.update(findings=[finding(severity='critical')]),
            'low-blocker': lambda p:p.update(findings=[finding(severity='low',classification='BLOCKER')]),
            'low-blocker-case': lambda p:p.update(findings=[finding(severity='low',classification=' bLoCkEr ')]),
            'critical-info': lambda p:p.update(findings=[finding(severity='critical',classification='INFO')]),
            'binding': lambda p: p.update(source_identity='x'),
            'disposition': lambda p: p.update(disposition='rejected'),
        }
        for name, change in changes.items():
            with self.subTest(case=name):
                run, out = self.proof(change)
                with self.assertRaises(ValueError): run()
                self.assertFalse(out.exists())
        for field in finding():
            for bad in (None,'',{},42):
                with self.subTest(field=field,bad=repr(bad)):
                    run,out=self.proof(lambda p:p.update(findings=[finding(**{field:bad})]))
                    with self.assertRaises(ValueError):run()
                    self.assertFalse(out.exists())
            with self.subTest(missing=field):
                run,out=self.proof(lambda p:p.update(findings=[{k:v for k,v in finding().items() if k!=field}]))
                with self.assertRaises(ValueError):run()
                self.assertFalse(out.exists())

    def test_parent_pin_cannot_make_producer_independent(self):
        run, out = self.proof(producer='separate-reviewer')
        with self.assertRaises(ValueError): run()
        self.assertFalse(out.exists())

    def test_companion_rechecks_payload(self):
        run,out=self.proof();run()
        self.c.verify_qualification23_companion(self.root/'bridge.json',self.root/'review.md',out,self.root)
        rp=self.root/'review.md';payload=self.c._review_payload(rp);payload['reviewed_sections']=[]
        rp.write_text('```json\n'+json.dumps(payload)+'\n```\n')
        with self.assertRaisesRegex(ValueError,'coverage-incomplete'):
            self.c.verify_qualification23_companion(self.root/'bridge.json',rp,out,self.root)

    def test_review_boundary_neighbors(self):
        run, out=self.proof(lambda p:p.update(reviewer_identity='abc',
            findings=[finding(severity='LoW')]))
        self.assertEqual(run()['status'],'accepted');self.assertTrue(out.exists())
        run,out=self.proof(lambda p:p.update(reviewed_sections=SECTIONS+['extra-reviewed-section']))
        self.assertEqual(run()['status'],'accepted')

    def close_setup(self):
        boot='synthetic-boot'; start=10.0
        phase='.planning/phases/GW-06-shared-repairs-and-two-playable-routes/'
        bindings={}
        for name in [phase+p for p in ('06-23-PLAN.md','06-23-PLAN-CHECK.md','06-CONTEXT.md')]+['.planning/context/OPERATING.md']:
            p=self.root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_text('authored inert binding')
            bindings[name]=self.a.ledger_digest(p)
        policy={'schema':'phase6-d125-qualification23-v1','plan':'06-23','status':'engineering-only',
            'game_admission':False,'test_fixture_only':False,'global_floor_seconds':34259.66586724999,
            'pea_floor_seconds':7098.193,'process_floor_seconds':5.865,'attempts_floor':2,
            'global_cap_seconds':43200.0,'pea_cap_seconds':9403.235,'process_cap_seconds':1800.0,
            'attempts_cap':3,'protected_process_seconds':1794.135,'closeout_reserve_seconds':120.0,
            'anchor_id':'authored','boot_identity':boot,'entry':{'monotonic':start},'bindings':bindings}
        value={'records':[{'d125_owner':'06-22','process_active_seconds':0.621,'new_target_attempts':1}],
            'usage':{'cumulative_repair_seconds':35000.0,'attempts_for_this_stop':2},
            'd125_recovery_policy':{'status':'terminal-halted-containment-acceptance-failure'},
            'd125_owner_events':[{'event':'terminal'}], 'd125_qualification23_policy':policy,
            'd125_qualification23_activities':[], 'd125_qualification23_reviews':[]}
        state=self.a._accounting_state(value)
        state['active_anchor']={'id':'authored','pea_charge':False,'boot_identity':boot,'monotonic_started_at':start}
        write(self.ledger,value)
        self.out=self.root/'terminal.json'
        self.kw={'output':self.out,'status':'HALTED','reason':'authored failure','boot_identity':boot,'project_root':self.root}
        self.clock=mock.patch.object(self.a.time,'monotonic',return_value=20.0); self.clock.start(); self.addCleanup(self.clock.stop)

    def test_fresh_close_publishes(self):
        self.close_setup(); report=self.a.close_qualification23(self.ledger,**self.kw)
        self.assertEqual(json.loads(self.out.read_bytes()),report)
        closed=json.loads(self.ledger.read_bytes()); self.assertIsNone(closed['phase6_accounting']['active_anchor'])
        self.assertEqual(report['global_used_seconds'],35130.0)
        before=self.ledger.read_bytes()
        with self.assertRaises(self.a.AccountingError): self.a.close_qualification23(self.ledger,**self.kw)
        self.assertEqual(before,self.ledger.read_bytes())

    def test_close_existing_symlink_and_escape_unchanged(self):
        self.close_setup(); before=self.ledger.read_bytes()
        self.out.write_bytes(b'keep')
        with self.assertRaises(self.a.AccountingError): self.a.close_qualification23(self.ledger,**self.kw)
        self.assertEqual(self.out.read_bytes(),b'keep'); self.out.unlink()
        self.out.symlink_to(self.root/'absent')
        with self.assertRaises(self.a.AccountingError): self.a.close_qualification23(self.ledger,**self.kw)
        self.out.unlink()
        with self.assertRaises(self.a.AccountingError):
            self.a.close_qualification23(self.ledger,**dict(self.kw,output=self.root.parent/'escape.json'))
        self.assertEqual(before,self.ledger.read_bytes())

    def test_interrupted_publication_recovery_no_double_charge(self):
        self.close_setup()
        with mock.patch.object(self.a,'_publish_receipt_once',side_effect=OSError('authored interruption')):
            with self.assertRaises(OSError): self.a.close_qualification23(self.ledger,**self.kw)
        closed=self.ledger.read_bytes(); self.assertFalse(self.out.exists())
        report=self.a.recover_qualification23_receipt(self.ledger,output=self.out,project_root=self.root)
        self.assertEqual(self.ledger.read_bytes(),closed)
        self.assertEqual(json.loads(self.out.read_bytes()),report)
        self.assertEqual(self.a.recover_qualification23_receipt(self.ledger,output=self.out,project_root=self.root),report)
        self.assertEqual(self.ledger.read_bytes(),closed)
        self.out.write_text('conflicting output')
        with self.assertRaises(self.a.AccountingError): self.a.recover_qualification23_receipt(self.ledger,output=self.out,project_root=self.root)
        self.assertEqual(self.out.read_text(),'conflicting output')

    def test_after_link_fsync_failure_recovers_complete_snapshot(self):
        self.close_setup()
        with mock.patch.object(self.a,'_fsync_directory',side_effect=OSError('directory flush interrupted')):
            with self.assertRaises(OSError): self.a.close_qualification23(self.ledger,**self.kw)
        before=self.ledger.read_bytes(); receipt=self.out.read_bytes()
        self.a.recover_qualification23_receipt(self.ledger,output=self.out,project_root=self.root)
        self.assertEqual(before,self.ledger.read_bytes());self.assertEqual(receipt,self.out.read_bytes())

    def test_recovery_rejects_wrong_path_symlink_missing_or_changed_intent(self):
        self.close_setup()
        with self.assertRaises(self.a.AccountingError):
            self.a.recover_qualification23_receipt(self.ledger,output=self.out,project_root=self.root)
        self.a.close_qualification23(self.ledger,**self.kw)
        with self.assertRaises(self.a.AccountingError):
            self.a.recover_qualification23_receipt(self.ledger,output=self.root/'other.json',project_root=self.root)
        self.out.unlink();self.out.symlink_to(self.root/'absent')
        with self.assertRaises(self.a.AccountingError):
            self.a.recover_qualification23_receipt(self.ledger,output=self.out,project_root=self.root)
        self.out.unlink()
        value=json.loads(self.ledger.read_bytes());value['d125_qualification23_terminal_receipt']['report']['reason']='changed'
        write(self.ledger,value)
        with self.assertRaises(self.a.AccountingError):
            self.a.recover_qualification23_receipt(self.ledger,output=self.out,project_root=self.root)
        self.assertFalse(self.out.exists())

    def test_two_closers_charge_once(self):
        self.close_setup(); barrier=threading.Barrier(2); results=[]
        def close():
            barrier.wait()
            try:self.a.close_qualification23(self.ledger,**self.kw);results.append('closed')
            except self.a.AccountingError:results.append('denied')
        threads=[threading.Thread(target=close) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(5);self.assertFalse(t.is_alive())
        self.assertCountEqual(results,['closed','denied'])
        value=json.loads(self.ledger.read_bytes())
        self.assertEqual(len(value['phase6_accounting']['closed_intervals']),2)
        self.assertEqual(len(value['d125_qualification23_reviews']),1)

    def test_publication_race_no_overwrite(self):
        target=self.root/'race.json'; barrier=threading.Barrier(2); results=[]
        def publish(n):
            barrier.wait()
            try: self.a._publish_receipt_once(target,{'winner':n}); results.append('won')
            except self.a.AccountingError: results.append('denied')
        threads=[threading.Thread(target=publish,args=(n,)) for n in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(5); self.assertFalse(t.is_alive())
        self.assertCountEqual(results,['won','denied'])
        self.assertIn(json.loads(target.read_bytes())['winner'],(0,1))
        self.assertEqual(list(self.root.glob('.race.json.*')),[])

    def test_publisher_symlink_and_interrupted_before_link(self):
        target=self.root/'receipt.json'; other=self.root/'other';other.write_bytes(b'keep')
        target.symlink_to(other)
        with self.assertRaises(self.a.AccountingError):self.a._publish_receipt_once(target,{'x':1})
        self.assertEqual(other.read_bytes(),b'keep');target.unlink()
        with mock.patch.object(self.a.os,'link',side_effect=OSError('interrupted before link')):
            with self.assertRaises(OSError):self.a._publish_receipt_once(target,{'x':1})
        self.assertFalse(target.exists());self.assertEqual(list(self.root.glob('.receipt.json.*')),[])

    def test_ledger_replacement_preserved(self):
        p=self.root/'replace.json';write(p,{'old':1}); p.chmod(0o640)
        self.a._atomic_write(p,{'new':2})
        self.assertEqual(json.loads(p.read_bytes()),{'new':2}); self.assertEqual(p.stat().st_mode&0o777,0o640)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--snapshot',action='store_true');parser.add_argument('--baseline',action='store_true');parser.add_argument('--output',required=True)
    args=parser.parse_args();WORK.mkdir(parents=True,exist_ok=True)
    if args.snapshot:
        for relative in SOURCES:
            dest=WORK/'baseline'/relative;dest.parent.mkdir(parents=True,exist_ok=True)
            if dest.exists():raise RuntimeError('baseline-already-frozen')
            shutil.copyfile(ROOT/relative,dest)
    SOURCE_ROOT=WORK/'baseline' if args.baseline else ROOT
    install_denial()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Regression)
    if args.baseline:
        suite=unittest.TestSuite(Regression(name) for name in (
            'test_proof_missing_coverage_rejected','test_parent_pin_cannot_make_producer_independent',
            'test_fresh_close_publishes','test_proof_valid_payload','test_ledger_replacement_preserved'))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={'schema':'d125-proof-receipt-regression-v1','scope':'synthetic-only-no-current-tuple-acceptance',
        'regression_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        'baseline':args.baseline,'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
        'process_api_counts':COUNTS,'guest_build_game_qualification_processes':0,
        'sources':{p:hashlib.sha256((SOURCE_ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
        'failure_names':[t.id() for t,_ in result.failures], 'error_names':[t.id() for t,_ in result.errors]}
    write(ROOT/args.output,report)
    sys.exit(not result.wasSuccessful())
