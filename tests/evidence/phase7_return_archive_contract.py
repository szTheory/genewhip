#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Denied real runner/coordinator archive-transition regression; no live eligibility."""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PHASE = Path('.planning/phases/GW-07-consolidated-compatibility-matrix-and-exact-byte-delivery')
COORDINATOR_SOURCE = ROOT / 'scripts/release/v02_qualification.py'

class HistoricalClock(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        value = cls(2026, 10, 30, 18, 2, tzinfo=datetime.timezone.utc)
        return value.astimezone(tz) if tz is not None else value.replace(tzinfo=None)

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

denial = load(ROOT / 'tests/evidence/phase7_sticky_denial.py', 'archive_denial')
if __name__ == '__main__':
    denial.install()
probe = load(ROOT / 'tests/evidence/phase7_wrapper_return.py', 'archive_runner')

@contextlib.contextmanager
def fixture():
    """Reconstruct pre-attempt3 state only under a temporary root with no client."""
    with tempfile.TemporaryDirectory(prefix='return-archive-') as temporary:
        root = Path(temporary).resolve()
        for relative in (PHASE, Path('scripts/release'), Path('evidence'),
                         Path('build/v02/campaign15')):
            (root / relative).mkdir(parents=True)
        for source in (ROOT / PHASE).glob('07-15-*'):
            if source.is_file():
                shutil.copy2(source, root / PHASE / source.name)
        for relative in ('scripts/release/v02_qualification.py', 'evidence/v02-execution.json',
                         'build/v02/campaign15/campaign.json',
                         'build/v02/campaign15/attempt2-started.json'):
            source = COORDINATOR_SOURCE if relative == 'scripts/release/v02_qualification.py' else ROOT / relative
            shutil.copy2(source, root / relative)
        for source, target in (('recovery15-attempt1', 'recovery15-attempt1'),
                               ('recovery15-attempt2', 'recovery15')):
            shutil.copytree(ROOT / 'build/v02' / source, root / 'build/v02' / target)
        packet_path = root / PHASE / '07-15-ADMISSION.json'
        packet = json.loads(packet_path.read_bytes())
        packet['packet_sha256'] = hashlib.sha256(packet_path.read_bytes()).hexdigest()
        coordinator = load(root / 'scripts/release/v02_qualification.py', 'archive_coordinator')
        with mock.patch.object(probe, 'ROOT', root), mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(datetime, 'datetime', HistoricalClock):
            yield root, packet, coordinator

def projection(root, coordinator):
    campaign = root / 'build/v02/campaign15/campaign.json'
    return coordinator._campaign_projection(campaign, root / 'evidence/v02-execution.json',
        expected_sha256=hashlib.sha256(campaign.read_bytes()).hexdigest(),
        phase='runtime', require_return=False)

class CaseBoundary(Exception):
    pass

class ArchiveContracts(unittest.TestCase):
    def test_actual_runner_reaches_fake_case_after_real_marker_archive_and_projection(self):
        with fixture() as (root, packet, coordinator):
            campaign = root / 'build/v02/campaign15/campaign.json'
            before = campaign.read_bytes()
            self.assertEqual(projection(root, coordinator)['started_at'], packet['resume_campaign']['campaign_started_at'])
            os.environ.clear()
            seen = []
            def boundary(index, case, *args):
                seen.append((index, case))
                self.assertTrue((root / 'build/v02/recovery15-attempt2/live.json').is_file())
                self.assertTrue((root / 'build/v02/campaign15/attempt3-started.json').is_file())
                self.assertFalse((root / 'build/v02/recovery15/live.json').exists())
                projection(root, coordinator)
                raise CaseBoundary('fake-external-case-boundary')
            # Immutable spent review cannot admit current source. Only its outer
            # packet gate is replaced; prechild/history/projection remain real.
            review = root / PHASE / '07-15-REVIEW.md'
            with mock.patch.object(probe, 'validate_packet_for_entry', return_value=(packet, review)), \
                 mock.patch.object(probe, 'packet_and_review', return_value=(packet, review)), \
                 mock.patch.object(probe, 'run_case', side_effect=boundary):
                with self.assertRaises(CaseBoundary):
                    probe.run_selected(root / PHASE / '07-15-ADMISSION.json', campaign,
                                       root / 'build/v02/recovery15/live.json')
                self.assertEqual(seen, [(1, 'shared_launch')])
                os.environ.clear()
                with self.assertRaisesRegex(ValueError, 'return-final-invocation-already-consumed'):
                    probe.run_selected(root / PHASE / '07-15-ADMISSION.json', campaign,
                                       root / 'build/v02/recovery15/live.json')
                self.assertEqual(seen, [(1, 'shared_launch')])
            self.assertEqual(campaign.read_bytes(), before)

    def test_history_and_final_marker_faults_reject_after_archive(self):
        faults = ('missing-history', 'corrupt-history', 'symlink-history', 'symlink-archive',
                  'missing-marker', 'symlink-marker', 'malformed-marker',
                  'marker-list', 'wrong-packet', 'wrong-campaign', 'wrong-limits',
                  'wrong-attempt2-marker', 'wrong-failure1', 'wrong-failure2',
                  'naive-time', 'future-time', 'unknown-credit', 'boolean-reserve', 'bad-digest')
        for fault in faults:
            with self.subTest(fault=fault), fixture() as (root, packet, coordinator):
                campaign = root / 'build/v02/campaign15/campaign.json'
                campaign_sha = hashlib.sha256(campaign.read_bytes()).hexdigest()
                probe.consume_final_invocation(packet, campaign_sha, packet['resume_campaign']['campaign_started_at'])
                probe.archive_failed_attempt2_and_prepare_recovery()
                # This assertion is the pre/post oracle; all faults start valid.
                projection(root, coordinator)
                history = root / 'build/v02/recovery15-attempt2/live.json'
                marker = root / 'build/v02/campaign15/attempt3-started.json'
                if fault == 'missing-history':
                    history.unlink()
                elif fault == 'corrupt-history':
                    history.write_bytes(b'{}')
                elif fault == 'symlink-history':
                    history.unlink(); history.symlink_to(campaign)
                elif fault == 'symlink-archive':
                    archive = history.parent
                    moved = archive.with_name('retained-history')
                    archive.rename(moved)
                    archive.symlink_to(moved, target_is_directory=True)
                elif fault == 'missing-marker':
                    marker.unlink()
                elif fault == 'symlink-marker':
                    marker.unlink(); marker.symlink_to(campaign)
                elif fault == 'malformed-marker':
                    marker.write_text('{')
                elif fault == 'marker-list':
                    marker.write_text('[]')
                elif fault == 'bad-digest':
                    doc = json.loads(marker.read_bytes())
                    doc['record_sha256'] = '0' * 64
                    marker.write_text(json.dumps(doc))
                else:
                    doc = json.loads(marker.read_bytes())
                    key, value = {
                        'wrong-packet': ('packet_sha256', '0' * 64),
                        'wrong-campaign': ('campaign_sha256', '0' * 64),
                        'wrong-limits': ('cumulative_limits', {}),
                        'wrong-attempt2-marker': ('attempt2_marker_sha256', '0' * 64),
                        'wrong-failure1': ('attempt1_failure_manifest_sha256', '0' * 64),
                        'wrong-failure2': ('attempt2_failure_manifest_sha256', '0' * 64),
                        'naive-time': ('consumed_at', '2026-10-30T18:01:53'),
                        'future-time': ('consumed_at', '2099-01-01T00:00:00+00:00'),
                        'unknown-credit': ('prior_wrapper_calls_used', 0),
                        'boolean-reserve': ('future_host_invocations_reserved', True),
                    }[fault]
                    doc[key] = value
                    doc.pop('record_sha256')
                    doc['record_sha256'] = hashlib.sha256(json.dumps(doc, sort_keys=True,
                        separators=(',', ':')).encode()).hexdigest()
                    marker.write_text(json.dumps(doc))
                with self.assertRaisesRegex(ValueError, 'recovery-campaign-identity-invalid'):
                    projection(root, coordinator)

    def test_prearchive_failed_history_and_unknown_reserves_stay_exact(self):
        for fault in ('missing', 'corrupt', 'symlink', 'unknown-zero'):
            with self.subTest(fault=fault), fixture() as (root, packet, coordinator):
                projection(root, coordinator)
                history = root / 'build/v02/recovery15/live.json'
                if fault == 'missing':
                    history.unlink()
                elif fault == 'corrupt':
                    history.write_bytes(b'{}')
                elif fault == 'symlink':
                    history.unlink(); history.symlink_to(root / 'build/v02/campaign15/campaign.json')
                else:
                    path = root / PHASE / '07-15-ADMISSION.json'
                    doc = json.loads(path.read_bytes())
                    doc['cumulative_limits']['prior_owner_starts_unknown_reserved'] = 0
                    path.write_text(json.dumps(doc))
                with self.assertRaisesRegex(ValueError, 'recovery-campaign-identity-invalid'):
                    projection(root, coordinator)

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveContracts))
    receipt = denial.receipt()
    print(json.dumps(receipt, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() and receipt['unexpected_denials'] == 0 else 1)
