"""Independently authored, unusable D122-policy data for the guarded D125 lane.

No project modules are imported here. The guarded entry owns source loading.
Only the two named execution leaves and explicit environmental metadata seams
are replaced; compiler, authorization, validators and publisher remain real.
"""
from __future__ import annotations
import copy
import contextlib
import hashlib
import io
import json
import pathlib
import struct
import types

IDS = ['title-no-start', 'start-idle', 'start-move', 'action-sound', 'action-no-trigger', 'sustained-play']
BOOT = 'd125-authored-fixture-boot'


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


class AuthoredFixture:
    def __init__(self, synthetic):
        self.synthetic = synthetic
        self.root = synthetic['root']
        self.calls = []
        self.originals = []
        self.historical = {}
        self.authority = None
        self.native = None
        self.baseline_checks = []
        self.progress_checks = []
        self.prospective = False
        self.baseline = [{'id': name, 'pcm_frames': 4, 'ac_range': 200 if name == 'action-sound' else 0}
                         for name in IDS]

    def write(self, relative, value):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value if isinstance(value, bytes) else
                           (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())
        return target

    def bind(self, relative, module, bindings):
        if pathlib.Path(module.__file__).resolve().relative_to(self.root).as_posix() != relative:
            raise RuntimeError('fixture-instance-file-mismatch')
        if relative == 'scripts/evidence/phase6_routes.py':
            module.TEST_FIXTURE_BASELINE_AUTHORITY = self.authority
        elif relative == 'scripts/evidence/phase6_accounting.py':
            self.originals.append((module, 'read_boot_identity', module.read_boot_identity))
            module.read_boot_identity = lambda: BOOT
            if self.prospective:
                module.TEST_FIXTURE_D125_AUTHORITY={'schema':'d125-authored-owner-authority-v1','root':str(self.root),'test_fixture_only':True}
        elif relative == 'tests/evidence/phase6_tank_continuation_contract.py':
            original = module.git_blob
            def authored_blob(revision, path):
                if revision != module.BASELINE_COMMIT or path not in self.historical:
                    raise RuntimeError('unauthored-historical-byte-request:' + path)
                return self.historical[path]
            self.originals.append((module, 'git_blob', original))
            module.git_blob = authored_blob
        elif relative == 'tests/session/phase6_route_contract.py':
            original = module._run_client
            if original.__module__ != module.__name__ or original.__name__ != '_run_client':
                raise RuntimeError('capture-execution-leaf-identity-invalid')
            self.originals.append((module, '_run_client', original))
            module._run_client = self.capture_leaf
        elif relative == 'tests/fixtures/phase4_game.py':
            original = module.bounded_run
            if original.__module__ != module.__name__ or original.__name__ != 'bounded_run':
                raise RuntimeError('control-execution-leaf-identity-invalid')
            self.originals.append((module, 'bounded_run', original))
            module.bounded_run = self.control_leaf
        elif relative == 'tests/fixtures/phase6_repairs.py':
            original = module.subprocess
            # The production capture records git head/dirty metadata before its
            # execution leaf. Only these exact metadata queries are authored.
            def check_output(argv, **kwargs):
                if pathlib.Path(kwargs.get('cwd', '')).resolve() != self.root:
                    raise RuntimeError('fixture-git-metadata-root-invalid')
                if argv == ['git', 'rev-parse', 'HEAD']:
                    return 'f' * 40 + '\n'
                if argv == ['git', 'diff', '--name-only']:
                    return ''
                raise RuntimeError('fixture-git-metadata-query-denied')
            module.subprocess = types.SimpleNamespace(check_output=check_output)
            self.originals.append((module, 'subprocess', original))
        bindings.append({'path': relative, 'module': module.__name__, 'test_fixture_only': True})

    def check_instance(self, relative, module):
        name = {'tests/fixtures/phase4_game.py': 'bounded_run',
                'tests/session/phase6_route_contract.py': '_run_client'}.get(relative)
        if name and getattr(getattr(module, name, None), '__self__', None) is not self:
            raise RuntimeError('execution-leaf-instance-binding-invalid:' + relative)

    def author_inputs(self):
        (self.root / 'build/phase6/d122-observer').mkdir(parents=True, exist_ok=True)
        self.write('metadata/d125-authored-root.json', {'schema': 'd125-authored-root-v1', 'test_fixture_only': True})
        self.write('evidence/phase6-repairs.json', {
            'test_fixture_only': True, 'records': [{'record_id': 'authored-control-baseline',
                'post_behavior': {'unchanged_control': {'status': 'pass', 'results': self.baseline}}}],
            'usage': {'cumulative_repair_seconds': 5095.179},
            'd121_recovery_amendment': {'status': 'prospective-approved', 'target_stop_signature': 'tank-battle:cpu:00ec32:4879:2',
                'prior_target_cap_seconds': 5400, 'effective_target_cap_seconds': 9000,
                'global_cap_seconds': 43200, 'other_target_cap_seconds': 5400, 'test_fixture_only': True},
            'budgets': {'cumulative_repair_seconds': 43200, 'investigation_seconds_per_stop': 5400, 'attempts_per_stop': 3}})
        roster, inventory = [], []
        for title, directory, cases in (
            ('tank-battle', 'phase5-a', [{'id': 'full-route'}, {'id': 'withheld-a'}, {'id': 'withheld-b'}]),
            ('recursion94', 'phase5-b', [{'id': 'full-route'}, {'id': 'withheld-a'}, {'id': 'withheld-b'}]),
            ('genewhip-independent-game-v2', 'independent-game-v2', [{'id': name} for name in IDS]),
        ):
            prefix = 'fixtures/' + directory
            rom = self.write(prefix + '/game.bin', ('UNUSABLE-AUTHORED-' + title).encode())
            source = self.write(prefix + '/source.txt', b'; independently authored fixture metadata; no game code\n')
            scenario = {'cases': cases, 'identities': {'rom_sha256': sha(rom)},
                'source': {'relative_path': source.relative_to(self.root).as_posix()},
                'rom': {'relative_path': rom.relative_to(self.root).as_posix()},
                'active_clock': {'kind': 'state-count', 'name': 'active_ticks', 'active_value': 1},
                'budget': {'total_fields': 4500, 'active_fields': 3600, 'boot_fields': 900},
                'render_field': 1, 'addresses': [{'name': 'game_state', 'address': 'E0FF0059', 'width': 1}]}
            scenario_path = self.write(prefix + '/scenario.json', scenario)
            oracle = self.write(prefix + '/oracle.json', {'case_ids': [c['id'] for c in cases], 'predicates': []})
            program = self.write(prefix + ('/host-controls.json' if directory == 'independent-game-v2' else '/input-program.json'),
                {'launch': {'field': 1, 'release_after_fields': 1, 'press': 'P1 Start'},
                 'actions': [], 'cases': {c['id']: [] for c in cases}})
            self.write(prefix + '/reference-build-record.json', {'scenario_sha256': sha(scenario_path), 'input_program_sha256': sha(program)})
            fixture_id = title if directory == 'independent-game-v2' else 'genewhip-phase5-' + ('a' if directory == 'phase5-a' else 'b')
            for case in cases:
                roster.append({'fixture_id': fixture_id, 'case_id': case['id'],
                    'scenario': {'sha256': sha(scenario_path)}, 'rom': {'sha256': sha(rom)},
                    'route_input_program': {'sha256': sha(program)}, 'oracle': {'sha256': sha(oracle)}, 'expectations': {}})
                inventory.append({'fixture_id': fixture_id, 'title_id': title,
                    'scenario_sha256': sha(scenario_path), 'rom_sha256': sha(rom)})
        roster_doc = {'cases': roster}
        baseline = {'roster_sha256': canonical(roster_doc), 'test_fixture_only': True}
        reference = self.write('evidence/authored-reference.json', {'test_fixture_only': True, 'status': 'authored'})
        self.write('evidence/phase5-baseline-roster.json', roster_doc)
        self.write('evidence/phase5-baseline.json', baseline)
        self.write('evidence/phase5-current-reference.json', {'status': 'qualified-pair', 'decision': 'D-118',
            'report': {'path': reference.relative_to(self.root).as_posix(), 'sha256': sha(reference)}, 'test_fixture_only': True})
        self.write('evidence/phase5-failure-inventory.json', {'records': inventory,
            'baseline_sha256': canonical(baseline), 'baseline_roster_sha256': canonical(roster_doc), 'reference_report_sha256': sha(reference)})
        self.authority = {'schema': 'd125-authored-baseline-v1', 'test_fixture_only': True, 'root': str(self.root),
            'baseline_sha256': canonical(baseline), 'roster_sha256': canonical(roster_doc), 'reference_sha256': sha(reference)}
        for name in ('CMakeLists.txt', 'src/authored.c', 'tests/api/phase6_repairs_contract.c',
                     'tests/session/phase6_stack_forward_contract.c', 'tests/evidence/phase6_accounting_contract.py'):
            self.write(name, b'/* authored inert source identity metadata */\n')
        self.write('build/phase6/tools/session/gw_headless', b'UNUSABLE-AUTHORED-CLIENT-NATIVE\n')
        for name in ('cmake', 'compiler', 'make'):
            self.write('metadata/tools/' + name, ('UNUSABLE-TOOL-' + name).encode())

    def capture_leaf(self, client, command, processes, *, report, timeout, cwd, retained_streams):
        self.assert_reserved('tank-continuation')
        if pathlib.Path(client).resolve() != self.root / 'build/phase6/tools/session/gw_headless' or pathlib.Path(cwd).resolve() != self.root:
            raise RuntimeError('capture-leaf-input-path-invalid')
        self.calls.append('capture')
        native = copy.deepcopy(self.native)
        plan = self.root / command[command.index('--route-plan') + 1]
        value = 14695981039346656037
        for byte in plan.read_bytes():
            value = ((value ^ byte) * 1099511628211) & 0xffffffffffffffff
        native.update(plan_fnv1a64=f'{value:016x}', samples=[])
        report.write_text(json.dumps(native, separators=(',', ':')))
        processes.append({'return_code': 1, 'bound_violation': False, 'timed_out': False, 'wall_seconds': 0.0})
        for key in ('stdout', 'stderr'):
            retained_streams[key] = {'text': '', 'sha256': hashlib.sha256(b'').hexdigest(),
                                    'observed_bytes': 0, 'retained_bytes': 0, 'truncated': False}
        return types.SimpleNamespace(returncode=1)

    def assert_reserved(self, purpose):
        ledger = json.loads((self.root / 'evidence/phase6-repairs.json').read_bytes())
        reserved = [row for row in ledger['records'] if row.get('status') == 'reserved']
        if len(reserved) != 1 or reserved[0].get('purpose') != purpose:
            raise RuntimeError('fake-leaf-without-durable-exact-reservation')

    def control_leaf(self, command, *, timeout, cap):
        self.assert_reserved('tank-continuation-control')
        if pathlib.Path(command[2]).resolve() != self.root / 'tests/fixtures/phase4_game.py':
            raise RuntimeError('wrong-control-driver-source')
        self.calls.append('control')
        report = pathlib.Path(command[command.index('--report') + 1])
        retain = pathlib.Path(command[command.index('--retain-artifacts') + 1])
        report.resolve().relative_to(self.root);retain.resolve().relative_to(self.root)
        retain.mkdir(parents=True, exist_ok=True)
        rows, children = [], []
        for baseline in self.baseline:
            name = baseline['id']
            samples = [-100, 100] * 4 if baseline['ac_range'] else [0] * 8
            pcm = self.write((retain / (name + '.pcm')).relative_to(self.root).as_posix(), struct.pack('<8h', *samples))
            streams = {}
            for key in ('stdout', 'stderr'):
                path = self.write((retain / (name + '.' + key)).relative_to(self.root).as_posix(), b'')
                streams[key] = {'path': path.relative_to(self.root).as_posix(), 'sha256': sha(path),
                                'observed_bytes': 0, 'retained_bytes': 0, 'truncated': False}
            rows.append(dict(baseline, retained_pcm={'path': pcm.relative_to(self.root).as_posix(), 'bytes': pcm.stat().st_size, 'sha256': sha(pcm)}))
            children.append({'case': name, 'return_code': 0, 'executable_path': 'build/phase6/tools/session/gw_headless',
                'executable_sha256': sha(self.root / 'build/phase6/tools/session/gw_headless'), 'command_sha256': canonical([name]), 'streams': streams})
        report.write_text(json.dumps({'outcome': 'pass', 'results': rows, 'native_child_processes': children}))
        return types.SimpleNamespace(stdout=b'', stderr=b'', returncode=0)

    def prepare_transaction(self, loaded):
        coordinator, checker = loaded['coordinator'], loaded['checker']
        accounting = coordinator.accounting
        ledger_path = self.root / 'evidence/phase6-repairs.json'
        self.check_baseline_authority(coordinator.compiler)
        # Historical data is independently authored; no production JSON or ROM
        # bytes enter this fixture. Reviewed Python sources are the only copies.
        for path in self.root.rglob('*'):
            if path.is_file() and not path.is_symlink():
                self.historical[path.relative_to(self.root).as_posix()] = path.read_bytes()
        self.native = checker._fake_receipt(self.root / 'output')['native_report']
        historical_native = copy.deepcopy(self.native)
        pair = historical_native['probe_boundary']
        pair['instruction_address'] = pair['before']['pc'] = 0x200
        pair['before']['a'][7] = 0xffff00
        pair['after']['a'][7] = 0xfffefc
        pair['after']['spans'].append({'address': 0xfffefc, 'bytes': '00e00010'})
        last = historical_native['last_boundary']
        last['before']['pc'] = last['instruction_address'] = 0x20e
        last['before']['d'][0] = 0x56781234
        historical_native['instruction_address'] = 0x20e
        raw_path = self.write('receipts/historical-native.json', historical_native)
        manifest = {'review_status': 'approved', 'status': 'verified-bounded-infrastructure',
            'test_fixture_only': True, 'source_identity': checker.tree_source_identity(checker.BASELINE_COMMIT, checker.source_paths(self.root)),
            'proof_inputs_sha256': {}, 'synthetic_process_rows': []}
        for index in range(10):
            path = self.write(f'metadata/proof-input-{index}.txt', f'authored-proof-input-{index}'.encode())
            relative = path.relative_to(self.root).as_posix()
            self.historical[relative] = path.read_bytes()
            manifest['proof_inputs_sha256'][relative] = sha(path)
        builds, tools = [], {}
        for variant in ('native', 'sanitize', 'hooks-off'):
            directory = 'build/observer-' + variant
            binary = self.write(directory + '/tools/session/gw_headless', ('UNUSABLE-ORIGINAL-' + variant).encode())
            guest = self.write(f'metadata/{variant}.rom', b'UNUSABLE-HISTORICAL-GUEST')
            descriptor = self.write(f'metadata/{variant}.route', b'AUTHORED-ORIGINAL-DESCRIPTOR')
            command = [binary.relative_to(self.root).as_posix(), '--route-plan', descriptor.relative_to(self.root).as_posix(), guest.relative_to(self.root).as_posix()]
            streams = {key: {'text': '', 'sha256': hashlib.sha256(b'').hexdigest(), 'truncated': False,
                             'observed_bytes': 0, 'retained_bytes': 0} for key in ('stdout', 'stderr')}
            manifest['synthetic_process_rows'].append({'status': 'passed', 'assertions': 9, 'fields': 0,
                'new_target_attempts': 0, 'case': variant, 'variant': variant,
                'processes': [{'return_code': 1, 'bound_violation': False}], 'retained_streams': streams,
                'native_report_path': raw_path.relative_to(self.root).as_posix(), 'native_report_sha256': sha(raw_path),
                'command': command, 'client_sha256': sha(binary), 'guest_sha256': sha(guest), 'plan_sha256': sha(descriptor)})
            cache = self.write(directory + '/CMakeCache.txt', b'authored inert cache\n')
            builds.append({'variant': variant, 'directory': directory, 'command': ['unusable-cmake', variant]})
            tools[variant] = {'cache_sha256': sha(cache), 'compiler_path': str(self.root / 'metadata/tools/compiler'),
                'compiler_sha256': sha(self.root / 'metadata/tools/compiler'), 'build_tool_path': str(self.root / 'metadata/tools/make'),
                'build_tool_sha256': sha(self.root / 'metadata/tools/make'), 'settings': {}, 'command': ['unusable-cmake', variant]}
        self.write('evidence/phase6-capture-recovery.json', manifest)
        self.write('evidence/phase6-stack-observation-manifest.json', {'test_fixture_only': True, 'kind': 'authored-original-observer'})
        self.write('evidence/phase6-stack-observation-manifest-d122.json', {'test_fixture_only': True, 'builds': builds})
        retained = checker.retain_original_binaries()
        ledger = json.loads(ledger_path.read_bytes())
        ledger['d122_recovery_exception'] = {
            'schema': 'phase6-d122-recovery-v1', 'status': 'prospective-approved', 'plan_scope': ['06-18', '06-14'],
            'approval_context_sha256': accounting.D122_APPROVAL_CONTEXT_SHA256, 'plan_check_sha256': accounting.D122_PLAN_CHECK_SHA256,
            'prior_pea_cap_seconds': 9000.0, 'effective_pea_cap_seconds': 9403.235,
            'historical_global_floor_seconds': 13163.411, 'historical_pea_floor_seconds': 6812.984,
            'historical_offline_seconds': 1813.235, 'historical_offline_limit_seconds': 1800.0,
            'partitions': {'observer_builds': 300.0, 'observer_proofs': 90.0, '14_processes': 1800.0, '14_other': 400.251},
            'global_cap_seconds': 43200.0, 'other_target_cap_seconds': 5400.0,
            'attempts_renewed': 0, 'processes_added': 0, 'acceptance_reduced': False, 'test_fixture_only': True}
        ledger['d122_accounting'] = {'other_charges': []}
        ledger['d122_successor_manifest'] = {'status': 'frozen', 'original_binary_retention': retained,
            'tool_identity': {'cmake_path': str(self.root / 'metadata/tools/cmake'), 'cmake_sha256': sha(self.root / 'metadata/tools/cmake'), 'builds': tools}}
        ledger_path.write_text(json.dumps(ledger))
        accounting.initialize_ledger(ledger_path, monotonic_started_at=accounting.time.monotonic(), boot_identity=BOOT, allowed_root=self.root)
        original = checker.revalidate_proof(self.root / 'build/phase6', self.root / 'output/authored-original-closure.json',
                                            update_ledger=False, binary_retention=checker.load_original_binary_retention(retained))
        source = accounting.source_identity(self.root)
        bridge = {'schema': 'phase6-tank-observer-bridge-v1', 'status': 'passed-observer-bridge-no-launch', 'test_fixture_only': True,
            'current_source_closure': {'source_identity': source, 'path_sha256': {p: sha(self.root / p) for p in checker.source_paths(self.root)}},
            'native_binary_sha256': sha(self.root / 'build/phase6/tools/session/gw_headless'),
            'control_client_binary_sha256': sha(self.root / 'build/phase6/tools/session/gw_headless'),
            'capture_descriptor_sha256': original['tank_capture_descriptor_sha256'],
            'original_observer_manifest_sha256': sha(self.root / 'evidence/phase6-stack-observation-manifest.json'),
            'successor_manifest_path': 'evidence/phase6-stack-observation-manifest-d122.json',
            'successor_manifest_sha256': sha(self.root / 'evidence/phase6-stack-observation-manifest-d122.json'),
            'original_semantic_closure': {'base_revision': original['base_commit'], 'old_source_identity': original['old_source_identity'],
                'retained_manifest_sha256': original['retained_manifest_sha256'], 'retained_reports': original['retained_reports'],
                'original_runtime_closure': original['original_runtime_closure'], 'current_control_inputs': original['control_driver_inputs'],
                'historical_control_inputs': original['historical_control_driver_inputs'], 'source_changed_paths': original['source_changed_paths']},
            'build_tool_identity': {'cmake_sha256': sha(self.root / 'metadata/tools/cmake'), 'builds': {variant: {
                'cache_sha256': row['cache_sha256'], 'compiler_name': 'compiler', 'compiler_sha256': row['compiler_sha256'],
                'build_tool_name': 'make', 'build_tool_sha256': row['build_tool_sha256'], 'settings': row['settings'], 'command': row['command']}
                for variant, row in tools.items()}}}
        bridge['bridge_sha256'] = canonical(bridge)
        self.bridge_path = self.write('evidence/authored-bridge.json', bridge)
        self.proof_path = self.write('evidence/authored-proof-review.md', b'authored fixture review record\n')
        # Mechanical fixture handoffs are visibly disjoint from the real parent
        # preimport review. They never leave this unusable retained fixture root.
        handoff = self.handoff('observer-proof-review', self.proof_path, bridge['bridge_sha256'], source)
        ledger = accounting._load(ledger_path, self.root)
        ledger['d122_observer_bridge'] = {'status': 'bridge-built-review-pending',
            'path': self.bridge_path.relative_to(self.root).as_posix(), 'bridge_sha256': bridge['bridge_sha256'],
            'source_identity': source, 'proof_count': 3, 'test_fixture_only': True}
        ledger['d122_trusted_review_handoffs'] = [handoff]
        accounting._write(ledger_path, ledger)
        self.review_check_path = self.root / 'evidence/authored-proof-check.json'
        payload = {'bridge_sha256': bridge['bridge_sha256'], 'source_identity': source, 'disposition': 'accepted',
            'reviewer_role': 'independent-reviewer', 'reviewer_identity': 'authored-fixture-reviewer', 'findings': [],
            'test_fixture_only': True, 'reviewed_sections': ['historical-source-and-assertion-closure', 'actual-observer-rows-and-binaries',
                'stack-read-ownership-and-same-pc-path', 'raw-process-stream-and-control-pcm-retention',
                'd122-partitions-and-active-anchor', 'downstream-authorization-gates']}
        self.proof_path.write_text('```json\n' + json.dumps(payload) + '\n```\n')
        ledger = accounting._load(ledger_path, self.root)
        ledger['d122_trusted_review_handoffs'][0]['review_sha256'] = sha(self.proof_path)
        accounting._write(ledger_path, ledger)
        checker.verify_proof_review(self.bridge_path, self.proof_path, self.root / 'build/phase6', self.review_check_path)
        return bridge

    def engineering24_chain(self, loaded, args, boundary, monitor):
        """Exercise the actual no-game reservation API in a synthetic root only.

        This is an owner activity transaction; it is never a proof/final-tuple
        consumer acceptance. The historical owner23 transaction is not reused.
        """
        if args.engineering_owner != '06-24' or args.case != 'engineering24-chain':
            raise RuntimeError('engineering24-explicit-chain-required')
        accounting = loaded['coordinator'].accounting
        project = self.root.resolve(strict=True)
        checkout = pathlib.Path(__file__).resolve().parents[2]
        if project == checkout or (project / '.git').exists():
            raise RuntimeError('engineering24-synthetic-root-required')
        live_path = project / 'evidence/phase6-repairs.json'
        before = sha(live_path)
        live = json.loads(live_path.read_bytes())
        policy = accounting.engineering24_owner(live, project_root=project,
            boot_identity=live.get('d125_engineering24_policy', {}).get('boot_identity'))
        denials = []
        for purpose, case in (('tank-continuation', accounting.TANK_CONTINUATION_CASE),
                ('tank-continuation-control', 'control-repeat-1'),
                ('independent-pea', 'tank-pea-regression'), ('rec-validation', 'rec-validation'),
                ('joint-qualification', 'joint-qualification')):
            try:
                accounting.authorize_launch(live_path, purpose=purpose, plan='06-24', case=case,
                    source_identity='a'*40, current_source_identity='a'*40,
                    contract_identity='owner24-synthetic-no-launch', boot_identity=policy['boot_identity'],
                    allowed_root=project, launcher=lambda _: (_ for _ in ()).throw(
                        RuntimeError('engineering24-forbidden-launcher-reached')),
                    target_signature=accounting.PEA_SIGNATURE if purpose in ('tank-continuation', 'independent-pea') else None)
            except accounting.AccountingError:
                denials.append({'purpose': purpose, 'denied': True})
            else:
                raise RuntimeError('engineering24-live-purpose-admitted:' + purpose)
        if sha(live_path) != before:
            raise RuntimeError('engineering24-owner-mutated-live-ledger')
        activity_id = 'd125-engineering24-synthetic-owner-transaction'
        row = accounting.begin_engineering24_activity(live_path, activity_id=activity_id,
            stage='engineering', exposure_seconds=2.0, remaining_forecast_seconds=3.0,
            boot_identity=policy['boot_identity'], project_root=project)
        final = accounting.finalize_engineering24_activity(live_path, activity_id=activity_id,
            status='completed', boot_identity=policy['boot_identity'], project_root=project)
        try:
            accounting.begin_engineering24_activity(live_path, activity_id=activity_id,
                stage='engineering', exposure_seconds=2.0, remaining_forecast_seconds=3.0,
                boot_identity=policy['boot_identity'], project_root=project)
        except accounting.AccountingError as exc:
            if str(exc) != 'engineering24-activity-spent':
                raise
        else:
            raise RuntimeError('engineering24-spent-activity-replayed')
        result = {'checks': [
            {'case': 'actual-owner24-reserved', 'passed': row['status'] == 'reserved'},
            {'case': 'actual-owner24-finalized', 'passed': final['status'] == 'completed'},
            {'case': 'actual-owner24-replay-denied', 'passed': True}],
            'current_tuple_accepted': False}
        result.update(engineering_owner='06-24', game_admission=False,
            retained_count=3, fresh_count=0, live_game_denials=denials,
            live_entry_ledger_sha256=policy['entry_ledger_sha256'],
            synthetic_only=True)
        result['checks'].extend({'case': 'engineering24-live-denied-' + item['purpose'], 'passed': item['denied']}
            for item in denials)
        if boundary.violation_count or monitor.process_events:
            raise RuntimeError('engineering24-process-denial-oracle-failed')
        result['checks'].append({'case': 'engineering24-process-denial-sticky-zero', 'passed': True})
        if not all(item.get('passed') is True for item in result['checks']):
            raise RuntimeError('engineering24-chain-oracle-failed')
        return result

    def check_baseline_authority(self, compiler):
        """Exercise actual baseline predicates; restore every synthetic mutation."""
        inventory_path = self.root / 'evidence/phase5-failure-inventory.json'
        ledger_path = self.root / 'evidence/phase6-repairs.json'
        original_inventory, original_ledger = inventory_path.read_bytes(), ledger_path.read_bytes()
        original_root, original_authority = compiler.ROOT, compiler.TEST_FIXTURE_BASELINE_AUTHORITY
        if len(compiler.trusted_baseline()[0]['cases']) != 12:
            raise RuntimeError('authored-baseline-positive-denominator')
        self.baseline_checks.append({'case': 'explicit-authored-baseline-positive', 'passed': True})
        checkout = next(p for p in self.root.parents if (p / '.git').exists())
        mutations = [('production-root-authority', 'test-fixture-baseline-authority-denied'),
                     ('implicit-activation', 'production-baseline-identity'),
                     ('mismatched-expected-hash', 'production-baseline-identity'),
                     ('mismatched-baseline-link', 'production-admission-link'),
                     ('mismatched-roster-link', 'production-roster-link'),
                     ('mismatched-reference-link', 'failure-inventory-reference-link'),
                     ('production-policy-authority', 'test-fixture-production-policy-denied')]
        for name, reason in mutations:
            try:
                if name == 'production-root-authority':
                    compiler.ROOT = checkout
                elif name == 'implicit-activation':
                    compiler.TEST_FIXTURE_BASELINE_AUTHORITY = None
                elif name == 'mismatched-expected-hash':
                    compiler.TEST_FIXTURE_BASELINE_AUTHORITY = dict(original_authority, baseline_sha256='0' * 64)
                elif name == 'production-policy-authority':
                    document = json.loads(original_ledger)
                    document['d124_recovery_policy'] = {}
                    ledger_path.write_text(json.dumps(document))
                else:
                    document = json.loads(original_inventory)
                    key = {'mismatched-baseline-link': 'baseline_sha256', 'mismatched-roster-link': 'baseline_roster_sha256',
                           'mismatched-reference-link': 'reference_report_sha256'}[name]
                    document[key] = '0' * 64
                    inventory_path.write_text(json.dumps(document))
                try:
                    compiler.trusted_baseline()
                except compiler.Invalid as error:
                    if str(error) != reason:
                        raise RuntimeError('baseline-negative-wrong-reason:' + name + ':' + str(error)) from error
                else:
                    raise RuntimeError('baseline-negative-accepted:' + name)
                self.baseline_checks.append({'case': name, 'passed': True, 'rejection': reason})
            finally:
                compiler.ROOT, compiler.TEST_FIXTURE_BASELINE_AUTHORITY = original_root, original_authority
                inventory_path.write_bytes(original_inventory)
                ledger_path.write_bytes(original_ledger)
        compiler.trusted_baseline()
        self.write('output/authored-baseline-checks.json', {'test_fixture_only': True, 'checks': self.baseline_checks})

    def handoff(self, lane, path, bridge_sha, source, receipt_sha=None):
        row = {'lane': lane, 'status': 'completed', 'review_path': path.relative_to(self.root).as_posix(),
            'review_sha256': sha(path), 'bridge_sha256': bridge_sha, 'source_identity': source, 'tool_handoff_result': 'completed',
            'reviewer_role': 'gsd-code-reviewer', 'reviewer_identity': 'authored-fixture-reviewer', 'producer_identity': 'authored-fixture-data',
            'disposition': 'accepted', 'critical_findings': 0, 'high_findings': 0, 'test_fixture_only': True}
        if receipt_sha is not None:
            row['receipt_sha256'] = receipt_sha
        return row

    def finish_transaction(self, loaded, bridge):
        coordinator, checker = loaded['coordinator'], loaded['checker']
        accounting = coordinator.accounting
        receipt = self.root / 'output/authored-receipt.json'
        import sys
        from unittest.mock import patch
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), patch.object(sys, 'argv', ['phase6_repairs.py', '--tank-continuation-once', '--build', str(self.root / 'build/phase6'),
                '--bridge', str(self.bridge_path), '--proof-review', str(self.proof_path), '--review-check', str(self.review_check_path), '--output', str(receipt)]):
            code = coordinator.main()
        self.write('output/coordinator.stdout.raw', captured.getvalue().encode())
        if code != 0:
            raise RuntimeError('real-coordinator-main-failed:' + captured.getvalue().strip())
        for purpose in ('independent-final-review', 'd122-closeout'):
            if self.prospective:
                accounting.begin_d125_activity(coordinator.LEDGER,activity_id='d125-authored-'+purpose,
                    stage='final-review' if purpose=='independent-final-review' else 'closeout',exposure_seconds=30,boot_identity=BOOT,project_root=self.root)
                accounting.finalize_d125_activity(coordinator.LEDGER,activity_id='d125-authored-'+purpose,status='completed',boot_identity=BOOT,allowed_root=self.root)
            else:
                accounting.begin_d122_other_interval(coordinator.LEDGER, purpose=purpose, interval_id='authored-' + purpose,
                    source_identity=accounting.source_identity(self.root), boot_identity=BOOT, allowed_root=self.root)
                accounting.finalize_d122_other_interval(coordinator.LEDGER, interval_id='authored-' + purpose, status='completed', boot_identity=BOOT, allowed_root=self.root)
        acceptance = self.write('evidence/authored-final-review.json', {'disposition': 'accepted', 'test_fixture_only': True,
            'receipt_sha256': sha(receipt), 'bridge_sha256': bridge['bridge_sha256'], 'source_identity': accounting.source_identity(self.root),
            'processes': 3, 'control_cases': 12})
        ledger = accounting._load(coordinator.LEDGER, self.root)
        ledger.setdefault('d125_trusted_review_handoffs' if self.prospective else 'd122_trusted_review_handoffs',[]).append(self.handoff('tank-final-acceptance', acceptance,
            bridge['bridge_sha256'], accounting.source_identity(self.root), sha(receipt)))
        accounting._write(coordinator.LEDGER, ledger)
        checked = self.root / 'output/authored-checked.json'
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), patch.object(sys, 'argv', ['phase6_tank_continuation_contract.py', '--verify-receipt', str(receipt),
                '--bridge', str(self.bridge_path), '--proof-review', str(self.proof_path), '--review-check', str(self.review_check_path),
                '--build', str(self.root / 'build/phase6'), '--acceptance-review', str(acceptance), '--output', str(checked)]):
            code = checker.main()
        self.write('output/checker.stdout.raw', captured.getvalue().encode())
        if code != 0:
            raise RuntimeError('real-receipt-cli-failed:' + captured.getvalue().strip())
        value = json.loads(checked.read_bytes())
        ledger = accounting._load(coordinator.LEDGER, self.root)
        reservations = [r for r in ledger['records'] if r.get('record_type') == 'authorization-reservation']
        checks = {'exact-fake-leaf-calls': self.calls == ['capture', 'control', 'control'],
            'three-durable-completed-reservations': len(reservations) == 3 and all(r['status'] == 'completed' for r in reservations),
            'one-synthetic-target-attempt': sum(r['new_target_attempts'] for r in reservations) == 1,
            'actual-recomputed-checked-output': value['status'] == 'independently-checked',
            'locked-passed-pointer': ledger['current_tank_continuation_receipt']['status'] == 'passed',
            'full-control-pcm-denominator': value['counts']['control_evidence']['full_pcm_files'] == 12}
        if not all(checks.values()):
            raise RuntimeError('transaction-oracle-failed:' + ','.join(k for k, v in checks.items() if not v))
        return {'checks': self.baseline_checks + [{'case': k, 'passed': v} for k, v in checks.items()], 'counts': value['counts'],
            'fake_leaf_calls': self.calls, 'reservations': [r['record_id'] for r in reservations],
            'checked_path': checked.relative_to(self.root).as_posix(), 'checked_sha256': sha(checked), 'test_fixture_only': True}

    def authored_owner(self, accounting, *, activate=True):
        """Distinct prospective fixture policy; never copy live ledger/approval bytes."""
        ledger = self.root / 'evidence/phase6-repairs.json'
        value = json.loads(ledger.read_bytes())
        value['d124_recovery_policy'] = {'status': 'halted-scope-breach', 'test_fixture_only': True}
        value['d125_recovery_policy'] = {'status': 'terminal-halted-containment-acceptance-failure', 'test_fixture_only': True}
        value.pop('phase6_accounting', None)
        accounting._accounting_state(value)
        value['phase6_accounting']['closed_baseline_seconds'] = 28288.671
        started = accounting.time.monotonic()
        value['phase6_accounting']['active_anchor'] = {'id': 'authored22-anchor', 'purpose': 'd125-owner22-global-engineering',
            'pea_charge': False, 'boot_identity': BOOT, 'monotonic_started_at': started}
        owner = {'generation_id': 'authored22-bootstrap', 'plan': '06-22', 'status': 'engineering-only',
            'immutable_generation': True, 'test_fixture_only': True, 'anchor_id': 'authored22-anchor', 'boot_identity': BOOT,
            'global_floor_seconds': 28286.671, 'global_cap_seconds': 43200.0, 'pea_floor_seconds': 7097.572,
            'pea_cap_seconds': 9403.235, 'process_floor_seconds': 5.244, 'process_cap_seconds': 1800.0,
            'attempts_floor': 1, 'attempts_cap': 3, 'bindings': {}}
        value['d125_owner_generations'] = [owner]
        value['d125_owner_events'] = []
        accounting.TEST_FIXTURE_D125_AUTHORITY = {'schema': 'd125-authored-owner-authority-v1', 'root': str(self.root), 'test_fixture_only': True}
        accounting._write(ledger, value)
        if not activate:return ledger,value
        runtime = {'source_identity': accounting.source_identity(self.root)}
        for key in ('bridge','proof_review','review_check','component_review','parent_pin'):
            target = self.write('metadata/authored22-' + key + '.json', {'test_fixture_only': True, 'kind': key})
            runtime[key] = {'path': target.relative_to(self.root).as_posix(), 'sha256': sha(target)}
        bound = dict(owner, generation_id='authored22-bound', status='prospective-bound', runtime_binding=runtime,
            parent_generation_sha256=canonical(owner),launch_forecast={'nonprocess_seconds':100.0,'final_review_seconds':80.0,
                'remaining_engineering_seconds':20.0,'process_seconds':1794.756,'closeout_seconds':120.0})
        accounting.install_d125_owner(ledger, generation=bound, boot_identity=BOOT, project_root=self.root)
        return ledger, accounting._load(ledger, self.root)

    def prepare_prospective(self,loaded):
        historical=self.prepare_transaction(loaded)
        old_bridge_path=self.bridge_path
        self.prospective=True
        accounting=loaded['coordinator'].accounting
        ledger,value=self.authored_owner(accounting,activate=False)
        bridge=dict(historical,recovery_owner='06-22',authored_historical_bridge_path=old_bridge_path.relative_to(self.root).as_posix(),
            authored_historical_bridge_sha256=historical['bridge_sha256'])
        if getattr(self,'current_qualification23_tuple',None) is not None:
            bridge['qualification23_current_evidence']=self.current_qualification23_tuple
        bridge.pop('bridge_sha256');bridge['bridge_sha256']=canonical(bridge)
        self.bridge_path=self.write('evidence/authored22-bridge.json',bridge)
        payload=json.loads(self.proof_path.read_text().split('```json\n',1)[1].split('\n```',1)[0])
        payload['bridge_sha256']=bridge['bridge_sha256']
        self.proof_path=self.write('evidence/authored22-proof-review.md',('```json\n'+json.dumps(payload)+'\n```\n').encode())
        value=accounting._load(ledger,self.root)
        value['d125_trusted_review_handoffs']=[self.handoff('observer-proof-review',self.proof_path,bridge['bridge_sha256'],accounting.source_identity(self.root))]
        accounting._write(ledger,value)
        self.review_check_path=self.root/'evidence/authored22-proof-check.json'
        loaded['checker'].verify_proof_review(self.bridge_path,self.proof_path,self.root/'build/phase6',self.review_check_path)
        value=accounting._load(ledger,self.root);owner=value['d125_owner_generations'][0]
        component=self.write('metadata/authored22-component-review.json',{'test_fixture_only':True,'scope':'authored mechanical transaction only'})
        pin=self.write('metadata/authored22-parent-pin.json',{'test_fixture_only':True,'scope':'mechanical handoff only'})
        runtime={'source_identity':accounting.source_identity(self.root)}
        for key,path in (('bridge',self.bridge_path),('proof_review',self.proof_path),('review_check',self.review_check_path),('component_review',component),('parent_pin',pin)):
            runtime[key]={'path':path.relative_to(self.root).as_posix(),'sha256':sha(path)}
        bound=dict(owner,generation_id='authored22-bound',status='prospective-bound',runtime_binding=runtime,parent_generation_sha256=canonical(owner),
            launch_forecast={'nonprocess_seconds':100.0,'final_review_seconds':80.0,'remaining_engineering_seconds':20.0,
                'process_seconds':1794.756,'closeout_seconds':120.0})
        accounting.install_d125_owner(ledger,generation=bound,boot_identity=BOOT,project_root=self.root)
        accounting.admit_d125_forecast(ledger,activity_id='d125-authored-prospective-full-forecast',nonprocess_seconds=100,
            process_seconds=1794.756,boot_identity=BOOT,project_root=self.root)
        self.forecast_mutations(accounting,ledger,bridge)
        return bridge

    def forecast_mutations(self,accounting,ledger,bridge):
        """Real launch consumer, before any durable process reservation."""
        protected=ledger.read_bytes();baseline=json.loads(protected)
        for name,mutate in (
                ('missing-status',lambda r:r.pop('status')),
                ('denied-status',lambda r:r.update(status='denied')),
                ('missing-process-reserve',lambda r:r.pop('process_seconds')),
                ('zero-final-review-forecast',lambda r:r.update(nonprocess_seconds=0)),
                ('zero-closeout',lambda r:r.update(closeout_seconds=0)),
                ('stale-source',lambda r:r.update(source_identity='0'*64)),
                ('stale-generation',lambda r:r.update(generation_id='old-owner')),
                ('tampered-forecast-digest',lambda r:r.update(launch_forecast_sha256='0'*64))):
            value=copy.deepcopy(baseline);mutate(value['d125_admissions'][-1]);accounting._write(ledger,value)
            try:
                accounting.authorize_launch(ledger,purpose='tank-continuation',plan='06-14',case=accounting.D125_CASES[0],
                    source_identity=accounting.source_identity(self.root),current_source_identity=accounting.source_identity(self.root),
                    contract_identity=bridge['bridge_sha256'],target_signature=accounting.PEA_SIGNATURE,
                    launcher=lambda _: (_ for _ in ()).throw(RuntimeError('invalid-forecast-reached-execution-leaf')),
                    boot_identity=BOOT,allowed_root=self.root)
            except accounting.AccountingError as exc:
                if str(exc)!='d125-launch-forecast-invalid':raise
                self.progress_checks.append({'case':'real-authorizer-forecast-'+name,'passed':True,'rejection':str(exc)})
                self.write('output/failed-forecast-'+name+'.json',json.loads(ledger.read_bytes()))
            else:raise RuntimeError('invalid-forecast-admitted:'+name)
            finally:ledger.write_bytes(protected)
        for name,change in (('stale-time',{'admitted_at_monotonic':accounting.time.monotonic()-61}),
                ('rollback-time',{'admitted_at_monotonic':accounting.time.monotonic()+10}),
                ('wellformed-zero-nonprocess',{'nonprocess_seconds':0}),('wellformed-reduced-process',{'process_seconds':1793.756}),
                ('wellformed-zero-closeout',{'closeout_seconds':0})):
            value=copy.deepcopy(baseline);row=value['d125_admissions'][-1];row.update(change)
            event=next(e for e in value['d125_owner_events'] if e.get('event')=='forecast-admitted' and e.get('activity_id')==row['activity_id'])
            event['admission_sha256']=canonical(row);accounting._write(ledger,value)
            try:
                accounting.authorize_launch(ledger,purpose='tank-continuation',plan='06-14',case=accounting.D125_CASES[0],
                    source_identity=accounting.source_identity(self.root),current_source_identity=accounting.source_identity(self.root),
                    contract_identity=bridge['bridge_sha256'],target_signature=accounting.PEA_SIGNATURE,
                    launcher=lambda _: (_ for _ in ()).throw(RuntimeError('stale-forecast-reached-execution-leaf')),boot_identity=BOOT,allowed_root=self.root)
            except accounting.AccountingError as exc:
                if str(exc)!='d125-launch-forecast-stale-or-incomplete':raise
                self.progress_checks.append({'case':'real-authorizer-forecast-'+name,'passed':True,'rejection':str(exc)})
                self.write('output/failed-forecast-'+name+'.json',json.loads(ledger.read_bytes()))
            else:raise RuntimeError('stale-forecast-admitted:'+name)
            finally:ledger.write_bytes(protected)

    def accounting_cases(self, loaded):
        import math
        accounting = loaded['coordinator'].accounting
        ledger, baseline = self.authored_owner(accounting)
        checks = self.progress_checks
        def positive(name, passed):
            if not passed:
                raise RuntimeError('accounting-oracle-failed:' + name)
            checks.append({'case': name, 'passed': True})
        def rejects(name, callback, reason):
            try:
                callback()
            except accounting.AccountingError as exc:
                if str(exc) != reason:
                    raise RuntimeError('accounting-wrong-rejection:' + name + ':' + str(exc)) from exc
                checks.append({'case': name, 'passed': True, 'rejection': reason})
            else:
                raise RuntimeError('accounting-mutation-survived:' + name)
        now = baseline['phase6_accounting']['active_anchor']['monotonic_started_at']
        def remaining(value=baseline, stamp=now, boot=BOOT):
            return accounting.d125_remaining(value, monotonic_now=stamp, boot_identity=boot, project_root=self.root)
        def admit(value, case=accounting.D125_CASES[0]):
            return accounting._d125_process_preflight(value, case=case, monotonic_now=now, boot_identity=BOOT, project_root=self.root)
        balance = remaining()
        positive('exact-inherited-floors-no-invented-processes', balance['process_used_seconds'] == 5.244 and
            balance['pea_used_seconds'] == 7097.572 and balance['attempts_used'] == 1 and not baseline['records'][1:])
        positive('global-only-engineering', remaining(stamp=now+30)['global_used_seconds'] - balance['global_used_seconds'] == 30 and
            remaining(stamp=now+30)['pea_used_seconds'] == balance['pea_used_seconds'])
        positive('preserved-terminal-policy-and-bootstrap', baseline['d124_recovery_policy']['status'] == 'halted-scope-breach' and
            baseline['d125_recovery_policy']['status'].startswith('terminal-') and len(baseline['d125_owner_generations']) == 2)
        positive('spent-notaccepted-without-reservation-or-attempt', len(baseline['d125_spent_purposes']) == 2 and
            all(r['attempts_added'] == 0 and r['production_reservation_created'] is False for r in baseline['d125_spent_purposes']))
        for amount, admitted in ((599.999,False),(599.9999,False),(600.0,True),(600.001,True)):
            value = copy.deepcopy(baseline)
            value['records'].append({'d125_owner':'06-22','case':accounting.D125_CASES[0], 'status':'completed',
                'process_active_seconds': 1794.756 - amount, 'new_target_attempts':1})
            if admitted:
                positive('next600-' + str(amount), admit(value,accounting.D125_CASES[1])['process_remaining_seconds'] >= 600)
            else:
                rejects('next600-' + str(amount),lambda v=value:admit(v,accounting.D125_CASES[1]),'d125-next600-headroom-insufficient')
        for spent, admitted in ((600,False),(590,True)):
            value = copy.deepcopy(baseline)
            value['records'] += [{'d125_owner':'06-22','case':case,'status':'completed','process_active_seconds':spent,
                'new_target_attempts':int(i==0)} for i,case in enumerate(accounting.D125_CASES[:2])]
            if admitted:
                positive('serial590-590-next600',admit(value,accounting.D125_CASES[2])['process_remaining_seconds'] >= 600)
            else:
                rejects('serial600-600-next600',lambda:admit(value,accounting.D125_CASES[2]),'d125-next600-headroom-insufficient')
        rejects('old-quarantined-purpose',lambda:admit(baseline,'control-repeat-1'),'d125-process-purpose-not-selected')
        value = copy.deepcopy(baseline);value['records'].append({'d125_owner':'06-22','case':accounting.D125_CASES[0], 'status':'reserved'})
        rejects('active-process-overlap',lambda:admit(value),'d125-process-already-active')
        value = copy.deepcopy(baseline);value['records'].append({'d125_owner':'06-22','case':accounting.D125_CASES[0], 'status':'interrupted'})
        rejects('timeout-spent-no-retry',lambda:admit(value),'d125-process-replayed-or-out-of-order')
        value = copy.deepcopy(baseline);value['d125_owner_generations'].append(value['d125_owner_generations'][0])
        rejects('ambiguous-owner',lambda:remaining(value),'d125-owner-ambiguous')
        value = copy.deepcopy(baseline);value['d125_owner_events'].append({'event':'terminal','generation_id':'authored22-bound'})
        rejects('terminal-owner',lambda:remaining(value),'d125-owner-terminal')
        rejects('reboot',lambda:remaining(boot='different-boot'),'d125-boot-identity-mismatch')
        rejects('clock-rollback',lambda:remaining(stamp=now-1),'active-clock-anchor-mismatch-or-reboot')
        for invalid in (True,False,float('nan'),float('inf'),-float('inf')):
            rejects('nonfinite-or-boolean-' + str(invalid),lambda v=invalid:remaining(stamp=v),'d125-monotonic-now-invalid')
        for key in ('bridge','proof_review','review_check','component_review','parent_pin'):
            value = copy.deepcopy(baseline);value['d125_owner_generations'][-1]['runtime_binding'][key]['sha256'] = '0'*64
            value['d125_owner_events'][0]['generation_sha256'] = canonical(value['d125_owner_generations'][-1])
            rejects('stale-tuple-'+key,lambda v=value:admit(v),'d125-owner-tuple-stale:'+key)
        value=copy.deepcopy(baseline);value['records'] += [
            {'d125_owner':'06-22','process_active_seconds':-1}, {'d125_owner':'06-22','process_active_seconds':2}]
        rejects('negative-charge-cannot-hide-in-sum',lambda:remaining(value),'d125-negative-process-charge')
        value=copy.deepcopy(baseline);value['d125_owner_generations'][0]['attempts_floor']=True
        rejects('bootstrap-mutation-invalidates-lineage',lambda:remaining(value),'d125-owner-lineage-stale')
        original_authority=accounting.TEST_FIXTURE_D125_AUTHORITY
        accounting.TEST_FIXTURE_D125_AUTHORITY=None
        rejects('fixture-marker-alone-denied',lambda:remaining(),'d125-fixture-authority-required')
        accounting.TEST_FIXTURE_D125_AUTHORITY=original_authority
        checkout=next(p for p in self.root.parents if (p/'.git').exists())
        rejects('fixture-authority-on-production-root-denied',lambda:accounting.selected_recovery_owner(baseline,project_root=checkout),
            'd125-fixture-authority-denied')
        for invalid in (True,float('nan'),float('inf'),-1):
            reason = 'd125-forecast-nonprocess-invalid' if invalid != -1 else 'd125-forecast-invalid'
            rejects('invalid-forecast-' + str(invalid), lambda v=invalid:accounting.admit_d125_forecast(ledger,
                activity_id='d125-invalid',nonprocess_seconds=v,process_seconds=1794.756,boot_identity=BOOT,project_root=self.root),reason)
        forecast = accounting.admit_d125_forecast(ledger,activity_id='d125-authored-forecast',nonprocess_seconds=100,
            process_seconds=1794.756,boot_identity=BOOT,project_root=self.root)
        positive('complete-forecast-includes-final-review',forecast['process_seconds']==1794.756 and forecast['closeout_seconds']==120)
        rejects('forecast-replayed',lambda:accounting.admit_d125_forecast(ledger,activity_id='d125-authored-forecast',nonprocess_seconds=100,
            process_seconds=1794.756,boot_identity=BOOT,project_root=self.root),'d125-forecast-replayed')
        accounting.begin_d125_activity(ledger,activity_id='d125-authored-batch',stage='fixture',exposure_seconds=30,boot_identity=BOOT,project_root=self.root)
        rejects('concurrent-batch',lambda:accounting.begin_d125_activity(ledger,activity_id='d125-second-batch',stage='fixture',exposure_seconds=30,
            boot_identity=BOOT,project_root=self.root),'d125-activity-already-active')
        row=accounting.finalize_d125_activity(ledger,activity_id='d125-authored-batch',status='completed',boot_identity=BOOT,allowed_root=self.root)
        positive('batch-wall-global-once-no-child-addition',row['pea_charge_seconds']==0 and row['elapsed_seconds']>=0)
        rejects('finalize-replayed',lambda:accounting.finalize_d125_activity(ledger,activity_id='d125-authored-batch',status='completed',
            boot_identity=BOOT,allowed_root=self.root),'d125-activity-not-live-or-replayed')
        accounting.begin_d125_activity(ledger,activity_id='d125-authored-timeout',stage='fixture-timeout',exposure_seconds=1e-12,
            boot_identity=BOOT,project_root=self.root)
        rejects('timeout-marked-spent',lambda:accounting.finalize_d125_activity(ledger,activity_id='d125-authored-timeout',status='completed',
            boot_identity=BOOT,allowed_root=self.root),'d125-exposure-exceeded')
        rejects('timeout-cannot-retry',lambda:accounting.begin_d125_activity(ledger,activity_id='d125-authored-timeout',stage='fixture-timeout',
            exposure_seconds=30,boot_identity=BOOT,project_root=self.root),'d125-activity-replayed')
        old=accounting._load(ledger,self.root)
        historical=canonical({k:old[k] for k in ('d124_recovery_policy','d125_recovery_policy','d125_owner_generations')})
        close_path=self.root/'output/authored-accounting-close.json'
        closed=accounting.close_d125_owner(ledger,output=close_path,status='HALTED',reason='authored terminal-accounting oracle only',
            boot_identity=BOOT,project_root=self.root)
        latest=accounting._load(ledger,self.root)
        positive('terminal-close-once-global-only',latest['phase6_accounting']['active_anchor'] is None and closed['closure']['parent_allowance_seconds']==120 and
            closed['accounting']['pea_used_seconds']==7097.572 and closed['accounting']['process_used_seconds']==5.244 and
            closed['accounting']['attempts_used']==1 and closed['accounting']['global_used_seconds']>=28288.671+120)
        positive('terminal-preserves-historical-policies-and-generations',historical==canonical({k:latest[k] for k in
            ('d124_recovery_policy','d125_recovery_policy','d125_owner_generations')}))
        rejects('terminal-close-replay-denied',lambda:accounting.close_d125_owner(ledger,output=close_path,status='HALTED',reason='replay',
            boot_identity=BOOT,project_root=self.root),'d124-anchor-output-exists-or-symlink')
        return {'checks':checks,'fake_leaf_calls':self.calls,'expected_denied_requests':0,'test_fixture_only':True}

    def expanded_case(self, loaded, case, boundary, monitor):
        import os
        if case=='prospective-chain':
            bridge=self.prepare_prospective(loaded)
            forecast_checks=list(self.progress_checks)
            result=self.finish_transaction(loaded,bridge)
            result['checks']=forecast_checks+result['checks']
            self.progress_checks=result['checks']
            accounting=loaded['coordinator'].accounting
            ledger_path=self.root/'evidence/phase6-repairs.json'
            ledger=accounting._load(ledger_path,self.root)
            rows=[r for r in ledger['records'] if r.get('d125_owner')=='06-22']
            result['checks'].append({'case':'exact-fresh-prospective-purpose-lineage','passed':[r['case'] for r in rows]==
                list(loaded['coordinator'].accounting.D125_CASES) and all(r['generation_id']=='authored22-bound' for r in rows)})
            for old_case in ('tank-pea-continuation-1','control-repeat-1','control-repeat-2'):
                try:accounting._authorization(ledger,purpose='tank-continuation' if old_case.startswith('tank') else 'tank-continuation-control',
                    plan='06-14',case=old_case,target_signature=accounting.PEA_SIGNATURE if old_case.startswith('tank') else None)
                except accounting.AccountingError as exc:
                    if str(exc)!='d125-selected-scope-denied':raise
                    result['checks'].append({'case':'quarantined-case-denied:'+old_case,'passed':True,'rejection':str(exc)})
                else:raise RuntimeError('quarantined-case-admitted')
            checker=loaded['checker']
            receipt_path=self.root/'output/authored-receipt.json'
            receipt=json.loads(receipt_path.read_bytes())
            invalid=copy.deepcopy(receipt);invalid['rec_processes']=False
            try:checker.validate_receipt_data(invalid,bridge,root=self.root)
            except ValueError as exc:
                if str(exc)!='continuation-observed-process-metadata-invalid':raise
                result['checks'].append({'case':'boolean-process-count-denied','passed':True,'rejection':str(exc)})
            else:raise RuntimeError('boolean-process-count-admitted')
            protected=ledger_path.read_bytes()
            value=copy.deepcopy(ledger);value['d125_owner_generations'].append(value['d125_owner_generations'][-1])
            try:accounting.selected_recovery_owner(value,project_root=self.root,require_runtime=True)
            except accounting.AccountingError as exc:
                if str(exc)!='d125-owner-ambiguous':raise
                result['checks'].append({'case':'prospective-consumer-ambiguous-owner-denied','passed':True,'rejection':str(exc)})
            else:raise RuntimeError('ambiguous-prospective-owner-admitted')
            # Exercise fresh prospective publication lock, including stale
            # ledger, source and selected tuple, after initial recomputation.
            original=accounting._locked;source_path=self.root/'src/authored.c';source_bytes=source_path.read_bytes()
            review_bytes=self.proof_path.read_bytes();mutation={'kind':None,'observed':False}
            @contextlib.contextmanager
            def swapped(path):
                with original(path):
                    if mutation['kind']=='ledger':
                        value=accounting._load(path,self.root);value['d125_owner_events'].append({'event':'authored-concurrent-swap'})
                        accounting._write(path,value)
                    elif mutation['kind']=='source':source_path.write_bytes(source_bytes+b'/* source swap */\n')
                    elif mutation['kind']=='tuple':self.proof_path.write_bytes(review_bytes+b'\nswapped\n')
                    mutation['observed']=True
                    yield
            saved=self.bind
            def bind(relative,module,bindings):
                saved(relative,module,bindings)
                if relative=='scripts/evidence/phase6_accounting.py':module._locked=swapped
            self.synthetic['bind_instance']=bind
            for kind,reason in (('ledger','d125-source-ledger-receipt-or-review-drift-under-lock'),
                    ('source','d125-owner-source-stale'),('tuple','d125-owner-tuple-stale:proof_review')):
                mutation.update(kind=kind,observed=False);output=self.root/('output/prospective-'+kind+'-rejected.json')
                try:checker.verify_receipt_file(receipt_path,self.bridge_path,self.proof_path,self.root/'build/phase6',output,
                    self.root/'evidence/authored-final-review.json',self.review_check_path)
                except (ValueError,RuntimeError) as exc:
                    if str(exc)!=reason:raise
                    result['checks'].append({'case':'prospective-under-lock-'+kind+'-rejected','passed':mutation['observed'] and not output.exists(),'rejection':str(exc)})
                else:raise RuntimeError('prospective-under-lock-'+kind+'-survived')
                finally:ledger_path.write_bytes(protected);source_path.write_bytes(source_bytes);self.proof_path.write_bytes(review_bytes)
            import sys
            from unittest.mock import patch
            failed_path=self.root/'output/authored-continuation-halt.json'
            original_calls=list(self.calls)
            for repeat in range(2):
                before=failed_path.read_bytes() if failed_path.exists() else None
                captured=io.StringIO()
                with contextlib.redirect_stdout(captured),patch.object(sys,'argv',['phase6_repairs.py','--tank-continuation-once',
                        '--build',str(self.root/'build/phase6'),'--bridge',str(self.bridge_path),'--proof-review',str(self.proof_path),
                        '--review-check',str(self.review_check_path),'--output',str(failed_path)]):
                    code=loaded['coordinator'].main()
                failed=json.loads(failed_path.read_bytes())
                passed=(code==1 and failed['status']=='HALTED' and failed['reason']=='d125-activity-replayed' and
                    failed['planned_denominator']=={'tank':1,'control_parents':2,'native_control_children':12,'full_pcm_files':12} and
                    self.calls==original_calls and (before is None or failed_path.read_bytes()==before))
                result['checks'].append({'case':'real-coordinator-failure-envelope-'+str(repeat),'passed':passed})
            if not all(c['passed'] for c in result['checks']):raise RuntimeError('prospective-chain-oracle-failed')
            return result
        if case in ('selected-authority','lock-serial'):
            result = self.accounting_cases(loaded)
            if case == 'lock-serial':
                import fcntl
                import tempfile
                accounting=loaded['coordinator'].accounting
                path=self.root/'evidence/phase6-repairs.json'
                with accounting._locked(path):
                    lock_name=hashlib.sha256(str(path).encode()).hexdigest()
                    with (pathlib.Path(tempfile.gettempdir())/('genewhip-phase6-accounting-'+lock_name+'.lock')).open('a') as stream:
                        try:
                            fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                        except BlockingIOError:
                            result['checks'].append({'case':'actual-lock-excludes-second-writer','passed':True})
                        else:
                            raise RuntimeError('actual-lock-second-writer-admitted')
            return result
        if case == 'controlled-denial':
            import subprocess
            original=boundary._originals[(id(subprocess),'Popen')]
            try:
                original(['unavailable-d125-probe'])
            except RuntimeError as exc:
                if str(exc) != 'process-denied:audit:subprocess.Popen':
                    raise
            else:
                raise RuntimeError('cached-alias-not-denied')
            return {'checks':[{'case':'cached-original-denied-before-os-launch','passed':boundary.violation_count==1 and monitor.process_events==0}],
                'expected_denied_requests':1,'fake_leaf_calls':[],'test_fixture_only':True}
        if case == 'binding-negative':
            module=next(m for p,m in loaded['modules'] if p=='tests/fixtures/phase4_game.py') if any(
                p=='tests/fixtures/phase4_game.py' for p,m in loaded['modules']) else None
            # Force the finite real loader edge, whose returned instance is bound.
            spec=__import__('importlib.util',fromlist=['util']).spec_from_file_location('binding_negative_phase4',self.root/'tests/fixtures/phase4_game.py')
            module=__import__('importlib.util',fromlist=['util']).module_from_spec(spec);spec.loader.exec_module(module)
            original=next(value for m,name,value in self.originals if m is module and name=='bounded_run')
            module.bounded_run=original
            try:self.check_instance('tests/fixtures/phase4_game.py',module)
            except RuntimeError as exc:
                rejected=str(exc)=='execution-leaf-instance-binding-invalid:tests/fixtures/phase4_game.py'
            else:rejected=False
            if not rejected or self.calls:
                raise RuntimeError('wrong-leaf-binding-not-rejected')
            checks=[{'case':'wrong-actual-instance-binding-rejected-preflight','passed':True}]
            import importlib.util
            unknown=self.write('metadata/unknown-edge.py',b'raise RuntimeError("must-never-execute")\n')
            try:importlib.util.spec_from_file_location('unknown_edge',unknown)
            except RuntimeError as exc:
                if str(exc)!='unknown-or-drifted-consumer-source:metadata/unknown-edge.py':raise
                checks.append({'case':'unknown-dynamic-edge-rejected-before-exec','passed':True,'rejection':str(exc)})
            else:raise RuntimeError('unknown-edge-admitted')
            target=self.root/'tests/fixtures/phase4_game.py';raw=target.read_bytes()
            target.write_bytes(raw+b'\n# drifted source\n')
            try:importlib.util.spec_from_file_location('drifted_edge',target)
            except RuntimeError as exc:
                if str(exc)!='unknown-or-drifted-consumer-source:tests/fixtures/phase4_game.py':raise
                checks.append({'case':'dynamic-source-drift-rejected-before-exec','passed':True,'rejection':str(exc)})
            else:raise RuntimeError('drifted-edge-admitted')
            finally:target.write_bytes(raw)
            return {'checks':checks,
                'expected_denied_requests':0,'fake_leaf_calls':[],'test_fixture_only':True}
        bridge=self.prepare_transaction(loaded)
        result=self.finish_transaction(loaded,bridge)
        self.progress_checks=result['checks']
        checker=loaded['checker'];accounting=loaded['coordinator'].accounting
        receipt=json.loads((self.root/'output/authored-receipt.json').read_bytes())
        def reject(name, callback, reason):
            try:callback()
            except ValueError as exc:
                if str(exc)!=reason:raise RuntimeError('wrong-mutation-rejection:'+name+':'+str(exc)) from exc
            else:raise RuntimeError('mutation-survived:'+name)
            result['checks'].append({'case':name,'passed':True,'rejection':reason})
        if case=='denominator-numeric':
            for label,mutate,reason in (
                ('missing-control',lambda r:r['controls'].pop(),'control-driver-denominator-invalid'),
                ('forged-zero-launch-count',lambda r:r.update(launches=0),'continuation-observed-process-metadata-invalid'),
                ('missing-native-child',lambda r:r['controls'][0]['native_child_processes'].pop(),'control-six-case-child-denominator-invalid'),
                ('missing-control-row',lambda r:r['controls'][0]['results'].pop(),'control-six-case-child-denominator-invalid')):
                value=copy.deepcopy(receipt);mutate(value)
                reject(label,lambda v=value:checker.validate_receipt_data(v,bridge,root=self.root),reason)
            pcm=self.root/receipt['controls'][0]['results'][0]['retained_pcm']['path'];raw=pcm.read_bytes()
            pcm.write_bytes(b'altered')
            reject('altered-full-pcm',lambda:checker.validate_receipt_data(receipt,bridge,root=self.root),'control-pcm-missing-or-changed')
            pcm.write_bytes(raw)
            missing=pcm.with_suffix('.temporarily-missing');pcm.rename(missing)
            try:checker.validate_receipt_data(receipt,bridge,root=self.root)
            except FileNotFoundError as exc:
                if pathlib.Path(exc.filename)!=pcm:raise
                result['checks'].append({'case':'missing-pcm-specific-path-rejected','passed':True,'rejection':'FileNotFoundError:'+pcm.relative_to(self.root).as_posix()})
            else:raise RuntimeError('missing-pcm-survived')
            finally:missing.rename(pcm)
        elif case=='filesystem-publication':
            target=self.root/'output/authored-checked.json';before=target.read_bytes()
            try:checker._atomic_publish_checked_output(target,b'collision')
            except (ValueError,FileExistsError):pass
            else:raise RuntimeError('checked-output-collision-survived')
            result['checks'].append({'case':'create-once-protected-publication','passed':target.read_bytes()==before})
            link=self.root/'output/escape-link.json';link.symlink_to(target)
            reject('symlink-retained-escape',lambda:checker.safe_retained_path(link.relative_to(self.root).as_posix(),self.root),'retained-path-symlink-denied')
            hardlink=self.root/'output/hardlink-checked.json';os.link(target,hardlink)
            reject('hardlink-checked-output-rejected',lambda:checker._atomic_publish_checked_output(hardlink,b'collision'),
                'checked-output-existing-object-not-private-regular-file')
            hardlink.unlink()
        elif case=='replay-quarantine':
            try:
                accounting.authorize_launch(self.root/'evidence/phase6-repairs.json',purpose='tank-continuation',plan='06-14',
                    case=accounting.TANK_CONTINUATION_CASE,source_identity=accounting.source_identity(self.root),current_source_identity=accounting.source_identity(self.root),
                    contract_identity=bridge['bridge_sha256'],target_signature=accounting.PEA_SIGNATURE,
                    launcher=lambda _: (_ for _ in ()).throw(RuntimeError('replay-reached-leaf')),boot_identity=BOOT,allowed_root=self.root)
            except accounting.AccountingError as exc:
                if str(exc)!='duplicate-reservation':raise
            else:raise RuntimeError('duplicate-reservation-survived')
            result['checks'].append({'case':'actual-reservation-replay-rejected','passed':True,'rejection':'duplicate-reservation'})
        elif case=='historical-locked-swap':
            original=accounting._locked
            mutation={'observed':False,'kind':None}
            ledger_path=self.root/'evidence/phase6-repairs.json'
            protected_ledger=ledger_path.read_bytes()
            source_path=self.root/'src/authored.c';protected_source=source_path.read_bytes()
            protected_review=self.proof_path.read_bytes()
            # Exercise the real publisher's lock; the injection only changes
            # authored data after acquisition, never its validator result.
            @contextlib.contextmanager
            def changed(path):
                with original(path):
                    if mutation['kind']=='pointer':
                        value=accounting._load(path,self.root)
                        value['current_tank_continuation_receipt']['capture_sha256']='0'*64
                        accounting._write(path,value)
                    elif mutation['kind']=='source':source_path.write_bytes(protected_source+b'/* swapped */\n')
                    elif mutation['kind']=='tuple':self.proof_path.write_bytes(protected_review+b'\nswapped review\n')
                    mutation['observed']=True
                    yield
            # Publisher dynamically loads accounting; bind the injection on
            # each returned instance, preserving the actual lock implementation.
            saved=self.bind
            def bind(relative,module,bindings):
                saved(relative,module,bindings)
                if relative=='scripts/evidence/phase6_accounting.py':module._locked=changed
            self.synthetic['bind_instance']=bind
            for kind,reason in (('pointer','ledger-capture-pointer-changed-during-check'),
                    ('source','checked-receipt-source-or-review-drift-before-promotion'),
                    ('tuple','selected-bridge-or-proof-review-drift-before-promotion')):
                mutation.update(kind=kind,observed=False)
                target=self.root/('output/locked-'+kind+'-checked.json')
                try:
                    checker.verify_receipt_file(self.root/'output/authored-receipt.json',self.bridge_path,self.proof_path,
                        self.root/'build/phase6',target,self.root/'evidence/authored-final-review.json',self.review_check_path)
                except ValueError as exc:
                    if str(exc)!=reason:raise
                    result['checks'].append({'case':'actual-under-lock-'+kind+'-swap-rejected','passed':mutation['observed'] and not target.exists(),
                        'rejection':str(exc)})
                else:raise RuntimeError('locked-'+kind+'-swap-survived')
                finally:
                    ledger_path.write_bytes(protected_ledger);source_path.write_bytes(protected_source);self.proof_path.write_bytes(protected_review)
        else:raise RuntimeError('unknown-expanded-case:'+str(case))
        if not all(row['passed'] for row in result['checks']):raise RuntimeError('expanded-oracle-failed')
        return result

    def prepare_qualification23(self, loaded):
        """Engineering23 exercises historical runtime mechanics only in inert roots."""
        self.qualification23_accounting_checks(loaded)
        bridge = self.prepare_prospective(loaded)
        self.progress_checks.append({'case': 'qualification23-authored-root-only',
            'passed': json.loads((self.root/'metadata/d125-authored-root.json').read_bytes()).get('test_fixture_only') is True
                and (self.root/'fixtures/phase5-a/game.bin').read_bytes().startswith(b'UNUSABLE-AUTHORED-')})
        return bridge

    def qualification23_accounting_checks(self, loaded):
        """Call the actual new selector on live read-only metadata and mutated copies."""
        accounting=loaded['coordinator'].accounting
        project=next(p for p in self.root.parents if (p/'.git').exists())
        live=json.loads((project/'evidence/phase6-repairs.json').read_bytes())
        protected=sha(project/'evidence/phase6-repairs.json')
        owner=accounting.qualification23_owner(live,project_root=project)
        checks=[{'case':'actual-qualification23-live-selector-engineering-only','passed':owner['game_admission'] is False}]
        def rejects(name,value,reason):
            try:accounting.qualification23_owner(value,project_root=project)
            except accounting.AccountingError as exc:
                if str(exc)!=reason:raise RuntimeError('qualification23-wrong-rejection:'+name+':'+str(exc)) from exc
            else:raise RuntimeError('qualification23-negative-survived:'+name)
            checks.append({'case':name,'passed':True,'rejection':reason})
        for name,key,value in (('game-admission','game_admission',True),('boolean-attempt','attempts_floor',True),
                               ('wrong-floor','process_floor_seconds',5.864),('terminal-replay','status','terminal-halted')):
            changed=copy.deepcopy(live);changed['d125_qualification23_policy'][key]=value
            rejects(name,changed,'qualification23-policy-invalid-or-terminal')
        changed=copy.deepcopy(live);changed['test_fixture_only']=True
        rejects('fixture-on-live',changed,'qualification23-live-fixture-authority-denied')
        changed=copy.deepcopy(live);changed['phase6_accounting']['active_anchor']=None
        rejects('missing-anchor',changed,'qualification23-anchor-invalid')
        changed=copy.deepcopy(live);changed['d125_qualification23_policy']['bindings']={}
        rejects('missing-plan-binding',changed,'qualification23-plan-binding-stale')
        now=accounting.time.monotonic()
        remaining=43200-accounting._closed_seconds(live['phase6_accounting'])-accounting._active_elapsed(live['phase6_accounting'],now,owner['boot_identity'])
        threshold=remaining-1794.135-120
        for delta in (-0.001,0.001):
            try:accounting._qualification23_headroom(live,owner,now,threshold+delta)
            except accounting.AccountingError as exc:
                if delta<0 or str(exc)!='qualification23-complete-forecast-and-reserves-insufficient':raise
            else:
                if delta>0:raise RuntimeError('qualification23-threshold-overrun-survived')
            checks.append({'case':'whole-forecast-threshold-'+str(delta),'passed':True})
        for number in (-1,float('nan'),float('inf'),True):
            try:accounting._qualification23_headroom(live,owner,now,number)
            except accounting.AccountingError:pass
            else:raise RuntimeError('qualification23-nonfinite-negative-or-bool-survived')
            checks.append({'case':'invalid-complete-forecast-'+str(number),'passed':True})
        for case in (*accounting.D125_CASES,'rec','reference'):
            try:accounting._authorization(live,purpose='tank-continuation',plan='06-23',case=case,target_signature=accounting.PEA_SIGNATURE)
            except accounting.AccountingError as exc:reason=str(exc)
            else:raise RuntimeError('qualification23-live-game-purpose-admitted:'+case)
            checks.append({'case':'live-runtime-denied:'+case,'passed':True,'rejection':reason})
        if sha(project/'evidence/phase6-repairs.json')!=protected:
            raise RuntimeError('qualification23-read-only-tests-mutated-live-ledger')
        self.progress_checks.extend(checks)

    def qualification23_chain(self, loaded, args, boundary, monitor):
        if args.engineering_owner != '06-23':
            raise RuntimeError('qualification23-explicit-engineering-owner-required')
        if args.case == 'qualification23-negatives':
            if args.negative_family is None:
                raise RuntimeError('qualification23-named-negative-family-required')
            return self.qualification23_negatives(loaded,args.negative_family,boundary,monitor)
        if args.case == 'qualification23-final':
            if (not getattr(self,'current_qualification23_tuple',None) or
                    self.current_qualification23_tuple.get('game_admission') is not False or
                    self.current_qualification23_tuple.get('qualification_count')!=3):
                raise RuntimeError('qualification23-final-current-tuple-not-qualified')
            self.qualification23_accounting_checks(loaded)
            previous=list(self.progress_checks)
            result=self.expanded_case(loaded,'prospective-chain',boundary,monitor)
            result['checks']=previous+result['checks']
            result.update(engineering_owner='06-23',game_admission=False,current_qualification23_tuple=self.current_qualification23_tuple)
            bridge=json.loads(self.bridge_path.read_bytes())
            result['checks'].append({'case':'exact-current-tuple-through-actual-coordinator-checker-publication',
                'passed':bridge.get('qualification23_current_evidence')==self.current_qualification23_tuple})
            if not all(c['passed'] for c in result['checks']):raise RuntimeError('qualification23-final-oracle-failed')
            return result
        bridge = self.prepare_qualification23(loaded)
        earlier = list(self.progress_checks)
        result = self.finish_transaction(loaded,bridge)
        result['checks'] = earlier + result['checks']
        result.update(engineering_owner='06-23',game_admission=False,
                      evidence_scope='test_fixture_only authored runtime mechanics')
        if args.case == 'qualification23-final':
            result['current_qualification23_tuple']=self.current_qualification23_tuple
            result['checks'].append({'case':'exact-current-tuple-through-actual-coordinator-checker-publication',
                'passed':bridge.get('qualification23_current_evidence')==self.current_qualification23_tuple})
        if not all(c['passed'] for c in result['checks']):
            raise RuntimeError('qualification23-chain-oracle-failed')
        return result

    def qualification23_negatives(self, loaded, family, boundary, monitor):
        result = self.expanded_case(loaded,family,boundary,monitor)
        result.update(engineering_owner='06-23',game_admission=False,negative_family=family)
        return result
