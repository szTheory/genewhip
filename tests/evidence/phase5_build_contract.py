"""Black-box contract tests for the Phase 5 candidate build supervisor."""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import uuid
import unittest
import copy
import contextlib
import io
import os
import tempfile
import tarfile
from types import SimpleNamespace
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[2]
SUPERVISOR = ROOT / "scripts" / "fixtures" / "phase5_candidate.py"
sys.path.insert(0, str(ROOT / "tools" / "evidence"))
import phase5_records as records  # noqa: E402
sys.path.insert(0, str(ROOT / "scripts" / "fixtures"))
import phase5_candidate as supervisor  # noqa: E402


def _pre_d114_ledger_bytes():
    result = subprocess.run(['git', 'show', '8376129:fixtures/candidate-screening-v2.json'],
                            cwd=ROOT, capture_output=True, check=True, timeout=10)
    return result.stdout


class CurrentPolicyContract(unittest.TestCase):
    def test_recursion_d114_authorization_is_bound_consumed_once_and_terminal(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT / 'local-fixtures/phase5')))
        for relative in ('evidence/phase5-recursion-setup-authorization.json',
                         'evidence/phase5-recursion-setup-failure.json',
                         'evidence/phase5-enforcement.json',
                         'fixtures/candidate-screening-v2.json',
                         '.planning/phases/GW-05-candidate-admission-and-baseline/05-10-CONTINUATION.md'):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative == 'fixtures/candidate-screening-v2.json':
                target.write_bytes(_pre_d114_ledger_bytes())
            else:
                shutil.copyfile(ROOT / relative, target)
        ledger = json.loads((root / 'fixtures/candidate-screening-v2.json').read_bytes())
        eligibility = root / 'evidence/phase5-eligibility-v2.json'
        eligibility.write_bytes(b'eligibility fixture\n')
        config = {'title_id': 'recursion94', 'workspace': 'fresh'}
        with patch.object(supervisor, 'ROOT', root):
            attempt = supervisor._consume_recursion_setup_authorization(ledger, config, eligibility)
            self.assertEqual(attempt['events'][0]['kind'], 'started')
            supervisor._finish_recursion_setup_authorization(attempt, success=False,
                                                             elapsed_us=321, reason='fixture failure')
            saved = json.loads((root / supervisor.RECURSION_SETUP_ATTEMPT).read_bytes())
            self.assertEqual([event['kind'] for event in saved['events']], ['started', 'failed'])
            self.assertEqual(saved['events'][1]['elapsed_us'], 321)
            self.assertEqual(saved['events'][1]['previous_sha256'], saved['events'][0]['sha256'])
            with self.assertRaisesRegex(supervisor.GateError, 'already been consumed'):
                supervisor._consume_recursion_setup_authorization(ledger, config, eligibility)

    def test_recursion_d114_rejects_changed_prior_ledger_or_failed_receipt(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT / 'local-fixtures/phase5')))
        for relative in ('evidence/phase5-recursion-setup-authorization.json',
                         'evidence/phase5-recursion-setup-failure.json',
                         'fixtures/candidate-screening-v2.json',
                         '.planning/phases/GW-05-candidate-admission-and-baseline/05-10-CONTINUATION.md'):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative == 'fixtures/candidate-screening-v2.json':
                target.write_bytes(_pre_d114_ledger_bytes())
            else:
                shutil.copyfile(ROOT / relative, target)
        ledger = json.loads((root / 'fixtures/candidate-screening-v2.json').read_bytes())
        (root / 'fixtures/candidate-screening-v2.json').write_bytes(b'changed prior ledger')
        with patch.object(supervisor, 'ROOT', root), self.assertRaisesRegex(supervisor.GateError, 'prior_ledger_sha256'):
            supervisor._recursion_setup_authorization_bindings(ledger)

        (root / 'fixtures/candidate-screening-v2.json').write_bytes(_pre_d114_ledger_bytes())
        (root / 'evidence/phase5-recursion-setup-failure.json').write_bytes(b'changed failed receipt')
        with patch.object(supervisor, 'ROOT', root), self.assertRaisesRegex(supervisor.GateError, 'failed_setup_record_sha256'):
            supervisor._recursion_setup_authorization_bindings(ledger)

    def test_recursion_setup_output_accepts_only_confined_regular_tool_files(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        required = [(name, b'output-' + str(index).encode(), tarfile.REGTYPE)
                    for index, name in enumerate(supervisor.RECURSION_SETUP_REQUIRED_OUTPUTS)]
        required.append((supervisor.RECURSION_SETUP_LOG_OUTPUT, b'setup complete\n', tarfile.REGTYPE))
        required += [('.toolcache/python/lib/python3.12/os.py', b'stdlib', tarfile.REGTYPE)]
        required += [('.toolcache/python/lib/python3.12/asyncio', b'', tarfile.DIRTYPE),
                     ('.toolcache/python/lib/python3.12/email', b'', tarfile.DIRTYPE),
                     ('.toolcache/python/lib/python3.12/asyncio/__init__.py', b'', tarfile.REGTYPE)]
        valid = self._tank_tar(required)
        observed = supervisor._extract_recursion_setup_outputs(valid, root)
        self.assertEqual(set(observed), {name for name, _, kind in required if kind == tarfile.REGTYPE})
        self.assertEqual((root / supervisor.RECURSION_SETUP_REQUIRED_OUTPUTS[0]).read_bytes(), b'output-0')
        self.assertEqual(observed['.toolcache/python/lib/python3.12/asyncio/__init__.py']['sha256'],
                         hashlib.sha256(b'').hexdigest())
        invalid = ([('../escape', b'x', tarfile.REGTYPE)],
                   [('/absolute', b'x', tarfile.REGTYPE)],
                   [('.toolcache/../../escape', b'x', tarfile.REGTYPE)],
                   [('./.toolcache/python/lib/python3.12/os.py', b'alias', tarfile.REGTYPE)],
                   [('.toolcache//python/lib/python3.12/os.py', b'alias', tarfile.REGTYPE)],
                   [('.toolcache/link', b'', tarfile.SYMTYPE)],
                   [('.toolcache/empty', b'', tarfile.REGTYPE)],
                   [('.toolcache/src/unreviewed', b'x', tarfile.REGTYPE)],
                   [('.toolcache/python/bin/python3', b'alias', tarfile.REGTYPE)])
        for entries in invalid:
            with self.subTest(entries=entries), self.assertRaises(supervisor.GateError):
                supervisor._extract_recursion_setup_outputs(self._tank_tar(entries), root)
        with self.assertRaisesRegex(supervisor.GateError, 'omitted required tool outputs'):
            supervisor._extract_recursion_setup_outputs(self._tank_tar(required[1:]), root)
        empty_required = [(name, b'', tarfile.REGTYPE)
                          if name == supervisor.RECURSION_SETUP_REQUIRED_OUTPUTS[0]
                          else (name, data, kind) for name, data, kind in required]
        with self.assertRaisesRegex(supervisor.GateError, 'required setup output file is empty'):
            supervisor._extract_recursion_setup_outputs(self._tank_tar(empty_required), root)

    def test_recursion_setup_shell_preserves_failure_tail_and_exports_log_on_success(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(
            dir=ROOT / 'local-fixtures/phase5')))
        bin_dir = root / 'bin'
        bin_dir.mkdir()
        sha_tool = bin_dir / 'sha256sum'
        sha_tool.write_text(
            f'#!{sys.executable}\n'
            'import hashlib, sys\n'
            'for name in sys.argv[1:]:\n'
            '    with open(name, "rb") as stream: digest = hashlib.sha256(stream.read()).hexdigest()\n'
            '    print(digest, name)\n', encoding='utf-8')
        sha_tool.chmod(0o755)
        env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get('PATH', ''))

        failing_script = (
            b'#!/bin/sh\nmkdir -p .toolcache/identity\n'
            b'head -c 300000 /dev/zero | tr "\\000" x > .toolcache/identity/setup.log\n'
            b'printf "TAILMARK" >> .toolcache/identity/setup.log\nexit 37\n')
        fail_tar = self._tank_tar([('.phase5-setup.sh', failing_script, tarfile.REGTYPE)])
        failure = subprocess.run(
            ['/bin/sh', '-c', supervisor._recursion_setup_wrapper(
                hashlib.sha256(failing_script).hexdigest(), workdir='.', enforce_address_limit=False)],
            cwd=root, env=env, input=fail_tar, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False)
        self.assertEqual(failure.returncode, 37)
        self.assertEqual(failure.stdout, b'')
        self.assertEqual(len(failure.stderr), 256 * 1024)
        self.assertTrue(failure.stderr.endswith(b'TAILMARK'))

        successful_script = (
            b'#!/bin/sh\nmkdir -p .toolcache/identity\n'
            b'printf "setup complete\\n" > .toolcache/identity/setup.log\n')
        files = {name: b'test output' for name in supervisor.RECURSION_SETUP_REQUIRED_OUTPUTS}
        files['.toolcache/identity/native-tools.sha256'] = b'test tool hashes\n'
        files['.toolcache/python/lib/python3.12/os.py'] = b'os module\n'
        files['.toolcache/python/lib/python3.12/asyncio/__init__.py'] = b''
        files['.toolcache/src/do-not-export.txt'] = b'excluded compiler source fixture\n'
        directories = {'.toolcache', '.toolcache/bin', '.toolcache/lib', '.toolcache/identity',
                       '.toolcache/src',
                       '.toolcache/python', '.toolcache/python/bin', '.toolcache/python/lib',
                       '.toolcache/python/lib/python3.12', '.toolcache/python/lib/python3.12/asyncio'}
        success_input = io.BytesIO()
        with tarfile.open(fileobj=success_input, mode='w') as archive:
            script_member = tarfile.TarInfo('.phase5-setup.sh')
            script_member.size = len(successful_script)
            archive.addfile(script_member, io.BytesIO(successful_script))
            for name in sorted(directories):
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                archive.addfile(member)
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o755 if name in supervisor.RECURSION_SETUP_REQUIRED_OUTPUTS[:4] else 0o644
                archive.addfile(member, io.BytesIO(data))
        success = subprocess.run(
            ['/bin/sh', '-c', supervisor._recursion_setup_wrapper(
                hashlib.sha256(successful_script).hexdigest(), workdir='.', enforce_address_limit=False)],
            cwd=root, env=env, input=success_input.getvalue(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False)
        self.assertEqual(success.returncode, 0, success.stderr[-512:])
        self.assertEqual(success.stderr, b'')
        with tarfile.open(fileobj=io.BytesIO(success.stdout), mode='r:') as archive:
            names = {member.name for member in archive.getmembers()}
        self.assertIn(supervisor.RECURSION_SETUP_LOG_OUTPUT, names)
        self.assertIn('.toolcache/python/lib/python3.12/os.py', names)
        self.assertNotIn('.phase5-setup.sh', names)
        self.assertFalse(any(name.startswith('.toolcache/src/') for name in names))
        extracted = root / 'successful-extract'
        observed = supervisor._extract_recursion_setup_outputs(success.stdout, extracted)
        self.assertIn(supervisor.RECURSION_SETUP_LOG_OUTPUT, observed)

    def test_recursion_setup_preparation_flattens_and_verifies_runtime_inventory_offline(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(
            dir=ROOT / 'local-fixtures/phase5')))
        (root / 'evidence').mkdir()
        (root / 'scripts/fixtures').mkdir(parents=True)
        recipe = b'test-only trusted setup recipe\n'
        (root / 'scripts/fixtures/setup.sh').write_bytes(recipe)
        recipe_hash = hashlib.sha256(recipe).hexdigest()
        base = root / 'local-fixtures/phase5/recursion94'
        base.mkdir(parents=True)
        setup_workspace = base / 'setup'
        clean = [base / 'clean-1', base / 'clean-2']
        for workspace in clean:
            workspace.mkdir()
            (workspace / 'build.sh').write_bytes(b'build recipe')
        source_path = clean[0] / 'inputs/tool-archive.tar'
        source_path.parent.mkdir()
        source_path.write_bytes(b'fixture archive identity')
        (clean[1] / 'inputs').mkdir()
        (clean[1] / 'inputs/tool-archive.tar').write_bytes(source_path.read_bytes())
        source_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
        archive_pin = 'sha256:' + source_hash

        output = io.BytesIO()
        entries = {
            '.toolcache/bin/vasmm68k_mot.exe': b'vasm bytes',
            '.toolcache/bin/sjasmplus.exe': b'sjasmplus bytes',
            '.toolcache/lib/libz.so.1': b'zlib bytes',
            '.toolcache/python/bin/python3.12': b'python bytes',
            '.toolcache/python/lib/python3.12/encodings/__init__.py': b'encoding init',
            '.toolcache/python/lib/python3.12/lib-dynload/zlib.cpython-312-x86_64-linux-musl.so': b'zlib module',
            '.toolcache/python/lib/python3.12/asyncio/__init__.py': b'',
            '.toolcache/identity/native-tools.sha256': b'fixture native output manifest\n',
            supervisor.RECURSION_SETUP_LOG_OUTPUT: b'fixture setup log\n',
        }
        directories = {
            '.toolcache', '.toolcache/bin', '.toolcache/lib', '.toolcache/identity',
            '.toolcache/python', '.toolcache/python/bin', '.toolcache/python/lib',
            '.toolcache/python/lib/python3.12', '.toolcache/python/lib/python3.12/encodings',
            '.toolcache/python/lib/python3.12/lib-dynload',
            '.toolcache/python/lib/python3.12/asyncio',
        }
        with tarfile.open(fileobj=output, mode='w') as archive:
            for name in sorted(directories):
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            for name, data in entries.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o755 if name in supervisor.RECURSION_SETUP_REQUIRED_OUTPUTS[:4] else 0o644
                archive.addfile(member, io.BytesIO(data))

        config_path = base / 'build-config.json'
        config = {
            'title_id': 'recursion94', 'source_revision': 'a' * 40,
            'build_image': 'example.invalid/toolchain@sha256:' + 'b' * 64,
            'recursion_setup': {'workspace': 'local-fixtures/phase5/recursion94/setup'},
            'output_relative': 'build/rom.bin',
            'build_recipe': {'path': 'build.sh', 'args': []},
        }
        config_path.write_text(json.dumps(config))
        fake_inputs = {'inputs/tools.tar': (source_hash, 'inputs/tool-archive.tar')}
        fake_run = {'image_id': 'sha256:' + 'c' * 64, 'elapsed_us': 1234,
                    'output_tar': output.getvalue(), 'stderr': b''}
        with patch.object(supervisor, 'ROOT', root), \
             patch.object(supervisor, 'RECURSION_SETUP_RECIPE', 'scripts/fixtures/setup.sh'), \
             patch.object(supervisor, 'RECURSION_SETUP_RECIPE_SHA256', recipe_hash), \
             patch.object(supervisor, 'RECURSION_SETUP_INPUTS', fake_inputs), \
             patch.object(supervisor, '_counted_recursion_setup', return_value=fake_run) as counted:
            receipt = supervisor._prepare_recursion_toolchain(
                config, config_path, clean, endpoint='unused', limits=records.SCREENING_LIMITS,
                deadline=supervisor.SetupDeadline(10_000_000))
            persisted = json.loads(config_path.read_text())
            self.assertEqual(counted.call_count, 1)
            self.assertTrue(all(isinstance(value, str) and len(value) == 64
                                for value in persisted['setup_outputs'].values()))
            supervisor._validate_native_tools(persisted['native_tools'], persisted['work_mount_mode'])
            candidate = {
                'source_revision': 'a' * 40,
                'toolchain_source_revision': archive_pin,
                'material_source_revisions': ['a' * 40, archive_pin, 'd' * 40],
                'build_image': config['build_image'],
                'materials': [
                    {'path': 'build.sh', 'sha256': hashlib.sha256(b'build recipe').hexdigest(),
                     'source_revision': 'd' * 40},
                    {'path': 'inputs/tool-archive.tar', 'sha256': source_hash,
                     'source_revision': archive_pin},
                ],
            }
            identity = supervisor._verify_build_inputs(clean, candidate, persisted)
            self.assertEqual(identity, supervisor._verify_build_inputs(clean, candidate, persisted))
            self.assertEqual(persisted['setup_outputs']['.toolcache/python/lib/python3.12/asyncio/__init__.py'],
                             hashlib.sha256(b'').hexdigest())
            receipt_path = root / 'evidence/phase5-recursion-setup.json'
            self.assertEqual(hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                             persisted['setup_receipt_sha256'])
            self.assertEqual(receipt['setup_outputs'], persisted['setup_outputs'])

    def test_recursion_setup_export_propagates_script_failure_and_excludes_sources(self):
        wrapper = supervisor._recursion_setup_wrapper('a' * 64)
        self.assertTrue(wrapper.startswith('set -eu;'))
        self.assertIn('if /bin/sh .phase5-setup.sh; then tar -cf -', wrapper)
        self.assertIn('tail -c 262144 .toolcache/identity/setup.log >&2', wrapper)
        self.assertNotIn('tar -cf - .toolcache ', wrapper)
        self.assertNotIn('.toolcache/src', wrapper)
        self.assertIn('.toolcache/python/lib/python3.12', wrapper)
        self.assertIn('.toolcache/bin/vasmm68k_mot.exe', wrapper)

    def test_recursion_setup_recipe_is_hash_pinned_before_container_launch(self):
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(
            dir=ROOT / 'local-fixtures/phase5')))
        workspace = directory / 'setup'
        workspace.mkdir()
        with patch.object(supervisor, '_docker_endpoint', side_effect=AssertionError('launch before hash')):
            with self.assertRaisesRegex(supervisor.GateError, 'recipe identity'):
                supervisor._counted_recursion_setup(
                    'image', workspace, limits=records.SCREENING_LIMITS, endpoint='endpoint',
                    deadline=supervisor.SetupDeadline(10_000_000), setup_script=b'exit 0',
                    expected_script_sha256='0' * 64)

    def test_recursion_setup_uses_deadline_and_bounded_policy_container(self):
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(
            dir=ROOT / 'local-fixtures/phase5')))
        workspace = directory / 'setup'
        workspace.mkdir()
        docker_config = directory / 'docker-config'
        docker_config.mkdir()
        output = self._tank_tar([('.toolcache/bin/vasm', b'bin', tarfile.REGTYPE)])
        deadline = supervisor.SetupDeadline(10_000_000)
        with patch.object(supervisor, '_docker_endpoint', return_value=('docker', 'endpoint')), \
             patch.object(supervisor, '_docker_env', return_value=({}, docker_config)), \
             patch.object(supervisor, '_image_digest', return_value='image-id'), \
             patch.object(supervisor, '_container_args', return_value=['docker', 'run']) as args, \
             patch.object(supervisor.subprocess, 'Popen') as popen, \
             patch.object(supervisor, '_monitor_docker_process', return_value={
                 'returncode': 0, 'stop_reason': None, 'stdout': output,
                 'stderr': b'', 'elapsed_seconds': .1, 'stdout_bytes': len(output),
                 'stdout_sha256': hashlib.sha256(output).hexdigest(),
                 'stderr_bytes': 0, 'stderr_sha256': hashlib.sha256(b'').hexdigest()}) as monitor:
            receipt = supervisor._counted_recursion_setup(
                'image', workspace, limits=records.SCREENING_LIMITS, endpoint='endpoint',
                deadline=deadline, setup_script=b'exit 0',
                expected_script_sha256=hashlib.sha256(b'exit 0').hexdigest())
        self.assertEqual(receipt['image_id'], 'image-id')
        self.assertEqual(receipt['output_tar'], output)
        self.assertEqual(monitor.call_args.kwargs['deadline'], deadline)
        self.assertEqual(monitor.call_args.kwargs['stdout_cap'], 256 * 1024 * 1024)
        self.assertEqual(args.call_args.kwargs['pids'], 64)
        self.assertEqual(args.call_args.kwargs['cpus'], 4)
        self.assertEqual(args.call_args.kwargs['memory'], '8589934592')
        self.assertEqual(args.call_args.kwargs['work_mount_mode'], 'exec')
        self.assertEqual(args.call_args.kwargs['pids'], 64)
        self.assertFalse((workspace / '.phase5-setup.sh').exists())

    def test_current_screen_with_relative_config_persists_relative_receipt_reference(self):
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT / 'local-fixtures/phase5')))
        ledger, eligibility, _ = records.migrate_screening(ROOT, records.amended_policy())
        ledger = records.begin_setup_continuation(ledger)
        ledger = records.charge_setup_elapsed(ledger, 1, probe_elapsed_us=1)
        ledger = records.complete_setup_continuation(ledger, success=True)
        ledger_path = directory / 'ledger.json'
        ledger_path.write_text(json.dumps(ledger))
        config = {'schema': 'genewhip-phase5-build-config-v2', 'build_image': 'image',
                  'work_mount_mode': 'noexec', 'native_tools': [], 'job_policy': {},
                  'output_relative': 'out/rom.bin', 'build_recipe': {'path': 'build.sh'},
                  'build_environment': {'PATH': '/bin'}}
        relative_config = (directory / 'config.json').relative_to(ROOT)
        (ROOT / relative_config).write_text(json.dumps(config))
        self.enterContext(patch.object(supervisor, '_current_prerequisites', return_value=(ledger, eligibility, {}, {})))
        self.enterContext(patch.object(supervisor, '_select_next_candidate', return_value=('tank-battle', 'selected')))
        self.enterContext(patch.object(supervisor, '_validate_build_config', return_value=(config, [])))
        self.enterContext(patch.object(supervisor, 'inspect_materials', return_value={'eligible': True}))
        self.enterContext(patch.object(records, 'validate_eligibility', return_value=True))
        self.enterContext(patch.object(supervisor, '_verify_build_inputs', return_value='workspace-identity'))
        self.enterContext(patch.object(supervisor, '_docker_endpoint', return_value=('docker', 'endpoint')))
        docker_config = directory / 'docker-config'
        docker_config.mkdir()
        self.enterContext(patch.object(supervisor, '_docker_env', return_value=({}, docker_config)))
        self.enterContext(patch.object(supervisor, '_image_digest', return_value='image-id'))
        self.enterContext(patch.object(supervisor, '_verify_continuation', return_value={'build_image_id': 'image-id'}))
        pair = self.enterContext(patch.object(supervisor, 'build_pair', return_value={
            'comparison': {'status': 'byte-identical'}, 'builds': []}))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(supervisor._screen_current(ledger_path, 'unused', relative_config))
        self.assertEqual(pair.call_args.kwargs['log_directory'], directory / 'logs')
        current = json.loads(ledger_path.read_bytes())
        row = next(candidate for candidate in current['candidates'] if candidate['id'] == 'tank-battle')
        receipt_path = ROOT / row['build_evidence']['quarantine_receipt']
        self.assertTrue(receipt_path.is_file())
        self.assertEqual(hashlib.sha256(receipt_path.read_bytes()).hexdigest(), row['build_evidence']['receipt_sha256'])
        self.assertEqual(row['state'], 'build-screened')

    def test_build_pair_accepts_relative_log_directory_after_successful_outputs(self):
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT / 'local-fixtures/phase5')))
        workspaces = [directory / name for name in ('clean-a', 'clean-b')]
        for workspace in workspaces:
            workspace.mkdir()
            (workspace / 'build.sh').write_bytes(b'recipe')
        ledger = records.migrate_screening(ROOT, records.amended_policy())[0]
        ledger = records.begin_setup_continuation(ledger)
        ledger = records.charge_setup_elapsed(ledger, 1, probe_elapsed_us=1)
        ledger = records.complete_setup_continuation(ledger, success=True)
        ledger_path = directory / 'ledger.json'
        ledger_path.write_text(json.dumps(ledger))
        def completed_build(image, workspace, output_relative, **kwargs):
            output = workspace / output_relative
            output.parent.mkdir(parents=True)
            output.write_bytes(b'rom')
            return {'returncode': 0, 'stop_reason': None, 'stderr': b'actual build log',
                    'image_id': 'image-id', 'output': {'path': str(output), 'bytes': 3,
                                                     'sha256': hashlib.sha256(b'rom').hexdigest()}}
        relative_logs = (directory / 'logs').relative_to(ROOT)
        with patch.object(supervisor, '_container_build', side_effect=completed_build) as build:
            pair = supervisor.build_pair('image', workspaces, 'out/rom.bin',
                limits=records.SCREENING_LIMITS, endpoint='unused', title_id='tank-battle',
                screening_path=ledger_path, identity={'source': 'synthetic'},
                screen_already_started=True, log_directory=relative_logs)
        self.assertEqual(build.call_count, 2)
        self.assertEqual(pair['comparison']['status'], 'byte-identical')
        self.assertEqual([entry['invocation'] for entry in pair['builds']], [1, 2])
        for entry in pair['builds']:
            self.assertEqual((ROOT / entry['log_path']).read_bytes(), b'actual build log')
            self.assertTrue(entry['log_path'].startswith(relative_logs.as_posix() + '/'))
        current = json.loads(ledger_path.read_bytes())
        tank = next(candidate for candidate in current['candidates'] if candidate['id'] == 'tank-battle')
        self.assertEqual(tank['counters']['rom_build_invocations'], 2)

    @staticmethod
    def _tank_tar(entries):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as archive:
            for name, data, kind in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                member.linkname = 'out/rom.bin' if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ''
                archive.addfile(member, io.BytesIO(data) if member.size else None)
        return output.getvalue()

    def test_tank_output_transfer_requires_exact_bounded_regular_rom_and_map(self):
        rom = ('out/rom.bin', b'rom', tarfile.REGTYPE)
        link_map = ('out/link.map', b'map', tarfile.REGTYPE)
        valid = self._tank_tar([rom, link_map])
        self.assertEqual(supervisor._tar_tank_outputs(valid, 'out/rom.bin', 3, 3), (b'rom', b'map'))
        mutants = ([rom], [rom, link_map, link_map], [rom, link_map, ('extra', b'x', tarfile.REGTYPE)],
                   [rom, ('../out/link.map', b'map', tarfile.REGTYPE)],
                   [rom, ('/out/link.map', b'map', tarfile.REGTYPE)],
                   [rom, ('./out/link.map', b'map', tarfile.REGTYPE)],
                   [rom, ('wrong/link.map', b'map', tarfile.REGTYPE)],
                   [rom, ('out/link.map', b'', tarfile.SYMTYPE)],
                   [rom, ('out/link.map', b'', tarfile.LNKTYPE)],
                   [rom, ('out/link.map', b'', tarfile.DIRTYPE)],
                   [rom, ('out/link.map', b'', tarfile.REGTYPE)],
                   [rom, ('out/link.map', b'four', tarfile.REGTYPE)],
                   [('out/rom.bin', b'four', tarfile.REGTYPE), link_map])
        for entries in mutants:
            with self.subTest(entries=entries), self.assertRaises(supervisor.GateError):
                supervisor._tar_tank_outputs(self._tank_tar(entries), 'out/rom.bin', 3, 3)
        for invalid in (valid[:515], valid[:2048], valid + b'x', valid + valid,
                        valid + b'\0' * (1024 * 1024 + 7)):
            with self.subTest(size=len(invalid)), self.assertRaises(supervisor.GateError):
                supervisor._tar_tank_outputs(invalid, 'out/rom.bin', 3, 3)
        with self.assertRaisesRegex(supervisor.GateError, 'confined'):
            supervisor._tar_tank_outputs(valid, '../out/rom.bin', 3, 3)
        # Historical/v1 output remains the original single-file parser contract.
        self.assertEqual(supervisor._tar_single_file(self._tank_tar([rom]), 'rom.bin', 3), b'rom')

    def test_container_output_collection_keeps_tank_map_without_changing_recipe(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(supervisor, 'ROOT', root))
        self.enterContext(patch.object(supervisor, '_docker_endpoint', return_value=('docker', 'endpoint')))
        self.enterContext(patch.object(supervisor, '_image_digest', return_value='image-id'))
        self.enterContext(patch.object(supervisor.subprocess, 'run'))
        process = self.enterContext(patch.object(supervisor.subprocess, 'Popen'))
        for title in ('tank-battle', 'recursion94', None):
            workspace = root / 'local-fixtures/phase5' / str(title)
            workspace.mkdir(parents=True)
            (workspace / 'build.sh').write_bytes(b'unchanged recipe')
            config_dir = root / ('docker-config-' + str(title))
            config_dir.mkdir()
            config = ({'title_id': title, 'work_mount_mode': 'noexec', 'native_tools': []}
                      if title is not None else None)
            entries = [('out/rom.bin', b'rom', tarfile.REGTYPE)]
            if title == 'tank-battle':
                entries.append(('out/link.map', b'linker members', tarfile.REGTYPE))
            with patch.object(supervisor, '_docker_env', return_value=({}, config_dir)), \
                 patch.object(supervisor, '_monitor_docker_process', return_value={
                     'returncode': 0, 'stop_reason': None, 'stdout': self._tank_tar(entries)}) as monitor:
                result = supervisor._container_build('image', workspace, 'out/rom.bin',
                    limits=records.SCREENING_LIMITS, endpoint='endpoint', invocation=str(title),
                    current_config=config, recipe_args=[])
            self.assertEqual((workspace / 'out/rom.bin').read_bytes(), b'rom')
            wrapper = process.call_args.args[0][-1]
            self.assertIn('/bin/sh ./build.sh', wrapper)
            extra = records.SCREENING_LIMITS['stdout_bytes_per_process'] if title == 'tank-battle' else 0
            self.assertEqual(monitor.call_args.kwargs['stdout_cap'],
                             records.SCREENING_LIMITS['rom_bytes'] + 1024 * 1024 + extra)
            if title == 'tank-battle':
                self.assertTrue(wrapper.endswith('out/rom.bin out/link.map'))
                self.assertEqual(pathlib.Path(result['link_map']['path']).read_bytes(), b'linker members')
                self.assertEqual(result['link_map']['sha256'], hashlib.sha256(b'linker members').hexdigest())
            else:
                self.assertNotIn('out/link.map', wrapper)
                self.assertNotIn('link_map', result)

    def test_build_pair_verification_requires_each_tank_link_map_identity(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(supervisor, 'ROOT', root))
        ledger = {'policy_sha256': 'policy', 'candidates': []}
        eligibility = {'candidates': []}
        tank_receipt = None
        for title, lineage in (('tank-battle', 'a'), ('recursion94', 'b')):
            candidate = {'title_id': title, 'source_revision': 'revision', 'lineage_id': lineage}
            eligibility['candidates'].append(candidate)
            builds = []
            for ordinal in (1, 2):
                directory = root / 'local-fixtures/phase5' / title / str(ordinal) / 'out'
                directory.mkdir(parents=True)
                rom_path = directory / 'rom.bin'
                rom_path.write_bytes(b'rom')
                build = {'ordinal': ordinal, 'quarantine_path': rom_path.relative_to(root).as_posix(),
                         'sha256': hashlib.sha256(b'rom').hexdigest(), 'bytes_count': 3}
                if title == 'tank-battle':
                    map_path = directory / 'link.map'
                    map_path.write_bytes(b'map')
                    build['link_map'] = {'quarantine_path': map_path.relative_to(root).as_posix(),
                                         'sha256': hashlib.sha256(b'map').hexdigest(), 'bytes_count': 3}
                builds.append(build)
            receipt = {'schema': 'genewhip-phase5-build-receipt-v2', 'title_id': title,
                       'source_revision': 'revision', 'policy_sha256': 'policy', 'builds': builds,
                       'comparison': records.compare_build_outputs([{'ordinal': n, 'bytes': b'rom'} for n in (1, 2)])}
            path = root / 'local-fixtures/phase5' / title / 'receipt.json'
            path.write_text(json.dumps(receipt))
            ledger['candidates'].append({'id': title, 'state': 'build-screened', 'outcome': 'pass',
                                         'build_evidence': {'quarantine_receipt': path.relative_to(root).as_posix(),
                                                            'receipt_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}})
            if title == 'tank-battle':
                tank_receipt = receipt, path
        self.enterContext(patch.object(supervisor, '_current_prerequisites', return_value=(ledger, eligibility, {}, {})))
        self.enterContext(patch.object(records, 'validate_eligibility', return_value=True))
        self.enterContext(patch.object(supervisor, 'inspect_materials', return_value={'eligible': True}))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(len(supervisor._verify_build_pair('l', 'e', 'p')), 2)
        for item in ledger['candidates']:
            item.update(state='reference-active-field-unknown', outcome='unknown',
                        post_build_checks={'repeatable_build': True})
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(len(supervisor._verify_build_pair('l', 'e', 'p')), 2)
        receipt, receipt_path = tank_receipt
        original_receipt = receipt_path.read_bytes()
        receipt_path.write_bytes(original_receipt + b' ')
        with self.assertRaisesRegex(supervisor.GateError, 'receipt hash mismatch'):
            supervisor._verify_build_pair('l', 'e', 'p')
        receipt_path.write_bytes(original_receipt)
        first_map = root / receipt['builds'][0]['link_map']['quarantine_path']
        for raw in (b'bad', b'', b'x' * (records.SCREENING_LIMITS['stdout_bytes_per_process'] + 1)):
            first_map.write_bytes(raw)
            with self.assertRaisesRegex(supervisor.GateError, 'linker map'):
                supervisor._verify_build_pair('l', 'e', 'p')
        first_map.write_bytes(b'map')
        first_map.unlink()
        first_map.symlink_to(first_map.with_name('rom.bin'))
        with self.assertRaisesRegex(supervisor.GateError, 'confined regular'):
            supervisor._verify_build_pair('l', 'e', 'p')
        for map_metadata in (None, {'quarantine_path': '../escape'}):
            receipt['builds'][0]['link_map'] = map_metadata
            receipt_path.write_text(json.dumps(receipt))
            ledger['candidates'][0]['build_evidence']['receipt_sha256'] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            with self.assertRaises(supervisor.GateError):
                supervisor._verify_build_pair('l', 'e', 'p')

    def test_material_revisions_require_reviewed_game_toolchain_and_wrapper_pins(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        workspaces = [root / name for name in ('a', 'b')]
        for workspace in workspaces:
            workspace.mkdir()
            (workspace / 'build.sh').write_bytes(b'recipe')
        candidate = {'source_revision': 'a' * 40, 'toolchain_source_revision': 'b' * 40,
                     'material_source_revisions': ['a' * 40, 'b' * 40, 'c' * 40],
                     'build_image': 'pinned-image', 'materials': [
                         {'path': 'build.sh', 'sha256': hashlib.sha256(b'recipe').hexdigest(), 'source_revision': 'c' * 40},
                         {'path': '/sgdk/src/boot/sega.s', 'origin': 'image', 'sha256': 'c' * 64, 'source_revision': 'b' * 40}]}
        config = {'source_revision': 'a' * 40, 'build_image': 'pinned-image',
                  'build_recipe': {'path': 'build.sh'}, 'output_relative': 'out/rom.bin'}
        self.assertTrue(supervisor._verify_build_inputs(workspaces, candidate, config))
        archive_pin = 'sha256:' + 'd' * 64
        archive_candidate = {**candidate, 'toolchain_source_revision': archive_pin,
                             'material_source_revisions': ['a' * 40, archive_pin, 'c' * 40],
                             'materials': [candidate['materials'][0],
                                           {**candidate['materials'][1], 'source_revision': archive_pin}]}
        self.assertTrue(supervisor._verify_build_inputs(workspaces, archive_candidate, config))
        for invalid_pin in ('d' * 64, 'sha256:' + 'e' * 63, 'sha256:' + 'g' * 64):
            mutant = {**archive_candidate, 'toolchain_source_revision': invalid_pin,
                      'material_source_revisions': ['a' * 40, invalid_pin, 'c' * 40]}
            with self.assertRaisesRegex(supervisor.GateError, 'exact reviewed'):
                supervisor._verify_build_inputs(workspaces, mutant, config)
        for field, value in (('toolchain_source_revision', None), ('toolchain_source_revision', 'unpinned')):
            mutant = {**candidate, field: value}
            with self.assertRaisesRegex(supervisor.GateError, 'exact reviewed'):
                supervisor._verify_build_inputs(workspaces, mutant, config)
        for revisions in (None, [], ['a' * 40, 'b' * 40], ['a' * 40, 'c' * 40],
                          ['b' * 40, 'c' * 40], ['a' * 40, 'b' * 40, 'unpinned'],
                          ['a' * 40, 'b' * 40, 'c' * 40, 'c' * 40]):
            mutant = {**candidate, 'material_source_revisions': revisions}
            with self.assertRaises(supervisor.GateError):
                supervisor._verify_build_inputs(workspaces, mutant, config)
        for ordinal, revision in ((0, 'd' * 40), (1, 'd' * 40), (1, None)):
            mutant = copy.deepcopy(candidate)
            mutant['materials'][ordinal]['source_revision'] = revision
            with self.assertRaisesRegex(supervisor.GateError, 'not reviewed'):
                supervisor._verify_build_inputs(workspaces, mutant, config)

    def test_counted_setup_outputs_are_separately_hash_bound_in_clean_workspaces(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        workspaces = [root / name for name in ('a', 'b')]
        for workspace in workspaces:
            workspace.mkdir()
            (workspace / 'build.sh').write_bytes(b'recipe')
            tool = workspace / '.toolcache/bin/python3.12'
            tool.parent.mkdir(parents=True)
            tool.write_bytes(b'measured setup output')
        digest = hashlib.sha256(b'measured setup output').hexdigest()
        candidate = {'source_revision': 'a' * 40, 'toolchain_source_revision': 'b' * 40,
                     'material_source_revisions': ['a' * 40, 'b' * 40, 'c' * 40],
                     'build_image': 'pinned-image', 'materials': [
                         {'path': 'build.sh', 'sha256': hashlib.sha256(b'recipe').hexdigest(),
                          'source_revision': 'c' * 40}]}
        config = {'source_revision': 'a' * 40, 'build_image': 'pinned-image',
                  'build_recipe': {'path': 'build.sh'}, 'output_relative': 'out/rom.bin',
                  'setup_outputs': {'.toolcache/bin/python3.12': digest}}
        self.assertTrue(supervisor._verify_build_inputs(workspaces, candidate, config))
        (workspaces[1] / '.toolcache/bin/python3.12').write_bytes(b'tampered')
        with self.assertRaisesRegex(supervisor.GateError, 'setup output'):
            supervisor._verify_build_inputs(workspaces, candidate, config)

    def _history_fixture(self):
        """Synthetic consumed observation, independent of the live ledger/quarantine."""
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        def save(relative, value):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
            return path
        ledger, eligibility, migration = records.migrate_screening(ROOT, records.amended_policy())
        eligibility['candidates'][0]['image_materials'] = []
        ledger = records.begin_setup_continuation(ledger)
        ledger = records.charge_setup_elapsed(ledger, 2)
        ledger = records.charge_setup_elapsed(ledger, 10, probe_elapsed_us=3)
        ledger = records.complete_setup_continuation(ledger, success=True)
        receipt = json.loads((ROOT / 'evidence/phase5-setup-continuation.json').read_bytes())
        producer = b'synthetic producer bytes'
        receipt['identities'] = {name: hashlib.sha256(producer).hexdigest()
                                 for name in supervisor.ENFORCEMENT_IDENTITY_FILES}
        archive = json.loads((ROOT / 'evidence/phase5-enforcement-setup.json').read_bytes())
        archive['identities'] = receipt['identities']
        archive_path = save('evidence/phase5-enforcement-setup.json', archive)
        receipt['enforcement_sha256'] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        preparation = save('local-fixtures/phase5/tank-battle/preparation.json', {'elapsed_seconds': .000002})
        receipt['preparation_receipts'] = [{'path': preparation.relative_to(root).as_posix(),
                                          'sha256': hashlib.sha256(preparation.read_bytes()).hexdigest()}]
        config = {'title_id': 'tank-battle', 'preparation_receipts': receipt['preparation_receipts']}
        save(receipt['config_path'], config)
        receipt.update(config_sha256=records.identity_digest(config), preparation_elapsed_us=2,
                       image_materials_sha256=records.identity_digest({'materials': []}),
                       continuation=records.setup_continuation_state(ledger), probe_elapsed_us=3,
                       measured_elapsed_us=11)
        stdout = ''.join(k + '=' + v + '\n' for k, v in receipt['effective_observations'].items()).encode()
        for stream, data in (('stdout', stdout), ('stderr', b'synthetic java output')):
            save(receipt['probe'][stream + '_path'], data)
            receipt['probe'][stream + '_bytes'] = len(data)
            receipt['probe'][stream + '_sha256'] = hashlib.sha256(data).hexdigest()
        save('ledger.json', ledger)
        save('eligibility.json', eligibility)
        save('policy.json', records.amended_policy())
        save('evidence/phase5-policy-migration.json', migration)
        receipt_path = save('receipt.json', receipt)
        self.enterContext(patch.object(supervisor, 'ROOT', root))
        self.enterContext(patch.object(supervisor, 'SETUP_OBSERVATION_SHA256',
                                      hashlib.sha256(receipt_path.read_bytes()).hexdigest()))
        git = self.enterContext(patch.object(supervisor.subprocess, 'run',
                                            return_value=SimpleNamespace(stdout=producer)))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        return root, receipt, ledger, git

    def _verify_history(self, root):
        return supervisor._verify_continuation(root / 'receipt.json', root / 'ledger.json',
                                               root / 'eligibility.json', root / 'policy.json')

    def test_historical_observation_survives_test_repair_without_launch_authority(self):
        root, receipt, ledger, git = self._history_fixture()
        with patch.object(supervisor, '_current_prerequisites', side_effect=AssertionError('launch gate called')), \
             patch.object(supervisor, '_enforcement_identities', return_value={'current-test': 'changed'}):
            # Documentary review evolves independently; historical material hashes
            # stay in the immutable receipt, and a launch still checks current rights.
            eligibility = json.loads((root / 'eligibility.json').read_bytes())
            eligibility['candidates'][0]['image_materials'] = [{'review': 'new documentary evidence'}]
            (root / 'eligibility.json').write_text(json.dumps(eligibility))
            self.assertEqual(self._verify_history(root), receipt)
            with self.assertRaisesRegex(supervisor.GateError, 'stale'):
                supervisor._verify_enforcement_document(json.loads(
                    (root / 'evidence/phase5-enforcement-setup.json').read_bytes()))
        self.assertEqual(git.call_count, len(supervisor.ENFORCEMENT_IDENTITY_FILES))
        self.assertTrue(all(call.args[0][:2] == ['git', 'show'] for call in git.call_args_list))
        with self.assertRaisesRegex(ValueError, 'already been consumed'):
            records.begin_setup_continuation(ledger)
        self.assertEqual(records.setup_continuation_state(ledger), receipt['continuation'])

    def test_historical_producer_bytes_must_match_actual_revision(self):
        root, _, _, git = self._history_fixture()
        git.return_value.stdout = b'changed producer'
        with self.assertRaisesRegex(supervisor.GateError, 'producer identity mismatch'):
            self._verify_history(root)
        self.assertIn(supervisor.SETUP_PRODUCER_REVISION, git.call_args.args[0][2])

    def test_historical_producer_history_must_be_available(self):
        root, _, _, git = self._history_fixture()
        git.side_effect = subprocess.CalledProcessError(128, ['git', 'show'])
        with self.assertRaisesRegex(supervisor.GateError, 'producer bytes unavailable'):
            self._verify_history(root)

    def test_historical_receipt_archive_config_and_raw_logs_reject_tampering(self):
        for target, error in (('receipt.json', 'observation bytes changed'),
                              ('evidence/phase5-enforcement-setup.json', 'enforcement archive changed'),
                              ('local-fixtures/phase5/tank-battle/amendment-build-config.json', 'config identity changed'),
                              ('local-fixtures/phase5/tank-battle/preparation.json', 'preparation receipt changed'),
                              ('local-fixtures/phase5/tank-battle/continuation.stdout', 'probe stdout changed'),
                              ('local-fixtures/phase5/tank-battle/continuation.stderr', 'probe stderr changed')):
            with self.subTest(target=target):
                root, _, _, _ = self._history_fixture()
                path = root / target
                # Whitespace preserves JSON semantics while changing captured bytes.
                path.write_bytes(path.read_bytes() + b' ')
                if 'config.json' in target:
                    config = json.loads(path.read_bytes())
                    config['title_id'] = 'changed'
                    path.write_text(json.dumps(config))
                with self.assertRaisesRegex(supervisor.GateError, error):
                    self._verify_history(root)

    def test_historical_observation_rejects_changed_policy_or_consumption(self):
        root, _, _, _ = self._history_fixture()
        policy = records.amended_policy()
        policy['linux_tasks_per_container'] = 128
        (root / 'policy.json').write_text(json.dumps(policy))
        with self.assertRaisesRegex(ValueError, 'frozen'):
            self._verify_history(root)
        (root / 'policy.json').write_text(json.dumps(records.amended_policy()))
        pristine = records.migrate_screening(ROOT, records.amended_policy())[0]
        (root / 'ledger.json').write_text(json.dumps(pristine))
        with self.assertRaisesRegex(supervisor.GateError, 'single-use'):
            self._verify_history(root)

    def test_future_launch_still_requires_current_enforcement_before_docker(self):
        with patch.object(supervisor, '_current_prerequisites', side_effect=supervisor.GateError('stale current controls')), \
             patch.object(supervisor, '_docker_endpoint') as docker:
            with self.assertRaisesRegex(supervisor.GateError, 'stale current controls'):
                supervisor._screen_current('ledger', 'eligibility', 'config')
            docker.assert_not_called()

    def test_undeclared_native_or_shell_indirection_recipe_rejects_before_launch(self):
        native = [{'command': ['/work/src/tool', 'input']}]
        supervisor._validate_recipe_commands(b'all:\n\t/work/src/tool input\n', native)
        for recipe in (b'all:\n\t/work/src/rogue input\n', b'all:\n\t/work/src/tool changed\n',
                       b'all:\n\t/bin/sh build.sh\n', b'all:\n\t/bin/cp /bin/sh /work/rogue; /work/rogue\n',
                       b'all: $(shell make -j)\n', b'all:\n\t/usr/bin/gcc -fplugin=/work/plugin.so x.c\n'):
            with self.subTest(recipe=recipe), self.assertRaisesRegex(supervisor.GateError, 'native|indirection|executable'):
                supervisor._validate_recipe_commands(recipe, native)

    def test_continuation_cannot_authorize_changed_config(self):
        config = {'title_id': 'tank-battle', 'work_mount_mode': 'noexec'}
        receipt = {'config_sha256': records.identity_digest(config)}
        supervisor._bind_continuation_config(receipt, config)
        with self.assertRaisesRegex(supervisor.GateError, 'config identity changed'):
            supervisor._bind_continuation_config(receipt, {**config, 'work_mount_mode': 'exec'})

    def test_endpoint_and_image_inspection_receive_remaining_deadline(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        deadline = supervisor.SetupDeadline(1000)
        with patch.object(supervisor.shutil, 'which', return_value='docker'), \
             patch.object(supervisor.subprocess, 'run', return_value=SimpleNamespace(
                 returncode=0, stdout='unix:///socket')) as run:
            supervisor._docker_endpoint(deadline=deadline)
            self.assertLessEqual(run.call_args.kwargs['timeout'], .001)
        deadline = supervisor.SetupDeadline(1000)
        with patch.object(supervisor.subprocess, 'run', return_value=SimpleNamespace(
                 returncode=0, stdout='sha256:'+'a'*64)) as run:
            supervisor._image_digest('docker', 'image@sha256:'+'b'*64, {}, deadline=deadline)
            self.assertLessEqual(run.call_args.kwargs['timeout'], .001)

    def test_conditional_selection_cannot_activate_recursion_before_tank(self):
        ledger = records.migrate_screening(ROOT, records.amended_policy())[0]
        eligibility = json.loads((ROOT / 'evidence/phase5-eligibility-v2.json').read_text())
        for candidate in eligibility['candidates']:
            candidate['decision'] = 'eligible'
            candidate['checks'] = {name: True for name in records.ELIGIBILITY_CHECKS}
            candidate['materials'] = [{'path': 'synthetic', 'license': 'MIT', 'notice': 'synthetic'}]
        selected, reason = supervisor._select_next_candidate(ledger, eligibility)
        self.assertIsNone(selected)
        self.assertIn('Tank', reason)
        ledger = records.begin_setup_continuation(ledger)
        ledger = records.charge_setup_elapsed(ledger, 1, probe_elapsed_us=1)
        ledger = records.complete_setup_continuation(ledger, success=True)
        self.assertEqual(supervisor._select_next_candidate(ledger, eligibility)[0], 'tank-battle')
        failed = records.complete_setup_continuation(records.begin_setup_continuation(
            records.migrate_screening(ROOT, records.amended_policy())[0]), success=False)
        self.assertIsNone(supervisor._select_next_candidate(failed, eligibility)[0])

    def test_recursion_prelaunch_hash_correction_resumes_same_screen_once(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT / 'local-fixtures/phase5')))
        for relative in ('evidence/phase5-recursion-setup-authorization.json',
                         'evidence/phase5-recursion-setup-failure.json',
                         'fixtures/candidate-screening-v2.json',
                         '.planning/phases/GW-05-candidate-admission-and-baseline/05-10-CONTINUATION.md'):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative == 'fixtures/candidate-screening-v2.json':
                target.write_bytes(_pre_d114_ledger_bytes())
            else:
                shutil.copyfile(ROOT / relative, target)
        ledger_path = root / 'fixtures/candidate-screening-v2.json'
        ledger = json.loads(ledger_path.read_bytes())
        eligibility = json.loads((ROOT / 'evidence/phase5-eligibility-v2.json').read_bytes())
        eligibility_path = root / 'evidence/eligibility.json'
        eligibility_path.parent.mkdir(parents=True, exist_ok=True)
        eligibility_path.write_text(json.dumps(eligibility), encoding='utf-8')
        next(item for item in ledger['candidates'] if item['id'] == 'tank-battle').update(
            state='build-screened', outcome='pass')
        with patch.object(supervisor, 'ROOT', root):
            selected, _ = supervisor._select_next_candidate(ledger, eligibility)
            self.assertEqual(selected, 'recursion94')

    def test_d114_screen_entry_consumes_before_one_setup_and_pair_and_rejects_replay(self):
        root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT / 'local-fixtures/phase5')))
        for relative in ('evidence/phase5-recursion-setup-authorization.json',
                         'evidence/phase5-recursion-setup-failure.json',
                         'evidence/phase5-enforcement.json',
                         'fixtures/candidate-screening-v2.json',
                         '.planning/phases/GW-05-candidate-admission-and-baseline/05-10-CONTINUATION.md'):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative == 'fixtures/candidate-screening-v2.json':
                target.write_bytes(_pre_d114_ledger_bytes())
            else:
                shutil.copyfile(ROOT / relative, target)
        ledger_path = root / 'fixtures/candidate-screening-v2.json'
        ledger = json.loads(ledger_path.read_bytes())
        eligibility = json.loads((ROOT / 'evidence/phase5-eligibility-v2.json').read_bytes())
        eligibility_path = root / 'evidence/eligibility.json'
        eligibility_path.parent.mkdir(parents=True, exist_ok=True)
        eligibility_path.write_text(json.dumps(eligibility), encoding='utf-8')
        for candidate in ledger['candidates']:
            if candidate['id'] == 'tank-battle':
                candidate.update(state='build-screened', outcome='pass')
        config = {'schema': 'genewhip-phase5-build-config-v2', 'title_id': 'recursion94',
                  'source_revision': next(c for c in eligibility['candidates']
                                          if c['title_id'] == 'recursion94')['source_revision'],
                  'build_image': 'reviewed@example.invalid/image@sha256:' + 'a'*64,
                  'workspaces': ['one', 'two'], 'output_relative': 'out/rom.bin',
                  'build_recipe': {'path': 'tools/build_rom.py', 'args': []},
                  'build_environment': {'PATH': '/usr/bin:/bin'}, 'work_mount_mode': 'exec',
                  'native_tools': [], 'job_policy': {'jobs': 4}}
        config_path = root / 'local-fixtures/phase5/d114/build-config.json'
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config), encoding='utf-8')
        workspaces = [root / 'local-fixtures/phase5/d114/clean-1',
                      root / 'local-fixtures/phase5/d114/clean-2']
        for workspace in workspaces:
            workspace.mkdir(parents=True)
        calls = {'setup': 0, 'pair': 0}

        def validate_config(*_args):
            return config, workspaces

        def setup(*_args, **_kwargs):
            calls['setup'] += 1
            attempt = json.loads((root / supervisor.RECURSION_SETUP_ATTEMPT).read_bytes())
            self.assertEqual(attempt['events'][0]['kind'], 'started')
            config.update(work_mount_mode='exec', setup_outputs={
                '.toolcache/bin/vasmm68k_mot.exe': '1'*64}, setup_receipt_sha256='2'*64,
                native_tools=[{'executable': '/work/src/.toolcache/bin/vasmm68k_mot.exe',
                               'executable_sha256': '1'*64, 'inputs': {}, 'command': ['/work/src/.toolcache/bin/vasmm68k_mot.exe']}])

        def pair(*_args, **_kwargs):
            calls['pair'] += 1
            live = json.loads(ledger_path.read_bytes())
            identity = {'test_pair_invocation': calls['pair']}
            for ordinal in range(2):
                live = records.append_attempt(live, 'recursion94', 'rom_build_invocation', identity,
                                              details={'ordinal': ordinal + 1})
            ledger_path.write_text(json.dumps(live), encoding='utf-8')
            return {'builds': [{'ordinal': 1}, {'ordinal': 2}],
                    'comparison': {'status': 'byte-identical', 'first_sha256': '3'*64,
                                   'second_sha256': '3'*64}}

        policy = records.amended_policy()
        enforcement = {'status': 'pass'}
        with patch.object(supervisor, 'ROOT', root), \
             patch.object(supervisor, '_current_prerequisites', return_value=(ledger, eligibility, policy, enforcement)), \
             patch.object(supervisor, '_validate_build_config', side_effect=validate_config), \
             patch.object(supervisor, '_verify_build_inputs', return_value='4'*64), \
             patch.object(supervisor, '_docker_endpoint', return_value=('docker', 'endpoint')), \
             patch.object(supervisor, '_docker_env', return_value=({}, root / 'docker-config')), \
             patch.object(supervisor, '_image_digest', return_value='image-id'), \
             patch.object(supervisor, '_verify_image_materials'), \
             patch.object(supervisor, '_prepare_recursion_toolchain', side_effect=setup), \
             patch.object(supervisor, 'build_pair', side_effect=pair):
            self.assertTrue(supervisor._screen_current(ledger_path, eligibility_path, config_path))
            receipt = json.loads((root / supervisor.RECURSION_SETUP_ATTEMPT).read_bytes())
            self.assertEqual([event['kind'] for event in receipt['events']], ['started', 'completed'])
            self.assertEqual(calls, {'setup': 1, 'pair': 1})
            self.assertFalse(supervisor._screen_current(ledger_path, eligibility_path, config_path))
            self.assertEqual(calls, {'setup': 1, 'pair': 1})

    def test_recursion_setup_correction_rejects_other_failures(self):
        row = {'identity_history': [{'event': 'build_setup_failed', 'details': {
            'failure_sha256': '0'*64}, 'sha256': '1'*64},
            {'event': 'build_environment_correction', 'details': {
                'failure_event_sha256': '1'*64,
                'correction': 'image-material-sha256-transcription'}}]}
        self.assertIsNone(supervisor._recursion_setup_correction_event(row))

    def test_current_slot_materials_does_not_require_final_rom(self):
        import contextlib, io
        with __import__('tempfile').TemporaryDirectory(dir=ROOT / 'local-fixtures/phase5') as tmp:
            directory = pathlib.Path(tmp)
            promotion = {'build_receipt_sha256': 'a'*64}
            for name, field in (('source_tree_identity', 'source_tree_sha256'),
                                ('build_lock', 'build_lock_sha256'), ('notices', 'notices_sha256')):
                path = directory / name; path.write_text(name)
                promotion[name] = path.relative_to(ROOT).as_posix()
                promotion[field] = hashlib.sha256(path.read_bytes()).hexdigest()
            doc = json.loads((ROOT / 'evidence/phase5-eligibility.json').read_text())
            entry = doc['candidates'][0]
            entry.update(slot_id='phase5-a', decision='eligible', promotion=promotion,
                         absent_categories=[name for name in records.MATERIAL_CATEGORIES if name != 'code'],
                         materials=[{'category': 'code', 'path': 's', 'sha256': 'a'*64,
                                     'source_revision': 's', 'terms_source': 'license', 'license': 'MIT', 'notice': 'n'}])
            path = directory / 'eligibility.json'; path.write_text(json.dumps(doc))
            with contextlib.redirect_stdout(io.StringIO()):
                supervisor._verify_slot('a', 'materials', path)
            with self.assertRaisesRegex(supervisor.GateError, 'rom_sha256'):
                supervisor._verify_slot('a', 'complete', path)

    def test_production_policy_configuration_is_explicit(self):
        self.assertTrue(callable(getattr(supervisor, '_current_container_args', None)),
                        'current production task/CPU/job configuration is missing')

    def test_current_args_keep_task_cpu_memory_and_exec_independent(self):
        policy = records.amended_policy()
        args = supervisor._current_container_args('docker', 'test', policy)
        for key, value in (('--pids-limit', '64'), ('--cpus', '4'), ('--memory', '8589934592'),
                           ('--memory-swap', '8589934592')):
            self.assertEqual(args[args.index(key)+1], value)
        self.assertIn('/work:rw,nosuid,nodev,noexec,size=8589934592,uid=65532,gid=65532,mode=0700', args)
        with self.assertRaisesRegex(supervisor.GateError, 'native'):
            supervisor._current_container_args('docker', 'test', policy, work_mount_mode='exec')
        native = [{'executable': '/work/src/helper', 'executable_sha256': 'a'*64,
                   'inputs': {'src/helper.c': 'b'*64}, 'command': ['/work/src/helper']}]
        args = supervisor._current_container_args('docker', 'test', policy,
                                                  work_mount_mode='exec', native_tools=native)
        self.assertIn('/work:rw,nosuid,nodev,exec,size=8589934592,uid=65532,gid=65532,mode=0700', args)
        self.assertTrue(any('/tmp:rw,nosuid,nodev,noexec,' in arg for arg in args))

    def test_recipe_jobserver_unbounded_and_native_identity_mutants_reject(self):
        valid = {'scheduler': 'gnu-make', 'jobs': 4,
                 'command': ['make', '-j4', '-f', 'Makefile']}
        supervisor._validate_job_policy(valid, {'PATH': '/usr/bin:/bin', 'MAKEFLAGS': '-j4'})
        for policy, environment in (({**valid, 'jobs': 5}, {}),
                                    ({**valid, 'command': ['make', '-j']}, {}),
                                    (valid, {'MAKEFLAGS': '--jobserver-auth=1,2'}),
                                    ({**valid, 'scheduler': 'unknown'}, {}),
                                    (valid, {'GNUMAKEFLAGS': '-j8'})):
            with self.subTest(policy=policy), self.assertRaisesRegex(supervisor.GateError, 'job|scheduler'):
                supervisor._validate_job_policy(policy, environment)
        for executable in ('/tmp/helper', '/usr/bin/helper', '/work/../tmp/helper'):
            with self.subTest(executable=executable), self.assertRaisesRegex(supervisor.GateError, 'native'):
                supervisor._validate_native_tools([{'executable': executable, 'executable_sha256': 'a'*64,
                    'inputs': {'src.c': 'b'*64}, 'command': [executable]}], 'exec')

    def test_current_gate_rejects_stale_missing_or_forged_enforcement(self):
        for receipt in ({}, {'schema': 'genewhip-phase5-enforcement-v2', 'status': 'pass'}):
            with self.assertRaisesRegex(supervisor.GateError, 'enforcement'):
                supervisor._verify_enforcement_document(receipt)
        policy = records.amended_policy()
        receipt = {'schema': 'genewhip-phase5-enforcement-v2', 'status': 'pass',
                   'policy_sha256': records.identity_digest(policy),
                   'identities': supervisor._enforcement_identities(),
                   'controls': {name: {'status': 'pass', 'observations': {'claimed': True}}
                                for name in supervisor.ENFORCEMENT_CONTROLS},
                   'candidate_execution': False, 'elapsed_us': 1,
                   'requested': {k: policy[k] for k in ('linux_tasks_per_container', 'cpus_per_container',
                                 'concurrent_build_jobs', 'aggregate_container_memory_bytes', 'swap_bytes',
                                 'address_space_bytes_per_process')}}
        with self.assertRaisesRegex(supervisor.GateError, 'named observation rejected'):
            supervisor._verify_enforcement_document(receipt)

    def test_monotonic_deadline_cannot_refresh_or_exceed_original_remainder(self):
        ticks = [1000000]
        deadline = supervisor.SetupDeadline(10, now_ns=lambda: ticks[0])
        self.assertEqual(deadline.remaining_us(), 10)
        ticks[0] += 1001
        self.assertEqual(deadline.elapsed_us(), 2)
        self.assertEqual(deadline.remaining_us(), 8)
        self.assertEqual(deadline.timeout_seconds(120), .000008)
        ticks[0] += 9000
        with self.assertRaisesRegex(supervisor.GateError, 'deadline'):
            deadline.timeout_seconds(120)


class BuildSupervisorContract(unittest.TestCase):
    def test_quarantine_cap_counts_all_workspaces_as_one_tree(self) -> None:
        test_root = ROOT / "local-fixtures" / "phase5" / ("aggregate-cap-" + uuid.uuid4().hex[:12])
        for name in ("workspace-a", "workspace-b"):
            workspace = test_root / name
            workspace.mkdir(parents=True)
            (workspace / "bytes.bin").write_bytes(b"123456")
        limits = dict(records.SCREENING_LIMITS)
        limits["total_quarantine_bytes"] = 10
        try:
            with self.assertRaisesRegex(supervisor.GateError, "aggregate disk cap"):
                supervisor._ensure_quarantine_capacity(limits, root=test_root)
        finally:
            shutil.rmtree(test_root, ignore_errors=True)

    def test_two_distinct_repeatable_lineages_stop_selection_including_reserve(self) -> None:
        ledger = json.loads((ROOT / "tests/evidence/fixtures/phase5-screening-synthetic.json").read_text())
        eligibility = []
        for frozen in ledger["candidates"]:
            eligibility.append({"title_id": frozen["id"], "lineage_id": frozen["lineage_id"],
                                "decision": "eligible",
                                "checks": {name: True for name in records.ELIGIBILITY_CHECKS},
                                "materials": [{"path": "src/main.c", "license": "MIT",
                                               "notice": "LICENSE"}]})
        for title_id in ("tank-battle", "recursion94"):
            item = next(value for value in ledger["candidates"] if value["id"] == title_id)
            item.update(state="build-screened", outcome="pass")
        selected, reason = supervisor._select_next_candidate(
            ledger, {"candidates": eligibility})
        self.assertIsNone(selected)
        self.assertIn("two distinct source lineages", reason)
        for item in ledger['candidates']:
            if item['id'] in ('tank-battle', 'recursion94'):
                item.update(state='reference-active-field-unknown', outcome='unknown',
                            post_build_checks={'repeatable_build': True})
        selected, reason = supervisor._select_next_candidate(ledger, {'candidates': eligibility})
        self.assertIsNone(selected)
        self.assertIn('two distinct source lineages', reason)

    def test_screen_next_without_config_returns_semantic_block_when_no_candidate_eligible(self) -> None:
        quarantine = ROOT / "local-fixtures" / "phase5"
        test_root = quarantine / ("screen-gate-test-" + uuid.uuid4().hex[:12])
        test_root.mkdir(parents=True)
        try:
            ledger = json.loads((ROOT / "fixtures" / "candidate-screening.json").read_text())
            for frozen in ledger["candidates"]:
                frozen["identity_history"] = []
                frozen["counters"] = {name: 0 for name in records.COUNTER_LIMITS}
                frozen["state"] = "unattempted"
                frozen["outcome"] = "unknown"
            ledger_path = test_root / "screening.json"
            ledger_path.write_text(json.dumps(records.validate_screening(ledger)), encoding="utf-8")
            eligibility = json.loads((ROOT / "evidence" / "phase5-eligibility.json").read_text())
            for candidate in eligibility["candidates"]:
                candidate["decision"] = "unknown"
                candidate["unverified_categories"] = list(records.MATERIAL_CATEGORIES)
            eligibility_path = test_root / "eligibility.json"
            eligibility_path.write_text(json.dumps(eligibility), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-I", str(SUPERVISOR), "--screen-next", "--ledger",
                 str(ledger_path), "--eligibility", str(eligibility_path)],
                cwd=ROOT, text=True, capture_output=True, timeout=30, check=False)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertIn('"status": "blocked"', result.stdout)
            self.assertNotIn("requires --ledger and --eligibility", result.stderr)
        finally:
            shutil.rmtree(test_root, ignore_errors=True)

    def test_self_test_exercises_enforced_subprocess_safety(self) -> None:
        result = subprocess.run(
            [sys.executable, "-I", str(SUPERVISOR), "--self-test"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"supervisor self-test must pass its real isolation and cap probes; "
            f"exit={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}",
        )
        self.assertIn("PASS", result.stdout)

    def test_container_has_independent_virtual_and_swap_caps(self) -> None:
        args = supervisor._container_args("docker", "limit-test", memory="64m",
                                         address_space_bytes=32 * 1024 * 1024)
        self.assertIn("--memory-swap", args)
        self.assertEqual(args[args.index("--memory-swap") + 1], "64m")
        self.assertIn("--memory", args)
        self.assertIn("--memory-swap", args)
        self.assertEqual(args[args.index("--memory") + 1], args[args.index("--memory-swap") + 1])
        self.assertEqual(supervisor.records.SCREENING_LIMITS["address_space_bytes_per_process"],
                         8_589_934_592)

    def test_two_clean_outputs_keep_order_and_raw_identities(self) -> None:
        result = records.compare_build_outputs([
            {"ordinal": 1, "bytes": b"same"},
            {"ordinal": 2, "bytes": b"same"},
        ])
        self.assertEqual(result["status"], "byte-identical")
        self.assertEqual([item["ordinal"] for item in result["raw_outputs"]], [1, 2])
        self.assertEqual(len({item["sha256"] for item in result["raw_outputs"]}), 1)

    def test_null_empty_and_unexplained_outputs_cannot_pass(self) -> None:
        with self.assertRaisesRegex(ValueError, "empty or null"):
            records.compare_build_outputs([{"ordinal": 1, "bytes": b""},
                                          {"ordinal": 2, "bytes": b"x"}])
        result = records.compare_build_outputs([{"ordinal": 1, "bytes": b"ax"},
                                                {"ordinal": 2, "bytes": b"ay"}])
        self.assertEqual(result["status"], "blocked-unexplained-variation")

    def test_explained_variation_requires_exact_raw_difference(self) -> None:
        outputs = [{"ordinal": 1, "bytes": b"ax"}, {"ordinal": 2, "bytes": b"ay"}]
        forged = {"regions": [{"start": 0, "end": 1}], "cause": "timestamp",
                  "implication": "canonical bytes retained", "canonical_ordinal": 1}
        self.assertEqual(records.compare_build_outputs(outputs, forged)["status"],
                         "blocked-unexplained-variation")
        exact = {"regions": [{"start": 1, "end": 2,
                              "first_sha256": __import__("hashlib").sha256(b"x").hexdigest(),
                              "second_sha256": __import__("hashlib").sha256(b"y").hexdigest()}],
                 "cause": "declared test variation", "implication": "keep both raw outputs",
                 "canonical_ordinal": 1}
        self.assertEqual(records.compare_build_outputs(outputs, exact)["status"],
                         "explained-variation")

    def test_title_attempt_counter_cannot_reset_on_identity_change(self) -> None:
        screening = __import__("json").loads(
            (ROOT / "fixtures" / "candidate-screening.json").read_text())
        first = records.append_attempt(screening, "tank-battle", "rom_build_invocation",
                                       {"source": "a"})
        second = records.append_attempt(first, "tank-battle", "rom_build_invocation",
                                        {"source": "b"})
        tank = next(item for item in second["candidates"] if item["id"] == "tank-battle")
        self.assertEqual(tank["counters"]["rom_build_invocations"], 2)
        self.assertNotEqual(tank["identity_history"][0]["identity_sha256"],
                            tank["identity_history"][1]["identity_sha256"])

    def test_material_review_fails_closed_on_silent_categories(self) -> None:
        candidate = {"title_id": "x", "materials": [{"category": "code", "path": "src/a.c",
                     "sha256": "abc", "source_revision": "rev", "terms_source": "LICENSE",
                     "license": "MIT", "notice": "NOTICE"}], "absent_categories": []}
        self.assertFalse(records.inspect_materials(candidate)["eligible"])

    def test_historical_screening_cli_is_read_only_even_with_eligible_synthetic_material(self) -> None:
        quarantine = ROOT / "local-fixtures" / "phase5"
        test_root = quarantine / ("screen-cli-test-" + uuid.uuid4().hex[:12])
        test_root.mkdir(parents=True)
        try:
            ledger = json.loads((ROOT / "fixtures" / "candidate-screening.json").read_text())
            for frozen in ledger["candidates"]:
                frozen["identity_history"] = []
                frozen["counters"] = {name: 0 for name in records.COUNTER_LIMITS}
                frozen["state"] = "unattempted"
                frozen["outcome"] = "unknown"
            ledger = records.validate_screening(ledger)
            workspaces = []
            source = b"reviewed-harmless-input\n"
            build = b"#!/bin/sh\nset -eu\nmkdir -p out\ncat source.txt > out/rom.bin\n"
            for name in ("clean-a", "clean-b"):
                workspace = test_root / name
                workspace.mkdir()
                (workspace / "source.txt").write_bytes(source)
                build_file = workspace / "build.sh"
                build_file.write_bytes(build)
                build_file.chmod(0o755)
                workspaces.append(workspace)

            candidates = []
            for frozen in ledger["candidates"]:
                review = {name: "harmless authored contract fixture"
                          for name in ("source_terms", "asset_terms", "font_music_terms",
                                       "runtime_terms", "generated_rom_terms", "retained_notices",
                                       "pinned_inputs", "lineage_evidence")}
                review["source_evidence"] = ["test-authored-local-fixture"]
                if frozen["id"] == "tank-battle":
                    materials = [
                        {"category": "code", "path": "source.txt",
                         "sha256": hashlib.sha256(source).hexdigest(),
                         "source_revision": frozen["source_revision"], "terms_source": "test fixture",
                         "license": "MIT", "notice": "test fixture notice"},
                        {"category": "build_tools", "path": "build.sh",
                         "sha256": hashlib.sha256(build).hexdigest(),
                         "source_revision": frozen["source_revision"], "terms_source": "test fixture",
                         "license": "MIT", "notice": "test fixture notice"},
                    ]
                    checks = {name: True for name in records.ELIGIBILITY_CHECKS}
                    checks["repeatable_build"] = False
                    candidates.append({"title_id": frozen["id"], "repository": frozen["repository"],
                                       "source_revision": frozen["source_revision"],
                                       "build_image": "alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
                                       "lineage_id": frozen["lineage_id"], "decision": "eligible",
                                       "materials": materials,
                                       "absent_categories": sorted(set(records.MATERIAL_CATEGORIES)
                                                                    - {"code", "build_tools"}),
                                       "checks": checks, "review": review})
                else:
                    candidates.append({"title_id": frozen["id"], "repository": frozen["repository"],
                                       "source_revision": frozen["source_revision"],
                                       "lineage_id": frozen["lineage_id"], "decision": "unknown",
                                       "materials": [], "unverified_categories": list(records.MATERIAL_CATEGORIES),
                                       "absent_categories": [], "checks": {}, "review": review})
            eligibility_path = test_root / "eligibility.json"
            eligibility_path.write_text(json.dumps({"schema": "genewhip-phase5-eligibility-v1",
                                                    "candidates": candidates}), encoding="utf-8")
            ledger_path = test_root / "screening.json"
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
            config = {"schema": "genewhip-phase5-build-config-v1", "title_id": "tank-battle",
                      "source_revision": ledger["candidates"][0]["source_revision"],
                      "build_image": "alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
                      "workspaces": [workspace.relative_to(ROOT).as_posix() for workspace in workspaces],
                      "output_relative": "out/rom.bin",
                      "build_recipe": {"path": "build.sh", "args": []},
                      "build_environment": {"PATH": "/usr/local/bin:/usr/bin:/bin"}}
            config_path = test_root / "build-config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            invalid_config = dict(config)
            invalid_config["build_environment"] = {"PATH": "/usr/bin", "HOME": "/tmp"}
            invalid_path = test_root / "invalid-build-config.json"
            invalid_path.write_text(json.dumps(invalid_config), encoding="utf-8")
            with self.assertRaisesRegex(supervisor.GateError, "reserved name"):
                supervisor._validate_build_config(invalid_path, "tank-battle")
            result = subprocess.run(
                [sys.executable, "-I", str(SUPERVISOR), "--screen-next", "--ledger", str(ledger_path),
                 "--eligibility", str(eligibility_path), "--build-config", str(config_path)],
                cwd=ROOT, text=True, capture_output=True, timeout=90, check=False)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertIn('historical v1 screening is read-only', result.stdout)
            self.assertEqual(json.loads(ledger_path.read_text()), ledger)
            self.assertFalse(any((workspace / 'out/rom.bin').exists() for workspace in workspaces))
        finally:
            shutil.rmtree(test_root, ignore_errors=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--policy-self-test"]:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(CurrentPolicyContract)
        raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
    if sys.argv[1:] == ["--enforcement-self-test"]:
        raise SystemExit(supervisor.enforcement_self_test())
    if sys.argv[1:] == ["--self-test"]:
        sys.argv = [sys.argv[0]]
    unittest.main(verbosity=2)
