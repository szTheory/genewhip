#!/usr/bin/env python3
"""Actual headless capture CLI; only independently authored 1024-byte guests.

No project module is imported. AST-load only the production pure argv function,
checking its caller uses it; diagnostics cannot enter accounting/game consumers.
The specified oracle distinguishes a retained PEA pair from a later SWAP/fault.
"""
import argparse
import ast
import hashlib
import json
import os
import pathlib
import signal
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[2]
LIMIT = 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def argv_builder():
    tree = ast.parse((ROOT / 'tests/fixtures/phase6_repairs.py').read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'capture_command')
    # Compile this pure definition alone. No import statements or module-level
    # expressions from the coordinator (including its dynamic loaders) execute.
    allowed = {'str'}
    assert all(isinstance(n.func, ast.Name) and n.func.id in allowed or
               isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and
               n.func.value.id == 'command' and n.func.attr == 'append'
               for n in ast.walk(function) if isinstance(n, ast.Call))
    caller = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_capture_reserved')
    assert sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and
               n.func.id == 'capture_command' for n in ast.walk(caller)) == 1
    scope = {'__builtins__': {'str': str}}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<pure-capture-argv>', 'exec'), scope)
    return scope['capture_command']


def acceptance_predicate():
    """Load named pure validators only, never either enclosing module."""
    def definitions(path, names, scope):
        tree = ast.parse((ROOT/path).read_text())
        selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
        assert {n.name for n in selected} == set(names)
        assert not any(isinstance(n, (ast.Import, ast.ImportFrom)) for f in selected for n in ast.walk(f))
        exec(compile(ast.Module(body=selected, type_ignores=[]), '<pure-capture-validators>', 'exec'), scope)
    stack = {}
    definitions('tests/evidence/phase6_stack_observation_contract.py', ['validate_stack_pair'], stack)

    def stack_only_loader(name, path):
        assert name == 'phase6_stack_contract' and path == 'tests/evidence/phase6_stack_observation_contract.py'
        return SimpleNamespace(validate_stack_pair=stack['validate_stack_pair'])

    scope = {'load_module': stack_only_loader}
    definitions('tests/evidence/phase6_tank_continuation_contract.py',
                ['boundary_pair', '_span', 'validate_pea_capture'], scope)
    return scope['validate_pea_capture']


def guest(code='48790006923c203c1234567848404afc'):
    data = bytearray(1024)
    struct.pack_into('>II', data, 0, 0x00ff0010, 0x200)
    data[0x200:0x200 + len(bytes.fromhex(code))] = bytes.fromhex(code)
    return bytes(data)


def descriptor():
    # Independent GWRC v1 field-clock descriptor: three signals, one field, at
    # most sixteen boundaries. No fixture compiler or source/game data.
    words = [0] * 44
    words[:7] = [0x43525747, 1, 3, 1, 1, 0, 3]
    words[30] = 16
    words[32:] = [0x200, 0x200, 2, 0, 0x202, 0x202, 2, 0, 0x204, 0x204, 2, 0]
    return struct.pack('<44I', *words)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    client = args.client.resolve()
    build_command = argv_builder()
    validate_capture = acceptance_predicate()
    rows, failures = [], []
    with tempfile.TemporaryDirectory(prefix='gw-capture-argv-') as temp:
        work = pathlib.Path(temp)
        rom, plan, report = work/'guest.bin', work/'route.gwrc', work/'report.json'
        plan.write_bytes(descriptor())

        def check(condition, message):
            if not condition:
                raise AssertionError(message)

        def run(name, *, pc=0x200, observer=True, prefix=False, remove=(), code=None, expected=1, legacy=False):
            data = guest() if code is None else guest(code)
            rom.write_bytes(data)
            plan_data = (b'GWRP'+struct.pack('<HHI',1,1,0)+struct.pack('<BBHIIQQ',1,0,1,0,0,1,0xffffffffffffffff)+
                         struct.pack('<IB3x',0x200,1)+b'\x48') if legacy else descriptor()
            plan.write_bytes(plan_data)
            report.unlink(missing_ok=True)
            command = build_command(client, plan, report, pc, rom, stack_observer=observer)
            if prefix:
                command.append('--route-probe-only')
            for flag in remove:
                index = command.index(flag)
                del command[index:index + (2 if flag in ('--route-plan', '--route-report', '--route-instruction-probe') else 1)]
            start = time.monotonic()
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            timed_out = False
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
                timed_out = True
            raw = report.read_bytes() if report.exists() else b''
            check(max(len(stdout), len(stderr), len(raw)) <= LIMIT, 'output limit')
            row = {'case': name, 'command': [str(x).replace(str(work), '<diagnostic>').replace(str(client), '<client>') for x in command],
                   'return_code': process.returncode, 'timed_out': timed_out, 'wall_seconds': time.monotonic()-start,
                   'guest_hex': data.hex(), 'guest_sha256': sha(data),
                   'descriptor_hex': plan_data.hex(), 'descriptor_sha256': sha(plan_data),
                   'stdout': stdout.decode(), 'stderr': stderr.decode(), 'report_raw': raw.decode(),
                   'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr), 'report_sha256': sha(raw)}
            rows.append(row)
            check(not timed_out, 'diagnostic process-tree deadline')
            check(process.returncode == expected, f'{name}: expected exit {expected}, got {process.returncode}')
            if expected == 2:
                check(not raw and not stdout and b'usage:' in stderr, 'usage precedes report/ROM execution')
                return None
            native = json.loads(raw)
            check(native['fields'] <= 1 and native['boundary_calls'] <= 16, 'work limit')
            return native

        def case(name, test):
            try:
                test()
                print('PASS', name)
            except (AssertionError, KeyError, TypeError, ValueError) as exc:
                failures.append({'case': name, 'error': str(exc)})
                print('FAIL', name, str(exc))

        def full(observer=True):
            native = run('full-observer' if observer else 'full-disabled', observer=observer)
            probe, last = native['probe_boundary'], native['last_boundary']
            check(native['termination'] == 'error' and native['stop_reason'] == 2, 'later unsupported stop required')
            check(last['before']['pc'] == 0x20e and last['opcode'] == 0x4afc and not last['retired'], 'exact later boundary')
            check(last['before']['d'][0] == 0x56781234, 'SWAP executed after probe')
            check(native['instruction_address'] == last['instruction_address'] == 0x20e and
                  native['first_stop_tick'] == last['after']['tick'] == native['final_tick'], 'terminal metadata')
            check(probe['before']['pc'] == 0x200 and probe['opcode'] == 0x4879 and probe['retired'], 'PEA pair')
            check(probe['after']['a'][7] == probe['before']['a'][7]-4 and
                  probe['after']['tick']-probe['before']['tick'] == 140 and
                  probe['after']['instructions'] == probe['before']['instructions']+1 and
                  probe['before']['sr'] == probe['after']['sr'], 'PEA retirement, stack, timing and SR')
            check(native['boundary_calls'] == 4 and native['final_tick'] > probe['after']['tick'], 'continued full capture')
            for state in ('before', 'after'):
                check(('stack_observation' in probe[state]) == observer, 'opt-in stack observation')
                check('stack_observation' not in last[state], 'no stack observation at later boundary')
            if observer:
                before, after = probe['before']['stack_observation'], probe['after']['stack_observation']
                check(before['bytes'] == [0,0,0,0] and after['bytes'] == [0,6,146,60], 'actual big endian PEA write')
                check(before['addresses24'] == after['addresses24'] == list(range(0xff000c,0xff0010)), 'same original A7 base')
                check(before['read_calls'] == after['read_calls'] == 4 and before['status'] == after['status'] == [0]*4, 'eight successful reads')
                check(all(validate_capture(native, 0x200).values()), 'actual consumer acceptance predicate')
            return native

        case('full capture preserves later stop', full)
        case('observer disabled preserves later stop', lambda: full(False))

        def prefix():
            native = run('prefix', prefix=True, expected=0)
            check(native['termination'] == 'diagnostic-prefix' and native['stop_reason'] == 0 and
                  native['first_stop_tick'] is None and native['boundary_calls'] == 1 and
                  native['last_boundary'] == native['probe_boundary'] and
                  native['probe_boundary']['after']['d'][0] == 0, 'prefix cannot masquerade as later-stop capture')
            try:
                validate_capture(native, 0x200)
            except ValueError as exc:
                check(str(exc) == 'capture-terminal-or-resource-invalid', 'exact consumer prefix rejection')
            else:
                raise AssertionError('consumer accepted diagnostic prefix as capture')
        case('prefix deliberately terminates early', prefix)

        for pc in (0x1ff, 0x202, 0x210):
            def absent(pc=pc):
                native = run('absent-'+str(pc), pc=pc)
                check(native['probe_boundary'] is None and native['instruction_address'] == 0x20e, 'absent target is explicit')
                check('stack_observation' not in native['last_boundary']['before'], 'absent target does not read stack')
            case('absent target '+str(pc), absent)

        def neighbor():
            native = run('neighbor', pc=0x206)
            probe = native['probe_boundary']
            check(probe['opcode'] == 0x203c and probe['after']['d'][0] == 0x12345678, 'neighbor instruction captured')
            check(probe['before']['stack_observation']['bytes'] == probe['after']['stack_observation']['bytes'], 'non-writing neighbor stack unchanged')
        case('instruction neighbor', neighbor)


        def error():
            native = run('observation-error', pc=0x206, code='2e7c0080000848790006923c4afc')
            pair = native['probe_boundary']
            check(native['stop_reason'] == 3 and pair['retired'] is False, 'bus fault retained')
            for state in ('before','after'):
                stack = pair[state]['stack_observation']
                check(stack['disposition'] == 'observation-error' and stack['bytes'] == [None]*4 and
                      all(status != 0 for status in stack['status']), 'failed reads explicit')
        case('observation error remains error', error)

        for flags in (('--route-instruction-probe',), ('--route-plan',), ('--route-report',),
                      ('--route-plan','--route-report')):
            case('missing prerequisites '+','.join(flags), lambda flags=flags: run('missing-'+','.join(flags), remove=flags, expected=2))
        case('prefix requires instruction probe', lambda: run('prefix-missing-probe', observer=False, prefix=True,
             remove=('--route-instruction-probe',), expected=2))
        case('stack observer requires controller', lambda: run('legacy-descriptor', legacy=True, expected=2))

    source_names = ['tools/headless/main.c', 'tools/session/route_controller.c', 'tools/session/session.c',
                    'tests/fixtures/phase6_repairs.py', 'tests/session/phase6_capture_argv_contract.py',
                    'tests/evidence/phase6_tank_continuation_contract.py', 'tests/evidence/phase6_stack_observation_contract.py',
                    'tools/session/CMakeLists.txt']
    evidence = {'schema': 'genewhip-d125-actual-capture-argv-v1', 'oracle_type': 'specified',
                'status': 'fail' if failures else 'pass', 'failures': failures, 'native_processes': len(rows),
                'diagnostic_only': True, 'qualification_evidence': False,
                'client_sha256': sha(client.read_bytes()), 'sources': {p: sha((ROOT/p).read_bytes()) for p in source_names},
                'limits': {'guest_bytes':1024, 'fields':1, 'boundaries':16, 'seconds_per_tree':5, 'stream_report_bytes':LIMIT}, 'runs': rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2)+'\n')
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
