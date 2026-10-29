#!/usr/bin/env python3
"""Bounded, append-only observed-stop repair coordinator; frozen inputs only."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import os

ROOT=pathlib.Path(__file__).resolve().parents[2]
LEDGER=ROOT/'evidence/phase6-repairs.json'
ACCOUNTING_ANCHOR=pathlib.Path('/private/tmp/genewhip-phase6-execution-anchor.json')

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

compiler=None
contracts=None
accounting=None

def _load_legacy_modules():
    global compiler,contracts,accounting,PEA_SHORT_CASES
    if compiler is None:compiler=module('repairs_compiler','scripts/evidence/phase6_routes.py')
    if contracts is None:contracts=module('repairs_contracts','tests/session/phase6_route_contract.py')
    if accounting is None:accounting=module('phase6_accounting','scripts/evidence/phase6_accounting.py')
    PEA_SHORT_CASES=accounting.PEA_SHORT_CASES

def now(): return datetime.now(timezone.utc).isoformat()
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def _write_control_stream_exclusive(directory_fd,name,data):
    if pathlib.PurePath(name).name!=name:raise RuntimeError('control-stream-name-invalid')
    try:
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=directory_fd)
    except FileExistsError as exc:
        raise RuntimeError('original-control-raw-stream-collision-after-launch') from exc
    with os.fdopen(fd,'wb') as stream:stream.write(data[:1048576])

class CaptureFailure(RuntimeError):
    """Carry the observed prefix out of temporary report storage."""
    def __init__(self, message, receipt):
        super().__init__(message)
        self.receipt=receipt

def validate_pair(pair,pc=None):
    if not isinstance(pair,dict): raise RuntimeError('missing-instruction-boundary')
    for name in ('before','after'):
        s=pair[name]
        if not all(isinstance(s[k],int) and s[k]>=0 for k in ('pc','sr','tick','instructions','diagnostic_dropped')): raise RuntimeError('invalid-boundary-scalars')
        if any(len(s[k])!=8 or any(type(v)!=int or not 0<=v<=0xffffffff for v in s[k]) for k in ('a','d')): raise RuntimeError('invalid-registers')
        if len(s['spans'])>64: raise RuntimeError('span-count-bound')
        for span in s['spans']:
            if not 0<=span['address']<=0xffffff or not 0<len(bytes.fromhex(span['bytes']))<=64: raise RuntimeError('span-byte-bound')
    if pair['before']['pc']!=pair['instruction_address'] or (pc is not None and pc!=pair['before']['pc']): raise RuntimeError('field-start-is-not-before-instruction')
    if pair['returned_overshoot']!=max(0,pair['after']['tick']-pair['target_tick']): raise RuntimeError('invalid-boundary-overshoot')
    return pair

def validate_capture_boundaries(native,pc,receipt):
    """Consume the controller producer contract without inferring probe reach."""
    if native['stop_reason'] in (2,3,4):
        pair=validate_pair(native['last_boundary'])
        if (any(native[k]!=pair[k] for k in ('instruction_address','opcode','stop_reason')) or
                native['first_stop_tick']!=pair['after']['tick'] or
                native['final_tick']!=pair['after']['tick']):
            raise RuntimeError('stop-boundary-metadata-mismatch')
        if native.get('probe_boundary') is None:
            # A real stop can precede the requested PC. It remains a halt,
            # with its observed boundary, never PEA success.
            receipt['boundary_disposition']='stopped-before-requested-probe'
            raise RuntimeError('probe-not-reached-before-stop')
    validate_pair(native['probe_boundary'],pc)

def authorize_capture(*, purpose, plan, case, source_identity, current_source_identity,
                      contract_identity, target_signature, ledger_path=None, launcher,
                      boot_identity, allowed_root=None):
    """Shared coordinator entry used by live capture and temporary-ledger tests."""
    actual_source_identity=accounting.source_identity(ROOT)
    return accounting.authorize_launch(
        pathlib.Path(ledger_path or LEDGER), purpose=purpose, plan=plan, case=case,
        source_identity=source_identity, current_source_identity=actual_source_identity,
        contract_identity=contract_identity, target_signature=target_signature,
        launcher=launcher, boot_identity=boot_identity,
        allowed_root=allowed_root or (pathlib.Path(ledger_path).parent if ledger_path else ROOT))

def freeze_observer_manifest(manifest_path, *, ledger_path=None, boot_identity, allowed_root=None):
    actual_source_identity=accounting.source_identity(ROOT)
    return accounting.freeze_observer_manifest(
        pathlib.Path(ledger_path or LEDGER), pathlib.Path(manifest_path),
        source_identity=actual_source_identity, boot_identity=boot_identity,
        allowed_root=allowed_root or (pathlib.Path(ledger_path).parent if ledger_path else ROOT))

def authorize_observer_activity(*, purpose, plan, case, source_identity, binary_identity,
                                command_identity, manifest_sha256, ledger_path=None,
                                launcher, boot_identity, allowed_root=None):
    actual_source_identity=accounting.source_identity(ROOT)
    return accounting.authorize_observer_activity(
        pathlib.Path(ledger_path or LEDGER), purpose=purpose, plan=plan, case=case,
        source_identity=source_identity, current_source_identity=actual_source_identity,
        binary_identity=binary_identity, command_identity=command_identity,
        manifest_sha256=manifest_sha256, launcher=launcher, boot_identity=boot_identity,
        allowed_root=allowed_root or (pathlib.Path(ledger_path).parent if ledger_path else ROOT))


def capture(build,title,pc,stop,label,*,purpose=None,case=None,contract_identity=None):
    if purpose is None:
        raise accounting.AccountingError('generic-capture-denied')
    if not case or not contract_identity:
        raise accounting.AccountingError('capture-purpose-requires-case-and-contract')
    expected_title='tank-battle' if purpose=='independent-pea' else 'recursion94' if purpose=='rec-validation' else None
    if title!=expected_title:
        raise accounting.AccountingError('capture-purpose-title-mismatch')
    if purpose=='independent-pea' and stop!=accounting.PEA_SIGNATURE:
        raise accounting.AccountingError('independent-pea-scope-denied')
    source_identity=accounting.source_identity(ROOT)
    boot_identity=accounting.read_boot_identity()

    def perform(_reservation):
        try:
            return _capture_reserved(build,title,pc,stop,label)
        except CaptureFailure as error:
            # authorize_launch persists this same reservation on failure. Keep
            # the native result even when its boundary cannot be validated.
            _reservation['launcher_failure_receipt']=error.receipt
            raise

    return authorize_capture(purpose=purpose,plan='06-11' if purpose=='independent-pea' else '06-12',
        case=case,source_identity=source_identity,current_source_identity=source_identity,
        contract_identity=contract_identity,target_signature=stop,launcher=perform,
        boot_identity=boot_identity)


def capture_command(client,plan,report,pc,rom,*,stack_observer=False):
    """Full capture continues after the probe; prefix-only is a different mode."""
    command=[str(client),'--route-plan',str(plan),'--route-report',str(report),
        '--route-instruction-probe',str(pc),str(rom)]
    if stack_observer:command.append('--route-probe-stack-before-a7')
    return command


def _capture_reserved(build,title,pc,stop,label,*,binary_override=None,stack_observer=False):
    d=json.loads(LEDGER.read_text())
    if sum(p.stat().st_size for p in build.rglob('*') if p.is_file())>6442450944:
        raise RuntimeError('route-disk-budget-exhausted')
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True,timeout=10).strip()
    attempt=sum(1 for row in d['records'] if row.get('record_type')=='probe-attempt'
                and row.get('target_stop_signature')==stop)+1
    route=next(r for r in compiler.compile_routes()['routes'] if r['fixture']==title and r['case']['id']=='full-route')
    binary,metadata=compiler.lower_route(route)
    if binary_override is not None:binary=binary_override
    client=build/'tools/session/gw_headless'
    r={'record_id':f'GW-06-04-{stop}-ATTEMPT-{attempt:03d}','record_type':'probe-attempt',
       'stop_id':stop,'target_stop_signature':stop,'title_id':title,'phase':'GW-06','label':label,
       'source_head':head,'source_dirty':bool(subprocess.check_output(['git','diff','--name-only'],cwd=ROOT,text=True,timeout=10).strip()),
       'implementation_sources':{str(p.relative_to(ROOT)):sha(p) for p in sorted((ROOT/'src').glob('*')) if p.is_file()},
       'baseline_sha256':contracts.BASELINE_SHA256,'compiled_sha256':hashlib.sha256(binary).hexdigest(),
       'identity':route['identity'],'client_binary_sha256':sha(client),'native_report':None,'processes':[],
       'status':'reserved','created_at':now(),'limits':{'total_fields':4500 if title=='tank-battle' else 7200,'active_ticks':3600,
       'watchdog_seconds':600,'stdout_bytes':1048576,'stderr_bytes':1048576,'trace_bytes':16777216,'trace_rows':100000,
       'summary_bytes':8388608,'disk_bytes':6442450944,'event_capacity':64}}
    try:
        with tempfile.TemporaryDirectory(prefix='repairs-',dir=build) as directory:
            work=pathlib.Path(directory);plan=work/'route.gwrc';report=work/'report.json';plan.write_bytes(binary)
            command=capture_command(client.relative_to(ROOT),plan.relative_to(ROOT),
                report.relative_to(ROOT),pc,compiler.SOURCES[title][3],stack_observer=stack_observer)
            r['command']=command
            r['process_streams']={}
            try:
                result=contracts._run_client(client,command,r['processes'],report=report,timeout=600,cwd=ROOT,
                    retained_streams=r['process_streams'])
            finally:
                # _run_client can itself raise while parsing the report.
                # Copy the bounded stream even on that exceptional path.
                if report.is_file():
                    if report.stat().st_size>r['limits']['summary_bytes']:
                        raise RuntimeError('native-report-byte-bound')
                    raw=report.read_bytes()
                    r['native_report_sha256']=hashlib.sha256(raw).hexdigest()
                    r['native_report_raw']=raw.decode('utf-8',errors='replace')
            if r['processes'][-1]['bound_violation']: raise RuntimeError('process-resource-bound')
            native=json.loads(report.read_text());r['native_report']=native
            if result.returncode not in (0,1) or native.get('schema')!='genewhip-route-native-v1': raise RuntimeError('native-execution-failure')
            if native['plan_fnv1a64']!=compiler.plan_fingerprint(binary): raise RuntimeError('descriptor-identity')
            if native['queue_high_water']>64 or len(native['samples'])>100000: raise RuntimeError('native-work-bound')
            validate_capture_boundaries(native,pc,r)
            r['status']='observed-stop' if result.returncode else 'route-returned'
            r['route_stages']={k:('pass' if k=='load' else 'blocked' if k=='boot' else 'unreached') for k in compiler.STAGES}
            r['outcome']='blocked' if result.returncode else 'pending-oracle-validation'
            print(json.dumps({'record_id':r['record_id'],'status':r['status'],'pc':native['instruction_address'],
                'opcode':native['opcode'],'tick':native['first_stop_tick'],'fields':native['fields'],'active_ticks':native['active_ticks'],
                'process_seconds':r['processes'][-1]['wall_seconds']},sort_keys=True))
    except (OSError,RuntimeError,ValueError,KeyError,TypeError) as e:
        r['status']='interrupted';r['failure']=str(e)
        raise CaptureFailure(str(e),r) from e
    return r

def blocked_lane(build,lane):
    """A binding failed prerequisite forbids another full-route search.

    These are honest blocked closeout reports, never cached acceptance passes.
    The complete case/stage denominator remains visible, including unexecuted
    withholds and audio. Only cheap already-authorized regressions run here.
    """
    d=json.loads(LEDGER.read_text());halt=d.get('halt',{})
    if not halt.get('binding'):raise RuntimeError('no-complete-feasibility-implementation; repairs-in-progress')
    commands=[]
    if lane=='cpu-bus':commands=[['ctest','--test-dir',str(build.relative_to(ROOT)),
        '--output-on-failure','--no-tests=error','-R','^phase6_repairs_contract$|^load_contract$|^movem_contract$|^gameplay_bus_contract$']]
    if lane=='devices':commands=[[str((build/'phase6_repairs_contract').relative_to(ROOT)),x] for x in ('io','ext')]
    checks=[]
    for command in commands:
        r=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=60)
        checks.append({'command':command,'return_code':r.returncode,
            'stdout':r.stdout.replace(str(ROOT),'[workspace]'),'stderr':r.stderr.replace(str(ROOT),'[workspace]')})
        if r.returncode:raise RuntimeError('bounded-regression-failed')
    roster=[]
    for route in compiler.compile_routes()['routes']:
        title=route['fixture'];case=route['case']['id'];is_control=title=='genewhip-independent-game-v2'
        actual=next((r for r in reversed(d['records']) if r.get('title_id')==title and r.get('native_report')),None) if case=='full-route' else None
        row={'fixture':title,'case':case,'identity':route['identity'],
            'execution':'retained-final-regression-control' if is_control else 'retained-bounded-production-observation' if actual else 'not-executed-after-binding-halt',
            'status':'pass' if is_control else 'blocked',
            'stages':{s:{'status':'unknown','reason':'binding-prerequisite-halt; no full-case qualification'} for s in compiler.STAGES},
            'required_audio':'unknown; no full audio-qualified route run',
            'evidence_record':'GW-06-04-FINAL-UNCHANGED-CONTROL' if is_control else actual['record_id'] if actual else None}
        if is_control:
            row['known']='six unchanged original cases freshly passed twice; no new-title claim'
        elif actual:
            n=actual['native_report'];row['observed']={k:n[k] for k in ('fields','active_ticks','final_tick','first_stop_tick','stop_reason','instruction_address','opcode','predicates')}
            row['stages']['load']={'status':'pass','reason':'actual successful public load'}
            if title=='recursion94':
                row['stages']['sustained']={'status':'fail','reason':'3599 observed completed steps <3600 required; frozen7200-field cap exhausted'}
                row['stages']['completion']={'status':'fail','reason':'all source predicates reached, but required duration remains unmet'}
            else:row['stages']['boot']={'status':'unsupported','reason':'actual PEA0x4879 at0xEC32 after9 completed video fields'}
        roster.append(row)
    report={'schema':'genewhip-phase6-repair-feasibility-v1','status':'blocked','lane':lane,
        'fresh_new_game_runs':0,'reason':halt['reason'],'disposition':halt['disposition'],
        'case_denominator':len(roster),'cases':roster,'bounded_regressions':checks,
        'budgets':d['budgets'],'usage':d['usage'],'no_phase_unlock':True,
        'original_full_report_stream_hash':'unknown; ledger native_report retained; canonical extraction separately identified'}
    out=build/'evidence'/('feasibility.json' if lane=='feasibility' else 'repairs-'+lane+'.json')
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':'blocked','lane':lane,'case_denominator':len(roster),
        'report':str(out.relative_to(ROOT)),'sha256':sha(out),'reason':halt['reason']},sort_keys=True))
    return 1

PEA_SHORT_CASES=None
if ('D133_SETTLEMENT' not in globals() and '--tank-checkpoint47' not in sys.argv[1:] and not any(
        arg=='--accounting-scope' or arg.startswith('--accounting-scope=')
        for arg in sys.argv[1:])):
    _load_legacy_modules()

TANK_PEA_WATCHES=(
    ('instruction-word-0',0x00ec32),('instruction-word-1',0x00ec34),('instruction-word-2',0x00ec36),
)

def add_tank_pea_watches(controller_bytes):
    """Append bounded public-observer spans without changing route semantics."""
    import struct
    if len(controller_bytes)<128 or len(controller_bytes)%4 or controller_bytes[:4]!=b'GWRC':
        raise RuntimeError('tank-continuation-controller-invalid')
    words=list(struct.unpack('<'+'I'*(len(controller_bytes)//4),controller_bytes))
    count=words[6]
    if count+len(TANK_PEA_WATCHES)>64:raise RuntimeError('tank-continuation-watch-count-exceeded')
    insert_at=32+count*4
    watches=[]
    for _name,address in TANK_PEA_WATCHES:watches.extend((address,address,2,0))
    words[6]=count+len(TANK_PEA_WATCHES)
    words[insert_at:insert_at]=watches
    return struct.pack('<'+'I'*len(words),*words)

def pea_guest(path):
    rom=bytearray(2048);rom[0:4]=bytes.fromhex('00ffff00');rom[4:8]=bytes.fromhex('00000200')
    # Original guest: PEA $00e00010; STOP #$2700. The stack result is read
    # through the actual public headless client, not a core-private helper.
    rom[512:520]=bytes.fromhex('487900e000104e722700')
    path.write_bytes(rom)

def run_pea_public_client(build,case):
    build=pathlib.Path(build).resolve()
    client=build/'tools/session/gw_headless'
    if not client.is_file(): raise RuntimeError('pea-public-client-missing')
    with tempfile.TemporaryDirectory(prefix='pea-public-',dir=build) as tmp:
        work=pathlib.Path(tmp);rom=work/'pea.grom';trace=work/'trace.jsonl';pea_guest(rom)
        command=[str(client.relative_to(ROOT)),str(rom.relative_to(ROOT)),'--fields','1',
                 '--peek','0xfffefc','4','--dump-instruction-trace',str(trace.relative_to(ROOT))]
        started=time.monotonic();result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=60)
        wall=time.monotonic()-started
        stdout=result.stdout.replace(str(ROOT),'[workspace]');stderr=result.stderr.replace(str(ROOT),'[workspace]')
        if len(stdout.encode())>1048576 or len(stderr.encode())>1048576: raise RuntimeError('pea-public-stream-bound')
        trace_rows=trace.read_text().splitlines() if trace.exists() else []
        if len(trace_rows)>128 or trace.stat().st_size>16777216: raise RuntimeError('pea-public-trace-bound')
        observed={'command':command,'exit_code':result.returncode,'wall_seconds':round(wall,3),
                  'stdout':stdout,'stderr':stderr,'trace_rows':len(trace_rows),
                  'trace':trace_rows,'source_identity_at_execution':accounting.source_identity(ROOT),
                  'client_sha256':sha(client),'rom_sha256':sha(rom)}
        if case.startswith('native-red-'):
            if result.returncode==0 or not any(json.loads(line).get('opcode')==0x4879 for line in trace_rows):
                raise RuntimeError('pea-public-red-not-named-unsupported-instruction')
        else:
            if result.returncode or '00e00010' not in stdout.lower() and '00 e0 00 10' not in stdout.lower():
                raise RuntimeError('pea-public-client-stack-assertion-failed')
            if not any(json.loads(line).get('opcode')==0x4879 for line in trace_rows):
                raise RuntimeError('pea-public-client-did-not-execute-pea')
        return observed

def pea_regressions(build):
    ledger=json.loads(LEDGER.read_text());rows={r.get('case'):r for r in ledger['records']
        if r.get('record_type')=='authorization-reservation' and r.get('purpose')=='pea-short-contract'}
    manifest_path=ROOT/'evidence/phase6-pea-manifest.json';manifest=json.loads(manifest_path.read_text())
    if set(rows)!=set(PEA_SHORT_CASES) or len(rows)!=10:raise RuntimeError('pea-process-roster-incomplete')
    completed=[]
    for case in PEA_SHORT_CASES:
        row=rows[case]
        if row.get('status')!='reserved':
            # Verification is read-only and never relaunches an already spent row.
            completed.append({'case':case,'status':row.get('status'),'verified_existing':True});continue
        if 'public-client' in case:
            variant='phase6' if case.startswith(('native-red','native-green')) else 'phase6-movem-sanitize' if case.startswith('sanitize') else 'phase6-movem-hooks-off'
            result=run_pea_public_client(ROOT/'build'/variant,case)
        elif case.startswith('native-mutant'):
            mode='pea-mutant-address' if case.endswith('address') else 'pea-mutant-stack'
            exe=ROOT/'build/phase6/phase6_repairs_contract';p=subprocess.run([str(exe.relative_to(ROOT)),mode],cwd=ROOT,
                    capture_output=True,text=True,timeout=60)
            expected='wrong-address/stack-order mutant'
            if p.returncode==0 or expected not in p.stderr:raise RuntimeError(f'{case}-did-not-fail-named-assertion')
            result={'command':[str(exe.relative_to(ROOT)),mode],'exit_code':p.returncode,
                    'stderr':p.stderr,'source_identity_at_execution':accounting.source_identity(ROOT)}
        else:
            variant='phase6' if case.startswith('native') else 'phase6-movem-sanitize' if case.startswith('sanitize') else 'phase6-movem-hooks-off'
            exe=ROOT/'build'/variant/'phase6_repairs_contract'
            p=subprocess.run([str(exe.relative_to(ROOT)),'pea'],cwd=ROOT,capture_output=True,text=True,timeout=60)
            if p.returncode:raise RuntimeError(f'{case}-failed:{p.stderr.strip()}')
            result={'command':[str(exe.relative_to(ROOT)),'pea'],'exit_code':p.returncode,
                    'stdout':p.stdout,'source_identity_at_execution':accounting.source_identity(ROOT)}
        status='completed'
        accounting.finalize_finite_process(LEDGER,case=case,status=status,result=result,allowed_root=ROOT)
        manifest_row=next(r for r in manifest['process_rows'] if r['case']==case)
        manifest_row.update({'status':status,'result':result,
                             'source_identity_at_execution':result.get('source_identity_at_execution')})
        manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
        completed.append({'case':case,'status':status,'exit_code':result.get('exit_code')})
    print(json.dumps({'status':'complete','process_rows':completed},sort_keys=True));return 0

def _pea_control_driver(build, repetition):
    driver=module('pea_control_driver','tests/fixtures/phase4_game.py')
    scenario=json.loads(driver.SCENARIO_PATH.read_text())
    oracle=json.loads(driver.ORACLE_PATH.read_text())
    if len(scenario['cases'])!=6 or len(oracle['case_ids'])!=6:raise RuntimeError('pea-control-denominator-changed')
    client=(build/'tools/session/gw_headless').resolve()
    rom=ROOT/scenario['rom']['relative_path']
    expected=next((r['post_behavior']['unchanged_control']['results'] for r in reversed(json.loads(LEDGER.read_text())['records'])
                   if r.get('post_behavior',{}).get('unchanged_control',{}).get('status')=='pass'),None)
    if not expected or len(expected)!=6:raise RuntimeError('historical-control-baseline-missing')
    retained=ROOT/'build/phase6/pea-controls'/f'repetition-{repetition}'
    retained.mkdir(parents=True,exist_ok=True)
    started=time.monotonic();actual_rows=[];pcm_files=[]
    with tempfile.TemporaryDirectory(prefix='pea-control-',dir=build) as temp:
        for case in scenario['cases']:
            result=driver.execute(client,rom,case,pathlib.Path(temp)/case['id'])
            pcm=result['audio']; pcm_path=retained/f"{case['id']}.pcm";pcm_path.write_bytes(pcm)
            pcm_files.append({'case':case['id'],'path':pcm_path.relative_to(ROOT).as_posix(),
                              'bytes':len(pcm),'sha256':hashlib.sha256(pcm).hexdigest()})
            row={'id':case['id'],'outcome':'pass','fields':case['frames'],
                 'input_sha256':result['input_sha256'],
                 'field_hashes_sha256':hashlib.sha256('\n'.join(result['hashes']).encode()).hexdigest(),
                 'raw_geometry_sha256':hashlib.sha256('\n'.join(result['geometry']).encode()).hexdigest(),
                 'pcm_frames':len(pcm)//4,'play_state':result['play_state'],'position':result['position'],
                 'psg':result['psg'],'ac_range':result['ac_range'],'machine_digest':result['machine_digest'],
                 'unsupported':0}
            wanted=next((r for r in expected if r['id']==case['id']),None)
            if wanted is None or any(row.get(k)!=wanted.get(k) for k in wanted):
                raise RuntimeError(f"pea-unchanged-control-drift:{case['id']}")
            actual_rows.append(row)
    wall=time.monotonic()-started
    if wall>600:raise RuntimeError('pea-control-driver-watchdog')
    return {'repetition':repetition,'status':'pass','cases':6,'results':actual_rows,
            'wall_seconds':round(wall,3),'pcm_files':pcm_files,
            'complete_pcm_retained':True,'pcm_repetition_identity':hashlib.sha256(
                ''.join(x['sha256'] for x in pcm_files).encode()).hexdigest()}

def pea_next_stop(build):
    manifest=json.loads((ROOT/'evidence/phase6-pea-manifest.json').read_text())
    if len(manifest.get('process_rows',[]))!=10 or any(r.get('status')!='completed' for r in manifest['process_rows']):
        raise RuntimeError('pea-short-regression-roster-not-complete')
    d=json.loads(LEDGER.read_text())
    if d.get('current_pea_outcome',{}).get('status'):
        raise RuntimeError('pea-next-stop-already-spent')
    anchor=json.loads(ACCOUNTING_ANCHOR.read_text())
    pre=accounting.preflight(LEDGER,monotonic_now=time.monotonic(),boot_identity=accounting.read_boot_identity(),
                             require_active_anchor=True,allowed_root=ROOT)
    if pre['status']!='ready' or pre['observed_signatures_used']!=9 or pre['tank_pea_attempts_remaining']<1:
        raise RuntimeError('pea-resource-preflight-not-ready')
    identity=accounting.source_identity(ROOT)
    next_signature=accounting.PEA_SIGNATURE
    rec=capture(build,'tank-battle',0xec32,next_signature,'06-11-independent-pea-next-stop',
        purpose='independent-pea',case='tank-pea-regression',contract_identity='NXP-M68000PRM-PEA-4-159;MC68000UM-7.9-T7-11')
    if not isinstance(rec,dict) or rec.get('status') not in ('observed-stop','route-returned'):
        raise RuntimeError('pea-tank-capture-incomplete')
    native=rec['native_report']
    if native.get('fields',0)>4500 or native.get('active_ticks',0)>3600:
        raise RuntimeError('pea-tank-capture-bound-exceeded')
    pair=validate_pair(native.get('last_boundary'))
    if pair['before']['pc']!=native['instruction_address'] or pair['before']['pc']==0xec32:
        raise RuntimeError('pea-next-stop-not-after-target')
    stop=native.get('stop_reason')
    signature=None
    if stop in (2,3,4):
        signature=f"tank-battle:cpu:{native['instruction_address']:06x}:{native['opcode']:04x}:{stop}"
    controls=[]
    for repetition in (1,2):
        case=f'control-repeat-{repetition}'
        current_identity=accounting.source_identity(ROOT)
        control=accounting.authorize_launch(LEDGER,purpose='independent-control',plan='06-11',case=case,
            source_identity=current_identity,current_source_identity=current_identity,
            contract_identity='phase4-game-six-case-control-v1',target_signature=None,
            launcher=lambda _reservation,n=repetition:_pea_control_driver(build,n),
            boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
        controls.append(control)
    if controls[0]['results']!=controls[1]['results']:
        raise RuntimeError('pea-control-repetitions-differ')
    ledger=json.loads(LEDGER.read_text())
    if signature and signature not in ledger['observed_stop_signatures']:
        if len(ledger['observed_stop_signatures'])>=12:raise RuntimeError('distinct-stop-cap-reached')
        ledger['observed_stop_signatures'].append(signature)
    outcome={'status':'passed','purpose':'independent-pea','target_signature':next_signature,
        'target_attempt':'1 of current remaining PEA budget','source_identity_after_mutation':accounting.source_identity(ROOT),
        'native_report':native,'target_boundary':native['probe_boundary'],'returned_boundary':pair,
        'target_tick':pair['target_tick'],'returned_overshoot':pair['returned_overshoot'],
        'first_stop_tick':native.get('first_stop_tick'),'fields':native.get('fields'),
        'active_ticks':native.get('active_ticks'),'next_stop_signature':signature,
        'next_stop_disposition':'captured only; repair and feasibility owned by06-09',
        'controls':controls,'manifest_sha256':sha(ROOT/'evidence/phase6-pea-manifest.json'),
        'authorization_anchor_id':anchor.get('id'),'preflight':pre,'rec_launches':0,
        'rec_receipt_required':False}
    ledger['current_pea_outcome']=outcome
    LEDGER.write_text(json.dumps(ledger,indent=2)+'\n')
    out=ROOT/'evidence/phase6-pea-next-stop.json';out.write_text(json.dumps(outcome,indent=2)+'\n')
    print(json.dumps({'status':'passed','record_id':rec['record_id'],'next_stop_signature':signature,
        'target_tick':outcome['target_tick'],'returned_overshoot':outcome['returned_overshoot'],
        'control_processes':2,'control_rows':12,'rec_launches':0},sort_keys=True));return 0

def verify_pea_receipt(build):
    ledger=json.loads(LEDGER.read_text());outcome=ledger.get('current_pea_outcome')
    path=ROOT/'evidence/phase6-pea-next-stop.json'
    if not isinstance(outcome,dict) or outcome.get('status')!='passed' or not path.is_file():
        raise RuntimeError('pea-next-stop-receipt-missing')
    filed=json.loads(path.read_text())
    if filed!=outcome or outcome.get('rec_launches')!=0:raise RuntimeError('pea-next-stop-receipt-mismatch')
    if len(outcome.get('controls',[]))!=2 or any(c.get('cases')!=6 or c.get('status')!='pass' for c in outcome['controls']):
        raise RuntimeError('pea-control-denominator-invalid')
    if any(not pathlib.Path(x['path']).is_file() or sha(ROOT/x['path'])!=x['sha256']
           for c in outcome['controls'] for x in c.get('pcm_files',[])):
        raise RuntimeError('pea-control-pcm-missing-or-changed')
    manifest=json.loads((ROOT/'evidence/phase6-pea-manifest.json').read_text())
    if len(manifest.get('process_rows',[]))!=10 or any(r.get('status')!='completed' for r in manifest['process_rows']):
        raise RuntimeError('pea-short-manifest-invalid')
    reservation=[r for r in ledger['records'] if r.get('record_id')=='GW-06-AUTH-independent-pea-tank-pea-regression']
    if len(reservation)!=1 or reservation[0].get('status')!='completed':raise RuntimeError('pea-authorization-not-complete')
    print(json.dumps({'status':'passed','read_only':True,'process_rows':10,'control_rows':12,
                      'rec_launches':0,'next_stop_signature':outcome.get('next_stop_signature')},sort_keys=True));return 0

def tank_continuation_begin():
    """Persist a unique same-boot active anchor before continuation work."""
    boot=accounting.read_boot_identity();start=time.monotonic();identifier='GW-06-13-execution'
    with accounting._locked(LEDGER):
        value=accounting._load(LEDGER,ROOT);state=value['phase6_accounting']
        if state.get('active_anchor') is not None:raise RuntimeError('active-accounting-anchor-already-open')
        previous=json.loads(ACCOUNTING_ANCHOR.read_text())
        if previous.get('status')!='closed-inactive-review' or previous.get('boot_identity')!=boot:
            raise RuntimeError('closed-accounting-anchor-not-current-boot')
        prior=accounting._closed_seconds(state)
        if abs(prior-10266.88)>0.0005:raise RuntimeError('closed-accounting-floor-mismatch')
        if any(row.get('id')==identifier for row in state['closed_intervals']):
            raise RuntimeError('plan-accounting-interval-already-used')
        anchor={'id':identifier,'monotonic_started_at':start,'boot_identity':boot,
                'prior_cumulative_seconds':prior,'started_at':now(),
                'basis':'persisted before plan06-13 resumed work'}
        state['active_anchor']=anchor;accounting._write(LEDGER,value)
    accounting._write_anchor_file(ACCOUNTING_ANCHOR,anchor)
    print(json.dumps({'status':'started','active_anchor':anchor},sort_keys=True));return 0

def tank_continuation_close():
    result=accounting.close_plan_anchor(LEDGER,ACCOUNTING_ANCHOR,
        monotonic_now=time.monotonic(),boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
    print(json.dumps(result,sort_keys=True));return 0

def tank_continuation_offline():
    """Exercise the production authorizer and atomic ledger with fake launchers only."""
    source=accounting.source_identity(ROOT);boot='tank-continuation-offline-boot'
    outcomes=[]
    for interrupted in (False,True):
        temporary=tempfile.TemporaryDirectory(prefix='tank-continuation-offline-')
        try:
            directory=pathlib.Path(temporary.name);ledger=directory/'ledger.json'
            value=json.loads(LEDGER.read_text())
            for field in ('d123_recovery_policy','d123_observer_manifest','d123_observer_bridge',
                          'd123_observer_review','d123_observer_bridge_binding'):
                value.pop(field,None)
            for field in ('d124_recovery_policy','d124_runs','d124_admissions',
                          'd124_component_disposition','d124_observer_bridge_binding','d124_observer_review'):
                value.pop(field,None)
            prefix_count=value['phase6_accounting']['immutable_prefix_count']
            value.pop('phase6_accounting',None)
            value['records']=value['records'][:prefix_count]
            value['tank_proof_revalidation']={'status':'passed','source_identity':source,
                'binary_identity':'0'*64,'contract_identity':'offline-proof-v1'}
            value['records'].append({'record_id':'offline-target-floor','record_type':'target-investigation-time',
                'target_stop_signature':accounting.PEA_SIGNATURE,'active_seconds':3916.453,'new_target_attempts':0})
            ledger.write_text(json.dumps(value,sort_keys=True));accounting.initialize_ledger(
                ledger,monotonic_started_at=time.monotonic()-1,boot_identity=boot,allowed_root=directory)
            with accounting._locked(ledger):
                current=accounting._load(ledger,directory)
                current['d122_observer_bridge_binding']={'status':'independently-accepted',
                    'bridge_sha256':'a'*64,'review_sha256':'b'*64,'trusted_handoff_sha256':'c'*64,
                    'review_check_sha256':'c'*64,'source_identity':source,'reviewer_identity':'offline-external-reviewer'}
                current['tank_proof_revalidation']={'status':'passed','source_identity':source,
                    'binary_identity':'d'*64,'contract_identity':'offline-proof-v1'}
                accounting._write(ledger,current)
            called=[]
            def fake_launcher(reservation):
                saved=accounting._load(ledger,directory)['records'][-1]
                if saved.get('status')!='reserved' or saved.get('new_target_attempts')!=1:
                    raise RuntimeError('reservation-not-persisted-before-launcher')
                called.append(saved['record_id'])
                if interrupted:raise InterruptedError('offline intentional interruption')
                return {'offline_fake_launcher':True}
            try:
                authorize_capture(purpose='tank-continuation',plan='06-14',
                    case=accounting.TANK_CONTINUATION_CASE,source_identity=source,
                    current_source_identity=source,contract_identity='offline-proof-v1',
                    target_signature=accounting.PEA_SIGNATURE,ledger_path=ledger,
                    launcher=fake_launcher,boot_identity=boot,allowed_root=directory)
                status='completed'
            except InterruptedError:
                status='interrupted'
            final=accounting._load(ledger,directory)['records'][-1]
            if final.get('status')!=status or len(called)!=1:raise RuntimeError('offline-reservation-finalization-invalid')
            outcomes.append({'status':status,'new_target_attempts':final['new_target_attempts'],
                             'process_count':final['process_count'],'case_count':final['case_count']})
        finally:temporary.cleanup()
    d123_result=_d123_tank_authorization_offline(source)
    print(json.dumps({'status':'passed','read_only_production_ledger':True,'guest_launches':0,
                      'fake_rows':outcomes,'d123_authorization':d123_result},sort_keys=True));return 0

def _d123_tank_authorization_offline(source):
    boot='d123-tank-authorization-offline-boot';denials=[];launches=[]
    for scenario in ('d122-only','development-only','partial-qualification','stale-source-authority','stale-source','accepted'):
        with tempfile.TemporaryDirectory(prefix='d123-tank-guard-') as temp:
            directory=pathlib.Path(temp);ledger=directory/'ledger.json'
            value=json.loads(LEDGER.read_text());prefix=value['phase6_accounting']['immutable_prefix_count']
            for field in ('d124_recovery_policy','d124_runs','d124_admissions',
                          'd124_component_disposition','d124_observer_bridge_binding','d124_observer_review'):
                value.pop(field,None)
            value.pop('phase6_accounting',None);value['records']=value['records'][:prefix]
            ledger.write_text(json.dumps(value,sort_keys=True))
            accounting.initialize_ledger(ledger,monotonic_started_at=time.monotonic()-1,
                boot_identity=boot,allowed_root=directory)
            with accounting._locked(ledger):
                current=accounting._load(ledger,directory);anchor=current['phase6_accounting']['active_anchor']
                anchor['purpose']='d123-global-engineering';anchor['pea_charge']=False
                policy={'schema':'phase6-d123-recovery-v1','status':'active','anchor_id':anchor['id']}
                current['d123_recovery_policy']=policy
                current['d123_observer_manifest']={'status':'frozen','sha256':'1'*64,'source_identity':source}
                current['tank_proof_revalidation']={'status':'passed','source_identity':source,
                    'binary_identity':'3'*64,'contract_identity':'2'*64}
                current['d122_observer_bridge_binding']={'status':'independently-accepted','bridge_sha256':'a'*64,
                    'review_sha256':'b'*64,'trusted_handoff_sha256':'c'*64}
                if scenario in ('development-only','partial-qualification','stale-source-authority','stale-source','accepted'):
                    current['d123_observer_bridge_binding']={'status':'independently-accepted',
                        'bridge_sha256':'2'*64,'review_sha256':'4'*64,'trusted_handoff_sha256':'5'*64,
                        'review_check_sha256':'6'*64,'manifest_sha256':'1'*64,
                        'qualification_sha256':'7'*64,'source_identity':source,
                        'producer_source_identity':source,'binary_identity':'3'*64}
                    current['d123_observer_review']={'status':'accepted','bridge_sha256':'2'*64,
                        'review_sha256':'4'*64,'source_identity':source}
                    current['tank_proof_revalidation']['contract_identity']='2'*64
                if scenario=='development-only':
                    current['d123_observer_bridge_binding']['status']='bridge-built-review-pending'
                    current['d123_observer_review']['status']='pending'
                if scenario=='partial-qualification':
                    current['d123_observer_manifest']['status']='qualification-incomplete'
                if scenario=='stale-source':
                    current['tank_proof_revalidation']['source_identity']='0'*64
                if scenario=='stale-source-authority':
                    current['d123_observer_bridge_binding']['source_identity']='0'*64
                    current['d123_observer_review']['source_identity']='0'*64
                    current['d123_observer_manifest']['source_identity']='0'*64
                accounting._write(ledger,current)
            called=[]
            def fake_launcher(reservation):
                saved=accounting._load(ledger,directory)['records'][-1]
                if saved.get('status')!='reserved' or saved.get('new_target_attempts')!=1:
                    raise RuntimeError('d123-fake-launcher-reservation-not-persisted')
                called.append(saved['record_id']);return {'fake_only':True}
            try:
                result=authorize_capture(purpose='tank-continuation',plan='06-14',
                    case=accounting.TANK_CONTINUATION_CASE,source_identity=source,
                    current_source_identity=source,contract_identity='2'*64,
                    target_signature=accounting.PEA_SIGNATURE,ledger_path=ledger,
                    launcher=fake_launcher,boot_identity=boot,allowed_root=directory)
            except accounting.AccountingError as error:
                if scenario=='accepted':raise RuntimeError('d123-accepted-fixture-denied:'+str(error)) from error
                if str(error) not in ('d123-independent-observer-review-required','d123-current-proof-identity-mismatch',
                                      'd123-stale-source-authority'):
                    raise
                if called:raise RuntimeError('d123-denied-fixture-reached-launcher')
                denials.append(scenario)
            else:
                if scenario!='accepted' or result!={'fake_only':True} or len(called)!=1:
                    raise RuntimeError('d123-accepted-fixture-or-denial-invalid')
                launches.append(scenario)
    return {'denied':denials,'fake14_launcher_calls':len(launches),'guest_launches':0}

def stack_observer_accounting_offline():
    """Exercise the approved manifest-bound coordinator path using temporary ledgers and fake callbacks."""
    source=accounting.source_identity(ROOT);boot='stack-observer-offline-boot'
    with tempfile.TemporaryDirectory(prefix='stack-observer-accounting-') as temp:
        directory=pathlib.Path(temp);ledger=directory/'ledger.json';manifest=directory/'manifest.json'
        value=json.loads(LEDGER.read_text());prefix=value['phase6_accounting']['immutable_prefix_count']
        value.pop('phase6_accounting',None);value['records']=value['records'][:prefix]
        value.pop('stack_observer_manifest',None)
        ledger.write_text(json.dumps(value,sort_keys=True))
        accounting.initialize_ledger(ledger,monotonic_started_at=time.monotonic()-1,
            boot_identity=boot,allowed_root=directory)
        with accounting._locked(ledger):
            state=accounting._load(ledger,directory)['phase6_accounting']
            current=accounting._load(ledger,directory);current['phase6_accounting']=state
            accounting._write(ledger,current)
        manifest_doc={'schema':'genewhip-phase6-stack-observation-d122-v1','status':'frozen',
            'source_identity':source,'cases':[{'purpose_id':purpose,'case':case}
                for purpose,case in accounting.OBSERVER_PROOF_PURPOSES.items()]}
        manifest_bytes=(json.dumps(manifest_doc,sort_keys=True)+'\n').encode();manifest.write_bytes(manifest_bytes)
        frozen={'sha256':hashlib.sha256(manifest_bytes).hexdigest(),'status':'frozen'}
        with accounting._locked(ledger):
            current=accounting._load(ledger,directory)
            current['phase6_accounting']['scope_approval']={'id':'GW-06-D122-observer-scope-approval','status':'approved'}
            current['d122_successor_manifest']={'status':'frozen','sha256':frozen['sha256'],
                'source_identity':source,'purpose_ids':list(accounting.OBSERVER_PROOF_PURPOSES),
                'path':'manifest.json'}
            accounting._write(ledger,current)
        rows=[]
        for purpose,case in accounting.OBSERVER_PROOF_PURPOSES.items():
            def fake_launcher(row):
                saved=accounting._load(ledger,directory)['records'][-1]
                if saved.get('status')!='reserved' or saved.get('manifest_sha256')!=frozen['sha256']:
                    raise RuntimeError('observer-reservation-not-persisted-before-fake')
                if saved.get('new_target_attempts')!=0 or saved.get('target_stop_signature') is not None:
                    raise RuntimeError('observer-proof-incorrectly-spends-target-attempt')
                return {'fake_only':True}
            result=authorize_observer_activity(purpose=purpose,plan='06-18',case=case,
                source_identity=source,binary_identity='b'*64,command_identity='c'*64,
                manifest_sha256=frozen['sha256'],ledger_path=ledger,launcher=fake_launcher,
                boot_identity=boot,allowed_root=directory)
            if result!={'fake_only':True}:raise RuntimeError('observer-fake-result-invalid')
            rows.append({'purpose':purpose,'case':case,'status':'completed'})
        before=ledger.read_bytes();called=[]
        try:
            authorize_observer_activity(purpose='stack-observer-fourth-1',plan='06-18',
                case='stack-observer-fourth-1',source_identity=source,binary_identity='b'*64,
                command_identity='c'*64,manifest_sha256=frozen['sha256'],ledger_path=ledger,
                launcher=lambda row:called.append(row),boot_identity=boot,allowed_root=directory)
        except accounting.AccountingError as error:
            if str(error)!='observer-proof-purpose-denied':raise
        else:raise RuntimeError('observer-fourth-purpose-admitted')
        if called or ledger.read_bytes()!=before:raise RuntimeError('observer-denial-mutated-or-launched')
    print(json.dumps({'status':'passed','manifest_sha256':frozen['sha256'],'fake_rows':rows,
        'guest_build_ctest_launches':0,'fourth_purpose_denied':True},sort_keys=True));return 0

def _continuation_bridge(build,bridge_path,proof_review_path,review_check_path,interval_id):
    checker=module('tank_continuation_checker','tests/evidence/phase6_tank_continuation_contract.py')
    bridge_path=bridge_path if bridge_path.is_absolute() else ROOT/bridge_path
    proof_review_path=proof_review_path if proof_review_path.is_absolute() else ROOT/proof_review_path
    review_check_path=review_check_path if review_check_path.is_absolute() else ROOT/review_check_path
    ledger_value=json.loads(LEDGER.read_bytes());d125=bool(ledger_value.get('d125_owner_generations'))
    if d125:accounting.selected_recovery_owner(ledger_value,project_root=ROOT,require_runtime=True)
    d124=not d125 and bool(ledger_value.get('d124_recovery_policy'))
    if not (d124 or d125):
        deadline=accounting.d122_other_interval_deadline(LEDGER,interval_id=interval_id,
            boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
        checker.D122_OTHER_DEADLINE_MONOTONIC=deadline['deadline_monotonic']
    try:
        bridge=checker.verify_observer_bridge(bridge_path,build)
        checker.verify_acceptance_review(review_check_path,bridge_path,build)
        review_check=json.loads(review_check_path.read_bytes())
        if proof_review_path.resolve().relative_to(ROOT.resolve()).as_posix()!=review_check.get('review_path'):
            raise RuntimeError('tank-proof-review-input-path-mismatch')
        source=accounting.source_identity(ROOT)
        client=build/'tools/session/gw_headless'
        if source!=bridge.get('current_source_closure',{}).get('source_identity') or sha(client)!=bridge.get('control_client_binary_sha256'):
            raise RuntimeError('tank-proof-source-or-binary-drift')
        route=next(r for r in compiler.compile_routes()['routes'] if r['fixture']=='tank-battle' and r['case']['id']=='full-route')
        original,_=compiler.lower_route(route);descriptor=add_tank_pea_watches(original)
        if hashlib.sha256(descriptor).hexdigest()!=bridge.get('capture_descriptor_sha256'):
            raise RuntimeError('tank-capture-descriptor-drift')
        if not (d124 or d125):
            accounting.d122_other_interval_deadline(LEDGER,interval_id=interval_id,
                boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
        return bridge,checker,source,client,descriptor,{
            'bridge_path':bridge_path,'bridge_file_sha256':sha(bridge_path),
            'proof_review_path':proof_review_path,'proof_review_sha256':sha(proof_review_path),
            'review_check_path':review_check_path,'review_check_sha256':sha(review_check_path)}
    finally:
        if not (d124 or d125):checker.D122_OTHER_DEADLINE_MONOTONIC=None

def _tank_control_driver(build,repetition,bridge_sha,source_identity,*,output_root=None):
    driver=ROOT/'tests/fixtures/phase4_game.py';client=build/'tools/session/gw_headless'
    if not client.is_file():raise RuntimeError('original-control-client-missing')
    expected=next((r['post_behavior']['unchanged_control']['results'] for r in
        reversed(json.loads(LEDGER.read_text())['records'])
        if r.get('post_behavior',{}).get('unchanged_control',{}).get('status')=='pass'),None)
    if not expected or len(expected)!=6:raise RuntimeError('historical-control-baseline-missing')
    # Preserve the original direct-call output layout; D124 supplies an explicit
    # per-receipt root so isolated consumer runs never collide with Plan14 paths.
    root=(output_root if output_root is not None else build/'phase6/pea-controls')/f'repetition-{repetition}'
    retain=root/'pcm';report=root/'report.json'
    command=[sys.executable,'-I',str(driver),str(client),'--report',str(report),'--retain-artifacts',str(retain)]
    command_sha=hashlib.sha256(json.dumps(command,separators=(',',':')).encode()).hexdigest()
    public_command=['python3','-I',driver.relative_to(ROOT).as_posix(),client.relative_to(ROOT).as_posix(),
        '--report',report.relative_to(ROOT).as_posix(),'--retain-artifacts',retain.relative_to(ROOT).as_posix()]
    root.mkdir(parents=True,exist_ok=True);root.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    for name in ('driver.stdout.raw','driver.stderr.raw'):
        if (root/name).is_symlink() or (root/name).exists():raise RuntimeError('original-control-raw-stream-exists-or-symlink')
    started=time.monotonic();timed_out=False;bound_violation=False
    root_fd=os.open(root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
    phase4=module('bounded_phase4_runner','tests/fixtures/phase4_game.py')
    try:
        result=phase4.bounded_run(command,timeout=600,cap=2097152)
        stdout,stderr,return_code=result.stdout,result.stderr,result.returncode
    except phase4.BoundedProcessError as error:
        stdout,stderr=error.stdout,error.stderr;return_code=None
        timed_out='timeout' in str(error);bound_violation='cap' in str(error)
    except BaseException:
        os.close(root_fd)
        raise
    wall=time.monotonic()-started
    streams={}
    try:
        for key,data in (('stdout',stdout),('stderr',stderr)):
            path=root/f'driver.{key}.raw'
            _write_control_stream_exclusive(root_fd,path.name,data)
            streams[key]={'path':path.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(data).hexdigest(),
                'observed_bytes':len(data),'retained_bytes':min(len(data),1048576),'truncated':len(data)>1048576}
    finally:os.close(root_fd)
    if return_code is None or return_code != 0 or timed_out or bound_violation or wall>600 or any(x['truncated'] for x in streams.values()):
        raise RuntimeError(f'original-control-driver-failed:{repetition}:{return_code}:timeout-or-output-bound')
    if not report.is_file() or report.stat().st_size>8388608:raise RuntimeError('original-control-report-missing-or-oversized')
    data=json.loads(report.read_text());rows=data.get('results',[])
    if data.get('outcome')!='pass' or len(rows)!=6 or len(data.get('native_child_processes',[]))!=6:
        raise RuntimeError('original-control-six-child-denominator-invalid')
    for row in rows:
        wanted=next((item for item in expected if item.get('id')==row.get('id')),None)
        if wanted is None or any(row.get(k)!=wanted.get(k) for k in wanted):
            raise RuntimeError(f"pea-unchanged-control-drift:{row.get('id')}")
        item=row.get('retained_pcm');path=ROOT/item['path']
        if not path.is_file() or path.stat().st_size!=item['bytes'] or sha(path)!=item['sha256']:
            raise RuntimeError(f"pea-control-pcm-retention-invalid:{row.get('id')}")
    return {'repetition':repetition,'status':'pass','cases':6,'results':rows,
        'report_path':report.relative_to(ROOT).as_posix(),'report_sha256':sha(report),
        'native_child_processes':data['native_child_processes'],'driver_process':{'return_code':result.returncode,
        'timed_out':timed_out,'bound_violation':bound_violation,
        'wall_seconds':round(wall,3),'stdout_bytes':len(stdout),'stderr_bytes':len(stderr),
        'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest(),
        'streams':streams,'command':public_command,'command_sha256':command_sha,'executable_path':driver.relative_to(ROOT).as_posix(),
        'executable_sha256':sha(driver),'client_path':client.relative_to(ROOT).as_posix(),
        'client_sha256':sha(client),'processes':1,'bridge_sha256':bridge_sha,'source_identity':source_identity}}

def tank_continuation_once(build,output,bridge_path,proof_review_path,review_check_path):
    ledger_value=json.loads(LEDGER.read_bytes());d125=bool(ledger_value.get('d125_owner_generations'))
    if d125:accounting.selected_recovery_owner(ledger_value,project_root=ROOT,require_runtime=True)
    d124=not d125 and bool(ledger_value.get('d124_recovery_policy'))
    preflight_id='tank-preflight-1';preflight_source=accounting.source_identity(ROOT)
    preflight_boot=accounting.read_boot_identity()
    activity_id='d124-integration-process-preflight-01'
    if d125:
        activity_id='d125-integration-process-preflight-01'
        accounting.begin_d125_activity(LEDGER,activity_id=activity_id,stage='preflight',exposure_seconds=60,
            boot_identity=preflight_boot,project_root=ROOT)
    elif d124:
        accounting.begin_d124_activity(LEDGER,activity_id=activity_id,stage='integration-preflight',
            exposure_seconds=300,boot_identity=preflight_boot,project_root=ROOT)
    else:
        accounting.begin_d122_other_interval(LEDGER,purpose='tank-preflight',interval_id=preflight_id,
            source_identity=preflight_source,boot_identity=preflight_boot,allowed_root=ROOT)
    try:bridge,checker,source,client,descriptor,selection=_continuation_bridge(
        build,bridge_path,proof_review_path,review_check_path,preflight_id)
    except BaseException:
        if d125:accounting.finalize_d125_activity(LEDGER,activity_id=activity_id,status='interrupted',
            boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
        elif d124:accounting.finalize_d124_activity(LEDGER,activity_id=activity_id,status='interrupted',
            boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
        else:accounting.finalize_d122_other_interval(LEDGER,interval_id=preflight_id,status='interrupted',
            boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
        raise
    if d125:accounting.finalize_d125_activity(LEDGER,activity_id=activity_id,status='completed',
        boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
    elif d124:accounting.finalize_d124_activity(LEDGER,activity_id=activity_id,status='completed',
        boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
    else:accounting.finalize_d122_other_interval(LEDGER,interval_id=preflight_id,status='completed',
        boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
    proof_path=selection['bridge_path'];proof_digest=selection['bridge_file_sha256']
    proof_digest=sha(proof_path)
    bridge_id=bridge['bridge_sha256'];boot=accounting.read_boot_identity()
    case=accounting.D125_CASES[0] if d125 else accounting.TANK_CONTINUATION_CASE
    if d125:
        current=accounting._load(LEDGER,ROOT);owner=accounting.selected_recovery_owner(current,project_root=ROOT,require_runtime=True)
        remaining=accounting.d125_remaining(current,monotonic_now=time.monotonic(),boot_identity=boot,project_root=ROOT)
        accounting.admit_d125_forecast(LEDGER,activity_id='d125-launch-forecast-'+case,
            nonprocess_seconds=owner['launch_forecast']['nonprocess_seconds'],process_seconds=remaining['process_remaining_seconds'],
            closeout_seconds=owner['launch_forecast']['closeout_seconds'],boot_identity=boot,project_root=ROOT)
    captured={}
    def capture_launcher(reservation):
        try:
            # Recheck every consumed source immediately before process creation.
            now_source=accounting.source_identity(ROOT)
            if d125:accounting.selected_recovery_owner(accounting._load(LEDGER,ROOT),project_root=ROOT,require_runtime=True)
            if (now_source!=source or sha(client)!=bridge['native_binary_sha256'] or
                    sha(selection['bridge_path'])!=selection['bridge_file_sha256'] or
                    sha(selection['proof_review_path'])!=selection['proof_review_sha256'] or
                    sha(selection['review_check_path'])!=selection['review_check_sha256']):
                raise RuntimeError('tank-capture-input-drift-before-process')
            result=_capture_reserved(build,'tank-battle',0xec32,accounting.PEA_SIGNATURE,
                '06-22-counted-tank-continuation' if d125 else '06-14-counted-tank-continuation',binary_override=descriptor,stack_observer=True)
            checks=checker.validate_pea_capture(result['native_report'],0xec32)
            result['pea_assertions']=checks
            captured['result']=result
            return result
        except BaseException as error:
            if isinstance(error,CaptureFailure):reservation['launcher_failure_receipt']=error.receipt
            elif captured.get('result') is not None:reservation['launcher_failure_receipt']=captured['result']
            reservation['failure_detail']=str(error)
            raise
    capture_result=accounting.authorize_launch(LEDGER,purpose='tank-continuation',plan='06-14',case=case,
        source_identity=source,current_source_identity=accounting.source_identity(ROOT),
        contract_identity=bridge_id,target_signature=accounting.PEA_SIGNATURE,launcher=capture_launcher,
        boot_identity=boot,allowed_root=ROOT)
    ledger=json.loads(LEDGER.read_text());reservation=next(r for r in ledger['records'] if r.get('record_id')==
        f'GW-06-AUTH-tank-continuation-{case}')
    capture_id=hashlib.sha256((reservation['record_id']+capture_result['native_report_sha256']+bridge_id).encode()).hexdigest()
    with accounting._locked(LEDGER):
        current=accounting._load(LEDGER,ROOT)
        current['current_tank_continuation_receipt']={'status':'captured','independently_checked':False,
            'record_id':reservation['record_id'],'purpose':'tank-continuation','plan':'06-14',
            'source_identity':source,'contract_identity':bridge_id,'capture_sha256':capture_id,
            'bridge_sha256':bridge_id,
            'native_report_sha256':capture_result['native_report_sha256'],
            'bridge_path':selection['bridge_path'].relative_to(ROOT).as_posix(),
            'bridge_file_sha256':selection['bridge_file_sha256'],
            'proof_review_path':selection['proof_review_path'].relative_to(ROOT).as_posix(),
            'proof_review_sha256':selection['proof_review_sha256'],
            'observer_review_check_path':selection['review_check_path'].relative_to(ROOT).as_posix(),
            'observer_review_check_file_sha256':selection['review_check_sha256'],
            'component_disposition_sha256':current.get('d124_component_disposition',{}).get('sha256')}
        if d125:
            owner=accounting.selected_recovery_owner(current,project_root=ROOT,require_runtime=True)
            current['current_tank_continuation_receipt'].update(recovery_owner='06-22',generation_id=owner['generation_id'])
        accounting._write(LEDGER,current)
    if not (d124 or d125):
        first_gap='tank-interprocess-0'
        accounting.begin_d122_other_interval(LEDGER,purpose='tank-interprocess',interval_id=first_gap,
            source_identity=source,boot_identity=boot,allowed_root=ROOT)
        accounting.finalize_d122_other_interval(LEDGER,interval_id=first_gap,status='completed',
            boot_identity=boot,allowed_root=ROOT)
    controls=[]
    control_output_root=(pathlib.Path(output).parent/(pathlib.Path(output).stem+'-controls')
        if d124 or d125 else build/'pea-controls')
    controls_cases=accounting.D125_CASES[1:] if d125 else ('control-repeat-1','control-repeat-2')
    for repetition,control_case in enumerate(controls_cases,1):
        if d125:
            gap_id=f'd125-interprocess-{repetition}'
            accounting.begin_d125_activity(LEDGER,activity_id=gap_id,stage='interprocess',exposure_seconds=60,
                boot_identity=accounting.read_boot_identity(),project_root=ROOT)
            accounting.finalize_d125_activity(LEDGER,activity_id=gap_id,status='completed',boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
        if repetition > 1 and not (d124 or d125):
            gap_id=f'tank-interprocess-{repetition-1}'
            accounting.begin_d122_other_interval(LEDGER,purpose='tank-interprocess',interval_id=gap_id,
                source_identity=source,boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
            accounting.finalize_d122_other_interval(LEDGER,interval_id=gap_id,status='completed',
                boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
        current_source=accounting.source_identity(ROOT)
        if d125:
            current=accounting._load(LEDGER,ROOT);owner=accounting.selected_recovery_owner(current,project_root=ROOT,require_runtime=True)
            current_boot=accounting.read_boot_identity()
            remaining=accounting.d125_remaining(current,monotonic_now=time.monotonic(),boot_identity=current_boot,project_root=ROOT)
            accounting.admit_d125_forecast(LEDGER,activity_id='d125-launch-forecast-'+control_case,
                nonprocess_seconds=owner['launch_forecast']['nonprocess_seconds'],process_seconds=remaining['process_remaining_seconds'],
                closeout_seconds=owner['launch_forecast']['closeout_seconds'],boot_identity=current_boot,project_root=ROOT)
        def control_launcher(_row,n=repetition):
            if d125:
                accounting.selected_recovery_owner(accounting._load(LEDGER,ROOT),project_root=ROOT,require_runtime=True)
                if (accounting.source_identity(ROOT)!=source or sha(client)!=bridge['control_client_binary_sha256'] or
                        sha(selection['bridge_path'])!=selection['bridge_file_sha256'] or
                        sha(selection['proof_review_path'])!=selection['proof_review_sha256'] or
                        sha(selection['review_check_path'])!=selection['review_check_sha256']):
                    raise RuntimeError('d125-control-input-drift-before-process')
            return _tank_control_driver(build,n,bridge_id,source,output_root=control_output_root)
        control=accounting.authorize_launch(LEDGER,purpose='tank-continuation-control',plan='06-14',case=control_case,
            source_identity=current_source,current_source_identity=current_source,contract_identity=bridge_id,
            target_signature=None,launcher=control_launcher,
            boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
        controls.append(control)
    receipt={'schema':'phase6-tank-continuation-v1','status':'passed-capture','reservation':reservation,
        'source_identity':source,'proof_revalidation_sha256':bridge_id,'client_binary_sha256':sha(client),
        'capture_descriptor_sha256':hashlib.sha256(descriptor).hexdigest(),
        'native_report_raw':capture_result['native_report_raw'],'native_report_sha256':capture_result['native_report_sha256'],
        'native_report':capture_result['native_report'],'processes':capture_result['processes'],
        'process_streams':capture_result['process_streams'],'controls':controls,'launches':3,'rec_processes':0,
        'guest_fields':capture_result['native_report'].get('fields'),'route_qualification':False}
    if d125:receipt.update(recovery_owner='06-22',generation_id=reservation['generation_id'])
    if output.exists() or output.is_symlink():raise RuntimeError('tank-continuation-output-exists-or-symlink')
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':'passed-capture','receipt':output.relative_to(ROOT).as_posix(),
        'target_attempts':1,'capture_processes':1,'control_driver_processes':2,'control_native_children':12,
        'rec_processes':0,'route_qualification':False},sort_keys=True));return 0

def _d133_main(argv):
    p=argparse.ArgumentParser()
    p.add_argument('--accounting-preflight',action='store_true',required=True)
    p.add_argument('--accounting-scope',choices=('D133',),required=True)
    settlement=globals().get('D133_SETTLEMENT')
    if settlement is None:settlement=module('phase6_settlement','scripts/evidence/phase6_settlement.py')
    settlement.cli_arguments(p)
    # Exact parser deliberately rejects every game, launch and close selector.
    a=p.parse_args(argv)
    try:
        report=settlement.d133_current_view(a.ledger,**settlement.cli_context(a))
        print(json.dumps(report,sort_keys=True));return 0
    except (OSError,RuntimeError,ValueError,KeyError,TypeError) as error:
        print(json.dumps({'status':'blocked','reason':str(error),'actual_total_status':'unknown'},sort_keys=True));return 1

def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if '--tank-checkpoint47' in argv:
        argv.remove('--tank-checkpoint47')
        legacy_prefixes=('--accounting-', '--d122-', '--tank-continuation-', '--pea-', '--capture', '--purpose')
        mixed=[arg for arg in argv if arg.startswith(legacy_prefixes)]
        if mixed:
            print(json.dumps({'status':'halted','reason':'mixed-plan47-and-legacy-flags','flags':mixed}),file=sys.stderr)
            return 2
        helper_path=ROOT/'scripts/evidence/phase6_tank_checkpoint.py'
        spec=importlib.util.spec_from_file_location('phase6_tank_checkpoint47',helper_path)
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        return helper.main(argv)
    if any(arg=='--accounting-scope' or arg.startswith('--accounting-scope=') for arg in argv):
        return _d133_main(argv)
    _load_legacy_modules()
    p=argparse.ArgumentParser();p.add_argument('--build',type=pathlib.Path)
    p.add_argument('--d125-close-owner',action='store_true')
    p.add_argument('--terminal-status',choices=('HALTED','accepted-original14-recovery'))
    p.add_argument('--terminal-reason')
    for flag in ('cpu-bus','devices','audio','feasibility'):p.add_argument('--'+flag,action='store_true')
    p.add_argument('--capture',choices=('tank-battle','recursion94'));p.add_argument('--pc',type=lambda s:int(s,0))
    p.add_argument('--stop-id');p.add_argument('--label',default='production-recheck')
    p.add_argument('--purpose',choices=('independent-pea','rec-validation','joint-qualification'))
    p.add_argument('--case');p.add_argument('--contract-identity')
    p.add_argument('--accounting-preflight',action='store_true');p.add_argument('--accounting-self-test',action='store_true')
    p.add_argument('--tank-continuation-offline',action='store_true')
    p.add_argument('--stack-observer-accounting-offline',action='store_true')
    p.add_argument('--tank-continuation-begin',action='store_true')
    p.add_argument('--tank-continuation-close',action='store_true')
    p.add_argument('--tank-continuation-once',action='store_true')
    p.add_argument('--bridge',type=pathlib.Path,default=pathlib.Path('evidence/phase6-tank-observer-bridge-d123-g02.json'))
    p.add_argument('--proof-review',type=pathlib.Path,default=pathlib.Path('.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-19-PROOF-REVIEW.md'))
    p.add_argument('--review-check',type=pathlib.Path)
    p.add_argument('--d122-other-begin',action='store_true');p.add_argument('--d122-other-close',action='store_true')
    p.add_argument('--d122-other-deadline',action='store_true')
    p.add_argument('--other-purpose',choices=sorted(accounting.D122_OTHER_PURPOSES));p.add_argument('--other-interval-id')
    p.add_argument('--other-source-identity')
    p.add_argument('--output',type=pathlib.Path)
    p.add_argument('--pea-regressions',action='store_true')
    p.add_argument('--pea-next-stop',action='store_true');p.add_argument('--verify-pea-receipt',action='store_true')
    p.add_argument('--accounting-close-current',action='store_true')
    a=p.parse_args(argv);build=a.build.resolve() if a.build else ROOT/'build'
    try:
        if a.d125_close_owner:
            if not a.output or not a.terminal_status or not a.terminal_reason:
                p.error('--d125-close-owner requires --output --terminal-status --terminal-reason')
            report=accounting.close_d125_owner(LEDGER,output=a.output if a.output.is_absolute() else ROOT/a.output,
                status=a.terminal_status,reason=a.terminal_reason,boot_identity=accounting.read_boot_identity(),project_root=ROOT)
            print(json.dumps({'status':report['status'],'anchor':None,'accounting':report['accounting']},sort_keys=True));return 0
        if a.tank_continuation_offline:return tank_continuation_offline()
        if a.stack_observer_accounting_offline:return stack_observer_accounting_offline()
        if a.tank_continuation_begin:return tank_continuation_begin()
        if a.tank_continuation_close:return tank_continuation_close()
        if a.tank_continuation_once:
            if not a.build or not a.output or not a.bridge or not a.proof_review or not a.review_check:
                p.error('--tank-continuation-once requires --build --output --bridge --proof-review --review-check')
            return tank_continuation_once(build,a.output if a.output.is_absolute() else ROOT/a.output,
                a.bridge,a.proof_review,a.review_check)
        if a.d122_other_begin:
            if not a.other_purpose or not a.other_interval_id or not a.other_source_identity:
                p.error('--d122-other-begin requires --other-purpose --other-interval-id --other-source-identity')
            row=accounting.begin_d122_other_interval(LEDGER,purpose=a.other_purpose,interval_id=a.other_interval_id,
                source_identity=a.other_source_identity,boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
            print(json.dumps(row,sort_keys=True));return 0
        if a.d122_other_close:
            if not a.other_interval_id:p.error('--d122-other-close requires --other-interval-id')
            row=accounting.finalize_d122_other_interval(LEDGER,interval_id=a.other_interval_id,
                boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
            print(json.dumps(row,sort_keys=True));return 0
        if a.d122_other_deadline:
            if not a.other_interval_id:p.error('--d122-other-deadline requires --other-interval-id')
            row=accounting.d122_other_interval_deadline(LEDGER,interval_id=a.other_interval_id,
                boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
            print(json.dumps(row,sort_keys=True));return 0
        if a.accounting_preflight:
            print(json.dumps(accounting.preflight(LEDGER,monotonic_now=time.monotonic(),
                boot_identity=accounting.read_boot_identity(),require_active_anchor=True,
                allowed_root=ROOT),sort_keys=True));return 0
        if a.accounting_close_current:
            source_anchor=json.loads(ACCOUNTING_ANCHOR.read_text())
            closed=accounting.close_external_interval(LEDGER,ACCOUNTING_ANCHOR,
                source_anchor=source_anchor,monotonic_now=time.monotonic(),
                boot_identity=accounting.read_boot_identity(),allowed_root=ROOT)
            print(json.dumps(closed,sort_keys=True));return 0
        if a.accounting_self_test:
            test=ROOT/'tests/evidence/phase6_accounting_contract.py'
            return subprocess.run([sys.executable,'-I',str(test)],cwd=ROOT).returncode
        if a.pea_regressions:
            if not a.build:p.error('--pea-regressions requires --build')
            return pea_regressions(build)
        if a.pea_next_stop:
            if not a.build:p.error('--pea-next-stop requires --build')
            return pea_next_stop(build)
        if a.verify_pea_receipt:
            if not a.build:p.error('--verify-pea-receipt requires --build')
            return verify_pea_receipt(build)
        if a.capture:
            if not a.build:p.error('--capture requires --build')
            if a.pc is None or not a.stop_id:p.error('--capture requires --pc and --stop-id')
            capture(build,a.capture,a.pc,a.stop_id,a.label,purpose=a.purpose,case=a.case,
                    contract_identity=a.contract_identity);return 0
        lanes=[lane for lane in ('cpu-bus','devices','audio','feasibility') if getattr(a,lane.replace('-','_'))]
        if len(lanes)!=1:p.error('choose exactly one lane or --capture')
        if not a.build:p.error('lane execution requires --build')
        return blocked_lane(build,lanes[0])
    except (OSError,RuntimeError,ValueError,KeyError,TypeError) as e:
        if a.tank_continuation_once and a.output:
            current=json.loads(LEDGER.read_bytes())
            if current.get('d125_owner_generations'):
                output=a.output if a.output.is_absolute() else ROOT/a.output
                if not output.exists() and not output.is_symlink():
                    selected=accounting._safe_create_path(output,ROOT)
                    rows=[r for r in current.get('records',[]) if r.get('d125_owner')=='06-22']
                    failed={'schema':'phase6-d125-continuation-halt-v1','status':'HALTED','recovery_owner':'06-22','reason':str(e),
                        'reservation_ids':[r['record_id'] for r in rows],'completed_reservations':sum(r.get('status')=='completed' for r in rows),
                        'planned_denominator':{'tank':1,'control_parents':2,'native_control_children':12,'full_pcm_files':12},
                        'retained_ledger_path':LEDGER.relative_to(ROOT).as_posix(),'retained_ledger_sha256':sha(LEDGER),
                        'retained_raw_receipts':[{'record_id':r['record_id'],'status':r.get('status'),
                            'native_report_sha256':r.get('launcher_failure_receipt',r.get('launcher_result',{})).get('native_report_sha256'),
                            'native_raw_in_ledger':bool(r.get('launcher_failure_receipt',r.get('launcher_result',{})).get('native_report_raw'))} for r in rows],
                        'available_controls_root':(output.parent/(output.stem+'-controls')).relative_to(ROOT).as_posix(),
                        'acceptance':'unreached; no retry; interrupted unreported child counts remain unknown'}
                    fd=os.open(selected,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
                    with os.fdopen(fd,'w') as stream:
                        json.dump(failed,stream,sort_keys=True,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        print(json.dumps({'status':'blocked','reason':str(e)},sort_keys=True));return 1

if __name__=='__main__':
    os.environ["GENEWHIP_PROCESS_CONTEXT"] = "host-cleanup-v1"
    raise SystemExit(main())
