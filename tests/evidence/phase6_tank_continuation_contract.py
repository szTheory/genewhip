#!/usr/bin/env python3
"""Independent, no-launch validation for the bounded Tank continuation proof."""
from __future__ import annotations
import argparse, contextlib, hashlib, importlib.util, io, json, os, pathlib, re, secrets, shutil, stat, struct, subprocess, sys, tempfile, time
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[2]
BASELINE_COMMIT='73c767bf5ecabe15eeb061296d7b571c7c0c5654'
MANIFEST=ROOT/'evidence/phase6-capture-recovery.json'
BRIDGE=ROOT/'evidence/phase6-tank-observer-bridge.json'
REVIEW_CHECK=ROOT/'evidence/phase6-tank-observer-review-check.json'
LEDGER=ROOT/'evidence/phase6-repairs.json'
ORIGINAL_BINARY_ROOT=ROOT/'build/phase6-d122-original-binaries'
ORIGINAL_BINARY_MANIFEST=ORIGINAL_BINARY_ROOT/'manifest.json'
WATCHES=(('instruction-word-0',0x00ec32),('instruction-word-1',0x00ec34),
         ('instruction-word-2',0x00ec36))
D122_OTHER_DEADLINE_MONOTONIC=None

def verify_qualification23_bridge(path, build):
    """Recompute the explicit engineering tuple without selecting runtime authority."""
    path=project_input_path(path)
    bridge=json.loads(path.read_bytes())
    if (bridge.get('schema')!='phase6-qualification23-bridge-v1' or bridge.get('engineering_owner')!='06-23' or
            bridge.get('game_admission') is not False or bridge.get('generation')!='23' or
            bridge.get('bridge_sha256')!=_canonical_digest({k:v for k,v in bridge.items() if k!='bridge_sha256'})):
        raise ValueError('qualification23-bridge-identity-invalid')
    accounting=load_module('qualification23_bridge_accounting','scripts/evidence/phase6_accounting.py')
    ledger=accounting._load(LEDGER,ROOT)
    accounting.qualification23_owner(ledger,project_root=ROOT)
    if bridge.get('source_identity')!=accounting.source_identity(ROOT):
        raise ValueError('qualification23-source-stale')
    artifacts={}
    for key in ('manifest','qualification','component_review','source_freeze'):
        item=bridge.get(key,{})
        artifact=project_input_path(item.get('path',''))
        if sha(artifact)!=item.get('sha256'):raise ValueError('qualification23-artifact-stale:'+key)
        artifacts[key]=json.loads(artifact.read_bytes())
    manifest=artifacts['manifest'];qualification=artifacts['qualification'];component=artifacts['component_review']
    frozen=ledger.get('d125_qualification23_manifest',{})
    if (manifest.get('generation')!='23' or manifest.get('engineering_owner')!='06-23' or
            manifest.get('game_admission') is not False or manifest.get('source_identity')!=bridge['source_identity'] or
            frozen.get('sha256')!=bridge['manifest']['sha256'] or frozen.get('path')!=bridge['manifest']['path']):
        raise ValueError('qualification23-manifest-binding-invalid')
    components=manifest.get('component_sha256',{})
    stack=load_module('qualification23_raw_recompute','tests/evidence/phase6_stack_observation_contract.py')
    if components!=stack._d123_current_component_map(accounting):
        raise ValueError('qualification23-complete-source-denominator-stale')
    for name,digest in components.items():
        if sha(project_input_path(name))!=digest:raise ValueError('qualification23-component-stale:'+name)
    variants=['native','sanitize','hooks-off']
    if (qualification.get('status')!='passed-three-rows' or qualification.get('qualification_count')!=3 or
            qualification.get('manifest_sha256')!=bridge['manifest']['sha256'] or
            qualification.get('source_identity')!=bridge['source_identity'] or qualification.get('target_attempts')!=0 or
            [r.get('variant') for r in qualification.get('rows',[])]!=variants or
            [r.get('variant') for r in manifest.get('cases',[])]!=variants or
            [r.get('variant') for r in manifest.get('builds',[])]!=variants):
        raise ValueError('qualification23-actual-three-row-denominator-invalid')
    for row,case,built in zip(qualification['rows'],manifest['cases'],manifest['builds']):
        variant=row['variant'];binary=project_input_path(built['binary_path'])
        cache=project_input_path(built['directory']+'/CMakeCache.txt')
        tools=stack._d123_build_tool_record(cache.parent,variant,built['command'])
        if (sha(binary)!=built['binary_sha256'] or sha(cache)!=built['cache_sha256'] or
                tools['compiler_sha256']!=built['compiler_sha256'] or tools['build_tool_sha256']!=built['build_tool_sha256'] or
                tools['settings']!=built['settings'] or row.get('binary_sha256')!=sha(binary)):
            raise ValueError('qualification23-build-or-tools-stale:'+variant)
        if (case!=stack._d123_variant_case(variant,'23') or row.get('purpose_id')!='d123-qual-g23-'+variant or
                row.get('guest_sha256')!=case['guest_sha256'] or row.get('descriptor_sha256')!=case['descriptor_sha256'] or
                row.get('source_identity')!=bridge['source_identity'] or row.get('process_return_code')!=1 or
                row.get('timed_out') is not False or row.get('bound_violation') is not False):
            raise ValueError('qualification23-input-process-or-purpose-invalid:'+variant)
        raw=project_input_path(row['raw_report_path'])
        if raw.stat().st_size>8388608 or sha(raw)!=row.get('raw_report_sha256'):
            raise ValueError('qualification23-raw-missing-or-stale:'+variant)
        run_path=raw.parent/'run.json';run=json.loads(run_path.read_bytes())
        guest_path=raw.parent/'guest.bin';descriptor=raw.parent/'route.bin'
        oracle=stack._qualification23_oracle()
        command=oracle.argv_builder()(built['binary_path'],descriptor.relative_to(ROOT).as_posix(),
            raw.relative_to(ROOT).as_posix(),0x200,guest_path.relative_to(ROOT).as_posix(),stack_observer=True)
        if (sha(guest_path)!=case['guest_sha256'] or sha(descriptor)!=case['descriptor_sha256'] or
                command!=row.get('command') or run.get('command')!=command or
                run.get('process',{}).get('return_code')!=1 or run['process'].get('timed_out') is not False or
                run['process'].get('bound_violation') is not False or run['process'].get('wall_seconds',31)>30):
            raise ValueError('qualification23-full-argv-or-process-invalid:'+variant)
        expected_oracle=sha_bytes(json.dumps(case['expected'],sort_keys=True).encode())
        if row.get('oracle_sha256')!=expected_oracle or run.get('oracle_sha256')!=expected_oracle:
            raise ValueError('qualification23-oracle-stale:'+variant)
        streams=row.get('process_streams',{})
        if set(streams)!={'stdout','stderr'} or streams!=run['process'].get('streams'):
            raise ValueError('qualification23-stream-denominator-invalid')
        for key,item in streams.items():
            stream=project_input_path(item['path'])
            if (sha(stream)!=item['sha256'] or item.get('truncated') is not False or
                    stream.stat().st_size!=item.get('observed_bytes') or stream.stat().st_size!=item.get('retained_bytes') or
                    stream.stat().st_size>1048576):
                raise ValueError('qualification23-stream-stale:'+variant+':'+key)
        checks=stack.validate_qualification23_capture(json.loads(raw.read_bytes()))
        if checks!=row.get('checks'):raise ValueError('qualification23-capture-recomputation-mismatch:'+variant)
    if (component.get('decision')!='accepted' or component.get('high_count')!=0 or component.get('critical_count')!=0 or
            component.get('reviewer_role')!='gsd-code-reviewer' or not component.get('reviewer_identity')):
        raise ValueError('qualification23-retained-component-not-accepted')
    for item in component.get('inspected_files',[]):
        name=item['path']
        # Current mutable planning/consumer/CLI files are excluded by this
        # narrow forwarding-component disposition; raw/runtime bindings below
        # remain mandatory and are independently enumerated in source-freeze.
        if name in artifacts['source_freeze'].get('retained_file_sha256',{}):
            if sha(project_input_path(name))!=item['sha256']:
                raise ValueError('qualification23-retained-component-stale:'+name)
    retained=artifacts['source_freeze'].get('retained_file_sha256',{})
    if not retained or any(sha(project_input_path(p))!=h for p,h in retained.items()):
        raise ValueError('qualification23-retained-raw-closure-missing-or-stale')
    return bridge


def create_qualification23_bridge(build, manifest_path, qualification_path, output_path, source_freeze):
    accounting=load_module('qualification23_create_accounting','scripts/evidence/phase6_accounting.py')
    phase='.planning/phases/GW-06-shared-repairs-and-two-playable-routes/'
    bridge={'schema':'phase6-qualification23-bridge-v1','engineering_owner':'06-23','generation':'23',
        'status':'passed-affected-qualification-no-game-authority','game_admission':False,
        'source_identity':accounting.source_identity(ROOT)}
    for key,p in (('manifest',manifest_path),('qualification',qualification_path),
                  ('component_review',ROOT/(phase+'06-23-COMPONENT-REVIEW.json')),('source_freeze',source_freeze)):
        p=project_input_path(p);bridge[key]={'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p)}
    bridge['bridge_sha256']=_canonical_digest(bridge)
    output=pathlib.Path(output_path)
    _atomic_publish_checked_output(output,(json.dumps(bridge,indent=2)+'\n').encode())
    verify_qualification23_bridge(output,build)
    return bridge


def verify_qualification23_proof(bridge_path, review_path, build, output):
    bridge=verify_qualification23_bridge(bridge_path,build)
    review_path=project_input_path(review_path);review=_review_payload(review_path)
    validate_qualification23_review_payload(review,bridge)
    accounting=load_module('qualification23_proof_accounting','scripts/evidence/phase6_accounting.py')
    ledger=accounting._load(LEDGER,ROOT)
    rows=[r for r in ledger.get('d125_qualification23_reviews',[]) if r.get('event')=='proof-review' and
          r.get('review_sha256')==sha(review_path) and r.get('bridge_sha256')==bridge['bridge_sha256']]
    if len(rows)!=1:raise ValueError('qualification23-parent-observed-proof-handoff-required')
    row=rows[0];pin_path=project_input_path(row['parent_pin_path']);pin=json.loads(pin_path.read_bytes())
    if (sha(pin_path)!=row['parent_pin_sha256'] or pin.get('origin')!='parent-observed-separate-reviewer-completion' or
            pin.get('tool_handoff_result')!='completed' or pin.get('decision')!='accepted' or
            pin.get('reviewer_identity')!=row.get('reviewer_identity') or pin.get('reviewer_identity')!=review.get('reviewer_identity') or
            not isinstance(pin.get('producer_identity'),str) or not pin['producer_identity'].strip() or
            pin['producer_identity'].strip().casefold()==review['reviewer_identity'].strip().casefold() or
            pin.get('reviewer_role')!='gsd-code-reviewer' or pin.get('review_sha256')!=sha(review_path) or
            pin.get('source_identity')!=bridge['source_identity'] or pin.get('bridge_file_sha256')!=sha(project_input_path(bridge_path)) or
            pin.get('test_fixture_only') is True):
        raise ValueError('qualification23-parent-proof-pin-stale')
    result={'schema':'phase6-qualification23-review-check-v1','status':'accepted','engineering_owner':'06-23',
        'game_admission':False,'source_identity':bridge['source_identity'],'bridge_sha256':bridge['bridge_sha256'],
        'bridge_path':project_input_path(bridge_path).relative_to(ROOT).as_posix(),'bridge_file_sha256':sha(project_input_path(bridge_path)),
        'review_path':review_path.relative_to(ROOT).as_posix(),'review_sha256':sha(review_path),
        'parent_pin_path':pin_path.relative_to(ROOT).as_posix(),'parent_pin_sha256':sha(pin_path),
        'qualification_count':3,'launches':0,'checker_sha256':sha(pathlib.Path(__file__))}
    result['check_sha256']=_canonical_digest(result)
    output=pathlib.Path(output);output=output if output.is_absolute() else ROOT/output
    before=sha(LEDGER)
    with accounting._locked(LEDGER):
        verify_qualification23_bridge(bridge_path,build)
        if (sha(LEDGER)!=before or sha(review_path)!=result['review_sha256'] or sha(pin_path)!=result['parent_pin_sha256']):
            raise ValueError('qualification23-proof-drift-under-lock')
        _atomic_publish_checked_output(output,(json.dumps(result,indent=2)+'\n').encode())
    return result


def verify_qualification23_companion(bridge_path, review_path, check_path, build):
    bridge=verify_qualification23_bridge(bridge_path,build)
    check_path=project_input_path(check_path);check=json.loads(check_path.read_bytes())
    review_path=project_input_path(review_path)
    validate_qualification23_review_payload(_review_payload(review_path),bridge)
    if (check.get('schema')!='phase6-qualification23-review-check-v1' or check.get('status')!='accepted' or
            check.get('check_sha256')!=_canonical_digest({k:v for k,v in check.items() if k!='check_sha256'}) or
            check.get('bridge_file_sha256')!=sha(project_input_path(bridge_path)) or
            check.get('bridge_sha256')!=bridge['bridge_sha256'] or check.get('source_identity')!=bridge['source_identity'] or
            check.get('review_path')!=review_path.relative_to(ROOT).as_posix() or check.get('review_sha256')!=sha(review_path) or
            check.get('qualification_count')!=3 or type(check.get('qualification_count')) is not int or
            check.get('launches')!=0 or check.get('game_admission') is not False or
            check.get('checker_sha256')!=sha(pathlib.Path(__file__))):
        raise ValueError('qualification23-companion-stale-or-wrong-denominator')
    pin_path=project_input_path(check['parent_pin_path']);pin=json.loads(pin_path.read_bytes())
    if (sha(pin_path)!=check['parent_pin_sha256'] or pin.get('origin')!='parent-observed-separate-reviewer-completion' or
            pin.get('decision')!='accepted' or pin.get('review_sha256')!=sha(review_path) or
            pin.get('bridge_file_sha256')!=sha(project_input_path(bridge_path))):
        raise ValueError('qualification23-companion-parent-pin-stale')
    return {'engineering_owner':'06-23','game_admission':False,'qualification_count':3,
        'source_identity':bridge['source_identity'],'bridge':{'path':project_input_path(bridge_path).relative_to(ROOT).as_posix(),
        'sha256':sha(project_input_path(bridge_path))},'proof_review':{'path':review_path.relative_to(ROOT).as_posix(),'sha256':sha(review_path)},
        'review_check':{'path':check_path.relative_to(ROOT).as_posix(),'sha256':sha(check_path)}}

def sha_bytes(value):return hashlib.sha256(value).hexdigest()
def _deadline_remaining():
    if D122_OTHER_DEADLINE_MONOTONIC is None:return None
    remaining=D122_OTHER_DEADLINE_MONOTONIC-time.monotonic()
    if remaining<=0:raise ValueError('d122-other-live-deadline-exhausted')
    return remaining
def sha(path):
    _deadline_remaining();digest=sha_bytes(pathlib.Path(path).read_bytes());_deadline_remaining();return digest
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def source_paths(root):
    files=list((root/'src').rglob('*.c'))+list((root/'src').rglob('*.h'))
    for directory in ('include','tools'):
        files+=list((root/directory).rglob('*.c'))+list((root/directory).rglob('*.h'))
    files += [root/'CMakeLists.txt']+list((root/'tools').rglob('CMakeLists.txt'))+list((root/'cmake').rglob('*.cmake'))
    files += [root/'scripts/evidence/phase6_routes.py',root/'scripts/evidence/phase6_accounting.py',
              root/'tests/fixtures/phase6_repairs.py',root/'tests/session/phase6_route_contract.py',
              root/'tests/api/phase6_repairs_contract.c']
    return sorted({p.relative_to(root).as_posix() for p in files if p.is_file()})
def git_blob(revision,path):
    remaining=_deadline_remaining();timeout=min(10.0,remaining) if remaining is not None else 10.0
    data=subprocess.check_output(['git','show',f'{revision}:{path}'],cwd=ROOT,timeout=timeout)
    _deadline_remaining();return data
def tree_source_identity(revision,paths):
    digest=hashlib.sha256()
    for name in paths:
        data=git_blob(revision,name);encoded=name.encode()
        digest.update(len(encoded).to_bytes(4,'big'));digest.update(encoded);digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()
def current_source_identity():
    _deadline_remaining();result=load_module('tank_continuation_accounting','scripts/evidence/phase6_accounting.py').source_identity(ROOT)
    _deadline_remaining();return result

def boundary_pair(native,pc):
    if native.get('stop_reason') in (2,3,4):
        pair=native.get('last_boundary')
        if not isinstance(pair,dict):raise ValueError('stop-boundary-missing')
        before=pair.get('before',{});after=pair.get('after',{})
        if (native.get('instruction_address')!=pair.get('instruction_address') or
            native.get('opcode')!=pair.get('opcode') or native.get('stop_reason')!=pair.get('stop_reason') or
            native.get('first_stop_tick')!=after.get('tick') or native.get('final_tick')!=after.get('tick')):
            raise ValueError('stop-boundary-metadata-mismatch')
        if native.get('probe_boundary') is None:raise ValueError('probe-not-reached-before-stop')
    pair=native.get('probe_boundary')
    if not isinstance(pair,dict):raise ValueError('probe-boundary-missing')
    before=pair.get('before');after=pair.get('after')
    if not isinstance(before,dict) or not isinstance(after,dict):raise ValueError('probe-boundary-states-invalid')
    if pair.get('instruction_address')!=pc or before.get('pc')!=pc:raise ValueError('probe-address-mismatch')
    for label,state in (('before',before),('after',after)):
        if state.get('boundary_calls') is not None and (type(state['boundary_calls']) is not int or state['boundary_calls']<0):
            raise ValueError('boundary-call-count-invalid:'+label)
    return True

def _span(state,address,length):
    for item in state.get('spans',[]):
        try:
            start=item['address'];data=bytes.fromhex(item['bytes'])
            if start<=address and address+length<=start+len(data):return data[address-start:address-start+length]
        except (KeyError,ValueError,TypeError):pass
    raise ValueError(f'missing-required-span:{address:06x}:{length}')

def validate_pea_capture(native,pc=0x00ec32):
    if not isinstance(native,dict) or native.get('schema')!='genewhip-route-native-v1':raise ValueError('native-report-schema-invalid')
    if native.get('stop_reason') not in (2,3,4) or native.get('fields',0)>4500 or native.get('active_ticks',0)>3600:
        raise ValueError('capture-terminal-or-resource-invalid')
    boundary_pair(native,pc)
    pair=native.get('probe_boundary');before=pair['before'];after=pair['after']
    stack_contract=load_module('phase6_stack_contract','tests/evidence/phase6_stack_observation_contract.py')
    stack=stack_contract.validate_stack_pair(pair,enabled=True,expected_source_a7=before['a'][7],
        expected_after=[0x00,0x06,0x92,0x3c])
    checks={
      'probe_pc':pair['instruction_address']==pc and before['pc']==pc,
      'probe_opcode_retired':pair['opcode']==0x4879 and pair['retired'] is True and after['instructions']==before['instructions']+1,
      'ea_instruction_bytes':_span(before,pc,6)==bytes.fromhex('48790006923c'),
      'effective_address':int.from_bytes(_span(before,pc+2,4),'big')==0x0006923c,
      'stack_delta':type(before['a'][7]) is int and type(after['a'][7]) is int and after['a'][7]==((before['a'][7]-4)&0xffffffff),
      'actual_stack_observation':pair['before']['stack_observation']['read_calls']+
          pair['after']['stack_observation']['read_calls']==8 and pair['after']['stack_observation']['status']==[0,0,0,0],
      'stack_big_endian':pair['after']['stack_observation']['bytes']==[0x00,0x06,0x92,0x3c],
      'sr_preserved':after['sr']==before['sr'],
      'sixteen_bit_bus_timing':after['tick']-before['tick']==140,
      'later_stop_metadata':native['instruction_address']==native['last_boundary']['instruction_address'] and
          native['first_stop_tick']==native['last_boundary']['after']['tick'] and native['final_tick']==native['last_boundary']['after']['tick']}
    if not all(checks.values()):raise ValueError('pea-assertion-failed:'+','.join(k for k,v in checks.items() if not v))
    if native.get('boundary_calls',129)>128 or native.get('queue_high_water',65)>64:
        raise ValueError('capture-boundary-or-event-limit')
    return checks

def validate_streams(process,streams):
    if not isinstance(process,dict) or process.get('return_code')!=1 or process.get('bound_violation') is not False or process.get('timed_out') is True:
        raise ValueError('capture-process-disposition-invalid')
    if not isinstance(streams,dict):raise ValueError('capture-streams-missing')
    for key in ('stdout','stderr'):
        item=streams.get(key)
        if not isinstance(item,dict) or item.get('truncated') is not False:raise ValueError('capture-stream-truncated')
        raw=item.get('text','').encode()
        if len(raw)!=item.get('retained_bytes') or len(raw)!=item.get('observed_bytes') or sha_bytes(raw)!=item.get('sha256'):
            raise ValueError('capture-stream-hash-or-size-mismatch')

def validate_retained_synthetic(native):
    if not isinstance(native,dict) or native.get('schema')!='genewhip-route-native-v1':raise ValueError('retained-report-schema-invalid')
    boundary_pair(native,0x200);p=native['probe_boundary'];last=native['last_boundary']
    checks={'pea_opcode_retired':p['opcode']==0x4879 and p['retired'] is True,
      'stack_pointer_and_sr':p['after']['a'][7]==0xfffefc and p['after']['sr']==p['before']['sr'],
      'pea_16bit_timing':p['after']['tick']-p['before']['tick']==140,
      'stack_value_big_endian':_span(p['after'],0xfffefc,4)==bytes.fromhex('00e00010'),
      'swap_result':last['before']['d'][0]==0x56781234,
      'exact_unsupported_stop':last['before']['pc']==0x20e and last['opcode']==0x4afc and not last['retired'],
      'bounded_zero_field_prefix':native['fields']==0 and native['active_ticks']==0 and native['boundary_calls']<=128,
      'fault_does_not_retire':last['before']['instructions']==last['after']['instructions'],
      'stop_metadata_agrees':native['instruction_address']==last['instruction_address'] and native['first_stop_tick']==last['after']['tick'] and native['final_tick']==last['after']['tick']}
    if not all(checks.values()):raise ValueError('retained-nine-assertions-failed:'+','.join(k for k,v in checks.items() if not v))
    return checks

def validate_receipt_data(receipt,bridge,*,check_pcm=True,root=ROOT,check_controls=True,ledger_path=None):
    if not isinstance(receipt,dict) or receipt.get('schema')!='phase6-tank-continuation-v1' or receipt.get('status')!='passed-capture':
        raise ValueError('continuation-receipt-not-passed')
    if type(receipt.get('launches')) is not int or receipt['launches'] != 3 or type(receipt.get('rec_processes')) is not int or receipt['rec_processes'] != 0:
        raise ValueError('continuation-observed-process-metadata-invalid')
    reservation=receipt.get('reservation')
    expected_case='d125-tank-pea-continuation-1' if receipt.get('recovery_owner')=='06-22' else 'tank-pea-continuation-1'
    if not isinstance(reservation,dict) or reservation.get('record_id')!='GW-06-AUTH-tank-continuation-'+expected_case or \
       reservation.get('purpose')!='tank-continuation' or reservation.get('plan')!='06-14' or \
       reservation.get('new_target_attempts')!=1 or reservation.get('process_count')!=1 or \
       reservation.get('case_count')!=1 or reservation.get('status')!='completed':
        raise ValueError('continuation-reservation-invalid-or-replayed')
    bridge_source=bridge.get('current_source_closure',{}).get('source_identity',bridge.get('current_source_identity'))
    if receipt.get('source_identity')!=bridge_source or \
       receipt.get('proof_revalidation_sha256')!=bridge.get('bridge_sha256') or \
       receipt.get('client_binary_sha256')!=bridge.get('control_client_binary_sha256') or \
       receipt.get('capture_descriptor_sha256')!=bridge.get('capture_descriptor_sha256'):
        raise ValueError('continuation-source-binary-or-bridge-mismatch')
    raw=receipt.get('native_report_raw')
    if not isinstance(raw,str) or sha_bytes(raw.encode())!=receipt.get('native_report_sha256'):
        raise ValueError('continuation-raw-report-hash-invalid')
    try:native=json.loads(raw)
    except json.JSONDecodeError as exc:raise ValueError('continuation-raw-report-invalid') from exc
    if native!=receipt.get('native_report'):raise ValueError('continuation-parsed-report-disagrees')
    checks=validate_pea_capture(native,0x00ec32)
    processes=receipt.get('processes')
    if not isinstance(processes,list) or len(processes)!=1:raise ValueError('continuation-process-denominator-invalid')
    validate_streams(processes[0],receipt.get('process_streams'))
    controls=receipt.get('controls')
    if not isinstance(controls,list) or len(controls)!=2:raise ValueError('control-driver-denominator-invalid')
    expected_ids=['title-no-start','start-idle','start-move','action-sound','action-no-trigger','sustained-play']
    for index,control in enumerate(controls,1):
        if control.get('repetition')!=index or control.get('status')!='pass' or control.get('cases')!=6:
            raise ValueError('control-driver-status-invalid')
        rows=control.get('results');children=control.get('native_child_processes')
        if not isinstance(rows,list) or [r.get('id') for r in rows]!=expected_ids or not isinstance(children,list) or len(children)!=6:
            raise ValueError('control-six-case-child-denominator-invalid')
        if [r.get('case') for r in children]!=expected_ids or any(r.get('return_code')!=0 for r in children):
            raise ValueError('control-child-process-inventory-invalid')
        if check_pcm:
            for row in rows:
                item=row.get('retained_pcm');path=safe_retained_path(item.get('path'),root)
                if path.stat().st_size!=item.get('bytes') or sha(path)!=item.get('sha256'):
                    raise ValueError('control-pcm-missing-or-changed')
    controls_check=validate_control_evidence(receipt,bridge,root=root,
        ledger_path=ledger_path if ledger_path is not None else root/'evidence/phase6-repairs.json') if check_controls else None
    return {'pea_assertions':checks,'target_attempts':1,'capture_processes':1,'control_driver_processes':2,
            'control_native_children':12,'control_rows':12,'rec_processes':0,'control_evidence':controls_check}

def control_inputs():
    driver=ROOT/'tests/fixtures/phase4_game.py';scenario=json.loads((ROOT/'fixtures/independent-game-v2/scenario.json').read_text())
    paths=control_input_paths(scenario)
    return {p:sha(ROOT/p) for p in paths}

def control_input_paths(scenario=None):
    if scenario is None:scenario=json.loads((ROOT/'fixtures/independent-game-v2/scenario.json').read_text())
    return ['tests/fixtures/phase4_game.py','fixtures/independent-game-v2/scenario.json',
        'fixtures/independent-game-v2/oracle.json',scenario['source']['relative_path'],scenario['rom']['relative_path']]


def safe_retained_path(value, root=ROOT):
    if not isinstance(value,str) or pathlib.Path(value).is_absolute() or '..' in pathlib.Path(value).parts:
        raise ValueError('retained-path-not-relative-or-contains-traversal')
    path=root/value
    if path.is_symlink():raise ValueError('retained-path-symlink-denied')
    resolved=path.resolve(strict=True);resolved.relative_to(root.resolve(strict=True))
    if not resolved.is_file():raise ValueError('retained-path-not-file')
    return resolved

def retain_original_binaries():
    manifest=json.loads(MANIFEST.read_bytes())
    if manifest.get('status')!='verified-bounded-infrastructure' or manifest.get('review_status')!='approved':
        raise ValueError('historical-binary-manifest-not-approved')
    original_manifest_sha=sha(MANIFEST)
    successor=json.loads((ROOT/'evidence/phase6-stack-observation-manifest-d122.json').read_bytes())
    successor_builds={row['variant']:row for row in successor.get('builds',[])}
    rows=manifest.get('synthetic_process_rows',[])
    if len(rows)!=3 or {r.get('variant') for r in rows}!={'native','sanitize','hooks-off'}:
        raise ValueError('historical-binary-denominator-invalid')
    if ORIGINAL_BINARY_ROOT.is_symlink():raise ValueError('historical-binary-retention-root-symlink')
    ORIGINAL_BINARY_ROOT.mkdir(parents=True,exist_ok=True)
    records={}
    for row in rows:
        command=row.get('command');source=pathlib.Path(command[0])
        if not source.is_absolute():source=ROOT/source
        if source.is_symlink():raise ValueError('historical-binary-source-symlink:'+row.get('variant','?'))
        source=source.resolve(strict=True)
        source.relative_to(ROOT.resolve(strict=True))
        expected_output=ROOT/successor_builds[row['variant']]['directory']/'tools/session/gw_headless'
        if source!=expected_output.resolve(strict=True):
            raise ValueError('historical-binary-and-observer-output-path-mismatch:'+row['variant'])
        if source.is_symlink() or sha(source)!=row.get('client_sha256'):
            raise ValueError('historical-binary-current-source-mismatch:'+row.get('variant','?'))
        target=ORIGINAL_BINARY_ROOT/row['variant']/'gw_headless'
        target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists() or target.is_symlink():
            if target.is_symlink() or sha(target)!=row['client_sha256']:
                raise ValueError('historical-binary-retained-copy-conflict:'+row['variant'])
        else:shutil.copyfile(source,target)
        if sha(target)!=row['client_sha256']:raise ValueError('historical-binary-retained-copy-hash-mismatch:'+row['variant'])
        records[row['variant']]={'original_command_path':pathlib.Path(command[0]).as_posix(),
            'retained_path':target.relative_to(ROOT).as_posix(),'sha256':row['client_sha256'],
            'observer_output_path':expected_output.relative_to(ROOT).as_posix(),
            'size_bytes':target.stat().st_size,'command_sha256':_canonical_digest(command),
            'guest_sha256':row['guest_sha256'],'descriptor_sha256':row['plan_sha256']}
    if len({row['sha256'] for row in records.values()})!=3:raise ValueError('historical-binary-variants-not-distinct')
    document={'schema':'phase6-d122-original-binary-retention-v1','status':'preserved-before-observer-builds',
        'baseline_commit':BASELINE_COMMIT,'recovery_manifest_sha256':original_manifest_sha,
        'original_source_identity':manifest['source_identity'],'binaries':records}
    payload=json.dumps(document,indent=2,sort_keys=True)+'\n'
    if ORIGINAL_BINARY_MANIFEST.exists():
        if ORIGINAL_BINARY_MANIFEST.read_text()!=payload:raise ValueError('historical-binary-retention-manifest-conflict')
    else:ORIGINAL_BINARY_MANIFEST.write_text(payload)
    return {'path':ORIGINAL_BINARY_MANIFEST.relative_to(ROOT).as_posix(),'sha256':sha(ORIGINAL_BINARY_MANIFEST),
        'binary_sha256':{name:row['sha256'] for name,row in records.items()},'binaries':records,
        'recovery_manifest_sha256':original_manifest_sha}

def load_original_binary_retention(binding):
    if not isinstance(binding,dict):raise ValueError('historical-binary-retention-binding-missing')
    path=safe_retained_path(binding.get('path'),ROOT);raw=path.read_bytes()
    if sha_bytes(raw)!=binding.get('sha256'):raise ValueError('historical-binary-retention-manifest-hash-mismatch')
    document=json.loads(raw)
    if document.get('schema')!='phase6-d122-original-binary-retention-v1' or document.get('status')!='preserved-before-observer-builds' or \
       document.get('baseline_commit')!=BASELINE_COMMIT or document.get('recovery_manifest_sha256')!=sha(MANIFEST):
        raise ValueError('historical-binary-retention-manifest-invalid')
    historical={row['variant']:row for row in json.loads(MANIFEST.read_bytes()).get('synthetic_process_rows',[])}
    if set(document.get('binaries',{}))!={'native','sanitize','hooks-off'}:
        raise ValueError('historical-binary-retention-denominator-invalid')
    for variant,row in document.get('binaries',{}).items():
        binary=safe_retained_path(row.get('retained_path'),ROOT)
        source=historical[variant]
        successor=json.loads((ROOT/'evidence/phase6-stack-observation-manifest-d122.json').read_bytes())
        build=next(item for item in successor['builds'] if item['variant']==variant)
        expected_output=(ROOT/build['directory']/'tools/session/gw_headless').relative_to(ROOT).as_posix()
        if row.get('original_command_path')!=pathlib.Path(source['command'][0]).as_posix() or \
           row.get('observer_output_path')!=expected_output or \
           row.get('command_sha256')!=_canonical_digest(source['command']) or row.get('guest_sha256')!=source.get('guest_sha256') or \
           row.get('descriptor_sha256')!=source.get('plan_sha256') or row.get('sha256')!=source.get('client_sha256') or \
           sha(binary)!=row.get('sha256') or row.get('sha256')!=binding.get('binary_sha256',{}).get(variant):
            raise ValueError('historical-binary-retained-object-changed:'+variant)
    if len({row['sha256'] for row in document['binaries'].values()})!=3:
        raise ValueError('historical-binary-retained-variants-not-distinct')
    return document

def project_input_path(path):
    candidate=pathlib.Path(path);candidate=candidate if candidate.is_absolute() else ROOT/candidate
    if candidate.is_symlink():raise ValueError('project-input-symlink-denied')
    resolved=candidate.resolve(strict=True);resolved.relative_to(ROOT.resolve(strict=True))
    if not resolved.is_file():raise ValueError('project-input-not-file')
    return resolved


def _baseline_control_results(ledger):
    for record in reversed(ledger.get('records',[])):
        control=record.get('post_behavior',{}).get('unchanged_control')
        if isinstance(control,dict) and control.get('status')=='pass' and len(control.get('results',[]))==6:
            return control['results']
    raise ValueError('historical-six-case-control-baseline-missing')


def validate_control_evidence(receipt, bridge, *, root=ROOT, ledger_path=None):
    ledger_path=(root/'evidence/phase6-repairs.json') if ledger_path is None else pathlib.Path(ledger_path)
    ledger=json.loads(ledger_path.read_text())
    baseline=_baseline_control_results(ledger)
    scenario=json.loads((root/'fixtures/independent-game-v2/scenario.json').read_text())
    oracle=json.loads((root/'fixtures/independent-game-v2/oracle.json').read_text())
    ids=['title-no-start','start-idle','start-move','action-sound','action-no-trigger','sustained-play']
    if [row['id'] for row in scenario['cases']]!=ids or oracle.get('case_ids')!=ids:
        raise ValueError('original-six-case-order-oracle-changed')
    expected_by_id={row['id']:row for row in baseline}
    runs=receipt.get('controls')
    if not isinstance(runs,list) or len(runs)!=2:raise ValueError('control-driver-denominator-invalid')
    pcm_by_repeat=[];semantic_by_repeat=[];expected_client=bridge.get('control_client_binary_sha256')
    driver_hashes=control_inputs()
    for repeat,run in enumerate(runs,1):
        if run.get('repetition')!=repeat or run.get('status')!='pass' or run.get('cases')!=6:
            raise ValueError('control-driver-status-invalid')
        report_path=safe_retained_path(run.get('report_path'),root)
        if report_path.stat().st_size>8388608 or sha(report_path)!=run.get('report_sha256'):
            raise ValueError('control-report-hash-or-size-invalid')
        report=json.loads(report_path.read_bytes())
        if report.get('outcome')!='pass' or [r.get('id') for r in report.get('results',[])]!=ids:
            raise ValueError('control-report-order-or-outcome-invalid')
        driver=run.get('driver_process',{})
        if (driver.get('return_code')!=0 or driver.get('timed_out') is not False or driver.get('bound_violation') is not False or
                driver.get('executable_path')!='tests/fixtures/phase4_game.py' or
                driver.get('executable_sha256')!=driver_hashes['tests/fixtures/phase4_game.py'] or
                driver.get('client_path')!='build/phase6/tools/session/gw_headless' or
                driver.get('client_sha256')!=expected_client or not isinstance(driver.get('command_sha256'),str)):
            raise ValueError('control-driver-command-or-executable-identity-invalid')
        for stream in driver.get('streams',{}).values():
            raw=safe_retained_path(stream.get('path'),root).read_bytes()
            if len(raw)!=stream.get('retained_bytes') or hashlib.sha256(raw).hexdigest()!=stream.get('sha256') or stream.get('truncated'):
                raise ValueError('control-driver-stream-retention-invalid')
        children=run.get('native_child_processes');rows=run.get('results')
        if not isinstance(children,list) or [r.get('case') for r in children]!=ids:
            raise ValueError('control-child-process-inventory-invalid')
        if not isinstance(rows,list) or [r.get('id') for r in rows]!=ids:
            raise ValueError('control-six-case-denominator-or-order-invalid')
        semantics=[]
        for child,row in zip(children,rows):
            if (child.get('return_code')!=0 or child.get('executable_path')!=driver.get('client_path') or
                    child.get('executable_sha256')!=expected_client or not isinstance(child.get('command_sha256'),str)):
                raise ValueError('control-child-command-or-executable-invalid')
            streams=child.get('streams')
            if not isinstance(streams,dict) or set(streams)!={'stdout','stderr'}:
                raise ValueError('control-child-streams-missing')
            for stream in streams.values():
                raw=safe_retained_path(stream.get('path'),root).read_bytes()
                if len(raw)!=stream.get('retained_bytes') or hashlib.sha256(raw).hexdigest()!=stream.get('sha256') or stream.get('truncated'):
                    raise ValueError('control-child-stream-retention-invalid')
            wanted=expected_by_id.get(row['id'])
            if not isinstance(wanted,dict) or any(row.get(k)!=v for k,v in wanted.items()):
                raise ValueError('control-case-differs-from-original-baseline:'+row['id'])
            item=row.get('retained_pcm')
            pcm_path=safe_retained_path(item.get('path') if isinstance(item,dict) else None,root)
            pcm=pcm_path.read_bytes()
            if len(pcm)!=item.get('bytes') or hashlib.sha256(pcm).hexdigest()!=item.get('sha256'):
                raise ValueError('control-pcm-hash-or-size-invalid')
            if len(pcm)!=row.get('pcm_frames',-1)*4 or len(pcm)%2:
                raise ValueError('control-pcm-frame-denominator-invalid')
            samples=struct.unpack('<'+'h'*(len(pcm)//2),pcm)
            if (max(samples)-min(samples) if samples else 0)!=row.get('ac_range'):
                raise ValueError('control-pcm-waveform-disagrees')
            pcm_by_repeat.append((repeat,row['id'],pcm))
            semantics.append({k:row.get(k) for k in wanted})
        semantic_by_repeat.append(semantics)
    for first,second in zip(pcm_by_repeat[:6],pcm_by_repeat[6:]):
        if first[1]!=second[1] or first[2]!=second[2]:raise ValueError('control-full-pcm-repetitions-differ')
    if semantic_by_repeat[0]!=semantic_by_repeat[1]:raise ValueError('control-semantic-repetitions-differ')
    return {'driver_processes':2,'native_child_processes':12,'case_rows':12,'full_pcm_files':12,
        'full_pcm_repetitions_equal':True,'original_order':ids,
        'actionsound_before_no_trigger':ids.index('action-sound')<ids.index('action-no-trigger')}

def revalidate_proof(build,output,*,update_ledger=True,binary_retention=None):
    manifest_bytes=MANIFEST.read_bytes();manifest=json.loads(manifest_bytes)
    observer_builds={row['variant']:row for row in json.loads((ROOT/'evidence/phase6-stack-observation-manifest-d122.json').read_bytes())['builds']}
    if manifest.get('review_status')!='approved' or manifest.get('status')!='verified-bounded-infrastructure':raise ValueError('retained-proof-manifest-status-invalid')
    paths=source_paths(ROOT);old_identity=tree_source_identity(BASELINE_COMMIT,paths)
    if old_identity!=manifest.get('source_identity'):raise ValueError('recorded-prechange-source-identity-does-not-match-immutable-object')
    changed={}
    proof_old={}
    for name,wanted in manifest['proof_inputs_sha256'].items():
        old=git_blob(BASELINE_COMMIT,name);old_hash=sha_bytes(old);current=sha(ROOT/name)
        if old_hash!=wanted:raise ValueError('retained-proof-input-not-bound-to-prechange-object:'+name)
        proof_old[name]=old_hash
        if current!=old_hash:changed[name]={'before_sha256':old_hash,'after_sha256':current}
    source_map={}
    for name in paths:
        old_hash=sha_bytes(git_blob(BASELINE_COMMIT,name));current=sha(ROOT/name)
        if current!=old_hash:source_map[name]={'before_sha256':old_hash,'after_sha256':current}
    current_identity=current_source_identity()
    rows=[];report_hashes=set();binary_hashes={};descriptor_hashes={};guest_hashes={}
    for row in manifest['synthetic_process_rows']:
        if row.get('status')!='passed' or row.get('assertions')!=9 or row.get('fields')!=0 or row.get('new_target_attempts')!=0:
            raise ValueError('spent-retained-row-unusable:'+str(row.get('case')))
        proc=row.get('processes',[])
        if len(proc)!=1 or proc[0].get('bound_violation') or proc[0].get('return_code')!=1:raise ValueError('retained-process-row-invalid')
        validate_streams(proc[0],row.get('retained_streams'))
        report_path=ROOT/row['native_report_path'];raw=report_path.read_bytes();digest=sha_bytes(raw)
        if digest!=row.get('native_report_sha256'):raise ValueError('retained-raw-report-hash-mismatch')
        native=json.loads(raw);checks=validate_retained_synthetic(native)
        if len(checks)!=9:raise ValueError('retained-assertion-denominator-invalid')
        binary=ROOT/row['command'][0];guest=ROOT/row['command'][-1];descriptor=ROOT/row['command'][2]
        actual_binary=binary
        if binary_retention is not None:
            retained=binary_retention.get('binaries',{}).get(row['variant'])
            if not isinstance(retained,dict) or retained.get('original_command_path')!=pathlib.Path(row['command'][0]).as_posix() or \
               retained.get('command_sha256')!=_canonical_digest(row['command']):
                raise ValueError('historical-binary-retention-command-binding-invalid:'+row['variant'])
            actual_binary=safe_retained_path(retained.get('retained_path'),ROOT)
        if sha(actual_binary)!=row['client_sha256'] or sha(guest)!=row['guest_sha256'] or sha(descriptor)!=row['plan_sha256']:
            raise ValueError('retained-source-binary-guest-or-descriptor-drift')
        report_hashes.add(digest);binary_hashes[row['variant']]=row['client_sha256']
        descriptor_hashes[row['variant']]=row['plan_sha256'];guest_hashes[row['variant']]=row['guest_sha256']
        rows.append({'case':row['case'],'variant':row['variant'],'raw_report_sha256':digest,
                     'assertions':checks,'process_stream_sha256':{k:v['sha256'] for k,v in row['retained_streams'].items()}})
    if len(rows)!=3 or len(report_hashes)!=1:raise ValueError('retained-three-row-agreement-invalid')
    coordinator=load_module('tank_continuation_coordinator','tests/fixtures/phase6_repairs.py')
    route=next(r for r in coordinator.compiler.compile_routes()['routes'] if r['fixture']=='tank-battle' and r['case']['id']=='full-route')
    original,_=coordinator.compiler.lower_route(route);watched=coordinator.add_tank_pea_watches(original)
    descriptor_sha=sha_bytes(watched)
    watch_ranges=[{'name':name,'address':address,'bytes':2,'observation':'side-effect-free boundary memory span'} for name,address in WATCHES]
    phase4=control_inputs()
    historical_phase4={name:sha_bytes(git_blob(BASELINE_COMMIT,name)) for name in control_input_paths()}
    if len(set(binary_hashes.values())) != 3:
        raise ValueError('original-native-sanitize-hooks-off-binaries-not-distinct')
    artifact={'schema':'phase6-tank-proof-revalidation-v1','status':'passed-no-launch','base_commit':BASELINE_COMMIT,
       'old_source_identity':old_identity,'current_source_identity':current_identity,
       'source_changed_paths':source_map,'proof_input_changed_paths':changed,
       'retained_manifest_sha256':sha_bytes(manifest_bytes),'retained_reports':rows,
       'retained_report_common_sha256':next(iter(report_hashes)),
       'original_runtime_closure':{'variant_binaries':binary_hashes,'variant_binaries_distinct':True,
           'variant_binary_command_paths':{row['variant']:row['command'][0] for row in manifest['synthetic_process_rows']},
           'observer_output_paths':{variant:(ROOT/row['directory']/'tools/session/gw_headless').relative_to(ROOT).as_posix()
               for variant,row in observer_builds.items()},
           'retained_historical_binary_paths':{name:item['retained_path'] for name,item in (binary_retention or {}).get('binaries',{}).items()},
           'descriptors':descriptor_hashes,'guests':guest_hashes,
           'common_raw_reports':True,'fixture_and_D118_authority_unchanged':True},
       'tank_capture_descriptor_sha256':descriptor_sha,
       'tank_capture_descriptor_bytes':len(watched),'watched_ranges':watch_ranges,
       'control_driver_inputs':phase4,'historical_control_driver_inputs':historical_phase4,
       'control_client_binary_sha256':sha(build/'tools/session/gw_headless'),
       'offline_authorization_proof':{'required_commands':['python3 -I tests/evidence/phase6_accounting_contract.py',
          'python3 -I tests/fixtures/phase6_repairs.py --tank-continuation-offline'],
          'executed_in_this_artifact':False,'test_contract_sha256':sha(ROOT/'tests/evidence/phase6_accounting_contract.py'),
          'coordinator_sha256':sha(ROOT/'tests/fixtures/phase6_repairs.py')},
       'verifier_sha256':sha(pathlib.Path(__file__)),'launches':0,'new_target_attempts':0,
       'historical_11_status':'halted-immutable','plan12_unblocked':False}
    artifact['native_binary_sha256']=binary_hashes['native']
    artifact['capture_descriptor_sha256']=descriptor_sha
    artifact['bridge_sha256']=sha_bytes(json.dumps(artifact,sort_keys=True,separators=(',',':')).encode())
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(artifact,indent=2,sort_keys=True)+'\n')
    if update_ledger:
        accounting=load_module('bridge_accounting','scripts/evidence/phase6_accounting.py')
        with accounting._locked(LEDGER):
            ledger=accounting._load(LEDGER,ROOT)
            ledger['tank_proof_revalidation']={'status':'passed','source_identity':current_identity,
              'binary_identity':binary_hashes['native'],'contract_identity':artifact['bridge_sha256'],
              'bridge_sha256':artifact['bridge_sha256'],'capture_descriptor_sha256':descriptor_sha,
              'verifier_sha256':artifact['verifier_sha256'],'checked_at':__import__('datetime').datetime.now().astimezone().isoformat()}
            accounting._write(LEDGER,ledger)
    return artifact


def _canonical_digest(value):
    return sha_bytes(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())


def _observer_manifest_and_rows(proof_rows_path, *, root=ROOT):
    manifest_path=root/'evidence/phase6-stack-observation-manifest-d122.json'
    original_path=root/'evidence/phase6-stack-observation-manifest.json'
    if sha(original_path)!='d8821aca38b898c81dbb6c1ce490d10792526f486081a6f8b95c717726737e23':
        raise ValueError('historical-observer-manifest-mutated')
    manifest=json.loads(manifest_path.read_bytes())
    if manifest.get('schema')!='genewhip-phase6-stack-observation-d122-v1' or manifest.get('status')!='authored-unlaunched':
        raise ValueError('d122-successor-manifest-status-invalid')
    rows_doc=json.loads(proof_rows_path.read_bytes())
    if rows_doc.get('schema')!='phase6-d122-observer-proof-rows-v1' or rows_doc.get('status')!='passed-three-rows':
        raise ValueError('actual-observer-proof-rows-not-complete')
    manifest_hash=sha(manifest_path)
    if rows_doc.get('manifest_sha256')!=manifest_hash or rows_doc.get('source_identity')!=current_source_identity():
        raise ValueError('actual-observer-manifest-or-source-identity-mismatch')
    expected_ids=['stack-observer-native-1','stack-observer-sanitize-1','stack-observer-hooks-off-1']
    cases={row['purpose_id']:row for row in manifest.get('cases',[])}
    proofs=rows_doc.get('proofs')
    if not isinstance(proofs,list) or [row.get('purpose_id') for row in proofs]!=expected_ids:
        raise ValueError('observer-proof-purpose-denominator-or-order-invalid')
    result=[]
    old_manifest=json.loads(original_path.read_bytes())
    historical_binaries={row['variant']:row['client_sha256'] for row in
        json.loads((root/'evidence/phase6-capture-recovery.json').read_text())['synthetic_process_rows']}
    build_rows=rows_doc.get('builds')
    expected_builds={row['variant']:row['command'] for row in manifest.get('builds',[])}
    frozen=json.loads((root/'evidence/phase6-repairs.json').read_text()).get('d122_successor_manifest',{})
    tool_identity=frozen.get('tool_identity',{})
    if frozen.get('status')!='frozen' or frozen.get('sha256')!=manifest_hash or not tool_identity:
        raise ValueError('observer-frozen-tool-identity-missing')
    if not isinstance(build_rows,list) or len(build_rows)!=3 or {r.get('variant') for r in build_rows}!=set(expected_builds):
        raise ValueError('observer-build-denominator-invalid')
    for build_row in build_rows:
        if build_row.get('command')!=expected_builds[build_row['variant']] or build_row.get('return_code')!=0 or build_row.get('timed_out') is not False or build_row.get('bound_violation') is not False or \
           not isinstance(build_row.get('wall_seconds'),(int,float)) or build_row['wall_seconds']>300 or \
           any(not isinstance(build_row.get('streams',{}).get(name),dict) or build_row['streams'][name].get('truncated') for name in ('stdout','stderr')):
            raise ValueError('observer-build-command-or-result-invalid:'+str(build_row.get('variant')))
        if build_row.get('executable_sha256')!=tool_identity.get('cmake_sha256'):
            raise ValueError('observer-build-tool-identity-differs-from-freeze:'+build_row['variant'])
        for stream in build_row['streams'].values():
            path=safe_retained_path(stream.get('path'),root);raw=path.read_bytes()
            if len(raw)!=stream.get('retained_bytes') or sha_bytes(raw)!=stream.get('sha256') or stream.get('truncated'):
                raise ValueError('observer-build-stream-retention-invalid:'+build_row['variant'])
    if sum(row['wall_seconds'] for row in build_rows)>300:
        raise ValueError('observer-build-aggregate-watchdog-exceeded')
    for proof in proofs:
        purpose=proof['purpose_id'];case=cases[purpose]
        variant={'stack-observer-native-1':'native','stack-observer-sanitize-1':'sanitize',
                 'stack-observer-hooks-off-1':'hooks-off'}[purpose]
        command=proof.get('command')
        if not isinstance(command,list) or len(command)!=10 or proof.get('command_sha256')!=sha_bytes(json.dumps(command,separators=(',',':')).encode()):
            raise ValueError('observer-command-identity-invalid:'+purpose)
        # Recorded argv may be absolute in the private build receipt. Rebase only
        # paths proven to lie under the project before they enter public evidence.
        raw_client=pathlib.Path(command[0])
        if raw_client.is_absolute():raw_client.resolve(strict=True).relative_to(root.resolve(strict=True))
        client_path=raw_client.resolve(strict=True)
        if sha(client_path)!=proof.get('binary_sha256'):
            raise ValueError('observer-current-binary-hash-mismatch:'+purpose)
        if sha(client_path)==historical_binaries.get(variant):
            raise ValueError('observer-binary-not-distinct-from-historical-proof:'+purpose)
        guest_path=pathlib.Path(command[1])
        if guest_path.is_absolute():guest_path.resolve(strict=True).relative_to(root.resolve(strict=True))
        guest_path=guest_path.resolve(strict=True)
        if command[2]!='--route-plan' or command[4]!='--route-report' or command[6]!='--route-instruction-probe' or \
           command[8:]!=['--route-probe-only','--route-probe-stack-before-a7']:
            raise ValueError('observer-command-flags-invalid:'+purpose)
        plan_index=command.index('--route-plan')+1
        descriptor_path=pathlib.Path(command[plan_index])
        if descriptor_path.is_absolute():descriptor_path.resolve(strict=True).relative_to(root.resolve(strict=True))
        descriptor_path=descriptor_path.resolve(strict=True)
        expected_build=next(row for row in manifest['builds'] if row['variant']==variant)
        expected_client=(root/expected_build['directory']/'tools/session/gw_headless').resolve(strict=True)
        expected_prefix=root/'build/phase6/d122-observer'
        expected_guest=expected_prefix/f'{purpose}.rom';expected_descriptor=expected_prefix/f'{purpose}.route'
        expected_report=expected_prefix/f'{purpose}.report.json'
        report_arg=pathlib.Path(command[5])
        if report_arg.is_absolute():report_arg.resolve(strict=False).relative_to(root.resolve(strict=True))
        expected_command=[str(client_path),str(guest_path),'--route-plan',str(descriptor_path),'--route-report',command[5],
            '--route-instruction-probe',str(case['probe_pc']),'--route-probe-only','--route-probe-stack-before-a7']
        if client_path!=expected_client or command!=expected_command or guest_path!=expected_guest or \
           descriptor_path!=expected_descriptor or report_arg.resolve(strict=False)!=expected_report.resolve(strict=False) or \
           sha_bytes(bytes.fromhex(case['guest_bytes_hex']))!=proof.get('guest_sha256') or sha(guest_path)!=proof.get('guest_sha256') or \
           sha_bytes(bytes.fromhex(case['descriptor_bytes_hex']))!=proof.get('descriptor_sha256') or sha(descriptor_path)!=proof.get('descriptor_sha256'):
            raise ValueError('observer-guest-or-descriptor-hash-mismatch:'+purpose)
        report_path=safe_retained_path(proof.get('report_path'),root)
        raw=report_path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=proof.get('report_sha256'):
            raise ValueError('observer-raw-report-hash-mismatch:'+purpose)
        report=json.loads(raw)
        stack=load_module('observer_stack_contract','tests/evidence/phase6_stack_observation_contract.py')
        checks=stack._validate_observation_report(case,report)
        if checks!=proof.get('checks'):
            raise ValueError('observer-checker-result-mismatch:'+purpose)
        process=proof.get('process',{})
        executable_path=pathlib.Path(process.get('executable_path','')).resolve(strict=True)
        if process.get('return_code')!=0 or process.get('timed_out') is not False or process.get('bound_violation') is not False or \
           process.get('wall_seconds',999)>30 or executable_path!=client_path or process.get('executable_sha256')!=proof.get('binary_sha256'):
            raise ValueError('observer-proof-process-result-invalid:'+purpose)
        streams={}
        for name,stream in process.get('streams',{}).items():
            path=safe_retained_path(stream.get('path'),root);data=path.read_bytes()
            if len(data)!=stream.get('retained_bytes') or sha_bytes(data)!=stream.get('sha256') or stream.get('truncated'):
                raise ValueError('observer-proof-stream-retention-invalid:'+purpose)
            streams[name]={"path":stream['path'],"sha256":stream['sha256'],"bytes":len(data)}
        if set(streams)!={'stdout','stderr'}:
            raise ValueError('observer-proof-stream-denominator-invalid:'+purpose)
        result.append({'purpose_id':purpose,'status':'observer-row-passed',
            'variant':variant,'binary_path':client_path.relative_to(root).as_posix(),
            'binary_sha256':proof['binary_sha256'],'historical_binary_sha256':historical_binaries[variant],
            'guest_path':guest_path.relative_to(root).as_posix(),'guest_sha256':proof['guest_sha256'],
            'descriptor_path':descriptor_path.relative_to(root).as_posix(),'descriptor_sha256':proof['descriptor_sha256'],
            'command_sha256':proof.get('command_sha256'),'command_template':['gw_headless','<guest>',
                '--route-plan','<descriptor>','--route-report','<report>','--route-instruction-probe',
                str(case['probe_pc']),'--route-probe-only','--route-probe-stack-before-a7'],
            'report_path':proof['report_path'],'report_sha256':proof['report_sha256'],
            'process_wall_seconds':process['wall_seconds'],'process_streams':streams,'assertions':checks})
    if sum(row['process_wall_seconds'] for row in result)>90 or rows_doc.get('launches')!=6 or rows_doc.get('target_attempts')!=0:
        raise ValueError('observer-proof-aggregate-or-launch-denominator-invalid')
    return manifest,rows_doc,result


def create_observer_bridge(build,proof_rows_path,output_path):
    build=pathlib.Path(build).resolve(strict=True);build.relative_to(ROOT.resolve(strict=True))
    proof_rows_path=pathlib.Path(proof_rows_path);proof_rows_path=proof_rows_path if proof_rows_path.is_absolute() else ROOT/proof_rows_path
    proof_rows_path=safe_retained_path(proof_rows_path.relative_to(ROOT).as_posix(),ROOT)
    output_path=pathlib.Path(output_path);output_path=output_path if output_path.is_absolute() else ROOT/output_path
    output_path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    if output_path.exists() or output_path.is_symlink():raise ValueError('observer-bridge-output-already-exists-or-symlink')
    ledger_data=json.loads(LEDGER.read_text())
    frozen=ledger_data.get('d122_successor_manifest',{})
    retention=load_original_binary_retention(frozen.get('original_binary_retention'))
    temp_root=ROOT/'build/phase6/d122-observer'
    temp_root.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='original-proof-closure-',dir=temp_root) as temporary:
        original=revalidate_proof(build,pathlib.Path(temporary)/'original-closure.json',update_ledger=False,binary_retention=retention)
    if original.get('status')!='passed-no-launch' or len(original.get('retained_reports',[]))!=3:
        raise ValueError('original-semantic-proof-closure-invalid')
    original_manifest=json.loads((ROOT/'evidence/phase6-capture-recovery.json').read_text())
    original_assertion_count=sum(len(row.get('assertions',{})) for row in original['retained_reports'])
    if len(original_manifest.get('proof_inputs_sha256',{}))!=10 or original_assertion_count!=27 or \
       any(len(row.get('assertions',{}))!=9 for row in original['retained_reports']):
        raise ValueError('original-semantic-proof-input-or-assertion-denominator-invalid')
    manifest,proof_rows,observer_rows=_observer_manifest_and_rows(proof_rows_path)
    if original['current_source_identity']!=proof_rows['source_identity']:
        raise ValueError('original-and-observer-source-binding-disagree')
    allowed_changed={'tools/session/route_controller.c','scripts/evidence/phase6_accounting.py',
        'tests/fixtures/phase6_repairs.py','tests/fixtures/phase4_game.py'}
    unexpected=set(original.get('source_changed_paths',{}))-allowed_changed
    changed_set=set(original.get('source_changed_paths',{}))
    if unexpected or changed_set!=allowed_changed:
        raise ValueError('unapproved-or-incomplete-current-source-change-set:'+','.join(sorted(unexpected or (allowed_changed-changed_set))))
    extra_sources=['tests/evidence/phase6_stack_observation_contract.py',
        'tests/evidence/phase6_tank_continuation_contract.py','tests/evidence/phase6_accounting_contract.py',
        'tests/fixtures/phase4_game.py']
    extra={name:sha(ROOT/name) for name in extra_sources}
    approval=ledger_data.get('d122_recovery_exception',{})
    tool_identity=frozen.get('tool_identity',{})
    if frozen.get('status')!='frozen' or not tool_identity:raise ValueError('d122-build-tool-freeze-missing')
    public_tools={'cmake_sha256':tool_identity.get('cmake_sha256'),
        'builds':{variant:{'cache_sha256':entry.get('cache_sha256'),
            'compiler_name':pathlib.Path(entry.get('compiler_path','')).name,
            'compiler_sha256':entry.get('compiler_sha256'),
            'build_tool_name':pathlib.Path(entry.get('build_tool_path','')).name,
            'build_tool_sha256':entry.get('build_tool_sha256'),'settings':entry.get('settings'),
            'command':entry.get('command')} for variant,entry in tool_identity.get('builds',{}).items()}}
    d122={key:approval.get(key) for key in ('approval_context_sha256','plan_check_sha256',
        'historical_global_floor_seconds','historical_pea_floor_seconds','historical_offline_seconds',
        'historical_offline_limit_seconds','partitions','effective_pea_cap_seconds','global_cap_seconds')}
    source_path_set=source_paths(ROOT)
    current_path_hashes={name:sha(ROOT/name) for name in source_path_set}
    bridge={'schema':'phase6-tank-observer-bridge-v1','status':'passed-observer-bridge-no-launch',
        'd122':d122,'historical_17_summary_sha256':'8526d3c3cc139e51258d3141a0ceeb448bbc15d69ebeecdd291703b5bfbd7f89',
        'original_observer_manifest_sha256':'d8821aca38b898c81dbb6c1ce490d10792526f486081a6f8b95c717726737e23',
        'successor_manifest_path':'evidence/phase6-stack-observation-manifest-d122.json',
        'successor_manifest_sha256':sha(ROOT/'evidence/phase6-stack-observation-manifest-d122.json'),
        'native_binary_sha256':sha(build/'tools/session/gw_headless'),
        'control_client_binary_sha256':sha(build/'tools/session/gw_headless'),
        'capture_descriptor_sha256':original['tank_capture_descriptor_sha256'],
        'original_semantic_closure':{'base_revision':original['base_commit'],
            'old_source_identity':original['old_source_identity'],'original_path_count':len(source_path_set),
            'original_proof_input_paths':sorted(original_manifest['proof_inputs_sha256']),
            'original_proof_input_sha256':original_manifest['proof_inputs_sha256'],
            'original_proof_input_count':len(original_manifest['proof_inputs_sha256']),
            'original_assertion_count':original_assertion_count,
            'retained_manifest_sha256':original['retained_manifest_sha256'],
            'historical_binary_retention':frozen['original_binary_retention'],
            'retained_reports':original['retained_reports'],
            'original_runtime_closure':original['original_runtime_closure'],
            'historical_control_inputs':original['historical_control_driver_inputs'],
            'current_control_inputs':original['control_driver_inputs'],
            'source_changed_paths':original['source_changed_paths'],
            'historical_fixture_and_oracle_hashes':original['control_driver_inputs']},
        'current_source_closure':{'source_identity':original['current_source_identity'],
            'path_set':source_path_set,'path_sha256':current_path_hashes,'extra_harness_source_sha256':extra,
            'allowed_changed_paths':sorted(allowed_changed)},
        'observer_transition':{'observer_rows':observer_rows,'builds':[
            {'variant':row['variant'],'command':row['command'],'return_code':row['return_code'],
             'executable_sha256':row['executable_sha256'],'wall_seconds':row['wall_seconds'],
             'streams':{name:{'path':stream['path'],'sha256':stream['sha256'],
                'retained_bytes':stream['retained_bytes']} for name,stream in row['streams'].items()}}
            for row in proof_rows['builds']],
            'build_count':len(proof_rows['builds']),'proof_count':len(observer_rows),
            'launches':proof_rows['launches'],'target_attempts':0},
        'build_tool_identity':public_tools,
        'real_tank_runtime_a7':'unknown until 06-14; observer rows do not prove Tank capture',
        'downstream_authority':{'accepted_independent_review_required':True,
            'bridge_hash_excludes_review':True,'plan12_authorized':False,'phase7_authorized':False}}
    bridge['bridge_sha256']=_canonical_digest(bridge)
    output_path.parent.mkdir(parents=True,exist_ok=True)
    output_path.write_text(json.dumps(bridge,indent=2,sort_keys=True)+'\n')
    with load_module('observer_bridge_accounting','scripts/evidence/phase6_accounting.py')._locked(LEDGER):
        accounting=load_module('observer_bridge_accounting_write','scripts/evidence/phase6_accounting.py')
        value=accounting._load(LEDGER,ROOT)
        if value.get('d122_observer_bridge') is not None:raise ValueError('d122-observer-bridge-already-bound')
        value['d122_observer_bridge']={'status':'bridge-built-review-pending',
            'path':output_path.relative_to(ROOT).as_posix(),'bridge_sha256':bridge['bridge_sha256'],
            'source_identity':original['current_source_identity'],'proof_count':3}
        accounting._write(LEDGER,value)
    return bridge

def create_d123_observer_bridge(build,manifest_path,qualification_path,output_path):
    """Create a new D123 bridge from the frozen manifest and independently recomputed rows."""
    build=pathlib.Path(build);build=build if build.is_absolute() else ROOT/build
    build=build.resolve(strict=True);build.relative_to(ROOT.resolve(strict=True))
    manifest_path=pathlib.Path(manifest_path);manifest_path=manifest_path if manifest_path.is_absolute() else ROOT/manifest_path
    manifest_path=project_input_path(manifest_path)
    qualification_path=pathlib.Path(qualification_path);qualification_path=qualification_path if qualification_path.is_absolute() else ROOT/qualification_path
    qualification_path=project_input_path(qualification_path)
    output_path=pathlib.Path(output_path);output_path=output_path if output_path.is_absolute() else ROOT/output_path
    output_path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    if output_path.exists() or output_path.is_symlink():raise ValueError('d123-observer-bridge-output-exists-or-symlink')
    manifest=json.loads(manifest_path.read_bytes());qualification=json.loads(qualification_path.read_bytes())
    if manifest.get('schema')!='phase6-d123-stack-observation-manifest-v1' or manifest.get('status')!='frozen':
        raise ValueError('d123-manifest-not-frozen')
    ledger=load_module('d123_bridge_accounting','scripts/evidence/phase6_accounting.py')._load(LEDGER,ROOT)
    frozen=ledger.get('d123_observer_manifest',{})
    manifest_sha=sha(manifest_path);source=current_source_identity();producer_source=manifest.get('source_identity')
    if frozen.get('status')!='frozen' or frozen.get('sha256')!=manifest_sha or frozen.get('source_identity')!=producer_source:
        raise ValueError('d123-manifest-ledger-binding-mismatch')
    if qualification.get('schema')!='phase6-d123-qualification-v1' or qualification.get('status')!='passed-three-rows' or \
            qualification.get('manifest_sha256')!=manifest_sha or [r.get('variant') for r in qualification.get('rows',[])]!=['native','sanitize','hooks-off']:
        raise ValueError('d123-qualification-denominator-or-manifest-binding-invalid')
    producer_components=manifest.get('component_sha256',{})
    if not producer_components:raise ValueError('d123-frozen-component-map-missing')
    components=dict(producer_components);changed=[]
    for name,old_digest in producer_components.items():
        actual=sha(ROOT/name)
        if actual!=old_digest:
            if name!='tests/evidence/phase6_tank_continuation_contract.py':
                raise ValueError('d123-non-validator-component-drift:'+name)
            changed.append({'path':name,'producer_sha256':old_digest,'current_sha256':actual,
                'classification':'validator-only-fix','disposition_required':'independent-review'})
            components[name]=actual
    for name in components:
        if sha(ROOT/name)!=components[name]:raise ValueError('d123-current-component-drift:'+name)
    if changed and len(changed)!=1:raise ValueError('d123-validator-delta-denominator-invalid')
    proof_loader=load_module('d123_original_binary_loader','tests/evidence/phase6_tank_continuation_contract.py')
    d122_frozen=ledger.get('d122_successor_manifest',{})
    retention=proof_loader.load_original_binary_retention(d122_frozen.get('original_binary_retention'))
    with tempfile.TemporaryDirectory(prefix='d123-original-semantic-',dir=ROOT/'build/phase6/d123-observer') as temporary:
        original=proof_loader.revalidate_proof(build,pathlib.Path(temporary)/'original.json',
            update_ledger=False,binary_retention=retention)
    if original.get('status')!='passed-no-launch' or original.get('original_runtime_closure',{}).get('variant_binaries_distinct') is not True:
        raise ValueError('d123-original-semantic-closure-invalid')
    for row in qualification['rows']:
        case=next((item for item in manifest['cases'] if item.get('variant')==row.get('variant')),None)
        build_row=next((item for item in manifest['builds'] if item.get('variant')==row.get('variant')),None)
        raw=safe_retained_path(row.get('raw_report_path'),ROOT)
        report=json.loads(raw.read_bytes())
        checks=load_module('d123_result_recompute','tests/evidence/phase6_stack_observation_contract.py')._validate_observation_report(
            {'expected':case['expected']},report)
        if row.get('kind')!='qualification' or row.get('status')!='passed' or row.get('source_identity')!=producer_source or \
           row.get('purpose_id')!=case.get('purpose_id') or row.get('binary_sha256')!=build_row.get('binary_sha256') or \
           row.get('guest_sha256')!=case.get('guest_sha256') or row.get('descriptor_sha256')!=case.get('descriptor_sha256') or \
           sha(raw)!=row.get('raw_report_sha256') or checks!=row.get('checks'):
            raise ValueError('d123-independent-qualification-row-invalid:'+str(row.get('variant')))
    client=build/'tools/session/gw_headless'
    bridge={'schema':'phase6-tank-observer-bridge-d123-v1','status':'passed-observer-bridge-no-launch',
        'manifest_path':manifest_path.relative_to(ROOT).as_posix(),'manifest_sha256':manifest_sha,
        'qualification_path':qualification_path.relative_to(ROOT).as_posix(),
        'qualification_sha256':sha(qualification_path),'producer_source_identity':producer_source,'source_identity':source,
        'native_binary_sha256':sha(client),'control_client_binary_sha256':sha(client),
        'capture_descriptor_sha256':next(row['descriptor_sha256'] for row in manifest['cases'] if row['variant']=='native'),
        'current_source_closure':{'source_identity':source,'component_sha256':components},
        'component_revalidation':{'status':'pending-independent-review' if changed else 'unchanged',
            'classification':'validator-only' if changed else 'none','changes':changed,
            'runtime_input_oracle_build_closure_unchanged':True,'raw_qualification_outputs_complete':True,
            'prior_verdict_preserved':True},
        'original_semantic_closure':original,
        'original_semantic_closure_sha256':_canonical_digest(original),
        'development_rows_excluded':True,'qualification_rows':qualification['rows'],
        'build_tool_identity':manifest.get('tool_identity'),
        'real_tank_runtime_a7':'unknown until 06-14; observer rows do not prove Tank capture',
        'downstream_authority':{'accepted_independent_review_required':True,'bridge_hash_excludes_review':True,
            'plan12_authorized':False,'phase7_authorized':False}}
    bridge['bridge_sha256']=_canonical_digest(bridge)
    output_path.parent.mkdir(parents=True,exist_ok=True);output_path.write_text(json.dumps(bridge,indent=2,sort_keys=True)+'\n')
    accounting=load_module('d123_bridge_writer_accounting','scripts/evidence/phase6_accounting.py')
    with accounting._locked(LEDGER):
        current=accounting._load(LEDGER,ROOT)
        prior=current.get('d123_observer_bridge')
        if prior is not None:
            history=current.setdefault('d123_observer_bridge_history',[])
            history.append({**prior,'superseded_by':output_path.relative_to(ROOT).as_posix(),
                'supersession_reason':'versioned bridge after validator-only checker correction'})
        current['d123_observer_bridge']={'status':'bridge-built-review-pending',
            'path':output_path.relative_to(ROOT).as_posix(),'bridge_sha256':bridge['bridge_sha256'],
            'source_identity':source,'producer_source_identity':producer_source,
            'manifest_sha256':manifest_sha,'qualification_sha256':bridge['qualification_sha256']}
        accounting._write(LEDGER,current)
    return bridge

D125_PRIOR_REVISION='5a80176'


def _d125_component_map():
    stack=load_module('d125_component_map','tests/evidence/phase6_stack_observation_contract.py')
    accounting=load_module('d125_component_identity','scripts/evidence/phase6_accounting.py')
    result=stack._d123_current_component_map(accounting)
    for name in ('scripts/evidence/phase6_routes.py','tests/session/phase6_route_contract.py',
                 'tests/evidence/phase6_d125_consumers_contract.py','tests/evidence/phase6_d125_authored_fixture.py',
                 'tests/evidence/phase6_d124_consumers_contract.py'):
        result[name]=sha(ROOT/name)
    return dict(sorted(result.items()))


def _d125_old_components(prior,current):
    old=dict(prior['current_source_closure']['component_sha256'])
    # Extra consumers were absent from the old component inventory. Bind their
    # actual accepted19 repository bytes explicitly, without inventing equality.
    for name in set(current)-set(old):
        try:old[name]=sha_bytes(git_blob(D125_PRIOR_REVISION,name))
        except subprocess.CalledProcessError:
            # New authored-only diagnostic files genuinely did not exist at19.
            if name not in ('tests/evidence/phase6_d125_consumers_contract.py','tests/evidence/phase6_d125_authored_fixture.py',
                            'tests/evidence/phase6_d124_consumers_contract.py'):raise
            old[name]='absent-at-accepted19'
    if set(old)!=set(current):raise ValueError('d125-component-denominator-changed')
    return dict(sorted(old.items()))


def _d125_raw_closure(prior,build):
    """Recompute the complete retained3-row and original-proof denominator."""
    build=pathlib.Path(build);build=build if build.is_absolute() else ROOT/build
    manifest_path=project_input_path(prior['manifest_path']);manifest=json.loads(manifest_path.read_bytes())
    qualification_path=project_input_path(prior['qualification_path']);qualification=json.loads(qualification_path.read_bytes())
    if sha(manifest_path)!=prior['manifest_sha256'] or sha(qualification_path)!=prior['qualification_sha256']:
        raise ValueError('d125-retained-manifest-or-qualification-drift')
    rows=qualification.get('rows',[])
    if (qualification.get('status')!='passed-three-rows' or [r.get('variant') for r in rows]!=['native','sanitize','hooks-off'] or
            qualification.get('manifest_sha256')!=prior['manifest_sha256']):
        raise ValueError('d125-retained-three-row-denominator-invalid')
    stack=load_module('d125_retained_stack','tests/evidence/phase6_stack_observation_contract.py')
    cases={r['variant']:r for r in manifest['cases']};builds={r['variant']:r for r in manifest['builds']}
    retained={manifest_path.relative_to(ROOT).as_posix():sha(manifest_path),qualification_path.relative_to(ROOT).as_posix():sha(qualification_path)}
    tools=manifest['tool_identity'];cmake=shutil.which(tools.get('cmake_name','cmake'))
    if not cmake or sha(pathlib.Path(cmake))!=tools['cmake_sha256']:raise ValueError('d125-cmake-identity-drift')
    external_tools={pathlib.Path(cmake).name:sha(pathlib.Path(cmake))}
    for variant,record in builds.items():
        cache=ROOT/record['directory']/'CMakeCache.txt';binary=safe_retained_path(record['binary_path'],ROOT)
        settings={line.split('=',1)[0].split(':',1)[0]:line.split('=',1)[1] for line in cache.read_text().splitlines() if '=' in line and ':' in line}
        if sha(cache)!=record['cache_sha256'] or sha(binary)!=record['binary_sha256']:
            raise ValueError('d125-retained-build-cache-or-binary-drift:'+variant)
        for name,key in (('CMAKE_C_COMPILER','compiler_sha256'),('CMAKE_MAKE_PROGRAM','build_tool_sha256')):
            tool=pathlib.Path(settings[name])
            if sha(tool)!=record[key]:raise ValueError('d125-retained-build-tool-drift:'+variant)
            external_tools[variant+':'+name]=sha(tool)
        if any(settings.get(name)!=value for name,value in record['settings'].items()):
            raise ValueError('d125-retained-build-settings-drift:'+variant)
        retained[cache.relative_to(ROOT).as_posix()]=sha(cache);retained[binary.relative_to(ROOT).as_posix()]=sha(binary)
    for row in rows:
        variant=row['variant'];case=cases[variant];record=builds[variant]
        raw=safe_retained_path(row['raw_report_path'],ROOT)
        if (row.get('kind')!='qualification' or row.get('status')!='passed' or row.get('purpose_id')!=case['purpose_id'] or
                row.get('source_identity')!=prior['producer_source_identity'] or row.get('binary_sha256')!=record['binary_sha256'] or
                row.get('guest_sha256')!=case['guest_sha256'] or row.get('descriptor_sha256')!=case['descriptor_sha256'] or
                sha(raw)!=row['raw_report_sha256'] or stack._validate_observation_report({'expected':case['expected']},json.loads(raw.read_bytes()))!=row['checks']):
            raise ValueError('d125-retained-row-identity-or-semantic-drift:'+variant)
        if (type(row.get('process_return_code')) is not int or row['process_return_code']!=0 or
                row.get('timed_out') is not False or row.get('bound_violation') is not False or
                row.get('oracle_sha256')!=sha_bytes(json.dumps(case['expected'],sort_keys=True).encode())):
            raise ValueError('d125-retained-process-or-oracle-invalid:'+variant)
        command=row['command'];guest=safe_retained_path(command[1],ROOT);descriptor=safe_retained_path(command[3],ROOT)
        expected=[record['binary_path']]+[{'<guest>':command[1],'<descriptor>':command[3],'<report>':row['raw_report_path']}.get(token,token)
            for token in case['command_suffix']]
        if (command!=expected or guest.read_bytes()!=bytes.fromhex(case['guest_bytes_hex']) or guest.stat().st_size>1024 or
                sha(guest)!=case['guest_sha256'] or descriptor.read_bytes()!=bytes.fromhex(case['descriptor_bytes_hex']) or
                sha(descriptor)!=case['descriptor_sha256']):
            raise ValueError('d125-retained-command-guest-descriptor-flags-invalid:'+variant)
        for retained_path in (guest,descriptor):retained[retained_path.relative_to(ROOT).as_posix()]=sha(retained_path)
        run_path=safe_retained_path((raw.parent/'run.json').relative_to(ROOT).as_posix(),ROOT)
        run=json.loads(run_path.read_bytes());process=run.get('process',{})
        if (run.get('command')!=command or run.get('raw_report_sha256')!=row['raw_report_sha256'] or
                process.get('command')!=command or process.get('executable_sha256')!=record['binary_sha256'] or
                process.get('return_code')!=0 or process.get('timed_out') is not False or process.get('bound_violation') is not False or
                type(process.get('wall_seconds')) not in (int,float) or not 0<=process['wall_seconds']<=30 or
                process.get('streams')!=row['process_streams']):
            raise ValueError('d125-retained-full-process-record-invalid:'+variant)
        retained[run_path.relative_to(ROOT).as_posix()]=sha(run_path)
        if set(row.get('process_streams',{}))!={'stdout','stderr'}:raise ValueError('d125-retained-stream-denominator-invalid')
        retained[raw.relative_to(ROOT).as_posix()]=sha(raw)
        for item in row['process_streams'].values():
            path=safe_retained_path(item['path'],ROOT);data=path.read_bytes()
            if len(data)!=item['retained_bytes'] or sha_bytes(data)!=item['sha256'] or item['truncated']:
                raise ValueError('d125-retained-stream-drift:'+variant)
            retained[path.relative_to(ROOT).as_posix()]=sha(path)
    ledger=json.loads(LEDGER.read_bytes())
    retention=load_original_binary_retention(ledger.get('d122_successor_manifest',{}).get('original_binary_retention'))
    parent=ROOT/'build/phase6/d123-observer';parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='d125-original-recompute-',dir=parent) as temporary:
        original=revalidate_proof(build,pathlib.Path(temporary)/'original.json',update_ledger=False,binary_retention=retention)
    old=prior['original_semantic_closure']
    variable={'bridge_sha256','current_source_identity','verifier_sha256','source_changed_paths','proof_input_changed_paths','offline_authorization_proof'}
    if set(original)!=set(old) or any(original[k]!=old[k] for k in set(old)-variable):
        raise ValueError('d125-behavior-bearing-original-closure-changed')
    for item in retention['binaries'].values():
        path=safe_retained_path(item['retained_path'],ROOT);retained[path.relative_to(ROOT).as_posix()]=sha(path)
    # Complete current fixture/oracle/source authority, including inputs that do
    # not belong to the C/source component inventory.
    compiler=load_module('d125_fixture_identity','scripts/evidence/phase6_routes.py')
    compiler.trusted_baseline()
    for group in compiler.SOURCES.values():
        for name in group:retained[name]=sha(ROOT/name)
    for name in control_input_paths():retained[name]=sha(ROOT/name)
    for name in ('evidence/phase5-baseline.json','evidence/phase5-baseline-roster.json','evidence/phase5-current-reference.json',
                 'evidence/phase5-failure-inventory.json','evidence/phase6-capture-recovery.json',
                 'evidence/phase6-stack-observation-manifest.json','evidence/phase6-stack-observation-manifest-d122.json'):
        retained[name]=sha(ROOT/name)
    if sha(build/'tools/session/gw_headless')!=prior['control_client_binary_sha256']:
        raise ValueError('d125-current-native-binary-drift')
    return {'retained_file_sha256':dict(sorted(retained.items())),'external_tool_sha256':external_tools,
        'qualification_variants':['native','sanitize','hooks-off'],'qualification_rows':rows,'original_semantic_closure':original,
        'capture_descriptor_sha256':original['tank_capture_descriptor_sha256']}


def _d125_component_candidate(prior_bridge_path,component_review_path,build,output_path):
    prior_path=project_input_path(prior_bridge_path);prior=json.loads(prior_path.read_bytes())
    saved=json.loads(LEDGER.read_bytes()).get('d123_observer_bridge_binding',{})
    if (prior.get('schema')!='phase6-tank-observer-bridge-d123-v1' or prior.get('status')!='passed-observer-bridge-no-launch' or
            prior.get('bridge_sha256')!=saved.get('bridge_sha256') or saved.get('status')!='independently-accepted' or
            prior.get('current_source_closure',{}).get('source_identity')!=saved.get('source_identity') or
            prior.get('bridge_sha256')!=_canonical_digest({k:v for k,v in prior.items() if k!='bridge_sha256'})):
        raise ValueError('d125-prior-bridge-digest-invalid')
    current=_d125_component_map();old=_d125_old_components(prior,current)
    review_path=project_input_path(component_review_path);review=_review_payload(review_path)
    components=[{'path':name,'old_sha256':old[name],'new_sha256':current[name]} for name in current]
    if (review.get('disposition')!='accepted' or review.get('components')!=[dict(row,decision='accepted') for row in components] or
            review.get('findings')!=[] or not review.get('reviewer_identity')):
        raise ValueError('d125-independent-component-review-incomplete')
    raw=_d125_raw_closure(prior,build)
    protected=[name for name in current if name.startswith(('src/','include/','tools/','cmake/')) or name=='CMakeLists.txt']
    if any(current[name]!=old[name] for name in protected):
        raise ValueError('d125-runtime-or-build-change-requires-affected-qualification')
    bridge={k:v for k,v in prior.items() if k!='bridge_sha256'}
    bridge.update(recovery_owner='06-22',source_identity=current_source_identity(),
        current_source_closure={'source_identity':current_source_identity(),'component_sha256':current},
        original_semantic_closure=raw['original_semantic_closure'],original_semantic_closure_sha256=_canonical_digest(raw['original_semantic_closure']),
        capture_descriptor_sha256=raw['capture_descriptor_sha256'])
    bridge['d125_component_disposition']={'schema':'phase6-d125-component-disposition-v1','prior_bridge_path':prior_path.relative_to(ROOT).as_posix(),
        'prior_bridge_file_sha256':sha(prior_path),'prior_bridge_sha256':prior['bridge_sha256'],'components':components,
        'component_review_path':review_path.relative_to(ROOT).as_posix(),'component_review_sha256':sha(review_path),'raw_closure':raw}
    bridge['bridge_sha256']=_canonical_digest(bridge)
    output=pathlib.Path(output_path);output=output if output.is_absolute() else ROOT/output
    output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists() or output.is_symlink():raise ValueError('d125-bridge-output-exists-or-symlink')
    _atomic_publish_checked_output(output,(json.dumps(bridge,sort_keys=True,indent=2)+'\n').encode())
    return {'status':'current-component-candidate','bridge_sha256':bridge['bridge_sha256'],'components':len(components),'launches':0}


def _verify_d125_bridge(path,build):
    bridge=json.loads(pathlib.Path(path).read_bytes())
    if bridge.get('bridge_sha256')!=_canonical_digest({k:v for k,v in bridge.items() if k!='bridge_sha256'}):
        raise ValueError('d125-bridge-hash-invalid')
    accounting=load_module('d125_bridge_accounting','scripts/evidence/phase6_accounting.py')
    ledger=accounting._load(LEDGER,ROOT);accounting.selected_recovery_owner(ledger,project_root=ROOT)
    if bridge.get('current_source_closure',{}).get('source_identity')!=current_source_identity():raise ValueError('d125-bridge-source-stale')
    # Authored prospective transactions retain the full historical real
    # validator; only the explicitly reviewed fixture authority is different.
    if bridge.get('test_fixture_only') is True:
        accounting._d125_fixture_authorized(ledger,ROOT)
        historical_path=project_input_path(bridge['authored_historical_bridge_path'])
        historical=json.loads(historical_path.read_bytes())
        if historical.get('bridge_sha256')!=bridge.get('authored_historical_bridge_sha256'):
            raise ValueError('d125-authored-prior-bridge-stale')
        return bridge if verify_observer_bridge(historical_path,build) else None
    disposition=bridge.get('d125_component_disposition',{})
    prior_path=project_input_path(disposition.get('prior_bridge_path',''));prior=json.loads(prior_path.read_bytes())
    saved=ledger.get('d123_observer_bridge_binding',{})
    if (sha(prior_path)!=disposition.get('prior_bridge_file_sha256') or prior.get('bridge_sha256')!=disposition.get('prior_bridge_sha256') or
            prior.get('bridge_sha256')!=saved.get('bridge_sha256') or saved.get('status')!='independently-accepted'):
        raise ValueError('d125-prior-bridge-file-stale')
    current=_d125_component_map();old=_d125_old_components(prior,current)
    components=[{'path':name,'old_sha256':old[name],'new_sha256':current[name]} for name in current]
    if bridge.get('current_source_closure',{}).get('component_sha256')!=current or disposition.get('components')!=components:
        raise ValueError('d125-component-denominator-or-source-stale')
    review_path=project_input_path(disposition.get('component_review_path',''));review=_review_payload(review_path)
    if sha(review_path)!=disposition.get('component_review_sha256') or review.get('disposition')!='accepted' or review.get('components')!=[dict(row,decision='accepted') for row in components]:
        raise ValueError('d125-component-review-stale-or-incomplete')
    raw=_d125_raw_closure(prior,build)
    if raw!=disposition.get('raw_closure') or bridge.get('original_semantic_closure')!=raw['original_semantic_closure'] or bridge.get('capture_descriptor_sha256')!=raw['capture_descriptor_sha256']:
        raise ValueError('d125-complete-raw-closure-stale')
    return bridge


def _verify_d125_proof_review(bridge_path,review_path,build,output):
    bridge=verify_observer_bridge(bridge_path,build);review_path=project_input_path(review_path)
    payload=_review_payload(review_path);validate_review_payload(payload,bridge)
    accounting=load_module('d125_proof_accounting','scripts/evidence/phase6_accounting.py')
    ledger=accounting._load(LEDGER,ROOT)
    handoff=_trusted_handoff(ledger,lane='observer-proof-review',review_path=review_path,review_digest=sha(review_path),
        bridge_sha=bridge['bridge_sha256'],source_identity=current_source_identity())
    bridge_path=project_input_path(bridge_path)
    result={'schema':'phase6-d125-observer-review-check-v1','status':'accepted','recovery_owner':'06-22',
        'bridge_path':bridge_path.relative_to(ROOT).as_posix(),'bridge_sha256':bridge['bridge_sha256'],'bridge_file_sha256':sha(bridge_path),
        'review_path':review_path.relative_to(ROOT).as_posix(),'review_sha256':sha(review_path),'source_identity':current_source_identity(),
        'reviewer_identity':handoff['reviewer_identity'],'reviewer_role':handoff['reviewer_role'],
        'trusted_handoff_sha256':_canonical_digest(handoff),'checker_sha256':sha(pathlib.Path(__file__)),'launches':0}
    result['check_sha256']=_canonical_digest(result)
    output=pathlib.Path(output);output=output if output.is_absolute() else ROOT/output
    output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists() or output.is_symlink():raise ValueError('d125-proof-check-output-exists-or-symlink')
    with accounting._locked(LEDGER):
        current=accounting._load(LEDGER,ROOT)
        if current_source_identity()!=result['source_identity'] or sha(review_path)!=result['review_sha256'] or sha(bridge_path)!=result['bridge_file_sha256']:
            raise ValueError('d125-proof-source-or-tuple-drift-under-lock')
        _trusted_handoff(current,lane='observer-proof-review',review_path=review_path,review_digest=sha(review_path),
            bridge_sha=bridge['bridge_sha256'],source_identity=result['source_identity'])
        _atomic_publish_checked_output(output,(json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
        current['d125_observer_bridge_binding']={**result,'review_check_path':output.relative_to(ROOT).as_posix(),
            'review_check_file_sha256':sha(output),'review_check_sha256':result['check_sha256'],'status':'independently-accepted'}
        accounting._write(LEDGER,current)
    return result


def _verify_d125_acceptance_review(check_path,bridge_path,build):
    bridge=verify_observer_bridge(bridge_path,build);check_path=project_input_path(check_path);check=json.loads(check_path.read_bytes())
    accounting=load_module('d125_acceptance_accounting','scripts/evidence/phase6_accounting.py')
    ledger=accounting._load(LEDGER,ROOT);owner=accounting.selected_recovery_owner(ledger,project_root=ROOT,require_runtime=True)
    binding=ledger.get('d125_observer_bridge_binding',{})
    if (check.get('schema')!='phase6-d125-observer-review-check-v1' or check.get('status')!='accepted' or
            check.get('check_sha256')!=_canonical_digest({k:v for k,v in check.items() if k!='check_sha256'}) or
            check.get('bridge_sha256')!=bridge['bridge_sha256'] or check.get('source_identity')!=current_source_identity() or
            check.get('checker_sha256')!=sha(pathlib.Path(__file__)) or binding.get('status')!='independently-accepted' or
            binding.get('review_check_file_sha256')!=sha(check_path) or binding.get('review_check_sha256')!=check['check_sha256'] or
            binding.get('bridge_file_sha256')!=sha(project_input_path(bridge_path))):
        raise ValueError('d125-current-review-binding-invalid')
    review_path=project_input_path(check['review_path'])
    if sha(review_path)!=check['review_sha256']:raise ValueError('d125-proof-review-file-stale')
    handoff=_trusted_handoff(ledger,lane='observer-proof-review',review_path=review_path,review_digest=check['review_sha256'],
        bridge_sha=bridge['bridge_sha256'],source_identity=check['source_identity'])
    if _canonical_digest(handoff)!=check['trusted_handoff_sha256']:raise ValueError('d125-proof-handoff-stale')
    return {'status':'accepted-current-review','bridge_sha256':bridge['bridge_sha256'],'launches':0,'generation_id':owner['generation_id']}


def _verify_d125_receipt_file(path,bridge_path,proof_review_path,build,output,acceptance_review,review_check_path):
    build=pathlib.Path(build);build=build if build.is_absolute() else ROOT/build
    bridge=verify_observer_bridge(bridge_path,build);_verify_d125_acceptance_review(review_check_path,bridge_path,build)
    path=project_input_path(path);receipt_bytes=path.read_bytes();receipt=json.loads(receipt_bytes)
    acceptance_path=project_input_path(acceptance_review);acceptance_bytes=acceptance_path.read_bytes();acceptance=json.loads(acceptance_bytes)
    accounting=load_module('d125_checked_receipt_accounting','scripts/evidence/phase6_accounting.py')
    ledger=accounting._load(LEDGER,ROOT);owner=accounting.selected_recovery_owner(ledger,project_root=ROOT,require_runtime=True)
    if receipt.get('recovery_owner')!='06-22' or receipt.get('generation_id')!=owner['generation_id']:
        raise ValueError('d125-receipt-owner-stale')
    counts=validate_receipt_data(receipt,bridge,root=ROOT,ledger_path=LEDGER)
    rows=[r for r in ledger['records'] if r.get('d125_owner')=='06-22']
    if ([r.get('case') for r in rows]!=list(accounting.D125_CASES) or any(r.get('status')!='completed' for r in rows) or
            [r.get('new_target_attempts') for r in rows]!=[1,0,0] or rows[0]!=receipt.get('reservation')):
        raise ValueError('d125-final-reservation-denominator-invalid')
    pointer=ledger.get('current_tank_continuation_receipt',{})
    capture_id=sha_bytes((rows[0]['record_id']+receipt['native_report_sha256']+bridge['bridge_sha256']).encode())
    if pointer.get('capture_sha256')!=capture_id or pointer.get('status') not in ('captured','passed'):
        raise ValueError('d125-final-capture-pointer-invalid')
    if (acceptance.get('disposition')!='accepted' or acceptance.get('receipt_sha256')!=sha_bytes(receipt_bytes) or
            acceptance.get('bridge_sha256')!=bridge['bridge_sha256'] or acceptance.get('source_identity')!=current_source_identity() or
            type(acceptance.get('processes')) is not int or acceptance['processes']!=3 or
            type(acceptance.get('control_cases')) is not int or acceptance['control_cases']!=12):
        raise ValueError('d125-final-review-content-invalid')
    handoff=_trusted_handoff(ledger,lane='tank-final-acceptance',review_path=acceptance_path,review_digest=sha_bytes(acceptance_bytes),
        bridge_sha=bridge['bridge_sha256'],source_identity=current_source_identity(),receipt_sha=sha_bytes(receipt_bytes))
    result={'schema':'phase6-tank-continuation-checked-v1','status':'independently-checked','independently_checked':True,
        'recovery_owner':'06-22','generation_id':owner['generation_id'],'receipt_sha256':sha_bytes(receipt_bytes),
        'bridge_sha256':bridge['bridge_sha256'],'acceptance_review_sha256':sha_bytes(acceptance_bytes),
        'source_identity':current_source_identity(),'native_binary_sha256':sha(build/'tools/session/gw_headless'),
        'checker_sha256':sha(pathlib.Path(__file__)),'counts':counts,'reservation_record_id':rows[0]['record_id'],
        'trusted_final_handoff_sha256':_canonical_digest(handoff),'launches':0}
    expected_ledger_sha=accounting.ledger_digest(LEDGER)
    output=pathlib.Path(output);output=output if output.is_absolute() else ROOT/output
    output.parent.mkdir(parents=True,exist_ok=True)
    with accounting._locked(LEDGER):
        current=accounting._load(LEDGER,ROOT)
        accounting.selected_recovery_owner(current,project_root=ROOT,require_runtime=True)
        if (accounting.ledger_digest(LEDGER)!=expected_ledger_sha or path.read_bytes()!=receipt_bytes or
                acceptance_path.read_bytes()!=acceptance_bytes or current_source_identity()!=result['source_identity'] or
                current.get('current_tank_continuation_receipt',{}).get('capture_sha256')!=capture_id):
            raise ValueError('d125-source-ledger-receipt-or-review-drift-under-lock')
        # Recompute full raw native/stream/PCM and review identities while the
        # actual promotion lock is held; initial checking is never authority.
        if validate_receipt_data(json.loads(path.read_bytes()),bridge,root=ROOT,ledger_path=LEDGER)!=counts:
            raise ValueError('d125-raw-denominator-drift-under-lock')
        _verify_d125_acceptance_review(review_check_path,bridge_path,build)
        latest_handoff=_trusted_handoff(current,lane='tank-final-acceptance',review_path=acceptance_path,review_digest=sha_bytes(acceptance_bytes),
            bridge_sha=bridge['bridge_sha256'],source_identity=result['source_identity'],receipt_sha=result['receipt_sha256'])
        if _canonical_digest(latest_handoff)!=result['trusted_final_handoff_sha256']:raise ValueError('d125-final-handoff-drift-under-lock')
        _atomic_publish_checked_output(output,(json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
        current['current_tank_continuation_receipt'].update(status='passed',independently_checked=True,
            checked_receipt_sha256=result['receipt_sha256'],checker_sha256=result['checker_sha256'],
            final_acceptance_review_sha256=result['acceptance_review_sha256'],trusted_final_handoff_sha256=result['trusted_final_handoff_sha256'])
        accounting._write(LEDGER,current)
    return result


def _d124_component_candidate(prior_bridge_path,component_review_path,build,output_path):
    """Create a reviewed successor closure while retaining D123 producer evidence."""
    prior_path=project_input_path(prior_bridge_path);prior=json.loads(prior_path.read_bytes())
    if (prior.get('schema')!='phase6-tank-observer-bridge-d123-v1' or
            prior.get('status')!='passed-observer-bridge-no-launch' or
            prior.get('bridge_sha256')!=_canonical_digest({k:v for k,v in prior.items() if k!='bridge_sha256'})):
        raise ValueError('d124-prior-d123-bridge-invalid')
    manifest=json.loads(project_input_path(prior['manifest_path']).read_bytes())
    producer=manifest.get('component_sha256',{})
    prior_components=prior.get('current_source_closure',{}).get('component_sha256',{})
    stack=load_module('d124_component_map','tests/evidence/phase6_stack_observation_contract.py')
    accounting=load_module('d124_component_accounting','scripts/evidence/phase6_accounting.py')
    current=stack._d123_current_component_map(accounting)
    if not producer or set(current)!=set(producer) or set(current)!=set(prior_components):
        raise ValueError('d124-component-map-denominator-changed')
    dispositions={
        'scripts/evidence/phase6_accounting.py':('accounting consumer','D124 policy install and global-only activity admission; preserve the historical PEA target and finite original06-14 process identities.'),
        'tests/evidence/phase6_accounting_contract.py':('accounting contract tests','Isolate legacy D122/D123 fixtures from the appended D124 ledger overlay and cover successor reserve denials.'),
        'tests/evidence/phase6_tank_continuation_contract.py':('receipt and locked publisher','Forward the explicit review-check; recompute and lock-recheck selected bridge, proof-review and review-check bytes before checked publication.'),
        'tests/fixtures/phase6_repairs.py':('continuation coordinator','Forward one explicit bridge/proof-review/review-check tuple through bridge verification, reservation and the pre-spawn drift callback.'),
    }
    changes=[]
    for name,old_digest in prior_components.items():
        new_digest=current[name]
        if old_digest==new_digest:continue
        if name not in dispositions:
            raise ValueError('d124-unclassified-source-component-delta:'+name)
        consumer,disposition=dispositions[name]
        changes.append({'path':name,'producer_sha256':old_digest,'current_sha256':new_digest,
            'producer_behavior':'D123 producer source covered by retained manifest/qualification',
            'current_consumer':consumer,'disposition':disposition})
    expected=set(dispositions)
    if {item['path'] for item in changes}!=expected:
        raise ValueError('d124-component-disposition-denominator-changed')
    # These closure fields are intentionally byte-identical to the previously
    # reviewed producer. Existing retained rows are revalidated by the checker.
    build=pathlib.Path(build);build=build if build.is_absolute() else ROOT/build
    if sha(build/'tools/session/gw_headless')!=prior.get('control_client_binary_sha256'):
        raise ValueError('d124-current-binary-differs-from-reviewed-producer')
    live_ledger=json.loads(LEDGER.read_bytes())
    retention=load_original_binary_retention(live_ledger.get('d122_successor_manifest',{}).get('original_binary_retention'))
    with tempfile.TemporaryDirectory(prefix='d124-retained-semantic-',dir=ROOT/'build/phase6/d123-observer') as temporary:
        recomputed=revalidate_proof(build,pathlib.Path(temporary)/'original.json',
            update_ledger=False,binary_retention=retention)
    saved=prior.get('original_semantic_closure',{})
    mutable={'bridge_sha256','current_source_identity','verifier_sha256','source_changed_paths',
        'proof_input_changed_paths','offline_authorization_proof'}
    if set(recomputed)!=set(saved) or any(recomputed.get(name)!=saved.get(name) for name in set(saved)-mutable):
        raise ValueError('d124-retained-original-semantic-closure-changed-outside-consumers')
    allowed_paths=set(dispositions)
    for field in ('source_changed_paths','proof_input_changed_paths'):
        old=saved.get(field,{}) or {};new=recomputed.get(field,{}) or {}
        if set(old)!=set(new) or any(old[name].get('before_sha256')!=new[name].get('before_sha256') or
                (old[name]!=new[name] and name not in allowed_paths) for name in old):
            raise ValueError('d124-retained-original-source-path-delta-invalid:'+field)
    offline=recomputed.get('offline_authorization_proof',{})
    if (set(saved.get('offline_authorization_proof',{}))!=set(offline) or
            offline.get('coordinator_sha256')!=current.get('tests/fixtures/phase6_repairs.py') or
            offline.get('test_contract_sha256')!=current.get('tests/evidence/phase6_accounting_contract.py') or
            offline.get('executed_in_this_artifact') is not False):
        raise ValueError('d124-offline-coordinator-consumer-proof-invalid')
    invariant={'c_sources_headers_unchanged':all(current[name]==prior_components[name] for name in current
            if name.startswith(('src/','include/')) or name.endswith(('.c','.h')) and name.startswith('tools/')),
        'build_cache_compiler_and_tool_records_sha256':_canonical_digest(prior.get('build_tool_identity',{})),
        'qualification_rows_sha256':_canonical_digest(prior.get('qualification_rows',[])),
        'launch_flags_and_process_closure_sha256':_canonical_digest(prior.get('original_semantic_closure',{})),
        'retained_qualification_denominator':['native','sanitize','hooks-off'],
        'retained_guest_descriptor_oracle_build_inputs_unchanged':True,
        'offline_authorization_consumer_proof_sha256':_canonical_digest(offline),
        'fresh_guest_or_build_required':False}
    if not invariant['c_sources_headers_unchanged']:
        raise ValueError('d124-core-or-tool-source-changed-requires-fresh-qualification')
    bridge={k:v for k,v in prior.items() if k!='bridge_sha256'}
    bridge['source_identity']=accounting.source_identity(ROOT)
    bridge['current_source_closure']={'source_identity':bridge['source_identity'],
        'component_sha256':current}
    bridge['original_semantic_closure']=recomputed
    bridge['original_semantic_closure_sha256']=_canonical_digest(recomputed)
    # The retained G02 top-level descriptor predates the final semantic closure
    # value. D124 binds the recomputed source-derived descriptor in its own
    # immutable candidate; G02 itself remains untouched.
    bridge['capture_descriptor_sha256']=recomputed['tank_capture_descriptor_sha256']
    invariant['original_semantic_recomputed_sha256']=_canonical_digest(recomputed)
    manifest_deltas=[{'path':name,'producer_sha256':old,'current_sha256':current.get(name)}
        for name,old in producer.items() if current.get(name)!=old]
    bridge['component_revalidation']={'status':'pending-independent-review','classification':'d124-exact-consumer-disposition',
        'changes':manifest_deltas,
        'runtime_input_oracle_build_closure_unchanged':True,'raw_qualification_outputs_complete':True,
        'prior_verdict_preserved':True}
    review_path=pathlib.Path(component_review_path)
    review_path=review_path if review_path.is_absolute() else ROOT/review_path
    review_path.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    disposition={'schema':'phase6-d124-component-disposition-v1','status':'pending-independent-review',
        'prior_bridge_path':prior_path.relative_to(ROOT).as_posix(),'prior_bridge_sha256':prior['bridge_sha256'],
        'prior_source_identity':prior.get('current_source_closure',{}).get('source_identity'),
        'current_source_identity':bridge['current_source_closure']['source_identity'],
        'changes':changes,'protected_invariants':invariant,
        'component_review_path':review_path.relative_to(ROOT).as_posix(),
        'review_binds_final_bridge_sha256':True}
    disposition['sha256']=_canonical_digest({k:v for k,v in disposition.items() if k!='sha256'})
    bridge['d124_component_disposition']=disposition
    bridge['bridge_sha256']=_canonical_digest(bridge)
    output=pathlib.Path(output_path);output=output if output.is_absolute() else ROOT/output
    output.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    if output.exists() or output.is_symlink():raise ValueError('d124-bridge-output-exists-or-symlink')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(bridge,indent=2,sort_keys=True)+'\n')
    return {'status':'pending-independent-review','bridge_path':output.relative_to(ROOT).as_posix(),
        'bridge_sha256':bridge['bridge_sha256'],'component_disposition_sha256':disposition['sha256'],
        'changed_components':[item['path'] for item in changes],'guest_launches':0,'builds':0}


def verify_observer_bridge(path,build,*,allow_pending_d124_review=False):
    path=project_input_path(path);bridge=json.loads(path.read_bytes())
    if bridge.get('recovery_owner')=='06-22':
        return _verify_d125_bridge(path,build)
    digest=bridge.get('bridge_sha256')
    unsigned={k:v for k,v in bridge.items() if k!='bridge_sha256'}
    active_ledger=json.loads(LEDGER.read_text())
    if active_ledger.get('d123_recovery_policy',{}).get('status')=='active' and \
            bridge.get('schema')!='phase6-tank-observer-bridge-d123-v1':
        raise ValueError('active-d123-policy-requires-d123-observer-bridge')
    if bridge.get('schema')=='phase6-tank-observer-bridge-d123-v1':
        build=pathlib.Path(build);build=build if build.is_absolute() else ROOT/build
        if bridge.get('status')!='passed-observer-bridge-no-launch' or digest!=_canonical_digest(unsigned):
            raise ValueError('d123-observer-bridge-hash-or-status-invalid')
        manifest_path=project_input_path(bridge.get('manifest_path',''))
        manifest=json.loads(manifest_path.read_bytes())
        if (manifest.get('schema')!='phase6-d123-stack-observation-manifest-v1' or
                manifest.get('status')!='frozen' or sha(manifest_path)!=bridge.get('manifest_sha256')):
            raise ValueError('d123-frozen-manifest-binding-invalid')
        source=bridge.get('source_identity');producer_source=bridge.get('producer_source_identity');ledger=active_ledger
        if source!=current_source_identity() or manifest.get('source_identity')!=producer_source:
            raise ValueError('d123-observer-current-source-drift')
        components=bridge.get('current_source_closure',{}).get('component_sha256',{})
        if not isinstance(components,dict) or not components or any(sha(ROOT/name)!=value for name,value in components.items()):
            raise ValueError('d123-observer-component-closure-drift')
        producer_components=manifest.get('component_sha256',{})
        deltas=[{'path':name,'producer_sha256':old,'current_sha256':components.get(name)}
            for name,old in producer_components.items() if components.get(name)!=old]
        declared=bridge.get('component_revalidation',{})
        d124_disposition=bridge.get('d124_component_disposition')
        if d124_disposition is not None:
            prior_path=project_input_path(d124_disposition.get('prior_bridge_path',''))
            prior=json.loads(prior_path.read_bytes())
            prior_components=prior.get('current_source_closure',{}).get('component_sha256',{})
            disposition_digest=_canonical_digest({k:v for k,v in d124_disposition.items() if k!='sha256'})
            delta_rows=[{'path':item.get('path'),'producer_sha256':item.get('producer_sha256'),
                'current_sha256':item.get('current_sha256')} for item in d124_disposition.get('changes',[])]
            disposition_paths={item.get('path') for item in d124_disposition.get('changes',[])}
            prior_deltas=[{'path':name,'producer_sha256':old,'current_sha256':components.get(name)}
                for name,old in prior_components.items() if components.get(name)!=old]
            manifest_deltas=[{'path':name,'producer_sha256':old,'current_sha256':components.get(name)}
                for name,old in producer_components.items() if components.get(name)!=old]
            binding=ledger.get('d124_observer_bridge_binding',{})
            accepted=(d124_disposition.get('status')=='pending-independent-review' and
                d124_disposition.get('schema')=='phase6-d124-component-disposition-v1' and
                d124_disposition.get('sha256')==disposition_digest and
                d124_disposition.get('prior_bridge_sha256')==prior.get('bridge_sha256') and
                d124_disposition.get('prior_source_identity')==prior.get('current_source_closure',{}).get('source_identity') and
                d124_disposition.get('current_source_identity')==source and
                prior_deltas==delta_rows and manifest_deltas==deltas and delta_rows==prior_deltas and
                disposition_paths=={'scripts/evidence/phase6_accounting.py',
                    'tests/evidence/phase6_accounting_contract.py','tests/evidence/phase6_tank_continuation_contract.py',
                    'tests/fixtures/phase6_repairs.py'} and
                declared.get('changes')==deltas and
                d124_disposition.get('protected_invariants',{}).get('c_sources_headers_unchanged') is True and
                d124_disposition.get('protected_invariants',{}).get('retained_guest_descriptor_oracle_build_inputs_unchanged') is True and
                d124_disposition.get('protected_invariants',{}).get('fresh_guest_or_build_required') is False)
            accepted=accepted and bridge.get('capture_descriptor_sha256')==bridge.get(
                'original_semantic_closure',{}).get('tank_capture_descriptor_sha256')
            if not accepted or (not allow_pending_d124_review and (
                    binding.get('status')!='independently-accepted' or binding.get('bridge_sha256')!=digest or
                    binding.get('component_disposition_sha256')!=disposition_digest or
                    ledger.get('d124_component_disposition',{}).get('sha256')!=disposition_digest or
                    ledger.get('d124_component_disposition',{}).get('status')!='independently-accepted')):
                raise ValueError('d124-component-revalidation-or-review-binding-invalid')
        elif set(components)!=set(producer_components) or (deltas and
                (deltas!=[{'path':item.get('path'),'producer_sha256':item.get('producer_sha256'),
                    'current_sha256':item.get('current_sha256')} for item in declared.get('changes',[])] or
                 any(item.get('path')!='tests/evidence/phase6_tank_continuation_contract.py' for item in deltas) or
                 declared.get('classification')!='validator-only') ) or (not deltas and declared.get('status')!='unchanged'):
            raise ValueError('d123-component-revalidation-disposition-invalid')
        qualification_path=project_input_path(bridge.get('qualification_path',''))
        if sha(qualification_path)!=bridge.get('qualification_sha256'):
            raise ValueError('d123-qualification-document-hash-invalid')
        qualification=json.loads(qualification_path.read_bytes())
        rows=qualification.get('rows',[])
        if qualification.get('schema')!='phase6-d123-qualification-v1' or qualification.get('status')!='passed-three-rows' or \
                qualification.get('manifest_sha256')!=bridge.get('manifest_sha256') or \
                [row.get('variant') for row in rows]!=['native','sanitize','hooks-off'] or any(
                row.get('kind')!='qualification' or row.get('status')!='passed' for row in rows):
            raise ValueError('d123-qualification-denominator-or-kind-invalid')
        cases={row.get('variant'):row for row in manifest.get('cases',[])}
        builds={row.get('variant'):row for row in manifest.get('builds',[])}
        tools=manifest.get('tool_identity',{});cmake=shutil.which(tools.get('cmake_name','cmake'))
        if not cmake or sha(pathlib.Path(cmake))!=tools.get('cmake_sha256'):
            raise ValueError('d123-cmake-identity-drift')
        for variant,build_row in builds.items():
            build_root=ROOT/build_row.get('directory','');cache=build_root/'CMakeCache.txt'
            binary=safe_retained_path(build_row.get('binary_path'),ROOT)
            settings={}
            for line in cache.read_text().splitlines():
                if '=' in line and ':' in line:
                    key,value=line.split('=',1);name=key.split(':',1)[0]
                    if name in ('CMAKE_C_COMPILER','CMAKE_MAKE_PROGRAM'):settings[name]=value
            if sha(cache)!=build_row.get('cache_sha256') or sha(binary)!=build_row.get('binary_sha256') or \
                    sha(pathlib.Path(settings.get('CMAKE_C_COMPILER',''))) != build_row.get('compiler_sha256') or \
                    sha(pathlib.Path(settings.get('CMAKE_MAKE_PROGRAM',''))) != build_row.get('build_tool_sha256'):
                raise ValueError('d123-qualified-build-closure-drift:'+variant)
        for row in rows:
            raw=safe_retained_path(row.get('raw_report_path'),ROOT)
            case=cases.get(row.get('variant'),{});build_row=builds.get(row.get('variant'),{})
            if row.get('kind')!='qualification' or row.get('purpose_id')!=case.get('purpose_id') or \
                    row.get('source_identity')!=producer_source or row.get('binary_sha256')!=build_row.get('binary_sha256') or \
                    row.get('guest_sha256')!=case.get('guest_sha256') or row.get('descriptor_sha256')!=case.get('descriptor_sha256') or \
                    sha(raw)!=row.get('raw_report_sha256'):
                raise ValueError('d123-qualification-raw-report-drift:'+str(row.get('variant')))
            report=json.loads(raw.read_bytes())
            stack=load_module('d123_bridge_stack_validator','tests/evidence/phase6_stack_observation_contract.py')
            checks=stack._validate_observation_report({'expected':case.get('expected',{})},report)
            if checks!=row.get('checks'):
                raise ValueError('d123-qualification-result-recomputation-mismatch:'+str(row.get('variant')))
            streams=row.get('process_streams',{})
            if set(streams)!={'stdout','stderr'}:
                raise ValueError('d123-qualification-stream-denominator-invalid')
            for stream in streams.values():
                stream_path=safe_retained_path(stream.get('path'),ROOT);data=stream_path.read_bytes()
                if len(data)!=stream.get('retained_bytes') or sha_bytes(data)!=stream.get('sha256') or stream.get('truncated'):
                    raise ValueError('d123-qualification-stream-drift:'+str(row.get('variant')))
        legacy=ledger.get('d122_successor_manifest',{})
        retention=load_original_binary_retention(legacy.get('original_binary_retention'))
        with tempfile.TemporaryDirectory(prefix='d123-bridge-original-check-',dir=ROOT/'build/phase6/d123-observer') as temporary:
            original=revalidate_proof(build,pathlib.Path(temporary)/'original.json',update_ledger=False,binary_retention=retention)
        if _canonical_digest(original)!=bridge.get('original_semantic_closure_sha256') or \
                original!=bridge.get('original_semantic_closure'):
            raise ValueError('d123-original-semantic-closure-recomputation-mismatch')
        build=pathlib.Path(build);build=build if build.is_absolute() else ROOT/build
        if sha(build/'tools/session/gw_headless')!=bridge.get('control_client_binary_sha256'):
            raise ValueError('d123-observer-control-binary-drift')
        ledger=active_ledger;policy=ledger.get('d123_recovery_policy',{})
        frozen=ledger.get('d123_observer_manifest',{})
        if (policy.get('status')!='active' or frozen.get('status')!='frozen' or
                frozen.get('sha256')!=bridge.get('manifest_sha256') or frozen.get('source_identity')!=producer_source):
            raise ValueError('d123-ledger-manifest-authority-mismatch')
        return bridge
    if bridge.get('schema')!='phase6-tank-observer-bridge-v1' or bridge.get('status')!='passed-observer-bridge-no-launch' or digest!=_canonical_digest(unsigned):
        raise ValueError('observer-bridge-hash-or-status-invalid')
    actual=current_source_identity()
    if actual!=bridge.get('current_source_closure',{}).get('source_identity'):
        raise ValueError('observer-bridge-source-drift')
    closure=bridge.get('current_source_closure',{}).get('path_sha256',{})
    if set(closure)!=set(source_paths(ROOT)) or any(sha(ROOT/name)!=value for name,value in closure.items()):
        raise ValueError('observer-bridge-current-path-closure-drift')
    for name,digest in bridge.get('current_source_closure',{}).get('extra_harness_source_sha256',{}).items():
        if sha(ROOT/name)!=digest:raise ValueError('observer-bridge-extra-harness-source-drift:'+name)
    if sha(ROOT/'evidence/phase6-stack-observation-manifest.json')!=bridge.get('original_observer_manifest_sha256') or \
       sha(ROOT/bridge.get('successor_manifest_path',''))!=bridge.get('successor_manifest_sha256'):
        raise ValueError('observer-bridge-manifest-identity-drift')
    build=pathlib.Path(build)
    build=build if build.is_absolute() else ROOT/build
    native=sha(build/'tools/session/gw_headless');control=sha(build/'tools/session/gw_headless')
    if native!=bridge.get('native_binary_sha256') or control!=bridge.get('control_client_binary_sha256'):
        raise ValueError('observer-bridge-binary-identity-drift')
    closure=bridge.get('original_semantic_closure',{})
    if control_inputs()!=closure.get('current_control_inputs'):
        raise ValueError('observer-bridge-current-control-input-drift')
    historical={name:sha_bytes(git_blob(BASELINE_COMMIT,name)) for name in control_input_paths()}
    if historical!=closure.get('historical_control_inputs'):
        raise ValueError('observer-bridge-immutable-control-input-drift')
    ledger=json.loads(LEDGER.read_text());frozen=ledger.get('d122_successor_manifest',{})
    with tempfile.TemporaryDirectory(prefix='bridge-recheck-',dir=ROOT/'build/phase6/d122-observer') as temp:
        original=revalidate_proof(build if build.is_absolute() else ROOT/build,pathlib.Path(temp)/'original.json',
            update_ledger=False,binary_retention=load_original_binary_retention(frozen.get('original_binary_retention')))
    saved_original=bridge.get('original_semantic_closure',{})
    if (original.get('status')!='passed-no-launch' or original.get('base_commit')!=saved_original.get('base_revision') or
        original.get('old_source_identity')!=saved_original.get('old_source_identity') or
        original.get('retained_manifest_sha256')!=saved_original.get('retained_manifest_sha256') or
        original.get('retained_reports')!=saved_original.get('retained_reports') or
        original.get('original_runtime_closure')!=saved_original.get('original_runtime_closure') or
        original.get('control_driver_inputs')!=saved_original.get('current_control_inputs') or
        original.get('historical_control_driver_inputs')!=saved_original.get('historical_control_inputs') or
        original.get('source_changed_paths')!=saved_original.get('source_changed_paths')):
        raise ValueError('observer-bridge-recomputed-original-closure-mismatch')
    saved=frozen.get('tool_identity',{});public_tools={'cmake_sha256':saved.get('cmake_sha256'),
        'builds':{variant:{'cache_sha256':entry.get('cache_sha256'),
            'compiler_name':pathlib.Path(entry.get('compiler_path','')).name,'compiler_sha256':entry.get('compiler_sha256'),
            'build_tool_name':pathlib.Path(entry.get('build_tool_path','')).name,
            'build_tool_sha256':entry.get('build_tool_sha256'),'settings':entry.get('settings'),'command':entry.get('command')}
            for variant,entry in saved.get('builds',{}).items()}}
    if bridge.get('build_tool_identity')!=public_tools:raise ValueError('observer-bridge-build-tool-freeze-mismatch')
    cmake=pathlib.Path(saved.get('cmake_path',''))
    if not cmake.is_file() or sha(cmake)!=saved.get('cmake_sha256'):raise ValueError('observer-cmake-file-identity-drift')
    manifest=json.loads((ROOT/bridge['successor_manifest_path']).read_bytes())
    for item in manifest['builds']:
        frozen_build=saved['builds'][item['variant']];cache=ROOT/item['directory']/'CMakeCache.txt'
        compiler=pathlib.Path(frozen_build['compiler_path']);maker=pathlib.Path(frozen_build['build_tool_path'])
        if sha(cache)!=frozen_build['cache_sha256'] or sha(compiler)!=frozen_build['compiler_sha256'] or sha(maker)!=frozen_build['build_tool_sha256']:
            raise ValueError('observer-bridge-cache-compiler-or-buildtool-drift:'+item['variant'])
    return bridge

def _review_payload(markdown):
    text=pathlib.Path(markdown).read_text()
    blocks=re.findall(r"```json\s*\n(.*?)\n```",text,re.S)
    if len(blocks)!=1:raise ValueError('proof-review-requires-one-machine-readable-json-block')
    return json.loads(blocks[0])

def validate_qualification23_review_payload(payload,bridge):
    """Validate review substance independently of a parent pin echoing its data.

    Plan23's actual payload has no version/schema field. Its closed structural
    contract is the seven fields below, not an invented version requirement.
    The eight sections are its actual proof-review denominator. This validates
    a bounded engineering review, never authority to reuse frozen rows.
    """
    required={'plan23-full-argv-and-later-stop-qualification-rows',
        'build-tool-cache-settings-and-current-binary-identities',
        'actual-report-predicate-and-raw-stream-denominator',
        'current-source-freeze-and-retained-component-disposition',
        'engineering-owner-counters-history-and-no-game-authority',
        'task1-g03-source-review-and-no-launch-guard-report',
        'proof-review-verifier-coverage-identity-and-findings-validation-source',
        'current-consumer-final-transaction-status-absent'}
    fields={'disposition','reviewer_identity','reviewer_role','source_identity',
        'bridge_sha256','findings','reviewed_sections'}
    if (not isinstance(payload,dict) or set(payload)!=fields or
            any(not isinstance(payload[k],str) for k in fields-{'findings','reviewed_sections'})):
        raise ValueError('qualification23-proof-review-schema-invalid')
    if (payload.get('disposition')!='accepted' or
            payload.get('bridge_sha256')!=bridge['bridge_sha256'] or
            payload.get('source_identity')!=bridge['source_identity'] or
            payload.get('reviewer_role')!='independent-reviewer'):
        raise ValueError('qualification23-proof-review-not-current-or-accepted')
    identity=payload.get('reviewer_identity')
    if (not isinstance(identity,str) or len(identity.strip())<3 or
            any(token in identity.casefold() for token in ('executor','coordinator','self-review','authoring-agent'))):
        raise ValueError('qualification23-proof-review-identity-not-independent')
    findings=payload.get('findings')
    if not isinstance(findings,list):
        raise ValueError('qualification23-proof-findings-malformed')
    for finding in findings:
        if (not isinstance(finding,dict) or not isinstance(finding.get('severity'),str) or
                set(finding)!={'severity','issue','classification','file','line','fix'} or
                any(not isinstance(v,str) or not v.strip() for v in finding.values()) or
                finding['severity'].casefold() not in {'info','low','medium','high','critical'} or
                not finding.get('issue','').strip()):
            raise ValueError('qualification23-proof-findings-malformed')
        # The actual review uses BLOCKER as a blocking disposition. Preserve
        # that meaning independently of severity; other labels are descriptive
        # strings, with no invented severity-to-classification mapping.
        if (finding['severity'].casefold() in {'high','critical'} or
                finding['classification'].strip().casefold()=='blocker'):
            raise ValueError('qualification23-proof-open-high-or-critical')
    sections=payload.get('reviewed_sections')
    if (not isinstance(sections,list) or any(not isinstance(s,str) or not s.strip() for s in sections) or
            len(set(sections))!=len(sections) or not required.issubset(sections)):
        raise ValueError('qualification23-proof-review-coverage-incomplete')
    return payload

def validate_review_payload(payload,bridge):
    if payload.get('bridge_sha256')!=bridge.get('bridge_sha256') or payload.get('source_identity')!=bridge['current_source_closure']['source_identity']:
        raise ValueError('independent-review-current-binding-mismatch')
    if payload.get('disposition')!='accepted' or payload.get('reviewer_role')!='independent-reviewer' or \
       not isinstance(payload.get('reviewer_identity'),str) or len(payload['reviewer_identity'].strip())<3:
        raise ValueError('independent-review-not-accepted-or-identity-missing')
    identity=payload['reviewer_identity'].lower()
    if any(token in identity for token in ('executor','coordinator','self-review','authoring-agent')):
        raise ValueError('independent-reviewer-not-independent')
    findings=payload.get('findings')
    if not isinstance(findings,list) or any(not isinstance(f,dict) or f.get('severity','').lower() in ('critical','high') for f in findings):
        raise ValueError('independent-review-open-critical-high-or-malformed-findings')
    reviewed=set(payload.get('reviewed_sections',[]))
    if bridge.get('schema')=='phase6-tank-observer-bridge-d123-v1' and bridge.get('d124_component_disposition') is not None:
        required={'historical-source-and-assertion-closure','actual-d123-qualification-and-binaries',
            'stack-read-ownership-and-neighbor-cases','raw-process-stream-and-global-accounting',
            'd124-accounting-and-component-consumer-disposition','downstream-14-launch-guard'}
    elif bridge.get('schema')=='phase6-tank-observer-bridge-d123-v1':
        required={'historical-source-and-assertion-closure','actual-d123-qualification-and-binaries',
            'stack-read-ownership-and-neighbor-cases','raw-process-stream-and-global-accounting',
            'd123-anchor-and-reserves','downstream-14-launch-guard','component-closure-and-revalidation-disposition'}
    else:
        required={'historical-source-and-assertion-closure','actual-observer-rows-and-binaries',
            'stack-read-ownership-and-same-pc-path','raw-process-stream-and-control-pcm-retention',
            'd122-partitions-and-active-anchor','downstream-authorization-gates'}
    if not required.issubset(reviewed):raise ValueError('independent-review-coverage-incomplete')
    return payload

def _trusted_handoff(ledger,*,lane,review_path,review_digest,bridge_sha,source_identity,receipt_sha=None,
                     handoff_key='d122_trusted_review_handoffs'):
    if ledger.get('d125_owner_generations'):
        accounting=load_module('d125_handoff_accounting','scripts/evidence/phase6_accounting.py')
        owner=accounting.selected_recovery_owner(ledger,project_root=ROOT)
        handoff_key='d125_trusted_review_handoffs'
    rel=pathlib.Path(review_path).relative_to(ROOT).as_posix()
    matches=[r for r in ledger.get(handoff_key,[]) if isinstance(r,dict) and
        r.get('lane')==lane and r.get('status')=='completed' and r.get('review_path')==rel and
        r.get('review_sha256')==review_digest and r.get('bridge_sha256')==bridge_sha and
        r.get('source_identity')==source_identity and r.get('tool_handoff_result')=='completed' and
        r.get('reviewer_role')=='gsd-code-reviewer' and isinstance(r.get('reviewer_identity'),str) and
        len(r['reviewer_identity'])>=3 and r.get('reviewer_identity')!=r.get('producer_identity') and
        r.get('disposition')=='accepted' and r.get('critical_findings',0)==0 and r.get('high_findings',0)==0 and
        (receipt_sha is None or r.get('receipt_sha256')==receipt_sha)]
    if len(matches)!=1:raise ValueError('trusted-independent-review-handoff-missing-or-ambiguous')
    if ledger.get('d125_owner_generations'):
        row=matches[0]
        fixture=owner.get('test_fixture_only') is True
        if row.get('test_fixture_only',False) is not fixture:
            raise ValueError('d125-fixture-handoff-in-production-denied')
        if not fixture:
            pin_path=project_input_path(row.get('parent_pin_path',''))
            pin=json.loads(pin_path.read_bytes())
            if (sha(pin_path)!=row.get('parent_pin_sha256') or pin.get('origin')!='parent-observed-separate-reviewer-completion' or
                    pin.get('tool_handoff_result')!='completed' or pin.get('decision')!='accepted' or pin.get('test_fixture_only') is True or
                    pin.get('reviewer_identity')!=row.get('reviewer_identity') or pin.get('reviewer_role')!='gsd-code-reviewer' or
                    pin.get('review_sha256')!=review_digest or pin.get('source_identity')!=source_identity or
                    pin.get('bridge_sha256')!=bridge_sha or (receipt_sha is not None and pin.get('receipt_sha256')!=receipt_sha)):
                raise ValueError('d125-parent-observed-handoff-stale-or-missing')
    return matches[0]

def _safe_output_dir(path):
    path=path if pathlib.Path(path).is_absolute() else ROOT/path
    path=pathlib.Path(os.path.abspath(path));path.relative_to(ROOT.resolve(strict=True))
    parent=path.parent
    relative_parent=parent.relative_to(ROOT.resolve(strict=True))
    if path.name in ('','.','..'):raise ValueError('checked-output-name-invalid')
    flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(ROOT.resolve(strict=True),flags)
    try:
        for component in relative_parent.parts:
            child=os.open(component,flags,dir_fd=fd);os.close(fd);fd=child
        return path,fd
    except BaseException:
        os.close(fd);raise

def _read_at_regular(dir_fd,name):
    info=os.stat(name,dir_fd=dir_fd,follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('checked-output-existing-object-not-private-regular-file')
    fd=os.open(name,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0),dir_fd=dir_fd)
    try:
        chunks=[]
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            chunks.append(chunk)
        return b''.join(chunks)
    finally:os.close(fd)

def _atomic_publish_checked_output(output,payload):
    """Durably publish exact bytes without following links or replacing a different result."""
    path,dir_fd=_safe_output_dir(pathlib.Path(output))
    name=path.name;temp_name=f'.{name}.{secrets.token_hex(12)}.tmp';fd=None
    try:
        try:
            existing=_read_at_regular(dir_fd,name)
        except FileNotFoundError:
            existing=None
        if existing is not None:
            if existing!=payload:raise ValueError('checked-output-existing-content-mismatch')
            return {'created':False,'sha256':sha_bytes(existing)}
        fd=os.open(temp_name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=dir_fd)
        view=memoryview(payload)
        while view:
            written=os.write(fd,view)
            if written<=0:raise OSError('checked-output-write-short')
            view=view[written:]
        os.fsync(fd);os.close(fd);fd=None
        os.link(temp_name,name,src_dir_fd=dir_fd,dst_dir_fd=dir_fd,follow_symlinks=False)
        os.unlink(temp_name,dir_fd=dir_fd);temp_name=''
        os.fsync(dir_fd)
        return {'created':True,'sha256':sha_bytes(payload)}
    finally:
        if fd is not None:os.close(fd)
        if temp_name:
            try:os.unlink(temp_name,dir_fd=dir_fd)
            except FileNotFoundError:pass
        os.close(dir_fd)

def _commit_checked_receipt_output(output,result,*,accounting,capture_id,acceptance_path,
                                   acceptance_digest,bridge,source_identity,proof_check,
                                   review_check_path,bridge_path=None,proof_review_path=None):
    payload=(json.dumps(result,indent=2,sort_keys=True)+'\n').encode()
    output_path=pathlib.Path(output)
    output_path=output_path if output_path.is_absolute() else ROOT/output_path
    with accounting._locked(LEDGER):
        current=accounting._load(LEDGER,ROOT)
        if current_source_identity()!=source_identity or sha(acceptance_path)!=acceptance_digest:
            raise ValueError('checked-receipt-source-or-review-drift-before-promotion')
        d124=bool(current.get('d124_recovery_policy'))
        if d124 or bridge_path is not None or proof_review_path is not None:
            if bridge_path is None or proof_review_path is None:
                raise ValueError('d124-selected-artifact-paths-required-under-promotion-lock')
            bridge_path=project_input_path(bridge_path);proof_review_path=project_input_path(proof_review_path)
            if (bridge_path.relative_to(ROOT).as_posix()!=result.get('selected_bridge_path') or
                    sha(bridge_path)!=result.get('selected_bridge_file_sha256') or
                    sha(proof_review_path)!=result.get('selected_proof_review_file_sha256') or
                    proof_review_path.relative_to(ROOT).as_posix()!=proof_check.get('review_path') or
                    json.loads(bridge_path.read_bytes())!=bridge):
                raise ValueError('selected-bridge-or-proof-review-drift-before-promotion')
        review_check_path=project_input_path(review_check_path)
        if sha(review_check_path)!=result.get('observer_review_check_file_sha256'):
            raise ValueError('selected-observer-review-check-file-drift-before-promotion')
        fresh_proof_check=json.loads(review_check_path.read_bytes())
        if fresh_proof_check!=proof_check or fresh_proof_check.get('status')!='accepted' or \
           fresh_proof_check.get('check_sha256')!=_canonical_digest({k:v for k,v in fresh_proof_check.items() if k!='check_sha256'}):
            raise ValueError('current-18-review-check-changed-before-promotion')
        is_d123=bridge.get('schema')=='phase6-tank-observer-bridge-d123-v1'
        is_d124=bridge.get('d124_component_disposition') is not None
        proof_handoff=_trusted_handoff(current,lane='observer-proof-review',review_path=safe_retained_path(proof_check.get('review_path'),ROOT),
            review_digest=proof_check.get('review_sha256'),bridge_sha=bridge['bridge_sha256'],source_identity=source_identity,
            handoff_key='d123_trusted_review_handoffs' if is_d123 else 'd122_trusted_review_handoffs')
        proof_binding=current.get('d124_observer_bridge_binding' if is_d124 else ('d123_observer_bridge_binding' if is_d123 else 'd122_observer_bridge_binding'),{})
        proof_record=current.get('d124_observer_review' if is_d124 else ('d123_observer_review' if is_d123 else 'd122_observer_review'),{})
        if proof_binding.get('status')!='independently-accepted' or \
           proof_binding.get('trusted_handoff_sha256')!=_canonical_digest(proof_handoff) or \
           proof_binding.get('bridge_sha256')!=bridge['bridge_sha256'] or \
           proof_record.get('review_sha256')!=proof_check.get('review_sha256') or \
           proof_record.get('review_check_sha256')!=proof_check.get('check_sha256') or \
           (is_d124 and (proof_binding.get('review_path')!=proof_check.get('review_path') or
            proof_binding.get('review_file_sha256')!=sha(safe_retained_path(proof_check.get('review_path'),ROOT)) or
            proof_binding.get('review_check_path')!=pathlib.Path(review_check_path).relative_to(ROOT).as_posix() or
            proof_binding.get('review_check_file_sha256')!=result.get('observer_review_check_file_sha256'))):
            raise ValueError('current-trusted-18-review-binding-changed-before-promotion')
        final_handoff=_trusted_handoff(current,lane='tank-final-acceptance',review_path=acceptance_path,
            review_digest=acceptance_digest,bridge_sha=bridge['bridge_sha256'],source_identity=source_identity,
            receipt_sha=result['receipt_sha256'])
        d124=bool(current.get('d124_recovery_policy'))
        if d124:
            observer=current.get('d124_observer_bridge_binding',{})
            disposition=current.get('d124_component_disposition',{})
            prior=current.get('d123_observer_bridge_binding',{})
            if (observer.get('status')!='independently-accepted' or
                    observer.get('bridge_sha256')!=bridge.get('bridge_sha256') or
                    observer.get('bridge_path')!=result.get('selected_bridge_path') or
                    observer.get('bridge_file_sha256')!=result.get('selected_bridge_file_sha256') or
                    observer.get('review_check_sha256')!=proof_check.get('check_sha256') or
                    observer.get('review_check_path')!=pathlib.Path(review_check_path).relative_to(ROOT).as_posix() or
                    observer.get('review_check_file_sha256')!=result.get('observer_review_check_file_sha256') or
                    disposition.get('status')!='independently-accepted' or
                    observer.get('component_disposition_sha256')!=disposition.get('sha256') or
                    observer.get('d123_bridge_sha256')!=prior.get('bridge_sha256') or
                    observer.get('d123_review_sha256')!=prior.get('review_sha256') or
                    observer.get('d123_trusted_handoff_sha256')!=prior.get('trusted_handoff_sha256')):
                raise ValueError('d124-selected-observer-binding-changed-before-promotion')
            result['final_acceptance_review_sha256']=acceptance_digest
            result['trusted_final_handoff_sha256']=_canonical_digest(final_handoff)
            result['selected_review_check_path']=observer.get('review_check_path')
            result['component_disposition_sha256']=disposition.get('sha256')
        if not d124:accounting.validate_d122_exception(current)
        process_rows=[r for r in current.get('records',[]) if r.get('plan')=='06-14' and
            r.get('purpose') in ('tank-continuation','tank-continuation-control')]
        if len(process_rows)!=3 or {r.get('case') for r in process_rows}!={'tank-pea-continuation-1','control-repeat-1','control-repeat-2'} or \
           any(r.get('status')!='completed' for r in process_rows) or \
           sum(r.get('new_target_attempts',0) for r in process_rows)!=1 or \
           any(r.get('new_target_attempts',0)!=0 for r in process_rows if r.get('purpose')=='tank-continuation-control') or \
           (not d124 and any(r.get('status')=='active' for r in current.get('d122_accounting',{}).get('other_charges',[]))):
            raise ValueError('d122-final-accounting-closure-invalid-before-promotion')
        if d124:
            required_stages={'preflight','interprocess','final-review','closeout','final-check'}
            runs=[r for r in current.get('d124_runs',[]) if r.get('status')=='completed']
            if not required_stages.issubset({r.get('stage') for r in runs}):
                raise ValueError('d124-final-activity-closure-incomplete-before-promotion')
        else:
            required={'tank-preflight','tank-interprocess','independent-final-review','d122-closeout'}
            charges=current.get('d122_accounting',{}).get('other_charges',[])
            if not required.issubset({r.get('purpose') for r in charges if r.get('status')=='completed'}):
                raise ValueError('d122-final-other-purpose-charge-missing-before-promotion')
        record=current.get('current_tank_continuation_receipt',{})
        if record.get('capture_sha256')!=capture_id:
            raise ValueError('ledger-capture-pointer-changed-during-check')
        if record.get('status')=='passed':
            if record.get('checked_receipt_sha256')!=result['receipt_sha256'] or \
               record.get('checker_sha256')!=result['checker_sha256'] or record.get('independently_checked') is not True:
                raise ValueError('checked-receipt-existing-promotion-mismatch')
        elif record.get('status')!='captured':
            raise ValueError('ledger-capture-pointer-not-promotable')
        # Publish while the ledger lock is held, only after every current binding
        # and the captured-or-matching-passed pointer have been revalidated.
        _atomic_publish_checked_output(output_path,payload)
        if record.get('status')=='captured':
            record.update(status='passed',independently_checked=True,
                checked_receipt_sha256=result['receipt_sha256'],checker_sha256=result['checker_sha256'])
            if d124:
                record.update(bridge_sha256=result['bridge_sha256'],
                    observer_review_check_file_sha256=result['observer_review_check_file_sha256'],
                    observer_review_check_path=result['selected_review_check_path'],
                    bridge_file_sha256=result['selected_bridge_file_sha256'],
                    bridge_path=result['selected_bridge_path'],
                    component_disposition_sha256=result['component_disposition_sha256'],
                    final_acceptance_review_sha256=result['final_acceptance_review_sha256'],
                    trusted_final_handoff_sha256=result['trusted_final_handoff_sha256'])
            current['current_tank_continuation_receipt']=record
            accounting._write(LEDGER,current)
    return result

def bridge_has_d124_disposition(path):
    return json.loads(project_input_path(path).read_bytes()).get('d124_component_disposition') is not None

def verify_proof_review(bridge_path,review_path,build,output,*,engineering_owner=None):
    if engineering_owner is not None:
        if engineering_owner!='06-23':raise ValueError('qualification23-explicit-owner-required')
        return verify_qualification23_proof(bridge_path,review_path,build,output)
    if json.loads(project_input_path(bridge_path).read_bytes()).get('recovery_owner')=='06-22':
        return _verify_d125_proof_review(bridge_path,review_path,build,output)
    bridge=verify_observer_bridge(bridge_path,build,
        allow_pending_d124_review=bridge_has_d124_disposition(bridge_path));review_path=project_input_path(review_path);payload=_review_payload(review_path)
    validate_review_payload(payload,bridge)
    is_d123=bridge.get('schema')=='phase6-tank-observer-bridge-d123-v1'
    is_d124=bridge.get('d124_component_disposition') is not None
    review_digest=sha(pathlib.Path(review_path));result={'schema':'phase6-d124-observer-review-check-v1' if is_d124 else ('phase6-d123-observer-review-check-v1' if is_d123 else 'phase6-d122-observer-review-check-v1'),'status':'accepted',
        'bridge_path':pathlib.Path(bridge_path).relative_to(ROOT).as_posix(),'bridge_sha256':bridge['bridge_sha256'],
        'review_path':pathlib.Path(review_path).relative_to(ROOT).as_posix(),'review_sha256':review_digest,
        'reviewer_identity':payload['reviewer_identity'],'reviewer_role':payload['reviewer_role'],
        'source_identity':bridge['current_source_closure']['source_identity'],'checker_sha256':sha(pathlib.Path(__file__)),
        'launches':0}
    if is_d123:
        result.update(manifest_sha256=bridge['manifest_sha256'],qualification_sha256=bridge['qualification_sha256'])
    if is_d124:result['component_disposition_sha256']=bridge['d124_component_disposition']['sha256']
    accounting=load_module('review_accounting','scripts/evidence/phase6_accounting.py')
    ledger=accounting._load(LEDGER,ROOT)
    handoff=_trusted_handoff(ledger,lane='observer-proof-review',review_path=review_path,
        review_digest=review_digest,bridge_sha=bridge['bridge_sha256'],source_identity=result['source_identity'],
        handoff_key='d123_trusted_review_handoffs' if is_d123 else 'd122_trusted_review_handoffs')
    result['reviewer_identity']=handoff['reviewer_identity'];result['reviewer_role']=handoff['reviewer_role']
    result['trusted_handoff_sha256']=_canonical_digest(handoff)
    result['check_sha256']=_canonical_digest(result)
    output=pathlib.Path(output);output=output if output.is_absolute() else ROOT/output
    output.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    if output.exists() or output.is_symlink():raise ValueError('review-check-output-exists-or-symlink')
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    with accounting._locked(LEDGER):
        ledger=accounting._load(LEDGER,ROOT)
        record={'status':'accepted','bridge_sha256':bridge['bridge_sha256'],'review_sha256':review_digest,
            'review_check_sha256':result['check_sha256'],'source_identity':result['source_identity'],
            'reviewer_identity':handoff['reviewer_identity']}
        if is_d124:
            policy=accounting._validate_d124_policy(ledger,project_root=ROOT)
            old=ledger.get('d123_observer_bridge_binding',{})
            component=bridge['d124_component_disposition']
            if (old.get('status')!='independently-accepted' or
                    ledger.get('d123_observer_review',{}).get('status')!='accepted' or
                    component.get('status')!='pending-independent-review' or
                    component.get('current_source_identity')!=result['source_identity']):
                raise ValueError('d124-review-does-not-preserve-d123-authority')
            ledger['d124_component_disposition']={'status':'independently-accepted',
                'sha256':component['sha256'],'prior_bridge_sha256':component['prior_bridge_sha256'],
                'review_sha256':review_digest,'review_check_sha256':result['check_sha256'],
                'reviewer_identity':handoff['reviewer_identity'],
                'trusted_handoff_sha256':result['trusted_handoff_sha256']}
            ledger['d124_observer_review']={**record,'status':'accepted',
                'component_disposition_sha256':component['sha256'],
                'reviewer_identity':handoff['reviewer_identity']}
            ledger['d124_observer_bridge_binding']={'status':'independently-accepted',
                'bridge_path':result['bridge_path'],'bridge_file_sha256':sha(bridge_path),
                'bridge_sha256':bridge['bridge_sha256'],'review_path':result['review_path'],
                'review_file_sha256':review_digest,'review_sha256':review_digest,
                'review_check_path':output.relative_to(ROOT).as_posix(),
                'review_check_file_sha256':sha(output),'review_check_sha256':result['check_sha256'],
                'trusted_handoff_sha256':result['trusted_handoff_sha256'],
                'd123_bridge_sha256':old['bridge_sha256'],'d123_review_sha256':old['review_sha256'],
                'd123_trusted_handoff_sha256':old['trusted_handoff_sha256'],
                'component_disposition_sha256':component['sha256'],
                'source_identity':result['source_identity'],
                'control_client_binary_sha256':bridge['control_client_binary_sha256']}
            ledger['tank_proof_revalidation']={'status':'passed','source_identity':result['source_identity'],
                'binary_identity':bridge['control_client_binary_sha256'],'contract_identity':bridge['bridge_sha256'],
                'bridge_sha256':bridge['bridge_sha256'],'capture_descriptor_sha256':bridge['capture_descriptor_sha256'],
                'verifier_sha256':result['checker_sha256']}
            accounting._write(LEDGER,ledger)
            return result
        if is_d123:
            prior=ledger.get('d123_observer_bridge',{})
            if prior.get('status')!='bridge-built-review-pending' or prior.get('bridge_sha256')!=bridge['bridge_sha256']:
                raise ValueError('ledger-d123-observer-bridge-binding-mismatch')
            ledger['d123_observer_review']={'status':'accepted','bridge_sha256':bridge['bridge_sha256'],
                'review_sha256':review_digest,'source_identity':result['source_identity'],
                'reviewer_identity':handoff['reviewer_identity'],'review_check_sha256':result['check_sha256'],
                'manifest_sha256':bridge['manifest_sha256'],
                'qualification_sha256':bridge['qualification_sha256']}
            ledger['d123_observer_bridge_binding']={'status':'independently-accepted',
                'bridge_sha256':bridge['bridge_sha256'],'review_sha256':review_digest,
                'trusted_handoff_sha256':result['trusted_handoff_sha256'],'review_check_sha256':result['check_sha256'],
                'manifest_sha256':bridge['manifest_sha256'],'qualification_sha256':bridge['qualification_sha256'],
                'source_identity':result['source_identity'],'binary_identity':bridge['control_client_binary_sha256']}
            ledger['tank_proof_revalidation']={'status':'passed','source_identity':result['source_identity'],
                'binary_identity':bridge['control_client_binary_sha256'],'contract_identity':bridge['bridge_sha256'],
                'bridge_sha256':bridge['bridge_sha256'],'capture_descriptor_sha256':bridge['capture_descriptor_sha256'],
                'verifier_sha256':result['checker_sha256']}
            accounting._write(LEDGER,ledger)
            return result
        prior=ledger.get('d122_observer_bridge',{})
        if prior.get('status')!='bridge-built-review-pending' or prior.get('bridge_sha256')!=bridge['bridge_sha256']:
            raise ValueError('ledger-observer-bridge-binding-mismatch')
        ledger['d122_observer_review']=record
        ledger['d122_observer_bridge_binding']={'status':'independently-accepted',
            'bridge_sha256':bridge['bridge_sha256'],'review_sha256':review_digest,
            'review_check_sha256':result['check_sha256'],'source_identity':result['source_identity'],
            'reviewer_identity':handoff['reviewer_identity'],'trusted_handoff_sha256':result['trusted_handoff_sha256']}
        ledger['tank_proof_revalidation']={'status':'passed','source_identity':result['source_identity'],
            'binary_identity':bridge['control_client_binary_sha256'],'contract_identity':bridge['bridge_sha256'],
            'bridge_sha256':bridge['bridge_sha256'],'capture_descriptor_sha256':bridge['capture_descriptor_sha256'],
            'verifier_sha256':result['checker_sha256']}
        accounting._write(LEDGER,ledger)
    return result

def verify_acceptance_review(check_path,bridge_path,build):
    if json.loads(project_input_path(bridge_path).read_bytes()).get('recovery_owner')=='06-22':
        return _verify_d125_acceptance_review(check_path,bridge_path,build)
    bridge=verify_observer_bridge(bridge_path,build);check=json.loads(project_input_path(check_path).read_bytes())
    unsigned={k:v for k,v in check.items() if k!='check_sha256'}
    is_d123=bridge.get('schema')=='phase6-tank-observer-bridge-d123-v1'
    is_d124=bridge.get('d124_component_disposition') is not None
    expected_schema='phase6-d124-observer-review-check-v1' if is_d124 else ('phase6-d123-observer-review-check-v1' if is_d123 else 'phase6-d122-observer-review-check-v1')
    if check.get('status')!='accepted' or check.get('check_sha256')!=_canonical_digest(unsigned) or \
       check.get('schema')!=expected_schema or check.get('bridge_sha256')!=bridge['bridge_sha256'] or \
       check.get('source_identity')!=current_source_identity() or \
       (is_d123 and (check.get('manifest_sha256')!=bridge.get('manifest_sha256') or
                     check.get('qualification_sha256')!=bridge.get('qualification_sha256'))) or \
       (is_d124 and check.get('component_disposition_sha256')!=bridge.get('d124_component_disposition',{}).get('sha256')):
        raise ValueError('current-independent-acceptance-binding-invalid')
    review_path=safe_retained_path(check.get('review_path'),ROOT)
    if sha(review_path)!=check.get('review_sha256') or check.get('checker_sha256')!=sha(pathlib.Path(__file__)):
        raise ValueError('independent-review-file-or-checker-drift')
    is_d123=bridge.get('schema')=='phase6-tank-observer-bridge-d123-v1'
    ledger=json.loads(LEDGER.read_text());record=ledger.get('d124_observer_review' if is_d124 else ('d123_observer_review' if is_d123 else 'd122_observer_review'),{})
    for key in ('bridge_sha256','review_sha256','review_check_sha256','source_identity','reviewer_identity'):
        if record.get(key)!=check.get(key if key!='review_check_sha256' else 'check_sha256'):
            raise ValueError('ledger-independent-review-binding-mismatch:'+key)
    proof=ledger.get('tank_proof_revalidation',{})
    handoff=_trusted_handoff(ledger,lane='observer-proof-review',review_path=review_path,
        review_digest=check.get('review_sha256'),bridge_sha=bridge['bridge_sha256'],
        source_identity=current_source_identity(),handoff_key='d123_trusted_review_handoffs' if is_d123 else 'd122_trusted_review_handoffs')
    binding=ledger.get('d124_observer_bridge_binding' if is_d124 else ('d123_observer_bridge_binding' if is_d123 else 'd122_observer_bridge_binding'),{})
    if binding.get('status')!='independently-accepted' or binding.get('trusted_handoff_sha256')!=_canonical_digest(handoff) or \
       binding.get('bridge_sha256')!=bridge['bridge_sha256'] or binding.get('review_sha256')!=check.get('review_sha256') or \
       (is_d124 and (binding.get('review_check_sha256')!=check.get('check_sha256') or
        binding.get('component_disposition_sha256')!=bridge.get('d124_component_disposition',{}).get('sha256') or
        binding.get('review_check_path')!=pathlib.Path(check_path).resolve().relative_to(ROOT).as_posix() or
        binding.get('review_check_file_sha256')!=sha(project_input_path(check_path)))) or \
       proof.get('status')!='passed' or proof.get('source_identity')!=current_source_identity() or \
       proof.get('contract_identity')!=bridge['bridge_sha256'] or proof.get('binary_identity')!=bridge['control_client_binary_sha256']:
        raise ValueError('current-d123-authorization-ledger-binding-invalid' if is_d123 else 'current-d122-authorization-ledger-binding-invalid')
    return {'status':'accepted-current-review','bridge_sha256':bridge['bridge_sha256'],'launches':0}

def verify_receipt_file(path,bridge_path,proof_review_path,build,output,acceptance_review,review_check_path):
    if json.loads(project_input_path(bridge_path).read_bytes()).get('recovery_owner')=='06-22':
        return _verify_d125_receipt_file(path,bridge_path,proof_review_path,build,output,acceptance_review,review_check_path)
    bridge=verify_observer_bridge(bridge_path,build);verify_acceptance_review(review_check_path,bridge_path,build)
    review_check_path=project_input_path(review_check_path)
    review_check_file_sha256=sha(review_check_path)
    proof_check=json.loads(review_check_path.read_bytes())
    if project_input_path(proof_review_path).relative_to(ROOT).as_posix()!=proof_check.get('review_path'):
        raise ValueError('plan14-proof-review-input-path-mismatch')
    path=project_input_path(path);receipt_bytes=path.read_bytes();receipt=json.loads(receipt_bytes)
    actual_source=current_source_identity();client=build/'tools/session/gw_headless';binary=sha(client)
    control_binary=sha(build/'tools/session/gw_headless')
    if actual_source!=bridge.get('current_source_closure',{}).get('source_identity') or binary!=bridge.get('control_client_binary_sha256') or \
       control_binary!=bridge.get('control_client_binary_sha256'):
        raise ValueError('current-source-or-native-binary-drift')
    if receipt.get('proof_revalidation_sha256')!=bridge.get('bridge_sha256'):raise ValueError('receipt-bridge-digest-mismatch')
    counts=validate_receipt_data(receipt,bridge,root=ROOT,ledger_path=LEDGER)
    ledger=json.loads(LEDGER.read_text());matches=[r for r in ledger['records'] if r.get('record_id')==receipt['reservation']['record_id']]
    if len(matches)!=1 or matches[0]!=receipt['reservation']:raise ValueError('receipt-ledger-reservation-mismatch')
    pointer=ledger.get('current_tank_continuation_receipt',{})
    capture_id=sha_bytes((matches[0]['record_id']+receipt['native_report_sha256']+bridge['bridge_sha256']).encode())
    if pointer.get('status') not in ('captured','passed') or pointer.get('capture_sha256')!=capture_id:
        raise ValueError('ledger-current-capture-pointer-mismatch')
    if pointer.get('status')=='passed' and (pointer.get('independently_checked') is not True or
       pointer.get('checked_receipt_sha256')!=sha_bytes(receipt_bytes)):
        raise ValueError('ledger-current-checked-pointer-mismatch')
    acceptance_path=project_input_path(acceptance_review);acceptance_bytes=acceptance_path.read_bytes()
    acceptance=json.loads(acceptance_bytes);acceptance_digest=sha_bytes(acceptance_bytes)
    if acceptance.get('disposition')!='accepted' or acceptance.get('receipt_sha256')!=sha_bytes(receipt_bytes) or \
       acceptance.get('bridge_sha256')!=bridge['bridge_sha256'] or acceptance.get('source_identity')!=actual_source or \
       acceptance.get('processes')!=3 or acceptance.get('control_cases')!=12:
        raise ValueError('d122-final-acceptance-review-content-invalid')
    accounting=load_module('checked_receipt_accounting','scripts/evidence/phase6_accounting.py')
    ledger=accounting._load(LEDGER,ROOT);_trusted_handoff(ledger,lane='tank-final-acceptance',
        review_path=acceptance_path,review_digest=acceptance_digest,bridge_sha=bridge['bridge_sha256'],
        source_identity=actual_source,receipt_sha=sha_bytes(receipt_bytes))
    d124=bool(ledger.get('d124_recovery_policy'))
    if not d124:accounting.validate_d122_exception(ledger)
    process_rows=[r for r in ledger.get('records',[]) if r.get('plan')=='06-14' and
        r.get('purpose') in ('tank-continuation','tank-continuation-control')]
    expected_cases={'tank-pea-continuation-1','control-repeat-1','control-repeat-2'}
    if len(process_rows)!=3 or {r.get('case') for r in process_rows}!=expected_cases or \
       any(r.get('status')!='completed' for r in process_rows) or \
       sum(r.get('new_target_attempts',0) for r in process_rows)!=1 or \
       any(r.get('new_target_attempts',0)!=0 for r in process_rows if r.get('purpose')=='tank-continuation-control') or \
       (not d124 and any(r.get('status')=='active' for r in ledger.get('d122_accounting',{}).get('other_charges',[]))):
        raise ValueError('d122-final-accounting-closure-invalid')
    if d124:
        required_stages={'preflight','interprocess','final-review','closeout','final-check'}
        runs=[r for r in ledger.get('d124_runs',[]) if r.get('status')=='completed']
        if not required_stages.issubset({r.get('stage') for r in runs}):
            raise ValueError('d124-final-activity-closure-incomplete')
    else:
        required_other={'tank-preflight','tank-interprocess','independent-final-review','d122-closeout'}
        other=ledger.get('d122_accounting',{}).get('other_charges',[])
        if not required_other.issubset({r.get('purpose') for r in other if r.get('status')=='completed'}):
            raise ValueError('d122-final-other-purpose-charge-missing')
    result={'schema':'phase6-tank-continuation-checked-v1','status':'independently-checked','independently_checked':True,
       'receipt_sha256':sha_bytes(receipt_bytes),'bridge_sha256':bridge['bridge_sha256'],
       'acceptance_review_sha256':acceptance_digest,
       'source_identity':actual_source,'native_binary_sha256':binary,'checker_sha256':sha(pathlib.Path(__file__)),
       'counts':counts,'reservation_record_id':matches[0]['record_id'],'launches':0,
       'observer_review_check_file_sha256':review_check_file_sha256}
    result['selected_bridge_file_sha256']=sha(bridge_path)
    result['selected_bridge_path']=pathlib.Path(bridge_path).relative_to(ROOT).as_posix()
    result['selected_proof_review_file_sha256']=sha(proof_review_path)
    return _commit_checked_receipt_output(output,result,accounting=accounting,capture_id=capture_id,
        acceptance_path=acceptance_path,acceptance_digest=acceptance_digest,bridge=bridge,
        source_identity=actual_source,proof_check=proof_check,review_check_path=review_check_path,
        bridge_path=bridge_path,proof_review_path=proof_review_path)

def _fake_receipt(tmp):
    base=0xa5ff000c
    addresses=[(base+i)&0xffffff for i in range(4)]
    before={'pc':0xec32,'sr':0x2700,'tick':1000,'instructions':5,'diagnostic_dropped':0,'d':[0]*8,'a':[0]*7+[0xa5ff0010],
            'spans':[{'address':0xec32,'bytes':'48790006923c'}],
            'stack_observation':{'source_a7':0xa5ff0010,'base32':base,'addresses24':addresses,
                'read_calls':4,'bytes':[0,0,0,0],'status':[0,0,0,0],'disposition':'observed'}}
    after={'pc':0xec38,'sr':0x2700,'tick':1140,'instructions':6,'diagnostic_dropped':0,'d':[0]*8,'a':[0]*7+[0xa5ff000c],
           'spans':[{'address':0xec32,'bytes':'48790006923c'}],
           'stack_observation':{'source_a7':0xa5ff0010,'base32':base,'addresses24':addresses,
                'read_calls':4,'bytes':[0,6,0x92,0x3c],'status':[0,0,0,0],'disposition':'observed'}}
    pair={'instruction_address':0xec32,'opcode':0x4879,'stop_reason':0,'target_tick':1001,'returned_overshoot':139,
          'fields':0,'active_ticks':0,'retired':True,'before':before,'after':after}
    last={'instruction_address':0xec38,'opcode':0x4afc,'stop_reason':2,'target_tick':1141,'returned_overshoot':27,
          'fields':0,'active_ticks':0,'retired':False,'before':after,'after':dict(after,pc=0xec3a,tick=1168)}
    native={'schema':'genewhip-route-native-v1','stop_reason':2,'instruction_address':0xec38,'opcode':0x4afc,
        'first_stop_tick':1168,'final_tick':1168,'fields':0,'active_ticks':0,'boundary_calls':4,'queue_high_water':0,
        'probe_boundary':pair,'last_boundary':last}
    pcm=tmp/'case.pcm';pcm.write_bytes(b'PCM')
    ids=['title-no-start','start-idle','start-move','action-sound','action-no-trigger','sustained-play']
    controls=[]
    for rep in (1,2):
        rows=[]
        for name in ids: rows.append({'id':name,'retained_pcm':{'path':'case.pcm','bytes':3,'sha256':sha(pcm)}})
        controls.append({'repetition':rep,'status':'pass','cases':6,'results':rows,
            'native_child_processes':[{'case':x,'return_code':0} for x in ids]})
    raw=json.dumps(native,separators=(',',':'))
    return {'schema':'phase6-tank-continuation-v1','status':'passed-capture','reservation':{
      'record_id':'GW-06-AUTH-tank-continuation-tank-pea-continuation-1','purpose':'tank-continuation','plan':'06-14',
      'new_target_attempts':1,'process_count':1,'case_count':1,'status':'completed'},
      'source_identity':'a'*64,'proof_revalidation_sha256':'c'*64,'client_binary_sha256':'b'*64,
      'capture_descriptor_sha256':'d'*64,'native_report_raw':raw,'native_report_sha256':sha_bytes(raw.encode()),
      'native_report':native,'processes':[{'return_code':1,'bound_violation':False}],
      'process_streams':{k:{'text':'','truncated':False,'retained_bytes':0,'observed_bytes':0,'sha256':sha_bytes(b'')} for k in ('stdout','stderr')},
      'controls':controls}

def self_test():
    good_bridge={'current_source_identity':'a'*64,'native_binary_sha256':'e'*64,'control_client_binary_sha256':'b'*64,
        'bridge_sha256':'c'*64,'capture_descriptor_sha256':'d'*64}
    with tempfile.TemporaryDirectory(prefix='tank-proof-self-test-') as directory:
        tmp=pathlib.Path(directory);base=_fake_receipt(tmp);validate_receipt_data(base,good_bridge,root=tmp,check_controls=False)
        mutants=[]
        def mutate(name,fn):
            item=json.loads(json.dumps(base));fn(item);mutants.append((name,item))
        mutate('forged-pass',lambda r:r.update(status='passed-fake'))
        mutate('missing-pair',lambda r:r['native_report'].update(probe_boundary=None))
        mutate('wrong-pair',lambda r:r['native_report']['probe_boundary']['before'].update(pc=0xec30))
        mutate('pea-timing',lambda r:r['native_report']['probe_boundary']['after'].update(tick=1139))
        mutate('pea-ea',lambda r:r['native_report']['probe_boundary']['before']['spans'][0].update(bytes='48790006923d'))
        mutate('pea-stack',lambda r:r['native_report']['probe_boundary']['after']['stack_observation'].update(bytes=[0,6,0x92,0x3d]))
        mutate('pea-sr',lambda r:r['native_report']['probe_boundary']['after'].update(sr=0x2701))
        mutate('terminal-disagreement',lambda r:r['native_report'].update(final_tick=99))
        mutate('timeout',lambda r:r['processes'][0].update(timed_out=True))
        mutate('truncation',lambda r:r['process_streams']['stdout'].update(truncated=True))
        mutate('wrong-source',lambda r:r.update(source_identity='0'*64))
        mutate('wrong-binary',lambda r:r.update(client_binary_sha256='0'*64))
        mutate('missing-control',lambda r:r.update(controls=r['controls'][:1]))
        mutate('control-denominator',lambda r:r['controls'][0].update(cases=5))
        mutate('missing-pcm',lambda r:r['controls'][0]['results'][0].update(retained_pcm={'path':'missing.pcm','bytes':3,'sha256':'0'*64}))
        mutate('replayed-reservation',lambda r:r['reservation'].update(record_id='GW-06-AUTH-independent-pea-tank-pea-regression'))
        failures=[]
        for name,item in mutants:
            try:validate_receipt_data(item,good_bridge,root=tmp,check_controls=False)
            except (OSError,ValueError,KeyError,TypeError):continue
            failures.append(name)
        if failures:raise ValueError('self-test-mutants-accepted:'+','.join(failures))
        if len(mutants)>64:raise ValueError('self-test-case-bound-exceeded')
        review_bridge={'bridge_sha256':'c'*64,'current_source_closure':{'source_identity':'a'*64}}
        sections=['historical-source-and-assertion-closure','actual-observer-rows-and-binaries',
            'stack-read-ownership-and-same-pc-path','raw-process-stream-and-control-pcm-retention',
            'd122-partitions-and-active-anchor','downstream-authorization-gates']
        valid={'bridge_sha256':'c'*64,'source_identity':'a'*64,'disposition':'accepted',
            'reviewer_role':'independent-reviewer','reviewer_identity':'external-review-role-1',
            'reviewed_sections':sections,'findings':[]}
        validate_review_payload(valid,review_bridge)
        review_mutants=[]
        for name,mutate_payload in (
            ('review-hash',lambda x:x.update(bridge_sha256='0'*64)),
            ('review-source',lambda x:x.update(source_identity='0'*64)),
            ('self-review',lambda x:x.update(reviewer_identity='phase6-executor')),
            ('review-open-high',lambda x:x.update(findings=[{'severity':'high','finding':'unresolved'}])),
            ('review-coverage',lambda x:x.update(reviewed_sections=sections[:-1])),
        ):
            mutant=json.loads(json.dumps(valid));mutate_payload(mutant);review_mutants.append((name,mutant))
        accepted=[]
        for name,mutant in review_mutants:
            try:validate_review_payload(mutant,review_bridge)
            except (ValueError,KeyError,TypeError):continue
            accepted.append(name)
        if accepted:raise ValueError('proof-review-mutants-accepted:'+','.join(accepted))
        control_mutants=_control_retention_self_test(tmp)
        bounded_results=_bounded_runner_self_test()
        cli_cases=_cli_argument_self_test()
        receipt_cli=_planned_receipt_cli_self_test()
        review_cli=_review_cli_integration_self_test()
        output_transaction=_checked_output_transaction_self_test()
        deadline_runner=_deadline_process_timeout_self_test()
        binary_retention=_binary_retention_self_test()
    return {'status':'passed','read_only':True,'mutants_rejected':len(mutants)+len(review_mutants),'guest_launches':0,
        'review_denials':len(review_mutants),'control_denials':control_mutants,'bounded_runner':bounded_results,
        'cli_argument_sets':cli_cases,'receipt_cli_dispatch':receipt_cli,'review_cli':review_cli,
        'output_transaction':output_transaction,'deadline_runner':deadline_runner,'binary_retention':binary_retention}

def _cli_argument_self_test():
    parser=cli_parser();cases=[
        ['--verify-observer-bridge','evidence/phase6-tank-observer-bridge.json','--build','build/phase6'],
        ['--verify-proof-review','--bridge','evidence/phase6-tank-observer-bridge.json','--proof-review',
         '.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-19-PROOF-REVIEW.md',
         '--build','build/phase6','--output','evidence/phase6-tank-observer-review-check.json'],
        ['--verify-18-review','--bridge','evidence/phase6-tank-observer-bridge.json',
         '--review-check','evidence/phase6-tank-observer-review-check.json','--build','build/phase6'],
        ['--verify-receipt','evidence/phase6-tank-continuation.json','--bridge',
         'evidence/phase6-tank-observer-bridge.json','--proof-review',
         '.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-19-PROOF-REVIEW.md',
         '--review-check','evidence/phase6-tank-observer-review-check.json',
         '--build','build/phase6','--acceptance-review',
         '.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-14-ACCEPTANCE-REVIEW.md',
         '--output','evidence/phase6-tank-continuation-check.json'],
        ['--create-observer-bridge','--build','build/phase6','--proof-rows',
         'build/phase6/d122-observer/observer-proof-rows.json','--output','evidence/phase6-tank-observer-bridge.json'],
        ['--d124-revalidate-components','--prior-bridge','evidence/phase6-tank-observer-bridge-d123-g02.json',
         '--component-review','.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-20-PRELAUNCH-REVIEW.md',
         '--build','build/phase6','--bridge-output','evidence/phase6-tank-observer-bridge-d124-g01.json']]
    for argv in cases:parser.parse_args(argv)
    return len(cases)

def _planned_receipt_cli_self_test():
    argv=['checker','--verify-receipt','evidence/phase6-tank-continuation.json','--bridge',
        'evidence/phase6-tank-observer-bridge.json','--proof-review',
        '.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-18-PROOF-REVIEW.md',
        '--review-check','evidence/phase6-tank-observer-review-check.json',
        '--build','build/phase6','--acceptance-review',
        '.planning/phases/GW-06-shared-repairs-and-two-playable-routes/06-14-ACCEPTANCE-REVIEW.md',
        '--output','evidence/phase6-tank-continuation-check.json']
    captured=io.StringIO();calls=[]
    def fake_check(*args):calls.append(args);return {'status':'fake-dispatch','launches':0}
    with mock.patch.object(sys,'argv',argv),mock.patch(__name__+'.verify_receipt_file',side_effect=fake_check),contextlib.redirect_stdout(captured):
        if main()!=0:raise ValueError('plan14-exact-cli-dispatch-failed')
    result=json.loads(captured.getvalue())
    if result.get('status')!='fake-dispatch' or len(calls)!=1 or len(calls[0])!=7:
        raise ValueError('plan14-exact-cli-inputs-not-dispatched')
    return {'exact_plan_command_dispatched':True,'fake_calls':1,'guest_launches':0}

def _checked_output_transaction_self_test():
    parent=ROOT/'build/phase6'
    with tempfile.TemporaryDirectory(prefix='receipt-output-transaction-',dir=parent) as name:
        work=pathlib.Path(name);real_ledger=LEDGER;real_review_check=REVIEW_CHECK
        source=current_source_identity();bridge_sha='b'*64;receipt_sha='f'*64;capture_sha='e'*64
        accounting=load_module('receipt_transaction_accounting','scripts/evidence/phase6_accounting.py')
        def prepare(label):
            directory=work/label;directory.mkdir();ledger_path=directory/'ledger.json'
            value=json.loads(real_ledger.read_bytes())
            value.pop('d124_recovery_policy',None);value.pop('d124_runs',None)
            value.pop('d124_admissions',None);value.pop('d124_component_disposition',None)
            value.pop('d124_observer_bridge_binding',None)
            rows=[]
            for purpose,case,attempts in (('tank-continuation','tank-pea-continuation-1',1),
                ('tank-continuation-control','control-repeat-1',0),('tank-continuation-control','control-repeat-2',0)):
                rows.append({'record_id':f'test-{label}-{case}','record_type':'authorization-reservation',
                    'purpose':purpose,'plan':'06-14','case':case,'new_target_attempts':attempts,
                    'status':'completed','process_active_seconds':0.01})
            value['records'].extend(rows)
            value['current_tank_continuation_receipt']={'status':'captured','capture_sha256':capture_sha,
                'record_id':rows[0]['record_id']}
            value['d122_accounting']['other_charges']=[{'interval_id':f'{label}-{purpose}',
                'purpose':purpose,'seconds':0.01,'status':'completed'} for purpose in
                ('tank-preflight','tank-interprocess','independent-final-review','d122-closeout')]
            proof=directory/'proof-review.md';proof.write_text('fake externally reviewed proof')
            acceptance=directory/'acceptance-review.json'
            acceptance_doc={'disposition':'accepted','receipt_sha256':receipt_sha,'bridge_sha256':bridge_sha,
                'source_identity':source,'processes':3,'control_cases':12}
            acceptance.write_text(json.dumps(acceptance_doc,sort_keys=True)+'\n')
            acceptance_sha=sha(acceptance)
            review_check={'status':'accepted','bridge_sha256':bridge_sha,'source_identity':source,
                'review_path':proof.relative_to(ROOT).as_posix(),'review_sha256':sha(proof)}
            review_check['check_sha256']=_canonical_digest(review_check)
            review_check_path=directory/'proof-review-check.json';review_check_path.write_text(json.dumps(review_check,sort_keys=True)+'\n')
            handoffs=[{'lane':'observer-proof-review','status':'completed','review_path':review_check['review_path'],
                'review_sha256':review_check['review_sha256'],'bridge_sha256':bridge_sha,'source_identity':source,
                'tool_handoff_result':'completed','reviewer_role':'gsd-code-reviewer',
                'reviewer_identity':'external-reviewer-18','producer_identity':'executor-18',
                'disposition':'accepted','critical_findings':0,'high_findings':0},
                {'lane':'tank-final-acceptance','status':'completed','review_path':acceptance.relative_to(ROOT).as_posix(),
                'review_sha256':acceptance_sha,'bridge_sha256':bridge_sha,'source_identity':source,
                'receipt_sha256':receipt_sha,'tool_handoff_result':'completed','reviewer_role':'gsd-code-reviewer',
                'reviewer_identity':'external-reviewer-14','producer_identity':'executor-18',
                'disposition':'accepted','critical_findings':0,'high_findings':0}]
            value['d122_trusted_review_handoffs']=handoffs
            proof_handoff=_canonical_digest(handoffs[0])
            value['d122_observer_bridge_binding']={'status':'independently-accepted','bridge_sha256':bridge_sha,
                'review_sha256':review_check['review_sha256'],'trusted_handoff_sha256':proof_handoff}
            value['d122_observer_review']={'review_sha256':review_check['review_sha256'],
                'review_check_sha256':review_check['check_sha256']}
            ledger_path.write_text(json.dumps(value,sort_keys=True))
            result={'schema':'phase6-tank-continuation-checked-v1','status':'independently-checked',
                'independently_checked':True,'receipt_sha256':receipt_sha,'bridge_sha256':bridge_sha,
                'acceptance_review_sha256':acceptance_sha,'source_identity':source,
                'checker_sha256':sha(pathlib.Path(__file__)),'counts':{},
                'reservation_record_id':rows[0]['record_id'],'launches':0,
                'observer_review_check_file_sha256':sha(review_check_path)}
            return ledger_path,acceptance,acceptance_sha,review_check,result
        def commit_one(ledger_path,acceptance,acceptance_sha,review_check,result,out):
            with mock.patch.dict(globals(),{'LEDGER':ledger_path}):
                return _commit_checked_receipt_output(out,result,accounting=accounting,capture_id=capture_sha,
                    acceptance_path=acceptance,acceptance_digest=acceptance_sha,
                    bridge={'bridge_sha256':bridge_sha},source_identity=source,proof_check=review_check,
                    review_check_path=pathlib.Path(acceptance).parent/'proof-review-check.json')
        # Output creation fails before the ledger is touched; exact retry recovers.
        l1,a1,ad1,p1,r1=prepare('output-failure');o1=work/'output-failure'/'checked.json'
        with mock.patch.dict(globals(),{'LEDGER':l1,'REVIEW_CHECK':work/'output-failure'/'proof-review-check.json'}), \
             mock.patch(__name__+'._atomic_publish_checked_output',side_effect=OSError('fake output create failure')):
            try:_commit_checked_receipt_output(o1,r1,accounting=accounting,capture_id=capture_sha,
                acceptance_path=a1,acceptance_digest=ad1,bridge={'bridge_sha256':bridge_sha},
                source_identity=source,proof_check=p1,review_check_path=o1.parent/'proof-review-check.json')
            except OSError:pass
            else:raise ValueError('fake-output-failure-not-raised')
            if json.loads(l1.read_text())['current_tank_continuation_receipt']['status']!='captured' or o1.exists():
                raise ValueError('output-failure-mutated-ledger-or-left-artifact')
        with mock.patch.dict(globals(),{'LEDGER':l1,'REVIEW_CHECK':work/'output-failure'/'proof-review-check.json'}):
            commit_one(l1,a1,ad1,p1,r1,o1)
        if json.loads(l1.read_text())['current_tank_continuation_receipt']['status']!='passed':
            raise ValueError('output-failure-retry-did-not-promote')
        # Ledger commit fails after durable publication; exact retry promotes without rerunning work.
        l2,a2,ad2,p2,r2=prepare('ledger-failure');o2=work/'ledger-failure'/'checked.json'
        original_write=accounting._write;calls=[]
        def fail_once(*args,**kwargs):
            calls.append(True)
            if len(calls)==1:raise OSError('fake ledger commit failure')
            return original_write(*args,**kwargs)
        with mock.patch.dict(globals(),{'LEDGER':l2,'REVIEW_CHECK':work/'ledger-failure'/'proof-review-check.json'}), \
             mock.patch.object(accounting,'_write',side_effect=fail_once):
            try:_commit_checked_receipt_output(o2,r2,accounting=accounting,capture_id=capture_sha,
                acceptance_path=a2,acceptance_digest=ad2,bridge={'bridge_sha256':bridge_sha},
                source_identity=source,proof_check=p2,review_check_path=o2.parent/'proof-review-check.json')
            except OSError:pass
            else:raise ValueError('fake-ledger-failure-not-raised')
            if not o2.is_file() or json.loads(l2.read_text())['current_tank_continuation_receipt']['status']!='captured':
                raise ValueError('ledger-failure-did-not-preserve-recoverable-prefix')
            _commit_checked_receipt_output(o2,r2,accounting=accounting,capture_id=capture_sha,
                acceptance_path=a2,acceptance_digest=ad2,bridge={'bridge_sha256':bridge_sha},
                source_identity=source,proof_check=p2,review_check_path=o2.parent/'proof-review-check.json')
        # Different pre-existing bytes and links are immutable conflicts.
        l3,a3,ad3,p3,r3=prepare('changed-output');o3=work/'changed-output'/'checked.json'
        o3.write_text('counterfeit')
        with mock.patch.dict(globals(),{'LEDGER':l3,'REVIEW_CHECK':work/'changed-output'/'proof-review-check.json'}):
            try:_commit_checked_receipt_output(o3,r3,accounting=accounting,capture_id=capture_sha,
                acceptance_path=a3,acceptance_digest=ad3,bridge={'bridge_sha256':bridge_sha},
                source_identity=source,proof_check=p3,review_check_path=o3.parent/'proof-review-check.json')
            except ValueError as exc:
                if str(exc)!='checked-output-existing-content-mismatch':raise
            else:raise ValueError('counterfeit-existing-output-accepted')
            if json.loads(l3.read_text())['current_tank_continuation_receipt']['status']!='captured':
                raise ValueError('changed-output-promoted-ledger')
        stale_mutations=('source','bridge','review','accounting','pointer')
        for mutation in stale_mutations:
            ledger_path,acceptance_path,acceptance_hash,check,result=prepare('stale-'+mutation)
            output=work/('stale-'+mutation)/'checked.json'
            current=json.loads(ledger_path.read_text())
            if mutation=='bridge':
                current['d122_trusted_review_handoffs'][1]['bridge_sha256']='0'*64
                ledger_path.write_text(json.dumps(current,sort_keys=True))
            elif mutation=='accounting':
                current['d122_accounting']['other_charges']=[row for row in current['d122_accounting']['other_charges']
                    if row.get('purpose')!='d122-closeout']
                ledger_path.write_text(json.dumps(current,sort_keys=True))
            elif mutation=='pointer':
                current['current_tank_continuation_receipt']['capture_sha256']='0'*64
                ledger_path.write_text(json.dumps(current,sort_keys=True))
            elif mutation=='review':
                acceptance_path.write_bytes(acceptance_path.read_bytes()+b' ')
            with mock.patch.dict(globals(),{'LEDGER':ledger_path,'REVIEW_CHECK':work/('stale-'+mutation)/'proof-review-check.json'}):
                source_patch=mock.patch(__name__+'.current_source_identity',return_value='0'*64) if mutation=='source' else contextlib.nullcontext()
                with source_patch:
                    try:_commit_checked_receipt_output(output,result,accounting=accounting,capture_id=capture_sha,
                        acceptance_path=acceptance_path,acceptance_digest=acceptance_hash,
                        bridge={'bridge_sha256':bridge_sha},source_identity=source,proof_check=check,
                        review_check_path=output.parent/'proof-review-check.json')
                    except (ValueError,OSError):pass
                    else:raise ValueError('stale-'+mutation+'-state-accepted')
            if output.exists() or json.loads(ledger_path.read_text())['current_tank_continuation_receipt'].get('status')=='passed':
                raise ValueError('stale-'+mutation+'-created-success-artifact-or-promoted-pointer')
        return {'output_failure_retry':True,'ledger_failure_retry':True,'changed_existing_output_denied':True,
            'stale_source_bridge_review_accounting_pointer_denied':len(stale_mutations),
            'production_ledger_writes':0,'guest_launches':0}

def _deadline_process_timeout_self_test():
    global D122_OTHER_DEADLINE_MONOTONIC
    old=D122_OTHER_DEADLINE_MONOTONIC;D122_OTHER_DEADLINE_MONOTONIC=100.0
    try:
        with mock.patch.object(time,'monotonic',return_value=99.75), \
             mock.patch.object(subprocess,'check_output',return_value=b'fake blob') as check:
            if git_blob('fake-revision','fake/path')!=b'fake blob':raise ValueError('deadline-git-fake-result-invalid')
            timeout=check.call_args.kwargs.get('timeout')
            if timeout!=0.25:raise ValueError('git-timeout-not-clamped-to-live-deadline')
        with mock.patch.object(time,'monotonic',return_value=100.0):
            try:_deadline_remaining()
            except ValueError as exc:
                if str(exc)!='d122-other-live-deadline-exhausted':raise
            else:raise ValueError('deadline-exhaustion-not-rejected')
        return {'fake_git_calls':1,'timeout_clamped_to_remaining':True,'deadline_exhaustion_denied':True}
    finally:D122_OTHER_DEADLINE_MONOTONIC=old

def _review_cli_integration_self_test():
    global LEDGER
    parent=ROOT/'build/phase6'
    with tempfile.TemporaryDirectory(prefix='review-cli-offline-',dir=parent) as name:
        work=pathlib.Path(name);real_ledger=LEDGER;fake_ledger=work/'phase6-repairs.json'
        ledger_value=json.loads(real_ledger.read_bytes())
        ledger_value['d122_observer_bridge']={'status':'bridge-built-review-pending','bridge_sha256':'c'*64}
        fake_ledger.write_text(json.dumps(ledger_value));LEDGER=fake_ledger
        source=current_source_identity();bridge={'bridge_sha256':'c'*64,
            'current_source_closure':{'source_identity':source},'control_client_binary_sha256':'d'*64,
            'capture_descriptor_sha256':'e'*64}
        bridge_path=work/'bridge.json';bridge_path.write_text(json.dumps(bridge))
        sections=['historical-source-and-assertion-closure','actual-observer-rows-and-binaries',
            'stack-read-ownership-and-same-pc-path','raw-process-stream-and-control-pcm-retention',
            'd122-partitions-and-active-anchor','downstream-authorization-gates']
        review={'bridge_sha256':'c'*64,'source_identity':source,'disposition':'accepted',
            'reviewer_role':'independent-reviewer','reviewer_identity':'external-review-role-2',
            'reviewed_sections':sections,'findings':[]}
        review_path=work/'review.md';review_path.write_text('## Review\n\n```json\n'+json.dumps(review,sort_keys=True)+'\n```\n')
        ledger_value['d122_trusted_review_handoffs']=[{'lane':'observer-proof-review','status':'completed',
            'review_path':review_path.relative_to(ROOT).as_posix(),'review_sha256':sha(review_path),
            'bridge_sha256':'c'*64,'source_identity':source,'tool_handoff_result':'completed',
            'reviewer_role':'gsd-code-reviewer','reviewer_identity':'external-review-role-2',
            'producer_identity':'phase6-executor','disposition':'accepted','critical_findings':0,'high_findings':0}]
        fake_ledger.write_text(json.dumps(ledger_value))
        output=work/'review-check.json';captured=io.StringIO()
        try:
            with mock.patch.dict(globals(),{'LEDGER':fake_ledger}),mock.patch(__name__+'.verify_observer_bridge',return_value=bridge):
                with mock.patch.object(sys,'argv',['checker','--verify-observer-bridge',str(bridge_path),'--build','unused']),contextlib.redirect_stdout(captured):
                    if main()!=0:raise ValueError('observer-bridge-cli-fake-integration-failed')
                with mock.patch.object(sys,'argv',['checker','--verify-proof-review','--bridge',str(bridge_path),
                    '--proof-review',str(review_path),'--build','unused','--output',str(output)]),contextlib.redirect_stdout(captured):
                    if main()!=0:raise ValueError('proof-review-cli-fake-integration-failed:'+captured.getvalue())
                with mock.patch.object(sys,'argv',['checker','--verify-18-review','--bridge',str(bridge_path),
                    '--review-check',str(output),'--build','unused']),contextlib.redirect_stdout(captured):
                    if main()!=0:raise ValueError('acceptance-review-cli-fake-integration-failed')
            checked=json.loads(output.read_bytes());accepted_status=checked.get('status')
            if checked.get('status')!='accepted' or accepted_status!='accepted' or not output.is_file():
                raise ValueError('review-cli-fake-integration-failed')
            d123_bridge={'schema':'phase6-tank-observer-bridge-d123-v1','bridge_sha256':'f'*64,
                'manifest_sha256':'1'*64,'qualification_sha256':'2'*64,'control_client_binary_sha256':'3'*64,
                'capture_descriptor_sha256':'4'*64,'source_identity':source,
                'current_source_closure':{'source_identity':source}}
            d123_bridge_path=work/'bridge-d123.json';d123_bridge_path.write_text(json.dumps(d123_bridge))
            d123_review_path=work/'review-d123.md'
            d123_sections=['historical-source-and-assertion-closure','actual-d123-qualification-and-binaries',
                'stack-read-ownership-and-neighbor-cases','raw-process-stream-and-global-accounting',
                'd123-anchor-and-reserves','downstream-14-launch-guard',
                'component-closure-and-revalidation-disposition']
            d123_review={'bridge_sha256':'f'*64,'source_identity':source,'disposition':'accepted',
                'reviewer_role':'independent-reviewer','reviewer_identity':'external-review-role-3',
                'reviewed_sections':d123_sections,'findings':[]}
            d123_review_path.write_text('## Review\n\n```json\n'+json.dumps(d123_review,sort_keys=True)+'\n```\n')
            current=json.loads(fake_ledger.read_text())
            current['d123_observer_manifest']={'status':'frozen','sha256':'1'*64,'source_identity':source}
            current['d123_observer_bridge']={'status':'bridge-built-review-pending','bridge_sha256':'f'*64}
            current['d123_trusted_review_handoffs']=[{'lane':'observer-proof-review','status':'completed',
                'review_path':d123_review_path.relative_to(ROOT).as_posix(),'review_sha256':sha(d123_review_path),
                'bridge_sha256':'f'*64,'source_identity':source,'tool_handoff_result':'completed',
                'reviewer_role':'gsd-code-reviewer','reviewer_identity':'external-review-role-3',
                'producer_identity':'phase6-executor','disposition':'accepted','critical_findings':0,'high_findings':0}]
            fake_ledger.write_text(json.dumps(current))
            d123_output=work/'review-check-d123.json';d123_stdout=io.StringIO()
            with mock.patch.dict(globals(),{'LEDGER':fake_ledger}),mock.patch(__name__+'.verify_observer_bridge',return_value=d123_bridge):
                with mock.patch.object(sys,'argv',['checker','--verify-proof-review','--bridge',str(d123_bridge_path),
                    '--proof-review',str(d123_review_path),'--build','unused','--output',str(d123_output)]),contextlib.redirect_stdout(d123_stdout):
                    if main()!=0:raise ValueError('d123-proof-review-cli-fake-integration-failed:'+d123_stdout.getvalue())
                with mock.patch.object(sys,'argv',['checker','--verify-18-review','--bridge',str(d123_bridge_path),
                    '--review-check',str(d123_output),'--build','unused']),contextlib.redirect_stdout(d123_stdout):
                    if main()!=0:raise ValueError('d123-acceptance-review-cli-fake-integration-failed:'+d123_stdout.getvalue())
            d123_checked=json.loads(d123_output.read_bytes())
            if d123_checked.get('schema')!='phase6-d123-observer-review-check-v1' or d123_checked.get('status')!='accepted':
                raise ValueError('d123-review-check-not-accepted')
            return {'bridge_review_acceptance_cli_commands':5,'legacy_d122_review_compatible':True,
                'd123_review_accepted':True,'ledger_writes':'temporary-only','actual_launches':0}
        finally:LEDGER=real_ledger

def _binary_retention_self_test():
    manifest_before=sha(ORIGINAL_BINARY_MANIFEST)
    document=json.loads(ORIGINAL_BINARY_MANIFEST.read_bytes())
    binding={'path':ORIGINAL_BINARY_MANIFEST.relative_to(ROOT).as_posix(),
        'sha256':manifest_before,'binary_sha256':{name:row['sha256'] for name,row in document['binaries'].items()}}
    retained=load_original_binary_retention(binding)
    if set(retained['binaries'])!={'native','sanitize','hooks-off'}:
        raise ValueError('historical-binary-retention-denominator-invalid')
    with tempfile.TemporaryDirectory(prefix='retained-closure-check-') as temp:
        verified=revalidate_proof(ROOT/'build/phase6',pathlib.Path(temp)/'closure.json',
            update_ledger=False,binary_retention=retained)
    if verified.get('status')!='passed-no-launch' or verified.get('original_runtime_closure',{}).get('variant_binaries_distinct') is not True:
        raise ValueError('retained-binary-original-closure-recheck-failed')
    if sha(ORIGINAL_BINARY_MANIFEST)!=manifest_before:
        raise ValueError('historical-binary-retention-manifest-mutated')
    return {'variants':3,'all_original_sha256_matched':True,'original_closure_rechecked':True,
        'historical_manifest_unchanged':True,'build_launches':0}

def _bounded_runner_self_test():
    runner=load_module('bounded_runner_fake_test','tests/fixtures/phase4_game.py')
    old_popen=runner.subprocess.Popen;old_killpg=runner.os.killpg;calls=[]
    # Supply both streams through independent pipes, without launching a process.
    plan=[(b'out',b'err'),(b'x'*17,b'')]
    class PipeProcess:
        pid=54321;returncode=0
        def __init__(self,command,**kwargs):
            out,err=plan.pop(0);read_out,write_out=os.pipe();read_err,write_err=os.pipe()
            os.write(write_out,out);os.close(write_out);os.write(write_err,err);os.close(write_err)
            self.stdout=os.fdopen(read_out,'rb');self.stderr=os.fdopen(read_err,'rb')
        def wait(self,*args,**kwargs):return 0
    runner.subprocess.Popen=PipeProcess
    runner.os.killpg=lambda pid,sig:calls.append((pid,sig))
    try:
        result=runner.bounded_run(['fake-only'],timeout=1)
        if result.stdout!=b'out' or result.stderr!=b'err':raise ValueError('bounded-runner-raw-success-mismatch')
        try:runner.bounded_run(['fake-only'],timeout=1,cap=16)
        except runner.BoundedProcessError as exc:
            if len(exc.stdout)!=16 or 'cap' not in str(exc):raise ValueError('bounded-runner-cap-prefix-invalid')
        else:raise ValueError('bounded-runner-cap-not-enforced')
        if len(calls)!=2:raise ValueError('bounded-runner-process-group-cleanup-missing')
        return {'fake_launches':2,'process_group_cleanup':2,'cap_bytes':16}
    finally:runner.subprocess.Popen=old_popen;runner.os.killpg=old_killpg

def _control_retention_self_test(root):
    global control_inputs
    original_control_inputs=control_inputs
    ids=['title-no-start','start-idle','start-move','action-sound','action-no-trigger','sustained-play']
    base_driver=root/'tests/fixtures/phase4_game.py';base_driver.parent.mkdir(parents=True,exist_ok=True);base_driver.write_bytes(b'driver')
    client=root/'build/phase6/tools/session/gw_headless';client.parent.mkdir(parents=True,exist_ok=True);client.write_bytes(b'client')
    driver_hash=sha(base_driver);client_hash=sha(client)
    control_inputs=lambda:{'tests/fixtures/phase4_game.py':driver_hash,'scenario':'a'*64,'oracle':'b'*64}
    try:
        scenario=root/'fixtures/independent-game-v2/scenario.json';scenario.parent.mkdir(parents=True,exist_ok=True)
        scenario.write_text(json.dumps({'cases':[{'id':x} for x in ids]}))
        (scenario.parent/'oracle.json').write_text(json.dumps({'case_ids':ids}))
        results=[]
        for case in ids:
            pcm=root/'controls'/f'{case}.pcm';pcm.parent.mkdir(parents=True,exist_ok=True);pcm.write_bytes(bytes.fromhex('00000100'))
            results.append({'id':case,'pcm_frames':1,'ac_range':1,'score':0,
                'retained_pcm':{'path':pcm.relative_to(root).as_posix(),'bytes':pcm.stat().st_size,'sha256':sha(pcm)}})
        ledger={'records':[{'post_behavior':{'unchanged_control':{'status':'pass','results':results}}}]}
        (root/'evidence').mkdir(exist_ok=True);(root/'evidence/phase6-repairs.json').write_text(json.dumps(ledger))
        report={'outcome':'pass','results':results};runs=[]
        for repetition in (1,2):
            report_path=root/'controls'/f'report-{repetition}.json';report_path.write_text(json.dumps(report))
            driver_streams={};children=[]
            for stream_name in ('stdout','stderr'):
                stream=root/'controls'/f'driver-{repetition}-{stream_name}.raw';stream.write_bytes(b'')
                driver_streams[stream_name]={'path':stream.relative_to(root).as_posix(),'sha256':sha(stream),
                    'retained_bytes':0,'truncated':False}
            for case in ids:
                child_streams={}
                for stream_name in ('stdout','stderr'):
                    stream=root/'controls'/f'{repetition}-{case}-{stream_name}.raw';stream.write_bytes(b'')
                    child_streams[stream_name]={'path':stream.relative_to(root).as_posix(),'sha256':sha(stream),
                        'retained_bytes':0,'truncated':False}
                children.append({'case':case,'return_code':0,'executable_path':'build/phase6/tools/session/gw_headless',
                    'executable_sha256':client_hash,'command_sha256':'c'*64,'streams':child_streams})
            runs.append({'repetition':repetition,'status':'pass','cases':6,'report_path':report_path.relative_to(root).as_posix(),
                'report_sha256':sha(report_path),'results':json.loads(json.dumps(results)),'native_child_processes':children,
                'driver_process':{'return_code':0,'timed_out':False,'bound_violation':False,
                    'executable_path':'tests/fixtures/phase4_game.py','executable_sha256':driver_hash,
                    'client_path':'build/phase6/tools/session/gw_headless','client_sha256':client_hash,
                    'command_sha256':'d'*64,'streams':driver_streams}})
        receipt={'controls':runs};bridge={'control_client_binary_sha256':client_hash}
        validate_control_evidence(receipt,bridge,root=root)
        mutants=[]
        mutants.append(('missing-pcm',lambda x:x['controls'][0]['results'][0]['retained_pcm'].update(sha256='0'*64)))
        mutants.append(('missing-child-stream',lambda x:x['controls'][1]['native_child_processes'][2]['streams'].pop('stderr')))
        mutants.append(('raw-driver-error',lambda x:x['controls'][0]['driver_process']['streams']['stderr'].update(truncated=True)))
        mutants.append(('control-order',lambda x:x['controls'][0]['results'].reverse()))
        mutants.append(('report-hash',lambda x:x['controls'][1].update(report_sha256='0'*64)))
        denied=[]
        for name,mutate_run in mutants:
            bad=json.loads(json.dumps(receipt));mutate_run(bad)
            try:validate_control_evidence(bad,bridge,root=root)
            except (OSError,ValueError,KeyError,TypeError):denied.append(name)
        if len(denied)!=len(mutants):raise ValueError('control-retention-mutant-accepted')
        return len(denied)
    finally:control_inputs=original_control_inputs

def cli_parser():
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=False)
    g.add_argument('--self-test',action='store_true');g.add_argument('--revalidate-proof',action='store_true')
    g.add_argument('--create-observer-bridge',action='store_true')
    g.add_argument('--verify-observer-bridge',type=pathlib.Path)
    g.add_argument('--verify-proof-review',action='store_true')
    g.add_argument('--verify-18-review',action='store_true')
    g.add_argument('--verify-receipt',type=pathlib.Path)
    g.add_argument('--d124-revalidate-components',action='store_true')
    g.add_argument('--d125-revalidate-components',action='store_true')
    p.add_argument('--acceptance-review',type=pathlib.Path)
    p.add_argument('--bridge',type=pathlib.Path);p.add_argument('--proof-rows',type=pathlib.Path)
    p.add_argument('--proof-review',type=pathlib.Path);p.add_argument('--review-check',type=pathlib.Path)
    p.add_argument('--build',type=pathlib.Path);p.add_argument('--output',type=pathlib.Path)
    p.add_argument('--prior-bridge',type=pathlib.Path);p.add_argument('--component-review',type=pathlib.Path)
    p.add_argument('--bridge-output',type=pathlib.Path)
    p.add_argument('--boot-identity',help=argparse.SUPPRESS)
    p.add_argument('--engineering-owner',choices=('06-23',))
    return p

def main():
    p=cli_parser();a=p.parse_args()
    selected=any((a.self_test,a.revalidate_proof,a.create_observer_bridge,bool(a.verify_observer_bridge),
                  a.verify_proof_review,a.verify_18_review,a.d124_revalidate_components,a.d125_revalidate_components))
    if bool(a.verify_receipt)==selected:p.error('select exactly one checker operation')
    try:
        if a.engineering_owner is not None:
            if not a.verify_proof_review or not all((a.bridge,a.proof_review,a.build,a.output)):
                p.error('engineering23 permits only explicit no-launch proof verification')
            result=verify_proof_review(a.bridge,a.proof_review,a.build,a.output,engineering_owner=a.engineering_owner)
            print(json.dumps(result,sort_keys=True))
            return 0
        if a.self_test:result=self_test()
        elif a.revalidate_proof:
            if not a.build or not a.output:p.error('--revalidate-proof requires --build and --output')
            result=revalidate_proof(a.build.resolve(),(ROOT/a.output).resolve() if not a.output.is_absolute() else a.output.resolve())
        elif a.create_observer_bridge:
            if not a.build or not a.proof_rows or not a.output:p.error('--create-observer-bridge requires --build --proof-rows --output')
            result=create_observer_bridge(a.build.resolve() if a.build.is_absolute() else (ROOT/a.build).resolve(),a.proof_rows,a.output)
        elif a.d125_revalidate_components:
            if not a.prior_bridge or not a.component_review or not a.build or not a.bridge_output:
                p.error('--d125-revalidate-components requires --prior-bridge --component-review --build --bridge-output')
            import signal
            prior_handler=signal.getsignal(signal.SIGALRM)
            signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(TimeoutError('d125-component-55-second-deadline')))
            signal.alarm(55)
            accounting=load_module('d125_component_activity_accounting','scripts/evidence/phase6_accounting.py')
            prior_runs=accounting._load(LEDGER,ROOT).get('d125_runs',[])
            activity_id='d125-component-review-'+str(1+sum(r.get('stage')=='component-revalidation' for r in prior_runs))
            boot=a.boot_identity or accounting.read_boot_identity()
            accounting.begin_d125_activity(LEDGER,activity_id=activity_id,stage='component-revalidation',exposure_seconds=60,
                boot_identity=boot,project_root=ROOT)
            try:result=_d125_component_candidate(a.prior_bridge,a.component_review,a.build,a.bridge_output)
            except BaseException:
                accounting.finalize_d125_activity(LEDGER,activity_id=activity_id,status='interrupted',boot_identity=boot,allowed_root=ROOT)
                raise
            finally:
                signal.alarm(0);signal.signal(signal.SIGALRM,prior_handler)
            accounting.finalize_d125_activity(LEDGER,activity_id=activity_id,status='completed',boot_identity=boot,allowed_root=ROOT)
        elif a.d124_revalidate_components:
            if not a.prior_bridge or not a.component_review or not a.build or not a.bridge_output:
                p.error('--d124-revalidate-components requires --prior-bridge --component-review --build --bridge-output')
            accounting=load_module('d124_component_activity_accounting','scripts/evidence/phase6_accounting.py')
            prior_runs=accounting._load(LEDGER,ROOT).get('d124_runs',[])
            serial=1+sum(1 for row in prior_runs if row.get('stage')=='component-revalidation')
            activity_id=f'd124-revalidate-component-review-{serial:02d}'
            boot=a.boot_identity or accounting.read_boot_identity()
            if not re.fullmatch(r'boot-session:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',boot):
                p.error('--boot-identity must be a normalized boot-session UUID')
            accounting.begin_d124_activity(LEDGER,activity_id=activity_id,stage='component-revalidation',
                exposure_seconds=300.0,boot_identity=boot,project_root=ROOT)
            try:
                result=_d124_component_candidate(a.prior_bridge,a.component_review,a.build,a.bridge_output)
            except BaseException:
                accounting.finalize_d124_activity(LEDGER,activity_id=activity_id,status='interrupted',
                    boot_identity=boot,allowed_root=ROOT)
                raise
            accounting.finalize_d124_activity(LEDGER,activity_id=activity_id,status='completed',
                boot_identity=boot,allowed_root=ROOT)
        elif a.verify_observer_bridge:
            if not a.build:p.error('--verify-observer-bridge requires --build')
            path=a.verify_observer_bridge if a.verify_observer_bridge.is_absolute() else ROOT/a.verify_observer_bridge
            result=verify_observer_bridge(path,a.build)
        elif a.verify_proof_review:
            if not a.bridge or not a.proof_review or not a.build or not a.output:p.error('--verify-proof-review requires --bridge --proof-review --build --output')
            bridge=a.bridge if a.bridge.is_absolute() else ROOT/a.bridge
            review=a.proof_review if a.proof_review.is_absolute() else ROOT/a.proof_review
            result=verify_proof_review(bridge,review,a.build,a.output)
        elif a.verify_18_review:
            if not a.bridge or not a.review_check or not a.build:p.error('--acceptance-review requires --bridge --review-check --build')
            bridge=a.bridge if a.bridge.is_absolute() else ROOT/a.bridge
            check=a.review_check if a.review_check.is_absolute() else ROOT/a.review_check
            result=verify_acceptance_review(check,bridge,a.build)
        else:
            if not a.verify_receipt:p.error('select one checker operation')
            if not a.verify_receipt or not a.build or not a.output or not a.acceptance_review or not a.bridge or not a.proof_review or not a.review_check:
                p.error('--verify-receipt requires --bridge --proof-review --review-check --build --acceptance-review --output')
            result=verify_receipt_file((ROOT/a.verify_receipt).resolve() if not a.verify_receipt.is_absolute() else a.verify_receipt.resolve(),
                (ROOT/a.bridge).resolve() if not a.bridge.is_absolute() else a.bridge.resolve(),
                (ROOT/a.proof_review).resolve() if not a.proof_review.is_absolute() else a.proof_review.resolve(),
                a.build.resolve(),(ROOT/a.output).resolve() if not a.output.is_absolute() else a.output.resolve(),
                (ROOT/a.acceptance_review).resolve() if not a.acceptance_review.is_absolute() else a.acceptance_review.resolve(),
                (ROOT/a.review_check).resolve() if not a.review_check.is_absolute() else a.review_check.resolve())
        print(json.dumps(result,sort_keys=True));return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print(json.dumps({'status':'halted','reason':str(exc),'launches':0},sort_keys=True));return 1
if __name__=='__main__':raise SystemExit(main())
