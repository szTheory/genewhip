#!/usr/bin/env python3
"""Three explicitly reserved tiny authored producer/consumer conformance rows.

This is not a game/control runner or a renewal of the historical PEA matrix.
The recovery manifest must be reviewed and source-bound before any invocation.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import pathlib
import struct
import time

ROOT=pathlib.Path(__file__).resolve().parents[2]
MANIFEST=ROOT/'evidence/phase6-capture-recovery.json'
VARIANTS={'native':'phase6','sanitize':'phase6-movem-sanitize','hooks-off':'phase6-movem-hooks-off'}

def module():
    spec=importlib.util.spec_from_file_location('capture_recovery',ROOT/'tests/fixtures/phase6_repairs.py')
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def inputs(coordinator):
    rom=bytearray(2048)
    struct.pack_into('>II',rom,0,0xffff00,0x200)
    # PEA addresses unmapped memory without reading it; SWAP must remain
    # reachable after PEA dispatch. ILLEGAL is an intentional bounded stop.
    code=bytes.fromhex('487900e00010 203c12345678 4840 4afc')
    rom[512:512+len(code)]=code
    h=[0]*32;h[1:6]=[1,3,1,1,0];h[30]=128
    sections=[[[0xfffefc,0xfffefc,2,0],[0xfffefe,0xfffefe,2,0]],[],[],[],[],[],[],[]]
    return bytes(rom),coordinator.compiler.encode_controller(h,sections)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--variant',choices=VARIANTS,required=True)
    args=parser.parse_args();coordinator=module()
    manifest=json.loads(MANIFEST.read_text())
    if manifest.get('review_status')!='approved':raise RuntimeError('recovery-manifest-not-reviewed')
    if manifest['source_identity']!=coordinator.accounting.source_identity(ROOT):raise RuntimeError('recovery-source-changed')
    for name,digest in manifest['proof_inputs_sha256'].items():
        if sha(ROOT/name)!=digest:raise RuntimeError('recovery-proof-input-changed:'+name)
    rows=manifest['synthetic_process_rows'];row=next(r for r in rows if r['variant']==args.variant)
    if row['status']!='reserved':raise RuntimeError('recovery-row-already-spent')
    if any(r['status']!='passed' for r in rows[:rows.index(row)]):
        raise RuntimeError('recovery-previous-row-not-passed')
    client=ROOT/'build'/VARIANTS[args.variant]/'tools/session/gw_headless'
    if sha(client)!=row['client_sha256']:raise RuntimeError('recovery-binary-changed')
    rom,binary=inputs(coordinator)
    if (hashlib.sha256(rom).hexdigest()!=row['guest_sha256'] or
            hashlib.sha256(binary).hexdigest()!=row['plan_sha256']):
        raise RuntimeError('recovery-authored-input-changed')
    # Parent owns this existing interval. Observe it; never close/reset it.
    boot=coordinator.accounting.read_boot_identity()
    pre=coordinator.accounting.preflight(coordinator.LEDGER,monotonic_now=time.monotonic(),
        boot_identity=boot,require_active_anchor=True,allowed_root=ROOT)
    ledger=json.loads(coordinator.LEDGER.read_text());anchor=ledger['phase6_accounting']['active_anchor']
    limits=manifest['accounting'];active=pre['active_seconds_since_anchor']
    if (anchor['id']!=limits['anchor_id'] or
            pre['closed_cumulative_seconds']!=limits['closed_global_seconds_at_entry'] or
            pre['tank_pea_active_seconds_used']!=limits['target_upper_bound_seconds_at_entry'] or
            pre['status']!='ready' or
            pre['cumulative_seconds_including_current']+30>=limits['global_limit_seconds'] or
            limits['target_upper_bound_seconds_at_entry']+active+30>=limits['target_limit_seconds'] or
            active+30>=limits['debug_total_wall_ceiling_seconds']):
        raise RuntimeError('recovery-existing-accounting-preflight-failed')
    row['read_only_preflight']=pre
    # Persist the spend before the first child. A failure leaves it spent.
    row['status']='started';MANIFEST.write_text(json.dumps(manifest,indent=2)+'\n')
    work=ROOT/'build/phase6/capture-recovery'/args.variant
    work.mkdir(parents=True,exist_ok=True)
    (work/'guest.bin').write_bytes(rom);(work/'route.gwrc').write_bytes(binary)
    report=work/'native.json';runs=[]
    row['retained_streams']={}
    command=[str(client.relative_to(ROOT)),'--route-plan',str((work/'route.gwrc').relative_to(ROOT)),
        '--route-report',str(report.relative_to(ROOT)),'--route-instruction-probe','512',
        str((work/'guest.bin').relative_to(ROOT))]
    try:
        result=coordinator.contracts._run_client(client,command,runs,report=report,timeout=30,cwd=ROOT,
            retained_streams=row['retained_streams'])
        row.update(processes=runs,client_sha256=sha(client),guest_sha256=sha(work/'guest.bin'),
                   plan_sha256=sha(work/'route.gwrc'),command=command)
        if runs[-1]['bound_violation'] or result.returncode!=1:raise RuntimeError('synthetic-process-disposition')
        if not report.is_file() or report.stat().st_size>8388608:raise RuntimeError('synthetic-report-bound')
        native=json.loads(report.read_text())
        if native['schema']!='genewhip-route-native-v1' or native['plan_fnv1a64']!=coordinator.compiler.plan_fingerprint(binary):
            raise RuntimeError('synthetic-producer-identity')
        coordinator.validate_capture_boundaries(native,512,{})
        probe=native['probe_boundary'];last=native['last_boundary']
        assert probe['opcode']==0x4879 and probe['retired'], 'PEA retires through public client'
        assert probe['after']['a'][7]==0xfffefc and probe['after']['sr']==probe['before']['sr'], 'PEA stack and flags'
        assert probe['after']['tick']-probe['before']['tick']==140, '16-bit MC68000 PEA abs.l 20 CPU clocks'
        assert [s['bytes'] for s in probe['after']['spans']]==['00e00010'], 'PEA expected big-endian stack'
        assert last['before']['d'][0]==0x56781234, 'SWAP survives PEA overlap'
        assert last['before']['pc']==0x20e and last['opcode']==0x4afc and not last['retired'], 'exact intended unsupported stop'
        assert native['fields']==0 and native['active_ticks']==0 and native['boundary_calls']<=128, 'finite instruction prefix'
        assert last['before']['instructions']==last['after']['instructions'], 'fault does not retire'
        row.update(status='passed',native_report_path=report.relative_to(ROOT).as_posix(),
                   native_report_sha256=sha(report),assertions=9,fields=0,route_qualification=False)
    except BaseException as error:
        row.update(status='interrupted',failure=str(error))
        raise
    finally:
        row['processes']=runs
        if report.is_file():
            row.update(native_report_path=report.relative_to(ROOT).as_posix(),native_report_sha256=sha(report))
        MANIFEST.write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(row,sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
