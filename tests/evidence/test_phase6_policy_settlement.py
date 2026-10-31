TRACER_CASES = ('reserved_current_readers', 'absent_publication', 'identical_repeat', 'missing_output_recovery')
CHECKPOINTS = ('before_intent','after_intent','before_publication','after_publication','after_verification')
REPEATED_RECOVERY = ('repeated_interrupted_recovery',)
REJECTION_CASES = (
 'identical_preexisting_receipt','conflicting_preexisting_receipt','changed_record','changed_destination',
 'missing_intent','corrupt_journal_schema','corrupt_intent','intent_digest_mismatch','receipt_digest_mismatch',
 'ledger_symlink_live','ledger_symlink_dangling','receipt_symlink_live','receipt_symlink_dangling',
 'directory_symlink_live','directory_symlink_dangling','root_symlink_live','root_symlink_dangling',
 'lock_symlink_live','lock_symlink_dangling','absolute_escape','traversal_escape','nested_destination',
 'publication_collision_identical','publication_collision_conflict','lock_timeout',
 'changed_original_object','missing_original_object','changed_baseline_map','duplicate_purpose_across_ids',
 'stale_baseline_pin','stale_source_pin','stale_approval_pin','stale_review_pin','stale_boot',
 'missing_own_observation','missing_terminal_observation','wrong_allocation','wrong_posted_base','wrong_total',
 'wrong_reserve','wrong_cap','hidden_unknown_tail','unrecognized_settlement_policy',
 'numeric_bool','numeric_nan','numeric_infinity','numeric_negative','numeric_overflow',
 'purpose_below_threshold','purpose_equal_threshold','purpose_above_threshold',
 'global_below_threshold','global_equal_threshold','global_above_threshold','known_excess',
 'funded_forecast_not_double_counted','pending_liabilities_not_double_counted','mixed_coordinator_flags')
NEGATIVE_CASES = ('wrong_total','double_counted_purpose','hidden_unknown_tail','false_receipt_success','stale_source_identity','forged_authority_identity')
DENIAL_PROBES = ('outside-open','outside-enumeration','unapproved-project-import','process-call-entry','unknown-fd','dir-fd','unknown-fd-stat','unknown-fd-flock','outside-stat','outside-lstat','outside-readlink','outside-access','socket-audit-only','native-audit-only','live-without-authority','clone-live-root-confusion','arbitrary-project-write','extra-receipt','extra-id','unsafe-temp','unsafe-lock','forbidden-caller','live-direct-ledger-open','live-direct-receipt-open','live-replace-receipt','live-rename-escape','live-unlink-ledger','live-chmod-ledger','live-nonexclusive-temp','live-follow-temp','live-alternate-lock','live-wrong-receipt-link')

# Independent D133 oracle. No producer totals, serializers or record builders are
# used to establish expected semantics. Loaded only inside the reviewed guard.
import hashlib
import json
import fcntl
import os
import time
from decimal import Decimal, InvalidOperation

ALLOCATIONS = {'D129-S':1800,'D130-old-A':5400,'D131-probe':1200,
 'D132-engineering29':4200,'D132-documentary-control':1800,
 'D133-documentary-control':2400,'D133-settlement30-current-readers':9000}
LOWER_BOUNDS = {'D129-S':'1508.589962375001','D130-old-A':'2306.7324035839993',
 'D131-probe':'762.6347023750423','D132-engineering29':'2522.823684834002',
 'D132-documentary-control':None,'D133-documentary-control':None}
ID = 'D133-settlement30'
RECEIPT = 'phase6-d133-settlement30-receipt.json'
POSTED = Decimal('45802.60140849992')
RESERVE = Decimal('1794.135')
CEILING = Decimal('73500')
LIABILITIES = Decimal('25800')
MAXIMUM = Decimal('73396.73640849992')
MARGIN = Decimal('103.26359150008')
ROSTERS = {'tracer':TRACER_CASES,'checkpoints':CHECKPOINTS,
 'repeated_recovery':REPEATED_RECOVERY,'rejections':REJECTION_CASES,
 'oracle_controls':NEGATIVE_CASES,'denial_probes':DENIAL_PROBES,
 'fault-matrix':CHECKPOINTS+REPEATED_RECOVERY+REJECTION_CASES,
 'oracle-negative-controls':NEGATIVE_CASES}


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()


def require(condition, name):
    if not condition:
        raise AssertionError(name)


def number(value, name):
    require(type(value) in (int,float,str),name)
    try:
        result=Decimal(str(value))
    except InvalidOperation:
        raise AssertionError(name)
    require(result.is_finite(),name)
    return result


def equal_number(actual,wanted,name):
    # JSON binary floats may differ by <=1e-10 seconds, never used in admission.
    require(abs(number(actual,name)-wanted)<=Decimal('0.0000000001'),name)


def record_oracle(record, expected, context):
    require(set(record)=={'kind','policy_settlement'} and record['kind']=='engineering-metadata', 'record-envelope')
    p=record['policy_settlement']
    require(p.get('schema')=='phase6-policy-settlement-v1','policy-schema')
    require(p.get('settlement_id')==ID and p.get('receipt_path')==RECEIPT,'policy-identity')
    require(p.get('expected_objects')==expected,'policy-original68-pins')
    require(p.get('baseline_sha256')==context['authority']['entry_ledger_sha256'],'policy-baseline-pin')
    pin=context['reader_pin']
    require(p.get('authority_pins')==pin['authority_pins'],'policy-authority-identity')
    require(p.get('source_sha256')==pin['source_sha256'],'policy-source-identity')
    require(p.get('allocations')==ALLOCATIONS,'policy-purpose-map')
    equal_number(p.get('posted_actual_closed_seconds'),POSTED,'policy-posted-base')
    equal_number(p.get('protected_process_reserve_seconds'),RESERVE,'policy-process-reserve')
    equal_number(p.get('operating_ceiling_seconds'),CEILING,'policy-operating-cap')
    equal_number(p.get('policy_liability_seconds'),LIABILITIES,'policy-liability-total')
    equal_number(p.get('policy_settled_exposure_seconds'),POSTED+LIABILITIES,'policy-settled-total')
    equal_number(p.get('maximum_policy_exposure_seconds'),MAXIMUM,'policy-maximum-total')
    require(p.get('actual_total_status')=='unknown','policy-unknown-actual')
    evidence=p.get('actual_evidence')
    require(isinstance(evidence,dict) and set(evidence)==set(ALLOCATIONS),'policy-evidence-roster')
    for purpose in ALLOCATIONS:
        row=evidence[purpose]
        require(row.get('unknown_tail') is True,'policy-unknown-tail:'+purpose)
        lower=(str(context['observation']['elapsed_seconds']) if purpose== 'D133-settlement30-current-readers' else LOWER_BOUNDS[purpose])
        if lower is None:
            require(row.get('lower_bound_seconds') is None,'policy-unknown-lower-bound:'+purpose)
        else:
            equal_number(row.get('lower_bound_seconds'),Decimal(lower),'policy-lower-bound:'+purpose)
    require(p.get('own_observation')==context['observation'],'policy-own-observation')
    require(context['observation']['boot_uuid']==context['authority']['boot_uuid'],'policy-boot')
    return p


def view_oracle(view, context, state='published'):
    expected={'posted_actual_closed_seconds':POSTED,'policy_liability_seconds':LIABILITIES,
     'policy_settled_exposure_seconds':POSTED+LIABILITIES,
     'protected_process_reserve_seconds':RESERVE,
     'policy_remaining_seconds':CEILING-POSTED-LIABILITIES,
     'admissible_policy_headroom_seconds':MARGIN}
    for key,wanted in expected.items():
        equal_number(view.get(key),wanted,'view-'+key)
    require(view.get('actual_total_status')=='unknown','view-unknown-actual')
    require(view.get('publication_state')==state,'view-publication-state')
    require(view.get('capacity_allowed') is (state!='pending-publication'),'view-capacity-publication')
    require(view.get('purpose_allocations')==ALLOCATIONS,'view-purpose-map')
    require(view.get('authority_pins')==context['reader_pin']['authority_pins'],'view-authority-identity')
    require(view.get('source_sha256')==context['reader_pin']['source_sha256'],'view-source-identity')
    actual=view.get('actual_evidence')
    require(isinstance(actual,dict) and set(actual)==set(ALLOCATIONS),'view-evidence-roster')
    for purpose,row in actual.items():
        require(row.get('unknown_tail') is True,'view-unknown-tail:'+purpose)
        lower=(str(context['observation']['elapsed_seconds']) if purpose=='D133-settlement30-current-readers' and state!='reserved' else '0' if purpose=='D133-settlement30-current-readers' else LOWER_BOUNDS[purpose])
        if lower is None:
            require(row.get('lower_bound_seconds') is None,'view-unknown-lower-bound:'+purpose)
        else:
            equal_number(row.get('lower_bound_seconds'),Decimal(lower),'view-lower-bound:'+purpose)
    require('current_global_used' not in view,'view-no-fabricated-measured-total')


def expected_receipt_bytes(record, expected):
    semantic={'schema':'ledger-transaction-intent-v1','transaction_id':ID,'receipt_path':RECEIPT,'record':record,'expected_objects':expected}
    payload={'schema':'ledger-transaction-receipt-v1','transaction_id':ID,'receipt_path':RECEIPT,'record':record,'intent_sha256':hashlib.sha256(canonical(semantic)).hexdigest()}
    return (json.dumps(payload,indent=2,sort_keys=False,allow_nan=False)+'\n').encode()


def original_oracle(value, expected, journal=True):
    require(set(value)==set(expected)|({'ledger_transactions_v1'} if journal else set()),'original-object-roster')
    for key,digest in expected.items():
        require(hashlib.sha256(canonical(value[key])).hexdigest()==digest,'original-object-unchanged:'+key)


def persisted_oracle(ledger,receipt,expected,record,view,context):
    value=json.loads(ledger.read_bytes())
    original_oracle(value,expected)
    journal=value.get('ledger_transactions_v1')
    require(isinstance(journal,dict) and journal.get('schema')=='ledger-transactions-v1','journal-schema')
    rows=journal.get('transactions')
    require(isinstance(rows,dict) and set(rows)=={ID},'exactly-one-policy-intent')
    row=rows[ID]
    require(row.get('record')==record,'persisted-record-exact')
    record_oracle(row['record'],expected,context)
    wanted=expected_receipt_bytes(record,expected)
    require(receipt.is_file(),'receipt-present')
    require(receipt.read_bytes()==wanted==row.get('receipt_bytes','').encode(),'receipt-exact-intent-bytes')
    require(hashlib.sha256(wanted).hexdigest()==row.get('receipt_sha256'),'receipt-independent-digest')
    semantic={'schema':'ledger-transaction-intent-v1','transaction_id':ID,'receipt_path':RECEIPT,'record':record,'expected_objects':expected}
    require(row.get('intent_bytes')==canonical(semantic).decode() and row.get('intent_sha256')==hashlib.sha256(canonical(semantic)).hexdigest(),'intent-independent-digest')
    view_oracle(view,context)
    return value


def make_record(api,expected,context):
    require(callable(getattr(api,'make_d133_settlement_record',None)),'missing-d133-settlement-constructor')
    return api.make_d133_settlement_record(authority=context['authority'],reader_pin=context['reader_pin'],observation=context['observation'],expected_objects=expected,baseline_sha256=context['authority']['entry_ledger_sha256'])


def common_for(directory,expected,context):
    return dict(project_root=directory,authority=context['authority'],reader_pin=context['reader_pin'],expected_objects=expected,baseline_sha256=context['authority']['entry_ledger_sha256'],lock_root=directory/'locks')


def scenario(root,name,baseline,expected,fresh_modules,context):
    directory=root/name
    directory.mkdir()
    ledger=directory/'ledger.json'
    ledger.write_bytes(baseline)
    modules=fresh_modules()
    api=modules['settlement']
    record=make_record(api,expected,context)
    record_oracle(record,expected,context)
    return directory,ledger,directory/RECEIPT,api,record,common_for(directory,expected,context)


def get_view(api,ledger,common):
    return api.d133_current_view(ledger,**common)


def commit(api,ledger,record,common,checkpoint=None):
    result=api.commit_d133_settlement(ledger,record=record,checkpoint=checkpoint,**common)
    require(result.get('actual_total_status')=='unknown','publisher-unknown-actual')
    return result


def recover(api,ledger,common,checkpoint=None):
    result=api.recover_d133_settlement(ledger,checkpoint=checkpoint,**common)
    require(result.get('actual_total_status')=='unknown','recovery-unknown-actual')
    return result


def failure(case,exc):
    return {'case_id':case,'status':'fail','assertion':str(exc),'exception':type(exc).__name__}


def run_tracer(api,root,baseline,expected,fresh_modules,context):
    rows=[]
    try:
        directory,ledger,receipt,api,record,common=scenario(root,'tracer',baseline,expected,fresh_modules,context)
    except Exception as exc:
        return [failure(case,exc) for case in TRACER_CASES]
    for case in TRACER_CASES:
        try:
            api=fresh_modules()['settlement']
            if case=='reserved_current_readers':
                view=get_view(api,ledger,common)
                view_oracle(view,context,'reserved')
                original_oracle(json.loads(ledger.read_bytes()),expected,False)
            elif case=='absent_publication':
                commit(api,ledger,record,common)
                publisher_path=directory/'record.json';publisher_path.write_bytes(canonical(record))
                argv=caller_argv(context,directory,ledger,common)
                for lane in ('commit-settlement','recover-settlement'):
                    status,stdout=context['settlement_main'](['--case',lane]+argv+(['--record',str(publisher_path)] if lane=='commit-settlement' else []))
                    require(status==0,'actual-publisher-cli:'+lane)
                    view_oracle(json.loads(stdout),context)
            elif case=='identical_repeat':
                before=(ledger.read_bytes(),receipt.read_bytes(),receipt.stat().st_ino)
                commit(api,ledger,record,common)
                require(before==(ledger.read_bytes(),receipt.read_bytes(),receipt.stat().st_ino),'identical-replay-inode-preserved')
            else:
                before=(ledger.read_bytes(),receipt.read_bytes())
                receipt.unlink()
                view_oracle(get_view(api,ledger,common),context,'pending-publication')
                for reported in exercise_current_callers(context,directory,ledger,common,case).values():
                    view_oracle(reported,context,'pending-publication')
                for _ in range(2):
                    api=fresh_modules()['settlement'];recover(api,ledger,common)
                require(before==(ledger.read_bytes(),receipt.read_bytes()),'same-intent-recovery-exact')
            view=get_view(api,ledger,common)
            if case!='reserved_current_readers':
                persisted_oracle(ledger,receipt,expected,record,view,context)
            # Context callbacks execute the actual CLI/parser/coordinator main.
            caller_results=exercise_current_callers(context,directory,ledger,common,case)
            require(set(caller_results)=={'coordinator','read-current','remaining','recompute-receipt'},'actual-caller-roster')
            for name,reported in caller_results.items():
                view_oracle(reported,context,'reserved' if case=='reserved_current_readers' else 'published')
            rows.append({'case_id':case,'status':'pass','actual_callers':list(caller_results),'view':view})
        except Exception as exc:
            rows.append(failure(case,exc))
    return rows


class InjectedBoundary(RuntimeError):
    pass


def interrupted(action,target):
    def hook(name):
        if name==target:
            raise InjectedBoundary(target)
    try:
        action(hook)
    except InjectedBoundary as exc:
        require(str(exc)==target,'checkpoint-identity')
    else:
        raise AssertionError('checkpoint-not-reached:'+target)


def pending_oracle(ledger,receipt,expected,record,api,common,context,target):
    value=json.loads(ledger.read_bytes())
    has_intent=target!='before_intent'
    published=target in ('after_publication','after_verification')
    original_oracle(value,expected,has_intent)
    require(receipt.exists()==published,'checkpoint-publication-order:'+target)
    if has_intent:
        require(set(value['ledger_transactions_v1']['transactions'])=={ID},'checkpoint-one-intent')
        require(value['ledger_transactions_v1']['transactions'][ID]['receipt_bytes'].encode()==expected_receipt_bytes(record,expected),'checkpoint-intent-receipt')
    state='published' if published else 'pending-publication' if has_intent else 'reserved'
    view_oracle(get_view(api,ledger,common),context,state)
    return {'ledger_sha256':hashlib.sha256(ledger.read_bytes()).hexdigest(),'intent_present':has_intent,'receipt_present':published,'state':state}


def expect_rejection(action,api,reason=None):
    try:
        action()
    except api.ACCOUNTING.AccountingError as exc:
        if reason is not None:
            require(str(exc)==reason,'rejection-reason:'+reason+':actual='+str(exc))
        require(bool(str(exc)),'rejection-named-reason')
        return str(exc)
    raise AssertionError('rejection-not-raised:'+str(reason))


def run_fault_matrix(root,baseline,expected,fresh_modules,context):
    checkpoints=[]
    for target in CHECKPOINTS:
        try:
            directory,ledger,receipt,api,record,common=scenario(root,target,baseline,expected,fresh_modules,context)
            observations=[]
            for _ in range(2):
                api=fresh_modules()['settlement']
                interrupted(lambda hook:commit(api,ledger,record,common,hook),target)
                observations.append(pending_oracle(ledger,receipt,expected,record,api,common,context,target))
            if target=='before_intent':
                expect_rejection(lambda:recover(api,ledger,common),api,'transaction-intent-missing')
                commit(api,ledger,record,common)
            for _ in range(2):
                api=fresh_modules()['settlement'];recover(api,ledger,common)
                persisted_oracle(ledger,receipt,expected,record,get_view(api,ledger,common),context)
            checkpoints.append({'case_id':target,'status':'pass','interruptions':observations,'fresh_recoveries':2})
        except Exception as exc:
            checkpoints.append(failure(target,exc))
    repeated=[]
    try:
        directory,ledger,receipt,api,record,common=scenario(root,'repeated-recovery',baseline,expected,fresh_modules,context)
        interrupted(lambda hook:commit(api,ledger,record,common,hook),'after_intent')
        observations=[]
        for _ in range(2):
            api=fresh_modules()['settlement']
            interrupted(lambda hook:recover(api,ledger,common,hook),'before_publication')
            observations.append(pending_oracle(ledger,receipt,expected,record,api,common,context,'before_publication'))
        for _ in range(2):
            api=fresh_modules()['settlement'];recover(api,ledger,common)
            persisted_oracle(ledger,receipt,expected,record,get_view(api,ledger,common),context)
        repeated.append({'case_id':REPEATED_RECOVERY[0],'status':'pass','interruptions':observations,'fresh_recoveries':2})
    except Exception as exc:
        repeated.append(failure(REPEATED_RECOVERY[0],exc))
    rejections=[]
    for case in REJECTION_CASES:
        try:
            result=rejection_case(case,root,baseline,expected,fresh_modules,context)
            rejections.append(dict(case_id=case,status='pass',**result))
        except Exception as exc:
            rejections.append(failure(case,exc))
    return {'checkpoints':checkpoints,'repeated_recovery':repeated,'rejections':rejections}


def clone(value):
    return json.loads(json.dumps(value))


def rejection_case(case,root,baseline,expected,fresh_modules,context):
    directory,ledger,receipt,api,record,common=scenario(root,case,baseline,expected,fresh_modules,context)
    call=lambda:commit(api,ledger,record,common)
    reason=None
    symlink_snapshot=None
    if case in ('identical_preexisting_receipt','conflicting_preexisting_receipt'):
        receipt.write_bytes(expected_receipt_bytes(record,expected) if case.startswith('identical') else b'conflicting receipt must survive\n')
        if case.startswith('identical'):
            before=(receipt.read_bytes(),receipt.stat().st_ino)
            call();persisted_oracle(ledger,receipt,expected,record,get_view(api,ledger,common),context)
            require(before==(receipt.read_bytes(),receipt.stat().st_ino),'preexisting-identical-no-clobber')
            return {'expectation':'preexisting-identical-no-clobber'}
        reason='transaction-receipt-conflict'
    elif case in ('changed_record','changed_destination'):
        call()
        if case=='changed_record':
            record['policy_settlement']['own_observation']['elapsed_seconds']+=1
            reason=None
        else:
            # Neutral canonical API must reject changed destination for same ID.
            call=lambda:api.ACCOUNTING.commit_ledger_transaction(ledger,project_root=directory,transaction_id=ID,receipt_path=directory/'other.json',record=record,expected_objects=expected,lock_root=common['lock_root'])
            reason='transaction-identity-conflict'
    elif case=='missing_intent':
        call();published=receipt.read_bytes()
        # Intentionally remove an actually committed journal while retaining its
        # valid receipt: current readers must not grant orphan capacity.
        ledger.write_bytes(baseline)
        view_oracle(get_view(api,ledger,common),context,'pending-publication')
        for reported in exercise_current_callers(context,directory,ledger,common,case).values():
            view_oracle(reported,context,'pending-publication')
        require(receipt.read_bytes()==published,'orphan-receipt-preserved')
        call=lambda:recover(api,ledger,common)
        reason='transaction-intent-missing'
    elif case in ('corrupt_journal_schema','corrupt_intent','intent_digest_mismatch','receipt_digest_mismatch','duplicate_purpose_across_ids','unrecognized_settlement_policy'):
        call();value=json.loads(ledger.read_bytes());journal=value['ledger_transactions_v1'];row=journal['transactions'][ID]
        if case=='corrupt_journal_schema':journal['schema']='invalid';reason='transaction-journal-invalid'
        elif case=='corrupt_intent':journal['transactions'][ID]=None;reason='transaction-intent-invalid'
        elif case in ('intent_digest_mismatch','receipt_digest_mismatch'):
            row['intent_sha256' if case.startswith('intent_') else 'receipt_sha256']='0'*64;reason='transaction-intent-digest-mismatch'
        elif case=='duplicate_purpose_across_ids':
            duplicate=clone(record)
            # Construct a syntactically valid second neutral intent, independently.
            other_id='duplicate-policy'
            semantic={'schema':'ledger-transaction-intent-v1','transaction_id':other_id,'receipt_path':'duplicate.json','record':duplicate,'expected_objects':expected}
            ib=canonical(semantic);payload={'schema':'ledger-transaction-receipt-v1','transaction_id':other_id,'receipt_path':'duplicate.json','record':duplicate,'intent_sha256':hashlib.sha256(ib).hexdigest()}
            rb=(json.dumps(payload,indent=2,sort_keys=False)+'\n').encode()
            journal['transactions'][other_id]=dict(semantic,intent_bytes=ib.decode(),intent_sha256=hashlib.sha256(ib).hexdigest(),receipt_bytes=rb.decode(),receipt_sha256=hashlib.sha256(rb).hexdigest())
            (directory/'duplicate.json').write_bytes(rb)
        else:
            row['record']['policy_settlement']['schema']='phase6-policy-settlement-v999'
            semantic={key:row[key] for key in ('schema','transaction_id','receipt_path','record','expected_objects')}
            ib=canonical(semantic);payload={'schema':'ledger-transaction-receipt-v1','transaction_id':ID,'receipt_path':RECEIPT,'record':row['record'],'intent_sha256':hashlib.sha256(ib).hexdigest()}
            rb=(json.dumps(payload,indent=2,sort_keys=False)+'\n').encode();row.update(intent_bytes=ib.decode(),intent_sha256=hashlib.sha256(ib).hexdigest(),receipt_bytes=rb.decode(),receipt_sha256=hashlib.sha256(rb).hexdigest());receipt.write_bytes(rb)
        ledger.write_bytes(canonical(value));call=lambda:get_view(api,ledger,common)
    elif 'symlink' in case:
        live=case.endswith('_live');target=directory/'target'
        kind=case.split('_')[0]
        if live:
            if kind in ('directory','root','lock'):
                target.mkdir();(target/'ledger.json').write_bytes(baseline)
            else:target.write_bytes(baseline if kind=='ledger' else b'target bytes')
        if kind=='ledger':ledger.unlink();ledger.symlink_to(target);reason='transaction-path-symlink'
        elif kind=='receipt':receipt.symlink_to(target);reason='transaction-path-symlink'
        elif kind=='directory':
            alias=directory/'alias';alias.symlink_to(target,target_is_directory=True);ledger=alias/'ledger.json';reason='transaction-path-symlink'
        elif kind=='root':
            alias=directory/'alias';alias.symlink_to(target,target_is_directory=True);common['project_root']=alias;reason='transaction-root-alias-or-symlink'
        else:
            common['lock_root'].symlink_to(target,target_is_directory=True)
            before=ledger.read_bytes()
            first=expect_rejection(call,api,'transaction-path-symlink')
            common['lock_root'].unlink();common['lock_root'].mkdir()
            lock_name='genewhip-phase6-accounting-'+hashlib.sha256(str(ledger).encode()).hexdigest()+'.lock'
            lock_path=common['lock_root']/lock_name
            file_target=directory/'lock-target'
            if live:file_target.write_bytes(b'lock target must survive')
            lock_path.symlink_to(file_target)
            second=expect_rejection(call,api,'transaction-lock-file-symlink')
            require(before==ledger.read_bytes() and not receipt.exists(),'both-lock-link-no-effects')
            require(lock_path.is_symlink(),'lock-file-link-preserved')
            require(file_target.read_bytes()==b'lock target must survive' if live else not file_target.exists(),'lock-link-target-preserved')
            return {'expectation':'both-lock-root-and-file-links-denied','reasons':[first,second]}
        link=ledger if kind=='ledger' else receipt if kind=='receipt' else alias
        target_data=(target/'ledger.json').read_bytes() if live and kind in ('directory','root') else target.read_bytes() if live else None
        symlink_snapshot=(link,os.readlink(link),target,target_data,live,kind)
    elif case in ('absolute_escape','traversal_escape','nested_destination'):
        destination={'absolute_escape':root/'outside.json','traversal_escape':'../outside.json','nested_destination':'nested/receipt.json'}[case]
        call=lambda:api.ACCOUNTING.commit_ledger_transaction(ledger,project_root=directory,transaction_id=ID,receipt_path=destination,record=record,expected_objects=expected,lock_root=common['lock_root'])
        reason='transaction-flat-destination-required' if case=='nested_destination' else 'transaction-path-escape'
    elif case.startswith('publication_collision_'):
        actual_link=os.link;observations=[]
        def collide(source,destination,**kwargs):
            if destination==receipt and not observations:
                observations.append(True);receipt.write_bytes(expected_receipt_bytes(record,expected) if case.endswith('identical') else b'collision must survive');observations.append((receipt.read_bytes(),receipt.stat().st_ino))
            return actual_link(source,destination,**kwargs)
        os.link=collide
        try:
            if case.endswith('identical'):
                call();persisted_oracle(ledger,receipt,expected,record,get_view(api,ledger,common),context)
            else:expect_rejection(call,api,'transaction-receipt-conflict')
            require(len(observations)==2 and observations[1]==(receipt.read_bytes(),receipt.stat().st_ino),'actual-link-collision-preserved')
            return {'expectation':'actual-FileExistsError','collision_injected':True}
        finally:os.link=actual_link
    elif case=='lock_timeout':
        common['lock_root'].mkdir();name=hashlib.sha256(str(ledger).encode()).hexdigest();fd=os.open(common['lock_root']/('genewhip-phase6-accounting-'+name+'.lock'),os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);start=time.monotonic();before=ledger.read_bytes();expect_rejection(call,api,'transaction-lock-timeout');elapsed=time.monotonic()-start
            require(1.9<=elapsed<3,'bounded-two-second-lock');require(before==ledger.read_bytes() and not receipt.exists(),'lock-timeout-no-effects');return {'expectation':'transaction-lock-timeout','elapsed_seconds':elapsed}
        finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
    elif case in ('changed_original_object','missing_original_object'):
        value=json.loads(ledger.read_bytes())
        if case.startswith('changed'):value['phase']='intentionally wrong';reason='transaction-original-object-changed'
        else:del value['phase'];reason='transaction-original-roster-changed'
        ledger.write_bytes(canonical(value))
    elif case=='changed_baseline_map':
        common['expected_objects']=dict(expected,phase='0'*64)
    elif case.startswith('stale_'):
        common['reader_pin']=clone(context['reader_pin'])
        if case=='stale_baseline_pin':common['baseline_sha256']='0'*64
        elif case=='stale_source_pin':common['reader_pin']['source_sha256'][next(iter(common['reader_pin']['source_sha256']))]='0'*64
        elif case=='stale_boot':record['policy_settlement']['own_observation']['boot_uuid']='different-boot'
        else:common['reader_pin']['authority_pins'][{'stale_approval_pin':'approval','stale_review_pin':'source_review'}[case]]='0'*64
    elif case in ('missing_own_observation','missing_terminal_observation'):
        if case=='missing_own_observation':del record['policy_settlement']['own_observation']
        else:del record['policy_settlement']['own_observation']['observed_monotonic_seconds']
    elif case in ('wrong_allocation','wrong_posted_base','wrong_total','wrong_reserve','wrong_cap','hidden_unknown_tail'):
        p=record['policy_settlement']
        if case=='wrong_allocation':p['allocations']['D129-S']=1799
        elif case=='wrong_posted_base':p['posted_actual_closed_seconds']='45801.60140849992'
        elif case=='wrong_total':p['policy_liability_seconds']=25799
        elif case=='wrong_reserve':p['protected_process_reserve_seconds']='1793.135'
        elif case=='wrong_cap':p['operating_ceiling_seconds']=73501
        else:p['actual_evidence']['D129-S']['unknown_tail']=False
    elif case.startswith('numeric_') or 'threshold' in case or case in ('known_excess','funded_forecast_not_double_counted'):
        kwargs=dict(elapsed_seconds=1000,remaining_forecast_seconds=7400,terminal_remaining_seconds=1200,newly_known_unallocated_liabilities=0)
        admitted=None
        if case.startswith('numeric_'):
            kwargs['elapsed_seconds']={'numeric_bool':True,'numeric_nan':float('nan'),'numeric_infinity':float('inf'),'numeric_negative':-1,'numeric_overflow':10**10000}[case]
            call=lambda:api.d133_admission(**kwargs)
        else:
            if case.startswith('purpose_'):
                kwargs['elapsed_seconds']=600
                kwargs['remaining_forecast_seconds']={'purpose_below_threshold':8399.999999,'purpose_equal_threshold':8400,'purpose_above_threshold':8400.000001}[case]
                admitted=not case.endswith('above_threshold')
            elif case.startswith('global_'):
                kwargs['newly_known_unallocated_liabilities']={'global_below_threshold':'103.263591500079','global_equal_threshold':'103.26359150008','global_above_threshold':'103.263591500081'}[case]
                admitted=not case.endswith('above_threshold')
            elif case=='known_excess':kwargs['newly_known_unallocated_liabilities']=104;admitted=False
            else:admitted=True
            result=api.d133_admission(**kwargs)
            require(result.get('admitted') is admitted,'independent-admission-threshold:'+case)
            if case in ('purpose_above_threshold','global_above_threshold'):
                precise=dict(kwargs)
                precise['remaining_forecast_seconds' if case.startswith('purpose_') else 'newly_known_unallocated_liabilities']=('8400.0000000000000000000000000000000001' if case.startswith('purpose_') else '103.2635915000800000000000000000000001')
                precise_result=api.d133_admission(**precise)
                require(precise_result.get('admitted') is False,'high-precision-above-denied:'+case)
            equal_number(result.get('maximum_policy_exposure_seconds'),MAXIMUM+Decimal(str(kwargs['newly_known_unallocated_liabilities'])),'global-full-slot-once')
            return {'expectation':'admitted' if admitted else 'denied','admission':result}
    elif case=='pending_liabilities_not_double_counted':
        interrupted(lambda hook:commit(api,ledger,record,common,hook),'after_intent')
        view_oracle(get_view(api,ledger,common),context,'pending-publication')
        return {'expectation':'pending-liabilities-reserved-once'}
    elif case=='mixed_coordinator_flags':
        result=exercise_mixed_coordinator(context,directory,ledger,common)
        require(result.get('rejected') is True,'mixed-coordinator-flags-denied')
        return result
    else:raise AssertionError('unimplemented-roster:'+case)
    before=ledger.read_bytes() if ledger.is_file() else None
    before_receipt=(receipt.read_bytes(),receipt.stat().st_ino) if receipt.is_file() else None
    observed=expect_rejection(call,api,reason)
    if case=='conflicting_preexisting_receipt':
        view_oracle(get_view(api,ledger,common),context,'pending-publication')
        for reported in exercise_current_callers(context,directory,ledger,common,case).values():
            view_oracle(reported,context,'pending-publication')
    if case!='conflicting_preexisting_receipt':require(before==(ledger.read_bytes() if ledger.is_file() else None),'rejection-ledger-preserved:'+case)
    if before_receipt is not None:require(before_receipt==(receipt.read_bytes(),receipt.stat().st_ino),'rejection-receipt-preserved:'+case)
    if symlink_snapshot is not None:
        link,text,target,data,live,kind=symlink_snapshot
        require(link.is_symlink() and os.readlink(link)==text,'symlink-spelling-preserved:'+case)
        after=(target/'ledger.json').read_bytes() if live and kind in ('directory','root') else target.read_bytes() if live else None
        require(after==data and (live or not target.exists()),'symlink-target-preserved:'+case)
    if case in ('absolute_escape','traversal_escape','nested_destination'):
        require(not (root/'outside.json').exists() and not (directory/'nested').exists(),'escape-destination-absent:'+case)
    return {'expectation':observed}


def run_negative_controls(root,baseline,expected,fresh_modules,context):
    rows=[]
    assertions={'wrong_total':'view-policy_liability_seconds','double_counted_purpose':'view-purpose-map',
     'hidden_unknown_tail':'view-unknown-tail:D129-S','false_receipt_success':'receipt-exact-intent-bytes',
     'stale_source_identity':'view-source-identity','forged_authority_identity':'view-authority-identity'}
    for case in NEGATIVE_CASES:
        try:
            directory,ledger,receipt,api,record,common=scenario(root,case,baseline,expected,fresh_modules,context)
            producer=commit(api,ledger,record,common);view=get_view(api,ledger,common)
            persisted_oracle(ledger,receipt,expected,record,view,context)
            if case=='wrong_total':view['policy_liability_seconds']=25799
            elif case=='double_counted_purpose':view['purpose_allocations']=dict(view['purpose_allocations'],duplicate=9000)
            elif case=='hidden_unknown_tail':view['actual_evidence']['D129-S']['unknown_tail']=False
            elif case=='false_receipt_success':receipt.write_bytes(b'wrong publication despite reported success\n')
            elif case=='stale_source_identity':view['source_sha256']={}
            else:view['authority_pins']={}
            try:persisted_oracle(ledger,receipt,expected,record,view,context)
            except AssertionError as exc:
                require(str(exc)==assertions[case],'negative-exact-assertion:'+case+':'+str(exc))
                rows.append({'case_id':case,'status':'pass','expected_assertion':str(exc),'producer_returned':producer})
            else:raise AssertionError('negative-control-escaped:'+case)
        except Exception as exc:rows.append(failure(case,exc))
    return rows


def caller_argv(context,directory,ledger,common):
    authority_path=directory/'authority.json';pin_path=directory/'reader-pin.json'
    authority_path.write_bytes(canonical(context['authority']));pin_path.write_bytes(canonical(context['reader_pin']))
    return ['--ledger',str(ledger),'--project-root',str(directory),'--lock-root',str(common['lock_root']),
      '--settlement-approval',str(authority_path),'--reader-pin',str(pin_path)]


def exercise_current_callers(context,directory,ledger,common,case):
    argv=caller_argv(context,directory,ledger,common);results={}
    status,stdout=context['coordinator_main'](['--accounting-preflight','--accounting-scope','D133']+argv)
    require(status==0,'actual-coordinator-exit');results['coordinator']=json.loads(stdout)
    for lane in ('read-current','remaining','recompute-receipt'):
        status,stdout=context['settlement_main'](['--case',lane]+argv)
        require(status==0,'actual-cli-exit:'+lane);results[lane]=json.loads(stdout)
    return results


def exercise_mixed_coordinator(context,directory,ledger,common):
    argv=caller_argv(context,directory,ledger,common)
    try:
        status,stdout=context['coordinator_main'](['--accounting-preflight','--accounting-scope','D133','--capture','tank-battle']+argv)
    except SystemExit as exc:
        require(exc.code==2,'mixed-flags-parser-exit');return {'rejected':True,'assertion':'mixed-flags-parser-exit'}
    require(status!=0,'mixed-flags-exit')
    require('mixed' in stdout.lower() or 'scope' in stdout.lower(),'mixed-flags-reason')
    return {'rejected':True,'status_code':status,'output':stdout}
