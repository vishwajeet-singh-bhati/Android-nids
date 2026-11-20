"""Finish user-authorized bounded Pixel tests sequentially; no model changes.

Remaining profiles plus a final normal control. Earlier verified cases are retained.
The explicit user instruction to automate supersedes the previous manual-only rule.
"""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'validation'))
import controlled_phone_test as lab
from manual_test_correlation import captured_tcp_tuples,endpoint,key,smoke as correlation_smoke

PROFILES=('HTTPFlood','SlowScan','Beacon','Benign')
OUTPUT=ROOT/'runs/v2_automated_phone_tests'
PUBLIC=ROOT/'validation/reports/v2_automated_phone_tests'
NAMES=['Benign','Bot','Brute Force','DDoS','DoS','Port Scan','Web Attack','Unclassified']
GATE='99e5f3b62b1f6940cd2fb40d05c2edb14b3a7fb83c3bc1f989e63879202ca529'
DIAG='585f43e8bf4299f755036e9ccbe55121fce14d8ff59a67fcfdcfb4ba8af951dd'


def state(phase,**extra):
    lab.save(OUTPUT/'status.json',{'phase':phase,'updated_at_ist':datetime.now(lab.IST).isoformat(),**extra})


def cancelled():
    if (OUTPUT/'STOP').exists():raise RuntimeError('Automated suite cancelled by STOP marker')


def wait_until(deadline,phase,**extra):
    while time.time()<deadline:
        cancelled();state(phase,seconds_remaining=round(deadline-time.time()),**extra)
        time.sleep(min(15,max(.1,deadline-time.time())))


def validate_identity():
    lab.select_phone()
    package=lab.adb('shell','dumpsys','package','nids.app')
    assert 'versionCode=36 ' in package and 'versionName=0.12.2-aligned-v2-test' in package
    for kind,wanted in [('gate',GATE),('diagnosis',DIAG)]:
        value=lab.adb('exec-out','run-as','nids.app','cat','files/aligned_v2_'+kind+'.pte',binary=True)
        assert hashlib.sha256(value).hexdigest()==wanted,'Installed v2 model changed'


def health():
    value=lab.monitor_state();assert value['enabled'] and value['foreground'],'Monitor paused/unavailable; no next test launched'
    assert value['schema']=='phone-aligned-v2'
    beat=value['last_heartbeat'];assert beat
    assert all(beat.get(k,-1)==0 for k in ['late_packets','queue_drops','evictions','history_evictions','forced_reorder','invalid_rate_flows']),beat
    return value


def trace_snapshot(path):
    data=lab.adb('exec-out','run-as','nids.app','cat','files/tsanet_validation_trace.jsonl',binary=True,required=False)
    path.write_bytes(data)
    return lab.json_lines(data.decode('utf-8'))


def prepare_fresh_session():
    health();lab.adb('shell','am','force-stop','nids.app')
    before=OUTPUT/'trace_before_suite.jsonl';trace_snapshot(before)
    # Only this backed-up diagnostic file is reset; history and Llama are retained.
    lab.adb('shell','run-as','nids.app','rm','-f','files/tsanet_validation_trace.jsonl')
    lab.adb('shell','am','start','-n','nids.app/.LearnedNetworkActivity','-f','0x20000000',
        '--ez','start_monitor','true','--ez','validation_trace','true')
    deadline=time.time()+45
    while True:
        cancelled()
        try:
            h=health()
            if h['history_age_seconds'] is not None and h['history_age_seconds']<60:break
        except (AssertionError,RuntimeError):pass
        assert time.time()<deadline,'Fresh monitor did not start'
        time.sleep(1)
    wait_until(time.time()+max(0,305-h['history_age_seconds']),'warming_history',profile=PROFILES[0])
    return {'trace_backup_sha256':hashlib.sha256(before.read_bytes()).hexdigest(),'activity_history_cleared':False,
        'connection_history_reset_and_rewarmed':True,'diagnostic_trace_reset':True}


def review(case):
    meta=json.loads((case/'run.json').read_text(encoding='utf-8'));check=json.loads((case/'check.json').read_text(encoding='utf-8'))
    trace=trace_snapshot(case/'nids_numeric_trace.jsonl');tuples,note=captured_tcp_tuples(case/'traffic.pcap');assert tuples is not None
    lower=meta['start_unix']*1000;upper=datetime.fromisoformat(check['checked_at_ist']).timestamp()*1000
    matched=[]
    for row in trace:
        if not lower<=row.get('time_ms',0)<=upper or row.get('schema')!='phone-aligned-v2':continue
        a=(row['source'],row['sport']);b=(row['destination'],row['dport'])
        if key(row['protocol'],a,b) in tuples:matched.append(row)
    assert matched,'No native decisions matched recorded test traffic'
    observed={key(r['protocol'],(r['source'],r['sport']),(r['destination'],r['dport'])) for r in matched}
    assert observed==tuples,'Missing test tuple in bounded native trace'
    flags=[r for r in matched if r['flagged']]
    count={name:sum(r['class_id']==i for r in matched) for i,name in enumerate(NAMES)}
    assert len(flags)==check['traffic_correlation']['counts']['matched_test_capture'],'Flag/trace test correlation disagrees'
    beat=check['monitor']['last_heartbeat']
    assert all(beat.get(k,-1)==0 for k in ['late_packets','queue_drops','evictions','history_evictions','forced_reorder','invalid_rate_flows'])
    if meta['profile']=='SlowScan':
        interpretation='Controlled scan detected' if flags else 'Controlled scan missed'
    elif meta['profile']=='Benign':
        interpretation='Normal control quiet' if not flags else 'Normal control flagged: false positives on controlled requests'
    elif meta['profile']=='HTTPFlood':
        interpretation='Bounded HTTP load flagged' if flags else 'Bounded HTTP load unflagged'
    else:
        verified=check['target_event_counts'].get('beacon_ping_pong',0)==12 and sum(r.get('response')=='PONG' for r in meta.get('beacon_responses',[]))==12
        interpretation=('Fixed beacon behavior flagged' if flags else 'Fixed beacon behavior unflagged') if verified else 'Inconclusive: beacon exchanges did not complete; inspect receiver connectivity'
    result={'run_id':case.name,'profile':meta['profile'],'invocation_mode':meta['invocation_mode'],'suite_id':meta['suite_id'],
        'attempts':len(meta['attempts']),'target_events':check['target_event_counts'],'traffic_summary':check['traffic_summary'],
        'captured_packets':check['packet_evidence']['captured_records'],'captured_tcp_tuples':len(tuples),
        'native_decisions_matched':len(matched),'all_capture_tuples_observed':True,
        'native_packet_count_sum':sum(r['flow'][1]+r['flow'][2] for r in matched),
        'test_matched_flags':len(flags),'classification_counts':count,
        'window_flags':check['nids_model_flags_during_window'],'correlation':check['traffic_correlation'],
        'activity_rows_in_window':check['new_or_updated_activity_rows'],'visible_activity_alerts':check['currently_visible_alerts_for_activity_rows'],
        'activity_types':[a.get('model_evidence',{}).get('suspected_pattern') for a in check['activities']],
        'capture_healthy':True,'interpretation':interpretation,'gate_model_sha256':GATE,'diagnosis_model_sha256':DIAG,
        'trace_rows_at_pull':len(trace),'scope':'One bounded case; retries/segments correlated. Load/heartbeat traffic does not establish full-scale DoS or real Bot malware. Window alerts are not automatically test detections.'}
    if meta['profile']=='Beacon':
        probe=[r for r in matched if r['source']==meta['phone'] and r['dport']==43990]
        result.update({'beacon_native_segments':len(probe),'beacon_flagged_segments':sum(r['flagged'] for r in probe),
            'target_behavior_verified':verified})
    lab.save(case/'native_trace_review.json',result)
    lab.save(PUBLIC/(case.name+'_review.json'),result)
    isolate=max([meta['traffic_end_unix']]+[r['time_ms']/1000 for r in matched])+305
    return result,isolate


def smoke():
    assert PROFILES==('HTTPFlood','SlowScan','Beacon','Benign')
    assert len(set(PROFILES))==4 and set(PROFILES).issubset(set(lab.ATTACKS)|{'Benign'})
    assert correlation_smoke()['passed']
    # Exact boundary guard: 130 seconds observation alone does not clear300s history.
    finish=1000;deadline=finish+305;assert deadline-(finish+130)==175
    result={'passed':True,'profiles':list(PROFILES),'serial_execution':True,'context_isolation_seconds':305,
        'unchanged_model_hashes':[GATE,DIAG],'background_flag_correlation_regression':True,'actual_phone_actions':0,'attack_requests_sent':0}
    lab.save(PUBLIC/'automation_smoke.json',result);print(json.dumps(result,indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--smoke',action='store_true');args=parser.parse_args()
    OUTPUT.mkdir(parents=True,exist_ok=True);PUBLIC.mkdir(parents=True,exist_ok=True)
    if args.smoke:smoke();return
    completed=[];manifest=PUBLIC/'results.json'
    if manifest.exists() and json.loads(manifest.read_text())['state']=='complete':
        print('Remaining suite already complete; no tests repeated.');return
    suite_id=datetime.now(lab.IST).strftime('%Y%m%d_%H%M%S_remaining_v2')
    lab.save(PUBLIC/'plan.json',{'suite_id':suite_id,'authorization':'User explicitly asked: run all tests automatedly and report results.',
        'profiles':list(PROFILES),'retained_previous_verified_cases':6,'models_fixed':True,'context_isolation_seconds':305,
        'parallel_profiles':False,'synthetic_alerts':False,'new_training':False})
    try:
        with lab.exclusive():
            validate_identity();state('preparing',suite_id=suite_id);prepared=prepare_fresh_session()
            for index,profile in enumerate(PROFILES):
                cancelled();h=health();assert h['history_age_seconds']>=300
                traces=trace_snapshot(OUTPUT/('trace_before_'+profile+'.jsonl'))
                assert len(traces)<1500,'Insufficient diagnostic trace budget; no next test launched'
                state('testing',suite_id=suite_id,index=index,total=len(PROFILES),profile=profile,completed=completed)
                print('AUTOMATED_CASE_START',profile,flush=True)
                lab.run_case(profile,130,suite_id=suite_id)
                case=Path(json.loads((lab.RUN/'latest.json').read_text())['directory']).resolve();case.relative_to(lab.RUN.resolve())
                result,isolate=review(case);completed.append(result)
                lab.save(manifest,{'state':'running','suite_id':suite_id,'prepared':prepared,'results':completed})
                print('AUTOMATED_CASE_COMPLETE',profile,result['interpretation'],result['test_matched_flags'],flush=True)
                if index+1<len(PROFILES):wait_until(isolate,'context_isolation',suite_id=suite_id,next_profile=PROFILES[index+1],completed_profiles=index+1)
            validate_identity();health()
            report={'state':'complete','suite_id':suite_id,'prepared':prepared,'results':completed,'installed_models_unchanged':True,
                'all_target_behaviors_verified':all(row.get('target_behavior_verified',True) for row in completed),
                'blocked_profiles':[row['profile'] for row in completed if not row.get('target_behavior_verified',True)],
                'phone_monitor_left_running':True,'scope':'Remaining three profiles plus post-suite normal control, explicitly user-authorized. Combine with six previously verified manual cases. No full-scale DDoS/real malware recall claim.'}
            lab.save(manifest,report);state('complete',suite_id=suite_id,completed_profiles=len(completed),total=len(PROFILES))
            print('AUTOMATED_REMAINING_SUITE_COMPLETE',flush=True)
    except BaseException as error:
        state('failed',suite_id=suite_id,error=str(error),completed_profiles=len(completed))
        lab.save(manifest,{'state':'failed','suite_id':suite_id,'error':str(error),'results':completed});raise


if __name__=='__main__':main()
