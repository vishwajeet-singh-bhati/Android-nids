"""Aggregate authorized test records. Filesystem only: no attacks or phone calls."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from pathlib import Path
from datetime import datetime,timezone,timedelta
import collections
import json

ROOT=Path(__file__).resolve().parents[1]
IST=timezone(timedelta(hours=5,minutes=30))


def target_evidence(name,meta,check,packet):
    events=check.get('target_event_counts',{})
    if name in ('PortScan','SlowScan'):
        if packet:return f"{packet.get('pc_to_phone_syn_packets',0)} SYN / {packet.get('phone_to_pc_rst_packets',0)} RST captured",bool(packet.get('pc_to_phone_syn_packets'))
        return 'TCP attempts recorded; packet arrival not retained',False
    if name=='PasswordGuessing':
        return f"{events.get('login_failure',0)} failed / {events.get('login_success',0)} successful dummy login",events.get('login_failure',0)>0
    if name=='SQLInjection':return f"{events.get('sqli_confirmed',0)} confirmed dummy SQL injection responses",events.get('sqli_confirmed',0)>0
    if name=='XSS':return f"{events.get('xss_execution_confirmed',0)} confirmed isolated script execution",events.get('xss_execution_confirmed',0)>0
    if name=='HTTPFlood':return f"{events.get('http_request',0)} HTTP requests; denial of service not established",events.get('http_request',0)>0
    if name=='ConnectionExhaustion':return f"{events.get('test_resource_denied',0)} denials of the isolated two-slot resource",events.get('test_resource_denied',0)>0
    if name=='Beacon':return f"{events.get('beacon_ping_pong',0)} fixed PING/PONG exchanges; behavior probe",events.get('beacon_ping_pong',0)>0
    if name=='Benign':return f"{events.get('http_request',0)} normal test requests",events.get('http_request',0)>0
    return 'Target proof requires review',False


def update_log(root=ROOT):
    records=[]
    for path in sorted((root/'runs/manual_phone_tests').glob('*/run.json')):
        try:
            meta=json.loads(path.read_text());check_path=path.with_name('check.json')
            check=json.loads(check_path.read_text()) if check_path.exists() else {}
            packet_path=path.with_name('packet_evidence.json')
            packet=json.loads(packet_path.read_text()) if packet_path.exists() else None
        except (ValueError,OSError):continue
        name=meta.get('profile','unknown');target,proof=target_evidence(name,meta,check,packet)
        from manual_test_correlation import correlate
        correlation=correlate(check.get('model_flags',[]),meta,path.with_name('traffic.pcap'))
        matched=correlation['counts']['matched_test_capture'] if correlation['capture_available_for_matching'] else None
        flags=check.get('nids_model_flags_during_window')
        if not meta.get('traffic_completed'):outcome='Interrupted/incomplete; review saved error'
        elif flags is None:outcome='Awaiting detector observation'
        elif flags and matched==0:outcome='Window flags do not match recorded test traffic; review background/unresolved events'
        elif flags:outcome='Test-traffic flags observed; native trace/type review required'
        elif name=='Benign':outcome='No alert in normal-traffic control'
        elif proof:outcome='No alert for verified test behavior'
        else:outcome='No alert; target proof incomplete'
        statuses=collections.Counter(str(r['http_status']) for r in meta.get('attempts',[]) if r.get('http_status') is not None)
        records.append({'run_id':path.parent.name,'profile':name,
            'invocation_mode':meta.get('invocation_mode','manual'),'suite_id':meta.get('suite_id'),
            'detector_schema':meta.get('detector_schema','tsanet_phone_v1'),
            'gate_model_sha256':meta.get('gate_model_sha256'),'diagnosis_model_sha256':meta.get('diagnosis_model_sha256'),
            'profile_variant':meta.get('profile_variant','original_fast' if name=='PasswordGuessing' else 'default'),
            'login_interval_seconds':meta.get('login_interval_seconds',.2 if name=='PasswordGuessing' else None),
            'started_at_ist':datetime.fromtimestamp(meta['start_unix'],IST).isoformat(),
            'attempts':len(meta.get('attempts',[])),'http_status_counts':dict(statuses),'target_evidence':target,
            'target_behavior_verified':proof,'model_flags_in_window':flags,
            'flags_matched_test_capture':matched,'traffic_correlation_counts':correlation['counts'],
            'new_or_updated_activity_rows':check.get('new_or_updated_activity_rows'),
            'visible_related_alerts':check.get('currently_visible_alerts_for_activity_rows'),
            'packet_capture_sha256':packet.get('sha256') if packet else None,
            'history_age_seconds':meta.get('history_age_at_start'),'observation_seconds':meta.get('observation_seconds'),
            'outcome':outcome})
    out=root/'validation/reports/manual_phone_tests';out.mkdir(parents=True,exist_ok=True)
    payload={'updated_at_ist':datetime.now(IST).isoformat(),'runs':records,
        'scope':'User-authorized sequential diagnostics; launch mode is recorded per case. Window-level flags may include background activity. Attempts/flows are not independent attacks. No population accuracy or attack-recall percentage inferred.'}
    (out/'test_log.json').write_text(json.dumps(payload,indent=2)+'\n')
    lines=['# Manual phone test log','',payload['scope'],'',
        '| Run (IST) | Detector | Profile | Attempts | Target evidence | Window flags | Matched test flags | App activities | Visible alerts | Outcome |',
        '|---|---|---|---:|---|---:|---:|---:|---:|---|']
    for r in records:
        name=r['profile']+(f" ({r['login_interval_seconds']}s spacing)" if r['profile']=='PasswordGuessing' else '')
        lines.append(f"| {r['started_at_ist'][11:19]} | {r['detector_schema']} | {name} | {r['attempts']} | {r['target_evidence']} | {r['model_flags_in_window']} | {r['flags_matched_test_capture']} | {r['new_or_updated_activity_rows']} | {r['visible_related_alerts']} | {r['outcome']} |")
    lines+=['','HTTP login guessing is under the original training Web Attack family; the Brute Force family contains FTP/SSH-Patator. A successful HTTP test does not establish an FTP/SSH reproduction. Fixed PING/PONG and bounded HTTP load do not establish bot infection or successful distributed DoS.',
        '', 'Private raw evidence remains in runs/manual_phone_tests. Models and thresholds stay unchanged during this campaign. Launch mode is recorded per case; the user subsequently authorized a sequential automated suite. This log itself schedules nothing.','']
    (out/'TEST_LOG.md').write_text('\n'.join(lines))
    return out/'TEST_LOG.md'


if __name__=='__main__':print(update_log())
