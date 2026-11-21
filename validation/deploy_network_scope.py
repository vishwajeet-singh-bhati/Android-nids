"""Install/inspect the reviewed scope fix. Never starts a lab target or an attack."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import time
import zipfile

import controlled_phone_test as lab

ROOT=Path(__file__).resolve().parents[1]
PRIVATE=ROOT/'runs/false_positive_audit_20261121'
PUBLIC=ROOT/'validation/reports/false_positive_audit_20261121'
APK=ROOT/'android/app/build/outputs/apk/debug/app-debug.apk'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(label):
    folder=PRIVATE/label;folder.mkdir(parents=True,exist_ok=True)
    for name in ('activity_history_v1.db','activity_history_v1.db-wal','activity_history_v1.db-shm'):
        value=lab.adb('exec-out','run-as','nids.app','cat','files/'+name,binary=True,required=False)
        if value:(folder/name).write_bytes(value)
    with sqlite3.connect(folder/'activity_history_v1.db') as db:
        integrity=db.execute('pragma integrity_check').fetchone()[0]
        assert integrity=='ok'
        rows=[json.loads(row[0]) for row in db.execute('select body from observations')]
        feedback=[row[0] for row in db.execute('select id from feedback')]
    lab.save(folder/'monitor.json',lab.monitor_state())
    notifications=lab.adb('shell','dumpsys','notification','--noredact')
    (folder/'notifications.txt').write_text(notifications,encoding='utf-8')
    lab.save(folder/'ids.json',{'observations':[r['id'] for r in rows],'feedback':feedback})
    return folder,rows,feedback


def deploy():
    lab.select_phone()
    package=lab.adb('shell','pm','path','nids.app').strip().removeprefix('package:')
    assert re.fullmatch(r'/data/app/[A-Za-z0-9_~+=/.-]+/base\.apk',package)
    installed_sha=lab.adb('shell','su','-c',"'sha256sum "+package+"'").split()[0]
    if installed_sha==sha(APK) and (PUBLIC/'deployment.json').exists():
        print('Reviewed APK already installed; inspecting without stopping monitoring.',flush=True)
        inspect();return
    assert installed_sha=='bfe0c3eb0d4deaa38c6be20400b40d0dc36cb64d996d125f98abc96d5a7c8563','Expected original code39; no app was stopped or replaced.'
    contract_path=PUBLIC/'feature_scope_contract.json'
    if not contract_path.exists():contract_path=PUBLIC/'isolated_contract.json'
    contract=json.loads(contract_path.read_text(encoding='utf-8'))
    assert contract['passed'] and contract['device_local_scope_and_history']
    for name,digest in contract['source_manifest'].items():
        base=ROOT/'android/app/src'/('androidTest' if name=='HybridNoteContract.kt' else 'main')/'kotlin/nids/app'
        assert sha(base/name)==digest,'Source changed after isolated validation: '+name
    # Pause the owned app for a consistent DB/WAL backup before any replacement.
    lab.adb('shell','am','force-stop','nids.app')
    before,rows,feedback=snapshot('before_code40')
    lab.adb('pull',package,str(before/'rollback.apk'),timeout=120)
    assert sha(before/'rollback.apk')=='bfe0c3eb0d4deaa38c6be20400b40d0dc36cb64d996d125f98abc96d5a7c8563'
    baseline=json.loads((ROOT/'validation/reports/forgesight_pr_review/final_deployment.json').read_text(encoding='utf-8'))
    with zipfile.ZipFile(APK) as z:
        for name,digest in baseline['model_hashes'].items():
            asset='assets/'+name
            if asset in z.namelist():assert hashlib.sha256(z.read(asset)).hexdigest()==digest
            else:
                actual=lab.adb('shell','run-as','nids.app','sha256sum','files/'+name).split()[0]
                assert actual==digest
    print(lab.adb('install','-r',str(APK)),flush=True)
    print(lab.adb('install','-r',str(ROOT/'android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk')),flush=True)
    result=lab.adb('shell','am','instrument','-w','-e','mode','aligned_v2_native','nids.app.test/nids.app.ValidationInstrumentation',timeout=120)
    assert 'INSTRUMENTATION_CODE: -1' in result and 'INSTRUMENTATION_RESULT: error=' not in result,result
    native=json.loads(lab.adb('exec-out','run-as','nids.app','cat','files/aligned_v2_native_validation.json'))
    assert native['passed'];lab.save(PUBLIC/'native_code40.json',native)
    lab.adb('shell','am','start','-n','nids.app/.LearnedNetworkActivity','--ez','start_monitor','true','--ez','validation_trace','true')
    deadline=time.monotonic()+40
    while True:
        state=lab.monitor_state()
        if state.get('enabled') and state.get('foreground') and state.get('last_heartbeat',{}).get('local_only_alerts_enabled') is False:break
        assert time.monotonic()<deadline,'New monitor did not initialize';time.sleep(1)
    started=next(r['time_ms'] for r in reversed(lab.monitor_log()) if r.get('event')=='session_start')
    release=ROOT/'artifacts/releases/nids-0.14.2-network-scope.apk';shutil.copy2(APK,release)
    lab.save(PUBLIC/'deployment.json',{'version_code':40,'version_name':'0.14.2-network-scope','apk_sha256':sha(APK),
        'model_hashes':baseline['model_hashes'],'weights_and_thresholds_unchanged':True,'native_checks_passed':True,
        'passive_observation_start_ms':started,'before_observations':len(rows),'before_feedback':len(feedback),
        'automatic_attacks_started':False,'ordinary_external_false_positives_fixed':False})
    print('DEPLOYED',40,sha(APK),'PASSIVE_START',started,flush=True)


def inspect():
    lab.select_phone();deployment=json.loads((PUBLIC/'deployment.json').read_text(encoding='utf-8'))
    package=lab.adb('shell','pm','path','nids.app').strip().removeprefix('package:')
    assert re.fullmatch(r'/data/app/[A-Za-z0-9_~+=/.-]+/base\.apk',package)
    installed_sha=lab.adb('shell','su','-c',"'sha256sum "+package+"'").split()[0]
    assert installed_sha==deployment['apk_sha256']
    state=lab.monitor_state();events=[r for r in lab.monitor_log() if r.get('time_ms',0)>=deployment['passive_observation_start_ms']]
    folder,rows,feedback=snapshot('after_code40')
    with sqlite3.connect(PRIVATE/'before_code40/activity_history_v1.db') as db:
        originals={json.loads(row[0])['id']:json.loads(row[0]) for row in db.execute('select body from observations')}
    current={r['id']:r for r in rows};missing=set(originals)-set(current)
    assert not missing,missing
    locals_=[r for r in rows if r.get('traffic_scope')=='device_local']
    changed=[]
    for row in locals_:
        original=originals.get(row['id'])
        if original:
            assert original['model_evidence']==row['model_evidence']
            assert row['revision']==original['revision']+1
            if 'feedback' in original:assert row['feedback']==original['feedback']
            changed.append(row['id'])
        assert row['disposition'] in ('dismissed','out_of_scope') and row['explanation_status']=='not_applicable'
    external_unchanged=all(current[k]==v for k,v in originals.items() if k not in changed)
    local_events=[r for r in events if r.get('event')=='device_local_flow']
    flags=[r for r in events if r.get('event')=='model_flag']
    result={'installed_apk_sha256_verified':installed_sha,'monitor':state,'session_age_seconds':(time.time()*1000-deployment['passive_observation_start_ms'])/1000,
        'device_local_summaries':len(local_events),'local_summaries_not_model_evaluated':sum(not r['model_evaluated'] for r in local_events),
        'model_flags':len(flags),'flags_by_scope':dict(Counter(r.get('evidence',{}).get('traffic_scope','unrecorded') for r in flags)),
        'original_observations_preserved':len(originals),'missing_originals':len(missing),'local_history_reclassified':len(changed),
        'external_history_unchanged':external_unchanged,'feedback_preserved':len(feedback)==deployment['before_feedback'],
        'benign_web_control_included':(PUBLIC/'benign_web_code40.json').exists(),
        'scope':'Post-install monitoring window, including the separately recorded benign web control when noted. Zero flags does not prove zero everyday FPR. No attack profiles launched.'}
    lab.save(PUBLIC/'passive_code40.json',result);print(json.dumps(result,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('deploy','inspect'));args=parser.parse_args()
    deploy() if args.action=='deploy' else inspect()
