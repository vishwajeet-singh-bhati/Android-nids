"""Persistent quality-gated capture campaign, then updated-data training/evaluation."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from datetime import datetime
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_capture_v1 import collect as capture
lab=capture.lab
PLAN=capture.PUBLIC/'campaign_plan.json'


def state(phase,**extra):
    lab.save(capture.RUN/'campaign_status.json',{'phase':phase,'pid':os.getpid(),'updated_at_ist':datetime.now(lab.IST).isoformat(),**extra})


def make_plan():
    if PLAN.exists():return json.loads(PLAN.read_text(encoding='utf-8'))
    sessions=[]
    for partition,modes in [('train',['mixed','benign','mixed','mixed','benign','mixed','mixed','benign','mixed','mixed','benign','mixed','mixed','mixed']),
                            ('validation',['mixed','benign','mixed']),('test',['mixed','benign','mixed'])]:
        for i,mode in enumerate(modes):
            number=len(sessions)+1
            sessions.append({'session':f'phone_v1_{partition}_{i+1:02d}','partition':partition,'mode':mode,
                'seed':23000+number*101,'campaign':'phone_real_v1'})
    sources={str(p.relative_to(ROOT)):capture.sha(p) for p in (ROOT/'experiments/phone_capture_v1').glob('*.py')}
    plan={'campaign':'phone_real_v1','authorization':'User explicitly authorized updated real-phone data, correct labels, quality procedure and additional observable attack subtypes.',
        'partitioning':'14/3/3 complete chronological sessions; held-out SQL/XSS forms and rate ranges; same-device pilot, not unseen-day/device evidence.',
        'sources_sha256':sources,'target_apk_sha256':capture.sha(capture.APK),'frozen_extractor_sha256':capture.sha(capture.BUNDLE/'core.jar'),
        'warmup_seconds':capture.WARM_SECONDS,'sessions':sessions,'normal_actions_per_mixed_session':24,'normal_actions_per_benign_session':72,'attack_actions_per_mixed_session':32,
        'fine_attack_subtypes':['http_password_guessing','http_password_spraying','sql_injection','xss'],
        'additional_class_policy':'Password spraying is a Web-family subtype; no extra output family claimed. No Bot/DoS positive labels from unverified probes.',
        'training_after_capture':'Only after all session quality gates and independent partition checks pass; all40epochs/everycheckpoint retained.'}
    lab.save(PLAN,plan);return plan


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--capture-only',action='store_true');args=parser.parse_args()
    capture.RUN.mkdir(parents=True,exist_ok=True);plan=make_plan()
    try:
        for name,digest in plan['sources_sha256'].items():assert capture.sha(ROOT/name)==digest,'Campaign source changed; do not silently resume'
        assert capture.sha(capture.APK)==plan['target_apk_sha256']
        pilot=capture.RUN/'sessions/pilot_development/quality.json'
        while not pilot.exists():
            capture.cancelled()
            assert not pilot.with_name('failure.json').exists(),'Pilot failed; no campaign traffic started'
            state('awaiting_pilot');time.sleep(10)
        assert json.loads(pilot.read_text(encoding='utf-8'))['passed'],'Pilot quality rejected'
        completed=[]
        with lab.exclusive():
            for session in plan['sessions']:
                capture.cancelled();state('collecting',session=session['session'],partition=session['partition'],completed=len(completed),total=len(plan['sessions']))
                quality=capture.collect(session);completed.append(quality)
                lab.save(capture.PUBLIC/'collection_summary.json',{'campaign':plan['campaign'],'accepted_sessions':len(completed),
                    'sessions':completed,'model_predictions_used_as_labels':False,'held_out_model_scores_reviewed':False})
        state('captures_complete',completed=len(completed),total=len(plan['sessions']))
        if not args.capture_only:
            from experiments.phone_capture_v1.augment import prepare
            prepare(plan);state('training')
            from experiments.phone_capture_v1.train_campaign import run
            run();state('complete',accepted_sessions=len(completed),evaluation_report='validation/reports/phone_capture_training_v1/RESULTS.md')
    except BaseException as error:
        state('failed',error=str(error));raise


if __name__=='__main__':main()
