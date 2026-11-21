"""Durable local repair scheduler; prepare/smoke/train/select/evaluate/export."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import fcntl,json,os,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_repair_v3.common import *


def publish(phase,**extra):atomic(RUN/'status.json',{'phase':phase,'pid':os.getpid(),'updated_unix':time.time(),**extra})


def step(script,phase,python=None):
    publish(phase)
    with (RUN/(phase+'.log')).open('a') as log:subprocess.run([str(python or sys.executable),str(ROOT/'experiments/phone_repair_v3'/script)],stdout=log,stderr=subprocess.STDOUT,check=True)


def main():
    RUN.mkdir(parents=True,exist_ok=True);PUBLIC.mkdir(parents=True,exist_ok=True)
    with (RUN/'scheduler.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        step('data.py','preparing_data')
        smoke=json.loads((PUBLIC/'automation_smoke.json').read_text()) if (PUBLIC/'automation_smoke.json').exists() else {}
        if not smoke.get('passed'):step('preflight.py','automation_smoke')
        assert json.loads((PUBLIC/'automation_smoke.json').read_text())['passed']
        if not (RUN/'config.json').exists():
            config=configuration();old=json.loads((BASE/'frozen_selection.json').read_text())['choices'];v=json.loads((BASE/'jobs'/old['gate']/'best_validation.json').read_text())['validation']
            config['baseline_policy']={'low':v['threshold'],'high':v['threshold'],'review_accept':.5,'type_cutoff':.6}
            files=sorted((ROOT/'experiments/phone_repair_v3').glob('*.py'))+[ROOT/'experiments/phone_alignment_v2'/p for p in ('models.py','train.py','evaluate.py','common.py')]+[ROOT/'experiments/tsanet_android/export_model.py']
            config['code_sha256']={str(p.relative_to(ROOT)):sha(p) for p in files};config['data_report_sha256']=sha(RUN/'data_ready.json');config['rollback_tag']='checkpoint/pre-repair-v3-20261119'
            atomic(RUN/'config.json',config);atomic(PUBLIC/'training_config.json',config)
        config=json.loads((RUN/'config.json').read_text());assert config['data_report_sha256']==sha(RUN/'data_ready.json')
        for file,expected in config['code_sha256'].items():assert sha(ROOT/file)==expected,'Frozen source changed: '+file
        pending=list(config['jobs']);running={};finished=[];attempts={};handles=[]
        while pending or running:
            for name,process in list(running.items()):
                code=process.poll()
                if code is None:continue
                del running[name]
                if code:
                    if attempts[name]<2:pending.insert(0,next(j for j in config['jobs'] if j['name']==name));print('JOB_RETRY',name,code,flush=True)
                    else:raise RuntimeError('Training failed after resumable retry: '+name)
                else:finished.append(name);print('JOB_COMPLETE',name,flush=True)
            while pending and len(running)<config['max_parallel_training']:
                job=pending.pop(0);name=job['name'];folder=RUN/'jobs'/name
                if (folder/'complete.json').exists():finished.append(name);continue
                attempts[name]=attempts.get(name,0)+1;log=(RUN/(name+'.log')).open('a');handles.append(log)
                running[name]=subprocess.Popen([sys.executable,str(ROOT/'experiments/phone_repair_v3/train.py'),'--job',name],stdout=log,stderr=subprocess.STDOUT)
                print('JOB_START',name,running[name].pid,flush=True)
            publish('training',completed=len(finished),total=len(config['jobs']),running={k:p.pid for k,p in running.items()},epochs_per_job=config['epochs'],early_stopping=False)
            if running:time.sleep(10)
        for h in handles:h.close()
        step('select.py','joint_selection');step('evaluate.py','final_comparison');step('export_mobile.py','mobile_export',os.environ.get('NIDS_EXPORT_PYTHON',sys.executable))
        report=json.loads((RUN/'evaluation.json').read_text());publish('complete',completed=len(config['jobs']),total=len(config['jobs']),epochs_retained=len(config['jobs'])*config['epochs'],
            repair_is_better=report['repair_is_better'],intended_deployment=report['intended_deployment'],device_validation_pending=True,deployment_executed=False)
        print('REPAIR_CAMPAIGN_COMPLETE',report['repair_is_better'],report['intended_deployment'],flush=True)


if __name__=='__main__':
    try:main()
    except BlockingIOError:print('REPAIR_SCHEDULER_ALREADY_RUNNING',flush=True)
    except BaseException as error:publish('failed',error=str(error));raise
