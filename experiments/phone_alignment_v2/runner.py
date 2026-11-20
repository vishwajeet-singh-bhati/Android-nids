"""Durable local scheduler: wait for complete raw data and smoke, train, freeze/evaluate."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import fcntl,json,os,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_alignment_v2.common import *
from experiments.phone_alignment_v2.preflight import configuration


def publish(phase,**extra):
    atomic(RUN/'status.json',{'phase':phase,'pid':os.getpid(),'updated_unix':time.time(),**extra})


def source_alive(pid,needle):
    try:return needle in Path(f'/proc/{pid}/cmdline').read_bytes().decode(errors='replace')
    except OSError:return False


def main():
    RUN.mkdir(parents=True,exist_ok=True)
    with (RUN/'scheduler.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        preparation=None
        if not (CACHE/'ready.json').exists():
            old=json.loads((RUN/'preparation_status.json').read_text()) if (RUN/'preparation_status.json').exists() else {}
            if not source_alive(old.get('pid',-1),'prepare.py'):
                with (RUN/'prepare.log').open('a') as out,(RUN/'prepare_error.log').open('a') as error:
                    preparation=subprocess.Popen([sys.executable,str(ROOT/'experiments/phone_alignment_v2/prepare.py')],stdout=out,stderr=error)
                atomic(RUN/'preparation_status.json',{'phase':'launching','pid':preparation.pid,'updated_unix':time.time()})
                print('PREPARATION_START',preparation.pid,flush=True)
        for _ in range(2160):
            prep=json.loads((RUN/'preparation_status.json').read_text()) if (RUN/'preparation_status.json').exists() else {}
            smoke=json.loads((PUBLIC/'automation_smoke.json').read_text()) if (PUBLIC/'automation_smoke.json').exists() else {}
            if prep.get('phase')=='failed':raise RuntimeError('Raw-data preparation failed: '+prep.get('error','unknown'))
            if preparation is not None and preparation.poll() not in (None,0):raise RuntimeError('Preparation subprocess failed; see prepare_error.log')
            if smoke.get('phase')=='failed':raise RuntimeError('Automation smoke failed: '+smoke.get('error','unknown'))
            if (CACHE/'ready.json').exists() and smoke.get('passed') and smoke.get('executorch_export_passed'):break
            if prep.get('pid') and not source_alive(prep['pid'],'prepare.py') and prep.get('phase')!='ready':raise RuntimeError('Preparation process ended before a ready dataset')
            publish('preparing_data',preparation=prep,automation_smoke_passed=bool(smoke.get('passed')),training_started=False)
            time.sleep(10)
        else:raise RuntimeError('Raw-data/smoke preparation exceeded six hours')
        if not (RUN/'config.json').exists():
            config=configuration()
            files=sorted((ROOT/'experiments/phone_alignment_v2').glob('*.py'))
            config['code_sha256']={str(p.relative_to(ROOT)):sha(p) for p in files}
            config['extractor_sha256']=sha(RUN/'extractor/core.jar')
            config['data_report_sha256']=sha(CACHE/'ready.json');config['rollback_tag']='checkpoint/pre-alignment-20261119'
            atomic(RUN/'config.json',config);atomic(PUBLIC/'training_config.json',config)
        config=json.loads((RUN/'config.json').read_text())
        assert config['data_report_sha256']==sha(CACHE/'ready.json')
        pending=list(config['jobs']);running={};finished=[];attempts={};handles=[]
        while pending or running:
            for name,process in list(running.items()):
                code=process.poll()
                if code is None:continue
                del running[name]
                if code:
                    if attempts.get(name,0)<2:
                        pending.insert(0,next(j for j in config['jobs'] if j['name']==name));print('JOB_RETRY',name,code,flush=True)
                    else:raise RuntimeError(f'Training job failed after retry: {name}; exit={code}')
                else:finished.append(name);print('JOB_COMPLETE',name,flush=True)
            while pending and len(running)<config['max_parallel_training']:
                job=pending.pop(0);name=job['name'];folder=RUN/'jobs'/name
                if (folder/'complete.json').exists():finished.append(name);continue
                attempts[name]=attempts.get(name,0)+1
                log=(RUN/(name+'.log')).open('a');handles.append(log)
                running[name]=subprocess.Popen([sys.executable,str(ROOT/'experiments/phone_alignment_v2/train.py'),'--job',name],stdout=log,stderr=subprocess.STDOUT)
                print('JOB_START',name,running[name].pid,flush=True)
            publish('training',completed=len(finished),total=len(config['jobs']),running={name:p.pid for name,p in running.items()},finished=finished,
                epochs_per_job=config['epochs'],early_stopping=False,config_sha256=sha(RUN/'config.json'))
            if running:time.sleep(10)
        for handle in handles:handle.close()
        publish('frozen_final_evaluation',completed=len(finished),total=len(config['jobs']))
        with (RUN/'evaluation.log').open('a') as log:
            subprocess.run([sys.executable,str(ROOT/'experiments/phone_alignment_v2/evaluate.py')],stdout=log,stderr=subprocess.STDOUT,check=True)
        publish('mobile_export',completed=len(finished),total=len(config['jobs']))
        with (RUN/'mobile_export.log').open('a') as log:
            subprocess.run([os.environ.get('NIDS_EXPORT_PYTHON',sys.executable),str(ROOT/'experiments/phone_alignment_v2/export_mobile.py')],stdout=log,stderr=subprocess.STDOUT,check=True)
        result=json.loads((RUN/'evaluation.json').read_text())
        publish('complete',completed=len(finished),total=len(config['jobs']),offline_targets_passed=result['offline_targets_passed'],deployment_allowed=False,
            device_validation_pending=True,results='validation/reports/phone_alignment_v2/RESULTS.md')
        print('ALIGNED_CAMPAIGN_COMPLETE',result['offline_targets_passed'],flush=True)


if __name__=='__main__':
    try:main()
    except BlockingIOError:
        print('SCHEDULER_ALREADY_RUNNING',flush=True)
    except BaseException as error:
        publish('failed',error=str(error));raise
