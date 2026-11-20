"""Bounded parallel local training and final evaluation after all capture gates."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json
from pathlib import Path
import subprocess
import time

from experiments.phone_capture_v1 import collect as capture
from experiments.phone_capture_v1.augment import TRAIN_RUN



def run():
    config=json.loads((TRAIN_RUN/'config.json').read_text(encoding='utf-8'));pending=list(config['jobs']);active={}
    logs=TRAIN_RUN/'logs';logs.mkdir(parents=True,exist_ok=True)
    try:
        while pending or active:
            capture.cancelled()
            while pending and len(active)<2:
                job=pending.pop(0);name=job['name']
                if (TRAIN_RUN/'jobs'/name/'complete.json').exists():continue
                stream=(logs/(name+'.log')).open('ab')
                process=subprocess.Popen(train_command('experiments.phone_capture_v1.train_augmented','--job',name),
                    cwd=capture.ROOT,stdout=stream,stderr=subprocess.STDOUT)
                active[name]=(process,stream);print('TRAIN_START',name,process.pid,flush=True)
            for name,(process,stream) in list(active.items()):
                code=process.poll()
                if code is None:continue
                stream.close();del active[name]
                assert code==0,'Training failed: '+name+'; inspect its saved log/checkpoint'
                folder=TRAIN_RUN/'jobs'/name
                complete=json.loads((folder/'complete.json').read_text(encoding='utf-8'))
                assert complete['epochs']==40 and complete['all_epochs_retained'] and len(list(folder.glob('epoch_*.pt')))==40
                print('TRAIN_COMPLETE',name,flush=True)
            capture.lab.save(TRAIN_RUN/'scheduler_status.json',{'running':{k:v[0].pid for k,v in active.items()},'pending':[j['name'] for j in pending],
                'completed':sum((TRAIN_RUN/'jobs'/j['name']/'complete.json').exists() for j in config['jobs']),'total':len(config['jobs']),'early_stopping':False})
            if active:time.sleep(10)
        with (logs/'evaluation.log').open('ab') as stream:
            result=subprocess.run(train_command('experiments.phone_capture_v1.evaluate_augmented'),cwd=capture.ROOT,stdout=stream,stderr=subprocess.STDOUT)
        assert result.returncode==0,'Evaluation failed; checkpoints preserved and no phone model changed'
        final=capture.ROOT/'validation/reports/phone_capture_training_v1'
        assert (final/'RESULTS.md').exists() and json.loads((final/'evaluation.json').read_text())['state']=='complete'
        assert all((TRAIN_RUN/'exports'/(kind+'.pt')).exists() for kind in ['gate','diagnosis'])
    finally:
        for process,stream in active.values():
            if process.poll() is None:process.terminate()
            stream.close()
