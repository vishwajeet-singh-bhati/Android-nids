"""Two-epoch automation smoke on real stored rows; no research accuracy claim."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json
import os
from pathlib import Path
import sys
import numpy as np

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
SMOKE_RUN=ROOT/'runs/phone_capture_v1/training_smoke'
SMOKE_CACHE=ROOT/'data/experiments/phone_capture_training_smoke'
os.environ['NIDS_ALIGNED_RUN']=str(SMOKE_RUN);os.environ['NIDS_ALIGNED_CACHE']=str(SMOKE_CACHE)
os.environ['NIDS_ALIGNED_PUBLIC']=str(ROOT/'validation/reports/phone_capture_v1')


def main():
    import torch
    from experiments.phone_alignment_v2 import train as training
    from experiments.phone_alignment_v2.models import build,RawWrapper
    from experiments.phone_alignment_v2.common import atomic,sha
    from experiments.phone_alignment_v2.data import transform
    training.SOURCES=(*training.SOURCES,'PHONE')
    old=ROOT/'data/experiments/phone_alignment_v2';SMOKE_RUN.mkdir(parents=True,exist_ok=True)
    pilot=ROOT/'runs/phone_capture_v1/sessions/pilot_development'
    assert json.loads((pilot/'quality.json').read_text())['passed']
    phone=[json.loads(line) for line in (pilot/'labeled_features.jsonl').read_text().splitlines()]
    normalization=json.loads((old/'normalization.json').read_text())
    for split in ['train','validation','test']:
        y=np.load(old/split/'y.npy',mmap_mode='r');ids=np.concatenate([np.flatnonzero(y==c)[:8] for c in range(7)])
        folder=SMOKE_CACHE/split;folder.mkdir(parents=True,exist_ok=True)
        for field in ['raw','x','y','source','fine','group','host','start','end']:
            value=np.array(np.load(old/split/(field+'.npy'),mmap_mode='r')[ids],copy=True)
            if split!='train':
                if field=='raw':extra=np.asarray([r['raw'] for r in phone],np.float32)
                elif field=='x':
                    raw=np.asarray([r['raw'] for r in phone],np.float32)
                    extra=((transform(raw)-np.asarray(normalization['mean']))/np.asarray(normalization['scale'])).astype(np.float32)
                elif field=='y':extra=np.asarray([r['family'] for r in phone],dtype=value.dtype)
                elif field=='source':extra=np.full(len(phone),7,dtype=value.dtype)
                elif field=='fine':extra=np.asarray([0 if r['family']==0 else 10 for r in phone],dtype=value.dtype)
                elif field in ['start','end']:extra=np.asarray([r[field] for r in phone],dtype=value.dtype)
                else:extra=np.full(len(phone),999,dtype=value.dtype)
                value=np.concatenate([value,extra])
            np.save(folder/(field+'.npy'),value)
    phone_folder=SMOKE_CACHE/'phone_test';phone_folder.mkdir(parents=True,exist_ok=True)
    atomic(phone_folder/'metadata.json',[{k:v for k,v in r.items() if k!='raw'} for r in phone])
    atomic(SMOKE_CACHE/'normalization.json',normalization)
    old_config=json.loads((ROOT/'runs/phone_alignment_v2/config.json').read_text())
    config={k:old_config[k] for k in ['learning_rate','max_benign_fpr','max_source_benign_fpr','min_attack_recall','min_class_attack_recall','min_typed_precision','min_typed_recall']}
    config.update({'epochs':2,'early_stopping':False,'batch_size':28,'jobs':[{'name':'gate_smoke','kind':'gate','width':96,'seed':1201},{'name':'diagnosis_smoke','kind':'diagnosis','width':64,'seed':1201}],
        'scope':'Real-row automation only; no final model or accuracy result.'})
    atomic(SMOKE_RUN/'config.json',config)
    for job in config['jobs']:
        training.train(job['name']);folder=SMOKE_RUN/'jobs'/job['name']
        assert len(list(folder.glob('epoch_*.pt')))==2 and (folder/'best.pt').exists() and (folder/'final.pt').exists()
        saved=torch.load(folder/'best.pt',map_location='cpu',weights_only=False);model=build(job);model.load_state_dict(saved['model'])
        wrapper=RawWrapper(model.eval(),normalization['mean'],normalization['scale']).eval()
        x=torch.tensor(np.asarray(phone[0]['raw'],np.float32))[None,:]
        exported=torch.jit.trace(wrapper,(x[:,:32],x[:,32:]),check_trace=False)
        assert torch.allclose(exported(x[:,:32],x[:,32:]),wrapper(x[:,:32],x[:,32:]),atol=1e-5)
        exported.save(str(folder/'smoke_export.pt'))
    atomic(ROOT/'validation/reports/phone_capture_v1/training_smoke.json',{'passed':True,'epochs_per_job':2,'every_checkpoint_retained':True,
        'jobs':['gate_smoke','diagnosis_smoke'],'real_captured_or_existing_dataset_rows_only':True,'new_phone_validation_source_checked':True,
        'raw_input_export_parity':True,'research_accuracy_claimed':False,'real_campaign_models_modified':False})
    print('REAL_ROW_TRAINING_AUTOMATION_SMOKE_PASSED',flush=True)


if __name__=='__main__':main()
