"""Reuse frozen v2 rows; isolate calibration/selection and mine TRAIN negatives."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json,sys,time
from pathlib import Path
import numpy as np
import torch
from sklearn.model_selection import train_test_split
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_repair_v3.common import *
from experiments.phone_alignment_v2.models import build


def load_split(name):
    return {key:np.load(CACHE/name/(key+'.npy'),mmap_mode='r') for key in ('x','y','fine','source','group','host','start','end')}


def logits(model,data,batch=2048):
    model.eval();out=[];device=next(model.parameters()).device
    with torch.inference_mode():
        for start in range(0,len(data['y']),batch):
            out.append(model(torch.from_numpy(np.array(data['x'][start:start+batch],copy=True)).to(device)).cpu().numpy())
    return np.concatenate(out)


def prepare():
    RUN.mkdir(parents=True,exist_ok=True);PUBLIC.mkdir(parents=True,exist_ok=True)
    if (RUN/'data_ready.json').exists():return
    torch.set_num_threads(2);validation=load_split('validation');groups,inverse=np.unique(validation['group'],return_inverse=True)
    targets=np.zeros(len(groups),np.int8);np.maximum.at(targets,inverse,validation['y'])
    calibration,selection=train_test_split(np.arange(len(groups)),test_size=.5,stratify=targets,random_state=9301)
    mask=np.zeros(len(groups),bool);mask[calibration]=True
    cal=np.flatnonzero(mask[inverse]);sel=np.flatnonzero(~mask[inverse]);np.save(RUN/'calibration_idx.npy',cal);np.save(RUN/'selection_idx.npy',sel)
    assert len(np.intersect1d(validation['group'][cal],validation['group'][sel]))==0
    assert min(np.bincount(validation['y'][cal],minlength=7))>=20 and min(np.bincount(validation['y'][sel],minlength=7))>=20
    selected=json.loads((BASE/'frozen_selection.json').read_text())['choices'];base_config=json.loads((BASE/'config.json').read_text());models={}
    device='cuda' if torch.cuda.is_available() else 'cpu'
    for kind,name in selected.items():
        job=next(j for j in base_config['jobs'] if j['name']==name);model=build(job).to(device)
        model.load_state_dict(torch.load(BASE/'jobs'/name/'best.pt',map_location='cpu',weights_only=False)['model']);models[kind]=model
        values=logits(model,validation);np.save(RUN/('baseline_'+kind+'_validation_logits.npy'),values)
    train=load_split('train');train_logits=logits(models['gate'],train);np.save(RUN/'baseline_gate_train_logits.npy',train_logits)
    raw=np.load(CACHE/'train/raw.npy',mmap_mode='r');reset=(raw[:,1]==1)&(raw[:,2]==1)&(raw[:,3]==0)&(raw[:,4]==0)&(raw[:,29]==1)&(raw[:,30]==1)&(raw[:,31]==1)
    hard=np.flatnonzero((train['y']==0)&(reset|(train_logits.reshape(-1)>=0)))
    assert len(hard)>=1000;np.save(RUN/'hard_benign_idx.npy',hard)
    files=[CACHE/'ready.json',CACHE/'normalization.json',BASE/'config.json',BASE/'frozen_selection.json',BASE/'evaluation.json']
    for split in ('train','validation','test'):
        for name in ('x','y','raw','group','source','fine'):files.append(CACHE/split/(name+'.npy'))
    inventory={}
    for p in files:
        atomic(RUN/'preparation_status.json',{'phase':'hashing_frozen_inputs','path':str(p.relative_to(ROOT)),'updated_unix':time.time()})
        inventory[str(p.relative_to(ROOT))]={'sha256':sha(p),'bytes':p.stat().st_size,'mtime_ns':p.stat().st_mtime_ns}
    report={'state':'ready','same_v2_rows':True,'label_changes':0,'feature_changes':0,'calibration_rows':len(cal),'selection_rows':len(sel),
        'calibration_groups':len(calibration),'selection_groups':len(selection),'calibration_selection_group_overlap':0,'hard_benign_rows':len(hard),
        'hard_pool_scope':'train split only: empty short reset pattern or frozen v2 gate probability >=.5; labels unchanged',
        'calibration_class_counts':np.bincount(validation['y'][cal],minlength=7).tolist(),'selection_class_counts':np.bincount(validation['y'][sel],minlength=7).tolist(),
        'inventory':inventory,'existing_test_scope':'Previously opened v2 diagnostic cohort, not a new blind holdout; phone sessions still pending.'}
    atomic(RUN/'data_ready.json',report);atomic(PUBLIC/'data_report.json',report)
    print('REPAIR_DATA_READY',len(cal),len(sel),len(hard),flush=True)


if __name__=='__main__':prepare()
