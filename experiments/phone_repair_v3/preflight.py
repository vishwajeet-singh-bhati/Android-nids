"""Meaningful synthetic routing/calibration/sampling/resume/export automation smoke."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json,os,subprocess,sys
from pathlib import Path
import numpy as np
import torch

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_repair_v3.common import *
from experiments.phone_repair_v3.policy import probabilities,decisions,score,fit_calibration
from experiments.phone_repair_v3.train import epoch_order
from experiments.phone_alignment_v2.models import build


def main():
    torch.set_num_threads(2);folder=RUN/'automation_smoke';folder.mkdir(parents=True,exist_ok=True);cache=folder/'cache';base=folder/'baseline';public=folder/'reports';rng=np.random.default_rng(9403)
    for split,n in [('train',2100),('validation',700),('test',700)]:
        y=np.arange(n)%7;raw=rng.uniform(0,.5,(n,147)).astype(np.float32);raw[np.arange(n),y]+=8
        x=raw.copy();x[:,:32]=np.log1p(x[:,:32]);x[:,128:146]=np.log1p(x[:,128:146]);target=cache/split;target.mkdir(parents=True,exist_ok=True)
        for key,value in {'raw':raw,'x':x,'y':y.astype(np.int64),'fine':y.astype(np.int16),'source':np.zeros(n,np.int8),'group':np.arange(n,dtype=np.int64),
            'host':np.arange(n,dtype=np.int64),'start':np.arange(n,dtype=np.float64),'end':np.arange(n,dtype=np.float64)+.1}.items():np.save(target/(key+'.npy'),value)
    atomic(cache/'normalization.json',{'mean':[0.]*147,'scale':[1.]*147})
    cfg=configuration(2,[0]);cfg['batch_size']=64;cfg['shortlist_per_metric']=1;cfg['joint_high_quantiles']=[.999];cfg['review_accept_thresholds']=[.5,.9];cfg['type_thresholds']=[.6]
    policy={'low':.7858333333333334,'high':.7858333333333334,'review_accept':.5,'type_cutoff':.6};cfg['baseline_policy']=policy
    # Odd/even within each class prevents missing a class in either synthetic subgroup.
    val_y=np.load(cache/'validation/y.npy');cal=np.flatnonzero((np.arange(len(val_y))//7)%2==0);sel=np.flatnonzero((np.arange(len(val_y))//7)%2==1)
    np.save(folder/'calibration_idx.npy',cal);np.save(folder/'selection_idx.npy',sel);hard=np.flatnonzero(np.load(cache/'train/y.npy')==0);np.save(folder/'hard_benign_idx.npy',hard)
    jobs=[{'name':'baseline_gate','kind':'gate','width':96,'seed':0},{'name':'baseline_diagnosis','kind':'diagnosis','width':32,'seed':0}];choices={j['kind']:j['name'] for j in jobs};base_outputs={}
    for j in jobs:
        torch.manual_seed(0);model=build(j).eval();out=base/'jobs'/j['name'];out.mkdir(parents=True,exist_ok=True);torch.save({'model':model.state_dict(),'epoch':0},out/'best.pt')
        with torch.inference_mode():
            for split in ('validation','test'):
                z=model(torch.tensor(np.load(cache/split/'x.npy'))).numpy()
                if split=='validation':np.save(folder/('baseline_'+j['kind']+'_validation_logits.npy'),z)
                else:base_outputs[j['kind']]=probabilities(z,j['kind'])
    atomic(base/'config.json',{'jobs':jobs});atomic(base/'frozen_selection.json',{'choices':choices})
    y=np.load(cache/'test/y.npy');pred,flag,routed=decisions(base_outputs['gate'],base_outputs['diagnosis'],policy);m=score(y,pred,flag,routed)
    atomic(base/'evaluation.json',{'pipeline':m});(base/'exports').mkdir(exist_ok=True);atomic(base/'exports/smoke_fallback.json',{'synthetic':True})
    atomic(folder/'config.json',cfg)
    # Routing invariants: a high warning survives benign diagnosis; review is conditional.
    d=np.array([[.99,.01,0,0,0,0,0],[.01,.99,0,0,0,0,0],[.99,.01,0,0,0,0,0]],np.float32)
    p,f,r=decisions(np.array([.95,.5,.5]),d,{'low':.2,'high':.9,'review_accept':.8,'type_cutoff':.6})
    assert f.tolist()==[True,True,False] and p.tolist()==[7,1,0]
    a=epoch_order(2100,0,1,'unweighted',hard,.1);b=epoch_order(2100,0,1,'moderate',hard,.1);assert np.array_equal(a,b)
    c=epoch_order(2100,0,1,'hard_benign',hard,.1);assert len(c)==len(a) and (np.load(cache/'train/y.npy')[c]==0).mean()>.20
    env=dict(os.environ,NIDS_REPAIR_RUN=str(folder),NIDS_REPAIR_CACHE=str(cache),NIDS_REPAIR_PUBLIC=str(public),NIDS_REPAIR_BASE=str(base))
    for job in cfg['jobs']:
        with (folder/(job['name']+'.log')).open('w') as log:subprocess.run([sys.executable,str(ROOT/'experiments/phone_repair_v3/train.py'),'--job',job['name']],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        assert len(list((folder/'jobs'/job['name']).glob('epoch_*.pt')))==2
    # Completed-job restart must not overwrite existing checkpoints.
    file=folder/'jobs'/cfg['jobs'][0]['name']/'epoch_01.pt';before=sha(file)
    subprocess.run([sys.executable,str(ROOT/'experiments/phone_repair_v3/train.py'),'--job',cfg['jobs'][0]['name']],env=env,check=True);assert sha(file)==before
    for script in ('select.py','evaluate.py','export_mobile.py'):
        python=os.environ.get('NIDS_EXPORT_PYTHON',sys.executable) if script=='export_mobile.py' else Path(sys.executable)
        with (folder/(script+'.log')).open('w') as log:subprocess.run([str(python),str(ROOT/'experiments/phone_repair_v3'/script)],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    result=json.loads((public/'mobile_export.json').read_text());assert result['native_policy_verification']['passed']
    # Matching seeds/models must initialize identically across all three arms.
    for kind in ('gate','diagnosis'):
        hashes={json.loads((folder/'jobs'/j['name']/'complete.json').read_text())['initial_state_sha256'] for j in cfg['jobs'] if j['kind']==kind};assert len(hashes)==1
    atomic(PUBLIC/'automation_smoke.json',{'passed':True,'training_jobs':6,'epochs_each':2,'all_epochs_retained':True,'identical_initialization_and_orders':True,
        'routing_invariants_passed':True,'calibration_selection_evaluation_native_export':True,'completed_job_resume_preserves_checkpoint':True,'scope':'synthetic automation only, not detector accuracy','new_attacks_sent':0})
    print('REPAIR_AUTOMATION_SMOKE_PASS',flush=True)


if __name__=='__main__':
    try:main()
    except BaseException as error:
        atomic(PUBLIC/'automation_smoke.json',{'passed':False,'error':str(error)});raise
