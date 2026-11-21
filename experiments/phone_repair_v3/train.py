"""Matched 40-epoch arms; resumable, every epoch and validation logits retained."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json,math,shutil,sys,time
from pathlib import Path
import numpy as np
import torch

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_repair_v3.common import *
from experiments.phone_repair_v3.data import load_split,logits
from experiments.phone_repair_v3.policy import probabilities,decisions,score
from experiments.phone_alignment_v2.models import build
from experiments.phone_alignment_v2.train import validation_metrics


def save(path,obj):
    temp=path.with_suffix(path.suffix+'.tmp');torch.save(obj,temp);temp.replace(path)


def weights_for(y,arm,cap):
    if arm!='moderate':return np.ones(7,np.float32)
    counts=np.bincount(y,minlength=7);w=np.sqrt(len(y)/(7*counts));w=np.clip(w/w.mean(),.2,20);w=w/w[0]
    return np.minimum(w,cap).astype(np.float32)


def epoch_order(n,seed,epoch,arm,hard,fraction):
    rng=np.random.default_rng(seed*10000+epoch)
    if arm!='hard_benign':return rng.permutation(n)
    count=int(n*fraction);order=np.r_[rng.permutation(n)[:n-count],rng.choice(hard,count,replace=True)];rng.shuffle(order);return order


def train(name):
    config=json.loads((RUN/'config.json').read_text());job=next(j for j in config['jobs'] if j['name']==name)
    for file,expected in config.get('code_sha256',{}).items():assert sha(ROOT/file)==expected,'Frozen source changed: '+file
    folder=RUN/'jobs'/name;folder.mkdir(parents=True,exist_ok=True)
    if (folder/'complete.json').exists():return
    torch.set_num_threads(2);torch.manual_seed(job['seed']);np.random.seed(job['seed'])
    device='cuda' if torch.cuda.is_available() else 'cpu';model=build(job).to(device)
    initial_sha=__import__('hashlib').sha256(b''.join(v.detach().cpu().numpy().tobytes() for v in model.state_dict().values())).hexdigest()
    train_data=load_split('train');validation=load_split('validation');y=np.asarray(train_data['y']);sel=np.load(RUN/'selection_idx.npy')
    w=weights_for(y,job['arm'],config['weight_cap_relative_to_benign']);tw=torch.tensor(w,device=device)
    hard=np.load(RUN/'hard_benign_idx.npy');n=len(y);batch=config['batch_size'];optimizer=torch.optim.AdamW(model.parameters(),lr=config['learning_rate'],weight_decay=1e-4)
    baseline_gate=probabilities(np.load(RUN/'baseline_gate_validation_logits.npy',mmap_mode='r')[sel],'gate')
    baseline_threshold=config['baseline_policy']['high'];baseline_policy=dict(config['baseline_policy'])
    history=[];first=1;best=None;best_loss=math.inf
    if (folder/'last.pt').exists():
        ck=torch.load(folder/'last.pt',map_location=device,weights_only=False);assert ck['config_sha256']==sha(RUN/'config.json')
        model.load_state_dict(ck['model']);optimizer.load_state_dict(ck['optimizer']);history=ck['history'];first=ck['epoch']+1;best=ck['best_rank'];best_loss=ck['best_loss']
        torch.set_rng_state(ck['cpu_rng'].cpu())
        if device=='cuda':torch.cuda.set_rng_state_all([v.cpu() for v in ck['cuda_rng']])
    for epoch in range(first,config['epochs']+1):
        began=time.monotonic();model.train();order=epoch_order(n,job['seed'],epoch,job['arm'],hard,config['hard_benign_fraction']);loss_sum=0.
        exposure=np.bincount(y[order],minlength=7).tolist()
        for step,start in enumerate(range(0,n,batch)):
            ids=order[start:start+batch];x=torch.from_numpy(np.array(train_data['x'][ids],copy=True)).to(device);target=torch.from_numpy(np.array(y[ids],copy=True)).to(device)
            optimizer.zero_grad(set_to_none=True);z=model(x)
            if job['kind']=='gate':loss=(torch.nn.functional.binary_cross_entropy_with_logits(z.flatten(),(target>0).float(),reduction='none')*tw[target]).mean()
            else:loss=torch.nn.functional.cross_entropy(z,target,weight=tw)
            if not torch.isfinite(loss):raise RuntimeError('Nonfinite training loss')
            loss.backward();torch.nn.utils.clip_grad_norm_(model.parameters(),5);optimizer.step();loss_sum+=float(loss.detach())*len(ids)
            if step%250==0:atomic(folder/'status.json',{'phase':'training','epoch':epoch,'epochs':config['epochs'],'step':step,'steps':math.ceil(n/batch),'updated_unix':time.time()})
        atomic(folder/'status.json',{'phase':'validation','epoch':epoch,'epochs':config['epochs'],'updated_unix':time.time()})
        z=logits(model,validation);np.save(folder/f'validation_logits_{epoch:02d}.npy',z)
        p=probabilities(z[sel],job['kind']);metrics=validation_metrics(np.asarray(validation['y'][sel]),p,job['kind'],config,np.asarray(validation['source'][sel]))
        if job['kind']=='diagnosis':
            pred,flag,routed=decisions(baseline_gate,p,baseline_policy);composed=score(validation['y'][sel],pred,flag,routed,validation['source'][sel],config);rank=composed['rank']
        else:composed=None;rank=metrics['rank']
        record={'epoch':epoch,'training_loss':loss_sum/n,'seconds':time.monotonic()-began,'validation':metrics,'reference_gate_pipeline':composed,'rank':rank,'class_exposures':exposure}
        history.append(record);improvement=best is None or tuple(rank)>tuple(best)
        if improvement:best=rank
        training_improved=record['training_loss']<best_loss;best_loss=min(best_loss,record['training_loss'])
        ck={'job':job,'epoch':epoch,'model':model.state_dict(),'optimizer':optimizer.state_dict(),'history':history,'best_rank':best,'best_loss':best_loss,
            'config_sha256':sha(RUN/'config.json'),'cpu_rng':torch.get_rng_state(),'cuda_rng':torch.cuda.get_rng_state_all() if device=='cuda' else [],'class_weights':w.tolist(),'initial_state_sha256':initial_sha}
        save(folder/f'epoch_{epoch:02d}.pt',ck);save(folder/'last.pt',ck)
        if improvement:shutil.copy2(folder/'last.pt',folder/'best.pt');atomic(folder/'best_validation.json',record)
        if training_improved:shutil.copy2(folder/'last.pt',folder/'best_training.pt')
        atomic(folder/'history.json',history);atomic(folder/'status.json',{'phase':'epoch_complete','epoch':epoch,'epochs':config['epochs'],'seconds':record['seconds'],'updated_unix':time.time()})
        print('EPOCH_COMPLETE',name,epoch,round(record['seconds'],1),metrics['recall'],metrics['benign_fpr'],flush=True)
    shutil.copy2(folder/'last.pt',folder/'final.pt')
    atomic(folder/'complete.json',{'epochs':config['epochs'],'all_epochs_retained':True,'early_stopping':False,'parameters':sum(p.numel() for p in model.parameters()),
        'initial_state_sha256':initial_sha,'class_weights':w.tolist(),'best_sha256':sha(folder/'best.pt'),'final_sha256':sha(folder/'final.pt'),'device':device})


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--job',required=True);train(p.parse_args().job)
