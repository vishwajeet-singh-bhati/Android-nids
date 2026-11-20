"""Fixed-budget, resumable jobs. Every epoch retained; selection uses validation only."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import collections,json,math,os,sys,time,shutil
from pathlib import Path
import numpy as np
import torch
from torch import nn

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_alignment_v2.common import *
from experiments.phone_alignment_v2.models import build


def save(path,value):
    temp=path.with_suffix(path.suffix+'.tmp');torch.save(value,temp);temp.replace(path)


def load_split(name):
    folder=CACHE/name
    return {k:np.load(folder/(k+'.npy'),mmap_mode='r') for k in ('x','y','source','fine','group','host','start','end')}


def probabilities(model,data,kind,device,batch=2048):
    outputs=[];model.eval()
    with torch.inference_mode():
        for start in range(0,len(data['y']),batch):
            x=torch.from_numpy(np.array(data['x'][start:start+batch],copy=True)).to(device)
            logits=model(x)
            probability=torch.sigmoid(logits).flatten() if kind=='gate' else torch.softmax(logits,dim=1)
            outputs.append(probability.cpu().numpy())
    return np.concatenate(outputs)


def threshold_metrics(y,p,config,sources=None):
    positive=y>0;pos=np.sort(p[positive]);neg=np.sort(p[~positive])
    source_neg={int(s):np.sort(p[(y==0)&(sources==s)]) for s in np.unique(sources)} if sources is not None else {}
    source_neg={s:v for s,v in source_neg.items() if len(v)}
    extra=np.concatenate([np.quantile(v,[.99,.995,.999]) for v in source_neg.values()]) if source_neg else np.array([])
    thresholds=np.unique(np.r_[np.linspace(.01,.99,25),np.quantile(neg,[.9,.95,.975,.99,.995,.999,.9995,.9999,.99999]),extra])
    choices=[]
    perclass={i:np.sort(p[y==i]) for i in range(1,7)}
    for value in thresholds:
        tp=len(pos)-np.searchsorted(pos,value,side='left');fp=len(neg)-np.searchsorted(neg,value,side='left')
        recall=tp/max(1,len(pos));precision=tp/max(1,tp+fp);fpr=fp/max(1,len(neg))
        recalls=[(len(v)-np.searchsorted(v,value,side='left'))/max(1,len(v)) for v in perclass.values()]
        minimum=min(recalls);f1=2*precision*recall/max(1e-12,precision+recall)
        source_fpr={SOURCES[s]:float((len(v)-np.searchsorted(v,value,side='left'))/len(v)) for s,v in source_neg.items()}
        eligible=fpr<=config['max_benign_fpr'] and recall>=config['min_attack_recall'] and minimum>=config['min_class_attack_recall'] and all(v<=config['max_source_benign_fpr'] for v in source_fpr.values())
        balanced=2*precision*minimum/max(1e-12,precision+minimum)
        rank=(int(eligible),balanced,f1,-fpr)
        choices.append((rank,{'threshold':float(value),'precision':float(precision),'recall':float(recall),'f1':float(f1),'benign_fpr':float(fpr),
            'class_attack_recall':dict(zip(CLASSES[1:],map(float,recalls))),'source_benign_fpr':source_fpr,'eligible':bool(eligible),'rank':list(map(float,rank))}))
    return max(choices,key=lambda v:v[0])[1]


def validation_metrics(y,p,kind,config,sources=None):
    attack=p if kind=='gate' else 1-p[:,0]
    result=threshold_metrics(y,attack,config,sources)
    if kind!='gate':
        from sklearn.metrics import classification_report
        typed=classification_report(y,p.argmax(1),labels=list(range(7)),target_names=CLASSES,output_dict=True,zero_division=0)
        result['macro_f1']=typed['macro avg']['f1-score'];result['typed_report']=typed
        result['typed_targets_passed']=all(typed[c]['precision']>=config['min_typed_precision'] and typed[c]['recall']>=config['min_typed_recall'] for c in CLASSES)
        result['eligible']=result['eligible'] and result['typed_targets_passed']
        result['rank']=[float(result['eligible']),float(typed['macro avg']['f1-score']),float(result['f1']),-float(result['benign_fpr'])]
    return result


def train(name):
    config=json.loads((RUN/'config.json').read_text());job=next(v for v in config['jobs'] if v['name']==name)
    for filename,expected in config.get('code_sha256',{}).items():assert sha(ROOT/filename)==expected,'Training source changed: '+filename
    folder=RUN/'jobs'/name;folder.mkdir(parents=True,exist_ok=True)
    if (folder/'complete.json').exists():return
    torch.set_num_threads(2);torch.manual_seed(job['seed']);np.random.seed(job['seed'])
    device='cuda' if torch.cuda.is_available() else 'cpu';model=build(job).to(device)
    train=load_split('train');validation=load_split('validation');y=np.asarray(train['y'])
    counts=np.bincount(y,minlength=7);weights=np.sqrt(len(y)/(7*counts));weights=np.clip(weights/weights.mean(),.2,20)
    class_weights=torch.tensor(weights,dtype=torch.float32,device=device)
    optimizer=torch.optim.AdamW(model.parameters(),lr=config['learning_rate'],weight_decay=1e-4)
    history=[];first=1;best_rank=None;best_loss=math.inf
    if (folder/'last.pt').exists():
        checkpoint=torch.load(folder/'last.pt',map_location=device,weights_only=False)
        assert checkpoint['config_sha256']==sha(RUN/'config.json')
        model.load_state_dict(checkpoint['model']);optimizer.load_state_dict(checkpoint['optimizer'])
        first=checkpoint['epoch']+1;history=checkpoint['history'];best_rank=checkpoint['best_rank'];best_loss=checkpoint['best_loss']
        torch.set_rng_state(checkpoint['cpu_rng'].cpu())
        if device=='cuda':torch.cuda.set_rng_state_all([v.cpu() for v in checkpoint['cuda_rng']])
    n=len(y);batch=config['batch_size']
    for epoch in range(first,config['epochs']+1):
        began=time.monotonic();model.train();order=np.random.default_rng(job['seed']*10000+epoch).permutation(n)
        loss_sum=0.0
        for step,start in enumerate(range(0,n,batch)):
            ids=order[start:start+batch];x=torch.from_numpy(np.array(train['x'][ids],copy=True)).to(device)
            target=torch.from_numpy(np.array(y[ids],copy=True)).to(device)
            optimizer.zero_grad(set_to_none=True);logits=model(x)
            if job['kind']=='gate':
                loss=nn.functional.binary_cross_entropy_with_logits(logits.flatten(),(target>0).float(),reduction='none')
                loss=(loss*class_weights[target]).mean()
            else:loss=nn.functional.cross_entropy(logits,target,weight=class_weights)
            if not torch.isfinite(loss):raise RuntimeError('Nonfinite loss')
            loss.backward();nn.utils.clip_grad_norm_(model.parameters(),5);optimizer.step();loss_sum+=float(loss.detach())*len(ids)
            if step%250==0:atomic(folder/'status.json',{'phase':'training','pid':os.getpid(),'epoch':epoch,'epochs':config['epochs'],'step':step,'steps':math.ceil(n/batch),'elapsed_epoch_seconds':time.monotonic()-began})
        atomic(folder/'status.json',{'phase':'validation','pid':os.getpid(),'epoch':epoch,'epochs':config['epochs']})
        p=probabilities(model,validation,job['kind'],device);metrics=validation_metrics(np.asarray(validation['y']),p,job['kind'],config,np.asarray(validation['source']))
        record={'epoch':epoch,'training_loss':loss_sum/n,'seconds':time.monotonic()-began,'validation':metrics};history.append(record)
        improved=best_rank is None or tuple(metrics['rank'])>tuple(best_rank)
        if improved:best_rank=metrics['rank']
        training_improved=record['training_loss']<best_loss;best_loss=min(best_loss,record['training_loss'])
        checkpoint={'job':job,'epoch':epoch,'model':model.state_dict(),'optimizer':optimizer.state_dict(),'history':history,
            'best_rank':best_rank,'best_loss':best_loss,'config_sha256':sha(RUN/'config.json'),
            'cpu_rng':torch.get_rng_state(),'cuda_rng':torch.cuda.get_rng_state_all() if device=='cuda' else [],'normalization':json.loads((CACHE/'normalization.json').read_text())}
        save(folder/f'epoch_{epoch:02d}.pt',checkpoint);save(folder/'last.pt',checkpoint)
        if improved:shutil.copy2(folder/'last.pt',folder/'best.pt');atomic(folder/'best_validation.json',record)
        if training_improved:shutil.copy2(folder/'last.pt',folder/'best_training.pt')
        atomic(folder/'history.json',history);atomic(folder/'status.json',{'phase':'epoch_complete','epoch':epoch,'epochs':config['epochs'],'seconds':record['seconds'],'validation':metrics})
        print('EPOCH_COMPLETE',name,epoch,round(record['seconds'],1),metrics.get('macro_f1'),metrics['recall'],metrics['benign_fpr'],flush=True)
    shutil.copy2(folder/'last.pt',folder/'final.pt')
    atomic(folder/'complete.json',{'epochs':config['epochs'],'all_epochs_retained':True,'parameters':sum(p.numel() for p in model.parameters()),
        'best_sha256':sha(folder/'best.pt'),'final_sha256':sha(folder/'final.pt'),'device':device,'early_stopping':False})


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--job',required=True);args=parser.parse_args();train(args.job)
