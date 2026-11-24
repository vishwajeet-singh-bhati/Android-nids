"""Evaluate fixed alert guards for rejected TCP handshakes; no fitting or traffic.

The legacy cache lacks endpoint-role metadata. Treating every qualifying row as
incoming gives a conservative upper bound on suppressed legacy detections.
All existing test sets have been inspected: these are regression comparisons.
"""
import argparse
import json
from pathlib import Path
import sys

import numpy as np
import torch

ROOT=Path(__file__).resolve().parents[1]
CACHE=ROOT/'data/experiments/phone_capture_training_v1'
CLASSES=['Benign','Bot','Brute Force','DDoS','DoS','Port Scan','Web Attack','Unclassified']

def masks(raw, classes):
    rejected=((raw[:,1]==1)&(raw[:,2]==1)&(raw[:,3]==0)&(raw[:,4]==0)&
              (raw[:,28]==0)&(raw[:,29]==1)&(raw[:,30]==1)&(raw[:,31]==1))
    c=raw[:,32:]
    # A port sweep or concentrated volume defeats the guard. These fixed limits
    # precede comparison; none uses an app identity, IP address, service or label.
    quiet=(c[:,6]<np.log1p(3)-1e-5)&(c[:,38]<np.log1p(3)-1e-5)&(c[:,70]<np.log1p(3)-1e-5)&\
          (c[:,0]<np.log1p(15)-1e-5)&(c[:,32]<np.log1p(31)-1e-5)&(c[:,21]<np.log1p(7)-1e-5)
    return {'rejected_handshake_only':rejected,
            'rejected_quiet_context':rejected&quiet,
            'rejected_quiet_bot_or_unknown':rejected&quiet&np.isin(classes,[1,7])}

def metrics(y,pred):
    positive=y>0; flagged=pred>0
    result={'tp':int((positive&flagged).sum()),'fn':int((positive&~flagged).sum()),
            'fp':int((~positive&flagged).sum()),'tn':int((~positive&~flagged).sum())}
    result['classwise']={}
    for c in np.unique(y):
        truth=y==c;guess=pred==c;tp=int((truth&guess).sum());support=int(truth.sum());n=int(guess.sum())
        precision=tp/n if n else 0.;recall=tp/support if support else 0.
        result['classwise'][CLASSES[c]]={'support':support,'precision':precision,'recall':recall,
            'f1':2*precision*recall/(precision+recall) if precision+recall else 0.,
            'binary_detected':int((truth&flagged).sum())}
    return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--observations',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--idle-only',action='store_true',help='Update the saved-alert replay without rescoring completed cohorts')
    args=parser.parse_args();args.output.parent.mkdir(parents=True,exist_ok=True)
    torch.set_num_threads(2)
    exports=ROOT/'runs/phone_capture_training_v1/exports'
    gate=torch.jit.load(str(exports/'gate.pt'),map_location='cpu').eval()
    diagnosis=torch.jit.load(str(exports/'diagnosis.pt'),map_location='cpu').eval()
    threshold=.5408333333333333
    report={'scope':'Fixed candidate regression; no new holdout, retraining or app/port exemptions.',
            'legacy_direction':'Incoming-only guard bounded conservatively by applying it to all directions in legacy cache.',
            'threshold':threshold,'type_cutoff':.8,'cohorts':{}}
    if args.idle_only:
        report=json.loads(args.output.read_text(encoding='utf-8'))
    def save():args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    def score(raw):
        output=[]
        with torch.inference_mode():
            for start in range(0,len(raw),2048):
                x=torch.from_numpy(np.array(raw[start:start+2048],dtype=np.float32,copy=True))
                g=torch.sigmoid(gate(x[:,:32],x[:,32:])).flatten().numpy()
                d=torch.softmax(diagnosis(x[:,:32],x[:,32:]),1).numpy()
                best=d.argmax(1);confidence=d.max(1)
                pred=np.where(g<threshold,0,np.where((best>0)&(confidence>=.8),best,7))
                output.append(pred)
        return np.concatenate(output)
    def cohort(name,raw,y,incoming=None):
        pred=score(raw);base=metrics(y,pred);result={'rows':len(y),'baseline':base,'candidates':{}}
        for key,hold in masks(raw,pred).items():
            if incoming is not None:hold=hold&incoming
            after=pred.copy();after[hold]=0
            result['candidates'][key]={'after':metrics(y,after),'held_baseline_flags':int(((pred>0)&hold).sum()),
                'held_positive_by_class':{CLASSES[c]:int(((y==c)&(pred>0)&hold).sum()) for c in np.unique(y) if c>0}}
        report['cohorts'][name]=result;save()
        print(name,json.dumps({'rows':len(y),'before':{k:base[k] for k in ['tp','fn','fp','tn']},
            'after':{k:{m:v['after'][m] for m in ['tp','fn','fp','tn']} for k,v in result['candidates'].items()}}),flush=True)
    observations=json.loads(args.observations.read_text(encoding='utf-8-sig'))
    raw=np.asarray([r['model_evidence']['flow_features']+r['model_evidence']['context_features'] for r in observations],dtype=np.float32)
    pred=score(raw)
    report['idle_alert_replay']={'activity_groups':len(raw),'represented_raw_flags':sum(r.get('count',1) for r in observations),'baseline_class_ids':pred.tolist(),
        'candidate_held_groups':{k:int(v.sum()) for k,v in masks(raw,pred).items()},
        'labels':'Unverified unsolicited incoming probes; no benign or bot ground-truth claim.'};save()
    if args.idle_only:return
    for split in ['validation','test']:
        directory=CACHE/('phone_'+split)
        cohort('phone_'+split,np.load(directory/'raw.npy'),np.load(directory/'y.npy'))
    from compare_applied_auth_policy import inputs
    records=[r for r in inputs() if r[2] is not None and (r[3]=='Benign' or r[4])]
    cohort('protocol_development',np.asarray([row['flow']+row['context'] for _,row,*_ in records],dtype=np.float32),
        np.asarray([truth for *_,truth in records]),np.asarray([row['destination']==row['watched'] for _,row,*_ in records]))
    for split in ['validation','test']:
        directory=CACHE/split
        if not (directory/'raw.npy').exists():
            report['cohorts']['legacy_'+split]={'unavailable':True};save();continue
        manifest=json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
        n=manifest['old_rows']
        cohort('legacy_'+split,np.load(directory/'raw.npy',mmap_mode='r')[:n],np.load(directory/'y.npy',mmap_mode='r')[:n])
    report['complete']=True;save()

if __name__=='__main__':main()
