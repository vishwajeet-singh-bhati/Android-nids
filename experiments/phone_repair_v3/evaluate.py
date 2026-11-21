"""Paired final diagnostics and explicit improved-model/fallback decision."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json,sys
from pathlib import Path
import numpy as np
import torch

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_repair_v3.common import *
from experiments.phone_repair_v3.data import load_split,logits
from experiments.phone_repair_v3.policy import probabilities,decisions,score,improved
from experiments.phone_alignment_v2.models import build


def predict(entry,data,split='test'):
    folder=RUN/'test_predictions';folder.mkdir(exist_ok=True);path=folder/(entry['checkpoint_sha256']+'_'+split+'.npy')
    assert sha(ROOT/entry['checkpoint'])==entry['checkpoint_sha256']
    if path.exists():return np.load(path,mmap_mode='r')
    model=build(entry['job']).to('cuda' if torch.cuda.is_available() else 'cpu');model.load_state_dict(torch.load(ROOT/entry['checkpoint'],map_location='cpu',weights_only=False)['model'])
    z=logits(model,data);np.save(path,z);return z


def evaluate_candidate(candidate,data,config):
    g=probabilities(predict(candidate['gate'],data),'gate',candidate.get('gate_calibration'))
    d=probabilities(predict(candidate['diagnosis'],data),'diagnosis',candidate.get('diagnosis_calibration'))
    pred,flag,routed=decisions(g,d,candidate['policy']);return score(np.asarray(data['y']),pred,flag,routed,np.asarray(data['source']),config),pred,flag


def paired_intervals(y,groups,old_pred,new_pred,old_flag,new_flag,repeats=300):
    unique,inv=np.unique(groups,return_inverse=True);rng=np.random.default_rng(9401);out={}
    for c,name in enumerate(CLASSES):
        vectors=[]
        for pred in (old_pred,new_pred):
            for mask in ((y==c)&(pred==c),(y!=c)&(pred==c),(y==c)&(pred!=c)):vectors.append(np.bincount(inv[mask],minlength=len(unique)))
        values=np.stack(vectors,1);values=values[values.sum(1)>0];samples=[]
        for _ in range(repeats):
            a,b,c1,d,e,f=values[rng.integers(0,len(values),len(values))].sum(0)
            samples.append([d/max(1,d+e)-a/max(1,a+b),d/max(1,d+f)-a/max(1,a+c1),2*d/max(1,2*d+e+f)-2*a/max(1,2*a+b+c1)])
        q=np.quantile(samples,[.025,.975],axis=0);out[name]={key:[float(q[0,i]),float(q[1,i])] for i,key in enumerate(('precision_delta','recall_delta','f1_delta'))}
    return {'method':'paired connection-group percentile bootstrap; not independent-session confidence','repeats':repeats,'classwise_95pct':out}


def main():
    torch.set_num_threads(2);config=json.loads((RUN/'config.json').read_text());frozen=json.loads((RUN/'frozen_selection.json').read_text());assert frozen['config_sha256']==sha(RUN/'config.json')
    data=load_split('test');y=np.asarray(data['y']);base_config=json.loads((BASE/'config.json').read_text());choices=json.loads((BASE/'frozen_selection.json').read_text())['choices'];baseline={'policy':config['baseline_policy']}
    for kind,name in choices.items():
        path=BASE/'jobs'/name/'best.pt';baseline[kind]={'job':next(j for j in base_config['jobs'] if j['name']==name),'checkpoint':str(path.relative_to(ROOT)),'checkpoint_sha256':sha(path)}
    base,old_pred,old_flag=evaluate_candidate(baseline,data,config)
    original=json.loads((BASE/'evaluation.json').read_text());assert base['confusion_with_unknown']==original['pipeline']['confusion_with_unknown'],'Baseline reproduction failed'
    finalists=[];selected=None;selected_pred=None;selected_flag=None
    for item in frozen['finalists']:
        result,pred,flag=evaluate_candidate(item,data,config);comparison=improved(result,base,config)
        key=(item['arm'],item['seed']);finalists.append({'arm':item['arm'],'seed':item['seed'],'metrics':result,'comparison':comparison,'policy':item['policy'],
            'fine_labels':{FINE[int(f)]:{'support':int((data['fine']==f).sum()),'flag_rate':float(flag[data['fine']==f].mean()),'correct_family_rate':float((pred[data['fine']==f]==y[data['fine']==f]).mean())} for f in np.unique(data['fine']) if f>=0}})
        if key==(frozen['selected']['arm'],frozen['selected']['seed']):selected=result;selected_pred=pred;selected_flag=flag
        atomic(RUN/'evaluation_partial.json',{'baseline':base,'finalists':finalists});print('FINALIST_TEST',*key,result['macro_f1'],result['classwise']['Bot']['precision'],comparison['better'],flush=True)
    comparison=improved(selected,base,config)
    choose_repair=frozen['selected']['comparison']['better'] and comparison['better']
    # Every arm's saved best and final models are also scored independently.
    from experiments.phone_alignment_v2.evaluate import metrics as standalone_metrics
    standalone={}
    for job in config['jobs']:
        for checkpoint in ('best','final'):
            path=RUN/'jobs'/job['name']/(checkpoint+'.pt');ck=torch.load(path,map_location='cpu',weights_only=False)
            entry={'job':job,'checkpoint':str(path.relative_to(ROOT)),'checkpoint_sha256':sha(path)}
            p=probabilities(predict(entry,data),job['kind']);v=ck['history'][-1]['validation']
            result=standalone_metrics(y,p,job,v['threshold'],data);result['epoch']=ck['epoch'];result['checkpoint_sha256']=entry['checkpoint_sha256']
            standalone[job['name']+':'+checkpoint]=result
            atomic(RUN/'standalone_partial.json',standalone)
            print('STANDALONE_TEST',job['name'],checkpoint,result['binary']['recall'],result['binary']['benign_fpr'],flush=True)
    intervals=paired_intervals(y,np.asarray(data['group']),old_pred,selected_pred,old_flag,selected_flag)
    report={'scope':'Matched fixed v2 rows/features/model sizes/40 epochs, controlled loss/sampling; joint routing/calibration learned on disjoint validation subgroups. Existing test is opened development data; phone evaluation pending.',
        'baseline':base,'selected_repair':selected,'selection_arm':frozen['selected']['arm'],'selection_seed':frozen['selected']['seed'],
        'validation_comparison':frozen['selected']['comparison'],'test_comparison':comparison,'repair_is_better':bool(choose_repair),
        'intended_deployment':'repair' if choose_repair else 'preserved_v2','deployment_executed':False,'device_validation_pending':True,
        'offline_readiness_targets_passed':selected['eligible'] if choose_repair else base['eligible'],'finalists':finalists,'standalone_best_final':standalone,'paired_intervals':intervals,'config_sha256':sha(RUN/'config.json')}
    atomic(RUN/'evaluation.json',report);atomic(PUBLIC/'evaluation.json',report)
    rows=['# Repair versus preserved phone-aligned v2','',report['scope'],'',f"Repair better by prespecified validation+test checks: {choose_repair}. Intended deployment: {report['intended_deployment']}. No installation executed; native/phone/resource/manual checks remain.",'',
        '| Class | V2 precision % | Repair precision % | V2 recall % | Repair recall % | V2 F1 % | Repair F1 % | Support |','|---|---:|---:|---:|---:|---:|---:|---:|']
    for c in CLASSES:
        a=base['classwise'][c];b=selected['classwise'][c];rows.append(f"| {c} | {a['precision']*100:.3f} | {b['precision']*100:.3f} | {a['recall']*100:.3f} | {b['recall']*100:.3f} | {a['f1-score']*100:.3f} | {b['f1-score']*100:.3f} | {b['support']:,} |")
    rows+=['','| Metric | Preserved v2 | Selected repair |','|---|---:|---:|']
    for key in ('precision','recall','benign_fpr'):rows.append(f"| Binary {key} | {base['binary'][key]*100:.5f}% | {selected['binary'][key]*100:.5f}% |")
    rows +=[f"| Typed macro F1 | {base['macro_f1']*100:.4f}% | {selected['macro_f1']*100:.4f}% |",f"| Diagnosis routing | {base['routing_fraction']*100:.3f}% | {selected['routing_fraction']*100:.3f}% |",'',
        'Comparison failures: '+', '.join(comparison['failed_comparison_checks'])+'.','',
        f"All arms use unchanged labels. No new verified application ground truth or independent attack sessions were invented. SQL support remains too small. Better offline numbers do not establish device accuracy. All{len(config['jobs'])*config['epochs']} training epochs and validation prediction snapshots are retained.",'']
    (PUBLIC/'COMPARISON.md').write_text('\n'.join(rows));print('REPAIR_EVALUATION_COMPLETE',choose_repair,flush=True)


if __name__=='__main__':main()
