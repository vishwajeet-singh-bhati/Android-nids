"""Choose the composed pipeline on validation, then open final test predictions once."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from collections import Counter
import json
import os
from pathlib import Path
import sys
import numpy as np
import torch
from sklearn.metrics import classification_report,confusion_matrix

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
SMOKE=os.environ.get('NIDS_PHONE_TRAINING_SMOKE')=='1'
os.environ['NIDS_ALIGNED_RUN']=str(ROOT/('runs/phone_capture_v1/training_smoke' if SMOKE else 'runs/phone_capture_training_v1'))
os.environ['NIDS_ALIGNED_CACHE']=str(ROOT/('data/experiments/phone_capture_training_smoke' if SMOKE else 'data/experiments/phone_capture_training_v1'))
os.environ['NIDS_ALIGNED_PUBLIC']=str(ROOT/('validation/reports/phone_capture_v1/evaluation_smoke' if SMOKE else 'validation/reports/phone_capture_training_v1'))
from experiments.phone_alignment_v2.common import RUN,CACHE,PUBLIC,CLASSES,atomic,sha
from experiments.phone_alignment_v2.models import build,RawWrapper


def predict_model(model,x,device):
    values=[];model.eval()
    with torch.inference_mode():
        for start in range(0,len(x),2048):values.append(model(torch.from_numpy(np.array(x[start:start+2048],copy=True)).to(device)).cpu().numpy())
    logits=np.concatenate(values)
    if logits.shape[1]==1:return torch.sigmoid(torch.from_numpy(logits)).numpy().flatten()
    return torch.softmax(torch.from_numpy(logits),1).numpy()


def compose(gate,diagnosis,threshold,cutoff):
    flags=gate>=threshold;arg=diagnosis.argmax(1);confidence=diagnosis.max(1)
    predicted=np.zeros(len(gate),np.int64);predicted[flags]=7
    named=flags&(arg!=0)&(confidence>=cutoff);predicted[named]=arg[named]
    return predicted,flags


def measures(y,predicted,flags):
    report=classification_report(y,predicted,labels=list(range(7)),target_names=CLASSES,zero_division=0,output_dict=True)
    present=[CLASSES[c] for c in range(7) if (y==c).any()]
    positive=y>0;tp=int((positive&flags).sum());fp=int((~positive&flags).sum());fn=int((positive&~flags).sum());tn=int((~positive&~flags).sum())
    return {'classwise':{name:report[name] for name in CLASSES},'macro_f1_present_classes':float(np.mean([report[name]['f1-score'] for name in present])),
        'binary':{'tp':tp,'fp':fp,'fn':fn,'tn':tn,'recall':tp/max(1,tp+fn),'precision':tp/max(1,tp+fp),'benign_fpr':fp/max(1,fp+tn)},
        'unknown_flags':int((predicted==7).sum()),'confusion_with_unknown_column':confusion_matrix(y,predicted,labels=list(range(8))).tolist()}


def baseline(raw,device):
    # The preserved mobile reference embeds CPU LSTM state allocations.
    # Keep that immutable artifact on CPU rather than rewriting its graph.
    folder=ROOT/'models/references/aligned_v2';g=torch.jit.load(str(folder/'gate.pt'),map_location='cpu').eval();d=torch.jit.load(str(folder/'diagnosis.pt'),map_location='cpu').eval()
    gp=[];dp=[]
    with torch.inference_mode():
        for start in range(0,len(raw),1024):
            x=torch.from_numpy(np.array(raw[start:start+1024],copy=True))
            gp.append(torch.sigmoid(g(x[:,:32],x[:,32:])).flatten().cpu().numpy());dp.append(torch.softmax(d(x[:,:32],x[:,32:]),1).cpu().numpy())
    return np.concatenate(gp),np.concatenate(dp)


def main():
    torch.set_num_threads(2);device='cuda' if torch.cuda.is_available() else 'cpu'
    config=json.loads((RUN/'config.json').read_text());PUBLIC.mkdir(parents=True,exist_ok=True)
    if (PUBLIC/'evaluation.json').exists():
        assert json.loads((PUBLIC/'evaluation.json').read_text())['state']=='complete'
        print('Evaluation already complete; no selection/test repeated.');return
    val_x=np.load(CACHE/'validation/x.npy',mmap_mode='r');val_y=np.load(CACHE/'validation/y.npy',mmap_mode='r');val_source=np.load(CACHE/'validation/source.npy',mmap_mode='r')
    probabilities={};variants=[]
    for job in config['jobs']:
        for checkpoint in ['best','final']:
            name=job['name']+'_'+checkpoint;path=RUN/'jobs'/job['name']/(checkpoint+'.pt')
            saved=torch.load(path,map_location='cpu',weights_only=False);model=build(job).to(device);model.load_state_dict(saved['model'])
            probabilities[name]=predict_model(model,val_x,device)
            info=json.loads((RUN/'jobs'/job['name']/('best_validation.json' if checkpoint=='best' else 'history.json')).read_text())
            metric=info['validation'] if checkpoint=='best' else info[-1]['validation']
            variants.append({'name':name,'job':job,'checkpoint':checkpoint,'threshold':metric['threshold'],'sha256':sha(path)})
    choices=[]
    for gate in [v for v in variants if v['job']['kind']=='gate']:
        for diagnosis in [v for v in variants if v['job']['kind']=='diagnosis']:
            for cutoff in [.5,.6,.7,.8]:
                predicted,flags=compose(probabilities[gate['name']],probabilities[diagnosis['name']],gate['threshold'],cutoff)
                old=measures(val_y[val_source!=7],predicted[val_source!=7],flags[val_source!=7]);phone=measures(val_y[val_source==7],predicted[val_source==7],flags[val_source==7])
                eligible=old['binary']['benign_fpr']<=.001 and old['binary']['recall']>=.98 and phone['binary']['benign_fpr']<=.02 and phone['binary']['recall']>=.85
                a=old['macro_f1_present_classes'];b=phone['macro_f1_present_classes'];harmonic=2*a*b/max(1e-12,a+b)
                choices.append({'gate':gate['name'],'diagnosis':diagnosis['name'],'threshold':gate['threshold'],'type_cutoff':cutoff,'eligible':eligible,
                    'rank':[int(eligible),harmonic,-phone['binary']['benign_fpr'],a],'validation':{'legacy':old,'phone':phone}})
    selected=max(choices,key=lambda value:tuple(value['rank']))
    frozen={'scope':'Full cascade selected on validation before final test predictions','selected':selected,'checkpoint_sha256':{v['name']:v['sha256'] for v in variants}}
    if (RUN/'frozen_selection.json').exists():
        before=json.loads((RUN/'frozen_selection.json').read_text());assert before==frozen,'Frozen selection changed; do not reuse the opened final test'
    else:atomic(RUN/'frozen_selection.json',frozen)
    atomic(PUBLIC/'validation_candidates.json',choices)
    # Test data/model predictions are opened only after selection is frozen above.
    test_x=np.load(CACHE/'test/x.npy',mmap_mode='r');test_raw=np.load(CACHE/'test/raw.npy',mmap_mode='r');test_y=np.load(CACHE/'test/y.npy',mmap_mode='r');test_source=np.load(CACHE/'test/source.npy',mmap_mode='r')
    results={};selected_p={}
    for v in variants:
        saved=torch.load(RUN/'jobs'/v['job']['name']/(v['checkpoint']+'.pt'),map_location='cpu',weights_only=False)
        model=build(v['job']).to(device);model.load_state_dict(saved['model']);p=predict_model(model,test_x,device)
        if v['name'] in [selected['gate'],selected['diagnosis']]:selected_p[v['name']]=p
        if v['job']['kind']=='gate':pred=np.where(p>=v['threshold'],7,0);flags=p>=v['threshold']
        else:pred=p.argmax(1);flags=pred!=0
        results[v['name']]={cohort:measures(test_y[take],pred[take],flags[take]) for cohort,take in [('legacy',test_source!=7),('phone',test_source==7)]}
    pred,flags=compose(selected_p[selected['gate']],selected_p[selected['diagnosis']],selected['threshold'],selected['type_cutoff'])
    current={cohort:measures(test_y[take],pred[take],flags[take]) for cohort,take in [('legacy',test_source!=7),('phone',test_source==7)]}
    bg,bd=baseline(test_raw,device);bp,bf=compose(bg,bd,.7858333333333334,.6)
    previous={cohort:measures(test_y[take],bp[take],bf[take]) for cohort,take in [('legacy',test_source!=7),('phone',test_source==7)]}
    phone_meta=json.loads((CACHE/'phone_test/metadata.json').read_text());phone_pred=pred[test_source==7];phone_flag=flags[test_source==7]
    subtypes={}
    for subtype in sorted({r['subtype'] for r in phone_meta}):
        take=np.array([r['subtype']==subtype for r in phone_meta]);y=np.asarray(test_y[test_source==7])[take]
        subtypes[subtype]={'support':int(take.sum()),'flag_rate':float(phone_flag[take].mean()),'correct_family_rate':float((phone_pred[take]==y).mean())}
    duration=0.0
    for sid in sorted({r['session'] for r in phone_meta}):
        rows=[r for r in phone_meta if r['session']==sid];duration+=max(r['end'] for r in rows)-min(r['start'] for r in rows)
    typed_ok=all(current['legacy']['classwise'][name]['precision']>=.85 and current['legacy']['classwise'][name]['recall']>=.85 for name in CLASSES)
    deployment=bool(selected['eligible'] and typed_ok and current['phone']['binary']['benign_fpr']<=.02 and current['phone']['binary']['recall']>=.85)
    episodes={}
    for sid in sorted({r['session'] for r in phone_meta}):
        take=np.array([r['session']==sid for r in phone_meta]);y=np.asarray(test_y[test_source==7])[take]
        episodes[sid]={'recorded_segments':int(take.sum()),'attack_segments':int((y>0).sum()),'normal_segments':int((y==0).sum()),
            'flagged_attack_segments':int(((y>0)&phone_flag[take]).sum()),'flagged_normal_segments':int(((y==0)&phone_flag[take]).sum())}
    report={'state':'complete','selected_validation_pipeline':selected,'frozen_v2_baseline':previous,'augmented_pipeline':current,'all_flagship_candidates':results,
        'phone_subtypes':subtypes,'phone_observed_traffic_seconds':duration,'deployment_eligible_in_this_pilot':deployment,'phone_model_replaced':False,
        'phone_test_sessions':episodes,'production_validated':False,'automation_smoke_only':SMOKE,'runtime':'Local WSL PyTorch CUDA/CPU; new-model native reattestation pending',
        'scope':'Same phone/app, chronological sessions with held-out request forms; small per-subtype support. Rates are recorded segments, not independent campaigns or general mobile accuracy. No auto-deployment.'}
    if SMOKE:report['scope']='Automation smoke only, not research model results. Technical fixtures reuse development pilot rows in validation/test to exercise code; excluded from the actual campaign.'
    report['baseline_artifact_sha256']={kind:sha(ROOT/'models/references/aligned_v2'/(kind+'.pt')) for kind in ['gate','diagnosis']}
    exports=RUN/'exports';exports.mkdir(exist_ok=True)
    norm=json.loads((CACHE/'normalization.json').read_text())
    for kind,name in [('gate',selected['gate']),('diagnosis',selected['diagnosis'])]:
        v=next(item for item in variants if item['name']==name);checkpoint=torch.load(RUN/'jobs'/v['job']['name']/(v['checkpoint']+'.pt'),map_location='cpu',weights_only=False)
        model=build(v['job']);model.load_state_dict(checkpoint['model']);wrapper=RawWrapper(model.eval(),norm['mean'],norm['scale']).eval()
        example=np.load(CACHE/'train/raw.npy',mmap_mode='r')[:1]
        row=torch.tensor(np.array(example,copy=True));torch.jit.trace(wrapper,(row[:,:32],row[:,32:]),check_trace=False).save(str(exports/(kind+'.pt')))
    lines=['# '+('Automation smoke only — not model results' if SMOKE else 'Real-phone augmented data v1 results'),'',report['scope'],'','No phone model was replaced. Deployment eligibility in this pilot: '+str(deployment)+'.','',
        '| Cohort | Version | Binary precision | Binary recall | Benign FPR | Typed macro F1 |','|---|---|---:|---:|---:|---:|']
    for cohort in ['legacy','phone']:
        for name,value in [('Frozen v2',previous[cohort]),('Augmented v1',current[cohort])]:
            m=value['binary'];lines.append(f"| {cohort} | {name} | {m['precision']:.6f} | {m['recall']:.6f} | {m['benign_fpr']:.6f} | {value['macro_f1_present_classes']:.6f} |")
    for cohort in ['legacy','phone']:
        lines+=['',f'## {cohort} classwise','', '| Class | Support | v2 P/R/F1 | Augmented P/R/F1 |','|---|---:|---|---|']
        for name in CLASSES:
            old=previous[cohort]['classwise'][name];new=current[cohort]['classwise'][name]
            if new['support']:
                left='/'.join(f"{old[k]:.4f}" for k in ['precision','recall','f1-score']);right='/'.join(f"{new[k]:.4f}" for k in ['precision','recall','f1-score'])
                lines.append(f"| {name} | {int(new['support'])} | {left} | {right} |")
    lines+=['','Classwise values, subtypes, counts, all best/final candidates and confusion matrices: evaluation.json. No test-driven checkpoint/threshold change follows this report.','']
    (PUBLIC/'RESULTS.md').write_text('\n'.join(lines),encoding='utf-8')
    atomic(PUBLIC/'evaluation.json',report)  # Completion marker follows successful exports/report.
    print('AUGMENTED_EVALUATION_COMPLETE',flush=True)


if __name__=='__main__':main()
