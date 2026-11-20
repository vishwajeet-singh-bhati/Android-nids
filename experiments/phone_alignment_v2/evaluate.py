"""Freeze validation choices, then evaluate all flagships and report honest scopes."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import collections,json,sys,time
from pathlib import Path
import numpy as np,torch
from sklearn.metrics import classification_report,confusion_matrix,roc_auc_score,average_precision_score

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_alignment_v2.common import *
from experiments.phone_alignment_v2.models import build,RawWrapper
from experiments.phone_alignment_v2.train import load_split,probabilities


def binary_metrics(y,p,threshold):
    positive=y>0;flag=p>=threshold
    tp=int((flag&positive).sum());fp=int((flag&~positive).sum());fn=int((~flag&positive).sum());tn=int((~flag&~positive).sum())
    return {'tp':tp,'fp':fp,'fn':fn,'tn':tn,'precision':tp/max(1,tp+fp),'recall':tp/max(1,tp+fn),'f1':2*tp/max(1,2*tp+fp+fn),
        'benign_fpr':fp/max(1,fp+tn),'accuracy':(tp+tn)/max(1,len(y)),
        'class_attack_recall':{CLASSES[c]:float(flag[y==c].mean()) if (y==c).any() else None for c in range(1,7)}}


def metrics(y,p,job,threshold,data):
    attack=p if job['kind']=='gate' else 1-p[:,0];result={'binary':binary_metrics(y,attack,threshold),'threshold':threshold}
    result['auroc']=float(roc_auc_score(y>0,attack));result['average_precision']=float(average_precision_score(y>0,attack))
    if job['kind']!='gate':
        predicted=p.argmax(1)
        result['classwise']=classification_report(y,predicted,labels=list(range(7)),target_names=CLASSES,zero_division=0,output_dict=True)
        result['confusion']=confusion_matrix(y,predicted,labels=list(range(7))).tolist()
    result['sources']={}
    for s in np.unique(data['source']):
        take=np.asarray(data['source'])==s;result['sources'][SOURCES[int(s)]]=binary_metrics(y[take],attack[take],threshold)
    result['fine_label_recall']={}
    for f,label in enumerate(FINE):
        take=np.asarray(data['fine'])==f
        if take.any():result['fine_label_recall'][label]={'support':int(take.sum()),'flag_rate':float((attack[take]>=threshold).mean()),
            'family_recall':float((p[take].argmax(1)==y[take]).mean()) if job['kind']!='gate' else None}
    return result


def main():
    config=json.loads((RUN/'config.json').read_text());jobs=config['jobs'];torch.set_num_threads(2)
    device='cuda' if torch.cuda.is_available() else 'cpu';test=load_split('test');y=np.asarray(test['y'])
    choices={}
    for kind in ('gate','diagnosis'):
        possible=[j for j in jobs if j['kind']==kind and j.get('selection_eligible',True)]
        selected=max(possible,key=lambda j:tuple(json.loads((RUN/'jobs'/j['name']/'best_validation.json').read_text())['validation']['rank']))
        choices[kind]=selected['name']
    frozen={'selection':'validation only, before this final evaluation','choices':choices,'model_hashes':{j['name']:sha(RUN/'jobs'/j['name']/'best.pt') for j in jobs},'frozen_unix':time.time()}
    if (RUN/'frozen_selection.json').exists():assert json.loads((RUN/'frozen_selection.json').read_text())['model_hashes']==frozen['model_hashes']
    else:atomic(RUN/'frozen_selection.json',frozen)
    results={};selected_probability={}
    for job in jobs:
        for checkpoint_name in ('best','final'):
            folder=RUN/'jobs'/job['name'];ck=torch.load(folder/(checkpoint_name+'.pt'),map_location='cpu',weights_only=False)
            model=build(job).to(device);model.load_state_dict(ck['model']);model.eval()
            p=probabilities(model,test,job['kind'],device);validation=ck['history'][-1]['validation']
            if checkpoint_name=='best':validation=json.loads((folder/'best_validation.json').read_text())['validation']
            key=job['name']+':'+checkpoint_name;results[key]=metrics(y,p,job,validation['threshold'],test)
            results[key].update({'checkpoint_sha256':sha(folder/(checkpoint_name+'.pt')),'epoch':ck['epoch'],'parameters':sum(v.numel() for v in model.parameters())})
            atomic(RUN/'evaluation_partial.json',results)
            if checkpoint_name=='best' and job['name'] in choices.values():selected_probability[job['kind']]=p
            print('FINAL_EVALUATION',key,results[key]['binary']['recall'],results[key]['binary']['benign_fpr'],flush=True)
    gate=selected_probability['gate'];diagnosis=selected_probability['diagnosis']
    gate_validation=json.loads((RUN/'jobs'/choices['gate']/'best_validation.json').read_text())['validation']
    threshold=gate_validation['threshold'];flag=gate>=threshold
    predicted=diagnosis.argmax(1);typed_score=diagnosis.max(1)
    predicted=np.where(flag,np.where((predicted!=0)&(typed_score>=config['type_score_cutoff']),predicted,7),0)
    pipeline={'binary':binary_metrics(y,gate,threshold),'diagnosis_never_vetoes_gate':True,
        'classwise':classification_report(y,predicted,labels=list(range(7)),target_names=CLASSES,output_dict=True,zero_division=0),
        'confusion_with_unknown':confusion_matrix(y,predicted,labels=list(range(8))).tolist(),
        'unknown_type_among_flagged':int(((predicted==7)&flag).sum())/max(1,int(flag.sum())),
        'flagged_rows':int(flag.sum()),'threshold':threshold,'type_score_cutoff':config['type_score_cutoff']}
    typed_ok=all(pipeline['classwise'][c]['precision']>=config['min_typed_precision'] and pipeline['classwise'][c]['recall']>=config['min_typed_recall'] for c in CLASSES)
    source_ok=all(v['benign_fpr']<=config['max_source_benign_fpr'] for v in results[choices['gate']+':best']['sources'].values())
    eligible=gate_validation['eligible'] and typed_ok and source_ok and pipeline['binary']['benign_fpr']<=config['max_benign_fpr'] and pipeline['binary']['recall']>=config['min_attack_recall'] and all(v>=config['min_class_attack_recall'] for v in pipeline['binary']['class_attack_recall'].values() if v is not None)
    reference=results.get('aligned32_s0:best',{}).get('classwise',{})
    regressions={c:{metric:pipeline['classwise'][c][metric]-reference[c][metric] for metric in ('precision','recall','f1-score')} for c in CLASSES} if reference else {}
    report={'config_sha256':sha(RUN/'config.json'),'frozen_selection':frozen,'models':results,'pipeline':pipeline,
        'offline_targets_passed':bool(eligible),'deployment_allowed':False,'device_reattest_required':True,'matched_regressions_vs_aligned32':regressions,
        'scope':'Grouped raw-flow benchmark with causal unlabeled stream context. Opened manual phone captures are excluded from fitting and are development diagnostics. Laboratory scores do not establish phone attack accuracy.'}
    atomic(RUN/'evaluation.json',report);atomic(PUBLIC/'evaluation.json',report)
    rows=['# Phone-aligned v2 results','',report['scope'],'','| Candidate | Attack precision | Attack recall | Benign FPR | Macro F1 (typed) |','|---|---:|---:|---:|---:|']
    for key,value in results.items():
        b=value['binary'];macro=value.get('classwise',{}).get('macro avg',{}).get('f1-score')
        rows.append(f"| {key} | {b['precision']:.6f} | {b['recall']:.6f} | {b['benign_fpr']:.6f} | {macro if macro is not None else 'gate only'} |")
    rows+=['','## Selected pipeline classwise results','','| Class | Precision | Recall | F1 | Support | Binary gate recall |','|---|---:|---:|---:|---:|---:|']
    for cls in CLASSES:
        value=pipeline['classwise'][cls];gate_recall=pipeline['binary']['class_attack_recall'].get(cls,'n/a')
        rows.append(f"| {cls} | {value['precision']:.6f} | {value['recall']:.6f} | {value['f1-score']:.6f} | {int(value['support'])} | {gate_recall} |")
    rows+=['',f"Offline targets passed: {eligible}. Deployment remains pending fresh native/ordinary-use/manual phone validation.",
        '', 'Diagnosis unknowns retain their binary alert. Exact application attack confirmation is not inferred from traffic shape alone. Fine-label/source metrics and every confusion count are in evaluation.json. Historical CSV benchmark results are a different cohort and are not directly comparable.', '']
    (PUBLIC/'RESULTS.md').write_text('\n'.join(rows))
    export=RUN/'exports';export.mkdir(exist_ok=True);norm=json.loads((CACHE/'normalization.json').read_text())
    exports={}
    for kind,name in choices.items():
        job=next(j for j in jobs if j['name']==name);checkpoint=torch.load(RUN/'jobs'/name/'best.pt',map_location='cpu',weights_only=False)
        model=build(job).eval();model.load_state_dict(checkpoint['model']);wrapper=RawWrapper(model,norm['mean'],norm['scale']).eval()
        raw=np.load(CACHE/'test/raw.npy',mmap_mode='r');ids=np.unique(np.r_[np.arange(min(512,len(y))),*[np.flatnonzero(y==c)[:64] for c in range(7)]])
        example=np.array(raw[ids],copy=True)
        a=torch.from_numpy(example[:,:32]);b=torch.from_numpy(example[:,32:])
        with torch.inference_mode():
            traced=torch.jit.trace(wrapper,(a[:1],b[:1]));path=export/(kind+'.pt');traced.save(str(path));actual=traced(a,b);expected=wrapper(a,b)
            assert torch.allclose(actual,expected,atol=1e-4,rtol=1e-4)
        exports[kind]={'job':name,'sha256':sha(path),'parameters':sum(p.numel() for p in model.parameters()),'parity_rows':len(a),'maximum_error':float((actual-expected).abs().max())}
    atomic(PUBLIC/'export_manifest.json',exports);print('ALIGNED_EVALUATION_COMPLETE',eligible,flush=True)


if __name__=='__main__':main()
