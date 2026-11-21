"""Read frozen, already-opened experiments for a report; never train or touch phones."""
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUT = ROOT / 'docs/project_report'
CLASSES = ['Benign', 'Bot', 'Brute Force', 'DDoS', 'DoS', 'Port Scan', 'Web Attack']
SOURCES = [
    'validation/reports/tsanet_paper/baseline_results.json',
    'validation/reports/tsanet_context/comparison.json',
    'validation/reports/tsanet_context/validation.json',
    'validation/reports/phone_alignment_v2/data_report.json',
    'validation/reports/phone_alignment_v2/evaluation.json',
    'validation/reports/phone_alignment_v2/drop_diagnostics.json',
    'validation/reports/phone_repair_v3/evaluation.json',
    'validation/reports/phone_repair_v3/selection.json',
    'validation/reports/phone_capture_v1/collection_summary.json',
    'validation/reports/phone_capture_training_v1/data_report.json',
    'validation/reports/publication_validity_audit/audit.json',
    'validation/reports/dataset_comparison/provenance.json',
    'validation/reports/v2_automated_phone_tests/results.json',
]


def read(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    import numpy as np
    import torch
    torch.set_num_threads(2)
    OUT.mkdir(parents=True, exist_ok=True)
    paper = read(SOURCES[0])
    context = read(SOURCES[1])
    aligned = read(SOURCES[4])
    repair = read(SOURCES[6])
    selection = read(SOURCES[7])['selected']
    data = read(SOURCES[3])
    payload = {
        'as_of_ist': datetime.now(timezone(timedelta(hours=5, minutes=30))).isoformat(),
        'scope': 'Read-only report on existing evidence. Dry runs use deterministic first rows of already-opened old cohorts, not the new phone validation/test cohort. No raw vectors, packets or private identities are published.',
        'classes': CLASSES,
        'source_files': [{'path': p, 'sha256': sha(ROOT/p)} for p in SOURCES],
        'paper': {'data': {k:paper['data'][k] for k in ['retained_rows','train_rows','test_rows','train_class_counts','test_class_counts']},
                  'models': {k:{'test':v['test'],'parameters':v['parameters'],'epochs':v['epochs']} for k,v in paper['models'].items()}},
        'context': context['results'],
        'aligned': {'counts':data['class_counts'], 'fine_counts':data['fine_counts'], 'source_counts':data['source_counts'],
                    'rows':data['rows'], 'pipeline':aligned['pipeline'],
                    'candidates': {k: {'binary':v.get('binary'), 'typed_macro_f1':v.get('classwise',{}).get('macro avg',{}).get('f1-score')} for k,v in aligned['models'].items()}},
        'repair': {'baseline':repair['baseline'],'selected':repair['selected_repair'],'selection_arm':repair['selection_arm'],
                   'selection_seed':repair['selection_seed'],'repair_is_better':repair['repair_is_better'],
                   'policy':selection['policy'], 'gate_epoch':selection['gate']['epoch'],'diagnosis_epoch':selection['diagnosis']['epoch'],
                   'finalists':[{'arm':v['arm'],'seed':v['seed'],'binary':v['metrics']['binary'],'macro_f1':v['metrics']['macro_f1']} for v in repair['finalists']]},
        'phone_augmentation':read(SOURCES[9]),
        'training_status':read('runs/phone_capture_training_v1/scheduler_status.json'),
        'dry_runs': []
    }
    cache = ROOT/'data/experiments/tsanet_paper_70_30'
    y = np.load(cache/'test_y.npy', mmap_mode='r')
    x = np.load(cache/'test_raw.npy', mmap_mode='r')
    ctx = np.load(ROOT/'data/experiments/tsanet_context_v1/test_raw.npy', mmap_mode='r')
    paper_models = {n:torch.jit.load(str(ROOT/'runs/tsanet_paper_70_30'/(n+'.pt')),map_location='cpu').eval() for n in ['baseline','pruned_30','pruned_40']}
    context_models = {n:torch.jit.load(str(ROOT/'runs/tsanet_context_v1'/(n+'.pt')),map_location='cpu').eval() for n in ['control_baseline','control_pruned_30','context_baseline','context_pruned_30']}
    norm = read('data/experiments/tsanet_paper_70_30/normalization.json')
    with torch.inference_mode():
        for cls in [0,1,6]:
            index = int(np.flatnonzero(y==cls)[0])
            flow = torch.from_numpy(np.array(x[index:index+1],copy=True))
            history = torch.from_numpy(np.array(ctx[index:index+1],copy=True))
            row = {'cohort':'historical CSV test','index':index,'known_label':CLASSES[cls],
                   'selected_flow_features':flow[0,:5].tolist(), 'selected_context_values':history[0,:8].tolist(),
                   'first_flow_standardization':{'raw':float(flow[0,0]),'mean':norm['mean'][0],'scale':norm['scale'][0],
                    'normalized':(float(flow[0,0])-norm['mean'][0])/norm['scale'][0]},'models':{}}
            for name,model in paper_models.items():
                logits=model(flow);p=torch.softmax(logits,1)[0]
                row['models'][name]={'logits':logits[0].tolist(),'probabilities':p.tolist(),'class':CLASSES[int(p.argmax())]}
            for name,model in context_models.items():
                logits=model(flow,history);p=torch.softmax(logits,1)[0]
                row['models'][name]={'logits':logits[0].tolist(),'probabilities':p.tolist(),'class':CLASSES[int(p.argmax())]}
            payload['dry_runs'].append(row)
    from experiments.phone_alignment_v2.models import build
    from experiments.phone_repair_v3.policy import probabilities, decisions
    cache=ROOT/'data/experiments/phone_alignment_v2/test'
    raw=np.load(cache/'raw.npy',mmap_mode='r');standard=np.load(cache/'x.npy',mmap_mode='r');labels=np.load(cache/'y.npy',mmap_mode='r')
    v2={kind:torch.jit.load(str(ROOT/'runs/phone_repair_v3/exports/preserved_v2'/(kind+'.pt')),map_location='cpu').eval() for kind in ['gate','diagnosis']}
    repaired={}
    for kind in ['gate','diagnosis']:
        checkpoint=torch.load(ROOT/selection[kind]['checkpoint'],map_location='cpu',weights_only=False)
        model=build(selection[kind]['job']).eval();model.load_state_dict(checkpoint['model']);repaired[kind]=model
    with torch.inference_mode():
        for cls in [0,1,3,6]:
            index=int(np.flatnonzero(labels==cls)[0]);r=torch.from_numpy(np.array(raw[index:index+1],copy=True));z=torch.from_numpy(np.array(standard[index:index+1],copy=True))
            gl=v2['gate'](r[:,:32],r[:,32:]);dl=v2['diagnosis'](r[:,:32],r[:,32:]);gp=torch.sigmoid(gl)[0,0].item();dp=torch.softmax(dl,1)[0]
            arg=int(dp.argmax());flag=gp>=.7858333333333334
            pred=CLASSES[arg] if flag and arg!=0 and float(dp.max())>=.6 else 'Unclassified' if flag else 'Benign'
            a=probabilities(repaired['gate'](z).numpy(),'gate',selection['gate_calibration'])
            b=probabilities(repaired['diagnosis'](z).numpy(),'diagnosis',selection['diagnosis_calibration'])
            policy=selection['policy'];rp_array,rf_array,routed=decisions(a,b,policy)
            route=bool(routed[0]);rf=bool(rf_array[0]);rp=CLASSES[int(rp_array[0])] if rp_array[0]<7 else 'Unclassified'
            payload['dry_runs'].append({'cohort':'opened aligned v2 test','index':index,'known_label':CLASSES[cls],
                'selected_flow_features':r[0,:5].tolist(),'selected_context_values':r[0,32:40].tolist(),
                'v2':{'gate_logit':float(gl[0,0]),'gate_probability':gp,'diagnosis_probabilities':dp.tolist(),'diagnosis_argmax':CLASSES[arg],
                    'diagnosis_would_run':flag,'flagged':flag,'final_type':pred},
                'repair':{'calibrated_gate_probability':float(a[0]),'diagnosis_probabilities':b[0].tolist(),'diagnosis_would_run':route,
                    'flagged':rf,'final_type':rp}})
        # A complete, explicitly invented software fixture, never training or attack truth.
        # Two zero-payload SYN/RST-ACK packets 10 ms apart; two prior similar flows.
        f=torch.tensor([[10000,1,1,0,0,0,0,0,0,0,0,0,0,0,200,10000,0,10000,10000,
                         0,0,0,0,0,0,0,0,0,0,1,1,1]],dtype=torch.float32)
        L2=float(np.log(2));L3=float(np.log(3))
        source=[L3,L3,L3,0,0,L2,L3,L2,0,1,1,1,0]
        destination=[L3,L3,L3,0,0,L2,L2,L3,0,1,1,1,0]
        c78=torch.tensor([(source+destination)*3],dtype=torch.float32)
        c115=torch.tensor([((source+[0,0,0])+(destination+[0,0,0]))*3+[0]*18+[float(np.log(301))]],dtype=torch.float32)
        fixture={'scope':'Hand-constructed coherent software input only; no accuracy label, training use, phone traffic or dataset row.',
                 'flow':f[0].tolist(),'context78':c78[0].tolist(),'context115':c115[0].tolist(),'models':{}}
        for name,model in paper_models.items():
            logits=model(f);p=torch.softmax(logits,1)[0]
            fixture['models'][name]={'logits':logits[0].tolist(),'probabilities':p.tolist(),'class':CLASSES[int(p.argmax())]}
        for name,model in context_models.items():
            logits=model(f,c78);p=torch.softmax(logits,1)[0]
            fixture['models'][name]={'logits':logits[0].tolist(),'probabilities':p.tolist(),'class':CLASSES[int(p.argmax())]}
        gl=v2['gate'](f,c115);dl=v2['diagnosis'](f,c115);gp=float(torch.sigmoid(gl)[0,0]);dp=torch.softmax(dl,1)[0]
        arg=int(dp.argmax());flag=gp>=.7858333333333334
        fixture['v2']={'gate_logit':float(gl[0,0]),'gate_probability':gp,'diagnosis_probabilities':dp.tolist(),
                       'diagnosis_would_run':flag,'final_type':CLASSES[arg] if flag and arg!=0 and float(dp.max())>=.6 else 'Unclassified' if flag else 'Benign'}
        from experiments.phone_alignment_v2.data import transform
        norm=read('data/experiments/phone_alignment_v2/normalization.json')
        rawfixture=np.concatenate([f.numpy(),c115.numpy()],axis=1)
        z=torch.from_numpy(((transform(rawfixture)-np.array(norm['mean']))/np.array(norm['scale'])).astype(np.float32))
        a=probabilities(repaired['gate'](z).numpy(),'gate',selection['gate_calibration'])
        b=probabilities(repaired['diagnosis'](z).numpy(),'diagnosis',selection['diagnosis_calibration'])
        label,flag,route=decisions(a,b,selection['policy'])
        fixture['repair']={'gate_probability':float(a[0]),'diagnosis_probabilities':b[0].tolist(),'diagnosis_would_run':bool(route[0]),
                           'final_type':CLASSES[int(label[0])] if label[0]<7 else 'Unclassified'}
        payload['software_fixture']=fixture
    # Save only aggregate tables and a few explicitly explained feature values, never full cohort vectors.
    target=OUT/'REPORT_EVIDENCE.json';target.write_text(json.dumps(payload,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    if (ROOT/'validation/reports/phone_capture_training_v1/evaluation.json').exists():
        from tools.report.final_training_report import update
        update(ROOT)
    if (ROOT/'validation/reports/false_positive_audit_20261121/later_benign_case_audit.json').exists():
        from tools.report.current_release_report import update as update_current
        update_current(ROOT)
    print(json.dumps({'report_evidence':str(target),'dry_runs':len(payload['dry_runs']),'training_completed':payload['training_status']['completed'],'raw_dataset_files_written':False},indent=2))


if __name__=='__main__':main()
