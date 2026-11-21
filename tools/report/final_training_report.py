"""Incorporate completed frozen aggregate results; never rescore held-out rows."""
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path


def update(root):
    folder=root/'docs/project_report';path=folder/'REPORT_EVIDENCE.json'
    result=root/'validation/reports/phone_capture_training_v1/evaluation.json'
    if not result.exists():return
    final=json.loads(result.read_text(encoding='utf-8'))
    assert final['state']=='complete' and not final['phone_model_replaced']
    data=json.loads(path.read_text(encoding='utf-8'));data['completed_augmentation']=final
    data['training_status']=json.loads((root/'runs/phone_capture_training_v1/scheduler_status.json').read_text(encoding='utf-8'))
    assert data['training_status']['completed']==6
    data['as_of_ist']=datetime.now(timezone(timedelta(hours=5,minutes=30))).isoformat()
    addition=' Completed frozen aggregate evaluation is included; no new held-out-row scoring, checkpoint replacement or threshold fitting is performed by reporting.'
    if addition.strip() not in data['scope']:data['scope']+=addition
    for relative in ['validation/reports/phone_capture_training_v1/evaluation.json','validation/reports/phone_capture_training_v1/RESULTS.md']:
        data['source_files']=[v for v in data['source_files'] if v['path']!=relative]
        data['source_files'].append({'path':relative,'sha256':hashlib.sha256((root/relative).read_bytes()).hexdigest()})
    import torch
    torch.set_num_threads(2)
    fixture=data['software_fixture'];flow=torch.tensor([fixture['flow']],dtype=torch.float32);context=torch.tensor([fixture['context115']],dtype=torch.float32)
    exports=root/'runs/phone_capture_training_v1/exports'
    gate=torch.jit.load(str(exports/'gate.pt'),map_location='cpu').eval();diagnosis=torch.jit.load(str(exports/'diagnosis.pt'),map_location='cpu').eval()
    with torch.inference_mode():
        g=float(torch.sigmoid(gate(flow,context))[0,0]);p=torch.softmax(diagnosis(flow,context),1)[0].tolist()
    selected=final['selected_validation_pipeline'];flag=g>=selected['threshold'];arg=max(range(7),key=p.__getitem__)
    fixture['augmented']={'scope':'Existing complete invented fixture only, not held-out phone traffic. Diagnosis is counterfactual when the gate is negative.',
        'gate_probability':g,'diagnosis_probabilities':p,'diagnosis_would_run':flag,
        'final_type':data['classes'][arg] if flag and arg!=0 and p[arg]>=selected['type_cutoff'] else 'Unclassified' if flag else 'Benign'}
    path.write_text(json.dumps(data,indent=2,allow_nan=False)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'training_complete':6,'phone_tp':final['augmented_pipeline']['phone']['binary']['tp'],
        'phone_fp':final['augmented_pipeline']['phone']['binary']['fp'],'deployment_eligible':final['deployment_eligible_in_this_pilot'],
        'heldout_rows_rescored':0},indent=2))


if __name__=='__main__':update(Path(__file__).resolve().parents[2])
