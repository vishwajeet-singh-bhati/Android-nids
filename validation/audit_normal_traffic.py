"""Offline diagnosis of already observed false positives. No phone actions or fitting.

These cases have already informed development. They are regression evidence, not
an independent hold-out set for choosing a new detector or quoting general FPR.
"""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'validation'))
PUBLIC=ROOT/'validation/reports/false_positive_audit_20261121'
PRIVATE=ROOT/'runs/false_positive_audit_20261121'


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def main():
    import numpy as np
    import torch
    import review_protocol_results as review
    import protocol_phone_test as protocol
    from experiments.phone_alignment_v2.models import build,RawWrapper

    torch.set_num_threads(2)
    password=json.loads((ROOT/'runs/manual_phone_tests/20261121_200901_PasswordGuessing/check.json').read_text(encoding='utf-8'))
    matched=password['traffic_correlation']['counts']['matched_test_capture']
    assert matched==21 and all(r['traffic_correlation']=='matched_test_capture' for r in password['model_flags'])
    password_audit=json.loads((PUBLIC/'password_case_audit.json').read_text(encoding='utf-8'))
    password_audit.update({'matched_flags':matched,'matched_flags_source':'check.json traffic_correlation.counts.matched_test_capture'})
    save(PUBLIC/'password_case_audit.json',password_audit)
    import ipaddress
    idle=[json.loads(line) for line in (PRIVATE/'monitor_tail.jsonl').read_text(encoding='utf-8').splitlines()]
    idle_flags=[r for r in idle if r.get('event')=='model_flag']
    loops=0
    for row in idle_flags:
        e=row['evidence'];a=e['attribution']
        loops+=int(all(ipaddress.ip_address(a[k].rsplit(':',1)[0]).is_loopback for k in ('initiator','responder')))
    save(PUBLIC/'initial_idle_audit.json',{'saved_tail_model_flags':len(idle_flags),'both_endpoints_loopback':loops,
        'all_flags_device_local':loops==len(idle_flags)>0,'producer_app_identified':False,
        'scope':'Read-only saved current-session tail; local traffic is not thereby established safe.'})
    case_ids=(*review.CASE_IDS,'20261121_201602_Benign_8c1433')
    raw=[];expected=[];partitions=[];baseline=[];case_reports=[]
    for case_id in case_ids:
        case=protocol.RUN/'cases'/case_id
        checked=review.audit(case);case_reports.append(checked)
        meta=json.loads((case/'run.json').read_text(encoding='utf-8'))
        events=json.loads((case/'target_events.json').read_text(encoding='utf-8'))
        by_key={protocol.key(6,(meta['contract']['phone'],e['local_port']),(e['peer'],e['peer_port'])):e['event']
                for e in events if 'peer' in e}
        trace=protocol.lab.json_lines((case/'native.jsonl').read_text(encoding='utf-8'))
        for row in trace:
            key=protocol.key(row['protocol'],(row['source'],row['sport']),(row['destination'],row['dport']))
            if key not in by_key:continue
            event=by_key[key];profile=checked['profile']
            label=0
            if profile in ('FTPBruteForce','SSHBruteForce') and event.endswith('login_failure'):label=2
            elif profile=='BotBehavior' and event=='bot_exchange':label=1
            elif profile in ('DoS','DDoS') and event in ('resource_held','resource_denied'):label=4 if profile=='DoS' else 3
            # Emulator trigger and availability probes are not attack requests.
            raw.append(row['flow']+row['context']);expected.append(label)
            partitions.append(profile+'/'+event);baseline.append(row['gate_score'])
    raw=np.asarray(raw,np.float32);y=np.asarray(expected)
    assert np.isfinite(raw).all() and len(raw)==sum(c['all_test_connections']['connections'] for c in case_reports)
    run=ROOT/'runs/phone_capture_training_v1';cache=ROOT/'data/experiments/phone_capture_training_v1'
    config=json.loads((run/'config.json').read_text(encoding='utf-8'))
    norm=json.loads((cache/'normalization.json').read_text(encoding='utf-8'))
    frozen=json.loads((run/'frozen_selection.json').read_text(encoding='utf-8'))
    cutoff=frozen['selected']['threshold']
    scores={};checkpoints={}
    with torch.inference_mode():
        for job in config['jobs']:
            if job['kind']!='gate':continue
            for variant in ('best','final'):
                path=run/'jobs'/job['name']/(variant+'.pt')
                model=build(job).eval();model.load_state_dict(torch.load(path,map_location='cpu',weights_only=False)['model'])
                wrapper=RawWrapper(model,norm['mean'],norm['scale']).eval()
                tensor=torch.from_numpy(raw)
                score=torch.sigmoid(wrapper(tensor[:,:32],tensor[:,32:])).flatten().numpy()
                name=job['name']+'_'+variant;scores[name]=score
                checkpoints[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    current=frozen['selected']['gate']
    max_error=float(np.max(np.abs(scores[current]-baseline)))
    assert max_error<2e-5
    summary={}
    for name,score in scores.items():
        by_partition={}
        for group in sorted(set(partitions)):
            mask=np.asarray([p==group for p in partitions])
            by_partition[group]={'connections':int(mask.sum()),'flagged':int((score[mask]>=cutoff).sum()),
                'score_range':[float(score[mask].min()),float(score[mask].max())]}
        summary[name]={'normal_flags':int(((y==0)&(score>=cutoff)).sum()),'normal_connections':int((y==0).sum()),
            'attack_flags':int(((y>0)&(score>=cutoff)).sum()),'attack_connections':int((y>0).sum()),'partitions':by_partition}
    # Compare normal protocol failures with normal *training* data. No fitting.
    transformed=raw.copy();transformed[:,:32]=np.log1p(np.maximum(transformed[:,:32],0))
    transformed[:,128:146]=np.log1p(np.maximum(transformed[:,128:146],0))
    z=(transformed-np.asarray(norm['mean']))/np.asarray(norm['scale'])
    diagnostic=[]
    specification=json.loads((ROOT/'runs/phone_alignment_v2/extractor/spec.json').read_text(encoding='utf-8'))
    for i,(label,part) in enumerate(zip(y,partitions)):
        if label!=0 or scores[current][i]<cutoff:continue
        top=np.argsort(np.abs(z[i]))[-6:][::-1]
        diagnostic.append({'partition':part,'gate_score':float(scores[current][i]),
            'largest_absolute_train_z':[{'feature_index':int(j),'name':specification['context_names'][j-32] if j>=32 else 'flow_'+str(j),
                'raw_value':float(raw[i,j]),'z':float(z[i,j])} for j in top]})
    protocol_training_counts={name:Counter() for name in ('ssh','ftp')}
    training_raw=np.load(cache/'train/raw.npy',mmap_mode='r');training_y=np.load(cache/'train/y.npy',mmap_mode='r')
    for start in range(0,len(training_y),65536):
        batch=training_raw[start:start+65536];labels=training_y[start:start+65536]
        for column,name in ((144,'ssh'),(145,'ftp')):
            protocol_training_counts[name].update(map(int,labels[batch[:,column]>0]))
    # Counterfactual feature ablation is diagnosis only: never install a parser
    # that lies about the protocol to obtain a quieter metric.
    name,variant=current.rsplit('_',1);job=next(j for j in config['jobs'] if j['name']==name)
    model=build(job).eval();model.load_state_dict(torch.load(run/'jobs'/name/(variant+'.pt'),map_location='cpu',weights_only=False)['model'])
    wrapper=RawWrapper(model,norm['mean'],norm['scale']).eval();masked=raw.copy();masked[:,144:146]=0
    with torch.inference_mode():
        tensor=torch.from_numpy(masked);ablated=torch.sigmoid(wrapper(tensor[:,:32],tensor[:,32:])).flatten().numpy()
    ablation={'diagnostic_only_not_deployed':True,'masked_features':['ssh_banner_seen','ftp_banner_or_credentials_seen'],
        'normal_flags':int(((y==0)&(ablated>=cutoff)).sum()),'attack_flags':int(((y>0)&(ablated>=cutoff)).sum()),
        'normal_connections':int((y==0).sum()),'attack_connections':int((y>0).sum())}
    save(PRIVATE/'external_false_positive_feature_diagnostics.json',diagnostic)
    save(PRIVATE/'regression_feature_rows.json',{'raw':raw.tolist(),'expected':expected,'partitions':partitions})
    result={'scope':'Already observed development/regression cases; no independent FPR or checkpoint-selection claim.',
        'fitting_or_threshold_changes':False,'phone_actions':0,'threshold':cutoff,'current':current,
        'native_reference_maximum_error':max_error,'rows':len(raw),'checkpoint_sha256':checkpoints,'candidates':summary,
        'protocol_indicator_training_counts':{k:dict(v) for k,v in protocol_training_counts.items()},
        'protocol_indicator_ablation':ablation,
        'normal_control_case_ids':[c for c in case_ids if '_Benign_' in c],
        'note':'Probe failures during the dummy-service DoS are effects, not attack payloads. No new attacks were run.'}
    save(PUBLIC/'frozen_checkpoint_regression.json',result)
    for name,values in summary.items():print(name,{k:v for k,v in values.items() if k!='partitions'},flush=True)
    print('NATIVE_PARITY',max_error,flush=True)
    print('PROTOCOL_TRAINING',protocol_training_counts,'ABLATION',ablation,flush=True)


if __name__=='__main__':main()
