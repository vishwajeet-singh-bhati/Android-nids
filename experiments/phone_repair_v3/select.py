"""Joint checkpoint/calibration/routing selection; reads validation only."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json,sys,time
from pathlib import Path
import numpy as np
import torch

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_repair_v3.common import *
from experiments.phone_repair_v3.data import load_split
from experiments.phone_repair_v3.policy import probabilities,fit_calibration,decisions,score,improved


def shortlist(job,config):
    folder=RUN/'jobs'/job['name'];history=json.loads((folder/'history.json').read_text());k=config['shortlist_per_metric']
    chosen={v['epoch'] for v in sorted(history,key=lambda v:tuple(v['rank']),reverse=True)[:k]};chosen.add(config['epochs'])
    if job['kind']=='diagnosis':
        for c in ('Bot','Web Attack'):chosen.add(max(history,key=lambda v:v['reference_gate_pipeline']['classwise'][c]['f1-score'])['epoch'])
    result=[]
    for epoch in sorted(chosen):
        checkpoint=folder/f'epoch_{epoch:02d}.pt'
        result.append({'job':job,'epoch':epoch,'checkpoint':str(checkpoint.relative_to(ROOT)),'checkpoint_sha256':sha(checkpoint),
            'validation_logits':str((folder/f'validation_logits_{epoch:02d}.npy').relative_to(ROOT))})
    return result


def calibrated(entry,data,cal_idx):
    key=entry['checkpoint_sha256'];folder=RUN/'calibration';folder.mkdir(exist_ok=True);params=folder/(key+'.json');output=folder/(key+'.npy')
    if params.exists() and output.exists():return np.load(output,mmap_mode='r'),json.loads(params.read_text())
    z=np.load(ROOT/entry['validation_logits'],mmap_mode='r');cal=fit_calibration(z[cal_idx],np.asarray(data['y'][cal_idx]),entry['job']['kind'])
    p=probabilities(z,entry['job']['kind'],cal);np.save(output,p);atomic(params,cal)
    print('CALIBRATED',entry['job']['name'],entry['epoch'],flush=True)
    return np.load(output,mmap_mode='r'),cal


def policy_search(y,g,d,source,config,baseline):
    neg=g[y==0];highs=np.unique(np.r_[np.quantile(neg,config['joint_high_quantiles']),.99])
    best=None
    for high in highs:
        lows=np.unique([high,min(high,.1),min(high,float(np.quantile(neg,.99)))])
        for low in lows:
            routed=g>=low
            if float(routed.mean())>config['max_routing_fraction']:continue
            for accept in config['review_accept_thresholds']:
                for type_cutoff in config['type_thresholds']:
                    policy={'low':float(low),'high':float(high),'review_accept':accept,'type_cutoff':type_cutoff}
                    pred,flag,routed=decisions(g,d,policy);metrics=score(y,pred,flag,routed,source,config);comparison=improved(metrics,baseline,config)
                    rank=[int(comparison['better']),*metrics['rank']]
                    if best is None or tuple(rank)>tuple(best['selection_rank']):best={'policy':policy,'metrics':metrics,'comparison':comparison,'selection_rank':rank}
    if best is None:
        policy={'low':1.,'high':1.,'review_accept':.99,'type_cutoff':.6};pred,flag,routed=decisions(g,d,policy)
        metrics=score(y,pred,flag,routed,source,config);best={'policy':policy,'metrics':metrics,'comparison':improved(metrics,baseline,config),'selection_rank':[-1,*metrics['rank']]}
    return best


def main():
    torch.set_num_threads(2);config=json.loads((RUN/'config.json').read_text());data=load_split('validation')
    cal=np.load(RUN/'calibration_idx.npy');sel=np.load(RUN/'selection_idx.npy');y=np.asarray(data['y'][sel]);source=np.asarray(data['source'][sel])
    base_g=probabilities(np.load(RUN/'baseline_gate_validation_logits.npy',mmap_mode='r')[sel],'gate')
    base_d=probabilities(np.load(RUN/'baseline_diagnosis_validation_logits.npy',mmap_mode='r')[sel],'diagnosis')
    pred,flag,routed=decisions(base_g,base_d,config['baseline_policy']);baseline=score(y,pred,flag,routed,source,config)
    entries={job['name']:shortlist(job,config) for job in config['jobs']};groups=[]
    for arm in ('unweighted','moderate','hard_benign'):
        for seed in sorted({j['seed'] for j in config['jobs']}):groups.append((arm,seed,entries[f'{arm}_gate_s{seed}'],entries[f'{arm}_diagnosis_s{seed}']))
    base_config=json.loads((BASE/'config.json').read_text());choices=json.loads((BASE/'frozen_selection.json').read_text())['choices'];base_entries={}
    for kind,name in choices.items():
        path=BASE/'jobs'/name/'best.pt';ck=torch.load(path,map_location='cpu',weights_only=False)
        base_entries[kind]={'job':next(j for j in base_config['jobs'] if j['name']==name),'epoch':ck['epoch'],'checkpoint':str(path.relative_to(ROOT)),
            'checkpoint_sha256':sha(path),'validation_logits':str((RUN/('baseline_'+kind+'_validation_logits.npy')).relative_to(ROOT))}
    groups.append(('routing_only',0,[base_entries['gate']],[base_entries['diagnosis']]))
    finalists=[];all_pairs=[]
    for arm,seed,gates,diagnoses in groups:
        winner=None
        for ge in gates:
            gp,gc=calibrated(ge,data,cal);g=np.asarray(gp[sel])
            for de in diagnoses:
                dp,dc=calibrated(de,data,cal);d=np.asarray(dp[sel])
                result=policy_search(y,g,d,source,config,baseline)
                result.update({'arm':arm,'seed':seed,'gate':ge,'diagnosis':de,'gate_calibration':gc,'diagnosis_calibration':dc})
                all_pairs.append({'arm':arm,'seed':seed,'gate_epoch':ge['epoch'],'diagnosis_epoch':de['epoch'],'policy':result['policy'],'selection_rank':result['selection_rank'],'comparison':result['comparison'],'macro_f1':result['metrics']['macro_f1']})
                if winner is None or tuple(result['selection_rank'])>tuple(winner['selection_rank']):winner=result
                atomic(RUN/'selection_status.json',{'phase':'joint_selection','arm':arm,'seed':seed,'pairs_scored':len(all_pairs),'updated_unix':time.time()})
        finalists.append(winner);atomic(RUN/'selection_partial.json',{'baseline':baseline,'finalists':finalists,'pairs':all_pairs})
        print('ARM_FINALIST',arm,seed,winner['metrics']['macro_f1'],winner['metrics']['classwise']['Bot']['precision'],winner['comparison']['better'],flush=True)
    winner=max(finalists,key=lambda v:tuple(v['selection_rank']))
    frozen={'scope':'Calibration groups disjoint from selection groups; all choices frozen before v3 test evaluation. The inherited v2 test is already opened development data.',
        'config_sha256':sha(RUN/'config.json'),'calibration_idx_sha256':sha(RUN/'calibration_idx.npy'),'selection_idx_sha256':sha(RUN/'selection_idx.npy'),
        'baseline_selection_metrics':baseline,'selected':winner,'finalists':finalists,'pairs_scored':len(all_pairs),'frozen_unix':time.time()}
    if (RUN/'frozen_selection.json').exists():
        previous=json.loads((RUN/'frozen_selection.json').read_text());assert previous['config_sha256']==frozen['config_sha256'];assert previous['selected']['gate']['checkpoint_sha256']==winner['gate']['checkpoint_sha256'];assert previous['selected']['policy']==winner['policy']
    else:atomic(RUN/'frozen_selection.json',frozen)
    atomic(PUBLIC/'selection.json',frozen);print('REPAIR_SELECTION_FROZEN',winner['arm'],winner['seed'],flush=True)


if __name__=='__main__':main()
