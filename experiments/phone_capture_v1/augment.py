"""Build a new training cache from immutable old splits plus verified phone sessions."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import numpy as np

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_capture_v1 import collect as capture
from experiments.phone_alignment_v2.data import transform

CACHE=ROOT/'data/experiments/phone_capture_training_v1'
OLD=ROOT/'data/experiments/phone_alignment_v2'
TRAIN_RUN=ROOT/'runs/phone_capture_training_v1'
PUBLIC=ROOT/'validation/reports/phone_capture_training_v1'
REPLAY_FACTOR=8  # Declared exact resampling, never presented as independent observations.
FINE={'normal_http':0,'successful_login':0,'ordinary_failed_login':0,'normal_search_or_code':0,'normal_page':0,
      'ordinary_server_error':0,'legitimate_http_burst':0,'http_password_guessing':10,'xss':11,'sql_injection':12,'http_password_spraying':13}


def hash64(text):return int.from_bytes(hashlib.sha256(text.encode()).digest()[:8],'little',signed=True)


def prepare(plan):
    CACHE.mkdir(parents=True,exist_ok=True);TRAIN_RUN.mkdir(parents=True,exist_ok=True);PUBLIC.mkdir(parents=True,exist_ok=True)
    if (CACHE/'ready.json').exists():return json.loads((CACHE/'ready.json').read_text(encoding='utf-8'))
    data={name:[] for name in ['train','validation','test']};sessions={name:[] for name in data};unique_counts={}
    for session in plan['sessions']:
        case=capture.RUN/'sessions'/session['session']
        quality=json.loads((case/'quality.json').read_text(encoding='utf-8'))
        assert quality['passed'] and quality['partition']==session['partition']
        assert quality['maximum_feature_error']<=1e-4 and quality['background_flows_automatically_labeled']==0
        rows=[json.loads(line) for line in (case/'labeled_features.jsonl').read_text(encoding='utf-8').splitlines()]
        assert all(r['session']==session['session'] and r['partition']==session['partition'] for r in rows)
        sessions[session['partition']].append(session['session']);data[session['partition']]+=rows
    assert len(sessions['train'])>=8 and len(sessions['validation'])>=2 and len(sessions['test'])>=2
    assert not(set(sessions['train'])&set(sessions['validation']) or set(sessions['train'])&set(sessions['test']) or set(sessions['validation'])&set(sessions['test']))
    assert all('pilot' not in sid for values in sessions.values() for sid in values)
    manifests={};output={};phone_only={}
    shapes={'raw':(np.float32,(147,)),'x':(np.float32,(147,)),'y':(np.int64,()),'source':(np.int8,()),'fine':(np.int16,()),
        'group':(np.int64,()),'host':(np.int64,()),'start':(np.float64,()),'end':(np.float64,())}
    for split,rows in data.items():
        unique_counts[split]=len(rows);assert len(rows)>=40
        assert all(any(r['subtype']==kind for r in rows) for kind in ['sql_injection','xss','http_password_guessing','http_password_spraying'])
        phone_raw=np.asarray([r['raw'] for r in rows],dtype=np.float32);phone_y=np.asarray([r['family'] for r in rows],np.int64)
        assert phone_raw.shape==(len(rows),147) and np.isfinite(phone_raw).all()
        phone_only[split]=(phone_raw,phone_y,rows)
        n_old=len(np.load(OLD/split/'y.npy',mmap_mode='r'));factor=REPLAY_FACTOR if split=='train' else 1
        ids=np.tile(np.arange(len(rows)),factor);n=n_old+len(ids)
        folder=CACHE/split;folder.mkdir(parents=True,exist_ok=True)
        arrays={k:np.lib.format.open_memmap(folder/(k+'.npy'),mode='w+',dtype=dtype,shape=(n,*shape)) for k,(dtype,shape) in shapes.items()}
        for k in shapes:
            if k=='x':continue
            old=np.load(OLD/split/(k+'.npy'),mmap_mode='r')
            for start in range(0,n_old,65536):
                stop=min(n_old,start+65536);arrays[k][start:stop]=old[start:stop]
        arrays['raw'][n_old:]=phone_raw[ids];arrays['y'][n_old:]=phone_y[ids];arrays['source'][n_old:]=7
        arrays['fine'][n_old:]=np.asarray([FINE[r['subtype']] for r in rows],np.int16)[ids]
        arrays['group'][n_old:]=np.asarray([hash64(r['session']) for r in rows],np.int64)[ids]
        arrays['host'][n_old:]=np.asarray([hash64('phone:'+r['watched']) for r in rows],np.int64)[ids]
        arrays['start'][n_old:]=np.asarray([r['start'] for r in rows])[ids];arrays['end'][n_old:]=np.asarray([r['end'] for r in rows])[ids]
        for start in range(0,n,65536):arrays['x'][start:start+65536]=transform(arrays['raw'][start:start+65536])
        manifests[split]={'old_rows':n_old,'unique_new_phone_rows':len(rows),'phone_training_resample_factor':factor,
            'rows':n,'phone_subtypes':dict(Counter(r['subtype'] for r in rows)),'phone_session_ids':sessions[split]}
        capture.lab.save(folder/'manifest.json',manifests[split]);output[split]=arrays
    train=output['train']['x'];total=np.zeros(147,np.float64);squares=np.zeros(147,np.float64)
    for start in range(0,len(train),65536):
        x=np.asarray(train[start:start+65536],np.float64);total+=x.sum(0);squares+=(x*x).sum(0)
    mean=total/len(train);scale=np.sqrt(np.maximum(squares/len(train)-mean*mean,.05**2))
    for split,arrays in output.items():
        for start in range(0,len(arrays['x']),65536):arrays['x'][start:start+65536]=(arrays['x'][start:start+65536]-mean)/scale
        for value in arrays.values():value.flush()
        x,y,rows=phone_only[split]
        phone_folder=CACHE/('phone_'+split);phone_folder.mkdir(parents=True,exist_ok=True)
        np.save(phone_folder/'raw.npy',x);np.save(phone_folder/'y.npy',y)
        (phone_folder/'metadata.json').write_text(json.dumps([{k:v for k,v in r.items() if k!='raw'} for r in rows],indent=2)+'\n',encoding='utf-8')
    group_sets={split:np.unique(arrays['group']) for split,arrays in output.items()}
    for a,b in [('train','validation'),('train','test'),('validation','test')]:
        assert len(np.intersect1d(group_sets[a],group_sets[b]))==0,'Augmented split group overlap'
    capture.lab.save(CACHE/'normalization.json',{'mean':mean.tolist(),'scale':scale.tolist(),'fit':'augmented train only; original validation/test unchanged and never used for fit',
        'transform':'log1p flow[0:32] and context auxiliary[128:146]; other fields unchanged'})
    report={'state':'ready','old_split_membership_preserved':True,'new_session_groups_disjoint':True,'old_diagnostics_and_pilot_excluded':True,
        'phone_training_resample_factor':REPLAY_FACTOR,'resampling_scope':'Exact repetition of real recorded training rows; not synthetic features or independent new sessions.',
        'unique_new_phone_rows':unique_counts,'splits':manifests,'all_combined_group_overlaps_zero':True,'campaign_plan_sha256':capture.sha(capture.PUBLIC/'campaign_plan.json'),
        'scope':'One phone and lab app, chronological sessions/held-out forms; not independent device/day/site generalization.'}
    capture.lab.save(PUBLIC/'data_report.json',report)
    old_config=json.loads((ROOT/'runs/phone_alignment_v2/config.json').read_text(encoding='utf-8'))
    config={k:old_config[k] for k in ['epochs','early_stopping','batch_size','learning_rate','max_benign_fpr','max_source_benign_fpr','min_attack_recall','min_class_attack_recall','min_typed_precision','min_typed_recall']}
    config.update({'version':'real-phone-augmented-v1','jobs':[{'name':f'{kind}_s{seed}','kind':kind,'width':96 if kind=='gate' else 64,'seed':seed} for seed in range(3) for kind in ['gate','diagnosis']],
        'code_sha256':{name:capture.sha(ROOT/name) for name in ['experiments/phone_alignment_v2/train.py','experiments/phone_alignment_v2/models.py']},
        'data_report_sha256':capture.sha(PUBLIC/'data_report.json'),'source_names':['Monday','Tuesday','Wednesday','Thursday','Friday','PARROT','AAGM','PHONE']})
    assert config['epochs']==40 and not config['early_stopping']
    capture.lab.save(TRAIN_RUN/'config.json',config)
    capture.lab.save(CACHE/'ready.json',report)
    return report
