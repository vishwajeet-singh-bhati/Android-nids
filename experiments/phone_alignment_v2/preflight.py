"""Contract/label/container and synthetic automation checks; never sends packets."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from pathlib import Path
import json,os,struct,subprocess,sys,time
import numpy as np

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_alignment_v2.common import *
from experiments.phone_alignment_v2.data import binary,freeze_extractor,transform


def configuration(epochs=40):
    jobs=[]
    for seed in range(3):
        jobs.extend([{'name':f'gate_s{seed}','kind':'gate','width':96,'seed':seed},
                     {'name':f'diagnosis64_s{seed}','kind':'diagnosis','width':64,'seed':seed}])
    jobs.extend([{'name':'aligned32_s0','kind':'diagnosis','width':32,'seed':0,'reference':True},
                 {'name':'wire_only32_s0','kind':'diagnosis','width':32,'seed':0,'wire_only':True,'reference':True,'selection_eligible':False}])
    return {'version':'phone-aligned-v2','epochs':epochs,'early_stopping':False,'batch_size':512,'learning_rate':.001,
        'max_parallel_training':2,'max_benign_fpr':.001,'max_source_benign_fpr':.005,'min_attack_recall':.95,
        'min_class_attack_recall':.85,'min_typed_precision':.85,'min_typed_recall':.8,'type_score_cutoff':.6,'jobs':jobs}


def extraction_checks():
    freeze_extractor();folder=RUN/'preflight';folder.mkdir(exist_ok=True)
    result=subprocess.run(java_command('nids.core.AlignedCheck',heap='2g'),capture_output=True,text=True,check=True)
    assert json.loads(result.stdout)['passed']
    capture=folder/'labels_fixture.pcap';labels=folder/'labels_fixture.tsv'
    data=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,768,1);lines=[]
    def packet(ts,source,dest,sport,dport,flags):
        src=bytes(map(int,source.split('.')));dst=bytes(map(int,dest.split('.')))
        ip=bytearray(20);ip[0]=0x45;ip[2:4]=struct.pack('!H',40);ip[8]=64;ip[9]=6;ip[12:16]=src;ip[16:20]=dst
        tcp=bytearray(20);tcp[:4]=struct.pack('!HH',sport,dport);tcp[12]=0x50;tcp[13]=flags
        frame=bytes(12)+b'\x08\x00'+ip+tcp;sec=int(ts);fraction=round((ts-sec)*1e6)
        return struct.pack('<IIII',sec,fraction,len(frame),len(frame))+frame
    for cls in range(7):
        for j in range(5):
            port=40000+cls*10+j;ts=1000+cls*10+j;source='10.0.0.1';dest='10.0.0.2'
            data+=packet(ts,source,dest,port,80,2)+packet(ts+.01,dest,source,80,port,20)
            a,b=sorted((f'{source}:{port}',f'{dest}:80'));lines.append(f'6|{a}|{b}\t{ts-1}\t{ts+1}\t{cls}\t{cls}\n')
    # Two conflicting class intervals must be excluded, never coerced to benign.
    data+=packet(1100,'10.0.0.1','10.0.0.2',49000,80,2)+packet(1100.01,'10.0.0.2','10.0.0.1',80,49000,20)
    for c in (0,5):lines.append(f'6|10.0.0.1:49000|10.0.0.2:80\t1099\t1101\t{c}\t{c}\n')
    capture.write_bytes(data);labels.write_text(''.join(lines));prefix=folder/'labels_result'
    r=subprocess.run(java_command('nids.core.AlignedExtract',win(capture),win(labels),win(prefix),'fixture'),capture_output=True,text=True,check=True)
    result=json.loads(Path(str(prefix)+'.ready.json').read_text());assert result['class_counts']==[10]*7,result
    assert result['unknown_views_excluded']==2 and len(binary(Path(str(prefix)+'.bin')))==70
    # Real PCAPNG container, unlabeled and bounded; these rows never enter training.
    raw=ROOT/'data/external/CICIDS2017/Monday-WorkingHours.pcap';prefix=folder/'container_result'
    subprocess.run(java_command('nids.core.AlignedExtract',win(raw),'-',win(prefix),'container_fixture','5000'),capture_output=True,text=True,check=True)
    container=json.loads(Path(str(prefix)+'.ready.json').read_text());assert container['records']==5000 and container['parsed']>0
    atomic(PUBLIC/'extraction_preflight.json',{'passed':True,'label_counts':result['class_counts'],'conflicts_excluded':2,
        'real_pcapng_records':5000,'real_parsed_packets':container['parsed'],'new_attacks_sent':0})
    print('EXTRACTION_PREFLIGHT_PASS',flush=True)


def automation_smoke():
    folder=RUN/'automation_smoke';cache=folder/'cache';out=folder/'reports';folder.mkdir(exist_ok=True)
    rng=np.random.default_rng(961);allraw={};ally={}
    for name,n in [('train',560),('validation',140),('test',140)]:
        y=np.arange(n)%7;raw=rng.uniform(0,.5,(n,147)).astype(np.float32);raw[np.arange(n),y]+=10
        allraw[name]=raw;ally[name]=y
    train=transform(allraw['train']);mean=train.mean(0);scale=np.maximum(train.std(0),.05)
    atomic(cache/'normalization.json',{'mean':mean.tolist(),'scale':scale.tolist(),'fit':'synthetic train only'})
    for si,name in enumerate(('train','validation','test')):
        target=cache/name;target.mkdir(parents=True,exist_ok=True);y=ally[name];raw=allraw[name];n=len(y)
        for key,value in {'raw':raw,'x':((transform(raw)-mean)/scale).astype(np.float32),'y':y.astype(np.int64),'fine':y.astype(np.int16),
            'source':np.zeros(n,np.int8),'group':np.arange(n,dtype=np.int64)+si*10000,'host':np.arange(n,dtype=np.int64),
            'start':np.arange(n,dtype=np.float64),'end':np.arange(n,dtype=np.float64)+.01}.items():np.save(target/(key+'.npy'),value)
    cfg=configuration(2);cfg['batch_size']=64;cfg['jobs']=[{'name':'gate_smoke','kind':'gate','width':96,'seed':0},
        {'name':'diagnosis_smoke','kind':'diagnosis','width':32,'seed':0}]
    atomic(folder/'config.json',cfg)
    env=dict(os.environ,NIDS_ALIGNED_RUN=str(folder),NIDS_ALIGNED_CACHE=str(cache),NIDS_ALIGNED_PUBLIC=str(out))
    for job in cfg['jobs']:
        with (folder/(job['name']+'.log')).open('w') as log:
            subprocess.run([sys.executable,str(ROOT/'experiments/phone_alignment_v2/train.py'),'--job',job['name']],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        assert len(list((folder/'jobs'/job['name']).glob('epoch_*.pt')))==2
    with (folder/'evaluate.log').open('w') as log:subprocess.run([sys.executable,str(ROOT/'experiments/phone_alignment_v2/evaluate.py')],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    assert (out/'evaluation.json').exists() and (out/'export_manifest.json').exists()
    with (folder/'mobile_export.log').open('w') as log:subprocess.run([os.environ.get('NIDS_EXPORT_PYTHON',sys.executable),str(ROOT/'experiments/phone_alignment_v2/export_mobile.py')],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    assert (out/'mobile_export.json').exists()
    atomic(PUBLIC/'automation_smoke.json',{'passed':True,'scope':'synthetic automation only; not real detection metrics','epochs_per_smoke_job':2,'every_epoch_retained':True,'evaluation_and_torchscript_export':True,'executorch_export_passed':True,'new_attacks_sent':0})
    print('AUTOMATION_SMOKE_PASS',flush=True)


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--smoke-only',action='store_true');args=p.parse_args()
    try:
        if args.smoke_only:automation_smoke()
        else:extraction_checks()
    except BaseException as error:
        atomic(PUBLIC/('automation_smoke.json' if args.smoke_only else 'extraction_preflight.json'),{'passed':False,'phase':'failed','error':str(error),'new_attacks_sent':0});raise
