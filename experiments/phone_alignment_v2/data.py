"""Raw-packet extraction uses frozen Kotlin; this module handles labels and splits."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from pathlib import Path
import collections,ipaddress,json,os,shutil,struct,subprocess,sys,time,zipfile
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from experiments.phone_alignment_v2.common import *


def freeze_extractor():
    bootstrap_reference_extractor()
    return RUN/'extractor'


def normalize_ip(value):
    address=ipaddress.ip_address(value)
    return str(address) if address.version==4 else ':'.join(v.lstrip('0') or '0' for v in address.exploded.split(':'))


def labels(source):
    folder=CACHE/'labels';folder.mkdir(parents=True,exist_ok=True);target=folder/(source+'.tsv')
    if target.exists() and target.with_suffix('.json').exists():return target
    from validation.audit_cicids_multiday_alignment import load_day_labels
    with zipfile.ZipFile(ROOT/'data/external/CICIDS2017/GeneratedLabelledFlows.zip') as archive:index,inventory=load_day_labels(archive,source)
    counts=collections.Counter();temporary=target.with_suffix('.partial')
    with temporary.open('w') as stream:
        for (proto,a,b),rows in index.items():
            first=normalize_ip(a[0])+':'+str(a[1]);second=normalize_ip(b[0])+':'+str(b[1])
            key=f'{proto}|{min(first,second)}|{max(first,second)}'
            for starts,duration,label in rows:
                label=' '.join(label.replace('\ufffd','').split());coarse=source_family(label)
                fine=FINE.index(label) if label in FINE else -1
                for lower,precision in starts:stream.write(f'{key}\t{lower:.9f}\t{lower+precision+duration:.9f}\t{coarse}\t{fine}\n')
                counts[label]+=1
    temporary.replace(target);atomic(target.with_suffix('.json'),{'inventory':inventory,'fine_counts':dict(counts),'sha256':sha(target)})
    return target


def extraction_inputs(source):
    from validation.audit_cicids_multiday_alignment import DAYS
    if source in DAYS:
        return str(win(ROOT/'data/external/CICIDS2017'/DAYS[source])),str(win(labels(source))),[ROOT/'data/external/CICIDS2017'/DAYS[source]]
    if source=='PARROT':
        captures=sorted(p for p in (ROOT/'data/external/PARROT2025/pcaps').rglob('*') if p.suffix.lower() in ('.pcap','.pcapng','.cap'))
        from experiments.phone_alignment_v2.capture_audit import audit_controls
        captures=audit_controls(source,captures)
        from reproducibility.dataset_labels import app_package
        tags=['PARROT:app:'+app_package(p.name) for p in captures]
    else:
        captures=sorted(p for p in (ROOT/'data/external/CIC-AAGM2017/Benign Pcaps').rglob('*') if p.suffix.lower() in ('.pcap','.pcapng','.cap'))
        from experiments.phone_alignment_v2.capture_audit import audit_controls
        captures=audit_controls(source,captures)
        tags=['AAGM:capture:'+p.name for p in captures]
    if not captures:raise RuntimeError('Missing Android controls: '+source)
    listing=CACHE/'labels'/(source+'_captures.tsv');listing.parent.mkdir(parents=True,exist_ok=True)
    listing.write_text(''.join(win(p)+'\t'+tag+'\n' for p,tag in zip(captures,tags)))
    return '@'+win(listing),'-',captures


def extract_source(source,limit=0):
    folder=CACHE/'sources';folder.mkdir(parents=True,exist_ok=True);prefix=folder/source
    ready=Path(str(prefix)+'.ready.json')
    if ready.exists() and not limit:
        report=json.loads(ready.read_text());assert report['version']=='phone-aligned-v2' and report['packet_limit']==0
        assert report['extractor_sha256']==json.loads((RUN/'extractor/manifest.json').read_text())['core_sha256']
        for v in report['input_inventory']:
            p=ROOT/v['path'];assert p.stat().st_size==v['bytes'] and p.stat().st_mtime_ns==v['mtime_ns'],'Source capture changed'
        return
    capture,label,files=extraction_inputs(source)
    if limit:prefix=folder/(source+'_preflight')
    command=java_command('nids.core.AlignedExtract',capture,label,win(prefix),source,str(limit))
    with (RUN/(source+('_preflight' if limit else '')+'_extract.log')).open('w') as stream:
        result=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT)
    if result.returncode:raise RuntimeError('Kotlin extraction failed for '+source+'; see source log')
    report=json.loads(Path(str(prefix)+'.ready.json').read_text())
    report['input_inventory']=[{'path':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'mtime_ns':p.stat().st_mtime_ns} for p in files]
    report['extractor_sha256']=json.loads((RUN/'extractor/manifest.json').read_text())['core_sha256']
    atomic(Path(str(prefix)+'.ready.json'),report)
    print('SOURCE_COMPLETE',source,report['records'],report['rows'],report['class_counts'],flush=True)


def binary(path):
    with path.open('rb') as stream:magic,flow,context,n=struct.unpack('>iiiQ',stream.read(20))
    assert magic==0x4e494432 and flow==32 and context==115
    dtype=np.dtype([('group','>i8'),('host','>i8'),('start','>f8'),('end','>f8'),('y','>i4'),('fine','>i4'),('role','>i4'),('raw','>f4',(147,))])
    assert path.stat().st_size==20+n*dtype.itemsize,(path.stat().st_size,n,dtype.itemsize)
    return np.memmap(path,mode='r',offset=20,dtype=dtype,shape=(n,))


def transform(raw):
    output=np.array(raw,np.float32,copy=True)
    assert np.isfinite(output).all() and (output>=0).all()
    output[:,:32]=np.log1p(output[:,:32]);output[:,128:146]=np.log1p(output[:,128:146])
    return output


def consolidate():
    if (CACHE/'ready.json').exists():return
    from sklearn.model_selection import train_test_split
    data=[];inventories=[]
    for source in SOURCES:
        report=json.loads((CACHE/'sources'/(source+'.ready.json')).read_text())
        assert report['packet_limit']==0 and report['rows']>0
        if report['flow_evictions'] or report['forced_reorder']:raise RuntimeError('Source resource degradation must be resolved before training: '+source)
        if report['late']/max(1,report['parsed'])>.001:raise RuntimeError('Excess residual timestamp disorder: '+source)
        data.append(binary(CACHE/'sources'/(source+'.bin')));inventories.append(report)
    groups=np.concatenate([np.asarray(d['group'],np.int64) for d in data]);ys=np.concatenate([np.asarray(d['y'],np.int8) for d in data]);fine=np.concatenate([np.asarray(d['fine'],np.int16) for d in data])
    unique,inv=np.unique(groups,return_inverse=True)
    group_fine=np.full(len(unique),-1,np.int16);np.maximum.at(group_fine,inv,fine)
    group_y=np.zeros(len(unique),np.int8);np.maximum.at(group_y,inv,ys)
    sizes=collections.Counter(group_fine.tolist());strata=np.array([v if sizes[v]>=14 else 100+int(c) for v,c in zip(group_fine,group_y)])
    if min(collections.Counter(strata.tolist()).values())<7:raise RuntimeError('Insufficient independent groups for class-stratified split')
    train,other=train_test_split(np.arange(len(unique)),test_size=.3,random_state=8621,stratify=strata)
    val,test=train_test_split(other,test_size=.5,random_state=8622,stratify=strata[other])
    allocation=np.empty(len(unique),np.int8);allocation[train]=0;allocation[val]=1;allocation[test]=2
    splits=allocation[inv];names=('train','validation','test');counts={name:int((splits==i).sum()) for i,name in enumerate(names)}
    output={};offsets=collections.Counter();class_counts={};fine_counts={};source_counts={}
    for i,name in enumerate(names):
        select=splits==i;class_counts[name]=np.bincount(ys[select],minlength=7).tolist();fine_counts[name]={FINE[j]:int((fine[select]==j).sum()) for j in range(len(FINE))}
        minimum=[10000,200,200,1000,1000,1000,200] if name=='train' else [1000,20,20,100,100,100,20]
        if any(n<bound for n,bound in zip(class_counts[name],minimum)):
            atomic(PUBLIC/'coverage_failure.json',{'class_counts':class_counts,'failed_split':name,'minimum':minimum,'classes':CLASSES});raise RuntimeError('Insufficient class coverage in '+name+'; training refused')
        folder=CACHE/name;folder.mkdir(parents=True,exist_ok=True)
        output[name]={key:np.lib.format.open_memmap(folder/(key+'.npy'),mode='w+',dtype=dtype,shape=(counts[name],*shape)) for key,dtype,shape in
            [('raw','float32',(147,)),('x','float32',(147,)),('y','int64',()),('fine','int16',()),('group','int64',()),('host','int64',()),('source','int8',()),('start','float64',()),('end','float64',())]}
    global_at=0
    for source_id,d in enumerate(data):
        for start in range(0,len(d),32768):
            batch=d[start:start+32768];assignment=splits[global_at+start:global_at+start+len(batch)]
            for i,name in enumerate(names):
                mask=assignment==i;n=int(mask.sum())
                if not n:continue
                at=offsets[name];raw=np.asarray(batch['raw'][mask],np.float32)
                output[name]['raw'][at:at+n]=raw;output[name]['x'][at:at+n]=transform(raw)
                for key in ('y','fine','group','host','start','end'):output[name][key][at:at+n]=batch[key][mask]
                output[name]['source'][at:at+n]=source_id;offsets[name]+=n
        global_at+=len(d)
    train_x=output['train']['x'];sums=np.zeros(147);squares=np.zeros(147)
    for start in range(0,len(train_x),65536):
        x=np.asarray(train_x[start:start+65536],np.float64);sums+=x.sum(0);squares+=(x*x).sum(0)
    mean=sums/len(train_x);scale=np.sqrt(np.maximum(squares/len(train_x)-mean*mean,.05**2))
    normalization={'mean':mean.tolist(),'scale':scale.tolist(),'fit':'train only','transform':'log1p flow[0:32] and auxiliary[128:146], others already log/fraction'}
    for name,arrays in output.items():
        for start in range(0,len(arrays['x']),65536):arrays['x'][start:start+65536]=(arrays['x'][start:start+65536]-mean)/scale
        for a in arrays.values():a.flush()
        source_counts[name]={source:int((arrays['source']==i).sum()) for i,source in enumerate(SOURCES)}
        atomic(CACHE/name/'manifest.json',{'rows':counts[name],'class_counts':class_counts[name],'fine_counts':fine_counts[name],'source_counts':source_counts[name],'groups':int(len(np.unique(arrays['group'])))})
    atomic(CACHE/'normalization.json',normalization)
    report={'state':'ready','rows':counts,'class_counts':class_counts,'fine_counts':fine_counts,'source_counts':source_counts,
        'classes':CLASSES,'feature_dimensions':[32,115],'groups_disjoint':True,'source_reports':inventories,
        'split':'70/15/15 stratified connection groups; Android app/capture groups; seed8621/8622',
        'scope':'Causal unlabeled history crosses row-group partitions; not independent capture generalization. Manual/phone diagnostics excluded from training.'}
    atomic(CACHE/'ready.json',report);atomic(PUBLIC/'data_report.json',report)
    print('DATA_READY',counts,class_counts,flush=True)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--source',choices=SOURCES);parser.add_argument('--limit',type=int,default=0);parser.add_argument('--consolidate',action='store_true')
    args=parser.parse_args()
    if args.source:extract_source(args.source,args.limit)
    elif args.consolidate:consolidate()
