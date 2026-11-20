"""Publisher flow features, user-authorized stratified 70/30 split, train-only scaling."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from collections import Counter
from pathlib import Path
import hashlib,json,os,time,zipfile
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

ROOT=Path(__file__).resolve().parents[2]
CACHE=ROOT/'data/experiments/tsanet_paper_70_30'
CLASSES=('Benign','Bot','Brute Force','DDoS','DoS','Port Scan','Web Attack')
FEATURES=(
    'Flow Duration','Total Fwd Packets','Total Backward Packets',
    'Total Length of Fwd Packets','Total Length of Bwd Packets',
    'Fwd Packet Length Max','Fwd Packet Length Min','Fwd Packet Length Mean','Fwd Packet Length Std',
    'Bwd Packet Length Max','Bwd Packet Length Min','Bwd Packet Length Mean','Bwd Packet Length Std',
    'Flow Bytes/s','Flow Packets/s','Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min',
    'Fwd IAT Total','Fwd IAT Mean','Fwd IAT Std','Fwd IAT Max','Fwd IAT Min',
    'Bwd IAT Total','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Max','Bwd IAT Min',
    'SYN Flag Count','RST Flag Count','ACK Flag Count')
assert len(FEATURES)==32

def atomic(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+f'.{os.getpid()}.tmp')
    tmp.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n');tmp.replace(path)

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for b in iter(lambda:stream.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def family(label):
    if label=='BENIGN':return 0
    if label=='Bot':return 1
    if label in ('FTP-Patator','SSH-Patator'):return 2
    if label=='DDoS':return 3
    if label.startswith('DoS '):return 4
    if label=='PortScan':return 5
    if label.startswith('Web Attack'):return 6
    return -1

def prepare(directory,cache=CACHE,seed=42,archive_path=None):
    directory=Path(directory);cache.mkdir(parents=True,exist_ok=True)
    contract={'features':list(FEATURES),'classes':list(CLASSES),'seed':seed,'test_fraction':.3,
              'cleaning':'drop nonfinite selected numeric rows; exclude Heartbleed/Infiltration outside paper classes; keep duplicates',
              'normalization':'StandardScaler fit on training rows only',
              'reproduction_scope':'Documented architecture/feature reconstruction; authors feature list and split indices unavailable'}
    if (cache/'ready.json').exists():
        assert json.loads((cache/'contract.json').read_text())==contract,'Cache contract changed; use another cache'
        ready=json.loads((cache/'ready.json').read_text());atomic(directory/'data_report.json',ready)
        return ready
    atomic(cache/'contract.json',contract)
    parts=[];targets=[];identities=[];raw=Counter();dropped=Counter();excluded=Counter();source=[]
    official_source=archive_path is None
    archive_path=Path(archive_path) if archive_path else ROOT/'data/external/CICIDS2017/GeneratedLabelledFlows.zip'
    blank=0
    began=time.time()
    with zipfile.ZipFile(archive_path) as archive:
        for source_index,member in enumerate(sorted(n for n in archive.namelist() if n.lower().endswith('.csv'))):
            before=len(parts);offset=0;rows=0
            with archive.open(member) as stream:
                reader=pd.read_csv(stream,usecols=lambda s:s.strip() in (*FEATURES,'Label'),chunksize=100000,
                                   encoding='utf-8-sig',encoding_errors='replace',low_memory=False)
                for chunk in reader:
                    chunk.columns=chunk.columns.str.strip()
                    if set(FEATURES)-set(chunk.columns):raise RuntimeError('Missing selected features: '+member)
                    labels=chunk['Label'].astype('string').fillna('').str.replace('\ufffd','',regex=False).str.split().str.join(' ')
                    empty=chunk.isna().all(axis=1);blank+=int(empty.sum())
                    raw.update(labels[labels!=''].tolist());mapped=labels.map(family).to_numpy(np.int64)
                    for label in labels[(mapped<0)&(~empty)]:excluded[str(label) or 'missing_label']+=1
                    numeric=chunk[list(FEATURES)].apply(pd.to_numeric,errors='coerce')
                    with np.errstate(over='ignore',invalid='ignore'):x=numeric.to_numpy(np.float32)
                    finite=np.isfinite(x).all(axis=1);valid=(mapped>=0)&finite
                    for c in mapped[(mapped>=0)&(~finite)]:dropped[CLASSES[int(c)]]+=1
                    row_id=(np.uint64(source_index)<<np.uint64(32))+np.arange(offset,offset+len(chunk),dtype=np.uint64)
                    parts.append(x[valid]);targets.append(mapped[valid]);identities.append(row_id[valid])
                    offset+=len(chunk);rows+=len(chunk)
                    atomic(directory/'status.json',{'state':'preparing_data','member':member,'member_rows':rows,
                           'raw_labeled_rows':sum(raw.values()),'elapsed_seconds':time.time()-began,'updated_unix':time.time()})
            source.append({'member':member,'raw_rows':rows,'retained_rows':sum(len(v) for v in parts[before:])})
            print('CSV_READY',source[-1],flush=True)
    if official_source:
        inventory=json.loads((ROOT/'validation/reports/cicids2017_multiday_alignment.json').read_text())
        expected=Counter()
        for day in inventory['days'].values():
            for label,n in day['label_inventory']['labels'].items():expected[' '.join(label.replace('\ufffd','').split())]+=n
        if raw!=expected:raise RuntimeError('Raw CSV label counts do not match the verified inventory')
    x=np.concatenate(parts);y=np.concatenate(targets);row_id=np.concatenate(identities)
    del parts,targets,identities
    assert x.shape==(len(y),32) and np.isfinite(x).all()
    train,test=train_test_split(np.arange(len(y)),test_size=.3,random_state=seed,stratify=y)
    assert np.intersect1d(row_id[train],row_id[test]).size==0
    scaler=StandardScaler();scaler.fit(x[train])
    mean=scaler.mean_.astype(np.float32);scale=scaler.scale_.astype(np.float32)
    np.save(cache/'train_indices.npy',train);np.save(cache/'test_indices.npy',test)
    for split,ids in [('train',train),('test',test)]:
        np.save(cache/(split+'_raw.npy'),x[ids],allow_pickle=False)
        normalized=((x[ids]-mean)/scale).astype(np.float32)
        assert np.isfinite(normalized).all()
        np.save(cache/(split+'_x.npy'),normalized,allow_pickle=False)
        np.save(cache/(split+'_y.npy'),y[ids],allow_pickle=False)
        np.save(cache/(split+'_row_id.npy'),row_id[ids],allow_pickle=False)
        counts=np.bincount(y[ids],minlength=7)
        if np.any(counts<10):raise RuntimeError(f'Insufficient class coverage in {split}: {counts}')
    # Descriptive overlap audit of the authorized random-row benchmark, not a tuning step.
    hashes=pd.util.hash_pandas_object(pd.DataFrame(x),index=False).to_numpy(np.uint64)
    shared=np.intersect1d(np.unique(hashes[train]),np.unique(hashes[test]))
    overlap_rows=int(np.isin(hashes[test],shared).sum())
    normalization={'mean':mean.tolist(),'scale':scale.tolist(),'fit':'training only'}
    atomic(cache/'normalization.json',normalization)
    ready={'contract':contract,'archive_sha256':sha(archive_path),'source_members':source,
        'raw_label_counts':dict(raw),'blank_rows_ignored':blank,'excluded_classes':dict(excluded),'nonfinite_rows_dropped':dict(dropped),
        'retained_rows':len(y),'train_rows':len(train),'test_rows':len(test),
        'train_class_counts':{c:int((y[train]==i).sum()) for i,c in enumerate(CLASSES)},
        'test_class_counts':{c:int((y[test]==i).sum()) for i,c in enumerate(CLASSES)},
        'train_indices_sha256':sha(cache/'train_indices.npy'),'test_indices_sha256':sha(cache/'test_indices.npy'),
        'exact_feature_overlap_test_rows':overlap_rows,'exact_feature_overlap_test_fraction':overlap_rows/len(test),
        'duplicate_policy':'kept; overlap reported to contextualize random-row benchmark',
        'elapsed_seconds':time.time()-began,'normalization_sha256':sha(cache/'normalization.json')}
    atomic(cache/'ready.json',ready);atomic(directory/'data_report.json',ready)
    print('DATA_READY',len(train),len(test),ready['train_class_counts'],flush=True)
    return ready

def load_split(split,cache=CACHE):
    return (np.load(cache/(split+'_x.npy'),mmap_mode='r',allow_pickle=False),
            np.load(cache/(split+'_y.npy'),mmap_mode='r',allow_pickle=False))
