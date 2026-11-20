
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from pathlib import Path
import hashlib,json,os,sys,time

ROOT=Path(__file__).resolve().parents[2]
RUN=Path(os.environ.get('NIDS_ALIGNED_RUN',str(ROOT/'runs/phone_alignment_v2')))
CACHE=Path(os.environ.get('NIDS_ALIGNED_CACHE',str(ROOT/'data/experiments/phone_alignment_v2')))
PUBLIC=Path(os.environ.get('NIDS_ALIGNED_PUBLIC',str(ROOT/'validation/reports/phone_alignment_v2')))
CLASSES=('Benign','Bot','Brute Force','DDoS','DoS','Port Scan','Web Attack')
FINE=('BENIGN','Bot','FTP-Patator','SSH-Patator','DDoS','DoS GoldenEye','DoS Hulk','DoS Slowhttptest','DoS slowloris','PortScan','Web Attack Brute Force','Web Attack XSS','Web Attack Sql Injection')
SOURCES=('Monday','Tuesday','Wednesday','Thursday','Friday','PARROT','AAGM')
JAVA=Path(java_path())


def atomic(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);temp=path.with_suffix(path.suffix+'.tmp')
    temp.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n');temp.replace(path)


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda:stream.read(1<<20),b''):h.update(data)
    return h.hexdigest()


def win(path):
    return runtime_path(path)


def java_command(main,*args,heap='18g'):
    manifest=json.loads((RUN/'extractor/manifest.json').read_text())
    core=RUN/'extractor/core.jar';runtime=RUN/'extractor/kotlin-stdlib.jar'
    assert sha(core)==manifest['core_sha256'] and sha(runtime)==manifest['runtime_sha256']
    return [str(JAVA),'-Xmx'+heap,'-cp',classpath([core,runtime]),main,*map(str,args)]


def source_family(label):
    label=' '.join(label.replace('\ufffd','').split())
    if label=='BENIGN':return 0
    if label=='Bot':return 1
    if label in ('FTP-Patator','SSH-Patator'):return 2
    if label=='DDoS':return 3
    if label.startswith('DoS '):return 4
    if label=='PortScan':return 5
    if label.startswith('Web Attack'):return 6
    return -1
