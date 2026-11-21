"""Independent repair workspace; frozen v2 inputs/models are read-only."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import hashlib,json,os,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
RUN=Path(os.environ.get('NIDS_REPAIR_RUN',ROOT/'runs/phone_repair_v3'))
CACHE=Path(os.environ.get('NIDS_REPAIR_CACHE',ROOT/'data/experiments/phone_alignment_v2'))
PUBLIC=Path(os.environ.get('NIDS_REPAIR_PUBLIC',ROOT/'validation/reports/phone_repair_v3'))
BASE=Path(os.environ.get('NIDS_REPAIR_BASE',ROOT/'runs/phone_alignment_v2'))
CLASSES=('Benign','Bot','Brute Force','DDoS','DoS','Port Scan','Web Attack')
FINE=('BENIGN','Bot','FTP-Patator','SSH-Patator','DDoS','DoS GoldenEye','DoS Hulk','DoS Slowhttptest','DoS slowloris','PortScan','Web Attack Brute Force','Web Attack XSS','Web Attack Sql Injection')
SOURCES=('Monday','Tuesday','Wednesday','Thursday','Friday','PARROT','AAGM')


def atomic(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n');tmp.replace(path)


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1<<20),b''):h.update(block)
    return h.hexdigest()


def configuration(epochs=40,seeds=range(3)):
    jobs=[]
    for seed in seeds:
        for arm in ('unweighted','moderate','hard_benign'):
            for kind,width in (('gate',96),('diagnosis',64)):
                jobs.append({'name':f'{arm}_{kind}_s{seed}','kind':kind,'width':width,'seed':seed,'arm':arm})
    return {'version':'phone-repair-v3','epochs':epochs,'early_stopping':False,'batch_size':512,'learning_rate':.001,
        'max_parallel_training':2,'weight_cap_relative_to_benign':3.,'hard_benign_fraction':.1,
        'max_benign_fpr':.001,'max_source_benign_fpr':.005,'min_attack_recall':.95,'min_class_attack_recall':.85,
        'min_typed_precision':.85,'min_typed_recall':.8,'type_score_cutoff':.6,'max_routing_fraction':.25,
        'shortlist_per_metric':2,'joint_high_quantiles':[.999,.9995,.9999],
        'review_accept_thresholds':[.5,.9,.99],'type_thresholds':[.5,.6,.8],
        'improvement':{'min_macro_f1_gain':.005,'min_bot_precision_gain':.05,'max_binary_recall_loss':.001,
            'max_class_binary_recall_loss':.01,'max_typed_recall_loss':.02,'max_typed_precision_loss':.01,'max_fpr_increase':0.},
        'jobs':jobs}
