"""Local detached paper-baseline reconstruction with frozen user split."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import argparse,fcntl,json,os,sys,time,traceback
from pathlib import Path
import numpy as np
import torch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(HERE))
from data import CACHE,FEATURES,atomic,sha,prepare,load_split
from experiment import stage,evaluate

MISSING=['Original 32-feature names and order','Author split ratio, seed and indices (user now specifies 70/30)',
         'Cleaning/scaling/duplicate policy','Convolution kernel, activations and attention normalizations',
         'Final Dense width and ambiguous diagram wiring','Precise pruning/mask policy and optimizer continuation',
         'Limited Android feature list, imputation/interpolation and fine-tuning data','Metric averaging and timing hardware']

def configuration(smoke=False):
    return {'scope':'paper-based reconstruction; not exact author reproduction','smoke':smoke,
        'seed':42,'train_fraction':.7,'test_fraction':.3,'stratified':True,
        'baseline_epochs':2 if smoke else 10,'finetune_epochs':1 if smoke else 5,
        'pruning_rates':[.3,.4],'learning_rate':.001,'batch_size':64 if smoke else 256,
        'optimizer':'Adam, default betas/epsilon, zero weight decay; reset for each pruning branch',
        'kernel_size':3,'dense_width':64,'features':list(FEATURES),'paper_missing_details':MISSING,
        'early_stopping':False,'checkpoint_policy':'save every epoch, best training loss and fixed final epoch',
        'paper_sha256':'d2163f2ce6cacf4d6f5df331e6dbae797cfe12d5330ae31345e1610ca005cadd',
        'paper_doi':'10.1109/ISED67359.2025.11404952','automatic_install':False}

def main(args):
    directory=Path(args.directory);directory.mkdir(parents=True,exist_ok=True)
    config=configuration(args.smoke)
    fingerprints={p.name:sha(p) for p in HERE.glob('*.py')}
    if not (directory/'config.json').exists():
        atomic(directory/'config.json',config);atomic(directory/'source_fingerprints.json',fingerprints)
    else:
        assert json.loads((directory/'config.json').read_text())==config,'Config changed; use a separate run'
        assert json.loads((directory/'source_fingerprints.json').read_text())==fingerprints,'Source changed; use a separate run'
    with (directory/'controller.lock').open('w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('This paper experiment is already running')
        torch.set_num_threads(2);torch.manual_seed(config['seed'])
        if args.smoke:
            from test_pipeline import run_checks,make_fixture
            run_checks();archive=make_fixture(directory);cache=directory/'synthetic_cache'
            prepare(directory,cache,config['seed'],archive)
            device='cpu'
        else:
            smoke=ROOT/'runs/tsanet_paper_smoke/SMOKE_PASS.json'
            if not smoke.exists() or json.loads(smoke.read_text())['source_fingerprints']!=fingerprints:
                raise RuntimeError('Matching final-code smoke is required before full training')
            cache=CACHE;prepare(directory,cache,config['seed']);device=os.environ.get('NIDS_TRAIN_DEVICE','cuda')
            if device=='cuda' and not torch.cuda.is_available():raise RuntimeError('CUDA unavailable; refusing unexpected slow full training')
            torch.cuda.set_per_process_memory_fraction(.7) if device=='cuda' else None
        torch.backends.cudnn.benchmark=False;torch.backends.cudnn.deterministic=True
        torch.set_float32_matmul_precision('highest')
        x,y=load_split('train',cache)
        # The 70% training data fit comfortably on this GPU; test is not loaded here.
        train_x=torch.tensor(np.array(x,copy=True),device=device)
        train_y=torch.tensor(np.array(y,copy=True),device=device,dtype=torch.long)
        stage(directory,cache,'baseline',config['baseline_epochs'],device,train_x,train_y)
        for rate in config['pruning_rates']:
            stage(directory,cache,f'pruned_{int(rate*100)}',config['finetune_epochs'],device,train_x,train_y,
                  initial=directory/'baseline/final.pt',rate=rate)
        del train_x,train_y
        if device=='cuda':torch.cuda.empty_cache()
        atomic(directory/'status.json',{'state':'frozen_evaluation','updated_unix':time.time(),'pid':os.getpid()})
        evaluate(directory,cache,device)
        if args.smoke:
            atomic(directory/'SMOKE_PASS.json',{'source_fingerprints':fingerprints,'config_sha256':sha(directory/'config.json'),
                   'scope':'Synthetic automation, not measured detection performance','completed_unix':time.time()})
        atomic(directory/'status.json',{'state':'complete','updated_unix':time.time(),'pid':os.getpid(),
               'report':str(directory/'COMPARISON.md'),'production_ready':False})
        print('TSANET_COMPARISON_COMPLETE',directory,flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--directory',default=str(ROOT/'runs/tsanet_paper_70_30'))
    parser.add_argument('--smoke',action='store_true');args=parser.parse_args()
    try:main(args)
    except Exception as exc:
        directory=Path(args.directory);atomic(directory/'error.json',{'error':str(exc),'traceback':traceback.format_exc(),'updated_unix':time.time()})
        atomic(directory/'status.json',{'state':'failed','error':str(exc),'updated_unix':time.time(),'pid':os.getpid()})
        traceback.print_exc();sys.exit(1)
