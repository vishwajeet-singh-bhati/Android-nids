"""Resumable detached local comparison; smoke gate precedes full training."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
import torch
from experiments.tsanet_paper.data import atomic, sha, prepare as prepare_baseline
from experiments.tsanet_context.context_features import BASE, CACHE, prepare
from experiments.tsanet_context.experiment import train_stage, evaluate, publish


def fingerprints():
    paths = list(HERE.glob('*.py')) + [HERE / 'PROTOCOL.md']
    paths += [ROOT / 'experiments/tsanet_paper' / name for name in ('data.py', 'model.py')]
    return {str(p.relative_to(ROOT)): sha(p) for p in paths}


def configuration(smoke):
    return {'version': 1, 'smoke': smoke, 'seed': 42, 'learning_rate': .001,
            'batch_size': 64 if smoke else 256,
            'baseline_epochs': 2 if smoke else 10,
            'finetune_epochs': 1 if smoke else 5,
            'pruning_rate': .3, 'early_stopping': False,
            'class_weighting': False, 'decision': 'argmax != Benign',
            'context_dimension': 78, 'windows_seconds': [120, 300, 900],
            'history_bank': 'training rows only; no labels',
            'selection': 'fixed final epochs; no test selection',
            'automatic_install': False}


def main(args):
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / 'controller.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Comparison already running', flush=True)
            return
        (directory / 'controller.pid').write_text(str(os.getpid()))
        code = fingerprints()
        config = configuration(args.smoke)
        if (directory / 'config.json').exists():
            assert json.loads((directory / 'config.json').read_text()) == config
            assert json.loads((directory / 'source_fingerprints.json').read_text()) == code
        else:
            atomic(directory / 'config.json', config)
            atomic(directory / 'source_fingerprints.json', code)
        torch.set_num_threads(2)
        torch.backends.cudnn.benchmark = False
        torch.backends.cudnn.deterministic = True
        torch.set_float32_matmul_precision('highest')
        if args.smoke:
            from experiments.tsanet_context.test_pipeline import run_checks, make_fixture
            run_checks()
            archive = make_fixture(directory)
            base = directory / 'base_cache'
            prepare_baseline(directory, base, seed=42, archive_path=archive)
            cache = directory / 'context_cache'
            report = prepare(directory, base, cache, archive)
            device = 'cpu'
        else:
            smoke = ROOT / 'runs/tsanet_context_smoke/SMOKE_PASS.json'
            assert smoke.exists(), 'Matching end-to-end smoke required'
            assert json.loads(smoke.read_text())['source_fingerprints'] == code
            assert os.environ.get('NIDS_TRAIN_DEVICE','cuda')!='cuda' or torch.cuda.is_available(), 'CUDA required unless NIDS_TRAIN_DEVICE=cpu'
            torch.cuda.set_per_process_memory_fraction(.7) if os.environ.get('NIDS_TRAIN_DEVICE','cuda')=='cuda' else None
            base, cache, device = BASE, CACHE, os.environ.get('NIDS_TRAIN_DEVICE','cuda')
            report = prepare(directory, base, cache)
        import pandas, sklearn, numba
        atomic(directory / 'environment.json', {
            'python': platform.python_version(), 'torch': torch.__version__,
            'numpy': np.__version__, 'pandas': pandas.__version__,
            'sklearn': sklearn.__version__, 'numba': numba.__version__,
            'cuda': torch.version.cuda,
            'gpu': torch.cuda.get_device_name(0) if device == 'cuda' else None,
        })
        atomic(directory / 'data_report.json', report)
        x = torch.tensor(np.load(base / 'train_x.npy'), device=device)
        y = torch.tensor(np.load(base / 'train_y.npy'), device=device, dtype=torch.long)
        context = torch.tensor(np.load(cache / 'train_x.npy'), device=device)
        for arm, enabled in (('control', False), ('context', True)):
            name = arm + '_baseline'
            train_stage(directory, name, enabled, config['baseline_epochs'], x, context, y, device)
            train_stage(directory, arm + '_pruned_30', enabled, config['finetune_epochs'],
                        x, context, y, device, initial=directory / name / 'final.pt')
        del x, context, y
        if device == 'cuda':
            torch.cuda.empty_cache()
        assert fingerprints() == code, 'Source changed during run'
        atomic(directory / 'status.json', {'state': 'frozen_evaluation',
            'updated_unix': time.time(), 'pid': os.getpid()})
        comparison = evaluate(directory, base, cache, device)
        publish(directory, comparison, report)
        if args.smoke:
            atomic(directory / 'SMOKE_PASS.json', {'source_fingerprints': code,
                'scope': 'Synthetic pipeline validation only; not detection performance',
                'completed_unix': time.time()})
        atomic(directory / 'status.json', {'state': 'complete', 'updated_unix': time.time(),
            'pid': os.getpid(), 'production_ready': False,
            'report': str(directory / 'COMPARISON.md')})
        print('CONTEXT_COMPARISON_COMPLETE', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', default=str(ROOT / 'runs/tsanet_context_v1'))
    parser.add_argument('--smoke', action='store_true')
    args = parser.parse_args()
    try:
        main(args)
    except Exception as error:
        directory = Path(args.directory)
        atomic(directory / 'error.json', {'error': str(error), 'traceback': traceback.format_exc()})
        atomic(directory / 'status.json', {'state': 'failed', 'error': str(error),
            'updated_unix': time.time(), 'pid': os.getpid()})
        traceback.print_exc()
        sys.exit(1)
