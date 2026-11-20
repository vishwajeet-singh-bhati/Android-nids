"""Fixed-budget matched comparison, retaining every epoch and frozen result."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from pathlib import Path
import hashlib
import json
import math
import os
import time

import numpy as np
import torch
from torch import nn
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    average_precision_score, roc_auc_score,
)

from experiments.tsanet_paper.data import atomic, sha, CLASSES
from experiments.tsanet_paper.model import magnitude_masks, apply_masks
from experiments.tsanet_context.context_model import ContextTSANet, RawContextWrapper


def save(path, value):
    temporary = path.with_name(path.name + '.tmp')
    torch.save(value, temporary)
    temporary.replace(path)


def load_model(path, device):
    checkpoint = torch.load(path, map_location='cpu', weights_only=True)
    model = ContextTSANet(checkpoint['enabled']).to(device)
    model.load_state_dict(checkpoint['model'])
    return model, checkpoint


def weight_digest(model):
    digest = hashlib.sha256()
    for name, value in model.state_dict().items():
        digest.update(name.encode())
        digest.update(value.detach().cpu().numpy().tobytes())
    return digest.hexdigest()


def train_stage(directory, name, enabled, epochs, x, context, y, device, initial=None):
    config = json.loads((directory / 'config.json').read_text())
    folder = directory / name
    folder.mkdir(exist_ok=True)
    if (folder / 'complete.json').exists():
        done = json.loads((folder / 'complete.json').read_text())
        assert sha(folder / 'final.pt') == done['checkpoint_sha256']
        return
    torch.manual_seed(config['seed'])
    if initial:
        model, _ = load_model(initial, device)
    else:
        model = ContextTSANet(enabled).to(device)
    initial_hash = weight_digest(model)
    rate = .3 if initial else 0.
    masks = magnitude_masks(model, rate) if rate else {}
    apply_masks(model, masks)
    optimizer = torch.optim.Adam(model.parameters(), lr=config['learning_rate'])
    history, first, best = [], 1, float('inf')
    if (folder / 'last.pt').exists():
        checkpoint = torch.load(folder / 'last.pt', map_location=device, weights_only=True)
        assert checkpoint['config_sha256'] == sha(directory / 'config.json')
        assert checkpoint['stage'] == name and checkpoint['enabled'] == enabled
        model.load_state_dict(checkpoint['model'])
        optimizer.load_state_dict(checkpoint['optimizer'])
        masks = {k: v.to(device) for k, v in checkpoint['masks'].items()}
        history = checkpoint['history']
        first = checkpoint['epoch'] + 1
        best = checkpoint['best_loss']
        initial_hash = checkpoint['initial_weights_sha256']
        torch.set_rng_state(checkpoint['torch_rng'].cpu())
        if device == 'cuda':
            torch.cuda.set_rng_state_all([v.cpu() for v in checkpoint['cuda_rng']])
    n, batch = len(y), config['batch_size']
    for epoch in range(first, epochs + 1):
        began = time.monotonic()
        model.train()
        generator = torch.Generator(device=device).manual_seed(
            config['seed'] + epoch + (100000 if rate else 0)
        )
        order = torch.randperm(n, device=device, generator=generator)
        total_loss = torch.zeros((), device=device)
        correct = torch.zeros((), device=device, dtype=torch.int64)
        for step, start in enumerate(range(0, n, batch)):
            ids = order[start:start + batch]
            optimizer.zero_grad(set_to_none=True)
            logits = model(x[ids], context[ids])
            loss = nn.functional.cross_entropy(logits, y[ids])
            if not torch.isfinite(loss):
                raise RuntimeError('Nonfinite loss')
            loss.backward()
            apply_masks(model, masks, gradients=True)
            optimizer.step()
            apply_masks(model, masks)
            total_loss += loss.detach() * len(ids)
            correct += (logits.detach().argmax(-1) == y[ids]).sum()
            if step % 200 == 0:
                atomic(directory / 'status.json', {
                    'state': 'training', 'stage': name, 'epoch': epoch,
                    'epochs': epochs, 'step': step, 'steps': math.ceil(n / batch),
                    'epoch_seconds': time.monotonic() - began,
                    'updated_unix': time.time(), 'pid': os.getpid(),
                    'early_stopping': False,
                })
        average = float(total_loss) / n
        history.append({'epoch': epoch, 'loss': average,
                        'online_training_accuracy': float(correct) / n,
                        'seconds': time.monotonic() - began})
        improved = average < best
        best = min(best, average)
        checkpoint = {
            'stage': name, 'enabled': enabled, 'epoch': epoch,
            'model': model.state_dict(), 'optimizer': optimizer.state_dict(),
            'masks': {k: v.cpu() for k, v in masks.items()},
            'history': history, 'best_loss': best,
            'config_sha256': sha(directory / 'config.json'),
            'initial_weights_sha256': initial_hash,
            'torch_rng': torch.get_rng_state(),
            'cuda_rng': torch.cuda.get_rng_state_all() if device == 'cuda' else [],
            'pruning_rate': rate,
            'parameters': sum(p.numel() for p in model.parameters()),
        }
        save(folder / f'epoch_{epoch:02d}.pt', checkpoint)
        save(folder / 'last.pt', checkpoint)
        if improved:
            save(folder / 'best_training_loss.pt', checkpoint)
        atomic(folder / 'history.json', history)
        print('EPOCH', name, history[-1], flush=True)
    save(folder / 'final.pt', torch.load(folder / 'last.pt', map_location='cpu', weights_only=True))
    atomic(folder / 'complete.json', {
        'checkpoint_sha256': sha(folder / 'final.pt'), 'epochs': epochs,
        'parameters': sum(p.numel() for p in model.parameters()),
        'initial_weights_sha256': initial_hash,
        'masked_matrix_weights': sum(int((m == 0).sum()) for m in masks.values()),
        'matrix_weights': sum(p.numel() for p in model.parameters() if p.ndim >= 2),
    })


def predict(model, x, context, device):
    model.eval()
    output = []
    with torch.inference_mode():
        for start in range(0, len(x), 2048):
            flow = torch.tensor(np.array(x[start:start + 2048], copy=True), device=device)
            ctx = torch.tensor(np.array(context[start:start + 2048], copy=True), device=device)
            output.append(torch.softmax(model(flow, ctx), -1).cpu().numpy())
    return np.concatenate(output)


def metrics(y, probabilities):
    predictions = probabilities.argmax(-1)
    attack, flag = y != 0, predictions != 0
    report = classification_report(y, predictions, labels=list(range(7)),
        target_names=list(CLASSES), output_dict=True, zero_division=0)
    return {
        'rows': len(y), 'accuracy': float(accuracy_score(y, predictions)),
        'macro_f1': report['macro avg']['f1-score'],
        'weighted_f1': report['weighted avg']['f1-score'],
        'classification_report': report,
        'confusion_matrix': confusion_matrix(y, predictions, labels=list(range(7))).tolist(),
        'binary_confusion': confusion_matrix(attack, flag, labels=[False, True]).tolist(),
        'binary_attack_recall': float(flag[attack].mean()),
        'benign_false_positive_rate': float(flag[~attack].mean()),
        'binary_roc_auc': float(roc_auc_score(attack, 1 - probabilities[:, 0])),
        'binary_average_precision': float(average_precision_score(attack, 1 - probabilities[:, 0])),
    }


def evaluate(directory, base, cache, device):
    config = json.loads((directory / 'config.json').read_text())
    names = ['control_baseline', 'control_pruned_30', 'context_baseline', 'context_pruned_30']
    frozen_path = directory / 'frozen_comparison.json'
    frozen = {
        'config_sha256': sha(directory / 'config.json'),
        'context_ready_sha256': sha(cache / 'ready.json'),
        'baseline_ready_sha256': sha(base / 'ready.json'),
        'checkpoints': {name: sha(directory / name / 'final.pt') for name in names},
        'policy': 'All four fixed final checkpoints frozen before test scoring; no test tuning',
    }
    if frozen_path.exists():
        assert json.loads(frozen_path.read_text()) == frozen
    else:
        atomic(frozen_path, frozen)
    for phase in ('baseline', 'pruned_30'):
        a = json.loads((directory / ('control_' + phase) / 'complete.json').read_text())
        b = json.loads((directory / ('context_' + phase) / 'complete.json').read_text())
        if phase == 'baseline':
            assert a['initial_weights_sha256'] == b['initial_weights_sha256']
        assert a['parameters'] == b['parameters'] == 46841
    x = np.load(base / 'test_x.npy', mmap_mode='r')
    y = np.load(base / 'test_y.npy', mmap_mode='r')
    ctx = np.load(cache / 'test_x.npy', mmap_mode='r')
    raw = np.load(base / 'test_raw.npy', mmap_mode='r')
    raw_ctx = np.load(cache / 'test_raw.npy', mmap_mode='r')
    flow_norm = json.loads((base / 'normalization.json').read_text())
    ctx_norm = json.loads((cache / 'normalization.json').read_text())
    results = {}
    for name in names:
        model, checkpoint = load_model(directory / name / 'final.pt', device)
        probability = predict(model, x, ctx, device)
        result = metrics(np.asarray(y), probability)
        result.update({'parameters': checkpoint['parameters'], 'epochs': checkpoint['epoch'],
                       'pruning_rate': checkpoint['pruning_rate'],
                       'checkpoint_sha256': frozen['checkpoints'][name]})
        np.save(directory / (name + '_test_predictions.npy'), probability.argmax(-1).astype(np.int8))
        model = model.cpu().eval()
        wrapper = RawContextWrapper(model, flow_norm['mean'], flow_norm['scale'],
                                    ctx_norm['mean'], ctx_norm['scale']).eval()
        example = (torch.tensor(np.array(raw[:64], copy=True)),
                   torch.tensor(np.array(raw_ctx[:64], copy=True)))
        with torch.inference_mode():
            traced = torch.jit.trace(wrapper, (example[0][:1], example[1][:1]))
            path = directory / (name + '.pt')
            traced.save(str(path))
            actual = torch.jit.load(str(path))(*example)
            expected = wrapper(*example)
            flips = int((actual.argmax(-1) != expected.argmax(-1)).sum())
            error = float((actual - expected).abs().max())
        if flips or not torch.allclose(actual, expected, atol=1e-4, rtol=1e-4):
            raise RuntimeError('Export parity failed')
        result['export'] = {'sha256': sha(path), 'bytes': path.stat().st_size,
                            'samples': len(example[0]), 'decision_flips': flips,
                            'maximum_absolute_error': error}
        results[name] = result
        atomic(directory / (name + '_metrics.json'), result)
        print('TEST_RESULT', name, result['accuracy'], result['macro_f1'],
              result['binary_attack_recall'], result['benign_false_positive_rate'], flush=True)
    historic = {}
    if not config['smoke']:
        original = json.loads((directory.parents[1] / 'validation/reports/tsanet_paper/baseline_results.json').read_text())
        historic = {name: value['test'] for name, value in original['models'].items()
                    if name in ('baseline', 'pruned_30')}
    comparison = {
        'scope': 'Previously opened random-row benchmark; causal interval-safe training-only history bank',
        'smoke': config['smoke'], 'results': results, 'historical_paper_baselines': historic,
        'no_test_tuning': True, 'production_ready': False,
    }
    atomic(directory / 'comparison.json', comparison)
    return comparison


def publish(directory, comparison, context_report):
    root = Path(__file__).resolve().parents[2]
    out = directory if comparison['smoke'] else root / 'validation/reports/tsanet_context'
    out.mkdir(parents=True, exist_ok=True)
    atomic(out / 'comparison.json', comparison)
    atomic(out / 'context_data_report.json', context_report)
    rows = [('Historical paper baseline', comparison['historical_paper_baselines'].get('baseline')),
            ('Historical paper pruned 30%', comparison['historical_paper_baselines'].get('pruned_30'))]
    rows += list(comparison['results'].items())
    lines = ['# TSANet: adding connection context', '',
        'Synthetic smoke only.' if comparison['smoke'] else 'Measured local comparison on the same frozen 70/30 flow rows; this is an already-opened development benchmark.', '',
        '| Model | Accuracy | Macro F1 | Attack recall | Benign false positives | Benign FPR |',
        '|---|---:|---:|---:|---:|---:|']
    for name, m in rows:
        if m is not None:
            lines.append(f"| {name} | {100*m['accuracy']:.4f}% | {100*m['macro_f1']:.4f}% | {100*m['binary_attack_recall']:.4f}% | {m['binary_confusion'][0][1]:,} | {100*m['benign_false_positive_rate']:.5f}% |")
    lines += ['', '## Same-capacity effects', '',
              '| Stage | Accuracy change (pp) | Macro F1 change (pp) | Attack recall change (pp) | Benign FPR change (pp) |',
              '|---|---:|---:|---:|---:|']
    changes = {}
    for phase in ('baseline', 'pruned_30'):
        control = comparison['results']['control_' + phase]
        context = comparison['results']['context_' + phase]
        keys = ('accuracy', 'macro_f1', 'binary_attack_recall', 'benign_false_positive_rate')
        changes[phase] = {k: 100 * (context[k] - control[k]) for k in keys}
        lines.append('| ' + phase + ' | ' + ' | '.join(f'{changes[phase][k]:+.5f}' for k in keys) + ' |')
    atomic(out / 'matched_changes.json', changes)
    lines += ['', '## Classwise recall', '',
        '| Class | Historical pruned 30% | Control baseline | Context baseline | Control pruned 30% | Context pruned 30% | Test rows |',
        '|---|---:|---:|---:|---:|---:|---:|']
    names = ('control_baseline', 'context_baseline', 'control_pruned_30', 'context_pruned_30')
    for cls in CLASSES:
        old = comparison['historical_paper_baselines'].get('pruned_30')
        old_value = f"{100*old['classification_report'][cls]['recall']:.2f}%" if old else 'n/a'
        values = [comparison['results'][name]['classification_report'][cls] for name in names]
        lines.append('| ' + cls + ' | ' + old_value + ' | ' + ' | '.join(f"{100*v['recall']:.2f}%" for v in values) + f" | {int(values[0]['support']):,} |")
    lines += ['', '## Scope and controls', '',
        '- History windows: 2, 5 and 15 minutes, for source and destination hosts; 78 aggregate features. No literal identities, calendar times or labels enter the tensors.',
        '- Only training rows populate history, for both train and test queries. Entire completion intervals must precede the query and lie within the window. Minute-rounded uncertain flows are omitted.',
        '- Both arms have 46,841 parameters, identical initial weights and training orders. Original paper model has 42,761 parameters. No class weighting, threshold or optimizer change.',
        '- Fixed 10 baseline and 5 pruning epochs per arm; all epochs retained. Four final checkpoints frozen before test scoring. No test-selected winner.',
        '- Full-flow completion benchmark, sampled history and one training seed; no independent-session, Android latency or alerts/day claims. No APK installed.',
        '- See experiments/tsanet_context/PROTOCOL.md and context_data_report.json for exact timing, inclusion rules and coverage.', '']
    (out / 'COMPARISON.md').write_text('\n'.join(lines))
    if out != directory:
        (directory / 'COMPARISON.md').write_text('\n'.join(lines))
    print('CONTEXT_REPORT', out / 'COMPARISON.md', flush=True)
