"""Temporal/bank isolation, matched model and resume checks before full training."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import copy
import csv
from datetime import datetime, timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import numpy as np
import torch

from experiments.tsanet_paper.data import FEATURES, atomic
from experiments.tsanet_paper.model import magnitude_masks, apply_masks
from experiments.tsanet_context.context_features import build_context, WINDOWS, timestamp_bounds
from experiments.tsanet_context.context_model import ContextTSANet, RawContextWrapper


def make_fixture(directory):
    random = np.random.default_rng(20261118)
    output = io.StringIO()
    writer = csv.writer(output)
    metadata = ['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'Timestamp']
    writer.writerow([*FEATURES, *metadata, 'Label'])
    labels = ['BENIGN','Bot','FTP-Patator','DDoS','DoS Hulk','PortScan','Web Attack XSS']
    for i in range(350):
        cls = i % 7
        features = np.abs(random.normal(cls + 1, .1, 32))
        features[0] = 1000 + i
        features[1:3] = [2 + cls, 1]
        features[3:5] = [100 + cls * 10, 60]
        features[29:32] = [1, 0, 1]
        stamp = (datetime(2017,7,3,9) + timedelta(seconds=i * 10)).strftime('%d/%m/%Y %H:%M:%S')
        writer.writerow([*features.tolist(), f'10.0.0.{1+cls}', '10.0.1.1', 40000+i, 80+cls, 6, stamp, labels[cls]])
    path = directory / 'synthetic_context.zip'
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('Monday.csv', output.getvalue())
    return path


def tiny_metadata():
    lower = np.array([0, 30, 80, 120, 180, 300, 420, 800, 1000, 1100, 1600, 1700.], float)
    return {
        'source': np.array([0,0,1,0,2,0,1,2,0,1,0,2], np.int32),
        'destination': np.array([1,2,2,1,0,2,0,1,2,2,1,0], np.int32),
        'sport': np.arange(12,dtype=np.int32) + 100,
        'dport': np.array([80,80,81,82,81,80,81,80,81,80,82,80], np.int32),
        'lower': lower, 'upper': lower + np.array([1,60,60,1,60,60,1,60,60,1,60,1]),
        'measures': np.column_stack((np.ones(12), np.arange(12)+1, np.arange(12)%3,
            (np.arange(12)+1)*10, (np.arange(12)%3)*20,
            np.arange(12)%3==0, np.arange(12)%2, np.ones(12), np.ones(12), np.zeros(12))).astype(float),
    }


def slow_reference(meta, bank):
    result = np.zeros((len(meta['source']), 78), np.float32)
    for q, anchor in enumerate(meta['lower']):
        for w, window in enumerate(WINDOWS):
            eligible = [i for i in bank if meta['upper'][i] < anchor and meta['lower'][i] >= anchor-window]
            for role, host in enumerate((meta['source'][q], meta['destination'][q])):
                values, peers, remote, local = [], set(), set(), set()
                for i in eligible:
                    for side in (0,1):
                        if meta['source' if side==0 else 'destination'][i] != host:
                            continue
                        v = meta['measures'][i].copy()
                        if side:
                            v[1:5] = v[[2,1,4,3]]
                            v[5] = meta['measures'][i,1] == 0
                        values.append(v)
                        peers.add(meta['destination' if side==0 else 'source'][i])
                        remote.add(meta['dport' if side==0 else 'sport'][i])
                        local.add(meta['sport' if side==0 else 'dport'][i])
                if values:
                    total = np.sum(values,axis=0)
                    result[q,w*26+role*13:w*26+(role+1)*13] = np.r_[
                        np.log1p(total[:5]),np.log1p([len(peers),len(remote),len(local)]),total[5:]/total[0]]
    return result


class Checks(unittest.TestCase):
    def test_windows_match_reference_with_uncertainty_and_expiry(self):
        meta = tiny_metadata()
        bank = np.array([0,1,2,3,4,6,8,10])
        np.testing.assert_allclose(build_context(meta, bank), slow_reference(meta, bank), atol=1e-6)

    def test_future_self_ties_and_heldout_do_not_enter_history(self):
        meta = tiny_metadata()
        bank = np.array([0,1,2,3,4,6,8,10])
        original = build_context(meta, bank)
        np.testing.assert_array_equal(original[0], 0)
        changed = copy.deepcopy(meta)
        changed['measures'][[5,7,9,11],1:5] *= 100000
        np.testing.assert_array_equal(build_context(changed, bank), original)
        changed = copy.deepcopy(meta)
        changed['measures'][10] *= 100000
        np.testing.assert_array_equal(build_context(changed,bank)[:10], original[:10])
        changed = copy.deepcopy(meta)
        changed['upper'][0] = changed['lower'][1]
        self.assertEqual(build_context(changed,bank)[1,0],0.)

    def test_clock_mapping_and_precision(self):
        a = timestamp_bounds('3/7/2017 1:00')
        b = timestamp_bounds('03/07/2017 13:00:00')
        self.assertEqual(a[0],b[0]); self.assertEqual(a[1],60); self.assertEqual(b[1],1)
        with self.assertRaises(ValueError): timestamp_bounds('3/7/2017 00:00')

    def test_matched_capacity_disabled_independence_and_raw_wrapper(self):
        torch.manual_seed(42); control = ContextTSANet(False).eval()
        torch.manual_seed(42); context = ContextTSANet(True).eval()
        for a,b in zip(control.parameters(),context.parameters()): self.assertTrue(torch.equal(a,b))
        self.assertEqual(sum(p.numel() for p in context.parameters()),46841)
        x,c = torch.randn(4,32),torch.randn(4,78)
        self.assertTrue(torch.equal(control(x,c),control(x,c*100)))
        wrapper = RawContextWrapper(context,np.zeros(32),np.ones(32),np.zeros(78),np.ones(78))
        torch.testing.assert_close(wrapper(x,c),context(x,c))

    def test_pruned_gradients_and_cuda(self):
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
        model = ContextTSANet(True).to(device)
        masks = magnitude_masks(model,.3); apply_masks(model,masks)
        optimizer = torch.optim.Adam(model.parameters(),lr=.001)
        loss = torch.nn.functional.cross_entropy(model(torch.randn(4,32,device=device),torch.randn(4,78,device=device)),torch.arange(4,device=device))
        loss.backward(); apply_masks(model,masks,gradients=True); optimizer.step(); apply_masks(model,masks)
        for name,value in model.named_parameters():
            self.assertTrue(torch.isfinite(value).all())
            if name in masks: self.assertTrue((value[masks[name]==0]==0).all())

    def test_interrupted_resume_matches_uninterrupted(self):
        from experiments.tsanet_context import experiment
        from experiments.tsanet_context.run import configuration
        torch.manual_seed(99)
        x,c,y = torch.randn(14,32),torch.randn(14,78),torch.arange(14)%7
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            a,b = root/'a',root/'b';a.mkdir();b.mkdir()
            for directory in (a,b): atomic(directory/'config.json',configuration(True))
            experiment.train_stage(a,'context_baseline',True,2,x,c,y,'cpu')
            real_atomic = experiment.atomic
            def interrupt_after_epoch(path,value):
                real_atomic(path,value)
                if path.name=='history.json': raise RuntimeError('simulated interruption')
            with patch.object(experiment,'atomic',interrupt_after_epoch):
                with self.assertRaisesRegex(RuntimeError,'simulated interruption'):
                    experiment.train_stage(b,'context_baseline',True,2,x,c,y,'cpu')
            experiment.train_stage(b,'context_baseline',True,2,x,c,y,'cpu')
            left = torch.load(a/'context_baseline/final.pt',weights_only=True)
            right = torch.load(b/'context_baseline/final.pt',weights_only=True)
            for name in left['model']: self.assertTrue(torch.equal(left['model'][name],right['model'][name]))


def run_checks():
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks))
    if not result.wasSuccessful(): raise RuntimeError('Context pipeline checks failed')


if __name__ == '__main__':
    torch.set_num_threads(2)
    run_checks()
