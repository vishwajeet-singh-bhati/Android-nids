"""Meaningful model/pruning/CSV tests before the full paper experiment."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import csv,io,json,unittest,zipfile
from pathlib import Path
import numpy as np
import torch
from data import FEATURES,CLASSES,family
from model import TSANet,RawFeatureWrapper,magnitude_masks,apply_masks

def make_fixture(directory):
    path=Path(directory)/'synthetic_flows.zip';rng=np.random.default_rng(42018)
    labels=['BENIGN','Bot','FTP-Patator','DDoS','DoS Hulk','PortScan','Web Attack XSS']
    stream=io.StringIO();writer=csv.writer(stream);writer.writerow([*FEATURES,'Label'])
    for c,label in enumerate(labels):
        for _ in range(100):writer.writerow([*(rng.normal(c+1,.15,32).tolist()),label])
    writer.writerow([*([0.]*32),'Infiltration']);writer.writerow([*([0.]*32),'Heartbleed'])
    bad=[1.]*32;bad[0]=float('inf');writer.writerow([*bad,'BENIGN'])
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as archive:archive.writestr('toy.csv',stream.getvalue())
    return path

class Checks(unittest.TestCase):
    def test_architecture_shapes_attention_and_gradients(self):
        torch.manual_seed(42);model=TSANet();x=torch.randn(4,32,1)
        a,b,spatial,temporal=model.branches(x)
        self.assertEqual(a.shape,(4,32,32));self.assertEqual(b.shape,(4,32,32))
        self.assertTrue(torch.all((spatial>=0)&(spatial<=1)))
        self.assertTrue(torch.allclose(temporal.sum(1),torch.ones(4,1),atol=1e-6))
        z=model(x);self.assertEqual(z.shape,(4,7));z.sum().backward()
        self.assertTrue(all(p.grad is None or torch.isfinite(p.grad).all() for p in model.parameters()))
        self.assertEqual(sum(p.numel() for p in model.parameters()),42761)
    def test_pruning_cannot_regrow(self):
        model=TSANet();masks=magnitude_masks(model,.3);apply_masks(model,masks)
        total=sum(m.numel() for m in masks.values());zeros=sum(int((m==0).sum()) for m in masks.values())
        self.assertEqual(zeros,int(.3*total))
        optimizer=torch.optim.Adam(model.parameters(),lr=.001)
        loss=torch.nn.functional.cross_entropy(model(torch.randn(4,32,1)),torch.tensor([0,1,2,3]))
        loss.backward();apply_masks(model,masks,gradients=True);optimizer.step();apply_masks(model,masks)
        for name,p in model.named_parameters():
            if name in masks:self.assertTrue(torch.all(p[masks[name]==0]==0))
    def test_raw_wrapper(self):
        model=TSANet().eval();x=torch.randn(3,32);mean=np.arange(32,dtype=np.float32);scale=np.ones(32,np.float32)*2
        wrapper=RawFeatureWrapper(model,mean,scale).eval()
        with torch.inference_mode():self.assertTrue(torch.allclose(wrapper(x),model(((x-torch.tensor(mean))/2).unsqueeze(-1))))
    def test_labels_and_feature_contract(self):
        self.assertEqual(len(FEATURES),32);self.assertEqual(len(set(FEATURES)),32)
        self.assertEqual(family('FTP-Patator'),family('SSH-Patator'))
        self.assertEqual(family('DoS GoldenEye'),4);self.assertEqual(family('Web Attack Brute Force'),6)
        self.assertEqual(family('Infiltration'),-1);self.assertEqual(family('Heartbleed'),-1)
        self.assertFalse(any(s in FEATURES for s in ('Label','Source IP','Destination IP','Flow ID','Timestamp')))
    def test_cuda_pruned_forward_when_available(self):
        if not torch.cuda.is_available():self.skipTest('No CUDA')
        model=TSANet().cuda();masks=magnitude_masks(model,.3);apply_masks(model,masks)
        z=model(torch.randn(4,32,1,device='cuda'));z.sum().backward()
        self.assertTrue(torch.isfinite(z).all())

def run_checks():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks))
    if not result.wasSuccessful():raise RuntimeError('Architecture/pruning preflight failed')

if __name__=='__main__':torch.set_num_threads(2);run_checks()
