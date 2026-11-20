"""Export only validation-selected frozen models; numeric and decision parity on all classes."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import copy,json,sys
from pathlib import Path
import numpy as np,torch
from torch import nn

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_alignment_v2.common import *
from experiments.phone_alignment_v2.models import build,RawWrapper
from reproducibility.export_layers import PortableLSTM


def unroll(module):
    for name,child in list(module.named_children()):
        if isinstance(child,nn.LSTM):setattr(module,name,PortableLSTM(child))
        else:unroll(child)


def main():
    from executorch.exir import to_edge_transform_and_lower
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import XnnpackPartitioner
    from executorch.backends.xnnpack.utils.configs import get_transform_passes
    from executorch.runtime import Runtime
    torch.set_num_threads(2)
    config=json.loads((RUN/'config.json').read_text());frozen=json.loads((RUN/'frozen_selection.json').read_text())
    normalization=json.loads((CACHE/'normalization.json').read_text());raw=np.load(CACHE/'test/raw.npy',mmap_mode='r');y=np.load(CACHE/'test/y.npy',mmap_mode='r')
    rng=np.random.default_rng(963);ids=np.unique(np.r_[rng.choice(len(y),min(512,len(y)),replace=False),*[rng.choice(np.flatnonzero(y==c),min(64,int((y==c).sum())),replace=False) for c in range(7)]])
    out=RUN/'exports';out.mkdir(exist_ok=True);reports={}
    gate_validation=json.loads((RUN/'jobs'/frozen['choices']['gate']/'best_validation.json').read_text())['validation']
    for kind,name in frozen['choices'].items():
        job=next(j for j in config['jobs'] if j['name']==name);checkpoint=RUN/'jobs'/name/'best.pt'
        assert sha(checkpoint)==frozen['model_hashes'][name]
        model=build(job).eval();model.load_state_dict(torch.load(checkpoint,map_location='cpu',weights_only=False)['model'])
        original=RawWrapper(model,normalization['mean'],normalization['scale']).eval();portable=copy.deepcopy(original);unroll(portable)
        expected=[];maximum_portable=0.0
        with torch.inference_mode():
            for i in ids:
                row=torch.tensor(np.array(raw[i:i+1],copy=True));args=(row[:,:32],row[:,32:])
                a=original(*args);b=portable(*args);torch.testing.assert_close(a,b,atol=.002,rtol=.0002)
                maximum_portable=max(maximum_portable,float((a-b).abs().max()));expected.append(a.numpy())
        sample=torch.tensor(np.array(raw[ids[:1]],copy=True));example=(sample[:,:32],sample[:,32:])
        edge=to_edge_transform_and_lower(torch.export.export(portable,example),partitioner=[XnnpackPartitioner()],transform_passes=get_transform_passes()).to_executorch()
        path=out/(kind+'.pte');path.write_bytes(edge.buffer)
        method=Runtime.get().load_program(str(path)).load_method('forward');maximum=0.0;flips=0;cases=[]
        with torch.inference_mode():
            for position,i in enumerate(ids):
                row=torch.tensor(np.array(raw[i:i+1],copy=True));args=(row[:,:32],row[:,32:])
                actual=method.execute(list(args))[0].numpy();reference=expected[position]
                np.testing.assert_allclose(actual,reference,atol=.002,rtol=.0002);maximum=max(maximum,float(np.max(np.abs(actual-reference))))
                if kind=='gate':
                    flips+=int(bool(torch.sigmoid(torch.from_numpy(actual)).item()>=gate_validation['threshold'])!=bool(torch.sigmoid(torch.from_numpy(reference)).item()>=gate_validation['threshold']))
                else:
                    flips+=int(actual.argmax()!=reference.argmax())
                if int(y[i]) not in {v['source_class'] for v in cases} or len(cases)<8:
                    cases.append({'flow':args[0].flatten().tolist(),'context':args[1].flatten().tolist(),'expected':actual.flatten().tolist(),'source_class':int(y[i])})
        assert flips==0,(kind,'Export decisions changed',flips)
        spec_path=RUN/'extractor/spec.json'
        if not spec_path.exists():spec_path=ROOT/'runs/phone_alignment_v2/extractor/spec.json'
        manifest={'schema':'phone-aligned-v2','kind':kind,'job':name,'checkpoint_sha256':sha(checkpoint),'model_sha256':sha(path),
            'parameters':sum(p.numel() for p in model.parameters()),'bytes':path.stat().st_size,'input_shapes':[[1,32],[1,115]],
            'feature_contract_sha256':sha(spec_path),'normalization_embedded':True,'parity_rows':len(ids),'all_source_classes':sorted(set(map(int,y[ids]))),
            'maximum_portable_error':maximum_portable,'maximum_pte_error':maximum,'decision_flips':flips,'gate_threshold':gate_validation['threshold'],
            'type_score_cutoff':config['type_score_cutoff'],'diagnosis_never_vetoes_gate':True,'device_native_verification_pending':True}
        atomic(out/(kind+'_manifest.json'),manifest);atomic(out/(kind+'_selfcheck.json'),{'model_sha256':sha(path),'absolute_tolerance':.002,'cases':cases})
        reports[kind]=manifest;print('MOBILE_EXPORT_PASS',kind,len(ids),maximum,flips,flush=True)
    atomic(PUBLIC/'mobile_export.json',reports)


if __name__=='__main__':main()
