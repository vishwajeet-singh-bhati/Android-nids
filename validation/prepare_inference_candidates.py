"""Frozen-weight inference experiments; no fitting, new split or threshold tuning.

E8 PTQ uses the user's reviewed code. Its FP32 reconstruction is evaluated before
any custom packed-kernel deployment is considered; that is not an E8 runtime.
"""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import copy
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from experiments.phone_alignment_v2.models import build,RawWrapper

RUN=ROOT/'runs/phone_capture_training_v1'
CACHE=ROOT/'data/experiments/phone_capture_training_v1'
OUT=ROOT/'runs/performance_v1/candidates'
PUBLIC=ROOT/'validation/reports/performance_v1'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


class HoistedLSTM(nn.Module):
    def __init__(self,source,last_only=False):
        super().__init__();self.hidden_size=source.hidden_size;self.last_only=last_only
        for name in ('weight_ih_l0','weight_hh_l0','bias_ih_l0','bias_hh_l0'):
            self.register_buffer(name,getattr(source,name).detach().clone())
    def forward(self,x):
        h=x.new_zeros((1,self.hidden_size));c=x.new_zeros((1,self.hidden_size));output=[]
        projected=F.linear(x,self.weight_ih_l0,self.bias_ih_l0)
        for i in range(32):
            gates=projected[:,i]+F.linear(h,self.weight_hh_l0,self.bias_hh_l0)
            ig,fg,cg,og=gates.chunk(4,dim=-1)
            c=torch.sigmoid(fg)*c+torch.sigmoid(ig)*torch.tanh(cg)
            h=torch.sigmoid(og)*torch.tanh(c)
            if not self.last_only:output.append(h)
        return (h.unsqueeze(1) if self.last_only else torch.stack(output,dim=1)),(h.unsqueeze(0),c.unsqueeze(0))


def hoist(module):
    for name,child in list(module.named_children()):
        if isinstance(child,nn.LSTM):setattr(module,name,HoistedLSTM(child,last_only=name=='final_lstm'))
        else:hoist(child)


def policy(gate,diagnosis,threshold,cutoff):
    flag=torch.sigmoid(torch.from_numpy(gate.reshape(-1))).numpy()>=threshold
    probs=torch.softmax(torch.from_numpy(diagnosis),dim=1).numpy();best=probs.argmax(1)
    typed=flag&(best!=0)&(probs.max(1)>=cutoff)
    pred=np.where(flag,7,0);pred[typed]=best[typed]
    return flag,pred


def original_outputs(model,raw):
    out=[]
    with torch.inference_mode():
        for offset in range(0,len(raw),64):
            x=torch.tensor(np.array(raw[offset:offset+64],copy=True))
            out.append(model(x[:,:32],x[:,32:]).numpy())
    return np.concatenate(out)


def main(source):
    from executorch.exir import to_edge_transform_and_lower
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import XnnpackPartitioner
    from executorch.backends.xnnpack.utils.configs import get_transform_passes
    from executorch.runtime import Runtime
    torch.set_num_threads(2)
    source=Path(source);quant_path=source/'e8_quant.py'
    # Only the user-reviewed local implementation is imported, never a download.
    assert sha(quant_path)=='12fc3893f415791efcf4442bbb36015574b9cca065618735f33e0eb608b7b0ee','Review changed E8 source before execution'
    spec=importlib.util.spec_from_file_location('user_e8_quant',quant_path);quant=importlib.util.module_from_spec(spec);spec.loader.exec_module(quant)
    codebook=quant.build_e8_codebook_8bit();norms=(codebook**2).sum(1)
    OUT.mkdir(parents=True,exist_ok=True)
    provenance={p.name:{'sha256':sha(p),'bytes':p.stat().st_size,'lines':len(p.read_text(encoding='utf-8-sig').splitlines())} for p in source.iterdir() if p.suffix in ('.py','.cpp')}
    save(PUBLIC/'source_review.json',{'local_sources':provenance,'python_codebook_shape':list(codebook.shape),
        'architecture_in_cpp':'BERT encoder, 12 layers/hidden768 by default; not an autoregressive Llama runner',
        'useful_ideas':['reused thread-local scratch','shared QKV lookup work','ARM NEON','measure serial latency separately from multi-request throughput','trim genuine token padding'],
        'constraints':['32 detector features are ordered scalar features, not token padding; do not trim them','8 simultaneous encoder samples are not 8-way acceleration of one causal Llama generation','E8 Python QAT forward reconstructs FP32 weights and uses F.linear','packed C++ E8 LUT math is not an operator supplied by the stock ExecuTorch Android AAR'],
        'source_edits':False,'training_performed':False})
    config=json.loads((RUN/'config.json').read_text(encoding='utf-8'));frozen=json.loads((RUN/'frozen_selection.json').read_text(encoding='utf-8'))
    selected=frozen['selected'];norm=json.loads((CACHE/'normalization.json').read_text(encoding='utf-8'))
    raw_all=np.load(CACHE/'validation/raw.npy',mmap_mode='r');y_all=np.load(CACHE/'validation/y.npy',mmap_mode='r');sources=np.load(CACHE/'validation/source.npy',mmap_mode='r')
    rng=np.random.default_rng(21112026)
    ids=np.unique(np.r_[rng.choice(len(y_all),512,replace=False),*[rng.choice(np.flatnonzero(y_all==c),min(64,int((y_all==c).sum())),replace=False) for c in range(7)],np.flatnonzero(sources==7)])
    raw=np.array(raw_all[ids],copy=True);y=np.array(y_all[ids],copy=True);np.save(OUT/'validation_ids.npy',ids)
    models={};reference={}
    for kind in ('gate','diagnosis'):
        job_name,variant=selected[kind].rsplit('_',1);job=next(j for j in config['jobs'] if j['name']==job_name)
        checkpoint=RUN/'jobs'/job_name/(variant+'.pt');assert sha(checkpoint)==frozen['checkpoint_sha256'][selected[kind]]
        model=build(job).eval();model.load_state_dict(torch.load(checkpoint,map_location='cpu',weights_only=False)['model'])
        models[kind]=RawWrapper(model,norm['mean'],norm['scale']).eval();reference[kind]=original_outputs(models[kind],raw)
    baseline=policy(reference['gate'],reference['diagnosis'],selected['threshold'],selected['type_cutoff'])
    reports=[]
    for name in ('hoisted_fp32','e8_blockmax_reconstructed','e8_rowsigma_reconstructed'):
        outputs={};record={'name':name,'rows':len(ids),'split':'validation-only diagnostic fixture','models':{},'training':False}
        for kind in ('gate','diagnosis'):
            model=copy.deepcopy(models[kind]);quantized=[]
            if name.startswith('e8_'):
                mode='block_max' if 'blockmax' in name else 'row_sigma'
                with torch.no_grad():
                    for key,parameter in model.named_parameters():
                        if parameter.ndim==2 and parameter.shape[1]>=32:
                            original=parameter.detach().clone();reconstructed=quant.e8_quantize_ste(original,codebook,norms,mode)
                            parameter.copy_(reconstructed)
                            blocks=parameter.shape[0]*((parameter.shape[1]+31)//32)
                            quantized.append({'name':key,'shape':list(parameter.shape),'packed_weight_payload_bytes':int(blocks*8),'fp32_weight_bytes':parameter.numel()*4,'relative_l2_error':float((reconstructed-original).norm()/original.norm().clamp_min(1e-12))})
            hoist(model)
            args=(torch.tensor(raw[:1,:32].copy()),torch.tensor(raw[:1,32:].copy()))
            program=to_edge_transform_and_lower(torch.export.export(model,args),partitioner=[XnnpackPartitioner()],transform_passes=get_transform_passes()).to_executorch()
            path=OUT/(name+'_'+kind+'.pte');path.write_bytes(program.buffer)
            runtime=Runtime.get().load_program(str(path)).load_method('forward');values=[]
            with torch.inference_mode():
                for row in raw:
                    values.append(runtime.execute([torch.tensor(row[None,:32].copy()),torch.tensor(row[None,32:].copy())])[0].numpy())
            actual=np.concatenate(values);outputs[kind]=actual
            if name=='hoisted_fp32':np.testing.assert_allclose(actual,reference[kind],atol=.002,rtol=.0002)
            error=float(np.abs(actual-reference[kind]).max())
            record['models'][kind]={'pte_sha256':sha(path),'pte_bytes':path.stat().st_size,'max_abs_logit_change':error,'quantized_tensors':quantized,
                'runtime_representation':'FP32 reconstructed weights with XNNPACK; not packed E8 inference' if quantized else 'unchanged FP32 weights, hoisted LSTM input projections'}
            print('CANDIDATE_MODEL',name,kind,'error',error,flush=True)
        predicted=policy(outputs['gate'],outputs['diagnosis'],selected['threshold'],selected['type_cutoff'])
        record['binary_flips']=int((predicted[0]!=baseline[0]).sum());record['family_flips']=int((predicted[1]!=baseline[1]).sum())
        record['classwise']=[{'class_id':c,'support':int((y==c).sum()),'baseline_correct':int(((y==c)&(baseline[1]==c)).sum()),'candidate_correct':int(((y==c)&(predicted[1]==c)).sum()),'baseline_flags':int(baseline[0][y==c].sum()),'candidate_flags':int(predicted[0][y==c].sum())} for c in range(7)]
        if name=='hoisted_fp32':assert record['binary_flips']==record['family_flips']==0
        reports.append(record);save(PUBLIC/'candidate_exports.json',{'variants':reports,'frozen_thresholds':selected,'held_out_test_opened':False,'no_retraining':True})
        print('CANDIDATE_COMPLETE',name,'binary_flips',record['binary_flips'],'family_flips',record['family_flips'],flush=True)


def make_bundles():
    from executorch.runtime import Runtime
    reports=json.loads((PUBLIC/'candidate_exports.json').read_text(encoding='utf-8'))
    for record in reports['variants']:
        name=record['name'];folder=OUT/'bundles'/name;folder.mkdir(parents=True,exist_ok=True)
        for kind in ('gate','diagnosis'):
            path=OUT/(name+'_'+kind+'.pte');(folder/f'aligned_v2_{kind}.pte').write_bytes(path.read_bytes())
            manifest=json.loads((ROOT/f'android/app/src/main/assets/aligned_v2_{kind}_manifest.json').read_text(encoding='utf-8'))
            manifest.update(model_sha256=sha(path),bytes=path.stat().st_size,performance_only=True,performance_variant=name)
            save(folder/f'aligned_v2_{kind}_manifest.json',manifest)
            fixture=json.loads((ROOT/f'android/app/src/main/assets/aligned_v2_{kind}_selfcheck.json').read_text(encoding='utf-8'))
            method=Runtime.get().load_program(str(path)).load_method('forward')
            for row in fixture['cases']:
                row['expected_current']=row['expected']
                args=[torch.tensor(row[k],dtype=torch.float32).reshape(1,-1) for k in ('flow','context')]
                row['expected']=method.execute(args)[0].numpy().flatten().tolist()
            fixture.update(model_sha256=sha(path),performance_only=True)
            save(folder/f'aligned_v2_{kind}_selfcheck.json',fixture)
        print('BUNDLE_READY',name,flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bundle-only',action='store_true')
    parser.add_argument('--e8-source',type=Path,default=Path('/mnt/d/infrence'));args=parser.parse_args()
    if not args.bundle_only:main(args.e8_source)
    make_bundles()
