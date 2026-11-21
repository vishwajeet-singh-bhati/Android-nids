"""Export calibrated repair and preserved fallback; verify the complete policy."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import copy,json,shutil,sys
from pathlib import Path
import numpy as np
import torch
from torch import nn

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_repair_v3.common import *
from experiments.phone_repair_v3.policy import probabilities,decisions
from experiments.phone_alignment_v2.models import build,RawWrapper
from reproducibility.export_layers import PortableLSTM


class CalibratedRaw(nn.Module):
    def __init__(self,model,norm,calibration):
        super().__init__();self.raw=RawWrapper(model,norm['mean'],norm['scale'])
        self.register_buffer('cal_scale',torch.tensor(calibration['scale'],dtype=torch.float32));self.register_buffer('cal_bias',torch.tensor(calibration['bias'],dtype=torch.float32))
    def forward(self,flow,context):return self.raw(flow,context)*self.cal_scale+self.cal_bias


def unroll(module):
    for name,child in list(module.named_children()):
        if isinstance(child,nn.LSTM):setattr(module,name,PortableLSTM(child))
        else:unroll(child)


def main():
    from executorch.exir import to_edge_transform_and_lower
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import XnnpackPartitioner
    from executorch.backends.xnnpack.utils.configs import get_transform_passes
    from executorch.runtime import Runtime
    torch.set_num_threads(2);frozen=json.loads((RUN/'frozen_selection.json').read_text());selected=frozen['selected'];evaluation=json.loads((RUN/'evaluation.json').read_text())
    norm=json.loads((CACHE/'normalization.json').read_text());raw=np.load(CACHE/'test/raw.npy',mmap_mode='r');y=np.load(CACHE/'test/y.npy',mmap_mode='r')
    rng=np.random.default_rng(9402);ids=np.unique(np.r_[rng.choice(len(y),min(512,len(y)),replace=False),*[rng.choice(np.flatnonzero(y==c),min(64,int((y==c).sum())),replace=False) for c in range(7)]])
    folder=RUN/'exports/repair';folder.mkdir(parents=True,exist_ok=True);reports={};outputs={}
    for kind in ('gate','diagnosis'):
        entry=selected[kind];assert sha(ROOT/entry['checkpoint'])==entry['checkpoint_sha256']
        model=build(entry['job']).eval();model.load_state_dict(torch.load(ROOT/entry['checkpoint'],map_location='cpu',weights_only=False)['model'])
        original=CalibratedRaw(model,norm,selected[kind+'_calibration']).eval();portable=copy.deepcopy(original);unroll(portable)
        row=torch.tensor(np.array(raw[ids[:1]],copy=True));args=(row[:,:32],row[:,32:])
        edge=to_edge_transform_and_lower(torch.export.export(portable,args),partitioner=[XnnpackPartitioner()],transform_passes=get_transform_passes()).to_executorch()
        path=folder/(kind+'.pte');path.write_bytes(edge.buffer);method=Runtime.get().load_program(str(path)).load_method('forward')
        expected=[];actual=[];error=0.;cases=[]
        with torch.inference_mode():
            for i in ids:
                row=torch.tensor(np.array(raw[i:i+1],copy=True));args=(row[:,:32],row[:,32:]);a=original(*args).numpy();b=method.execute(list(args))[0].numpy()
                np.testing.assert_allclose(a,b,atol=.003,rtol=.0003);error=max(error,float(np.max(np.abs(a-b))));expected.append(a);actual.append(b)
                if int(y[i]) not in {c['source_class'] for c in cases} or len(cases)<8:cases.append({'flow':args[0].flatten().tolist(),'context':args[1].flatten().tolist(),'expected':b.flatten().tolist(),'source_class':int(y[i])})
        outputs[kind]=(np.concatenate(expected),np.concatenate(actual))
        metadata={'schema':'phone-aligned-v2-repair-v3-policy','kind':kind,'job':entry['job']['name'],'epoch':entry['epoch'],'checkpoint_sha256':entry['checkpoint_sha256'],
            'model_sha256':sha(path),'parameters':sum(p.numel() for p in model.parameters()),'bytes':path.stat().st_size,'input_shapes':[[1,32],[1,115]],
            'normalization_and_calibration_embedded':True,'output':'calibrated logits','parity_rows':len(ids),'all_source_classes':sorted(set(map(int,y[ids]))),'maximum_pte_error':error,'device_native_verification_pending':True}
        atomic(folder/(kind+'_manifest.json'),metadata);atomic(folder/(kind+'_selfcheck.json'),{'model_sha256':sha(path),'absolute_tolerance':.003,'cases':cases});reports[kind]=metadata
    pred_a,flag_a,route_a=decisions(probabilities(outputs['gate'][0],'gate'),probabilities(outputs['diagnosis'][0],'diagnosis'),selected['policy'])
    pred_b,flag_b,route_b=decisions(probabilities(outputs['gate'][1],'gate'),probabilities(outputs['diagnosis'][1],'diagnosis'),selected['policy'])
    flips=int((pred_a!=pred_b).sum());flag_flips=int((flag_a!=flag_b).sum());route_flips=int((route_a!=route_b).sum())
    atomic(folder/'policy.json',{'policy':selected['policy'],'high_alert_never_vetoed':True,'review_is_not_an_alert':True,'feature_contract':'32 flow +115 context; same frozen v2 extractor','device_validation_pending':True})
    verification={'pipeline_type_flips':flips,'binary_flag_flips':flag_flips,'routing_flips':route_flips,'rows':len(ids),'passed':flips==flag_flips==route_flips==0}
    atomic(folder/'native_policy_verification.json',verification);assert verification['passed'],'Native complete-policy decisions changed'
    fallback=RUN/'exports/preserved_v2';fallback.mkdir(exist_ok=True)
    for p in (BASE/'exports').glob('*'):
        if p.is_file():shutil.copy2(p,fallback/p.name)
    atomic(fallback/'policy.json',{'policy':json.loads((RUN/'config.json').read_text())['baseline_policy'],'calibration_embedded':False,'device_validation_pending':True})
    bundle={'intended_deployment':evaluation['intended_deployment'],'selected_bundle':'exports/repair' if evaluation['repair_is_better'] else 'exports/preserved_v2',
        'repair_models':reports,'native_policy_verification':verification,'fallback_preserved':True,'device_validation_pending':True,'deployment_executed':False,
        'offline_readiness_targets_passed':evaluation['offline_readiness_targets_passed'],'fallback_authorization':'User instructed comparison followed by improved repair or preserved v2 deployment; device absent, no install attempted.'}
    atomic(PUBLIC/'mobile_export.json',bundle);atomic(RUN/'deployment_bundle.json',bundle);print('REPAIR_MOBILE_EXPORT_PASS',verification,flush=True)


if __name__=='__main__':main()
