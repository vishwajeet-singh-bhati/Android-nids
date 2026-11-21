"""Compare unchanged/hoisted PTEs on saved phone inputs; no new traffic or fitting."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from pathlib import Path
import hashlib
import json
import sys

import numpy as np
import torch
from executorch.runtime import Runtime

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'validation/reports/performance_v1'
RUN=ROOT/'runs/performance_v1/candidates'


def predict(gate,diagnosis):
    if float(gate[0])<np.log(.5408333333333333/(1-.5408333333333333)):return 0
    z=diagnosis.astype(np.float64);p=np.exp(z-z.max());p/=p.sum();best=int(p.argmax())
    return best if best!=0 and p[best]>=.8 else 7


def main():
    torch.set_num_threads(2)
    cases=['104159_Benign','105054_PortScan','105921_SlowScan','113935_PasswordGuessing','114213_SQLInjection','114437_XSS','114717_ConnectionExhaustion','114945_HTTPFlood','115902_HTTPFlood','120751_ConnectionExhaustion','121909_XSS']
    paths=[ROOT/'runs/manual_phone_tests'/('20261121_'+name)/'nids_numeric_trace.jsonl' for name in cases]
    paths+=sorted((ROOT/'runs/protocol_phone_tests/cases').glob('*/native.jsonl'))
    rows=[];sources=[]
    for path in paths:
        if not path.exists():raise FileNotFoundError(path)
        count=0
        for line in path.read_text(encoding='utf-8').splitlines():
            row=json.loads(line)
            if len(row.get('flow',[]))!=32 or len(row.get('context',[]))!=115:continue
            values=np.array(row['flow']+row['context'],np.float32);assert np.isfinite(values).all()
            rows.append((values,int(row['class_id'])));count+=1
        sources.append({'case':path.parent.name,'rows':count,'native_snapshot_sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    old=ROOT/'runs/phone_capture_training_v1/mobile_trial'
    method=lambda path:Runtime.get().load_program(str(path)).load_method('forward')
    gate=method(old/'gate.pte');baseline=method(old/'diagnosis.pte');candidate=method(RUN/'hoisted_fp32_diagnosis.pte')
    assert hashlib.sha256((old/'gate.pte').read_bytes()).digest()==hashlib.sha256((RUN/'hoisted_fp32_gate.pte').read_bytes()).digest()
    maximum=0.;flips=0;native_mismatch=0
    for i,(row,expected_native) in enumerate(rows):
        args=[torch.tensor(row[None,:32].copy()),torch.tensor(row[None,32:].copy())]
        g=gate.execute(args)[0].numpy().flatten();a=baseline.execute(args)[0].numpy().flatten();b=candidate.execute(args)[0].numpy().flatten()
        np.testing.assert_allclose(a,b,atol=.002,rtol=.0002)
        maximum=max(maximum,float(np.abs(a-b).max()));flips+=int(predict(g,a)!=predict(g,b));native_mismatch+=int(predict(g,a)!=expected_native)
        if i%1000==0:print('PHONE_PARITY',i,'/',len(rows),flush=True)
    result={'rows':len(rows),'sources':sources,'gate_pte_byte_identical':True,'maximum_diagnosis_logit_change':maximum,
        'candidate_family_flips_vs_current':flips,'current_cpu_vs_saved_phone_family_flips':native_mismatch,
        'thresholds_changed':False,'training_performed':False,'scope':'Saved development phone inputs, including background rows. No new traffic; numeric/decision parity only, not new accuracy evidence.'}
    (OUT/'saved_phone_parity.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    assert flips==0 and native_mismatch==0,result
    print('SAVED_PHONE_PARITY_PASS',len(rows),maximum,flush=True)


if __name__=='__main__':main()
