"""Calibration and complete routing/alert policy, independent of fitting code."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import numpy as np
import torch
from experiments.phone_repair_v3.common import CLASSES,SOURCES


def probabilities(logits,kind,calibration=None):
    x=np.asarray(logits,np.float64)
    if calibration:x=x*calibration['scale']+np.array(calibration['bias'])
    if kind=='gate':return (1/(1+np.exp(-np.clip(x.reshape(-1),-80,80)))).astype(np.float32)
    x-=x.max(1,keepdims=True);x=np.exp(x);return (x/x.sum(1,keepdims=True)).astype(np.float32)


def fit_calibration(logits,y,kind):
    """Positive shared logit scale plus class biases; fit only calibration groups."""
    x=torch.tensor(np.asarray(logits),dtype=torch.float32);target=torch.tensor(y>0 if kind=='gate' else y,dtype=torch.float32 if kind=='gate' else torch.long)
    if kind=='gate':x=x.reshape(-1,1);target=target.reshape(-1,1)
    logscale=torch.zeros((),requires_grad=True);bias=torch.zeros(x.shape[1],requires_grad=True)
    optimizer=torch.optim.LBFGS([logscale,bias],lr=.5,max_iter=40,line_search_fn='strong_wolfe')
    def closure():
        optimizer.zero_grad();z=x*torch.exp(logscale.clamp(-3,3))+bias
        loss=torch.nn.functional.binary_cross_entropy_with_logits(z,target) if kind=='gate' else torch.nn.functional.cross_entropy(z,target)
        loss=loss+1e-4*(bias.square().mean()+logscale.square());loss.backward();return loss
    optimizer.step(closure)
    return {'scale':float(torch.exp(logscale.detach().clamp(-3,3))),'bias':bias.detach().tolist(),'method':'positive shared logit scale plus class biases; natural-frequency calibration NLL'}


def decisions(gate,diagnosis,policy):
    high=gate>=policy['high'];review=(gate>=policy['low'])&~high
    flag=high|(review&((1-diagnosis[:,0])>=policy['review_accept']))
    label=diagnosis.argmax(1);known=(label!=0)&(diagnosis.max(1)>=policy['type_cutoff'])
    return np.where(flag,np.where(known,label,7),0),flag,gate>=policy['low']


def score(y,pred,flag,routed,sources=None,config=None):
    matrix=np.bincount(np.asarray(y)*8+pred,minlength=64).reshape(8,8);n=len(y);classwise={}
    for i,c in enumerate(CLASSES):
        tp=int(matrix[i,i]);actual=int(matrix[i].sum());named=int(matrix[:,i].sum())
        precision=tp/max(1,named);recall=tp/max(1,actual)
        classwise[c]={'precision':precision,'recall':recall,'f1-score':2*tp/max(1,actual+named),'support':actual}
    attack=y>0;tp=int((flag&attack).sum());fp=int((flag&~attack).sum());fn=int((~flag&attack).sum());tn=int((~flag&~attack).sum())
    binary={'tp':tp,'fp':fp,'fn':fn,'tn':tn,'precision':tp/max(1,tp+fp),'recall':tp/max(1,tp+fn),'f1':2*tp/max(1,2*tp+fp+fn),'benign_fpr':fp/max(1,fp+tn),
        'class_attack_recall':{CLASSES[i]:float(flag[y==i].mean()) if (y==i).any() else 0. for i in range(1,7)}}
    source_fpr={SOURCES[int(s)]:float(flag[(y==0)&(sources==s)].mean()) for s in np.unique(sources) if ((y==0)&(sources==s)).any()} if sources is not None else {}
    macro=float(np.mean([v['f1-score'] for v in classwise.values()]));minimum_p=min(v['precision'] for v in classwise.values());minimum_r=min(v['recall'] for v in classwise.values())
    eligible=False
    if config:
        eligible=binary['benign_fpr']<=config['max_benign_fpr'] and binary['recall']>=config['min_attack_recall'] and min(binary['class_attack_recall'].values())>=config['min_class_attack_recall']
        eligible=eligible and minimum_p>=config['min_typed_precision'] and minimum_r>=config['min_typed_recall'] and all(v<=config['max_source_benign_fpr'] for v in source_fpr.values()) and float(routed.mean())<=config['max_routing_fraction']
    balance=2*minimum_p*minimum_r/max(1e-12,minimum_p+minimum_r)
    return {'binary':binary,'classwise':classwise,'macro_f1':macro,'typed_accuracy':float(np.trace(matrix)/max(1,n)),'source_benign_fpr':source_fpr,
        'confusion_with_unknown':matrix.tolist(),'routing_fraction':float(routed.mean()),'unknown_flagged':int(((pred==7)&flag).sum()),'eligible':bool(eligible),
        'rank':[int(eligible),balance,macro,binary['f1'],-binary['benign_fpr']]}


def improved(candidate,baseline,config):
    c=candidate;b=baseline;rule=config['improvement'];fail=[]
    if c['macro_f1']<b['macro_f1']+rule['min_macro_f1_gain']:fail.append('macro_f1_gain')
    if c['classwise']['Bot']['precision']<b['classwise']['Bot']['precision']+rule['min_bot_precision_gain']:fail.append('bot_precision_gain')
    if c['binary']['benign_fpr']>b['binary']['benign_fpr']+rule['max_fpr_increase']+1e-12:fail.append('benign_fpr_regression')
    if c['binary']['recall']<b['binary']['recall']-rule['max_binary_recall_loss']:fail.append('binary_recall_regression')
    for cls in CLASSES:
        if c['classwise'][cls]['recall']<b['classwise'][cls]['recall']-rule['max_typed_recall_loss']:fail.append(cls+'_typed_recall_regression')
        if c['classwise'][cls]['precision']<b['classwise'][cls]['precision']-rule['max_typed_precision_loss']:fail.append(cls+'_typed_precision_regression')
    for cls,value in b['binary']['class_attack_recall'].items():
        if c['binary']['class_attack_recall'][cls]<value-rule['max_class_binary_recall_loss']:fail.append(cls+'_binary_recall_regression')
    if any(v>config['max_source_benign_fpr'] for v in c['source_benign_fpr'].values()):fail.append('source_fpr_limit')
    return {'better':not fail,'failed_comparison_checks':fail}
