"""Fixed-budget TSANet baseline/pruning comparison; never tune on test scores."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from pathlib import Path
import json,math,os,time
import numpy as np
import torch
from torch import nn
from sklearn.metrics import accuracy_score,classification_report,confusion_matrix,average_precision_score,roc_auc_score
from data import CACHE,CLASSES,atomic,sha,load_split
from model import TSANet,RawFeatureWrapper,magnitude_masks,apply_masks

def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.tmp');torch.save(value,tmp);tmp.replace(path)

def checkpoint_model(path,device):
    ck=torch.load(path,map_location='cpu',weights_only=True)
    model=TSANet(ck['kernel_size'],ck['dense_width']).to(device);model.load_state_dict(ck['model'])
    return model,ck

def stage(directory,cache,name,epochs,device,train_x,train_y,initial=None,rate=0.):
    config=json.loads((directory/'config.json').read_text());folder=directory/name;folder.mkdir(exist_ok=True)
    if (folder/'complete.json').exists():
        result=json.loads((folder/'complete.json').read_text())
        assert sha(folder/'final.pt')==result['checkpoint_sha256'];return
    torch.manual_seed(config['seed'])
    if initial:model,_=checkpoint_model(initial,device)
    else:model=TSANet(config['kernel_size'],config['dense_width']).to(device)
    masks=magnitude_masks(model,rate) if rate else {};apply_masks(model,masks)
    optimizer=torch.optim.Adam(model.parameters(),lr=config['learning_rate'])
    history=[];first=1;best_loss=float('inf')
    if (folder/'last.pt').exists():
        ck=torch.load(folder/'last.pt',map_location=device,weights_only=True)
        assert ck['config_sha256']==sha(directory/'config.json') and ck['stage']==name
        model.load_state_dict(ck['model']);optimizer.load_state_dict(ck['optimizer'])
        masks={k:v.to(device) for k,v in ck['masks'].items()};history=ck['history'];first=ck['epoch']+1;best_loss=ck['best_training_loss']
        torch.set_rng_state(ck['torch_rng'].cpu())
        if device=='cuda' and ck['cuda_rng']:torch.cuda.set_rng_state_all([v.cpu() for v in ck['cuda_rng']])
    n=len(train_y);batch=config['batch_size']
    for epoch in range(first,epochs+1):
        began=time.monotonic();model.train()
        generator=torch.Generator(device=device).manual_seed(config['seed']+epoch+(100000 if rate else 0))
        order=torch.randperm(n,device=device,generator=generator)
        loss_sum=torch.zeros((),device=device);correct=torch.zeros((),device=device,dtype=torch.int64)
        for step,start in enumerate(range(0,n,batch)):
            ids=order[start:start+batch];x=train_x[ids].unsqueeze(-1);y=train_y[ids]
            optimizer.zero_grad(set_to_none=True);logits=model(x);loss=nn.functional.cross_entropy(logits,y)
            if not torch.isfinite(loss):raise RuntimeError('Nonfinite loss')
            loss.backward();apply_masks(model,masks,gradients=True);optimizer.step();apply_masks(model,masks)
            loss_sum+=loss.detach()*len(ids);correct+=(logits.detach().argmax(-1)==y).sum()
            if step%100==0:
                atomic(directory/'status.json',{'state':'training','stage':name,'epoch':epoch,'epochs':epochs,
                    'step':step,'steps':math.ceil(n/batch),'elapsed_epoch_seconds':time.monotonic()-began,
                    'updated_unix':time.time(),'pid':os.getpid(),'early_stopping':False})
        average_loss=float(loss_sum)/n
        row={'epoch':epoch,'loss':average_loss,'online_training_accuracy':float(correct)/n,
             'seconds':time.monotonic()-began,'learning_rate':config['learning_rate']}
        history.append(row);improved=average_loss<best_loss;best_loss=min(best_loss,average_loss)
        ck={'stage':name,'epoch':epoch,'kernel_size':config['kernel_size'],'dense_width':config['dense_width'],
            'model':model.state_dict(),'optimizer':optimizer.state_dict(),'masks':{k:v.cpu() for k,v in masks.items()},
            'history':history,'best_training_loss':best_loss,'config_sha256':sha(directory/'config.json'),
            'torch_rng':torch.get_rng_state(),'cuda_rng':torch.cuda.get_rng_state_all() if device=='cuda' else [],
            'parameters':sum(p.numel() for p in model.parameters()),'pruning_rate':rate}
        save(folder/f'epoch_{epoch:02d}.pt',ck);save(folder/'last.pt',ck)
        if improved:save(folder/'best_training_loss.pt',ck)
        atomic(folder/'history.json',history);print('EPOCH',name,row,flush=True)
    # The final fixed epoch is the benchmark checkpoint, never a test-selected epoch.
    last=torch.load(folder/'last.pt',map_location='cpu',weights_only=True);save(folder/'final.pt',last)
    zeros=sum(int((p==0).sum()) for p in model.parameters());matrix=sum(p.numel() for p in model.parameters() if p.ndim>=2)
    atomic(folder/'complete.json',{'epochs':epochs,'checkpoint_sha256':sha(folder/'final.pt'),
        'parameter_count':sum(p.numel() for p in model.parameters()),'zero_parameters':zeros,
        'masked_matrix_weights':sum(int((m==0).sum()) for m in masks.values()),'matrix_weights':matrix,
        'best_training_loss_checkpoint_is_not_used_for_test':True})

def predict(model,x,device,batch=2048):
    output=[];model.eval()
    with torch.inference_mode():
        for start in range(0,len(x),batch):
            values=torch.tensor(np.array(x[start:start+batch],copy=True),device=device).unsqueeze(-1)
            output.append(torch.softmax(model(values),-1).cpu().numpy())
    return np.concatenate(output)

def metrics(y,probability):
    prediction=probability.argmax(-1);positive=y!=0;flag=prediction!=0
    report=classification_report(y,prediction,labels=list(range(7)),target_names=list(CLASSES),output_dict=True,zero_division=0)
    result={'rows':len(y),'accuracy':float(accuracy_score(y,prediction)),
        'macro_precision':report['macro avg']['precision'],'macro_recall':report['macro avg']['recall'],'macro_f1':report['macro avg']['f1-score'],
        'weighted_precision':report['weighted avg']['precision'],'weighted_recall':report['weighted avg']['recall'],'weighted_f1':report['weighted avg']['f1-score'],
        'classification_report':report,'confusion_matrix':confusion_matrix(y,prediction,labels=list(range(7))).tolist(),
        'binary_confusion':confusion_matrix(positive,flag,labels=[False,True]).tolist(),
        'binary_attack_recall':float(flag[positive].mean()),'benign_false_positive_rate':float(flag[~positive].mean()),
        'binary_average_precision':float(average_precision_score(positive,1-probability[:,0])),
        'binary_roc_auc':float(roc_auc_score(positive,1-probability[:,0]))}
    return result

def timing(model,x,device):
    value=torch.tensor(np.array(x[:1],copy=True),device=device).unsqueeze(-1);model.eval();samples=[]
    with torch.inference_mode():
        for _ in range(30):model(value)
        if device=='cuda':torch.cuda.synchronize()
        for _ in range(200):
            begin=time.perf_counter_ns();model(value)
            if device=='cuda':torch.cuda.synchronize()
            samples.append((time.perf_counter_ns()-begin)/1e6)
    return {'device':device,'unit':'milliseconds per sample; work PC only, not Android',
            'mean':float(np.mean(samples)),'median':float(np.median(samples)),'p95':float(np.quantile(samples,.95))}

def evaluate(directory,cache,device):
    config=json.loads((directory/'config.json').read_text());names=['baseline']+[f'pruned_{int(rate*100)}' for rate in config['pruning_rates']]
    frozen_path=directory/'frozen_comparison.json'
    if not frozen_path.exists():
        atomic(frozen_path,{'config_sha256':sha(directory/'config.json'),'data_ready_sha256':sha(cache/'ready.json'),
            'normalization_sha256':sha(cache/'normalization.json'),'created_unix':time.time(),
            'checkpoints':{name:sha(directory/name/'final.pt') for name in names},
            'policy':'All final fixed-epoch checkpoints frozen before test inference; no test-selected checkpoint or threshold'})
    frozen=json.loads(frozen_path.read_text());assert frozen['config_sha256']==sha(directory/'config.json')
    train_x,train_y=load_split('train',cache);test_x,test_y=load_split('test',cache)
    norm=json.loads((cache/'normalization.json').read_text());results={}
    for name in names:
        path=directory/name/'final.pt';assert sha(path)==frozen['checkpoints'][name]
        model,ck=checkpoint_model(path,device)
        train_prob=predict(model,train_x,device);test_prob=predict(model,test_x,device)
        result={'parameters':ck['parameters'],'epochs':ck['epoch'],'pruning_rate':ck['pruning_rate'],
            'train':metrics(np.asarray(train_y),train_prob),'test':metrics(np.asarray(test_y),test_prob),
            'work_pc_batch1_timing':timing(model,test_x,device),'checkpoint_sha256':sha(path)}
        target=.9735 if name=='baseline' else .983 if name=='pruned_30' else None
        result['paper_test_accuracy_reference']=target
        result['measured_minus_paper_percentage_points']=100*(result['test']['accuracy']-target) if target is not None else None
        result['same_at_reported_two_decimal_percent']=round(100*result['test']['accuracy'],2)==round(100*target,2) if target is not None else None
        atomic(directory/(name+'_metrics.json'),result)
        np.save(directory/(name+'_test_predictions.npy'),test_prob.argmax(-1).astype(np.int8))
        # TorchScript export follows the paper. It is not installed into the current app.
        model=model.cpu().eval();wrapper=RawFeatureWrapper(model,norm['mean'],norm['scale']).eval()
        raw=np.load(cache/'test_raw.npy',mmap_mode='r');example=torch.tensor(np.array(raw[:1],copy=True))
        with torch.inference_mode():
            traced=torch.jit.trace(wrapper,example);export=directory/(name+'.pt');traced.save(str(export))
            restored=torch.jit.load(str(export)).eval()
            actual=restored(torch.tensor(np.array(raw[:64],copy=True))).numpy()
            expected=wrapper(torch.tensor(np.array(raw[:64],copy=True))).numpy()
        error=float(np.abs(actual-expected).max());flips=int((actual.argmax(-1)!=expected.argmax(-1)).sum())
        if error>=.0001 or flips:raise RuntimeError('TorchScript numerical parity failed')
        result['torchscript']={'sha256':sha(export),'bytes':export.stat().st_size,'maximum_absolute_error':error,
                              'decision_flips':flips,'samples':min(64,len(raw))}
        results[name]=result;del model,wrapper,train_prob,test_prob
        print('TEST_RESULT',name,result['test']['accuracy'],result['test']['macro_f1'],flush=True)
    report={'scope':'Paper-based reconstruction with user-defined stratified 70/30 split; not an exact author reproduction',
        'smoke':config['smoke'],'results':results,'paper_missing_details':config['paper_missing_details'],
        'limited_mobile_feature_experiment':'Not reproduced: available-feature list, imputation/interpolation and mobile fine-tuning data are not given.',
        'device_timing':'Work-PC timing only. Paper Android latency and loading-time claims are not reproduced.',
        'no_test_tuning':True,'production_ready':False}
    atomic(directory/'comparison.json',report)
    lines=['# TSANet paper-based baseline comparison','',
        '**Synthetic automation smoke only.**' if config['smoke'] else '**Measured reconstruction, not an exact author reproduction.**','',
        'User split: 70% train / 30% test, stratified, seed 42. The authors do not disclose their split or 32-feature list. See PROTOCOL.md for every assumption.','',
        '| Model | Paper test accuracy | Measured test accuracy | Delta (percentage points) | Macro F1 | Attack recall | Benign false-positive rate |',
        '|---|---:|---:|---:|---:|---:|---:|']
    for name,result in results.items():
        m=result['test'];target=result['paper_test_accuracy_reference'];delta=result['measured_minus_paper_percentage_points']
        lines.append(f"| {name} | {100*target:.2f}% | {100*m['accuracy']:.2f}% | {delta:+.2f} | {m['macro_f1']:.5f} | {100*m['binary_attack_recall']:.2f}% | {100*m['benign_false_positive_rate']:.5f}% |" if target is not None else
                     f"| {name} | not stated numerically | {100*m['accuracy']:.2f}% | n/a | {m['macro_f1']:.5f} | {100*m['binary_attack_recall']:.2f}% | {100*m['benign_false_positive_rate']:.5f}% |")
    lines+=['','Full classwise metrics and confusion matrices: `comparison.json`. No test score selects a checkpoint or changes the implementation. The 32-feature list, scaling, activations, kernels and pruning method are explicit reconstruction choices. Exact feature duplication across the random split is reported in `data_report.json`.','',
        'Unstructured zeros do not reduce the dense network dimensions or guarantee a latency reduction. No Android performance or missing-feature experiment is claimed.','']
    (directory/'COMPARISON.md').write_text('\n'.join(lines))
