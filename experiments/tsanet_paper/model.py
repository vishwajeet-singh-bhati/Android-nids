"""Explicit reconstruction of Figure 1; unreported choices are in PROTOCOL.md."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import torch
from torch import nn


class TSANet(nn.Module):
    def __init__(self,kernel_size=3,dense_width=64):
        super().__init__()
        self.spatial_conv=nn.Conv1d(1,32,kernel_size,padding=kernel_size//2)
        self.spatial_attention=nn.Conv1d(32,1,1)
        self.temporal_lstm=nn.LSTM(1,32,batch_first=True)
        self.temporal_attention=nn.Linear(32,1)
        # Keras-style BN settings reconstructed from the figure's terminology.
        self.temporal_bn=nn.BatchNorm1d(32,eps=.001,momentum=.01)
        self.fusion_bn=nn.BatchNorm1d(64,eps=.001,momentum=.01)
        self.final_lstm=nn.LSTM(64,64,batch_first=True)
        self.classifier=nn.Sequential(nn.Linear(64,dense_width),nn.ReLU(),nn.Linear(dense_width,7))

    def branches(self,x):
        spatial=torch.relu(self.spatial_conv(x.transpose(1,2)))
        spatial_weight=torch.sigmoid(self.spatial_attention(spatial))
        spatial=(spatial*spatial_weight).transpose(1,2)
        temporal,_=self.temporal_lstm(x)
        temporal_weight=torch.softmax(self.temporal_attention(temporal),dim=1)
        temporal=self.temporal_bn((temporal*temporal_weight).transpose(1,2)).transpose(1,2)
        return spatial,temporal,spatial_weight,temporal_weight

    def forward(self,x):
        spatial,temporal,_,_=self.branches(x)
        fused=torch.cat((spatial,temporal),dim=-1)
        fused=self.fusion_bn(fused.transpose(1,2)).transpose(1,2)
        sequence,_=self.final_lstm(fused)
        return self.classifier(sequence[:,-1])


class RawFeatureWrapper(nn.Module):
    def __init__(self,model,mean,scale):
        super().__init__();self.model=model
        self.register_buffer('mean',torch.tensor(mean,dtype=torch.float32))
        self.register_buffer('scale',torch.tensor(scale,dtype=torch.float32))
    def forward(self,features):
        return self.model(((features-self.mean)/self.scale).unsqueeze(-1))


def magnitude_masks(model,rate):
    """Exactly floor(rate*N) matrix weights masked, including recurrent weights."""
    named=[(name,p) for name,p in model.named_parameters() if p.ndim>=2]
    flat=torch.cat([p.detach().abs().flatten().cpu() for _,p in named])
    order=torch.argsort(flat,stable=True);mask=torch.ones_like(flat)
    mask[order[:int(rate*len(flat))]]=0
    result={};start=0
    for name,p in named:
        result[name]=mask[start:start+p.numel()].reshape(p.shape).to(p.device)
        start+=p.numel()
    return result


def apply_masks(model,masks,gradients=False):
    with torch.no_grad():
        for name,p in model.named_parameters():
            if name in masks:
                if gradients:
                    if p.grad is not None:p.grad.mul_(masks[name])
                else:p.mul_(masks[name])
