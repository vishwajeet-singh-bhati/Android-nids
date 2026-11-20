
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import torch
from torch import nn


class Diagnosis(nn.Module):
    def __init__(self,width=32,wire_only=False):
        super().__init__();self.wire_only=wire_only
        self.spatial=nn.Conv1d(1,width,3,padding=1);self.spatial_attention=nn.Conv1d(width,1,1)
        self.temporal=nn.LSTM(1,width,batch_first=True);self.temporal_attention=nn.Linear(width,1)
        self.temporal_bn=nn.BatchNorm1d(width,eps=.001,momentum=.01)
        self.fusion_bn=nn.BatchNorm1d(width*2,eps=.001,momentum=.01)
        self.final_lstm=nn.LSTM(width*2,width*2,batch_first=True)
        self.context=nn.Sequential(nn.Linear(115,32),nn.ReLU(),nn.Linear(32,16),nn.ReLU())
        self.classifier=nn.Sequential(nn.Linear(width*2+16,width*2),nn.ReLU(),nn.Linear(width*2,7))
    def forward(self,x):
        flow=x[:,:32].unsqueeze(-1);context=x[:,32:]
        if self.wire_only:context=torch.cat((torch.zeros_like(context[:,:96]),context[:,96:114],torch.zeros_like(context[:,114:])),dim=1)
        spatial=torch.relu(self.spatial(flow.transpose(1,2)))
        spatial=(spatial*torch.sigmoid(self.spatial_attention(spatial))).transpose(1,2)
        temporal,_=self.temporal(flow);weights=torch.softmax(self.temporal_attention(temporal),dim=1)
        temporal=self.temporal_bn((temporal*weights).transpose(1,2)).transpose(1,2)
        fused=self.fusion_bn(torch.cat((spatial,temporal),dim=-1).transpose(1,2)).transpose(1,2)
        sequence,_=self.final_lstm(fused)
        return self.classifier(torch.cat((sequence[:,-1],self.context(context)),dim=-1))


class Gate(nn.Module):
    def __init__(self,width=96):
        super().__init__();self.layers=nn.Sequential(nn.Linear(147,width),nn.ReLU(),nn.Linear(width,width//2),nn.ReLU(),nn.Linear(width//2,1))
    def forward(self,x):return self.layers(x)


def build(job):
    return Gate(job.get('width',96)) if job['kind']=='gate' else Diagnosis(job.get('width',64),job.get('wire_only',False))


class RawWrapper(nn.Module):
    def __init__(self,model,mean,scale):
        super().__init__();self.model=model
        self.register_buffer('mean',torch.tensor(mean,dtype=torch.float32));self.register_buffer('scale',torch.tensor(scale,dtype=torch.float32))
    def forward(self,flow,context):
        transformed=torch.cat((torch.log1p(torch.clamp(flow,min=0)),context[:,:96],torch.log1p(torch.clamp(context[:,96:114],min=0)),context[:,114:]),dim=1)
        return self.model((transformed-self.mean)/self.scale)
