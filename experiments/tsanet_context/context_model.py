"""Matched-capacity TSANet fusion and its raw-input export contract."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import torch
from torch import nn

from experiments.tsanet_paper.model import TSANet

CONTEXT_DIM = 78


class ContextTSANet(nn.Module):
    def __init__(self, enabled=True):
        super().__init__()
        self.enabled = enabled
        self.flow = TSANet()
        self.context = nn.Sequential(
            nn.Linear(CONTEXT_DIM, 32), nn.ReLU(),
            nn.Linear(32, 16), nn.ReLU(),
        )
        self.flow.classifier[0] = nn.Linear(80, 64)

    def forward(self, features, context):
        if not self.enabled:
            context = torch.zeros_like(context)
        spatial, temporal, _, _ = self.flow.branches(features.unsqueeze(-1))
        fused = self.flow.fusion_bn(
            torch.cat((spatial, temporal), dim=-1).transpose(1, 2)
        ).transpose(1, 2)
        sequence, _ = self.flow.final_lstm(fused)
        return self.flow.classifier(torch.cat(
            (sequence[:, -1], self.context(context)), dim=-1
        ))


class RawContextWrapper(nn.Module):
    def __init__(self, model, flow_mean, flow_scale, context_mean, context_scale):
        super().__init__()
        self.model = model
        for name, value in (
            ('flow_mean', flow_mean), ('flow_scale', flow_scale),
            ('context_mean', context_mean), ('context_scale', context_scale),
        ):
            self.register_buffer(name, torch.tensor(value, dtype=torch.float32))

    def forward(self, features, context):
        return self.model(
            (features - self.flow_mean) / self.flow_scale,
            (context - self.context_mean) / self.context_scale,
        )
