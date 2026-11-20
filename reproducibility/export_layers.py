import torch
from torch import nn
from torch.nn import functional as F

class PortableLSTM(nn.Module):
    def __init__(self, source):
        super().__init__()
        self.hidden_size = source.hidden_size
        for name in ('weight_ih_l0', 'weight_hh_l0', 'bias_ih_l0', 'bias_hh_l0'):
            self.register_buffer(name, getattr(source, name).detach().clone())

    def forward(self, x):
        h = x.new_zeros((1, self.hidden_size))
        c = x.new_zeros((1, self.hidden_size))
        output = []
        for i in range(32):
            gates = F.linear(x[:, i], self.weight_ih_l0, self.bias_ih_l0)
            gates = gates + F.linear(h, self.weight_hh_l0, self.bias_hh_l0)
            ig, fg, cg, og = gates.chunk(4, dim=-1)
            c = torch.sigmoid(fg) * c + torch.sigmoid(ig) * torch.tanh(cg)
            h = torch.sigmoid(og) * torch.tanh(c)
            output.append(h)
        return torch.stack(output, dim=1), (h.unsqueeze(0), c.unsqueeze(0))
